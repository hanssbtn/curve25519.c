#include "../tests.h"

int32_t curve25519_key_xor_test(void) {
	printf("Key XOR Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x7C5501C9611CFBA6ULL,
		0xED47796158F61E32ULL,
		0x4F67747621E8560FULL,
		0x465CBAFE6B8C34AAULL,
		0xC8349BAD1E171A7CULL,
		0x03ED542AB4C46741ULL,
		0xF3DEF07DED28D403ULL,
		0x930571E7B445EBD5ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xAC93A973083F9949ULL,
		0xBE43A5F3D2953B75ULL,
		0x1D5BFCF56E246843ULL,
		0xF28DB92E03B2F6B5ULL,
		0x345E2AEBE7940A99ULL,
		0xAC7FBAB68BE5CFC1ULL,
		0xC56B8C0E2DCB3BC9ULL,
		0x59270DB3BE6643B6ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xD0C6A8BA692362EFULL,
		0x5304DC928A632547ULL,
		0x523C88834FCC3E4CULL,
		0xB4D103D0683EC21FULL,
		0xFC6AB146F98310E5ULL,
		0xAF92EE9C3F21A880ULL,
		0x36B57C73C0E3EFCAULL,
		0xCA227C540A23A863ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x19417C1D34B55CD0ULL,
		0x30B6E2ADDCEE16CFULL,
		0xEB948AA84F059FC9ULL,
		0x6EB431C7D8C28115ULL,
		0x9A5255485A12B7E4ULL,
		0x75255EC2DBAB55C3ULL,
		0x9ACD34007A31BFC4ULL,
		0xAF3ECECF40E3CA01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA7F008A0C79610ULL,
		0x26C505610C95DEABULL,
		0xA829778448E72792ULL,
		0xE62FE30E60E8EBC3ULL,
		0x6A83B85B93E1E651ULL,
		0xC76C02874C1B37E8ULL,
		0xFDE5458B4A9D425FULL,
		0x5E747FE8FC08AC68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04E68C159472CAC0ULL,
		0x1673E7CCD07BC864ULL,
		0x43BDFD2C07E2B85BULL,
		0x889BD2C9B82A6AD6ULL,
		0xF0D1ED13C9F351B5ULL,
		0xB2495C4597B0622BULL,
		0x6728718B30ACFD9BULL,
		0xF14AB127BCEB6669ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x555E25395CDFC856ULL,
		0x9834A6FE47679828ULL,
		0xBCF5A7F7C8A1FBECULL,
		0x70F7121EC2662CE9ULL,
		0xE7FCF392B00DF52BULL,
		0x555DE03EDA672826ULL,
		0x2AD4F60437C78CF6ULL,
		0x2DD4862D188B668FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19E799161878A01ULL,
		0xAFDA60FB2AC2463DULL,
		0xB78A38EB4E53E8BFULL,
		0x97CCA2D1EB67CAD5ULL,
		0x5A0EB2F62AED317DULL,
		0x3B9ED5A428E4D4E7ULL,
		0xF8B51DB4289F3F8DULL,
		0xB6C7D6D694EC021BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C05CA83D584257ULL,
		0x37EEC6056DA5DE15ULL,
		0x0B7F9F1C86F21353ULL,
		0xE73BB0CF2901E63CULL,
		0xBDF241649AE0C456ULL,
		0x6EC3359AF283FCC1ULL,
		0xD261EBB01F58B37BULL,
		0x9B1350FB8C676494ULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x11706F9BB2402F67ULL,
		0x67BA1C382CAD0371ULL,
		0xAD4F03CC62455DA3ULL,
		0x7F978B6A34CF2156ULL,
		0x7E139CFF80F521ECULL,
		0x12C31985379636D1ULL,
		0xD7ADD90DF3F884EFULL,
		0xF39EE3A47E523EE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E22A1FFBE0C08BCULL,
		0x09E52A48DD28DF3CULL,
		0x4EAC0B8F2DF3AB11ULL,
		0x7AD331714142998EULL,
		0xE367119B9FD358F9ULL,
		0xC9ACF3FA229B7948ULL,
		0x7153C1E417A1DB40ULL,
		0xF150242FDA10973FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F52CE640C4C27DBULL,
		0x6E5F3670F185DC4DULL,
		0xE3E308434FB6F6B2ULL,
		0x0544BA1B758DB8D8ULL,
		0x9D748D641F267915ULL,
		0xDB6FEA7F150D4F99ULL,
		0xA6FE18E9E4595FAFULL,
		0x02CEC78BA442A9DBULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x475783BE9CA966EAULL,
		0x340879FF72AD8387ULL,
		0xB7280EF0BB52FE5DULL,
		0x1A691A4F563023E3ULL,
		0xC0BDCBD3B846E166ULL,
		0x25CDDC8BD62475F9ULL,
		0x4D9F9386E5A4E02FULL,
		0xB2D1F1C950D57D98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x350DC78C70D86409ULL,
		0xFE3059C1BA5F5592ULL,
		0xB8007804853C8B28ULL,
		0xE8D12B8B65034C64ULL,
		0xC87057F947D738A5ULL,
		0xCE43F80AE735C0EFULL,
		0x65F429DE0F0CFA18ULL,
		0x4C72476230F559E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x725A4432EC7102E3ULL,
		0xCA38203EC8F2D615ULL,
		0x0F2876F43E6E7575ULL,
		0xF2B831C433336F87ULL,
		0x08CD9C2AFF91D9C3ULL,
		0xEB8E24813111B516ULL,
		0x286BBA58EAA81A37ULL,
		0xFEA3B6AB6020247AULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8DDBA53825AE5513ULL,
		0x365B64675F8F6042ULL,
		0x5F882F3FF39B6067ULL,
		0xBF0188BB6953ADA4ULL,
		0x493E6C7EEE6F8847ULL,
		0xB6ABD56576A3C11FULL,
		0xA89815234DC6C24FULL,
		0x255CBC8674257AD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BE6494731252B3ULL,
		0x96FF18946E6D82BDULL,
		0x868D777C7F823814ULL,
		0x021C5832E567EC70ULL,
		0xB4722126E14BDFA9ULL,
		0xF9DBE4FEDD7BBA23ULL,
		0xB7CE25119658F1C6ULL,
		0xA5D81BD1C48F7454ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2465C1AC56BC07A0ULL,
		0xA0A47CF331E2E2FFULL,
		0xD90558438C195873ULL,
		0xBD1DD0898C3441D4ULL,
		0xFD4C4D580F2457EEULL,
		0x4F70319BABD87B3CULL,
		0x1F563032DB9E3389ULL,
		0x8084A757B0AA0E84ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDB0155576E304446ULL,
		0xC9B6DE1A0485C1B1ULL,
		0x93151487EAFEC16DULL,
		0x239A68DF61992D20ULL,
		0x9F0418C1AEFD5D32ULL,
		0xE0278FDC389641D2ULL,
		0xD7459E3D31B6F2C7ULL,
		0x62BA91CF1DAFDEA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BB6D05D997230F6ULL,
		0xFE6F42B33FA3E317ULL,
		0x3ADBFC029735E18EULL,
		0xD3500479DC6ABAB0ULL,
		0xE655C87D5D46DC9EULL,
		0xEEE5B9592A3440A4ULL,
		0x35A5DE5DA7681C98ULL,
		0xB59F3E16D3AB2955ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50B7850AF74274B0ULL,
		0x37D99CA93B2622A6ULL,
		0xA9CEE8857DCB20E3ULL,
		0xF0CA6CA6BDF39790ULL,
		0x7951D0BCF3BB81ACULL,
		0x0EC2368512A20176ULL,
		0xE2E0406096DEEE5FULL,
		0xD725AFD9CE04F7F0ULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE994120FAE5AA740ULL,
		0xD00B9A1630D1A54DULL,
		0x9C9071F8682C7221ULL,
		0xD57EDA08059D424BULL,
		0x8856ABC197AE62FEULL,
		0x97F2F47B30021624ULL,
		0x7D61CC3F1C2FD273ULL,
		0x80282F45D9EE5A18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A107ED5D13F481ULL,
		0x3BD660A7CB8A6B94ULL,
		0x597E123199A0158DULL,
		0xA7DF0956E311BCCDULL,
		0xD25C0A5E97579195ULL,
		0xE00E2905FE76BA54ULL,
		0x3E9D5B64BA4DF6BDULL,
		0xD2B07FA1BB8676EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB83515E2F34953C1ULL,
		0xEBDDFAB1FB5BCED9ULL,
		0xC5EE63C9F18C67ACULL,
		0x72A1D35EE68CFE86ULL,
		0x5A0AA19F00F9F36BULL,
		0x77FCDD7ECE74AC70ULL,
		0x43FC975BA66224CEULL,
		0x529850E462682CF6ULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE8B18F185D212A9BULL,
		0x1299743CE1554CEEULL,
		0xA0E05E56F01D9FB4ULL,
		0xE06AAC75061860DDULL,
		0x356B5BCF43075245ULL,
		0xE96B4054A4C007A4ULL,
		0x15620BC5AE05A31CULL,
		0x0558CDD1DD447E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3AC1470139F58CULL,
		0xFBA0BF71546AD3BEULL,
		0xE828F4AB393B5F32ULL,
		0xE35A934B836B9B6AULL,
		0x7D9C42FCD89481BAULL,
		0x88920315DFC0F1E1ULL,
		0xCB92BAF4BA6CC888ULL,
		0x8528031FB7FDB627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x428B4E5F5C18DF17ULL,
		0xE939CB4DB53F9F50ULL,
		0x48C8AAFDC926C086ULL,
		0x03303F3E8573FBB7ULL,
		0x48F719339B93D3FFULL,
		0x61F943417B00F645ULL,
		0xDEF0B13114696B94ULL,
		0x8070CECE6AB9C85FULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4F228FD550BF59A5ULL,
		0x792130B7A6458675ULL,
		0xDF0D93FFBAD6E506ULL,
		0xAA7F2EBBDA69467CULL,
		0x59F4B1F0AC6D8B5FULL,
		0xE64323BF0178B4B1ULL,
		0x189AD11160C1A707ULL,
		0x9955624FCD84E6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6DF1484BD4CB727ULL,
		0xA8460C0437357B5FULL,
		0xC8E3C2C394EF4CDFULL,
		0x4825AF8EB5D8EE04ULL,
		0x7EE9DA58A5A9BCF4ULL,
		0x71C6E66E38D8DF26ULL,
		0x70AE0B54609C7550ULL,
		0xE7DC4F7D8B9F1D03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99FD9B51EDF3EE82ULL,
		0xD1673CB39170FD2AULL,
		0x17EE513C2E39A9D9ULL,
		0xE25A81356FB1A878ULL,
		0x271D6BA809C437ABULL,
		0x9785C5D139A06B97ULL,
		0x6834DA45005DD257ULL,
		0x7E892D32461BFBB6ULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB38EB05E9DE6B10DULL,
		0x0E444523C20B15A7ULL,
		0x479F21C2C32252D2ULL,
		0x0110EFF698B8E683ULL,
		0x2481B22CBA8FC9C8ULL,
		0xCB6F56DA660961B8ULL,
		0x793B91FC97F2CB9EULL,
		0x949CE27CA2D9F07BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x466D08520887CED2ULL,
		0x5B750AC2526CFC84ULL,
		0x32C31780919564CDULL,
		0xD0D59C912DB33FBAULL,
		0x8FAD0BC7B64B14FEULL,
		0xFC1AC87AA72AE26AULL,
		0xB97E78305DAC718DULL,
		0xDA9E2A5F4D2521D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5E3B80C95617FDFULL,
		0x55314FE19067E923ULL,
		0x755C364252B7361FULL,
		0xD1C57367B50BD939ULL,
		0xAB2CB9EB0CC4DD36ULL,
		0x37759EA0C12383D2ULL,
		0xC045E9CCCA5EBA13ULL,
		0x4E02C823EFFCD1A2ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDE30E11A4D809733ULL,
		0x1FAA43A901EFC5F0ULL,
		0x3499C9BF4A396B02ULL,
		0xCE0C65DA91C116D4ULL,
		0x679BB9619FE116E6ULL,
		0x9CB2F3D8A6392AF0ULL,
		0x7902A9449F37BB62ULL,
		0xB09FF7B158F72263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33EA7CCD4EA19992ULL,
		0x8DEC92B830FF62ADULL,
		0x3B2704B5CA697B88ULL,
		0xDEE688033EA6A9CEULL,
		0x6CD1DE566B0A622FULL,
		0x07E4D47261258661ULL,
		0x95D3FF259FF115A7ULL,
		0xAE0B5510B71DCBDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDDA9DD703210EA1ULL,
		0x9246D1113110A75DULL,
		0x0FBECD0A8050108AULL,
		0x10EAEDD9AF67BF1AULL,
		0x0B4A6737F4EB74C9ULL,
		0x9B5627AAC71CAC91ULL,
		0xECD1566100C6AEC5ULL,
		0x1E94A2A1EFEAE9B8ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9294B834E777407BULL,
		0x4513D08001F7913FULL,
		0x66513A910310AA9DULL,
		0xA15CC86D50AF1532ULL,
		0xA85A56A8BD568989ULL,
		0xCB192F53C6CA5785ULL,
		0x62A3D4757D2CDE4FULL,
		0xE8633509DD6F84AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A97F90CD82552DEULL,
		0x79BE9A209B2F20FEULL,
		0x172357096C3E34B8ULL,
		0xFB3C8947D0B61393ULL,
		0xF0083B5088EDBF1FULL,
		0xAD9FD6414C66F795ULL,
		0xC36AB3BE7D0A0077ULL,
		0x93BA05B7F389C364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD80341383F5212A5ULL,
		0x3CAD4AA09AD8B1C1ULL,
		0x71726D986F2E9E25ULL,
		0x5A60412A801906A1ULL,
		0x58526DF835BB3696ULL,
		0x6686F9128AACA010ULL,
		0xA1C967CB0026DE38ULL,
		0x7BD930BE2EE647CAULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE9D66439C1317FFCULL,
		0xFB31139E9FC0FC4CULL,
		0x7964B89605314488ULL,
		0x4A0C57A4E29E1DE2ULL,
		0xE085908D2E1A351EULL,
		0x564433A27CD2CE3CULL,
		0x22F4A203EC974E26ULL,
		0x8B52FF49EEF149EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34A4E4577EF1BCBULL,
		0x17423D4E904DBB59ULL,
		0x64FD649F0C1B4341ULL,
		0x63457C538E992E6AULL,
		0x97408F41757232BDULL,
		0x3E81D55AF4A0F8A5ULL,
		0xDEEB2E1FDD8F2714ULL,
		0x3E031849642F7B60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A9C2A7CB6DE6437ULL,
		0xEC732ED00F8D4715ULL,
		0x1D99DC09092A07C9ULL,
		0x29492BF76C073388ULL,
		0x77C51FCC5B6807A3ULL,
		0x68C5E6F888723699ULL,
		0xFC1F8C1C31186932ULL,
		0xB551E7008ADE328AULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAB9F517988792780ULL,
		0x4D10DB1B7291F72EULL,
		0x22090B7F9938BEC1ULL,
		0xA7AA9D781B5C2CC7ULL,
		0x0BCC711D46E70774ULL,
		0x4A8E28DBC2724192ULL,
		0xCB32588E2F00382DULL,
		0x456BE6F394BEEC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFEE30EE59203DA8ULL,
		0xA16CD286EE149127ULL,
		0xE04FAB25A8E375CDULL,
		0xF90C1373C40FBB74ULL,
		0xBAE511D006C68D9AULL,
		0xC880A97CB862A53FULL,
		0x8AFCACE3BA4D8534ULL,
		0xC0BE908338BBE41EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64716197D1591A28ULL,
		0xEC7C099D9C856609ULL,
		0xC246A05A31DBCB0CULL,
		0x5EA68E0BDF5397B3ULL,
		0xB12960CD40218AEEULL,
		0x820E81A77A10E4ADULL,
		0x41CEF46D954DBD19ULL,
		0x85D57670AC050800ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFB199A8AF6670DF5ULL,
		0x9F005367181972B8ULL,
		0xE55EAA88C7F34EF7ULL,
		0x867A3E15BC774E9DULL,
		0xFE8FC2AB7A05E4ABULL,
		0xB8BDECA56B163543ULL,
		0x0860A8A72D0D8652ULL,
		0xC1BB72EBD66A5289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8752293CBDE2366BULL,
		0x145D29E77DC73501ULL,
		0x5E54364780F644BAULL,
		0x3147E745EDDAC881ULL,
		0x350A2666B4308AA2ULL,
		0x74E9E71B47122FFBULL,
		0x424123CEA550B872ULL,
		0x213F759863B50DF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C4BB3B64B853B9EULL,
		0x8B5D7A8065DE47B9ULL,
		0xBB0A9CCF47050A4DULL,
		0xB73DD95051AD861CULL,
		0xCB85E4CDCE356E09ULL,
		0xCC540BBE2C041AB8ULL,
		0x4A218B69885D3E20ULL,
		0xE0840773B5DF5F78ULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x907B572F7E4F8A9EULL,
		0xD9A61E9C0E7A804AULL,
		0x06F2627B2559EF54ULL,
		0xB967702275309101ULL,
		0x1EB102B44A8C84A5ULL,
		0x6294A1826EA9933BULL,
		0x9CE094E412FF7095ULL,
		0x20117AE995C2F9A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7CC48B266431500ULL,
		0x665E78BE621F6916ULL,
		0xC7F109359890A79BULL,
		0x909F4A1884976F7AULL,
		0xAAB86A8381460592ULL,
		0x1A748B8CAB7B9545ULL,
		0x22B9BEB6AE812ABCULL,
		0xDEEA4ED28AF5CB1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47B71F9D180C9F9EULL,
		0xBFF866226C65E95CULL,
		0xC1036B4EBDC948CFULL,
		0x29F83A3AF1A7FE7BULL,
		0xB4096837CBCA8137ULL,
		0x78E02A0EC5D2067EULL,
		0xBE592A52BC7E5A29ULL,
		0xFEFB343B1F3732B9ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x87BFD3B32C2804A2ULL,
		0x51973FDA57FB23CFULL,
		0x5D3E2EF201253737ULL,
		0xD18E542FCB4E1876ULL,
		0x2F6E4DA1B693DAF1ULL,
		0x12FE9D78711F9C91ULL,
		0x768169219967141CULL,
		0xEE338A3976D0BC16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED1087DCFA067FBULL,
		0xBD889AB52D03746CULL,
		0x62C2CE226011A788ULL,
		0x486D5AB84493631FULL,
		0xC4F084C65D4C0292ULL,
		0x950FFA1DB8C698ECULL,
		0x241E1F068E35C334ULL,
		0x8C5F2F6E0BB1E4B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC96EDBCEE3886359ULL,
		0xEC1FA56F7AF857A3ULL,
		0x3FFCE0D0613490BFULL,
		0x99E30E978FDD7B69ULL,
		0xEB9EC967EBDFD863ULL,
		0x87F16765C9D9047DULL,
		0x529F76271752D728ULL,
		0x626CA5577D6158AEULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6FD12D8DD9D0296ULL,
		0x7880107C11B628B3ULL,
		0x8BE326953EDEA762ULL,
		0x8F408D3A01E9764DULL,
		0x1C61BC57F24CCC8CULL,
		0x263663AD41687AF0ULL,
		0x72C0870CEE6B232DULL,
		0x07167F209B756189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78AF317F3833EDEEULL,
		0x003BC3F84E3D4BC0ULL,
		0xCAF250E8E57BABF6ULL,
		0x775457F90CEAC2E5ULL,
		0xE40A86F1DCCAD6F8ULL,
		0xF7F3413EE095AC02ULL,
		0x4C84A7E81D103C70ULL,
		0x6C1320BF36A80A99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE5223A7E5AEEF78ULL,
		0x78BBD3845F8B6373ULL,
		0x4111767DDBA50C94ULL,
		0xF814DAC30D03B4A8ULL,
		0xF86B3AA62E861A74ULL,
		0xD1C52293A1FDD6F2ULL,
		0x3E4420E4F37B1F5DULL,
		0x6B055F9FADDD6B10ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB36D8BEF25E3DEAAULL,
		0xB0A78DC9A1DA2EECULL,
		0x07CCF2FEBABCC0F0ULL,
		0x8DD3E07418701FC2ULL,
		0x92015B59EC361D4AULL,
		0x4FEB6FC93208049DULL,
		0x2EE885EAF04FA7EBULL,
		0x2CB2E3980ABD3368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A5855EDEF219832ULL,
		0x7B41BD34E1CB4F32ULL,
		0xE9FB1B2FAD4AEFA5ULL,
		0x260C21C1153579BFULL,
		0x82CA3E34092B6C5BULL,
		0x085B98D65F69CB33ULL,
		0x4B4D243DE4B2ADF2ULL,
		0xEF616D87514C0A66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE935DE02CAC24698ULL,
		0xCBE630FD401161DEULL,
		0xEE37E9D117F62F55ULL,
		0xABDFC1B50D45667DULL,
		0x10CB656DE51D7111ULL,
		0x47B0F71F6D61CFAEULL,
		0x65A5A1D714FD0A19ULL,
		0xC3D38E1F5BF1390EULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE0F534536549BB94ULL,
		0xAED4F82969F6139CULL,
		0xF52A7CD35CA9FC77ULL,
		0x54FE14457076B2C9ULL,
		0xCA52AD4DC1FEF84EULL,
		0x4B846DAD042411F3ULL,
		0xD2BD2F39719F3F61ULL,
		0x18F88683C129E704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE333276012C8F723ULL,
		0xEFD82E8BDF8BBD3FULL,
		0x449DBCBF2E26C131ULL,
		0x47BA59195DCDF711ULL,
		0x245B08479C711652ULL,
		0xE942951579A79BEEULL,
		0xACE0FAA0E1D5C234ULL,
		0x2BC9389CD2A6DCD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03C6133377814CB7ULL,
		0x410CD6A2B67DAEA3ULL,
		0xB1B7C06C728F3D46ULL,
		0x13444D5C2DBB45D8ULL,
		0xEE09A50A5D8FEE1CULL,
		0xA2C6F8B87D838A1DULL,
		0x7E5DD599904AFD55ULL,
		0x3331BE1F138F3BD7ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0126ED655B0759DDULL,
		0x7A7D1C5D9DC8579AULL,
		0xC96E2924DBE08221ULL,
		0xFD479B830003F114ULL,
		0x563F4121468CDFE3ULL,
		0x551242BC0C8E2E56ULL,
		0xD31654FED9CF112DULL,
		0xD15A45029B24C082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B8B776B49C3ACCCULL,
		0xD4738B1E1435AE1DULL,
		0x51A1ACF222592A2FULL,
		0x7D48317A355A8D13ULL,
		0xAAD3225C20051208ULL,
		0xECD4165D7182B3A4ULL,
		0xFD960D54B1916115ULL,
		0x03267A5E254C80A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AAD9A0E12C4F511ULL,
		0xAE0E974389FDF987ULL,
		0x98CF85D6F9B9A80EULL,
		0x800FAAF935597C07ULL,
		0xFCEC637D6689CDEBULL,
		0xB9C654E17D0C9DF2ULL,
		0x2E8059AA685E7038ULL,
		0xD27C3F5CBE684021ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3D69C26CC1413C3EULL,
		0x033370BC8F4F12F0ULL,
		0x59844E90FFDB2437ULL,
		0x0C69453B1F11AD3BULL,
		0x4FD5FDD3757B34B2ULL,
		0xAA2DF7BDA75F2B3DULL,
		0x66F7B8E2BCF107B8ULL,
		0xA6DF2DD4BDAABCDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37ED2F0CF1A3F2F4ULL,
		0x570337837404FDA6ULL,
		0x0DAC5320981ABF61ULL,
		0x153F60293D5FE820ULL,
		0xE2014EA4F636746BULL,
		0xAC6D21B4B52EF0CCULL,
		0xB6288A44DA97D272ULL,
		0xEE940195B1CCC933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A84ED6030E2CECAULL,
		0x5430473FFB4BEF56ULL,
		0x54281DB067C19B56ULL,
		0x19562512224E451BULL,
		0xADD4B377834D40D9ULL,
		0x0640D6091271DBF1ULL,
		0xD0DF32A66666D5CAULL,
		0x484B2C410C6675E9ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x64C9B0DCD53AB5A2ULL,
		0x3F0F73B8C34C2015ULL,
		0xBA9B49544BB1B186ULL,
		0xBEACC226C16CDE0CULL,
		0x790B8631478BB604ULL,
		0x01565107F8AD44D8ULL,
		0xBEEDBB37EF09694BULL,
		0x881C5384FEF5632EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB128A346E3BB7AC7ULL,
		0xD6ED84667F284A19ULL,
		0x76C19B9F23142899ULL,
		0xD6C37B3DA04DD210ULL,
		0x36997FC102A0B89FULL,
		0xF378F1773A75F65EULL,
		0x38224C0511F79C60ULL,
		0xA435EC8717A4CE4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5E1139A3681CF65ULL,
		0xE9E2F7DEBC646A0CULL,
		0xCC5AD2CB68A5991FULL,
		0x686FB91B61210C1CULL,
		0x4F92F9F0452B0E9BULL,
		0xF22EA070C2D8B286ULL,
		0x86CFF732FEFEF52BULL,
		0x2C29BF03E951AD61ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x85CEC15F49F3858AULL,
		0xEEC558EACE6C9DDCULL,
		0xD5E3E0DB8DA6FB37ULL,
		0x1040F3C6780525E8ULL,
		0xFE317471F5A0BA2EULL,
		0xE8D430043EF63BF5ULL,
		0xAB8F8053AE6BA838ULL,
		0x68B1CF1C45856A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6AF7F99551A6629ULL,
		0xC9481D0882A079A5ULL,
		0x7F36C7198DADE4C5ULL,
		0xB1B33F0E39E3C19BULL,
		0x868265491AD3C37EULL,
		0xA7C5CC66297C7A12ULL,
		0x24E05849B9A7E551ULL,
		0xEE73C1DEDE323333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3361BEC61CE9E3A3ULL,
		0x278D45E24CCCE479ULL,
		0xAAD527C2000B1FF2ULL,
		0xA1F3CCC841E6E473ULL,
		0x78B31138EF737950ULL,
		0x4F11FC62178A41E7ULL,
		0x8F6FD81A17CC4D69ULL,
		0x86C20EC29BB75963ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4AE471FEC1A0C89DULL,
		0x6C7E955D82650FFCULL,
		0x47A5BFE37FCE9E3BULL,
		0xC730E36D8726DBC6ULL,
		0x2B7C125FC1143EB5ULL,
		0x4DC3480EDDB88189ULL,
		0x26756905B5E37F8FULL,
		0xF7197A144424BEF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64A44F7C753D72F8ULL,
		0xC51D0E85F32A09D4ULL,
		0x5EB884C2F26D9B6EULL,
		0xD4ABC8CDB4E527DAULL,
		0x02C16E1D15E5EDE4ULL,
		0x89DB9469F6CAF934ULL,
		0xC38939A21624C3C5ULL,
		0x50510CF5EF147BF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E403E82B49DBA65ULL,
		0xA9639BD8714F0628ULL,
		0x191D3B218DA30555ULL,
		0x139B2BA033C3FC1CULL,
		0x29BD7C42D4F1D351ULL,
		0xC418DC672B7278BDULL,
		0xE5FC50A7A3C7BC4AULL,
		0xA74876E1AB30C504ULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x93311D09B8441AC9ULL,
		0xC98EE219B8B6E302ULL,
		0x55AAE8EC36857ECFULL,
		0xE9C4E0096EB97E11ULL,
		0x9E603312C0EE43C2ULL,
		0x7555A47A35B1371CULL,
		0x95A53B207FE6C4BAULL,
		0x5022295206275D0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C746B6FA7F77E51ULL,
		0x7CF2551A738FF314ULL,
		0x531C8B11A7AAA1B6ULL,
		0x298F5D170B8E7625ULL,
		0xB620802179D0DB86ULL,
		0x7B88C64F25BBDD66ULL,
		0x8DCB2423501B9AF3ULL,
		0xEAA20ED4621CF420ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F4576661FB36498ULL,
		0xB57CB703CB391016ULL,
		0x06B663FD912FDF79ULL,
		0xC04BBD1E65370834ULL,
		0x2840B333B93E9844ULL,
		0x0EDD6235100AEA7AULL,
		0x186E1F032FFD5E49ULL,
		0xBA802786643BA92BULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x37C9B7B5D5B4CB01ULL,
		0x99B8C41A745C68E1ULL,
		0xA7D9171AAA14E815ULL,
		0x7A3DEABB4A0C8C46ULL,
		0x195A6F6FDD2E79F6ULL,
		0xDBAB1B4C41305835ULL,
		0xCE2C2EB6DC6C1263ULL,
		0x14FE395956D72E3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916890C08CC0AF3CULL,
		0x158A6BEA644FD02AULL,
		0xD7542E2C488DFA71ULL,
		0x709383974414778FULL,
		0xFA0539E0320ADA59ULL,
		0x22EB2DB37FDCEB87ULL,
		0x8E903FBEE845394EULL,
		0xFF969A8CF8BDF6E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6A127755974643DULL,
		0x8C32AFF01013B8CBULL,
		0x708D3936E2991264ULL,
		0x0AAE692C0E18FBC9ULL,
		0xE35F568FEF24A3AFULL,
		0xF94036FF3EECB3B2ULL,
		0x40BC110834292B2DULL,
		0xEB68A3D5AE6AD8D6ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2C12A92C61F8390BULL,
		0x3A0FB421E1150EA7ULL,
		0x0B7C16A64EB744D8ULL,
		0x8FE7892FA35F3A9BULL,
		0x6DC7AD2DEA419EABULL,
		0x52D68D3CEF0D3680ULL,
		0x46F9506E8ACFE35CULL,
		0x9272C587290CAC98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD482A8D0F038377BULL,
		0x64768EB847323F6EULL,
		0x6B60303B3E28811DULL,
		0x1DD931A42E52EBCDULL,
		0x883034B7EBC545A4ULL,
		0xD18D4978602547BFULL,
		0xC0D25553ACECF0C1ULL,
		0x7310008F9CBD7983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF89001FC91C00E70ULL,
		0x5E793A99A62731C9ULL,
		0x601C269D709FC5C5ULL,
		0x923EB88B8D0DD156ULL,
		0xE5F7999A0184DB0FULL,
		0x835BC4448F28713FULL,
		0x862B053D2623139DULL,
		0xE162C508B5B1D51BULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC92DF13BE925F421ULL,
		0x410A0497C8907EF9ULL,
		0x0540D803345BF1D4ULL,
		0x60CD79F4E7F503C7ULL,
		0x9BD675CB1EB8C52EULL,
		0x77727F4BC3F2FB5BULL,
		0x9023C01065C05460ULL,
		0x93308F3B85A3E79BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA1BE83D0280302ULL,
		0x8FE6D8E8B091279EULL,
		0xFD49B6E3252C4FA7ULL,
		0x8F22E493FAC507ABULL,
		0x6C9299870F581A52ULL,
		0x7A3538DABF08D8E4ULL,
		0xF8591EB7A94AF72FULL,
		0x6C95D002A4D8E1BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC78C4FB8390DF723ULL,
		0xCEECDC7F78015967ULL,
		0xF8096EE01177BE73ULL,
		0xEFEF9D671D30046CULL,
		0xF744EC4C11E0DF7CULL,
		0x0D4747917CFA23BFULL,
		0x687ADEA7CC8AA34FULL,
		0xFFA55F39217B0626ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2F026A0678346567ULL,
		0x2547D4A0ACEE6F8DULL,
		0xBFF745994A2E7AFDULL,
		0xE2175E5923E15C98ULL,
		0xF77BDE590ED12C19ULL,
		0x96AB5DF6351CC674ULL,
		0x39941C97AB75A059ULL,
		0xB922DF61F5A75E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3245274EAF2724C7ULL,
		0xAE8CB44CA7969FCEULL,
		0xFBF1DB7D6E78729EULL,
		0xAB3E02D551706FA4ULL,
		0xDC1411399FC5705DULL,
		0xE66F9372AC80E79EULL,
		0x3C5CAD32E4B951CBULL,
		0x485E96DEC9F0779EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D474D48D71341A0ULL,
		0x8BCB60EC0B78F043ULL,
		0x44069EE424560863ULL,
		0x49295C8C7291333CULL,
		0x2B6FCF6091145C44ULL,
		0x70C4CE84999C21EAULL,
		0x05C8B1A54FCCF192ULL,
		0xF17C49BF3C5729D9ULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE9A2B74EA9127D92ULL,
		0x8D91549B391416A7ULL,
		0x68510BE9AF45868AULL,
		0x800F0822D0FFB170ULL,
		0x3322257CB36C9600ULL,
		0x6F0C31689F752F47ULL,
		0xBD45ED17C7E17624ULL,
		0x9BA4A55170378DF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0009365B0C5436E4ULL,
		0xD6AC27A89826B792ULL,
		0xF0FC54B7F9969C95ULL,
		0x1593A4A4290D8CCDULL,
		0x5043C52849630C1AULL,
		0x9774C195998F2BC2ULL,
		0xD8D9178807DB6378ULL,
		0xD2C058231EF5D4ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9AB8115A5464B76ULL,
		0x5B3D7333A132A135ULL,
		0x98AD5F5E56D31A1FULL,
		0x959CAC86F9F23DBDULL,
		0x6361E054FA0F9A1AULL,
		0xF878F0FD06FA0485ULL,
		0x659CFA9FC03A155CULL,
		0x4964FD726EC2595EULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2EAF7407D0A60D85ULL,
		0xF7C74A56A2C2745CULL,
		0xE854BE664FCDC994ULL,
		0x4D9B153C93674416ULL,
		0x399CA72E93EDDDD8ULL,
		0x1E0E6BA9D59B859DULL,
		0x4D373BE94CF7C646ULL,
		0x3455943ADB15DC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC75C4BBA9D0579FFULL,
		0xA113415853504466ULL,
		0x5F6B946FE6C8F809ULL,
		0x3BD6924CEBCD9B2BULL,
		0x97ABD2C4B5E94340ULL,
		0xE6F1DE29A2D5EA8BULL,
		0x7F78A2BAA47BEA25ULL,
		0x04C09D2DBCE5B2A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9F33FBD4DA3747AULL,
		0x56D40B0EF192303AULL,
		0xB73F2A09A905319DULL,
		0x764D877078AADF3DULL,
		0xAE3775EA26049E98ULL,
		0xF8FFB580774E6F16ULL,
		0x324F9953E88C2C63ULL,
		0x3095091767F06EB6ULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5E50C883124EE611ULL,
		0x5A1F66F56D98EF01ULL,
		0x05C93BBBE1F20220ULL,
		0x2F9E3739E54C7BE8ULL,
		0x31F04A45950489CFULL,
		0x5963051338C205B5ULL,
		0x29F16CB012BED5B7ULL,
		0x5AAF2AA7D1F456F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD725FC0E2F8DCDE5ULL,
		0xC1B7FF0FECCD5786ULL,
		0xA227D676B255BC59ULL,
		0x74E7DA0A0F64E27FULL,
		0x3FF9D776649BC687ULL,
		0x5F719298B3D9AFF7ULL,
		0x9942FA8038FC537EULL,
		0x4BB1F1E9D832887CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8975348D3DC32BF4ULL,
		0x9BA899FA8155B887ULL,
		0xA7EEEDCD53A7BE79ULL,
		0x5B79ED33EA289997ULL,
		0x0E099D33F19F4F48ULL,
		0x0612978B8B1BAA42ULL,
		0xB0B396302A4286C9ULL,
		0x111EDB4E09C6DE8AULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8F44B2A71FA16473ULL,
		0x3A7A0248690B4610ULL,
		0x58AC9B26CC9CD832ULL,
		0xC41A480AB1AF41CEULL,
		0xDB51510B71261018ULL,
		0xE84BE8BC0CC53AE2ULL,
		0x3C446B39810B1B55ULL,
		0x8949535559FA97C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92143543089D239ULL,
		0xFB64B8D9930F2B36ULL,
		0xC3DC290E37957019ULL,
		0x126ACC14F6551C18ULL,
		0x0D6C1392EB364AF9ULL,
		0x80B2543FD412BE3BULL,
		0xF82D9D32727A4360ULL,
		0xBDFD9120048F8428ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6665F1F32F28B64AULL,
		0xC11EBA91FA046D26ULL,
		0x9B70B228FB09A82BULL,
		0xD670841E47FA5DD6ULL,
		0xD63D42999A105AE1ULL,
		0x68F9BC83D8D784D9ULL,
		0xC469F60BF3715835ULL,
		0x34B4C2755D7513EFULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x56D854483D1CFA60ULL,
		0x46EDD604C919E81EULL,
		0x19BAC1FEE44CFF52ULL,
		0xD5618D330813082CULL,
		0x8E09031186EDBC19ULL,
		0xB6175DE4042EABC4ULL,
		0x7ED2DD79833D8FF5ULL,
		0xC1515A7D1A29A161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82ACB29AE640AD98ULL,
		0xD27319211091394CULL,
		0x319155A0D9951EFFULL,
		0xDE07F395CD9CE276ULL,
		0x7697E8BD0334ECA2ULL,
		0x96FD3D3640E813BBULL,
		0x331229DB23553280ULL,
		0xE6E4954244BCCC02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD474E6D2DB5C57F8ULL,
		0x949ECF25D988D152ULL,
		0x282B945E3DD9E1ADULL,
		0x0B667EA6C58FEA5AULL,
		0xF89EEBAC85D950BBULL,
		0x20EA60D244C6B87FULL,
		0x4DC0F4A2A068BD75ULL,
		0x27B5CF3F5E956D63ULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC60E93A735A9F3A4ULL,
		0x1420C67F68BF5EB0ULL,
		0x511CCA752CF74469ULL,
		0xAB87414BD68ABBA8ULL,
		0x1C8EA614BF822AACULL,
		0x6EF51CB3E55EAF11ULL,
		0xBCDB598285AEAD59ULL,
		0xC3EE123F3A950886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72C26D1B05490964ULL,
		0xF2FFCD883C8BA983ULL,
		0x599D01CFE70E003FULL,
		0xB457305AF1B0E65BULL,
		0x210011F8DABD55EAULL,
		0x5072A5FA2E9ED1DFULL,
		0x6E30D4FB19E23EDBULL,
		0x60491EEFB3A19F25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4CCFEBC30E0FAC0ULL,
		0xE6DF0BF75434F733ULL,
		0x0881CBBACBF94456ULL,
		0x1FD07111273A5DF3ULL,
		0x3D8EB7EC653F7F46ULL,
		0x3E87B949CBC07ECEULL,
		0xD2EB8D799C4C9382ULL,
		0xA3A70CD0893497A3ULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB45DC6433513F041ULL,
		0x7227D925001CC40BULL,
		0xABF42EDFCAAF1CA4ULL,
		0x733FFB5015037420ULL,
		0x0590CE637AD352ADULL,
		0xC5D7E2C4EDF032C6ULL,
		0xE2F915A71A731B12ULL,
		0x30974019358D1A0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8B5A636E2E3A43ULL,
		0x30C7421535FA3B30ULL,
		0xAF270B396C2D8BA2ULL,
		0x193B328155E93029ULL,
		0xD73186A8FD25A3E6ULL,
		0x6D17CD725828D649ULL,
		0xB0B0C3713DF4DCD6ULL,
		0xE4F70DE05BC04F62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDED69C205B3DCA02ULL,
		0x42E09B3035E6FF3BULL,
		0x04D325E6A6829706ULL,
		0x6A04C9D140EA4409ULL,
		0xD2A148CB87F6F14BULL,
		0xA8C02FB6B5D8E48FULL,
		0x5249D6D62787C7C4ULL,
		0xD4604DF96E4D5568ULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB7ADF5EE5A1BA340ULL,
		0x5837A08FD811FBFFULL,
		0xF823C68CF4D94173ULL,
		0x76E0B086B52076A1ULL,
		0x1B53B5019505E2CCULL,
		0xE8740515D2834729ULL,
		0x58EAA4B0C3605348ULL,
		0xE9DCE2C2197C28A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2526BF7CA141A1C5ULL,
		0xC06547078EF0DDBDULL,
		0x82FE1D026BC6346EULL,
		0xF4CB68688E624552ULL,
		0x705EBB56635D4EBAULL,
		0x264D7364413FF61FULL,
		0xA9B0EEEE5A199496ULL,
		0x3B80145A8CA29E3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x928B4A92FB5A0285ULL,
		0x9852E78856E12642ULL,
		0x7ADDDB8E9F1F751DULL,
		0x822BD8EE3B4233F3ULL,
		0x6B0D0E57F658AC76ULL,
		0xCE39767193BCB136ULL,
		0xF15A4A5E9979C7DEULL,
		0xD25CF69895DEB69AULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF01FD1F85EB96B6DULL,
		0xA641BACECD71F73DULL,
		0x6E36C598EACEA1F7ULL,
		0x12D64D9A981C8048ULL,
		0xE2C1AE4B16557A6CULL,
		0x86F672387ABB30DDULL,
		0x13B543059E4B2C2CULL,
		0xF8020B98A0FBDAFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0544B73A2606BE92ULL,
		0x037EDE8F1732902DULL,
		0x5763F2491C7D19FEULL,
		0xFE06632B8B3FC2A7ULL,
		0x4D34532192C4BCA8ULL,
		0xA6EF9782579032B2ULL,
		0xFF3847D7888A3D47ULL,
		0xA994019FD31F4B05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF55B66C278BFD5FFULL,
		0xA53F6441DA436710ULL,
		0x395537D1F6B3B809ULL,
		0xECD02EB1132342EFULL,
		0xAFF5FD6A8491C6C4ULL,
		0x2019E5BA2D2B026FULL,
		0xEC8D04D216C1116BULL,
		0x51960A0773E491FEULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB530B5BA7E5A4424ULL,
		0x44D3BAEA8A31C96FULL,
		0xBC99E6B981084D99ULL,
		0xA2140EB70CAA9FAAULL,
		0x285ECBAFAB78E4FFULL,
		0x5D5BA3F1501BDB73ULL,
		0xBEF099CD128C4E56ULL,
		0xB635CB52E5597FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3041F3284E8600ULL,
		0xFDE6621AACE1A6D5ULL,
		0xD471E42334DA61C7ULL,
		0x71BE2ECAF8C017BBULL,
		0xEBB4B0B1714EB432ULL,
		0x022ECC4C8B556753ULL,
		0x10B41180F0212D14ULL,
		0x281D7051EFDE0650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3900F4495614C224ULL,
		0xB935D8F026D06FBAULL,
		0x68E8029AB5D22C5EULL,
		0xD3AA207DF46A8811ULL,
		0xC3EA7B1EDA3650CDULL,
		0x5F756FBDDB4EBC20ULL,
		0xAE44884DE2AD6342ULL,
		0x9E28BB030A8779B3ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4691EB15B13F181BULL,
		0x3F3624033A62321CULL,
		0x6D1F3677FFCA5649ULL,
		0x9F8C61B2DCDC24F5ULL,
		0x7CFD5478F9E8DA4AULL,
		0xD4E8E393417227E4ULL,
		0xCAEAE6D8D099B3E8ULL,
		0xFFE89B5ADBB80982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658D688B418FDF50ULL,
		0x26C60A0ADA44E3AEULL,
		0x72570E967542813DULL,
		0x9704608239500304ULL,
		0xAD02B3382A4DEDF9ULL,
		0x82E230874D9CADBBULL,
		0xC4CC4A9D8CEA969CULL,
		0xCC24AEB94A05DC63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x231C839EF0B0C74BULL,
		0x19F02E09E026D1B2ULL,
		0x1F4838E18A88D774ULL,
		0x08880130E58C27F1ULL,
		0xD1FFE740D3A537B3ULL,
		0x560AD3140CEE8A5FULL,
		0x0E26AC455C732574ULL,
		0x33CC35E391BDD5E1ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB5DCD1EF5A21EC43ULL,
		0x1AEAC6EE6C3BD1F9ULL,
		0x705B4835F6D9B1E4ULL,
		0x75BC865DFDA313E4ULL,
		0x4CC0E352B0AB59A8ULL,
		0xE87B401706343571ULL,
		0x056F5C7DDCDBE08BULL,
		0x4AA611ACF1C48841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36F693B5567AAF6DULL,
		0x64F004014B18FA12ULL,
		0xCEDF997DC392B8E5ULL,
		0x74164AA598A9E958ULL,
		0x0B23A72980E28905ULL,
		0xF580780BCDE75E0DULL,
		0x6BECB3F3ADF83520ULL,
		0xF99F582FBF834F68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x832A425A0C5B432EULL,
		0x7E1AC2EF27232BEBULL,
		0xBE84D148354B0901ULL,
		0x01AACCF8650AFABCULL,
		0x47E3447B3049D0ADULL,
		0x1DFB381CCBD36B7CULL,
		0x6E83EF8E7123D5ABULL,
		0xB33949834E47C729ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5554B651B33ADA1EULL,
		0x6226E3691108F05EULL,
		0x8E646F8E2E174376ULL,
		0x62D826392FF26E8DULL,
		0x59EA74D1A28EA32BULL,
		0x18593F5DE2217DB6ULL,
		0x88CFB826EB814ED8ULL,
		0x4B8A28AB2630598EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7547A8D8081AD8EDULL,
		0xA0F28CEC56C0F219ULL,
		0x8B349491D274326EULL,
		0xF5BF16B0CA92CDF8ULL,
		0x86DC24EDF4250756ULL,
		0xA958E0422EB4EAF3ULL,
		0x325207346E51FB74ULL,
		0xBE398213D21E23F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20131E89BB2002F3ULL,
		0xC2D46F8547C80247ULL,
		0x0550FB1FFC637118ULL,
		0x97673089E560A375ULL,
		0xDF36503C56ABA47DULL,
		0xB101DF1FCC959745ULL,
		0xBA9DBF1285D0B5ACULL,
		0xF5B3AAB8F42E7A77ULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x80F2DE3720B362C2ULL,
		0xE913985FF0AB79FAULL,
		0x273772F04341A2EEULL,
		0x7A0EA2E982363410ULL,
		0x81B4586B270537D7ULL,
		0x69292A8665179C98ULL,
		0xD30432E47DEC8484ULL,
		0x4723B835F51C0357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C3323DEA2CA45C8ULL,
		0x7B590FFA1C4A1C8FULL,
		0xED8251E9FAAC7CA6ULL,
		0x90918FF5D74F1AE7ULL,
		0x29746DBD843CF8F6ULL,
		0x03BEFDB25505D1B1ULL,
		0x8F64C8E71A2F21A3ULL,
		0x9782D9198460F50FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCC1FDE98279270AULL,
		0x924A97A5ECE16575ULL,
		0xCAB52319B9EDDE48ULL,
		0xEA9F2D1C55792EF7ULL,
		0xA8C035D6A339CF21ULL,
		0x6A97D73430124D29ULL,
		0x5C60FA0367C3A527ULL,
		0xD0A1612C717CF658ULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x499814FB65703D22ULL,
		0x7AB7F0983603D63CULL,
		0x88097248B7D0E547ULL,
		0x213C85042F26CF31ULL,
		0xDC842F0B67785F4CULL,
		0x0626B422EDF8688FULL,
		0x345552052B0AB8FEULL,
		0x1F7E4A2389768965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6CC0C1B98C68C50ULL,
		0x8E5A4A3411EFA873ULL,
		0x12D905A8E63890F8ULL,
		0x419A8E0CFFB939CCULL,
		0x6D2329F3CEBE24D7ULL,
		0xC8DBAC738D8D1627ULL,
		0x80CE48A2F5962540ULL,
		0x794B5E94D40DD090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF5418E0FDB6B172ULL,
		0xF4EDBAAC27EC7E4FULL,
		0x9AD077E051E875BFULL,
		0x60A60B08D09FF6FDULL,
		0xB1A706F8A9C67B9BULL,
		0xCEFD185160757EA8ULL,
		0xB49B1AA7DE9C9DBEULL,
		0x663514B75D7B59F5ULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6D2DD92B2FD4F5CEULL,
		0x7F54E771422A26A3ULL,
		0x77C8073967CECE67ULL,
		0x2A628FA50F136620ULL,
		0x9B716A97F5BB28A6ULL,
		0x1F487758939EDD97ULL,
		0x79799AF798B8473DULL,
		0x1B35BE0CF42A69B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB09F52A7BD57ADULL,
		0x4E9F34B526EB5018ULL,
		0x10A81AA02A0CCFD7ULL,
		0x4FC2F246E35D119DULL,
		0xB3A9D4FE4FDF79F3ULL,
		0xB4692EF6EE289873ULL,
		0xED9E343D8B3D017DULL,
		0x9EC97FD17E53A61EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC69D46798869A263ULL,
		0x31CBD3C464C176BBULL,
		0x67601D994DC201B0ULL,
		0x65A07DE3EC4E77BDULL,
		0x28D8BE69BA645155ULL,
		0xAB2159AE7DB645E4ULL,
		0x94E7AECA13854640ULL,
		0x85FCC1DD8A79CFAFULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF8091C557CD019E0ULL,
		0xB4F5436FADF317C2ULL,
		0x9EC40ADE71BCD525ULL,
		0x57D10782B5CBD0FCULL,
		0x88EF0DCA1414E223ULL,
		0x650F230D0CF1D7CAULL,
		0xE6062317D5CF2B0FULL,
		0xD06513167ABF55B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE3C0F822751E6B1ULL,
		0xCA0FBD23F1E02F76ULL,
		0xDF50F756919270E7ULL,
		0x5C86850DC65D5956ULL,
		0xE514E6AFC8A0F870ULL,
		0x3267C8863B5730F4ULL,
		0x4B9710CE34E4538DULL,
		0x6322712E20FBD0B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x063513D75B81FF51ULL,
		0x7EFAFE4C5C1338B4ULL,
		0x4194FD88E02EA5C2ULL,
		0x0B57828F739689AAULL,
		0x6DFBEB65DCB41A53ULL,
		0x5768EB8B37A6E73EULL,
		0xAD9133D9E12B7882ULL,
		0xB34762385A448501ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x57B5179B416B370FULL,
		0x85F382EA0130ADC1ULL,
		0x2AEF7253F44BCA12ULL,
		0x94B05334B3A6A8CEULL,
		0x8EA1F231BA6B0437ULL,
		0x68473A150C049F1DULL,
		0x4C07A2EFFE553FA1ULL,
		0x81A68DDAE33AD082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B50DBDF91484D88ULL,
		0xB0F7F8A641C0ABFAULL,
		0x72F8581CB4D491FDULL,
		0x028108C41B4E3102ULL,
		0xEF7A1A9D67FEBAAAULL,
		0xBFB3AA0E8CDF87B6ULL,
		0x43995183BEAF41DFULL,
		0x0DF6ED5F04AACC67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CE5CC44D0237A87ULL,
		0x35047A4C40F0063BULL,
		0x58172A4F409F5BEFULL,
		0x96315BF0A8E899CCULL,
		0x61DBE8ACDD95BE9DULL,
		0xD7F4901B80DB18ABULL,
		0x0F9EF36C40FA7E7EULL,
		0x8C506085E7901CE5ULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x663B3E31ABEEE700ULL,
		0xBE091A7659E64748ULL,
		0xEC1F29FDAC7E5F1FULL,
		0x2ED13F6D58081472ULL,
		0x5C5E0988D0D22986ULL,
		0xB2369FB87164F4C9ULL,
		0x020250F9C2538DAFULL,
		0x6B0C7D026852EC4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3056B7FE0C90CA28ULL,
		0x5F2D51CA6693A819ULL,
		0xE86FB5B6EF9609DFULL,
		0x6AD14C23EDC97568ULL,
		0xB441EB3BB524E2C9ULL,
		0x2FD493C3534B3F15ULL,
		0x89EDB718B20269D1ULL,
		0x6137155DAE26AB7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x566D89CFA77E2D28ULL,
		0xE1244BBC3F75EF51ULL,
		0x04709C4B43E856C0ULL,
		0x4400734EB5C1611AULL,
		0xE81FE2B365F6CB4FULL,
		0x9DE20C7B222FCBDCULL,
		0x8BEFE7E17051E47EULL,
		0x0A3B685FC6744731ULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9A2FE09F15A96C4DULL,
		0x6B149895AB058FF7ULL,
		0xB5014DE9EA2BFE47ULL,
		0x95D4AF5084E81F1EULL,
		0x79FD30D1EC636911ULL,
		0xAF76D82E1465F6A2ULL,
		0x78B901619EF53D44ULL,
		0xE97AC544CC698D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22C06C43A1626817ULL,
		0xD251995B6A3FC6F9ULL,
		0x844E75DD14D5B04BULL,
		0x088C4D7D68670299ULL,
		0xB8C9A4EA6F1AD440ULL,
		0x28F8E68FE5CCDA70ULL,
		0x52A49442EF981B56ULL,
		0x75C86E63EA010801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8EF8CDCB4CB045AULL,
		0xB94501CEC13A490EULL,
		0x314F3834FEFE4E0CULL,
		0x9D58E22DEC8F1D87ULL,
		0xC134943B8379BD51ULL,
		0x878E3EA1F1A92CD2ULL,
		0x2A1D9523716D2612ULL,
		0x9CB2AB272668853DULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6EC900C10FDD7272ULL,
		0x7773CF03EAA86BBFULL,
		0x0CE3716659392948ULL,
		0x783A3391E9DDEDC5ULL,
		0x04C40E7516350F65ULL,
		0xFB0990138F1B28C1ULL,
		0xB58FD1FC02A585F0ULL,
		0x2804E4281B370488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0241FCBFEFF0EB0FULL,
		0x35D861B6BBA6A04EULL,
		0x7B97719691657672ULL,
		0xE7AF3AFE50589297ULL,
		0x6C46F09892766AF0ULL,
		0x88AB6DAEF8D37E39ULL,
		0x4546E1455154CEE7ULL,
		0x57C2B007127089DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C88FC7EE02D997DULL,
		0x42ABAEB5510ECBF1ULL,
		0x777400F0C85C5F3AULL,
		0x9F95096FB9857F52ULL,
		0x6882FEED84436595ULL,
		0x73A2FDBD77C856F8ULL,
		0xF0C930B953F14B17ULL,
		0x7FC6542F09478D57ULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3FA4DF27115E3E56ULL,
		0x5FD7CADF4303C8FEULL,
		0xA3F957AE3E3F50C1ULL,
		0x637A6BF0A4D2851DULL,
		0x84AEDC05FC25DD54ULL,
		0x92A1EF6716CEEB3BULL,
		0x138CDD9A54130A9CULL,
		0x7DEDFC86EEEE3017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57442853448D9131ULL,
		0xBCB88D6167ADF0AEULL,
		0x8BAA7636B402818CULL,
		0xB5E1F3C9CA6A70D7ULL,
		0xC673733CCB2D3C89ULL,
		0xF15D07A3D2F353B3ULL,
		0x4790C06C6CFAABE3ULL,
		0x7529E7EC1290D0AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68E0F77455D3AF67ULL,
		0xE36F47BE24AE3850ULL,
		0x285321988A3DD14DULL,
		0xD69B98396EB8F5CAULL,
		0x42DDAF393708E1DDULL,
		0x63FCE8C4C43DB888ULL,
		0x541C1DF638E9A17FULL,
		0x08C41B6AFC7EE0B9ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB85C709E3D98079DULL,
		0x3CEF086699F50CC3ULL,
		0x3ED920CC8576D4CBULL,
		0x8C86866C24CB7ECFULL,
		0xE4CFFD1702A9036CULL,
		0xFB58A0B70764C20FULL,
		0x06BE6EAE74C9DE58ULL,
		0x781C8A19F8260B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EE3220FF297B11ULL,
		0x3DD461FDB560733BULL,
		0x6C10687DE4D5AB4DULL,
		0x5C01E03CEA9EB57AULL,
		0xC551D03734E220D4ULL,
		0x608D8A6C6C263A68ULL,
		0x9BC65CDDDD042008ULL,
		0x411FF8385884CC8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB242BEC2B17C8CULL,
		0x013B699B2C957FF8ULL,
		0x52C948B161A37F86ULL,
		0xD0876650CE55CBB5ULL,
		0x219E2D20364B23B8ULL,
		0x9BD52ADB6B42F867ULL,
		0x9D783273A9CDFE50ULL,
		0x39037221A0A2C786ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF7E48B80DF86147CULL,
		0xC035F52748C4DC1BULL,
		0x046F396A30C97ED9ULL,
		0xDBBACABE959CDBBBULL,
		0xFF3DEA1E6ACDFAB1ULL,
		0xEB515AC4B1D3F582ULL,
		0xD6D9964C64525E70ULL,
		0x4EB7CBCBD211316CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE9A48D9F6077A68ULL,
		0xDA5F8A92FFD963AFULL,
		0x8DFC682C28FAE8B2ULL,
		0x4E2934110A52BC88ULL,
		0x2D1EF26800385405ULL,
		0x1CCF833FAC92EC31ULL,
		0x0703B4D4B97354D9ULL,
		0xEE7BFA67A252A496ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x497EC35929816E14ULL,
		0x1A6A7FB5B71DBFB4ULL,
		0x899351461833966BULL,
		0x9593FEAF9FCE6733ULL,
		0xD22318766AF5AEB4ULL,
		0xF79ED9FB1D4119B3ULL,
		0xD1DA2298DD210AA9ULL,
		0xA0CC31AC704395FAULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3626C6FE756AAF60ULL,
		0x32D79B2D62BCAAD7ULL,
		0xAE455F9DE45EE683ULL,
		0x62BAA059F9457ACDULL,
		0x4B6D0235E918FC22ULL,
		0x054956DC1AE4FCA5ULL,
		0x59798D94466A6205ULL,
		0xE0C2F6E31E7B6D27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13984B25E2A9D156ULL,
		0x6DA480198D4C47D2ULL,
		0x12F82DF8493F7D94ULL,
		0xC69CDEC98ADE2B79ULL,
		0x4A9FAA9CADD587C5ULL,
		0xDD580BD37B2D01E1ULL,
		0x6C5AC10F6DBAAC77ULL,
		0x2B4CED3C19F5A3FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25BE8DDB97C37E36ULL,
		0x5F731B34EFF0ED05ULL,
		0xBCBD7265AD619B17ULL,
		0xA4267E90739B51B4ULL,
		0x01F2A8A944CD7BE7ULL,
		0xD8115D0F61C9FD44ULL,
		0x35234C9B2BD0CE72ULL,
		0xCB8E1BDF078ECEDAULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x066717C4F997DA5CULL,
		0x2DD6A7709D6C5C22ULL,
		0xB2513D7E465A00B4ULL,
		0x0CBE6284A1663783ULL,
		0xE86E9C1ECEA1418EULL,
		0x51C91D5122311D26ULL,
		0x1FB567DBD621316CULL,
		0x67793B2773A0E4AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E658AC5F813CED7ULL,
		0x221C774C8A091BDCULL,
		0x9C82762D8873462FULL,
		0xAAE64F864E6FE395ULL,
		0x45D8E278DFCCBE1DULL,
		0x6479EC904531370AULL,
		0x5D021A3A47BCF041ULL,
		0x093AF2B25C9FF146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78029D010184148BULL,
		0x0FCAD03C176547FEULL,
		0x2ED34B53CE29469BULL,
		0xA6582D02EF09D416ULL,
		0xADB67E66116DFF93ULL,
		0x35B0F1C167002A2CULL,
		0x42B77DE1919DC12DULL,
		0x6E43C9952F3F15ECULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDB8569F9B21009C7ULL,
		0x71B7B55EBFC78CF3ULL,
		0x71AD5F34629FA782ULL,
		0x7F6DC9C8B660246FULL,
		0x0803B98CFEB8DFB5ULL,
		0x7C56B9408E25BA3EULL,
		0x36746326578239A0ULL,
		0x39BE6ABCE73F905BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2A0EDFA7744CFDCULL,
		0x649203406426C89BULL,
		0xA602550B1152BDE5ULL,
		0x3E461869154EB383ULL,
		0x6E96FAA1D7FD38D2ULL,
		0xF08EA66D87BC3135ULL,
		0xEA15D339596CE546ULL,
		0x5837B737C801BFABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29258403C554C61BULL,
		0x1525B61EDBE14468ULL,
		0xD7AF0A3F73CD1A67ULL,
		0x412BD1A1A32E97ECULL,
		0x6695432D2945E767ULL,
		0x8CD81F2D09998B0BULL,
		0xDC61B01F0EEEDCE6ULL,
		0x6189DD8B2F3E2FF0ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x18C4BEB9311D2FBFULL,
		0x31D16F7EC330689BULL,
		0x3C715DEC46115969ULL,
		0xE29E95D79855DFAEULL,
		0x98FE16A507745063ULL,
		0xBF15E0253B6B83FEULL,
		0x5E33D3CB6ECB837EULL,
		0x961CDB3670BF9323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A7E5DCD0C0B6D9ULL,
		0x6234D4DCF8DE9978ULL,
		0x0B463BD821F5BE18ULL,
		0xED718ACB21EFFCA5ULL,
		0xEADB17CEFF2C524CULL,
		0x813B5335EDFA85A0ULL,
		0x06A07CCEB52BC87EULL,
		0x153C35FD3789E9E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF635B65E1DD9966ULL,
		0x53E5BBA23BEEF1E3ULL,
		0x3737663467E4E771ULL,
		0x0FEF1F1CB9BA230BULL,
		0x7225016BF858022FULL,
		0x3E2EB310D691065EULL,
		0x5893AF05DBE04B00ULL,
		0x8320EECB47367AC0ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA569B6A9D39CA706ULL,
		0x954A8863D8C3E8EFULL,
		0x12243483101EB608ULL,
		0x5CF4F576E536E2B2ULL,
		0x295FE0555F7A51B8ULL,
		0x57F38153172C50F0ULL,
		0xDBA31701213CED2DULL,
		0xE447B299F3159E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB23B5F5A924B8C10ULL,
		0x1AE031CE87C4B72AULL,
		0x306A8B1F53C05D34ULL,
		0x5E032115E4F684EBULL,
		0x59C8CEC569014240ULL,
		0x32CBEF83AB12F2AFULL,
		0x4CF50F61CF371615ULL,
		0x92B423F06C12C65FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1752E9F341D72B16ULL,
		0x8FAAB9AD5F075FC5ULL,
		0x224EBF9C43DEEB3CULL,
		0x02F7D46301C06659ULL,
		0x70972E90367B13F8ULL,
		0x65386ED0BC3EA25FULL,
		0x97561860EE0BFB38ULL,
		0x76F391699F075828ULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2AE3410484F5DC0AULL,
		0x704B3ED1D98F4FFDULL,
		0xCDFF4DC43501D696ULL,
		0xD7FC79505F9100ABULL,
		0xD00080BEFEB395B1ULL,
		0xDFB4F9A579D519D2ULL,
		0x5A68825F98B4A19FULL,
		0xEFDB77B6C796D266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x103BDB0450775F4DULL,
		0xFA3A0248D67CC5E6ULL,
		0xF6761A9FC3780454ULL,
		0xEC820209D18998CBULL,
		0xA59BD16742B262FFULL,
		0x99686C985BFA579FULL,
		0x1966B4C79043628BULL,
		0x8B25BED95361FCC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AD89A00D4828347ULL,
		0x8A713C990FF38A1BULL,
		0x3B89575BF679D2C2ULL,
		0x3B7E7B598E189860ULL,
		0x759B51D9BC01F74EULL,
		0x46DC953D222F4E4DULL,
		0x430E369808F7C314ULL,
		0x64FEC96F94F72EA1ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD3C3E90031BF63FEULL,
		0x830BA160880F5228ULL,
		0xAF6AB758DD1F28FFULL,
		0xBF00235748685018ULL,
		0xE04DACA166D7A4B1ULL,
		0x8261F3C90D1EDAC8ULL,
		0x9E9B21A1DCA763E6ULL,
		0x318773E97F5D5D1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x554C3D49A9AE0694ULL,
		0x940DB04335E0757DULL,
		0x1DBBEC71C077D5B3ULL,
		0xA2D8C5327E7877CBULL,
		0x65EA5551157BFBF5ULL,
		0x215F2F8B08016D96ULL,
		0xF5CB79368D723D60ULL,
		0xD3880FDE62922923ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x868FD4499811656AULL,
		0x17061123BDEF2755ULL,
		0xB2D15B291D68FD4CULL,
		0x1DD8E665361027D3ULL,
		0x85A7F9F073AC5F44ULL,
		0xA33EDC42051FB75EULL,
		0x6B50589751D55E86ULL,
		0xE20F7C371DCF743CULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x86D1ECDC8FDAD9E6ULL,
		0x1511D33E108B734CULL,
		0x6B01C6C8E80CC1D8ULL,
		0x220F3B8097E324F9ULL,
		0x7B29B1EC1D5CF9EBULL,
		0xE5A3E5A35DA520A2ULL,
		0xF6128295C1B93404ULL,
		0x67E4F0476F16EF6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49CA07C530655218ULL,
		0x47C395FCF55BF675ULL,
		0x3E3925F7687A835FULL,
		0x6FE251E7D4A3B0DFULL,
		0x0E9BE5771D62C2C2ULL,
		0x87093B6E047DD75DULL,
		0xBE6D1830A2D8AD8EULL,
		0x5DFA009BFC0F2EE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF1BEB19BFBF8BFEULL,
		0x52D246C2E5D08539ULL,
		0x5538E33F80764287ULL,
		0x4DED6A6743409426ULL,
		0x75B2549B003E3B29ULL,
		0x62AADECD59D8F7FFULL,
		0x487F9AA56361998AULL,
		0x3A1EF0DC9319C18DULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB31A679BC6EEA46FULL,
		0x235E261E7DA19EEFULL,
		0x760D991D83D07887ULL,
		0xBD17968898719F7FULL,
		0xC4410BE573E48E77ULL,
		0x2B89B0B4DD2D36EAULL,
		0x27FB4A6B6C6A0586ULL,
		0xC49BB9354C455CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC6DC92EFB9D154ULL,
		0x3C41FE15269B0BDBULL,
		0xDBB700BD9679601CULL,
		0xE92111B92666E5AEULL,
		0xC269573AFC9C86E0ULL,
		0x0C7D9ACEB5D43465ULL,
		0x0F2EEBCC51D41860ULL,
		0xF007B79209F8AB07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EDCBB092957753BULL,
		0x1F1FD80B5B3A9534ULL,
		0xADBA99A015A9189BULL,
		0x54368731BE177AD1ULL,
		0x06285CDF8F780897ULL,
		0x27F42A7A68F9028FULL,
		0x28D5A1A73DBE1DE6ULL,
		0x349C0EA745BDF7F2ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7415B3EA10E5ABAAULL,
		0x23D0F8B8FD00DB63ULL,
		0xEAEF4323DF61888DULL,
		0xF3006610F06EC1C9ULL,
		0xAF71291A96372D22ULL,
		0x5F272C464915CFB8ULL,
		0x8C70F56066C69A22ULL,
		0xCAE8C40C0B9613C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB13EE607956950ULL,
		0xF9FA84EA584AA89BULL,
		0x01A65ACEAFF4420AULL,
		0x7682A3D8DB761ADCULL,
		0xA1113E65779DB0B0ULL,
		0x0BDD5BC4C19D358AULL,
		0x3EA906EC94AA2FA6ULL,
		0x7D22546C3A091A7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AA48D0C1770C2FAULL,
		0xDA2A7C52A54A73F8ULL,
		0xEB4919ED7095CA87ULL,
		0x8582C5C82B18DB15ULL,
		0x0E60177FE1AA9D92ULL,
		0x54FA77828888FA32ULL,
		0xB2D9F38CF26CB584ULL,
		0xB7CA9060319F09BEULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDB5C6D781D4B963AULL,
		0xDBF9C974D86F1E39ULL,
		0xB8ACFDED9E7A8F50ULL,
		0x8DCA3C23E561D8AEULL,
		0xFF9A0DFF9104E32CULL,
		0x7D246BA5E5DFBF2CULL,
		0xF83105210027009BULL,
		0x88D83C6ED9516857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64AD703A319D3110ULL,
		0xD0A2B80B4B2A6C60ULL,
		0x6769A02E4421D498ULL,
		0x9C0FBECB42B0F323ULL,
		0xA20929ADB42357ADULL,
		0x75ABF1ED3BBDA7BDULL,
		0xD21BACC5A9F8185BULL,
		0x08389DD2A03C421DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFF11D422CD6A72AULL,
		0x0B5B717F93457259ULL,
		0xDFC55DC3DA5B5BC8ULL,
		0x11C582E8A7D12B8DULL,
		0x5D9324522527B481ULL,
		0x088F9A48DE621891ULL,
		0x2A2AA9E4A9DF18C0ULL,
		0x80E0A1BC796D2A4AULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE981CF7956BA8ADEULL,
		0x3FAFABA0DFB7D056ULL,
		0x5A270C737D4FAF65ULL,
		0xBD6A29574E66A3F3ULL,
		0x652ECF08EA5026DDULL,
		0x5B0F78B5ABF13041ULL,
		0xBC481325C8C15E56ULL,
		0x1561D6506942CF47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18CF047D96D6610ULL,
		0x2F7042327C633739ULL,
		0x9F75FB08B09DE5CDULL,
		0x66B36A7BD5D243F0ULL,
		0xBCCB451F52B35811ULL,
		0xDA69FCA4D7D05A8FULL,
		0x1D04EB6EFA3CCEF3ULL,
		0xC5234F2B26A818DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x380D3F3E8FD7ECCEULL,
		0x10DFE992A3D4E76FULL,
		0xC552F77BCDD24AA8ULL,
		0xDBD9432C9BB4E003ULL,
		0xD9E58A17B8E37ECCULL,
		0x816684117C216ACEULL,
		0xA14CF84B32FD90A5ULL,
		0xD042997B4FEAD79BULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x193446588565D10AULL,
		0x8AC4F5074321B845ULL,
		0x289BD798D1033F3DULL,
		0xB1F853CD5EA1757DULL,
		0x243F7C59563F7C41ULL,
		0x48796F108822A968ULL,
		0x47FD0FD44D8CDB41ULL,
		0x089C637F4DC6904AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0192212878FF1641ULL,
		0xFC7D1A8687FFD9F4ULL,
		0x36C94351AC71A52BULL,
		0x16EEAD27697E1995ULL,
		0x2C3339E2543A9E80ULL,
		0x960A0F823FBF728DULL,
		0x4243E19E49D69E4AULL,
		0x1216D73A5FEA9268ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18A66770FD9AC74BULL,
		0x76B9EF81C4DE61B1ULL,
		0x1E5294C97D729A16ULL,
		0xA716FEEA37DF6CE8ULL,
		0x080C45BB0205E2C1ULL,
		0xDE736092B79DDBE5ULL,
		0x05BEEE4A045A450BULL,
		0x1A8AB445122C0222ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE34438C244337A9EULL,
		0x1658D12A3915A991ULL,
		0xDC9BDDECBAD7F994ULL,
		0x5F5D2C8577D7D42CULL,
		0xBB186B8DAE07D762ULL,
		0xD580F717E4965A8AULL,
		0xF1E0F211031798CCULL,
		0x368663538E688F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42A3B1A9663FD80ULL,
		0x0C96C09320214533ULL,
		0x13E861C7412058E6ULL,
		0x75774FE37CDED112ULL,
		0xE253D5C0B47BCC8EULL,
		0x303395B3AEE127AFULL,
		0x874BF4A0C5F8BC60ULL,
		0xC196DE9637E14984ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x176E03D8D250871EULL,
		0x1ACE11B91934ECA2ULL,
		0xCF73BC2BFBF7A172ULL,
		0x2A2A63660B09053EULL,
		0x594BBE4D1A7C1BECULL,
		0xE5B362A44A777D25ULL,
		0x76AB06B1C6EF24ACULL,
		0xF710BDC5B989C6DEULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAA5E8E8E0C224279ULL,
		0xF2D5D33811896957ULL,
		0xA231FC6F536D5725ULL,
		0x129CF8BC0A93AF1CULL,
		0x1DADC249F6412A4DULL,
		0x404E6D0E678A6B7AULL,
		0x69F4850484A73C7EULL,
		0x7626C4B00929C940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F15F4DEAB063B7ULL,
		0x4EE1BE9FD94A8AC4ULL,
		0xA824F738187AABBDULL,
		0x9DCB377761852576ULL,
		0x5E5AF235B12B6DADULL,
		0xD93662EBB112962BULL,
		0x392A0E9B1A941E13ULL,
		0xBBA8BA35994A07F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79AFD1C3E69221CEULL,
		0xBC346DA7C8C3E393ULL,
		0x0A150B574B17FC98ULL,
		0x8F57CFCB6B168A6AULL,
		0x43F7307C476A47E0ULL,
		0x99780FE5D698FD51ULL,
		0x50DE8B9F9E33226DULL,
		0xCD8E7E859063CEB3ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6F782CCD45E6DD22ULL,
		0x0076C7BFD499A5E4ULL,
		0x31BFF4E12DD45BCFULL,
		0x979E7BD7E0D8B199ULL,
		0xC1FF985DD8E09683ULL,
		0x248372BF727DDF4AULL,
		0x360D952273537E94ULL,
		0xE822085F7F69F844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB583FA0757567270ULL,
		0x10F1E5CCDC6896EFULL,
		0xE731BCE824FD8B3AULL,
		0x4251E862462466CAULL,
		0xC23838FAE1D65887ULL,
		0x6D65C13B7B3C235FULL,
		0xCF494FE9ADE6621FULL,
		0x42E7BD5CC755F750ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAFBD6CA12B0AF52ULL,
		0x1087227308F1330BULL,
		0xD68E48090929D0F5ULL,
		0xD5CF93B5A6FCD753ULL,
		0x03C7A0A73936CE04ULL,
		0x49E6B3840941FC15ULL,
		0xF944DACBDEB51C8BULL,
		0xAAC5B503B83C0F14ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF8770CBE3CF2E5A5ULL,
		0x181F2841C756696FULL,
		0xADB35906BD104AD2ULL,
		0x274E7DB94B0DD30CULL,
		0x8D865FF565565549ULL,
		0x124498AE10FE982DULL,
		0xC3C00E257EF0B539ULL,
		0x48647983AA94CB58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0277256B237C520DULL,
		0xDBC6752A04F9519DULL,
		0xAA0E3F172C53C9F6ULL,
		0xBD5C578799093988ULL,
		0xF104924D4695A95CULL,
		0x292A4CD1E916E553ULL,
		0xE9C6860355F113A1ULL,
		0xF380F2E53DA12FACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA0029D51F8EB7A8ULL,
		0xC3D95D6BC3AF38F2ULL,
		0x07BD661191438324ULL,
		0x9A122A3ED204EA84ULL,
		0x7C82CDB823C3FC15ULL,
		0x3B6ED47FF9E87D7EULL,
		0x2A0688262B01A698ULL,
		0xBBE48B669735E4F4ULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3BF49FE681E68237ULL,
		0xDFD1D1DA5E90E92EULL,
		0x76DB25F26FB38A64ULL,
		0x0F39E9E8161F1915ULL,
		0xA1D91BC7CD3569DBULL,
		0x1E6B5890EFCC1111ULL,
		0xBBEFC22585CDCEE7ULL,
		0xFA12F3E288FB8201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE24B0B0731251860ULL,
		0x8AEB00862A32E23AULL,
		0x526559C40D8FA14FULL,
		0x8193C0DE8CC759BDULL,
		0x7E4FE8772A208D27ULL,
		0x59A800B300063BF0ULL,
		0xD2A132731BDC5018ULL,
		0x9F18A34E4FC8B0FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9BF94E1B0C39A57ULL,
		0x553AD15C74A20B14ULL,
		0x24BE7C36623C2B2BULL,
		0x8EAA29369AD840A8ULL,
		0xDF96F3B0E715E4FCULL,
		0x47C35823EFCA2AE1ULL,
		0x694EF0569E119EFFULL,
		0x650A50ACC73332FBULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x89598AFCCDA5170EULL,
		0xC06BAF1F35675088ULL,
		0x69E03A2456127028ULL,
		0x7B1A144F6A9A0873ULL,
		0x617A158D1AEF9430ULL,
		0xD05586F1FBCA1551ULL,
		0xB87F857CA556CB00ULL,
		0x59A72E812C6FAC92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A529816D1866F2AULL,
		0x68E63E8E870358DDULL,
		0x75A27F27F9B28F79ULL,
		0xF014D0276B8CEC6CULL,
		0x0C6B31AC8BFF4082ULL,
		0x709CFF6127901B72ULL,
		0x3B774E1B30FBCB6EULL,
		0x6B871129DB5EDC13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x030B12EA1C237824ULL,
		0xA88D9191B2640855ULL,
		0x1C424503AFA0FF51ULL,
		0x8B0EC4680116E41FULL,
		0x6D1124219110D4B2ULL,
		0xA0C97990DC5A0E23ULL,
		0x8308CB6795AD006EULL,
		0x32203FA8F7317081ULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA9DD7424CB1345DDULL,
		0x8E9983B30A2856E2ULL,
		0x1EA7F52A891BE673ULL,
		0xBEC8FB4390B42496ULL,
		0x40D2A16205F7C994ULL,
		0x5535C08197A14C14ULL,
		0x08E9CFDB4F13F918ULL,
		0x54425DE6FA4F2A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8B4E82AA0092E52ULL,
		0x42C8C74FB163E2CCULL,
		0xAD7054192636468EULL,
		0x84CCD536A67898F5ULL,
		0x293B718A5906E955ULL,
		0x366D2F53652B7B91ULL,
		0x2E3CCFF1D64A6F50ULL,
		0x5E8D1262FDBD66C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11699C0E6B1A6B8FULL,
		0xCC5144FCBB4BB42EULL,
		0xB3D7A133AF2DA0FDULL,
		0x3A042E7536CCBC63ULL,
		0x69E9D0E85CF120C1ULL,
		0x6358EFD2F28A3785ULL,
		0x26D5002A99599648ULL,
		0x0ACF4F8407F24CAEULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3CE36DE3DA6265FEULL,
		0xFFC56207F4752A53ULL,
		0x291E0DBDDD7B726EULL,
		0xDEB4CF9D3EFA207CULL,
		0xD79CEE62F022261FULL,
		0x0DF1151A38DA2A66ULL,
		0x0174D132B50CF40DULL,
		0xD9EFA5678EE01EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F4F2FA6AA465A96ULL,
		0x3D1942060641CD69ULL,
		0xE7F3DAE3447AE77BULL,
		0x7E21E7B5A239932DULL,
		0xE229C1B3BC663866ULL,
		0xBBC5A15A925E4F31ULL,
		0xBADC9B48F0D46CFAULL,
		0x792D7FFC7A34DF47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63AC424570243F68ULL,
		0xC2DC2001F234E73AULL,
		0xCEEDD75E99019515ULL,
		0xA09528289CC3B351ULL,
		0x35B52FD14C441E79ULL,
		0xB634B440AA846557ULL,
		0xBBA84A7A45D898F7ULL,
		0xA0C2DA9BF4D4C1F6ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAA357297FAC3A125ULL,
		0x04D7DE9D4F754742ULL,
		0x40D051CF290932D4ULL,
		0xEF4F90138B6B9208ULL,
		0x2C4A240997331C61ULL,
		0x0741DA1359E97126ULL,
		0xE6F2551DE17D7209ULL,
		0x0360AAA7FFC9D2D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95BDAA2D8FBF8253ULL,
		0xF14CD39AE20359E0ULL,
		0xEF1DDE6AEDF551EAULL,
		0x00DD2C10363B6F60ULL,
		0xEA4F53D692B6455AULL,
		0xA1FFBAF1705D6A78ULL,
		0x3A1205215C16C93BULL,
		0x271F5937801D5208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F88D8BA757C2376ULL,
		0xF59B0D07AD761EA2ULL,
		0xAFCD8FA5C4FC633EULL,
		0xEF92BC03BD50FD68ULL,
		0xC60577DF0585593BULL,
		0xA6BE60E229B41B5EULL,
		0xDCE0503CBD6BBB32ULL,
		0x247FF3907FD480D0ULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB40AD5A3F80E02FBULL,
		0xA6C9F5713AF55B19ULL,
		0xD9AAC9C00814DEDAULL,
		0x0DAE694EF5E98D24ULL,
		0x87E541F2BF4DE6DFULL,
		0x5A73AAE958ADC1F5ULL,
		0x1AA09E21D9FA0782ULL,
		0xE77E632AE474DE9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43BEEE9A8BEA1356ULL,
		0x80F22FE627051FDAULL,
		0xAF1C3A2FF59F7F78ULL,
		0x1122C31279872060ULL,
		0x2E32F35D61B2A185ULL,
		0xE4BF71F233D96BF0ULL,
		0x1A5F68C80B570C0BULL,
		0x7411D81F94E2590BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7B43B3973E411ADULL,
		0x263BDA971DF044C3ULL,
		0x76B6F3EFFD8BA1A2ULL,
		0x1C8CAA5C8C6EAD44ULL,
		0xA9D7B2AFDEFF475AULL,
		0xBECCDB1B6B74AA05ULL,
		0x00FFF6E9D2AD0B89ULL,
		0x936FBB3570968794ULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0DCBE7902635B4ECULL,
		0x793116A769DBE5FBULL,
		0x056C960E38D99518ULL,
		0xD262F344387D681BULL,
		0x41B86E072E50B342ULL,
		0xC17EC3D96C887F7CULL,
		0xEB8DA1F8851AEFA8ULL,
		0xA83E913AFF394261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2A0DD8783AB3E2ULL,
		0x9D1DD01BC3E8B4F1ULL,
		0xE32A8D1FC5250C3AULL,
		0xB5A00070B5D42F4BULL,
		0x5C449BCF745BFD03ULL,
		0xE77BAB1669FB7470ULL,
		0xF357CB53EF755D65ULL,
		0xED911C31040C3715ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57E1EA485E0F070EULL,
		0xE42CC6BCAA33510AULL,
		0xE6461B11FDFC9922ULL,
		0x67C2F3348DA94750ULL,
		0x1DFCF5C85A0B4E41ULL,
		0x260568CF05730B0CULL,
		0x18DA6AAB6A6FB2CDULL,
		0x45AF8D0BFB357574ULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x88908804ACE18EE9ULL,
		0x6FB23909F22261FFULL,
		0x72A31C0095789687ULL,
		0xF6B6D56CEC754339ULL,
		0x1B7C4EB8CF686A05ULL,
		0xA28D419038F079C2ULL,
		0xE52B09C5DEA49F36ULL,
		0x574FBC5503B3FC41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBDB4B86E0A6C960ULL,
		0x86EAADF8BE48B61CULL,
		0x5434D2959D42A758ULL,
		0xB8697C78306E01B0ULL,
		0x29DB6FA0DFA7D822ULL,
		0x29B177D34DE451AEULL,
		0x4E1D197721E571F6ULL,
		0xDD799019A5D7898CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x434BC3824C474789ULL,
		0xE95894F14C6AD7E3ULL,
		0x2697CE95083A31DFULL,
		0x4EDFA914DC1B4289ULL,
		0x32A7211810CFB227ULL,
		0x8B3C36437514286CULL,
		0xAB3610B2FF41EEC0ULL,
		0x8A362C4CA66475CDULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA0DACF4214D979A1ULL,
		0xA16936F8F3FE9794ULL,
		0x7F3E4943F13512AFULL,
		0x99109B481EB8EC7FULL,
		0x6BE750DCA287D4BDULL,
		0xFBA5DEA69653EFB5ULL,
		0x628A378765146859ULL,
		0x6FA8DF7E2B76A778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3FE11A908FC8F1ULL,
		0x8EB79B3A966D606BULL,
		0x1FF08A29A2A229A2ULL,
		0xF072128B5A96E4D0ULL,
		0xB64F2352C4D8B5A0ULL,
		0x2B55D30F5900678AULL,
		0x821EA375BB686BE6ULL,
		0x4D540AF347FD2D7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACE52E588456B150ULL,
		0x2FDEADC26593F7FFULL,
		0x60CEC36A53973B0DULL,
		0x696289C3442E08AFULL,
		0xDDA8738E665F611DULL,
		0xD0F00DA9CF53883FULL,
		0xE09494F2DE7C03BFULL,
		0x22FCD58D6C8B8A05ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF03A1EC10C97536EULL,
		0x15E1E93688A1B340ULL,
		0x8A8CA2E8DBE7F8E5ULL,
		0xDD7C04FF9E614506ULL,
		0xFBD3EC04D6071C9EULL,
		0xD5C9FF850EDA31A9ULL,
		0x580926FD0E31D4B1ULL,
		0x43408304AE697B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D3F7B865B36A39ULL,
		0x0DCEF94785B69E26ULL,
		0xCA021CD42191F52EULL,
		0x8B00EAD4C088CBD7ULL,
		0x7ECA65FCC71005DBULL,
		0xB09249854650CE7DULL,
		0x64F7FC7AFB8C7EEFULL,
		0xF2ED3C70C647DF4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5E9E97969243957ULL,
		0x182F10710D172D66ULL,
		0x408EBE3CFA760DCBULL,
		0x567CEE2B5EE98ED1ULL,
		0x851989F811171945ULL,
		0x655BB600488AFFD4ULL,
		0x3CFEDA87F5BDAA5EULL,
		0xB1ADBF74682EA4CEULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9C6526A854A34304ULL,
		0xAD7291939652361AULL,
		0x22E180CDA1E9E3DDULL,
		0xE00E7B7EB464A569ULL,
		0x4F2B12E0EAC7DA63ULL,
		0x68FDDBFD8F0B7FA4ULL,
		0xB97DDABF1855DBCCULL,
		0xB9E6C8DD37329C51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0071BC16E07EB99EULL,
		0x9E77922A0BEA96C2ULL,
		0x81949DA44A8B1851ULL,
		0x3FD99154AA863F0EULL,
		0xFD874C5246F47298ULL,
		0xF27BD4E69215C15AULL,
		0x74C87D2FBFF6E707ULL,
		0x4D4E9A41187E697DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C149ABEB4DDFA9AULL,
		0x330503B99DB8A0D8ULL,
		0xA3751D69EB62FB8CULL,
		0xDFD7EA2A1EE29A67ULL,
		0xB2AC5EB2AC33A8FBULL,
		0x9A860F1B1D1EBEFEULL,
		0xCDB5A790A7A33CCBULL,
		0xF4A8529C2F4CF52CULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x587BBEE300E590F7ULL,
		0x839F7D338D24DB3CULL,
		0xEA36E080426AC7A8ULL,
		0x599BF69ABBFEEDA6ULL,
		0xE58FC13919C49C5AULL,
		0x1751CA7A877F12B7ULL,
		0xD5BCAF86B53E5797ULL,
		0x0341D98F771B9245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BE5BDD712C6B14ULL,
		0xABAFF4F4EF262DD9ULL,
		0x5265AAD965F39BBBULL,
		0x8B9210AD45E2E7D9ULL,
		0xC33134D5B4DC7879ULL,
		0x388EBF946A323FE5ULL,
		0x141E33F819DDCC45ULL,
		0xAD7499301CCEC366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDC5E53E71C9FBE3ULL,
		0x283089C76202F6E5ULL,
		0xB8534A5927995C13ULL,
		0xD209E637FE1C0A7FULL,
		0x26BEF5ECAD18E423ULL,
		0x2FDF75EEED4D2D52ULL,
		0xC1A29C7EACE39BD2ULL,
		0xAE3540BF6BD55123ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE0BA15254B97082CULL,
		0x9B8B7321EAE2C74BULL,
		0x754BABFF0AB50BD6ULL,
		0xD7AD4A5FA1B962D8ULL,
		0xA90641A9B7ADA458ULL,
		0xA7ABC4A012917B91ULL,
		0x1C8546C30D656338ULL,
		0xD2604099E9EE3FD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10817F334475ED83ULL,
		0xFC93BE26085712ECULL,
		0xA5F0B21C483E2150ULL,
		0x3DAB82CA4316B1BEULL,
		0x1794CC0965DAE09BULL,
		0x4CC2DB5991063524ULL,
		0x22A43527FE31338BULL,
		0x73CEF1567AD54D44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF03B6A160FE2E5AFULL,
		0x6718CD07E2B5D5A7ULL,
		0xD0BB19E3428B2A86ULL,
		0xEA06C895E2AFD366ULL,
		0xBE928DA0D27744C3ULL,
		0xEB691FF983974EB5ULL,
		0x3E2173E4F35450B3ULL,
		0xA1AEB1CF933B7291ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7F9D74011007BA96ULL,
		0x1CBEE9CF1FBAAC24ULL,
		0x25D2C6FEE5F7A92CULL,
		0xD1E4CE0C8AAC96A4ULL,
		0x7F522CB0CFAE98A0ULL,
		0xA4B5A1A9DDFBD268ULL,
		0xDE57B70B254F8BDBULL,
		0xFD763742FF75F6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3EDDBDDCFEE7A1ULL,
		0xA1EF8545CB86BE78ULL,
		0x4EA4025E2CC7A19EULL,
		0x5488C37C5039C114ULL,
		0xA60BABA276CA26CFULL,
		0x57605A7E706F4EF1ULL,
		0xF9B75F28E5A05324ULL,
		0xCB83CCBD306CE21EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03A3A9BCCCF95D37ULL,
		0xBD516C8AD43C125CULL,
		0x6B76C4A0C93008B2ULL,
		0x856C0D70DA9557B0ULL,
		0xD9598712B964BE6FULL,
		0xF3D5FBD7AD949C99ULL,
		0x27E0E823C0EFD8FFULL,
		0x36F5FBFFCF1914ABULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5F3848C18EA0BF3CULL,
		0xD9ED0FDF3ADDA1DCULL,
		0x466A56AF5F3D46C5ULL,
		0x0209CD0CF81EF0C9ULL,
		0x5D44F1419EDA6E01ULL,
		0xE64B0573D9FD3621ULL,
		0x03E9223F0A951515ULL,
		0xDD7A532895D6CBB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80B7DCCFC02BD086ULL,
		0xE0B83199A5688687ULL,
		0x9325196D3F59F5F9ULL,
		0x15B640026368E781ULL,
		0x254ACC00F5F615CEULL,
		0x178C53F0B0068164ULL,
		0x9FF34876E3E02FB2ULL,
		0x4655F1A559EB0F69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF8F940E4E8B6FBAULL,
		0x39553E469FB5275BULL,
		0xD54F4FC26064B33CULL,
		0x17BF8D0E9B761748ULL,
		0x780E3D416B2C7BCFULL,
		0xF1C7568369FBB745ULL,
		0x9C1A6A49E9753AA7ULL,
		0x9B2FA28DCC3DC4DEULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x555DBC222F5D4081ULL,
		0xA9016945F5FC99FDULL,
		0x69B9C060E6CC6176ULL,
		0xEDF331D9991E9CE2ULL,
		0x0D22DBE1864102A2ULL,
		0xAD0C69C927087487ULL,
		0x5D7AFB361FA82181ULL,
		0xECE39B6D5073D04CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA76F09B84742AF1ULL,
		0x2C4C6411F589BEA8ULL,
		0xD218C1DAE0B81FDEULL,
		0xCFEC01091357756BULL,
		0x46249BEB83A32A11ULL,
		0x82E94868B8408935ULL,
		0xE3B9FA0DBE0AAB7EULL,
		0xF4E79009F0F0EE1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF2B4CB9AB296A70ULL,
		0x854D0D5400752755ULL,
		0xBBA101BA06747EA8ULL,
		0x221F30D08A49E989ULL,
		0x4B06400A05E228B3ULL,
		0x2FE521A19F48FDB2ULL,
		0xBEC3013BA1A28AFFULL,
		0x18040B64A0833E53ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE3ABCE35F88FBAD9ULL,
		0xEE6C6607D04DF4A7ULL,
		0xC8F2384F56C368A1ULL,
		0x7956448139BF66FEULL,
		0xA0D93C2A9C1204E5ULL,
		0x849C0B370D3564BBULL,
		0x22A050C0AE1D9A07ULL,
		0x4E3B4D024B4366D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDAABCAB919262D7ULL,
		0x3260A3B2C739149CULL,
		0x7C611A8F589B125BULL,
		0x0D03F5ED1FEEA702ULL,
		0x027E336F31A4882CULL,
		0x2D94C411BA37681EULL,
		0xCA299D2F0B919E1FULL,
		0x3E9207E5FC275A74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E01729E691DD80EULL,
		0xDC0CC5B51774E03BULL,
		0xB49322C00E587AFAULL,
		0x7455B16C2651C1FCULL,
		0xA2A70F45ADB68CC9ULL,
		0xA908CF26B7020CA5ULL,
		0xE889CDEFA58C0418ULL,
		0x70A94AE7B7643CA3ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9FAA67B6F43921D1ULL,
		0x715C546AD4715FCDULL,
		0x8ECFCB767E511CFDULL,
		0x958D17F7B3063F4CULL,
		0xE816D6820F8364CDULL,
		0xF5F2FC75F3EBA91DULL,
		0xD599E4D98F1236C6ULL,
		0x8BDF788AAE6CB5F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB992DBB49DA68EULL,
		0xE4F8BC628E1DCE72ULL,
		0x9FC5BEDE156D6496ULL,
		0x9128A76DFFB97C08ULL,
		0x1032704039896F32ULL,
		0xC1522718FFF88C1AULL,
		0x10E477A9CA1C50EDULL,
		0x5573727D38201FD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2413F56D40A4875FULL,
		0x95A4E8085A6C91BFULL,
		0x110A75A86B3C786BULL,
		0x04A5B09A4CBF4344ULL,
		0xF824A6C2360A0BFFULL,
		0x34A0DB6D0C132507ULL,
		0xC57D9370450E662BULL,
		0xDEAC0AF7964CAA24ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6ED0AC256C7F3C38ULL,
		0x81AA50E6353208A6ULL,
		0x67E17FA5C9CA111DULL,
		0xE365E3124F675ABFULL,
		0xB85697847EB209D2ULL,
		0x65ECFE63635B0D9BULL,
		0xCB5336F774FAA2F0ULL,
		0x75D116A010A94436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C97465DAF8E88FULL,
		0xBF56DA88771A9773ULL,
		0xE0F19F0B66BFDAA8ULL,
		0xD0C795F8844F08F0ULL,
		0x5B73AAF49801830AULL,
		0xC6A730E5AB50AE0BULL,
		0x5B651E0E63FE16CCULL,
		0x289A0CB4DD4D02E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD719D840B687D4B7ULL,
		0x3EFC8A6E42289FD5ULL,
		0x8710E0AEAF75CBB5ULL,
		0x33A276EACB28524FULL,
		0xE3253D70E6B38AD8ULL,
		0xA34BCE86C80BA390ULL,
		0x903628F91704B43CULL,
		0x5D4B1A14CDE446D6ULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF6558C1874D0C4B0ULL,
		0x8776E2E500FC1236ULL,
		0x5A1C1411789F89AFULL,
		0x046E1D15699C9285ULL,
		0xDF5A8222FE7D0A7DULL,
		0x6CEFD1EF82CC788AULL,
		0x62EF13A58F030A91ULL,
		0xE7E0CC774B40B9D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CEC7950F10B51EDULL,
		0xBEABAEB98C6678C6ULL,
		0x95A69F59BA67D8A8ULL,
		0xAACB912658E3BEE0ULL,
		0x0A155B4663AF835AULL,
		0xA1A49607924C4636ULL,
		0x8E8ECF19E53BE604ULL,
		0x982C5D11B4A70F3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AB9F54885DB955DULL,
		0x39DD4C5C8C9A6AF0ULL,
		0xCFBA8B48C2F85107ULL,
		0xAEA58C33317F2C65ULL,
		0xD54FD9649DD28927ULL,
		0xCD4B47E810803EBCULL,
		0xEC61DCBC6A38EC95ULL,
		0x7FCC9166FFE7B6E2ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA60B23A803B334A1ULL,
		0x1A69601B53A9B018ULL,
		0xB8EDCCFE07376C8CULL,
		0x47A68BAF6B24FDBDULL,
		0xC296105B6D7C5627ULL,
		0xA6AE651E6614FCDCULL,
		0xFBA81F314D66B790ULL,
		0xBA53D2A646BE2E26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD70049C6C3EB20DULL,
		0x62C146B19267570DULL,
		0x606688AA25541B80ULL,
		0xDFE7819A30577166ULL,
		0x4036980613F74723ULL,
		0x63C467E6B9BB1842ULL,
		0xF64F29B4F451C70CULL,
		0x32A93B83EE09D050ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B7B27346F8D86ACULL,
		0x78A826AAC1CEE715ULL,
		0xD88B44542263770CULL,
		0x98410A355B738CDBULL,
		0x82A0885D7E8B1104ULL,
		0xC56A02F8DFAFE49EULL,
		0x0DE73685B937709CULL,
		0x88FAE925A8B7FE76ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8B6215130DDBCABBULL,
		0x64536D03C88206AFULL,
		0x834AF53E8AB7A80CULL,
		0xD847EB65C10AA23EULL,
		0x013C37030CA2F0C6ULL,
		0x148C2E75CD36DEE0ULL,
		0x9C46B664DD1640B6ULL,
		0x2C0F1636EE32F289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FD2FF0267DE7592ULL,
		0xAC94D1BA68945E50ULL,
		0xF9569D15843C246CULL,
		0xA2302E975D5FBD91ULL,
		0x0C973580393EEB89ULL,
		0x50F0FCE1AFB2202CULL,
		0xFF52D1459C2C5CE9ULL,
		0x3FE88F989AD5BC14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04B0EA116A05BF29ULL,
		0xC8C7BCB9A01658FFULL,
		0x7A1C682B0E8B8C60ULL,
		0x7A77C5F29C551FAFULL,
		0x0DAB0283359C1B4FULL,
		0x447CD2946284FECCULL,
		0x63146721413A1C5FULL,
		0x13E799AE74E74E9DULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x284204002C5FF317ULL,
		0x8C842F3624B30AEBULL,
		0x55B0919B9E791540ULL,
		0x8C67941FE64621D6ULL,
		0x2E7F1497188710CDULL,
		0x4E19F81C34FDA6FEULL,
		0xC0737C84C4499604ULL,
		0x24D78A24B96ABE70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA97E19B6A688616ULL,
		0x32CA3C8FD3F1929BULL,
		0xF3910D066A926E96ULL,
		0x9D76286667B7D3BEULL,
		0xE5299B9527520543ULL,
		0xDAC9D4252FCA7EFAULL,
		0x7FB51345AEF7B0A8ULL,
		0x24E894056624289CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82D5E59B46377501ULL,
		0xBE4E13B9F7429870ULL,
		0xA6219C9DF4EB7BD6ULL,
		0x1111BC7981F1F268ULL,
		0xCB568F023FD5158EULL,
		0x94D02C391B37D804ULL,
		0xBFC66FC16ABE26ACULL,
		0x003F1E21DF4E96ECULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xABCE02ECA21E9E57ULL,
		0x5813D08CABE6A420ULL,
		0xC484B1CD7FB77D7DULL,
		0xF62536E7CB5BBE14ULL,
		0x72ECFD3005C89BDDULL,
		0xC09EFF2803F6D53CULL,
		0x66F8BB64E76DFFB1ULL,
		0xB2FB17B4537FC3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46131F455C7332B0ULL,
		0x1E69F8E287452DC0ULL,
		0x8050E9AF7A293C3FULL,
		0x113E00ED9DC2F8F3ULL,
		0xAC90B83AE8059992ULL,
		0x894D16BDF1F977F2ULL,
		0xEDA1C3EEEAB5374DULL,
		0x4C44E77D86CC5371ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDDD1DA9FE6DACE7ULL,
		0x467A286E2CA389E0ULL,
		0x44D45862059E4142ULL,
		0xE71B360A569946E7ULL,
		0xDE7C450AEDCD024FULL,
		0x49D3E995F20FA2CEULL,
		0x8B59788A0DD8C8FCULL,
		0xFEBFF0C9D5B390A5ULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBFB6A220900AC9CFULL,
		0x58BCBA7BF52E12AEULL,
		0xF4120A6B0035FBC7ULL,
		0xD6FF5BEDD3FE1658ULL,
		0xC969A320E3FCC091ULL,
		0x4CE0C3C381ABFA39ULL,
		0x9133FC25FC2B4A56ULL,
		0xE2A30FD651469469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46374C32BE915F42ULL,
		0x435F3598C1E994A6ULL,
		0x9913D357FDAE940BULL,
		0x69F8DE35FEA4A6A7ULL,
		0x073D090F50771DF7ULL,
		0x74C1199E5539A05AULL,
		0x748ABD8771F7F17CULL,
		0x24581AAA6A523DE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF981EE122E9B968DULL,
		0x1BE38FE334C78608ULL,
		0x6D01D93CFD9B6FCCULL,
		0xBF0785D82D5AB0FFULL,
		0xCE54AA2FB38BDD66ULL,
		0x3821DA5DD4925A63ULL,
		0xE5B941A28DDCBB2AULL,
		0xC6FB157C3B14A98BULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x91694F042594388FULL,
		0xBCEA599BC16BF15FULL,
		0x436BAA7039F91C52ULL,
		0xF706CF53B6C76A10ULL,
		0x064D6FBF8BF9F9C2ULL,
		0xCA714344661AA62AULL,
		0x9873F4C14E29FDBDULL,
		0x43DA09C8561FA19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CDFD9ADD97EF88DULL,
		0x34FF5719ADB46945ULL,
		0x9EAACA54C04A54EFULL,
		0x8A575D30E9EAD9C9ULL,
		0xA75E279B122FA4C8ULL,
		0x564FEE6E89B19BE6ULL,
		0x84208789C9CB2717ULL,
		0xEB781B1BFE070E17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DB696A9FCEAC002ULL,
		0x88150E826CDF981AULL,
		0xDDC16024F9B348BDULL,
		0x7D5192635F2DB3D9ULL,
		0xA113482499D65D0AULL,
		0x9C3EAD2AEFAB3DCCULL,
		0x1C53734887E2DAAAULL,
		0xA8A212D3A818AF8CULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEFC96C84A321AC7FULL,
		0xF01C07FA5021BC34ULL,
		0x70C4D7EEB1459276ULL,
		0x0E174147C93F76B2ULL,
		0xD7BA0B8BC1FE944FULL,
		0xD1E39EC63E43EAFAULL,
		0x8B8764539D3808F9ULL,
		0xC1E04AC8C2A5C9DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499EEA14971AA681ULL,
		0x2224BDC30298FD1BULL,
		0x724FF25E58923152ULL,
		0xA3ACA7F53FF53F87ULL,
		0x73F6F25A2EC4793BULL,
		0xA925353E45C372BDULL,
		0x6591599E6561D91CULL,
		0x995724B29E4FF9F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6578690343B0AFEULL,
		0xD238BA3952B9412FULL,
		0x028B25B0E9D7A324ULL,
		0xADBBE6B2F6CA4935ULL,
		0xA44CF9D1EF3AED74ULL,
		0x78C6ABF87B809847ULL,
		0xEE163DCDF859D1E5ULL,
		0x58B76E7A5CEA3029ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7547C74CCEFD3FBDULL,
		0x662DB88B00BB2D95ULL,
		0x2E7CE1789082FC8FULL,
		0x77A902C7F69A3FDFULL,
		0x2C3C0D9918E52397ULL,
		0xC6F581C283969CF5ULL,
		0x4EE4EF957FA6866FULL,
		0x587D095DFE63D14EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42CEABEB3EFF6D3ULL,
		0x82DE26449302AA6AULL,
		0xC6BAB6DB1CD9EBF9ULL,
		0xD737095FFAF5AA73ULL,
		0xC64354FA6989D3CAULL,
		0x996018084CCBB1FFULL,
		0xC28B191C58E0E0E1ULL,
		0xB8D016C56E8AF6B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC16B2DF27D12C96EULL,
		0xE4F39ECF93B987FFULL,
		0xE8C657A38C5B1776ULL,
		0xA09E0B980C6F95ACULL,
		0xEA7F5963716CF05DULL,
		0x5F9599CACF5D2D0AULL,
		0x8C6FF6892746668EULL,
		0xE0AD1F9890E927F8ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9A1B13AC136211FCULL,
		0x3D4A869A13AA3F01ULL,
		0x88FB87822F9D2F86ULL,
		0xA88EC749938D427FULL,
		0x347D024F52CF567FULL,
		0x4C9C5A1E8E34B3DDULL,
		0x1C2D812E8170FF20ULL,
		0xFF0A059D68C2817CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87427861B7B2BC3EULL,
		0x4D929D0F628CE231ULL,
		0x78C1CE8AFA7B47C4ULL,
		0x00E8F416A91AA109ULL,
		0x81EFB6729E3351B4ULL,
		0x7794ABB41783FB40ULL,
		0x7BC299FDB1F69F67ULL,
		0x60EF7A7A5D4DC364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D596BCDA4D0ADC2ULL,
		0x70D81B957126DD30ULL,
		0xF03A4908D5E66842ULL,
		0xA866335F3A97E376ULL,
		0xB592B43DCCFC07CBULL,
		0x3B08F1AA99B7489DULL,
		0x67EF18D330866047ULL,
		0x9FE57FE7358F4218ULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFFFC8A3B6E323F7BULL,
		0x307A8F7235B0FD14ULL,
		0x5B77E0E9F05BE565ULL,
		0x8A3BFAD624A4B17DULL,
		0xB97C01ACAA0E82D3ULL,
		0x33583B3CFE9EF231ULL,
		0xFA8682C6BDEDB310ULL,
		0x3B890BE20790AF92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B2FC0155F24035ULL,
		0xCFCF036C34ADC29DULL,
		0xD1EDCA245C4FF01EULL,
		0x0835B2D686D7983FULL,
		0x817688F4F1C4C586ULL,
		0x926E92A09248BBC8ULL,
		0xC5D649F36E9F7B08ULL,
		0x87D76F2919B3BEA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE4E763A3BC07F4EULL,
		0xFFB58C1E011D3F89ULL,
		0x8A9A2ACDAC14157BULL,
		0x820E4800A2732942ULL,
		0x380A89585BCA4755ULL,
		0xA136A99C6CD649F9ULL,
		0x3F50CB35D372C818ULL,
		0xBC5E64CB1E23113BULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4CEAB17AA1EFFA56ULL,
		0x2222F2A8BA89F1CFULL,
		0x8E4CEE5DA391DB12ULL,
		0x37CC37B1BE3ADB9EULL,
		0x600C33EEFF14BF39ULL,
		0xB9623943C9A6D13BULL,
		0x6F1BA1368185D4A4ULL,
		0x2D4E34DE56DFDAB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C2B681084269F4ULL,
		0x632DCF379993C684ULL,
		0xB21E357AE0AB7AADULL,
		0x9D2EB5628BBEC5A0ULL,
		0x126ACFE49FFED3A0ULL,
		0x7134B6B2564A4A2EULL,
		0x8329390E63D30B97ULL,
		0x5EF981781A157E4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF2807FBA9AD93A2ULL,
		0x410F3D9F231A374BULL,
		0x3C52DB27433AA1BFULL,
		0xAAE282D335841E3EULL,
		0x7266FC0A60EA6C99ULL,
		0xC8568FF19FEC9B15ULL,
		0xEC329838E256DF33ULL,
		0x73B7B5A64CCAA4FCULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x30DB71FCEA0D0A95ULL,
		0x10ADEC0C0A743C3EULL,
		0x31D885CA80A662C4ULL,
		0xCC9D6683E4726965ULL,
		0xFFE8A2E06C015F6AULL,
		0xAD6C3AACB37D5796ULL,
		0x42619DA1178B9227ULL,
		0x7CD52204CE638315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E996FB8BB48CC1ULL,
		0x52959C3E0796CCBAULL,
		0x565239930D8C5983ULL,
		0xAEA9DD9AC4A6C6BCULL,
		0x0CEB48EE6E32A36BULL,
		0x11CD85E93248BBB5ULL,
		0x8137FE0E9C8022D8ULL,
		0xB01DCF8053F10A12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE332E70761B98654ULL,
		0x423870320DE2F084ULL,
		0x678ABC598D2A3B47ULL,
		0x6234BB1920D4AFD9ULL,
		0xF303EA0E0233FC01ULL,
		0xBCA1BF458135EC23ULL,
		0xC35663AF8B0BB0FFULL,
		0xCCC8ED849D928907ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5E4A71910584788DULL,
		0x9DC1AFBCFEF9AC03ULL,
		0x7E832791FEB34142ULL,
		0x7D8F28F9D3A5EC98ULL,
		0x6D42F84A23AAAFB6ULL,
		0x35B27193A55A52F9ULL,
		0x1EDB98EBEC642A72ULL,
		0x247AE8EBCB057C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F108ABDC3D62E5BULL,
		0x32313E360D07550FULL,
		0x9A04CA27446B3D8CULL,
		0xC467708164B5D638ULL,
		0xD575B4ACEB1D42C2ULL,
		0x86106083081E98E0ULL,
		0x5D3112724AA0F92BULL,
		0xF17964F4C1BC3F14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x315AFB2CC65256D6ULL,
		0xAFF0918AF3FEF90CULL,
		0xE487EDB6BAD87CCEULL,
		0xB9E85878B7103AA0ULL,
		0xB8374CE6C8B7ED74ULL,
		0xB3A21110AD44CA19ULL,
		0x43EA8A99A6C4D359ULL,
		0xD5038C1F0AB9439FULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB2DD8A6487641FC8ULL,
		0xBE8177804460ABC2ULL,
		0xCB4934E3F3F63EB0ULL,
		0xC4203A988525641BULL,
		0x2BE0DFF063691A15ULL,
		0xD9AA63352C53D2CCULL,
		0x96C143D1607732D3ULL,
		0x0B7F4622A48D49F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x102E874010500CE1ULL,
		0x48D47977FDBA6545ULL,
		0xF15C970D4826A4A0ULL,
		0xE400776DC1630255ULL,
		0x35D97DEA6D4E57DFULL,
		0xE6257992532B1DE4ULL,
		0xA175D938CEBC8863ULL,
		0xF06AF851FFD2DA71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2F30D2497341329ULL,
		0xF6550EF7B9DACE87ULL,
		0x3A15A3EEBBD09A10ULL,
		0x20204DF54446664EULL,
		0x1E39A21A0E274DCAULL,
		0x3F8F1AA77F78CF28ULL,
		0x37B49AE9AECBBAB0ULL,
		0xFB15BE735B5F9382ULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE8FCE6F525088F49ULL,
		0x61AD15F7E0FBA68BULL,
		0xEDF6C8E280EE0DF4ULL,
		0x6697D99328A82514ULL,
		0x4C2A3E81AEB2222BULL,
		0xE8CA91F0D5B4F0C0ULL,
		0xE222B99865B81DF4ULL,
		0x445778B89674BCB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BCD9EE468EA9AA5ULL,
		0xDCB2D02646631B51ULL,
		0x7B991117AE14D5FEULL,
		0x192AE2D5B78CA702ULL,
		0x587ACD32FE2609A1ULL,
		0xD99A0172394EE64DULL,
		0xD0D1B598EC44304FULL,
		0x0F765CBBFDACE451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE33178114DE215ECULL,
		0xBD1FC5D1A698BDDAULL,
		0x966FD9F52EFAD80AULL,
		0x7FBD3B469F248216ULL,
		0x1450F3B350942B8AULL,
		0x31509082ECFA168DULL,
		0x32F30C0089FC2DBBULL,
		0x4B2124036BD858E2ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD189BD5A994B616FULL,
		0x2F9DA47200A44FD9ULL,
		0xE4ECD78F002A1A8EULL,
		0xCC7D5B0B9BC88AC3ULL,
		0xF194602B9B1C0B83ULL,
		0xA8C0C2CBC20B8848ULL,
		0xB22CFD0A8DF9D59FULL,
		0x5D74E3950E49D033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93E972EC2A2D6201ULL,
		0x8BCABCA1C18494B9ULL,
		0x087A9DCDC472841DULL,
		0x46D2215ED3017788ULL,
		0x70728C61853FABB2ULL,
		0x8EB2381DF43F0D62ULL,
		0x78EB7B59F23A4BFAULL,
		0xBDCBB3F1102A3C1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4260CFB6B366036EULL,
		0xA45718D3C120DB60ULL,
		0xEC964A42C4589E93ULL,
		0x8AAF7A5548C9FD4BULL,
		0x81E6EC4A1E23A031ULL,
		0x2672FAD63634852AULL,
		0xCAC786537FC39E65ULL,
		0xE0BF50641E63EC2EULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1A9514BB100243E4ULL,
		0x337D421F07B57CB9ULL,
		0xC25C599A1936A1CBULL,
		0x5B276991FF6A4EA0ULL,
		0xFA4B214F7FF48C31ULL,
		0x4B1FBD635A59213DULL,
		0xCA97E5849FF443D5ULL,
		0x6301CA4D218B0BE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9E11F928CE837AULL,
		0x95CA89CF3EBFD6B8ULL,
		0x9B87A1D1C44E2C5CULL,
		0x9A90CE36A0A371B4ULL,
		0x6F74E42DD3AA687FULL,
		0x148DB6D5D36C84C4ULL,
		0xE0D204510AE70F0FULL,
		0xFB4C06A1E099CB2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x600B054238CCC09EULL,
		0xA6B7CBD0390AAA01ULL,
		0x59DBF84BDD788D97ULL,
		0xC1B7A7A75FC93F14ULL,
		0x953FC562AC5EE44EULL,
		0x5F920BB68935A5F9ULL,
		0x2A45E1D595134CDAULL,
		0x984DCCECC112C0C2ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x023DC6B9513D9F93ULL,
		0xA3FFCE3D361181BFULL,
		0x13ABD6BD8CE4F167ULL,
		0xCF49248C34580A2CULL,
		0xA7DFFD1515CCE39BULL,
		0x0A4AABDB567BA033ULL,
		0x565D5FE1555A6373ULL,
		0x4A631C0EFD53F39FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC92952708AE05289ULL,
		0x1D7604CEDAA5C52BULL,
		0x50F309EF37371DD2ULL,
		0xD43F6137A9CD40AAULL,
		0xC3822C4942B311D9ULL,
		0xFFC73080F9734EB0ULL,
		0x8F0BD970A51B48E9ULL,
		0xB51EA8355E7C98C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB1494C9DBDDCD1AULL,
		0xBE89CAF3ECB44494ULL,
		0x4358DF52BBD3ECB5ULL,
		0x1B7645BB9D954A86ULL,
		0x645DD15C577FF242ULL,
		0xF58D9B5BAF08EE83ULL,
		0xD9568691F0412B9AULL,
		0xFF7DB43BA32F6B5CULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0C80E6BBA6156DC3ULL,
		0xD424501561FF8157ULL,
		0xE8B1C8BE7CDEDCA6ULL,
		0x21C6D89966D1A47EULL,
		0xC408E39DC4C36E98ULL,
		0x31B7B697434794D3ULL,
		0xCE204B91D83D3ABEULL,
		0x647F5651134AE7A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0DBE4AADD5EA83ULL,
		0x3DF4DFDCE145FDB5ULL,
		0x2B02BB6E550D46C0ULL,
		0x55CAADE38569A646ULL,
		0xBA590C165D621CA5ULL,
		0x0A2D5A847AC6EDA2ULL,
		0xAFC28953CC5BB8CDULL,
		0xF669123C63FB772AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x928D58F10BC08740ULL,
		0xE9D08FC980BA7CE2ULL,
		0xC3B373D029D39A66ULL,
		0x740C757AE3B80238ULL,
		0x7E51EF8B99A1723DULL,
		0x3B9AEC1339817971ULL,
		0x61E2C2C214668273ULL,
		0x9216446D70B1908FULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6C357DCC329C1258ULL,
		0x93138A7035239FCFULL,
		0xEE819D3824A0EB7AULL,
		0x017D2A6099A4C326ULL,
		0x792D2B616B640B80ULL,
		0x935AE9E6D2A990CEULL,
		0x8A4239BFA1C391B7ULL,
		0x50B37B68FC6DEFA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1A677CB78BEA63ULL,
		0x34CFD57D8DE1A4C4ULL,
		0x89A05A9C1AE0A2AAULL,
		0xD9CB6058219EB337ULL,
		0xDF0C2B7391253059ULL,
		0x77B9F2862B18B50DULL,
		0x6C7C0B3559CDD3AFULL,
		0x68C230FB50CFA7ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x262F1AB08517F83BULL,
		0xA7DC5F0DB8C23B0BULL,
		0x6721C7A43E4049D0ULL,
		0xD8B64A38B83A7011ULL,
		0xA6210012FA413BD9ULL,
		0xE4E31B60F9B125C3ULL,
		0xE63E328AF80E4218ULL,
		0x38714B93ACA2480DULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7122CFF911B168B2ULL,
		0xE674CEEF39840CC2ULL,
		0x801A8DECBBBD19ECULL,
		0x40E8C6184082ABF1ULL,
		0x1279D3DA2AA0685CULL,
		0x517FEF9CA712AD56ULL,
		0xFE116735031E761CULL,
		0x1C09986A1579769CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F2D7C9CCE0FCB8EULL,
		0xF9162EE9B19BF750ULL,
		0xD4923B312E0A9B3FULL,
		0x912147DFCE48EB6AULL,
		0xF2FCE46D91CBC58EULL,
		0x643932BBB09EF728ULL,
		0x9591298800474577ULL,
		0x474F702454B5B6ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E0FB365DFBEA33CULL,
		0x1F62E006881FFB92ULL,
		0x5488B6DD95B782D3ULL,
		0xD1C981C78ECA409BULL,
		0xE08537B7BB6BADD2ULL,
		0x3546DD27178C5A7EULL,
		0x6B804EBD0359336BULL,
		0x5B46E84E41CCC070ULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2C0224B603C47726ULL,
		0x34D12407D1E85DF7ULL,
		0x7610B29BDF603FFBULL,
		0xC527CAACC97ECD47ULL,
		0x06C35B6E721C7D0AULL,
		0xC2C67C47D8F89726ULL,
		0x18D40688E81D6484ULL,
		0xFF25C753D5C91348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCCC763EE585BB79ULL,
		0x24AB255A40425A76ULL,
		0x150CE7203D50CCF8ULL,
		0xC479A85A9FFF8FBFULL,
		0x8BF02DBD992CE63EULL,
		0x5AF863D4D6684048ULL,
		0x0C8C7EE1D07AB837ULL,
		0xE7F488AC78458CCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0CE5288E641CC5FULL,
		0x107A015D91AA0781ULL,
		0x631C55BBE230F303ULL,
		0x015E62F6568142F8ULL,
		0x8D3376D3EB309B34ULL,
		0x983E1F930E90D76EULL,
		0x145878693867DCB3ULL,
		0x18D14FFFAD8C9F85ULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x422D21428EFADF44ULL,
		0x36D67C11CF8659D9ULL,
		0x2D91957DA2AE94ABULL,
		0x146C1C14EA672B18ULL,
		0x9F2A243647353BD6ULL,
		0x864F715447D35822ULL,
		0x229B18EFDD74C547ULL,
		0xB1FD60BF305412F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x903CA482848B1425ULL,
		0xE4C511BACA62D05DULL,
		0xD16CB32BD12DCE62ULL,
		0x44DDE0A1210C9F6EULL,
		0x97FD895E31CB76EDULL,
		0x046EA51AD57E03F2ULL,
		0x7968A572C65AC406ULL,
		0x37B2814EEF05FD75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD21185C00A71CB61ULL,
		0xD2136DAB05E48984ULL,
		0xFCFD265673835AC9ULL,
		0x50B1FCB5CB6BB476ULL,
		0x08D7AD6876FE4D3BULL,
		0x8221D44E92AD5BD0ULL,
		0x5BF3BD9D1B2E0141ULL,
		0x864FE1F1DF51EF8DULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF0970D43CD7283FULL,
		0x7733C63292C91B8DULL,
		0x7E8E4DF66EEB21B9ULL,
		0x52702613D0858579ULL,
		0x8B22423D3571685EULL,
		0x349C601B5DF0CBD3ULL,
		0xC8570C5F07D0C3EAULL,
		0x8BFDB438939B3D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55288D3B5650005AULL,
		0x0F9607C9F1E77897ULL,
		0x60360CC01BD9BE96ULL,
		0xF6C345483A63018CULL,
		0x3B908E917CC0D974ULL,
		0x1E22B4B3192B4F2CULL,
		0x91FC0D35BB4F0557ULL,
		0xEF5162D84619644FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA21FDEF6A872865ULL,
		0x78A5C1FB632E631AULL,
		0x1EB8413675329F2FULL,
		0xA4B3635BEAE684F5ULL,
		0xB0B2CCAC49B1B12AULL,
		0x2ABED4A844DB84FFULL,
		0x59AB016ABC9FC6BDULL,
		0x64ACD6E0D5825972ULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC578253C1AA90C99ULL,
		0x35D75E50A83AF11BULL,
		0xD4B7615888CFAF05ULL,
		0xF1B2C70E186BB23DULL,
		0x70E18488CA0754B6ULL,
		0xBF028AA1F650811DULL,
		0xAD00059FC51BBCB6ULL,
		0x8977E144F95BF3C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF4772D8FEB695F4ULL,
		0xFB821B8EF439D5C1ULL,
		0xC8E1FF6358D15692ULL,
		0x52F4A43CD1AEBF78ULL,
		0xE45B6519DECE9476ULL,
		0xBEC0F41E442389DCULL,
		0xD8D199D628B93FE0ULL,
		0x2BFDEDF02AED44D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A3F57E4E41F996DULL,
		0xCE5545DE5C0324DAULL,
		0x1C569E3BD01EF997ULL,
		0xA3466332C9C50D45ULL,
		0x94BAE19114C9C0C0ULL,
		0x01C27EBFB27308C1ULL,
		0x75D19C49EDA28356ULL,
		0xA28A0CB4D3B6B714ULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5ABEB0E7243DFD39ULL,
		0xEB1284F5ADBA0A8FULL,
		0x5149652A651AF7A2ULL,
		0x8CAED512A9BCB9E1ULL,
		0x5853179BE495DD91ULL,
		0x1ABFAAF5BB765E8BULL,
		0x7B2EB2CB1A188719ULL,
		0x59E0D552DCBD193EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEAFC5AEF0E60A8ULL,
		0x579BF78A13C1DE49ULL,
		0x0F6779035930BFAAULL,
		0xD4C9EDE0CD88A76BULL,
		0xC72FC9AB4744860DULL,
		0x9206A02ECF73A6DBULL,
		0x6DFB691680E15828ULL,
		0xD3B05A1D8B64BEC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17544CBDCB339D91ULL,
		0xBC89737FBE7BD4C6ULL,
		0x5E2E1C293C2A4808ULL,
		0x586738F264341E8AULL,
		0x9F7CDE30A3D15B9CULL,
		0x88B90ADB7405F850ULL,
		0x16D5DBDD9AF9DF31ULL,
		0x8A508F4F57D9A7F9ULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3437840E5BEBF4A0ULL,
		0xBE107F40811B05C5ULL,
		0x0202C3F342819047ULL,
		0xADA2D0FFDD354EBFULL,
		0x3063DCB88DA9FB61ULL,
		0x2F723EEE3BB8D6AAULL,
		0x9735779BBC1E5399ULL,
		0xD4FF0A796A8F9A69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3841D1FF0BD904DEULL,
		0x058E763C8C85DCE5ULL,
		0x43A77F600D771A14ULL,
		0x78EB417FAD0015D8ULL,
		0x52642088705C9761ULL,
		0x5C252E5AECCC88E6ULL,
		0xF9719635354566F7ULL,
		0x03802028E7CD09BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C7655F15032F07EULL,
		0xBB9E097C0D9ED920ULL,
		0x41A5BC934FF68A53ULL,
		0xD549918070355B67ULL,
		0x6207FC30FDF56C00ULL,
		0x735710B4D7745E4CULL,
		0x6E44E1AE895B356EULL,
		0xD77F2A518D4293D3ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8B94FEAE117F3AEFULL,
		0x098E891A1CD6E70EULL,
		0xCAA7CBED825D1895ULL,
		0xEB7B8109511959FDULL,
		0x9FF18942BE7CBD09ULL,
		0x295BD2C7D95EEB5DULL,
		0x577F778E89CB0C69ULL,
		0x80B9C02E4E31E877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D1C68A5CD49D91ULL,
		0x624E9FA712A17A6DULL,
		0x8AEFBA8AF4CDF9BAULL,
		0xDDCC37A86234F35DULL,
		0x447E95CF36AAD017ULL,
		0xBF44FC93C4611A53ULL,
		0xFE5CF83E4344F718ULL,
		0x9DDD8B3199632502ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F4538244DABA77EULL,
		0x6BC016BD0E779D63ULL,
		0x404871677690E12FULL,
		0x36B7B6A1332DAAA0ULL,
		0xDB8F1C8D88D66D1EULL,
		0x961F2E541D3FF10EULL,
		0xA9238FB0CA8FFB71ULL,
		0x1D644B1FD752CD75ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAFBDD1E7E1865415ULL,
		0x1C2798F32F7415DFULL,
		0xAF96760F0726EAA2ULL,
		0x4BEDADC4850BAE2EULL,
		0x4B3D3A87225F4CCCULL,
		0x2C9CA2EE01464195ULL,
		0xB7334B0F0A937ABCULL,
		0x8FE172C07139D1D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x982D640D823B0BD1ULL,
		0x8ED9E49E642E2C6EULL,
		0x6CA8CD2F205D6249ULL,
		0x92667254C5973070ULL,
		0xC0779B16ABD483AFULL,
		0xA237CB44BEA5D598ULL,
		0xEE58D1B6F2485420ULL,
		0xD103E28D6134AFA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3790B5EA63BD5FC4ULL,
		0x92FE7C6D4B5A39B1ULL,
		0xC33EBB20277B88EBULL,
		0xD98BDF90409C9E5EULL,
		0x8B4AA191898BCF63ULL,
		0x8EAB69AABFE3940DULL,
		0x596B9AB9F8DB2E9CULL,
		0x5EE2904D100D7E7FULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4454099214F63D89ULL,
		0x0E7C6DA3B469D48DULL,
		0x19A0055CD32B1AA5ULL,
		0x6C13863F2280B5A9ULL,
		0x9D2D2DE7E2A0FAA5ULL,
		0xFC83ACAC85AF4FB9ULL,
		0xE61668381DB5CC1BULL,
		0x8B22108420941FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD333BCD768D19E14ULL,
		0x0991665143C1FC69ULL,
		0x4FC38F3D96C66712ULL,
		0x082D50156F693EF0ULL,
		0xB6239F8CEEDE2538ULL,
		0x72108D3969B884B5ULL,
		0x9CE2B796F5EE70A2ULL,
		0x0F4F6FF8BB62D45FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9767B5457C27A39DULL,
		0x07ED0BF2F7A828E4ULL,
		0x56638A6145ED7DB7ULL,
		0x643ED62A4DE98B59ULL,
		0x2B0EB26B0C7EDF9DULL,
		0x8E932195EC17CB0CULL,
		0x7AF4DFAEE85BBCB9ULL,
		0x846D7F7C9BF6CB9AULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDBD3ED79A235E4DDULL,
		0x4A7B951714B6CA38ULL,
		0x1B68EECBE536F2ACULL,
		0x63F96D12458B7E81ULL,
		0x71903AABDD445D3BULL,
		0x3C409B634132BF35ULL,
		0x97D8753DF385A1F6ULL,
		0x399B51F393B1B333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EC329FA1A4F23F5ULL,
		0x58B23BD41BC84DE6ULL,
		0x4C5A4384154461B7ULL,
		0xB2892E77B4663FAEULL,
		0x3C4018A929AC14ABULL,
		0x4F844F07B78FD569ULL,
		0x4F0C56EAD001CBE0ULL,
		0x8B21821324C99D98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4510C483B87AC728ULL,
		0x12C9AEC30F7E87DEULL,
		0x5732AD4FF072931BULL,
		0xD1704365F1ED412FULL,
		0x4DD02202F4E84990ULL,
		0x73C4D464F6BD6A5CULL,
		0xD8D423D723846A16ULL,
		0xB2BAD3E0B7782EABULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7A3D78296230C086ULL,
		0x56450AD2ABCA663AULL,
		0x23F4ED62091DF4AFULL,
		0x908239EC7AB7BA90ULL,
		0xBF36A9B955F244AAULL,
		0x83ECED799900796FULL,
		0xA944F5666A985DF7ULL,
		0x62F2D0BA4C550677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB58B2D08ED3F25ULL,
		0x810C0CEDB113CF72ULL,
		0x07C53946CB90CFB5ULL,
		0x68A95C2205260E23ULL,
		0xBDF8D07AAF2306D7ULL,
		0x94ACF69B70455A66ULL,
		0xC664CBA12B1E396FULL,
		0xF63EFBDF64F73A60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2788F3046ADDFFA3ULL,
		0xD749063F1AD9A948ULL,
		0x2431D424C28D3B1AULL,
		0xF82B65CE7F91B4B3ULL,
		0x02CE79C3FAD1427DULL,
		0x17401BE2E9452309ULL,
		0x6F203EC741866498ULL,
		0x94CC2B6528A23C17ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6BFD966FEFA71E9ULL,
		0x35689FEE5706925AULL,
		0xE9CF99589DFFDEE4ULL,
		0x4C9760837B85641CULL,
		0x0DE7110DEC680393ULL,
		0x9200207C0578636DULL,
		0x74FE1614538EDA73ULL,
		0xBF234056CAF6CF7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x404482A49D9B9986ULL,
		0x4A6C7996292DB838ULL,
		0xEE0F17137A525EECULL,
		0xDD72DB5402B58309ULL,
		0x99B8FFC2C338B5D9ULL,
		0xC813D476BD4E7DA7ULL,
		0x2686CD878E4F5083ULL,
		0x01E66153379BE33EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6FB5BC26361E86FULL,
		0x7F04E6787E2B2A62ULL,
		0x07C08E4BE7AD8008ULL,
		0x91E5BBD77930E715ULL,
		0x945FEECF2F50B64AULL,
		0x5A13F40AB8361ECAULL,
		0x5278DB93DDC18AF0ULL,
		0xBEC52105FD6D2C45ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x237B911575838B24ULL,
		0x2778B890D3883F32ULL,
		0xBE3BB24B39FF8651ULL,
		0x591244AC961B6B34ULL,
		0xAAFC4B1383C37ECDULL,
		0x9FE4D314B263868BULL,
		0xC25F0E1881F8712CULL,
		0xD37DFECD1CA760FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF75750DC096E9DFULL,
		0xE8457B1ED51EE9CFULL,
		0x0C01739288F01495ULL,
		0x155A8C55E738A30AULL,
		0xE1CB2D7CE1CFD4B6ULL,
		0x6D6363AA51C3BB1DULL,
		0xD295826705D931EFULL,
		0xBA6AD5FA05BDC5AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC0EE418B51562FBULL,
		0xCF3DC38E0696D6FDULL,
		0xB23AC1D9B10F92C4ULL,
		0x4C48C8F97123C83EULL,
		0x4B37666F620CAA7BULL,
		0xF287B0BEE3A03D96ULL,
		0x10CA8C7F842140C3ULL,
		0x69172B37191AA554ULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCC5E967AD47FA3F4ULL,
		0x55136809542106C5ULL,
		0x2585612333E1DE42ULL,
		0x71C63767CCC6CFC7ULL,
		0x04413D248029FDD8ULL,
		0x7319DE7F2D3BEE13ULL,
		0x6C6932441088034AULL,
		0x62EBF87F463BBF2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2458892E3020744ULL,
		0x497AB4B8D5E792BAULL,
		0xBAE4FF6D063F6D22ULL,
		0xE5DF6F1588671427ULL,
		0x53EB13CF17E17727ULL,
		0x5CD1FCF09DF24F1AULL,
		0x8FCA7C60F870924CULL,
		0xDD38444207FE98D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E1B1EE8377DA4B0ULL,
		0x1C69DCB181C6947FULL,
		0x9F619E4E35DEB360ULL,
		0x9419587244A1DBE0ULL,
		0x57AA2EEB97C88AFFULL,
		0x2FC8228FB0C9A109ULL,
		0xE3A34E24E8F89106ULL,
		0xBFD3BC3D41C527F5ULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x912294378B6A9EB1ULL,
		0xF90768F5FD593DB0ULL,
		0xFFE4D05F8046C130ULL,
		0xE0A1DE343EBEB0A0ULL,
		0x071AFA95881A0A92ULL,
		0x6BD73814818D0B8DULL,
		0x028C78AC1380E6D9ULL,
		0x56ACE20873BB7BA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C6BFC6FBA3CC4C3ULL,
		0x8DE6EF2C72EA0FABULL,
		0x84D8A5276C9FD9AEULL,
		0x31BE5ED7E84BC3DFULL,
		0x3D4C081A7B2A1261ULL,
		0x10A9422DCF7ADBC1ULL,
		0xA307E6FCEE0BC610ULL,
		0xA702A0DFD0A63FE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD49685831565A72ULL,
		0x74E187D98FB3321BULL,
		0x7B3C7578ECD9189EULL,
		0xD11F80E3D6F5737FULL,
		0x3A56F28FF33018F3ULL,
		0x7B7E7A394EF7D04CULL,
		0xA18B9E50FD8B20C9ULL,
		0xF1AE42D7A31D4440ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCC8C0D8244477C57ULL,
		0x759D8FFD1161898BULL,
		0x8097107CEC33AC13ULL,
		0x43D6C0D98C721DE9ULL,
		0x1543C596E683EC25ULL,
		0x3DB3F3732D9FE76EULL,
		0x08D2D4608648D905ULL,
		0xCC3C4897556B866FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FEAF2C73475B23BULL,
		0x58413BD60915F3E8ULL,
		0x503E62C2BE94AE1CULL,
		0x4C201ADF6BE775AAULL,
		0xD14257A583EC6EC7ULL,
		0x0EF20F61812583FAULL,
		0x4BCB7A8CD7523F6BULL,
		0x7A9A4727EA41DCAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF366FF457032CE6CULL,
		0x2DDCB42B18747A63ULL,
		0xD0A972BE52A7020FULL,
		0x0FF6DA06E7956843ULL,
		0xC4019233656F82E2ULL,
		0x3341FC12ACBA6494ULL,
		0x4319AEEC511AE66EULL,
		0xB6A60FB0BF2A5AC0ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC3EF8674A72A05F9ULL,
		0xC3E4842F1C87FB4AULL,
		0x516E7A629A4C2737ULL,
		0x966DC6C930F82DABULL,
		0x6C9BF5B3109C3F6BULL,
		0xE230ABF11E1B5CDBULL,
		0x9323991F7BDBE9E0ULL,
		0x79DE30C30D238902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E407727ECC7975ULL,
		0x6B23CF6F6D9C337CULL,
		0xF46D0D23184800D8ULL,
		0xBD10593F90D959BAULL,
		0xFAB23BD3E903065DULL,
		0x2D034AD13984ED49ULL,
		0x5CCFE3C287562E20ULL,
		0x3BAE6C7096688F5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x930B8106D9E67C8CULL,
		0xA8C74B40711BC836ULL,
		0xA5037741820427EFULL,
		0x2B7D9FF6A0217411ULL,
		0x9629CE60F99F3936ULL,
		0xCF33E120279FB192ULL,
		0xCFEC7ADDFC8DC7C0ULL,
		0x42705CB39B4B0659ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B6A1582479F1D23ULL,
		0x69C62B7A7A540B17ULL,
		0x66CC06BC6CF29984ULL,
		0x0B0BAC94B3266B82ULL,
		0x2A30B3F8F0E868E5ULL,
		0x9B19E63DC4D7A13EULL,
		0x23CD407F58881C8EULL,
		0x102684AEEF3CDD57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x000DDDE25E666B8EULL,
		0x0CC95B8572EC2EE7ULL,
		0x333F39D78F7E9D9AULL,
		0x423E9132E4727824ULL,
		0xEC53FF4C9113CEE6ULL,
		0x9C09873E86B24D3CULL,
		0xE4B04E8FB69563BFULL,
		0xD643A5B8B3F9CCA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B67C86019F976ADULL,
		0x650F70FF08B825F0ULL,
		0x55F33F6BE38C041EULL,
		0x49353DA6575413A6ULL,
		0xC6634CB461FBA603ULL,
		0x071061034265EC02ULL,
		0xC77D0EF0EE1D7F31ULL,
		0xC66521165CC511F2ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x47129C47F8125708ULL,
		0x5379D949E5AA029DULL,
		0x5BF04D863148F9E1ULL,
		0x14697289E0CADC5AULL,
		0xA0D488A49677A4EEULL,
		0xF88B9145F9EE3720ULL,
		0x47C2CF8C9706E269ULL,
		0x1D314A33268B08FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855CD500AAFB040DULL,
		0x178A950A55F28892ULL,
		0x46757F0F7493A1E4ULL,
		0xD1B0AD2716F7D868ULL,
		0x3D7F3F7BF59D7E1CULL,
		0x4443BBAA411F516EULL,
		0xC392AB71DB199A3BULL,
		0x70E3B26E92AA8025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC24E494752E95305ULL,
		0x44F34C43B0588A0FULL,
		0x1D85328945DB5805ULL,
		0xC5D9DFAEF63D0432ULL,
		0x9DABB7DF63EADAF2ULL,
		0xBCC82AEFB8F1664EULL,
		0x845064FD4C1F7852ULL,
		0x6DD2F85DB42188DEULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA436B2875B5F1A9AULL,
		0xF703EE9AD74BA0E7ULL,
		0x9235AA688AA59928ULL,
		0x0697047585956420ULL,
		0xFBBF7C1AA3943880ULL,
		0xD2A644EE6EBE4494ULL,
		0xE93111FFBA0FF059ULL,
		0xCBF8D8CEB529E1D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE6821CB29A14EBCULL,
		0xC2EB10D80ADCE5B5ULL,
		0xDA1FD1834E02631FULL,
		0x9FCF60DC50DA24C2ULL,
		0x08F7593C6D182672ULL,
		0xAB24BCC496496223ULL,
		0x1EF4E204D713F89DULL,
		0x3137F9D89FB787D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A5E934C72FE5426ULL,
		0x35E8FE42DD974552ULL,
		0x482A7BEBC4A7FA37ULL,
		0x995864A9D54F40E2ULL,
		0xF3482526CE8C1EF2ULL,
		0x7982F82AF8F726B7ULL,
		0xF7C5F3FB6D1C08C4ULL,
		0xFACF21162A9E6607ULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2E47F3E7B1670A14ULL,
		0x79DE804A552EB15AULL,
		0x0974D5B0692F239EULL,
		0x1EC55D388A04C26EULL,
		0x959E97F8A7F8E315ULL,
		0x42317643C17DAC35ULL,
		0xDD042E72A26D5ACEULL,
		0x7DAC8FB7B5D7C324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F97349B95FCFADULL,
		0x846895D7C429801DULL,
		0x3DE3B57270B35763ULL,
		0xAEFBF6DE4C880DCAULL,
		0xEAF608A1B4535577ULL,
		0xCBB8E8F5C19E0AEFULL,
		0x88FB5C6EB1A94672ULL,
		0xA873A8466492B1C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8BE80AE0838C5B9ULL,
		0xFDB6159D91073147ULL,
		0x349760C2199C74FDULL,
		0xB03EABE6C68CCFA4ULL,
		0x7F689F5913ABB662ULL,
		0x89899EB600E3A6DAULL,
		0x55FF721C13C41CBCULL,
		0xD5DF27F1D14572EDULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4CC13F7D15D51BE1ULL,
		0xFCD6560AA630CE05ULL,
		0x7579E827FC2F4585ULL,
		0xC654683B642CD2F4ULL,
		0x243F715FF8100FB2ULL,
		0x55B32330B92EBA17ULL,
		0x899512980584EFA6ULL,
		0x8FBCC79AA3D464C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C1F4F5972C853FFULL,
		0x6A04984587FA4622ULL,
		0x7E8C801E263E33D9ULL,
		0x60E8FDFB512015D3ULL,
		0xD2E0AAE205F4A856ULL,
		0xC5208C25EE70C7F3ULL,
		0x42C6F5CA0EA58B45ULL,
		0x2E528D612689404FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70DE7024671D481EULL,
		0x96D2CE4F21CA8827ULL,
		0x0BF56839DA11765CULL,
		0xA6BC95C0350CC727ULL,
		0xF6DFDBBDFDE4A7E4ULL,
		0x9093AF15575E7DE4ULL,
		0xCB53E7520B2164E3ULL,
		0xA1EE4AFB855D248AULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x76B48D95C4A58F6CULL,
		0xDA899FD4E648BB9BULL,
		0x7FD750AC66363C0AULL,
		0x60FD284BE2CDFF1CULL,
		0x03A316676FFD8395ULL,
		0xEF08CFCC9DAC1753ULL,
		0x6BA31C452EF78F5EULL,
		0x4C4A425C2C001A99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D1874B4AB90302ULL,
		0x82FD1482B75E969DULL,
		0xDFD1358A34A3B226ULL,
		0x3CC5C51A6FFDC641ULL,
		0x1AC537E691CF67AFULL,
		0x9AFFD27B4B8EE48DULL,
		0x485712AD2B3ABEDDULL,
		0xABB7413EA8EDA32AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04650ADE8E1C8C6EULL,
		0x58748B5651162D06ULL,
		0xA006652652958E2CULL,
		0x5C38ED518D30395DULL,
		0x19662181FE32E43AULL,
		0x75F71DB7D622F3DEULL,
		0x23F40EE805CD3183ULL,
		0xE7FD036284EDB9B3ULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE899ECF72F75702EULL,
		0x5D23B2A8249A1B90ULL,
		0x94A6F80BF36ECD70ULL,
		0xE835EE429F011E5FULL,
		0x4F76CB225D1723F2ULL,
		0xCF2636AB03D932BAULL,
		0x863EC4655D3683E0ULL,
		0x34B80DA359AF1751ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB5EE82D3CD4F1C6ULL,
		0xC9CA1AC687E17C14ULL,
		0x3784D8F4E3CB1A4CULL,
		0xD9983ABF8B477563ULL,
		0xB620A8E6073225BAULL,
		0xD1420D428F364252ULL,
		0xDBCC6693F710BBF2ULL,
		0x8F1379449C1C9ACAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43C704DA13A181E8ULL,
		0x94E9A86EA37B6784ULL,
		0xA32220FF10A5D73CULL,
		0x31ADD4FD14466B3CULL,
		0xF95663C45A250648ULL,
		0x1E643BE98CEF70E8ULL,
		0x5DF2A2F6AA263812ULL,
		0xBBAB74E7C5B38D9BULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x099E49BA5388DF83ULL,
		0x985407A285DAABDBULL,
		0x2337A242C3A06314ULL,
		0xE34D8485E6730537ULL,
		0xE266D491A97E0429ULL,
		0xFD8ED3B454C9F0F3ULL,
		0x540ACE8625C2C479ULL,
		0x8E1E19CF09683CD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955911CFD924DA84ULL,
		0x2167ADFDFB98726AULL,
		0x3E10FDA1C37F250EULL,
		0x99C854F28D5096A1ULL,
		0x1E0AEED1BB86DBA9ULL,
		0x00FBF15315DC079AULL,
		0x53BA5DD2FE9C4754ULL,
		0x58EE067C42B57EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CC758758AAC0507ULL,
		0xB933AA5F7E42D9B1ULL,
		0x1D275FE300DF461AULL,
		0x7A85D0776B239396ULL,
		0xFC6C3A4012F8DF80ULL,
		0xFD7522E74115F769ULL,
		0x07B09354DB5E832DULL,
		0xD6F01FB34BDD4262ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x93B84A57C4C3F0A4ULL,
		0xFFA47F4898DE2D39ULL,
		0x6F1C1B7C35E4A237ULL,
		0xB701C0483C10C938ULL,
		0x8F3E1E446BDE7FC5ULL,
		0xC821BA611A259973ULL,
		0x5A10B7BB30C9959EULL,
		0x6998BBDFD6E46FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0047585596A96C3ULL,
		0x3797BFD7F6404913ULL,
		0x659FBBDDAC23A7B4ULL,
		0x6CF0CB37C1F828BDULL,
		0x5BAAE53A3B454FD5ULL,
		0x17312033568B64E1ULL,
		0x7ECE2AEE1344B19DULL,
		0x8DF7369B1E275D33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33BC3FD29DA96667ULL,
		0xC833C09F6E9E642AULL,
		0x0A83A0A199C70583ULL,
		0xDBF10B7FFDE8E185ULL,
		0xD494FB7E509B3010ULL,
		0xDF109A524CAEFD92ULL,
		0x24DE9D55238D2403ULL,
		0xE46F8D44C8C332C0ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA25EF77334B70AE7ULL,
		0x09B6396DC8F647B8ULL,
		0x045F95CA0F68AD41ULL,
		0x4BF05FAA6B1E0879ULL,
		0x69686F33BD96D7E8ULL,
		0x08B1E4A40CD2EA8CULL,
		0x6354478A0E16BFADULL,
		0xE0C41898CA2B856EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D1EF2AD94235AEULL,
		0x5DD85ED7BE3576C0ULL,
		0x5E65BB6434414934ULL,
		0x97E9C388E4F57E49ULL,
		0x6DD07A62C21C86EEULL,
		0xCE5863E7001496C7ULL,
		0x8F92E71ED79ECD47ULL,
		0x76D13082F5579A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x128F1859EDF53F49ULL,
		0x546E67BA76C33178ULL,
		0x5A3A2EAE3B29E475ULL,
		0xDC199C228FEB7630ULL,
		0x04B815517F8A5106ULL,
		0xC6E987430CC67C4BULL,
		0xECC6A094D98872EAULL,
		0x9615281A3F7C1FE3ULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF4AE2BAF85BB6454ULL,
		0x20168EE7A9F4A135ULL,
		0xEEEFAF29B2AD4BD6ULL,
		0xCFAB0A12D0C34562ULL,
		0x4F70226B2E22BC69ULL,
		0xFB2D39B02B4EF1FEULL,
		0xBB28449C6B80D56FULL,
		0x583E8049A121B4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BC527579450AE1ULL,
		0xD4117A09B18586A3ULL,
		0xBB5BA1056A2414E4ULL,
		0xAA5DF4D7D49723B5ULL,
		0x4EB18EADA6463FCDULL,
		0xFC612A095DBCB780ULL,
		0xD273A8AD7B404952ULL,
		0xED764E1C0DA0D155ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE01279DAFCFE6EB5ULL,
		0xF407F4EE18712796ULL,
		0x55B40E2CD8895F32ULL,
		0x65F6FEC5045466D7ULL,
		0x01C1ACC6886483A4ULL,
		0x074C13B976F2467EULL,
		0x695BEC3110C09C3DULL,
		0xB548CE55AC8165F4ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1F6C5D3AA79CB77AULL,
		0xB7D1CFB80A29CAC3ULL,
		0x125BEC4365ABEA01ULL,
		0x8EAB57A32E9DCE17ULL,
		0x70295911A0C90549ULL,
		0xBB516DCECC516F24ULL,
		0x7F44F70E6F9F0260ULL,
		0xF437F4AB21497592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F20493256EF89C0ULL,
		0x545EB2A3F7968F5DULL,
		0x7A5A4332421AD5D9ULL,
		0x4FC60412A8D96B04ULL,
		0x15072F26172D98D1ULL,
		0xDC413570A4B4BA15ULL,
		0x1AE564F9BEEB5C0CULL,
		0xC8DCA4A184CDA39DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004C1408F1733EBAULL,
		0xE38F7D1BFDBF459EULL,
		0x6801AF7127B13FD8ULL,
		0xC16D53B18644A513ULL,
		0x652E7637B7E49D98ULL,
		0x671058BE68E5D531ULL,
		0x65A193F7D1745E6CULL,
		0x3CEB500AA584D60FULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0E722AFBD16D4685ULL,
		0x9D6692EF76B5F1A4ULL,
		0x4101439BC675AD6CULL,
		0xEAD220539BE81BA6ULL,
		0xF4C826583C4CD29FULL,
		0xA6FF3625CB5C1550ULL,
		0x0898D0CBAEB2A2BEULL,
		0x370230EF79D42ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD0D5C0614B5165ULL,
		0x72A01B39A7A5528FULL,
		0x3C279E5463E96143ULL,
		0x66BFFBCA700F57D8ULL,
		0x13369F248DEF7F3FULL,
		0x6618D8FBF1E6255AULL,
		0x6A7BEB88929FC2E2ULL,
		0x54037A1C6E7D8AD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13A2FF3BB02617E0ULL,
		0xEFC689D6D110A32BULL,
		0x7D26DDCFA59CCC2FULL,
		0x8C6DDB99EBE74C7EULL,
		0xE7FEB97CB1A3ADA0ULL,
		0xC0E7EEDE3ABA300AULL,
		0x62E33B433C2D605CULL,
		0x63014AF317A9A40EULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCC99062C52381F5FULL,
		0x7F9B6EFDB2427894ULL,
		0xB75CB51DA11C6F0DULL,
		0x8A28206EFE6F397FULL,
		0xEE6E9CFFE769DA7AULL,
		0x8CBFB3057DF81BA0ULL,
		0x433FC66DA772803FULL,
		0xD113674B6985682BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E8260D59F119B2ULL,
		0x8DFD6581EA195E51ULL,
		0x4783397B6749627DULL,
		0xD9DD08CD7CFF3291ULL,
		0xC3BF7A84D065A07FULL,
		0xAA7B4DA0B33ACA20ULL,
		0x6219A33383121DB6ULL,
		0xAA4F4BD5E034D350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C7120210BC906EDULL,
		0xF2660B7C585B26C5ULL,
		0xF0DF8C66C6550D70ULL,
		0x53F528A382900BEEULL,
		0x2DD1E67B370C7A05ULL,
		0x26C4FEA5CEC2D180ULL,
		0x2126655E24609D89ULL,
		0x7B5C2C9E89B1BB7BULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x376980A7C674F0AEULL,
		0x99AA047E3BB1D5E3ULL,
		0x4D06E477A627D01CULL,
		0xFCDE9EC9FE576826ULL,
		0xA571018DC9E89D23ULL,
		0x3B520863D7B06603ULL,
		0x8F8A054FE6D4BE2EULL,
		0xD1AA2341AD326AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD99A79046D755CFCULL,
		0x903805541654E3B3ULL,
		0x3773CA890D507D26ULL,
		0x3E864D677AD17F2DULL,
		0x31089D371747AE22ULL,
		0x2BB156C4F8BCFAD0ULL,
		0xBC7ACBD872C66B65ULL,
		0x711174CAE9332AA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEF3F9A3AB01AC52ULL,
		0x0992012A2DE53650ULL,
		0x7A752EFEAB77AD3AULL,
		0xC258D3AE8486170BULL,
		0x94799CBADEAF3301ULL,
		0x10E35EA72F0C9CD3ULL,
		0x33F0CE979412D54BULL,
		0xA0BB578B4401406FULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6DB03B37A724F59DULL,
		0xF70C3A0ACC8DE223ULL,
		0xF6594AFA274B2EEBULL,
		0xD3907C88B86C9FB2ULL,
		0x5CDDAAB410AF1ADEULL,
		0x98810A57E8C9820AULL,
		0x13EA68220FB300CFULL,
		0xEEA9A4FAB2AE8172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D59319CC8EB9EAULL,
		0x93D661B1F592533BULL,
		0xBC73CD2D58033A6CULL,
		0x4771070971B3FE55ULL,
		0xD85F7C7338B03F8CULL,
		0xDE012D309660188FULL,
		0xAC44A583D9D90489ULL,
		0x597EDDD14A4A0306ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A65A82E6BAA4C77ULL,
		0x64DA5BBB391FB118ULL,
		0x4A2A87D77F481487ULL,
		0x94E17B81C9DF61E7ULL,
		0x8482D6C7281F2552ULL,
		0x468027677EA99A85ULL,
		0xBFAECDA1D66A0446ULL,
		0xB7D7792BF8E48274ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAF832732F29CF93BULL,
		0x808C4DB6699B6573ULL,
		0xE8970C76C221F286ULL,
		0xEF7AECA3CA1E6F7FULL,
		0x263436805F376DCAULL,
		0x5280AE056E0C077EULL,
		0xBDC6C3DA67F4F294ULL,
		0x67C61665DB3CA8C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CFE0028D6A7DA40ULL,
		0x76C9069CA17D5BE5ULL,
		0x8C99442CCFFF3BFBULL,
		0x2DFB7E1072BDA300ULL,
		0x5148BF512E06AE15ULL,
		0xA86714655F35ADC6ULL,
		0x8E5956F071D560A4ULL,
		0x672C5004CE5E50F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x937D271A243B237BULL,
		0xF6454B2AC8E63E96ULL,
		0x640E485A0DDEC97DULL,
		0xC28192B3B8A3CC7FULL,
		0x777C89D17131C3DFULL,
		0xFAE7BA603139AAB8ULL,
		0x339F952A16219230ULL,
		0x00EA46611562F836ULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFEB6F5BDB1026C40ULL,
		0x756CB9650412AA11ULL,
		0xA9420CBE26F67971ULL,
		0xA14594F046F2474BULL,
		0x8106D5954A59F5E0ULL,
		0xB2E901126F2175BAULL,
		0xC4694B594F5CE83EULL,
		0xAD7003F04A5B34A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D71E75B9DB8679ULL,
		0x103E6BB9CA3B9C4CULL,
		0x741BB5FE6AFC34C0ULL,
		0x7FFCBA108BD4D9A7ULL,
		0x9DFAE7AAE93B647EULL,
		0xBE3D405828630F97ULL,
		0x43BC14DA38F2385EULL,
		0x1919C7D7B559618BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC61EBC808D9EA39ULL,
		0x6552D2DCCE29365DULL,
		0xDD59B9404C0A4DB1ULL,
		0xDEB92EE0CD269EECULL,
		0x1CFC323FA362919EULL,
		0x0CD4414A47427A2DULL,
		0x87D55F8377AED060ULL,
		0xB469C427FF025529ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5334AE75FBE4D49ULL,
		0x08DA90371AB241C7ULL,
		0x678BC78BF7CA4D35ULL,
		0xA742F0A5D0395220ULL,
		0x174B5D7BF4D86C10ULL,
		0x0B8F2707837547FAULL,
		0x341C8FE8D71BD962ULL,
		0xB3D40FAB5D31ED9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE0A58DACE5CC28ULL,
		0x3AF0FB155090B269ULL,
		0xF9500C2FC286B04EULL,
		0x51C048C00083D7F4ULL,
		0x5D538E887B1F6420ULL,
		0xFEAAC9F2AB74DC89ULL,
		0xD058A7C2D3CE40F6ULL,
		0x12E475EC9086C952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFD3EF6AF35B8161ULL,
		0x322A6B224A22F3AEULL,
		0x9EDBCBA4354CFD7BULL,
		0xF682B865D0BA85D4ULL,
		0x4A18D3F38FC70830ULL,
		0xF525EEF528019B73ULL,
		0xE444282A04D59994ULL,
		0xA1307A47CDB724CDULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFB5D8CB40CCF1816ULL,
		0x523155B7DD9402E0ULL,
		0xFC6DD99DD2D75C87ULL,
		0x7A6B3925AA354D8FULL,
		0xFD1A3B8EEF1AC22BULL,
		0x534093E61AEFF8D4ULL,
		0x4362727F35AC2570ULL,
		0x93C61A81B7DC07E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2386520381A3A129ULL,
		0xD2A610C2B9396B24ULL,
		0xF861C352617271E6ULL,
		0xFA77ADC2CC552366ULL,
		0xC094933BF48F788DULL,
		0x71906C76E46727C1ULL,
		0x70E3871EAB6CE13DULL,
		0x4BF43A3A3DC2879EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8DBDEB78D6CB93FULL,
		0x8097457564AD69C4ULL,
		0x040C1ACFB3A52D61ULL,
		0x801C94E766606EE9ULL,
		0x3D8EA8B51B95BAA6ULL,
		0x22D0FF90FE88DF15ULL,
		0x3381F5619EC0C44DULL,
		0xD83220BB8A1E807EULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF9977C67EF08D53ULL,
		0xBFA39F128710EF43ULL,
		0x9F70CA0D7F8AF464ULL,
		0x6257820EE8014685ULL,
		0x329018087456A6BAULL,
		0x11E2911C4F09CC38ULL,
		0xA160E86B3446D964ULL,
		0x1D770E714CA9965DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9420C2306BEB1F10ULL,
		0x439EFC7949F8E27AULL,
		0x2153D3FE474E66D9ULL,
		0x158EC2B583224C76ULL,
		0x47499958E2729146ULL,
		0xC7F97B05406380D1ULL,
		0x377CCA94EEE903EFULL,
		0x1D89A189DCAC8B6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BB9B5F6151B9243ULL,
		0xFC3D636BCEE80D39ULL,
		0xBE2319F338C492BDULL,
		0x77D940BB6B230AF3ULL,
		0x75D98150962437FCULL,
		0xD61BEA190F6A4CE9ULL,
		0x961C22FFDAAFDA8BULL,
		0x00FEAFF890051D37ULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD8893F4167D2EDAAULL,
		0xAFA704BA0485C55AULL,
		0x4C5573B0B0AAE7D7ULL,
		0x1C3AF6AFDF0829B3ULL,
		0xD0C77E1FF2A78FC4ULL,
		0x88F49313ACB6A647ULL,
		0x852C2123CFA0C6FAULL,
		0x6E7FFE2B94C4E12DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB222CAD92A4B017AULL,
		0x2CBA0446D3DF9EF1ULL,
		0x9308C44FB41C691EULL,
		0xEB14A08C9650276FULL,
		0xF8481CD681115B2BULL,
		0x858E517D7E8381CCULL,
		0x5CE8E5038669BCBFULL,
		0x92A4115E857B046EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AABF5984D99ECD0ULL,
		0x831D00FCD75A5BABULL,
		0xDF5DB7FF04B68EC9ULL,
		0xF72E562349580EDCULL,
		0x288F62C973B6D4EFULL,
		0x0D7AC26ED235278BULL,
		0xD9C4C42049C97A45ULL,
		0xFCDBEF7511BFE543ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3DBAF9C24552C8FAULL,
		0x4DD0F2AFBA3B1BF8ULL,
		0xA455DD6F3F0E9D1AULL,
		0xC25F917D9C2AEA94ULL,
		0x7BEB9582EA3F556AULL,
		0xC180BC79FEACC8C8ULL,
		0xD170A4F2912C721DULL,
		0xC79990A32D8F989EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B1A041EC63EBCECULL,
		0x74218B22B966061EULL,
		0xB2C12B5885E1446BULL,
		0xD3A565304F86FBA1ULL,
		0xCE6F0717EC7185A2ULL,
		0x2E83B66AE7108DB6ULL,
		0x34BA2618D08B1E1FULL,
		0x33BAB26CC05D8280ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A0FDDC836C7416ULL,
		0x39F1798D035D1DE6ULL,
		0x1694F637BAEFD971ULL,
		0x11FAF44DD3AC1135ULL,
		0xB5849295064ED0C8ULL,
		0xEF030A1319BC457EULL,
		0xE5CA82EA41A76C02ULL,
		0xF42322CFEDD21A1EULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x78BC67B92FDAEC96ULL,
		0xB2063D7AE0DC6DD6ULL,
		0xD5E57D186B98CBB1ULL,
		0xA355BB633843D535ULL,
		0x736B7C66FFFEC0EBULL,
		0xA562371A5CC88982ULL,
		0xB459A99461D78C50ULL,
		0xD3BEA08563CAA2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE13C95C5352A93CEULL,
		0xE15B4B788EFDA03DULL,
		0xC2ABAE66A766A032ULL,
		0xB31D84D19E17ACB5ULL,
		0xE48FD9A2B28F36C8ULL,
		0x920832FCC2A7CBE9ULL,
		0x4AC982A1C7A71FD4ULL,
		0x582DE975C20B94CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9980F27C1AF07F58ULL,
		0x535D76026E21CDEBULL,
		0x174ED37ECCFE6B83ULL,
		0x10483FB2A6547980ULL,
		0x97E4A5C44D71F623ULL,
		0x376A05E69E6F426BULL,
		0xFE902B35A6709384ULL,
		0x8B9349F0A1C1367EULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBC0E0A8DCC8BF3EBULL,
		0xDA4DAB71F1A0D08CULL,
		0x1BEEE9E3CE682E5DULL,
		0xE1E9A1AA4D9F40B0ULL,
		0x0B36C684DC5C4A54ULL,
		0x56100F84A3E6B3AEULL,
		0xAAC96C3F0081FB89ULL,
		0x6B3D0F4453DAB22DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4F7DE37917201AULL,
		0xF721C6C41DC473AFULL,
		0xF19BEDFA682D126EULL,
		0x8260DA520BDA3D33ULL,
		0xCD06DC0F22232AF7ULL,
		0x8B1F730FD509EB2AULL,
		0x4B4F5BD0FB827422ULL,
		0x940827FF4F5ED06EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5641776EB59CD3F1ULL,
		0x2D6C6DB5EC64A323ULL,
		0xEA750419A6453C33ULL,
		0x63897BF846457D83ULL,
		0xC6301A8BFE7F60A3ULL,
		0xDD0F7C8B76EF5884ULL,
		0xE18637EFFB038FABULL,
		0xFF3528BB1C846243ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDB14773D109B902CULL,
		0x159B148EC07246D3ULL,
		0x669C08DA2D01211DULL,
		0x878885CBEB45B04CULL,
		0xE3073C581BB435EFULL,
		0x952EDFEDFBB42CFAULL,
		0x19A214CEF7D4C900ULL,
		0x76DF102A86353009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51E32068A445F56ULL,
		0x151D070A554A49B5ULL,
		0xD9E89C71FEDE77DAULL,
		0x77E80A8EAE14D082ULL,
		0xEAF9B00545345289ULL,
		0x810519B0DD9B31E7ULL,
		0x656F2312401B56E6ULL,
		0x1BFA114237D7FAABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E0A453B9ADFCF7AULL,
		0x0086138495380F66ULL,
		0xBF7494ABD3DF56C7ULL,
		0xF0608F45455160CEULL,
		0x09FE8C5D5E806766ULL,
		0x142BC65D262F1D1DULL,
		0x7CCD37DCB7CF9FE6ULL,
		0x6D250168B1E2CAA2ULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x91C2CBBC9F3BE9E7ULL,
		0xF2D79B4FC729AC8CULL,
		0x2BDBF82AAF2D432BULL,
		0xD18B53EB5C44914FULL,
		0x075313D90C14FEB4ULL,
		0x14FFB249EF0C4475ULL,
		0xDB7D125FA17BC9EFULL,
		0xE5420CBB13630EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5BA4B6F908DE363ULL,
		0x71C11C86881E9425ULL,
		0x06EAD24511495F7EULL,
		0xE70A5AC37567F299ULL,
		0xEEB65C3704E08A76ULL,
		0x385B9835FEF01A01ULL,
		0xD236C0D9CF1A9C1AULL,
		0x387277958D8A8B1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x247880D30FB60A84ULL,
		0x831687C94F3738A9ULL,
		0x2D312A6FBE641C55ULL,
		0x36810928292363D6ULL,
		0xE9E54FEE08F474C2ULL,
		0x2CA42A7C11FC5E74ULL,
		0x094BD2866E6155F5ULL,
		0xDD307B2E9EE985B3ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC22DBF230FF4D39EULL,
		0x4A7C8B91F0D6AF20ULL,
		0x5D2A0B3E022FCDB0ULL,
		0x90F1E51EEB6F9361ULL,
		0xD05985ECE19BD5DEULL,
		0x71F1522345830A0DULL,
		0xF51C7072134DACA8ULL,
		0x64A24897604CB494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x370DCCB35C1D3961ULL,
		0x447A12D3A5950859ULL,
		0x06CD9FA975CAF6D7ULL,
		0x67E2C5A2341C775DULL,
		0xB56EF29865B94988ULL,
		0xE292E1E17FAC2449ULL,
		0xA44B847EBDA34FF4ULL,
		0xF9479741C831646BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF520739053E9EAFFULL,
		0x0E0699425543A779ULL,
		0x5BE7949777E53B67ULL,
		0xF71320BCDF73E43CULL,
		0x6537777484229C56ULL,
		0x9363B3C23A2F2E44ULL,
		0x5157F40CAEEEE35CULL,
		0x9DE5DFD6A87DD0FFULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x076B5253055D89DEULL,
		0xA55436550DA6701BULL,
		0x2D1BD39CCA0D1374ULL,
		0x3686F2979ABF4139ULL,
		0x3E1A0CDFFD9B8762ULL,
		0xF3B3516EE6C7072FULL,
		0xE04B34A5DD3D128FULL,
		0x139CD7D923FE4AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF19956B1101FC7D4ULL,
		0x61B9400B7EB972D3ULL,
		0xC83A699E8017CC33ULL,
		0x5FDBFBA0A21554C6ULL,
		0x9220EBE604BCA356ULL,
		0xF12FC4799CDBBB72ULL,
		0x9398CD31DE329A6EULL,
		0xC73DD0950553BC17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6F204E215424E0AULL,
		0xC4ED765E731F02C8ULL,
		0xE521BA024A1ADF47ULL,
		0x695D093738AA15FFULL,
		0xAC3AE739F9272434ULL,
		0x029C95177A1CBC5DULL,
		0x73D3F994030F88E1ULL,
		0xD4A1074C26ADF6B5ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE56AC18C1D6A8425ULL,
		0xA3FC8F0AC97A6B39ULL,
		0x1BC31875D7870873ULL,
		0xE6AF1D4FFECFE498ULL,
		0xFDEF5C4DC67765A5ULL,
		0x8F7A186B2977BFCFULL,
		0xE69B69294F711310ULL,
		0xE425814243AF47E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x045F874E84014EA5ULL,
		0xD7F2A32872DD134AULL,
		0xCF4C22F4DBB1D6FDULL,
		0x26786F3D63426E06ULL,
		0x0B1D2B18458396DAULL,
		0x837D6D2F7EF06451ULL,
		0xD11D8348783BDF60ULL,
		0x6F1597A0CB7DD5B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE13546C2996BCA80ULL,
		0x740E2C22BBA77873ULL,
		0xD48F3A810C36DE8EULL,
		0xC0D772729D8D8A9EULL,
		0xF6F2775583F4F37FULL,
		0x0C0775445787DB9EULL,
		0x3786EA61374ACC70ULL,
		0x8B3016E288D2925FULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCCCD644580B87435ULL,
		0x95DBFC6069B16228ULL,
		0x21BC278F88DFC888ULL,
		0xDAA12C98EB12D41FULL,
		0xC6DCA3259587C3C0ULL,
		0xF03E885A6D716622ULL,
		0x73AA134D777B4A73ULL,
		0x5B811D82F05168B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8F4401825DDB8C5ULL,
		0x4A88D81A37F8ACFBULL,
		0x4020C81B3D8643C1ULL,
		0xFBC3882F81111C67ULL,
		0x3B2127E0F164B191ULL,
		0x8B3420ECB376B48FULL,
		0xDDBED786C872B332ULL,
		0xCFB13A65CED0A899ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7439245DA565CCF0ULL,
		0xDF53247A5E49CED3ULL,
		0x619CEF94B5598B49ULL,
		0x2162A4B76A03C878ULL,
		0xFDFD84C564E37251ULL,
		0x7B0AA8B6DE07D2ADULL,
		0xAE14C4CBBF09F941ULL,
		0x943027E73E81C02FULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x19CB0228493F99A1ULL,
		0x6EFC1950D997F7C1ULL,
		0x7D0FCAF74817A510ULL,
		0x1C074582AAD1312EULL,
		0x3DE9593153BE5704ULL,
		0x7FC4B6E96B56CF7CULL,
		0x65D16AF47DC3AF50ULL,
		0xBA5A59D075236983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A27DF7A0B4D69AULL,
		0x142BE96D8E5B0146ULL,
		0xE23F07FFA7B393B1ULL,
		0xBD97FD8F0BA3ED57ULL,
		0x7B8AA66DB1B5A8C4ULL,
		0xE80BCD3D8C7EE7D1ULL,
		0x1E141C35465B8EEEULL,
		0x167F534FFC45198EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C697FDFE98B4F3BULL,
		0x7AD7F03D57CCF687ULL,
		0x9F30CD08EFA436A1ULL,
		0xA190B80DA172DC79ULL,
		0x4663FF5CE20BFFC0ULL,
		0x97CF7BD4E72828ADULL,
		0x7BC576C13B9821BEULL,
		0xAC250A9F8966700DULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9640D753D7AA38B3ULL,
		0x995942C0DF7C72AAULL,
		0xAF14796E572D3C94ULL,
		0xE76DACA449F21EAFULL,
		0xD9F30DF9EC12EA84ULL,
		0xFFC51BD8353661D3ULL,
		0xF1F3970882504C4FULL,
		0x9D715748BB27F3A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x671AF60992AEEC08ULL,
		0x609A16C48C49278BULL,
		0x23C4EE64CD7D91B2ULL,
		0x756ACCE7B2AFC3DDULL,
		0x999DEA8F25E17C88ULL,
		0x314743A4B35FFB36ULL,
		0xBF0980E6B639B1ADULL,
		0xFA075B4F60D23CCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF15A215A4504D4BBULL,
		0xF9C3540453355521ULL,
		0x8CD0970A9A50AD26ULL,
		0x92076043FB5DDD72ULL,
		0x406EE776C9F3960CULL,
		0xCE82587C86699AE5ULL,
		0x4EFA17EE3469FDE2ULL,
		0x67760C07DBF5CF63ULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x82A6705C77460943ULL,
		0x96EC1F850361899BULL,
		0xAA3A9DD61272AE94ULL,
		0x20E16622A9D8EB18ULL,
		0xFE87264117C66AD8ULL,
		0x14C46FF015FC49A0ULL,
		0x2C397456F5C76AAFULL,
		0x232DE523589E953BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D0880580696A2DULL,
		0xD19E9FE4E51218A5ULL,
		0xBE56ABE72CC45B2BULL,
		0x3B14A34C6D7B36D7ULL,
		0x37C69206177C5608ULL,
		0xEB5963DC00D1B8E7ULL,
		0x099947DEF0D241B8ULL,
		0xF40FAC068DC1034FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA76F859F72F636EULL,
		0x47728061E673913EULL,
		0x146C36313EB6F5BFULL,
		0x1BF5C56EC4A3DDCFULL,
		0xC941B44700BA3CD0ULL,
		0xFF9D0C2C152DF147ULL,
		0x25A0338805152B17ULL,
		0xD7224925D55F9674ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF74E3A7679B64041ULL,
		0xCA0AC158152A38EEULL,
		0x881590D5B739348CULL,
		0x294A4E5062494436ULL,
		0xD964E05C170CF904ULL,
		0xED5D98052FACB994ULL,
		0x933C5B991CADF532ULL,
		0x267F0F87C112EBDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733218CB7E0FA312ULL,
		0xF42CECB1610C1A58ULL,
		0x6D34FFAC15AFF3E4ULL,
		0x1BA5AA3FCD36D8FFULL,
		0x185EAC51C4E13123ULL,
		0xBE2F43752AF57D1CULL,
		0x29E2E63FD2A23C4EULL,
		0xBEF1CF4D447F86BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x847C22BD07B9E353ULL,
		0x3E262DE9742622B6ULL,
		0xE5216F79A296C768ULL,
		0x32EFE46FAF7F9CC9ULL,
		0xC13A4C0DD3EDC827ULL,
		0x5372DB700559C488ULL,
		0xBADEBDA6CE0FC97CULL,
		0x988EC0CA856D6D67ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x643F4D878DB87674ULL,
		0x1548D7A463A21713ULL,
		0x16447EF691F6AAACULL,
		0x14FA8150B05E7874ULL,
		0x924FED0749AF7683ULL,
		0xAA8DC351CAB86CC0ULL,
		0x61574B0110F1B1E5ULL,
		0xBAE1D9FF1258B81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B4A2BA2C7CB541ULL,
		0x607E3B4B817A55A3ULL,
		0xF61002057A990ED1ULL,
		0x35477DA47FA95171ULL,
		0xF2AB869E3433285AULL,
		0x6EFB617AD10F594EULL,
		0x8AB925249711943FULL,
		0xEC6CEC041EEC480AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8BEF3DA1C4C335ULL,
		0x7536ECEFE2D842B0ULL,
		0xE0547CF3EB6FA47DULL,
		0x21BDFCF4CFF72905ULL,
		0x60E46B997D9C5ED9ULL,
		0xC476A22B1BB7358EULL,
		0xEBEE6E2587E025DAULL,
		0x568D35FB0CB4F010ULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2D89637CC7AF6F3EULL,
		0xA8162C788E1206C9ULL,
		0xB1F83647587E1DCCULL,
		0x058EDE72E847AB9AULL,
		0x1E272167F68AC32FULL,
		0x6AABE4BA6513BF9EULL,
		0x95572C3EE6056CCDULL,
		0xC36810162D00909BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A196D4E75E1F9B6ULL,
		0x05D367B77A612C05ULL,
		0xF1C6D07E930F886DULL,
		0xA677B2FE4B5A5212ULL,
		0xFB1336E2D4DDFEB3ULL,
		0xD5379743E9A97754ULL,
		0xBFCF1F4D92FC55C8ULL,
		0x80BAC1CEE1619DB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07900E32B24E9688ULL,
		0xADC54BCFF4732ACCULL,
		0x403EE639CB7195A1ULL,
		0xA3F96C8CA31DF988ULL,
		0xE534178522573D9CULL,
		0xBF9C73F98CBAC8CAULL,
		0x2A98337374F93905ULL,
		0x43D2D1D8CC610D2CULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x79B21EE48653F4B2ULL,
		0x98068DACCDEDE545ULL,
		0xC82D6366205EB71DULL,
		0x134B983CB4F32A54ULL,
		0xE45DC18273CC6679ULL,
		0x63A128B19F5F0A85ULL,
		0x2FEAC5AA9E804F21ULL,
		0xDE4764EF9CA637F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF857E48B8AC3D402ULL,
		0x7056514DCF5C51F5ULL,
		0x42BD0B3D5593AC35ULL,
		0x5F2CEF3108190C0DULL,
		0x2FE2ED88193F7A48ULL,
		0x936A76403122842CULL,
		0x262FAD39F9664FC6ULL,
		0x31241AAF1A0C95C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81E5FA6F0C9020B0ULL,
		0xE850DCE102B1B4B0ULL,
		0x8A90685B75CD1B28ULL,
		0x4C67770DBCEA2659ULL,
		0xCBBF2C0A6AF31C31ULL,
		0xF0CB5EF1AE7D8EA9ULL,
		0x09C5689367E600E7ULL,
		0xEF637E4086AAA230ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x19362A4F656E1C21ULL,
		0xF2B5EEF41146EA05ULL,
		0x8BCCA8F4723F3D28ULL,
		0x0DF4C5922BA5DF17ULL,
		0xC0C190C981AE9978ULL,
		0x37D8555FB4E60096ULL,
		0x13F3DB2CBBD84457ULL,
		0xB7A8AC5153B3F01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C8367B8F07B1B0ULL,
		0x8501676ED8915876ULL,
		0xE611E85514D5A769ULL,
		0xC83278AEFC6CD82AULL,
		0xFBA0C2E93D9DD73AULL,
		0xE23D8CEBDACD3F0BULL,
		0x71583D1A7E5D4AC2ULL,
		0x50ADEEFA7766E9DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DFE1C34EA69AD91ULL,
		0x77B4899AC9D7B273ULL,
		0x6DDD40A166EA9A41ULL,
		0xC5C6BD3CD7C9073DULL,
		0x3B615220BC334E42ULL,
		0xD5E5D9B46E2B3F9DULL,
		0x62ABE636C5850E95ULL,
		0xE70542AB24D519C0ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5D89CBC8073D0F8EULL,
		0xA56AA917036BA9B6ULL,
		0xA602D80C480A4EE4ULL,
		0x33143B84589FCEDEULL,
		0x88E840CC213B4EEAULL,
		0x7F780764C3F1990AULL,
		0xDF9BF3C694619A8EULL,
		0x4EFEFA9A9E5C061DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83634E73E1B2EA41ULL,
		0x06A0DD482BEB4B5AULL,
		0x09ED6CA95BBCDB88ULL,
		0x9A9D905D5077D372ULL,
		0xB96D5250112A14C0ULL,
		0xF46F1F917FAD08ADULL,
		0x05E9BCA98D49A363ULL,
		0x6A347CDB487F907CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEEA85BBE68FE5CFULL,
		0xA3CA745F2880E2ECULL,
		0xAFEFB4A513B6956CULL,
		0xA989ABD908E81DACULL,
		0x3185129C30115A2AULL,
		0x8B1718F5BC5C91A7ULL,
		0xDA724F6F192839EDULL,
		0x24CA8641D6239661ULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x328084144C2D83B3ULL,
		0x42AEAA75D60F0382ULL,
		0x0E1F911BDC5237FDULL,
		0xFF0260ECCB79CBC2ULL,
		0xBCFEE33CB55BAB82ULL,
		0x89323146DD6BE0FDULL,
		0xBF980D598B512851ULL,
		0x7944F3698F4882A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2797A129278960ULL,
		0x0C34A4CD96202B09ULL,
		0xC388227B3F54E5BFULL,
		0x4FB9364B311B9755ULL,
		0xEE5DDD6291E60C9CULL,
		0x08D06FEA7D9076B3ULL,
		0xF611371039508997ULL,
		0x37D258C5A7E3EF28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EA713B5650A0AD3ULL,
		0x4E9A0EB8402F288BULL,
		0xCD97B360E306D242ULL,
		0xB0BB56A7FA625C97ULL,
		0x52A33E5E24BDA71EULL,
		0x81E25EACA0FB964EULL,
		0x49893A49B201A1C6ULL,
		0x4E96ABAC28AB6D8EULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3ACDFA0F3CB3D8B5ULL,
		0x09238F61304717E9ULL,
		0x29F9FF2EB5D35BD7ULL,
		0x03FADDCB70BA9290ULL,
		0xAB34751676088F30ULL,
		0x19948839315075D9ULL,
		0xE90283EEBA3CADD6ULL,
		0xF0581E115362F0B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8C23293B8F7D674ULL,
		0x3B0CEF7EC954C529ULL,
		0xCBD633A11DFB308DULL,
		0xFA9CF3D3F1DB45B9ULL,
		0x3B9F336D6A6F67C6ULL,
		0xD7220B78B953E0CEULL,
		0x00B7E332B1BFE7FEULL,
		0x5D4F21C445450904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x820FC89C84440EC1ULL,
		0x322F601FF913D2C0ULL,
		0xE22FCC8FA8286B5AULL,
		0xF9662E188161D729ULL,
		0x90AB467B1C67E8F6ULL,
		0xCEB6834188039517ULL,
		0xE9B560DC0B834A28ULL,
		0xAD173FD51627F9B5ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF2885BACA0D1F71FULL,
		0x610C9B1041813304ULL,
		0xEE448503526FBBE7ULL,
		0x530EBD84D0A61A73ULL,
		0x85BA33B479CADE53ULL,
		0x2B7DD669F1611653ULL,
		0x9B44717D194A4294ULL,
		0x1D334C6C2E829D93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23911391B76627C6ULL,
		0xDD42412CD90E9539ULL,
		0x426734FF76DBCC18ULL,
		0x2FD9210B128983ADULL,
		0x2E44F31B5400B7DFULL,
		0xD169F25E783C715BULL,
		0x0BCFD7D72AD75240ULL,
		0x581FC9BE89C40A00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD119483D17B7D0D9ULL,
		0xBC4EDA3C988FA63DULL,
		0xAC23B1FC24B477FFULL,
		0x7CD79C8FC22F99DEULL,
		0xABFEC0AF2DCA698CULL,
		0xFA142437895D6708ULL,
		0x908BA6AA339D10D4ULL,
		0x452C85D2A7469793ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFECAD142017D3190ULL,
		0xFFD67D150987F020ULL,
		0x5F206E54144F936BULL,
		0x0EEBBD9C07600367ULL,
		0x0131E92E4C2FF932ULL,
		0xDCCE73E085C7E8DFULL,
		0xBD70BF28ED3FF168ULL,
		0x4BD0B79CC95DBB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DBC01F8F3E8CAAULL,
		0xFBB685003A834D54ULL,
		0x775BD3608A5876D2ULL,
		0xA3FC1F79E0A6334BULL,
		0x18C1ABD6D6625EBAULL,
		0x0218ABDFB0EA6F10ULL,
		0xBB17F11FC3D14F9DULL,
		0x6BA0C170D4C15D3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC11115D8E43BD3AULL,
		0x0460F8153304BD74ULL,
		0x287BBD349E17E5B9ULL,
		0xAD17A2E5E7C6302CULL,
		0x19F042F89A4DA788ULL,
		0xDED6D83F352D87CFULL,
		0x06674E372EEEBEF5ULL,
		0x207076EC1D9CE60AULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFFEE95FBDFE32DB7ULL,
		0x3A5E66C33B8E86CCULL,
		0xADA3B3F4D8656E16ULL,
		0x0A05C43DF5EB0E7BULL,
		0xFADA1BA3A5CA8B71ULL,
		0x47EF7E9080F3B17FULL,
		0x30F3D9BB59A7FFF4ULL,
		0x932586CDB68001C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1F1DB4F50D353D1ULL,
		0x1A545049D1A542AAULL,
		0xF9F99C521D937D4DULL,
		0xF301DC90C435D348ULL,
		0xCA01C509A19AB5F8ULL,
		0x0B5FCCA35F78BBF7ULL,
		0xBB969A0A8D5D30BDULL,
		0x0A371C3189A2B37CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E1F4EB48F307E66ULL,
		0x200A368AEA2BC466ULL,
		0x545A2FA6C5F6135BULL,
		0xF90418AD31DEDD33ULL,
		0x30DBDEAA04503E89ULL,
		0x4CB0B233DF8B0A88ULL,
		0x8B6543B1D4FACF49ULL,
		0x99129AFC3F22B2BBULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAB528E20BE32FEDEULL,
		0x2D1DC6024B246100ULL,
		0x7C27ED1E912FA8C5ULL,
		0x4713B5C8CBD3635EULL,
		0x17C8530C38F64DA7ULL,
		0x5394E3CFC5CFE26DULL,
		0x356F5B929973FE88ULL,
		0x64EFBCCE5B982891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23DBA66E150E093CULL,
		0x58B3082D6A1F3441ULL,
		0x5649F826E2A8DB8DULL,
		0x065E441AC2748537ULL,
		0x238DBD893221751FULL,
		0x2D2BBAC6C9372B9DULL,
		0x4EBB82AD992E680AULL,
		0xCD2BD5BF4BE331E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8889284EAB3CF7E2ULL,
		0x75AECE2F213B5541ULL,
		0x2A6E153873877348ULL,
		0x414DF1D209A7E669ULL,
		0x3445EE850AD738B8ULL,
		0x7EBF59090CF8C9F0ULL,
		0x7BD4D93F005D9682ULL,
		0xA9C46971107B1971ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7889B9B4CB92D5A1ULL,
		0xAD82C1B7E4387E24ULL,
		0xF3CDC73619B63BB1ULL,
		0xF219744752F01078ULL,
		0x70554E3BC12A43C2ULL,
		0x762979C07DC1CBE0ULL,
		0x87C3E1F9F04E31CFULL,
		0x5EFBF8D9DDF35342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38A39A2CB9F5913ULL,
		0x534B4CA25EABF388ULL,
		0xCB1D1E73DAEE9E63ULL,
		0x05FF56C4963F8437ULL,
		0x1A2D3512449DDB88ULL,
		0x3165216752BDE5F3ULL,
		0x05C041B5B1EC1BAAULL,
		0x1D93DCAFA5C36EE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB038016000D8CB2ULL,
		0xFEC98D15BA938DACULL,
		0x38D0D945C358A5D2ULL,
		0xF7E62283C4CF944FULL,
		0x6A787B2985B7984AULL,
		0x474C58A72F7C2E13ULL,
		0x8203A04C41A22A65ULL,
		0x4368247678303DA7ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6B87253A553283FULL,
		0x0F5BAFFC9937C5F4ULL,
		0x25C0C39562805B99ULL,
		0xDA7072CFBDA1EF1BULL,
		0x4AD59EF86872B7A1ULL,
		0x5EB0D17F71E05EB6ULL,
		0x5BA586F41E78442BULL,
		0xCAFDFC3E4F3F904DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A4FCADE330A12B0ULL,
		0x3B4C40C199EC84C3ULL,
		0x4C051E82E06C685EULL,
		0xF6A5DF88971F6555ULL,
		0xB118D8D34F8EA1DFULL,
		0xB6DF32FBDB82C504ULL,
		0xE4EA44835D977A0BULL,
		0x988B14C831634599ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CF7B88D96593A8FULL,
		0x3417EF3D00DB4137ULL,
		0x69C5DD1782EC33C7ULL,
		0x2CD5AD472ABE8A4EULL,
		0xFBCD462B27FC167EULL,
		0xE86FE384AA629BB2ULL,
		0xBF4FC27743EF3E20ULL,
		0x5276E8F67E5CD5D4ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2AB80780B135533BULL,
		0x5AD8EFFDDC05F742ULL,
		0x370F98DAB97E932BULL,
		0x4B2EDC5D6731774EULL,
		0xE37C6943200D162DULL,
		0xEECB87711904FEA4ULL,
		0xFE943D007938B5F7ULL,
		0xCF748CFB8A7608ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA68B4DF136EF28B7ULL,
		0x6BCA18F2B83CD7FBULL,
		0x2B4EADB3F288AE03ULL,
		0x02CB4414A375B75BULL,
		0x88B4E5AB2063201EULL,
		0x44E6DD02108E99CDULL,
		0x69543FCE8D2BB747ULL,
		0x2213E8CEA64AFBC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C334A7187DA7B8CULL,
		0x3112F70F643920B9ULL,
		0x1C4135694BF63D28ULL,
		0x49E59849C444C015ULL,
		0x6BC88CE8006E3633ULL,
		0xAA2D5A73098A6769ULL,
		0x97C002CEF41302B0ULL,
		0xED6764352C3CF32BULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD30CF6285E2403FAULL,
		0xE9B2E4463E234775ULL,
		0x24C524BEA27F2EC2ULL,
		0xBFE5FA9194D748BEULL,
		0x9FED6D17603AB2FAULL,
		0x7826671FD6099374ULL,
		0xF4FF9CC07BDA6322ULL,
		0x34C59273D6CC1677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33DEE2AF6AE86E64ULL,
		0xACD6D9B53429EF21ULL,
		0x90CE31ADC37D445AULL,
		0x7380365ECD8B114FULL,
		0x466675A9A655603AULL,
		0xA69BBCA62AEC9A65ULL,
		0x9474C89898ED45EBULL,
		0x116DE8F7E974F421ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0D2148734CC6D9EULL,
		0x45643DF30A0AA854ULL,
		0xB40B151361026A98ULL,
		0xCC65CCCF595C59F1ULL,
		0xD98B18BEC66FD2C0ULL,
		0xDEBDDBB9FCE50911ULL,
		0x608B5458E33726C9ULL,
		0x25A87A843FB8E256ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEC0922B1E32126F7ULL,
		0x5D1428DAFF55A930ULL,
		0xC05D7487CFBC95D6ULL,
		0x7B786B0B3965575FULL,
		0x02355A9B522D64CAULL,
		0xE1600E3F32F64E82ULL,
		0x280B3233EB76BB8BULL,
		0xF4734B4CB5A37876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C80DADD56C6C621ULL,
		0xBC1FEBE1CA505A02ULL,
		0x350272B0774E9BE9ULL,
		0xCF771EAC7445077DULL,
		0xDB02CA7FE0EF6D68ULL,
		0x8ABC4CD423382FC4ULL,
		0x8983CBEF10017026ULL,
		0x274BD1698573356FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD089F86CB5E7E0D6ULL,
		0xE10BC33B3505F332ULL,
		0xF55F0637B8F20E3FULL,
		0xB40F75A74D205022ULL,
		0xD93790E4B2C209A2ULL,
		0x6BDC42EB11CE6146ULL,
		0xA188F9DCFB77CBADULL,
		0xD3389A2530D04D19ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD758F8B5E83BD85BULL,
		0x488DE002B056387EULL,
		0xA81FCD7ED4E889CBULL,
		0x56BF87B456C27958ULL,
		0x29156AA3B63A3DDCULL,
		0x3A413F2F7D7A9AF4ULL,
		0x4E23C10D03E64434ULL,
		0x9AE4BDC8937CD4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32337F1113146DAAULL,
		0x1E12A10E83EC1534ULL,
		0xBAB24AC6020BCE24ULL,
		0x778DBA43D597D4C6ULL,
		0x5149E5D8BEAB5104ULL,
		0xF2CC8380D2FB6EBAULL,
		0xBE49154BC35F4FE4ULL,
		0x7E4FB5A1336DAAECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE56B87A4FB2FB5F1ULL,
		0x569F410C33BA2D4AULL,
		0x12AD87B8D6E347EFULL,
		0x21323DF78355AD9EULL,
		0x785C8F7B08916CD8ULL,
		0xC88DBCAFAF81F44EULL,
		0xF06AD446C0B90BD0ULL,
		0xE4AB0869A0117E30ULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB035EE5C54575294ULL,
		0xA61AE5AB278828AFULL,
		0x9A1B2A3D9F3A2079ULL,
		0x31FB46089CAA1AB8ULL,
		0x937B138DB9E3021BULL,
		0x2090AD6FE3076677ULL,
		0xCAD43B5D1FF81ADBULL,
		0x2324FED4F0E9DD3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19C5592EBF814C13ULL,
		0x4095495E76DEA8DDULL,
		0x6D15D9FD9162856CULL,
		0xBC5E46ADC6959C29ULL,
		0x95F5A37855B80C2AULL,
		0xB42F8AF3180E66AEULL,
		0xC1D52D2B391885C9ULL,
		0xA0CA3BE11DBF3817ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9F0B772EBD61E87ULL,
		0xE68FACF551568072ULL,
		0xF70EF3C00E58A515ULL,
		0x8DA500A55A3F8691ULL,
		0x068EB0F5EC5B0E31ULL,
		0x94BF279CFB0900D9ULL,
		0x0B01167626E09F12ULL,
		0x83EEC535ED56E529ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8FC24858C2EFCEE0ULL,
		0x2333164DE5B11FD1ULL,
		0xBC27BEA704D12D52ULL,
		0x97EAB144379524FFULL,
		0x17DEC99A82E1C946ULL,
		0xFD7FC65867E7BD3DULL,
		0xA67C40D0292243F3ULL,
		0xA791D767D3082C03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DD19DB635A4704ULL,
		0x87D64369E6A50EEAULL,
		0x0233B6B5380B3B63ULL,
		0xAFA439DBBBA98152ULL,
		0x7F0B0FCCE48E5FD5ULL,
		0xEE70F936F8A239F3ULL,
		0xD2B2CC3C5F7B9B25ULL,
		0xEEFA032E08417D6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA71F5183A1B589E4ULL,
		0xA4E555240314113BULL,
		0xBE1408123CDA1631ULL,
		0x384E889F8C3CA5ADULL,
		0x68D5C656666F9693ULL,
		0x130F3F6E9F4584CEULL,
		0x74CE8CEC7659D8D6ULL,
		0x496BD449DB495168ULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2F8EBCF2C61787CAULL,
		0x275DF23BF95E3488ULL,
		0x576AEF3A473A2403ULL,
		0x57ACF21FD4DE7AF6ULL,
		0x6F7CFD753F0C8185ULL,
		0xDAD8A6F88288EF0EULL,
		0xF046DC0D615806B1ULL,
		0xABF007446B43E572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x389703D3D78DFAF3ULL,
		0x757F50051C1C9D7DULL,
		0x8E0393C9EBB16F9BULL,
		0x7A8C11DB5247D47DULL,
		0xD68F96CF0F3A5ACEULL,
		0x5C65FEC041A57A31ULL,
		0xE42260E356B1C8DAULL,
		0x58C631F00DCE965CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1719BF21119A7D39ULL,
		0x5222A23EE542A9F5ULL,
		0xD9697CF3AC8B4B98ULL,
		0x2D20E3C48699AE8BULL,
		0xB9F36BBA3036DB4BULL,
		0x86BD5838C32D953FULL,
		0x1464BCEE37E9CE6BULL,
		0xF33636B4668D732EULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7AF4E58BBE60CEE3ULL,
		0x7AB3016863A6BBE0ULL,
		0x5938A0C9D40DB2E4ULL,
		0x45A26B37AD59A26EULL,
		0xF43D844B7D628F12ULL,
		0xD8C1AC2317679264ULL,
		0x60448B6C2BC76D61ULL,
		0xAAC7EE6BBA989C2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12719842CA9054C7ULL,
		0xB23658A8ED756F4CULL,
		0xD04890AA50FE8479ULL,
		0x7BC9271C1BAB0F22ULL,
		0x3CB7A20F8C33FBD2ULL,
		0xA970F9FC16BF6F48ULL,
		0xC0DF61BDC752DF6EULL,
		0xA6927E4E6263F5C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68857DC974F09A24ULL,
		0xC88559C08ED3D4ACULL,
		0x8970306384F3369DULL,
		0x3E6B4C2BB6F2AD4CULL,
		0xC88A2644F15174C0ULL,
		0x71B155DF01D8FD2CULL,
		0xA09BEAD1EC95B20FULL,
		0x0C559025D8FB69EFULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x28C89120A5EF1A4DULL,
		0x0E70E838CA9DA405ULL,
		0x852778D6D89B7643ULL,
		0x848576F73CE4B12BULL,
		0x6CCB48EF24107C51ULL,
		0x4C09FC8DDD97328AULL,
		0x3B6FF65348FFED0CULL,
		0xE295332B2264AC36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED003A6A7017D32ULL,
		0x432D7B10BDD279E9ULL,
		0xEB4FD6051356EE32ULL,
		0x9D669B501537D573ULL,
		0x76E2FDBC7CF7F3A9ULL,
		0xDAB09E4A7DDB4CEDULL,
		0x7C1A92F698253111ULL,
		0x0748B5DBD9FA8208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6618928602EE677FULL,
		0x4D5D9328774FDDECULL,
		0x6E68AED3CBCD9871ULL,
		0x19E3EDA729D36458ULL,
		0x1A29B55358E78FF8ULL,
		0x96B962C7A04C7E67ULL,
		0x477564A5D0DADC1DULL,
		0xE5DD86F0FB9E2E3EULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFD151DE10307F0C2ULL,
		0x6856ACC242D08EB4ULL,
		0x390B3F627B29EE30ULL,
		0x5FE02E02F3C44393ULL,
		0x90C0F54DA98FD482ULL,
		0xA8F4F23A25217150ULL,
		0xE816951030697D9CULL,
		0x5D9A1D441E1CD65AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FBF38DBD2CDCF4AULL,
		0xD2303E0FEF924591ULL,
		0xCB581876918A4015ULL,
		0x9D67992A1A236D90ULL,
		0xC5D5740EEAF15C39ULL,
		0x2039604D02A909CFULL,
		0x34B2319691E29666ULL,
		0xA2A97CBD62247AEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2AA253AD1CA3F88ULL,
		0xBA6692CDAD42CB25ULL,
		0xF2532714EAA3AE25ULL,
		0xC287B728E9E72E03ULL,
		0x55158143437E88BBULL,
		0x88CD92772788789FULL,
		0xDCA4A486A18BEBFAULL,
		0xFF3361F97C38ACB5ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC4F253EFB76A76F8ULL,
		0x8EEBD088329A7E8AULL,
		0x214C03E0484C63D8ULL,
		0x510171DFEF7EC42FULL,
		0x620549FCCAED8B82ULL,
		0x2619C63EA4807809ULL,
		0x4928CC235C27E300ULL,
		0x4E62E035EA96377BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6662642DE2AD2CFBULL,
		0xB8F250A093E0CEEFULL,
		0xD8AA26907024A31BULL,
		0x2CA89A97DA172EA6ULL,
		0x2BAF977A68AB72BBULL,
		0x675B087A36D85F82ULL,
		0x73A536A8AA343117ULL,
		0x1CB8ED02C3874749ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA29037C255C75A03ULL,
		0x36198028A17AB065ULL,
		0xF9E625703868C0C3ULL,
		0x7DA9EB483569EA89ULL,
		0x49AADE86A246F939ULL,
		0x4142CE449258278BULL,
		0x3A8DFA8BF613D217ULL,
		0x52DA0D3729117032ULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12386A6921028D0CULL,
		0xC5EA69883415F147ULL,
		0xA55A926C9E32B37DULL,
		0xBCC0D50B0597FFFCULL,
		0x0E35E43CB5786A69ULL,
		0xED7BFB65C134CBFEULL,
		0x1EC0A0F736C9B0C8ULL,
		0x976509E9C2DFB357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E9A53786834112ULL,
		0xA49787AB95A4BB9BULL,
		0x395D02B332C86AEAULL,
		0x0752568AB118C6E2ULL,
		0xE066E2CF8F1F72F7ULL,
		0x153B98081B07267EULL,
		0xD3188C98D15CAECDULL,
		0x71A4EB7B65B38408ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAD1CF5EA781CC1EULL,
		0x617DEE23A1B14ADCULL,
		0x9C0790DFACFAD997ULL,
		0xBB928381B48F391EULL,
		0xEE5306F33A67189EULL,
		0xF840636DDA33ED80ULL,
		0xCDD82C6FE7951E05ULL,
		0xE6C1E292A76C375FULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF91AD3772854FB1FULL,
		0x1E379463ED57DE2FULL,
		0x5AC29944392A68EEULL,
		0x4E8132F4FCCEFA20ULL,
		0x54B58855A283827DULL,
		0x8C960CB35B721444ULL,
		0xAA9A590A7FE173DFULL,
		0x52E7F28E041ABED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE020BF4231FB6D6ULL,
		0x9BDC1FFD85B2713BULL,
		0x4C274E956482712DULL,
		0x29CC8F821D1BB349ULL,
		0x5D32C5728048384FULL,
		0xEB3BBC9D52D681E0ULL,
		0x56BB58017751388DULL,
		0x3E3D9A59480DE06AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2718D8830B4B4DC9ULL,
		0x85EB8B9E68E5AF14ULL,
		0x16E5D7D15DA819C3ULL,
		0x674DBD76E1D54969ULL,
		0x09874D2722CBBA32ULL,
		0x67ADB02E09A495A4ULL,
		0xFC21010B08B04B52ULL,
		0x6CDA68D74C175EB3ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF441B19C8F39DDCFULL,
		0x5291B09BDD613256ULL,
		0xB540CAA84F77242FULL,
		0xEB1D11AD1EBB12B1ULL,
		0x2426504CF35F3872ULL,
		0x3DDAF5F1A78BFD4EULL,
		0x82A28327AF558C79ULL,
		0x2BC5460A8105FBCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9820D70325B9E8DULL,
		0x891567EB4C95DEBDULL,
		0xCD1E7FD9F97C9D29ULL,
		0x17FC18D8BE0347B9ULL,
		0xCC3A936EE9BD6282ULL,
		0xD97E7CBC41EA0990ULL,
		0x2E87D3692B04EB7BULL,
		0x244A21E25BF9C7FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DC3BCECBD624342ULL,
		0xDB84D77091F4ECEBULL,
		0x785EB571B60BB906ULL,
		0xFCE10975A0B85508ULL,
		0xE81CC3221AE25AF0ULL,
		0xE4A4894DE661F4DEULL,
		0xAC25504E84516702ULL,
		0x0F8F67E8DAFC3C33ULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x87A5B9FBDEF59EACULL,
		0x32CC6C9F0B65D66FULL,
		0x3704D9C6B299896AULL,
		0x6D40D8186F788C24ULL,
		0x5FCF29282BC735FAULL,
		0xF6BE1CDFD5B8787AULL,
		0xF90C54CF2CF4C4A2ULL,
		0x7587669F6BC7F637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD76C9B7E763810C2ULL,
		0x668C7DB58A8CFF09ULL,
		0x113F898851C6D161ULL,
		0xAD4F6249AEA0891EULL,
		0x941474D31D35DA8DULL,
		0xEE4F2F9EF6C5E7BFULL,
		0x8A7AD54A46B53CFCULL,
		0xA476E955412F1C16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50C92285A8CD8E6EULL,
		0x5440112A81E92966ULL,
		0x263B504EE35F580BULL,
		0xC00FBA51C1D8053AULL,
		0xCBDB5DFB36F2EF77ULL,
		0x18F13341237D9FC5ULL,
		0x737681856A41F85EULL,
		0xD1F18FCA2AE8EA21ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6D10FFAA84BD47F8ULL,
		0x924DF9CED45DB302ULL,
		0xEA9B247CBE3DAB0FULL,
		0xD8780B6AF2FFAD58ULL,
		0x7BDE1CB954833685ULL,
		0xDB6D513365B76F57ULL,
		0x0522452B9C8EEF93ULL,
		0x434A864FD9DFD034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE58E6EE1E32AA04ULL,
		0xB2EF20C73B2D246FULL,
		0x3FBFA0B24896EB79ULL,
		0xDF43ACF63CBD7FE3ULL,
		0xAFBE43B0EAB7A1B1ULL,
		0xC52CB918E1C49E44ULL,
		0xA5C8551A66D587FBULL,
		0xF46205FB9E035F64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD34819449A8FEDFCULL,
		0x20A2D909EF70976DULL,
		0xD52484CEF6AB4076ULL,
		0x073BA79CCE42D2BBULL,
		0xD4605F09BE349734ULL,
		0x1E41E82B8473F113ULL,
		0xA0EA1031FA5B6868ULL,
		0xB72883B447DC8F50ULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x32501343471BD226ULL,
		0xD144510692478EF6ULL,
		0x0B7C89F4E65F166CULL,
		0x9D3BFCFB87E27307ULL,
		0x7ED5CBCA731B9662ULL,
		0x85592EC254F8D6FEULL,
		0x015575C799C2B4BAULL,
		0x1784484EFA5844CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B69E14F922FE27ULL,
		0x49890E5C353F908FULL,
		0xBF9B91C6E2DE0601ULL,
		0x3F152EFFB810F781ULL,
		0xE0AE2A7559D12A2BULL,
		0x45507BF288D5AF53ULL,
		0xAE3200123D4D2445ULL,
		0x54B29CCD4B542065ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABE68D57BE392C01ULL,
		0x98CD5F5AA7781E79ULL,
		0xB4E718320481106DULL,
		0xA22ED2043FF28486ULL,
		0x9E7BE1BF2ACABC49ULL,
		0xC0095530DC2D79ADULL,
		0xAF6775D5A48F90FFULL,
		0x4336D483B10C64AAULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x05D0C5F1575E0F68ULL,
		0x04C09708C96AC90DULL,
		0x3BF04E85AA4606D1ULL,
		0xC6B46C2405EA4487ULL,
		0x33530BCC56E29C3EULL,
		0xDCF89967C09A3936ULL,
		0x046A50F6DB3F1ABAULL,
		0xB3D80F54C6111006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D26CBFB3A69182ULL,
		0x1FC9784CA1E36E37ULL,
		0x72A9C5DF6F9FCAF0ULL,
		0x078E327CF05323E1ULL,
		0x70FBCA55DE4E52F7ULL,
		0x47ACDFDD40EC2323ULL,
		0x2F63333A2DE656ACULL,
		0x6954C93597526F42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C02A94EE4F89EEAULL,
		0x1B09EF446889A73AULL,
		0x49598B5AC5D9CC21ULL,
		0xC13A5E58F5B96766ULL,
		0x43A8C19988ACCEC9ULL,
		0x9B5446BA80761A15ULL,
		0x2B0963CCF6D94C16ULL,
		0xDA8CC66151437F44ULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x742290310B7DAB77ULL,
		0xB7741DB47C834534ULL,
		0xBB09BB15E989EFDFULL,
		0x83B08DC3097E68F9ULL,
		0x5EF4448A1668632CULL,
		0xB035F1DBDD351669ULL,
		0xDFF7FF8D2E7B0844ULL,
		0xDBB073E3F7F795AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D826CA5334147DULL,
		0xBC50D7330C22F1ADULL,
		0x69878D23651AEA79ULL,
		0xEE76465BC3EB889DULL,
		0x1481FF633B93202FULL,
		0x0C89EBC1625E3860ULL,
		0xF5D769C2771EFF16ULL,
		0xFB886288665F63D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16FAB6FB5849BF0AULL,
		0x0B24CA8770A1B499ULL,
		0xD28E36368C9305A6ULL,
		0x6DC6CB98CA95E064ULL,
		0x4A75BBE92DFB4303ULL,
		0xBCBC1A1ABF6B2E09ULL,
		0x2A20964F5965F752ULL,
		0x2038116B91A8F67BULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2759E9EEC49E5A1FULL,
		0x9163CC30285CDE8CULL,
		0x1DA3B392D5E5CB00ULL,
		0xD648072800D29FC3ULL,
		0xCB11226C4C5BE3E8ULL,
		0xC10CA0E06C6DE4E9ULL,
		0xBE79D9A65A7EF97BULL,
		0xEBBB61BBEDB46047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E7880EA512C0B6ULL,
		0x8B0F9F6821763746ULL,
		0xBF40E846DDAE709AULL,
		0xC9580985FA844560ULL,
		0x2F1D0FB30FBC13BDULL,
		0x3845DA99DB6B7D8AULL,
		0xFDE4561D7151C678ULL,
		0xEC30189A34E29D78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEBE61E0618C9AA9ULL,
		0x1A6C5358092AE9CAULL,
		0xA2E35BD4084BBB9AULL,
		0x1F100EADFA56DAA3ULL,
		0xE40C2DDF43E7F055ULL,
		0xF9497A79B7069963ULL,
		0x439D8FBB2B2F3F03ULL,
		0x078B7921D956FD3FULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB414DE962BA514E6ULL,
		0x6475A60CE3C7796EULL,
		0x901F5A03AED179C1ULL,
		0x468DB3D247153E29ULL,
		0xED2719212ECC3B41ULL,
		0x8AEC18113617B97BULL,
		0x7A0396460477DB1CULL,
		0x7184587D7D2B0568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC348CF6237CD2E5ULL,
		0x7FF93B8BB171D27BULL,
		0x3B0C355ED683D5B7ULL,
		0x9EFEECB344403343ULL,
		0xF9C56DFA215C0DF6ULL,
		0x1D60C116EDA78A0CULL,
		0x4DBD6A672A17F293ULL,
		0x8915CC107D76CA9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5820526008D9C603ULL,
		0x1B8C9D8752B6AB15ULL,
		0xAB136F5D7852AC76ULL,
		0xD8735F6103550D6AULL,
		0x14E274DB0F9036B7ULL,
		0x978CD907DBB03377ULL,
		0x37BEFC212E60298FULL,
		0xF891946D005DCFF7ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA61AF41AF6D68651ULL,
		0x9CEDE061ADA15AD8ULL,
		0xDAA68F00293FFD12ULL,
		0x96C06D6B137B5C2DULL,
		0x305BE603273C3699ULL,
		0x169DFF44DEAD7E63ULL,
		0xEC350C2729E60320ULL,
		0x9B334B8C599C3D08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63F3F34100F17FE0ULL,
		0xE14D9F0ADCF5C385ULL,
		0x70652CB0626E3076ULL,
		0x53478CE85392CA11ULL,
		0x731EB2AEFEE5CFBCULL,
		0x6DFC06DDCDAE5882ULL,
		0x19C933734D8FF2EDULL,
		0x5C52378D2E7565F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5E9075BF627F9B1ULL,
		0x7DA07F6B7154995DULL,
		0xAAC3A3B04B51CD64ULL,
		0xC587E18340E9963CULL,
		0x434554ADD9D9F925ULL,
		0x7B61F999130326E1ULL,
		0xF5FC3F546469F1CDULL,
		0xC7617C0177E958F9ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC5F7F9A2BF27EFA3ULL,
		0xD361C8DB892FECB9ULL,
		0x737C0EFC103FA319ULL,
		0xE1866288FBF7DC11ULL,
		0xC82BF0E8735AA4DAULL,
		0x00DA9000CA680413ULL,
		0x75D2CD97ED5B5956ULL,
		0x46A9C8399816A170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD24E3FFB973A107ULL,
		0xB540C2E0C6B3A328ULL,
		0x7C79EE8766648A54ULL,
		0x1D47E2A465D32D8CULL,
		0x63D8426F16C3F657ULL,
		0x096A7F2953998F96ULL,
		0x6112E6B00E3683D0ULL,
		0x5814C53C88FF4EDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D31A5D06544EA4ULL,
		0x66210A3B4F9C4F91ULL,
		0x0F05E07B765B294DULL,
		0xFCC1802C9E24F19DULL,
		0xABF3B2876599528DULL,
		0x09B0EF2999F18B85ULL,
		0x14C02B27E36DDA86ULL,
		0x1EBD0D0510E9EFADULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC503D7CA556C95BDULL,
		0x03DD0DC4D82CA864ULL,
		0x575407A3B8D11B56ULL,
		0xF7E184D46D05108FULL,
		0x6B04E43C1E9814C8ULL,
		0x44E59D8D22BC350AULL,
		0xD63B0895E3DF65A4ULL,
		0x7CCEBB30E098EE2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x701AD2F0FCFC4A8CULL,
		0x805AAE62142207F1ULL,
		0x449CF6AEFCCAD89FULL,
		0x136A41D41AABA22FULL,
		0x8B7C798140F24175ULL,
		0x1FA9892E70B2CA3AULL,
		0xE40FD0AE90699FF9ULL,
		0x82F9E6917278FD3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB519053AA990DF31ULL,
		0x8387A3A6CC0EAF95ULL,
		0x13C8F10D441BC3C9ULL,
		0xE48BC50077AEB2A0ULL,
		0xE0789DBD5E6A55BDULL,
		0x5B4C14A3520EFF30ULL,
		0x3234D83B73B6FA5DULL,
		0xFE375DA192E01314ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3C4CEADF350029F8ULL,
		0xD9DDE41B4BBE4B73ULL,
		0x533B585F8DC1FFE0ULL,
		0xD70E91681F9E1CCBULL,
		0x415C6CBC6433BB37ULL,
		0x02B2586454A83216ULL,
		0x555C0AB22EF6D78AULL,
		0x8339121F9CE60100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADEC94E7C3B6E99CULL,
		0xE6850B79CB7C4B34ULL,
		0xAFF068F7BD873DB4ULL,
		0xE03FB52E11E91C1BULL,
		0xC631CD1BCA7261D6ULL,
		0xD4B6ED1DAB455144ULL,
		0x0EDDF9C6BE1969C3ULL,
		0x5D32C4B9E1A9DC94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91A07E38F6B6C064ULL,
		0x3F58EF6280C20047ULL,
		0xFCCB30A83046C254ULL,
		0x373124460E7700D0ULL,
		0x876DA1A7AE41DAE1ULL,
		0xD604B579FFED6352ULL,
		0x5B81F37490EFBE49ULL,
		0xDE0BD6A67D4FDD94ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x79CF6ACD953CED5BULL,
		0xCB7FACCEB012EB2AULL,
		0x5B41F7184018BF2AULL,
		0xE6BC37A023EA3D0AULL,
		0x0AC33F3B454D0D03ULL,
		0xF31B80CD67C0FD0AULL,
		0xC1CC07633A2B05F5ULL,
		0xB516113172612C4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BF9857DD1B15B7ULL,
		0x45085A54058A15D2ULL,
		0x5CFF923AE0709659ULL,
		0x4E68634F8E1C0013ULL,
		0x62A4AE180679CD09ULL,
		0x0054386D60E4E911ULL,
		0x10AA66C598887C26ULL,
		0xD279A08ECBD87580ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB70F29A4827F8ECULL,
		0x8E77F69AB598FEF8ULL,
		0x07BE6522A0682973ULL,
		0xA8D454EFADF63D19ULL,
		0x686791234334C00AULL,
		0xF34FB8A00724141BULL,
		0xD16661A6A2A379D3ULL,
		0x676FB1BFB9B959CFULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDBA0C85A1163AB94ULL,
		0xB59C446DE8E1947FULL,
		0x9FFE2A12997FFB4AULL,
		0x597551ED3DB469F0ULL,
		0xCD89D8F0D64509DDULL,
		0x22EB9E36CB64A0CFULL,
		0xD873EAB9AB659B0DULL,
		0xE42ADA9376581BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E40BC37E974FC7EULL,
		0xF2554F54E9599FE1ULL,
		0x01FCB7F8F93ADEBAULL,
		0x8668EB87FD198A02ULL,
		0x2925225F9FEAB887ULL,
		0xA5FBEEE40AD905E5ULL,
		0x25A1EF37A10A18C8ULL,
		0xF8CE3AA7B7E22F9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5E0746DF81757EAULL,
		0x47C90B3901B80B9EULL,
		0x9E029DEA604525F0ULL,
		0xDF1DBA6AC0ADE3F2ULL,
		0xE4ACFAAF49AFB15AULL,
		0x871070D2C1BDA52AULL,
		0xFDD2058E0A6F83C5ULL,
		0x1CE4E034C1BA3441ULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC7542FDDC21C7745ULL,
		0xA0A4BACC5635F000ULL,
		0xD4A0805317248806ULL,
		0xA407A29B817DAF70ULL,
		0x76264B9F1E3932D2ULL,
		0x2B34B4AB623DBB2EULL,
		0xDB1ED49E39A0E445ULL,
		0xD1D2EF278AD29E22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1A200D25909978DULL,
		0xAD27BD48F328B14DULL,
		0x776DB87575CF96CEULL,
		0x0E197932AE4104C7ULL,
		0x9062DD7CCC43216AULL,
		0xD75A76676C36B34FULL,
		0xCC4B0CA9036F5A5DULL,
		0x8D6C98FD1951245DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76F62F0F9B15E0C8ULL,
		0x0D830784A51D414DULL,
		0xA3CD382662EB1EC8ULL,
		0xAA1EDBA92F3CABB7ULL,
		0xE64496E3D27A13B8ULL,
		0xFC6EC2CC0E0B0861ULL,
		0x1755D8373ACFBE18ULL,
		0x5CBE77DA9383BA7FULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x08B52CA8400EB0CBULL,
		0x2DAEDC3CF76AE7EBULL,
		0xB5C7B95E39EDC545ULL,
		0x735CED89737B7089ULL,
		0x20F5688AD3F1291EULL,
		0xCF22C312ACC30E18ULL,
		0xDC22EC3271C0CC9DULL,
		0xCD1A3797080982A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BD66E9AB31176F5ULL,
		0x42B67EC59042D2B2ULL,
		0x814DB3DA95F61E50ULL,
		0x8EA4393DD65427F8ULL,
		0xE78B8A529328019DULL,
		0x1EB82EE83BC90E41ULL,
		0xECBD6D68EDAAA7C9ULL,
		0xD1F7744F7864DB63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23634232F31FC63EULL,
		0x6F18A2F967283559ULL,
		0x348A0A84AC1BDB15ULL,
		0xFDF8D4B4A52F5771ULL,
		0xC77EE2D840D92883ULL,
		0xD19AEDFA970A0059ULL,
		0x309F815A9C6A6B54ULL,
		0x1CED43D8706D59C6ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4E337F9A2B9BE97DULL,
		0xDFB82D365EB7E7FCULL,
		0x4037FA3A97FE0539ULL,
		0x47E1D1A535BBC7DDULL,
		0xD3B82BF0B9DAE228ULL,
		0xDCD106FEA6D8F7BEULL,
		0xA82B34308C8CD31CULL,
		0x9534225C3954C4E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EC2A0D33FC82FF1ULL,
		0x53BA26D997BF9C2CULL,
		0xBB156AF0EBE4A756ULL,
		0x04B3F774F2B52412ULL,
		0xB80C8F66CDE9C254ULL,
		0x9CEFDBD12C456538ULL,
		0x592DFE54D96E3BB6ULL,
		0x306C126E2D5593F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10F1DF491453C68CULL,
		0x8C020BEFC9087BD0ULL,
		0xFB2290CA7C1AA26FULL,
		0x435226D1C70EE3CFULL,
		0x6BB4A4967433207CULL,
		0x403EDD2F8A9D9286ULL,
		0xF106CA6455E2E8AAULL,
		0xA558303214015718ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x74F7F45D6D9C9609ULL,
		0x3F8F4145225514ABULL,
		0xB5FD17C1C63D2691ULL,
		0xFFA56FCAE08C308EULL,
		0xC8E3C8A54A9A5F11ULL,
		0xBAF4549E23FD5005ULL,
		0x51402F6896C47E2CULL,
		0x5EF759486C1D3EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD277D978E0C3FED1ULL,
		0x296929D17D4A7EE1ULL,
		0xA1E004C4DE59E87DULL,
		0xC03399FA6EC31150ULL,
		0xEEF07B692E9A53B7ULL,
		0x2BF0D988A63BA05DULL,
		0x3C4D60F5706D6526ULL,
		0x6153EA274C1D07DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6802D258D5F68D8ULL,
		0x16E668945F1F6A4AULL,
		0x141D13051864CEECULL,
		0x3F96F6308E4F21DEULL,
		0x2613B3CC64000CA6ULL,
		0x91048D1685C6F058ULL,
		0x6D0D4F9DE6A91B0AULL,
		0x3FA4B36F20003937ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE2F4AAE538D79417ULL,
		0x93EFF226096932B2ULL,
		0x9A312342D246BB66ULL,
		0xFFDA07FE0D367A47ULL,
		0xCEF0B50F8558E065ULL,
		0xB55433EACAE7DC78ULL,
		0x314D6994D428D507ULL,
		0xEE330AF7831C4706ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742E4046527711A0ULL,
		0xAD1D3D2D8E647476ULL,
		0x90F75B9F578545CEULL,
		0x84D62687A3C8DF80ULL,
		0x7FE422D4D41B31F8ULL,
		0xC05629C51883F94AULL,
		0xE1189CB5C64A489AULL,
		0x6528A447F4203BE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96DAEAA36AA085B7ULL,
		0x3EF2CF0B870D46C4ULL,
		0x0AC678DD85C3FEA8ULL,
		0x7B0C2179AEFEA5C7ULL,
		0xB11497DB5143D19DULL,
		0x75021A2FD2642532ULL,
		0xD055F52112629D9DULL,
		0x8B1BAEB0773C7CE5ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x412A3C16DCCC1B31ULL,
		0xBFF6F2AFE996B595ULL,
		0xCDF9DADEBA7391ECULL,
		0x60B45B268A027760ULL,
		0x333406D7622D9DDCULL,
		0x49F1E8C0E14A14FDULL,
		0xAF71DB1BBFF22829ULL,
		0x649DCD18E9C7EC58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x970F035A41601547ULL,
		0x1D5CC2DFAFB43D0FULL,
		0xD7951B53291BBD42ULL,
		0x66E1E9A62F5358BEULL,
		0x20C73DBA3067D4FEULL,
		0xFBC248B10D560F03ULL,
		0x876D5C359E34813BULL,
		0xD659825F0CC881F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6253F4C9DAC0E76ULL,
		0xA2AA30704622889AULL,
		0x1A6CC18D93682CAEULL,
		0x0655B280A5512FDEULL,
		0x13F33B6D524A4922ULL,
		0xB233A071EC1C1BFEULL,
		0x281C872E21C6A912ULL,
		0xB2C44F47E50F6DAFULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0A9CC71D48EF2F5CULL,
		0x64276FB70A0D888DULL,
		0xAF661DC27CC8E24FULL,
		0x9C059A6BB2AEF7BBULL,
		0x4D24D4E83D4B4A8FULL,
		0x9514D01DE938404FULL,
		0xF83FD1D0D54002A6ULL,
		0xC4BEE57A4DEF78C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4AFF8BAE158F933ULL,
		0xBDB69FE14FC21C36ULL,
		0xF3B1AE263C3C2E22ULL,
		0xE994F09D135293F8ULL,
		0x1C4D0494EDF50757ULL,
		0xBAC793C3DEB3B109ULL,
		0x916631A09E881BF2ULL,
		0x8E8291C5FCDF38D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE333FA7A9B7D66FULL,
		0xD991F05645CF94BBULL,
		0x5CD7B3E440F4CC6DULL,
		0x75916AF6A1FC6443ULL,
		0x5169D07CD0BE4DD8ULL,
		0x2FD343DE378BF146ULL,
		0x6959E0704BC81954ULL,
		0x4A3C74BFB1304014ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x91EE204BC61489C8ULL,
		0x73D4A8F612D537AAULL,
		0xA7A765F6CB9F6E85ULL,
		0xF3BC2FC013DD761FULL,
		0xF96C5DF389581F0FULL,
		0x5B75C169C3B11030ULL,
		0x8B3D3200059E599BULL,
		0x7A8352264F2808C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1C966AE144879F5ULL,
		0xAF989D20C94CA7A7ULL,
		0xDB01FF3D5E1980D1ULL,
		0x21275B66B414F8BEULL,
		0xC246A85B2ED46BF5ULL,
		0x44824B025787A4A1ULL,
		0x07396A6D72A42A75ULL,
		0xB0E4407B4FE5CB0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x602746E5D25CF03DULL,
		0xDC4C35D6DB99900DULL,
		0x7CA69ACB9586EE54ULL,
		0xD29B74A6A7C98EA1ULL,
		0x3B2AF5A8A78C74FAULL,
		0x1FF78A6B9436B491ULL,
		0x8C04586D773A73EEULL,
		0xCA67125D00CDC3CEULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1CF499663D510853ULL,
		0xAB6D76F4CB9C127FULL,
		0x9382A2FE72DD90DCULL,
		0x178E931AF7EC6EBFULL,
		0x5EA405A477DF8837ULL,
		0x3FF0CCB959BC97D8ULL,
		0x6669B9C0F0037A83ULL,
		0xC05AAC4270F9E855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D4EB24E6C6D9A0AULL,
		0x23D899FA86F56207ULL,
		0xF6D92AE2658D8510ULL,
		0x7DE0C80793233F73ULL,
		0xC2203305344A4964ULL,
		0x501148B653A839FDULL,
		0x7A7CC2091E4D6A6AULL,
		0x304D1C0E4C9E803FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31BA2B28513C9259ULL,
		0x88B5EF0E4D697078ULL,
		0x655B881C175015CCULL,
		0x6A6E5B1D64CF51CCULL,
		0x9C8436A14395C153ULL,
		0x6FE1840F0A14AE25ULL,
		0x1C157BC9EE4E10E9ULL,
		0xF017B04C3C67686AULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5A696D0063D02ECFULL,
		0xAC942F2C0FE3151CULL,
		0x5B331E5664CB777DULL,
		0x11D65A152C7ECDDAULL,
		0x4BBA476E3EADF933ULL,
		0x1B3B1A9B44B518EAULL,
		0x0C4EE8437E5E70C6ULL,
		0x66CCE913B395D4D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49126B24445B960ULL,
		0xFE6919B9BEE7BAFDULL,
		0x9468362ECA369992ULL,
		0xDBD95B53ED45B2ABULL,
		0x8DE9AE04AFAF7D1BULL,
		0xA2E172EC44665164ULL,
		0x09A24949C190C0F7ULL,
		0x254722C92D738EE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EF84BB2279597AFULL,
		0x52FD3695B104AFE1ULL,
		0xCF5B2878AEFDEEEFULL,
		0xCA0F0146C13B7F71ULL,
		0xC653E96A91028428ULL,
		0xB9DA687700D3498EULL,
		0x05ECA10ABFCEB031ULL,
		0x438BCBDA9EE65A31ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB06D2650E2AB2659ULL,
		0x5721C0A43D70163FULL,
		0xF1D3F2F0308474BBULL,
		0x361CA462C2AD2202ULL,
		0x446191708260C9D3ULL,
		0xA4DE1F2AF493D2D5ULL,
		0x05248C31243F822AULL,
		0x80F7123D19F198A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95476FD4BEF031FULL,
		0xB1124D3BD1555AD4ULL,
		0x9B898ECB35B67FA3ULL,
		0x0F08C2F282C23C6CULL,
		0xAF50F8A6A9DF4290ULL,
		0x1053A968B4661F84ULL,
		0xB5A09019C9B58A80ULL,
		0x72549CB909FE4705ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x093950ADA9442546ULL,
		0xE6338D9FEC254CEBULL,
		0x6A5A7C3B05320B18ULL,
		0x39146690406F1E6EULL,
		0xEB3169D62BBF8B43ULL,
		0xB48DB64240F5CD51ULL,
		0xB0841C28ED8A08AAULL,
		0xF2A38E84100FDFA3ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x429D7469DD265A91ULL,
		0xC920697C488F60CAULL,
		0x05F8012CBDD7260CULL,
		0xA5FAF46528A846DDULL,
		0x4563B0A0C31BF8E9ULL,
		0xFF4B9BC9465B1066ULL,
		0x7D1B5D249D79D33FULL,
		0xB36660016855E756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF1E2F957425942ULL,
		0x413C03472038D541ULL,
		0x61CA5DA6D7BC5B16ULL,
		0x206D9DCB4F4D3064ULL,
		0xDB2F9789DED83D09ULL,
		0x3730D289B3106BE7ULL,
		0xA59C665193733BA4ULL,
		0x75056C304A04D3BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB96C96908A6403D3ULL,
		0x881C6A3B68B7B58BULL,
		0x64325C8A6A6B7D1AULL,
		0x859769AE67E576B9ULL,
		0x9E4C27291DC3C5E0ULL,
		0xC87B4940F54B7B81ULL,
		0xD8873B750E0AE89BULL,
		0xC6630C31225134EDULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x27DAA119298B9B23ULL,
		0xDDAF64D125FAF72FULL,
		0x88791507ECCF1124ULL,
		0x76E9BE63BC3CBB74ULL,
		0x8E2187C0557263C6ULL,
		0xDABE57EEEE96B2EAULL,
		0xDF0C9605AFD54C5DULL,
		0x2D7BA24C7B03457EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD04ED27C9C27EAC7ULL,
		0x180D97661406BFBFULL,
		0x3F0DF7D7BD046293ULL,
		0xBB01BD3D07B1FC55ULL,
		0xDC1256D82386AF63ULL,
		0x0A61C2765672051EULL,
		0x4E9E4F298415E16DULL,
		0x0AFCC594D115650AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7947365B5AC71E4ULL,
		0xC5A2F3B731FC4890ULL,
		0xB774E2D051CB73B7ULL,
		0xCDE8035EBB8D4721ULL,
		0x5233D11876F4CCA5ULL,
		0xD0DF9598B8E4B7F4ULL,
		0x9192D92C2BC0AD30ULL,
		0x278767D8AA162074ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA384A9BE073B7B1DULL,
		0x03DC3D127FB8075DULL,
		0x7A71B17BD6AA7DD7ULL,
		0x33D96E528CE37100ULL,
		0x1B5BA97D5B6B1C8DULL,
		0x4E287A95255313D0ULL,
		0xEC435B70A87FC473ULL,
		0xF02FFA46C7B906DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8448CDCDBDD77EULL,
		0xB9FDB4BD9C2B913BULL,
		0x1F81B89F4EE913F6ULL,
		0x337AB2916CA09B09ULL,
		0xD726760118AC91E2ULL,
		0xBC07B68EDA17CC85ULL,
		0x1726EF1BC217E017ULL,
		0x144026E7FC5BB18DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2800E173CA86AC63ULL,
		0xBA2189AFE3939666ULL,
		0x65F009E498436E21ULL,
		0x00A3DCC3E043EA09ULL,
		0xCC7DDF7C43C78D6FULL,
		0xF22FCC1BFF44DF55ULL,
		0xFB65B46B6A682464ULL,
		0xE46FDCA13BE2B751ULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x48A1C3911C00AA67ULL,
		0x7288A9D94E18060FULL,
		0x8E14B7E91F6B46B7ULL,
		0xFFC4BAD1F75EBCC1ULL,
		0x2A2FC09E5B92358FULL,
		0x7FC966A599AF865CULL,
		0x17988B0C0D909A0CULL,
		0x00F5A074406706E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4579D1ACF619DCE6ULL,
		0xB1B2C680A6CE6EBDULL,
		0x223E550D5F276CC4ULL,
		0xFB17F494EC7E6DA4ULL,
		0x669F0251894BE717ULL,
		0x287E0E16CB38F133ULL,
		0x08AE58D8DEE00A8AULL,
		0xAA7C7A677E1F38E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DD8123DEA197681ULL,
		0xC33A6F59E8D668B2ULL,
		0xAC2AE2E4404C2A73ULL,
		0x04D34E451B20D165ULL,
		0x4CB0C2CFD2D9D298ULL,
		0x57B768B35297776FULL,
		0x1F36D3D4D3709086ULL,
		0xAA89DA133E783E0DULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x00BAE5D39079DD2FULL,
		0x9EFDED57A9DD88A4ULL,
		0xFEC9B956A34BDF4CULL,
		0x73F2E5EDEACC1C6FULL,
		0xC99925D33058A304ULL,
		0x04E634DE8C6A22D3ULL,
		0xF3B6E6E2E9A26A1FULL,
		0x13EC3B8B9B493502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x139C867BF7BF9B39ULL,
		0x7ADA88DF0D7DA01BULL,
		0x0D0CB49EE33E4020ULL,
		0x4580DD2464031D9AULL,
		0x82C1B9D0BEDB8F95ULL,
		0x11F44F2BA11AC12AULL,
		0xCC52810C07EBF83AULL,
		0x23D8C65F358E2310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x132663A867C64616ULL,
		0xE4276588A4A028BFULL,
		0xF3C50DC840759F6CULL,
		0x367238C98ECF01F5ULL,
		0x4B589C038E832C91ULL,
		0x15127BF52D70E3F9ULL,
		0x3FE467EEEE499225ULL,
		0x3034FDD4AEC71612ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9F23A9EC8DB6A500ULL,
		0x1EBBDE4AAFC761D6ULL,
		0x183FC3E9D6377D93ULL,
		0xAF321D673867BC5EULL,
		0x80DA887831D27CC1ULL,
		0x55DB66DF81198844ULL,
		0x3F06EBDFAEB916F1ULL,
		0x037D849BDF26E14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75EDAC866061F0AEULL,
		0x2D34BC3D3A84DB7EULL,
		0xAC342F96922D445CULL,
		0x8B44A15A4D2E6FFDULL,
		0xAC14FC6163BC2D6EULL,
		0x04ACC149D42A44CBULL,
		0x16897A838D6CF897ULL,
		0xDAE5D6D23559DA2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEACE056AEDD755AEULL,
		0x338F62779543BAA8ULL,
		0xB40BEC7F441A39CFULL,
		0x2476BC3D7549D3A3ULL,
		0x2CCE7419526E51AFULL,
		0x5177A7965533CC8FULL,
		0x298F915C23D5EE66ULL,
		0xD9985249EA7F3B61ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBFB7CE638ED48713ULL,
		0xE1C5BAA83CA65C94ULL,
		0xD0094C5802DD4BB9ULL,
		0x80FAF4C807847A5DULL,
		0xEF30D1EFA503C906ULL,
		0xB9FA801E306E10AFULL,
		0x7D9DEA2079B68A34ULL,
		0x44092E64A4D22B93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB609994FA12632EEULL,
		0xFD57E56E8D612F59ULL,
		0x641C117E65FCC133ULL,
		0x891ECAA1051746FDULL,
		0xA0667A3874026B2CULL,
		0x5A1D861FBA771168ULL,
		0x77A47796CE256A3AULL,
		0x359C38B272C067BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09BE572C2FF2B5FDULL,
		0x1C925FC6B1C773CDULL,
		0xB4155D2667218A8AULL,
		0x09E43E6902933CA0ULL,
		0x4F56ABD7D101A22AULL,
		0xE3E706018A1901C7ULL,
		0x0A399DB6B793E00EULL,
		0x719516D6D6124C2CULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5109F2FA1617555ULL,
		0x42B2CE5F1B1833A8ULL,
		0xC82BE160DF53F0D8ULL,
		0x2BB4E01F42BEB3F8ULL,
		0x8E7D8AB52FAE5CA1ULL,
		0xA4D31850B2DEF190ULL,
		0x777DB75D08CF8B7CULL,
		0x8FCCA43D7AC4A1EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C1E3191F85165AULL,
		0x43C502E06C65F68DULL,
		0x30D7E7749DA5A4DAULL,
		0x6F95FA3AD8A2EAF8ULL,
		0x850D9B366A48CE0FULL,
		0xAA778DC8708963B4ULL,
		0x69E39BB722854EF1ULL,
		0x60A94C83ECB9D1E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12D17C36BEE4630FULL,
		0x0177CCBF777DC525ULL,
		0xF8FC061442F65402ULL,
		0x44211A259A1C5900ULL,
		0x0B70118345E692AEULL,
		0x0EA49598C2579224ULL,
		0x1E9E2CEA2A4AC58DULL,
		0xEF65E8BE967D700CULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEE72B0F44BFF4BDAULL,
		0xA904233345885CFAULL,
		0x3F577A26F4F25A99ULL,
		0x611AD5E62423CFB5ULL,
		0x850C4251E83349D7ULL,
		0x629883B011D820E2ULL,
		0x6FFEAAC27503AAAEULL,
		0x1F24E649276C4FD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC08D73AEBAC9429ULL,
		0x94692ABAA420D028ULL,
		0xDF5CF677A7FD3CA4ULL,
		0x51159639BDD01F5CULL,
		0x8FAF47C211C3D2EFULL,
		0xE17DC38BD06F341CULL,
		0xA05B96165BAEE712ULL,
		0x57D844B931F100B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x127A67CEA053DFF3ULL,
		0x3D6D0989E1A88CD2ULL,
		0xE00B8C51530F663DULL,
		0x300F43DF99F3D0E9ULL,
		0x0AA30593F9F09B38ULL,
		0x83E5403BC1B714FEULL,
		0xCFA53CD42EAD4DBCULL,
		0x48FCA2F0169D4F62ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE555BA500AB164FFULL,
		0x1A5BF4DBE148C170ULL,
		0x215827C7346B3712ULL,
		0x95D02DFD4DF7BEC2ULL,
		0x8485E2F153F39EA9ULL,
		0x70A04FF5945FFF62ULL,
		0x74EBB6FA159879D0ULL,
		0xE07F635E5C5A9F13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4335B3EE0EA52082ULL,
		0x363C4181A38A258DULL,
		0x5EC6F722419E999CULL,
		0xF0FC1F4B5CB9758AULL,
		0xFFD6B0096819CDABULL,
		0x07C23246ABB00D07ULL,
		0x4E5A2005B55E9ACBULL,
		0x489143EE8626AE2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA66009BE0414447DULL,
		0x2C67B55A42C2E4FDULL,
		0x7F9ED0E575F5AE8EULL,
		0x652C32B6114ECB48ULL,
		0x7B5352F83BEA5302ULL,
		0x77627DB33FEFF265ULL,
		0x3AB196FFA0C6E31BULL,
		0xA8EE20B0DA7C313DULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA8B2F766000CE126ULL,
		0xD1FF3887181EDF8DULL,
		0x7D2B3AB59298A9D2ULL,
		0x0835F14225ED944AULL,
		0x9641FD567FDAEB0BULL,
		0xC41281B7294C1F19ULL,
		0xF77E769CFFAFBA54ULL,
		0x718130056C711B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x840F2ED391C1CC58ULL,
		0x3A17CE06B117B560ULL,
		0x85525A8A398D164AULL,
		0x8F352B6FDD6F08D9ULL,
		0xFF2006775732D708ULL,
		0xEDF77EAEB6070FB5ULL,
		0xB90A70ACC8DB7F14ULL,
		0x1B5C0B243F67B951ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CBDD9B591CD2D7EULL,
		0xEBE8F681A9096AEDULL,
		0xF879603FAB15BF98ULL,
		0x8700DA2DF8829C93ULL,
		0x6961FB2128E83C03ULL,
		0x29E5FF199F4B10ACULL,
		0x4E7406303774C540ULL,
		0x6ADD3B215316A2CAULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFB9D40EDD73F4C4DULL,
		0x04C0FF16F1EB8D10ULL,
		0x3D7FF95A72AAA344ULL,
		0xD059A7D68D180682ULL,
		0xCD735F9DB9615407ULL,
		0xF544CDF5D0D0DE99ULL,
		0xE14409873868C860ULL,
		0x0C98992FBA58FC42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2487062F777D62ULL,
		0x72EC74624CC0A293ULL,
		0x12877FBA3E82E8AAULL,
		0x5B1BD07B6AD7D944ULL,
		0x120445AF75EA52A9ULL,
		0x8086E88C2A270655ULL,
		0x67743A84D067FCE5ULL,
		0x978DF25A2630F8E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6B9C7EBF848312FULL,
		0x762C8B74BD2B2F83ULL,
		0x2FF886E04C284BEEULL,
		0x8B4277ADE7CFDFC6ULL,
		0xDF771A32CC8B06AEULL,
		0x75C22579FAF7D8CCULL,
		0x86303303E80F3485ULL,
		0x9B156B759C6804A2ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4B4095F393F23956ULL,
		0x9CC8166AA69BE343ULL,
		0x6983387E3D7B6F6DULL,
		0xD6F475EB0F757342ULL,
		0xA823DD2F8FED067EULL,
		0x5E7463BF2A68DDC2ULL,
		0x47BDD3CA1008B776ULL,
		0x6238E040A39E9EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CAA51DC2CC7674AULL,
		0x6585EBECAE888481ULL,
		0x3D5A73C57B1B8915ULL,
		0xF2ED50350E5BA8E2ULL,
		0xB8C7B5A7719F822CULL,
		0x2C16BA8B9689A4B6ULL,
		0xB69C3FC63D54EE5BULL,
		0x90C21022EAFECBE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7EAC42FBF355E1CULL,
		0xF94DFD86081367C2ULL,
		0x54D94BBB4660E678ULL,
		0x241925DE012EDBA0ULL,
		0x10E46888FE728452ULL,
		0x7262D934BCE17974ULL,
		0xF121EC0C2D5C592DULL,
		0xF2FAF0624960555EULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x74856D23D1151482ULL,
		0x0BC8F2CA46236256ULL,
		0xF3A19D2571B9FFF8ULL,
		0x4DBA32D6865ACC16ULL,
		0x85A028A8AC77F1D8ULL,
		0xAEBCB76DB2F855E9ULL,
		0x951E224649F0B6E6ULL,
		0xC992B0BCA355B973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE887037E63103BE4ULL,
		0x0FB99AF1F70C388CULL,
		0x9E5FAC2F1760F88CULL,
		0x0700BBAE07D24FC3ULL,
		0xB95976790057DCA8ULL,
		0xBBC1DB3F8D7ECEAEULL,
		0xCE3CCF2E5F18790DULL,
		0xDDC0098C86A9A3A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C026E5DB2052F66ULL,
		0x0471683BB12F5ADAULL,
		0x6DFE310A66D90774ULL,
		0x4ABA8978818883D5ULL,
		0x3CF95ED1AC202D70ULL,
		0x157D6C523F869B47ULL,
		0x5B22ED6816E8CFEBULL,
		0x1452B93025FC1AD7ULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC6FDAC08A087D552ULL,
		0x1D45C0DEC932055DULL,
		0xDBFE27ED12A50819ULL,
		0x9FBB1551C628C7BFULL,
		0xDADA864A083FDE29ULL,
		0x4776ED05D0D5D5A7ULL,
		0xC02C6847C03F8B1BULL,
		0x64F4A24814686A93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63E9F1BEEE84A2CULL,
		0xFF51F8D8C9ADF633ULL,
		0xBD1B3E137CA6EE0DULL,
		0x8422805C123245E1ULL,
		0xF13CFDDFB155EC84ULL,
		0x6695AB43912BEB39ULL,
		0x69C19D78A252E587ULL,
		0xFE086020AD1A0630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C333134E6F9F7EULL,
		0xE2143806009FF36EULL,
		0x66E519FE6E03E614ULL,
		0x1B99950DD41A825EULL,
		0x2BE67B95B96A32ADULL,
		0x21E3464641FE3E9EULL,
		0xA9EDF53F626D6E9CULL,
		0x9AFCC268B9726CA3ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x58345FEEFA201BCFULL,
		0x0367F5639A7CDE39ULL,
		0x8717BB82B6658A5DULL,
		0x5F42E6E094C0753EULL,
		0x1DFB0BD16C877B98ULL,
		0x5AEEBA01CA977D3CULL,
		0x7C81344F1D8CE784ULL,
		0x5532CFC45BFF38D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x165BBFD28A1248E8ULL,
		0xAA2EE7B17DB6842CULL,
		0x3BE676ADB81445F2ULL,
		0xEFD891083179B6E0ULL,
		0x75AA5D65DBCAAE86ULL,
		0x1AA3C1498BAA264CULL,
		0x57A978A89658D818ULL,
		0x06F1D7F699D75A62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E6FE03C70325327ULL,
		0xA94912D2E7CA5A15ULL,
		0xBCF1CD2F0E71CFAFULL,
		0xB09A77E8A5B9C3DEULL,
		0x685156B4B74DD51EULL,
		0x404D7B48413D5B70ULL,
		0x2B284CE78BD43F9CULL,
		0x53C31832C22862B0ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x78422524FC0FCC24ULL,
		0x355700246AD2F451ULL,
		0x591EC9781E5DE865ULL,
		0x1886C940C09ED774ULL,
		0x0194257AF53EBB72ULL,
		0x040B707098DCDE66ULL,
		0x537DCA1890FCCFB7ULL,
		0x3F69912FA8885F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B377FCD1978033AULL,
		0x90262C9ECC1D3AD8ULL,
		0x0BF2A2780911E7E8ULL,
		0xD3E107E3A577326FULL,
		0xC7225E77C91A2FDAULL,
		0x54E06114C32D035DULL,
		0x14A4E037E711A7DCULL,
		0xB25C3FC3FC48578EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23755AE9E577CF1EULL,
		0xA5712CBAA6CFCE89ULL,
		0x52EC6B00174C0F8DULL,
		0xCB67CEA365E9E51BULL,
		0xC6B67B0D3C2494A8ULL,
		0x50EB11645BF1DD3BULL,
		0x47D92A2F77ED686BULL,
		0x8D35AEEC54C008D0ULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x31384EB4DDD5E861ULL,
		0xFEBC2C73D2C3B9B5ULL,
		0x9DF6EAA3974CF37AULL,
		0xBCF748BB806A3A9DULL,
		0xE16ED62169127F3DULL,
		0x47C20FB1E3534942ULL,
		0xE9AF22AD87AF67AFULL,
		0xD11B86240E211E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2339BA3BDEB370EBULL,
		0xDBF08D7A594CCD3BULL,
		0x822E1EC5FF6890C7ULL,
		0xD64827BE7E6EE828ULL,
		0xF9C10198FEB8DBF9ULL,
		0x360459E4C93F8187ULL,
		0x75ABEF8759B90E79ULL,
		0x44586105059114E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1201F48F0366988AULL,
		0x254CA1098B8F748EULL,
		0x1FD8F466682463BDULL,
		0x6ABF6F05FE04D2B5ULL,
		0x18AFD7B997AAA4C4ULL,
		0x71C656552A6CC8C5ULL,
		0x9C04CD2ADE1669D6ULL,
		0x9543E7210BB00A92ULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA522D12B51A87186ULL,
		0x1DD34EB97C38A92CULL,
		0x1488D97CBF33C015ULL,
		0x5246E94E901F25B3ULL,
		0xA3AE105101E46D43ULL,
		0x91F522AB883E09E5ULL,
		0x1D3AB6B77A283F9BULL,
		0x2A4C8A19B6C6F990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27257A2558BF4755ULL,
		0x7A5370E69A390F31ULL,
		0xBFBE1F584AD991F2ULL,
		0x214F3E75E37E88FDULL,
		0x8F9F9EE7D1004226ULL,
		0x0346E3D0D3E9CC09ULL,
		0x501E367F472F9F10ULL,
		0x1A213F86E1EABC9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8207AB0E091736D3ULL,
		0x67803E5FE601A61DULL,
		0xAB36C624F5EA51E7ULL,
		0x7309D73B7361AD4EULL,
		0x2C318EB6D0E42F65ULL,
		0x92B3C17B5BD7C5ECULL,
		0x4D2480C83D07A08BULL,
		0x306DB59F572C450EULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD6A073C4906BD65EULL,
		0x7557DD51445E5E98ULL,
		0x11DA20B48EB658DAULL,
		0x3D6FC2DB6D78069EULL,
		0xA77490056EC8D9DCULL,
		0xC4A304D22E7AC076ULL,
		0xFED4439915CDD0ACULL,
		0x5D35E6D58BE0CA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4569063E1E05930AULL,
		0x312D4D854B205FD5ULL,
		0x0B3C431E7C8DA835ULL,
		0xCE756999EB09174BULL,
		0x07CA567EBA77FEF2ULL,
		0xBD03737B14B49F6EULL,
		0xBA56F4A91E922583ULL,
		0x3F8C396D1094728EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93C975FA8E6E4554ULL,
		0x447A90D40F7E014DULL,
		0x1AE663AAF23BF0EFULL,
		0xF31AAB42867111D5ULL,
		0xA0BEC67BD4BF272EULL,
		0x79A077A93ACE5F18ULL,
		0x4482B7300B5FF52FULL,
		0x62B9DFB89B74B80BULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC689DF93B6D025DEULL,
		0x076ADF68D4544883ULL,
		0xB4775791BCC508D9ULL,
		0x18B2ED25F4E273E8ULL,
		0x530D675BF9D61F99ULL,
		0x1B480FABAD01141AULL,
		0x238E5DA91BA6B07BULL,
		0x4F1ADAF51DA58A1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C910CA342385A38ULL,
		0xB33F6A6DBD36BD81ULL,
		0xDBF1900757A7D37AULL,
		0x203DEA966F5ED22DULL,
		0x9D625C089C6F6E87ULL,
		0x69951D0CA3480715ULL,
		0x161828285F19BBC3ULL,
		0xFCC0C69C149260E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA18D330F4E87FE6ULL,
		0xB455B5056962F502ULL,
		0x6F86C796EB62DBA3ULL,
		0x388F07B39BBCA1C5ULL,
		0xCE6F3B5365B9711EULL,
		0x72DD12A70E49130FULL,
		0x3596758144BF0BB8ULL,
		0xB3DA1C690937EAF8ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x977DD70E62F2AEEAULL,
		0x1463AA0284687B5DULL,
		0x1E6B575E79DBAF82ULL,
		0x0429EBB27BC84DC3ULL,
		0xAFE1F50C68CD9B86ULL,
		0x5405311381C2CB38ULL,
		0xFC89D29EFC768026ULL,
		0x3AC3C9446260EF15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0045BA480104B82BULL,
		0x5F327F248739DD09ULL,
		0xB2D798B85C4D37B4ULL,
		0x725B8810BA9471FBULL,
		0xB9B7160B1874885DULL,
		0x20D126D3DB79C6C5ULL,
		0x9AB33EC6BF12932DULL,
		0xE337F6DF7EBCAA66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97386D4663F616C1ULL,
		0x4B51D5260351A654ULL,
		0xACBCCFE625969836ULL,
		0x767263A2C15C3C38ULL,
		0x1656E30770B913DBULL,
		0x74D417C05ABB0DFDULL,
		0x663AEC584364130BULL,
		0xD9F43F9B1CDC4573ULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x11240B2EC9875C36ULL,
		0x78C27F1854336206ULL,
		0x548B509DB18BC7FEULL,
		0x063BBDEEF4B67339ULL,
		0x1DE67F3E3EBB1144ULL,
		0xF6D7448CCC159A7BULL,
		0xF074B00954A6586FULL,
		0x30FFC3AB0A343745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09DB66DF7FC59002ULL,
		0x6826A993B79D045BULL,
		0x096B49599D70CE2EULL,
		0x489AC5ED5C7B05FDULL,
		0x88CCB01FBA5E9689ULL,
		0x4FB74A640DE4B5A5ULL,
		0x1EA2417F263C3675ULL,
		0x1D6452670AE1253DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18FF6DF1B642CC34ULL,
		0x10E4D68BE3AE665DULL,
		0x5DE019C42CFB09D0ULL,
		0x4EA17803A8CD76C4ULL,
		0x952ACF2184E587CDULL,
		0xB9600EE8C1F12FDEULL,
		0xEED6F176729A6E1AULL,
		0x2D9B91CC00D51278ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x56F6DEE42B51BB6FULL,
		0x681735E41CAB9D16ULL,
		0xF68E219289BF571AULL,
		0xB0595006127AD887ULL,
		0xCA17E968D2AE1BEFULL,
		0xA500FD641A21EBADULL,
		0x461322E433AACD05ULL,
		0x4F71BDC5CD11564AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03BD6573F4BDCC56ULL,
		0x371896ED178A932AULL,
		0x7D4E30E2A842B962ULL,
		0xAC5BDDB33AEECBADULL,
		0xB27DB2401B1B60D8ULL,
		0x1D99DA488AEC87DAULL,
		0x60B5D6536912393CULL,
		0x7384B15B69182DD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x554BBB97DFEC7739ULL,
		0x5F0FA3090B210E3CULL,
		0x8BC0117021FDEE78ULL,
		0x1C028DB52894132AULL,
		0x786A5B28C9B57B37ULL,
		0xB899272C90CD6C77ULL,
		0x26A6F4B75AB8F439ULL,
		0x3CF50C9EA4097B98ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB34011A7F7E069E1ULL,
		0x95260AA310816400ULL,
		0x09A9FCEB01BB4C3AULL,
		0xD0D11A4C3BD8BF41ULL,
		0x5ACBF4CA25BC5001ULL,
		0xA5FA15AE1A521139ULL,
		0xBF4A75BDE07C5E20ULL,
		0xF55AD42D063470D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21964C021B02055DULL,
		0x9CE014B935CD2AE3ULL,
		0x528E27283878F2D1ULL,
		0x03A34FA65181BC73ULL,
		0x8B1FD4BCD0A84FC3ULL,
		0x0FB30CD4B9821891ULL,
		0xDFF31ABCBCBF6748ULL,
		0x0E5917131604578FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92D65DA5ECE26CBCULL,
		0x09C61E1A254C4EE3ULL,
		0x5B27DBC339C3BEEBULL,
		0xD37255EA6A590332ULL,
		0xD1D42076F5141FC2ULL,
		0xAA49197AA3D009A8ULL,
		0x60B96F015CC33968ULL,
		0xFB03C33E10302757ULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF086168D51CFB669ULL,
		0x1DCBC735B1E65BD2ULL,
		0x96408069615CE6B9ULL,
		0xF7C588A806A69C28ULL,
		0x5EBA7EBA7FB3F100ULL,
		0x40C6B4A44D609636ULL,
		0x01304851D7E0DA92ULL,
		0xF21B66447AEFD098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE20833710B7F1DAULL,
		0x3E8ABADFEA35BA62ULL,
		0xB2DC55D6E7E037F0ULL,
		0x48A170CFA6EB1033ULL,
		0xC5617769574C78B5ULL,
		0x1BF8DBBD28187310ULL,
		0x7DFE3A563AA7ED83ULL,
		0xFDC86073BC96DF5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EA695BA417847B3ULL,
		0x23417DEA5BD3E1B0ULL,
		0x249CD5BF86BCD149ULL,
		0xBF64F867A04D8C1BULL,
		0x9BDB09D328FF89B5ULL,
		0x5B3E6F196578E526ULL,
		0x7CCE7207ED473711ULL,
		0x0FD30637C6790FC6ULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x88DFD5DADA13DFDAULL,
		0x6FAE94895DFB3AE4ULL,
		0xDCE66223EBB844FEULL,
		0x2D264228751390B3ULL,
		0x56ECCAC1C4691488ULL,
		0x1533F2727CE2EBBDULL,
		0x87CE63158DE1925FULL,
		0x99E9E92AED404100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x652DB20193BBEE7EULL,
		0xAE8AC8E60D2D5423ULL,
		0x311DB0789E8C81F2ULL,
		0xD782F9D3E4B1311BULL,
		0x2E1AF415B560F09CULL,
		0x3F7CBF9E120A4A7DULL,
		0x58B8874048B9652AULL,
		0xE734DFF754BC7B73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDF267DB49A831A4ULL,
		0xC1245C6F50D66EC7ULL,
		0xEDFBD25B7534C50CULL,
		0xFAA4BBFB91A2A1A8ULL,
		0x78F63ED47109E414ULL,
		0x2A4F4DEC6EE8A1C0ULL,
		0xDF76E455C558F775ULL,
		0x7EDD36DDB9FC3A73ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA23E18A7FFA41AE1ULL,
		0x894EA720CB72A91AULL,
		0xB58B0A9CC4D78FADULL,
		0xA463B4B756F56E20ULL,
		0xE7C9AD6932CE9645ULL,
		0xF788AB263E34426EULL,
		0x23D807C1F0AA0BDCULL,
		0x6245BE98AC2C8066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF47F86E2E1D4379ULL,
		0x386FEB76CD417713ULL,
		0x2EBA777C1E593B61ULL,
		0x82420B2EA63061FEULL,
		0x2B87F451E423EAFAULL,
		0xA9A814C8CC810CFBULL,
		0xF6B611AF56205B06ULL,
		0x3895C5C13590CF84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D79E0C9D1B95998ULL,
		0xB1214C560633DE09ULL,
		0x9B317DE0DA8EB4CCULL,
		0x2621BF99F0C50FDEULL,
		0xCC4E5938D6ED7CBFULL,
		0x5E20BFEEF2B54E95ULL,
		0xD56E166EA68A50DAULL,
		0x5AD07B5999BC4FE2ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x852FA55488B5A2D6ULL,
		0x4B585AEDAD51E861ULL,
		0x791F815D49DBE877ULL,
		0x5A709CAEF0CC4F17ULL,
		0x002EF2F97FAB0033ULL,
		0x258EAC6A3C07B81AULL,
		0x2BD68313E666386DULL,
		0x55F5F8E612A079DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39B6CDF13B1A43B8ULL,
		0xC7B31482F6473203ULL,
		0x4C0D74DBFDCFD6A2ULL,
		0x549C10A355F87992ULL,
		0x428B4ACF6506EDEDULL,
		0x1FD79A6EA736C1E5ULL,
		0x5C78570E9AC76E7EULL,
		0xA88FBAD606FB27F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC9968A5B3AFE16EULL,
		0x8CEB4E6F5B16DA62ULL,
		0x3512F586B4143ED5ULL,
		0x0EEC8C0DA5343685ULL,
		0x42A5B8361AADEDDEULL,
		0x3A5936049B3179FFULL,
		0x77AED41D7CA15613ULL,
		0xFD7A4230145B5E2DULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x07A2CB56AECE5FC1ULL,
		0xEC11982791E518A5ULL,
		0x08D13825DF049966ULL,
		0xA29661AF4926EA92ULL,
		0x960620A0F8609410ULL,
		0x8A810284EF2FF3F0ULL,
		0x075273F0AAB8DAA9ULL,
		0x571E941A436064CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F1117164407E68ULL,
		0x273948CEED299BEBULL,
		0xAFCA75DFC0A39BBEULL,
		0x0997596064CAF786ULL,
		0x4E0A8E0DE79F7A4EULL,
		0xF7440AD0B057AF47ULL,
		0x052AE35C232E1ACFULL,
		0x20E6CBD73464FBE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA453DA27CA8E21A9ULL,
		0xCB28D0E97CCC834EULL,
		0xA71B4DFA1FA702D8ULL,
		0xAB0138CF2DEC1D14ULL,
		0xD80CAEAD1FFFEE5EULL,
		0x7DC508545F785CB7ULL,
		0x027890AC8996C066ULL,
		0x77F85FCD77049F2FULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x72D19EE3201BBD39ULL,
		0x708509CE05B7B4D2ULL,
		0xE47189289E2F71F4ULL,
		0x9038D450F9FFBD4FULL,
		0x84F4613E0DEE9B1CULL,
		0x9719E49347C94E82ULL,
		0x8B0234A11871CB06ULL,
		0x34D7109B82C0AEADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9B0F54DC106EA8ULL,
		0xFF3BE8C0406AC890ULL,
		0x9DA8070994AB9AF4ULL,
		0xCA2AFC5E37242F02ULL,
		0x88959B254E459A00ULL,
		0x36CCC1594BF0B50BULL,
		0xCDC5CA7A63A2EB5CULL,
		0x9EC3671E5BE7A693ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E4A91B7FC0BD391ULL,
		0x8FBEE10E45DD7C42ULL,
		0x79D98E210A84EB00ULL,
		0x5A12280ECEDB924DULL,
		0x0C61FA1B43AB011CULL,
		0xA1D525CA0C39FB89ULL,
		0x46C7FEDB7BD3205AULL,
		0xAA147785D927083EULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9DA7D5A57EC97D62ULL,
		0x5159734ADBCCBB65ULL,
		0xE6E9316BC7C5D5CBULL,
		0x42B82FD3BF3EEE3BULL,
		0x357C0F8676FA8A28ULL,
		0xEA976FFC69968C42ULL,
		0x387B3805DB6DB14FULL,
		0xB7E8F8D98E20B8C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227550B3E8924B1AULL,
		0x8B73BD9876A56D37ULL,
		0xD49D7A711E9AD74EULL,
		0x2A30F0880650D2F7ULL,
		0xD11676B340E964ABULL,
		0x7C8160739B5E8E41ULL,
		0x2BE173210377EBBDULL,
		0x558D02B03AEC4C64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFD28516965B3678ULL,
		0xDA2ACED2AD69D652ULL,
		0x32744B1AD95F0285ULL,
		0x6888DF5BB96E3CCCULL,
		0xE46A79353613EE83ULL,
		0x96160F8FF2C80203ULL,
		0x139A4B24D81A5AF2ULL,
		0xE265FA69B4CCF4A0ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2C3A6651ABDCD405ULL,
		0x96861892F682D123ULL,
		0x4164EF48F5D52D50ULL,
		0x546914110549839BULL,
		0x2DC7137A106BDCE1ULL,
		0x37F7075F61884135ULL,
		0x217D755334738031ULL,
		0x2E036549EAF455E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028CD7A66422E994ULL,
		0x7AB9AA5B805CDB80ULL,
		0xAC05686786F910A7ULL,
		0xAF40D9FA597C0AB7ULL,
		0x624FBD38CD363ECCULL,
		0xB8E8359143A50CEFULL,
		0x5CE3CF7D56E1E500ULL,
		0xA52793F35A326BEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EB6B1F7CFFE3D91ULL,
		0xEC3FB2C976DE0AA3ULL,
		0xED61872F732C3DF7ULL,
		0xFB29CDEB5C35892CULL,
		0x4F88AE42DD5DE22DULL,
		0x8F1F32CE222D4DDAULL,
		0x7D9EBA2E62926531ULL,
		0x8B24F6BAB0C63E02ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD7DE63A22862C65EULL,
		0x3494CFD1D863C056ULL,
		0xA542DB581EF18CC4ULL,
		0x7C04820F92DA3A2AULL,
		0x413AB701BC962AA1ULL,
		0x1708D2BC7900294FULL,
		0x78DF2A3585775D7EULL,
		0xEF44088FC37B30D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BDAC62700F7C1C0ULL,
		0xCAD7527D198DBE7DULL,
		0x0C83D75BC581036AULL,
		0xB6FFB93438B279F7ULL,
		0xF39FA099D9EDEF3AULL,
		0x054F91549B2075DEULL,
		0xA60C10F82D801C9CULL,
		0x45A03B2701A6459BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C04A5852895079EULL,
		0xFE439DACC1EE7E2BULL,
		0xA9C10C03DB708FAEULL,
		0xCAFB3B3BAA6843DDULL,
		0xB2A51798657BC59BULL,
		0x124743E8E2205C91ULL,
		0xDED33ACDA8F741E2ULL,
		0xAAE433A8C2DD754CULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAC56B3656338FBEAULL,
		0xB8463A8B873AB03BULL,
		0xC77526A42CB913A5ULL,
		0x39FE9186ADFAABA7ULL,
		0x258EE987168EF3DCULL,
		0x3A9E43517CE7B72CULL,
		0x35E9DEEBD896F473ULL,
		0x9374A501EFEEEA6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41CE3B84DF279186ULL,
		0x903ECE1399321618ULL,
		0xBAE79634163F36D3ULL,
		0xE4A6B9C2C7E53545ULL,
		0x9E5A5921E4A4CA6CULL,
		0x2BB4B0ACDA74B2B7ULL,
		0x02725458F7942F22ULL,
		0x7F2DA83A41B3638AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED9888E1BC1F6A6CULL,
		0x2878F4981E08A623ULL,
		0x7D92B0903A862576ULL,
		0xDD5828446A1F9EE2ULL,
		0xBBD4B0A6F22A39B0ULL,
		0x112AF3FDA693059BULL,
		0x379B8AB32F02DB51ULL,
		0xEC590D3BAE5D89E4ULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5F1D67C2C30EB2CULL,
		0xCA5F0F1E20EB3C8AULL,
		0xC32DD6685843BB25ULL,
		0xF999955D847CD492ULL,
		0x5B779B63AA946131ULL,
		0x7653C843BDB91EECULL,
		0x02BCF936A637E817ULL,
		0x5D1753ABD719BE23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70520F536878C362ULL,
		0xF8E52D778D5FE17DULL,
		0x1D7BDAECA0DEE9F4ULL,
		0xBB7A7C18B15A16C8ULL,
		0xA127D984DC05F2DFULL,
		0xA8E51E18E64DD82EULL,
		0x866FAE0DB3668817ULL,
		0x54EDD30FCD647CF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5A3D92F4448284EULL,
		0x32BA2269ADB4DDF7ULL,
		0xDE560C84F89D52D1ULL,
		0x42E3E9453526C25AULL,
		0xFA5042E7769193EEULL,
		0xDEB6D65B5BF4C6C2ULL,
		0x84D3573B15516000ULL,
		0x09FA80A41A7DC2DBULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x67053BE9F3E65D20ULL,
		0x7BD8241B0CEC470CULL,
		0x3598F0A3CAC2894CULL,
		0x493ED72678B54043ULL,
		0xAD5AFA8FFD20AA0FULL,
		0x3151B8193B68A18FULL,
		0xF3BB30D2A2211AA6ULL,
		0xA46573945235BD4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5253FD7AA35901DULL,
		0xC761E0FDA8EA0240ULL,
		0xECFF971DAC52D4BFULL,
		0x7B392EEDC4A3A26BULL,
		0xA986199E988313B0ULL,
		0xFBD1CF7F0F73B2F0ULL,
		0xF3FFB95A262629E5ULL,
		0xCA2127A61D29F1FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8220043E59D3CD3DULL,
		0xBCB9C4E6A406454CULL,
		0xD96767BE66905DF3ULL,
		0x3207F9CBBC16E228ULL,
		0x04DCE31165A3B9BFULL,
		0xCA807766341B137FULL,
		0x0044898884073343ULL,
		0x6E4454324F1C4CB0ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x37F0CEB304B32700ULL,
		0x590744F9D8D21CD0ULL,
		0x79CB499D8C9A7A9FULL,
		0x8B81E63DB63FED3FULL,
		0xD767CA44C23CB206ULL,
		0xA2651935A8AC1C4EULL,
		0xF369A9ABB9B88E5BULL,
		0xEB1B6963BF79F242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72B4C1210871508CULL,
		0xDB8819AB0685E9A9ULL,
		0x854FC14A523F8A1BULL,
		0x3D0FCA80E7C7C5D0ULL,
		0xC6C17E0ED18124DEULL,
		0x61D23064C9A54A56ULL,
		0xD533D0EB3384B15DULL,
		0xB3292B43A1BA8441ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45440F920CC2778CULL,
		0x828F5D52DE57F579ULL,
		0xFC8488D7DEA5F084ULL,
		0xB68E2CBD51F828EFULL,
		0x11A6B44A13BD96D8ULL,
		0xC3B7295161095618ULL,
		0x265A79408A3C3F06ULL,
		0x583242201EC37603ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD20B88BE44E9FD8EULL,
		0x9F1300FF2634E29AULL,
		0x0F040B8F5B9DF1B0ULL,
		0xBF14E94C20A028EEULL,
		0x479C30AAF71B7EDEULL,
		0x36349CFF2AB32411ULL,
		0xD5F2D8299BFF291AULL,
		0x697EA0A0735B41C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FFCEAB4CC3A3F23ULL,
		0x59062704766DFCF3ULL,
		0x13B4DFDA286070D7ULL,
		0x9E105A9259D1DAB9ULL,
		0xD3782F0098AE94D8ULL,
		0x8ECD3D448502E870ULL,
		0x601E2CA6276F7C3BULL,
		0x5A3D376A808816F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DF7620A88D3C2ADULL,
		0xC61527FB50591E69ULL,
		0x1CB0D45573FD8167ULL,
		0x2104B3DE7971F257ULL,
		0x94E41FAA6FB5EA06ULL,
		0xB8F9A1BBAFB1CC61ULL,
		0xB5ECF48FBC905521ULL,
		0x334397CAF3D35735ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAD7B2A4FCDCB4D50ULL,
		0xBEF74F445DE50484ULL,
		0x07BBEEA0C09029D3ULL,
		0x240FC8D1B7A7BCD8ULL,
		0x0169FF727320A91FULL,
		0x6B642FB8582695DFULL,
		0xE1B252AEF35344C1ULL,
		0xF159ADCE0EDFE69BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x422EF1DC1D17A111ULL,
		0xDC782C7642EFE8E2ULL,
		0x1F1C3A71FD8BA168ULL,
		0x9CAB7FC58A4283A1ULL,
		0x152D07C795306EAFULL,
		0xE7AE9EEAE66D6604ULL,
		0xA1018E3F8F50FC5AULL,
		0x709AE445A88339D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF55DB93D0DCEC41ULL,
		0x628F63321F0AEC66ULL,
		0x18A7D4D13D1B88BBULL,
		0xB8A4B7143DE53F79ULL,
		0x1444F8B5E610C7B0ULL,
		0x8CCAB152BE4BF3DBULL,
		0x40B3DC917C03B89BULL,
		0x81C3498BA65CDF49ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE0AFE862D157FF5AULL,
		0x846D0AD4C7CFD5D1ULL,
		0x2E9D30DD41FD5CDEULL,
		0x9FF6B8026C962CDDULL,
		0x201550BA0A6D993BULL,
		0x1821F4CE5C41A4A3ULL,
		0x693FBB6AB64DF58BULL,
		0x5E7CF05E6BF40D1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB293E5071AE20ADBULL,
		0x1C8F6324DF9B97B5ULL,
		0xC465CCDF88466BA2ULL,
		0xE87550C486CD9827ULL,
		0xDCE165473EEBDCF2ULL,
		0x66BF26FA53B916ECULL,
		0xAB96963CE3D43F55ULL,
		0xD2F7B2BD64AB17D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x523C0D65CBB5F581ULL,
		0x98E269F018544264ULL,
		0xEAF8FC02C9BB377CULL,
		0x7783E8C6EA5BB4FAULL,
		0xFCF435FD348645C9ULL,
		0x7E9ED2340FF8B24FULL,
		0xC2A92D565599CADEULL,
		0x8C8B42E30F5F1ACBULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3DF670654D8F163DULL,
		0x7EE0B0466C933D1FULL,
		0xD9B808FDEF8458D7ULL,
		0xF8A1718381BADF37ULL,
		0x0B2A5EDE21F24FFFULL,
		0x231A6DC42EFD1AF5ULL,
		0x37B9AF5FDA8297B8ULL,
		0x6A925A19236C73EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE2F151B1720A82AULL,
		0xEB650C58BE1A0387ULL,
		0x8B61E5CF8876E6F5ULL,
		0xD398B04FAA1ED3E2ULL,
		0xBA17764F08486235ULL,
		0xCCBB62010ED486CBULL,
		0x13C13F77B44710ACULL,
		0xA038A1F03DDBE2B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3D9657E5AAFBE17ULL,
		0x9585BC1ED2893E98ULL,
		0x52D9ED3267F2BE22ULL,
		0x2B39C1CC2BA40CD5ULL,
		0xB13D289129BA2DCAULL,
		0xEFA10FC520299C3EULL,
		0x247890286EC58714ULL,
		0xCAAAFBE91EB79159ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x614A926AE5B002F5ULL,
		0x07F6C9E40D755CA8ULL,
		0x3AA97EE2BC11C00CULL,
		0xDA8BC21883CA265EULL,
		0xC293AB47EFFD4803ULL,
		0xCCF41BD40367922FULL,
		0xEE770DD41ED3BCA1ULL,
		0xA244A85FE42B5E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x637C866DFCF60201ULL,
		0x27BDC220E529675DULL,
		0xFC5B62398B8B13FDULL,
		0x5595474D6FDFB2B1ULL,
		0x0769A4962F7CB792ULL,
		0x2801F6E9B9C31FA4ULL,
		0xFD942DDFA6A619D4ULL,
		0x478BE4992FFC19DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02361407194600F4ULL,
		0x204B0BC4E85C3BF5ULL,
		0xC6F21CDB379AD3F1ULL,
		0x8F1E8555EC1594EFULL,
		0xC5FA0FD1C081FF91ULL,
		0xE4F5ED3DBAA48D8BULL,
		0x13E3200BB875A575ULL,
		0xE5CF4CC6CBD74750ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE1A6D9E59503A851ULL,
		0xA3BC8946AD1BC827ULL,
		0x8AF194C9370C7473ULL,
		0xDE923AD749F30FCAULL,
		0x4CF367A2A3E90F90ULL,
		0x2C25D3F28F1694F2ULL,
		0x8B4E26057EE0E197ULL,
		0xDCDD0B5575CD9363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x446D00CCA7DB93F8ULL,
		0x8DE8FF89DD0402B9ULL,
		0x23D4E0DDD274184AULL,
		0xBB4071053F0F55DAULL,
		0x52BC10337CB98B79ULL,
		0xE6F012F3D4EDFA39ULL,
		0x83F309738677D3DCULL,
		0xDC0A53E0D9051AFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5CBD92932D83BA9ULL,
		0x2E5476CF701FCA9EULL,
		0xA9257414E5786C39ULL,
		0x65D24BD276FC5A10ULL,
		0x1E4F7791DF5084E9ULL,
		0xCAD5C1015BFB6ECBULL,
		0x08BD2F76F897324BULL,
		0x00D758B5ACC8899DULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAEF32AC4866A6A85ULL,
		0x0CDC4ABC54E68CDEULL,
		0xBB6CF4F6625782DFULL,
		0x386BE75EDA9A4770ULL,
		0xF85AF99E523751D6ULL,
		0x80A03F529649FF9AULL,
		0xB1FF329D09143B78ULL,
		0xB7248D389BFF4918ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E562B9D4919C03ULL,
		0xD50BF46CAF1FA981ULL,
		0x09C331B1E20F3EFAULL,
		0x6B6D4A39D056B5B0ULL,
		0x0081327FA9126E9EULL,
		0xD803098B68765D9DULL,
		0xCAAF500C10564AE5ULL,
		0xD80A2C855535A0BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB16487D52FBF686ULL,
		0xD9D7BED0FBF9255FULL,
		0xB2AFC5478058BC25ULL,
		0x5306AD670ACCF2C0ULL,
		0xF8DBCBE1FB253F48ULL,
		0x58A336D9FE3FA207ULL,
		0x7B5062911942719DULL,
		0x6F2EA1BDCECAE9A4ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCEE94622A9669A61ULL,
		0x6313F374334EF9EDULL,
		0x1DEB30E9D3F8197BULL,
		0x9068AC7E3D3A80C6ULL,
		0x756C91DFE9B0BD7AULL,
		0xD4B0CF21251D04E6ULL,
		0x5C83A82901F35BE5ULL,
		0xFE964426534D1F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCF58E0DD9BADCCULL,
		0x5C6FF5774CDC63B0ULL,
		0x4FB4BCF7EBC47CFEULL,
		0xE228B40CF11751F0ULL,
		0x47A6736F11BCEC65ULL,
		0x262F0A2B6F7CD0D6ULL,
		0xF2BCDCB749761170ULL,
		0x6B3CAE672F07A69EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45261EC274FD37ADULL,
		0x3F7C06037F929A5DULL,
		0x525F8C1E383C6585ULL,
		0x72401872CC2DD136ULL,
		0x32CAE2B0F80C511FULL,
		0xF29FC50A4A61D430ULL,
		0xAE3F749E48854A95ULL,
		0x95AAEA417C4AB9B6ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x380ECB618F754710ULL,
		0x3D26C34ABBC92FB5ULL,
		0xEAEA809CFC82CDEEULL,
		0x5FB4C4B140D03A14ULL,
		0x4ACA6C7501F70173ULL,
		0x6F65548CEA899310ULL,
		0xD9F842CFC254DE8AULL,
		0xA08102B1408A5ADEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2A128CFE25455FULL,
		0xCC7DBB4E8A0A8D63ULL,
		0x14A205FF5181CE01ULL,
		0x92A41F116E8287DFULL,
		0x01B50A24D12B1238ULL,
		0xE70FC112C1E9C7BEULL,
		0x154076394909AFDCULL,
		0xD73973BFCABC66EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4224D9ED7150024FULL,
		0xF15B780431C3A2D6ULL,
		0xFE488563AD0303EFULL,
		0xCD10DBA02E52BDCBULL,
		0x4B7F6651D0DC134BULL,
		0x886A959E2B6054AEULL,
		0xCCB834F68B5D7156ULL,
		0x77B8710E8A363C34ULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x426B9189FB7532BDULL,
		0x5F1C5F73C8044194ULL,
		0xF71634177014C6A5ULL,
		0x63BF147E932CA212ULL,
		0x40273995F5D0D556ULL,
		0xE516A4225458BD38ULL,
		0xB61E120D6D138033ULL,
		0xAA5B2E33EE6055ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD979AD6551C287D3ULL,
		0x4D3A172443012A95ULL,
		0xB27B2916136D933CULL,
		0xF7AA7ABCE4D114AAULL,
		0x0AADD13BBF2942BCULL,
		0xA46587AB6A9597F1ULL,
		0xADE66A81D94E8C16ULL,
		0x3A11A752F313B19CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B123CECAAB7B56EULL,
		0x122648578B056B01ULL,
		0x456D1D0163795599ULL,
		0x94156EC277FDB6B8ULL,
		0x4A8AE8AE4AF997EAULL,
		0x417323893ECD2AC9ULL,
		0x1BF8788CB45D0C25ULL,
		0x904A89611D73E430ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x43E928072F57668BULL,
		0xC7FE940992EF698CULL,
		0xACD3D730054B6CEFULL,
		0xEF19DEEF9D003E35ULL,
		0x77044BC56276B278ULL,
		0xB16ADE7E568CD005ULL,
		0x80DE6693DB959BB0ULL,
		0xB6AE7F436AD8AA8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9436201CB0AFC645ULL,
		0x1C762125C87D1EBAULL,
		0xE5C0A8955DCE51E2ULL,
		0xAC6CBAF7356B8A97ULL,
		0xCA6F0323D9654ED7ULL,
		0xBFE2C3559CD93A8DULL,
		0xA769B3EECBB08F7DULL,
		0x9DECA0335BB9526FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7DF081B9FF8A0CEULL,
		0xDB88B52C5A927736ULL,
		0x49137FA558853D0DULL,
		0x43756418A86BB4A2ULL,
		0xBD6B48E6BB13FCAFULL,
		0x0E881D2BCA55EA88ULL,
		0x27B7D57D102514CDULL,
		0x2B42DF703161F8E1ULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x534F21012C1AED07ULL,
		0xBA36A55F05BC6811ULL,
		0x1E08D764CEBB6A89ULL,
		0xAB6E2C4731BE08B4ULL,
		0x9E92616897F08FFAULL,
		0x3BE37506DE39B8F4ULL,
		0x75963D67D8FBD956ULL,
		0x5DB4CE6EA246180FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C35E793CD6AF1F8ULL,
		0x55BB6BE4E6676A60ULL,
		0x90E522FF31FE929EULL,
		0x69108BE1F8D49855ULL,
		0x612D42B5BF617236ULL,
		0xC53A2F0E9CA335A3ULL,
		0xD00BB2D134E74E4CULL,
		0x68856F8A690ED4B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F7AC692E1701CFFULL,
		0xEF8DCEBBE3DB0271ULL,
		0x8EEDF59BFF45F817ULL,
		0xC27EA7A6C96A90E1ULL,
		0xFFBF23DD2891FDCCULL,
		0xFED95A08429A8D57ULL,
		0xA59D8FB6EC1C971AULL,
		0x3531A1E4CB48CCBBULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x219C83CF031D96C4ULL,
		0x69813D1E4DEF4C07ULL,
		0x26E1EB7C51B50859ULL,
		0xF620C4B08F2ED008ULL,
		0x32D9CA725E0EE83FULL,
		0xC222D67162299E45ULL,
		0x489AB0EDFBE4036BULL,
		0x91A85F2DB0AD7D07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02E378AA39831799ULL,
		0x32DA9D6C27F31659ULL,
		0x9389D9A9FA37BF72ULL,
		0xCFD4316908ABBC27ULL,
		0x70A2F1AB8BD10AB9ULL,
		0xF01A0E9B8C107774ULL,
		0x4749173F555DAE06ULL,
		0x89EBA5249F6C0EC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x237FFB653A9E815DULL,
		0x5B5BA0726A1C5A5EULL,
		0xB56832D5AB82B72BULL,
		0x39F4F5D987856C2FULL,
		0x427B3BD9D5DFE286ULL,
		0x3238D8EAEE39E931ULL,
		0x0FD3A7D2AEB9AD6DULL,
		0x1843FA092FC173C2ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x54AD71129392A8FCULL,
		0x7C38D12CA210D2C4ULL,
		0xFFA6B77F46753787ULL,
		0x6280E9ABB860CED8ULL,
		0xE575EC0920951BBAULL,
		0x3536E5A6F7651FF4ULL,
		0x6DDD20991D942841ULL,
		0xB6238205550AD511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F3F9D353254944ULL,
		0x3B6A06AF12B9D606ULL,
		0x1C24812213EEB1BAULL,
		0x72E4EA7DCC6F1270ULL,
		0x1FDDDF39366D47D6ULL,
		0xBF071184C8F31A46ULL,
		0x4194C0463924C390ULL,
		0x9155E2A2B12F61ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x835E88C1C0B7E1B8ULL,
		0x4752D783B0A904C2ULL,
		0xE382365D559B863DULL,
		0x106403D6740FDCA8ULL,
		0xFAA8333016F85C6CULL,
		0x8A31F4223F9605B2ULL,
		0x2C49E0DF24B0EBD1ULL,
		0x277660A7E425B4BCULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEB4CB729845F9C3BULL,
		0x510658B57553C0E9ULL,
		0x6A5D0C9427BA8445ULL,
		0x7B56A099475C5EBBULL,
		0x2434DC4F7A9B6669ULL,
		0x19C4553BEE76F6ECULL,
		0x87409E0BAE29AF25ULL,
		0xD8391A341DF50CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0212349178E1BF5BULL,
		0x2EC508A7D346C661ULL,
		0xB991A1E4EC41ED4EULL,
		0xFAA9CE2EBB9116C6ULL,
		0x1C51C5AF764F45A7ULL,
		0xE55292C614D9BF8FULL,
		0x1D516C19DC961A6BULL,
		0xCF07581BDF57AD13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE95E83B8FCBE2360ULL,
		0x7FC35012A6150688ULL,
		0xD3CCAD70CBFB690BULL,
		0x81FF6EB7FCCD487DULL,
		0x386519E00CD423CEULL,
		0xFC96C7FDFAAF4963ULL,
		0x9A11F21272BFB54EULL,
		0x173E422FC2A2A1BEULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1231A5157F5A56AFULL,
		0xA2F5D5F55EFF2373ULL,
		0x866C4FF19F3CE119ULL,
		0x06C1BAD71C06D4CEULL,
		0x391D486C2055B4C5ULL,
		0xD29D961E0CE239A7ULL,
		0x7D213DCABC92319EULL,
		0x8FF1F571C9E659CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF9260A2157D21D6ULL,
		0x428433BBBC562B49ULL,
		0xEFEC157F638CE319ULL,
		0xF0BC75F8BD04B4ACULL,
		0xB4D9954ABD7BB3B2ULL,
		0xE6956B7CE5045982ULL,
		0xFF1430C293CA567AULL,
		0x9CFCAD0FC0A8FD15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA3C5B76A277779ULL,
		0xE071E64EE2A9083AULL,
		0x69805A8EFCB00200ULL,
		0xF67DCF2FA1026062ULL,
		0x8DC4DD269D2E0777ULL,
		0x3408FD62E9E66025ULL,
		0x82350D082F5867E4ULL,
		0x130D587E094EA4DEULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC6A868C513483F80ULL,
		0x12E7C477380EED35ULL,
		0x2FC3D73B94937931ULL,
		0x0BF005F7F38F2CE2ULL,
		0x52E90DBFA1CC133AULL,
		0xD57BC5DFB0574DE4ULL,
		0xEAF787A95BBF2411ULL,
		0x213BEB29EF8C213CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A9F4C64FDC93FDULL,
		0x3ECBF28262D6C294ULL,
		0x87B1F576F1BF5CC5ULL,
		0x2008DF2F1F88BAD5ULL,
		0x78EA1EAC40886BBCULL,
		0x7061206A0AC12F84ULL,
		0xC685F50E1A7238C9ULL,
		0x454D9AA8FE90DFA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74019C035C94AC7DULL,
		0x2C2C36F55AD82FA1ULL,
		0xA872224D652C25F4ULL,
		0x2BF8DAD8EC079637ULL,
		0x2A031313E1447886ULL,
		0xA51AE5B5BA966260ULL,
		0x2C7272A741CD1CD8ULL,
		0x64767181111CFE94ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8FDB9272EF1E025CULL,
		0x7A7F96A946BDB517ULL,
		0x3E2AAF3BC20D5F6EULL,
		0xFF9B107D02A2BDBDULL,
		0x6EAC6A099ED97214ULL,
		0x7B1CD7C5627B4FE7ULL,
		0x860C8BB5EE7B1A98ULL,
		0x6E4D072362BED1D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BEBB5193D54D0E5ULL,
		0x89CE3DAACD696584ULL,
		0x53EB5BA15176EBA7ULL,
		0xB3B08457BED6C630ULL,
		0x277779B3F66E459BULL,
		0xC134D854A7FD5375ULL,
		0x7F1752144FAA7C05ULL,
		0x02BC44767EE35F13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA430276BD24AD2B9ULL,
		0xF3B1AB038BD4D093ULL,
		0x6DC1F49A937BB4C9ULL,
		0x4C2B942ABC747B8DULL,
		0x49DB13BA68B7378FULL,
		0xBA280F91C5861C92ULL,
		0xF91BD9A1A1D1669DULL,
		0x6CF143551C5D8ECBULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9D0A6B7E7919F7F4ULL,
		0x02E1D1ACDA7D3005ULL,
		0x778218B679DAF535ULL,
		0x40D96290B765C393ULL,
		0x71315C487C268BD0ULL,
		0x4662B2A897414E00ULL,
		0xA236A5E63873160BULL,
		0x51236136BBB29605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330BC567430720A4ULL,
		0x9106533649049B57ULL,
		0x046B4BF265BECE8FULL,
		0x82E0FF5DDF66BE7DULL,
		0x1104551AC2C98CFAULL,
		0x9317D138541B7575ULL,
		0xCB877EED64ADF52DULL,
		0x60FBD6031606FB53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE01AE193A1ED750ULL,
		0x93E7829A9379AB52ULL,
		0x73E953441C643BBAULL,
		0xC2399DCD68037DEEULL,
		0x60350952BEEF072AULL,
		0xD5756390C35A3B75ULL,
		0x69B1DB0B5CDEE326ULL,
		0x31D8B735ADB46D56ULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0DE1ECC24E5A9A83ULL,
		0x3C9D736E275B1B99ULL,
		0x4C314F69EB976501ULL,
		0x149F698518DE9368ULL,
		0x74B37F300F71FE0EULL,
		0xF8D3F2565D47FE61ULL,
		0xBA07D799F2914173ULL,
		0x78082D83A8960F58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D86711D3A79075ULL,
		0x5FBF5D348962730BULL,
		0x5D45FC5EF2B58451ULL,
		0xF02E58786D40E98EULL,
		0xBFCADEA828C143D4ULL,
		0xEA8DCC5C7BAA084FULL,
		0x28ED404907633AF8ULL,
		0xF3DBA8F1C16A4278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94398BD39DFD0AF6ULL,
		0x63222E5AAE396892ULL,
		0x1174B3371922E150ULL,
		0xE4B131FD759E7AE6ULL,
		0xCB79A19827B0BDDAULL,
		0x125E3E0A26EDF62EULL,
		0x92EA97D0F5F27B8BULL,
		0x8BD3857269FC4D20ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFEF56B5EF74AE013ULL,
		0x51D1B4CB386635ECULL,
		0x96EB28DC6F187FA4ULL,
		0xDBE6555A70F07C5CULL,
		0xF5C8206346F2340CULL,
		0xC082E14FED8958D2ULL,
		0x5BCBCF7D8AD2E5F0ULL,
		0x70A3849D29092B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4ADB76CFFCECD9ULL,
		0x7695C45A077BD726ULL,
		0xD44196295C4AA853ULL,
		0x9A339CE63E3E46DAULL,
		0x653ED906F6A20C17ULL,
		0x78DC1879324E98A7ULL,
		0x59BA50CBEAE6E796ULL,
		0xB40226F3A4BFBBA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95BFB02838B60CCAULL,
		0x274470913F1DE2CAULL,
		0x42AABEF53352D7F7ULL,
		0x41D5C9BC4ECE3A86ULL,
		0x90F6F965B050381BULL,
		0xB85EF936DFC7C075ULL,
		0x02719FB660340266ULL,
		0xC4A1A26E8DB690BDULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2D615B9B6BF11AFDULL,
		0x00E7A7D9816BB319ULL,
		0x4CCEF2561CB5F98CULL,
		0xF8CF1BE0EF3717C7ULL,
		0x871D84A408656115ULL,
		0x31E7AFB81DAE5FAEULL,
		0xBE5CC2D68B56CC21ULL,
		0x5DFEC2DEB26B3B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49753655952897BCULL,
		0x8C2D2C783964E644ULL,
		0x2D264B4C0E8523C0ULL,
		0xB5FA8BB90AF11395ULL,
		0x056A7928907BDF48ULL,
		0xEA578AADCE6FDEB5ULL,
		0xF29400E5BBE080D8ULL,
		0xF0A2FADE03EB5D81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64146DCEFED98D41ULL,
		0x8CCA8BA1B80F555DULL,
		0x61E8B91A1230DA4CULL,
		0x4D359059E5C60452ULL,
		0x8277FD8C981EBE5DULL,
		0xDBB02515D3C1811BULL,
		0x4CC8C23330B64CF9ULL,
		0xAD5C3800B18066A0ULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0AF9A9D8DD5D2542ULL,
		0x8B870381E0161555ULL,
		0x89117A0BB8D7D586ULL,
		0x576EBFE085F17D18ULL,
		0xF3926EAA2351F241ULL,
		0x3287DBA11309554FULL,
		0x5A8F634B03CFD9BDULL,
		0x7290D531D4D181C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CE4021F4E4C4A9DULL,
		0x1FE25F6AAE41022BULL,
		0xCA2D3D3BB2BFBD29ULL,
		0xFD1272F6623901C8ULL,
		0xECADADAA4779C119ULL,
		0xBB96A6851FE13C2EULL,
		0x98ED36E375017824ULL,
		0xAB08763B12617B5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x061DABC793116FDFULL,
		0x94655CEB4E57177EULL,
		0x433C47300A6868AFULL,
		0xAA7CCD16E7C87CD0ULL,
		0x1F3FC30064283358ULL,
		0x89117D240CE86961ULL,
		0xC26255A876CEA199ULL,
		0xD998A30AC6B0FA9BULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x543FEE70DCB58962ULL,
		0x09F3635A1CF1C345ULL,
		0xDBAAD02E2575D679ULL,
		0x18F643FB6A239052ULL,
		0xF617E7F2392A4E64ULL,
		0x5440FDC7E0F32B29ULL,
		0x27EF3B223062C91EULL,
		0xABD694CE3F38C630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD309DCA70CF4F735ULL,
		0x5371F61BDFF1419EULL,
		0x2682F9D73EE57FF1ULL,
		0xF26C98CF60D5E691ULL,
		0xD5E67CB561A58C8BULL,
		0x0CC1152D4158CB4FULL,
		0x526CCA2F9D498CA0ULL,
		0x9F8E4A28691257D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x873632D7D0417E57ULL,
		0x5A829541C30082DBULL,
		0xFD2829F91B90A988ULL,
		0xEA9ADB340AF676C3ULL,
		0x23F19B47588FC2EFULL,
		0x5881E8EAA1ABE066ULL,
		0x7583F10DAD2B45BEULL,
		0x3458DEE6562A91E1ULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9B4B4C1549F26043ULL,
		0xFB992F7B875FCB42ULL,
		0x83B90175EDAA98F0ULL,
		0xFE17EA4700AD2909ULL,
		0x3EFE5F403428FB54ULL,
		0xB58088F5911638A3ULL,
		0xDC13B526F885BF17ULL,
		0xC344B31F13A29EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A048B4F60C17689ULL,
		0x8EF4ACD5879325C0ULL,
		0xF0F05CF0BCA676B0ULL,
		0xCB5DD3510B516774ULL,
		0x2837009AA877FA89ULL,
		0xFFEAC46454639857ULL,
		0x4935ABCF2B254D4CULL,
		0x84AC92437D1871EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE14FC75A293316CAULL,
		0x756D83AE00CCEE82ULL,
		0x73495D85510CEE40ULL,
		0x354A39160BFC4E7DULL,
		0x16C95FDA9C5F01DDULL,
		0x4A6A4C91C575A0F4ULL,
		0x95261EE9D3A0F25BULL,
		0x47E8215C6EBAEF30ULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x18CAF52C48D35787ULL,
		0xD24CDE8A991E1027ULL,
		0xD274BB4B07D231DCULL,
		0xF364FD38A6768223ULL,
		0x3F6146933476FA4CULL,
		0x78BD4396FD6DFCD3ULL,
		0x5C33320A9C2BB209ULL,
		0x651694549218580EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF90A93983254880BULL,
		0x2DC6E6B1643F0874ULL,
		0x3C3B1E3A93017C7AULL,
		0x0CFED7FBAE88F977ULL,
		0x547071BC0FCE4ADFULL,
		0x695CD7C196697C0BULL,
		0x69179405BD961C86ULL,
		0xA59678301D89BEA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1C066B47A87DF8CULL,
		0xFF8A383BFD211853ULL,
		0xEE4FA57194D34DA6ULL,
		0xFF9A2AC308FE7B54ULL,
		0x6B11372F3BB8B093ULL,
		0x11E194576B0480D8ULL,
		0x3524A60F21BDAE8FULL,
		0xC080EC648F91E6A9ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8E600DE935C859D7ULL,
		0x0B56E1F53B8769CBULL,
		0xD26EFA0F153FF61CULL,
		0x0E659FD99243C828ULL,
		0x594DC0CC33BB292DULL,
		0xE56B0AB9BCE349D6ULL,
		0xC4D95EBE9815FC8AULL,
		0x8211DC063BA21B40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6753DEFFA2570F41ULL,
		0x5578E6406007B258ULL,
		0xA1655ECE475E5AF0ULL,
		0xE40887F58EA03441ULL,
		0x757BF4599B777FD9ULL,
		0x9C86874944552920ULL,
		0xFD6AF0C2FF397150ULL,
		0xBF7CF12A41AB4EDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE933D316979F5696ULL,
		0x5E2E07B55B80DB93ULL,
		0x730BA4C15261ACECULL,
		0xEA6D182C1CE3FC69ULL,
		0x2C363495A8CC56F4ULL,
		0x79ED8DF0F8B660F6ULL,
		0x39B3AE7C672C8DDAULL,
		0x3D6D2D2C7A09559DULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC0EAAED2D95330A6ULL,
		0x42E9CFBC23CAA18AULL,
		0x16CD10950CD69192ULL,
		0x8623E426B79EEA9BULL,
		0x1AFBB653864EE97FULL,
		0x10D0495247DE4ECDULL,
		0xDDFDF7A050A27D35ULL,
		0xE7CE88D8119B7214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB4D2977E34FC33ULL,
		0x0CE341B07ED2C1C0ULL,
		0x3C11C4ECC1D4A542ULL,
		0x96EF8EB4217AED0FULL,
		0xB02CDD07E4D7B4AFULL,
		0xA6789FA7B911938DULL,
		0x18A48A636F6138C0ULL,
		0xD19361A08D256146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA5E7C45A767CC95ULL,
		0x4E0A8E0C5D18604AULL,
		0x2ADCD479CD0234D0ULL,
		0x10CC6A9296E40794ULL,
		0xAAD76B5462995DD0ULL,
		0xB6A8D6F5FECFDD40ULL,
		0xC5597DC33FC345F5ULL,
		0x365DE9789CBE1352ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEEAF73DB99FBB211ULL,
		0x1A1BD3F7709532F7ULL,
		0xB8DDCE8B79DD5B1FULL,
		0x76E46CA1B68BFB9EULL,
		0xFFCA991A45064540ULL,
		0x52B6CCEE33491460ULL,
		0x5F668137ECBDDFB8ULL,
		0xECE64BFDBAE8C74AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5C65E6AB9563EDULL,
		0xAD28DCEC305FD0ECULL,
		0x68F6A50C08085663ULL,
		0x7F1F4337D3C36CC2ULL,
		0xFCB673937282AD6BULL,
		0xCD0D786E6F8A8A56ULL,
		0x3440DA24E79F3ED0ULL,
		0xCD5E492F0144EE32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5F3163D326ED1FCULL,
		0xB7330F1B40CAE21BULL,
		0xD02B6B8771D50D7CULL,
		0x09FB2F966548975CULL,
		0x037CEA893784E82BULL,
		0x9FBBB4805CC39E36ULL,
		0x6B265B130B22E168ULL,
		0x21B802D2BBAC2978ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6374EDCC10C14C64ULL,
		0xC53D6420DBFFEABCULL,
		0x06960AF3F47C74BDULL,
		0xEA83FF61C887656AULL,
		0xA40B338591D424BBULL,
		0xA1DA6BC8739D984CULL,
		0x7AB908C619C508C3ULL,
		0x77BB278F5CD0615FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FEAA9D3B5CFA01ULL,
		0xB2568E0576B2FB42ULL,
		0x0BDE5AB6D136CA69ULL,
		0x450FCCF7EBD12DFBULL,
		0x52A9D3F622BE2D1DULL,
		0xCC84400C5589FD8BULL,
		0x4936A8CE7963828BULL,
		0x863A7D1454FE5962ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x628A47512B9DB665ULL,
		0x776BEA25AD4D11FEULL,
		0x0D485045254ABED4ULL,
		0xAF8C339623564891ULL,
		0xF6A2E073B36A09A6ULL,
		0x6D5E2BC4261465C7ULL,
		0x338FA00860A68A48ULL,
		0xF1815A9B082E383DULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7E7CFF4A0BFDA1A6ULL,
		0x19794A5003209664ULL,
		0x5352974274492296ULL,
		0x2C3B9CA4F5DC6DA7ULL,
		0xC42179CF96293792ULL,
		0xDB6BB935199C3CB7ULL,
		0xCB1783D0B48C374EULL,
		0x865862991A0928B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30267981E9BCE6DFULL,
		0x986217438813AD56ULL,
		0x9BC2463F28D366EBULL,
		0x687E3ED4427BD417ULL,
		0xDB30861CDEFD00E7ULL,
		0x6D6A200CA7E5989BULL,
		0xDC8ED1F566E540F4ULL,
		0x6B34F8EE50790E42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E5A86CBE2414779ULL,
		0x811B5D138B333B32ULL,
		0xC890D17D5C9A447DULL,
		0x4445A270B7A7B9B0ULL,
		0x1F11FFD348D43775ULL,
		0xB6019939BE79A42CULL,
		0x17995225D26977BAULL,
		0xED6C9A774A7026FAULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDA025BE04AACC499ULL,
		0x5B8733EEFDB9CD60ULL,
		0xD28A404E9E40FFB4ULL,
		0xF0EE9D9F7B100ECBULL,
		0xDD1C97E07E48AEF6ULL,
		0x43DE3A532B9F154CULL,
		0xD5D186604E3F94D9ULL,
		0x06ECBE0569B24DECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCCA5FBABDC78087ULL,
		0xF48305CAD6C17841ULL,
		0xE5D41470797D4BF3ULL,
		0xFE2E74CCF14556ECULL,
		0xA1049F46739DAE49ULL,
		0x07647E4D2FD0854EULL,
		0xBE2C43529FB26CDEULL,
		0x33DD4E87027DB762ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06C8045AF76B441EULL,
		0xAF0436242B78B521ULL,
		0x375E543EE73DB447ULL,
		0x0EC0E9538A555827ULL,
		0x7C1808A60DD500BFULL,
		0x44BA441E044F9002ULL,
		0x6BFDC532D18DF807ULL,
		0x3531F0826BCFFA8EULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0F4AABE84592106FULL,
		0xCD05EBCDF615B280ULL,
		0x11F8CC58656C6420ULL,
		0xACB66B2AF793F3B3ULL,
		0x7E6A821C396062C6ULL,
		0x9679AE6E94CCF8DCULL,
		0xCF9CA1606B7B1CEAULL,
		0xEDDB39303F321113ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAB5EE4C16FE6BACULL,
		0xF1BDFA3534E73AF0ULL,
		0x6C0F4A18540ED912ULL,
		0x7726897C1D712790ULL,
		0xCF2B5949DD2B4C9DULL,
		0xD590F7932B2067F0ULL,
		0xDA9FEE963F7A5A40ULL,
		0xC9A03B44F059B24FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5FF45A4536C7BC3ULL,
		0x3CB811F8C2F28870ULL,
		0x7DF786403162BD32ULL,
		0xDB90E256EAE2D423ULL,
		0xB141DB55E44B2E5BULL,
		0x43E959FDBFEC9F2CULL,
		0x15034FF6540146AAULL,
		0x247B0274CF6BA35CULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x694AB78ABA9ABA78ULL,
		0xC98F4C26DD2B8A2CULL,
		0xA968A505FC9DAFCAULL,
		0xBF959D99E525900BULL,
		0x22F46CB83A54C8AFULL,
		0x7EA0DD8E177537FFULL,
		0x0897BBB8D270779BULL,
		0x2199457F0E031B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF79C8BD120BE8893ULL,
		0xBFD7D37D223DEF77ULL,
		0xEAB2EE43032D6C21ULL,
		0x407723D43F70B2E4ULL,
		0xEBAAE2B24C075FB7ULL,
		0x5D2A85D93C2D1D90ULL,
		0x9E0E3B171695E78FULL,
		0xB139CAA1C44BDEAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ED63C5B9A2432EBULL,
		0x76589F5BFF16655BULL,
		0x43DA4B46FFB0C3EBULL,
		0xFFE2BE4DDA5522EFULL,
		0xC95E8E0A76539718ULL,
		0x238A58572B582A6FULL,
		0x969980AFC4E59014ULL,
		0x90A08FDECA48C53FULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7784160E4E613603ULL,
		0x1C992A3221C4C7C6ULL,
		0x09D7EAD52D303264ULL,
		0xB3661F648923F145ULL,
		0xF1FC2A1FF72E1039ULL,
		0xF3516656E1C319DEULL,
		0x5C31619C4EC7B2F3ULL,
		0xFB16DA6D50B59826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E5DD2832BE15EABULL,
		0x06786182D1862BEEULL,
		0x5E08F1D10CD8FCB9ULL,
		0xAF7781CBC46F02A9ULL,
		0x6FE4E6274A4887E6ULL,
		0xAC68855D21AD7E78ULL,
		0x9B93173D68538F90ULL,
		0x1568610F880EAB75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49D9C48D658068A8ULL,
		0x1AE14BB0F042EC28ULL,
		0x57DF1B0421E8CEDDULL,
		0x1C119EAF4D4CF3ECULL,
		0x9E18CC38BD6697DFULL,
		0x5F39E30BC06E67A6ULL,
		0xC7A276A126943D63ULL,
		0xEE7EBB62D8BB3353ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB71CADAFE6211EA8ULL,
		0x497B874C1A9D066EULL,
		0x2D83E44DADF58006ULL,
		0x536C738C74A56C3AULL,
		0xC179C6C3369E2C25ULL,
		0x114349158992EE50ULL,
		0x257A1AB36013D8AFULL,
		0x5657B82B4AEE83E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D1AF2AD4271D305ULL,
		0x3453CF567D54BE76ULL,
		0xF2979D57F267A90DULL,
		0xD36BD8169980B283ULL,
		0xC4CB50F18A0EA539ULL,
		0x713FDC3237A57C50ULL,
		0xBDBC733DF56AEA6EULL,
		0xEC86A9DA53E602EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A065F02A450CDADULL,
		0x7D28481A67C9B818ULL,
		0xDF14791A5F92290BULL,
		0x8007AB9AED25DEB9ULL,
		0x05B29632BC90891CULL,
		0x607C9527BE379200ULL,
		0x98C6698E957932C1ULL,
		0xBAD111F11908810EULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8E125DFECDB0C427ULL,
		0x1A6103503F85C701ULL,
		0x3D4CE04BDB77D848ULL,
		0x7E570E781C8F85D3ULL,
		0x30E880EB3A162018ULL,
		0x33E5F31401F54705ULL,
		0x11E4F1D40118F156ULL,
		0xAB33A93AE832E08FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F057ABFD5CD9AD9ULL,
		0x45FEDE56DC63C4E2ULL,
		0x1A54DBB1046FF7E1ULL,
		0xEC3207798FEA872EULL,
		0x3360CC2B6D77C604ULL,
		0x55D5348D746431E5ULL,
		0x9E39D61CA55F63D9ULL,
		0x6B505096450B157EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11172741187D5EFEULL,
		0x5F9FDD06E3E603E3ULL,
		0x27183BFADF182FA9ULL,
		0x92650901936502FDULL,
		0x03884CC05761E61CULL,
		0x6630C799759176E0ULL,
		0x8FDD27C8A447928FULL,
		0xC063F9ACAD39F5F1ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2D27D9FBBB091370ULL,
		0xEE174EE8ED733C6AULL,
		0xA0D88B1805D0E785ULL,
		0x47E4127D2670C846ULL,
		0xC1DF282B7AA7E9C1ULL,
		0x6B90B382178FC205ULL,
		0xCB8275ECEB8355C6ULL,
		0xE74EBBE7D2018D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x734B9525AD926426ULL,
		0x8C242F915D822CACULL,
		0x96D34D4361223AEBULL,
		0x4E442162626FB913ULL,
		0x006AD032334BCD1FULL,
		0x698C51B98974CE47ULL,
		0x5429351521D186D1ULL,
		0x7C68326CF62EE1E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E6C4CDE169B7756ULL,
		0x62336179B0F110C6ULL,
		0x360BC65B64F2DD6EULL,
		0x09A0331F441F7155ULL,
		0xC1B5F81949EC24DEULL,
		0x021CE23B9EFB0C42ULL,
		0x9FAB40F9CA52D317ULL,
		0x9B26898B242F6CA1ULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x280BC41CDE0FA98EULL,
		0xE9642AD22EE57AA8ULL,
		0xCE063914BA020BDDULL,
		0xAB063CC1E3EC2B46ULL,
		0x3D4E46EC18D3FBFCULL,
		0xACFAB8909BF020E6ULL,
		0xE45A6D5453D3C61CULL,
		0x26327A594B932757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3CED794D5F0C87CULL,
		0xA0A7512D89A813B0ULL,
		0x605B6A88A7D1D60EULL,
		0xF11C36CBB2268AB2ULL,
		0x3750DFF18410B80FULL,
		0x153D8983CDB5869BULL,
		0x21913C697B2EC409ULL,
		0x526B7DAF434836C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBC513880BFF61F2ULL,
		0x49C37BFFA74D6918ULL,
		0xAE5D539C1DD3DDD3ULL,
		0x5A1A0A0A51CAA1F4ULL,
		0x0A1E991D9CC343F3ULL,
		0xB9C731135645A67DULL,
		0xC5CB513D28FD0215ULL,
		0x745907F608DB1191ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEE08D0165E81220AULL,
		0x2FDFEB82EF6B1D4EULL,
		0x55F0D696721CF5B3ULL,
		0x70B869EE5841152CULL,
		0x98EFEA7ED77E049DULL,
		0x475BA8D85DADB1D3ULL,
		0xC436083A244A2D2DULL,
		0xA94C12C7FB6D5EE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A65E0C1709F0BDULL,
		0x752A59E8B6E9272AULL,
		0xF410F7B4980B3DD0ULL,
		0xDFC385391D216D4AULL,
		0xBB0E069E5F62F942ULL,
		0x4A6C8EA79019748DULL,
		0xA02F7496121DC303ULL,
		0xFAFF4D3240D9C692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFAE8E1A4988D2B7ULL,
		0x5AF5B26A59823A64ULL,
		0xA1E02122EA17C863ULL,
		0xAF7BECD745607866ULL,
		0x23E1ECE0881CFDDFULL,
		0x0D37267FCDB4C55EULL,
		0x64197CAC3657EE2EULL,
		0x53B35FF5BBB4987AULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6A6843BF5FB3C60FULL,
		0x5B927893632A7590ULL,
		0x3EBBE3223A5E1E93ULL,
		0x7C29DAF87EEB7103ULL,
		0x17303EDDBBC82480ULL,
		0xD05B2032672D6C59ULL,
		0xD5AACE4CCE907DB3ULL,
		0x7390FFA323D846A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF24E9DE3BAC0FAC5ULL,
		0x5861B4FD0672E775ULL,
		0x22FBAC8AF45282D0ULL,
		0x51915D4118C3E9D8ULL,
		0x878374B332D3A763ULL,
		0xA7BCFA6A039367C4ULL,
		0x7A631E57683911FFULL,
		0x76CB4E2ABAD24BFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9826DE5CE5733CCAULL,
		0x03F3CC6E655892E5ULL,
		0x1C404FA8CE0C9C43ULL,
		0x2DB887B9662898DBULL,
		0x90B34A6E891B83E3ULL,
		0x77E7DA5864BE0B9DULL,
		0xAFC9D01BA6A96C4CULL,
		0x055BB189990A0D5EULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAD4140EB9C2B7CD3ULL,
		0x30AC54895D710ACAULL,
		0x91AC0B08CE01EC64ULL,
		0x06F290BF3A3AB470ULL,
		0xC3EF5CE1CAB4FAB4ULL,
		0xB5F45F9F227E3A77ULL,
		0xB2670A03742BD003ULL,
		0xB77420D5FD5AEE66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8AF25C16C26E1AAULL,
		0xC954D71F995D0A4FULL,
		0x9E6D8F26E09678D6ULL,
		0x0067079CC8AEFEA3ULL,
		0xECDAE102F818E0F2ULL,
		0xE65411C6058400F7ULL,
		0xCDD9A31D5A9CFCC4ULL,
		0x2E26F30A4CA849AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55EE652AF00D9D79ULL,
		0xF9F88396C42C0085ULL,
		0x0FC1842E2E9794B2ULL,
		0x06959723F2944AD3ULL,
		0x2F35BDE332AC1A46ULL,
		0x53A04E5927FA3A80ULL,
		0x7FBEA91E2EB72CC7ULL,
		0x9952D3DFB1F2A7C8ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x37485CB99437888EULL,
		0xF0386724F5E884AFULL,
		0xF85D36B4E03453BDULL,
		0x688F9DB2561CCACCULL,
		0xA0B5641C8AD50698ULL,
		0x3A07C4B1BA9AC088ULL,
		0x77D13FE3C3337A3DULL,
		0x0D322D00B26E86ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DBA6C497A8A8D30ULL,
		0x34F8683586E8A05EULL,
		0x5293446A48D950F6ULL,
		0xFF2B83C9C5C1A051ULL,
		0x996C5E72577B64D7ULL,
		0x885153E42A1487E2ULL,
		0x067E69596B072367ULL,
		0x87BF599605BD6786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAF230F0EEBD05BEULL,
		0xC4C00F11730024F1ULL,
		0xAACE72DEA8ED034BULL,
		0x97A41E7B93DD6A9DULL,
		0x39D93A6EDDAE624FULL,
		0xB2569755908E476AULL,
		0x71AF56BAA834595AULL,
		0x8A8D7496B7D3E12DULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC6D1515BC113A164ULL,
		0xEA45B0B76BF0BDEDULL,
		0xA97BE1A5B121C280ULL,
		0xC862FB3508E59592ULL,
		0xE0926651D08B5B95ULL,
		0xE97368F12D2AB4E9ULL,
		0x6C54EAAE734E0711ULL,
		0x6E24FE46214F44D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33022649CFBA62E0ULL,
		0xA45366BAE5DA770EULL,
		0x0EE8F91863BD919CULL,
		0x490E8A162FA28BE9ULL,
		0x1B9295C367492400ULL,
		0xF4506D56C8F719C2ULL,
		0x04C5B81F9F812E82ULL,
		0x4901E3D25C260696ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5D377120EA9C384ULL,
		0x4E16D60D8E2ACAE3ULL,
		0xA79318BDD29C531CULL,
		0x816C712327471E7BULL,
		0xFB00F392B7C27F95ULL,
		0x1D2305A7E5DDAD2BULL,
		0x689152B1ECCF2993ULL,
		0x27251D947D694244ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x40439F3EE3F52741ULL,
		0xFA7BBEE917005036ULL,
		0x96F3F85A8476F2C9ULL,
		0x406E3BA0B0F0C812ULL,
		0x0E2DA07F18B3F0C0ULL,
		0xCA0C27697C49D190ULL,
		0xA529F1F89F1F83DAULL,
		0x458945144FEEBB29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D0E9DB01685ABEBULL,
		0x4D649946B9D12845ULL,
		0x59F9C0A40AB96C7BULL,
		0x5AB53BE6F411DC65ULL,
		0x2ED92BFA9FB64E36ULL,
		0xE339860B6DB31E4AULL,
		0xC852C04A86BA2285ULL,
		0xBEA6C6C33DB9667CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD4D028EF5708CAAULL,
		0xB71F27AFAED17873ULL,
		0xCF0A38FE8ECF9EB2ULL,
		0x1ADB004644E11477ULL,
		0x20F48B858705BEF6ULL,
		0x2935A16211FACFDAULL,
		0x6D7B31B219A5A15FULL,
		0xFB2F83D77257DD55ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x927AD9C31872046EULL,
		0x15E11BA8A496D7FAULL,
		0x73B411D612930F20ULL,
		0x1C7E4FD43292474DULL,
		0x1BEEFDCE3E1E1F42ULL,
		0xB3F090055178D45CULL,
		0x9EA07959BFF0642AULL,
		0xA1910CD73D2B1447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA888E48408E3A84BULL,
		0x961C80A7F6BEA2A3ULL,
		0xA698176924E9715EULL,
		0x0CE43EE2BDB78849ULL,
		0x7FB63321A4376055ULL,
		0xF1D69CB09BD63801ULL,
		0xDF4B35B91589D5CAULL,
		0x0DB03F445F7F45D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AF23D471091AC25ULL,
		0x83FD9B0F52287559ULL,
		0xD52C06BF367A7E7EULL,
		0x109A71368F25CF04ULL,
		0x6458CEEF9A297F17ULL,
		0x42260CB5CAAEEC5DULL,
		0x41EB4CE0AA79B1E0ULL,
		0xAC21339362545195ULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB4FDEA47B1D0932CULL,
		0x6372B46C6D3D9B3CULL,
		0x911351645D589700ULL,
		0xDD3433FBF20B4B05ULL,
		0x5AE37197BE39AC6EULL,
		0x2C8DB8AEF85303E0ULL,
		0x4210C1EE2C4311D0ULL,
		0x401F8BC180FAEB0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x982E4E8454468E1BULL,
		0xAA344A286D438DC7ULL,
		0x979B11C8471E59F8ULL,
		0xFC30ACE1AB653065ULL,
		0xDB183FD98073FED3ULL,
		0x09B4BD39B8F8E3C4ULL,
		0xCC08C430B3322477ULL,
		0xBBD52067437BBCB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CD3A4C3E5961D37ULL,
		0xC946FE44007E16FBULL,
		0x068840AC1A46CEF8ULL,
		0x21049F1A596E7B60ULL,
		0x81FB4E4E3E4A52BDULL,
		0x2539059740ABE024ULL,
		0x8E1805DE9F7135A7ULL,
		0xFBCAABA6C38157BDULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x740FB99D330134C0ULL,
		0x082CF4B36D2EE982ULL,
		0x533B7F7C5E6AD34BULL,
		0xD574525D51811B19ULL,
		0x6AF62FE9DA9CE3ADULL,
		0x8DEB29CD3621BF26ULL,
		0x4B6132C4289FB2DAULL,
		0x5D9CAA87ACA431A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DE4CEC602FC96E8ULL,
		0x94A9DEA27CAEBFDDULL,
		0x088202D734257127ULL,
		0x3BC66E3C71901744ULL,
		0x3A8694D99886E961ULL,
		0x0DD05F2866200C4CULL,
		0x5376AE4CE0E91F9EULL,
		0x327636A1C266EA7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9EB775B31FDA228ULL,
		0x9C852A111180565FULL,
		0x5BB97DAB6A4FA26CULL,
		0xEEB23C6120110C5DULL,
		0x5070BB30421A0ACCULL,
		0x803B76E55001B36AULL,
		0x18179C88C876AD44ULL,
		0x6FEA9C266EC2DBD8ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF2BA83D735C9089ULL,
		0xF8B8A2CEB081B8A2ULL,
		0x3346B1DE59139B6EULL,
		0x8488F6E3C78DFB39ULL,
		0x07FD4B926A103E38ULL,
		0x2431FA0795777888ULL,
		0x5A21BED8016D9F92ULL,
		0xB75C51F416C5566FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D8F22EAEF913ECULL,
		0x98E54582153C0E79ULL,
		0x7D413D64EFB4A565ULL,
		0x200D7917108D53C9ULL,
		0xE1283E57631CE9B0ULL,
		0x8E1B83E223674303ULL,
		0xAAAC28C8DA8E7FA3ULL,
		0xD47F9097DE1BBAA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DF35A13DDA58365ULL,
		0x605DE74CA5BDB6DBULL,
		0x4E078CBAB6A73E0BULL,
		0xA4858FF4D700A8F0ULL,
		0xE6D575C5090CD788ULL,
		0xAA2A79E5B6103B8BULL,
		0xF08D9610DBE3E031ULL,
		0x6323C163C8DEECCAULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCEAFF691B363040BULL,
		0x9E8029787C9192EFULL,
		0x37595E4480BAB86CULL,
		0xB408EDA27230C47CULL,
		0x825DC6A1683CA402ULL,
		0xBFA2D16C085B0018ULL,
		0xA3FD00F6A073ECE5ULL,
		0x32F9E3A3BBFCEE02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98783B31E765ABADULL,
		0x97029DD903DD893CULL,
		0xA722B44442CE7BDFULL,
		0xC0C9FFFEAFAA38FDULL,
		0x9F399F87076731FDULL,
		0xC62674F6BE5D0DA3ULL,
		0xD3C1F743EBCD2A59ULL,
		0x9FD75C0BAC341ABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56D7CDA05406AFA6ULL,
		0x0982B4A17F4C1BD3ULL,
		0x907BEA00C274C3B3ULL,
		0x74C1125CDD9AFC81ULL,
		0x1D6459266F5B95FFULL,
		0x7984A59AB6060DBBULL,
		0x703CF7B54BBEC6BCULL,
		0xAD2EBFA817C8F4B8ULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD0CD14BACE5AD4DDULL,
		0x038D326C3A521A80ULL,
		0x67CA89AEE056AC14ULL,
		0x52C4E09C260D5449ULL,
		0x14E0C7EBAE605942ULL,
		0x766D7A838910A342ULL,
		0xDB19114BB18FE1B4ULL,
		0x47646D82F91EE072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2E284BE4C505956ULL,
		0xC5A9057691A1E7A9ULL,
		0x619CAA91E771C56AULL,
		0xD4276881B5B55B11ULL,
		0x77108F99FD2F9C7AULL,
		0x29B3A1951ACD77FDULL,
		0x6019AD7033C8D616ULL,
		0x9B2A509AE0E68F6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x122F9004820A8D8BULL,
		0xC624371AABF3FD29ULL,
		0x0656233F0727697EULL,
		0x86E3881D93B80F58ULL,
		0x63F04872534FC538ULL,
		0x5FDEDB1693DDD4BFULL,
		0xBB00BC3B824737A2ULL,
		0xDC4E3D1819F86F1FULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0A70E9BB4E9D6B84ULL,
		0xE96AE630A3B27D8BULL,
		0xB29DC14FF42510ACULL,
		0x1D76F1173BA7DAFDULL,
		0x5DD94DCC539F260BULL,
		0x98236CB4016CA463ULL,
		0x27ED948EEA9A6E37ULL,
		0xA69938B7A2615503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D72B25BC62AF37ULL,
		0x7BE22786A008B132ULL,
		0xD9FFE2A55489C242ULL,
		0xB6F985EDB061728DULL,
		0xC124E61FB98802B2ULL,
		0x4219220E440050FAULL,
		0x945AEFD65C5E7FD8ULL,
		0xFB9CFB4C7182E74FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EA7C29EF2FFC4B3ULL,
		0x9288C1B603BACCB9ULL,
		0x6B6223EAA0ACD2EEULL,
		0xAB8F74FA8BC6A870ULL,
		0x9CFDABD3EA1724B9ULL,
		0xDA3A4EBA456CF499ULL,
		0xB3B77B58B6C411EFULL,
		0x5D05C3FBD3E3B24CULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBFFD580092182CE8ULL,
		0x26DB498C1A041846ULL,
		0x6F1F447EEC26DF50ULL,
		0xE5660FBF79F747B7ULL,
		0xA58BCD5EE54454A2ULL,
		0x164E5A19FEEB0BCAULL,
		0x0FF5E5DA220733ECULL,
		0x07FFE08F8FB407CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ECA4AC53004A555ULL,
		0xECA4406C11D5AEA4ULL,
		0x5ED9D9D23ED42635ULL,
		0x8320E2788FFB42E0ULL,
		0xD5D2D6887EEB3237ULL,
		0xA946234A61CD4D3BULL,
		0x994990EEBCE54F32ULL,
		0xEDD453CA111C664EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB13712C5A21C89BDULL,
		0xCA7F09E00BD1B6E2ULL,
		0x31C69DACD2F2F965ULL,
		0x6646EDC7F60C0557ULL,
		0x70591BD69BAF6695ULL,
		0xBF0879539F2646F1ULL,
		0x96BC75349EE27CDEULL,
		0xEA2BB3459EA86185ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD6FA3D0669E84E8AULL,
		0xF52C0CE637463AF4ULL,
		0x0CAB91C5887D96D0ULL,
		0xFFBC34621F76B780ULL,
		0xFA71C49600E7D87CULL,
		0x2F0371B5656D5064ULL,
		0x9A6E54F8435B5CB3ULL,
		0xDE882E2631485568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE44FD83CF826661DULL,
		0x944B3FC59DC3BA75ULL,
		0xA0ECE323FCD85EA0ULL,
		0x8A7700DBE7B5D89FULL,
		0xB47DCEF48EF2D1EBULL,
		0x286F81BCAC65E07CULL,
		0x55D83E49C3BB73F0ULL,
		0xAA8EBCF104203141ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32B5E53A91CE2897ULL,
		0x61673323AA858081ULL,
		0xAC4772E674A5C870ULL,
		0x75CB34B9F8C36F1FULL,
		0x4E0C0A628E150997ULL,
		0x076CF009C908B018ULL,
		0xCFB66AB180E02F43ULL,
		0x740692D735686429ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x22C43F96311150FCULL,
		0x493E14480F63ED0DULL,
		0xE6ED3E2BB1F81A40ULL,
		0x3DF4095FC578176DULL,
		0x60845DD86F19AE52ULL,
		0x4C246DC16EACCF01ULL,
		0xE65E474B529BED5EULL,
		0x718F7F0EC35A3D0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC2955B98C75E19ULL,
		0xDBE7DC9AB552CBF4ULL,
		0x812789BF61866B08ULL,
		0xAA05F3A75C52AAF7ULL,
		0x5A71A3EFCDB418DDULL,
		0x6F5F3C0224736B7AULL,
		0x7DAB36C3F90D21C4ULL,
		0x885A7577F5B30F26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D06AACDA9D60EE5ULL,
		0x92D9C8D2BA3126F9ULL,
		0x67CAB794D07E7148ULL,
		0x97F1FAF8992ABD9AULL,
		0x3AF5FE37A2ADB68FULL,
		0x237B51C34ADFA47BULL,
		0x9BF57188AB96CC9AULL,
		0xF9D50A7936E9322DULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x83B4C25B7623952CULL,
		0x6FF238685E38095AULL,
		0x6409DF314923FC8FULL,
		0x5457622B79199089ULL,
		0x766B23DC5D4C9F34ULL,
		0x0E8FD4CC1C25D8FFULL,
		0xAD51584A39EAABF7ULL,
		0x2A4A4B7788BE8499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x830DAF6D756143FCULL,
		0x9DD5ED2DD754BB12ULL,
		0x3E702C9B1540EC44ULL,
		0x57874C2EF5F85A3AULL,
		0x06FC7CA0A83B5A12ULL,
		0x5DA4DA9688ECF599ULL,
		0x6E33E89E6F5CFB15ULL,
		0xE3A51BF5DDC8FE24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00B96D360342D6D0ULL,
		0xF227D545896CB248ULL,
		0x5A79F3AA5C6310CBULL,
		0x03D02E058CE1CAB3ULL,
		0x70975F7CF577C526ULL,
		0x532B0E5A94C92D66ULL,
		0xC362B0D456B650E2ULL,
		0xC9EF508255767ABDULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x07E609A7A4EE0D2EULL,
		0xA598C64829BD757AULL,
		0x3FF1E55D27B6EB45ULL,
		0x6130CFAB2B0E2761ULL,
		0xF3AA1A2D0C2AF968ULL,
		0xD7E7DA7ABED603E9ULL,
		0xED5BB646999A8950ULL,
		0xC48107800358CBF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8717FA6AC8350A94ULL,
		0x8F060BC48FECDA59ULL,
		0xEFA9A64CCFE2E389ULL,
		0xCB25FA1191C9FCA9ULL,
		0x773B41E39C4A23B0ULL,
		0xB3EA378468F50D8BULL,
		0xDE884CFE8F61F917ULL,
		0x7E49AD5098BBFA02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80F1F3CD6CDB07BAULL,
		0x2A9ECD8CA651AF23ULL,
		0xD0584311E85408CCULL,
		0xAA1535BABAC7DBC8ULL,
		0x84915BCE9060DAD8ULL,
		0x640DEDFED6230E62ULL,
		0x33D3FAB816FB7047ULL,
		0xBAC8AAD09BE331F1ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB04E714205A35BE0ULL,
		0x2023F6D20EFB5A0CULL,
		0x61FDBCAF4A539BA6ULL,
		0xB8FDDED1595CF428ULL,
		0xEDC114371AD023B5ULL,
		0xF98B82AA4F64B699ULL,
		0x2DA5DC1B093EA01AULL,
		0x9F3B045F7B1E32E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03680227A5743916ULL,
		0x8853DAF1CB29935DULL,
		0x7AE54CAFCDD95233ULL,
		0x6705BEDA53AA2BF6ULL,
		0x159EA1DF4CC4C8D8ULL,
		0x89465014A18355BFULL,
		0xC5E0962FB37A516BULL,
		0xF602D9E4DA17F1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3267365A0D762F6ULL,
		0xA8702C23C5D2C951ULL,
		0x1B18F000878AC995ULL,
		0xDFF8600B0AF6DFDEULL,
		0xF85FB5E85614EB6DULL,
		0x70CDD2BEEEE7E326ULL,
		0xE8454A34BA44F171ULL,
		0x6939DDBBA109C332ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6DD115048F8A4DAEULL,
		0xD5AC1B7C0F755D46ULL,
		0xCCC2CCC361B06F84ULL,
		0xD05735F506DFF99BULL,
		0xD0BF9209ED1496FFULL,
		0x26CA66BF48F31310ULL,
		0x065266EFB89F1A92ULL,
		0x06357200E00E7E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9961ED8979E693C6ULL,
		0x41CC7C8F76DBC1DDULL,
		0x83B2A00BC567263CULL,
		0xB46167105909B095ULL,
		0xBA345A0DA5B4FF9CULL,
		0x34701E1329B73F39ULL,
		0xF6FAE09DC9E89577ULL,
		0x1C203DF16217C60EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4B0F88DF66CDE68ULL,
		0x946067F379AE9C9BULL,
		0x4F706CC8A4D749B8ULL,
		0x643652E55FD6490EULL,
		0x6A8BC80448A06963ULL,
		0x12BA78AC61442C29ULL,
		0xF0A8867271778FE5ULL,
		0x1A154FF18219B822ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x515F9B794C02CFB2ULL,
		0x65EBE87D7F7605EEULL,
		0xB75153DB80F31E9BULL,
		0xE7CE5B2EF425615EULL,
		0x308BFD6DB70F5314ULL,
		0xB1DC160F517F61A7ULL,
		0x8C8ED501CCB4A956ULL,
		0x210E831F6D1F6902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB460BE5AA3555E69ULL,
		0x423D65903FF9E475ULL,
		0xB01E3DCA5F1489F4ULL,
		0xFC760F24826310EDULL,
		0x2996607BB85799B9ULL,
		0xCEEC1CFD831BB42DULL,
		0xB97649BE7E6B1D3CULL,
		0x6BA82D9B1E70DBADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE53F2523EF5791DBULL,
		0x27D68DED408FE19BULL,
		0x074F6E11DFE7976FULL,
		0x1BB8540A764671B3ULL,
		0x191D9D160F58CAADULL,
		0x7F300AF2D264D58AULL,
		0x35F89CBFB2DFB46AULL,
		0x4AA6AE84736FB2AFULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7B2AC2BE69557518ULL,
		0x4AC5BDEAFD724A98ULL,
		0xF33A515663B51A06ULL,
		0x36D339506AE7E6C6ULL,
		0xE02773C409399B81ULL,
		0xB54AF9E6CD731053ULL,
		0x6343E683F43E83EBULL,
		0x1D6767D963CAAF4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8418463EF0B0B752ULL,
		0x3225C26F84B43C78ULL,
		0x5401E8FA4CCB9D6CULL,
		0x0AA42373E5C20BE6ULL,
		0xF032FC0A0CCD7AA6ULL,
		0x824D540081ED03CCULL,
		0xCCE3098C67B24DCAULL,
		0x87E5C23F46DFDC94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF32848099E5C24AULL,
		0x78E07F8579C676E0ULL,
		0xA73BB9AC2F7E876AULL,
		0x3C771A238F25ED20ULL,
		0x10158FCE05F4E127ULL,
		0x3707ADE64C9E139FULL,
		0xAFA0EF0F938CCE21ULL,
		0x9A82A5E6251573DFULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD5889727967DFBD5ULL,
		0x8CAE432A94C3440EULL,
		0x6CBEB3BE66F5F784ULL,
		0x84FB457A563B0442ULL,
		0x8A58B4A7913F43C5ULL,
		0x963DDDEA661FEA05ULL,
		0x8DD3FB9C5918A34AULL,
		0x9EDD9D07AB72FDDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA102DF12BA2A07ULL,
		0x84F300CCC55EE266ULL,
		0xA336D108078E07D9ULL,
		0xFAF5F682DE245A62ULL,
		0xA3733EE1017323F2ULL,
		0x1F0C4002192FE33CULL,
		0x27E232867FCC1E4BULL,
		0x080BE58553D2E04EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF2995F884C7D1D2ULL,
		0x085D43E6519DA668ULL,
		0xCF8862B6617BF05DULL,
		0x7E0EB3F8881F5E20ULL,
		0x292B8A46904C6037ULL,
		0x89319DE87F300939ULL,
		0xAA31C91A26D4BD01ULL,
		0x96D67882F8A01D92ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9EDE2C0FCABD5555ULL,
		0x086F1BDF396E0B7FULL,
		0x48E8AC3E9B8388F8ULL,
		0x0F1E35C4DD95EA30ULL,
		0xC6688026DD2A3064ULL,
		0x94345839625BAB50ULL,
		0xDECB43701928E8A6ULL,
		0xFDC31A6D1CD65026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC372A1A223DF0717ULL,
		0xADFBB2BE490B9F34ULL,
		0x8DF9FBE56D6E2DC8ULL,
		0x6C6DDD5D65D80BB1ULL,
		0x2638AC92D5B60410ULL,
		0x43F1C8C88C100F94ULL,
		0xCEF1421EB415B14EULL,
		0xBD58A6938AEFCC63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DAC8DADE9625242ULL,
		0xA594A9617065944BULL,
		0xC51157DBF6EDA530ULL,
		0x6373E899B84DE181ULL,
		0xE0502CB4089C3474ULL,
		0xD7C590F1EE4BA4C4ULL,
		0x103A016EAD3D59E8ULL,
		0x409BBCFE96399C45ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5BBDB049587163EULL,
		0x3F4E93BFFDF0077EULL,
		0x8443EB0C65479197ULL,
		0xCDF3EEF48FA0B5ACULL,
		0x6E92FE39685E05ACULL,
		0x523FE795EFDF01F8ULL,
		0xA020495B48ABA1FAULL,
		0xB5C8B5D365BCBFECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582A5F1D7F911CE3ULL,
		0xF38B18912749C289ULL,
		0x667A4EE20F3A9A5BULL,
		0xF8A5F96700DF712FULL,
		0xC630FBDF653DFD5AULL,
		0x65EF3FDE2ACC6557ULL,
		0xF5439F4660E984CEULL,
		0x7FD6D7D6C9739E99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD918419EA160ADDULL,
		0xCCC58B2EDAB9C5F7ULL,
		0xE239A5EE6A7D0BCCULL,
		0x355617938F7FC483ULL,
		0xA8A205E60D63F8F6ULL,
		0x37D0D84BC51364AFULL,
		0x5563D61D28422534ULL,
		0xCA1E6205ACCF2175ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x50476765BA56C139ULL,
		0x7F57323E31130B00ULL,
		0xF8443A1A07F68341ULL,
		0xD8E10A6E682B02B5ULL,
		0x89440B3D9F07D77EULL,
		0x82CAB9AFA2F5C338ULL,
		0xD671B59C728A8A03ULL,
		0x675473702FB54E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52158740FCA836FFULL,
		0x1986F2E8A6626428ULL,
		0x464D18F91BEC6E5BULL,
		0x0F7F7BB81996CA25ULL,
		0x83F9AA2A252A9ECFULL,
		0x96CC7B783CFBEA19ULL,
		0xDB8DA7FAEB6F7812ULL,
		0xDC62761D05E2EDA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0252E02546FEF7C6ULL,
		0x66D1C0D697716F28ULL,
		0xBE0922E31C1AED1AULL,
		0xD79E71D671BDC890ULL,
		0x0ABDA117BA2D49B1ULL,
		0x1406C2D79E0E2921ULL,
		0x0DFC126699E5F211ULL,
		0xBB36056D2A57A3FDULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7A74020194E7CCBDULL,
		0x1EEDCCC5D42CCBFFULL,
		0xBA0FEA8A1469D084ULL,
		0x72A24EA572B07896ULL,
		0xBB1431DAA2A2F03DULL,
		0x5E47AF3653AA8161ULL,
		0xE7CDB099A6C23663ULL,
		0x50592B0F128FA8F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x237B67414C8F1EADULL,
		0x31B801334485CDBDULL,
		0x232F2EA3ED70021DULL,
		0x98FC5DE3C4B4A743ULL,
		0x7C088F6685027BF0ULL,
		0xC6B08F745E26C507ULL,
		0x0E7D1E5162445C24ULL,
		0x5029BE026CACB447ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x590F6540D868D210ULL,
		0x2F55CDF690A90642ULL,
		0x9920C429F919D299ULL,
		0xEA5E1346B604DFD5ULL,
		0xC71CBEBC27A08BCDULL,
		0x98F720420D8C4466ULL,
		0xE9B0AEC8C4866A47ULL,
		0x0070950D7E231CB4ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2AE4CFF00B893F0FULL,
		0xFC42EA7D420B1369ULL,
		0x93644BFD555B09EFULL,
		0x1A19C686A6F2C80DULL,
		0xE888A941FA8A21E2ULL,
		0x04E7A23A7DACA255ULL,
		0x5EE7597CEEFBFDE8ULL,
		0xE0A9EB1854DF59CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B103DA594CBF196ULL,
		0xAA63FF4517830CA9ULL,
		0xFF272FBEB61B679DULL,
		0x022AB4BE7F08CC14ULL,
		0x3EB51A460E7788B3ULL,
		0x0308A319F96C86F9ULL,
		0xB8BD630AE9BC1036ULL,
		0xA068545716380C38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1F4F2559F42CE99ULL,
		0x5621153855881FC0ULL,
		0x6C436443E3406E72ULL,
		0x18337238D9FA0419ULL,
		0xD63DB307F4FDA951ULL,
		0x07EF012384C024ACULL,
		0xE65A3A760747EDDEULL,
		0x40C1BF4F42E755F7ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8D6547DA86D37D48ULL,
		0x948328B30DFEA9CAULL,
		0x1C2FEA16638ED92CULL,
		0xE9D3DA763D005474ULL,
		0x195954825B40FF3DULL,
		0x557476407C2410C3ULL,
		0x349B5A9AC51A2383ULL,
		0x10FFE97437F6C957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574D9DE22013606CULL,
		0x044CD131BA213878ULL,
		0x2A3CC63718D78B03ULL,
		0x1E6163D19871D35AULL,
		0x13C6CDCDA0639CDDULL,
		0xE171DE6DD94B5B84ULL,
		0xB2EAD362A09BFD41ULL,
		0xA380F46F2D36BC46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA28DA38A6C01D24ULL,
		0x90CFF982B7DF91B2ULL,
		0x36132C217B59522FULL,
		0xF7B2B9A7A571872EULL,
		0x0A9F994FFB2363E0ULL,
		0xB405A82DA56F4B47ULL,
		0x867189F86581DEC2ULL,
		0xB37F1D1B1AC07511ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x10995457B11E8AF6ULL,
		0xF2B58DA3497CD9CDULL,
		0x8C72441E8DBAC878ULL,
		0x9C81192B67B58466ULL,
		0xC2F92556A3A8737CULL,
		0x707DCA5C475FBCA1ULL,
		0xA8E877E9ECC941BBULL,
		0x474F2476969A6F07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3EFA097587860EBULL,
		0x6592BE25CFA3BA34ULL,
		0x37488E9BF761F4E6ULL,
		0x7EA367D46068A4F3ULL,
		0x775F25F293F2F6EBULL,
		0xF2493449EAA7ACD4ULL,
		0xA4536414D70042F0ULL,
		0xADCC2BB850C81474ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC376F4C0E966EA1DULL,
		0x9727338686DF63F9ULL,
		0xBB3ACA857ADB3C9EULL,
		0xE2227EFF07DD2095ULL,
		0xB5A600A4305A8597ULL,
		0x8234FE15ADF81075ULL,
		0x0CBB13FD3BC9034BULL,
		0xEA830FCEC6527B73ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB97E4EC0A712A0A4ULL,
		0x0E4108DC0F3C9C04ULL,
		0x76F1A19AFBD41A8BULL,
		0xBB2EC488E897604EULL,
		0x27299DCC834672B1ULL,
		0x6EBCBC54EA5786A0ULL,
		0xCB2CD416A143E1BCULL,
		0x99E5CBF092A74CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFEDB6AB061A3009ULL,
		0x004465B1A46C9481ULL,
		0x736F4FC891AD3D72ULL,
		0xAF3A10B048B0D8BAULL,
		0x81313388674261ABULL,
		0xDF3960D185D8C5F5ULL,
		0x643877C4B09D5BBDULL,
		0xDB6F9F31DF9A3076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5693F86BA10890ADULL,
		0x0E056D6DAB500885ULL,
		0x059EEE526A7927F9ULL,
		0x1414D438A027B8F4ULL,
		0xA618AE44E404131AULL,
		0xB185DC856F8F4355ULL,
		0xAF14A3D211DEBA01ULL,
		0x428A54C14D3D7CDDULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAE2774F14BFEED97ULL,
		0x87E71434D48123EBULL,
		0xF137A271FAB77D75ULL,
		0x0AFBE2E936FF5F17ULL,
		0x5800BC2A08696121ULL,
		0x9426BB89D333B5B1ULL,
		0x9096C5C97EFB7D18ULL,
		0xB5A70A68CD36EF7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6330D3530ECA472ULL,
		0x853F28938B87CCF5ULL,
		0x6B2F3E9A6066DFFAULL,
		0x4EDBFF1C05579BCAULL,
		0x20D2F279A2672B71ULL,
		0x96CCEFAEF0137314ULL,
		0x078A940BD36E983BULL,
		0x6D21EE6B6A2005ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x181479C47B1249E5ULL,
		0x02D83CA75F06EF1EULL,
		0x9A189CEB9AD1A28FULL,
		0x44201DF533A8C4DDULL,
		0x78D24E53AA0E4A50ULL,
		0x02EA54272320C6A5ULL,
		0x971C51C2AD95E523ULL,
		0xD886E403A716EAD3ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x06CE78A7E9A61B77ULL,
		0x2A2A5696B4E8A426ULL,
		0x7814B34B267CA406ULL,
		0x8A0C82574BC20ABBULL,
		0x99D8B7FDC1A34AC8ULL,
		0xA2D3FDACDE4267CBULL,
		0xE2D7C767E27491D8ULL,
		0x89527C0B9B5495DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024B8ECCC76D82ADULL,
		0x26809350CD7A202FULL,
		0x9BE462657EBBBABEULL,
		0xD93834D7EECCEDC9ULL,
		0x4CF88C0F8F3DD5BBULL,
		0xD1B2471F0F25E1A2ULL,
		0xB060D2AC4B6A42DDULL,
		0xEFD5ADDF4C18343CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0485F66B2ECB99DAULL,
		0x0CAAC5C679928409ULL,
		0xE3F0D12E58C71EB8ULL,
		0x5334B680A50EE772ULL,
		0xD5203BF24E9E9F73ULL,
		0x7361BAB3D1678669ULL,
		0x52B715CBA91ED305ULL,
		0x6687D1D4D74CA1E1ULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4B0E3F37C9B02F47ULL,
		0x99286E47183B0BE9ULL,
		0x849BFF949C23C5A6ULL,
		0x01B7027525EE5A14ULL,
		0x10D94FE1E56BF1ADULL,
		0xB09064742F48ECDBULL,
		0xFBB36F6AFEA5D6E8ULL,
		0x4E121A2FF1DABD4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B5D3AF70996859ULL,
		0xB66F3EFBD0EE5AB4ULL,
		0xDF8B86103EE7B091ULL,
		0x5D3F262587DABD64ULL,
		0xAFD2A18C946DFEF6ULL,
		0x53B3046718F2FD9AULL,
		0x22D4BA2672FF8D2AULL,
		0xB45F95E19CCFF429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FBBEC98B929471EULL,
		0x2F4750BCC8D5515DULL,
		0x5B107984A2C47537ULL,
		0x5C882450A234E770ULL,
		0xBF0BEE6D71060F5BULL,
		0xE323601337BA1141ULL,
		0xD967D54C8C5A5BC2ULL,
		0xFA4D8FCE6D154967ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B61CF3F14BB81B7ULL,
		0xC9805AC651EB26D9ULL,
		0x80A58FFB1BA4E22CULL,
		0x96C775E39627A50EULL,
		0xE47C9115079D12BFULL,
		0x2A82F1EF6AED56A8ULL,
		0xC63B719D86A41FDCULL,
		0x745D591D9E4CDB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F9AFECF2DC0021ULL,
		0x6FED0C89FD781BE6ULL,
		0xEB630C48CD5ACFFFULL,
		0x811500DD99462D54ULL,
		0xB08968682759671DULL,
		0x07BC0A3DA31A9396ULL,
		0xF066D715E0A2F2E4ULL,
		0x6845845CB5D99312ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F9860D3E6678196ULL,
		0xA66D564FAC933D3FULL,
		0x6BC683B3D6FE2DD3ULL,
		0x17D2753E0F61885AULL,
		0x54F5F97D20C475A2ULL,
		0x2D3EFBD2C9F7C53EULL,
		0x365DA6886606ED38ULL,
		0x1C18DD412B95482BULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x56114762C19E30D7ULL,
		0xBC0FE74231EE688EULL,
		0x461DBD03B929E3B2ULL,
		0x396AB64D4B656F10ULL,
		0xD37F1211076B4ABEULL,
		0xA932D8EB454EE2B2ULL,
		0xC535B72265B14265ULL,
		0x6998E5F13FD93F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83DDDE378293FE8AULL,
		0x3FC654738DBBBAEFULL,
		0x22791D8009B290CDULL,
		0x549530A93E2DFCFFULL,
		0xFC2C583640C2522BULL,
		0xED80496ADD581421ULL,
		0xF856F85152A4F4D3ULL,
		0x319F8A1BB6726756ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5CC9955430DCE5DULL,
		0x83C9B331BC55D261ULL,
		0x6464A083B09B737FULL,
		0x6DFF86E4754893EFULL,
		0x2F534A2747A91895ULL,
		0x44B291819816F693ULL,
		0x3D634F733715B6B6ULL,
		0x58076FEA89AB584DULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCAD7D31D42374102ULL,
		0x1081931BE65C1434ULL,
		0xAF0E57BA37F82DCCULL,
		0xC23A6696CC12AA64ULL,
		0x908BBAF8DEDCDEB3ULL,
		0x03461BA66193C819ULL,
		0x80CCBC6ECD1C9BA6ULL,
		0x2723440B6BA21825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC43BF7B70DC504BULL,
		0xBFB4D505976FFB20ULL,
		0x22D6FF38530D7DBFULL,
		0xDC114EC27D538A26ULL,
		0x2C8CB4E4187C87F5ULL,
		0x8E473ED4ED8AF41FULL,
		0x34B742CB745CA7BAULL,
		0x10AB3E5FB2A6426BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76946C6632EB1149ULL,
		0xAF35461E7133EF14ULL,
		0x8DD8A88264F55073ULL,
		0x1E2B2854B1412042ULL,
		0xBC070E1CC6A05946ULL,
		0x8D0125728C193C06ULL,
		0xB47BFEA5B9403C1CULL,
		0x37887A54D9045A4EULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x17E3C4A6BC9C1379ULL,
		0x8A4FFF8B22D43D3CULL,
		0x598671073DF1C8B0ULL,
		0xB50923EDA0D5F315ULL,
		0xBF9093D41BEF3D8BULL,
		0x9EA5896E5E1CADFBULL,
		0x8A26ACE384E508D8ULL,
		0x61305CE491C06A6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EAB7AB8071A68BAULL,
		0x12DDBD21CD321528ULL,
		0x0AA7F3CC1E0F6CBBULL,
		0xE0D553EC8A7386CBULL,
		0xE0BD2550CE4B53ABULL,
		0x9CF7EE65876DF4C1ULL,
		0x7085C6736C9FBFDAULL,
		0xFC7F7060AC00A997ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0948BE1EBB867BC3ULL,
		0x989242AAEFE62814ULL,
		0x532182CB23FEA40BULL,
		0x55DC70012AA675DEULL,
		0x5F2DB684D5A46E20ULL,
		0x0252670BD971593AULL,
		0xFAA36A90E87AB702ULL,
		0x9D4F2C843DC0C3FDULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC64BA309903683B0ULL,
		0x8F1B1D4C8ADD6E6FULL,
		0x6D44825D289F2C9DULL,
		0xA1C75E1D24865EE8ULL,
		0x3C5E63D95FFB22D7ULL,
		0x68630AB94DD1FB41ULL,
		0xFB4BFD8F488D9E62ULL,
		0xD532A485BD96DAD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBFA41413B78740AULL,
		0x5B8B2816D3262103ULL,
		0x07531AD6A3842B61ULL,
		0xAFBAD65002A4F185ULL,
		0xE838BC4E8A91DC66ULL,
		0x278D9D11C9A25D4DULL,
		0xAA42BA1E863794BDULL,
		0x0A5AA569FBE70C62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DB1E248AB4EF7BAULL,
		0xD490355A59FB4F6CULL,
		0x6A17988B8B1B07FCULL,
		0x0E7D884D2622AF6DULL,
		0xD466DF97D56AFEB1ULL,
		0x4FEE97A88473A60CULL,
		0x51094791CEBA0ADFULL,
		0xDF6801EC4671D6B5ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x613804D634242948ULL,
		0x3684DE4DA47F020BULL,
		0xC8217DBF99D606D2ULL,
		0xFBB2E44D7400E418ULL,
		0xFA9CE946D0B1566BULL,
		0xDE6E7FFD2365C04AULL,
		0xD6045F16FBD07C67ULL,
		0x83B3CB70047A0073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CAE44B37F9B6E23ULL,
		0x0EF726589746E2CDULL,
		0xEF2FB3516D3FDE9FULL,
		0x9D5CFDA53B4D6544ULL,
		0xF2DF2C3108D71A87ULL,
		0xE219BF0F94D82693ULL,
		0xD6B48AED514FF8F3ULL,
		0x80E5E660520DA217ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D9640654BBF476BULL,
		0x3873F8153339E0C6ULL,
		0x270ECEEEF4E9D84DULL,
		0x66EE19E84F4D815CULL,
		0x0843C577D8664CECULL,
		0x3C77C0F2B7BDE6D9ULL,
		0x00B0D5FBAA9F8494ULL,
		0x03562D105677A264ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xADB6B9522AAF3877ULL,
		0xE00C46708E19BFAAULL,
		0x8B9F8A7A6FA86FB8ULL,
		0x68994A5E398F7232ULL,
		0xFBA3BF3231103730ULL,
		0x5AA7768D9082601BULL,
		0xD9C14668C50DC4ECULL,
		0x5593EF8A5FCFED12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C2C4AA210EFFB6ULL,
		0x9B2BCB00E6994629ULL,
		0x1CE57F00E586B52FULL,
		0x7CAFE86DA9BF9A7DULL,
		0x9CB24BF938BC9E32ULL,
		0x38E9B3A5D31F42F7ULL,
		0x7E0426F2A10ABC9AULL,
		0x58574AF6C4A8B1E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94747DF80BA1C7C1ULL,
		0x7B278D706880F983ULL,
		0x977AF57A8A2EDA97ULL,
		0x1436A2339030E84FULL,
		0x6711F4CB09ACA902ULL,
		0x624EC528439D22ECULL,
		0xA7C5609A64077876ULL,
		0x0DC4A57C9B675CF3ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6828550DBCCFBFCULL,
		0xAE317DBA67067FC4ULL,
		0x2BF70495A3277F53ULL,
		0xE7FD24B0C431E88EULL,
		0xC72BB81FAC45E540ULL,
		0x249D39EC76022612ULL,
		0x17FF12F43325C1D0ULL,
		0x84E8E0EA5C316C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0767D525D459C02EULL,
		0x721F2E04171584C6ULL,
		0x91432C4750B73FBEULL,
		0x55B2EFC91596647CULL,
		0x391E494ABE737E54ULL,
		0x66F46CF09C20C2E2ULL,
		0xEA847F389475606AULL,
		0xCFCA33633E532057ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1E550750F953BD2ULL,
		0xDC2E53BE7013FB02ULL,
		0xBAB428D2F39040EDULL,
		0xB24FCB79D1A78CF2ULL,
		0xFE35F15512369B14ULL,
		0x4269551CEA22E4F0ULL,
		0xFD7B6DCCA750A1BAULL,
		0x4B22D38962624C77ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x32D2B708CFF4B243ULL,
		0x049D0E0A8A885017ULL,
		0xC319EF4F5F8EBDEEULL,
		0x966910357A85CA76ULL,
		0x4E88345944391BD4ULL,
		0x9AB101141DDCCCC0ULL,
		0xF36B99E632496A63ULL,
		0xDC1C763A47EE515FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2878A428537B2E24ULL,
		0xFB6BE6B1BB8BF9DEULL,
		0xDB5634BEFA8A9E60ULL,
		0xC2E6E80F4B0EA7C9ULL,
		0xEFD960E168583AD6ULL,
		0x4C551F789E07A4DEULL,
		0xB6FF418143A1FD34ULL,
		0x1566CF9A2CF48EF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AAA13209C8F9C67ULL,
		0xFFF6E8BB3103A9C9ULL,
		0x184FDBF1A504238EULL,
		0x548FF83A318B6DBFULL,
		0xA15154B82C612102ULL,
		0xD6E41E6C83DB681EULL,
		0x4594D86771E89757ULL,
		0xC97AB9A06B1ADFA6ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x83872459989D2015ULL,
		0x85F3BA333067E3CCULL,
		0xE246D8D8DE7D3EBAULL,
		0x8121B0CDD3518405ULL,
		0x1124AF6111376FBAULL,
		0x4BAC050AE4F58E3FULL,
		0x4BFDD4A74B9B5C6DULL,
		0x1D9D96A0B2E1226DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A181CCA41E16D90ULL,
		0xB03340DA232F123EULL,
		0x5E96937CF8DD4E52ULL,
		0x42C43AD01558A433ULL,
		0x6DF0E7803E02CF83ULL,
		0x7022E5438BFAE635ULL,
		0x00149CF9B04702F6ULL,
		0xD552BAF393A17DBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x899F3893D97C4D85ULL,
		0x35C0FAE91348F1F2ULL,
		0xBCD04BA426A070E8ULL,
		0xC3E58A1DC6092036ULL,
		0x7CD448E12F35A039ULL,
		0x3B8EE0496F0F680AULL,
		0x4BE9485EFBDC5E9BULL,
		0xC8CF2C5321405FD0ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB3FB0618296504F4ULL,
		0xF219DC1B552D548EULL,
		0x72B800E2B7DC4F5EULL,
		0xACDDEEF8CE6C5CA4ULL,
		0xFF0F7F58A5F01FF3ULL,
		0xDC132A47B0C86DC6ULL,
		0xBF265297214BB5A0ULL,
		0x58D2F44A1D333013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C085C83B0FB15AULL,
		0xC47C343DF971B4C1ULL,
		0x13577667B6D17263ULL,
		0x9F51B9732FE239C5ULL,
		0xA71A3913F90E8290ULL,
		0x25862A48A998BD38ULL,
		0x8F0DEC4AE532317AULL,
		0x51733442F166C913ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD63B83D0126AB5AEULL,
		0x3665E826AC5CE04FULL,
		0x61EF7685010D3D3DULL,
		0x338C578BE18E6561ULL,
		0x5815464B5CFE9D63ULL,
		0xF995000F1950D0FEULL,
		0x302BBEDDC47984DAULL,
		0x09A1C008EC55F900ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB008310426864B51ULL,
		0xFB755079FA240BF2ULL,
		0x243BE6BF582F58A5ULL,
		0x8A8B0E9AB0F8420EULL,
		0x9612E91EDF308BE3ULL,
		0xCA6363DCF7DB743FULL,
		0x633866DC4D3B0605ULL,
		0x80EAECF026D358D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38F832BBDD9122CULL,
		0x0601F41BF53314BAULL,
		0xB32A079DEEC25B02ULL,
		0x8DD59CB60BC4E10AULL,
		0x9AB1DD85FF864EACULL,
		0x7016B9EE485A3A3BULL,
		0xBAD456F166BC03DAULL,
		0x578B47950B28B8BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6387B22F9B5F597DULL,
		0xFD74A4620F171F48ULL,
		0x9711E122B6ED03A7ULL,
		0x075E922CBB3CA304ULL,
		0x0CA3349B20B6C54FULL,
		0xBA75DA32BF814E04ULL,
		0xD9EC302D2B8705DFULL,
		0xD761AB652DFBE06AULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDCAACEFF83004241ULL,
		0xCF11AE2C3A91DAB5ULL,
		0x8E4C5A30B427BAA5ULL,
		0x58F937C13742439BULL,
		0x67457D477C0C0186ULL,
		0x8E39BB9A8CFC92F2ULL,
		0xCE8F20CFAE4ED65CULL,
		0xF2A06CC442C7589AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C97CF7DAF5E53A4ULL,
		0x5190E7BD5033EC66ULL,
		0x46343F40EF0F02C9ULL,
		0x476F5EE2D5C3F095ULL,
		0xD66398594F847F43ULL,
		0xC9C8092262DF7304ULL,
		0x1F864B71C11796E1ULL,
		0xC9A31D9AA2310A1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x803D01822C5E11E5ULL,
		0x9E8149916AA236D3ULL,
		0xC87865705B28B86CULL,
		0x1F966923E281B30EULL,
		0xB126E51E33887EC5ULL,
		0x47F1B2B8EE23E1F6ULL,
		0xD1096BBE6F5940BDULL,
		0x3B03715EE0F65286ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x715E5E277226D639ULL,
		0x6164AB4856DEB909ULL,
		0x254F5C5DA76FDB56ULL,
		0x9F70DF99A9BC0306ULL,
		0xB1FCF1B6ECAD4183ULL,
		0x00D81A2ED8516341ULL,
		0xECE9165AD3FE7AF7ULL,
		0x6654AA0DF007860AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B7A616FC9428F5ULL,
		0xFA18F854D6ABD804ULL,
		0xF199F63A8E7A7A8AULL,
		0xFE3D9E77DDA5FF6BULL,
		0x2AD7CDC2CA6CD6C8ULL,
		0x4290989BBC188C8EULL,
		0x5E242B6CD9C54933ULL,
		0x990ECBE6ADEBC5C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62E9F8318EB2FECCULL,
		0x9B7C531C8075610DULL,
		0xD4D6AA672915A1DCULL,
		0x614D41EE7419FC6DULL,
		0x9B2B3C7426C1974BULL,
		0x424882B56449EFCFULL,
		0xB2CD3D360A3B33C4ULL,
		0xFF5A61EB5DEC43C3ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7D13FDBE7D031B22ULL,
		0x27484FC6E79ED0DCULL,
		0xF3D82499E092DA88ULL,
		0xCB007B31A009FC50ULL,
		0xA7ECE65B83AB071CULL,
		0xBC7EA7745F61D5CFULL,
		0xF4F6E8A3964F72E3ULL,
		0x702E8E0A09998863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF25693B9B9287870ULL,
		0x55EC0501D3D36C23ULL,
		0xED12E10B97115770ULL,
		0x260C6A5BB20DA1C5ULL,
		0x40D6FA17DF0FCD20ULL,
		0xD425D9C5A4EC087FULL,
		0x2C4816A1D61C08A3ULL,
		0x52E3A2BC9065578FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F456E07C42B6352ULL,
		0x72A44AC7344DBCFFULL,
		0x1ECAC59277838DF8ULL,
		0xED0C116A12045D95ULL,
		0xE73A1C4C5CA4CA3CULL,
		0x685B7EB1FB8DDDB0ULL,
		0xD8BEFE0240537A40ULL,
		0x22CD2CB699FCDFECULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA315B6E8674D5A35ULL,
		0xD43B1DAF632CEEF3ULL,
		0x3CB63BAC9246AEC9ULL,
		0x9692C36217CC7EA9ULL,
		0xFBFCC91F9CB298BEULL,
		0x55AD68292323ADCAULL,
		0x116E0B067D33DE37ULL,
		0xF4FD92373CA8ED7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A5AB214DB65697ULL,
		0x444BF11EA737BC56ULL,
		0x520256498A635B3DULL,
		0x082E46B0F416A08FULL,
		0x9A05B5980CABCAC2ULL,
		0xB8ED4644C7FCE674ULL,
		0x3511EFD30E5A3EAFULL,
		0xBD4D9B88F9BD8486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24B01DC92AFB0CA2ULL,
		0x9070ECB1C41B52A5ULL,
		0x6EB46DE51825F5F4ULL,
		0x9EBC85D2E3DADE26ULL,
		0x61F97C879019527CULL,
		0xED402E6DE4DF4BBEULL,
		0x247FE4D57369E098ULL,
		0x49B009BFC51569F8ULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2B0B6002FD27C1DFULL,
		0xF755D32BEE64AB8AULL,
		0x97788AC09DFCEE8EULL,
		0x518DC8F2CC3E3D36ULL,
		0xF17A2B47E270F57EULL,
		0x5D827693A767A25AULL,
		0xC11335C7E1529499ULL,
		0xCDD65A4AFD565188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C9848219E7E6D4ULL,
		0xAC81566DC250BFBCULL,
		0x6AF8811F0BB30BF7ULL,
		0xD7AD98D335A3A455ULL,
		0x6FE3D22A86632D9DULL,
		0x999E7EB71A4543B0ULL,
		0x0500725BB9AD0E28ULL,
		0x01949FAFBDFEF0BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CC2E480E4C0270BULL,
		0x5BD485462C341436ULL,
		0xFD800BDF964FE579ULL,
		0x86205021F99D9963ULL,
		0x9E99F96D6413D8E3ULL,
		0xC41C0824BD22E1EAULL,
		0xC413479C58FF9AB1ULL,
		0xCC42C5E540A8A135ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7642638642A9104AULL,
		0x9C19C7D3AA7254D5ULL,
		0x56419CDABD6F769CULL,
		0xC85FA94AB321C7C9ULL,
		0x3F6C56259AE5A3DAULL,
		0xB64AA0245C0347C8ULL,
		0xDE4CE5BC074253FFULL,
		0x3F55E728E87C6044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7601B0916DE0163ULL,
		0x013FAD5AA1C73448ULL,
		0x7CDD7C06823E6E59ULL,
		0x5FA2DD6F2EF0BEBDULL,
		0x09072C9184648EE7ULL,
		0x42905CDC9513C026ULL,
		0xE48562B2982868FFULL,
		0x0D7E5A1B177FE950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC122788F54771129ULL,
		0x9D266A890BB5609DULL,
		0x2A9CE0DC3F5118C5ULL,
		0x97FD74259DD17974ULL,
		0x366B7AB41E812D3DULL,
		0xF4DAFCF8C91087EEULL,
		0x3AC9870E9F6A3B00ULL,
		0x322BBD33FF038914ULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B4F9A6192C73997ULL,
		0xB57FF927D92D672DULL,
		0x7BA989652BD710BDULL,
		0xCA8C9A37C2C55B19ULL,
		0xDF95456909E61B59ULL,
		0x7E4CAA7FAE019788ULL,
		0x3E9B19722FBA4067ULL,
		0xCDB1407213764345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BA4177740808EAULL,
		0x429620615E7DDE13ULL,
		0xC9054BC0D00C4012ULL,
		0x87A8B8E3C45E4180ULL,
		0x7340ECEF0231DBF0ULL,
		0x74F6E890741447A7ULL,
		0x7984EF99BF16C8E6ULL,
		0xB122648BDF6A0B6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02F5DB16E6CF317DULL,
		0xF7E9D9468750B93EULL,
		0xB2ACC2A5FBDB50AFULL,
		0x4D2422D4069B1A99ULL,
		0xACD5A9860BD7C0A9ULL,
		0x0ABA42EFDA15D02FULL,
		0x471FF6EB90AC8881ULL,
		0x7C9324F9CC1C4828ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB8A4A2D962CCAF36ULL,
		0x65D1EC61CDAB65E4ULL,
		0x40357B9C3D2C87AEULL,
		0x050A225847464C0CULL,
		0xFC6FB04A850301DFULL,
		0x1861405E62C0B1CAULL,
		0xDAF0FF3541F4FC2BULL,
		0xF59706A62E5EA731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E450B62FDF14A6AULL,
		0x679D02B65D035AFFULL,
		0xCEE90A53AA935195ULL,
		0x46C5F517E9B8A057ULL,
		0x1E6495FC2F607190ULL,
		0x8AC96C6AA0C56B6FULL,
		0xCC24DB261B2DFA8AULL,
		0xC8997A008F216F54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6E1A9BB9F3DE55CULL,
		0x024CEED790A83F1BULL,
		0x8EDC71CF97BFD63BULL,
		0x43CFD74FAEFEEC5BULL,
		0xE20B25B6AA63704FULL,
		0x92A82C34C205DAA5ULL,
		0x16D424135AD906A1ULL,
		0x3D0E7CA6A17FC865ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x13B11820223372BCULL,
		0x0A11BE20798E33E1ULL,
		0xD479282BCC53CE2CULL,
		0xA6B97C868545F345ULL,
		0x6508ECCAA253CF3FULL,
		0xD47F1BD124D8801AULL,
		0x919EB700A074C152ULL,
		0xDA12819DD15E0560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1DA700E3517659FULL,
		0x4E069EADE2F15F44ULL,
		0x80232302AEAA7E13ULL,
		0x205CADB107CD6BA3ULL,
		0xB205107ADED75F0EULL,
		0xCAB61B3AA67DF8F4ULL,
		0x5A4AE165F8ABD6E3ULL,
		0x32E84026E3945F98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD26B682E17241723ULL,
		0x4417208D9B7F6CA5ULL,
		0x545A0B2962F9B03FULL,
		0x86E5D137828898E6ULL,
		0xD70DFCB07C849031ULL,
		0x1EC900EB82A578EEULL,
		0xCBD4566558DF17B1ULL,
		0xE8FAC1BB32CA5AF8ULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA4239E72B55F0B9BULL,
		0xAD5A6E244E906609ULL,
		0x89BD6FEE25F5F1C1ULL,
		0x4337F7ACCFA45372ULL,
		0x7CF0A715095C91AFULL,
		0x7A8D55E8E29048D0ULL,
		0xA6252B32ECE153F3ULL,
		0x15A5BB1E2A145CD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56DDC1A3EF15768FULL,
		0xC607AE6B2585E974ULL,
		0xE2E7A197305FA147ULL,
		0xD64C72A5E36D07ADULL,
		0x23F6858CBF810E42ULL,
		0x131C675D67EFDF11ULL,
		0x089C3345A5106D41ULL,
		0xA1652E43D4D9FA92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2FE5FD15A4A7D14ULL,
		0x6B5DC04F6B158F7DULL,
		0x6B5ACE7915AA5086ULL,
		0x957B85092CC954DFULL,
		0x5F062299B6DD9FEDULL,
		0x699132B5857F97C1ULL,
		0xAEB9187749F13EB2ULL,
		0xB4C0955DFECDA642ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x060481AAAF99C6A0ULL,
		0x87435EC18833D17CULL,
		0x9DF6923536707C7EULL,
		0xF6208FA55958F394ULL,
		0x9BA6474DE42CD6E0ULL,
		0x2997E1E151BDD802ULL,
		0xBE928D470F442A42ULL,
		0x9EA538345C6FCA23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97D53C60FFD6CC4ULL,
		0x6E47CC8D1664001DULL,
		0xD76705D21CBFE7D4ULL,
		0xB71295D9B43B96DCULL,
		0x20A000D5BC73EA84ULL,
		0x68F31F6429A05D39ULL,
		0x0D4AF754EA6B237FULL,
		0x05DF80B9B1C29B12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF79D26CA064AA64ULL,
		0xE904924C9E57D161ULL,
		0x4A9197E72ACF9BAAULL,
		0x41321A7CED636548ULL,
		0xBB064798585F3C64ULL,
		0x4164FE85781D853BULL,
		0xB3D87A13E52F093DULL,
		0x9B7AB88DEDAD5131ULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5DA5A7B27B05D316ULL,
		0x7721CF8B64E3C1E1ULL,
		0xFDA8489265662722ULL,
		0xB55578F8B0092350ULL,
		0x136B71A78A717EFDULL,
		0x42B21270F440512DULL,
		0x272AC6C22BD1310DULL,
		0x11CCB62032ED627EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F893E1A5F650A9EULL,
		0xEDC3B14916A9D350ULL,
		0xFAA3CA248640B966ULL,
		0xDFDECC38866C2BA9ULL,
		0x24FBAC105DA35E67ULL,
		0x6C1FE1629DA3DF09ULL,
		0xD1DDB246FFEB62C6ULL,
		0x09A9FF0A48875255ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x022C99A82460D988ULL,
		0x9AE27EC2724A12B1ULL,
		0x070B82B6E3269E44ULL,
		0x6A8BB4C0366508F9ULL,
		0x3790DDB7D7D2209AULL,
		0x2EADF31269E38E24ULL,
		0xF6F77484D43A53CBULL,
		0x1865492A7A6A302BULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x900A54ECAB97FAA8ULL,
		0x5CCCA35A39EE33CBULL,
		0x93116B1B4221A39FULL,
		0xFF65A9FFE303CB4AULL,
		0x2C73BECFAC75F177ULL,
		0x725A0F6D3C52B7F9ULL,
		0x978B3DEEE99C0A5EULL,
		0x26D7ACB32A3D5C4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2CCBA6278EEE658ULL,
		0xEB4BF2DCB28901E0ULL,
		0x5D6EE6A708900BA7ULL,
		0x84B83A52C7E32CB4ULL,
		0xED146ECD6E834B21ULL,
		0x956F7A65F84EC927ULL,
		0xEEB7A73996EDEEA9ULL,
		0x475CB680A9C6F6C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52C6EE8ED3791CF0ULL,
		0xB78751868B67322BULL,
		0xCE7F8DBC4AB1A838ULL,
		0x7BDD93AD24E0E7FEULL,
		0xC167D002C2F6BA56ULL,
		0xE7357508C41C7EDEULL,
		0x793C9AD77F71E4F7ULL,
		0x618B1A3383FBAA88ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC4F62E753CE1C62EULL,
		0x734B4255D33B7371ULL,
		0xBCF48E504906723EULL,
		0x53D57B2D5D08478AULL,
		0x9617D3F683371E81ULL,
		0xC35C22EEC8801930ULL,
		0xA685BEAA6C7AB37BULL,
		0x52CF261DF41A5F86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CCE4EF4D42A9248ULL,
		0x55882E232DF17B9BULL,
		0x503457E90B6D5D85ULL,
		0xD11CD5A56BCE9E0BULL,
		0x274CA2D0359F15C2ULL,
		0x0AE66AD2716A3C41ULL,
		0x4961ADCAEC23A272ULL,
		0x4E04D2181EFC36E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8386081E8CB5466ULL,
		0x26C36C76FECA08EAULL,
		0xECC0D9B9426B2FBBULL,
		0x82C9AE8836C6D981ULL,
		0xB15B7126B6A80B43ULL,
		0xC9BA483CB9EA2571ULL,
		0xEFE4136080591109ULL,
		0x1CCBF405EAE66963ULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBEC23849053C7413ULL,
		0x277B3CB55E7DD939ULL,
		0x56909FA30347C934ULL,
		0x59D82694AA7F75A9ULL,
		0xF355D61073448123ULL,
		0x748D96993739B5DBULL,
		0x5FDCEE28213BE766ULL,
		0x35EE33232CB0FBDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAC3551D902785F8ULL,
		0xF619529434DA906EULL,
		0x1C59C6E89034B7CAULL,
		0x8C085E1253A72596ULL,
		0xAF4FC8A3AA6C5791ULL,
		0x01DCF8F300EB6C39ULL,
		0x88594097E54B4072ULL,
		0x66A2863CF0B9661EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44016D54951BF1EBULL,
		0xD1626E216AA74957ULL,
		0x4AC9594B93737EFEULL,
		0xD5D07886F9D8503FULL,
		0x5C1A1EB3D928D6B2ULL,
		0x75516E6A37D2D9E2ULL,
		0xD785AEBFC470A714ULL,
		0x534CB51FDC099DC5ULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9B4C1F4791121B15ULL,
		0x4E116DF4AC76FABAULL,
		0x7356B0D2F65055DAULL,
		0xACC20EECD3C4290EULL,
		0xD6823888C0E8BA80ULL,
		0x852C199B77CA033CULL,
		0x9A1B688B327E9F9BULL,
		0xE3DBFCE64DA9ECE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9827232498FF50CFULL,
		0xD56329C4FD4F669CULL,
		0x16E69DEA7ED32501ULL,
		0x90C8C06650C49F43ULL,
		0xFF747D9694036937ULL,
		0x2B50181EEEAFB498ULL,
		0x502BCC330E82758CULL,
		0x6B7F86A2E8228B08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x036B3C6309ED4BDAULL,
		0x9B72443051399C26ULL,
		0x65B02D38888370DBULL,
		0x3C0ACE8A8300B64DULL,
		0x29F6451E54EBD3B7ULL,
		0xAE7C01859965B7A4ULL,
		0xCA30A4B83CFCEA17ULL,
		0x88A47A44A58B67EDULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8BE4E31A5119B92AULL,
		0x64558A71BF2862EAULL,
		0xC3FF5F579758AB59ULL,
		0x57E9CD26E071E9FCULL,
		0x94C5248C27895961ULL,
		0xCE8B23B48091AD7AULL,
		0xD9F375EA6C5818A0ULL,
		0x67EBFEA8A8EC14D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0B8C4D1C9CD4BDDULL,
		0x4EA766789338F397ULL,
		0x36BEF4DB235E9CA7ULL,
		0xA6A4B98B509E42CFULL,
		0xD0E045067FC04E03ULL,
		0xA6297AE488B236AAULL,
		0xF1B068ACB4A3823CULL,
		0xCB55656DE09BC29FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B5C27CB98D4F2F7ULL,
		0x2AF2EC092C10917DULL,
		0xF541AB8CB40637FEULL,
		0xF14D74ADB0EFAB33ULL,
		0x4425618A58491762ULL,
		0x68A2595008239BD0ULL,
		0x28431D46D8FB9A9CULL,
		0xACBE9BC54877D64EULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE376B20A7B04E4CCULL,
		0x50F678093E9B8A57ULL,
		0x72AEC629F3CBEAF5ULL,
		0x8706C5ABCAA4B581ULL,
		0x3DEA4D54079E2298ULL,
		0x7AE47FE13CDBB17EULL,
		0x65620CDFC4BB23F4ULL,
		0x18DDA1B2A0F5CDAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99C00AEA9C03FC59ULL,
		0x36BC8EC9AEB4C13EULL,
		0x208A82B0F6B59A5BULL,
		0xBFB100D9BCEF9E49ULL,
		0x127AE2B6A814BE83ULL,
		0x779FAF4FF6C17BCCULL,
		0x3C7B6369B4739B87ULL,
		0xB6FD7A9FFFF08352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AB6B8E0E7071895ULL,
		0x664AF6C0902F4B69ULL,
		0x52244499057E70AEULL,
		0x38B7C572764B2BC8ULL,
		0x2F90AFE2AF8A9C1BULL,
		0x0D7BD0AECA1ACAB2ULL,
		0x59196FB670C8B873ULL,
		0xAE20DB2D5F054EF8ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0F7D74B3432353DBULL,
		0xDD1200B82C36159BULL,
		0xEC8FD7A40BE227FAULL,
		0xF5B89CF5B9C23AA0ULL,
		0x8FA03295308866F0ULL,
		0x07B0815FF391C5D4ULL,
		0x14949674896825EAULL,
		0xCBA1C1208B5960CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33CE93EE0FA6D7CULL,
		0xF299AF364CCAEA7AULL,
		0xC5C3DC92D895710CULL,
		0x65A3F649DC97F249ULL,
		0xC733CF5A3764BB98ULL,
		0xE8715C3FEEE9EC9EULL,
		0xE20A1092B4A666C7ULL,
		0x174192C1883F5BC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC419D8DA3D93EA7ULL,
		0x2F8BAF8E60FCFFE1ULL,
		0x294C0B36D37756F6ULL,
		0x901B6ABC6555C8E9ULL,
		0x4893FDCF07ECDD68ULL,
		0xEFC1DD601D78294AULL,
		0xF69E86E63DCE432DULL,
		0xDCE053E103663B0AULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x47E1B8F7B615D519ULL,
		0xC412FD9023F54B90ULL,
		0x32CFC9772C481B97ULL,
		0x31FC23C7B86C1553ULL,
		0x612A03DF666BC391ULL,
		0xD734DFDDF5AEA178ULL,
		0x38B1D63A33029431ULL,
		0x202409303BCD5CBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C67BB024D6EDDAULL,
		0x28FB85C23D4D1CA1ULL,
		0x9F7DC8313B90F024ULL,
		0xD822E4C09AC5F6C9ULL,
		0xDB0BF761B1A94A5DULL,
		0x087F7DB93A1C09B8ULL,
		0x2470A7B464D29C0AULL,
		0x7F130166B12E4243ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E27C34792C338C3ULL,
		0xECE978521EB85731ULL,
		0xADB2014617D8EBB3ULL,
		0xE9DEC70722A9E39AULL,
		0xBA21F4BED7C289CCULL,
		0xDF4BA264CFB2A8C0ULL,
		0x1CC1718E57D0083BULL,
		0x5F3708568AE31EF9ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xABB2C7A6A3D59904ULL,
		0x9C3BE7544E889959ULL,
		0xFDD416318850EE33ULL,
		0x64A667870DE5436BULL,
		0x5299BD77364F2A5EULL,
		0xC6BA20F9043F277FULL,
		0xF93B755F1B72F2E7ULL,
		0x15E7E444D273CDDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A35D69BEB2145B2ULL,
		0xE193B2695B4119B6ULL,
		0x1C351B1E602F7382ULL,
		0x3211C68EA3848B8BULL,
		0x2BEB51E8B5D05034ULL,
		0xDBFA095F8376C833ULL,
		0x8293FD7AE4325CBFULL,
		0xD1C207AB95D870D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC187113D48F4DCB6ULL,
		0x7DA8553D15C980EFULL,
		0xE1E10D2FE87F9DB1ULL,
		0x56B7A109AE61C8E0ULL,
		0x7972EC9F839F7A6AULL,
		0x1D4029A68749EF4CULL,
		0x7BA88825FF40AE58ULL,
		0xC425E3EF47ABBD0DULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5962B85514767732ULL,
		0xA59E35B185DB624FULL,
		0x9E4AD8FCE0AE0AB5ULL,
		0x231587C954E659E7ULL,
		0x71FCA7C46A160EF9ULL,
		0xF9F44CAE78EF4706ULL,
		0x3E124C08B2F31402ULL,
		0x557260C56E0E7AE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2499E18C1E06E6EAULL,
		0x157829B018C8CB29ULL,
		0xBAA24D5927E382EBULL,
		0x198BAE978038E2EDULL,
		0x7A7AEB2AC1322B2BULL,
		0xB2487369F152E8F8ULL,
		0x831CA88621F9E441ULL,
		0x6883449D46EC5536ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DFB59D90A7091D8ULL,
		0xB0E61C019D13A966ULL,
		0x24E895A5C74D885EULL,
		0x3A9E295ED4DEBB0AULL,
		0x0B864CEEAB2425D2ULL,
		0x4BBC3FC789BDAFFEULL,
		0xBD0EE48E930AF043ULL,
		0x3DF1245828E22FD4ULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x04AFE2B0CAD14EA3ULL,
		0x6A2064CAEE8765C1ULL,
		0xE184ABACF72658BAULL,
		0x219A50D043ACFE3EULL,
		0x8C2CAA1F99CFF7E5ULL,
		0xFF7237BDC3D3D24EULL,
		0x8695E32065C05641ULL,
		0x7CB9545908633583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x240B81914AAABAF1ULL,
		0xCA7A1542EEF3B6F5ULL,
		0x11FF349DDDD42858ULL,
		0x4D5C12AB2074832BULL,
		0xE9BD231C5C108CA7ULL,
		0xADE12E7BF0DBE30AULL,
		0x60C6F328F4CBD8DEULL,
		0xBE22D290EE0CBECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20A46321807BF452ULL,
		0xA05A71880074D334ULL,
		0xF07B9F312AF270E2ULL,
		0x6CC6427B63D87D15ULL,
		0x65918903C5DF7B42ULL,
		0x529319C633083144ULL,
		0xE6531008910B8E9FULL,
		0xC29B86C9E66F8B4EULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0B7D3DD28AEB0FE7ULL,
		0xED9B6398F87C862DULL,
		0xB6F14ED9AB55DA12ULL,
		0x39871C1A62BEA556ULL,
		0x4D483CFED4562238ULL,
		0x22ADFFBD324788FBULL,
		0x15D298570018F530ULL,
		0xDE0CEEFEE8FE31CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA2508B8FDCE501ULL,
		0xBD2D6E5D3799F502ULL,
		0xB6B9D1AB736BFA2AULL,
		0xD7BB6AA61EE84D2AULL,
		0x27E7DA10799F88DFULL,
		0xCFE2252D6891E63FULL,
		0x21AE3EC38089931DULL,
		0x185E855C1792DA9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01DF6D590537EAE6ULL,
		0x50B60DC5CFE5732FULL,
		0x00489F72D83E2038ULL,
		0xEE3C76BC7C56E87CULL,
		0x6AAFE6EEADC9AAE7ULL,
		0xED4FDA905AD66EC4ULL,
		0x347CA6948091662DULL,
		0xC6526BA2FF6CEB51ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF791C8C950E70308ULL,
		0x5C0B0D42AB16B29BULL,
		0x0CFD3F1031088305ULL,
		0x1BF6A2F1EE911845ULL,
		0xE08675D9C406AEA3ULL,
		0xE6876F76416FEC59ULL,
		0xE4714D7CBCB9E504ULL,
		0xC3404F33C17C6E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D11DCE179C2AEBULL,
		0xBA4708EB96CC671CULL,
		0x0A067DD20A82BA1FULL,
		0xC0BF2DA893BBCA2FULL,
		0xA7D9D5A9FCCC3197ULL,
		0x6A7C8ECE79DCCF50ULL,
		0x732696113F35A932ULL,
		0xF2A1BD59392255DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E40D507477B29E3ULL,
		0xE64C05A93DDAD587ULL,
		0x06FB42C23B8A391AULL,
		0xDB498F597D2AD26AULL,
		0x475FA07038CA9F34ULL,
		0x8CFBE1B838B32309ULL,
		0x9757DB6D838C4C36ULL,
		0x31E1F26AF85E3BBCULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x021ACB3DDD788148ULL,
		0x4ADB434E5EDDF35DULL,
		0x0176240B5E1FBD33ULL,
		0xD610EFB08D87A557ULL,
		0xC5B38F8DFEBA7041ULL,
		0xC934B7EC36714372ULL,
		0xE7FD3748630335FDULL,
		0xB0C0EC932D94F674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C96B40C62EF6733ULL,
		0xAE93E3C2633DC872ULL,
		0x681DEBD21FA9501CULL,
		0x68E419808BC8C028ULL,
		0x3B22C0E95ABFB642ULL,
		0xBC9C29ABF894F2F2ULL,
		0x51FE849738549BA0ULL,
		0x8B0DCE9077F487D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E8C7F31BF97E67BULL,
		0xE448A08C3DE03B2FULL,
		0x696BCFD941B6ED2FULL,
		0xBEF4F630064F657FULL,
		0xFE914F64A405C603ULL,
		0x75A89E47CEE5B180ULL,
		0xB603B3DF5B57AE5DULL,
		0x3BCD22035A6071A5ULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6E9D32E1605979CAULL,
		0xFF800C7D5B247DF3ULL,
		0xA4B08283B7CEAD35ULL,
		0xA9F85F0C23FCE8AFULL,
		0x820C1E1A400A8019ULL,
		0x389F1A340D81CA07ULL,
		0x93FCAB77817BEA7EULL,
		0x11F25346BCC824CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6666145EBCFD8D51ULL,
		0x1CDC6BA37EE98149ULL,
		0x235160886D75725DULL,
		0x22FC63F0C3B2EA1DULL,
		0x1FCBDFB763639197ULL,
		0xD724305566DCAC95ULL,
		0x9B778B784269F5BDULL,
		0x88E88D463AC1697EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08FB26BFDCA4F49BULL,
		0xE35C67DE25CDFCBAULL,
		0x87E1E20BDABBDF68ULL,
		0x8B043CFCE04E02B2ULL,
		0x9DC7C1AD2369118EULL,
		0xEFBB2A616B5D6692ULL,
		0x088B200FC3121FC3ULL,
		0x991ADE0086094DB4ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC1C7602F633C2CDEULL,
		0x8D1A436FA2C3CFFAULL,
		0x7A6AF53D6AEC3345ULL,
		0x1DFAE67D2418128FULL,
		0x09456325EFD762C3ULL,
		0x2FFBE253C37B0855ULL,
		0xC188955CEBE0CEFEULL,
		0xEB62AAB2CD3A5AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9046AB106AD0EEC3ULL,
		0xA7BEE409CDF42512ULL,
		0x26413FB58B89D867ULL,
		0x704919C7C1D758ECULL,
		0x45CBBF8E7D26CCD7ULL,
		0xBE1E82E96542A0F4ULL,
		0xD20CA936F64A83BAULL,
		0x7D57FA0BA5D0FC50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5181CB3F09ECC21DULL,
		0x2AA4A7666F37EAE8ULL,
		0x5C2BCA88E165EB22ULL,
		0x6DB3FFBAE5CF4A63ULL,
		0x4C8EDCAB92F1AE14ULL,
		0x91E560BAA639A8A1ULL,
		0x13843C6A1DAA4D44ULL,
		0x963550B968EAA693ULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x918CBE38937D1074ULL,
		0xA6973D166BFDF3FBULL,
		0x422BF29BB8B34124ULL,
		0xD23BBE8DD8E911BFULL,
		0xA9B8F6C56AB9B234ULL,
		0x2A4E2F82463E1AC1ULL,
		0x47B7D367D6937D6DULL,
		0x2EED91638A38865AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0772AEA4BEFD64AULL,
		0x6D64FE25D39CEA0EULL,
		0xF16EC5CD7CE2C45BULL,
		0x0F59BD393DDC7D20ULL,
		0xA76DCE026677DB71ULL,
		0xA738960CDF8F4A73ULL,
		0xC7C22E7FB9045668ULL,
		0x95BEEA3CFEE582B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71FB94D2D892C63EULL,
		0xCBF3C333B86119F5ULL,
		0xB3453756C451857FULL,
		0xDD6203B4E5356C9FULL,
		0x0ED538C70CCE6945ULL,
		0x8D76B98E99B150B2ULL,
		0x8075FD186F972B05ULL,
		0xBB537B5F74DD04E3ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x759C59E9D1D88674ULL,
		0xA250D62BF25AD55EULL,
		0x2F769786C03F5683ULL,
		0xA809626958C4D321ULL,
		0xAC9B1E06F65641E9ULL,
		0x61D91FEB7EEFC709ULL,
		0x622BA1ABEB22F3EDULL,
		0x7FE022A3C3136A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAC6AC92FD704045ULL,
		0xA1F2C0566C095EF4ULL,
		0x3017832DE2C76FCFULL,
		0xF007D95042C49272ULL,
		0x518140204D12AF3DULL,
		0xB1DCE7DD711C8979ULL,
		0xFF524274A03C78CDULL,
		0x66E4F241AD033184ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F5AF57B2CA8C631ULL,
		0x03A2167D9E538BAAULL,
		0x1F6114AB22F8394CULL,
		0x580EBB391A004153ULL,
		0xFD1A5E26BB44EED4ULL,
		0xD005F8360FF34E70ULL,
		0x9D79E3DF4B1E8B20ULL,
		0x1904D0E26E105BE5ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x040FE78FE54620C4ULL,
		0x4268D17A532B9215ULL,
		0x11BF15347A16994DULL,
		0xC2E046B37EAD3E1BULL,
		0x74F52A6584118E16ULL,
		0x0EC0C12F88ED33A5ULL,
		0xA4D17B26398B8F04ULL,
		0x2D5298004A9354D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0219F3582F445A5FULL,
		0x1426354BC563E48DULL,
		0x784CE0972FCDCB65ULL,
		0xC5C694B869296D83ULL,
		0xD650B113DA810D5BULL,
		0xCA59659297C89B9DULL,
		0xE3DC62CE38572F31ULL,
		0xAFF7B2E890705F20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x061614D7CA027A9BULL,
		0x564EE43196487698ULL,
		0x69F3F5A355DB5228ULL,
		0x0726D20B17845398ULL,
		0xA2A59B765E90834DULL,
		0xC499A4BD1F25A838ULL,
		0x470D19E801DCA035ULL,
		0x82A52AE8DAE30BF5ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAF15F609BC5CF143ULL,
		0xE60F8A000096BF7BULL,
		0x3E669E5E7FDEE4D5ULL,
		0x2B1240C4C63707EAULL,
		0x71E2FBE919F6740CULL,
		0x9B6C5AE77B527EAAULL,
		0x3CB14E145B54B475ULL,
		0x894CE456AFF60ED3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BAAEB46550AB59CULL,
		0xA46E6F157B1E0350ULL,
		0x72121227D4B92DF2ULL,
		0x11CA4978EE030A20ULL,
		0x891989B1C66C15A8ULL,
		0x3A89E1132AE1974BULL,
		0x9F7DB8D196008190ULL,
		0x3B3F3988FA61EC83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4BF1D4FE95644DFULL,
		0x4261E5157B88BC2BULL,
		0x4C748C79AB67C927ULL,
		0x3AD809BC28340DCAULL,
		0xF8FB7258DF9A61A4ULL,
		0xA1E5BBF451B3E9E1ULL,
		0xA3CCF6C5CD5435E5ULL,
		0xB273DDDE5597E250ULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBDBB67909E4EFC63ULL,
		0x52CD33ED01FF6409ULL,
		0x47AF2AA71C28C94FULL,
		0x6FE6194D5A17C28AULL,
		0xE28A5D476B4BA109ULL,
		0x11B2EA8A39703677ULL,
		0x4AC2CACCE6776C36ULL,
		0xDA0CBAB55FEFB431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27F41AF3FA0C6F90ULL,
		0xEC369C33DC9E5907ULL,
		0xBE063211F0DDA6E8ULL,
		0xE72635504AC0CC73ULL,
		0x7A11789F4A6DF1FEULL,
		0xC3A6283FD95610B0ULL,
		0xF6A63577B08F9C0EULL,
		0x34A19BBC1F0AB199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A4F7D63644293F3ULL,
		0xBEFBAFDEDD613D0EULL,
		0xF9A918B6ECF56FA7ULL,
		0x88C02C1D10D70EF9ULL,
		0x989B25D8212650F7ULL,
		0xD214C2B5E02626C7ULL,
		0xBC64FFBB56F8F038ULL,
		0xEEAD210940E505A8ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4FEAFD2C64F727BFULL,
		0x8EB8B85DC4DBB085ULL,
		0xE0572D531731A131ULL,
		0x0535D1D00CD1ED91ULL,
		0x8295F438F3FB7759ULL,
		0x266ADCF551DEB8B9ULL,
		0x0A2C5288F1756CC4ULL,
		0xB1F889F0BD891FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9222E2AD9A63B14ULL,
		0x07C51E2DB597982AULL,
		0x0B097E2A4C5D7A13ULL,
		0xC416BF35764851F7ULL,
		0xD311177F0AE08EC6ULL,
		0xF1D3DFE62BE4C8EBULL,
		0xF2D1EC2D037AF1B4ULL,
		0xFFF656629E5D2927ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6C8D306BD511CABULL,
		0x897DA670714C28AFULL,
		0xEB5E53795B6CDB22ULL,
		0xC1236EE57A99BC66ULL,
		0x5184E347F91BF99FULL,
		0xD7B903137A3A7052ULL,
		0xF8FDBEA5F20F9D70ULL,
		0x4E0EDF9223D436DAULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5A0A6BE018AD5718ULL,
		0x9067082B742D9437ULL,
		0x935AF3AA74A6D008ULL,
		0x1680525BCA9FFD4FULL,
		0xD5386D4FB4E6BE6FULL,
		0x32E8A11C7B8877EAULL,
		0x10A648F3ADCE2E4EULL,
		0x86FFBE516D3DD828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504789C61C8E0E9EULL,
		0x51A3C5B821EBEE61ULL,
		0x0B71478C4B893F69ULL,
		0x173443DC5262BE90ULL,
		0x0C5680225515B8BDULL,
		0x2F27059C60E13585ULL,
		0x9152F6BE5A453E2BULL,
		0xAF9912B6B1D0B25BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A4DE22604235986ULL,
		0xC1C4CD9355C67A56ULL,
		0x982BB4263F2FEF61ULL,
		0x01B4118798FD43DFULL,
		0xD96EED6DE1F306D2ULL,
		0x1DCFA4801B69426FULL,
		0x81F4BE4DF78B1065ULL,
		0x2966ACE7DCED6A73ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE68C11A0C61992ACULL,
		0x27B3AD5D29C69128ULL,
		0x3FF9FFC3789629DEULL,
		0x6775FD0E1451A3C4ULL,
		0x4D409F8CF1D9CF82ULL,
		0x746987964CE3A0DEULL,
		0xD88725EF110318B7ULL,
		0x60AB0A1CBCD12C12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E290887478A3E10ULL,
		0x8608A3B41B79D9FDULL,
		0xDBAC78F2C6BD29C5ULL,
		0xEB5E4935E608D0D9ULL,
		0xE9640E68E5B6D82CULL,
		0xF62E933CAED118D0ULL,
		0xB214A3A9F9711DCEULL,
		0x9C1E5F308AA6EF0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8A519278193ACBCULL,
		0xA1BB0EE932BF48D5ULL,
		0xE4558731BE2B001BULL,
		0x8C2BB43BF259731DULL,
		0xA42491E4146F17AEULL,
		0x824714AAE232B80EULL,
		0x6A938646E8720579ULL,
		0xFCB5552C3677C319ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x36C27A15E2C34080ULL,
		0xA34419A21759242DULL,
		0x2A22257D24EBB947ULL,
		0xFF3CF833306AB234ULL,
		0x34F336A612C438BCULL,
		0xFD3704F28044984DULL,
		0x7CABE3CDA4FCD336ULL,
		0xC983A7033257CCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66D2DDA99957CFDFULL,
		0x847494C7DB043080ULL,
		0x6F7B55BCC353EF36ULL,
		0xFD4AD11A30818EBFULL,
		0x080B4FE5D5A4479FULL,
		0x4A2CC656D5F661C9ULL,
		0xA4ACDE573B4EC4D9ULL,
		0x1293CD8A682C966AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5010A7BC7B948F5FULL,
		0x27308D65CC5D14ADULL,
		0x455970C1E7B85671ULL,
		0x0276292900EB3C8BULL,
		0x3CF87943C7607F23ULL,
		0xB71BC2A455B2F984ULL,
		0xD8073D9A9FB217EFULL,
		0xDB106A895A7B5ABEULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCE908DA0875BBBF2ULL,
		0xD5D657D250DBE7FDULL,
		0x422FC724859CA622ULL,
		0xC7D208B6F0AF0711ULL,
		0x764F57546BADA5EDULL,
		0x2973AF8A5920445EULL,
		0x85D9927657987C0CULL,
		0xD041A576CC39C748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8775EA7BBE14B15ULL,
		0x28E2DCFE0AF1225FULL,
		0xD53EDEF20012D110ULL,
		0x32EFCDC453BE30A0ULL,
		0x1148164AEE1E65B4ULL,
		0x38015A23125AEDC6ULL,
		0xE9AFF4C04BB97EC8ULL,
		0xDE6DB9D7F216372CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06E7D3073CBAF0E7ULL,
		0xFD348B2C5A2AC5A2ULL,
		0x971119D6858E7732ULL,
		0xF53DC572A31137B1ULL,
		0x6707411E85B3C059ULL,
		0x1172F5A94B7AA998ULL,
		0x6C7666B61C2102C4ULL,
		0x0E2C1CA13E2FF064ULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12A7533118C3BBF8ULL,
		0xD881F6E9DA38D71AULL,
		0xD06C30F340A196DCULL,
		0x77548D97AB74068EULL,
		0xE9E57BC554305E00ULL,
		0x684E3415D56AE48BULL,
		0x64684089B7FE0F2FULL,
		0x495169BAA0F8FBCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9405D8D9D9AD175DULL,
		0x7D9863F32CCA8E7DULL,
		0x122A54B9694C701DULL,
		0x5DF1172CED39D3D5ULL,
		0xD22A6FE3CBBFA18FULL,
		0x7AF4BFFF1EF9EEF5ULL,
		0xFB0F3A54BAA1B99DULL,
		0xEC2521E7B4107B20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86A28BE8C16EACA5ULL,
		0xA519951AF6F25967ULL,
		0xC246644A29EDE6C1ULL,
		0x2AA59ABB464DD55BULL,
		0x3BCF14269F8FFF8FULL,
		0x12BA8BEACB930A7EULL,
		0x9F677ADD0D5FB6B2ULL,
		0xA574485D14E880EAULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC9B3150E8F24CA67ULL,
		0x808CB4B37B4A4622ULL,
		0x78365B0EBDD13CB4ULL,
		0xE426BCDE0FC3A883ULL,
		0x1FDB68EF4AF281E1ULL,
		0x125065196BA51B47ULL,
		0x80E2FA5E8437EEF5ULL,
		0xEA0E3ED9FBC977C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x587A392051763F4DULL,
		0x43D8DB7F4DE56BE2ULL,
		0x23A71709AD1D7DEBULL,
		0x33CC81C35786A408ULL,
		0x4F53422F9CDB6F47ULL,
		0x8C3096B4D03990B5ULL,
		0xD3D5BEB0B3028B13ULL,
		0x0DD6852CE1F0BD74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C92C2EDE52F52AULL,
		0xC3546FCC36AF2DC0ULL,
		0x5B914C0710CC415FULL,
		0xD7EA3D1D58450C8BULL,
		0x50882AC0D629EEA6ULL,
		0x9E60F3ADBB9C8BF2ULL,
		0x533744EE373565E6ULL,
		0xE7D8BBF51A39CAB1ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCDE95B12EF5C05CBULL,
		0x45C50F3E44DB63E4ULL,
		0x3371845AC1A67476ULL,
		0xAEC3E1EDFD5D9468ULL,
		0x64366F169674D9D2ULL,
		0xED1E0EF98762A6D5ULL,
		0x97DC3F63EB1B7534ULL,
		0xF38F7CAD15F84875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE8EA7904B9F222ULL,
		0x0D9BE79D7DC88117ULL,
		0xFA944D4CD0FC026AULL,
		0x77D363CE09FB4E6DULL,
		0xD5276DBB1EB96A5BULL,
		0x67F9F11657076311ULL,
		0x97FC7A54972693FDULL,
		0xC00E1C5558495E45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9101B16BEBE5F7E9ULL,
		0x485EE8A33913E2F3ULL,
		0xC9E5C916115A761CULL,
		0xD9108223F4A6DA05ULL,
		0xB11102AD88CDB389ULL,
		0x8AE7FFEFD065C5C4ULL,
		0x002045377C3DE6C9ULL,
		0x338160F84DB11630ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x88C0FB84ECD73779ULL,
		0x863D04BC0FA690C8ULL,
		0x3C69FF9767EF0921ULL,
		0x7DE4A62B35BA3D2FULL,
		0x67B79553D6E2F51EULL,
		0x10EA99FA33D22832ULL,
		0x305093531A8C2AC2ULL,
		0xBB7665627A81C451ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C73AE02BA2DD75CULL,
		0x2C46999C5A2A738CULL,
		0x7ABD4FD79E8CA2D2ULL,
		0x74ABBDEA0489D129ULL,
		0x2A4F7D4617DF9464ULL,
		0x786C2D7289888D4AULL,
		0xF7A31A114E0D70B6ULL,
		0x3FEE47ACAE3CFDA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4B3558656FAE025ULL,
		0xAA7B9D20558CE344ULL,
		0x46D4B040F963ABF3ULL,
		0x094F1BC13133EC06ULL,
		0x4DF8E815C13D617AULL,
		0x6886B488BA5AA578ULL,
		0xC7F3894254815A74ULL,
		0x849822CED4BD39F0ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8484DCA3E80EFD29ULL,
		0x23771868EF11647AULL,
		0xC993A1262D838392ULL,
		0x9943C1F3AF28F285ULL,
		0x888B266C27710998ULL,
		0x7A3D668DC1D536E7ULL,
		0xD18494A0281A425FULL,
		0x9A7E0CCF2D517E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9889759DDAB50EECULL,
		0xBBE63DE15A819569ULL,
		0x6537119B2358DF29ULL,
		0x58076CBDEE80D922ULL,
		0x9B54C0722BACEF6DULL,
		0x99C7F02B057DCCB6ULL,
		0xCEC7ACE56CE0DC11ULL,
		0x61DA651FA0079748ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C0DA93E32BBF3C5ULL,
		0x98912589B590F113ULL,
		0xACA4B0BD0EDB5CBBULL,
		0xC144AD4E41A82BA7ULL,
		0x13DFE61E0CDDE6F5ULL,
		0xE3FA96A6C4A8FA51ULL,
		0x1F43384544FA9E4EULL,
		0xFBA469D08D56E955ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD2693C4A5D124CF0ULL,
		0x0DFAB43637D590C9ULL,
		0x379CF81DF0BD94C8ULL,
		0xF62FBFE3CE9C2839ULL,
		0xD84452F2BBD665FDULL,
		0x45624C436EFF1720ULL,
		0x8BAC7C42C003ED87ULL,
		0xFF1322150FE00922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50AC588C00D5BA4DULL,
		0xEAA0E541D49BE82CULL,
		0x1E6CC86A856887D9ULL,
		0x9582DDD32FB13879ULL,
		0x5CC46B2F3696193BULL,
		0x211D426DC7FC611CULL,
		0x0ED8801544B42BB3ULL,
		0x251C40825AFEA553ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82C564C65DC7F6BDULL,
		0xE75A5177E34E78E5ULL,
		0x29F0307775D51311ULL,
		0x63AD6230E12D1040ULL,
		0x848039DD8D407CC6ULL,
		0x647F0E2EA903763CULL,
		0x8574FC5784B7C634ULL,
		0xDA0F6297551EAC71ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8DA452D6F4A5EC41ULL,
		0xE242266261E38BA2ULL,
		0x6003D9A27B5DEBBAULL,
		0x45566D0BBFF55710ULL,
		0x6B2020A12933C345ULL,
		0xA07A59A7E9D87D5CULL,
		0x205E124A50422FBBULL,
		0x9DDEC55FEC270267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB31712765C955871ULL,
		0x4A718F2BCC8076BAULL,
		0x8DDFCD0FA19E963FULL,
		0xA9235022EE425805ULL,
		0x287265ED58F2EFF8ULL,
		0xB300892DE57DF2B0ULL,
		0xFCBECCB7E0D9A0B5ULL,
		0x3DF369D788A6CBD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EB340A0A830B430ULL,
		0xA833A949AD63FD18ULL,
		0xEDDC14ADDAC37D85ULL,
		0xEC753D2951B70F15ULL,
		0x4352454C71C12CBDULL,
		0x137AD08A0CA58FECULL,
		0xDCE0DEFDB09B8F0EULL,
		0xA02DAC886481C9B5ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8395CE52F1C31646ULL,
		0x05E5BF83AC488DA4ULL,
		0x4A98B6DFC5B4CB5FULL,
		0xF977719F7640458CULL,
		0x27F6834C1A5F4D2FULL,
		0xD188ADBD81B44720ULL,
		0xFFBBAA290B823328ULL,
		0x32F7EB837DA6F386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEA34C08CFFA7A07ULL,
		0x499B42B34FBC348FULL,
		0x029F3489C2890424ULL,
		0x3022DFC277A7D20CULL,
		0x109271CCB29DB2D1ULL,
		0x0AB87CDEB8F555EDULL,
		0x943460F34651B870ULL,
		0xCA29B841AF4638C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D36825A3E396C41ULL,
		0x4C7EFD30E3F4B92BULL,
		0x48078256073DCF7BULL,
		0xC955AE5D01E79780ULL,
		0x3764F280A8C2FFFEULL,
		0xDB30D163394112CDULL,
		0x6B8FCADA4DD38B58ULL,
		0xF8DE53C2D2E0CB41ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC622B415E0DF6B83ULL,
		0x958C384D00FBDCD3ULL,
		0xEF9AC7679E0CA1CFULL,
		0x8A04516F4C2E16B5ULL,
		0xFD52537F40E75D11ULL,
		0xC3A738E7871E1697ULL,
		0xC7ACF22278E3EEB3ULL,
		0x002224F1600B7331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CF13285643A710ULL,
		0xFDE8A85C8B94EBA2ULL,
		0xD15CD40198943508ULL,
		0x7829A9BDA3C5F339ULL,
		0x7AD933DA7C8F3830ULL,
		0xD9CDD0C8D8AA068CULL,
		0x66801DD400FA4EDAULL,
		0x4007F0295EFE27FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77EDA73DB69CCC93ULL,
		0x686490118B6F3771ULL,
		0x3EC61366069894C7ULL,
		0xF22DF8D2EFEBE58CULL,
		0x878B60A53C686521ULL,
		0x1A6AE82F5FB4101BULL,
		0xA12CEFF67819A069ULL,
		0x4025D4D83EF554CAULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9F53902B55D36DB8ULL,
		0x591C011032CA9598ULL,
		0xFB86FC3F42D0CA8EULL,
		0x21679540EB532678ULL,
		0x5CF05C982D94BCD4ULL,
		0x73FBB7A52AB01A8FULL,
		0x4B24631F43A8B022ULL,
		0x56521DBA8BD7652DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A3DFA06D46C5662ULL,
		0xDAE5E7787720DB1FULL,
		0x810AB9ECDFCECAB1ULL,
		0x39F6C8E5677418E7ULL,
		0x7BB8D393D285F494ULL,
		0xC3D53C6D9B682E28ULL,
		0x3C91CBD70CA34F56ULL,
		0x9FDAAA93450ED58EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x956E6A2D81BF3BDAULL,
		0x83F9E66845EA4E87ULL,
		0x7A8C45D39D1E003FULL,
		0x18915DA58C273E9FULL,
		0x27488F0BFF114840ULL,
		0xB02E8BC8B1D834A7ULL,
		0x77B5A8C84F0BFF74ULL,
		0xC988B729CED9B0A3ULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC002DA2A56B50BF4ULL,
		0x81D3EC00681ECCA6ULL,
		0x960DBA49742F08BDULL,
		0x8A55EA3903D2E370ULL,
		0xF0D3D6BDA154AA3DULL,
		0x9362F02A5B2A80F9ULL,
		0x3282B6E662BDDA16ULL,
		0xD097948C22D3861DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB128B0B2606551ULL,
		0xEE0C855B30093522ULL,
		0x2BEB9C3D08A10C92ULL,
		0xA6308FC364001778ULL,
		0xD5A7F0F242789376ULL,
		0x95EDB93ADBF585FAULL,
		0x9325FABA74E0DE3DULL,
		0x662CF43B8D5DAF1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FB3F29AE4D56EA5ULL,
		0x6FDF695B5817F984ULL,
		0xBDE626747C8E042FULL,
		0x2C6565FA67D2F408ULL,
		0x2574264FE32C394BULL,
		0x068F491080DF0503ULL,
		0xA1A74C5C165D042BULL,
		0xB6BB60B7AF8E2907ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4CC2CF2C9F3061E4ULL,
		0x092FE617A5E51DBBULL,
		0xF9A4E53F45BAB631ULL,
		0x49BCF8E1D64F7687ULL,
		0xB3C3F2A03B4327B2ULL,
		0x8098EDCA4E702C23ULL,
		0xC8EF88CBB41FAAD0ULL,
		0x7E161E5606DEA500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5909B5A4E79D9E29ULL,
		0xA1B9F68243422270ULL,
		0x247CA347801D5A9CULL,
		0x30A19D97D5D63DA8ULL,
		0x0C8B0CEF15DE1744ULL,
		0x5B886A57F6ADF6D1ULL,
		0x4227975133F7929AULL,
		0x49239C260D541CECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15CB7A8878ADFFCDULL,
		0xA8961095E6A73FCBULL,
		0xDDD84678C5A7ECADULL,
		0x791D657603994B2FULL,
		0xBF48FE4F2E9D30F6ULL,
		0xDB10879DB8DDDAF2ULL,
		0x8AC81F9A87E8384AULL,
		0x373582700B8AB9ECULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC4B4E4875619D3F4ULL,
		0x5BB18893A8015FC8ULL,
		0xE6714F044CDB90EDULL,
		0x950499D2B1064CE4ULL,
		0xAD948345266A6AAAULL,
		0x22EB4F69CD858EC2ULL,
		0x88D85E37D23B8478ULL,
		0x941A82AB1CB926B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54DBC08A332DCD84ULL,
		0x15C88A1BF1D4B8A5ULL,
		0x48C6B8815EC1977DULL,
		0x4E1FB07C502C3BABULL,
		0x2952C137A2960595ULL,
		0xD02C59C5552BDEE7ULL,
		0x5451CBA933809C62ULL,
		0x8573AB64269A01CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x906F240D65341E70ULL,
		0x4E79028859D5E76DULL,
		0xAEB7F785121A0790ULL,
		0xDB1B29AEE12A774FULL,
		0x84C6427284FC6F3FULL,
		0xF2C716AC98AE5025ULL,
		0xDC89959EE1BB181AULL,
		0x116929CF3A232778ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEB01176EC586A714ULL,
		0x00C668370F65BDD2ULL,
		0xD0C5827299D08D13ULL,
		0x433FDB7B8C7D5BE8ULL,
		0x85C3CBA42D579785ULL,
		0x2C1794048D9331EBULL,
		0x558C9F84D5FD8111ULL,
		0xDD74C84762AB5639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x919A67FA30648FBBULL,
		0x0DAA1A5CBE6ADED4ULL,
		0x0DFD586B8BD405A9ULL,
		0xF6F50AC8BC3F9EE2ULL,
		0x503796049C2BA2C0ULL,
		0x65A6D7F162392C17ULL,
		0xA852409EC7AC2F24ULL,
		0x94042482E6F60282ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A9B7094F5E228AFULL,
		0x0D6C726BB10F6306ULL,
		0xDD38DA19120488BAULL,
		0xB5CAD1B33042C50AULL,
		0xD5F45DA0B17C3545ULL,
		0x49B143F5EFAA1DFCULL,
		0xFDDEDF1A1251AE35ULL,
		0x4970ECC5845D54BBULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x04E4029B63927632ULL,
		0x02EAF223E30D4077ULL,
		0x9672FC8B2C208F77ULL,
		0xC5AB43AA1B476F6EULL,
		0x27DD8E909643C36DULL,
		0xB236432A045B773FULL,
		0xB35AF13F835A9B88ULL,
		0xCD946825255AAB8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4390A55B731E1EA2ULL,
		0x1567839E32722FD2ULL,
		0x12C7DDC3BFD65E3FULL,
		0x4A8FCA36CB148F1EULL,
		0x620465CAC7C8EAD2ULL,
		0x208CEF1048FED282ULL,
		0x7D5CF9083E5BA7F6ULL,
		0x831DF2DD3D154272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4774A7C0108C6890ULL,
		0x178D71BDD17F6FA5ULL,
		0x84B5214893F6D148ULL,
		0x8F24899CD053E070ULL,
		0x45D9EB5A518B29BFULL,
		0x92BAAC3A4CA5A5BDULL,
		0xCE060837BD013C7EULL,
		0x4E899AF8184FE9F8ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE9E35740206D5D54ULL,
		0x2CEAAD0C9A6383F4ULL,
		0x4C4305C6858C228AULL,
		0x471BCC350DB68012ULL,
		0x243FBC717F763E41ULL,
		0xDC3D8F5B4C29F5ADULL,
		0x34994467EBB96F80ULL,
		0xFB6EDF4003AB79EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A5360DE3E44848ULL,
		0x1AB2BAFC50D7AA55ULL,
		0x075157672B40D67CULL,
		0x019DDA28DDD4D76EULL,
		0xDE844DA4EAC2D6A6ULL,
		0x98F56EF072914109ULL,
		0xA9CA57EE7D6420D8ULL,
		0x8385F2D24FFE967AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE46614DC389151CULL,
		0x365817F0CAB429A1ULL,
		0x4B1252A1AECCF4F6ULL,
		0x4686161DD062577CULL,
		0xFABBF1D595B4E8E7ULL,
		0x44C8E1AB3EB8B4A4ULL,
		0x9D53138996DD4F58ULL,
		0x78EB2D924C55EF91ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x43EFF772A26CB7C4ULL,
		0xB0E257B87ACDB73AULL,
		0x0351CCFA0E689784ULL,
		0x9D445797BF15EA93ULL,
		0xF304FBF3CC50DD91ULL,
		0x735FC6F2786B3169ULL,
		0xD8BC95928D913935ULL,
		0xCDCC0AAE7DA6A9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98158D78B2386999ULL,
		0x9AC302F4D907E077ULL,
		0xFB1C1F785CE43AEEULL,
		0x17277C714494F304ULL,
		0x25DCA83E17223A41ULL,
		0xBF7CA918394EF1C4ULL,
		0xC9DE27DFD795D5B6ULL,
		0x9C900023B745A5D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBFA7A0A1054DE5DULL,
		0x2A21554CA3CA574DULL,
		0xF84DD382528CAD6AULL,
		0x8A632BE6FB811997ULL,
		0xD6D853CDDB72E7D0ULL,
		0xCC236FEA4125C0ADULL,
		0x1162B24D5A04EC83ULL,
		0x515C0A8DCAE30C01ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9147B284B39606D0ULL,
		0x00365FA8DABBF750ULL,
		0xAB74FC11F8DAD750ULL,
		0x0DC3C36FC79CBCE2ULL,
		0x9E24D1F679ABB7F8ULL,
		0xF7904AC5511A5338ULL,
		0xBCB3B74EB4651C4FULL,
		0x5C4265B185AAE443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x748C8AFEABCD376EULL,
		0xF1A090DF7669D94AULL,
		0xF6D75202119890C9ULL,
		0x6047FCA4C508442DULL,
		0xB1056B1767FBA33DULL,
		0xA7BB220B19D3A56DULL,
		0xCF7650BAD6B6C2CCULL,
		0x7F169DCC234BF3ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5CB387A185B31BEULL,
		0xF196CF77ACD22E1AULL,
		0x5DA3AE13E9424799ULL,
		0x6D843FCB0294F8CFULL,
		0x2F21BAE11E5014C5ULL,
		0x502B68CE48C9F655ULL,
		0x73C5E7F462D3DE83ULL,
		0x2354F87DA6E117E8ULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x53507EB0A3E9B1C7ULL,
		0xFDCC3B63844AE2CFULL,
		0x6AE8EAF7F2A55F04ULL,
		0x1692734971389F36ULL,
		0x2F194F88EACDCB9FULL,
		0x651655A2E2B7AD0DULL,
		0xB25C6D58D5A8CD84ULL,
		0x24194AC385BD94DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61FCC0A49E13163FULL,
		0x74FD5D5AF593D16DULL,
		0x684C2CE71ECF0642ULL,
		0xE73F081EB592BFA9ULL,
		0x6D1B3F10C5A82F91ULL,
		0x9E7079DA82CD1667ULL,
		0x84C001E9CCD07030ULL,
		0x63A1B870315E3498ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32ACBE143DFAA7F8ULL,
		0x8931663971D933A2ULL,
		0x02A4C610EC6A5946ULL,
		0xF1AD7B57C4AA209FULL,
		0x420270982F65E40EULL,
		0xFB662C78607ABB6AULL,
		0x369C6CB11978BDB4ULL,
		0x47B8F2B3B4E3A045ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x70D35E75C16DF817ULL,
		0x22ADE3538793F569ULL,
		0x3D908C023B2B36B7ULL,
		0xAF12ABC6EC233808ULL,
		0x9D9D676A474EBF0EULL,
		0x607A11F4E3D3D3FFULL,
		0x7DBB3A1062068A7DULL,
		0x4257DBCE92F6B548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA337C9D69BB04068ULL,
		0xB5F7C701F14A6BDBULL,
		0x4CAF605BB0DDC3FFULL,
		0x7E552E974F9D1166ULL,
		0x3A92C8E58811456AULL,
		0xFCDD376FA0F39D44ULL,
		0xFD5AE0012810A96EULL,
		0xF01B719FBA70526CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3E497A35ADDB87FULL,
		0x975A245276D99EB2ULL,
		0x713FEC598BF6F548ULL,
		0xD1478551A3BE296EULL,
		0xA70FAF8FCF5FFA64ULL,
		0x9CA7269B43204EBBULL,
		0x80E1DA114A162313ULL,
		0xB24CAA512886E724ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8B0E19CCBF5D7B86ULL,
		0x7673AF4E4E1777FEULL,
		0xCF30A8034847EE2FULL,
		0xD7A70F3ECEA51ACEULL,
		0xDFFC1E248752C263ULL,
		0x28A5E56A75B203B0ULL,
		0xC38A007FEDA95635ULL,
		0xF92C9772837E0B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF837B5AF579D5431ULL,
		0x00B47A6FB4B96935ULL,
		0x76EA90C466DECD23ULL,
		0x57180E7480742E00ULL,
		0x05038CB350014991ULL,
		0xB7BE33D978738DA6ULL,
		0xC60D19085DB5E1D7ULL,
		0x51915B23D865EE2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7339AC63E8C02FB7ULL,
		0x76C7D521FAAE1ECBULL,
		0xB9DA38C72E99230CULL,
		0x80BF014A4ED134CEULL,
		0xDAFF9297D7538BF2ULL,
		0x9F1BD6B30DC18E16ULL,
		0x05871977B01CB7E2ULL,
		0xA8BDCC515B1BE505ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDD72B4EE7AA02E3DULL,
		0xC9A20BA107FA25F9ULL,
		0xFC464711AD8DDF31ULL,
		0x535CDD992922F249ULL,
		0xA81F9D2570B8E44DULL,
		0x7906FF958630B0D9ULL,
		0x3F1CAE23AC9B8D6AULL,
		0x6BF3BBACAA613253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95DB0A43D5BC44B2ULL,
		0x3F9FDF040EBA3340ULL,
		0x4D345D15E1E4BD4CULL,
		0x8D18C82276369E6DULL,
		0xFD1CA05AC6872257ULL,
		0x19AB06337A62641BULL,
		0x1ADF5506D142B418ULL,
		0x853E31A9839A7672ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48A9BEADAF1C6A8FULL,
		0xF63DD4A5094016B9ULL,
		0xB1721A044C69627DULL,
		0xDE4415BB5F146C24ULL,
		0x55033D7FB63FC61AULL,
		0x60ADF9A6FC52D4C2ULL,
		0x25C3FB257DD93972ULL,
		0xEECD8A0529FB4421ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE65DD79B48DD2F40ULL,
		0x5B0E6DE6820C1C24ULL,
		0x25C7FB9D349901AAULL,
		0x937819C49DD532DEULL,
		0x190EDF1DA836AC22ULL,
		0x7F4068565E7AD350ULL,
		0x13D5A6F058B3C447ULL,
		0x4059D25E866A4F2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB57BB4D79698388ULL,
		0x9EEFEBE72DB3C1E7ULL,
		0x34054E487A17052EULL,
		0xD6F0A0C31026B070ULL,
		0xC0CCF3CB2555B439ULL,
		0xA796EB839EED165DULL,
		0x7E506648034891FDULL,
		0xBCBA6CCD34B12DFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D0A6CD631B4ACC8ULL,
		0xC5E18601AFBFDDC3ULL,
		0x11C2B5D54E8E0484ULL,
		0x4588B9078DF382AEULL,
		0xD9C22CD68D63181BULL,
		0xD8D683D5C097C50DULL,
		0x6D85C0B85BFB55BAULL,
		0xFCE3BE93B2DB62D2ULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1C3AF18872892178ULL,
		0x3C897BCC6DB85412ULL,
		0x977E91DAC2A5239CULL,
		0x9CDCEA69E2B07605ULL,
		0xED6434D2DF54C018ULL,
		0x2ACCEDA5D76A24E8ULL,
		0xB90463A57D7917D0ULL,
		0xCD66021D5AF80839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC494FF730B4B1D1ULL,
		0x7D27A2A7A14D41DDULL,
		0xB6F0E6ED163C37D3ULL,
		0xA9CA43CE562D5F97ULL,
		0xA70A6C2A7090AE3CULL,
		0xDBA9190F08FC124FULL,
		0xCCEE0648581EF76EULL,
		0x7CDD5304A6C5AE5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF073BE7F423D90A9ULL,
		0x41AED96BCCF515CFULL,
		0x218E7737D499144FULL,
		0x3516A9A7B49D2992ULL,
		0x4A6E58F8AFC46E24ULL,
		0xF165F4AADF9636A7ULL,
		0x75EA65ED2567E0BEULL,
		0xB1BB5119FC3DA667ULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6305016620EFF98CULL,
		0xE5F0F03F4F70AC1EULL,
		0x9B2463BFBD230876ULL,
		0xB8D20158639AD71DULL,
		0x38303DBDC71048D2ULL,
		0xA8FB8878B34BC629ULL,
		0x66ABF13081E04CADULL,
		0xBD4B5EDE1F60E344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6F5DECA226D5CAULL,
		0xF94F3B34D580992CULL,
		0x2250A40BF599798FULL,
		0x2DE1FA53C21F4504ULL,
		0xF390CA04B712BD8BULL,
		0x5ABED626D8AF4D9AULL,
		0x2ECA4C0F497EA754ULL,
		0x81F216219F0323C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E6A5C8A82C92C46ULL,
		0x1CBFCB0B9AF03532ULL,
		0xB974C7B448BA71F9ULL,
		0x9533FB0BA1859219ULL,
		0xCBA0F7B97002F559ULL,
		0xF2455E5E6BE48BB3ULL,
		0x4861BD3FC89EEBF9ULL,
		0x3CB948FF8063C080ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC763B1ED19CC9FCEULL,
		0xD18A2B97DCCB57C6ULL,
		0xAFB734BA22705940ULL,
		0x438489CA824C8153ULL,
		0x77297B4A49DDD9B5ULL,
		0x15E0CC9BA9D12445ULL,
		0x2951BF0276AA85BCULL,
		0x93CA6CA86734F5C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18900EFB1EFB336EULL,
		0x0594B3286051BD61ULL,
		0xBF5266EB0DA286ABULL,
		0xBAF4AB88D3815F2AULL,
		0xDEB11B3D9DCE34F3ULL,
		0x41635BB6F021AC0CULL,
		0x6B8A3C489C3CEE7EULL,
		0x62127C63E2B0CAB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFF3BF160737ACA0ULL,
		0xD41E98BFBC9AEAA7ULL,
		0x10E552512FD2DFEBULL,
		0xF970224251CDDE79ULL,
		0xA9986077D413ED46ULL,
		0x5483972D59F08849ULL,
		0x42DB834AEA966BC2ULL,
		0xF1D810CB85843F76ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0AEDA970FD325945ULL,
		0x2C9B5D0FE5D61AF6ULL,
		0xB090596A358AA41FULL,
		0x9E46C74718799D1AULL,
		0x27C6B6C61C17EFDBULL,
		0x72687EC6419B9BD2ULL,
		0xF8C1284FF3D1B47CULL,
		0x07280BADDFEC50CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA8FDD8D4AB11800ULL,
		0x1983C434396CF3B4ULL,
		0xCE754D1A3BD854D8ULL,
		0x74C3EE6D4F39FB9AULL,
		0xC5D1A45A1BD23C9CULL,
		0x04F7DBFE1649F8F6ULL,
		0xA76C265D79864303ULL,
		0x3553D68233C46FFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC06274FDB7834145ULL,
		0x3518993BDCBAE942ULL,
		0x7EE514700E52F0C7ULL,
		0xEA85292A57406680ULL,
		0xE217129C07C5D347ULL,
		0x769FA53857D26324ULL,
		0x5FAD0E128A57F77FULL,
		0x327BDD2FEC283F32ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB8A6196973A9146DULL,
		0xBCFF15E49E63D72BULL,
		0xA5C026F0848889BAULL,
		0x63F9E3327F3D6131ULL,
		0x1C6632DF184E0A61ULL,
		0x79FE85737972D2FAULL,
		0x294B8DCC0714A228ULL,
		0xE863939D6964F5F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D90DBA4931E13D4ULL,
		0x92BA375E6A3E21E8ULL,
		0x9EC4D9BCF8F71ED6ULL,
		0x6537234DDB40D9ACULL,
		0x647F58AABC1669E7ULL,
		0x0D3773104D975819ULL,
		0xF7B8770D88CD9E64ULL,
		0x7C0C10F9E203288AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA536C2CDE0B707B9ULL,
		0x2E4522BAF45DF6C3ULL,
		0x3B04FF4C7C7F976CULL,
		0x06CEC07FA47DB89DULL,
		0x78196A75A4586386ULL,
		0x74C9F66334E58AE3ULL,
		0xDEF3FAC18FD93C4CULL,
		0x946F83648B67DD7CULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5CCE42513A31247ULL,
		0x28648F13E39BA0FBULL,
		0x5785794BCA3601DDULL,
		0x4481C7728DF38CAEULL,
		0xE11124DF7129ABFCULL,
		0x17F936A61B79E544ULL,
		0x82596DA8575ABDCEULL,
		0x2A4EF4F087BD382FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81EE3CA5A9EFD8E9ULL,
		0x32A21CE8D2BF3EDDULL,
		0xC13772BC9C4A8981ULL,
		0x0C2A91A7E00D9765ULL,
		0x19A970122AF8DD7DULL,
		0x8ED4856E3A8C91E3ULL,
		0x81258D26437C17E0ULL,
		0xDD78FAEAE04935DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2422D880BA4CCAAEULL,
		0x1AC693FB31249E26ULL,
		0x96B20BF7567C885CULL,
		0x48AB56D56DFE1BCBULL,
		0xF8B854CD5BD17681ULL,
		0x992DB3C821F574A7ULL,
		0x037CE08E1426AA2EULL,
		0xF7360E1A67F40DF3ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x725F3CA82C4471EDULL,
		0xC3C823A4E9C3477FULL,
		0xFF6D9A289403EE5BULL,
		0xF669290515713935ULL,
		0xE180C07BE234D19FULL,
		0xCC27DBD00B3B48D1ULL,
		0xB66C9A738B120523ULL,
		0x3AFF67B8F781A0DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FD31D957B11F35ULL,
		0x081CADC7890F1B31ULL,
		0xD0DBEE7FE90308BDULL,
		0xCA0AA5543659D9D5ULL,
		0x43D8161F90FE9272ULL,
		0x961775F50185C3E7ULL,
		0x0906FCB3A0F9722CULL,
		0xE24ADD1911551E27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83A20D717BF56ED8ULL,
		0xCBD48E6360CC5C4EULL,
		0x2FB674577D00E6E6ULL,
		0x3C638C512328E0E0ULL,
		0xA258D66472CA43EDULL,
		0x5A30AE250ABE8B36ULL,
		0xBF6A66C02BEB770FULL,
		0xD8B5BAA1E6D4BEFAULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFD281E41AD18577DULL,
		0xA2AFBEACDCAA1FA5ULL,
		0x6D299A43BB91D788ULL,
		0x0E892963107FC75FULL,
		0xB03BDAE49B7134D4ULL,
		0x010DF74CF08FDA54ULL,
		0x74602E05BA90F2D6ULL,
		0x61F93BE437D4F03BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F7A97B85BDA301CULL,
		0x4D035D9A5D44C13BULL,
		0x91607C15967BBC19ULL,
		0x3C57F17892B2CD85ULL,
		0x9B723EDF26A739D0ULL,
		0x975201E78585572BULL,
		0xFAC9A410FD7C4E86ULL,
		0x271E9F80DB4E4D1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x725289F9F6C26761ULL,
		0xEFACE33681EEDE9EULL,
		0xFC49E6562DEA6B91ULL,
		0x32DED81B82CD0ADAULL,
		0x2B49E43BBDD60D04ULL,
		0x965FF6AB750A8D7FULL,
		0x8EA98A1547ECBC50ULL,
		0x46E7A464EC9ABD24ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8FD4954AAEAC63E2ULL,
		0xD508A831620282C5ULL,
		0x2A34A4612015508EULL,
		0x26100B630AE54EE5ULL,
		0x5D25B4C6DD5D71CEULL,
		0x7887448DA2B6E192ULL,
		0x56CFBCD45D20465CULL,
		0xB090BF48B81687BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52D7EF841A2E390DULL,
		0x971098E35EE494CAULL,
		0x86B2B4F2477BC825ULL,
		0x36A7E1919514AFE2ULL,
		0xE2080E59C42714CFULL,
		0xF04D9CEE7AF7CDF6ULL,
		0x11585E6284691CF3ULL,
		0xD016C520A932F053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD037ACEB4825AEFULL,
		0x421830D23CE6160FULL,
		0xAC861093676E98ABULL,
		0x10B7EAF29FF1E107ULL,
		0xBF2DBA9F197A6501ULL,
		0x88CAD863D8412C64ULL,
		0x4797E2B6D9495AAFULL,
		0x60867A68112477EEULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x68F56851B122EC2BULL,
		0x813ABD9CC9B3EE8CULL,
		0x4CEF0C1F91090866ULL,
		0x252AD747C049A2DAULL,
		0x72DDC4A8EE63ECF7ULL,
		0x38D2787E0CF1DD70ULL,
		0x0889C56E4B16965BULL,
		0x654B227783FF2000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC163F6D8A6A263A9ULL,
		0x5BFFDB15DF7A4A07ULL,
		0xF210384AE782DADEULL,
		0xED0891A0828C1A34ULL,
		0x86A9C2E754A34934ULL,
		0x5BC6138FCA451864ULL,
		0xBE15C94192AB81C1ULL,
		0xE35ED8F786A7514AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9969E8917808F82ULL,
		0xDAC5668916C9A48BULL,
		0xBEFF3455768BD2B8ULL,
		0xC82246E742C5B8EEULL,
		0xF474064FBAC0A5C3ULL,
		0x63146BF1C6B4C514ULL,
		0xB69C0C2FD9BD179AULL,
		0x8615FA800558714AULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE2EB36CFFC758830ULL,
		0xF04AC9FCFF97CF50ULL,
		0x8D408165EE0478C0ULL,
		0xBAD0E0E5E0FC88ECULL,
		0x3249099AE6AC78E8ULL,
		0x1C3D243FEF13985EULL,
		0x77A0334A519A6BDDULL,
		0x85FFAB1C4D02311DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE64DCFFFD9CB495CULL,
		0xAB4B8AC8E3569AF7ULL,
		0x8D3827BEDEC6049DULL,
		0xDBF357A501619E25ULL,
		0x06947AA564E2DDCCULL,
		0xAC981961F9BC6668ULL,
		0x4171895622EEAB21ULL,
		0x7707AD98E2B04A86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A6F93025BEC16CULL,
		0x5B0143341CC155A7ULL,
		0x0078A6DB30C27C5DULL,
		0x6123B740E19D16C9ULL,
		0x34DD733F824EA524ULL,
		0xB0A53D5E16AFFE36ULL,
		0x36D1BA1C7374C0FCULL,
		0xF2F80684AFB27B9BULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x61ABEE0A39E916E3ULL,
		0x1EAA474848B6CE11ULL,
		0x743032DB9B3BA1B7ULL,
		0x405E9D1FA1B02EF4ULL,
		0xB340EA79E3807905ULL,
		0x16C1C5F2364C3C4FULL,
		0x53BF131226AD7A82ULL,
		0x7F636752EE0C4D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED6B8A0A7124614BULL,
		0xEDF855D99A6404CEULL,
		0xBE87FDF0B74C4FF8ULL,
		0x2DF15E59A67E5D1FULL,
		0xF10D29AC2836733FULL,
		0x3293B97137912B87ULL,
		0x75C88ACE0139951BULL,
		0x9C9C7A21B6CBBCABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CC0640048CD77A8ULL,
		0xF3521291D2D2CADFULL,
		0xCAB7CF2B2C77EE4FULL,
		0x6DAFC34607CE73EBULL,
		0x424DC3D5CBB60A3AULL,
		0x24527C8301DD17C8ULL,
		0x267799DC2794EF99ULL,
		0xE3FF1D7358C7F1A9ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9ACAF188FFC442A9ULL,
		0x289F8E974E6C8300ULL,
		0x8315EC150A8FBD25ULL,
		0xF0A07CF3F1C9659FULL,
		0xEA17A78822CC785BULL,
		0xA1B9C05895C04604ULL,
		0xE5980C37B1CCBE6FULL,
		0x078446DF7BC03D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D99832E3A91319ULL,
		0x8329489E37027B2AULL,
		0x7248A1CB0635F2C4ULL,
		0xE379E04FAB61337BULL,
		0x1571940A8DC14E98ULL,
		0x212E66E04DB190DAULL,
		0xA41414D18FF2491AULL,
		0x50BA81134B1DFDB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF1369BA1C6D51B0ULL,
		0xABB6C609796EF82AULL,
		0xF15D4DDE0CBA4FE1ULL,
		0x13D99CBC5AA856E4ULL,
		0xFF663382AF0D36C3ULL,
		0x8097A6B8D871D6DEULL,
		0x418C18E63E3EF775ULL,
		0x573EC7CC30DDC08AULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1B3FED9A68101F95ULL,
		0x245130C37E07845EULL,
		0x6A36EB9B31BC714FULL,
		0x9BAF677DE7F5FA77ULL,
		0xF7013BA29FBBA2F9ULL,
		0xE00DC0B19C01B475ULL,
		0x7E7C6408A3DFB238ULL,
		0x5E46082C54A15AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8EE7E8CDD58FFEULL,
		0x0E27246364C8C3EEULL,
		0x0CFA1D8E3A4E5953ULL,
		0x280088B40910684BULL,
		0xE509933EF7337433ULL,
		0xC5169F6A37551C9AULL,
		0x88673E022EF40CACULL,
		0x563884129E1193ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0B10A72A5C5906BULL,
		0x2A7614A01ACF47B0ULL,
		0x66CCF6150BF2281CULL,
		0xB3AFEFC9EEE5923CULL,
		0x1208A89C6888D6CAULL,
		0x251B5FDBAB54A8EFULL,
		0xF61B5A0A8D2BBE94ULL,
		0x087E8C3ECAB0C956ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x766DD1810945E20DULL,
		0xF69D020B79427509ULL,
		0x77F0A34DBEB4F4BDULL,
		0x8DAE17A6F1868035ULL,
		0xA3225E440AF6759FULL,
		0xFF1DFB761E6024A2ULL,
		0x3F1BBD047049A28BULL,
		0x65CCB196C4A97228ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6FB31975EDB0899ULL,
		0x0CB1DD50308CFCF8ULL,
		0x0EF4C86BBF2FD2CBULL,
		0x73B3E1B447FB7D12ULL,
		0xE8EEA48B1DBDEC85ULL,
		0xCA3847003EB81B39ULL,
		0x8098357C02B2BCC1ULL,
		0xCD9996A22F6FDF4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC096E016579EEA94ULL,
		0xFA2CDF5B49CE89F1ULL,
		0x79046B26019B2676ULL,
		0xFE1DF612B67DFD27ULL,
		0x4BCCFACF174B991AULL,
		0x3525BC7620D83F9BULL,
		0xBF83887872FB1E4AULL,
		0xA8552734EBC6AD62ULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFD2592C19161C657ULL,
		0x30F84D86D0613B2DULL,
		0x6742DBB3BECFBF76ULL,
		0x64388771D1336597ULL,
		0xC8BED019987C0F58ULL,
		0xE5B3CA3EA67315D8ULL,
		0xFBF2FA64E2FE4A55ULL,
		0xB6A5899B28D4719CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB84E6CADA22E108CULL,
		0xC324AE3102C01A20ULL,
		0xCC7D71ECE676DA9FULL,
		0x215B93838471DCBAULL,
		0x3688C709A4EAE86BULL,
		0xD526B1B814FF403BULL,
		0x26961A1D7F10E620ULL,
		0xBB07D4230417E5DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x456BFE6C334FD6DBULL,
		0xF3DCE3B7D2A1210DULL,
		0xAB3FAA5F58B965E9ULL,
		0x456314F25542B92DULL,
		0xFE3617103C96E733ULL,
		0x30957B86B28C55E3ULL,
		0xDD64E0799DEEAC75ULL,
		0x0DA25DB82CC39440ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5EB0737E84B83A1EULL,
		0xA0D9BAF88F523ACFULL,
		0x7D5D42B7FB3EA91BULL,
		0xA650EF87FBCFAE69ULL,
		0x5D03D67D379194E9ULL,
		0xD90BE818064A4FB3ULL,
		0xB87027615900017DULL,
		0x5FBC0D19DEFE7630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA769E2E4D5823EULL,
		0x0D7EBAC11AA6D065ULL,
		0x9A7BB63466271667ULL,
		0xA26922F61A5C969FULL,
		0x20E208C138884AC1ULL,
		0x12389BFD09302FCFULL,
		0x979AB2213CC1F173ULL,
		0x2A9FAFEE0C663EBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94171A9C606DB820ULL,
		0xADA7003995F4EAAAULL,
		0xE726F4839D19BF7CULL,
		0x0439CD71E19338F6ULL,
		0x7DE1DEBC0F19DE28ULL,
		0xCB3373E50F7A607CULL,
		0x2FEA954065C1F00EULL,
		0x7523A2F7D298488BULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB3280FAD30D447A0ULL,
		0x9897DE420BC11A38ULL,
		0x1625023BE7792C94ULL,
		0xDDAD4BEB2AB89E19ULL,
		0x7B110B4A4C90FE61ULL,
		0xB8AD6DFC1B5F1F54ULL,
		0xFF99886F70BA58EAULL,
		0x70EF7E8A09BEF73CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x502E0595B9C52D8AULL,
		0x5C71869BAD1338CAULL,
		0x6C6DE57916FCCFD3ULL,
		0xF1F04BA1A996BF58ULL,
		0xD4DB43E8F6DFAA56ULL,
		0xF1063A933E62BE62ULL,
		0x26EECD19969CA21CULL,
		0xEA0DF4B7115267F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3060A3889116A2AULL,
		0xC4E658D9A6D222F2ULL,
		0x7A48E742F185E347ULL,
		0x2C5D004A832E2141ULL,
		0xAFCA48A2BA4F5437ULL,
		0x49AB576F253DA136ULL,
		0xD9774576E626FAF6ULL,
		0x9AE28A3D18EC90CEULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8C83A5B40E9CB53EULL,
		0x7C2E28482310482CULL,
		0xB2AA1C2F66B809ABULL,
		0xBD12890F538AADFBULL,
		0x877B1AC72D810E79ULL,
		0xEC16FF8D7F80F3CDULL,
		0x8BB3C833750CEB3BULL,
		0x880B6719B13008B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF697A6ABAADB11ULL,
		0x395BD412EC6F1743ULL,
		0xCE790695AF095AE4ULL,
		0xDB31EB799A02122AULL,
		0xD68A12C5736822EDULL,
		0x67186448AC30246AULL,
		0xD5DCDC86E5D6DCD8ULL,
		0x284CF066A718B87EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03753212A5366E2FULL,
		0x4575FC5ACF7F5F6FULL,
		0x7CD31ABAC9B1534FULL,
		0x66236276C988BFD1ULL,
		0x51F108025EE92C94ULL,
		0x8B0E9BC5D3B0D7A7ULL,
		0x5E6F14B590DA37E3ULL,
		0xA047977F1628B0CAULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9E5786404562F161ULL,
		0x4DB27E68DA5C98BFULL,
		0xBA5C0D394257C302ULL,
		0x69062271F89A8DE9ULL,
		0x9DCE9FEDD97FE773ULL,
		0x501145BB3C9A374EULL,
		0x63730A081F8F0649ULL,
		0xBAF656CC531485C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD9CBF58DDDB8DADULL,
		0x5B790CBEE436288DULL,
		0xFEFFB30847DFE7F1ULL,
		0x651115E2A4307277ULL,
		0x0A878A52E190C238ULL,
		0x8B913F82E5FD02ACULL,
		0xA5A6A45C67D0D750ULL,
		0xA4BF6037CA83C0E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53CB391898B97CCCULL,
		0x16CB72D63E6AB032ULL,
		0x44A3BE31058824F3ULL,
		0x0C1737935CAAFF9EULL,
		0x974915BF38EF254BULL,
		0xDB807A39D96735E2ULL,
		0xC6D5AE54785FD119ULL,
		0x1E4936FB99974522ULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1A4FE9E87A9E5508ULL,
		0x610311FF9BF214B6ULL,
		0xFE99D13E55F63A89ULL,
		0x04D02118B4849861ULL,
		0x441013FF6A84640AULL,
		0xB98B76C8B9CF741EULL,
		0x9FB5FBE6A0A24833ULL,
		0x70E2E6A5E2BA9F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEADC8F4C850A4A8FULL,
		0x3E896D36BB4BF047ULL,
		0x454425F97F41B5E0ULL,
		0xDA06CD03E0CD516FULL,
		0x066B82286ECE509BULL,
		0xA4FC43EAD003A35EULL,
		0xA3E86EFBDA9A4C17ULL,
		0xC9053B31A6125E6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF09366A4FF941F87ULL,
		0x5F8A7CC920B9E4F1ULL,
		0xBBDDF4C72AB78F69ULL,
		0xDED6EC1B5449C90EULL,
		0x427B91D7044A3491ULL,
		0x1D77352269CCD740ULL,
		0x3C5D951D7A380424ULL,
		0xB9E7DD9444A8C1E1ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0A6D24DD93BA4327ULL,
		0xBEB975C6D74E5F3CULL,
		0xF1B5AD35AD0AB4D7ULL,
		0xD05B43A8C90D9DBAULL,
		0x8BF0BA79B0AF04A3ULL,
		0x52B959C9A6697D53ULL,
		0x1160A460796DD300ULL,
		0x9DA0986F2E79E141ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF869F062CC176C9DULL,
		0x36C64F700A312D9AULL,
		0x96BAF5958DFFC53DULL,
		0x5F14AAEDC801C829ULL,
		0x3C9A1DDBC1DFBDA8ULL,
		0x1F9070CC4219D1EFULL,
		0x2E86BD7976B4D97FULL,
		0x8B7B30DBCF0376E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF204D4BF5FAD2FBAULL,
		0x887F3AB6DD7F72A6ULL,
		0x670F58A020F571EAULL,
		0x8F4FE945010C5593ULL,
		0xB76AA7A27170B90BULL,
		0x4D292905E470ACBCULL,
		0x3FE619190FD90A7FULL,
		0x16DBA8B4E17A97A2ULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2F7270B7EC28EAB6ULL,
		0xEB78CAF0B7F53516ULL,
		0x19CBCC22B8DC1FA9ULL,
		0x1198FD6398B7484FULL,
		0x2F0A931BEDA3BE4AULL,
		0xE8440BAE84FDB67EULL,
		0xB4D899F6DE143B2FULL,
		0x3B78BA39D243EC71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D40ECB11DCE46CEULL,
		0xDE54266C0DF7F152ULL,
		0xFBD7A8E7D7571C4CULL,
		0xEBB218011FCADCE1ULL,
		0xD72360B45BFEB31EULL,
		0xA78FD9BFA3ED4249ULL,
		0x6AC3F4E611B57839ULL,
		0x4C7B46ACDFE98FF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62329C06F1E6AC78ULL,
		0x352CEC9CBA02C444ULL,
		0xE21C64C56F8B03E5ULL,
		0xFA2AE562877D94AEULL,
		0xF829F3AFB65D0D54ULL,
		0x4FCBD2112710F437ULL,
		0xDE1B6D10CFA14316ULL,
		0x7703FC950DAA6389ULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6BF2D912C0BD48C9ULL,
		0xDF070866E97B3496ULL,
		0x036E2DA3E7F9E3AFULL,
		0xE655AB75BF1D31E7ULL,
		0x17D032DC904B2FACULL,
		0x8D1F19327AF1250EULL,
		0xCD6ED834125176A3ULL,
		0x8D2064BF04F29244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31846C3EC7AB7337ULL,
		0xFA87F5E6C625A2D2ULL,
		0xA45F7D24C7E2D83AULL,
		0x70CE0964B21ECCB6ULL,
		0x4BB9187C73B9E727ULL,
		0x09034E15EB3D3C25ULL,
		0x42D90322959283D2ULL,
		0x60054C420B8A0813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A76B52C07163BFEULL,
		0x2580FD802F5E9644ULL,
		0xA7315087201B3B95ULL,
		0x969BA2110D03FD51ULL,
		0x5C692AA0E3F2C88BULL,
		0x841C572791CC192BULL,
		0x8FB7DB1687C3F571ULL,
		0xED2528FD0F789A57ULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDFA26E391658CC31ULL,
		0x74D00B5DA1E12D80ULL,
		0xC65603E389F68A15ULL,
		0x0C0DD8F19E1197AAULL,
		0xCF738A9CED38042FULL,
		0xE016EBE2312428EEULL,
		0x299E9B617328E1BCULL,
		0x6C8ADD7179DD26DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC432AC8508A5E0ULL,
		0xB95A60056E22AE75ULL,
		0x32AB6904708E9368ULL,
		0xACA28256E24D56BDULL,
		0x1D660729761CBC21ULL,
		0x81D4E798B79742DDULL,
		0x858E6C7937A8902BULL,
		0x5DAF4D19D854A27FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65665C95935069D1ULL,
		0xCD8A6B58CFC383F5ULL,
		0xF4FD6AE7F978197DULL,
		0xA0AF5AA77C5CC117ULL,
		0xD2158DB59B24B80EULL,
		0x61C20C7A86B36A33ULL,
		0xAC10F71844807197ULL,
		0x31259068A18984A2ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x885C0D4117712FD8ULL,
		0x4977F74DFDD4E961ULL,
		0xCDE228EA21AC33C7ULL,
		0xF503C32D69B26D39ULL,
		0xD87945EE2B629D61ULL,
		0xBE6244DE02AB3405ULL,
		0xDF48F9D1A49ABD48ULL,
		0x4E9E30E84B3A08D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18D1A9568494D12ULL,
		0x5B4D76452935C634ULL,
		0x88527D712D93E44FULL,
		0x9AFAB2D83B958E67ULL,
		0x4B50A6B1A2DF4571ULL,
		0x00087406802BC8DAULL,
		0x71C7B0C9AFAC2F78ULL,
		0xAABF8B676A336708ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59D117D47F3862CAULL,
		0x123A8108D4E12F55ULL,
		0x45B0559B0C3FD788ULL,
		0x6FF971F55227E35EULL,
		0x9329E35F89BDD810ULL,
		0xBE6A30D88280FCDFULL,
		0xAE8F49180B369230ULL,
		0xE421BB8F21096FDDULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB9C6AAB933CEDF18ULL,
		0x62467C969A50FB01ULL,
		0x8D18578F800F89FBULL,
		0xDA918F55E8FDBC19ULL,
		0xE78EDF266807F7D2ULL,
		0xCA554A303991826CULL,
		0x2A76A34CDF83CC87ULL,
		0x954D36246073AEEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D357684882895D2ULL,
		0x0EB7C98954C752CAULL,
		0xFD264A2066AFE019ULL,
		0x67F0B3B73588476BULL,
		0xB1056C885FBD8DE4ULL,
		0x19315BE0A7616A70ULL,
		0xB3CBCD0FCDA2C755ULL,
		0x8FC5C6A0D619DDADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24F3DC3DBBE64ACAULL,
		0x6CF1B51FCE97A9CBULL,
		0x703E1DAFE6A069E2ULL,
		0xBD613CE2DD75FB72ULL,
		0x568BB3AE37BA7A36ULL,
		0xD36411D09EF0E81CULL,
		0x99BD6E4312210BD2ULL,
		0x1A88F084B66A7342ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x96C6710D0E6D1854ULL,
		0x9060E2B4C8D8E8C3ULL,
		0xE809149C62633FCCULL,
		0xFEAE616A44140B85ULL,
		0x201616E01A6D118BULL,
		0xDC99F06897AD3B1EULL,
		0x9B54E51744B9234DULL,
		0x28FE7E40196AF15AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C00CC40AC8D74FEULL,
		0x2CED193AB318E422ULL,
		0x752E70F02CD5D0B8ULL,
		0x7F4CC7A633E076DFULL,
		0x4079701D939F8048ULL,
		0xF04B1AB0E7EE462FULL,
		0x359EA2E52368F352ULL,
		0xAF762F2F159D7F04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAC6BD4DA2E06CAAULL,
		0xBC8DFB8E7BC00CE1ULL,
		0x9D27646C4EB6EF74ULL,
		0x81E2A6CC77F47D5AULL,
		0x606F66FD89F291C3ULL,
		0x2CD2EAD870437D31ULL,
		0xAECA47F267D1D01FULL,
		0x8788516F0CF78E5EULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x741457955ABA143EULL,
		0x8CD1F4C02FF635DEULL,
		0xF118CF7360D1215DULL,
		0x807789A286C3548DULL,
		0x9A9E103BD3DDAA02ULL,
		0x10B9EA1290E74BF0ULL,
		0xE21724830243B80FULL,
		0x418B5081F98CB79FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x032A3C655F94C2A2ULL,
		0x33071902A2E3ADD6ULL,
		0x670DCFB1289D02CDULL,
		0xD32740FCF0F830B9ULL,
		0x8042241F562CD936ULL,
		0x0C1E3C5EFA3A7D4AULL,
		0x3394857A03EFA0A0ULL,
		0x3467CC8BEC396DBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x773E6BF0052ED69CULL,
		0xBFD6EDC28D159808ULL,
		0x961500C2484C2390ULL,
		0x5350C95E763B6434ULL,
		0x1ADC342485F17334ULL,
		0x1CA7D64C6ADD36BAULL,
		0xD183A1F901AC18AFULL,
		0x75EC9C0A15B5DA22ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12002B0F1EB77235ULL,
		0x2214E526E5D1604DULL,
		0x5643C0B9359490A0ULL,
		0xFC8D70FA88A6BFF6ULL,
		0xF9BAD836D329AB35ULL,
		0xBF99D5F8FA214DFBULL,
		0xC65E06674B969D17ULL,
		0xD81F887B6AC48657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6215357E20A5D3DAULL,
		0x2953CF40F4948AB5ULL,
		0xC45A5AD9D7DDB64CULL,
		0xA5DE85C672858B79ULL,
		0xED0880552F648A06ULL,
		0xA5522AE1CEA8CCDFULL,
		0x7866858CB781474DULL,
		0x9783AFA3831DF823ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70151E713E12A1EFULL,
		0x0B472A661145EAF8ULL,
		0x92199A60E24926ECULL,
		0x5953F53CFA23348FULL,
		0x14B25863FC4D2133ULL,
		0x1ACBFF1934898124ULL,
		0xBE3883EBFC17DA5AULL,
		0x4F9C27D8E9D97E74ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0F3D3715614BC17BULL,
		0xADC0D649FEA56BDFULL,
		0x496B3BA50DCD2BACULL,
		0x490D97689172DF17ULL,
		0x5380070340A19599ULL,
		0xEDE80589CED75CFFULL,
		0xD6F13F9B450AAA6FULL,
		0x088BF8190CBF007FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4989374DAB03229FULL,
		0x9B150EAD740A974DULL,
		0xBF564E8B826CD7A6ULL,
		0x9813B674A90AE781ULL,
		0xCB05BF1E1478EF70ULL,
		0x2478F64A0D4933EDULL,
		0x910B19A818CBD21EULL,
		0xA9CD278D96C72068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46B40058CA48E3E4ULL,
		0x36D5D8E48AAFFC92ULL,
		0xF63D752E8FA1FC0AULL,
		0xD11E211C38783896ULL,
		0x9885B81D54D97AE9ULL,
		0xC990F3C3C39E6F12ULL,
		0x47FA26335DC17871ULL,
		0xA146DF949A782017ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x11ED2A613C5F4562ULL,
		0x85BEF11D0F8A6932ULL,
		0x2B76156523DA5906ULL,
		0x9DA42A510221D533ULL,
		0x391EC0D1C4B9D06FULL,
		0x39065B8325C95D2AULL,
		0x19F58E169082BBBEULL,
		0x6DD48CAF64947088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6630B8E27B907DB6ULL,
		0xF89404C4D1C6C933ULL,
		0xECFD7B74F540F325ULL,
		0xB3C8A3CD8E765963ULL,
		0xB227FB546413D36CULL,
		0x024838739D96A2C9ULL,
		0x2B4F040F7321A719ULL,
		0x4B8D9352324BA560ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77DD928347CF38D4ULL,
		0x7D2AF5D9DE4CA001ULL,
		0xC78B6E11D69AAA23ULL,
		0x2E6C899C8C578C50ULL,
		0x8B393B85A0AA0303ULL,
		0x3B4E63F0B85FFFE3ULL,
		0x32BA8A19E3A31CA7ULL,
		0x26591FFD56DFD5E8ULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF8AA7CFCD049EEAAULL,
		0x18D4709CB7BB03FFULL,
		0x090E10467DD1CF87ULL,
		0x6FF13BEDEBDD37EFULL,
		0x01A00E2F81A8739AULL,
		0x05E74F7A12F1100DULL,
		0xD10A8A17BE44378BULL,
		0x22B6DA4BCD1DAA96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37615AA526704775ULL,
		0x3412F9DDBDD9C512ULL,
		0xEA8F779F196315A5ULL,
		0xFC2CA2224DE063ECULL,
		0x2537E87CB99AEAB2ULL,
		0x7AF3AFDDE6B27D13ULL,
		0xBF9AE1564E11DFEAULL,
		0x020CDA950C8435BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFCB2659F639A9DFULL,
		0x2CC689410A62C6EDULL,
		0xE38167D964B2DA22ULL,
		0x93DD99CFA63D5403ULL,
		0x2497E65338329928ULL,
		0x7F14E0A7F4436D1EULL,
		0x6E906B41F055E861ULL,
		0x20BA00DEC1999F2DULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x78CFEE905A776529ULL,
		0xD341BCDBA1CBB786ULL,
		0x029BC9F4449A63FFULL,
		0xADFEAEF158CCCB27ULL,
		0xC9064D00C7245877ULL,
		0x0C69890137E1CADEULL,
		0xC13E9B5A0CFC9A7EULL,
		0xA78BE2E228C38A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40CB326410364F51ULL,
		0xD9D37D6D1530E0EDULL,
		0x123CDD17A9C328A1ULL,
		0x309B53CC98C9E730ULL,
		0x3963CC051D81BD06ULL,
		0xE99F7B605F6A5389ULL,
		0xF36D9E7200C77C50ULL,
		0x6A8BDD81EBD42A6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3804DCF44A412A78ULL,
		0x0A92C1B6B4FB576BULL,
		0x10A714E3ED594B5EULL,
		0x9D65FD3DC0052C17ULL,
		0xF0658105DAA5E571ULL,
		0xE5F6F261688B9957ULL,
		0x325305280C3BE62EULL,
		0xCD003F63C317A079ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x880BA68484BBB3CEULL,
		0x53DF64F12D35C96BULL,
		0x4119908C556C84C5ULL,
		0x49F7B85CA39891AFULL,
		0x892D3740667F8110ULL,
		0x1F8F7785C844E2DEULL,
		0xED191EF28F16630DULL,
		0x8168C2FE32D3BD51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFED2F7271CDC7231ULL,
		0x84FC728907A6394AULL,
		0x367D395665499BE3ULL,
		0x6C2770AE1286645FULL,
		0x7352E9D14E8C0283ULL,
		0xF4089858B9615B04ULL,
		0x8EBE29EFAE040DCEULL,
		0xBEACE9E0E27DC0A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76D951A39867C1FFULL,
		0xD72316782A93F021ULL,
		0x7764A9DA30251F26ULL,
		0x25D0C8F2B11EF5F0ULL,
		0xFA7FDE9128F38393ULL,
		0xEB87EFDD7125B9DAULL,
		0x63A7371D21126EC3ULL,
		0x3FC42B1ED0AE7DF5ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6F549DB77B54BD88ULL,
		0xFEEED963D1F243F2ULL,
		0xEE1247BDB3C90E92ULL,
		0x9E080A03B7FB62A0ULL,
		0xD1BA779894916ECDULL,
		0x8D56B852F760CA5FULL,
		0xD070BDF941F69674ULL,
		0x9F860BAF4DF838B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x346C39E331B4C3CBULL,
		0xA3011624DCBE8F2BULL,
		0xDDD05ED779392158ULL,
		0x556EB077224B5A98ULL,
		0x88C8F4AC86B6AF48ULL,
		0xE32E47E15FCB4D23ULL,
		0x9D2BD0C09AF28E04ULL,
		0xF468F54D7FB7104FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B38A4544AE07E43ULL,
		0x5DEFCF470D4CCCD9ULL,
		0x33C2196ACAF02FCAULL,
		0xCB66BA7495B03838ULL,
		0x597283341227C185ULL,
		0x6E78FFB3A8AB877CULL,
		0x4D5B6D39DB041870ULL,
		0x6BEEFEE2324F28FCULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1174DDC1290D5EB9ULL,
		0x165F8E78A7900470ULL,
		0xC240F4E45CE5D863ULL,
		0xA5A08E1C6F236A5DULL,
		0x8BC33C673109101EULL,
		0xB4BCA87898E75A99ULL,
		0x6E7FCBF4CEBECFD4ULL,
		0xE1CBD70AF2F1B10FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B81E32B05048B8BULL,
		0x90C6F0AE80BF5BA0ULL,
		0x7185EC6AA6EC3E50ULL,
		0x80BEA4768FAF78BFULL,
		0x5FC84C2BB43478CCULL,
		0x630F5F3714F55DA7ULL,
		0x070C2596ABCC0A60ULL,
		0x7D987DBFB80645E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AF53EEA2C09D532ULL,
		0x86997ED6272F5FD0ULL,
		0xB3C5188EFA09E633ULL,
		0x251E2A6AE08C12E2ULL,
		0xD40B704C853D68D2ULL,
		0xD7B3F74F8C12073EULL,
		0x6973EE626572C5B4ULL,
		0x9C53AAB54AF7F4EAULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x18F2E3D69C130497ULL,
		0x6706BCDEA56DFF52ULL,
		0xB24C8A72FF71ECB7ULL,
		0x27B567CB5A92507AULL,
		0xE99FE551B4E38A28ULL,
		0x7DAB95C6D0E553B2ULL,
		0xBC9F183ED13F6D7DULL,
		0x5C40F331F04E3DB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C80C54DBCB21608ULL,
		0x62D1ECE0ADDB6F65ULL,
		0x3379BE5D88751E30ULL,
		0x892FE6F37AF38078ULL,
		0x4CE981AF3CEA42E1ULL,
		0xBAC2A3E2500F137EULL,
		0x7E7AD414F294849CULL,
		0x68C2EA21AB26C699ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3472269B20A1129FULL,
		0x05D7503E08B69037ULL,
		0x8135342F7704F287ULL,
		0xAE9A81382061D002ULL,
		0xA57664FE8809C8C9ULL,
		0xC769362480EA40CCULL,
		0xC2E5CC2A23ABE9E1ULL,
		0x348219105B68FB2AULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB17EABAA460C4284ULL,
		0x118ABF04BCD3DEE8ULL,
		0x61E495354F89C7BDULL,
		0x7DAEA909B1A68AC8ULL,
		0xC1E56EB89E75871FULL,
		0xB65C2209424B42EDULL,
		0x7DC6BABC25EEEF55ULL,
		0x3F9FCC255798D517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5490239D0BC4DA79ULL,
		0x11F11E6C08093713ULL,
		0x984AD377536FCDE2ULL,
		0x45D1ABDEBC0ED0B3ULL,
		0xEC2E9088535AF81BULL,
		0xE5BBCE1A38BD640FULL,
		0x2DF272DA0B2B697DULL,
		0x9B0A54BEE72AD41AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5EE88374DC898FDULL,
		0x007BA168B4DAE9FBULL,
		0xF9AE46421CE60A5FULL,
		0x387F02D70DA85A7BULL,
		0x2DCBFE30CD2F7F04ULL,
		0x53E7EC137AF626E2ULL,
		0x5034C8662EC58628ULL,
		0xA495989BB0B2010DULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x097F16244AF677BEULL,
		0x04C8F440BD3B3BCFULL,
		0x9BE55995C51AB80BULL,
		0x67B9747A7927C733ULL,
		0xBB4DEAE2AE1C3472ULL,
		0xDFDCFF1C79ED3C10ULL,
		0x6508E4D3F3CC196EULL,
		0x986F875F1CB17CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69B35F518554C134ULL,
		0x56A3E4F29847E8A1ULL,
		0x44B3F1E8442B953BULL,
		0x9FCCD6D217E43D7FULL,
		0xA41B18AD95E375F9ULL,
		0xCC903674260B107EULL,
		0x3B07516F7D873095ULL,
		0xD0B849AF1A1DCFE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60CC4975CFA2B68AULL,
		0x526B10B2257CD36EULL,
		0xDF56A87D81312D30ULL,
		0xF875A2A86EC3FA4CULL,
		0x1F56F24F3BFF418BULL,
		0x134CC9685FE62C6EULL,
		0x5E0FB5BC8E4B29FBULL,
		0x48D7CEF006ACB302ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x06BEDD3F102F19CFULL,
		0xF8F99492AFFAB0EBULL,
		0x30B272769655E762ULL,
		0x12671BD49488B068ULL,
		0xD928757163727CD7ULL,
		0x59409BBF6FBFBE4BULL,
		0xC15094C69AF25ABDULL,
		0xE291C241FA7AB974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD69F9932EDDEC788ULL,
		0x0BA39677D8529D69ULL,
		0x7C27A45D5035AAF7ULL,
		0x2A2EBC1E081B9F40ULL,
		0x6852B47B54C781ABULL,
		0x36C6F0F3E484B9B8ULL,
		0x5809B2FED6607E90ULL,
		0x476AA677883C5D4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD021440DFDF1DE47ULL,
		0xF35A02E577A82D82ULL,
		0x4C95D62BC6604D95ULL,
		0x3849A7CA9C932F28ULL,
		0xB17AC10A37B5FD7CULL,
		0x6F866B4C8B3B07F3ULL,
		0x995926384C92242DULL,
		0xA5FB64367246E43FULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBB143919056758CCULL,
		0x3B23AAC0D2C717FBULL,
		0x511703372C2D1E19ULL,
		0xDC4435A0EFE88821ULL,
		0xC123C4BC02F19448ULL,
		0xA8F631123F2FD67EULL,
		0xE792F633F0659337ULL,
		0xE290A8FBCAA3EA8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44B0C4224F5BCB5ULL,
		0xEEC733F8053A4734ULL,
		0xA3B06AB73B81375BULL,
		0x357805FE351B4332ULL,
		0xEDC0E06EC5E988D6ULL,
		0x72FC234A4CF7F8CCULL,
		0x8DD2A218A926B52CULL,
		0x6CC985AAD56206F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F5F355B2192E479ULL,
		0xD5E49938D7FD50CFULL,
		0xF2A7698017AC2942ULL,
		0xE93C305EDAF3CB13ULL,
		0x2CE324D2C7181C9EULL,
		0xDA0A125873D82EB2ULL,
		0x6A40542B5943261BULL,
		0x8E592D511FC1EC74ULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAC6703F5590C3BB3ULL,
		0x7F596C07813567F3ULL,
		0x4366BB5779C482D3ULL,
		0x8121DDD11C9EE9C9ULL,
		0xC2FC3371BE1EA400ULL,
		0x72C3293A5B7AD671ULL,
		0x05F62A7BE32C9996ULL,
		0xA3CB2B089B877BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9687BBA1E409602ULL,
		0x37F9CE7976713288ULL,
		0x7BA5F4B482555ED1ULL,
		0xA97C285F5933D9D8ULL,
		0x0EDA75AC51AFFB15ULL,
		0xC5DB2B48177E0089ULL,
		0x58898C06350302E0ULL,
		0x709200B2C9CB3363ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x650F784F474CADB1ULL,
		0x48A0A27EF744557BULL,
		0x38C34FE3FB91DC02ULL,
		0x285DF58E45AD3011ULL,
		0xCC2646DDEFB15F15ULL,
		0xB71802724C04D6F8ULL,
		0x5D7FA67DD62F9B76ULL,
		0xD3592BBA524C48DCULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4E4E7415E9331D60ULL,
		0x85A1A4BA71C84046ULL,
		0x1BACA26E069F5EE2ULL,
		0x7FBCA85895EDD1FFULL,
		0xBC52303D76EA7807ULL,
		0x5D82A0AE7AA62AB7ULL,
		0x3C13BFD5889AD07BULL,
		0xB0C1FD58E169F2A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F356082D68F4829ULL,
		0xD655F36B06B3DDA0ULL,
		0xC6D69BAD55F83147ULL,
		0x33627CC3BE8E6A45ULL,
		0x885462D2619E64CCULL,
		0xC64892219D649333ULL,
		0xDDFE0E796EEE4961ULL,
		0xC38FAFE8B339E99AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x017B14973FBC5549ULL,
		0x53F457D1777B9DE6ULL,
		0xDD7A39C353676FA5ULL,
		0x4CDED49B2B63BBBAULL,
		0x340652EF17741CCBULL,
		0x9BCA328FE7C2B984ULL,
		0xE1EDB1ACE674991AULL,
		0x734E52B052501B3FULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB89A427C75EEC729ULL,
		0x8FA6371F966481E0ULL,
		0x1D186FD896D1CE40ULL,
		0x47B12E9DAF2752A0ULL,
		0x4658799D9BE44969ULL,
		0x6CAA77D3A3D1A92DULL,
		0xDE38D7F964197174ULL,
		0x838CEDD33535E311ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750EA7A08CF6560FULL,
		0x535F5925E9D8BD96ULL,
		0xD718EA761118762BULL,
		0xC0DFDECF8CFB111CULL,
		0x644F14402B697DA1ULL,
		0xA54E373F73CDBC68ULL,
		0x37442361DEB837B3ULL,
		0x9C3FA1FF81C3180CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD94E5DCF9189126ULL,
		0xDCF96E3A7FBC3C76ULL,
		0xCA0085AE87C9B86BULL,
		0x876EF05223DC43BCULL,
		0x22176DDDB08D34C8ULL,
		0xC9E440ECD01C1545ULL,
		0xE97CF498BAA146C7ULL,
		0x1FB34C2CB4F6FB1DULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x26923F8804CB6043ULL,
		0x6A27D6DB180163DAULL,
		0x8EDEE7E3E6433DDEULL,
		0x9692E3D1F88903BEULL,
		0x74357BC4D075DA23ULL,
		0xDCCF913825B3840CULL,
		0x5CF99A834E076255ULL,
		0xBC4E2D416F0C61F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFAFC09029B5DDC4ULL,
		0xF8554E610775D1DCULL,
		0x97810F2B972C3956ULL,
		0xFB259090352042A9ULL,
		0xDA7BDA63AC1CBC40ULL,
		0xCD785BE038C8018AULL,
		0xF0DF44E7DF939CCFULL,
		0x06BC90BD5248179DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x893DFF182D7EBD87ULL,
		0x927298BA1F74B206ULL,
		0x195FE8C8716F0488ULL,
		0x6DB77341CDA94117ULL,
		0xAE4EA1A77C696663ULL,
		0x11B7CAD81D7B8586ULL,
		0xAC26DE649194FE9AULL,
		0xBAF2BDFC3D44766DULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0F2AC46E4D509256ULL,
		0x156FF001F07D7738ULL,
		0xF1F52DB8F9FBBDB8ULL,
		0x2FBE6F6759DD53A9ULL,
		0xD9BF26C18B57ED9DULL,
		0xADFFB69D0B0AA880ULL,
		0xCA83CC1EAFAA972CULL,
		0xDD99CEDCBF1A61C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5CA328E38CEF4FCULL,
		0x7C77EC9FC75EDAC5ULL,
		0xAC77C8ED05C8F680ULL,
		0x8086BED15FD10CC7ULL,
		0x7E82605532842F1EULL,
		0x0F7027E58EF960B8ULL,
		0xBC91D81114F925F4ULL,
		0xFE613F8B182A04A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAE0F6E0759E66AAULL,
		0x69181C9E3723ADFDULL,
		0x5D82E555FC334B38ULL,
		0xAF38D1B6060C5F6EULL,
		0xA73D4694B9D3C283ULL,
		0xA28F917885F3C838ULL,
		0x7612140FBB53B2D8ULL,
		0x23F8F157A7306560ULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4E9287B9D4AA826DULL,
		0xF15E8D15D3D6E034ULL,
		0x41DE4AF8A9485996ULL,
		0xC75B28B671E732E6ULL,
		0x2B4700381AC6E82AULL,
		0x345BA19022B2AC30ULL,
		0x733B3C9BFD354B37ULL,
		0x1D848B61830F93D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFCC5681FD749A87ULL,
		0x5333D98EDEF45BA2ULL,
		0xB4BE518CE8A1572EULL,
		0xB1D440B566571415ULL,
		0x71D26696D14A6401ULL,
		0xDD297A5F86D2B876ULL,
		0x635DA1B0A105DCE4ULL,
		0xF854BB379AF3634FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x815ED13829DE18EAULL,
		0xA26D549B0D22BB96ULL,
		0xF5601B7441E90EB8ULL,
		0x768F680317B026F3ULL,
		0x5A9566AECB8C8C2BULL,
		0xE972DBCFA4601446ULL,
		0x10669D2B5C3097D3ULL,
		0xE5D0305619FCF09AULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5C332636BDE84958ULL,
		0x0C5BE676A10145CCULL,
		0xADD00FBD95E6C51CULL,
		0x3EBBA4EBB7A2CBF3ULL,
		0xC2CB06C280E7148CULL,
		0x57F265E5F9D55728ULL,
		0xC94F4C7F513134FEULL,
		0xE9059EEA05099E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64D2D485A86E6682ULL,
		0xFAAB41C9675F62D0ULL,
		0x423198906ACABD36ULL,
		0x50C56AFC87200F64ULL,
		0x04D85F72CAD917C1ULL,
		0x1CF485E8CE5C16F1ULL,
		0x4B515B9F2B53B632ULL,
		0x6DBDE07A25CB21F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38E1F2B315862FDAULL,
		0xF6F0A7BFC65E271CULL,
		0xEFE1972DFF2C782AULL,
		0x6E7ECE173082C497ULL,
		0xC61359B04A3E034DULL,
		0x4B06E00D378941D9ULL,
		0x821E17E07A6282CCULL,
		0x84B87E9020C2BFD4ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xECABE20B332992D2ULL,
		0x6A316F286442F54BULL,
		0x3EF422A6BCB163E7ULL,
		0xFEAC636F67303005ULL,
		0x8AEDCEAFDE9DA462ULL,
		0x5572F78409BA6624ULL,
		0x50FF01E29E482CD6ULL,
		0x8BBCD22F34F8CD55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F88F507EA8B6A00ULL,
		0xDDC1274DA19AEC09ULL,
		0x22B5FF95CF3AB311ULL,
		0x5209E45E0998BEFDULL,
		0x9F820F51AA0D91EFULL,
		0x1999DDCE1EEE0602ULL,
		0xFCADEFD58C662C99ULL,
		0xAA5594DA5D70DCBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9323170CD9A2F8D2ULL,
		0xB7F04865C5D81942ULL,
		0x1C41DD33738BD0F6ULL,
		0xACA587316EA88EF8ULL,
		0x156FC1FE7490358DULL,
		0x4CEB2A4A17546026ULL,
		0xAC52EE37122E004FULL,
		0x21E946F5698811EAULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB93D5BB9AF839FDAULL,
		0x042830F8048544CAULL,
		0xB400925C49A7C589ULL,
		0xCCD000C6070C5029ULL,
		0xA4BB9D7C3BFEEC1CULL,
		0x47A1420A0AB79FB0ULL,
		0x61FE2F848625D8D5ULL,
		0x26A5B6C79C8CBEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA702E257E9A31934ULL,
		0xBFCE06816FEABE2BULL,
		0x20F7722C07A7C433ULL,
		0xFB1B4F56C71E68ECULL,
		0x99E908F95A9EFE74ULL,
		0xD90860A6FA96C196ULL,
		0xFA8A2217254B6029ULL,
		0xE17A0FAD1CFE9BE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E3FB9EE462086EEULL,
		0xBBE636796B6FFAE1ULL,
		0x94F7E0704E0001BAULL,
		0x37CB4F90C01238C5ULL,
		0x3D52958561601268ULL,
		0x9EA922ACF0215E26ULL,
		0x9B740D93A36EB8FCULL,
		0xC7DFB96A8072253AULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF920D53DCD870350ULL,
		0xBCFE7A5E51705B2EULL,
		0xF8274FC6C4A4CD96ULL,
		0x80F5E3B4DEA2DC48ULL,
		0xADE2AC8E2C9EDD17ULL,
		0xA9E51908C1BF0B2EULL,
		0x67B5E504A4DF261BULL,
		0xE2A444CEBE68CFFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE37E65CB501735D0ULL,
		0x56D54177AD49003FULL,
		0xA9386F228E8F644BULL,
		0xC777C301FAB3C716ULL,
		0x7D307E3F9E9BCEF5ULL,
		0xA10557B73871B26CULL,
		0x91D2C90E8F7544E4ULL,
		0x93B21BC58743BA06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A5EB0F69D903680ULL,
		0xEA2B3B29FC395B11ULL,
		0x511F20E44A2BA9DDULL,
		0x478220B524111B5EULL,
		0xD0D2D2B1B20513E2ULL,
		0x08E04EBFF9CEB942ULL,
		0xF6672C0A2BAA62FFULL,
		0x71165F0B392B75FDULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5E1CC3C987F9D9B0ULL,
		0xD94856D4C7AAD936ULL,
		0xA6DC5127DEDD3F4CULL,
		0xC894B448F70BD744ULL,
		0x8E25318A9B76AB18ULL,
		0xD799F1269B5B4053ULL,
		0x411277A0EC7E168EULL,
		0x9C91822A75210681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE906BA41D1B811ULL,
		0xCC4CC996BF031C1EULL,
		0x0D2CF8C02983847BULL,
		0x9DD962B40873512FULL,
		0x36363D36C580544BULL,
		0x6CC765DF53F08E21ULL,
		0x40D60255D653E9A3ULL,
		0x52881A6E57900D93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32F5C573C62861A1ULL,
		0x15049F4278A9C528ULL,
		0xABF0A9E7F75EBB37ULL,
		0x554DD6FCFF78866BULL,
		0xB8130CBC5EF6FF53ULL,
		0xBB5E94F9C8ABCE72ULL,
		0x01C475F53A2DFF2DULL,
		0xCE19984422B10B12ULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF2C0052F3AE82788ULL,
		0x2D82CA0376449806ULL,
		0x60FE2650E13AF726ULL,
		0x88CFB00F67C83BDDULL,
		0xBAA47D9EA2E9ED11ULL,
		0x75218139922F5409ULL,
		0x3A9D892AD2962856ULL,
		0xC9F8AA81D2CDF749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF1B92CE2C0F084ULL,
		0xB02DFB8BC338A5BEULL,
		0x76A8DA5C60813670ULL,
		0xF33C06BA78A1C5B3ULL,
		0x5B3DA112F626E175ULL,
		0xC730D75E58982965ULL,
		0x8986359C8CAC764DULL,
		0xC951BCD4D7C5499AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C31BC03D828D70CULL,
		0x9DAF3188B57C3DB8ULL,
		0x1656FC0C81BBC156ULL,
		0x7BF3B6B51F69FE6EULL,
		0xE199DC8C54CF0C64ULL,
		0xB2115667CAB77D6CULL,
		0xB31BBCB65E3A5E1BULL,
		0x00A916550508BED3ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF984FD16D426A2B5ULL,
		0x1E9DA8B14D725714ULL,
		0xE4E7354EAB13E1B4ULL,
		0x290E391757218DD0ULL,
		0xB6D539CD56D654F8ULL,
		0x330A15F7583B0943ULL,
		0x647DB817980DEC83ULL,
		0xF6AA6D3ECFFA19D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1417EC54E16E96F6ULL,
		0x8A07DB22F27FF7F3ULL,
		0xADDEB547664B6EBCULL,
		0x324C49689D8269EBULL,
		0x5D21F5820C11F695ULL,
		0xA1011B577F138A0EULL,
		0x060DDCE7B2E14BE8ULL,
		0x9B94DC1369BE8594ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED93114235483443ULL,
		0x949A7393BF0DA0E7ULL,
		0x49398009CD588F08ULL,
		0x1B42707FCAA3E43BULL,
		0xEBF4CC4F5AC7A26DULL,
		0x920B0EA02728834DULL,
		0x627064F02AECA76BULL,
		0x6D3EB12DA6449C40ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4698DC1EB95FB14CULL,
		0x50A47D497CEF3C6BULL,
		0x0B6B139A4DA15E43ULL,
		0x32A167B624D2228BULL,
		0x87F97ECDBEF945B8ULL,
		0x7F9786454E611A81ULL,
		0x74F49B315F096FBEULL,
		0x77447ED71A36F236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9F6C6D18E658132ULL,
		0x6D6AE4EE4BE12A64ULL,
		0xB873A89137506A16ULL,
		0xC2D6D956CC5642CCULL,
		0x2D6666EC423F1218ULL,
		0x78687990D971AAB3ULL,
		0x92628BE77D0791F0ULL,
		0x748BD4214EA73AC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF6E1ACF373A307EULL,
		0x3DCE99A7370E160FULL,
		0xB318BB0B7AF13455ULL,
		0xF077BEE0E8846047ULL,
		0xAA9F1821FCC657A0ULL,
		0x07FFFFD59710B032ULL,
		0xE69610D6220EFE4EULL,
		0x03CFAAF65491C8F6ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6F02C7005C9E21CULL,
		0xB4A0354C4B9C5334ULL,
		0x6795D85D7096C888ULL,
		0x0993340F9C4DF192ULL,
		0xC6B345E1EF2E6F7CULL,
		0xF8886C271E1950F1ULL,
		0x3312247CF6E1238FULL,
		0x6AADC4E66A82DD54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26623B66F460479ULL,
		0x7C5BDEC1685D08D1ULL,
		0x7DA918A39D3153D0ULL,
		0x5170D642AADF5150ULL,
		0x230D92141C1A876CULL,
		0xCCDBBD0A784F0299ULL,
		0x837949B715C60745ULL,
		0x452B9E11B991AF9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14960FC66A8FE665ULL,
		0xC8FBEB8D23C15BE5ULL,
		0x1A3CC0FEEDA79B58ULL,
		0x58E3E24D3692A0C2ULL,
		0xE5BED7F5F334E810ULL,
		0x3453D12D66565268ULL,
		0xB06B6DCBE32724CAULL,
		0x2F865AF7D31372C8ULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0B594FFCB0C6A2B9ULL,
		0x0C3DD52AA597AD49ULL,
		0xC8F05CFCD65E4CA9ULL,
		0x6B2CBF06B8AC04CCULL,
		0x7B01649DEEE69DA6ULL,
		0x8982B0DF6A573B4EULL,
		0x770537BD13DB60A8ULL,
		0x2EFD6FE9BB6C2171ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76039CE2C5BF71EULL,
		0xEF9D121DF71C53D3ULL,
		0x68B1E4EDEADBE687ULL,
		0x85CD146882F94A7DULL,
		0x2BFEC72BDA37F3BCULL,
		0x7E0F588EBBDDE861ULL,
		0x1F4E84D8FD1CC72BULL,
		0x4934E23B1798172AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC3976329C9D55A7ULL,
		0xE3A0C737528BFE9AULL,
		0xA041B8113C85AA2EULL,
		0xEEE1AB6E3A554EB1ULL,
		0x50FFA3B634D16E1AULL,
		0xF78DE851D18AD32FULL,
		0x684BB365EEC7A783ULL,
		0x67C98DD2ACF4365BULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4C71A4430FEE0852ULL,
		0x3F016A64F88480DAULL,
		0x23F9545413ACEC6CULL,
		0xBF92B47D6CDB6ECBULL,
		0x24798AA7CA6D831CULL,
		0x3C6BF47846957496ULL,
		0x13A43D40386709F5ULL,
		0x686C477671FD0B30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB45D47767FDE55E3ULL,
		0x58290239BA2BA19DULL,
		0xD0BB7A370F9FB845ULL,
		0x9B31E6D7CC26B401ULL,
		0xD21D64C8B3BAA7DAULL,
		0xF5CF56E731C38219ULL,
		0x954255435A3D983DULL,
		0x8AF70DF46404321CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF82CE33570305DB1ULL,
		0x6728685D42AF2147ULL,
		0xF3422E631C335429ULL,
		0x24A352AAA0FDDACAULL,
		0xF664EE6F79D724C6ULL,
		0xC9A4A29F7756F68FULL,
		0x86E66803625A91C8ULL,
		0xE29B4A8215F9392CULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x21718D9BAE19DC6BULL,
		0x1DCFC42CC91FA143ULL,
		0x7CBC1F79C653F1F1ULL,
		0xF80B4BB079866E37ULL,
		0x58B90D564F31BB49ULL,
		0x110A637D04D8D1F3ULL,
		0xAF3ED03DB645F9C5ULL,
		0x5CDAC545AC604411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFCFDB580CB0D9EULL,
		0xE939BBD9D669B98BULL,
		0x182F2FF09AF9C5DAULL,
		0x91F2B8A20473D036ULL,
		0xF8AA0382EC635887ULL,
		0xBDE4815B9F3A7D3BULL,
		0xC715906D9CC26142ULL,
		0x7563A2D0A20B6717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E8D702E2ED2D1F5ULL,
		0xF4F67FF51F7618C8ULL,
		0x649330895CAA342BULL,
		0x69F9F3127DF5BE01ULL,
		0xA0130ED4A352E3CEULL,
		0xACEEE2269BE2ACC8ULL,
		0x682B40502A879887ULL,
		0x29B967950E6B2306ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB191C9A4CD812743ULL,
		0xC5ACFBA4069CC0E4ULL,
		0x6135D7B052EB70C6ULL,
		0xCF851244631887AFULL,
		0x078E67C038B38BFDULL,
		0x6DC3BB5F7156A048ULL,
		0x5CB5DC443F2A66CAULL,
		0xA092DD5DC3826B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75F1CAEA61B53447ULL,
		0x579213D919C94C89ULL,
		0xAD1F66537DB66EC4ULL,
		0xAFECF2D121B407BCULL,
		0x393EA1076A2BCF4FULL,
		0xB17F6EB42C03806BULL,
		0x12E50BA1B9BC7ED0ULL,
		0x70C6F393019A4E52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC460034EAC341304ULL,
		0x923EE87D1F558C6DULL,
		0xCC2AB1E32F5D1E02ULL,
		0x6069E09542AC8013ULL,
		0x3EB0C6C7529844B2ULL,
		0xDCBCD5EB5D552023ULL,
		0x4E50D7E58696181AULL,
		0xD0542ECEC218251CULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8A8C617555B81172ULL,
		0x8D17B1AD1937E9E0ULL,
		0x36FF2684898721B2ULL,
		0xDD639CB7BF8479EEULL,
		0x81CC11D3727038E4ULL,
		0xEAFE4D00F0574DFBULL,
		0xDE3259113502D5C7ULL,
		0x06BDA1D739EF294BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519A255A8F6AFAEDULL,
		0xE74924E785AD491EULL,
		0x7DF39AE726E001E7ULL,
		0x7118BA22DC1EA161ULL,
		0x9B79D48BA2D9C6E1ULL,
		0xE7253CFFA4DD9689ULL,
		0xF19887CA2319BE0FULL,
		0x599D5D7E9F10E9AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB16442FDAD2EB9FULL,
		0x6A5E954A9C9AA0FEULL,
		0x4B0CBC63AF672055ULL,
		0xAC7B2695639AD88FULL,
		0x1AB5C558D0A9FE05ULL,
		0x0DDB71FF548ADB72ULL,
		0x2FAADEDB161B6BC8ULL,
		0x5F20FCA9A6FFC0E5ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAD816611E10C6C9EULL,
		0x7A6E2FA248A69D95ULL,
		0xB7F98C64286507CFULL,
		0x2C1E395AE98D874AULL,
		0xEC3792D03D45F4D5ULL,
		0xD3CAB1240083EBA1ULL,
		0xDE18DA5796016BE8ULL,
		0x841983ECD62987E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63CDCF526C32CF43ULL,
		0xB1A15021755F1D71ULL,
		0x181EE5D93F29B064ULL,
		0x8907EF54EBF1D353ULL,
		0xBDC0412668572E05ULL,
		0xAB48B162A1593E9BULL,
		0x339A68B6E3E39965ULL,
		0xBBA27E1CB7A72F9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE4CA9438D3EA3DDULL,
		0xCBCF7F833DF980E4ULL,
		0xAFE769BD174CB7ABULL,
		0xA519D60E027C5419ULL,
		0x51F7D3F65512DAD0ULL,
		0x78820046A1DAD53AULL,
		0xED82B2E175E2F28DULL,
		0x3FBBFDF0618EA87FULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE5D22A527D2EAD1AULL,
		0xB421F03AC7EC2607ULL,
		0xC7ADFE02CE35634DULL,
		0xB1341B3CE0D53C9CULL,
		0xF8007F7D04592444ULL,
		0xC2BD79F57A6CE0A0ULL,
		0xFFB0DF31D0871D6FULL,
		0x06E066263CB5F26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7184B5E9851EFE1BULL,
		0xEFB679F6C8140EFAULL,
		0x0A44D4A3248513C1ULL,
		0x147AF7033C952D0AULL,
		0xAAAC10A96E50DDD1ULL,
		0xC7DFCC6DDF0C0AA8ULL,
		0xCF7D1832A0E32A5DULL,
		0xC2F691D905BC7082ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94569FBBF8305301ULL,
		0x5B9789CC0FF828FDULL,
		0xCDE92AA1EAB0708CULL,
		0xA54EEC3FDC401196ULL,
		0x52AC6FD46A09F995ULL,
		0x0562B598A560EA08ULL,
		0x30CDC70370643732ULL,
		0xC416F7FF390982EFULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x616DA253D5ABCCFBULL,
		0x91D47FC22CF58B56ULL,
		0xC7BDF11B45D35F86ULL,
		0xA2AE96E8854BE942ULL,
		0xB79106C7389E47C7ULL,
		0x7A304894E2008B7BULL,
		0x3831AEE9920AB0CEULL,
		0xF732956A6296A02BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA97262B6DCD2319ULL,
		0xB82C94ED7B875D57ULL,
		0xF167A9834325A6BCULL,
		0x8F9E054942EEB272ULL,
		0x051D207D92937941ULL,
		0xE606E413B55AEB88ULL,
		0x1015D34A278D4FA9ULL,
		0x4DD6488D03738731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BFA8478B866EFE2ULL,
		0x29F8EB2F5772D601ULL,
		0x36DA589806F6F93AULL,
		0x2D3093A1C7A55B30ULL,
		0xB28C26BAAA0D3E86ULL,
		0x9C36AC87575A60F3ULL,
		0x28247DA3B587FF67ULL,
		0xBAE4DDE761E5271AULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x930AFE4E3F7705ABULL,
		0x29C8DF9C489C9222ULL,
		0xB3B138EE2D44ECE2ULL,
		0xD64C323E41AD96A3ULL,
		0x2C16C06D1C53B080ULL,
		0xCB5E3E05B9D6797AULL,
		0x18E8034E702FC293ULL,
		0xD430E7A89C51D07FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53171A908A2FC4B9ULL,
		0x6DFAE109FAB818A7ULL,
		0xEAA862D2991140CEULL,
		0xE78E35E57FC1CCCEULL,
		0x74DE0AD714023F87ULL,
		0xB5B4C9BA5983B543ULL,
		0xF984B7C9BD9BADF6ULL,
		0x1781E7F5B345D718ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC01DE4DEB558C112ULL,
		0x44323E95B2248A85ULL,
		0x59195A3CB455AC2CULL,
		0x31C207DB3E6C5A6DULL,
		0x58C8CABA08518F07ULL,
		0x7EEAF7BFE055CC39ULL,
		0xE16CB487CDB46F65ULL,
		0xC3B1005D2F140767ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2B5D10C33787D045ULL,
		0x5CB9E7BA4B0CA4CBULL,
		0xEB3E9DDBC2C6388EULL,
		0xA774B5A7431AA0E1ULL,
		0xA6346C919EDD9012ULL,
		0x463519EDE6A77247ULL,
		0x1924DE1B8243787BULL,
		0xC27E1BE1B866EDEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE484F94177555C20ULL,
		0x604E7D5D6B0A15D9ULL,
		0x217D16C15EE0DD75ULL,
		0x0C4493F8F11E6960ULL,
		0xF0204F25422EA444ULL,
		0x44A5D40BBA9B90F2ULL,
		0x7550DBAABB356346ULL,
		0x442C7114C99B0F0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFD9E98240D28C65ULL,
		0x3CF79AE72006B112ULL,
		0xCA438B1A9C26E5FBULL,
		0xAB30265FB204C981ULL,
		0x561423B4DCF33456ULL,
		0x0290CDE65C3CE2B5ULL,
		0x6C7405B139761B3DULL,
		0x86526AF571FDE2E2ULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF8A9B73939381496ULL,
		0x3E1D39EE5F97CB05ULL,
		0x2B92F82E1FAB01F2ULL,
		0xF48245B5B3FB3518ULL,
		0xF13C4A0E72A103EDULL,
		0x65286F899016C66AULL,
		0x3E4C98FEBAC438A8ULL,
		0x1311831C581E6970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB29A2A2D968292EULL,
		0x6CEF7E633C9085A4ULL,
		0x6763D1A71CA607D2ULL,
		0x4CFF20C5AB748802ULL,
		0x00C61B47A66136FDULL,
		0xE05884438D99E600ULL,
		0xBF73E7CDD2022DDEULL,
		0xF8354CBE5FBD8F91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4380159BE0503DB8ULL,
		0x52F2478D63074EA1ULL,
		0x4CF12989030D0620ULL,
		0xB87D6570188FBD1AULL,
		0xF1FA5149D4C03510ULL,
		0x8570EBCA1D8F206AULL,
		0x813F7F3368C61576ULL,
		0xEB24CFA207A3E6E1ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x64695E24111221C4ULL,
		0x4E4C254DFE511747ULL,
		0x849CF0DC532C435AULL,
		0x1AB6EA05F246005FULL,
		0xD374FCA879880B7BULL,
		0xDC9521E7A68B032EULL,
		0xD3D72493B2B11C20ULL,
		0x942FE3C96207F7F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7B79D795FC5FDBCULL,
		0xA7D7932E6513BFA7ULL,
		0xFC80C6B88B29B4F2ULL,
		0x70AF8CD61434075AULL,
		0x8F139707B4B25BBDULL,
		0xD6FE8F4ACC25D001ULL,
		0xF7C9DAB9E734C17FULL,
		0xAA23C9D99D64BF46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3DEC35D4ED7DC78ULL,
		0xE99BB6639B42A8E0ULL,
		0x781C3664D805F7A8ULL,
		0x6A1966D3E6720705ULL,
		0x5C676BAFCD3A50C6ULL,
		0x0A6BAEAD6AAED32FULL,
		0x241EFE2A5585DD5FULL,
		0x3E0C2A10FF6348B2ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA8A36AFC75D01FA3ULL,
		0x5F5416A7A068C65DULL,
		0x2CBB0B56C2E7CA54ULL,
		0xA4DF751EAAF803A0ULL,
		0x7EC93B4E5F097B09ULL,
		0xA553605906D0B63DULL,
		0x5561C3E8A0B38147ULL,
		0x4E2C8B7EEB0C84BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E1347DA597CE9BCULL,
		0xDBF6A40B08EE11E1ULL,
		0x662E9C91A37D2099ULL,
		0xCD913032F5BD245FULL,
		0xCF1D71A608AF2F5CULL,
		0xA4ED61CCF820F725ULL,
		0xD20912B31744F9F3ULL,
		0xF0B7591EE3E6F037ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96B02D262CACF61FULL,
		0x84A2B2ACA886D7BCULL,
		0x4A9597C7619AEACDULL,
		0x694E452C5F4527FFULL,
		0xB1D44AE857A65455ULL,
		0x01BE0195FEF04118ULL,
		0x8768D15BB7F778B4ULL,
		0xBE9BD26008EA748CULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9A41F70679538F46ULL,
		0x2AAEFBDE96833D6DULL,
		0x93A1774183B07FCBULL,
		0x193BE36E599FC2D4ULL,
		0x67780E2E443B4966ULL,
		0x0AAD3ACD290EFA09ULL,
		0x455B41CB6E758CB3ULL,
		0xC74F798C287BD134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95BA82F760FF5A4ULL,
		0x56846C2B371F38A9ULL,
		0xC4C7003E2F6E4B74ULL,
		0x63766525214B3E84ULL,
		0xBCD0E0FBB468C553ULL,
		0x8DB42BBE339C1B02ULL,
		0x4018651D66F310C3ULL,
		0xFF4DF81C26CEF3DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x231A5F290F5C7AE2ULL,
		0x7C2A97F5A19C05C4ULL,
		0x5766777FACDE34BFULL,
		0x7A4D864B78D4FC50ULL,
		0xDBA8EED5F0538C35ULL,
		0x871911731A92E10BULL,
		0x054324D608869C70ULL,
		0x380281900EB522EEULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1D9C4F35985D6670ULL,
		0x84D3D618F2FC073AULL,
		0x3F621FEE4CE8D284ULL,
		0x3F78C14526EA9E63ULL,
		0x0E5D09BF73FE453BULL,
		0x172093F494435928ULL,
		0xB2E9F2639F8E26FDULL,
		0xD18D4D88DF731610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C4D8918B46F993ULL,
		0xC9CD92A445F7A818ULL,
		0xCFC1A4859948F7DDULL,
		0x2215A95268C80FEBULL,
		0xAF65EE5BCFBADABCULL,
		0xC80A3D6F14CD24B4ULL,
		0x0F77CDEE7DAAA1EBULL,
		0x6EC965C3C1277EDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x985897A4131B9FE3ULL,
		0x4D1E44BCB70BAF22ULL,
		0xF0A3BB6BD5A02559ULL,
		0x1D6D68174E229188ULL,
		0xA138E7E4BC449F87ULL,
		0xDF2AAE9B808E7D9CULL,
		0xBD9E3F8DE2248716ULL,
		0xBF44284B1E5468CCULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5790AB2F79C4F2B7ULL,
		0x2D48E2E9F7E31A02ULL,
		0xAE696EC642512254ULL,
		0x0A536A3B9D4420DEULL,
		0x2052D6F2B24E2C0CULL,
		0x8E0A82848F5B77C5ULL,
		0x9D4941A66F6A14CBULL,
		0xD215B204782924BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA91A8309E75E02ULL,
		0x789712EAC68E2E3FULL,
		0x94053BDF0E2CFE60ULL,
		0x47AA083C83AFCBCBULL,
		0x81A9BEDC3A20C7E2ULL,
		0x5D38EA395620EBF6ULL,
		0xCEA10DF69F99B280ULL,
		0xCDC4D8FB5D0FA22BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA939B1AC7023ACB5ULL,
		0x55DFF003316D343DULL,
		0x3A6C55194C7DDC34ULL,
		0x4DF962071EEBEB15ULL,
		0xA1FB682E886EEBEEULL,
		0xD33268BDD97B9C33ULL,
		0x53E84C50F0F3A64BULL,
		0x1FD16AFF25268695ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBEFDC2CE8CE05DD8ULL,
		0x7E5694501408B99EULL,
		0xE99DF02B40DBC110ULL,
		0xF25A67D76138C8A0ULL,
		0xCA04EDC770A53593ULL,
		0xE3D2FC62303712F7ULL,
		0x369815F4185A15B4ULL,
		0xE052936819103C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D83EED661408E5ULL,
		0xA1FD057BDFC05BCCULL,
		0x7E2B0DD4B0BF82FDULL,
		0xDD0AAC6957443C35ULL,
		0x3590A6A59A847B4AULL,
		0x4C2A6285B45EDC24ULL,
		0xC5A492A806A13748ULL,
		0x4609021F07CA1CD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD725FC23EAF4553DULL,
		0xDFAB912BCBC8E252ULL,
		0x97B6FDFFF06443EDULL,
		0x2F50CBBE367CF495ULL,
		0xFF944B62EA214ED9ULL,
		0xAFF89EE78469CED3ULL,
		0xF33C875C1EFB22FCULL,
		0xA65B91771EDA20FEULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x191F879AC9FD7469ULL,
		0xDF5B0A509362259FULL,
		0xAF3305E0FAE0F4B3ULL,
		0xF5B785FDE7D8A4EBULL,
		0xC9354487FADDD8D1ULL,
		0xB75A0072B2C87D25ULL,
		0x63903CFFB696391FULL,
		0x2F0263DD2AA53C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D7A74C87F0E8272ULL,
		0x09FAD35FB7C613D0ULL,
		0x4216C21A3C838EA1ULL,
		0x0C89B75AB1776C43ULL,
		0x84CDB669FF4EE1BCULL,
		0x636D73C947A686C3ULL,
		0x0A56B16E9002A839ULL,
		0xA5EF3CF94C340A12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7465F352B6F3F61BULL,
		0xD6A1D90F24A4364FULL,
		0xED25C7FAC6637A12ULL,
		0xF93E32A756AFC8A8ULL,
		0x4DF8F2EE0593396DULL,
		0xD43773BBF56EFBE6ULL,
		0x69C68D9126949126ULL,
		0x8AED5F2466913683ULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC8EDC6428E9C61A9ULL,
		0x3AD26855C9908744ULL,
		0xD259A5A0434E40A2ULL,
		0xA3D6FBEF59FD0C90ULL,
		0xD6B5DED42A98A0C7ULL,
		0xA912210C99E29995ULL,
		0xE642FFE8102D3348ULL,
		0xABBB671C153297CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB5A1F1E19E59E7ULL,
		0xE31FB19CB9E328C1ULL,
		0x40BA88849EEECEBAULL,
		0xB94B9FF15C59DB71ULL,
		0x1DE2061D72C7BB06ULL,
		0xE20A3981627D5569ULL,
		0x2F7E23648A24AE16ULL,
		0xCBB278C37A8B7A31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x225867B36F02384EULL,
		0xD9CDD9C97073AF85ULL,
		0x92E32D24DDA08E18ULL,
		0x1A9D641E05A4D7E1ULL,
		0xCB57D8C9585F1BC1ULL,
		0x4B18188DFB9FCCFCULL,
		0xC93CDC8C9A099D5EULL,
		0x60091FDF6FB9EDFEULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x643339F0EBB664B8ULL,
		0x88FA6AEE524C97A0ULL,
		0x03FC0A8B695F8927ULL,
		0x010AA21A4A0EA237ULL,
		0x29BA58FCDDE53AE3ULL,
		0xFAF08B24501D8230ULL,
		0xD99BE85A61E02539ULL,
		0x43DD0B91AB38D0AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B6E7BB570972480ULL,
		0x9F8CA91FA184A78FULL,
		0x7A4CD4B331DE9600ULL,
		0x8EF35D3518619748ULL,
		0x5CED1F6F0BA10F9CULL,
		0xFA006111DA9D716EULL,
		0x3A7B7DAF4F070CD7ULL,
		0x49D31052C8510801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F5D42459B214038ULL,
		0x1776C3F1F3C8302FULL,
		0x79B0DE3858811F27ULL,
		0x8FF9FF2F526F357FULL,
		0x75574793D644357FULL,
		0x00F0EA358A80F35EULL,
		0xE3E095F52EE729EEULL,
		0x0A0E1BC36369D8AFULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFAE81137A363D42BULL,
		0x370F8BC0340F804DULL,
		0x408DAD4FD79CDE18ULL,
		0xE5983DD092142BBDULL,
		0xD5342735004E9519ULL,
		0x1711EDD3EE22C927ULL,
		0x85643C3C1A2F303EULL,
		0x4828C8B0FD42628DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E843A4521EEA75ULL,
		0xCF1D7B2ACC7975DAULL,
		0x0E50040D0052D5F1ULL,
		0x998E2A86C354959AULL,
		0x85D21CB20B606B02ULL,
		0x02E21207DAB9EE67ULL,
		0x373BE04CF2B772BFULL,
		0x9D830E156C1E916BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3005293F17D3E5EULL,
		0xF812F0EAF876F597ULL,
		0x4EDDA942D7CE0BE9ULL,
		0x7C1617565140BE27ULL,
		0x50E63B870B2EFE1BULL,
		0x15F3FFD4349B2740ULL,
		0xB25FDC70E8984281ULL,
		0xD5ABC6A5915CF3E6ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1A2C5EA9E4A3140AULL,
		0xA540DC66A99A9E39ULL,
		0xF04704106547D24FULL,
		0x4C050F6CE4B8DF86ULL,
		0xDA268B6DF0BA60B6ULL,
		0x08B6B03083A7EBF1ULL,
		0x49561EA3883834EFULL,
		0x6F9BB84E1D56A3C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE559EDB308F9490ULL,
		0x22C60A81B387C165ULL,
		0x28E99EF436D7E1FEULL,
		0x594CC79727B3AA2BULL,
		0x082ABBB835049EC1ULL,
		0xE732FAFD2FC22131ULL,
		0x5460B612D83CF2F4ULL,
		0x6FE38FE66A834034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC479C072D42C809AULL,
		0x8786D6E71A1D5F5CULL,
		0xD8AE9AE4539033B1ULL,
		0x1549C8FBC30B75ADULL,
		0xD20C30D5C5BEFE77ULL,
		0xEF844ACDAC65CAC0ULL,
		0x1D36A8B15004C61BULL,
		0x007837A877D5E3F0ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x45B268F8C46649C6ULL,
		0xEE16AAB8AA10D1FEULL,
		0xEEBD690952FEB700ULL,
		0xF5022EC653F153E1ULL,
		0xE5F1DB80E88E09ABULL,
		0x0E6CE9F4CACB058CULL,
		0x417E738F4357A3AEULL,
		0x7765655064BED2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A98E13ADB1E079AULL,
		0x9D9001688507062EULL,
		0xD9301E2419BB4CB0ULL,
		0x68F1717F207CDD42ULL,
		0x9C2C622CF095EC63ULL,
		0xE0B8508D6ABAFAAFULL,
		0xD70A8FEBD0D13776ULL,
		0x9E9EF91DC0421ED2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F2A89C21F784E5CULL,
		0x7386ABD02F17D7D0ULL,
		0x378D772D4B45FBB0ULL,
		0x9DF35FB9738D8EA3ULL,
		0x79DDB9AC181BE5C8ULL,
		0xEED4B979A071FF23ULL,
		0x9674FC64938694D8ULL,
		0xE9FB9C4DA4FCCC76ULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0B950E30841C9112ULL,
		0x1E8309D4590706DCULL,
		0x046B3B67A27AF32CULL,
		0x19576CD1CED29C64ULL,
		0xD9CB5BE9683F02AEULL,
		0xA80E26268882159DULL,
		0x59FAF7D7F47821D4ULL,
		0x3383184C1BEC0875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44874097E024A179ULL,
		0xD933F20584DEAE76ULL,
		0xE8DC8985B3EE2474ULL,
		0x621C6D20E9879B52ULL,
		0x1B86EE7251F576F3ULL,
		0x7949FB732A1F32FAULL,
		0x29B2F18EAAA9662CULL,
		0x1E6CE5698D509EE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F124EA76438306BULL,
		0xC7B0FBD1DDD9A8AAULL,
		0xECB7B2E21194D758ULL,
		0x7B4B01F127550736ULL,
		0xC24DB59B39CA745DULL,
		0xD147DD55A29D2767ULL,
		0x704806595ED147F8ULL,
		0x2DEFFD2596BC9692ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x971BB19DC4ECC764ULL,
		0x3A45AC217E2D3A85ULL,
		0x76844E55FAB5EC34ULL,
		0x907CF9B6E7F64E49ULL,
		0x2276F296E4AADB6CULL,
		0xBE5102D623607F53ULL,
		0x59ADED000BEA40E6ULL,
		0xCC25189DAA92C6CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB61223EC856CCF6ULL,
		0xBBD495666EA9076BULL,
		0x2C3A83FB9BD2FD2FULL,
		0x62B5D0A7A3FF00F9ULL,
		0xA233085BF915B83DULL,
		0x50C3A02249B1917FULL,
		0x155DA6C134486DA9ULL,
		0x8765234E8AAE7505ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C7A93A30CBA0B92ULL,
		0x8191394710843DEEULL,
		0x5ABECDAE6167111BULL,
		0xF2C9291144094EB0ULL,
		0x8045FACD1DBF6351ULL,
		0xEE92A2F46AD1EE2CULL,
		0x4CF04BC13FA22D4FULL,
		0x4B403BD3203CB3C9ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x99C563B4B63FE8ADULL,
		0x2B5BFE8F6B3D8129ULL,
		0xC63B39B91EB022F3ULL,
		0x94763E2DC8FED714ULL,
		0xFAEF6B3BCFE68064ULL,
		0x4E73F93AADF30CF7ULL,
		0xB173FA031BECCBAAULL,
		0x57999A84C4F1FA47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEF9D3C35EFD449DULL,
		0xF3331065B84A14B0ULL,
		0xB13E75AB5AE6E718ULL,
		0xD219CEE7A606126BULL,
		0x969E6F547B200ED5ULL,
		0xC5D886AFDBDCA230ULL,
		0x308A3A3D252F6D00ULL,
		0xC98351181E1F50CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x473CB077E8C2AC30ULL,
		0xD868EEEAD3779599ULL,
		0x77054C124456C5EBULL,
		0x466FF0CA6EF8C57FULL,
		0x6C71046FB4C68EB1ULL,
		0x8BAB7F95762FAEC7ULL,
		0x81F9C03E3EC3A6AAULL,
		0x9E1ACB9CDAEEAA8CULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF3718EB96EA607D6ULL,
		0xA5C6C254103A9EA5ULL,
		0x3CC8E19F9CFAB512ULL,
		0x925EE585C96A26C4ULL,
		0x42D2C6756077DAA1ULL,
		0x970D902B27BCE4B3ULL,
		0xB0F2DBBD2B2F94EFULL,
		0x1A34560D96BD4CCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3322A59B40F2E3BULL,
		0xF10F4A56B948552FULL,
		0x62977743A9225715ULL,
		0xC133F6CB0A29E397ULL,
		0x9E2DB3E6CAD605C4ULL,
		0x4B054493A6F77838ULL,
		0x700D260DD2F4F5DBULL,
		0x2EAB90095E4235D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5043A4E0DAA929EDULL,
		0x54C98802A972CB8AULL,
		0x5E5F96DC35D8E207ULL,
		0x536D134EC343C553ULL,
		0xDCFF7593AAA1DF65ULL,
		0xDC08D4B8814B9C8BULL,
		0xC0FFFDB0F9DB6134ULL,
		0x349FC604C8FF791EULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEAE819BD5CC3CBC6ULL,
		0xFF53F014839E4632ULL,
		0xE967237AAA8FBB43ULL,
		0x09F9CB7AD6A65C34ULL,
		0x15745C8A2C4F6A62ULL,
		0x4DD035DB3255026AULL,
		0x3E8DB2F319C85B24ULL,
		0x9953885A30CB6090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4AAD0FC4C62423BULL,
		0x0777157F2785C02CULL,
		0x882842E36678DEC1ULL,
		0xA2EE4394FE8DE891ULL,
		0x7976F155597EF93BULL,
		0x30F1AEAA8A40C9D5ULL,
		0x71F947C20934B578ULL,
		0x6C54AA9E126C833FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E42C94110A189FDULL,
		0xF824E56BA41B861EULL,
		0x614F6199CCF76582ULL,
		0xAB1788EE282BB4A5ULL,
		0x6C02ADDF75319359ULL,
		0x7D219B71B815CBBFULL,
		0x4F74F53110FCEE5CULL,
		0xF50722C422A7E3AFULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE0C55450502F4BE3ULL,
		0xDFD45C5B5006A8C6ULL,
		0x4B90D7ED49F1AF2BULL,
		0x8E3221586AD33D48ULL,
		0xD816BCB5A1906395ULL,
		0x80744C84518A6FA4ULL,
		0x691F7CFB95FEB44FULL,
		0xF778ACEDA7CC9AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F8F3AB0EFF8743ULL,
		0x7EA47B8C755DB6FCULL,
		0xA264618782679F5DULL,
		0x2827A1996A124A09ULL,
		0xFF0B407289E6D139ULL,
		0x28D72D000AC39A0DULL,
		0x4A3C2435A2593CC4ULL,
		0x643CF50771C2977EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD03DA7FB5ED0CCA0ULL,
		0xA17027D7255B1E3AULL,
		0xE9F4B66ACB963076ULL,
		0xA61580C100C17741ULL,
		0x271DFCC72876B2ACULL,
		0xA8A361845B49F5A9ULL,
		0x232358CE37A7888BULL,
		0x934459EAD60E0D93ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBFD0162D3912D57EULL,
		0xF305303847823390ULL,
		0xDBC95B92E8EC3C29ULL,
		0x6320F0D01AA312E8ULL,
		0xB384749F913BF377ULL,
		0x2AF10A786020A19FULL,
		0xCCD4E27E821C9C84ULL,
		0x01F58A6A4EA83943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83FF3D041C5CC48EULL,
		0x154FB30294EC2B8FULL,
		0xCD9E3432960646B1ULL,
		0x8BF896C210F9CE71ULL,
		0x840169E3CE31C5CDULL,
		0xFDE3C072DA1D7665ULL,
		0xF6729FE63D3B789FULL,
		0x856A70A22CB3012AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C2F2B29254E11F0ULL,
		0xE64A833AD36E181FULL,
		0x16576FA07EEA7A98ULL,
		0xE8D866120A5ADC99ULL,
		0x37851D7C5F0A36BAULL,
		0xD712CA0ABA3DD7FAULL,
		0x3AA67D98BF27E41BULL,
		0x849FFAC8621B3869ULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8F1868447C23AE5CULL,
		0x12A3A80072EAF1E5ULL,
		0xB067AD624E5C13F4ULL,
		0xF6C6C5B8D808DD0BULL,
		0xF06728FA3EC765F7ULL,
		0x1366901EC4D3E593ULL,
		0x10A437623F4B7748ULL,
		0x7ED6A4F69B689F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A2A6CFF604E77EULL,
		0xEA86CC5996D81FF5ULL,
		0x009175CB6E957E2EULL,
		0x92A997A01BE29CE5ULL,
		0x60790D6B73D62374ULL,
		0xAD0325C129B11163ULL,
		0x2BBBB869513BB827ULL,
		0x3AF75314C609D20BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CBACE8B8A274922ULL,
		0xF8256459E432EE10ULL,
		0xB0F6D8A920C96DDAULL,
		0x646F5218C3EA41EEULL,
		0x901E25914D114683ULL,
		0xBE65B5DFED62F4F0ULL,
		0x3B1F8F0B6E70CF6FULL,
		0x4421F7E25D614D6DULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAD195D44116BD7BBULL,
		0xC05401564841394FULL,
		0x45FDD5D3855DADC0ULL,
		0xA850C7855A9F6129ULL,
		0xBDD4E945E7CDA0A6ULL,
		0x597EA4C07B848372ULL,
		0x463ADA837AFA67D0ULL,
		0x41F893806373653FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43526F16BDC69439ULL,
		0x7CBE05FAE05C9AF3ULL,
		0x439A5D2866B09976ULL,
		0x4CB3BB1B14A6EDA7ULL,
		0x7100FA8BD4631293ULL,
		0x4FB639E0AE08F307ULL,
		0xC78E24851E87E02EULL,
		0xEAA47D23D5450530ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE4B3252ACAD4382ULL,
		0xBCEA04ACA81DA3BCULL,
		0x066788FBE3ED34B6ULL,
		0xE4E37C9E4E398C8EULL,
		0xCCD413CE33AEB235ULL,
		0x16C89D20D58C7075ULL,
		0x81B4FE06647D87FEULL,
		0xAB5CEEA3B636600FULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x602532CA2A1CCDF7ULL,
		0xB9CA7EF321437E3CULL,
		0x8B72ACEB0E3E4047ULL,
		0xBC38E12AA7D60987ULL,
		0x42CDF84E862A6584ULL,
		0x883EE7035C7FB594ULL,
		0xBF5C88F223603749ULL,
		0x69368E5CF17BDDE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8CA8F78C167811ULL,
		0xEA662FE809F45DACULL,
		0xD559E96D3219096FULL,
		0x1CF697E1C316A6FCULL,
		0x22795BD1AEB605B1ULL,
		0x42E457FA6F93B17FULL,
		0x2D1B3A945D1925F2ULL,
		0x82C39928912FD734ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFA99A3DA60AB5E6ULL,
		0x53AC511B28B72390ULL,
		0x5E2B45863C274928ULL,
		0xA0CE76CB64C0AF7BULL,
		0x60B4A39F289C6035ULL,
		0xCADAB0F933EC04EBULL,
		0x9247B2667E7912BBULL,
		0xEBF5177460540ADCULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x27519DAF3393C587ULL,
		0x177FE57E49AB2D57ULL,
		0xC66A05DAEFC370D2ULL,
		0x7E7B1C9F994C5AC3ULL,
		0x2F854DCD5AF3CE36ULL,
		0x5546FBDB347D09EDULL,
		0xCDE64E18630D4506ULL,
		0xAA402D47A865F89FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E8041B18FD145EULL,
		0x653E17284B732583ULL,
		0xBB269F5194D1F773ULL,
		0xD2E1C14EFEE52A21ULL,
		0x4A9E41A6F4B3DFDEULL,
		0x21DC7A090D8683F8ULL,
		0x28F7BA5ED9475910ULL,
		0xB9ADD22CBA2E49A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0B999B42B6ED1D9ULL,
		0x7241F25602D808D4ULL,
		0x7D4C9A8B7B1287A1ULL,
		0xAC9ADDD167A970E2ULL,
		0x651B0C6BAE4011E8ULL,
		0x749A81D239FB8A15ULL,
		0xE511F446BA4A1C16ULL,
		0x13EDFF6B124BB13AULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF6956F5CB872C5ABULL,
		0x1BA9265235978624ULL,
		0xA641C4A0733D8932ULL,
		0x4633750C9D146DAEULL,
		0x8D364E9ACF95A887ULL,
		0xF18FD75B816F97A9ULL,
		0x2EE672056CB65C6AULL,
		0xCBF6FD01C12D40D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACEB96CF99819DAULL,
		0xEB7AC29DF1A9AA79ULL,
		0xB3D97275E014F334ULL,
		0x412D07D2D8AD9F1EULL,
		0x7FEC4600BB55CD86ULL,
		0x61CA41970B0A78EEULL,
		0x2B6B51C561FF790DULL,
		0xFC96CFA408FB63A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C5BD63041EADC71ULL,
		0xF0D3E4CFC43E2C5DULL,
		0x1598B6D593297A06ULL,
		0x071E72DE45B9F2B0ULL,
		0xF2DA089A74C06501ULL,
		0x904596CC8A65EF47ULL,
		0x058D23C00D492567ULL,
		0x376032A5C9D6237DULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x029CEDCD992A526BULL,
		0xCAFC9E2B7363EFBDULL,
		0xD7F4E1E3B3B0FA62ULL,
		0x500C402807F61338ULL,
		0x6D238B421A1B2154ULL,
		0x403DC8CD95C124DFULL,
		0x1DADFE19C19EE531ULL,
		0xBC3B6C07214BA4C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3DFE4A7EED802BBULL,
		0xF6F4CD1B20D08DA5ULL,
		0x701F33126192C69EULL,
		0x874B664B9494C9A9ULL,
		0x6DFFF80F83828294ULL,
		0x233B9ADF4F03FF9BULL,
		0x0251BD5D91969635ULL,
		0x3C534BF62C51249FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB143096A77F250D0ULL,
		0x3C08533053B36218ULL,
		0xA7EBD2F1D2223CFCULL,
		0xD74726639362DA91ULL,
		0x00DC734D9999A3C0ULL,
		0x63065212DAC2DB44ULL,
		0x1FFC434450087304ULL,
		0x806827F10D1A8058ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x923D949F0D23F636ULL,
		0x719324B74AC1293AULL,
		0xB48CB7E84B00B7B6ULL,
		0x3243A9FE7B723770ULL,
		0xAD602B414A94AF2CULL,
		0x38C4AF316CCC8A2CULL,
		0x6EC811BCA45670CBULL,
		0x5920D9897ED8D3FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC86478FCD67BD0ULL,
		0x1BD155E1BD3C8F52ULL,
		0xEFA8CBD9247A5FBAULL,
		0x908678EBB30262D9ULL,
		0xC57F4352D5FB6C87ULL,
		0xBD192A9343790E79ULL,
		0xC54BE6AC440ABA65ULL,
		0x0CA5A32974E5F37DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DF5F0E7F1F58DE6ULL,
		0x6A427156F7FDA668ULL,
		0x5B247C316F7AE80CULL,
		0xA2C5D115C87055A9ULL,
		0x681F68139F6FC3ABULL,
		0x85DD85A22FB58455ULL,
		0xAB83F710E05CCAAEULL,
		0x55857AA00A3D2081ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x555DFD4887B70495ULL,
		0x92E2156C273758E5ULL,
		0x9613B81D2ACE2DBEULL,
		0xC08FB3FE91CB4EE6ULL,
		0x1F3BEFD2F6F2F6A3ULL,
		0x76781D846F2E12CBULL,
		0x4796AC0D2D17CFD2ULL,
		0x2E5C538A2469779CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1388AFCEB4F6D80AULL,
		0xDA27F80E0B9047DEULL,
		0x314DA2A70474DF68ULL,
		0xFAEB3641250E07FFULL,
		0xF398A04D9EE5DBAAULL,
		0x640F18AA943D16E8ULL,
		0xF1E86EF42473B61CULL,
		0x30C325D01330D034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46D552863341DC9FULL,
		0x48C5ED622CA71F3BULL,
		0xA75E1ABA2EBAF2D6ULL,
		0x3A6485BFB4C54919ULL,
		0xECA34F9F68172D09ULL,
		0x1277052EFB130423ULL,
		0xB67EC2F9096479CEULL,
		0x1E9F765A3759A7A8ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x65C3A0ACCD59CC36ULL,
		0xCA2120E02686E465ULL,
		0x919105811F9E1530ULL,
		0x2F64CC1CCCAE4730ULL,
		0x2F59726A7195A13BULL,
		0x8F0F2C50451249DDULL,
		0x8E3D0895A585F7CCULL,
		0x17A666EDEE6C85D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD217FF29F0994F8ULL,
		0x8A5AD92F66BC5F70ULL,
		0xE2593A6158A371D0ULL,
		0x15A3B2B6F99F619EULL,
		0xC74AEACE6B348F83ULL,
		0xE91EA66518D790CEULL,
		0xD6315D7033E5DD65ULL,
		0x80F887EA5413EB3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8E2DF5E525058CEULL,
		0x407BF9CF403ABB15ULL,
		0x73C83FE0473D64E0ULL,
		0x3AC77EAA353126AEULL,
		0xE81398A41AA12EB8ULL,
		0x66118A355DC5D913ULL,
		0x580C55E596602AA9ULL,
		0x975EE107BA7F6EE9ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBEDC21A14277B385ULL,
		0xD09356E67A752369ULL,
		0xEBC0057DDD39709DULL,
		0x1C764A262001E785ULL,
		0xE4A0EAFE390B115FULL,
		0x3BF155B01A917641ULL,
		0x1BD7C97D737C21FAULL,
		0xA107F569008998F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE088C5A2C0BFAA1ULL,
		0x7E10B9E60BDEA06EULL,
		0xDB6FF7DF1676D476ULL,
		0xBC49F5B73440E2F3ULL,
		0x3DD6E9DBB1C7E576ULL,
		0xBA04968748195311ULL,
		0xAD8DFA56E647C865ULL,
		0xB4D05C7966BE1F31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D4ADFB6E7C4924ULL,
		0xAE83EF0071AB8307ULL,
		0x30AFF2A2CB4FA4EBULL,
		0xA03FBF9114410576ULL,
		0xD976032588CCF429ULL,
		0x81F5C33752882550ULL,
		0xB65A332B953BE99FULL,
		0x15D7A910663787C5ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xED325A51F71F8A33ULL,
		0x71BC33F716E9D45DULL,
		0x98783A44F9C238CEULL,
		0xA282F6A63D8425BBULL,
		0x82957558DDE7B913ULL,
		0x0BE1ACB20270D24BULL,
		0xB146A1DCDBDAE69BULL,
		0x8001769D7E1818F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C25850EC3DB7B6ULL,
		0x09A9B0046C02FE85ULL,
		0x4EB8AAEC9BC67A19ULL,
		0xAE2AF3810E2FBA9AULL,
		0x32176DD8A6A6BFC3ULL,
		0x2A87FB63609044D5ULL,
		0xB23E2F57185DBBA4ULL,
		0xEB514045951E3BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CF002011B223D85ULL,
		0x781583F37AEB2AD8ULL,
		0xD6C090A8620442D7ULL,
		0x0CA8052733AB9F21ULL,
		0xB08218807B4106D0ULL,
		0x216657D162E0969EULL,
		0x03788E8BC3875D3FULL,
		0x6B5036D8EB062352ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8B66D23572BE29EBULL,
		0x9C64DF0207D525E3ULL,
		0xD28F3FC1ABB083F2ULL,
		0xA438407ACA060BDBULL,
		0xCB5F7D1C1B82DB89ULL,
		0x69D7FFAAFB9182F5ULL,
		0x318133D820F9A1A5ULL,
		0x5B727834690CEBBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C4B2DB65903912ULL,
		0xC0BDDEC5A0D7175EULL,
		0x3B545E08206EDE5EULL,
		0xD27C53231995432CULL,
		0x3E92A5C7142C97F6ULL,
		0xEC027D2EF9EFB05CULL,
		0x20188266EAF726AEULL,
		0x107ADDCB8142C5B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53A260EE172E10F9ULL,
		0x5CD901C7A70232BDULL,
		0xE9DB61C98BDE5DACULL,
		0x76441359D39348F7ULL,
		0xF5CDD8DB0FAE4C7FULL,
		0x85D58284027E32A9ULL,
		0x1199B1BECA0E870BULL,
		0x4B08A5FFE84E2E0CULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12365A25BC286EDBULL,
		0xD918D288FB57DC52ULL,
		0x4D70FFD7929110B3ULL,
		0x54833A0D2551B5E8ULL,
		0xD29CA36B563C5F8BULL,
		0xF4A41E93D3BD891CULL,
		0x4E85E0A60C14E65BULL,
		0xF23241D98AB4B9B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x196527C238DFB126ULL,
		0x30BCE132006A0C60ULL,
		0x5EB8649E5FEAAA9DULL,
		0x39B081CF1C63B6B5ULL,
		0x2F78B1CC2404D419ULL,
		0x8F5B6A0E13D76C3EULL,
		0x3B19111346051F2CULL,
		0x753D6AEED5D4D17BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B537DE784F7DFFDULL,
		0xE9A433BAFB3DD032ULL,
		0x13C89B49CD7BBA2EULL,
		0x6D33BBC23932035DULL,
		0xFDE412A772388B92ULL,
		0x7BFF749DC06AE522ULL,
		0x759CF1B54A11F977ULL,
		0x870F2B375F6068C9ULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA1BE7A4F9609383ULL,
		0x9737D534F3F57F32ULL,
		0x6D6949C08B0FA78AULL,
		0xFF9B0A57EBEC713BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFEAA3284D062C4AULL,
		0x98AB1C60A6C7160FULL,
		0x8122A34E5C731274ULL,
		0xC44D2622A4B6C5D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFEAA3284D062C4AULL,
		0x98AB1C60A6C7160FULL,
		0x8122A34E5C731274ULL,
		0xC44D2622A4B6C5D4ULL,
		0xAA1BE7A4F9609383ULL,
		0x9737D534F3F57F32ULL,
		0x6D6949C08B0FA78AULL,
		0xFF9B0A57EBEC713BULL
	}};
	printf("Test Case 501\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAB8735AC142E24A1ULL,
		0x0590A88D891E10DEULL,
		0xB562DB9F5130CE75ULL,
		0x40DE2630E4FD4CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675DF9820BEE7A44ULL,
		0xAF0C837DFEE4A552ULL,
		0x7A15BB5F9ACBD1CAULL,
		0x70F3D0EA6134ED52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x675DF9820BEE7A44ULL,
		0xAF0C837DFEE4A552ULL,
		0x7A15BB5F9ACBD1CAULL,
		0x70F3D0EA6134ED52ULL,
		0xAB8735AC142E24A1ULL,
		0x0590A88D891E10DEULL,
		0xB562DB9F5130CE75ULL,
		0x40DE2630E4FD4CBEULL
	}};
	printf("Test Case 502\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 502 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE00C9D2E8F179681ULL,
		0xF68021F5F9018749ULL,
		0xE80BFEA9A2504CF8ULL,
		0x9E68DFABCC5D330FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DF811EA55E70D4BULL,
		0x0D3D21840A9D8ABAULL,
		0xB20FB29DFCC86365ULL,
		0x83F84E78CC3062D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DF811EA55E70D4BULL,
		0x0D3D21840A9D8ABAULL,
		0xB20FB29DFCC86365ULL,
		0x83F84E78CC3062D4ULL,
		0xE00C9D2E8F179681ULL,
		0xF68021F5F9018749ULL,
		0xE80BFEA9A2504CF8ULL,
		0x9E68DFABCC5D330FULL
	}};
	printf("Test Case 503\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 503 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6FA4D11C88DAB935ULL,
		0xA6646E88FC55A964ULL,
		0x03075FAEB34A2E25ULL,
		0x359D1AD5629297BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48831D2BD9A4B52ULL,
		0x41AA2BD8B8862F40ULL,
		0x20BC77FC66CC5BF7ULL,
		0x56C29EE89C366CDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE48831D2BD9A4B52ULL,
		0x41AA2BD8B8862F40ULL,
		0x20BC77FC66CC5BF7ULL,
		0x56C29EE89C366CDCULL,
		0x6FA4D11C88DAB935ULL,
		0xA6646E88FC55A964ULL,
		0x03075FAEB34A2E25ULL,
		0x359D1AD5629297BBULL
	}};
	printf("Test Case 504\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 504 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3E783BFE1DB19A9CULL,
		0x272D13726D6F79E6ULL,
		0x047789AC17F7E9D3ULL,
		0x9984CCB17407CA19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD696CF546EB7D6B8ULL,
		0x8F5DC92510131924ULL,
		0x7684BF9E025692AFULL,
		0xD909DB105A5AF4B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD696CF546EB7D6B8ULL,
		0x8F5DC92510131924ULL,
		0x7684BF9E025692AFULL,
		0xD909DB105A5AF4B9ULL,
		0x3E783BFE1DB19A9CULL,
		0x272D13726D6F79E6ULL,
		0x047789AC17F7E9D3ULL,
		0x9984CCB17407CA19ULL
	}};
	printf("Test Case 505\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 505 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA2C1C1FE7B4F285ULL,
		0x3C4A2977D1719EC3ULL,
		0xC1FC596FBF5E017BULL,
		0x3C1DA4A15C161DFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5E98064A7378553ULL,
		0x8697A7B092A2E4CBULL,
		0xA3CB72785B3C231AULL,
		0xCF662FD999B36747ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5E98064A7378553ULL,
		0x8697A7B092A2E4CBULL,
		0xA3CB72785B3C231AULL,
		0xCF662FD999B36747ULL,
		0xCA2C1C1FE7B4F285ULL,
		0x3C4A2977D1719EC3ULL,
		0xC1FC596FBF5E017BULL,
		0x3C1DA4A15C161DFCULL
	}};
	printf("Test Case 506\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 506 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56277E00510578B7ULL,
		0xE669D16C9D65CB8EULL,
		0xF8DB4345E97CFA3AULL,
		0x4BC632DA30DB8C77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A54CDDB94703CAEULL,
		0x859FD20064A8EBB8ULL,
		0x9FE783F4EF72A1C4ULL,
		0x3C4D3484A1F9236AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A54CDDB94703CAEULL,
		0x859FD20064A8EBB8ULL,
		0x9FE783F4EF72A1C4ULL,
		0x3C4D3484A1F9236AULL,
		0x56277E00510578B7ULL,
		0xE669D16C9D65CB8EULL,
		0xF8DB4345E97CFA3AULL,
		0x4BC632DA30DB8C77ULL
	}};
	printf("Test Case 507\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 507 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40FBAEC254FAAAF5ULL,
		0xF84BAA08D9BBA9EFULL,
		0x71AD1A35C4F6A3FDULL,
		0xA3D535E6D9DF3597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4054C5D69A2A247ULL,
		0xD27C86B32B5F1FACULL,
		0xB709274DBA2197C7ULL,
		0x60BEA98A6E467510ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4054C5D69A2A247ULL,
		0xD27C86B32B5F1FACULL,
		0xB709274DBA2197C7ULL,
		0x60BEA98A6E467510ULL,
		0x40FBAEC254FAAAF5ULL,
		0xF84BAA08D9BBA9EFULL,
		0x71AD1A35C4F6A3FDULL,
		0xA3D535E6D9DF3597ULL
	}};
	printf("Test Case 508\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 508 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA2F84ECFFE17EFDBULL,
		0x294EABC8329BDF3AULL,
		0x1CDB71C8E816732CULL,
		0x71C6347D779FBB61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA718D2B789710982ULL,
		0x48D77FCC30A726E4ULL,
		0xAE57D390F4D17D5EULL,
		0x98672180E9145943ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA718D2B789710982ULL,
		0x48D77FCC30A726E4ULL,
		0xAE57D390F4D17D5EULL,
		0x98672180E9145943ULL,
		0xA2F84ECFFE17EFDBULL,
		0x294EABC8329BDF3AULL,
		0x1CDB71C8E816732CULL,
		0x71C6347D779FBB61ULL
	}};
	printf("Test Case 509\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 509 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A47930BFDB1E9D8ULL,
		0x4325E2526E17C406ULL,
		0x78DE154C6BBDA542ULL,
		0x5CA7E7306A9249E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4309E5B0B625FD93ULL,
		0xA76A6E613126E64EULL,
		0xF384A95676A237E2ULL,
		0x55BF57A2A54FFCC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4309E5B0B625FD93ULL,
		0xA76A6E613126E64EULL,
		0xF384A95676A237E2ULL,
		0x55BF57A2A54FFCC8ULL,
		0x3A47930BFDB1E9D8ULL,
		0x4325E2526E17C406ULL,
		0x78DE154C6BBDA542ULL,
		0x5CA7E7306A9249E9ULL
	}};
	printf("Test Case 510\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 510 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}