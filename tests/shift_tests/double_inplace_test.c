#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA97CFDD2B62D70EBULL,
		0x4C155AD304B9673CULL,
		0x2DE1B925EF146940ULL,
		0x1953C1D71BEFF8BFULL,
		0x4A56838FF68392B5ULL,
		0xC4163CED308FF0D4ULL,
		0xF4DF9037F34F240BULL,
		0x2801FB88E61A00A3ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x52F9FBA56C5AE1D6ULL,
		0x982AB5A60972CE79ULL,
		0x5BC3724BDE28D280ULL,
		0x32A783AE37DFF17EULL,
		0x94AD071FED07256AULL,
		0x882C79DA611FE1A8ULL,
		0xE9BF206FE69E4817ULL,
		0x5003F711CC340147ULL
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
		0xF4AA4A1CF8E1A07AULL,
		0x9C6F31B13C90671AULL,
		0xC698CBC4BCDE216AULL,
		0xCE4A95CDC53B8AECULL,
		0xB8435627D4E45604ULL,
		0x7FD5DB1DAEC42E96ULL,
		0x1BF81862F13B2727ULL,
		0x2AA717A37CEDC3F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9549439F1C340F4ULL,
		0x38DE63627920CE35ULL,
		0x8D31978979BC42D5ULL,
		0x9C952B9B8A7715D9ULL,
		0x7086AC4FA9C8AC09ULL,
		0xFFABB63B5D885D2DULL,
		0x37F030C5E2764E4EULL,
		0x554E2F46F9DB87F2ULL
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
		0x53E0016189940080ULL,
		0xDA2DB26058CDFCE7ULL,
		0xADB47C4F3F8288C2ULL,
		0x1186195F0F3ABA80ULL,
		0x772BFE9BB19F0FC4ULL,
		0x4AE6C0574B346010ULL,
		0xA3E5CCDA393C1A75ULL,
		0x1DF427905160B85AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7C002C313280100ULL,
		0xB45B64C0B19BF9CEULL,
		0x5B68F89E7F051185ULL,
		0x230C32BE1E757501ULL,
		0xEE57FD37633E1F88ULL,
		0x95CD80AE9668C020ULL,
		0x47CB99B4727834EAULL,
		0x3BE84F20A2C170B5ULL
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
		0x52ED366FD3C74C33ULL,
		0x82B2AAC38A9CF0A3ULL,
		0x537B537BBE59A456ULL,
		0x8E531B9260B6C794ULL,
		0x423D34ECB4AE5650ULL,
		0xC8E706463E35F48FULL,
		0xF0B088575339D2CDULL,
		0x0CF3E6689C9EB348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5DA6CDFA78E9866ULL,
		0x056555871539E146ULL,
		0xA6F6A6F77CB348ADULL,
		0x1CA63724C16D8F28ULL,
		0x847A69D9695CACA1ULL,
		0x91CE0C8C7C6BE91EULL,
		0xE16110AEA673A59BULL,
		0x19E7CCD1393D6691ULL
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
		0x6E2A4F6D0A3745A5ULL,
		0x3376E54FD5734659ULL,
		0x76C1AD34B8EE2964ULL,
		0x76E91CA38FE2FE3FULL,
		0x9BADC45C4327B2D7ULL,
		0x9EC7AB5A9644077DULL,
		0x913A6028A0316EE9ULL,
		0x2CF3CF8748E3A9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC549EDA146E8B4AULL,
		0x66EDCA9FAAE68CB2ULL,
		0xED835A6971DC52C8ULL,
		0xEDD239471FC5FC7EULL,
		0x375B88B8864F65AEULL,
		0x3D8F56B52C880EFBULL,
		0x2274C0514062DDD3ULL,
		0x59E79F0E91C75369ULL
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
		0xB98719D7213BAAE9ULL,
		0x01070B251923D8FEULL,
		0x25835E393266B03EULL,
		0xDA325DBBDE98FE39ULL,
		0x03B66EC03C6FC499ULL,
		0xC026A9986DE0B6F5ULL,
		0x4FB2BD4824484FB3ULL,
		0x0F0F78DBBE9DF54CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730E33AE427755D2ULL,
		0x020E164A3247B1FDULL,
		0x4B06BC7264CD607CULL,
		0xB464BB77BD31FC72ULL,
		0x076CDD8078DF8933ULL,
		0x804D5330DBC16DEAULL,
		0x9F657A9048909F67ULL,
		0x1E1EF1B77D3BEA98ULL
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
		0x25C625F6344422CEULL,
		0x03464780E15C48BFULL,
		0xE04230CE7DA1F119ULL,
		0x9A57A22BB631DCDBULL,
		0x850ACBF108FA592CULL,
		0x63EFDD7EB5AFC7B9ULL,
		0xD47570B1977FD79DULL,
		0x16C8F63CA389CCCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B8C4BEC6888459CULL,
		0x068C8F01C2B8917EULL,
		0xC084619CFB43E232ULL,
		0x34AF44576C63B9B7ULL,
		0x0A1597E211F4B259ULL,
		0xC7DFBAFD6B5F8F73ULL,
		0xA8EAE1632EFFAF3AULL,
		0x2D91EC794713999FULL
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
		0x926322DC1387240CULL,
		0x92F29F985D51D97AULL,
		0xA99DFFFA5FB4CAB8ULL,
		0xFB59B36FBF351E14ULL,
		0x796D3CD755D35AEAULL,
		0x1F90EDC69BBB232BULL,
		0xAF18FACDBC4313EDULL,
		0x1F1D840EEA3DE5FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C645B8270E4818ULL,
		0x25E53F30BAA3B2F5ULL,
		0x533BFFF4BF699571ULL,
		0xF6B366DF7E6A3C29ULL,
		0xF2DA79AEABA6B5D5ULL,
		0x3F21DB8D37764656ULL,
		0x5E31F59B788627DAULL,
		0x3E3B081DD47BCBF9ULL
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
		0xF47569EFA96CCEE1ULL,
		0xB107F996411E42E9ULL,
		0x57C5084A47C3EC43ULL,
		0x1AF5CFF64D5A4873ULL,
		0x07C093DC4701290AULL,
		0x7290ADA09D31B136ULL,
		0x419BE99B712FC5A2ULL,
		0x08544CB4B2151453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8EAD3DF52D99DC2ULL,
		0x620FF32C823C85D3ULL,
		0xAF8A10948F87D887ULL,
		0x35EB9FEC9AB490E6ULL,
		0x0F8127B88E025214ULL,
		0xE5215B413A63626CULL,
		0x8337D336E25F8B44ULL,
		0x10A89969642A28A6ULL
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
		0x4CBB9D52580F71F2ULL,
		0xDAB65279BCA6DC1FULL,
		0x6B4C29D84AF4A859ULL,
		0x70F0EA2F754C9650ULL,
		0xA7FC0D5FBE74BA7EULL,
		0xBAC825A4A0BD2000ULL,
		0x825FE633700FD667ULL,
		0x2146AE9E9C9E400DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99773AA4B01EE3E4ULL,
		0xB56CA4F3794DB83EULL,
		0xD69853B095E950B3ULL,
		0xE1E1D45EEA992CA0ULL,
		0x4FF81ABF7CE974FCULL,
		0x75904B49417A4001ULL,
		0x04BFCC66E01FACCFULL,
		0x428D5D3D393C801BULL
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
		0xC89B5CCC9D10D851ULL,
		0x197ABBE847C865DBULL,
		0xFB43278F59D2009FULL,
		0x8F81C0D4A5FFB6FEULL,
		0xED8B55008D08D0B4ULL,
		0x71D46CD3E3CB6E72ULL,
		0xAEB270AFDA6DC48BULL,
		0x290B8B92CD36650CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9136B9993A21B0A2ULL,
		0x32F577D08F90CBB7ULL,
		0xF6864F1EB3A4013EULL,
		0x1F0381A94BFF6DFDULL,
		0xDB16AA011A11A169ULL,
		0xE3A8D9A7C796DCE5ULL,
		0x5D64E15FB4DB8916ULL,
		0x521717259A6CCA19ULL
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
		0xF51765C70F107083ULL,
		0x4D49CF044EA5C72AULL,
		0xC91D96D0DCFFE337ULL,
		0x9A71ED85CBED7F83ULL,
		0xD45DBDBFEC7B897DULL,
		0x6C2F43B8DDAABFF7ULL,
		0xBFDF65DF47184E0AULL,
		0x12944E55ABD7143BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2ECB8E1E20E106ULL,
		0x9A939E089D4B8E55ULL,
		0x923B2DA1B9FFC66EULL,
		0x34E3DB0B97DAFF07ULL,
		0xA8BB7B7FD8F712FBULL,
		0xD85E8771BB557FEFULL,
		0x7FBECBBE8E309C14ULL,
		0x25289CAB57AE2877ULL
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
		0x3BD3CDB435EAA020ULL,
		0x8543442D97030CF3ULL,
		0xE7765386D0300D9EULL,
		0x91FFF0AE7334740BULL,
		0xE72E6353B8B373D0ULL,
		0xD03F0DCF1CDBFABEULL,
		0xFEB83B7F6BD6B022ULL,
		0x24495DD567EF6A49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77A79B686BD54040ULL,
		0x0A86885B2E0619E6ULL,
		0xCEECA70DA0601B3DULL,
		0x23FFE15CE668E817ULL,
		0xCE5CC6A77166E7A1ULL,
		0xA07E1B9E39B7F57DULL,
		0xFD7076FED7AD6045ULL,
		0x4892BBAACFDED493ULL
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
		0x051797C994E2E4F0ULL,
		0xAD0C31ACE8DF8A6EULL,
		0xF5FBFB90420CE509ULL,
		0xBBAF0FF276D78463ULL,
		0x013CF8F6784870F2ULL,
		0x841DC227116288E4ULL,
		0x6C5126CD38238AA1ULL,
		0x019C2F923B107D23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2F2F9329C5C9E0ULL,
		0x5A186359D1BF14DCULL,
		0xEBF7F7208419CA13ULL,
		0x775E1FE4EDAF08C7ULL,
		0x0279F1ECF090E1E5ULL,
		0x083B844E22C511C8ULL,
		0xD8A24D9A70471543ULL,
		0x03385F247620FA46ULL
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
		0x2190ED307EB9A432ULL,
		0x8DCDA7B095C7EA5BULL,
		0x9BAEC37839A7C1B9ULL,
		0x56E7FF009869ED1EULL,
		0xB2A654EB28729C40ULL,
		0x6E9920BB8C3C5231ULL,
		0xA95B4F13433DBDFBULL,
		0x15E5FB02F5C5D033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4321DA60FD734864ULL,
		0x1B9B4F612B8FD4B6ULL,
		0x375D86F0734F8373ULL,
		0xADCFFE0130D3DA3DULL,
		0x654CA9D650E53880ULL,
		0xDD3241771878A463ULL,
		0x52B69E26867B7BF6ULL,
		0x2BCBF605EB8BA067ULL
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
		0x429E239710CC749EULL,
		0xE39D85C09E8364FCULL,
		0x3DC1B0790FFCD12DULL,
		0x22A9A4951447CB96ULL,
		0xC6E81F602EFD8990ULL,
		0x33EBB1EAAE47D423ULL,
		0x0407A6E95663AEC6ULL,
		0x3741FF8B7633E73BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x853C472E2198E93CULL,
		0xC73B0B813D06C9F8ULL,
		0x7B8360F21FF9A25BULL,
		0x4553492A288F972CULL,
		0x8DD03EC05DFB1320ULL,
		0x67D763D55C8FA847ULL,
		0x080F4DD2ACC75D8CULL,
		0x6E83FF16EC67CE76ULL
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
		0x5E6BDBB408962E13ULL,
		0xA121A187E6821A72ULL,
		0x025266D3A5585CD9ULL,
		0xE1080B4C87EC3346ULL,
		0x732AE3C7A1766B4AULL,
		0xFCE0EADFF3A91D96ULL,
		0xD496F897D67C04ADULL,
		0x08BF0297A1FB0DB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCD7B768112C5C26ULL,
		0x4243430FCD0434E4ULL,
		0x04A4CDA74AB0B9B3ULL,
		0xC21016990FD8668CULL,
		0xE655C78F42ECD695ULL,
		0xF9C1D5BFE7523B2CULL,
		0xA92DF12FACF8095BULL,
		0x117E052F43F61B69ULL
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
		0xD33347155EDCDE4EULL,
		0x170A01495409EE70ULL,
		0xFA0FCA7CDBCEEC04ULL,
		0xFFA061A9C3BA53C1ULL,
		0x57AA2935A3C4B5E0ULL,
		0xEE51FFCE541B62A6ULL,
		0x6FFFDFF283A37497ULL,
		0x19DFDC83EC900F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6668E2ABDB9BC9CULL,
		0x2E140292A813DCE1ULL,
		0xF41F94F9B79DD808ULL,
		0xFF40C3538774A783ULL,
		0xAF54526B47896BC1ULL,
		0xDCA3FF9CA836C54CULL,
		0xDFFFBFE50746E92FULL,
		0x33BFB907D9201E38ULL
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
		0xCC514AFB161952F6ULL,
		0xF374799820B4DC70ULL,
		0x118A0A02692318B3ULL,
		0x4CF8C5546699B54CULL,
		0x81C8F312D10C08E9ULL,
		0x813738B584AF66F4ULL,
		0xACC34E587FB5A8FDULL,
		0x26FD17C79F8AF0AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A295F62C32A5ECULL,
		0xE6E8F3304169B8E1ULL,
		0x23141404D2463167ULL,
		0x99F18AA8CD336A98ULL,
		0x0391E625A21811D2ULL,
		0x026E716B095ECDE9ULL,
		0x59869CB0FF6B51FBULL,
		0x4DFA2F8F3F15E15DULL
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
		0x5DD9B31F3F0956F7ULL,
		0xC7FAC9131D9D54C7ULL,
		0xE4E4B24A54F39C73ULL,
		0x13F3BBB57CCC0020ULL,
		0xAF3D6B6B728959F7ULL,
		0x55E7F013457D222DULL,
		0xD9CDD1ECB2C4A271ULL,
		0x398F83853697EDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB3663E7E12ADEEULL,
		0x8FF592263B3AA98EULL,
		0xC9C96494A9E738E7ULL,
		0x27E7776AF9980041ULL,
		0x5E7AD6D6E512B3EEULL,
		0xABCFE0268AFA445BULL,
		0xB39BA3D9658944E2ULL,
		0x731F070A6D2FDBB5ULL
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
		0x52AE168CDFB420DFULL,
		0xEC0B1E5CA3CF9253ULL,
		0x709640B2B68DBC76ULL,
		0x02D17B954F63D951ULL,
		0x8381834095A5AE9AULL,
		0x770395BB20837788ULL,
		0x4E5BF84E2DDEBC8BULL,
		0x02B26C14C86111DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55C2D19BF6841BEULL,
		0xD8163CB9479F24A6ULL,
		0xE12C81656D1B78EDULL,
		0x05A2F72A9EC7B2A2ULL,
		0x070306812B4B5D34ULL,
		0xEE072B764106EF11ULL,
		0x9CB7F09C5BBD7916ULL,
		0x0564D82990C223B6ULL
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
		0x334CFC49D8151690ULL,
		0x66CCAEE88AFBA20BULL,
		0x722C9528AD11FC6FULL,
		0xF15331908D0FCA43ULL,
		0xBF08DF4E7F9537A0ULL,
		0x5F3495C1C09053AFULL,
		0xBC7A68A4C9AB7E8EULL,
		0x31424AB1CA58F5A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6699F893B02A2D20ULL,
		0xCD995DD115F74416ULL,
		0xE4592A515A23F8DEULL,
		0xE2A663211A1F9486ULL,
		0x7E11BE9CFF2A6F41ULL,
		0xBE692B838120A75FULL,
		0x78F4D1499356FD1CULL,
		0x6284956394B1EB45ULL
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
		0x4493B3220924C02BULL,
		0x197EB51632D1555FULL,
		0x8637FD9F45251140ULL,
		0x97C62E8E3EDB1582ULL,
		0xA242231025A848E1ULL,
		0x886E65764C111C49ULL,
		0x80EBCFAC0B922584ULL,
		0x33F2BDB2195F0A2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8927664412498056ULL,
		0x32FD6A2C65A2AABEULL,
		0x0C6FFB3E8A4A2280ULL,
		0x2F8C5D1C7DB62B05ULL,
		0x448446204B5091C3ULL,
		0x10DCCAEC98223893ULL,
		0x01D79F5817244B09ULL,
		0x67E57B6432BE145DULL
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
		0x8C60F0E3947A9C40ULL,
		0x88D63ACDCC248ABAULL,
		0xAD30C8058A9DA7AEULL,
		0x2DAC66FEA74BB62DULL,
		0xF358C562F95435C6ULL,
		0xF020699769D6559CULL,
		0x156F91014795E322ULL,
		0x347A53A98AB38E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C1E1C728F53880ULL,
		0x11AC759B98491575ULL,
		0x5A61900B153B4F5DULL,
		0x5B58CDFD4E976C5BULL,
		0xE6B18AC5F2A86B8CULL,
		0xE040D32ED3ACAB39ULL,
		0x2ADF22028F2BC645ULL,
		0x68F4A75315671CCAULL
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
		0x1BB8E743B45450F3ULL,
		0x61BB123ED8C47427ULL,
		0xAEED0A27EC593E62ULL,
		0xB7799761E9F220CBULL,
		0x7845AFAE23F541DDULL,
		0xD15390CAE5056673ULL,
		0x9DCB05116340455EULL,
		0x0891D2D1D4570E44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3771CE8768A8A1E6ULL,
		0xC376247DB188E84EULL,
		0x5DDA144FD8B27CC4ULL,
		0x6EF32EC3D3E44197ULL,
		0xF08B5F5C47EA83BBULL,
		0xA2A72195CA0ACCE6ULL,
		0x3B960A22C6808ABDULL,
		0x1123A5A3A8AE1C89ULL
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
		0x750629E844A4647EULL,
		0x53F5C3528437011FULL,
		0x649A608D507CC37FULL,
		0x400164D464570B02ULL,
		0xFE20E844ECE7394EULL,
		0x9DFCD60E9374BA22ULL,
		0xDDD38127CE71F42BULL,
		0x122CB31292CEC212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA0C53D08948C8FCULL,
		0xA7EB86A5086E023EULL,
		0xC934C11AA0F986FEULL,
		0x8002C9A8C8AE1604ULL,
		0xFC41D089D9CE729CULL,
		0x3BF9AC1D26E97445ULL,
		0xBBA7024F9CE3E857ULL,
		0x24596625259D8425ULL
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
		0x715AB892B435D1E9ULL,
		0x419EA4298AC323F3ULL,
		0x3414BCB2699EF65FULL,
		0xED21319B24ACDF91ULL,
		0x60B78AD2452BB25EULL,
		0xDD7C87D46B81D2F9ULL,
		0xBBC797ABB0F9C0C3ULL,
		0x0EE5E0BD2C9E6CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B57125686BA3D2ULL,
		0x833D4853158647E6ULL,
		0x68297964D33DECBEULL,
		0xDA4263364959BF22ULL,
		0xC16F15A48A5764BDULL,
		0xBAF90FA8D703A5F2ULL,
		0x778F2F5761F38187ULL,
		0x1DCBC17A593CD9B9ULL
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
		0xD11C141167D9E2F2ULL,
		0xC506ACE3C81E6CBDULL,
		0x02178F165B788015ULL,
		0x6BEC5C25CFB9FBC8ULL,
		0xA6E9C4D569CF1D3FULL,
		0xDB1488C2B3E0546CULL,
		0x64F6761C41BD0629ULL,
		0x39D94F8DA39FB218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2382822CFB3C5E4ULL,
		0x8A0D59C7903CD97BULL,
		0x042F1E2CB6F1002BULL,
		0xD7D8B84B9F73F790ULL,
		0x4DD389AAD39E3A7EULL,
		0xB629118567C0A8D9ULL,
		0xC9ECEC38837A0C53ULL,
		0x73B29F1B473F6430ULL
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
		0xC03AE970BD148F6AULL,
		0x8F4A27EB19024F96ULL,
		0x964417E2B82CE404ULL,
		0xE1577A1CADAC15F5ULL,
		0x023284A2D47DCE32ULL,
		0xB45EA1AB9B23982EULL,
		0x0B7B02434B29CA2FULL,
		0x1A0B36BECD9804DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8075D2E17A291ED4ULL,
		0x1E944FD632049F2DULL,
		0x2C882FC57059C809ULL,
		0xC2AEF4395B582BEBULL,
		0x04650945A8FB9C65ULL,
		0x68BD43573647305CULL,
		0x16F604869653945FULL,
		0x34166D7D9B3009B4ULL
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
		0xD236FFEFF96171FBULL,
		0xB7C05AF6BA671AECULL,
		0xE38F7140EED30298ULL,
		0x3C940DDA4F073B60ULL,
		0x7ED6120071D89BFDULL,
		0x6521F22BE878B615ULL,
		0x595914050E027541ULL,
		0x31100D7F85EB9C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA46DFFDFF2C2E3F6ULL,
		0x6F80B5ED74CE35D9ULL,
		0xC71EE281DDA60531ULL,
		0x79281BB49E0E76C1ULL,
		0xFDAC2400E3B137FAULL,
		0xCA43E457D0F16C2AULL,
		0xB2B2280A1C04EA82ULL,
		0x62201AFF0BD73802ULL
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
		0x9B92C47282113F24ULL,
		0x40CFFA5740C11790ULL,
		0x92F9CF56E7688344ULL,
		0x922C84F5051A30B6ULL,
		0xD183F2FF4C7C1B2BULL,
		0x05C0C478BE9A5961ULL,
		0xE9ACD08810558C3EULL,
		0x3A19B0ADCB6B09CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x372588E504227E48ULL,
		0x819FF4AE81822F21ULL,
		0x25F39EADCED10688ULL,
		0x245909EA0A34616DULL,
		0xA307E5FE98F83657ULL,
		0x0B8188F17D34B2C3ULL,
		0xD359A11020AB187CULL,
		0x7433615B96D6139BULL
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
		0x39B725A9E2643E22ULL,
		0xFA222429FAFA8D51ULL,
		0x8EEC5106D77C785DULL,
		0xB9F5855812B8F970ULL,
		0x6090AB34B9CC9FA3ULL,
		0x5263A8C356918F6BULL,
		0xBD6BD8795BC9EF73ULL,
		0x0BD9358D51491D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736E4B53C4C87C44ULL,
		0xF4444853F5F51AA2ULL,
		0x1DD8A20DAEF8F0BBULL,
		0x73EB0AB02571F2E1ULL,
		0xC121566973993F47ULL,
		0xA4C75186AD231ED6ULL,
		0x7AD7B0F2B793DEE6ULL,
		0x17B26B1AA2923A93ULL
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
		0x7E9837460823DD3DULL,
		0xDF70B24E2122D931ULL,
		0xA5353A2D6A6355E3ULL,
		0xD9E04829CD17A138ULL,
		0x4302C2563C621FEAULL,
		0x2FE8AC0871925169ULL,
		0x360E993ECBDB4DF1ULL,
		0x0A229717A80C79B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD306E8C1047BA7AULL,
		0xBEE1649C4245B262ULL,
		0x4A6A745AD4C6ABC7ULL,
		0xB3C090539A2F4271ULL,
		0x860584AC78C43FD5ULL,
		0x5FD15810E324A2D2ULL,
		0x6C1D327D97B69BE2ULL,
		0x14452E2F5018F370ULL
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
		0xEB081AE2B44D095AULL,
		0x2DCBDC3C4D989155ULL,
		0x09D3B859857AFE28ULL,
		0x98ED9071FC87AB07ULL,
		0x4CB4155B4E8C3418ULL,
		0x8701404F5C70D490ULL,
		0xA4EC7F67280BB646ULL,
		0x016F8FE287F371F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD61035C5689A12B4ULL,
		0x5B97B8789B3122ABULL,
		0x13A770B30AF5FC50ULL,
		0x31DB20E3F90F560EULL,
		0x99682AB69D186831ULL,
		0x0E02809EB8E1A920ULL,
		0x49D8FECE50176C8DULL,
		0x02DF1FC50FE6E3EDULL
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
		0x94A186E39DBAAE19ULL,
		0x564E156B0BC0FF68ULL,
		0x353410FAA87E15BCULL,
		0x3F9828AFDBB0187CULL,
		0xB1EB042DFF6B3808ULL,
		0x0480E4562F51CE57ULL,
		0x1F733C61BD325B71ULL,
		0x0A1833700BAFF7A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29430DC73B755C32ULL,
		0xAC9C2AD61781FED1ULL,
		0x6A6821F550FC2B78ULL,
		0x7F30515FB76030F8ULL,
		0x63D6085BFED67010ULL,
		0x0901C8AC5EA39CAFULL,
		0x3EE678C37A64B6E2ULL,
		0x143066E0175FEF44ULL
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
		0x842A3C72F9AA7263ULL,
		0xD0B136509F03ED8CULL,
		0x78E30DF666CC8738ULL,
		0x8BD1DE23EAF516F1ULL,
		0xF11E10FF906F9C8CULL,
		0x9EA50AF6FBE6A00BULL,
		0x343F9E437D418D14ULL,
		0x21A744B9B010DBABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085478E5F354E4C6ULL,
		0xA1626CA13E07DB19ULL,
		0xF1C61BECCD990E71ULL,
		0x17A3BC47D5EA2DE2ULL,
		0xE23C21FF20DF3919ULL,
		0x3D4A15EDF7CD4017ULL,
		0x687F3C86FA831A29ULL,
		0x434E89736021B756ULL
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
		0xCF78CD61351FD177ULL,
		0x2262C40F82727B90ULL,
		0x319CDBC240311C2AULL,
		0x41F25D769C4C96E8ULL,
		0x422E825D112009A9ULL,
		0x50682BE3ABCCFAA0ULL,
		0x978E048D63B7A229ULL,
		0x1EAA9546AEB524C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EF19AC26A3FA2EEULL,
		0x44C5881F04E4F721ULL,
		0x6339B78480623854ULL,
		0x83E4BAED38992DD0ULL,
		0x845D04BA22401352ULL,
		0xA0D057C75799F540ULL,
		0x2F1C091AC76F4452ULL,
		0x3D552A8D5D6A498FULL
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
		0xF26C773C4422EF6EULL,
		0x2472022FFCD28979ULL,
		0xA8C217B8C22FCD5AULL,
		0x65508ACE7369E07EULL,
		0xC8597504DF7C0450ULL,
		0xB5DEA888EB8886E4ULL,
		0x15B14EDD5EAB109DULL,
		0x1C16CA01CC5E3BD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D8EE788845DEDCULL,
		0x48E4045FF9A512F3ULL,
		0x51842F71845F9AB4ULL,
		0xCAA1159CE6D3C0FDULL,
		0x90B2EA09BEF808A0ULL,
		0x6BBD5111D7110DC9ULL,
		0x2B629DBABD56213BULL,
		0x382D940398BC77A6ULL
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
		0xCA4B5AF49EB373B3ULL,
		0x4D3552DC3EDAE9F3ULL,
		0x6A0DEB850232CB01ULL,
		0xC8F65502F9A12F51ULL,
		0x8519C992C997B815ULL,
		0x32B877FF11310C95ULL,
		0x23EA635A4C1997A7ULL,
		0x3E34D010B946E7B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9496B5E93D66E766ULL,
		0x9A6AA5B87DB5D3E7ULL,
		0xD41BD70A04659602ULL,
		0x91ECAA05F3425EA2ULL,
		0x0A339325932F702BULL,
		0x6570EFFE2262192BULL,
		0x47D4C6B498332F4EULL,
		0x7C69A021728DCF68ULL
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
		0x0E578F4D47F3CC50ULL,
		0x701F4152EE2AA937ULL,
		0xCD73FD6CB2CBF475ULL,
		0x048A6488951384A3ULL,
		0x06582573CFC2931FULL,
		0x6061774A19B00C4CULL,
		0x4FE2F8D5BAED6FF7ULL,
		0x0B5AC4D39E073D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CAF1E9A8FE798A0ULL,
		0xE03E82A5DC55526EULL,
		0x9AE7FAD96597E8EAULL,
		0x0914C9112A270947ULL,
		0x0CB04AE79F85263EULL,
		0xC0C2EE9433601898ULL,
		0x9FC5F1AB75DADFEEULL,
		0x16B589A73C0E7AC2ULL
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
		0xEA4630E61F53C79CULL,
		0xCD5A2895447D6CAFULL,
		0x538CA0F13BFB1AC2ULL,
		0xEBE98A1C334EDE72ULL,
		0x849F9CCEDD65C27CULL,
		0x972C732B8CCBF395ULL,
		0x3322CF7951EB7982ULL,
		0x19C4BF4268ED6D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD48C61CC3EA78F38ULL,
		0x9AB4512A88FAD95FULL,
		0xA71941E277F63585ULL,
		0xD7D31438669DBCE4ULL,
		0x093F399DBACB84F9ULL,
		0x2E58E6571997E72BULL,
		0x66459EF2A3D6F305ULL,
		0x33897E84D1DADA58ULL
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
		0x6E606940498C30FCULL,
		0xDAF0C6A90EC95514ULL,
		0xD1FFB2AB32964FE2ULL,
		0xFE5F704DD4953ED1ULL,
		0xEE16DF8DF3B1E3DEULL,
		0xB1152D94925E32BEULL,
		0x423A3E9BB87319A2ULL,
		0x200ADBF984E9B3E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCC0D280931861F8ULL,
		0xB5E18D521D92AA28ULL,
		0xA3FF6556652C9FC5ULL,
		0xFCBEE09BA92A7DA3ULL,
		0xDC2DBF1BE763C7BDULL,
		0x622A5B2924BC657DULL,
		0x84747D3770E63345ULL,
		0x4015B7F309D367CEULL
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
		0xF7E0CF0508B5C966ULL,
		0xB3B5EC6B2CC77029ULL,
		0xB450921723A1EE4DULL,
		0x13BD8F9D53A88D50ULL,
		0xF2536A424C955EEEULL,
		0x551EF8E213F9E148ULL,
		0xA50A311A0381377AULL,
		0x3E288356E8CAFDEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC19E0A116B92CCULL,
		0x676BD8D6598EE053ULL,
		0x68A1242E4743DC9BULL,
		0x277B1F3AA7511AA1ULL,
		0xE4A6D484992ABDDCULL,
		0xAA3DF1C427F3C291ULL,
		0x4A14623407026EF4ULL,
		0x7C5106ADD195FBDDULL
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
		0x8DA8CC1476972E8BULL,
		0x5DC32EBCB5CE2883ULL,
		0x86452AC7A34F1AF3ULL,
		0x45ADFCC879A88DA0ULL,
		0x021C0050E1048D79ULL,
		0x6BF92747BC35F347ULL,
		0x5805F385EA9A0CA0ULL,
		0x1197AFF1B2377719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B519828ED2E5D16ULL,
		0xBB865D796B9C5107ULL,
		0x0C8A558F469E35E6ULL,
		0x8B5BF990F3511B41ULL,
		0x043800A1C2091AF2ULL,
		0xD7F24E8F786BE68EULL,
		0xB00BE70BD5341940ULL,
		0x232F5FE3646EEE32ULL
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
		0x4AB56D0D00F8217FULL,
		0xD3E17CCB14D70820ULL,
		0xB14DDFB50E40EBA3ULL,
		0xF102D6D6D0198639ULL,
		0x1BE1208EC8A1C796ULL,
		0x30F7FA50FC2E42B4ULL,
		0x9419733DADC993BFULL,
		0x1B4434508FB42814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956ADA1A01F042FEULL,
		0xA7C2F99629AE1040ULL,
		0x629BBF6A1C81D747ULL,
		0xE205ADADA0330C73ULL,
		0x37C2411D91438F2DULL,
		0x61EFF4A1F85C8568ULL,
		0x2832E67B5B93277EULL,
		0x368868A11F685029ULL
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
		0xA9E5111A77ACE08BULL,
		0x499ADFA54649BED4ULL,
		0x2F18E00BBDF6E01FULL,
		0x70D738BEF7D4C88BULL,
		0xCCA90F1DFD20E125ULL,
		0x09148F7D410CCDADULL,
		0x20E39CE87C8B67E4ULL,
		0x2128D467559397EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53CA2234EF59C116ULL,
		0x9335BF4A8C937DA9ULL,
		0x5E31C0177BEDC03EULL,
		0xE1AE717DEFA99116ULL,
		0x99521E3BFA41C24AULL,
		0x12291EFA82199B5BULL,
		0x41C739D0F916CFC8ULL,
		0x4251A8CEAB272FD6ULL
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
		0x7D9AF8EA1644B5D9ULL,
		0x9FDEE3289BB6EF91ULL,
		0xCA9C2F720843857EULL,
		0x0CFA5B43C4DA3E38ULL,
		0xBE636E4717B2A6CAULL,
		0xE4ECAAF7F3CDEA7AULL,
		0x3CE2D14C1B790944ULL,
		0x014A4824E710D025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB35F1D42C896BB2ULL,
		0x3FBDC651376DDF22ULL,
		0x95385EE410870AFDULL,
		0x19F4B68789B47C71ULL,
		0x7CC6DC8E2F654D94ULL,
		0xC9D955EFE79BD4F5ULL,
		0x79C5A29836F21289ULL,
		0x02949049CE21A04AULL
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
		0x70F59A18D3503690ULL,
		0x28729C4CDDD4DE21ULL,
		0xB2213F20E384DADCULL,
		0x30887FB1334C9AB1ULL,
		0x79735DC7E58D1611ULL,
		0x271E4F818F848C29ULL,
		0x110D6E24B2795E1FULL,
		0x19EE1284E64D3196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1EB3431A6A06D20ULL,
		0x50E53899BBA9BC42ULL,
		0x64427E41C709B5B8ULL,
		0x6110FF6266993563ULL,
		0xF2E6BB8FCB1A2C22ULL,
		0x4E3C9F031F091852ULL,
		0x221ADC4964F2BC3EULL,
		0x33DC2509CC9A632CULL
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
		0xA65D4D86F6896489ULL,
		0x064439DDD1D7D8B2ULL,
		0xFD8332F0195FDCD9ULL,
		0x2493F1FFE25267A5ULL,
		0x0AB581EA6FFA3C19ULL,
		0x214026F953BB73ACULL,
		0x5DC6A9E7E14DDA56ULL,
		0x33A7575462FADD97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CBA9B0DED12C912ULL,
		0x0C8873BBA3AFB165ULL,
		0xFB0665E032BFB9B2ULL,
		0x4927E3FFC4A4CF4BULL,
		0x156B03D4DFF47832ULL,
		0x42804DF2A776E758ULL,
		0xBB8D53CFC29BB4ACULL,
		0x674EAEA8C5F5BB2EULL
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
		0x234BEFCF7FD4ABBDULL,
		0x6634937837952C2EULL,
		0xAD7E6E93FFCB0EACULL,
		0x7E9A501FEB4C8435ULL,
		0x4BB0B5E0E163516EULL,
		0x8CFAB3E86A5AF792ULL,
		0x7C624FC395854498ULL,
		0x3D85CCBA5DFD9C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4697DF9EFFA9577AULL,
		0xCC6926F06F2A585CULL,
		0x5AFCDD27FF961D58ULL,
		0xFD34A03FD699086BULL,
		0x97616BC1C2C6A2DCULL,
		0x19F567D0D4B5EF24ULL,
		0xF8C49F872B0A8931ULL,
		0x7B0B9974BBFB3810ULL
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
		0xD01A2928885E3D9AULL,
		0xE547DA2CAB4EE23AULL,
		0xCC9A9296F6B31498ULL,
		0xE4FCD4E873EB84E8ULL,
		0x5C89329EA037C6B5ULL,
		0x9E8774A64D842BBBULL,
		0x4743BA2D585329D6ULL,
		0x126B2AA06AAD157AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA034525110BC7B34ULL,
		0xCA8FB459569DC475ULL,
		0x9935252DED662931ULL,
		0xC9F9A9D0E7D709D1ULL,
		0xB912653D406F8D6BULL,
		0x3D0EE94C9B085776ULL,
		0x8E87745AB0A653ADULL,
		0x24D65540D55A2AF4ULL
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
		0xC8EAC5091C404297ULL,
		0x1544837E998EA22FULL,
		0xC52382E678868122ULL,
		0x30D1221B898E0231ULL,
		0xFB1989EF98F312F8ULL,
		0x2C507830B9FD5105ULL,
		0xE19B5139EB296BF0ULL,
		0x2A548F61B796B11CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D58A123880852EULL,
		0x2A8906FD331D445FULL,
		0x8A4705CCF10D0244ULL,
		0x61A24437131C0463ULL,
		0xF63313DF31E625F0ULL,
		0x58A0F06173FAA20BULL,
		0xC336A273D652D7E0ULL,
		0x54A91EC36F2D6239ULL
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
		0x6A8DFE0B3F347B73ULL,
		0x696A81494321E525ULL,
		0x17F98F992D77B9CCULL,
		0x51A305DC82E140ACULL,
		0xCB109DEAD91A6215ULL,
		0xC60E71E7F7C0E35FULL,
		0x68C072DA571737BDULL,
		0x03548FCE2A408EE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51BFC167E68F6E6ULL,
		0xD2D502928643CA4AULL,
		0x2FF31F325AEF7398ULL,
		0xA3460BB905C28158ULL,
		0x96213BD5B234C42AULL,
		0x8C1CE3CFEF81C6BFULL,
		0xD180E5B4AE2E6F7BULL,
		0x06A91F9C54811DC6ULL
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
		0xD05F52E745175D4FULL,
		0x75AE532F8BE25B67ULL,
		0x45252776AE549144ULL,
		0x81C073D002FAA4F7ULL,
		0x2F50DF2C7C6528C1ULL,
		0xBEE4C1855DD18A10ULL,
		0x83288CCBB07CCB18ULL,
		0x358B6426EA29D02EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0BEA5CE8A2EBA9EULL,
		0xEB5CA65F17C4B6CFULL,
		0x8A4A4EED5CA92288ULL,
		0x0380E7A005F549EEULL,
		0x5EA1BE58F8CA5183ULL,
		0x7DC9830ABBA31420ULL,
		0x0651199760F99631ULL,
		0x6B16C84DD453A05DULL
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
		0x6EDBF5F80729BF7FULL,
		0x83E9BD5BB6D682F0ULL,
		0xDA85AD92F4035DFAULL,
		0x7CFCE3D41271E480ULL,
		0x24349DBCCA197030ULL,
		0x42B36DA60DBA2900ULL,
		0xC292C5D10A9BC1F2ULL,
		0x18FC2EF5C204FB97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB7EBF00E537EFEULL,
		0x07D37AB76DAD05E0ULL,
		0xB50B5B25E806BBF5ULL,
		0xF9F9C7A824E3C901ULL,
		0x48693B799432E060ULL,
		0x8566DB4C1B745200ULL,
		0x85258BA2153783E4ULL,
		0x31F85DEB8409F72FULL
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
		0xD7C7F2C65CEC3B1DULL,
		0x98C6AAE0355EA9F6ULL,
		0xB385AB102F807BDBULL,
		0x05E00674433DB8DDULL,
		0x8A4CE4D994C9BD20ULL,
		0x9F5C79B502E9A91AULL,
		0xE15BCC1AA493C775ULL,
		0x1B00C500D794F8CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8FE58CB9D8763AULL,
		0x318D55C06ABD53EDULL,
		0x670B56205F00F7B7ULL,
		0x0BC00CE8867B71BBULL,
		0x1499C9B329937A40ULL,
		0x3EB8F36A05D35235ULL,
		0xC2B7983549278EEBULL,
		0x36018A01AF29F199ULL
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
		0x610CFEEE0E17C03CULL,
		0xBD8D9493184E4B78ULL,
		0x4A4CE495CA3227CEULL,
		0xB8EA371ED767EA3FULL,
		0xA99AB54577F57C18ULL,
		0xE81E357AD57E9DC9ULL,
		0xAEB5D807C305A551ULL,
		0x1D267741ACD0D2B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC219FDDC1C2F8078ULL,
		0x7B1B2926309C96F0ULL,
		0x9499C92B94644F9DULL,
		0x71D46E3DAECFD47EULL,
		0x53356A8AEFEAF831ULL,
		0xD03C6AF5AAFD3B93ULL,
		0x5D6BB00F860B4AA3ULL,
		0x3A4CEE8359A1A563ULL
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
		0x5E225A737351E1BBULL,
		0xDBEA986928196A95ULL,
		0x92D8CFB37270399BULL,
		0x50BB10DB4A588DA6ULL,
		0xD30A5127520EFB2CULL,
		0xB3FA064EDE886A7DULL,
		0xCA41D47CCD720C76ULL,
		0x210475B668B6B62DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC44B4E6E6A3C376ULL,
		0xB7D530D25032D52AULL,
		0x25B19F66E4E07337ULL,
		0xA17621B694B11B4DULL,
		0xA614A24EA41DF658ULL,
		0x67F40C9DBD10D4FBULL,
		0x9483A8F99AE418EDULL,
		0x4208EB6CD16D6C5BULL
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
		0x2146475CE7D93606ULL,
		0xA8ED6B54B730E6A8ULL,
		0x6278AB8BFE2EAC1BULL,
		0x3196E6F5923D1611ULL,
		0x7D74BD121D65A8A4ULL,
		0x634E4F44039E950DULL,
		0x8D1F464EB5C56841ULL,
		0x3955F1A0F94497B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428C8EB9CFB26C0CULL,
		0x51DAD6A96E61CD50ULL,
		0xC4F15717FC5D5837ULL,
		0x632DCDEB247A2C22ULL,
		0xFAE97A243ACB5148ULL,
		0xC69C9E88073D2A1AULL,
		0x1A3E8C9D6B8AD082ULL,
		0x72ABE341F2892F61ULL
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
		0x6E5E307786088A23ULL,
		0x13E76433FED0329FULL,
		0x316A4618ABC6EF50ULL,
		0x35F58E6F5B6FDB81ULL,
		0x8F3701672E578CC1ULL,
		0x0B5AFA4547A0CD9EULL,
		0xBBC3E776619570F7ULL,
		0x23E9338970E78578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBC60EF0C111446ULL,
		0x27CEC867FDA0653EULL,
		0x62D48C31578DDEA0ULL,
		0x6BEB1CDEB6DFB702ULL,
		0x1E6E02CE5CAF1982ULL,
		0x16B5F48A8F419B3DULL,
		0x7787CEECC32AE1EEULL,
		0x47D26712E1CF0AF1ULL
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
		0x2CF491E1E309F0DFULL,
		0x4F33F59881B17FB6ULL,
		0x991C8EF20E593D42ULL,
		0x37922FE8B45BCB62ULL,
		0x89E25C736286897BULL,
		0xBEC413E5274911A9ULL,
		0xCE431ECAD7BA3B6CULL,
		0x1124D9C389DCA870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E923C3C613E1BEULL,
		0x9E67EB310362FF6CULL,
		0x32391DE41CB27A84ULL,
		0x6F245FD168B796C5ULL,
		0x13C4B8E6C50D12F6ULL,
		0x7D8827CA4E922353ULL,
		0x9C863D95AF7476D9ULL,
		0x2249B38713B950E1ULL
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
		0x06021C5456421B67ULL,
		0x0B4D759AF92E3675ULL,
		0x53367D835987AF84ULL,
		0x9220A6B064D92250ULL,
		0x3D576FD13C25AC28ULL,
		0x42C47473DC361E68ULL,
		0x622AD8773E5E0B0EULL,
		0x32AAD241E71F71DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0438A8AC8436CEULL,
		0x169AEB35F25C6CEAULL,
		0xA66CFB06B30F5F08ULL,
		0x24414D60C9B244A0ULL,
		0x7AAEDFA2784B5851ULL,
		0x8588E8E7B86C3CD0ULL,
		0xC455B0EE7CBC161CULL,
		0x6555A483CE3EE3B8ULL
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
		0x048ECC7692F6AEAEULL,
		0x6F60357E56FAA377ULL,
		0xEABD44577B72AE60ULL,
		0x039B9B61C63AAF01ULL,
		0xA90B0AC747B7D8EEULL,
		0x0F69CC9E79FE89ABULL,
		0x38FF7A10A079A0BDULL,
		0x1D64DB56650C6ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x091D98ED25ED5D5CULL,
		0xDEC06AFCADF546EEULL,
		0xD57A88AEF6E55CC0ULL,
		0x073736C38C755E03ULL,
		0x5216158E8F6FB1DCULL,
		0x1ED3993CF3FD1357ULL,
		0x71FEF42140F3417AULL,
		0x3AC9B6ACCA18D59AULL
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
		0x3752393F7D039840ULL,
		0xCD628DE38D5909C0ULL,
		0x448B30721C0015D3ULL,
		0x4C2BCEC471C7461BULL,
		0xD10FBCF5818625FBULL,
		0xD83FC53799E69E0FULL,
		0x0A70D33995852B9CULL,
		0x1F017936663C5D32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA4727EFA073080ULL,
		0x9AC51BC71AB21380ULL,
		0x891660E438002BA7ULL,
		0x98579D88E38E8C36ULL,
		0xA21F79EB030C4BF6ULL,
		0xB07F8A6F33CD3C1FULL,
		0x14E1A6732B0A5739ULL,
		0x3E02F26CCC78BA64ULL
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
		0x90223BF61E41455FULL,
		0xF5CFC40791235C78ULL,
		0x8CB8470CF23A80FCULL,
		0x991DB3887BFDA7A1ULL,
		0xB11EE6EAE61C5798ULL,
		0x8DCDB699CF2EDAE4ULL,
		0x67EC8F782694C3F0ULL,
		0x1190BA48677D1CAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x204477EC3C828ABEULL,
		0xEB9F880F2246B8F1ULL,
		0x19708E19E47501F9ULL,
		0x323B6710F7FB4F43ULL,
		0x623DCDD5CC38AF31ULL,
		0x1B9B6D339E5DB5C9ULL,
		0xCFD91EF04D2987E1ULL,
		0x23217490CEFA3954ULL
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
		0x571CEA77BD77E7C2ULL,
		0x8DAEC9B9A98AD92CULL,
		0xB10B3A9A69A5F841ULL,
		0x36B60624C22DF244ULL,
		0x6E68FB84EFB55CFCULL,
		0xD298EB5CE8B099CFULL,
		0x894E3214D31C0BC3ULL,
		0x3D7DB431F765AC34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE39D4EF7AEFCF84ULL,
		0x1B5D93735315B258ULL,
		0x62167534D34BF083ULL,
		0x6D6C0C49845BE489ULL,
		0xDCD1F709DF6AB9F8ULL,
		0xA531D6B9D161339EULL,
		0x129C6429A6381787ULL,
		0x7AFB6863EECB5869ULL
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
		0xD67FAABB4C507FE0ULL,
		0xA157D207FF030E42ULL,
		0x8B11EFF363DFAA1FULL,
		0x5D86A21FC0F1BDC0ULL,
		0x3CA9A33D5E71C7C5ULL,
		0xB085E2D1B25A43E1ULL,
		0xC55FEA0E29762FEAULL,
		0x1E5CE42EE142774AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACFF557698A0FFC0ULL,
		0x42AFA40FFE061C85ULL,
		0x1623DFE6C7BF543FULL,
		0xBB0D443F81E37B81ULL,
		0x7953467ABCE38F8AULL,
		0x610BC5A364B487C2ULL,
		0x8ABFD41C52EC5FD5ULL,
		0x3CB9C85DC284EE95ULL
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
		0x4D26C651CABDBE33ULL,
		0x8A622A55DD63256BULL,
		0x864B62C208294103ULL,
		0xD1DECF39898DFD43ULL,
		0x5AB0541643DD6D5FULL,
		0xA8753DBEE6E7D40EULL,
		0xB8B710DE51D790CAULL,
		0x1EEF85BE7B6179D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A4D8CA3957B7C66ULL,
		0x14C454ABBAC64AD6ULL,
		0x0C96C58410528207ULL,
		0xA3BD9E73131BFA87ULL,
		0xB560A82C87BADABFULL,
		0x50EA7B7DCDCFA81CULL,
		0x716E21BCA3AF2195ULL,
		0x3DDF0B7CF6C2F3ABULL
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
		0xE48F74FD6E5E5FEEULL,
		0xCCCB581199032C19ULL,
		0x3560EB44C579E648ULL,
		0x913892F845CE906DULL,
		0x4EA04038C149E0FBULL,
		0x0BA86B7C79066FDBULL,
		0xC12E6D1154C43469ULL,
		0x1EAA4E8B6FE25D05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91EE9FADCBCBFDCULL,
		0x9996B02332065833ULL,
		0x6AC1D6898AF3CC91ULL,
		0x227125F08B9D20DAULL,
		0x9D4080718293C1F7ULL,
		0x1750D6F8F20CDFB6ULL,
		0x825CDA22A98868D2ULL,
		0x3D549D16DFC4BA0BULL
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
		0x405C30D1FB014A37ULL,
		0x9B90A744072C4ED3ULL,
		0x39F01B6CD02EAB81ULL,
		0x9BB15FCD97BDE481ULL,
		0x5C8995931C996658ULL,
		0x7506BCCF5CAFE7EAULL,
		0x661C9D2504577FA7ULL,
		0x0AD68F944C3BCDF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80B861A3F602946EULL,
		0x37214E880E589DA6ULL,
		0x73E036D9A05D5703ULL,
		0x3762BF9B2F7BC902ULL,
		0xB9132B263932CCB1ULL,
		0xEA0D799EB95FCFD4ULL,
		0xCC393A4A08AEFF4EULL,
		0x15AD1F2898779BE4ULL
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
		0xF7BF25B8893332E2ULL,
		0xAD547BE4BE2FF0D0ULL,
		0xF35D7AD380D827CCULL,
		0xB1C015DAE1DBEA1DULL,
		0x18FBD0365620FE06ULL,
		0xA30BF5A7FBBA186EULL,
		0x37139056DDCF3B01ULL,
		0x0C2CC6D9BC78E25DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF7E4B71126665C4ULL,
		0x5AA8F7C97C5FE1A1ULL,
		0xE6BAF5A701B04F99ULL,
		0x63802BB5C3B7D43BULL,
		0x31F7A06CAC41FC0DULL,
		0x4617EB4FF77430DCULL,
		0x6E2720ADBB9E7603ULL,
		0x18598DB378F1C4BAULL
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
		0xFD72076C04C3DEEAULL,
		0x5039E7557975F836ULL,
		0xBEB06E0865B08527ULL,
		0xA2B539538C8B5390ULL,
		0xC61AE970890350C7ULL,
		0xE0BFDC8A251B22CAULL,
		0xEEFA037CDC8815D9ULL,
		0x10512347C0E5D93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE40ED80987BDD4ULL,
		0xA073CEAAF2EBF06DULL,
		0x7D60DC10CB610A4EULL,
		0x456A72A71916A721ULL,
		0x8C35D2E11206A18FULL,
		0xC17FB9144A364595ULL,
		0xDDF406F9B9102BB3ULL,
		0x20A2468F81CBB27FULL
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
		0xB699393673CDE20FULL,
		0x08933FEF819AB8D4ULL,
		0x089A0AD1C7835FF2ULL,
		0xA704E54C8E6C7C18ULL,
		0x0D0431190D6FAEF5ULL,
		0x3254B9035B6F0D4CULL,
		0xF928D66CDB807FC8ULL,
		0x253BD65CF72A4C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D32726CE79BC41EULL,
		0x11267FDF033571A9ULL,
		0x113415A38F06BFE4ULL,
		0x4E09CA991CD8F830ULL,
		0x1A0862321ADF5DEBULL,
		0x64A97206B6DE1A98ULL,
		0xF251ACD9B700FF90ULL,
		0x4A77ACB9EE54985FULL
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
		0x7A3D78EBF20FD8AFULL,
		0xFCDDC38780C4E399ULL,
		0xCC3E0D6CF83C83BDULL,
		0x788F2CEB95ACF30CULL,
		0x86089B90C6D70F55ULL,
		0x15DC403407C0ADD9ULL,
		0x0C4880C96A29E8BEULL,
		0x03F09B491AE91CCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF47AF1D7E41FB15EULL,
		0xF9BB870F0189C732ULL,
		0x987C1AD9F079077BULL,
		0xF11E59D72B59E619ULL,
		0x0C1137218DAE1EAAULL,
		0x2BB880680F815BB3ULL,
		0x18910192D453D17CULL,
		0x07E1369235D23998ULL
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
		0x5942AE7E2FCF4580ULL,
		0xD525B2D16AF96B4CULL,
		0x61C8C08E3F7C6D64ULL,
		0x4CA1F477DF8C3A1CULL,
		0xBDE16FBCBA25BC60ULL,
		0x3C989397DF97F686ULL,
		0x16102FE8FB5CD87AULL,
		0x09C50C051CC2F245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2855CFC5F9E8B00ULL,
		0xAA4B65A2D5F2D698ULL,
		0xC391811C7EF8DAC9ULL,
		0x9943E8EFBF187438ULL,
		0x7BC2DF79744B78C0ULL,
		0x7931272FBF2FED0DULL,
		0x2C205FD1F6B9B0F4ULL,
		0x138A180A3985E48AULL
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
		0x2A76EC1C31A853AFULL,
		0xCF8E67CE4675043DULL,
		0x6DD3C23E3DD53033ULL,
		0x14AA37364F6E0297ULL,
		0xBE53481B5763D534ULL,
		0x9F65689A1A32C708ULL,
		0x5EB134B5D6511C27ULL,
		0x1CCAEAEA1C7F2A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54EDD8386350A75EULL,
		0x9F1CCF9C8CEA087AULL,
		0xDBA7847C7BAA6067ULL,
		0x29546E6C9EDC052EULL,
		0x7CA69036AEC7AA68ULL,
		0x3ECAD13434658E11ULL,
		0xBD62696BACA2384FULL,
		0x3995D5D438FE5508ULL
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
		0x0EC721CC2F6FA735ULL,
		0xABE0DF0A93D3E34AULL,
		0x4ADAA66480CA46EAULL,
		0x82321D7E38940DCEULL,
		0xC4022545D45A79AEULL,
		0xF0A0CE390D2E52BAULL,
		0xEBF54D023C7A134AULL,
		0x001CB48E29907BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8E43985EDF4E6AULL,
		0x57C1BE1527A7C694ULL,
		0x95B54CC901948DD5ULL,
		0x04643AFC71281B9CULL,
		0x88044A8BA8B4F35DULL,
		0xE1419C721A5CA575ULL,
		0xD7EA9A0478F42695ULL,
		0x0039691C5320F7D3ULL
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
		0x7CC02EDCD801EF9CULL,
		0x26167F4A743589BAULL,
		0x2C0210033F258221ULL,
		0x0EF21D1E01DCE093ULL,
		0xDDEE2874C300D0FAULL,
		0x338AC368E271ACBAULL,
		0xFFDEBA3343C710DEULL,
		0x1E18109ED90692CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9805DB9B003DF38ULL,
		0x4C2CFE94E86B1374ULL,
		0x580420067E4B0442ULL,
		0x1DE43A3C03B9C126ULL,
		0xBBDC50E98601A1F4ULL,
		0x671586D1C4E35975ULL,
		0xFFBD7466878E21BCULL,
		0x3C30213DB20D2597ULL
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
		0xC4AC3188385AF896ULL,
		0x9AFF99D3BA850E90ULL,
		0xAD63DA5BF725C92FULL,
		0xE88D1AAF64F56F55ULL,
		0xCAB853A9F1228611ULL,
		0x6BE450094A73647AULL,
		0x9C9F7B7882DB2384ULL,
		0x2684B26FC8BF2E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8958631070B5F12CULL,
		0x35FF33A7750A1D21ULL,
		0x5AC7B4B7EE4B925FULL,
		0xD11A355EC9EADEABULL,
		0x9570A753E2450C23ULL,
		0xD7C8A01294E6C8F5ULL,
		0x393EF6F105B64708ULL,
		0x4D0964DF917E5C9DULL
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
		0x43F2121874876610ULL,
		0x0B98982E8D0586D0ULL,
		0x192A415D71BEBD56ULL,
		0x2A3E7B75BA0B25A3ULL,
		0x2806FC143E514AB1ULL,
		0x0F797B7AC89FFF97ULL,
		0xF78B404A136DC95DULL,
		0x0BEDC819A0C8946FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E42430E90ECC20ULL,
		0x1731305D1A0B0DA0ULL,
		0x325482BAE37D7AACULL,
		0x547CF6EB74164B46ULL,
		0x500DF8287CA29562ULL,
		0x1EF2F6F5913FFF2EULL,
		0xEF16809426DB92BAULL,
		0x17DB9033419128DFULL
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
		0x66600AA66F5206FFULL,
		0x1645EC4F94AB95D8ULL,
		0x297EC327731D7589ULL,
		0xD3E6F0419909DA34ULL,
		0x5B46B87924A2B61BULL,
		0xEDB51D6B7E287E5CULL,
		0xC1B4567D542B8B57ULL,
		0x0411AD30587B0699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC0154CDEA40DFEULL,
		0x2C8BD89F29572BB0ULL,
		0x52FD864EE63AEB12ULL,
		0xA7CDE0833213B468ULL,
		0xB68D70F249456C37ULL,
		0xDB6A3AD6FC50FCB8ULL,
		0x8368ACFAA85716AFULL,
		0x08235A60B0F60D33ULL
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
		0x1AB7B03B17256FE7ULL,
		0x157473D39B77BCB1ULL,
		0x44E9235412E33BA8ULL,
		0x79867E04D34D706EULL,
		0x3E3C4FF4A787F45AULL,
		0x85F676D1E95D2BC2ULL,
		0x2F0FF09A7C2490D6ULL,
		0x3097590FC827951BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x356F60762E4ADFCEULL,
		0x2AE8E7A736EF7962ULL,
		0x89D246A825C67750ULL,
		0xF30CFC09A69AE0DCULL,
		0x7C789FE94F0FE8B4ULL,
		0x0BECEDA3D2BA5784ULL,
		0x5E1FE134F84921ADULL,
		0x612EB21F904F2A36ULL
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
		0x4A3A0B7B768BDC27ULL,
		0xDAEE369B8D7B13E7ULL,
		0x6210FEF1D9E2AB8DULL,
		0x5BD7D77FFCD03F4FULL,
		0x3A39A47C2903F9F7ULL,
		0xFCCDF519C8EA5610ULL,
		0x84B2987CF53C2854ULL,
		0x19A81604FC611527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x947416F6ED17B84EULL,
		0xB5DC6D371AF627CEULL,
		0xC421FDE3B3C5571BULL,
		0xB7AFAEFFF9A07E9EULL,
		0x747348F85207F3EEULL,
		0xF99BEA3391D4AC20ULL,
		0x096530F9EA7850A9ULL,
		0x33502C09F8C22A4FULL
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
		0x6D816B1E885EA89DULL,
		0xCBD0CB9328887336ULL,
		0x58C278BEABBB8A5BULL,
		0x25A4D4F5ACD6FA5EULL,
		0xFECA588A5AD25856ULL,
		0xCA769EC5036BBB8DULL,
		0x58C46A05795ECE72ULL,
		0x2DCB28206C2A0BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB02D63D10BD513AULL,
		0x97A197265110E66CULL,
		0xB184F17D577714B7ULL,
		0x4B49A9EB59ADF4BCULL,
		0xFD94B114B5A4B0ACULL,
		0x94ED3D8A06D7771BULL,
		0xB188D40AF2BD9CE5ULL,
		0x5B965040D854179EULL
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
		0x987C7EC0BC2B9B90ULL,
		0xB93A01D19EDAF05BULL,
		0x9D2F0A6638B7E795ULL,
		0xA26B791667480EAFULL,
		0xAA16EF999C5ED2C8ULL,
		0x698E7C0EEAF3DCC3ULL,
		0x84BAC72904162965ULL,
		0x2E94AFE2ABAF4215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F8FD8178573720ULL,
		0x727403A33DB5E0B7ULL,
		0x3A5E14CC716FCF2BULL,
		0x44D6F22CCE901D5FULL,
		0x542DDF3338BDA591ULL,
		0xD31CF81DD5E7B987ULL,
		0x09758E52082C52CAULL,
		0x5D295FC5575E842BULL
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
		0xF2831D145CC04D2DULL,
		0x019490C1D91E83EBULL,
		0xE9DB9A1A9C8C91F0ULL,
		0xC080B478A4541E79ULL,
		0x1BEA4805A4E348FAULL,
		0x5A5E52143CDA262EULL,
		0x0B16D0B017DCAF3BULL,
		0x04EDB8DF6DC0CEF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5063A28B9809A5AULL,
		0x03292183B23D07D7ULL,
		0xD3B73435391923E0ULL,
		0x810168F148A83CF3ULL,
		0x37D4900B49C691F5ULL,
		0xB4BCA42879B44C5CULL,
		0x162DA1602FB95E76ULL,
		0x09DB71BEDB819DE2ULL
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
		0x0C30CBA085B9F3FEULL,
		0xA0B55FC6F7462AFEULL,
		0x3DC3113AA0260804ULL,
		0xA9945A073EA34F6AULL,
		0xBCBC5748394036E3ULL,
		0x36F4CC5AEB52C4FAULL,
		0xC0C55BAD95C19BDBULL,
		0x14A3A677923A10AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x186197410B73E7FCULL,
		0x416ABF8DEE8C55FCULL,
		0x7B862275404C1009ULL,
		0x5328B40E7D469ED4ULL,
		0x7978AE9072806DC7ULL,
		0x6DE998B5D6A589F5ULL,
		0x818AB75B2B8337B6ULL,
		0x29474CEF2474215FULL
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
		0x0B129482A30A56ACULL,
		0x11F4F9DFC4C6405CULL,
		0xECF46E047342987CULL,
		0x15BF27A794D5E461ULL,
		0x0AA137EE5A8A4DEBULL,
		0x3950E0F6E605145DULL,
		0x971583389AAB333AULL,
		0x2F5D10814E72292DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x162529054614AD58ULL,
		0x23E9F3BF898C80B8ULL,
		0xD9E8DC08E68530F8ULL,
		0x2B7E4F4F29ABC8C3ULL,
		0x15426FDCB5149BD6ULL,
		0x72A1C1EDCC0A28BAULL,
		0x2E2B067135566674ULL,
		0x5EBA21029CE4525BULL
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
		0xB543F70334401805ULL,
		0x1978504BDE48D437ULL,
		0x2793CBACB154C79DULL,
		0x661A8226B24915DFULL,
		0x85121B39AD39E134ULL,
		0x94DB5B6344018BB4ULL,
		0xB5818131A4B3800CULL,
		0x06B62BA792CFB37CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A87EE066880300AULL,
		0x32F0A097BC91A86FULL,
		0x4F27975962A98F3AULL,
		0xCC35044D64922BBEULL,
		0x0A2436735A73C268ULL,
		0x29B6B6C688031769ULL,
		0x6B03026349670019ULL,
		0x0D6C574F259F66F9ULL
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
		0x54F79C7C6241A0A2ULL,
		0x19E9556C3512B869ULL,
		0x286ED7324C301C1CULL,
		0x6040FC0A89A7556FULL,
		0x7CDA2697C23DC352ULL,
		0xA627D34D56BF3AB9ULL,
		0xEDDDFC12397DE16EULL,
		0x15A5E2975626CBB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EF38F8C4834144ULL,
		0x33D2AAD86A2570D2ULL,
		0x50DDAE6498603838ULL,
		0xC081F815134EAADEULL,
		0xF9B44D2F847B86A4ULL,
		0x4C4FA69AAD7E7572ULL,
		0xDBBBF82472FBC2DDULL,
		0x2B4BC52EAC4D976FULL
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
		0xDE114939162831CAULL,
		0x75D69EDA6BF0C748ULL,
		0x12D0C7A3AF186CA5ULL,
		0x0A02CF3A53448ABDULL,
		0xC134D09BE6F9EBF1ULL,
		0x1092AC81C694A98CULL,
		0x37F4DB79C400E42AULL,
		0x14C6B281767265EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC2292722C506394ULL,
		0xEBAD3DB4D7E18E91ULL,
		0x25A18F475E30D94AULL,
		0x14059E74A689157AULL,
		0x8269A137CDF3D7E2ULL,
		0x212559038D295319ULL,
		0x6FE9B6F38801C854ULL,
		0x298D6502ECE4CBDAULL
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
		0xAD19F97D682462EBULL,
		0xBDA9FEB739A6204CULL,
		0xC5C7C585D4D82D60ULL,
		0xF3F37AB4C2ED76E7ULL,
		0xAE6FADE81D7ED702ULL,
		0xE80F5705B46C0A8BULL,
		0xEB25D0160173C6EFULL,
		0x238254185B672BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A33F2FAD048C5D6ULL,
		0x7B53FD6E734C4099ULL,
		0x8B8F8B0BA9B05AC1ULL,
		0xE7E6F56985DAEDCFULL,
		0x5CDF5BD03AFDAE05ULL,
		0xD01EAE0B68D81517ULL,
		0xD64BA02C02E78DDFULL,
		0x4704A830B6CE57DBULL
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
		0x6408C487C4553BA9ULL,
		0xAF7E947726B3B6A5ULL,
		0x2C48494756F47688ULL,
		0x6D230042EE3FC533ULL,
		0x773EFC15A1C78F0EULL,
		0x827588873AC05422ULL,
		0x326CA62F841E3640ULL,
		0x28B5CB35D7191C36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC811890F88AA7752ULL,
		0x5EFD28EE4D676D4AULL,
		0x5890928EADE8ED11ULL,
		0xDA460085DC7F8A66ULL,
		0xEE7DF82B438F1E1CULL,
		0x04EB110E7580A844ULL,
		0x64D94C5F083C6C81ULL,
		0x516B966BAE32386CULL
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
		0x1DF8E8B4E90980BAULL,
		0x35FD2FFAF8EC5793ULL,
		0x759F98B1C8C6918CULL,
		0xEC40C3BBA2BCD4D2ULL,
		0x468AC37D9C342602ULL,
		0xC3A9C1650F2A597CULL,
		0x657D21ADC57D15F9ULL,
		0x095636D03B76BA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BF1D169D2130174ULL,
		0x6BFA5FF5F1D8AF26ULL,
		0xEB3F3163918D2318ULL,
		0xD88187774579A9A4ULL,
		0x8D1586FB38684C05ULL,
		0x875382CA1E54B2F8ULL,
		0xCAFA435B8AFA2BF3ULL,
		0x12AC6DA076ED744AULL
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
		0x4978215AFD85CC92ULL,
		0x1D41DBEF295273F7ULL,
		0x83CC95C146AE9D2DULL,
		0x6E17BA42DF2B49DBULL,
		0x8FF8B611D8BF59BBULL,
		0x214D7408921AD78FULL,
		0x26C866B050CD84F4ULL,
		0x1DED0B8B40E92474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F042B5FB0B9924ULL,
		0x3A83B7DE52A4E7EEULL,
		0x07992B828D5D3A5AULL,
		0xDC2F7485BE5693B7ULL,
		0x1FF16C23B17EB376ULL,
		0x429AE8112435AF1FULL,
		0x4D90CD60A19B09E8ULL,
		0x3BDA171681D248E8ULL
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
		0xC709AA79BD2B334CULL,
		0x98FC16303E961E8FULL,
		0x3290D5F2487F0B43ULL,
		0xE0B73BC63A8A3DBEULL,
		0x0FBAE3D133DE19C8ULL,
		0x0D8EA559E21E221CULL,
		0x00262C1E7BB91A89ULL,
		0x07DC368FEFC284CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E1354F37A566698ULL,
		0x31F82C607D2C3D1FULL,
		0x6521ABE490FE1687ULL,
		0xC16E778C75147B7CULL,
		0x1F75C7A267BC3391ULL,
		0x1B1D4AB3C43C4438ULL,
		0x004C583CF7723512ULL,
		0x0FB86D1FDF85099AULL
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
		0xD457268E127F50B2ULL,
		0xF3E28E3E226E0FBAULL,
		0xDD71047DD6EAEDC4ULL,
		0x63A96E416C16841FULL,
		0x87748FC02B24870EULL,
		0x3370A87EB303015BULL,
		0x0E84E4C2C8105280ULL,
		0x15DC4B9D255798D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8AE4D1C24FEA164ULL,
		0xE7C51C7C44DC1F75ULL,
		0xBAE208FBADD5DB89ULL,
		0xC752DC82D82D083FULL,
		0x0EE91F8056490E1CULL,
		0x66E150FD660602B7ULL,
		0x1D09C9859020A500ULL,
		0x2BB8973A4AAF31B0ULL
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
		0x265DCA53CB05181EULL,
		0x3A4A7C999A9FBE68ULL,
		0x857C31CD22884416ULL,
		0x840E0B085D9DBF48ULL,
		0xA9561C02F20932EBULL,
		0x5FBB62DDD9615086ULL,
		0x19C3B19738526EA1ULL,
		0x0E71C5A3F6C5CE4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CBB94A7960A303CULL,
		0x7494F933353F7CD0ULL,
		0x0AF8639A4510882CULL,
		0x081C1610BB3B7E91ULL,
		0x52AC3805E41265D7ULL,
		0xBF76C5BBB2C2A10DULL,
		0x3387632E70A4DD42ULL,
		0x1CE38B47ED8B9C94ULL
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
		0x9F8F8C3AB5C6E9FCULL,
		0xA0CF6370AE372623ULL,
		0x1A9B63664B1B7FB8ULL,
		0xEEA691F26E336453ULL,
		0x6170A9D33ED34E05ULL,
		0xE6FA5CA8BC180603ULL,
		0x92ADAB7DBCABBA3CULL,
		0x086F7850CB5F535CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1F18756B8DD3F8ULL,
		0x419EC6E15C6E4C47ULL,
		0x3536C6CC9636FF71ULL,
		0xDD4D23E4DC66C8A6ULL,
		0xC2E153A67DA69C0BULL,
		0xCDF4B95178300C06ULL,
		0x255B56FB79577479ULL,
		0x10DEF0A196BEA6B9ULL
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
		0x4311A357E5407270ULL,
		0x26442CAFCB7E45EAULL,
		0xBB19A019DE959A42ULL,
		0x6F844416D7DCB555ULL,
		0x953177945D7F7DBFULL,
		0x1CCC41304FED9C89ULL,
		0x10D89CA4CA0DBE51ULL,
		0x1C46AB0CDF4035CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x862346AFCA80E4E0ULL,
		0x4C88595F96FC8BD4ULL,
		0x76334033BD2B3484ULL,
		0xDF08882DAFB96AABULL,
		0x2A62EF28BAFEFB7EULL,
		0x399882609FDB3913ULL,
		0x21B13949941B7CA2ULL,
		0x388D5619BE806B9EULL
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
		0xA807235675A8B4F5ULL,
		0x676E9BB0721030F0ULL,
		0x7261CF846EEF6379ULL,
		0x2F9B4772688920D5ULL,
		0x322B21BA7AC191B8ULL,
		0x5C54FCE3DD9645E6ULL,
		0x891B5CA5463414D4ULL,
		0x0C36C187F9422BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x500E46ACEB5169EAULL,
		0xCEDD3760E42061E1ULL,
		0xE4C39F08DDDEC6F2ULL,
		0x5F368EE4D11241AAULL,
		0x64564374F5832370ULL,
		0xB8A9F9C7BB2C8BCCULL,
		0x1236B94A8C6829A8ULL,
		0x186D830FF28457C1ULL
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
		0xC6589BDA3E2D77FDULL,
		0x512E1F7B10DA62D1ULL,
		0x4D87F9C23B621BE2ULL,
		0x607B18F31B65A231ULL,
		0x47B7EE53E2D8FC8DULL,
		0x0FF49425F938AA24ULL,
		0xC27D904DDC1F9196ULL,
		0x3122A9CCE6CB9786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB137B47C5AEFFAULL,
		0xA25C3EF621B4C5A3ULL,
		0x9B0FF38476C437C4ULL,
		0xC0F631E636CB4462ULL,
		0x8F6FDCA7C5B1F91AULL,
		0x1FE9284BF2715448ULL,
		0x84FB209BB83F232CULL,
		0x62455399CD972F0DULL
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
		0x7B3E41FCF7C34CF1ULL,
		0x262C0137D1030A84ULL,
		0x2B795CCE3382121BULL,
		0x3DF457B1D3A6FD9BULL,
		0xEC5D43E119C32DE3ULL,
		0x0043851DB6B90392ULL,
		0xB12A99E00AACCC0DULL,
		0x021F73B471181E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF67C83F9EF8699E2ULL,
		0x4C58026FA2061508ULL,
		0x56F2B99C67042436ULL,
		0x7BE8AF63A74DFB36ULL,
		0xD8BA87C233865BC6ULL,
		0x00870A3B6D720725ULL,
		0x625533C01559981AULL,
		0x043EE768E2303CEFULL
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
		0xBB57DC4B476FCFF5ULL,
		0x642D36C9408819B3ULL,
		0x3B8332E2CAFB816EULL,
		0xE2792541292EC27AULL,
		0x57D37FA58BE5468FULL,
		0x8F5880618CFE7550ULL,
		0x9E1CF76BB0FB8B57ULL,
		0x0D0440EE241F76D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76AFB8968EDF9FEAULL,
		0xC85A6D9281103367ULL,
		0x770665C595F702DCULL,
		0xC4F24A82525D84F4ULL,
		0xAFA6FF4B17CA8D1FULL,
		0x1EB100C319FCEAA0ULL,
		0x3C39EED761F716AFULL,
		0x1A0881DC483EEDA5ULL
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
		0x7712EBDDAE55FF28ULL,
		0x78CAD3669486FB31ULL,
		0x44BF3C3C23B71C75ULL,
		0x1D5942B4A1B83B0CULL,
		0x155C920AD6065650ULL,
		0x99EB7FFE0F08DD05ULL,
		0x6FB0C73ADC42EE25ULL,
		0x1264065FED785C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE25D7BB5CABFE50ULL,
		0xF195A6CD290DF662ULL,
		0x897E7878476E38EAULL,
		0x3AB2856943707618ULL,
		0x2AB92415AC0CACA0ULL,
		0x33D6FFFC1E11BA0AULL,
		0xDF618E75B885DC4BULL,
		0x24C80CBFDAF0B8DCULL
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
		0x8994771C2A685A8CULL,
		0x5B5B8F40874716BAULL,
		0x8F5663475DF64E1DULL,
		0x72C4D88B7587CB83ULL,
		0x0298D9C8D6E43286ULL,
		0x1ABF5CA023BF95DFULL,
		0xE2137C19D9F1FCAAULL,
		0x2D4E822CE1FA7EC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1328EE3854D0B518ULL,
		0xB6B71E810E8E2D75ULL,
		0x1EACC68EBBEC9C3AULL,
		0xE589B116EB0F9707ULL,
		0x0531B391ADC8650CULL,
		0x357EB940477F2BBEULL,
		0xC426F833B3E3F954ULL,
		0x5A9D0459C3F4FD85ULL
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
		0xA70AB12FB90AEA11ULL,
		0x09DE1C46439B7623ULL,
		0x2AD0C764F12EC12FULL,
		0xB2AF4C03A262BB17ULL,
		0xE59B7CC17EEB857BULL,
		0xF776807466E614EBULL,
		0xEE79B3CAC31C87EDULL,
		0x1F6D4595C5F24DA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E15625F7215D422ULL,
		0x13BC388C8736EC47ULL,
		0x55A18EC9E25D825EULL,
		0x655E980744C5762EULL,
		0xCB36F982FDD70AF7ULL,
		0xEEED00E8CDCC29D7ULL,
		0xDCF3679586390FDBULL,
		0x3EDA8B2B8BE49B49ULL
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
		0x15069DDDADC452AAULL,
		0x535FD56DD3E73880ULL,
		0x5479ACF0B2E26035ULL,
		0x45ED879B9BA3A7FFULL,
		0x8C4C566A4C7C0E48ULL,
		0x7ACD8E59C0FB99DEULL,
		0x9FF1963DA754546EULL,
		0x0FA0232FDA53A110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A0D3BBB5B88A554ULL,
		0xA6BFAADBA7CE7100ULL,
		0xA8F359E165C4C06AULL,
		0x8BDB0F3737474FFEULL,
		0x1898ACD498F81C90ULL,
		0xF59B1CB381F733BDULL,
		0x3FE32C7B4EA8A8DCULL,
		0x1F40465FB4A74221ULL
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
		0xB3692EE7C2222999ULL,
		0xE048E4A460173789ULL,
		0x1AF5C6295B13BE01ULL,
		0xFBB75F54E99B3209ULL,
		0x30E49A08FB8C46C9ULL,
		0x3AED27BF96D2607DULL,
		0x78803F5713392EB9ULL,
		0x2FCCB2E5C6D683A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66D25DCF84445332ULL,
		0xC091C948C02E6F13ULL,
		0x35EB8C52B6277C03ULL,
		0xF76EBEA9D3366412ULL,
		0x61C93411F7188D93ULL,
		0x75DA4F7F2DA4C0FAULL,
		0xF1007EAE26725D72ULL,
		0x5F9965CB8DAD074AULL
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
		0xE010972797C0F319ULL,
		0x123367F788BDE0BFULL,
		0x819BE0B9C729DD3AULL,
		0x4B241FD216F994ADULL,
		0x2770DCC985C2C66BULL,
		0x07F78E7B8A99B6BFULL,
		0xE9D7E3C6E1ED720DULL,
		0x2FE259683E17729AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0212E4F2F81E632ULL,
		0x2466CFEF117BC17FULL,
		0x0337C1738E53BA74ULL,
		0x96483FA42DF3295BULL,
		0x4EE1B9930B858CD6ULL,
		0x0FEF1CF715336D7EULL,
		0xD3AFC78DC3DAE41AULL,
		0x5FC4B2D07C2EE535ULL
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
		0x5510618CE111044BULL,
		0xAEDD017FFE9FBA62ULL,
		0x1258422757B19AECULL,
		0xDC9A57DB225A9A66ULL,
		0x44207AD477B37F36ULL,
		0x120C84F9DA67BB20ULL,
		0x7F0287584F64446CULL,
		0x369B904A6CB9A0ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA20C319C2220896ULL,
		0x5DBA02FFFD3F74C4ULL,
		0x24B0844EAF6335D9ULL,
		0xB934AFB644B534CCULL,
		0x8840F5A8EF66FE6DULL,
		0x241909F3B4CF7640ULL,
		0xFE050EB09EC888D8ULL,
		0x6D372094D9734156ULL
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
		0xB444DC45B96BB238ULL,
		0xC9857E7E9B4D0615ULL,
		0xADDBDCB887682EECULL,
		0x737B3A745244D4D5ULL,
		0x96C5459583F23D42ULL,
		0xD34483657479085EULL,
		0x0045077DF226A204ULL,
		0x06792776EE991539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6889B88B72D76470ULL,
		0x930AFCFD369A0C2BULL,
		0x5BB7B9710ED05DD9ULL,
		0xE6F674E8A489A9ABULL,
		0x2D8A8B2B07E47A84ULL,
		0xA68906CAE8F210BDULL,
		0x008A0EFBE44D4409ULL,
		0x0CF24EEDDD322A72ULL
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
		0x84AFDB04F5CC20A6ULL,
		0x318EFAB7253016A1ULL,
		0x011F8A53FF4AB3FAULL,
		0x16551AD2B6AF1AC5ULL,
		0x8976F69F6C66F219ULL,
		0x17FAB0550F08FBF8ULL,
		0xAC2B92B4F0874DCAULL,
		0x26C77F58486BA0AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095FB609EB98414CULL,
		0x631DF56E4A602D43ULL,
		0x023F14A7FE9567F4ULL,
		0x2CAA35A56D5E358AULL,
		0x12EDED3ED8CDE432ULL,
		0x2FF560AA1E11F7F1ULL,
		0x58572569E10E9B94ULL,
		0x4D8EFEB090D7415DULL
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
		0x4A4FB761A6EFF3FAULL,
		0x9A15857143A48B42ULL,
		0xA140D113116533FDULL,
		0x5F876B32CDEE4563ULL,
		0x7960D3C239C011CDULL,
		0x025FC5281A59CE30ULL,
		0xE721B14066A5920EULL,
		0x115F4D9945B7CA0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x949F6EC34DDFE7F4ULL,
		0x342B0AE287491684ULL,
		0x4281A22622CA67FBULL,
		0xBF0ED6659BDC8AC7ULL,
		0xF2C1A7847380239AULL,
		0x04BF8A5034B39C60ULL,
		0xCE436280CD4B241CULL,
		0x22BE9B328B6F941DULL
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
		0x9D42C79F26E43762ULL,
		0x190961FEFAC358D8ULL,
		0x53B1B4777014A977ULL,
		0xDED7960126B697C8ULL,
		0x7F8EF19FEE2ECFD9ULL,
		0xBC877830B6FC6303ULL,
		0xBA478E1F08F80F8BULL,
		0x3AB3C1557DAE82A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A858F3E4DC86EC4ULL,
		0x3212C3FDF586B1B1ULL,
		0xA76368EEE02952EEULL,
		0xBDAF2C024D6D2F90ULL,
		0xFF1DE33FDC5D9FB3ULL,
		0x790EF0616DF8C606ULL,
		0x748F1C3E11F01F17ULL,
		0x756782AAFB5D054BULL
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
		0x856EBAB45AE5C424ULL,
		0x2BEC75E11367088BULL,
		0x72F0236E21E9CCDFULL,
		0xF97EF470A3C141B9ULL,
		0xF44EED431F88036AULL,
		0x6762C6C9BE90A748ULL,
		0x02C1ED5C7EAFD363ULL,
		0x14060ED60F64D453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ADD7568B5CB8848ULL,
		0x57D8EBC226CE1117ULL,
		0xE5E046DC43D399BEULL,
		0xF2FDE8E147828372ULL,
		0xE89DDA863F1006D5ULL,
		0xCEC58D937D214E91ULL,
		0x0583DAB8FD5FA6C6ULL,
		0x280C1DAC1EC9A8A6ULL
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
		0xCF9C5A481924C76DULL,
		0xD34BFB27D17088EBULL,
		0x44E4668FCEED01C9ULL,
		0x8F7E41B95A30ECA8ULL,
		0x8868FDB24EC2FEAEULL,
		0xAAF9A8FAC6F36E35ULL,
		0x787D97AFF823751CULL,
		0x03826599F5298EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F38B49032498EDAULL,
		0xA697F64FA2E111D7ULL,
		0x89C8CD1F9DDA0393ULL,
		0x1EFC8372B461D950ULL,
		0x10D1FB649D85FD5DULL,
		0x55F351F58DE6DC6BULL,
		0xF0FB2F5FF046EA39ULL,
		0x0704CB33EA531DECULL
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
		0x1BD96DD682149DBEULL,
		0x032BC85E76A157D0ULL,
		0x487D6DF3470E7B1CULL,
		0x36DCD70B70CD57FEULL,
		0x58FE5CFDDA018E88ULL,
		0x02DB7C90B53AFCA0ULL,
		0xE23BD891825BD128ULL,
		0x0D0D9EEF80786D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B2DBAD04293B7CULL,
		0x065790BCED42AFA0ULL,
		0x90FADBE68E1CF638ULL,
		0x6DB9AE16E19AAFFCULL,
		0xB1FCB9FBB4031D10ULL,
		0x05B6F9216A75F940ULL,
		0xC477B12304B7A250ULL,
		0x1A1B3DDF00F0DAF9ULL
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
		0xDD99DE3B755CF5C9ULL,
		0xC6A10C80EDC748ABULL,
		0xEC1108C435D5686EULL,
		0x9E96F8EFB3A67089ULL,
		0xA371B166338EAAF3ULL,
		0x93641502FB593B2FULL,
		0xF3C45C11843B6087ULL,
		0x286B9090094D5B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB33BC76EAB9EB92ULL,
		0x8D421901DB8E9157ULL,
		0xD82211886BAAD0DDULL,
		0x3D2DF1DF674CE113ULL,
		0x46E362CC671D55E7ULL,
		0x26C82A05F6B2765FULL,
		0xE788B8230876C10FULL,
		0x50D72120129AB737ULL
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
		0xC96E64DB955268D4ULL,
		0x9A2246F08B627DE7ULL,
		0x202B099376957060ULL,
		0x2451632DE224EF43ULL,
		0xD46973DAD7F0DF73ULL,
		0x724EE1C24D5745ECULL,
		0xF1F4FD87BD56C133ULL,
		0x0DE9EBB8D3400236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92DCC9B72AA4D1A8ULL,
		0x34448DE116C4FBCFULL,
		0x40561326ED2AE0C1ULL,
		0x48A2C65BC449DE86ULL,
		0xA8D2E7B5AFE1BEE6ULL,
		0xE49DC3849AAE8BD9ULL,
		0xE3E9FB0F7AAD8266ULL,
		0x1BD3D771A680046DULL
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
		0x31E29EF248027D1FULL,
		0x09F51DA6A1E11742ULL,
		0x06971D37ECA0F63BULL,
		0xBFA4A5D9D80BF408ULL,
		0x8B7EA993551D1123ULL,
		0xC1216DEF00FD2241ULL,
		0x2919901D81B2EC27ULL,
		0x07B0044680781FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C53DE49004FA3EULL,
		0x13EA3B4D43C22E84ULL,
		0x0D2E3A6FD941EC76ULL,
		0x7F494BB3B017E810ULL,
		0x16FD5326AA3A2247ULL,
		0x8242DBDE01FA4483ULL,
		0x5233203B0365D84FULL,
		0x0F60088D00F03FC6ULL
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
		0xF0740190CC5C3FB0ULL,
		0x2EB261CDBBD5FA97ULL,
		0xF4D30DB04EB41002ULL,
		0x88BEDAB94E745262ULL,
		0x4C997DEDDA33669BULL,
		0x6E29BDD93AF175C9ULL,
		0xDC03F376D12C9CD3ULL,
		0x368DBEEE122E0DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0E8032198B87F60ULL,
		0x5D64C39B77ABF52FULL,
		0xE9A61B609D682004ULL,
		0x117DB5729CE8A4C5ULL,
		0x9932FBDBB466CD37ULL,
		0xDC537BB275E2EB92ULL,
		0xB807E6EDA25939A6ULL,
		0x6D1B7DDC245C1BE9ULL
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
		0xCB9F09A03E6C1BE5ULL,
		0x4972D65780947302ULL,
		0x9E94185CB974EFEEULL,
		0x170F67BED39DE39FULL,
		0xA5465C1C70937665ULL,
		0xC48A085A092A21DFULL,
		0xFC6E63F05299B18DULL,
		0x2B1BCABA0A091DE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x973E13407CD837CAULL,
		0x92E5ACAF0128E605ULL,
		0x3D2830B972E9DFDCULL,
		0x2E1ECF7DA73BC73FULL,
		0x4A8CB838E126ECCAULL,
		0x891410B4125443BFULL,
		0xF8DCC7E0A533631BULL,
		0x5637957414123BC7ULL
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
		0x08BD57C0ABC13228ULL,
		0x221D46B2E1DF5B68ULL,
		0x460CA5ED07145130ULL,
		0x814436C7B6AF8716ULL,
		0x266D5677E625DED8ULL,
		0xFBDC009551F5C659ULL,
		0x5CA90ACC055B53C9ULL,
		0x3D456A8DEB2B9803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117AAF8157826450ULL,
		0x443A8D65C3BEB6D0ULL,
		0x8C194BDA0E28A260ULL,
		0x02886D8F6D5F0E2CULL,
		0x4CDAACEFCC4BBDB1ULL,
		0xF7B8012AA3EB8CB2ULL,
		0xB95215980AB6A793ULL,
		0x7A8AD51BD6573006ULL
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
		0x52968F25D2BCC58FULL,
		0x7C1B6CA0D4C5CB69ULL,
		0x662B0BB0CECB5B05ULL,
		0xF528722B45B96D8AULL,
		0x80B1E25045526D5AULL,
		0xC1D1E381DCD2A001ULL,
		0xA4085B726491F3CBULL,
		0x2D48D8BF0ECC4148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA52D1E4BA5798B1EULL,
		0xF836D941A98B96D2ULL,
		0xCC5617619D96B60AULL,
		0xEA50E4568B72DB14ULL,
		0x0163C4A08AA4DAB5ULL,
		0x83A3C703B9A54003ULL,
		0x4810B6E4C923E797ULL,
		0x5A91B17E1D988291ULL
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
		0x23CBD120FB11EB0AULL,
		0x1F767FB06E4C8F15ULL,
		0x326B69F4B46F43EAULL,
		0x90AE3B84C8175EABULL,
		0x6F1EAD1461C6EA4CULL,
		0x0150CA7FE9C7F0A1ULL,
		0x0D6BF103B31F4964ULL,
		0x03F9DBA2D5B4B927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4797A241F623D614ULL,
		0x3EECFF60DC991E2AULL,
		0x64D6D3E968DE87D4ULL,
		0x215C7709902EBD56ULL,
		0xDE3D5A28C38DD499ULL,
		0x02A194FFD38FE142ULL,
		0x1AD7E207663E92C8ULL,
		0x07F3B745AB69724EULL
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
		0xEC7B54774B254F06ULL,
		0x8BFC547C13C35C4BULL,
		0x7AF861B054D1A9C7ULL,
		0xEA8DEB6F53769624ULL,
		0x729AC826E60678B6ULL,
		0x6918C8C72F289E15ULL,
		0x6397F1C716F11F40ULL,
		0x37AE8A6354D93738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F6A8EE964A9E0CULL,
		0x17F8A8F82786B897ULL,
		0xF5F0C360A9A3538FULL,
		0xD51BD6DEA6ED2C48ULL,
		0xE535904DCC0CF16DULL,
		0xD231918E5E513C2AULL,
		0xC72FE38E2DE23E80ULL,
		0x6F5D14C6A9B26E70ULL
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
		0xE5C1661FC1FB8560ULL,
		0x31D8069AD5A4E085ULL,
		0xD0049705443E45D9ULL,
		0xA7183296DA82B084ULL,
		0x78F9887CA15EF16AULL,
		0x7AA448CD28F229CCULL,
		0xC568B692E09E17D5ULL,
		0x2338DE0129D66656ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB82CC3F83F70AC0ULL,
		0x63B00D35AB49C10BULL,
		0xA0092E0A887C8BB2ULL,
		0x4E30652DB5056109ULL,
		0xF1F310F942BDE2D5ULL,
		0xF548919A51E45398ULL,
		0x8AD16D25C13C2FAAULL,
		0x4671BC0253ACCCADULL
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
		0x08183FFA8F77CAFCULL,
		0x5965BE4311431A2BULL,
		0x41C18C1B10403742ULL,
		0x331715195CC2D348ULL,
		0xDFB9AEC9C67EC594ULL,
		0xA22992490B476F07ULL,
		0x348FF44964416D9EULL,
		0x11FB059BD6DD2453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10307FF51EEF95F8ULL,
		0xB2CB7C8622863456ULL,
		0x8383183620806E84ULL,
		0x662E2A32B985A690ULL,
		0xBF735D938CFD8B28ULL,
		0x44532492168EDE0FULL,
		0x691FE892C882DB3DULL,
		0x23F60B37ADBA48A6ULL
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
		0x01C64B2CA5E7EEA0ULL,
		0x8BB67E480872E0A5ULL,
		0xA3EE729FEA6BA53EULL,
		0x1FFC1BBDCA2B47CDULL,
		0x45B91C732BB8A59EULL,
		0x8CF005A15423577CULL,
		0x3CB052F13CB5953FULL,
		0x02B7F2A3872DA13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x038C96594BCFDD40ULL,
		0x176CFC9010E5C14AULL,
		0x47DCE53FD4D74A7DULL,
		0x3FF8377B94568F9BULL,
		0x8B7238E657714B3CULL,
		0x19E00B42A846AEF8ULL,
		0x7960A5E2796B2A7FULL,
		0x056FE5470E5B4276ULL
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
		0x9D2CCE93BFBED297ULL,
		0xA80FF28CA5D9BB87ULL,
		0x828CFF733EFAA16BULL,
		0x8AF74DA1D9BD9FF7ULL,
		0xE93AB7A2C82FBA44ULL,
		0xE438EEC0BF356FE1ULL,
		0xD1C7B862043AEB40ULL,
		0x296847DA4F8D7096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A599D277F7DA52EULL,
		0x501FE5194BB3770FULL,
		0x0519FEE67DF542D7ULL,
		0x15EE9B43B37B3FEFULL,
		0xD2756F45905F7489ULL,
		0xC871DD817E6ADFC3ULL,
		0xA38F70C40875D681ULL,
		0x52D08FB49F1AE12DULL
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
		0x4CCA1F4A91F55706ULL,
		0x8463C0F90CB37457ULL,
		0x08399A2885F85E34ULL,
		0xA310EC646DE7CBA1ULL,
		0x065496D8ADB985A6ULL,
		0x8F4834F0A8802011ULL,
		0x6D802276B140CB81ULL,
		0x29B24E5C8C20E55EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99943E9523EAAE0CULL,
		0x08C781F21966E8AEULL,
		0x107334510BF0BC69ULL,
		0x4621D8C8DBCF9742ULL,
		0x0CA92DB15B730B4DULL,
		0x1E9069E151004022ULL,
		0xDB0044ED62819703ULL,
		0x53649CB91841CABCULL
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
		0x7BBBDA11A01A1A35ULL,
		0x832501805F7E2425ULL,
		0x69B62AC9E014B37AULL,
		0x2101D955E8D37389ULL,
		0x75DC41CC40895F4DULL,
		0x5C490AD1D61B53CBULL,
		0x607E7B9A2B26E6C3ULL,
		0x266B70B607E57C68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF777B4234034346AULL,
		0x064A0300BEFC484AULL,
		0xD36C5593C02966F5ULL,
		0x4203B2ABD1A6E712ULL,
		0xEBB883988112BE9AULL,
		0xB89215A3AC36A796ULL,
		0xC0FCF734564DCD86ULL,
		0x4CD6E16C0FCAF8D0ULL
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
		0xE41614DC95EEC850ULL,
		0xE0DE1274FD51B6E2ULL,
		0x7B71DAAB0B73970CULL,
		0xF26583961CE0E663ULL,
		0x6C1600423601CA67ULL,
		0xC840D4754D2626D4ULL,
		0x86F529EAE85F0BD6ULL,
		0x2627E4A2FABC8A5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC82C29B92BDD90A0ULL,
		0xC1BC24E9FAA36DC5ULL,
		0xF6E3B55616E72E19ULL,
		0xE4CB072C39C1CCC6ULL,
		0xD82C00846C0394CFULL,
		0x9081A8EA9A4C4DA8ULL,
		0x0DEA53D5D0BE17ADULL,
		0x4C4FC945F57914BDULL
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
		0xECC34DC39CA9B284ULL,
		0x13B2B25DE788A32DULL,
		0x5729767EAF4A553AULL,
		0xC5929B288346E63FULL,
		0x44750FD320309C08ULL,
		0x1A076C5FF78FE84EULL,
		0xF33CF92645BAA9E9ULL,
		0x23831B27B38B47F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9869B8739536508ULL,
		0x276564BBCF11465BULL,
		0xAE52ECFD5E94AA74ULL,
		0x8B253651068DCC7EULL,
		0x88EA1FA640613811ULL,
		0x340ED8BFEF1FD09CULL,
		0xE679F24C8B7553D2ULL,
		0x4706364F67168FEBULL
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
		0x24DF5D1A5949944DULL,
		0x2BDE77EFA1E05633ULL,
		0x52AF1E8DE6DCF5EAULL,
		0x59FAD7BB5416CCF1ULL,
		0x538C525892C1B333ULL,
		0xCC8DA73F9B56A492ULL,
		0xF0441BAB862C9178ULL,
		0x0655BECA53749292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BEBA34B293289AULL,
		0x57BCEFDF43C0AC66ULL,
		0xA55E3D1BCDB9EBD4ULL,
		0xB3F5AF76A82D99E2ULL,
		0xA718A4B125836666ULL,
		0x991B4E7F36AD4924ULL,
		0xE08837570C5922F1ULL,
		0x0CAB7D94A6E92525ULL
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
		0x7C3D1E9EF42C699FULL,
		0xAC073425CEDBE744ULL,
		0x6729B73A8E5D3419ULL,
		0x8C625DDF80AFD1E5ULL,
		0xEC406A875BE207EAULL,
		0xCA98B0B47A897FCFULL,
		0x7A834D41B7F10FCBULL,
		0x099F06BE2D41561FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF87A3D3DE858D33EULL,
		0x580E684B9DB7CE88ULL,
		0xCE536E751CBA6833ULL,
		0x18C4BBBF015FA3CAULL,
		0xD880D50EB7C40FD5ULL,
		0x95316168F512FF9FULL,
		0xF5069A836FE21F97ULL,
		0x133E0D7C5A82AC3EULL
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
		0x2EE9FB8C78B81620ULL,
		0x0604272FA85D2BCCULL,
		0x48AE4E5219CF4435ULL,
		0xD6565CB112B82B76ULL,
		0x03B8DF91236A70FAULL,
		0x5E9D7FFD607BACCAULL,
		0xF035CB65D76CD85CULL,
		0x143A4ACDECE66D05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD3F718F1702C40ULL,
		0x0C084E5F50BA5798ULL,
		0x915C9CA4339E886AULL,
		0xACACB962257056ECULL,
		0x0771BF2246D4E1F5ULL,
		0xBD3AFFFAC0F75994ULL,
		0xE06B96CBAED9B0B8ULL,
		0x2874959BD9CCDA0BULL
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
		0xA319DCD5C56DB1B4ULL,
		0xB52A8610E4ED241CULL,
		0x3E73991529CA9614ULL,
		0x8E41131E1F31D318ULL,
		0x1821E1D5DB006CDFULL,
		0x7C0A91E5380E42A3ULL,
		0xE0278BF3751C62BBULL,
		0x17254E63073E6288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4633B9AB8ADB6368ULL,
		0x6A550C21C9DA4839ULL,
		0x7CE7322A53952C29ULL,
		0x1C82263C3E63A630ULL,
		0x3043C3ABB600D9BFULL,
		0xF81523CA701C8546ULL,
		0xC04F17E6EA38C576ULL,
		0x2E4A9CC60E7CC511ULL
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
		0x48548E9DDADCB5ACULL,
		0x261385E2DA6400D8ULL,
		0x31F0CD0881518041ULL,
		0xF92DD73E0D14F862ULL,
		0x6D244E663A676426ULL,
		0x965F740FF45CFF8AULL,
		0xB3D280FCD6F6F196ULL,
		0x10B240787378AE69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A91D3BB5B96B58ULL,
		0x4C270BC5B4C801B0ULL,
		0x63E19A1102A30082ULL,
		0xF25BAE7C1A29F0C4ULL,
		0xDA489CCC74CEC84DULL,
		0x2CBEE81FE8B9FF14ULL,
		0x67A501F9ADEDE32DULL,
		0x216480F0E6F15CD3ULL
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
		0xF7B74E5D3864B866ULL,
		0x5BCFD8683F61FE7AULL,
		0x5869A4D5FAF5790CULL,
		0x22D9FA980CFF39C3ULL,
		0xA482F96C76ECF0EAULL,
		0x9185B25EC563DF78ULL,
		0x47EA5E3F92F814D7ULL,
		0x00E430B609F99FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF6E9CBA70C970CCULL,
		0xB79FB0D07EC3FCF5ULL,
		0xB0D349ABF5EAF218ULL,
		0x45B3F53019FE7386ULL,
		0x4905F2D8EDD9E1D4ULL,
		0x230B64BD8AC7BEF1ULL,
		0x8FD4BC7F25F029AFULL,
		0x01C8616C13F33FEEULL
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
		0xEBEBB696EEC691CAULL,
		0xF84B4DF8DE9300DBULL,
		0x7E1627190CFE2611ULL,
		0xA331AD130E9EC164ULL,
		0xB54EE420C8DAC580ULL,
		0x64438EFE5280AC36ULL,
		0xACF5F0DCA52B5814ULL,
		0x2034BA54DB4E6219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D76D2DDD8D2394ULL,
		0xF0969BF1BD2601B7ULL,
		0xFC2C4E3219FC4C23ULL,
		0x46635A261D3D82C8ULL,
		0x6A9DC84191B58B01ULL,
		0xC8871DFCA501586DULL,
		0x59EBE1B94A56B028ULL,
		0x406974A9B69CC433ULL
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
		0xC623C86A44064A06ULL,
		0xC89676EC4C8FAF7CULL,
		0xD77A63FD248C7F17ULL,
		0x6A70533C863652B8ULL,
		0xD47CE390D731FD86ULL,
		0xABBB7511E461E996ULL,
		0x0560536D20211510ULL,
		0x06FA5008E85E2A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C4790D4880C940CULL,
		0x912CEDD8991F5EF9ULL,
		0xAEF4C7FA4918FE2FULL,
		0xD4E0A6790C6CA571ULL,
		0xA8F9C721AE63FB0CULL,
		0x5776EA23C8C3D32DULL,
		0x0AC0A6DA40422A21ULL,
		0x0DF4A011D0BC5416ULL
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
		0x72BFB30A283D7960ULL,
		0x9E179B59963611B2ULL,
		0x32E6BF310F4FBAC7ULL,
		0xE6DCC3BB3D728988ULL,
		0xFA6BE037D3755057ULL,
		0x9CA95CC9DC3D33C6ULL,
		0x361CE522BF2E793DULL,
		0x3452D5A0CE2674D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE57F6614507AF2C0ULL,
		0x3C2F36B32C6C2364ULL,
		0x65CD7E621E9F758FULL,
		0xCDB987767AE51310ULL,
		0xF4D7C06FA6EAA0AFULL,
		0x3952B993B87A678DULL,
		0x6C39CA457E5CF27BULL,
		0x68A5AB419C4CE9B0ULL
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
		0x745E7E923CE1D150ULL,
		0x3DD786BD7E3AABB5ULL,
		0x68458E588D6BCE4BULL,
		0xA5D5E9FF6B8E79B8ULL,
		0x9253DADD03243F67ULL,
		0xC50FBCAE1263E743ULL,
		0x1C65496BDF8E1D01ULL,
		0x3EB115D70D009B30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8BCFD2479C3A2A0ULL,
		0x7BAF0D7AFC75576AULL,
		0xD08B1CB11AD79C96ULL,
		0x4BABD3FED71CF370ULL,
		0x24A7B5BA06487ECFULL,
		0x8A1F795C24C7CE87ULL,
		0x38CA92D7BF1C3A03ULL,
		0x7D622BAE1A013660ULL
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
		0x28F1CB6BE65E35FBULL,
		0xA546A8D10B4FC2C1ULL,
		0x40D4BA009C33ECD5ULL,
		0xB30F8EA92B03A63CULL,
		0xA452ABE59E0554B4ULL,
		0xE25F854A7521CF7CULL,
		0x2440DC04284F4C74ULL,
		0x25B72A9290CCDB4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51E396D7CCBC6BF6ULL,
		0x4A8D51A2169F8582ULL,
		0x81A974013867D9ABULL,
		0x661F1D5256074C78ULL,
		0x48A557CB3C0AA969ULL,
		0xC4BF0A94EA439EF9ULL,
		0x4881B808509E98E9ULL,
		0x4B6E55252199B698ULL
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
		0xC2DA99D5729C4CFFULL,
		0xE9D82F43FDAAA3F5ULL,
		0x4AC551490D43B791ULL,
		0x42EA35E72EC3D989ULL,
		0x93A314EC8B9C54BFULL,
		0x285537679237056DULL,
		0xD9A3FAE762B319FEULL,
		0x0AE8638ADAA3DAECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B533AAE53899FEULL,
		0xD3B05E87FB5547EBULL,
		0x958AA2921A876F23ULL,
		0x85D46BCE5D87B312ULL,
		0x274629D91738A97EULL,
		0x50AA6ECF246E0ADBULL,
		0xB347F5CEC56633FCULL,
		0x15D0C715B547B5D9ULL
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
		0x8A5DA9C02AD7C56EULL,
		0x977BD89E425962B4ULL,
		0x81471410BA69C609ULL,
		0x577861D2F5B1EBB3ULL,
		0x14A6439FF03F9F20ULL,
		0x78C2712C95184FCBULL,
		0xC9768F810E94A0D0ULL,
		0x100E21ECFAE24BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BB538055AF8ADCULL,
		0x2EF7B13C84B2C569ULL,
		0x028E282174D38C13ULL,
		0xAEF0C3A5EB63D767ULL,
		0x294C873FE07F3E40ULL,
		0xF184E2592A309F96ULL,
		0x92ED1F021D2941A0ULL,
		0x201C43D9F5C497F1ULL
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
		0x4579B5AE5D8F2065ULL,
		0xB83371DA5ADDBA2FULL,
		0x5E802126E5DBBA2AULL,
		0xC24F59365576C1A1ULL,
		0x3BA9F301E4B45553ULL,
		0x9E910B1B5C25CE4FULL,
		0x95432BB2C2408E47ULL,
		0x0FDA42269A89D99DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AF36B5CBB1E40CAULL,
		0x7066E3B4B5BB745EULL,
		0xBD00424DCBB77455ULL,
		0x849EB26CAAED8342ULL,
		0x7753E603C968AAA7ULL,
		0x3D221636B84B9C9EULL,
		0x2A86576584811C8FULL,
		0x1FB4844D3513B33BULL
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
		0xB34DD466A00332C4ULL,
		0xAD24FB9FA0C71701ULL,
		0xF851352785508F28ULL,
		0x247695E4062651AFULL,
		0x98AB7542D2907E6CULL,
		0xF8D91A669A90BBDCULL,
		0xAE9EE02B389320D3ULL,
		0x205CD187E2D10EF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669BA8CD40066588ULL,
		0x5A49F73F418E2E03ULL,
		0xF0A26A4F0AA11E51ULL,
		0x48ED2BC80C4CA35FULL,
		0x3156EA85A520FCD8ULL,
		0xF1B234CD352177B9ULL,
		0x5D3DC056712641A7ULL,
		0x40B9A30FC5A21DF1ULL
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
		0x1DAB20C6B5CCF22AULL,
		0x40DF0EB86ED36505ULL,
		0x1457758C9B19AD30ULL,
		0x57C4B4691C4AA3E3ULL,
		0xFC04C126D9CDF4D8ULL,
		0x8FE5A9A44ED55BA8ULL,
		0x2F352D6668FC4457ULL,
		0x28CE1454E228BF89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B56418D6B99E454ULL,
		0x81BE1D70DDA6CA0AULL,
		0x28AEEB1936335A60ULL,
		0xAF8968D2389547C6ULL,
		0xF809824DB39BE9B0ULL,
		0x1FCB53489DAAB751ULL,
		0x5E6A5ACCD1F888AFULL,
		0x519C28A9C4517F12ULL
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
		0xBD6DF1EB673F9EF9ULL,
		0xD7B773F707A989ADULL,
		0x95C3E69CD056D160ULL,
		0xC746471749EA1FFEULL,
		0x37D587F917D5036DULL,
		0xFBD9A6E3C8FC9C47ULL,
		0x08D342BA2D7A657EULL,
		0x0D89BA093158E05FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ADBE3D6CE7F3DF2ULL,
		0xAF6EE7EE0F53135BULL,
		0x2B87CD39A0ADA2C1ULL,
		0x8E8C8E2E93D43FFDULL,
		0x6FAB0FF22FAA06DBULL,
		0xF7B34DC791F9388EULL,
		0x11A685745AF4CAFDULL,
		0x1B13741262B1C0BEULL
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
		0x86E1A7D832CE55A2ULL,
		0xA0E65A04D6697326ULL,
		0x3611FAE66E4436AAULL,
		0x530DCA3BA088FC98ULL,
		0xFDC1F33E0E124209ULL,
		0x20860B6403244A11ULL,
		0xA23FF15EBBA32D71ULL,
		0x09C01F64A4A05813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC34FB0659CAB44ULL,
		0x41CCB409ACD2E64DULL,
		0x6C23F5CCDC886D55ULL,
		0xA61B94774111F930ULL,
		0xFB83E67C1C248412ULL,
		0x410C16C806489423ULL,
		0x447FE2BD77465AE2ULL,
		0x13803EC94940B027ULL
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
		0x03501DEE45C01664ULL,
		0x45BA944CC1AB1554ULL,
		0xC1847052BAC066B5ULL,
		0x25BAC7D2A0ED1987ULL,
		0x7BD23AC4E71F47C4ULL,
		0x1D3426682C75F8E9ULL,
		0x7750E02EFCD69BDDULL,
		0x0541BE0B85D3B6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06A03BDC8B802CC8ULL,
		0x8B75289983562AA8ULL,
		0x8308E0A57580CD6AULL,
		0x4B758FA541DA330FULL,
		0xF7A47589CE3E8F88ULL,
		0x3A684CD058EBF1D2ULL,
		0xEEA1C05DF9AD37BAULL,
		0x0A837C170BA76DBEULL
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
		0xE00D181DDEA68F96ULL,
		0x861EA9A338696446ULL,
		0x701CFC085126D9D9ULL,
		0x5896A699DC046004ULL,
		0x0DA444E353650F77ULL,
		0xC6310AB94A513E3BULL,
		0xF091D941AD7EA1ACULL,
		0x0A56C4EB99D6D225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC01A303BBD4D1F2CULL,
		0x0C3D534670D2C88DULL,
		0xE039F810A24DB3B3ULL,
		0xB12D4D33B808C008ULL,
		0x1B4889C6A6CA1EEEULL,
		0x8C62157294A27C76ULL,
		0xE123B2835AFD4359ULL,
		0x14AD89D733ADA44BULL
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
		0x6E0ED591B7C0CA6BULL,
		0xE663C31311AA7CECULL,
		0x1027922DB2FCF688ULL,
		0x4568077B80B2AE3CULL,
		0xDF551A9232B7E6ACULL,
		0x7DC3DD0512FB840AULL,
		0x2B9ED3E651F1A09EULL,
		0x23D5D8352789F836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC1DAB236F8194D6ULL,
		0xCCC786262354F9D8ULL,
		0x204F245B65F9ED11ULL,
		0x8AD00EF701655C78ULL,
		0xBEAA3524656FCD58ULL,
		0xFB87BA0A25F70815ULL,
		0x573DA7CCA3E3413CULL,
		0x47ABB06A4F13F06CULL
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
		0x8697191A0C032571ULL,
		0x18E9A8DB40C0181FULL,
		0xCFDA7B0F6FA9F1B7ULL,
		0x3D3170357C60CEC6ULL,
		0x4DFDA4749F70B157ULL,
		0x6FD946E320CEF600ULL,
		0x4D07BDFEC21BE68FULL,
		0x1F55E1B2FA145662ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2E323418064AE2ULL,
		0x31D351B68180303FULL,
		0x9FB4F61EDF53E36EULL,
		0x7A62E06AF8C19D8DULL,
		0x9BFB48E93EE162AEULL,
		0xDFB28DC6419DEC00ULL,
		0x9A0F7BFD8437CD1EULL,
		0x3EABC365F428ACC4ULL
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
		0x2A59D7E7DB83E53BULL,
		0xD89B9304EE2C7E8FULL,
		0xADE0FC3ECC10A008ULL,
		0xDF24D9D5943973BEULL,
		0xD16DB97A7B9FD87BULL,
		0x36D089BAF59D5E0FULL,
		0x5F2E1AAF10A9D2F7ULL,
		0x1FAEB6B411F462CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B3AFCFB707CA76ULL,
		0xB1372609DC58FD1EULL,
		0x5BC1F87D98214011ULL,
		0xBE49B3AB2872E77DULL,
		0xA2DB72F4F73FB0F7ULL,
		0x6DA11375EB3ABC1FULL,
		0xBE5C355E2153A5EEULL,
		0x3F5D6D6823E8C594ULL
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
		0x17CFD5B44703F225ULL,
		0x1907EAC28DCE6D9FULL,
		0x9BFF5CE895EF8272ULL,
		0xBEC8B6249D66E284ULL,
		0xA10E394D9C59203FULL,
		0xDB7467C0C4C32E1BULL,
		0xBFBAEEC6D2E5D68DULL,
		0x11521A7FB67431F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F9FAB688E07E44AULL,
		0x320FD5851B9CDB3EULL,
		0x37FEB9D12BDF04E4ULL,
		0x7D916C493ACDC509ULL,
		0x421C729B38B2407FULL,
		0xB6E8CF8189865C37ULL,
		0x7F75DD8DA5CBAD1BULL,
		0x22A434FF6CE863E9ULL
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
		0xA7B66280C7441666ULL,
		0x236806FF1350B617ULL,
		0xF4BA1CB9BF44444FULL,
		0xBBBC7E04C42D2CDAULL,
		0x43A7E5E3BEC89121ULL,
		0x8236055D4C73832CULL,
		0x113294C6BAA855B6ULL,
		0x1382969DA80FB48AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F6CC5018E882CCCULL,
		0x46D00DFE26A16C2FULL,
		0xE97439737E88889EULL,
		0x7778FC09885A59B5ULL,
		0x874FCBC77D912243ULL,
		0x046C0ABA98E70658ULL,
		0x2265298D7550AB6DULL,
		0x27052D3B501F6914ULL
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
		0x3AC9D63537518746ULL,
		0x63A700A6D207B60DULL,
		0x1C7A33F7B20A3CA3ULL,
		0x4A00FEC3A748652CULL,
		0xAE2BEC005064250DULL,
		0xBA1428918F1D343AULL,
		0x34F755A26157D7EAULL,
		0x17D5F51C35A13B41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7593AC6A6EA30E8CULL,
		0xC74E014DA40F6C1AULL,
		0x38F467EF64147946ULL,
		0x9401FD874E90CA58ULL,
		0x5C57D800A0C84A1AULL,
		0x742851231E3A6875ULL,
		0x69EEAB44C2AFAFD5ULL,
		0x2FABEA386B427682ULL
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
		0x95375C1358BF36C3ULL,
		0xFDAE09E04AF0D4BBULL,
		0x17A3C0764CAE0E89ULL,
		0x13AA6919B0EE884CULL,
		0xC989B037756562FEULL,
		0x4E94DF962F24EA30ULL,
		0xFF0EA2BE716B6C59ULL,
		0x1B7575497B8E788FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A6EB826B17E6D86ULL,
		0xFB5C13C095E1A977ULL,
		0x2F4780EC995C1D13ULL,
		0x2754D23361DD1098ULL,
		0x9313606EEACAC5FCULL,
		0x9D29BF2C5E49D461ULL,
		0xFE1D457CE2D6D8B2ULL,
		0x36EAEA92F71CF11FULL
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
		0xA2C089BFE751773FULL,
		0x1538077283393D28ULL,
		0x2092A9EBE41EDE40ULL,
		0x5F7AC623FDEC4E66ULL,
		0x0222E12F0C023639ULL,
		0x0B7B1766EDE3556CULL,
		0x3E3017EE2E860139ULL,
		0x140BA693F1B07262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4581137FCEA2EE7EULL,
		0x2A700EE506727A51ULL,
		0x412553D7C83DBC80ULL,
		0xBEF58C47FBD89CCCULL,
		0x0445C25E18046C72ULL,
		0x16F62ECDDBC6AAD8ULL,
		0x7C602FDC5D0C0272ULL,
		0x28174D27E360E4C4ULL
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
		0x75DD0964CA921186ULL,
		0x5899B579D512371EULL,
		0x8530990EC1944D4DULL,
		0x6D228AB36AB2958AULL,
		0x9EFA51426134EF40ULL,
		0x981455330014FD0FULL,
		0xF91D4BCBDABB40FEULL,
		0x0433593A43E7FE73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBA12C99524230CULL,
		0xB1336AF3AA246E3CULL,
		0x0A61321D83289A9AULL,
		0xDA451566D5652B15ULL,
		0x3DF4A284C269DE80ULL,
		0x3028AA660029FA1FULL,
		0xF23A9797B57681FDULL,
		0x0866B27487CFFCE7ULL
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
		0x14A658A63E228924ULL,
		0xBD4D5B32B5D49B08ULL,
		0xC13BD1289BD83F24ULL,
		0xA557F6FD01FC8DAEULL,
		0x4CB8B3FEB41C1237ULL,
		0x2DBA33D4EB9103E0ULL,
		0x13FACF0F391D3D0CULL,
		0x06229C899647B0FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x294CB14C7C451248ULL,
		0x7A9AB6656BA93610ULL,
		0x8277A25137B07E49ULL,
		0x4AAFEDFA03F91B5DULL,
		0x997167FD6838246FULL,
		0x5B7467A9D72207C0ULL,
		0x27F59E1E723A7A18ULL,
		0x0C4539132C8F61F8ULL
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
		0xB93709D3C71D0DD1ULL,
		0xCA1977090129971FULL,
		0xD80936306C42BBA7ULL,
		0xE8074766346707ACULL,
		0xA1333AE792997843ULL,
		0xA80549AEF3DA2330ULL,
		0x874ECA65C673D2C8ULL,
		0x123F4D961316BB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726E13A78E3A1BA2ULL,
		0x9432EE1202532E3FULL,
		0xB0126C60D885774FULL,
		0xD00E8ECC68CE0F59ULL,
		0x426675CF2532F087ULL,
		0x500A935DE7B44661ULL,
		0x0E9D94CB8CE7A591ULL,
		0x247E9B2C262D7701ULL
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
		0x891C08F1E8E77989ULL,
		0x21AB9BD91C6E0B8AULL,
		0xB98122CE03C29612ULL,
		0xE1D3C1D8E2F3C660ULL,
		0x104DBD512C9AF2ACULL,
		0x0CAB29DEF34ED019ULL,
		0xA39AA9A63465F2B3ULL,
		0x1A0B54024428F250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x123811E3D1CEF312ULL,
		0x435737B238DC1715ULL,
		0x7302459C07852C24ULL,
		0xC3A783B1C5E78CC1ULL,
		0x209B7AA25935E559ULL,
		0x195653BDE69DA032ULL,
		0x4735534C68CBE566ULL,
		0x3416A8048851E4A1ULL
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
		0x4848059D96049FAEULL,
		0x8733BEB850DCB0EBULL,
		0x18E18873455D2FD1ULL,
		0x11171685E18E44AFULL,
		0x29362DD3892BC72AULL,
		0xCA5ED7531F7BD18AULL,
		0x6C22190E68F84F72ULL,
		0x0A89B3212170BABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90900B3B2C093F5CULL,
		0x0E677D70A1B961D6ULL,
		0x31C310E68ABA5FA3ULL,
		0x222E2D0BC31C895EULL,
		0x526C5BA712578E54ULL,
		0x94BDAEA63EF7A314ULL,
		0xD844321CD1F09EE5ULL,
		0x1513664242E17574ULL
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
		0xE2E10746E6AB41F7ULL,
		0x769FD603EAF93589ULL,
		0xD72A41BC3F691BF6ULL,
		0xD94B253395AAB3EFULL,
		0xEE88D09D36DF0E76ULL,
		0xB7C62A9FAF5C582CULL,
		0x28440F8FC154D938ULL,
		0x3F6010993E6729B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C20E8DCD5683EEULL,
		0xED3FAC07D5F26B13ULL,
		0xAE5483787ED237ECULL,
		0xB2964A672B5567DFULL,
		0xDD11A13A6DBE1CEDULL,
		0x6F8C553F5EB8B059ULL,
		0x50881F1F82A9B271ULL,
		0x7EC021327CCE5372ULL
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
		0x39A9FA4B9B01C349ULL,
		0xAD3A8EFF821801B3ULL,
		0x4062D8520146D5ABULL,
		0x99100994C8873A24ULL,
		0xC939154898298FD8ULL,
		0x9CC67CDEA4AAF025ULL,
		0xBCA7B62E1FDF1D30ULL,
		0x0FD1DF935BDCBA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7353F49736038692ULL,
		0x5A751DFF04300366ULL,
		0x80C5B0A4028DAB57ULL,
		0x32201329910E7448ULL,
		0x92722A9130531FB1ULL,
		0x398CF9BD4955E04BULL,
		0x794F6C5C3FBE3A61ULL,
		0x1FA3BF26B7B97415ULL
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
		0xE88BD9C21775C6E0ULL,
		0xEEA572FDC5690FA0ULL,
		0xAABFFEECFF7717B8ULL,
		0xAB6F27E2B5FE1C87ULL,
		0x6D36E3CB76C16FAFULL,
		0x8B5B46BCF64AD4B3ULL,
		0x38A386B068ED2172ULL,
		0x291547E3F0C5D9C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD117B3842EEB8DC0ULL,
		0xDD4AE5FB8AD21F41ULL,
		0x557FFDD9FEEE2F71ULL,
		0x56DE4FC56BFC390FULL,
		0xDA6DC796ED82DF5FULL,
		0x16B68D79EC95A966ULL,
		0x71470D60D1DA42E5ULL,
		0x522A8FC7E18BB38AULL
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
		0xF55F30CD7B074FC1ULL,
		0x06FEEA1B224AA4A1ULL,
		0xEAFA9624BDAC1601ULL,
		0xD017797EC2A1CD09ULL,
		0x522A15154278E545ULL,
		0x4D69760A58622625ULL,
		0xCA59AB76207420F7ULL,
		0x2248CFE20F958CFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEABE619AF60E9F82ULL,
		0x0DFDD43644954943ULL,
		0xD5F52C497B582C02ULL,
		0xA02EF2FD85439A13ULL,
		0xA4542A2A84F1CA8BULL,
		0x9AD2EC14B0C44C4AULL,
		0x94B356EC40E841EEULL,
		0x44919FC41F2B19F5ULL
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
		0x349C1782E414A384ULL,
		0xEA2E678626903C73ULL,
		0xE4DA73B7A6122638ULL,
		0x64B6041725D98EFBULL,
		0x43588A85C72737BDULL,
		0xF7492712DCC1E4D4ULL,
		0xAC91723746B46401ULL,
		0x145FE01DB33D5BCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69382F05C8294708ULL,
		0xD45CCF0C4D2078E6ULL,
		0xC9B4E76F4C244C71ULL,
		0xC96C082E4BB31DF7ULL,
		0x86B1150B8E4E6F7AULL,
		0xEE924E25B983C9A8ULL,
		0x5922E46E8D68C803ULL,
		0x28BFC03B667AB79BULL
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
		0x63648D5E65B8AAB6ULL,
		0xFCD4CABFD6151A30ULL,
		0x083AEA3A1C9845D8ULL,
		0xED7D1BC3BF9DB0ADULL,
		0xD97B8819236442E0ULL,
		0x7F4129893158DC52ULL,
		0xAC796B651221CB36ULL,
		0x00DC67C3303F6B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C91ABCCB71556CULL,
		0xF9A9957FAC2A3460ULL,
		0x1075D47439308BB1ULL,
		0xDAFA37877F3B615AULL,
		0xB2F7103246C885C1ULL,
		0xFE82531262B1B8A5ULL,
		0x58F2D6CA2443966CULL,
		0x01B8CF86607ED623ULL
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
		0x8422652DC1D423A9ULL,
		0x738F1056B4731E64ULL,
		0xD68BA6D429CA8B2FULL,
		0x67BD57868F54DF71ULL,
		0x371A31DB77C00684ULL,
		0x863E54226E6338D5ULL,
		0x3ADE6BAD7E7DA748ULL,
		0x38BECB405140317BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0844CA5B83A84752ULL,
		0xE71E20AD68E63CC9ULL,
		0xAD174DA85395165EULL,
		0xCF7AAF0D1EA9BEE3ULL,
		0x6E3463B6EF800D08ULL,
		0x0C7CA844DCC671AAULL,
		0x75BCD75AFCFB4E91ULL,
		0x717D9680A28062F6ULL
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
		0x8E08C3527FC583E6ULL,
		0xFBE8F4511340D4AFULL,
		0x90F1BE15F5B5AF4BULL,
		0xAF0CAF2168640231ULL,
		0x0634B9456F616604ULL,
		0x36C8CECEB68205DAULL,
		0xED50D083D87845FBULL,
		0x0D7AEB6DD8347FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C1186A4FF8B07CCULL,
		0xF7D1E8A22681A95FULL,
		0x21E37C2BEB6B5E97ULL,
		0x5E195E42D0C80463ULL,
		0x0C69728ADEC2CC09ULL,
		0x6D919D9D6D040BB4ULL,
		0xDAA1A107B0F08BF6ULL,
		0x1AF5D6DBB068FF8BULL
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
		0xF953595C1E98BA09ULL,
		0x5AF83DBF0E392240ULL,
		0xFA5B409CDB1185B7ULL,
		0xBE39FCD9D0884B8CULL,
		0x4F4C8DA4992195F8ULL,
		0xDDEF35411FFDA3E6ULL,
		0xE79AA4A58E006193ULL,
		0x1EBB8637A1CB16C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2A6B2B83D317412ULL,
		0xB5F07B7E1C724481ULL,
		0xF4B68139B6230B6EULL,
		0x7C73F9B3A1109719ULL,
		0x9E991B4932432BF1ULL,
		0xBBDE6A823FFB47CCULL,
		0xCF35494B1C00C327ULL,
		0x3D770C6F43962D89ULL
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
		0x0B027ED48F4F3031ULL,
		0x459C65F650CA4E11ULL,
		0xAC18237F17F30FA2ULL,
		0xB85B5BF154C00FA8ULL,
		0x32178DF3EE352561ULL,
		0x3E95BA567073061DULL,
		0x4ED57B95E2AA3E62ULL,
		0x11E850BD97E31C93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1604FDA91E9E6062ULL,
		0x8B38CBECA1949C22ULL,
		0x583046FE2FE61F44ULL,
		0x70B6B7E2A9801F51ULL,
		0x642F1BE7DC6A4AC3ULL,
		0x7D2B74ACE0E60C3AULL,
		0x9DAAF72BC5547CC4ULL,
		0x23D0A17B2FC63926ULL
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
		0x7DCDDA99A0B2E6ADULL,
		0xA0BF5BC9B6B8478DULL,
		0x0B3DA0E15EFCA2C3ULL,
		0x5B14B78833FCF164ULL,
		0x515828C03D7F7827ULL,
		0x5D8F62869CDC3453ULL,
		0x60F7A0EBC9F3C4A8ULL,
		0x1DD69218B6CAE9E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB9BB5334165CD5AULL,
		0x417EB7936D708F1AULL,
		0x167B41C2BDF94587ULL,
		0xB6296F1067F9E2C8ULL,
		0xA2B051807AFEF04EULL,
		0xBB1EC50D39B868A6ULL,
		0xC1EF41D793E78950ULL,
		0x3BAD24316D95D3C0ULL
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
		0x31B70951BD12E424ULL,
		0x75CC1BB4E4BBAEA5ULL,
		0xF876DC7FEADD00C7ULL,
		0xCD8544776E937BF5ULL,
		0x196CF3FED5F14C68ULL,
		0x4CFD6FAE182748F8ULL,
		0x1724948BFD7D5B56ULL,
		0x169E525FB8F0218DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x636E12A37A25C848ULL,
		0xEB983769C9775D4AULL,
		0xF0EDB8FFD5BA018EULL,
		0x9B0A88EEDD26F7EBULL,
		0x32D9E7FDABE298D1ULL,
		0x99FADF5C304E91F0ULL,
		0x2E492917FAFAB6ACULL,
		0x2D3CA4BF71E0431AULL
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
		0xE515B536AE181F06ULL,
		0xACC6E6DFC738D4DDULL,
		0x10F1790C2FA81812ULL,
		0x9B62A661CB763641ULL,
		0x92ECA3ACF75FFC49ULL,
		0x49DA06D37A2B5551ULL,
		0x0609F7AD3A25027BULL,
		0x19296AB09DF6C532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA2B6A6D5C303E0CULL,
		0x598DCDBF8E71A9BBULL,
		0x21E2F2185F503025ULL,
		0x36C54CC396EC6C82ULL,
		0x25D94759EEBFF893ULL,
		0x93B40DA6F456AAA3ULL,
		0x0C13EF5A744A04F6ULL,
		0x3252D5613BED8A64ULL
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
		0xE19030D1A5412C61ULL,
		0x995FAA6200DE7813ULL,
		0x12DD21F8E5352D13ULL,
		0x4C280C60FBBE3802ULL,
		0x40FFA5349C191683ULL,
		0x83A2DA4DD2A2011EULL,
		0x87462FC2ED8318A4ULL,
		0x0D0E135F20098FA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC32061A34A8258C2ULL,
		0x32BF54C401BCF027ULL,
		0x25BA43F1CA6A5A27ULL,
		0x985018C1F77C7004ULL,
		0x81FF4A6938322D06ULL,
		0x0745B49BA544023CULL,
		0x0E8C5F85DB063149ULL,
		0x1A1C26BE40131F47ULL
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
		0xDE2967FA93696D07ULL,
		0x1BA3E73F30BA214DULL,
		0x7ED566E8D10A3278ULL,
		0x0EBB854748C2A592ULL,
		0x259C0DC6FC8CAD43ULL,
		0x9A3AE6FD4AFA31A7ULL,
		0x8D5CD20D470A52A6ULL,
		0x15C782E70FCF81F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC52CFF526D2DA0EULL,
		0x3747CE7E6174429BULL,
		0xFDAACDD1A21464F0ULL,
		0x1D770A8E91854B24ULL,
		0x4B381B8DF9195A86ULL,
		0x3475CDFA95F4634EULL,
		0x1AB9A41A8E14A54DULL,
		0x2B8F05CE1F9F03EBULL
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
		0x32118930D34D9486ULL,
		0x4E85B1A9B46E31B0ULL,
		0x3984BF70D3B33AA9ULL,
		0xFDAF9CC6AF904E90ULL,
		0x48F56A5C317EDE38ULL,
		0xE71CBDE4F8835B0FULL,
		0x5793499A0B5D9E68ULL,
		0x0D5EC22B2C50C8C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64231261A69B290CULL,
		0x9D0B635368DC6360ULL,
		0x73097EE1A7667552ULL,
		0xFB5F398D5F209D20ULL,
		0x91EAD4B862FDBC71ULL,
		0xCE397BC9F106B61EULL,
		0xAF26933416BB3CD1ULL,
		0x1ABD845658A1918AULL
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
		0xE510A47906B20DC0ULL,
		0x4965B581CC746242ULL,
		0x8477F499AA496461ULL,
		0x35E7248FB7C2AD11ULL,
		0x1D53D2B6CE8D6F91ULL,
		0xAF27C325F9CFB8E4ULL,
		0x65D42762A5BC2B2AULL,
		0x23EFC92291B5AFB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA2148F20D641B80ULL,
		0x92CB6B0398E8C485ULL,
		0x08EFE9335492C8C2ULL,
		0x6BCE491F6F855A23ULL,
		0x3AA7A56D9D1ADF22ULL,
		0x5E4F864BF39F71C8ULL,
		0xCBA84EC54B785655ULL,
		0x47DF9245236B5F60ULL
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
		0xA24053A2D2A34508ULL,
		0x81B96E07A0A4796AULL,
		0x768774CE6811CA62ULL,
		0xAE763DDB521E98CDULL,
		0x0295C0BD69A22FF0ULL,
		0x5DED3689727393DEULL,
		0x9E1725D344B7227CULL,
		0x32B06A5DFE7E7D67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4480A745A5468A10ULL,
		0x0372DC0F4148F2D5ULL,
		0xED0EE99CD02394C5ULL,
		0x5CEC7BB6A43D319AULL,
		0x052B817AD3445FE1ULL,
		0xBBDA6D12E4E727BCULL,
		0x3C2E4BA6896E44F8ULL,
		0x6560D4BBFCFCFACFULL
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
		0x1E76EC5A0D9FFFA5ULL,
		0x207E62176324ABA8ULL,
		0x5115DF3D67A7A92CULL,
		0x086B60B8F2148FC7ULL,
		0x1FF1613ED5FBA46DULL,
		0x5FCFE834F6405224ULL,
		0xBDBF436238EB6ACEULL,
		0x216CA3B01CD7EE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CEDD8B41B3FFF4AULL,
		0x40FCC42EC6495750ULL,
		0xA22BBE7ACF4F5258ULL,
		0x10D6C171E4291F8EULL,
		0x3FE2C27DABF748DAULL,
		0xBF9FD069EC80A448ULL,
		0x7B7E86C471D6D59CULL,
		0x42D9476039AFDCC5ULL
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
		0x2DD25B730C39B465ULL,
		0x946FD724E4817761ULL,
		0x6623614328CA703FULL,
		0xC50A8D4A65401148ULL,
		0x956BD27A8D23B800ULL,
		0xC30B3050C4C55F7BULL,
		0x847B634522BFDC50ULL,
		0x0664DD6EE06A08AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BA4B6E6187368CAULL,
		0x28DFAE49C902EEC2ULL,
		0xCC46C2865194E07FULL,
		0x8A151A94CA802290ULL,
		0x2AD7A4F51A477001ULL,
		0x861660A1898ABEF7ULL,
		0x08F6C68A457FB8A1ULL,
		0x0CC9BADDC0D41155ULL
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
		0x5ED2A332ADC89A13ULL,
		0x935B7D3466390EFFULL,
		0x66B90B4537C375C5ULL,
		0xCCA8A7136A3A4407ULL,
		0x56A52EF8254E6B91ULL,
		0x40F154BA31421158ULL,
		0x7295608783D6182EULL,
		0x1C4A9A8E3CC00C75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA546655B913426ULL,
		0x26B6FA68CC721DFEULL,
		0xCD72168A6F86EB8BULL,
		0x99514E26D474880EULL,
		0xAD4A5DF04A9CD723ULL,
		0x81E2A974628422B0ULL,
		0xE52AC10F07AC305CULL,
		0x3895351C798018EAULL
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
		0xF997A8567725574CULL,
		0x09162629477F8AE4ULL,
		0xE1767353E600B015ULL,
		0x379CA31D3A16F0E2ULL,
		0xB696618AB690E15EULL,
		0x940D6FEB0956A390ULL,
		0x1F79D9AC0FC620ACULL,
		0x3300B3BFF7F45246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF32F50ACEE4AAE98ULL,
		0x122C4C528EFF15C9ULL,
		0xC2ECE6A7CC01602AULL,
		0x6F39463A742DE1C5ULL,
		0x6D2CC3156D21C2BCULL,
		0x281ADFD612AD4721ULL,
		0x3EF3B3581F8C4159ULL,
		0x6601677FEFE8A48CULL
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
		0x949B990D9D7FDA99ULL,
		0xD31E86928CE42479ULL,
		0x73E08FBDC83BCDF0ULL,
		0xD2CF208C2AB22B4EULL,
		0x63D82C64F49A872AULL,
		0x860EAD232E75E4C9ULL,
		0x33EC2BEF5AC40901ULL,
		0x13DFB31352AAD88EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2937321B3AFFB532ULL,
		0xA63D0D2519C848F3ULL,
		0xE7C11F7B90779BE1ULL,
		0xA59E41185564569CULL,
		0xC7B058C9E9350E55ULL,
		0x0C1D5A465CEBC992ULL,
		0x67D857DEB5881203ULL,
		0x27BF6626A555B11CULL
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
		0x19D2B69C045D922DULL,
		0x7BA4A21F64100B3CULL,
		0x3F55C6626472C639ULL,
		0xF5435688611CBFAAULL,
		0xDE743C69DA8BC97CULL,
		0xC040EB707B16CE89ULL,
		0xE3F8A3EBF709D155ULL,
		0x1336218F838E4E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A56D3808BB245AULL,
		0xF749443EC8201678ULL,
		0x7EAB8CC4C8E58C72ULL,
		0xEA86AD10C2397F54ULL,
		0xBCE878D3B51792F9ULL,
		0x8081D6E0F62D9D13ULL,
		0xC7F147D7EE13A2ABULL,
		0x266C431F071C9C63ULL
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
		0x18FBE04A393B2473ULL,
		0x42460E1B05945869ULL,
		0x4EFB8C43B6DC31CDULL,
		0xB1B106D170ED2583ULL,
		0xD6C34CD110C76D4EULL,
		0x058C1C6F40081DD4ULL,
		0x45625460A621C22AULL,
		0x0A57E3575C209012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F7C094727648E6ULL,
		0x848C1C360B28B0D2ULL,
		0x9DF718876DB8639AULL,
		0x63620DA2E1DA4B06ULL,
		0xAD8699A2218EDA9DULL,
		0x0B1838DE80103BA9ULL,
		0x8AC4A8C14C438454ULL,
		0x14AFC6AEB8412024ULL
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
		0x2AE16EC4D8BC1B76ULL,
		0xF30FF56B4E61DE77ULL,
		0x472F19CB694F9BE1ULL,
		0x588B1D4CFD8599B1ULL,
		0x85D0DEB2A0535C7AULL,
		0x4D8833CF8182A7ACULL,
		0xABE7DF69AD92807AULL,
		0x18D5A7A6F4B69181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C2DD89B17836ECULL,
		0xE61FEAD69CC3BCEEULL,
		0x8E5E3396D29F37C3ULL,
		0xB1163A99FB0B3362ULL,
		0x0BA1BD6540A6B8F4ULL,
		0x9B10679F03054F59ULL,
		0x57CFBED35B2500F4ULL,
		0x31AB4F4DE96D2303ULL
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
		0xBDC63D030A4A2510ULL,
		0x499EB375779ABF83ULL,
		0x3E587CC46CAF554AULL,
		0x6A51DC2C5C6AF9A4ULL,
		0x0096E9E3759F527DULL,
		0x5FF73492A926768AULL,
		0xF17D2F27B781A637ULL,
		0x318BD1D26FB1CE08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B8C7A0614944A20ULL,
		0x933D66EAEF357F07ULL,
		0x7CB0F988D95EAA94ULL,
		0xD4A3B858B8D5F348ULL,
		0x012DD3C6EB3EA4FAULL,
		0xBFEE6925524CED14ULL,
		0xE2FA5E4F6F034C6EULL,
		0x6317A3A4DF639C11ULL
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
		0xD15A2E876032AAF5ULL,
		0xC2BAF5F1E9D346ADULL,
		0xC7AB54A1DCC307B9ULL,
		0x575A9F4431C943BBULL,
		0x5DA897178C5BBD1CULL,
		0xD62B1A02625C197EULL,
		0x534CD99F412CAA96ULL,
		0x2B67AD6322498E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2B45D0EC06555EAULL,
		0x8575EBE3D3A68D5BULL,
		0x8F56A943B9860F73ULL,
		0xAEB53E8863928777ULL,
		0xBB512E2F18B77A38ULL,
		0xAC563404C4B832FCULL,
		0xA699B33E8259552DULL,
		0x56CF5AC644931C62ULL
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
		0xE006DC2241DB59D4ULL,
		0x564054CB7095C646ULL,
		0x041D7E755837A917ULL,
		0x56DF008A159143F4ULL,
		0x421C4E911CC605F5ULL,
		0xFFCD53BD7E2D0FACULL,
		0xE1EAF0B1981FA85DULL,
		0x2186B294201D0242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00DB84483B6B3A8ULL,
		0xAC80A996E12B8C8DULL,
		0x083AFCEAB06F522EULL,
		0xADBE01142B2287E8ULL,
		0x84389D22398C0BEAULL,
		0xFF9AA77AFC5A1F58ULL,
		0xC3D5E163303F50BBULL,
		0x430D6528403A0485ULL
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
		0x6E1452BC0B522A6DULL,
		0xE3022B51ADD016E5ULL,
		0xFEDFC1FB4FBEDBD9ULL,
		0x2C87EEB08C217D02ULL,
		0x07B456854DCAEB64ULL,
		0xEFAEC0DFF418D365ULL,
		0x403C961D66904951ULL,
		0x1EC1424B1F8BB6D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC28A57816A454DAULL,
		0xC60456A35BA02DCAULL,
		0xFDBF83F69F7DB7B3ULL,
		0x590FDD611842FA05ULL,
		0x0F68AD0A9B95D6C8ULL,
		0xDF5D81BFE831A6CAULL,
		0x80792C3ACD2092A3ULL,
		0x3D8284963F176DAEULL
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
		0x1D2F5872FFC33F78ULL,
		0x98E0AF524B43EC3AULL,
		0xAEDB7508E3A8F0DCULL,
		0xBE633AE2DACBA1DFULL,
		0xFDC0AEC05B547954ULL,
		0x1359F52379D78422ULL,
		0x42DD8C6D3C85674FULL,
		0x21F745CC2785B8F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5EB0E5FF867EF0ULL,
		0x31C15EA49687D874ULL,
		0x5DB6EA11C751E1B9ULL,
		0x7CC675C5B59743BFULL,
		0xFB815D80B6A8F2A9ULL,
		0x26B3EA46F3AF0845ULL,
		0x85BB18DA790ACE9EULL,
		0x43EE8B984F0B71EEULL
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
		0x92B89A7C6DEBC8EEULL,
		0x33A1885131B7B6EFULL,
		0x93F0BB09514AB81DULL,
		0x03B15849F1DB34FEULL,
		0xADBD719B38CD3150ULL,
		0xECDEA4B070790C52ULL,
		0x1B2CEF9409196BD1ULL,
		0x20B19BF7C5C79851ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x257134F8DBD791DCULL,
		0x674310A2636F6DDFULL,
		0x27E17612A295703AULL,
		0x0762B093E3B669FDULL,
		0x5B7AE336719A62A0ULL,
		0xD9BD4960E0F218A5ULL,
		0x3659DF281232D7A3ULL,
		0x416337EF8B8F30A2ULL
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
	k1 = (curve25519_key_t){.key64 = {
		0x1F6F07E05BC428C1ULL,
		0x19329CDFECFEBB7DULL,
		0xE8A6E6B3CCFD8AFEULL,
		0x216E4E8D34CAD84AULL,
		0x019A9F98477BFB85ULL,
		0x218E01B17F4F37A8ULL,
		0xDF1E724549C9474EULL,
		0x044E77C3A71B2529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EDE0FC0B7885182ULL,
		0x326539BFD9FD76FAULL,
		0xD14DCD6799FB15FCULL,
		0x42DC9D1A6995B095ULL,
		0x03353F308EF7F70AULL,
		0x431C0362FE9E6F50ULL,
		0xBE3CE48A93928E9CULL,
		0x089CEF874E364A53ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE23826AA95A67823ULL,
		0x37406D910C23A0B9ULL,
		0x74720E930C525234ULL,
		0xBFC0F668B8D03CFCULL,
		0x982E9C198DE362A0ULL,
		0xCDDE8973210B5296ULL,
		0x12D99932F9A608B1ULL,
		0x1A4FA5E865E76F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4704D552B4CF046ULL,
		0x6E80DB2218474173ULL,
		0xE8E41D2618A4A468ULL,
		0x7F81ECD171A079F8ULL,
		0x305D38331BC6C541ULL,
		0x9BBD12E64216A52DULL,
		0x25B33265F34C1163ULL,
		0x349F4BD0CBCEDE10ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4127355429C9E6E0ULL,
		0x8A87301D2E3D0975ULL,
		0x8E1CEFACA1B70503ULL,
		0xC7EF86415E065A5EULL,
		0x2FDDBE3238611A8DULL,
		0x9E87EA4B7BF7FEDFULL,
		0x37EC127FFC950AFBULL,
		0x0D7062ADE2340D6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x824E6AA85393CDC0ULL,
		0x150E603A5C7A12EAULL,
		0x1C39DF59436E0A07ULL,
		0x8FDF0C82BC0CB4BDULL,
		0x5FBB7C6470C2351BULL,
		0x3D0FD496F7EFFDBEULL,
		0x6FD824FFF92A15F7ULL,
		0x1AE0C55BC4681ADCULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3017693E61AADE06ULL,
		0x6B20FD6DAC8CDF21ULL,
		0xAF87A272A9FB157EULL,
		0xEA9F35E3D0A842DBULL,
		0x9A42D03C29A1F047ULL,
		0x30D9FCE0BDBFB148ULL,
		0x3ACC1C80C0FD45A8ULL,
		0x06241AEE0091714FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x602ED27CC355BC0CULL,
		0xD641FADB5919BE42ULL,
		0x5F0F44E553F62AFCULL,
		0xD53E6BC7A15085B7ULL,
		0x3485A0785343E08FULL,
		0x61B3F9C17B7F6291ULL,
		0x7598390181FA8B50ULL,
		0x0C4835DC0122E29EULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63C21CE80788FC96ULL,
		0x1D0C72570E771D64ULL,
		0xD270BBC6FEDB0F04ULL,
		0xF4DBA0B313D671D3ULL,
		0x843BABC6F6992F76ULL,
		0xCF81F80F6CBCF707ULL,
		0x414DD1E56027E189ULL,
		0x26C4FD2B09AED031ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78439D00F11F92CULL,
		0x3A18E4AE1CEE3AC8ULL,
		0xA4E1778DFDB61E08ULL,
		0xE9B7416627ACE3A7ULL,
		0x0877578DED325EEDULL,
		0x9F03F01ED979EE0FULL,
		0x829BA3CAC04FC313ULL,
		0x4D89FA56135DA062ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5833D820A91D3588ULL,
		0x8D64C392EF676152ULL,
		0xFF7932C117691AE5ULL,
		0x9AF5E5DD8951DE3DULL,
		0x75E6293807194450ULL,
		0xC3648D1BE0A1FB8AULL,
		0x287EFF7EE1112310ULL,
		0x3D5E29471CDBAC1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB067B041523A6B10ULL,
		0x1AC98725DECEC2A4ULL,
		0xFEF265822ED235CBULL,
		0x35EBCBBB12A3BC7BULL,
		0xEBCC52700E3288A1ULL,
		0x86C91A37C143F714ULL,
		0x50FDFEFDC2224621ULL,
		0x7ABC528E39B7583EULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFF522415C221353ULL,
		0xAD796AE99A79F466ULL,
		0xB4F87B54326EC843ULL,
		0xC6F187766FEA6959ULL,
		0xCF7A21051E0A3B79ULL,
		0xB33DEB5FE717109AULL,
		0x94E9481FA01351E6ULL,
		0x00FCD88CBEA9A5A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FEA4482B84426A6ULL,
		0x5AF2D5D334F3E8CDULL,
		0x69F0F6A864DD9087ULL,
		0x8DE30EECDFD4D2B3ULL,
		0x9EF4420A3C1476F3ULL,
		0x667BD6BFCE2E2135ULL,
		0x29D2903F4026A3CDULL,
		0x01F9B1197D534B53ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x609CA02F6CFA6930ULL,
		0xEA9641A3F693367DULL,
		0xD03DB3E251A157AFULL,
		0xA717AC9E613A2016ULL,
		0xE0C02E940E0413DEULL,
		0x99458A80C33EB4DFULL,
		0xFFAEF67EF387A468ULL,
		0x22428EF6F684B746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC139405ED9F4D260ULL,
		0xD52C8347ED266CFAULL,
		0xA07B67C4A342AF5FULL,
		0x4E2F593CC274402DULL,
		0xC1805D281C0827BDULL,
		0x328B1501867D69BFULL,
		0xFF5DECFDE70F48D1ULL,
		0x44851DEDED096E8DULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25300D73D384C668ULL,
		0x70252DF64F4F8B06ULL,
		0x574212F7110D6294ULL,
		0x55EDFB73F220FE72ULL,
		0x3EDCEC4E7485BC70ULL,
		0xB69BFE1F1DC9B5FDULL,
		0x03C7170C383E4A8AULL,
		0x36078C43463E1AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A601AE7A7098CD0ULL,
		0xE04A5BEC9E9F160CULL,
		0xAE8425EE221AC528ULL,
		0xABDBF6E7E441FCE4ULL,
		0x7DB9D89CE90B78E0ULL,
		0x6D37FC3E3B936BFAULL,
		0x078E2E18707C9515ULL,
		0x6C0F18868C7C354CULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77ECBEABDF277808ULL,
		0x3785C72371F54E5DULL,
		0x17901DC1A3723DA5ULL,
		0xAAE686FF9A04DC4BULL,
		0x9DD9A126BBFB1676ULL,
		0x37A0AB4F69B8EF00ULL,
		0x2B3B84DD936F44EAULL,
		0x13CFD064B2BA4963ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD97D57BE4EF010ULL,
		0x6F0B8E46E3EA9CBAULL,
		0x2F203B8346E47B4AULL,
		0x55CD0DFF3409B896ULL,
		0x3BB3424D77F62CEDULL,
		0x6F41569ED371DE01ULL,
		0x567709BB26DE89D4ULL,
		0x279FA0C9657492C6ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x560D3CB0B28AD6EAULL,
		0xC2D8E868ACFD7C4DULL,
		0xC2488928A3326B6BULL,
		0xF0C8784C07859AC7ULL,
		0x263D7A419CED1D46ULL,
		0xF511C63C6EE03D64ULL,
		0x9A9094CC76B52202ULL,
		0x11A001EC7E69783DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC1A79616515ADD4ULL,
		0x85B1D0D159FAF89AULL,
		0x849112514664D6D7ULL,
		0xE190F0980F0B358FULL,
		0x4C7AF48339DA3A8DULL,
		0xEA238C78DDC07AC8ULL,
		0x35212998ED6A4405ULL,
		0x234003D8FCD2F07BULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x873064A293103D54ULL,
		0x68E4585EC28E94B3ULL,
		0x66A273F6CBC35EC9ULL,
		0x65A04F640C0087C5ULL,
		0x5E40D968BA927C48ULL,
		0x3826708020868599ULL,
		0x94DE305524B2960DULL,
		0x3773E7C86B6EF633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E60C94526207AA8ULL,
		0xD1C8B0BD851D2967ULL,
		0xCD44E7ED9786BD92ULL,
		0xCB409EC818010F8AULL,
		0xBC81B2D17524F890ULL,
		0x704CE100410D0B32ULL,
		0x29BC60AA49652C1AULL,
		0x6EE7CF90D6DDEC67ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3639B3682C58534EULL,
		0xC475F823FB2F3363ULL,
		0xC3788458F81ACD6CULL,
		0x898B3641666325BCULL,
		0xBCC10416AD0A4E56ULL,
		0xF603D85ED4D78F23ULL,
		0x99154A1DE0B03561ULL,
		0x3C148A257FAF7537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7366D058B0A69CULL,
		0x88EBF047F65E66C6ULL,
		0x86F108B1F0359AD9ULL,
		0x13166C82CCC64B79ULL,
		0x7982082D5A149CADULL,
		0xEC07B0BDA9AF1E47ULL,
		0x322A943BC1606AC3ULL,
		0x7829144AFF5EEA6FULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70AFBDC82CD249F5ULL,
		0x44B3F756162A6D1CULL,
		0x14813DB915182FAFULL,
		0x15ADF99E1D7D1C92ULL,
		0x737BF4B0C2E29403ULL,
		0x01B4F6A52A1F21B4ULL,
		0xA78143F9E291C114ULL,
		0x0704D404FC1E475EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15F7B9059A493EAULL,
		0x8967EEAC2C54DA38ULL,
		0x29027B722A305F5EULL,
		0x2B5BF33C3AFA3924ULL,
		0xE6F7E96185C52806ULL,
		0x0369ED4A543E4368ULL,
		0x4F0287F3C5238228ULL,
		0x0E09A809F83C8EBDULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x870ADD1D22B370D2ULL,
		0xE47FC7BC2F682921ULL,
		0x89C6A627FDB20F4AULL,
		0xF1FD9B19ED730E77ULL,
		0xD5D23DF83CAEBFD5ULL,
		0x27E15658EBA895CBULL,
		0x7E7F6300C0658FCCULL,
		0x009465FDC26D2D26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E15BA3A4566E1A4ULL,
		0xC8FF8F785ED05243ULL,
		0x138D4C4FFB641E95ULL,
		0xE3FB3633DAE61CEFULL,
		0xABA47BF0795D7FABULL,
		0x4FC2ACB1D7512B97ULL,
		0xFCFEC60180CB1F98ULL,
		0x0128CBFB84DA5A4CULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69E122B934B86E61ULL,
		0xE4CD14497DC064B8ULL,
		0x0E04F66717CFA452ULL,
		0x804911A3E8A6134AULL,
		0xAB1ACE42353CB972ULL,
		0xA238B9D6BD6CAE17ULL,
		0x468E2CE5061985F5ULL,
		0x347C7CF517F77003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C245726970DCC2ULL,
		0xC99A2892FB80C970ULL,
		0x1C09ECCE2F9F48A5ULL,
		0x00922347D14C2694ULL,
		0x56359C846A7972E5ULL,
		0x447173AD7AD95C2FULL,
		0x8D1C59CA0C330BEBULL,
		0x68F8F9EA2FEEE006ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70DFBADEB0505FD3ULL,
		0xB8F75200C4C482D7ULL,
		0xBAFCD040193D1B2EULL,
		0x4B9E89FFDACC1275ULL,
		0x0B3A37187EFA4EAEULL,
		0x2C13F9BCEFE90A79ULL,
		0xBE43FE8E86AD287EULL,
		0x05F0609932C5D8DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1BF75BD60A0BFA6ULL,
		0x71EEA401898905AEULL,
		0x75F9A080327A365DULL,
		0x973D13FFB59824EBULL,
		0x16746E30FDF49D5CULL,
		0x5827F379DFD214F2ULL,
		0x7C87FD1D0D5A50FCULL,
		0x0BE0C132658BB1B9ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6422313AB142A9A1ULL,
		0x446E0580B8E8BCC4ULL,
		0x8A24EC863DE8B2D6ULL,
		0x2D4F06A6DC0C2409ULL,
		0x9B58D5DC72C37BA1ULL,
		0xDDD5033067E9F50CULL,
		0x94B118EB1079CE10ULL,
		0x36D66AEE3BD9B9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC844627562855342ULL,
		0x88DC0B0171D17988ULL,
		0x1449D90C7BD165ACULL,
		0x5A9E0D4DB8184813ULL,
		0x36B1ABB8E586F742ULL,
		0xBBAA0660CFD3EA19ULL,
		0x296231D620F39C21ULL,
		0x6DACD5DC77B373F5ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x430CEAADC692EC09ULL,
		0xA6E855F6D3889E97ULL,
		0xD12D7B936696A145ULL,
		0x7934D775469B9AB9ULL,
		0xA9EC312C1F486E53ULL,
		0x422F901F489B35ABULL,
		0x91EA83CA64C98BDBULL,
		0x25630CFA6308D194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8619D55B8D25D812ULL,
		0x4DD0ABEDA7113D2EULL,
		0xA25AF726CD2D428BULL,
		0xF269AEEA8D373573ULL,
		0x53D862583E90DCA6ULL,
		0x845F203E91366B57ULL,
		0x23D50794C99317B6ULL,
		0x4AC619F4C611A329ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8C13B6AFFB104A3ULL,
		0xB9629122C82C2A5DULL,
		0x8C615EDDBB5D1263ULL,
		0x9C03BD707FCE666DULL,
		0x6225C084077A2A8AULL,
		0x067DFEF0862E34B0ULL,
		0xAEB3A8E9171C3618ULL,
		0x00EB7D59C1360C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518276D5FF620946ULL,
		0x72C52245905854BBULL,
		0x18C2BDBB76BA24C7ULL,
		0x38077AE0FF9CCCDBULL,
		0xC44B81080EF45515ULL,
		0x0CFBFDE10C5C6960ULL,
		0x5D6751D22E386C30ULL,
		0x01D6FAB3826C1877ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56278BB2330625F3ULL,
		0x62F58349D5FF932CULL,
		0xBF0FE70D54C2FFEBULL,
		0x844B3C489BB8E525ULL,
		0x82D9F007A877C632ULL,
		0xE2ED31EBF42C2A9AULL,
		0x0313A20BA098CC7DULL,
		0x34642F0AB775D6F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC4F1764660C4BE6ULL,
		0xC5EB0693ABFF2658ULL,
		0x7E1FCE1AA985FFD6ULL,
		0x089678913771CA4BULL,
		0x05B3E00F50EF8C65ULL,
		0xC5DA63D7E8585535ULL,
		0x06274417413198FBULL,
		0x68C85E156EEBADE8ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8726C5BB67E9C0E7ULL,
		0x43BB6D7DA8F7EDDAULL,
		0xFE2A0702C06E94B4ULL,
		0x24CF1BC43443AD22ULL,
		0x39D343E053DB990BULL,
		0x91104CA94A791E75ULL,
		0xEDA7AAB33A85E161ULL,
		0x33C51389795C89EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E4D8B76CFD381CEULL,
		0x8776DAFB51EFDBB5ULL,
		0xFC540E0580DD2968ULL,
		0x499E378868875A45ULL,
		0x73A687C0A7B73216ULL,
		0x2220995294F23CEAULL,
		0xDB4F5566750BC2C3ULL,
		0x678A2712F2B913D5ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB51B6A6EC24880FULL,
		0xB3CE68186660D106ULL,
		0xAC9ADC49EA51D72AULL,
		0x065337B07673B4F5ULL,
		0x8B37EE29CDAD6575ULL,
		0xB0644ED79D8476F1ULL,
		0xCB6A60B4F15DB958ULL,
		0x23DEEB497C15C74DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A36D4DD849101EULL,
		0x679CD030CCC1A20DULL,
		0x5935B893D4A3AE55ULL,
		0x0CA66F60ECE769EBULL,
		0x166FDC539B5ACAEAULL,
		0x60C89DAF3B08EDE3ULL,
		0x96D4C169E2BB72B1ULL,
		0x47BDD692F82B8E9BULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C497554137030FFULL,
		0xD575C1251AB8A64BULL,
		0x9E0BF8DBC25E1805ULL,
		0x2EF56914F316CA35ULL,
		0xDDB9DE6661F19228ULL,
		0x98ABFB897EF67E8DULL,
		0x24F2B9B54DF37AAEULL,
		0x0B025BAAE771B0C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1892EAA826E061FEULL,
		0xAAEB824A35714C97ULL,
		0x3C17F1B784BC300BULL,
		0x5DEAD229E62D946BULL,
		0xBB73BCCCC3E32450ULL,
		0x3157F712FDECFD1BULL,
		0x49E5736A9BE6F55DULL,
		0x1604B755CEE36180ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6337F028D14DCB59ULL,
		0x5AF31D47D7E9F8D3ULL,
		0xB087F8BF9E8DC3E7ULL,
		0x50C8FC1074BD0A1BULL,
		0x875E2DD0153E58F9ULL,
		0xA5B52BB1FD4A9755ULL,
		0x0F7B387EA2F3CFD9ULL,
		0x0D2E3F18FF3A5895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66FE051A29B96B2ULL,
		0xB5E63A8FAFD3F1A6ULL,
		0x610FF17F3D1B87CEULL,
		0xA191F820E97A1437ULL,
		0x0EBC5BA02A7CB1F2ULL,
		0x4B6A5763FA952EABULL,
		0x1EF670FD45E79FB3ULL,
		0x1A5C7E31FE74B12AULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x505C870965708F17ULL,
		0x734ACC60DD25145EULL,
		0x1CE4AA082813239FULL,
		0x57C2D580B431F6BAULL,
		0x349806703D3AE6F1ULL,
		0x304AD1847A9CE688ULL,
		0xF295E53FDB146F7BULL,
		0x1FD27DB33AA3BB7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B90E12CAE11E2EULL,
		0xE69598C1BA4A28BCULL,
		0x39C954105026473EULL,
		0xAF85AB016863ED74ULL,
		0x69300CE07A75CDE2ULL,
		0x6095A308F539CD10ULL,
		0xE52BCA7FB628DEF6ULL,
		0x3FA4FB66754776FFULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC02C4B8384FE3D9EULL,
		0x8E21B2DFDB154A4AULL,
		0xDF813A44FD4DF859ULL,
		0xAABE912850CD5640ULL,
		0xC55BAAD719E2D427ULL,
		0xF488AF894265753AULL,
		0x685E94593330B207ULL,
		0x2119032961F8E407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8058970709FC7B3CULL,
		0x1C4365BFB62A9495ULL,
		0xBF027489FA9BF0B3ULL,
		0x557D2250A19AAC81ULL,
		0x8AB755AE33C5A84FULL,
		0xE9115F1284CAEA75ULL,
		0xD0BD28B26661640FULL,
		0x42320652C3F1C80EULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE307FE1BCA538B2ULL,
		0x062B0758788A0B9AULL,
		0x5D12859F9C931772ULL,
		0xD4571E1D1D4C523CULL,
		0x375E589E9BC5F780ULL,
		0xC6EF9DAD65B4665BULL,
		0xC86669C8A8FCA189ULL,
		0x08EBE00429F5DB0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC60FFC3794A7164ULL,
		0x0C560EB0F1141735ULL,
		0xBA250B3F39262EE4ULL,
		0xA8AE3C3A3A98A478ULL,
		0x6EBCB13D378BEF01ULL,
		0x8DDF3B5ACB68CCB6ULL,
		0x90CCD39151F94313ULL,
		0x11D7C00853EBB619ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10C8087F26215101ULL,
		0x982B8AB79A197AA5ULL,
		0x66887DAA926ABC42ULL,
		0xEEB45176ACE7BE67ULL,
		0x76C6FC71C54EBAD2ULL,
		0xCDD8E766F6D907A4ULL,
		0xAD2CFF779310DFF1ULL,
		0x2021B177E72F6514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x219010FE4C42A202ULL,
		0x3057156F3432F54AULL,
		0xCD10FB5524D57885ULL,
		0xDD68A2ED59CF7CCEULL,
		0xED8DF8E38A9D75A5ULL,
		0x9BB1CECDEDB20F48ULL,
		0x5A59FEEF2621BFE3ULL,
		0x404362EFCE5ECA29ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC780AAB47AC894F8ULL,
		0xB46ACC2A52FC3AFEULL,
		0xE0F6FECD2A200AABULL,
		0xDBBE1E01DD77BDF8ULL,
		0x5DA39CA1319CC748ULL,
		0xC4F7339153D44B14ULL,
		0x3B1535D2B5764A1AULL,
		0x32B339A5CDDE7C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F015568F59129F0ULL,
		0x68D59854A5F875FDULL,
		0xC1EDFD9A54401557ULL,
		0xB77C3C03BAEF7BF1ULL,
		0xBB47394263398E91ULL,
		0x89EE6722A7A89628ULL,
		0x762A6BA56AEC9435ULL,
		0x6566734B9BBCF85EULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26F3795ECFFF6ECDULL,
		0xDD5597093E74ABCFULL,
		0x804399405B22193AULL,
		0x16B792A3CE6F5B03ULL,
		0x3DF6529D07665295ULL,
		0x72B66B7F0284AE09ULL,
		0x6EC029DAF766F58CULL,
		0x3429E168BB0FF63EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE6F2BD9FFEDD9AULL,
		0xBAAB2E127CE9579EULL,
		0x00873280B6443275ULL,
		0x2D6F25479CDEB607ULL,
		0x7BECA53A0ECCA52AULL,
		0xE56CD6FE05095C12ULL,
		0xDD8053B5EECDEB18ULL,
		0x6853C2D1761FEC7CULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D8B73C0CE1CD9EAULL,
		0xB362BB944B876FFAULL,
		0x173FB2A46BD0A078ULL,
		0xEED39A2E3E0E564FULL,
		0x857F413E7A58C120ULL,
		0x8A91D8E4B415BA3FULL,
		0xEE95D05E26E24167ULL,
		0x264C63ABFF82A8E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB16E7819C39B3D4ULL,
		0x66C57728970EDFF4ULL,
		0x2E7F6548D7A140F1ULL,
		0xDDA7345C7C1CAC9EULL,
		0x0AFE827CF4B18241ULL,
		0x1523B1C9682B747FULL,
		0xDD2BA0BC4DC482CFULL,
		0x4C98C757FF0551C1ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2BA3095FE437820ULL,
		0x11E9758E875C306DULL,
		0x84C9B9669C8E8C04ULL,
		0x4DF1DD6218F9730CULL,
		0x05546DE51E199374ULL,
		0xD9F19ABB86D1F19AULL,
		0xE953628F019B85F9ULL,
		0x32C534DB2F3DF93DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC574612BFC86F040ULL,
		0x23D2EB1D0EB860DBULL,
		0x099372CD391D1808ULL,
		0x9BE3BAC431F2E619ULL,
		0x0AA8DBCA3C3326E8ULL,
		0xB3E335770DA3E334ULL,
		0xD2A6C51E03370BF3ULL,
		0x658A69B65E7BF27BULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22EB7CD7EE5A5CD6ULL,
		0x916C806418AF04ABULL,
		0xC641A650AB2683F3ULL,
		0x0ED309449D465777ULL,
		0x9B30B4BAACE1539EULL,
		0xD96A586C0521734FULL,
		0xA7687A5A9C00FFF8ULL,
		0x2C2256B0A09A7CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45D6F9AFDCB4B9ACULL,
		0x22D900C8315E0956ULL,
		0x8C834CA1564D07E7ULL,
		0x1DA612893A8CAEEFULL,
		0x3661697559C2A73CULL,
		0xB2D4B0D80A42E69FULL,
		0x4ED0F4B53801FFF1ULL,
		0x5844AD614134F9D1ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA561BF020DB89903ULL,
		0x68587E69E18A0FC8ULL,
		0x33215D3F3CA5863EULL,
		0x460534DFF61912F2ULL,
		0xF821703EE07958E7ULL,
		0xE171491455E4FFE7ULL,
		0x5FDF1EBE4444F606ULL,
		0x23C237A015378E60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AC37E041B713206ULL,
		0xD0B0FCD3C3141F91ULL,
		0x6642BA7E794B0C7CULL,
		0x8C0A69BFEC3225E4ULL,
		0xF042E07DC0F2B1CEULL,
		0xC2E29228ABC9FFCFULL,
		0xBFBE3D7C8889EC0DULL,
		0x47846F402A6F1CC0ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD35D1A0F966708CEULL,
		0xD883A17951F4C85CULL,
		0x9A84B347CBE9E0F8ULL,
		0x87BCB5225C418D5DULL,
		0xB293F80CF7ECFAB1ULL,
		0xE8A5B130D872834CULL,
		0xD0648C9097FC1CCEULL,
		0x0CE0BECF77DA7570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BA341F2CCE119CULL,
		0xB10742F2A3E990B9ULL,
		0x3509668F97D3C1F1ULL,
		0x0F796A44B8831ABBULL,
		0x6527F019EFD9F563ULL,
		0xD14B6261B0E50699ULL,
		0xA0C919212FF8399DULL,
		0x19C17D9EEFB4EAE1ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69AFC936FABC2ECULL,
		0xA7932630CE3103E7ULL,
		0x0CB5B17FD5855735ULL,
		0xC343A4E58A19D0E5ULL,
		0xD915D0DDD758B10DULL,
		0xB0D04F1077A4CE1EULL,
		0xC463001B6A4D91FEULL,
		0x23C301A271C7AC09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D35F926DF5785D8ULL,
		0x4F264C619C6207CFULL,
		0x196B62FFAB0AAE6BULL,
		0x868749CB1433A1CAULL,
		0xB22BA1BBAEB1621BULL,
		0x61A09E20EF499C3DULL,
		0x88C60036D49B23FDULL,
		0x47860344E38F5813ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73E9D60EB07BBDACULL,
		0x8B44AA20B961BC97ULL,
		0x086C100871541D85ULL,
		0x93C67BE38B17D5C9ULL,
		0x6D95C03786FFDA3EULL,
		0x1277F637EDD3292EULL,
		0x4459ED2D4D1ED5EBULL,
		0x1260FDDEE4FBBBF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7D3AC1D60F77B58ULL,
		0x1689544172C3792EULL,
		0x10D82010E2A83B0BULL,
		0x278CF7C7162FAB92ULL,
		0xDB2B806F0DFFB47DULL,
		0x24EFEC6FDBA6525CULL,
		0x88B3DA5A9A3DABD6ULL,
		0x24C1FBBDC9F777ECULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25707D817AF8C5DEULL,
		0x918C69C760DDB383ULL,
		0xD32188EC81C0DA2FULL,
		0xCE2EE5F7E4874281ULL,
		0x2F1F509C6E765F79ULL,
		0x02527960C664D7B8ULL,
		0x21033CD7FFAF3283ULL,
		0x2447F40E8B055E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE0FB02F5F18BBCULL,
		0x2318D38EC1BB6706ULL,
		0xA64311D90381B45FULL,
		0x9C5DCBEFC90E8503ULL,
		0x5E3EA138DCECBEF3ULL,
		0x04A4F2C18CC9AF70ULL,
		0x420679AFFF5E6506ULL,
		0x488FE81D160ABC54ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE83AD8BD521083F9ULL,
		0x670C032853787950ULL,
		0x106BC4F865C9C0A1ULL,
		0xB5D7104ABE10E9DDULL,
		0x26D7AFB7A0FEB771ULL,
		0x8654FAFDBBFB9EE7ULL,
		0x8B65900806609DC6ULL,
		0x1520B9FC01F4400BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD075B17AA42107F2ULL,
		0xCE180650A6F0F2A1ULL,
		0x20D789F0CB938142ULL,
		0x6BAE20957C21D3BAULL,
		0x4DAF5F6F41FD6EE3ULL,
		0x0CA9F5FB77F73DCEULL,
		0x16CB20100CC13B8DULL,
		0x2A4173F803E88017ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x803E0840FA1D3446ULL,
		0x98D08F4CA4E1C045ULL,
		0x884567FA6763FF1EULL,
		0x001813E0DF507B06ULL,
		0x4BEFC8E2A3E7A99DULL,
		0x8F120BBED4FAD2BBULL,
		0x371AEF1DD3B3D5E6ULL,
		0x11016A1279CCB3AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x007C1081F43A688CULL,
		0x31A11E9949C3808BULL,
		0x108ACFF4CEC7FE3DULL,
		0x003027C1BEA0F60DULL,
		0x97DF91C547CF533AULL,
		0x1E24177DA9F5A576ULL,
		0x6E35DE3BA767ABCDULL,
		0x2202D424F399675EULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5605814C5CC7BBF8ULL,
		0xF52230ADAD0D77E9ULL,
		0xC6E182668C5C25AFULL,
		0x7A197493CD0882CDULL,
		0xD1D84CC1516AD86AULL,
		0x6B65F18E74D6A848ULL,
		0x21C63576320CE241ULL,
		0x01663C39F01622F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC0B0298B98F77F0ULL,
		0xEA44615B5A1AEFD2ULL,
		0x8DC304CD18B84B5FULL,
		0xF432E9279A11059BULL,
		0xA3B09982A2D5B0D4ULL,
		0xD6CBE31CE9AD5091ULL,
		0x438C6AEC6419C482ULL,
		0x02CC7873E02C45E2ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2C3834052364448ULL,
		0x0B5685DCF8268C60ULL,
		0x36717687CF526AD9ULL,
		0x1ED94BB93D78A008ULL,
		0x74CB6EBF76202BD6ULL,
		0x64D2B8F72495AE15ULL,
		0x3D4E207DBEF4EBA4ULL,
		0x27DD0A8655786708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45870680A46C8890ULL,
		0x16AD0BB9F04D18C1ULL,
		0x6CE2ED0F9EA4D5B2ULL,
		0x3DB297727AF14010ULL,
		0xE996DD7EEC4057ACULL,
		0xC9A571EE492B5C2AULL,
		0x7A9C40FB7DE9D748ULL,
		0x4FBA150CAAF0CE10ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BBAC50DF1DE3B0EULL,
		0x0D513DC7F115A630ULL,
		0x8C51AB0F90D6AC4CULL,
		0x31C764732B8C6451ULL,
		0x888403D97C712C88ULL,
		0xAF0D7C2C68B25BBCULL,
		0x8DF701318E482500ULL,
		0x19831D6AD4CEC6ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57758A1BE3BC761CULL,
		0x1AA27B8FE22B4C60ULL,
		0x18A3561F21AD5898ULL,
		0x638EC8E65718C8A3ULL,
		0x110807B2F8E25910ULL,
		0x5E1AF858D164B779ULL,
		0x1BEE02631C904A01ULL,
		0x33063AD5A99D8D57ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD97C9B87B201E80ULL,
		0xCE8B598666B97865ULL,
		0x0469B675178F4307ULL,
		0x065C1C678188ECC7ULL,
		0x62E02C38ED20A878ULL,
		0x247657B2AFC047D6ULL,
		0x4EC4D5844E614C88ULL,
		0x0A0F087F15202EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B2F9370F6403D00ULL,
		0x9D16B30CCD72F0CBULL,
		0x08D36CEA2F1E860FULL,
		0x0CB838CF0311D98EULL,
		0xC5C05871DA4150F0ULL,
		0x48ECAF655F808FACULL,
		0x9D89AB089CC29910ULL,
		0x141E10FE2A405D74ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F3F164EA6922759ULL,
		0x4BA7AEE88AF1AB65ULL,
		0x9815BFC652389ED0ULL,
		0x4EAC7ED393425879ULL,
		0xEA52823781F95FF1ULL,
		0x8BB3392B2CD6F82EULL,
		0x283378F75C977DDFULL,
		0x29F463391AC17C96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE7E2C9D4D244EB2ULL,
		0x974F5DD115E356CAULL,
		0x302B7F8CA4713DA0ULL,
		0x9D58FDA72684B0F3ULL,
		0xD4A5046F03F2BFE2ULL,
		0x1766725659ADF05DULL,
		0x5066F1EEB92EFBBFULL,
		0x53E8C6723582F92CULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40FA83DB6D6E79EDULL,
		0x3EE2B82BE8363BA5ULL,
		0xCBD8FE29B6A5BF24ULL,
		0x694659D016011750ULL,
		0xF8C20D0AF0988620ULL,
		0xCEC7BE0EC35D3CE1ULL,
		0x594F4F8764838153ULL,
		0x389071022F82CF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81F507B6DADCF3DAULL,
		0x7DC57057D06C774AULL,
		0x97B1FC536D4B7E48ULL,
		0xD28CB3A02C022EA1ULL,
		0xF1841A15E1310C40ULL,
		0x9D8F7C1D86BA79C3ULL,
		0xB29E9F0EC90702A7ULL,
		0x7120E2045F059ED4ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC21D1B5F4401B34DULL,
		0xA7A1E803056B25CDULL,
		0x526C9EAF3F9B11D8ULL,
		0x4CCFCBA874A84E11ULL,
		0xE07445F5D1A45B5CULL,
		0x334F5777700AB36EULL,
		0x47A40E3A0EE9923BULL,
		0x396DB0DF2D6AD3E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x843A36BE8803669AULL,
		0x4F43D0060AD64B9BULL,
		0xA4D93D5E7F3623B1ULL,
		0x999F9750E9509C22ULL,
		0xC0E88BEBA348B6B8ULL,
		0x669EAEEEE01566DDULL,
		0x8F481C741DD32476ULL,
		0x72DB61BE5AD5A7C2ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27EF296C972DA6AAULL,
		0xE395D4742309ABC0ULL,
		0x6FC261BFEFB288E4ULL,
		0xD37DD4C569C839AEULL,
		0xF5BC312C1B7E5549ULL,
		0xE24AC433C7944E28ULL,
		0x6B0893FA2C4AA6EDULL,
		0x3CCB18ECA2FC10D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FDE52D92E5B4D54ULL,
		0xC72BA8E846135780ULL,
		0xDF84C37FDF6511C9ULL,
		0xA6FBA98AD390735CULL,
		0xEB78625836FCAA93ULL,
		0xC49588678F289C51ULL,
		0xD61127F458954DDBULL,
		0x799631D945F821A0ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x508ABD7FDA87C7B1ULL,
		0x25074C050EBC724AULL,
		0x8CCAAE49E0B0F3E0ULL,
		0xEE179CB0112579E6ULL,
		0xAC049722136C8C13ULL,
		0xCB42F6C4359DED5FULL,
		0xE1A0A2627EFB8A22ULL,
		0x1AD292CA75266CD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1157AFFB50F8F62ULL,
		0x4A0E980A1D78E494ULL,
		0x19955C93C161E7C0ULL,
		0xDC2F3960224AF3CDULL,
		0x58092E4426D91827ULL,
		0x9685ED886B3BDABFULL,
		0xC34144C4FDF71445ULL,
		0x35A52594EA4CD9A1ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B39184068A5D997ULL,
		0x7853880788B1CD03ULL,
		0x903047459D8B1FB1ULL,
		0xFFF29897C6521446ULL,
		0xEFCCE34CC50C0D24ULL,
		0xE0B39B276E7565E5ULL,
		0x290E4289122D656BULL,
		0x1D9DEBB74E99B0AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36723080D14BB32EULL,
		0xF0A7100F11639A07ULL,
		0x20608E8B3B163F62ULL,
		0xFFE5312F8CA4288DULL,
		0xDF99C6998A181A49ULL,
		0xC167364EDCEACBCBULL,
		0x521C8512245ACAD7ULL,
		0x3B3BD76E9D336154ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDEA61D60C2CD4FBULL,
		0x7B8EAE644C499F46ULL,
		0x97DB202B9A0C97B4ULL,
		0xDF4C418973CEE39AULL,
		0xFD9B10E1E947F451ULL,
		0x9EB4ABCA71951151ULL,
		0x53AB86DE489EBE10ULL,
		0x0F540B646CE6C3D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD4C3AC1859A9F6ULL,
		0xF71D5CC898933E8DULL,
		0x2FB6405734192F68ULL,
		0xBE988312E79DC735ULL,
		0xFB3621C3D28FE8A3ULL,
		0x3D695794E32A22A3ULL,
		0xA7570DBC913D7C21ULL,
		0x1EA816C8D9CD87A6ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66018A8389C6567BULL,
		0xDEC134AD3A2E042EULL,
		0xC34847C08D811AF8ULL,
		0x97E2547325DA72A1ULL,
		0x9B5EA42E2E675A0AULL,
		0xB030F830F66375C9ULL,
		0x6BE5F4B4E6D1F3A3ULL,
		0x30AD924C024962E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC031507138CACF6ULL,
		0xBD82695A745C085CULL,
		0x86908F811B0235F1ULL,
		0x2FC4A8E64BB4E543ULL,
		0x36BD485C5CCEB415ULL,
		0x6061F061ECC6EB93ULL,
		0xD7CBE969CDA3E747ULL,
		0x615B24980492C5CAULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE54A9D4D9AC6ACC0ULL,
		0x60009EEEFDFA3C92ULL,
		0x181999DD89AB423BULL,
		0xD5DC5C12D0047190ULL,
		0xA2F6D134C4A601C4ULL,
		0xA4CB3CD66D9234C2ULL,
		0x3FEA7C7D461F0C0AULL,
		0x1478874241838D70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA953A9B358D5980ULL,
		0xC0013DDDFBF47925ULL,
		0x303333BB13568476ULL,
		0xABB8B825A008E320ULL,
		0x45EDA269894C0389ULL,
		0x499679ACDB246985ULL,
		0x7FD4F8FA8C3E1815ULL,
		0x28F10E8483071AE0ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3A9E431FCBF01DEULL,
		0x66ED5EA391AA1C85ULL,
		0x726099949CE2D94DULL,
		0x8F5767040A4FAA3AULL,
		0x8158A86B69D6D995ULL,
		0x5008BED6FA2031C2ULL,
		0xA9EC0A81F2FC7CCCULL,
		0x20DF5F2FAE6D7D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE753C863F97E03BCULL,
		0xCDDABD472354390BULL,
		0xE4C1332939C5B29AULL,
		0x1EAECE08149F5474ULL,
		0x02B150D6D3ADB32BULL,
		0xA0117DADF4406385ULL,
		0x53D81503E5F8F998ULL,
		0x41BEBE5F5CDAFA79ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEF7A212F56AC1FCULL,
		0xBE4B75AB2D6EF407ULL,
		0x471A6E8FDA2CC0F9ULL,
		0x2F22B4B109D4D355ULL,
		0xAC0397C74F161A39ULL,
		0x948CEDF01D0B6D42ULL,
		0xA1954E6E95932595ULL,
		0x3F2D86877C57A700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DEF4425EAD583F8ULL,
		0x7C96EB565ADDE80FULL,
		0x8E34DD1FB45981F3ULL,
		0x5E45696213A9A6AAULL,
		0x58072F8E9E2C3472ULL,
		0x2919DBE03A16DA85ULL,
		0x432A9CDD2B264B2BULL,
		0x7E5B0D0EF8AF4E01ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21376246208EF8F4ULL,
		0xD846844B9BDC0CB3ULL,
		0xB268D7F632BAE199ULL,
		0x18B788E8F3566066ULL,
		0x6754A8312C329C5BULL,
		0xB867FCC02722EEA5ULL,
		0x7ACFF64CB36F453CULL,
		0x10EC498AB71D1B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x426EC48C411DF1E8ULL,
		0xB08D089737B81966ULL,
		0x64D1AFEC6575C333ULL,
		0x316F11D1E6ACC0CDULL,
		0xCEA95062586538B6ULL,
		0x70CFF9804E45DD4AULL,
		0xF59FEC9966DE8A79ULL,
		0x21D893156E3A3666ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F8B15CEB524B399ULL,
		0xD20757880C1B21E6ULL,
		0x32AF3691AE02378FULL,
		0x6448E5EBFE62FCDEULL,
		0xF468812E986F0322ULL,
		0xBB8A190B3BDA56F7ULL,
		0x9ED68247AEED359BULL,
		0x24F2F38131E35093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F162B9D6A496732ULL,
		0xA40EAF10183643CCULL,
		0x655E6D235C046F1FULL,
		0xC891CBD7FCC5F9BCULL,
		0xE8D1025D30DE0644ULL,
		0x7714321677B4ADEFULL,
		0x3DAD048F5DDA6B37ULL,
		0x49E5E70263C6A127ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84081E785A4C3DBBULL,
		0x542673524C537C00ULL,
		0x5C26FAC4DC943A5AULL,
		0xA5BD2F21B5B34339ULL,
		0xD8DC4986665863BFULL,
		0x94C3FA2F189648EBULL,
		0xB30B9616239F59CCULL,
		0x306CF88B37361DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08103CF0B4987B76ULL,
		0xA84CE6A498A6F801ULL,
		0xB84DF589B92874B4ULL,
		0x4B7A5E436B668672ULL,
		0xB1B8930CCCB0C77FULL,
		0x2987F45E312C91D7ULL,
		0x66172C2C473EB399ULL,
		0x60D9F1166E6C3BDBULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E23C793A6290C62ULL,
		0x5A2579D9C9C67C33ULL,
		0x6C7DA3E3BF73F7BAULL,
		0x33778C1D73447AFDULL,
		0x1A7035BDB3FA846CULL,
		0xFA46D2BA87DC9C27ULL,
		0x60D9ABB07A126680ULL,
		0x2CF4C6A2D1C7AFD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C478F274C5218C4ULL,
		0xB44AF3B3938CF866ULL,
		0xD8FB47C77EE7EF74ULL,
		0x66EF183AE688F5FAULL,
		0x34E06B7B67F508D8ULL,
		0xF48DA5750FB9384EULL,
		0xC1B35760F424CD01ULL,
		0x59E98D45A38F5FB2ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FFC06A3FE5C23D5ULL,
		0x7F07F3A9D365BE88ULL,
		0xD06C3C63235DA776ULL,
		0xF1CF35409FF7D19CULL,
		0x7B5792B0DA01ECDCULL,
		0xC9D80F905962ADA6ULL,
		0x2169D7BBC852680AULL,
		0x3F7C2FC377A8232DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FF80D47FCB847AAULL,
		0xFE0FE753A6CB7D10ULL,
		0xA0D878C646BB4EECULL,
		0xE39E6A813FEFA339ULL,
		0xF6AF2561B403D9B9ULL,
		0x93B01F20B2C55B4CULL,
		0x42D3AF7790A4D015ULL,
		0x7EF85F86EF50465AULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0627C1471819F0DULL,
		0x33F1E0A7D9C12517ULL,
		0xB67F70B5D926CAAFULL,
		0x4F10A37506968715ULL,
		0xE1D1F2CE5974431BULL,
		0xDF73FBAEC09CE85BULL,
		0xABA5ACE8B08FB435ULL,
		0x16C26D6444B3643CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C4F828E3033E1AULL,
		0x67E3C14FB3824A2FULL,
		0x6CFEE16BB24D955EULL,
		0x9E2146EA0D2D0E2BULL,
		0xC3A3E59CB2E88636ULL,
		0xBEE7F75D8139D0B7ULL,
		0x574B59D1611F686BULL,
		0x2D84DAC88966C879ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30379D84B34E5CEAULL,
		0x046367F9B7A7E48DULL,
		0x639929D5D24C8FE8ULL,
		0x046D6239D440B5DCULL,
		0xC5B8BB63C1BB2BECULL,
		0x70FE5A89066D92D9ULL,
		0xC203CEC3D2DAB5B8ULL,
		0x2A678E27E3F9CBC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606F3B09669CB9D4ULL,
		0x08C6CFF36F4FC91AULL,
		0xC73253ABA4991FD0ULL,
		0x08DAC473A8816BB8ULL,
		0x8B7176C7837657D8ULL,
		0xE1FCB5120CDB25B3ULL,
		0x84079D87A5B56B70ULL,
		0x54CF1C4FC7F39785ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17B5661F629FA9E4ULL,
		0x46F8038CF2B3BAEBULL,
		0x55EFA2043293BF7FULL,
		0x4AC09A27441128D1ULL,
		0xCAECEF9E2729763BULL,
		0x24BC0B15DC67F10BULL,
		0x455B634A7E9C831DULL,
		0x24CEF2AD646FF428ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F6ACC3EC53F53C8ULL,
		0x8DF00719E56775D6ULL,
		0xABDF440865277EFEULL,
		0x9581344E882251A2ULL,
		0x95D9DF3C4E52EC76ULL,
		0x4978162BB8CFE217ULL,
		0x8AB6C694FD39063AULL,
		0x499DE55AC8DFE850ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A764206857C6213ULL,
		0x78D5D8CF022315A8ULL,
		0x75EE720FD7E2E4E7ULL,
		0x5756C150A1911706ULL,
		0xE07F481A99A4C042ULL,
		0xCBE94FC2EE8F42CAULL,
		0x07E1F0AB73C84C00ULL,
		0x14BE1CD309AFE5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94EC840D0AF8C426ULL,
		0xF1ABB19E04462B50ULL,
		0xEBDCE41FAFC5C9CEULL,
		0xAEAD82A143222E0CULL,
		0xC0FE903533498084ULL,
		0x97D29F85DD1E8595ULL,
		0x0FC3E156E7909801ULL,
		0x297C39A6135FCBCEULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56FFDC7D20321D02ULL,
		0x6A65BB25E38DE380ULL,
		0x2B6B1B772519B838ULL,
		0x9F18CA1E288D73EEULL,
		0x9313F4F550FC9C62ULL,
		0x1C0253ECB6401A5FULL,
		0x7BD084F5565F6CB7ULL,
		0x28A812E4F5A1EA91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADFFB8FA40643A04ULL,
		0xD4CB764BC71BC700ULL,
		0x56D636EE4A337070ULL,
		0x3E31943C511AE7DCULL,
		0x2627E9EAA1F938C5ULL,
		0x3804A7D96C8034BFULL,
		0xF7A109EAACBED96EULL,
		0x515025C9EB43D522ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F884C9D26B886ECULL,
		0x834AD9735826566CULL,
		0x5EC14E62D544FBFFULL,
		0x6B4FB7B30D60D5C1ULL,
		0xD3C0E875346F20EDULL,
		0x66D1B535A872881CULL,
		0xC9B5EEC447DBEAA7ULL,
		0x2259244004BED8E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F10993A4D710DD8ULL,
		0x0695B2E6B04CACD9ULL,
		0xBD829CC5AA89F7FFULL,
		0xD69F6F661AC1AB82ULL,
		0xA781D0EA68DE41DAULL,
		0xCDA36A6B50E51039ULL,
		0x936BDD888FB7D54EULL,
		0x44B24880097DB1CFULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C0FE3A5C7053DA3ULL,
		0x67F23EA8EEBB4C67ULL,
		0xEDFB72F4CD16A55EULL,
		0x098E67B22AB378A6ULL,
		0x7026C01116FA9A85ULL,
		0xF2011CB7CB9BE0C2ULL,
		0xAB656B99A45DB780ULL,
		0x2846581B40552ACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381FC74B8E0A7B46ULL,
		0xCFE47D51DD7698CEULL,
		0xDBF6E5E99A2D4ABCULL,
		0x131CCF645566F14DULL,
		0xE04D80222DF5350AULL,
		0xE402396F9737C184ULL,
		0x56CAD73348BB6F01ULL,
		0x508CB03680AA559DULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80784F278F929D80ULL,
		0x9168E7335FF4F75CULL,
		0xBD9ADB9BDA5EB134ULL,
		0x3547FF73DEC95D5DULL,
		0x1F97D8FC1EACC24AULL,
		0x92A4A52AEF95D762ULL,
		0xF55941B0B0855C57ULL,
		0x0C756B87F20FD584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F09E4F1F253B00ULL,
		0x22D1CE66BFE9EEB9ULL,
		0x7B35B737B4BD6269ULL,
		0x6A8FFEE7BD92BABBULL,
		0x3F2FB1F83D598494ULL,
		0x25494A55DF2BAEC4ULL,
		0xEAB28361610AB8AFULL,
		0x18EAD70FE41FAB09ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CACD26CEE7D9B94ULL,
		0x61059F9E816D6C5CULL,
		0xED6081010F7806D9ULL,
		0x8D9978FB93F9F4C0ULL,
		0x1384AA959BD4DA05ULL,
		0x00958DFA0D0A261BULL,
		0x738C5294F4B45516ULL,
		0x39ED9D5A06175153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB959A4D9DCFB3728ULL,
		0xC20B3F3D02DAD8B8ULL,
		0xDAC102021EF00DB2ULL,
		0x1B32F1F727F3E981ULL,
		0x2709552B37A9B40BULL,
		0x012B1BF41A144C36ULL,
		0xE718A529E968AA2CULL,
		0x73DB3AB40C2EA2A6ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE05A5A4E92BADC74ULL,
		0xA1EA71A26031F2D0ULL,
		0x2D787CFC76CF0184ULL,
		0x004E3A3680FB2629ULL,
		0x0B30D962755F6E4BULL,
		0xE1BC9E977052AAB8ULL,
		0xFE4BD37F4FDFDE67ULL,
		0x0F38AA41E7AD07C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0B4B49D2575B8E8ULL,
		0x43D4E344C063E5A1ULL,
		0x5AF0F9F8ED9E0309ULL,
		0x009C746D01F64C52ULL,
		0x1661B2C4EABEDC96ULL,
		0xC3793D2EE0A55570ULL,
		0xFC97A6FE9FBFBCCFULL,
		0x1E715483CF5A0F87ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10C756984D44D373ULL,
		0xD3909667BB60DDE4ULL,
		0x52AC151BE2C0FBB6ULL,
		0x07C53E4EF280BD26ULL,
		0x06ECF62312BCF184ULL,
		0x6967B86F4DF32826ULL,
		0x13974C5418370294ULL,
		0x3071E62E8A97D8D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x218EAD309A89A6E6ULL,
		0xA7212CCF76C1BBC8ULL,
		0xA5582A37C581F76DULL,
		0x0F8A7C9DE5017A4CULL,
		0x0DD9EC462579E308ULL,
		0xD2CF70DE9BE6504CULL,
		0x272E98A8306E0528ULL,
		0x60E3CC5D152FB1A2ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50933CC6882A048EULL,
		0xDCA6D155C500A46AULL,
		0xF5B6B6A38D38A7D4ULL,
		0xA91867A3E4663373ULL,
		0x93FD07201BD3BF82ULL,
		0x265E23C202DF3C62ULL,
		0x3FAD8F8B3B4838A3ULL,
		0x3ADC07E00AFF7E11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA126798D1054091CULL,
		0xB94DA2AB8A0148D4ULL,
		0xEB6D6D471A714FA9ULL,
		0x5230CF47C8CC66E7ULL,
		0x27FA0E4037A77F05ULL,
		0x4CBC478405BE78C5ULL,
		0x7F5B1F1676907146ULL,
		0x75B80FC015FEFC22ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69C879BC24080A0ULL,
		0x1E048322F6DAE009ULL,
		0xAF5A7A675DCE2E53ULL,
		0x26E4A8AA9B6A8EA5ULL,
		0x3866EDB3FBADF9C5ULL,
		0xFEBD8176DE408ABDULL,
		0xAAF43BBBB4923FA8ULL,
		0x3F5A5C5F88A0C062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D390F3784810140ULL,
		0x3C090645EDB5C013ULL,
		0x5EB4F4CEBB9C5CA6ULL,
		0x4DC9515536D51D4BULL,
		0x70CDDB67F75BF38AULL,
		0xFD7B02EDBC81157AULL,
		0x55E8777769247F51ULL,
		0x7EB4B8BF114180C5ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87802951F6DEF814ULL,
		0xE54F19D94CB94FF6ULL,
		0xDDE994040178F338ULL,
		0x8C4C6ADEA4D89E78ULL,
		0x39FD23FFB23233E9ULL,
		0xD77E4A12A2A38057ULL,
		0x47F36A885C67C778ULL,
		0x3C38C79B4B0BF483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0052A3EDBDF028ULL,
		0xCA9E33B299729FEDULL,
		0xBBD3280802F1E671ULL,
		0x1898D5BD49B13CF1ULL,
		0x73FA47FF646467D3ULL,
		0xAEFC9425454700AEULL,
		0x8FE6D510B8CF8EF1ULL,
		0x78718F369617E906ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F7740A6318BD859ULL,
		0x8C560452958E57F9ULL,
		0xF03A3BD1B35CB172ULL,
		0x41516F5604E50A38ULL,
		0x1619B70DAE6E74B4ULL,
		0xAFF6170447F60C97ULL,
		0x9044ED1879382CB5ULL,
		0x121B8B9540326B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EEE814C6317B0B2ULL,
		0x18AC08A52B1CAFF2ULL,
		0xE07477A366B962E5ULL,
		0x82A2DEAC09CA1471ULL,
		0x2C336E1B5CDCE968ULL,
		0x5FEC2E088FEC192EULL,
		0x2089DA30F270596BULL,
		0x2437172A8064D6A5ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69DD628977C996C0ULL,
		0xA4D82DE796A5DEC1ULL,
		0x8C9D50C56755A595ULL,
		0xA9A92C91AD5626BDULL,
		0x85FAE956D7BA68BDULL,
		0xD92AB2D7119EB690ULL,
		0xBB884CC4D165B9C0ULL,
		0x00252D262B8BFAD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3BAC512EF932D80ULL,
		0x49B05BCF2D4BBD82ULL,
		0x193AA18ACEAB4B2BULL,
		0x535259235AAC4D7BULL,
		0x0BF5D2ADAF74D17BULL,
		0xB25565AE233D6D21ULL,
		0x77109989A2CB7381ULL,
		0x004A5A4C5717F5B1ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC717AF6A7B191AE2ULL,
		0x588F3AC6C57B6C76ULL,
		0x2C5A58810D9962CFULL,
		0x1A09AE2B7D5A7B5AULL,
		0x680B788739A6607BULL,
		0x0BEB76F602D11C90ULL,
		0x6600AC6E0280420EULL,
		0x108F9BE04609018FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E2F5ED4F63235C4ULL,
		0xB11E758D8AF6D8EDULL,
		0x58B4B1021B32C59EULL,
		0x34135C56FAB4F6B4ULL,
		0xD016F10E734CC0F6ULL,
		0x17D6EDEC05A23920ULL,
		0xCC0158DC0500841CULL,
		0x211F37C08C12031EULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D277C74FB923161ULL,
		0xCCCEC856C1481ED7ULL,
		0xF898A9239E83AFCAULL,
		0x3A76C1A5677EF933ULL,
		0xA3D8EBD845F278C0ULL,
		0x06FBBC3AF94EDF62ULL,
		0x9DB7B6F69E5E4FF3ULL,
		0x1B9EC2C19FF3C264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A4EF8E9F72462C2ULL,
		0x999D90AD82903DAEULL,
		0xF13152473D075F95ULL,
		0x74ED834ACEFDF267ULL,
		0x47B1D7B08BE4F180ULL,
		0x0DF77875F29DBEC5ULL,
		0x3B6F6DED3CBC9FE6ULL,
		0x373D85833FE784C9ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4167AB624425C5BDULL,
		0x034AD73F2ABE65E3ULL,
		0x29D416B61632E332ULL,
		0x31D4F1F02A8F0E25ULL,
		0x46FE8FB9F7A53041ULL,
		0x44D5296D66C0299CULL,
		0x1126C5218D4A96CEULL,
		0x1F6FA81A5972EED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82CF56C4884B8B7AULL,
		0x0695AE7E557CCBC6ULL,
		0x53A82D6C2C65C664ULL,
		0x63A9E3E0551E1C4AULL,
		0x8DFD1F73EF4A6082ULL,
		0x89AA52DACD805338ULL,
		0x224D8A431A952D9CULL,
		0x3EDF5034B2E5DDAAULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x204D593F8AD36393ULL,
		0xA6A289B69D0DCE82ULL,
		0xC3E3699ADDA5F079ULL,
		0xBE4F8B25A7494039ULL,
		0xC5BEC008EF5A539FULL,
		0x2B2B60DDC205C8C3ULL,
		0x4AC682CBC76F4754ULL,
		0x285E7A8BB68A4CAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x409AB27F15A6C726ULL,
		0x4D45136D3A1B9D04ULL,
		0x87C6D335BB4BE0F3ULL,
		0x7C9F164B4E928073ULL,
		0x8B7D8011DEB4A73FULL,
		0x5656C1BB840B9187ULL,
		0x958D05978EDE8EA8ULL,
		0x50BCF5176D149954ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x468A7C5743DDB0EFULL,
		0xF8B0AAC17C7F8F81ULL,
		0xC56044BA11EEECD9ULL,
		0x774B8566104271CAULL,
		0xD5D5D8E750B07069ULL,
		0x4BA4CB9E61B0A8D5ULL,
		0x99E50DBF9742A7DFULL,
		0x398BB638EB5FB8CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D14F8AE87BB61DEULL,
		0xF1615582F8FF1F02ULL,
		0x8AC0897423DDD9B3ULL,
		0xEE970ACC2084E395ULL,
		0xABABB1CEA160E0D2ULL,
		0x9749973CC36151ABULL,
		0x33CA1B7F2E854FBEULL,
		0x73176C71D6BF7195ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6E8F71BE9F59145ULL,
		0xA0D03B652EDFD816ULL,
		0x445CEA6F2AB15011ULL,
		0x4C5B687F455966BEULL,
		0xF6A3C6C633734194ULL,
		0x5DF4F5558CB02339ULL,
		0x7B76EF96B772A7AAULL,
		0x00075815F8A0A1FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD1EE37D3EB228AULL,
		0x41A076CA5DBFB02DULL,
		0x88B9D4DE5562A023ULL,
		0x98B6D0FE8AB2CD7CULL,
		0xED478D8C66E68328ULL,
		0xBBE9EAAB19604673ULL,
		0xF6EDDF2D6EE54F54ULL,
		0x000EB02BF14143FEULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x262300AAE507A189ULL,
		0x168CEA93759CD656ULL,
		0x3A2DF8D769E17D48ULL,
		0x1BC4066EF4821D4EULL,
		0x0F4AEC7F9220A491ULL,
		0x99FA31064A516F9EULL,
		0x32E44099B1C3CC5EULL,
		0x10716DCFD83A2720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C460155CA0F4312ULL,
		0x2D19D526EB39ACACULL,
		0x745BF1AED3C2FA90ULL,
		0x37880CDDE9043A9CULL,
		0x1E95D8FF24414922ULL,
		0x33F4620C94A2DF3CULL,
		0x65C88133638798BDULL,
		0x20E2DB9FB0744E40ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD61EB224C2E4EB5ULL,
		0x095E7F6B0CD7B1F2ULL,
		0xF122E08068853111ULL,
		0x0A40E0A00B3DE4E2ULL,
		0x3E7C14C551933757ULL,
		0x9AF2DC5D00E33377ULL,
		0x70691E2598D55826ULL,
		0x08A3767AC868222AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC3D644985C9D6AULL,
		0x12BCFED619AF63E5ULL,
		0xE245C100D10A6222ULL,
		0x1481C140167BC9C5ULL,
		0x7CF8298AA3266EAEULL,
		0x35E5B8BA01C666EEULL,
		0xE0D23C4B31AAB04DULL,
		0x1146ECF590D04454ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF99B4530A282B9CULL,
		0x0417092175C8710DULL,
		0xD2CBAFAFA9740B5BULL,
		0xED707190AC1C3D4DULL,
		0x41611A456F969A01ULL,
		0xEF0B3E104561A5F8ULL,
		0x2565A58FAE7BD0A5ULL,
		0x00644C74001958BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF3368A614505738ULL,
		0x082E1242EB90E21BULL,
		0xA5975F5F52E816B6ULL,
		0xDAE0E32158387A9BULL,
		0x82C2348ADF2D3403ULL,
		0xDE167C208AC34BF0ULL,
		0x4ACB4B1F5CF7A14BULL,
		0x00C898E80032B17AULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA50862283A789B4ULL,
		0x6DB76A3F394F1EAFULL,
		0x308F091D2B8A6A1AULL,
		0x99E5F8396D1F15B6ULL,
		0xC65FE0028A393AFDULL,
		0x4230F433F88B625CULL,
		0x80BC7C6732D6A10AULL,
		0x08DE54858C2B5017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4A10C45074F1368ULL,
		0xDB6ED47E729E3D5FULL,
		0x611E123A5714D434ULL,
		0x33CBF072DA3E2B6CULL,
		0x8CBFC005147275FBULL,
		0x8461E867F116C4B9ULL,
		0x0178F8CE65AD4214ULL,
		0x11BCA90B1856A02FULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF51BD0E91B20C66AULL,
		0x9A398F3A2E330990ULL,
		0x670BA0938D214CDAULL,
		0xA79C5C8C4151B533ULL,
		0xE50C2AD31FD660A5ULL,
		0x4B47DEC0885BF515ULL,
		0x62FA552D515B2A29ULL,
		0x281B618700E21895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA37A1D236418CD4ULL,
		0x34731E745C661321ULL,
		0xCE1741271A4299B5ULL,
		0x4F38B91882A36A66ULL,
		0xCA1855A63FACC14BULL,
		0x968FBD8110B7EA2BULL,
		0xC5F4AA5AA2B65452ULL,
		0x5036C30E01C4312AULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACCFA8CBE6060969ULL,
		0x6A8DCBE65273A918ULL,
		0xD3CF4A75058CE6E6ULL,
		0x3D4B5D19016E4B42ULL,
		0xA422625A0791D44BULL,
		0xEAD28A1F55CFEEFDULL,
		0x7484C952B5D8983AULL,
		0x1DBBE53321F8D646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x599F5197CC0C12D2ULL,
		0xD51B97CCA4E75231ULL,
		0xA79E94EA0B19CDCCULL,
		0x7A96BA3202DC9685ULL,
		0x4844C4B40F23A896ULL,
		0xD5A5143EAB9FDDFBULL,
		0xE90992A56BB13075ULL,
		0x3B77CA6643F1AC8CULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7530655AD214F136ULL,
		0x563F9C549836EB90ULL,
		0x145B11E5E8F0E5EAULL,
		0x93899EB404570D27ULL,
		0x30C9A40F928B42E2ULL,
		0xB8CF6CA566670297ULL,
		0x0F9B8E0ACD749533ULL,
		0x1B2F7AD9A775BCC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA60CAB5A429E26CULL,
		0xAC7F38A9306DD720ULL,
		0x28B623CBD1E1CBD4ULL,
		0x27133D6808AE1A4EULL,
		0x6193481F251685C5ULL,
		0x719ED94ACCCE052EULL,
		0x1F371C159AE92A67ULL,
		0x365EF5B34EEB7988ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B39B6BA86853BB7ULL,
		0xED2D506BE8685FD6ULL,
		0xB67F044AF10A465BULL,
		0x53444F9137B5F3D8ULL,
		0x0B0411FAF3244C61ULL,
		0x7D0A39CA6C88622AULL,
		0x04B832656C821712ULL,
		0x18725E89F93C6FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6736D750D0A776EULL,
		0xDA5AA0D7D0D0BFACULL,
		0x6CFE0895E2148CB7ULL,
		0xA6889F226F6BE7B1ULL,
		0x160823F5E64898C2ULL,
		0xFA147394D910C454ULL,
		0x097064CAD9042E24ULL,
		0x30E4BD13F278DF72ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58A03F49D0672A37ULL,
		0x01EFFC9318E9564AULL,
		0xA0611D1B72782871ULL,
		0xD1C16C999219A52FULL,
		0xF7721CF1D1E6EF9BULL,
		0xB73E565F512CDBFCULL,
		0x41B080B36245693BULL,
		0x2B70B17BC35F1D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1407E93A0CE546EULL,
		0x03DFF92631D2AC94ULL,
		0x40C23A36E4F050E2ULL,
		0xA382D93324334A5FULL,
		0xEEE439E3A3CDDF37ULL,
		0x6E7CACBEA259B7F9ULL,
		0x83610166C48AD277ULL,
		0x56E162F786BE3B28ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x514D7CA88950E075ULL,
		0xD15C6AF3D7F0E54FULL,
		0x4E765B9045FA3027ULL,
		0xE879B342FCBC5CF1ULL,
		0xEE4CA52C96718E1DULL,
		0xEDC14803C6A20D62ULL,
		0x42B6AE5DBE4B41F6ULL,
		0x028E0F26D784D0DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA29AF95112A1C0EAULL,
		0xA2B8D5E7AFE1CA9EULL,
		0x9CECB7208BF4604FULL,
		0xD0F36685F978B9E2ULL,
		0xDC994A592CE31C3BULL,
		0xDB8290078D441AC5ULL,
		0x856D5CBB7C9683EDULL,
		0x051C1E4DAF09A1BAULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B523BB294AA9955ULL,
		0x336C4F5CC38E12BDULL,
		0x261BBADE33E9610EULL,
		0x9951D91A21C2BCFCULL,
		0x8542A7BA01D8A0A2ULL,
		0x4597003488CFBFDCULL,
		0x581051F2107CB6E4ULL,
		0x24AAC4EB0F718DB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A47765295532AAULL,
		0x66D89EB9871C257AULL,
		0x4C3775BC67D2C21CULL,
		0x32A3B234438579F8ULL,
		0x0A854F7403B14145ULL,
		0x8B2E0069119F7FB9ULL,
		0xB020A3E420F96DC8ULL,
		0x495589D61EE31B68ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC7AE939699E5418ULL,
		0xB2B90A30D88ADD33ULL,
		0x02401C88B7423318ULL,
		0x0799BF08578D9601ULL,
		0x8CC12A92BCB66CA5ULL,
		0x7D3FEB3E46C010E6ULL,
		0x5E0EC3C2F3AB8B01ULL,
		0x353D4B868233E18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F5D272D33CA830ULL,
		0x65721461B115BA67ULL,
		0x048039116E846631ULL,
		0x0F337E10AF1B2C02ULL,
		0x19825525796CD94AULL,
		0xFA7FD67C8D8021CDULL,
		0xBC1D8785E7571602ULL,
		0x6A7A970D0467C316ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA96F4F718397255AULL,
		0x2167B31AE729635DULL,
		0x932296CF7D8D5620ULL,
		0x559D16E796F7B23BULL,
		0xCAED98DE97DB71E6ULL,
		0xB9F4A70B4D7BA38FULL,
		0x1194C7EF7F6D1BF6ULL,
		0x0473BF45029AA67BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DE9EE3072E4AB4ULL,
		0x42CF6635CE52C6BBULL,
		0x26452D9EFB1AAC40ULL,
		0xAB3A2DCF2DEF6477ULL,
		0x95DB31BD2FB6E3CCULL,
		0x73E94E169AF7471FULL,
		0x23298FDEFEDA37EDULL,
		0x08E77E8A05354CF6ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x877DDFFBFE344514ULL,
		0xF82FBAF40D3AE6A8ULL,
		0x0380362B1CE6894CULL,
		0x5C12B36506EA70D7ULL,
		0xA7A18709274FA1B1ULL,
		0x760FD7DBE6360150ULL,
		0xCCBB858E181CD310ULL,
		0x08D5B7CDC7863BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFBBFF7FC688A28ULL,
		0xF05F75E81A75CD51ULL,
		0x07006C5639CD1299ULL,
		0xB82566CA0DD4E1AEULL,
		0x4F430E124E9F4362ULL,
		0xEC1FAFB7CC6C02A1ULL,
		0x99770B1C3039A620ULL,
		0x11AB6F9B8F0C77E7ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3516601867A37ED7ULL,
		0xE61ADA31C6558363ULL,
		0xBCCA6669573CEE02ULL,
		0x6A50BDB94A1B6F11ULL,
		0x75222BC1EE75BE59ULL,
		0x4BB887EB4FD54C6CULL,
		0x544A680881582791ULL,
		0x1B5C3133679BF7BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2CC030CF46FDAEULL,
		0xCC35B4638CAB06C6ULL,
		0x7994CCD2AE79DC05ULL,
		0xD4A17B729436DE23ULL,
		0xEA445783DCEB7CB2ULL,
		0x97710FD69FAA98D8ULL,
		0xA894D01102B04F22ULL,
		0x36B86266CF37EF7CULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF40B1B8DF713B329ULL,
		0x9A6C8E96E05EA9BAULL,
		0x41F34DE4E4DFCD7AULL,
		0xC631BF3C19758B01ULL,
		0x90523D980002AD18ULL,
		0x0996C91D461E782BULL,
		0x73055F13E2419B89ULL,
		0x2EEC5397908E78BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE816371BEE276652ULL,
		0x34D91D2DC0BD5375ULL,
		0x83E69BC9C9BF9AF5ULL,
		0x8C637E7832EB1602ULL,
		0x20A47B3000055A31ULL,
		0x132D923A8C3CF057ULL,
		0xE60ABE27C4833712ULL,
		0x5DD8A72F211CF178ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC57B054F570D9D1BULL,
		0x378CBB65302BE63CULL,
		0xFF9B90E9A8A9B1A3ULL,
		0x22D404D470B9291AULL,
		0x58E5F5454F44A2F7ULL,
		0x0F60AAB31478FDE8ULL,
		0x51497B18AACF971EULL,
		0x21C76DD077489171ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AF60A9EAE1B3A36ULL,
		0x6F1976CA6057CC79ULL,
		0xFF3721D351536346ULL,
		0x45A809A8E1725235ULL,
		0xB1CBEA8A9E8945EEULL,
		0x1EC1556628F1FBD0ULL,
		0xA292F631559F2E3CULL,
		0x438EDBA0EE9122E2ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90A88CE2C45A618FULL,
		0x2BFFE451E0981E34ULL,
		0x150FAFAE02B55E0EULL,
		0x96FEEB2DD03B1144ULL,
		0x2EF1A13AAAB63307ULL,
		0x2E0E0F327BAA3A13ULL,
		0xA24E8A656C2AFC96ULL,
		0x19FF68078B9043F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x215119C588B4C31EULL,
		0x57FFC8A3C1303C69ULL,
		0x2A1F5F5C056ABC1CULL,
		0x2DFDD65BA0762288ULL,
		0x5DE34275556C660FULL,
		0x5C1C1E64F7547426ULL,
		0x449D14CAD855F92CULL,
		0x33FED00F172087E7ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93D43F132E2FDF47ULL,
		0x3DE73BEFC96716E8ULL,
		0x8D02503AD61CF938ULL,
		0x580694D20BC0871CULL,
		0x4590F86B83ECFDECULL,
		0x3BCDBDED0C0E78B3ULL,
		0x2E05BD5553EFC88AULL,
		0x3FDEDF2279E332DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A87E265C5FBE8EULL,
		0x7BCE77DF92CE2DD1ULL,
		0x1A04A075AC39F270ULL,
		0xB00D29A417810E39ULL,
		0x8B21F0D707D9FBD8ULL,
		0x779B7BDA181CF166ULL,
		0x5C0B7AAAA7DF9114ULL,
		0x7FBDBE44F3C665BAULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFDD0CF076D34817ULL,
		0xCE838E65A9C254A4ULL,
		0x3BCBAF9532C52936ULL,
		0xCDB1E21848A282E6ULL,
		0x923E5D56EA05969CULL,
		0x6981AD122D595480ULL,
		0xB389987C378D2FF6ULL,
		0x29FA0E5631E977ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FBA19E0EDA6902EULL,
		0x9D071CCB5384A949ULL,
		0x77975F2A658A526DULL,
		0x9B63C430914505CCULL,
		0x247CBAADD40B2D39ULL,
		0xD3035A245AB2A901ULL,
		0x671330F86F1A5FECULL,
		0x53F41CAC63D2EF5BULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80613CB0BBD40342ULL,
		0x5800DEFC96C1733AULL,
		0x9323FB2DE95828FAULL,
		0xC4DD607D949A12B6ULL,
		0x4092D8E229E587C8ULL,
		0x770B6F7B9A636E52ULL,
		0x72A64028975D0183ULL,
		0x0EA938F0E79F3489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00C2796177A80684ULL,
		0xB001BDF92D82E675ULL,
		0x2647F65BD2B051F4ULL,
		0x89BAC0FB2934256DULL,
		0x8125B1C453CB0F91ULL,
		0xEE16DEF734C6DCA4ULL,
		0xE54C80512EBA0306ULL,
		0x1D5271E1CF3E6912ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68D11A5CA0B1E4E8ULL,
		0x756C8272359240F0ULL,
		0xE38265C333B2B047ULL,
		0xBADCF089C2AF5967ULL,
		0x75637C0353CD2C37ULL,
		0xB691A99C6A7B87E1ULL,
		0xB94CE0E75B49BDE0ULL,
		0x2B88F974D1066FD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A234B94163C9D0ULL,
		0xEAD904E46B2481E0ULL,
		0xC704CB866765608EULL,
		0x75B9E113855EB2CFULL,
		0xEAC6F806A79A586FULL,
		0x6D235338D4F70FC2ULL,
		0x7299C1CEB6937BC1ULL,
		0x5711F2E9A20CDFA9ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x343990C3793B657AULL,
		0x571990765BFE403AULL,
		0x35D2E7417439394FULL,
		0x302706D4C4EA4362ULL,
		0xA01F2DE75A924CA5ULL,
		0x2B3A8D8DEBA3B401ULL,
		0xBAF1FDEFEC252979ULL,
		0x2C4485853D77ACA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68732186F276CAF4ULL,
		0xAE3320ECB7FC8074ULL,
		0x6BA5CE82E872729EULL,
		0x604E0DA989D486C4ULL,
		0x403E5BCEB524994AULL,
		0x56751B1BD7476803ULL,
		0x75E3FBDFD84A52F2ULL,
		0x58890B0A7AEF5953ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B2D28B3CE9917FULL,
		0x51B86CCB522169F4ULL,
		0x9D794E686BC56306ULL,
		0x04E6D674B02F1407ULL,
		0x4BC8913E9D4CD01BULL,
		0x8210418E67BBF820ULL,
		0xE3EE8D9CE871814AULL,
		0x00AFBF6C53C01EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA365A51679D322FEULL,
		0xA370D996A442D3E8ULL,
		0x3AF29CD0D78AC60CULL,
		0x09CDACE9605E280FULL,
		0x9791227D3A99A036ULL,
		0x0420831CCF77F040ULL,
		0xC7DD1B39D0E30295ULL,
		0x015F7ED8A7803DBDULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DF96F1B561B25E3ULL,
		0xA2D24A936FAC3C0AULL,
		0xB891A0CDE40A6B5AULL,
		0x11AF532F1AA061F7ULL,
		0x20C49E77D8760E89ULL,
		0x8EC726DE254BF61DULL,
		0x4B231A64521AC0D6ULL,
		0x2E4C9B1CF18A31CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BF2DE36AC364BC6ULL,
		0x45A49526DF587815ULL,
		0x7123419BC814D6B5ULL,
		0x235EA65E3540C3EFULL,
		0x41893CEFB0EC1D12ULL,
		0x1D8E4DBC4A97EC3AULL,
		0x964634C8A43581ADULL,
		0x5C993639E314639EULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF71BE124B7B8AC32ULL,
		0xDC731A20D86C9732ULL,
		0x2E9CD060306B6218ULL,
		0x16398C77ACDD306EULL,
		0xCA0B02C575329E27ULL,
		0x9FAA7CBF8203D808ULL,
		0x32B9455A6B400989ULL,
		0x3E0E3042F4883B99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE37C2496F715864ULL,
		0xB8E63441B0D92E65ULL,
		0x5D39A0C060D6C431ULL,
		0x2C7318EF59BA60DCULL,
		0x9416058AEA653C4EULL,
		0x3F54F97F0407B011ULL,
		0x65728AB4D6801313ULL,
		0x7C1C6085E9107732ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30240D601520216CULL,
		0x52B06781C031A68DULL,
		0x3389F0BE45B32717ULL,
		0x9328444E814C7A0BULL,
		0x6347FD01F2F98AEEULL,
		0xFE253C184DC8AAC7ULL,
		0xCF30C140E55B7C05ULL,
		0x380A207F3E70F835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60481AC02A4042D8ULL,
		0xA560CF0380634D1AULL,
		0x6713E17C8B664E2EULL,
		0x2650889D0298F416ULL,
		0xC68FFA03E5F315DDULL,
		0xFC4A78309B91558EULL,
		0x9E618281CAB6F80BULL,
		0x701440FE7CE1F06BULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A8865A873D0AB23ULL,
		0x51B29BBFA44681F7ULL,
		0xFABC2F43A3806F55ULL,
		0xD5477C3814A253C8ULL,
		0x94D59D753EF226BBULL,
		0x3DF82110CFD39E47ULL,
		0x8B552F7B1043D7A0ULL,
		0x1E09CB05D36E3AA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1510CB50E7A15646ULL,
		0xA365377F488D03EFULL,
		0xF5785E874700DEAAULL,
		0xAA8EF8702944A791ULL,
		0x29AB3AEA7DE44D77ULL,
		0x7BF042219FA73C8FULL,
		0x16AA5EF62087AF40ULL,
		0x3C13960BA6DC754FULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4066181E33081693ULL,
		0x0EFCD70499B89FB2ULL,
		0x2BA4A5AA321655BFULL,
		0xE93240BA61325100ULL,
		0x49DBE4CB2FC653CCULL,
		0xA3C58A4D577747D3ULL,
		0xEFDE26F0A7D4C74CULL,
		0x2030E9A98D1DD1ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80CC303C66102D26ULL,
		0x1DF9AE0933713F64ULL,
		0x57494B54642CAB7EULL,
		0xD2648174C264A200ULL,
		0x93B7C9965F8CA799ULL,
		0x478B149AAEEE8FA6ULL,
		0xDFBC4DE14FA98E99ULL,
		0x4061D3531A3BA359ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2821C74FBB2905CEULL,
		0x677EC3A2313A994CULL,
		0xC18B1D792D8D9C3DULL,
		0x29705406326290DCULL,
		0x74F972FDA7006D0DULL,
		0xB3657CCE50FE84EAULL,
		0x53361CC448FE97F9ULL,
		0x35985A7676797875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50438E9F76520B9CULL,
		0xCEFD874462753298ULL,
		0x83163AF25B1B387AULL,
		0x52E0A80C64C521B9ULL,
		0xE9F2E5FB4E00DA1AULL,
		0x66CAF99CA1FD09D4ULL,
		0xA66C398891FD2FF3ULL,
		0x6B30B4ECECF2F0EAULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78FCD8CC1B74985EULL,
		0x0B577F7707E6D18EULL,
		0xADB91E36A27545FAULL,
		0x9C23CA73CE91F084ULL,
		0x4BB03B2EF7C8B174ULL,
		0xE8DF5B613CD86DF1ULL,
		0x59CAF8AD988B25E4ULL,
		0x165E6E199F03DFC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1F9B19836E930BCULL,
		0x16AEFEEE0FCDA31CULL,
		0x5B723C6D44EA8BF4ULL,
		0x384794E79D23E109ULL,
		0x9760765DEF9162E9ULL,
		0xD1BEB6C279B0DBE2ULL,
		0xB395F15B31164BC9ULL,
		0x2CBCDC333E07BF90ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09F4465A91AB4714ULL,
		0x7FFF48F430EFF8DCULL,
		0x6C6F0D805558EBB1ULL,
		0x88DEEF8AE40528AEULL,
		0x4E0260FFC74B42BAULL,
		0xC74E2DC402A3CC06ULL,
		0xD5FBACE1FD6E4450ULL,
		0x292811EB217DF640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13E88CB523568E28ULL,
		0xFFFE91E861DFF1B8ULL,
		0xD8DE1B00AAB1D762ULL,
		0x11BDDF15C80A515CULL,
		0x9C04C1FF8E968575ULL,
		0x8E9C5B880547980CULL,
		0xABF759C3FADC88A1ULL,
		0x525023D642FBEC81ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB6F2331FD58C916ULL,
		0x0BA7180543226A4AULL,
		0x4EE99CB6086D0DC5ULL,
		0x420F8655B25F87BCULL,
		0x52CAD5E54B4D0DBDULL,
		0x4C504C8FE516FC98ULL,
		0x403F9F220005D19DULL,
		0x3A989B7E9B4D375BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96DE4663FAB1922CULL,
		0x174E300A8644D495ULL,
		0x9DD3396C10DA1B8AULL,
		0x841F0CAB64BF0F78ULL,
		0xA595ABCA969A1B7AULL,
		0x98A0991FCA2DF930ULL,
		0x807F3E44000BA33AULL,
		0x753136FD369A6EB6ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DCCC542E2D29DBEULL,
		0x592FBB7CFD08266EULL,
		0xA261B003119A8223ULL,
		0x8A5FE1D0A11A9CDEULL,
		0x9CC930EE017F113AULL,
		0x12B3752F7F4AA0E9ULL,
		0xF5D31EADEEF8B459ULL,
		0x215C2420751DF4F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B998A85C5A53B7CULL,
		0xB25F76F9FA104CDCULL,
		0x44C3600623350446ULL,
		0x14BFC3A1423539BDULL,
		0x399261DC02FE2275ULL,
		0x2566EA5EFE9541D3ULL,
		0xEBA63D5BDDF168B2ULL,
		0x42B84840EA3BE9E7ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E6E7A4E28956465ULL,
		0x00E8247159B3D774ULL,
		0x71F70381228BEB81ULL,
		0x0D919D5FA485CA41ULL,
		0x03992BAE1D2125F3ULL,
		0xE251981710AC3FEAULL,
		0x6E16C583FA857A6AULL,
		0x03374D5CFD45142CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCDCF49C512AC8CAULL,
		0x01D048E2B367AEE8ULL,
		0xE3EE07024517D702ULL,
		0x1B233ABF490B9482ULL,
		0x0732575C3A424BE6ULL,
		0xC4A3302E21587FD4ULL,
		0xDC2D8B07F50AF4D5ULL,
		0x066E9AB9FA8A2858ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BC4B070537C2C4AULL,
		0x5CFA506CBE0F2515ULL,
		0xCDB30872B659335FULL,
		0x7B5A4CA91395A44EULL,
		0x5251B907901E37A7ULL,
		0xBAFD29B589B8747CULL,
		0xDC58D66DC340693FULL,
		0x2E385316DE72786FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x778960E0A6F85894ULL,
		0xB9F4A0D97C1E4A2AULL,
		0x9B6610E56CB266BEULL,
		0xF6B49952272B489DULL,
		0xA4A3720F203C6F4EULL,
		0x75FA536B1370E8F8ULL,
		0xB8B1ACDB8680D27FULL,
		0x5C70A62DBCE4F0DFULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47053BBDB1ECD610ULL,
		0xE0D5E489769F8672ULL,
		0xB82894FA781A77FAULL,
		0xBB81DB8C43EB6A91ULL,
		0xC90579F19A7B1891ULL,
		0x9B43131FF875A40BULL,
		0x8F76DDB061079C55ULL,
		0x3ADC0A7A75E247C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E0A777B63D9AC20ULL,
		0xC1ABC912ED3F0CE4ULL,
		0x705129F4F034EFF5ULL,
		0x7703B71887D6D523ULL,
		0x920AF3E334F63123ULL,
		0x3686263FF0EB4817ULL,
		0x1EEDBB60C20F38ABULL,
		0x75B814F4EBC48F85ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45955F5E409C7D87ULL,
		0x5643024DD4435C74ULL,
		0x6FE428E8C76AB54CULL,
		0xA90B859E151549F3ULL,
		0xDFFB5BEEF34A12E4ULL,
		0x0314974A5B5BD0E0ULL,
		0xC6A9342A19D6B493ULL,
		0x286942A87B78A2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2ABEBC8138FB0EULL,
		0xAC86049BA886B8E8ULL,
		0xDFC851D18ED56A98ULL,
		0x52170B3C2A2A93E6ULL,
		0xBFF6B7DDE69425C9ULL,
		0x06292E94B6B7A1C1ULL,
		0x8D52685433AD6926ULL,
		0x50D28550F6F145D1ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9A04C9F4D88CB15ULL,
		0xFFEB7AC86ECA9B45ULL,
		0xFA28DA9FDAE95F63ULL,
		0x5521B1B4DCE245A2ULL,
		0x24729E40C9ACCDFCULL,
		0x5A2076A7CFFAC8E7ULL,
		0xDAC3069D7B9F80C4ULL,
		0x3FC0C5FD9F958623ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9340993E9B11962AULL,
		0xFFD6F590DD95368BULL,
		0xF451B53FB5D2BEC7ULL,
		0xAA436369B9C48B45ULL,
		0x48E53C8193599BF8ULL,
		0xB440ED4F9FF591CEULL,
		0xB5860D3AF73F0188ULL,
		0x7F818BFB3F2B0C47ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD623B2DC16721ADULL,
		0xD1C39F7D76D5B15AULL,
		0xA5E481E778302CC0ULL,
		0x40D0CF33696BE7A0ULL,
		0xE7A7DCB551AAF13BULL,
		0xD8B599989DDF2C7BULL,
		0x8DD79AEA91633A0FULL,
		0x3A2C1A8A75FE11C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAC4765B82CE435AULL,
		0xA3873EFAEDAB62B5ULL,
		0x4BC903CEF0605981ULL,
		0x81A19E66D2D7CF41ULL,
		0xCF4FB96AA355E276ULL,
		0xB16B33313BBE58F7ULL,
		0x1BAF35D522C6741FULL,
		0x74583514EBFC238BULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BB519BC93E244F8ULL,
		0xF7F31509550099D8ULL,
		0xA319B158063F5E82ULL,
		0x3B3910A52133D330ULL,
		0xB6EC9F8493F9818FULL,
		0x884ADAC28FC32644ULL,
		0xC36F583FCC267A06ULL,
		0x1DE5F73DA99464D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x176A337927C489F0ULL,
		0xEFE62A12AA0133B0ULL,
		0x463362B00C7EBD05ULL,
		0x7672214A4267A661ULL,
		0x6DD93F0927F3031EULL,
		0x1095B5851F864C89ULL,
		0x86DEB07F984CF40DULL,
		0x3BCBEE7B5328C9B1ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB844070ED6F94BA8ULL,
		0x60B42BB05E3FF621ULL,
		0x7E00ACC3EFCD017EULL,
		0xD1459F5F01BE4E93ULL,
		0xFA0A9A32B284484AULL,
		0xBBB643FEE4A15361ULL,
		0x353ED5283EA7814BULL,
		0x2C8BD7B57DDA110AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70880E1DADF29750ULL,
		0xC1685760BC7FEC43ULL,
		0xFC015987DF9A02FCULL,
		0xA28B3EBE037C9D26ULL,
		0xF415346565089095ULL,
		0x776C87FDC942A6C3ULL,
		0x6A7DAA507D4F0297ULL,
		0x5917AF6AFBB42214ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x837C9BDD03BDA9D3ULL,
		0x9BFEE59BBB28F0FFULL,
		0x4B0EE56EBAECE9A3ULL,
		0xFA5CD754C83C1994ULL,
		0x7F3730770589D6E2ULL,
		0x5F6A54F8417F1536ULL,
		0x94787E972A081752ULL,
		0x24A4D5E1D4CCDFA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F937BA077B53A6ULL,
		0x37FDCB377651E1FFULL,
		0x961DCADD75D9D347ULL,
		0xF4B9AEA990783328ULL,
		0xFE6E60EE0B13ADC5ULL,
		0xBED4A9F082FE2A6CULL,
		0x28F0FD2E54102EA4ULL,
		0x4949ABC3A999BF45ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D897187871F569EULL,
		0x12DFFCFAF6C802FEULL,
		0x27EB378B7C127AABULL,
		0x7B653B66F8677358ULL,
		0x12A713AC7EAE8A31ULL,
		0xE5E50A0234EA4461ULL,
		0x102491CAB47220D6ULL,
		0x24749523F978B84BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B12E30F0E3EAD3CULL,
		0x25BFF9F5ED9005FCULL,
		0x4FD66F16F824F556ULL,
		0xF6CA76CDF0CEE6B0ULL,
		0x254E2758FD5D1462ULL,
		0xCBCA140469D488C2ULL,
		0x2049239568E441ADULL,
		0x48E92A47F2F17096ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE443CF1ABC59F04ULL,
		0x36A3A1A9209918CCULL,
		0x5C4853E0B36FA1A2ULL,
		0x40E4DE49983AC249ULL,
		0x232A82E4BAE9BF82ULL,
		0x26925BCD1E1D6F20ULL,
		0xA8122BDF5409BF70ULL,
		0x3535463AD7C03894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C8879E3578B3E08ULL,
		0x6D47435241323199ULL,
		0xB890A7C166DF4344ULL,
		0x81C9BC9330758492ULL,
		0x465505C975D37F04ULL,
		0x4D24B79A3C3ADE40ULL,
		0x502457BEA8137EE0ULL,
		0x6A6A8C75AF807129ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA103C4B40921239ULL,
		0x660BB5DEB13FC712ULL,
		0x660267FEF5A23ABFULL,
		0xCA8D6F64CFCB791BULL,
		0x24F5D49554A32FA4ULL,
		0x4D07FFD7C1547923ULL,
		0x65257B2B355CC1DEULL,
		0x013D09FDE168CCE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9420789681242472ULL,
		0xCC176BBD627F8E25ULL,
		0xCC04CFFDEB44757EULL,
		0x951ADEC99F96F236ULL,
		0x49EBA92AA9465F49ULL,
		0x9A0FFFAF82A8F246ULL,
		0xCA4AF6566AB983BCULL,
		0x027A13FBC2D199D0ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6268A56355D79099ULL,
		0x5F53F8D810BB4272ULL,
		0x86D7896D30FFDC7FULL,
		0x4340DA1388174549ULL,
		0x4296124313A83BF2ULL,
		0xC65DF1299DAD57B0ULL,
		0xCA7A7771CF594EADULL,
		0x3E7F5A5DF8B1E5DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D14AC6ABAF2132ULL,
		0xBEA7F1B0217684E4ULL,
		0x0DAF12DA61FFB8FEULL,
		0x8681B427102E8A93ULL,
		0x852C2486275077E4ULL,
		0x8CBBE2533B5AAF60ULL,
		0x94F4EEE39EB29D5BULL,
		0x7CFEB4BBF163CBBBULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21B278950F7DE002ULL,
		0xE2104B70038844BCULL,
		0x010491F993AC149BULL,
		0x3F3449B029F5137EULL,
		0x55445E9B2641E8DDULL,
		0xC83DF33FFF66A556ULL,
		0x52A898B9615C5224ULL,
		0x2B1C3B6A9A8525ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4364F12A1EFBC004ULL,
		0xC42096E007108978ULL,
		0x020923F327582937ULL,
		0x7E68936053EA26FCULL,
		0xAA88BD364C83D1BAULL,
		0x907BE67FFECD4AACULL,
		0xA5513172C2B8A449ULL,
		0x563876D5350A4B5AULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x362655EDCE03B8E4ULL,
		0xBBF42451456A739FULL,
		0x3D1F5F790641BC4AULL,
		0x80B9568D8CF396D9ULL,
		0x5126D9CC83967D86ULL,
		0x43979C6C5D3D4C0DULL,
		0x835B2489F0547425ULL,
		0x1C09CECF285A90DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C4CABDB9C0771C8ULL,
		0x77E848A28AD4E73EULL,
		0x7A3EBEF20C837895ULL,
		0x0172AD1B19E72DB2ULL,
		0xA24DB399072CFB0DULL,
		0x872F38D8BA7A981AULL,
		0x06B64913E0A8E84AULL,
		0x38139D9E50B521BFULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C4F28C1F9E17604ULL,
		0x033026EA988DA52EULL,
		0x6577688D0B6531F4ULL,
		0x72A0670B7229F5FFULL,
		0xF8310990C0C270DBULL,
		0x22FB8BEA4A9A6978ULL,
		0xD42ABC2CE8A31C89ULL,
		0x0B1012009B61FBD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x389E5183F3C2EC08ULL,
		0x06604DD5311B4A5CULL,
		0xCAEED11A16CA63E8ULL,
		0xE540CE16E453EBFEULL,
		0xF06213218184E1B6ULL,
		0x45F717D49534D2F1ULL,
		0xA8557859D1463912ULL,
		0x1620240136C3F7A3ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F914DDFEC849A89ULL,
		0xDE6827DCC25F3170ULL,
		0x5A96E148562335F8ULL,
		0x3C7EF26E714A2619ULL,
		0xA051D21D63A59B01ULL,
		0x1466B8236E25FDD4ULL,
		0xB312E2D8C135F4D4ULL,
		0x040853C0453AE013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F229BBFD9093512ULL,
		0xBCD04FB984BE62E0ULL,
		0xB52DC290AC466BF1ULL,
		0x78FDE4DCE2944C32ULL,
		0x40A3A43AC74B3602ULL,
		0x28CD7046DC4BFBA9ULL,
		0x6625C5B1826BE9A8ULL,
		0x0810A7808A75C027ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF9E189F4D86C250ULL,
		0x0418B8C7B3A647F4ULL,
		0xFCE9FC1D3C62ECA9ULL,
		0xB48CD2F4B12A0F1EULL,
		0x0BBB5739E03E3225ULL,
		0x58ED935B4996A482ULL,
		0x4F9393FC4DEEAB67ULL,
		0x055B56FE938F6356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF3C313E9B0D84A0ULL,
		0x0831718F674C8FE9ULL,
		0xF9D3F83A78C5D952ULL,
		0x6919A5E962541E3DULL,
		0x1776AE73C07C644BULL,
		0xB1DB26B6932D4904ULL,
		0x9F2727F89BDD56CEULL,
		0x0AB6ADFD271EC6ACULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67BB7BE20F24F05BULL,
		0x25D37E30077FFCAAULL,
		0xCA36F38C9F005292ULL,
		0xDDA492012DC5F17AULL,
		0x84C98FCF046DFF77ULL,
		0x485037818907A2D8ULL,
		0x10682BC3E62888CFULL,
		0x22C52DFCF2434FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF76F7C41E49E0B6ULL,
		0x4BA6FC600EFFF954ULL,
		0x946DE7193E00A524ULL,
		0xBB4924025B8BE2F5ULL,
		0x09931F9E08DBFEEFULL,
		0x90A06F03120F45B1ULL,
		0x20D05787CC51119EULL,
		0x458A5BF9E4869F9CULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFEA6AC733C77F32ULL,
		0x317DE44462D30C9BULL,
		0xC2B8B203F15EBD06ULL,
		0xA213A9AA1FDA962DULL,
		0x7FB7099BC4DD82ADULL,
		0x85F043477FA23E64ULL,
		0xC4330C65E354A784ULL,
		0x02BF85E55F5B936AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD4D58E678EFE64ULL,
		0x62FBC888C5A61937ULL,
		0x85716407E2BD7A0CULL,
		0x442753543FB52C5BULL,
		0xFF6E133789BB055BULL,
		0x0BE0868EFF447CC8ULL,
		0x886618CBC6A94F09ULL,
		0x057F0BCABEB726D5ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDC7EF1468333114ULL,
		0x6124B32F4422E101ULL,
		0x629D0791A1752C89ULL,
		0x9207BC49C1FDF3D2ULL,
		0xEB9FBC4D37142CD4ULL,
		0x19E516C478DBECA8ULL,
		0xBAE4D5CBDA9D84B8ULL,
		0x1EAFA9F3E769889AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB8FDE28D0666228ULL,
		0xC249665E8845C203ULL,
		0xC53A0F2342EA5912ULL,
		0x240F789383FBE7A4ULL,
		0xD73F789A6E2859A9ULL,
		0x33CA2D88F1B7D951ULL,
		0x75C9AB97B53B0970ULL,
		0x3D5F53E7CED31135ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10E96755BB4EF87FULL,
		0x0C3825D50F976D7EULL,
		0x0A6E34AFA97AB506ULL,
		0x0B91FC33915BFCF2ULL,
		0x205AD2584CD0D980ULL,
		0x8C60D065DE1865B4ULL,
		0x9A47024934FC4EAAULL,
		0x0D685EB3D7BE67F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D2CEAB769DF0FEULL,
		0x18704BAA1F2EDAFCULL,
		0x14DC695F52F56A0CULL,
		0x1723F86722B7F9E4ULL,
		0x40B5A4B099A1B300ULL,
		0x18C1A0CBBC30CB68ULL,
		0x348E049269F89D55ULL,
		0x1AD0BD67AF7CCFEFULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81D239812B78B6DDULL,
		0xFC0AE4E6008479E1ULL,
		0xB0FD302F26EFABC6ULL,
		0xDE4D94DEBED07A50ULL,
		0x264D2C34EFB2EDCBULL,
		0x24861D267EF7F866ULL,
		0x8465A472ADC56830ULL,
		0x23C04C0FCED6F4A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A4730256F16DBAULL,
		0xF815C9CC0108F3C3ULL,
		0x61FA605E4DDF578DULL,
		0xBC9B29BD7DA0F4A1ULL,
		0x4C9A5869DF65DB97ULL,
		0x490C3A4CFDEFF0CCULL,
		0x08CB48E55B8AD060ULL,
		0x4780981F9DADE94DULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4344B1110B7EF86CULL,
		0xD5D1FCFB459DDD8DULL,
		0x5C3913B4ACD438EDULL,
		0x251CB2EAA51884A2ULL,
		0x52CE082AF9401566ULL,
		0x61608AF3E2795467ULL,
		0x83B8F6A76A2F36ADULL,
		0x215F06F3329DEBB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8689622216FDF0D8ULL,
		0xABA3F9F68B3BBB1AULL,
		0xB872276959A871DBULL,
		0x4A3965D54A310944ULL,
		0xA59C1055F2802ACCULL,
		0xC2C115E7C4F2A8CEULL,
		0x0771ED4ED45E6D5AULL,
		0x42BE0DE6653BD76FULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2A1699E350EB38AULL,
		0xA5599AE97F8735F1ULL,
		0xE18E84272758AFC5ULL,
		0x495A6C61EE4E2228ULL,
		0x0B66E9BCCC76CA0AULL,
		0x52ADE49096406CD9ULL,
		0xF596BDE91F24A761ULL,
		0x386132424D9194D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8542D33C6A1D6714ULL,
		0x4AB335D2FF0E6BE3ULL,
		0xC31D084E4EB15F8BULL,
		0x92B4D8C3DC9C4451ULL,
		0x16CDD37998ED9414ULL,
		0xA55BC9212C80D9B2ULL,
		0xEB2D7BD23E494EC2ULL,
		0x70C264849B2329ABULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BC8A453D68F4765ULL,
		0xB7070F8A34D27995ULL,
		0x7B515F0850857915ULL,
		0x05568C1A96AAA49AULL,
		0x608713644F88387FULL,
		0x709774CAF8BCD6F4ULL,
		0x21CF4B7B658B3F83ULL,
		0x1A03C07A2377EABFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x179148A7AD1E8ECAULL,
		0x6E0E1F1469A4F32BULL,
		0xF6A2BE10A10AF22BULL,
		0x0AAD18352D554934ULL,
		0xC10E26C89F1070FEULL,
		0xE12EE995F179ADE8ULL,
		0x439E96F6CB167F06ULL,
		0x340780F446EFD57EULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1806B179B0DA0329ULL,
		0x2E530DA433EFD8AFULL,
		0x964FA629E263C330ULL,
		0xE7B59186C342BD43ULL,
		0x7F4A1EA81FAA6B5FULL,
		0xC56A975B59241296ULL,
		0x6F06D6D9F2A8A15FULL,
		0x1D311166B125CA13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x300D62F361B40652ULL,
		0x5CA61B4867DFB15EULL,
		0x2C9F4C53C4C78660ULL,
		0xCF6B230D86857A87ULL,
		0xFE943D503F54D6BFULL,
		0x8AD52EB6B248252CULL,
		0xDE0DADB3E55142BFULL,
		0x3A6222CD624B9426ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3268380012FA0BBEULL,
		0x0DE6978D5AF23A26ULL,
		0x58FEAA048C6BDEF0ULL,
		0xAD6716691B3B305DULL,
		0x7C310C7296249B88ULL,
		0x1F5773A03ECEAFE6ULL,
		0xC4400765E058EEB5ULL,
		0x3721159EEBE52729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64D0700025F4177CULL,
		0x1BCD2F1AB5E4744CULL,
		0xB1FD540918D7BDE0ULL,
		0x5ACE2CD2367660BAULL,
		0xF86218E52C493711ULL,
		0x3EAEE7407D9D5FCCULL,
		0x88800ECBC0B1DD6AULL,
		0x6E422B3DD7CA4E53ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB1D1B3CB0A8DA8AULL,
		0x8996483AF5001BACULL,
		0xEA61101293CD858CULL,
		0x164846A5172E1581ULL,
		0xE678D85573EA7C22ULL,
		0x02C9D5FA3CE1099EULL,
		0x66964E705728FB3CULL,
		0x39D7C1773D2F988DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763A36796151B514ULL,
		0x132C9075EA003759ULL,
		0xD4C22025279B0B19ULL,
		0x2C908D4A2E5C2B03ULL,
		0xCCF1B0AAE7D4F844ULL,
		0x0593ABF479C2133DULL,
		0xCD2C9CE0AE51F678ULL,
		0x73AF82EE7A5F311AULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AA4DBD0FA3B72EAULL,
		0x5478604EEF870406ULL,
		0x9C0F372860923D8BULL,
		0x9176FB73F67EE11BULL,
		0x7AF8ACE5D4EBCB00ULL,
		0x7773231F4F1A9312ULL,
		0x386BEF1B4F1B890CULL,
		0x1D3F76CE2FBFA424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5549B7A1F476E5D4ULL,
		0xA8F0C09DDF0E080CULL,
		0x381E6E50C1247B16ULL,
		0x22EDF6E7ECFDC237ULL,
		0xF5F159CBA9D79601ULL,
		0xEEE6463E9E352624ULL,
		0x70D7DE369E371218ULL,
		0x3A7EED9C5F7F4848ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F67C604646D46CCULL,
		0xBB6338F1BAFEB631ULL,
		0x55B8382CCA1385D5ULL,
		0x7DDDD33B95E578CAULL,
		0x3EC9E9BD05D58A32ULL,
		0xAB19D4C2C82C9790ULL,
		0xC305D901D62A1679ULL,
		0x20693FF8EB9E6C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECF8C08C8DA8D98ULL,
		0x76C671E375FD6C63ULL,
		0xAB70705994270BABULL,
		0xFBBBA6772BCAF194ULL,
		0x7D93D37A0BAB1464ULL,
		0x5633A98590592F20ULL,
		0x860BB203AC542CF3ULL,
		0x40D27FF1D73CD92FULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB32A16977B877D40ULL,
		0xD6149600BEEFE12FULL,
		0xF8166C34CEFA2AA1ULL,
		0xE9A5C3B9B9325386ULL,
		0x7EC92D7C7EC65A7EULL,
		0xFE5FE3D47CB22573ULL,
		0x91297470D9BDEEB7ULL,
		0x0BB51A3267694849ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66542D2EF70EFA80ULL,
		0xAC292C017DDFC25FULL,
		0xF02CD8699DF45543ULL,
		0xD34B87737264A70DULL,
		0xFD925AF8FD8CB4FDULL,
		0xFCBFC7A8F9644AE6ULL,
		0x2252E8E1B37BDD6FULL,
		0x176A3464CED29093ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DE8E0753D8FEC7EULL,
		0xFED9A2BEB8E5B6FAULL,
		0xFF19048A9A43E023ULL,
		0xC735E4951E657960ULL,
		0xE7E259EA927629BCULL,
		0xBAC85506D31B9F19ULL,
		0xBB3FB468DC8FA3C0ULL,
		0x1D2EA54078C6A7AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD1C0EA7B1FD8FCULL,
		0xFDB3457D71CB6DF4ULL,
		0xFE3209153487C047ULL,
		0x8E6BC92A3CCAF2C1ULL,
		0xCFC4B3D524EC5379ULL,
		0x7590AA0DA6373E33ULL,
		0x767F68D1B91F4781ULL,
		0x3A5D4A80F18D4F55ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48884892DE1FE8D4ULL,
		0xE785FF7622A12E49ULL,
		0x904690D1CE4A51CEULL,
		0xDFAD62AD420BF862ULL,
		0x4827FE1C855F80ADULL,
		0x8A29EA0CBFEC528BULL,
		0x3F74CFE4C2149CF9ULL,
		0x0AD72513434C9423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91109125BC3FD1A8ULL,
		0xCF0BFEEC45425C92ULL,
		0x208D21A39C94A39DULL,
		0xBF5AC55A8417F0C5ULL,
		0x904FFC390ABF015BULL,
		0x1453D4197FD8A516ULL,
		0x7EE99FC9842939F3ULL,
		0x15AE4A2686992846ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67269774ED489158ULL,
		0x1490B0134A718283ULL,
		0x46B0BE8795DC0F5FULL,
		0x3FCC3801FDCAAFB9ULL,
		0x1C904CEAEF93C3F3ULL,
		0xB8BA3C5CCAF027BFULL,
		0xCC00FEE2C396920BULL,
		0x35597231C3486B46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4D2EE9DA9122B0ULL,
		0x2921602694E30506ULL,
		0x8D617D0F2BB81EBEULL,
		0x7F987003FB955F72ULL,
		0x392099D5DF2787E6ULL,
		0x717478B995E04F7EULL,
		0x9801FDC5872D2417ULL,
		0x6AB2E4638690D68DULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B7FEE64E3516956ULL,
		0xF2A8F03C3D68B521ULL,
		0x9EEFE0B0A539848DULL,
		0xAF5A060436C7A117ULL,
		0xA7D104BADECC65E6ULL,
		0xC0FBDFA0A0B4E698ULL,
		0x75B46612D8688EFBULL,
		0x03FF2B15847DFC77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56FFDCC9C6A2D2ACULL,
		0xE551E0787AD16A42ULL,
		0x3DDFC1614A73091BULL,
		0x5EB40C086D8F422FULL,
		0x4FA20975BD98CBCDULL,
		0x81F7BF414169CD31ULL,
		0xEB68CC25B0D11DF7ULL,
		0x07FE562B08FBF8EEULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE28F5C4199FC0974ULL,
		0x1287DE11AE969747ULL,
		0x86E7996E4B9651D4ULL,
		0xDC45A1910FF2F386ULL,
		0xB942B4639EA6AA8FULL,
		0x86587FBD55A248A7ULL,
		0x9FB9CFB36A7FB637ULL,
		0x2B71B596C572C610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51EB88333F812E8ULL,
		0x250FBC235D2D2E8FULL,
		0x0DCF32DC972CA3A8ULL,
		0xB88B43221FE5E70DULL,
		0x728568C73D4D551FULL,
		0x0CB0FF7AAB44914FULL,
		0x3F739F66D4FF6C6FULL,
		0x56E36B2D8AE58C21ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0A5E2FB8B2A57D4ULL,
		0xD8A8EBBF1761A251ULL,
		0x9BD78203D61312C2ULL,
		0x7631D8635194F648ULL,
		0x3D06950BDDB926BFULL,
		0xA3D85B47B74AFD72ULL,
		0x0BE786C497629797ULL,
		0x160C7F59B891EFFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC14BC5F71654AFA8ULL,
		0xB151D77E2EC344A3ULL,
		0x37AF0407AC262585ULL,
		0xEC63B0C6A329EC91ULL,
		0x7A0D2A17BB724D7EULL,
		0x47B0B68F6E95FAE4ULL,
		0x17CF0D892EC52F2FULL,
		0x2C18FEB37123DFFCULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x508563EE65EF5323ULL,
		0x49E50B9B031C810EULL,
		0x8E09A29713D7954EULL,
		0x1C7E50FE0B972139ULL,
		0x978ADA4D84DF639DULL,
		0x5241F3B46EF39D8AULL,
		0x02C1D0236CB4E0ADULL,
		0x187AF2AEB148F106ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10AC7DCCBDEA646ULL,
		0x93CA17360639021CULL,
		0x1C13452E27AF2A9CULL,
		0x38FCA1FC172E4273ULL,
		0x2F15B49B09BEC73AULL,
		0xA483E768DDE73B15ULL,
		0x0583A046D969C15AULL,
		0x30F5E55D6291E20CULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96F40680EA1ED9A1ULL,
		0x41BD2EB136A0DE24ULL,
		0x11A8D97BE2139992ULL,
		0x4379E07737B9CC78ULL,
		0x10411DC9260058B1ULL,
		0x3ABA979646A9992DULL,
		0x8D96F609BFE09F77ULL,
		0x00848FDB67A0DBE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE80D01D43DB342ULL,
		0x837A5D626D41BC49ULL,
		0x2351B2F7C4273324ULL,
		0x86F3C0EE6F7398F0ULL,
		0x20823B924C00B162ULL,
		0x75752F2C8D53325AULL,
		0x1B2DEC137FC13EEEULL,
		0x01091FB6CF41B7C9ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE88F788A36271181ULL,
		0xE7DC89CCD4398C85ULL,
		0xE46D35DAEC8F811DULL,
		0xA74366E19E3B3541ULL,
		0x15CAA768942934B9ULL,
		0x4279091C361CB3A0ULL,
		0x8BEB5D1C360A0085ULL,
		0x14E8C668DF1218B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD11EF1146C4E2302ULL,
		0xCFB91399A873190BULL,
		0xC8DA6BB5D91F023BULL,
		0x4E86CDC33C766A83ULL,
		0x2B954ED128526973ULL,
		0x84F212386C396740ULL,
		0x17D6BA386C14010AULL,
		0x29D18CD1BE24316BULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E7A8827B314BCAAULL,
		0x4C5055EAE93674F2ULL,
		0xC35A4CF03B625B3AULL,
		0x23129EA0E51F0E05ULL,
		0xF766C3C15C5262F7ULL,
		0x210A714939B02D32ULL,
		0x2C4E7FD284BEA16EULL,
		0x1B0F24DF58F20693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CF5104F66297954ULL,
		0x98A0ABD5D26CE9E5ULL,
		0x86B499E076C4B674ULL,
		0x46253D41CA3E1C0BULL,
		0xEECD8782B8A4C5EEULL,
		0x4214E29273605A65ULL,
		0x589CFFA5097D42DCULL,
		0x361E49BEB1E40D26ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE257C8F737C4B059ULL,
		0x93C8B5996097729AULL,
		0xBFE582CE35F3454FULL,
		0xB1AF978F2984C2D0ULL,
		0x86E90A22480A8A80ULL,
		0x3ED00F9FE5837050ULL,
		0x9C327231498BC420ULL,
		0x3B22E10BBCF48ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4AF91EE6F8960B2ULL,
		0x27916B32C12EE535ULL,
		0x7FCB059C6BE68A9FULL,
		0x635F2F1E530985A1ULL,
		0x0DD2144490151501ULL,
		0x7DA01F3FCB06E0A1ULL,
		0x3864E46293178840ULL,
		0x7645C21779E91DB3ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A1801B2BBAE8ECCULL,
		0x2771A514C0E93761ULL,
		0x5C12352E710A4F38ULL,
		0xD484FFCC95626A3FULL,
		0x41B2006DCD0CE88FULL,
		0x6BDE031C59B005DCULL,
		0xCF1EC7398A00218DULL,
		0x10075FCD7FE26D68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4300365775D1D98ULL,
		0x4EE34A2981D26EC2ULL,
		0xB8246A5CE2149E70ULL,
		0xA909FF992AC4D47EULL,
		0x836400DB9A19D11FULL,
		0xD7BC0638B3600BB8ULL,
		0x9E3D8E731400431AULL,
		0x200EBF9AFFC4DAD1ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD39E549BDE47E9EAULL,
		0x35DBAF8EDA309105ULL,
		0x4412DEBEEC557A4EULL,
		0x2CFD6FCF02F7CD9EULL,
		0xAC81B21510DE8EDBULL,
		0x2A24EE6CD31FB758ULL,
		0x4FBA49E155E56A79ULL,
		0x0B7733730D10D4C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA73CA937BC8FD3D4ULL,
		0x6BB75F1DB461220BULL,
		0x8825BD7DD8AAF49CULL,
		0x59FADF9E05EF9B3CULL,
		0x5903642A21BD1DB6ULL,
		0x5449DCD9A63F6EB1ULL,
		0x9F7493C2ABCAD4F2ULL,
		0x16EE66E61A21A986ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x130830FE6EC90B9AULL,
		0x4D13BE233FF2594DULL,
		0x2A5EA1F4D0F1A72EULL,
		0xF13A8BA9C5DA2506ULL,
		0x9A66B489BF1D0929ULL,
		0x6D1E1BCFC49155D5ULL,
		0xD7D0F0FC354267A5ULL,
		0x1F659F4D4CAF9EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261061FCDD921734ULL,
		0x9A277C467FE4B29AULL,
		0x54BD43E9A1E34E5CULL,
		0xE27517538BB44A0CULL,
		0x34CD69137E3A1253ULL,
		0xDA3C379F8922ABABULL,
		0xAFA1E1F86A84CF4AULL,
		0x3ECB3E9A995F3DD3ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E200A05C8C3C60CULL,
		0x474A6EC9E2AB075AULL,
		0x73959E585E0714A6ULL,
		0xC579DD582B1803C9ULL,
		0x7837E590E61FA9DAULL,
		0x13F7F62D20208F19ULL,
		0x3779BC3FA39E1D06ULL,
		0x033A76C3750ACA59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC40140B91878C18ULL,
		0x8E94DD93C5560EB4ULL,
		0xE72B3CB0BC0E294CULL,
		0x8AF3BAB056300792ULL,
		0xF06FCB21CC3F53B5ULL,
		0x27EFEC5A40411E32ULL,
		0x6EF3787F473C3A0CULL,
		0x0674ED86EA1594B2ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB47DD6DE42EB971CULL,
		0x59C23BE62E6B6E4CULL,
		0xC14692F4439678C3ULL,
		0x921918536CF9F988ULL,
		0x1A2C149F162B4A17ULL,
		0xEF65E0CB6A5FF389ULL,
		0x8D942F1D72299D1BULL,
		0x3262212E017FCC40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68FBADBC85D72E38ULL,
		0xB38477CC5CD6DC99ULL,
		0x828D25E8872CF186ULL,
		0x243230A6D9F3F311ULL,
		0x3458293E2C56942FULL,
		0xDECBC196D4BFE712ULL,
		0x1B285E3AE4533A37ULL,
		0x64C4425C02FF9881ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC2BF95C33816EEBULL,
		0x38B0DF315D0F91F6ULL,
		0xE45FAAA15FDAEF7AULL,
		0xA6C8F89E7BD8A197ULL,
		0xB5E6389696EDB51BULL,
		0x23CF53C83F6ADD55ULL,
		0xE6794AD7AFC27A1FULL,
		0x22F9B4B9DD30D4CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9857F2B86702DDD6ULL,
		0x7161BE62BA1F23EDULL,
		0xC8BF5542BFB5DEF4ULL,
		0x4D91F13CF7B1432FULL,
		0x6BCC712D2DDB6A37ULL,
		0x479EA7907ED5BAABULL,
		0xCCF295AF5F84F43EULL,
		0x45F36973BA61A995ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76EB2392D520A71AULL,
		0xFBC700C643861B3FULL,
		0x59033A919B3FDC8DULL,
		0xF7F6C1EB1EECB015ULL,
		0x8B25E6B5F50E6396ULL,
		0x4D315DE95F04FE2EULL,
		0x305F9D10083C7B6CULL,
		0x1148D62BC9FE1ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD64725AA414E34ULL,
		0xF78E018C870C367EULL,
		0xB2067523367FB91BULL,
		0xEFED83D63DD9602AULL,
		0x164BCD6BEA1CC72DULL,
		0x9A62BBD2BE09FC5DULL,
		0x60BF3A201078F6D8ULL,
		0x2291AC5793FC3D9CULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA94577D77648A503ULL,
		0x59C86F5286C9987FULL,
		0x95C124A679C68D65ULL,
		0x7F74E0AA6125E893ULL,
		0xC30FB9829B00CD8AULL,
		0x1312EFE67401584BULL,
		0xBD5224429C8814A0ULL,
		0x3A834B77FE95B7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528AEFAEEC914A06ULL,
		0xB390DEA50D9330FFULL,
		0x2B82494CF38D1ACAULL,
		0xFEE9C154C24BD127ULL,
		0x861F730536019B14ULL,
		0x2625DFCCE802B097ULL,
		0x7AA4488539102940ULL,
		0x750696EFFD2B6FC7ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14BA444C8A83C841ULL,
		0xE07A6069EEDC7019ULL,
		0xA3F36DD35ACFF944ULL,
		0x0B5EAB542452A120ULL,
		0x5D3E59CFDFF27EB0ULL,
		0x20CC0ED6435A18E6ULL,
		0x5A93A2F59B5D12E3ULL,
		0x0795B10F3B6EB62FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2974889915079082ULL,
		0xC0F4C0D3DDB8E032ULL,
		0x47E6DBA6B59FF289ULL,
		0x16BD56A848A54241ULL,
		0xBA7CB39FBFE4FD60ULL,
		0x41981DAC86B431CCULL,
		0xB52745EB36BA25C6ULL,
		0x0F2B621E76DD6C5EULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2000FE759C828721ULL,
		0xAD3D652FB58B57BBULL,
		0xDF2B8F0B9C8CA179ULL,
		0x25D6192830E5DEECULL,
		0xB3EF43A0635E19EEULL,
		0x44A09F320B5CF9AEULL,
		0x03B0465CBFA8B28CULL,
		0x06A06D36AAB3765AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4001FCEB39050E42ULL,
		0x5A7ACA5F6B16AF76ULL,
		0xBE571E17391942F3ULL,
		0x4BAC325061CBBDD9ULL,
		0x67DE8740C6BC33DCULL,
		0x89413E6416B9F35DULL,
		0x07608CB97F516518ULL,
		0x0D40DA6D5566ECB4ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FD337CB3FDE3F1FULL,
		0x73FF80FD85B50AB3ULL,
		0x2AC78FC698A6A08BULL,
		0x1F1AF0A18B91AFABULL,
		0xDFE2DE06273F2615ULL,
		0x5A3C6FA60DA7E08DULL,
		0x9E0EF2200839AC38ULL,
		0x13C1C69CEF247C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA66F967FBC7E3EULL,
		0xE7FF01FB0B6A1566ULL,
		0x558F1F8D314D4116ULL,
		0x3E35E14317235F56ULL,
		0xBFC5BC0C4E7E4C2AULL,
		0xB478DF4C1B4FC11BULL,
		0x3C1DE44010735870ULL,
		0x27838D39DE48F8D7ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3348BB5119D0E538ULL,
		0x0B84EE3F89CB070AULL,
		0xDE0A07F32F9085A5ULL,
		0xE9816DA289693239ULL,
		0x1D915DC45FDF30B1ULL,
		0xFED0B517F40433D3ULL,
		0xE719DC6CE0A34268ULL,
		0x2031F02AC8DA9B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669176A233A1CA70ULL,
		0x1709DC7F13960E14ULL,
		0xBC140FE65F210B4AULL,
		0xD302DB4512D26473ULL,
		0x3B22BB88BFBE6163ULL,
		0xFDA16A2FE80867A6ULL,
		0xCE33B8D9C14684D1ULL,
		0x4063E05591B536EBULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA943095BBA65D2A2ULL,
		0xDC892B759A41E733ULL,
		0xFFDE89E483A0A9E7ULL,
		0x4A372BD2C856A35AULL,
		0xBEB70BC827CF7DD8ULL,
		0xFEDCAC5856CF91CAULL,
		0x9617DE7C42CF59ECULL,
		0x3AD39AC01D50BB1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528612B774CBA544ULL,
		0xB91256EB3483CE67ULL,
		0xFFBD13C9074153CFULL,
		0x946E57A590AD46B5ULL,
		0x7D6E17904F9EFBB0ULL,
		0xFDB958B0AD9F2395ULL,
		0x2C2FBCF8859EB3D9ULL,
		0x75A735803AA17635ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEA67FC8B50D163EULL,
		0x6BFE4F86E5A568F3ULL,
		0x5C87393438427621ULL,
		0x3EB99F4115466B58ULL,
		0x9886AC2394C5772DULL,
		0x3552CCD89A66D284ULL,
		0xCFF99454A284C735ULL,
		0x1772824CE61C9E3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4CFF916A1A2C7CULL,
		0xD7FC9F0DCB4AD1E7ULL,
		0xB90E72687084EC42ULL,
		0x7D733E822A8CD6B0ULL,
		0x310D5847298AEE5AULL,
		0x6AA599B134CDA509ULL,
		0x9FF328A945098E6AULL,
		0x2EE50499CC393C7BULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x617BEF09707EF924ULL,
		0xC07AFE10E664B97FULL,
		0x67FE16289034EEB0ULL,
		0x300FB94FEB839C9CULL,
		0x43659BB25C71FF08ULL,
		0x64BE3E48201E4029ULL,
		0x3FDB2520EDA068C5ULL,
		0x16A10A7177F6F685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F7DE12E0FDF248ULL,
		0x80F5FC21CCC972FEULL,
		0xCFFC2C512069DD61ULL,
		0x601F729FD7073938ULL,
		0x86CB3764B8E3FE10ULL,
		0xC97C7C90403C8052ULL,
		0x7FB64A41DB40D18AULL,
		0x2D4214E2EFEDED0AULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F52D693F76E86FBULL,
		0x5B54FC46AB524060ULL,
		0x44867FCCA7C3019AULL,
		0xA06FD40DC3331B23ULL,
		0x3A08672E740C4402ULL,
		0xA7D54DB8634961FFULL,
		0xFF2F530AAA025541ULL,
		0x0D795DAF63446BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA5AD27EEDD0DF6ULL,
		0xB6A9F88D56A480C0ULL,
		0x890CFF994F860334ULL,
		0x40DFA81B86663646ULL,
		0x7410CE5CE8188805ULL,
		0x4FAA9B70C692C3FEULL,
		0xFE5EA6155404AA83ULL,
		0x1AF2BB5EC688D7D3ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A3E5805936D7EEFULL,
		0x714EBB1105B21EACULL,
		0x558A3E0C3C9E2C49ULL,
		0xDEF0052F5F8246E3ULL,
		0xE672F12375D6888AULL,
		0x62B117C4C172D7ECULL,
		0xFD92067C216ABB73ULL,
		0x1F990DCE36BB2957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x147CB00B26DAFDDEULL,
		0xE29D76220B643D58ULL,
		0xAB147C18793C5892ULL,
		0xBDE00A5EBF048DC6ULL,
		0xCCE5E246EBAD1115ULL,
		0xC5622F8982E5AFD9ULL,
		0xFB240CF842D576E6ULL,
		0x3F321B9C6D7652AFULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A05E5877AED13C4ULL,
		0xA2D0C724EEEE5E45ULL,
		0x03122F2FBC05F1DFULL,
		0x13FF9ACB39424EA9ULL,
		0xD44819846F43E5CAULL,
		0xF7CB1C6C606CF0E3ULL,
		0x5D63BD45B3A07119ULL,
		0x1571E2C6655E1994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740BCB0EF5DA2788ULL,
		0x45A18E49DDDCBC8AULL,
		0x06245E5F780BE3BFULL,
		0x27FF359672849D52ULL,
		0xA8903308DE87CB94ULL,
		0xEF9638D8C0D9E1C7ULL,
		0xBAC77A8B6740E233ULL,
		0x2AE3C58CCABC3328ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57628E235C3FF754ULL,
		0x87214A101D6FCB9DULL,
		0x8D22156C7E056E48ULL,
		0x9A31D93004DD8C47ULL,
		0x5BC1862285968D9AULL,
		0x69C9840FB914EC1AULL,
		0xEAD8D4E1E66E91FAULL,
		0x0AD23EB6D7803ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC51C46B87FEEA8ULL,
		0x0E4294203ADF973AULL,
		0x1A442AD8FC0ADC91ULL,
		0x3463B26009BB188FULL,
		0xB7830C450B2D1B35ULL,
		0xD393081F7229D834ULL,
		0xD5B1A9C3CCDD23F4ULL,
		0x15A47D6DAF00759BULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAFB38544D2E3FD3ULL,
		0x0DDF1C9013331712ULL,
		0x3A98A7E1CFDC8235ULL,
		0x9A3D86182BA21A2AULL,
		0x58D203694A968B1FULL,
		0x15AEDF116DAF5E9BULL,
		0x1B1063C3138D9F21ULL,
		0x06963345D19083DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F670A89A5C7FA6ULL,
		0x1BBE392026662E25ULL,
		0x75314FC39FB9046AULL,
		0x347B0C3057443454ULL,
		0xB1A406D2952D163FULL,
		0x2B5DBE22DB5EBD36ULL,
		0x3620C786271B3E42ULL,
		0x0D2C668BA32107BEULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12E2A37F0EE944A1ULL,
		0x9AF8C3258E9892EDULL,
		0x51475F923810AA47ULL,
		0x6F742D9DAC32D2A9ULL,
		0x475127D74084E54BULL,
		0xDA13C54CBC5BD294ULL,
		0x89C044071BE0768BULL,
		0x060348B2F344A7C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C546FE1DD28942ULL,
		0x35F1864B1D3125DAULL,
		0xA28EBF247021548FULL,
		0xDEE85B3B5865A552ULL,
		0x8EA24FAE8109CA96ULL,
		0xB4278A9978B7A528ULL,
		0x1380880E37C0ED17ULL,
		0x0C069165E6894F93ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71B8D7868F2C2C95ULL,
		0x988AB060A0EF1571ULL,
		0xEF308E99EBC0B298ULL,
		0xD8BA20FD180F9D0DULL,
		0xA6BA6C908919D772ULL,
		0xB9654E23BE53A81DULL,
		0xDCD54E86CFEF8E77ULL,
		0x21A96D4B2268E3C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE371AF0D1E58592AULL,
		0x311560C141DE2AE2ULL,
		0xDE611D33D7816531ULL,
		0xB17441FA301F3A1BULL,
		0x4D74D9211233AEE5ULL,
		0x72CA9C477CA7503BULL,
		0xB9AA9D0D9FDF1CEFULL,
		0x4352DA9644D1C789ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5240B6B597FD2955ULL,
		0x7DA7B515D33F79C0ULL,
		0x68B3538B7949F26DULL,
		0xE43238A854DAA1B4ULL,
		0x12A5BB32190DCA18ULL,
		0xA536A6F23353D617ULL,
		0x89B4CDF0279CB0A2ULL,
		0x08689EF7F11BEBBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4816D6B2FFA52AAULL,
		0xFB4F6A2BA67EF380ULL,
		0xD166A716F293E4DAULL,
		0xC8647150A9B54368ULL,
		0x254B7664321B9431ULL,
		0x4A6D4DE466A7AC2EULL,
		0x13699BE04F396145ULL,
		0x10D13DEFE237D77DULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x667646ED48DB98AAULL,
		0x52EAE787D730811EULL,
		0x26F2ECECAF167A24ULL,
		0x9DA4DE73C500ADB8ULL,
		0xFA3789320A7E6E61ULL,
		0x3BB5B90C6DF08C5BULL,
		0xE80FEEDB83DA69D7ULL,
		0x24DACFE918FEEC89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCEC8DDA91B73154ULL,
		0xA5D5CF0FAE61023CULL,
		0x4DE5D9D95E2CF448ULL,
		0x3B49BCE78A015B70ULL,
		0xF46F126414FCDCC3ULL,
		0x776B7218DBE118B7ULL,
		0xD01FDDB707B4D3AEULL,
		0x49B59FD231FDD913ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D95ACAC6E5A9B1BULL,
		0x044D9C84098DB0F7ULL,
		0xC2EA03C1780656B2ULL,
		0xB0FFAEF15E9EC7FEULL,
		0x93900378503C6414ULL,
		0xCBE457D8C9D9AAFCULL,
		0x547699D3851CB613ULL,
		0x258838710AD61010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B2B5958DCB53636ULL,
		0x089B3908131B61EEULL,
		0x85D40782F00CAD64ULL,
		0x61FF5DE2BD3D8FFDULL,
		0x272006F0A078C829ULL,
		0x97C8AFB193B355F9ULL,
		0xA8ED33A70A396C27ULL,
		0x4B1070E215AC2020ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x529B407ECBEF26EDULL,
		0x96709DC739B0BC3CULL,
		0x1CE0B84B0100C25FULL,
		0x0D137E98E6CCF37AULL,
		0x88E692797402409CULL,
		0x2080D28355DACD15ULL,
		0xEE86671FEB0CF0A3ULL,
		0x3A38AE947D40A239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53680FD97DE4DDAULL,
		0x2CE13B8E73617878ULL,
		0x39C17096020184BFULL,
		0x1A26FD31CD99E6F4ULL,
		0x11CD24F2E8048138ULL,
		0x4101A506ABB59A2BULL,
		0xDD0CCE3FD619E146ULL,
		0x74715D28FA814473ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAE12B752CA09C65ULL,
		0xC54FB7C908E641F7ULL,
		0x26C52A0BDA4A86F1ULL,
		0xC3A6D8CCE954D124ULL,
		0x140C82412FDB6F22ULL,
		0x7A36279F38171C11ULL,
		0xBA9C9DE63F3FAF4AULL,
		0x152F2978A7C34053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5C256EA594138CAULL,
		0x8A9F6F9211CC83EFULL,
		0x4D8A5417B4950DE3ULL,
		0x874DB199D2A9A248ULL,
		0x281904825FB6DE45ULL,
		0xF46C4F3E702E3822ULL,
		0x75393BCC7E7F5E94ULL,
		0x2A5E52F14F8680A7ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC3790400915D1D2ULL,
		0x9E30A0F7B94D6F01ULL,
		0x9BD6390AEBBEAA9FULL,
		0x854FFF0C7F22C259ULL,
		0x6BC05C1626928F56ULL,
		0xB31DA6B777E386BFULL,
		0xE139F51385460FCEULL,
		0x0F9C6863F8F246C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD86F2080122BA3A4ULL,
		0x3C6141EF729ADE03ULL,
		0x37AC7215D77D553FULL,
		0x0A9FFE18FE4584B3ULL,
		0xD780B82C4D251EADULL,
		0x663B4D6EEFC70D7EULL,
		0xC273EA270A8C1F9DULL,
		0x1F38D0C7F1E48D8DULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF424461267F17558ULL,
		0x571CCA2C12849467ULL,
		0xFA601D42C463DFA0ULL,
		0x950254649FDC5755ULL,
		0x885ED10DA44CC704ULL,
		0x6DF621D8EADB0A69ULL,
		0xB1BB7C4D32A69618ULL,
		0x0E1271B51E584DA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8488C24CFE2EAB0ULL,
		0xAE399458250928CFULL,
		0xF4C03A8588C7BF40ULL,
		0x2A04A8C93FB8AEABULL,
		0x10BDA21B48998E09ULL,
		0xDBEC43B1D5B614D3ULL,
		0x6376F89A654D2C30ULL,
		0x1C24E36A3CB09B4FULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74867D691AB12D22ULL,
		0xEB497095AE1BF268ULL,
		0xCFDD953314E9BE1DULL,
		0x43B094FB8DD332C4ULL,
		0xBCD36663BE32922BULL,
		0x6AB6DDDBE2300159ULL,
		0x0DFB042BA59E0C97ULL,
		0x20B102BD0BB2D825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE90CFAD235625A44ULL,
		0xD692E12B5C37E4D0ULL,
		0x9FBB2A6629D37C3BULL,
		0x876129F71BA66589ULL,
		0x79A6CCC77C652456ULL,
		0xD56DBBB7C46002B3ULL,
		0x1BF608574B3C192EULL,
		0x4162057A1765B04AULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17099B3563A4EB7FULL,
		0xC4897602EB4FA304ULL,
		0x0C00912C471C7418ULL,
		0xD6B0CF090FDCC3CCULL,
		0x4CA2286AB7A952E3ULL,
		0x7C5337550E6924B0ULL,
		0x696E60682F30DD02ULL,
		0x39AA90B0CFDB7298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E13366AC749D6FEULL,
		0x8912EC05D69F4608ULL,
		0x180122588E38E831ULL,
		0xAD619E121FB98798ULL,
		0x994450D56F52A5C7ULL,
		0xF8A66EAA1CD24960ULL,
		0xD2DCC0D05E61BA04ULL,
		0x735521619FB6E530ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86EEB1F6886630D5ULL,
		0x61A4467EC6775AF5ULL,
		0x41C95F16939A4CA5ULL,
		0xD866F4ADAA147235ULL,
		0xD790CA4EA4B9C1E2ULL,
		0x047DBB3575DAC444ULL,
		0xC9686C1619DD6A9EULL,
		0x3FA6F01623F8C37CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DDD63ED10CC61AAULL,
		0xC3488CFD8CEEB5EBULL,
		0x8392BE2D2734994AULL,
		0xB0CDE95B5428E46AULL,
		0xAF21949D497383C5ULL,
		0x08FB766AEBB58889ULL,
		0x92D0D82C33BAD53CULL,
		0x7F4DE02C47F186F9ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2C74E83175BF073ULL,
		0xF2E744731E0A58B3ULL,
		0xE3FD45CDD0D66665ULL,
		0xE92291DB6E1B9B1EULL,
		0x7E603886BCEAAD8EULL,
		0x83A4A70B25C02450ULL,
		0xC28B0D12043250B0ULL,
		0x270BBC191290AC4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x458E9D062EB7E0E6ULL,
		0xE5CE88E63C14B167ULL,
		0xC7FA8B9BA1ACCCCBULL,
		0xD24523B6DC37363DULL,
		0xFCC0710D79D55B1DULL,
		0x07494E164B8048A0ULL,
		0x85161A240864A161ULL,
		0x4E1778322521589BULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BAF4B0B96C4120FULL,
		0x02E6EE029E94296EULL,
		0x1B479810A2CDD5A2ULL,
		0x9F2C4AA19D9E83B7ULL,
		0x66874933116E25F0ULL,
		0x92DED5EA897A2218ULL,
		0xE4343DD94D9CE964ULL,
		0x3A3B0435B15B8E50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x175E96172D88241EULL,
		0x05CDDC053D2852DCULL,
		0x368F3021459BAB44ULL,
		0x3E5895433B3D076EULL,
		0xCD0E926622DC4BE1ULL,
		0x25BDABD512F44430ULL,
		0xC8687BB29B39D2C9ULL,
		0x7476086B62B71CA1ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A1EAD9855239A68ULL,
		0x9B593099E847D0ABULL,
		0xC779B132CB44E595ULL,
		0xEE9F163111E84718ULL,
		0x7531FF3B8EC68B2CULL,
		0x1CD4EF9F52F24D27ULL,
		0xCFC8F5DA28F205FFULL,
		0x24C59B2988E9FD9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543D5B30AA4734D0ULL,
		0x36B26133D08FA156ULL,
		0x8EF362659689CB2BULL,
		0xDD3E2C6223D08E31ULL,
		0xEA63FE771D8D1659ULL,
		0x39A9DF3EA5E49A4EULL,
		0x9F91EBB451E40BFEULL,
		0x498B365311D3FB37ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x718A5AF5BAAF3402ULL,
		0x54C88F676BAC94CDULL,
		0x65E17430CE42F2B0ULL,
		0xB05335EDDCB18433ULL,
		0xD287BF658B3E4F36ULL,
		0x233771371BDEC5F1ULL,
		0x98BAC1A158C860BAULL,
		0x3A7A772EB619DF80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE314B5EB755E6804ULL,
		0xA9911ECED759299AULL,
		0xCBC2E8619C85E560ULL,
		0x60A66BDBB9630866ULL,
		0xA50F7ECB167C9E6DULL,
		0x466EE26E37BD8BE3ULL,
		0x31758342B190C174ULL,
		0x74F4EE5D6C33BF01ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EA981B82C22DBAFULL,
		0x16CA0CCE2937EA14ULL,
		0x01CBD5DAEE5C0F92ULL,
		0x433138EA3517B9A8ULL,
		0x85A7E3380125C92AULL,
		0x65D3B26CDEE30F14ULL,
		0xB9449F6A9E2C8B2AULL,
		0x233C0FB1607D6144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D5303705845B75EULL,
		0x2D94199C526FD429ULL,
		0x0397ABB5DCB81F24ULL,
		0x866271D46A2F7350ULL,
		0x0B4FC670024B9254ULL,
		0xCBA764D9BDC61E29ULL,
		0x72893ED53C591654ULL,
		0x46781F62C0FAC289ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEE01796E007CE00ULL,
		0xE98AE28F5EE77AF2ULL,
		0x807F5FEC48007AE3ULL,
		0x4F58F54F0BCAA3FDULL,
		0x7E9DC770D0F7AA61ULL,
		0x7D06D69671E3B927ULL,
		0xFEF77C440737491BULL,
		0x13EF6E5403DDCFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC02F2DC00F9C00ULL,
		0xD315C51EBDCEF5E5ULL,
		0x00FEBFD89000F5C7ULL,
		0x9EB1EA9E179547FBULL,
		0xFD3B8EE1A1EF54C2ULL,
		0xFA0DAD2CE3C7724EULL,
		0xFDEEF8880E6E9236ULL,
		0x27DEDCA807BB9FDFULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFD5B095224BE9B2ULL,
		0x4BFACFE325FF2275ULL,
		0xE3C637346487D4FAULL,
		0xC9D916042E0932E7ULL,
		0x2356E55D97373233ULL,
		0x2C0980B838C7A42AULL,
		0x34B2BC54D093812FULL,
		0x2BEB44091112DFA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFAB612A4497D364ULL,
		0x97F59FC64BFE44EBULL,
		0xC78C6E68C90FA9F4ULL,
		0x93B22C085C1265CFULL,
		0x46ADCABB2E6E6467ULL,
		0x58130170718F4854ULL,
		0x696578A9A127025EULL,
		0x57D688122225BF46ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7FED03732EA17A7ULL,
		0x4AB673867F1DE8A7ULL,
		0x665D20FDB7526099ULL,
		0xCA8DEC5A8DB63249ULL,
		0x02B77AF5403E5275ULL,
		0xAA8CC2B0171E2C2EULL,
		0x768FD888113B26B8ULL,
		0x3D57BC60440FE571ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFDA06E65D42F4EULL,
		0x956CE70CFE3BD14FULL,
		0xCCBA41FB6EA4C132ULL,
		0x951BD8B51B6C6492ULL,
		0x056EF5EA807CA4EBULL,
		0x551985602E3C585CULL,
		0xED1FB11022764D71ULL,
		0x7AAF78C0881FCAE2ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6950B4B951D465F5ULL,
		0x70CE5F1335936073ULL,
		0x11E81CACEC2E219BULL,
		0x61210114001508E7ULL,
		0x7416727B97B2A78CULL,
		0xAF33B09855A5967EULL,
		0x18C63E26E71AB243ULL,
		0x09713F2ABE94596AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2A16972A3A8CBEAULL,
		0xE19CBE266B26C0E6ULL,
		0x23D03959D85C4336ULL,
		0xC2420228002A11CEULL,
		0xE82CE4F72F654F18ULL,
		0x5E676130AB4B2CFCULL,
		0x318C7C4DCE356487ULL,
		0x12E27E557D28B2D4ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD411AEF67A1DBAD8ULL,
		0xAB96A132D1C62BCDULL,
		0x7DBB9D4D777D4EAAULL,
		0x9EDEC87950649151ULL,
		0xDD5E44FE39D689CBULL,
		0x298CA4ABDFE71CABULL,
		0x2B6627FF9F8F96C8ULL,
		0x35014E72E48563F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8235DECF43B75B0ULL,
		0x572D4265A38C579BULL,
		0xFB773A9AEEFA9D55ULL,
		0x3DBD90F2A0C922A2ULL,
		0xBABC89FC73AD1397ULL,
		0x53194957BFCE3957ULL,
		0x56CC4FFF3F1F2D90ULL,
		0x6A029CE5C90AC7E2ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7811850686957637ULL,
		0x15BC54D14D853376ULL,
		0x255BFCD799EB917FULL,
		0xC34EF64C3EDB27DEULL,
		0xD767B7FA51735A41ULL,
		0x0623AD2F897D9E13ULL,
		0x1925EC92CF75953EULL,
		0x1DC08B48EABDE110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0230A0D0D2AEC6EULL,
		0x2B78A9A29B0A66ECULL,
		0x4AB7F9AF33D722FEULL,
		0x869DEC987DB64FBCULL,
		0xAECF6FF4A2E6B483ULL,
		0x0C475A5F12FB3C27ULL,
		0x324BD9259EEB2A7CULL,
		0x3B811691D57BC220ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3980833ADF97CA66ULL,
		0x1B36C59901C06EB6ULL,
		0x062A04BFE53BD45DULL,
		0xC5D4BD958FFD37DBULL,
		0x550BB5FDC1CE9ABDULL,
		0x732A25E5D07C1901ULL,
		0xDDFF182C8D80A542ULL,
		0x36E055E7D976BE07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73010675BF2F94CCULL,
		0x366D8B320380DD6CULL,
		0x0C54097FCA77A8BAULL,
		0x8BA97B2B1FFA6FB6ULL,
		0xAA176BFB839D357BULL,
		0xE6544BCBA0F83202ULL,
		0xBBFE30591B014A84ULL,
		0x6DC0ABCFB2ED7C0FULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2B0387FCC8E1194ULL,
		0x6A55610C912ED688ULL,
		0x5B067DAF00F33A90ULL,
		0x8B7AA7510E4BB06DULL,
		0x7F2F623E44850573ULL,
		0xE32EE3BC5C06F9B0ULL,
		0x3227EEA99A9ED401ULL,
		0x02732245F10D494CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x656070FF991C2328ULL,
		0xD4AAC219225DAD11ULL,
		0xB60CFB5E01E67520ULL,
		0x16F54EA21C9760DAULL,
		0xFE5EC47C890A0AE7ULL,
		0xC65DC778B80DF360ULL,
		0x644FDD53353DA803ULL,
		0x04E6448BE21A9298ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11E73578CC91DE03ULL,
		0x2F9C21C37B01023AULL,
		0x235051EB4756D6F9ULL,
		0xD935B16D52A03134ULL,
		0x5C5AB7D8DC668743ULL,
		0x96ED8906475AA839ULL,
		0x1F8BC4C8BA467878ULL,
		0x2A7DC7A70D076418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23CE6AF19923BC06ULL,
		0x5F384386F6020474ULL,
		0x46A0A3D68EADADF2ULL,
		0xB26B62DAA5406268ULL,
		0xB8B56FB1B8CD0E87ULL,
		0x2DDB120C8EB55072ULL,
		0x3F178991748CF0F1ULL,
		0x54FB8F4E1A0EC830ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x449F5703513E5009ULL,
		0xA0820446BD65A434ULL,
		0x90436285425283CDULL,
		0xD3BB96D291AD8B93ULL,
		0x57C49245ECC0F2E2ULL,
		0x304922AE61C65BBAULL,
		0xEC7E16D5570672D4ULL,
		0x2E1F91F618EF5FF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x893EAE06A27CA012ULL,
		0x4104088D7ACB4868ULL,
		0x2086C50A84A5079BULL,
		0xA7772DA5235B1727ULL,
		0xAF89248BD981E5C5ULL,
		0x6092455CC38CB774ULL,
		0xD8FC2DAAAE0CE5A8ULL,
		0x5C3F23EC31DEBFEDULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE0A1A75700E5982ULL,
		0x8974BFD81F43140CULL,
		0xD51A6297799F9CD0ULL,
		0x25A781DE2D83F1DAULL,
		0xEFBD97273372955DULL,
		0x3F5A6C2E7CFCBD2EULL,
		0xEACD8EC675E576CAULL,
		0x0D7C949DEF7DC356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C1434EAE01CB304ULL,
		0x12E97FB03E862819ULL,
		0xAA34C52EF33F39A1ULL,
		0x4B4F03BC5B07E3B5ULL,
		0xDF7B2E4E66E52ABAULL,
		0x7EB4D85CF9F97A5DULL,
		0xD59B1D8CEBCAED94ULL,
		0x1AF9293BDEFB86ADULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93BFFA8C1C8E90C4ULL,
		0xD301EC4D98FF66A8ULL,
		0xD3BFF736AA9694D3ULL,
		0x88779985D1271F68ULL,
		0x0BF7952AC5DFA7BFULL,
		0x80E64ADEB436965FULL,
		0x084CC873CA520AF2ULL,
		0x0C6948F7287FD201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x277FF518391D2188ULL,
		0xA603D89B31FECD51ULL,
		0xA77FEE6D552D29A7ULL,
		0x10EF330BA24E3ED1ULL,
		0x17EF2A558BBF4F7FULL,
		0x01CC95BD686D2CBEULL,
		0x109990E794A415E5ULL,
		0x18D291EE50FFA402ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D44209FD2699E24ULL,
		0x1FBBA3DF3A0B8863ULL,
		0xC21F09C6591CEFABULL,
		0x2C232945933B69A1ULL,
		0x4774FF790048B16CULL,
		0x3AD26C9F664F54BEULL,
		0xF1B361723E58A643ULL,
		0x12E3A461CE85578AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA88413FA4D33C48ULL,
		0x3F7747BE741710C6ULL,
		0x843E138CB239DF56ULL,
		0x5846528B2676D343ULL,
		0x8EE9FEF2009162D8ULL,
		0x75A4D93ECC9EA97CULL,
		0xE366C2E47CB14C86ULL,
		0x25C748C39D0AAF15ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BE7E70A13C92D35ULL,
		0x32D8AB716F64BEF7ULL,
		0x77DB4D5E5BA745CAULL,
		0x48E5315672F51BE9ULL,
		0xD16BB35E0A215270ULL,
		0x1C79B614FB1B5B71ULL,
		0xF3EBF57E21FC8532ULL,
		0x1DBBEDA3BB745108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77CFCE1427925A6AULL,
		0x65B156E2DEC97DEEULL,
		0xEFB69ABCB74E8B94ULL,
		0x91CA62ACE5EA37D2ULL,
		0xA2D766BC1442A4E0ULL,
		0x38F36C29F636B6E3ULL,
		0xE7D7EAFC43F90A64ULL,
		0x3B77DB4776E8A211ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21920C6750355473ULL,
		0x81A4F32FEDEB9D6AULL,
		0x443545211EFB5059ULL,
		0xD52FCF7D6D4E2AD1ULL,
		0xFE1960F562221940ULL,
		0xA6C0B3CAA4E80ADDULL,
		0x6D20F1B0A8978607ULL,
		0x2E2BA180770D88FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432418CEA06AA8E6ULL,
		0x0349E65FDBD73AD4ULL,
		0x886A8A423DF6A0B3ULL,
		0xAA5F9EFADA9C55A2ULL,
		0xFC32C1EAC4443281ULL,
		0x4D81679549D015BBULL,
		0xDA41E361512F0C0FULL,
		0x5C574300EE1B11F8ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF4FCE164BB97EEULL,
		0x4B7B36EF92CED8F3ULL,
		0xDC49DE157F012AEAULL,
		0x5067A0854FEF1F51ULL,
		0x6B977CCE95F8BA73ULL,
		0x6C7A1E2AA2F10D08ULL,
		0xCB0272CF2DFA5DA3ULL,
		0x219022B11F2693D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E9F9C2C9772FDCULL,
		0x96F66DDF259DB1E7ULL,
		0xB893BC2AFE0255D4ULL,
		0xA0CF410A9FDE3EA3ULL,
		0xD72EF99D2BF174E6ULL,
		0xD8F43C5545E21A10ULL,
		0x9604E59E5BF4BB46ULL,
		0x432045623E4D27A5ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6979B84AA6E216ABULL,
		0x4578B7140D635E11ULL,
		0x0F713A8288EE95D8ULL,
		0x165DB9D0B610C709ULL,
		0x32F5E547420241D6ULL,
		0x97D70719A7944826ULL,
		0x495B1203263A0674ULL,
		0x05098C9B67DD9716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F370954DC42D56ULL,
		0x8AF16E281AC6BC22ULL,
		0x1EE2750511DD2BB0ULL,
		0x2CBB73A16C218E12ULL,
		0x65EBCA8E840483ACULL,
		0x2FAE0E334F28904CULL,
		0x92B624064C740CE9ULL,
		0x0A131936CFBB2E2CULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x729E25C6D7CFE9BBULL,
		0x14FFF80A06A2BCF5ULL,
		0x587E62763637581FULL,
		0xE62A6FDAAA06922AULL,
		0xE12D303624CF4C33ULL,
		0xDB960E6CF6CAA788ULL,
		0x348C2EE133A410FEULL,
		0x2BACC00C47FA6608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53C4B8DAF9FD376ULL,
		0x29FFF0140D4579EAULL,
		0xB0FCC4EC6C6EB03EULL,
		0xCC54DFB5540D2454ULL,
		0xC25A606C499E9867ULL,
		0xB72C1CD9ED954F11ULL,
		0x69185DC2674821FDULL,
		0x575980188FF4CC10ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83F729D2583323DEULL,
		0x009BEC4E901C07B7ULL,
		0x32508E2060801AACULL,
		0x19CC9770F2157F92ULL,
		0x085998869A55CD29ULL,
		0x92D392DE3F13EAF7ULL,
		0x571EB0A9F58EC30FULL,
		0x28CE6DF498D4946CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07EE53A4B06647BCULL,
		0x0137D89D20380F6FULL,
		0x64A11C40C1003558ULL,
		0x33992EE1E42AFF24ULL,
		0x10B3310D34AB9A52ULL,
		0x25A725BC7E27D5EEULL,
		0xAE3D6153EB1D861FULL,
		0x519CDBE931A928D8ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA51F3CE8B480614CULL,
		0xD1D0B90944FCDB76ULL,
		0x760FD4E135ED0C05ULL,
		0x22BC44274CEC809FULL,
		0xE7748C80F8972D26ULL,
		0xDD0ADEAE155E3687ULL,
		0x8AAD5B0F59F6B159ULL,
		0x33C461208FE5AD63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A3E79D16900C298ULL,
		0xA3A1721289F9B6EDULL,
		0xEC1FA9C26BDA180BULL,
		0x4578884E99D9013EULL,
		0xCEE91901F12E5A4CULL,
		0xBA15BD5C2ABC6D0FULL,
		0x155AB61EB3ED62B3ULL,
		0x6788C2411FCB5AC7ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8456F800185AFDF0ULL,
		0x06A5148E96BCD4A1ULL,
		0xBD88DB1CF398A3AEULL,
		0x8CA850CFBC297E80ULL,
		0xF785A863E39EC13BULL,
		0x18D415C25390BF33ULL,
		0x19A745A11B9731F8ULL,
		0x3DA8627115299128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08ADF00030B5FBE0ULL,
		0x0D4A291D2D79A943ULL,
		0x7B11B639E731475CULL,
		0x1950A19F7852FD01ULL,
		0xEF0B50C7C73D8277ULL,
		0x31A82B84A7217E67ULL,
		0x334E8B42372E63F0ULL,
		0x7B50C4E22A532250ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD385959D8772BF7AULL,
		0x0E30095A738DABACULL,
		0x2490164F888F1393ULL,
		0x526E0E6A3A0EA091ULL,
		0xADA793278AF2363CULL,
		0xF5119477A2CC09C8ULL,
		0xCF8ACA4E7071E7E3ULL,
		0x2E2986F0E3D7338AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70B2B3B0EE57EF4ULL,
		0x1C6012B4E71B5759ULL,
		0x49202C9F111E2726ULL,
		0xA4DC1CD4741D4122ULL,
		0x5B4F264F15E46C78ULL,
		0xEA2328EF45981391ULL,
		0x9F15949CE0E3CFC7ULL,
		0x5C530DE1C7AE6715ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9AEB248E1000D0AULL,
		0xEA7E6010837B48FDULL,
		0xBA1CD2A6C1B6F44DULL,
		0xD36CD1C2B1B1D821ULL,
		0x8BD04C605EA8F554ULL,
		0x53D2A0572D2BD0C7ULL,
		0xCBD6829618FFA80AULL,
		0x2B823E8308C32CA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD35D6491C2001A14ULL,
		0xD4FCC02106F691FBULL,
		0x7439A54D836DE89BULL,
		0xA6D9A3856363B043ULL,
		0x17A098C0BD51EAA9ULL,
		0xA7A540AE5A57A18FULL,
		0x97AD052C31FF5014ULL,
		0x57047D0611865953ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68B2B3500B55DC0BULL,
		0xBEF437CFED525414ULL,
		0x6A1EC8A429A5B6EEULL,
		0x7EEB3B7992331743ULL,
		0xD59BCC53B0C305BAULL,
		0x1C3BA45371CAC7BAULL,
		0x508D77C743D8675BULL,
		0x29C74D531A951612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD16566A016ABB816ULL,
		0x7DE86F9FDAA4A828ULL,
		0xD43D9148534B6DDDULL,
		0xFDD676F324662E86ULL,
		0xAB3798A761860B74ULL,
		0x387748A6E3958F75ULL,
		0xA11AEF8E87B0CEB6ULL,
		0x538E9AA6352A2C24ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46BB8F249F6F7243ULL,
		0xBC5264037D956BD7ULL,
		0x7DF6766043371960ULL,
		0xE8776A47334B2DCCULL,
		0x6FF81CE55B910F71ULL,
		0x448FA540786449F8ULL,
		0xD36AD47E3EEF44B4ULL,
		0x3BE21955BBB9CC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D771E493EDEE486ULL,
		0x78A4C806FB2AD7AEULL,
		0xFBECECC0866E32C1ULL,
		0xD0EED48E66965B98ULL,
		0xDFF039CAB7221EE3ULL,
		0x891F4A80F0C893F0ULL,
		0xA6D5A8FC7DDE8968ULL,
		0x77C432AB7773990BULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A2E49A27760DA15ULL,
		0x66B5FEFAB522669CULL,
		0x60612AF39CED0AB9ULL,
		0x46D171741A3A3347ULL,
		0x93AE2D99946170DEULL,
		0x5F271898A0A51001ULL,
		0x181130C4CBE3AE0AULL,
		0x201A630CCF1B7C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x545C9344EEC1B42AULL,
		0xCD6BFDF56A44CD38ULL,
		0xC0C255E739DA1572ULL,
		0x8DA2E2E83474668EULL,
		0x275C5B3328C2E1BCULL,
		0xBE4E3131414A2003ULL,
		0x3022618997C75C14ULL,
		0x4034C6199E36F82EULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D3BE25362865365ULL,
		0x9003736E51C4B0CDULL,
		0xB177239929ED50C8ULL,
		0xD1D1041C0D155793ULL,
		0x0D1A77A58E7DB959ULL,
		0x29E3A5AC62D16029ULL,
		0x1C1A9F701A0B4A88ULL,
		0x2CBD77EA127CE09BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A77C4A6C50CA6CAULL,
		0x2006E6DCA389619AULL,
		0x62EE473253DAA191ULL,
		0xA3A208381A2AAF27ULL,
		0x1A34EF4B1CFB72B3ULL,
		0x53C74B58C5A2C052ULL,
		0x38353EE034169510ULL,
		0x597AEFD424F9C136ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2711D9FA9C53C4AULL,
		0x3EBBB7EF2A573456ULL,
		0x8318F0CC3C7E10DCULL,
		0xC10128ADD4FE5916ULL,
		0x296D8CB71E97CA64ULL,
		0x1D02FFC1A768BA6DULL,
		0xCF16A5CFA1CFACA8ULL,
		0x38829698F3F0F503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4E23B3F538A7894ULL,
		0x7D776FDE54AE68ADULL,
		0x0631E19878FC21B8ULL,
		0x8202515BA9FCB22DULL,
		0x52DB196E3D2F94C9ULL,
		0x3A05FF834ED174DAULL,
		0x9E2D4B9F439F5950ULL,
		0x71052D31E7E1EA07ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7E61E4B5725D0A2ULL,
		0x2FE02B77549C59DFULL,
		0x07F07B5DDE8CCEFDULL,
		0x59BBC6E37AD490A1ULL,
		0x74C8A0BAE15B7F5BULL,
		0xE23CE8453A6579EFULL,
		0xC8F3EDCABCF88CE4ULL,
		0x0250009E18DFD5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FCC3C96AE4BA144ULL,
		0x5FC056EEA938B3BFULL,
		0x0FE0F6BBBD199DFAULL,
		0xB3778DC6F5A92142ULL,
		0xE9914175C2B6FEB6ULL,
		0xC479D08A74CAF3DEULL,
		0x91E7DB9579F119C9ULL,
		0x04A0013C31BFABD5ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC689B453E8841BCULL,
		0x58C8CCCA205D4A0BULL,
		0xB6562E14C9F8B65DULL,
		0x0E0B9C187CAC34BCULL,
		0x317A69DE73C0EF04ULL,
		0x18BC8BAD3D50B7B9ULL,
		0xF6F1CDBC6724EC0CULL,
		0x0EED848AD6AB161EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D1368A7D108378ULL,
		0xB191999440BA9417ULL,
		0x6CAC5C2993F16CBAULL,
		0x1C173830F9586979ULL,
		0x62F4D3BCE781DE08ULL,
		0x3179175A7AA16F72ULL,
		0xEDE39B78CE49D818ULL,
		0x1DDB0915AD562C3DULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7AA055B8C563A57ULL,
		0x26CA38B43803472AULL,
		0x9DE56AE1F735FAB4ULL,
		0x68382A6F7360CB00ULL,
		0xFA0F8CE81F35D6D7ULL,
		0xB340E9D72C0DA356ULL,
		0xD521889A027FBCFDULL,
		0x15C47B9EEA6F185CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF540AB718AC74AEULL,
		0x4D94716870068E55ULL,
		0x3BCAD5C3EE6BF568ULL,
		0xD07054DEE6C19601ULL,
		0xF41F19D03E6BADAEULL,
		0x6681D3AE581B46ADULL,
		0xAA43113404FF79FBULL,
		0x2B88F73DD4DE30B9ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA1B2D10A3800891ULL,
		0x9C579A47905E52DBULL,
		0xA2F77138D669EE99ULL,
		0xEE7AAC5649C55DC6ULL,
		0x54A63161974F5598ULL,
		0xBF2BD17BEA8C52C8ULL,
		0x471623925F45E946ULL,
		0x256B3C1F8AFF1E14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4365A2147001122ULL,
		0x38AF348F20BCA5B7ULL,
		0x45EEE271ACD3DD33ULL,
		0xDCF558AC938ABB8DULL,
		0xA94C62C32E9EAB31ULL,
		0x7E57A2F7D518A590ULL,
		0x8E2C4724BE8BD28DULL,
		0x4AD6783F15FE3C28ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C92C9F958D03204ULL,
		0x9FC8750F38E7CE36ULL,
		0x159E6A0A00D6490CULL,
		0x4756CC9D984F6B20ULL,
		0x76FE50F4495C088BULL,
		0xFC135B1608E8E210ULL,
		0x4BB8DBA30EB75DADULL,
		0x2FC13A72298B0CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x392593F2B1A06408ULL,
		0x3F90EA1E71CF9C6DULL,
		0x2B3CD41401AC9219ULL,
		0x8EAD993B309ED640ULL,
		0xEDFCA1E892B81116ULL,
		0xF826B62C11D1C420ULL,
		0x9771B7461D6EBB5BULL,
		0x5F8274E4531619EAULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x987D79F2C8D0EE3CULL,
		0xEE87732C87A4B43FULL,
		0xD3D8FEE7ACE0C025ULL,
		0xE1B2FC74AC6EEA3CULL,
		0x97FF9642318DD254ULL,
		0x2143B5677FE886E7ULL,
		0x4977F185CBD3B98FULL,
		0x2597791A7C47810AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FAF3E591A1DC78ULL,
		0xDD0EE6590F49687FULL,
		0xA7B1FDCF59C1804BULL,
		0xC365F8E958DDD479ULL,
		0x2FFF2C84631BA4A9ULL,
		0x42876ACEFFD10DCFULL,
		0x92EFE30B97A7731EULL,
		0x4B2EF234F88F0214ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3566C01BA8853955ULL,
		0x0732124B5F17F92EULL,
		0x4ABAD2A599F60D71ULL,
		0xEB78C9CC776DCCBCULL,
		0x15CB0A68C76246E0ULL,
		0x7CBD76640CBD9EF2ULL,
		0x764D2F392F766C87ULL,
		0x2EA01BF8A8320BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACD8037510A72AAULL,
		0x0E642496BE2FF25CULL,
		0x9575A54B33EC1AE2ULL,
		0xD6F19398EEDB9978ULL,
		0x2B9614D18EC48DC1ULL,
		0xF97AECC8197B3DE4ULL,
		0xEC9A5E725EECD90EULL,
		0x5D4037F150641798ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB99E78E930D2930CULL,
		0x02ADD18C6A0CD570ULL,
		0x964121FE14A47B75ULL,
		0xD247887D8E639232ULL,
		0xDAE55C41A8A06CC3ULL,
		0xF05E7556FDA42876ULL,
		0x1E1F23367A1F44EAULL,
		0x21F76034BE837F2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733CF1D261A52618ULL,
		0x055BA318D419AAE1ULL,
		0x2C8243FC2948F6EAULL,
		0xA48F10FB1CC72465ULL,
		0xB5CAB8835140D987ULL,
		0xE0BCEAADFB4850EDULL,
		0x3C3E466CF43E89D5ULL,
		0x43EEC0697D06FE5AULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0A52BC208E71893ULL,
		0xD50CEFE268539518ULL,
		0x5948D20987035095ULL,
		0x4952877AA5CE80B7ULL,
		0xAC36B74DEE76DE0EULL,
		0x6333AD1378D372B1ULL,
		0x9E4D5B8E539BC42FULL,
		0x3A257113FA5C634DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x614A578411CE3126ULL,
		0xAA19DFC4D0A72A31ULL,
		0xB291A4130E06A12BULL,
		0x92A50EF54B9D016EULL,
		0x586D6E9BDCEDBC1CULL,
		0xC6675A26F1A6E563ULL,
		0x3C9AB71CA737885EULL,
		0x744AE227F4B8C69BULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43E9A5B973E68A11ULL,
		0xF4531E13A5C455DDULL,
		0xD4E0337EBA58614EULL,
		0x35130E364C73DBD2ULL,
		0x86B2E729FBCE5832ULL,
		0x458F23AD0C96E79BULL,
		0x32BF2FE43617C6B7ULL,
		0x1446009E04409424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D34B72E7CD1422ULL,
		0xE8A63C274B88ABBAULL,
		0xA9C066FD74B0C29DULL,
		0x6A261C6C98E7B7A5ULL,
		0x0D65CE53F79CB064ULL,
		0x8B1E475A192DCF37ULL,
		0x657E5FC86C2F8D6EULL,
		0x288C013C08812848ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6235191F9BBD9082ULL,
		0x3158628C56F7508AULL,
		0xF79F8A6335D6112BULL,
		0x79CF8BAF281E09CAULL,
		0x6A1E5B865E1E7EBBULL,
		0xB212BE482030C9DAULL,
		0xD18B7EA7092E310DULL,
		0x3BF6DFBCAC91CD7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46A323F377B2104ULL,
		0x62B0C518ADEEA114ULL,
		0xEF3F14C66BAC2256ULL,
		0xF39F175E503C1395ULL,
		0xD43CB70CBC3CFD76ULL,
		0x64257C90406193B4ULL,
		0xA316FD4E125C621BULL,
		0x77EDBF7959239AF5ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B97D3A2F251C1A7ULL,
		0xAA8D14962B49F419ULL,
		0x0F36795E5EEFB7ABULL,
		0x6939EDE2E29A7DB4ULL,
		0xD136A6EBAFE735F0ULL,
		0x1915C268A81AAEA4ULL,
		0xC475AAB92EF62A3AULL,
		0x123A78C463EEEFF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x172FA745E4A3834EULL,
		0x551A292C5693E833ULL,
		0x1E6CF2BCBDDF6F57ULL,
		0xD273DBC5C534FB68ULL,
		0xA26D4DD75FCE6BE0ULL,
		0x322B84D150355D49ULL,
		0x88EB55725DEC5474ULL,
		0x2474F188C7DDDFE9ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x262E935FB64C55AAULL,
		0x818C0CC37DAC6DC5ULL,
		0x65D3583A5073B3A3ULL,
		0xE61C4002983C2A91ULL,
		0x30177C57E7C1F5B9ULL,
		0x3753F81EF58BA457ULL,
		0xFD14A6A2F0EF4C64ULL,
		0x03DFBC944B465162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C5D26BF6C98AB54ULL,
		0x03181986FB58DB8AULL,
		0xCBA6B074A0E76747ULL,
		0xCC38800530785522ULL,
		0x602EF8AFCF83EB73ULL,
		0x6EA7F03DEB1748AEULL,
		0xFA294D45E1DE98C8ULL,
		0x07BF7928968CA2C5ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ACA4106C56DABC9ULL,
		0x20709C8817F17BF7ULL,
		0x4D056C10121DE9B1ULL,
		0xC6BD13D1AC74B529ULL,
		0x5044E1C52942A63FULL,
		0xFE608BEB48215A2CULL,
		0xD093412A5C55CEE5ULL,
		0x2D817C6641BD6ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3594820D8ADB5792ULL,
		0x40E139102FE2F7EEULL,
		0x9A0AD820243BD362ULL,
		0x8D7A27A358E96A52ULL,
		0xA089C38A52854C7FULL,
		0xFCC117D69042B458ULL,
		0xA1268254B8AB9DCBULL,
		0x5B02F8CC837ADD9BULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56FE0F0BBDB5F751ULL,
		0xF78CD1C0816AFE61ULL,
		0x0EECF3B2FEFAFCAEULL,
		0x9FFD879149E03E10ULL,
		0x09ECFD6D72BBD979ULL,
		0x9BCAB03459128B2AULL,
		0xA35E7506DAEB67B0ULL,
		0x3EC52BEE00D2DE12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADFC1E177B6BEEA2ULL,
		0xEF19A38102D5FCC2ULL,
		0x1DD9E765FDF5F95DULL,
		0x3FFB0F2293C07C20ULL,
		0x13D9FADAE577B2F3ULL,
		0x37956068B2251654ULL,
		0x46BCEA0DB5D6CF61ULL,
		0x7D8A57DC01A5BC25ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x291C6E0D99A548E6ULL,
		0x2C3B91EA18DBC37DULL,
		0x4ED89647B8D2A6F3ULL,
		0x71C6B60D9AFB2F68ULL,
		0x2599E3D8D8D69169ULL,
		0xEC68ADF2CDDFCB89ULL,
		0x073420481E0A3D11ULL,
		0x3FE57408AF841007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5238DC1B334A91CCULL,
		0x587723D431B786FAULL,
		0x9DB12C8F71A54DE6ULL,
		0xE38D6C1B35F65ED0ULL,
		0x4B33C7B1B1AD22D2ULL,
		0xD8D15BE59BBF9712ULL,
		0x0E6840903C147A23ULL,
		0x7FCAE8115F08200EULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1AB735C1304AC89ULL,
		0x781ABD862F928734ULL,
		0x37ECC8E567004EB8ULL,
		0xA39CB899ED27B989ULL,
		0x62FD0041A1A68C20ULL,
		0xC558FEB4CE7D0924ULL,
		0xC69BECA54F5C9558ULL,
		0x0E7E765562AE2814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8356E6B826095912ULL,
		0xF0357B0C5F250E69ULL,
		0x6FD991CACE009D70ULL,
		0x47397133DA4F7312ULL,
		0xC5FA0083434D1841ULL,
		0x8AB1FD699CFA1248ULL,
		0x8D37D94A9EB92AB1ULL,
		0x1CFCECAAC55C5029ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4573E03199185CF0ULL,
		0xE8F38804A537E65AULL,
		0xBE360F1A010CA146ULL,
		0x0FCA695FCE3825E5ULL,
		0x58B40A9593B7A0F7ULL,
		0x57EF2E217D3CFDD0ULL,
		0x1DD13FB2B4103F6CULL,
		0x19BBFEEDA3FE3BF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE7C0633230B9E0ULL,
		0xD1E710094A6FCCB4ULL,
		0x7C6C1E340219428DULL,
		0x1F94D2BF9C704BCBULL,
		0xB168152B276F41EEULL,
		0xAFDE5C42FA79FBA0ULL,
		0x3BA27F6568207ED8ULL,
		0x3377FDDB47FC77E0ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47B844E442223C76ULL,
		0xEA857F8E59B83AF7ULL,
		0x2498985FF85D69B4ULL,
		0xEFD8EC664723957BULL,
		0x4445F273F4296494ULL,
		0x71458317CE2EFEB8ULL,
		0xF2B8D28A345DB94CULL,
		0x05E5312DBE19A2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F7089C8844478ECULL,
		0xD50AFF1CB37075EEULL,
		0x493130BFF0BAD369ULL,
		0xDFB1D8CC8E472AF6ULL,
		0x888BE4E7E852C929ULL,
		0xE28B062F9C5DFD70ULL,
		0xE571A51468BB7298ULL,
		0x0BCA625B7C33455DULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E75B7F7F8D30FB9ULL,
		0x77553E025E5E18C6ULL,
		0xEF560C845105DFBAULL,
		0xECA849D36135DB50ULL,
		0x2D00CF50FE2C947DULL,
		0x0E893BE865CB0674ULL,
		0xF570B6E4A9C230D8ULL,
		0x1F2569FF8E87C9EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CEB6FEFF1A61F72ULL,
		0xEEAA7C04BCBC318CULL,
		0xDEAC1908A20BBF74ULL,
		0xD95093A6C26BB6A1ULL,
		0x5A019EA1FC5928FBULL,
		0x1D1277D0CB960CE8ULL,
		0xEAE16DC9538461B0ULL,
		0x3E4AD3FF1D0F93DFULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6759EE72FAA17762ULL,
		0xF410139CBF4034D5ULL,
		0xE4D77C22156DBB5AULL,
		0x6E4FF5BFE142F7C9ULL,
		0x41E96571844DCFC2ULL,
		0x6DF3EFC703F49CF8ULL,
		0x7D717F27FE998390ULL,
		0x1D30463A12390867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB3DCE5F542EEC4ULL,
		0xE82027397E8069AAULL,
		0xC9AEF8442ADB76B5ULL,
		0xDC9FEB7FC285EF93ULL,
		0x83D2CAE3089B9F84ULL,
		0xDBE7DF8E07E939F0ULL,
		0xFAE2FE4FFD330720ULL,
		0x3A608C74247210CEULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E26DEA795A552F8ULL,
		0x1BD85555DC3979CEULL,
		0xB20332AEFDAF164DULL,
		0x2E9F797BBA2EE37EULL,
		0xE921FEAAF68DDFA9ULL,
		0xAE2C9479BA46DF81ULL,
		0x5300FFDB7ABE932DULL,
		0x22E65AAE88750459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4DBD4F2B4AA5F0ULL,
		0x37B0AAABB872F39CULL,
		0x6406655DFB5E2C9AULL,
		0x5D3EF2F7745DC6FDULL,
		0xD243FD55ED1BBF52ULL,
		0x5C5928F3748DBF03ULL,
		0xA601FFB6F57D265BULL,
		0x45CCB55D10EA08B2ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5996362A8922D108ULL,
		0xE5D4B42D12D99DDFULL,
		0xEE5A494AF5E68F3EULL,
		0xE974B06C823696A9ULL,
		0xA1AC5DCF8BE1ADC1ULL,
		0x5A9CF6871BD2BF69ULL,
		0x6F1B9ECCE422D878ULL,
		0x3299F3F1BD1195C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32C6C551245A210ULL,
		0xCBA9685A25B33BBEULL,
		0xDCB49295EBCD1E7DULL,
		0xD2E960D9046D2D53ULL,
		0x4358BB9F17C35B83ULL,
		0xB539ED0E37A57ED3ULL,
		0xDE373D99C845B0F0ULL,
		0x6533E7E37A232B92ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BD9981C790BD971ULL,
		0xBC6BBC049763F0A1ULL,
		0x909A87FD0674583EULL,
		0xF58EA2CD19445079ULL,
		0xA440FB41D7C6B8ACULL,
		0xC1E5571263BA0249ULL,
		0xCF0398E2F02BC4C9ULL,
		0x1624060D332ED33FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B33038F217B2E2ULL,
		0x78D778092EC7E142ULL,
		0x21350FFA0CE8B07DULL,
		0xEB1D459A3288A0F3ULL,
		0x4881F683AF8D7159ULL,
		0x83CAAE24C7740493ULL,
		0x9E0731C5E0578993ULL,
		0x2C480C1A665DA67FULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x370456AB1B928D96ULL,
		0x3D39AD3B14AAC47EULL,
		0x2A1F4C530A70835AULL,
		0x41754D36A373AE71ULL,
		0x7F66E30F9714C58AULL,
		0xCF4CB840B00CF493ULL,
		0xC9BD99135AF70737ULL,
		0x3F586C68894DDD0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E08AD5637251B2CULL,
		0x7A735A76295588FCULL,
		0x543E98A614E106B4ULL,
		0x82EA9A6D46E75CE2ULL,
		0xFECDC61F2E298B14ULL,
		0x9E9970816019E926ULL,
		0x937B3226B5EE0E6FULL,
		0x7EB0D8D1129BBA19ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3857EA0A3F05B28CULL,
		0x7D4AC51B10707939ULL,
		0xB416AB8FFD9C6D36ULL,
		0xACD12E892272137BULL,
		0xEA10E2EC0D7CAAB5ULL,
		0x0FD91627A0378E1CULL,
		0x8D76D5E9A7A0F232ULL,
		0x10CC718A327741EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70AFD4147E0B6518ULL,
		0xFA958A3620E0F272ULL,
		0x682D571FFB38DA6CULL,
		0x59A25D1244E426F7ULL,
		0xD421C5D81AF9556BULL,
		0x1FB22C4F406F1C39ULL,
		0x1AEDABD34F41E464ULL,
		0x2198E31464EE83DBULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA33A3A3EB251A2AULL,
		0xA08C820FB7C06283ULL,
		0x213E017D19FEDCA1ULL,
		0xD02368382122DBA6ULL,
		0x6171EB18704713C3ULL,
		0x941E0229DC3BD458ULL,
		0x847B03AF7AC0BA6CULL,
		0x3935F9DA0314F524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4674747D64A3454ULL,
		0x4119041F6F80C507ULL,
		0x427C02FA33FDB943ULL,
		0xA046D0704245B74CULL,
		0xC2E3D630E08E2787ULL,
		0x283C0453B877A8B0ULL,
		0x08F6075EF58174D9ULL,
		0x726BF3B40629EA49ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDEA7F64AB1AB262ULL,
		0x1C4D4BF90435666CULL,
		0xBA75F1D92D3D85D4ULL,
		0x8BC9B2EF41BABE50ULL,
		0x5ACEE8A65BAE348EULL,
		0x84A9F6380BEF88F3ULL,
		0x33C59BE52C7C4BA1ULL,
		0x3E82065511BAF22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD4FEC9563564C4ULL,
		0x389A97F2086ACCD9ULL,
		0x74EBE3B25A7B0BA8ULL,
		0x179365DE83757CA1ULL,
		0xB59DD14CB75C691DULL,
		0x0953EC7017DF11E6ULL,
		0x678B37CA58F89743ULL,
		0x7D040CAA2375E45CULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x265B5CDACB4E232DULL,
		0xFDD5FC49AA4AB01AULL,
		0x333C5328784106D0ULL,
		0x3592F9BD5A05C58AULL,
		0x626B756FF16D752CULL,
		0xAF36C5D1170B6CE1ULL,
		0x0A0AD997DA4D7DADULL,
		0x0F2459438CE3B0B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CB6B9B5969C465AULL,
		0xFBABF89354956034ULL,
		0x6678A650F0820DA1ULL,
		0x6B25F37AB40B8B14ULL,
		0xC4D6EADFE2DAEA58ULL,
		0x5E6D8BA22E16D9C2ULL,
		0x1415B32FB49AFB5BULL,
		0x1E48B28719C76170ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D7F55E8AFE94E35ULL,
		0xC643AA105174BE5CULL,
		0xAC03FF4934210518ULL,
		0x7268D9CA15A5B7CCULL,
		0x83016206F775842DULL,
		0x8F3537EE17D8B976ULL,
		0x9581B0F26AFFFB36ULL,
		0x2831BE371BCB3AD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFEABD15FD29C6AULL,
		0x8C875420A2E97CB9ULL,
		0x5807FE9268420A31ULL,
		0xE4D1B3942B4B6F99ULL,
		0x0602C40DEEEB085AULL,
		0x1E6A6FDC2FB172EDULL,
		0x2B0361E4D5FFF66DULL,
		0x50637C6E379675A9ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x384FB5D8E752DB46ULL,
		0x4920B27655DD1405ULL,
		0xAEF587BF3CC1257EULL,
		0x460C7AF36A66BF5DULL,
		0x0434EE25B063C6E8ULL,
		0xCC63588AED9AA6EEULL,
		0x3046002E0D88CE4EULL,
		0x328B594FFA368E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x709F6BB1CEA5B68CULL,
		0x924164ECABBA280AULL,
		0x5DEB0F7E79824AFCULL,
		0x8C18F5E6D4CD7EBBULL,
		0x0869DC4B60C78DD0ULL,
		0x98C6B115DB354DDCULL,
		0x608C005C1B119C9DULL,
		0x6516B29FF46D1C8AULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15810CD85A801720ULL,
		0x7269ACC1216DE96BULL,
		0x60DCCA2C0ECA9560ULL,
		0xD7449D3A4C96C1AFULL,
		0x6A28D9830C3B5C91ULL,
		0x0C7EAC82165AEE49ULL,
		0xB9C81E5C06581983ULL,
		0x033B68B2ADDED31AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B0219B0B5002E40ULL,
		0xE4D3598242DBD2D6ULL,
		0xC1B994581D952AC0ULL,
		0xAE893A74992D835EULL,
		0xD451B3061876B923ULL,
		0x18FD59042CB5DC92ULL,
		0x73903CB80CB03306ULL,
		0x0676D1655BBDA635ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84D64D141436B075ULL,
		0x41461D3E7A80CC47ULL,
		0x76CEB7EAB9A20C17ULL,
		0x7F946206CF1467D2ULL,
		0xA019C0C88B3FAB58ULL,
		0x7A4EE732F82E51C2ULL,
		0xFC85DF248903D4F4ULL,
		0x29E575E659FECB0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09AC9A28286D60EAULL,
		0x828C3A7CF501988FULL,
		0xED9D6FD57344182EULL,
		0xFF28C40D9E28CFA4ULL,
		0x40338191167F56B0ULL,
		0xF49DCE65F05CA385ULL,
		0xF90BBE491207A9E8ULL,
		0x53CAEBCCB3FD9619ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48F1D68C46959350ULL,
		0xCBB06971B358C102ULL,
		0xAF303AB24D51F16EULL,
		0x878B73AF76CF28A8ULL,
		0xEDAC81B98F06D393ULL,
		0xD27BB07BF316C9E4ULL,
		0x6B0496CB191BA2A7ULL,
		0x22EE0DF87CD40E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E3AD188D2B26A0ULL,
		0x9760D2E366B18204ULL,
		0x5E6075649AA3E2DDULL,
		0x0F16E75EED9E5151ULL,
		0xDB5903731E0DA727ULL,
		0xA4F760F7E62D93C9ULL,
		0xD6092D963237454FULL,
		0x45DC1BF0F9A81CF0ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99B4AB831B11518BULL,
		0x0AAF41ABF9A19609ULL,
		0x41B8C34CFF295CF6ULL,
		0x1F6998D7B31255B4ULL,
		0xDFB230D8F3B5E820ULL,
		0xE007710FBB70B157ULL,
		0x1DD31EEA32116434ULL,
		0x11E098C6D5C09A86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x336957063622A316ULL,
		0x155E8357F3432C13ULL,
		0x83718699FE52B9ECULL,
		0x3ED331AF6624AB68ULL,
		0xBF6461B1E76BD040ULL,
		0xC00EE21F76E162AFULL,
		0x3BA63DD46422C869ULL,
		0x23C1318DAB81350CULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x590059398AF6AD03ULL,
		0xBD0A400CB7B8BD36ULL,
		0x86CE6F35E1CD61DAULL,
		0x1FD732101DA83D2DULL,
		0xC1B35B60F0A3454BULL,
		0xF4AECE2FF1BF790BULL,
		0x8C65CEB55C1D8AB7ULL,
		0x00A01AB31CCFBA9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB200B27315ED5A06ULL,
		0x7A1480196F717A6CULL,
		0x0D9CDE6BC39AC3B5ULL,
		0x3FAE64203B507A5BULL,
		0x8366B6C1E1468A96ULL,
		0xE95D9C5FE37EF217ULL,
		0x18CB9D6AB83B156FULL,
		0x01403566399F7537ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD4B59FCC8084584ULL,
		0xD7B1E5A4F5392632ULL,
		0xAA64F954D2594025ULL,
		0xC5B758495694189DULL,
		0x65F1EE0577DCE25BULL,
		0x9F518F5D2C7172C5ULL,
		0x2F7694A1810B2BCFULL,
		0x1E72AAF83C0DC43EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A96B3F990108B08ULL,
		0xAF63CB49EA724C65ULL,
		0x54C9F2A9A4B2804BULL,
		0x8B6EB092AD28313BULL,
		0xCBE3DC0AEFB9C4B7ULL,
		0x3EA31EBA58E2E58AULL,
		0x5EED29430216579FULL,
		0x3CE555F0781B887CULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99EEE3A888B4EFA0ULL,
		0x798B78C83BBF0187ULL,
		0x2213975F314EA912ULL,
		0xF3864CE87F1CD9A4ULL,
		0x7013F32290EFA551ULL,
		0xB28ED232F87FD612ULL,
		0x1B22BA24593D40ECULL,
		0x0CA754EEF5FAC65EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33DDC7511169DF40ULL,
		0xF316F190777E030FULL,
		0x44272EBE629D5224ULL,
		0xE70C99D0FE39B348ULL,
		0xE027E64521DF4AA3ULL,
		0x651DA465F0FFAC24ULL,
		0x36457448B27A81D9ULL,
		0x194EA9DDEBF58CBCULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0E7686CE1F6B257ULL,
		0x2D4FDF00427FF2EEULL,
		0xCDC8393BA7F81A11ULL,
		0x133EE6E03F0DEDC9ULL,
		0x6A154D7A72B8A00CULL,
		0x31A0EFC33AF9FA9CULL,
		0xB1ABCDC5DA0D81D0ULL,
		0x2D669CF444364626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1CED0D9C3ED64AEULL,
		0x5A9FBE0084FFE5DDULL,
		0x9B9072774FF03422ULL,
		0x267DCDC07E1BDB93ULL,
		0xD42A9AF4E5714018ULL,
		0x6341DF8675F3F538ULL,
		0x63579B8BB41B03A0ULL,
		0x5ACD39E8886C8C4DULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C25EE2AB8272B65ULL,
		0xDDAB76411D6F4D6CULL,
		0xBF3D10E0A695F8AAULL,
		0x2EB09B3B1006374EULL,
		0x22822035D8FF5B38ULL,
		0x76549112AB18A2D7ULL,
		0x6C52D4E2CB31AD96ULL,
		0x248B022518613B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x584BDC55704E56CAULL,
		0xBB56EC823ADE9AD8ULL,
		0x7E7A21C14D2BF155ULL,
		0x5D613676200C6E9DULL,
		0x4504406BB1FEB670ULL,
		0xECA92225563145AEULL,
		0xD8A5A9C596635B2CULL,
		0x4916044A30C2773AULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18D33A03803FB954ULL,
		0x1FA14DDACDC461A3ULL,
		0x8B66E8E82A27076FULL,
		0x5613CBA051571534ULL,
		0xBB81B83847234A3AULL,
		0xE0CC1C436E2F61FAULL,
		0xF34CF6166EA6C5A4ULL,
		0x2088761DD3362C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A67407007F72A8ULL,
		0x3F429BB59B88C346ULL,
		0x16CDD1D0544E0EDEULL,
		0xAC279740A2AE2A69ULL,
		0x770370708E469474ULL,
		0xC1983886DC5EC3F5ULL,
		0xE699EC2CDD4D8B49ULL,
		0x4110EC3BA66C5801ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5358D86B589FF1C7ULL,
		0x1233D69DB1EC7E6EULL,
		0x408968AFDAA16933ULL,
		0xD2D31622D0DE8DE4ULL,
		0x97836AB43F1DE43FULL,
		0xC873D6C836009EDEULL,
		0x43A6CF0B8508753EULL,
		0x11CDEA107BA1AC2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6B1B0D6B13FE38EULL,
		0x2467AD3B63D8FCDCULL,
		0x8112D15FB542D266ULL,
		0xA5A62C45A1BD1BC8ULL,
		0x2F06D5687E3BC87FULL,
		0x90E7AD906C013DBDULL,
		0x874D9E170A10EA7DULL,
		0x239BD420F743585AULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD34CF6BE9374512ULL,
		0xBF8F661580C58DCCULL,
		0xFADF4E24819B98A8ULL,
		0x77268DEC6770E104ULL,
		0xBA09F17C1DEF5AB8ULL,
		0x4298A35A590EC4CBULL,
		0xD996C9D33EAA9BFDULL,
		0x342DAD1028523E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A699ED7D26E8A24ULL,
		0x7F1ECC2B018B1B99ULL,
		0xF5BE9C4903373151ULL,
		0xEE4D1BD8CEE1C209ULL,
		0x7413E2F83BDEB570ULL,
		0x853146B4B21D8997ULL,
		0xB32D93A67D5537FAULL,
		0x685B5A2050A47D17ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4796759784B7260ULL,
		0xF09BC47C94DFAE6AULL,
		0xC10A8553763325CDULL,
		0x6127FD7E0A52A7B0ULL,
		0xA63636F4822977EFULL,
		0x9C2BE4B312B57774ULL,
		0xD7F00FF7D8F6611DULL,
		0x23296B29C0C74797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F2CEB2F096E4C0ULL,
		0xE13788F929BF5CD5ULL,
		0x82150AA6EC664B9BULL,
		0xC24FFAFC14A54F61ULL,
		0x4C6C6DE90452EFDEULL,
		0x3857C966256AEEE9ULL,
		0xAFE01FEFB1ECC23BULL,
		0x4652D653818E8F2FULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BD3C0F0A2844B85ULL,
		0xA1920F71ECA99B89ULL,
		0x260B01A32E12244EULL,
		0x3468E58F2A4DCCA1ULL,
		0x99327F0FB710C011ULL,
		0x13E3823C57C51893ULL,
		0x78D0BD38960B4F46ULL,
		0x2CB1CD49078F0207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7A781E14508970AULL,
		0x43241EE3D9533712ULL,
		0x4C1603465C24489DULL,
		0x68D1CB1E549B9942ULL,
		0x3264FE1F6E218022ULL,
		0x27C70478AF8A3127ULL,
		0xF1A17A712C169E8CULL,
		0x59639A920F1E040EULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECF0B10802073A9FULL,
		0x6BF84FF87B550163ULL,
		0x35BA7D2D9DABBB5EULL,
		0x38783A19533E4CD4ULL,
		0xCF58AFBB1AFF17A9ULL,
		0x07CBEC099E584B18ULL,
		0x4C6C4D6DDB7E4403ULL,
		0x1B27C02BAD66F4E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9E16210040E753EULL,
		0xD7F09FF0F6AA02C7ULL,
		0x6B74FA5B3B5776BCULL,
		0x70F07432A67C99A8ULL,
		0x9EB15F7635FE2F52ULL,
		0x0F97D8133CB09631ULL,
		0x98D89ADBB6FC8806ULL,
		0x364F80575ACDE9CAULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0819141BDF79D87EULL,
		0xF1EC7664C045C5F9ULL,
		0x506976A8AA280855ULL,
		0x2282116A97611A88ULL,
		0x6B0CF5D2740DEB6FULL,
		0x69B3078D13AEF8A1ULL,
		0x24DECFF870BA6AF8ULL,
		0x2C876AABFA5E8B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10322837BEF3B0FCULL,
		0xE3D8ECC9808B8BF2ULL,
		0xA0D2ED51545010ABULL,
		0x450422D52EC23510ULL,
		0xD619EBA4E81BD6DEULL,
		0xD3660F1A275DF142ULL,
		0x49BD9FF0E174D5F0ULL,
		0x590ED557F4BD16D8ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD97C6DAA5AB72D9DULL,
		0x0B0E9895719E5240ULL,
		0x39BB1311AD31B911ULL,
		0x7B291FB0A067A5DAULL,
		0x9715A7DC4D1E8950ULL,
		0xEB5332A283D7FD97ULL,
		0x4BC968F79712D111ULL,
		0x3B1E3B228D9C95FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F8DB54B56E5B3AULL,
		0x161D312AE33CA481ULL,
		0x737626235A637222ULL,
		0xF6523F6140CF4BB4ULL,
		0x2E2B4FB89A3D12A0ULL,
		0xD6A6654507AFFB2FULL,
		0x9792D1EF2E25A223ULL,
		0x763C76451B392BFEULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8982F1327E8039CBULL,
		0x8484F0CB8948C71FULL,
		0x39CCA6BC511A5E42ULL,
		0xAFE1BEADB8EAB003ULL,
		0xC703C2264270A1BCULL,
		0x22DFA02A97C8C751ULL,
		0x31E241201AA235B0ULL,
		0x11D853958DCE6CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1305E264FD007396ULL,
		0x0909E19712918E3FULL,
		0x73994D78A234BC85ULL,
		0x5FC37D5B71D56006ULL,
		0x8E07844C84E14379ULL,
		0x45BF40552F918EA3ULL,
		0x63C4824035446B60ULL,
		0x23B0A72B1B9CD9C4ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB7E5672612A30D4ULL,
		0x0DD2976575DFB929ULL,
		0x9D1EE739A1C90880ULL,
		0x8FCAD68C2F70DB7CULL,
		0x1962FC3D7ADEC5B8ULL,
		0xD5FD043F27D0913EULL,
		0xB48A8EE95C521D73ULL,
		0x2C313DA45B0DD38DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6FCACE4C25461A8ULL,
		0x1BA52ECAEBBF7253ULL,
		0x3A3DCE7343921100ULL,
		0x1F95AD185EE1B6F9ULL,
		0x32C5F87AF5BD8B71ULL,
		0xABFA087E4FA1227CULL,
		0x69151DD2B8A43AE7ULL,
		0x58627B48B61BA71BULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1931544180D891B0ULL,
		0x404466D69FD1FFC3ULL,
		0x30A8715F48B18842ULL,
		0xECA7359772B38B7BULL,
		0xECD6899529B96C39ULL,
		0x73D1671265836E5BULL,
		0x356F6EC55D4F91B1ULL,
		0x2A6D393DD0450CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3262A88301B12360ULL,
		0x8088CDAD3FA3FF86ULL,
		0x6150E2BE91631084ULL,
		0xD94E6B2EE56716F6ULL,
		0xD9AD132A5372D873ULL,
		0xE7A2CE24CB06DCB7ULL,
		0x6ADEDD8ABA9F2362ULL,
		0x54DA727BA08A199AULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3225022AE6F6DEABULL,
		0xB3D7AA2EA13EA38DULL,
		0x26D625123C41EEADULL,
		0xB0138A689C29E96BULL,
		0x24666EA0AFCC1881ULL,
		0xAE5D27125BE7EC95ULL,
		0x56BF45F208452D4DULL,
		0x20D092BCB33F3E91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x644A0455CDEDBD56ULL,
		0x67AF545D427D471AULL,
		0x4DAC4A247883DD5BULL,
		0x602714D13853D2D6ULL,
		0x48CCDD415F983103ULL,
		0x5CBA4E24B7CFD92AULL,
		0xAD7E8BE4108A5A9BULL,
		0x41A12579667E7D22ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ADFB31B24EAFB0CULL,
		0xAC18CF7E62B028F8ULL,
		0x0262A0F332639725ULL,
		0xDF3DBE9E0C545BF9ULL,
		0x769187F594E7209AULL,
		0x9C03DE133E7A8B48ULL,
		0xD04557E2FD8D939BULL,
		0x3B5DEE163FCC2695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15BF663649D5F618ULL,
		0x58319EFCC56051F0ULL,
		0x04C541E664C72E4BULL,
		0xBE7B7D3C18A8B7F2ULL,
		0xED230FEB29CE4135ULL,
		0x3807BC267CF51690ULL,
		0xA08AAFC5FB1B2737ULL,
		0x76BBDC2C7F984D2BULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAFAFF01E4FC2D83ULL,
		0x5D71E2F1923624EAULL,
		0xAB9D6EE4E77384BBULL,
		0xF3155AE13CA352FDULL,
		0x2EFBFA8FD1B43149ULL,
		0x2ACD5AF86B84F095ULL,
		0x6E82F522C99B605BULL,
		0x0C03FC2525FB9047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F5FE03C9F85B06ULL,
		0xBAE3C5E3246C49D5ULL,
		0x573ADDC9CEE70976ULL,
		0xE62AB5C27946A5FBULL,
		0x5DF7F51FA3686293ULL,
		0x559AB5F0D709E12AULL,
		0xDD05EA459336C0B6ULL,
		0x1807F84A4BF7208EULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BE4A119AA84C7F2ULL,
		0x919DE89FDBA2EE86ULL,
		0xD7D94306AB24DD0FULL,
		0x4A76CC9C32ED0EB7ULL,
		0xD8E823ED57E50717ULL,
		0xAD5FBC65AB3F879FULL,
		0x4D960D678132E716ULL,
		0x16265651C58266FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77C9423355098FE4ULL,
		0x233BD13FB745DD0CULL,
		0xAFB2860D5649BA1FULL,
		0x94ED993865DA1D6FULL,
		0xB1D047DAAFCA0E2EULL,
		0x5ABF78CB567F0F3FULL,
		0x9B2C1ACF0265CE2DULL,
		0x2C4CACA38B04CDF6ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F697D7FE1441E8FULL,
		0x540B855EFA2322FCULL,
		0xA4705F20164C3B68ULL,
		0x745DF5A14F989448ULL,
		0x3E8627EF861F3DBCULL,
		0x2465752FF3AAD444ULL,
		0xDFB2B12D052CC05EULL,
		0x1038D527C960A0D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBED2FAFFC2883D1EULL,
		0xA8170ABDF44645F8ULL,
		0x48E0BE402C9876D0ULL,
		0xE8BBEB429F312891ULL,
		0x7D0C4FDF0C3E7B78ULL,
		0x48CAEA5FE755A888ULL,
		0xBF65625A0A5980BCULL,
		0x2071AA4F92C141A1ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BDD167904B65F39ULL,
		0xBC1FB4D35275AD47ULL,
		0x12164FC44DCAFADFULL,
		0x4AA46CEA24D17CD4ULL,
		0xD5BBB93941B342A3ULL,
		0x0AE74E4E85B08D6DULL,
		0xB82094C78D058415ULL,
		0x02D12F5E01C996C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37BA2CF2096CBE72ULL,
		0x783F69A6A4EB5A8FULL,
		0x242C9F889B95F5BFULL,
		0x9548D9D449A2F9A8ULL,
		0xAB77727283668546ULL,
		0x15CE9C9D0B611ADBULL,
		0x7041298F1A0B082AULL,
		0x05A25EBC03932D83ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2237FB57CF12A677ULL,
		0x0D82594AAD22B539ULL,
		0x67825C24519EA795ULL,
		0xEE40CA9EB573DACEULL,
		0x9BA389953ECFC6DAULL,
		0x4E73AA1423E673EDULL,
		0xD3041CC5BCC69B13ULL,
		0x0D6A55A1D61A371FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x446FF6AF9E254CEEULL,
		0x1B04B2955A456A72ULL,
		0xCF04B848A33D4F2AULL,
		0xDC81953D6AE7B59CULL,
		0x3747132A7D9F8DB5ULL,
		0x9CE7542847CCE7DBULL,
		0xA608398B798D3626ULL,
		0x1AD4AB43AC346E3FULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDE1EA7F7E3D3278ULL,
		0x1DCF08232AF59452ULL,
		0xD081C50499EC9F97ULL,
		0x23530F6592FA2697ULL,
		0xA96B226BE2BF5686ULL,
		0x9DDC3ABF4DF1A205ULL,
		0x3FEA33767D03BA96ULL,
		0x01CC6FDB3CB76185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC3D4FEFC7A64F0ULL,
		0x3B9E104655EB28A5ULL,
		0xA1038A0933D93F2EULL,
		0x46A61ECB25F44D2FULL,
		0x52D644D7C57EAD0CULL,
		0x3BB8757E9BE3440BULL,
		0x7FD466ECFA07752DULL,
		0x0398DFB6796EC30AULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5AB8F05B5751C83ULL,
		0x2A141A9212F12E66ULL,
		0x796222627956532AULL,
		0x4B9B6DFA1164AF49ULL,
		0x3E60ED88B80E8405ULL,
		0x564B0256ABC23D23ULL,
		0x31F92B8DF0A42CB9ULL,
		0x1F26249C96DF3E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB571E0B6AEA3906ULL,
		0x5428352425E25CCDULL,
		0xF2C444C4F2ACA654ULL,
		0x9736DBF422C95E92ULL,
		0x7CC1DB11701D080AULL,
		0xAC9604AD57847A46ULL,
		0x63F2571BE1485972ULL,
		0x3E4C49392DBE7C42ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C505BC8801B8C2EULL,
		0x77FAFA046D9CB4B6ULL,
		0x4D52084FEB4C7F10ULL,
		0x4F1EC09D9E91349CULL,
		0x1961D0C9142E6801ULL,
		0xFF88EFCF01CA3AC1ULL,
		0xB80A8523BCEAD166ULL,
		0x31A4DBB4CABF4BA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A0B7910037185CULL,
		0xEFF5F408DB39696CULL,
		0x9AA4109FD698FE20ULL,
		0x9E3D813B3D226938ULL,
		0x32C3A192285CD002ULL,
		0xFF11DF9E03947582ULL,
		0x70150A4779D5A2CDULL,
		0x6349B769957E9751ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB397F8A3F2530EF5ULL,
		0x77B54E3E7FD98B72ULL,
		0x7D2C037E39F459E6ULL,
		0x6668F552D11D1200ULL,
		0x4501850DFCDBA4D2ULL,
		0xCBB384438F575ABFULL,
		0xF9C3EA5D477011C0ULL,
		0x08F9298F15105314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x672FF147E4A61DEAULL,
		0xEF6A9C7CFFB316E5ULL,
		0xFA5806FC73E8B3CCULL,
		0xCCD1EAA5A23A2400ULL,
		0x8A030A1BF9B749A4ULL,
		0x976708871EAEB57EULL,
		0xF387D4BA8EE02381ULL,
		0x11F2531E2A20A629ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D812B043F7D8E2FULL,
		0x8DC0610A7B37901EULL,
		0xBB653DC9340BDB7DULL,
		0xFBD192570D98F4DBULL,
		0xE04377F323C8FD55ULL,
		0x41209880695B4476ULL,
		0xE6D0C9ED31FFB7C1ULL,
		0x2106B79B8989A9B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0256087EFB1C5EULL,
		0x1B80C214F66F203CULL,
		0x76CA7B926817B6FBULL,
		0xF7A324AE1B31E9B7ULL,
		0xC086EFE64791FAABULL,
		0x82413100D2B688EDULL,
		0xCDA193DA63FF6F82ULL,
		0x420D6F371313536FULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF2E55F02DADE64FULL,
		0x484B0BEF61577EE9ULL,
		0xDD708C5D3D4B2CDCULL,
		0x40B5A4713EBD9882ULL,
		0x757085B40CF55DE1ULL,
		0x715D2F1D482AE67DULL,
		0xFE8EF84F200CAF91ULL,
		0x2938E32E6343F2ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E5CABE05B5BCC9EULL,
		0x909617DEC2AEFDD3ULL,
		0xBAE118BA7A9659B8ULL,
		0x816B48E27D7B3105ULL,
		0xEAE10B6819EABBC2ULL,
		0xE2BA5E3A9055CCFAULL,
		0xFD1DF09E40195F22ULL,
		0x5271C65CC687E559ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0A977FF224C7C97ULL,
		0x1B857F46B8547C98ULL,
		0x630B94C6AD7DCFDEULL,
		0xD5C256228D9E4F77ULL,
		0x938B91342705D5C9ULL,
		0x96275AB37FF81AA1ULL,
		0xD426B88A35E0E982ULL,
		0x2EEF482F9E18AED3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8152EFFE4498F92EULL,
		0x370AFE8D70A8F931ULL,
		0xC617298D5AFB9FBCULL,
		0xAB84AC451B3C9EEEULL,
		0x271722684E0BAB93ULL,
		0x2C4EB566FFF03543ULL,
		0xA84D71146BC1D305ULL,
		0x5DDE905F3C315DA7ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C7CB1F3A08DEEEAULL,
		0x4B5178648A4E6554ULL,
		0x62F956427AEB8D49ULL,
		0xD003F39D36CFFC39ULL,
		0xC6C15BFA4EC842FEULL,
		0x15B9517252DDE8CCULL,
		0x7B7DC60352683B72ULL,
		0x3394DE66EB4639F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F963E7411BDDD4ULL,
		0x96A2F0C9149CCAA8ULL,
		0xC5F2AC84F5D71A92ULL,
		0xA007E73A6D9FF872ULL,
		0x8D82B7F49D9085FDULL,
		0x2B72A2E4A5BBD199ULL,
		0xF6FB8C06A4D076E4ULL,
		0x6729BCCDD68C73E4ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8BA22C9789D6FF5ULL,
		0x5DA5F39BAA990B39ULL,
		0x3215B307B9DE2179ULL,
		0x64BA7FA8FAC93784ULL,
		0x1E099A6ADF3518A5ULL,
		0x54BC1D532B152C9DULL,
		0x2217E77324C9C8A0ULL,
		0x0C35F56CAFAD615BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71744592F13ADFEAULL,
		0xBB4BE73755321673ULL,
		0x642B660F73BC42F2ULL,
		0xC974FF51F5926F08ULL,
		0x3C1334D5BE6A314AULL,
		0xA9783AA6562A593AULL,
		0x442FCEE649939140ULL,
		0x186BEAD95F5AC2B6ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94ECB45050665905ULL,
		0x2D7976CB893FD89CULL,
		0xF7CB6199F3805E25ULL,
		0xCF15829046248A08ULL,
		0x0AEC833FE91F95FEULL,
		0xDFCDDAC841A6D10AULL,
		0xCB6D716F9C51DEEFULL,
		0x34E0542C94481D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D968A0A0CCB20AULL,
		0x5AF2ED97127FB139ULL,
		0xEF96C333E700BC4AULL,
		0x9E2B05208C491411ULL,
		0x15D9067FD23F2BFDULL,
		0xBF9BB590834DA214ULL,
		0x96DAE2DF38A3BDDFULL,
		0x69C0A85928903B0BULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBEC03CB4B579F85ULL,
		0x090DBA518E2BA797ULL,
		0x48711A60C8D292F9ULL,
		0x8C1FA1707E0A309BULL,
		0x8E8C8AA620AF3B71ULL,
		0xA29D5F84B62B8413ULL,
		0xBD191585D8E358EFULL,
		0x3B17EA61A5B5EF29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D8079696AF3F0AULL,
		0x121B74A31C574F2FULL,
		0x90E234C191A525F2ULL,
		0x183F42E0FC146136ULL,
		0x1D19154C415E76E3ULL,
		0x453ABF096C570827ULL,
		0x7A322B0BB1C6B1DFULL,
		0x762FD4C34B6BDE53ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AB75446B473BE3BULL,
		0x2B67A8A0F1642EA6ULL,
		0xEE8904345471A938ULL,
		0x616C3A913B8C224EULL,
		0x09C7AB1BE3CFA412ULL,
		0x4A7FF47B131DE871ULL,
		0x22BE5D2C4DE5C5A1ULL,
		0x19B2DB4BE446A3BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556EA88D68E77C76ULL,
		0x56CF5141E2C85D4CULL,
		0xDD120868A8E35270ULL,
		0xC2D875227718449DULL,
		0x138F5637C79F4824ULL,
		0x94FFE8F6263BD0E2ULL,
		0x457CBA589BCB8B42ULL,
		0x3365B697C88D477AULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x487DE946A144464CULL,
		0xCD0F12BEAEA383E2ULL,
		0x4C61364EADDF5634ULL,
		0x57B7C30610F7D35CULL,
		0xDF2362076EBD8463ULL,
		0xEF1F950BA5144588ULL,
		0x2E6B37A4E88172A9ULL,
		0x386CA6616FC5FB7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90FBD28D42888C98ULL,
		0x9A1E257D5D4707C4ULL,
		0x98C26C9D5BBEAC69ULL,
		0xAF6F860C21EFA6B8ULL,
		0xBE46C40EDD7B08C6ULL,
		0xDE3F2A174A288B11ULL,
		0x5CD66F49D102E553ULL,
		0x70D94CC2DF8BF6FEULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30D8EA360E5E7241ULL,
		0x688976276EAB0E3CULL,
		0xE1727CAFB2716B63ULL,
		0x1A51E124A8A5C37BULL,
		0x1449406DF5C5BD52ULL,
		0x4E5CD9EDADFDEEE1ULL,
		0x99609A7C86578AE3ULL,
		0x20A2522E70599268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61B1D46C1CBCE482ULL,
		0xD112EC4EDD561C78ULL,
		0xC2E4F95F64E2D6C6ULL,
		0x34A3C249514B86F7ULL,
		0x289280DBEB8B7AA4ULL,
		0x9CB9B3DB5BFBDDC2ULL,
		0x32C134F90CAF15C6ULL,
		0x4144A45CE0B324D1ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC02EE4316378FE82ULL,
		0xEF763EFE8AD9C49EULL,
		0xAF464B73953CA177ULL,
		0x8B9BF7A3391C4C38ULL,
		0xA84EEFA3B409B5CFULL,
		0xBEB28BB5FC7036D6ULL,
		0x898AEAFD231C933AULL,
		0x0C5569AB7941489FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805DC862C6F1FD04ULL,
		0xDEEC7DFD15B3893DULL,
		0x5E8C96E72A7942EFULL,
		0x1737EF4672389871ULL,
		0x509DDF4768136B9FULL,
		0x7D65176BF8E06DADULL,
		0x1315D5FA46392675ULL,
		0x18AAD356F282913FULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x075D830F086B01E1ULL,
		0xB5FCE03F31F6535CULL,
		0xC679AEB5870FBABDULL,
		0x8A9D94FE6F0C705BULL,
		0x6E9EBFB276366F2DULL,
		0x68202856B0D46367ULL,
		0x5AEAFE5BEAE1E4AEULL,
		0x1AA5FD4888F9E54EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EBB061E10D603C2ULL,
		0x6BF9C07E63ECA6B8ULL,
		0x8CF35D6B0E1F757BULL,
		0x153B29FCDE18E0B7ULL,
		0xDD3D7F64EC6CDE5BULL,
		0xD04050AD61A8C6CEULL,
		0xB5D5FCB7D5C3C95CULL,
		0x354BFA9111F3CA9CULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8808893A17F5450ULL,
		0x87CF694F2A5934ACULL,
		0xE61BBAB4E74BA284ULL,
		0x22DF8905A727D8C8ULL,
		0x5FD7FF7FAF8F1137ULL,
		0xCA3EFD5D08F8E9E6ULL,
		0xDAA86F84DECFABBDULL,
		0x128618F4E8C3E66BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD101112742FEA8A0ULL,
		0x0F9ED29E54B26959ULL,
		0xCC377569CE974509ULL,
		0x45BF120B4E4FB191ULL,
		0xBFAFFEFF5F1E226EULL,
		0x947DFABA11F1D3CCULL,
		0xB550DF09BD9F577BULL,
		0x250C31E9D187CCD7ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}