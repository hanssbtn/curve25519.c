#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0x24B4360ABCF6C2D8ULL,
		0xFC89421B6A9D5775ULL,
		0x079908E0193D39CDULL,
		0x22352ECD68F439AFULL,
		0x9E11ABD0A6886D21ULL,
		0x3C6500EBCC1F4FC5ULL,
		0x9A15142B2324734EULL,
		0x619B296470C8EA83ULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0xC890F057AC92025DULL,
		0x85E095F46C47C584ULL,
		0x7B4758E066DA07D4ULL,
		0x4C8F535069387B34ULL,
		0x1BFFFECBD027E88CULL,
		0x83BC0512DF9196D4ULL,
		0x409E55074127076FULL,
		0x98DE6783DE5A7ECBULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x5C2345B31064C07BULL,
		0x76A8AC26FE5591F0ULL,
		0x8C51AFFFB26331F9ULL,
		0xD5A5DB7CFFBBBE7AULL,
		0x8211AD04D6608494ULL,
		0xB8A8FBD8EC8DB8F1ULL,
		0x5976BF23E1FD6BDEULL,
		0xC8BCC1E0926E6BB8ULL
	}};
	printf("Underflow\n");
	int sign = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5385A2373A1ED2A1ULL,
		0x3D2A35E600A7DD93ULL,
		0x96482A72F1EC3996ULL,
		0x80C1F2593FBC5DD9ULL,
		0xA1C4BF539A4AA214ULL,
		0xC43F6FBD4864A437ULL,
		0x44F5F1AC356B29C6ULL,
		0x16D493DCA8878C9DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22179B7507591F9ULL,
		0x051BFCDE88F16CC8ULL,
		0x3A9FEE83F28D03B1ULL,
		0x2C9FD435C40D2A63ULL,
		0x3218CA809651AFC2ULL,
		0x1034B350AD0B30E7ULL,
		0x7F72CEDBB7C6764FULL,
		0x6B4587435908776FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7164287FE9A940A8ULL,
		0x380E390777B670CAULL,
		0x5BA83BEEFF5F35E5ULL,
		0x54221E237BAF3376ULL,
		0x6FABF4D303F8F252ULL,
		0xB40ABC6C9B597350ULL,
		0xC58322D07DA4B377ULL,
		0xAB8F0C994F7F152DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFD099BFF8C1A9604ULL,
		0xF56EA0FC53E57F48ULL,
		0x5CCD8FFEB49369B0ULL,
		0xD12860DD1EDE401DULL,
		0xDF84FD0ACE1FB937ULL,
		0x09995DEBE4631553ULL,
		0xFF03AADFD17B806CULL,
		0xBE5B696DC4DD33D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EEE58ECC5C422B9ULL,
		0xEEA76E3E2A240CA2ULL,
		0x1CE1F23E216D2A2FULL,
		0x31E3BF06E1802C23ULL,
		0x1F32644C8EDC50CEULL,
		0x76B8C2B132A45C86ULL,
		0x7E6BF534C183B8B9ULL,
		0x8B810D30332B1F34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE1B4312C656734BULL,
		0x06C732BE29C172A6ULL,
		0x3FEB9DC093263F81ULL,
		0x9F44A1D63D5E13FAULL,
		0xC05298BE3F436869ULL,
		0x92E09B3AB1BEB8CDULL,
		0x8097B5AB0FF7C7B2ULL,
		0x32DA5C3D91B214A2ULL
	}};
	sign = 0;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0F2D6C6602C45ED3ULL,
		0x62385B8FA1B89015ULL,
		0xA69FF76DDCC8F329ULL,
		0x1E4E1B6BB624E158ULL,
		0x7F54D4A8F65C0FC0ULL,
		0x7B968DD57A2580D7ULL,
		0x02FD3CEA86AC4863ULL,
		0x3288D08A044D002CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB34C101D1D805E30ULL,
		0xA03D85953B55757BULL,
		0x256151736C21EC00ULL,
		0xAC38BAB569FC398AULL,
		0x3C56D316EA0343B3ULL,
		0xDFCF06A9CBB17A99ULL,
		0x91E2CCFD85210DB2ULL,
		0x0BDA21BCC45B11D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BE15C48E54400A3ULL,
		0xC1FAD5FA66631A99ULL,
		0x813EA5FA70A70728ULL,
		0x721560B64C28A7CEULL,
		0x42FE01920C58CC0CULL,
		0x9BC7872BAE74063EULL,
		0x711A6FED018B3AB0ULL,
		0x26AEAECD3FF1EE54ULL
	}};
	sign = 0;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x016F81FBAFA676C0ULL,
		0x16AA62F29EE4C396ULL,
		0x4C5B4769D44FFF3CULL,
		0x47EBE317CB5C1CB0ULL,
		0x81356E444F94F71AULL,
		0x3AFC065724A3B3CAULL,
		0x17AF0E216048A1CDULL,
		0xECC0308A13E52E29ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5403D05532FD23EEULL,
		0x880A6D8DE3B602C0ULL,
		0xDBD35C0A0EE739B7ULL,
		0x9BF1C6E5533054EDULL,
		0xBF6455FF8D82F9BAULL,
		0xDC4A2EB633698A3CULL,
		0xC24309858CDCD01AULL,
		0xC91877D14A8BF40CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD6BB1A67CA952D2ULL,
		0x8E9FF564BB2EC0D5ULL,
		0x7087EB5FC568C584ULL,
		0xABFA1C32782BC7C2ULL,
		0xC1D11844C211FD5FULL,
		0x5EB1D7A0F13A298DULL,
		0x556C049BD36BD1B2ULL,
		0x23A7B8B8C9593A1CULL
	}};
	sign = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDB5A8CB6CDF314BBULL,
		0xD3DC37FC05429BF2ULL,
		0xAE1380B9761D75A4ULL,
		0x19AE295D15875D2DULL,
		0x5FBE02E27F5A6103ULL,
		0x93AC634FBDF7D035ULL,
		0xD40BC2C53B384881ULL,
		0x42D26F2E184F963AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF1DFA245845C6CEULL,
		0x5B6BF047BEC7F6D3ULL,
		0xE63E2C02A36868ECULL,
		0x10E181AEC5250495ULL,
		0x84511D7E72B15DFEULL,
		0x7BEEF7806E1DF364ULL,
		0x2F266D45022B7F4BULL,
		0x438FB6E36D583711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C3C929275AD4DEDULL,
		0x787047B4467AA51FULL,
		0xC7D554B6D2B50CB8ULL,
		0x08CCA7AE50625897ULL,
		0xDB6CE5640CA90305ULL,
		0x17BD6BCF4FD9DCD0ULL,
		0xA4E55580390CC936ULL,
		0xFF42B84AAAF75F29ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0EF8BF4DE16DE16ULL,
		0x2686199994F99C94ULL,
		0x63E6ADA1D3971B7DULL,
		0x8650BF46931F2ECAULL,
		0xAF7339398D6D0681ULL,
		0x3148EAA4294A709FULL,
		0xB7D6B2F80197C787ULL,
		0x10EB91AE999F91B2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F74BB169E6463A3ULL,
		0xD26A02999BB1E34EULL,
		0xBD69D6AAA186BD89ULL,
		0xB0E049E027A26052ULL,
		0xD9B4365FDD3C2C52ULL,
		0x98FA84A9ACCE7686ULL,
		0xE2C25F0B0DC88660ULL,
		0x395A096D8C643026ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x717AD0DE3FB27A73ULL,
		0x541C16FFF947B946ULL,
		0xA67CD6F732105DF3ULL,
		0xD57075666B7CCE77ULL,
		0xD5BF02D9B030DA2EULL,
		0x984E65FA7C7BFA18ULL,
		0xD51453ECF3CF4126ULL,
		0xD79188410D3B618BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55620475D29D7EA3ULL,
		0x8408983B73AFD4A0ULL,
		0x9971CBD0D51F5C20ULL,
		0xD7962F6A5CF8BCB5ULL,
		0xAEF26335B6099089ULL,
		0xB6ED8614EA5F78B1ULL,
		0x8C43A9E1B81A382CULL,
		0x9A3305ADE5FEA1E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9131BF6E831CC556ULL,
		0x076C1C5BEEB92044ULL,
		0xA2BE21601F276FBCULL,
		0x837AA5B31106B825ULL,
		0x3ACF0C0FEFA373E1ULL,
		0x2698D488C8E79B51ULL,
		0x86DFDB3E4E8250ABULL,
		0x28746785048EA21FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC43045074F80B94DULL,
		0x7C9C7BDF84F6B45BULL,
		0xF6B3AA70B5F7EC64ULL,
		0x541B89B74BF2048FULL,
		0x74235725C6661CA8ULL,
		0x9054B18C2177DD60ULL,
		0x0563CEA36997E781ULL,
		0x71BE9E28E16FFFC4ULL
	}};
	sign = 0;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x60C82968F7C2FE76ULL,
		0x251265DC2DB02B59ULL,
		0xCB1991ECD9B0FDC1ULL,
		0x7BCD79D4A2862DA7ULL,
		0x7908633D9ECA85DAULL,
		0x6FF4CAD5078B5D1CULL,
		0x2EC6779372CB2D80ULL,
		0xBC92B8CA24647FD9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE4DD8DFC4AAD31ULL,
		0x8163C26F66552526ULL,
		0x0A5EAF048795AA76ULL,
		0x00B30C1D620A4957ULL,
		0xF3FBD2A74D214EA5ULL,
		0x8355D35874BE858CULL,
		0x4A33CFB291692666ULL,
		0x935007FA46EC4EA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55E34BDAFB785145ULL,
		0xA3AEA36CC75B0633ULL,
		0xC0BAE2E8521B534AULL,
		0x7B1A6DB7407BE450ULL,
		0x850C909651A93735ULL,
		0xEC9EF77C92CCD78FULL,
		0xE492A7E0E1620719ULL,
		0x2942B0CFDD783135ULL
	}};
	sign = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x97BFFE5BC2420F0BULL,
		0xC6EFEDF3CB4CB501ULL,
		0x887FFC892F350A3CULL,
		0x0ED7193BF019D444ULL,
		0xC13E2BA884EC82DAULL,
		0xA7DC52D8EE932884ULL,
		0x27FD5AB23E931CA2ULL,
		0x71821401D89B0112ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB3F09B873A62FFULL,
		0x7147D8504C2C1BB0ULL,
		0x42F4CC60FA90CA0BULL,
		0x1B4157658CB9E1EDULL,
		0x48A7F549482913B3ULL,
		0x5FBB01EDD49449A1ULL,
		0xCA0E0E23F504D0B8ULL,
		0x7F5173269E2D753CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080C0DC03B07AC0CULL,
		0x55A815A37F209951ULL,
		0x458B302834A44031ULL,
		0xF395C1D6635FF257ULL,
		0x7896365F3CC36F26ULL,
		0x482150EB19FEDEE3ULL,
		0x5DEF4C8E498E4BEAULL,
		0xF230A0DB3A6D8BD5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8BF6E5AEC86A9CF4ULL,
		0x9FBCE5C0A3E52CAFULL,
		0x391D6BA1F4E61986ULL,
		0x756CBF0565E649F1ULL,
		0x2E22A8416B874AA3ULL,
		0x0735AF202CC8C726ULL,
		0x10389D9A13A0BDA0ULL,
		0xBE5FAD703034B69DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD27A14B99C690BULL,
		0xED00610CC51EA8D9ULL,
		0xAF334989A7F7FE51ULL,
		0x8C719603F7830514ULL,
		0x1D7513AD3D907D0FULL,
		0x11EE6833D3801C39ULL,
		0xE673AD0254458ACEULL,
		0xBBD7287518451E81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E246B9A0ECE33E9ULL,
		0xB2BC84B3DEC683D6ULL,
		0x89EA22184CEE1B34ULL,
		0xE8FB29016E6344DCULL,
		0x10AD94942DF6CD93ULL,
		0xF54746EC5948AAEDULL,
		0x29C4F097BF5B32D1ULL,
		0x028884FB17EF981BULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2FD63E809476E6D2ULL,
		0xC5B5ADA51F8D8219ULL,
		0x8E48F719BB2E92A8ULL,
		0x45222E9A44C77896ULL,
		0xE608A7CDD265BC40ULL,
		0x6ABE484C4A141E58ULL,
		0x14824A7B620EEDDDULL,
		0x1D887CA51B607285ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBEA5856B58F4E42ULL,
		0xF0B79E57672D2659ULL,
		0x17A75874525003E0ULL,
		0xC2577339E244CEABULL,
		0x1F29820CECF4BBA0ULL,
		0x71EECB73B66D8787ULL,
		0x3AD1FC3FD6D38782ULL,
		0xAD8C23A8D0B2DFEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33EBE629DEE79890ULL,
		0xD4FE0F4DB8605BBFULL,
		0x76A19EA568DE8EC7ULL,
		0x82CABB606282A9EBULL,
		0xC6DF25C0E571009FULL,
		0xF8CF7CD893A696D1ULL,
		0xD9B04E3B8B3B665AULL,
		0x6FFC58FC4AAD9297ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBB8E7FD5A31FB4C1ULL,
		0x0FD161C541114BFFULL,
		0xD005754ABBB38489ULL,
		0x1D765DDD6DE0B1A2ULL,
		0x6DE4E24F798CB7A5ULL,
		0x368F6E4C74821C3AULL,
		0xD240832F3B9F60A7ULL,
		0x5D81390B44FE08EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A108E5270E6E1AULL,
		0x70F039A643C8D1C8ULL,
		0xA153BCFE81E08C42ULL,
		0x9D6137B56DC4EC74ULL,
		0x1133CB7649BFA014ULL,
		0x9C22E0F7F771415DULL,
		0x426284F64C12DB7BULL,
		0xBDDE7836981A12BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54ED76F07C1146A7ULL,
		0x9EE1281EFD487A37ULL,
		0x2EB1B84C39D2F846ULL,
		0x80152628001BC52EULL,
		0x5CB116D92FCD1790ULL,
		0x9A6C8D547D10DADDULL,
		0x8FDDFE38EF8C852BULL,
		0x9FA2C0D4ACE3F630ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x199FE72A4EBDCCE8ULL,
		0x37104DA46F3F5D33ULL,
		0xF8A8E6508FD95A06ULL,
		0x82C4F7F09699FB83ULL,
		0x27D92F38FAA1636EULL,
		0xCE5701FE40CFF54EULL,
		0x7E14A6879BB26794ULL,
		0x2091C72ED7FF3564ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1873FC3FFBF0936ULL,
		0xC93F78E751CE754CULL,
		0xC7323A5896C7299FULL,
		0x395BE0ACEB97C30FULL,
		0x51437B8E303515D1ULL,
		0xAC056270C33EDDBEULL,
		0x5B8841AE096387C1ULL,
		0x75CDD07CD1861196ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4818A7664EFEC3B2ULL,
		0x6DD0D4BD1D70E7E6ULL,
		0x3176ABF7F9123066ULL,
		0x49691743AB023874ULL,
		0xD695B3AACA6C4D9DULL,
		0x22519F8D7D91178FULL,
		0x228C64D9924EDFD3ULL,
		0xAAC3F6B2067923CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x869FD72072D82515ULL,
		0x180819A8C35E4EA9ULL,
		0xA4BD472E8C0BEA44ULL,
		0xAEC668D8024CE2BAULL,
		0x0FF7876E506502C2ULL,
		0xB768A0576DC9A3E2ULL,
		0xBA8C657209449BB5ULL,
		0x5F0503E5E2B9B543ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0438054EC9B6C3A2ULL,
		0x13AC68AFA81A76E7ULL,
		0xCEECC0F8CDFAA2B3ULL,
		0xCD6261BD6CE63BA4ULL,
		0xDABF27952A582193ULL,
		0xBD376C42D07C1A0DULL,
		0xD42AC311667BE0CFULL,
		0x96679FE7BD083A9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8267D1D1A9216173ULL,
		0x045BB0F91B43D7C2ULL,
		0xD5D08635BE114791ULL,
		0xE164071A9566A715ULL,
		0x35385FD9260CE12EULL,
		0xFA3134149D4D89D4ULL,
		0xE661A260A2C8BAE5ULL,
		0xC89D63FE25B17AA6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF39868DE30CF80F7ULL,
		0x13DD724F227192D3ULL,
		0xCA2B6292D1925E55ULL,
		0x1807CC77AD578C91ULL,
		0x7B1A4811BDB15D40ULL,
		0x85549C31CFDE0B31ULL,
		0xC66C835C24EDC11CULL,
		0x606692A509148FF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2986AD4158D180F9ULL,
		0x28A000381DC5348AULL,
		0x8F48FFC27DE7C2A5ULL,
		0xF466FA159FC7B333ULL,
		0xE3E191A780628D7BULL,
		0xDBBE8BA824065D54ULL,
		0x56DF6E5BB8461C4FULL,
		0x0D66E089F848ECB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA11BB9CD7FDFFFEULL,
		0xEB3D721704AC5E49ULL,
		0x3AE262D053AA9BAFULL,
		0x23A0D2620D8FD95EULL,
		0x9738B66A3D4ECFC4ULL,
		0xA9961089ABD7ADDCULL,
		0x6F8D15006CA7A4CCULL,
		0x52FFB21B10CBA33AULL
	}};
	sign = 0;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F5C8F95E470C6D3ULL,
		0x45F2D40D23861FCAULL,
		0x1601E82CF2D7DCF7ULL,
		0x1FFE7D62AA82C3D5ULL,
		0x27EA9CEAE15CB897ULL,
		0xB38192CE4B39CF84ULL,
		0x6CED4211FBB61817ULL,
		0xCE1CA8457E910F48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C769D1AACDE1AD8ULL,
		0x49540BBFA2CE5DA4ULL,
		0x47DC759571DB9115ULL,
		0x9D5068CEBD04477BULL,
		0x38929D21189D49E0ULL,
		0xAB82BD06F22A8160ULL,
		0xA796EBF4C34DFA14ULL,
		0x19FF6F75247F583BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2E5F27B3792ABFBULL,
		0xFC9EC84D80B7C225ULL,
		0xCE25729780FC4BE1ULL,
		0x82AE1493ED7E7C59ULL,
		0xEF57FFC9C8BF6EB6ULL,
		0x07FED5C7590F4E23ULL,
		0xC556561D38681E03ULL,
		0xB41D38D05A11B70CULL
	}};
	sign = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1E76DFE75A1787DDULL,
		0xB10F8FE22961DA79ULL,
		0xE89923AB629A2266ULL,
		0xB7B0A3506C4F9136ULL,
		0xDEFA47D84010639CULL,
		0xDDA192335D2AB9CBULL,
		0x57F8DFB30C2636EEULL,
		0xC45EC7174CD2338FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1269927A347FB5C9ULL,
		0xA194692DF8489AD1ULL,
		0x7ED8F7E23F9EBCC1ULL,
		0x52FE4569A370AB25ULL,
		0x2E5F1041DAEC26B8ULL,
		0x80B1F1E0B96AA76BULL,
		0x20B5C69275AFE10EULL,
		0x979D5D1ACF3EF35FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0D4D6D2597D214ULL,
		0x0F7B26B431193FA8ULL,
		0x69C02BC922FB65A5ULL,
		0x64B25DE6C8DEE611ULL,
		0xB09B379665243CE4ULL,
		0x5CEFA052A3C01260ULL,
		0x37431920967655E0ULL,
		0x2CC169FC7D934030ULL
	}};
	sign = 0;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x13EC82BF8CDE8B97ULL,
		0x3BEC4CD6882EFE49ULL,
		0x3F3FA0B4590EBD91ULL,
		0x2C9D73462F0884D6ULL,
		0xD647942E5231C3B0ULL,
		0x7BDB071CA74050BBULL,
		0x9D3D808564A8C661ULL,
		0x0064A3FE00CCCE27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F485C870F26BC7AULL,
		0x8AA2C4F83CEF3C43ULL,
		0xAC60132CBEF6E079ULL,
		0x76691450FC622CB4ULL,
		0x19702B7BFBAEAF27ULL,
		0x66C0D59FB9E2D604ULL,
		0x8CE323A49AB84A6FULL,
		0xB9286A1936C621E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4A426387DB7CF1DULL,
		0xB14987DE4B3FC205ULL,
		0x92DF8D879A17DD17ULL,
		0xB6345EF532A65821ULL,
		0xBCD768B256831488ULL,
		0x151A317CED5D7AB7ULL,
		0x105A5CE0C9F07BF2ULL,
		0x473C39E4CA06AC42ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x51840F863592CE69ULL,
		0xBA34BB39E8E055C1ULL,
		0x9577673F3B037396ULL,
		0x2F047EFCEE37C89EULL,
		0x3C32545F8A64FA6CULL,
		0x07FC1584C3E994C1ULL,
		0x3213C9DA7CD89DFBULL,
		0xD37F752D24AD704AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DDECCCEA849EBFEULL,
		0xD7E2AD60DBC3CA47ULL,
		0x1CCEB340B8B92F29ULL,
		0x94DCAB8C64EABF80ULL,
		0x4B216B2CDBEBA433ULL,
		0x88C93903D5BA0BB3ULL,
		0xA996F4B5FADF9413ULL,
		0xBACD8E3004271EF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33A542B78D48E26BULL,
		0xE2520DD90D1C8B7AULL,
		0x78A8B3FE824A446CULL,
		0x9A27D370894D091EULL,
		0xF110E932AE795638ULL,
		0x7F32DC80EE2F890DULL,
		0x887CD52481F909E7ULL,
		0x18B1E6FD20865152ULL
	}};
	sign = 0;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7EAEC11884D93DE8ULL,
		0xA61AE170B03F0008ULL,
		0x68F730FCE1B8567BULL,
		0x9BCE6548740C14D3ULL,
		0x517556E039E8271AULL,
		0x7FF38029753785B2ULL,
		0x79F27FA6720650DFULL,
		0x2AD1F916B59D52D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06AAEDC781C9CA7ULL,
		0x11F7BC5B20BFF373ULL,
		0x5F4D52774D0EB258ULL,
		0xD93359A1C47FAAC3ULL,
		0x69536460DC27EAC5ULL,
		0xE33D965D5FA27ACBULL,
		0xB577EB3BD2BA7A31ULL,
		0x0A403CFBFB5F04D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE44123C0CBCA141ULL,
		0x942325158F7F0C94ULL,
		0x09A9DE8594A9A423ULL,
		0xC29B0BA6AF8C6A10ULL,
		0xE821F27F5DC03C54ULL,
		0x9CB5E9CC15950AE6ULL,
		0xC47A946A9F4BD6ADULL,
		0x2091BC1ABA3E4E03ULL
	}};
	sign = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x32466655E542760AULL,
		0x9F47103219C651B2ULL,
		0x31CD72F406690E0FULL,
		0x984C3FFEC2265163ULL,
		0x9DFDD48D2FC00772ULL,
		0x06FE82727876A6D3ULL,
		0x46DB25B9D2AFB97BULL,
		0x27A18A0D1C0BF58FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x337D78AADB05A20EULL,
		0xEFCD983F877932E9ULL,
		0x13951351E35DE1B1ULL,
		0xF86B468F3D454C9EULL,
		0xB09A7F1794E37E87ULL,
		0xA09E00F213026DEAULL,
		0x01A562027E5474A9ULL,
		0x6AA19A1DC7711827ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEC8EDAB0A3CD3FCULL,
		0xAF7977F2924D1EC8ULL,
		0x1E385FA2230B2C5DULL,
		0x9FE0F96F84E104C5ULL,
		0xED6355759ADC88EAULL,
		0x66608180657438E8ULL,
		0x4535C3B7545B44D1ULL,
		0xBCFFEFEF549ADD68ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x10DDEF754F0D6AFAULL,
		0x09E3D7CF84C97447ULL,
		0x66766C7A69062033ULL,
		0x36F82273865E0659ULL,
		0x1ED374EE1785D170ULL,
		0xB9615911D534F574ULL,
		0xD1212DB8667346D5ULL,
		0x2DD5F4E3B7A27364ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB6EA25965EBC8FULL,
		0xB7D1FDF419E5184CULL,
		0xF65EA90DB7035505ULL,
		0x1594F45214A6E80CULL,
		0xD525AE6D23521973ULL,
		0x601EF180AE09E916ULL,
		0xD0758D178A1FF5FBULL,
		0x750F82FC2A5F048DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF327054FB8AEAE6BULL,
		0x5211D9DB6AE45BFAULL,
		0x7017C36CB202CB2DULL,
		0x21632E2171B71E4CULL,
		0x49ADC680F433B7FDULL,
		0x59426791272B0C5DULL,
		0x00ABA0A0DC5350DAULL,
		0xB8C671E78D436ED7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2216DB3F70959D67ULL,
		0x29584E1DE4266894ULL,
		0x4ACA9C6AE739F410ULL,
		0xF8180E1D26AAC8C6ULL,
		0x9655559AB45F5B33ULL,
		0x33BA26D3BC424CE9ULL,
		0x51239C6B7288FCB0ULL,
		0x19E766573B33248EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB8265DBC9CAC388ULL,
		0x3985261074D5E15BULL,
		0xA9A4A4C4279E201FULL,
		0x9644C74D47A73D7CULL,
		0x7E87926A9644C6B7ULL,
		0x8EFE6557B7838B47ULL,
		0xC379F9150CBF654FULL,
		0x54BAE948030B2B30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66947563A6CAD9DFULL,
		0xEFD3280D6F508738ULL,
		0xA125F7A6BF9BD3F0ULL,
		0x61D346CFDF038B49ULL,
		0x17CDC3301E1A947CULL,
		0xA4BBC17C04BEC1A2ULL,
		0x8DA9A35665C99760ULL,
		0xC52C7D0F3827F95DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD83F537D8DADA3D9ULL,
		0x86AF2C740596DB21ULL,
		0x6C66162119E783B5ULL,
		0xA895490837DB7A1BULL,
		0xB9AA5EBCFB7013C2ULL,
		0xA857495B44B92F09ULL,
		0xCB3193D3BCDB73D3ULL,
		0x70A93EA7DD50F504ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x313E9C6C6DFF9402ULL,
		0x933B00C91FE090BDULL,
		0x1387C84DA9DF0449ULL,
		0x138C9DEFFD1BF15CULL,
		0x9E310BD18B097419ULL,
		0xA6AEFE064496DF68ULL,
		0x27F56098A48398D5ULL,
		0x7F4FCB50E7A16620ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA700B7111FAE0FD7ULL,
		0xF3742BAAE5B64A64ULL,
		0x58DE4DD370087F6BULL,
		0x9508AB183ABF88BFULL,
		0x1B7952EB70669FA9ULL,
		0x01A84B5500224FA1ULL,
		0xA33C333B1857DAFEULL,
		0xF1597356F5AF8EE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFCAF4B8A54636996ULL,
		0x25A859185D224CF2ULL,
		0x601EFEE25052D9D6ULL,
		0x9E0A787951C9F114ULL,
		0x26C3BF5CAD55029BULL,
		0x4801FFD58C1B8653ULL,
		0x7C2094C973E27A48ULL,
		0x9FEA1DF191B4EE87ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE759895151CF7E3ULL,
		0x9D536B2B11ABA391ULL,
		0xF6F3AA8224888992ULL,
		0x5C343EA47E4B5762ULL,
		0xF87C0195CDE74E36ULL,
		0x2E3AD47A7C885813ULL,
		0x02A8767CCBB7E445ULL,
		0x2F499CC7882841EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E39B2F53F4671B3ULL,
		0x8854EDED4B76A961ULL,
		0x692B54602BCA5043ULL,
		0x41D639D4D37E99B1ULL,
		0x2E47BDC6DF6DB465ULL,
		0x19C72B5B0F932E3FULL,
		0x79781E4CA82A9603ULL,
		0x70A0812A098CAC98ULL
	}};
	sign = 0;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE3C94BBEA786B491ULL,
		0xA7560D6548C56DA3ULL,
		0x93D7135184A96F7CULL,
		0xF28229381560D600ULL,
		0x48EF82B2BCE961C1ULL,
		0xC67B3A2B912BD0B5ULL,
		0x338ECC870E38F289ULL,
		0xBD1ADCC06C856007ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0698AC22293BAEC6ULL,
		0xB60D211CBD455E7FULL,
		0xDBFDDF4DD3F2BDCAULL,
		0x8FCF9CB1D15D7501ULL,
		0x6E8BC0C21B0596B6ULL,
		0xC42EA057A6E93B16ULL,
		0x1A45844BC48E91FFULL,
		0xD24DA8BF15DF32DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD309F9C7E4B05CBULL,
		0xF148EC488B800F24ULL,
		0xB7D93403B0B6B1B1ULL,
		0x62B28C86440360FEULL,
		0xDA63C1F0A1E3CB0BULL,
		0x024C99D3EA42959EULL,
		0x1949483B49AA608AULL,
		0xEACD340156A62D28ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC901D8CB3AFB8036ULL,
		0x1BCD935727DE12FDULL,
		0x82809EDC2E8D557EULL,
		0x86EBCBEBDE1EC487ULL,
		0xA3DDAD93B325AA56ULL,
		0x95F69811806691FCULL,
		0x5DD593140B80BD59ULL,
		0xFD2E73566A7802CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CFA3D1C045C8AFULL,
		0x0C40786F32F6ED53ULL,
		0x1435BD52788E05F0ULL,
		0xAD5C163185504321ULL,
		0x8B5D2AF4138E0238ULL,
		0x2311D458B066B629ULL,
		0x9EB841EDF6E2751DULL,
		0x7E6730D7FA3A7722ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF73234F97AB5B787ULL,
		0x0F8D1AE7F4E725A9ULL,
		0x6E4AE189B5FF4F8EULL,
		0xD98FB5BA58CE8166ULL,
		0x1880829F9F97A81DULL,
		0x72E4C3B8CFFFDBD3ULL,
		0xBF1D5126149E483CULL,
		0x7EC7427E703D8BABULL
	}};
	sign = 0;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82138818523AF072ULL,
		0xEA59218C0214E235ULL,
		0xC67E1BF69BAF5E26ULL,
		0xB65500FFDA88AB19ULL,
		0xD02CC43976097520ULL,
		0x4EE6466C5D686378ULL,
		0x3816DD4770849985ULL,
		0x5F68C1078A802C33ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14F1C0D8ED8B8FB7ULL,
		0x75B3551B8D645E98ULL,
		0x5690377B1F1A6C31ULL,
		0x3AB40B32D5C2EF32ULL,
		0x2A8488FEF776AB13ULL,
		0x696B89E63A59F71DULL,
		0xD7CA8A42CB65B90EULL,
		0xB5DADEDB53C50054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D21C73F64AF60BBULL,
		0x74A5CC7074B0839DULL,
		0x6FEDE47B7C94F1F5ULL,
		0x7BA0F5CD04C5BBE7ULL,
		0xA5A83B3A7E92CA0DULL,
		0xE57ABC86230E6C5BULL,
		0x604C5304A51EE076ULL,
		0xA98DE22C36BB2BDEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0896F60A060E22DAULL,
		0xBB14246B17AA471FULL,
		0x88C586E5ACB8BB42ULL,
		0x7A36E863CCE1D65CULL,
		0xE2370001759DC330ULL,
		0x768E36C72762589DULL,
		0x9F574377A56E6C51ULL,
		0x380AEAF52D3023B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83823C8E7F3E1156ULL,
		0xDA5F6559C8FD5037ULL,
		0xFDBE291EDAC6C5C3ULL,
		0x9910E620E7957803ULL,
		0x07FD8FD094CFB00DULL,
		0x7237D4C77B9AF4AEULL,
		0xEE0D805F2E2EB965ULL,
		0xEEC896780C67E764ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8514B97B86D01184ULL,
		0xE0B4BF114EACF6E7ULL,
		0x8B075DC6D1F1F57EULL,
		0xE1260242E54C5E58ULL,
		0xDA397030E0CE1322ULL,
		0x045661FFABC763EFULL,
		0xB149C318773FB2ECULL,
		0x4942547D20C83C50ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3B07299436930B57ULL,
		0x17EF066F270B7F12ULL,
		0x0C50F3F31B918075ULL,
		0x56260CEB161DFE83ULL,
		0x63D30CFD8B441A71ULL,
		0xF332D0C7F3752AE2ULL,
		0x0AC91C4AA0B1B7ECULL,
		0xFAFD3BC3AFE1A285ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF03E7D79755DF28EULL,
		0x12A793A2E427A743ULL,
		0x684D1B6E1361F02FULL,
		0x81A2D9BC6AEA59A2ULL,
		0x471DFB3516DBF5FCULL,
		0x95BEE966E8E3E955ULL,
		0x3B3EA7064E00CD26ULL,
		0x55677FA0DBDEC975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AC8AC1AC13518C9ULL,
		0x054772CC42E3D7CEULL,
		0xA403D885082F9046ULL,
		0xD483332EAB33A4E0ULL,
		0x1CB511C874682474ULL,
		0x5D73E7610A91418DULL,
		0xCF8A754452B0EAC6ULL,
		0xA595BC22D402D90FULL
	}};
	sign = 0;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0AE3D203A325FB54ULL,
		0xE4173A44EC050ADAULL,
		0xC45F49874CCC4886ULL,
		0x1707104A552DD042ULL,
		0x31CAAB91633C73DDULL,
		0xB06300D44A4D8F73ULL,
		0x37E5C337C5056D5BULL,
		0x172843E51F6CA579ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6131EE48272BCDCEULL,
		0xF3955FEAFB4D8106ULL,
		0xD5D916979FEBB2F5ULL,
		0x634A138FF5BDC161ULL,
		0x609692328B0ADF75ULL,
		0xBACB0A00A83A5B35ULL,
		0x72C87F5EE2C3D7BBULL,
		0x57B8C3B70E347BD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9B1E3BB7BFA2D86ULL,
		0xF081DA59F0B789D3ULL,
		0xEE8632EFACE09590ULL,
		0xB3BCFCBA5F700EE0ULL,
		0xD134195ED8319467ULL,
		0xF597F6D3A213343DULL,
		0xC51D43D8E241959FULL,
		0xBF6F802E113829A3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9BAE8077C52B7480ULL,
		0xC8FD142CA84388DEULL,
		0x44E15040A9D6BC01ULL,
		0x4EE6EECF5CA60324ULL,
		0x35435636E2E6A008ULL,
		0x97BB55DF79C67FB5ULL,
		0x9DBA9427E4840933ULL,
		0xA8D7D2E67F6EA9EEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12118559B8D9F158ULL,
		0x5949F1475A7214A7ULL,
		0x89CC43DA40C01ACCULL,
		0xF6B3627FB7117A5BULL,
		0xBC89E82C626E2D42ULL,
		0xF9A23F9B6BCF92AFULL,
		0xE9042CB4D783C322ULL,
		0x22CC51373097A19DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x899CFB1E0C518328ULL,
		0x6FB322E54DD17437ULL,
		0xBB150C666916A135ULL,
		0x58338C4FA59488C8ULL,
		0x78B96E0A807872C5ULL,
		0x9E1916440DF6ED05ULL,
		0xB4B667730D004610ULL,
		0x860B81AF4ED70850ULL
	}};
	sign = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCE020D3A9C99BCA1ULL,
		0xBF2E3D2C8E7439DCULL,
		0x5CCCECD477EF0E7DULL,
		0x6584AED913A23EECULL,
		0xC251E934B3060C43ULL,
		0x2143156EDC8EFA43ULL,
		0x480DA9C79C3ACD21ULL,
		0xDC36921B656140E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08F55BA47D1025A3ULL,
		0xEE52FF76476C8508ULL,
		0x704B3468CAC40875ULL,
		0x893BE19CCFEE6690ULL,
		0x163869D9E55DC325ULL,
		0x092B72863270B458ULL,
		0x91297C19256C76DAULL,
		0x8684A85A6EAD09E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC50CB1961F8996FEULL,
		0xD0DB3DB64707B4D4ULL,
		0xEC81B86BAD2B0607ULL,
		0xDC48CD3C43B3D85BULL,
		0xAC197F5ACDA8491DULL,
		0x1817A2E8AA1E45EBULL,
		0xB6E42DAE76CE5647ULL,
		0x55B1E9C0F6B436FDULL
	}};
	sign = 0;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0F7E8EC9259B46CULL,
		0xCB1070A3B7174382ULL,
		0xE597E2284F1FF02DULL,
		0xBA25D1DFDB52460BULL,
		0x2A66EA10CF1349A5ULL,
		0x1D21DC761626FAD6ULL,
		0x1B001D0368BB15CEULL,
		0x67E3846A092A7F99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBAC07153505AF3CULL,
		0x310AEDA4E8ECE17AULL,
		0x81CC637FA346137FULL,
		0xBF478414A2237E05ULL,
		0xDCD3ADEB67459F25ULL,
		0x7F0401809FD51D21ULL,
		0x3A744A7E53BD8126ULL,
		0x2F1C4C0DEC2A5A81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x154BE1D75D540530ULL,
		0x9A0582FECE2A6208ULL,
		0x63CB7EA8ABD9DCAEULL,
		0xFADE4DCB392EC806ULL,
		0x4D933C2567CDAA7FULL,
		0x9E1DDAF57651DDB4ULL,
		0xE08BD28514FD94A7ULL,
		0x38C7385C1D002517ULL
	}};
	sign = 0;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C2352D0E5D344A7ULL,
		0x2FD1A1AFD7A6CEE6ULL,
		0xC62729D88681E334ULL,
		0x52F397498E4CCF46ULL,
		0xAF997C7E7B664096ULL,
		0x84709058BB712CD5ULL,
		0xF34508A1F27FDD12ULL,
		0x30E7A7BABBD97ECBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x810498CE47DA9C15ULL,
		0x6F879ADC153DCD6AULL,
		0x29827E5BB5F2774EULL,
		0x24A412BEA5FB5907ULL,
		0x76BBAC800956FB4BULL,
		0xE4CE554915800321ULL,
		0xE2BFA51B7FA879A0ULL,
		0x017C1FF6F6379350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB1EBA029DF8A892ULL,
		0xC04A06D3C269017BULL,
		0x9CA4AB7CD08F6BE5ULL,
		0x2E4F848AE851763FULL,
		0x38DDCFFE720F454BULL,
		0x9FA23B0FA5F129B4ULL,
		0x1085638672D76371ULL,
		0x2F6B87C3C5A1EB7BULL
	}};
	sign = 0;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6D6750B7F195285FULL,
		0xFD86770002955234ULL,
		0xAEE9849B90B72FFAULL,
		0x7412AE02FD45A3FBULL,
		0x0726C2D808AA5B75ULL,
		0x4E68396EA9B93BBAULL,
		0xA8534F8A58C7BEBCULL,
		0xA4C9F094D1ABEB0BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A8E6C39B9232FBULL,
		0x1BC12509D90D4B24ULL,
		0x10F65F2EBD722BFDULL,
		0x297D71A855902CF4ULL,
		0x6C1DD8A8EA8DD828ULL,
		0x633DCEC2EA2B89CAULL,
		0x6E88383EDCBD382FULL,
		0xC859BC5AE7375FCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33BE69F45602F564ULL,
		0xE1C551F629880710ULL,
		0x9DF3256CD34503FDULL,
		0x4A953C5AA7B57707ULL,
		0x9B08EA2F1E1C834DULL,
		0xEB2A6AABBF8DB1EFULL,
		0x39CB174B7C0A868CULL,
		0xDC703439EA748B3DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x489461B0ED2173E4ULL,
		0x86B5374D821AFDE8ULL,
		0x2520B76D015C4628ULL,
		0xA3BF86BFC17D6EA0ULL,
		0x478117754B17CF00ULL,
		0x2330F71E03E85537ULL,
		0x6BF99DC0CC4118CFULL,
		0xD4D303ED075C99ABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x099B20F362818133ULL,
		0xA904E4F1E70234EAULL,
		0xA81B638F4C57F91EULL,
		0x8D4C713A12E317C3ULL,
		0x2397DAC1153C4C64ULL,
		0xDCEDD8142822D2E0ULL,
		0xE8B28B4B01449C8FULL,
		0x0DC21B86CC522267ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EF940BD8A9FF2B1ULL,
		0xDDB0525B9B18C8FEULL,
		0x7D0553DDB5044D09ULL,
		0x16731585AE9A56DCULL,
		0x23E93CB435DB829CULL,
		0x46431F09DBC58257ULL,
		0x83471275CAFC7C3FULL,
		0xC710E8663B0A7743ULL
	}};
	sign = 0;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8FB2CC9BA10A0C28ULL,
		0x3E421FA6828A2D73ULL,
		0xF7856CEC83DCE156ULL,
		0x7315ABDFCFCE119EULL,
		0x4F63B7EF092BD0C0ULL,
		0xD3CDAC88589B9933ULL,
		0x43A18E2230060EACULL,
		0x10FA8DABCA24DDE5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB2AFFD459DB59C2ULL,
		0xB5E2D71E43B0A450ULL,
		0x0F25F41C5EC58D4DULL,
		0x84CEC506A48DC8BBULL,
		0x8F3D211C72066609ULL,
		0x84F859E63CE03298ULL,
		0x8C6696D206623CA0ULL,
		0x0FEE7506A898D2EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB487CCC7472EB266ULL,
		0x885F48883ED98922ULL,
		0xE85F78D025175408ULL,
		0xEE46E6D92B4048E3ULL,
		0xC02696D297256AB6ULL,
		0x4ED552A21BBB669AULL,
		0xB73AF75029A3D20CULL,
		0x010C18A5218C0AF7ULL
	}};
	sign = 0;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3C0A84C18BB1689CULL,
		0x85B150ACC2485BCEULL,
		0xD1E2E96BC035F068ULL,
		0x373C97D645D57CFBULL,
		0x5A43DDFA445A959CULL,
		0xAD859ACB8103E9A7ULL,
		0x8422B2B36D061B4FULL,
		0x56004B34BF025A39ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADAA2A9C9CA422B0ULL,
		0xD502F8643015AD2DULL,
		0x1C4A75C1E2C83C4FULL,
		0x6D365D019CCD7872ULL,
		0x2CDA585FCFDC2B09ULL,
		0xFA25EDB6A4C5EC48ULL,
		0x63A8B667339C8F84ULL,
		0x04024BDB10829482ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E605A24EF0D45ECULL,
		0xB0AE58489232AEA0ULL,
		0xB59873A9DD6DB418ULL,
		0xCA063AD4A9080489ULL,
		0x2D69859A747E6A92ULL,
		0xB35FAD14DC3DFD5FULL,
		0x2079FC4C39698BCAULL,
		0x51FDFF59AE7FC5B7ULL
	}};
	sign = 0;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xADE0FB27BFE849ECULL,
		0xEC75419E76DC91A0ULL,
		0x794B69B4108DF14BULL,
		0xB27FA0FFCF931AFCULL,
		0xC7B155B9A3F26101ULL,
		0x643BCE4A0C444760ULL,
		0xC72D95A0E98CCC39ULL,
		0xC045A913CAA6DD2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE5CCEA3B1A6429ULL,
		0xDF03CFAD88EA9154ULL,
		0xBE00266F0C60E402ULL,
		0x26C9C0FE4D578201ULL,
		0x0E99EE634FF1BEFFULL,
		0x749C55BDDA5A30ABULL,
		0x31E44CBB2C8CDCB3ULL,
		0xD2AF908D64FAF140ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0FB2E3D84CDE5C3ULL,
		0x0D7171F0EDF2004BULL,
		0xBB4B4345042D0D49ULL,
		0x8BB5E001823B98FAULL,
		0xB91767565400A202ULL,
		0xEF9F788C31EA16B5ULL,
		0x954948E5BCFFEF85ULL,
		0xED96188665ABEBEBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5944E0444992CD4DULL,
		0x898C07AA937B0DC3ULL,
		0xAF5360FDF09FDB65ULL,
		0x37910E11AC9AD04BULL,
		0x5696CC26F7C9762EULL,
		0x992E24B4405A3B23ULL,
		0x91F0131E86639DADULL,
		0xB233F3B0387C183BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6343B2F97114A2A7ULL,
		0x7DD769F82F58E416ULL,
		0xC93A8B6867F19E78ULL,
		0xE990EFC2885D8557ULL,
		0x2602C61815E67E11ULL,
		0x44619D4140FF701EULL,
		0xC6A7053BCB7558FAULL,
		0x6B348788AB3E7B8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6012D4AD87E2AA6ULL,
		0x0BB49DB2642229ACULL,
		0xE618D59588AE3CEDULL,
		0x4E001E4F243D4AF3ULL,
		0x3094060EE1E2F81CULL,
		0x54CC8772FF5ACB05ULL,
		0xCB490DE2BAEE44B3ULL,
		0x46FF6C278D3D9CAEULL
	}};
	sign = 0;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4858048EFB8289EEULL,
		0x837E25670C5B7995ULL,
		0x635EFC0AD1D00361ULL,
		0xC956649B64E17371ULL,
		0x63D2E522B601640AULL,
		0x06D4E944B6B04E13ULL,
		0x7B909F60B8C1E5ADULL,
		0xE3554979F5A7DB7BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7716EE7E15FBE1ULL,
		0xD809288EEF0B82A4ULL,
		0xBBD9DF65D2602A32ULL,
		0xDED30ADDA248402BULL,
		0xB0F1E4B028E1E7C4ULL,
		0xA86EA78CF7EE1E32ULL,
		0xF34C6A7A9DD07A8BULL,
		0xEA895895587316B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE0EDA07D6C8E0DULL,
		0xAB74FCD81D4FF6F0ULL,
		0xA7851CA4FF6FD92EULL,
		0xEA8359BDC2993345ULL,
		0xB2E100728D1F7C45ULL,
		0x5E6641B7BEC22FE0ULL,
		0x884434E61AF16B21ULL,
		0xF8CBF0E49D34C4C2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x89266B238FB0F705ULL,
		0xD5E449BF59A0A1B9ULL,
		0x857E358D9021F4B9ULL,
		0x0A7BE413E0A13427ULL,
		0xB84D682AD2F7D8F0ULL,
		0x1B6DF4B4EBC59283ULL,
		0x9BCADE5F9CC85006ULL,
		0xF3DAADEB0D599B58ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x734C6AD9B390A743ULL,
		0x7FF0B80520EED7FBULL,
		0x0BCE486B3E15ADB0ULL,
		0x3E8D580D4B1D3CA1ULL,
		0x3C9F8064B451AEA5ULL,
		0x6F5B4E6FE318765FULL,
		0x34281E2BDC6F94B2ULL,
		0xAB624A6FC040761BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15DA0049DC204FC2ULL,
		0x55F391BA38B1C9BEULL,
		0x79AFED22520C4709ULL,
		0xCBEE8C069583F786ULL,
		0x7BADE7C61EA62A4AULL,
		0xAC12A64508AD1C24ULL,
		0x67A2C033C058BB53ULL,
		0x4878637B4D19253DULL
	}};
	sign = 0;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x56FE495E4B7884DAULL,
		0x6209CAB1358AE5A4ULL,
		0x16FEEE1506D4BD76ULL,
		0x4FACEA3914CFCB1CULL,
		0x3A95063CEC2F2640ULL,
		0x2FDB5389D271B85AULL,
		0x1E128DADC8EF2C15ULL,
		0x820C41D237D8CDECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF2BEAEB5A1623ABULL,
		0xCDFD69C49A5324F4ULL,
		0x15087612FC0D77A4ULL,
		0x0119DA63B46045DCULL,
		0x0AC46369FEE39447ULL,
		0xB4697B6934C429BBULL,
		0x6FBA9EF39A123449ULL,
		0x7E5C0652715D1BF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87D25E72F162612FULL,
		0x940C60EC9B37C0AFULL,
		0x01F678020AC745D1ULL,
		0x4E930FD5606F8540ULL,
		0x2FD0A2D2ED4B91F9ULL,
		0x7B71D8209DAD8E9FULL,
		0xAE57EEBA2EDCF7CBULL,
		0x03B03B7FC67BB1F7ULL
	}};
	sign = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF743A39EFEA2194BULL,
		0x1FC59A8A35335B0CULL,
		0x589656C539B1B24DULL,
		0xBC7BF491D1E5AD92ULL,
		0xBD1197B8D85ECD16ULL,
		0x56E7D12E098FA783ULL,
		0xFCBED88876C56224ULL,
		0x77FCD8A372542A24ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xACB7CA41ADCB8857ULL,
		0xB84706478AE59574ULL,
		0x9EA37BF1BF781412ULL,
		0x9ACF07F2C3807103ULL,
		0x6DCD1D54514DFECBULL,
		0xF3E48A7B00542CBAULL,
		0x486E0EE14B4B6933ULL,
		0xF7F027C90C2BB6D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A8BD95D50D690F4ULL,
		0x677E9442AA4DC598ULL,
		0xB9F2DAD37A399E3AULL,
		0x21ACEC9F0E653C8EULL,
		0x4F447A648710CE4BULL,
		0x630346B3093B7AC9ULL,
		0xB450C9A72B79F8F0ULL,
		0x800CB0DA6628734CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE0FCE4AA74319F05ULL,
		0x53A757823F102FFFULL,
		0xB92C65751525C39AULL,
		0x3C55EFC276B4E34CULL,
		0x5598D8BE2782B40AULL,
		0xC81706A83B868956ULL,
		0xE5540366D93D08C8ULL,
		0x0C7E311C5788635EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x99271EB55267A7EEULL,
		0xFE42556EFCF7C25BULL,
		0x66A281009452B395ULL,
		0x2D17C9372D46D254ULL,
		0x43E89B404A1A2EAEULL,
		0x0A85DC8A966E6461ULL,
		0x0AFFDFEEDD009E59ULL,
		0x366E8A6E5535C53CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47D5C5F521C9F717ULL,
		0x5565021342186DA4ULL,
		0x5289E47480D31004ULL,
		0x0F3E268B496E10F8ULL,
		0x11B03D7DDD68855CULL,
		0xBD912A1DA51824F5ULL,
		0xDA542377FC3C6A6FULL,
		0xD60FA6AE02529E22ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFB38A71B6C9F16FBULL,
		0xC7DEDB815AFAC953ULL,
		0xF079BC7366852011ULL,
		0xC1AED2AEC8980F96ULL,
		0x0106684116200BF6ULL,
		0x4F30772323F04FD2ULL,
		0x91F22DDB603AAAF3ULL,
		0x398B620F6ECB0AD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC3F489C1CBB520BULL,
		0x49E100F8472F41C4ULL,
		0x2F7F6FE564D716DBULL,
		0xFE06444AF76B0B82ULL,
		0x532C6247CB6A4FACULL,
		0xBA3D7D178290430BULL,
		0x32EBDC47ED6AEFBEULL,
		0x88C43A8B3AA2ED55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EF95E7F4FE3C4F0ULL,
		0x7DFDDA8913CB878FULL,
		0xC0FA4C8E01AE0936ULL,
		0xC3A88E63D12D0414ULL,
		0xADDA05F94AB5BC49ULL,
		0x94F2FA0BA1600CC6ULL,
		0x5F06519372CFBB34ULL,
		0xB0C7278434281D7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD072B2C20195DB55ULL,
		0x1F776586B5B110B1ULL,
		0x326858266161EAE2ULL,
		0x81F5BDD822BB6A68ULL,
		0x4DE454110AFBE831ULL,
		0xF83CE5F826B1AE87ULL,
		0x560668EF6A72258EULL,
		0x1F670B4902CDE793ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1C0559F7C58C0DULL,
		0xE869D5CEB8CADDD9ULL,
		0xD186A55A2034454EULL,
		0x43504DBBFA92DF97ULL,
		0x3565F3FB239A0C86ULL,
		0x9B16EAE1C8CB7E6FULL,
		0xB8D69361B24979DBULL,
		0x9FD39B969AB1C54EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1356AD6809D04F48ULL,
		0x370D8FB7FCE632D8ULL,
		0x60E1B2CC412DA593ULL,
		0x3EA5701C28288AD0ULL,
		0x187E6015E761DBABULL,
		0x5D25FB165DE63018ULL,
		0x9D2FD58DB828ABB3ULL,
		0x7F936FB2681C2244ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3FC73AFF713AEA22ULL,
		0x4F8A549CFEFA7A9CULL,
		0xAE675D20C18CC4CAULL,
		0x95CD403015CF79F9ULL,
		0xB109F6664B44CD92ULL,
		0xCD50CF60132073EAULL,
		0x7026B0C863C34DC8ULL,
		0x3F6C5BFFAD7D3082ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E119BB7BB199CE1ULL,
		0x61D93B1A0D1F9621ULL,
		0x22A9D8078191A92DULL,
		0xE167C7EA614F87A7ULL,
		0x0DA7CD0F5DA84CBDULL,
		0x83AB72F63FA06444ULL,
		0x62BE57D1433CBE76ULL,
		0x1660FBCB918AA302ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1B59F47B6214D41ULL,
		0xEDB11982F1DAE47AULL,
		0x8BBD85193FFB1B9CULL,
		0xB4657845B47FF252ULL,
		0xA3622956ED9C80D4ULL,
		0x49A55C69D3800FA6ULL,
		0x0D6858F720868F52ULL,
		0x290B60341BF28D80ULL
	}};
	sign = 0;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B1D2C8FB48606B3ULL,
		0xEECADDA9FBB522D6ULL,
		0xB3D62BE1071DB553ULL,
		0x2423E455F4BA4802ULL,
		0xF971A2A564B6C406ULL,
		0x34BCA7B15306B408ULL,
		0x8077426768CF8DE7ULL,
		0xE947E1EBE460624BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B3746EE73F0D585ULL,
		0x21C1E34DD6D68001ULL,
		0x42C798FC7152275FULL,
		0x0D4A0527829B4D5AULL,
		0xBEBE6270CD7CA7BFULL,
		0xBD1AD3335C9832A7ULL,
		0x61F62F3544B19DC1ULL,
		0xD94376FB0B1188E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE5E5A14095312EULL,
		0xCD08FA5C24DEA2D5ULL,
		0x710E92E495CB8DF4ULL,
		0x16D9DF2E721EFAA8ULL,
		0x3AB34034973A1C47ULL,
		0x77A1D47DF66E8161ULL,
		0x1E811332241DF025ULL,
		0x10046AF0D94ED968ULL
	}};
	sign = 0;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1BE1CA595E89FE81ULL,
		0x757C201C547670A4ULL,
		0xA8B8E826A2A568B1ULL,
		0xD0196E9715AC72FFULL,
		0x07814EDB204A8373ULL,
		0x8F3B7C89983D6104ULL,
		0xBAE25F1B36D84DD9ULL,
		0x7F0D06C1E1B4EA37ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x22202875F1C7155FULL,
		0x6FCFADAE3F2ED953ULL,
		0x8C0EDF6C3ED8FF62ULL,
		0xCBF83A41CC714A9CULL,
		0xF92A176C66729EFFULL,
		0xC1E5870FECD7A001ULL,
		0x16CE57631F3E9ABAULL,
		0xAC058FFB74D4A3EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9C1A1E36CC2E922ULL,
		0x05AC726E15479750ULL,
		0x1CAA08BA63CC694FULL,
		0x04213455493B2863ULL,
		0x0E57376EB9D7E474ULL,
		0xCD55F579AB65C102ULL,
		0xA41407B81799B31EULL,
		0xD30776C66CE04648ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x49B038121DB717DEULL,
		0xAC62E0CC3AD581BAULL,
		0xCBC68ABE310A3FD1ULL,
		0x50B533E977F5AEE6ULL,
		0x3DA547AC71ABFE8DULL,
		0x8FC0C659384689A7ULL,
		0x6C5A042AD2BE9A69ULL,
		0x33552A0A8D3D7F53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55E3CBE04149C428ULL,
		0x37CD4695F382E90FULL,
		0xF628430C7082D97FULL,
		0x459CCF23CA0EF840ULL,
		0x2FE2A1E2F01631C5ULL,
		0x43BBA6A17CA9FD74ULL,
		0x009ACC94BDD885B3ULL,
		0x5E3FBD94721ABD0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3CC6C31DC6D53B6ULL,
		0x74959A36475298AAULL,
		0xD59E47B1C0876652ULL,
		0x0B1864C5ADE6B6A5ULL,
		0x0DC2A5C98195CCC8ULL,
		0x4C051FB7BB9C8C33ULL,
		0x6BBF379614E614B6ULL,
		0xD5156C761B22C244ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9A4E18A17D22EB3EULL,
		0xA9F7515F1A114640ULL,
		0xB22F5EC54A1F46AFULL,
		0x27FD2E9501690311ULL,
		0xD200724A27774108ULL,
		0x8D0EE129C3F68C05ULL,
		0x04911E34024255A1ULL,
		0x594DDC29C884CBF8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58C0E66F7E240EDBULL,
		0xEFB7D4A6C920CDF1ULL,
		0xBE342A0DD04F9009ULL,
		0xE2592B67EDB82EF2ULL,
		0x57BAC684D59E0882ULL,
		0x07FDC2276F6FACFFULL,
		0x4F92ED7E4F951037ULL,
		0xB920BE66223DA9A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x418D3231FEFEDC63ULL,
		0xBA3F7CB850F0784FULL,
		0xF3FB34B779CFB6A5ULL,
		0x45A4032D13B0D41EULL,
		0x7A45ABC551D93885ULL,
		0x85111F025486DF06ULL,
		0xB4FE30B5B2AD456AULL,
		0xA02D1DC3A6472253ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3FE2427E9CB5715ULL,
		0x6E50B756F0BD67E0ULL,
		0x0C5276FFE35014CEULL,
		0x9832E1C67CFE71EBULL,
		0x39DA4EE592DF7C75ULL,
		0x47FE8525B036F1A8ULL,
		0xBE1D18ACFDDBB88EULL,
		0x232D501F8C49C1D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAFB339A6F45CA9AULL,
		0xE7617DFE428A486BULL,
		0x941E1622D3B2EB17ULL,
		0xAC30EF4C728A47D1ULL,
		0x3BC399ECA50057FFULL,
		0xF65B242FB0808B00ULL,
		0x9E71C16DC71D143AULL,
		0x274DC3064E8CD53AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF902F08D7A858C7BULL,
		0x86EF3958AE331F74ULL,
		0x783460DD0F9D29B6ULL,
		0xEC01F27A0A742A19ULL,
		0xFE16B4F8EDDF2475ULL,
		0x51A360F5FFB666A7ULL,
		0x1FAB573F36BEA453ULL,
		0xFBDF8D193DBCEC97ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA41F07A853BD4CDCULL,
		0x9CBADD87E12D5866ULL,
		0x62C0A11125E84C30ULL,
		0x483DD9BA43D5EFECULL,
		0x1AF48252A6DCEC1CULL,
		0x2677C0B7B44C9A0BULL,
		0xB4BA9D62082CE6B9ULL,
		0x90F49DB21BA89A89ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x86BB6B86A1C15C20ULL,
		0x3BEEBA65BB2E3E2BULL,
		0xFDADFF1C69C55AF6ULL,
		0x5AAE0287B889D9F5ULL,
		0xAEE4E2291B2E4771ULL,
		0x427AC1F89DCC872FULL,
		0x9BB4FD409EA90E47ULL,
		0x04CAAEFDC0A6AC17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D639C21B1FBF0BCULL,
		0x60CC232225FF1A3BULL,
		0x6512A1F4BC22F13AULL,
		0xED8FD7328B4C15F6ULL,
		0x6C0FA0298BAEA4AAULL,
		0xE3FCFEBF168012DBULL,
		0x1905A0216983D871ULL,
		0x8C29EEB45B01EE72ULL
	}};
	sign = 0;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8474058C528700A8ULL,
		0xD7B41CD88D8087F7ULL,
		0xE90407AB2DE5A277ULL,
		0x3A9A0B8AEB439D95ULL,
		0x047AF4343C38D1A0ULL,
		0x7D87D2EB8AE558F5ULL,
		0x03EC315105EF7AD8ULL,
		0x9370FCB2F75717C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x681CE3A4FD51EF1FULL,
		0xF5F291A4DF9105F9ULL,
		0x30D62BECC1BAFA0FULL,
		0x7416FEA70E3F3682ULL,
		0x271D38DCD34C6274ULL,
		0x99E7BD81D1B1C0B6ULL,
		0x212932D831A9995AULL,
		0x79A5ED9016F90DC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C5721E755351189ULL,
		0xE1C18B33ADEF81FEULL,
		0xB82DDBBE6C2AA867ULL,
		0xC6830CE3DD046713ULL,
		0xDD5DBB5768EC6F2BULL,
		0xE3A01569B933983EULL,
		0xE2C2FE78D445E17DULL,
		0x19CB0F22E05E09FFULL
	}};
	sign = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBA5E32AB7EDEC4C3ULL,
		0xE5D0126AC6E484B2ULL,
		0xCD10DA02D3350F48ULL,
		0x78C1E6F1A66CDEF4ULL,
		0x2C292A5237ACEAEDULL,
		0x93D45778DDA1912BULL,
		0x8FF3F74C134E6C10ULL,
		0x3D829201C7357FE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61CE535F2415491ULL,
		0x39993AC69E342CE5ULL,
		0x61A085AAFC6377B4ULL,
		0x0E98242130277839ULL,
		0x4F61DCEE398B79F4ULL,
		0x83DEBC0103452310ULL,
		0x7026C277853C9375ULL,
		0x65648A27D0E8C9C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4414D758C9D7032ULL,
		0xAC36D7A428B057CCULL,
		0x6B705457D6D19794ULL,
		0x6A29C2D0764566BBULL,
		0xDCC74D63FE2170F9ULL,
		0x0FF59B77DA5C6E1AULL,
		0x1FCD34D48E11D89BULL,
		0xD81E07D9F64CB61CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4B433AE0460BD28CULL,
		0x806BEC0EC2411488ULL,
		0xD0AB1016B9664C52ULL,
		0xD404685DFCBE5D36ULL,
		0x5871C21176424A31ULL,
		0xDDF5EE803AD48901ULL,
		0x76B4E34A99E5B62EULL,
		0x1081283E26EEA58BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4878BD5E1B289A7ULL,
		0xB06B090FA16A2CF1ULL,
		0xDA38E21895A0DA95ULL,
		0x1B2D94DAB36FF3CAULL,
		0x1DB416978FDD62ADULL,
		0x103082E81FF56A5EULL,
		0x14EAF8B20CFF2F04ULL,
		0xA740F22929CABF5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66BBAF0A645948E5ULL,
		0xD000E2FF20D6E796ULL,
		0xF6722DFE23C571BCULL,
		0xB8D6D383494E696BULL,
		0x3ABDAB79E664E784ULL,
		0xCDC56B981ADF1EA3ULL,
		0x61C9EA988CE6872AULL,
		0x69403614FD23E62DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06FE27F18471DBFEULL,
		0x5D61CD9C8BA87CCBULL,
		0x262E8C2D2BFED861ULL,
		0xE10CEF664660E86AULL,
		0x89B30F8B3623E433ULL,
		0x3B82003FE5554F87ULL,
		0x1A4034BE6CE5D0B3ULL,
		0xBB8063E4BDA82E27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B3CCB2F7C77F22ULL,
		0xFF3749031F159C9BULL,
		0x045AD13CDFAF2B00ULL,
		0x99C49A90F658A8C0ULL,
		0x4128C4F1F96A12FFULL,
		0x52A476C48F30472AULL,
		0xB130D953F69BA800ULL,
		0xDA3965B555F32F32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E4A5B3E8CAA5CDCULL,
		0x5E2A84996C92E02FULL,
		0x21D3BAF04C4FAD60ULL,
		0x474854D550083FAAULL,
		0x488A4A993CB9D134ULL,
		0xE8DD897B5625085DULL,
		0x690F5B6A764A28B2ULL,
		0xE146FE2F67B4FEF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFB194A313D2BB998ULL,
		0x6EF90D8CA11D472AULL,
		0xBB8826C501B2B620ULL,
		0xEA0A0DA2D0A0FAACULL,
		0x3BD123E1A8EF2A9EULL,
		0x68AA887E1CD52092ULL,
		0xB37CF998939272CFULL,
		0x1621576DE9B02395ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8731FC92611E591DULL,
		0x3593BF17ABABA234ULL,
		0xADCED03CD374DC1FULL,
		0x6913BBF9885A11E7ULL,
		0x4C9DAB28093AFE86ULL,
		0x338F1715B02B2344ULL,
		0xDECF57CC11954177ULL,
		0xA74D4DF092CC90BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73E74D9EDC0D607BULL,
		0x39654E74F571A4F6ULL,
		0x0DB956882E3DDA01ULL,
		0x80F651A94846E8C5ULL,
		0xEF3378B99FB42C18ULL,
		0x351B71686CA9FD4DULL,
		0xD4ADA1CC81FD3158ULL,
		0x6ED4097D56E392D8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF80C4D81DE1EE100ULL,
		0x7E2AD02FA7EDD69AULL,
		0xFD24326F061FD905ULL,
		0x0C394AA0C04E4ACBULL,
		0x9109D2C6F9DD4850ULL,
		0x47B900B69AABC645ULL,
		0x22FE58327DE2346BULL,
		0xEFFBA6019C5F8C2FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x139E5BA559050E26ULL,
		0x3BB8A16FC4260701ULL,
		0x8A6F2A7F2156B716ULL,
		0x6CD800885D234989ULL,
		0x04AF26476EA7F6AEULL,
		0x4B77CCEC7F4CB3ABULL,
		0xD5A765C0C88D51B4ULL,
		0x2F2EC504FFD0F79BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE46DF1DC8519D2DAULL,
		0x42722EBFE3C7CF99ULL,
		0x72B507EFE4C921EFULL,
		0x9F614A18632B0142ULL,
		0x8C5AAC7F8B3551A1ULL,
		0xFC4133CA1B5F129AULL,
		0x4D56F271B554E2B6ULL,
		0xC0CCE0FC9C8E9493ULL
	}};
	sign = 0;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x647D8FFCE6240D61ULL,
		0x80688AB51F72634FULL,
		0x2E3753BCB93069A3ULL,
		0xFF08243FF9DEF763ULL,
		0xE01553F15024BDA7ULL,
		0xD6438304F8C5F68FULL,
		0x9EC439FB8BF5504FULL,
		0x02E4963FF7E1BD40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC37CA314F5642469ULL,
		0xABCDBABB52F27799ULL,
		0x8B2D95EC8BF8563FULL,
		0xFF826D48DFD5A424ULL,
		0x1905392F238747CAULL,
		0xC3C8D29B5579C185ULL,
		0x4F0B7E197992A2E2ULL,
		0x4EB5E31A8C2ADFA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA100ECE7F0BFE8F8ULL,
		0xD49ACFF9CC7FEBB5ULL,
		0xA309BDD02D381363ULL,
		0xFF85B6F71A09533EULL,
		0xC7101AC22C9D75DCULL,
		0x127AB069A34C350AULL,
		0x4FB8BBE21262AD6DULL,
		0xB42EB3256BB6DD9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x16C4532654DD2056ULL,
		0xFA2F0391E0A94D10ULL,
		0xD6DACADB2EA2FB3CULL,
		0xED5ECA88D40C0B28ULL,
		0x646E481BDDB9BDE5ULL,
		0x441883754614277CULL,
		0x6F8D626AC2E1710BULL,
		0x4AEDF6530A5C27CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE594467F6213A12ULL,
		0xFC71A1F6CC8FFBDDULL,
		0xEE821223A03E19B0ULL,
		0xDE7F039B7462B9A9ULL,
		0x50C30397402D6297ULL,
		0x24F0D90C15A3A27CULL,
		0xB1B669736AAE46E4ULL,
		0x7463DB3F977A2F87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x686B0EBE5EBBE644ULL,
		0xFDBD619B14195132ULL,
		0xE858B8B78E64E18BULL,
		0x0EDFC6ED5FA9517EULL,
		0x13AB44849D8C5B4EULL,
		0x1F27AA6930708500ULL,
		0xBDD6F8F758332A27ULL,
		0xD68A1B1372E1F847ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBBC76AF1711EA205ULL,
		0x7E34BC230A2D50EFULL,
		0xB36849FAC6CE4027ULL,
		0x0C83B09A327FE3D3ULL,
		0x3476C8B73E56A23FULL,
		0xE50CC663AAB94596ULL,
		0xBEF897A5C0DEE3E8ULL,
		0xFAF75DCFC4D91F19ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x873CD4C3AAB920B9ULL,
		0x23A396B9B381D6B5ULL,
		0x9B84B9BCBF683E51ULL,
		0xC671B1B917779D7AULL,
		0xBBE72570ED3F47F3ULL,
		0xBAD6A3A9C8A9276FULL,
		0xCFDCD26798EFD31EULL,
		0xEF603130AA8A54B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x348A962DC665814CULL,
		0x5A91256956AB7A3AULL,
		0x17E3903E076601D6ULL,
		0x4611FEE11B084659ULL,
		0x788FA34651175A4BULL,
		0x2A3622B9E2101E26ULL,
		0xEF1BC53E27EF10CAULL,
		0x0B972C9F1A4ECA65ULL
	}};
	sign = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC904905110C473F9ULL,
		0x871B5B672B881837ULL,
		0x09F95E57989C947BULL,
		0x76597B98FA9C1253ULL,
		0xF7F74073F714B32AULL,
		0x6055AA04A6AE0F36ULL,
		0xF482C1B48B2F1172ULL,
		0x1C5AA34C0F8D2F0DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA5560D54DD80DAULL,
		0x247C4F7DFD0D1F61ULL,
		0x64B5AFFFF5D932D4ULL,
		0x32BBD526C7832417ULL,
		0xDF61E6D25CFAD144ULL,
		0x01B70AFDE38F39E4ULL,
		0x078BAF568FD7D69FULL,
		0xD231BCCCCBDF8DD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A5F3A43BBE6F31FULL,
		0x629F0BE92E7AF8D6ULL,
		0xA543AE57A2C361A7ULL,
		0x439DA6723318EE3BULL,
		0x189559A19A19E1E6ULL,
		0x5E9E9F06C31ED552ULL,
		0xECF7125DFB573AD3ULL,
		0x4A28E67F43ADA13BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB7423FCF4BCE4E05ULL,
		0x7647793AF2193AC9ULL,
		0x013F86E5613D5A55ULL,
		0x7AE60F7AD21613F8ULL,
		0x73B3B9631B137F76ULL,
		0x329DD5D0B12C3CBBULL,
		0x6E7C6C7C98FD4479ULL,
		0xE31D00A3F5AFF847ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE460C6AA24CD65EULL,
		0x7ABBACA55E90321BULL,
		0xC667D81F3DBE1C87ULL,
		0xE267EB849C7931F2ULL,
		0xBA6E049362D429D6ULL,
		0xD8F25EA77D2D881DULL,
		0xC685A5362A3A9326ULL,
		0xF4D8BE0B9AEACBA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8FC3364A98177A7ULL,
		0xFB8BCC95938908ADULL,
		0x3AD7AEC6237F3DCDULL,
		0x987E23F6359CE205ULL,
		0xB945B4CFB83F559FULL,
		0x59AB772933FEB49DULL,
		0xA7F6C7466EC2B152ULL,
		0xEE4442985AC52CA5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x583270CC82DB22A0ULL,
		0x5A2C8B67B8F1D447ULL,
		0xF7B308E4D8E5291AULL,
		0x45D0C403CC979D7BULL,
		0xBE919937E0A8FF02ULL,
		0x44D342E3ABA7054CULL,
		0xE419321F05AE0C09ULL,
		0x5BF93404D529528AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD0186A5498B68EULL,
		0x0AEA963D5B56C1DDULL,
		0xC280EDD44B20C8C8ULL,
		0x0CD21F71516A21BBULL,
		0x0AED5F56DBBB635CULL,
		0xC1C597B003C5443EULL,
		0x22E2692FACD22145ULL,
		0x0862E2F404156DF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA6258622E426C12ULL,
		0x4F41F52A5D9B1269ULL,
		0x35321B108DC46052ULL,
		0x38FEA4927B2D7BC0ULL,
		0xB3A439E104ED9BA6ULL,
		0x830DAB33A7E1C10EULL,
		0xC136C8EF58DBEAC3ULL,
		0x53965110D113E498ULL
	}};
	sign = 0;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC3EE7088B799885FULL,
		0x76469D7758E925BAULL,
		0x1CD731448CA4A1BFULL,
		0x9B52E4660D564ECEULL,
		0x96331973C1433FEEULL,
		0x89F98EBDE996C990ULL,
		0xCF2C8F1C39C5F35FULL,
		0xD2C67D94D9B2E185ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9652A39B9437093ULL,
		0xF7DB5785F7EBDE3AULL,
		0x6DB466E924863436ULL,
		0x9409506992164965ULL,
		0x2CE326E8BF47166EULL,
		0x0645DF43414778F5ULL,
		0xC2D5446392A190ADULL,
		0x61E75E74694F3239ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA89464EFE5617CCULL,
		0x7E6B45F160FD477FULL,
		0xAF22CA5B681E6D88ULL,
		0x074993FC7B400568ULL,
		0x694FF28B01FC2980ULL,
		0x83B3AF7AA84F509BULL,
		0x0C574AB8A72462B2ULL,
		0x70DF1F207063AF4CULL
	}};
	sign = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x16BE5EF3D1D99606ULL,
		0x8AD6A2B9145CD627ULL,
		0x39DD0D5776306A79ULL,
		0x8204CA0C8E053A37ULL,
		0x8825B7CB488061EBULL,
		0x902303F36940ADA3ULL,
		0x98A8F5241402C182ULL,
		0x6B48192926822194ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8965003CE2D76692ULL,
		0x936017EBFC6DFE50ULL,
		0x9736357E578515E9ULL,
		0xCC4141840B73117AULL,
		0xA2D6FB4039936B7FULL,
		0xFC75CEDC7C833D47ULL,
		0xB09874DD23754F47ULL,
		0x52DB6585FA3288F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D595EB6EF022F74ULL,
		0xF7768ACD17EED7D6ULL,
		0xA2A6D7D91EAB548FULL,
		0xB5C38888829228BCULL,
		0xE54EBC8B0EECF66BULL,
		0x93AD3516ECBD705BULL,
		0xE8108046F08D723AULL,
		0x186CB3A32C4F98A2ULL
	}};
	sign = 0;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC8DCF94501C73A32ULL,
		0x2C31966108E5BF19ULL,
		0xC3438E1450836298ULL,
		0x870CA327621F1BE7ULL,
		0x04606DB31AED5FB0ULL,
		0x5F759729667CAB3AULL,
		0x40E7CA139C82E8CDULL,
		0x14C7D8D341DEFFD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE644B71C71678BC0ULL,
		0x716FBFCD7E9E4067ULL,
		0x17EB4687A93524B8ULL,
		0xB736F4CB29DCE8DCULL,
		0x34ABBF979D0CC59DULL,
		0x52087FE9E429D36DULL,
		0x3905D4F8CBD5800AULL,
		0x298E8B3B41ABD912ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2984228905FAE72ULL,
		0xBAC1D6938A477EB1ULL,
		0xAB58478CA74E3DDFULL,
		0xCFD5AE5C3842330BULL,
		0xCFB4AE1B7DE09A12ULL,
		0x0D6D173F8252D7CCULL,
		0x07E1F51AD0AD68C3ULL,
		0xEB394D98003326C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB4FEBD63F58B7542ULL,
		0x3C7FFC3751393C07ULL,
		0xEDA060856A2B197DULL,
		0x0F0F492659A7BC58ULL,
		0x76BB72785CA1FA52ULL,
		0x5D7E890FE58BD9AAULL,
		0xEB12EB5860BDC0EDULL,
		0x1DE9503C9DCDE3E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x965778B4A0F84DD3ULL,
		0x0CD854286DDEBDA6ULL,
		0x740F5A1B8BBB6F4CULL,
		0x8364D9E1C45798EFULL,
		0xEE818D5CF3F2C3CAULL,
		0xD6BB2FF144167EFDULL,
		0x27BF62ED3D454646ULL,
		0x8BA8F43B9F86F91BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EA744AF5493276FULL,
		0x2FA7A80EE35A7E61ULL,
		0x79910669DE6FAA31ULL,
		0x8BAA6F4495502369ULL,
		0x8839E51B68AF3687ULL,
		0x86C3591EA1755AACULL,
		0xC353886B23787AA6ULL,
		0x92405C00FE46EACCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE9A62804B3CED5AULL,
		0x6DF7AE9398D5D0EEULL,
		0xBACA9C8F7F73A30FULL,
		0xDC2DF3B70371D116ULL,
		0x55B5DD3600EE0D9FULL,
		0x2EFBC173A8EA739AULL,
		0xE42B0F13F4740A4AULL,
		0x63434CD246B45271ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF03B54CB256BE657ULL,
		0xE34A0F2BE0736957ULL,
		0xC6E9E0FD8363CDDBULL,
		0x78DDA0BFFD5D6749ULL,
		0x9B79841CBA425EEEULL,
		0xFF57BF77ECC49B0CULL,
		0x1C4CFBF186B0EE67ULL,
		0x5D89BE212267FBB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE5F0DB525D10703ULL,
		0x8AAD9F67B8626796ULL,
		0xF3E0BB91FC0FD533ULL,
		0x635052F7061469CCULL,
		0xBA3C591946ABAEB1ULL,
		0x2FA401FBBC25D88DULL,
		0xC7DE13226DC31BE2ULL,
		0x05B98EB1244C56BDULL
	}};
	sign = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFFC66601AE8EC8F8ULL,
		0x85927E5654001A25ULL,
		0x4967AE9127FFAC69ULL,
		0x47C6C11015D8612CULL,
		0x249F6981111AB3D9ULL,
		0x793A47DCC11CB468ULL,
		0xF2DD415B9CB4D96FULL,
		0xF74445ADEB6CA23BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E1DCBC5E2A2A26EULL,
		0x89AACE2A2BF88132ULL,
		0x4ED7E12927088945ULL,
		0xD2A46EE9E1F54C5AULL,
		0xDA6ED2ACF0E1247EULL,
		0x37A583760F44AE21ULL,
		0x97C6864F75AF117FULL,
		0xB3F02D31C343C121ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61A89A3BCBEC268AULL,
		0xFBE7B02C280798F3ULL,
		0xFA8FCD6800F72323ULL,
		0x7522522633E314D1ULL,
		0x4A3096D420398F5AULL,
		0x4194C466B1D80646ULL,
		0x5B16BB0C2705C7F0ULL,
		0x4354187C2828E11AULL
	}};
	sign = 0;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x498216168E7B789BULL,
		0xFB43DAB2BBA6D30EULL,
		0xBC72841E8333E397ULL,
		0x7E85E754D00CDBCFULL,
		0x3EF7BA7361687695ULL,
		0x710314D61E53127FULL,
		0xCCF57B941F2A8B28ULL,
		0xF836B3B64B6AB127ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83290B15D162749FULL,
		0x53AB102E21A18ACFULL,
		0xE90DA3CEA5B23AE2ULL,
		0xD28911FE7674F4C9ULL,
		0x4BFFEDDBFF2C6C41ULL,
		0xAE76F5BF781BAE56ULL,
		0x416322661511118FULL,
		0x86B150BC26FCB379ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6590B00BD1903FCULL,
		0xA798CA849A05483EULL,
		0xD364E04FDD81A8B5ULL,
		0xABFCD5565997E705ULL,
		0xF2F7CC97623C0A53ULL,
		0xC28C1F16A6376428ULL,
		0x8B92592E0A197998ULL,
		0x718562FA246DFDAEULL
	}};
	sign = 0;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFCADB6E5CFB22A26ULL,
		0xEC9DEA545F4888F1ULL,
		0x26F0941798C26EF1ULL,
		0x59400DD25D909494ULL,
		0x2D0AD6BE433CF33FULL,
		0x40A30769AE010D48ULL,
		0xB4BD480C0465CC39ULL,
		0x688998016957B0B1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x853FA12DBCA550BFULL,
		0x16DACE72950315BFULL,
		0xB2F36D9E3C957D30ULL,
		0x3CD974F6CF171220ULL,
		0x9077E5DBBAEEB463ULL,
		0x0742CD7ECF00C0EEULL,
		0x6022E12587657C5CULL,
		0xA769453A438EBB86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x776E15B8130CD967ULL,
		0xD5C31BE1CA457332ULL,
		0x73FD26795C2CF1C1ULL,
		0x1C6698DB8E798273ULL,
		0x9C92F0E2884E3EDCULL,
		0x396039EADF004C59ULL,
		0x549A66E67D004FDDULL,
		0xC12052C725C8F52BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF5057C2C621E8D09ULL,
		0x28AEF52BE717C8EDULL,
		0x8145DDEED2EEFD02ULL,
		0x36708DB3A58A6576ULL,
		0x9D0E25513E982582ULL,
		0xF078C94DDFF6B9C5ULL,
		0x02BDDA69C7C71DFAULL,
		0xC7DAC5CE8AEDA0FCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F880D93D000E410ULL,
		0x4BF94512A7E77A0DULL,
		0x0932C170A001FA0FULL,
		0xB72A1FC1BC1AF015ULL,
		0x5F4432DFA02EFC14ULL,
		0x22CE49090105DF1AULL,
		0x7295459D73AB0947ULL,
		0x2DC80DE18B0EE5F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x757D6E98921DA8F9ULL,
		0xDCB5B0193F304EE0ULL,
		0x78131C7E32ED02F2ULL,
		0x7F466DF1E96F7561ULL,
		0x3DC9F2719E69296DULL,
		0xCDAA8044DEF0DAABULL,
		0x902894CC541C14B3ULL,
		0x9A12B7ECFFDEBB09ULL
	}};
	sign = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE0B506AD83D83AD4ULL,
		0x97C247AC6EB80D84ULL,
		0x0B6209E04756E4C6ULL,
		0x5C346AB79114EB2BULL,
		0x780A098B458C05BCULL,
		0x1017089330AB287CULL,
		0x3E5F9E0D1D13CC19ULL,
		0x087E6DF5293D4BCDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x816D8CB13CC04D02ULL,
		0xE51CBF1BD5450BB9ULL,
		0x22D29771019C11F4ULL,
		0xD8338E20D8E53B48ULL,
		0x91A3E81978F29607ULL,
		0x488B0D1766DB710EULL,
		0x6DF8AB01753D1C08ULL,
		0x4CCCA9E9AA98070BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F4779FC4717EDD2ULL,
		0xB2A58890997301CBULL,
		0xE88F726F45BAD2D1ULL,
		0x8400DC96B82FAFE2ULL,
		0xE6662171CC996FB4ULL,
		0xC78BFB7BC9CFB76DULL,
		0xD066F30BA7D6B010ULL,
		0xBBB1C40B7EA544C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEA692C3EE24CD319ULL,
		0x27D3B6238D2E55D9ULL,
		0x50B762E5E5303392ULL,
		0x3B062C524C4AD83BULL,
		0x6C2F4F2B6399E23FULL,
		0xFB97BC0BE791DC3AULL,
		0xF0501A03BEDB8BEDULL,
		0x8958EA2CB0C883DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF1BF0024433177EULL,
		0x27C220D252C54ADCULL,
		0x0737722C4E06B0BAULL,
		0x02E3204EF5E8BDFFULL,
		0x63993EF57DA2420AULL,
		0x4A55BDAF7AD5206BULL,
		0x0B4CC984007F733DULL,
		0xE3C51106C4FF99ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B4D3C3C9E19BB9BULL,
		0x001195513A690AFDULL,
		0x497FF0B9972982D8ULL,
		0x38230C0356621A3CULL,
		0x08961035E5F7A035ULL,
		0xB141FE5C6CBCBBCFULL,
		0xE503507FBE5C18B0ULL,
		0xA593D925EBC8EA33ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x43F483612129B387ULL,
		0x459EAD0E084D8B6CULL,
		0xA3031479C1D8C88CULL,
		0xCE6D905AE51FCA99ULL,
		0x3C1700751B02D260ULL,
		0xB3E5574759E90FF9ULL,
		0x90D8F1318EDF21EAULL,
		0x02A20D5F4834C8D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x273984E41DDA96D4ULL,
		0xA61B8CADBAE4286BULL,
		0x89203541ECA47E3FULL,
		0x682AAB5238C76A58ULL,
		0x22C95FF6DA81C164ULL,
		0x9CD481D7062DE329ULL,
		0x5CA532E12FAEB24AULL,
		0x4AE3A95EBC7E1F8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CBAFE7D034F1CB3ULL,
		0x9F8320604D696301ULL,
		0x19E2DF37D5344A4CULL,
		0x6642E508AC586041ULL,
		0x194DA07E408110FCULL,
		0x1710D57053BB2CD0ULL,
		0x3433BE505F306FA0ULL,
		0xB7BE64008BB6A945ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB6D3819193494C9ULL,
		0xE9E948893B23973BULL,
		0x4A168D5132558C4BULL,
		0x23E8E308889EE08BULL,
		0x1D916050A652689BULL,
		0xAE8C7A35E2F61827ULL,
		0x5003EBE8CD35DE14ULL,
		0xF662A95923DCCBB4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6027D2501924F7ADULL,
		0xE5676F5E175D8670ULL,
		0x26E65E507C53690CULL,
		0x50A7067D2FDD2AE0ULL,
		0x6D7186CCB0CDD1A4ULL,
		0x8F519F921A7C8073ULL,
		0xFEC50BDDE13F2037ULL,
		0xD57E8CB868970785ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B4565C9000F9D1CULL,
		0x0481D92B23C610CBULL,
		0x23302F00B602233FULL,
		0xD341DC8B58C1B5ABULL,
		0xB01FD983F58496F6ULL,
		0x1F3ADAA3C87997B3ULL,
		0x513EE00AEBF6BDDDULL,
		0x20E41CA0BB45C42EULL
	}};
	sign = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xABD8C003984C2FC5ULL,
		0x56B5B4802FB9C8EAULL,
		0x20129F8A3A9962EBULL,
		0xC883663897CF7487ULL,
		0xFC8C9AD31EA4661DULL,
		0xAC53B1D02707E725ULL,
		0xD547A804D09421FFULL,
		0xC29F4B78D7D89E8EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B848138B146C94ULL,
		0xA68313507041CD3CULL,
		0x3DF9AC53C2B49B2AULL,
		0x36F32365AE9FAA94ULL,
		0x65CEECB179204F3FULL,
		0x61B2DE3FF135E75BULL,
		0x82F77CB15FDFF776ULL,
		0x19A5523A685DAEF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B2077F00D37C331ULL,
		0xB032A12FBF77FBAEULL,
		0xE218F33677E4C7C0ULL,
		0x919042D2E92FC9F2ULL,
		0x96BDAE21A58416DEULL,
		0x4AA0D39035D1FFCAULL,
		0x52502B5370B42A89ULL,
		0xA8F9F93E6F7AEF98ULL
	}};
	sign = 0;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE10CDA573202F2D2ULL,
		0x60E9FE99F5E04105ULL,
		0x2339DF0CECDDD5E3ULL,
		0x7EC39824286B0F74ULL,
		0x52EFBCAFB1AEA2BEULL,
		0xA42EB538F9846C97ULL,
		0xE296483954E6FFA1ULL,
		0xDD1B189628A4E8F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA45F75EE9435BBECULL,
		0x99E6D1EC44CF9C54ULL,
		0x305F0B3D766E4E46ULL,
		0xBE9C4D7EEC3F08ADULL,
		0xBA310855DBCBCA19ULL,
		0xD57596D5AC36F07DULL,
		0x04B561E6B01CC40CULL,
		0x719673E472341A57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CAD64689DCD36E6ULL,
		0xC7032CADB110A4B1ULL,
		0xF2DAD3CF766F879CULL,
		0xC0274AA53C2C06C6ULL,
		0x98BEB459D5E2D8A4ULL,
		0xCEB91E634D4D7C19ULL,
		0xDDE0E652A4CA3B94ULL,
		0x6B84A4B1B670CE9CULL
	}};
	sign = 0;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6E06691B40300299ULL,
		0x0EECC32AAF9C65BBULL,
		0x2B3570B44131D069ULL,
		0xC24AB02CE487886AULL,
		0x41FECAE1F75AD733ULL,
		0x120C314098A31756ULL,
		0x324A668F370068DDULL,
		0x053DB7AC0CA83CAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4E2074D6451B49BULL,
		0x4CC29EEA7C060627ULL,
		0xDD63C20AF0BB8186ULL,
		0xAE67128A48FB25C6ULL,
		0x69CFEBB565C9D01BULL,
		0x000B3D7B8501F192ULL,
		0xC5AD85AE20D980BCULL,
		0x27A0BC8E84FE58F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x992461CDDBDE4DFEULL,
		0xC22A244033965F93ULL,
		0x4DD1AEA950764EE2ULL,
		0x13E39DA29B8C62A3ULL,
		0xD82EDF2C91910718ULL,
		0x1200F3C513A125C3ULL,
		0x6C9CE0E11626E821ULL,
		0xDD9CFB1D87A9E3B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x83E12FA3CD3A51F0ULL,
		0xC39BB788B1A7D192ULL,
		0xA1C0FBC94440157EULL,
		0xFC665954E6C3B2BEULL,
		0x63C6F9343733C370ULL,
		0xE25ABF9B32F8728AULL,
		0xBA681184E6E83AFBULL,
		0xE759B96F1702E16BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66DC441F51F1D0EEULL,
		0xF2A332B4FADE3104ULL,
		0x7E340A1FF90CC1B4ULL,
		0x1FCA9D9FEFF6DA6FULL,
		0x97173EBA985DB3DCULL,
		0x05C15CD7B125692DULL,
		0xF466FA56626D8FA0ULL,
		0x8BCD654BE9DDB6A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D04EB847B488102ULL,
		0xD0F884D3B6C9A08EULL,
		0x238CF1A94B3353C9ULL,
		0xDC9BBBB4F6CCD84FULL,
		0xCCAFBA799ED60F94ULL,
		0xDC9962C381D3095CULL,
		0xC601172E847AAB5BULL,
		0x5B8C54232D252AC4ULL
	}};
	sign = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDD5E826B531CBA23ULL,
		0x874DF0416D354F6FULL,
		0xD40294A9F7F811FAULL,
		0x3A2EAEA11A043592ULL,
		0x20CBF71166E8123EULL,
		0x7E1D9222AD63A883ULL,
		0x065A87D3347DA365ULL,
		0x7D447DB8E53ABAC9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF80AF6403A240451ULL,
		0x20F1ABC392148323ULL,
		0xA1C4CDAB21CBF52AULL,
		0x6C61687ACBCE96B9ULL,
		0x0EDD6203032FE02DULL,
		0x4C123B8C67CAA87FULL,
		0xF4B3A8649940B63BULL,
		0x844A3C16874FDE92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5538C2B18F8B5D2ULL,
		0x665C447DDB20CC4BULL,
		0x323DC6FED62C1CD0ULL,
		0xCDCD46264E359ED9ULL,
		0x11EE950E63B83210ULL,
		0x320B569645990004ULL,
		0x11A6DF6E9B3CED2AULL,
		0xF8FA41A25DEADC36ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x16DAF23D24145026ULL,
		0x3FD1108429F70F06ULL,
		0x494029592293DB32ULL,
		0x01E298F3900014A7ULL,
		0xF4E450CCA1B601D0ULL,
		0x3C85FF5578EA8D76ULL,
		0x46EDCF3C8E10E37FULL,
		0xE1E06BE73AB459CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8BDF44206F60293ULL,
		0x7B6DBD61D0A70E28ULL,
		0xA5DF3843B3607B76ULL,
		0x69C074F2EE9E89F7ULL,
		0xE92055FACA2CFA0BULL,
		0x0A037E3CCC21AB32ULL,
		0x740EE90874DBABBEULL,
		0x866D74A7725C1788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E1CFDFB1D1E4D93ULL,
		0xC4635322595000DDULL,
		0xA360F1156F335FBBULL,
		0x98222400A1618AAFULL,
		0x0BC3FAD1D78907C4ULL,
		0x32828118ACC8E244ULL,
		0xD2DEE634193537C1ULL,
		0x5B72F73FC8584244ULL
	}};
	sign = 0;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8DF2ED21EF9F8D69ULL,
		0x51013E8DF5C8185EULL,
		0xCBA93CE08B8DC6D2ULL,
		0x05FB92B08A84BA79ULL,
		0xAB928EA6B0534476ULL,
		0xD73298F2589DAB3CULL,
		0x5A1448ED0C82C456ULL,
		0xADFD58BABD3437ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x239832653E30EC9DULL,
		0x76BC5DC94290FD96ULL,
		0x6608F82879D07355ULL,
		0x469258AAFC0A24DCULL,
		0x38830B8D8587207EULL,
		0x81546AD5D711E131ULL,
		0x5F3DA297663F1AFDULL,
		0xE66C9E42FA2E1A56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A5ABABCB16EA0CCULL,
		0xDA44E0C4B3371AC8ULL,
		0x65A044B811BD537CULL,
		0xBF693A058E7A959DULL,
		0x730F83192ACC23F7ULL,
		0x55DE2E1C818BCA0BULL,
		0xFAD6A655A643A959ULL,
		0xC790BA77C3061D56ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x61EA843AA1E05B6DULL,
		0x66D86B2B17CAE0A5ULL,
		0x8018ADF2B72998FDULL,
		0xCEDD8EE5556EA34AULL,
		0x17501CBBEF429BFFULL,
		0x2752466B6D7041E4ULL,
		0x866A43CB4C8B3939ULL,
		0x14CB08991C211F8AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46554A3C9F101776ULL,
		0x52393C65E9C2D5E0ULL,
		0x4134203AB3C97016ULL,
		0x858CE3C1100D9FBCULL,
		0xC2E463FA7824D20CULL,
		0x897EE4A04B0EF327ULL,
		0xD564221C98EBFBFFULL,
		0xD0E8872105E54F5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B9539FE02D043F7ULL,
		0x149F2EC52E080AC5ULL,
		0x3EE48DB8036028E7ULL,
		0x4950AB244561038EULL,
		0x546BB8C1771DC9F3ULL,
		0x9DD361CB22614EBCULL,
		0xB10621AEB39F3D39ULL,
		0x43E28178163BD02BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x78033A84115CF029ULL,
		0x9DC85924AA410B9AULL,
		0x54A88904F97BD8D3ULL,
		0x7147F181DAEC4C52ULL,
		0xAE64534D37583BE7ULL,
		0xD6787C06CD76C920ULL,
		0x79BFFFAEF84273F0ULL,
		0x78488C22E18F7009ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F44177E88E7386ULL,
		0x0947DEA5E338A0E8ULL,
		0x1C4853C57CFA78ECULL,
		0x60C552E03DEE55D5ULL,
		0x2E9FBD5EE81D03B8ULL,
		0xC1862775D83BA9ADULL,
		0x750AF8255BB8D5A2ULL,
		0x16BCB7615D43F7E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA30EF90C28CE7CA3ULL,
		0x94807A7EC7086AB1ULL,
		0x3860353F7C815FE7ULL,
		0x10829EA19CFDF67DULL,
		0x7FC495EE4F3B382FULL,
		0x14F25490F53B1F73ULL,
		0x04B507899C899E4EULL,
		0x618BD4C1844B7829ULL
	}};
	sign = 0;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA1D1714EB29C0A6AULL,
		0xB61A706024F4D2F7ULL,
		0x1DB5E5EDCA769CF9ULL,
		0x316D5DD859132E9FULL,
		0x03F87D466CEDB55CULL,
		0x2A6AF1895B0CDB08ULL,
		0xF857629EA4FDC7F4ULL,
		0x26C015F4EA671BF6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2226936DC80FD079ULL,
		0xEBA94B5E0F25D1F7ULL,
		0x9C6BC764B096BFAFULL,
		0x9402E7DC7D69FBFBULL,
		0x4721331DC3D907CFULL,
		0x5DD502FD9E7645A6ULL,
		0xDAE22120475C3896ULL,
		0xFB0B08B79839341DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FAADDE0EA8C39F1ULL,
		0xCA71250215CF0100ULL,
		0x814A1E8919DFDD49ULL,
		0x9D6A75FBDBA932A3ULL,
		0xBCD74A28A914AD8CULL,
		0xCC95EE8BBC969561ULL,
		0x1D75417E5DA18F5DULL,
		0x2BB50D3D522DE7D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D0AE8E9D09B937AULL,
		0x2D05A7AEB8062021ULL,
		0xC8C5B2FECD7ADB89ULL,
		0x564E23E6291FBDB5ULL,
		0xE166F8ABFB02DE4EULL,
		0x7541C7EE19E4D8DBULL,
		0xB2FD0176B05CED9AULL,
		0xD7FED97DE992C241ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A3C3272E618EDCULL,
		0xAB8E24D871733F92ULL,
		0x002697DFA20C0175ULL,
		0xE7577CB9602F0C00ULL,
		0xB2B65CA60F88C69DULL,
		0x9732DE6CD2245AC2ULL,
		0x46CDD5705401647AULL,
		0x24E4DD8D0C2F2164ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x976725C2A23A049EULL,
		0x817782D64692E08EULL,
		0xC89F1B1F2B6EDA13ULL,
		0x6EF6A72CC8F0B1B5ULL,
		0x2EB09C05EB7A17B0ULL,
		0xDE0EE98147C07E19ULL,
		0x6C2F2C065C5B891FULL,
		0xB319FBF0DD63A0DDULL
	}};
	sign = 0;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x362C593F355FBA73ULL,
		0x45D0FC98A55BFC1BULL,
		0xD4C4C89C924308CFULL,
		0x979BF9148CAED8B4ULL,
		0xB05B625B5FEE57B3ULL,
		0xB375C5354255586EULL,
		0x50F9073346307D17ULL,
		0xE949440C33A3252CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC21C65DB9882D96ULL,
		0x4006AD92B6CCF90AULL,
		0xA7337D8E65BCEA00ULL,
		0x928BC7F5A41D2F81ULL,
		0x51A60EBD04FDA87FULL,
		0x61984268B71216EFULL,
		0x66F109083A077D8AULL,
		0x77CAF17A74A7149FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A0A92E17BD78CDDULL,
		0x05CA4F05EE8F0310ULL,
		0x2D914B0E2C861ECFULL,
		0x0510311EE891A933ULL,
		0x5EB5539E5AF0AF34ULL,
		0x51DD82CC8B43417FULL,
		0xEA07FE2B0C28FF8DULL,
		0x717E5291BEFC108CULL
	}};
	sign = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x423F0E615750B374ULL,
		0x61D900D62DB2A501ULL,
		0x544483B9E93C118AULL,
		0xC5A87F5F7206EB98ULL,
		0x0D2BCC5C2B9A6E34ULL,
		0xA57156A273E893B7ULL,
		0x9548C7EF57D2445EULL,
		0xD639ECFEF6C3492BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9238B52AEE9EA86ULL,
		0x8614628FE42E556CULL,
		0x9BAA1A0D0F6ED8B7ULL,
		0x95A75460B8AFB9E2ULL,
		0xB6C8989E987D9C4CULL,
		0x586BA06B02B6CFE4ULL,
		0xB08E6DEE9868E5BCULL,
		0xBA0C7CE1FD499CBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x891B830EA866C8EEULL,
		0xDBC49E4649844F94ULL,
		0xB89A69ACD9CD38D2ULL,
		0x30012AFEB95731B5ULL,
		0x566333BD931CD1E8ULL,
		0x4D05B6377131C3D2ULL,
		0xE4BA5A00BF695EA2ULL,
		0x1C2D701CF979AC70ULL
	}};
	sign = 0;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0C5FFBDFF6ADEB7ULL,
		0x3428068A0B9E31F0ULL,
		0xE8C53EB7F2E8AA28ULL,
		0xAAEC5286D948DB31ULL,
		0x302D58FBC0ED88A3ULL,
		0x25B3FBAB923AD0D1ULL,
		0xF12738F82E71EE08ULL,
		0x15A1BE7B2C765AABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7DED27DF11DCCBULL,
		0xABE3FDC9184034E5ULL,
		0xAEDB2E3514A239BEULL,
		0x01D5B5E587F9D990ULL,
		0x04A56CDAD802C454ULL,
		0x2187A7EEB2C44B16ULL,
		0x5FBEFA21650A13F7ULL,
		0x1002DD394BFF64E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1481296205901ECULL,
		0x884408C0F35DFD0BULL,
		0x39EA1082DE467069ULL,
		0xA9169CA1514F01A1ULL,
		0x2B87EC20E8EAC44FULL,
		0x042C53BCDF7685BBULL,
		0x91683ED6C967DA11ULL,
		0x059EE141E076F5C4ULL
	}};
	sign = 0;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA34A89B0904249F9ULL,
		0xD8300C1AE8155C77ULL,
		0x87E80D1FA0D4892DULL,
		0x5B570FC7B30146F4ULL,
		0x4F9795E3B5EA31EDULL,
		0x5ACB591F21202F84ULL,
		0xE80C4C491BEA0A43ULL,
		0xF7CAE9E79B533252ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5312BCD2BC7E41F1ULL,
		0x81F13852C6B1D6CEULL,
		0x94073CD239A8E6DCULL,
		0x1B11937B5A7857A2ULL,
		0xAA50FA37CE770663ULL,
		0x3882A1A91BD4CA3EULL,
		0x510105478FF1AC5CULL,
		0xE0DF89FADDB052C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5037CCDDD3C40808ULL,
		0x563ED3C8216385A9ULL,
		0xF3E0D04D672BA251ULL,
		0x40457C4C5888EF51ULL,
		0xA5469BABE7732B8AULL,
		0x2248B776054B6545ULL,
		0x970B47018BF85DE7ULL,
		0x16EB5FECBDA2DF8CULL
	}};
	sign = 0;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE9B3A0B1DC2BC07EULL,
		0x2CAAE2DA0A356360ULL,
		0x83A20AAB492F1A51ULL,
		0x81165C4E351A9F9CULL,
		0x2700E84479DC0417ULL,
		0x3D24FAEE16C4A43CULL,
		0xC5CA119E9AA76BA8ULL,
		0x6AE452C8BE6FB4C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x91936F9BD3DF6A76ULL,
		0x26C15E5C4EA370FFULL,
		0x6E5E68CFE1CB05A4ULL,
		0x4459696B8833ACA5ULL,
		0xE17EE55A11ED1B28ULL,
		0xDC339E5DFA39D794ULL,
		0x51529EFF176C1F6FULL,
		0xBB1315580EC48E99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58203116084C5608ULL,
		0x05E9847DBB91F261ULL,
		0x1543A1DB676414ADULL,
		0x3CBCF2E2ACE6F2F7ULL,
		0x458202EA67EEE8EFULL,
		0x60F15C901C8ACCA7ULL,
		0x7477729F833B4C38ULL,
		0xAFD13D70AFAB262AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0844909C0E71DD47ULL,
		0x853E4B8B2C17EFE5ULL,
		0x4E0FE7F8DB3B7156ULL,
		0x986635E9283F57B6ULL,
		0xCA47475F0CCA3BCAULL,
		0x47BD9BA2F0BF8F76ULL,
		0x0CFC442BE471215BULL,
		0x940E0BC4F5CD7AC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x198BED8D0B52FC0DULL,
		0x24E8DBAF50EE8254ULL,
		0x373D076CB24AE95BULL,
		0xFDD3909BE9CE5E4EULL,
		0x537BA259B9E46C17ULL,
		0x0940D384898FCD01ULL,
		0x1C9E9EA325541D4BULL,
		0x2D89BD9A130769F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEB8A30F031EE13AULL,
		0x60556FDBDB296D90ULL,
		0x16D2E08C28F087FBULL,
		0x9A92A54D3E70F968ULL,
		0x76CBA50552E5CFB2ULL,
		0x3E7CC81E672FC275ULL,
		0xF05DA588BF1D0410ULL,
		0x66844E2AE2C610CFULL
	}};
	sign = 0;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x86C7709DAD71796FULL,
		0x25F3463493284EAEULL,
		0xFA6CA4F06B2910D1ULL,
		0x74E65696A8892B36ULL,
		0x6B9DD2B34BCAF0BDULL,
		0xEE7AFF484A02BFE8ULL,
		0xC99BC8C77230195CULL,
		0xAE54B3F720CC1BB6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA85CBE04B71A2CC1ULL,
		0xE45429E5F28BB654ULL,
		0xDFA64D01441B881CULL,
		0x91929A8B952F7F99ULL,
		0x69B1C2668834BB2AULL,
		0x9072550D7B555EAFULL,
		0x05B7C343DEB34CE4ULL,
		0xFC3C6E24111B7194ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE6AB298F6574CAEULL,
		0x419F1C4EA09C9859ULL,
		0x1AC657EF270D88B4ULL,
		0xE353BC0B1359AB9DULL,
		0x01EC104CC3963592ULL,
		0x5E08AA3ACEAD6139ULL,
		0xC3E40583937CCC78ULL,
		0xB21845D30FB0AA22ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A29130CCFA4AC76ULL,
		0x7450CD3B208EB38BULL,
		0xBBB871D76B33F0F5ULL,
		0xE7954A11D661D4D8ULL,
		0xF86FC91CD72EE78DULL,
		0x8824A3981EA9B0A9ULL,
		0x93DE504494AE5CCBULL,
		0x2324D9598D48BB80ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB6B466EEA379861ULL,
		0xEAF7CCA6335E0279ULL,
		0x0C9D4A81B5B5FAD2ULL,
		0xD35C86FF182B67A9ULL,
		0x9F9A15AD91EE8EA3ULL,
		0xD5411EFC583F6D5AULL,
		0x4994382F5D2D8A6BULL,
		0x6D0BBCF22EBEDEC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EBDCC9DE56D1415ULL,
		0x89590094ED30B111ULL,
		0xAF1B2755B57DF622ULL,
		0x1438C312BE366D2FULL,
		0x58D5B36F454058EAULL,
		0xB2E3849BC66A434FULL,
		0x4A4A18153780D25FULL,
		0xB6191C675E89DCB8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0D77CD9894CE38BULL,
		0xDA7AFA7B86B847E5ULL,
		0x47094AE45763ADCBULL,
		0x8F0DB30D4407958BULL,
		0xF329B1A53975E774ULL,
		0x28142BA2116B85CCULL,
		0x7719745B1CDF9E5EULL,
		0x0D14F6CDA905508CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x932EF0D297BBAF69ULL,
		0x61AE5E316DCDAE9CULL,
		0xBCCB63A6E064620DULL,
		0x9386771EB3C1C1F6ULL,
		0xADA772D2AC67EC4FULL,
		0xB6D43CC2768A4580ULL,
		0xDF74F128DA4BED1DULL,
		0xC7E4E137244C8204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DA88C06F1913422ULL,
		0x78CC9C4A18EA9949ULL,
		0x8A3DE73D76FF4BBEULL,
		0xFB873BEE9045D394ULL,
		0x45823ED28D0DFB24ULL,
		0x713FEEDF9AE1404CULL,
		0x97A483324293B140ULL,
		0x4530159684B8CE87ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9AC7F1868940BB8AULL,
		0x1CE4271EFEF3CCA6ULL,
		0x81BA6A6957086E98ULL,
		0xCAA22408ADFFA3D3ULL,
		0xEB3AAAEFEBEA341DULL,
		0x0A0D9F523E46F50CULL,
		0x9B83C5C636CDF645ULL,
		0x58194D724ABAABC9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA16BD04589C669CULL,
		0x47E7EDD54312850FULL,
		0x4F232F439C3E83DFULL,
		0x6E6DA06EB21F5D7CULL,
		0x8EC11A6C1F03D349ULL,
		0x9768538B1734D284ULL,
		0x1A4DF19047DCB403ULL,
		0x0D850BAD3EB443CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0B1348230A454EEULL,
		0xD4FC3949BBE14796ULL,
		0x32973B25BAC9EAB8ULL,
		0x5C348399FBE04657ULL,
		0x5C799083CCE660D4ULL,
		0x72A54BC727122288ULL,
		0x8135D435EEF14241ULL,
		0x4A9441C50C0667FFULL
	}};
	sign = 0;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2BFC16DD50274BFBULL,
		0xAF57EFDB1BFB3404ULL,
		0x9B6D64B17132A372ULL,
		0x5BEB515747420EEAULL,
		0xA53BA78BCDD498BCULL,
		0xB28664F35DFDBFA9ULL,
		0xBCD9EA5E4DB535CEULL,
		0xEFDF3B44F42DD06FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB1DC9262974B493ULL,
		0xB0585EE39F3F429BULL,
		0xA89DB069D1861D0BULL,
		0xD79EB16367016C31ULL,
		0x31E4887A1DA0833DULL,
		0x906D9362237FD741ULL,
		0xE4BA8A25C16525FDULL,
		0x919A3CC1AD54476DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40DE4DB726B29768ULL,
		0xFEFF90F77CBBF168ULL,
		0xF2CFB4479FAC8666ULL,
		0x844C9FF3E040A2B8ULL,
		0x73571F11B034157EULL,
		0x2218D1913A7DE868ULL,
		0xD81F60388C500FD1ULL,
		0x5E44FE8346D98901ULL
	}};
	sign = 0;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39E7FB896DED2E06ULL,
		0xDAEC771B16F75354ULL,
		0x4FFC95EE1D61E6E5ULL,
		0xAD766AFAFDD0FB84ULL,
		0x8541BA2AC68C9283ULL,
		0xD17D1FB3A185B696ULL,
		0x5BC62E5010D72E93ULL,
		0x494896C58A9DD433ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF5E3D104F307F4ULL,
		0x1421957726C8DBF4ULL,
		0xCD21D41808F0B916ULL,
		0xBADDD93FDC736296ULL,
		0x5858AAA550B3939FULL,
		0x9889489146C54B0AULL,
		0x3A689D15420D9789ULL,
		0xA9D8F60BD2048485ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9F217B868FA2612ULL,
		0xC6CAE1A3F02E775FULL,
		0x82DAC1D614712DCFULL,
		0xF29891BB215D98EDULL,
		0x2CE90F8575D8FEE3ULL,
		0x38F3D7225AC06B8CULL,
		0x215D913ACEC9970AULL,
		0x9F6FA0B9B8994FAEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9145E260AB8933D4ULL,
		0xAC3702A47E52734FULL,
		0x2428F9A3F8BD17A2ULL,
		0xC1C23884AEF7E046ULL,
		0x4FBCB5E4AA532E90ULL,
		0x0D809CC5EBFDCE1CULL,
		0x085F63665895718CULL,
		0x5DEC614E7077598CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1607E0A724618CDBULL,
		0xEBA5D33260E4BAB7ULL,
		0x0E2F3DE4C80AC179ULL,
		0x1892726675179745ULL,
		0xAA2C0ED2B22D6430ULL,
		0x74B494FE8C41D624ULL,
		0xC9D3DD154EEFD75EULL,
		0xA7780CAC9B450B78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B3E01B98727A6F9ULL,
		0xC0912F721D6DB898ULL,
		0x15F9BBBF30B25628ULL,
		0xA92FC61E39E04901ULL,
		0xA590A711F825CA60ULL,
		0x98CC07C75FBBF7F7ULL,
		0x3E8B865109A59A2DULL,
		0xB67454A1D5324E13ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5FCB95DD01F63811ULL,
		0x9F2ADF55662BF604ULL,
		0xDEB8CA2660614F59ULL,
		0x51E002D9CD044871ULL,
		0xC87AFFC5822F673AULL,
		0x1E12953E8A555D7EULL,
		0x1798F2273E6C5D6BULL,
		0x1070459D1DDC8C23ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CEBFEC285B93583ULL,
		0xFC0967078EBA6874ULL,
		0x66E282DD48712E82ULL,
		0x97F83033666745ECULL,
		0x6A648DA4D1EB2528ULL,
		0x0660E4021CE55CECULL,
		0x1B1F350DDA94002CULL,
		0x9196C273AB68E28DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12DF971A7C3D028EULL,
		0xA321784DD7718D90ULL,
		0x77D6474917F020D6ULL,
		0xB9E7D2A6669D0285ULL,
		0x5E167220B0444211ULL,
		0x17B1B13C6D700092ULL,
		0xFC79BD1963D85D3FULL,
		0x7ED983297273A995ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3D2F46628C21668ULL,
		0x277DD4172BDEE681ULL,
		0x546DE39B87DC24A2ULL,
		0xC82F9C7263450A76ULL,
		0x0C88F7B662461CF1ULL,
		0xE4DB1034A833CAA6ULL,
		0xAC4F29166417618EULL,
		0x4127462795989620ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34321B01E51FCAD3ULL,
		0x4A42BB6D611098BBULL,
		0xAB025C02766223E0ULL,
		0x2A46719FC1DB7E0AULL,
		0x9F1BFC28D9BC3D68ULL,
		0x2F529F376EB567D3ULL,
		0x1E9F48821115D473ULL,
		0x468E4C02C8192441ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFA0D96443A24B95ULL,
		0xDD3B18A9CACE4DC6ULL,
		0xA96B8799117A00C1ULL,
		0x9DE92AD2A1698C6BULL,
		0x6D6CFB8D8889DF89ULL,
		0xB58870FD397E62D2ULL,
		0x8DAFE09453018D1BULL,
		0xFA98FA24CD7F71DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCC1F09307BADFC69ULL,
		0xA439634F4F0C8DC0ULL,
		0x824A3EB68404B8F1ULL,
		0xCDEABB6FB7775176ULL,
		0xE5924AD4ECE9AB8AULL,
		0x25AE3D7B651A5981ULL,
		0x38D9888EFA933D67ULL,
		0xA422ECAB81B1D32EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x86055C275E4E202EULL,
		0x9EC5CF249FDA3B39ULL,
		0x58CEDC94AC35C4EEULL,
		0x483C31CC70A6D05AULL,
		0x6DC8226175A7F1C3ULL,
		0x46F46726B4D814D6ULL,
		0x6BE8EE19EE1E6754ULL,
		0xB52817559C5BF874ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4619AD091D5FDC3BULL,
		0x0573942AAF325287ULL,
		0x297B6221D7CEF403ULL,
		0x85AE89A346D0811CULL,
		0x77CA28737741B9C7ULL,
		0xDEB9D654B04244ABULL,
		0xCCF09A750C74D612ULL,
		0xEEFAD555E555DAB9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5B478FB096C213AULL,
		0xF518E6A7C00DB931ULL,
		0xF92D9807C3971760ULL,
		0x3B3932D6A5F595C2ULL,
		0xD76E61CC4F800086ULL,
		0x5A04A7C4EE5F86C1ULL,
		0x8460801FFA99D465ULL,
		0xC48978221905A6DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4DBB3885A4A444ULL,
		0x412F47BF55A264B7ULL,
		0xBD569FAA3CBE1A70ULL,
		0xDF86A469F7559658ULL,
		0x6994FEA9B6A9CD02ULL,
		0xA61F76B74BE03C88ULL,
		0x40BEAE9A558E8C1FULL,
		0xE9BF274045F7F77DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB966BDC283C77CF6ULL,
		0xB3E99EE86A6B547AULL,
		0x3BD6F85D86D8FCF0ULL,
		0x5BB28E6CAE9FFF6AULL,
		0x6DD9632298D63383ULL,
		0xB3E5310DA27F4A39ULL,
		0x43A1D185A50B4845ULL,
		0xDACA50E1D30DAF60ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB6DCF10A0CF80BD1ULL,
		0x5EB60F366D3E15B0ULL,
		0xA870C978C532C78CULL,
		0x42CCABDBC5034466ULL,
		0xA60264E218AE837DULL,
		0x9B39BDA1DEA53E8EULL,
		0xEFD04F7A95C0758FULL,
		0xC2DA1433131EF13BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63823DA88A6707ECULL,
		0x5EECE7479B31710CULL,
		0xDDCF0FC35650E27CULL,
		0x491400956301577DULL,
		0xDF42A14D2BD8172DULL,
		0xD88C55D353DA5C72ULL,
		0xA49D1FCE1E3D2D09ULL,
		0x7796E5FC1C06AF5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x535AB361829103E5ULL,
		0xFFC927EED20CA4A4ULL,
		0xCAA1B9B56EE1E50FULL,
		0xF9B8AB466201ECE8ULL,
		0xC6BFC394ECD66C4FULL,
		0xC2AD67CE8ACAE21BULL,
		0x4B332FAC77834885ULL,
		0x4B432E36F71841E1ULL
	}};
	sign = 0;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB8BBA6894D3294B5ULL,
		0x3DE9C60B36F41589ULL,
		0x0ACC7B03CAB0FFAAULL,
		0x4191060525FFC9F8ULL,
		0xFA2FE7A63E410DABULL,
		0xADA739E025A4A20AULL,
		0x515AF2214984E6D7ULL,
		0xDD3F9B4712FA5C61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8B276F4F0EC33EULL,
		0x77997A85B616B3ECULL,
		0xFD049F372949E290ULL,
		0x06273E2D2E93BDA1ULL,
		0xFE5CF885645EA2BEULL,
		0x041B727AA8ADC835ULL,
		0x6FA71400220C7294ULL,
		0x1783C401D323D9F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A307F19FE23D177ULL,
		0xC6504B8580DD619DULL,
		0x0DC7DBCCA1671D19ULL,
		0x3B69C7D7F76C0C56ULL,
		0xFBD2EF20D9E26AEDULL,
		0xA98BC7657CF6D9D4ULL,
		0xE1B3DE2127787443ULL,
		0xC5BBD7453FD6826DULL
	}};
	sign = 0;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCB4462B2DE527AFCULL,
		0x8CF053717FC1E850ULL,
		0xB40A3E55D21C1994ULL,
		0xFA83DD1B0B9205B2ULL,
		0x96AFE9B5D92C0B6EULL,
		0xF307DCF8E7D124D0ULL,
		0x13AC8DB6891DA3A4ULL,
		0x030420B30CFFDBC0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7BECA928FBB95CULL,
		0x8108D327F390906EULL,
		0xB3FB6336017ED2EFULL,
		0x13FA12E82DAE3049ULL,
		0xC94B00EF261E74C7ULL,
		0x21D4A70A48B53FD2ULL,
		0x202318DE7749D14DULL,
		0x568178F6064722EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFC87609B556C1A0ULL,
		0x0BE780498C3157E1ULL,
		0x000EDB1FD09D46A5ULL,
		0xE689CA32DDE3D569ULL,
		0xCD64E8C6B30D96A7ULL,
		0xD13335EE9F1BE4FDULL,
		0xF38974D811D3D257ULL,
		0xAC82A7BD06B8B8D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2AA09454A8E446B2ULL,
		0x3BD6E3A70122EA7AULL,
		0xD9C3AE74D28A0C2CULL,
		0x5035C7EC9C1D8EBAULL,
		0xFA5730F0AAD4EF57ULL,
		0x5B735D610BE0ED97ULL,
		0xC0F9A68EF93F56CEULL,
		0x1BDC2F5705E210CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DBEC64D69745B6BULL,
		0xFD9BBA60993916D6ULL,
		0xB58AAC3DE6D1B718ULL,
		0x23C7E7CFC9DA6029ULL,
		0x5B37A9176B1FF6E0ULL,
		0x8BEA73FD4DB81195ULL,
		0x04E73128014A3E38ULL,
		0x504A5A4C6AD59ADEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CE1CE073F6FEB47ULL,
		0x3E3B294667E9D3A3ULL,
		0x24390236EBB85513ULL,
		0x2C6DE01CD2432E91ULL,
		0x9F1F87D93FB4F877ULL,
		0xCF88E963BE28DC02ULL,
		0xBC127566F7F51895ULL,
		0xCB91D50A9B0C75F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x09BCC5CB286AAFDDULL,
		0x80C608DF66C49EA2ULL,
		0x4F096410177B1FB6ULL,
		0x2303313529B1DA29ULL,
		0xDBBC33AC4ABF22F0ULL,
		0x9A332ABFB4AE642AULL,
		0xB78764BF7E7E9AADULL,
		0xFE0B4EFF668D0110ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51D2B03642C9BC8ULL,
		0x9A37BAD06C0928ACULL,
		0x52414F574529A484ULL,
		0xE39D2B9AACAC46C1ULL,
		0x65BCCDB584AF14D8ULL,
		0x708180ED3A469D3CULL,
		0x4F6B2AFFF22C697DULL,
		0x06F645CC48F43F97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x449F9AC7C43E1415ULL,
		0xE68E4E0EFABB75F5ULL,
		0xFCC814B8D2517B31ULL,
		0x3F66059A7D059367ULL,
		0x75FF65F6C6100E17ULL,
		0x29B1A9D27A67C6EEULL,
		0x681C39BF8C523130ULL,
		0xF71509331D98C179ULL
	}};
	sign = 0;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF88BF91678B84D3EULL,
		0xAC0BF24BB1D3F60DULL,
		0x4E836814C30D1DBCULL,
		0xB8B8DBF44DCFE7FAULL,
		0xAFFBF80F9EF906EAULL,
		0x735451369A75EDC6ULL,
		0x30E626BBED8E4FB4ULL,
		0x80004D779F01130CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E754C2E70B6202ULL,
		0xCA9FC4DFBFE22799ULL,
		0x65D268E840DA62A2ULL,
		0x712FF82383A80076ULL,
		0xEF98403A3AEC069FULL,
		0xFEF4D90B55E2D82DULL,
		0xFF88ADC1C99620D3ULL,
		0x9B5DA1BA3BBC373EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7A4A45391ACEB3CULL,
		0xE16C2D6BF1F1CE74ULL,
		0xE8B0FF2C8232BB19ULL,
		0x4788E3D0CA27E783ULL,
		0xC063B7D5640D004BULL,
		0x745F782B44931598ULL,
		0x315D78FA23F82EE0ULL,
		0xE4A2ABBD6344DBCDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x897B560D33117CE5ULL,
		0x9AF75C07259BB6EEULL,
		0x74B32CC9DDCE7785ULL,
		0xC659F16C4FD54F0BULL,
		0xF14DF64982CA3326ULL,
		0xD1FD5D80A56DD78EULL,
		0xD5700716E72051D5ULL,
		0x24394577F475D0B7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2657A352A1B8C8ULL,
		0xDE62E771715A5DAEULL,
		0x2E64D2E2584E8FD9ULL,
		0x5A5A16F91A6E4FAAULL,
		0x2EA164EA78486A66ULL,
		0x4F7035B4A8458A8AULL,
		0x2F71BC000AC0CF0AULL,
		0xA8DB1C4AE1FCAA7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F54FE69E06FC41DULL,
		0xBC947495B4415940ULL,
		0x464E59E7857FE7ABULL,
		0x6BFFDA733566FF61ULL,
		0xC2AC915F0A81C8C0ULL,
		0x828D27CBFD284D04ULL,
		0xA5FE4B16DC5F82CBULL,
		0x7B5E292D12792639ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6EFCEC9D9E1FB444ULL,
		0x61752E9003F6CF24ULL,
		0xC13224EE19F06224ULL,
		0xCD0DEBA346025D2CULL,
		0xFEF62FDF82F31953ULL,
		0xA9B85A2B8B633958ULL,
		0xAAED2D08486912EDULL,
		0xCAAE99F97E0F7C22ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC0AC5C79764CC18ULL,
		0xF8C909C2C6E6115EULL,
		0x140F65162AF63C41ULL,
		0x6A1C185AF963BB5CULL,
		0x477526C5CE0DC054ULL,
		0x382C7B7A21F9EEC8ULL,
		0xE4D64AE342B635F3ULL,
		0x8F02626AFAFF8EA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2F226D606BAE82CULL,
		0x68AC24CD3D10BDC5ULL,
		0xAD22BFD7EEFA25E2ULL,
		0x62F1D3484C9EA1D0ULL,
		0xB7810919B4E558FFULL,
		0x718BDEB169694A90ULL,
		0xC616E22505B2DCFAULL,
		0x3BAC378E830FED7CULL
	}};
	sign = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEA80E00C72145312ULL,
		0x111064504D685200ULL,
		0xC896354F8DD8F309ULL,
		0xA6840959E5CB7E34ULL,
		0xEB55802A91275233ULL,
		0xC239E873B93C25C4ULL,
		0x50A86493C4F3C5D3ULL,
		0x5D70663394E00584ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E29D9C483FC0A7ULL,
		0xBEC45E81A7547279ULL,
		0x465F4A74365081E5ULL,
		0xCB4D9AF63A1905F2ULL,
		0x13AF69136A629E8DULL,
		0xDDED2F7369DF7238ULL,
		0xA3755708EF94DCAEULL,
		0x21CFC66E8B5B051BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF99E427029D4926BULL,
		0x524C05CEA613DF86ULL,
		0x8236EADB57887123ULL,
		0xDB366E63ABB27842ULL,
		0xD7A6171726C4B3A5ULL,
		0xE44CB9004F5CB38CULL,
		0xAD330D8AD55EE924ULL,
		0x3BA09FC509850068ULL
	}};
	sign = 0;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x75B108ACECF55A1DULL,
		0xA42639256A9DEF3EULL,
		0xBBB840A7E13D6D58ULL,
		0x367D05DFAE65C82AULL,
		0x04FB6F9C2C372196ULL,
		0x7A781B565A36A9FEULL,
		0x33270ACDC68D152AULL,
		0xA51777E045CE6456ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA322C5E3105EB340ULL,
		0x05C46B4FB8454FB4ULL,
		0x8207F9E2E6A9A401ULL,
		0xF31896D52F70E90AULL,
		0xF01D692D2625DC02ULL,
		0xCEEB0A0A20E41AA7ULL,
		0xFFD8BFA9A7C7F89CULL,
		0x2A5CFB376BDD6C09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD28E42C9DC96A6DDULL,
		0x9E61CDD5B2589F89ULL,
		0x39B046C4FA93C957ULL,
		0x43646F0A7EF4DF20ULL,
		0x14DE066F06114593ULL,
		0xAB8D114C39528F56ULL,
		0x334E4B241EC51C8DULL,
		0x7ABA7CA8D9F0F84CULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA084F0C3D4AE6BEEULL,
		0xD063FE8CAB16985EULL,
		0xE1CF2A508C85708EULL,
		0xE17CB4F476CF74BCULL,
		0xC28D51F429416EF8ULL,
		0xD8FFA0046E31E1F2ULL,
		0xDDC91E272140D6D9ULL,
		0xC59D4D0AEDFD1A53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB61FDC30C3306CAULL,
		0xA5AC45DD2F7A5D4CULL,
		0x157D024B63F6CC85ULL,
		0x6BD6DDC45CDBBE9EULL,
		0xA1BADF7A606D2633ULL,
		0x205D858D8CAC9506ULL,
		0x249672B1F21BA79BULL,
		0x63CB375299FFB8F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB522F300C87B6524ULL,
		0x2AB7B8AF7B9C3B11ULL,
		0xCC522805288EA409ULL,
		0x75A5D73019F3B61EULL,
		0x20D27279C8D448C5ULL,
		0xB8A21A76E1854CECULL,
		0xB932AB752F252F3EULL,
		0x61D215B853FD615EULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x84EDF72E654BB246ULL,
		0xD84FBBDE384977E1ULL,
		0x965F15877CE18E9FULL,
		0x542A6C0023F8542FULL,
		0xFFB91E7304B343AAULL,
		0x9341B88843345C43ULL,
		0xE8688619D38C9AD3ULL,
		0xE8175213A7887C36ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A975252D909F947ULL,
		0x47692F7D6B285264ULL,
		0x81F22BCDD20B2A05ULL,
		0x3D3FA43295414F14ULL,
		0x6A100F60DFFBD920ULL,
		0x55117585220A541EULL,
		0xB8E098E6D28C586AULL,
		0x961644EE5B05AFFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA56A4DB8C41B8FFULL,
		0x90E68C60CD21257CULL,
		0x146CE9B9AAD6649AULL,
		0x16EAC7CD8EB7051BULL,
		0x95A90F1224B76A8AULL,
		0x3E304303212A0825ULL,
		0x2F87ED3301004269ULL,
		0x52010D254C82CC37ULL
	}};
	sign = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x96B51222CFE8095FULL,
		0x99ACC65A68BEA948ULL,
		0x8C201D4CFF6FB323ULL,
		0x4F1CD4BCBF32763FULL,
		0xC6EA0B9E974B62C1ULL,
		0x5E02192EB508D7F0ULL,
		0x1F64D371CBB57A5DULL,
		0xEB7B9D70ECA5C3ACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9308B5F3735A30C5ULL,
		0xCBE2AE6E2DC550C8ULL,
		0x2E8D40DF1F9637E2ULL,
		0x073A76FE2C4CC2B4ULL,
		0x979631DB16537763ULL,
		0xC756A260C8253381ULL,
		0xE1508FFAA65B3DB7ULL,
		0x24E8A0223460B27EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03AC5C2F5C8DD89AULL,
		0xCDCA17EC3AF95880ULL,
		0x5D92DC6DDFD97B40ULL,
		0x47E25DBE92E5B38BULL,
		0x2F53D9C380F7EB5EULL,
		0x96AB76CDECE3A46FULL,
		0x3E144377255A3CA5ULL,
		0xC692FD4EB845112DULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x41B6CE16691629D6ULL,
		0x028FE9FEA9DB5C68ULL,
		0x70274539EEC9460FULL,
		0x27BCEB3A5C3EDBBEULL,
		0x933A2736F9396D6AULL,
		0x8341D0967A537992ULL,
		0x7AD1DA7D9077020BULL,
		0xA1C3A7933044B534ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D29AC9DFE0F8B31ULL,
		0x1F9BC351FC6F3BB2ULL,
		0xD3B62B6D08E42C5BULL,
		0xD620B5D201BF6CDCULL,
		0xAE74655E52A25CEEULL,
		0x84473CFF29483382ULL,
		0x98918DBC0FE878A8ULL,
		0x45016F9E950691EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA48D21786B069EA5ULL,
		0xE2F426ACAD6C20B5ULL,
		0x9C7119CCE5E519B3ULL,
		0x519C35685A7F6EE1ULL,
		0xE4C5C1D8A697107BULL,
		0xFEFA9397510B460FULL,
		0xE2404CC1808E8962ULL,
		0x5CC237F49B3E2348ULL
	}};
	sign = 0;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x40762FF6BFB06726ULL,
		0xA205AE5793293200ULL,
		0x5A271315FE586F1CULL,
		0x056DEA1A4413BC0DULL,
		0xB216C1B424584F2DULL,
		0x859D9B8DF4A88B1AULL,
		0xA94868D03C14C229ULL,
		0x827534384BECE489ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D074F8676BD131ULL,
		0xEE86D2AF9D8885EDULL,
		0xAC4BB2C8E50EA392ULL,
		0x91C944C52B08D101ULL,
		0x615AAAAAC73EF756ULL,
		0x48771A5EE748E8D4ULL,
		0x94E1F04FA4D6D2D5ULL,
		0x065163A21FDF64DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68A5BAFE584495F5ULL,
		0xB37EDBA7F5A0AC12ULL,
		0xADDB604D1949CB89ULL,
		0x73A4A555190AEB0BULL,
		0x50BC17095D1957D6ULL,
		0x3D26812F0D5FA246ULL,
		0x14667880973DEF54ULL,
		0x7C23D0962C0D7FADULL
	}};
	sign = 0;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06DCC16AD02CFCCEULL,
		0x5D6A88F9A3111C0AULL,
		0x49D64366EE4447CAULL,
		0xE92797E20B894857ULL,
		0x334129452703FD8FULL,
		0x115E5C561C07E299ULL,
		0x9BB4F3F21681E5E6ULL,
		0xD58BC4BB5D5654D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x893694B6EABCA2C1ULL,
		0x920F2DCB26ADD402ULL,
		0x015FFF2AF3BC838FULL,
		0xD0F357D5A88B8D4BULL,
		0x4E41FFD15AB47F63ULL,
		0xEC78AA73690F02F2ULL,
		0xDB1E4E227C735944ULL,
		0xB26958E75F7ABA1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DA62CB3E5705A0DULL,
		0xCB5B5B2E7C634807ULL,
		0x4876443BFA87C43AULL,
		0x1834400C62FDBB0CULL,
		0xE4FF2973CC4F7E2CULL,
		0x24E5B1E2B2F8DFA6ULL,
		0xC096A5CF9A0E8CA1ULL,
		0x23226BD3FDDB9AB8ULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0E85E9A0D192326ULL,
		0x3A2D012D8EC860EDULL,
		0xA9BE99C501ECF400ULL,
		0x89937E13B86CB0D8ULL,
		0x5C280C1338BF46B8ULL,
		0x1B55374A4A090C8FULL,
		0xBC7A14CF871B7348ULL,
		0x8A6A1C3FA94E5910ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DE1B29A79FBA63ULL,
		0xAEADEB1675340845ULL,
		0x321138FB1414336EULL,
		0xB2957E77666D98D9ULL,
		0x4A36FDC730D95F56ULL,
		0x654BA5157ABF60BDULL,
		0xCE49292FB1A3D900ULL,
		0x445A89F836A186AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A0A4370657968C3ULL,
		0x8B7F1617199458A8ULL,
		0x77AD60C9EDD8C091ULL,
		0xD6FDFF9C51FF17FFULL,
		0x11F10E4C07E5E761ULL,
		0xB6099234CF49ABD2ULL,
		0xEE30EB9FD5779A47ULL,
		0x460F924772ACD260ULL
	}};
	sign = 0;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82180BC79CCF5863ULL,
		0x791143BDABF2D2E2ULL,
		0x456C19FEC97A3414ULL,
		0x4600266C6A93AC37ULL,
		0x685D05EE00818674ULL,
		0xF2B6BD9E84822A73ULL,
		0xFCFBAAEAFD4990D7ULL,
		0x6949C053A7950C07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E016D6DF719A448ULL,
		0x70272937888BCB2FULL,
		0xE93BDA49B9CFEF7AULL,
		0x119634456C79C3ABULL,
		0x60AF8020778F9A66ULL,
		0x25C4E6783685D498ULL,
		0xFE0C208F7AC206F8ULL,
		0x0B0E1A09149CA2ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4169E59A5B5B41BULL,
		0x08EA1A86236707B2ULL,
		0x5C303FB50FAA449AULL,
		0x3469F226FE19E88BULL,
		0x07AD85CD88F1EC0EULL,
		0xCCF1D7264DFC55DBULL,
		0xFEEF8A5B828789DFULL,
		0x5E3BA64A92F8695AULL
	}};
	sign = 0;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDAF9B7938BFF8E38ULL,
		0x2B9CDB8B32BED205ULL,
		0x5CFC3435FC598590ULL,
		0x49F85D0C8F39EF22ULL,
		0xA039C5662572944CULL,
		0x03D5AD93D1BBA7A0ULL,
		0x66E3E207268A9FC7ULL,
		0xE222FF48038AA475ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B771E59E4DDC67FULL,
		0xC5632CDF0716892AULL,
		0x72958794F0208ED9ULL,
		0xDD8279D4EE6C4A79ULL,
		0xD081D54FED883F18ULL,
		0x9F7AF9E8C99B65B0ULL,
		0x0E0A7F19945101B3ULL,
		0x0CF0916ABED87EBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F829939A721C7B9ULL,
		0x6639AEAC2BA848DBULL,
		0xEA66ACA10C38F6B6ULL,
		0x6C75E337A0CDA4A8ULL,
		0xCFB7F01637EA5533ULL,
		0x645AB3AB082041EFULL,
		0x58D962ED92399E13ULL,
		0xD5326DDD44B225B7ULL
	}};
	sign = 0;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1029D01BD72BA088ULL,
		0xC1FDA0FCE5B35BB4ULL,
		0x3E1728647044BB68ULL,
		0xD7A4B40C3E601324ULL,
		0x8FCC71384674B9F6ULL,
		0x6AB499495612E42EULL,
		0x64D4C5CEC4AD8C5CULL,
		0x01AA556D8906CBB8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB4A19A1D51582F3ULL,
		0xE9D4884F2F5971BCULL,
		0xB39D844DDB965A2FULL,
		0xFE2C18A71DAE9E49ULL,
		0x61453CA57CC9FF36ULL,
		0x3D519D5524D5CA72ULL,
		0x5BB0C5D37B17113CULL,
		0x92FDDF645205417FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54DFB67A02161D95ULL,
		0xD82918ADB659E9F7ULL,
		0x8A79A41694AE6138ULL,
		0xD9789B6520B174DAULL,
		0x2E873492C9AABABFULL,
		0x2D62FBF4313D19BCULL,
		0x0923FFFB49967B20ULL,
		0x6EAC760937018A39ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAD4F9A9C7119E94CULL,
		0x37363DAA1B9BEA80ULL,
		0x82FB69771970BD36ULL,
		0xD54B12C2C1A63115ULL,
		0x58E70A83E094FA52ULL,
		0xA854CDF296495FF6ULL,
		0xB7AE2A00175C851BULL,
		0x8F621A72E52C9141ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3931B67389D0FE67ULL,
		0x94B363D46A8ED8F1ULL,
		0x43D62096DAF638FBULL,
		0x8698A21909DCA0F9ULL,
		0x35174C8719029C16ULL,
		0xC3B2FA38165B0CC8ULL,
		0xBAC22ECF00340035ULL,
		0xA0F226501FE5195AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x741DE428E748EAE5ULL,
		0xA282D9D5B10D118FULL,
		0x3F2548E03E7A843AULL,
		0x4EB270A9B7C9901CULL,
		0x23CFBDFCC7925E3CULL,
		0xE4A1D3BA7FEE532EULL,
		0xFCEBFB31172884E5ULL,
		0xEE6FF422C54777E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x43BFD33163E8E10DULL,
		0x42C149D2B4124DE2ULL,
		0x744624D0FF914DB4ULL,
		0x63FD5DE1DDAD476FULL,
		0x88387B88BAEAD966ULL,
		0x2F11553472FD1340ULL,
		0x21D7241884F0C6F0ULL,
		0xF9A78DF1E4C43B6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0C66A101AA5219ULL,
		0x6233A22E430C0D00ULL,
		0xB284D8055D9FFF49ULL,
		0xE38BD5E1BE1B7B95ULL,
		0xEDE327294C74BC01ULL,
		0xBAF870160A716B3EULL,
		0xB8E80E8305B3827EULL,
		0xF8D491AD8CB927D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37B36C90623E8EF4ULL,
		0xE08DA7A4710640E2ULL,
		0xC1C14CCBA1F14E6AULL,
		0x807188001F91CBD9ULL,
		0x9A55545F6E761D64ULL,
		0x7418E51E688BA801ULL,
		0x68EF15957F3D4471ULL,
		0x00D2FC44580B1396ULL
	}};
	sign = 0;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3E4D1A7D4624C34CULL,
		0x411F9DDA4E6BA417ULL,
		0xA59B9DF05B14D4B5ULL,
		0xB74EEA61FCCD7B52ULL,
		0xA42B7DC99A4136D4ULL,
		0x8CF034FC362D5F16ULL,
		0x5136E822C5327C7BULL,
		0x9F81F12337D66396ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA6E1F454FBB25FULL,
		0x5F0AB26B2E96D855ULL,
		0x693B8B30B6745664ULL,
		0xDD9E9276930D9C3BULL,
		0xB5875136DC70A35AULL,
		0x160E0D0449FD9908ULL,
		0xF38CB400AE212091ULL,
		0x5703EBCAF33B043AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03A63888F12910EDULL,
		0xE214EB6F1FD4CBC2ULL,
		0x3C6012BFA4A07E50ULL,
		0xD9B057EB69BFDF17ULL,
		0xEEA42C92BDD09379ULL,
		0x76E227F7EC2FC60DULL,
		0x5DAA342217115BEAULL,
		0x487E0558449B5F5BULL
	}};
	sign = 0;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB64DE957E4317BF8ULL,
		0x42FD0BC02E45FCEFULL,
		0xA5E876CA6D4F8DD5ULL,
		0x2C8020880631B435ULL,
		0x81D4A30B75FB05B9ULL,
		0x2AD845942CA71E1DULL,
		0xA51BCFBEC3CF97A2ULL,
		0x8B78A63AFBA73DD9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9586E5C673AFD84ULL,
		0xB6A82B1A3365CAC2ULL,
		0x055A1875A9A92ED4ULL,
		0x09094C8FF21CE8C9ULL,
		0xCEB8F62C8E00B0D7ULL,
		0x069589957E52E79FULL,
		0x2308230014B5CE01ULL,
		0x9CFD83F6155CA9A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCF57AFB7CF67E74ULL,
		0x8C54E0A5FAE0322CULL,
		0xA08E5E54C3A65F00ULL,
		0x2376D3F81414CB6CULL,
		0xB31BACDEE7FA54E2ULL,
		0x2442BBFEAE54367DULL,
		0x8213ACBEAF19C9A1ULL,
		0xEE7B2244E64A9432ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x414BBE4B9A537542ULL,
		0x359D0C1944FE72BFULL,
		0x58CEA058904BF370ULL,
		0xFEC1FFC39A5D5AD9ULL,
		0x6DA67825436193D9ULL,
		0x6A651EFF9EDC1A34ULL,
		0xF1159C0A4EE42CDBULL,
		0xB301EECD7841815BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4D1204760B26CCULL,
		0x75C86F83C7EE771EULL,
		0x0C6BC55A46EF8F8CULL,
		0x7829CFE071A0F272ULL,
		0x34B291BD3CC58FC7ULL,
		0x86BD8981564E5B82ULL,
		0x14ABA23C0EB17B2FULL,
		0x24EDCC93108BA050ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71FEAC4724484E76ULL,
		0xBFD49C957D0FFBA0ULL,
		0x4C62DAFE495C63E3ULL,
		0x86982FE328BC6867ULL,
		0x38F3E668069C0412ULL,
		0xE3A7957E488DBEB2ULL,
		0xDC69F9CE4032B1ABULL,
		0x8E14223A67B5E10BULL
	}};
	sign = 0;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEE60752AF58190D1ULL,
		0xB5379DC0BEF5D04BULL,
		0x94C01B9D91BDF88CULL,
		0xB52C9ADF07B33AB4ULL,
		0xF4F037730D1768A1ULL,
		0xA8DB46B4ABCF3B5AULL,
		0xC0DC3E18A71A7036ULL,
		0x5995C519B24A3B02ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69DD012420927D72ULL,
		0xD5DFD7C44E2090DCULL,
		0x410CDE1A118FCD55ULL,
		0x53F0CAE77D03DE3AULL,
		0xAACDB17B0B45786DULL,
		0xC01F2533460BB609ULL,
		0xB674315757E6287AULL,
		0x44BC2EF157685190ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84837406D4EF135FULL,
		0xDF57C5FC70D53F6FULL,
		0x53B33D83802E2B36ULL,
		0x613BCFF78AAF5C7AULL,
		0x4A2285F801D1F034ULL,
		0xE8BC218165C38551ULL,
		0x0A680CC14F3447BBULL,
		0x14D996285AE1E972ULL
	}};
	sign = 0;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7DD91282BA5CEB50ULL,
		0xA841567EC0C6071AULL,
		0x349DF26E12E2159DULL,
		0xB2E279B23509A436ULL,
		0x9E993ADEE2822D29ULL,
		0x89C5550E198359F8ULL,
		0x73D4841F7969E27FULL,
		0xF66A19CC15C3D5E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x736BC68F864D1B30ULL,
		0xA06E6CC8C9A63801ULL,
		0x4EF3668031B4CC86ULL,
		0x7A0CB77E8558471CULL,
		0x813281E76FB176BEULL,
		0x2C07A3F7C46ECA1CULL,
		0x366A374DE9C804D6ULL,
		0x84B70A74867F67FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A6D4BF3340FD020ULL,
		0x07D2E9B5F71FCF19ULL,
		0xE5AA8BEDE12D4917ULL,
		0x38D5C233AFB15D19ULL,
		0x1D66B8F772D0B66BULL,
		0x5DBDB11655148FDCULL,
		0x3D6A4CD18FA1DDA9ULL,
		0x71B30F578F446DE5ULL
	}};
	sign = 0;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0C008A04B8B94C7AULL,
		0x22DFDBC30AA51E8AULL,
		0x691CA0EA4052E1D8ULL,
		0x5D2B000B5E1533CCULL,
		0xCB1FED6023D24BF8ULL,
		0xE302BD9882C69490ULL,
		0x0B4571715B614609ULL,
		0x36BE3A2136A27753ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x545B1C7882E56304ULL,
		0x0651887859FF1ADFULL,
		0x0825E73173BAFFE4ULL,
		0xC4B998D5E9528599ULL,
		0x98B714EF7133EC90ULL,
		0x543DB9A75504B289ULL,
		0x91161045107F71C1ULL,
		0x18341228484399B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7A56D8C35D3E976ULL,
		0x1C8E534AB0A603AAULL,
		0x60F6B9B8CC97E1F4ULL,
		0x9871673574C2AE33ULL,
		0x3268D870B29E5F67ULL,
		0x8EC503F12DC1E207ULL,
		0x7A2F612C4AE1D448ULL,
		0x1E8A27F8EE5EDD9FULL
	}};
	sign = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x83F3AFC0EC2A02A7ULL,
		0xDF69611CEA139539ULL,
		0x788E73361A6A3075ULL,
		0xD815231F81C35109ULL,
		0x101624AF9E37D4B0ULL,
		0x03DF21071801CF1AULL,
		0xAE66338929BDB943ULL,
		0x670DD3D604CE48C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF9E93311FA8042EULL,
		0xF8EE764AAF359943ULL,
		0x17F5706E07D26332ULL,
		0x2EFDA755E30F1641ULL,
		0x71F66B175384AADDULL,
		0x351A305EF587A286ULL,
		0xC71F0BB7B1F9B22DULL,
		0xBA6983E3D65F1864ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4551C8FCC81FE79ULL,
		0xE67AEAD23ADDFBF5ULL,
		0x609902C81297CD42ULL,
		0xA9177BC99EB43AC8ULL,
		0x9E1FB9984AB329D3ULL,
		0xCEC4F0A8227A2C93ULL,
		0xE74727D177C40715ULL,
		0xACA44FF22E6F305FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD1351C6C57932B08ULL,
		0xB9ADAFF237699ADDULL,
		0x0B9EF18147A49076ULL,
		0x6A5672E0B1EDD02FULL,
		0x6CCA739C2FCD5D70ULL,
		0x250388F2071AE3E5ULL,
		0x93A6F08BC2B21180ULL,
		0x9941800C26D60EA5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E992C48493EBAD1ULL,
		0xF2C07BC61EA8C46AULL,
		0x40ADC3D5D99978EAULL,
		0x7DFCFED2AEFEC083ULL,
		0x4CFD9E31C3AFB1B7ULL,
		0x5EC2ECF2E11D7A8BULL,
		0x7D9D98CF94EB6DCEULL,
		0xAA5607A663CB9703ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x529BF0240E547037ULL,
		0xC6ED342C18C0D673ULL,
		0xCAF12DAB6E0B178BULL,
		0xEC59740E02EF0FABULL,
		0x1FCCD56A6C1DABB8ULL,
		0xC6409BFF25FD695AULL,
		0x160957BC2DC6A3B1ULL,
		0xEEEB7865C30A77A2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x726A2BA7E15037FAULL,
		0xE1E1D9F90BBAE73FULL,
		0x12259A6A3361DBDFULL,
		0xC67B300CD6BA2109ULL,
		0xB0C93E940B8063DAULL,
		0xEE418B99636F4477ULL,
		0xDF1D187FFB30E578ULL,
		0x8CCD14E84C1876BDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x96F5C6B4A04000A2ULL,
		0x439CA0F708D41177ULL,
		0x79AFE25843640D92ULL,
		0x518E45579AF08940ULL,
		0x52E5C73043ABDC47ULL,
		0x177F18D95C8783C0ULL,
		0x79246CE1DD615952ULL,
		0x4F1A5E28D2DED845ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB7464F341103758ULL,
		0x9E45390202E6D5C7ULL,
		0x9875B811EFFDCE4DULL,
		0x74ECEAB53BC997C8ULL,
		0x5DE37763C7D48793ULL,
		0xD6C272C006E7C0B7ULL,
		0x65F8AB9E1DCF8C26ULL,
		0x3DB2B6BF79399E78ULL
	}};
	sign = 0;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x24ABA80DA5B6A714ULL,
		0x182A0E1670222E52ULL,
		0x8B4DE571A01CCF86ULL,
		0x55E6D5BD0CBDAAAFULL,
		0xCDF7447D2B681A0AULL,
		0x9382548C9471454FULL,
		0x62A6617C308B0181ULL,
		0x663B32FEED39A214ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x91784E2F00267A41ULL,
		0x78BD0A541A644D85ULL,
		0x4916F1D030C9F68EULL,
		0xA986731FD6BD8D6AULL,
		0x6262A75BF49DEF75ULL,
		0x9D392FE001DBFF4BULL,
		0x1490637E6F00C505ULL,
		0x50558B169AD134CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x933359DEA5902CD3ULL,
		0x9F6D03C255BDE0CCULL,
		0x4236F3A16F52D8F7ULL,
		0xAC60629D36001D45ULL,
		0x6B949D2136CA2A94ULL,
		0xF64924AC92954604ULL,
		0x4E15FDFDC18A3C7BULL,
		0x15E5A7E852686D47ULL
	}};
	sign = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x755758BB478C4764ULL,
		0x8B0C63F8BA5455BFULL,
		0x5C80C5C538A66D6CULL,
		0xF6F690AC4A36D598ULL,
		0xAD06259499CE1F41ULL,
		0x88AAEB9ECB9D54A0ULL,
		0x849436BFAD09135AULL,
		0x2E750F6482815CAEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E549AFBFE1722AULL,
		0xABC9AC3AAD7579CFULL,
		0x9C361B081DC729F3ULL,
		0x9B020F64871CA75EULL,
		0xD664D3A9CDBA5582ULL,
		0x222C31F5EEBED95EULL,
		0x5C8550317022A0ADULL,
		0x0BAA1CF9FF3CB5CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D720F0B87AAD53AULL,
		0xDF42B7BE0CDEDBEFULL,
		0xC04AAABD1ADF4378ULL,
		0x5BF48147C31A2E39ULL,
		0xD6A151EACC13C9BFULL,
		0x667EB9A8DCDE7B41ULL,
		0x280EE68E3CE672ADULL,
		0x22CAF26A8344A6E4ULL
	}};
	sign = 0;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93683FCDFF306664ULL,
		0x2C6CC16D49ACC22EULL,
		0x747845E5A2B84A9AULL,
		0x18FFF7F048353ACEULL,
		0xF80C2AD63BD5C61DULL,
		0x46286D2AE7AD4EDFULL,
		0xB14FD457ECC79785ULL,
		0xEED3D374AF22D658ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB090D37605C25EULL,
		0x2C093964C2AA375EULL,
		0xC71D8D6B925ACC44ULL,
		0xE4DCF6013A6D1AE1ULL,
		0x33203D9AAF5E4433ULL,
		0xBC17B8882F9847EEULL,
		0x5E7B5E69C7F69197ULL,
		0xC6AFF3BA1283FA0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7B7AEFA892AA406ULL,
		0x0063880887028ACFULL,
		0xAD5AB87A105D7E56ULL,
		0x342301EF0DC81FECULL,
		0xC4EBED3B8C7781E9ULL,
		0x8A10B4A2B81506F1ULL,
		0x52D475EE24D105EDULL,
		0x2823DFBA9C9EDC4BULL
	}};
	sign = 0;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x57FA03188204AE99ULL,
		0xAA27C4BCF090F733ULL,
		0x0CECF7700A6CE6BBULL,
		0xE359AE160AD1B912ULL,
		0xB75FF5D45C2CC9D8ULL,
		0x7FAC8C5E1B5D703EULL,
		0xA5E9440EEF0A731EULL,
		0x43FBE04456E8F930ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ECC17E6EAA1E96FULL,
		0x0A1E9E9E3BC13E6FULL,
		0xE59B4895957C6078ULL,
		0xCD45CEF5B39FEE57ULL,
		0x3742F1980137E7B6ULL,
		0x2A0A1BFDB2035C72ULL,
		0xF1812E67DF97DF21ULL,
		0xD4D5C0159D64275DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x092DEB319762C52AULL,
		0xA009261EB4CFB8C4ULL,
		0x2751AEDA74F08643ULL,
		0x1613DF205731CABAULL,
		0x801D043C5AF4E222ULL,
		0x55A27060695A13CCULL,
		0xB46815A70F7293FDULL,
		0x6F26202EB984D1D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC698C9D88341536DULL,
		0x4D49F806C42624C1ULL,
		0x2171D95CD864EE92ULL,
		0x1253771CFE3F55B4ULL,
		0xDF7513F5A0135638ULL,
		0x11059519151021A8ULL,
		0x9436EAB701BDD0BEULL,
		0x2F3130D0DBEE9075ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EE71621203A034EULL,
		0xDB3273F5CE6817DCULL,
		0x3B41E3FFAF06730BULL,
		0xE5ED2F7F27E8D270ULL,
		0x461891425BF70AA2ULL,
		0x2B77E96FF5AD99C7ULL,
		0x04E0D7BEC86D0CD9ULL,
		0xAD30C8943F8424EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97B1B3B76307501FULL,
		0x72178410F5BE0CE5ULL,
		0xE62FF55D295E7B86ULL,
		0x2C66479DD6568343ULL,
		0x995C82B3441C4B95ULL,
		0xE58DABA91F6287E1ULL,
		0x8F5612F83950C3E4ULL,
		0x8200683C9C6A6B8AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0EC564C63518C8B0ULL,
		0x6756D185AB2A6AADULL,
		0x05A0D307B5FF77E8ULL,
		0x8B4787B7D714FCFCULL,
		0xACF3B9A861E81970ULL,
		0x42A4E49E33975E3AULL,
		0x7931582C0FC9EB42ULL,
		0xAE4BE116B3620DD4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD0506B31B0BDEEULL,
		0x88D44C47B568ACF3ULL,
		0xF7252180D80C08FFULL,
		0x97F4BD5BDE66C750ULL,
		0x03619A8DDDAD3729ULL,
		0x9208335CDBCC2E4EULL,
		0x7F306238DC1D05E3ULL,
		0x9B3CC37C95D3C63FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52F5145B03680AC2ULL,
		0xDE82853DF5C1BDB9ULL,
		0x0E7BB186DDF36EE8ULL,
		0xF352CA5BF8AE35ABULL,
		0xA9921F1A843AE246ULL,
		0xB09CB14157CB2FECULL,
		0xFA00F5F333ACE55EULL,
		0x130F1D9A1D8E4794ULL
	}};
	sign = 0;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1D251D7E4A39FE59ULL,
		0x5B1F99AD7880E40CULL,
		0xAC992FEDE6810A17ULL,
		0x7F2F4A4E64A2E8B9ULL,
		0x3ED69BCEA7885BC4ULL,
		0x286B7704C72CF2D4ULL,
		0x93696B73905BAD7FULL,
		0xB80C3214B63CA163ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x968D07CDC750B7BAULL,
		0xA9A02B50A7322FA1ULL,
		0x8743EDE4785C7952ULL,
		0x607B0FDDC836F924ULL,
		0x356BCF88631E9F09ULL,
		0xE0C853A4A207F686ULL,
		0x4187D30BDB435546ULL,
		0x4E35D2233079D7B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x869815B082E9469FULL,
		0xB17F6E5CD14EB46AULL,
		0x255542096E2490C4ULL,
		0x1EB43A709C6BEF95ULL,
		0x096ACC464469BCBBULL,
		0x47A323602524FC4EULL,
		0x51E19867B5185838ULL,
		0x69D65FF185C2C9B2ULL
	}};
	sign = 0;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB409490E2EB3090FULL,
		0xC9A2F139CE48B17FULL,
		0xF4744F36FBD73E0AULL,
		0x5D94EE59F34C3E95ULL,
		0x780ABCA0AEFBB022ULL,
		0xD1BE6A655BA4B4B6ULL,
		0x949AF8B8FE9BA762ULL,
		0xF3FEAB7DB700D44EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2DBE1C942097256ULL,
		0xCC3866BAB91218FCULL,
		0x3DF4B27639DBAFB7ULL,
		0x3E164C852C6E06D2ULL,
		0x6EEB66632C1F047EULL,
		0xB6BC5C861952B291ULL,
		0x5A59145E8B56EFABULL,
		0x84409CC793BAB24AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x112D6744ECA996B9ULL,
		0xFD6A8A7F15369883ULL,
		0xB67F9CC0C1FB8E52ULL,
		0x1F7EA1D4C6DE37C3ULL,
		0x091F563D82DCABA4ULL,
		0x1B020DDF42520225ULL,
		0x3A41E45A7344B7B7ULL,
		0x6FBE0EB623462204ULL
	}};
	sign = 0;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F2FA407F9E13F5BULL,
		0xABAD7A89C4442EC6ULL,
		0xA8FE804DF1C3854BULL,
		0x76645A971C1B1CABULL,
		0xF13D6B392D1776DAULL,
		0xE37C0F18FA6E7ACAULL,
		0xB66549E84D24CC8AULL,
		0x28F5882076827D39ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60285EFE086549EDULL,
		0xC33B68294AA8E2E9ULL,
		0xE52B3666A822A2FAULL,
		0x0E7FA4AFEDD84A76ULL,
		0xCB2310634D2C58DAULL,
		0x880D358942EEC665ULL,
		0x29D569487153A151ULL,
		0x4F3330E9F3F8A49CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF074509F17BF56EULL,
		0xE8721260799B4BDCULL,
		0xC3D349E749A0E250ULL,
		0x67E4B5E72E42D234ULL,
		0x261A5AD5DFEB1E00ULL,
		0x5B6ED98FB77FB465ULL,
		0x8C8FE09FDBD12B39ULL,
		0xD9C257368289D89DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9787DA4D8A6A9455ULL,
		0xCA887DA9B2C07896ULL,
		0xC3139046A75B1230ULL,
		0x1D41E8865865D070ULL,
		0xFBDFC71B7D8C42B0ULL,
		0x7BC3DA04F2A19D0DULL,
		0xEC3DCBAA7CB03606ULL,
		0xE86CB7948CDA41A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D55227F82CA9990ULL,
		0xDDD9458162E10449ULL,
		0x716DA2AD2731FB53ULL,
		0xF8AAD816073D01EFULL,
		0xE87CF45A6262E977ULL,
		0xDC2F5A09FC726352ULL,
		0xF929B2A64ECF58DEULL,
		0xE570598682C7DFB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A32B7CE079FFAC5ULL,
		0xECAF38284FDF744DULL,
		0x51A5ED99802916DCULL,
		0x249710705128CE81ULL,
		0x1362D2C11B295938ULL,
		0x9F947FFAF62F39BBULL,
		0xF31419042DE0DD27ULL,
		0x02FC5E0E0A1261E6ULL
	}};
	sign = 0;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1F849BB4F8AD50DULL,
		0x4BAFB42DEA6C0D5BULL,
		0xC7C6A1663D269FB4ULL,
		0x1779F37024007174ULL,
		0x0A1CB0399D1CBC2DULL,
		0xBC1174DE5298507BULL,
		0x78EA03675E9806F0ULL,
		0xC709013C164F70A3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C39AF554BE8B2CULL,
		0x5A1FB8786C64BD64ULL,
		0x8CAF89C47C4331C7ULL,
		0x38C2077CA67DBADFULL,
		0xAABC4411FF7EF48DULL,
		0x9669893A25058F05ULL,
		0x91B58E278E3A9831ULL,
		0x855A62622B92E03AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B34AEC5FACC49E1ULL,
		0xF18FFBB57E074FF7ULL,
		0x3B1717A1C0E36DECULL,
		0xDEB7EBF37D82B695ULL,
		0x5F606C279D9DC79FULL,
		0x25A7EBA42D92C175ULL,
		0xE734753FD05D6EBFULL,
		0x41AE9ED9EABC9068ULL
	}};
	sign = 0;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F34C7789F7D3736ULL,
		0x2F4519D046D8FE02ULL,
		0x1CB6F2999FE04AB9ULL,
		0x56A243C9F4AD35FEULL,
		0x9E292083EF756136ULL,
		0x511D8BB77520BE0AULL,
		0xFD3ABAD8C06E9DCBULL,
		0x011799A75AE1AD2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9426F0F1501908DEULL,
		0x974CC450CD8F2D49ULL,
		0xF27C8E4537A286E1ULL,
		0x9810E36DB348143FULL,
		0xD236289D79593A0FULL,
		0xCBAC895C95D35C61ULL,
		0xEDFA524AAD8EB192ULL,
		0x2C005767E2DAA076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B0DD6874F642E58ULL,
		0x97F8557F7949D0B8ULL,
		0x2A3A6454683DC3D7ULL,
		0xBE91605C416521BEULL,
		0xCBF2F7E6761C2726ULL,
		0x8571025ADF4D61A8ULL,
		0x0F40688E12DFEC38ULL,
		0xD517423F78070CB6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x605AF4D14F8B3AA8ULL,
		0x882E9D6B1ACF1F7AULL,
		0x0A553955452DC724ULL,
		0x6015ABB0D7769EE2ULL,
		0x5C4057A5BE2B2AEDULL,
		0x22167050F2BC8498ULL,
		0x45B8FC804A05E574ULL,
		0xFE0D0B58344DEE49ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AB57A61BBB54E88ULL,
		0xEDFAEC845EC80009ULL,
		0x7D15314B814F3D39ULL,
		0x0D849C5D3FD8BD7DULL,
		0xFD6A9192B56751B6ULL,
		0xCA9D75D4C718E79AULL,
		0xE3094A53410DBEB8ULL,
		0xBD4C04D920360ADCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35A57A6F93D5EC20ULL,
		0x9A33B0E6BC071F71ULL,
		0x8D400809C3DE89EAULL,
		0x52910F53979DE164ULL,
		0x5ED5C61308C3D937ULL,
		0x5778FA7C2BA39CFDULL,
		0x62AFB22D08F826BBULL,
		0x40C1067F1417E36CULL
	}};
	sign = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x510A1872C76C5C4DULL,
		0xC32EEB8E0F7B161CULL,
		0x60B144C4AB3F1691ULL,
		0x71BED223F2D4F6E3ULL,
		0x759C3AF75DD98CFCULL,
		0xD53D2EA1CB856FBAULL,
		0x89852FC798662469ULL,
		0xE902FCF8CA15C54FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA19EF3B90BA093D1ULL,
		0xBF4B8A44FC16FA14ULL,
		0x7EFA0536D0C60049ULL,
		0x1C74ACAA76BCF714ULL,
		0x01EEDE8F9BFF0B65ULL,
		0x1D35D07BD5636113ULL,
		0x5996A7AABEC116FCULL,
		0x7BD71248763FC2A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF6B24B9BBCBC87CULL,
		0x03E3614913641C07ULL,
		0xE1B73F8DDA791648ULL,
		0x554A25797C17FFCEULL,
		0x73AD5C67C1DA8197ULL,
		0xB8075E25F6220EA7ULL,
		0x2FEE881CD9A50D6DULL,
		0x6D2BEAB053D602A8ULL
	}};
	sign = 0;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7944D154F5A0D222ULL,
		0xEA1C44764199F918ULL,
		0x09353C9D0DA9340AULL,
		0x5FCD521B5AA34B7DULL,
		0x6B818BA3F29F2621ULL,
		0x2FE2CE65DC1609A3ULL,
		0xC5D774C692DD6DB9ULL,
		0xA673573284971540ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBBB0353FDEFCDAULL,
		0xBBE12DFEE38508D4ULL,
		0xBE2645C249BF54F4ULL,
		0xBB3AC58BCC06D9F9ULL,
		0x4009D607A02992F4ULL,
		0xE117352758B19353ULL,
		0x7DF0927964C4C554ULL,
		0x061A596923D3AB3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D89211FB5C1D548ULL,
		0x2E3B16775E14F043ULL,
		0x4B0EF6DAC3E9DF16ULL,
		0xA4928C8F8E9C7183ULL,
		0x2B77B59C5275932CULL,
		0x4ECB993E83647650ULL,
		0x47E6E24D2E18A864ULL,
		0xA058FDC960C36A01ULL
	}};
	sign = 0;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82747E4416DC0A5CULL,
		0xEB63434E731442F2ULL,
		0xFB27D7F2B95CBB4CULL,
		0x0FDA8DAD1F338B59ULL,
		0xAC58F9B113A7B68EULL,
		0xAC57B59130B0A2D9ULL,
		0x70D9C3176DEF44A6ULL,
		0x81655BB002B9D685ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7782DBA8EBD98E4CULL,
		0x1BC544E36EB0F842ULL,
		0x9B2DA1A53132CBE7ULL,
		0xE6CD048E3FA179A6ULL,
		0x71031F1058E06A4EULL,
		0x0237227D90529588ULL,
		0xE5DE1B5D37A1FE93ULL,
		0xBE8BAB705134ACC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AF1A29B2B027C10ULL,
		0xCF9DFE6B04634AB0ULL,
		0x5FFA364D8829EF65ULL,
		0x290D891EDF9211B3ULL,
		0x3B55DAA0BAC74C3FULL,
		0xAA209313A05E0D51ULL,
		0x8AFBA7BA364D4613ULL,
		0xC2D9B03FB18529BBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2522EA337B33A0C6ULL,
		0x8C47A4DB98976DBFULL,
		0x64E243B82FA94ADAULL,
		0x20D82BF724051B7EULL,
		0x3C683FDEE227E4A3ULL,
		0xC75EA36BEE4D2A11ULL,
		0x714230E4B8DCCDDBULL,
		0xCA999B53CC5F01F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC322B1DD6B4D61ULL,
		0x3681637C5FB90082ULL,
		0x858CF96ECD954185ULL,
		0x2C18B80E1197B89FULL,
		0xC7DC449359094528ULL,
		0xDC9D565EDEF93D7AULL,
		0xC0E2154DEFC9FDBFULL,
		0x81B5CEABBF8E82ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE55FC7819DC85365ULL,
		0x55C6415F38DE6D3CULL,
		0xDF554A4962140955ULL,
		0xF4BF73E9126D62DEULL,
		0x748BFB4B891E9F7AULL,
		0xEAC14D0D0F53EC96ULL,
		0xB0601B96C912D01BULL,
		0x48E3CCA80CD07F4CULL
	}};
	sign = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x359BDFE0B031CB0BULL,
		0xDC8AF12EED1E96ACULL,
		0x051981477DE941FFULL,
		0x255C1EFDA71CB4BDULL,
		0x589F2D2965723FB7ULL,
		0xA0019DCAD9ED4F10ULL,
		0xDF59B9329782C32FULL,
		0x25E2BE586D843F0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB982F1135E6AB697ULL,
		0x01219B44AFD39F86ULL,
		0x36AD40FC54F5964BULL,
		0xC04A600D152C7787ULL,
		0x43870F391CBE655EULL,
		0x31AE9EAF6000685CULL,
		0x3F751B587E9F03A8ULL,
		0xF37AF6AE337BB319ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C18EECD51C71474ULL,
		0xDB6955EA3D4AF725ULL,
		0xCE6C404B28F3ABB4ULL,
		0x6511BEF091F03D35ULL,
		0x15181DF048B3DA58ULL,
		0x6E52FF1B79ECE6B4ULL,
		0x9FE49DDA18E3BF87ULL,
		0x3267C7AA3A088BF5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30512263671786B1ULL,
		0xB192BACBAEF8C3F8ULL,
		0xBA10F9AE6DB09AEFULL,
		0x529AEC495335EA13ULL,
		0xF49D70DD0DA371DBULL,
		0x443007D41E317CCCULL,
		0xEF4B0328AE68520EULL,
		0x28221CC6067F317FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA8B3D6FD9ACC2EULL,
		0xEFC0AD6BB360D0F3ULL,
		0xF43B20B73FE1D8F8ULL,
		0xCF3EC4DB948520EBULL,
		0x2BCB600068610811ULL,
		0x63C63C727408202FULL,
		0x1CA300208286C76DULL,
		0x0E4774F0D539949DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74A86E8C697CBA83ULL,
		0xC1D20D5FFB97F304ULL,
		0xC5D5D8F72DCEC1F6ULL,
		0x835C276DBEB0C927ULL,
		0xC8D210DCA54269C9ULL,
		0xE069CB61AA295C9DULL,
		0xD2A803082BE18AA0ULL,
		0x19DAA7D531459CE2ULL
	}};
	sign = 0;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x63670C714EA8EB5AULL,
		0xEBFCB899C6E231D7ULL,
		0x0D3FE53140632E06ULL,
		0x9AF4CA8DD57CEFA5ULL,
		0xA4B550222FA04CE5ULL,
		0x58C1A4D21B697A6CULL,
		0xB38A0B65926DA033ULL,
		0x116088D12D702CFEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC998DC91C18BB196ULL,
		0x00A353CD0C08E39EULL,
		0x2684AADA5A53ED09ULL,
		0x5ECF36B19E88A13AULL,
		0x33A43A8B8EE1237FULL,
		0x26576E2291DC9A7DULL,
		0x617D8367921136AFULL,
		0x681B4C90209953A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99CE2FDF8D1D39C4ULL,
		0xEB5964CCBAD94E38ULL,
		0xE6BB3A56E60F40FDULL,
		0x3C2593DC36F44E6AULL,
		0x71111596A0BF2966ULL,
		0x326A36AF898CDFEFULL,
		0x520C87FE005C6984ULL,
		0xA9453C410CD6D95AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4A1B70D91624AB29ULL,
		0xBD9047E5B7D965C8ULL,
		0x8EB12E051A143E3FULL,
		0xCE0DF27452A56B9AULL,
		0xE409B4C3B6427E59ULL,
		0x1BD53614EF59584DULL,
		0x59F9FE59AC882B1FULL,
		0x3ED92745B5FA4C98ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A659C4609C7D4A0ULL,
		0xDCE533ABA45776B9ULL,
		0x1037129F47C7BA1DULL,
		0x64E77D5884116313ULL,
		0x3EACB2BA4C49CEF9ULL,
		0x79E27EA77FA6BD84ULL,
		0xF4E703BC094F66A3ULL,
		0x66C02FDCF8BCA26CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFB5D4930C5CD689ULL,
		0xE0AB143A1381EF0EULL,
		0x7E7A1B65D24C8421ULL,
		0x6926751BCE940887ULL,
		0xA55D020969F8AF60ULL,
		0xA1F2B76D6FB29AC9ULL,
		0x6512FA9DA338C47BULL,
		0xD818F768BD3DAA2BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x31E15E99F63327E8ULL,
		0x4D2E9E892523F691ULL,
		0x1213AAF6F9CCCE34ULL,
		0x5442FD4F1C2E0428ULL,
		0x6E682B7795A4B1E8ULL,
		0xED9AA3BBD503E4DEULL,
		0xE1BB628AB6D75B7EULL,
		0x4D6F1E81ADE9C52EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F789B301A3F8D9ULL,
		0x3497C2123E320999ULL,
		0x6D6A7A8789F99818ULL,
		0x31C843D479D0611CULL,
		0x06C51DD399055320ULL,
		0xA442BDFDD30CC9D6ULL,
		0xA6AEB61C141D3E00ULL,
		0x0806B10239631213ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69E9D4E6F48F2F0FULL,
		0x1896DC76E6F1ECF7ULL,
		0xA4A9306F6FD3361CULL,
		0x227AB97AA25DA30BULL,
		0x67A30DA3FC9F5EC8ULL,
		0x4957E5BE01F71B08ULL,
		0x3B0CAC6EA2BA1D7EULL,
		0x45686D7F7486B31BULL
	}};
	sign = 0;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC2A438D1AA5FD54DULL,
		0xB4A0B763D25FECCBULL,
		0xC8F92FFD7EE1B637ULL,
		0x24CF0793BF7A7C53ULL,
		0xA47A56C602FBA5ACULL,
		0x98230993A3502C09ULL,
		0xCFF5BE573C9224B8ULL,
		0x915CEDCF20338689ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D9EF50755D5F8A7ULL,
		0x59480DB188D98385ULL,
		0xFC1CBDF3F19CB0CAULL,
		0x6FED72B02671B0EEULL,
		0x9EA827997AFF8059ULL,
		0xA3CA45EAAC1E12A0ULL,
		0x5FFB25EE04E8E9D0ULL,
		0x2CA840727A0EE8AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x350543CA5489DCA6ULL,
		0x5B58A9B249866946ULL,
		0xCCDC72098D45056DULL,
		0xB4E194E39908CB64ULL,
		0x05D22F2C87FC2552ULL,
		0xF458C3A8F7321969ULL,
		0x6FFA986937A93AE7ULL,
		0x64B4AD5CA6249DDBULL
	}};
	sign = 0;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBB2EDE895FA502A9ULL,
		0x14CCF06A7832F092ULL,
		0x3C435C9BB71B2A84ULL,
		0x4BEEFCF66C71DE4DULL,
		0x81776392FDF90BDAULL,
		0x096F1B1322978B52ULL,
		0xCF69F613786E5355ULL,
		0x3CDECD0CBA93DBC1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A6B97D8FCEEA779ULL,
		0xE6032F3E0D020A1FULL,
		0x3F68816BF7D46D7DULL,
		0xBD943AD24008A71AULL,
		0xB6B96F6B4AA985FAULL,
		0x12C3ABF24CBE3C8BULL,
		0xB9D75676EC09453BULL,
		0xAAC16C1419956ADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90C346B062B65B30ULL,
		0x2EC9C12C6B30E673ULL,
		0xFCDADB2FBF46BD06ULL,
		0x8E5AC2242C693732ULL,
		0xCABDF427B34F85DFULL,
		0xF6AB6F20D5D94EC6ULL,
		0x15929F9C8C650E19ULL,
		0x921D60F8A0FE70E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF46446BBC8B028DCULL,
		0xEC50C0F6E3374D9EULL,
		0xF43748EA78C786A9ULL,
		0xB35A1CF545E2883FULL,
		0x7B4CADB6C69B158CULL,
		0x7BA142AB4D2B99B9ULL,
		0x91F2DD5B0CA672E4ULL,
		0x19D42A886F0A7EADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E4FFF46397E4EC0ULL,
		0x16620C1E1CFFC037ULL,
		0x7577A1F3DCAC6DE6ULL,
		0xE9D62C4F89F4E70BULL,
		0x8412EF672041A90DULL,
		0x7ECB70D2C0E2E2B5ULL,
		0x7AA7EA3AA5078DA9ULL,
		0xE288C9A50F97802AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x961447758F31DA1CULL,
		0xD5EEB4D8C6378D67ULL,
		0x7EBFA6F69C1B18C3ULL,
		0xC983F0A5BBEDA134ULL,
		0xF739BE4FA6596C7EULL,
		0xFCD5D1D88C48B703ULL,
		0x174AF320679EE53AULL,
		0x374B60E35F72FE83ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF2585E8CFEEA11B0ULL,
		0x5A26AB83734EFD1AULL,
		0x29CC5F5800D19027ULL,
		0x4826032B44A4371CULL,
		0x7FFCE03F5808EC0BULL,
		0x4E0B140A5E7C4456ULL,
		0xF138C66B6C2A150AULL,
		0xB4BC625922FA207FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5893879B278E91C2ULL,
		0xB0B70B7E16D85904ULL,
		0x2DA5CBCA76841238ULL,
		0x327CEB0CF5EE4062ULL,
		0x3DE9DBB671AC772FULL,
		0x2269732E35DC016CULL,
		0xF2057EDA124581F7ULL,
		0xC0D858047D97102DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99C4D6F1D75B7FEEULL,
		0xA96FA0055C76A416ULL,
		0xFC26938D8A4D7DEEULL,
		0x15A9181E4EB5F6B9ULL,
		0x42130488E65C74DCULL,
		0x2BA1A0DC28A042EAULL,
		0xFF33479159E49313ULL,
		0xF3E40A54A5631051ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x33AE420753AC9B54ULL,
		0x518FAE717B9B251BULL,
		0x155B08ED2179F7ECULL,
		0xF1A2E5580DB68F63ULL,
		0x9294309CCF4E0044ULL,
		0xBCE4BC7FAD684268ULL,
		0xF10EE4E27A86DE9BULL,
		0xD7DC38CEA305C63DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C284ADB297B824ULL,
		0xCA1AFB84358A414AULL,
		0xD0781168BBE2D1DAULL,
		0x552693536FC1ACC2ULL,
		0x4BB825D03CC600D2ULL,
		0x683FE7AADD5DEC99ULL,
		0xE0179B489F261AE4ULL,
		0x09A74161FA70726AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79EBBD59A114E330ULL,
		0x8774B2ED4610E3D0ULL,
		0x44E2F78465972611ULL,
		0x9C7C52049DF4E2A0ULL,
		0x46DC0ACC9287FF72ULL,
		0x54A4D4D4D00A55CFULL,
		0x10F74999DB60C3B7ULL,
		0xCE34F76CA89553D3ULL
	}};
	sign = 0;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDD3B8ED92468DE14ULL,
		0x12DEFFFE94B5E128ULL,
		0xCA4C2C09510C9D10ULL,
		0x6785DAA7D7033CC1ULL,
		0x261AE8DE0F72E4D9ULL,
		0xDA165E73D5CC7119ULL,
		0x0A8AD62202153C20ULL,
		0xE220D0E47CB224E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBF0422B060BB90ULL,
		0x7547AE94B45FB555ULL,
		0x666657EAFCFCF459ULL,
		0x46249423B9119D98ULL,
		0x74AA495551F4F4D4ULL,
		0x3E1E38040AA7F9A2ULL,
		0x4B5384B560922B4DULL,
		0x4FCD7AB0FFADBB7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD7C8AB674082284ULL,
		0x9D975169E0562BD2ULL,
		0x63E5D41E540FA8B6ULL,
		0x216146841DF19F29ULL,
		0xB1709F88BD7DF005ULL,
		0x9BF8266FCB247776ULL,
		0xBF37516CA18310D3ULL,
		0x925356337D04696BULL
	}};
	sign = 0;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB3172D2E7049E9A4ULL,
		0x3BFC6C6272314A1AULL,
		0xC540634019604F66ULL,
		0x45F355FA4F22D4DBULL,
		0x679C442B6C622CFFULL,
		0xEC29C5001EA3D1FBULL,
		0x739D99C8968FC990ULL,
		0x08B4EB08DE0582C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4F2B1D87F3EDCEULL,
		0x0B62CB535A695C05ULL,
		0xDC20EA6940318DCAULL,
		0xE7D62CF3B7EFB5EEULL,
		0x7E89F95819993704ULL,
		0x7780E1DD14A495F5ULL,
		0x8984CBBFFBCAD382ULL,
		0x2A9225B2B337BF27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C80210E855FBD6ULL,
		0x3099A10F17C7EE14ULL,
		0xE91F78D6D92EC19CULL,
		0x5E1D290697331EECULL,
		0xE9124AD352C8F5FAULL,
		0x74A8E32309FF3C05ULL,
		0xEA18CE089AC4F60EULL,
		0xDE22C5562ACDC39FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x433D9EBC20DB9ADDULL,
		0xB4922E714C00D1F1ULL,
		0x14C1557C40DA2FFCULL,
		0x049E5CD61748E187ULL,
		0x4B907ECE0C7B9DF6ULL,
		0x7280B00DCE951E4DULL,
		0x4989A93BC4FDB191ULL,
		0x1686548AB9F7050BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7035F9683DAF3C2AULL,
		0x15C3BD9C1DCDF941ULL,
		0xF759681695276BEBULL,
		0x2AEF466AC9B5FB59ULL,
		0x8200AEDC5FD03496ULL,
		0x3FF6CC305983A646ULL,
		0xB432377AA2D58621ULL,
		0x2E458CBA2BA41747ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD307A553E32C5EB3ULL,
		0x9ECE70D52E32D8AFULL,
		0x1D67ED65ABB2C411ULL,
		0xD9AF166B4D92E62DULL,
		0xC98FCFF1ACAB695FULL,
		0x3289E3DD75117806ULL,
		0x955771C122282B70ULL,
		0xE840C7D08E52EDC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C099F51982BB4F8ULL,
		0xA26BBF71A8FF7E91ULL,
		0x2CBBA959122DED37ULL,
		0xA0521E7F7426BDF6ULL,
		0x73DA0B85A27A61CAULL,
		0xB8BCDFDDF357F9C1ULL,
		0xB591EE7C36505EB7ULL,
		0x076709EAD7C89569ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8670CEF81EE88A8ULL,
		0x688B11C9FC645462ULL,
		0x15EC4847752A429BULL,
		0x1D1CE27AEB4DEA54ULL,
		0x1EF8B187A9F39240ULL,
		0xF09F5CD66D04BD0EULL,
		0xF24E7EB4C666815EULL,
		0x5E33D3D9AE9A3095ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43A29262163D2C50ULL,
		0x39E0ADA7AC9B2A2EULL,
		0x16CF61119D03AA9CULL,
		0x83353C0488D8D3A2ULL,
		0x54E159FDF886CF8AULL,
		0xC81D830786533CB3ULL,
		0xC3436FC76FE9DD58ULL,
		0xA9333611292E64D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x820F1EE127DFB241ULL,
		0xF7DB02C2A0A08BC4ULL,
		0xF8B04E490B0E148CULL,
		0xD17F0AABE1EF0C24ULL,
		0xDC1BA2C2A33D8269ULL,
		0xB24D8CC8105CF166ULL,
		0x8B43010A622ED274ULL,
		0xF73E5D6E74EA568AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BCFBB38760C8307ULL,
		0xFF1678E4C1F6CE79ULL,
		0x7024361747C8C18EULL,
		0x15F7718A9965BB45ULL,
		0xF8DD8A9A35FD4982ULL,
		0xE6563E3286F5CBE4ULL,
		0x442FB3E2C68DF0B7ULL,
		0x1143FC8313A1E525ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x763F63A8B1D32F3AULL,
		0xF8C489DDDEA9BD4BULL,
		0x888C1831C34552FDULL,
		0xBB879921488950DFULL,
		0xE33E18286D4038E7ULL,
		0xCBF74E9589672581ULL,
		0x47134D279BA0E1BCULL,
		0xE5FA60EB61487165ULL
	}};
	sign = 0;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFF082E59D3439C6CULL,
		0x818FD85CADB9CD14ULL,
		0x1B7D6BDA7B0E3F17ULL,
		0x8F991442815C4A8AULL,
		0xFC1D671CAF7CCCD9ULL,
		0x1157E0A8E8B3213EULL,
		0xD5C37391C04C72DBULL,
		0x49649A5B814887D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9BFE0CF64A43C5DULL,
		0xCF49F5156D8848F6ULL,
		0x65C53568E4E93EF1ULL,
		0xC2A5473CA944AE6DULL,
		0xAD628C2C14C86710ULL,
		0x5E8CB496A7913A00ULL,
		0x880170370B50394BULL,
		0x4A3E667CA9F3CBDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35484D8A6E9F600FULL,
		0xB245E3474031841EULL,
		0xB5B8367196250025ULL,
		0xCCF3CD05D8179C1CULL,
		0x4EBADAF09AB465C8ULL,
		0xB2CB2C124121E73EULL,
		0x4DC2035AB4FC398FULL,
		0xFF2633DED754BBF9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCAA7EE60890D7877ULL,
		0xD7DC693DB3A8F393ULL,
		0x35049A68F2F68A5CULL,
		0x3BEFD64DB7F28FF5ULL,
		0x6CC70DDA77BC9767ULL,
		0xA62DD7BA884D5D38ULL,
		0xDF522C3BCC962E3BULL,
		0x0AB330FA80A03870ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB21A04253181FECULL,
		0x564342A15C73EC54ULL,
		0xCFFB51352D660AECULL,
		0x56564674DDD42483ULL,
		0xDD31B6ADB557650BULL,
		0x16FBEF5A8BDD562AULL,
		0xE41894F3A63825E0ULL,
		0x6A683761DD728967ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF864E1E35F5588BULL,
		0x8199269C5735073EULL,
		0x65094933C5907F70ULL,
		0xE5998FD8DA1E6B71ULL,
		0x8F95572CC265325BULL,
		0x8F31E85FFC70070DULL,
		0xFB399748265E085BULL,
		0xA04AF998A32DAF08ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3E3023697793BA4DULL,
		0x044B71919E8971E0ULL,
		0x773890B7D7EA8988ULL,
		0xD14F5DFFFCE8C091ULL,
		0x2CB1681B42F6192CULL,
		0xCBAC57D5C75BF9E8ULL,
		0x5B7A06D8934E3700ULL,
		0x20116B94A97FA257ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7770CCC568EFA0FULL,
		0x5AB2AF6990E9C054ULL,
		0x16D68BB4BFC28C60ULL,
		0x8E41DD4C10C31151ULL,
		0x0ED92F19588CED8AULL,
		0xDCB42D2A6803A4A1ULL,
		0xA20CC514117B02B8ULL,
		0x1C2AC2BE4B96C0D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66B9169D2104C03EULL,
		0xA998C2280D9FB18BULL,
		0x606205031827FD27ULL,
		0x430D80B3EC25AF40ULL,
		0x1DD83901EA692BA2ULL,
		0xEEF82AAB5F585547ULL,
		0xB96D41C481D33447ULL,
		0x03E6A8D65DE8E184ULL
	}};
	sign = 0;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55234CE7A922CF0DULL,
		0x0F00DD637BE4077AULL,
		0xFAB0C29D12E09F64ULL,
		0x724F76160F1A47CCULL,
		0x6A9EE07A534D936BULL,
		0x3E496841AFC31747ULL,
		0xAC22801973248DD9ULL,
		0xDB63D027D127E9E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A069632E7F5684ULL,
		0x66333926664743D1ULL,
		0x7CA13401910BE4C5ULL,
		0x1A47A88B87B17C8EULL,
		0x25B17938022DF488ULL,
		0xF1FE05EB44E46061ULL,
		0xCAF5F79F750015A9ULL,
		0xA726802D9B54861BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF82E3847AA37889ULL,
		0xA8CDA43D159CC3A8ULL,
		0x7E0F8E9B81D4BA9EULL,
		0x5807CD8A8768CB3EULL,
		0x44ED6742511F9EE3ULL,
		0x4C4B62566ADEB6E6ULL,
		0xE12C8879FE24782FULL,
		0x343D4FFA35D363C7ULL
	}};
	sign = 0;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x37E24CA4D968EC2DULL,
		0xF9A6F8BBF7F59085ULL,
		0x531534C9D4D0F601ULL,
		0x530EDA3CCBB6283CULL,
		0xC998B7182EA1ED1FULL,
		0xF4B671A3A24B6CD6ULL,
		0xCC6FCD1E9F7C240FULL,
		0x1E13C020721176CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0425F103E91A9C95ULL,
		0x526889D9EF7A08F3ULL,
		0xDDB20E2ACE1EE3EBULL,
		0x5AE986E4A11DF3FEULL,
		0x7896C62D08425E9EULL,
		0x51C055B573282F37ULL,
		0xD3877A79DE2892EDULL,
		0x725183C6EB303FD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33BC5BA0F04E4F98ULL,
		0xA73E6EE2087B8792ULL,
		0x7563269F06B21216ULL,
		0xF82553582A98343DULL,
		0x5101F0EB265F8E80ULL,
		0xA2F61BEE2F233D9FULL,
		0xF8E852A4C1539122ULL,
		0xABC23C5986E136F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x14360B5397152CCAULL,
		0xB5ABF6EA3261D27CULL,
		0xD8DFBFB6BB1065FCULL,
		0x31613DD5C18BAA46ULL,
		0xD133B99DF4CE64A8ULL,
		0xD8EED0A81B8B9DA2ULL,
		0xCB2179FF11D64D4DULL,
		0x91E330A8CABFBA65ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C7E4C94671AD36ULL,
		0xC776990F8E67693DULL,
		0x14B1A4B8B41734E6ULL,
		0xBD07C509398AB577ULL,
		0xE9D8D218C0C4A770ULL,
		0x3F773B625CAF1833ULL,
		0x29830C5F9334E740ULL,
		0x0D1B9A2585E0AE27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C6E268A50A37F94ULL,
		0xEE355DDAA3FA693EULL,
		0xC42E1AFE06F93115ULL,
		0x745978CC8800F4CFULL,
		0xE75AE7853409BD37ULL,
		0x99779545BEDC856EULL,
		0xA19E6D9F7EA1660DULL,
		0x84C7968344DF0C3EULL
	}};
	sign = 0;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x01DF98D8B122B8B8ULL,
		0xE488FC5D92087A13ULL,
		0xE80DBEC37223353FULL,
		0x2826B502EFF13A42ULL,
		0xF1F87FF7442C3DDEULL,
		0x7C606211D3EBCDC6ULL,
		0x0A8C73FBB7C27BB0ULL,
		0x847CAB9810E66792ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x884A50557A489F1CULL,
		0x8EF227B7653EF414ULL,
		0x48996896DFA5609DULL,
		0x5F8E5010BE5212ADULL,
		0xF729E644D935C114ULL,
		0x78DBB09F39C79B77ULL,
		0x7A3D8F87DFF9D150ULL,
		0x264AA0356AEC5B18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7995488336DA199CULL,
		0x5596D4A62CC985FEULL,
		0x9F74562C927DD4A2ULL,
		0xC89864F2319F2795ULL,
		0xFACE99B26AF67CC9ULL,
		0x0384B1729A24324EULL,
		0x904EE473D7C8AA60ULL,
		0x5E320B62A5FA0C79ULL
	}};
	sign = 0;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66377847DD232A53ULL,
		0x06F5118F39AB060BULL,
		0x09765622B2A9C505ULL,
		0xCE80569E2BB7F79AULL,
		0x14D0306C43EF7E4FULL,
		0x99BBB5F45BD00A02ULL,
		0xDD95E136F985E7E6ULL,
		0xD14C09CB1928B935ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF339279B9C31A0ULL,
		0xF6D0281DA001414BULL,
		0x3A948E684652D8E9ULL,
		0x7AEFB59D83125B38ULL,
		0x99038238165C6A67ULL,
		0x7B0E84F6F4F01FD0ULL,
		0xCD8D69F4B66A8274ULL,
		0xECB82AD082860B2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89443F204186F8B3ULL,
		0x1024E97199A9C4BFULL,
		0xCEE1C7BA6C56EC1BULL,
		0x5390A100A8A59C61ULL,
		0x7BCCAE342D9313E8ULL,
		0x1EAD30FD66DFEA31ULL,
		0x10087742431B6572ULL,
		0xE493DEFA96A2AE08ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0ECCE0505E952ABULL,
		0xB7EA0E71E330EAF6ULL,
		0xD97AB8A52DDFAD3EULL,
		0x2E880B76A227FE33ULL,
		0xF00F23354464BCF8ULL,
		0x64B71DDDEE7C13CFULL,
		0x7C611ED2DC1FBFEEULL,
		0xC0936C41BADB07F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x483074B1250576D7ULL,
		0xEA9F786E16F6018AULL,
		0x4D2B541AB951A22EULL,
		0xB4B46698801AE391ULL,
		0x280741F10579B7EAULL,
		0x82531626C083EFA6ULL,
		0xD81EA0F0A24F3D00ULL,
		0xD7E01CC7E72DF40BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8BC5953E0E3DBD4ULL,
		0xCD4A9603CC3AE96CULL,
		0x8C4F648A748E0B0FULL,
		0x79D3A4DE220D1AA2ULL,
		0xC807E1443EEB050DULL,
		0xE26407B72DF82429ULL,
		0xA4427DE239D082EDULL,
		0xE8B34F79D3AD13ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7E6952A254087550ULL,
		0xA00C4B19C0CC9793ULL,
		0x4273216A87AFBDE9ULL,
		0x90F78FF6D353DF4DULL,
		0x2F41EFB1681801CEULL,
		0xE0A3CDFAF078D3CDULL,
		0x7BA7BD7BB1BE980AULL,
		0x8B386F39DEC8BE84ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FEF72DD0DB1DE1FULL,
		0x01B57AC630331279ULL,
		0xC47A68BF1A69E1AAULL,
		0xFCCCDFE3B2F0EF60ULL,
		0x34D9DA30CCDA2392ULL,
		0x7872957B4221E810ULL,
		0x1306A92BF0E66B8AULL,
		0x37485C141B8BC960ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E79DFC546569731ULL,
		0x9E56D0539099851AULL,
		0x7DF8B8AB6D45DC3FULL,
		0x942AB0132062EFECULL,
		0xFA6815809B3DDE3BULL,
		0x6831387FAE56EBBCULL,
		0x68A1144FC0D82C80ULL,
		0x53F01325C33CF524ULL
	}};
	sign = 0;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDF21ACAFBB73B07BULL,
		0x7E7060861FEC977EULL,
		0xDFB2AE564AAFE237ULL,
		0x9FDB9F906123D7C7ULL,
		0x9969E20A892F27EAULL,
		0xFFEC21FF8B343AC4ULL,
		0x76F2A614E1788AC2ULL,
		0x73FE574FAE9CE891ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27F18699A445EAA1ULL,
		0xDB3AB8F43721E5DBULL,
		0xFA5BF23E26E641FEULL,
		0xE1CE4BA6F2F09F19ULL,
		0x6B3FDB96FA7C30D8ULL,
		0xD1C1B754E37A4A60ULL,
		0x979B0205838A375BULL,
		0xD39560AD69756E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7302616172DC5DAULL,
		0xA335A791E8CAB1A3ULL,
		0xE556BC1823C9A038ULL,
		0xBE0D53E96E3338ADULL,
		0x2E2A06738EB2F711ULL,
		0x2E2A6AAAA7B9F064ULL,
		0xDF57A40F5DEE5367ULL,
		0xA068F6A245277A7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB30AFD632622528BULL,
		0x34AADF197D45C523ULL,
		0x78D5ACC12F500190ULL,
		0xDFA86B779009A5CBULL,
		0x555A7155027890B0ULL,
		0x84AB54C1EB85733FULL,
		0xE7E6E662A526E5BFULL,
		0xA4121BAC73FFDA23ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD1625A34A07335ULL,
		0xEA78A148E3E62F65ULL,
		0x0CE7D83EDBC725C8ULL,
		0x609B52DF151DA8D5ULL,
		0xE2D1EFFD972D3C7FULL,
		0x2CA83E023C7B01A1ULL,
		0x8BFB8F3DA31330D6ULL,
		0x28FD5F9E1C0D4DF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66399B08F181DF56ULL,
		0x4A323DD0995F95BEULL,
		0x6BEDD4825388DBC7ULL,
		0x7F0D18987AEBFCF6ULL,
		0x728881576B4B5431ULL,
		0x580316BFAF0A719DULL,
		0x5BEB57250213B4E9ULL,
		0x7B14BC0E57F28C2BULL
	}};
	sign = 0;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39687D836C3FB4BDULL,
		0xCAEFD2DB620C37DBULL,
		0xE1710CCA59C93AB2ULL,
		0x500DEAF52D1B0212ULL,
		0x48F43556C13CE63FULL,
		0x0A4A6434EF96E5D8ULL,
		0xE089334525BC7A37ULL,
		0xB06172A56B5C304EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1772E2C1CE9B80ULL,
		0x566D45F8ED85E4FDULL,
		0x1BB7A75A75619A35ULL,
		0xC03974A942ADF868ULL,
		0x541B02FEA1DA534BULL,
		0x4FCC56FBD725E90CULL,
		0x4A7019A44E6FAFA7ULL,
		0xC249974FA5E9B2B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA510AA0AA71193DULL,
		0x74828CE2748652DDULL,
		0xC5B9656FE467A07DULL,
		0x8FD4764BEA6D09AAULL,
		0xF4D932581F6292F3ULL,
		0xBA7E0D391870FCCBULL,
		0x961919A0D74CCA8FULL,
		0xEE17DB55C5727D97ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2175509276079EA1ULL,
		0x43D912C3880B8941ULL,
		0x79EECF6F1455752BULL,
		0x467989C27A7D39A0ULL,
		0xDADEC08DEFF86458ULL,
		0x08F06093FAAA8432ULL,
		0x3E3DF45EE8213925ULL,
		0x97C4ACE7575A5046ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x231B7E9A5AF07992ULL,
		0x6D25DCD7DCCAB175ULL,
		0x5C9168B1A401915AULL,
		0xED78E568BF02DE1AULL,
		0xC3B075CCF950B7F1ULL,
		0xB082B7E400028A99ULL,
		0xAD4A742AF7AB573DULL,
		0x113A28E0DEBC2693ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE59D1F81B17250FULL,
		0xD6B335EBAB40D7CBULL,
		0x1D5D66BD7053E3D0ULL,
		0x5900A459BB7A5B86ULL,
		0x172E4AC0F6A7AC66ULL,
		0x586DA8AFFAA7F999ULL,
		0x90F38033F075E1E7ULL,
		0x868A8406789E29B2ULL
	}};
	sign = 0;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE248D772453D832ULL,
		0x6D283140CE226B67ULL,
		0x8AB8689F86D1DA0CULL,
		0xC62087166E824C1FULL,
		0x42CDA4EA85EF231BULL,
		0x25EF1019AA932D41ULL,
		0x4110C200BEFD6F48ULL,
		0x34572BDC6DF86960ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC4964572588687ULL,
		0x9F6400F74316F5F0ULL,
		0xEA12B70F403CE090ULL,
		0x6942C1EFBC638A92ULL,
		0x9F3BB3CE1C2DA36AULL,
		0x71E231D3D703971DULL,
		0x3C5B409FE65902E7ULL,
		0x0D4A8778A2B20AE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE15FF731B1FB51ABULL,
		0xCDC430498B0B7576ULL,
		0xA0A5B1904694F97BULL,
		0x5CDDC526B21EC18CULL,
		0xA391F11C69C17FB1ULL,
		0xB40CDE45D38F9623ULL,
		0x04B58160D8A46C60ULL,
		0x270CA463CB465E7AULL
	}};
	sign = 0;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4443E63DFD6E7C23ULL,
		0xD7E45A1B0B054ED4ULL,
		0xF43A9693F58601EFULL,
		0xE1A2337C1837DA9AULL,
		0xD8967DDAC4757D50ULL,
		0x2F221294CC6768CCULL,
		0x84A6CF710916EE03ULL,
		0x987639AF1B841339ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9395C821B0ADF3DULL,
		0xC9EA24F37BC7A3D3ULL,
		0x3D14D972901BBAFAULL,
		0xD1162F455C8FD629ULL,
		0xAD30E27B93CE3C45ULL,
		0x90D04859E44D586AULL,
		0x4CE8479F4B2F2725ULL,
		0x2048F71878223568ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B0A89BBE2639CE6ULL,
		0x0DFA35278F3DAB00ULL,
		0xB725BD21656A46F5ULL,
		0x108C0436BBA80471ULL,
		0x2B659B5F30A7410BULL,
		0x9E51CA3AE81A1062ULL,
		0x37BE87D1BDE7C6DDULL,
		0x782D4296A361DDD1ULL
	}};
	sign = 0;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9E664AD6C05DDE6EULL,
		0x0F43DCE1A68B2498ULL,
		0xB71BB665E953619CULL,
		0xED2B67791AB9FBFEULL,
		0xBB8B6D5CC4EC1A79ULL,
		0xF64B0CE27110E4D1ULL,
		0x2BA48106C8CCD73DULL,
		0xD08484B860B26ABCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4DCD939544F4D78ULL,
		0xF3B15BB3017BEC0AULL,
		0xBBBA77F13009114BULL,
		0xEC51FE19D5D3E82EULL,
		0xA688048A417FA222ULL,
		0x6AF5E3CEA11842C9ULL,
		0x6E1D2B2432237262ULL,
		0xB5364657BD6E3120ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE989719D6C0E90F6ULL,
		0x1B92812EA50F388DULL,
		0xFB613E74B94A5050ULL,
		0x00D9695F44E613CFULL,
		0x150368D2836C7857ULL,
		0x8B552913CFF8A208ULL,
		0xBD8755E296A964DBULL,
		0x1B4E3E60A344399BULL
	}};
	sign = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDD1B0B5DA2A2DBF9ULL,
		0xF30A2DB4C3AD5112ULL,
		0x759EF131DCAD76ACULL,
		0x2D986782B3B1E1DEULL,
		0x45030F5CAE0A355FULL,
		0xACCD0991C6266C00ULL,
		0x2B9575BB72201D2AULL,
		0xCF2EA1E79EBE92FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x280A4AE337884EA3ULL,
		0xC25C6AF9739C112BULL,
		0x19FFA3D389C694A6ULL,
		0xDE4C0E7EDAC39B7FULL,
		0x1679D4F83F62B409ULL,
		0x05144E53664BBB77ULL,
		0xBF45DCAB46CB7567ULL,
		0x43B347FC7C3BE1BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB510C07A6B1A8D56ULL,
		0x30ADC2BB50113FE7ULL,
		0x5B9F4D5E52E6E206ULL,
		0x4F4C5903D8EE465FULL,
		0x2E893A646EA78155ULL,
		0xA7B8BB3E5FDAB089ULL,
		0x6C4F99102B54A7C3ULL,
		0x8B7B59EB2282B143ULL
	}};
	sign = 0;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC896DA5843C042A1ULL,
		0x8996D787E1AD645FULL,
		0xE725DF71DAE38C87ULL,
		0x610EC319FA9E2603ULL,
		0x1865307E2A95CF0DULL,
		0x1C150BC1605BE8B3ULL,
		0xDD161FC2ADB447BDULL,
		0xE48190C44F806428ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E2930E99AB4ABCEULL,
		0xC761A06BA678C9ACULL,
		0x05C4B9021A17A3D0ULL,
		0x920ACB68BCE7C3DCULL,
		0xB81F856D60E4AD95ULL,
		0xD372809EA9C18464ULL,
		0x0B3790E3C48C0307ULL,
		0x4C0E65531E870A99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A6DA96EA90B96D3ULL,
		0xC235371C3B349AB3ULL,
		0xE161266FC0CBE8B6ULL,
		0xCF03F7B13DB66227ULL,
		0x6045AB10C9B12177ULL,
		0x48A28B22B69A644EULL,
		0xD1DE8EDEE92844B5ULL,
		0x98732B7130F9598FULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF64D096AEBDE1B11ULL,
		0xBC7920DB1A69CDA2ULL,
		0x1F99A33074A2AB37ULL,
		0xE79D7F50E97EA8CDULL,
		0x53D809872D8139A9ULL,
		0x9747562BFE585E3AULL,
		0xC75F4E4CFE6BD1C5ULL,
		0x7E1540CA9335AAC2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAFCEF9B28614D72ULL,
		0xF3632788E941B532ULL,
		0x381CF1B566356621ULL,
		0x73397CE9550762B9ULL,
		0x69A5EEEA76FF34C5ULL,
		0x9BDC4CAEE2984676ULL,
		0xB990C063DAD54F34ULL,
		0x1930F5CA7F141E4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B5019CFC37CCD9FULL,
		0xC915F95231281870ULL,
		0xE77CB17B0E6D4515ULL,
		0x7464026794774613ULL,
		0xEA321A9CB68204E4ULL,
		0xFB6B097D1BC017C3ULL,
		0x0DCE8DE923968290ULL,
		0x64E44B0014218C76ULL
	}};
	sign = 0;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8F9F21A917B81ACFULL,
		0x1184812D812BA07DULL,
		0x72132D907216234FULL,
		0xE8F6A6DBCFBECF50ULL,
		0xAB132840656513BEULL,
		0xC6373624FC9D4EE8ULL,
		0xEE5CECD6B2048B29ULL,
		0x862757F7AC1B6F10ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A85AC66E6BCB26ULL,
		0x1C9CFE701FD7454FULL,
		0xDE8BC0A12736890CULL,
		0x0CCDDE2D5A82C5ACULL,
		0xEAF9C978DC8D0E4AULL,
		0xC04B27F1E24035FEULL,
		0xB6C36A4C00FA1129ULL,
		0x84F2D3B7311E1B28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CF6C6E2A94C4FA9ULL,
		0xF4E782BD61545B2EULL,
		0x93876CEF4ADF9A42ULL,
		0xDC28C8AE753C09A3ULL,
		0xC0195EC788D80574ULL,
		0x05EC0E331A5D18E9ULL,
		0x3799828AB10A7A00ULL,
		0x013484407AFD53E8ULL
	}};
	sign = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1637B915A51D4AB3ULL,
		0xA9D263819C9FCC51ULL,
		0x0BB52E7914B6CB3FULL,
		0xD3A57EFE8524AFBAULL,
		0x03CE2D2B9A20F409ULL,
		0xE427F197E6419635ULL,
		0x6443B861B95944FCULL,
		0x7ABCC5CC36B55EF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AECD70433BC04D0ULL,
		0xC84BEABA54155E04ULL,
		0x8730F3ECA96EB9D3ULL,
		0x03E1B0EF30F7238CULL,
		0x19394A5BBE90AB3DULL,
		0x84F10D3DB2C98812ULL,
		0x541673DCD8D87EFCULL,
		0xE49D1C80F551107EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B4AE211716145E3ULL,
		0xE18678C7488A6E4CULL,
		0x84843A8C6B48116BULL,
		0xCFC3CE0F542D8C2DULL,
		0xEA94E2CFDB9048CCULL,
		0x5F36E45A33780E22ULL,
		0x102D4484E080C600ULL,
		0x961FA94B41644E74ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x152019FCD5E15770ULL,
		0xC81344B429075680ULL,
		0x7FF4A118210D4D67ULL,
		0x0C45DF42FE5C4F52ULL,
		0x8B23FC067B352AC7ULL,
		0x4039E6B00DAB24BDULL,
		0x80DEEA70DB509B69ULL,
		0x53B92E037925DD86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x801C79DE3453D312ULL,
		0xC4FA0566203BA564ULL,
		0xAB92B5439F470745ULL,
		0xDBA107C82A76A816ULL,
		0x448143B135536604ULL,
		0x0F7017E204D12854ULL,
		0xED14DC69509FECD8ULL,
		0x41413ABA162B5211ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9503A01EA18D845EULL,
		0x03193F4E08CBB11BULL,
		0xD461EBD481C64622ULL,
		0x30A4D77AD3E5A73BULL,
		0x46A2B85545E1C4C2ULL,
		0x30C9CECE08D9FC69ULL,
		0x93CA0E078AB0AE91ULL,
		0x1277F34962FA8B74ULL
	}};
	sign = 0;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4193862417EF9ED2ULL,
		0x8E012C7AF636AF1BULL,
		0x229E26E58A24B212ULL,
		0x0FBA57AE998E2ADFULL,
		0xA2486C2735DE3BFEULL,
		0x1AD1E48B01FCF0CFULL,
		0x78EB8748431E2C21ULL,
		0x9788455E174B1950ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E66E3B5615F335FULL,
		0xDE0A63335D0C257AULL,
		0x86990193955F405FULL,
		0xEF0CD8112B76C274ULL,
		0x34F8B60FF0137A24ULL,
		0xA7F5EE6853E1D632ULL,
		0x76DC06D6F6831B83ULL,
		0x16623CDBB9E28890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD32CA26EB6906B73ULL,
		0xAFF6C947992A89A0ULL,
		0x9C052551F4C571B2ULL,
		0x20AD7F9D6E17686AULL,
		0x6D4FB61745CAC1D9ULL,
		0x72DBF622AE1B1A9DULL,
		0x020F80714C9B109DULL,
		0x812608825D6890C0ULL
	}};
	sign = 0;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x754A73FF327FC4B9ULL,
		0x1F1485A21FEF87C9ULL,
		0x48A207046A96BED4ULL,
		0xB4F8B6377B8C0773ULL,
		0xFF08B64E20F85D25ULL,
		0xDBF0D61B07D6C9FAULL,
		0x11BB1E6DAB6EB78BULL,
		0x18F9E2DBA88B93A9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE41A8F6C50D6AC8DULL,
		0x2081F7B4747902F2ULL,
		0xAE65370EA6E7EDD8ULL,
		0x445FCFCDCB5A6477ULL,
		0x4033F52AB477CF50ULL,
		0xD617E6C811789F73ULL,
		0x58C6403142A60994ULL,
		0xD33673840159F128ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x912FE492E1A9182CULL,
		0xFE928DEDAB7684D6ULL,
		0x9A3CCFF5C3AED0FBULL,
		0x7098E669B031A2FBULL,
		0xBED4C1236C808DD5ULL,
		0x05D8EF52F65E2A87ULL,
		0xB8F4DE3C68C8ADF7ULL,
		0x45C36F57A731A280ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5734B262E28DB00CULL,
		0x1BBE55C6DC41D5A0ULL,
		0xD6D7514B824CA86DULL,
		0x05B980B1BC30EA83ULL,
		0x0BD80C9753BA9FE1ULL,
		0x031EE5E98AC7BB3DULL,
		0xE2432F1333EE410AULL,
		0x1526CAA8F16284EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB25A740DE32DA9CULL,
		0xA4D5A8041737661FULL,
		0xF4F530507BA002A2ULL,
		0xD2B1479AF88890D4ULL,
		0x39AD5310B09F2099ULL,
		0x0F025805BCAF4B4CULL,
		0xE1DD3A3F0F45C417ULL,
		0x9AF935DD5707E500ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C0F0B22045AD570ULL,
		0x76E8ADC2C50A6F80ULL,
		0xE1E220FB06ACA5CAULL,
		0x33083916C3A859AEULL,
		0xD22AB986A31B7F47ULL,
		0xF41C8DE3CE186FF0ULL,
		0x0065F4D424A87CF2ULL,
		0x7A2D94CB9A5A9FEDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1DF608284BD38839ULL,
		0x3F11D898DAA7623CULL,
		0x45497DFFDB279368ULL,
		0x128BE81838427EECULL,
		0xBCE3E3E040463880ULL,
		0x9F34CFD39372BD7FULL,
		0xC4C1EDC4CEE6A64CULL,
		0xB02C281929A96483ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x467A23E16A3B7039ULL,
		0xE3F917CA14BC0BB0ULL,
		0xCE7D3F866082CAFBULL,
		0xE3F20843697E7E10ULL,
		0x090F930939E76A2EULL,
		0x12F1558C76AF0588ULL,
		0xCE7B6F31609CE604ULL,
		0x80DDF69CA2DBED6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD77BE446E1981800ULL,
		0x5B18C0CEC5EB568BULL,
		0x76CC3E797AA4C86CULL,
		0x2E99DFD4CEC400DBULL,
		0xB3D450D7065ECE51ULL,
		0x8C437A471CC3B7F7ULL,
		0xF6467E936E49C048ULL,
		0x2F4E317C86CD7718ULL
	}};
	sign = 0;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F5EC23B3BA89669ULL,
		0x22A9DB3CFDE75B22ULL,
		0x660DD94A8EDC70DFULL,
		0xB5898C1994103C5BULL,
		0x76F7C9747F36E0E5ULL,
		0xA41CD8DE15CEF9CFULL,
		0x006D0512B53D5209ULL,
		0x305B835FB3898B7DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AF73336E4C04FA7ULL,
		0x2A3C39570CA5F11BULL,
		0x36975D8B10D309E5ULL,
		0xE706B7B0E9722328ULL,
		0xBDB2FC48F8D4DE64ULL,
		0xD59F0573D9BD8040ULL,
		0x49EEDA32FDB93CCDULL,
		0x7A17D5D93D818FF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4678F0456E846C2ULL,
		0xF86DA1E5F1416A06ULL,
		0x2F767BBF7E0966F9ULL,
		0xCE82D468AA9E1933ULL,
		0xB944CD2B86620280ULL,
		0xCE7DD36A3C11798EULL,
		0xB67E2ADFB784153BULL,
		0xB643AD867607FB8BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2FB033589FE65E1BULL,
		0x61DBA13FFB0D7D6CULL,
		0xBC47E06C0C3E483FULL,
		0x1E1F3FCFED20CF6EULL,
		0x06A60119F718C8AAULL,
		0x927CED5E5878EBD0ULL,
		0xBBDD17B2F60C46E0ULL,
		0xC7097FC14D1F77CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC3577F396945B7ULL,
		0x0E1E107052E6BAD7ULL,
		0x4722EB45B920028CULL,
		0xA158C63A65F244F1ULL,
		0xB99522FD92B03CFCULL,
		0x9B691478A9E3C14FULL,
		0xAACA8709A1A1047DULL,
		0x656EC3E8D485B752ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FECDBD9667D1864ULL,
		0x53BD90CFA826C294ULL,
		0x7524F526531E45B3ULL,
		0x7CC67995872E8A7DULL,
		0x4D10DE1C64688BADULL,
		0xF713D8E5AE952A80ULL,
		0x111290A9546B4262ULL,
		0x619ABBD87899C07DULL
	}};
	sign = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x22DF97E742AF5228ULL,
		0x0C760BC453A25193ULL,
		0x0F724BF380AF580FULL,
		0x41D17402A7791B06ULL,
		0x5742BD59BB7EEF70ULL,
		0xCA25B4D3B118192FULL,
		0xE3AC987D7172ECE7ULL,
		0x832A4BE463FCB722ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4D6CD7C6354FB9ULL,
		0x651ECF4640D751D5ULL,
		0x4EEECD9FD9134FC0ULL,
		0xAA78C09A5CFCE6D4ULL,
		0xE8F6B4F2958D99A5ULL,
		0x8EF234A274542237ULL,
		0x20E20D43ADF59971ULL,
		0x77B968C9BEBEA700ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55922B0F7C7A026FULL,
		0xA7573C7E12CAFFBDULL,
		0xC0837E53A79C084EULL,
		0x9758B3684A7C3431ULL,
		0x6E4C086725F155CAULL,
		0x3B3380313CC3F6F7ULL,
		0xC2CA8B39C37D5376ULL,
		0x0B70E31AA53E1022ULL
	}};
	sign = 0;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD6D5B2E7BB40A247ULL,
		0x72C8473114ADB115ULL,
		0x5FD048B952A399F5ULL,
		0x93DE57C633CCBAEAULL,
		0x75DE0514D1325BABULL,
		0xC5B740786FEC1260ULL,
		0xB3465605596599DDULL,
		0x27C578566D03435BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x279FE4DC43F6A91FULL,
		0x6BFC25D5A3A6D8C5ULL,
		0x6A00B81DD5112912ULL,
		0x3D95FEB3897688ABULL,
		0x75D304B2E2F40A49ULL,
		0x2A4F17488EA9224DULL,
		0x36931900B6DDBD8BULL,
		0xB0D4105896D3063CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF35CE0B7749F928ULL,
		0x06CC215B7106D850ULL,
		0xF5CF909B7D9270E3ULL,
		0x56485912AA56323EULL,
		0x000B0061EE3E5162ULL,
		0x9B68292FE142F013ULL,
		0x7CB33D04A287DC52ULL,
		0x76F167FDD6303D1FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xACACE30D4B7A3DC1ULL,
		0x290827B8B69EF9C6ULL,
		0xED3F0934AB451D76ULL,
		0x513F51E41B70E8CEULL,
		0xE75EAAD816E28B70ULL,
		0x8E202B530DA4CAF4ULL,
		0xB8318AF7193F09E2ULL,
		0xA3AF0EE2C221E7B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x421C3FE984AC83CDULL,
		0x0597CAF4C6A1E834ULL,
		0xF5E426769CDF2E96ULL,
		0x5B4DA58A48C02F5FULL,
		0xAB363E327C4768F3ULL,
		0xD0BDBBCE1D93C36DULL,
		0xADF8A15F9D243E1CULL,
		0xC48F212798105757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A90A323C6CDB9F4ULL,
		0x23705CC3EFFD1192ULL,
		0xF75AE2BE0E65EEE0ULL,
		0xF5F1AC59D2B0B96EULL,
		0x3C286CA59A9B227CULL,
		0xBD626F84F0110787ULL,
		0x0A38E9977C1ACBC5ULL,
		0xDF1FEDBB2A11905FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x52946F153B868FB2ULL,
		0xE3040A987740CA68ULL,
		0xC5D2E22CA722137CULL,
		0x00B90D473FD3F74EULL,
		0xE72ED62F3FF949B5ULL,
		0x69224259FAD008A6ULL,
		0x30300926DAE67144ULL,
		0x6B45DEB079A8A8A3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52950971698AB046ULL,
		0xE4D2B4F262DF7B0CULL,
		0x9454B8985EF866F4ULL,
		0x05A88E3A99C67E6EULL,
		0x9F43F06AAFF98447ULL,
		0x9D091663F32FA223ULL,
		0x27A62B463A3A2F14ULL,
		0xC86E8BCA328F566DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFFF65A3D1FBDF6CULL,
		0xFE3155A614614F5BULL,
		0x317E29944829AC87ULL,
		0xFB107F0CA60D78E0ULL,
		0x47EAE5C48FFFC56DULL,
		0xCC192BF607A06683ULL,
		0x0889DDE0A0AC422FULL,
		0xA2D752E647195236ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA79BABC4A7C58597ULL,
		0xE72ABEE330B94C4BULL,
		0x5A7D9B2EA01E0891ULL,
		0x4484B91248D2A7F3ULL,
		0x5452F1AD1689039FULL,
		0x44FB4C4D3159DC0EULL,
		0x9829FA3786D09ED0ULL,
		0x06A9E0050F5AD41FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CDC8120BC8C9328ULL,
		0x6DC23552366DC945ULL,
		0x0000688090281F2DULL,
		0x01629EFAE723BD7AULL,
		0x4296AE58FD27DD3CULL,
		0xC77B3D7B4FC7F77FULL,
		0x7599EC83F3B6D585ULL,
		0x74115F26F6E53AE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ABF2AA3EB38F26FULL,
		0x79688990FA4B8306ULL,
		0x5A7D32AE0FF5E964ULL,
		0x43221A1761AEEA79ULL,
		0x11BC435419612663ULL,
		0x7D800ED1E191E48FULL,
		0x22900DB39319C94AULL,
		0x929880DE1875993BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x44621E57003E551AULL,
		0x95E3C0748BB97B1BULL,
		0x8E06F59F200A1EA2ULL,
		0xBF6D438A64D7EABCULL,
		0x6C1CC676ED383187ULL,
		0x439BDB7FA392D78AULL,
		0x455FEC4E5A6825D7ULL,
		0xDB89E1510DC66D74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60043CD4CFE5A426ULL,
		0x01F0492C935431A4ULL,
		0x3AF6C24DB6F2C9F0ULL,
		0xC57D7EA187FD87E4ULL,
		0xB3FECD218DB4DE35ULL,
		0xD2336637E6873B37ULL,
		0x52DC093D12C861F3ULL,
		0xE27CDF4A41C59675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE45DE1823058B0F4ULL,
		0x93F37747F8654976ULL,
		0x53103351691754B2ULL,
		0xF9EFC4E8DCDA62D8ULL,
		0xB81DF9555F835351ULL,
		0x71687547BD0B9C52ULL,
		0xF283E311479FC3E3ULL,
		0xF90D0206CC00D6FEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBC8839A22ACC9FD5ULL,
		0x4F749841E5DD2C66ULL,
		0x63B2FB4698C88D14ULL,
		0x7FB9A04C154524D1ULL,
		0xFD02079A1BB0C0CAULL,
		0x5AE1D5EAEEEBD9CDULL,
		0x797C7B68CC7CC5F4ULL,
		0xAF9B4EB02E2AFD4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x060B7A5E2BB2A187ULL,
		0x0DFD403F9D913FF6ULL,
		0x9213F50B2D1B3391ULL,
		0xA91C43A229459B7FULL,
		0x2AF2FB724395F37EULL,
		0x2630F792146EFA86ULL,
		0xAB8909D4699BDF80ULL,
		0xFEDB521FAF2F4565ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB67CBF43FF19FE4EULL,
		0x41775802484BEC70ULL,
		0xD19F063B6BAD5983ULL,
		0xD69D5CA9EBFF8951ULL,
		0xD20F0C27D81ACD4BULL,
		0x34B0DE58DA7CDF47ULL,
		0xCDF3719462E0E674ULL,
		0xB0BFFC907EFBB7E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x15876438464A12E7ULL,
		0xF2B980C95564DCCCULL,
		0x11BDFB39C9CDE46CULL,
		0xB4ADB1715F779CC2ULL,
		0x8711F2D28EABE058ULL,
		0x26854FFB685A2B50ULL,
		0x08E6D1E4FF2407D1ULL,
		0xAA10029E95F70763ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA01E6B66C3F72AA6ULL,
		0x0F1A9CF152622A8DULL,
		0x92EE1A0BD9EADF1CULL,
		0x2A26BC6A32F1D5CFULL,
		0x66C25396567794FEULL,
		0xA07229C2F56E6E8EULL,
		0x2620CD0BF2F48D14ULL,
		0xB6AE1B0E2BCC5DFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7568F8D18252E841ULL,
		0xE39EE3D80302B23EULL,
		0x7ECFE12DEFE30550ULL,
		0x8A86F5072C85C6F2ULL,
		0x204F9F3C38344B5AULL,
		0x8613263872EBBCC2ULL,
		0xE2C604D90C2F7ABCULL,
		0xF361E7906A2AA967ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x784BE15BBC5F125CULL,
		0x80F9374B5DCC56E3ULL,
		0x5907255872BB202AULL,
		0x68949ED07AC50084ULL,
		0x3AF7A5DF80021B37ULL,
		0x1C7D1A9B599CD214ULL,
		0x9C7EFCDE369F65B0ULL,
		0xF081AECC14FA9BA3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB35D029F86AA1200ULL,
		0x0EEF9FCFFC599989ULL,
		0x0C52D66AE29EDF89ULL,
		0x18CC45F85E1AC4C8ULL,
		0x595598F8736B1CB4ULL,
		0x76002D1C2FA44D5DULL,
		0x74D6827FBD24F645ULL,
		0xD5F59B30EB1C8AEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4EEDEBC35B5005CULL,
		0x7209977B6172BD59ULL,
		0x4CB44EED901C40A1ULL,
		0x4FC858D81CAA3BBCULL,
		0xE1A20CE70C96FE83ULL,
		0xA67CED7F29F884B6ULL,
		0x27A87A5E797A6F6AULL,
		0x1A8C139B29DE10B5ULL
	}};
	sign = 0;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF10CB61B82D5D160ULL,
		0x9B5B7B6ACBB75FD0ULL,
		0x3A7E35CC06A77C3FULL,
		0xF72E39BA80CF02BCULL,
		0x50B72835AE454196ULL,
		0xFBADA03154F9CF7DULL,
		0x5DFEC13766244A11ULL,
		0x89294494BBBB091DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x292374EA39ACF9E5ULL,
		0xCD9F3A07D6B0C507ULL,
		0x35C2B925231A150AULL,
		0x9937A6C8F5245843ULL,
		0x0ECD670A5F89AB5CULL,
		0xBD0A4F06220A7EA6ULL,
		0x957A07903367E32BULL,
		0xDCDB001F54F444BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7E941314928D77BULL,
		0xCDBC4162F5069AC9ULL,
		0x04BB7CA6E38D6734ULL,
		0x5DF692F18BAAAA79ULL,
		0x41E9C12B4EBB963AULL,
		0x3EA3512B32EF50D7ULL,
		0xC884B9A732BC66E6ULL,
		0xAC4E447566C6C461ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x53D2FA96E3204C32ULL,
		0xA5B77EE880B0E980ULL,
		0x81F0E571A2D4405CULL,
		0xAF9BD96F7C4E61D0ULL,
		0x0DB1F0BE3A58274FULL,
		0xACA191E376C6C4FDULL,
		0x71726ACAE28D8184ULL,
		0xB2200CA571648942ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC557BF0EFD3EAAC2ULL,
		0xE37BFD9F0FAED42CULL,
		0xF240F9FD8719E198ULL,
		0xE621D471A6E506C5ULL,
		0x43F9A1C6AFFBC378ULL,
		0x76745CB9941B61C2ULL,
		0x35F7341E814DEC09ULL,
		0x988AC2E6CCCFA4ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E7B3B87E5E1A170ULL,
		0xC23B814971021553ULL,
		0x8FAFEB741BBA5EC3ULL,
		0xC97A04FDD5695B0AULL,
		0xC9B84EF78A5C63D6ULL,
		0x362D3529E2AB633AULL,
		0x3B7B36AC613F957BULL,
		0x199549BEA494E495ULL
	}};
	sign = 0;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6980CD73E5EB29E3ULL,
		0xE9D6C6337047ACABULL,
		0xAA4142738EA1EF82ULL,
		0xE942FE32C6331DAAULL,
		0xC7B1DB1C1F480200ULL,
		0x2421627EF4D6937EULL,
		0x3D987800369E37E0ULL,
		0xCDE495AE27C5F84EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7589E60EA425D8ULL,
		0x5AB61C666BFF82EAULL,
		0x162E4FA5E7310491ULL,
		0x5B2044EF5657BB7CULL,
		0x3B0814E25ECEC896ULL,
		0x4376BA3470B64340ULL,
		0xD647D839840B3307ULL,
		0xA937EAFA044718C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC0B438DD747040BULL,
		0x8F20A9CD044829C0ULL,
		0x9412F2CDA770EAF1ULL,
		0x8E22B9436FDB622EULL,
		0x8CA9C639C079396AULL,
		0xE0AAA84A8420503EULL,
		0x67509FC6B29304D8ULL,
		0x24ACAAB4237EDF88ULL
	}};
	sign = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8E5F8A47BB0C616ULL,
		0xF01140D57C294C35ULL,
		0xBF6CADB6D7C25BAFULL,
		0x6C464BBD8C6E3BDCULL,
		0x75A314B1939D71B3ULL,
		0x21A9C30F9A9829FEULL,
		0x637839A500A3FA75ULL,
		0x831F77C74CBC03A5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9682F3658F8C87DULL,
		0xAE7A57D30BB3974EULL,
		0x07DCE8ED9BF5441AULL,
		0x85285F83352B4BBAULL,
		0x75CD7D4375A40F7EULL,
		0x4C13F5C216BB49C6ULL,
		0x3244BE2003ED608FULL,
		0xCB12B90653531710ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F7DC96E22B7FD99ULL,
		0x4196E9027075B4E7ULL,
		0xB78FC4C93BCD1795ULL,
		0xE71DEC3A5742F022ULL,
		0xFFD5976E1DF96234ULL,
		0xD595CD4D83DCE037ULL,
		0x31337B84FCB699E5ULL,
		0xB80CBEC0F968EC95ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8FADFE93837B90B1ULL,
		0xEADA1A9A2D1A37F6ULL,
		0x42B181712215CD5FULL,
		0x25F743F38AA479A5ULL,
		0x642FF43B01C64ED3ULL,
		0x8CBFD1FF55DB7802ULL,
		0x02020DFAB1B92E22ULL,
		0x0AA684DF82AC9B45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A7351DA1315BAD2ULL,
		0xFEE4D85FD0E5AA12ULL,
		0x06E132742F11A2F0ULL,
		0xC5C3C7EA92B05DCCULL,
		0x30BFC959AF9D003BULL,
		0x34E1C950A9199F7CULL,
		0x24A68D3CAF694A2DULL,
		0xE6B629CF9C4E111AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x153AACB97065D5DFULL,
		0xEBF5423A5C348DE4ULL,
		0x3BD04EFCF3042A6EULL,
		0x60337C08F7F41BD9ULL,
		0x33702AE152294E97ULL,
		0x57DE08AEACC1D886ULL,
		0xDD5B80BE024FE3F5ULL,
		0x23F05B0FE65E8A2AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7322927311015260ULL,
		0xD8EA1282556A5EEBULL,
		0x1345A150A24921D8ULL,
		0xE35C45D89EEC4BFCULL,
		0xEFC7610BCC6028DFULL,
		0xC1AD9D01EAD5D52CULL,
		0x373B57FCF8F24D93ULL,
		0x62E8CD31E4F1C64EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x377B3610EAF0D777ULL,
		0xCD97920F147C80BFULL,
		0xD99A60BB65C61986ULL,
		0x6AD2BD9F9FCB4048ULL,
		0x0E6E4A669B713DAAULL,
		0xB966B592AF1021DDULL,
		0xE37E2246EBC5DD16ULL,
		0xAF9E3F5B42882F07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BA75C6226107AE9ULL,
		0x0B52807340EDDE2CULL,
		0x39AB40953C830852ULL,
		0x78898838FF210BB3ULL,
		0xE15916A530EEEB35ULL,
		0x0846E76F3BC5B34FULL,
		0x53BD35B60D2C707DULL,
		0xB34A8DD6A2699746ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC15444E253C593C7ULL,
		0x208CEF188FE18F97ULL,
		0x544EA2DAEF1E4F05ULL,
		0x6829E6E8038F1932ULL,
		0x7ADDF11DC7E7B9F3ULL,
		0x42CE4A5A07A9C8B0ULL,
		0x46D2A5B1EB936FCFULL,
		0xA8055AC837F996D7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D64A7049ADD3BDULL,
		0x3244938D75491B23ULL,
		0xC310B55CCCDB9281ULL,
		0x2DB8C807F17E3504ULL,
		0x467DBA5EEA3B05C9ULL,
		0x90225EDE21B270B0ULL,
		0x189A118874038DE5ULL,
		0x931C1A0AA89EF042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A7DFA720A17C00AULL,
		0xEE485B8B1A987474ULL,
		0x913DED7E2242BC83ULL,
		0x3A711EE01210E42DULL,
		0x346036BEDDACB42AULL,
		0xB2ABEB7BE5F75800ULL,
		0x2E389429778FE1E9ULL,
		0x14E940BD8F5AA695ULL
	}};
	sign = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39F4AE7462D9D631ULL,
		0x4FD829CFB2AB2E3FULL,
		0xA0AC2FED0AF2A25BULL,
		0xC91FE40E88568BB2ULL,
		0xB5C65144DBEEDFD5ULL,
		0x50A6EC4DA58B84F8ULL,
		0x38EA3C59C4CE4946ULL,
		0xC94EBDED48817D8BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD75DBD2E530D6528ULL,
		0xEBB757F36F94C395ULL,
		0x9934D39853B4D559ULL,
		0x8D9F2EA30A14D138ULL,
		0x995F474CCFA28098ULL,
		0xE9E8443733452892ULL,
		0x4C731F45CD3D51C5ULL,
		0x731A9EE664587FDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6296F1460FCC7109ULL,
		0x6420D1DC43166AA9ULL,
		0x07775C54B73DCD01ULL,
		0x3B80B56B7E41BA7AULL,
		0x1C6709F80C4C5F3DULL,
		0x66BEA81672465C66ULL,
		0xEC771D13F790F780ULL,
		0x56341F06E428FDAFULL
	}};
	sign = 0;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF552BB1427920FD5ULL,
		0x1EBD0EF81620E83BULL,
		0x32CEC6F8DB6DAFBCULL,
		0x7DEAF078A13CBF1CULL,
		0x45C3CB62699F474FULL,
		0xD47C4B17BA68EDC2ULL,
		0x1E2E492938775A58ULL,
		0xD08C14CC8000AC17ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x495301A2025C6DF7ULL,
		0xEEDF0AC73BAE77C4ULL,
		0xE9F994D63849706DULL,
		0xBBAF0C68645CA562ULL,
		0xCB129BAFA934C04DULL,
		0x7BA9CD069633E4D9ULL,
		0x3492DFEFF1DF6F8BULL,
		0x15C722E9AA7C0916ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABFFB9722535A1DEULL,
		0x2FDE0430DA727077ULL,
		0x48D53222A3243F4EULL,
		0xC23BE4103CE019B9ULL,
		0x7AB12FB2C06A8701ULL,
		0x58D27E11243508E8ULL,
		0xE99B69394697EACDULL,
		0xBAC4F1E2D584A300ULL
	}};
	sign = 0;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x95E1477FC2FB0C91ULL,
		0xC22CF2BAC5376D2CULL,
		0x3F71EEDCA2125E00ULL,
		0xB5EFA53956E39286ULL,
		0x1A030D38C029787BULL,
		0x11FCC8BCC8006B68ULL,
		0xB812444796734E41ULL,
		0xF71896B91C0A0993ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3A072671775A61ULL,
		0x04B29B8CB324F3B3ULL,
		0x0116EBC3846EC417ULL,
		0x6F8C0508AEAC780DULL,
		0xF4B749EABE5E9CA8ULL,
		0x978ABFB6A80C4C84ULL,
		0xE60E21E3A86A0891ULL,
		0x648CF79077B830C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BA740595183B230ULL,
		0xBD7A572E12127979ULL,
		0x3E5B03191DA399E9ULL,
		0x4663A030A8371A79ULL,
		0x254BC34E01CADBD3ULL,
		0x7A7209061FF41EE3ULL,
		0xD2042263EE0945AFULL,
		0x928B9F28A451D8CCULL
	}};
	sign = 0;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7ADF49D43555557AULL,
		0x361BF21E53DD807BULL,
		0xF86B02A3FB70550EULL,
		0xAD03887EA08E3AC4ULL,
		0x4FEF462E30902C05ULL,
		0xC852D40AAF8ACA9FULL,
		0x07312624CE082046ULL,
		0x2204535DC7C89B0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62368333C8B188FFULL,
		0xBCAB91320A8A458EULL,
		0x9F3B1F00D28DE951ULL,
		0x8804BCB830500AABULL,
		0x7428EC4724F7B423ULL,
		0x685EA9D4EE5692F1ULL,
		0xC64A7F54A7D9E944ULL,
		0x4477163A4FCA5C6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18A8C6A06CA3CC7BULL,
		0x797060EC49533AEDULL,
		0x592FE3A328E26BBCULL,
		0x24FECBC6703E3019ULL,
		0xDBC659E70B9877E2ULL,
		0x5FF42A35C13437ADULL,
		0x40E6A6D0262E3702ULL,
		0xDD8D3D2377FE3EA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC890E9109E5E8EADULL,
		0x84594CBB12A21163ULL,
		0x8FA3EA24EE6980F0ULL,
		0x3C802519F0D5681BULL,
		0x08CC0E2EFF09F8B8ULL,
		0x378A4E0FA9D4FBBDULL,
		0x61D0EDDE098A912FULL,
		0x6F5E5A10F7BDC925ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x809F4C56EC9B743CULL,
		0x10F309C586B8CAD9ULL,
		0x9737C4AA410FD4AAULL,
		0x5AEC04F5DA87849FULL,
		0x002839671843D464ULL,
		0x59A34E3F2002F619ULL,
		0x0F5E3E20432C089EULL,
		0x10D794FAE4EDD909ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47F19CB9B1C31A71ULL,
		0x736642F58BE9468AULL,
		0xF86C257AAD59AC46ULL,
		0xE1942024164DE37BULL,
		0x08A3D4C7E6C62453ULL,
		0xDDE6FFD089D205A4ULL,
		0x5272AFBDC65E8890ULL,
		0x5E86C51612CFF01CULL
	}};
	sign = 0;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x552C5254CC8F2D6BULL,
		0x8C593BD4EC027C77ULL,
		0xAF91DDE75D2FCDFEULL,
		0xD40E183399FA5AE4ULL,
		0xE1D18D00F8C0B39BULL,
		0x79B415FD5995B147ULL,
		0xCC0C2D5E1EA82B4BULL,
		0x1B07D268324B53C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E895FE94B89F00AULL,
		0xACACC1BAC41A8EF0ULL,
		0x56B2E3857BAF5591ULL,
		0x5CBAB5F485F06A03ULL,
		0x8091B3595ECC6929ULL,
		0xDCDA379F0D3B6181ULL,
		0x7975B25B8332A78CULL,
		0xC25D6ACA98B6DBEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6A2F26B81053D61ULL,
		0xDFAC7A1A27E7ED86ULL,
		0x58DEFA61E180786CULL,
		0x7753623F1409F0E1ULL,
		0x613FD9A799F44A72ULL,
		0x9CD9DE5E4C5A4FC6ULL,
		0x52967B029B7583BEULL,
		0x58AA679D999477DCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x05D7B71EDDA4B68EULL,
		0xBD0064E6F55C5D2AULL,
		0x65450700F26AF123ULL,
		0xE4D58E86BF166512ULL,
		0xA67927421B38A6B8ULL,
		0x2162F9B802E2B6A3ULL,
		0x857A7124C7846652ULL,
		0x2333BCC76500CAABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F558320C5BED4B2ULL,
		0x8583D0ECE304B02DULL,
		0xCEF130591714AEE5ULL,
		0xD867044B9E0A466AULL,
		0x6EC5D82A940CAE69ULL,
		0x056A95EA88AFE90AULL,
		0x8C6E10E3F925DF9DULL,
		0xB3FA3540EAA09A0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x868233FE17E5E1DCULL,
		0x377C93FA1257ACFCULL,
		0x9653D6A7DB56423EULL,
		0x0C6E8A3B210C1EA7ULL,
		0x37B34F17872BF84FULL,
		0x1BF863CD7A32CD99ULL,
		0xF90C6040CE5E86B5ULL,
		0x6F3987867A60309CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1D92F555C9E7DE3DULL,
		0x56626673B631F16BULL,
		0x4118CE5510DDABB8ULL,
		0x730027BB1ABDFA77ULL,
		0x2E5355475CC197ABULL,
		0x4198584C1714F615ULL,
		0x752F2C367CF47B9FULL,
		0x0147B797D61FC54BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36432E006BCFE101ULL,
		0xA060B971A1FC595CULL,
		0x53AB12F0DC653578ULL,
		0x657AA3FDC58B24A5ULL,
		0xE313C21C10165A85ULL,
		0x7DE9AAB83CB305D8ULL,
		0x33EFC655816C821EULL,
		0x5E090BCDC3EDF7A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE74FC7555E17FD3CULL,
		0xB601AD021435980EULL,
		0xED6DBB643478763FULL,
		0x0D8583BD5532D5D1ULL,
		0x4B3F932B4CAB3D26ULL,
		0xC3AEAD93DA61F03CULL,
		0x413F65E0FB87F980ULL,
		0xA33EABCA1231CDAAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA72B98E8F8F585E6ULL,
		0xC0DD42555E398A3FULL,
		0x0FF2D5DFB870BC1CULL,
		0x0ACC82E7E141839FULL,
		0x9A1E6213FE956299ULL,
		0xD969928F1FFC67EFULL,
		0x3F073A77D9164DE5ULL,
		0x757AD398B824F990ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5274BC797E53F218ULL,
		0xBE76B4E4C95B7476ULL,
		0x09C217925EA56AD0ULL,
		0xAA60948A0FF065ADULL,
		0xBBF161F727D9B5A6ULL,
		0xB519AFA0406B465CULL,
		0xA2C42AEF788CF8CDULL,
		0xC4F729A73239787BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54B6DC6F7AA193CEULL,
		0x02668D7094DE15C9ULL,
		0x0630BE4D59CB514CULL,
		0x606BEE5DD1511DF2ULL,
		0xDE2D001CD6BBACF2ULL,
		0x244FE2EEDF912192ULL,
		0x9C430F8860895518ULL,
		0xB083A9F185EB8114ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD8CA634357BDC00EULL,
		0x66AC93EB3A2159B8ULL,
		0xDABD9D03AA8BC794ULL,
		0xAF69A2BB656AD45DULL,
		0x4CCAE58E9643C1FFULL,
		0xEB4530409F0A0A1DULL,
		0x47545FF6EC888B96ULL,
		0x82E38D1F6B4025F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9F8D6278CF9B774ULL,
		0x80787A314D224DB0ULL,
		0x94B60A97DABCE31BULL,
		0x5FC7986E403C3DFEULL,
		0x1F349890EF69F8B1ULL,
		0xF0AF39E812177A0EULL,
		0x450FE8EFE744124DULL,
		0xDB49392CB09A5159ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFED18D1BCAC4089AULL,
		0xE63419B9ECFF0C07ULL,
		0x4607926BCFCEE478ULL,
		0x4FA20A4D252E965FULL,
		0x2D964CFDA6D9C94EULL,
		0xFA95F6588CF2900FULL,
		0x0244770705447948ULL,
		0xA79A53F2BAA5D497ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C0E8EE243ACC065ULL,
		0xCAA83667B7F5E7A7ULL,
		0x4981D2B29007DA65ULL,
		0x70E6C2E63839496DULL,
		0x152E2D221AD3336AULL,
		0x160B6B999CFB2BC6ULL,
		0xB1FE53D5306E85D5ULL,
		0x13B86BD00F8D1B69ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B658DAF41E92637ULL,
		0xEE324F90D82B8A25ULL,
		0x2C59393CA208CC5EULL,
		0x458B84A0D704843DULL,
		0x8E2BB95FE8CEAEF6ULL,
		0x6CFC6B64C1121950ULL,
		0x04FFE99DB251343EULL,
		0x6163B44E0D877566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10A9013301C39A2EULL,
		0xDC75E6D6DFCA5D82ULL,
		0x1D289975EDFF0E06ULL,
		0x2B5B3E456134C530ULL,
		0x870273C232048474ULL,
		0xA90F0034DBE91275ULL,
		0xACFE6A377E1D5196ULL,
		0xB254B7820205A603ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC1F390E7D552F72BULL,
		0x9750A1DD22052DFDULL,
		0x5A2B4671B7C610D4ULL,
		0xBAA22DB3408A3E3EULL,
		0x4F40EE1D3F19EA99ULL,
		0xD4EC379C474C4E85ULL,
		0x62B577A85F84797DULL,
		0x9CE08F5933745D22ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA87F9A1D83C88FF5ULL,
		0x8875D245573FA2F2ULL,
		0x9752B9B0FE1F7B73ULL,
		0x2AD9BE0479BC4CACULL,
		0xD7BA0C60F8AE527DULL,
		0xDFCB744D8E7E0B5AULL,
		0xE8F88E29F685396CULL,
		0x851E9D0E066D7CF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1973F6CA518A6736ULL,
		0x0EDACF97CAC58B0BULL,
		0xC2D88CC0B9A69561ULL,
		0x8FC86FAEC6CDF191ULL,
		0x7786E1BC466B981CULL,
		0xF520C34EB8CE432AULL,
		0x79BCE97E68FF4010ULL,
		0x17C1F24B2D06E02EULL
	}};
	sign = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6D1BF8B201F2BAAFULL,
		0x853105134F0F5036ULL,
		0x7EF660ED0267A5F0ULL,
		0x03C496BA04D8BD98ULL,
		0xF1929BEDC438091BULL,
		0xEBF64F9948A4D71EULL,
		0x1CB40512A4508345ULL,
		0xD0486010F8EA0685ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1F8E0C433B8AF6ULL,
		0x603521AEDC9AF518ULL,
		0x740BE73A0BF7C696ULL,
		0x9E592D66A638282EULL,
		0x187945C9C9F08B10ULL,
		0x3765EBC63A3A57B9ULL,
		0xA60A847418493B02ULL,
		0x093A4A0027B45AE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42FC6AA5BEB72FB9ULL,
		0x24FBE36472745B1EULL,
		0x0AEA79B2F66FDF5AULL,
		0x656B69535EA0956AULL,
		0xD9195623FA477E0AULL,
		0xB49063D30E6A7F65ULL,
		0x76A9809E8C074843ULL,
		0xC70E1610D135ABA2ULL
	}};
	sign = 0;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3ABE83FC640622D6ULL,
		0xF092C225B28F7F07ULL,
		0x339E1E9FCF8BEAE3ULL,
		0x41F12E1AE412B3A0ULL,
		0xF08A44E7828855A6ULL,
		0x08D2FC72ACC1BDA1ULL,
		0xDBF9C9A6AB3504F6ULL,
		0x0FEF87FC349F0F13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8753FFE92F613413ULL,
		0x47E6D810D2596A1FULL,
		0x89D185391E8C9890ULL,
		0xEE1ED00BDFDE3F7FULL,
		0x4AD24EFA52FA4F7BULL,
		0x8B311CF566E23306ULL,
		0x0461E4748A99FFF6ULL,
		0x773BF79CA9FC52D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB36A841334A4EEC3ULL,
		0xA8ABEA14E03614E7ULL,
		0xA9CC9966B0FF5253ULL,
		0x53D25E0F04347420ULL,
		0xA5B7F5ED2F8E062AULL,
		0x7DA1DF7D45DF8A9BULL,
		0xD797E532209B04FFULL,
		0x98B3905F8AA2BC43ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x80AEBAAE0FAC16B7ULL,
		0x931E3D2C68E79167ULL,
		0x504C024A8B93CB23ULL,
		0x2674A698FFFB33E0ULL,
		0x2486B3D227579613ULL,
		0xD511477295B4A2CDULL,
		0x93A679767EE57052ULL,
		0x373A302971C3C271ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E00C290F1CE8BAULL,
		0xC47AF130B757F5B0ULL,
		0x33B93717F419B227ULL,
		0xBBB55AE560AE26BAULL,
		0x1485A24AF175F33FULL,
		0xCB8240833CA288F9ULL,
		0xEF9B51448B86BA0AULL,
		0x79BD461BE2C91E92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FCEAE85008F2DFDULL,
		0xCEA34BFBB18F9BB7ULL,
		0x1C92CB32977A18FBULL,
		0x6ABF4BB39F4D0D26ULL,
		0x1001118735E1A2D3ULL,
		0x098F06EF591219D4ULL,
		0xA40B2831F35EB648ULL,
		0xBD7CEA0D8EFAA3DEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDA32CDD53C131C37ULL,
		0x2B725AE99427F9AAULL,
		0xF2986E23C3707820ULL,
		0x0F234253479BB61EULL,
		0x6091F51D2FEB0D80ULL,
		0x029620926CFDD65FULL,
		0xCBFF7E4CF0203301ULL,
		0x2A8821FFC8277B47ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EAE4F563FF1C0EULL,
		0xADE2115236D3BC13ULL,
		0xC3876B6215FBD5ECULL,
		0xAC7EA9CCD8FCAC10ULL,
		0x9025C4BD332A1CCDULL,
		0x772769F747973305ULL,
		0xCCDA98FC39192D30ULL,
		0x63057487410E7925ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5047E8DFD8140029ULL,
		0x7D9049975D543D97ULL,
		0x2F1102C1AD74A233ULL,
		0x62A498866E9F0A0EULL,
		0xD06C305FFCC0F0B2ULL,
		0x8B6EB69B2566A359ULL,
		0xFF24E550B70705D0ULL,
		0xC782AD7887190221ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7DA71C8435E681D8ULL,
		0xB3A984F16DD6D9C0ULL,
		0xD48F2822325A69EAULL,
		0xAF9B3F521E9D778AULL,
		0x4C32B57615D8C78BULL,
		0x2A379691B73EB304ULL,
		0x1E12DAB964736FF1ULL,
		0x3EC45EF2B3161335ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x247B04668323091EULL,
		0x4920C526D09855DEULL,
		0x81FCC748C5AD4C9CULL,
		0x722A13A67DF714DCULL,
		0x8D4EE518628058CBULL,
		0x38BC5D6264838E9EULL,
		0x641A43FA0C641330ULL,
		0x62B9C9F9B819757EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x592C181DB2C378BAULL,
		0x6A88BFCA9D3E83E2ULL,
		0x529260D96CAD1D4EULL,
		0x3D712BABA0A662AEULL,
		0xBEE3D05DB3586EC0ULL,
		0xF17B392F52BB2465ULL,
		0xB9F896BF580F5CC0ULL,
		0xDC0A94F8FAFC9DB6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB705622211E50BF6ULL,
		0x879CBDBA13720151ULL,
		0xB52056EB0C476E16ULL,
		0xB6F63337F185E761ULL,
		0x81D9F108EE2B4463ULL,
		0xC1853DCD1B31F76EULL,
		0x8E4C142F7A5F84FDULL,
		0xE8F610E36C98658CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD28E45B1A23EC9F1ULL,
		0xAA8FC8CB74794C7CULL,
		0xAB8144658558EDE9ULL,
		0x6F5BA3298C48DD00ULL,
		0xD970342CFACB482CULL,
		0x53D1256F3EA0C116ULL,
		0x101C8E2A3EF7E1B8ULL,
		0xB37B1251D647BA86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4771C706FA64205ULL,
		0xDD0CF4EE9EF8B4D4ULL,
		0x099F128586EE802CULL,
		0x479A900E653D0A61ULL,
		0xA869BCDBF35FFC37ULL,
		0x6DB4185DDC913657ULL,
		0x7E2F86053B67A345ULL,
		0x357AFE919650AB06ULL
	}};
	sign = 0;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE6A1657F412EC1C7ULL,
		0x10CB0EBFA1400C73ULL,
		0x920CDEA2268B9717ULL,
		0xC131DD5259C9A92EULL,
		0xD11C3B17A6A300EDULL,
		0x073D9BEA49DB0C48ULL,
		0x27B4D5603951FA95ULL,
		0x7D942AAB2901FAF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58607D59A7FDA428ULL,
		0x8B385261C8555060ULL,
		0xD6C18F6C184F68FCULL,
		0xC806B2703B2B3863ULL,
		0x7C89288529E1DC00ULL,
		0xC6304AC6140C8485ULL,
		0x992F7E13EE6A7956ULL,
		0xC189748DCDF9D8E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E40E82599311D9FULL,
		0x8592BC5DD8EABC13ULL,
		0xBB4B4F360E3C2E1AULL,
		0xF92B2AE21E9E70CAULL,
		0x549312927CC124ECULL,
		0x410D512435CE87C3ULL,
		0x8E85574C4AE7813EULL,
		0xBC0AB61D5B08220AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA2DDEAA7FCB52ED1ULL,
		0xB7C5DF706913AC83ULL,
		0x34F9EBEF81103035ULL,
		0x52A95FA01452EDF6ULL,
		0x10A6B1E9FBCAC402ULL,
		0xA6B0C08B4E328D2CULL,
		0x064090D5F4B92DB9ULL,
		0x42675C4B8DC48D7AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x711AA0F358766466ULL,
		0x3E1C0945D125845EULL,
		0xB67AF2B3FBA71D48ULL,
		0xCFF3CA80A28D1F2DULL,
		0xCC2380E51EF03B97ULL,
		0x1587683E5C26AD82ULL,
		0x0E9770CED6DC5791ULL,
		0x93BFF9CA4E8A0AABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31C349B4A43ECA6BULL,
		0x79A9D62A97EE2825ULL,
		0x7E7EF93B856912EDULL,
		0x82B5951F71C5CEC8ULL,
		0x44833104DCDA886AULL,
		0x9129584CF20BDFA9ULL,
		0xF7A920071DDCD628ULL,
		0xAEA762813F3A82CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30DFFA4946AA6460ULL,
		0xD246D7D5F9A95062ULL,
		0xD598425C1331A635ULL,
		0x8AFEFE0608E60BDAULL,
		0xACE8037FD7FDF3CAULL,
		0x10E935B28B99C7AFULL,
		0x73437D2E72B2034CULL,
		0x82FFF49531F7BB2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC46D675436F69EAULL,
		0x82337F7D68E66F55ULL,
		0x932C90626B414441ULL,
		0xE346943F12E9FA52ULL,
		0x9549CD3F2ECE4577ULL,
		0x8148E0F54D3AC7C6ULL,
		0x65955010852F72D4ULL,
		0xAFAD980B371E3A49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x449923D4033AFA76ULL,
		0x5013585890C2E10CULL,
		0x426BB1F9A7F061F4ULL,
		0xA7B869C6F5FC1188ULL,
		0x179E3640A92FAE52ULL,
		0x8FA054BD3E5EFFE9ULL,
		0x0DAE2D1DED829077ULL,
		0xD3525C89FAD980E2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4BE03F004A35039AULL,
		0xE95078BE8B4FD970ULL,
		0xB4691077C2D7802DULL,
		0x39A447E79521AD22ULL,
		0xB4D8618B133F3EE3ULL,
		0x631D53FF8A36C837ULL,
		0xD4353660B51FEE11ULL,
		0xFFD43280B54EA8A9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BD25A855517D819ULL,
		0xEA2B1EFC7F9FBA11ULL,
		0x175486E629F76BA5ULL,
		0x8B0B359B046F1594ULL,
		0xC62BAEE64E06C1A4ULL,
		0x48F33DF0691918EFULL,
		0x999E77F7D94694DBULL,
		0x8D37C0F1D6716F80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000DE47AF51D2B81ULL,
		0xFF2559C20BB01F5FULL,
		0x9D14899198E01487ULL,
		0xAE99124C90B2978EULL,
		0xEEACB2A4C5387D3EULL,
		0x1A2A160F211DAF47ULL,
		0x3A96BE68DBD95936ULL,
		0x729C718EDEDD3929ULL
	}};
	sign = 0;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7ABADEFAA434277BULL,
		0x6E02EE7CAA7E17BBULL,
		0x5E8F5E1AB67AC284ULL,
		0x60A2648BB949BC9BULL,
		0x5CEC82400B3AFBE8ULL,
		0x0EA1C11E31D6C08DULL,
		0x81B466D0E78B15A2ULL,
		0x915E7BC000198EE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D8BA7E59508996ULL,
		0x53BE843E9B0B9653ULL,
		0x7D7DBE4BB9717ACFULL,
		0xFD3C02C4D68E9396ULL,
		0x8603631861526934ULL,
		0xD680880CFD3D1E5AULL,
		0xD8F3A9EB5A12C88DULL,
		0xB69012324F023F10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18E2247C4AE39DE5ULL,
		0x1A446A3E0F728168ULL,
		0xE1119FCEFD0947B5ULL,
		0x636661C6E2BB2904ULL,
		0xD6E91F27A9E892B3ULL,
		0x382139113499A232ULL,
		0xA8C0BCE58D784D14ULL,
		0xDACE698DB1174FD0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x31DA0F860A168910ULL,
		0x70E602E18D61415BULL,
		0xCA042BE2A6C987B8ULL,
		0xDDC6C902DE3A09C0ULL,
		0xDF1D4A58E125F9E7ULL,
		0xD4783B3A80E3E8E4ULL,
		0xDAE23EF6CE6B564AULL,
		0x54B27BDCBBD558BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A775BC77F23512ULL,
		0x027DAC7C00D3AEE1ULL,
		0x123413AB8B29BA54ULL,
		0xC155F29F1B7EE8EDULL,
		0x171516806E120AB4ULL,
		0xB163819CC45E468DULL,
		0xA182A07204E6D527ULL,
		0xF0601A750A75F5BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF03299C9922453FEULL,
		0x6E6856658C8D9279ULL,
		0xB7D018371B9FCD64ULL,
		0x1C70D663C2BB20D3ULL,
		0xC80833D87313EF33ULL,
		0x2314B99DBC85A257ULL,
		0x395F9E84C9848123ULL,
		0x64526167B15F6300ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCC2A600936D3DD30ULL,
		0x79FAEBC5426E1B70ULL,
		0xB0DCFD25F5E02EA1ULL,
		0xB0446065083453BEULL,
		0xBD22AF0417271B9CULL,
		0xC5AA77E9C3E0B799ULL,
		0xDCA4EF5BA691BBE1ULL,
		0xAF05FBC679B01F2EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CC3E2A86E00BF3AULL,
		0x32A1D885593F5539ULL,
		0x98F5B8DB25B176F6ULL,
		0x1B72C4761499689FULL,
		0x4BE277FB57DB2980ULL,
		0x1E22AA6F25BFD058ULL,
		0xF69DFCBAF0690404ULL,
		0x60ACEA139ECAF43DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F667D60C8D31DF6ULL,
		0x4759133FE92EC637ULL,
		0x17E7444AD02EB7ABULL,
		0x94D19BEEF39AEB1FULL,
		0x71403708BF4BF21CULL,
		0xA787CD7A9E20E741ULL,
		0xE606F2A0B628B7DDULL,
		0x4E5911B2DAE52AF0ULL
	}};
	sign = 0;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4195BD098B1A240EULL,
		0xFDB8C29653A48E27ULL,
		0xF168954FAEC7F17BULL,
		0xE81C6A3651DDAE5EULL,
		0x18A519D2C7EEAA6DULL,
		0x0F9A3903D063045BULL,
		0xA74B388FB1C5F4A2ULL,
		0xACCAC6C0D78BE2E0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x91AAD9A435AF3213ULL,
		0x285EAD5C807F5982ULL,
		0xE3BEBF78484B1772ULL,
		0x57B636B9E88908DDULL,
		0xA3A6618DF35DE12CULL,
		0x295FBB366C3F9B8EULL,
		0x4FD4A3464D77C50EULL,
		0x28206F6AE6CE6D75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFEAE365556AF1FBULL,
		0xD55A1539D32534A4ULL,
		0x0DA9D5D7667CDA09ULL,
		0x9066337C6954A581ULL,
		0x74FEB844D490C941ULL,
		0xE63A7DCD642368CCULL,
		0x57769549644E2F93ULL,
		0x84AA5755F0BD756BULL
	}};
	sign = 0;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA368BE376C8A9040ULL,
		0xE38AE1C716560DF5ULL,
		0xBD2904301513CAAFULL,
		0x58E3CE35B4AD874AULL,
		0xE4A75C1B0F589543ULL,
		0xDAC29CE354883870ULL,
		0xDFA405D3B625FDB5ULL,
		0x14F9F28BE52D647AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE518B5B728B21B78ULL,
		0x3F5BEBAAE631C122ULL,
		0x9B7D5CA486F8D6C2ULL,
		0x6C1C2962E5CA5ECDULL,
		0xB294C38A38A56AADULL,
		0xFBEA180001F200DCULL,
		0x4937B4E96CBE9875ULL,
		0x2D6A3D4CF2F5FB81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE50088043D874C8ULL,
		0xA42EF61C30244CD2ULL,
		0x21ABA78B8E1AF3EDULL,
		0xECC7A4D2CEE3287DULL,
		0x32129890D6B32A95ULL,
		0xDED884E352963794ULL,
		0x966C50EA4967653FULL,
		0xE78FB53EF23768F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x353444157B029863ULL,
		0x7788D158BAB7C37CULL,
		0x2785BCCA9CC656C2ULL,
		0x5D90BADD2F31BD19ULL,
		0x0F00B259A0979673ULL,
		0x4472B74B545263CCULL,
		0x7884990C9A43174BULL,
		0x2B8E9C2EF7BEB380ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9172C4DB4A36E362ULL,
		0xF7E8D8825B5EB605ULL,
		0xFA0DC7C86B57B460ULL,
		0x1D8B6F2420E7D7ABULL,
		0x2A9C150E21116EEEULL,
		0xAEEF30AF3560B3D5ULL,
		0xF13CC74B0BA0C897ULL,
		0x38121F14DEA174A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3C17F3A30CBB501ULL,
		0x7F9FF8D65F590D76ULL,
		0x2D77F502316EA261ULL,
		0x40054BB90E49E56DULL,
		0xE4649D4B7F862785ULL,
		0x9583869C1EF1AFF6ULL,
		0x8747D1C18EA24EB3ULL,
		0xF37C7D1A191D3EDAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE9B473BAF423CC46ULL,
		0x5269C77131B75B38ULL,
		0x8EBBDF6527F95677ULL,
		0x82155A35E50E2020ULL,
		0x8352C754374422B0ULL,
		0x91AF81F905E6654DULL,
		0x131F494745609C03ULL,
		0xB5D95C907A0F283FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4A55F0D4D460A0ULL,
		0x85328242BC3FA213ULL,
		0x145672E91B97F242ULL,
		0x2137A262BE3A6241ULL,
		0x819AA28FA8B4FF40ULL,
		0x1AC874847C8F8972ULL,
		0x61B34D551D5442A1ULL,
		0xF8CD93552649B94DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B6A1DCA1F4F6BA6ULL,
		0xCD37452E7577B925ULL,
		0x7A656C7C0C616434ULL,
		0x60DDB7D326D3BDDFULL,
		0x01B824C48E8F2370ULL,
		0x76E70D748956DBDBULL,
		0xB16BFBF2280C5962ULL,
		0xBD0BC93B53C56EF1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFA4E77F3B44E38EFULL,
		0x96F0F959B5DF1F55ULL,
		0x86D183614917A94CULL,
		0x28A67C46262E7E78ULL,
		0xC52FC94EFC2A4C5DULL,
		0xA93876EF6315B647ULL,
		0x995CA9D011E004D5ULL,
		0x7C83AFEE73E5F179ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x949D5A6DAE3B7783ULL,
		0x7F77B3642F2B477BULL,
		0x85C09FD9B5C38ED8ULL,
		0x95E59E85F612D7FAULL,
		0x6CDAD236B678A0FEULL,
		0xE829AB446EF7B5FBULL,
		0x2B8987325F81D764ULL,
		0x6FF76F929B9C341DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65B11D860612C16CULL,
		0x177945F586B3D7DAULL,
		0x0110E38793541A74ULL,
		0x92C0DDC0301BA67EULL,
		0x5854F71845B1AB5EULL,
		0xC10ECBAAF41E004CULL,
		0x6DD3229DB25E2D70ULL,
		0x0C8C405BD849BD5CULL
	}};
	sign = 0;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xADECF07CA9262DA5ULL,
		0x208011929C1C279FULL,
		0x6A61882C862966A6ULL,
		0xA5B8090F946454E9ULL,
		0x6FA3A165A8013E00ULL,
		0xC2E88088E9F4C8E3ULL,
		0xA776AE8BFF3F4BC8ULL,
		0xED2F02647B2EC364ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EDAAA478B482B58ULL,
		0xAE1DA1F24E2A1F3EULL,
		0x52867D332146D939ULL,
		0xDB5FFC6F826F3C7CULL,
		0x9687B1B8C3870861ULL,
		0x8AFF21C1D0D52B25ULL,
		0x590EC1AF9E44E216ULL,
		0x04E6362D52B60050ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F1246351DDE024DULL,
		0x72626FA04DF20861ULL,
		0x17DB0AF964E28D6CULL,
		0xCA580CA011F5186DULL,
		0xD91BEFACE47A359EULL,
		0x37E95EC7191F9DBDULL,
		0x4E67ECDC60FA69B2ULL,
		0xE848CC372878C314ULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3C0A84096CAA068ULL,
		0xB8EEB48C0EF91CB6ULL,
		0x77C02FBADA2032B9ULL,
		0xE7FFDCC424C20A52ULL,
		0x89A876FB67F2B5A9ULL,
		0xF04CB160D2CB4190ULL,
		0xA3C44924D72BCA4DULL,
		0x67A6C205869F0940ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF182C19832338D4DULL,
		0x998B282C545FB7B6ULL,
		0xAF97CA0DC326AEF9ULL,
		0x8CB265FC6D3BB486ULL,
		0xFF31886799B4AB0FULL,
		0xA85AA241B18F5832ULL,
		0x112DCCE33F7A934BULL,
		0x2FCD27B808C1501FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023DE6A86497131BULL,
		0x1F638C5FBA996500ULL,
		0xC82865AD16F983C0ULL,
		0x5B4D76C7B78655CBULL,
		0x8A76EE93CE3E0A9AULL,
		0x47F20F1F213BE95DULL,
		0x92967C4197B13702ULL,
		0x37D99A4D7DDDB921ULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA77296CC31520FCCULL,
		0x0001DC3DD643C6F0ULL,
		0x4A1F35D019B98F57ULL,
		0x7E14C0F98335B104ULL,
		0xBD0FD431BBB6A69AULL,
		0x34CC4C2D39C3888EULL,
		0x4F6FBE967C7F2B9FULL,
		0x0DBE46DEAF43F1DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97FAE76752E2378CULL,
		0x27C0BA48CF298178ULL,
		0xE1ED2DB480E9C8C8ULL,
		0xF11642A75DED3683ULL,
		0x807A08A020DF77CBULL,
		0xEF915DC2902469FEULL,
		0x31F500E6EC64D9D1ULL,
		0x3CA5165F7D594DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F77AF64DE6FD840ULL,
		0xD84121F5071A4578ULL,
		0x6832081B98CFC68EULL,
		0x8CFE7E5225487A80ULL,
		0x3C95CB919AD72ECEULL,
		0x453AEE6AA99F1E90ULL,
		0x1D7ABDAF901A51CDULL,
		0xD119307F31EAA3E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9BD8DD34B0458BB5ULL,
		0x43B2B8D7704945C4ULL,
		0x849CD84A96B911A5ULL,
		0x81D5933C3B06C322ULL,
		0xF1BC7B98D69B217BULL,
		0x8FB5DA99576D7E8AULL,
		0xDB052E047F390403ULL,
		0x1BF6896F0A3E9C3CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAB9E7B031E7A708ULL,
		0x72377DB3D80B40CBULL,
		0xC90B4963172AB657ULL,
		0x051F9D112EC50C46ULL,
		0xA29FB181A56FC7D0ULL,
		0x34A58698D8C9B0CCULL,
		0x84263BA064274860ULL,
		0x1C1F8CA32D03BFC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF11EF5847E5DE4ADULL,
		0xD17B3B23983E04F8ULL,
		0xBB918EE77F8E5B4DULL,
		0x7CB5F62B0C41B6DBULL,
		0x4F1CCA17312B59ABULL,
		0x5B1054007EA3CDBEULL,
		0x56DEF2641B11BBA3ULL,
		0xFFD6FCCBDD3ADC7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDF62F0DF8F5BA33AULL,
		0xE43C107CB431A7C4ULL,
		0x2AD1292466514439ULL,
		0x0E06CD4334427BAEULL,
		0x0BE4A3843528C65DULL,
		0x42092F28920E5D82ULL,
		0x87A9196B35272101ULL,
		0xDC0936C91A2CC4AFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x07E8BC4D2533878DULL,
		0xC93E0F97F8B2ADBBULL,
		0x3590D703E80FF286ULL,
		0x19F9E23F97852494ULL,
		0xBAAB4F8832636F0FULL,
		0xB9132F2A2B828A34ULL,
		0x9637BB6ED9958355ULL,
		0x0F6482D79BB45D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD77A34926A281BADULL,
		0x1AFE00E4BB7EFA09ULL,
		0xF54052207E4151B3ULL,
		0xF40CEB039CBD5719ULL,
		0x513953FC02C5574DULL,
		0x88F5FFFE668BD34DULL,
		0xF1715DFC5B919DABULL,
		0xCCA4B3F17E786797ULL
	}};
	sign = 0;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x979622B2D88F7AE9ULL,
		0x28123783F621390DULL,
		0x342DEBC01412749BULL,
		0x002AA30973054FCAULL,
		0x2BE26FA2F533C994ULL,
		0xCD85D03BE75BF4F9ULL,
		0xAF2DF785FD7A28F2ULL,
		0x1D19C40DCEE1E4C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3EEB714576580EFULL,
		0x50FBFB5C607B9935ULL,
		0x57E7DCFA9097A887ULL,
		0x30F951EE3CD5DE28ULL,
		0xC2F0F79F73AB24ABULL,
		0xF5AB9F788F1497ADULL,
		0xD3BAC147B834AF3AULL,
		0xEB329E53AEEA01EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3A76B9E8129F9FAULL,
		0xD7163C2795A59FD7ULL,
		0xDC460EC5837ACC13ULL,
		0xCF31511B362F71A1ULL,
		0x68F178038188A4E8ULL,
		0xD7DA30C358475D4BULL,
		0xDB73363E454579B7ULL,
		0x31E725BA1FF7E2D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD3B61D8749009DC5ULL,
		0x48783190A12CB71AULL,
		0x6D86E4D3D5DD624CULL,
		0x5D8861D771F95B44ULL,
		0x1D2D03AE8A96D395ULL,
		0xEE086881726EE75BULL,
		0xBD98A511FF8DD798ULL,
		0x7871D8B6589E02A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1625317123BA171ULL,
		0xFE446196B47AE6BEULL,
		0xDF4403A91DE0D86AULL,
		0xDEF3A6E91D61516DULL,
		0xE955953396CEFB6CULL,
		0xD0BD6CFAC21464AFULL,
		0x96D19C2787C19E2EULL,
		0xFC6BD2A165327DA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3253CA7036C4FC54ULL,
		0x4A33CFF9ECB1D05CULL,
		0x8E42E12AB7FC89E1ULL,
		0x7E94BAEE549809D6ULL,
		0x33D76E7AF3C7D828ULL,
		0x1D4AFB86B05A82ABULL,
		0x26C708EA77CC396AULL,
		0x7C060614F36B8500ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x356F3AD97D1AEE9FULL,
		0xB9D542066A0087DBULL,
		0x554E6E42CF808BACULL,
		0xE4A9E0C9D3E2ECF5ULL,
		0x4B7B29F1E44A63D7ULL,
		0x0146175A9BAB0FCFULL,
		0x4ABF9733E29EEE7CULL,
		0x05B6A9E5D7B61B58ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DECB09E3C6D145ULL,
		0x331D121EA7E994D3ULL,
		0x10E18222D9F6DADCULL,
		0xD38C00690A6DEEA8ULL,
		0x324592E92891E557ULL,
		0xF3A03B01DAFA1854ULL,
		0x74CE0332F8D91060ULL,
		0x65FD4FD378DBA366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83906FCF99541D5AULL,
		0x86B82FE7C216F307ULL,
		0x446CEC1FF589B0D0ULL,
		0x111DE060C974FE4DULL,
		0x19359708BBB87E80ULL,
		0x0DA5DC58C0B0F77BULL,
		0xD5F19400E9C5DE1BULL,
		0x9FB95A125EDA77F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF799A561AEAB6CEFULL,
		0x0B1E29AA0A0B0401ULL,
		0xCCC4BF2D6628B01DULL,
		0xFB7B189AEFCE0875ULL,
		0x2302FFA877EDFDA2ULL,
		0xCB668EEACC226E5FULL,
		0x8C69E735A03E11FBULL,
		0xEDDBE4469DF911BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DFEA73CD0962D6ULL,
		0xC238507E1DC3F0D5ULL,
		0x332337D1C575FEC4ULL,
		0x15DA0F77F8120006ULL,
		0x9BB8EE766EC305F1ULL,
		0x75851D88A08173A3ULL,
		0x9080F2FD8620AFC1ULL,
		0x958DBC0BE910F5B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6B9BAEDE1A20A19ULL,
		0x48E5D92BEC47132CULL,
		0x99A1875BA0B2B158ULL,
		0xE5A10922F7BC086FULL,
		0x874A1132092AF7B1ULL,
		0x55E171622BA0FABBULL,
		0xFBE8F4381A1D623AULL,
		0x584E283AB4E81C06ULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x53B16E414EB05D57ULL,
		0x3329D6C2D12CFEA8ULL,
		0xC1EBEC1420736493ULL,
		0xB00446A4C54F4CD0ULL,
		0x8C733A191D8FA082ULL,
		0x671E7C6A87183DD5ULL,
		0x7E14F5BF701BF348ULL,
		0x4055BBB90BB0C420ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB71A9580296294E3ULL,
		0x8A7ECC977BB3AEB6ULL,
		0x25B8E7ED406AA59EULL,
		0x683A3CA6F321ED6CULL,
		0xD1964230DE1DD263ULL,
		0xE03C3003D05AB230ULL,
		0x83AD367E4C36F6CCULL,
		0x1FCAE0AB96897458ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C96D8C1254DC874ULL,
		0xA8AB0A2B55794FF1ULL,
		0x9C330426E008BEF4ULL,
		0x47CA09FDD22D5F64ULL,
		0xBADCF7E83F71CE1FULL,
		0x86E24C66B6BD8BA4ULL,
		0xFA67BF4123E4FC7BULL,
		0x208ADB0D75274FC7ULL
	}};
	sign = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x572CF196E16D1B72ULL,
		0xD0DB389A2C9D34A0ULL,
		0xD1A07F83C84E9BC5ULL,
		0x61E2EF588B5D3052ULL,
		0xE28C6A4DF08CDD71ULL,
		0xF2F1C46EEFBF347CULL,
		0xCE84F7FE3B7990D3ULL,
		0xC5E112B791ECA9B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x314327F22054AF65ULL,
		0x18105139703E8A68ULL,
		0x226E77AE7801E1A1ULL,
		0x2BA1F82A8B8E069AULL,
		0x221856AC81587069ULL,
		0x821D7A277D10BFC7ULL,
		0xE8B282AF98039299ULL,
		0x0F84346F09CF2771ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25E9C9A4C1186C0DULL,
		0xB8CAE760BC5EAA38ULL,
		0xAF3207D5504CBA24ULL,
		0x3640F72DFFCF29B8ULL,
		0xC07413A16F346D08ULL,
		0x70D44A4772AE74B5ULL,
		0xE5D2754EA375FE3AULL,
		0xB65CDE48881D8244ULL
	}};
	sign = 0;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B86E85352DEC32FULL,
		0x6D045F416FC71FEEULL,
		0x8C78F71825B4E333ULL,
		0x6A64D22FB4BA2EF8ULL,
		0x15EEFAD1D9F05613ULL,
		0x91539E86705BE17BULL,
		0xBD29FE455E102F78ULL,
		0xD1E5D7C3D688439FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x359098D266495439ULL,
		0x92F89972761ACEFAULL,
		0x53818B1AF586BD03ULL,
		0xECFE13E00E0ADD82ULL,
		0x6C7F955FE39AD4FCULL,
		0x78B32ED2A073D5CFULL,
		0x8C52A83ABE4460ADULL,
		0xE4F06624434B7BB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65F64F80EC956EF6ULL,
		0xDA0BC5CEF9AC50F4ULL,
		0x38F76BFD302E262FULL,
		0x7D66BE4FA6AF5176ULL,
		0xA96F6571F6558116ULL,
		0x18A06FB3CFE80BABULL,
		0x30D7560A9FCBCECBULL,
		0xECF5719F933CC7E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCCBD94DD43640A77ULL,
		0xEEDC0CBD3D3FD269ULL,
		0x6844B587EE927C30ULL,
		0x7EB4DBCB5171A297ULL,
		0x5A11650C8A1F9449ULL,
		0x4A98A93A9771B109ULL,
		0x176CEA9CEA54C5E4ULL,
		0xF461FF776BBA83FFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41177BD5974B7EBULL,
		0x1A63442BD24B19FCULL,
		0xF53267892ABEF131ULL,
		0xB8D3FE888661584AULL,
		0x98B4F3176D81FC25ULL,
		0xE432C7A50BCE5131ULL,
		0x10B73AA23742DF54ULL,
		0xFFA946639E548EFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08AC1D1FE9EF528CULL,
		0xD478C8916AF4B86DULL,
		0x73124DFEC3D38AFFULL,
		0xC5E0DD42CB104A4CULL,
		0xC15C71F51C9D9823ULL,
		0x6665E1958BA35FD7ULL,
		0x06B5AFFAB311E68FULL,
		0xF4B8B913CD65F500ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6D0CF33E54DC0734ULL,
		0x5ACB70F8AA4E40BDULL,
		0x2665ED517FED7482ULL,
		0xC05823B5749AEF4DULL,
		0x6D32033BB782FFF9ULL,
		0xB28F67551A350293ULL,
		0xDA3D5F1C74958C00ULL,
		0x76653CA08121593DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10434DA695DA3309ULL,
		0xFB7013C687C7040FULL,
		0xD31C9B7E24EF8B34ULL,
		0x5AEC73C3EA715FA1ULL,
		0x06A96C6F8C7C4641ULL,
		0x3120FFBCBADE9C63ULL,
		0x968C21A823EE026DULL,
		0x530A00882EC14FEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CC9A597BF01D42BULL,
		0x5F5B5D3222873CAEULL,
		0x534951D35AFDE94DULL,
		0x656BAFF18A298FABULL,
		0x668896CC2B06B9B8ULL,
		0x816E67985F566630ULL,
		0x43B13D7450A78993ULL,
		0x235B3C185260094EULL
	}};
	sign = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3270944FC13C1710ULL,
		0x83A40A7D8A85D905ULL,
		0x74EDAFB5CFD927CEULL,
		0xF5AA069DE3AC1D4DULL,
		0xB5DA7420D8771F4DULL,
		0x0239C3C422E40B20ULL,
		0x9F80F38BBE874409ULL,
		0xC63C01792924685EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5377B1FF7C1E293ULL,
		0x51F0F564DB6C9CAFULL,
		0x6EAA869ECACA314FULL,
		0xE6412833AC80E4E8ULL,
		0xF48C79F1594A963CULL,
		0x6C2D0CD1F975DBACULL,
		0x41CF95989A75450BULL,
		0x791726E66894C2FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D39192FC97A347DULL,
		0x31B31518AF193C55ULL,
		0x06432917050EF67FULL,
		0x0F68DE6A372B3865ULL,
		0xC14DFA2F7F2C8911ULL,
		0x960CB6F2296E2F73ULL,
		0x5DB15DF32411FEFDULL,
		0x4D24DA92C08FA562ULL
	}};
	sign = 0;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x035B4408DCD02652ULL,
		0x08994A9A432A6503ULL,
		0xAF2AA9F6F38BA26EULL,
		0x26D8121C83484F15ULL,
		0x0A51F112D91B12A1ULL,
		0x5CBA289E1C6481ADULL,
		0xA6A46F1D713B6AF6ULL,
		0xC50EC0CF2D26DD4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C5809E2EC4B7842ULL,
		0x57C52E192FB5D10FULL,
		0x47A70B3CA692D794ULL,
		0xFE4B6B48127D7C60ULL,
		0xC9879B033CACCA2BULL,
		0x63E4E3A6D1DA8AD7ULL,
		0x261190DF7A26C38CULL,
		0xFEF4EC5EBD734C66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77033A25F084AE10ULL,
		0xB0D41C81137493F3ULL,
		0x67839EBA4CF8CAD9ULL,
		0x288CA6D470CAD2B5ULL,
		0x40CA560F9C6E4875ULL,
		0xF8D544F74A89F6D5ULL,
		0x8092DE3DF714A769ULL,
		0xC619D4706FB390E5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x924B3EB2C39D694BULL,
		0x126EB9977702BEDFULL,
		0xA6AB481F21DE266EULL,
		0x8B9F086338A1211BULL,
		0x070E541063C2DAC9ULL,
		0x833492010A0D47DBULL,
		0xE0C85FF68DEE1565ULL,
		0xDF52930B15F1AB13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE2A395E10F779CULL,
		0x2A6225533DD7EE04ULL,
		0xBC2651793637D2D7ULL,
		0x2E59A1F0E2271954ULL,
		0x8CACFDE3DB34C4C2ULL,
		0x0C47FF91DCF6777EULL,
		0xE27EC04E717A9594ULL,
		0xCDF4F78BA9727876ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47689B1CE28DF1AFULL,
		0xE80C9444392AD0DBULL,
		0xEA84F6A5EBA65396ULL,
		0x5D456672567A07C6ULL,
		0x7A61562C888E1607ULL,
		0x76EC926F2D16D05CULL,
		0xFE499FA81C737FD1ULL,
		0x115D9B7F6C7F329CULL
	}};
	sign = 0;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBAFA1BAD6D5AA909ULL,
		0x9C41DE23FD9523C9ULL,
		0xB6B74C2ADF485FEAULL,
		0xED31DC06375A7190ULL,
		0xDBE67A7A4D5BCA60ULL,
		0xA93B93E3C4120EAEULL,
		0x4F7909C2D8B68D08ULL,
		0x36993A8C4A74A6C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE25B5E7AAB64A90ULL,
		0x47925910A91A6DF5ULL,
		0xAC6BC90C4853025AULL,
		0xEF267ED19734E3A8ULL,
		0xFE7FF1B59B4F4A26ULL,
		0xE3018FDBE035A9CFULL,
		0xA635EA198935BAA7ULL,
		0x7DCB11286E988075ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECD465C5C2A45E79ULL,
		0x54AF8513547AB5D3ULL,
		0x0A4B831E96F55D90ULL,
		0xFE0B5D34A0258DE8ULL,
		0xDD6688C4B20C8039ULL,
		0xC63A0407E3DC64DEULL,
		0xA9431FA94F80D260ULL,
		0xB8CE2963DBDC2651ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CE860FF39D04A0FULL,
		0x56C431BA20FC2FB6ULL,
		0xE4BE9F5E2308808EULL,
		0xB75001357264A44EULL,
		0x3BD627021135897FULL,
		0xEA7F050AD1C21D14ULL,
		0x9AADC320A82CC634ULL,
		0xA8826522DD5602B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE93008A9E894979AULL,
		0xA978DA3103869469ULL,
		0xC0F184798A62A64DULL,
		0x43C109B0E8FD504DULL,
		0x27DA20372DB549D5ULL,
		0x92DC14F2C5CFEAF5ULL,
		0x1F1CB99D429298E7ULL,
		0xBDD2EF0EEFB437BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63B85855513BB275ULL,
		0xAD4B57891D759B4CULL,
		0x23CD1AE498A5DA40ULL,
		0x738EF78489675401ULL,
		0x13FC06CAE3803FAAULL,
		0x57A2F0180BF2321FULL,
		0x7B910983659A2D4DULL,
		0xEAAF7613EDA1CAF7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2DFF1F4B8DD99234ULL,
		0xF61D9EFD56C590B5ULL,
		0x28566AC50257F073ULL,
		0x888C7B07F9AE7CD6ULL,
		0x72E96CD2BD9BA470ULL,
		0x5B49B417A7C974B3ULL,
		0xFC544B7472CBDDD2ULL,
		0xBAE97E747DA22703ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1F4BD31B663094ULL,
		0xAF7160FC975F87E1ULL,
		0xAF554243B33C8E2CULL,
		0xFCBE4EB1B6389204ULL,
		0x6EDE3EAAE2F76B37ULL,
		0xB540849FFF546EB9ULL,
		0xAF1D8A5B0E7D15C7ULL,
		0x2A0B690AFD7E34A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EDFD378727361A0ULL,
		0x46AC3E00BF6608D3ULL,
		0x790128814F1B6247ULL,
		0x8BCE2C564375EAD1ULL,
		0x040B2E27DAA43938ULL,
		0xA6092F77A87505FAULL,
		0x4D36C119644EC80AULL,
		0x90DE15698023F262ULL
	}};
	sign = 0;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEAFEB88F165C3BA0ULL,
		0x1658F268A690A857ULL,
		0xA192D5F96AA9A29EULL,
		0x409CC71EDA7D4CC0ULL,
		0xECF602DE170DDA0EULL,
		0xB36E088885753B88ULL,
		0x2DCB185211A3DBA0ULL,
		0x922C83C3F3EEFCCEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF65F8B66E5C936B9ULL,
		0x4641FCFE6ED57A17ULL,
		0xD5F19CFA027495C7ULL,
		0xFE360BA12663BADFULL,
		0xD75377B111F485CCULL,
		0x74AD133F622B92C2ULL,
		0xD7E5DFD7DEE9EA9CULL,
		0x42778AABAF70CCDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF49F2D28309304E7ULL,
		0xD016F56A37BB2E3FULL,
		0xCBA138FF68350CD6ULL,
		0x4266BB7DB41991E0ULL,
		0x15A28B2D05195441ULL,
		0x3EC0F5492349A8C6ULL,
		0x55E5387A32B9F104ULL,
		0x4FB4F918447E2FEFULL
	}};
	sign = 0;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x77F155FA8CCB25C5ULL,
		0x989E97292F935C40ULL,
		0xCE826FE0BDA4EA07ULL,
		0xD7FEEABF75C6F5C4ULL,
		0x56706B1B363D2C14ULL,
		0x844D434902EF9FEEULL,
		0xE7CDBABDBC46BA13ULL,
		0x01920E00FC1A8FE0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x982A30E4719FD384ULL,
		0x9D2B50F5901BD7AEULL,
		0x24FE3BEF1F7266ACULL,
		0x5BE66CFF6B521C3BULL,
		0x3DB43E5A7E4CF6D7ULL,
		0x6AC5209FE2E5995CULL,
		0x56A9E8D75E1721F8ULL,
		0xF516D700094E7B11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFC725161B2B5241ULL,
		0xFB7346339F778491ULL,
		0xA98433F19E32835AULL,
		0x7C187DC00A74D989ULL,
		0x18BC2CC0B7F0353DULL,
		0x198822A9200A0692ULL,
		0x9123D1E65E2F981BULL,
		0x0C7B3700F2CC14CFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6DCBE33BE1390DE0ULL,
		0x757D1189C5EB3C05ULL,
		0x0BE09BCDA55B63E6ULL,
		0xE8DCB30C34F84273ULL,
		0x1DB2C6D95B777877ULL,
		0xBB294B49CB4193E9ULL,
		0x70A01B4DD1CD4578ULL,
		0x0600CDEA16303E4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x54FACF1EE09DA6BBULL,
		0x50D838EAE829B35BULL,
		0x62732906393D214DULL,
		0xD67A548025179B49ULL,
		0x235A6488500C70EDULL,
		0x8584ED8E35312D65ULL,
		0xBE9407D440B1F125ULL,
		0x2CF4AA89365600CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D1141D009B6725ULL,
		0x24A4D89EDDC188AAULL,
		0xA96D72C76C1E4299ULL,
		0x12625E8C0FE0A729ULL,
		0xFA5862510B6B078AULL,
		0x35A45DBB96106683ULL,
		0xB20C1379911B5453ULL,
		0xD90C2360DFDA3D83ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x94C6ED2F39A5E174ULL,
		0x378D48C13F3A2132ULL,
		0x3392A4894D4CDCA3ULL,
		0x6CBBC2B26099ABC8ULL,
		0x5B90C728EB980B09ULL,
		0x53C6D3751B5C7082ULL,
		0xF88354716A209F06ULL,
		0x43DADF9EBDA03176ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17FB5EF5AF984E61ULL,
		0x621CB0CE8B12EE62ULL,
		0xBC13D8AAB5B66988ULL,
		0x99CCF962E1AB4040ULL,
		0xD3AA49F7C9E161F6ULL,
		0x7AB2BFCE7127417AULL,
		0x80D90867E8C5ADB0ULL,
		0xC4F6BA9E59233AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CCB8E398A0D9313ULL,
		0xD57097F2B42732D0ULL,
		0x777ECBDE9796731AULL,
		0xD2EEC94F7EEE6B87ULL,
		0x87E67D3121B6A912ULL,
		0xD91413A6AA352F07ULL,
		0x77AA4C09815AF155ULL,
		0x7EE42500647CF689ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA5EE775A4CC5F8FBULL,
		0xA151AA40DEDD99ADULL,
		0x21DD3C6839596FB6ULL,
		0xC21379FE52952FF6ULL,
		0x0699DDC3D332AD5AULL,
		0xCEBD7C01DE7909E3ULL,
		0x6AAE647CB6A063D3ULL,
		0xBB1B0306247764FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1450F09D1F08D42ULL,
		0x89423F6223E4B599ULL,
		0x98477DAE166B6051ULL,
		0xCDD1381F57E0B904ULL,
		0x3AE592C2E4D16846ULL,
		0x064B0FB1FF90DFD1ULL,
		0x52EEE78C8A05C645ULL,
		0xEB75F065287AF929ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4A968507AD56BB9ULL,
		0x180F6ADEBAF8E413ULL,
		0x8995BEBA22EE0F65ULL,
		0xF44241DEFAB476F1ULL,
		0xCBB44B00EE614513ULL,
		0xC8726C4FDEE82A11ULL,
		0x17BF7CF02C9A9D8EULL,
		0xCFA512A0FBFC6BD5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF5D0851FA01E323ULL,
		0x2749A3783444AC7AULL,
		0x9ABB8CE9B96E0C96ULL,
		0x1B4722FD4F01386AULL,
		0x71C6E692A7AE84CBULL,
		0x12C571914161E930ULL,
		0xEDF7E7BBB99B3505ULL,
		0x47302E38C42B5910ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27F607F42A2B767DULL,
		0x263E636D63CF27B6ULL,
		0x62B9B672F5351CF1ULL,
		0xF49D8D6ACB81F495ULL,
		0x5BDFA42C974E0AA4ULL,
		0xC115BA003A128BCCULL,
		0xFC68EE1DF2696DA0ULL,
		0x384A096E3DACF4FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC767005DCFD66CA6ULL,
		0x010B400AD07584C4ULL,
		0x3801D676C438EFA5ULL,
		0x26A99592837F43D5ULL,
		0x15E7426610607A26ULL,
		0x51AFB791074F5D64ULL,
		0xF18EF99DC731C764ULL,
		0x0EE624CA867E6414ULL
	}};
	sign = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFE9CEB6E93F10388ULL,
		0x665783DEBE243479ULL,
		0x1E7004C2EAC6FDF0ULL,
		0x12E78EF021D116E4ULL,
		0x8CF443156E9FF544ULL,
		0xE0B3CC1CD472005BULL,
		0x6C6F9967D4C7DD50ULL,
		0xABD2C7381FAA1F32ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x60D41A338F1BACE6ULL,
		0x801A8E2498D2294AULL,
		0x86921B9DB1A1C8FDULL,
		0x98AAB8EB0CE02960ULL,
		0x167647C58EAC6B23ULL,
		0x196C2A7C8ECD3968ULL,
		0x76B78392858376FAULL,
		0x7D86C5AA6A09C709ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DC8D13B04D556A2ULL,
		0xE63CF5BA25520B2FULL,
		0x97DDE925392534F2ULL,
		0x7A3CD60514F0ED83ULL,
		0x767DFB4FDFF38A20ULL,
		0xC747A1A045A4C6F3ULL,
		0xF5B815D54F446656ULL,
		0x2E4C018DB5A05828ULL
	}};
	sign = 0;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E2763EAEB90600EULL,
		0x643D5928D6341860ULL,
		0x17578BB68B75B229ULL,
		0x8B8F11AE9D793F2CULL,
		0x8965A2BAE7961744ULL,
		0x3E2652EF066C8D16ULL,
		0xCAB6A2D03894CDCFULL,
		0x86E8F9D9D7B193E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20034BB4FDDB349CULL,
		0x150DCECA7630D632ULL,
		0xF4C324D18712D43BULL,
		0xF9AE6F5D93EA9EFFULL,
		0xF9B5D64175C09742ULL,
		0x7554FD1EFBECAD47ULL,
		0x6CEE3B11D406BCB3ULL,
		0xA0D7ED9067F6B471ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E241835EDB52B72ULL,
		0x4F2F8A5E6003422EULL,
		0x229466E50462DDEEULL,
		0x91E0A251098EA02CULL,
		0x8FAFCC7971D58001ULL,
		0xC8D155D00A7FDFCEULL,
		0x5DC867BE648E111BULL,
		0xE6110C496FBADF78ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA797A93C7AA4C1ECULL,
		0x196FA3205BD055F3ULL,
		0xE2CFA5DF06FEB075ULL,
		0xEFC094B7BF766EDAULL,
		0xFC6BEFE707501DD8ULL,
		0x3D1F59B8F7147AB1ULL,
		0xA1AF584C532D1462ULL,
		0x29FF71891B36256AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2241108E38B1EC3DULL,
		0xF95D463376A32B81ULL,
		0x8E4E2E3A362CECD2ULL,
		0x2035E2CDF18DA287ULL,
		0x6B8836C4AFC321ABULL,
		0x0E2599A340D811A6ULL,
		0xD0AB12E0655F84B4ULL,
		0x0C6076F81B635569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x855698AE41F2D5AFULL,
		0x20125CECE52D2A72ULL,
		0x548177A4D0D1C3A2ULL,
		0xCF8AB1E9CDE8CC53ULL,
		0x90E3B922578CFC2DULL,
		0x2EF9C015B63C690BULL,
		0xD104456BEDCD8FAEULL,
		0x1D9EFA90FFD2D000ULL
	}};
	sign = 0;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7173A9B376507803ULL,
		0x2D9D050B3B9393A5ULL,
		0x66ED405F0ADA5837ULL,
		0x95C3317BA24FCA58ULL,
		0x32ABDC3D0C31411AULL,
		0x58FC5A35A5567021ULL,
		0x97FE85F28F416C6FULL,
		0xD96BBE8511686635ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x828A102A358C9821ULL,
		0x1EFA6D005041A265ULL,
		0x1231D096ECCF496FULL,
		0x7007172AF206F684ULL,
		0x5CB99362E3C3CCD4ULL,
		0x6314472484D35D8AULL,
		0x12CC333C60EAF6C2ULL,
		0x5B202D30F88AE7A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEE9998940C3DFE2ULL,
		0x0EA2980AEB51F13FULL,
		0x54BB6FC81E0B0EC8ULL,
		0x25BC1A50B048D3D4ULL,
		0xD5F248DA286D7446ULL,
		0xF5E8131120831296ULL,
		0x853252B62E5675ACULL,
		0x7E4B915418DD7E92ULL
	}};
	sign = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B27B42CF3503CBDULL,
		0x1628884EAD66197AULL,
		0x02F6D57453E15B75ULL,
		0x88A5E8065E824E2AULL,
		0x0659E2F98A5B7827ULL,
		0xFE15D066EB976629ULL,
		0x9EEC56A64E9C4BA3ULL,
		0xB5C3A73250EA7CB0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8968FF471863DE9ULL,
		0x90AAF44BE040D578ULL,
		0x572D784FAB29CF0BULL,
		0x5E075A93B9F61AA6ULL,
		0x81BA0AFB37B9385CULL,
		0xB0D65EC5EE2CD83AULL,
		0x3DF1915886C000A3ULL,
		0xAB9B53726A0426BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA291243881C9FED4ULL,
		0x857D9402CD254401ULL,
		0xABC95D24A8B78C69ULL,
		0x2A9E8D72A48C3383ULL,
		0x849FD7FE52A23FCBULL,
		0x4D3F71A0FD6A8DEEULL,
		0x60FAC54DC7DC4B00ULL,
		0x0A2853BFE6E655F2ULL
	}};
	sign = 0;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDB932EFF16DBDFF5ULL,
		0xFDEE8C00D70E44CFULL,
		0xF2F528EEB278C1C2ULL,
		0x2EFDCD9B92C9A709ULL,
		0x73728DA60D40E06FULL,
		0x2907F94917203C04ULL,
		0xE0C81FF4725BCCE4ULL,
		0x68FEA5DA18DB2214ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76840218053B05A9ULL,
		0x3A8B241F4AAAB126ULL,
		0x328BAF2E01AFD031ULL,
		0xFD2A652F69697CDBULL,
		0x6ACABC2DE4F86E0CULL,
		0x09428593D2820705ULL,
		0xADF3E38169A75538ULL,
		0x0BE2DB67F31AEA12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x650F2CE711A0DA4CULL,
		0xC36367E18C6393A9ULL,
		0xC06979C0B0C8F191ULL,
		0x31D3686C29602A2EULL,
		0x08A7D17828487262ULL,
		0x1FC573B5449E34FFULL,
		0x32D43C7308B477ACULL,
		0x5D1BCA7225C03802ULL
	}};
	sign = 0;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x319C3067B1DA705DULL,
		0x0491C4C8482FA063ULL,
		0x7C85A36A60E0C2D5ULL,
		0x011075226CA574DDULL,
		0x33067E0A249D857DULL,
		0x6A86FFC39B53A0A5ULL,
		0xFD29CA175CE1A615ULL,
		0xC2A5020B7BBC4202ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD743B8085697ADULL,
		0x4C44735353125DDCULL,
		0x74F5B6C424CCC55EULL,
		0x01C7B9C8DEE5C903ULL,
		0x40D651CF5FFF88D8ULL,
		0xF2AA6746073569FBULL,
		0xCD8D77D160288F91ULL,
		0x25516E9102337615ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4C4ECAFA983D8B0ULL,
		0xB84D5174F51D4286ULL,
		0x078FECA63C13FD76ULL,
		0xFF48BB598DBFABDAULL,
		0xF2302C3AC49DFCA4ULL,
		0x77DC987D941E36A9ULL,
		0x2F9C5245FCB91683ULL,
		0x9D53937A7988CBEDULL
	}};
	sign = 0;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1AB212433F39C2DBULL,
		0xD377F36E7BB44B9CULL,
		0x2611CDAA12831EBCULL,
		0x323279ABD7A21456ULL,
		0xBF235D3200883197ULL,
		0x45000A2156E54E43ULL,
		0x4C5FB1BF7F7D887BULL,
		0x2A9351E340F6FEA8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E391B2FC11E5D1ULL,
		0x076CDDAEB03FF189ULL,
		0xAAEA8BDED2FBCE7FULL,
		0x2F142FF831B7373DULL,
		0x4529ABD7F3A07FFAULL,
		0xFE45AACD26CE2657ULL,
		0xFB8DE5BAFA41FB74ULL,
		0x2D961EC79590F9F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3CE80904327DD0AULL,
		0xCC0B15BFCB745A12ULL,
		0x7B2741CB3F87503DULL,
		0x031E49B3A5EADD18ULL,
		0x79F9B15A0CE7B19DULL,
		0x46BA5F54301727ECULL,
		0x50D1CC04853B8D06ULL,
		0xFCFD331BAB6604B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x159890D7B9F00DEAULL,
		0xDBCFE5EE84DD1A39ULL,
		0x68762014C2428E20ULL,
		0x40AE0C214DEA4605ULL,
		0xEA4859111AE24B7BULL,
		0x91C1DE9AFD722635ULL,
		0x81AF01833FDDC068ULL,
		0x1022439824D81588ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x579CD94692FE232DULL,
		0x948DC08F4483401DULL,
		0x80E78DA4B43B22A4ULL,
		0x3F7671915A8C6D36ULL,
		0xDCC5E36ECBA2B34AULL,
		0xFE66F7BEEA4D187DULL,
		0xBE8FD79E955D1668ULL,
		0xF420945BC5C51DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDFBB79126F1EABDULL,
		0x4742255F4059DA1BULL,
		0xE78E92700E076B7CULL,
		0x01379A8FF35DD8CEULL,
		0x0D8275A24F3F9831ULL,
		0x935AE6DC13250DB8ULL,
		0xC31F29E4AA80A9FFULL,
		0x1C01AF3C5F12F7D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFC6E47661762D8C1ULL,
		0x48C46B25D098C13EULL,
		0x4399F25EE274F527ULL,
		0xEF90A8AEF9A605FFULL,
		0x98113013DE71F388ULL,
		0x4CE800F405C27311ULL,
		0xBAE64199031D6857ULL,
		0x15C0C00F05AAB3EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DDDFD6FF08CAF5ULL,
		0xCB5F36C319636228ULL,
		0x87ADEC9B9BA1C36CULL,
		0x0661AD9D2629C5ACULL,
		0x88974A6D62356B0DULL,
		0xC966F3C4892975A5ULL,
		0xA6C4139F29C564B5ULL,
		0x42B8AA2BDCD63FF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8690678F185A0DCCULL,
		0x7D653462B7355F16ULL,
		0xBBEC05C346D331BAULL,
		0xE92EFB11D37C4052ULL,
		0x0F79E5A67C3C887BULL,
		0x83810D2F7C98FD6CULL,
		0x14222DF9D95803A1ULL,
		0xD30815E328D473F4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE42CE64248630504ULL,
		0x6E22107BFDB30DA9ULL,
		0xBC2577E6C7697244ULL,
		0x87B6F6E26BD2D82BULL,
		0x05F4F357E9B93CEEULL,
		0x60C9BB0837FD12FDULL,
		0xCAA89F02110ABCFDULL,
		0xEE1918D6674B0A23ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A91DB9D305FD253ULL,
		0x9436885346B2DC63ULL,
		0x4E3F8A597028DD81ULL,
		0xAF95F8A29D12EEDFULL,
		0xACF5966DAB38D855ULL,
		0xA72BE93CA48662D5ULL,
		0x4F12F49E29020602ULL,
		0x13A3220717108930ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x699B0AA5180332B1ULL,
		0xD9EB8828B7003146ULL,
		0x6DE5ED8D574094C2ULL,
		0xD820FE3FCEBFE94CULL,
		0x58FF5CEA3E806498ULL,
		0xB99DD1CB9376B027ULL,
		0x7B95AA63E808B6FAULL,
		0xDA75F6CF503A80F3ULL
	}};
	sign = 0;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCAF38424BFB7C2D5ULL,
		0x322F400CF1461ED3ULL,
		0x83429DC89B78ADF9ULL,
		0x48F9F6899727CE81ULL,
		0xEB5F0E75BC331550ULL,
		0xD79B9BA22ECEAB98ULL,
		0x9D02B7ECCCD981DAULL,
		0xDB387037DC3E4B41ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1023EA4FB23EE079ULL,
		0x94B684CAC2F1883BULL,
		0x993D828C17EA061AULL,
		0xB94294C1C820EC59ULL,
		0xE29441CCEA211E37ULL,
		0x78C8705F059F96FFULL,
		0x1FB073A4E6B4A13DULL,
		0x355AE2132BD2CA4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBACF99D50D78E25CULL,
		0x9D78BB422E549698ULL,
		0xEA051B3C838EA7DEULL,
		0x8FB761C7CF06E227ULL,
		0x08CACCA8D211F718ULL,
		0x5ED32B43292F1499ULL,
		0x7D524447E624E09DULL,
		0xA5DD8E24B06B80F5ULL
	}};
	sign = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07C082C29D40B946ULL,
		0xA7F871DE3C463772ULL,
		0xE52EE1FEE9D2C90DULL,
		0x1A19B3CF6304771AULL,
		0x3E7AD52F86BA715DULL,
		0x21F39FA2368AE2E4ULL,
		0xD46BCBB7C50D3EDDULL,
		0xBA48A38840854ADDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C0F7DEA992D53DEULL,
		0x91D9E162B1941EBDULL,
		0x30C883A0B1033791ULL,
		0x8012A51C324196F6ULL,
		0xAD18466E3678DB6FULL,
		0x4FBA292528184508ULL,
		0x2C811C70D5E09197ULL,
		0x32856996495F0C73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBB104D804136568ULL,
		0x161E907B8AB218B4ULL,
		0xB4665E5E38CF917CULL,
		0x9A070EB330C2E024ULL,
		0x91628EC1504195EDULL,
		0xD239767D0E729DDBULL,
		0xA7EAAF46EF2CAD45ULL,
		0x87C339F1F7263E6AULL
	}};
	sign = 0;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9DC7F877887C8EA1ULL,
		0x39041BDBFB480ADDULL,
		0x6B6997F7E6C601B3ULL,
		0x67730A74EABC7745ULL,
		0x8581EA6B7377D758ULL,
		0xC338F6F1FBFB4EBFULL,
		0x70843766A2023ACCULL,
		0x710F4AFCAABCCB40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x94B065F8256D6457ULL,
		0x8EBAB24538CC3AEEULL,
		0xC3F424431A16BCCFULL,
		0x7CC6B8B322B1BA7BULL,
		0x1070628CE664D651ULL,
		0x79A41EAAC9ACAD3BULL,
		0xB9670B355E2442AAULL,
		0xB8AE6E95D9946E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0917927F630F2A4AULL,
		0xAA496996C27BCFEFULL,
		0xA77573B4CCAF44E3ULL,
		0xEAAC51C1C80ABCC9ULL,
		0x751187DE8D130106ULL,
		0x4994D847324EA184ULL,
		0xB71D2C3143DDF822ULL,
		0xB860DC66D1285D12ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCE399D46CDB965ADULL,
		0xF8F0384DA402E1F2ULL,
		0x9A7CDB8D27867D04ULL,
		0x81EAE3B7E4EDED9EULL,
		0x568A347187317D90ULL,
		0x888FB485F6F41FD9ULL,
		0xD7B2885E9BAAA887ULL,
		0x4D62CF0EF6D4E64FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D09DA4C76F41A96ULL,
		0x9CB2C6CE4E3551CDULL,
		0x924B800E70AF7B48ULL,
		0x358123ACC029D3DFULL,
		0xB4E079CB5EA1884FULL,
		0x64FC856597F17125ULL,
		0xB08DB77DF631C27FULL,
		0x50CBBBAECB906CC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x412FC2FA56C54B17ULL,
		0x5C3D717F55CD9025ULL,
		0x08315B7EB6D701BCULL,
		0x4C69C00B24C419BFULL,
		0xA1A9BAA6288FF541ULL,
		0x23932F205F02AEB3ULL,
		0x2724D0E0A578E608ULL,
		0xFC9713602B44798CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8C82BB2896FE1958ULL,
		0x6C428177CEFED002ULL,
		0x4002E4F0845B99CFULL,
		0xDB57ADC77CE7F0A7ULL,
		0xE10E31C7636E82C0ULL,
		0xC9EB0C8E688792BCULL,
		0x590F630B3533ED31ULL,
		0xCAA7DB28BFE99172ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x466D23138D7F1B9AULL,
		0xE96261DBDC7C162DULL,
		0x8A6BF008DFC40FC3ULL,
		0xFCF57A0B6D0A03FAULL,
		0xC210F7CDAEA3ABAFULL,
		0xCB0C6B24089A8E6BULL,
		0x56275A06701B67E2ULL,
		0xF604E4F0598B75B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46159815097EFDBEULL,
		0x82E01F9BF282B9D5ULL,
		0xB596F4E7A4978A0BULL,
		0xDE6233BC0FDDECACULL,
		0x1EFD39F9B4CAD710ULL,
		0xFEDEA16A5FED0451ULL,
		0x02E80904C518854EULL,
		0xD4A2F638665E1BB9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98E7BA15134099FDULL,
		0x5F21C89926EC56CFULL,
		0x84BA1C30E0A3BC18ULL,
		0x708C0F2774B3C47EULL,
		0x16B9532512EBC5ADULL,
		0x39968FFC189E3F93ULL,
		0x9FA1F3AF43452EBEULL,
		0x20E8F264F38712F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x48808AD9B77A2371ULL,
		0x993F1DC97B5631BBULL,
		0x60E10976EEA7947EULL,
		0xD90492F2DF85BA3BULL,
		0xAC82E96C3BFB0F21ULL,
		0x1CEB82B45A0BB845ULL,
		0x692992632350E1F4ULL,
		0xD47028DB4031EE25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50672F3B5BC6768CULL,
		0xC5E2AACFAB962514ULL,
		0x23D912B9F1FC2799ULL,
		0x97877C34952E0A43ULL,
		0x6A3669B8D6F0B68BULL,
		0x1CAB0D47BE92874DULL,
		0x3678614C1FF44CCAULL,
		0x4C78C989B35524D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE9C70B877643FFBULL,
		0xDD091B6CF08CE2C2ULL,
		0xA9237951ED73A30BULL,
		0x50F89FE73A7DDBEDULL,
		0x218F08E5EB7739FCULL,
		0x804C785ADC07E83FULL,
		0x3A505BCDEE19BC8DULL,
		0xFCBDD7BCE0789635ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1543C52C204A77A3ULL,
		0x1CD3118092031693ULL,
		0xCBAE164D342A77FCULL,
		0xAC6EC3DB33768CF7ULL,
		0x98A6988592506A30ULL,
		0xAC2EC26D6DA8067AULL,
		0x844F84D661C25AC2ULL,
		0xBB9D33BA491C3451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC958AB8C5719C858ULL,
		0xC03609EC5E89CC2FULL,
		0xDD756304B9492B0FULL,
		0xA489DC0C07074EF5ULL,
		0x88E870605926CFCBULL,
		0xD41DB5ED6E5FE1C4ULL,
		0xB600D6F78C5761CAULL,
		0x4120A402975C61E3ULL
	}};
	sign = 0;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x36C087F43523F0F7ULL,
		0xFDE5E52D60C47CC7ULL,
		0xE436A5B8B52F7BCCULL,
		0x39D3A423940241BBULL,
		0x0A5561CE3BD9945AULL,
		0xC6AF1DDC20999609ULL,
		0x561EA1F72FC52B08ULL,
		0x6A1CDB338DB8913FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46C7920C7DD5918ULL,
		0x12B71D34FE5951F3ULL,
		0x5B0B53109E852D05ULL,
		0x5208DCBB7D03F0F8ULL,
		0xC8A248CD7504DC33ULL,
		0x593EC78127A794A1ULL,
		0x41C3E22CB03B5FCDULL,
		0x08C9EC50AC6F278CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82540ED36D4697DFULL,
		0xEB2EC7F8626B2AD3ULL,
		0x892B52A816AA4EC7ULL,
		0xE7CAC76816FE50C3ULL,
		0x41B31900C6D4B826ULL,
		0x6D70565AF8F20167ULL,
		0x145ABFCA7F89CB3BULL,
		0x6152EEE2E14969B3ULL
	}};
	sign = 0;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD439CE1D234E8E96ULL,
		0xA5709FDD66A7FB1DULL,
		0x7B342D9DE28B59FEULL,
		0x6A3D56C4E3185CC9ULL,
		0xD3A549963092CC75ULL,
		0xE04559B6B2A06D83ULL,
		0x0252F61AA02FFBF9ULL,
		0x866F35F678CC021AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5A9026EA335AC44ULL,
		0x45EE770E280EAFB5ULL,
		0x9AD56A6CB2EDDF34ULL,
		0xFC011E297F8FFADAULL,
		0xEAA1CBAD863D4340ULL,
		0x6426D6C1AEF758BDULL,
		0x3D7B783C7F157B9AULL,
		0xCD50CD62944FCD77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E90CBAE8018E252ULL,
		0x5F8228CF3E994B68ULL,
		0xE05EC3312F9D7ACAULL,
		0x6E3C389B638861EEULL,
		0xE9037DE8AA558934ULL,
		0x7C1E82F503A914C5ULL,
		0xC4D77DDE211A805FULL,
		0xB91E6893E47C34A2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF9F17A673735CF57ULL,
		0x9EB97C1AC5FDDE90ULL,
		0xAF361EEE9418CB5CULL,
		0x22B234EA9244BB62ULL,
		0x22B4DCEAD059595EULL,
		0xEACDEB32CD01CA72ULL,
		0x54321E01BD25069DULL,
		0x5BA81153C8BE5CFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81A49167555BAE3ULL,
		0x6FC2838668C71014ULL,
		0x6F3EBFABBF7E45B3ULL,
		0x49E0626BD17B981AULL,
		0xE284CD70729905E0ULL,
		0x2EF12848E5993C9EULL,
		0x94DA9D6D0509C7E5ULL,
		0x32AC71B44B2593B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31D73150C1E01474ULL,
		0x2EF6F8945D36CE7CULL,
		0x3FF75F42D49A85A9ULL,
		0xD8D1D27EC0C92348ULL,
		0x40300F7A5DC0537DULL,
		0xBBDCC2E9E7688DD3ULL,
		0xBF578094B81B3EB8ULL,
		0x28FB9F9F7D98C949ULL
	}};
	sign = 0;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC6CB61A5775C2128ULL,
		0xADE55A852BA53A9AULL,
		0x8ADB434F1DF27D04ULL,
		0x08003F7CB5FA4E14ULL,
		0xFD0ECF38870AF48FULL,
		0x5DEC637EBF20ACE0ULL,
		0x5203D46B06AAEDA5ULL,
		0x1CDB97B9D5EADD07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF75A4649EFD4E21ULL,
		0x15532A1A77296FE1ULL,
		0xF04F3F1087C54F49ULL,
		0xE1045024E4BE2BE7ULL,
		0x46B68CC20F7C8734ULL,
		0xE71F2E34E3F3A08FULL,
		0x618B14A801611031ULL,
		0x0ADAFD44FE73B6F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC755BD40D85ED307ULL,
		0x9892306AB47BCAB8ULL,
		0x9A8C043E962D2DBBULL,
		0x26FBEF57D13C222CULL,
		0xB6584276778E6D5AULL,
		0x76CD3549DB2D0C51ULL,
		0xF078BFC30549DD73ULL,
		0x12009A74D7772612ULL
	}};
	sign = 0;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC7C609CBF1EA2EABULL,
		0xC353DD96EE763133ULL,
		0xAC233EC72E07DD1DULL,
		0x33F3D081785A4111ULL,
		0x7CBF947942122EAEULL,
		0x3B0B02E8E7B0B222ULL,
		0xED158309203C7727ULL,
		0x4EF951817BF362F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9A130E3EE02C8EULL,
		0x99A033AD2BF5A803ULL,
		0x61140D9BF5AF0F58ULL,
		0x0F819F59B053DD52ULL,
		0x153E6C4D11EB3B63ULL,
		0x597C7C4753D97745ULL,
		0x816FA4E1175EB3D8ULL,
		0x83BD412AEF7EB397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A2BF6BDB30A021DULL,
		0x29B3A9E9C2808930ULL,
		0x4B0F312B3858CDC5ULL,
		0x24723127C80663BFULL,
		0x6781282C3026F34BULL,
		0xE18E86A193D73ADDULL,
		0x6BA5DE2808DDC34EULL,
		0xCB3C10568C74AF61ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x239E8D46F4459F93ULL,
		0xD92DD201D90122A7ULL,
		0xCB4429E7808B5283ULL,
		0x236CAAB084F8133AULL,
		0x56A28A6CA5CFC74BULL,
		0xCA876D8393A39515ULL,
		0x7BDEDE8A4921CB8DULL,
		0xE5FD3F64A238C8EBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CE410FC8E26EEB5ULL,
		0x2AB1E28594E7E885ULL,
		0x36F56E9609F47569ULL,
		0xBE3C21400E06F4D0ULL,
		0xE1ED2AC702AC9992ULL,
		0xB231D5183EC3D17BULL,
		0x120B6BC9CDF1ACFEULL,
		0x19B44AC09FE877D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6BA7C4A661EB0DEULL,
		0xAE7BEF7C44193A21ULL,
		0x944EBB517696DD1AULL,
		0x6530897076F11E6AULL,
		0x74B55FA5A3232DB8ULL,
		0x1855986B54DFC399ULL,
		0x69D372C07B301E8FULL,
		0xCC48F4A402505116ULL
	}};
	sign = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD223E4150B7B5716ULL,
		0x04E081BAF81AA6F8ULL,
		0x520C11865F218715ULL,
		0x7444A656BA4335FEULL,
		0xE67FD1754ACE84E9ULL,
		0x124B73FADB37B86CULL,
		0x6252F4752E5CCD03ULL,
		0x12018B233E2E8E08ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7366CB741347F945ULL,
		0x99497A4D76B6D043ULL,
		0x86BC4BE8756D63CEULL,
		0xDFE75150700B35EDULL,
		0x0ADDEF7B776CF809ULL,
		0x191E6913425541D1ULL,
		0x8792732C8EB3FF63ULL,
		0xFBB6E7EC3AD2E160ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EBD18A0F8335DD1ULL,
		0x6B97076D8163D6B5ULL,
		0xCB4FC59DE9B42346ULL,
		0x945D55064A380010ULL,
		0xDBA1E1F9D3618CDFULL,
		0xF92D0AE798E2769BULL,
		0xDAC081489FA8CD9FULL,
		0x164AA337035BACA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6947D9C872B42FBDULL,
		0xEB083BD0C2E860B0ULL,
		0x74D71F8A6E83F46BULL,
		0x9998C2B19CF3E91AULL,
		0x45E22551220117F3ULL,
		0x31844525EF2D57F4ULL,
		0xAD063E4D44338B69ULL,
		0x8F7DD0BA3389099AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F0778A4784D612AULL,
		0x6BBE0636BDCAA079ULL,
		0xEC249F964D5CA989ULL,
		0xBF32228C626E6231ULL,
		0xEC1E2BC700706C6BULL,
		0xE245483590B3C624ULL,
		0x6BDD65C07B8C3EA1ULL,
		0xD28461BE5F8BA2B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A406123FA66CE93ULL,
		0x7F4A359A051DC037ULL,
		0x88B27FF421274AE2ULL,
		0xDA66A0253A8586E8ULL,
		0x59C3F98A2190AB87ULL,
		0x4F3EFCF05E7991CFULL,
		0x4128D88CC8A74CC7ULL,
		0xBCF96EFBD3FD66E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0DEFBA29038E8CF0ULL,
		0xC6943DDFD1242FC3ULL,
		0xEC04DF21CF45417EULL,
		0x051013020A1D249AULL,
		0x024A084FA7BB46C3ULL,
		0xB7CAE2AEB9C336CDULL,
		0x3A05F0A68C9005CBULL,
		0x4A9C429F384B585EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x808DBFBB56E2F081ULL,
		0xD06CEDD5E4975718ULL,
		0x40B51D8D61D0D8E7ULL,
		0x0A8CA4B69EA9C7C5ULL,
		0x1104E54C7C3F0362ULL,
		0x5E92D7B9F393683DULL,
		0x5413140E041E0956ULL,
		0x769D549BCEA42002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D61FA6DACAB9C6FULL,
		0xF6275009EC8CD8AAULL,
		0xAB4FC1946D746896ULL,
		0xFA836E4B6B735CD5ULL,
		0xF14523032B7C4360ULL,
		0x59380AF4C62FCE8FULL,
		0xE5F2DC988871FC75ULL,
		0xD3FEEE0369A7385BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C937C03D6E8845DULL,
		0x4FD23C4EBC565710ULL,
		0x8737D2C3A2B2B04CULL,
		0x1B948DB6FBB98F4DULL,
		0x5F073389ED320328ULL,
		0x5378E2645B226069ULL,
		0x3C414861A05C65BCULL,
		0x0BA05F7773697A43ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7793AF30EEF23629ULL,
		0x217509FA94EAAE4DULL,
		0xE7FF64A5DD24A454ULL,
		0x4BFD0EB2F0C07F8AULL,
		0xA9CF278A5AFD1693ULL,
		0x9C209C41AFD54B5AULL,
		0x091DF129E87CF273ULL,
		0xA98A8B8CBEDB9EC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4FFCCD2E7F64E34ULL,
		0x2E5D3254276BA8C2ULL,
		0x9F386E1DC58E0BF8ULL,
		0xCF977F040AF90FC2ULL,
		0xB5380BFF9234EC94ULL,
		0xB7584622AB4D150EULL,
		0x33235737B7DF7348ULL,
		0x6215D3EAB48DDB80ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA076B9F105910266ULL,
		0x5DBBC4C4EA74091DULL,
		0xD24BA9222D37C8D4ULL,
		0xF46CBA7BB1C573ABULL,
		0x80ADEBB6ACDC9521ULL,
		0x31F92D6C4B4FB735ULL,
		0x236EF9D87BEE3FDEULL,
		0x17223642408A444EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x069AD75793243015ULL,
		0x2416BF8FD0A6DD2CULL,
		0x330506A1AF22B864ULL,
		0xD45F69ECC9FB0415ULL,
		0x66DF0A0F068D7922ULL,
		0xC6DC25142A091A80ULL,
		0xBDE7EF89F157DEAAULL,
		0x7817CC7EC09A38AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99DBE299726CD251ULL,
		0x39A5053519CD2BF1ULL,
		0x9F46A2807E151070ULL,
		0x200D508EE7CA6F96ULL,
		0x19CEE1A7A64F1BFFULL,
		0x6B1D085821469CB5ULL,
		0x65870A4E8A966133ULL,
		0x9F0A69C37FF00BA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x08C9F02BB0E21CABULL,
		0xAEAC7FF1C0679DA8ULL,
		0x928E14D740B947E5ULL,
		0x0AA2D8BDE7CFF6BAULL,
		0x53BFB9DF836D4479ULL,
		0xF84C53129F4A0B68ULL,
		0x7EFF745E769E8266ULL,
		0x0B1F6628B9C3AB11ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1783F1C66621BE20ULL,
		0x6839FD77BA99E0E9ULL,
		0x3F560CCD206C688DULL,
		0xA9DC6E4D5205DE4AULL,
		0xDFE709BE91019542ULL,
		0xFF3E8400FA16EA68ULL,
		0xB6474ED34C7044CAULL,
		0x83CA68DF8A748D2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF145FE654AC05E8BULL,
		0x4672827A05CDBCBEULL,
		0x5338080A204CDF58ULL,
		0x60C66A7095CA1870ULL,
		0x73D8B020F26BAF36ULL,
		0xF90DCF11A53320FFULL,
		0xC8B8258B2A2E3D9BULL,
		0x8754FD492F4F1DE3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5E6B7DBC339CD3C8ULL,
		0xAB09A845D0D68396ULL,
		0xCBC9D351FA5E025DULL,
		0x5E4B18BE0B11ABA4ULL,
		0xBA1C447969188BD8ULL,
		0x02132D5404A3ABF1ULL,
		0x4134DACAC6DF895EULL,
		0x11DBB26690B7F1B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1363D57C973B1AFFULL,
		0x0C76373B448665F0ULL,
		0x5059A94781E32531ULL,
		0xADFD010CEA0FF878ULL,
		0x01918FE088AAF3D0ULL,
		0xE3D941B96CC50695ULL,
		0x7B983AC3046AA7B9ULL,
		0x9A29E2F3D099F28EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B07A83F9C61B8C9ULL,
		0x9E93710A8C501DA6ULL,
		0x7B702A0A787ADD2CULL,
		0xB04E17B12101B32CULL,
		0xB88AB498E06D9807ULL,
		0x1E39EB9A97DEA55CULL,
		0xC59CA007C274E1A4ULL,
		0x77B1CF72C01DFF29ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1D3B1D88FF98A56ULL,
		0x6C3E373764265C97ULL,
		0x0124C3DF4DF50141ULL,
		0xB354239791CFFDF9ULL,
		0x70877DCA964C6462ULL,
		0xED8AC570B2BC4CD7ULL,
		0x9F52E529BABFEC61ULL,
		0x319B807955DAB1B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4863A92B413E61ULL,
		0x8002D868C2E79B0AULL,
		0x9ADD5D3DBBF14D02ULL,
		0x3ECC459F0FE2204AULL,
		0xA22AF20F8C17285AULL,
		0x649D1EBA66CBC174ULL,
		0xED30FA76BE733446ULL,
		0xAD100801745C704EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA38B4E2F64B84BF5ULL,
		0xEC3B5ECEA13EC18DULL,
		0x664766A19203B43EULL,
		0x7487DDF881EDDDAEULL,
		0xCE5C8BBB0A353C08ULL,
		0x88EDA6B64BF08B62ULL,
		0xB221EAB2FC4CB81BULL,
		0x848B7877E17E4166ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8CB334DD5B25E535ULL,
		0x690C25B229F0A1BEULL,
		0xC6ABB5136EE22E21ULL,
		0x933469778CAD24B5ULL,
		0x443B6C6664DEB055ULL,
		0xB12FADC654302937ULL,
		0x1909EC6FFFAED46AULL,
		0xB1C518826F145893ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x937C1A604116AB4AULL,
		0x15EC66C39D1C6F26ULL,
		0xE5F6E803141F0CFDULL,
		0x807C3E4379BFE362ULL,
		0x1F1BF50CDA8E1779ULL,
		0x9AF052EDF75CAB01ULL,
		0xA1B4E352740769A2ULL,
		0x4221C74C1A3FD0B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9371A7D1A0F39EBULL,
		0x531FBEEE8CD43297ULL,
		0xE0B4CD105AC32124ULL,
		0x12B82B3412ED4152ULL,
		0x251F77598A5098DCULL,
		0x163F5AD85CD37E36ULL,
		0x7755091D8BA76AC8ULL,
		0x6FA3513654D487DEULL
	}};
	sign = 0;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBB5F41E6513FAB5BULL,
		0xF3F82801AE116EAEULL,
		0xD031E32DAE68B517ULL,
		0x33EAACF895271A72ULL,
		0x3A7AE6627A18EDEEULL,
		0x0776F9E860A21ACFULL,
		0x3484FCF112EF1299ULL,
		0x263494C357E70233ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE38436544B0B0B81ULL,
		0x4490D72FEAF055FCULL,
		0x3F6757BFE7CD9C62ULL,
		0x00C0AEC4559F2946ULL,
		0x0C4D3E075F145E4CULL,
		0x3D596D4D678D886CULL,
		0xCD20A3A5C503E214ULL,
		0x49347149F5DC86C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7DB0B9206349FDAULL,
		0xAF6750D1C32118B1ULL,
		0x90CA8B6DC69B18B5ULL,
		0x3329FE343F87F12CULL,
		0x2E2DA85B1B048FA2ULL,
		0xCA1D8C9AF9149263ULL,
		0x6764594B4DEB3084ULL,
		0xDD002379620A7B71ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30AEAEA010736D58ULL,
		0x61E8B7A5209B9C22ULL,
		0x7C5FC3B868238A61ULL,
		0x8A3EF91505298896ULL,
		0x17E2DF3EBDA43F97ULL,
		0x4BEB5CEEF684EC5FULL,
		0xEBA94A9816B96C80ULL,
		0xA9C060686D158A78ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x141C8A49023DDEB3ULL,
		0x6E51DE2DDAEDCA9EULL,
		0xEBC9F683EF891A07ULL,
		0x41F23FE5783096A2ULL,
		0x6D9B4C9BA1C310E8ULL,
		0xEB5E22CC10286F74ULL,
		0x42A45A0BF1D8DB2BULL,
		0xEE687ED42B76D05DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C9224570E358EA5ULL,
		0xF396D97745ADD184ULL,
		0x9095CD34789A7059ULL,
		0x484CB92F8CF8F1F3ULL,
		0xAA4792A31BE12EAFULL,
		0x608D3A22E65C7CEAULL,
		0xA904F08C24E09154ULL,
		0xBB57E194419EBA1BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55362D68A61B63ACULL,
		0xB43D3E946AC1D65FULL,
		0x484701CDF78761C4ULL,
		0x4008E711FC0BD6FAULL,
		0x3F3B277234F45620ULL,
		0xB77257380506265BULL,
		0x8676615634DAF5E5ULL,
		0x7CE2CC82B0D51DDFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFEB192CFABE08BAULL,
		0xA7D1F330459CB905ULL,
		0xA996AE00109F5C90ULL,
		0x42BA0649BD51D15CULL,
		0xF90B79F33D21AEADULL,
		0x0CE308077A1046F3ULL,
		0xA7D27EB54DF90E6CULL,
		0xEA01D6E854D76939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x554B143BAB5D5AF2ULL,
		0x0C6B4B6425251D59ULL,
		0x9EB053CDE6E80534ULL,
		0xFD4EE0C83EBA059DULL,
		0x462FAD7EF7D2A772ULL,
		0xAA8F4F308AF5DF67ULL,
		0xDEA3E2A0E6E1E779ULL,
		0x92E0F59A5BFDB4A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCAFA74053D3E4ACAULL,
		0x0FE164090C732D24ULL,
		0x90FB3BE27967E02EULL,
		0x4A3645205B6A1C19ULL,
		0x6796C5469D7E670DULL,
		0x7DFF474DE30E4191ULL,
		0x6378E330671158A0ULL,
		0x2CF35825F9170C67ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5080A5A1B6BFE3DULL,
		0xF3F0B7F697470BE0ULL,
		0x7444B02E4C01FFA3ULL,
		0x224781D72843FCC5ULL,
		0x716EA1C6C6FF462DULL,
		0x7BEAD9F41E6F8A8CULL,
		0xA8C75440AFC34B5BULL,
		0x61EB3C3477A983E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15F269AB21D24C8DULL,
		0x1BF0AC12752C2144ULL,
		0x1CB68BB42D65E08AULL,
		0x27EEC34933261F54ULL,
		0xF628237FD67F20E0ULL,
		0x02146D59C49EB704ULL,
		0xBAB18EEFB74E0D45ULL,
		0xCB081BF1816D8881ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x353ECA7F0FC448C4ULL,
		0x286ED5CF4B16FCB2ULL,
		0x211A2239DCDAB38AULL,
		0x9ECAC063D12327E6ULL,
		0x645C2FB61E099077ULL,
		0x8D1DBF00C230C7DAULL,
		0x2D68B708E12D045EULL,
		0xCC06EDBEB0C2FA0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B0F60243778E78ULL,
		0x085597A7A71E67FDULL,
		0x07734B904D6054AFULL,
		0x60832C76B9FF2FFBULL,
		0xB8380A22B73F55F3ULL,
		0xA5F3A1F38C7DA297ULL,
		0xD6B29029AB3AE372ULL,
		0x36F706A94F45B20DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x838DD47CCC4CBA4CULL,
		0x20193E27A3F894B4ULL,
		0x19A6D6A98F7A5EDBULL,
		0x3E4793ED1723F7EBULL,
		0xAC24259366CA3A84ULL,
		0xE72A1D0D35B32542ULL,
		0x56B626DF35F220EBULL,
		0x950FE715617D4800ULL
	}};
	sign = 0;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9021B99BE1E21A80ULL,
		0xD68830581C43DEACULL,
		0x7221C2CACE2DBD07ULL,
		0x4E0B3D87D31C50A3ULL,
		0x9321B6AF9A511479ULL,
		0x2AA1A278099DC10BULL,
		0x2064EBEAEB44625DULL,
		0xB0A99C862C941A86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x119BA9B6CA28693EULL,
		0xAF91FAFB53B416BBULL,
		0x92BD4992D2DE0924ULL,
		0x878BC33DAE5E451AULL,
		0x5B6DA8750048B8E7ULL,
		0xCB5B79B94F0075B6ULL,
		0x77203613BCC2AF72ULL,
		0xFBE1E726393BBAA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E860FE517B9B142ULL,
		0x26F6355CC88FC7F1ULL,
		0xDF647937FB4FB3E3ULL,
		0xC67F7A4A24BE0B88ULL,
		0x37B40E3A9A085B91ULL,
		0x5F4628BEBA9D4B55ULL,
		0xA944B5D72E81B2EAULL,
		0xB4C7B55FF3585FE0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x65199E0DAA78EA6FULL,
		0xC49DAF95086A2F25ULL,
		0x1204E4D6DAEF9366ULL,
		0x2F859EDF828B32CEULL,
		0x4AD139E3734DD4E1ULL,
		0x7386E72588A57877ULL,
		0x1AACD7A286C16AA0ULL,
		0xDCEFCC3E98F8D528ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B1F34DA6B5454DULL,
		0x25F304979FB6D3C4ULL,
		0xFE7064C4D3A0AD4FULL,
		0xDE29D8D4F9E98728ULL,
		0x9ED6BFE895527A80ULL,
		0x3623CDB8FE955C30ULL,
		0x6D6A7B6C1199926AULL,
		0x23F0C204C4080ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC67AAC003C3A522ULL,
		0x9EAAAAFD68B35B60ULL,
		0x13948012074EE617ULL,
		0x515BC60A88A1ABA5ULL,
		0xABFA79FADDFB5A60ULL,
		0x3D63196C8A101C46ULL,
		0xAD425C367527D836ULL,
		0xB8FF0A39D4F0CA58ULL
	}};
	sign = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC2509FB4C4B856D0ULL,
		0x8B1BB1E4EE2FBDF4ULL,
		0x15078749C9691659ULL,
		0x44F887D99F442FE7ULL,
		0xE6482D1CC467C890ULL,
		0x78C507CA00AF4CD3ULL,
		0x57D37E275C7E4247ULL,
		0xE8262F94A1678B23ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BFE7885D5244952ULL,
		0xC76409A6C6EB690AULL,
		0xEF4AE8EE2FC23CB0ULL,
		0x677672E39C0077FCULL,
		0xAD2F1EFE6F93D236ULL,
		0x46AA0FE46337AD7BULL,
		0xB54020E86A9CDF06ULL,
		0x0D85D433886A5CCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4652272EEF940D7EULL,
		0xC3B7A83E274454EAULL,
		0x25BC9E5B99A6D9A8ULL,
		0xDD8214F60343B7EAULL,
		0x39190E1E54D3F659ULL,
		0x321AF7E59D779F58ULL,
		0xA2935D3EF1E16341ULL,
		0xDAA05B6118FD2E53ULL
	}};
	sign = 0;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB9FC5CD51940514ULL,
		0xF4201A59F35699F6ULL,
		0x70EB6413FB597D1CULL,
		0xDD4A28C787618375ULL,
		0x95B1890036FFE667ULL,
		0xA40C8989405D1CB4ULL,
		0xF71F708D79DD7254ULL,
		0x5A7FB7D041D78851ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x67427173D38C540CULL,
		0xAB2CEFF06993F65DULL,
		0xBD9C4848F9EC6A12ULL,
		0xBCDDCC0E8390E36AULL,
		0x73BBA02743E699EAULL,
		0xB050B651622A6CCFULL,
		0x664ACDEE22A5473BULL,
		0x687A74118F6FB71FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x845D54597E07B108ULL,
		0x48F32A6989C2A399ULL,
		0xB34F1BCB016D130AULL,
		0x206C5CB903D0A00AULL,
		0x21F5E8D8F3194C7DULL,
		0xF3BBD337DE32AFE5ULL,
		0x90D4A29F57382B18ULL,
		0xF20543BEB267D132ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7AD128CBE9E968ECULL,
		0xEF87115BDC9129C8ULL,
		0xEE868B24E756ABD6ULL,
		0x7B7B6C7E1B6C0215ULL,
		0xD104F5E90695B331ULL,
		0x27A2283221A0CE77ULL,
		0x2D13787A7958D837ULL,
		0x43A819F8919DBF21ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0349254663153D7ULL,
		0x704B9B178604109EULL,
		0x25766C74EC0E5DCEULL,
		0x49CEB1D86617AAB4ULL,
		0x030D7B75F95484D2ULL,
		0x083DCB0129B42ED2ULL,
		0xC5BAF5220A41185FULL,
		0x85C2C2B5EE499760ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA9C967783B81515ULL,
		0x7F3B7644568D1929ULL,
		0xC9101EAFFB484E08ULL,
		0x31ACBAA5B5545761ULL,
		0xCDF77A730D412E5FULL,
		0x1F645D30F7EC9FA5ULL,
		0x675883586F17BFD8ULL,
		0xBDE55742A35427C0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55B437F6D78B3C01ULL,
		0xAE4EC5D5257B3962ULL,
		0x444BE58B7BC0811EULL,
		0x990FF8E87103B85FULL,
		0xDED9C2D06030A38EULL,
		0xE24B02C87A21D0EFULL,
		0xABBB526B98513DD2ULL,
		0x9F04BC41CC89914FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDC574ACCFF4251DULL,
		0x69F63FB46ADB296EULL,
		0x36A5F7AF8188B1F1ULL,
		0x0D156502C136426DULL,
		0x6DCDF7FFE82E8E88ULL,
		0x04DC30EF726DA320ULL,
		0x72B891B8D3D5E758ULL,
		0x20782636BF37B29BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77EEC34A079716E4ULL,
		0x44588620BAA00FF3ULL,
		0x0DA5EDDBFA37CF2DULL,
		0x8BFA93E5AFCD75F2ULL,
		0x710BCAD078021506ULL,
		0xDD6ED1D907B42DCFULL,
		0x3902C0B2C47B567AULL,
		0x7E8C960B0D51DEB4ULL
	}};
	sign = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x633199B45B729F72ULL,
		0x6F4DEAECD19F4EAFULL,
		0xB96FD8522023CBDBULL,
		0x9620A75D67B2A865ULL,
		0x658F26266DE063A8ULL,
		0xAD14965EDC4D6721ULL,
		0x1649256792A2DE24ULL,
		0x317B6DC3C264A01EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA79116C51C0D8E7ULL,
		0x6E73F7551DCE9DC5ULL,
		0x6A9CBA0E75A19ED0ULL,
		0x773EA94144C4E328ULL,
		0x51268E12381A761EULL,
		0xD895BA6B3EC59B0CULL,
		0xFABD619B0C3A6CA4ULL,
		0xC08DFF0AC16C3826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78B8884809B1C68BULL,
		0x00D9F397B3D0B0E9ULL,
		0x4ED31E43AA822D0BULL,
		0x1EE1FE1C22EDC53DULL,
		0x1468981435C5ED8AULL,
		0xD47EDBF39D87CC15ULL,
		0x1B8BC3CC8668717FULL,
		0x70ED6EB900F867F7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9CD65A3CE2783B7ULL,
		0xBE8CB0FD6619DDF7ULL,
		0xCC092A22F876F401ULL,
		0x75CD4D4D9A0CA090ULL,
		0x02FD95DF67012AABULL,
		0x64DF2B7B2608B6D5ULL,
		0x44B55D6AF01FA972ULL,
		0x6A7520D84D31219AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7774613BD0755FC7ULL,
		0x0F643DB320327754ULL,
		0x2030695DF8A1E9E8ULL,
		0xF980DD256758D06AULL,
		0xF010D3971B3F7ADCULL,
		0x5169A618F4D9ED47ULL,
		0x202B0113DA045EFCULL,
		0x3E17911B7A0171F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62590467FDB223F0ULL,
		0xAF28734A45E766A3ULL,
		0xABD8C0C4FFD50A19ULL,
		0x7C4C702832B3D026ULL,
		0x12ECC2484BC1AFCEULL,
		0x13758562312EC98DULL,
		0x248A5C57161B4A76ULL,
		0x2C5D8FBCD32FAFA7ULL
	}};
	sign = 0;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x96FF0B0AC470B10BULL,
		0x725B6DA7D00B25F2ULL,
		0xECC00AB1F3715547ULL,
		0x2F6B1971F279012FULL,
		0x72F6B0FD183022D4ULL,
		0xFDDCC72D6DFE1E46ULL,
		0x1B971DAEC510DA16ULL,
		0x756B8230C148F741ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76C726AC2CBBD53DULL,
		0xEE76230DE96F6F4AULL,
		0x582A723281D37512ULL,
		0x1E254E55C6470D13ULL,
		0x18C08C721573DC20ULL,
		0x34063CC0AED19337ULL,
		0x648218F028FA4D9BULL,
		0x014FD5D5291B7430ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2037E45E97B4DBCEULL,
		0x83E54A99E69BB6A8ULL,
		0x9495987F719DE034ULL,
		0x1145CB1C2C31F41CULL,
		0x5A36248B02BC46B4ULL,
		0xC9D68A6CBF2C8B0FULL,
		0xB71504BE9C168C7BULL,
		0x741BAC5B982D8310ULL
	}};
	sign = 0;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4B15C43A38A9573FULL,
		0xF080A2592EB4DD0FULL,
		0xE32BF3E81A795393ULL,
		0x0A897AFE8D69DA57ULL,
		0x28406EF86E464325ULL,
		0x7D6A9BE568D2A137ULL,
		0xEB7FD3DD14BFB196ULL,
		0x3AFE9AE6A74ECC16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6DC4612B7950FBULL,
		0x212BD1DDDFAC766AULL,
		0x9DF071E84DD2029FULL,
		0x27CB6439BEE5D93FULL,
		0xDC7ECC90B4948BDEULL,
		0xEBF58AFDF951542AULL,
		0xDCE3B1B8D17819AAULL,
		0x45AC3EED8C5C9155ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFA7FFD90D300644ULL,
		0xCF54D07B4F0866A4ULL,
		0x453B81FFCCA750F4ULL,
		0xE2BE16C4CE840118ULL,
		0x4BC1A267B9B1B746ULL,
		0x917510E76F814D0CULL,
		0x0E9C2224434797EBULL,
		0xF5525BF91AF23AC1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C9A4C317E916524ULL,
		0x090BE6ACBFC9562CULL,
		0xC07336CA828897F1ULL,
		0x8EB2092FC3F9A512ULL,
		0x12252EA567308439ULL,
		0xE016EA2B47D3D9B9ULL,
		0x76AB344F56C665A5ULL,
		0x53DFB114F8749E23ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x096200E4B857BE13ULL,
		0x5EA88C60177D9A3DULL,
		0x0F41AD44EF805679ULL,
		0xE532F7F47FDA9287ULL,
		0xBC5C030DC47A19E0ULL,
		0x7AB45D57946645A9ULL,
		0x4473DFA93C765E64ULL,
		0x903A0501F1260DBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93384B4CC639A711ULL,
		0xAA635A4CA84BBBEFULL,
		0xB131898593084177ULL,
		0xA97F113B441F128BULL,
		0x55C92B97A2B66A58ULL,
		0x65628CD3B36D940FULL,
		0x323754A61A500741ULL,
		0xC3A5AC13074E9068ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4840503331722BB3ULL,
		0x64BA5E7355DD21CDULL,
		0x865E1F97E9699CE0ULL,
		0x81B62A6F83AAF184ULL,
		0x2EFE7C472931C163ULL,
		0x5CC0FBCF4BB8B920ULL,
		0xF613150A5568E09AULL,
		0xD3FDF4C95C53EED1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA146B68BF5ED50ULL,
		0x607BA9E9446DD88AULL,
		0xDE395F68E317F7C4ULL,
		0x9540BB9B2BED4368ULL,
		0x085FA5433B1F6311ULL,
		0x99B958DDFF717E9FULL,
		0x8472AA291D53CD28ULL,
		0xE84AD305A4EBEA75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD99F097CA57C3E63ULL,
		0x043EB48A116F4942ULL,
		0xA824C02F0651A51CULL,
		0xEC756ED457BDAE1BULL,
		0x269ED703EE125E51ULL,
		0xC307A2F14C473A81ULL,
		0x71A06AE138151371ULL,
		0xEBB321C3B768045CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC9BEB0B57C825ABEULL,
		0xAEEAD0BDA4AF0C34ULL,
		0x1AA0CB2974394034ULL,
		0x2CC655EB107996E8ULL,
		0xDDC5A1F535905F3FULL,
		0x905A114C363FCB0AULL,
		0x6DF2CB06919B3F1BULL,
		0x892850110AE433D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E009D3CB5630CFULL,
		0x859466D25C0A43D7ULL,
		0x2961608C848DB3FCULL,
		0x8B0D1AA14C1661EDULL,
		0x4A7C4C83AC163936ULL,
		0xC52F80669AB1EE2BULL,
		0xE0D71066416655A2ULL,
		0x76CE8D4FDCE6E52EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2DEA6E1B12C29EFULL,
		0x295669EB48A4C85CULL,
		0xF13F6A9CEFAB8C38ULL,
		0xA1B93B49C46334FAULL,
		0x93495571897A2608ULL,
		0xCB2A90E59B8DDCDFULL,
		0x8D1BBAA05034E978ULL,
		0x1259C2C12DFD4EA7ULL
	}};
	sign = 0;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF28A38EDD8D0AFFFULL,
		0x37EF482A4A548DC0ULL,
		0xBA92293529A2831CULL,
		0x49F721C13130D165ULL,
		0x778BA4C193766B9FULL,
		0xA0B07CD8944B6149ULL,
		0xB9FAE9E966630AC0ULL,
		0x27AAA2D1E51231F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x095162FB6EB4ECE0ULL,
		0x35824A324F44E4BDULL,
		0xD1729DEC5EA8F244ULL,
		0xF72CB242428FB637ULL,
		0xE082F8E48484B275ULL,
		0x97C8BD2319203340ULL,
		0x3612ED128189666FULL,
		0x4342433DB98CF1DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE938D5F26A1BC31FULL,
		0x026CFDF7FB0FA903ULL,
		0xE91F8B48CAF990D8ULL,
		0x52CA6F7EEEA11B2DULL,
		0x9708ABDD0EF1B929ULL,
		0x08E7BFB57B2B2E08ULL,
		0x83E7FCD6E4D9A451ULL,
		0xE4685F942B854017ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD3E020F57E6C5230ULL,
		0x3BDE46B4F457AFE0ULL,
		0xA36D736C3B54BD73ULL,
		0x5F526CECA1BDAD1FULL,
		0x2AF7F2457CDB1ABAULL,
		0x54F294C67CB1417AULL,
		0x056CAC98A740B4EFULL,
		0x8CB8F998115979B1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6961C29B09034096ULL,
		0x0742240C2473F1AFULL,
		0x057F8D5A15DB2F09ULL,
		0x769DEBD3B6E6961BULL,
		0x4DE0C277111DF921ULL,
		0x7B1F340CCA0355D6ULL,
		0x35DA266271C12A42ULL,
		0xD653A188138F7CCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A7E5E5A7569119AULL,
		0x349C22A8CFE3BE31ULL,
		0x9DEDE61225798E6AULL,
		0xE8B48118EAD71704ULL,
		0xDD172FCE6BBD2198ULL,
		0xD9D360B9B2ADEBA3ULL,
		0xCF928636357F8AACULL,
		0xB665580FFDC9FCE1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6E63134B3F51D99EULL,
		0x200DCBD577A015FAULL,
		0xB0568BB501979B63ULL,
		0x8756F983CDBBFD6CULL,
		0xB5F699CBD4E1DF33ULL,
		0x060C99F1388B8944ULL,
		0x41D0F05FCD6FCE2DULL,
		0xECB235DC645791CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x15AC097ADD007D8EULL,
		0x6F85E0CF25D09431ULL,
		0x53ECF0049B33FA46ULL,
		0xBFE39A2888AF33F6ULL,
		0x2DD7F7C17287F133ULL,
		0xD8EBC7187E4FF445ULL,
		0xC0F9F82AFD4011ABULL,
		0x4244606362F00871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58B709D062515C10ULL,
		0xB087EB0651CF81C9ULL,
		0x5C699BB06663A11CULL,
		0xC7735F5B450CC976ULL,
		0x881EA20A6259EDFFULL,
		0x2D20D2D8BA3B94FFULL,
		0x80D6F834D02FBC81ULL,
		0xAA6DD5790167895BULL
	}};
	sign = 0;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30D9705BFF70FD62ULL,
		0x3F4C9F74FDE4912AULL,
		0xC4FF8A4ACB48EB1CULL,
		0x78B92626BAD7E340ULL,
		0x89BD66143C5B328AULL,
		0x338F52B9D66FB043ULL,
		0xD17C17558B784BE7ULL,
		0xADF7E7185B903435ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0875186FC977EE0DULL,
		0x0439DC79568C4CF7ULL,
		0x032FC9B673F33AA8ULL,
		0x4C309F6005D412E2ULL,
		0x92A285235CD2F8FEULL,
		0x7D27D11B174EB923ULL,
		0x8543AB5B7D2A0129ULL,
		0x192DC0BC6240ADCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x286457EC35F90F55ULL,
		0x3B12C2FBA7584433ULL,
		0xC1CFC0945755B074ULL,
		0x2C8886C6B503D05EULL,
		0xF71AE0F0DF88398CULL,
		0xB667819EBF20F71FULL,
		0x4C386BFA0E4E4ABDULL,
		0x94CA265BF94F8668ULL
	}};
	sign = 0;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x50673FA3A3EB0891ULL,
		0x8CBE2D7DB3D00A59ULL,
		0x6B5B9C0CBD7FEA73ULL,
		0x2A11346532BFFAF2ULL,
		0xA1B6AC7ADA42DFDEULL,
		0xB28A7B5E468B0637ULL,
		0xA22B5FC1AB4C5B1FULL,
		0xEFE0286E39B3E73FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C303927AB5CD9CULL,
		0xFC9CB8939E84B8B3ULL,
		0x712A9609553F3854ULL,
		0xD67CB9E61F02FE9CULL,
		0x861C119602C71DFDULL,
		0xC9E3E3345F1B79E7ULL,
		0x2525F868053CFC6BULL,
		0xA2109C4ECD49BD64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DA43C1129353AF5ULL,
		0x902174EA154B51A5ULL,
		0xFA3106036840B21EULL,
		0x53947A7F13BCFC55ULL,
		0x1B9A9AE4D77BC1E0ULL,
		0xE8A69829E76F8C50ULL,
		0x7D056759A60F5EB3ULL,
		0x4DCF8C1F6C6A29DBULL
	}};
	sign = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x988C79C0F3F3A5C5ULL,
		0x66BF159859A03262ULL,
		0x2BFE0526F18A9057ULL,
		0x75F2648F8972F022ULL,
		0x42FDB7D3116E21D5ULL,
		0x9FBF811C252DF407ULL,
		0xB01F690E82840168ULL,
		0x8C124B57416BAA4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x293FB9719B3821D8ULL,
		0x620DB87087D22E61ULL,
		0xE79AC5693CFB7ADFULL,
		0x50164DBE251D4A51ULL,
		0xFA88591ADDA899D5ULL,
		0x4196C6F99FB546C5ULL,
		0xDA7AC40B898DCF9EULL,
		0x7C631376C6FAF8DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F4CC04F58BB83EDULL,
		0x04B15D27D1CE0401ULL,
		0x44633FBDB48F1578ULL,
		0x25DC16D16455A5D0ULL,
		0x48755EB833C58800ULL,
		0x5E28BA228578AD41ULL,
		0xD5A4A502F8F631CAULL,
		0x0FAF37E07A70B16FULL
	}};
	sign = 0;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE250A12BA46045AULL,
		0xD8D0D8D80F3C4C81ULL,
		0x9BE1E22542942659ULL,
		0x0CAE3A461E667335ULL,
		0x74572F274FBDC578ULL,
		0xC2826B257AF485E0ULL,
		0x33806F8BCA1DB781ULL,
		0x24D63F343DAEFABBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88DD47CF6A3395B6ULL,
		0x7B5BFA8A238FD18CULL,
		0xE49546C27A150406ULL,
		0x321BCB26AD02DAB5ULL,
		0xF0E1F666961F6AE9ULL,
		0x3400C73C494BCA58ULL,
		0xFD93B7F2D185920DULL,
		0x01550574F8FDAB0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5547C24350126EA4ULL,
		0x5D74DE4DEBAC7AF5ULL,
		0xB74C9B62C87F2253ULL,
		0xDA926F1F7163987FULL,
		0x837538C0B99E5A8EULL,
		0x8E81A3E931A8BB87ULL,
		0x35ECB798F8982574ULL,
		0x238139BF44B14FADULL
	}};
	sign = 0;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE79E922D984BCDAULL,
		0x5B51D516AAFCE245ULL,
		0x02C8A9E100D3DFA5ULL,
		0xA881E26EF5F79C03ULL,
		0x86E5D22BE2E01CB7ULL,
		0xEB60F0723A063403ULL,
		0xDB16B02B00E22D7FULL,
		0x17D4BFDC5F980F34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5679FFFDE91961FULL,
		0x99D183DED5BA7D8CULL,
		0xC180573AE9A1CA65ULL,
		0xE570342B8425E144ULL,
		0x2515C2377DDA83E4ULL,
		0x60FA6AE26C649872ULL,
		0x45BECD25E76B2493ULL,
		0x90F1EC416F83CABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9124922FAF326BBULL,
		0xC1805137D54264B8ULL,
		0x414852A61732153FULL,
		0xC311AE4371D1BABEULL,
		0x61D00FF4650598D2ULL,
		0x8A66858FCDA19B91ULL,
		0x9557E305197708ECULL,
		0x86E2D39AF014447AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x94687DB9F968503CULL,
		0xDC68AAEB7F59920EULL,
		0xBFC5352D00C66D90ULL,
		0x72C520B45E2A28AFULL,
		0xB1C25D8A8B26D559ULL,
		0x3536C2C710F7931DULL,
		0x5009D3BBE8002A2AULL,
		0x58EE10326393152BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x922472D85F66A58AULL,
		0xB7EFDDECAFD57052ULL,
		0x3B9EFFCFE74A2015ULL,
		0xC87AA4E591E0865EULL,
		0xF9171F9BF3229B0AULL,
		0xAB217C4B21912E2DULL,
		0xD4C30A1251FF2459ULL,
		0x86150D7ABFA94AAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02440AE19A01AAB2ULL,
		0x2478CCFECF8421BCULL,
		0x8426355D197C4D7BULL,
		0xAA4A7BCECC49A251ULL,
		0xB8AB3DEE98043A4EULL,
		0x8A15467BEF6664EFULL,
		0x7B46C9A9960105D0ULL,
		0xD2D902B7A3E9CA7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDBCB1BCF7466CCF9ULL,
		0x24AF41885C2977A0ULL,
		0x4C1ADB2342E4E9BDULL,
		0x59901D0BBE699453ULL,
		0x3962A2481B6C76E1ULL,
		0x80B7E0B6565F062FULL,
		0xAF01868CF5F7365EULL,
		0x742641CEFDB21837ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2049A0835728F2BULL,
		0x1BCC9D58CE218FD9ULL,
		0x93F6B4E71DC44A7DULL,
		0x4F559BFAA2879905ULL,
		0x68EB8576A580D7E0ULL,
		0x38BCA825092A1216ULL,
		0x0A072C45131DDB1FULL,
		0x90FF23730325508CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39C681C73EF43DCEULL,
		0x08E2A42F8E07E7C7ULL,
		0xB824263C25209F40ULL,
		0x0A3A81111BE1FB4DULL,
		0xD0771CD175EB9F01ULL,
		0x47FB38914D34F418ULL,
		0xA4FA5A47E2D95B3FULL,
		0xE3271E5BFA8CC7ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0E9FC936A8AADEAFULL,
		0x4D86C3ABDB299D2CULL,
		0x23FA73A3ECC9C841ULL,
		0x62D2347A4B061FBAULL,
		0x21D41BABD73795D5ULL,
		0x0B67FC0C013D916CULL,
		0x9C4159AA49BAF462ULL,
		0x2DE9EE8833EE912FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DE38FDF7B499B27ULL,
		0xAD249ED8C3C24548ULL,
		0x95434FE3A0B76B5DULL,
		0xD33B3B99672C55ECULL,
		0xFCFEBF2EB732392CULL,
		0xEC5E8FADD68208E8ULL,
		0x4974E7C7FFFE6A6BULL,
		0xD07CBB9143224BDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0BC39572D614388ULL,
		0xA06224D3176757E3ULL,
		0x8EB723C04C125CE3ULL,
		0x8F96F8E0E3D9C9CDULL,
		0x24D55C7D20055CA8ULL,
		0x1F096C5E2ABB8883ULL,
		0x52CC71E249BC89F6ULL,
		0x5D6D32F6F0CC4555ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB78830B959F22C52ULL,
		0x17550798D3B950DBULL,
		0x15F843426C546A7BULL,
		0x4F968A4ABA06EC8FULL,
		0x3A08E74006B2572DULL,
		0x910951AB23EB4655ULL,
		0xC8661A3C5CD2E005ULL,
		0x47F469497A6DBC8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88148B01929D4661ULL,
		0x11993469FA3C4BBAULL,
		0x936F994F21E5181EULL,
		0x1E7D17C54D56A63DULL,
		0xBD7108F306A8FD93ULL,
		0x1B0B32A4F19F39B3ULL,
		0x06F952A0A0E57063ULL,
		0x6FF6D5A9707BE092ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F73A5B7C754E5F1ULL,
		0x05BBD32ED97D0521ULL,
		0x8288A9F34A6F525DULL,
		0x311972856CB04651ULL,
		0x7C97DE4D0009599AULL,
		0x75FE1F06324C0CA1ULL,
		0xC16CC79BBBED6FA2ULL,
		0xD7FD93A009F1DBFAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDB98553C4F65C31FULL,
		0xC173A56C0CDC2010ULL,
		0xA0AB3D30233A7EE7ULL,
		0xDC55C1A1CFEB6867ULL,
		0x99026723BC8C22F5ULL,
		0xB60A7DD355A00077ULL,
		0xECC6881F6451683AULL,
		0xB779F4095389AD05ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC061C7428ABD39FULL,
		0x21FDBA4097D9D8FAULL,
		0xCB8B25F33D206732ULL,
		0xA5B281AC7710E91DULL,
		0xF4F00FFA75C60F1CULL,
		0x5E72E565EFE2580EULL,
		0x4351ED3649162D8EULL,
		0xB23AA2F8DE01C1DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F9238C826B9EF80ULL,
		0x9F75EB2B75024716ULL,
		0xD520173CE61A17B5ULL,
		0x36A33FF558DA7F49ULL,
		0xA412572946C613D9ULL,
		0x5797986D65BDA868ULL,
		0xA9749AE91B3B3AACULL,
		0x053F51107587EB2AULL
	}};
	sign = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x76556162F2A7F20CULL,
		0x0F1D51999BC0CCBAULL,
		0x217A1A5C336B6955ULL,
		0x7A90C51D45015122ULL,
		0x7D9E799C7A84A391ULL,
		0x2142819293181F45ULL,
		0x3FCA789843891503ULL,
		0x67EB496357E6C1A8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA19D4676442A793ULL,
		0x11B7EB592E60F2FFULL,
		0xD16A5FB5374C79F2ULL,
		0x125A2A297F778B57ULL,
		0x5971CDC2245C3109ULL,
		0xBD320291AE6AB155ULL,
		0x4139B1E68AF87F03ULL,
		0x3446BF59A9BE9978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC3B8CFB8E654A79ULL,
		0xFD6566406D5FD9BAULL,
		0x500FBAA6FC1EEF62ULL,
		0x68369AF3C589C5CAULL,
		0x242CABDA56287288ULL,
		0x64107F00E4AD6DF0ULL,
		0xFE90C6B1B89095FFULL,
		0x33A48A09AE28282FULL
	}};
	sign = 0;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x26ED226CE8DD601BULL,
		0xF54BF94013AD067FULL,
		0x51C0001D26F25EA1ULL,
		0xD38A71BA292F1C22ULL,
		0x83BF55E92B0145D3ULL,
		0x9EE50AC82AC2DE16ULL,
		0x7248ED6976660EC7ULL,
		0xB0AF64A7A5BC090AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BE340C9ACE3A47ULL,
		0x195F57E1067D6F6EULL,
		0xC5A0AB1247B83A81ULL,
		0x8812212C3713FCB2ULL,
		0xC0469E806C593A6CULL,
		0x96B34D5ED8E053E2ULL,
		0xE8ACBE09070437D6ULL,
		0xA6D8FF3660A5FDC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF12EEE604E0F25D4ULL,
		0xDBECA15F0D2F9710ULL,
		0x8C1F550ADF3A2420ULL,
		0x4B78508DF21B1F6FULL,
		0xC378B768BEA80B67ULL,
		0x0831BD6951E28A33ULL,
		0x899C2F606F61D6F1ULL,
		0x09D6657145160B49ULL
	}};
	sign = 0;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x38B011BE3DDDFEBAULL,
		0xEFCF73EF59EB2306ULL,
		0x2817EC55E7E15F47ULL,
		0x64C8C52DFC55730AULL,
		0xC600D224AECF64CEULL,
		0x957D6D14DF66437CULL,
		0x6F32FB1E87A0F1B3ULL,
		0x0753D834805864DFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B16B992BBD61FF3ULL,
		0xB35B5543AA905FD1ULL,
		0xFBD52DDD2CDC253EULL,
		0xB859E3C21E238BF8ULL,
		0xE0E47217B896D579ULL,
		0xE1F949A08B952EC8ULL,
		0xFF38EF6CA652BC4BULL,
		0xB9DF4F4A28E222D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD99582B8207DEC7ULL,
		0x3C741EABAF5AC334ULL,
		0x2C42BE78BB053A09ULL,
		0xAC6EE16BDE31E711ULL,
		0xE51C600CF6388F54ULL,
		0xB384237453D114B3ULL,
		0x6FFA0BB1E14E3567ULL,
		0x4D7488EA57764207ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x77471814C6AC1A1DULL,
		0x01F854E20BC0524DULL,
		0x98129C6DC5161232ULL,
		0x88EA9483C1B89EE8ULL,
		0x429603D35BFEE2DDULL,
		0xAA78E41709D50453ULL,
		0xBF8EA0B3138B4BB2ULL,
		0x459D87049C1291DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EAE20D69883DB27ULL,
		0xE8DD42604BFD5086ULL,
		0x44C41E964CC01752ULL,
		0x2BC4810EFFE0649BULL,
		0xF3528D5F2F70D299ULL,
		0xF9E928B96BAFF253ULL,
		0x13E29C725C8A9095ULL,
		0xE648FA800E04FAF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0898F73E2E283EF6ULL,
		0x191B1281BFC301C7ULL,
		0x534E7DD77855FADFULL,
		0x5D261374C1D83A4DULL,
		0x4F4376742C8E1044ULL,
		0xB08FBB5D9E2511FFULL,
		0xABAC0440B700BB1CULL,
		0x5F548C848E0D96E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C5615680B03005AULL,
		0x0FCB50B247F92BD7ULL,
		0xA5E56D2E3CB7E2BFULL,
		0x329403607B998570ULL,
		0x98913707E49A50F6ULL,
		0x2788FD060973A6A6ULL,
		0x74CD3D209272DD58ULL,
		0x4C756A6F96347F56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x91740F54BA2959E1ULL,
		0xC4A94B025CAE717EULL,
		0x39EE4AF4F24EB734ULL,
		0x424CDFB4D3AA51B3ULL,
		0x74A37568369020EBULL,
		0x6D8E0563A9044EA9ULL,
		0x8F38B3245B042317ULL,
		0x091FF945384A827AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AE2061350D9A679ULL,
		0x4B2205AFEB4ABA59ULL,
		0x6BF722394A692B8AULL,
		0xF04723ABA7EF33BDULL,
		0x23EDC19FAE0A300AULL,
		0xB9FAF7A2606F57FDULL,
		0xE59489FC376EBA40ULL,
		0x4355712A5DE9FCDBULL
	}};
	sign = 0;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x150AFED834ECC6E7ULL,
		0xD8DB8BD83A1BD17AULL,
		0x723198B09DFFB7D7ULL,
		0x553CA74A93BF7907ULL,
		0x69F608121EED1264ULL,
		0x40A4BE9634ABF255ULL,
		0x5E77C955B7193997ULL,
		0x7BE97BCD3254BD7EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E709F8D8AFAAA3FULL,
		0xA6487C0007FDB041ULL,
		0x3A5D8F591EC95D7FULL,
		0xDCFEEFFCA483D78BULL,
		0x51D0431EFA946973ULL,
		0x62F2147BDB0BBDFCULL,
		0xC4BC558CFAEBB8E1ULL,
		0x2D1583DBB244C053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x969A5F4AA9F21CA8ULL,
		0x32930FD8321E2138ULL,
		0x37D409577F365A58ULL,
		0x783DB74DEF3BA17CULL,
		0x1825C4F32458A8F0ULL,
		0xDDB2AA1A59A03459ULL,
		0x99BB73C8BC2D80B5ULL,
		0x4ED3F7F1800FFD2AULL
	}};
	sign = 0;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x90C3E796A4D95ADDULL,
		0x976629B04849B25DULL,
		0x50E8E320E2900E5DULL,
		0x0C7285A5F820FAC0ULL,
		0x797F7508428A2FB6ULL,
		0x1A54A0372EEC9990ULL,
		0x3E3E565B81281489ULL,
		0x6673749701F82551ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x740B4B4660C54DB1ULL,
		0xAF4A3E94AFA5D1DFULL,
		0x7B63E50043EB6007ULL,
		0xD841294B2BBB4C0FULL,
		0x74F17F089BBC85AFULL,
		0xC5EC2BF301506AA7ULL,
		0x08DD4999E64FF817ULL,
		0x76FAFDDA2359C372ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CB89C5044140D2CULL,
		0xE81BEB1B98A3E07EULL,
		0xD584FE209EA4AE55ULL,
		0x34315C5ACC65AEB0ULL,
		0x048DF5FFA6CDAA06ULL,
		0x546874442D9C2EE9ULL,
		0x35610CC19AD81C71ULL,
		0xEF7876BCDE9E61DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE30D3967621F89BBULL,
		0xC62D2110D22FCDD4ULL,
		0x5985DF284DE5821FULL,
		0xD80C4F26FD16BFD6ULL,
		0xA2993240A72DBFE2ULL,
		0xD3DEDEC8BE7AAC0FULL,
		0xAA99137A56C5F3C8ULL,
		0x49CD798743C53CCCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CDFF21581237C64ULL,
		0x50B99AFECA59A3A7ULL,
		0x919A43B98FD83D0CULL,
		0xAA90BD4350808A88ULL,
		0xE2E7C3D12900749AULL,
		0x3F1CC1CFD5F727BFULL,
		0x91BD5993B98DF3DCULL,
		0x7A0B029D7E29728CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x462D4751E0FC0D57ULL,
		0x7573861207D62A2DULL,
		0xC7EB9B6EBE0D4513ULL,
		0x2D7B91E3AC96354DULL,
		0xBFB16E6F7E2D4B48ULL,
		0x94C21CF8E883844FULL,
		0x18DBB9E69D37FFECULL,
		0xCFC276E9C59BCA40ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x64595A986AD347BDULL,
		0x0A7825041052D1B2ULL,
		0xDE9BD52A4C7E0AC3ULL,
		0xE6901CC35B3834E6ULL,
		0x7AFBEEFC9059393CULL,
		0x3732000F07701468ULL,
		0x0209B47BE4D51CB9ULL,
		0xD8210BBA1AFE3189ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B5CC484A9773F7ULL,
		0x46715422F77B3470ULL,
		0xCDC56F48420D1230ULL,
		0xDF3D1C2CD60B1D9FULL,
		0xC7B75AA8148EE882ULL,
		0xAA19A8C7F9E5B8A1ULL,
		0x9BC2660FAFC6DDB5ULL,
		0xE5EF1B8BB9547DDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CA38E50203BD3C6ULL,
		0xC406D0E118D79D41ULL,
		0x10D665E20A70F892ULL,
		0x07530096852D1747ULL,
		0xB34494547BCA50BAULL,
		0x8D1857470D8A5BC6ULL,
		0x66474E6C350E3F03ULL,
		0xF231F02E61A9B3A9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3E133BA6664BFF3ULL,
		0xF28603A912F6B363ULL,
		0x2719E114798CBB07ULL,
		0x346CF9ED10A2E2DCULL,
		0xCD2A2A771EE4E7FAULL,
		0x540151C05CDAAE71ULL,
		0x5BA8AE20674B1B7CULL,
		0xAD5DB7D3673B557CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD64BC7FBCFC2811DULL,
		0x5CAEEE03A52B6470ULL,
		0x8F64ED166341F634ULL,
		0x66D919383D923FBCULL,
		0x9D801DFC9FD87F6AULL,
		0xEDB34DA5C0D79305ULL,
		0x7079151B088DCC41ULL,
		0x8E574C62C33E4B2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D956BBE96A23ED6ULL,
		0x95D715A56DCB4EF3ULL,
		0x97B4F3FE164AC4D3ULL,
		0xCD93E0B4D310A31FULL,
		0x2FAA0C7A7F0C688FULL,
		0x664E041A9C031B6CULL,
		0xEB2F99055EBD4F3AULL,
		0x1F066B70A3FD0A51ULL
	}};
	sign = 0;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC32CB4C7A544684AULL,
		0x57476D0482ACD2EDULL,
		0x52D0DD4BCD7FAF64ULL,
		0x612AE9119754FB36ULL,
		0xB01635B2A88B804EULL,
		0x6EB1D87F121894DFULL,
		0xC9C81BBA2E52286EULL,
		0x57A6F24CADB31B5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04C559480DC8373ULL,
		0xDC1AB4DEB19B7CE5ULL,
		0xFE9866F8D6DFF927ULL,
		0xC512100156683FB4ULL,
		0xAE00BE696D75A678ULL,
		0x0EF7931EE1B33024ULL,
		0x809048F5A91085E3ULL,
		0x6863CD3EAA645011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12E05F332467E4D7ULL,
		0x7B2CB825D1115608ULL,
		0x54387652F69FB63CULL,
		0x9C18D91040ECBB81ULL,
		0x021577493B15D9D5ULL,
		0x5FBA4560306564BBULL,
		0x4937D2C48541A28BULL,
		0xEF43250E034ECB4DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDFB710DF5F495A49ULL,
		0x0842F2C7158C3DE2ULL,
		0x4650D75A6F315C50ULL,
		0x065733A18554DD20ULL,
		0xCD9637A39360898EULL,
		0x62A093A3874B42F8ULL,
		0x7CB8714F09BC56D5ULL,
		0x67A295B99B4F6D9BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37A445B7286E8870ULL,
		0x495B1E6779FDCCD6ULL,
		0xE975FDFE292572ECULL,
		0x5408EDE20DA61978ULL,
		0x0E901C12522E0FFBULL,
		0xC7FA5C15DA5F3609ULL,
		0xE89072CDA0BB57E3ULL,
		0xF6DD4E6AF84920FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA812CB2836DAD1D9ULL,
		0xBEE7D45F9B8E710CULL,
		0x5CDAD95C460BE963ULL,
		0xB24E45BF77AEC3A7ULL,
		0xBF061B9141327992ULL,
		0x9AA6378DACEC0CEFULL,
		0x9427FE816900FEF1ULL,
		0x70C5474EA3064C9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5804D8E3F3423825ULL,
		0xE6B6C588AF551C6EULL,
		0xD9C00D87D08B6576ULL,
		0x17FB1A80ADB923D4ULL,
		0x6675BCE19ECE291AULL,
		0x83A34BC04FED3AF9ULL,
		0x40EA27FE20C1B31CULL,
		0xEBD02B00E056091DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74060F84B294FD29ULL,
		0x87125A72FF1DC1CFULL,
		0x1467A7F15602B7F6ULL,
		0xFA428AD687841185ULL,
		0x1A5115982525C857ULL,
		0x38F3DAE9A09B492EULL,
		0x18C756AE45C7DA27ULL,
		0xD18BEC6D6B012D47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3FEC95F40AD3AFCULL,
		0x5FA46B15B0375A9EULL,
		0xC55865967A88AD80ULL,
		0x1DB88FAA2635124FULL,
		0x4C24A74979A860C2ULL,
		0x4AAF70D6AF51F1CBULL,
		0x2822D14FDAF9D8F5ULL,
		0x1A443E937554DBD6ULL
	}};
	sign = 0;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5C606EAD72F6B6E2ULL,
		0xB526066AAF92911DULL,
		0x78559BE03865FEC5ULL,
		0x2ADB1731907476EDULL,
		0x187F2E52E6E73E0CULL,
		0x2869FF3838DA35D8ULL,
		0x5D69D62154619F84ULL,
		0x4233B89BEDEE7709ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x715FB4CCB20FBB09ULL,
		0x513AEA46F39BC08CULL,
		0x1B2CA48B7E8EBCC7ULL,
		0xAFCA68C8DDEE02D3ULL,
		0x684A6132855547C4ULL,
		0x90893548812CA78CULL,
		0xF5EA6F60BD34E2C7ULL,
		0x344B508BE9A380FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB00B9E0C0E6FBD9ULL,
		0x63EB1C23BBF6D090ULL,
		0x5D28F754B9D741FEULL,
		0x7B10AE68B286741AULL,
		0xB034CD206191F647ULL,
		0x97E0C9EFB7AD8E4BULL,
		0x677F66C0972CBCBCULL,
		0x0DE86810044AF60BULL
	}};
	sign = 0;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x806EF74EF5B78C10ULL,
		0x377990EDD54A6F63ULL,
		0xB68BD0D274997BAFULL,
		0xCA411C767755A37CULL,
		0xB55494B3CDE69640ULL,
		0xD6958821BBDC5BBCULL,
		0xF44702AD6723A8C2ULL,
		0x2B22C202A916CC4DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEE06020B3D731B8ULL,
		0xFFFA1D42CEF74AF1ULL,
		0x8AD7C556749DA522ULL,
		0xDD50E32F095FE68CULL,
		0x93CCEC823A9F2D05ULL,
		0x5840685FD1C9A4D0ULL,
		0x624A083E69FF4E8BULL,
		0x83CA90A401FBED32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD18E972E41E05A58ULL,
		0x377F73AB06532471ULL,
		0x2BB40B7BFFFBD68CULL,
		0xECF039476DF5BCF0ULL,
		0x2187A8319347693AULL,
		0x7E551FC1EA12B6ECULL,
		0x91FCFA6EFD245A37ULL,
		0xA758315EA71ADF1BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x19B88F7B3B34B910ULL,
		0xB49D2D0DEA11FB50ULL,
		0x785C466B472E62D1ULL,
		0x7FA8F01ED91E9329ULL,
		0x347F591A6A72C836ULL,
		0x19F85F8EF578B3B8ULL,
		0x143A06112D502C07ULL,
		0x23663DA51BC855C7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7154B6FEFE4A197ULL,
		0x45D64DA5B41B696CULL,
		0x0C4D871990139CF3ULL,
		0x7D70FC3B84EA18F3ULL,
		0x9D98EAA78ED22D85ULL,
		0x6630CC355DB2D802ULL,
		0x1A7732618A831B0AULL,
		0xA98AA0DDE46E51B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52A3440B4B501779ULL,
		0x6EC6DF6835F691E3ULL,
		0x6C0EBF51B71AC5DEULL,
		0x0237F3E354347A36ULL,
		0x96E66E72DBA09AB1ULL,
		0xB3C7935997C5DBB5ULL,
		0xF9C2D3AFA2CD10FCULL,
		0x79DB9CC7375A0416ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDF7A8E3C10C81DC9ULL,
		0x4995D3894F4B3437ULL,
		0x44B3C2691061929EULL,
		0xA046D23578C019A6ULL,
		0x1BBAFD34AFC75D85ULL,
		0x3C6C74B4E25A9FE5ULL,
		0xFCD6CA59DC9A8879ULL,
		0xBB87574D18684535ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF4FF3CA2E6A432ULL,
		0x99C211E4BBC13FD8ULL,
		0x2D7E3C18DFA65827ULL,
		0x02763A7593AB2F6CULL,
		0xE0E37DF833F3BE5CULL,
		0x64B433B737FDE75BULL,
		0x4D205EDBB75151DCULL,
		0x21B38CFD4903EAF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F858EFF6DE17997ULL,
		0xAFD3C1A49389F45FULL,
		0x1735865030BB3A76ULL,
		0x9DD097BFE514EA3AULL,
		0x3AD77F3C7BD39F29ULL,
		0xD7B840FDAA5CB889ULL,
		0xAFB66B7E2549369CULL,
		0x99D3CA4FCF645A45ULL
	}};
	sign = 0;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x597B3B6738D611EAULL,
		0x488BAE8165C1680FULL,
		0x6171E5C9107B398BULL,
		0xB0C95730170D8F7DULL,
		0xE0087D0CB91383F3ULL,
		0xA4D1CC925BD99170ULL,
		0xBCC8032B28E80DC0ULL,
		0x5A6821F7DB4B060FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4F5531CF85A6DB3ULL,
		0xE8302D36041D56C4ULL,
		0x78612E1C0332821CULL,
		0x133EE35FB48D7EA5ULL,
		0x1766816040D64D0AULL,
		0x29B8A0936AAED95AULL,
		0xC5F8CDFD6E37667FULL,
		0x1DA0FD6589BD76DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB485E84A407BA437ULL,
		0x605B814B61A4114AULL,
		0xE910B7AD0D48B76EULL,
		0x9D8A73D0628010D7ULL,
		0xC8A1FBAC783D36E9ULL,
		0x7B192BFEF12AB816ULL,
		0xF6CF352DBAB0A741ULL,
		0x3CC72492518D8F2FULL
	}};
	sign = 0;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD4E0CD23D2269C93ULL,
		0xD2EAC8D25369AF72ULL,
		0xBD10C03802084933ULL,
		0x344318D027A7B0DAULL,
		0xFAB9E078CD1EFAD7ULL,
		0xCA44276A0913B3C3ULL,
		0xD96A5F7F57202848ULL,
		0x714791081BE4FFD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64702A074E8FEDE6ULL,
		0x5CE4534FCF28EC4AULL,
		0xE8B7000A0435875EULL,
		0x0F14080B387CD474ULL,
		0xBCBC8F38A1AB62F1ULL,
		0x73C823DCAB1E1B06ULL,
		0x7E4F4F77FA8DE44BULL,
		0x2BE601E7E319EC06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7070A31C8396AEADULL,
		0x760675828440C328ULL,
		0xD459C02DFDD2C1D5ULL,
		0x252F10C4EF2ADC65ULL,
		0x3DFD51402B7397E6ULL,
		0x567C038D5DF598BDULL,
		0x5B1B10075C9243FDULL,
		0x45618F2038CB13D2ULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B9EA788E391C3BEULL,
		0x0313F9C53A5E8995ULL,
		0xD5C16CE721C2FC13ULL,
		0xB2F14D9E25F59138ULL,
		0x6EA55F6865C90A66ULL,
		0x7330880995C18A7BULL,
		0xCB1E01618808D446ULL,
		0xA59EA9102FC6EF2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69C44EDCE9B7AE12ULL,
		0x2E4FFC51F20391DBULL,
		0xC7C577480EE4CDF4ULL,
		0xFFF15A5BE6D3B6D7ULL,
		0x89F59A51285C8742ULL,
		0x78C1059EF9AE6B05ULL,
		0x46C42ED158F3B34CULL,
		0x38249ADEA22D851BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1DA58ABF9DA15ACULL,
		0xD4C3FD73485AF7B9ULL,
		0x0DFBF59F12DE2E1EULL,
		0xB2FFF3423F21DA61ULL,
		0xE4AFC5173D6C8323ULL,
		0xFA6F826A9C131F75ULL,
		0x8459D2902F1520F9ULL,
		0x6D7A0E318D996A10ULL
	}};
	sign = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE7CDDE4EB04E4EF5ULL,
		0x2658B1999B789102ULL,
		0x12F95482002E1589ULL,
		0xF104D512F2E40D05ULL,
		0x0F820DB71E35DF7EULL,
		0x57AC71C0787A957EULL,
		0xFD67EDB5BB6C6B0BULL,
		0xA71C074D1A7D6FD0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F923E952A780BCEULL,
		0x84FBF87AC6F5AA6AULL,
		0x570B8F9500A69BC4ULL,
		0x5848763FC563B9FCULL,
		0x9846506A232A5189ULL,
		0xFC3CD0F82A317607ULL,
		0xEC7440E15EAD9DFFULL,
		0x467B3A278F75B7F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD83B9FB985D64327ULL,
		0xA15CB91ED482E698ULL,
		0xBBEDC4ECFF8779C4ULL,
		0x98BC5ED32D805308ULL,
		0x773BBD4CFB0B8DF5ULL,
		0x5B6FA0C84E491F76ULL,
		0x10F3ACD45CBECD0BULL,
		0x60A0CD258B07B7DFULL
	}};
	sign = 0;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBCA33E850DE73512ULL,
		0xF638E0844D018B82ULL,
		0x7C36E007124F5732ULL,
		0x8B6E5D2690F8F099ULL,
		0xA849D2D6DC269971ULL,
		0xF9AE70D0C4F69722ULL,
		0x2D96D49A4462E26FULL,
		0x734BD13791F1D2B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF1C643196952AFULL,
		0xE3CD4E68D95A5F92ULL,
		0x0D0D2C89A95786E5ULL,
		0xB2EA9B08716EA061ULL,
		0x81CA22F23949242AULL,
		0x1AB4ACAB66338C5BULL,
		0xB04A5BDD580E4FD2ULL,
		0x7542C5EE98FC19C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1B17841F47DE263ULL,
		0x126B921B73A72BEFULL,
		0x6F29B37D68F7D04DULL,
		0xD883C21E1F8A5038ULL,
		0x267FAFE4A2DD7546ULL,
		0xDEF9C4255EC30AC7ULL,
		0x7D4C78BCEC54929DULL,
		0xFE090B48F8F5B8EEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x182179F7CB3E1A08ULL,
		0x08D757E565D050A8ULL,
		0xD631FB296ACD877BULL,
		0xD045BAEC2B294C43ULL,
		0x5FCF1DCBCB754636ULL,
		0xAA01324CBC390D95ULL,
		0xE7E2BAA9373CCC52ULL,
		0x707943166F929FCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78A9E80FCA73ADDULL,
		0x122D27D730BF361DULL,
		0xCB94004C0FA61C37ULL,
		0x888B3D0DB6B0F329ULL,
		0x6DDE7D6486CBF183ULL,
		0x801608D57A5E9AF4ULL,
		0xB8B85B65D46E3E3BULL,
		0x3921A8A13519FE47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2096DB76CE96DF2BULL,
		0xF6AA300E35111A8AULL,
		0x0A9DFADD5B276B43ULL,
		0x47BA7DDE7478591AULL,
		0xF1F0A06744A954B3ULL,
		0x29EB297741DA72A0ULL,
		0x2F2A5F4362CE8E17ULL,
		0x37579A753A78A183ULL
	}};
	sign = 0;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F94E6328CB7772FULL,
		0x1277D29EE13CEE52ULL,
		0x2766AE04DB7BC12FULL,
		0x96657BB43130D59FULL,
		0x4299CF6CAC4D351AULL,
		0x334F74BCEE4D8F5FULL,
		0xADB1796FAA0668D7ULL,
		0x7478D2C551AB9F85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1124F6E460E80AULL,
		0xD6732B5E6E6D4EDEULL,
		0xF55A843526437EBAULL,
		0x4C453C37C63C85F0ULL,
		0xD6C6D0CABBF12CA3ULL,
		0x73DE76FC2D24A79AULL,
		0x0F0E0583C3D9C1FFULL,
		0x639A72D220D8C295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3083C13BA8568F25ULL,
		0x3C04A74072CF9F74ULL,
		0x320C29CFB5384274ULL,
		0x4A203F7C6AF44FAEULL,
		0x6BD2FEA1F05C0877ULL,
		0xBF70FDC0C128E7C4ULL,
		0x9EA373EBE62CA6D7ULL,
		0x10DE5FF330D2DCF0ULL
	}};
	sign = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x484E3980C217DD9BULL,
		0xE13A2B82E36ADC16ULL,
		0x430FF2192DE2D08FULL,
		0xAF60712A77517A6DULL,
		0x7B304B4F302580F5ULL,
		0x9F7330497C13BE4FULL,
		0x5F56CE678653C126ULL,
		0x750EDF1EE23BB560ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC99991188B3376ULL,
		0x3035BFFC6E495EC1ULL,
		0xE260B9AF58C8A30DULL,
		0x5CBE9F99B1089673ULL,
		0x5A37C774504B14E1ULL,
		0xEBD10CEAD0B45C6BULL,
		0x6D530DD95D4899C6ULL,
		0x2CC032C2FE094A24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59849FEFA98CAA25ULL,
		0xB1046B8675217D54ULL,
		0x60AF3869D51A2D82ULL,
		0x52A1D190C648E3F9ULL,
		0x20F883DADFDA6C14ULL,
		0xB3A2235EAB5F61E4ULL,
		0xF203C08E290B275FULL,
		0x484EAC5BE4326B3BULL
	}};
	sign = 0;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE216D96A68F482F6ULL,
		0xC57125607CE0AB7CULL,
		0xF365A5ADE7977099ULL,
		0x6CB8D9BD644799D8ULL,
		0x1252E0F18237698DULL,
		0x299F341A0CD90155ULL,
		0xBEEC0D945197F022ULL,
		0x8CA32AD44F99E7D2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8B132EAE7CAD884ULL,
		0x2CE3F2411FF9619AULL,
		0xC4AF69861DE7DE26ULL,
		0xF4603488E5C6E752ULL,
		0xF97A85E00A502D91ULL,
		0x755F5D6D4D666346ULL,
		0x96BB6F380904FBBCULL,
		0x3DC71F5956AC2989ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3965A67F8129AA72ULL,
		0x988D331F5CE749E2ULL,
		0x2EB63C27C9AF9273ULL,
		0x7858A5347E80B286ULL,
		0x18D85B1177E73BFBULL,
		0xB43FD6ACBF729E0EULL,
		0x28309E5C4892F465ULL,
		0x4EDC0B7AF8EDBE49ULL
	}};
	sign = 0;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x502BE518D8D3DCF2ULL,
		0xE94EB17EBE1DAAF3ULL,
		0xE33304FEA836D7C7ULL,
		0xCF34C60E2DFADC5BULL,
		0x742BACF69D331788ULL,
		0xE167AA8F6BAA83C5ULL,
		0x4BF1E46C65374492ULL,
		0x59AA65B032632426ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF53E50FA35360270ULL,
		0xC8BBE22B54EC19C1ULL,
		0x5B44FF03782CDE42ULL,
		0xA5D5D125F84A9C02ULL,
		0x23F5575F89FAD034ULL,
		0x031A42EFE766D1E8ULL,
		0xBBC41588EA8E6B61ULL,
		0x766ECAB410970238ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AED941EA39DDA82ULL,
		0x2092CF5369319131ULL,
		0x87EE05FB3009F985ULL,
		0x295EF4E835B04059ULL,
		0x5036559713384754ULL,
		0xDE4D679F8443B1DDULL,
		0x902DCEE37AA8D931ULL,
		0xE33B9AFC21CC21EDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x373D048791CC6C4BULL,
		0x414B9400C96E55E4ULL,
		0x672AC9420EFD822DULL,
		0xD0C82A5DCF5199E8ULL,
		0x17E78DA44630E404ULL,
		0x993388E947274AD7ULL,
		0x42A2B9826273D535ULL,
		0xD6186BDB2C76C4F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE29D52BB38221CA3ULL,
		0x9D6F8AAC8F547A12ULL,
		0x22698A5911C93C0CULL,
		0xFEC8624AEF7D5CA1ULL,
		0x60EEF745D41992B9ULL,
		0x7D71B5D904A4E26CULL,
		0xA414D6DC8C4E9354ULL,
		0x083A6C736B5A0778ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x549FB1CC59AA4FA8ULL,
		0xA3DC09543A19DBD1ULL,
		0x44C13EE8FD344620ULL,
		0xD1FFC812DFD43D47ULL,
		0xB6F8965E7217514AULL,
		0x1BC1D3104282686AULL,
		0x9E8DE2A5D62541E1ULL,
		0xCDDDFF67C11CBD80ULL
	}};
	sign = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAAA4869B32B7C4C3ULL,
		0xFB858513D42ED1EDULL,
		0xEA931328A7D86F4EULL,
		0xCE0D8BFBD35BF1A4ULL,
		0x661E3A4CEB6E0133ULL,
		0x76EB0CA9AECD7067ULL,
		0xEE34D4D782C23082ULL,
		0xDFAF5A604CE5F0FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5FF7BC292C0295ULL,
		0x448E4E645F1550EDULL,
		0xAF19D9311833321AULL,
		0x6345F480ACB61A4DULL,
		0x906F600B0F0F4DD7ULL,
		0x8F1DA168AA55DA0EULL,
		0xD2482B9C7C447174ULL,
		0x00F9CC90F696ADA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE448EDF098BC22EULL,
		0xB6F736AF751980FFULL,
		0x3B7939F78FA53D34ULL,
		0x6AC7977B26A5D757ULL,
		0xD5AEDA41DC5EB35CULL,
		0xE7CD6B4104779658ULL,
		0x1BECA93B067DBF0DULL,
		0xDEB58DCF564F4352ULL
	}};
	sign = 0;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0228002898CF9088ULL,
		0x970A163E1E303EEFULL,
		0x1432B5F586C028E8ULL,
		0x8D9962A978CAEA25ULL,
		0x08790C4604C6F7DAULL,
		0xA9DE7464A12C0D92ULL,
		0xC182A3006A77202EULL,
		0x43D2952499D5D482ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FBDE362405DD040ULL,
		0x71792E3ECF6DC5F9ULL,
		0x67475452E6BDA3F2ULL,
		0xA5D72FD42BCBF08AULL,
		0x8E1754255BEFB000ULL,
		0xB41E904B5587BF67ULL,
		0xA24B38689597F2DBULL,
		0x9DB6F9A6845C3355ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC26A1CC65871C048ULL,
		0x2590E7FF4EC278F5ULL,
		0xACEB61A2A00284F6ULL,
		0xE7C232D54CFEF99AULL,
		0x7A61B820A8D747D9ULL,
		0xF5BFE4194BA44E2AULL,
		0x1F376A97D4DF2D52ULL,
		0xA61B9B7E1579A12DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xED2460C95CED1F73ULL,
		0xC9C9717154275345ULL,
		0xD643FF1AF01065B5ULL,
		0x6B658FB3EEF05914ULL,
		0x73F484434D66A630ULL,
		0x7919CB152A494167ULL,
		0xDACA4A73BB700477ULL,
		0xF5D49D2E1D180873ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD07DD26BAE97F1ULL,
		0xCE4AF107DA1B41BFULL,
		0x9077E76BA578588BULL,
		0x98945224B04A7383ULL,
		0x52DE8C94F0FF63F6ULL,
		0x85DCF0BC9D672D3AULL,
		0x0B115BB33D90E56FULL,
		0x4B1E9A3B8FB13B8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF53E2F6F13E8782ULL,
		0xFB7E80697A0C1185ULL,
		0x45CC17AF4A980D29ULL,
		0xD2D13D8F3EA5E591ULL,
		0x2115F7AE5C674239ULL,
		0xF33CDA588CE2142DULL,
		0xCFB8EEC07DDF1F07ULL,
		0xAAB602F28D66CCE4ULL
	}};
	sign = 0;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB0A9D2D4F11CDEE1ULL,
		0xA429A44FAE363EA8ULL,
		0x6127D5CD313B5985ULL,
		0xD6E46ABF883C75B3ULL,
		0x9A8BE4D4F330BC4DULL,
		0x7E54A8863C6F3BDCULL,
		0xCE1505FAFFDD8309ULL,
		0x4DC039B16CBF355DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x216287E2F91EB804ULL,
		0x0E53CB6A5EF682B2ULL,
		0x2AEBE7346546FB49ULL,
		0x920D9EA8070F600DULL,
		0x6CB4751D9FE8FC3AULL,
		0xFC00AB65D96A9631ULL,
		0xE088DDA99AFB9DA5ULL,
		0xDC9C653CF4047EE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F474AF1F7FE26DDULL,
		0x95D5D8E54F3FBBF6ULL,
		0x363BEE98CBF45E3CULL,
		0x44D6CC17812D15A6ULL,
		0x2DD76FB75347C013ULL,
		0x8253FD206304A5ABULL,
		0xED8C285164E1E563ULL,
		0x7123D47478BAB677ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2222576340F90EB1ULL,
		0x8718F5B684AE4882ULL,
		0x3A2BBBFC6EBD1334ULL,
		0x4770FDAF542E9FDDULL,
		0xCF9243A933DB884DULL,
		0x8A23DBA316C3ED40ULL,
		0x8738F9AEF053A0B7ULL,
		0x4584408055B1E6D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4415D516FE3484DULL,
		0x2BF526E538EA7A97ULL,
		0x08E77125070953F7ULL,
		0xF5A6FFE55C652163ULL,
		0x61C7776C259C21E5ULL,
		0x5CE00D3AB0BB42E6ULL,
		0x714F56F5FCA218EBULL,
		0x5A4C9162DFB9861FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DE0FA11D115C664ULL,
		0x5B23CED14BC3CDEAULL,
		0x31444AD767B3BF3DULL,
		0x51C9FDC9F7C97E7AULL,
		0x6DCACC3D0E3F6667ULL,
		0x2D43CE686608AA5AULL,
		0x15E9A2B8F3B187CCULL,
		0xEB37AF1D75F860B7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x03040F1F63D282EFULL,
		0x023DE2FBF77F87BAULL,
		0xBA5AD9369A9D9695ULL,
		0x8F37BC4663E02B81ULL,
		0x162DC08D788C5781ULL,
		0x22EB3E3BA8300FFAULL,
		0xF863AA74339D45DFULL,
		0xC3CE1D9B89F45A27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D7E45AA46BC160ULL,
		0xC4428D29C9F736B7ULL,
		0x624CC37DE15A2212ULL,
		0x666BE70F907F8FA0ULL,
		0x81E4C80C5B220F20ULL,
		0x91834E2F708C5BB1ULL,
		0xAF5DB0E248FE6A0AULL,
		0x726967F71E49115EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F2C2AC4BF66C18FULL,
		0x3DFB55D22D885102ULL,
		0x580E15B8B9437482ULL,
		0x28CBD536D3609BE1ULL,
		0x9448F8811D6A4861ULL,
		0x9167F00C37A3B448ULL,
		0x4905F991EA9EDBD4ULL,
		0x5164B5A46BAB48C9ULL
	}};
	sign = 0;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD477DEA6A40D86FFULL,
		0x27B1BC96C226DBF8ULL,
		0x67824DBB3B1979F6ULL,
		0x94D588BFA48FFB8CULL,
		0xA5ED63965A754B24ULL,
		0xAF6A4928443CD4CEULL,
		0xA561D5E0A1738157ULL,
		0xCBECF1FCF4AC0B6CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E4AD3EAB41A230ULL,
		0x256166FECC1EE5CFULL,
		0x433A423E13A45FCBULL,
		0x753864E501BCA762ULL,
		0x620DD447FDDF36F6ULL,
		0x34E5CDEF358DD52AULL,
		0x6D45BCCEB1B97216ULL,
		0xE2D7DC45E4D80144ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A933167F8CBE4CFULL,
		0x02505597F607F629ULL,
		0x24480B7D27751A2BULL,
		0x1F9D23DAA2D3542AULL,
		0x43DF8F4E5C96142EULL,
		0x7A847B390EAEFFA4ULL,
		0x381C1911EFBA0F41ULL,
		0xE91515B70FD40A28ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x288FAD384AF478B1ULL,
		0x93E6F86588E88366ULL,
		0x32F9A4FC847D9AE1ULL,
		0x8BB09A45675CAA56ULL,
		0xBDE60175F5D2F711ULL,
		0x96DDEA0ADA01A864ULL,
		0x450876036D989FD3ULL,
		0xE2C878BD8E76AF58ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17ED0671CCC1951ULL,
		0x234DEACEABF30BC8ULL,
		0x410031235E38828EULL,
		0xB6DA6AD358163D50ULL,
		0x6B6704C08402DA9AULL,
		0x83BD44948600B9C6ULL,
		0x4728A906F0228EE7ULL,
		0xA8FD02DF7B7D49A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7710DCD12E285F60ULL,
		0x70990D96DCF5779DULL,
		0xF1F973D926451853ULL,
		0xD4D62F720F466D05ULL,
		0x527EFCB571D01C76ULL,
		0x1320A5765400EE9EULL,
		0xFDDFCCFC7D7610ECULL,
		0x39CB75DE12F965B1ULL
	}};
	sign = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0E1ADE886358BEAULL,
		0xD6F7C561E4A58B4DULL,
		0xE416E425E1465290ULL,
		0xD3A1CCE06D1CD886ULL,
		0x85A0DC6458EB7423ULL,
		0x15744DB2A0B5582FULL,
		0x0A23F7093308B5DAULL,
		0x9FFB4762AB83B2FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C7834962D36B7B8ULL,
		0xA7C7322C82C2A6B8ULL,
		0xD7B42B10361A5A81ULL,
		0xB96CFA54044FCE72ULL,
		0xE4766126201A2682ULL,
		0xA0EFF1BDCDFEAE8DULL,
		0x0518F327B6FABD1BULL,
		0x619C7A026A3BC534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9469795258FED432ULL,
		0x2F30933561E2E495ULL,
		0x0C62B915AB2BF80FULL,
		0x1A34D28C68CD0A14ULL,
		0xA12A7B3E38D14DA1ULL,
		0x74845BF4D2B6A9A1ULL,
		0x050B03E17C0DF8BEULL,
		0x3E5ECD604147EDC7ULL
	}};
	sign = 0;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2B2AE3A906A4514AULL,
		0xBD7F87360EEA9A6CULL,
		0x51974F23B1823BABULL,
		0xCD23FCEF9345A553ULL,
		0xF433621CA7E37827ULL,
		0xD89B413613290CD7ULL,
		0x112C1CAFC852D42BULL,
		0x2312A7ABADE2A26DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x642176A0024BF1D7ULL,
		0x330B3C091E13C1EBULL,
		0xA33EEFAF29F0B72DULL,
		0x277978C3FAD306C1ULL,
		0xCE0AF51022641104ULL,
		0xA055091C694DED26ULL,
		0xC620FA72E97F2AE7ULL,
		0x0E7427F4785EA879ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7096D0904585F73ULL,
		0x8A744B2CF0D6D880ULL,
		0xAE585F748791847EULL,
		0xA5AA842B98729E91ULL,
		0x26286D0C857F6723ULL,
		0x38463819A9DB1FB1ULL,
		0x4B0B223CDED3A944ULL,
		0x149E7FB73583F9F3ULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC92725EA047D2525ULL,
		0x82EDE0BDD6AE57A5ULL,
		0x03FD9566CC217925ULL,
		0x5F8F36ECDAD0CF96ULL,
		0xA81335184C9B7E20ULL,
		0x417445A8114B0D43ULL,
		0xFB7405333A0D5D87ULL,
		0xC0FCF0A59C68D006ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x78EFE6019DBCED2EULL,
		0xA91FEEF533EBBAFBULL,
		0x6CA0A60CFAF5580CULL,
		0x5B30ED1743ECF55DULL,
		0x4F0A100050814B8EULL,
		0x8FDD92153194ED6CULL,
		0x184DE0954855D93FULL,
		0x9A4ABF3F1FAD3B3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50373FE866C037F7ULL,
		0xD9CDF1C8A2C29CAAULL,
		0x975CEF59D12C2118ULL,
		0x045E49D596E3DA38ULL,
		0x59092517FC1A3292ULL,
		0xB196B392DFB61FD7ULL,
		0xE326249DF1B78447ULL,
		0x26B231667CBB94CAULL
	}};
	sign = 0;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2BF3EB757AC40D65ULL,
		0x743780AD7A73C7E6ULL,
		0xB6A22E39AB630F66ULL,
		0xB83BC036B80ED429ULL,
		0xD628CC6BA7F2499CULL,
		0xD191EB2E65FCC412ULL,
		0x3BC354C8DCF200C1ULL,
		0xB995BA358B7C845FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF18F292B05C9FA0ULL,
		0xE093D499B44CD47CULL,
		0x2FA50A9A02B710BBULL,
		0x3CDA78F321192437ULL,
		0xDDFA1CB440F951C9ULL,
		0x45066F2B38A70339ULL,
		0x205976F003F5BF96ULL,
		0xEB059CE3501C39C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CDAF8E2CA676DC5ULL,
		0x93A3AC13C626F369ULL,
		0x86FD239FA8ABFEAAULL,
		0x7B61474396F5AFF2ULL,
		0xF82EAFB766F8F7D3ULL,
		0x8C8B7C032D55C0D8ULL,
		0x1B69DDD8D8FC412BULL,
		0xCE901D523B604A9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x94840CFBD1181C18ULL,
		0xA49D72C331823633ULL,
		0x2CCA894CA376DFE8ULL,
		0xF6C2D1E3E310C3E6ULL,
		0x82157830B4BDDD72ULL,
		0xA16A649B29E16A81ULL,
		0xC13403E429AF5ADAULL,
		0x25BEE3A26B70F5C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF426B9B29393711EULL,
		0x646BC5B9323FDAABULL,
		0x294DB843DCA921C9ULL,
		0x7470992DF042E297ULL,
		0x6CF1C64C19F4C5B8ULL,
		0x5BF60B6EA3DD28B6ULL,
		0x2E75866D82672F9AULL,
		0xE2E022FE91BDF192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA05D53493D84AAFAULL,
		0x4031AD09FF425B87ULL,
		0x037CD108C6CDBE1FULL,
		0x825238B5F2CDE14FULL,
		0x1523B1E49AC917BAULL,
		0x4574592C860441CBULL,
		0x92BE7D76A7482B40ULL,
		0x42DEC0A3D9B3042FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBBD0A893E3EF9138ULL,
		0x02AF8046E7642870ULL,
		0xA3779131258305BEULL,
		0x31B3F2609610A7A7ULL,
		0xEB5B7752A1DF5D6CULL,
		0x265BF9CE2B7B269EULL,
		0x96A2575BB6AED828ULL,
		0xAC9852C73D9BF902ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6FC835F3591C6AAULL,
		0x0DAAE027B6233067ULL,
		0x9EB25260DF7083C0ULL,
		0x98F90AE0044CB48BULL,
		0x42C422317F53C438ULL,
		0x825C0C987A0BDA4FULL,
		0x01AD93B56B48E3FEULL,
		0x8CC857F9A8C30562ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4D42534AE5DCA8EULL,
		0xF504A01F3140F808ULL,
		0x04C53ED0461281FDULL,
		0x98BAE78091C3F31CULL,
		0xA8975521228B9933ULL,
		0xA3FFED35B16F4C4FULL,
		0x94F4C3A64B65F429ULL,
		0x1FCFFACD94D8F3A0ULL
	}};
	sign = 0;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCAD64E177268B234ULL,
		0x30D81C55CBCC12ADULL,
		0xAE34319A95659356ULL,
		0x83BC5F4931703697ULL,
		0x8783E8904DDAACFDULL,
		0x6F6F9C2E5D0D8F82ULL,
		0x0632D3E1AE659AB9ULL,
		0x781330301D4503D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x525A03548797698FULL,
		0x7B7A724D2C1B80C8ULL,
		0x60A2D47C3ADF2168ULL,
		0x6393F7E957E3A4FAULL,
		0xAB21EAFB4C06AD07ULL,
		0x0AD4CD84D2292351ULL,
		0x2889DB1AD16876CBULL,
		0x5CF15C9341D74723ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x787C4AC2EAD148A5ULL,
		0xB55DAA089FB091E5ULL,
		0x4D915D1E5A8671EDULL,
		0x2028675FD98C919DULL,
		0xDC61FD9501D3FFF6ULL,
		0x649ACEA98AE46C30ULL,
		0xDDA8F8C6DCFD23EEULL,
		0x1B21D39CDB6DBCB4ULL
	}};
	sign = 0;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE142B4CBE4EC5CEEULL,
		0x8253ACAFB6A16FE0ULL,
		0xF9593E8493215020ULL,
		0xE7EBE7D48A960C6AULL,
		0x135F50F62F91D8B9ULL,
		0xD02FCED65F132F40ULL,
		0xE58B24F149A7FC45ULL,
		0x976BFA8401B9A5D2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BFF91286EA8532ULL,
		0x40189CC86C48D621ULL,
		0x3EC9A36F93A403C5ULL,
		0x3717A1BC9186FB0CULL,
		0x6121A205CC5447E9ULL,
		0x7BF7ECA028E7C5F5ULL,
		0x8030028947849CCAULL,
		0x5C3A48017C5A47B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5782BBB95E01D7BCULL,
		0x423B0FE74A5899BFULL,
		0xBA8F9B14FF7D4C5BULL,
		0xB0D44617F90F115EULL,
		0xB23DAEF0633D90D0ULL,
		0x5437E236362B694AULL,
		0x655B226802235F7BULL,
		0x3B31B282855F5E1BULL
	}};
	sign = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x755B1485AE042031ULL,
		0x13B563514A82F57DULL,
		0x1F58EF586A67DEA1ULL,
		0xA9D4744EC1FFF1CDULL,
		0xD5D3441C1218EB7CULL,
		0x36C7EB6DDB19B2A7ULL,
		0x7CD31133BFAC2FB4ULL,
		0xF76A8740531AD6E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2C18B582F6116EULL,
		0x3688D010EC30C634ULL,
		0x1A27C58B67BCE7FDULL,
		0xE6EEB523010B5500ULL,
		0xA0EFA9BFE8B6B63FULL,
		0x61D91741F221EFEBULL,
		0xD2BC34C0C92DCC0EULL,
		0x82F0C8769EBBFF59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x362EFBD02B0E0EC3ULL,
		0xDD2C93405E522F49ULL,
		0x053129CD02AAF6A3ULL,
		0xC2E5BF2BC0F49CCDULL,
		0x34E39A5C2962353CULL,
		0xD4EED42BE8F7C2BCULL,
		0xAA16DC72F67E63A5ULL,
		0x7479BEC9B45ED78CULL
	}};
	sign = 0;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0924CB5C0D037559ULL,
		0x9DFE4F63003C71D3ULL,
		0x1E38F71852547369ULL,
		0xCA8DDB0561746DDAULL,
		0xB4AEC9C6E9004ACFULL,
		0x55998C971D635F83ULL,
		0x8EC8E97B66A1867FULL,
		0xF9387CE071881CCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x684B72B46D959C82ULL,
		0xEE65FFBD7F7F26DAULL,
		0x83B7943E782FA1E1ULL,
		0x5C4A0D88ADDDC5E4ULL,
		0x90CAE4C39DBFEAFCULL,
		0x757A6C96665E1EA7ULL,
		0x5ACD9B2C36F6D137ULL,
		0xB3518D20BE73065AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D958A79F6DD8D7ULL,
		0xAF984FA580BD4AF8ULL,
		0x9A8162D9DA24D187ULL,
		0x6E43CD7CB396A7F5ULL,
		0x23E3E5034B405FD3ULL,
		0xE01F2000B70540DCULL,
		0x33FB4E4F2FAAB547ULL,
		0x45E6EFBFB3151670ULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x443AC26D72FA54EBULL,
		0xA265BE60102181AEULL,
		0x606D41204E802709ULL,
		0x94F9BC6C66E36C30ULL,
		0x3984795A29A51BE0ULL,
		0x01CAED3A12A1368DULL,
		0x15BDAB05864B6CC6ULL,
		0x970A3A23C84FEF0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA9373C35C856A7ULL,
		0x167612637F438860ULL,
		0xCBC3138137924DBDULL,
		0xB038F3956833150FULL,
		0x09C2134701762509ULL,
		0x8752CEB7555769CBULL,
		0x2E88CD0928DEE8A1ULL,
		0xCE0C8D7DB40D4907ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58918B313D31FE44ULL,
		0x8BEFABFC90DDF94DULL,
		0x94AA2D9F16EDD94CULL,
		0xE4C0C8D6FEB05720ULL,
		0x2FC26613282EF6D6ULL,
		0x7A781E82BD49CCC2ULL,
		0xE734DDFC5D6C8424ULL,
		0xC8FDACA61442A606ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x69CD4A97B69F3606ULL,
		0x4DB3BA8D437D3DC6ULL,
		0x1AFE079AF56F1069ULL,
		0xB23F45A51948DA03ULL,
		0xEAF41434BF4A8793ULL,
		0xA76BB0640171380DULL,
		0xC020E2EF8B9E84B7ULL,
		0x51906C2B73F85A41ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A396F29669FA5DEULL,
		0x93537E72AA2A613EULL,
		0x0BF1BFA87DDC6E0AULL,
		0x3033AA5278D4D7E3ULL,
		0x6394CBC128AAF91FULL,
		0xF0C62E243DD1670CULL,
		0x0A6076B196020E94ULL,
		0x0F863D0D614C268CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF93DB6E4FFF9028ULL,
		0xBA603C1A9952DC87ULL,
		0x0F0C47F27792A25EULL,
		0x820B9B52A0740220ULL,
		0x875F4873969F8E74ULL,
		0xB6A5823FC39FD101ULL,
		0xB5C06C3DF59C7622ULL,
		0x420A2F1E12AC33B5ULL
	}};
	sign = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x88271C60E3805185ULL,
		0x673B2F8638644A3CULL,
		0x10BF5536A80148DCULL,
		0x880C599E8FB4B421ULL,
		0xE1F993995443DFBDULL,
		0x2369A6FA66742F06ULL,
		0x2C169B4A76341E0EULL,
		0x0892F573C8FBD8F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97D9B7E3FD51B03FULL,
		0xCCF7A85FE83FF259ULL,
		0x44A3530C1B69F006ULL,
		0x375C0F37E0172A6FULL,
		0xA4F6DA094288F642ULL,
		0x008E4A567047EE4FULL,
		0x5B23E3F78AAD019BULL,
		0x82030C474D2909ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF04D647CE62EA146ULL,
		0x9A438726502457E2ULL,
		0xCC1C022A8C9758D5ULL,
		0x50B04A66AF9D89B1ULL,
		0x3D02B99011BAE97BULL,
		0x22DB5CA3F62C40B7ULL,
		0xD0F2B752EB871C73ULL,
		0x868FE92C7BD2CF4AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7A92172E2FF7BA6CULL,
		0x4E09454218E3268AULL,
		0xDE9FF6C50D8F99C0ULL,
		0xC4C19DCB9F0C69F9ULL,
		0xA9C71170BA00320EULL,
		0x1B4BEA4F868F84EAULL,
		0xFCFC6B16DF5A4A5BULL,
		0xDF1912C294F10825ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABCF9C5C52828B0DULL,
		0x6236E5363EB7E0D8ULL,
		0x844BB38893262387ULL,
		0x28D4071ECC3F18E0ULL,
		0x39F847C6A09850E4ULL,
		0xDBDC95641FE4A3D4ULL,
		0xFFBA42EF53F6FAEEULL,
		0xBBCEBB26664AB24EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEC27AD1DD752F5FULL,
		0xEBD2600BDA2B45B1ULL,
		0x5A54433C7A697638ULL,
		0x9BED96ACD2CD5119ULL,
		0x6FCEC9AA1967E12AULL,
		0x3F6F54EB66AAE116ULL,
		0xFD4228278B634F6CULL,
		0x234A579C2EA655D6ULL
	}};
	sign = 0;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6FC14E338000F9EBULL,
		0xBEF2F28A15D6FF99ULL,
		0xDD321E8C3A1BEB6FULL,
		0x96E4AEF5AB8669D3ULL,
		0xE4607F6F3C5BBE5CULL,
		0x29338CD467CA2AB0ULL,
		0xD599B9136D989E3CULL,
		0x46FF72092A37892EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9AC214CB990F108ULL,
		0xB787734CAE4C432FULL,
		0xB6EC731F1DA75BD6ULL,
		0x7E3478A18939C083ULL,
		0xF0CFBDB4E9716A3AULL,
		0x8C7A615471418F60ULL,
		0xA2E9B9867EE1D643ULL,
		0x8E6C08181835F170ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6152CE6C67008E3ULL,
		0x076B7F3D678ABC69ULL,
		0x2645AB6D1C748F99ULL,
		0x18B03654224CA950ULL,
		0xF390C1BA52EA5422ULL,
		0x9CB92B7FF6889B4FULL,
		0x32AFFF8CEEB6C7F8ULL,
		0xB89369F1120197BEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x25D87A904EC8CF23ULL,
		0xA88C81D67D4B4CEBULL,
		0x1173F7AFA47262C1ULL,
		0x62061410D1C1A619ULL,
		0x38B2A76B0B8B043DULL,
		0x9B0CA53D217AF05EULL,
		0xF0AD35F14AC751DCULL,
		0xDBBBB836B052124CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02606B657BAFB290ULL,
		0x9E514383E8D2F696ULL,
		0x9EF0AA6F06D491F0ULL,
		0x0702E406AEC969B0ULL,
		0xA173602F14F81A13ULL,
		0xD55D7FD49B1D3E0AULL,
		0x4D2A803D86DE014AULL,
		0xB6FEE2292E2B740DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23780F2AD3191C93ULL,
		0x0A3B3E5294785655ULL,
		0x72834D409D9DD0D1ULL,
		0x5B03300A22F83C68ULL,
		0x973F473BF692EA2AULL,
		0xC5AF2568865DB253ULL,
		0xA382B5B3C3E95091ULL,
		0x24BCD60D82269E3FULL
	}};
	sign = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE3E00650EC9CBB28ULL,
		0xA4150E0FCC0449C7ULL,
		0x06D5229D9B5DC605ULL,
		0x1AE055855D33EA5FULL,
		0x7F8BED017BC3E9E1ULL,
		0xA7B91A40F3B7D8CAULL,
		0x86B3FDCF667DA4E8ULL,
		0xF9291D19E92C694BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26133817743DA5A9ULL,
		0xE9BF6911AB138450ULL,
		0xBD9B739FCFE6488FULL,
		0x2403FABBE0A3A640ULL,
		0x732F486A7BD00924ULL,
		0xC9F8C2387F084B11ULL,
		0x63FA37638FCDE57DULL,
		0xA23D1CB8E51F063BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDCCCE39785F157FULL,
		0xBA55A4FE20F0C577ULL,
		0x4939AEFDCB777D75ULL,
		0xF6DC5AC97C90441EULL,
		0x0C5CA496FFF3E0BCULL,
		0xDDC0580874AF8DB9ULL,
		0x22B9C66BD6AFBF6AULL,
		0x56EC0061040D6310ULL
	}};
	sign = 0;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD278AFBD72F566B5ULL,
		0x5FDC438071591AB7ULL,
		0x73D9014FF0C02E6DULL,
		0x5FA357B58EC74F42ULL,
		0x4156F7DD1E2FC283ULL,
		0xFFC2EA6A88FB3F8BULL,
		0x94B4AD6EA0822A88ULL,
		0xA75ACE7CE062C4EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9FAE29BC25827E1ULL,
		0x5050B859A7B6B031ULL,
		0x2FDD7CD0FB33F8BEULL,
		0x6996B8A04FD96704ULL,
		0xA53514EE44068C46ULL,
		0x17A241B0B161FE3AULL,
		0xD0CFB7073FE319DAULL,
		0x08F3C993C5CDDE53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF87DCD21B09D3ED4ULL,
		0x0F8B8B26C9A26A85ULL,
		0x43FB847EF58C35AFULL,
		0xF60C9F153EEDE83EULL,
		0x9C21E2EEDA29363CULL,
		0xE820A8B9D7994150ULL,
		0xC3E4F667609F10AEULL,
		0x9E6704E91A94E69BULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x601DF22EA8960FA4ULL,
		0xF588969B1948B3B6ULL,
		0xD70DFF55BE6BBF4FULL,
		0x6D2AF2F8E7C2314DULL,
		0x5AAC169EE1FBEE39ULL,
		0x8517EF717308A003ULL,
		0x225B307E488C7FECULL,
		0xE3F7AAAB038C5725ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3E89574604A162ULL,
		0x7F69D695B773CB94ULL,
		0x8A13A5F9B427980FULL,
		0xB209D4C4F416E6FEULL,
		0xCCCF0C97CC899870ULL,
		0x0863BE37CC4A3FD2ULL,
		0x366132C20D8F46EEULL,
		0x022E3C2E86EB3268ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3DF68D762916E42ULL,
		0x761EC00561D4E821ULL,
		0x4CFA595C0A442740ULL,
		0xBB211E33F3AB4A4FULL,
		0x8DDD0A07157255C8ULL,
		0x7CB43139A6BE6030ULL,
		0xEBF9FDBC3AFD38FEULL,
		0xE1C96E7C7CA124BCULL
	}};
	sign = 0;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x36AF3BA75F6111EDULL,
		0xECBC58CA1205EE23ULL,
		0x76F0397374609E49ULL,
		0x06C67A2014DF698DULL,
		0x794001764E053C9DULL,
		0x3D93857E25012969ULL,
		0x33C6ED96D276F21CULL,
		0x3355E3A5C9B2E575ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F802514D672133BULL,
		0x5D48BD19F36406E0ULL,
		0xF5A1C49E6FF77A31ULL,
		0xBE904C34C582834FULL,
		0xEF1D912CC2DF985CULL,
		0x0BBD29CAA29517F2ULL,
		0x257013CF0F774A69ULL,
		0xB42E9848D2D6EB8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF72F169288EEFEB2ULL,
		0x8F739BB01EA1E742ULL,
		0x814E74D504692418ULL,
		0x48362DEB4F5CE63DULL,
		0x8A2270498B25A440ULL,
		0x31D65BB3826C1176ULL,
		0x0E56D9C7C2FFA7B3ULL,
		0x7F274B5CF6DBF9E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x637F9475B427A3F2ULL,
		0xFEA411323C4FFB7AULL,
		0x8CF9493574F0D3C1ULL,
		0xC6399D6F12DE19B0ULL,
		0x6FBAB2E4D1FD2089ULL,
		0xDD63BF8D1EEAF34BULL,
		0x535C32C307FCAEC7ULL,
		0x15704860001B31A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C4F08ADC836F78ULL,
		0x71A3D8E0EA8B269BULL,
		0x96456AA503489F17ULL,
		0x83BD0FC719EB809BULL,
		0x81B4AACC755BB10DULL,
		0x095C244A3A0DFC20ULL,
		0xC43561A3AF5D571DULL,
		0xB6724A6DECAEB6CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CBAA3EAD7A4347AULL,
		0x8D00385151C4D4DEULL,
		0xF6B3DE9071A834AAULL,
		0x427C8DA7F8F29914ULL,
		0xEE0608185CA16F7CULL,
		0xD4079B42E4DCF72AULL,
		0x8F26D11F589F57AAULL,
		0x5EFDFDF2136C7AD0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC835966F6788BB37ULL,
		0x9B51009EF7AB209AULL,
		0x01B78EB287E64F8AULL,
		0x4A0EBEE4C24B306AULL,
		0xBE05EA49C4648A59ULL,
		0xCC502602FED6443DULL,
		0x3793A9586B3645C7ULL,
		0x4B75DC537C19B3EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB184C8C4EA7E5EULL,
		0x0D8B5058FE6768E5ULL,
		0x2A56563854C15DD2ULL,
		0x3AAE705EC80648A2ULL,
		0xCE9DE4EBFCF57E5EULL,
		0x816E98BFDB24F316ULL,
		0xAED753425291241DULL,
		0x2A1D961CFC403997ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE88411A6A29E3CD9ULL,
		0x8DC5B045F943B7B4ULL,
		0xD761387A3324F1B8ULL,
		0x0F604E85FA44E7C7ULL,
		0xEF68055DC76F0BFBULL,
		0x4AE18D4323B15126ULL,
		0x88BC561618A521AAULL,
		0x215846367FD97A52ULL
	}};
	sign = 0;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9783A631768647BULL,
		0xD41183C423B038FFULL,
		0xA5FC619580349130ULL,
		0xEC59B69CDBDD6166ULL,
		0x4FB44409B2917B7FULL,
		0x0CDBA8FCC2B09C4CULL,
		0x4254B6776BD56171ULL,
		0x1A98392170AA9A42ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA795A78066537583ULL,
		0x07EB52DE95320D44ULL,
		0xD5B859106B953490ULL,
		0xE92A5776666D53D9ULL,
		0x098B82DFAC695730ULL,
		0x63BB94342B2F8561ULL,
		0x91B34FE1FA04D7EEULL,
		0x8D2AC2E540B38487ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31E292E2B114EEF8ULL,
		0xCC2630E58E7E2BBBULL,
		0xD0440885149F5CA0ULL,
		0x032F5F2675700D8CULL,
		0x4628C12A0628244FULL,
		0xA92014C8978116EBULL,
		0xB0A1669571D08982ULL,
		0x8D6D763C2FF715BAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x29F9A5C757066855ULL,
		0x280A0786B4BFCCEEULL,
		0x1B96D65BA3F93F66ULL,
		0xFFCBF752F05EA4F6ULL,
		0xDD71DD8E74458E15ULL,
		0xB1D4A958D7269408ULL,
		0x5745639C865B80CFULL,
		0x34216499995BCE69ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x303376E5FF8F83EDULL,
		0x4E23BDF4414CE7F2ULL,
		0x9976689191049C24ULL,
		0xFD0A5C13EBAFFE35ULL,
		0x1BF0E1E1443139A6ULL,
		0xEAB389642B0CCF58ULL,
		0x5E0884D62F9D0ED2ULL,
		0x9777E067622359A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9C62EE15776E468ULL,
		0xD9E649927372E4FBULL,
		0x82206DCA12F4A341ULL,
		0x02C19B3F04AEA6C0ULL,
		0xC180FBAD3014546FULL,
		0xC7211FF4AC19C4B0ULL,
		0xF93CDEC656BE71FCULL,
		0x9CA98432373874C7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xABB1F7824D2D724BULL,
		0x86C9C80BC7DAE350ULL,
		0x9EA34FCA23659BBBULL,
		0xBFB4D85BF1D0065BULL,
		0x0439DD9DEA9795A4ULL,
		0x1159F35696B62FF9ULL,
		0xA8388005C0E5B800ULL,
		0xB7B7AB64D1F9FD47ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89674B73172DF77BULL,
		0x4E66B7017E84213DULL,
		0x90510150D745918BULL,
		0xC518297968AD9D29ULL,
		0xC9EEC0A9934C417FULL,
		0xF6899AE48398BB46ULL,
		0x39153E15AC90333EULL,
		0x8960A01D9843D3B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x224AAC0F35FF7AD0ULL,
		0x3863110A4956C213ULL,
		0x0E524E794C200A30ULL,
		0xFA9CAEE289226932ULL,
		0x3A4B1CF4574B5424ULL,
		0x1AD05872131D74B2ULL,
		0x6F2341F0145584C1ULL,
		0x2E570B4739B62996ULL
	}};
	sign = 0;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5CA8FA7474A9FF6EULL,
		0xE49C96E1C3182EC6ULL,
		0xF57AB676F27A4818ULL,
		0xC3D6E19F4314CD9AULL,
		0xD156CFCE3D57FC83ULL,
		0xFA64DD484DC0184CULL,
		0x14A77AC15EB87EBDULL,
		0x477CD78EE8940BFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB8B40E654DE223ULL,
		0x12C74E95A1C38AD7ULL,
		0xE9A9D1872B73B44FULL,
		0xBE088581D0DCAB2BULL,
		0x7C05CD934EFBF932ULL,
		0x9C0CC98810A4B79CULL,
		0xB8577598A8E890A1ULL,
		0xAF0107B10772F2A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FF046660F5C1D4BULL,
		0xD1D5484C2154A3EEULL,
		0x0BD0E4EFC70693C9ULL,
		0x05CE5C1D7238226FULL,
		0x5551023AEE5C0351ULL,
		0x5E5813C03D1B60B0ULL,
		0x5C500528B5CFEE1CULL,
		0x987BCFDDE121195CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEA359D38B7BC69D4ULL,
		0x23E1CCE2A66D27B7ULL,
		0xB983898A63DE8898ULL,
		0x661F111CE5DECC54ULL,
		0x06AFB23C09933F3BULL,
		0xC812ED59991D8347ULL,
		0x52A81FE15830ADB6ULL,
		0x6BA26E8AA5984F6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF274C105A9A280ULL,
		0x245D788D581DC6E3ULL,
		0x5D5BFE810B589CCBULL,
		0xFF8D1788284E46CFULL,
		0x75B812033F867447ULL,
		0x8720A27C2F875516ULL,
		0x27CB5C3214A1B083ULL,
		0x879A1A162EF79AB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E432877B212C754ULL,
		0xFF8454554E4F60D4ULL,
		0x5C278B095885EBCCULL,
		0x6691F994BD908585ULL,
		0x90F7A038CA0CCAF3ULL,
		0x40F24ADD69962E30ULL,
		0x2ADCC3AF438EFD33ULL,
		0xE408547476A0B4B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBD032F6B5C089D6FULL,
		0x57F4C1908A79E03AULL,
		0x8D27C1D6BC146081ULL,
		0x00FFC9BC6091DCC3ULL,
		0x01B95EC67E5299F9ULL,
		0x954D1FF03F676F56ULL,
		0xF775ED3CB78B94EAULL,
		0xE0C0FED003BDC67DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46C706B9841FD73AULL,
		0xD39357E94A18542DULL,
		0x3DB09F0C2DB44AD8ULL,
		0x6C0A8FBA18901438ULL,
		0x82C8896AE3AB4223ULL,
		0x98476AEC8E5BCAD0ULL,
		0x03389B7DD491CC0FULL,
		0x715DF9FD82A8AA33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x763C28B1D7E8C635ULL,
		0x846169A740618C0DULL,
		0x4F7722CA8E6015A8ULL,
		0x94F53A024801C88BULL,
		0x7EF0D55B9AA757D5ULL,
		0xFD05B503B10BA485ULL,
		0xF43D51BEE2F9C8DAULL,
		0x6F6304D281151C4AULL
	}};
	sign = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDA1F5CB673EE1A6AULL,
		0xB0BF203ACC7856B6ULL,
		0xCFFED4AEB0DE2954ULL,
		0x4FCCEA40932FB584ULL,
		0xFDA47BA972513389ULL,
		0xB4D15816B72ABEBFULL,
		0xC2CB6FC821952113ULL,
		0x8EA436A6A7FDAD45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B53D668126853FULL,
		0x59ED17E1081DFD87ULL,
		0x4F3BEAF8207F33B9ULL,
		0xAB385BAB408EDE4AULL,
		0x5E41D59EF4980ABDULL,
		0xCC7D3D1ED7FB0EFAULL,
		0x0C4F3BD117E3A790ULL,
		0x1B1AAC4C820C45F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB56A1F4FF2C7952BULL,
		0x56D20859C45A592FULL,
		0x80C2E9B6905EF59BULL,
		0xA4948E9552A0D73AULL,
		0x9F62A60A7DB928CBULL,
		0xE8541AF7DF2FAFC5ULL,
		0xB67C33F709B17982ULL,
		0x73898A5A25F1674CULL
	}};
	sign = 0;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x81FB0E723D863F0CULL,
		0x1CA5C1FD2081AAE0ULL,
		0xED00F8DA4D67D1CDULL,
		0x10AAC25786556BD1ULL,
		0xA1E1E538CD9AD2FDULL,
		0xC0B7FC7A674CDCBDULL,
		0xC2E5AC73C79DE50CULL,
		0x25B8B6C9716E1A6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF07CC46D203E6AD5ULL,
		0x1833780FBF31123EULL,
		0x19E3F4B4087A996FULL,
		0x0D67E5A876F1D6B1ULL,
		0xD9BB193789A1CC02ULL,
		0xC6DBBE368F7D6847ULL,
		0x5630C4A13CA09569ULL,
		0x5FDF8632290B0461ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x917E4A051D47D437ULL,
		0x047249ED615098A1ULL,
		0xD31D042644ED385EULL,
		0x0342DCAF0F639520ULL,
		0xC826CC0143F906FBULL,
		0xF9DC3E43D7CF7475ULL,
		0x6CB4E7D28AFD4FA2ULL,
		0xC5D930974863160AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9986151219189EA0ULL,
		0xEDD487C4ACECBCEBULL,
		0xE57C3FDF78845D60ULL,
		0xEA50BFEF28DFF9F7ULL,
		0xB985F80669A2AF8DULL,
		0x7DEFD8B4A51F3BDFULL,
		0xD639274D8F65A29EULL,
		0x5129A5CA438DF731ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B64D163B88AC91DULL,
		0xFFFE59E81FED3793ULL,
		0x3C51779488DD310CULL,
		0x238C01AF9471A23CULL,
		0x449EA8D8E12E6183ULL,
		0x845A4E94F0F72B7AULL,
		0x3B123089B3B9BB40ULL,
		0xD96CD1121438BB21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E2143AE608DD583ULL,
		0xEDD62DDC8CFF8558ULL,
		0xA92AC84AEFA72C53ULL,
		0xC6C4BE3F946E57BBULL,
		0x74E74F2D88744E0AULL,
		0xF9958A1FB4281065ULL,
		0x9B26F6C3DBABE75DULL,
		0x77BCD4B82F553C10ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD0913DD70D6D611CULL,
		0xD7CE110DB5AAB94AULL,
		0xFF60295C5B6E401FULL,
		0xF1026EB11935295BULL,
		0xEF2EA9D8DA587E66ULL,
		0xB48E07E19642FE6CULL,
		0xA17728A60C01CDC7ULL,
		0xC226F5424729C0BCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC2F1DBADB92611ULL,
		0x3E97AC3201AA0DC7ULL,
		0x3DD8DE458D2B53E5ULL,
		0xEFFF73B31BC00FAFULL,
		0xED6C769D41EEB90CULL,
		0x593632E0C986F54EULL,
		0x0EB189A66F8B459EULL,
		0xD6D54793FCBA434AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01CE4BFB5FB43B0BULL,
		0x993664DBB400AB83ULL,
		0xC1874B16CE42EC3AULL,
		0x0102FAFDFD7519ACULL,
		0x01C2333B9869C55AULL,
		0x5B57D500CCBC091EULL,
		0x92C59EFF9C768829ULL,
		0xEB51ADAE4A6F7D72ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E34C2CE64C4C52BULL,
		0xAA1006AE53F9038AULL,
		0x3FD3804128684F56ULL,
		0x2DA9E1D572028A36ULL,
		0xC55DD5EE72237673ULL,
		0x970D0B8DD91EFF57ULL,
		0x4AA0586E39B5B7E0ULL,
		0xDA5016465419A43DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C119605591C0DEAULL,
		0x4BDFF95FD6CFBDCBULL,
		0x07845D929A0F1992ULL,
		0xA400B854B0E1ACA1ULL,
		0x8FB4CB5CFD4FFC37ULL,
		0x59ED8371AF3A72C3ULL,
		0x5A5D82A7C073E0DAULL,
		0x4FB57AA959892B6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2232CC90BA8B741ULL,
		0x5E300D4E7D2945BEULL,
		0x384F22AE8E5935C4ULL,
		0x89A92980C120DD95ULL,
		0x35A90A9174D37A3BULL,
		0x3D1F881C29E48C94ULL,
		0xF042D5C67941D706ULL,
		0x8A9A9B9CFA9078D1ULL
	}};
	sign = 0;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C8662A759E64A2AULL,
		0xD6EE23A7CB5BF9F3ULL,
		0x0F0614936FCC518BULL,
		0x76F081323A467197ULL,
		0x301D82722DCE310CULL,
		0x1411BEDB1822CED3ULL,
		0xB4307DABC0F8DD69ULL,
		0x8EFD797944EF0485ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x446FE629A5A70D4AULL,
		0xB9342713572442B0ULL,
		0x3C02B2FDD0D936EBULL,
		0x5E02D4F1120461BDULL,
		0x95F4F5C96726EEE5ULL,
		0xA4264482021F1AE9ULL,
		0x4954C5B3544BE105ULL,
		0xCACD64E71FBA5801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28167C7DB43F3CE0ULL,
		0x1DB9FC947437B743ULL,
		0xD30361959EF31AA0ULL,
		0x18EDAC4128420FD9ULL,
		0x9A288CA8C6A74227ULL,
		0x6FEB7A591603B3E9ULL,
		0x6ADBB7F86CACFC63ULL,
		0xC43014922534AC84ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD8696B075ADBF66CULL,
		0x6BBBE655277D4170ULL,
		0x0DFC21FDCAC9E182ULL,
		0xBA6A05E492FF8A44ULL,
		0xD48AA1142816BCD0ULL,
		0xFD74010D3385218EULL,
		0xFBC70DC9DB7F38A0ULL,
		0x83F9F3FE7C1970A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7233EACB57F8856CULL,
		0xE899BCB5B8163516ULL,
		0x3FC8B82D463576F5ULL,
		0x3194DB7F8AA996E6ULL,
		0x81974E79441AA405ULL,
		0x2849A82DA14E55DDULL,
		0x82F4C2D7C3E8694FULL,
		0x6EB808782D0CB4D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6635803C02E37100ULL,
		0x8322299F6F670C5AULL,
		0xCE3369D084946A8CULL,
		0x88D52A650855F35DULL,
		0x52F3529AE3FC18CBULL,
		0xD52A58DF9236CBB1ULL,
		0x78D24AF21796CF51ULL,
		0x1541EB864F0CBBD2ULL
	}};
	sign = 0;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5F9406E4723FEF82ULL,
		0x2BB5751EB0305E6DULL,
		0xA7DB3896BE215790ULL,
		0x362EBB772D60D167ULL,
		0x3915D765EC1691E4ULL,
		0x0D0CF429371051F6ULL,
		0x3753B5EB4D5BB6A4ULL,
		0x6B3D873761FEBA5FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x439498BC059EBC00ULL,
		0x1DC466EE34E6CB33ULL,
		0x5B62731163482044ULL,
		0xF5329922379048A0ULL,
		0xDC23F7FB3626150EULL,
		0x894663F8790A4A39ULL,
		0x927D761B84F235C3ULL,
		0xF3A66B522A2A34ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BFF6E286CA13382ULL,
		0x0DF10E307B49933AULL,
		0x4C78C5855AD9374CULL,
		0x40FC2254F5D088C7ULL,
		0x5CF1DF6AB5F07CD5ULL,
		0x83C69030BE0607BCULL,
		0xA4D63FCFC86980E0ULL,
		0x77971BE537D485B3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCC1AA43667AAFD21ULL,
		0xB8A27E7E53104A71ULL,
		0xA2E58804691F533EULL,
		0x1CB3BA50E5704A95ULL,
		0xF3A54804172F6441ULL,
		0x583D35530AB87839ULL,
		0x4EDBC12FFCBBA0E0ULL,
		0x71F57592E66B975FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7D5796A23C445DULL,
		0x85437FE4C31B989AULL,
		0x68A48D62E9BE0081ULL,
		0xF5DD048256F82B9AULL,
		0xD3233C5F05C8E07AULL,
		0xB0C73E46874AC96EULL,
		0x689332079B937D5CULL,
		0xA5D1C54E2CB69FF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C9D4C9FC56EB8C4ULL,
		0x335EFE998FF4B1D7ULL,
		0x3A40FAA17F6152BDULL,
		0x26D6B5CE8E781EFBULL,
		0x20820BA5116683C6ULL,
		0xA775F70C836DAECBULL,
		0xE6488F2861282383ULL,
		0xCC23B044B9B4F766ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8347171C5EC360E6ULL,
		0xB87549429D5304BEULL,
		0xDF6C26F22529E86AULL,
		0xF074403FC896CEB6ULL,
		0xC680E698F113399CULL,
		0x5C04F43C7A15ADD2ULL,
		0x2FCBA6FA1CD88882ULL,
		0xA286FB660F456809ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6930DE6CBB1DE150ULL,
		0xD7A5DAB5A77C44AAULL,
		0xECA3025E14AD0A5AULL,
		0x70C1D5E866A567E7ULL,
		0x02681CD3EC8DBBB0ULL,
		0x1C8CEC854F2F25D4ULL,
		0xA2CFB0DEA996E2A7ULL,
		0x05F3D663D6DB53D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A1638AFA3A57F96ULL,
		0xE0CF6E8CF5D6C014ULL,
		0xF2C92494107CDE0FULL,
		0x7FB26A5761F166CEULL,
		0xC418C9C504857DECULL,
		0x3F7807B72AE687FEULL,
		0x8CFBF61B7341A5DBULL,
		0x9C932502386A1432ULL
	}};
	sign = 0;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x34A6856B0FA9628BULL,
		0xB89FD763322CABECULL,
		0x9EE057EC42B272E8ULL,
		0xA2D32A102126145DULL,
		0x8E3DEFB0892B1755ULL,
		0x7A26B5FFD35744BAULL,
		0xFFC319658450782AULL,
		0xF7A45D7455A5FDF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80612CBFF2A9A657ULL,
		0xEDBD03F85549B82BULL,
		0xEEB47994CA442614ULL,
		0xBBB95986054ADB4DULL,
		0xFCC75B73743B8A2EULL,
		0x03DA1FC8CD476FD9ULL,
		0x666404331366406CULL,
		0xF0C4AD9720AA873FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB44558AB1CFFBC34ULL,
		0xCAE2D36ADCE2F3C0ULL,
		0xB02BDE57786E4CD3ULL,
		0xE719D08A1BDB390FULL,
		0x9176943D14EF8D26ULL,
		0x764C9637060FD4E0ULL,
		0x995F153270EA37BEULL,
		0x06DFAFDD34FB76B1ULL
	}};
	sign = 0;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE481A1510046A261ULL,
		0xA39635195094D6AFULL,
		0x865E937D93AB74D2ULL,
		0x48C59BC8A5EB85D1ULL,
		0x83175C1867888EABULL,
		0x7FA86982446C0776ULL,
		0xAD0C3447D683D890ULL,
		0x80F79744167DD4F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x489E61684452604EULL,
		0x7F737E4F00FBE628ULL,
		0x55EC2709DAB8FB23ULL,
		0xFF84B70BC35EC006ULL,
		0xD197078DE424A436ULL,
		0x8597F99D81366033ULL,
		0x6F5966C1C5881A90ULL,
		0xCC3B8EAD334AF246ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BE33FE8BBF44213ULL,
		0x2422B6CA4F98F087ULL,
		0x30726C73B8F279AFULL,
		0x4940E4BCE28CC5CBULL,
		0xB180548A8363EA74ULL,
		0xFA106FE4C335A742ULL,
		0x3DB2CD8610FBBDFFULL,
		0xB4BC0896E332E2B3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE85AA5439D5BBF3BULL,
		0xB1416EA188735C55ULL,
		0x75B9D832C7BBA2F2ULL,
		0xFF00421C44AD0DEAULL,
		0xAC10A593A749A6D9ULL,
		0xD59D54B46E4BB152ULL,
		0xD2E6C39068F1C0D7ULL,
		0xA33181B10503006EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C2B0945134A9EC4ULL,
		0xDC0DCD902C8A0708ULL,
		0x79B5F56865ECE9AFULL,
		0xC0C13F4DDCC0519DULL,
		0xEC5AD6A7B597D735ULL,
		0x1BF04B9CF2F0658FULL,
		0x6808EF1A693FE0ECULL,
		0xDBADBC4EAE485597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C2F9BFE8A112077ULL,
		0xD533A1115BE9554DULL,
		0xFC03E2CA61CEB942ULL,
		0x3E3F02CE67ECBC4CULL,
		0xBFB5CEEBF1B1CFA4ULL,
		0xB9AD09177B5B4BC2ULL,
		0x6ADDD475FFB1DFEBULL,
		0xC783C56256BAAAD7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF08B403A0EAD44DFULL,
		0xD5469C337DD4AC3CULL,
		0x751BB5319CF95D35ULL,
		0xDFFB3CBFCCC438F9ULL,
		0x11309D98D283AC84ULL,
		0xDA7A145706D99AF3ULL,
		0xF75BC773511621C8ULL,
		0xD264973F05AB20FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0A90E07FFBD2D1ULL,
		0x434060D5C57EDC76ULL,
		0x185B27C483381F35ULL,
		0x320194D5C270C503ULL,
		0xFCEBE5060BA4328DULL,
		0xB14490D96BB4BDDBULL,
		0xD0B31296A3ED2D16ULL,
		0x41910F5362F931CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9580AF598EB1720EULL,
		0x92063B5DB855CFC6ULL,
		0x5CC08D6D19C13E00ULL,
		0xADF9A7EA0A5373F6ULL,
		0x1444B892C6DF79F7ULL,
		0x2935837D9B24DD17ULL,
		0x26A8B4DCAD28F4B2ULL,
		0x90D387EBA2B1EF33ULL
	}};
	sign = 0;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x11887ABE1F0D1BDBULL,
		0xC7E2688F354B2B5FULL,
		0x0D5CC4979988C995ULL,
		0x664FD71E5F28C6EEULL,
		0xCD254623F49BE158ULL,
		0xA2778F0BDB2D72DAULL,
		0x42898E05A7E0D117ULL,
		0x4A7FECA72640C7EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD839348E8DA100CBULL,
		0x77564F7E8883D81AULL,
		0xC643A3AA3205144EULL,
		0x50D4716889345ACBULL,
		0x29834F849C0B566BULL,
		0x04B7BD469BE9A942ULL,
		0xC1D76898718056F5ULL,
		0x4C490D2346FF75D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x394F462F916C1B10ULL,
		0x508C1910ACC75344ULL,
		0x471920ED6783B547ULL,
		0x157B65B5D5F46C22ULL,
		0xA3A1F69F58908AEDULL,
		0x9DBFD1C53F43C998ULL,
		0x80B2256D36607A22ULL,
		0xFE36DF83DF415215ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0F0BDB3AF0491EEBULL,
		0xEF1BBA7F6E8F536FULL,
		0x90957836E7956DFAULL,
		0x1175F1F18C34E3FAULL,
		0x90A271EC4430A77FULL,
		0x1D6B5C43E0EDF9EAULL,
		0xB2BE4BA5B28C44E4ULL,
		0xA1354703A74284D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x574FFBC559E7A69EULL,
		0xB47105B6C887E352ULL,
		0xDD377E8F996117E9ULL,
		0x344F803DCB43AF76ULL,
		0x6DBBE0295371BC57ULL,
		0xCA13EE99EFD66CC9ULL,
		0x330FB9EACD454E03ULL,
		0xE39E634E3B9CDF94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7BBDF759661784DULL,
		0x3AAAB4C8A607701CULL,
		0xB35DF9A74E345611ULL,
		0xDD2671B3C0F13483ULL,
		0x22E691C2F0BEEB27ULL,
		0x53576DA9F1178D21ULL,
		0x7FAE91BAE546F6E0ULL,
		0xBD96E3B56BA5A53DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8ACB8C29C7F2E5CAULL,
		0x999A42D40C76996BULL,
		0x0E6DA37045F1305AULL,
		0xD0A68EDF1AA64029ULL,
		0x7A40C7D32C5F57D7ULL,
		0x1D82DF7C6D51E555ULL,
		0xF033E882DF0E6CD3ULL,
		0xF0BD53B9848DB27CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x915C95C68F7778B3ULL,
		0xDAC9E2E6E293CD00ULL,
		0x3F9179FEA327E17DULL,
		0x3BCB8DE820210228ULL,
		0xF04A0AC239DE0E0CULL,
		0x7A9FCE7D44702825ULL,
		0xF5CEB2C96999C1DBULL,
		0xFB0657BB721EA049ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF96EF663387B6D17ULL,
		0xBED05FED29E2CC6AULL,
		0xCEDC2971A2C94EDCULL,
		0x94DB00F6FA853E00ULL,
		0x89F6BD10F28149CBULL,
		0xA2E310FF28E1BD2FULL,
		0xFA6535B97574AAF7ULL,
		0xF5B6FBFE126F1232ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7664762364BB8AD3ULL,
		0xD3DE8E1FCA03498DULL,
		0x6965B7B01EF6F600ULL,
		0x41D3733F68E996BFULL,
		0x96792D101F316F18ULL,
		0x97114956D918962EULL,
		0xCDCCB2EBE5AD19D2ULL,
		0x33558E7F2CB00A22ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9390426B37D4B5FAULL,
		0x59BFFD655BB745B4ULL,
		0x084EBD3B55EF67E0ULL,
		0x2E52F47E35CB6021ULL,
		0xE6E47126162EDBB9ULL,
		0x6275BEE0631F7541ULL,
		0x7E1D84003FC11ED7ULL,
		0x9E751F14A2D3153BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2D433B82CE6D4D9ULL,
		0x7A1E90BA6E4C03D8ULL,
		0x6116FA74C9078E20ULL,
		0x13807EC1331E369EULL,
		0xAF94BBEA0902935FULL,
		0x349B8A7675F920ECULL,
		0x4FAF2EEBA5EBFAFBULL,
		0x94E06F6A89DCF4E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3D3284620A180172ULL,
		0x294A17259C8E6AC8ULL,
		0x23830C4DFFFB06A4ULL,
		0x648B1D495D02A649ULL,
		0x4248DBCB9499E93AULL,
		0x9498207AC5DF411DULL,
		0x9B686DFB2852AC29ULL,
		0x74B48C6B49DB05E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x474008E48ACA402AULL,
		0x7E732804272CEDC4ULL,
		0x7EE2021D40D897F6ULL,
		0xFE2888718DDEE6E5ULL,
		0xBE8BBBBDD31281E2ULL,
		0x69DCCE85BB4833A9ULL,
		0x7F3B4D30CDA225F9ULL,
		0xE1B510886FFF9877ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5F27B7D7F4DC148ULL,
		0xAAD6EF2175617D03ULL,
		0xA4A10A30BF226EADULL,
		0x666294D7CF23BF63ULL,
		0x83BD200DC1876757ULL,
		0x2ABB51F50A970D73ULL,
		0x1C2D20CA5AB08630ULL,
		0x92FF7BE2D9DB6D6FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5336C1CC002D63D1ULL,
		0x2EB4FE5AA6E49195ULL,
		0x4136620AFEAAF0CFULL,
		0x0843E961684FEBF7ULL,
		0xE47380FE6A542A6CULL,
		0xF16B27042E94CD47ULL,
		0x018E3EE6E65D6350ULL,
		0x2A3D0225117BFFD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A1F7D7DE56F572AULL,
		0x36F5EDDA3FF105CBULL,
		0x37736DD8EA782F39ULL,
		0x184CD14007B5CB67ULL,
		0x917FA34174D8311AULL,
		0xBB8DC8C18C6E0B3EULL,
		0xA3529F3A65E107F4ULL,
		0xCC41C688046CF275ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB917444E1ABE0CA7ULL,
		0xF7BF108066F38BC9ULL,
		0x09C2F4321432C195ULL,
		0xEFF71821609A2090ULL,
		0x52F3DDBCF57BF951ULL,
		0x35DD5E42A226C209ULL,
		0x5E3B9FAC807C5B5CULL,
		0x5DFB3B9D0D0F0D62ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0644E05442959A11ULL,
		0x8EFE45D1972F4B23ULL,
		0x4031FC31D47E2D55ULL,
		0x59D133720C4C3ECAULL,
		0x5ABAC1E4E1D5A5CCULL,
		0x34458948D1484D1AULL,
		0x358BF81A297AEA22ULL,
		0xF5DBFCC48D2D7447ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB643B64692576EAULL,
		0x4ACD1BD66DACBBEEULL,
		0xCA4F6B98F0596A30ULL,
		0x4C2918FC2E2FF0B9ULL,
		0xE738222FA199BF14ULL,
		0x6232DA5DC8BD7991ULL,
		0xBE1852E12C54FA85ULL,
		0x8981F72922447743ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AE0A4EFD9702327ULL,
		0x443129FB29828F34ULL,
		0x75E29098E424C325ULL,
		0x0DA81A75DE1C4E10ULL,
		0x73829FB5403BE6B8ULL,
		0xD212AEEB088AD388ULL,
		0x7773A538FD25EF9CULL,
		0x6C5A059B6AE8FD03ULL
	}};
	sign = 0;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4A1FD98BE8FB7C3DULL,
		0x1C19FFAF56429566ULL,
		0xD08743A34AF8A404ULL,
		0xB5B5F8662E526892ULL,
		0x132FC16A45173569ULL,
		0xE5F198625827AA0DULL,
		0xCE72D85C6D8BBA97ULL,
		0x343F80139A8ECDDEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B22D75D17012B57ULL,
		0x727CBB95F29B9086ULL,
		0x2D64788329B72BADULL,
		0xF25D27EA3F0A6314ULL,
		0xF7983D6539779BDDULL,
		0xA6C0E9BA2A6508AAULL,
		0x65F4C4E5DEF7EBF8ULL,
		0x2CBF8AACEEA4EA4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEFD022ED1FA50E6ULL,
		0xA99D441963A704DFULL,
		0xA322CB2021417856ULL,
		0xC358D07BEF48057EULL,
		0x1B9784050B9F998BULL,
		0x3F30AEA82DC2A162ULL,
		0x687E13768E93CE9FULL,
		0x077FF566ABE9E393ULL
	}};
	sign = 0;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6196297037B48B14ULL,
		0xC073F7B87E731766ULL,
		0x2C001D15F49EACD6ULL,
		0x7AA816516F411A86ULL,
		0x4B9628713D8A8707ULL,
		0x142AC4679625522DULL,
		0xE48A8E24CBB8494CULL,
		0x337BE47A97FD7D02ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF3FC0DE19076C3BULL,
		0x6DF1B1F9C82772B8ULL,
		0x50C5C200EACEFEE7ULL,
		0xD1F4C8FD02441D03ULL,
		0x8072780D53CBE5B0ULL,
		0xA2B5A3CCB8FA86F1ULL,
		0xB43FCF080B7BB06DULL,
		0xB5CEAB5E07D8EFCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA25668921EAD1ED9ULL,
		0x528245BEB64BA4ADULL,
		0xDB3A5B1509CFADEFULL,
		0xA8B34D546CFCFD82ULL,
		0xCB23B063E9BEA156ULL,
		0x7175209ADD2ACB3BULL,
		0x304ABF1CC03C98DEULL,
		0x7DAD391C90248D34ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x317D47F31F86EB3DULL,
		0x8A9647044310DF66ULL,
		0x815E1E07F04396D2ULL,
		0xED6EE64F61FEC9EBULL,
		0x3613941ABC2F0DCAULL,
		0xF99A05D12294A945ULL,
		0x3E0803F807E5C876ULL,
		0x6C1A2A9BC12E8D8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE3BB5492DE3D11ULL,
		0x0EC5FE301160A012ULL,
		0x73D05AC2AB3211C7ULL,
		0x2457BC55B8DDD7B5ULL,
		0x028FFF427DB44222ULL,
		0x609850924D91C390ULL,
		0xF99F664A9871042FULL,
		0x4CA3594A95CBD141ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81998C9E8CA8AE2CULL,
		0x7BD048D431B03F53ULL,
		0x0D8DC3454511850BULL,
		0xC91729F9A920F236ULL,
		0x338394D83E7ACBA8ULL,
		0x9901B53ED502E5B5ULL,
		0x44689DAD6F74C447ULL,
		0x1F76D1512B62BC4BULL
	}};
	sign = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x46DF754562F431C7ULL,
		0x832248FD19FC2798ULL,
		0x2BE860B26FE862B9ULL,
		0xB377B09B69FBBD3CULL,
		0xCFF7F2BE1C3607B5ULL,
		0x65C9A84563D224F3ULL,
		0x59CE48DF14EC1EE4ULL,
		0x7B07F1D83A4F52EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12295C1FD164E882ULL,
		0x8F24A2FAF43064E1ULL,
		0x2C4F264939DF37D1ULL,
		0xEC48BC3F5E034604ULL,
		0x0D9BCBD15A7F53CDULL,
		0xADA223786A82B82CULL,
		0xA195A2BC788D772FULL,
		0x9C5D59A887F7CE2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34B61925918F4945ULL,
		0xF3FDA60225CBC2B7ULL,
		0xFF993A6936092AE7ULL,
		0xC72EF45C0BF87737ULL,
		0xC25C26ECC1B6B3E7ULL,
		0xB82784CCF94F6CC7ULL,
		0xB838A6229C5EA7B4ULL,
		0xDEAA982FB25784BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0DDABC4CCB49CB05ULL,
		0x51CE56E0D3378822ULL,
		0x2D9939136B2B4713ULL,
		0xF0D137F88070F5DAULL,
		0x2951FAA3BA746F6AULL,
		0x70590FC1A1F58F5AULL,
		0x5E6EC48F1BA3DFC2ULL,
		0x54F377EC847C4F20ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F16A9C22FC45E57ULL,
		0xF50D2F0A3320BA5AULL,
		0xE99D15D50ECE2B46ULL,
		0xC156F9BFD5894AC5ULL,
		0x3347263490427E2EULL,
		0x1BE5DC69109CB8F4ULL,
		0x2C26C923077B9514ULL,
		0x600262587687B59AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEC4128A9B856CAEULL,
		0x5CC127D6A016CDC7ULL,
		0x43FC233E5C5D1BCCULL,
		0x2F7A3E38AAE7AB14ULL,
		0xF60AD46F2A31F13CULL,
		0x547333589158D665ULL,
		0x3247FB6C14284AAEULL,
		0xF4F115940DF49986ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD72ADF0BAE5466C1ULL,
		0x132388AE45BDFE03ULL,
		0x22997BAC15000B27ULL,
		0x0EC023DDC202EA7AULL,
		0x3F94740F20FD1D3FULL,
		0x3E975EC6C712266AULL,
		0x7C8B1701D9EE3365ULL,
		0xD97C211702D5B2C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F4064277CB9EFEULL,
		0x98FE250BA306161BULL,
		0x55B98ACF09E55C7AULL,
		0xF46EB0C587E872AAULL,
		0xF1F40127E5542888ULL,
		0x30A18E7DECBACF48ULL,
		0xDBA69295EEB69825ULL,
		0xC5DD0888B70D791DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F36D8C93688C7C3ULL,
		0x7A2563A2A2B7E7E8ULL,
		0xCCDFF0DD0B1AAEACULL,
		0x1A5173183A1A77CFULL,
		0x4DA072E73BA8F4B6ULL,
		0x0DF5D048DA575721ULL,
		0xA0E4846BEB379B40ULL,
		0x139F188E4BC839ABULL
	}};
	sign = 0;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA4706CBE49AED5E9ULL,
		0x86D947808649744CULL,
		0x34F6107764DA4F1EULL,
		0xA319E846338E213AULL,
		0x9792DB89A6FC393BULL,
		0xD2DE6BF8115D9C8CULL,
		0x4BC75CE946AD4EA3ULL,
		0x9977A484AB62C99CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D05871E332AFE2AULL,
		0xE22C8CD4B15FD04EULL,
		0xD2BB28C6588C0BC9ULL,
		0x2FB158C61CAC58B9ULL,
		0xDE9B215673ACE6D6ULL,
		0x271720D08432EE54ULL,
		0xF803B39C2D5628F1ULL,
		0x7D24EC30EDB3148AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x076AE5A01683D7BFULL,
		0xA4ACBAABD4E9A3FEULL,
		0x623AE7B10C4E4354ULL,
		0x73688F8016E1C880ULL,
		0xB8F7BA33334F5265ULL,
		0xABC74B278D2AAE37ULL,
		0x53C3A94D195725B2ULL,
		0x1C52B853BDAFB511ULL
	}};
	sign = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39F965CBF03B0044ULL,
		0xCFD75101E618BBDCULL,
		0xA63DBF6B6AAA3F8AULL,
		0x99BB7519C2D809A5ULL,
		0x09E7ED6894660659ULL,
		0x6E78FE6EF60B5C72ULL,
		0xD7F9D6D0ACB4525DULL,
		0x98A8BCBD3F6F5458ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D71FFD53EFE0D4ULL,
		0x79AD886C0E4048E3ULL,
		0x20990BC6028491E0ULL,
		0xD0153660C214A11EULL,
		0x99E2338C39105A02ULL,
		0xEE9B51B5DAEDE451ULL,
		0x607E0E891EDF91B0ULL,
		0xD9B19D6B585AEE3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC22245CE9C4B1F70ULL,
		0x5629C895D7D872F8ULL,
		0x85A4B3A56825ADAAULL,
		0xC9A63EB900C36887ULL,
		0x7005B9DC5B55AC56ULL,
		0x7FDDACB91B1D7820ULL,
		0x777BC8478DD4C0ACULL,
		0xBEF71F51E7146619ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE5827631875C965FULL,
		0x97FC58FE4AC5E4D5ULL,
		0x64E56A2DCE9F16C0ULL,
		0xD794609D3C828D21ULL,
		0xF89454F5CBB1CFD4ULL,
		0xA58BF5E69CAD3383ULL,
		0x8747280C3FDD155CULL,
		0x82FB46A5F33E73EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x910D83848CA415C7ULL,
		0xACCF616BA118B809ULL,
		0xA2ACB6590ACD15C1ULL,
		0xBB11C096FA293C5DULL,
		0xAF26B7ACC0BC2DC1ULL,
		0xB3BCBCB2F69F1C55ULL,
		0x27A184620BA919B8ULL,
		0xD4B782E997529BBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5474F2ACFAB88098ULL,
		0xEB2CF792A9AD2CCCULL,
		0xC238B3D4C3D200FEULL,
		0x1C82A006425950C3ULL,
		0x496D9D490AF5A213ULL,
		0xF1CF3933A60E172EULL,
		0x5FA5A3AA3433FBA3ULL,
		0xAE43C3BC5BEBD832ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x61DD89FAF764504DULL,
		0x47122353A7E8E315ULL,
		0xBDC57D556CB48894ULL,
		0xA8F6036FE052BE01ULL,
		0xAE60A101407259A4ULL,
		0x5AB6CE3FD844A91AULL,
		0x977EA6F59ACC0C31ULL,
		0x6CFD4AC120A112CCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x13BB2DA4437EECDDULL,
		0xCE9F8E1D066E43F8ULL,
		0x0B57780AAE1CDADEULL,
		0x0B59D77043A975D7ULL,
		0xC0F2FBC8C97B0A0FULL,
		0x51D426EB0C9B9552ULL,
		0xD749815C8E95478FULL,
		0xE11BA311165FEADFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E225C56B3E56370ULL,
		0x78729536A17A9F1DULL,
		0xB26E054ABE97ADB5ULL,
		0x9D9C2BFF9CA9482AULL,
		0xED6DA53876F74F95ULL,
		0x08E2A754CBA913C7ULL,
		0xC03525990C36C4A2ULL,
		0x8BE1A7B00A4127ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE7D4EE04538ED1E0ULL,
		0x5724CE7CF37957FCULL,
		0xD150ACD287F295FEULL,
		0x7A8D44BF67BA0D2EULL,
		0x31BD96920D045DB4ULL,
		0x0D846AA07E3A53B4ULL,
		0xDB6785DDAD83E421ULL,
		0xFA650579C681C3CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x826B26CE6CCBAA3DULL,
		0x111C5412C104B729ULL,
		0xB0D33EB055C8FA49ULL,
		0xE296730F508BDEFFULL,
		0x942B44A7D39F8E7FULL,
		0x765DAD70E7FA5AFAULL,
		0x4BCA79698C48F871ULL,
		0xE2CF1934D80597EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6569C735E6C327A3ULL,
		0x46087A6A3274A0D3ULL,
		0x207D6E2232299BB5ULL,
		0x97F6D1B0172E2E2FULL,
		0x9D9251EA3964CF34ULL,
		0x9726BD2F963FF8B9ULL,
		0x8F9D0C74213AEBAFULL,
		0x1795EC44EE7C2BE0ULL
	}};
	sign = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6FEF2FF020C6EF46ULL,
		0x2EBABF13469243DBULL,
		0x18F1558CC92B19B2ULL,
		0x5BC17748B72640EDULL,
		0xE4D179E2602210E5ULL,
		0xFAAE5F84923B51F2ULL,
		0xC5455D7DA669E7E1ULL,
		0xA3E00F68B71B274AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA674F282229CD9ULL,
		0xD76528F3CCB25DCDULL,
		0xC2E72686766C4E67ULL,
		0x58B32E825BFD241FULL,
		0x5549035E5812005CULL,
		0x42601120515409D2ULL,
		0x9463B9489379FA29ULL,
		0xE6FAF76A1986E4A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA348BAFD9EA4526DULL,
		0x5755961F79DFE60DULL,
		0x560A2F0652BECB4AULL,
		0x030E48C65B291CCDULL,
		0x8F88768408101089ULL,
		0xB84E4E6440E74820ULL,
		0x30E1A43512EFEDB8ULL,
		0xBCE517FE9D9442A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC7055267814BA9E9ULL,
		0x6139C36E0FA360F2ULL,
		0x234F0DF97FF31154ULL,
		0x15DB0A23431465C9ULL,
		0x1AB5C24C5C538400ULL,
		0x23BD131027E78299ULL,
		0x7FE634E4B4A63C57ULL,
		0x6BF940A57908AD7AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E920C072681ED7ULL,
		0xA2C754CFEFD5A88FULL,
		0xBAA331E01A5A3AC9ULL,
		0x11C87C87F84ADB20ULL,
		0x45ED112A837B5D4AULL,
		0xA2FF5CD5CE880837ULL,
		0xC9224919B96400D9ULL,
		0xD2064E18DC284643ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x431C31A70EE38B12ULL,
		0xBE726E9E1FCDB863ULL,
		0x68ABDC196598D68AULL,
		0x04128D9B4AC98AA8ULL,
		0xD4C8B121D8D826B6ULL,
		0x80BDB63A595F7A61ULL,
		0xB6C3EBCAFB423B7DULL,
		0x99F2F28C9CE06736ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD72D45C15F15C7B0ULL,
		0xB150A3381019C925ULL,
		0x0CB04B312E225EFEULL,
		0x23C04B65CCBE12F7ULL,
		0xA6FB7AF274090EF3ULL,
		0xE794DC22E4B81F5BULL,
		0x4C25F4AFAACA61E9ULL,
		0xC33A37B3DF7B1E80ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x178673C340C48E55ULL,
		0x2E32A3EA9D762918ULL,
		0x3A108F2645093BD4ULL,
		0x427FBFC59297032CULL,
		0xEF5105A7CEDCA174ULL,
		0x78A1E1F63D1540EAULL,
		0x90BE08FE79147BB0ULL,
		0xFEF308E2F841246BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFA6D1FE1E51395BULL,
		0x831DFF4D72A3A00DULL,
		0xD29FBC0AE919232AULL,
		0xE1408BA03A270FCAULL,
		0xB7AA754AA52C6D7EULL,
		0x6EF2FA2CA7A2DE70ULL,
		0xBB67EBB131B5E639ULL,
		0xC4472ED0E739FA14ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x88834CF69F5358C3ULL,
		0x6838279593F9BE1BULL,
		0x5CF5E77DBB889136ULL,
		0xCF50C2716013F5E7ULL,
		0x6D319188E50323C7ULL,
		0x5692DCCDA81DB23EULL,
		0xE8369ACD404F989FULL,
		0x772FD669C29A658BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x23BB03D61A523637ULL,
		0x31C9F407241E5800ULL,
		0x382C93710A3E1D7BULL,
		0xB29EF6CF4721E734ULL,
		0xC509AAD0484CD8DBULL,
		0x9E9ECF2070F4A21FULL,
		0xCC4988DE9CAD2C51ULL,
		0xF4B75F1DBEAA97F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64C849208501228CULL,
		0x366E338E6FDB661BULL,
		0x24C9540CB14A73BBULL,
		0x1CB1CBA218F20EB3ULL,
		0xA827E6B89CB64AECULL,
		0xB7F40DAD3729101EULL,
		0x1BED11EEA3A26C4DULL,
		0x8278774C03EFCD99ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFB0D8071BD4BF005ULL,
		0x324832C0C47FB07BULL,
		0xA74887EFE316C819ULL,
		0x4CA40AB3056A2C1FULL,
		0x9A3B011A5A744AE1ULL,
		0xE5FDB1905E884B7EULL,
		0xB47956511B329208ULL,
		0x340D831657497422ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CB488C9FB84BB28ULL,
		0xC3D5E6CC1611D3A2ULL,
		0xD66F62D642B539DEULL,
		0x427286846DEE9046ULL,
		0x97856F025574FB21ULL,
		0xEC46BAE3FFFF4364ULL,
		0x458E7196EDDC83DEULL,
		0xB1A79FB52C467299ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E58F7A7C1C734DDULL,
		0x6E724BF4AE6DDCD9ULL,
		0xD0D92519A0618E3AULL,
		0x0A31842E977B9BD8ULL,
		0x02B5921804FF4FC0ULL,
		0xF9B6F6AC5E89081AULL,
		0x6EEAE4BA2D560E29ULL,
		0x8265E3612B030189ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3C9AB9ECA71096C9ULL,
		0xF9F83B2EFD05E8C9ULL,
		0x265CD4585A50908DULL,
		0x0DC226195E6EF730ULL,
		0xBB367F9B9DC054DBULL,
		0x6BC3B21B49F9D552ULL,
		0xE7CE79FF5FBAC43DULL,
		0x5F6294E99EA6633FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD838EF851934E10ULL,
		0x4A4526BE3F10F808ULL,
		0x7DC0B09E55DBB72AULL,
		0x0EF8C4A04F9DC1E1ULL,
		0x1D0117813CC2B14AULL,
		0x44E757362810880CULL,
		0x0ECA7A0ED6D366D9ULL,
		0xD25C45F1C4E71A84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F172AF4557D48B9ULL,
		0xAFB31470BDF4F0C0ULL,
		0xA89C23BA0474D963ULL,
		0xFEC961790ED1354EULL,
		0x9E35681A60FDA390ULL,
		0x26DC5AE521E94D46ULL,
		0xD903FFF088E75D64ULL,
		0x8D064EF7D9BF48BBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6137718B87E6D4EDULL,
		0x99F2D09F3396687EULL,
		0xC05A5D7DB90EBE20ULL,
		0x829287B51974DAD5ULL,
		0xB8DF9DC37377BEDDULL,
		0x7F794E23D72F392EULL,
		0x6F5DF629395AD51DULL,
		0x336ED3BE15E234C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8D8954FBFCB437FULL,
		0x2A35A5704E6A0F41ULL,
		0x86A227324FAEC815ULL,
		0x5C51295A4E041F65ULL,
		0xF61679E09DAF44D7ULL,
		0xB8C2280BE4ECAABEULL,
		0x6C13310AF2D09652ULL,
		0x46E694EBF63121BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x985EDC3BC81B916EULL,
		0x6FBD2B2EE52C593CULL,
		0x39B8364B695FF60BULL,
		0x26415E5ACB70BB70ULL,
		0xC2C923E2D5C87A06ULL,
		0xC6B72617F2428E6FULL,
		0x034AC51E468A3ECAULL,
		0xEC883ED21FB11304ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C3DC7736F2BA12CULL,
		0x4D0C626EBEDCC7C3ULL,
		0x8002B7BA425840D6ULL,
		0xAF4C1F3DC9F899AAULL,
		0x571590FA5A34167BULL,
		0xEE76487F5F778DF4ULL,
		0x8CEBA338D4A9578BULL,
		0xD73C13EE2582F683ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x39268BB149E98ABDULL,
		0x31DFAC831AD9DED8ULL,
		0x69BA3E23B091B0A1ULL,
		0xE180E900795B0536ULL,
		0x53434A941242298AULL,
		0xF585934E9CADE9E9ULL,
		0x67D3EEF57A30AE3CULL,
		0x970690EECA41BF71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33173BC22542166FULL,
		0x1B2CB5EBA402E8EBULL,
		0x1648799691C69035ULL,
		0xCDCB363D509D9474ULL,
		0x03D2466647F1ECF0ULL,
		0xF8F0B530C2C9A40BULL,
		0x2517B4435A78A94EULL,
		0x403582FF5B413712ULL
	}};
	sign = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0518FD5D56B3BDDULL,
		0x01A1FE094118F629ULL,
		0xDADD31FD797F64F5ULL,
		0xC753A845F85A1D4DULL,
		0xC4258C5A556E9088ULL,
		0x737593012E5671E8ULL,
		0xFC342A4DB2F2AF2EULL,
		0x8613B33B62CA4CE0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEFCF97C57CD4F21ULL,
		0x1A487302D1704F5AULL,
		0xAABA1C9E7ADD1085ULL,
		0xB2508BDDF4EA1E48ULL,
		0xA065C76052ACA173ULL,
		0xC333C0E262C22003ULL,
		0x30683F71A9C1FA88ULL,
		0xD3145D87A3D80A5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x115496597D9DECBCULL,
		0xE7598B066FA8A6CFULL,
		0x3023155EFEA2546FULL,
		0x15031C68036FFF05ULL,
		0x23BFC4FA02C1EF15ULL,
		0xB041D21ECB9451E5ULL,
		0xCBCBEADC0930B4A5ULL,
		0xB2FF55B3BEF24285ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD2504E846C2E5DD0ULL,
		0x04E1E4E46FC7A724ULL,
		0x0A7BCC56B5FB1019ULL,
		0x5501EAF64FF6B926ULL,
		0x0CD88F37E11470D9ULL,
		0xAB4E33094B4FE48AULL,
		0xC03DD342DF98BB2FULL,
		0xAD143F2246037446ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x162B4160AFEC64DEULL,
		0x8307AA1D118A89CDULL,
		0x2A0C04A4FF04B2E0ULL,
		0x52774379379F6875ULL,
		0x8A3B029CC36C8933ULL,
		0x4062D78A8B5C4132ULL,
		0x6BDCE46631F5280DULL,
		0x5EDE0EB64200E745ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC250D23BC41F8F2ULL,
		0x81DA3AC75E3D1D57ULL,
		0xE06FC7B1B6F65D38ULL,
		0x028AA77D185750B0ULL,
		0x829D8C9B1DA7E7A6ULL,
		0x6AEB5B7EBFF3A357ULL,
		0x5460EEDCADA39322ULL,
		0x4E36306C04028D01ULL
	}};
	sign = 0;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x59E6A01A7387A3F8ULL,
		0x591ECB334508F21EULL,
		0x4C3A36EB23CDA17DULL,
		0x080AC0BE245FBF85ULL,
		0x7AADB6EF67D534B4ULL,
		0x16ED1FEC7038505BULL,
		0xE1C7DB54D658BAD8ULL,
		0x0C03C8E2DCCC940CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4506B68BF349692ULL,
		0x1D3E0744DDDC8645ULL,
		0x236C5416319A0C76ULL,
		0xC781AF34E1C1EB8FULL,
		0x5BEC1DBED7FA01CBULL,
		0x7AED717449234D72ULL,
		0xE0B8A96F6ED44FD3ULL,
		0xC9AE890B933E91C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x959634B1B4530D66ULL,
		0x3BE0C3EE672C6BD8ULL,
		0x28CDE2D4F2339507ULL,
		0x40891189429DD3F6ULL,
		0x1EC199308FDB32E8ULL,
		0x9BFFAE78271502E9ULL,
		0x010F31E567846B04ULL,
		0x42553FD7498E0246ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x99E509CD5E294D10ULL,
		0xC6009392C9CFEEC3ULL,
		0x1AC4CEDDBC2F6A6BULL,
		0xE68F9618AD5C4AECULL,
		0x533039BABA0AF246ULL,
		0x4A10F321BBCF3E33ULL,
		0x5C899D27B1778E9FULL,
		0xDB0EEA3AE6E1D9AFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0049FD9840FAE588ULL,
		0x97A53908A813BD4BULL,
		0xAE93ABEABF529914ULL,
		0x668DC9C5848528BBULL,
		0xBD434EE7DC7CF033ULL,
		0xB06D9A48CCEB1079ULL,
		0xD1C90FDCD256AD69ULL,
		0x5C38D50A2A6B18A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x999B0C351D2E6788ULL,
		0x2E5B5A8A21BC3178ULL,
		0x6C3122F2FCDCD157ULL,
		0x8001CC5328D72230ULL,
		0x95ECEAD2DD8E0213ULL,
		0x99A358D8EEE42DB9ULL,
		0x8AC08D4ADF20E135ULL,
		0x7ED61530BC76C10AULL
	}};
	sign = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x44FAC849F13A20F8ULL,
		0x2B9395F3EDD671B9ULL,
		0xCA3AF98D5B73623BULL,
		0x2424AC70BAED013DULL,
		0x082947AE99D1C769ULL,
		0xE0026B642602F9A8ULL,
		0x38DD6B300E6D56A8ULL,
		0x094178A838921450ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C614170D9C56560ULL,
		0x3027799858E665C8ULL,
		0x0569EDF595CDE5D8ULL,
		0x8B0328EE64890CA2ULL,
		0x601E705245AA8E76ULL,
		0xFB76F1FB6226D6F5ULL,
		0x9BF66B632F14E2C7ULL,
		0x30581C28FC32FC6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE89986D91774BB98ULL,
		0xFB6C1C5B94F00BF0ULL,
		0xC4D10B97C5A57C62ULL,
		0x992183825663F49BULL,
		0xA80AD75C542738F2ULL,
		0xE48B7968C3DC22B2ULL,
		0x9CE6FFCCDF5873E0ULL,
		0xD8E95C7F3C5F17E4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3BBC8FD2A3BA2D91ULL,
		0x062EFDA55E5D0ADCULL,
		0x8CB664ECAB87B87EULL,
		0xF3F08C00B80C11DCULL,
		0x39EB4D121B5AE78FULL,
		0xF91A66A3A5F9926EULL,
		0xA192DC5C7C34C56CULL,
		0x846789F82171A5C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC906561B9C573E6ULL,
		0xBE107DFA8B8BF77DULL,
		0x65A5544F64C4474DULL,
		0x1047C0267A4C9818ULL,
		0xA2E39342780A5DEDULL,
		0xFF0ACE3884451A67ULL,
		0x493490BF0D81EBD4ULL,
		0x8403DE2992EBAC6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F2C2A70E9F4B9ABULL,
		0x481E7FAAD2D1135EULL,
		0x2711109D46C37130ULL,
		0xE3A8CBDA3DBF79C4ULL,
		0x9707B9CFA35089A2ULL,
		0xFA0F986B21B47806ULL,
		0x585E4B9D6EB2D997ULL,
		0x0063ABCE8E85F958ULL
	}};
	sign = 0;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x764C2A4C968E55B2ULL,
		0x5304F4AF838B3C63ULL,
		0xA9AB6AFF0F748D78ULL,
		0x6640C137607B8F15ULL,
		0x6D54D3324DBECEF8ULL,
		0xEB60DEA3C3BE2522ULL,
		0x7003CC8F3A63C499ULL,
		0x2921BEE129F7B8A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC307FC68B3D07FULL,
		0x82834E3AA09265D7ULL,
		0x082F4D801C97DCF8ULL,
		0xE6D68C7218CCB3CEULL,
		0x7EBBDC6372D07E8FULL,
		0xBE9138731FBB5DA0ULL,
		0xD33A0FE7B536D005ULL,
		0xDBBA12678D2D8D01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD88922502DDA8533ULL,
		0xD081A674E2F8D68BULL,
		0xA17C1D7EF2DCB07FULL,
		0x7F6A34C547AEDB47ULL,
		0xEE98F6CEDAEE5068ULL,
		0x2CCFA630A402C781ULL,
		0x9CC9BCA7852CF494ULL,
		0x4D67AC799CCA2B9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x67D79B1111B3C3CBULL,
		0x465F6965DAFA3937ULL,
		0xAD28866CED11CBF8ULL,
		0x1D862D95A32937BEULL,
		0x3A6ACB2493BB4195ULL,
		0x6C7CE61E7A4F76C8ULL,
		0xEF74AFD30AB31C31ULL,
		0x30BAD450855C7E3EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A237D75BFFFB25ULL,
		0xCA1832C4745503D0ULL,
		0xB1DDFA71A86CC3E3ULL,
		0x3BF99425D0CF4091ULL,
		0x53DC2E347E786F2FULL,
		0x88772234F768946BULL,
		0x498FC7D15877943AULL,
		0x8AD7219AA6BF4443ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F356339B5B3C8A6ULL,
		0x7C4736A166A53566ULL,
		0xFB4A8BFB44A50814ULL,
		0xE18C996FD259F72CULL,
		0xE68E9CF01542D265ULL,
		0xE405C3E982E6E25CULL,
		0xA5E4E801B23B87F6ULL,
		0xA5E3B2B5DE9D39FBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3219255A5944E43ULL,
		0x38CBA540142C53C3ULL,
		0xFA818E7840BB4687ULL,
		0xB3222A0C59659EBEULL,
		0xB8C8551CA83F933DULL,
		0xBF8A8DBD7F8A719DULL,
		0x575F6293BB1A8C0CULL,
		0xB42E9A062EEDA622ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CC7458C8D7293F9ULL,
		0x13ED75E4347F92F1ULL,
		0x35E434DF37DB60DFULL,
		0x5E7DFD6B96D9D9D6ULL,
		0x116E16D450601B57ULL,
		0x5BE02A858539B9E8ULL,
		0xBC8EF69E223FF933ULL,
		0xD941E59E88D3726BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x965A4CC91821BA4AULL,
		0x24DE2F5BDFACC0D2ULL,
		0xC49D599908DFE5A8ULL,
		0x54A42CA0C28BC4E8ULL,
		0xA75A3E4857DF77E6ULL,
		0x63AA6337FA50B7B5ULL,
		0x9AD06BF598DA92D9ULL,
		0xDAECB467A61A33B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x656A4231501368B6ULL,
		0xF5328025C5279964ULL,
		0x20797FE954E6D0A3ULL,
		0x3CE0D1C1E97FD1CBULL,
		0x9273AB3E571A4751ULL,
		0x37D02CD5A57643C6ULL,
		0x95F5DA965D271948ULL,
		0xE952339971B87992ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9763FA508FBF9C05ULL,
		0xBB62921BB767FAB0ULL,
		0x3B48D9AAA134076AULL,
		0x5F9A8A63BB8B6EC0ULL,
		0x800609F2F2522155ULL,
		0xEA79EE23EE14ED98ULL,
		0x8048CB5A9A24F190ULL,
		0xC7911B03F4FE878FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE0647E0C053CCB1ULL,
		0x39CFEE0A0DBF9EB3ULL,
		0xE530A63EB3B2C939ULL,
		0xDD46475E2DF4630AULL,
		0x126DA14B64C825FBULL,
		0x4D563EB1B761562EULL,
		0x15AD0F3BC30227B7ULL,
		0x21C118957CB9F203ULL
	}};
	sign = 0;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9C19A8871309C61ULL,
		0x459C925817370CF0ULL,
		0xA981FC470DB18477ULL,
		0xF193042575ED3C3AULL,
		0x67B4AE6CF9AD3BB4ULL,
		0xA7104F95421083F0ULL,
		0x5752A2B0B1CDFAC2ULL,
		0xD5C740BB55624C96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x760F0085AAE8424EULL,
		0x677C63A12C14222FULL,
		0xB9E1561E15254049ULL,
		0x097053EF036B617CULL,
		0xD7D1C3BAD1D5B14CULL,
		0xF31F6C0BFEE25E37ULL,
		0x445527E8D1C6180DULL,
		0xDDCA17C993FAA214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63B29A02C6485A13ULL,
		0xDE202EB6EB22EAC1ULL,
		0xEFA0A628F88C442DULL,
		0xE822B0367281DABDULL,
		0x8FE2EAB227D78A68ULL,
		0xB3F0E389432E25B8ULL,
		0x12FD7AC7E007E2B4ULL,
		0xF7FD28F1C167AA82ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE4C930B836EE7576ULL,
		0x8B27F06B752C176CULL,
		0x379B624D1A2A77BFULL,
		0x692297E33932DC0EULL,
		0xD916BC08E99E08F2ULL,
		0x4E0032A5E2DC8934ULL,
		0x42CE9CA5113A30E7ULL,
		0xBFEB74B28013772AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A89D56097F2FA3EULL,
		0x0FE6B91447993C00ULL,
		0x8379F9F462358B3DULL,
		0x45E819AEE0EB9177ULL,
		0x5C01E53EE96C431FULL,
		0xA66FB833F002BA30ULL,
		0xAB1840FC49AFC528ULL,
		0xEBB3B986C4B289C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA3F5B579EFB7B38ULL,
		0x7B4137572D92DB6CULL,
		0xB4216858B7F4EC82ULL,
		0x233A7E3458474A96ULL,
		0x7D14D6CA0031C5D3ULL,
		0xA7907A71F2D9CF04ULL,
		0x97B65BA8C78A6BBEULL,
		0xD437BB2BBB60ED67ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x634621CF93591E65ULL,
		0xE0A169A92EA8DD81ULL,
		0xF49B811D481235E6ULL,
		0xCA02BF33368C445AULL,
		0xB2C55C6D09841AEFULL,
		0xCBB9210C77F4C1DDULL,
		0x68E2C0892A7C93DFULL,
		0x9A5774E9697FC599ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x19745EC817E6FCDBULL,
		0xFA11190E3956D66DULL,
		0x5410BB1DA3687DC3ULL,
		0x80D7278AB7F55820ULL,
		0x53150FFE23E7BFEFULL,
		0x489404F58269E1DBULL,
		0x95ED0B919C103979ULL,
		0x6BACC239FA2F83D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49D1C3077B72218AULL,
		0xE690509AF5520714ULL,
		0xA08AC5FFA4A9B822ULL,
		0x492B97A87E96EC3AULL,
		0x5FB04C6EE59C5B00ULL,
		0x83251C16F58AE002ULL,
		0xD2F5B4F78E6C5A66ULL,
		0x2EAAB2AF6F5041C3ULL
	}};
	sign = 0;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE1FAF0DC651BC260ULL,
		0x77EB934DD2BF6839ULL,
		0x6FC5EC207F0822F0ULL,
		0x8FF9A3D8CEDFF2E3ULL,
		0x868F3B6B9641D16DULL,
		0x67A126760F70AC87ULL,
		0x263D81EFBC43AE9FULL,
		0xF45BF724754A156CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x949919AAC3CD58F9ULL,
		0x4177AD354BA2B8F7ULL,
		0x8CEEDF6D0D9422A7ULL,
		0x1EBF09CA5BC9C9ABULL,
		0x921A6A48085C6073ULL,
		0xF1E4DA6634459BF5ULL,
		0x80C9BB538977AE8AULL,
		0xCD7F98250E0EBFE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D61D731A14E6967ULL,
		0x3673E618871CAF42ULL,
		0xE2D70CB371740049ULL,
		0x713A9A0E73162937ULL,
		0xF474D1238DE570FAULL,
		0x75BC4C0FDB2B1091ULL,
		0xA573C69C32CC0014ULL,
		0x26DC5EFF673B5588ULL
	}};
	sign = 0;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA5926405412918F2ULL,
		0xEA484DFEF1D78006ULL,
		0x2B19D6CB3218737AULL,
		0xF9A0423C9286DF7EULL,
		0x24472D3B3349D744ULL,
		0xCE0439404591B1FFULL,
		0xE2A63446DC0C25DCULL,
		0xD64A240D9C5FC170ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A3ABB32CD21DD1ULL,
		0xF524FA790457562FULL,
		0x991943FB4F7F2F49ULL,
		0x7391ACD62B36EE54ULL,
		0x81F7B4835E5635F1ULL,
		0xA35B68682A1A8CA9ULL,
		0x1B3B39E04CC09CDAULL,
		0xA3296F35932AA9B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21EEB8521456FB21ULL,
		0xF5235385ED8029D7ULL,
		0x920092CFE2994430ULL,
		0x860E9566674FF129ULL,
		0xA24F78B7D4F3A153ULL,
		0x2AA8D0D81B772555ULL,
		0xC76AFA668F4B8902ULL,
		0x3320B4D8093517BEULL
	}};
	sign = 0;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7BE6EF1F844BE875ULL,
		0xDC3C22D3AD833C7CULL,
		0x0E264676F8CE57DAULL,
		0xC108E6C6C4A93A25ULL,
		0xF97DE129EF5B2247ULL,
		0x77B8A8A888218406ULL,
		0x9CE6D423C468339BULL,
		0xB0CFC1DB584D0954ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE4C29B3687893CULL,
		0x86EB0938BA4C9237ULL,
		0x7FCE32B62FCBF658ULL,
		0x91FE7A6840C10962ULL,
		0x73BAFBE0FED32591ULL,
		0xBDF78E19E5C80E31ULL,
		0x58B1427251861FC0ULL,
		0x63F5FBE505D9DF41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC022C844DC45F39ULL,
		0x5551199AF336AA44ULL,
		0x8E5813C0C9026182ULL,
		0x2F0A6C5E83E830C2ULL,
		0x85C2E548F087FCB6ULL,
		0xB9C11A8EA25975D5ULL,
		0x443591B172E213DAULL,
		0x4CD9C5F652732A13ULL
	}};
	sign = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x53A2A624C9520E52ULL,
		0x911FB08CFA872A33ULL,
		0x7EF84A0466DC983AULL,
		0x7F6BB07EBB3809E2ULL,
		0x0D7E52465F5608DAULL,
		0x6EFE1D3CA717CB45ULL,
		0xB668CE8CB3018E58ULL,
		0xE49409E2E50161C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53AD2F9A64F7587AULL,
		0xB5ABF5CC933DAEE3ULL,
		0x3A1F74327D1EFFE8ULL,
		0x68339177CE13E5B3ULL,
		0x04D13EC9DB0E9C90ULL,
		0xB75B0D3E28B95B1EULL,
		0x183D02908BEFFF47ULL,
		0x53EDA691B17CD53AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFF5768A645AB5D8ULL,
		0xDB73BAC067497B4FULL,
		0x44D8D5D1E9BD9851ULL,
		0x17381F06ED24242FULL,
		0x08AD137C84476C4AULL,
		0xB7A30FFE7E5E7027ULL,
		0x9E2BCBFC27118F10ULL,
		0x90A6635133848C8CULL
	}};
	sign = 0;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB2E049A7FD8ABDAFULL,
		0xF0EFAD717AE28788ULL,
		0x2580E8DE7FED483DULL,
		0x053EC5E91D027739ULL,
		0x64CD7976FD21714FULL,
		0x3B4DDBFA5729AF4CULL,
		0x09C4499B66E12AAEULL,
		0x6514253713F8D6D5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6555ED6072273CFULL,
		0xC300FD8C3371CFEEULL,
		0x4933A06BC877B427ULL,
		0xCFA972A3721E8478ULL,
		0xCAC8196FC41BED9AULL,
		0xDB0D7BD6F56E4C1FULL,
		0x1FE7122BA9A78211ULL,
		0x9090BF5E3A9C9DD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC8AEAD1F66849E0ULL,
		0x2DEEAFE54770B799ULL,
		0xDC4D4872B7759416ULL,
		0x35955345AAE3F2C0ULL,
		0x9A056007390583B4ULL,
		0x6040602361BB632CULL,
		0xE9DD376FBD39A89CULL,
		0xD48365D8D95C3904ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3A2192CF930D3DC2ULL,
		0xF8F6568F83485F9EULL,
		0x8C1D16528EF3D8B2ULL,
		0xC0CF4891B74471D4ULL,
		0x14D20ABDE98E9BF3ULL,
		0x693A91612097AA53ULL,
		0x6015FE561D4BCCD1ULL,
		0xB174FC072C08E947ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9942184493788EBFULL,
		0xC05902BDD9F3E9ABULL,
		0x78E5C67CF7C31426ULL,
		0xECCD40319A31BF96ULL,
		0x207D914FF2119FB8ULL,
		0xCF00F39443335969ULL,
		0x798E6A2B3603EA76ULL,
		0xE41833E63E7E702EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0DF7A8AFF94AF03ULL,
		0x389D53D1A95475F2ULL,
		0x13374FD59730C48CULL,
		0xD40208601D12B23EULL,
		0xF454796DF77CFC3AULL,
		0x9A399DCCDD6450E9ULL,
		0xE687942AE747E25AULL,
		0xCD5CC820ED8A7918ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x87AD6CB231808DEFULL,
		0x228D285BB4C14320ULL,
		0xA98F29F86A95D594ULL,
		0xFFF54A12EC515A25ULL,
		0xB298B2BED6A937B3ULL,
		0x101FBD98FFBB4C8AULL,
		0x3DD64DE56B84F1FDULL,
		0xC32A2F091254F169ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE20D78FBC85DB44FULL,
		0x4E2CAA350FAD96E7ULL,
		0xF4A7807CB4C573C8ULL,
		0x5E8C81DAFC36900FULL,
		0xDDCE9799967C21EFULL,
		0x1C42954FE8E55A21ULL,
		0x874F0B72860F6018ULL,
		0xD307661CDC58E559ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA59FF3B66922D9A0ULL,
		0xD4607E26A513AC38ULL,
		0xB4E7A97BB5D061CBULL,
		0xA168C837F01ACA15ULL,
		0xD4CA1B25402D15C4ULL,
		0xF3DD284916D5F268ULL,
		0xB6874272E57591E4ULL,
		0xF022C8EC35FC0C0FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x79CCDF2EE4C96079ULL,
		0x0E3353335CA49133ULL,
		0xE091FCC27C23C0B2ULL,
		0x9AD5E0221BF3ABAFULL,
		0xB050FDD96046B175ULL,
		0x9DA507E833997D57ULL,
		0xA92A484EE9E341C5ULL,
		0x82A0968A00E68ECFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0226C39D860B90EAULL,
		0xD4746F2D85266C95ULL,
		0x2F97E057F5B103CDULL,
		0xBA310E0040B03F1FULL,
		0xBCC23F05A32F6794ULL,
		0x870DC0CADA7195DDULL,
		0x8D32A382BEBA34CFULL,
		0x801D374B54A8158FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77A61B915EBDCF8FULL,
		0x39BEE405D77E249EULL,
		0xB0FA1C6A8672BCE4ULL,
		0xE0A4D221DB436C90ULL,
		0xF38EBED3BD1749E0ULL,
		0x1697471D5927E779ULL,
		0x1BF7A4CC2B290CF6ULL,
		0x02835F3EAC3E7940ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4897741BB8ABFAF7ULL,
		0x5899304E53634FCCULL,
		0xF96B812934C76E83ULL,
		0x4A239CC9FADA9B28ULL,
		0x188E400762C05034ULL,
		0x002880EDEB5541C8ULL,
		0xC688BB9B0BB75DCFULL,
		0x4879BB0D2B66B991ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE6D130DFA558F7ULL,
		0xE8F84CD5F8E5C955ULL,
		0x59ACBE98551FD5AEULL,
		0xB61022BB48334C2BULL,
		0x0E25F47A18F373EAULL,
		0x8F1917859C27FA99ULL,
		0xBE0995F29AB52A81ULL,
		0x3225AA0C0A98DF69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8B0A2EAD906A200ULL,
		0x6FA0E3785A7D8676ULL,
		0x9FBEC290DFA798D4ULL,
		0x94137A0EB2A74EFDULL,
		0x0A684B8D49CCDC49ULL,
		0x710F69684F2D472FULL,
		0x087F25A87102334DULL,
		0x1654110120CDDA28ULL
	}};
	sign = 0;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3A3742A5F70432D1ULL,
		0x1C02CA6FD1F1860FULL,
		0x98A95040F363F218ULL,
		0x8BA67C5A66EBF60CULL,
		0x2C713647E35CDC83ULL,
		0xEBF7C5960B0D3260ULL,
		0x97916C675F86253EULL,
		0x291A810A4F5A7669ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B32CFA06B4DD24ULL,
		0x51086A6F19A3BE09ULL,
		0x28011FF0CDB5AF39ULL,
		0x3F45AD19B4F54BEBULL,
		0x1496A4174986A156ULL,
		0x67B0E2289EE7403CULL,
		0xDCD5D5BDDECD34FFULL,
		0x893E3EB5A3712ECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA78415ABF04F55ADULL,
		0xCAFA6000B84DC805ULL,
		0x70A8305025AE42DEULL,
		0x4C60CF40B1F6AA21ULL,
		0x17DA923099D63B2DULL,
		0x8446E36D6C25F224ULL,
		0xBABB96A980B8F03FULL,
		0x9FDC4254ABE9479BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x44B6A0345A4009C2ULL,
		0x106B537C8A9282C5ULL,
		0x8BB3D6338D0A4029ULL,
		0x964C5BC1FD285A32ULL,
		0x2B9DCCAAA2335564ULL,
		0x677DE267B0296C47ULL,
		0xDD78840875766D5AULL,
		0x1E6B86D9D2D35235ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D6959C476536FDULL,
		0xA7281E77D0AAAEA6ULL,
		0xDEAF9E8D415A2E66ULL,
		0x9ADB53D7FD121C57ULL,
		0xC4A2970BA4BD4D01ULL,
		0xBD74435720ABF3E3ULL,
		0xC1E8A43937FEE141ULL,
		0x820130F45B42620DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13E00A9812DAD2C5ULL,
		0x69433504B9E7D41FULL,
		0xAD0437A64BB011C2ULL,
		0xFB7107EA00163DDAULL,
		0x66FB359EFD760862ULL,
		0xAA099F108F7D7863ULL,
		0x1B8FDFCF3D778C18ULL,
		0x9C6A55E57790F028ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD4247C9D058A6380ULL,
		0x59A3A97922424472ULL,
		0x0601A739AC0FB18BULL,
		0x010888438932EAD8ULL,
		0xCB39EDC00500E194ULL,
		0xEC46945E5E76FD28ULL,
		0xA9465DEDE04ECE50ULL,
		0xE276A1BD4CBB16D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF1BD6C1CCB88053ULL,
		0xC2248E01C367AE75ULL,
		0xA28F74F7EDB6278EULL,
		0xA07EAAC9BDE5874BULL,
		0x1BCC078446C18F6AULL,
		0xE22BB1660200A1B2ULL,
		0xB5573B9485BD7CAEULL,
		0x813A633D1BBC87CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1508A5DB38D1E32DULL,
		0x977F1B775EDA95FDULL,
		0x63723241BE5989FCULL,
		0x6089DD79CB4D638CULL,
		0xAF6DE63BBE3F5229ULL,
		0x0A1AE2F85C765B76ULL,
		0xF3EF22595A9151A2ULL,
		0x613C3E8030FE8F06ULL
	}};
	sign = 0;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C8C3B5B9CA42699ULL,
		0xEA7011A3D0CD9BF6ULL,
		0x02B9E92E843F8712ULL,
		0xDF07B4F87530BA25ULL,
		0x43298CF4412D512AULL,
		0x6241605A2019A190ULL,
		0x1EA2817C978382D9ULL,
		0xF3173E471791191FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F8B9B207C97CC7ULL,
		0x16C9E1C18E8F9A4EULL,
		0xD83E429D8D22B856ULL,
		0xCD5CE4C3A62A7EB2ULL,
		0x834FE26F7AB34E53ULL,
		0x541DA632DC1102FBULL,
		0xA9D27AB61BAD763CULL,
		0xDDB40172429002E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x199381A994DAA9D2ULL,
		0xD3A62FE2423E01A8ULL,
		0x2A7BA690F71CCEBCULL,
		0x11AAD034CF063B72ULL,
		0xBFD9AA84C67A02D7ULL,
		0x0E23BA2744089E94ULL,
		0x74D006C67BD60C9DULL,
		0x15633CD4D501163AULL
	}};
	sign = 0;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB95EFE967ED6DABBULL,
		0xA8CBC65A2FB792C0ULL,
		0x223DB4681AD779A0ULL,
		0x9EB1F5408CB8DDBCULL,
		0xC1C038AF394BBD6FULL,
		0x0517F8B15CD0BCF0ULL,
		0xC4D050BCF197D7A9ULL,
		0xC58C706CA2628303ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD8B851A81AC9A89ULL,
		0xCF4FB59C0E7449EEULL,
		0x4DA98195236D82F9ULL,
		0xB44368DD105895D2ULL,
		0x7E48E534DE57859FULL,
		0x3D1554723E0F5273ULL,
		0xFBDEDC52828A1E86ULL,
		0xA0A13E97A2771E34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBD3797BFD2A4032ULL,
		0xD97C10BE214348D1ULL,
		0xD49432D2F769F6A6ULL,
		0xEA6E8C637C6047E9ULL,
		0x4377537A5AF437CFULL,
		0xC802A43F1EC16A7DULL,
		0xC8F1746A6F0DB922ULL,
		0x24EB31D4FFEB64CEULL
	}};
	sign = 0;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC517779D6FB4220ULL,
		0x79669AA73C4B4D6EULL,
		0x6B2B0E019EC4D926ULL,
		0x65BC27849989AF70ULL,
		0x8F4996194915DB02ULL,
		0x5F8456564C767DDEULL,
		0x0165BE1E0BCC802EULL,
		0x807821B06A17D253ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C474FCAB02A4949ULL,
		0xA1E63A05292B3551ULL,
		0x63DF889854E5EF08ULL,
		0xB3D757046BC3A7EBULL,
		0x2DB22EA0DDA8A8CFULL,
		0x17E5FE0ADE96A68FULL,
		0xE40908CF0C6B2CC4ULL,
		0x4A1D8DBD8F3C2D49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB00A27AF26D0F8D7ULL,
		0xD78060A21320181DULL,
		0x074B856949DEEA1DULL,
		0xB1E4D0802DC60785ULL,
		0x619767786B6D3232ULL,
		0x479E584B6DDFD74FULL,
		0x1D5CB54EFF61536AULL,
		0x365A93F2DADBA509ULL
	}};
	sign = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5FD3746F0B73F345ULL,
		0xF15BE316E7AEF3E8ULL,
		0x1F35BAE94481D704ULL,
		0x9E3BE712DB370D96ULL,
		0x2F154B880FAA6157ULL,
		0x65CD11600F5B7BA0ULL,
		0xE2F1DE4E9DC99581ULL,
		0x2858C7EDD3C12C70ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x064E4F8DA060221DULL,
		0x87124897165A8A71ULL,
		0x0E4AB17D9530D4F7ULL,
		0xB86FC2796C961EF2ULL,
		0xC1765FF749D0C09FULL,
		0x32FADE2817E87215ULL,
		0x7D415877F1856CA7ULL,
		0x6EB8B0F793134521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x598524E16B13D128ULL,
		0x6A499A7FD1546977ULL,
		0x10EB096BAF51020DULL,
		0xE5CC24996EA0EEA4ULL,
		0x6D9EEB90C5D9A0B7ULL,
		0x32D23337F773098AULL,
		0x65B085D6AC4428DAULL,
		0xB9A016F640ADE74FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBD8B6159F9ADDE96ULL,
		0x8DCD5230EC5ED333ULL,
		0x98E43CDBF43093D1ULL,
		0x25E09918F8D32990ULL,
		0x3B5B7A67D2D3DFAEULL,
		0x64F527ECD51859A2ULL,
		0x4773856E0E6F1B64ULL,
		0x5AB0986C21C3AEE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55EB53685F057CAULL,
		0x5D8FB9EE573E6795ULL,
		0x14455D906C8504EDULL,
		0x8906693AAA5BF8DBULL,
		0xBBD85C9A20D30644ULL,
		0x3EEB8EDCC45E41FEULL,
		0x742AF2A1F5014B89ULL,
		0x2201D7FF7BB32F4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD82CAC2373BD86CCULL,
		0x303D984295206B9DULL,
		0x849EDF4B87AB8EE4ULL,
		0x9CDA2FDE4E7730B5ULL,
		0x7F831DCDB200D969ULL,
		0x2609991010BA17A3ULL,
		0xD34892CC196DCFDBULL,
		0x38AEC06CA6107F93ULL
	}};
	sign = 0;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x20AE87667D8EE7A1ULL,
		0xE5CAC4A0BBD712B0ULL,
		0x77CE64C19D1D33EDULL,
		0x11D4C9C2D838D038ULL,
		0xC537F07BDDB5FC5CULL,
		0x5B576003D9F50400ULL,
		0x700C27BBB505B87BULL,
		0xBBB273CD3CEB3D56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x681E505573F99EA4ULL,
		0x4C62B4AFE0AFADF0ULL,
		0x52CBF79F3976BDA8ULL,
		0x6A3038B61FE4EB18ULL,
		0xDBA3D8B3BB97F3A5ULL,
		0xF7804BDA2D55D2AFULL,
		0xD17B2D80F522D8E0ULL,
		0x3D5A29C08A13B32AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8903711099548FDULL,
		0x99680FF0DB2764BFULL,
		0x25026D2263A67645ULL,
		0xA7A4910CB853E520ULL,
		0xE99417C8221E08B6ULL,
		0x63D71429AC9F3150ULL,
		0x9E90FA3ABFE2DF9AULL,
		0x7E584A0CB2D78A2BULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x89FDB9D135EE0459ULL,
		0x3D131D374471455EULL,
		0xDA130AC937E2E079ULL,
		0x3CAAF8000CF7580FULL,
		0xF597BAE9B77C7FF9ULL,
		0xE2A8965634AF25FEULL,
		0x28F4857FBA741D47ULL,
		0x60847FFBF67F0BE5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF218AFE5252227FBULL,
		0x20DE0572F41E4CA7ULL,
		0xCD88003BCDA038B2ULL,
		0x7A072FA5AC744AC5ULL,
		0xC22DFEA9EFC8EAC8ULL,
		0xEBDDB88DC14D96BDULL,
		0x34E3E720B82B4E65ULL,
		0xE6BC507F9F02CF5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97E509EC10CBDC5EULL,
		0x1C3517C45052F8B6ULL,
		0x0C8B0A8D6A42A7C7ULL,
		0xC2A3C85A60830D4AULL,
		0x3369BC3FC7B39530ULL,
		0xF6CADDC873618F41ULL,
		0xF4109E5F0248CEE1ULL,
		0x79C82F7C577C3C89ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x80A1C11129DA35BDULL,
		0xEA1C75FB3FD56A8AULL,
		0x8195B547B8B26118ULL,
		0x52B6F9F2F4610D71ULL,
		0xDA2C01028C652BC4ULL,
		0x0132735398E64F21ULL,
		0x8076D7ED363AEB0CULL,
		0x6C6ACD79D9D91655ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38219938050A1E0EULL,
		0xAB94D0808B2DEAD2ULL,
		0xFACAE7BCFA91FD49ULL,
		0xAB808389BBC3D659ULL,
		0x6D7BBA42C6C3F846ULL,
		0xFBC43A4006F32C67ULL,
		0xB073107CA6ECE27EULL,
		0xF519F914EDCE61DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x488027D924D017AFULL,
		0x3E87A57AB4A77FB8ULL,
		0x86CACD8ABE2063CFULL,
		0xA7367669389D3717ULL,
		0x6CB046BFC5A1337DULL,
		0x056E391391F322BAULL,
		0xD003C7708F4E088DULL,
		0x7750D464EC0AB475ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA9B648E2BBA5C16DULL,
		0xF7F34DDA8CAD9380ULL,
		0xD6E2E2307DD6A41FULL,
		0x65779B33AF0F79D9ULL,
		0xDF833B0021D3A274ULL,
		0xF33F5C59E826BE2AULL,
		0x63EA204700016866ULL,
		0xC33D735F944655D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E88191ED93041CULL,
		0x7887E63DAD2EDDBBULL,
		0x1C77B0081C2C7A35ULL,
		0xF311EBE4181F7E2BULL,
		0x69DC5F3EFFD5E2D6ULL,
		0x6E3CB52AF5F4B8D9ULL,
		0xB5C9BA71EE6F0BC3ULL,
		0xA6D5D0EA0B42C1A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32CDC750CE12BD51ULL,
		0x7F6B679CDF7EB5C5ULL,
		0xBA6B322861AA29EAULL,
		0x7265AF4F96EFFBAEULL,
		0x75A6DBC121FDBF9DULL,
		0x8502A72EF2320551ULL,
		0xAE2065D511925CA3ULL,
		0x1C67A27589039436ULL
	}};
	sign = 0;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x781F1AFAD0F967F6ULL,
		0x012419556F0722E6ULL,
		0xA34C1CA38FE0900BULL,
		0xDCF914D28EC273D7ULL,
		0x37E23B74E505DA75ULL,
		0x7FB03C97E3F48BC9ULL,
		0x55D2B4425288A237ULL,
		0xDE95FD42E16587D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD95B300E8D579C61ULL,
		0x39F7078A6AC4B1B8ULL,
		0xE92CE11717A13A0CULL,
		0x00EE32827FF4928AULL,
		0x62B27730371E2F93ULL,
		0x032B4B2628627ACAULL,
		0x3474B71D71A2D1E0ULL,
		0x05ADE9BBC49F9169ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC3EAEC43A1CB95ULL,
		0xC72D11CB0442712DULL,
		0xBA1F3B8C783F55FEULL,
		0xDC0AE2500ECDE14CULL,
		0xD52FC444ADE7AAE2ULL,
		0x7C84F171BB9210FEULL,
		0x215DFD24E0E5D057ULL,
		0xD8E813871CC5F668ULL
	}};
	sign = 0;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2969438FE1CF332ULL,
		0x5CCBA5B7F80DC0B1ULL,
		0xFE882D88EC38EA3EULL,
		0x10ECB304C5F431BFULL,
		0x5D83475A59199965ULL,
		0x2F5CF1B349FE8E18ULL,
		0xB64742751E10F866ULL,
		0x66A3B4D8449479F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5E9527AA62E7256ULL,
		0x4B90CC2E3C1F1859ULL,
		0xA6CFFCC2485E1A54ULL,
		0x33D746402FA30920ULL,
		0xCC0A32DCAA71D4BFULL,
		0x75DBEF98B66F1731ULL,
		0xA203D2AC08A08CC0ULL,
		0xAE37AA2893D9FFC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CAD41BE57EE80DCULL,
		0x113AD989BBEEA858ULL,
		0x57B830C6A3DACFEAULL,
		0xDD156CC49651289FULL,
		0x9179147DAEA7C4A5ULL,
		0xB981021A938F76E6ULL,
		0x14436FC915706BA5ULL,
		0xB86C0AAFB0BA7A30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x613960F4F0899AFDULL,
		0x8BFBBB9473AE7261ULL,
		0x672DE27DD6A41EC1ULL,
		0x9D41E8641522CD76ULL,
		0xD89BC51AF8ABE676ULL,
		0x583CAB823FFD37EBULL,
		0x9112981B2328FBF4ULL,
		0x6B2B521325FC2352ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F1CADCEB146EFACULL,
		0x076FAD0E24B0CA80ULL,
		0x30A4AF46A4446D66ULL,
		0x435689DA204E3804ULL,
		0xD89418ABA122F1ABULL,
		0x9171236EF280F50FULL,
		0x4AC2238C3AC7F4E1ULL,
		0xD6C68EF270B04ABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x321CB3263F42AB51ULL,
		0x848C0E864EFDA7E1ULL,
		0x36893337325FB15BULL,
		0x59EB5E89F4D49572ULL,
		0x0007AC6F5788F4CBULL,
		0xC6CB88134D7C42DCULL,
		0x4650748EE8610712ULL,
		0x9464C320B54BD898ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x38E847CBCDD5CEF6ULL,
		0xB7CECFE505253CD9ULL,
		0xA58091D3B2518643ULL,
		0x399FD183C381C89FULL,
		0x798944BF768D243FULL,
		0xF25FEAD3CC553D68ULL,
		0x5351C79B27383691ULL,
		0x58996FDC83EE9259ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D547B9FE267FCC2ULL,
		0x9A7318C1E5B0A9DDULL,
		0xC7997E36B39A5C17ULL,
		0x0ABA50DA0C78E531ULL,
		0x4A4232CA3C08ABABULL,
		0x46E069F97A5E10FAULL,
		0x57EF592AC652CD6FULL,
		0x933B795F19D9D9A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B93CC2BEB6DD234ULL,
		0x1D5BB7231F7492FBULL,
		0xDDE7139CFEB72A2CULL,
		0x2EE580A9B708E36DULL,
		0x2F4711F53A847894ULL,
		0xAB7F80DA51F72C6EULL,
		0xFB626E7060E56922ULL,
		0xC55DF67D6A14B8B0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B352D48045502C1ULL,
		0x536729D9A881486AULL,
		0x57981CE0C533A2C9ULL,
		0x27CF78EC6727F6BBULL,
		0x70427FF9B40389E5ULL,
		0x722F159F05178345ULL,
		0x972E7E86D9C89BDAULL,
		0x13F53620CD96A0E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x67019CB2562C4825ULL,
		0x2046AD7A196918B5ULL,
		0xEA3297F4123352E2ULL,
		0xDD7F4C8015CA3E49ULL,
		0x653098266C7DB603ULL,
		0x5FA22315F35841B4ULL,
		0x3E6AAE8A0F62C8B2ULL,
		0xBEBE4DA5C9353A5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4339095AE28BA9CULL,
		0x33207C5F8F182FB4ULL,
		0x6D6584ECB3004FE7ULL,
		0x4A502C6C515DB871ULL,
		0x0B11E7D34785D3E1ULL,
		0x128CF28911BF4191ULL,
		0x58C3CFFCCA65D328ULL,
		0x5536E87B0461668AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7CFD7C229FF971DAULL,
		0xAC8EA7D4BCF577B2ULL,
		0xD3BB93D91E454D42ULL,
		0x121F80C277F9F0B7ULL,
		0x30905D086BAAE73DULL,
		0xAF96C735416A81EAULL,
		0x7FAB2E15D5219FD1ULL,
		0x928BCB0CA40CE632ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E77BD714B5E733ULL,
		0x1DDD9B66EC8648DDULL,
		0xCBBD8DD6F8BFA7A5ULL,
		0xFC19F159CF34FA6AULL,
		0x4E331FBDA7641C38ULL,
		0xC8850B49F8720775ULL,
		0x34C08F59677F88C1ULL,
		0xC6497AE3B2F47B9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B16004B8B438AA7ULL,
		0x8EB10C6DD06F2ED5ULL,
		0x07FE06022585A59DULL,
		0x16058F68A8C4F64DULL,
		0xE25D3D4AC446CB04ULL,
		0xE711BBEB48F87A74ULL,
		0x4AEA9EBC6DA2170FULL,
		0xCC425028F1186A95ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00F2097E42D5085FULL,
		0xA2C0856DD935D307ULL,
		0x05A3CA9AD2B3CF7AULL,
		0x518E7D660D451778ULL,
		0x320FFF79DA1EC455ULL,
		0x511CCBB7224ECF70ULL,
		0x525B99A77A54B6DBULL,
		0xD7C1A2B8DF388DFEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58688E599B7CA0FDULL,
		0x0E14E1A46E71D338ULL,
		0xF99EFFD88134CA56ULL,
		0x82F88D8BD4243A75ULL,
		0xFA2D4B20C5A1AC6FULL,
		0xB443C26B2F448542ULL,
		0x28705355CCAE1F3EULL,
		0x847536038DE9E8DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8897B24A7586762ULL,
		0x94ABA3C96AC3FFCEULL,
		0x0C04CAC2517F0524ULL,
		0xCE95EFDA3920DD02ULL,
		0x37E2B459147D17E5ULL,
		0x9CD9094BF30A4A2DULL,
		0x29EB4651ADA6979CULL,
		0x534C6CB5514EA51FULL
	}};
	sign = 0;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE9968EEB343D3E61ULL,
		0x32EEA747FB463172ULL,
		0xDAD58941FC10A609ULL,
		0x33747045BA735DDFULL,
		0xE45FE3B8870AB28BULL,
		0x91CB9D1925BA552AULL,
		0xF07C6545535F362AULL,
		0xF59B1D32FFABCE93ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FE17D8925C4D31AULL,
		0x97FB98E36E77CE0DULL,
		0x9CE1C3234257B578ULL,
		0x5DAD9AEC4445EE36ULL,
		0xE11225A2B1DDC80FULL,
		0xCC381DF52A606A1DULL,
		0x8EA5F92D72974271ULL,
		0x8F7D551A879AABE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49B511620E786B47ULL,
		0x9AF30E648CCE6365ULL,
		0x3DF3C61EB9B8F090ULL,
		0xD5C6D559762D6FA9ULL,
		0x034DBE15D52CEA7BULL,
		0xC5937F23FB59EB0DULL,
		0x61D66C17E0C7F3B8ULL,
		0x661DC818781122AEULL
	}};
	sign = 0;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x09FC4641087DFCFDULL,
		0x2A7EC8497322E24EULL,
		0xF512451DF23DB3A3ULL,
		0x5D9927448779723FULL,
		0x0DA924635D27197AULL,
		0xB6E1A774403FABD2ULL,
		0x4E5A28B92FE98A84ULL,
		0x4A76B656323DC416ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDFAEA918237A6ECULL,
		0xEBF4FD1C7ED095BEULL,
		0xF19F458585E5ADD6ULL,
		0xB9E5E0CE42E8E5D9ULL,
		0x1629436DD3BFE6B1ULL,
		0xDB03D12043F01EDCULL,
		0xB92972A9EA44E22DULL,
		0x2A8C8B90001E4288ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C015BAF86465611ULL,
		0x3E89CB2CF4524C8FULL,
		0x0372FF986C5805CCULL,
		0xA3B3467644908C66ULL,
		0xF77FE0F5896732C8ULL,
		0xDBDDD653FC4F8CF5ULL,
		0x9530B60F45A4A856ULL,
		0x1FEA2AC6321F818DULL
	}};
	sign = 0;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF178CB61BE2F840ULL,
		0xC9A287AF008ED718ULL,
		0x196CC8D1181A36E6ULL,
		0xD8A3A6D76416429FULL,
		0x5B7AA60DF513686AULL,
		0x0604574B4EA9EA1BULL,
		0xF97EFC2C241780D8ULL,
		0x1B92296257393D79ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A0F5FD5D2FEADEULL,
		0x76D3330D6A4CE982ULL,
		0x23AE8A0D71106551ULL,
		0x9E56F3C100D1C8A1ULL,
		0xD3EA7CF71FD4DFD4ULL,
		0x94E5B73B7E1175A5ULL,
		0x6B380C5E329A74F6ULL,
		0x43391B29D0E0379AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D7696B8BEB30D62ULL,
		0x52CF54A19641ED96ULL,
		0xF5BE3EC3A709D195ULL,
		0x3A4CB316634479FDULL,
		0x87902916D53E8896ULL,
		0x711EA00FD0987475ULL,
		0x8E46EFCDF17D0BE1ULL,
		0xD8590E38865905DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAE0F4E0AECA49756ULL,
		0x1D733927ECCEFF34ULL,
		0x43B1F5E5C9A715FBULL,
		0x27F08D8FEA2CAC76ULL,
		0x6EEDFFDD9733E004ULL,
		0x66FE0BCAF4195F14ULL,
		0x5E25E56F96153131ULL,
		0xE6C1BF7EB29172D0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC983066062861C9BULL,
		0x9652C2C8AB61FE34ULL,
		0xC28F5EAF3702C5CAULL,
		0x5493686C2BDB4C3EULL,
		0xA1237F2CD8F56F3BULL,
		0x64E2D704136F0F03ULL,
		0x956F6CC2E111BB3DULL,
		0x962EDFE3D40439C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE48C47AA8A1E7ABBULL,
		0x8720765F416D00FFULL,
		0x8122973692A45030ULL,
		0xD35D2523BE516037ULL,
		0xCDCA80B0BE3E70C8ULL,
		0x021B34C6E0AA5010ULL,
		0xC8B678ACB50375F4ULL,
		0x5092DF9ADE8D3907ULL
	}};
	sign = 0;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x538A9BC32EB85AF9ULL,
		0x9CB4F9BFDA3BA5E6ULL,
		0x0A0807548659C193ULL,
		0x33972ADF02C4337BULL,
		0x3A4A26DFC4B2F474ULL,
		0xBAA827E45E6B0716ULL,
		0xEE5FA0B7BE4B549AULL,
		0x38C555D7EE37D91FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BF628A7E88ECC07ULL,
		0x895770784722CD21ULL,
		0x947B60385EC38038ULL,
		0x7723FF789C888776ULL,
		0x2026C29900B5BCFAULL,
		0x353D24B5B97BD47BULL,
		0x88A74E467A78CF30ULL,
		0x59EEB8E071B2BC9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD794731B46298EF2ULL,
		0x135D89479318D8C4ULL,
		0x758CA71C2796415BULL,
		0xBC732B66663BAC04ULL,
		0x1A236446C3FD3779ULL,
		0x856B032EA4EF329BULL,
		0x65B8527143D2856AULL,
		0xDED69CF77C851C80ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFCDEFB959503416CULL,
		0x5E258C3C87E0B115ULL,
		0x18C0675DC364877BULL,
		0x9511635BF5819778ULL,
		0x84581EA70D4325FDULL,
		0x9BF31870FAD27AAAULL,
		0x2666DE746A79E6E9ULL,
		0x81B954B8E8A35067ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F23B58EB9175585ULL,
		0xC388A87726E599E8ULL,
		0x3FB32950DD92CA6FULL,
		0x205E04FE02F64E50ULL,
		0xBDFDC17913C6E4A4ULL,
		0x5018A080F6AE9EEFULL,
		0x03B6E86FA6651E02ULL,
		0xB3352AFB29C05A4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADBB4606DBEBEBE7ULL,
		0x9A9CE3C560FB172DULL,
		0xD90D3E0CE5D1BD0BULL,
		0x74B35E5DF28B4927ULL,
		0xC65A5D2DF97C4159ULL,
		0x4BDA77F00423DBBAULL,
		0x22AFF604C414C8E7ULL,
		0xCE8429BDBEE2F618ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCCBF9F420E80E02DULL,
		0x9C163BFE32A086AEULL,
		0xEEB5B1E3EFECC34EULL,
		0x71FB34738D956F00ULL,
		0x42E60485585C6B4AULL,
		0x864BE466A82AE236ULL,
		0xF3ABDDCAF52A0716ULL,
		0xFCEEFEB0EFE3B25CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0DC072BCD18241ULL,
		0xAF0D47F382D6085DULL,
		0x62343944054EDBCBULL,
		0x095CD4527A13ECA2ULL,
		0x525EBA504C8A96B2ULL,
		0x719E91901EDFDF02ULL,
		0x7B01E95A9B119C96ULL,
		0xB712F0DA5A31C3CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEB1DECF51AF5DECULL,
		0xED08F40AAFCA7E50ULL,
		0x8C81789FEA9DE782ULL,
		0x689E60211381825EULL,
		0xF0874A350BD1D498ULL,
		0x14AD52D6894B0333ULL,
		0x78A9F4705A186A80ULL,
		0x45DC0DD695B1EE92ULL
	}};
	sign = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB07EF576A806166ULL,
		0x55F1120FF4326A7BULL,
		0x32E0543093E50589ULL,
		0x7F37223C6E2B5EC7ULL,
		0xFC61FB253B133B2CULL,
		0xCE36EC6EF8CC0E60ULL,
		0xCE828656BCBE3FD3ULL,
		0xED9CF4A446A9892DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x853FAD24BC77FD9AULL,
		0xB34461DDD235DCB8ULL,
		0xB2A71BEB257EB396ULL,
		0x45C8059227BC318BULL,
		0x2BE2FAADA76FAE91ULL,
		0x7F056A06EBF13C53ULL,
		0xCA925060447FEA20ULL,
		0x2A0A428DFC7A6685ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65C84232AE0863CCULL,
		0xA2ACB03221FC8DC3ULL,
		0x803938456E6651F2ULL,
		0x396F1CAA466F2D3BULL,
		0xD07F007793A38C9BULL,
		0x4F3182680CDAD20DULL,
		0x03F035F6783E55B3ULL,
		0xC392B2164A2F22A8ULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFED998185A276734ULL,
		0x050C0147C4A644A3ULL,
		0xEFAE1D0B11ECEC45ULL,
		0xBBDA3AE2D733AE67ULL,
		0xCD7995C255789878ULL,
		0xE0979D3244926D7CULL,
		0x05466A1CE5F1F429ULL,
		0xD5ECF8E419861ED2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3DA8244F1B631A4ULL,
		0xE45EC8EAF5CA4699ULL,
		0x48B9E6BFAECB8E44ULL,
		0xDF1932B19341C82AULL,
		0xF80F6F1EA2F9FC47ULL,
		0x6F594F9585A36134ULL,
		0xB093777B531123FFULL,
		0xB44BF54A7750BCE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AFF15D368713590ULL,
		0x20AD385CCEDBFE0AULL,
		0xA6F4364B63215E00ULL,
		0xDCC1083143F1E63DULL,
		0xD56A26A3B27E9C30ULL,
		0x713E4D9CBEEF0C47ULL,
		0x54B2F2A192E0D02AULL,
		0x21A10399A23561EDULL
	}};
	sign = 0;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E85CF03AF6F93D8ULL,
		0x9A4B09D91EE74DD8ULL,
		0x1D6EBE502BDB2553ULL,
		0x45FC4A7631F6A427ULL,
		0xB7653377E25B35F1ULL,
		0x5E9D8D14F837996FULL,
		0x04EE8C94A7A7B51CULL,
		0x8A22E74490544414ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x01C6472EE04C8B7EULL,
		0xFF44F4C471505362ULL,
		0x8EE931B23E32417FULL,
		0x9368A81513761971ULL,
		0xB0B6B0DB1763F0B1ULL,
		0xE69A8CEA791DA06DULL,
		0x2B7D320A7BFA41D2ULL,
		0x8372965CFC543F33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CBF87D4CF23085AULL,
		0x9B061514AD96FA76ULL,
		0x8E858C9DEDA8E3D3ULL,
		0xB293A2611E808AB5ULL,
		0x06AE829CCAF7453FULL,
		0x7803002A7F19F902ULL,
		0xD9715A8A2BAD7349ULL,
		0x06B050E7940004E0ULL
	}};
	sign = 0;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBBD0A8CF46DBE31EULL,
		0xF40AE0101752AC98ULL,
		0x88D8A2DD1540D87CULL,
		0xE1A8EEAC8DF9CC97ULL,
		0xCED34FBECC4AECC3ULL,
		0x2078916876E5913EULL,
		0x4FD1D422BA2A3BE0ULL,
		0xE2126315B58E7FFEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3E824499C69D02ULL,
		0x71D7A79CD24F1DAAULL,
		0x804154882821BC19ULL,
		0xFE1F66A38CE6C70AULL,
		0x8C36154993B91166ULL,
		0xB7B7F2639350D09AULL,
		0x23DBBBFF929C743BULL,
		0xB58025F6183F9BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E92268AAD15461CULL,
		0x8233387345038EEEULL,
		0x08974E54ED1F1C63ULL,
		0xE38988090113058DULL,
		0x429D3A753891DB5CULL,
		0x68C09F04E394C0A4ULL,
		0x2BF61823278DC7A4ULL,
		0x2C923D1F9D4EE43CULL
	}};
	sign = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x04BCCDAA6F5BD5D7ULL,
		0x7CE1F6D9D3C78AEBULL,
		0xDF4850AECA1490A3ULL,
		0xA66885AD2F4EF9B5ULL,
		0xE353C933BB8F6BF2ULL,
		0xE9DFCB8DF5C6C01AULL,
		0xC1B8F1FD37F9A383ULL,
		0x0B92EF2E1850F9F3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2210E8FB27D8738ULL,
		0x238FFBF2357A3262ULL,
		0x427161F8A307155FULL,
		0xD388766A5B9A4935ULL,
		0x51FC0BB36408E254ULL,
		0x6D71DF717DCEBD41ULL,
		0x9B7F21979974FDD3ULL,
		0xD0A0F3730B103BBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x129BBF1ABCDE4E9FULL,
		0x5951FAE79E4D5888ULL,
		0x9CD6EEB6270D7B44ULL,
		0xD2E00F42D3B4B080ULL,
		0x9157BD805786899DULL,
		0x7C6DEC1C77F802D9ULL,
		0x2639D0659E84A5B0ULL,
		0x3AF1FBBB0D40BE34ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C3E15CD1F3ED83CULL,
		0x18DDC44DC68DB37FULL,
		0x2EEBFB084F5069BCULL,
		0x6273FC2657952DC0ULL,
		0xA86AABD0C62E0202ULL,
		0x92675B51849BEC62ULL,
		0xD7DF6C112AC49E41ULL,
		0x7B253B5A57617772ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F382E084CC69E0ULL,
		0xE234933DDEBBDFBFULL,
		0xA94DABF1F1164972ULL,
		0x162544184CC56352ULL,
		0xF2B6B3936BF30606ULL,
		0xA08F967C444DA5CEULL,
		0x9799EC2F5166320DULL,
		0x5E61B299CF96AE99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x244A92EC9A726E5CULL,
		0x36A9310FE7D1D3C0ULL,
		0x859E4F165E3A2049ULL,
		0x4C4EB80E0ACFCA6DULL,
		0xB5B3F83D5A3AFBFCULL,
		0xF1D7C4D5404E4693ULL,
		0x40457FE1D95E6C33ULL,
		0x1CC388C087CAC8D9ULL
	}};
	sign = 0;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B0FB6718C0089E7ULL,
		0xF06B39658721FEC5ULL,
		0x4FBA77DABD896EE8ULL,
		0x75EEE1E4EE5AE738ULL,
		0x494852DEF14BE4D2ULL,
		0x04077A98DCCDC3C8ULL,
		0x8C842ABA46FE5883ULL,
		0xB2A4A8A6C49334B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FAB4D9723F06F9BULL,
		0xBAF1A751209DC4E7ULL,
		0xA95C325E0201FEE4ULL,
		0xC8B847E79B067CAEULL,
		0x7E884F3EDB21B39CULL,
		0x26C88B5358C9A405ULL,
		0xFEFAE6E08141952CULL,
		0xDD2620FC1DFED579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB6468DA68101A4CULL,
		0x35799214668439DDULL,
		0xA65E457CBB877004ULL,
		0xAD3699FD53546A89ULL,
		0xCAC003A0162A3135ULL,
		0xDD3EEF4584041FC2ULL,
		0x8D8943D9C5BCC356ULL,
		0xD57E87AAA6945F3EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAEFB20D7CD7AE00DULL,
		0x2EE291D69898A4DDULL,
		0x00CC336955C4561FULL,
		0x75203EA09CA58840ULL,
		0x807905CF9387DC4FULL,
		0xE15172C8161BF880ULL,
		0x2A906F648F4CC6B1ULL,
		0xD5B7E33E6AA44CD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF09CB365B27009B7ULL,
		0xCEB879D4D28B6F54ULL,
		0x36CC5950DAE62A89ULL,
		0xF903A8EE98D3C1A2ULL,
		0x224DA9FDE75FBA0BULL,
		0xCB8681B4EE4AE5BDULL,
		0x9E8BC812E79CA25DULL,
		0xDEDE257FBCB13F8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE5E6D721B0AD656ULL,
		0x602A1801C60D3588ULL,
		0xC9FFDA187ADE2B95ULL,
		0x7C1C95B203D1C69DULL,
		0x5E2B5BD1AC282243ULL,
		0x15CAF11327D112C3ULL,
		0x8C04A751A7B02454ULL,
		0xF6D9BDBEADF30D49ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB7B4A9E96DBBDFA7ULL,
		0x45407F1669329169ULL,
		0xCF5C7B96BE657509ULL,
		0x12380DC86DCBE378ULL,
		0x72BF7F5A9A9F3680ULL,
		0x0CAD6725B9B12028ULL,
		0x82388754ED0A1D09ULL,
		0x79416D0403915DDBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE32ADAB1620C0B76ULL,
		0xEFD9F694BD694307ULL,
		0x82659A8D30C33B52ULL,
		0xAABA7696121A6389ULL,
		0x16EB867740DD89C1ULL,
		0x533AAA5855183F5AULL,
		0x8B8C136EFECEF6C9ULL,
		0xE8C6DBE723739CE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD489CF380BAFD431ULL,
		0x55668881ABC94E61ULL,
		0x4CF6E1098DA239B6ULL,
		0x677D97325BB17FEFULL,
		0x5BD3F8E359C1ACBEULL,
		0xB972BCCD6498E0CEULL,
		0xF6AC73E5EE3B263FULL,
		0x907A911CE01DC0F8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x538CF1CB9FC4B702ULL,
		0xF21EA0BC1372A3A3ULL,
		0x15B215DA40671F53ULL,
		0xECDF4E86078B1A93ULL,
		0xAFDD6892D11C5CA8ULL,
		0x57AC7A315F1995E6ULL,
		0x3403E544402CBC8DULL,
		0x4AB07AB34A21B7FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD144F5F5CBC0BE94ULL,
		0xF45C06F8191B1D0AULL,
		0x48AA236CF7DEEAE2ULL,
		0xF2BAB96F066E17C1ULL,
		0xD05DE8BBFFE7910CULL,
		0x2D0215B4B067B415ULL,
		0xD3D0775106AAC1BAULL,
		0xF387249A15D2E95FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8247FBD5D403F86EULL,
		0xFDC299C3FA578698ULL,
		0xCD07F26D48883470ULL,
		0xFA249517011D02D1ULL,
		0xDF7F7FD6D134CB9BULL,
		0x2AAA647CAEB1E1D0ULL,
		0x60336DF33981FAD3ULL,
		0x57295619344ECE9AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE83B9313091AAC8ULL,
		0x561B5599A1A1B49DULL,
		0x5BF61BA5D4F06CF2ULL,
		0x5A515836ED420E6DULL,
		0xD707BC199128BC94ULL,
		0xA509CBA6DDDCE68FULL,
		0xAEAEF2EC57DDA83CULL,
		0xCD50516565FFB18CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3887F13BD9A22570ULL,
		0x089A08FCD405E062ULL,
		0x750E67D7F489C73BULL,
		0x80BC685CC9F6AFBFULL,
		0x4CCFD3D86D180E48ULL,
		0x59B827A36F520098ULL,
		0x3770F24A460EE2F8ULL,
		0x02BBA4BDD6317455ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85FBC7F556EF8558ULL,
		0x4D814C9CCD9BD43BULL,
		0xE6E7B3CDE066A5B7ULL,
		0xD994EFDA234B5EADULL,
		0x8A37E8412410AE4BULL,
		0x4B51A4036E8AE5F7ULL,
		0x773E00A211CEC544ULL,
		0xCA94ACA78FCE3D37ULL
	}};
	sign = 0;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}