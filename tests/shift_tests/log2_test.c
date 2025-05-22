#include "../tests.h"

int32_t curve25519_key_log2_test(void) {
	printf("Key Log2 Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xDA7E6E92CD11E7BFULL,
		0x06FC8CC0819A3131ULL,
		0x753AC123011D00E0ULL,
		0x2DC8459C85ED577AULL,
		0x73B6AA863225DBC7ULL,
		0x86C0921CB67B2278ULL,
		0x64EC8189D5441771ULL,
		0x1F2D9B28902B73FDULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	int64_t la = 508;
	curve25519_key_t r = { };
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	int l2 = curve25519_key_log2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBC7888FEBE478B69ULL,
		0x1DA3552D726A1DD2ULL,
		0x19731A28A22A48B1ULL,
		0x858A89828CBCD519ULL,
		0x495F602319C2F323ULL,
		0x85B824D0E313D520ULL,
		0xA954C0C02408E98AULL,
		0xDCE463D247D6C153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCD7AF7355FFD4CF1ULL,
		0x3C70825015181BA7ULL,
		0x234115FEC301376DULL,
		0x6CD891CF17AD30F5ULL,
		0x4BE425E78483A94DULL,
		0xC8B92343F7DB0800ULL,
		0xDA81F5823E5F97ACULL,
		0x36F3D26F350A3F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1DCC008814D8EBD9ULL,
		0x221510EBDF8AFFA0ULL,
		0x80DECCC12E04D9E8ULL,
		0xC874C72FE62D4D93ULL,
		0x9B22763787D363FAULL,
		0xC44B9950EF54FD4AULL,
		0x6B0857CF63520187ULL,
		0x252FB2E5E7893923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEA1D58EC9C8D90B3ULL,
		0x60F2601F67143BD1ULL,
		0xC74E909BA5EB0D0EULL,
		0xEE462CADE3E534ABULL,
		0x1F1DF0511706CB12ULL,
		0x13B641F14391DDCDULL,
		0xC3611B6BC5801BFBULL,
		0x838FB7057890E147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7921B516F2ACA951ULL,
		0x0ABFACD9765FFEB7ULL,
		0xCD17174417B61272ULL,
		0x8132A8772A1A5AF6ULL,
		0x896319B4E0D4F075ULL,
		0x41A20B184CC28E27ULL,
		0x916FA3AB4D36F49BULL,
		0x25DE3086E1BB372EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xB6925EB562719F2CULL,
		0xAD545657F9132767ULL,
		0xDF48D8F6FD5EAFB4ULL,
		0x8DC0D84189E200E4ULL,
		0xDF69AFC737C3D2BBULL,
		0xE5BD6777E13D63B2ULL,
		0x93740778A59F688AULL,
		0x0ED9F76065887784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCF306A035E7658AAULL,
		0x5BC987D15B41B158ULL,
		0x6D60BCFE755001F4ULL,
		0x403C2CC3F17F213FULL,
		0x6EB3CCC066F955B4ULL,
		0x132B37EE083F38B7ULL,
		0x0EF440E9B06D2370ULL,
		0x81CA512AE8CA0A39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x113035508B1B60E9ULL,
		0x4A2957F61A6F3522ULL,
		0xE7F76240CD05EBA9ULL,
		0x891718369B09D4E2ULL,
		0x330341D7FC9A06C2ULL,
		0x5A6B6F5CD8E0E1A5ULL,
		0xA5115D059A788200ULL,
		0x204EABC9131C57F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x547C0810583417D7ULL,
		0x0E9015CDBCA0794DULL,
		0x367DA6C49187EC3DULL,
		0x36D3E8F9F08EBCB2ULL,
		0xD88B7CB89322ECD1ULL,
		0x15D8364431D0DA08ULL,
		0xD0A516775F32AC55ULL,
		0x78627AD1E107F895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x98C5434805A9C7F5ULL,
		0x50DE0BBC31D06478ULL,
		0xD5C0335C0B781723ULL,
		0xB199A9AE1DCF2EFFULL,
		0x83023F9C4E7C09C8ULL,
		0x86393A887FC8524AULL,
		0xC0C027A06574E6F0ULL,
		0xD78DC175977977EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xBABF8A5604C691A4ULL,
		0x92453DFAB4AB77B1ULL,
		0xA5AEA9E92D8D9447ULL,
		0x741AA66D7416196FULL,
		0xF09CA998A70EF139ULL,
		0x035215BEACDDA5B3ULL,
		0x6498B3AED4291CDFULL,
		0x1A72DFF63EC1044EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x2AC930F1FEEB661EULL,
		0x4A5BFE4122DA3DE3ULL,
		0x42C299CD458214D1ULL,
		0x8D41CEF390D23048ULL,
		0x524A3F127CC93C79ULL,
		0x225E9FD4A92DC865ULL,
		0x0749F0989DDA0944ULL,
		0x0ABC47C304AD982EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x023C7E20FC63F936ULL,
		0x2C0822E39253CA63ULL,
		0x71B6E81CEC63431BULL,
		0x7A188431724076B8ULL,
		0x4933A728384A504DULL,
		0xAA7ACE7D0AEE0998ULL,
		0xC0B0070FE6F881DEULL,
		0x57D225DF6747F9ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x96E325011E4DF9F2ULL,
		0x905E1BF3C74C9A47ULL,
		0x22BBB02A0A2C641BULL,
		0xD3F17E7E842FE106ULL,
		0x360F80B990CA6837ULL,
		0xE62F9D98E660488AULL,
		0x02337F97E27D31D9ULL,
		0x9B9828BD6AD575FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8D8031B4C5A79A0DULL,
		0x599E2B984B714D96ULL,
		0xA6F7FFC02B7C17CBULL,
		0x777C2AD58DBDC445ULL,
		0x3BD17971FCE720D3ULL,
		0x9EC6E3D2200573EAULL,
		0x51C6B03F6D6B082BULL,
		0xD7F85D21B6E62D12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA1BF4AABDE7A42D8ULL,
		0xE8C3829CA94A061CULL,
		0x4E1D81F8B5D211B2ULL,
		0x3EEE7A7D970A3249ULL,
		0xAAB1D9D3236603D4ULL,
		0x092D2AA601BAD7F8ULL,
		0xFD271338D18DC179ULL,
		0x9DCCAE036164484BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9E9F4510FAEC3D4BULL,
		0xA5DCBFCD67579A73ULL,
		0x30D2FEC5C2CF93BFULL,
		0x5F3F772D194C4358ULL,
		0xE0F2288222C1FD06ULL,
		0x08103C3DE0CA5FD3ULL,
		0x0DEAF9278389EBF7ULL,
		0x43BB1BF5AB591952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD8FBF29EDA606BEBULL,
		0xC6CE44CB3DDED04EULL,
		0x7F442513E2E2F45CULL,
		0xE4C30FC288CEAE9FULL,
		0xF85730B02D181EC5ULL,
		0xA5BED464081A1770ULL,
		0x22328C3D8E8A5AF4ULL,
		0x53F31155ECBAC664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEF4AED97D27EC116ULL,
		0xBEE8E145CC41277AULL,
		0x8FE540472A9C9C65ULL,
		0x08C112286BCBC5A4ULL,
		0x51902C2FF24168ABULL,
		0x342C8EBA072CF215ULL,
		0x5D1C8213AF8ACB4CULL,
		0xB42A6C642F12556CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA58DD42A8D8BD2DEULL,
		0xC392263CCFA5FB8FULL,
		0x7EE01F7A5E042D97ULL,
		0x67745F5531927B62ULL,
		0x3111FAF851D7A290ULL,
		0xC9C9FBAFC0B9A3D8ULL,
		0xA56B3918104225A6ULL,
		0xB3D1CE286F4EAA6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC40C3376E2717FFEULL,
		0x1E803CABCE6B40C9ULL,
		0xC7C00D1310E62D5CULL,
		0xB21B822DC40775CBULL,
		0x2E08A3F53348FC30ULL,
		0xC4412A8F433B5F38ULL,
		0xC2D9C6039C744B07ULL,
		0x3C322196BEE43514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x06C8526BEEC9CA0AULL,
		0x51042853739DA77BULL,
		0x341909E0D23135E4ULL,
		0x96E8F2394012A0DDULL,
		0x4EA67B627673EF96ULL,
		0xC6011E66464A2853ULL,
		0x730CFF440FDABC3FULL,
		0x79BC72EBB60FF768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6C06476357D626F9ULL,
		0x3CDE685FB2561AFFULL,
		0x9ED16BABAFF6E017ULL,
		0xA17BA15A9D6FC266ULL,
		0x93C4F97ECEA68003ULL,
		0x928EF5890B9985FFULL,
		0x440B9DB2B9AD73D6ULL,
		0x3DA99496167AF2EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x47D521B5FF6E91CEULL,
		0x121ED64714B0F433ULL,
		0xDFDCCE98FEE06839ULL,
		0x9BA6F523AD61B0B1ULL,
		0x6F97E4AE4D3DCCBCULL,
		0xA96FC388A1FE0921ULL,
		0xF113090535F26A48ULL,
		0x22E391A18B725D97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x10772E021670CD81ULL,
		0x673FF718DB8D3479ULL,
		0x18C3915DA1689612ULL,
		0x21347D98759FF91FULL,
		0xAD3A2CC3955C7798ULL,
		0x540EED057EEC743EULL,
		0x0A8BED9D711FD5ACULL,
		0xC4B9F391836988E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x421DEB7DDCB7C4AAULL,
		0x0107C5722652430BULL,
		0x1F8161251ACA0780ULL,
		0x4AB30DE0962694BBULL,
		0x9A6D8E42CEEEB9C7ULL,
		0xA3F7BB9D43A6BFF8ULL,
		0xAC8A4151C54AEB8DULL,
		0x15FCC6F161F11EC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5F616E03428BDC54ULL,
		0x679EA0919D7DB09CULL,
		0xA1DFB3235B7556D7ULL,
		0x90C9E85861F9F615ULL,
		0x40E8F5601C2F9EF1ULL,
		0x2A42C5E7312614EBULL,
		0xC27746C68CEB4BEBULL,
		0x2064BC608DED40C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x88FDF069B7003527ULL,
		0x39C74E9F8DD23D10ULL,
		0xEAB1BC0A924E087EULL,
		0xE6CE94F3FA306ED6ULL,
		0x795402EBFA8D7FABULL,
		0xBEBB5352747DF020ULL,
		0xF2AD79E2CC5EB823ULL,
		0x74B30F3E43A300F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA1490A5CA2A3E04EULL,
		0xBF3C7B32F9C6C1DDULL,
		0x92E8F11B5F7DFDEDULL,
		0x0441011FD0BD90DBULL,
		0x7D9E9372A1603369ULL,
		0x65C2D00E40CA85C5ULL,
		0xDC108362924C05AFULL,
		0x44B10F4F32DD2257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2C4EC78A22E85601ULL,
		0x5CB35A75DC2ED47AULL,
		0xD0EAD32900C4A013ULL,
		0x6BCB69EE02CD12E3ULL,
		0xDFD4970EF3CDC192ULL,
		0x200DF6AFC52DE26CULL,
		0xF4F7B4FF686521A1ULL,
		0x95FFEF4265D9005FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1558D2BC86DAA853ULL,
		0x97E254F3C7EFB1FEULL,
		0xA0F7B4334DC5064BULL,
		0x489E8D507A808B04ULL,
		0x106EF7B802C01484ULL,
		0x988D6022E7E9A40CULL,
		0xCEBB4E596FF1941DULL,
		0x481DB53D43819889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x062A54892BD9F90AULL,
		0xFBDF793418C23677ULL,
		0xB9C048515FD30A43ULL,
		0xAAF1E88F9DD0EE22ULL,
		0x95C9960E76B543BCULL,
		0xEBCF9F6402DB7EB6ULL,
		0x7E561AD414E27456ULL,
		0x6D179D4F347CD482ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1CF9AF8F841DEA8BULL,
		0x6A80511569563240ULL,
		0x2DF7C0D5450760FCULL,
		0x1BFA33BD25522B52ULL,
		0x581AC4F441E8DDEBULL,
		0x0B29A5836EEA39CDULL,
		0xBAD63AC5F4EC4F3DULL,
		0xB2C176B662EA883EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDFCE1B46EE9BC529ULL,
		0x60393E991C20020DULL,
		0x67C0C0263E24859BULL,
		0x30B6C84B2D7DD1ECULL,
		0xE25660DAD3457AE1ULL,
		0xADDB0B13A50B7AA6ULL,
		0x0827E8197856CB9AULL,
		0x960BE6A67C683D2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF0F56F5C49E5ED0DULL,
		0x6FC74F56DD8A92BEULL,
		0xF61FEE359C56BF0AULL,
		0xC3FCF96F8838D711ULL,
		0x034CF4D535F1AF4CULL,
		0x439356F0D5753C6BULL,
		0x56C2CFBE54A4ADBAULL,
		0xEE4763512BB79997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x08587AA2FB092C35ULL,
		0x893803AFC722F8AFULL,
		0x01DC9A76C8FCBC1BULL,
		0x723E9C3747D35A80ULL,
		0x662A442F0422B8C6ULL,
		0x4A26EAF9A0AA7D25ULL,
		0x245C06EDBB7B14E0ULL,
		0xF130EE23F7DC91F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2DD144CDC0662C23ULL,
		0x0281C066BDAEEADEULL,
		0x7EF240BFDC3AAC72ULL,
		0x2CED258C8CED604CULL,
		0x878C5B0F3760262FULL,
		0x0875F0C4A9BFE4D1ULL,
		0x826682D70624757AULL,
		0xFDA52503B40545CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5738D775D9612C23ULL,
		0xDA8DCCD5D3176101ULL,
		0xA9B264A79CE4DB29ULL,
		0xEBB718DC283A5D57ULL,
		0xE7E7A02BCD1E04D8ULL,
		0x4CCEF571B5830135ULL,
		0x6BF1AA2D2BBDDDAAULL,
		0x9C2EB682AFB08F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1BF5D194E338D580ULL,
		0x839F616964756E32ULL,
		0x547B8CC4F449407BULL,
		0x020B04ED972700A0ULL,
		0xBDC6E0331B77270CULL,
		0x1E61990E4F4D56D0ULL,
		0x9E04BA3F2185BA7CULL,
		0xAEA80C3DBF45D42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7B43330FF4A7F9E6ULL,
		0x68F1202F2E7E840BULL,
		0x3979325A91234C88ULL,
		0x72CF13E8D6589CD5ULL,
		0x80241EC9842C36BDULL,
		0x6D7D142EC18D9539ULL,
		0xF184D2A314D8DDE5ULL,
		0xCFEF0523AF625F44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4EC0D77383DF1071ULL,
		0xD42A336A37EFD9D3ULL,
		0x3CE647F5FA82806CULL,
		0x538FA99F1FF4E7B7ULL,
		0x7EE916AAC6FF21ADULL,
		0xEC699774E513D191ULL,
		0xEA6B2B9D9FD06BBFULL,
		0xD6D433D388ED5665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4345D2879C62DB37ULL,
		0xC6BDAD75C6B2C52BULL,
		0xA0D0885CA0CA64D6ULL,
		0xEAE96399481EB1B9ULL,
		0xA158CBCA68D5A92CULL,
		0x486DFE3313096D23ULL,
		0x99915B7BFED364CCULL,
		0x8793C05193F7EC56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3B240ADAAD7C32AAULL,
		0xD84CA4867797CE6FULL,
		0xD27259990ED1F457ULL,
		0x24B745FF0405C62BULL,
		0x87570BF5CCB4AD8EULL,
		0x2759D6233B076940ULL,
		0xCDE0A1FEF548685EULL,
		0x6DD1D97CA14B8616ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9ED5658CB870CF1CULL,
		0x19D616C1BD9E2EF6ULL,
		0xD1BFE326BDCA84E2ULL,
		0x789CCA2598DC03B3ULL,
		0x6BCCF6A10A7FD433ULL,
		0xCC041D421E03F06DULL,
		0x20E5D9F7BCFF303CULL,
		0x3D499B32D2448A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF88AC35A2DAD0A28ULL,
		0xCD2A3F57290FBE7FULL,
		0xCCAB8761D3CFDD8BULL,
		0x06595E8000BBB5B4ULL,
		0x5DB6A73E23E3A8F1ULL,
		0x78B6F3AF13C9E5C0ULL,
		0xD44EA6168C625D60ULL,
		0x9E92375709A48B83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x47392A637DC7CAE8ULL,
		0x6EDC1B52D781328BULL,
		0x1AF7E04A5EC378E0ULL,
		0x6EFDA08DCEF25B19ULL,
		0x40796814B720F95FULL,
		0x2D467F7C0DED11DAULL,
		0xAF666D1C03391251ULL,
		0x7E31337CB22930F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xAF78F296DFC36F3FULL,
		0xEB95251DF31E4573ULL,
		0xBAEAF7BF9CBD6F00ULL,
		0x0CF11773ACDDC17BULL,
		0xC2A8E96B03B9080DULL,
		0x81819A3E79B33305ULL,
		0x963862E06205955AULL,
		0x1C15D427BBD2ACD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDE2C60345B24B8B7ULL,
		0x0378DA36060EBDB8ULL,
		0xB5E36C758F117B55ULL,
		0x6513D31A1EF1A2CDULL,
		0xC03F49CBCF6B6BC1ULL,
		0x3ECD8D46BC896B14ULL,
		0x24925AE34C41CFF0ULL,
		0x7FDF2CF73EC5D8B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEC9B2C11E0491CFEULL,
		0x1FEB7A799F86ABC0ULL,
		0x464194C3338380DEULL,
		0x1BA0735576842EABULL,
		0x3F6D655125865534ULL,
		0x3E589B301B3CD615ULL,
		0x9EC4AADDC710AA0AULL,
		0xA9D50AA519874AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x498BFDDC99193274ULL,
		0x757B5C72E4A040D4ULL,
		0xB3E9FF2873C0D1CCULL,
		0xD2B5EA7451C710E5ULL,
		0xED39433149DF8F69ULL,
		0x2586A44C30C00BF4ULL,
		0x6D2A63730E7C2B7EULL,
		0xC93218E92BEDC6BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD42CF6E01EF570EFULL,
		0x920B762081CA11B6ULL,
		0xD0DD33F54E90B0AAULL,
		0xD50E4F5ABB7B5009ULL,
		0x400AABE282FADF34ULL,
		0x264339FEC03A25D8ULL,
		0x4BDA718A9BC72171ULL,
		0x41735B71B532A423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xECFBB948B69C6C37ULL,
		0xDE05647264149A96ULL,
		0x602570D9C2D0613EULL,
		0xF0990F9048597DB2ULL,
		0xE708D6832D8AC61BULL,
		0x6D4068FF94C5B8F8ULL,
		0xBC0A3B20D1780B94ULL,
		0x9C26E2757AFFC828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1E9646D0DFBBDE6AULL,
		0x159D2A28CC2D1139ULL,
		0x8E5C40B793330EE7ULL,
		0x85308E2E85923062ULL,
		0xF6D4B19C1205C20FULL,
		0x100AF0F046773672ULL,
		0x25FB5F530411150BULL,
		0xDF62DC3E5BFBBB85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF4A739F2FE664B04ULL,
		0x17168A80891F93A6ULL,
		0x90D010B52295F304ULL,
		0x3C3545F19590913BULL,
		0x5DB78E52203F1BC0ULL,
		0x4E0DF1CDF24C6939ULL,
		0x66816126C2B19882ULL,
		0xA5AB4FD352F63A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x290C7978186DBDF2ULL,
		0xE45AF33A498204A7ULL,
		0xC982AD4DDF24D2BCULL,
		0xA435264EFAB473AEULL,
		0x437B2B96A04431EBULL,
		0x5445BB0E78ADFB28ULL,
		0x2E6A1A8F40ECB353ULL,
		0x0D9232D798A192FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x1C97DB282ED1A628ULL,
		0xF93B87AE006E61A0ULL,
		0x6C5CADD5772F6FECULL,
		0x0BEFD944125DC5F5ULL,
		0xF25421D29354A162ULL,
		0x583625DE20FF6240ULL,
		0x6A948B861F9D795CULL,
		0x063ADDC64D6E1E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x16291BB4A16C9F14ULL,
		0x79118D8ABAF77CFDULL,
		0x0CFC6AAA3C63F3A3ULL,
		0xAC3596EFE8D90F5AULL,
		0xE8C5AA2068FAF929ULL,
		0xC6B9136F0B8A5075ULL,
		0x873FBD2242CA748AULL,
		0xDE708D5D139FC4CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE0B4D195F6ECF55FULL,
		0x0AF94D16E8FA8289ULL,
		0xA38C9359A54AB734ULL,
		0x87A60CA4F2257578ULL,
		0x0790FD46FF25C465ULL,
		0x2AEC5089158EDCF9ULL,
		0x8920D2F16E67E861ULL,
		0x692045DCABC07D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x117A92B083097FE8ULL,
		0xF477F19C7BA360ADULL,
		0x8B1FECF84F8ADE7BULL,
		0xC432CF0FEEB034F5ULL,
		0x2225DC2121B1BF30ULL,
		0x073FDC9DDAAAD812ULL,
		0x8CFBF7D26954E7EEULL,
		0x6D9D4B6772533578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x08554696C7CA4BC4ULL,
		0xF9B0534E3F806256ULL,
		0x47FD513861B32570ULL,
		0xD5271AE811840E58ULL,
		0xC08882FC4A8C9DAFULL,
		0x364CEB89E8B24911ULL,
		0x13B4125A07975ABCULL,
		0xC951B4176DA95C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xB4F08980EDA9D54AULL,
		0x5DD3970F2462EA28ULL,
		0x4693243C1792B216ULL,
		0x16E3615B6A2EFB3BULL,
		0xEE529D7822D4205CULL,
		0xA0D62F729C82DD1CULL,
		0x97F9286B9077CDDFULL,
		0x0DF00368B77480C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x88A676F14676B50BULL,
		0x8D8A45209C7D4AC0ULL,
		0xA6140A60E99C3B5EULL,
		0x2A0DB60E20665773ULL,
		0xC49EE6D34F527DDEULL,
		0x481D7CCB1EACEDE0ULL,
		0xED9F8DA0B5ACBEF7ULL,
		0x91D65F96DC0E0508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x776F02D56EEF1515ULL,
		0x139E9EC2C5CF8E5AULL,
		0xA13C31DA1E81C0A9ULL,
		0x03D4EABBC66F8034ULL,
		0xA8218964C6683BACULL,
		0x6D75ECDBFFC9EA66ULL,
		0x42D85A409BEB73D9ULL,
		0x349002EDA108C161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1AA23ABA77BFF505ULL,
		0x59874D77200A1F30ULL,
		0x8CDBB4F6FC53625CULL,
		0x1F88273000D42EB3ULL,
		0x1082743612DD95E3ULL,
		0x661DEDE51EDE71A4ULL,
		0xEA12E5D9D29BD686ULL,
		0x4FF6831F84876093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAE3BC744ED62C21CULL,
		0x9BC3C8F202C27105ULL,
		0xA5350C905FDD763EULL,
		0xF640C6A02346519CULL,
		0x341E40181CE5C0D7ULL,
		0xFA88B98707C23F10ULL,
		0x75B6A76681819279ULL,
		0xB545F12ADEFC0796ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAC5BEC11D01CBF56ULL,
		0xE1E90C262CCC946CULL,
		0x6A1D83A886B33B70ULL,
		0x3111EDB35E1BBAC0ULL,
		0xC4387A7B1FBA9C5AULL,
		0xBA4143C132C0F034ULL,
		0x68565B8342F77011ULL,
		0x2D04F471AF463E02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE59DF9C2C99E0FA7ULL,
		0xD73FD37D9A2C7A00ULL,
		0x6C69058547006F2FULL,
		0x5C65DDB6D0581DF9ULL,
		0x2E5454854B168773ULL,
		0x028DCEB7DEC21BACULL,
		0xDCAD69C14B159941ULL,
		0x9E8BEE5EAA9753DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x640477E5148916C1ULL,
		0x5FA69AED0CC9DFEAULL,
		0x48CB99E07554EE57ULL,
		0xFFAC70DB806F0E99ULL,
		0xA3AF5EC66EA84C61ULL,
		0xAD8BB07A262B7A49ULL,
		0x518F3BF077D6C779ULL,
		0xC3BBBB5DA1077DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x75DAEB19213012C6ULL,
		0xF9F0084DB57C990AULL,
		0x297F54F92D9D6F15ULL,
		0x3E7FB953C0BDD3C4ULL,
		0xD5DC2D6ED8BB30F7ULL,
		0x41D72D1ABB38F7DBULL,
		0x86CCF52D6B4D40B3ULL,
		0xEA0A8458E78A8AEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6CEF4EAFDF8E3583ULL,
		0x44E8AFF26DAB729CULL,
		0x73A08BC8DF0F2449ULL,
		0x5EDDB7C3318387FBULL,
		0x3269ABCA612C4AD1ULL,
		0x8BAE38EC2E36863BULL,
		0xCF0DA5C80A6929AFULL,
		0x7F7CE59A9254885BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x17DE217123DE06DCULL,
		0xAD6A5F0E3ABAF48EULL,
		0x5F6874B180C9255CULL,
		0x1337733EE80D6414ULL,
		0x602E926709AA3A08ULL,
		0xFDCD681A4E88EC02ULL,
		0xE2A343B16A76F86CULL,
		0xA3C7C80FF4DADC72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x833C04E4C2457464ULL,
		0xBAD213CE74981A34ULL,
		0x1C0D7A7EFF5A8EF3ULL,
		0x30A0B0C6B7DC083EULL,
		0x578570EBB9DA157CULL,
		0xF29D2AC15F9D4C07ULL,
		0xA46A99C23FE0302BULL,
		0xEB6EE2ED70DFEA86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7F5EFE28EC60D0BBULL,
		0xA0EAE3D04151D94BULL,
		0x3D43908CA142729CULL,
		0x223E6E0E37D5BAC7ULL,
		0x280B00E0CB68344BULL,
		0x15D44C67824E77E2ULL,
		0xBA82FD400617F16CULL,
		0x6F9144E5B88B5BE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5794CEAEDD89327EULL,
		0x2289CE12F1181A9CULL,
		0xFE669829EC012F93ULL,
		0xDDF8023396DF9D14ULL,
		0xCF79F0FC75BDF362ULL,
		0xC20F324FA273A137ULL,
		0xD785D3E16D12C51DULL,
		0x2676C67FA1528767ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB5D377E73420DFACULL,
		0xD9FC964DF9E5F08AULL,
		0xEE14200F1EB31B19ULL,
		0x63508241CCCF0A5DULL,
		0x312573F7ACA2AC6BULL,
		0xA7AE919D9BD9F764ULL,
		0x07C958C7A99522BDULL,
		0xA782C2BFFBB8BC17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4A3E9009712FFA42ULL,
		0xBA5B4FF7BA662A27ULL,
		0x754EACF7EA8AF472ULL,
		0x97436CD2D19BC8BFULL,
		0xF37EA96AE6F11E2FULL,
		0x4B3C5A7C80BCA4C7ULL,
		0x3F0A95E6ABD368EEULL,
		0x39DDF95F81120E74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x64BB258E4157CB0FULL,
		0xECAB4F8C52705A8DULL,
		0x14C130BCD1DBC994ULL,
		0xC2E3A9BE9146D665ULL,
		0x1B39140B40866494ULL,
		0xD400709D9CD47B93ULL,
		0x86D34E92A34292DDULL,
		0xE2939FE997EADAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBF7B14AA6302C1C2ULL,
		0x110EFF146929018DULL,
		0x3396246A24DE5801ULL,
		0x2CD3479DEFCC0E5BULL,
		0x4432FDCBFEC29F51ULL,
		0x70BDA47C2B70158CULL,
		0x8CAC000EA8D7797CULL,
		0x6411088389248020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x49B0A45DB55C3125ULL,
		0x24597432984FDA71ULL,
		0x2403899DEF844829ULL,
		0xD629E751E5E5F15FULL,
		0xE7E4E69973151678ULL,
		0x49D7AD32807FF59EULL,
		0x4DD632DB889E28D9ULL,
		0x099709BF1BCB2EBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF924393DF01921E5ULL,
		0xBBCECBC4D3D0F3BFULL,
		0x59D13CC7551C126FULL,
		0x0C974039171E676CULL,
		0x919ABD43E46F60BCULL,
		0xA28F70BB134E2A93ULL,
		0x8E74A5FF01DCA241ULL,
		0x7EBAFD9CB0FD8E94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x82CE4EE3B81E4E73ULL,
		0xBEC7D84A1104019CULL,
		0x3E69BA075C4A4ACAULL,
		0x0B56C1F6BF96D84FULL,
		0xC271208AC5C83B23ULL,
		0x5EE173B2B16118E3ULL,
		0x80EBE0B35AD392EBULL,
		0xB18CF65DE9D149FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x490337377CFCB255ULL,
		0xDD2652D2CB376272ULL,
		0xBCB358E19E29CBE5ULL,
		0x39DB6FAC071B1E2BULL,
		0x305CD11511E212BAULL,
		0x8F82CAE41117F9CFULL,
		0xE5258CA843060E2FULL,
		0xFD41001520CCA766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4E6C02ACDAE19477ULL,
		0x2CD4F53E88E58CD0ULL,
		0xD623F21FDF3A8F0CULL,
		0x7E23B9AC54CE4983ULL,
		0xEE2D7AD618EF3A34ULL,
		0x48812EF19827B724ULL,
		0x0E3D80903FEF8E85ULL,
		0xE85C455F3BCC34E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3FA06BFE70A03F43ULL,
		0x91D78EA94C088E96ULL,
		0xACB529DFF1DD564FULL,
		0xD746D61FA09B7CE5ULL,
		0x288CE8E866183706ULL,
		0x218379C64E44A5A4ULL,
		0x11BEB5AC6DF794EFULL,
		0xBE817F50DE0B393CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x285388E628259DDDULL,
		0xAF21C64BBFAC19D5ULL,
		0x8670E6AEF5E7220DULL,
		0x1F046D242272EDD1ULL,
		0x174C0F9D770EC22DULL,
		0x1F5BB33BC91D56E2ULL,
		0xA045904194B3482BULL,
		0xDF64688F93E3D9E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x61FAA8E0192541F4ULL,
		0x1D50CE76E93B294CULL,
		0xE5C5DA45817DDCFFULL,
		0xDD73CF81E7FBBF63ULL,
		0xAD9FE05A6ED48F21ULL,
		0x4D096F2C4E98B2AEULL,
		0x6A42DC2BA1C8374FULL,
		0x6D82BB45CDEF840CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBE26ABE56F09CD05ULL,
		0xD041A2F2CE4F6B98ULL,
		0x7A157962442E3132ULL,
		0x7EAE18E37603F38CULL,
		0x7BCC065A7DF74D43ULL,
		0x8EDD261FCCCA5CC0ULL,
		0x458338DC50B366EDULL,
		0x7702465FAD246E92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x71FA07EED68DD551ULL,
		0x3A301546D99E9767ULL,
		0x201277DB0AC86F90ULL,
		0x624D176AC46C8035ULL,
		0xAF921AE3842DC637ULL,
		0x286ED871048557BFULL,
		0x6C5711757F38C35AULL,
		0xE5DA61B691D182D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7125F2845D8F6B3CULL,
		0xA9F7D34787CDD2CEULL,
		0x12B36D155663D262ULL,
		0x8DB3B4D6432F9E9CULL,
		0xFC9E74AB0CC79944ULL,
		0x6BBE919CDA2093CBULL,
		0xBE93FC1D9B3E492DULL,
		0x7D2C2DF3220B79AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDBE4DDE2018F6063ULL,
		0x7F0EE9CD16F0BA7BULL,
		0xB02C821E8D2852ADULL,
		0xA9A22EB40B527AF9ULL,
		0xB1EC7A80A6D9BDE2ULL,
		0x4AA2D6FBEF3C2633ULL,
		0xB4D694AACB911EA6ULL,
		0xAF2EF850F7996CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC05C1B2EE905A997ULL,
		0x935FB7C8B9AB2C7BULL,
		0xB5E068F25687A969ULL,
		0xF9B8D97092057135ULL,
		0x342E619B10673675ULL,
		0x76D7D32CB3A510B1ULL,
		0x0CE9645E47F401A9ULL,
		0x2714260A62AE6288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFAB85C358E82C435ULL,
		0x20496CC5CF0E72E9ULL,
		0x4921408CAFD2BC59ULL,
		0x530A527A4E6332B7ULL,
		0x10812EF6A159BBC4ULL,
		0x0504DF2EDA85E9B8ULL,
		0x4EE473DD95464BC0ULL,
		0x31CEB57D565074FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3E2B2D53AC1B9E8EULL,
		0xB69B510D472936AFULL,
		0x2D6D4D9F316F7523ULL,
		0xC3729B33B764C883ULL,
		0xEEABB1D96D2F3A89ULL,
		0xA2B12ACFE3560AA9ULL,
		0x5064363EDBC77452ULL,
		0xA7AAA6A054BE1574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xA5EB1B909B8B8758ULL,
		0x9039E35E3F09680EULL,
		0x9EC8A6B839562FF7ULL,
		0xD4DF972B01861237ULL,
		0x2ABF2F0C4CEEF42CULL,
		0x4EA696F3C35D544DULL,
		0xB5DC39957032E8E3ULL,
		0x023CC43E5EA21BA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB0A127D757945CC1ULL,
		0xA6DF0C59F1B57AAFULL,
		0x4BCD7A5675B818DFULL,
		0x4E3294060EE7545DULL,
		0x16B1AFB0078F1E54ULL,
		0x7DE773FC96A1ABA2ULL,
		0xD1DAAA76E8D4DF3BULL,
		0x3E14A1BD7BD9D191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x05A51E8EB527BA16ULL,
		0x3C1350F388C29520ULL,
		0x36C54BF1F34A682FULL,
		0x86B1D9887B6EDD31ULL,
		0x802B136C9DEDBCFEULL,
		0x018CFDF4CCA7D3D3ULL,
		0x0C681684D2D7EBC8ULL,
		0x9AE4B06C67B8BDCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x597EE891FC799223ULL,
		0x53AFE09736802878ULL,
		0xE75EBACFA2F408D7ULL,
		0x89AB0E7E0E9C9A4AULL,
		0xB9C77A8C98A1B76EULL,
		0x1950BFA7EB0BBD7FULL,
		0xDD45058FA1A91D2BULL,
		0xF2A68F8B593E6054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x519EA0138951D3BCULL,
		0x4D6CC7F5C2F5A9F5ULL,
		0x5146FA296DC8B5BBULL,
		0xC420D59EAC2CDE16ULL,
		0x43401F4F03381521ULL,
		0xADEC37E690B8A880ULL,
		0x6B499458B5781CE3ULL,
		0xC7C58EF80255D933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x28AC5FCE7A73D897ULL,
		0x0EE49AAAC394CB4DULL,
		0xF67022FEAA43CC88ULL,
		0xC91DFEFC0187E73BULL,
		0x93394014CFF64D69ULL,
		0x494B1450F6C1F591ULL,
		0xAD7E41438DFB2FABULL,
		0x81CA672CA78B6EEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD3F9213EB720EAC6ULL,
		0x1AA7B3242871A9B7ULL,
		0x093FD8DC01909B7FULL,
		0x173DF55B7A46A84BULL,
		0x099221AED575BC1FULL,
		0x6CBADE9274C9978CULL,
		0xEA058807034C0864ULL,
		0x892E4ABD636BB4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB6A679F198222B96ULL,
		0x83444F833D978CE1ULL,
		0xB7A602D79E0DEB5DULL,
		0xEF552C69E2DBA41BULL,
		0xEE3790644F40B784ULL,
		0x6FABB053598B974CULL,
		0x908AA75C9CCAF538ULL,
		0xDCA03E7776C47D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4EEE34FD0BFFE544ULL,
		0x567AA3E1BC7610D0ULL,
		0xAEFFCEE129DC8D24ULL,
		0x7EBB7A173EA970C7ULL,
		0x098D3C879723D2A1ULL,
		0x6F183EAB2FBE9E55ULL,
		0x296B40956F0EE776ULL,
		0x412D002A709B4CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE118D9FB565FD037ULL,
		0x493490B643517556ULL,
		0x714B0CE55BD043D9ULL,
		0x9EB7A8B4CCD03BAEULL,
		0xC78CA07D022F54B9ULL,
		0x3D3A6C2BEDCD4E78ULL,
		0xC7188D95F1306D2EULL,
		0x8E3461CD059DFAE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2748D82C6F4C0E8FULL,
		0x66C64C5CBD3FEA76ULL,
		0x564F22FBBB530261ULL,
		0xF913D5D4AF18EC50ULL,
		0x779697F15FECFAA1ULL,
		0x55BAA93F8E40D8D7ULL,
		0x1E5A2A3E04C52A0FULL,
		0x8FA13E4221F1CB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6017A60F44122AD8ULL,
		0x36E326003240856CULL,
		0x0FD2538FD629BBE4ULL,
		0xA8C5B6232F8A35C6ULL,
		0xAEF9F4012CF3164CULL,
		0xEBBD91D53D09FFFDULL,
		0xF77D8AE777E83421ULL,
		0x57896B5664F43175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9455A4FABF3EA1B9ULL,
		0x97EE31907DD03A2BULL,
		0x07410DCDCEEBDBAEULL,
		0x031B6579DD20BF08ULL,
		0x3B8D3CC23E1D36CBULL,
		0xB0C81B623CEC7EC0ULL,
		0xF8002164F5BD804CULL,
		0xE16287F8A0CE6FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x70AD72677ACD70A5ULL,
		0x0756581580294BCFULL,
		0xB77B6833090744B8ULL,
		0x6F4B198F45C4D30BULL,
		0xC0813C5BD8AC37F0ULL,
		0x7FD8A73B8986D54BULL,
		0x1128D12940159C36ULL,
		0x9D25482F4A3D4CBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x5935797CED605B88ULL,
		0x1E110887454EA941ULL,
		0x3B0FC03A9D28463AULL,
		0x4CAFA5A58B970FD3ULL,
		0x2B35115159A76A66ULL,
		0xB3527EF3BB70BEFEULL,
		0xD9304B52FF945589ULL,
		0x167DE840ED75D5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4B90D79E7406C629ULL,
		0xB67458B55ACD682FULL,
		0xE5252BCFE9593239ULL,
		0xB9DDF342200B359FULL,
		0x2D2B77F5DC420D54ULL,
		0xC33302E8CF3E9886ULL,
		0xE04704B5CBD8A666ULL,
		0xD27E2B0DB8EDDB95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC3A15FD691CC89B0ULL,
		0x329D958654AB4171ULL,
		0xEE83067BCB516446ULL,
		0x8EC2A6B5D2748C53ULL,
		0x3320D8F2F1EEF344ULL,
		0x43DD3303125F2F47ULL,
		0x2EEC1FAAC9F4D8D7ULL,
		0x9057911B84A21140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF9B8DD43BB31D4CEULL,
		0x7D6D83B4754BC9BAULL,
		0xF1D18E41227735ADULL,
		0x42DB6DD95BAC8560ULL,
		0xCB787EC3B4C45C2CULL,
		0xA63FF3E03BACB04CULL,
		0x7467B8F5286E328AULL,
		0xA8C32260EC18E36EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x25662B44AEA8E102ULL,
		0x3DC437B6E086433FULL,
		0x18E4DD21193FDD9CULL,
		0xB2C7503993C3C35EULL,
		0x408FB2C6D8B165A5ULL,
		0x00A3F5F3AC9CAFB8ULL,
		0x52C287B7881EE921ULL,
		0xBEB1D99FA926F914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x513A3F4CFBE1AD17ULL,
		0x9C176F872A1AAF9EULL,
		0xC6311EB5BE0B45BFULL,
		0x8FBE13B15101E6B5ULL,
		0x727477D2CB2B51F0ULL,
		0xA1D90D8E8C3C8A9BULL,
		0x25012F71A5CBBEA8ULL,
		0xED7DA2911A25CAB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0327BC7C6269DB0FULL,
		0x1541940D4CCFDDBDULL,
		0x79DD78EB13897C67ULL,
		0x81A65D5A2E00F607ULL,
		0x81E61AEA3ACA067EULL,
		0x9E811E8E3A9A6AC0ULL,
		0x9611F206D1E60320ULL,
		0xDBEC38418D94E6B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x3AAD8D59A6542E99ULL,
		0x64E147CEB08B8C24ULL,
		0xED5B87B7E3985D6CULL,
		0x3D86C1FFE937B11EULL,
		0x840A12921103F9ADULL,
		0xA7EAFD6AF22AD6E6ULL,
		0xAA1B65F9CC8E0991ULL,
		0x119F6F4067E2D49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA6659F01FD6D0A75ULL,
		0xAA4F9E109E836865ULL,
		0x41F78EE32FB7D76DULL,
		0x862291C1C0E00B44ULL,
		0xDA379B7AFB4243ACULL,
		0xE6A667CF778E1FD4ULL,
		0xC9B998D5253FC9B8ULL,
		0xD7E23005C577639FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x43FB4913C359BAA3ULL,
		0x9F72522E7B4506DBULL,
		0x1E8710F79BA7079AULL,
		0x9CAEEF7F09EF2E94ULL,
		0xE06E6B292C1EA95AULL,
		0xB8CCA3E5E09F5FD7ULL,
		0x51F0DD4A965C1992ULL,
		0x77D85E2DB95B8430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4B480FE1936B3A98ULL,
		0x003989FFB70B9810ULL,
		0x0DB62BC726CC1D43ULL,
		0x6D616ABA828E88E3ULL,
		0x6020A0574D8713B9ULL,
		0x005CD5B29194B4DFULL,
		0x6FA891807B8CEDA0ULL,
		0x3D3C2709EE8F769FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2571D9DE0FCD70E1ULL,
		0xCA9C42EFF9A33C99ULL,
		0x7537AD24059926F5ULL,
		0x92ED4FC60635CEBBULL,
		0xB0AF152F20AC7D82ULL,
		0x0DE797DB5483F477ULL,
		0x93A0D88B0C3C5248ULL,
		0x78721AFD8E14F526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x125B7B70368499B1ULL,
		0x5122159B40A11CE8ULL,
		0x3044EF52DAF3FD94ULL,
		0x4B8E1ED6B1AD3151ULL,
		0xB46BE68EC8AB66F5ULL,
		0x0881CC83DBA4349AULL,
		0xB36D856756FF12D3ULL,
		0x7EA9ACBC87E6A37FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x47A8F3E4C6CB14E4ULL,
		0xE1B2998DA50DE0EEULL,
		0x439078DECD4DB7B9ULL,
		0x4B066FD9AA57B738ULL,
		0x228D549C4B2F7927ULL,
		0xE4DC0E1B6BAEF87DULL,
		0x1340045903138E0FULL,
		0x96B3BC71C8FCB159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC945A3560743B1E8ULL,
		0x932728F8BEB2CA46ULL,
		0xC5185E4550F1DD06ULL,
		0xB21B27782BA1DFF9ULL,
		0x59AA4FC3CA8BFCFCULL,
		0x022A34F3435EF938ULL,
		0xFCD9B79FB6C1472AULL,
		0x1A03D0D0626E2518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFC6EFA6618B54CB8ULL,
		0x03F662C9E796E11DULL,
		0x4270D4A1FA219342ULL,
		0x816F1F746D1E6E08ULL,
		0xDC1C7CC0B33B5FEDULL,
		0x76F851FA3B62D7F7ULL,
		0xB2C42D27943C5191ULL,
		0x5C40E823A8C85927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6F7EF8EE78BADF73ULL,
		0x11B07B15562B6950ULL,
		0x643B4EB31A7A93F0ULL,
		0x9B1D6622C1BB5034ULL,
		0xFFCB3C2EFA6E17E7ULL,
		0x027C18E338719D66ULL,
		0x0C976774732C00D9ULL,
		0xA1532C60C43868D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x10FFFD5611C46DAFULL,
		0xDB12CFDFF98DA77CULL,
		0xBDACE8C498F0ACC2ULL,
		0xD408677807437411ULL,
		0xD7C8B6FDD4B10FC7ULL,
		0x2AA8CC20C89B3DB7ULL,
		0xE8A622F5951AD38FULL,
		0x93B3E6DE64D86F42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x346A8CFE61DDE6ADULL,
		0xBCB40C900CB3F88DULL,
		0x39A35639BF15E7EBULL,
		0x9B8E8CE6A8134167ULL,
		0x3CDF76A9E220E784ULL,
		0x3658F73F9591B338ULL,
		0x107AF6AC5AF94D85ULL,
		0x9A83F436654251CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6E41D84D33162343ULL,
		0x97D7C80B59DB9D20ULL,
		0x0CDA62701B5392B0ULL,
		0xC220E42BC217A3BBULL,
		0xE9B9931D85B6A25EULL,
		0x77B0359CAFE6BF5BULL,
		0x8ACD71759ED5D1CAULL,
		0x1CCB1B07B401C1D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x71E6449DA21F3DD9ULL,
		0xB09470CD52703D4FULL,
		0x21A7340CDC5FA677ULL,
		0xF1C261C6DADBD5FFULL,
		0xD9F73CD264313B56ULL,
		0xD7B77250DA8F72E9ULL,
		0x2E896B5BF93BA141ULL,
		0x0EB184F506B4D896ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x61AFD39BAE1A3800ULL,
		0x02B16693FC924B19ULL,
		0x873E41D66A84EB19ULL,
		0xD04E5BFA511AA897ULL,
		0x239EF04AD74E6BC6ULL,
		0xCB169CC03CA44217ULL,
		0xFAFF3545F7AE1774ULL,
		0xFBC66D6192A9DD37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x413CAD2A0FB4E007ULL,
		0x05B4DA27AECDECDBULL,
		0x8A3B7FD80DF5F7A0ULL,
		0x8D9AAA99EBE6B875ULL,
		0x26AB6DB357469907ULL,
		0x7B22ABD72EDF58F2ULL,
		0x1C1B10E042C582BDULL,
		0x4CEBE547BED8E2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD2280E5D7D998050ULL,
		0x0BAE5F412D247C56ULL,
		0xA7A5C8B417D51133ULL,
		0xAD57A76F8FC48C16ULL,
		0x158BA241C1B087D1ULL,
		0x780B8F57C34FAE70ULL,
		0x28B725293A9AA1EFULL,
		0x475E425F9DC8B7A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC449A4CF5F495BC8ULL,
		0x2E42F56E58F0363BULL,
		0x70525AA242D79FE4ULL,
		0x5D3436958343A516ULL,
		0xDF374EFA311DDD14ULL,
		0x89035E400CFE1E65ULL,
		0xC980437E9343A45CULL,
		0xF702A79703F41734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8BD70BCBEAD0434ULL,
		0xF8963566C91CADA9ULL,
		0xB4AD337163EA1D34ULL,
		0xCA03035842C161BFULL,
		0x7BFF4704D9885C1AULL,
		0xD96420475F5A6A86ULL,
		0xFE48F885253102B9ULL,
		0xEF72D2404FE5E943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x8139B0458900D355ULL,
		0xBE74F5150FE4EC6FULL,
		0x7E7BC1AC2B86C815ULL,
		0x574CC9A9397CF980ULL,
		0x44081EF4CFA4D5EDULL,
		0x2A2FB81AE9CE8144ULL,
		0xF5BC74268D24A7DDULL,
		0x1E066BCBE03A78F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x41B4582A334BA614ULL,
		0x1C4CC03235C89916ULL,
		0xA072F8C4EB4DBEB4ULL,
		0x63B81086014681EBULL,
		0xF65FB98E654CB15AULL,
		0xF77C1184DB00A59AULL,
		0x90539D9047CC2283ULL,
		0xFD87DF3D9A349AC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1E17374614AB9E0DULL,
		0x7AEE737FEBD94415ULL,
		0x7C603A0D70D15DF6ULL,
		0xF6C06DA9E0EA7248ULL,
		0x2DA950E5B9D92302ULL,
		0x84D0D0C39DF52CBAULL,
		0xCB9A118DF775C89BULL,
		0x8761CBB6569130CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFC3E9E2811BBCBFDULL,
		0xAC5B26A72AF49F3AULL,
		0x71320E33D57B9B1FULL,
		0x44DCEFCAD53CD5F9ULL,
		0x351917DEC5BFB75DULL,
		0xBA3DDD7B90B6100CULL,
		0xF494B410157D7C14ULL,
		0x6CEDAC60D0B712E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x64087FC3C9A3404CULL,
		0x58B0F53451DB1645ULL,
		0x2414D2F26904AE41ULL,
		0x9BB97C8308F74290ULL,
		0x8766589A925C208EULL,
		0x313CB61913EF12D6ULL,
		0x1C2D76F7A0EB1BE8ULL,
		0x9DC5196451D3AF6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x05D714F649538CE5ULL,
		0x75725DCFD281AB12ULL,
		0x4472E7EE2821CFA1ULL,
		0x8A283C55611EE95FULL,
		0x45E7592EB60A5E01ULL,
		0xD37007ACFF4FB73EULL,
		0x5B02334E4704BF44ULL,
		0x2FF49E7B28D0C545ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF11D3FB82F692D2AULL,
		0xE79C14D2F04F9D08ULL,
		0x3F553362BCE1218AULL,
		0xB007764C6923DF2BULL,
		0xE137DA3987A52145ULL,
		0x972A460A2C42EDC0ULL,
		0xCA58458F5F77727CULL,
		0x5F4D26BCB25FA751ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9CDA210DFE5B5A4EULL,
		0xDA842E4EA04B9C7BULL,
		0xB48C6083E754886EULL,
		0x1FF5C524033E13ADULL,
		0x9F8B47C81A2FC1BFULL,
		0x4431346CAE224194ULL,
		0x975A18F7E7FF242BULL,
		0x407A6CB1A2A965E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA9C914E211546A0DULL,
		0x2AF65C352415488DULL,
		0x8CF1FF6BF33134FAULL,
		0x089C35DE1871F938ULL,
		0x44752811CAABF6C9ULL,
		0x60F94A556149D85FULL,
		0xB403F40BF9055E07ULL,
		0x8A0F376B0DB575F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9018A6A80068759CULL,
		0xFA14B619FFF41E5BULL,
		0xF1C49B4E0297DDA8ULL,
		0x240CDA96D1BEC398ULL,
		0x8FCE460884CDD469ULL,
		0x2C6B8D10BD252AC8ULL,
		0x68923A603E9E5C97ULL,
		0xA5186B37BCBC677FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x190913683F890ED4ULL,
		0x525CFC83329E73A2ULL,
		0x481416364911BBDCULL,
		0x640A3F67C1B021AFULL,
		0x3C37781E6910E50DULL,
		0xC8D4FECEEDB5FEC6ULL,
		0x0DAF540ADBA61025ULL,
		0xA92237B69DC90037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF76597BE46E74A21ULL,
		0xD75B5BEADDC4F3F9ULL,
		0xB009DA74F9007290ULL,
		0x974729F865DEBBC2ULL,
		0x1F5119478FE4A6BDULL,
		0x111C05ABF9A828B1ULL,
		0x5C0B3B60BA1F0A5FULL,
		0xCBAB2F28DFBF4423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC4789024FD6D6330ULL,
		0x177EF6F980C0FA11ULL,
		0xCCF9BBCD58DAAD14ULL,
		0x16E5DEC5C47A7B8EULL,
		0xBB78980DD84CCA58ULL,
		0xD1690FD062D3744AULL,
		0x39AE90E8D7548BDAULL,
		0xF3D7B8110B5545AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFFB570AD1D1CAD81ULL,
		0x862566AE99585B40ULL,
		0x5A87871D843B55E8ULL,
		0x94F2BF35BC870BECULL,
		0x358EE9B4D000C294ULL,
		0x4BC681F6536325D3ULL,
		0x75BF9AA495A7D2D4ULL,
		0x5417EE2D670DACF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x073BB473E2FCC195ULL,
		0xDB60AF7366C757F0ULL,
		0x5BD9F7A79A45CB10ULL,
		0x162CCB5D7C229313ULL,
		0x3D59DD6D5A86AE45ULL,
		0xE85CB25BBA5C62FFULL,
		0x8FF90B9E46077C6CULL,
		0x63809A551F710B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2B34019FD2AC52B4ULL,
		0x028F25ACE572F1C6ULL,
		0xA53605877C844802ULL,
		0xCACA69C32F94EF06ULL,
		0xD640808BEE968DE0ULL,
		0xA463098D6163FCCAULL,
		0x5CD98458B63587DCULL,
		0x7FB90456FB295CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFB1950FDEF314FD7ULL,
		0xBF16667ACC7204F7ULL,
		0x32477B77FCCAFBABULL,
		0x86B63DA1C7D74E0FULL,
		0xDDE0FED02344FBC3ULL,
		0x67400CAC7A3C9A61ULL,
		0x0B5CA86DB103DC39ULL,
		0x202BB0180B376312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA19AA048C3B427C8ULL,
		0x0965A1AA1BE8E137ULL,
		0x18D409E5D572BDF7ULL,
		0xDA137141940D63BFULL,
		0xD33793F440F4CA70ULL,
		0x0BD47D9D25515984ULL,
		0x0217FD03AA81187BULL,
		0xFB5B02E3459EE003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x2C163B40C9543B28ULL,
		0x4829F870E2040B1BULL,
		0xFB4ED8DA6B0E87DEULL,
		0x374544CCDDA2D9DFULL,
		0xB6F65CDA86FA6B67ULL,
		0xAB6D91AF6861AE89ULL,
		0xF51C14BEE76D2A89ULL,
		0x1B5544C4544EC76BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5AE0BE2CF9AE49C4ULL,
		0xB73BDB346A58996DULL,
		0x944550E9251C8A8AULL,
		0x056824DC0B6F1011ULL,
		0x688AC089CC6FDC60ULL,
		0xEA6D26F413BC1A6EULL,
		0x16D9BB72D63023D3ULL,
		0x5AB82FE4036FCD3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7A7C006D039F4D59ULL,
		0x8F528228B87CFC2BULL,
		0x2A2A1AF8803AE5C1ULL,
		0xAE6C57D63E90605EULL,
		0x7E1263987D738B6AULL,
		0x7D1C2E32357E195AULL,
		0x7000C562CAFD0AB4ULL,
		0xA5174ABAA32E9758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6A3AB2A3957EAD0AULL,
		0x6B02B1583D3531EAULL,
		0x7634E95AC3610965ULL,
		0xFC6AED1F60B2BDEEULL,
		0x41BBFA9E13CF1721ULL,
		0x47652B56CEE2129BULL,
		0x5371E7211B8E6A1DULL,
		0x63FB2819F8FA91A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4C49D2DE0C1CCB90ULL,
		0xC3C46799FD27059FULL,
		0xE509F77DCF4FD368ULL,
		0x5B14AFD4C689C349ULL,
		0xF50DD8D6A78545E6ULL,
		0xA70907AAC23AE155ULL,
		0x280F06BDC9FA2269ULL,
		0x2D7AF4B91CF6F532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5E731A211A666882ULL,
		0x5A3255720F8A5BFBULL,
		0x028EB06C0939BC35ULL,
		0x047FBD37B8CC66DEULL,
		0x75BF5B0C01ABCEBAULL,
		0xB2FC05CDE9AC1F25ULL,
		0x03623B8ECAEFDFBCULL,
		0x28BB715E4E29456AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x58C1C3586C62F39DULL,
		0x8529F775504E7E46ULL,
		0x7B641E8E59BD3678ULL,
		0xF77FE6D386BAD40DULL,
		0x63835901C65F3D6FULL,
		0x68D869556729DD7EULL,
		0xEFEF9DC1648528C3ULL,
		0x85C849B600D203B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x60A3890D8DFE6724ULL,
		0x0D2CF5477F5F5600ULL,
		0x9EC3F46CCA27998FULL,
		0x52A8E7D5B40B6864ULL,
		0x7BCF54F62124ABBCULL,
		0x268D8318EECA0D43ULL,
		0x7F8269F8976F57DFULL,
		0x5328227004259CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x92B52FBE60AE44CEULL,
		0x579BB37849F2070EULL,
		0xB46070AFC7797D30ULL,
		0x9CEE50EF75F4419EULL,
		0x86F7EAAF4CF01810ULL,
		0xBB98D041E01D64A4ULL,
		0x455BB0D2C96751C7ULL,
		0x71C6A32B98285167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4D538B12AA751D5DULL,
		0x551A179D3ED22108ULL,
		0x4633371B2673119DULL,
		0x471E42C765D7A62DULL,
		0x2CFB02C46A7F3AFEULL,
		0xAF9999F6AEEC4287ULL,
		0xCEB65CA70BE82A39ULL,
		0xE55DBBA9DE735BB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1B40E39DA52DB17EULL,
		0xAFB674A262EE0AC0ULL,
		0x5E16C7EAA72ED328ULL,
		0x078FE87A9E939D11ULL,
		0x7BE742FC61335877ULL,
		0xE06A4A78E643C064ULL,
		0x003D10AD074EB6A3ULL,
		0xF9609312D7857BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB282AADC93E21140ULL,
		0x1EE7A7D8DD56F61CULL,
		0x1473692BFC9CD2EBULL,
		0xF234221042308CB1ULL,
		0xB25F8800376ED5FFULL,
		0x6BD17371D2FB7EF1ULL,
		0x179F4D133918E87CULL,
		0xB72713BE9AD05C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2498C27C4D9BD1B5ULL,
		0xD189EDCF6ED61840ULL,
		0xC7F439FF85966549ULL,
		0x78678A7CCC4E4F11ULL,
		0x6CAB72116EDA4C17ULL,
		0x6C5983206A3D900FULL,
		0xF6D24A29F40CCDC5ULL,
		0xEC34D5D03E65F77CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1A6B079C79F08D34ULL,
		0x31D2238FC25CD41BULL,
		0xBC2305B460C50877ULL,
		0xE8C649558A11F535ULL,
		0x97E0BD6AC3C33326ULL,
		0x3351C28D1F253518ULL,
		0x014F718D47C6E311ULL,
		0xCFF9776678C778DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5094756AB4BDB14EULL,
		0x22C307B63BE86CF9ULL,
		0x21E2BFFDF635B9A2ULL,
		0x76BE78A22D6983B1ULL,
		0x0F818F86ACE46549ULL,
		0x0BF58EDB370499ADULL,
		0x4FE8900ACAF19BB8ULL,
		0xD8AFFA568A00EFE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9A10B4D52BD3E336ULL,
		0x96B617FB8A3576E8ULL,
		0x249D0B38CAA03D4EULL,
		0x54481372C6AA5142ULL,
		0xF8F09E53FF5DC6B8ULL,
		0x1001453C0E0EC89BULL,
		0xE388263EBCFA59A9ULL,
		0x8F5B8883789660EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x583419FEC888151EULL,
		0x224E84B8383A7CD2ULL,
		0x39E0432D9BF0F90BULL,
		0x178D1F2F96C7EBF9ULL,
		0xAB02FB6C0AE9B297ULL,
		0x61DC4987C35C3AD8ULL,
		0xACAA53E8960475A9ULL,
		0x95F8C149355371E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x22E7D9D776A5E339ULL,
		0x3906BC732620821BULL,
		0x8C5F7DF6AE6FADD4ULL,
		0x188A993DE9975D8BULL,
		0x9E5C5AB70672B64EULL,
		0xDE1B391B12993CA5ULL,
		0xF7B43A4A0BD8CF3CULL,
		0xBEB21400E0B5C4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x68B23EBD93950AFAULL,
		0xC88F415785C657C3ULL,
		0x5C8E23C69729B4A1ULL,
		0xD09AC2038089BDD7ULL,
		0x25E43C037DA3BF4FULL,
		0x5C7A5CFDB333FD7EULL,
		0x384D56A9F74ADB8CULL,
		0xE2008A1AB00E4BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE8D7F9F99BB160B5ULL,
		0x7F2C177192034CD1ULL,
		0x26FAE2C4B2BF2FC9ULL,
		0xD04CC348F803CC5BULL,
		0xC575239DD7D25460ULL,
		0xCD931CF2E1FBEF1FULL,
		0x78E9B599A8221164ULL,
		0x1649EDD3048250B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x11FC64E8AFD56C63ULL,
		0x3666967BB82A201BULL,
		0x5E6FA4893746965DULL,
		0xDDF0EB1E2B0BE558ULL,
		0x4E818CAB7B6DEEB1ULL,
		0xD77734D6351F0D8DULL,
		0x2102C860F8CA7998ULL,
		0x22B7F1CC5F71A038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x03F8C47E10949F93ULL,
		0xEB2FF7A3B36FDC12ULL,
		0xEF2B897B9E605524ULL,
		0x30C4D5356BFC9E4EULL,
		0x468CB1D783B0894BULL,
		0x8A34337B5C33397BULL,
		0x2AADF4E83E1B1167ULL,
		0xF3867F4F06C378E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFE7724018313433FULL,
		0xCC71940AFC260263ULL,
		0xED85024E1B0851BDULL,
		0x5072F9FF10DA6BD5ULL,
		0xB1106D8A1FFBBC05ULL,
		0x248D92FE0C918354ULL,
		0x6E7C28DB1BD2A56DULL,
		0xE0C9FFFFD3EE2F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFABEEE7319B82F4BULL,
		0xEE75DC3C808D0DD2ULL,
		0xC1712759097EEDD3ULL,
		0x0190C3DFAF7E2548ULL,
		0x87464AAA4E030C59ULL,
		0x4C2B4D0149B4B11FULL,
		0xE6A49A21D2798158ULL,
		0xD87C689CAA527433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD6DF87D227CF8AE3ULL,
		0x62BDB2B3D4D67D53ULL,
		0x3DA295819693215FULL,
		0xC61D04FDDCCF0A42ULL,
		0x21CF55DF56AC6C88ULL,
		0xF4506403810B9868ULL,
		0x9EB05D7CE59A4CB9ULL,
		0x7F0618A32460D417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6DB4F8E8B4091E80ULL,
		0x6C4874AAEA0CA245ULL,
		0x7503A056B4404E1EULL,
		0xA5A6E2E90D383759ULL,
		0x5D56293E8B9DD7F8ULL,
		0x81EF1536D652B6EBULL,
		0x02FCD3FDA6F39D9CULL,
		0x1E3F22ADC7B3376AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x84C6F8AE8C0B74BEULL,
		0xBA9346E3A5F5E6CAULL,
		0xE4E50640546599BAULL,
		0xF66B00B7B4653B52ULL,
		0x3A62AFAC155F49F7ULL,
		0x6BC4CE1B594412C5ULL,
		0x6DE45F48C644FEA4ULL,
		0xA18C77DD9CFA944BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBEBE63077039B7ACULL,
		0x1C61EAC031E5997EULL,
		0x36BAA61A8BAEB076ULL,
		0x8FB94FB73252BF09ULL,
		0x8EBCB376D905F0C7ULL,
		0xE95F16583F6CE816ULL,
		0x1646566ADDC8F02CULL,
		0xC947065D2AAE2585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7F5A9B4858F6483EULL,
		0xD7CC68C645479537ULL,
		0x55B7265FEAF81521ULL,
		0xC89F189249BA3D0DULL,
		0x5E707A3073FF13EFULL,
		0x4B3B721DB6A68214ULL,
		0x185A449E05212EB7ULL,
		0x41459A79B53396FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x02B5D8476EA5F658ULL,
		0xA99B9F761B7CC1E6ULL,
		0xAB36C83A2F909717ULL,
		0x8D82233E66D46C5FULL,
		0x3127ADE7B9A4F1F0ULL,
		0x12865C6D6F7C8C4AULL,
		0x04E1742E141B292CULL,
		0xC4A71CFD112962CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x28150D9CC0429352ULL,
		0xBE688760E54EF348ULL,
		0xB13078AB18A33784ULL,
		0x857D85CCD7559574ULL,
		0x397502957264EAB8ULL,
		0x643ACCBBECCF3733ULL,
		0x3F8BE08C9FC2F77EULL,
		0xAF85B6D2D3C3AD31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x109F26580366BA0EULL,
		0x6C3B5552F4E9A807ULL,
		0x3C98DC947D2E35B5ULL,
		0x6CC5929A75055048ULL,
		0x791DD3BC111750A4ULL,
		0x858F619EE1B6DDCFULL,
		0x6A6CC07A5D946CFCULL,
		0xA392F9AB307571FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1A5FB82224EA3727ULL,
		0x2433357BDB80B752ULL,
		0x4633EE6D24CBCB18ULL,
		0xD3656359EA2932E3ULL,
		0x67399B965240ABFCULL,
		0x4A8FC1A1DEBA6D34ULL,
		0x82D2ECA9F4B453AFULL,
		0xFC219AEA805D9595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0FD3F4419B8AB70CULL,
		0x08365145B8D179F4ULL,
		0xDB078A9181ED3B0EULL,
		0xA164B0935B69AEDEULL,
		0x2312A429879D507DULL,
		0x9994EC7F2A1DD5D0ULL,
		0x3692F0B133FF84F7ULL,
		0x74F742B2FBE9EA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2779234C85BEA825ULL,
		0x95B634415885E17AULL,
		0x32C8818530B51C2DULL,
		0xA9DC3AF8543236E3ULL,
		0x396219878575F5E4ULL,
		0x9F23613C0FEAF7DBULL,
		0x953246170E9E0F89ULL,
		0x26CE7A0CFA595F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5E0FE24E1B1A5178ULL,
		0x65AC345DEF4DC6A7ULL,
		0x8B80B0E4CE3873E6ULL,
		0x27B81E202C76949EULL,
		0x3BC0B475B0EB5B56ULL,
		0x3D979C3DDBC1BAD2ULL,
		0x54A5B956D47A195AULL,
		0x3197D102ABF97712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5C23FBDB2FEE71D8ULL,
		0xB686D842268F6C03ULL,
		0xACB47CF6BD16123CULL,
		0x9565CD0D7A053D26ULL,
		0x3AA7B783FBD13996ULL,
		0xC2D76A26B271813CULL,
		0xD79FF494DE8A3312ULL,
		0xCB91DAF9AF6751D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2AA0875D49B6BAF4ULL,
		0xC8DEA857E02A4391ULL,
		0xAE17104096743732ULL,
		0x0B3F0503503A29E0ULL,
		0xF4AE9D022714C75DULL,
		0x7FB9110237AA4CA6ULL,
		0xAED26DE9F321FB27ULL,
		0xA82528546947499AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE2092C00C1D3851ULL,
		0xCBB4FD6807150736ULL,
		0x226A1BEBCE142741ULL,
		0x8755AC01230D507DULL,
		0xD24B958B021AF0FAULL,
		0x9688D12CE6ED6B75ULL,
		0xD47DAC870A0FC06CULL,
		0xC2B0E9C42AF535B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x538961E931BD8A94ULL,
		0xA63131C0F3FB0768ULL,
		0xB39D1BF39EB3976DULL,
		0xEF8B69C0AA7A51A1ULL,
		0x4F932CB28BB1DE89ULL,
		0xF9F0C303843F6A35ULL,
		0x8E56009FAE618806ULL,
		0x74DDDB004B49A2D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE34CF6219A0451C0ULL,
		0x64845E3B7EF92828ULL,
		0xE8B24C7E3CC01053ULL,
		0xEB2BE85D925E3F93ULL,
		0x530ED8C1A8E5A59CULL,
		0x0985A567E6916637ULL,
		0x9EEF69944E8289BFULL,
		0xA06C2C7118454B97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBB662CFFA6338B0DULL,
		0xDFFDAF7A47B063ACULL,
		0x4AC3CCCAE76F61CAULL,
		0x9D65A71630C33BC7ULL,
		0xBD74B782EFBB7E1DULL,
		0xDBB699E7AEB5F747ULL,
		0x6AA2332575596CF7ULL,
		0x31576F289F29E7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x96C84946AFE00555ULL,
		0x53619B45C2503554ULL,
		0xFB514D9AC115DB70ULL,
		0x88EBF0CCAD503E23ULL,
		0x50134336B2E4D6F3ULL,
		0x7DDF1B98A0469E23ULL,
		0x2314B573BA4A32C9ULL,
		0x79E7854442B82487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDB5F258D8177F333ULL,
		0xAD41EF75B628015FULL,
		0xBF600954625E0AA2ULL,
		0xA01123346C2F96D3ULL,
		0x6C1D52C0F8AD6B56ULL,
		0x8F8CD1B1249B5305ULL,
		0x2BEEC5A9F6DF37C6ULL,
		0x6C71F1B2F7E84305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x40627ED54B77AC55ULL,
		0x40A05097BEC48B53ULL,
		0x641BEE2BFD93715AULL,
		0x51F0F6B8E3FD4611ULL,
		0xC5C2D2F628B81071ULL,
		0x876795F26A4DF639ULL,
		0x7B6C54E2890B66A1ULL,
		0xF46098947F66FE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x45FC5D9D04448982ULL,
		0x5872CC4946E39F1DULL,
		0x596CB17772700B08ULL,
		0x6B285F01B637CF57ULL,
		0x3E03589A23E923F8ULL,
		0xE8BA5BF73EE1C762ULL,
		0x052785AA2E91CC8BULL,
		0x13AF699FEEDFAB61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB325A000801B8E7CULL,
		0x57856AB6B9358504ULL,
		0x795C64D6ACBB0975ULL,
		0x855CEFC7C69DDCE6ULL,
		0xE777E3C507C0AF1AULL,
		0x6EF9C999ADFA602AULL,
		0x1A741E7DC56C8C0FULL,
		0xB4C7A1C880F011AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x20FF3ECD6DD63621ULL,
		0xDECAECE274AE9B4FULL,
		0x1A5167E522949C0BULL,
		0x11965386F1E421DBULL,
		0x5382DF3CBA8A33FBULL,
		0xD9C393A5CD640849ULL,
		0xEB9F720F6B2607E6ULL,
		0x05FD6297D099F511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x12A03F5B0FD02342ULL,
		0x7F8AEFA1879E6BC5ULL,
		0x1BC07A075E8DABBAULL,
		0x141ABD7683A15844ULL,
		0x6C5B416734D4AD36ULL,
		0x07E3D1E0743CD088ULL,
		0xD4878B9E1974B3CEULL,
		0x9C37CA7967D0A3FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD7FA61D539BB6ED3ULL,
		0xB4C8CA740EDE2E6FULL,
		0xC514C962137275AFULL,
		0x95F23C80B16264ABULL,
		0x164FCEA34E6FDB94ULL,
		0xB8778B806BCAF9C4ULL,
		0x9583CE25D239FB93ULL,
		0x763F4717F545A82CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x29FA47760449F353ULL,
		0x32AB716F2D543E42ULL,
		0xC1A03696614ABA13ULL,
		0x6012406FA02C02AFULL,
		0x63247AC046C944ABULL,
		0x3C2977F599B63BBBULL,
		0x56ED61B1FFCF1FA3ULL,
		0x3093FD3DDB93CE8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8B3ED13D073A24D9ULL,
		0xDDECB4F4BFD9B734ULL,
		0xCED776AF9918AF32ULL,
		0xAD368F3B2D546247ULL,
		0xB736F563668CFA3BULL,
		0x62CC4A81E874FC4AULL,
		0x7C83BB5E08ED09D5ULL,
		0x4E66189BB0239583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x96682517ABB978F9ULL,
		0x5DA160D4902A6D6AULL,
		0x2409A869A8863B37ULL,
		0x0500E1EF60D1624AULL,
		0xF9BBEBF8565BBB67ULL,
		0x7471AC106A4C9162ULL,
		0x886EFB20E4095574ULL,
		0x9A6B1205A0505AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF9411095B6E1200EULL,
		0x3649B5F7A21237EFULL,
		0xA90DCD60536EAE1BULL,
		0x04D78ACC5970889FULL,
		0x79D1367D81A11D86ULL,
		0x97E24C1F381A93B7ULL,
		0x3E5C5BDE827B2230ULL,
		0x30DDFE810A002481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x69CDEC4DB1F5A756ULL,
		0x042F0839BA43E40CULL,
		0xE29BD20D8FC09C84ULL,
		0xDE9A78FB283F836CULL,
		0x5A78F95F43B30F49ULL,
		0xD2F250DB163E3A86ULL,
		0xD930663AF8FDC853ULL,
		0x41C3D4F10100D2E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB962BAF9B004EC5EULL,
		0x5094849F9A2E997DULL,
		0x8561A43C72069804ULL,
		0xBD22860F8D0807A1ULL,
		0xFCA9F95304540BF0ULL,
		0x30A969CD94A7F19EULL,
		0x6AA3755C6EC38F8EULL,
		0x420DBA6ADB2FC61AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x81E8340A6DBF569CULL,
		0xA226F4C3E2380E6AULL,
		0xEEE521478A5DF953ULL,
		0x26F8CDE2F9DB9BA4ULL,
		0x2D46A2E7DE6D3245ULL,
		0x33DD359149D697C4ULL,
		0xA895AB6698A03B09ULL,
		0x7CD7B1A1DE3D47B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1BBF251F4DE1B8C6ULL,
		0xDB0480932C35748AULL,
		0x31F4665B26B919C6ULL,
		0xECE10597A13A6B70ULL,
		0xA9EDF6B3E1418DA8ULL,
		0x386AE88133DE7AF6ULL,
		0x2AAADF169BCA3AA1ULL,
		0x5E945FF1D9476C87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xED67C5CE630C4777ULL,
		0xFFE959418491E357ULL,
		0xADBE972931E94B8AULL,
		0x6CD700C1CAEA7D68ULL,
		0xB9A8C3740D914D29ULL,
		0xE6B5B20DC8CE22BCULL,
		0xCDB0B34A94FC5BA8ULL,
		0x2D8489C9F1FE997DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x66EDDBB75070BEE7ULL,
		0x42E361A4791E5BF3ULL,
		0xFFA02200EBB83E4CULL,
		0x77293FA2FBF8921AULL,
		0x8CD7A4431C5E0F7EULL,
		0x2E646BCE744BB89CULL,
		0xF5405778FC3A0004ULL,
		0x908CC3578D4BC67BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1D6FAAE012D3C217ULL,
		0x940E9F27251D0FCEULL,
		0x35583D4E983C7FDEULL,
		0x2CBFE12EADD479A0ULL,
		0x69535DEE1D3730F6ULL,
		0x3DF0E3EF41A47ECBULL,
		0xB5CB7A04E6432C69ULL,
		0xE119682F4F4C5CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x21B6AA877A6F3BFCULL,
		0x2788A7801605CA3AULL,
		0x4939FB1BBF6EEC7EULL,
		0x0DAF16F8C521C429ULL,
		0xFB88FF785127F116ULL,
		0x2278D50246400B94ULL,
		0xC53147D8EF2A6DFDULL,
		0xCAE152456C21D932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9C6EF9DDA6DAE979ULL,
		0x0A7BE1A7B74020E1ULL,
		0xD0C67C984401C031ULL,
		0x7BB5AC111E1EDAD9ULL,
		0x821755108732C10FULL,
		0xBDB1240C66C52E04ULL,
		0x74E6F62D5D8EA99FULL,
		0x85A0C43ABBAFD172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x036887622C5955DBULL,
		0xAF16D5C55AD1FE87ULL,
		0xEAB020C5EB3EEE99ULL,
		0x866E04B9B7820C9BULL,
		0x819A6949DCC7DD89ULL,
		0xDF5F90F7F00AB9FCULL,
		0xA10611799839E456ULL,
		0x0ED2E0A16834E4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9C18CF984A40C957ULL,
		0x09A7556604AAD527ULL,
		0xDF02E855400B1348ULL,
		0x607EF05880FA583BULL,
		0x72F80A65004EF451ULL,
		0x378F5FA394749690ULL,
		0x50017E5C75BD930EULL,
		0xE6F00A7BDEFE9551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFD3E6D3C25595453ULL,
		0xEF42D056B8195AFCULL,
		0x3FBB2CC9F0C5F976ULL,
		0x3D8ADD0F22DDA9A7ULL,
		0x02C34EE8D5D4B8BCULL,
		0x5F1E2BCC809CD6A4ULL,
		0x96BCC70244C0C7C6ULL,
		0x4DABA5D5576D05B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDFA82522E67E93B5ULL,
		0x7CEB01230CCF5F94ULL,
		0x9E19A72172AA24FDULL,
		0x7BD218684A73E74CULL,
		0x73E9916BF953C313ULL,
		0xEB55774254E39719ULL,
		0xA84F2ABC32FB795CULL,
		0x702FAAF534CCF270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE78D45DBB21E9273ULL,
		0x6BF24545EF1599C9ULL,
		0xA71D59DD785EE5CBULL,
		0xDE1F4ECFF23EC9B9ULL,
		0xC5336058C2815D1CULL,
		0x4DC131E865BE363FULL,
		0x2792D084E65C10DAULL,
		0x6FA066B7A0628CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x659230B9B244AC2DULL,
		0x43E41C224EBC7F91ULL,
		0xF949B6BBB98BB4E7ULL,
		0xC89B7397092B1ED7ULL,
		0x461B43263E4E8926ULL,
		0xFBE36A8118725427ULL,
		0xD09AB82FCEC2F633ULL,
		0x92AB06AE46169608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4CD655147B16893FULL,
		0x7F7BFB1E223671B8ULL,
		0xC01B82A9ED8B9C70ULL,
		0x061CD65225F19A06ULL,
		0xEDE5999AEA76DCD4ULL,
		0x9874653F6FA29535ULL,
		0x92CC6CA46D08A645ULL,
		0xABB7F6784515D6FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x90667316DAA620EBULL,
		0x44D774391618C808ULL,
		0x6DB0EB4C417FD43FULL,
		0x8F664A2DF70E6D9CULL,
		0x1C576DDF87A25462ULL,
		0x6306B1DA2A8A73C0ULL,
		0x1B11904D826AFC1CULL,
		0xEAD5C893236AFD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB93EA766AD3D7816ULL,
		0x24E39E5AAD192629ULL,
		0x913BE7BD63AB49E3ULL,
		0xBBB2383281965DF7ULL,
		0xCC8179D3CF448CDBULL,
		0x1779A7E7F856A9BBULL,
		0x9EA0EBE850BC5EE0ULL,
		0xD749CDBF0EB59A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7F0F9EF5A9419C3FULL,
		0x6572635BA41718F5ULL,
		0xF4062270BAD5CF43ULL,
		0x22D446415E96D8B2ULL,
		0x6583CCD9142B2333ULL,
		0x07CC8BBACDFC9C4FULL,
		0x2B3BC933DF46C105ULL,
		0xC75E8E2C2F3D6E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x974FDAF5A9E5CEDFULL,
		0x0F22213303DEC3C9ULL,
		0x24EE04B876692184ULL,
		0x8181179768FBB7ECULL,
		0x72A5E21DF06BAA94ULL,
		0xE045EAA6CA8A5BF9ULL,
		0x3D026FA5CB152597ULL,
		0x6ECDB7AF3F69CEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x1ADA4025BED6EE3BULL,
		0xACD7D5A272827586ULL,
		0x11E40DF15E86F218ULL,
		0xD947587FC43C2405ULL,
		0x9756B99163B374F6ULL,
		0xA08918BB9ED8501BULL,
		0x54EC79264276BCD8ULL,
		0x05E1D419D9D84D96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4F34536D629B7830ULL,
		0x477256475F8265B8ULL,
		0x506603B1DB90EB23ULL,
		0x0251CD49AB0D658BULL,
		0x4D948D9DC71799CCULL,
		0x16411BDE7C32A316ULL,
		0xE1E66A7451349CE7ULL,
		0xAEE8F8C819970AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x485D7C6997F99D99ULL,
		0x171610D4302C39C6ULL,
		0x6DAE712DC759F6FBULL,
		0x1085965C8FCAE764ULL,
		0xBA52826C98BEC39BULL,
		0x55FB4F8ADC523B9EULL,
		0x56010E59DAF35547ULL,
		0x4350B34A9D214D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA54149705D4B2DABULL,
		0x6EF5AB5BBAF63824ULL,
		0x0A386B622EC9F9F2ULL,
		0x7F8EAE8BFC34A7AEULL,
		0x989D9FBBBE21812DULL,
		0x1511174BFAF49511ULL,
		0x1B735DA036253923ULL,
		0x1EA31A4DFCA279F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x44A1C2864B1524F1ULL,
		0x57910603AD56802FULL,
		0x07C750EA2EDB3DA2ULL,
		0xD4F0F1046CBAEDB0ULL,
		0xCFAC77BA639BD811ULL,
		0x382B4E0780761E6CULL,
		0xA9E960B5B784BF76ULL,
		0xF1282C820A849E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4BFF4E5A857EC5B3ULL,
		0x38FCF10226E65D73ULL,
		0x45BD291799BB5BB4ULL,
		0x82B46B781802010DULL,
		0x8A7CBDCF7A598E79ULL,
		0x766AF89C14294564ULL,
		0x4642F519F6E0287EULL,
		0x4B59152029F7F98AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA2A511E4E65106E3ULL,
		0x69D8ED5D22567328ULL,
		0x48DC5DE23037ED78ULL,
		0xAB83EC8EAA28C574ULL,
		0x5463363D0DECDA73ULL,
		0x4350C84A0174C48DULL,
		0x894B4C6B00840D7FULL,
		0xEF28503ED773B4B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x39DC83D4CA93EC38ULL,
		0x6AB33C82FF900B94ULL,
		0x87E8F48D07EB40ACULL,
		0xA65EBFEE73429792ULL,
		0x4366673FFDC8A871ULL,
		0xBBE5ACE1968E1215ULL,
		0xB56DE5166AE678F6ULL,
		0x30894011FC1A6809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x90C656A18A66F39DULL,
		0x12F6A05B3F21B9C5ULL,
		0x013DDE9DB713365FULL,
		0x474F89E1CC752317ULL,
		0xC8ACAB679FAB8F69ULL,
		0xE128D2CE1C212B10ULL,
		0xF3F14C78FF125E4DULL,
		0x9A7CC911E90F67A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1E2CEAF76418B329ULL,
		0x2B97E2C9778E1278ULL,
		0x3E3C25047FE51E47ULL,
		0x3788921F878A8540ULL,
		0xF30AA424DE3B9562ULL,
		0xA20374789D5F0257ULL,
		0x0B3778FBA9C25486ULL,
		0x6D6CE6D5CF554331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x65EF10D7D6CFB61CULL,
		0x07A3796074B64C9BULL,
		0xF550E07E7A668649ULL,
		0xEBC12B915E3B00A7ULL,
		0x8CAF76D0C3652FF4ULL,
		0x9D140DD15E8F1AFBULL,
		0x9238A0070104B03AULL,
		0x3A1ECCF5E2D9AF5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1AC2561CA11EBDA3ULL,
		0x842B02F73158341BULL,
		0xFC7DB4909DAA9343ULL,
		0xDC8EDC964CD41256ULL,
		0xFEFC3287E73E1330ULL,
		0x9FDD93578AAFF4A6ULL,
		0x5053FEF1F716960FULL,
		0x94D82C5344946920ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF943FDC18B234971ULL,
		0x92CD2442939AE523ULL,
		0x8208A26AD62B7844ULL,
		0x490E895944411826ULL,
		0x442287977740124FULL,
		0x446B5074522F089CULL,
		0xE94ACD7059E65FB4ULL,
		0x90DBEF39311A4FFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x82BFBDD06F9A4C6BULL,
		0xC9952C8F16E427EAULL,
		0x4E2545E149D8CEEBULL,
		0x317340837A1EA90DULL,
		0xCE216C1025DA40C4ULL,
		0xEB0A670C7D5311E6ULL,
		0xD987F7B639BEF70DULL,
		0x98758C51E4769559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x272F7F6F9537477DULL,
		0xD5ABB09DE8476167ULL,
		0xB7C57C6EA0333B4CULL,
		0x40CDE504320656A1ULL,
		0xE5BBC5363C75AF0DULL,
		0xBA88C076D16618B0ULL,
		0xDA4FF6C0EC3C23A9ULL,
		0x44727439DC388EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF62F392062831239ULL,
		0x808621D78790CE6EULL,
		0xD7A77BE3C80E9915ULL,
		0xDBF025F7ABB97980ULL,
		0x1F2133EB4363C37DULL,
		0x57EBEC9226ADB080ULL,
		0xBFDEA290D425C43DULL,
		0x80EB0A9209335587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x35B628177B2A9CF7ULL,
		0xCECD472798C0200CULL,
		0x4CD856F2337551E7ULL,
		0xA68C2E0BC0686AB0ULL,
		0xB49DBF5AB7FE026EULL,
		0xCF2CFF411A206425ULL,
		0x801E65C101FE6338ULL,
		0x67F5238406021E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD631F632E48BF6B4ULL,
		0x6CC56CC3FC3A9F07ULL,
		0x0CC1B5166CAA0636ULL,
		0xC66208E0A724E0B8ULL,
		0x271488DE6AB72943ULL,
		0x21E5D82E0400FCA7ULL,
		0xF8B49C6083D34C7CULL,
		0x32BD0617AD5E739EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x017931F626F8D4E0ULL,
		0x98A7A834E82317D6ULL,
		0x0AACF67017D09842ULL,
		0x1E78D6FDBC74A546ULL,
		0xBFAE0EA49DA2177EULL,
		0xA35F40F72CF2A237ULL,
		0x77F1C5849C8A7917ULL,
		0x6293F22FBD08BB94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3FBD86732FE562E0ULL,
		0x35B1EB3AAF662641ULL,
		0xDE0BDF39C8FF4646ULL,
		0x375E63D62F36A61EULL,
		0xFE8F476A1B9B193EULL,
		0xBA818930A90C6A65ULL,
		0xD0B814523CB9A5C5ULL,
		0xCE18A6E6B88CFC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5437C481A4EC5AEBULL,
		0xCED34FC18BD09496ULL,
		0xB0BA5D2220A37F9EULL,
		0xBC3ED24856B2C7E4ULL,
		0x23A6008C5333512CULL,
		0x97F7EE23D7AE18B6ULL,
		0x6F7F33274095F9FAULL,
		0xA2320AA249CBD291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8AC954E0AF248681ULL,
		0x4929857DDF56F7CDULL,
		0xA3A1BAF1BF4EC7C6ULL,
		0x80A896130A6586D0ULL,
		0xC8B262BF030339A5ULL,
		0x148AF4F1CDF36036ULL,
		0x9B0B506184C333FEULL,
		0x5EDE18EEB186897AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7AE462FC3199FC9AULL,
		0x163A44BE5C671483ULL,
		0x5869CC0846675F9AULL,
		0x64A7A44E2CE53948ULL,
		0x1C120C4E725EC968ULL,
		0xF3077BE2F83904F8ULL,
		0x96F2440642E35B63ULL,
		0x2AB329FF2EEA055DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4DBC463859959C6AULL,
		0x86C05467406B9540ULL,
		0x11828DDB32877B37ULL,
		0x212E9F93C9D4FFEAULL,
		0x1D9B7F0AE008F4CFULL,
		0x8E3ABBE9B2C01E9DULL,
		0x20DFEA7F13B3D599ULL,
		0x81BC1724184EE6F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEAE8D0CDC4E77E40ULL,
		0x4DFC6F481B17D38CULL,
		0x36CEE63E660D66DBULL,
		0x574C643EB93FDFF3ULL,
		0xCFC7979FB049BA4AULL,
		0x6B258FA8BFBE3B65ULL,
		0x718A8BEEF81556EAULL,
		0x602A96A9A6672DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x62770C71B3413244ULL,
		0x7DA9276F842D6222ULL,
		0x0418D028A5F5B094ULL,
		0xA9D549414CD6E588ULL,
		0xE26C2629BD306B9EULL,
		0x852C08415D208E74ULL,
		0x749855BEB25302DEULL,
		0xFFF87F470ACEF32EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x905F224668C74C68ULL,
		0xDB9AA0847CE18CA5ULL,
		0xFBB5A8916CF05947ULL,
		0xB6CA325AA7FEE707ULL,
		0x7462182CE01F6BEBULL,
		0xEA87E6AC10AA41B7ULL,
		0x7543ECDA9000F99CULL,
		0x6FCDF6D0CEB90AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE13BC462C5214DC0ULL,
		0x85292756FE426943ULL,
		0xDC8BFB177966AF32ULL,
		0x4E91AF985CC538ECULL,
		0x5CCEA36A629BB144ULL,
		0x9E820C6CFA367AABULL,
		0x358D6D14DAE559ABULL,
		0x73A95BAE1FAE7C0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFEEF9E6FBB2FC0C0ULL,
		0xBB5D334CAFDB2BF3ULL,
		0x2CC5E9739E656449ULL,
		0xAD493407D1CB3EDDULL,
		0x4F49A3C483CB3C3AULL,
		0x295D5F6B2C5DB0F9ULL,
		0xAC7F51A0E4214085ULL,
		0xB64709141344FECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB15B0B8C5C0C869FULL,
		0xE946E1ED48FF6814ULL,
		0x30F12BBD46AEEAC3ULL,
		0x334E182D08CD936FULL,
		0xB51DB3E65B289224ULL,
		0xB18700B4DDAF9D40ULL,
		0xC903E39C5BA957AEULL,
		0x191DEDF8BC654B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2EC40FCEA61A6451ULL,
		0x6A290BD4F41ED6A5ULL,
		0xCE15747878251669ULL,
		0xB09D67B97536ECE6ULL,
		0x0D7622768327D621ULL,
		0x8BDB5B9C00D9395BULL,
		0x2F87D83AB7D2C79FULL,
		0x6F2B251874340718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x96969DC3886D8BF0ULL,
		0x1A09E0FFB581691CULL,
		0x6D87358089742870ULL,
		0x4977556B5299451AULL,
		0x5FED37DA103B30A0ULL,
		0x8522D0D745B7CB1EULL,
		0x449336AB8945FF94ULL,
		0x8E432D6277B0FE0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x92FDAC706CF3DE24ULL,
		0x97CF250AF1F25558ULL,
		0xACC131F588ABAF0FULL,
		0x9ABF60C778A5A9D9ULL,
		0x10B2189618A01F79ULL,
		0x2708897B33A468C6ULL,
		0xC698035D6F42DB66ULL,
		0x81BD130424C02A7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xBB9E54E78D086FDDULL,
		0xD83C465D0807FA27ULL,
		0xC3CB632D4B13476CULL,
		0x6ECAF498F340361EULL,
		0xE0C3903E0531BDEEULL,
		0x72BDF43FC52BC937ULL,
		0xBE8E6D03D4702B91ULL,
		0x01714883395D39C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x17188653B55B067AULL,
		0xBAC5CA6827255EC9ULL,
		0x58DBE0206BF31BE7ULL,
		0x9138109C22C04A6FULL,
		0x857374737B9F7313ULL,
		0x4CCC699069C35B6FULL,
		0x6FF66DB6D410E9E3ULL,
		0xA606DBFF3824FB94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE48CFE87818542DEULL,
		0x7CBC9D1ED6573174ULL,
		0xC48B399CE0293E48ULL,
		0xEDE85C6304A20AACULL,
		0x966D10AAC2F7F208ULL,
		0xE96A99B5DEDDB1C3ULL,
		0xC7619D7FD63AAE19ULL,
		0x16CE1FD8920EF08AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x8F5179B8262E53FCULL,
		0xCF5BDEA7CAD07B95ULL,
		0x344254C3DCADF657ULL,
		0x1AAF57ADAC8181B6ULL,
		0xF0172C238DC89590ULL,
		0x6BEC2EEAB42F6D30ULL,
		0xB5B646C3F0EF9418ULL,
		0x0732A8E024175E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x31C233260A98EE07ULL,
		0x35BA0A1AA95EC08EULL,
		0x1DC78060192920E5ULL,
		0x8D913EE7B11296A0ULL,
		0x1104D24604D72E12ULL,
		0xDA2EB42C0365372CULL,
		0x0827CB37A793ED36ULL,
		0x58081CA44C53884EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x41C309C34583453BULL,
		0x6194CC9397C91F04ULL,
		0xF42B9F63DE759BEBULL,
		0xDFE9A2653F59B5DAULL,
		0xE8BC8BFE819319B3ULL,
		0xFC8776504EAC5394ULL,
		0x062295C2D3F7B9A1ULL,
		0x53B77D45856C6734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDE6A9BEE568C70EFULL,
		0x709E3C2FAA965E8DULL,
		0x467318B0F5209829ULL,
		0xB46DD336DAD9B024ULL,
		0x061C50E551189A4AULL,
		0x7227EA70A6B5D695ULL,
		0xF87137993B8AD657ULL,
		0xB16C42932FF4B007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7493C1956AB58F2CULL,
		0x50CBA801D122C6B5ULL,
		0xECE28A48D8D453B0ULL,
		0x06C1B78F20A52DE5ULL,
		0x6B965BD94269F59AULL,
		0x9FD718CC27A988A5ULL,
		0x0697F6D106100CF6ULL,
		0x3210E1A2EB1806BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA6865B1E123A5FBBULL,
		0x07A4F7B77F4D4971ULL,
		0xE9622B407FA8122CULL,
		0x642362F0B9C1095BULL,
		0x8C89FF73FFA34CE8ULL,
		0x8081B1B6C354C9DAULL,
		0x21E5C8BC717FA4E3ULL,
		0x74E6F317D4772A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3CE6AE9B93AA29C4ULL,
		0x92E4F6DB4582B7D7ULL,
		0x3B149F18DBD0DAD6ULL,
		0xA0E960B1E63A24A1ULL,
		0x7D3DFC7FDF9C6C6BULL,
		0x3E3E74DBDE0F5558ULL,
		0xDDB1BAACEC677BB1ULL,
		0x4AAEFD3CA1307F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF409CE2191F10BDDULL,
		0xEF7BE101E1EECCCDULL,
		0x4BF8E353D674DE0AULL,
		0xFDBE39BCF89D5ECEULL,
		0xE4F75E50F0B4D88DULL,
		0x15A7CD0CC24D7062ULL,
		0x733429227F9235E2ULL,
		0xCD9F39556EB4DA55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x31FE7298BA4F585DULL,
		0xC829B5B092D3089CULL,
		0xA31174E9B7837CEAULL,
		0xB0D720ABFFD38B49ULL,
		0xA2736080F10D6016ULL,
		0x122689025FC6BA25ULL,
		0xDD687F454D509532ULL,
		0x8D32FE15040A8613ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9AA04C2359C6284CULL,
		0x1F44F689B0A701AEULL,
		0x02D24EB7CEC7F97DULL,
		0xAAB80C07143119C6ULL,
		0xCD2F349F7D27C97AULL,
		0xC1A182A0C207EB31ULL,
		0x55B677EAAB5144E0ULL,
		0xE8832DAB95999C03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0A7CE746BC3F0691ULL,
		0x7944FB2BF4D3A951ULL,
		0xB1B15069396491EDULL,
		0x463FB7EB58546190ULL,
		0xB08838C0FC936792ULL,
		0xA91233F2ABFE7CD2ULL,
		0x42FFEB9E7BB8027BULL,
		0x775721A8EC023160ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4AF61EFD17572A66ULL,
		0x1CF857E58F1F7B5FULL,
		0xC6E294523146ADB8ULL,
		0xA5937D04AB759A16ULL,
		0xCDC17EFBB029B73AULL,
		0x1708C9E4915D9F3FULL,
		0xE5C0E377C71A008AULL,
		0x2E0F69D97A5F3509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0DEBA2ACFC388359ULL,
		0xEAD4FCC6719E7CE7ULL,
		0x06AFF9332DFB4827ULL,
		0x2FE037DCA3910BCAULL,
		0xA9706F4ABA85AD44ULL,
		0x4606ABC74A97B40BULL,
		0x5F48D7BFE0A008D5ULL,
		0xE129B9F3BDA69FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB0D534C822D6E5FULL,
		0x0AB7CD33EB7554E7ULL,
		0xE4450B6D3E5EEE26ULL,
		0x8A1F175AF54C4F92ULL,
		0x78FC125EEE28C509ULL,
		0x3E967CA4795D4904ULL,
		0xC0A105A8CC714429ULL,
		0x87B35CC0AF99F5B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE42E152D5FA1BA19ULL,
		0x99D4DB1F677ECF0AULL,
		0xD3EA05AA1624DBE2ULL,
		0x82423C1A31140CE7ULL,
		0x47E0A4617C3A0C41ULL,
		0xC391A3631A59A5C0ULL,
		0x08665F608FA5DFFDULL,
		0x635F9C21660C8529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC343566EC5142A2AULL,
		0x4B6E291D3FE7EFA4ULL,
		0x7E393C4C534187BBULL,
		0xC0EE549B4844C921ULL,
		0x9AD2379BEE13F21AULL,
		0x51974EE47CE22EC5ULL,
		0x3C5D547CB1C61C2EULL,
		0xF5E7932D4A3FC126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0xD0758AAE648F6362ULL,
		0x7378238BE5B8843DULL,
		0xEC89EFD83AC1A437ULL,
		0x85E9101CA3DA4FAFULL,
		0xFE99FB3AB7154460ULL,
		0xD521FDE7C28FFA5BULL,
		0xAC3C2C12ABA22E12ULL,
		0x00F8307A659E9430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9F9891B2E48BEA73ULL,
		0xE81D86EBC7A7C77AULL,
		0x599092154B6A86E8ULL,
		0x4AA9B68A3D95B836ULL,
		0xF1C8B4D49C8F116AULL,
		0xB57D86806826A64EULL,
		0x8139039566D79C3EULL,
		0xA2F2A44CFE97928EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4476BDA2578696F1ULL,
		0xDCC267F3324DCA69ULL,
		0xFBAF3C21740DB37EULL,
		0xB3633C868E63F6EEULL,
		0xD881A7B915B5D385ULL,
		0xD746654B0B8E1068ULL,
		0x48C0685AF2159783ULL,
		0x42A7A4CCAD8F7C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x08E2E5123880B769ULL,
		0x28DEB31F8E5B51FAULL,
		0xF384BADFBEC30EEDULL,
		0xCCF96D70DE457F52ULL,
		0xBBE831C7C18E004CULL,
		0xDC95044640F72D00ULL,
		0x41656EA5DDF86D05ULL,
		0xE2FD0248DAF2D31FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9F459D5FD527AC9AULL,
		0xF9EFAD92B5E8042DULL,
		0xAE3E95C09C708164ULL,
		0xE4E5E025875BB308ULL,
		0x77F6E28870757CC4ULL,
		0xBC403791397E9B3FULL,
		0x11125ABB3BC158EFULL,
		0x51646FDEB45EFF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x67DEAD5FF63D409BULL,
		0x87D1F84781422D89ULL,
		0x1A35569FF303A14EULL,
		0xD068C2064E27D927ULL,
		0xAC81AAC50861479BULL,
		0x6B76FC27E48383E3ULL,
		0x3C03E5531139931FULL,
		0x39F121FFD2A3DC01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x64266F7419F5925CULL,
		0xDEB4C71FC132DCD5ULL,
		0x8D19D80EEEB2689FULL,
		0x04F0ABDAA3936D57ULL,
		0x3E0492AF27732C9CULL,
		0x018444C8691C7458ULL,
		0x217E28250D22466AULL,
		0x2802C18E5B0A89F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAB1D3B2E6F6D0F4BULL,
		0x59ED2B54574B9EB8ULL,
		0xC44665B2BF6C3CD6ULL,
		0xB769E8AFB5B8D355ULL,
		0x5A7169B8DD924415ULL,
		0x40A5B27CA4134A8BULL,
		0x84A5D76147B16B0DULL,
		0x637EA5061B79AC81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x061109A4E8112263ULL,
		0xD5A098F512FD6026ULL,
		0xADD94D77240FD4DFULL,
		0xDD7E4D194EB354C3ULL,
		0x6FE24011151C55CBULL,
		0xF503DD11AEA6A1E4ULL,
		0x2756BCFC33F5AB8EULL,
		0x5CE61B9B85749E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x60C5F71C431131CEULL,
		0x4A316FB70ADE5252ULL,
		0xCE71CE7C61BCFDA6ULL,
		0x8E236017CE58C43EULL,
		0x421600B59EBE0229ULL,
		0xABAE40F6914F6E2BULL,
		0x8FC3862BBF5C3E01ULL,
		0x6EABCE21DE1ACB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xDD195FBC06CC5196ULL,
		0x7201ABD56385C0D9ULL,
		0x622B5B054F7B6F5CULL,
		0xAD73CA6A7E403346ULL,
		0xA3E03B80A06EA0FCULL,
		0xF766FE8FE70E7014ULL,
		0xE9B620B881385135ULL,
		0x15CA3B3A1C1F036DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF41AC20697CC782CULL,
		0x3CA27F1971075B6AULL,
		0x25F027D17FF94EF7ULL,
		0x07C1EA24ADB7500CULL,
		0xC4F4BC702BD82674ULL,
		0xEFC6BD8C6822486CULL,
		0xC23839034B37E123ULL,
		0xEE7933A8E5D6D0ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6718DB0DFD2BB9BCULL,
		0x60592153307CCC71ULL,
		0x611F6DC511530965ULL,
		0x384713DADEB4E314ULL,
		0x4734C5B8183DC1CFULL,
		0xB5D9B99C55098884ULL,
		0x5B345D5C7D8AAAB7ULL,
		0xF74A5EAA95CE4FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x43E6D5941DD5ED64ULL,
		0xFA20381A847AF659ULL,
		0x09016C2870BCACAFULL,
		0xB378BA0A04269872ULL,
		0xE1A484D74A12AB95ULL,
		0xC614F3D5A60E8265ULL,
		0xF5A8F45B5FB39E86ULL,
		0x5D74B946F48C2CBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x537D2D966CEC620FULL,
		0xA8CC7007F67615C7ULL,
		0xACFD54C229977F8CULL,
		0x7E56196320803122ULL,
		0xC9107E8ED45A8F80ULL,
		0xF431A7A07E1B4A06ULL,
		0xD13C4FCD8D85BF4FULL,
		0x69D7C94A16E43FB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	la = 502;
	k1 = (curve25519_key_t){.key64 = {
		0xA4EA052F36DEAF40ULL,
		0x509D129E3E30F5C5ULL,
		0xABA150EC721D9E3BULL,
		0x38A2F1377F318C83ULL,
		0x7277DAF0DEC6BB02ULL,
		0xFA33200A8485B7D6ULL,
		0x28FBCEF6FA0806BBULL,
		0x005B7D1A5D68FACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xABB5C75AB868EAACULL,
		0xF9F44D901F415EB7ULL,
		0x329982BB4AB1B8DAULL,
		0x7E571F56CD98545AULL,
		0x694632F2C9B422FEULL,
		0x027027D6C79877DBULL,
		0x667B6CDD2B12D3FAULL,
		0x327001F8CA000F4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7B4A54A783F76568ULL,
		0xB00FDC3358FE7F75ULL,
		0x1818447F87D53861ULL,
		0x81471731D1F74D1AULL,
		0xD6A54DD50FEFFD90ULL,
		0x221AA015AFCE9188ULL,
		0xFAFA2BC9C4FF932FULL,
		0xBC84F96F38FE96B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD92F6CD6345AE310ULL,
		0xFC115FC8C24B1152ULL,
		0x0716380501BBE099ULL,
		0xF503FDA6C21E983CULL,
		0x7B665DFE18D80029ULL,
		0x0EC4DCCACFA9D7F9ULL,
		0xA4BE95FFAC560667ULL,
		0x909B01FC88005431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE734965757279E91ULL,
		0x17DBD730EAB0085EULL,
		0xB49B524EBA9D062DULL,
		0xD645D0F7561E7700ULL,
		0x732318F8009272EBULL,
		0xEB05329950E0AE38ULL,
		0x47BACB4A5EA993F2ULL,
		0xED555AC2F367EE1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x70C4D44283C922E8ULL,
		0x674B9A6E46B31286ULL,
		0x0E760EAA04A95E31ULL,
		0x3170A9BE452BDEEDULL,
		0xD1A1B0A5E59317ABULL,
		0x4F68389CB5A057C6ULL,
		0xDECEA6E59A7467AAULL,
		0x2F0C92779B4BD3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7B886A591EFF234FULL,
		0x2D48FB8FDDE3CF93ULL,
		0xA3C9427EF71207EFULL,
		0xE40CE1F43D9AC9E9ULL,
		0xA69412D127369E39ULL,
		0x4056C19E8B7DD23BULL,
		0xD01C6806EB4A4E13ULL,
		0x8F06E5BF8153E6BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4165F57F2D75228EULL,
		0x52459F57E4833CE8ULL,
		0x2517091E36ABAC55ULL,
		0x6E76FF120A58F8C7ULL,
		0x406F5C079FFBB727ULL,
		0x37598018369DAA9FULL,
		0xC99627258319A4BCULL,
		0xB82D99831F210725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xB98908E82CED0A24ULL,
		0x977AB96A267A5A8DULL,
		0x83C980DC8312B7C0ULL,
		0xA100AE78B2BFB897ULL,
		0xF8149039F7B3419FULL,
		0xC4A43D37E0C945E5ULL,
		0x37D9A900372641AEULL,
		0x0D95B9EAFC039DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0x5B2B8BE026EDE64BULL,
		0x5731DF7EDAF3BD8DULL,
		0x6A9FA6EDA04EE721ULL,
		0x095455CD393CA252ULL,
		0x224037B58357FCD0ULL,
		0x87F4AABA15A5ACCCULL,
		0x79C1CE8A289B6508ULL,
		0x00A23AF70A19ED03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEC134ADC6EB1C160ULL,
		0x68918C4090DA98CCULL,
		0x3680968DB128EF77ULL,
		0xF440707B0E8429D6ULL,
		0x2233AB7B62A23AADULL,
		0x3984B14D8504126DULL,
		0x22DD40240C05D4E9ULL,
		0x9268B4D2ADBF71C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x280DD1CEBAA26C1FULL,
		0xDB1C4F8858B60E1FULL,
		0x1D4420F6B6AA22F7ULL,
		0xC163AE268FDB19ACULL,
		0x484FA07F994923E1ULL,
		0x3EF87C2D87C8DB05ULL,
		0x5F327E3EDA2F277CULL,
		0x7BD021A1C4DA77F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBECA215E9C745BDDULL,
		0xF611715E384E4AFBULL,
		0x1A86E7493DAC1BF7ULL,
		0x8527F6002235F8C0ULL,
		0xC214CDD0C85F31E1ULL,
		0xDEC301D1FD9A8F27ULL,
		0x13958C7D95523F50ULL,
		0xA329E17ADEF01FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x9842B4582C1EF6A9ULL,
		0xAC4325478EDBE302ULL,
		0x51C6C77E2CD7ABB9ULL,
		0x2CDE875E787B85D6ULL,
		0xD0DEC53B3597A8F0ULL,
		0x1BE5987830D472C1ULL,
		0x72CA8633FA6C563AULL,
		0x1A0C00F345B1F557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xECE05FAE649F5AF4ULL,
		0x144CD97513427317ULL,
		0x2FF696E3816511E2ULL,
		0x7CF0D1465693B798ULL,
		0x54C223D2EE0BFC1EULL,
		0x7E551B726FBD5913ULL,
		0xFA64D24DE5BD49E2ULL,
		0x59D2F1DD0D24FA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB45A97599608A552ULL,
		0xAD05DFFCED31BEEFULL,
		0x6737E89E0BCF0B9BULL,
		0x077C24B0DECF53F7ULL,
		0x89152C08A66B6D71ULL,
		0x8121F1112A27D738ULL,
		0xA251A71CE4B552B9ULL,
		0x26DC5A6E18E67DA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x19EBA5A2AC7778EDULL,
		0xAFEE866B5FA76099ULL,
		0xD2055F9CBEC1E293ULL,
		0xE554BBABD10CB2F5ULL,
		0x26148641CBB6D19AULL,
		0x89B153FD8701C5ECULL,
		0x37E04502C6C19D4AULL,
		0xCD1C7640182DB474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x26D193748147D5EAULL,
		0x742DF222E98515CAULL,
		0x16299AAFE31BB0D3ULL,
		0x965BD7F1B06D57C3ULL,
		0x859B080526A313CBULL,
		0xC4678D1C785CE2DCULL,
		0x225E49761C4C74B7ULL,
		0xCBB6EED049650627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6ED89EF56F0B54F7ULL,
		0xD315480EF2DAE218ULL,
		0x03349DF4E0EF08E3ULL,
		0xC333999D716D04AFULL,
		0x05606189C830AADCULL,
		0x50FEB8B3B133A871ULL,
		0x57F46784C6697533ULL,
		0xB9EC713A3DAE7104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF346665BFE4BF316ULL,
		0xC375EF3A06CA89C1ULL,
		0x6BDE0431F46DDF1DULL,
		0x83042B0B6D1A2ACAULL,
		0x7EA755BA98E4CD0BULL,
		0x67977E8C51100B7CULL,
		0x9FE778519EB53AEAULL,
		0xE31F121B0CBB8DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD6BB05A1B8E61A04ULL,
		0xE186C97D1702C38DULL,
		0xA76A09263351A023ULL,
		0x955187CDE3BBDF21ULL,
		0xFC97D6346FBBC320ULL,
		0xC443A3DABF7B6EC3ULL,
		0x892783BB84114306ULL,
		0x6673FF3703CE5DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF9B7431A17E3AAFEULL,
		0xF759FDD4E99A7E57ULL,
		0x3582F4C11FD5B3A4ULL,
		0xF67236AB61EF5C13ULL,
		0xD9BA13567BECF599ULL,
		0xD7CE73F0F02A540CULL,
		0x00B988F464907AB1ULL,
		0x6358C35DF68C92B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8D9488EB8DD5FCEFULL,
		0x3E95594F11BD95D2ULL,
		0x97178B4E1C67B872ULL,
		0x6E4121BAAE364CB5ULL,
		0x7169D90037A26603ULL,
		0x92C17680B2892299ULL,
		0x80953B27293E23C6ULL,
		0xB8FF162FBADEDD52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x215D6FFB4B9528CCULL,
		0xF6356308764E1E36ULL,
		0xDCEF9D922CD0A236ULL,
		0x7580531D2EE6DB5BULL,
		0x9A7F1A75D62FE896ULL,
		0x8B69D3301DBA28BFULL,
		0x52221CB9ADBB1477ULL,
		0xCE5ED1D92BA04385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDFB3F200DFB5348EULL,
		0x7A9A10E9709E995BULL,
		0x20BBF338AD8C590FULL,
		0x3A0EE56562BB9AB0ULL,
		0x244DFA18325685BFULL,
		0x1018CDB7E6144C30ULL,
		0x5F3C1788AAAF3ADBULL,
		0x7E7B80D71766669EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x43B8B5CEAF3C2D76ULL,
		0xB16CFD3CB17D5B61ULL,
		0x19976477726E6C67ULL,
		0x42EA61CAF2609FC7ULL,
		0x7D3B4AF75A6C89A6ULL,
		0xF07D6EE03E9A11F7ULL,
		0x5371507E39BF792EULL,
		0xD64021EF1888DA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x83B8B9D4B4CE1F5EULL,
		0xE545AFEF31D6DEC8ULL,
		0xEB151C5F677A739EULL,
		0x45E103D9CCFA3702ULL,
		0x331AF50E03CA6D96ULL,
		0x23A14A54FE60E41CULL,
		0x58C444E2E626E169ULL,
		0xEF200D2840B61077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE4DB6443C68B5766ULL,
		0x84EA397A48ECCF1FULL,
		0x798B6A7725E5D5AEULL,
		0xFC5E7B05C26C806BULL,
		0x5D00AA1F06B26534ULL,
		0xA9BA4B4FD95B8E07ULL,
		0x5DE286D41DDCA14CULL,
		0xD6AE106A6EF40587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x508D443ACCAC8024ULL,
		0x4514C8E376EC5F36ULL,
		0xDB3ABDE6FA0434F0ULL,
		0x55F455A3C3014528ULL,
		0x8B1B4703883D68A2ULL,
		0x76A654FA65FADB04ULL,
		0x0FBDFD5E2C2BDA1EULL,
		0x9A2B78C4AC9C53C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x232BA3A2031B9E46ULL,
		0x9D5A08C1ED6C7CEBULL,
		0x49E95B0E28141CC3ULL,
		0x41182E66749342DEULL,
		0x85DB5DDACF765B3CULL,
		0xFA5410DFA2034212ULL,
		0xF37BC83204FACE9AULL,
		0x7977979934B30B74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8C76FFC2FC5063ABULL,
		0x137DC73F385DDC5EULL,
		0xAA9AB3CFD5C2EE45ULL,
		0xA76FF311D45A213CULL,
		0xBCCDBB4AD6F38CFFULL,
		0xBFFFA69923A6A003ULL,
		0x0A7AC5EF5EF0418CULL,
		0xF64B3F20FD734A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0B622D92D846AE5FULL,
		0xEAE8A7C7642E7E12ULL,
		0x6B3F66B9EF9556FDULL,
		0x85C939D6C5B441BEULL,
		0x8B9DA938D2025D37ULL,
		0x7ED675AFCBA3F1ACULL,
		0x9F00EEAD15F1C73BULL,
		0xE11FFE105656A33CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA6B05E9758C30E88ULL,
		0xD68BE17965FE0385ULL,
		0x54D5C4A5F6342B8EULL,
		0xD0DFD8E0F9796E36ULL,
		0xAB8546730C7FEB92ULL,
		0xA0BE1F86D5898D12ULL,
		0xF1685667EE7B699BULL,
		0x4AA18604C6E866AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1DEF9D6FF222056EULL,
		0x2C8DE503E6B2B4B0ULL,
		0x1EEE9C1C1BEB0FC9ULL,
		0x7E5C5B9B2399330EULL,
		0xEA2BB23A0D51198AULL,
		0xEC3FAD564F5C0853ULL,
		0x9D7992AC20151172ULL,
		0x9EDA3BA3F51AF02AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x50D0AF8AB705FA94ULL,
		0xF82641BCC0BD6150ULL,
		0x51C2249F4057C01DULL,
		0x6FA5EAAD2555901BULL,
		0xC2547338B7098DCBULL,
		0xE0F471C7FF887C19ULL,
		0xB9BCF5C72A742EEFULL,
		0x7480040DDA24AB67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF7127ECF3407463AULL,
		0x8D1744871C3120B6ULL,
		0x4BCB9333E16C5B3AULL,
		0xFBDC692E3D299AEBULL,
		0x4D67670394543E1BULL,
		0x0429BF569D245200ULL,
		0x755755FF701AA9F1ULL,
		0x3E4F47B4F7B5F275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x985C25F8B865D766ULL,
		0x0A75E29618F0E51CULL,
		0x78F3E99D6A64BE1FULL,
		0x05EEF8B90D5C8B98ULL,
		0xF9E9E621D53F19F7ULL,
		0xFBEA5ABBFBFDF620ULL,
		0xD617EF1E445A608DULL,
		0x97650851706FF6DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x540AFC84CFC73305ULL,
		0x9444B231690CD0D3ULL,
		0x9BAB153209581F87ULL,
		0x246F98D12194288AULL,
		0xCD32CFDDB362F5AEULL,
		0x6D8B8F03CDBE083AULL,
		0x11D06729D38500D3ULL,
		0x33DA427584327662ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0355491530193D9AULL,
		0xEFC6DA265A27D4DDULL,
		0xB5032174F8FA196CULL,
		0x36E1D2564C4C23A7ULL,
		0x43818D778C51CEE7ULL,
		0x8F60B82CD4053AB1ULL,
		0x4CE28F8220B1A666ULL,
		0x889AABA4461E5C69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDA5418B66A41FCD4ULL,
		0x3AB83100C4192153ULL,
		0x5F0B0DD2B3E4E092ULL,
		0x9DC31D1511DACF5EULL,
		0xAF675E3D6E0DA3E7ULL,
		0xAB7685BC2808D5B1ULL,
		0xD7B6ED3F76CE9A6EULL,
		0x77C6256B1CC3AA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x80F4FCA554633FE8ULL,
		0x2E662406E41C9887ULL,
		0x6C0FB7201AC37DC4ULL,
		0x52C472786D19C810ULL,
		0x86A4FE82515C2E5CULL,
		0x1E239EBA8F0EA70EULL,
		0x695BAE34A4E71A90ULL,
		0x2AFFE09C81923D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCB1B56B950798BFEULL,
		0x1FC95DB56A9BD85EULL,
		0xBA4BE38C0D4C9613ULL,
		0x5F67D9B24F561D6CULL,
		0x7AEA1AFEFF593FB4ULL,
		0x47FE75260E02C252ULL,
		0xFA613F4558A0DC0CULL,
		0xCC0AE3BAED8920E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2961F482885DCEFCULL,
		0xCEA46D1D97185428ULL,
		0xB6BAE2F761BC2496ULL,
		0xA3350473CBCBE7EEULL,
		0x462667E14148D329ULL,
		0xEED03B20C367B633ULL,
		0x016100338BDA2D5BULL,
		0xD681A051F5884715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB527A51D0371CD20ULL,
		0x81270A0C4D0F95EEULL,
		0x49926557B16BB5CFULL,
		0x6BA42488EF966A08ULL,
		0x07C90308F4FCFA53ULL,
		0xE906848C010B7B07ULL,
		0x4071A26D658D219DULL,
		0x2ACD95D3C9143C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7422D24539E87726ULL,
		0x484A85E0ED471E4BULL,
		0x0584A872410D728EULL,
		0x8D7FAB84ED9DD2F6ULL,
		0x42E11045DB4B7C9DULL,
		0xBA84DAB9B798B30FULL,
		0xF86DF8BBD2D068AFULL,
		0x9633DDC4D8669EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x435081B73ECAFE5EULL,
		0xEF15965E8D65998CULL,
		0xBD3A2AD0BA3240C9ULL,
		0x3D0C81E8AA2E1304ULL,
		0xD30B8563A4E5C0BCULL,
		0xC988A4BCEDADDE83ULL,
		0xD4CA2D837391997BULL,
		0x252D0B2525A01DCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA330B9C82A54ADA2ULL,
		0xF45BA8911EF9A0C3ULL,
		0x5D6B9181C0782681ULL,
		0x4CDA0C5043F662E8ULL,
		0xC813FDF0B17D5EC1ULL,
		0x02973695DBBFB816ULL,
		0xC5381008E4CE0F01ULL,
		0x4C50A45EFA2767ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF7112799C8433EA1ULL,
		0xD5020624BA1C0C38ULL,
		0x3F4144D0FBFDA835ULL,
		0xB3F4A737F9299F76ULL,
		0x2082D8E3D55421A5ULL,
		0x0C09062FE5D6ABBFULL,
		0x1B1A29EA779A7AADULL,
		0xBBFA6938CF29AC5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x174AB42FAC91CD8AULL,
		0xC1D4CC39740CC8CFULL,
		0xD51C17761EEAA7E8ULL,
		0xF9C0F4734CA82353ULL,
		0x2B13DB51476682ADULL,
		0xA108A315EEB32BC2ULL,
		0xEB001AF0A1F0BF2CULL,
		0x172FFDDF4EDD87ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6C083158D08EF62EULL,
		0x21299AE608E1C927ULL,
		0x1F2C088AC86155C5ULL,
		0xE633BFE6E3EAD404ULL,
		0x93A2E1DFEA17377FULL,
		0xC4C96C8130AA982CULL,
		0xF2DE39A38877F6CEULL,
		0xADB6B2012AAA399BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE3BF22A772DD3DF2ULL,
		0xCFAFB87A628A1DE2ULL,
		0x0DD369F943089C77ULL,
		0x7A3BA158B02B1EBEULL,
		0x1BE7EE8DB0E2CEE6ULL,
		0x41C5E9F25A71471EULL,
		0xBDF60048F39EACC5ULL,
		0x66DDB3058D82F882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x74E0ED897F5E2E73ULL,
		0x3DB3F59FA20397E5ULL,
		0x90A0F297855E156CULL,
		0x0282E10A16E8DC37ULL,
		0x657E84994E862B93ULL,
		0xAE40FEE49B9E145DULL,
		0x7E84307153E60824ULL,
		0x2E4928F7DB192A7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x11D29E407CCEF003ULL,
		0x2EEBCB6004B3280DULL,
		0x7417B7FC4D5F52D0ULL,
		0x5DB4A7B55A8C5C49ULL,
		0xF896D9A24F4AF329ULL,
		0x6D5DCAB47D190FA8ULL,
		0xD526316D3F6EDF4CULL,
		0xBB0A75A1896AA696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x83D1D27024F7824CULL,
		0xBA08C99288C7DC00ULL,
		0x66F5D5F6BC480A3EULL,
		0x5BF389108CBE673CULL,
		0x96B6A7B2359A3487ULL,
		0x94EA2458931F5058ULL,
		0x8C91F175FECDDC74ULL,
		0x5B49302E4298511AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xD813116C67FF7883ULL,
		0x280EFC476B51D550ULL,
		0x327DDB747C149ABDULL,
		0x2E991F2E99816288ULL,
		0x2403AD8761960220ULL,
		0xCD21D989D1EF1B17ULL,
		0x800C28CA0D01AEE6ULL,
		0x0970E40D4DE622AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x59DDECC184323082ULL,
		0x92E4E0416F091660ULL,
		0xABDF539D991692F4ULL,
		0x67E5558BA1360EF5ULL,
		0x93EFD154555AEEAAULL,
		0x22F83768378B3F01ULL,
		0x78FEEE5B07E3C808ULL,
		0x9C408E60ECA6C9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD8B627F7DC8C1ED7ULL,
		0x7C6F12BA0B364DA1ULL,
		0x42977DEE85467959ULL,
		0x7F3F96C743608E9FULL,
		0x66BFA21615A52641ULL,
		0xF047AFB8A52A2FFFULL,
		0x0707C5DD9026FF98ULL,
		0xCFD0F68398A465E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x24B1E0C548752017ULL,
		0xB1BA4DFE46EEFFA6ULL,
		0x0719E358D38B9E6AULL,
		0x886DC3E68708AB6FULL,
		0x8C2D48F1E789BFB0ULL,
		0x7C6FA72A72DF80D9ULL,
		0x88175FB7AA3F2D09ULL,
		0xB3B40618A76D1DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2F18A87E94A74FD4ULL,
		0x72384018B724049AULL,
		0x18EC8FAEB7A9090DULL,
		0x25095296B0BACEB9ULL,
		0xD98C49276C1933DCULL,
		0x3A4ABBBEB6ABBBCCULL,
		0x539080F1062713E9ULL,
		0x54367E481EBC53D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x34D122A7A0768233ULL,
		0xE62503DE9E4DE255ULL,
		0xDF612F2A935098C9ULL,
		0x452CA2E95026B9D7ULL,
		0x1416F9447DD78A23ULL,
		0xFABD66AB90F55373ULL,
		0x341276EE98DBEEA7ULL,
		0x418B03FE9BFE9EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB97EE1EB5EDECC7DULL,
		0x308A457D62662F3FULL,
		0x9801EE00EAFC4A62ULL,
		0x59F42DD3C02A189FULL,
		0xDEAFA5745A32CECBULL,
		0x29080C56A0F5349AULL,
		0x8CCF9E0294111A1DULL,
		0xEDF5534B83693BEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x02F4DC077AA90BABULL,
		0x49156CC8A5E5D88FULL,
		0x519B49459BC73E60ULL,
		0x3C4921A47A60B869ULL,
		0xA233226D541E3D63ULL,
		0xC0FEA502C217CB1EULL,
		0xF5BF5A5EB815E68EULL,
		0xDF4AE5CDCEF0AE99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAB3028803395F91FULL,
		0x8393D24BF84C029EULL,
		0x7AB79B90F4B751C4ULL,
		0x02522B08A713CFF6ULL,
		0xCD4C95CBE54668DCULL,
		0x7B2576714B3C58B9ULL,
		0x81686DC24794E828ULL,
		0x9FED9C93FA49002BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9C3FACAD51C77AFEULL,
		0x1459E72D24B9C7DDULL,
		0xF8593186F93D7957ULL,
		0xA6A842629CEDB9E4ULL,
		0x7FDD8493216A9E5EULL,
		0xB6CCB47137BE7654ULL,
		0x9AD0F2D10DF222E1ULL,
		0xC9CDE9BCF9D90968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE0DE2850BF2A304EULL,
		0x9B4F02E85A619E87ULL,
		0x6CCF3A1C34A8A2EBULL,
		0x6196634774D12754ULL,
		0x60F811E252F298ADULL,
		0x2322F4BF60E7C619ULL,
		0xD177230E643F7BAAULL,
		0xFF608F8CF5B0F310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7D6B75EFE6DBC3D7ULL,
		0x0F79175A162249E5ULL,
		0xE9645F6BA189BA57ULL,
		0xE12063C1E5F497D7ULL,
		0xE0443817EDAFE130ULL,
		0x71177007ECE88387ULL,
		0x71013A57AAF75F9BULL,
		0x8C9D68D1337F2F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDD540C7E1BF12F9FULL,
		0x32631803F1B60328ULL,
		0xA491647D4D05C376ULL,
		0x3F358D4FAB8F19F9ULL,
		0x5B0861093EE08E2EULL,
		0x9BD0B9D20F7E3E9EULL,
		0x1D25143AF7FEFBAEULL,
		0x4BDE2F6EB1AABF29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1AB2772F11F3595DULL,
		0x95E397713DC35140ULL,
		0x36F0E43074793747ULL,
		0x83F27C8F4E9FE158ULL,
		0x8F20CF2F05C92E9BULL,
		0x113A90251A66C91CULL,
		0x4772603163E1BCB6ULL,
		0x6ADA16313BB36460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC7023FA407398B62ULL,
		0xD21BBA50BC0B5BF5ULL,
		0x7FFE030617F8DB2CULL,
		0x491DBBCF3D173B58ULL,
		0x8766F4F850AC81DFULL,
		0x2CF7CAE302F91393ULL,
		0xC032884C0A37657CULL,
		0x255E876E2396828FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5DE0FFCB1BE8759CULL,
		0x37E3C9E5F9C641D0ULL,
		0xAC73F162262AC7C8ULL,
		0x7F02D259220EC4D7ULL,
		0xA73F63822D858477ULL,
		0xC2A1390580F1F17DULL,
		0xFDD7C2FD7C7EF548ULL,
		0x342B995D1B2194C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5CA2677E8D859420ULL,
		0x6AC71480EB947522ULL,
		0x289069E1036967F2ULL,
		0xFB27CA93472F6C71ULL,
		0xDA0818678089080FULL,
		0xD73CC6044B8AAA67ULL,
		0xB816AEED5314B28AULL,
		0x84668F9DE7BAA9E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xDD329032D5847369ULL,
		0xCAA0FE2A6F41200AULL,
		0x8BD5A9957BD77BD4ULL,
		0x8A277D070D02817BULL,
		0x56758A4118B5767AULL,
		0x50351A1DE69A8BCFULL,
		0x092125E5800986EFULL,
		0x22DD6A4236B18382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0804E0A2944790A9ULL,
		0x141B52EBC3573079ULL,
		0x10D2C893C6AC9600ULL,
		0xC3E979BB7190B6BDULL,
		0x09B059707E677E54ULL,
		0x9244FD30E33D493EULL,
		0x8A0A5E1B3764D4E4ULL,
		0x5A174F46DC2F7C24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x38385A4E6F386ACDULL,
		0xBC7AB87D7C05D397ULL,
		0x37845500E346C3BCULL,
		0xFD7BA64EE2CEAB46ULL,
		0x8096F0C676EDB896ULL,
		0xC73E7F69F6A7033FULL,
		0x44BC51162BC2F365ULL,
		0x371E0C0B60E625EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x960DB79584C4CED7ULL,
		0x0B6090E2DC7732A9ULL,
		0xCEFA8688488C987EULL,
		0x1395383FCDCFD0C9ULL,
		0xC62F86B340F9A3DAULL,
		0x92FAFBC2E3501C1DULL,
		0xBC21B063C979F91DULL,
		0xD1DB5F5908735C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x1FBEF003921714CAULL,
		0x86C2477260A7A0DAULL,
		0x6C00BF51FC828543ULL,
		0xEEE6997405BFA6CAULL,
		0x5AC141EEDD9667E2ULL,
		0x73589DF6873C0D19ULL,
		0xA8BB359772712AB9ULL,
		0x1243716158E9A08AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xFA70E2F1B0795E6CULL,
		0x981789579EDF2371ULL,
		0x3AE73B836BCE201AULL,
		0x42F14D6E79745497ULL,
		0xE353B60CAF2F01B7ULL,
		0xC3C8F7E6C4B03D89ULL,
		0xB0FC147E26A9EBDCULL,
		0x1E3AD6C4F5327275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x0CEFC9A886776DACULL,
		0xA7E9D515E544725BULL,
		0xCFA2C841FDAEEA9AULL,
		0x4E43FEB14DFDB27AULL,
		0x02D975B1D2416542ULL,
		0x0FCF871B3490835FULL,
		0x7D5A3B9AA5E50589ULL,
		0x0274166B0153BDD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEB5F65EA133F3A32ULL,
		0x572D81F32EE2A620ULL,
		0xF2369906724A50B4ULL,
		0xBB12917E7AAA4BAAULL,
		0x7B14D2F50ADDE06AULL,
		0xBB8F611578089F99ULL,
		0xA0A789BC03E551CCULL,
		0x712F02DFEFA82A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x42313B79FE9CB7F1ULL,
		0x482D08D083BCC2B4ULL,
		0xDADBC6F007969581ULL,
		0x2AE27001CCBCD1C6ULL,
		0xF8F2C3B0DF5455B2ULL,
		0xEDE3E5FE77401309ULL,
		0xF47D1FEC789E09D9ULL,
		0xD746224ED21D505DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF72116B0F9DE42D6ULL,
		0x5EE8F13070A51E75ULL,
		0x57B321B5E48EA107ULL,
		0x547688D268AD040CULL,
		0x7CD5ED0F39FA854CULL,
		0x7B14260836E97C5DULL,
		0x88C9F330F7824ACCULL,
		0x268A214682CE2E80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x23D80F8B23440506ULL,
		0x0A9488F1AAAB1569ULL,
		0xC50415B6F9495C3DULL,
		0x7BB929CA1D0E0E95ULL,
		0xA5F42077817BEAE6ULL,
		0x208F695CF2A74590ULL,
		0xB5EDE20594C87120ULL,
		0x64C1F3C9447E13CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x89B582F7A9D15FFAULL,
		0x78031D266EDAB353ULL,
		0x63791D9F63909490ULL,
		0xFB280FE7E3D39152ULL,
		0x0C19FBF9F36E9DDFULL,
		0xF71509CE508226C7ULL,
		0x5DEED61BB56A1D03ULL,
		0xB4DC236803BB5680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD566BC774688BF04ULL,
		0xF957ED152DAFB22BULL,
		0x19811C007154C4AFULL,
		0x3FDB801ABC923B94ULL,
		0xDD5F797E3EB19DA5ULL,
		0xBA3C7E1D3A7CBD0AULL,
		0x1FCA7AA40E09829FULL,
		0x909ACF87259539A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9D9C7D426407D4F8ULL,
		0xC51F8064C678E28DULL,
		0xBDF7E8F40D5DC107ULL,
		0xED08E9E85B9C820AULL,
		0x6F6E39DC3B95FDB0ULL,
		0x4E0CBCA17E294076ULL,
		0x4D7BA8C931C3228DULL,
		0xFB43A6C409EB6906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5FFB290B8FA7AA83ULL,
		0x0C429EDEE415C9CBULL,
		0xC737165D00DCA5ADULL,
		0xF904C7AF57068F70ULL,
		0x41CC9C3D025B110CULL,
		0x898990E504E0C9AEULL,
		0x9585A7D396A0FB57ULL,
		0xA18E04963FEADF86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x75D28FC53ABE916CULL,
		0xA5E167256CD53972ULL,
		0x54E6880BF2BE3B8CULL,
		0x273A981D5E2CA04AULL,
		0x8DA3F0548E4B9794ULL,
		0x0CFDF4DE5E6B6044ULL,
		0xCD711DEF9229F449ULL,
		0xD4FAE39DF558B694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x70BF99AFDEBD9BC1ULL,
		0xCE36D36E39C63894ULL,
		0xE5D204D7A33D949EULL,
		0xC5CF0BED7B671932ULL,
		0x18560457C298C5CDULL,
		0x24AE66E74488B859ULL,
		0xFD7B1B8F7D12D3BFULL,
		0xEFB35776E88158C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x386666CD8869B6C7ULL,
		0x2D5ED7564A042652ULL,
		0x05DA9A74B389C914ULL,
		0x8479513EF7997469ULL,
		0x557BBD6749517D70ULL,
		0xE789A1E6C487EFE2ULL,
		0x60069C59705239EFULL,
		0x830E0A6257150A46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD3B638C33EE3D8BEULL,
		0x9E0B899E381D31E9ULL,
		0x9A98FF4645E45293ULL,
		0xF73EC3438C08EFABULL,
		0xDEEF585FA54C6438ULL,
		0xE7B129FAF05622D9ULL,
		0x683723AA4632E941ULL,
		0xE66F7E6C70FFB18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x285B1A543648B37AULL,
		0xAA026E2F71DB5D77ULL,
		0xE5B8102EB57597AFULL,
		0xFCD4C00C0809604CULL,
		0xD2D89EE81E1CD897ULL,
		0x8B73138E0573BE7DULL,
		0x038D5B13AE2FC6BBULL,
		0x7278C570E0F517DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x18F1B5D5AFB253B7ULL,
		0x2DBE7314508B1185ULL,
		0x056057A719F5D09BULL,
		0x774871D727B84C24ULL,
		0x569FD01C5A30DF26ULL,
		0xA4BCC03FBD22A711ULL,
		0xBBB4D3F0EBC344E5ULL,
		0xB1B76C2C2D88DAFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF10187D266BBE520ULL,
		0xCE858383274C28ADULL,
		0x83E65EE16BD84667ULL,
		0x65B2C4B3ECD8CCB1ULL,
		0x3DD0E5FB850F354EULL,
		0xB875B9AAB7381F0CULL,
		0xC0F62931DFE7F3E8ULL,
		0x281063C6151EE4CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD594771DEB2650E8ULL,
		0xCE1D4044F0994890ULL,
		0xBAC383D6DBC87B7BULL,
		0x79C6B677B0C649E7ULL,
		0x55C8392D141B26C3ULL,
		0xA287F595B3FF662FULL,
		0xCEC9A5095D412BB1ULL,
		0xB3E9870A2F7F9231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x90EBAEB1BE4308F1ULL,
		0xAAD9000FC638786DULL,
		0x8215C8CCC11CFF0AULL,
		0x043B4C9D214C5460ULL,
		0x618887F4DA026487ULL,
		0xBD12E9C718E224D5ULL,
		0x856E3D15FD8C7922ULL,
		0x2BF3142A001A3073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4651B458E2F1409AULL,
		0xA67D084C7C1FF973ULL,
		0xEAF7AED4B751ECCCULL,
		0xDD938C9FE83EE196ULL,
		0xD93E318335426D72ULL,
		0xD36102A11D856498ULL,
		0x2802F715B0CAC236ULL,
		0x50250CD7AF0A55C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	la = 500;
	k1 = (curve25519_key_t){.key64 = {
		0xD031B1D83B30B84FULL,
		0x9A8EA6696A2771F1ULL,
		0x87CA104879EBBF66ULL,
		0x5C384CD370B767FCULL,
		0xC55F4F460609CDBEULL,
		0x6F1F8DC9A33E3CF3ULL,
		0x2EA26F3426FC2319ULL,
		0x00194D280477E865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0010000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBA77189A4FE13A0DULL,
		0xCD3D165A0AAF073FULL,
		0x7927D3827D1F97E3ULL,
		0x132E7CDC00F40B97ULL,
		0xED2EFD48BFC38E7BULL,
		0x742A1E33A7C860C1ULL,
		0xAC7FAF31CE3DC7A5ULL,
		0x45D1CCFEE0AC2C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD5FA96DDEECC95ECULL,
		0x0F0F603DA7DF6ABDULL,
		0x19BCF613C3CD0F66ULL,
		0x34C4850326465CAAULL,
		0x8B20894BA15EA1BEULL,
		0xA66E3AC67ADAB457ULL,
		0x6F3418B095854213ULL,
		0x9DF1C1ADA3EBBE5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x55210C671DDC6373ULL,
		0x567364919FC9EE89ULL,
		0x27303D41FC5E30ABULL,
		0xF22EC4F233543005ULL,
		0x431F0DE536ADF694ULL,
		0xA04DC245AD85D485ULL,
		0xCED4CEB08582CABFULL,
		0x317BED28372406D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDA55639239261B6FULL,
		0x77FB0A3530A84B90ULL,
		0xEB7E82E92ED55F55ULL,
		0x66A5C6F14A2D3344ULL,
		0xE86EE19EE4CAEC79ULL,
		0x698C9FA9B7F89BF3ULL,
		0x76BF98EA326FD536ULL,
		0x5730963BA4B59203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC055A4D1D1E80AEFULL,
		0x59C3C16318EA200EULL,
		0xB6B3E4D097C6DAE6ULL,
		0x19B006F2DB3773A9ULL,
		0xFE39D5974F605937ULL,
		0x3CDE02B3717BBE9CULL,
		0x318A360556538053ULL,
		0x8802587C987ACC66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xCB1C7ED243BE996FULL,
		0x44E36269AAF39BFBULL,
		0x4B3DFCB31FE359ADULL,
		0xCD0A49FF9C20BEEDULL,
		0x3B27E31244171EB5ULL,
		0xDA92D94789DABB7EULL,
		0x79B9CBEB903ADF45ULL,
		0x1E744CA47A3C3AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x92CD0FB60FB8B645ULL,
		0x6D221EA750758061ULL,
		0x1377BE03D908C33BULL,
		0x41BCE484E8853465ULL,
		0xB8C9058BBC445256ULL,
		0x9EE2D2C1B1409127ULL,
		0x6C26AAB28B88B26FULL,
		0x886ACAEE32B384D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2165BA9F0D3582F0ULL,
		0x5C2E98F025EAE5CFULL,
		0x36E4E6240B2AB9D8ULL,
		0x1844650E0637FDEFULL,
		0xB2721FCCFE44C21BULL,
		0xDC21CE426E1A9757ULL,
		0xEA5D65505E92DE78ULL,
		0xAA1AFE8E2752E0FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3AB54FA9EAE2C154ULL,
		0xA4CA41FB10328626ULL,
		0x2B88D248B4B74C28ULL,
		0x64D0EA995DE35B8BULL,
		0x6E0AE5E14D942EBFULL,
		0xE86BA4D8CFC359E6ULL,
		0xB7984997CDC6D6FAULL,
		0x7C2772852AFDB923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x30F77EBCDC15B219ULL,
		0xB606A52A64F6A038ULL,
		0x80D6E5F428ED7126ULL,
		0xCD16A060BA25591BULL,
		0x9178F55BBDBAEB8CULL,
		0x9F092521D8404C73ULL,
		0x224AAE1615475B21ULL,
		0x88680A5DCAF3A288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8BEE64C8166BD7EDULL,
		0x4103F4C15CC28C19ULL,
		0xD81828B767CD49B7ULL,
		0x3414A23F9189E365ULL,
		0x86ABA4AA5CD0B882ULL,
		0xB4BCE15255782837ULL,
		0x5749D7FE4CE4A60FULL,
		0xC87BBB8519096563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6B2EF4B5BD67C17BULL,
		0xC833B785EBBD5651ULL,
		0x7517F2C5CC2D493FULL,
		0x4B2E8AC4C959EF2AULL,
		0x4B14D6164A096EADULL,
		0x5A45D134A9D77F39ULL,
		0xA89435469E76F386ULL,
		0xA2E91052976DC9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x63348BD2BBE21F1DULL,
		0x30CA5AC930996CE1ULL,
		0xB66E19B2B628E8E4ULL,
		0x7F06638F0F1ACCB8ULL,
		0xEAE7696BEC4F7401ULL,
		0x2226DF051655974BULL,
		0xD537EB38E13A92BFULL,
		0x0E10CE84E356ADA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xC64373B0E376CBF7ULL,
		0xA953460734375312ULL,
		0x13CDD71F6FF10398ULL,
		0x1E63FE26BC7E6192ULL,
		0xFAD5F159BF7871C3ULL,
		0x530412CB0CBB0EB2ULL,
		0x849A2EC4BEE68B3EULL,
		0x02439CEA97DBCA8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA36D68F565F80473ULL,
		0x50FF26DFA1AD97F3ULL,
		0xDEFEA64E25CD50E7ULL,
		0x0C02BF4BFD541BE9ULL,
		0x9456CA07737F6CD3ULL,
		0x39C97B6EEE1E6700ULL,
		0xF814BB619C020E46ULL,
		0xBB7657FF894C0802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x9CE9F0816C7BA510ULL,
		0xC4534EF46114F6BEULL,
		0x81A2A2D1FC9D7DFDULL,
		0x04828563C214DBF3ULL,
		0x41E2FF889427A5C4ULL,
		0x4D20A32B53B8920FULL,
		0x90C831F305E573EFULL,
		0x1F3BBB86B9C79983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x68656366635FD721ULL,
		0xB0AD3841F1B24A69ULL,
		0x07E255DEB42EF676ULL,
		0x3E33A0C24ACFC953ULL,
		0xFD43D4EDAC838831ULL,
		0x87E49AEED7E4FF3EULL,
		0xC1C0941AB575870AULL,
		0xB0C7BB401AFCE5F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2F2E152719152CFFULL,
		0xC29D4070A6FACB29ULL,
		0xCBF6EFD5D4F6D31BULL,
		0x03EF7D987A9E9C03ULL,
		0x99CC2457D5D4A625ULL,
		0x41EB776355BE17EEULL,
		0x579054B1320AC1D2ULL,
		0x94908C796886AC1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE02B30C77D3B1834ULL,
		0xE7AD024AC742E447ULL,
		0xC3A5D6719975B1CDULL,
		0xFD419D30FB42E6E3ULL,
		0x54D38A0BB713C29DULL,
		0x0E41A5C466F6EAE0ULL,
		0x3B6CE7C548CA0102ULL,
		0x2F79C1080E3B362FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCB8ABD9FA72BF224ULL,
		0x54F5AA0509A59FA2ULL,
		0x733C1C4A7AC8B27AULL,
		0xCEA7B19536F73575ULL,
		0x0E16E19DA2181DB9ULL,
		0x2C4C7B92467D9156ULL,
		0xA2B92FA7C633FF31ULL,
		0x3695A19910D5DD2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x3D4CCCF5930EE6D1ULL,
		0x334E96EB35CE8056ULL,
		0xD9B8C892131E3DC7ULL,
		0x76E4D9A78A7D142DULL,
		0xA1CD223A845C2498ULL,
		0xDEBB8F33329C2237ULL,
		0x3AF0E7F2971F9BF4ULL,
		0x063E15E070CA4301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1D961FB4C28E9CEBULL,
		0x0757D35A4D85B771ULL,
		0x07AC846A766E93B7ULL,
		0x23C9BB1357E1AB1FULL,
		0x73B9F3A04A8933B0ULL,
		0x84617FA403E1786DULL,
		0xBDE7F00C71B777CDULL,
		0x3CC7F0FD2DF86972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD10D49448F5C60E5ULL,
		0x60917393DE26B044ULL,
		0x22372C746E6721B8ULL,
		0x1BA46EF5613A6FA0ULL,
		0xCE794B17E101C03EULL,
		0x4FC45CBDB4E606FBULL,
		0xA2EDBC3DB081AF0BULL,
		0x7603AB202A9DB917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x74DDB4C31D691DD5ULL,
		0x21F005978DDDCB98ULL,
		0x1286CCCF47186CFCULL,
		0x0449661A21DB524FULL,
		0xF8F09972E766B81DULL,
		0x8B1D1DE5150B8E51ULL,
		0xC90488C2A4F94204ULL,
		0x7AC69B86F977D582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3C1DD2018653A694ULL,
		0x54134900D2A8D4FEULL,
		0x786FED28C04284C3ULL,
		0x5F4C835CED197B58ULL,
		0xA929EDFEE4DC1370ULL,
		0x95F9A6A4FB51FE62ULL,
		0x0F7C8C01BF734725ULL,
		0xB6F3E6590912299FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x15EB3FB24A19DDBDULL,
		0x241C6291A1F7CD0FULL,
		0x59DF89D8947B8B19ULL,
		0xAADA6C8F41D2FE42ULL,
		0x45F505C2E4A58CB4ULL,
		0x96A729012FCB4A7DULL,
		0x52BA3CCB6326B731ULL,
		0x7B7CA531050D2E3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1635E4E530591727ULL,
		0x0EE7123D910979B2ULL,
		0xC75E0226B3C8C920ULL,
		0x605084D9FB91FC83ULL,
		0xD8212B881A00026AULL,
		0x7001D92CCAFD84A9ULL,
		0x343F776FE795F23CULL,
		0x3394EF688E203D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAD82A2BCBB6D7294ULL,
		0x4B44D7B6187D2131ULL,
		0xB7A5E7A7E4FB599FULL,
		0x4920E661709A7502ULL,
		0xD7D6EFFA28488E59ULL,
		0x84E8D8D182EE0186ULL,
		0x6464B4F21FDCF08BULL,
		0xE5EC57946FF3C385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x30E843A4C268AF29ULL,
		0x47E0B2EDE423E255ULL,
		0xFFB38BD4FFF87DC9ULL,
		0x8496767B3DAE21A2ULL,
		0xA18CC2B0AF9A1E89ULL,
		0xB23BA42303F3CA4EULL,
		0x057FBDF07F806B6BULL,
		0xC8A00190BBF3ED38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE91C68E0944F0BCULL,
		0x3BD35A929BB5377EULL,
		0x08D8E2B1C3EAB150ULL,
		0x102691EF53DC0691ULL,
		0xC62EF280AED66DE4ULL,
		0x1CE72800B176EEF8ULL,
		0xA1C106A3C1648CC8ULL,
		0xB04B54E3B0170EABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8DA99A3124CBC8D0ULL,
		0x62418D54F7A11AA9ULL,
		0x129242EFDF6243A6ULL,
		0xFF9D1A08021E71B4ULL,
		0x98C1D738097E7B6CULL,
		0x4BD92A93B2439B95ULL,
		0x309BDCA987E49C68ULL,
		0x3662D88520567B5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7581185F114F7AE7ULL,
		0x418F63AC49FA8248ULL,
		0x9A7B7F5489682846ULL,
		0xD18D5979B08902B3ULL,
		0x7399756D6AB5DC3EULL,
		0x8AC1098F7072ECF4ULL,
		0xB9C043602BA30896ULL,
		0x91A35B05F7B67186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xB6E35B4321E204C5ULL,
		0x9B40151AC660B352ULL,
		0x141770350F6A9AFEULL,
		0x5ED27EE5CC76CE29ULL,
		0x3EDEB51DBAA6889EULL,
		0xA425A98176A3A6A8ULL,
		0x8A68EAFDF933708BULL,
		0x0FDD182AF3A15A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD697CB17E88387C3ULL,
		0xF69034B9E860F033ULL,
		0x8F8E39042CD067BFULL,
		0xF1929CF95EC56A82ULL,
		0xA6D86112BEA78131ULL,
		0x64E963065A507169ULL,
		0x33ADA0AEAEEBD26CULL,
		0xB9AD3F115788204AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCBA97384A76F979BULL,
		0xB1DCC46DDCBF4B82ULL,
		0xC1645236F129C4E0ULL,
		0x6F9F5CE817D771ABULL,
		0xBF0EE5D91F0B8DB9ULL,
		0x680BD9C5B704BA8DULL,
		0x2804E11CB63D6A40ULL,
		0xBC068C62EBD9C60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBA7C333E0826D67BULL,
		0x9950EC988048DD5CULL,
		0xE203DBFB771C8A25ULL,
		0x4AC25C3E635F9FDBULL,
		0xEC27C1CFC38043C7ULL,
		0xA1038F62FEA2FA9AULL,
		0x411208EFEB06C75BULL,
		0x980EA653841C030AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5909DD3677500724ULL,
		0xD0F961EAA7854F31ULL,
		0xB0597C4B012DB928ULL,
		0x2F30EC67B9E5728EULL,
		0xD4759F8C25AC07D9ULL,
		0xBE5811C141F51BE0ULL,
		0x4EE1C8491105636FULL,
		0x8CA21590E9551ABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC32F6D4124D43E55ULL,
		0x1F6A6C907AC6B971ULL,
		0xA4C33D1ADD166CC5ULL,
		0x69FE8A9D47604847ULL,
		0x0B25B54C7E37704CULL,
		0x74B8EAE83EEDCFCFULL,
		0xE18A583A555EA9D3ULL,
		0xA32918713E708951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x076DD6F16196C045ULL,
		0x3D9CC8A0D7CE1568ULL,
		0xB4DAF183160CACD8ULL,
		0xEBE6B07D6AA7EB4AULL,
		0xBC0B6802EAD18786ULL,
		0x4146D38C2C2A5502ULL,
		0x1CD46F3F4B421763ULL,
		0xF9A49F2A1F31BE48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC3672981099E377AULL,
		0x20052A6843EFF99DULL,
		0x38685374BA357729ULL,
		0x58CDFD78F7444F8CULL,
		0x0BE771DF823F29A8ULL,
		0x9DC36078C9CCCCDFULL,
		0x9691721379BC140EULL,
		0x3FA017B6FC926880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x86AD2ABB6E10FFB9ULL,
		0xBB90EF5F2481ABF8ULL,
		0x20E61394CADEB6E1ULL,
		0x0AEDFBDD44EB4827ULL,
		0x877EAE88C513C2FDULL,
		0xE59ED2B4C9F2D25FULL,
		0x2716A8883931BA7BULL,
		0x1CF52AAF5272E3D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD13567FFFEF4A08AULL,
		0x986AC5C2B3241682ULL,
		0xFB76E6D225339B96ULL,
		0x86CAD14C23F58DE6ULL,
		0x4253FF42CE7FEA89ULL,
		0xF2C94D9FDD7123DEULL,
		0x40E4A4C3E0082886ULL,
		0xA2869CCE40379194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6E5459F8EA0F5C2BULL,
		0x8C2A2EC98D6E43D8ULL,
		0xB35C36ADDDB02969ULL,
		0xE47D614DF313F134ULL,
		0xBF6B7B55FB17A67FULL,
		0x013E90B6F09F8C55ULL,
		0x465D9A7B4FF59F85ULL,
		0x18536895A1EEBCEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x979C2D706A4C5D5EULL,
		0xD0D709DAC0AD8CDAULL,
		0xCDB7D94CB3E0BD25ULL,
		0xFE2182951EE1A358ULL,
		0xEDB1C8EBAFEA1A31ULL,
		0x15A10D53526D33F6ULL,
		0x3FFDA4669D38C0B6ULL,
		0xD229ACDBB4E6F777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x139F8F2A10402989ULL,
		0xDC2AB9CB76BEA8B6ULL,
		0xBA25C933C597B749ULL,
		0xC9DFADD1B2E45C2AULL,
		0xF6514023524825BDULL,
		0xF1894834CB99ED71ULL,
		0x389A56BB840C7B89ULL,
		0xFF7090581B7AA22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8DE5B0EF979CF5AULL,
		0x3278A19FBB1AA0ECULL,
		0x8F24F094477A2947ULL,
		0x0F9E93D1E30129BAULL,
		0x21C1D0D3EC39BB58ULL,
		0x7A78910B3D5864B0ULL,
		0xE49C30B5BB465347ULL,
		0x993CA9AF27ECBEF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7ED428C42E238E7BULL,
		0xF506FDBC3AEDBFA2ULL,
		0xEF168AF7D28672D4ULL,
		0xF19D6E4F3D2F68CEULL,
		0xDC6A4D4F8335CD1CULL,
		0x3F68B803B8273E34ULL,
		0xB5375FD0F3837869ULL,
		0x865EBEEF2098E2AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7C5830E9E623106DULL,
		0x75C6A4198F021C39ULL,
		0xDB67464B4119AA21ULL,
		0xBF6C293DC37EDC1DULL,
		0xB2FBE1066B6947CCULL,
		0x5A035F5472E2968DULL,
		0x213BD37D118797F4ULL,
		0xA2C456E9F351912EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE5D7E4564EF9D3B2ULL,
		0xA2899B654BFB9A58ULL,
		0x525E623A48CDB4B4ULL,
		0x5DA3607A0C711E9DULL,
		0x842285EE29F961D3ULL,
		0x5B3E2F8CBC7BF1A0ULL,
		0xFE47B88EA0BA9076ULL,
		0x71ED8F4F01F33311ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8F9D2F86AA37CE49ULL,
		0xCC468B08D0176566ULL,
		0x0072AA58B9C9E582ULL,
		0xCEB44B5D90A320B0ULL,
		0x416E24EA07FE6004ULL,
		0x2000B9750BB3171CULL,
		0x74B1D487382DC992ULL,
		0xFB4F3CD825F82E51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7EADA679D9E59124ULL,
		0x37C67252C99F30B3ULL,
		0xEF1EEEA90B085E76ULL,
		0xBE6A012E70952436ULL,
		0xF9084C5A9A8F0057ULL,
		0xEE7B7BE14B948A95ULL,
		0xFCF63FB96C6DC6FBULL,
		0x56CAE667D3897B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x77689C97A5910B93ULL,
		0x82B12CFB77A4C9A5ULL,
		0xBD2B67FC46807E7EULL,
		0xCFEF8B72C9ADA3CFULL,
		0x0017A575E854F356ULL,
		0x63BBEB5EE4FB7653ULL,
		0x4A3D118BFF195A39ULL,
		0xB68A757AF81D3A08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF5AC31697AAC02AAULL,
		0x0F654ECB0AD965ADULL,
		0x5A42100D34824AFCULL,
		0x31287A1636FD8E6EULL,
		0x9845343C8824B503ULL,
		0x06F43A45862CA88AULL,
		0xFBF73F42C3B4089CULL,
		0xB73A92F29E8136C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF4F93F76B7A4393DULL,
		0x57C83C6C126B04A9ULL,
		0x7570CB647B03C669ULL,
		0xF18C098864FE55B3ULL,
		0x7E2F971C1CB5694AULL,
		0x13629D9591A3E5E4ULL,
		0x27EB03775CC47FA5ULL,
		0xD362E03EECA20831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF3D9D5A6972E0028ULL,
		0xE2A59C3096B42F4AULL,
		0xCB6B6D7057F053F0ULL,
		0xDC4462610FB665FEULL,
		0x353F0F62CF06F6DDULL,
		0x5A8479D3D29A7878ULL,
		0xF2CD7BE9DDA537D7ULL,
		0xC8CEC936943ED5B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0ABD3AE94EF4A6C6ULL,
		0xD944B9988EEB9C9DULL,
		0x56566F672C8AAE4AULL,
		0x2759FB8D5D07A7F7ULL,
		0x1054F5ADB9484EC3ULL,
		0xFC25D3BD43D00D08ULL,
		0x88A8C2454F4463FBULL,
		0xB5F48424D116F290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x35002D1B0CC881BEULL,
		0xF512F436C4BD28EBULL,
		0x9B27FB51EA155E7CULL,
		0x70E9CADED5802B9BULL,
		0x4E64DF699024E328ULL,
		0xA13B5715E90CB5DDULL,
		0x34B71FCB1439D122ULL,
		0x1EAC54EEA9499B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4C0D7DD7D27CFF1CULL,
		0x87E2C9FD2B386496ULL,
		0x0075297C02D50A27ULL,
		0x5ECF058202C02126ULL,
		0x893F8A41ABB6B7DAULL,
		0x8594807F95BB8B10ULL,
		0xABD8DF0BD978F4D6ULL,
		0x606E6B94A5CD24EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF1E9AD5830879D46ULL,
		0xD1A9AADE077D0A12ULL,
		0xD0E8F80E39208487ULL,
		0xC35914EC3BD44C2AULL,
		0xA1455DAFA792BB52ULL,
		0xCF593DAE7C5E6DF8ULL,
		0xE2C54FAA3A8A4598ULL,
		0x9C7F181C9D735D5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0BB95C8597757513ULL,
		0x62E36075B371C244ULL,
		0xF7500427800D1344ULL,
		0xDDAA99BD35E812BDULL,
		0xE6791BAC3A47BDE1ULL,
		0x2F40785F40D38C45ULL,
		0x9A64DB6F5CC2EAB4ULL,
		0xE73CD73489214B63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCA0253848C66E7EAULL,
		0x40B7DBC8B2D99E98ULL,
		0x905E53BD0E023671ULL,
		0x5F8E859FF875AA19ULL,
		0x61E8C6F59E2EE5D7ULL,
		0x554425501F1502FAULL,
		0xDF5DC2A5D2A9094CULL,
		0xA9E6D6A0681FF671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x370AF5E8A1F285A2ULL,
		0x331D453BA1F69A57ULL,
		0xE6E1917FFDE79EBAULL,
		0x597198CD9D9C7A48ULL,
		0x83687C302461C58EULL,
		0xAACE0BB9719D6C27ULL,
		0x202FE2AF22DC2ECCULL,
		0x9B5839C447057E0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x20E4487403DDA777ULL,
		0xEFBC5CB718562678ULL,
		0x6107C4F2C9F847A3ULL,
		0xD2EFA3DEB522B842ULL,
		0xA30A940AA5D088B7ULL,
		0x51D386C4C8F04776ULL,
		0xB7175354047D2D31ULL,
		0xADA4C5F853A802F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x389A58616EADE6FEULL,
		0x3045733572E8F5C5ULL,
		0x73C6E81D5A4E8FABULL,
		0xE36302829D36019AULL,
		0xBD46E612CC74C2CAULL,
		0x4CF9DAF9AD1CE6DAULL,
		0x034381441518D6D1ULL,
		0x2F4F471784EA2CFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAE6877C54069A19CULL,
		0xF2BCB878412E420BULL,
		0x2081706FF58102A5ULL,
		0x0157C36FA12758B6ULL,
		0x2E1E07DA35168AFDULL,
		0x5E821AA866839940ULL,
		0xD08AB3A511C65B1BULL,
		0xBBC8C7830E01B2C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x762B801805DCA947ULL,
		0xC8311692F2082695ULL,
		0xEE92E2528FFC3243ULL,
		0xEE6FBBF9F89A6D57ULL,
		0xC929A82C6209BEF4ULL,
		0xCE1F9E2180DE3328ULL,
		0x30986D88360DD88AULL,
		0x91730B0D1268C7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x72F517EC666B2B70ULL,
		0x6EF66AE578415DBBULL,
		0xB590E2A4099A2F8AULL,
		0xFFDE0ACE4C42D91FULL,
		0xC917CC4A08D59D26ULL,
		0x9D6043A545064328ULL,
		0x05EC8D4F49350E55ULL,
		0xC7C60A9965710C13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD03FBD812D739DE5ULL,
		0xCA152A8AEEF7B04BULL,
		0xE589EB3C048CD577ULL,
		0xB58043F7A95E7DE6ULL,
		0x8A5E728B9F774505ULL,
		0x2C055FE3C2851D15ULL,
		0x74DB4C58F75362D4ULL,
		0x36E0D053F699047EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1414FA15D6465C40ULL,
		0x9703287638C5BC2DULL,
		0x1E8CC8BED37B7944ULL,
		0xCF1762A1EDF879DDULL,
		0xBE0BF4CA640B92A4ULL,
		0x23B297F8113E7FAAULL,
		0x6EF73AFDE6B1B828ULL,
		0x7708850DD71FFA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7569DB4D926FCBACULL,
		0x980F618E13FF4418ULL,
		0x48B72C1A64A3E7C2ULL,
		0x7A6C3EE356EB5144ULL,
		0x3A9704D1CF9924D9ULL,
		0xD6BC4FB6EB39B8AEULL,
		0xCFB5937F4DC00B4FULL,
		0x61D32F4D82B9C3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5F9941E169AAC013ULL,
		0xDC73B59EB5CA6C0CULL,
		0xBB407155BA4007E7ULL,
		0xD813B5749A1DC8B1ULL,
		0x7C394181B606D155ULL,
		0x4C384890B349D720ULL,
		0x491D832CBD92911CULL,
		0x8467FE2B1969BFF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0329C03842A570BBULL,
		0x226AC68BB47C173FULL,
		0xA7B4742F7D928728ULL,
		0xA8E48B39359270C0ULL,
		0xA8A44376EE57B268ULL,
		0xA04BD6CFA6520EA8ULL,
		0xFB333B077FFF3F4BULL,
		0x626C896BE95D43E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x69088F470A5524B1ULL,
		0xBE95884779310C0DULL,
		0xF8C632EC9252744CULL,
		0xFDED46F8B6E5E603ULL,
		0x5D56EE7D28301E23ULL,
		0xF9B7F0F9393A9A6AULL,
		0xD635E0FF7EA08D34ULL,
		0xB997AA7FFFCBE5B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x820038DEFE48B1BEULL,
		0xE5A3BD738DEF6CF5ULL,
		0x06D095CAE94A6CCEULL,
		0x8576EBE7DD72589FULL,
		0x844B247307B68CDAULL,
		0xCB28739D837E3E2BULL,
		0x5FA79DAF495420A9ULL,
		0x07258AF46C2494BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xED767D51E1788338ULL,
		0x762F3F408D004C94ULL,
		0x0B48E7337078252EULL,
		0xA9149AAECBA22A83ULL,
		0x37D8B7EBE08E836AULL,
		0x4263C88925EF0016ULL,
		0x6D9DFB576F1C1494ULL,
		0x98A0FFFF94EF4112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC6668FCEF279A41FULL,
		0x8316296AFFB71CDEULL,
		0xA77B284FE02B5D4EULL,
		0x7947944B0BDD701EULL,
		0x1A499B3382DD5978ULL,
		0x16B2332D2F9D7AD4ULL,
		0x834EF9645B0EFB91ULL,
		0x3B29BE4849BCD170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xDBFE7AD2A4520DF5ULL,
		0xCBFCD8BFB23F56B8ULL,
		0x4F995A849DDA30E7ULL,
		0xECC67C055493028DULL,
		0x1BF6BB84DB9470D4ULL,
		0xFD7B3496366D45D4ULL,
		0xE456CB3042538870ULL,
		0x1A9B9BD199232065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCE34E451284E02DEULL,
		0x80DDFD0FD83BEABCULL,
		0x666B50D4B3681987ULL,
		0x54401E317FBAD1C1ULL,
		0x6526C5D31F5310B8ULL,
		0xB3A6466E07C2DA4DULL,
		0xDD97473ABA76D35BULL,
		0x41D56965EBCC061CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x41E6B08D1F7E5EE7ULL,
		0x3D587B0287C21109ULL,
		0x3E89518CDC0F1C6BULL,
		0x104DD6854327C432ULL,
		0x2055FBF532345198ULL,
		0x41D2AABC94B9D0D9ULL,
		0x02FC17C4C323DA8EULL,
		0x417CC522B782EC0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xF5C2BC148D4DB015ULL,
		0xC3C91A200354C5B9ULL,
		0x0C6D058B03FBD9FAULL,
		0x46E1B598EF34BA60ULL,
		0x128B0F026B4D2407ULL,
		0xCA73B678C6E145BAULL,
		0xCA4E2B6AC48C5FEAULL,
		0x0197227E948CAF85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x8CA8CDF9C5F940C0ULL,
		0x17B91FA06CCA318FULL,
		0x1BCFE315323A9F51ULL,
		0x885AA6F1FC560BB2ULL,
		0xA48249EE19E19E9AULL,
		0x127F6787E9B3DE83ULL,
		0x9799F3036F39833CULL,
		0x0A0550847245CED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x02A1F02F3CC79B73ULL,
		0x00B8B8D540AEA82BULL,
		0x7EF00EB250DF8C04ULL,
		0x6ED12F3DB27D8C39ULL,
		0x14FD96375152B8C4ULL,
		0xE5AB818E6D9321CFULL,
		0x15AF47143EFC361CULL,
		0xC2DBC8597D9EFC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB85E00BE95EDA0D7ULL,
		0x1C2CA63DFB602404ULL,
		0x31AD5407AC650959ULL,
		0x5BF1C60A002CB673ULL,
		0x70D7B460820D579DULL,
		0x37045CD2C599C8DFULL,
		0x44B6166F08FB48FAULL,
		0x44BFC227C1905718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF86B1AD566247926ULL,
		0x320D29A2FC0825A4ULL,
		0x2D66A27EFEA8B3A9ULL,
		0x76D69208E0AC0CBCULL,
		0x2EE73005CCE0FE14ULL,
		0xCCFD29C554FD9AECULL,
		0x6018F41EDAFAC08DULL,
		0x67D26D00BE88B630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE54140F67756E99BULL,
		0x40B9D25BBD42FBE0ULL,
		0x6F068E829EB9B80EULL,
		0x0439FDD21E59C08FULL,
		0xCB4545DDBAFA95AAULL,
		0x6DDD69A1002081F2ULL,
		0xA6011DBD7A092044ULL,
		0x124F24D2BCB44B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xBE232AE94563E7CBULL,
		0x88F4891CF6799F92ULL,
		0x0152C8F61F46D33AULL,
		0xE489D68F08BC6D2AULL,
		0x918329D330918CC5ULL,
		0x16262E706ACB6157ULL,
		0x3C157C7FFA82EBF1ULL,
		0x01DA38391ACAEBD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA6E5C6F8E3707728ULL,
		0xEDA2F9BFED25AE0DULL,
		0x30DB8DDF1D570E99ULL,
		0x40B9ABFD685A8707ULL,
		0xA4B45F84A9AA7922ULL,
		0x11769CF87B4BB6BBULL,
		0x9E53CC84FC254778ULL,
		0xE47A9FCDADC3CEC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE172DA837EAB99C0ULL,
		0x6BF89318D89A3A1FULL,
		0x28F58B330B01FDC1ULL,
		0x018DAA69F7A646FBULL,
		0xA91F5212688730E5ULL,
		0x6BD20AA6CC3B95D5ULL,
		0xB61ED385CD95904BULL,
		0xE3511C03BC643F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x07788B511073302AULL,
		0x7C0DE8D4022726B1ULL,
		0x687206CDF8EC3C15ULL,
		0xFFE4BFBD975B0765ULL,
		0xCA50094ED8C41081ULL,
		0x58840AE4A1BE6837ULL,
		0x4A4A61A8914DE712ULL,
		0x71D3B5C96D146291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x530A11C8E095707CULL,
		0x36D2966F3BB1A02AULL,
		0x8BABB910CF18BEA6ULL,
		0x404E0E642903ECFCULL,
		0x1EA6F031C0E30CA5ULL,
		0xB076166BC5B72688ULL,
		0xC0946B6A6583A583ULL,
		0xDDAB568375D5D217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE85F822EC7C3D9A1ULL,
		0x61757ED3F52E3E22ULL,
		0xDB6738758684E457ULL,
		0x7B0DC87AA5811F24ULL,
		0x70F2002A6E36DC57ULL,
		0x0365A9D70B080567ULL,
		0xF6A5036859E16B83ULL,
		0x7F17A961A8903980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF503EC20A2550978ULL,
		0x633593A77F7F60A1ULL,
		0x90DEB8645E271312ULL,
		0x51122A1C8F5CD0C1ULL,
		0xDA96DC4ABE58C68EULL,
		0xFC9F08334E93AC30ULL,
		0xA08A232F46A7D565ULL,
		0x860636647E0BB2D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF025AC3F027C34ADULL,
		0x9CF24F59BCD9F220ULL,
		0xD889D4D446F5031CULL,
		0x8016859EB3F61A9CULL,
		0x94E0A54C6FCE511FULL,
		0x38EE972D1DD83D4FULL,
		0xB5E3700AB1035BA6ULL,
		0x7954BE2230AAE511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1C2C0F1F9A2E9158ULL,
		0xDD3B53476E2A18FBULL,
		0x21D40F999802B578ULL,
		0x52C5EA3BFC68B639ULL,
		0x8E9EB1E5A8FC51B0ULL,
		0x2B754C9FE16A220AULL,
		0x7EA4EB3DB926078DULL,
		0xD58A7DD67C205267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x169DEC1B71CC5D60ULL,
		0xB614568FC43704B2ULL,
		0xE30332EF0BF2389FULL,
		0x8C3D5191C371E77FULL,
		0x8D1EB1572DE9FA40ULL,
		0x0C8C7E1DFE4F602EULL,
		0x4EA5816C8F20DFB8ULL,
		0xEA4CC2278124B6F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE82815AB74DA3A77ULL,
		0x09F9380033EDB38EULL,
		0x0E977D51EEB441E6ULL,
		0x557253F626CD633AULL,
		0xB7ACAF02BB53B0EBULL,
		0x48775D9B088AFDC6ULL,
		0x834AA732ADC0DDC2ULL,
		0xA59035C62D6B3E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC2832527778EDDF6ULL,
		0xA866DB35B6165561ULL,
		0x907D4B8834E11A28ULL,
		0xDB4137CB26DF0DD9ULL,
		0x7681B42E844679B3ULL,
		0xB9B918347357D82EULL,
		0x765926A36EB1410EULL,
		0xC3DE1E09815DDC0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xED05889BB4B57F37ULL,
		0x5C60F6593D743E0FULL,
		0x0108FB0293206B1DULL,
		0xC5230CD9F27A526BULL,
		0x32E5CDD00FA16DB0ULL,
		0x19E477014B74065CULL,
		0x2F59CC0C73C1F801ULL,
		0x8B214D1C008730D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x47A18E7F3F8E740EULL,
		0x2C96C2418010F9D6ULL,
		0x8ADDA824798727FEULL,
		0x4AA1DDF9413445DAULL,
		0xDB19D6EE3CE1D2ABULL,
		0x958F54FCD27F650DULL,
		0x7EF242138EAF8295ULL,
		0xDB71A3EAE78AF5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x402E71BB3F914A5BULL,
		0xF0C68C1AA210613EULL,
		0x27F5B5BAC8E4640DULL,
		0x88E482FC6F9EE4F8ULL,
		0x5DF4426E25FDAF5AULL,
		0xAEBE4C3D9533F2A1ULL,
		0x36AC48BC65C667B2ULL,
		0xF23B1FF9534B5507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x684E73AEC7FDE359ULL,
		0x86D43B29737BFD6FULL,
		0x94A8F739D0D61ED7ULL,
		0xE6BF26E1421C1158ULL,
		0x018C3552D19A7633ULL,
		0xAA90561191811AFFULL,
		0x47658A5FBC2085F3ULL,
		0xD6D3FE052B94D949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF379F0104620EBFEULL,
		0xD7FD0972E7B0F893ULL,
		0xA1EB2E4629B0DF63ULL,
		0x833E0AA67D3E245BULL,
		0xCE11F7FAADE2C412ULL,
		0x37F2B8AFABF865ACULL,
		0xA2E3816F80B53639ULL,
		0x4CE43BFD0D81B573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1DE8CBC8C80D03ABULL,
		0x48F22696D768E79FULL,
		0xDF5117476A12D37DULL,
		0xD514CF095D726926ULL,
		0x1E55D3E124ACD4D2ULL,
		0x741517BE66C32CD7ULL,
		0x0C2014736D6C854BULL,
		0x59206C4AAF1F7529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD01B74F229AEB7F7ULL,
		0x53E1474A95C0DB66ULL,
		0x69D7110CD509BDAFULL,
		0x1B9871136812F98BULL,
		0xBA45E514D13B9CDAULL,
		0xA5D262DC351280FEULL,
		0xDA105CC8C02AC591ULL,
		0x7D4BFBA9B023CBCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4B8EF54A4C5FE211ULL,
		0xA408A48D1C590479ULL,
		0xCB70B10430D1A576ULL,
		0x31ED0736B535463BULL,
		0xD3336EC78E072CD7ULL,
		0xFF8FA7B420D961DCULL,
		0x9ED6D9427B408ED8ULL,
		0x6D2CC74582DDBF18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1D5728AD8F5639B5ULL,
		0x52235A93926F2BDAULL,
		0xE72AD73A06C9C732ULL,
		0x10A47EB2A046D5A7ULL,
		0xCBC005DB6FBE597BULL,
		0xE15B8E0BF408F92DULL,
		0x0372442FCE479264ULL,
		0xE90DECDAAEFE591FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5F38D7ACFB46909BULL,
		0x5B0F5DDBA05F9235ULL,
		0x275D661059947AFCULL,
		0x1FEA903773DA9351ULL,
		0x2E8BC619E1A422D8ULL,
		0xF7F59891E5E3DB5BULL,
		0x90A2F6FD7FCBBBF8ULL,
		0xA89E3D691FCCA8D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4A72F2E0FD488CE1ULL,
		0xF9EA9EAD47225AE4ULL,
		0xB639D227A24D2249ULL,
		0x9BDC19DC47218473ULL,
		0x2CDB33EEB8F4413CULL,
		0x112A0B4E9C2C0642ULL,
		0xCB884ADE72F29B17ULL,
		0x24616FCEB22DE227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x56B9343B407D2240ULL,
		0x475797333F34A5FFULL,
		0xB4AF876BB8117563ULL,
		0x33F40588A7B18B93ULL,
		0x3ACD002088506548ULL,
		0x63C91D5E3C6D64C9ULL,
		0x486FE09B8B079151ULL,
		0x235BA5DA07F18B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4A832C6B0BB7CFA2ULL,
		0xA232B3FF04A5185CULL,
		0x1E0B972546BB508DULL,
		0xF1300D6DC9549593ULL,
		0x70B82297CE6F36A1ULL,
		0x5DA31F22D1093AA7ULL,
		0xEE3D51FD03C5E724ULL,
		0x53C656CA68BAF6B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x295F2A08F605B3D1ULL,
		0xB97B6624CB94B846ULL,
		0x057C2E69BF33642AULL,
		0xAA45A43F3BAB3A0FULL,
		0xF6ECB20237602320ULL,
		0x300CE9FB1DF3EC49ULL,
		0x4541D138B2F85715ULL,
		0x4E0D067A259B0BC4ULL
	}};
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0D4A9326D873F3A2ULL,
		0xE030767A155B5590ULL,
		0x6DD776335EC9B746ULL,
		0x3CFEB6745AEC0BFBULL,
		0x6C4E36F4C611FE50ULL,
		0xDF73E0837F77E006ULL,
		0x43A50D43668B6EF2ULL,
		0xDCCE9DD447CBA607ULL
	}};
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x0B04213D9C812C1CULL,
		0x9C86528204935D74ULL,
		0xDB5B8825653B042FULL,
		0x5AA3046C457C44AFULL,
		0xF2AB8E0EB4685D79ULL,
		0xDE76CE70E9E7750AULL,
		0x6AB5946D82BEC16DULL,
		0x0978A753F32AE58BULL
	}};
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x862DAF433247A671ULL,
		0x7EAB0A8DB6863932ULL,
		0xCB134F8B8B0DBC8AULL,
		0x5D116C94B40CDD9DULL,
		0xBA65F93998B1376CULL,
		0x3A25DBC516E4B87DULL,
		0xD7C478483406A40AULL,
		0x9DF895BDB126A7B9ULL
	}};
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFBD35731FBF7C448ULL,
		0x05713058FECC849AULL,
		0x5A328340E5C0410CULL,
		0xA4CBEEF72D99D077ULL,
		0x1201044FBE8E7B20ULL,
		0xB27499A8774E199DULL,
		0xFFA5D070B4FC3915ULL,
		0x5636600FD5C3644DULL
	}};
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEA4C79E4918E65FAULL,
		0xD0F6548A3117A2D4ULL,
		0xBC512DFFD770D06AULL,
		0xEBE135E6FE94B8FBULL,
		0xD3DC4F4DA131D9C5ULL,
		0xFFCFF0A2ADAE21AFULL,
		0x9E6F17D6B59BB94AULL,
		0xDB3935FC534012F8ULL
	}};
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 506 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x245A7DDCD76357A8ULL,
		0x66AC47EDEDB4B135ULL,
		0xB85EB285840E1896ULL,
		0xA6ADE7ADAF5FA7E4ULL,
		0xE80464E5A80C405DULL,
		0xB5CB2AA1BEA3342EULL,
		0x944E17C3DEC4BB63ULL,
		0x4745EF5D78E9EC09ULL
	}};
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 507 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x15C58AEA2D467150ULL,
		0x1CB4A24CFF0EBFA2ULL,
		0x3A87060AE3930BCEULL,
		0x3C14CC22C882AD59ULL,
		0x021B443248FD98B6ULL,
		0x9BCEBF8D077CCE07ULL,
		0x3B8D4F6783679C21ULL,
		0xC57289ADA9497604ULL
	}};
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 508 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE12F317364CFBF84ULL,
		0xAC1177806346888AULL,
		0x19CA0C8B8C8C63C2ULL,
		0x7DD7C91467C79B27ULL,
		0x66821D1EB38F42EBULL,
		0xD1ECC9405A45E6AEULL,
		0xBAC42B88DBB23C5BULL,
		0xA4D16C638F07DB12ULL
	}};
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBE1FA836E74B71C5ULL,
		0x29860C2E942CB0EBULL,
		0xDB32FF572171ACD7ULL,
		0xFDF4D8456458D9F7ULL,
		0x134612D00E1D39D9ULL,
		0xC17C8232CF9069BAULL,
		0x42420D5E0A15C79CULL,
		0x315BA24B4DC7F827ULL
	}};
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 510 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xFC9CC4CE487BAF6EULL,
		0xF948A5884780528DULL,
		0xB4386EFFA99E764BULL,
		0xC03CFB9799D82223ULL,
		0x676ED6A0A3941BEFULL,
		0x14B84B8E7EAC6D14ULL,
		0xC0730E078006A40CULL,
		0x112C0B97444B51C9ULL
	}};
	printf("Test Case 511\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 511 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -511;
	} else {
		printf("Test Case 511 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x90D46631852FEC8AULL,
		0x04E5E6E30DED092EULL,
		0x83182CD633208CCBULL,
		0x1D1EF392CA5747B9ULL,
		0xB764DDB72672C216ULL,
		0x5DB539478F8D85C8ULL,
		0x89F96D8927406229ULL,
		0x0F99BDDAC7CD9773ULL
	}};
	printf("Test Case 512\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 512 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -512;
	} else {
		printf("Test Case 512 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x1F52EDAB8ECB0D60ULL,
		0x3C5B5B88EEE872F5ULL,
		0x5007A1B8C066F996ULL,
		0xFC5A4BE75DB39B14ULL,
		0x65892834B2F4A36AULL,
		0x69C10AF5A2634559ULL,
		0x947766862860A3CEULL,
		0x0CC20E4E068D0375ULL
	}};
	printf("Test Case 513\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 513 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -513;
	} else {
		printf("Test Case 513 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0BDCCE4D3D3BFDD4ULL,
		0x33F9666163B5BCD2ULL,
		0x6AAD84126C6FCAF8ULL,
		0xE06961B3E2216895ULL,
		0x4E8F5D512B2FB5A3ULL,
		0x2618A25F14B3B8E6ULL,
		0x9D02021212325822ULL,
		0x873FECDA071CA9EDULL
	}};
	printf("Test Case 514\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 514 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -514;
	} else {
		printf("Test Case 514 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB230C55CE5237C83ULL,
		0x9BE10F5497118F66ULL,
		0xF5C1E11140A3A9EFULL,
		0xFD73AC8A19B325C9ULL,
		0xF975EE0AC2C400D7ULL,
		0x4C12F65D6A6F08C0ULL,
		0x4FA323649EBA4D2AULL,
		0x84F8D5269EAD3AFDULL
	}};
	printf("Test Case 515\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 515 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -515;
	} else {
		printf("Test Case 515 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3C209608CC86A1E0ULL,
		0x05F4E46C76017CD2ULL,
		0xE85F95500630DC05ULL,
		0xF38CE5B309BD1079ULL,
		0xC96C1626F3B562BFULL,
		0xEA05752D70C6E068ULL,
		0x141A640108D99E59ULL,
		0xD43E99EA171D4078ULL
	}};
	printf("Test Case 516\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 516 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -516;
	} else {
		printf("Test Case 516 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x291897EFDE569BD9ULL,
		0xE623AD743AF64C60ULL,
		0xF909CE52558062D2ULL,
		0x45CBA8712DB57E02ULL,
		0x76A58FF4995311CDULL,
		0x78C3F6448919F962ULL,
		0x30EC6A0ACFC92B9EULL,
		0xAED588A5D3249FC6ULL
	}};
	printf("Test Case 517\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 517 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -517;
	} else {
		printf("Test Case 517 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7EB559F02B4AC095ULL,
		0x24E77E0714230E2EULL,
		0x4D504F17FBB2AA0CULL,
		0x6E5BBA87E6EFA8F7ULL,
		0x384FCAA1B0D2ED5FULL,
		0xBF3FAF6FD5E784C2ULL,
		0x8041D43E4C0B64F6ULL,
		0x5F4A2EB56E435742ULL
	}};
	printf("Test Case 518\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 518 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -518;
	} else {
		printf("Test Case 518 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7DA5727A5D8118DCULL,
		0x0FCE32BFAE57807BULL,
		0x9957966B86D8F90EULL,
		0x4916F1370716D773ULL,
		0xF2E3351B037A5F97ULL,
		0x231A4FBDAA3FEDF1ULL,
		0xE3D6838AC9086EEAULL,
		0x2A240B823D1152C5ULL
	}};
	printf("Test Case 519\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 519 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -519;
	} else {
		printf("Test Case 519 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF95BC3D6ECABF1A6ULL,
		0xC11EBBEC3EE5E8FCULL,
		0x65D63DC67EDB27DEULL,
		0xF0301B9EE964BDF2ULL,
		0x4B39DF0215EF0C1BULL,
		0x3FB71C59D338AED7ULL,
		0xB340938F403B31DDULL,
		0x7C0F97D0234AE098ULL
	}};
	printf("Test Case 520\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 520 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -520;
	} else {
		printf("Test Case 520 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0D28E75D1C5687E8ULL,
		0x6E9CFF5ABB56659BULL,
		0x3FF06CE6C854E97FULL,
		0x731C15DEB434AD2EULL,
		0xF1890A9BA8510F78ULL,
		0x7D49732377670D55ULL,
		0x9E9F6BC09EDA1D94ULL,
		0x3C21400A8B6977BBULL
	}};
	printf("Test Case 521\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 521 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -521;
	} else {
		printf("Test Case 521 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x45F248446F31EC87ULL,
		0x71833238F0201ABFULL,
		0x736DBFCA015B967FULL,
		0xB740D7C52673BAF0ULL,
		0x24E7725552459449ULL,
		0x4A028F331284CE8DULL,
		0xA5CFFEF6773CAB42ULL,
		0x39B4BDBC7611E901ULL
	}};
	printf("Test Case 522\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 522 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -522;
	} else {
		printf("Test Case 522 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0A57F6720B0B9705ULL,
		0xC36283D34EF0EC40ULL,
		0xD6975CE69FF45433ULL,
		0x2581358664A64F21ULL,
		0x88FCB9C157654681ULL,
		0xDBAF3D01DBA28661ULL,
		0x1A16A9CD2A42842DULL,
		0xC6187F78B886DA40ULL
	}};
	printf("Test Case 523\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 523 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -523;
	} else {
		printf("Test Case 523 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x53F13B309A8DBA44ULL,
		0x0DF7BBD2FA16D39EULL,
		0x3F53EC6C0D452837ULL,
		0xA46EECC41B624911ULL,
		0x2AC028CF5E199315ULL,
		0xA42CA424787A5F70ULL,
		0x9D0F3B036B1DD4E4ULL,
		0x02E0A64116C233CEULL
	}};
	printf("Test Case 524\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 524 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -524;
	} else {
		printf("Test Case 524 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5E998B4335EB9A6DULL,
		0xEC6B8B8FE1E816D8ULL,
		0x8FDCD59EBD7856CDULL,
		0x585F7DADC019A009ULL,
		0x7A161C2237E6173CULL,
		0x2F306F1FAE7BF30CULL,
		0x99C0BFA88E53D71FULL,
		0xD0FB203093024CB1ULL
	}};
	printf("Test Case 525\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 525 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -525;
	} else {
		printf("Test Case 525 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xDFE37251D7DBC0EEULL,
		0xD5C4E2719731CECFULL,
		0xB8DC6A9CE095882AULL,
		0x1F7E56449A112513ULL,
		0xD5B76BB5C0038957ULL,
		0xD4487B4986865AD9ULL,
		0x7693A5A80BC8D70FULL,
		0x2D4ECD27813AF1D2ULL
	}};
	printf("Test Case 526\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 526 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -526;
	} else {
		printf("Test Case 526 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x12A43B4975B82ABDULL,
		0xD2FBBD8F4589AFBEULL,
		0xC06A536FD07B2688ULL,
		0x6F37A42799F37D23ULL,
		0xC5BE625EE7551498ULL,
		0x6597ADC36823DF0CULL,
		0xCF432FA10F69A5E1ULL,
		0x2A8312898B76F0B2ULL
	}};
	printf("Test Case 527\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 527 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -527;
	} else {
		printf("Test Case 527 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2BCB104DB87732C4ULL,
		0x8680DF7C9EA5C22CULL,
		0x2652C2A0CAFC3F8CULL,
		0x87415A3A6D8FE214ULL,
		0xF8FAA26ADA19502BULL,
		0x869D03D0C05394B2ULL,
		0x481B1414450538A4ULL,
		0xEC878890475AE85DULL
	}};
	printf("Test Case 528\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 528 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -528;
	} else {
		printf("Test Case 528 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF272DCEBAC2E87C8ULL,
		0x3CDBB9AE67ACA42BULL,
		0xDF398723CD26E033ULL,
		0x0F64404CE00D85C4ULL,
		0xBAB3BFBF7E778DB5ULL,
		0xA2DD3770B95F3F81ULL,
		0x01E032C0EDF17929ULL,
		0xAA0580D6694DC638ULL
	}};
	printf("Test Case 529\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 529 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -529;
	} else {
		printf("Test Case 529 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x23137C430033491EULL,
		0xDC805D5938320713ULL,
		0x6B622EA59E8F2623ULL,
		0x88EF3E91E1FFD600ULL,
		0xE7856431FB123212ULL,
		0x077CC379D3640BDAULL,
		0xBB920722761A40F1ULL,
		0xC2211915F0F2DA08ULL
	}};
	printf("Test Case 530\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 530 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -530;
	} else {
		printf("Test Case 530 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE33FB546097261F5ULL,
		0x0778739C72E32F5BULL,
		0xD071FB0210FFC2C1ULL,
		0x658B41E5E2268101ULL,
		0x511F1201077C0E70ULL,
		0xD80C8F90AAC6BDDBULL,
		0xBD3ADEEA841B3270ULL,
		0x2F68362B601D0058ULL
	}};
	printf("Test Case 531\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 531 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -531;
	} else {
		printf("Test Case 531 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB4B9DE4353C1ED51ULL,
		0x8C4204A2835CB112ULL,
		0x7C44378A25E60EE4ULL,
		0xBA655D8C27C9C7A3ULL,
		0xA55F5B6873D862C6ULL,
		0x14428F73BBA8D32FULL,
		0xC983152C6B947C63ULL,
		0xE74B75E8766275F0ULL
	}};
	printf("Test Case 532\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 532 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -532;
	} else {
		printf("Test Case 532 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6DDC2D2E5C76AB00ULL,
		0x119903A584D6DD0BULL,
		0xB78FB60A4A4F5335ULL,
		0xB7DA0404E63F6E79ULL,
		0x2949F6B9B06E38A7ULL,
		0x08B3636813CA7F1DULL,
		0x12F761E0356FF597ULL,
		0x38493EF0F4F441B2ULL
	}};
	printf("Test Case 533\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 533 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -533;
	} else {
		printf("Test Case 533 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8E6C866D2A898A49ULL,
		0x81A16EC5B0FCFF7AULL,
		0x6EB7C19A37F7C591ULL,
		0xE980056A98648C1DULL,
		0x33F5926A5E8DBED5ULL,
		0x05F895534500CF39ULL,
		0x3515114B1685AAD6ULL,
		0x5B122227E6C590CBULL
	}};
	printf("Test Case 534\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 534 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -534;
	} else {
		printf("Test Case 534 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2E78C17D26C2885AULL,
		0x093A41F383D02BEAULL,
		0xEF25B695B9338123ULL,
		0xC4B13B45D1273C70ULL,
		0x21CE16CE2340189FULL,
		0x94685885900CC374ULL,
		0x7BB81F329253F99DULL,
		0x32937123CFD3B089ULL
	}};
	printf("Test Case 535\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 535 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -535;
	} else {
		printf("Test Case 535 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x01A48099297B3E88ULL,
		0x325A1C989EA75C6EULL,
		0xEC0E13A7E02F8710ULL,
		0xDD307534A960CBEFULL,
		0xDE625D253861D25DULL,
		0x4CD79421C00C94E9ULL,
		0xDF8F17D7602B1F4CULL,
		0x9F4B510FF68CFA37ULL
	}};
	printf("Test Case 536\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 536 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -536;
	} else {
		printf("Test Case 536 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1D844A3BBFD44007ULL,
		0x29C4FB12FB1B1DF5ULL,
		0x5E2C6E6AC1C6A64BULL,
		0x911BD5010B4913C5ULL,
		0xB237CF28FCD32B52ULL,
		0x374B80D63408A22FULL,
		0x43BF6E304BB86D47ULL,
		0x9821045A9FFAAAFFULL
	}};
	printf("Test Case 537\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 537 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -537;
	} else {
		printf("Test Case 537 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xD5E54DC80D6F7999ULL,
		0x3FCE4767AE6A9F97ULL,
		0x562CC126759B22C3ULL,
		0xD8E7BEB8928530BDULL,
		0x8BAD7902265B69A7ULL,
		0x9C91CB3674B33325ULL,
		0x0A476B47977FDEE0ULL,
		0x17255C8D8B223861ULL
	}};
	printf("Test Case 538\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 538 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -538;
	} else {
		printf("Test Case 538 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBE8FE827903B62A2ULL,
		0xD8E9BC3538079981ULL,
		0xA01324C583557DA3ULL,
		0x96144742067C1493ULL,
		0x0B29D9BE95391572ULL,
		0x7F8676C700DB2A60ULL,
		0xA866544D61C96625ULL,
		0x41E0E292061F6889ULL
	}};
	printf("Test Case 539\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 539 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -539;
	} else {
		printf("Test Case 539 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDA15C62C99BA1A59ULL,
		0x27A120834698BD15ULL,
		0x98454E20E71A2674ULL,
		0x018C4E59F922D2D6ULL,
		0x03D84EF2A4AC661CULL,
		0x6705D5831BEB8CD4ULL,
		0xBE2C286B46B06209ULL,
		0x963C7F2D8B62BA3FULL
	}};
	printf("Test Case 540\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 540 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -540;
	} else {
		printf("Test Case 540 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x977E6DA0960C1DFCULL,
		0x58C9CC9BFA9E1721ULL,
		0x50FDF443C494E9E6ULL,
		0x5C7C976387E151E5ULL,
		0x5796E59752A638EFULL,
		0x2284CA44296B2BDFULL,
		0xD5D4A382D5168021ULL,
		0x1BB9BD020B33FAD9ULL
	}};
	printf("Test Case 541\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 541 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -541;
	} else {
		printf("Test Case 541 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6A36A7830463A4DEULL,
		0xE170D27509386876ULL,
		0x413FA33283A8F9ECULL,
		0xD2883960CBFFA108ULL,
		0x8B2DD58C7F09F1EDULL,
		0x4211A3015DE14924ULL,
		0xC46C895D95B24E58ULL,
		0xE02329D4FD102EF5ULL
	}};
	printf("Test Case 542\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 542 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -542;
	} else {
		printf("Test Case 542 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x89F5D57F501FE571ULL,
		0xA4927A834F9C964CULL,
		0x4D782618A138075EULL,
		0xEF763007777562ADULL,
		0xF7F37A90B3031FFDULL,
		0xC986940CAC4FD320ULL,
		0x1D5A2F78E06FC394ULL,
		0x4A9DA0E856F69692ULL
	}};
	printf("Test Case 543\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 543 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -543;
	} else {
		printf("Test Case 543 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x538E2815C9BAE574ULL,
		0xF4CC551FA82B8C96ULL,
		0x59D096A38F04B9E9ULL,
		0x44303A0D8AE32F2AULL,
		0x3A0626103B03AB1AULL,
		0x8DB3F8666AE031C8ULL,
		0x9A08DC5F09D63960ULL,
		0x9E691E61391843E8ULL
	}};
	printf("Test Case 544\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 544 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -544;
	} else {
		printf("Test Case 544 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0868E26FE1F14DC1ULL,
		0xDE874B530D38C201ULL,
		0xA7CC0C3F0CE0C24DULL,
		0x2B7F74A580CF907EULL,
		0xAE42A67AFA667593ULL,
		0x9A10EA3D0C5D1D31ULL,
		0x6AF1538BCAB99D8EULL,
		0x11A96F6D13D4707FULL
	}};
	printf("Test Case 545\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 545 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -545;
	} else {
		printf("Test Case 545 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xE376A4E7FEFFC4FEULL,
		0x91F6511F3EF2D9A7ULL,
		0xBC92817110DF48DAULL,
		0x5A20E4F3B3F03884ULL,
		0x8B6B00C804653FF0ULL,
		0xE87BE38E76F36CC9ULL,
		0x8FB80BF26CC44466ULL,
		0x0D22ADC7127C85F3ULL
	}};
	printf("Test Case 546\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 546 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -546;
	} else {
		printf("Test Case 546 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFAC2FBE16027BC48ULL,
		0x047F6C17F4B68EAEULL,
		0x8A29ED489DE248FDULL,
		0x2D338FEE026DDA42ULL,
		0x661888D50AB8C354ULL,
		0x88D401BC07DA393BULL,
		0x0831C248AD31C32CULL,
		0x725AEF88A98C0B1FULL
	}};
	printf("Test Case 547\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 547 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -547;
	} else {
		printf("Test Case 547 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDDA3370A3B717654ULL,
		0x61FFA0A4696AA5FAULL,
		0x08CA259C4C2FAFC1ULL,
		0x0F35A9ECB6E2B065ULL,
		0xFB2B4111F29C1C06ULL,
		0x1C2C73AF928FDCBDULL,
		0xB8C2CDA95A83E6EBULL,
		0x5A70ED6979DD5D31ULL
	}};
	printf("Test Case 548\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 548 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -548;
	} else {
		printf("Test Case 548 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA95C64949996B5F3ULL,
		0x01A5864F7D9FCC2AULL,
		0x1773A3BBDBA8094DULL,
		0x43E5E2706163B130ULL,
		0x5427F0D63516AB59ULL,
		0xAEF1687672367692ULL,
		0xD018735A908390B3ULL,
		0x87C87E43EAED6023ULL
	}};
	printf("Test Case 549\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 549 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -549;
	} else {
		printf("Test Case 549 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x298D04A19C7BD63FULL,
		0x10B8C2A79AF6B71EULL,
		0x8E566F38358CF02BULL,
		0x5FA5F1F7774A0C10ULL,
		0xDE43E2B8CEC8D522ULL,
		0x06446BDB564658B9ULL,
		0xC54AF45C1C1A033FULL,
		0xB2B14803797EEBA5ULL
	}};
	printf("Test Case 550\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 550 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -550;
	} else {
		printf("Test Case 550 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x92F2860BAC6BFE65ULL,
		0xDCABED506F75EA6DULL,
		0x4C3E16E3A791B3FFULL,
		0x58A2501EA0DEB67EULL,
		0xFA680111BB78E3C1ULL,
		0x1F457A0B8A14991EULL,
		0x18FE5A52CDB42AF3ULL,
		0x73B415E4023F8ADCULL
	}};
	printf("Test Case 551\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 551 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -551;
	} else {
		printf("Test Case 551 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7C5A1239366EEEF2ULL,
		0x5C8F48E651E1B9E5ULL,
		0x368AB6DAC762DFF5ULL,
		0xC2AE1D25AFC09015ULL,
		0x320EFE3FC6A5282FULL,
		0x2FA39FFB90B1F0E6ULL,
		0xD41F7AACC9FD59D2ULL,
		0xBCB9DC95623FAFA2ULL
	}};
	printf("Test Case 552\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 552 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -552;
	} else {
		printf("Test Case 552 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC812023BE270CEDEULL,
		0xA74B0A0612AEED60ULL,
		0xA28DE7242048D9C3ULL,
		0x8FFF2C74DAE75822ULL,
		0x3AF7B5D44DBA8456ULL,
		0xDCCB00D9CF8985C0ULL,
		0x30A8AFA0236C9586ULL,
		0x7EA093DA4CBEF9C3ULL
	}};
	printf("Test Case 553\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 553 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -553;
	} else {
		printf("Test Case 553 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x96C5B16E16787B22ULL,
		0x30BF6872DCBCED5AULL,
		0x74E8691B9340D740ULL,
		0x2DA6C02135C59871ULL,
		0x92C975C16D9AAEBCULL,
		0x64524261AABEB730ULL,
		0x0465855501272242ULL,
		0xBB73045950D27333ULL
	}};
	printf("Test Case 554\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 554 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -554;
	} else {
		printf("Test Case 554 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x46366D433981D049ULL,
		0x0D99C0D47FEA5390ULL,
		0x790DBB4EAB351198ULL,
		0x5B8FA0C025AE3E23ULL,
		0x00BBEF16665ED695ULL,
		0xF62E3373CA557C3FULL,
		0xC098FEBC99C55209ULL,
		0xAB96D8A72287503FULL
	}};
	printf("Test Case 555\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 555 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -555;
	} else {
		printf("Test Case 555 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x326A15E8C9CD7759ULL,
		0x7E583840CDA2AAB3ULL,
		0xD53C494908864327ULL,
		0x583AC5CD84F8A21FULL,
		0x86D7C3998CCFB969ULL,
		0x42E66BA0EB56DE2DULL,
		0x19006C5B185FEE08ULL,
		0xB16BC6C454C8E676ULL
	}};
	printf("Test Case 556\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 556 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -556;
	} else {
		printf("Test Case 556 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2A5D027CDBACCD8AULL,
		0x0BC954BDE21A0A0CULL,
		0x3ED5C6F19A881A08ULL,
		0x16B132C9EB03DDAFULL,
		0x4DDD2D53069BFA39ULL,
		0x8F3C03415BEE2038ULL,
		0xFA178116403571BFULL,
		0xFE902EF5AB673C8EULL
	}};
	printf("Test Case 557\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 557 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -557;
	} else {
		printf("Test Case 557 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5C99ED37D9C6CC16ULL,
		0xE0477A1E43643E79ULL,
		0x16FA30B0BF5F13F7ULL,
		0x98AC36AE61B35D79ULL,
		0xA1099BEF47435D16ULL,
		0xDDAD94E554EEB40EULL,
		0x2DC51BC8468DCC04ULL,
		0x7908E111C6665F9FULL
	}};
	printf("Test Case 558\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 558 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -558;
	} else {
		printf("Test Case 558 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC34BFF9E65B0A838ULL,
		0x8816D38CB1BBCDC9ULL,
		0x65550646C9F819DBULL,
		0xFE9D2262E67CE76DULL,
		0x6B65C3D82853B83EULL,
		0x6E9F94847D865088ULL,
		0x1F027D43F90A4C8EULL,
		0x36802AF78246E9C8ULL
	}};
	printf("Test Case 559\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 559 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -559;
	} else {
		printf("Test Case 559 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA3A428448A9FE912ULL,
		0xB3AFE29FE0FA3C07ULL,
		0xD9075DC2A945162FULL,
		0xCD696148496E07F5ULL,
		0x4AF2AF8215722C35ULL,
		0x10CA2F4A5D1DBA0DULL,
		0x194FA5D69CEF9ADAULL,
		0xD2AB35D1BDA6C4B1ULL
	}};
	printf("Test Case 560\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 560 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -560;
	} else {
		printf("Test Case 560 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x320993754FDF5B77ULL,
		0x373A4ADBCDF2CB96ULL,
		0xA8B9CC523E407F09ULL,
		0x7ADC855EE867DA12ULL,
		0xE28B5B24B9C90506ULL,
		0xE92FA1B7456B42A8ULL,
		0xF6CBFE7D3FF1E164ULL,
		0xD075475EA5020761ULL
	}};
	printf("Test Case 561\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 561 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -561;
	} else {
		printf("Test Case 561 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8264D652A25CDE29ULL,
		0x06E231576813D05FULL,
		0x0DA197CC822AE489ULL,
		0x311E9868224C17BBULL,
		0xC0BBF5F71F74C545ULL,
		0xA33A42711F105090ULL,
		0x65F3765BED159673ULL,
		0x3711FF75B54F4308ULL
	}};
	printf("Test Case 562\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 562 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -562;
	} else {
		printf("Test Case 562 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFF386EC5CB9EE2D1ULL,
		0x697F45FA11402A32ULL,
		0xCC9497CCCB79E1C1ULL,
		0xE4E0C01615D06134ULL,
		0x8E18269053469E49ULL,
		0x50F27DF17480C0FEULL,
		0x94059CE8A8BD8499ULL,
		0x388314F8141ADCB9ULL
	}};
	printf("Test Case 563\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 563 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -563;
	} else {
		printf("Test Case 563 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xADFC9B7F9AC86395ULL,
		0xB9B9A74641EF4789ULL,
		0xC51C9C6A2C4346A6ULL,
		0xE0D4D95F7DEED5E6ULL,
		0x8D262F0B20B44C13ULL,
		0xACAEE2770A41C227ULL,
		0x4E4156C0402A2887ULL,
		0x22DC674B456725DDULL
	}};
	printf("Test Case 564\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 564 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -564;
	} else {
		printf("Test Case 564 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8B8C4258E39CC234ULL,
		0xE8CFC3C2C1FCAA19ULL,
		0x541020BFA47B7475ULL,
		0xE66F0AEB1F7764E3ULL,
		0x2A9420192B4B9452ULL,
		0xFD1E10AF405F9085ULL,
		0x139367F8F1150B81ULL,
		0x450447F678C0C899ULL
	}};
	printf("Test Case 565\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 565 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -565;
	} else {
		printf("Test Case 565 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x36EC6D86219E33FAULL,
		0x1CA6488BD7E04160ULL,
		0xCB4892693EEA4E6FULL,
		0xFB44E2539ECEDF03ULL,
		0x6F6803BD5F463C38ULL,
		0x9A65C0C297232EDCULL,
		0x1DE3834570A689A4ULL,
		0x9868D79B3A783ED9ULL
	}};
	printf("Test Case 566\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 566 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -566;
	} else {
		printf("Test Case 566 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC47435B2451DDE73ULL,
		0x4FCF5AA17FF6A628ULL,
		0x148E6D933E8C1706ULL,
		0xC07D5BD8AE16186DULL,
		0x701F894F015F94FAULL,
		0x638C9720357B7B67ULL,
		0x90F6AE1A1E3E3B6FULL,
		0xD92638FC1504A732ULL
	}};
	printf("Test Case 567\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 567 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -567;
	} else {
		printf("Test Case 567 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x0F72C7D08974CC2CULL,
		0xCA1779046B5169EAULL,
		0x666E9984EE506E7DULL,
		0x464CF65EBAAFFB35ULL,
		0x029F68CCB7D220D5ULL,
		0x956F04EB90A33143ULL,
		0xAFEDB5D8D90D526CULL,
		0x0C7F1454332FB755ULL
	}};
	printf("Test Case 568\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 568 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -568;
	} else {
		printf("Test Case 568 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6E1C1DCF5F15280AULL,
		0xBFE9C45A813D03B6ULL,
		0x32655F45241A52B6ULL,
		0xC9433AEEB4839D0EULL,
		0x88D1BF7426E1765DULL,
		0x249C955E0D70FDACULL,
		0x8006C5F8AC89A179ULL,
		0x9C53FFB1578E1FDCULL
	}};
	printf("Test Case 569\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 569 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -569;
	} else {
		printf("Test Case 569 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x85816D86B81AB351ULL,
		0x1F779C0892ED2A11ULL,
		0xC72B94D57825A574ULL,
		0xAA532585F3F963E2ULL,
		0x93EC61A67672F339ULL,
		0xA20766E0F0E522BAULL,
		0x100F59140C5C25A0ULL,
		0x88AD7EA4747424BCULL
	}};
	printf("Test Case 570\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 570 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -570;
	} else {
		printf("Test Case 570 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x86F81E110AE23D1CULL,
		0xD1655CFFDBB6A32AULL,
		0x4247243A1F111FA2ULL,
		0xAE7A242C3BFE847AULL,
		0xAD5336D060B745B6ULL,
		0x40A72C3C39FD91A2ULL,
		0x624D0264CC9DCFA5ULL,
		0x0926CDFC3E478582ULL
	}};
	printf("Test Case 571\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 571 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -571;
	} else {
		printf("Test Case 571 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x22FB6D765EE58746ULL,
		0x490021744C3CD17FULL,
		0xA3090550864B9B7EULL,
		0x63DD038962C3E78FULL,
		0xDEAD1689900CF7B8ULL,
		0xB6E07951E864CB3EULL,
		0x31E792CBCEF747FEULL,
		0xCE8936B083F92381ULL
	}};
	printf("Test Case 572\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 572 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -572;
	} else {
		printf("Test Case 572 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x73316A28C9A60DABULL,
		0xF5F0711E817CA453ULL,
		0x21AABDCF22F7072AULL,
		0x3A4E7944A80B51C7ULL,
		0x5ADA9B38BCE8FAA2ULL,
		0xC3662888EB504447ULL,
		0xFF82F8348C3BA0C1ULL,
		0xC1B37AD5D7FEB86DULL
	}};
	printf("Test Case 573\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 573 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -573;
	} else {
		printf("Test Case 573 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xF5E1B42ED56C3269ULL,
		0x70FD79FD15A84EA3ULL,
		0x0DFFAF1A8186662BULL,
		0xE7BC3C76DBED45FBULL,
		0x8C9AEDBA4C477A8CULL,
		0x046673FDB92A0757ULL,
		0x87413064F48420B8ULL,
		0x0EA711A398E7270BULL
	}};
	printf("Test Case 574\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 574 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -574;
	} else {
		printf("Test Case 574 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE99E914FE163531ULL,
		0x1436F6C0E0D8E583ULL,
		0xDB88265A1CBDA58AULL,
		0xD3CC4E4144B66B04ULL,
		0xA6A6761E1B37D8AFULL,
		0x631DE190158DCD49ULL,
		0x61BF981E06C9FF2EULL,
		0xEEEA4B120FA8E371ULL
	}};
	printf("Test Case 575\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 575 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -575;
	} else {
		printf("Test Case 575 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x48C41400FDC85BD9ULL,
		0x2EC46FDBA1FF5B4DULL,
		0x1BEA21EAF5DF7A45ULL,
		0xDA1DB47EC0115CC1ULL,
		0x507B35E0FF2B13FCULL,
		0xEA055AC4591805EBULL,
		0x1DC8A3AF5804AC3EULL,
		0x81D7D5EBAD66C44FULL
	}};
	printf("Test Case 576\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 576 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -576;
	} else {
		printf("Test Case 576 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFBC32BED1537DA72ULL,
		0xB06FFFF606C62703ULL,
		0x9807876D123F3692ULL,
		0xD2D07BF3C58EAAC6ULL,
		0x631BCBC2D8E7B22DULL,
		0x4B81DD6E8B49FC3CULL,
		0xDF2C3A48834B31E6ULL,
		0xDB96C74CDBEC77DDULL
	}};
	printf("Test Case 577\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 577 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -577;
	} else {
		printf("Test Case 577 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC51E96715654FBF7ULL,
		0x7535AB517C1B3450ULL,
		0x4C47DA2C1EC8F4DBULL,
		0xAFDAF35EF3CA9579ULL,
		0x2C4C41254328D814ULL,
		0xE98021FC9B536FE4ULL,
		0x080AE2FB198A200AULL,
		0xC1283B1CDD1EBFEEULL
	}};
	printf("Test Case 578\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 578 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -578;
	} else {
		printf("Test Case 578 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x87F29AA8AF539E90ULL,
		0x65E780F3D756B65CULL,
		0x77A2D441353720E7ULL,
		0x8462362881C82757ULL,
		0x86618E3196EF3602ULL,
		0x242AE71837001D58ULL,
		0xC82DE72AF625B98CULL,
		0xFF4C29E870623621ULL
	}};
	printf("Test Case 579\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 579 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -579;
	} else {
		printf("Test Case 579 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFB7C9D35697CB5F5ULL,
		0xF319AEB37B7AAD7DULL,
		0x9D1DCE91623040C6ULL,
		0xADEDB8445622D25DULL,
		0x1E45FBEAF77FF9DDULL,
		0xD0641C42E5179DF5ULL,
		0x4B15C09BB450B681ULL,
		0x9646137FE1A27AC5ULL
	}};
	printf("Test Case 580\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 580 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -580;
	} else {
		printf("Test Case 580 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDE6DEB89B98C6010ULL,
		0xCB2D05B55C656E85ULL,
		0x0D53FBF33EC17AA8ULL,
		0x996BE02859F1294FULL,
		0x8CF9AAF81AEE3121ULL,
		0x888E1B5D9F74D498ULL,
		0x3DD73DD4864AF979ULL,
		0x47C4882AD4BF924BULL
	}};
	printf("Test Case 581\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 581 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -581;
	} else {
		printf("Test Case 581 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0282A8C6C5EBD515ULL,
		0xCA795A2EAB964443ULL,
		0x32FD9C39A31872A0ULL,
		0xE6DB4DC86CC5F494ULL,
		0x9AF9F6B0CC919CC4ULL,
		0xBE3E9EA95AA14E5AULL,
		0x4D292E7650F961C2ULL,
		0x8A2C69A94ECF0FADULL
	}};
	printf("Test Case 582\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 582 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -582;
	} else {
		printf("Test Case 582 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x4030889596DD986FULL,
		0x272AA658FF0A159FULL,
		0x9D2533B0722E9A21ULL,
		0x74D035A0F4EBA35AULL,
		0x74FDE4A98B5FB44AULL,
		0xA00AFA6483FF500DULL,
		0x7197ADC27D553F72ULL,
		0x1DDBAFFACFC66FB5ULL
	}};
	printf("Test Case 583\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 583 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -583;
	} else {
		printf("Test Case 583 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x50ECDA2A0617A906ULL,
		0x524F943E71F64621ULL,
		0x863BC642745E3217ULL,
		0x60CCC64BCF160BADULL,
		0xA79CF068C4477F32ULL,
		0x809384581DDAB732ULL,
		0xE76F3D9D794C471CULL,
		0xAD1E555915909F46ULL
	}};
	printf("Test Case 584\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 584 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -584;
	} else {
		printf("Test Case 584 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAEE15DD4B25A331CULL,
		0x9F3EA75D5F11FC33ULL,
		0x23DD5E455F064A04ULL,
		0x9C01B8529186DC73ULL,
		0xA60A66FDE5A14D03ULL,
		0xC40DE3BAD75667E6ULL,
		0xB2757FBF581FCFC4ULL,
		0x43A1DB436462A6C3ULL
	}};
	printf("Test Case 585\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 585 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -585;
	} else {
		printf("Test Case 585 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBBDCBDE5F588317DULL,
		0xEDA7DD14248B3013ULL,
		0xD2140FD90CADF182ULL,
		0x96CC566BF3D63059ULL,
		0xE58DCB7AC4E6F58BULL,
		0x2B31E00EF500A2F3ULL,
		0x5EA7AB30468CC1A3ULL,
		0xB3FA11B09AA79B06ULL
	}};
	printf("Test Case 586\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 586 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -586;
	} else {
		printf("Test Case 586 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6249F974D1F6327EULL,
		0xFA63EFBF7DB8D2D1ULL,
		0xF28AA300DEA53B1AULL,
		0xC69126237C50AE26ULL,
		0xC02C670840569BD4ULL,
		0x78DED603C1EE81B7ULL,
		0x86707A6507B86CA5ULL,
		0x4BBA6823D9410EBBULL
	}};
	printf("Test Case 587\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 587 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -587;
	} else {
		printf("Test Case 587 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2F07CBFC315EFC22ULL,
		0xB944AA39C208B0A8ULL,
		0x93B3E391ACA9488FULL,
		0x55A8052E358044EFULL,
		0x39396D81C1393B04ULL,
		0x5CCAA02649A4C695ULL,
		0xE1ED4D63DD838F52ULL,
		0x5411984D72B40DD1ULL
	}};
	printf("Test Case 588\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 588 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -588;
	} else {
		printf("Test Case 588 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0AC3D6DA09F5A428ULL,
		0xEB7DCB8681E35176ULL,
		0xB7858835BE01D224ULL,
		0x23D5FD18E1993D24ULL,
		0x880736BCEB865D84ULL,
		0xAC390E7911B45B7AULL,
		0x1DFEC9289D6D8EA2ULL,
		0xB91147A7B1346E8DULL
	}};
	printf("Test Case 589\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 589 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -589;
	} else {
		printf("Test Case 589 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC71E45841A9C0F04ULL,
		0x2E7686FBE2DE6CEBULL,
		0x52BDCDB02CFDA3B1ULL,
		0xF693AC90D6407F61ULL,
		0x82C280314ABC6ABAULL,
		0x6C8E5E5A5A468B4CULL,
		0x14F9E77A6918F987ULL,
		0x2393BB2F32CD0832ULL
	}};
	printf("Test Case 590\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 590 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -590;
	} else {
		printf("Test Case 590 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xEB91467C69A104ABULL,
		0xC2B2648CFDBCE11AULL,
		0x342D2F0B7EB7DE45ULL,
		0x031EDF99AECB8F18ULL,
		0xBC09BB0BB31A0CBDULL,
		0x412268CAFF6A4B1DULL,
		0x2A78B3EF9679CCC6ULL,
		0x0A94AD793C8975B1ULL
	}};
	printf("Test Case 591\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 591 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -591;
	} else {
		printf("Test Case 591 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4FF6A3B70E67EE8CULL,
		0x82F3273F6C860E62ULL,
		0x8A96BA7EC89CE65BULL,
		0x5DB1E39995205451ULL,
		0xDE6E4D819A119F04ULL,
		0x173E23B618C0C8E4ULL,
		0xF8873B67F5DF934DULL,
		0x700EFD7C61298C26ULL
	}};
	printf("Test Case 592\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 592 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -592;
	} else {
		printf("Test Case 592 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2F67D30A31B2E673ULL,
		0x5EFFBF33B76D74AAULL,
		0xC003EC407786B4E5ULL,
		0x8AB9F42030197561ULL,
		0x5DCFCE1092823970ULL,
		0xE43B4E3B275B9B55ULL,
		0xB3A86E3122E5A17FULL,
		0x3ACF4DE2B430571CULL
	}};
	printf("Test Case 593\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 593 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -593;
	} else {
		printf("Test Case 593 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC345245DACD5F1F3ULL,
		0x5CF9507E655B577DULL,
		0x0925FA4E1354C1B0ULL,
		0xF3ED43B0ABB99E03ULL,
		0x9AFDBBF61961815BULL,
		0x831697B2494CBA10ULL,
		0x31BB2111FA478127ULL,
		0x8E798757925F656DULL
	}};
	printf("Test Case 594\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 594 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -594;
	} else {
		printf("Test Case 594 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC122BF812FE6899EULL,
		0x8C1E0C774D1F43C2ULL,
		0x2E215BC416373355ULL,
		0xE34094654FE01DA7ULL,
		0xB8D65F7A3A1EDB7FULL,
		0xA5B11A702B094035ULL,
		0xEBBE3441DE3FAF84ULL,
		0x19BEDB7436633160ULL
	}};
	printf("Test Case 595\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 595 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -595;
	} else {
		printf("Test Case 595 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x42DD5B5FA59B8772ULL,
		0xD2DDE60DCF6930E6ULL,
		0x1769344231D311B0ULL,
		0xF0150B25DFA768E2ULL,
		0x3A453FDC4A181412ULL,
		0x3F70A92C45AB819AULL,
		0x16C7E3A8E5A3A726ULL,
		0xC666D5DFD3FD2C78ULL
	}};
	printf("Test Case 596\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 596 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -596;
	} else {
		printf("Test Case 596 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9FD0D1F37C43FB64ULL,
		0x13F02F34FEC6F454ULL,
		0xC3C1082E8C1335D3ULL,
		0xF6FBF9BEBA5D8807ULL,
		0xA5298AF076A099C7ULL,
		0xF4D5D9F25AC05B2AULL,
		0xA8176C74DAAC9E68ULL,
		0xEFA016652FE0D2F7ULL
	}};
	printf("Test Case 597\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 597 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -597;
	} else {
		printf("Test Case 597 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBFCACAA53A8109A1ULL,
		0x8FC0D7E1F740ADD8ULL,
		0xE411E5E8688FEA32ULL,
		0x03082B1E6FBD91A9ULL,
		0x24F89BABEB348488ULL,
		0x47FC82F3F3714DF5ULL,
		0x8DC056911D70361BULL,
		0x600B3C9EC7192698ULL
	}};
	printf("Test Case 598\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 598 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -598;
	} else {
		printf("Test Case 598 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7671A9E2A09C2577ULL,
		0xF1B7A05814E95457ULL,
		0x9D57AFF590077225ULL,
		0x1DB2E3144141E802ULL,
		0xA2F583C3384B4BBFULL,
		0x8954D08E22EADE54ULL,
		0x2E03585F7FB31558ULL,
		0x93C5AC3B7813E589ULL
	}};
	printf("Test Case 599\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 599 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -599;
	} else {
		printf("Test Case 599 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x68C63456E8A12E78ULL,
		0x8D03C61AD2266CA1ULL,
		0xDC58DEE2F8BD4303ULL,
		0xA74613C23FCBFC3BULL,
		0x698FC3B6B72F139DULL,
		0x7B8FDC54DFCCF4D5ULL,
		0xAC138BE79BAEB19CULL,
		0x8BEFA424644B3AB1ULL
	}};
	printf("Test Case 600\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 600 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -600;
	} else {
		printf("Test Case 600 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x70407052F7523FA1ULL,
		0xBC94BEAE8FFDCA4FULL,
		0x1B9C8CCCCA17E578ULL,
		0x0713483BDA8A511BULL,
		0x8BCDED6BBF4B06DCULL,
		0xA02CED98E764C388ULL,
		0x2410EE6CE78165F9ULL,
		0xF38A3432ED4A067EULL
	}};
	printf("Test Case 601\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 601 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -601;
	} else {
		printf("Test Case 601 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x46AB26F0F63BFB7BULL,
		0x378771DB8DBEBF30ULL,
		0xF66F4AD8DF45BDD8ULL,
		0x7C03C8A06347A9AEULL,
		0x238F5A0370F29C4AULL,
		0x8B38D35F096277BAULL,
		0x99E906D0B8A61C1BULL,
		0x30AEFF4A9C352975ULL
	}};
	printf("Test Case 602\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 602 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -602;
	} else {
		printf("Test Case 602 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2FA7CDEC10ACFC7AULL,
		0x54A4AD6ED670E108ULL,
		0xEA8B2BA24576FAE1ULL,
		0xFA0EECB807F00DD9ULL,
		0x0A733F0C074367ECULL,
		0x69A7B543F6AA2CA0ULL,
		0xBCB6CB783FAC38B7ULL,
		0xD4622001F4EF87FBULL
	}};
	printf("Test Case 603\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 603 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -603;
	} else {
		printf("Test Case 603 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0FA91599D24CC659ULL,
		0xD8F43CA27DE0D623ULL,
		0xFB2743C3167227C2ULL,
		0x065D9310D252A903ULL,
		0x37BBA3D65AC8F7F3ULL,
		0xFB90795AFDA6C1A9ULL,
		0x4DA138E83096582AULL,
		0xF8E7503F097961BCULL
	}};
	printf("Test Case 604\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 604 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -604;
	} else {
		printf("Test Case 604 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x44190BCB058AFE78ULL,
		0x30F6B21D0B22FE52ULL,
		0x10C25F54BFEEDAB7ULL,
		0x72B690F113C5CB59ULL,
		0xB84A9F7BA655EB2FULL,
		0x7DC0348D48480AA1ULL,
		0xF60760A5674D6284ULL,
		0x785F889CCB99A7ADULL
	}};
	printf("Test Case 605\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 605 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -605;
	} else {
		printf("Test Case 605 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA7F55AC4F0B45B82ULL,
		0xB995132B05A55E9CULL,
		0xF1A29D968B1F8AD5ULL,
		0xF025FE2A14BEE68FULL,
		0xC211D6C1DA3934F1ULL,
		0x07BC9E1FA8A21CB5ULL,
		0xE9A94C0E7A79DD1EULL,
		0xCBDC02FC5595EC4FULL
	}};
	printf("Test Case 606\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 606 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -606;
	} else {
		printf("Test Case 606 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8143956A4018A30FULL,
		0xC1357DAFCB20E37EULL,
		0x36680EEDC8AD8F37ULL,
		0x21621AC531575336ULL,
		0xAF07759AD08E6496ULL,
		0x1CDA54782BBA20B8ULL,
		0xC11B1A8AE2DCD34CULL,
		0x449BA38EDAD4BAE5ULL
	}};
	printf("Test Case 607\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 607 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -607;
	} else {
		printf("Test Case 607 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x868A960E8AAE7354ULL,
		0x1B7E9DC126A60261ULL,
		0x76FB8202A65AE1F4ULL,
		0xB51F0E90C6300A5AULL,
		0xC49813FAB2674A3EULL,
		0x435B66386C951612ULL,
		0xE55CB9CBFA6A8D6FULL,
		0x49B596B0D8AC644EULL
	}};
	printf("Test Case 608\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 608 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -608;
	} else {
		printf("Test Case 608 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x24C432573810BC88ULL,
		0xB4CB0FAB29453632ULL,
		0xD6F48FB635DDE0B8ULL,
		0x369D456DD03E2DFEULL,
		0xF5F0BCA2CFD23456ULL,
		0xCDCA2D5868C929F7ULL,
		0x79110023461EAB83ULL,
		0x486229881A0B4F50ULL
	}};
	printf("Test Case 609\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 609 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -609;
	} else {
		printf("Test Case 609 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x64713EC706A95913ULL,
		0x1DCFE99D11F091FDULL,
		0x5015533B15890956ULL,
		0xDAE1143898894A88ULL,
		0xEC56FEB018EC0D28ULL,
		0xE014E0501CD18B5EULL,
		0xB6E989CA430CB135ULL,
		0x7A03803825EB5059ULL
	}};
	printf("Test Case 610\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 610 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -610;
	} else {
		printf("Test Case 610 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEEDF5E08F41219F9ULL,
		0x076AD4910CEBB3E6ULL,
		0x1BD78A06B72A2984ULL,
		0xA0411BDA5F59EC21ULL,
		0x2306BF0201DFE0B8ULL,
		0xD2133A0A0A2421F4ULL,
		0x2061B9FD4193854EULL,
		0xCC85F483F7DD1F39ULL
	}};
	printf("Test Case 611\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 611 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -611;
	} else {
		printf("Test Case 611 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC7E07EB8AB313B86ULL,
		0x491DD74D1E0214BCULL,
		0x3C69A6F9159EF3A2ULL,
		0x85FFDFA21F8D4890ULL,
		0x4763A01751303AAEULL,
		0xD6E81BD884BAE7D3ULL,
		0xC6CFB79A8F2B72FCULL,
		0x3E15A4921D04E818ULL
	}};
	printf("Test Case 612\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 612 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -612;
	} else {
		printf("Test Case 612 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1968B1E9085FE6DDULL,
		0xFC8701D4AF15CD38ULL,
		0x2E9076005AA298EDULL,
		0xC99395CEF24DE62AULL,
		0x754B94CE5F95DD0BULL,
		0x0DB8D9060E20E782ULL,
		0x21C2C7CE83686E7EULL,
		0x900706EF8CC7586FULL
	}};
	printf("Test Case 613\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 613 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -613;
	} else {
		printf("Test Case 613 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3960D64F27944AAAULL,
		0x7BF6D2BFBF4F8FBFULL,
		0x6DF756016AA9C5D8ULL,
		0x934B7B06C214114FULL,
		0x9EE8EDAF176B5B7CULL,
		0xD0D30565E0AF8B53ULL,
		0x1144B3FA2873FAF8ULL,
		0xC6A54902175AD735ULL
	}};
	printf("Test Case 614\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 614 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -614;
	} else {
		printf("Test Case 614 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x27FF0A0C196D89E0ULL,
		0x50F62C18204A7131ULL,
		0x50598FCD7BAEF068ULL,
		0x04DA98190F9E4F50ULL,
		0x01272766145C6243ULL,
		0x583E4FDEDD8F2AB7ULL,
		0x5F20DF927AB34353ULL,
		0x5AFDC8F9180A5CDEULL
	}};
	printf("Test Case 615\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 615 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -615;
	} else {
		printf("Test Case 615 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x27DD0B02286402BFULL,
		0x8F268C3B6FB376C3ULL,
		0x6365555D2C01B5ECULL,
		0x9A0CBEC9093BFD5EULL,
		0x0637B34C335BD317ULL,
		0x7F4D8F76FD886E85ULL,
		0xFB5AF76E84E4E091ULL,
		0xD5F668FECA6BF39FULL
	}};
	printf("Test Case 616\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 616 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -616;
	} else {
		printf("Test Case 616 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x79680540548B2B93ULL,
		0xBCE8D69F42193DE9ULL,
		0x855FE1C6D2B4AE3FULL,
		0x28ADB078EB5C138DULL,
		0x6FCFFF4E7AFA2725ULL,
		0x0A066F897EF9A54BULL,
		0xF330B49BC9EA63D6ULL,
		0xA03341BB5AEB3CF2ULL
	}};
	printf("Test Case 617\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 617 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -617;
	} else {
		printf("Test Case 617 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x455B7F5B4EE0FF47ULL,
		0xF72D3154FFDC53E2ULL,
		0x4915B1CCA875C5B3ULL,
		0xC33E024416DE9DF9ULL,
		0xE6715D0E9215C61BULL,
		0x5A74C1D7B729198DULL,
		0xA79E3B325E12EE25ULL,
		0x13EDBAE8D46A5579ULL
	}};
	printf("Test Case 618\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 618 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -618;
	} else {
		printf("Test Case 618 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA49B8E9CD04F36E6ULL,
		0x145F13E133C943C7ULL,
		0x0EAEC99BAAD8B110ULL,
		0xFD3EFDCB92753EE2ULL,
		0xC64DD52AA2116454ULL,
		0x5D7ADD6EB3455529ULL,
		0x7B202E6D81BD6DA9ULL,
		0xE1C558DF3612048EULL
	}};
	printf("Test Case 619\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 619 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -619;
	} else {
		printf("Test Case 619 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE213A148DF4F807EULL,
		0x385F427DBD8C7FD7ULL,
		0x2C9C72C2B88FA889ULL,
		0x689CCD78454306EEULL,
		0x7C25F44BE612F850ULL,
		0x83C6563B2B325C99ULL,
		0x635CA4F8EFC599EDULL,
		0xDD653F2ECD18B49BULL
	}};
	printf("Test Case 620\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 620 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -620;
	} else {
		printf("Test Case 620 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4ABDF556D59CDBF9ULL,
		0xB0507EE78B515FCEULL,
		0x87514EF0D96C6AA2ULL,
		0x1DF715910D1A3C52ULL,
		0x9361EB42C4F20E85ULL,
		0xC9D7A53ED19437EBULL,
		0x1F1AA61F1F035F4CULL,
		0x743B89501701EED6ULL
	}};
	printf("Test Case 621\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 621 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -621;
	} else {
		printf("Test Case 621 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x61C6B44F0F92B46DULL,
		0x9DF6C81EAED0AA55ULL,
		0x0779DD265234351DULL,
		0x5BEFC5DE50B66B30ULL,
		0x92239BA7485DC1A9ULL,
		0x579CCA93BBEB7D9EULL,
		0x41E5226CC59282ABULL,
		0x5F3CA5F2F9BA688FULL
	}};
	printf("Test Case 622\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 622 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -622;
	} else {
		printf("Test Case 622 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xADC84139B7933B79ULL,
		0x7CBDFA235E8C8F21ULL,
		0xB5D3C06ABECF437AULL,
		0xEBA38DBF499B43C3ULL,
		0x70ED99A11EF645F8ULL,
		0xA4A0A6A4B771AA28ULL,
		0xDDFC94626719DEF2ULL,
		0x4156105DBA05DF6DULL
	}};
	printf("Test Case 623\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 623 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -623;
	} else {
		printf("Test Case 623 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAE4B1F3211E76D61ULL,
		0xBD0EDD11ACB6A13DULL,
		0x3F5A379760FBB83CULL,
		0x4C8648A9443EB181ULL,
		0xB4E6444A39DF1336ULL,
		0x66AE7BD0B8FBE9A2ULL,
		0x4A2695CEEAA3CB55ULL,
		0x399F8C5EDD09974BULL
	}};
	printf("Test Case 624\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 624 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -624;
	} else {
		printf("Test Case 624 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9E388E75A6F4558DULL,
		0xBC5CFAFE66EA9C35ULL,
		0x882C68C81C45FF49ULL,
		0x809D6AB0BE20B72FULL,
		0x280027A78DAAA79CULL,
		0xF7A1B5273493FB0FULL,
		0x842B40292B4CB255ULL,
		0x78B8A8C5FB257F60ULL
	}};
	printf("Test Case 625\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 625 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -625;
	} else {
		printf("Test Case 625 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x11C1D8E8650C21D5ULL,
		0x2E92453E155543A4ULL,
		0xA4D9FB5A4D7F7B4EULL,
		0x9D37C42898342904ULL,
		0x1FE3616D53A82301ULL,
		0x64AE71ACBF27B80EULL,
		0xE8787856BE65EFEAULL,
		0x962131C4C911E549ULL
	}};
	printf("Test Case 626\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 626 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -626;
	} else {
		printf("Test Case 626 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBD688896BF76B1E3ULL,
		0xF23220D4060825E8ULL,
		0xEB316C7F9383D8E4ULL,
		0xEEEBB5935E523043ULL,
		0x260D510DD175A9DEULL,
		0x0425CE37A7C44598ULL,
		0x597FA7EB553EB716ULL,
		0x90A78CE78F824F6CULL
	}};
	printf("Test Case 627\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 627 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -627;
	} else {
		printf("Test Case 627 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1D70504C17C4EDB3ULL,
		0x959FF1FA0795AFE7ULL,
		0x61CB6A3F6B20B07CULL,
		0xD67475542092B299ULL,
		0xFE815421FB59F4B4ULL,
		0x3ED3D9AE5D9D7281ULL,
		0x0B8A75B3A26F652CULL,
		0x2BC0634C15B60D44ULL
	}};
	printf("Test Case 628\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 628 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -628;
	} else {
		printf("Test Case 628 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x92371C09599C7E64ULL,
		0x3ADFA182AB754D45ULL,
		0x965C658C7DC695CDULL,
		0x40F7E7F48D1A9EF9ULL,
		0x0B3A55D7E32F2659ULL,
		0x46C05744F6862F3BULL,
		0x395E44CA33FD1EBBULL,
		0x6F9E0CF07E37CF79ULL
	}};
	printf("Test Case 629\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 629 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -629;
	} else {
		printf("Test Case 629 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x7EFB171862C64AA7ULL,
		0x872864D1EF34C79BULL,
		0xB106BBBB76C38E45ULL,
		0xC8CF756B0FC14364ULL,
		0xD8E037C206CE733AULL,
		0xD859497B317788D6ULL,
		0x562528AE58A25158ULL,
		0x13E783D2C918800DULL
	}};
	printf("Test Case 630\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 630 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -630;
	} else {
		printf("Test Case 630 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2D67657474D64961ULL,
		0x6CF052B38EF06877ULL,
		0x8F12872E9B72B022ULL,
		0x60AE3E79D0252A96ULL,
		0x46A4BFD0A5BED073ULL,
		0x5FFBF5F85F3157AAULL,
		0x05446892FE45080FULL,
		0xCBDC3394BE739AA2ULL
	}};
	printf("Test Case 631\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 631 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -631;
	} else {
		printf("Test Case 631 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x13CC2B0AB85D5EE9ULL,
		0x631F34F3FA407728ULL,
		0x5493BC42807F657BULL,
		0x18829366CDA72078ULL,
		0xFF2CBB4D738FFE52ULL,
		0x59A384DCF7310CD4ULL,
		0x0EB0DBAA72D94D89ULL,
		0x28A4FA222A9F0805ULL
	}};
	printf("Test Case 632\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 632 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -632;
	} else {
		printf("Test Case 632 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x5C922DDB440DA890ULL,
		0x76C404B6291692BFULL,
		0xB514A1467E6A65E3ULL,
		0x52102C63B2742047ULL,
		0x5E36BC5AC07D9182ULL,
		0x4F7A381C65DF28C1ULL,
		0xC08695A47C4710D7ULL,
		0x09BF375AA3D1F5A9ULL
	}};
	printf("Test Case 633\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 633 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -633;
	} else {
		printf("Test Case 633 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x512CB4439DA4D521ULL,
		0xBA7FE3173BDBF0A9ULL,
		0xFAB489BFEA1A1A6CULL,
		0xB79368FBC4F0264CULL,
		0xA52F5307523E240DULL,
		0xC8FF1F2E97412E01ULL,
		0x4C2232681C09C297ULL,
		0xCA3097D3BCFF53B8ULL
	}};
	printf("Test Case 634\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 634 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -634;
	} else {
		printf("Test Case 634 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x673687C74187A4F3ULL,
		0x9C59E323604FD5B9ULL,
		0x5348A68DAA3531B8ULL,
		0xD6CA9A4825528837ULL,
		0x09C41C54E86ABCD8ULL,
		0xC25704C2425B6D02ULL,
		0xFC01B10D56A60D7FULL,
		0x5B08743D118225C1ULL
	}};
	printf("Test Case 635\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 635 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -635;
	} else {
		printf("Test Case 635 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x96F1F218DE93CCBEULL,
		0xD5761C7F236E2C28ULL,
		0xFEEA4913BAC6FE29ULL,
		0x5882990EDAACEE81ULL,
		0xB127C450D02E80E7ULL,
		0x49D65023CA43D75FULL,
		0x70EF97516133ED52ULL,
		0x025D85D122F85505ULL
	}};
	printf("Test Case 636\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 636 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -636;
	} else {
		printf("Test Case 636 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAFADE0477EED2AC5ULL,
		0xA6EF362750F0F849ULL,
		0x99AEBF03D7CB88CFULL,
		0x4D6611F2490E97A1ULL,
		0x9923A739DB3D4292ULL,
		0xE61F12A146EB7B22ULL,
		0x7BB047373CA23D4BULL,
		0x61C658A4F38FD168ULL
	}};
	printf("Test Case 637\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 637 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -637;
	} else {
		printf("Test Case 637 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5F7037C68B369326ULL,
		0x8C75E817BB32CD9EULL,
		0xCD6851E3DCED3A82ULL,
		0x73F08221A66BB5F4ULL,
		0x4E82E1D91F47B7AFULL,
		0x93B191F7E6E7DAD5ULL,
		0x10FEAA6C0E1A96DAULL,
		0x52FF7B6A5C8154F7ULL
	}};
	printf("Test Case 638\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 638 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -638;
	} else {
		printf("Test Case 638 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5B1747911201787DULL,
		0x1F2E59244CE2372CULL,
		0xF600C4E2BD845A29ULL,
		0xBB8A895849B62B04ULL,
		0x4A20777528EB2C1AULL,
		0x131F63037E87B9ADULL,
		0x54C9EF41A8C1CF26ULL,
		0x8878A6E2000C8B2AULL
	}};
	printf("Test Case 639\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 639 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -639;
	} else {
		printf("Test Case 639 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF84A322A795959D4ULL,
		0x6E92958C14B2BBC2ULL,
		0x93A41D84DD758610ULL,
		0xAC1996107B737C30ULL,
		0xD137A7656AA69E40ULL,
		0x706EA1BC6C75DE71ULL,
		0x7301DC91FAD37395ULL,
		0x8BED1CB240D548DAULL
	}};
	printf("Test Case 640\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 640 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -640;
	} else {
		printf("Test Case 640 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0031ACEE68E1975DULL,
		0xFB7990EDA8A359B0ULL,
		0xC156B14067977548ULL,
		0x0D807796522C5E4AULL,
		0x6E0B7E244BC1007AULL,
		0x46E299A2416BA2FBULL,
		0xDA4F148F2781E9BBULL,
		0x4F46F9E011451FD6ULL
	}};
	printf("Test Case 641\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 641 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -641;
	} else {
		printf("Test Case 641 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x70B73FEBE5929FDBULL,
		0xB26F094E3C86CA0CULL,
		0x29E15E614CBD8CBFULL,
		0x9B8BE70146E355B1ULL,
		0x3A07FC3937D35038ULL,
		0x428A946E73DA1663ULL,
		0x1DEF5AB4CDE0CADAULL,
		0x1B0102922576B18BULL
	}};
	printf("Test Case 642\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 642 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -642;
	} else {
		printf("Test Case 642 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBFB7E2E0BA953B44ULL,
		0x7FFFA61AC4DD5804ULL,
		0xA7934577EEE12870ULL,
		0xB682A7FCC6278376ULL,
		0xB143DE8FBDB86120ULL,
		0x9732E5D026CD656CULL,
		0xC652EA7F50D8B6EFULL,
		0xB551D154F268CCEDULL
	}};
	printf("Test Case 643\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 643 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -643;
	} else {
		printf("Test Case 643 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xB760A7E17DE61C8BULL,
		0xA31F843E6B4F5AD4ULL,
		0x2F43AD1B5F016BD4ULL,
		0xB5A573410F4BC0AEULL,
		0x2E834BAD5E93A0AAULL,
		0xEDB854C556081A64ULL,
		0x8754CA7269E72958ULL,
		0x0E813EC71A216729ULL
	}};
	printf("Test Case 644\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 644 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -644;
	} else {
		printf("Test Case 644 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x5B6A8362EFDBD30DULL,
		0xC720605C92F1B9F9ULL,
		0xD7B0B2BEDEFCA1A4ULL,
		0x43A4EFA1F91D6B50ULL,
		0x5DD917E780A493E8ULL,
		0x6A82627C5F660273ULL,
		0xB21E0DBD20610453ULL,
		0x0DEED868E24DE250ULL
	}};
	printf("Test Case 645\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 645 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -645;
	} else {
		printf("Test Case 645 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x473974E2C0961AB2ULL,
		0x49B32C554524CE5BULL,
		0x70BE57AF72A54F2BULL,
		0xA9854A1F8C9CD654ULL,
		0xE32AFE39DAD6043EULL,
		0xB1B7E7E1C5A10940ULL,
		0xC475522D8D1A03A6ULL,
		0x9B7B02DE1AE1B011ULL
	}};
	printf("Test Case 646\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 646 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -646;
	} else {
		printf("Test Case 646 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x007E775988F31DA5ULL,
		0x5AD2D39696FCDDBBULL,
		0x3F79FF4FFDEF7213ULL,
		0xC23F252C59AECB47ULL,
		0xA461CE99B8F25318ULL,
		0xE35A48B8205CB207ULL,
		0x681FEE8AE885F4B8ULL,
		0x41C9B2BB71A5E085ULL
	}};
	printf("Test Case 647\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 647 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -647;
	} else {
		printf("Test Case 647 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9DBE898A66AFF81DULL,
		0xF019696924E17C48ULL,
		0x51F56FD35BB31E68ULL,
		0x2F0B40796E5B42FBULL,
		0xAE2A21116F1199B9ULL,
		0x0305B908C3BC7265ULL,
		0xF3A2E75090FCE880ULL,
		0x21F4B8BDBBE7AF69ULL
	}};
	printf("Test Case 648\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 648 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -648;
	} else {
		printf("Test Case 648 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEC98986827E93AFEULL,
		0xB2D3C675AF8B9503ULL,
		0xE4696A657B696ECFULL,
		0x2882A5157D196A33ULL,
		0xB55872806C65579DULL,
		0x00267EF93AEFF82BULL,
		0x4DF37FF0BA0B2BD6ULL,
		0xB90239A869C0CD7BULL
	}};
	printf("Test Case 649\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 649 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -649;
	} else {
		printf("Test Case 649 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5062D8D70F0CA798ULL,
		0xCEC7DB0CB55555CFULL,
		0x3D958BAD53D419E8ULL,
		0x526FF0EDA226E8CEULL,
		0x413C71D258A96BA2ULL,
		0xD50703B8257020B5ULL,
		0xB7DC68DFFF818302ULL,
		0xDFEB1AC1364311DEULL
	}};
	printf("Test Case 650\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 650 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -650;
	} else {
		printf("Test Case 650 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCA7C2BBA3A0DF249ULL,
		0xF5BB623290AB0369ULL,
		0x61702F50D0DB73ABULL,
		0x682988C63387F953ULL,
		0xC4C6CAEDA741ECD6ULL,
		0x2C759A5B735811CCULL,
		0xFB4757A52AFC609AULL,
		0x2E4DFB159762BEB5ULL
	}};
	printf("Test Case 651\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 651 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -651;
	} else {
		printf("Test Case 651 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x24100AB125DF92FCULL,
		0xEFD4FC7C37BD1A49ULL,
		0x1702078EA5135E8CULL,
		0xF86CEF5569F3BF6AULL,
		0xB803C0EB69CD0C4DULL,
		0x7547763495891BC2ULL,
		0x85532A1714332863ULL,
		0x9B0636B373DCD452ULL
	}};
	printf("Test Case 652\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 652 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -652;
	} else {
		printf("Test Case 652 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6D1044EC37B63F3CULL,
		0xA4B433A0A3FE318BULL,
		0x270F98FB807B8AF4ULL,
		0x1B4D2001D7B364A0ULL,
		0xD9458A8446C47DD0ULL,
		0x285BED446777528FULL,
		0x916526AD5455B6B4ULL,
		0x47397FC547A817F2ULL
	}};
	printf("Test Case 653\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 653 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -653;
	} else {
		printf("Test Case 653 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x457C1B6E924DD690ULL,
		0x34CBE87806076566ULL,
		0xEF157BF9FE28AA9FULL,
		0x08D1009AE0934612ULL,
		0xEF03A2C6877137AFULL,
		0x879F8378942735FEULL,
		0x2AD7D7B7DA46005DULL,
		0xD605803AD563765CULL
	}};
	printf("Test Case 654\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 654 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -654;
	} else {
		printf("Test Case 654 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x09C785C99555AC77ULL,
		0x2EF260AF38A01B18ULL,
		0x6D1F061E7F37A1A4ULL,
		0xC3A0E3E5858206BFULL,
		0x82991B5495CD6D46ULL,
		0x3FB315B2CBB05241ULL,
		0xC2F703DEDBB78EDEULL,
		0xEEFD9DB55AE3F0A3ULL
	}};
	printf("Test Case 655\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 655 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -655;
	} else {
		printf("Test Case 655 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD412C1F490B54F3CULL,
		0x5C9ED851EE29E429ULL,
		0xB866AB195D1B05C1ULL,
		0x5F26D054E447F52DULL,
		0x38988A15FA0440CFULL,
		0x608F04399985444FULL,
		0x4C259CB80CE0806BULL,
		0x7AC78CAC85F389E2ULL
	}};
	printf("Test Case 656\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 656 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -656;
	} else {
		printf("Test Case 656 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2C0075D54B5E0C17ULL,
		0x2F7355234B6F404FULL,
		0x12593002E73D6546ULL,
		0x533106824688B1C2ULL,
		0xE37DF48ACEC7C9EBULL,
		0x01BCAFF84B5776E5ULL,
		0xCC3857207929F0BFULL,
		0x89CDC9D93E25E115ULL
	}};
	printf("Test Case 657\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 657 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -657;
	} else {
		printf("Test Case 657 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF21CD363115CB5A8ULL,
		0xB546DFB9728B5659ULL,
		0xC3B5155C1C1E316FULL,
		0x4127FE35649E20D5ULL,
		0x1B58D01FACEEA6A5ULL,
		0x70267C645CAE201BULL,
		0x975CBB7D0F3A52D1ULL,
		0xD65E4169473BE7B2ULL
	}};
	printf("Test Case 658\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 658 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -658;
	} else {
		printf("Test Case 658 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x7B5DAF654CCE4572ULL,
		0x59DBC0111B74850FULL,
		0x17A57EF311802123ULL,
		0xBDEF79C373948657ULL,
		0x0A969C912347FFEBULL,
		0x17F4B77BD0AFC086ULL,
		0x40EF133F4993B06BULL,
		0x03E05E7C66F00DD2ULL
	}};
	printf("Test Case 659\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 659 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -659;
	} else {
		printf("Test Case 659 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8BB30222F15CB2D1ULL,
		0x711604EEB12D17A8ULL,
		0x52B9447FAF82B05EULL,
		0x3E720F820FF18DB3ULL,
		0xEAB07AD1B1D731F1ULL,
		0x53FCAB32F396E7FEULL,
		0x4BC94F98DD2BF515ULL,
		0x715B273244470532ULL
	}};
	printf("Test Case 660\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 660 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -660;
	} else {
		printf("Test Case 660 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1D1E7C17297932F1ULL,
		0xE442A70809F5FC45ULL,
		0x0320A202A1535827ULL,
		0x6D84D256D08471D1ULL,
		0x1055FCC21A934062ULL,
		0xE9F24F7FAF59D986ULL,
		0x12318DAC19865DAAULL,
		0xE6E1792F3A66DFE0ULL
	}};
	printf("Test Case 661\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 661 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -661;
	} else {
		printf("Test Case 661 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8AB9B283862E05AAULL,
		0xAE7A6C0C05AE1024ULL,
		0x22959C472DA81680ULL,
		0xD9412EB65BA238A5ULL,
		0xD9F6D1EAC9D7EF96ULL,
		0xEEA0174F4D487E2FULL,
		0x4028063F38E9306FULL,
		0x779921D509B16EE8ULL
	}};
	printf("Test Case 662\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 662 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -662;
	} else {
		printf("Test Case 662 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x918D31B26A3F7367ULL,
		0x33EB3A36E887E748ULL,
		0x69DA00191C385D69ULL,
		0xE58B62DE3732AAC9ULL,
		0x94E9D681E04BF65DULL,
		0xBEA9C690B7865A60ULL,
		0xE1C4EBEC4325A835ULL,
		0xA3671F9560C25ED5ULL
	}};
	printf("Test Case 663\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 663 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -663;
	} else {
		printf("Test Case 663 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC3EB31BF4A36A375ULL,
		0x00104C73E3A3C8FDULL,
		0x4191F824E4991501ULL,
		0x3543AAFFF069A165ULL,
		0x5B10D01FEC61358AULL,
		0xBBC3FBF28B63C640ULL,
		0xBED2EEC9457E7DDAULL,
		0x137081F53E137AC8ULL
	}};
	printf("Test Case 664\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 664 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -664;
	} else {
		printf("Test Case 664 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1B4270EF91AD7E46ULL,
		0x2EA3B2630E4C2D65ULL,
		0x3DA34FEFADBE1735ULL,
		0xCE673731721E1E60ULL,
		0x13DD6B66CEA367E7ULL,
		0x751704BAAE125982ULL,
		0xDE6E650E057D1EEEULL,
		0x62A03012AC642179ULL
	}};
	printf("Test Case 665\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 665 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -665;
	} else {
		printf("Test Case 665 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x912EB59382E26B2AULL,
		0x8D3A928E614527B2ULL,
		0xC0E6B4FD13F4A0D1ULL,
		0x6BE3E331B68CD037ULL,
		0x838C5EC8016F8FD2ULL,
		0x7D79B9457596B37DULL,
		0x9AE30F5EBD29747BULL,
		0x9BA36F262CCF85B1ULL
	}};
	printf("Test Case 666\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 666 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -666;
	} else {
		printf("Test Case 666 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC2E3FAD5916095DAULL,
		0x5F395D45135CFBABULL,
		0x13AF98C85C7CC0D1ULL,
		0x34AD5A70A929D5AAULL,
		0x228347D60BEAB30BULL,
		0x650C9E397B4702C7ULL,
		0xAE364C8B94930350ULL,
		0x66D9AED6FF035405ULL
	}};
	printf("Test Case 667\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 667 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -667;
	} else {
		printf("Test Case 667 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x283EDBDB06CDBE05ULL,
		0x57AE5AFFDA7E3707ULL,
		0x06DAA307CA1E3C7BULL,
		0x5D49298E9CB7BC8AULL,
		0x75B39BDEE79BE35FULL,
		0x3919555EF39C2033ULL,
		0x9E26374DE21B818EULL,
		0x906FEB15291A13DBULL
	}};
	printf("Test Case 668\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 668 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -668;
	} else {
		printf("Test Case 668 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCC11CEE26ECEBE2BULL,
		0xBE26E7585E4A312DULL,
		0x696D8A21D10751CDULL,
		0x9A7F74BBD89E7FD1ULL,
		0x636E28C868137B20ULL,
		0x850816CF3318CC74ULL,
		0x14DBD93745D0DDD5ULL,
		0x96DE77E784B89025ULL
	}};
	printf("Test Case 669\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 669 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -669;
	} else {
		printf("Test Case 669 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA1E1BB46E1504028ULL,
		0xD2D929586CFED832ULL,
		0x2DC38B15FAD475F9ULL,
		0x8AECDCFB6D05D39EULL,
		0xD58E40EC9A02C8FCULL,
		0x69539A5504B5E37AULL,
		0x43CE308B0E48E380ULL,
		0xC0AB3686F8315A67ULL
	}};
	printf("Test Case 670\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 670 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -670;
	} else {
		printf("Test Case 670 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF66A089126E5CDB4ULL,
		0x58672622BF58F398ULL,
		0x32BF66BA9B3D0060ULL,
		0x916685C8CDDB76AAULL,
		0xD41C49EB4401931EULL,
		0xD6E60ABC97E206A5ULL,
		0xB57F35F70DC977EDULL,
		0xDBFE954AB5190F5DULL
	}};
	printf("Test Case 671\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 671 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -671;
	} else {
		printf("Test Case 671 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xF170A23D4A09A35AULL,
		0x907841D47A634D38ULL,
		0x9A588BC968E4931CULL,
		0x6ABA6C0137B22FFEULL,
		0x7F84D348E0F6C8EEULL,
		0xC0A19E9CBFFF71ABULL,
		0x1FFE7E68869AE4EDULL,
		0x17D83DCD67F35B02ULL
	}};
	printf("Test Case 672\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 672 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -672;
	} else {
		printf("Test Case 672 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA6AEC071F5E2F3D6ULL,
		0xD6A49E54867406EEULL,
		0x799F1F446F6BB561ULL,
		0x9FF0EF37CB48F6B3ULL,
		0x93126FDEEE3639F8ULL,
		0x095E52E71B9177DDULL,
		0x52235FA68E07F505ULL,
		0xCA13BB0B6F065B61ULL
	}};
	printf("Test Case 673\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 673 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -673;
	} else {
		printf("Test Case 673 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x998A69104E018A48ULL,
		0xC6595FCA4FE18226ULL,
		0x597C15CDB5626179ULL,
		0xD167DC060632E713ULL,
		0xEBE4BA35FCDF9CFDULL,
		0x027324F30A8CAD56ULL,
		0x45FF92F49483831BULL,
		0x3003A21B7D0D8C31ULL
	}};
	printf("Test Case 674\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 674 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -674;
	} else {
		printf("Test Case 674 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2C8BC4F1B4B0F294ULL,
		0x60966CC6E1225F3DULL,
		0x0D464CB5474C8CDEULL,
		0xA14AEE1ED077715BULL,
		0x7AEB2D2484155383ULL,
		0xD3F7CD34BC2D07DEULL,
		0xCE5BA3DBD1C85190ULL,
		0x2C2A42B7ED2A0823ULL
	}};
	printf("Test Case 675\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 675 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -675;
	} else {
		printf("Test Case 675 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA9A6652364EC1CCDULL,
		0x6FE3594E28B6753DULL,
		0xA666D7EE975B7406ULL,
		0x68A45DE4F4B6A663ULL,
		0xDAE65CF13C27F25AULL,
		0xE9C1132BB8123FB8ULL,
		0x25CA0743B6C76742ULL,
		0x49BA2C0E3F69C35EULL
	}};
	printf("Test Case 676\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 676 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -676;
	} else {
		printf("Test Case 676 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x62DC511A4A4BC563ULL,
		0xE7679AAD14D99C00ULL,
		0xE1593288529AE922ULL,
		0x7FE9556B861C4D65ULL,
		0x1867DCE3A7A0A3B2ULL,
		0x88EBF3DB3BB83E56ULL,
		0x77BB9E4472FF59A4ULL,
		0x728DD228A3612348ULL
	}};
	printf("Test Case 677\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 677 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -677;
	} else {
		printf("Test Case 677 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x22A98C0C35DA2341ULL,
		0xE6ECE2E75D94C3D7ULL,
		0x26EA9D5BB70EDDFEULL,
		0x56FB77C05C9EB144ULL,
		0xC38B7F9B81BCA791ULL,
		0x2CEB67EAA5FA997AULL,
		0xAA5FE3DB8E85F1CAULL,
		0x8FBA8C2AF4E29744ULL
	}};
	printf("Test Case 678\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 678 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -678;
	} else {
		printf("Test Case 678 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA4993A9DD079FF7FULL,
		0x4D2EE08018041975ULL,
		0xA45C8F9733831F29ULL,
		0x466D77F5ED57CCDCULL,
		0x908A483AB198ED75ULL,
		0xEED77463589B059DULL,
		0x530BD3734AE67C09ULL,
		0xB0A95920DF6C5409ULL
	}};
	printf("Test Case 679\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 679 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -679;
	} else {
		printf("Test Case 679 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEB0638240D24BF2DULL,
		0x000521CCFEF53997ULL,
		0x38FED1B58230949EULL,
		0xF16C31B237086EB0ULL,
		0xE22EC146259D83B9ULL,
		0x7B5C80FA5E7CAEDBULL,
		0xDB5F54CC8CB91C42ULL,
		0x522D1125ACEB0130ULL
	}};
	printf("Test Case 680\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 680 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -680;
	} else {
		printf("Test Case 680 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7ABA4EB369DE06BBULL,
		0x45280B001DAE5C46ULL,
		0xF1AD4153171741E4ULL,
		0xC3A1ED893E2CFD31ULL,
		0x556BEAB0BABFB299ULL,
		0xEEC74B58F0EECD4FULL,
		0x93BC845BD5878530ULL,
		0xF4F9C9FA66C00863ULL
	}};
	printf("Test Case 681\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 681 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -681;
	} else {
		printf("Test Case 681 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x09BC64BAC446D1D1ULL,
		0xDE8571F3BFAD1D39ULL,
		0x2BA8CFCD4A96A4B1ULL,
		0x3006E1137CD7D546ULL,
		0x5EAE2FA3B131B71BULL,
		0x346447C5C5656A8BULL,
		0x8ACD7B9C2A48B915ULL,
		0x311CC836EC839E38ULL
	}};
	printf("Test Case 682\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 682 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -682;
	} else {
		printf("Test Case 682 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9B74BE83AF37871CULL,
		0x62CED368A8F9FA45ULL,
		0x4CC55C79A0E7C333ULL,
		0x95A7DAE2CB798852ULL,
		0x0AE1353D5532D139ULL,
		0xE570A9A8FA46C6E9ULL,
		0xD4380D2C5E9F1BA7ULL,
		0x24E32D24231BD838ULL
	}};
	printf("Test Case 683\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 683 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -683;
	} else {
		printf("Test Case 683 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8C6CF8BB9CFADDE3ULL,
		0x985231A52BFCC02CULL,
		0x99AAFF65A455AD02ULL,
		0xC98E708F3EA6E8AAULL,
		0xE646931BBD9CFE43ULL,
		0xA8FFA7EF3F02F8EEULL,
		0xE9C92584A6450003ULL,
		0x8E73064C73D540F4ULL
	}};
	printf("Test Case 684\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 684 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -684;
	} else {
		printf("Test Case 684 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD04AAE399943FDBEULL,
		0x0240D895AAEC9F4BULL,
		0xF6E532C76C976BEEULL,
		0x4621FBEBDCF0AAB8ULL,
		0x599E12E6C9F627D1ULL,
		0x2CAB740DAC360E5AULL,
		0x6D053E4125AD5D56ULL,
		0x611EB754FF44479DULL
	}};
	printf("Test Case 685\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 685 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -685;
	} else {
		printf("Test Case 685 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF254638CEE069C43ULL,
		0x5D645835AAF87653ULL,
		0x1B98A799CA4785B1ULL,
		0x9906D8F60687A67AULL,
		0x7DB26476CEE7F82FULL,
		0xED3DFDD966519BC5ULL,
		0x8226B9ABC312076BULL,
		0xE497B47C1DDABDAFULL
	}};
	printf("Test Case 686\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 686 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -686;
	} else {
		printf("Test Case 686 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2D087A4D3B3DEC23ULL,
		0x4D80788CEE020585ULL,
		0xA5450E9D8DA8CBAEULL,
		0xEB41BD5C1D4890FBULL,
		0xD661257584F3F4DBULL,
		0xF11F55ADD7E7A4DFULL,
		0x65F6CC8C8C4569D7ULL,
		0x5F65CC961EB43F7DULL
	}};
	printf("Test Case 687\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 687 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -687;
	} else {
		printf("Test Case 687 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x11DE56AEC30E7BCAULL,
		0x3DB00BEEC6E85D15ULL,
		0xFFFFBC9202F39BB1ULL,
		0x69EC04513FA75B6FULL,
		0xC4C108E78620AD38ULL,
		0x895F563793D2CFD3ULL,
		0x9D0C83F3EB21F80BULL,
		0x69E60FE6DDD5B5A7ULL
	}};
	printf("Test Case 688\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 688 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -688;
	} else {
		printf("Test Case 688 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC456EFE3B115D869ULL,
		0xD0DA5D098EF774B8ULL,
		0x934FC70C14C6EDCFULL,
		0xC3327305B0CB6223ULL,
		0xE0ED31C9C1ED0A11ULL,
		0xAE8FBFD49D656629ULL,
		0xF9C78903FF8AB3A1ULL,
		0x898C8964B843F8CDULL
	}};
	printf("Test Case 689\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 689 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -689;
	} else {
		printf("Test Case 689 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x79301B0D67E9392CULL,
		0x47AB27DB12F762E7ULL,
		0x602E240B1C80C7A5ULL,
		0xDE15101F3C716085ULL,
		0xF954E7164B1D3117ULL,
		0xDBC502B93F60047FULL,
		0xB187DC6207D28206ULL,
		0x45EAD68CE3A6C871ULL
	}};
	printf("Test Case 690\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 690 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -690;
	} else {
		printf("Test Case 690 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2D51F0CA83E76252ULL,
		0x85FDE823B4DFE59AULL,
		0x245AD262A494702FULL,
		0xCCAE9D798DB76C77ULL,
		0x53E2CF4A45152167ULL,
		0x0B6267F5D95E657DULL,
		0x524D49395D8BEDB0ULL,
		0x388846118EA4E6F1ULL
	}};
	printf("Test Case 691\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 691 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -691;
	} else {
		printf("Test Case 691 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x0E1959ACA119EC38ULL,
		0x4BA20463096B159EULL,
		0xCDDC1E635182145AULL,
		0x28F9213AEA364638ULL,
		0x05F356364A474D5AULL,
		0x7E01D4A7D8B52633ULL,
		0xC32287C00204F382ULL,
		0x0ECB08185135EF58ULL
	}};
	printf("Test Case 692\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 692 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -692;
	} else {
		printf("Test Case 692 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB4102CCB24683C47ULL,
		0xB3CF1D114CB8CB86ULL,
		0x0D0D7BE5C7068F64ULL,
		0x2A67AEA9CE376891ULL,
		0xFCA95D188AA1DC62ULL,
		0x9E02CCF59D6F95BAULL,
		0xEC2C1D7B6713DBDDULL,
		0x3226EE28BB99F72DULL
	}};
	printf("Test Case 693\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 693 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -693;
	} else {
		printf("Test Case 693 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x65383C04777475B0ULL,
		0xF70566D17289EDA8ULL,
		0x0FD943F3B217D48CULL,
		0xB046C410A86BD658ULL,
		0x5DE94D1EC8C40CC2ULL,
		0x02B07AAB98E56636ULL,
		0xBCE941B3B68D351FULL,
		0xBEEDC11FA8DDB2D6ULL
	}};
	printf("Test Case 694\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 694 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -694;
	} else {
		printf("Test Case 694 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x063259DE4D45E27BULL,
		0x57B281A37C02F5DCULL,
		0xEA3A8ABDEDB6BCB9ULL,
		0x43D1AF3B482E2ECFULL,
		0xE8BF7002D10AF2EAULL,
		0x82B389F30ABF800AULL,
		0x4257C5673DE0AE43ULL,
		0x82057AF947198D61ULL
	}};
	printf("Test Case 695\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 695 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -695;
	} else {
		printf("Test Case 695 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x94DAB8AF3E1C5050ULL,
		0x087D9992FDB77916ULL,
		0x18C17CD28EA5FA36ULL,
		0x2C0B54BBBC5CF1E2ULL,
		0x6E7FBABD2CA6C82DULL,
		0x7025B82DB60007D0ULL,
		0x15708CC065EB1AE5ULL,
		0x783C7DFEF7573F15ULL
	}};
	printf("Test Case 696\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 696 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -696;
	} else {
		printf("Test Case 696 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x25A7C08513C0532DULL,
		0xA7B08609FB3FBBCAULL,
		0x6E48AB90C38A7624ULL,
		0xA9D037782975FEF1ULL,
		0xC8A2DF3CE2E6D99CULL,
		0x1BF55A8E45AA32DEULL,
		0xCC662D5FB88AAB3BULL,
		0x35701A3C9AB2B1A7ULL
	}};
	printf("Test Case 697\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 697 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -697;
	} else {
		printf("Test Case 697 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x85F5C4EA04CA8D49ULL,
		0x8AF56F48C2E7C656ULL,
		0xC0689B10C077C7F9ULL,
		0xE195DE26D609A56FULL,
		0x9C60330D60D9566AULL,
		0x6E3BEF24CD250966ULL,
		0x6BA42B390F2FBC8AULL,
		0x2627939184BB77F5ULL
	}};
	printf("Test Case 698\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 698 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -698;
	} else {
		printf("Test Case 698 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA7B66594C7765A85ULL,
		0x3C5DF4A6DD8DC36FULL,
		0xCFF8A5A073223ACBULL,
		0x6C505154702B14C9ULL,
		0xD4DDA1FE6427DE40ULL,
		0x0419150CCADCD672ULL,
		0xDBC5B1771228F63EULL,
		0xBF7AEE746785A274ULL
	}};
	printf("Test Case 699\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 699 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -699;
	} else {
		printf("Test Case 699 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x748096706F838201ULL,
		0x7C6B3C210399E4F9ULL,
		0xD501E21C9C0BCCB7ULL,
		0x7178ECD49BC960C5ULL,
		0x2D8094DAC3ED782FULL,
		0xD741562A833F8439ULL,
		0x15C693DC2D1F2984ULL,
		0xF702E57632AFBAFFULL
	}};
	printf("Test Case 700\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 700 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -700;
	} else {
		printf("Test Case 700 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x894B34A53AD4A388ULL,
		0xD39BA07F034ECAC3ULL,
		0x874039B3DF856156ULL,
		0xD5916B9152C41FE7ULL,
		0xA77C20C1C8FCF6B1ULL,
		0x3107A685B5ED700DULL,
		0x9E1C21E348FFF1C1ULL,
		0xDCF0B10EC385EBD2ULL
	}};
	printf("Test Case 701\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 701 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -701;
	} else {
		printf("Test Case 701 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x1755ABF1921C2FDEULL,
		0x16595A6C472960E3ULL,
		0x0B5F89F3C577823AULL,
		0x02AA98096BD2DEA8ULL,
		0xCBD41DF33640EEA9ULL,
		0xF4A550E776516EEAULL,
		0xC79D35BBFEA9FFBAULL,
		0x023933F850FA7FB1ULL
	}};
	printf("Test Case 702\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 702 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -702;
	} else {
		printf("Test Case 702 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8A3EA85E066854C8ULL,
		0x8E02687F34A9034EULL,
		0x302B3D390F3BEC51ULL,
		0x5F1789BB9B2500A8ULL,
		0x6EF683E0F19BA814ULL,
		0x7DE11210C2B40C2CULL,
		0xB1F586AB12211084ULL,
		0x605F1002D0078AA2ULL
	}};
	printf("Test Case 703\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 703 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -703;
	} else {
		printf("Test Case 703 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC78D188CBFA38E45ULL,
		0x8867DD2B1280F6CBULL,
		0xB211526D6318BC04ULL,
		0xDA8FB888E628A5EFULL,
		0xF5A96A7015F6CAF5ULL,
		0xA98DCA2B65EE3A97ULL,
		0x37501B43FF491FD2ULL,
		0xCFDA240476EB112FULL
	}};
	printf("Test Case 704\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 704 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -704;
	} else {
		printf("Test Case 704 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x776E2A72BD1336E2ULL,
		0xAEABE75E4D782901ULL,
		0x419EC30080BBA8D2ULL,
		0x83A9FE64C69E545FULL,
		0x0245C9CE3EDEC316ULL,
		0x6A8FEB596B6E4344ULL,
		0x77747C7F47FFF277ULL,
		0x3B6BCC49AE509BDEULL
	}};
	printf("Test Case 705\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 705 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -705;
	} else {
		printf("Test Case 705 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6235FF6B47004555ULL,
		0xF36EE2C26BF12203ULL,
		0xBEFDBF8BC5348DB6ULL,
		0x8E6CF250552709E6ULL,
		0x8752D6EA5FDD1591ULL,
		0x808BF1D3B41B193FULL,
		0xF8181FF36F393E87ULL,
		0x17A291F9C5D2ACAAULL
	}};
	printf("Test Case 706\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 706 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -706;
	} else {
		printf("Test Case 706 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5CBE88F646276E22ULL,
		0x1ED00897EB1C86AEULL,
		0xCCBFBADD47669847ULL,
		0x4AC2984065CB57B7ULL,
		0x69C67A07D99F7451ULL,
		0x6D91AC63FA6AA66FULL,
		0x05D22F52D69CBBBEULL,
		0xB8E8DAEF35C64003ULL
	}};
	printf("Test Case 707\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 707 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -707;
	} else {
		printf("Test Case 707 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x25C61B6CEF6F9AD8ULL,
		0x4DC17D929D3C608FULL,
		0x7429B57BB7750963ULL,
		0xB8872FBA833C0E84ULL,
		0xCD3C569D61BA64A2ULL,
		0x79364EAECFE3817FULL,
		0x495EBF54ACB96A43ULL,
		0x403A298CBCDCBD51ULL
	}};
	printf("Test Case 708\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 708 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -708;
	} else {
		printf("Test Case 708 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFC03A727E5EB06A5ULL,
		0x193C83C3C765FD43ULL,
		0x7B48D0E80A6AA3BAULL,
		0x0A9F3A0416F6FED2ULL,
		0x638635876804D135ULL,
		0xE4CD5E5BE7C8667DULL,
		0x1F78DAC721439B08ULL,
		0xAABB48D38DC8F532ULL
	}};
	printf("Test Case 709\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 709 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -709;
	} else {
		printf("Test Case 709 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xD4CED633C0BA9F99ULL,
		0xEBE3FFB834E2E39DULL,
		0x26F7982811020993ULL,
		0x2FC016E015D55F39ULL,
		0x0038BA1571EC61EFULL,
		0x8BA08B2A877CD5EDULL,
		0x1B474C0509EDD244ULL,
		0x0D64796308C86FC5ULL
	}};
	printf("Test Case 710\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 710 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -710;
	} else {
		printf("Test Case 710 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFEC6FCA10E6D283EULL,
		0x2F16A4838368014EULL,
		0xEE22AB04226B3750ULL,
		0xD8B2C90ADD14AA37ULL,
		0x38154083AC07205EULL,
		0xA4DC0F3ED49FD271ULL,
		0xEBB685A679AA8A75ULL,
		0xAA2F340C32D0B553ULL
	}};
	printf("Test Case 711\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 711 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -711;
	} else {
		printf("Test Case 711 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xACD4D347BAF73096ULL,
		0xB9B97988D1B2FEFBULL,
		0xAF6B8745A675F112ULL,
		0x846E3FCC1D5F3E07ULL,
		0xDA5AA7EE05A01E26ULL,
		0xDEC466E6709EFE3CULL,
		0x0391E7D2F93D1304ULL,
		0xD63536284566B5BDULL
	}};
	printf("Test Case 712\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 712 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -712;
	} else {
		printf("Test Case 712 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCE16D831E228A72AULL,
		0x20DAB877811C1871ULL,
		0xD141B6D3EE7412ADULL,
		0xEB9DBD81E996D572ULL,
		0x79FDC94FF613DABCULL,
		0x9905CB9C3EB8EE19ULL,
		0x9D3656B1EA75FA18ULL,
		0xEA7ECBF716E6E27EULL
	}};
	printf("Test Case 713\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 713 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -713;
	} else {
		printf("Test Case 713 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5D0E37655EC9F654ULL,
		0x4789728CCAC9D1A9ULL,
		0x3CE4CD4C32170C6EULL,
		0xEFF79DC21DE0832CULL,
		0xAF6F398F03892BF1ULL,
		0x5F61157D6F1147EAULL,
		0xECA52B62D31C521BULL,
		0x341450BD1974D970ULL
	}};
	printf("Test Case 714\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 714 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -714;
	} else {
		printf("Test Case 714 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE0FD20AA82581457ULL,
		0x0FD57220101E506AULL,
		0xEC613866620099C5ULL,
		0xB178F080CFF8D5C1ULL,
		0xC7EF8A3AAFA116AFULL,
		0xCB614FEF2DB860BFULL,
		0xC7CD7E8E5890E12BULL,
		0x2FD98AF9ACC7538CULL
	}};
	printf("Test Case 715\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 715 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -715;
	} else {
		printf("Test Case 715 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x78864409DA415D62ULL,
		0x92DA302DE479E6DFULL,
		0x004D7FCB1511CEC6ULL,
		0xE2560F16B89BD0D4ULL,
		0x55A53020663D961FULL,
		0xABF30F8846D8ECECULL,
		0x7A40596F7B4E4DC9ULL,
		0x850C0EC17026430BULL
	}};
	printf("Test Case 716\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 716 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -716;
	} else {
		printf("Test Case 716 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x03EBF8E5FC0F05C5ULL,
		0x3BDDDBB25A781D46ULL,
		0xA58199BCED5436FDULL,
		0xCF2737609C351504ULL,
		0x2BEEA0D1EB60D017ULL,
		0xD026A4C7E65BF0C9ULL,
		0xEC6A4FA5D46218E3ULL,
		0xE9A866DF4DAF38E1ULL
	}};
	printf("Test Case 717\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 717 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -717;
	} else {
		printf("Test Case 717 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x489D2B7796DD4A7CULL,
		0x99CA5E7BE21819B6ULL,
		0xA42CB5AD5EBB4D81ULL,
		0xF12F4989D19FB4ABULL,
		0x3B89579A5C5D8EBBULL,
		0x16B404342994836CULL,
		0xFF3C594A3AB8F62CULL,
		0x0367B2A20C89196FULL
	}};
	printf("Test Case 718\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 718 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -718;
	} else {
		printf("Test Case 718 PASSED\n");
	}
	printf("---\n\n");
	la = 501;
	k1 = (curve25519_key_t){.key64 = {
		0xA1467A18997A28FBULL,
		0xB06F6B347BF9C8AAULL,
		0xE0A06F4EE04CD5B6ULL,
		0x4B226ADB3B3F9C8FULL,
		0x998B4E382B8D216BULL,
		0xE416E65B97A34879ULL,
		0xE3D9F4EC632E4459ULL,
		0x003C09A8497FDDBBULL
	}};
	printf("Test Case 719\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 719 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -719;
	} else {
		printf("Test Case 719 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9704D15D6333A169ULL,
		0x619413E9EF2A31B5ULL,
		0x463CA9E4196AC669ULL,
		0x2613A3ADEF9C730EULL,
		0xB272C0C01C15C50DULL,
		0x0E3D38C85320B07EULL,
		0x958098396B0E45EEULL,
		0x989A430FEEF6212EULL
	}};
	printf("Test Case 720\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 720 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -720;
	} else {
		printf("Test Case 720 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB3E7C987F9F339A3ULL,
		0x2AC12B1167BC3A57ULL,
		0xE30E881A47945026ULL,
		0xF6890C5782BAC8CDULL,
		0x8580638554F55582ULL,
		0x1A6589E535404287ULL,
		0xE7873798F17C4C37ULL,
		0xA916B33D54AC291DULL
	}};
	printf("Test Case 721\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 721 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -721;
	} else {
		printf("Test Case 721 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x28D693BA150772C8ULL,
		0x16E611BFB059E9EEULL,
		0x0A046C4EEAB6DF14ULL,
		0xBFDE817A925F2039ULL,
		0xFDA9711D25E7AEC3ULL,
		0x36E8223F002274E9ULL,
		0xA934987C12F5A0B7ULL,
		0xF45314574A550031ULL
	}};
	printf("Test Case 722\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 722 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -722;
	} else {
		printf("Test Case 722 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3174EF9287FD5C65ULL,
		0xE4B4E13990288F59ULL,
		0x9F492D40843DB46FULL,
		0xE395B857CBC57A42ULL,
		0x7086D559FF26517FULL,
		0x2BC7E4C58CE97C38ULL,
		0x26BF0D29C08A3A76ULL,
		0xEBBEE889054080D0ULL
	}};
	printf("Test Case 723\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 723 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -723;
	} else {
		printf("Test Case 723 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFDA2CFD05B307B49ULL,
		0x70011B12162FFFFDULL,
		0xC71E25E912FB3D81ULL,
		0x91484A571F990F57ULL,
		0x5A8CFECD199895F3ULL,
		0xCDA01CEB8256EBD6ULL,
		0xBFCDF6E79BBA4E75ULL,
		0x31A12A7FD3D1AE7FULL
	}};
	printf("Test Case 724\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 724 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -724;
	} else {
		printf("Test Case 724 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x83877A20B9F4FA2CULL,
		0x6C79766208CD06BFULL,
		0x76EFBB022AE0319EULL,
		0x4948789A13DD0C63ULL,
		0x7000741AD6B20964ULL,
		0xF067655155F6F9D9ULL,
		0x5CF4B947A77BB600ULL,
		0x9AA2AF88BD21BBADULL
	}};
	printf("Test Case 725\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 725 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -725;
	} else {
		printf("Test Case 725 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0E4A8437BAEC1DFEULL,
		0x7F2844832ECC59C2ULL,
		0xC2892CE89E4F3D07ULL,
		0xE24286656900EF60ULL,
		0x7DDA727C33E5E419ULL,
		0x257657B91D03D5E2ULL,
		0xEFFAF18D29A278E1ULL,
		0xEB38524164820159ULL
	}};
	printf("Test Case 726\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 726 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -726;
	} else {
		printf("Test Case 726 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBE61B4EB6B551586ULL,
		0xAB7DCCF0A202DCADULL,
		0x23B96E520D585014ULL,
		0xFC7A7C76836E970FULL,
		0xF1031A4D524E5F3BULL,
		0x0BD3146D1235F492ULL,
		0x5B06029F16F0799DULL,
		0xEACE0920F78C4A78ULL
	}};
	printf("Test Case 727\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 727 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -727;
	} else {
		printf("Test Case 727 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x76143080DF4DC19DULL,
		0xFBFA43AE524B69ECULL,
		0x6DBDAE755AE347F8ULL,
		0x45AB94344FA00122ULL,
		0x84D98C939C73C859ULL,
		0xB3B6711F0FDA877BULL,
		0x143272455AF75699ULL,
		0xA49DEA10B5D41B93ULL
	}};
	printf("Test Case 728\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 728 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -728;
	} else {
		printf("Test Case 728 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6C44B6D8C6BA864CULL,
		0x080157C361C227D9ULL,
		0xB0108BE566F7CA61ULL,
		0x0825B3EDA03C7BDEULL,
		0xF32396E44036DA5BULL,
		0xC09C301970059FB2ULL,
		0xEE78D94ABE5B99DFULL,
		0xF50CB6901359679AULL
	}};
	printf("Test Case 729\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 729 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -729;
	} else {
		printf("Test Case 729 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE33BAD6593B52696ULL,
		0x01C6D2CFC41001A5ULL,
		0x2FE3E27D071C6B55ULL,
		0x3EDB54A50AF480C6ULL,
		0x887B68B0E4E592F1ULL,
		0xCF3E75B6CC665F4CULL,
		0x3BBEC519F17E0A0AULL,
		0x34B7A188E4F91493ULL
	}};
	printf("Test Case 730\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 730 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -730;
	} else {
		printf("Test Case 730 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x982A83EA55892241ULL,
		0x1502331B733D38C8ULL,
		0xDF4BDA591902ADD5ULL,
		0x7385EE6C94AA24EDULL,
		0x7422A28E7637833DULL,
		0xEF9D1D20C744B92BULL,
		0x36EE5C2EE5DF88D9ULL,
		0xB54B6F47492EBA99ULL
	}};
	printf("Test Case 731\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 731 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -731;
	} else {
		printf("Test Case 731 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6DF174A20B0B275AULL,
		0x534AF84297B79929ULL,
		0x8A033E77C0709C9FULL,
		0x1DA992A0EBCA49AAULL,
		0xA637BD3884240036ULL,
		0xC2E7B9100F897EDAULL,
		0x2695E9C08A9374E4ULL,
		0xF89E1E9A44376984ULL
	}};
	printf("Test Case 732\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 732 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -732;
	} else {
		printf("Test Case 732 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8CB581656AE03E18ULL,
		0xDFD3E515726C9221ULL,
		0x6E362378A4ABFA21ULL,
		0x4240FE8C9A79E0B8ULL,
		0xF3042F460147E305ULL,
		0x61F492AB1539619EULL,
		0x89C79BD01DC5D82FULL,
		0xD7630C16D9FCE23AULL
	}};
	printf("Test Case 733\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 733 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -733;
	} else {
		printf("Test Case 733 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x35F182F603892118ULL,
		0x50EA4E3C9E8380A9ULL,
		0x5B8633FC147A5012ULL,
		0xCAF86C90A237AD26ULL,
		0x7B4A9E2923E83CC7ULL,
		0x3B91F0B1C5B53A2BULL,
		0x5D70A13028957000ULL,
		0x64E8E9756EBE449DULL
	}};
	printf("Test Case 734\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 734 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -734;
	} else {
		printf("Test Case 734 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x76764DBABD6B988FULL,
		0x216173C13DA7E6C6ULL,
		0x618D49E15072A1DAULL,
		0x2076695CE6E52ECDULL,
		0xE423050A1346F950ULL,
		0xFD7A6EA781B2CA8BULL,
		0x4353EE6397B0938EULL,
		0xFF3EE4404147F295ULL
	}};
	printf("Test Case 735\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 735 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -735;
	} else {
		printf("Test Case 735 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF01D76BADEDFA438ULL,
		0xC4BC810CB75A6F55ULL,
		0xFCE229963D051B06ULL,
		0x346CF170700D4783ULL,
		0x34A8A0172B7D82D3ULL,
		0xE6816D9F02F5E980ULL,
		0x54149FE841594082ULL,
		0xF4F936802ACFA3CFULL
	}};
	printf("Test Case 736\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 736 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -736;
	} else {
		printf("Test Case 736 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC56014026A0CCAF0ULL,
		0x124FFBFB4D1EC1BEULL,
		0xE025426C6F22ED02ULL,
		0xF84E195DBF89E15EULL,
		0x2404F565C5641481ULL,
		0x180BC754A1DFAF59ULL,
		0x8148C0FD0EF77364ULL,
		0x84A74AD183EDD28AULL
	}};
	printf("Test Case 737\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 737 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -737;
	} else {
		printf("Test Case 737 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x37B7776BACEA35C0ULL,
		0x10E68F34898E419DULL,
		0x0B4FB94DFBA445B7ULL,
		0xE6DF46254B3320FEULL,
		0x5779AB049FEF3CB8ULL,
		0xA61E3B01560CF103ULL,
		0x73049A4192376EA0ULL,
		0x6F6E32B9E3D51F23ULL
	}};
	printf("Test Case 738\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 738 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -738;
	} else {
		printf("Test Case 738 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB5E7B574103C19FAULL,
		0x66F9A03CB048F758ULL,
		0x836CAA8C9032C063ULL,
		0xE9AE456E0D8D36DAULL,
		0xBF001DE6D679B07AULL,
		0x13D5B99CD38C9356ULL,
		0x0F0C214D00F5FF78ULL,
		0xFDB14E254C210B9BULL
	}};
	printf("Test Case 739\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 739 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -739;
	} else {
		printf("Test Case 739 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB838DBE32E2BE602ULL,
		0x5653804A24E34E14ULL,
		0x3DE90D202A276C94ULL,
		0xEC78624DE0480428ULL,
		0x5BA910F1E478645BULL,
		0x255F6DC8AE527103ULL,
		0x8EAF7050FBDD49CFULL,
		0x89BA210B61FDDC4BULL
	}};
	printf("Test Case 740\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 740 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -740;
	} else {
		printf("Test Case 740 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x46890C463A7B1AFFULL,
		0x3C17A02562E57602ULL,
		0x22C95EF84B650538ULL,
		0xFB54704B037D7728ULL,
		0x25848FC3FA100E3BULL,
		0xF92691E9E743BDDFULL,
		0x04BB85361AC8B791ULL,
		0x850FF6022E82D902ULL
	}};
	printf("Test Case 741\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 741 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -741;
	} else {
		printf("Test Case 741 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1E4C3B73BC00BF3FULL,
		0x4A9083ACFBA7A00CULL,
		0xE6563AD238420205ULL,
		0x6AC29D49610962E4ULL,
		0x8E4FFA103DE61644ULL,
		0x566271DBC1516BBEULL,
		0xC18CB636A4E3B13FULL,
		0xFAAFE71929912395ULL
	}};
	printf("Test Case 742\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 742 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -742;
	} else {
		printf("Test Case 742 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD363968216A79F97ULL,
		0x1FF107B68A5852B8ULL,
		0x99ED6EA08FE1FC4CULL,
		0xA7112895E0B4823BULL,
		0xB67216BB3D98478AULL,
		0x1B0D89DC4AD34374ULL,
		0x4AD7120CD6794470ULL,
		0xD12967500F8D74A4ULL
	}};
	printf("Test Case 743\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 743 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -743;
	} else {
		printf("Test Case 743 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x192D98A1C5F05575ULL,
		0xCD7FC85AE9D66ADCULL,
		0xBF6484CD02825031ULL,
		0xCCE137BAC4592D6FULL,
		0x88BCC95BFF39926DULL,
		0xBD921568D5CF3F54ULL,
		0xF6B1CC1508A110D7ULL,
		0x52CB0DED38C07889ULL
	}};
	printf("Test Case 744\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 744 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -744;
	} else {
		printf("Test Case 744 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD76E99C917729110ULL,
		0x1ECAA76534393FAEULL,
		0x36D27B6D28EEBF88ULL,
		0xD132D22350FBCF09ULL,
		0x7DAC7DB909800CBDULL,
		0x982C8F16DF5471E0ULL,
		0xB3ED4A27FE03CDBCULL,
		0xD1A9A7989A6FBB5DULL
	}};
	printf("Test Case 745\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 745 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -745;
	} else {
		printf("Test Case 745 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7B9AD04099A8B91AULL,
		0x35F8DCE077EEE5F6ULL,
		0x3EE1055EF578EAF9ULL,
		0xBB6A2EC2C12270E9ULL,
		0x1B7824BC41A2F46DULL,
		0xAE5C69E4FB87C421ULL,
		0x39BC096E3B1584E3ULL,
		0xC6DCD7B632193F4CULL
	}};
	printf("Test Case 746\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 746 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -746;
	} else {
		printf("Test Case 746 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1B16F8E524E3C513ULL,
		0xF92FA534B78357E5ULL,
		0x30A8A575F5977755ULL,
		0x54DDC95A71740AB1ULL,
		0x89D6E999535BBF03ULL,
		0x1085EBCAF32BE267ULL,
		0x6EA9FA8057CEE57CULL,
		0x89D73704B813D893ULL
	}};
	printf("Test Case 747\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 747 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -747;
	} else {
		printf("Test Case 747 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x5397D724F23560FFULL,
		0xC08BDC015373DB9DULL,
		0xCA8C44944A2BF69DULL,
		0x6AD8B269B1D037AAULL,
		0x65A8F2C6B61192E3ULL,
		0x707260C4E6195955ULL,
		0xF5F69852AC4F746DULL,
		0x0D98B61147D6B697ULL
	}};
	printf("Test Case 748\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 748 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -748;
	} else {
		printf("Test Case 748 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAB540BF526305B29ULL,
		0x709B2C930336976BULL,
		0xB8567B9C7E171761ULL,
		0xE8340148038F31F2ULL,
		0x52B8A00A6FE733B6ULL,
		0xD7DD0DA994FC601FULL,
		0xF2A9BD768DB05A4DULL,
		0xF8A554D9B09E4C43ULL
	}};
	printf("Test Case 749\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 749 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -749;
	} else {
		printf("Test Case 749 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x28CE9D3DE1133632ULL,
		0xD58F9CC072C11455ULL,
		0x8D29A6B9EA0ACC30ULL,
		0x44D9F51EAB89799BULL,
		0xEBBFC744E08BA84FULL,
		0x6EC2293AF812F12BULL,
		0x3ADEE2B9E681BBF8ULL,
		0x336F2E931DE2088DULL
	}};
	printf("Test Case 750\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 750 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -750;
	} else {
		printf("Test Case 750 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xBF56336B4008FA56ULL,
		0x6A65276D38D302B0ULL,
		0xF13F261EDA1AC053ULL,
		0xBD2E52EFDE97D266ULL,
		0xE1BD76574A33A91CULL,
		0x1EA8C417FE6945BFULL,
		0x00FDEC639DB96511ULL,
		0x08F15535003809CAULL
	}};
	printf("Test Case 751\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 751 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -751;
	} else {
		printf("Test Case 751 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF5B30BCF0ACCFAC6ULL,
		0x67DE5F9544721284ULL,
		0x03A2715DE5C8573CULL,
		0x7919DA848849332CULL,
		0x3A3201A5281AC349ULL,
		0x015B2F5E33DD0582ULL,
		0x96393664C5D01F19ULL,
		0xC91AF1180F06E4BAULL
	}};
	printf("Test Case 752\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 752 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -752;
	} else {
		printf("Test Case 752 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6FDDA96C54428A03ULL,
		0x57D790B57DFBDE2BULL,
		0x5A0A4FAB26B0CDDBULL,
		0x7CA00A0E0DFF4422ULL,
		0x14C94255F5C1FE44ULL,
		0x814D76903AA02CF6ULL,
		0x008A74083D9550EFULL,
		0xFB6E1EF7EAF1C509ULL
	}};
	printf("Test Case 753\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 753 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -753;
	} else {
		printf("Test Case 753 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6030C6A0BD5584D1ULL,
		0x898D2B4071F955D4ULL,
		0x8C723AEFC9D2CEEFULL,
		0x9AA4AFD7AE3730F5ULL,
		0x6D3593967A9C915DULL,
		0x0DCE9138D8106945ULL,
		0xA386C3686DD712D9ULL,
		0x9D044C4945CAD4AAULL
	}};
	printf("Test Case 754\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 754 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -754;
	} else {
		printf("Test Case 754 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAEDB50229DE184DEULL,
		0x55B9844EB9ACF6CAULL,
		0x3B66A39B0F1E0086ULL,
		0x4C65A7305C4B367AULL,
		0x026F5D4116946442ULL,
		0x5BF49E0660BF4C42ULL,
		0x13153A821F4E2A07ULL,
		0x343410CD45D2C995ULL
	}};
	printf("Test Case 755\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 755 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -755;
	} else {
		printf("Test Case 755 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x51176242753E95D1ULL,
		0x97070E6331C040D3ULL,
		0x453AE3A623060C06ULL,
		0x1DA96FD8FFAB24F6ULL,
		0x005C3E97EA436442ULL,
		0x77314ECCA29F03F0ULL,
		0x5874B8B2DF180C93ULL,
		0x9CF7581F9D1EB557ULL
	}};
	printf("Test Case 756\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 756 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -756;
	} else {
		printf("Test Case 756 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF69148CD395B95E2ULL,
		0xAB313425C05720AAULL,
		0x029954A7D726F040ULL,
		0xB84B8139FC112066ULL,
		0xD144AA8386A84C84ULL,
		0xA98E3E4E5A675344ULL,
		0x808CCD8502D50990ULL,
		0x5B6F6927084A68F0ULL
	}};
	printf("Test Case 757\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 757 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -757;
	} else {
		printf("Test Case 757 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x06D35D9094FC3CE2ULL,
		0x8DC578EA29D79338ULL,
		0xF9E1B7F11124E890ULL,
		0xE8769F48F120DF84ULL,
		0xDAA10D10D9E0E888ULL,
		0x4C48B478B98AC586ULL,
		0xB3646D45FD2E36B2ULL,
		0x7E2C4DAFB7788F88ULL
	}};
	printf("Test Case 758\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 758 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -758;
	} else {
		printf("Test Case 758 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC1827E268FA15856ULL,
		0xD92BEE5F93325955ULL,
		0x7052C7C9730AD425ULL,
		0x32DC580047714C5FULL,
		0x5FA9664F295C1FA0ULL,
		0x4F8C5BE8B27F2693ULL,
		0xECC1748CD7527DEAULL,
		0xD788C4B81376225DULL
	}};
	printf("Test Case 759\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 759 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -759;
	} else {
		printf("Test Case 759 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xAD121E17347C11B5ULL,
		0x5312FB95D07EAA34ULL,
		0x2751BD28189184AEULL,
		0xB1E8830B7E990B82ULL,
		0xE4FD0BB5B2101E50ULL,
		0xC59B201E0B7F9879ULL,
		0x630924D0E125A157ULL,
		0x1F26766BABE6AD7FULL
	}};
	printf("Test Case 760\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 760 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -760;
	} else {
		printf("Test Case 760 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD531987A0E140983ULL,
		0xBD24DDFE20F930F5ULL,
		0xFA5DEF4561F815B0ULL,
		0xCFB0C681E943F729ULL,
		0x35DD39AB553326E8ULL,
		0xF8D6922CA08AA2CDULL,
		0xD3304A332CE760C4ULL,
		0x91C9DBF965E1C7BBULL
	}};
	printf("Test Case 761\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 761 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -761;
	} else {
		printf("Test Case 761 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD571E2A278DD0A73ULL,
		0x1F0BC900D52D9C79ULL,
		0xA6EF4E6363D2AFB5ULL,
		0x3957F0999A82F313ULL,
		0x16F6F162F1EEA7B9ULL,
		0x254C735773844E24ULL,
		0x84A96139DF99AAC0ULL,
		0x9273D9299A5C2AFCULL
	}};
	printf("Test Case 762\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 762 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -762;
	} else {
		printf("Test Case 762 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x22A19A38BE340BB7ULL,
		0x290D7CF0D7DC4789ULL,
		0x254BC3A5CA121033ULL,
		0xC4D6355B8DA3D0D6ULL,
		0x94D1D40D3EFCE2C8ULL,
		0xD453F89FC9198B4BULL,
		0x7F5697706B6107F6ULL,
		0x186E21527BC7452DULL
	}};
	printf("Test Case 763\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 763 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -763;
	} else {
		printf("Test Case 763 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB2C1EF924347F964ULL,
		0xC928682FA886AB6FULL,
		0x858F5D8527AA94B1ULL,
		0x53E9CC2C599E6FE9ULL,
		0xE566E03B51E0744FULL,
		0x237EF794D7782D52ULL,
		0xFE8B23BF54A3A33EULL,
		0xCEE6D903BAA6C5FAULL
	}};
	printf("Test Case 764\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 764 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -764;
	} else {
		printf("Test Case 764 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC7802B6DA7ED1A2EULL,
		0x77078A96F0F14390ULL,
		0xB463130C6CCF4C61ULL,
		0xEB75D53118C379FEULL,
		0xEA41CBCBE5085516ULL,
		0xD152B6C0CDA18DF7ULL,
		0x46B65BF46339DA46ULL,
		0x6CD27F6B9FD80485ULL
	}};
	printf("Test Case 765\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 765 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -765;
	} else {
		printf("Test Case 765 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB207A35A5E2C9FE7ULL,
		0x9EAF73B69126A997ULL,
		0x625035E6D5D548C1ULL,
		0x43D2E6274AE4F826ULL,
		0x27A910520C2D15B1ULL,
		0xD0FF3E6943C38E77ULL,
		0x62676EE11B7C1659ULL,
		0x949834A5A1478F19ULL
	}};
	printf("Test Case 766\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 766 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -766;
	} else {
		printf("Test Case 766 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x02FC04FB45287562ULL,
		0xA93C98B51779AC28ULL,
		0x3FCC220AB36F004DULL,
		0x33BD9B339CE73556ULL,
		0xB704FCD3756DDBE0ULL,
		0xA1BC97008B9D65B8ULL,
		0x253309E197C7FC3BULL,
		0x528FBD119AF1296DULL
	}};
	printf("Test Case 767\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 767 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -767;
	} else {
		printf("Test Case 767 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xF2B2948DD3AA4664ULL,
		0x32A33BC2551ECF4AULL,
		0x4AD326B6CE30E690ULL,
		0x09A15B1186115C1CULL,
		0xE371AEBDC1D720D9ULL,
		0xB409499C3CAF8BCAULL,
		0x083A68A04E0CDF32ULL,
		0x12C665A9F5916B4FULL
	}};
	printf("Test Case 768\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 768 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -768;
	} else {
		printf("Test Case 768 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7FE2CA3065DB70EAULL,
		0x1601B7EFCF2A1C1DULL,
		0x24AAAC7640B1DE3AULL,
		0xE2E14B549785A8C1ULL,
		0x4660E6D3D52FC197ULL,
		0xB9BE61E24FE16DE4ULL,
		0x3AE08543F57F78FEULL,
		0x6545129D21B38ACCULL
	}};
	printf("Test Case 769\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 769 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -769;
	} else {
		printf("Test Case 769 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4D8AAD099107E5BFULL,
		0xF8AF737681FEC71BULL,
		0x057C1CDF8468E118ULL,
		0xCA83D53FA0D4FB91ULL,
		0xEBC08C5884F0ED97ULL,
		0xF675D218FD06D550ULL,
		0x16D64E0B120182C3ULL,
		0xD9BE2EBF2D11DC0EULL
	}};
	printf("Test Case 770\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 770 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -770;
	} else {
		printf("Test Case 770 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC0564D67A67C9016ULL,
		0x9421E83D9643DDB3ULL,
		0x28B9A27416E83621ULL,
		0x87FE4C60A222594DULL,
		0x795C26E04607829AULL,
		0x1D79D150FAB21D13ULL,
		0x4D513FC46BB09805ULL,
		0x7D952C108F642AEAULL
	}};
	printf("Test Case 771\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 771 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -771;
	} else {
		printf("Test Case 771 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x88BDF659C2F61C3FULL,
		0xCDD676A496817E25ULL,
		0x1E0DA11459F09E2BULL,
		0x88A5BF1326DA2023ULL,
		0xC50781ACB70AEC48ULL,
		0xFA7D5A40A8442AE6ULL,
		0x985D969132C8A39AULL,
		0xB1091C8F3B9591A1ULL
	}};
	printf("Test Case 772\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 772 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -772;
	} else {
		printf("Test Case 772 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEB1EFE1CB3511F44ULL,
		0x9E92E2D553826A47ULL,
		0x34E9FAB63C43E3D1ULL,
		0xBBEBD1433A04F003ULL,
		0x77774134BCA47D00ULL,
		0xE515B8E0BA33B051ULL,
		0x8B699E86DAAFD071ULL,
		0x91F537A0F8993FCAULL
	}};
	printf("Test Case 773\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 773 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -773;
	} else {
		printf("Test Case 773 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9CE969E4523B5AE1ULL,
		0xFA94096CBB0E2615ULL,
		0xE29EA57F022328D3ULL,
		0xEFA087E2E6A9961BULL,
		0xC70C9C1DA415D631ULL,
		0xFDA04E0D8C762D99ULL,
		0x3A555451DA8BF6B3ULL,
		0x901CE057E540D166ULL
	}};
	printf("Test Case 774\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 774 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -774;
	} else {
		printf("Test Case 774 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5C2C644526AF48EEULL,
		0xE5505DF8C89FE61DULL,
		0x78DDEB3C2AB9854FULL,
		0x236DC013DEEF56B0ULL,
		0x3F898E0C8E36C981ULL,
		0xEFBA9520D12A93B1ULL,
		0x464A12C33A4BB331ULL,
		0x7A12F4C99E42B69FULL
	}};
	printf("Test Case 775\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 775 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -775;
	} else {
		printf("Test Case 775 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCBF29903BC5BC28DULL,
		0x7213966C3F5457EAULL,
		0x08E6615575604ED4ULL,
		0xE35CE97A2B7A5372ULL,
		0xC413BBE95A49C331ULL,
		0x1CB6E58A49AF598CULL,
		0xF356AB6871944464ULL,
		0x3F857473C2B18354ULL
	}};
	printf("Test Case 776\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 776 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -776;
	} else {
		printf("Test Case 776 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x06E194E51599D9B6ULL,
		0x08269B5515240973ULL,
		0xF881D9C73646F207ULL,
		0x47A81B751E1B7F35ULL,
		0x1732717BF23EC8DCULL,
		0xE46C583AB8BFD7CBULL,
		0x1F86588706DC4687ULL,
		0xA5C7B2AC9326A573ULL
	}};
	printf("Test Case 777\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 777 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -777;
	} else {
		printf("Test Case 777 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0F99651F8881928AULL,
		0x62206F8338D74074ULL,
		0x526C4349119F62E7ULL,
		0xA0870E88417C14F8ULL,
		0xCF5554C1D24E58E6ULL,
		0xC92E09D7D1AE9F00ULL,
		0x1E9942EA460E2D6FULL,
		0xED341B9FD039D6E8ULL
	}};
	printf("Test Case 778\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 778 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -778;
	} else {
		printf("Test Case 778 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB1D1F8F8C58E0EC8ULL,
		0x52EC6469881277D1ULL,
		0x1C9B6A177AAF44C2ULL,
		0xCD6FEEA2D4EA2F4DULL,
		0xDA1561C0227C440FULL,
		0x4A6D5C1ADFB0BAC6ULL,
		0x40F594F181E2241EULL,
		0xE49C49DF47893ECDULL
	}};
	printf("Test Case 779\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 779 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -779;
	} else {
		printf("Test Case 779 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF3D4A41B9AC19B1BULL,
		0xA829A49FE6EC173DULL,
		0x9B72987050ACF51CULL,
		0xF7B055C7CEF5B026ULL,
		0x2CBC0277195595BFULL,
		0xBF31092705D3C877ULL,
		0xAED521AA6450C6A0ULL,
		0x3896AE35514750AEULL
	}};
	printf("Test Case 780\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 780 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -780;
	} else {
		printf("Test Case 780 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3E80AB9395ECA03AULL,
		0x34099F2912F01DBBULL,
		0xE896070088065626ULL,
		0x60948024CF4E4BDCULL,
		0x7AB20CFF083983F6ULL,
		0x8E70DDAD9C4CB22EULL,
		0x14EC5F9560606A29ULL,
		0xE1ECF467FC25003FULL
	}};
	printf("Test Case 781\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 781 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -781;
	} else {
		printf("Test Case 781 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2A1BE189A5F13935ULL,
		0xD9C2136D7AA0F2F6ULL,
		0x53BC4320E7322140ULL,
		0x18D7CE5F75A80BA1ULL,
		0xD9D8930E12A691B1ULL,
		0x998AF7B9E550C262ULL,
		0x34B796E63821C13CULL,
		0xE5FCE78AEFC9B261ULL
	}};
	printf("Test Case 782\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 782 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -782;
	} else {
		printf("Test Case 782 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEB5D99A1DFF6AAA6ULL,
		0x60265D9DE64D1100ULL,
		0xCF877B031E77C2DFULL,
		0xF8F8BB70F0012CAEULL,
		0x532EE071285C52B8ULL,
		0x4E1A73E50C3CB9ACULL,
		0x362291C1D62C765CULL,
		0xB5571392D49B568DULL
	}};
	printf("Test Case 783\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 783 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -783;
	} else {
		printf("Test Case 783 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDF08D17BC9B9EB1CULL,
		0x52231626147A9E30ULL,
		0x32F3BECA7DC05B7EULL,
		0x24180E63BD40FDB3ULL,
		0x0A7BDF608059ED36ULL,
		0x604420A46FAACDBBULL,
		0x227D88A4621B2840ULL,
		0x496C52E95C6298ADULL
	}};
	printf("Test Case 784\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 784 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -784;
	} else {
		printf("Test Case 784 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x65D246316AD01FD9ULL,
		0x54065BD2340F189CULL,
		0x7062CC2B6ACA0E7AULL,
		0x1007B191268715D1ULL,
		0xD9638AFD0BD27656ULL,
		0xE379B21F5B9C6681ULL,
		0xEC5124873805803FULL,
		0xC1B4A918353F8801ULL
	}};
	printf("Test Case 785\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 785 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -785;
	} else {
		printf("Test Case 785 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0B2697B826FF8776ULL,
		0xD634655E2CF58837ULL,
		0xE20A51717096E93CULL,
		0x95DA2D8B1204436FULL,
		0xE343221A9BF249D4ULL,
		0xFEAB52EE992AC10CULL,
		0x3C90F1584F2B1B32ULL,
		0xAB13E21CC50AA365ULL
	}};
	printf("Test Case 786\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 786 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -786;
	} else {
		printf("Test Case 786 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0519DCABD8063727ULL,
		0x703E2D1DC8AEDC37ULL,
		0x5982C5E1ED823C29ULL,
		0x86386B3CAFB9AF30ULL,
		0x8D7C7974AE3EC0D5ULL,
		0x0754A1C369E33AE4ULL,
		0xD4AF758EB77D4A61ULL,
		0xCD86F5A97D3B6CD9ULL
	}};
	printf("Test Case 787\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 787 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -787;
	} else {
		printf("Test Case 787 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3244FA67DF5C0652ULL,
		0xF383CFFDF11DBA80ULL,
		0x2BCA2BA508EDF328ULL,
		0x5E944F502C95500EULL,
		0xF7502DBCAF441012ULL,
		0x9FC78C15D3090167ULL,
		0xC1A017DE7DD2D20DULL,
		0x9D5AA8B5C5DCC96AULL
	}};
	printf("Test Case 788\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 788 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -788;
	} else {
		printf("Test Case 788 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD70B40C6644C9C99ULL,
		0x65F9DAABB886A329ULL,
		0x9AC0F23FE4FCD448ULL,
		0xEFD2902AF09B77D7ULL,
		0x54057A5D5C4F8144ULL,
		0x725A23B61FF4F6F0ULL,
		0x727CE1DE6D15ED2CULL,
		0x75E715B95A12EC27ULL
	}};
	printf("Test Case 789\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 789 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -789;
	} else {
		printf("Test Case 789 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB907CD45A081DDE7ULL,
		0x93CBA7431380D81EULL,
		0xB1C7D66F3DF31DEBULL,
		0x2DEFE13F8627FCB3ULL,
		0xA5D231C355B10855ULL,
		0x714F8046CB1DCFF4ULL,
		0xF68803A7C15A5995ULL,
		0x8A42EEA2BFC60692ULL
	}};
	printf("Test Case 790\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 790 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -790;
	} else {
		printf("Test Case 790 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0734D7F9D5673175ULL,
		0x612EE23C7B258BA3ULL,
		0x5AD20AD8AD85CBA6ULL,
		0x18A8ECDB44758FE9ULL,
		0x837D74DF430A98F1ULL,
		0x385A017A7987C37AULL,
		0xB5470E8119C156FBULL,
		0xA79490D5B9147B4BULL
	}};
	printf("Test Case 791\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 791 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -791;
	} else {
		printf("Test Case 791 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8176340D18BB518CULL,
		0xB92B14528D13FF70ULL,
		0x96ADBD04541E372AULL,
		0x71DD032438313A14ULL,
		0x1B6906D2744990B3ULL,
		0x2BEEA9CB87C669B0ULL,
		0x5FC10E0190C871B3ULL,
		0x4A204FEF9687D262ULL
	}};
	printf("Test Case 792\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 792 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -792;
	} else {
		printf("Test Case 792 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6230E3766E8A18B8ULL,
		0xB9B96B4889A8EEE9ULL,
		0x0E1852A65C0693B4ULL,
		0x7CBF7E3B8C4E9FB7ULL,
		0x43E0556FCBD85A23ULL,
		0xC9BB46615770B1C0ULL,
		0xC4D1AAF21CDBB0BEULL,
		0x214BB467876ACF96ULL
	}};
	printf("Test Case 793\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 793 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -793;
	} else {
		printf("Test Case 793 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE7D2A78212A08DE7ULL,
		0x4C410A12A860DA70ULL,
		0xC3D6038E1A85986EULL,
		0x3C9F8723562B694BULL,
		0xDAB4F309DB3C8747ULL,
		0x88DA077F170C3555ULL,
		0xBAA89399A3658F62ULL,
		0x4B10ACBF1F195FCDULL
	}};
	printf("Test Case 794\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 794 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -794;
	} else {
		printf("Test Case 794 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9ED54DDBE3007D55ULL,
		0xDD8EA1810DEF5E3AULL,
		0x753D198F2502394EULL,
		0x9A561C1275B3179EULL,
		0x7EDE87D39A1DF1ABULL,
		0x40A2F93AE91C4BC6ULL,
		0x1167DC6C59C35AB4ULL,
		0xE3C53F53ECD13214ULL
	}};
	printf("Test Case 795\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 795 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -795;
	} else {
		printf("Test Case 795 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x647C76FFE033751FULL,
		0x2AFA387356C19BD1ULL,
		0x177DEBF9C5C08576ULL,
		0xA6AA9B7803824FE1ULL,
		0x9CB9130209D7FB1AULL,
		0x9B488B51301E3272ULL,
		0x8A08010CF5D5875EULL,
		0xDD70A1C63B0DC8AFULL
	}};
	printf("Test Case 796\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 796 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -796;
	} else {
		printf("Test Case 796 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3A0EEFBF76452148ULL,
		0xAEE5018792681362ULL,
		0xC54BCC6EF7AF1A19ULL,
		0x131647B6E3A85A94ULL,
		0x894F3E0F5CE9AE04ULL,
		0x17FAD0A4D5236E7AULL,
		0xBD72041D38B9BF5AULL,
		0xBB9BBD6E661D59F6ULL
	}};
	printf("Test Case 797\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 797 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -797;
	} else {
		printf("Test Case 797 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xCB2BFEA431A773CAULL,
		0xC37841568A65D514ULL,
		0x00B875019FB6F9FAULL,
		0xFE94F9D924A7F955ULL,
		0x37FC5B1A77165E21ULL,
		0x6B2FFE74D09C3787ULL,
		0xEBA1DFF9B6ABEFC3ULL,
		0x01C0C32ABCF43BA5ULL
	}};
	printf("Test Case 798\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 798 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -798;
	} else {
		printf("Test Case 798 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDD380A67EEB700B6ULL,
		0x8D5712B4934B6788ULL,
		0x894AB4DFB56F9560ULL,
		0xDD68DAB10153B036ULL,
		0x5B7C3B354A647B6FULL,
		0x24B021C89B4647FDULL,
		0x6BB648C85D3EE42AULL,
		0xC1DB6F827B9D113EULL
	}};
	printf("Test Case 799\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 799 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -799;
	} else {
		printf("Test Case 799 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x612111A35531448DULL,
		0xC2E71C5E1473E8F2ULL,
		0x8A65EE26CD4C3A4BULL,
		0x9821F68ABE5AA9FAULL,
		0xA41DE717FAD9F82BULL,
		0xF83EB9994C98BCDEULL,
		0x748005C7B233C1B0ULL,
		0xD4D373A74A1DC0C6ULL
	}};
	printf("Test Case 800\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 800 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -800;
	} else {
		printf("Test Case 800 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3F65D0AE6D65735AULL,
		0x5F5F3D112B5C15EEULL,
		0x633BD0CBA2CA32B3ULL,
		0xC738DEAF45813B5DULL,
		0x99429AACBCB3464BULL,
		0xDC0E8E035C856191ULL,
		0x8300EBE021FB03D5ULL,
		0xA023512B35FA1EF2ULL
	}};
	printf("Test Case 801\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 801 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -801;
	} else {
		printf("Test Case 801 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAC1FA966AF745379ULL,
		0x22B025B21074754CULL,
		0x229ECF767B3E1082ULL,
		0x0F6B2CFBB5B6108EULL,
		0xE022DEE50A86B72AULL,
		0x2EB7F7790067FEE9ULL,
		0xA9DA12740E785EE4ULL,
		0xA0EE5CD8E560F158ULL
	}};
	printf("Test Case 802\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 802 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -802;
	} else {
		printf("Test Case 802 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB97EC765C42F6AE5ULL,
		0xDD6F88BC62C58320ULL,
		0xFDA2EF27172FF73CULL,
		0x0449F1BEA9DDE500ULL,
		0x6583AA9E0089E09CULL,
		0xFAFB7662E11049B6ULL,
		0x3441FD7429D7CE67ULL,
		0xA359C75CF6708E28ULL
	}};
	printf("Test Case 803\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 803 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -803;
	} else {
		printf("Test Case 803 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE0D6C109F9001A4EULL,
		0x43A5CF4EDD0E54A1ULL,
		0x5795D2353AB977A0ULL,
		0xA0FFCCCBABE5F2F7ULL,
		0x0227D27521837E13ULL,
		0x19BA0F5A47D39FFAULL,
		0x76A58DE3D9073F9AULL,
		0x19F0E7C080E3BBC2ULL
	}};
	printf("Test Case 804\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 804 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -804;
	} else {
		printf("Test Case 804 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0C82192CAED253D5ULL,
		0x7F351D7229079C74ULL,
		0x4508F4A703529CD9ULL,
		0xC578A30D2A844A36ULL,
		0x225F58E0BD30D3FCULL,
		0x0BCDA3032810705EULL,
		0xA71BA2308E4D05E6ULL,
		0xE64D530C427657F0ULL
	}};
	printf("Test Case 805\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 805 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -805;
	} else {
		printf("Test Case 805 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6B6033E491AFC1D0ULL,
		0xF7640CF919C10FF4ULL,
		0x9FB14B2FF9BE6083ULL,
		0x42630861E07F69A0ULL,
		0x3F2538F77853AAB2ULL,
		0xFAFFFA32027039B8ULL,
		0xE590A28D5E519E8AULL,
		0xCA6BAA95387F1576ULL
	}};
	printf("Test Case 806\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 806 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -806;
	} else {
		printf("Test Case 806 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xADAB90EF2D2A6EEBULL,
		0xBCAF03BFB2B1B2FEULL,
		0xE28E2EEC6306ACF3ULL,
		0x3C542AF6C36FA501ULL,
		0xCF9955722798ABB6ULL,
		0x5057C391D54916C0ULL,
		0x0267F2194F1E4A87ULL,
		0xEC06880E10DBD1FCULL
	}};
	printf("Test Case 807\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 807 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -807;
	} else {
		printf("Test Case 807 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6B8F63CD40A0910AULL,
		0xDF18894BD1A5BDE2ULL,
		0x3F1FA47610229DD0ULL,
		0x080086E84C10CAF0ULL,
		0xFDCCF9BC838E18FDULL,
		0x2EAC85FA796C2590ULL,
		0x6BDA16796F8AC77BULL,
		0x3DBCE0E2ADDC2F91ULL
	}};
	printf("Test Case 808\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 808 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -808;
	} else {
		printf("Test Case 808 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x04C8A6C2DA97EC63ULL,
		0x19DBF62BCAC85F27ULL,
		0xE88467B282CEF154ULL,
		0xF12862D1D3121429ULL,
		0x95967EDF0DC574E5ULL,
		0x25FAF8FA59779A58ULL,
		0x44E4DB9D3ACD0BC1ULL,
		0xA3F778BDB6CBFCC8ULL
	}};
	printf("Test Case 809\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 809 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -809;
	} else {
		printf("Test Case 809 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x50851C99539AAEEAULL,
		0xFEBCFAF8DCF2BB44ULL,
		0xA569CE998ED959B2ULL,
		0x7CA8D32854F254FEULL,
		0x833633D3E3B4C750ULL,
		0xA30F889817F088E0ULL,
		0x7D6D9C3E8FB870C3ULL,
		0xA2C37113BC08B332ULL
	}};
	printf("Test Case 810\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 810 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -810;
	} else {
		printf("Test Case 810 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE9E1C5DFD72BE1FFULL,
		0x7B5586AE3AB03BD7ULL,
		0x6CA27D5AE84D0DA4ULL,
		0x3575FFA3B34651BBULL,
		0xC0709A90F34100DAULL,
		0x39A7A8C304CA30A7ULL,
		0x985536CC0C38E691ULL,
		0xC92D7EF7DE576BE9ULL
	}};
	printf("Test Case 811\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 811 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -811;
	} else {
		printf("Test Case 811 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF8B89D8504215CE4ULL,
		0x7E1C8604F6E16581ULL,
		0xDD2D9F07AC5E7DBFULL,
		0x2F7B01D46213DA90ULL,
		0xDFAEC8F0E2B9FBB5ULL,
		0x641A48467F17502BULL,
		0xEB7E15C0E067A5D2ULL,
		0x877D7D413567E001ULL
	}};
	printf("Test Case 812\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 812 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -812;
	} else {
		printf("Test Case 812 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x39842B124325B27EULL,
		0xAD78B0A80EA28B56ULL,
		0x258E04E857E1123DULL,
		0x27CDD61B0A72B8B1ULL,
		0x3D444C381F9BB204ULL,
		0x89125AB3AD2E521BULL,
		0x64990191A2E24C79ULL,
		0x0B7FF511F58A63AEULL
	}};
	printf("Test Case 813\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 813 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -813;
	} else {
		printf("Test Case 813 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0F2EEA8FB1F1167EULL,
		0x87F03AC4AC5A6FB4ULL,
		0x11CC39D8B12FBFE5ULL,
		0xAD7B8309B2CC0179ULL,
		0xE50BB013126FA41AULL,
		0x4C3E4383B92F982EULL,
		0xF440BBAFBFAC9413ULL,
		0x94C07A01159CC697ULL
	}};
	printf("Test Case 814\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 814 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -814;
	} else {
		printf("Test Case 814 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE86F3CCCB5B63DB5ULL,
		0xA4F409F8B7409637ULL,
		0x36D58213A3184A4EULL,
		0x47297C93E677E784ULL,
		0xB3322F8BA126E933ULL,
		0xD67B50B986BAB65CULL,
		0x34560B1038FB6115ULL,
		0xA439F8CD6BA27AA1ULL
	}};
	printf("Test Case 815\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 815 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -815;
	} else {
		printf("Test Case 815 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x40B1DC7479456A9FULL,
		0x7607AA273708B806ULL,
		0xAC103F85B20E04D1ULL,
		0x6B528F39EB9CC23FULL,
		0x8B6A9ACB23F2F8B6ULL,
		0x906B2B40145D72E6ULL,
		0xC7BF360B69AD5FFCULL,
		0xA9F7529B11DB600CULL
	}};
	printf("Test Case 816\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 816 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -816;
	} else {
		printf("Test Case 816 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0F1E89EEED22AC76ULL,
		0x3DD712921421FFE7ULL,
		0xFD857A2AAF249D9AULL,
		0xC2181C4293840012ULL,
		0x60F8FA3C8F82D06CULL,
		0x703DDBC71F698FB8ULL,
		0xF3D250BC91DE642FULL,
		0xCA6D74D5218AB11EULL
	}};
	printf("Test Case 817\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 817 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -817;
	} else {
		printf("Test Case 817 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5EC4DBAF7FA824C8ULL,
		0x9FDD968D5D4BF431ULL,
		0x143B835ED51D16A3ULL,
		0xC5369F4218846B3AULL,
		0x5CC814607F09D7B9ULL,
		0x4124A8C0D7FB760AULL,
		0x884C524A6A4C3B09ULL,
		0xFC25A0C7D547ED50ULL
	}};
	printf("Test Case 818\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 818 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -818;
	} else {
		printf("Test Case 818 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x877959AEB8831ED4ULL,
		0xC37680AEE67CCF60ULL,
		0x52AED2DAB33795DEULL,
		0x67A034909EAF39C1ULL,
		0x33101D5BC0CF5033ULL,
		0x46883A81C9802B86ULL,
		0x22D1181898F503CCULL,
		0x7B830A759822D3F0ULL
	}};
	printf("Test Case 819\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 819 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -819;
	} else {
		printf("Test Case 819 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x82C2DFD74AB032CAULL,
		0xF2FA1F9F01A65E6AULL,
		0x0D32C246B3B07202ULL,
		0x78292953C51C6C27ULL,
		0xDA6C40FA10A3804BULL,
		0x4267B167B4E2B3D0ULL,
		0xACBA155818AFE08BULL,
		0x57B92494CF36944EULL
	}};
	printf("Test Case 820\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 820 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -820;
	} else {
		printf("Test Case 820 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6DCFB6FC4E7E1C31ULL,
		0x8C006BE7191FE986ULL,
		0x550D90B4280CCBA1ULL,
		0xCEF989007F36CFECULL,
		0x5EB8B26FC3D1FD4EULL,
		0xF028E1899F4D3E1DULL,
		0x43EBB36190970ADDULL,
		0x238CBE873AB6AB13ULL
	}};
	printf("Test Case 821\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 821 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -821;
	} else {
		printf("Test Case 821 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAF9B6EA5FE33947EULL,
		0x58FCF075812701C5ULL,
		0xC64BCC8702AEE574ULL,
		0x97779992629A6045ULL,
		0xAEDB729A20DB2013ULL,
		0xC1ED7C4E85527804ULL,
		0xFAD1FC6A2C6FB3B0ULL,
		0xCCBF8AC6F6EC3D49ULL
	}};
	printf("Test Case 822\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 822 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -822;
	} else {
		printf("Test Case 822 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD10234B10B427143ULL,
		0x1BB12AE479C38C63ULL,
		0x32A7C5C435CBBB70ULL,
		0x67D066839D5978B0ULL,
		0xC0F49AF16BE1015DULL,
		0x52A61F970F254C48ULL,
		0x92C1A22F12DCB3D0ULL,
		0xF0B442A95628E8D7ULL
	}};
	printf("Test Case 823\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 823 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -823;
	} else {
		printf("Test Case 823 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x5A2108FD671158CBULL,
		0xEB47BAB9399DB8C7ULL,
		0xBBA8E5E3AE5067F5ULL,
		0x17D86D2371B4B2BBULL,
		0x2A6D6AEA405B20C7ULL,
		0x404EF078861638A7ULL,
		0xA38636DA1478DD09ULL,
		0x174581D829EA9BDBULL
	}};
	printf("Test Case 824\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 824 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -824;
	} else {
		printf("Test Case 824 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x2485C15D6DD57BA1ULL,
		0x695B05E604A56423ULL,
		0x6344A294458553B6ULL,
		0x4B2E5AE87F1F9E82ULL,
		0x4D2A4C03ED6E3585ULL,
		0x8E6AA7ECC324F0DCULL,
		0xDA21B2877298015DULL,
		0x03F2AC7022A07E6EULL
	}};
	printf("Test Case 825\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 825 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -825;
	} else {
		printf("Test Case 825 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xD920CD734A5D60B1ULL,
		0xA1EFD33A5EF60708ULL,
		0x82F75A2272E19693ULL,
		0x7020BEC4FA66AEC3ULL,
		0x5957610F62466041ULL,
		0x03621D9CC92BB882ULL,
		0x2F7FB83AF4406B19ULL,
		0x1C7F161FF0C6EB5CULL
	}};
	printf("Test Case 826\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 826 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -826;
	} else {
		printf("Test Case 826 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x52A02B53211961A2ULL,
		0x283734F3FD8E2A7AULL,
		0x29A247C3DCBC7737ULL,
		0xA229626E769A6223ULL,
		0xDDDF5EC839B9C698ULL,
		0xF34346873022AA5BULL,
		0xFE70CACBDF7EDFA4ULL,
		0x32944A21EE755C5BULL
	}};
	printf("Test Case 827\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 827 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -827;
	} else {
		printf("Test Case 827 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x72F491BC338DEFD6ULL,
		0x5B77F2ED3F0199EDULL,
		0x8536491E6F884C68ULL,
		0x00F56D78E859D408ULL,
		0xD31700C9B24E26DFULL,
		0x0A52B4282BDCF530ULL,
		0x676B0F6746804358ULL,
		0x8DB533B644E0209DULL
	}};
	printf("Test Case 828\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 828 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -828;
	} else {
		printf("Test Case 828 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x921BB489D5720361ULL,
		0x553D5C55013E07AFULL,
		0xB93AE2FDFD7BC106ULL,
		0x2BDE8AA3B0B8E8C9ULL,
		0xBB9F62A723DB86CBULL,
		0x3679A8C517A656B3ULL,
		0x11142A8F416D2D5EULL,
		0x3E563EE112A40B17ULL
	}};
	printf("Test Case 829\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 829 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -829;
	} else {
		printf("Test Case 829 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7E58EDEAE0F95821ULL,
		0xAEDEBEDA8041B128ULL,
		0xA1BABA99715BC738ULL,
		0xD0757496C3DA3B21ULL,
		0xE6B94B3B16216E40ULL,
		0xC6FDBC398BFCE9A4ULL,
		0x7A860257767D4066ULL,
		0xF98F6DEC9710EF4FULL
	}};
	printf("Test Case 830\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 830 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -830;
	} else {
		printf("Test Case 830 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7E724DB56017D480ULL,
		0x75236769C17B04FDULL,
		0x813544AEED9CA190ULL,
		0x300234C341F823B9ULL,
		0x627AFD4499AE366DULL,
		0x89416E1556D4F1A0ULL,
		0xF7F21EBFE4360BB7ULL,
		0xC3573580EC66ABA2ULL
	}};
	printf("Test Case 831\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 831 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -831;
	} else {
		printf("Test Case 831 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1C930D90608C7516ULL,
		0xC42E4533A2E085E5ULL,
		0x2F684AA2EFD89778ULL,
		0xA1CE2ABD981F62F7ULL,
		0x5686FAFD3D213B5AULL,
		0x58FC6580C2BDD02EULL,
		0xD2FD116D2F6C61A3ULL,
		0x4F67072436A19332ULL
	}};
	printf("Test Case 832\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 832 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -832;
	} else {
		printf("Test Case 832 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x7AD873CAE4421BF2ULL,
		0xD0150F1FE947699EULL,
		0xF244B107D446281CULL,
		0x9C2E73956505B979ULL,
		0x70C3EAD826621172ULL,
		0x43A63ABD50555B89ULL,
		0x524681B20732220AULL,
		0x0F4841A9657E5181ULL
	}};
	printf("Test Case 833\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 833 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -833;
	} else {
		printf("Test Case 833 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0CC8FD632EE8B7A1ULL,
		0x57F02C1DF00B8E2FULL,
		0xE689DE58D9F3AE32ULL,
		0x488FEE5B753A22ECULL,
		0xD8AA13CAACFEBF07ULL,
		0x5F7ED1971919D45FULL,
		0xF5886F1A6AEF78C9ULL,
		0x5F78333714F54F92ULL
	}};
	printf("Test Case 834\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 834 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -834;
	} else {
		printf("Test Case 834 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x01FB8DC4943981C1ULL,
		0xC860B37C39F2E269ULL,
		0xAD548354EE02689CULL,
		0xF393AD78331EFC80ULL,
		0xA3A6DAB2105012F5ULL,
		0x5AD6FB93AC1F87B8ULL,
		0x1AF2E5449A5A2659ULL,
		0xAA9B8E725BCCA4BDULL
	}};
	printf("Test Case 835\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 835 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -835;
	} else {
		printf("Test Case 835 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x16BEC7EDA459B713ULL,
		0xC887A3E369B13497ULL,
		0xE3A635DA2181FEBDULL,
		0x94BD51EF962C4BF1ULL,
		0x014A4CE11D636163ULL,
		0xD8AA9BB58DE17453ULL,
		0x93C73490FF6FD65EULL,
		0xE2D9A24513273471ULL
	}};
	printf("Test Case 836\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 836 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -836;
	} else {
		printf("Test Case 836 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB35843EB7928F66AULL,
		0x10763D45542BF427ULL,
		0x7D2D6866508092CFULL,
		0x1B7E3D66F8CE6C05ULL,
		0x3AB8EDD14CF73D2BULL,
		0xD38323781C9A87CEULL,
		0xD16B55977597F428ULL,
		0x4C595D3CC3ADDBB1ULL
	}};
	printf("Test Case 837\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 837 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -837;
	} else {
		printf("Test Case 837 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCCC6EE081247F4DAULL,
		0x5ECF7328A9284137ULL,
		0x534BB78A259A885CULL,
		0x4592C13735A1A335ULL,
		0x6811180D0DFB734BULL,
		0xE3F2DD9696B3600BULL,
		0x386111DF74A0A842ULL,
		0x54D03583279BEE3EULL
	}};
	printf("Test Case 838\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 838 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -838;
	} else {
		printf("Test Case 838 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2F87C07E13E313BFULL,
		0x7A753EC534D5068FULL,
		0xBCB6C558F0E81FD9ULL,
		0x576B644AD99C345FULL,
		0xAF4D816A5BE39AFCULL,
		0x765F7D9E7C7BA43FULL,
		0x8595ED5910969B96ULL,
		0xF2F760CE0860F4AEULL
	}};
	printf("Test Case 839\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 839 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -839;
	} else {
		printf("Test Case 839 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFC8FFF70D563F665ULL,
		0xF43DB7201439D828ULL,
		0xB02984E17F1621BCULL,
		0x5F7B5086B351D865ULL,
		0xE59FEB2CF65EF13FULL,
		0x96599053081A6903ULL,
		0xB66FCF95157A8ADDULL,
		0x41468643EAB1F3B9ULL
	}};
	printf("Test Case 840\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 840 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -840;
	} else {
		printf("Test Case 840 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD9F0ADF94E5F8C4BULL,
		0x531D4B455DF7803BULL,
		0x29208C29EA7B32CDULL,
		0x673F43D268870E46ULL,
		0xDAB85F1ADA221115ULL,
		0x56DBAF7DB5FDACF1ULL,
		0x47A8D3B954F06002ULL,
		0x968219AC0A5B8F39ULL
	}};
	printf("Test Case 841\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 841 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -841;
	} else {
		printf("Test Case 841 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7B19F0880D31CE06ULL,
		0xF9CF39FDFAE8FE0DULL,
		0xBF17F6DAED5B3AF9ULL,
		0x5E164899C25205F2ULL,
		0x44226E263AB517C8ULL,
		0x1FCE3E7F1BB82F8CULL,
		0x3AF1C5A1B7912D93ULL,
		0x77415CAFDB2BC27AULL
	}};
	printf("Test Case 842\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 842 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -842;
	} else {
		printf("Test Case 842 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7510B0D938BF290CULL,
		0x4EE20DCBB6A34E29ULL,
		0x13B7EE8A284AD8BCULL,
		0x45E1BD9092CFA2D3ULL,
		0xC7BA338E883BEF8AULL,
		0x4E2198D1BE133303ULL,
		0x439E27894EA5874CULL,
		0xAD19C77A878C9966ULL
	}};
	printf("Test Case 843\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 843 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -843;
	} else {
		printf("Test Case 843 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x7F05236CEF49CC57ULL,
		0x097CD84F11A1B983ULL,
		0x927E902C3CCDD6FDULL,
		0xA4C5A007D616DD01ULL,
		0x791BE9757958195AULL,
		0xC61AF4347687F1D2ULL,
		0x804EB1BE0AE3C856ULL,
		0x1076E7F9E8AC0722ULL
	}};
	printf("Test Case 844\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 844 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -844;
	} else {
		printf("Test Case 844 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x805CDA17733959A6ULL,
		0xD763EF2BC5AAE73CULL,
		0x3F2E0B3E8E470250ULL,
		0x19646F7D1AB4ECB0ULL,
		0x79C3782534E2BFC4ULL,
		0xC4E1A031E57337D0ULL,
		0x0BEEC653962F00ACULL,
		0xDE1B7FACC618454DULL
	}};
	printf("Test Case 845\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 845 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -845;
	} else {
		printf("Test Case 845 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x46C78FEA663B7306ULL,
		0xDEE30C1441B7A672ULL,
		0x69830950DB92D3FEULL,
		0x7C38F6A883FBCBBEULL,
		0x9ECF960A3A160CFEULL,
		0xDCABAAD17A649695ULL,
		0xF718472208353411ULL,
		0x295C683EBA91B015ULL
	}};
	printf("Test Case 846\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 846 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -846;
	} else {
		printf("Test Case 846 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x95AEEABDE6763C11ULL,
		0x50CD0E3D427F8F2DULL,
		0x64405B25A14609FCULL,
		0xA0D9F9FDF19AA841ULL,
		0x78D9F32B28642061ULL,
		0x29AEADC487460627ULL,
		0x0BCA769D43C5E19EULL,
		0xA0BAD70BC8F4FBA6ULL
	}};
	printf("Test Case 847\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 847 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -847;
	} else {
		printf("Test Case 847 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBD2D141FB63E9754ULL,
		0x6AC142D140089F17ULL,
		0x0A23B993266B488BULL,
		0xE2347E09178DC2C6ULL,
		0x77A510404BA4B44EULL,
		0x704B835A66F3FC06ULL,
		0x95179628D644896AULL,
		0x351EE67ABF8A84C3ULL
	}};
	printf("Test Case 848\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 848 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -848;
	} else {
		printf("Test Case 848 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6222081B8CF4D919ULL,
		0xDA4E2E5E27D4EF3EULL,
		0xAF6397AC1F80FC32ULL,
		0x8E50975FDFD9055AULL,
		0xCEC9C07B0802E60EULL,
		0xDE1AB4F85C7FB727ULL,
		0xCDA20886602152A1ULL,
		0x5BFD04237E4516A6ULL
	}};
	printf("Test Case 849\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 849 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -849;
	} else {
		printf("Test Case 849 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB5737AF1359513DULL,
		0x03859DB6B6D0ACD4ULL,
		0xD1C07CBE3433E0F7ULL,
		0x466379C040784523ULL,
		0x047BE7A7F5129178ULL,
		0x362A5CBE28215054ULL,
		0xED5DDF42FFDB3A20ULL,
		0x915C1A24BB1B0807ULL
	}};
	printf("Test Case 850\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 850 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -850;
	} else {
		printf("Test Case 850 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x10C6619C92D32DC0ULL,
		0x7DAFF41F9302677BULL,
		0xB79728C2E47A464CULL,
		0x6A27CC625509A99FULL,
		0xACAEA76AAD1C4727ULL,
		0x5706A5F2D1E37761ULL,
		0x25972B21884F666AULL,
		0x09483784B9C5676FULL
	}};
	printf("Test Case 851\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 851 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -851;
	} else {
		printf("Test Case 851 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1C2395AD926AFE67ULL,
		0x2F01FC600925A951ULL,
		0xCA35F8EF13744AA8ULL,
		0x6218EE848CBC0509ULL,
		0x6B37097127E1F354ULL,
		0x72A59BF5FC7B1BBFULL,
		0x20DD53F671AD4AB0ULL,
		0x731A342DD6845AACULL
	}};
	printf("Test Case 852\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 852 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -852;
	} else {
		printf("Test Case 852 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x615EF55E77D2F2D8ULL,
		0xC73A5397E5265862ULL,
		0xB05E94818C03BE8AULL,
		0x08C8249883A03412ULL,
		0xFC250A0A6785437CULL,
		0xF52390B08F428E4FULL,
		0xE32E4B5B2EBF3AC0ULL,
		0x68666C8F25AEFFF3ULL
	}};
	printf("Test Case 853\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 853 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -853;
	} else {
		printf("Test Case 853 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7283EE25C6D0BE6AULL,
		0xB5582A669F33AFD4ULL,
		0x5C3BD42DBF219481ULL,
		0xD779379AA7A7612AULL,
		0xB24F3A12BFF6223CULL,
		0x7C76D9A95C878B2AULL,
		0x96DC9B9F2E25FB80ULL,
		0x7FB91B8AEC1536E1ULL
	}};
	printf("Test Case 854\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 854 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -854;
	} else {
		printf("Test Case 854 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFBB30952F296F9CEULL,
		0xA901607CF90BCF4AULL,
		0xAF3FF4E559D087F1ULL,
		0x42E5A506B1AAB517ULL,
		0x2D0A2DD4CDB4180DULL,
		0x8B89E27417CC8CC3ULL,
		0x0053FA6E3E49499DULL,
		0x85845240A85CC066ULL
	}};
	printf("Test Case 855\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 855 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -855;
	} else {
		printf("Test Case 855 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7A87A2F00595AE62ULL,
		0xE1404FBA2082E31FULL,
		0xA24EE69D030CE9A1ULL,
		0xBB8CE2C34BF83212ULL,
		0x548CFCF43B847336ULL,
		0x4051E814729F0516ULL,
		0x9145D9C4BD51765EULL,
		0xD998B6494A364CEFULL
	}};
	printf("Test Case 856\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 856 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -856;
	} else {
		printf("Test Case 856 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x556E689A92EC8C29ULL,
		0x599F0CFF765C0D9CULL,
		0x45A720A577A9675FULL,
		0x8DA0293BE18A50D6ULL,
		0x039F5A7DFF0855C5ULL,
		0x5169AD9384E6049CULL,
		0xEC8D3EADC5983F6AULL,
		0xFACEDA650B6037E6ULL
	}};
	printf("Test Case 857\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 857 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -857;
	} else {
		printf("Test Case 857 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9E782CED8134B71BULL,
		0xDA247945DB5EBE12ULL,
		0x2FA3F4FF3761BB44ULL,
		0x69A5A6EEE43D7CEAULL,
		0x4BAD8F1CFE9BC61AULL,
		0x2A9116596ADBEED1ULL,
		0xA38D17252D425D35ULL,
		0x2DFAC823AB7E6067ULL
	}};
	printf("Test Case 858\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 858 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -858;
	} else {
		printf("Test Case 858 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFEB50D651E5B4501ULL,
		0xA28A7B3D55938F50ULL,
		0xA7A15C473735D7C8ULL,
		0x367103E5F6FCDDE9ULL,
		0xF6C87592151002C1ULL,
		0xCBAA8E0F9C8AE379ULL,
		0x7B20034550CEA594ULL,
		0x6E7C85A60A7157A8ULL
	}};
	printf("Test Case 859\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 859 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -859;
	} else {
		printf("Test Case 859 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x569A138492CA771DULL,
		0xA9EA9DEAA9FF8AAFULL,
		0xD1131742170C04A3ULL,
		0x74A3A7264B570CEFULL,
		0x1BB9C58030DF1DA7ULL,
		0x23EBA1FD1FE11516ULL,
		0xA5754B472861FBE5ULL,
		0x06FA9EDB4E4CCC5AULL
	}};
	printf("Test Case 860\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 860 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -860;
	} else {
		printf("Test Case 860 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3824B437E48244ECULL,
		0x83F4025E39CDDAF6ULL,
		0x8E574DDF23B389B9ULL,
		0x52275D3FB61A0D26ULL,
		0x5EADFB24D1B693CEULL,
		0xF199C28B7CB790F5ULL,
		0x374C16DC1EF43E4FULL,
		0xC00F692C46ECE7E9ULL
	}};
	printf("Test Case 861\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 861 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -861;
	} else {
		printf("Test Case 861 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x60E93C68FFEF57ACULL,
		0x0AA4B6BA1BFFBA97ULL,
		0x8F50AFFB5FD5B157ULL,
		0x32B0892F40F1DF6FULL,
		0xCEBAC64251DD1E43ULL,
		0xB1BBA8BAD037EFDFULL,
		0xFBC0D0A443170EAAULL,
		0x2A1AA273023A8184ULL
	}};
	printf("Test Case 862\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 862 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -862;
	} else {
		printf("Test Case 862 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC2CBBD8A37100CD3ULL,
		0x6E412A8DE482DF60ULL,
		0x4D5197748DD43622ULL,
		0x0396A256849518C2ULL,
		0x428FB35779512E58ULL,
		0x3FCE777F2E97F79BULL,
		0x109D71C61CD4D721ULL,
		0x81EEEFB885884058ULL
	}};
	printf("Test Case 863\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 863 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -863;
	} else {
		printf("Test Case 863 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8047DB23B848398BULL,
		0xFAEEDFFBB0790853ULL,
		0xD871D3D70251B8C5ULL,
		0x71EC162632D09D32ULL,
		0xCC58F6288FD734DFULL,
		0x4AA739E1E124DAE3ULL,
		0x018785971285D496ULL,
		0x2B3B6AC2C5D7C24EULL
	}};
	printf("Test Case 864\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 864 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -864;
	} else {
		printf("Test Case 864 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA95ADCC4BFA3DAA0ULL,
		0xC74E003B9B9E403DULL,
		0x0C4AC94DCC4AEE30ULL,
		0x3F68ADA92A3154D7ULL,
		0xAF066278417F2F1CULL,
		0x5034732910158D4CULL,
		0x012951A5A607F03BULL,
		0x79E097F3562EB871ULL
	}};
	printf("Test Case 865\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 865 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -865;
	} else {
		printf("Test Case 865 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1B01F45B843E953FULL,
		0xA828D4FB8EA4B480ULL,
		0xE14C3880949F0CDEULL,
		0xC4E7A6B7373E661DULL,
		0x2CCE9FB5DB2505B4ULL,
		0xF52F5A5364E1B298ULL,
		0x3A28E848B06A30CDULL,
		0xE9D1253C14595541ULL
	}};
	printf("Test Case 866\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 866 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -866;
	} else {
		printf("Test Case 866 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF2A264BAD7029D88ULL,
		0xDBE947DA698219DAULL,
		0xDD7DA4FBF503D0A0ULL,
		0x0EA78A0559DC6685ULL,
		0x6615235CD7541645ULL,
		0x757687F5427C406BULL,
		0xBF8C06A734A26B7CULL,
		0xDB9B31D7EB9D0BB2ULL
	}};
	printf("Test Case 867\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 867 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -867;
	} else {
		printf("Test Case 867 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE21E60A6914D6B4DULL,
		0xBEDB4B448931619EULL,
		0xCF36C066D75F7882ULL,
		0x46EC95E5C38DB7B0ULL,
		0x90A811C421F9A834ULL,
		0x59CC3139FD399B67ULL,
		0xE0A2CE7C6FB72A89ULL,
		0xD31C51012A475CD6ULL
	}};
	printf("Test Case 868\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 868 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -868;
	} else {
		printf("Test Case 868 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6586455016520ACBULL,
		0xE4C8486E526F2309ULL,
		0x3101AD63B7AB4EEFULL,
		0xB2EA78DB6BD42505ULL,
		0xE7AD64B2D65E56B7ULL,
		0xCBBCEB333D5FC8E2ULL,
		0x6689205E4AB607C0ULL,
		0x344E795793B70C7CULL
	}};
	printf("Test Case 869\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 869 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -869;
	} else {
		printf("Test Case 869 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x389EA38E7EE2E496ULL,
		0x518B3E97629FFED6ULL,
		0x1E8071F5B96D38BBULL,
		0x4A12F265D43C9B0DULL,
		0xABBF5D4926B7C1CEULL,
		0x6DFC863C4CB09D27ULL,
		0x3CFF875A1BA58E5FULL,
		0xF3183E161E670873ULL
	}};
	printf("Test Case 870\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 870 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -870;
	} else {
		printf("Test Case 870 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x17EEAD3E8EB37663ULL,
		0xD5C43F6DE7138FF7ULL,
		0x8B6079E25359C0E2ULL,
		0xE57DDD6303892A9DULL,
		0x4FC48B45A7C4EFDAULL,
		0x6FA058D3E33493C8ULL,
		0xCFE0FD904B9DAE14ULL,
		0x75493AAFC6E8CA04ULL
	}};
	printf("Test Case 871\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 871 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -871;
	} else {
		printf("Test Case 871 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFFAD27BB37FE63CFULL,
		0xA613045D4115F8D7ULL,
		0xA5F07DA5BF92D295ULL,
		0x963572ADAC49BE58ULL,
		0x01A7520B024A3CF1ULL,
		0xB36C604D706675FDULL,
		0xFF140F04D3768B7BULL,
		0xDEDFCE56E679389EULL
	}};
	printf("Test Case 872\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 872 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -872;
	} else {
		printf("Test Case 872 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x62557732DC5896F1ULL,
		0x28419520E328BF27ULL,
		0x10F4E958142A6DF6ULL,
		0xCB797B8E69EC7E91ULL,
		0x53CBECA141DBDA60ULL,
		0xD92C493E2DE9A36EULL,
		0x018368AC9118595AULL,
		0x499B60665FA97472ULL
	}};
	printf("Test Case 873\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 873 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -873;
	} else {
		printf("Test Case 873 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x23B0DBDBA39C4A7EULL,
		0x145E3A364EF2417EULL,
		0xDB060ABBA69D8E8CULL,
		0x2D93CC7DDF21F8DFULL,
		0x7C000FEC6AB3A10EULL,
		0x4C8CC65D773398D1ULL,
		0xD8F1B93C6744D743ULL,
		0x95E9EF8CDCA4AC0DULL
	}};
	printf("Test Case 874\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 874 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -874;
	} else {
		printf("Test Case 874 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x54659424B5DA3ECDULL,
		0xF157AFB767FEEBB2ULL,
		0x9F1A0DB7A929FA2DULL,
		0x60CE06BBB615500FULL,
		0x55AAF69F99046292ULL,
		0x549A07073C2280F8ULL,
		0xD107DA8C4ED64F4AULL,
		0x81CDB0D84DB33C38ULL
	}};
	printf("Test Case 875\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 875 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -875;
	} else {
		printf("Test Case 875 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xEBCF803E3A709A04ULL,
		0x8CE611D939BA1FEDULL,
		0xDCDA7A8CDEE11475ULL,
		0xE7690DF32EBDEE20ULL,
		0x29B368025BF643E4ULL,
		0x5EB5987F5452AA12ULL,
		0xBA0081366F29DAC9ULL,
		0x08DCD4BD53C53FB0ULL
	}};
	printf("Test Case 876\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 876 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -876;
	} else {
		printf("Test Case 876 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA0A1E1DC049238E5ULL,
		0x82392D842316C3F4ULL,
		0xBC6D2B356455C4C8ULL,
		0xC7A4B1E42AFBB203ULL,
		0xE93DE8BBC6DEC19AULL,
		0xA2611AA16F08460DULL,
		0x6649B70931D471A2ULL,
		0x2FF4218A6354A88BULL
	}};
	printf("Test Case 877\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 877 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -877;
	} else {
		printf("Test Case 877 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x400B4D2C5A1E1620ULL,
		0x1ECB8C539447BBB7ULL,
		0x9EBB0EFF8AB391E4ULL,
		0x3A0B71D1EBF70775ULL,
		0x09C8F36D00D93CE1ULL,
		0x4FCDD28944438B09ULL,
		0xFB598AA76532E225ULL,
		0x19995A8F47857D19ULL
	}};
	printf("Test Case 878\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 878 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -878;
	} else {
		printf("Test Case 878 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x022781E81CBB8378ULL,
		0x03BED6DBD456B9CEULL,
		0x26B54C265F9BF888ULL,
		0x9C706123BBF83DF3ULL,
		0x55B71FF41CFAC1CDULL,
		0x280032426ADAE62EULL,
		0x166A0D19C05F5C60ULL,
		0x5020A215DFE4CA1DULL
	}};
	printf("Test Case 879\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 879 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -879;
	} else {
		printf("Test Case 879 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x79ABFCFA8ED27ED9ULL,
		0x5642C400700C5AC9ULL,
		0x8DA9D2F93B3E526DULL,
		0xC62B4EFD083074B3ULL,
		0xCF91F971E33F61C6ULL,
		0x6097890EAB4870F9ULL,
		0x010724F62DE11F5EULL,
		0xF41F42BC4A72BFCBULL
	}};
	printf("Test Case 880\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 880 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -880;
	} else {
		printf("Test Case 880 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC1EFD8FE2B48DFFEULL,
		0x7ED1ABA237C7F0FEULL,
		0xC2F5A57D5CCEC66EULL,
		0xC04228027BE2D01FULL,
		0x4FDDFA7DB9281EB0ULL,
		0x3A5645B7166C24B8ULL,
		0x19FA559BE3D557ABULL,
		0xFBB276A0279B4E31ULL
	}};
	printf("Test Case 881\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 881 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -881;
	} else {
		printf("Test Case 881 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9874E6C80594EEE6ULL,
		0x96A12A619DABC6EBULL,
		0xE76974717D2E8B99ULL,
		0x30C1C6A7A4A676E6ULL,
		0x71F0C1E5E06BD281ULL,
		0xDBAA45928BCA1740ULL,
		0x1C6B2B7897AE5232ULL,
		0x5A95480AABE023E5ULL
	}};
	printf("Test Case 882\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 882 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -882;
	} else {
		printf("Test Case 882 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6C421E2BBC9C9B2CULL,
		0x0FE04489D59439ABULL,
		0xF5E75FA91FE2D819ULL,
		0x0691F56E42CDE8F4ULL,
		0x8479D417CBFFD1CCULL,
		0xF37B5640C9B4BD1CULL,
		0xE01381753B948763ULL,
		0x4A32FD55B40EFC2DULL
	}};
	printf("Test Case 883\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 883 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -883;
	} else {
		printf("Test Case 883 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2F9F5DDD6E9D5F5BULL,
		0xA6FEC778002985F7ULL,
		0x30E2BA0778ACACB8ULL,
		0xA0895ABCF3226BAFULL,
		0x9CA9FA27A0ECD804ULL,
		0xBEEEC9C21B524EF1ULL,
		0x6ACCBE1D3AC83340ULL,
		0x22121576A8B4CEB2ULL
	}};
	printf("Test Case 884\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 884 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -884;
	} else {
		printf("Test Case 884 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x48D6365978FDB8FEULL,
		0x588675E38E4500DEULL,
		0x815C33C481A34D35ULL,
		0xF8190286069316EBULL,
		0x6F98749F12141E6AULL,
		0xABD372D10979A116ULL,
		0x53E5A9AD376B911CULL,
		0x5C1FC8323B0E448CULL
	}};
	printf("Test Case 885\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 885 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -885;
	} else {
		printf("Test Case 885 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBD96A2CB2DF0D77FULL,
		0xB36BCE35CC6C9861ULL,
		0x01BE5E6749880668ULL,
		0xBAA6DAE431B84CDBULL,
		0x8E1FD8B64B2C0095ULL,
		0x43C9ADE67A2353BFULL,
		0x274A403B438B4177ULL,
		0x21382B0C58924C60ULL
	}};
	printf("Test Case 886\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 886 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -886;
	} else {
		printf("Test Case 886 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA3420B1ABD1A0264ULL,
		0xEBE15FD7DC228FD0ULL,
		0xA750F1A20BB2D406ULL,
		0xEEB109C362E55082ULL,
		0xA759D361E69BCF1EULL,
		0x2DB783C68FF6F509ULL,
		0x1F9692218766AC35ULL,
		0x1F510EDAFC0C58A8ULL
	}};
	printf("Test Case 887\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 887 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -887;
	} else {
		printf("Test Case 887 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE684ECD560767C58ULL,
		0x491A79B6E9175563ULL,
		0x6E27F91D67A609E4ULL,
		0x7F6DCB77AEA98B67ULL,
		0x952DE309F7E57D6EULL,
		0xE206FB7EAD7BF078ULL,
		0x86D998B96A226E13ULL,
		0xEF0FD22D2B4763C1ULL
	}};
	printf("Test Case 888\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 888 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -888;
	} else {
		printf("Test Case 888 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8373760177099BB6ULL,
		0x718270AF3C5C7E8AULL,
		0x22C7BD221E79460DULL,
		0xE1986656D4F006F2ULL,
		0xC48521CC38240E2DULL,
		0xCA14813D8B4659C3ULL,
		0xF70F31136E212F37ULL,
		0xFE30BAC976FDF92EULL
	}};
	printf("Test Case 889\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 889 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -889;
	} else {
		printf("Test Case 889 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x61C65A38994A6640ULL,
		0x6B93E555333AE196ULL,
		0xFFA6300D29428E87ULL,
		0xE6EAE10E3525CC1CULL,
		0xE1C01833C03F0BD5ULL,
		0x155DCE3279898BDBULL,
		0xEFEF65F23AF1ECF0ULL,
		0xFA8B8F9F786CFEA2ULL
	}};
	printf("Test Case 890\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 890 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -890;
	} else {
		printf("Test Case 890 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC6E65E3DE0905780ULL,
		0x3FB8F91CCDC3A363ULL,
		0x6801CBA2E55ED85BULL,
		0x9131F88EEB4D4C58ULL,
		0xE6F9CE5A85DC14CEULL,
		0x747C529F54D30397ULL,
		0xF949355BC5691E0EULL,
		0x24864A603599E6A3ULL
	}};
	printf("Test Case 891\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 891 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -891;
	} else {
		printf("Test Case 891 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1590382683DB4DE0ULL,
		0x2AC5A453A77AD38CULL,
		0x307C710DEC6CCAB7ULL,
		0x42D9DEB993DF94C3ULL,
		0xC6991F21B5662B00ULL,
		0x0BC00A197404C8AEULL,
		0xA68739BDA96C53C5ULL,
		0x529A08E9A213F735ULL
	}};
	printf("Test Case 892\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 892 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -892;
	} else {
		printf("Test Case 892 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF42D44B64C895F51ULL,
		0xA51900F44FAED5D3ULL,
		0x35E8E0492245D5E8ULL,
		0xA8C293FE889CB178ULL,
		0xD649C85A44AD0AE9ULL,
		0x6F57D02B33C60494ULL,
		0x26EB0AD005FB5CF3ULL,
		0xFD6B9C119BDD8587ULL
	}};
	printf("Test Case 893\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 893 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -893;
	} else {
		printf("Test Case 893 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x1AD943D6AAD90123ULL,
		0xBAA4AF0F6A28D1C0ULL,
		0x0066772D6359881AULL,
		0xC171F40767EA8A3CULL,
		0xB1F85259B94E3C42ULL,
		0x3B52D51A393561B8ULL,
		0x03D7C6EF49463979ULL,
		0x0358A2B3A5C23CC2ULL
	}};
	printf("Test Case 894\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 894 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -894;
	} else {
		printf("Test Case 894 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x62D4ADBDFCFAF1E1ULL,
		0x2023245C31D730BBULL,
		0x1702D1B99733ABCEULL,
		0x1FE468C689B22D23ULL,
		0x8C94F813B2734D3EULL,
		0x85D2FD8BAF58CFC4ULL,
		0x5132D7977B684CDAULL,
		0xDC6AFDC46974EDE1ULL
	}};
	printf("Test Case 895\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 895 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -895;
	} else {
		printf("Test Case 895 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8CE54C2B47FF2CBAULL,
		0x8DE8A9AA04CBE032ULL,
		0xA2C1D06B3689F1D8ULL,
		0x1DE9876B9F2F19EBULL,
		0xF3E3EDECA540ED36ULL,
		0x3E3336583C77492EULL,
		0x8BA8950ECF58D841ULL,
		0xFA595764F3080851ULL
	}};
	printf("Test Case 896\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 896 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -896;
	} else {
		printf("Test Case 896 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0CCC5F0C529694F7ULL,
		0x2A3940CBDAAC3EE2ULL,
		0xCABBC5D206749EEDULL,
		0x88286C35DFEE7A40ULL,
		0x714927E6D6E91118ULL,
		0x51DFE5367761AF65ULL,
		0x71324F2861CC0319ULL,
		0x1ADBFEF2CC234D78ULL
	}};
	printf("Test Case 897\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 897 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -897;
	} else {
		printf("Test Case 897 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x67F7DD80F7EEF8A7ULL,
		0x27248177BC8AACF4ULL,
		0xC4BD0430D1369160ULL,
		0x460DE1921F478723ULL,
		0x5E1CC344CE94A98AULL,
		0x59D522106C40FBF5ULL,
		0x06E87B4CED8D7CA1ULL,
		0x3EC3871C667949F2ULL
	}};
	printf("Test Case 898\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 898 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -898;
	} else {
		printf("Test Case 898 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7DD71F82C5419E6FULL,
		0xDA73C8ED1C7B2524ULL,
		0x7C28BFD84C9EE748ULL,
		0x7A789F0BD6AB5FA6ULL,
		0x4412B6BCF1F197D8ULL,
		0x0FAE69F3EC8067AAULL,
		0x1345983DC9E93DC7ULL,
		0xE781EAC0298AB1FCULL
	}};
	printf("Test Case 899\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 899 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -899;
	} else {
		printf("Test Case 899 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8C66571D7A072603ULL,
		0x6C03A7A06C1A08EBULL,
		0x354E4B307B6734D2ULL,
		0x1A9309BF7A973511ULL,
		0x707DEF461B247A0FULL,
		0x58B7B1437AE6D98BULL,
		0xE4BECEF85E7555A2ULL,
		0x462C14BC50056C42ULL
	}};
	printf("Test Case 900\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 900 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -900;
	} else {
		printf("Test Case 900 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC2C7ACC179E50470ULL,
		0xD9A0E09B9789AD20ULL,
		0xADA3D5908C0EBA57ULL,
		0xF55B63A6C2F95790ULL,
		0xE630E8DE5D1B198FULL,
		0xCAC372FFD4662555ULL,
		0xA903FCB15D8E8FFEULL,
		0x402C2DE515AA11B2ULL
	}};
	printf("Test Case 901\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 901 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -901;
	} else {
		printf("Test Case 901 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9EF52336CC5D2C4FULL,
		0x5BC10DDE1564F199ULL,
		0xE5A94636AC93E109ULL,
		0x3E9053E6151D332EULL,
		0x1C82813B02629BBFULL,
		0xC62DC95F47B60D4EULL,
		0xD4EB92013A5B2A64ULL,
		0x2BB5E4B3D823C2D6ULL
	}};
	printf("Test Case 902\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 902 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -902;
	} else {
		printf("Test Case 902 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x646AD36C68041217ULL,
		0x5D80AC354B5F0ED0ULL,
		0x036D5805E48C1892ULL,
		0x53C5433E6EF49255ULL,
		0x10B5BB7F99016985ULL,
		0xDC9C27911BD64828ULL,
		0x4349FE9DC7044B1EULL,
		0x8248BE89401812B8ULL
	}};
	printf("Test Case 903\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 903 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -903;
	} else {
		printf("Test Case 903 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x05493767F96E6D42ULL,
		0xDC955126FF27DA78ULL,
		0x3A6C782E959BE289ULL,
		0x87B09F13E25BAADEULL,
		0x141D70B6370CBFF2ULL,
		0xB0F297BBB5E18F5EULL,
		0xA54096944E25C2FDULL,
		0x714AA80649EFDD1BULL
	}};
	printf("Test Case 904\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 904 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -904;
	} else {
		printf("Test Case 904 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE1912E402F3BA84AULL,
		0xE7EE4BAA95162209ULL,
		0xF2BAEDD445BBBF0AULL,
		0x1046D4AABF1A7373ULL,
		0x48B00C3EBBBF948EULL,
		0x560E3B91D7321E82ULL,
		0xD0B2BF6447327080ULL,
		0x14DDBB0EBA96BE81ULL
	}};
	printf("Test Case 905\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 905 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -905;
	} else {
		printf("Test Case 905 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4E33405D6B51EC1DULL,
		0x9AD8C55059FD70E7ULL,
		0xDEF8C915D837AB9DULL,
		0x2CFA8F5A9A0525B5ULL,
		0xABCC8FBD68C73B46ULL,
		0x7DAA3F1943676ECBULL,
		0x9848CB1E45C3AF1CULL,
		0x809DBBB63A063CF9ULL
	}};
	printf("Test Case 906\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 906 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -906;
	} else {
		printf("Test Case 906 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3278D30FC502250CULL,
		0xB136669D9F13B572ULL,
		0xF98B9A7ABB666671ULL,
		0xDB4EFE46E4959271ULL,
		0x81A79C2BF4526619ULL,
		0x96FFFFCF8CF30C9EULL,
		0x6D2489CF76A58E4BULL,
		0x8A92D80F1F2F5A1FULL
	}};
	printf("Test Case 907\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 907 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -907;
	} else {
		printf("Test Case 907 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5D1E4B7E46A6109BULL,
		0xB512035AD68D2E0FULL,
		0x876B5C2192B60CD5ULL,
		0x9F711BC92D519882ULL,
		0x3047E40408B6AFF5ULL,
		0x0A1BB6288FA8FE5FULL,
		0x94D70F81F683A279ULL,
		0xDEC4288E5E7B323BULL
	}};
	printf("Test Case 908\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 908 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -908;
	} else {
		printf("Test Case 908 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFDB630EE9C852AE6ULL,
		0x6B746772C2A5CFBFULL,
		0x6F34A5CB030E6EE8ULL,
		0x9E82755307BA458AULL,
		0x2B90626E93A3F78BULL,
		0xABF6A2842FFF8FE8ULL,
		0xF10EF26D70CFEF3EULL,
		0x53C8BDD59AFD1A61ULL
	}};
	printf("Test Case 909\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 909 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -909;
	} else {
		printf("Test Case 909 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2A96DF89DC46B1E8ULL,
		0x50F91B282187C2B1ULL,
		0x075848296F0315CFULL,
		0x2703BE6F0FFCA378ULL,
		0x868E2B4139AB42A2ULL,
		0x2A57D90361EA007FULL,
		0x9DDBA453DE2999AAULL,
		0x5E31C703D925146AULL
	}};
	printf("Test Case 910\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 910 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -910;
	} else {
		printf("Test Case 910 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDDC4D32BC0EFCABEULL,
		0xBAF1AC16E161464FULL,
		0xCB7F75FA3D9FB83DULL,
		0x2E1C674F503BBDDBULL,
		0x2FE1DEF853B05221ULL,
		0x6D1EDCFFFB66A664ULL,
		0x48CAB54699E315ECULL,
		0x5136D35D0C2256F9ULL
	}};
	printf("Test Case 911\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 911 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -911;
	} else {
		printf("Test Case 911 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x04BE65E9BA6B83EDULL,
		0xFB54F2F7F9DD45ABULL,
		0x5C149E26B3393208ULL,
		0xF02C79ADAB8E52F5ULL,
		0x909C75DF10212CB7ULL,
		0x0698354E1A9CB44CULL,
		0x5027F4695A7E473AULL,
		0x70776ED3E188B507ULL
	}};
	printf("Test Case 912\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 912 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -912;
	} else {
		printf("Test Case 912 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1FE84E779FC28C14ULL,
		0x40E8D119F4E1170DULL,
		0x808C8052690DCD40ULL,
		0x0015413B0581AD94ULL,
		0x3418158D618E5C8EULL,
		0x6A8A27866443AFBAULL,
		0xD866BB489D400768ULL,
		0xCC7FACF6648A7E88ULL
	}};
	printf("Test Case 913\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 913 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -913;
	} else {
		printf("Test Case 913 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x9ADCD54FCD420262ULL,
		0x0A6D3EA336F26FEDULL,
		0x1C7ACAB684757C61ULL,
		0xFC912386A3416E7DULL,
		0x5910060839066498ULL,
		0x23B8479748D9E934ULL,
		0x452FC19A67F2D9CAULL,
		0x06512DE7A0869A93ULL
	}};
	printf("Test Case 914\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 914 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -914;
	} else {
		printf("Test Case 914 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFC380F4C10D23FC5ULL,
		0x8D232CAEC1EF143CULL,
		0x6A8E216624DB0A52ULL,
		0x4579C6C6B10448E6ULL,
		0x133B7DE3EAAB6CE5ULL,
		0x6678425FE45FD48EULL,
		0xB3090C274267FB90ULL,
		0x52FA15CA1EED0C31ULL
	}};
	printf("Test Case 915\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 915 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -915;
	} else {
		printf("Test Case 915 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7087012114544A1EULL,
		0x8760852E99ED08D9ULL,
		0x8C9606FB2E1D51D2ULL,
		0x41558B2EC6B59E8CULL,
		0x3075901AA2A556C6ULL,
		0x6EFFEBB3F4B4D433ULL,
		0x98E6A27C67E84C6CULL,
		0xC6BD1CCE3F170AA3ULL
	}};
	printf("Test Case 916\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 916 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -916;
	} else {
		printf("Test Case 916 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xA844ED55F8A2AB4DULL,
		0x4AFD930D095271BAULL,
		0x2F813C6A0EA12936ULL,
		0xE38792FBB7435DECULL,
		0x66FCAC52ACE46EA8ULL,
		0x1B3A4CFF20C83689ULL,
		0x3932CAED39255763ULL,
		0x05B4AC19E0F54BF6ULL
	}};
	printf("Test Case 917\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 917 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -917;
	} else {
		printf("Test Case 917 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x61F5486E9775A62BULL,
		0x58C73E569622DD89ULL,
		0x97C2A8873663D9A8ULL,
		0x3FAD62F4D3E05C24ULL,
		0xB72730843D862D91ULL,
		0x2F7BE75D2A656D8EULL,
		0x908F54BE18C27700ULL,
		0x9F50741F2B401A50ULL
	}};
	printf("Test Case 918\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 918 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -918;
	} else {
		printf("Test Case 918 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x01160989EB868524ULL,
		0xF04E99462AEFB227ULL,
		0xDA7B074D89118869ULL,
		0x41AE72CBB53C9D65ULL,
		0x926BA8B36CFAFF07ULL,
		0x0391EC5F7E62BA3FULL,
		0x3F63D2B4D1D6B5FCULL,
		0x0B30955FFF68379CULL
	}};
	printf("Test Case 919\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 919 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -919;
	} else {
		printf("Test Case 919 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x7001C62AAED655FFULL,
		0x6F93F0C30D4FB7A8ULL,
		0x7BDF06DC0459E827ULL,
		0x2F4867F62B3FE1A0ULL,
		0x2C6B707FFCCB8095ULL,
		0xBE7AECC61703ECB5ULL,
		0x3C57872C231F0872ULL,
		0x11C45855627FD883ULL
	}};
	printf("Test Case 920\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 920 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -920;
	} else {
		printf("Test Case 920 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDE4BB56AF1F07113ULL,
		0x5ADEA95B09709B20ULL,
		0x9C2C1ED371B62DE9ULL,
		0x1785BCC47E09B5D9ULL,
		0x0D8CDE6E756D93CFULL,
		0x5D3923EF870F8CEAULL,
		0x518B8F47DA580465ULL,
		0x5E042BEFC05199BAULL
	}};
	printf("Test Case 921\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 921 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -921;
	} else {
		printf("Test Case 921 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6C9671162ED1F76FULL,
		0xF0CD0AB1E56E9C08ULL,
		0x0D1F0041F441E441ULL,
		0x98A593080F8D3251ULL,
		0xA1B580432877ED22ULL,
		0x252F81D0C4BC48BCULL,
		0xE35EC475E3F87013ULL,
		0xF17FE9B137034F8BULL
	}};
	printf("Test Case 922\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 922 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -922;
	} else {
		printf("Test Case 922 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x216AB24157CC98DAULL,
		0xBF977FABDF604E44ULL,
		0x796266743A3A77D2ULL,
		0x9F151C310AC23699ULL,
		0x330790BE154B3492ULL,
		0x1126601A47590C59ULL,
		0x75F0EEE496A736F4ULL,
		0x3526E82D0101FA40ULL
	}};
	printf("Test Case 923\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 923 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -923;
	} else {
		printf("Test Case 923 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xED86E7D8BD7B3F0FULL,
		0x2A104F9320F43532ULL,
		0xF380D91EB7CB609EULL,
		0x85FDEE8EB5CF9C25ULL,
		0x82F7D4D7069A03A5ULL,
		0xD152523649FEF5CBULL,
		0xA3A6240B5B5B979EULL,
		0xB12C19E3F0FF6D73ULL
	}};
	printf("Test Case 924\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 924 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -924;
	} else {
		printf("Test Case 924 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC87D190170CBB040ULL,
		0x6163E8586CCAF643ULL,
		0x3B805DED721E0290ULL,
		0x524CBF664F940F60ULL,
		0x1CE565B7F4D6EBC8ULL,
		0xD4C89E75B4D7DA77ULL,
		0x36237C5E00F6A989ULL,
		0x503BACC21BC28069ULL
	}};
	printf("Test Case 925\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 925 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -925;
	} else {
		printf("Test Case 925 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB2AD11363C9BC937ULL,
		0xC8ED19F08B8F3EA4ULL,
		0xB37E0A9758610365ULL,
		0xB36F300833CAB56EULL,
		0xF3F0129016EF7C03ULL,
		0x869EE3A78FA27F92ULL,
		0xCCEAFAC45E59A8C5ULL,
		0xAFC479367D7BEEB1ULL
	}};
	printf("Test Case 926\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 926 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -926;
	} else {
		printf("Test Case 926 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD54F936CDC50E0CEULL,
		0x901773EEF75C06E1ULL,
		0xB4B4C63E59E95EF4ULL,
		0xBB158904E95F3822ULL,
		0x74CF15D4516A478AULL,
		0xD96B4C3A9DC35A71ULL,
		0x5B7E50FDF1984CE3ULL,
		0x2CE9F538F8C68E62ULL
	}};
	printf("Test Case 927\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 927 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -927;
	} else {
		printf("Test Case 927 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x3A06C1EC7EFDF989ULL,
		0x8C9D2355CAD25FB3ULL,
		0xBBFB24C8D8EC8E83ULL,
		0x5F6643B71120CE21ULL,
		0xCA340D29A2197418ULL,
		0xD17BC9189910DA73ULL,
		0xD024EC4ABA218CACULL,
		0x111C35B10E0EAA51ULL
	}};
	printf("Test Case 928\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 928 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -928;
	} else {
		printf("Test Case 928 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB33A6999BD4CEEE6ULL,
		0x7429A41922914206ULL,
		0x9ECF4357BD5861E6ULL,
		0xB332C6C59546BEA4ULL,
		0x78C4FC0A4A3609A9ULL,
		0x4C75703D5D63897BULL,
		0x7CEA5BF65BD935D6ULL,
		0x590CA39848172953ULL
	}};
	printf("Test Case 929\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 929 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -929;
	} else {
		printf("Test Case 929 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xE8F8DD7D124EA7FDULL,
		0xF2D59771B7FDBE3BULL,
		0x4EAC53C5DA587E8EULL,
		0x3A40D71040B26A3BULL,
		0x52A3ED5149E3B554ULL,
		0xB11E908277DE1405ULL,
		0xF3F4A408C45C9D9DULL,
		0x0BD2A4693BAB7A4FULL
	}};
	printf("Test Case 930\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 930 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -930;
	} else {
		printf("Test Case 930 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6B5C76188FF33CD1ULL,
		0x709D98946B120D1DULL,
		0x278F7A5E1A24BBC4ULL,
		0x4A8E0F51176597E5ULL,
		0xAD18786D29317E0CULL,
		0xBDAAE6FD2845BC3FULL,
		0x28C0425AF13204AFULL,
		0xC42FF2D83AA47B7FULL
	}};
	printf("Test Case 931\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 931 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -931;
	} else {
		printf("Test Case 931 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x119618B2508CF455ULL,
		0x57E6D1BA28465F3CULL,
		0x868E30846AF885BDULL,
		0x284F2342D0EAE473ULL,
		0xAE0FAB64327BDA44ULL,
		0x8BC0EF864B5632FCULL,
		0x6A382568230D19F2ULL,
		0x2089A998E63E7469ULL
	}};
	printf("Test Case 932\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 932 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -932;
	} else {
		printf("Test Case 932 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1AB1F6400B6C5DBFULL,
		0x9733636F0FCCAC22ULL,
		0xF5C3BD8F102FAE14ULL,
		0x422A97EF1F9A745EULL,
		0x330E831A335BFE9FULL,
		0xF3DB855B1853AD9AULL,
		0x4E7FD061EBEB8417ULL,
		0x3374FFFB56049148ULL
	}};
	printf("Test Case 933\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 933 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -933;
	} else {
		printf("Test Case 933 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDAEF4453CAB6200CULL,
		0xDA3A5A0C2231C97CULL,
		0xA54DEBCF5EBB4EB1ULL,
		0x2388398273B978DFULL,
		0x8E706B337575F024ULL,
		0xBFF86C10B3763346ULL,
		0x5DB4E8C6AB2E6483ULL,
		0x8EEC19A532174A7BULL
	}};
	printf("Test Case 934\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 934 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -934;
	} else {
		printf("Test Case 934 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x303DA9DAD4734E2CULL,
		0x005D7A8CE4B9C12BULL,
		0x32F2D7995B7D7C8AULL,
		0x97F8BA8040164BA1ULL,
		0x65F63CFFFBFF7FE4ULL,
		0x2F96B57AB9237E87ULL,
		0xA4E79A9940D63A83ULL,
		0xFCFF596569EC33EAULL
	}};
	printf("Test Case 935\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 935 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -935;
	} else {
		printf("Test Case 935 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2615944FEC3D76BCULL,
		0x53CDFB90501BBC0AULL,
		0x3D6FC0157C76D390ULL,
		0xD7455651A29E14FAULL,
		0x85A7118C26132F11ULL,
		0x63DBAAFC55EA28BBULL,
		0x4BA41D0BA5BDF1F3ULL,
		0x4A25B883EDF15EC5ULL
	}};
	printf("Test Case 936\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 936 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -936;
	} else {
		printf("Test Case 936 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEF0498A89C0004DCULL,
		0x2F796868F7BA81DFULL,
		0xDD17B22093F6B4E0ULL,
		0x58030B8BF92A6705ULL,
		0x50649C4B1B340440ULL,
		0x72722B74A6E6B13FULL,
		0xC5E34888DB8B7F2FULL,
		0x76EF61F0324B50DEULL
	}};
	printf("Test Case 937\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 937 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -937;
	} else {
		printf("Test Case 937 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2A6FB84FBC619472ULL,
		0xF34ABA3D652EEA1EULL,
		0x2BA556A93D59624FULL,
		0xDEBF135889BEB7BBULL,
		0x05E5BEEA568A1AC9ULL,
		0x0449C98F252322FCULL,
		0x23ECD700F8D1E861ULL,
		0x3CA232A116A2C25AULL
	}};
	printf("Test Case 938\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 938 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -938;
	} else {
		printf("Test Case 938 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB9532FAED493D78DULL,
		0xEA35F6739EBFE457ULL,
		0xE9362FE6DB12062BULL,
		0xB9EF3F8F8AF431F0ULL,
		0x2984ECB46192C685ULL,
		0x9BA17CCA98FE07FDULL,
		0xCA974906C96F7EFEULL,
		0xD181E5D9EE1C2AD2ULL
	}};
	printf("Test Case 939\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 939 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -939;
	} else {
		printf("Test Case 939 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8B5450AD89E68197ULL,
		0xAEAC2159B2BFE3DAULL,
		0xFD350C54A2F2D65DULL,
		0x96D172A4557978A4ULL,
		0xBDEF5A883C1A1567ULL,
		0xD130D1B31BC78BC5ULL,
		0x245CBE48E9E5E32DULL,
		0xC371542395FB8009ULL
	}};
	printf("Test Case 940\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 940 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -940;
	} else {
		printf("Test Case 940 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE0C983BD396F9069ULL,
		0x98B23DA0B26FBA4BULL,
		0x855D6C5C2B13931CULL,
		0x17B4BC792E92B7A7ULL,
		0xA0F1F991039E5970ULL,
		0xCEB3CE85DE04592AULL,
		0x8E8844052146BFEBULL,
		0xBD428B17E15975D0ULL
	}};
	printf("Test Case 941\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 941 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -941;
	} else {
		printf("Test Case 941 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3725C71026BC3736ULL,
		0x3397B64BA71EFF2FULL,
		0xE825BEB3DE40B45BULL,
		0x47C08AA3A199077AULL,
		0x077CF998E9506E02ULL,
		0x7E73BEE41ACAA24EULL,
		0xD0FE319ED76C19D1ULL,
		0x2412E6EC3CBE4CEDULL
	}};
	printf("Test Case 942\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 942 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -942;
	} else {
		printf("Test Case 942 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xDC01204A8E9D4DBEULL,
		0x1E587C141C81705EULL,
		0xB48B6BEDCDA6956DULL,
		0xD575DBFC1F29292FULL,
		0xEF48ADFD7DF58D01ULL,
		0x1211AA1AC488C728ULL,
		0x152624DAB7E8346AULL,
		0x084A44B91CE2FE7BULL
	}};
	printf("Test Case 943\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 943 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -943;
	} else {
		printf("Test Case 943 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAA1D43774823D4D6ULL,
		0x0FA7BBFC2D7FB3ECULL,
		0x53507143A859F968ULL,
		0xC13D9D2796BD3FBFULL,
		0x7577F62455258BE7ULL,
		0xDFEBF17023161785ULL,
		0xAF34632D6CCF2227ULL,
		0x587384FBDCD1ADE4ULL
	}};
	printf("Test Case 944\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 944 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -944;
	} else {
		printf("Test Case 944 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x8F79C037FC595A4BULL,
		0x937E913A72F7B253ULL,
		0x0315DB861E721CC6ULL,
		0x5F9247D204D60BFDULL,
		0xBA0007353E97AA76ULL,
		0xDB7384AA0C10E746ULL,
		0x33CABFE0CF0F576EULL,
		0x1C3A24CB357D9809ULL
	}};
	printf("Test Case 945\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 945 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -945;
	} else {
		printf("Test Case 945 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5967521D06E2625AULL,
		0xA002116B5612C73FULL,
		0x06B4016320F7C2E6ULL,
		0x8CC525BDEAD69FFCULL,
		0x47FEEBAE3A200447ULL,
		0x0AEEB0596F86C388ULL,
		0x6A6EE158F1530139ULL,
		0x659A444E78CC7399ULL
	}};
	printf("Test Case 946\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 946 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -946;
	} else {
		printf("Test Case 946 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBA4B87A2153938F4ULL,
		0xBD26AD584A5074E8ULL,
		0xF1312FF6EDFA29AFULL,
		0x23E2800BBF030760ULL,
		0x03CE859819D8828AULL,
		0x4A03AE2CA6698861ULL,
		0xE5509C018F45C11BULL,
		0x235DB450D5793BE5ULL
	}};
	printf("Test Case 947\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 947 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -947;
	} else {
		printf("Test Case 947 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x71BEF7E4FAD96F00ULL,
		0x52F319C8BBB5AADCULL,
		0x7D7DE59DD989CF40ULL,
		0x951D38609B8F7FD8ULL,
		0x71BB9F9478EFC862ULL,
		0x61B36DD3D15AA803ULL,
		0xC3E051C5D99BC517ULL,
		0x7316D8F811F8AF8AULL
	}};
	printf("Test Case 948\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 948 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -948;
	} else {
		printf("Test Case 948 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE852AD823846D22CULL,
		0xE321E53FD3DFCCE2ULL,
		0x1699796949EECE91ULL,
		0x4D0AEF736A1DF20BULL,
		0xDFE794566D47FD85ULL,
		0x635E5395371E1EF2ULL,
		0x247E35485BA29BB8ULL,
		0x3C32D9B843DF47EFULL
	}};
	printf("Test Case 949\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 949 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -949;
	} else {
		printf("Test Case 949 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEA8C5CB0B2E62CFDULL,
		0xD416F79B66D7963AULL,
		0xF316C02A662B4E92ULL,
		0xD897C88E03E1E9FFULL,
		0x18AA7B69F2308C0BULL,
		0x0657DBCA3DD1B661ULL,
		0x3D4F442AEDF0D06AULL,
		0x75E8BBD438F49BBFULL
	}};
	printf("Test Case 950\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 950 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -950;
	} else {
		printf("Test Case 950 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD8AF4E353485D469ULL,
		0x58E78B0635F5C9E6ULL,
		0x8635717EA374A7E5ULL,
		0xB91EF28CCC99CE8AULL,
		0x222C107103E20428ULL,
		0x7F2DA99DF6E8D70CULL,
		0xBF1988B2AFCF4B91ULL,
		0x896E922D5CA8A825ULL
	}};
	printf("Test Case 951\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 951 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -951;
	} else {
		printf("Test Case 951 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2BB33BB3BC2C337DULL,
		0x8318C5A472FB68A4ULL,
		0x72F1049393822F05ULL,
		0x85277766431D7B37ULL,
		0xF24F5A929B54A359ULL,
		0xBBB1E8D27EEEB997ULL,
		0xC41994AEEDF7634FULL,
		0x9A23718D4DF44C54ULL
	}};
	printf("Test Case 952\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 952 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -952;
	} else {
		printf("Test Case 952 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0F57C14FDE86EDA6ULL,
		0xF9BE2F786092B7B1ULL,
		0xE6B985093D7BD539ULL,
		0xBEB0EB2645077B6EULL,
		0xC7E29FB40AB70E20ULL,
		0x2C016D3396356F85ULL,
		0xA9F6AB2F80873ADCULL,
		0x22A005B573403942ULL
	}};
	printf("Test Case 953\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 953 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -953;
	} else {
		printf("Test Case 953 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5D32A5FAF0CB4F30ULL,
		0x199DA8726CEB34F0ULL,
		0xE544CDB7F427D69AULL,
		0x70F1AD733F148AFBULL,
		0x1AC0D9C64E2BF545ULL,
		0xCA1468695CDF3D87ULL,
		0x0954BF6DB44AD1D3ULL,
		0xB812655CB85F431BULL
	}};
	printf("Test Case 954\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 954 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -954;
	} else {
		printf("Test Case 954 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xABE0E517C4029D96ULL,
		0x34660B4140941B21ULL,
		0xBF0F06C3EAE83313ULL,
		0xAB0235EF79F961C6ULL,
		0x51204C0D31837BE1ULL,
		0xC607275D12ED9160ULL,
		0xEA468F09313BAE81ULL,
		0x4B3943CF89F731A4ULL
	}};
	printf("Test Case 955\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 955 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -955;
	} else {
		printf("Test Case 955 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x941128F50D0C830FULL,
		0x3B9380B27B6016C6ULL,
		0xCDB585D2E50ADD97ULL,
		0xC591016EF72D83A1ULL,
		0x7D9323E5C3C562B4ULL,
		0x3A0F6B891DDB957DULL,
		0xA257B0051D75950AULL,
		0xB58BBD13E219470DULL
	}};
	printf("Test Case 956\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 956 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -956;
	} else {
		printf("Test Case 956 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x2C051483E548B03AULL,
		0xE9876729A435BE5FULL,
		0xDDC194291480FC58ULL,
		0xF84E6026B8C186FDULL,
		0xA156D0FB848B980BULL,
		0x619F2BCA59120E64ULL,
		0x5710CB8EE9BA114FULL,
		0x0E37C1F6185E04E5ULL
	}};
	printf("Test Case 957\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 957 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -957;
	} else {
		printf("Test Case 957 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7C9DCA636C1E4F72ULL,
		0xC2900A2CC1D05135ULL,
		0x7D81F7465B5B6646ULL,
		0xD188B9405847621DULL,
		0x3DDADB3C3040529AULL,
		0x27D14297723C9E33ULL,
		0x03E90A19427D4C50ULL,
		0xFC7629ACAE3FE20CULL
	}};
	printf("Test Case 958\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 958 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -958;
	} else {
		printf("Test Case 958 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6425902D79D9664AULL,
		0x2FCC233FD0513AA0ULL,
		0xD28316395BD38481ULL,
		0xCBD4BFBC4DC99985ULL,
		0xFAF8BD8CC834F8F5ULL,
		0xBCB507E493849432ULL,
		0x0705D5C48F0A3762ULL,
		0x232BE659938AB186ULL
	}};
	printf("Test Case 959\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 959 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -959;
	} else {
		printf("Test Case 959 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8FE2A71017734BB2ULL,
		0xBB17E1ACEC51EB6EULL,
		0xED60080E244F25BBULL,
		0xE0C9C5EAC3F3BC45ULL,
		0x04EB1AA73151035CULL,
		0x6DF7C1427C718B80ULL,
		0x1F62B7AF0C805DA3ULL,
		0xF665EA591E306790ULL
	}};
	printf("Test Case 960\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 960 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -960;
	} else {
		printf("Test Case 960 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7F8F542084E3C322ULL,
		0xFCA04F33D484D3C8ULL,
		0x0A7545F1DB0D5FF0ULL,
		0x152C89C5A2DBCD3EULL,
		0x4DBC968FD0172F61ULL,
		0x7417A4CF5E248ABEULL,
		0x5EB7F2FA123C027CULL,
		0x2F06129688750DC6ULL
	}};
	printf("Test Case 961\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 961 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -961;
	} else {
		printf("Test Case 961 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7C719D20D18C3DB2ULL,
		0xEFC4D6A0A6472CB1ULL,
		0x634CAEB6459CCFFAULL,
		0x73940D276B46F75FULL,
		0x5C48812E6F0112FDULL,
		0x61B6E79334DDC3B0ULL,
		0x707FA803364793A7ULL,
		0x59BA59778C997D2BULL
	}};
	printf("Test Case 962\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 962 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -962;
	} else {
		printf("Test Case 962 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x844E20E9082AD462ULL,
		0x0F3020476ACC4C8CULL,
		0x0442A167CA487F32ULL,
		0xB6E405DB5BC170BFULL,
		0xB567DB0F29854152ULL,
		0xC1D5934C9DEC25B2ULL,
		0xDD6F088110C6996FULL,
		0x34294AE33B67E206ULL
	}};
	printf("Test Case 963\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 963 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -963;
	} else {
		printf("Test Case 963 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA88BA28BF90FD21BULL,
		0xC93E18C078ACE5D6ULL,
		0x69A14FAC7ADAE52AULL,
		0x3C42FB7FDB3FFCEBULL,
		0xC0EDA75421056469ULL,
		0x644B4506BB172144ULL,
		0x0D23281819C96313ULL,
		0x1D8EFE743ED1388DULL
	}};
	printf("Test Case 964\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 964 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -964;
	} else {
		printf("Test Case 964 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x35E0271961A15DD6ULL,
		0x23A8265C72F47F36ULL,
		0x7C103718AD0F8530ULL,
		0x2B3A8063CFBE3479ULL,
		0xAF01319829C654B4ULL,
		0xE52F43BBE9E187B3ULL,
		0x05139F8CC001E4CCULL,
		0x38A371278D2978F6ULL
	}};
	printf("Test Case 965\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 965 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -965;
	} else {
		printf("Test Case 965 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5B49F9C64B434B7BULL,
		0xB82462F1ED957826ULL,
		0x19C1CE104F8F33F5ULL,
		0x059B576BEF9A5D24ULL,
		0x9CE9474344759481ULL,
		0x6BA1A6666A00E99FULL,
		0x9779EF1BE4B7A1F4ULL,
		0xE76B4A3A64BF2090ULL
	}};
	printf("Test Case 966\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 966 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -966;
	} else {
		printf("Test Case 966 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFFC1E2D3A6B992F0ULL,
		0x05717E4E9721EE74ULL,
		0x7620EF6981656A58ULL,
		0xAE107A2C2043FFF9ULL,
		0x16E03C4C3F98C593ULL,
		0x1D86D3FE37F66654ULL,
		0xE1EC521AF19ACECBULL,
		0xD3ABD6C42B6DDCDAULL
	}};
	printf("Test Case 967\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 967 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -967;
	} else {
		printf("Test Case 967 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA56A811932310FFCULL,
		0xC7D69CE677C2A8A4ULL,
		0x4CC72C4143F42939ULL,
		0x8F2059805CA6EC78ULL,
		0xFEC88814954A8C69ULL,
		0x6550F342C744AC47ULL,
		0xE68C0E71FB1CF2D7ULL,
		0xB7130C7B50D640F4ULL
	}};
	printf("Test Case 968\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 968 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -968;
	} else {
		printf("Test Case 968 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCEB8E640DB48888BULL,
		0x6D3097D65BFC2C0CULL,
		0x39021D8FD0E7C261ULL,
		0xCB2F74BD20DBD7E7ULL,
		0x9277F6154A5F4E62ULL,
		0x6268CC97DD91B220ULL,
		0x058927AB26DD00C8ULL,
		0xBCC6BE6136F49826ULL
	}};
	printf("Test Case 969\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 969 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -969;
	} else {
		printf("Test Case 969 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x01D24C014C93811BULL,
		0xE3259763E433A694ULL,
		0x9C683E532B6BF3B5ULL,
		0x67825715A62AD5A5ULL,
		0x01F1B9C816E6271AULL,
		0x9429A6B7400CD44BULL,
		0x5B7B1EF723A908DEULL,
		0xA646D67DB5C4FD52ULL
	}};
	printf("Test Case 970\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 970 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -970;
	} else {
		printf("Test Case 970 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x16B339F18CEC7549ULL,
		0x1BD975961798C776ULL,
		0x41E8DF4C3604A619ULL,
		0xD2711209F3A95403ULL,
		0x83F2B065530F6E29ULL,
		0xCA86BA1954D1703AULL,
		0x42E657EA23319611ULL,
		0x021F5D14B01076BDULL
	}};
	printf("Test Case 971\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 971 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -971;
	} else {
		printf("Test Case 971 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3FB60EB7A5DEE302ULL,
		0x69FEBEC5C756583FULL,
		0x5D26F69DF126E1FBULL,
		0x4756A82171A3C95BULL,
		0x862A3488271F2704ULL,
		0x0736997102E6180DULL,
		0x413EC0D7E420713DULL,
		0x3286517EE98D945AULL
	}};
	printf("Test Case 972\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 972 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -972;
	} else {
		printf("Test Case 972 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xA9BCAA5D3C3E8498ULL,
		0xA04B99611E8907D2ULL,
		0x0D1E46E2E68674CBULL,
		0x3ED8C2769C084F7EULL,
		0xF594FC9FC3C83FFCULL,
		0xB8A606BCE949EF6CULL,
		0x38FDF55A87EF4095ULL,
		0x0EA5E691A4841967ULL
	}};
	printf("Test Case 973\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 973 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -973;
	} else {
		printf("Test Case 973 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7CF5571B6E16482AULL,
		0x84553A583C735802ULL,
		0xA8F9BE96C9A7671AULL,
		0x7974F6B84884CF77ULL,
		0x909B1138F6637C8FULL,
		0xE75ADB4C5452670AULL,
		0x64A1DD3CBF08858FULL,
		0x227F694CA9CB82A9ULL
	}};
	printf("Test Case 974\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 974 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -974;
	} else {
		printf("Test Case 974 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC20150D3733212DEULL,
		0x6F439ECC057E8CA7ULL,
		0x8654EC128EC3DE54ULL,
		0x92A9DB936A22BB53ULL,
		0xED8C904B5907D01FULL,
		0x01CED25983BEA0ADULL,
		0x6F7FAD3D561CEF16ULL,
		0x559EA23322F0B1BAULL
	}};
	printf("Test Case 975\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 975 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -975;
	} else {
		printf("Test Case 975 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7E164206719A058CULL,
		0x48C276AF02DFC5BBULL,
		0xE61961C147D4FD72ULL,
		0x5C2FC9904FB0E5F1ULL,
		0x0079551A1510E388ULL,
		0x52E83D68AB1D58F1ULL,
		0x616369F933888F6FULL,
		0x58150D062194AC37ULL
	}};
	printf("Test Case 976\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 976 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -976;
	} else {
		printf("Test Case 976 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x73349B63E2DD60C1ULL,
		0x4417C0E89741E537ULL,
		0x2B11B658351967D5ULL,
		0x4DDF21A27782B1D0ULL,
		0x74EF83AEEAF601C3ULL,
		0x5DC8822B20DFC15BULL,
		0xC4EEF9C299C7E31AULL,
		0xB11F480D1FB12F18ULL
	}};
	printf("Test Case 977\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 977 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -977;
	} else {
		printf("Test Case 977 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA42B8D602C32C8ABULL,
		0x0567ECB6C87CAE09ULL,
		0x07C782EAACF8E182ULL,
		0xF91667A0F87CE16AULL,
		0x30B0A6693E7E3C71ULL,
		0xD509F6781A578222ULL,
		0x599BB14433C3BBC7ULL,
		0x7BE353EE2F97F36DULL
	}};
	printf("Test Case 978\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 978 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -978;
	} else {
		printf("Test Case 978 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1929AB893002D725ULL,
		0xE14A1ADCD0A6F4C7ULL,
		0x50B16893D9F9349AULL,
		0x78988525B24B38E5ULL,
		0xB6FAA1B2E98C210FULL,
		0xB10BCB2D22F7AD2FULL,
		0x11E916CA8F5217E3ULL,
		0x88503541AB752ADBULL
	}};
	printf("Test Case 979\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 979 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -979;
	} else {
		printf("Test Case 979 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x5F8AB336DD3C3580ULL,
		0x2254E9D20649125BULL,
		0x312631CB0432FD14ULL,
		0x162899DECFE946C8ULL,
		0x757D9141423FAC30ULL,
		0x3A0ABC43DA60F641ULL,
		0x9350C5C177D4079FULL,
		0x1658530AE5F9E613ULL
	}};
	printf("Test Case 980\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 980 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -980;
	} else {
		printf("Test Case 980 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x432FAF49F96AD0FAULL,
		0x9A4659A327738EEBULL,
		0x157DC924E110DEF3ULL,
		0x4707B12225789A6CULL,
		0x2ABB9239CF6A5991ULL,
		0x0F64DF291A120ED9ULL,
		0x7CDEF0B6E5A89F47ULL,
		0xABD24B152905D12AULL
	}};
	printf("Test Case 981\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 981 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -981;
	} else {
		printf("Test Case 981 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x127034A264ACA86FULL,
		0xDD4B6620DB7A5CF8ULL,
		0x17E2EBD734DE17D3ULL,
		0x5DBC2FDC33765EDEULL,
		0xE79AB932EC1266A3ULL,
		0x9717317F587F9E98ULL,
		0x904060AE4FB7F042ULL,
		0xEA5FF521CE1A274CULL
	}};
	printf("Test Case 982\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 982 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -982;
	} else {
		printf("Test Case 982 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8EAFA7F315ACFA41ULL,
		0xDC86E80E3C77D7E8ULL,
		0x683B7CBCA3FA5F52ULL,
		0xEB2E2A441613D2E3ULL,
		0x614D4D6B1880495AULL,
		0x46B794D2771A9875ULL,
		0x4070B9794FC7DD09ULL,
		0x7DF4D1ECB80FFFF4ULL
	}};
	printf("Test Case 983\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 983 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -983;
	} else {
		printf("Test Case 983 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB6C383954DB24958ULL,
		0x7B6CD5C96C675CB2ULL,
		0xD5754AE8FE32EE98ULL,
		0x83E45FBF5E319DBDULL,
		0x305A929842D0852EULL,
		0x79D087C162414797ULL,
		0x9F40A9FA9C6F56EFULL,
		0x52385DCBE89DF938ULL
	}};
	printf("Test Case 984\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 984 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -984;
	} else {
		printf("Test Case 984 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x991993F840CE7E71ULL,
		0x4349B70D129D9F3EULL,
		0xD643D5E4B30FF430ULL,
		0xCDE0590E5D8AC644ULL,
		0x9DC01BED9A26759EULL,
		0x65A2513DD0DE7353ULL,
		0x2B4AE4C0C2178D3DULL,
		0xD5D359F4304E3776ULL
	}};
	printf("Test Case 985\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 985 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -985;
	} else {
		printf("Test Case 985 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAABA8B602465D6D2ULL,
		0xE7103BD061AFF5F9ULL,
		0x876DF4618ECD12FDULL,
		0xF2DF9E7B75C9E171ULL,
		0x7B4C9294E031E3ADULL,
		0xB4FDC2193AC44013ULL,
		0xAA34B9A482B71245ULL,
		0xED29B624DADB7189ULL
	}};
	printf("Test Case 986\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 986 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -986;
	} else {
		printf("Test Case 986 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0FF496D56CAC2BFFULL,
		0xD117DE8A26788FFBULL,
		0x2280C88D79DF86EDULL,
		0x945DB711CC966505ULL,
		0xD185F23E708831B3ULL,
		0xE13667F2E1FC02A0ULL,
		0xF83D1682B969B27EULL,
		0xA6F4DEC42B1FB845ULL
	}};
	printf("Test Case 987\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 987 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -987;
	} else {
		printf("Test Case 987 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBD5B1313AC01FE2EULL,
		0xABB4FAFE6AFD99F5ULL,
		0x427692C54955209DULL,
		0x28819939BF7E66CAULL,
		0x08096EC7D35CED21ULL,
		0xCA8BB45466018444ULL,
		0x69BE52B4EEECF007ULL,
		0x816D4E7D855950DFULL
	}};
	printf("Test Case 988\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 988 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -988;
	} else {
		printf("Test Case 988 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFB631004F2343A19ULL,
		0xB7BBCC70F426CD5CULL,
		0x977AE82C44CEC39EULL,
		0xAD928F03B44D8AD3ULL,
		0x3362C180BFC3AC16ULL,
		0xC480C775E2FACA21ULL,
		0x3C94A526E23A9F13ULL,
		0x89FBB102326BA467ULL
	}};
	printf("Test Case 989\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 989 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -989;
	} else {
		printf("Test Case 989 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x14C98FF0A268F2BEULL,
		0x150617377485DC63ULL,
		0x4E90417EF670D4A6ULL,
		0x8899F8C9E308F7B1ULL,
		0x91145FCA6A797224ULL,
		0xB9B8B55AE4DC2907ULL,
		0xE93A763FFDD0E4CAULL,
		0xDF4E72ACBD259669ULL
	}};
	printf("Test Case 990\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 990 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -990;
	} else {
		printf("Test Case 990 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2DA2C4FE6BF0537BULL,
		0xAE20FA056DE12A4AULL,
		0x54E91C25A480DE10ULL,
		0x9CAA6E7F28DA8C45ULL,
		0xAEC308DF9DB608B1ULL,
		0x5ED38C53C572ED16ULL,
		0x5DB04C9D556CE453ULL,
		0x606F91B3D8C7BCE3ULL
	}};
	printf("Test Case 991\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 991 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -991;
	} else {
		printf("Test Case 991 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6EE8F48D91812954ULL,
		0x87F3E3E1148AD96AULL,
		0xF5343D8CF6AB9B1AULL,
		0x46978956A5E85319ULL,
		0x9CE38800749DD81AULL,
		0x9B05505889C53104ULL,
		0x498BE09C2138636BULL,
		0x59E18D07264EA967ULL
	}};
	printf("Test Case 992\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 992 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -992;
	} else {
		printf("Test Case 992 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8187EAC597482362ULL,
		0x1E58B8F37B1AA19AULL,
		0x2F41C4213ACAE082ULL,
		0xBD35CF0E2A4B817BULL,
		0xA8055267F2A6722DULL,
		0xA63B5CC210B18B59ULL,
		0x914B764609769CCDULL,
		0x768C5A5FED0B78C8ULL
	}};
	printf("Test Case 993\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 993 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -993;
	} else {
		printf("Test Case 993 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD5ABA4A7FE421317ULL,
		0x48625C437670C8ACULL,
		0x3C041A5D9018811BULL,
		0x32430B08530693D1ULL,
		0x56442BC782B5004DULL,
		0x496B6E42D309C3B1ULL,
		0xCCA0FB14ACCA99E0ULL,
		0xFB7375905509BA0AULL
	}};
	printf("Test Case 994\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 994 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -994;
	} else {
		printf("Test Case 994 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCA0EEC619AE9C85EULL,
		0x0F7A8A54BAE97FC4ULL,
		0xE110AD8F3FB066F1ULL,
		0xCBF34C29F7CEDA44ULL,
		0xBE6D556CCE89B490ULL,
		0x18A59089A0D87AD0ULL,
		0xFDF31D6D819985F0ULL,
		0xEB2E8052638AE523ULL
	}};
	printf("Test Case 995\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 995 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -995;
	} else {
		printf("Test Case 995 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD67371DE98AE26EBULL,
		0xA6456D205E1C5D8BULL,
		0x0319AFC64FAC8639ULL,
		0xDC29993ADF74B1BCULL,
		0x64EA9A60A01D46B6ULL,
		0x315D2C2017D2EDD1ULL,
		0xDBA4839728F72005ULL,
		0x5EA2363436771193ULL
	}};
	printf("Test Case 996\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 996 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -996;
	} else {
		printf("Test Case 996 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCEFA6794D73FCAD3ULL,
		0x66A57ACB512DE6B9ULL,
		0x645AAFACD18398E2ULL,
		0xD32799E9EBBF3E98ULL,
		0xC78F5F93C5B9F830ULL,
		0xA4C5D9ECED1B23F1ULL,
		0xBC40DBEBA9D3E2FDULL,
		0xFF34402BC1BF6741ULL
	}};
	printf("Test Case 997\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 997 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -997;
	} else {
		printf("Test Case 997 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2B87A4052EDEFA09ULL,
		0xBAE680F797BE1B51ULL,
		0x85C4BE6180261B20ULL,
		0xD72EBDA399230EF7ULL,
		0xC6BFF737A0FA8FDBULL,
		0x297A68DD320322ABULL,
		0x012D4CFE5E6E971EULL,
		0xDD0DF8005F0CA8B6ULL
	}};
	printf("Test Case 998\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 998 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -998;
	} else {
		printf("Test Case 998 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2B5EE83C5721E196ULL,
		0xA5CC2C2CB419FBB7ULL,
		0xF7E26C7DE1731480ULL,
		0x5FAD089C7FB4E797ULL,
		0x22A736C1F299145CULL,
		0xA18381BF46636E78ULL,
		0x84DB535C448C4845ULL,
		0xB105B13D6590CAD1ULL
	}};
	printf("Test Case 999\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 999 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -999;
	} else {
		printf("Test Case 999 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9C14775480E8EE40ULL,
		0xB7AD2A790850A710ULL,
		0xCB4A4D84FF06B1F0ULL,
		0x30DA3C83BADD4B64ULL,
		0xBCACF073A234128EULL,
		0xF243F8887F061168ULL,
		0x9D90AAEB996DF83EULL,
		0x28C8BD3B4BA984A7ULL
	}};
	printf("Test Case 1000\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 1000 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1000;
	} else {
		printf("Test Case 1000 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}