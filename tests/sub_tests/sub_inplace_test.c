#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0xDD2FFFCC5496465AULL,
		0xE42E80F435A75E5FULL,
		0xD5BB9ECCBB4B7D32ULL,
		0x07B509F059FC5AE4ULL,
		0x7C4C2F5F28320513ULL,
		0x402BBFEA51AAA82FULL,
		0x59F0186AACF0B4E0ULL,
		0xDE22913C7A63F883ULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0x956AF7A9D2FFEC43ULL,
		0xCFA6C970D9313922ULL,
		0x08E2844090702118ULL,
		0xC17D0D97471C2909ULL,
		0x91C5B3045F333964ULL,
		0x83C9CECEE0C4BB2CULL,
		0xAF9679DA26F48A86ULL,
		0xE72CBE0B150D3D58ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x47C5082281965A17ULL,
		0x1487B7835C76253DULL,
		0xCCD91A8C2ADB5C1AULL,
		0x4637FC5912E031DBULL,
		0xEA867C5AC8FECBAEULL,
		0xBC61F11B70E5ED02ULL,
		0xAA599E9085FC2A59ULL,
		0xF6F5D3316556BB2AULL
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
		0x6AC36B7AFA7C5FB5ULL,
		0xE7FED1543EBA7E3CULL,
		0x605916B8C07E2850ULL,
		0x4D922DFC127B0E59ULL,
		0x3B1041F55671C278ULL,
		0x768095B9A7530E27ULL,
		0x2ED58680EBDCE296ULL,
		0xD638678E2DED4D96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64904E15303B7AB9ULL,
		0xFEB278E2EEFFE317ULL,
		0xCE9835F7A6355954ULL,
		0xF8666BBCCC86F2CAULL,
		0x5BA286AA6516E8B4ULL,
		0x8E90657905DF5C42ULL,
		0xE3217F03A73FD591ULL,
		0xF90D1EDAC4257F29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06331D65CA40E4FCULL,
		0xE94C58714FBA9B25ULL,
		0x91C0E0C11A48CEFBULL,
		0x552BC23F45F41B8EULL,
		0xDF6DBB4AF15AD9C3ULL,
		0xE7F03040A173B1E4ULL,
		0x4BB4077D449D0D04ULL,
		0xDD2B48B369C7CE6CULL
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
		0x6A795BF01FEECC0DULL,
		0xA628E373C9F725C4ULL,
		0x3AD20937C020DA95ULL,
		0x9EEFCEF8D4FFA457ULL,
		0x4D73359ED4BEF02DULL,
		0xF63617E43C5DB6DDULL,
		0x0B293432623DAC41ULL,
		0xCA94158A337B0F17ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A43413C8140AD2AULL,
		0x75B3BF7414C2414DULL,
		0x7E3ED6287023BCCEULL,
		0xC5BAF8234CC027D0ULL,
		0x4B38DFE379243FA8ULL,
		0x22BFFFFECA4D0064ULL,
		0x1B16B07FA7C3F4B2ULL,
		0x51F1E5AD9E7F367FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30361AB39EAE1EE3ULL,
		0x307523FFB534E477ULL,
		0xBC93330F4FFD1DC7ULL,
		0xD934D6D5883F7C86ULL,
		0x023A55BB5B9AB084ULL,
		0xD37617E57210B679ULL,
		0xF01283B2BA79B78FULL,
		0x78A22FDC94FBD897ULL
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
		0x6AB70C1DC2D5AB63ULL,
		0xC76B4459A4913752ULL,
		0x619F4383BD327E13ULL,
		0x2850C3FFA8AC0719ULL,
		0xE4818FD1BAC31FF0ULL,
		0x66CE8FE006809DABULL,
		0xD5969C100DBD49D4ULL,
		0x8191C6903A1151B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x029170F7813FAE67ULL,
		0xB455A81C4F5C1B05ULL,
		0x9A7188C2D7F5D958ULL,
		0x8C001D349FE26997ULL,
		0x8596C94CA46A474AULL,
		0xABA794AC2BE7B19BULL,
		0xC9DA54180B6377A4ULL,
		0xB6A6A5A75F1F89ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68259B264195FCFCULL,
		0x13159C3D55351C4DULL,
		0xC72DBAC0E53CA4BBULL,
		0x9C50A6CB08C99D81ULL,
		0x5EEAC6851658D8A5ULL,
		0xBB26FB33DA98EC10ULL,
		0x0BBC47F80259D22FULL,
		0xCAEB20E8DAF1C80DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x56322E357E4CAE78ULL,
		0xA0CE93A2EBB2DD86ULL,
		0x59089260C47F977EULL,
		0x894432F03591F1B5ULL,
		0xE328D2BC9D7910D4ULL,
		0x7DA648524A678C1FULL,
		0x835512ECCF215051ULL,
		0x195BE7F92348E307ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x293CDBF910117409ULL,
		0x83777059B98D9F86ULL,
		0x42C6C4A5A354DD02ULL,
		0x56A081634B08F5F5ULL,
		0xBFAA215BCFA4CA81ULL,
		0xE70432CCF0D1155CULL,
		0x98A88FFD02F7AF31ULL,
		0x9557EDBCA2815E4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CF5523C6E3B3A6FULL,
		0x1D57234932253E00ULL,
		0x1641CDBB212ABA7CULL,
		0x32A3B18CEA88FBC0ULL,
		0x237EB160CDD44653ULL,
		0x96A21585599676C3ULL,
		0xEAAC82EFCC29A11FULL,
		0x8403FA3C80C784B8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2E9AE4D02DF0EF4EULL,
		0x11C2E859D3F58764ULL,
		0x4F8D6B9C2904ED8AULL,
		0x6036D18FF931D4BBULL,
		0xBEB71ACEAC97FBA5ULL,
		0xB44D4DD3AB46F759ULL,
		0x06586EC810479EB6ULL,
		0x345469BA3FEE7B7EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA81B9ABA56B5099ULL,
		0x78594D9B69605BAFULL,
		0x644F0FA637710395ULL,
		0x8D1BFA53A43053FCULL,
		0xF57DCF07FA0147C7ULL,
		0x636D207B4405A840ULL,
		0x7F56C517B743B06CULL,
		0x39539330ABDD7CEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54192B2488859EB5ULL,
		0x99699ABE6A952BB4ULL,
		0xEB3E5BF5F193E9F4ULL,
		0xD31AD73C550180BEULL,
		0xC9394BC6B296B3DDULL,
		0x50E02D5867414F18ULL,
		0x8701A9B05903EE4AULL,
		0xFB00D6899410FE8FULL
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
		0x2695D693BD59A4F9ULL,
		0x138FA4D0FADAA2F3ULL,
		0x08D9CA19DDD6EAC5ULL,
		0xD5B16E7007F1C3FBULL,
		0x41BCAA531AB04559ULL,
		0x6CB5B40B93420D95ULL,
		0x74D694A10E2A28FEULL,
		0x7D6D0742881567B7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB9AC72F5CC316AFULL,
		0xB68E758D519CA70CULL,
		0x3873CEBD2CC6AFDEULL,
		0x553534A75273C504ULL,
		0x6C331DA0AFF52293ULL,
		0xAC157540B8E01A6DULL,
		0xCF9ADECFA7DD6EF0ULL,
		0x68735549972B6EAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AFB0F6460968E4AULL,
		0x5D012F43A93DFBE6ULL,
		0xD065FB5CB1103AE6ULL,
		0x807C39C8B57DFEF6ULL,
		0xD5898CB26ABB22C6ULL,
		0xC0A03ECADA61F327ULL,
		0xA53BB5D1664CBA0DULL,
		0x14F9B1F8F0E9F908ULL
	}};
	sign = 0;
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
		0xBAE22D64050C7452ULL,
		0xE0C6332546C1D2A6ULL,
		0x894F150A41B2B64EULL,
		0xF5E7BDF478E3315AULL,
		0x875318652570A516ULL,
		0x805EC0235CE968B3ULL,
		0x94AB79D0D8E965DBULL,
		0x2776B9F603C7EC3FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC1A41C8E2E5D1DULL,
		0x8BAC1DEBBAB2DFD1ULL,
		0x577FDD2F81B63088ULL,
		0xB2ABF91565E81D07ULL,
		0x33CF7E752D9AE82AULL,
		0x7B5EE7B66C16CD9FULL,
		0xFAC0897510D9C1C2ULL,
		0xE706756F22F6E5A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD20894776DE1735ULL,
		0x551A15398C0EF2D5ULL,
		0x31CF37DABFFC85C6ULL,
		0x433BC4DF12FB1453ULL,
		0x538399EFF7D5BCECULL,
		0x04FFD86CF0D29B14ULL,
		0x99EAF05BC80FA419ULL,
		0x40704486E0D10697ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF4EDB3CC47957E99ULL,
		0x2AC52F99A2991DA6ULL,
		0x091FF0B2E2EC254DULL,
		0x4362FB7466473F47ULL,
		0xA53D8B2E5D391763ULL,
		0xA131E75A7897B5B9ULL,
		0x3C15CCEE8D307F13ULL,
		0xB6B9205C4123CA62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92E90031B4829E9ULL,
		0x69174C84B878C5ACULL,
		0x8C3C2D75E6B2FB09ULL,
		0xD9F4FF7BBB902BE5ULL,
		0x2DEE25757540EB49ULL,
		0xCB573906566ECF56ULL,
		0x7BD5F88669E88132ULL,
		0x8D4119F64FBFCEA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BBF23C92C4D54B0ULL,
		0xC1ADE314EA2057FAULL,
		0x7CE3C33CFC392A43ULL,
		0x696DFBF8AAB71361ULL,
		0x774F65B8E7F82C19ULL,
		0xD5DAAE542228E663ULL,
		0xC03FD4682347FDE0ULL,
		0x29780665F163FBC0ULL
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
		0x8ED71873D5497AE3ULL,
		0x423110960389DF19ULL,
		0x9D066CD8324972A5ULL,
		0xF50C4416DECF47CCULL,
		0x609129F8E56ADEA9ULL,
		0x396F68815B261C07ULL,
		0x9E9C922FC158B2B2ULL,
		0x2D0D8B6CD018E6CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4593F1E5D2ACFAULL,
		0xF6ED8AAFE2A6A169ULL,
		0x4C20E7472FD88214ULL,
		0x55E5A9C3FA7CE7FEULL,
		0xBA4F3F3C7008F5B6ULL,
		0x7976D7E0B03CEFEDULL,
		0x368AE3BA3079647AULL,
		0x65405157A2884AC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23918481EF76CDE9ULL,
		0x4B4385E620E33DB0ULL,
		0x50E585910270F090ULL,
		0x9F269A52E4525FCEULL,
		0xA641EABC7561E8F3ULL,
		0xBFF890A0AAE92C19ULL,
		0x6811AE7590DF4E37ULL,
		0xC7CD3A152D909C08ULL
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
		0x7C65FF6E29C20218ULL,
		0x48FFA6A526687217ULL,
		0xCC25634C67DC9E66ULL,
		0xB079A52ECA748819ULL,
		0x31B1A8A6C24F0ED9ULL,
		0x3704CF461F871352ULL,
		0x7752B2CF6BB217D9ULL,
		0x867C418C036C0D8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD910165F1709368FULL,
		0x49F57A7DDA893CD2ULL,
		0x3D8194A00EB21F3FULL,
		0xB9B3E2C88AC90E82ULL,
		0x69CA4E9F90C45FE9ULL,
		0x9C1A6EA76D3B32F0ULL,
		0x9B838E3AC90DAA92ULL,
		0x9288D1F3E9DAB06FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA355E90F12B8CB89ULL,
		0xFF0A2C274BDF3544ULL,
		0x8EA3CEAC592A7F26ULL,
		0xF6C5C2663FAB7997ULL,
		0xC7E75A07318AAEEFULL,
		0x9AEA609EB24BE061ULL,
		0xDBCF2494A2A46D46ULL,
		0xF3F36F9819915D1DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFA87820338E6E5A6ULL,
		0xC0CBF2C5C1B118B0ULL,
		0xF2BC6E04F781F551ULL,
		0xA01CB4AF471AC631ULL,
		0xA4DA77D790150396ULL,
		0x4676DFA5F9298E54ULL,
		0x315DA553BB030F1AULL,
		0xD69CC841F95AD173ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x526ED4EEB6012F9DULL,
		0xD9B28B8E5DDD791AULL,
		0x13EF45B5FB9FF484ULL,
		0x4EE8A758A7965DCFULL,
		0x61D75359165883A8ULL,
		0x21C15B85BB2D1335ULL,
		0x57B83EE0823D5B50ULL,
		0xD6D395DA5F74E8C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA818AD1482E5B609ULL,
		0xE719673763D39F96ULL,
		0xDECD284EFBE200CCULL,
		0x51340D569F846862ULL,
		0x4303247E79BC7FEEULL,
		0x24B584203DFC7B1FULL,
		0xD9A5667338C5B3CAULL,
		0xFFC9326799E5E8B2ULL
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
		0xAD999D35117D68B2ULL,
		0xF0EDF2DD6F042F85ULL,
		0x123775A2BABC290EULL,
		0x29DA7B89D99D577EULL,
		0xCE867D316CCCDE4BULL,
		0x12B747FD28CA3ACAULL,
		0x5E63AC90EDB1AC48ULL,
		0x7178A701B6AE5906ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0410B7265858F774ULL,
		0x4C39FC8476A65D28ULL,
		0x7F04B5474AFE3DB9ULL,
		0xAB2E0570871B961BULL,
		0x0212443C6890A9FAULL,
		0xBADF8CA5CD030310ULL,
		0xF5338229738B6EC8ULL,
		0xADB38055F41C9BEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA988E60EB924713EULL,
		0xA4B3F658F85DD25DULL,
		0x9332C05B6FBDEB55ULL,
		0x7EAC76195281C162ULL,
		0xCC7438F5043C3450ULL,
		0x57D7BB575BC737BAULL,
		0x69302A677A263D7FULL,
		0xC3C526ABC291BD17ULL
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
		0x873ECA86B8D6C5FAULL,
		0xDAF5894321C9719BULL,
		0x93714D1BB1F2228EULL,
		0x0F2B707F6F239E65ULL,
		0xF9C9A42D4BFC60C6ULL,
		0x953DD9A61F9B187FULL,
		0x59776E6A5CA30AD3ULL,
		0xCCC5C92EA67B4916ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D159721F31F9C0ULL,
		0xA6B0CDD4BBAB6E4FULL,
		0x38664D1DDB1ED49FULL,
		0x2DE73EF1B6DD28C9ULL,
		0x9FE3FEB496B0892DULL,
		0x784FF3C093E3C31AULL,
		0xEC6DB2A4603517E1ULL,
		0x9C0D669E7EA943BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x246D711499A4CC3AULL,
		0x3444BB6E661E034CULL,
		0x5B0AFFFDD6D34DEFULL,
		0xE144318DB846759CULL,
		0x59E5A578B54BD798ULL,
		0x1CEDE5E58BB75565ULL,
		0x6D09BBC5FC6DF2F2ULL,
		0x30B8629027D20558ULL
	}};
	sign = 0;
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
		0x76D10EDAA8488431ULL,
		0x0EFA28EA6518B9D0ULL,
		0x39AD5CE438B937FAULL,
		0x9573EDEE15C0EF2BULL,
		0x0135BDA7DE191618ULL,
		0xBC25ECD93CB6FE6DULL,
		0x7C6DB7F1467138CFULL,
		0xD6BF6933CDDC2B41ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AEF9922E9E6BD9EULL,
		0x289E3DD60A7EB8B5ULL,
		0x6CB87FAEBBAF0658ULL,
		0xBF54B1AC5A5200FFULL,
		0x5C8CF31B797D0E98ULL,
		0x44C74D5B1A209A5BULL,
		0xD7DDC65E36A57CCAULL,
		0xF68AB0557758170DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BE175B7BE61C693ULL,
		0xE65BEB145A9A011BULL,
		0xCCF4DD357D0A31A1ULL,
		0xD61F3C41BB6EEE2BULL,
		0xA4A8CA8C649C077FULL,
		0x775E9F7E22966411ULL,
		0xA48FF1930FCBBC05ULL,
		0xE034B8DE56841433ULL
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
		0xE8D3DBF20CE6B72AULL,
		0xE09EE8FF56F8A619ULL,
		0x2E87C637FD423F96ULL,
		0x3AC3E9319CE6CDCBULL,
		0x57BBCEA3344A7C53ULL,
		0x31F723BDA488372DULL,
		0x1FFCF2578E1C4CBDULL,
		0x3C4220405E1226F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB82F6A71CEF58BF0ULL,
		0xE198F1AB13D3C97EULL,
		0x50368AEDE2833A4CULL,
		0xEC4231B96DB35DD5ULL,
		0x7BA318125DC064CCULL,
		0x2501C8C125DBFA4FULL,
		0xA7EC2113012BBB42ULL,
		0xA9E4A48A5CA53D42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30A471803DF12B3AULL,
		0xFF05F7544324DC9BULL,
		0xDE513B4A1ABF0549ULL,
		0x4E81B7782F336FF5ULL,
		0xDC18B690D68A1786ULL,
		0x0CF55AFC7EAC3CDDULL,
		0x7810D1448CF0917BULL,
		0x925D7BB6016CE9B3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC9D37DC8A415A7ADULL,
		0xDE911825C067C937ULL,
		0xB4285D8206FE9D2FULL,
		0x50FB06DF8DA09B2AULL,
		0xD526EABC86A4C1CFULL,
		0xA64E0C3A5618B5FEULL,
		0x6575890FF0781651ULL,
		0xD6E646B68236404DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BDE7FDB7AC65D58ULL,
		0x6D1FE3E54343CB0BULL,
		0x963DF3F8D3D87092ULL,
		0x606DC270DF9172DAULL,
		0x53A65BD48621EF5DULL,
		0x27446BB2E113F21CULL,
		0x583B7A88BCDEE3BEULL,
		0x54EDA642DFFDD1EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DF4FDED294F4A55ULL,
		0x717134407D23FE2CULL,
		0x1DEA698933262C9DULL,
		0xF08D446EAE0F2850ULL,
		0x81808EE80082D271ULL,
		0x7F09A0877504C3E2ULL,
		0x0D3A0E8733993293ULL,
		0x81F8A073A2386E63ULL
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
		0x81282719E8A122BBULL,
		0xDD55A013D6870617ULL,
		0xDAA62507DF37E785ULL,
		0x91FFA411003E7BB6ULL,
		0xFFD77AA1A855C96AULL,
		0xAEE6B3A241B2FCABULL,
		0x0A636D39B5DBAB71ULL,
		0x5E87676446639229ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C1F528397BD57BDULL,
		0xD2D8B8BE52803ABAULL,
		0x5BA17560721D85C2ULL,
		0xF6721BF2039F353EULL,
		0xAAFB575CF3093431ULL,
		0x19A7CC427CBE740EULL,
		0xCB7A0F9F08342E3CULL,
		0xFB550D9C4F9CC3DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6508D49650E3CAFEULL,
		0x0A7CE7558406CB5DULL,
		0x7F04AFA76D1A61C3ULL,
		0x9B8D881EFC9F4678ULL,
		0x54DC2344B54C9538ULL,
		0x953EE75FC4F4889DULL,
		0x3EE95D9AADA77D35ULL,
		0x633259C7F6C6CE4EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1C7706A99D7311FAULL,
		0xECD30269922B7611ULL,
		0x2B8FEF9EDBB6A80AULL,
		0x57B95C48902608C7ULL,
		0xF8B7B8040E6E8684ULL,
		0xC0C4DCFA18689DA8ULL,
		0x79EEFE131142ED75ULL,
		0x408B9C87388B9175ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB03E4C7570218A69ULL,
		0x29701C4B607C8F58ULL,
		0x75FCA33E4032A3A7ULL,
		0xD0C22B9F208049E1ULL,
		0x452429CE988A6DD2ULL,
		0xB15D67C650E5779DULL,
		0xA977B9D8C9E8150AULL,
		0x246CB73BC8D17C80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C38BA342D518791ULL,
		0xC362E61E31AEE6B8ULL,
		0xB5934C609B840463ULL,
		0x86F730A96FA5BEE5ULL,
		0xB3938E3575E418B1ULL,
		0x0F677533C783260BULL,
		0xD077443A475AD86BULL,
		0x1C1EE54B6FBA14F4ULL
	}};
	sign = 0;
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
		0xCB92F854A8F0663CULL,
		0x02C3A8A28CB15C17ULL,
		0x264B036415388EE5ULL,
		0xBEA604A8EA868A0AULL,
		0x7BBCE5AF9E693935ULL,
		0x23B7A5C534966B28ULL,
		0x9A09EE6CCD88B0E1ULL,
		0x03A016FA4F5773A6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA8B65C8CB0A8EEULL,
		0x7B5D2E45C8375D24ULL,
		0x8B2E40C793172FB6ULL,
		0xBC3062454CF45DF9ULL,
		0x6E75C3226FBC6D06ULL,
		0xE8686663BEA1AFE3ULL,
		0x7BDEF96A7DAD5958ULL,
		0x79E4686433CC05F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FEA41F81C3FBD4EULL,
		0x87667A5CC479FEF3ULL,
		0x9B1CC29C82215F2EULL,
		0x0275A2639D922C10ULL,
		0x0D47228D2EACCC2FULL,
		0x3B4F3F6175F4BB45ULL,
		0x1E2AF5024FDB5788ULL,
		0x89BBAE961B8B6DB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4C58BE819DC538E4ULL,
		0x7E78629A39610924ULL,
		0x133C50C1607C7923ULL,
		0x04D9B090E1EEBC28ULL,
		0xAD748A3EE0AEE716ULL,
		0xACF2745880F0A997ULL,
		0x1A4BA1C6C6507A5DULL,
		0x7352AC7367240389ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6955F3DD5BF6A6AFULL,
		0x984A30B0A2E0AE32ULL,
		0x3D7DDB59A819105EULL,
		0x4C2763A39CCFF807ULL,
		0xBB0731CF54E01DE4ULL,
		0xD3EB1942D09961E2ULL,
		0x27B3817182298755ULL,
		0xB4D59442C343F403ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE302CAA441CE9235ULL,
		0xE62E31E996805AF1ULL,
		0xD5BE7567B86368C4ULL,
		0xB8B24CED451EC420ULL,
		0xF26D586F8BCEC931ULL,
		0xD9075B15B05747B4ULL,
		0xF29820554426F307ULL,
		0xBE7D1830A3E00F85ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA0C3653A92BE3F81ULL,
		0x7B6E1CD4DE8D0419ULL,
		0xED8BA3C1A71ED888ULL,
		0xE9A627057DE782F6ULL,
		0x0D3FFF871E9C0D89ULL,
		0x20EE17431D06F9DDULL,
		0x322987931DDD49B8ULL,
		0x4DDEF716988F71FFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x751C17A4DA97B231ULL,
		0xB9760CFDF122CCA1ULL,
		0x243EF6D83DF90EAFULL,
		0xE6083330FB94583CULL,
		0xDFB958A90AF9C5DFULL,
		0x22A526C0C3D583F8ULL,
		0xD2A2AC96F6BBABA3ULL,
		0xCE6B58C4354BFE26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BA74D95B8268D50ULL,
		0xC1F80FD6ED6A3778ULL,
		0xC94CACE96925C9D8ULL,
		0x039DF3D482532ABAULL,
		0x2D86A6DE13A247AAULL,
		0xFE48F082593175E4ULL,
		0x5F86DAFC27219E14ULL,
		0x7F739E52634373D8ULL
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
		0xF0BC298A42C8F884ULL,
		0x9EB1A71507FF5904ULL,
		0xF4A0ACFFC9802BFCULL,
		0xF2F074CAF8E0FB06ULL,
		0x023ABB8EFB30FC8CULL,
		0x8851ED7422AFB58BULL,
		0x8407CFFE3E737645ULL,
		0x39B60C75D38C62C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98258E0078C865AULL,
		0x173E35A41998067EULL,
		0x175C470DE24BA81AULL,
		0x77F502F88FEAD602ULL,
		0x2889225EF47A64C6ULL,
		0xE6F736D544D16474ULL,
		0x345BC9F831DF2377ULL,
		0xFA819FF5DF53ED66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3739D0AA3B3C722AULL,
		0x87737170EE675286ULL,
		0xDD4465F1E73483E2ULL,
		0x7AFB71D268F62504ULL,
		0xD9B1993006B697C6ULL,
		0xA15AB69EDDDE5116ULL,
		0x4FAC06060C9452CDULL,
		0x3F346C7FF438755CULL
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
		0x4DEADCB1C87F6357ULL,
		0x51F465C707F62DCAULL,
		0x3BCA3C62168488B2ULL,
		0x5555AAED6909F290ULL,
		0xA8B1175F6949368EULL,
		0x1A1FD4160793FD67ULL,
		0x88A3812F8E8D03A8ULL,
		0xD389CBD1826995FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x00174BF08E553712ULL,
		0x4949BACB68077086ULL,
		0x220AEC38F7321E71ULL,
		0x341CB226920A0979ULL,
		0x46E66F0D4E417815ULL,
		0x0E8538F892E56CC6ULL,
		0xC5A0DB9A8C10D965ULL,
		0x9148A4D4ECAF3516ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DD390C13A2A2C45ULL,
		0x08AAAAFB9FEEBD44ULL,
		0x19BF50291F526A41ULL,
		0x2138F8C6D6FFE917ULL,
		0x61CAA8521B07BE79ULL,
		0x0B9A9B1D74AE90A1ULL,
		0xC302A595027C2A43ULL,
		0x424126FC95BA60E6ULL
	}};
	sign = 0;
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
		0x34326AAB1777B949ULL,
		0xF6C1DF4182FF1A84ULL,
		0xB7F1D5581B61BBC8ULL,
		0xB3480D67A94DE7B0ULL,
		0x4E5CA49AAC42E6EFULL,
		0x3E228F78836EC473ULL,
		0x6B0CA1BABC5BBE20ULL,
		0xD5C018A77BDF7AD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0AC4369446B5C2ULL,
		0x236759AEA65BD24EULL,
		0x15D0169C6A9ECEDCULL,
		0x1941821C020188C9ULL,
		0x1B29E89E1FB5535DULL,
		0xBFE9E39AFB7498D3ULL,
		0x806FA57109881DAFULL,
		0xAF73EBCCA3630C2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF727A67483310387ULL,
		0xD35A8592DCA34835ULL,
		0xA221BEBBB0C2ECECULL,
		0x9A068B4BA74C5EE7ULL,
		0x3332BBFC8C8D9392ULL,
		0x7E38ABDD87FA2BA0ULL,
		0xEA9CFC49B2D3A070ULL,
		0x264C2CDAD87C6EAAULL
	}};
	sign = 0;
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
		0x7DC6673E8240BA94ULL,
		0x604E4C98CCD73DB3ULL,
		0x871D7224516A46BDULL,
		0xD5FD66FB9DF197EBULL,
		0xD416B52BE992E77CULL,
		0x89C7D1F912AA2C15ULL,
		0x0B8A161C63491653ULL,
		0xEFA55EDB21CE730AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2C21DCC22449FABULL,
		0xD6DB7446B8278B3CULL,
		0x23E55F7DCAAE4A4FULL,
		0x2557C64409202998ULL,
		0x2225F9E3229233B2ULL,
		0x8687F7A2726C486EULL,
		0x4F1C6B73E747F5D5ULL,
		0x7EF3288A226A3E0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB0449725FFC1AE9ULL,
		0x8972D85214AFB276ULL,
		0x633812A686BBFC6DULL,
		0xB0A5A0B794D16E53ULL,
		0xB1F0BB48C700B3CAULL,
		0x033FDA56A03DE3A7ULL,
		0xBC6DAAA87C01207EULL,
		0x70B23650FF6434FBULL
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
		0x7CF8A5B682B748C5ULL,
		0x82C5F24F52675A67ULL,
		0xD40CC6F4FFACC802ULL,
		0x7D8149FCA0B6BD03ULL,
		0xE6EBA67B39747BB4ULL,
		0x6ACEC65FF2AF89C8ULL,
		0x780F51F5A0DBCDA2ULL,
		0x8E9D2BA5029EAA2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4DD2C0668C5A631ULL,
		0xA689F9F1454C47CBULL,
		0xC38C90FBAD93543EULL,
		0x51C559A7BFB80B33ULL,
		0x9ABA97EEA3219A5CULL,
		0x836F72CB493DF755ULL,
		0x541687E068C65073ULL,
		0x705540EDE72B1566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x881B79B019F1A294ULL,
		0xDC3BF85E0D1B129BULL,
		0x108035F9521973C3ULL,
		0x2BBBF054E0FEB1D0ULL,
		0x4C310E8C9652E158ULL,
		0xE75F5394A9719273ULL,
		0x23F8CA1538157D2EULL,
		0x1E47EAB71B7394C6ULL
	}};
	sign = 0;
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
		0x63A7C15FF4808542ULL,
		0xC4B73F8AEAAFC67FULL,
		0x50882C20C3FE9059ULL,
		0x450850D802F8DAA5ULL,
		0x6DBE05B8D73AF903ULL,
		0x96C76576E14B584DULL,
		0x7A75A53BC8824CA8ULL,
		0xEE124FBADC9A6795ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E60C7586E7A6671ULL,
		0x7C68097AE2A787D3ULL,
		0x963605EC2C4F06A1ULL,
		0xB90B6805F9E7E144ULL,
		0xDB1B593CD044DC2EULL,
		0x0A3F11BCD55732BDULL,
		0xDA6D53838F5585EEULL,
		0x4F441A1AB7C1FA31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4546FA0786061ED1ULL,
		0x484F361008083EACULL,
		0xBA52263497AF89B8ULL,
		0x8BFCE8D20910F960ULL,
		0x92A2AC7C06F61CD4ULL,
		0x8C8853BA0BF4258FULL,
		0xA00851B8392CC6BAULL,
		0x9ECE35A024D86D63ULL
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
		0x1EA60F6A6E190376ULL,
		0x27767AE1CBEE30ACULL,
		0x1DC28343D70CB63DULL,
		0x509ABA25F3EF1BF7ULL,
		0xCB4BD37B60B79609ULL,
		0x5642021AE6EBF5FFULL,
		0xF9B5AA9F71B12F5DULL,
		0x8447844611AA7A88ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B8A234A2D26B97AULL,
		0xB06BEF1CEF825B0CULL,
		0x1A8873B462B6A68BULL,
		0x830FDB6235F76637ULL,
		0x4FF441C31BDCC187ULL,
		0xA6449682AA53A7CBULL,
		0x22C8C39912708456ULL,
		0x238BB5A84EC50146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD31BEC2040F249FCULL,
		0x770A8BC4DC6BD59FULL,
		0x033A0F8F74560FB1ULL,
		0xCD8ADEC3BDF7B5C0ULL,
		0x7B5791B844DAD481ULL,
		0xAFFD6B983C984E34ULL,
		0xD6ECE7065F40AB06ULL,
		0x60BBCE9DC2E57942ULL
	}};
	sign = 0;
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
		0x3E8AC036112210E6ULL,
		0x02E901B4F0A71CB4ULL,
		0x2A7493DF7B5295DFULL,
		0x5A8316E6C182974DULL,
		0x332905CCB5F9A8F7ULL,
		0x621F77F5FFD45E1DULL,
		0x597477447F560290ULL,
		0xB41048E9C5252EA3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF88314877F583CD2ULL,
		0xEBF16F845715E910ULL,
		0x882E8B18BE0E1528ULL,
		0x12A61B843C2CB7F8ULL,
		0x53C56790204B7D64ULL,
		0xA4341B0F2D2674CFULL,
		0xB92808211749CBAAULL,
		0xE1DD2AD8688D0182ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4607ABAE91C9D414ULL,
		0x16F79230999133A3ULL,
		0xA24608C6BD4480B6ULL,
		0x47DCFB628555DF54ULL,
		0xDF639E3C95AE2B93ULL,
		0xBDEB5CE6D2ADE94DULL,
		0xA04C6F23680C36E5ULL,
		0xD2331E115C982D20ULL
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
		0xC78EA720ED181E2CULL,
		0xA45FA79FD26921CFULL,
		0x1994B04A68386825ULL,
		0x955734E38EA69D41ULL,
		0x656308D56A01CE6FULL,
		0xED561AE8007D067EULL,
		0x5D5F5FD1B3A6F177ULL,
		0xE9212A4CDBE83FCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34861928293A5F98ULL,
		0xCE141A5357A6C328ULL,
		0x675F456BFB3154ACULL,
		0x4454E5A1CA5DFC5AULL,
		0x21FBF80A6FD5C87FULL,
		0xDEAB6D0B9291F099ULL,
		0xBD74ACB9A06BC32CULL,
		0x2A9281C2C7880DC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93088DF8C3DDBE94ULL,
		0xD64B8D4C7AC25EA7ULL,
		0xB2356ADE6D071378ULL,
		0x51024F41C448A0E6ULL,
		0x436710CAFA2C05F0ULL,
		0x0EAAADDC6DEB15E5ULL,
		0x9FEAB318133B2E4BULL,
		0xBE8EA88A14603201ULL
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
		0x79DD4B756332AF44ULL,
		0x365A6CF38C4385E7ULL,
		0x09E40AD76D8B58ABULL,
		0x79BF38A993E5A4F9ULL,
		0x05AC2FF7E4812D12ULL,
		0x30B4FCB4A30A2884ULL,
		0xBB6C05F4B5541B16ULL,
		0xE5D60775783D8201ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF545CD805238091ULL,
		0xBC38F44D4F6235B5ULL,
		0x4C0EE95E3247C3FBULL,
		0x48532D9ABCE0CE39ULL,
		0xD3D898C3B43D3DAFULL,
		0x0D4CD5712B8E7B07ULL,
		0xAE9ABEBE0EB2707CULL,
		0xBB43CC658BBD13A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA88EE9D5E0F2EB3ULL,
		0x7A2178A63CE15031ULL,
		0xBDD521793B4394AFULL,
		0x316C0B0ED704D6BFULL,
		0x31D397343043EF63ULL,
		0x23682743777BAD7CULL,
		0x0CD14736A6A1AA9AULL,
		0x2A923B0FEC806E58ULL
	}};
	sign = 0;
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
		0xD98032950A07D47AULL,
		0x99FCEA78272D5E9EULL,
		0xF8DFBE1F1A1F0A0BULL,
		0x2AE8A17B34A0D7F7ULL,
		0x3FF43342F92FB6BDULL,
		0x8F8F4F6E6FE948BEULL,
		0xBCAC4CA00B342411ULL,
		0x0AF1281A77A857BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47108E093BBF1FF5ULL,
		0xC9DC4BFDDB1724C1ULL,
		0xF83710AEDA01E6DFULL,
		0x2754646D39FBBB14ULL,
		0x4ED426A03FE975D8ULL,
		0xC8BA0E4C124CF8FFULL,
		0x3EF1CB0DBEC69A49ULL,
		0xCC73D457D315EF40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x926FA48BCE48B485ULL,
		0xD0209E7A4C1639DDULL,
		0x00A8AD70401D232BULL,
		0x03943D0DFAA51CE3ULL,
		0xF1200CA2B94640E5ULL,
		0xC6D541225D9C4FBEULL,
		0x7DBA81924C6D89C7ULL,
		0x3E7D53C2A492687EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFF06A0470615A852ULL,
		0xFB8C33A73897572FULL,
		0x09DB46FEBBC521B2ULL,
		0x5369607ABE8E0799ULL,
		0x1F8F19BC714E5202ULL,
		0x7255978A7570E9E9ULL,
		0x5AB42805779A0B38ULL,
		0x931A6BCA80F5195FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D00EBDC4B97BA6ULL,
		0xC3AE65013C6747B1ULL,
		0xB355EEE9287AB3A8ULL,
		0x017D5F038761EC1BULL,
		0x165309E972441AFCULL,
		0xCDD0B4C09A442BE6ULL,
		0xBB94CA645F419F2CULL,
		0x096B8762AF9FF2B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC369189415C2CACULL,
		0x37DDCEA5FC300F7EULL,
		0x56855815934A6E0AULL,
		0x51EC0177372C1B7DULL,
		0x093C0FD2FF0A3706ULL,
		0xA484E2C9DB2CBE03ULL,
		0x9F1F5DA118586C0BULL,
		0x89AEE467D15526A5ULL
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
		0xB9F657441572CD7CULL,
		0x492EE7F951B60F2DULL,
		0x5A56D9B4214416EEULL,
		0x88B6CE613EB4A73FULL,
		0xE8396FF5A4FA6F20ULL,
		0xC3BFE91A2AB9FD81ULL,
		0x5281651202D77ABFULL,
		0x970D258268DA9483ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27389C277ADD2472ULL,
		0x582A5A06AA4ED788ULL,
		0xC68D12696FEC5870ULL,
		0xD6E270EA27067968ULL,
		0xABF0DB060548BDD5ULL,
		0x168343CB7BD56A1BULL,
		0x9C9264F5EEE54697ULL,
		0x018B9E766398487DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92BDBB1C9A95A90AULL,
		0xF1048DF2A76737A5ULL,
		0x93C9C74AB157BE7DULL,
		0xB1D45D7717AE2DD6ULL,
		0x3C4894EF9FB1B14AULL,
		0xAD3CA54EAEE49366ULL,
		0xB5EF001C13F23428ULL,
		0x9581870C05424C05ULL
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
		0xF07DB8D2D8AEED8EULL,
		0x3E7E7A506B0CF3E7ULL,
		0xB883836B6E27643AULL,
		0x06C1D69093FD5AD7ULL,
		0x0CAEB1FB4778FF59ULL,
		0x761FDB6E220A0601ULL,
		0x8FE34248AB182252ULL,
		0xF4A9E14FCAFE7E8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C62DCED9364AFBCULL,
		0x125809A428BAADB0ULL,
		0x50A7ED2DE621C52DULL,
		0x3295DB30AC29AC75ULL,
		0xDDDF100164138BE1ULL,
		0x4B242417C21744F9ULL,
		0x54774D6B9EB57C73ULL,
		0xEF3417FA27FEEEABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x941ADBE5454A3DD2ULL,
		0x2C2670AC42524637ULL,
		0x67DB963D88059F0DULL,
		0xD42BFB5FE7D3AE62ULL,
		0x2ECFA1F9E3657377ULL,
		0x2AFBB7565FF2C107ULL,
		0x3B6BF4DD0C62A5DFULL,
		0x0575C955A2FF8FE1ULL
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
		0x53BABF34A6B49F10ULL,
		0x0A48F847DFC65E6AULL,
		0x2A3AC50C526ED8BDULL,
		0x4DC2BF18832A2178ULL,
		0xD122B7003620DE14ULL,
		0xB804CD8C8A612B2FULL,
		0x5907A1E3D0D7AAF0ULL,
		0xE4F779B8785DD499ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0C153B0B2BC1F3ULL,
		0x4E7BC8BE5F4C3D54ULL,
		0x042359089FB6B854ULL,
		0x0A41B444457048DAULL,
		0x23B902F726CF8243ULL,
		0xE857ADA0AEBC8906ULL,
		0xD4041256AD46A7A0ULL,
		0x8BC3412108CE9913ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4AEA9F99B88DD1DULL,
		0xBBCD2F89807A2115ULL,
		0x26176C03B2B82068ULL,
		0x43810AD43DB9D89EULL,
		0xAD69B4090F515BD1ULL,
		0xCFAD1FEBDBA4A229ULL,
		0x85038F8D2391034FULL,
		0x593438976F8F3B85ULL
	}};
	sign = 0;
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
		0xF514E020AC1913E6ULL,
		0xF82DA6839A93720FULL,
		0x610AC3BBF9E9AC34ULL,
		0x744522CA32305DFAULL,
		0x487BF1264594B472ULL,
		0xE205D6364E66CFFAULL,
		0x8909B4340BDBA8D2ULL,
		0x71E6733422E4C0E0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50191FD32D9A9EAULL,
		0xE2BDEE83514038F3ULL,
		0xCA46C3B7ED7375E2ULL,
		0x88FB6F11C0ABD4AFULL,
		0x19A03CB5E3235A69ULL,
		0xF6482683B56CBF4AULL,
		0x6523771E232B45C3ULL,
		0xEED4F6BAD1F27486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20134E23793F69FCULL,
		0x156FB8004953391CULL,
		0x96C400040C763652ULL,
		0xEB49B3B87184894AULL,
		0x2EDBB47062715A08ULL,
		0xEBBDAFB298FA10B0ULL,
		0x23E63D15E8B0630EULL,
		0x83117C7950F24C5AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCEC735F833B7A3B4ULL,
		0xBAEB88272A77AF30ULL,
		0xB433FB5B2D8EE448ULL,
		0xCA6028A9BAD809C4ULL,
		0x40B648FF0B82C284ULL,
		0x8CE6ADFA552FD205ULL,
		0x2CD25461C8094155ULL,
		0x603E084CB8A089A1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x84236E5BDF2B55BDULL,
		0xC56A68DFFB51D05DULL,
		0x66E96F42ED1139FBULL,
		0xBF18663B8FF98D7DULL,
		0xC4BD17213F7D0D6BULL,
		0xE0B9298F08B5767EULL,
		0x09E9FF67D29F4565ULL,
		0x31B84ADF48D0CB9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AA3C79C548C4DF7ULL,
		0xF5811F472F25DED3ULL,
		0x4D4A8C18407DAA4CULL,
		0x0B47C26E2ADE7C47ULL,
		0x7BF931DDCC05B519ULL,
		0xAC2D846B4C7A5B86ULL,
		0x22E854F9F569FBEFULL,
		0x2E85BD6D6FCFBE02ULL
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
		0x9424CB9B4D8436EBULL,
		0x6B5235564D914D18ULL,
		0xA3EBBC84068E3550ULL,
		0x6FF134443BEE9418ULL,
		0x1C17F87698B2479BULL,
		0xAE2AF9EC684576E5ULL,
		0x3E82ED6D8019FF7EULL,
		0x25F1E52AFB704C1FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC826A83F3CF4C73ULL,
		0x1B0BBF0F98DE7313ULL,
		0xF61C596A9AD792FFULL,
		0x5FF1C57D61E1D0A1ULL,
		0x1BC9BF8DD9F530AFULL,
		0xA4F326BAD8B62D27ULL,
		0x554B2157CDCB5584ULL,
		0x384E220B87459969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7A2611759B4EA78ULL,
		0x50467646B4B2DA04ULL,
		0xADCF63196BB6A251ULL,
		0x0FFF6EC6DA0CC376ULL,
		0x004E38E8BEBD16ECULL,
		0x0937D3318F8F49BEULL,
		0xE937CC15B24EA9FAULL,
		0xEDA3C31F742AB2B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC335888D8DC6A64DULL,
		0xEE80CE12C2AEF431ULL,
		0x9247DF011E5EA6DBULL,
		0xE11DD323ABE86222ULL,
		0x047C278ECD046C87ULL,
		0x8117E83B2EBD509AULL,
		0x7092CB7120460209ULL,
		0x63999F6664DFE61AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xED5822202E0FD32EULL,
		0x9948B0F4787471D6ULL,
		0xE157FFFA0D401881ULL,
		0xDCE05750A469FE0FULL,
		0x44658694F048304AULL,
		0x27D9B93C2C8C07C3ULL,
		0x8639275EEF71966DULL,
		0xDF088D3DAA9FE763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5DD666D5FB6D31FULL,
		0x55381D1E4A3A825AULL,
		0xB0EFDF07111E8E5AULL,
		0x043D7BD3077E6412ULL,
		0xC016A0F9DCBC3C3DULL,
		0x593E2EFF023148D6ULL,
		0xEA59A41230D46B9CULL,
		0x84911228BA3FFEB6ULL
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
		0x169EBCCD63EF3482ULL,
		0x9D3DEE8EDE608BF0ULL,
		0x2E4037FCF3A9BAB1ULL,
		0x48189749A954F63EULL,
		0x2567190D82C929F0ULL,
		0x248970339AF66585ULL,
		0xEA36BC51F918FF6BULL,
		0x6CCC18A2445528CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32DB32BE19F6345DULL,
		0xEA2269830959CE0BULL,
		0x4DDC143AE125B08BULL,
		0xCE4C01386C056EB6ULL,
		0x266C3AEB54A5FE2AULL,
		0x2EC75F9A39F0F49EULL,
		0xFB849C1696B3EBA0ULL,
		0x9F2F5579C8DC7150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3C38A0F49F90025ULL,
		0xB31B850BD506BDE4ULL,
		0xE06423C212840A25ULL,
		0x79CC96113D4F8787ULL,
		0xFEFADE222E232BC5ULL,
		0xF5C21099610570E6ULL,
		0xEEB2203B626513CAULL,
		0xCD9CC3287B78B77EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6A584E01746C90C3ULL,
		0xAC1318E5B653463CULL,
		0xDD7DD88727BF98CFULL,
		0x102BF61C4D085D06ULL,
		0xA9126B85945FD42BULL,
		0x251D30408E302B18ULL,
		0xE4F2232FCF4A5AF5ULL,
		0xD920133197F593B7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4DB872D3C46264ULL,
		0xFE5896BAA23FA0B7ULL,
		0x197861294F33E571ULL,
		0x2C2D81892D7360FBULL,
		0x9EA58B1EE7A92297ULL,
		0x1392F38D3C0E359EULL,
		0x755ACA594BE85086ULL,
		0xA0612D0C5B86B366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF0A958EA0A82E5FULL,
		0xADBA822B1413A584ULL,
		0xC405775DD88BB35DULL,
		0xE3FE74931F94FC0BULL,
		0x0A6CE066ACB6B193ULL,
		0x118A3CB35221F57AULL,
		0x6F9758D683620A6FULL,
		0x38BEE6253C6EE051ULL
	}};
	sign = 0;
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
		0xA591AFFA82545510ULL,
		0x2488E301839EDCDCULL,
		0xDAB2C04373E43CB7ULL,
		0x4C752BB9BA74E398ULL,
		0x79885366A97122CDULL,
		0x25029FACEF967E61ULL,
		0x3BA1AD01F2B4F61CULL,
		0x296CBA9D72F19EF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E638982E9EFF7CAULL,
		0x3BBD575EF11444B1ULL,
		0xB3B0B85A17683B39ULL,
		0x7540B9D6C765622AULL,
		0xDC4734C3DF3C5509ULL,
		0xF698E604B7533231ULL,
		0xDF9A0E98B3010725ULL,
		0x943E201EE5D0EDEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x072E267798645D46ULL,
		0xE8CB8BA2928A982BULL,
		0x270207E95C7C017DULL,
		0xD73471E2F30F816EULL,
		0x9D411EA2CA34CDC3ULL,
		0x2E69B9A838434C2FULL,
		0x5C079E693FB3EEF6ULL,
		0x952E9A7E8D20B107ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x97FAE27B0BA1C84CULL,
		0xFF2D849F75B5ABC7ULL,
		0x57A9B52596C48920ULL,
		0x0B88C3BD133B9A29ULL,
		0x6974CCE54336FC57ULL,
		0xC7E41F01228BC949ULL,
		0xA5EDAF6B8A3B8ECAULL,
		0x1DD0E1520D97DC93ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AEBA5690AB64C75ULL,
		0xBE026F26EFA6AB68ULL,
		0x69623E3939FF5BF3ULL,
		0x579BA49D3D6A11B4ULL,
		0xED8E1330A6AC911AULL,
		0xD1A5D1C87298C84DULL,
		0xBE922900BF07F7AAULL,
		0xBAFAB1E3FCC6DA39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D0F3D1200EB7BD7ULL,
		0x412B1578860F005FULL,
		0xEE4776EC5CC52D2DULL,
		0xB3ED1F1FD5D18874ULL,
		0x7BE6B9B49C8A6B3CULL,
		0xF63E4D38AFF300FBULL,
		0xE75B866ACB33971FULL,
		0x62D62F6E10D10259ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9AC30CD9FD58C3F7ULL,
		0xD04B9E39BF153E32ULL,
		0x1DD9C333681CD68CULL,
		0x6F97798C3471FD00ULL,
		0xA04CED1211597234ULL,
		0x7C9A3840A05C2CAEULL,
		0x4AAFEBAF2F1F424FULL,
		0x6457133F77CD9062ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76EBF585A423DE50ULL,
		0xC2ED71783F19CB7AULL,
		0x0FEBEE644B7879B6ULL,
		0xBF0C9A8100100286ULL,
		0xABC9F349F816D75DULL,
		0xD79DA0992F63C01AULL,
		0xECA7CFB6165DF9E2ULL,
		0x38DFA1F5DB2276A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23D717545934E5A7ULL,
		0x0D5E2CC17FFB72B8ULL,
		0x0DEDD4CF1CA45CD6ULL,
		0xB08ADF0B3461FA7AULL,
		0xF482F9C819429AD6ULL,
		0xA4FC97A770F86C93ULL,
		0x5E081BF918C1486CULL,
		0x2B7771499CAB19C0ULL
	}};
	sign = 0;
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
		0xF852E8F3029B1963ULL,
		0xD10C2FAD060F4E92ULL,
		0xC768688879C6A4EFULL,
		0xF194219587400870ULL,
		0xE70C152DCA16AE5BULL,
		0x600B4C14D74D622AULL,
		0x476BC2782F95A4A4ULL,
		0x01A44EE9F7B1A8BFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CA89A83AD9E48F1ULL,
		0x1BE10FAB2BD6BD79ULL,
		0xE15BF1F6731B94ADULL,
		0x01461674A67C0156ULL,
		0x1C815A36A4B38223ULL,
		0xF316255337FCBB94ULL,
		0x36073212F43FE56AULL,
		0x880523C0882F1A12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BAA4E6F54FCD072ULL,
		0xB52B2001DA389119ULL,
		0xE60C769206AB1042ULL,
		0xF04E0B20E0C40719ULL,
		0xCA8ABAF725632C38ULL,
		0x6CF526C19F50A696ULL,
		0x116490653B55BF39ULL,
		0x799F2B296F828EADULL
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
		0xAF6FC517C27B54FBULL,
		0x4788ABCE62E5F2D8ULL,
		0xE76DAAD631214931ULL,
		0x45843CBBD653878CULL,
		0xAFF398D05D2C27A6ULL,
		0xD2DA94AD3F41D4A4ULL,
		0xB1DA19AABFC12AA4ULL,
		0x8A7C98FF0BDF9EACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98FDEDF9D9B420D0ULL,
		0xC54B00C964203F5FULL,
		0xC59D5963F74D4A7CULL,
		0x052F01C1BAFFCFD8ULL,
		0x2228DDB447FDBB8DULL,
		0x5C133BCD54311E21ULL,
		0x63B313FD197CB262ULL,
		0x8C812E01920F3322ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1671D71DE8C7342BULL,
		0x823DAB04FEC5B379ULL,
		0x21D0517239D3FEB4ULL,
		0x40553AFA1B53B7B4ULL,
		0x8DCABB1C152E6C19ULL,
		0x76C758DFEB10B683ULL,
		0x4E2705ADA6447842ULL,
		0xFDFB6AFD79D06B8AULL
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
		0xE46028E326DBAAFBULL,
		0xE0C897915F53D861ULL,
		0x6149411FE187FE00ULL,
		0x6BEC765108BFAB37ULL,
		0x7C15A548F570F0E6ULL,
		0x02A1790F9DD34C3BULL,
		0x4C6611D36AFED2F7ULL,
		0xDAEF01086B3138B1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A3B47C94F4A12BULL,
		0xEE32F9A0E06E2FC4ULL,
		0x7CBE3CEDD98B144BULL,
		0xA64EF69C4FA2D140ULL,
		0xA1CF1530899C3560ULL,
		0xEF0A7A6AF302301BULL,
		0xA218251160DA7F8AULL,
		0x698951A513F63B60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81BC746691E709D0ULL,
		0xF2959DF07EE5A89DULL,
		0xE48B043207FCE9B4ULL,
		0xC59D7FB4B91CD9F6ULL,
		0xDA4690186BD4BB85ULL,
		0x1396FEA4AAD11C1FULL,
		0xAA4DECC20A24536CULL,
		0x7165AF63573AFD50ULL
	}};
	sign = 0;
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
		0x9DDE5A7326B9E283ULL,
		0xCA167F817B544F92ULL,
		0x429CEEFF82B94470ULL,
		0x6DD0B82684DB7401ULL,
		0xB5783D5951973A4DULL,
		0xD5C53F710979E9C9ULL,
		0x76CB05FF8E499CEFULL,
		0x18862533290D669AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x40DC59975EF5560FULL,
		0x020F928A32021BF4ULL,
		0x70F6F371D5693065ULL,
		0xF36A39D0D30678B6ULL,
		0xF05DECC0B6FF5607ULL,
		0xDFBD27DDC8BC307AULL,
		0xA6FC5BBA1C7EFB22ULL,
		0x0F0FCB9DE503472BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D0200DBC7C48C74ULL,
		0xC806ECF74952339EULL,
		0xD1A5FB8DAD50140BULL,
		0x7A667E55B1D4FB4AULL,
		0xC51A50989A97E445ULL,
		0xF608179340BDB94EULL,
		0xCFCEAA4571CAA1CCULL,
		0x09765995440A1F6EULL
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
		0xBBC5F056D31E1CC5ULL,
		0x9641286CF11C5838ULL,
		0x7DA315753D0EDFCAULL,
		0xF64E94981DA7BA10ULL,
		0x9E86F8B3346DCB87ULL,
		0xD2B384269E0D6F7EULL,
		0x3C8F897B8C2B56FCULL,
		0xC62215B4653746DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A828B1C5C808B81ULL,
		0x349A3133D2C0CD84ULL,
		0xD359596BE3756E59ULL,
		0xA76491A36A0C3498ULL,
		0x1829445AAC518DECULL,
		0x52C65D966506C1CBULL,
		0x34B908054635BB41ULL,
		0x4E1CACCEDEF9F31CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7143653A769D9144ULL,
		0x61A6F7391E5B8AB4ULL,
		0xAA49BC0959997171ULL,
		0x4EEA02F4B39B8577ULL,
		0x865DB458881C3D9BULL,
		0x7FED26903906ADB3ULL,
		0x07D6817645F59BBBULL,
		0x780568E5863D53BFULL
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
		0xD5F8CB96EBA48018ULL,
		0xF9784BCFB34034A0ULL,
		0x03EDA691E252B77FULL,
		0x257DD0D78B60B282ULL,
		0x1FC20DAC1BE50825ULL,
		0x9A5452AE30C17BB7ULL,
		0x461C194FDD9DEF53ULL,
		0x45E44A80F84F39B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F9BC3B3D508AC68ULL,
		0x140AEC9CE9D24ED8ULL,
		0xC73E0CA82CB3ADA2ULL,
		0x1BBFAA980C74461BULL,
		0x9C181403BDFF1881ULL,
		0x8F9C6871E178EB6AULL,
		0xAAC41B399DA87E3CULL,
		0x801C346125318577ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x765D07E3169BD3B0ULL,
		0xE56D5F32C96DE5C8ULL,
		0x3CAF99E9B59F09DDULL,
		0x09BE263F7EEC6C66ULL,
		0x83A9F9A85DE5EFA4ULL,
		0x0AB7EA3C4F48904CULL,
		0x9B57FE163FF57117ULL,
		0xC5C8161FD31DB440ULL
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
		0x56C478BB998EEB28ULL,
		0x73A2E8EF59E9002BULL,
		0x2E9F4D2C42AD701AULL,
		0xF8B24736405835A8ULL,
		0xFA6CA9B1C3AE8B64ULL,
		0xA8A67AB7F69F8C36ULL,
		0x5552682611BFFA3FULL,
		0xA0CD35D97F43BBD3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CBBC6F43F7C7BAULL,
		0x7B0CCBB3090D8A82ULL,
		0x950F2C2B25AE6310ULL,
		0x81C68D38B571FECFULL,
		0x9E2A875B0BFB558FULL,
		0x62B11A520FCEC3B7ULL,
		0x1F5B08259FA1C907ULL,
		0x362374B9161C2336ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33F8BC4C5597236EULL,
		0xF8961D3C50DB75A9ULL,
		0x999021011CFF0D09ULL,
		0x76EBB9FD8AE636D8ULL,
		0x5C422256B7B335D5ULL,
		0x45F56065E6D0C87FULL,
		0x35F76000721E3138ULL,
		0x6AA9C1206927989DULL
	}};
	sign = 0;
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
		0xA82C337FCB4A3640ULL,
		0x81E6DDAE4D773BA3ULL,
		0x3CEDF60B5F52F864ULL,
		0xDEF5B755FEADDEEBULL,
		0x8CAAA4B86A492DF7ULL,
		0x533EA426F3690FF0ULL,
		0xC1EA0BE5B7D6731BULL,
		0xE696FAF4AD8D24A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7F2F650E815597ULL,
		0xBE534E9DB260A108ULL,
		0xAED2ECF1BDBE4C5FULL,
		0x5A2C6D26749EA61BULL,
		0xB6D6426238333191ULL,
		0xAE023D0A72996E70ULL,
		0xC416CD74653A4548ULL,
		0xC97A66198D175FFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCAD041ABCC8E0A9ULL,
		0xC3938F109B169A9AULL,
		0x8E1B0919A194AC04ULL,
		0x84C94A2F8A0F38CFULL,
		0xD5D462563215FC66ULL,
		0xA53C671C80CFA17FULL,
		0xFDD33E71529C2DD2ULL,
		0x1D1C94DB2075C4A5ULL
	}};
	sign = 0;
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
		0x8C79D4035A9B3B81ULL,
		0xB96AFE73C814C18BULL,
		0x39D6D40084CEFBD3ULL,
		0x3ACE144938BA1762ULL,
		0x3BD83F1945D98606ULL,
		0xC705F63B2F926882ULL,
		0xCDF9C4874B0ED447ULL,
		0x0F9AF769AF2F9493ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8FD5ABF397A3DEDULL,
		0xFAC60E5C5B2D12C5ULL,
		0x66CC88F0A44644B2ULL,
		0x4BA213C45C8C5061ULL,
		0xC68F020CEAC9EA97ULL,
		0x03468BE9F6B8C610ULL,
		0x091FD6FA1D7D0EB9ULL,
		0x9462789E3D6CF4E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD37C79442120FD94ULL,
		0xBEA4F0176CE7AEC5ULL,
		0xD30A4B0FE088B720ULL,
		0xEF2C0084DC2DC700ULL,
		0x75493D0C5B0F9B6EULL,
		0xC3BF6A5138D9A271ULL,
		0xC4D9ED8D2D91C58EULL,
		0x7B387ECB71C29FB3ULL
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
		0x8118D4E1741D2EACULL,
		0x224F8985F6E37A80ULL,
		0x9CAD83A8081F7B37ULL,
		0xCB0724921C9F060EULL,
		0x7F2911EC46FC5380ULL,
		0xD7452004249C9E2BULL,
		0x150E9DEF1CF10CCAULL,
		0xA7A9B7BCBD6C6D27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2C5DBB156526FEULL,
		0xB930C5C988DC7DAEULL,
		0x2D90A5ABD47C9E8AULL,
		0x1D09FCEC9A71AA84ULL,
		0x2BFD014CFD8F0D05ULL,
		0x2B74C3F85255FB1CULL,
		0xE6F024E94A0B49D9ULL,
		0xEC7C0436365F3874ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41EC77265EB807AEULL,
		0x691EC3BC6E06FCD2ULL,
		0x6F1CDDFC33A2DCACULL,
		0xADFD27A5822D5B8AULL,
		0x532C109F496D467BULL,
		0xABD05C0BD246A30FULL,
		0x2E1E7905D2E5C2F1ULL,
		0xBB2DB386870D34B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x763B3690A4A807C1ULL,
		0x247B34E66906F416ULL,
		0x1418CC4BB2CA28FFULL,
		0x41DF18180B23A1A6ULL,
		0x4B851EC2D3566BC1ULL,
		0x0BB276FC44E1E1B9ULL,
		0xFFB4D1EA02B0A389ULL,
		0x8B7739D058072CE0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1B4E621746A12A5ULL,
		0x41FF5C23318AC334ULL,
		0x554F771C6258B5C3ULL,
		0x2249EFAF9D4B7E76ULL,
		0xC640FE5F41E897E3ULL,
		0x6AB1BD06B4A807F2ULL,
		0xE877BD6DF8BC3843ULL,
		0x0AA8AC70B852AD89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD486506F303DF51CULL,
		0xE27BD8C3377C30E1ULL,
		0xBEC9552F5071733BULL,
		0x1F9528686DD8232FULL,
		0x85442063916DD3DEULL,
		0xA100B9F59039D9C6ULL,
		0x173D147C09F46B45ULL,
		0x80CE8D5F9FB47F57ULL
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
		0x46C1714AD1719947ULL,
		0xCFD74461AC680152ULL,
		0x5FD8808BC980089DULL,
		0x462F7812886835F8ULL,
		0x5425C5385FCBC088ULL,
		0xD3723484C4E324B2ULL,
		0x6B104EC4C15F98A7ULL,
		0x764ECB89FE255D0DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE41A284FC37C05E3ULL,
		0x37AD8E1F2C4D2C68ULL,
		0x437F739B36E99FA4ULL,
		0x7C0D30B5782BD60EULL,
		0xFA6AA2A63BE47BADULL,
		0xC0878FFBE9D5D5AEULL,
		0x8456EA1B5D58DAA5ULL,
		0x05F2F2021196A0EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62A748FB0DF59364ULL,
		0x9829B642801AD4E9ULL,
		0x1C590CF0929668F9ULL,
		0xCA22475D103C5FEAULL,
		0x59BB229223E744DAULL,
		0x12EAA488DB0D4F03ULL,
		0xE6B964A96406BE02ULL,
		0x705BD987EC8EBC22ULL
	}};
	sign = 0;
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
		0xBB4B1D744D6EC519ULL,
		0x0C41357E5D1AC58DULL,
		0xFFF6F00CF7A8447EULL,
		0xFED11C05325CD5F1ULL,
		0xA4E9E2C06BFA2E13ULL,
		0xA9DD3983270910DAULL,
		0x64F34AAECF8E7738ULL,
		0xB9B8515604BC5A0CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E077F5D82487B93ULL,
		0x03A39F7B2328F13BULL,
		0xBAE70FA4AD1CFDE4ULL,
		0x4C17C890F15BFB5DULL,
		0xD6E62E8CFFDB81E8ULL,
		0xBB5A7FDD925BF852ULL,
		0xF02F13D742C04393ULL,
		0xB9EFEF6D9E1B8FBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D439E16CB264986ULL,
		0x089D960339F1D452ULL,
		0x450FE0684A8B469AULL,
		0xB2B953744100DA94ULL,
		0xCE03B4336C1EAC2BULL,
		0xEE82B9A594AD1887ULL,
		0x74C436D78CCE33A4ULL,
		0xFFC861E866A0CA50ULL
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
		0x745027F41A755F04ULL,
		0xBC92FD83C78D7D6AULL,
		0x330FEABEADFB6D42ULL,
		0xE12BEF1274D5D57BULL,
		0x7156A1A7AD9B19DBULL,
		0x77AE289FB5AF677BULL,
		0xC0BCA4AB08502E7CULL,
		0x196622DEED0F79D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x644F2E944C7D7704ULL,
		0x44EE1293435ECE2DULL,
		0x7A485376ADF1D320ULL,
		0x6D472F494526BDC2ULL,
		0x962836C3E482F209ULL,
		0xCC566568622D9934ULL,
		0x689599FEE4595264ULL,
		0xF1A2E2D8DBF2428BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000F95FCDF7E800ULL,
		0x77A4EAF0842EAF3DULL,
		0xB8C7974800099A22ULL,
		0x73E4BFC92FAF17B8ULL,
		0xDB2E6AE3C91827D2ULL,
		0xAB57C3375381CE46ULL,
		0x58270AAC23F6DC17ULL,
		0x27C34006111D3746ULL
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
		0xDB5C7743D4B06BE4ULL,
		0xE4CC640978DE05D5ULL,
		0x3D66A96D90C1421AULL,
		0xBF70D2405211142EULL,
		0x30D1D304C249966DULL,
		0x34F7A0C00C416B1DULL,
		0xC8AD96E36915FFF6ULL,
		0xAB200B1396620087ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6977C5253D8FE15ULL,
		0xC4BE45BC3C8DAD9BULL,
		0x91372A614C5C099BULL,
		0x0390B7F54BB195CBULL,
		0xA7EE2A121B7389FAULL,
		0x0F09E0C07366BFBCULL,
		0xCB527D2623C7C401ULL,
		0x4ADE8AE807D787BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04C4FAF180D76DCFULL,
		0x200E1E4D3C50583AULL,
		0xAC2F7F0C4465387FULL,
		0xBBE01A4B065F7E62ULL,
		0x88E3A8F2A6D60C73ULL,
		0x25EDBFFF98DAAB60ULL,
		0xFD5B19BD454E3BF5ULL,
		0x6041802B8E8A78C8ULL
	}};
	sign = 0;
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
		0x7F0B655A45F17209ULL,
		0x725BC550713CD404ULL,
		0xD56331CDD086B1DAULL,
		0xD6F67A1CEEB32F59ULL,
		0x8B97AB11657353D8ULL,
		0xE4AC9D14E96DA274ULL,
		0xA2B513B8575F6883ULL,
		0x62B1398D3BE98990ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7033ABC9903F2934ULL,
		0x490DA160ED3B0E71ULL,
		0x9C25C06CDDD21551ULL,
		0x3C430264EC26F76FULL,
		0x0CAB6522DEFDD65CULL,
		0xDA386EB1B57FD130ULL,
		0x15B5E03F9FBFE8C0ULL,
		0x5B3DE46A745D2D9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ED7B990B5B248D5ULL,
		0x294E23EF8401C593ULL,
		0x393D7160F2B49C89ULL,
		0x9AB377B8028C37EAULL,
		0x7EEC45EE86757D7CULL,
		0x0A742E6333EDD144ULL,
		0x8CFF3378B79F7FC3ULL,
		0x07735522C78C5BF6ULL
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
		0xD542D3BE0B2EDA2FULL,
		0x1811C3B1D36D74CBULL,
		0xDFA18CC3EBE98026ULL,
		0x53D49D3B22036C57ULL,
		0xA7A0E586F1279618ULL,
		0xD28A9FEAC9F1F292ULL,
		0x349E8928A06D2C7AULL,
		0x1C7DA2220BE705EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x614D08F2AE0C80A9ULL,
		0x8641D6D9E887F9A6ULL,
		0xCB52BFC617AC352CULL,
		0x87EA0A67ADA6A0F7ULL,
		0x728C063098D83A32ULL,
		0xBE54A1A26C8E47B2ULL,
		0x8CDBC951C52DB34CULL,
		0x086AF3D9FA939E62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73F5CACB5D225986ULL,
		0x91CFECD7EAE57B25ULL,
		0x144ECCFDD43D4AF9ULL,
		0xCBEA92D3745CCB60ULL,
		0x3514DF56584F5BE5ULL,
		0x1435FE485D63AAE0ULL,
		0xA7C2BFD6DB3F792EULL,
		0x1412AE481153678CULL
	}};
	sign = 0;
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
		0x8CF217A5332FC213ULL,
		0xA8760347AF0B213AULL,
		0x0F5FCDF003299946ULL,
		0x60AAC9CD16824B9BULL,
		0x7D296A96D1CF0857ULL,
		0x47625737DDD13A4AULL,
		0x6344A79F7A1886D3ULL,
		0x40637F6F9AA6E138ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x00121C793C4716DDULL,
		0x350650F668595CF8ULL,
		0xD943FAFC992929A1ULL,
		0xC80DCD9BC7C1BD8AULL,
		0xE1DED966F7F118EFULL,
		0xBDC1BA82FE1A268EULL,
		0x58ACAE88FB05E34FULL,
		0x32491992D4B73D5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CDFFB2BF6E8AB36ULL,
		0x736FB25146B1C442ULL,
		0x361BD2F36A006FA5ULL,
		0x989CFC314EC08E10ULL,
		0x9B4A912FD9DDEF67ULL,
		0x89A09CB4DFB713BBULL,
		0x0A97F9167F12A383ULL,
		0x0E1A65DCC5EFA3DBULL
	}};
	sign = 0;
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
		0xDC01FC9DB2C422E8ULL,
		0x792778942DDF7937ULL,
		0xC2B9F95864E853B0ULL,
		0xF84F81BF7B79187EULL,
		0xFA7C5BC8A9C19DE4ULL,
		0x59A215E785EDF272ULL,
		0x2CAFF96CA34A07F8ULL,
		0x60E9C6DA0A2FED74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECA900DCE7C1FA2ULL,
		0x8AB7A45D7C06E187ULL,
		0x45D71E49A4DFEB1CULL,
		0x0282E446A879F5D7ULL,
		0x50B6077CB0794D9AULL,
		0x0FC9B262A6894C27ULL,
		0xF63D50DC9911D2B3ULL,
		0x7AFD7CE021663A16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D376C8FE4480346ULL,
		0xEE6FD436B1D897B0ULL,
		0x7CE2DB0EC0086893ULL,
		0xF5CC9D78D2FF22A7ULL,
		0xA9C6544BF948504AULL,
		0x49D86384DF64A64BULL,
		0x3672A8900A383545ULL,
		0xE5EC49F9E8C9B35DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7788A37A8B53E54CULL,
		0xCCC888C4656BCF4CULL,
		0xB7FD0BBC3AE67B19ULL,
		0x868AADD376A721E6ULL,
		0xE6B0A0E21A4C697FULL,
		0x5A6C3445397ABAD0ULL,
		0xEF87EFC45A6722ECULL,
		0x89F76E4D69FF7BA3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF335A4267E94EBCDULL,
		0x49E3E4FF6A4511DEULL,
		0x71254C21F6E5254CULL,
		0x95C8883E855FCC3CULL,
		0x1C56E2EB5C1A19ECULL,
		0xC82B2BF4AACF5EADULL,
		0x3B68B93EC79BAB82ULL,
		0x877DF3FE7FA249A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8452FF540CBEF97FULL,
		0x82E4A3C4FB26BD6DULL,
		0x46D7BF9A440155CDULL,
		0xF0C22594F14755AAULL,
		0xCA59BDF6BE324F92ULL,
		0x924108508EAB5C23ULL,
		0xB41F368592CB7769ULL,
		0x02797A4EEA5D3200ULL
	}};
	sign = 0;
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
		0xE561ABA376E6F3B8ULL,
		0x6B02BFACB1DEC841ULL,
		0x53915C490BE06181ULL,
		0xD351C6AF6DA8EB9FULL,
		0x7953B5EFF687E59EULL,
		0xC927D5866857A406ULL,
		0x3A26FCD56824A9BBULL,
		0x6DE4BC634E84F675ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4C0639B7A17992EULL,
		0x13766B73CE16965DULL,
		0x8B44F46E23C097B1ULL,
		0x5146ED3BD15A5593ULL,
		0x35B1115D6E8F1398ULL,
		0xFFF0F6365DD657A0ULL,
		0x46ABBFB12D7877F9ULL,
		0xDEA65AC51B4A159FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A14807FCCF5A8AULL,
		0x578C5438E3C831E4ULL,
		0xC84C67DAE81FC9D0ULL,
		0x820AD9739C4E960BULL,
		0x43A2A49287F8D206ULL,
		0xC936DF500A814C66ULL,
		0xF37B3D243AAC31C1ULL,
		0x8F3E619E333AE0D5ULL
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
		0x1528829F603FDAFEULL,
		0xEBF0436AC67CE66BULL,
		0x8048B2839916079AULL,
		0x2551A6C7CE341B3BULL,
		0xDE1ADBFAD907B76AULL,
		0xD2CAE5137B4CB022ULL,
		0xF2E69724629E265FULL,
		0x89C16725D5A57644ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C5CAC922F662E65ULL,
		0xC624D5537206224BULL,
		0x6BE3FD85B0A76D71ULL,
		0x783DDB9716BDBAA0ULL,
		0x9F0CB1CA680EF849ULL,
		0x21B6F36F912CB300ULL,
		0xFD74E50F4D252145ULL,
		0xC44F6F213105ED13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88CBD60D30D9AC99ULL,
		0x25CB6E175476C41FULL,
		0x1464B4FDE86E9A29ULL,
		0xAD13CB30B776609BULL,
		0x3F0E2A3070F8BF20ULL,
		0xB113F1A3EA1FFD22ULL,
		0xF571B2151579051AULL,
		0xC571F804A49F8930ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x279A04CBAD9487FDULL,
		0x5E3318E4EA76CAD4ULL,
		0xABF27EAA4833DCBCULL,
		0x0B8E3812FA003C48ULL,
		0xB74BFEC34BC92D4FULL,
		0xAAB33EF67A44CCADULL,
		0xC939F0EF91633BEEULL,
		0x3C20EE8AC58CB436ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D02D54940C954A5ULL,
		0xEE99643B8DB6B087ULL,
		0x4F9BE182FCD43695ULL,
		0x44047979B31E4F84ULL,
		0x55CD691E12C0CA16ULL,
		0xD371A28846A399DCULL,
		0xDA58BD9C15C20B57ULL,
		0x41A9131C7DB7125BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA972F826CCB3358ULL,
		0x6F99B4A95CC01A4CULL,
		0x5C569D274B5FA626ULL,
		0xC789BE9946E1ECC4ULL,
		0x617E95A539086338ULL,
		0xD7419C6E33A132D1ULL,
		0xEEE133537BA13096ULL,
		0xFA77DB6E47D5A1DAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x47D177C3BB665212ULL,
		0x12C7330AA41DE7AFULL,
		0xA2217363488AD26AULL,
		0x37A7B3A068FB48C7ULL,
		0x31DF8983C645A258ULL,
		0xC8281E4CF94E3304ULL,
		0xEFBA7CF5B9DFFA5BULL,
		0x79B7DBC4B665A237ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB3FB4CBD2F4DD7ULL,
		0x7413DE2A45FD9AF5ULL,
		0xC1EA51011903B6AFULL,
		0x5997E0EC3C031945ULL,
		0x5300F329CA7041CEULL,
		0xC0BF3E194BFC14EEULL,
		0xFEF2A9662067C5A6ULL,
		0xC4F02062D0C8A51BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC1D7C76FE37043BULL,
		0x9EB354E05E204CB9ULL,
		0xE03722622F871BBAULL,
		0xDE0FD2B42CF82F81ULL,
		0xDEDE9659FBD56089ULL,
		0x0768E033AD521E15ULL,
		0xF0C7D38F997834B5ULL,
		0xB4C7BB61E59CFD1BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFCCCAE6F1F0DCC7AULL,
		0xD5BC71F599B8ECE7ULL,
		0x975B1CE31F69C8DDULL,
		0xD41543F568A273CFULL,
		0xA7C32B0E1F577CDAULL,
		0xA7C6F1B3119D4D9AULL,
		0xE2E5FF563CB245ECULL,
		0x675315F0455E785CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5808C1AB6125353AULL,
		0xA7A42F103874CAABULL,
		0x4E12DC8EEB1B3847ULL,
		0xA17B4092A82D2E31ULL,
		0x5F47B4E14C25CF8BULL,
		0xB7973CA58B6BCB9FULL,
		0x584A114659E2C30DULL,
		0x09740E8FA005CC4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4C3ECC3BDE89740ULL,
		0x2E1842E56144223CULL,
		0x49484054344E9096ULL,
		0x329A0362C075459EULL,
		0x487B762CD331AD4FULL,
		0xF02FB50D863181FBULL,
		0x8A9BEE0FE2CF82DEULL,
		0x5DDF0760A558AC0DULL
	}};
	sign = 0;
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
		0x7DF7045BD3538654ULL,
		0x83D309231083006FULL,
		0xF02BF800D9459ABFULL,
		0x9EEA8B4F760F90A5ULL,
		0x556FE2289E3343F1ULL,
		0xE6DD2241DFE6C81EULL,
		0x170B3C1605261CDAULL,
		0x90671D5656ED0587ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8C76EA66A9F9EE5ULL,
		0x60168820FD466F3BULL,
		0x33578D0C0B7516E7ULL,
		0xC65C3AF2B4AF069FULL,
		0xECB2786DF41EE467ULL,
		0x50874BC4A8A31648ULL,
		0x45D886325DC16618ULL,
		0xD7035B544A42803CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x852F95B568B3E76FULL,
		0x23BC8102133C9133ULL,
		0xBCD46AF4CDD083D8ULL,
		0xD88E505CC1608A06ULL,
		0x68BD69BAAA145F89ULL,
		0x9655D67D3743B1D5ULL,
		0xD132B5E3A764B6C2ULL,
		0xB963C2020CAA854AULL
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
		0xC57D02791A4271A4ULL,
		0x4E4ADDF77E474B76ULL,
		0xF11092122A12BDE1ULL,
		0x979787BD070E4998ULL,
		0x006E983FA8644872ULL,
		0x6D504F465430F0CBULL,
		0x2950A1C242F352CBULL,
		0xFB3E2C737AFBECB8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42C2061ED096B94ULL,
		0x162C3F7239DB696DULL,
		0xE2239367C17D182CULL,
		0x31D0F673A88924D1ULL,
		0xF93CD778F9339C24ULL,
		0xA08DE577AADFC7CFULL,
		0xFCF4494B564CA862ULL,
		0xA809E3F43A5BD7C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD150E2172D390610ULL,
		0x381E9E85446BE208ULL,
		0x0EECFEAA6895A5B5ULL,
		0x65C691495E8524C7ULL,
		0x0731C0C6AF30AC4EULL,
		0xCCC269CEA95128FBULL,
		0x2C5C5876ECA6AA68ULL,
		0x5334487F40A014EEULL
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
		0xBF1B8E0C41BE909FULL,
		0x93ADB772B1DC2E92ULL,
		0x5CA136C9DAA9B6B3ULL,
		0x11C168CED3B0305FULL,
		0xEC1692527A053407ULL,
		0xEB5E1822E93736BAULL,
		0x5BBCCE2A09FEEBBCULL,
		0x2CBA47CF2153F478ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A58264C133F685DULL,
		0x5865118BB6F1CAF2ULL,
		0x045F2C204C13CC9CULL,
		0x0797DC55FD70B446ULL,
		0x704A15E40B5E4016ULL,
		0xB61EB2B7E0178B5BULL,
		0x53700AEC18C668F5ULL,
		0x23BEF418B1E49E34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84C367C02E7F2842ULL,
		0x3B48A5E6FAEA63A0ULL,
		0x58420AA98E95EA17ULL,
		0x0A298C78D63F7C19ULL,
		0x7BCC7C6E6EA6F3F1ULL,
		0x353F656B091FAB5FULL,
		0x084CC33DF13882C7ULL,
		0x08FB53B66F6F5644ULL
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
		0xF095ACEFC7F505A6ULL,
		0x08EEBEDBD9FB8F6DULL,
		0x5762B10D9F3E987BULL,
		0xAA53CA1929A03A68ULL,
		0x99271EA01DE645FFULL,
		0x855D88465154B25AULL,
		0x58A489C55A081DE0ULL,
		0x62F0F75191876FCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DF558FF83BE600ULL,
		0x6D681B37939C31F0ULL,
		0x664E1AC459424B54ULL,
		0xD19479E2D0ECBA41ULL,
		0x24D2BCBD6FA3A74FULL,
		0x719ED31F442DDE70ULL,
		0xBB1050F8C218C3D9ULL,
		0x12613BCE039AF406ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EB6575FCFB91FA6ULL,
		0x9B86A3A4465F5D7DULL,
		0xF114964945FC4D26ULL,
		0xD8BF503658B38026ULL,
		0x745461E2AE429EAFULL,
		0x13BEB5270D26D3EAULL,
		0x9D9438CC97EF5A07ULL,
		0x508FBB838DEC7BC3ULL
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
		0x865DAB497FF6F097ULL,
		0x2BADB6F98F5B9C2FULL,
		0xF1600E1D9F8EB920ULL,
		0x313D424CBEFCB480ULL,
		0xEE388EC25C628A57ULL,
		0x1002E2D0C680D3CAULL,
		0x7814DB4187BB5C5CULL,
		0xE9CAFF38DD008187ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E0DF46E47CFEF8ULL,
		0x4635667CB434FB3AULL,
		0x2FCE102EDD2DFCA4ULL,
		0xF1E05F52293A3D6DULL,
		0x31E94270680346B5ULL,
		0xC33613F09D497122ULL,
		0x4495C928F27C1631ULL,
		0x8D18677E9FC6882AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x227CCC029B79F19FULL,
		0xE578507CDB26A0F5ULL,
		0xC191FDEEC260BC7BULL,
		0x3F5CE2FA95C27713ULL,
		0xBC4F4C51F45F43A1ULL,
		0x4CCCCEE0293762A8ULL,
		0x337F1218953F462AULL,
		0x5CB297BA3D39F95DULL
	}};
	sign = 0;
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
		0x2212E2D0692E322EULL,
		0xC1EABA12A8C19A68ULL,
		0x8D2B08706FBFFD3FULL,
		0x73E50E74ACCE8256ULL,
		0x26997A333D5A629AULL,
		0xF212B57B8330F099ULL,
		0x3875D28DC2DFFFB2ULL,
		0xD58E864BD92A79E1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF653B71E59B6DD8BULL,
		0xF1578BBE27F1129FULL,
		0xABB1D2170D62E806ULL,
		0x2585DBFAC02DD6E0ULL,
		0x3D82F360464361FAULL,
		0x96DE6BD4D53D02A3ULL,
		0x875862CC7090D1CDULL,
		0x474B5EBA87FB950CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BBF2BB20F7754A3ULL,
		0xD0932E5480D087C8ULL,
		0xE1793659625D1538ULL,
		0x4E5F3279ECA0AB75ULL,
		0xE91686D2F71700A0ULL,
		0x5B3449A6ADF3EDF5ULL,
		0xB11D6FC1524F2DE5ULL,
		0x8E432791512EE4D4ULL
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
		0x30B27278DFF00C8BULL,
		0xAD83F91F5EA46F44ULL,
		0x4889E8E0807D84A8ULL,
		0x191973A2D5C58BB0ULL,
		0xEB1EF00DBAC1549BULL,
		0x8AA5639F8588FCFFULL,
		0x85973B1FC01316FDULL,
		0xE96ADE72385D2723ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60B292C55B122D0ULL,
		0x31DE78CE8AAD7971ULL,
		0x0B21F34D9F6DCBCAULL,
		0x67D8CD08CA773CB5ULL,
		0xE33021339CB7A413ULL,
		0xA316C2EA5CA88B1CULL,
		0xFF7793C9DDDA590FULL,
		0x435B5D2AA9C29DE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AA7494C8A3EE9BBULL,
		0x7BA58050D3F6F5D2ULL,
		0x3D67F592E10FB8DEULL,
		0xB140A69A0B4E4EFBULL,
		0x07EECEDA1E09B087ULL,
		0xE78EA0B528E071E3ULL,
		0x861FA755E238BDEDULL,
		0xA60F81478E9A893DULL
	}};
	sign = 0;
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
		0xAA183B395F7B40ADULL,
		0x4685C0B043FC426DULL,
		0x4FC694FBDE11D96CULL,
		0xBC4759707FD04BE0ULL,
		0xD836B1009358554FULL,
		0x5B1333E8A68FCD13ULL,
		0x5A5C102EDCC722ACULL,
		0xB92ADB55614073E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x888E4152968EEC4EULL,
		0x4560EE4DCEF76A61ULL,
		0x4A57B7584D7258FCULL,
		0x041D81232F3F2446ULL,
		0x84717EE9D3B54204ULL,
		0x2234DFD998066ADEULL,
		0xA55F45B7236AF590ULL,
		0xF3B3DB496B4A83FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2189F9E6C8EC545FULL,
		0x0124D2627504D80CULL,
		0x056EDDA3909F8070ULL,
		0xB829D84D5091279AULL,
		0x53C53216BFA3134BULL,
		0x38DE540F0E896235ULL,
		0xB4FCCA77B95C2D1CULL,
		0xC577000BF5F5EFE6ULL
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
		0x0CB417352489912CULL,
		0xCC85AD3B15CC0233ULL,
		0xFF81E8CBBFE59664ULL,
		0xEEF1810DDAFAB39EULL,
		0x405DD553E98B3899ULL,
		0xF91EB5153F39BBE8ULL,
		0x7F04FDFD0A680F93ULL,
		0xE28965B1520703CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F9468031D3E228ULL,
		0x94A61B2368066AA0ULL,
		0x3D3C15C8CDADA552ULL,
		0x9D8B14E70F0CF7BDULL,
		0x983568F11D7D0F28ULL,
		0x64ED054ACA2C4332ULL,
		0x9E3BBDB9F1E5E263ULL,
		0xEAFAEAFE427999E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9BAD0B4F2B5AF04ULL,
		0x37DF9217ADC59792ULL,
		0xC245D302F237F112ULL,
		0x51666C26CBEDBBE1ULL,
		0xA8286C62CC0E2971ULL,
		0x9431AFCA750D78B5ULL,
		0xE0C9404318822D30ULL,
		0xF78E7AB30F8D69E3ULL
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
		0x8496D06FC5DF6B73ULL,
		0x18347FF281AAD715ULL,
		0x8CE25EC78E94D930ULL,
		0xA4FB273444CE682BULL,
		0x5DBA3B2FD9699B46ULL,
		0x09F727CAE835E7B2ULL,
		0x322CF399CEC614D6ULL,
		0xCF0B16FBAB51A487ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06A7A9602E974A2CULL,
		0x43B0624352C3107BULL,
		0x9B0556B528D370ADULL,
		0x919EAAF4C1A4586BULL,
		0xA42A928EBD03BB8DULL,
		0x426EB9F0C52B466CULL,
		0x7A1CE3A5090FF37FULL,
		0x370F895AD7C9875BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DEF270F97482147ULL,
		0xD4841DAF2EE7C69AULL,
		0xF1DD081265C16882ULL,
		0x135C7C3F832A0FBFULL,
		0xB98FA8A11C65DFB9ULL,
		0xC7886DDA230AA145ULL,
		0xB8100FF4C5B62156ULL,
		0x97FB8DA0D3881D2BULL
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
		0x903BB455DDE8A3E8ULL,
		0xB78521E8D6D7AD5AULL,
		0x8B8431083331C3BDULL,
		0xFF87FD2DAB484D88ULL,
		0x4A6330260EA71478ULL,
		0x67DAD527D700D492ULL,
		0x5DC4FD31608186E0ULL,
		0xD5146B55E7DA60F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B20B06A5CCFC68ULL,
		0x754FF87A4EE553CEULL,
		0xC46883A6367DC132ULL,
		0xA76795B5D74ED590ULL,
		0x6F5D4C5A557ABCF7ULL,
		0xE68D3F7420E49553ULL,
		0xC884EE1842FB13B9ULL,
		0x86E31ABB459561C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC889A94F381BA780ULL,
		0x4235296E87F2598BULL,
		0xC71BAD61FCB4028BULL,
		0x58206777D3F977F7ULL,
		0xDB05E3CBB92C5781ULL,
		0x814D95B3B61C3F3EULL,
		0x95400F191D867326ULL,
		0x4E31509AA244FF31ULL
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
		0x52004063320127E5ULL,
		0x2141EE993269B828ULL,
		0xEA5FA521141A8DD1ULL,
		0xC6E9A07BC0F7DCA1ULL,
		0x349A6958A0DFC6B2ULL,
		0x0312A80104F7F0ACULL,
		0x918FF2A31329A83CULL,
		0x13A2AA365E700C24ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x903B2BB589562C54ULL,
		0x91F34E5D0A3787EAULL,
		0x6FBBC6049E3BFBAAULL,
		0x2F49572F58B150EEULL,
		0x379DF1DBCCE03242ULL,
		0x5A30335333378019ULL,
		0x738E6D1BF3207CE5ULL,
		0x7D731D5DBC57131AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1C514ADA8AAFB91ULL,
		0x8F4EA03C2832303DULL,
		0x7AA3DF1C75DE9226ULL,
		0x97A0494C68468BB3ULL,
		0xFCFC777CD3FF9470ULL,
		0xA8E274ADD1C07092ULL,
		0x1E01858720092B56ULL,
		0x962F8CD8A218F90AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF283098C8E03C8F3ULL,
		0x23472AC88FFBD194ULL,
		0x97474F3422AFF8E0ULL,
		0x6E1B0B1F4EE2021CULL,
		0x09DE32DF54682AE8ULL,
		0xA793CB6F87598522ULL,
		0x9F72BAF8EA12C8C9ULL,
		0x7A3437AD25A19F5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0CA0FF00AF5ABEAULL,
		0xC7372AA72FA81EECULL,
		0x1E7DB7ACF8482DE3ULL,
		0x319F59F39C7CF36BULL,
		0xA2FB479173CAA362ULL,
		0xEB2C15B438B59CB1ULL,
		0x49625AC284ABC080ULL,
		0x36262E77873F6D95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01B8F99C830E1D09ULL,
		0x5C1000216053B2A8ULL,
		0x78C997872A67CAFCULL,
		0x3C7BB12BB2650EB1ULL,
		0x66E2EB4DE09D8786ULL,
		0xBC67B5BB4EA3E870ULL,
		0x5610603665670848ULL,
		0x440E09359E6231C9ULL
	}};
	sign = 0;
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
		0x373BE7FF5B679695ULL,
		0x097FF0FD251B6C1FULL,
		0xF28AFBEBE3D68C3FULL,
		0x66606CED109448E0ULL,
		0x28B0476F73D94E95ULL,
		0xF014A195B0E9E516ULL,
		0x87E2D482A04E20B0ULL,
		0x763EBCBAF39EF93EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32821E56E0455927ULL,
		0xB56A4836D4C6242BULL,
		0xF62DC9B6EAA589E6ULL,
		0xD9F741D3F9253088ULL,
		0x5B1B6329EC8D02C8ULL,
		0xE2111CC00E9BF3B7ULL,
		0x5CF24EE43FC50015ULL,
		0xF6A831E7E37B78E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04B9C9A87B223D6EULL,
		0x5415A8C6505547F4ULL,
		0xFC5D3234F9310258ULL,
		0x8C692B19176F1857ULL,
		0xCD94E445874C4BCCULL,
		0x0E0384D5A24DF15EULL,
		0x2AF0859E6089209BULL,
		0x7F968AD310238055ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5B248072E13095A4ULL,
		0x6A2EDCC203E462CFULL,
		0xDA2E3F258A92832FULL,
		0xA8E6FB247A42C827ULL,
		0xDEFD096DF520B53DULL,
		0x81A1508AE4A5BE37ULL,
		0xBC09051E6793BC1BULL,
		0x9189B3F6DB85D29DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C5C357D93F3002ULL,
		0x727A988FAF0AD56BULL,
		0x383632EB1DEA1C54ULL,
		0xA1D6A20AABA41001ULL,
		0xB9752F549A301A5CULL,
		0x22649E60845F0314ULL,
		0xA2DEB6CB49DF21ACULL,
		0xECA94D751435101DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x525EBD1B07F165A2ULL,
		0xF7B4443254D98D64ULL,
		0xA1F80C3A6CA866DAULL,
		0x07105919CE9EB826ULL,
		0x2587DA195AF09AE1ULL,
		0x5F3CB22A6046BB23ULL,
		0x192A4E531DB49A6FULL,
		0xA4E06681C750C280ULL
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
		0x004A6A98C74578A4ULL,
		0xF0CC4E943B746266ULL,
		0xF14F8FF861D4BFBBULL,
		0xCF74229D41DCAA58ULL,
		0x153B600D224F7DE0ULL,
		0xE04C0D7BD3D44F68ULL,
		0xCF05FF01AFFE1D76ULL,
		0xB5E3DD491B49377FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3C22BF0D95F7F3ULL,
		0x4BBDB99C5089C533ULL,
		0x53635DA2AE4EE1ECULL,
		0xBD41C4756948B751ULL,
		0x70ACA36DFE119B74ULL,
		0xB98C05687CE9D966ULL,
		0xEC60573E0AC95CC0ULL,
		0xCEE3927C4E00D81BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x740E47D9B9AF80B1ULL,
		0xA50E94F7EAEA9D32ULL,
		0x9DEC3255B385DDCFULL,
		0x12325E27D893F307ULL,
		0xA48EBC9F243DE26CULL,
		0x26C0081356EA7601ULL,
		0xE2A5A7C3A534C0B6ULL,
		0xE7004ACCCD485F63ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAC888DBEFA16A230ULL,
		0x6718B76E313B4FAAULL,
		0x238F41DB94CA5A86ULL,
		0x6C6380287AB934D4ULL,
		0x5ABF819B79CBDD80ULL,
		0x71FA2964B04DCA51ULL,
		0xC7C348666F7E4E37ULL,
		0x431245EF6F069DEFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CAF005017A909AULL,
		0x0F088913F40F12C7ULL,
		0x0864E2FFA1146A6EULL,
		0xA5108143A8468CCFULL,
		0x402CC95EE60CC43FULL,
		0xE8DA99E9490B027CULL,
		0x34479894C4A663BDULL,
		0x8789A21CCEA95FC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3BD9DB9F89C1196ULL,
		0x58102E5A3D2C3CE2ULL,
		0x1B2A5EDBF3B5F018ULL,
		0xC752FEE4D272A805ULL,
		0x1A92B83C93BF1940ULL,
		0x891F8F7B6742C7D5ULL,
		0x937BAFD1AAD7EA79ULL,
		0xBB88A3D2A05D3E26ULL
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
		0xD75D63427A37ACEBULL,
		0x3F2F22C01CE3BC66ULL,
		0x460F1D44214F783AULL,
		0x5385400A7E0EEEFFULL,
		0xFB2955E31CF646EBULL,
		0x290AE609B08DE58CULL,
		0xF38BC3E2D52D12F0ULL,
		0xEAC08AD5A94B3AB8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34DE9B60F6694901ULL,
		0x5A39B3B18C0C7F47ULL,
		0x19BB266C84473B87ULL,
		0x05C08130E92E3006ULL,
		0xADA96D0B771A1080ULL,
		0x75BB82987EAF712DULL,
		0x2212EEF053DBD17FULL,
		0xAE5E6997B8CE8270ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA27EC7E183CE63EAULL,
		0xE4F56F0E90D73D1FULL,
		0x2C53F6D79D083CB2ULL,
		0x4DC4BED994E0BEF9ULL,
		0x4D7FE8D7A5DC366BULL,
		0xB34F637131DE745FULL,
		0xD178D4F281514170ULL,
		0x3C62213DF07CB848ULL
	}};
	sign = 0;
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
		0xFEA63F0320DF52DEULL,
		0x6B49F0008F13B0D0ULL,
		0x5C66CC80D1312CD2ULL,
		0x6FE92B4D47120C09ULL,
		0xF41DF6D3E4C78D33ULL,
		0x053B44D4DAEEF8A8ULL,
		0x5BA3C7ADC2372B1EULL,
		0x0126D06A22B0280FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA21817DAF5335F3ULL,
		0x9B167BCE03877DBBULL,
		0xA30215DD9C960C0DULL,
		0xC4CCE419864A1982ULL,
		0x45D77B40F5A75C7CULL,
		0x1F1313DE76583DCAULL,
		0x44C51CE9062992C8ULL,
		0x27ECA3AF3E1AA54BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5484BD85718C1CEBULL,
		0xD03374328B8C3315ULL,
		0xB964B6A3349B20C4ULL,
		0xAB1C4733C0C7F286ULL,
		0xAE467B92EF2030B6ULL,
		0xE62830F66496BADEULL,
		0x16DEAAC4BC0D9855ULL,
		0xD93A2CBAE49582C4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF5284E9EFC926D48ULL,
		0xA92E40383285119CULL,
		0x5DA96B9DDFE7F099ULL,
		0x86FF1F359BCE54C5ULL,
		0x526355977FD73DC1ULL,
		0xD2341C855A58DEAFULL,
		0x8722669B23E9BBB1ULL,
		0xC923394597C820D9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA6E631954A7C65ULL,
		0xDB93A50DD832DE07ULL,
		0xCEDB7CEA9F27F68EULL,
		0x18434FD68FCD73A3ULL,
		0x835CD29051262303ULL,
		0xBF280F1AD41945A0ULL,
		0xB951EC9F5AC19075ULL,
		0x7A042D8A6E530CC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A81686D6747F0E3ULL,
		0xCD9A9B2A5A523395ULL,
		0x8ECDEEB340BFFA0AULL,
		0x6EBBCF5F0C00E121ULL,
		0xCF0683072EB11ABEULL,
		0x130C0D6A863F990EULL,
		0xCDD079FBC9282B3CULL,
		0x4F1F0BBB29751413ULL
	}};
	sign = 0;
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
		0xCFD39A52DA6306C0ULL,
		0xF60EEE1BB903B9A5ULL,
		0x01F39DFFBE8B8476ULL,
		0xDDF4624EA8D5712CULL,
		0xFFD8204A86CC6253ULL,
		0xC6B65633180F508DULL,
		0x5059BD6CC8E2B090ULL,
		0x796DB52BD4323AD6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FDBA8D5E482C900ULL,
		0x6F628D55E22F1285ULL,
		0xCE873256B3FAA9EAULL,
		0xBCD7958FF8059E41ULL,
		0xF76C1039E0B98901ULL,
		0x4539B45ED19CB809ULL,
		0x4180CDBB1E739771ULL,
		0x79BB5928B1A4F93AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FF7F17CF5E03DC0ULL,
		0x86AC60C5D6D4A720ULL,
		0x336C6BA90A90DA8CULL,
		0x211CCCBEB0CFD2EAULL,
		0x086C1010A612D952ULL,
		0x817CA1D446729884ULL,
		0x0ED8EFB1AA6F191FULL,
		0xFFB25C03228D419CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD252A3EE3339D66AULL,
		0x2947DA09920FFCBBULL,
		0x765131522269C75FULL,
		0x31A364D7473A5E0DULL,
		0xC8934E2F18DF16C2ULL,
		0xBE00A54D7E00A87EULL,
		0xADF8E0461D45CA71ULL,
		0x6247145F3AE2E721ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0DD05302ECB5482ULL,
		0xCBC805BA6A5B008EULL,
		0xD6BEC59F54B51CFBULL,
		0x3893A1C9DC6AFD9DULL,
		0xFD4F4B496CC206BDULL,
		0x681D02F6AD43785CULL,
		0x584DC306622FB1E9ULL,
		0xC8AE9339C3144D45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21759EBE046E81E8ULL,
		0x5D7FD44F27B4FC2DULL,
		0x9F926BB2CDB4AA63ULL,
		0xF90FC30D6ACF606FULL,
		0xCB4402E5AC1D1004ULL,
		0x55E3A256D0BD3021ULL,
		0x55AB1D3FBB161888ULL,
		0x9998812577CE99DCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x10A3665685134A9CULL,
		0x85C2E3C923EF99EDULL,
		0x77AA705C422D5413ULL,
		0xC15C73F05581E51FULL,
		0x1532334C5C020899ULL,
		0x0010A65CCE4AF403ULL,
		0x591F05BC6F8D7DB8ULL,
		0x9C58BF720FD3806EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32DD501A1780E48CULL,
		0x7E95D9E94D91506CULL,
		0x0E51CA851B979536ULL,
		0xB15CE6EB3D928058ULL,
		0x5D93C8A074CD0534ULL,
		0xC0C01CB8794690F5ULL,
		0x6947E45125E580C9ULL,
		0x98B040907AE71B04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDC6163C6D926610ULL,
		0x072D09DFD65E4980ULL,
		0x6958A5D72695BEDDULL,
		0x0FFF8D0517EF64C7ULL,
		0xB79E6AABE7350365ULL,
		0x3F5089A45504630DULL,
		0xEFD7216B49A7FCEEULL,
		0x03A87EE194EC6569ULL
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
		0x1E047618FFB6467EULL,
		0x712CEF7C214E90E1ULL,
		0xC22328D1667ACB69ULL,
		0x444F6C7D953E39ADULL,
		0xE3C189F7E0F1BEC9ULL,
		0xD53D2F9B918551A4ULL,
		0xC99F431C63B7688EULL,
		0xB77F57028D8DDC52ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x882D2799372551F9ULL,
		0x68E80016A6357366ULL,
		0x2499D3F47263F2CDULL,
		0x8F498BD785D42C65ULL,
		0x1C7EC8749E51CCD4ULL,
		0x083F2DEA510A2E64ULL,
		0x31CA56EF411FFAB0ULL,
		0x755EA0B90D5047E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95D74E7FC890F485ULL,
		0x0844EF657B191D7AULL,
		0x9D8954DCF416D89CULL,
		0xB505E0A60F6A0D48ULL,
		0xC742C183429FF1F4ULL,
		0xCCFE01B1407B2340ULL,
		0x97D4EC2D22976DDEULL,
		0x4220B649803D946BULL
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
		0x7D41E0A1F0F2A7E6ULL,
		0x436DCBC387A745AFULL,
		0xDC392A482F1505FEULL,
		0x6C6E1D219610A4D3ULL,
		0x06219285DCA99C68ULL,
		0x96248DC1241CF47BULL,
		0x1CA0CDAA4E48B5FDULL,
		0xE1293283B892EC73ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56981C29CFAA7989ULL,
		0xFEAD59115697F8F4ULL,
		0x1047A0EE261A9385ULL,
		0xD2DEBC8E9B75DEADULL,
		0x4E0491EF20CAD4BAULL,
		0x8A417C5D3E994390ULL,
		0xCC57E7CFDF026EA0ULL,
		0x51C3CD8AF1D4B217ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26A9C47821482E5DULL,
		0x44C072B2310F4CBBULL,
		0xCBF1895A08FA7278ULL,
		0x998F6092FA9AC626ULL,
		0xB81D0096BBDEC7ADULL,
		0x0BE31163E583B0EAULL,
		0x5048E5DA6F46475DULL,
		0x8F6564F8C6BE3A5BULL
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
		0xACFBA745A77EFF27ULL,
		0x40996AE04CAA0756ULL,
		0x2B5D7276D7BF00B1ULL,
		0x0D576E3779DF1928ULL,
		0xE12A1238A78A5932ULL,
		0xC8026DFF56D3EFBBULL,
		0x59C73E9BAC7A508EULL,
		0x2407A7A0CA0C88ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64EFD4F28FA2418ULL,
		0x1ABF125AF29DED32ULL,
		0xEB6F88A18B2744DDULL,
		0xF32B577E0B2C497BULL,
		0x5C06D1D6D9475EA9ULL,
		0xC40ADF2BF4CB0503ULL,
		0xD071CDDA72453250ULL,
		0xE9538A81DC818C67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6ACA9F67E84DB0FULL,
		0x25DA58855A0C1A23ULL,
		0x3FEDE9D54C97BBD4ULL,
		0x1A2C16B96EB2CFACULL,
		0x85234061CE42FA88ULL,
		0x03F78ED36208EAB8ULL,
		0x895570C13A351E3EULL,
		0x3AB41D1EED8AFC45ULL
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
		0xD42246A85EA66EEFULL,
		0x4195450899206F49ULL,
		0x8434B324DAA1FCFEULL,
		0xB151672B07873C6DULL,
		0x0E6AE77EECC1C3B1ULL,
		0xED2BC74B489F707AULL,
		0x58A315D2337F9EDAULL,
		0xE0905C1637A12B57ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x255201B6A74B2B9EULL,
		0xBC48B951E1DA6AFAULL,
		0xDD50251C73323A18ULL,
		0xD3204C4A80383097ULL,
		0xA9997127BCE697EAULL,
		0x617735D01E4B95C2ULL,
		0xE701C4F552C93CA0ULL,
		0x068A6F98A2CFC265ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAED044F1B75B4351ULL,
		0x854C8BB6B746044FULL,
		0xA6E48E08676FC2E5ULL,
		0xDE311AE0874F0BD5ULL,
		0x64D176572FDB2BC6ULL,
		0x8BB4917B2A53DAB7ULL,
		0x71A150DCE0B6623AULL,
		0xDA05EC7D94D168F1ULL
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
		0x0A101972B40D7779ULL,
		0xF5EF95BA8B04DE49ULL,
		0xEFA9AEC234E6F270ULL,
		0xD3693C3A312116C2ULL,
		0xD5BE88907CFC7006ULL,
		0x3783602531D367EDULL,
		0x61C6BEE1474A5557ULL,
		0xE452A372D5FEE873ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B43AFE3D60792F7ULL,
		0xD6775C3364D6AC81ULL,
		0x8565D48E9BECD3C4ULL,
		0x18DB1E9F931C6352ULL,
		0x2DF878AD3F0768DDULL,
		0x290808E092215A52ULL,
		0x525F43DCD0DB65CAULL,
		0xC02D42C843337F95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ECC698EDE05E482ULL,
		0x1F783987262E31C7ULL,
		0x6A43DA3398FA1EACULL,
		0xBA8E1D9A9E04B370ULL,
		0xA7C60FE33DF50729ULL,
		0x0E7B57449FB20D9BULL,
		0x0F677B04766EEF8DULL,
		0x242560AA92CB68DEULL
	}};
	sign = 0;
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
		0x481FF744933E88C2ULL,
		0x6B44F260C6B5BC27ULL,
		0x45FCAEF8A630673CULL,
		0x081FA1705F2B1F10ULL,
		0xCA1809D97364AA61ULL,
		0xA553D22C615417DBULL,
		0x1F9DDDAC06719D4CULL,
		0x7F397EEC395229F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x754527FE1D4BE44FULL,
		0x9F09D5B177B5A555ULL,
		0xA3A24A7C40535A2CULL,
		0x002E9A53CF7F8312ULL,
		0x75B8A1BFFBF9E8AEULL,
		0x7C7868E06B1ABF79ULL,
		0x590263EC24B89374ULL,
		0x15D44C935E9324C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2DACF4675F2A473ULL,
		0xCC3B1CAF4F0016D1ULL,
		0xA25A647C65DD0D0FULL,
		0x07F1071C8FAB9BFDULL,
		0x545F6819776AC1B3ULL,
		0x28DB694BF6395862ULL,
		0xC69B79BFE1B909D8ULL,
		0x69653258DABF052FULL
	}};
	sign = 0;
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
		0xDD020D2CF403F978ULL,
		0x09C4D0A5E007A984ULL,
		0xE5F049A20E34C4C9ULL,
		0x8325BF77635C4CAEULL,
		0x89CD201F182C577FULL,
		0x6030B20B2F0EB158ULL,
		0xD431F6C0E8D1EF6CULL,
		0x8725295BCF1B5392ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD737D7160692245ULL,
		0x333E765BC2800E80ULL,
		0xC7FEC093CB3F3FD6ULL,
		0xE16874213348CFB1ULL,
		0xA46E820EA2955D6BULL,
		0x9F9FC0801B27BE5DULL,
		0x91F633D1734BA636ULL,
		0xD16FB3A6C4CBE3FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F8E8FBB939AD733ULL,
		0xD6865A4A1D879B04ULL,
		0x1DF1890E42F584F2ULL,
		0xA1BD4B5630137CFDULL,
		0xE55E9E107596FA13ULL,
		0xC090F18B13E6F2FAULL,
		0x423BC2EF75864935ULL,
		0xB5B575B50A4F6F97ULL
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
		0x10D09C725E64CC6CULL,
		0x75938BE1CAB7CEC5ULL,
		0x4901CA13B525288EULL,
		0xA445E772773429CCULL,
		0x382E04DCFB2B195CULL,
		0x335D6A61AE6CC05EULL,
		0xC0B1017354ADE670ULL,
		0x19A49AF81709371EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCED3ED3A8E769F3ULL,
		0x9E70FF4EC8507EA4ULL,
		0xE75E653B234A7A52ULL,
		0xBC9F37705D0B4087ULL,
		0x80A444F8ED01CE2DULL,
		0x009A009DE5D4011BULL,
		0x66939717E3AEF9A9ULL,
		0xABB13212573958C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33E35D9EB57D6279ULL,
		0xD7228C9302675020ULL,
		0x61A364D891DAAE3BULL,
		0xE7A6B0021A28E944ULL,
		0xB789BFE40E294B2EULL,
		0x32C369C3C898BF42ULL,
		0x5A1D6A5B70FEECC7ULL,
		0x6DF368E5BFCFDE5AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9D250DC0B1A668A0ULL,
		0x12C3AD310CBAF6D9ULL,
		0xD90014AEA0564191ULL,
		0x8AB6A5E28CF64B1BULL,
		0x91145678A45F1206ULL,
		0x4CAF6476F6137C91ULL,
		0x1F7B902CA1D52ACDULL,
		0x3CA7203F780D170BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0208F62948680B0EULL,
		0x70824BEFEE1E8402ULL,
		0xD557B9D68B80875DULL,
		0x53CF38C09A04CC37ULL,
		0x5EC400BBDE18A32DULL,
		0x3CF54E9A8CC75A8DULL,
		0x6A2C9026741E98FBULL,
		0x569038E6E7C6EEE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B1C1797693E5D92ULL,
		0xA24161411E9C72D7ULL,
		0x03A85AD814D5BA33ULL,
		0x36E76D21F2F17EE4ULL,
		0x325055BCC6466ED9ULL,
		0x0FBA15DC694C2204ULL,
		0xB54F00062DB691D2ULL,
		0xE616E75890462825ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0249C5F350C2A98BULL,
		0x0DE15571E505E0C7ULL,
		0xF53E8B407AB1660EULL,
		0xBF5BF4094564711CULL,
		0x0B073C99E87C49A0ULL,
		0xB288116EDB9631F8ULL,
		0x720D8168EDE2C48EULL,
		0xE3F747029D73C195ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5392BD6F1DF4F6CFULL,
		0x9FC16333BB7851AEULL,
		0x4C7320E28A3C34FEULL,
		0x3C8BF8C7CF8260EFULL,
		0xF363DAFE027DE484ULL,
		0x098A660B3B374FB1ULL,
		0x259007F902943506ULL,
		0x55A513FAEA373C37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEB7088432CDB2BCULL,
		0x6E1FF23E298D8F18ULL,
		0xA8CB6A5DF075310FULL,
		0x82CFFB4175E2102DULL,
		0x17A3619BE5FE651CULL,
		0xA8FDAB63A05EE246ULL,
		0x4C7D796FEB4E8F88ULL,
		0x8E523307B33C855EULL
	}};
	sign = 0;
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
		0xFCB91D2DE9522220ULL,
		0xF71A39AEA8E82410ULL,
		0xC70F3AABC98643D6ULL,
		0x651AC26C9187A35BULL,
		0xA4F11DB1CE40428EULL,
		0xA78FFAD94458D94BULL,
		0xFFE7D07F622A71CBULL,
		0xB5FD918E1864CD7EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC191FF0963755CBAULL,
		0x9BCA34BBF5B8DF71ULL,
		0x74B9FC70B9BE4BDAULL,
		0x84957E8BC89EA9AAULL,
		0x9407B3970EC76F59ULL,
		0xBEEA18566D07367BULL,
		0xE7B4448381053E47ULL,
		0x0E584CABE1396E40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B271E2485DCC566ULL,
		0x5B5004F2B32F449FULL,
		0x52553E3B0FC7F7FCULL,
		0xE08543E0C8E8F9B1ULL,
		0x10E96A1ABF78D334ULL,
		0xE8A5E282D751A2D0ULL,
		0x18338BFBE1253383ULL,
		0xA7A544E2372B5F3EULL
	}};
	sign = 0;
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
		0xC54779DAF285ADEEULL,
		0xC8332C61AB0B22B0ULL,
		0x0FE4DA0582F01CB9ULL,
		0x68C0CF11466414EEULL,
		0xACDE807CC303452CULL,
		0x0060774536C08725ULL,
		0xDEC592A0D976D99CULL,
		0xF67875A8E8050C62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD132D3DD059E677BULL,
		0x86B4A4BCFDDA40CAULL,
		0x65D40D5FF3BBF181ULL,
		0x6F072887F052D853ULL,
		0xC7C10EEB07AFE314ULL,
		0x1ACFAFE2646A964EULL,
		0x4E3B698B4670B42FULL,
		0x65C3420EB95DF8ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF414A5FDECE74673ULL,
		0x417E87A4AD30E1E5ULL,
		0xAA10CCA58F342B38ULL,
		0xF9B9A68956113C9AULL,
		0xE51D7191BB536217ULL,
		0xE590C762D255F0D6ULL,
		0x908A29159306256CULL,
		0x90B5339A2EA713B5ULL
	}};
	sign = 0;
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
		0xA7C41F29DDE2D9A2ULL,
		0xB1610DE3438DCB59ULL,
		0xF7FC537D09701F22ULL,
		0x77BB686F2458A83CULL,
		0xD2F51F00A3564C38ULL,
		0x7F5E1AD67F83C9D2ULL,
		0x1E9DFC6DF3733810ULL,
		0xD7623F5B26B35336ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F916E1AE5352D8ULL,
		0x5416718B14A71B5FULL,
		0x3638E9C2E98B3D18ULL,
		0xC67AE6DF5A96654EULL,
		0xEEBEBD8AEB58DED8ULL,
		0x72E6981DB9803F7CULL,
		0x1E70E8B45529A599ULL,
		0x289CE91F16A6E54BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3CB08482F8F86CAULL,
		0x5D4A9C582EE6AFF9ULL,
		0xC1C369BA1FE4E20AULL,
		0xB140818FC9C242EEULL,
		0xE4366175B7FD6D5FULL,
		0x0C7782B8C6038A55ULL,
		0x002D13B99E499277ULL,
		0xAEC5563C100C6DEBULL
	}};
	sign = 0;
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
		0x9227F10FB78A1695ULL,
		0x08561AF131C9C1F5ULL,
		0x32F1FBD60E797001ULL,
		0xD435E197963F8298ULL,
		0x4614C0637BC977C6ULL,
		0xC54DB924681254DCULL,
		0x1918322C8AF07E1BULL,
		0x542B00E1E63EFABEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF58DD518D6358D02ULL,
		0xF64687BA7760E30FULL,
		0x0D3218D26A000E47ULL,
		0xFEA167DA568CDD82ULL,
		0x34C2B60D06602D20ULL,
		0x766FB748A30F225DULL,
		0x847A297F9E8EE67FULL,
		0xED94EA45BEC6A9A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C9A1BF6E1548993ULL,
		0x120F9336BA68DEE5ULL,
		0x25BFE303A47961B9ULL,
		0xD59479BD3FB2A516ULL,
		0x11520A5675694AA5ULL,
		0x4EDE01DBC503327FULL,
		0x949E08ACEC61979CULL,
		0x6696169C27785119ULL
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
		0x604120B214646C5EULL,
		0xE62F9FFCED99D68DULL,
		0xB5B3E56296C52D76ULL,
		0x1BFC8152D1C4279DULL,
		0x0288A260394A9838ULL,
		0x9FC177AB674765C9ULL,
		0x1A6E5EF67D9A7B8BULL,
		0xDB7070B3DD7DA5A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF025825F538DD820ULL,
		0x1400EF0507D189C5ULL,
		0x2BE5CCA6434830B6ULL,
		0xF456405D5B7E8EDFULL,
		0x0A05C3C4715FD051ULL,
		0x0663E8B56171130FULL,
		0x6AE43A46A943022AULL,
		0x5F43A5086B7E8FFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x701B9E52C0D6943EULL,
		0xD22EB0F7E5C84CC7ULL,
		0x89CE18BC537CFCC0ULL,
		0x27A640F5764598BEULL,
		0xF882DE9BC7EAC7E6ULL,
		0x995D8EF605D652B9ULL,
		0xAF8A24AFD4577961ULL,
		0x7C2CCBAB71FF15A3ULL
	}};
	sign = 0;
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
		0x5DBB6500F81BED46ULL,
		0xAEF0E7A855F843C5ULL,
		0x1411E8FBE033694BULL,
		0x5F9F7EE06C4A45CFULL,
		0x1840BE5109F36D81ULL,
		0x0B23A0F804FB08FCULL,
		0xC502E13AA2DF7D2FULL,
		0xC605030F0F7634AAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8658CB4079551004ULL,
		0x72B46B40BEFE0950ULL,
		0xD0B36A7BD734B594ULL,
		0x9379C83000983D65ULL,
		0x8B9155475DA75AADULL,
		0x7E94226B0940EF2EULL,
		0xB2733F755D0E8269ULL,
		0xA5EB389478F7BB5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD76299C07EC6DD42ULL,
		0x3C3C7C6796FA3A74ULL,
		0x435E7E8008FEB3B7ULL,
		0xCC25B6B06BB20869ULL,
		0x8CAF6909AC4C12D3ULL,
		0x8C8F7E8CFBBA19CDULL,
		0x128FA1C545D0FAC5ULL,
		0x2019CA7A967E794EULL
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
		0x173D861EB56C2EF3ULL,
		0x1A27F71802D1BC42ULL,
		0x9760953F0DB334A3ULL,
		0x30EA3FBDC6B4678EULL,
		0x5B9E3238B1F1D290ULL,
		0xF78249348A6C0865ULL,
		0x1023FCFDF46027ACULL,
		0x2FC8AD619B45B711ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x397B7A2504A8F4DBULL,
		0xB32E7D9300EBA740ULL,
		0x70837FD570A93BA0ULL,
		0x347A429F52771607ULL,
		0xFDF333FD293F8E26ULL,
		0xA594A42ACBAA4609ULL,
		0x6BD828E7ED215553ULL,
		0xE8657FAA0312ED15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDC20BF9B0C33A18ULL,
		0x66F9798501E61501ULL,
		0x26DD15699D09F902ULL,
		0xFC6FFD1E743D5187ULL,
		0x5DAAFE3B88B24469ULL,
		0x51EDA509BEC1C25BULL,
		0xA44BD416073ED259ULL,
		0x47632DB79832C9FBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEA747DE94E85A46DULL,
		0x3E9DC510DB0AAF1EULL,
		0xD5C2FB7A261FF6BFULL,
		0xEC3C2EA6D83816F2ULL,
		0x4EB51E69625CA8C7ULL,
		0xF66748F8EBA2774AULL,
		0x5F7114A192F0FF55ULL,
		0x78BDB33C658B387BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA42C0A293B5091FULL,
		0xC952C091D77DA04BULL,
		0x874861A5815D9D90ULL,
		0x02EB257C757B63C1ULL,
		0xFA5C562C4A3A6D15ULL,
		0xA25FEAEF7909C083ULL,
		0x0AE81F0CA0C5973BULL,
		0x33F6F16378AD4B69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF031BD46BAD09B4EULL,
		0x754B047F038D0ED2ULL,
		0x4E7A99D4A4C2592EULL,
		0xE951092A62BCB331ULL,
		0x5458C83D18223BB2ULL,
		0x54075E097298B6C6ULL,
		0x5488F594F22B681AULL,
		0x44C6C1D8ECDDED12ULL
	}};
	sign = 0;
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
		0xC692EEA6BB1673A1ULL,
		0x66A0798CA423F8D8ULL,
		0x96ED494AF3A4007AULL,
		0x1632760FDC66728BULL,
		0xCDC30BC88508937AULL,
		0x2C61278CFA77AECDULL,
		0x3D60DB0DE3DD1C76ULL,
		0x3D59217B8DDB4022ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4805301C741387EULL,
		0x9E3312959F9AD785ULL,
		0xBEE040B285089D88ULL,
		0x138B5748A9F41236ULL,
		0xD97420DB61CD1759ULL,
		0xDEB287F7AC235F62ULL,
		0x00572A0C53A2FECEULL,
		0x7A8992A78BC0DE93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2129BA4F3D53B23ULL,
		0xC86D66F704892152ULL,
		0xD80D08986E9B62F1ULL,
		0x02A71EC732726054ULL,
		0xF44EEAED233B7C21ULL,
		0x4DAE9F954E544F6AULL,
		0x3D09B101903A1DA7ULL,
		0xC2CF8ED4021A618FULL
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
		0xEA8D0DDD8066FD0AULL,
		0xEDE5488AC2B899F6ULL,
		0x437C14B2B9554D0CULL,
		0x1DD26280C05F8CBBULL,
		0x24F7130C36BEFDCFULL,
		0x6F2D02B7257E9FD3ULL,
		0xDCCAFBD7ACECFF86ULL,
		0x5AC1BF3CC0BCFE39ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C55FC1FFDABB82CULL,
		0xBF2CF775A806E190ULL,
		0x40CA38B5DA7EA4ECULL,
		0x2F6907D3D1EAB7C3ULL,
		0x316D94127DA14267ULL,
		0x31DCBDC132DB639DULL,
		0x4368921E8422B619ULL,
		0xE63AFE0CBAE60233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E3711BD82BB44DEULL,
		0x2EB851151AB1B866ULL,
		0x02B1DBFCDED6A820ULL,
		0xEE695AACEE74D4F8ULL,
		0xF3897EF9B91DBB67ULL,
		0x3D5044F5F2A33C35ULL,
		0x996269B928CA496DULL,
		0x7486C13005D6FC06ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x32518C8A1585D949ULL,
		0x338320B4CEE3D496ULL,
		0x8125AF46CB2D3EA4ULL,
		0xE463EF27AA5E1278ULL,
		0x4FE67534ABB317BAULL,
		0xE7066D07DA16F9E4ULL,
		0x0051B51C084EFBFBULL,
		0xA4C899B1E6AE43E2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4345D9F90A6B3FBULL,
		0xC4E92268D6AB89CDULL,
		0xEC8225D50C45E100ULL,
		0xDDA173C728226AF7ULL,
		0xCF2A0D1CD38452F0ULL,
		0xF0357A42CA0EFB9CULL,
		0x1F3C8CF33FD8F10AULL,
		0xA499F50BE24ED22DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E1D2EEA84DF254EULL,
		0x6E99FE4BF8384AC8ULL,
		0x94A38971BEE75DA3ULL,
		0x06C27B60823BA780ULL,
		0x80BC6817D82EC4CAULL,
		0xF6D0F2C51007FE47ULL,
		0xE1152828C8760AF0ULL,
		0x002EA4A6045F71B4ULL
	}};
	sign = 0;
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
		0x232B0C3767CA81DDULL,
		0x4293142266318238ULL,
		0x661D1454563037D8ULL,
		0x6CBD88E5626903F8ULL,
		0xE74854ECD8D8A68FULL,
		0xD1C603E2C4EF08B0ULL,
		0x81CF03DA3C677336ULL,
		0xB6A91E3BF77128B3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A58968A87A5DC7ULL,
		0x5A9F154B3E5FC51BULL,
		0xC7E34FA67FB915A8ULL,
		0xECB6C26834710928ULL,
		0x446B809426211327ULL,
		0x265349138037FA33ULL,
		0xF58BB7EF5F8BAF1BULL,
		0x60F52ED4F47DDE6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF08582CEBF502416ULL,
		0xE7F3FED727D1BD1CULL,
		0x9E39C4ADD677222FULL,
		0x8006C67D2DF7FACFULL,
		0xA2DCD458B2B79367ULL,
		0xAB72BACF44B70E7DULL,
		0x8C434BEADCDBC41BULL,
		0x55B3EF6702F34A47ULL
	}};
	sign = 0;
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
		0x712524E0AB465740ULL,
		0xE21D5DCD4FB9360CULL,
		0xB24033F3C67F5305ULL,
		0xE7A9359878CA0AFCULL,
		0x35263685B5CFB627ULL,
		0x34F3E5E121303E1FULL,
		0x8DC886D339ACEE00ULL,
		0x85C8CC8085989B35ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76EC6E0CB9247AAAULL,
		0xB5ED06C860512C25ULL,
		0xC686E8887EE54172ULL,
		0xFE4643C87CC465EAULL,
		0x8ACD4ED7C30F25E6ULL,
		0x91A181EEFC460DBFULL,
		0x8BF5511CE4A366BFULL,
		0x2FB5DBA8D68836F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA38B6D3F221DC96ULL,
		0x2C305704EF6809E6ULL,
		0xEBB94B6B479A1193ULL,
		0xE962F1CFFC05A511ULL,
		0xAA58E7ADF2C09040ULL,
		0xA35263F224EA305FULL,
		0x01D335B655098740ULL,
		0x5612F0D7AF106440ULL
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
		0x5DB3BA4BD1BFCE3EULL,
		0x60DFE8BC67B773E2ULL,
		0x51E9A480D80A79BEULL,
		0x930E5BA5FCD5D265ULL,
		0x69AA4428FAAE53ACULL,
		0x45D37F11ADF2CF7DULL,
		0xB15B130AD33983CBULL,
		0x49AF6C2BD086AE21ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95CDEAF76E54931BULL,
		0xC3E61FA5D7B5575EULL,
		0x0A09083D6D87ED8EULL,
		0x5F4EBECCE93F022EULL,
		0xB020DF1E550CA0C0ULL,
		0xE2B44A8FB097514FULL,
		0x04EE5A5E868C5A6AULL,
		0xA7C7C9D18A5EFB6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7E5CF54636B3B23ULL,
		0x9CF9C91690021C83ULL,
		0x47E09C436A828C2FULL,
		0x33BF9CD91396D037ULL,
		0xB989650AA5A1B2ECULL,
		0x631F3481FD5B7E2DULL,
		0xAC6CB8AC4CAD2960ULL,
		0xA1E7A25A4627B2B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9EE4FDB2A9106545ULL,
		0xEB169A56C2227D25ULL,
		0x73B1E3BA230435D7ULL,
		0x47091874F45273B7ULL,
		0x954E8E424BDD649DULL,
		0x3794684B5657FCA4ULL,
		0x7CBD91618B52F475ULL,
		0xD4DC99989301F800ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37838ABCF60169D5ULL,
		0xC18316CAD509E049ULL,
		0xE01E1D7EF4FFDD0EULL,
		0xB6F3E727103F8FF8ULL,
		0xDA35FB1C8413091CULL,
		0xBE837F1AB6FCA9C5ULL,
		0x8F1187D76CF0AE62ULL,
		0xC3C51B35619B220FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x676172F5B30EFB70ULL,
		0x2993838BED189CDCULL,
		0x9393C63B2E0458C9ULL,
		0x9015314DE412E3BEULL,
		0xBB189325C7CA5B80ULL,
		0x7910E9309F5B52DEULL,
		0xEDAC098A1E624612ULL,
		0x11177E633166D5F0ULL
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
		0x9C698204B929A76BULL,
		0x5BA1E2901689E88CULL,
		0xFD82F2DFE37926DFULL,
		0x7AFB084C578EF9A2ULL,
		0x96267F04C5A0C2F8ULL,
		0x67AD2737596B23A6ULL,
		0x75BF4D8DF27C82B8ULL,
		0x8060FAA5667FBD31ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A51C842A9FD2F55ULL,
		0x3D623454A4B65B6AULL,
		0xE230DE93531D7709ULL,
		0x740BD47228F69D7BULL,
		0x1B2AB245D8901451ULL,
		0x4206744EEEE01CD1ULL,
		0x5F3BC68EE4FA6A17ULL,
		0x0F5E94574F560347ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1217B9C20F2C7816ULL,
		0x1E3FAE3B71D38D22ULL,
		0x1B52144C905BAFD6ULL,
		0x06EF33DA2E985C27ULL,
		0x7AFBCCBEED10AEA7ULL,
		0x25A6B2E86A8B06D5ULL,
		0x168386FF0D8218A1ULL,
		0x7102664E1729B9EAULL
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
		0x591D287D97678D96ULL,
		0x446F2EC4E9B9AE21ULL,
		0x777CADF6915CE7D6ULL,
		0xB0E9514DAD809727ULL,
		0x155340B2D36BD534ULL,
		0x321FCDDC99631C96ULL,
		0x6414A3E4C8BD4AC8ULL,
		0xBDC9CB7557884769ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ECADED94BC983B4ULL,
		0xDA5062F1F2895F2CULL,
		0x621B3C1E31B33B8FULL,
		0x2589B813DDFBE578ULL,
		0xB4C78A2ABEA5C2CCULL,
		0xDB0C33E8ADA2B9BAULL,
		0xD0FD22330AF7A2D2ULL,
		0x2CB94D5A57973B12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA5249A44B9E09E2ULL,
		0x6A1ECBD2F7304EF4ULL,
		0x156171D85FA9AC46ULL,
		0x8B5F9939CF84B1AFULL,
		0x608BB68814C61268ULL,
		0x571399F3EBC062DBULL,
		0x931781B1BDC5A7F5ULL,
		0x91107E1AFFF10C56ULL
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
		0xF177CFC6FEBB94D7ULL,
		0x5C88D24ACED37996ULL,
		0x0CDF1EBBA4C26B11ULL,
		0x7613475423139D7BULL,
		0x4DFF2E270643A8B7ULL,
		0xE194351233CAD650ULL,
		0x3947F27C17FE7DE2ULL,
		0x1C25CCC5ACA9CE13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x442E4C79ED76CE18ULL,
		0x42B907F7C423150BULL,
		0xDA03B774F552A078ULL,
		0x1A63C80853DCE08BULL,
		0x1F3977B28492FEC6ULL,
		0x875AEA9BF7EC62F3ULL,
		0x6F95C3372C4382BFULL,
		0xACE39C4EBE366E80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD49834D1144C6BFULL,
		0x19CFCA530AB0648BULL,
		0x32DB6746AF6FCA99ULL,
		0x5BAF7F4BCF36BCEFULL,
		0x2EC5B67481B0A9F1ULL,
		0x5A394A763BDE735DULL,
		0xC9B22F44EBBAFB23ULL,
		0x6F423076EE735F92ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x575534A05160ECF1ULL,
		0x9F07A0703321AAC2ULL,
		0x6374DBB20D4AC12EULL,
		0x2E7C6B5E0B3D69D9ULL,
		0xA13A37BBC5A8A2F5ULL,
		0xA2D552BB7B21B158ULL,
		0x2C26C94139CAFA13ULL,
		0x3EC06182615BBCADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B880C2ACCB926BULL,
		0x1848E51A7751A501ULL,
		0xD9ECFD953E5425DAULL,
		0x0D65A849BFE5943AULL,
		0xC1B087DFB9710E67ULL,
		0x5D80DAFD01C196D3ULL,
		0x6181F433BCB8FDDCULL,
		0x6A35B62D245FABAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF39CB3DDA4955A86ULL,
		0x86BEBB55BBD005C0ULL,
		0x8987DE1CCEF69B54ULL,
		0x2116C3144B57D59EULL,
		0xDF89AFDC0C37948EULL,
		0x455477BE79601A84ULL,
		0xCAA4D50D7D11FC37ULL,
		0xD48AAB553CFC10FDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC8D7B2F95E175C44ULL,
		0x19D399D489F2737DULL,
		0x2126B0A530E1D0EEULL,
		0x8B25969E5EC9D04AULL,
		0x99C4CF017F972F5CULL,
		0x89EDEB3E0873D153ULL,
		0x7A405257CF56DF5EULL,
		0x568AE4F3C94D5D07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A6A5AF0353C1FDULL,
		0xF6121C7C37CDFA35ULL,
		0x4C76A831C2764BD7ULL,
		0xCA07C40C8F05F82EULL,
		0x6858E4EA65488E34ULL,
		0x819071A1D975EF19ULL,
		0xA080D3B4776A32B4ULL,
		0x5A58D2F24B597568ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87310D4A5AC39A47ULL,
		0x23C17D5852247948ULL,
		0xD4B008736E6B8516ULL,
		0xC11DD291CFC3D81BULL,
		0x316BEA171A4EA127ULL,
		0x085D799C2EFDE23AULL,
		0xD9BF7EA357ECACAAULL,
		0xFC3212017DF3E79EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCFA6B138951EC850ULL,
		0x62DD9D7C3BC0E7D1ULL,
		0x8CEC90FB96922DACULL,
		0xF654291407F63721ULL,
		0x190FE44770A09750ULL,
		0x42F02671EFCA2662ULL,
		0x8C3F6D8951BCF853ULL,
		0x7A95C58E5E67E66BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7452CAE406029A59ULL,
		0x4EA8712FA52DE17DULL,
		0x4DDA0EBE53AF1FD8ULL,
		0xD330D49C17AE2867ULL,
		0xB550553F110BFED1ULL,
		0x492D80687E73F86DULL,
		0xBB522506E47E7CC1ULL,
		0x1CDE4AF09AD77D0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B53E6548F1C2DF7ULL,
		0x14352C4C96930654ULL,
		0x3F12823D42E30DD4ULL,
		0x23235477F0480EBAULL,
		0x63BF8F085F94987FULL,
		0xF9C2A60971562DF4ULL,
		0xD0ED48826D3E7B91ULL,
		0x5DB77A9DC390695EULL
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
		0xF28362CB06EB6D57ULL,
		0xAC2EFB7D393E1DEEULL,
		0x3AE200F686D92C61ULL,
		0xA60EF82A7F5C7767ULL,
		0x7BC842FB9290F5F6ULL,
		0xBA3E93B5804F5C04ULL,
		0x96BD1B636BD82DA5ULL,
		0x0DF243796FAA8E7BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1781587D6B6BBBF8ULL,
		0x88F625571F97A21EULL,
		0x40D20863EC887EF6ULL,
		0x49720C1216EED991ULL,
		0xF90A522CA44BD4F5ULL,
		0xF013A77A3ACCA6E8ULL,
		0xE14B35E570395CFAULL,
		0x99427EA8D0D8610DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB020A4D9B7FB15FULL,
		0x2338D62619A67BD0ULL,
		0xFA0FF8929A50AD6BULL,
		0x5C9CEC18686D9DD5ULL,
		0x82BDF0CEEE452101ULL,
		0xCA2AEC3B4582B51BULL,
		0xB571E57DFB9ED0AAULL,
		0x74AFC4D09ED22D6DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1F907A7F142DC49EULL,
		0xE6206F949FB0CAA6ULL,
		0x5B329AD7544CD32BULL,
		0xE33B8001D434DA95ULL,
		0xEE439A5F75F36FD8ULL,
		0xBD78106700117DA4ULL,
		0xEB67929DB32C49D2ULL,
		0x0C66DD450DDF0037ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C001DDA5F22794ULL,
		0x2F2327A43267361FULL,
		0x3CCB1E774CCE8F99ULL,
		0x05EE9B2F6DA33BE0ULL,
		0x525190BE52EC369EULL,
		0x489B17C0764DF851ULL,
		0x54CCEACB94E69303ULL,
		0x6E34406A53FBA204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15D078A16E3B9D0AULL,
		0xB6FD47F06D499487ULL,
		0x1E677C60077E4392ULL,
		0xDD4CE4D266919EB5ULL,
		0x9BF209A12307393AULL,
		0x74DCF8A689C38553ULL,
		0x969AA7D21E45B6CFULL,
		0x9E329CDAB9E35E33ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA5B9535772930519ULL,
		0x7806ADED971012D8ULL,
		0x56DDCDA82B7B5CABULL,
		0x60C534A55AFE4C90ULL,
		0x29F816F6A93D7FF1ULL,
		0xCA3E13C6CF188F18ULL,
		0x95B579E93063A0C7ULL,
		0x985BCEDB31E5EDB2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B892715A7D9F28FULL,
		0x48C816D777B4C258ULL,
		0x32521FEC7A77D338ULL,
		0x8C6192078930A9F6ULL,
		0x67C671FB4F9083D4ULL,
		0x45D1D727A32D0557ULL,
		0xB5C6BE558CEC441FULL,
		0x97F4A67A3DFD10A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A302C41CAB9128AULL,
		0x2F3E97161F5B5080ULL,
		0x248BADBBB1038973ULL,
		0xD463A29DD1CDA29AULL,
		0xC231A4FB59ACFC1CULL,
		0x846C3C9F2BEB89C0ULL,
		0xDFEEBB93A3775CA8ULL,
		0x00672860F3E8DD0EULL
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
		0x7FDE0C1156171C6BULL,
		0x35817A62BF923DD2ULL,
		0xF3CE3AD12EE02ECCULL,
		0x5E9EB2054539BA82ULL,
		0x926295078E6B7ABDULL,
		0x82240113251E1B08ULL,
		0xF58DC590867FC431ULL,
		0xD343F56D8FA9C3F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BE3D82444B4D88ULL,
		0x5939EF21886A8ADCULL,
		0x6CB90503D4EE163FULL,
		0x011C77D5D3B5F6F7ULL,
		0x44C4C4657F86273CULL,
		0x635109FA535E075FULL,
		0x83821993E24C3C52ULL,
		0x3060E39600B6A6EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD61FCE8F11CBCEE3ULL,
		0xDC478B413727B2F5ULL,
		0x871535CD59F2188CULL,
		0x5D823A2F7183C38BULL,
		0x4D9DD0A20EE55381ULL,
		0x1ED2F718D1C013A9ULL,
		0x720BABFCA43387DFULL,
		0xA2E311D78EF31D03ULL
	}};
	sign = 0;
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
		0x1F3F993CC3617DA8ULL,
		0x0E595A1A3180D9A0ULL,
		0xD63FFDE4A2C3932EULL,
		0xCB3A2750BC67B216ULL,
		0x2BE24AD10AC432CFULL,
		0x89C7B3FBA6452637ULL,
		0x30E209582B3411C5ULL,
		0x474C8C66DBD9BD8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF395359EBC704FULL,
		0x5DF364025A4FC429ULL,
		0xFBD450B8D2D63863ULL,
		0xCC300A7CD24B5AD0ULL,
		0x033B46BBA4CEE572ULL,
		0xFEE9EA928C965216ULL,
		0xA773079F30A98FEAULL,
		0x1AF0F2F6F8B77170ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x014C040724A50D59ULL,
		0xB065F617D7311577ULL,
		0xDA6BAD2BCFED5ACAULL,
		0xFF0A1CD3EA1C5745ULL,
		0x28A7041565F54D5CULL,
		0x8ADDC96919AED421ULL,
		0x896F01B8FA8A81DAULL,
		0x2C5B996FE3224C1EULL
	}};
	sign = 0;
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
		0xED51C3983CF86590ULL,
		0x27A464240936D241ULL,
		0xE635CD41942B497CULL,
		0x9251D77F7454E535ULL,
		0xF9ECDB321A753871ULL,
		0xD74196A4F09CBF17ULL,
		0x54F331923634D9B5ULL,
		0xE092AB00B63CDF9AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A57502F5CF8F00AULL,
		0x5375B321F50CF1C0ULL,
		0x727B136F2FBDD9ACULL,
		0xDAEBD49172247FE5ULL,
		0x193E93F1931F6809ULL,
		0x942A87D854BC2152ULL,
		0xF8B3C6ED3AF50CBFULL,
		0x4ACED7A415B0E6E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2FA7368DFFF7586ULL,
		0xD42EB1021429E081ULL,
		0x73BAB9D2646D6FCFULL,
		0xB76602EE02306550ULL,
		0xE0AE47408755D067ULL,
		0x43170ECC9BE09DC5ULL,
		0x5C3F6AA4FB3FCCF6ULL,
		0x95C3D35CA08BF8B9ULL
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
		0xC7FAF98A525F9C9AULL,
		0xB1F34E4896F75CB2ULL,
		0x9B82754EC64FAEB9ULL,
		0xA3EE8EB7415176FCULL,
		0x4CF70F882AB481F0ULL,
		0x9FA0339513503820ULL,
		0x6ACCFD02079B55F0ULL,
		0xCA3B7C49DC53CFDFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A65BECAE61B8D48ULL,
		0x9D21735117DCE7CEULL,
		0xB8FAA041291A778EULL,
		0x580F482C6F490056ULL,
		0x89AE06861F1A7F1BULL,
		0x9152998E34A08B7BULL,
		0xE694EFB7E7CD1EF2ULL,
		0x5F3A6A0EF50DC47FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD953ABF6C440F52ULL,
		0x14D1DAF77F1A74E4ULL,
		0xE287D50D9D35372BULL,
		0x4BDF468AD20876A5ULL,
		0xC34909020B9A02D5ULL,
		0x0E4D9A06DEAFACA4ULL,
		0x84380D4A1FCE36FEULL,
		0x6B01123AE7460B5FULL
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
		0x796DD05A1E181304ULL,
		0xD03D360744CC7771ULL,
		0xC009DA0FC5A91804ULL,
		0x4775D31F3C9CCB4DULL,
		0x389DC422512130C5ULL,
		0xDA2D4E0332346480ULL,
		0x3A5AE1395AE22EB4ULL,
		0xB59AC53544494B6AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1447456547B6E91EULL,
		0x15CD61BDF6E34DCDULL,
		0x0EB48449AA2E4C60ULL,
		0xA06F0DFF36BA453EULL,
		0xC0C8865E3AA862ECULL,
		0x1CB7489DE97C20E6ULL,
		0xB47232854EF400E1ULL,
		0xA40DFBD40FF7F80CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65268AF4D66129E6ULL,
		0xBA6FD4494DE929A4ULL,
		0xB15555C61B7ACBA4ULL,
		0xA706C52005E2860FULL,
		0x77D53DC41678CDD8ULL,
		0xBD76056548B84399ULL,
		0x85E8AEB40BEE2DD3ULL,
		0x118CC9613451535DULL
	}};
	sign = 0;
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
		0x9CD286CE2E1BB134ULL,
		0x64E6AD55C39329C3ULL,
		0xEE560E0A7016741DULL,
		0x1CD70E4A5D113255ULL,
		0xDB0CD347A0298D3CULL,
		0xADC9A35712808934ULL,
		0x2E0795AD85E6F0D4ULL,
		0xD64363D4D63ADCBFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC843EC5FBDAF6DULL,
		0x4D37A252ECB7B312ULL,
		0xE0A307196C29BEE0ULL,
		0x864FA35B9AF7CC0EULL,
		0xFA0201F8B11ECA6DULL,
		0x1BDEF56F8713753AULL,
		0x1490ED8217C6CE16ULL,
		0x1BF65AE7EC20B326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD0A42E1CE5E01C7ULL,
		0x17AF0B02D6DB76B0ULL,
		0x0DB306F103ECB53DULL,
		0x96876AEEC2196647ULL,
		0xE10AD14EEF0AC2CEULL,
		0x91EAADE78B6D13F9ULL,
		0x1976A82B6E2022BEULL,
		0xBA4D08ECEA1A2999ULL
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
		0x7B5D4FDEDB2D08B3ULL,
		0x7B95D210CC9B60A1ULL,
		0x86FC3B1CF2C881F8ULL,
		0xE32AACBE11A71C12ULL,
		0x8E1E78E722B7FA59ULL,
		0xD841F499BA0145BAULL,
		0xDB6F0793BFD6EEAAULL,
		0x2BE216B98A59C489ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E25D699F8DE459ULL,
		0xCAC4EDE257748B9AULL,
		0xFDCA35F68A7E0C08ULL,
		0xA9807690F85156DDULL,
		0x02AD5714EFA9538DULL,
		0x66F7CB1337F136A3ULL,
		0x21CCD698351E6990ULL,
		0x15FAD8BFA0A133F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x097AF2753B9F245AULL,
		0xB0D0E42E7526D507ULL,
		0x89320526684A75EFULL,
		0x39AA362D1955C534ULL,
		0x8B7121D2330EA6CCULL,
		0x714A298682100F17ULL,
		0xB9A230FB8AB8851AULL,
		0x15E73DF9E9B89096ULL
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
		0x4BCE1C20959424E1ULL,
		0xDC1F7F03B89D801FULL,
		0x0F384BAB1CF0BE75ULL,
		0xD704416B357977BEULL,
		0xAC42B50AF02A936FULL,
		0x4BB75EBF23D1D99CULL,
		0x068A6A1E40BBB0FEULL,
		0x2F6A94FC88E155DFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x229AD7852AAAB304ULL,
		0x3F98C6B19015079DULL,
		0x3DFE9C5E735BA903ULL,
		0xF0A68787DF348152ULL,
		0xBDE617C3459163AFULL,
		0xC9AF970A4DF285C0ULL,
		0x56E46FD854B70FA0ULL,
		0x73AE2A9B6C64D507ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2933449B6AE971DDULL,
		0x9C86B85228887882ULL,
		0xD139AF4CA9951572ULL,
		0xE65DB9E35644F66BULL,
		0xEE5C9D47AA992FBFULL,
		0x8207C7B4D5DF53DBULL,
		0xAFA5FA45EC04A15DULL,
		0xBBBC6A611C7C80D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEA8A2A397B1E86E6ULL,
		0xA761DB0D00F036ABULL,
		0x1A94FAC809DE9850ULL,
		0x1E4A8A970A6B8433ULL,
		0xCAB59F7557427289ULL,
		0x23FD07C3452462DDULL,
		0x5FCBB97661BF6CBFULL,
		0x9145F6317BAB834BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35C112CEB5C89741ULL,
		0x141E18391564B520ULL,
		0x861B5194705B6AA2ULL,
		0x954A7EC79830E608ULL,
		0x8C1A1F0468449EB4ULL,
		0xDBFC953597C547BAULL,
		0xDCE8DE40AD11A79FULL,
		0xFC4F0C5D303BA34FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4C9176AC555EFA5ULL,
		0x9343C2D3EB8B818BULL,
		0x9479A93399832DAEULL,
		0x89000BCF723A9E2AULL,
		0x3E9B8070EEFDD3D4ULL,
		0x4800728DAD5F1B23ULL,
		0x82E2DB35B4ADC51FULL,
		0x94F6E9D44B6FDFFBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5A19E44261016588ULL,
		0x8EE2ABA10C84B5C5ULL,
		0xBF3B5BB200A5A533ULL,
		0x47E5678E4B639B13ULL,
		0xA752E2880658C951ULL,
		0x469E97A67A5BDCECULL,
		0xF6A37A2F2F876F13ULL,
		0x97B6B6153185824CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B015A0A627CA4BDULL,
		0x5FAA7E9C8ED5E418ULL,
		0xDCDFD4252C6722C1ULL,
		0xF29C981847865F46ULL,
		0xCB361C307AFDF5CFULL,
		0xFCB1C5BB91DF4842ULL,
		0x563EFF92969CB3F7ULL,
		0x236F40FAF707C084ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F188A37FE84C0CBULL,
		0x2F382D047DAED1ADULL,
		0xE25B878CD43E8272ULL,
		0x5548CF7603DD3BCCULL,
		0xDC1CC6578B5AD381ULL,
		0x49ECD1EAE87C94A9ULL,
		0xA0647A9C98EABB1BULL,
		0x7447751A3A7DC1C8ULL
	}};
	sign = 0;
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
		0x70C3A0B0C8D75C5AULL,
		0xE78C6DB68B608953ULL,
		0x1EB833D36BF6693CULL,
		0xF457E77AF85CBDAEULL,
		0xBED4C2E96E113FEBULL,
		0x933675F645DCE6AFULL,
		0xA10FB1C3BF9410D0ULL,
		0x3E3DF74924E62CEFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x91F3B6E9A3028D37ULL,
		0x7822D0CFB0D784CEULL,
		0xAEB18FF57EE459BCULL,
		0x9D51921D68A0F9C8ULL,
		0xA641D5EA8AC55581ULL,
		0x42C0CBF7B8E6DA78ULL,
		0x0B467F55C20651D4ULL,
		0xB9E416244775CC19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDECFE9C725D4CF23ULL,
		0x6F699CE6DA890484ULL,
		0x7006A3DDED120F80ULL,
		0x5706555D8FBBC3E5ULL,
		0x1892ECFEE34BEA6AULL,
		0x5075A9FE8CF60C37ULL,
		0x95C9326DFD8DBEFCULL,
		0x8459E124DD7060D6ULL
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
		0x0A0826140A6CC12BULL,
		0xAB682B767B003F86ULL,
		0x55C1BC58298747E6ULL,
		0x9763F585AF11443DULL,
		0x78FCB1A19455949FULL,
		0xC0D4556C668FF8C6ULL,
		0x506350DC2FB07949ULL,
		0x3E3D072D781A4D4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x837B5408650DB038ULL,
		0x86972D9F74423F6CULL,
		0xA3583740F1C10C50ULL,
		0x3652E208D6614764ULL,
		0x866710A7BEF4732AULL,
		0x221214383F136B04ULL,
		0x07C032CC585F3002ULL,
		0xE9EE654D483A8E7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x868CD20BA55F10F3ULL,
		0x24D0FDD706BE0019ULL,
		0xB269851737C63B96ULL,
		0x6111137CD8AFFCD8ULL,
		0xF295A0F9D5612175ULL,
		0x9EC24134277C8DC1ULL,
		0x48A31E0FD7514947ULL,
		0x544EA1E02FDFBED1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA34DD62CAF62E77DULL,
		0x422A69090524C0ECULL,
		0x5308302F8AF4E042ULL,
		0x9D67C0B3EC89FEFFULL,
		0x2D8386D1CAC1B062ULL,
		0x77A35129EB968C86ULL,
		0x973BF7A819ECBCB0ULL,
		0x980D5E52A5801F7FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF289780214FFF357ULL,
		0xCF54820745377DBDULL,
		0xCEF33C9CE6836F31ULL,
		0x2E64C6693B902693ULL,
		0x2A4770BAF5D2C8E9ULL,
		0x8FF909D3DAD2CF07ULL,
		0x90FC3B5491951902ULL,
		0xC6DCF1B2F8C7594FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0C45E2A9A62F426ULL,
		0x72D5E701BFED432EULL,
		0x8414F392A4717110ULL,
		0x6F02FA4AB0F9D86BULL,
		0x033C1616D4EEE779ULL,
		0xE7AA475610C3BD7FULL,
		0x063FBC538857A3ADULL,
		0xD1306C9FACB8C630ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x387EE1B9F0CE73E5ULL,
		0x55272CA7EB214C77ULL,
		0x9FDFC607545E2CADULL,
		0x9D438D6B5FBDCD1BULL,
		0x4B43652F9C7D9882ULL,
		0x12557B76F4B368F7ULL,
		0xEF04C474359A8EEFULL,
		0xCB7C8794864AB069ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA11332C5D8EDC4ULL,
		0x2C0261CD91E5B7A0ULL,
		0x902A9F0F6A3143EAULL,
		0x1BEF2463B055062FULL,
		0xFEDFE4B6AA6FA7ECULL,
		0xF5E4176EB7B9CD99ULL,
		0xBA0F0E288C0E0598ULL,
		0x6F5202A634C9E405ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DDDCE872AF58621ULL,
		0x2924CADA593B94D6ULL,
		0x0FB526F7EA2CE8C3ULL,
		0x81546907AF68C6ECULL,
		0x4C638078F20DF096ULL,
		0x1C7164083CF99B5DULL,
		0x34F5B64BA98C8956ULL,
		0x5C2A84EE5180CC64ULL
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
		0xDE0EE572ACAC659FULL,
		0x217AF8748C711A10ULL,
		0x4525325024ECCED6ULL,
		0x1D1402D1A48BF0AEULL,
		0x4F4E7FEBD1AC6B17ULL,
		0x1CA528FC614C9A3EULL,
		0xFB6A12EE4FEC4F08ULL,
		0xB995AE5C60B7AA2FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A9035832E789144ULL,
		0x950A924EFC8ED29CULL,
		0x847D9D7B239AB2B3ULL,
		0x1634244405E0F28DULL,
		0xB0EC02C3512AAFD3ULL,
		0xFFE83BB4E0E4C33CULL,
		0x494B664459B51974ULL,
		0x72BE8EF66ED16774ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB37EAFEF7E33D45BULL,
		0x8C7066258FE24774ULL,
		0xC0A794D501521C22ULL,
		0x06DFDE8D9EAAFE20ULL,
		0x9E627D288081BB44ULL,
		0x1CBCED478067D701ULL,
		0xB21EACA9F6373593ULL,
		0x46D71F65F1E642BBULL
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
		0xC2C374CD7B799A95ULL,
		0x7DF7EA79838CAF26ULL,
		0xD4B662C4B11A284BULL,
		0xBB8C73BE88FB2AEDULL,
		0xCCE2083380284B50ULL,
		0x1C342E63B0BBD889ULL,
		0xDBED9B3077F2A8EEULL,
		0x97D7426E787FBF58ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x33FE58C7639CE34BULL,
		0x049C6A5974FC8833ULL,
		0x16229B9F12AF32F5ULL,
		0xDABA8CEFD68BF7D5ULL,
		0xB2F453389125A459ULL,
		0xA13202BE8D84A79BULL,
		0x8B32C4FE4CEEA9FAULL,
		0x68015A3E13D4226AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EC51C0617DCB74AULL,
		0x795B80200E9026F3ULL,
		0xBE93C7259E6AF556ULL,
		0xE0D1E6CEB26F3318ULL,
		0x19EDB4FAEF02A6F6ULL,
		0x7B022BA5233730EEULL,
		0x50BAD6322B03FEF3ULL,
		0x2FD5E83064AB9CEEULL
	}};
	sign = 0;
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
		0x0A4D9100D845C893ULL,
		0x2E009F11D1223704ULL,
		0x38E0CF1AAAD173DDULL,
		0x3D698680714EF062ULL,
		0x7A59EDAC5F4EB213ULL,
		0xCC82AC889A94644AULL,
		0x008623C72B926598ULL,
		0x7C41D4D4F202CDA2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB2E8115728C5B8ULL,
		0xC8775D14DC54D156ULL,
		0x91C22ECC0EB35DC1ULL,
		0x995333A52E35426FULL,
		0x37F10DD95FAE2FF4ULL,
		0x7D4D9B4ABCFA4CD5ULL,
		0x148E679E115384CFULL,
		0x6156C35DFEC1C465ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B9AA8EF811D02DBULL,
		0x658941FCF4CD65ADULL,
		0xA71EA04E9C1E161BULL,
		0xA41652DB4319ADF2ULL,
		0x4268DFD2FFA0821EULL,
		0x4F35113DDD9A1775ULL,
		0xEBF7BC291A3EE0C9ULL,
		0x1AEB1176F341093CULL
	}};
	sign = 0;
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
		0x4C006078035ED40DULL,
		0x6C29F7C6A743EF8DULL,
		0x03EDCDE5B7EA7DD8ULL,
		0x8E08F7701DFE4D8DULL,
		0x8AD314A94871DC9FULL,
		0x22B764F158268910ULL,
		0x88F493B86D9E3D20ULL,
		0x109F9E98BFA6BBE7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1DBFECC7C2629CDULL,
		0xB18733C39830F0C4ULL,
		0x31C3B7477A94EEFDULL,
		0x58B4C07A63EBCED3ULL,
		0x818A1552C2C6C086ULL,
		0x11C0F0C581643385ULL,
		0xFF16CF6D4751288CULL,
		0x64D2925CC94C933AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA2461AB8738AA40ULL,
		0xBAA2C4030F12FEC8ULL,
		0xD22A169E3D558EDAULL,
		0x355436F5BA127EB9ULL,
		0x0948FF5685AB1C19ULL,
		0x10F6742BD6C2558BULL,
		0x89DDC44B264D1494ULL,
		0xABCD0C3BF65A28ACULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2E22BFC65218F4DDULL,
		0xD146447D166967B8ULL,
		0x2AFE4EF42CFCD64BULL,
		0x1DE872AFF730644AULL,
		0xA77FC447D11682B1ULL,
		0x3E5D3CC9F148C235ULL,
		0xCEA6353159036F6BULL,
		0x1AC160C2252ACD69ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA9F3B615AB9C336ULL,
		0x7C35200CCC38CE13ULL,
		0x2461FAFA51ED7C2BULL,
		0x7FAD3DDD46557BACULL,
		0x23B211FFCD09D7D9ULL,
		0x600287388B4A78E3ULL,
		0xA92E3BE78A969CD9ULL,
		0x590274E07CA4E6B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53838464F75F31A7ULL,
		0x551124704A3099A4ULL,
		0x069C53F9DB0F5A20ULL,
		0x9E3B34D2B0DAE89EULL,
		0x83CDB248040CAAD7ULL,
		0xDE5AB59165FE4952ULL,
		0x2577F949CE6CD291ULL,
		0xC1BEEBE1A885E6B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6B60717897F40AB3ULL,
		0xA4CA4A057F3C8E82ULL,
		0x31E2E4803F7F71D5ULL,
		0x6B189C21FD67FB95ULL,
		0x0420371B2D391B26ULL,
		0x5F393AC771E32C7BULL,
		0x24C090F4BC56777FULL,
		0xC91C75FBA38FB168ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38843CA5432DB2DEULL,
		0x09156EDE38958D75ULL,
		0x95B0ED7AE431A374ULL,
		0xBCEA69B1A75C771DULL,
		0x9B51E30D9490E242ULL,
		0xCE2C5D416F957711ULL,
		0xBAFDD688AE40644BULL,
		0x5BC97411ED5A69ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32DC34D354C657D5ULL,
		0x9BB4DB2746A7010DULL,
		0x9C31F7055B4DCE61ULL,
		0xAE2E3270560B8477ULL,
		0x68CE540D98A838E3ULL,
		0x910CDD86024DB569ULL,
		0x69C2BA6C0E161333ULL,
		0x6D5301E9B63547BBULL
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
		0x41BEC7BB3E8A427FULL,
		0x5BAFDCF65C2B5278ULL,
		0x548786134C395AFEULL,
		0x00ADE5F60052B3FAULL,
		0x16A2B6982A1F0194ULL,
		0x18EC7ECF673DA7AAULL,
		0xA1283E302D5C1CD1ULL,
		0x7D34667CCCB98FC3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE156DD786C2D8F5ULL,
		0xC6F9800A06ECAC7FULL,
		0xC6BAD879AC5CC278ULL,
		0x8381A970C4FDE1F4ULL,
		0xBB933FC4C65382C5ULL,
		0xE2602D22FDDCB5AAULL,
		0xDEFCBB7D22B15C54ULL,
		0x52E7B49B7245351CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A959E3B7C7698AULL,
		0x94B65CEC553EA5F8ULL,
		0x8DCCAD999FDC9885ULL,
		0x7D2C3C853B54D205ULL,
		0x5B0F76D363CB7ECEULL,
		0x368C51AC6960F1FFULL,
		0xC22B82B30AAAC07CULL,
		0x2A4CB1E15A745AA6ULL
	}};
	sign = 0;
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
		0x49223EA26F46C21EULL,
		0x31A7A47F98E10E3CULL,
		0x668E870ED87037C2ULL,
		0x86B66569DAF35367ULL,
		0xA7937178E0A25002ULL,
		0x4D7F288ABBC75CB8ULL,
		0xE690692777B2037CULL,
		0x336C99B6A83ABA37ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7295C7A1E15E0C4CULL,
		0x0D25E761B1E31EAEULL,
		0x8E96BA0A211C294FULL,
		0x550CDC2993E5E789ULL,
		0x1A8AF8CF5EABA92AULL,
		0x180CDB86B32654F3ULL,
		0x5E40659651648176ULL,
		0xA763CD12AF082F1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD68C77008DE8B5D2ULL,
		0x2481BD1DE6FDEF8DULL,
		0xD7F7CD04B7540E73ULL,
		0x31A98940470D6BDDULL,
		0x8D0878A981F6A6D8ULL,
		0x35724D0408A107C5ULL,
		0x88500391264D8206ULL,
		0x8C08CCA3F9328B19ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6C9AD42E968CD668ULL,
		0x4F589B35BF191361ULL,
		0xC88FD55054588AD3ULL,
		0xF77EAE351D6A2B8BULL,
		0x182FFCEFD26B9165ULL,
		0xF68D02319FD2CA09ULL,
		0xADFD1A57C9BE300DULL,
		0x77F198E15CBE390AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6658B0DF33AFD81AULL,
		0xB759516F3D240181ULL,
		0xCB7C3C876141D976ULL,
		0x68CA1C82B955D244ULL,
		0xE2830CE4F2F621B0ULL,
		0x84350E96A0E0704EULL,
		0x31776402421185D0ULL,
		0x94A5A146714B554AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0642234F62DCFE4EULL,
		0x97FF49C681F511E0ULL,
		0xFD1398C8F316B15CULL,
		0x8EB491B264145946ULL,
		0x35ACF00ADF756FB5ULL,
		0x7257F39AFEF259BAULL,
		0x7C85B65587ACAA3DULL,
		0xE34BF79AEB72E3C0ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD21E4F44ACE1F0AAULL,
		0xA86A9A7C4D0A0879ULL,
		0x7922248F765021B1ULL,
		0xDD7C9251D5C42737ULL,
		0x1BF5486CEC96F131ULL,
		0x53B842EEAB895C1CULL,
		0xA3BA0ED658678AAAULL,
		0xCA79A26A42B5C1E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAB3CA0048D30CCULL,
		0x2B28C2C6565F5F57ULL,
		0x5E6A8B6C649D02DCULL,
		0x3F0AC2A93685B349ULL,
		0x6E24472D1FAFC915ULL,
		0xE8541F0C396787ECULL,
		0x96C0F767120F3AB1ULL,
		0x8EC916D9F266F869ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE47312A4A854BFDEULL,
		0x7D41D7B5F6AAA921ULL,
		0x1AB7992311B31ED5ULL,
		0x9E71CFA89F3E73EEULL,
		0xADD1013FCCE7281CULL,
		0x6B6423E27221D42FULL,
		0x0CF9176F46584FF8ULL,
		0x3BB08B90504EC97CULL
	}};
	sign = 0;
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
		0x47356F62A9A720A7ULL,
		0xD2B1CBC33DD1579BULL,
		0xB9B0E8794ED48F76ULL,
		0xC37A9216DDAF3055ULL,
		0x6C6650F78A3778ECULL,
		0xED917C00A4F53617ULL,
		0x6D4B25F3B4445080ULL,
		0x2345DF4FFBE4AE0EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB46EB06749842AULL,
		0x252CDACA0CDA0FF6ULL,
		0xE63BCCC7008A5CDEULL,
		0x44ED7E7838A43DBDULL,
		0x99BCD38C09DB7FCAULL,
		0x0A33066421FCE633ULL,
		0x95D72E712DBD2D00ULL,
		0xF4DDF8AE8AEFB965ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC78100B2425D9C7DULL,
		0xAD84F0F930F747A4ULL,
		0xD3751BB24E4A3298ULL,
		0x7E8D139EA50AF297ULL,
		0xD2A97D6B805BF922ULL,
		0xE35E759C82F84FE3ULL,
		0xD773F78286872380ULL,
		0x2E67E6A170F4F4A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFEE8770C6CA5D80EULL,
		0x6BCB8595D423D666ULL,
		0x47CC8A4835E54AEFULL,
		0x288BACC398F1A774ULL,
		0x05CB1A424BEEC045ULL,
		0x202E82CC6A8B72BBULL,
		0xFBA458502674B9D6ULL,
		0xCF0C1C9DB270354FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x679E35C71308CA9EULL,
		0x13B7DF50558B5D63ULL,
		0x0F354E2D1B8B0EB5ULL,
		0x79AC6708050D6978ULL,
		0x199C400AE7636AC3ULL,
		0x3C0FFEF7BC0A3979ULL,
		0x470B9D3C801A24F8ULL,
		0x9D83C10810F6702CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x974A4145599D0D70ULL,
		0x5813A6457E987903ULL,
		0x38973C1B1A5A3C3AULL,
		0xAEDF45BB93E43DFCULL,
		0xEC2EDA37648B5581ULL,
		0xE41E83D4AE813941ULL,
		0xB498BB13A65A94DDULL,
		0x31885B95A179C523ULL
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
		0x37F25FCC335B59B2ULL,
		0x9A241B4CEE999726ULL,
		0x572620A0ACA9B181ULL,
		0x5DE0E4813F2C7E84ULL,
		0x2C5FF2FDD0C93AD5ULL,
		0xB2431B538CA26518ULL,
		0xE34A04B5CF9C7241ULL,
		0xFD32D3AD285E19BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE78A440C9C1B81DULL,
		0x81F87BC60F1F3430ULL,
		0x8F9CF08E221B2770ULL,
		0x799FAAED94608E1FULL,
		0xE11B0371977FA644ULL,
		0xDECEC1F4B9780F35ULL,
		0xA50372CE32B391ABULL,
		0x05CE7BFFEE7A5347ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6979BB8B6999A195ULL,
		0x182B9F86DF7A62F5ULL,
		0xC78930128A8E8A11ULL,
		0xE4413993AACBF064ULL,
		0x4B44EF8C39499490ULL,
		0xD374595ED32A55E2ULL,
		0x3E4691E79CE8E095ULL,
		0xF76457AD39E3C677ULL
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
		0x65F36B031C52F872ULL,
		0x9B3D31F1396A7DD2ULL,
		0xAFF43000ECF9CD3AULL,
		0x2981EA355E27E9C3ULL,
		0xE536ECFD7B1D6861ULL,
		0xAD707900BF55B5B1ULL,
		0x1670D976434573D8ULL,
		0x5269674CA0BF57E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A3B79A187893B15ULL,
		0x2E41434FC4067153ULL,
		0x78CEADAA527C0DBBULL,
		0x2079A69D40F05303ULL,
		0xB5DD743FD4F67E06ULL,
		0x4FBFFB9F21704B52ULL,
		0x891CFB43617A2A75ULL,
		0xDFB4C7851D6D3698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BB7F16194C9BD5DULL,
		0x6CFBEEA175640C7FULL,
		0x372582569A7DBF7FULL,
		0x090843981D3796C0ULL,
		0x2F5978BDA626EA5BULL,
		0x5DB07D619DE56A5FULL,
		0x8D53DE32E1CB4963ULL,
		0x72B49FC78352214AULL
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
		0x6AC3574118F4BDE9ULL,
		0x8BC66D6447B02798ULL,
		0x40C0593614FB955DULL,
		0x55C48AF40CBDC3B3ULL,
		0x1159E068D3D66190ULL,
		0x92FB4B700D1866E7ULL,
		0x8060F5B1EF994B47ULL,
		0xE110E830BD0609FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FE277D710A51EAULL,
		0x0F68A1CCD83C1667ULL,
		0xBC9089D77895621FULL,
		0x3D6B5BF1AD9249B7ULL,
		0x5FABFC6E7788B4E3ULL,
		0x761BF8B64F6C6CB8ULL,
		0xA8DFBC5B012A1C24ULL,
		0x7E30DC32D3D409C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68C52FC3A7EA6BFFULL,
		0x7C5DCB976F741131ULL,
		0x842FCF5E9C66333EULL,
		0x18592F025F2B79FBULL,
		0xB1ADE3FA5C4DACADULL,
		0x1CDF52B9BDABFA2EULL,
		0xD7813956EE6F2F23ULL,
		0x62E00BFDE9320034ULL
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
		0xA0E4533AB3A2CA0BULL,
		0xD99EF009C5F669C5ULL,
		0x64BEDE52559EBA2FULL,
		0x8F1815BBE85BED6AULL,
		0x659D7BA50224388DULL,
		0xD201CE57BAE69091ULL,
		0x96FA47A1AE97810FULL,
		0x94897CFE1D2F61C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF54C067364990307ULL,
		0x8B7B4AC661A55757ULL,
		0x9D91F179528E4FDDULL,
		0x2B8FB57B3A0E7384ULL,
		0x29B7F9907729303CULL,
		0x072B6E1DAD0ABCE6ULL,
		0x116E3B4602969821ULL,
		0x675D83B8DB60D4A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB984CC74F09C704ULL,
		0x4E23A5436451126DULL,
		0xC72CECD903106A52ULL,
		0x63886040AE4D79E5ULL,
		0x3BE582148AFB0851ULL,
		0xCAD6603A0DDBD3ABULL,
		0x858C0C5BAC00E8EEULL,
		0x2D2BF94541CE8D20ULL
	}};
	sign = 0;
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
		0xA8E6AB9C879C50FBULL,
		0x569ACC769FF00079ULL,
		0xA5CDEEF178ED56DDULL,
		0xA2B9365A15FA1FFCULL,
		0xCA1F6AA16874C267ULL,
		0x84877B9629E8665EULL,
		0xCCA70F7C9A6AE280ULL,
		0xAA55BBFE60C2B217ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7496B68054E4AFULL,
		0x4A22112DFEF4C69FULL,
		0xDB7E42EAB961B506ULL,
		0x40E7B387ED342E2FULL,
		0x0AF4E0EEB5DC5687ULL,
		0x444EEFFFFD6CB4DCULL,
		0xF8F2CE2DDEB4F86BULL,
		0x03FF96B027308004ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D7214E607476C4CULL,
		0x0C78BB48A0FB39DAULL,
		0xCA4FAC06BF8BA1D7ULL,
		0x61D182D228C5F1CCULL,
		0xBF2A89B2B2986BE0ULL,
		0x40388B962C7BB182ULL,
		0xD3B4414EBBB5EA15ULL,
		0xA656254E39923212ULL
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
		0x635D0550C1986D5AULL,
		0x73D85361F6D3570BULL,
		0x41CCCCE24F71D271ULL,
		0x85D1963C09883A8AULL,
		0xF8116E13BAD9E8F5ULL,
		0x7F85F3CA80CCA1A5ULL,
		0xCD1E5E94AA14E0BCULL,
		0xF06E2E983DB12A13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A6FBFFEADBAF770ULL,
		0xC0F10432D1354A9BULL,
		0x5783AE8E87115BAFULL,
		0xAFBE82FA1D575FA1ULL,
		0x320889AE3BEBA462ULL,
		0x406F20024C111F2EULL,
		0xC4F634F74CD01664ULL,
		0x9BE536EB543B998EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48ED455213DD75EAULL,
		0xB2E74F2F259E0C70ULL,
		0xEA491E53C86076C1ULL,
		0xD6131341EC30DAE8ULL,
		0xC608E4657EEE4492ULL,
		0x3F16D3C834BB8277ULL,
		0x0828299D5D44CA58ULL,
		0x5488F7ACE9759085ULL
	}};
	sign = 0;
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
		0xE8D22B92522C4096ULL,
		0x9F504BFB3623E478ULL,
		0xCCB4F9B82E138CA2ULL,
		0x4806BF50BE687F4CULL,
		0xCE4E82C2E5BAE249ULL,
		0x63772D1089F3ED82ULL,
		0x48AA41454C70AA10ULL,
		0x586321714469DA9FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x089DAD6BA1CF85D0ULL,
		0x6E4670D9D46CFF32ULL,
		0x365295EF5BF5B625ULL,
		0x3AB29C753B77F9F4ULL,
		0x16A093BEA7F6576BULL,
		0x4A26401640F48E6FULL,
		0x6C7CCC103A9EAF19ULL,
		0xC927A12729C9D1E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0347E26B05CBAC6ULL,
		0x3109DB2161B6E546ULL,
		0x966263C8D21DD67DULL,
		0x0D5422DB82F08558ULL,
		0xB7ADEF043DC48ADEULL,
		0x1950ECFA48FF5F13ULL,
		0xDC2D753511D1FAF7ULL,
		0x8F3B804A1AA008BBULL
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
		0x8E971F51CDB09496ULL,
		0xC18F457D71A60B6EULL,
		0xAFF51EE0165C6B65ULL,
		0x39FEFAE69B67AE50ULL,
		0x8C0A4AFFF67C507FULL,
		0xCA2A2BE003DA168DULL,
		0xC3363AEF2DB06A13ULL,
		0xDBE57D05BA2C4971ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x946DEB3481D96929ULL,
		0x193163DED8E87F07ULL,
		0x39D1B4457C69A841ULL,
		0xC94DBA5242D0F98FULL,
		0x3CFFDC4E27A5E09CULL,
		0xECFF8A1DBB758DB4ULL,
		0x46C3E95A872901E7ULL,
		0x114E35F038A7C17BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA29341D4BD72B6DULL,
		0xA85DE19E98BD8C66ULL,
		0x76236A9A99F2C324ULL,
		0x70B140945896B4C1ULL,
		0x4F0A6EB1CED66FE2ULL,
		0xDD2AA1C2486488D9ULL,
		0x7C725194A687682BULL,
		0xCA974715818487F6ULL
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
		0x857DA7D059183B9BULL,
		0xCA28A586E6E259B2ULL,
		0x33108EBF35EEB836ULL,
		0x847D1BDE64074E9BULL,
		0x3EE138798A23C740ULL,
		0xF4D1A85E33A32A53ULL,
		0x2188C92FB1D19306ULL,
		0x2589988E2404F378ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5ED855C7A945D31ULL,
		0xE202D47879BC0372ULL,
		0x499DC29C38D80AADULL,
		0xD8A99B6AC8802111ULL,
		0xD27C84331EFA1C2BULL,
		0xED7CBB2473B72A10ULL,
		0x2EB6E9C0FF69E0B7ULL,
		0x3FBF2912003FCA3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F902273DE83DE6AULL,
		0xE825D10E6D26563FULL,
		0xE972CC22FD16AD88ULL,
		0xABD380739B872D89ULL,
		0x6C64B4466B29AB14ULL,
		0x0754ED39BFEC0042ULL,
		0xF2D1DF6EB267B24FULL,
		0xE5CA6F7C23C5293CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEDADD467AEE801EBULL,
		0x536E21A0D03A7910ULL,
		0x0C873CE7642D3E31ULL,
		0x1F4D53B8E7211B3DULL,
		0x2CB46005A3811F64ULL,
		0x752B050FD0A38254ULL,
		0x7400BB67883CB9A8ULL,
		0xE36E42F237A6CFB8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB81E581ADC9DBACEULL,
		0x76F751A8A21CB6FBULL,
		0x10A2AB51C569EB00ULL,
		0xF4AA63F0871DE6F5ULL,
		0xAAA170CC9257E232ULL,
		0xEC412DE66FB86891ULL,
		0x0E9D4CD5928E721DULL,
		0xF6CA55654BA7B672ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x358F7C4CD24A471DULL,
		0xDC76CFF82E1DC215ULL,
		0xFBE491959EC35330ULL,
		0x2AA2EFC860033447ULL,
		0x8212EF3911293D31ULL,
		0x88E9D72960EB19C2ULL,
		0x65636E91F5AE478AULL,
		0xECA3ED8CEBFF1946ULL
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
		0x7C9661F4398E67D8ULL,
		0xE8784A8BCD16F276ULL,
		0x7C8E9BEA562D939FULL,
		0xF59EABE0010CC5DCULL,
		0xFD4954526957747AULL,
		0x33D625352582D951ULL,
		0xB0913AA621675685ULL,
		0x71F4E83A4510C617ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0123B0AD83EE2758ULL,
		0x8323CF31E096A69FULL,
		0x4F2B904455CD8D5CULL,
		0xE3EC84043EACE403ULL,
		0x73A34A23C56D5908ULL,
		0x78A0C47493D4ED0AULL,
		0xB038F02D78532122ULL,
		0x55A372C7A434530CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B72B146B5A04080ULL,
		0x65547B59EC804BD7ULL,
		0x2D630BA600600643ULL,
		0x11B227DBC25FE1D9ULL,
		0x89A60A2EA3EA1B72ULL,
		0xBB3560C091ADEC47ULL,
		0x00584A78A9143562ULL,
		0x1C517572A0DC730BULL
	}};
	sign = 0;
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
		0xE6E755EC1447FDD1ULL,
		0x6EE206880F647EE7ULL,
		0x2DADEFBA3567E9EEULL,
		0xD26B29A79D32753EULL,
		0xF9755831C984A37BULL,
		0xBBD23E224AD3AE13ULL,
		0x7D7E5B8F0383DDDBULL,
		0xDC9D6299084C4510ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5939D0B1D85F41E5ULL,
		0xBE15D88570F8690AULL,
		0xA60F9DE2C4CBB3BCULL,
		0xFCE81757CC748A5BULL,
		0x2C6C8DC38BD01144ULL,
		0x2597A6C0D71B8F1EULL,
		0x4186047E01841037ULL,
		0x6A738EDFF3E5B8E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DAD853A3BE8BBECULL,
		0xB0CC2E029E6C15DDULL,
		0x879E51D7709C3631ULL,
		0xD583124FD0BDEAE2ULL,
		0xCD08CA6E3DB49236ULL,
		0x963A976173B81EF5ULL,
		0x3BF8571101FFCDA4ULL,
		0x7229D3B914668C2BULL
	}};
	sign = 0;
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
		0x3B039CC6EB463DA3ULL,
		0xA970D748D7FF5C70ULL,
		0xE6601F3205259DBFULL,
		0xA4A11E080343D3DCULL,
		0xF73CD13635CBB9AAULL,
		0x46AA409E6DE17AE5ULL,
		0x97D0BC2F24A0EDA0ULL,
		0x54AD9935273329FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD489FCF2B913CB0EULL,
		0x7BDF7D6CCCC67DE9ULL,
		0x330FA17368873E71ULL,
		0x9A85CCFE293C64F2ULL,
		0xBF7ECFEA2750583AULL,
		0xA812B429AE30745DULL,
		0x968B70C471E471FEULL,
		0xDAEC12E8BC53849AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66799FD432327295ULL,
		0x2D9159DC0B38DE86ULL,
		0xB3507DBE9C9E5F4EULL,
		0x0A1B5109DA076EEAULL,
		0x37BE014C0E7B6170ULL,
		0x9E978C74BFB10688ULL,
		0x01454B6AB2BC7BA1ULL,
		0x79C1864C6ADFA564ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x235511FDBD1AC787ULL,
		0xD48D654BAA865D77ULL,
		0x827803C2CFEA969EULL,
		0x5A2AAB9F2C4291F3ULL,
		0x0D8DD8CF049FA857ULL,
		0xC8EC9A312872A0A8ULL,
		0x66B2C3AF65C0ACB3ULL,
		0xC11D2FAC60745128ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14A830963D679795ULL,
		0xA8F55F66A01BDF21ULL,
		0xB19CC639853A0B1BULL,
		0x2A244B184A05DE67ULL,
		0xCED222EF57A7980AULL,
		0xD02920DF587450F7ULL,
		0x8E34AFA0CB70B377ULL,
		0x24C370250AB200EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EACE1677FB32FF2ULL,
		0x2B9805E50A6A7E56ULL,
		0xD0DB3D894AB08B83ULL,
		0x30066086E23CB38BULL,
		0x3EBBB5DFACF8104DULL,
		0xF8C37951CFFE4FB0ULL,
		0xD87E140E9A4FF93BULL,
		0x9C59BF8755C2503CULL
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
		0x363324B6ADB79282ULL,
		0xC46A4EDEC6461725ULL,
		0xB11716AEF68AF534ULL,
		0x01C1C36A3751D802ULL,
		0x2C8ED384D6BCC022ULL,
		0x16972B702BB29828ULL,
		0x17DBC60B17B1CFB9ULL,
		0xA5C8752A4226043BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B5FE82FB5550982ULL,
		0x06943D95334643EFULL,
		0xB8FA54674A364FFDULL,
		0x687D4498AD5C88EEULL,
		0x5DBB7731EEB708D2ULL,
		0xCDCAF14FCD5D73FCULL,
		0x9043366CCDC7C881ULL,
		0xA95234B44B78900AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAD33C86F8628900ULL,
		0xBDD6114992FFD335ULL,
		0xF81CC247AC54A537ULL,
		0x99447ED189F54F13ULL,
		0xCED35C52E805B74FULL,
		0x48CC3A205E55242BULL,
		0x87988F9E49EA0737ULL,
		0xFC764075F6AD7430ULL
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
		0x24A36A91B32DADEAULL,
		0x679664BCC9E4F9CEULL,
		0xB8BB26D589627489ULL,
		0x83216AC5274377A0ULL,
		0xDCDD857968FEDE32ULL,
		0xD2E8F22516FFC5B5ULL,
		0x478DD57FE50FE348ULL,
		0x1ACF90E472A04B27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A74BE3EDBE00578ULL,
		0x3DB3525A8B6FEF86ULL,
		0x76A7029C48D1F423ULL,
		0x88B77CC0F76DE056ULL,
		0xF3F6047203011449ULL,
		0xF3ED3EDF9D99716FULL,
		0x91732CF34015A574ULL,
		0x6B2A339F65B13ED9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A2EAC52D74DA872ULL,
		0x29E312623E750A48ULL,
		0x4214243940908066ULL,
		0xFA69EE042FD5974AULL,
		0xE8E7810765FDC9E8ULL,
		0xDEFBB34579665445ULL,
		0xB61AA88CA4FA3DD3ULL,
		0xAFA55D450CEF0C4DULL
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
		0x879FDCB7153F168FULL,
		0xC6AE67A07C258BE8ULL,
		0xBA296C959115D865ULL,
		0x945AB8A325B7134EULL,
		0x78060D4F3B47BA35ULL,
		0x2EA4A3871CA65506ULL,
		0x0C9855D689571DDBULL,
		0x519DD3C08F9F151CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F59E71C3622ED7ULL,
		0xC4395EFC5F25F91AULL,
		0xED2868DC2DFBA489ULL,
		0x5B0A79DB98BFAC74ULL,
		0xE923AECC4B661EA8ULL,
		0xF8A23A16896E5781ULL,
		0xB0DAE7ED34F04844ULL,
		0x22A99F23C568D2D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91AA3E4551DCE7B8ULL,
		0x027508A41CFF92CDULL,
		0xCD0103B9631A33DCULL,
		0x39503EC78CF766D9ULL,
		0x8EE25E82EFE19B8DULL,
		0x360269709337FD84ULL,
		0x5BBD6DE95466D596ULL,
		0x2EF4349CCA364245ULL
	}};
	sign = 0;
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
		0x84BDC59DB9274717ULL,
		0x88314FC34BF2CA64ULL,
		0x834E0694A0E3F05BULL,
		0x123558664B1F7C27ULL,
		0x3D3043498FBFA074ULL,
		0x12092C7D7FA0FFA3ULL,
		0xC53DBF0650EBD6D8ULL,
		0x6C47F12A43EADB4FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x83834204A0E75D65ULL,
		0xAEC672B3E8CF4803ULL,
		0x28845A84F1491FB4ULL,
		0x0C540E4AA106A6DCULL,
		0x99940AD8BC6425A9ULL,
		0x27711B07EB357C80ULL,
		0x5BFC5FF24EA4D272ULL,
		0xD9766EDEDD4F6340ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x013A8399183FE9B2ULL,
		0xD96ADD0F63238261ULL,
		0x5AC9AC0FAF9AD0A6ULL,
		0x05E14A1BAA18D54BULL,
		0xA39C3870D35B7ACBULL,
		0xEA981175946B8322ULL,
		0x69415F1402470465ULL,
		0x92D1824B669B780FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x53748DF5417854DAULL,
		0x98A5CD97222D46A4ULL,
		0x1094D098DECD044BULL,
		0x33B2EECC50491B0AULL,
		0x8AFF16EB862BE76AULL,
		0x6594F7C1B25D5E97ULL,
		0x5EECC63A831D8229ULL,
		0x382F8E2ACB3751DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x51ACFB5FEFF2A3BEULL,
		0xF5C08CC9281C3C83ULL,
		0xFB370E14DF99F004ULL,
		0x31F1CA2DFAD00284ULL,
		0xA1BF0165516C61A2ULL,
		0x4E9A48F30CA3AAAFULL,
		0x2745EB20198ABFA6ULL,
		0x6AA8AD9B19C13EB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01C792955185B11CULL,
		0xA2E540CDFA110A21ULL,
		0x155DC283FF331446ULL,
		0x01C1249E55791885ULL,
		0xE940158634BF85C8ULL,
		0x16FAAECEA5B9B3E7ULL,
		0x37A6DB1A6992C283ULL,
		0xCD86E08FB176132BULL
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
		0x0EAA03F6445CCE51ULL,
		0x6B5CAC4E3AA8EF3EULL,
		0x8A37D3DF52BB5858ULL,
		0x1750546FA7E4909CULL,
		0xAE051A394838FB9BULL,
		0x14A45B4761BC7FFCULL,
		0x681E65D2CE66249FULL,
		0xE903F8335FD3ADF4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F6DD5A970227582ULL,
		0x039AF570150313B5ULL,
		0x1D8ED595E11D462AULL,
		0x0D80B9839CA4B447ULL,
		0x3FF14E592C7DF793ULL,
		0xDF60FA2CDBD3C2C3ULL,
		0xE228F386239F1A68ULL,
		0x35A049D06B8E3FB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF3C2E4CD43A58CFULL,
		0x67C1B6DE25A5DB88ULL,
		0x6CA8FE49719E122EULL,
		0x09CF9AEC0B3FDC55ULL,
		0x6E13CBE01BBB0408ULL,
		0x3543611A85E8BD39ULL,
		0x85F5724CAAC70A36ULL,
		0xB363AE62F4456E3CULL
	}};
	sign = 0;
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
		0x8E314E395AE27DB1ULL,
		0x9FE0254250A1A4EEULL,
		0xA75ABF0A6024C59CULL,
		0x1A06F3A10E0D7C67ULL,
		0x05A6F3FF9B22F5CFULL,
		0x7A3D18BC74A4EADFULL,
		0x0FF1896439E71992ULL,
		0xCA1AA1762D376A48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x856931AB53864A1DULL,
		0xF9BD89E868C6C3C5ULL,
		0xA66DE4502C756E1FULL,
		0xCD425E9FD08F515BULL,
		0x498C0AB75E1C2E48ULL,
		0x9A057AA60F16AB33ULL,
		0xAD88A36E63378A2AULL,
		0x2B44CE88CB70EA62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08C81C8E075C3394ULL,
		0xA6229B59E7DAE129ULL,
		0x00ECDABA33AF577CULL,
		0x4CC495013D7E2B0CULL,
		0xBC1AE9483D06C786ULL,
		0xE0379E16658E3FABULL,
		0x6268E5F5D6AF8F67ULL,
		0x9ED5D2ED61C67FE5ULL
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
		0xB3651A37567F9EACULL,
		0xB682D1DD6994D2DFULL,
		0x437B7A351A47E76EULL,
		0x83A874681F1CAF82ULL,
		0x382F6E9382EBE6F5ULL,
		0x39D9CA2ECE37CDE6ULL,
		0xFEF3B01026A429C5ULL,
		0x454326A6AD7565BCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3FB2A76DF0C0E86ULL,
		0x25D0DD52D29C0A75ULL,
		0x4F824CD9EE64AC62ULL,
		0x0A540C170A7D302DULL,
		0x47E8C8D305B451E2ULL,
		0x574396BFAD7C66F6ULL,
		0x8B3A7DF8560C8201ULL,
		0x95E8905E677FAED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF69EFC077739026ULL,
		0x90B1F48A96F8C869ULL,
		0xF3F92D5B2BE33B0CULL,
		0x79546851149F7F54ULL,
		0xF046A5C07D379513ULL,
		0xE296336F20BB66EFULL,
		0x73B93217D097A7C3ULL,
		0xAF5A964845F5B6E4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x236E823B51EB804EULL,
		0xEEAEDD5E081C9D25ULL,
		0x5DD1F96AEAAF16ABULL,
		0x599C7476D44C3F96ULL,
		0x9C20CB403CE59300ULL,
		0x1C3701FE4690E531ULL,
		0x451383D6A8849F10ULL,
		0x7A06AF3B36221201ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D628DC283226C5CULL,
		0x6C12FA69EAF1D65CULL,
		0xEC6095B228197912ULL,
		0xB957000905BDAF6EULL,
		0x37B48774B99665F8ULL,
		0x4B90FBB85A777592ULL,
		0xD9F6D3F171463011ULL,
		0x71430C711786DE2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE60BF478CEC913F2ULL,
		0x829BE2F41D2AC6C8ULL,
		0x717163B8C2959D99ULL,
		0xA045746DCE8E9027ULL,
		0x646C43CB834F2D07ULL,
		0xD0A60645EC196F9FULL,
		0x6B1CAFE5373E6EFEULL,
		0x08C3A2CA1E9B33D5ULL
	}};
	sign = 0;
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
		0x9AAB3E4991D7794AULL,
		0x7B30A87A260990DBULL,
		0x1DE1CCDA66E5FFEEULL,
		0x59F6012628F7E7FAULL,
		0x3B34E375886FC4BAULL,
		0xEC97E28348A7B8FEULL,
		0x4EB5F9F735B9B1A7ULL,
		0xB48C6F23F8E6B7A9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92D1958481FDAA54ULL,
		0x99E870CF555ECA18ULL,
		0x2EB51DF614532559ULL,
		0x16B7DAE74C5ACE9EULL,
		0x8150951DE0631B54ULL,
		0x7D38A0FBE5212383ULL,
		0x5C6BCB5A0FEF3C15ULL,
		0xA496228055F0A137ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07D9A8C50FD9CEF6ULL,
		0xE14837AAD0AAC6C3ULL,
		0xEF2CAEE45292DA94ULL,
		0x433E263EDC9D195BULL,
		0xB9E44E57A80CA966ULL,
		0x6F5F41876386957AULL,
		0xF24A2E9D25CA7592ULL,
		0x0FF64CA3A2F61671ULL
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
		0x1668D2076110A36AULL,
		0x1DF0F60DF119E35DULL,
		0xD028BEA3E087CBC9ULL,
		0x74BC51FDC49FE0B7ULL,
		0x93E24E1B455872F8ULL,
		0x48A687D15D06D895ULL,
		0xD022E0A7CDED2336ULL,
		0xFAA74A9C0B07D0D9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE47C4A3554F05476ULL,
		0x4ED91A35A4DCA107ULL,
		0xBA3178C8717314B0ULL,
		0xA24DD894E5993E89ULL,
		0x443DBAD97A5E16B0ULL,
		0x3C484CFE6CFCC8B5ULL,
		0x2E2777F2657A8283ULL,
		0x701163192031C61FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31EC87D20C204EF4ULL,
		0xCF17DBD84C3D4255ULL,
		0x15F745DB6F14B718ULL,
		0xD26E7968DF06A22EULL,
		0x4FA49341CAFA5C47ULL,
		0x0C5E3AD2F00A0FE0ULL,
		0xA1FB68B56872A0B3ULL,
		0x8A95E782EAD60ABAULL
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
		0xF5BAE3965AEF2F0DULL,
		0xD2B2F5DD1CD01179ULL,
		0xC8BE383366C1D1E6ULL,
		0x75310AB127C5D385ULL,
		0x0E945761A8B9F505ULL,
		0xE4D07C358D117D28ULL,
		0xCBD2A6B48074662CULL,
		0x8699594F43BDA78BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A0D7830E74B34FULL,
		0xDA1224D543535A6BULL,
		0x6945313E0F7E59A8ULL,
		0x9AA7E518F775AE8CULL,
		0xFC794C18ABA436D8ULL,
		0xC9775A229C74FFA3ULL,
		0x9D842A6404BCAD1BULL,
		0x21AF2FBE5733AD6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041A0C134C7A7BBEULL,
		0xF8A0D107D97CB70EULL,
		0x5F7906F55743783DULL,
		0xDA892598305024F9ULL,
		0x121B0B48FD15BE2CULL,
		0x1B592212F09C7D84ULL,
		0x2E4E7C507BB7B911ULL,
		0x64EA2990EC89FA1EULL
	}};
	sign = 0;
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
		0x8C4A83CCBABF9FB1ULL,
		0xABBA11C47C11CD91ULL,
		0x8FB351ACF1EA9992ULL,
		0xA330ABB86F81F055ULL,
		0x1BF0E430450AAE9BULL,
		0x513515CEF2B64199ULL,
		0x0246CE8AB85A15E9ULL,
		0xA77DC4ED18DEC86EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A460B9B7DE2C3D7ULL,
		0xD3F583C7371130B8ULL,
		0x5932C4BDA482009CULL,
		0x1496E0F1FB6E6008ULL,
		0x409DB4B483A34EE9ULL,
		0x717F78E5BCC814ADULL,
		0x1E3E698CE63FA0F2ULL,
		0x71AB0AC3752ADD09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x520478313CDCDBDAULL,
		0xD7C48DFD45009CD9ULL,
		0x36808CEF4D6898F5ULL,
		0x8E99CAC67413904DULL,
		0xDB532F7BC1675FB2ULL,
		0xDFB59CE935EE2CEBULL,
		0xE40864FDD21A74F6ULL,
		0x35D2BA29A3B3EB64ULL
	}};
	sign = 0;
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
		0x1F6ABE1953EAC468ULL,
		0x97AAE18E2DC34CC8ULL,
		0x6738641C3778447AULL,
		0x47D9459913EB3749ULL,
		0xA187FE7114810604ULL,
		0x6F30A4D4290EBA3BULL,
		0xE89EABB18C9AC00CULL,
		0xDBD3B7F867ED9A90ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD01AF89B591B032ULL,
		0xB9C85B684A278BFFULL,
		0xC0BEF3DFAB0A9287ULL,
		0x767B2F31FBA9044DULL,
		0x14B2FFC961AACB48ULL,
		0xB19A9690F4DD1784ULL,
		0x0E32EA061CFEDB44ULL,
		0xC7C73295C9470AC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72690E8F9E591436ULL,
		0xDDE28625E39BC0C8ULL,
		0xA679703C8C6DB1F2ULL,
		0xD15E1667184232FBULL,
		0x8CD4FEA7B2D63ABBULL,
		0xBD960E433431A2B7ULL,
		0xDA6BC1AB6F9BE4C7ULL,
		0x140C85629EA68FC7ULL
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
		0xD4B9865E3F92A572ULL,
		0x35E0558F9ECBA997ULL,
		0x95575D7EDBFFF4ACULL,
		0xB29585D0876B8E4EULL,
		0x74623363205413A8ULL,
		0xA9E3AF88EF6A13A5ULL,
		0x2200CBB8074AFC75ULL,
		0x1A51D2D974A3574EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B28DA6D4981FE03ULL,
		0x0356E68D9C207683ULL,
		0xB1299EA21743F93BULL,
		0xFF0287B0203E4EDCULL,
		0xA581DDECD855C1F1ULL,
		0x4D7692883D5ABCB6ULL,
		0x5794D86DC10E56D0ULL,
		0x7BD7C28AD3E1778AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4990ABF0F610A76FULL,
		0x32896F0202AB3314ULL,
		0xE42DBEDCC4BBFB71ULL,
		0xB392FE20672D3F71ULL,
		0xCEE0557647FE51B6ULL,
		0x5C6D1D00B20F56EEULL,
		0xCA6BF34A463CA5A5ULL,
		0x9E7A104EA0C1DFC3ULL
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
		0x01C93002F32FA8FAULL,
		0x7D2172D15283F787ULL,
		0x7CE62F020F81A2FCULL,
		0x0AC2116ADA15CB9DULL,
		0x2C4290A3AF0DA4A6ULL,
		0xCFD07C5B65C1CD9AULL,
		0xBD870D791BAFC4D3ULL,
		0xA122302DF6AD1AF3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD2D16D85714DAFULL,
		0x6D1991D86E98425FULL,
		0x8E2AE86559A5C6D7ULL,
		0x6DEE23F1C3149B2BULL,
		0x7F4F20C3FDD6645FULL,
		0x8A1D263D7E918051ULL,
		0x7A04B7AE431BE4D7ULL,
		0x2BC6B8E97003BEBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1F65E956DBE5B4BULL,
		0x1007E0F8E3EBB527ULL,
		0xEEBB469CB5DBDC25ULL,
		0x9CD3ED7917013071ULL,
		0xACF36FDFB1374046ULL,
		0x45B3561DE7304D48ULL,
		0x438255CAD893DFFCULL,
		0x755B774486A95C34ULL
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
		0x3413B5138DEE07C5ULL,
		0xD2D559142ADB6462ULL,
		0xD455B198F07851F3ULL,
		0xBA8A9D558F89D6EBULL,
		0x1842D2E8ABC85AF5ULL,
		0x4B892658470EABFFULL,
		0x04BFB6B8B0428779ULL,
		0x578FB0032DB728DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x500BEE8DC1DE8C0EULL,
		0xFC0C9FFA30730C84ULL,
		0xC513DBB2451B465EULL,
		0x10F5287D3ADD6E95ULL,
		0x64F81325AE894286ULL,
		0x134CA5C2C7A3D349ULL,
		0x464F4819E2439BB1ULL,
		0x1224FC1E89848FC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE407C685CC0F7BB7ULL,
		0xD6C8B919FA6857DDULL,
		0x0F41D5E6AB5D0B94ULL,
		0xA99574D854AC6856ULL,
		0xB34ABFC2FD3F186FULL,
		0x383C80957F6AD8B5ULL,
		0xBE706E9ECDFEEBC8ULL,
		0x456AB3E4A4329919ULL
	}};
	sign = 0;
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
		0xBB0E385B3FA22D17ULL,
		0x40A44BC080A4900CULL,
		0x2140DA687C40FFB4ULL,
		0x4F5B95E649081B0CULL,
		0xFD8C079F0E0AFE47ULL,
		0x88D75C30266B0E93ULL,
		0x0C4EDE80C96BA23FULL,
		0xBB1DB4FAA76F46C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0301DF0B4A1EFEULL,
		0x4835A0BC87206E77ULL,
		0xBC53DAEB9C3C6FF0ULL,
		0x680AFC82F081E633ULL,
		0xD2CB139A3C2EE63AULL,
		0x1F9188CE718589FCULL,
		0x37A142FBE7938A1FULL,
		0x080B3BFAEDE66E53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200B367C34580E19ULL,
		0xF86EAB03F9842195ULL,
		0x64ECFF7CE0048FC3ULL,
		0xE7509963588634D8ULL,
		0x2AC0F404D1DC180CULL,
		0x6945D361B4E58497ULL,
		0xD4AD9B84E1D81820ULL,
		0xB31278FFB988D86EULL
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
		0xE76B31EC6D65F7CAULL,
		0x2D20B4D68F9D7CBEULL,
		0xB9E6D76316AB618AULL,
		0x48088B23C89733BBULL,
		0xE77C4D4A58AC416DULL,
		0xA8308224E58B48C9ULL,
		0x017C3F3D7B00B937ULL,
		0xA3F4DFA598FA45D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89840E276B724A08ULL,
		0xE3BF56C6F2CFF46EULL,
		0x9CB838203B0E74CFULL,
		0x150802C4DCB81EB5ULL,
		0x144C3B5188808D99ULL,
		0x859BE23FE5BBAE5AULL,
		0xF2D6789898CA18F5ULL,
		0xAF0BAFD9AC044102ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DE723C501F3ADC2ULL,
		0x49615E0F9CCD8850ULL,
		0x1D2E9F42DB9CECBAULL,
		0x3300885EEBDF1506ULL,
		0xD33011F8D02BB3D4ULL,
		0x22949FE4FFCF9A6FULL,
		0x0EA5C6A4E236A042ULL,
		0xF4E92FCBECF604D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0740FE6B5072BB8EULL,
		0xBDB5BE199191CDDCULL,
		0x975028B2BF643AE1ULL,
		0xDE64D9091D9C58C5ULL,
		0xD9D3C634D5063B6CULL,
		0x7D6D7DDE9101381EULL,
		0x85A1B9F69BD9AB6CULL,
		0x65DD72F6944C2813ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3640FD93CF0EF08CULL,
		0xC368ADBECA744404ULL,
		0x94FC872849B0479AULL,
		0x63CD0AC90EF6C4C3ULL,
		0x8AB1D154B7314FE7ULL,
		0xD35C8ABCB3E59E4EULL,
		0xB4B8E5214E7ADEFAULL,
		0x416FDBC4AD8575F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD10000D78163CB02ULL,
		0xFA4D105AC71D89D7ULL,
		0x0253A18A75B3F346ULL,
		0x7A97CE400EA59402ULL,
		0x4F21F4E01DD4EB85ULL,
		0xAA10F321DD1B99D0ULL,
		0xD0E8D4D54D5ECC71ULL,
		0x246D9731E6C6B21BULL
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
		0x495EB80B7F1DB4B8ULL,
		0x32F87BDD8278F166ULL,
		0xABF6A5903F0E6A25ULL,
		0x58696E88B3E7461EULL,
		0x9BAA6885A2B705D9ULL,
		0x7A7B490B26991197ULL,
		0x44A7D53B48B4854AULL,
		0x8AA3BC1BCCB46E0CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB34087A0577379D6ULL,
		0x570362F75996DD85ULL,
		0xDA100CCA9525EC74ULL,
		0x59DCED74EC53CA48ULL,
		0x4CB11C47C02EEE15ULL,
		0xC2CF2E5434C58C58ULL,
		0x2AF44A0949E6FA9BULL,
		0x9F3E8274E7087DDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x961E306B27AA3AE2ULL,
		0xDBF518E628E213E0ULL,
		0xD1E698C5A9E87DB0ULL,
		0xFE8C8113C7937BD5ULL,
		0x4EF94C3DE28817C3ULL,
		0xB7AC1AB6F1D3853FULL,
		0x19B38B31FECD8AAEULL,
		0xEB6539A6E5ABF02DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5FC869CDCB4A8FC9ULL,
		0x559F693A94561023ULL,
		0x546E34B8CD7562F7ULL,
		0xCD577B0206973A2DULL,
		0xA630D81527476C7DULL,
		0x59F57E7124FDFD11ULL,
		0xE597CF807A38BD62ULL,
		0x4EFAC2B039E1EA62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B9BCB82DE6B7A0ULL,
		0x23A6C7D317510F15ULL,
		0x4A29E6D07DE6B658ULL,
		0x0B711D45A8F4CFFFULL,
		0x843BB243A3E3C237ULL,
		0x8D9AFF8C59AC26C5ULL,
		0xAE791FC3D57603E0ULL,
		0x08F39F2144E13AFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC0EAD159D63D829ULL,
		0x31F8A1677D05010DULL,
		0x0A444DE84F8EAC9FULL,
		0xC1E65DBC5DA26A2EULL,
		0x21F525D18363AA46ULL,
		0xCC5A7EE4CB51D64CULL,
		0x371EAFBCA4C2B981ULL,
		0x4607238EF500AF64ULL
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
		0x00BA75BC2BD082B3ULL,
		0x421D0E8DFEA528AFULL,
		0x972A37002FA7A29BULL,
		0x0C3B4D23EC22055DULL,
		0xAC4E98666079162EULL,
		0xA2FE0C2FF3562090ULL,
		0xB874EA3188F188A2ULL,
		0x8E7CD5C1AF84EFCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D45B50CCA0A1B0AULL,
		0xE67554D63FDE25FCULL,
		0xCBB5E4640DACE711ULL,
		0x6EBE4E1CD3EEDD99ULL,
		0x97331B8EC5B9FDC3ULL,
		0x0D6B8181881A467AULL,
		0xE8F38D53D2EBFCCEULL,
		0x096ACCAC8B4F2AFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC374C0AF61C667A9ULL,
		0x5BA7B9B7BEC702B2ULL,
		0xCB74529C21FABB89ULL,
		0x9D7CFF07183327C3ULL,
		0x151B7CD79ABF186AULL,
		0x95928AAE6B3BDA16ULL,
		0xCF815CDDB6058BD4ULL,
		0x851209152435C4CCULL
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
		0x776FDF3543FBE4EAULL,
		0x553BD9831E77D984ULL,
		0x1748FC41E560A05DULL,
		0x50E385C4513FDFC8ULL,
		0xDC8585073F2F4511ULL,
		0x62C65C9BDEC1CCA3ULL,
		0x2A6D3E6EE8287E7DULL,
		0xC6D7999EF1C82449ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E2871E9C2F9408ULL,
		0x0E8C5A26F29A0119ULL,
		0xAC59E8021E549A04ULL,
		0x30115525FF65E630ULL,
		0x107408766D76ABC8ULL,
		0x45C945E86C34691FULL,
		0x636BFA7B4001E7D2ULL,
		0xCA50CD1470748015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD8D5816A7CC50E2ULL,
		0x46AF7F5C2BDDD86AULL,
		0x6AEF143FC70C0659ULL,
		0x20D2309E51D9F997ULL,
		0xCC117C90D1B89949ULL,
		0x1CFD16B3728D6384ULL,
		0xC70143F3A82696ABULL,
		0xFC86CC8A8153A433ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3E2C4D23EE318DD5ULL,
		0x82B94C69F95F0715ULL,
		0xA6CA8B8FD639AF3AULL,
		0x5E5D44C6D278B81FULL,
		0xCC0D7A0760CACB46ULL,
		0x7354CCF29391FA3EULL,
		0x2DE980D285A521E4ULL,
		0x873E8F896B20865CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A9B5B0829EE81AULL,
		0x69F89DA93E201FF0ULL,
		0x1E7EB89BAFE4A0CFULL,
		0xAFA887D64A7E117AULL,
		0x6923B752EFF2EF96ULL,
		0xD64B43E9819C2519ULL,
		0x41CE58EEBEE4B772ULL,
		0x3768EA640D6B84C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD58297736B92A5BBULL,
		0x18C0AEC0BB3EE724ULL,
		0x884BD2F426550E6BULL,
		0xAEB4BCF087FAA6A5ULL,
		0x62E9C2B470D7DBAFULL,
		0x9D09890911F5D525ULL,
		0xEC1B27E3C6C06A71ULL,
		0x4FD5A5255DB5019BULL
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
		0x79C2DD60C3F45D1EULL,
		0x4AE0785D9D9CD49DULL,
		0x29A645075EF69E39ULL,
		0xA70947ED84350E6BULL,
		0xEB93ECA12AB0CF6DULL,
		0xD982E9A164284E98ULL,
		0xB1C11A715ACC93E9ULL,
		0xC464166389535169ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD86C695911C415C0ULL,
		0xC5E09F6F2D78D1DBULL,
		0x53E21AD7D1BC6647ULL,
		0x3AE9A9BC13045878ULL,
		0x3F30F5652D399DC2ULL,
		0x0604A84491D55963ULL,
		0x30369FB22B3D0088ULL,
		0xFAA61210669D3A4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1567407B230475EULL,
		0x84FFD8EE702402C1ULL,
		0xD5C42A2F8D3A37F1ULL,
		0x6C1F9E317130B5F2ULL,
		0xAC62F73BFD7731ABULL,
		0xD37E415CD252F535ULL,
		0x818A7ABF2F8F9361ULL,
		0xC9BE045322B6171AULL
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
		0x1C7FA9AF46D914EAULL,
		0x11878CBBEE9425BDULL,
		0xCB4235D42B2C4355ULL,
		0x5B9E9BB16FE7EDAAULL,
		0x8AC014E96DA92F66ULL,
		0x795CC0C94725788AULL,
		0x1C698FD2F3A35CE7ULL,
		0x7887EFAB22EB3C53ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C07CAD186A3C73ULL,
		0x88679920283322F3ULL,
		0xC7C1220B070F5C75ULL,
		0x072C86DA3C4B4DFEULL,
		0xFC073F8AFAD8DDA4ULL,
		0xA66242854882237FULL,
		0x3F65025E6DCC9314ULL,
		0x01E7A0FF13085CD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36BF2D022E6ED877ULL,
		0x891FF39BC66102C9ULL,
		0x038113C9241CE6DFULL,
		0x547214D7339C9FACULL,
		0x8EB8D55E72D051C2ULL,
		0xD2FA7E43FEA3550AULL,
		0xDD048D7485D6C9D2ULL,
		0x76A04EAC0FE2DF80ULL
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
		0xD2BD41D084F54076ULL,
		0x98FC4F34A961571DULL,
		0x0E3267ADDC11DE84ULL,
		0xFBAD728ACD3FB6A4ULL,
		0x5463116BD4BF6BDFULL,
		0x0676D2E18831E2E9ULL,
		0x2CDFA9451577FC60ULL,
		0x0E7B86AAF031AD42ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD04FBB6AA31D44ECULL,
		0x52313BCFFE61CF11ULL,
		0xF59BF28493DF7D08ULL,
		0xA6FED797D85E8121ULL,
		0x07068F97FAADB788ULL,
		0xC5C70CFE4A237632ULL,
		0x63E1035C047336F7ULL,
		0x0FD8E85E3B8FF110ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x026D8665E1D7FB8AULL,
		0x46CB1364AAFF880CULL,
		0x189675294832617CULL,
		0x54AE9AF2F4E13582ULL,
		0x4D5C81D3DA11B457ULL,
		0x40AFC5E33E0E6CB7ULL,
		0xC8FEA5E91104C568ULL,
		0xFEA29E4CB4A1BC31ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3FE550DDB399099FULL,
		0x215349C560096106ULL,
		0x58BAD4585D3DC3ECULL,
		0x0896E648DEB3C9DFULL,
		0xC365DB16662DAC6DULL,
		0x0F6E60572437B5BDULL,
		0x00F4E9763242EECFULL,
		0x2B83BF1AF5C4F52DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80D37CC209B7B570ULL,
		0x9DF95D4C53A86676ULL,
		0xB3F1811E549CD569ULL,
		0x9ED6A0CD7789ADB5ULL,
		0x64F7E91D7EB5F12BULL,
		0x97A2D44A59F98CB4ULL,
		0x39DECB588E88840BULL,
		0x7E6D11BA84CCDCD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF11D41BA9E1542FULL,
		0x8359EC790C60FA8FULL,
		0xA4C9533A08A0EE82ULL,
		0x69C0457B672A1C29ULL,
		0x5E6DF1F8E777BB41ULL,
		0x77CB8C0CCA3E2909ULL,
		0xC7161E1DA3BA6AC3ULL,
		0xAD16AD6070F81853ULL
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
		0x393AEEA6A7AA5C66ULL,
		0x7468343BEEA555E7ULL,
		0x1295C82EE52B267CULL,
		0xD08888BF0C23776EULL,
		0x7A47682860B22002ULL,
		0xBEE212B6F537B4B3ULL,
		0x4EDE65178FC16EA5ULL,
		0xEE8D50633C89B269ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x656E563DBACA1159ULL,
		0xA45E5422A2A0DA0EULL,
		0x048A72A8FFC41DF1ULL,
		0x966199B510457BB3ULL,
		0x57EAEE7291B6DF55ULL,
		0x7F566A1E8EE695BFULL,
		0x9925AF393EFB526BULL,
		0x2F5466CD9122E480ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3CC9868ECE04B0DULL,
		0xD009E0194C047BD8ULL,
		0x0E0B5585E567088AULL,
		0x3A26EF09FBDDFBBBULL,
		0x225C79B5CEFB40ADULL,
		0x3F8BA89866511EF4ULL,
		0xB5B8B5DE50C61C3AULL,
		0xBF38E995AB66CDE8ULL
	}};
	sign = 0;
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
		0x8B0F62F50A0211B3ULL,
		0x8F6EBFF08D6429AEULL,
		0x55D2115AB06654D5ULL,
		0xF6035C1F4D740653ULL,
		0x1701C702C10169B8ULL,
		0x27155BB1B7EEE4F1ULL,
		0x1DBF3FB51C5837CDULL,
		0x973745A826C99756ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B11B71583E7186ULL,
		0xE4387BA62DBD6AF5ULL,
		0xAF4FE65672AD648AULL,
		0xF86224DC4B319DF7ULL,
		0x1B69BC4C9EA52A96ULL,
		0xAC4094DDE279237FULL,
		0xEECBCB1255A2966AULL,
		0xC667AAA27E283A6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA65E4783B1C3A02DULL,
		0xAB36444A5FA6BEB8ULL,
		0xA6822B043DB8F04AULL,
		0xFDA137430242685BULL,
		0xFB980AB6225C3F21ULL,
		0x7AD4C6D3D575C171ULL,
		0x2EF374A2C6B5A162ULL,
		0xD0CF9B05A8A15CE8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC52A05DD877E3B02ULL,
		0xDFD6441E515A03F7ULL,
		0x3BD18A5E03427B46ULL,
		0xC5FD8993EA7EFBC0ULL,
		0xB59235738E38ACF9ULL,
		0xD22C69ACC5B63E8AULL,
		0x5B15C946A2DC0671ULL,
		0x361F9005D22E2206ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53D45D12E19E5C1ULL,
		0x9BFBC4B706B62FB7ULL,
		0xDE604A337DE819C0ULL,
		0x4570448F54458E7CULL,
		0xF32D99FD428FEFC1ULL,
		0xD730A199B25A40ABULL,
		0x7AC29DEB15713EC2ULL,
		0x54C6EA6DAF83E782ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFECC00C59645541ULL,
		0x43DA7F674AA3D43FULL,
		0x5D71402A855A6186ULL,
		0x808D450496396D43ULL,
		0xC2649B764BA8BD38ULL,
		0xFAFBC813135BFDDEULL,
		0xE0532B5B8D6AC7AEULL,
		0xE158A59822AA3A83ULL
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
	return 0;
}