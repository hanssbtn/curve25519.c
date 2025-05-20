#include "tests.h"

int32_t curve25519_key_add_inplace_test(void) {
	printf("Add Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9FF654E919EDC7C2,
		0x899A87EDD9712E51,
		0xCF0DD5FD4AF8577C,
		0x26434EDD321B25D3
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA61A0445B79C4471,
		0x487C14C707B7378C,
		0x25B943F597F4FC59,
		0x29D8FC9BEB0BC153
	}};
	curve25519_key_t k3 = {.key64 = {
		0x4610592ED18A0C33,
		0xD2169CB4E12865DE,
		0xF4C719F2E2ED53D5,
		0x501C4B791D26E726
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C7AB464128E0600,
		0xDB29308840B2805F,
		0x0DD1F9925AB274CA,
		0x515B61C84E469321
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3192A446A33CB7AB,
		0xB223591D52C60E44,
		0xE6AC29E739D29B88,
		0x30BA68FD6D676585
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E0D58AAB5CABDBE,
		0x8D4C89A593788EA3,
		0xF47E237994851053,
		0x0215CAC5BBADF8A6
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82582F86DF55C3B0,
		0x1AB384BCB5038432,
		0xBF298E860F27D923,
		0x73EBCC532DCF459A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34A7C7553B702147,
		0x9B68CFFF974F04BE,
		0x11BC32EFB4B568D3,
		0x3B898F559967908B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6FFF6DC1AC5E50A,
		0xB61C54BC4C5288F0,
		0xD0E5C175C3DD41F6,
		0x2F755BA8C736D625
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE86CECBCCF6CA45C,
		0xC7D7DEF0D74234AE,
		0x20AB98937C323272,
		0x728CD4A576E0EACE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A58052AC76F76C,
		0x548455993CD431F9,
		0x5BE052E6B51CD496,
		0x3368C1743B5E3C88
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70126D0F7BE39BDB,
		0x1C5C348A141666A8,
		0x7C8BEB7A314F0709,
		0x25F59619B23F2756
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B175DA1D97EC227,
		0xD2CE2D7737584B59,
		0x42295D90F2038BB6,
		0x3F1F68CAC8EC89DC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AAC683670327081,
		0xA01E91791F80258F,
		0x801D8AB496E44D1F,
		0x078CEB27FD541BD3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85C3C5D849B132A8,
		0x72ECBEF056D870E8,
		0xC246E84588E7D8D6,
		0x46AC53F2C640A5AF
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x723C580900333982,
		0x88E57DA7E856CB1F,
		0x5692F6995BDCF3EC,
		0x605B428DD8A1CAC2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4B32F4AAE8FD36,
		0xFC2F25D59A191B6E,
		0xE34268149E4EFB86,
		0x245E45A84DAF4DE5
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C878AFDAB1C36CB,
		0x8514A37D826FE68E,
		0x39D55EADFA2BEF73,
		0x04B98836265118A8
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF2B1BC3EDE3B2A,
		0xC1ED4AAB00DC2588,
		0xAC772285275F1471,
		0x613C615BB11A56A2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726517BB9E98397F,
		0x947512FA4A1789E8,
		0x5E8B0C7845F48EDA,
		0x4BF6502757EBCE48
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D57C977DD7674BC,
		0x56625DA54AF3AF71,
		0x0B022EFD6D53A34C,
		0x2D32B183090624EB
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF356F89322BE295F,
		0xE6A67E5626F939B3,
		0x53A3F1B9BE79A848,
		0x06EC320B6D0E849E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x613A7CFB134FD4C5,
		0xC2B975640E1B2486,
		0x1EE0931BC587FA50,
		0x1D8B218FA5010D5A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5491758E360DFE24,
		0xA95FF3BA35145E3A,
		0x728484D58401A299,
		0x2477539B120F91F8
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A9C146EC57A2366,
		0x0E177CD03555C848,
		0xA9C2B078D799379B,
		0x279881EF2F81452B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D48C366ED2DFAC7,
		0xBD97EE8E20E6F8A2,
		0x46758CCD88047357,
		0x13D246F89658D709
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37E4D7D5B2A81E2D,
		0xCBAF6B5E563CC0EA,
		0xF0383D465F9DAAF2,
		0x3B6AC8E7C5DA1C34
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F15BDFD48560298,
		0x396FAD3F02EAFC53,
		0xCF6B99A87019C02F,
		0x471F3BDBACFDC600
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20047F61187DC098,
		0x0E7F9E0E3F2A87F5,
		0x6B65128316543550,
		0x1E00B4F04B2D3F5B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F1A3D5E60D3C330,
		0x47EF4B4D42158448,
		0x3AD0AC2B866DF57F,
		0x651FF0CBF82B055C
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}