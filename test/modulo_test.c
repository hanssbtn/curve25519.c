#include "tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {
		0xBEDD5456360AEB04,
		0xC1E743D12E920763,
		0x8E0CE4F4E855272F,
		0xEB405010EA0F9D73
	};	curve25519_key_t k2 = {
		0xBEDD5456360AEB17,
		0xC1E743D12E920763,
		0x8E0CE4F4E855272F,
		0x6B405010EA0F9D73
	};	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xEB8C352EF3D584E3,
		0x42A04377E59D49F8,
		0x1F6720840C52BB5F,
		0x700CF42A69A9DC48
	};	k2 = (curve25519_key_t){
		0xEB8C352EF3D584E3,
		0x42A04377E59D49F8,
		0x1F6720840C52BB5F,
		0x700CF42A69A9DC48
	};	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x776B0CB229B116EC,
		0x0E8B1C89C229CFA8,
		0x51E6DD1315735060,
		0x84793A42AC8B6E66
	};	k2 = (curve25519_key_t){
		0x776B0CB229B116FF,
		0x0E8B1C89C229CFA8,
		0x51E6DD1315735060,
		0x04793A42AC8B6E66
	};	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x79C34B8F73433481,
		0xF326E8BFEEA58EA7,
		0x7B90E08935AA3DA3,
		0xD9189EF42C914AE8
	};	k2 = (curve25519_key_t){
		0x79C34B8F73433494,
		0xF326E8BFEEA58EA7,
		0x7B90E08935AA3DA3,
		0x59189EF42C914AE8
	};	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6F95C93DB987F61D,
		0x6A37BE903843A9BC,
		0x349B851BF17FC6CD,
		0x405548BEDCC73119
	};	k2 = (curve25519_key_t){
		0x6F95C93DB987F61D,
		0x6A37BE903843A9BC,
		0x349B851BF17FC6CD,
		0x405548BEDCC73119
	};	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x43808F02DC195731,
		0xB0FC435F1682262C,
		0xB6FBAF9891C95AA8,
		0x0AD3EF4C937EBA07
	};	k2 = (curve25519_key_t){
		0x43808F02DC195731,
		0xB0FC435F1682262C,
		0xB6FBAF9891C95AA8,
		0x0AD3EF4C937EBA07
	};	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x54FB4F5996C21493,
		0xECC3DCAB93E69AB4,
		0xCD39ACE2A4B8AFBC,
		0x9D35D7CB02EC8AF1
	};	k2 = (curve25519_key_t){
		0x54FB4F5996C214A6,
		0xECC3DCAB93E69AB4,
		0xCD39ACE2A4B8AFBC,
		0x1D35D7CB02EC8AF1
	};	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x941249BEDCA3AD74,
		0x4C8C153F0175371A,
		0xE78C28C7DB7FF980,
		0x318E3CF795D5604F
	};	k2 = (curve25519_key_t){
		0x941249BEDCA3AD74,
		0x4C8C153F0175371A,
		0xE78C28C7DB7FF980,
		0x318E3CF795D5604F
	};	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5E8925145EBA1F83,
		0x559FDFB5AD822B52,
		0x9E9C2684A2F2E4D2,
		0x0F61EEE08D795682
	};	k2 = (curve25519_key_t){
		0x5E8925145EBA1F83,
		0x559FDFB5AD822B52,
		0x9E9C2684A2F2E4D2,
		0x0F61EEE08D795682
	};	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x50ACDEB11D185E84,
		0xBD7F0857C82D31C3,
		0xC5FBBEC1F7165F89,
		0x9836D1676E93347A
	};	k2 = (curve25519_key_t){
		0x50ACDEB11D185E97,
		0xBD7F0857C82D31C3,
		0xC5FBBEC1F7165F89,
		0x1836D1676E93347A
	};	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC00A89EA7040AF3E,
		0x139010A9AB4BE072,
		0x23EAF840FC8771D8,
		0x7401CFBD10E549C5
	};	k2 = (curve25519_key_t){
		0xC00A89EA7040AF3E,
		0x139010A9AB4BE072,
		0x23EAF840FC8771D8,
		0x7401CFBD10E549C5
	};	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x139D26B9CC06B209,
		0x8179AB4A7A28BD5D,
		0x774204D6AB88862B,
		0x4E72B26B2ED9D784
	};	k2 = (curve25519_key_t){
		0x139D26B9CC06B209,
		0x8179AB4A7A28BD5D,
		0x774204D6AB88862B,
		0x4E72B26B2ED9D784
	};	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4438886C61E5FDCF,
		0xA482586CB19FE2E4,
		0x5819A9AF0A60B6F7,
		0xA6A4FECF6CD3C4CE
	};	k2 = (curve25519_key_t){
		0x4438886C61E5FDE2,
		0xA482586CB19FE2E4,
		0x5819A9AF0A60B6F7,
		0x26A4FECF6CD3C4CE
	};	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xB536C3D05E5F56C0,
		0x915A23A24783A59A,
		0x3F4815928EA5B5A0,
		0xF990C5AE51E15B72
	};	k2 = (curve25519_key_t){
		0xB536C3D05E5F56D3,
		0x915A23A24783A59A,
		0x3F4815928EA5B5A0,
		0x7990C5AE51E15B72
	};	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x42C3E919B75F56C8,
		0xF1E73BEBEB663E69,
		0x8C96B4185B273C86,
		0x214FC9CA652CD78D
	};	k2 = (curve25519_key_t){
		0x42C3E919B75F56C8,
		0xF1E73BEBEB663E69,
		0x8C96B4185B273C86,
		0x214FC9CA652CD78D
	};	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5EB01223CD6E9F5A,
		0x60DA1E33836D345F,
		0xB6D4C2CEBBF16744,
		0x66BE6916F3EBB97C
	};	k2 = (curve25519_key_t){
		0x5EB01223CD6E9F5A,
		0x60DA1E33836D345F,
		0xB6D4C2CEBBF16744,
		0x66BE6916F3EBB97C
	};	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4A60779E45E1781B,
		0xCE993CDC688C061F,
		0x6751B21707EADA58,
		0x62188E3541376882
	};	k2 = (curve25519_key_t){
		0x4A60779E45E1781B,
		0xCE993CDC688C061F,
		0x6751B21707EADA58,
		0x62188E3541376882
	};	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA94DF332CC1ADFBB,
		0x3B7677760E45AC29,
		0x322BE8C29315412E,
		0x22FB6F8E52C44D05
	};	k2 = (curve25519_key_t){
		0xA94DF332CC1ADFBB,
		0x3B7677760E45AC29,
		0x322BE8C29315412E,
		0x22FB6F8E52C44D05
	};	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5778CA46A659AA6D,
		0x3D66ED411A459215,
		0x009442489FDEBAAF,
		0x26556DE9AFEC3749
	};	k2 = (curve25519_key_t){
		0x5778CA46A659AA6D,
		0x3D66ED411A459215,
		0x009442489FDEBAAF,
		0x26556DE9AFEC3749
	};	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x342A76924730087A,
		0x1316BA85525BA958,
		0xA4FEF4A063984574,
		0x589D823FB9C38EA1
	};	k2 = (curve25519_key_t){
		0x342A76924730087A,
		0x1316BA85525BA958,
		0xA4FEF4A063984574,
		0x589D823FB9C38EA1
	};	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xFF4BFD61BBE5BEFD,
		0x10FD7A660AED58D9,
		0xEB88359EDB2DAE91,
		0x90484006FBF9BF12
	};	k2 = (curve25519_key_t){
		0xFF4BFD61BBE5BF10,
		0x10FD7A660AED58D9,
		0xEB88359EDB2DAE91,
		0x10484006FBF9BF12
	};	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x792467E23F3F0B9A,
		0x5F679FF367476829,
		0x86E7E255664F4AE0,
		0xC40837FAD3B02C72
	};	k2 = (curve25519_key_t){
		0x792467E23F3F0BAD,
		0x5F679FF367476829,
		0x86E7E255664F4AE0,
		0x440837FAD3B02C72
	};	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x94750CB6C811EAB7,
		0x4834E1600A98ED52,
		0x8C9315A9D5FE7F43,
		0xABC8D7606B3F92F1
	};	k2 = (curve25519_key_t){
		0x94750CB6C811EACA,
		0x4834E1600A98ED52,
		0x8C9315A9D5FE7F43,
		0x2BC8D7606B3F92F1
	};	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xF922AC7A424E4D3B,
		0x6FB2975BD2DCB7BF,
		0x62921EBBEBE34E75,
		0xA092D7B5B91CE542
	};	k2 = (curve25519_key_t){
		0xF922AC7A424E4D4E,
		0x6FB2975BD2DCB7BF,
		0x62921EBBEBE34E75,
		0x2092D7B5B91CE542
	};	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x522FD503B0615CF5,
		0x8CF7C386130CE2BD,
		0x9770F9D43E7BF15E,
		0x41D59E93EC782637
	};	k2 = (curve25519_key_t){
		0x522FD503B0615CF5,
		0x8CF7C386130CE2BD,
		0x9770F9D43E7BF15E,
		0x41D59E93EC782637
	};	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x558630704F94F56F,
		0xDC5C33C0FDD07C0C,
		0x461A30A75F64D367,
		0xC7AB0A66D0DA2CDF
	};	k2 = (curve25519_key_t){
		0x558630704F94F582,
		0xDC5C33C0FDD07C0C,
		0x461A30A75F64D367,
		0x47AB0A66D0DA2CDF
	};	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xFDCDD30C2AF5B502,
		0x2F49AA9633E7536D,
		0xD2EB73C7A1A0479B,
		0xCCD7AC512A5A695E
	};	k2 = (curve25519_key_t){
		0xFDCDD30C2AF5B515,
		0x2F49AA9633E7536D,
		0xD2EB73C7A1A0479B,
		0x4CD7AC512A5A695E
	};	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x93CDAF87EC7C8B64,
		0xF7D35DE0A1A0AE6B,
		0x1F4670C3FABFC590,
		0x91143DFFB4329A5D
	};	k2 = (curve25519_key_t){
		0x93CDAF87EC7C8B77,
		0xF7D35DE0A1A0AE6B,
		0x1F4670C3FABFC590,
		0x11143DFFB4329A5D
	};	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6CCEE6848B32C886,
		0x45C79AB5D6983C1A,
		0xA48ACE6C5A6BCFD0,
		0x2C1B5D069B37BC07
	};	k2 = (curve25519_key_t){
		0x6CCEE6848B32C886,
		0x45C79AB5D6983C1A,
		0xA48ACE6C5A6BCFD0,
		0x2C1B5D069B37BC07
	};	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE9E5779E341F1BA8,
		0x1155C932AA74087E,
		0xB9D0112942BFEECF,
		0xF91BCC6835964444
	};	k2 = (curve25519_key_t){
		0xE9E5779E341F1BBB,
		0x1155C932AA74087E,
		0xB9D0112942BFEECF,
		0x791BCC6835964444
	};	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x965315C6329A938B,
		0x75C90F535034E2A8,
		0x673665DA2C73E539,
		0xDE3300134630A11B
	};	k2 = (curve25519_key_t){
		0x965315C6329A939E,
		0x75C90F535034E2A8,
		0x673665DA2C73E539,
		0x5E3300134630A11B
	};	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x185A87661CD0F8B1,
		0x7DE529D548CC3ACB,
		0xDBD6170132BE936C,
		0xECA31C0D9B729767
	};	k2 = (curve25519_key_t){
		0x185A87661CD0F8C4,
		0x7DE529D548CC3ACB,
		0xDBD6170132BE936C,
		0x6CA31C0D9B729767
	};	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xB03F620F68AF381F,
		0x56F34A1384E8F7CD,
		0x8D99E52877703F0E,
		0xC51F237EE96A84DB
	};	k2 = (curve25519_key_t){
		0xB03F620F68AF3832,
		0x56F34A1384E8F7CD,
		0x8D99E52877703F0E,
		0x451F237EE96A84DB
	};	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x1C51D5B496B56029,
		0x24456DF158BF78C5,
		0x87C041DD704F66EC,
		0xB707D941AEF2029F
	};	k2 = (curve25519_key_t){
		0x1C51D5B496B5603C,
		0x24456DF158BF78C5,
		0x87C041DD704F66EC,
		0x3707D941AEF2029F
	};	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x399AF47A54FE412B,
		0xA3EC832B61B369D1,
		0x08CD27B26B9BC778,
		0x1B18275243745935
	};	k2 = (curve25519_key_t){
		0x399AF47A54FE412B,
		0xA3EC832B61B369D1,
		0x08CD27B26B9BC778,
		0x1B18275243745935
	};	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA6DBF18631A58E27,
		0x9A996EE27461BE0B,
		0x69B7D6AD32797388,
		0x190A0B9271B21C76
	};	k2 = (curve25519_key_t){
		0xA6DBF18631A58E27,
		0x9A996EE27461BE0B,
		0x69B7D6AD32797388,
		0x190A0B9271B21C76
	};	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x236E55A083CD31A2,
		0x37113D83944AB9D0,
		0xCA7BAEE354F8A664,
		0x9306AD88A719C8C8
	};	k2 = (curve25519_key_t){
		0x236E55A083CD31B5,
		0x37113D83944AB9D0,
		0xCA7BAEE354F8A664,
		0x1306AD88A719C8C8
	};	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x60E2081794E8CD52,
		0x090D8DC3CDD2BADA,
		0xC3ED989A408DD7E3,
		0x34A290E7A48180A2
	};	k2 = (curve25519_key_t){
		0x60E2081794E8CD52,
		0x090D8DC3CDD2BADA,
		0xC3ED989A408DD7E3,
		0x34A290E7A48180A2
	};	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4C077903C3631784,
		0x9359ED66D6A67641,
		0x6CD4DA6F03C01860,
		0x72F2F217F5E84C6E
	};	k2 = (curve25519_key_t){
		0x4C077903C3631784,
		0x9359ED66D6A67641,
		0x6CD4DA6F03C01860,
		0x72F2F217F5E84C6E
	};	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4757BE588C2788FB,
		0x99D86682698A79A6,
		0x4A20D91431AC04C4,
		0x3819D7FCD4BF30B3
	};	k2 = (curve25519_key_t){
		0x4757BE588C2788FB,
		0x99D86682698A79A6,
		0x4A20D91431AC04C4,
		0x3819D7FCD4BF30B3
	};	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6D456A1AFE864957,
		0x64272D62D8CA07F1,
		0x75C3B80DA2040CBB,
		0x6FB9BF0962969911
	};	k2 = (curve25519_key_t){
		0x6D456A1AFE864957,
		0x64272D62D8CA07F1,
		0x75C3B80DA2040CBB,
		0x6FB9BF0962969911
	};	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x52C5730D94607E6C,
		0xA2CEB132D9685EAF,
		0x6EBB46738F58C4B2,
		0x35B6E8E65F303392
	};	k2 = (curve25519_key_t){
		0x52C5730D94607E6C,
		0xA2CEB132D9685EAF,
		0x6EBB46738F58C4B2,
		0x35B6E8E65F303392
	};	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC6A0C2726CF0D51F,
		0x34384831EA9E6C47,
		0xE98C16C6CAAA2B31,
		0xE7336D6F403CC030
	};	k2 = (curve25519_key_t){
		0xC6A0C2726CF0D532,
		0x34384831EA9E6C47,
		0xE98C16C6CAAA2B31,
		0x67336D6F403CC030
	};	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xDA7CF385B4E35B87,
		0x66F06BF121C5EFC4,
		0x94E372C4D7F11D91,
		0x89883FB93A66A2E5
	};	k2 = (curve25519_key_t){
		0xDA7CF385B4E35B9A,
		0x66F06BF121C5EFC4,
		0x94E372C4D7F11D91,
		0x09883FB93A66A2E5
	};	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x0577F9561FA0C97C,
		0xCD377457C0BAE63F,
		0xCCD65B50A4E7FC6A,
		0xB48B46CAC84ED16E
	};	k2 = (curve25519_key_t){
		0x0577F9561FA0C98F,
		0xCD377457C0BAE63F,
		0xCCD65B50A4E7FC6A,
		0x348B46CAC84ED16E
	};	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x006FFE88B7E89609,
		0x05F1D1DC2988ED47,
		0xE5D7FE87D1829E6D,
		0x471CE2FA4DDEF950
	};	k2 = (curve25519_key_t){
		0x006FFE88B7E89609,
		0x05F1D1DC2988ED47,
		0xE5D7FE87D1829E6D,
		0x471CE2FA4DDEF950
	};	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x97A5D1C42538E40B,
		0x3A226BC585DBFC7D,
		0x26EDB1B90AC674EB,
		0xE0F0971034FF85F1
	};	k2 = (curve25519_key_t){
		0x97A5D1C42538E41E,
		0x3A226BC585DBFC7D,
		0x26EDB1B90AC674EB,
		0x60F0971034FF85F1
	};	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x59C581E73ED8E048,
		0xBA11FEF05D9C0175,
		0x8CEA88915FBE4052,
		0x6EE12BA6B34F5449
	};	k2 = (curve25519_key_t){
		0x59C581E73ED8E048,
		0xBA11FEF05D9C0175,
		0x8CEA88915FBE4052,
		0x6EE12BA6B34F5449
	};	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x9CB552E34A2C5D35,
		0x48402D23E0DA70DB,
		0xBB092A1F2926B4B8,
		0x3CF302EEB26D62D2
	};	k2 = (curve25519_key_t){
		0x9CB552E34A2C5D35,
		0x48402D23E0DA70DB,
		0xBB092A1F2926B4B8,
		0x3CF302EEB26D62D2
	};	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x40E4DED59C9B1633,
		0xA33D16F7F2F38CF8,
		0x41E4F5FB43EA2A8E,
		0x6FFEEA84D2EFD721
	};	k2 = (curve25519_key_t){
		0x40E4DED59C9B1633,
		0xA33D16F7F2F38CF8,
		0x41E4F5FB43EA2A8E,
		0x6FFEEA84D2EFD721
	};	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x80269258AA63E26E,
		0xAEC5D143A9443D45,
		0xCA058B8C964A9509,
		0x9607255C3EA15CB5
	};	k2 = (curve25519_key_t){
		0x80269258AA63E281,
		0xAEC5D143A9443D45,
		0xCA058B8C964A9509,
		0x1607255C3EA15CB5
	};	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5934D5E6AB7B298C,
		0x104A1F9CD7F6674D,
		0x1978B98F5F47F629,
		0x5A561CA9CCADB429
	};	k2 = (curve25519_key_t){
		0x5934D5E6AB7B298C,
		0x104A1F9CD7F6674D,
		0x1978B98F5F47F629,
		0x5A561CA9CCADB429
	};	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x62E437DFC0FACFC5,
		0x1E81652FE1024E9B,
		0x4FF4FFBE3C0D2C95,
		0xF56F6F97181A33BA
	};	k2 = (curve25519_key_t){
		0x62E437DFC0FACFD8,
		0x1E81652FE1024E9B,
		0x4FF4FFBE3C0D2C95,
		0x756F6F97181A33BA
	};	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x0B0C6E8A24DCED5D,
		0xE54CDDCD4DFD3BD7,
		0x4923CD0A3008E36E,
		0x9F1A89F0DAA77E15
	};	k2 = (curve25519_key_t){
		0x0B0C6E8A24DCED70,
		0xE54CDDCD4DFD3BD7,
		0x4923CD0A3008E36E,
		0x1F1A89F0DAA77E15
	};	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x3D485271A5730437,
		0x2EFD4904DE238444,
		0x9A3627F4E10AA746,
		0x4CE3FF31A06D0D04
	};	k2 = (curve25519_key_t){
		0x3D485271A5730437,
		0x2EFD4904DE238444,
		0x9A3627F4E10AA746,
		0x4CE3FF31A06D0D04
	};	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE82653D725DC7426,
		0x05DEE014F7ECBA92,
		0x6F42F832C844578C,
		0x065955FA616158DA
	};	k2 = (curve25519_key_t){
		0xE82653D725DC7426,
		0x05DEE014F7ECBA92,
		0x6F42F832C844578C,
		0x065955FA616158DA
	};	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x133626C2BE8CF0EF,
		0x226657A3EB4C7883,
		0x9C5735C7570E2900,
		0x6EF0008EA904D9EB
	};	k2 = (curve25519_key_t){
		0x133626C2BE8CF0EF,
		0x226657A3EB4C7883,
		0x9C5735C7570E2900,
		0x6EF0008EA904D9EB
	};	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xFE8DF37FB741D89A,
		0x8CDD0412CA07B069,
		0x01CD7C49F7E6F18E,
		0xD2231637ED2376B1
	};	k2 = (curve25519_key_t){
		0xFE8DF37FB741D8AD,
		0x8CDD0412CA07B069,
		0x01CD7C49F7E6F18E,
		0x52231637ED2376B1
	};	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x86D9C202BC86B123,
		0x248D0AC7D18119FC,
		0x347ED41224A4D19A,
		0x6C0F1A65C2901A75
	};	k2 = (curve25519_key_t){
		0x86D9C202BC86B123,
		0x248D0AC7D18119FC,
		0x347ED41224A4D19A,
		0x6C0F1A65C2901A75
	};	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xAFAE7B00D0CC3513,
		0x693AFF558DFEC154,
		0x658EB53DCEB6274D,
		0xB4DC8F1C26AE3294
	};	k2 = (curve25519_key_t){
		0xAFAE7B00D0CC3526,
		0x693AFF558DFEC154,
		0x658EB53DCEB6274D,
		0x34DC8F1C26AE3294
	};	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x65F31418D670D397,
		0x8A9D2C2C1FCF2EFD,
		0x9C296023978FFCA3,
		0x25FFA543564DE992
	};	k2 = (curve25519_key_t){
		0x65F31418D670D397,
		0x8A9D2C2C1FCF2EFD,
		0x9C296023978FFCA3,
		0x25FFA543564DE992
	};	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA84A7CA96D9DD5C8,
		0x26FCC0F69A9EB5B2,
		0xC5BBEB3D0F8342FA,
		0xD7D9DC3CE4D1094D
	};	k2 = (curve25519_key_t){
		0xA84A7CA96D9DD5DB,
		0x26FCC0F69A9EB5B2,
		0xC5BBEB3D0F8342FA,
		0x57D9DC3CE4D1094D
	};	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x910C1C0145EE21B0,
		0xC1C5F57228796579,
		0x5126D760D628EAEB,
		0x0F94677807127A2A
	};	k2 = (curve25519_key_t){
		0x910C1C0145EE21B0,
		0xC1C5F57228796579,
		0x5126D760D628EAEB,
		0x0F94677807127A2A
	};	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA16AE31249BCBAD0,
		0x35B11C2B38793F19,
		0xA14246CC67C6C35B,
		0x67EBA2BC72540CE8
	};	k2 = (curve25519_key_t){
		0xA16AE31249BCBAD0,
		0x35B11C2B38793F19,
		0xA14246CC67C6C35B,
		0x67EBA2BC72540CE8
	};	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6E2169BF838B19F7,
		0x4C46AA3BC74EAA6D,
		0x1EB8855B224A0475,
		0xC2CF8E39C1469A8A
	};	k2 = (curve25519_key_t){
		0x6E2169BF838B1A0A,
		0x4C46AA3BC74EAA6D,
		0x1EB8855B224A0475,
		0x42CF8E39C1469A8A
	};	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA43D8040DD9B5F59,
		0xD9DFBA639CCA46B7,
		0xBF8F90ADDF3495B8,
		0x7A03AED21095B06A
	};	k2 = (curve25519_key_t){
		0xA43D8040DD9B5F59,
		0xD9DFBA639CCA46B7,
		0xBF8F90ADDF3495B8,
		0x7A03AED21095B06A
	};	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x859E6CDAEE1A09A4,
		0xE1064E773212CC27,
		0x15303698E996745A,
		0x6F67D32D76590166
	};	k2 = (curve25519_key_t){
		0x859E6CDAEE1A09A4,
		0xE1064E773212CC27,
		0x15303698E996745A,
		0x6F67D32D76590166
	};	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5F827F03DB73F217,
		0x1CACD9D80FC771D8,
		0x1BAF844948FC86E2,
		0xD6E1ED89DC2ABF25
	};	k2 = (curve25519_key_t){
		0x5F827F03DB73F22A,
		0x1CACD9D80FC771D8,
		0x1BAF844948FC86E2,
		0x56E1ED89DC2ABF25
	};	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x2F357E1C2E991FA6,
		0xE04CD6AA86433328,
		0xCD5D9D2B163AE342,
		0x7D1EA4B2714F3505
	};	k2 = (curve25519_key_t){
		0x2F357E1C2E991FA6,
		0xE04CD6AA86433328,
		0xCD5D9D2B163AE342,
		0x7D1EA4B2714F3505
	};	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD70798A897682621,
		0xEC5E54971BE83AFC,
		0x104C0E74E2835714,
		0x7D58211859007A45
	};	k2 = (curve25519_key_t){
		0xD70798A897682621,
		0xEC5E54971BE83AFC,
		0x104C0E74E2835714,
		0x7D58211859007A45
	};	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xDEF366052429A4ED,
		0xFD0D3722DC2A3121,
		0x98AAFBD81AC50F83,
		0x9AD128E2C94F264D
	};	k2 = (curve25519_key_t){
		0xDEF366052429A500,
		0xFD0D3722DC2A3121,
		0x98AAFBD81AC50F83,
		0x1AD128E2C94F264D
	};	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6CC77E8A8B205AEE,
		0x3AB694C47AE36A5F,
		0xE11616BAFF617A07,
		0x376FFFDD6CF4A664
	};	k2 = (curve25519_key_t){
		0x6CC77E8A8B205AEE,
		0x3AB694C47AE36A5F,
		0xE11616BAFF617A07,
		0x376FFFDD6CF4A664
	};	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4AD992C6293991B5,
		0x21EF96285ACEF9D3,
		0xD48993342D5C3BB2,
		0x05FD30ED77424647
	};	k2 = (curve25519_key_t){
		0x4AD992C6293991B5,
		0x21EF96285ACEF9D3,
		0xD48993342D5C3BB2,
		0x05FD30ED77424647
	};	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5CF64CDC05BD9B4A,
		0x7004E64CECEF5FE1,
		0x4F845F6EE1935B66,
		0xC82F1BFD9245F30D
	};	k2 = (curve25519_key_t){
		0x5CF64CDC05BD9B5D,
		0x7004E64CECEF5FE1,
		0x4F845F6EE1935B66,
		0x482F1BFD9245F30D
	};	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4F9E7C3ED8D78D33,
		0xF19F9BF740059A85,
		0x2483A98A8DABC457,
		0x33BF326C2AA38872
	};	k2 = (curve25519_key_t){
		0x4F9E7C3ED8D78D33,
		0xF19F9BF740059A85,
		0x2483A98A8DABC457,
		0x33BF326C2AA38872
	};	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x40DCDB4596A97A34,
		0x6947F90B59720BB0,
		0x890F5EC23475262A,
		0x83B236F120563200
	};	k2 = (curve25519_key_t){
		0x40DCDB4596A97A47,
		0x6947F90B59720BB0,
		0x890F5EC23475262A,
		0x03B236F120563200
	};	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xAE71C48B704E4C3E,
		0x8F9A1482726F5678,
		0xEB205E63C4407AFB,
		0x120AEB072DD72495
	};	k2 = (curve25519_key_t){
		0xAE71C48B704E4C3E,
		0x8F9A1482726F5678,
		0xEB205E63C4407AFB,
		0x120AEB072DD72495
	};	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x9E45F91FFFFCD076,
		0xAF0B787C1F5DAF44,
		0xBCA2AC1EFB385F4D,
		0xA8B997D0D9A64092
	};	k2 = (curve25519_key_t){
		0x9E45F91FFFFCD089,
		0xAF0B787C1F5DAF44,
		0xBCA2AC1EFB385F4D,
		0x28B997D0D9A64092
	};	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x66DA38C6E8B03A1E,
		0x2D0701AAB7AD0D44,
		0xD14059F5C2DA49D5,
		0xB3C745E1F0D016EF
	};	k2 = (curve25519_key_t){
		0x66DA38C6E8B03A31,
		0x2D0701AAB7AD0D44,
		0xD14059F5C2DA49D5,
		0x33C745E1F0D016EF
	};	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC612DF16BA77147F,
		0xC5378BB39E225B7A,
		0x7752A4F5641A3C43,
		0x98AD6993716E5B81
	};	k2 = (curve25519_key_t){
		0xC612DF16BA771492,
		0xC5378BB39E225B7A,
		0x7752A4F5641A3C43,
		0x18AD6993716E5B81
	};	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x2C54EE4FA7D293D8,
		0x9749E8FEFBC1D399,
		0x0DD6860CE5E52A2A,
		0xACAD7D9CE6BA838F
	};	k2 = (curve25519_key_t){
		0x2C54EE4FA7D293EB,
		0x9749E8FEFBC1D399,
		0x0DD6860CE5E52A2A,
		0x2CAD7D9CE6BA838F
	};	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC1299EF1367FC3AA,
		0xAFA1C7A6970100B7,
		0x080B2E05A6E70386,
		0x89E3E963D69EA9E0
	};	k2 = (curve25519_key_t){
		0xC1299EF1367FC3BD,
		0xAFA1C7A6970100B7,
		0x080B2E05A6E70386,
		0x09E3E963D69EA9E0
	};	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6D17E92F087AD579,
		0xF9951F8E1A238AB9,
		0x1C5FEA8621B2BC11,
		0xAFDCFC615FADF1C5
	};	k2 = (curve25519_key_t){
		0x6D17E92F087AD58C,
		0xF9951F8E1A238AB9,
		0x1C5FEA8621B2BC11,
		0x2FDCFC615FADF1C5
	};	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE80ABA92C2AC06A3,
		0x01C12385B48FAE9A,
		0xCF5A1A9ADD25434D,
		0xFFFD2A330AAEBC7D
	};	k2 = (curve25519_key_t){
		0xE80ABA92C2AC06B6,
		0x01C12385B48FAE9A,
		0xCF5A1A9ADD25434D,
		0x7FFD2A330AAEBC7D
	};	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x81B6DBC0F46B9F42,
		0xC2135D48F17B0A76,
		0x31581BA347B19535,
		0xCB67037D5D2A44FA
	};	k2 = (curve25519_key_t){
		0x81B6DBC0F46B9F55,
		0xC2135D48F17B0A76,
		0x31581BA347B19535,
		0x4B67037D5D2A44FA
	};	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xDAE72F70DEB83FA1,
		0x0D8EB10F48B30F10,
		0x9A2E9F37EE42B6DE,
		0x1820E7293130C36A
	};	k2 = (curve25519_key_t){
		0xDAE72F70DEB83FA1,
		0x0D8EB10F48B30F10,
		0x9A2E9F37EE42B6DE,
		0x1820E7293130C36A
	};	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x3F264EA9886B3FB2,
		0xA704C8747422EE5E,
		0xE018DA7492507A38,
		0x074285024F03AAB8
	};	k2 = (curve25519_key_t){
		0x3F264EA9886B3FB2,
		0xA704C8747422EE5E,
		0xE018DA7492507A38,
		0x074285024F03AAB8
	};	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x222106F45D6E8F9B,
		0x3BDE2FF1B6AF2A00,
		0xC84832562F9CD113,
		0xF160EDE655D1D35A
	};	k2 = (curve25519_key_t){
		0x222106F45D6E8FAE,
		0x3BDE2FF1B6AF2A00,
		0xC84832562F9CD113,
		0x7160EDE655D1D35A
	};	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x9C160423F311B46E,
		0x5B129EBA8C9A6F22,
		0x940D02BA69CA43CB,
		0x5524CC8D7380F675
	};	k2 = (curve25519_key_t){
		0x9C160423F311B46E,
		0x5B129EBA8C9A6F22,
		0x940D02BA69CA43CB,
		0x5524CC8D7380F675
	};	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x5B14EEEFD5AAF6EC,
		0xD0CC69F1D06C18AD,
		0x888453AD242012B0,
		0x4634CFCC1F9716DE
	};	k2 = (curve25519_key_t){
		0x5B14EEEFD5AAF6EC,
		0xD0CC69F1D06C18AD,
		0x888453AD242012B0,
		0x4634CFCC1F9716DE
	};	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x445313A5725A07BD,
		0x95A77655B601ADEC,
		0x9A490FC1F99544FA,
		0x50C21E3A2FE6FCC9
	};	k2 = (curve25519_key_t){
		0x445313A5725A07BD,
		0x95A77655B601ADEC,
		0x9A490FC1F99544FA,
		0x50C21E3A2FE6FCC9
	};	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA33F959C7EB57BC3,
		0xB249BA20E98C2004,
		0xF4D3EB3663C4CE99,
		0x2D39DCE26B3306EE
	};	k2 = (curve25519_key_t){
		0xA33F959C7EB57BC3,
		0xB249BA20E98C2004,
		0xF4D3EB3663C4CE99,
		0x2D39DCE26B3306EE
	};	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC65B0FB3FCB9E526,
		0x2FC396027CEC4334,
		0xFB93F3B974409CB0,
		0xA0D087DA12E2CC57
	};	k2 = (curve25519_key_t){
		0xC65B0FB3FCB9E539,
		0x2FC396027CEC4334,
		0xFB93F3B974409CB0,
		0x20D087DA12E2CC57
	};	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x45C910EBC081F1D2,
		0x8AD2571E643B85C6,
		0xC3E6F23F20A67F52,
		0x2011B349A63C9187
	};	k2 = (curve25519_key_t){
		0x45C910EBC081F1D2,
		0x8AD2571E643B85C6,
		0xC3E6F23F20A67F52,
		0x2011B349A63C9187
	};	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x9F4345C8C8792B1A,
		0x64BAFB148D9E9D41,
		0xEBED82B6177CCD43,
		0xFF93DF8CC04601BE
	};	k2 = (curve25519_key_t){
		0x9F4345C8C8792B2D,
		0x64BAFB148D9E9D41,
		0xEBED82B6177CCD43,
		0x7F93DF8CC04601BE
	};	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA6FA5BDBD1234625,
		0xB08902DC4F26AF28,
		0xEA1DDC3DD127BE8E,
		0x0A03DE295DDAE354
	};	k2 = (curve25519_key_t){
		0xA6FA5BDBD1234625,
		0xB08902DC4F26AF28,
		0xEA1DDC3DD127BE8E,
		0x0A03DE295DDAE354
	};	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x121967EBB88A7205,
		0xDAD03818B8715668,
		0x6B54FFFD0BE1BA16,
		0x02D58722C9ECA6B5
	};	k2 = (curve25519_key_t){
		0x121967EBB88A7205,
		0xDAD03818B8715668,
		0x6B54FFFD0BE1BA16,
		0x02D58722C9ECA6B5
	};	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC22663F17DE6E8C9,
		0xC5C278C248A833B6,
		0x7F1A32A136AF8BCD,
		0x16CF764C063CA003
	};	k2 = (curve25519_key_t){
		0xC22663F17DE6E8C9,
		0xC5C278C248A833B6,
		0x7F1A32A136AF8BCD,
		0x16CF764C063CA003
	};	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD62CEC3F83A2125F,
		0x3846AE1248BF7244,
		0x8CC79CECFFAFE1A5,
		0xB258478703A3EACA
	};	k2 = (curve25519_key_t){
		0xD62CEC3F83A21272,
		0x3846AE1248BF7244,
		0x8CC79CECFFAFE1A5,
		0x3258478703A3EACA
	};	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xCC40E3F273DD6059,
		0x95C3882FA280EA63,
		0x034C5DFBD135C900,
		0x62A868A53D197F1A
	};	k2 = (curve25519_key_t){
		0xCC40E3F273DD6059,
		0x95C3882FA280EA63,
		0x034C5DFBD135C900,
		0x62A868A53D197F1A
	};	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}