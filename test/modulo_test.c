#include "tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xB9FD4A5658AFE8AE,
		0x58AAEB252D80DE0E,
		0x195A827ABE1AC33B,
		0x4C278585736B6436
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB9FD4A5658AFE8AE,
		0x58AAEB252D80DE0E,
		0x195A827ABE1AC33B,
		0x4C278585736B6436
	}};
	printf("Test Case 1\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xFC977D87D00936B0,
		0x425EE51A44312F61,
		0xBA458B89747B7F38,
		0x56FEF5866B3B4502
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC977D87D00936B0,
		0x425EE51A44312F61,
		0xBA458B89747B7F38,
		0x56FEF5866B3B4502
	}};
	printf("Test Case 2\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xD519EB0042EA7672,
		0x349D3A83B234B399,
		0x676FCB4F85744831,
		0x42F5EE59B0376D92
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD519EB0042EA7672,
		0x349D3A83B234B399,
		0x676FCB4F85744831,
		0x42F5EE59B0376D92
	}};
	printf("Test Case 3\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x6FE8B7D2297A87A1,
		0xF6C6DC9D5CDBF81F,
		0x2FFF62284FEE176D,
		0x466A4763B80E1867
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FE8B7D2297A87A1,
		0xF6C6DC9D5CDBF81F,
		0x2FFF62284FEE176D,
		0x466A4763B80E1867
	}};
	printf("Test Case 4\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x42F8CD3717A4BBD2,
		0x2A64E7DE0062E571,
		0x3E07124A53F8BE48,
		0xBF047EAE1F5D947D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42F8CD3717A4BBE5,
		0x2A64E7DE0062E571,
		0x3E07124A53F8BE48,
		0x3F047EAE1F5D947D
	}};
	printf("Test Case 5\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x466E7CCEF89990BA,
		0x63012CA165C64998,
		0xF9F66C6AD7198741,
		0x9205F82E5BDB3013
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x466E7CCEF89990CD,
		0x63012CA165C64998,
		0xF9F66C6AD7198741,
		0x1205F82E5BDB3013
	}};
	printf("Test Case 6\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x3594F070524E641C,
		0x54C53ACC3369BEDC,
		0x3D0B65E6806E0C3A,
		0x8E9E62A1FAEF7079
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3594F070524E642F,
		0x54C53ACC3369BEDC,
		0x3D0B65E6806E0C3A,
		0x0E9E62A1FAEF7079
	}};
	printf("Test Case 7\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x76F89A06791E9BDC,
		0xB3231E197B91FFAC,
		0x5CD8FD8168888F29,
		0x98083A3E4D497AA8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F89A06791E9BEF,
		0xB3231E197B91FFAC,
		0x5CD8FD8168888F29,
		0x18083A3E4D497AA8
	}};
	printf("Test Case 8\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x21104B338E7CD510,
		0xB06B9E1046DFD7C5,
		0xE5768E3F2AD51100,
		0x64C262F5A54E9CDB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21104B338E7CD510,
		0xB06B9E1046DFD7C5,
		0xE5768E3F2AD51100,
		0x64C262F5A54E9CDB
	}};
	printf("Test Case 9\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xDD60A396BD3E581E,
		0x69C087ED2E861F89,
		0x8E315104EC6D830A,
		0x95E8019B2B24D551
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD60A396BD3E5831,
		0x69C087ED2E861F89,
		0x8E315104EC6D830A,
		0x15E8019B2B24D551
	}};
	printf("Test Case 10\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x8628BCD4A5798C34,
		0xF08F77E8669C9AD1,
		0x6D6F14A0F4CF5926,
		0xD5331C7CD309D66B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8628BCD4A5798C47,
		0xF08F77E8669C9AD1,
		0x6D6F14A0F4CF5926,
		0x55331C7CD309D66B
	}};
	printf("Test Case 11\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xAF8396CE54AE57CD,
		0x00A62911E229726F,
		0xFC7A1612C010A3EC,
		0xB2204983EF8C13DB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8396CE54AE57E0,
		0x00A62911E229726F,
		0xFC7A1612C010A3EC,
		0x32204983EF8C13DB
	}};
	printf("Test Case 12\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x2E09B06F516CBB0B,
		0xA40898CB808273A5,
		0x8626C3DA3E694604,
		0xAD124315B473D88D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E09B06F516CBB1E,
		0xA40898CB808273A5,
		0x8626C3DA3E694604,
		0x2D124315B473D88D
	}};
	printf("Test Case 13\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x2A087567C404354F,
		0x0BEB2CE0C5F9B2A3,
		0xFA1656D260F1D924,
		0x7BB79C07A17AFFBD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A087567C404354F,
		0x0BEB2CE0C5F9B2A3,
		0xFA1656D260F1D924,
		0x7BB79C07A17AFFBD
	}};
	printf("Test Case 14\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x6220CA372BF6229C,
		0x5B59F0D60206D4B2,
		0xD64AD1A72FE3FD36,
		0xF78D99DA7E8DB123
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6220CA372BF622AF,
		0x5B59F0D60206D4B2,
		0xD64AD1A72FE3FD36,
		0x778D99DA7E8DB123
	}};
	printf("Test Case 15\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x7A72AB15A8F3599B,
		0x1880211EC61C232A,
		0xE2E80A8F8EC22031,
		0xD09FAF34EB074FD2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A72AB15A8F359AE,
		0x1880211EC61C232A,
		0xE2E80A8F8EC22031,
		0x509FAF34EB074FD2
	}};
	printf("Test Case 16\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x9BA2258133636928,
		0xB05323F569CE5C8B,
		0xFC010701CD2BC83B,
		0xF6E901B51B61B00A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA225813363693B,
		0xB05323F569CE5C8B,
		0xFC010701CD2BC83B,
		0x76E901B51B61B00A
	}};
	printf("Test Case 17\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xC65A4D5E91BFFC63,
		0xD4798D4771634318,
		0x5A710A149FACA2E7,
		0xAD4A4434DE0C6AEA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC65A4D5E91BFFC76,
		0xD4798D4771634318,
		0x5A710A149FACA2E7,
		0x2D4A4434DE0C6AEA
	}};
	printf("Test Case 18\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x62878A101C8A6B5C,
		0x5CD7D2AB5A90620E,
		0x28DA4D1905499CFA,
		0xB20C90734C3EE7D7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62878A101C8A6B6F,
		0x5CD7D2AB5A90620E,
		0x28DA4D1905499CFA,
		0x320C90734C3EE7D7
	}};
	printf("Test Case 19\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xA636A84A1EEB5329,
		0xE6CA3425AB5E81AE,
		0x6FF12FDF814150CA,
		0x04BCE3B12C78510F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA636A84A1EEB5329,
		0xE6CA3425AB5E81AE,
		0x6FF12FDF814150CA,
		0x04BCE3B12C78510F
	}};
	printf("Test Case 20\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x99F10871547B938C,
		0x0182FB5CABA68E8C,
		0x295F617181A7696C,
		0xDF11BE25B124EBB7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99F10871547B939F,
		0x0182FB5CABA68E8C,
		0x295F617181A7696C,
		0x5F11BE25B124EBB7
	}};
	printf("Test Case 21\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x6A3A0345BC6C0D06,
		0x12DEDB6370463174,
		0xDDE732BE69C0A13B,
		0x4F793DE2ACD2C30E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3A0345BC6C0D06,
		0x12DEDB6370463174,
		0xDDE732BE69C0A13B,
		0x4F793DE2ACD2C30E
	}};
	printf("Test Case 22\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x5A21F3472DF5BA2E,
		0x08ACB917B3865EA2,
		0xA343B5239B64F832,
		0xABCE80939F14EBDC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A21F3472DF5BA41,
		0x08ACB917B3865EA2,
		0xA343B5239B64F832,
		0x2BCE80939F14EBDC
	}};
	printf("Test Case 23\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xDC2376E93507A960,
		0x72767F1B4B0213A6,
		0xE7586D7A46B20ED4,
		0x81928C3572EF93EF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2376E93507A973,
		0x72767F1B4B0213A6,
		0xE7586D7A46B20ED4,
		0x01928C3572EF93EF
	}};
	printf("Test Case 24\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xF678267EE7CA72BD,
		0xC4E1A95A7C0245F6,
		0xF6D87BB8E7CE3684,
		0x333BC020CAF6EADF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF678267EE7CA72BD,
		0xC4E1A95A7C0245F6,
		0xF6D87BB8E7CE3684,
		0x333BC020CAF6EADF
	}};
	printf("Test Case 25\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x867486F0F8FC73BE,
		0xEB90D32892DD439B,
		0xC6ABF4537553F050,
		0x80CDBFF2E2CD188C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x867486F0F8FC73D1,
		0xEB90D32892DD439B,
		0xC6ABF4537553F050,
		0x00CDBFF2E2CD188C
	}};
	printf("Test Case 26\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x6F47EDF46D24CDE2,
		0x36D4685B093BC92C,
		0x18E48E0DC0D86277,
		0xB34B49B7326AE483
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F47EDF46D24CDF5,
		0x36D4685B093BC92C,
		0x18E48E0DC0D86277,
		0x334B49B7326AE483
	}};
	printf("Test Case 27\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x93DD60C85CB03DD7,
		0x5E5B84C585C8F6D7,
		0x7F69DEF2A6E540D0,
		0xE14B773998FC5744
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93DD60C85CB03DEA,
		0x5E5B84C585C8F6D7,
		0x7F69DEF2A6E540D0,
		0x614B773998FC5744
	}};
	printf("Test Case 28\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x18A80F274F5FD4CA,
		0x24F6F7198F817CFE,
		0x40D7401D954A7FDB,
		0xAA7A2A2FBCE25C21
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18A80F274F5FD4DD,
		0x24F6F7198F817CFE,
		0x40D7401D954A7FDB,
		0x2A7A2A2FBCE25C21
	}};
	printf("Test Case 29\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xBD386ACE5190BD61,
		0x091C252D4B9A8EE5,
		0xA5A60DE750109799,
		0x69CEA12964E5C796
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD386ACE5190BD61,
		0x091C252D4B9A8EE5,
		0xA5A60DE750109799,
		0x69CEA12964E5C796
	}};
	printf("Test Case 30\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x80F12A783756026D,
		0x81C2828100A81A9B,
		0x0F5D555471D8E5FD,
		0xC0DB8BD1C4C15065
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F12A7837560280,
		0x81C2828100A81A9B,
		0x0F5D555471D8E5FD,
		0x40DB8BD1C4C15065
	}};
	printf("Test Case 31\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x3517CC0D6F407BEE,
		0xCD7DBD56F2F8F4F9,
		0xC3C8937185042E2A,
		0x28B97D394692CC13
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3517CC0D6F407BEE,
		0xCD7DBD56F2F8F4F9,
		0xC3C8937185042E2A,
		0x28B97D394692CC13
	}};
	printf("Test Case 32\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x094397F70EBB7340,
		0xB8F018A2487D93A9,
		0xAC2384A35E1F00A9,
		0xDAE51EEFA47C7B28
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094397F70EBB7353,
		0xB8F018A2487D93A9,
		0xAC2384A35E1F00A9,
		0x5AE51EEFA47C7B28
	}};
	printf("Test Case 33\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x2633E6FB5F9FE9EE,
		0x16E5A4EBF86E6636,
		0xD287A5EA6DF190FD,
		0xA15098EDB88F70A3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2633E6FB5F9FEA01,
		0x16E5A4EBF86E6636,
		0xD287A5EA6DF190FD,
		0x215098EDB88F70A3
	}};
	printf("Test Case 34\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x20F13AFD66B13683,
		0xF29D442F03696D28,
		0xF17EB35118908F10,
		0xE837C2A6D40EAAC4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20F13AFD66B13696,
		0xF29D442F03696D28,
		0xF17EB35118908F10,
		0x6837C2A6D40EAAC4
	}};
	printf("Test Case 35\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xE564468CE17037A5,
		0x877E53415AEACC3B,
		0xFFC8729DB9E5C1E2,
		0x467AE731547961F4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE564468CE17037A5,
		0x877E53415AEACC3B,
		0xFFC8729DB9E5C1E2,
		0x467AE731547961F4
	}};
	printf("Test Case 36\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x5E1E7A6E5EA3674C,
		0x49B8CF1AE95E0C8D,
		0x1B7BCFE4972CF5FF,
		0x25319D988868BB3C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E1E7A6E5EA3674C,
		0x49B8CF1AE95E0C8D,
		0x1B7BCFE4972CF5FF,
		0x25319D988868BB3C
	}};
	printf("Test Case 37\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xEEC17A0C37034698,
		0xC3E72086190E1222,
		0xCCA78BD3727B9464,
		0x9DA1072148F9AB7C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC17A0C370346AB,
		0xC3E72086190E1222,
		0xCCA78BD3727B9464,
		0x1DA1072148F9AB7C
	}};
	printf("Test Case 38\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x2FD480B506156BB9,
		0xB96CD4DABF9A7D77,
		0xB0229B3D0478DA06,
		0x65AC62071EC958E4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD480B506156BB9,
		0xB96CD4DABF9A7D77,
		0xB0229B3D0478DA06,
		0x65AC62071EC958E4
	}};
	printf("Test Case 39\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xE92ED7A6D2CF2A0C,
		0x2056EF308BF3299A,
		0x027A8F3503E09C94,
		0x8885E89A2BA1E0B9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92ED7A6D2CF2A1F,
		0x2056EF308BF3299A,
		0x027A8F3503E09C94,
		0x0885E89A2BA1E0B9
	}};
	printf("Test Case 40\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x94C203BFDAA3107B,
		0x523BE837445E7AB6,
		0x16D4FB2F1FF2FC83,
		0x06A6CC768578073C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94C203BFDAA3107B,
		0x523BE837445E7AB6,
		0x16D4FB2F1FF2FC83,
		0x06A6CC768578073C
	}};
	printf("Test Case 41\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xDC6BA3FCF30BBB01,
		0x1CDB4E27002F9888,
		0x9F0827A5C90990B8,
		0x7F6D52371CCF7136
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC6BA3FCF30BBB01,
		0x1CDB4E27002F9888,
		0x9F0827A5C90990B8,
		0x7F6D52371CCF7136
	}};
	printf("Test Case 42\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x8F4F94C2F0876A00,
		0x2DEA4C03E4C325A6,
		0xFDCAB61CC7259C82,
		0x9E1F108C946C6860
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F4F94C2F0876A13,
		0x2DEA4C03E4C325A6,
		0xFDCAB61CC7259C82,
		0x1E1F108C946C6860
	}};
	printf("Test Case 43\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x8E61036366EC826F,
		0x519501163717C25F,
		0x331B02957E7D4538,
		0x740495043D0C90C5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E61036366EC826F,
		0x519501163717C25F,
		0x331B02957E7D4538,
		0x740495043D0C90C5
	}};
	printf("Test Case 44\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xD50720D2EC15728E,
		0xCDCD3BA20A64380B,
		0xB1ED9B4D141195B1,
		0xC284BF99CA3673DF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50720D2EC1572A1,
		0xCDCD3BA20A64380B,
		0xB1ED9B4D141195B1,
		0x4284BF99CA3673DF
	}};
	printf("Test Case 45\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xC5FD929270F209D2,
		0x426947E4703E98D4,
		0x0C3473E9C7DDE5E5,
		0x4CD44E19146D71E5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5FD929270F209D2,
		0x426947E4703E98D4,
		0x0C3473E9C7DDE5E5,
		0x4CD44E19146D71E5
	}};
	printf("Test Case 46\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x1E54C152C6E1439E,
		0x9B14303D3EC89DBC,
		0xEB6DBD54F3DAB649,
		0xE97AD6B1E1F47CC2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E54C152C6E143B1,
		0x9B14303D3EC89DBC,
		0xEB6DBD54F3DAB649,
		0x697AD6B1E1F47CC2
	}};
	printf("Test Case 47\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x407626B5ECBCAFA4,
		0x0471A950874B58AF,
		0x1311BD8EE6BA465A,
		0xFEB542B818862D10
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407626B5ECBCAFB7,
		0x0471A950874B58AF,
		0x1311BD8EE6BA465A,
		0x7EB542B818862D10
	}};
	printf("Test Case 48\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xA26BF2E46358581A,
		0x62AEC4F172726464,
		0x2554D7C8B92C0A0D,
		0x2FB6EFAF57747AFE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26BF2E46358581A,
		0x62AEC4F172726464,
		0x2554D7C8B92C0A0D,
		0x2FB6EFAF57747AFE
	}};
	printf("Test Case 49\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x77FF56FA56733190,
		0x26A2299AF40158BC,
		0x1557AB7BE95175FB,
		0x371CD446616838BC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77FF56FA56733190,
		0x26A2299AF40158BC,
		0x1557AB7BE95175FB,
		0x371CD446616838BC
	}};
	printf("Test Case 50\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x3DB0DE74E563BF35,
		0x8923388315A12370,
		0x5AC775FD4E7D64C4,
		0xE8A7D59883CFAFDB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DB0DE74E563BF48,
		0x8923388315A12370,
		0x5AC775FD4E7D64C4,
		0x68A7D59883CFAFDB
	}};
	printf("Test Case 51\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x21B4617FA0310221,
		0x8BC754D43C00795D,
		0x829DF8B1DACC09DC,
		0xD15389FD2EBB4419
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B4617FA0310234,
		0x8BC754D43C00795D,
		0x829DF8B1DACC09DC,
		0x515389FD2EBB4419
	}};
	printf("Test Case 52\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x720B459B230D3D2F,
		0x456A0E0C4DC683B4,
		0x0BD1AA3499C4CD1A,
		0x38AC61920BED39C0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720B459B230D3D2F,
		0x456A0E0C4DC683B4,
		0x0BD1AA3499C4CD1A,
		0x38AC61920BED39C0
	}};
	printf("Test Case 53\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x42C270FCD115C11A,
		0xB36A8A266296C76C,
		0x6AAC429A8CE50D37,
		0xAFF6B51115B58C1D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C270FCD115C12D,
		0xB36A8A266296C76C,
		0x6AAC429A8CE50D37,
		0x2FF6B51115B58C1D
	}};
	printf("Test Case 54\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x8A8DB761ED530412,
		0xE38BB8E07E17DFF6,
		0x6EE73B1BA70C3B33,
		0x15B3958194017D62
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A8DB761ED530412,
		0xE38BB8E07E17DFF6,
		0x6EE73B1BA70C3B33,
		0x15B3958194017D62
	}};
	printf("Test Case 55\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x4DCEB54CBBDE4B09,
		0xFB27C3175B2B69BC,
		0xE1A59B1B287E1791,
		0xC929971D907AA714
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCEB54CBBDE4B1C,
		0xFB27C3175B2B69BC,
		0xE1A59B1B287E1791,
		0x4929971D907AA714
	}};
	printf("Test Case 56\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x4FA050FC6D185F52,
		0xADA628E9B99E5134,
		0x90F478C263677D34,
		0xA3ABD8D2253F5D12
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FA050FC6D185F65,
		0xADA628E9B99E5134,
		0x90F478C263677D34,
		0x23ABD8D2253F5D12
	}};
	printf("Test Case 57\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xA86B96D98E301BB4,
		0xC7A6EB66C7FCDE49,
		0x5A3C2EB198E86308,
		0xC53134E04D79BA4E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86B96D98E301BC7,
		0xC7A6EB66C7FCDE49,
		0x5A3C2EB198E86308,
		0x453134E04D79BA4E
	}};
	printf("Test Case 58\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x4CD4353E1F902F05,
		0xB31B5716822EAF53,
		0x84D68E855235F4D9,
		0xC224F0A668F686AD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD4353E1F902F18,
		0xB31B5716822EAF53,
		0x84D68E855235F4D9,
		0x4224F0A668F686AD
	}};
	printf("Test Case 59\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x41DECC7688744788,
		0xC7988E7CE84F68DE,
		0xFDC089C55D5405DD,
		0x3C698376C4E1C5FA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41DECC7688744788,
		0xC7988E7CE84F68DE,
		0xFDC089C55D5405DD,
		0x3C698376C4E1C5FA
	}};
	printf("Test Case 60\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x106BAECF09AF7203,
		0x6DD3984A687B5B88,
		0x1CAD3406E5756DD3,
		0x64C69DD52BE415CA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x106BAECF09AF7203,
		0x6DD3984A687B5B88,
		0x1CAD3406E5756DD3,
		0x64C69DD52BE415CA
	}};
	printf("Test Case 61\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x6CD684FB4F07D883,
		0x4AA4B9DD97E4A8EB,
		0x7853327D11A4294E,
		0x7D41FA5993EA6524
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD684FB4F07D883,
		0x4AA4B9DD97E4A8EB,
		0x7853327D11A4294E,
		0x7D41FA5993EA6524
	}};
	printf("Test Case 62\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x36826680DCEC42A1,
		0x2006DE3D614BCF4A,
		0xD93E7107492273F4,
		0x56EA73CDC6D42405
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36826680DCEC42A1,
		0x2006DE3D614BCF4A,
		0xD93E7107492273F4,
		0x56EA73CDC6D42405
	}};
	printf("Test Case 63\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x83246C2685968AF8,
		0x2329DEF500637E9D,
		0x7262483F27B81928,
		0x657B59EAA4913E2D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83246C2685968AF8,
		0x2329DEF500637E9D,
		0x7262483F27B81928,
		0x657B59EAA4913E2D
	}};
	printf("Test Case 64\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xA25446E50983DE8B,
		0xB12A66473962DACA,
		0x9AAEAEA7E7BF08A3,
		0x74F5D9C9F31F4B31
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25446E50983DE8B,
		0xB12A66473962DACA,
		0x9AAEAEA7E7BF08A3,
		0x74F5D9C9F31F4B31
	}};
	printf("Test Case 65\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xEF1F56C8B7CC818A,
		0x1BF3C9389D9B103A,
		0xE26D272A4717B719,
		0xA17736462681216C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF1F56C8B7CC819D,
		0x1BF3C9389D9B103A,
		0xE26D272A4717B719,
		0x217736462681216C
	}};
	printf("Test Case 66\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x5AEE169DAC825FE4,
		0x18970E29F1B28295,
		0x6B0D15BCFF97A841,
		0x1D8083CAF36C17CB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AEE169DAC825FE4,
		0x18970E29F1B28295,
		0x6B0D15BCFF97A841,
		0x1D8083CAF36C17CB
	}};
	printf("Test Case 67\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x01028544D4268AAF,
		0xDEDDB55A94B55DA3,
		0xD2D4A7A4E1000E2F,
		0xD3C176EAA1C3D863
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01028544D4268AC2,
		0xDEDDB55A94B55DA3,
		0xD2D4A7A4E1000E2F,
		0x53C176EAA1C3D863
	}};
	printf("Test Case 68\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x1E5D62365D20F5E9,
		0x05C063E2CFC307E1,
		0x7424AA885B67CD06,
		0xC555D5073B6877CC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5D62365D20F5FC,
		0x05C063E2CFC307E1,
		0x7424AA885B67CD06,
		0x4555D5073B6877CC
	}};
	printf("Test Case 69\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x43238CE1557A403A,
		0xE7C40E15A3F09A3F,
		0xB911946AAEFB24A6,
		0xFDC8CC02F5218FC1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43238CE1557A404D,
		0xE7C40E15A3F09A3F,
		0xB911946AAEFB24A6,
		0x7DC8CC02F5218FC1
	}};
	printf("Test Case 70\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xBB0F473476E5DB82,
		0x3AD0E0560A7501DE,
		0x60A05BA80F03C3E7,
		0x2E372AB8FA7665D3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0F473476E5DB82,
		0x3AD0E0560A7501DE,
		0x60A05BA80F03C3E7,
		0x2E372AB8FA7665D3
	}};
	printf("Test Case 71\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x582F3452DFCC7D82,
		0xD0EB92B99BEA8628,
		0x206120B352A653BD,
		0xBA6B67366B7EEBE4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582F3452DFCC7D95,
		0xD0EB92B99BEA8628,
		0x206120B352A653BD,
		0x3A6B67366B7EEBE4
	}};
	printf("Test Case 72\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x85EAC219E47424F8,
		0x7EA967E32766B08C,
		0xC42EF9C0B3965794,
		0x0D40FEE010C37598
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85EAC219E47424F8,
		0x7EA967E32766B08C,
		0xC42EF9C0B3965794,
		0x0D40FEE010C37598
	}};
	printf("Test Case 73\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x1B0C8C0308A4618D,
		0xBA5CDEDB78451FF0,
		0x252467BC695E4C3C,
		0xA6EAB4A013DE5CD5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0C8C0308A461A0,
		0xBA5CDEDB78451FF0,
		0x252467BC695E4C3C,
		0x26EAB4A013DE5CD5
	}};
	printf("Test Case 74\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x4E6055E6199A05C4,
		0x03BDA82B344718BE,
		0x4997DC64B121BC8A,
		0xFEA7940A77C17695
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E6055E6199A05D7,
		0x03BDA82B344718BE,
		0x4997DC64B121BC8A,
		0x7EA7940A77C17695
	}};
	printf("Test Case 75\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x2AECECA711F39F28,
		0xECA6945A6E89F820,
		0xD9427896C6EA92F4,
		0xD0D9461A197CF880
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AECECA711F39F3B,
		0xECA6945A6E89F820,
		0xD9427896C6EA92F4,
		0x50D9461A197CF880
	}};
	printf("Test Case 76\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x89B344C2C647CD82,
		0x30453EBDCBC18487,
		0xED8386080251D7DE,
		0x66732645B36F909E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B344C2C647CD82,
		0x30453EBDCBC18487,
		0xED8386080251D7DE,
		0x66732645B36F909E
	}};
	printf("Test Case 77\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x413654383B13EC0D,
		0x105953EDF6240A87,
		0xE0B3610EB8BE2AC5,
		0xB70249248EAB15AA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x413654383B13EC20,
		0x105953EDF6240A87,
		0xE0B3610EB8BE2AC5,
		0x370249248EAB15AA
	}};
	printf("Test Case 78\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x0ED11065C1A90410,
		0x0E6E2BA1A3A2EE2E,
		0x4020662F1A2B49CD,
		0xCA923D6F83360509
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED11065C1A90423,
		0x0E6E2BA1A3A2EE2E,
		0x4020662F1A2B49CD,
		0x4A923D6F83360509
	}};
	printf("Test Case 79\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xE1C4112F19F339A8,
		0x28424DE74B8E139D,
		0x6536B1F6B82D04DC,
		0x2C19370DEE1411FC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C4112F19F339A8,
		0x28424DE74B8E139D,
		0x6536B1F6B82D04DC,
		0x2C19370DEE1411FC
	}};
	printf("Test Case 80\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x29119A300BFDF103,
		0xC6AC69F10AB3989E,
		0x73206902D239A1DD,
		0x63BEE8BB4A841ECC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29119A300BFDF103,
		0xC6AC69F10AB3989E,
		0x73206902D239A1DD,
		0x63BEE8BB4A841ECC
	}};
	printf("Test Case 81\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xF7BD4C49600FEED7,
		0xB717FF5113E1879E,
		0xF918E3BDE1CAB915,
		0x88497FC1F37C7856
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7BD4C49600FEEEA,
		0xB717FF5113E1879E,
		0xF918E3BDE1CAB915,
		0x08497FC1F37C7856
	}};
	printf("Test Case 82\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x36248E0D7BC26845,
		0x75678F8DA43865C8,
		0x93E145DED4F3AB92,
		0x8757C16B7EDF1B8B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36248E0D7BC26858,
		0x75678F8DA43865C8,
		0x93E145DED4F3AB92,
		0x0757C16B7EDF1B8B
	}};
	printf("Test Case 83\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xC4C58C2E93C892F3,
		0xCC138E799EBCC07B,
		0x8CF8033330F0A6C8,
		0x233FF98F89E1ED78
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C58C2E93C892F3,
		0xCC138E799EBCC07B,
		0x8CF8033330F0A6C8,
		0x233FF98F89E1ED78
	}};
	printf("Test Case 84\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x2F30850CC3408868,
		0xCB2A9DC7826C4F72,
		0xE49404DE1886D967,
		0x2B2469291D3065CF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F30850CC3408868,
		0xCB2A9DC7826C4F72,
		0xE49404DE1886D967,
		0x2B2469291D3065CF
	}};
	printf("Test Case 85\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xADC7DF8888945106,
		0xA19BEF52EE9E46B7,
		0x69A1E8EA1958C20E,
		0xFD10D5B831320094
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC7DF8888945119,
		0xA19BEF52EE9E46B7,
		0x69A1E8EA1958C20E,
		0x7D10D5B831320094
	}};
	printf("Test Case 86\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x1F75843D4866A315,
		0x68D5F24EBE7326FC,
		0xBC199A1AF118CC35,
		0xC5B94B9BF2C12BC2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F75843D4866A328,
		0x68D5F24EBE7326FC,
		0xBC199A1AF118CC35,
		0x45B94B9BF2C12BC2
	}};
	printf("Test Case 87\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xBB35B049A53FFD18,
		0x1AEB4E2E92CBEF13,
		0x98D37F3577718DD0,
		0x401F5DF3B7D34D17
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB35B049A53FFD18,
		0x1AEB4E2E92CBEF13,
		0x98D37F3577718DD0,
		0x401F5DF3B7D34D17
	}};
	printf("Test Case 88\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xD8CADECBEE2C4358,
		0xFA45D9B3114BA852,
		0x8CE79BBB493A63A6,
		0x385C972354539BFB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CADECBEE2C4358,
		0xFA45D9B3114BA852,
		0x8CE79BBB493A63A6,
		0x385C972354539BFB
	}};
	printf("Test Case 89\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xED5C4D1FD9104737,
		0xE88015DF338405D0,
		0x95B3652B6C68D152,
		0xCD341DC290630860
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED5C4D1FD910474A,
		0xE88015DF338405D0,
		0x95B3652B6C68D152,
		0x4D341DC290630860
	}};
	printf("Test Case 90\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xF5121418E3C34566,
		0x092063D45A45FB3C,
		0xBD799387DCE2CCB8,
		0x27697BC1E501EF14
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5121418E3C34566,
		0x092063D45A45FB3C,
		0xBD799387DCE2CCB8,
		0x27697BC1E501EF14
	}};
	printf("Test Case 91\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xF7B269BB9596D1D6,
		0x2C45D149CFD9C60C,
		0x9491BDD96CE0563C,
		0xDA4EDF6CBEB5D52E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B269BB9596D1E9,
		0x2C45D149CFD9C60C,
		0x9491BDD96CE0563C,
		0x5A4EDF6CBEB5D52E
	}};
	printf("Test Case 92\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xC8E9B6A344272131,
		0x0DBB1562BC7849E3,
		0x183625DFC7DC00DD,
		0x31A8187C3E4F6E8B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E9B6A344272131,
		0x0DBB1562BC7849E3,
		0x183625DFC7DC00DD,
		0x31A8187C3E4F6E8B
	}};
	printf("Test Case 93\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x8630566CB2886B63,
		0x6A92221411F09E97,
		0xEB4B068E827679C8,
		0xAE0243A4D14A52DF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8630566CB2886B76,
		0x6A92221411F09E97,
		0xEB4B068E827679C8,
		0x2E0243A4D14A52DF
	}};
	printf("Test Case 94\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x08CA35827AB3ADA0,
		0x7BB1EBD092F4E516,
		0xB8567F056BFCA699,
		0x186CA9F0452F73C9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08CA35827AB3ADA0,
		0x7BB1EBD092F4E516,
		0xB8567F056BFCA699,
		0x186CA9F0452F73C9
	}};
	printf("Test Case 95\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xA04FFCA36215CCD7,
		0x7DD9A3569B159F4A,
		0xC4B11F56D09FCA2E,
		0xC305F8582DA3E7B6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA04FFCA36215CCEA,
		0x7DD9A3569B159F4A,
		0xC4B11F56D09FCA2E,
		0x4305F8582DA3E7B6
	}};
	printf("Test Case 96\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x3B7C3950B01B7A0F,
		0x030991FE0B67C78C,
		0x55C7BA45ABF90508,
		0x3C79AF0148D812DC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B7C3950B01B7A0F,
		0x030991FE0B67C78C,
		0x55C7BA45ABF90508,
		0x3C79AF0148D812DC
	}};
	printf("Test Case 97\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xA3E6AD5ADAF6901F,
		0x4CB6DA84D3DF93AE,
		0x4C557DD76C8B35DA,
		0xC01AD8D7D74883B0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3E6AD5ADAF69032,
		0x4CB6DA84D3DF93AE,
		0x4C557DD76C8B35DA,
		0x401AD8D7D74883B0
	}};
	printf("Test Case 98\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0x5DD41BC75365CDF8,
		0x02BD03563D2119EF,
		0x843DE97A837BB53A,
		0xC928C62310C5A32A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD41BC75365CE0B,
		0x02BD03563D2119EF,
		0x843DE97A837BB53A,
		0x4928C62310C5A32A
	}};
	printf("Test Case 99\n");
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
	k1 = (curve25519_key_t){.key64 = {
		0xCE51D261D3C8FE1E,
		0x63C9AAAFE740D746,
		0x4575C91265A23D5B,
		0x3520E635295836CB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE51D261D3C8FE1E,
		0x63C9AAAFE740D746,
		0x4575C91265A23D5B,
		0x3520E635295836CB
	}};
	printf("Test Case 100\n");
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