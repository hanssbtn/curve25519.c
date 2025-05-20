#include "tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x602344CF8F742FB1,
		0x0E9C86A96A01C5C9,
		0x8E70CFC34B996AA3,
		0x5EB28F723E5E2F82
	}};
	curve25519_key_t k2 = {.key64 = {
		0x602344CF8F742FB1,
		0x0E9C86A96A01C5C9,
		0x8E70CFC34B996AA3,
		0x5EB28F723E5E2F82
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
		0x1B2708F3D12027C4,
		0xF1B80845B77293A9,
		0x00CBE21432C2A52E,
		0xCF632B1847B2E3F9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2708F3D12027D7,
		0xF1B80845B77293A9,
		0x00CBE21432C2A52E,
		0x4F632B1847B2E3F9
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
		0x7617539B53D491B6,
		0x45868F74CC0F0742,
		0x62761050AFDEC443,
		0x5D479D806B1D1B2A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7617539B53D491B6,
		0x45868F74CC0F0742,
		0x62761050AFDEC443,
		0x5D479D806B1D1B2A
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
		0x3DAA59B448D5617E,
		0xCB5E213626554F76,
		0xC5F01DD85619CC93,
		0x305E26ECC7EE4F9E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DAA59B448D5617E,
		0xCB5E213626554F76,
		0xC5F01DD85619CC93,
		0x305E26ECC7EE4F9E
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
		0x3E7D14AD3BB73F4F,
		0x32430BDB2B033BCA,
		0x2B82211A38CB9328,
		0xC87A5AA1B31C8BDC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E7D14AD3BB73F62,
		0x32430BDB2B033BCA,
		0x2B82211A38CB9328,
		0x487A5AA1B31C8BDC
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
		0xC67F119BF7267187,
		0x4DFD198A5C352931,
		0xAC360EB318997EF8,
		0x7A0ACAE83E1FB944
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC67F119BF7267187,
		0x4DFD198A5C352931,
		0xAC360EB318997EF8,
		0x7A0ACAE83E1FB944
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
		0x9895983F7693661A,
		0xE321239EC163D1A2,
		0xAFE851C3C8AB4E16,
		0x4327417CB44429B4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9895983F7693661A,
		0xE321239EC163D1A2,
		0xAFE851C3C8AB4E16,
		0x4327417CB44429B4
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
		0xF0FF4BB3D245CCD9,
		0xDF23D0BFDB75B66B,
		0xD1F2022194EB610C,
		0x38784DCB0A892845
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0FF4BB3D245CCD9,
		0xDF23D0BFDB75B66B,
		0xD1F2022194EB610C,
		0x38784DCB0A892845
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
		0x22F1AFE496A62B57,
		0x228C96B5669AB77C,
		0x86AB926EF8E9F674,
		0xAB3E4BCD5799DED1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22F1AFE496A62B6A,
		0x228C96B5669AB77C,
		0x86AB926EF8E9F674,
		0x2B3E4BCD5799DED1
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
		0x92F48121F69D266E,
		0xA8FF477963A8B930,
		0x701955A0C3B836C2,
		0x59ACC6AE77AB7B7B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F48121F69D266E,
		0xA8FF477963A8B930,
		0x701955A0C3B836C2,
		0x59ACC6AE77AB7B7B
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
	return 0;
}