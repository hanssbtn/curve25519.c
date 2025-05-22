#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6CA923920EAC9B76ULL,
		0xAC6127B1341D798FULL,
		0xF7E3EBD39384389BULL,
		0xD1023AD2F31FE0DAULL,
		0xD296AAB4258FD87DULL,
		0x7413A148BDF0E153ULL,
		0x8E12ECD4CC58AC21ULL,
		0xC0E1E33DC23767C6ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xAF067A4FA206C252ULL,
		0xE74B187D65DEEC00ULL,
		0x0EB31369E8ADC592ULL,
		0x7289F5FDC7594854ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB6E4AC4B9EDD7432ULL,
		0x4F62CC1ECD4B9346ULL,
		0x5432C11BAF9B6BA1ULL,
		0x6DB94DAF6F4ED6B0ULL,
		0x9C01F68B56A4B6C6ULL,
		0x5557E48252D0D2D7ULL,
		0x587F4377273D3F9DULL,
		0xAC2CE2D76D12C850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF2F44FA7B50995FULL,
		0xFA6EB777184ADF47ULL,
		0x7716C4CB82B2DCFBULL,
		0x7C62F9A9A018929DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x73940AE8DDC1241AULL,
		0x45BBCC39B61F110AULL,
		0xD2757EA4D90FB311ULL,
		0x10CE9107A9E50D76ULL,
		0x6F1CA16A6809E188ULL,
		0xA9C4ACDAC3B25965ULL,
		0xDCBFF1A203368E82ULL,
		0xBDFDC5BA046D1E9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1D400B44F38A272ULL,
		0x78ED74B2C2985618ULL,
		0x96F35CB15328DA76ULL,
		0x4479EAA452179931ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x944DA1FA40C0D2F6ULL,
		0x986D010CA7416AC6ULL,
		0x45492623EAD42F2AULL,
		0x4209CF98446898D3ULL,
		0x23AB3AE314402178ULL,
		0x70D5F2283A0F25CDULL,
		0x7C9C8A3A9A6916C0ULL,
		0x3FB3665D17AD352AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB85FAF4245CC2FULL,
		0x582EF30545810739ULL,
		0xC485AAD6D66D8FBBULL,
		0x36AB0169C81E7D21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4BE1781A4DEDF228ULL,
		0xAC113F811D438691ULL,
		0xEA1DA63BED87D7E6ULL,
		0x7C190A05599C68EFULL,
		0x66C117337122AA78ULL,
		0xD3EB70078650898FULL,
		0x51508ED7180D7810ULL,
		0x4A742934A2294AFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C8AE9BD191341ADULL,
		0x2103E09F0D37F1DAULL,
		0xFC12DA297F87AA66ULL,
		0x095727D56BBD8A17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1233F153EED8646EULL,
		0xE71A93F3C7E4734DULL,
		0xA851C4D7BB2A011AULL,
		0xDF89A09C429186DDULL,
		0xCA0ACEC4BCA0F7BAULL,
		0xDEE8F5F92C2F1CA7ULL,
		0x2A3FACFC766E9943ULL,
		0x207FAB7081C78EE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FCEA287EEBD2ADBULL,
		0xFDAF16F056E2B435ULL,
		0xEDC572514F94C12DULL,
		0x327D134F8630BCE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF05843137F5EFEEDULL,
		0xB8C5BFC18BFD1550ULL,
		0x5577B55A7C09070BULL,
		0xCEED231C226B6F56ULL,
		0x6845AAF7AB97A406ULL,
		0x243B222D939C19CBULL,
		0x566EDD55D6C2125FULL,
		0x6A408FA48329092FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAFA3D6F7E15A44ULL,
		0x198CD2857528E982ULL,
		0x29EC90185CD7C12BULL,
		0x148275879A82CC5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD7C3DCE2C550F258ULL,
		0xE28225ABE8BE437FULL,
		0x48739E8859E5D3B2ULL,
		0xA82EA45F1EEA3613ULL,
		0x0F64698E130AC6FAULL,
		0x35DDE9F22AB976F2ULL,
		0x2FCA2B7BE20249C7ULL,
		0x017BEA9B8B162535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20AB87F998EA7B87ULL,
		0xE172DF9E4045EB6EULL,
		0x607612EBE63CC744ULL,
		0x60937775C433BBF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB4A04B72EEF76529ULL,
		0xA5C18B4FDE82A477ULL,
		0xAA3DFE9EE93777EFULL,
		0x6A3E9F0D88B34704ULL,
		0xD0E4DB2B1FA8B10DULL,
		0x035DE3443EB034D3ULL,
		0x63E7FA1FF1AADB6AULL,
		0x1AECF03B62B34F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB698D3D9A201ADAFULL,
		0x25B147712CAA7BE8ULL,
		0x7EAD1F5CC89409ACULL,
		0x696A47DE2F510703ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEC4D1269EAA8FDFBULL,
		0x9BD1DA74C6AC7DD6ULL,
		0xA0761991C4A68959ULL,
		0xF51F7E01498F875BULL,
		0x7E97FDE90B1D2E1AULL,
		0x05C625FDEC37F435ULL,
		0xE4E1B76DCBAA580BULL,
		0x315D95A7976B6E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6DCC30190FDD707ULL,
		0x773B7E25D6FABDC7ULL,
		0x99F753DDFFEF9AFCULL,
		0x4903B4E1C381F20DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5F2A11DE9B8C6D4FULL,
		0xA5483EFB2D023DBEULL,
		0xEDD281B05921F93AULL,
		0xCA9E15F050EE2F7AULL,
		0x47DA01592068A025ULL,
		0x70CAAFD23F65A921ULL,
		0xB72E0D2395200EADULL,
		0x4E78C0941EC86195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x098645196B143495ULL,
		0x635E5830961958AFULL,
		0x1EA874F87BE426F9ULL,
		0x708AABECE2ACABB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6DC7456E325E9772ULL,
		0x28E3C90DE123602FULL,
		0x6A8A41A84A825288ULL,
		0x1B2DE32DF594957CULL,
		0x800B9CDBE04960EDULL,
		0xCD3F329FB93E7415ULL,
		0xC5A7F3E8A2080F8DULL,
		0x2FDD5941D3CDEB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F808E117D42FBAAULL,
		0xA0454CC360689B60ULL,
		0xC178763057B4A194ULL,
		0x360922F366257EDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF1C4E7D8726C182AULL,
		0x587150179E62D9CDULL,
		0xD153439F28F54504ULL,
		0x8585CCFCFF14DD49ULL,
		0x179978A4A8DFD90EULL,
		0xD93C61C5131DBA17ULL,
		0x991BE66347ED703BULL,
		0x001CC12F02EDAB4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728CD04983A65051ULL,
		0x9767D35874CC793BULL,
		0x8B77765BD633EDE6ULL,
		0x09CA79F76E5C4A5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4A60A2CF127D7DF0ULL,
		0xF663C3FE49E43317ULL,
		0xC3895BA4A0B750C3ULL,
		0x1718A5F3FD1010CDULL,
		0x840EA31ACF9CEDEDULL,
		0xBA412549BC5142E5ULL,
		0x8DD8A3E4690357A8ULL,
		0xB200092B3F9951AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48CD8C9E3C8D30DULL,
		0x9C0F4CF03DF42128ULL,
		0xD1B1AF8C373653CFULL,
		0x031A025F6DD230B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x91BF119A0905569CULL,
		0xA682640558C8FDA3ULL,
		0x1561297CAC269A6FULL,
		0x74F2CACEB0932141ULL,
		0x6CA7E3D2619FA3B9ULL,
		0x57C08105C76B5CEFULL,
		0x47D69BFF23C788EDULL,
		0x86AE408E77E1AB77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AAE2D486B7A70AULL,
		0xAD158AE0F2B8C92DULL,
		0xBF3C515BFBC4EDAAULL,
		0x72D05FF47C1294F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2D79BCD5A1E611BBULL,
		0x284F01D510239FE4ULL,
		0x3AA271A93968C9B2ULL,
		0xF9A2DFD4D5CA2B3EULL,
		0x546242C0F045C808ULL,
		0x0C5022AD8D49D205ULL,
		0x6EA81619B15C839FULL,
		0xD7C66C4684F696BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB40FA5794C41C7D1ULL,
		0xFC3427980918CCAEULL,
		0xA795B9798D24534DULL,
		0x0116F24C92648B5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x620977C5833B63DCULL,
		0x52B3FF3635844381ULL,
		0x4FE6B7D9F57DF0E0ULL,
		0x0EA210D114C6578AULL,
		0x480772A7E84F5B64ULL,
		0x8B68659E808FB5D8ULL,
		0x484713AE6A507417ULL,
		0x2DC49B064023BB50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13247CB1FF02F5ABULL,
		0x043314BD4AD9419CULL,
		0x0A73A3BDBD6F2C5FULL,
		0x59D113BE9A142575ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1FFCE53683DF7880ULL,
		0x3F1CCDC305AECC7EULL,
		0x2979CFDD41B214A6ULL,
		0x7597D109EEA2E1AFULL,
		0xF0A1C755B537AC09ULL,
		0xF9390B7BA835D17AULL,
		0x5FB144A2A61D8EB8ULL,
		0xCE914A2BD06FC9D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8007BEF6A230670ULL,
		0x3D94821DFDABE4BDULL,
		0x5DCA0001EA15441BULL,
		0x1F28D38ADF3AD7A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9FFE40FC2B7E8577ULL,
		0x2811C9472ED17FD1ULL,
		0xB06A63E714C6ACF0ULL,
		0xDD6A6B9AB0502E0CULL,
		0x4EB6B728C0619FFAULL,
		0x171F7E870027E28EULL,
		0x64078621DF542DC5ULL,
		0x38CFDF519A92E65AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F1D7108B9FC45E9ULL,
		0x96BE915134BD20F1ULL,
		0x89884CEE3B457831ULL,
		0x4C4591B7A21E5F77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8E43155109AB8379ULL,
		0x40C9E3385C74E1D8ULL,
		0x16C7D5A1AC42C7F4ULL,
		0x8471920D13EE6F1CULL,
		0xF78685F62C97C4EBULL,
		0x93EA1F86CCBC538CULL,
		0x0F21325F8395BFACULL,
		0x1381A45A964B8130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3AF7DBA832BECDULL,
		0x358A913AC06948C5ULL,
		0x55B54FCF347D3B92ULL,
		0x69AFF77F63239C3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE116C1B84D8425BDULL,
		0xFE4706BBB2A8E8D5ULL,
		0x30BF10D92E767A2BULL,
		0x716E1994BFA70D89ULL,
		0x557768D6C9C3A448ULL,
		0x2EA858E1188B62C5ULL,
		0xBFF0E15583D205B3ULL,
		0x21EF1A64310612ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D0519A408E892BULL,
		0xEB44382557599220ULL,
		0xAE80838ABFA352C4ULL,
		0x7AEC0474068DDCADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB3BAAC8DCC831B9AULL,
		0xA2C934CA3A68DA49ULL,
		0x5361E782D76895BDULL,
		0x589EF0DB2190BA86ULL,
		0xB343B68D5BE0B6A0ULL,
		0x64E7268D078353F3ULL,
		0x1AB0B69819F234DCULL,
		0xE76A89CC1A9BAD04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC7C5896FDE3C79ULL,
		0x9D18EDB957E75076ULL,
		0x499D0216B15C6E74ULL,
		0x326F652714AC6922ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x75AD4D58B604895AULL,
		0xB1FE12E43DB37B4CULL,
		0x8252A85ABA1F8272ULL,
		0xB6421266D4876259ULL,
		0x2F392E2D934BB6A9ULL,
		0x072C5DA33E709032ULL,
		0xD530FE1C2F433BD9ULL,
		0xE94299ED949ED173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x782A281C9341ABA2ULL,
		0xC293F91F8268E2BFULL,
		0x27986089BE1A64A9ULL,
		0x5624EBAAE41A798BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCD69FA873AB86E2BULL,
		0x7BA3FF193EED097FULL,
		0xC7A41C3EBC24AD45ULL,
		0xA33DD5F0FF63BA18ULL,
		0xB6EBE5F74DBAB25EULL,
		0x37F4EDCD3B19D98DULL,
		0xEC9DB89A6CA5F3D6ULL,
		0xCCC3AB700B3D05C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF46E1D3CC46EECB9ULL,
		0xC9FF4B9004C35488ULL,
		0xE70D832ADCC6DF11ULL,
		0x08494892AA7295EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x05AC520D3D91638FULL,
		0xDEEF8525150749EDULL,
		0x20BBB32CFC674E5EULL,
		0xF6CF1C95D5CE9752ULL,
		0x8C7AD42D51276AF8ULL,
		0x9EE635F274F6E058ULL,
		0xDA3B73B8C08A3F9AULL,
		0xBF0814F72AA22301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE7D0C7496B48ADULL,
		0x751B872271AC9711ULL,
		0x858EE09990ECBF52ULL,
		0x5202394629DFC998ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x42AF80B307E12E95ULL,
		0x4C11F8D65C9ADB0DULL,
		0xC6E57E162ED39037ULL,
		0x2CD69FBE72884DBBULL,
		0xFCDADE891255E019ULL,
		0xB66762EA95002B26ULL,
		0x11C9CE2ECA90E1E7ULL,
		0x83725A2BFE9C26ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB2C890BC0A07530ULL,
		0x5F6AA7A87AA142D6ULL,
		0x6ADA19084055189CULL,
		0x2FD002463DB60B6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9B88316A14D5D68CULL,
		0xE78B4AA5FCB130F0ULL,
		0xB9F3F9867E522FE6ULL,
		0x8CFF3D4CAAC8045BULL,
		0xBBCD7692A65E6D59ULL,
		0x67E532DEED552BF3ULL,
		0x1BBBEFFCD45869EFULL,
		0x63125FA0239580A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C07CB2EC6DA13FCULL,
		0x5390D7BD3755B71EULL,
		0xD7D9990E0371E970ULL,
		0x41B96F11F2F91CDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x643028CF34241726ULL,
		0x4CA5F0884CFA9462ULL,
		0x0546CD361E6AFC92ULL,
		0x74F17A21F35745F1ULL,
		0x113ED3FFED6ABD9AULL,
		0xD03B0619BD4ACEDBULL,
		0x4ADEFAF6D3A44D5FULL,
		0xCE9CD98D4D229789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF383A0CC71FC409CULL,
		0x3568D85A661548E6ULL,
		0x22600DD988CE78CBULL,
		0x2039C51B6679C452ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xACCC88F7B2266623ULL,
		0xC87F2FBDD262246DULL,
		0x1A38BFF388C99A56ULL,
		0x5C5963951337281BULL,
		0xFD08832283D4B1BCULL,
		0xBC803091CE6F049AULL,
		0x962246EFBF735A6EULL,
		0x458B2C1AC5AC18B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C10001743B8C99AULL,
		0xC386656276DCD36FULL,
		0x634F4789F3E906C6ULL,
		0x2F01EF8E6AC2D381ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x684939643D9E9265ULL,
		0x179378281CA4E316ULL,
		0xFC4A7F4A5AB343A9ULL,
		0xF528FB05C70BBEB8ULL,
		0x1D217208044AF318ULL,
		0x4F450D0CBC916AC4ULL,
		0xBBA888280AD49109ULL,
		0x894EBCDEDD539B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB402694E0BEAB13ULL,
		0xDBD3680C1A3ABC32ULL,
		0xD74EB53BF640CB0AULL,
		0x56D9041AA174C4D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEA9759FA38C78BECULL,
		0x0D8D1F9C80BD221EULL,
		0xE66E611FED4DB28BULL,
		0x4C258512B6FFE019ULL,
		0x3DFC7806CD82CED4ULL,
		0xC3D76DD62F5B7284ULL,
		0xFE814CDCEEB9F821ULL,
		0xADBA2B0ECDE7D393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E112AFCBA324340ULL,
		0x1F876D67885021C0ULL,
		0xAD9FC9EB5CE8878EULL,
		0x15C7E94547694811ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x630A0A7517591953ULL,
		0xA576C0E71F1619EAULL,
		0xDE023C1BA515A58CULL,
		0x7B491D45473F6254ULL,
		0x479F7A2F418A3F3BULL,
		0x6CD09E1D67DFB9D8ULL,
		0x680CFEB90B176A95ULL,
		0x4BB05BFFF302B6AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B62D78D1DE7DCAULL,
		0xCC6E39448A4BB005ULL,
		0x4FF00B934A8F77BAULL,
		0x3776C54359A67FA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x89172089B1A7307DULL,
		0xAF32A2CA0C6C90FFULL,
		0x75668A272846464BULL,
		0x9151778FEFF0B3D2ULL,
		0x1F452A431B10E3C5ULL,
		0xBCDDB91639FA5862ULL,
		0xD569DDE35D2F4842ULL,
		0xBCE7E1E579854286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D5B667FB62903F6ULL,
		0xB81C1C16A795AF90ULL,
		0x231D79E6FD4B0033ULL,
		0x1BBCFF9FF9B893D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4445D73D385BDF21ULL,
		0x2099EB44A0EF230EULL,
		0x862CDE87E16EEF97ULL,
		0x2E3620920B1D841DULL,
		0x1E75B913AC42A7DDULL,
		0x48C67377FB4C8289ULL,
		0xDBBAA7539104E941ULL,
		0x96F7265A8F8C89CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9BF5028CA40CD46ULL,
		0xEE0F0F13EE4A8368ULL,
		0x23E1B4EF68298F47ULL,
		0x16E5D20359F9F8D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x11FB2205EBA5D08DULL,
		0xB0A0B897F4292EE9ULL,
		0x1D6E85F5C24CFD16ULL,
		0x2CDAB0E1B4A6901FULL,
		0x9E33D8A01853A50BULL,
		0x84215A50733982BFULL,
		0x56BE006CD6C9620DULL,
		0xEAE99B118BAF216FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DAD49C988105561ULL,
		0x4D9420890EB2975AULL,
		0xFDA2961DA4318B18ULL,
		0x0B87B57C70A586A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3FB0EFEBD7739133ULL,
		0x862FEFB2083AB88CULL,
		0x991B37D1F76353E4ULL,
		0xB8CA72AE6080273EULL,
		0xA661C25B61E4E823ULL,
		0xC9EEAED75898071AULL,
		0x424BDEE6B5EACD3FULL,
		0x66496E82B45704EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF233C97C5F6E08B2ULL,
		0x7F9DE3A92ECBC680ULL,
		0x705E4E10F83DCB5CULL,
		0x67B0DA15256AE22AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCFEE731976FCE905ULL,
		0x4D95983E1D7551BBULL,
		0x21DE1C1B327992F5ULL,
		0xD6214DA495A6752DULL,
		0x3A281CC1F0E8CCE0ULL,
		0x72F3FCD07A5E7CCDULL,
		0x755AC1ADC1DD66B4ULL,
		0x7CDA809F623A6671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E2B7E3398B5517ULL,
		0x5DCD1F30477BD832ULL,
		0x8D56DBE5F956D1BEULL,
		0x5E90654D2A51AA04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x820653AC8FF481C9ULL,
		0xFCA26B4F257E9AF9ULL,
		0x5670EA6DF5371D67ULL,
		0x1DE0C2DC4D4ECA55ULL,
		0xCF4133AED21C28ABULL,
		0x0D4C72E754C9DE41ULL,
		0x73056D20C07C556EULL,
		0xB0F8FADA93E2FF7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B3FF9FC0228F07ULL,
		0xF5FB79A5BB7598BEULL,
		0x693F1D4A87ABCBBDULL,
		0x62D5FF4E4100B71AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD2F4A77A97008EFFULL,
		0xAC6465E9F96FD35CULL,
		0x040FEB7DC656A6FEULL,
		0x39CA26062AD359DDULL,
		0x24243D87127FBFD7ULL,
		0xB78849D6C64E86E0ULL,
		0x35846571DFBFC224ULL,
		0x26448A4EC84CC274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3055C98755F709BAULL,
		0xEA9F5BCB6917D8A2ULL,
		0xF5B6FA64FCCD7871ULL,
		0x67F6ADB7E638371CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x46137720F051C97EULL,
		0xFFF2D7652B12BFE5ULL,
		0x76B21AC9B8B67DE0ULL,
		0x4EE12534336EC4C0ULL,
		0xD08CFEA46B103E23ULL,
		0xBF993C782EEB855EULL,
		0xF4443D5BFEF238E2ULL,
		0x4A58FC1E7436DABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B014388D4BB0452ULL,
		0x70B1D13C22088BF8ULL,
		0xB8D3367190AAEF89ULL,
		0x581691B973933CCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3E0316C9A3E7DEDCULL,
		0x23469FC2259FB8BAULL,
		0x9963E2BC9BEBABF0ULL,
		0xC9E6FF351D6FCF3CULL,
		0x89C8576AD4A34AD7ULL,
		0xF284F7C66D167D54ULL,
		0xEB6906F643FD6F63ULL,
		0x796F46DED8F40CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C010A53424FD85ULL,
		0x2303673656F65346ULL,
		0x8AFAEB4AB38A34C6ULL,
		0x506B844951A9BB97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDBAEF4E45AFF00A2ULL,
		0x71479057BA28F285ULL,
		0x60516D0F72937172ULL,
		0x422476C44BF8238CULL,
		0x44A3C9C1D75C78EFULL,
		0xA10AD86558C4EFF0ULL,
		0x61D8C274F9F80BC8ULL,
		0x2F8D22B65CDEC102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BFEE7AA52B8F526ULL,
		0x58E3AF62E7649030ULL,
		0xE67E4A6C8D65313AULL,
		0x51179DD61508C9E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC6488411726FFBA7ULL,
		0xD9BEE683FFFF239EULL,
		0x9E5C23C67E7C5BA3ULL,
		0xEB765DC4659A7A80ULL,
		0x136C3963BCE2FA48ULL,
		0xE733F161D58346E4ULL,
		0x5099AB071BEC401CULL,
		0xBCE1DEE334783F7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA85908DF7C212692ULL,
		0x2B74BB09B17BA979ULL,
		0x952B86D4A38DDFEEULL,
		0x74FD737E2F73E740ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9D1A4B7C9E271C56ULL,
		0x7D11A08C41A2A612ULL,
		0xFD48C429C850F23CULL,
		0x2C8E093E33504E10ULL,
		0xA4C203CECA40F549ULL,
		0x960A4C413DFFA347ULL,
		0x7F91F73C36CB3573ULL,
		0xBD01325987556A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E6DC2EA3CB8954ULL,
		0xC298F23B7594E2B5ULL,
		0xECF37719EA7AE164ULL,
		0x3ABB828849FE214BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAF8C8BF6D7643C34ULL,
		0xD0E4D20C3174EA8AULL,
		0x545E35132BED8E05ULL,
		0xB25BED87CB24B809ULL,
		0xECC6C1086C07F96FULL,
		0x7A299552E931FDB6ULL,
		0x5FB849BF518859ABULL,
		0x017D2A84A711DC90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50D3336E09342C1ULL,
		0xF310FC5ACEE093B1ULL,
		0x89B92779462ADD79ULL,
		0x6AF03D3897CB7577ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x98E7C18D1539FDB9ULL,
		0x6D47AB909AC49229ULL,
		0x7D8AC3AB5440F664ULL,
		0xD08BB2133FFEB29FULL,
		0x1B65F79D6B71F0B4ULL,
		0xF79D8DC0C48ECFE5ULL,
		0xEDF783A909FCE919ULL,
		0x3211911B154A52A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA0A82EB0823B9A1ULL,
		0x2EAAB62DC7F76E2BULL,
		0xD0484EC2CFCB903FULL,
		0x3F273C186906F7B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8B54155E28135EB7ULL,
		0x9B925D9CD823115EULL,
		0x922632B0942611C6ULL,
		0x327F2DD9891D2C22ULL,
		0x922CD2C2CE0C715FULL,
		0x264F70B82A397F1EULL,
		0x7F52E379B997C6BAULL,
		0x84642113EBF348FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DFB5E48BDEC35B6ULL,
		0x4B5D18F31CABEFE8ULL,
		0x7873F6C220AD9168ULL,
		0x595C16CE8F3A020FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEE017B4C186DC90FULL,
		0x2E2A14EC77722FDFULL,
		0xDF26C668FCE8E217ULL,
		0x38F39B4318C1125AULL,
		0x321AEA234028DC0FULL,
		0xEA2785C42C5B4049ULL,
		0x122BA75BFC47496CULL,
		0x26EB061B58B02C2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E003C879E7E741AULL,
		0xF007F00B0CFDBABDULL,
		0x91A19E106F7DC841ULL,
		0x7FD6835242E7A099ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x33DDBDA49AD27F34ULL,
		0xF5C742643A8A064CULL,
		0xF44AA86D2F715461ULL,
		0xEC72A0FEB5F649E1ULL,
		0x099CC184B6944F2DULL,
		0x82A37BCEA288A033ULL,
		0x17566E8509E3DA77ULL,
		0xFE2C24E24A060C68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1227757B4D64599ULL,
		0x5A0BA3105AD1CDDFULL,
		0x6B1F102CA743C21FULL,
		0x27001A95B2DC2155ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF444CD2379AE0DA2ULL,
		0xB00AF69DA5F21E0AULL,
		0x2A4808B9B4557439ULL,
		0x83B7E2477C2A6211ULL,
		0x7B2ECEA98380E5A9ULL,
		0x22C86113623F65E3ULL,
		0x9FBD2C0053D1020AULL,
		0x4246E466B53D4DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D377A4CFED02634ULL,
		0xD9C95F7E3B5B3DCFULL,
		0xE05C90C6255BC1BAULL,
		0x5A3DC9866343EA22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x99059A4C0BF8930CULL,
		0x4025CCA75295EF6FULL,
		0x2C812D8A70E6E497ULL,
		0x9E2A085E5FD5C294ULL,
		0xA87096BCCDC23879ULL,
		0xB02A7BDEF79D646AULL,
		0x91650C2B996BD511ULL,
		0x01588DC4307868A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99BBFA5296CCF515ULL,
		0x66742FC013F2D744ULL,
		0xC180FC0336E88537ULL,
		0x514F137D91B54BBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD63BD4527CA2E647ULL,
		0x801F9CA691A23804ULL,
		0xA8623CB123C845B3ULL,
		0x0DF4B68B6BE8285AULL,
		0x12D636DBD271F005ULL,
		0x46CACD7E2F89504AULL,
		0xF7B97F256DF20719ULL,
		0x509E61683972577CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA207F8F3B98C88CDULL,
		0x023A1D61A0042303ULL,
		0x6DEB1C3F75B55374ULL,
		0x05772C03F2E124E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBBC6690942400C9AULL,
		0x86B80F66CA3A02D9ULL,
		0xC15A5F9C7AF4BC10ULL,
		0x0A752F3A134AE231ULL,
		0x85CD98A2382B5471ULL,
		0x085C67ABCAC4CB69ULL,
		0x7B0FC3DD669449E2ULL,
		0xD3087E27D1E00A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984B111D98AE99FAULL,
		0xC46F72E6E3703483ULL,
		0x05B17279B4F7B39DULL,
		0x5DB7E9233A8C6B7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9D36E6A288F68D97ULL,
		0x83ABD4B3AC21120CULL,
		0x98C06CE353A8ED5CULL,
		0xFFAEC449FB4FC133ULL,
		0x85CBE7FA3DA03DF9ULL,
		0x56C12110519BA099ULL,
		0x64CD9819E68DB6A1ULL,
		0xF26C82EDFBD8A1F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x797B55C7AEBFC5F8ULL,
		0x6456BD1FC93AE8D6ULL,
		0x8F4500BB8CB2094FULL,
		0x7BCA339D5D77CB54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x44BC6268B527634FULL,
		0x0253ED45CA1BFD24ULL,
		0x93F18B0798D860BFULL,
		0x6BE549BF88857DA5ULL,
		0xF9A67B658AF6B9B5ULL,
		0x9588A8301C754384ULL,
		0x40FD4DEE3365E691ULL,
		0x36BC973A2B98A09AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5372B37B55C6F570ULL,
		0x349CE46A038402E1ULL,
		0x398B1C6339F89A5BULL,
		0x0BE3BC62012D548BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x081C27BE6926E006ULL,
		0x531EA9C53EF0C674ULL,
		0xD8281AD19D626A0EULL,
		0x2179A8F3A7150576ULL,
		0x777BBA91F12405C8ULL,
		0xFF064578571ED461ULL,
		0x24ECA41FBAF2EE03ULL,
		0xCE4F42976C959EF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC479D968347FC03DULL,
		0x2E0CF9A22D844CEBULL,
		0x534877875D71BEA6ULL,
		0x413D8B6DC54A9E72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEAA6EF5646A17FC7ULL,
		0xF1D93CE66332519BULL,
		0x5B4D4671DE33F547ULL,
		0x094ED7CDC251CA07ULL,
		0x87EFC266142B81A5ULL,
		0xBF0691A7456054D2ULL,
		0xF2A8158147E5D466ULL,
		0x1556B92F509FF4C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x183DCA7D4516BEB7ULL,
		0x4CD2DBBAAF7EE8DCULL,
		0x604077A28A517C88ULL,
		0x342E54D3BA101F43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE71988D4B0A6C049ULL,
		0x30C6334E2E1EBE74ULL,
		0xB4194B397F900960ULL,
		0xB1AD967BB09958C7ULL,
		0x7A9AACE18792899DULL,
		0x71E4D2A8A90C10B7ULL,
		0x03E424774CF46B1AULL,
		0x287543DCDF023B7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A0F324ED0672E8EULL,
		0x18BD785745E939B1ULL,
		0x47F6B4EEEBD7EF4DULL,
		0x3315A944CAEE2D0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x44E1E51A0087B690ULL,
		0xAC51B8C20A8A73F7ULL,
		0x8C78A9FA5FC48EA5ULL,
		0x906D3682AEE87047ULL,
		0xE40A8B53E7626017ULL,
		0x42F74D374F219267ULL,
		0x6ECC2698973302FEULL,
		0x9DE89194142AA746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E72938E5921FD8AULL,
		0x9D072EF7C9862F63ULL,
		0xFEC664A0D1570063ULL,
		0x00F2D27DAD3D44BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDFB7480FF233962AULL,
		0xF9E793D5479CEF29ULL,
		0x829F1D0F5847425EULL,
		0x9992D745418626CEULL,
		0xB7423B036CCB39FEULL,
		0x1E498E99C0083A1FULL,
		0xF331115516879BF1ULL,
		0xB3437F6BB1B73085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x138C0A92185E35E0ULL,
		0x78D2BEA7C8D58FDFULL,
		0x9BE7AFB0B0686829ULL,
		0x3597C141A2B75AB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA8B5D637464D04FFULL,
		0x13D639B57F73107FULL,
		0x662C8A65FD0F70ACULL,
		0x946D80B1CBCFD2BCULL,
		0x248F5FC6E9AF0175ULL,
		0x4A45611D102402DCULL,
		0x1AAECE6AD1599705ULL,
		0xB4D183463588FC8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15FE0DBDF647405FULL,
		0x1A22A405E4CB7D2DULL,
		0x5C1F2E41105BDB75ULL,
		0x6B86FD1DBE254F62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xADBAEB7DAA5F87AAULL,
		0xAD7AFA39D37D2F58ULL,
		0x67ADDC549D64C73BULL,
		0xACB103FCEC63934CULL,
		0x5D3DF03BF8DA05A6ULL,
		0x4C116745DEE841B8ULL,
		0xF5A9191F9D23250CULL,
		0xAB226DB74D9C65FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84EC94649ABC622AULL,
		0xF8104E98E9F6F0B6ULL,
		0xDEC79705F09C470EULL,
		0x13CD4D32719AB6FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x88FFAA5B8880305FULL,
		0x4CE11A9E3FA6ACF0ULL,
		0xA9A390661CF7200CULL,
		0xA7006AE51936EA07ULL,
		0x2B852051DB0BA392ULL,
		0xFF0661BFC42303BBULL,
		0xBAD0912FC9D77D08ULL,
		0x6BCEB9007B68999CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC276820C3A7A7EULL,
		0x27D39D155CD93AB8ULL,
		0x64991D7E12F3AF62ULL,
		0x27AFE0F76ABDB74BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC32EA174AED930D5ULL,
		0x605CC2BD1F8EE045ULL,
		0x56A55B8FF76C85A1ULL,
		0x2CEF34468833F4C9ULL,
		0x5865B9B904911456ULL,
		0xD5739BC9921CDFC8ULL,
		0xB35BD86764EE2642ULL,
		0x58AD3B6A545B0C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE24832EB5C623787ULL,
		0x0F85E2A8CFD81802ULL,
		0xF6477AE8F2C6338DULL,
		0x56A6060F0DB7CD11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8B9A0CD3FC4EF8F0ULL,
		0x7B5B02254308655CULL,
		0x26426BDF090C5059ULL,
		0xE5CD129BAE1168E6ULL,
		0xE08926B9D7AEFB17ULL,
		0xAC7DEC3E97480436ULL,
		0x930EE40268A356A6ULL,
		0x5F8A947C666C6EF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF5CC6A00484094ULL,
		0x160C136FB7B90581ULL,
		0xFA78443A914B2D17ULL,
		0x145F1D12E229E133ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x301F9A5E570E833CULL,
		0xAFD803693CC39F88ULL,
		0xC4E42261F5064BE0ULL,
		0x2E0E55252421D319ULL,
		0xDC3BA47DC51166D4ULL,
		0x6063EEBDBECAB35EULL,
		0x4CFE49FED8626136ULL,
		0xF2B3041E49D2B40AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0FA050997A3CC0CULL,
		0xFEAD73938EDA3F9CULL,
		0x32A31E3613A0B9F2ULL,
		0x34A0F1A419688CA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5C358DCAF7C93718ULL,
		0x65CF38FD5DDCDBA8ULL,
		0x5F0AD207CD19FE04ULL,
		0x02D9D17B97CDDDF5ULL,
		0x08E0011616DEB8ECULL,
		0x7F9614C5D62271ADULL,
		0xB0DD87CF1C9F2FDFULL,
		0x7C6D42894CFFDE5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD75B7125CD8ACCCULL,
		0x56164E5B26F9BB57ULL,
		0x9FECFAC60CBB1931ULL,
		0x7B11B1DD05C8E029ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC8E3CC6A8E70DE60ULL,
		0x1BB96C762F527229ULL,
		0xB34DB63CF415DD14ULL,
		0xAC7AEA4C8F60B849ULL,
		0x25E00D58DFF9EE54ULL,
		0xDCF5D3F5A85F4764ULL,
		0xBDB40EF2C6846A13ULL,
		0x623F4CC5EA1519D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6825C79BCD8A4112ULL,
		0xE836E2ED2D770B07ULL,
		0xDC07EE466BBD9C06ULL,
		0x41E04FAD4E828D45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5770004F5C3B8F56ULL,
		0x10605495DF064651ULL,
		0xFDE7BEAF49928046ULL,
		0xED92D12199394C31ULL,
		0x867A71A36F795E85ULL,
		0xA98995B48560E830ULL,
		0x5CB0611B0CB5F089ULL,
		0x7B14B66A50ACD77FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9CDE91E83F99E6ULL,
		0x3ACC8D61AB68BD85ULL,
		0xC01628B32C9434B5ULL,
		0x32A5E4E992E14919ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD245E6FC39EC428CULL,
		0x8801BDEAD38AE881ULL,
		0xEBD3A926151FF8F5ULL,
		0x142C5B874BEF957DULL,
		0xD76EF14162DA7391ULL,
		0xA529B0CC5ECFA406ULL,
		0xA725209A3F264C38ULL,
		0x307D43A261537ADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCBDB6B0E6596B1CULL,
		0x0C31FC40E65D4185ULL,
		0xBB56800B74CF495EULL,
		0x46C465A1BE53D264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x66CDBAB8C58498DEULL,
		0x33BE61ED9BA59AF9ULL,
		0x6E59AFCC49D653CEULL,
		0xDA6097BF528F0571ULL,
		0x2D4708155F20828EULL,
		0xB9A1DFA68816DD4FULL,
		0x8C94EE53873A49C7ULL,
		0x212693952D90F54BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F58EDE4E457FAC3ULL,
		0xC1C594A5CF0A74BAULL,
		0x4C7510325C7D4773ULL,
		0x461A7FE416136EA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF9B8EE7F140D4907ULL,
		0xAB5BF41B5DBB7B5EULL,
		0x0B8DFA87D9D04410ULL,
		0xB0AFFD26FB8529FAULL,
		0xD166BBFF6B5A5BE9ULL,
		0x9C8F409E7CFB467EULL,
		0x672A41C40A3848D5ULL,
		0x743CE0730A87CB57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF8D6690376F036ULL,
		0xE89F8BA1EB07F232ULL,
		0x5BD3BDA15E2B13C5ULL,
		0x71B94E3A8BAD58F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x077530F5D9602D89ULL,
		0x8CB98F790849E2E2ULL,
		0xE9C76980405B0FFBULL,
		0x8166EE2B5095F7BCULL,
		0xC428205AF68E9CC9ULL,
		0xA14582576B40BC23ULL,
		0x45DCEC8E7C52A8DBULL,
		0x4A4D0CDA5CF247CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2569FE76728B7514ULL,
		0x7D0AE872F3E5D031ULL,
		0x489286A6B4A02095ULL,
		0x08D6D6951C8CA00FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5456666875E58FAFULL,
		0x61069565D6F5C4CCULL,
		0x09BF3AF3D5D12241ULL,
		0x6B9BFAE68C458696ULL,
		0x752CD89C0BA25C9FULL,
		0x0845138B550BD886ULL,
		0x8CF11CAA21F5448FULL,
		0x8068A0B438E2CA6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8FE8D922FFF521BULL,
		0x9B477C1476B7E8C1ULL,
		0xF5897C34E0394F7CULL,
		0x7B23D5A6FDEF9324ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2C706A354E1FBA94ULL,
		0x3163A32A67F2811BULL,
		0xDDE3B79DD2D505A4ULL,
		0x7316EACE678BFAA5ULL,
		0x0286A570C44607DEULL,
		0xF1F346008D9634D0ULL,
		0x91671EBA4A1DBE58ULL,
		0xF66BC814EDEA6237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C6CF8F27084EB06ULL,
		0x1B80073F6C3E57FBULL,
		0x73324744D33F46D8ULL,
		0x07169DE9B8568EE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x225B6B8C24B1D91CULL,
		0x578E9A62FD652046ULL,
		0x86370328D94B303EULL,
		0xF65C911820EEB903ULL,
		0x6B0F42734D7E3A4CULL,
		0xBBDB7B8EA8EE3E94ULL,
		0x119585917B468B18ULL,
		0x7963954F10F677E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x069F48A9A56E8323ULL,
		0x3A22F19010C26A4EULL,
		0x2268D6C125C3D5EAULL,
		0x7B24BAD4A5848576ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x78F248F5B6B48C47ULL,
		0x38DB84DCF32DBD0EULL,
		0x79F2906690D18FE8ULL,
		0x4C6DE67530180E72ULL,
		0xA2A388D22DD1F98CULL,
		0x5831CDA41C8B11DDULL,
		0x848ECA9AB337E6CDULL,
		0xAA205DAAB97B2252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D38982883DF9AD8ULL,
		0x50400B392FD263F4ULL,
		0x2724A35D2B1DD263ULL,
		0x0D3BCDCCB85F26B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x13A3C1A44274626CULL,
		0x350A25545B457B13ULL,
		0x636F2E892C49A75BULL,
		0xCFF906202B36D95DULL,
		0x5EE8E606E05998BEULL,
		0x8F9E9CB0E9363A2AULL,
		0x755BA7EAA2266268ULL,
		0x472959CF12836B53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A35E6A98FC11042ULL,
		0x86956796F9521D5DULL,
		0xCF0A1B5D3DFC42E0ULL,
		0x601C5ADCEAB8C7C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x13FDFA1D206CB3B1ULL,
		0x8EAC9CEE79C2433DULL,
		0xE1C6D86B64CD98BDULL,
		0xEEE56210931A8273ULL,
		0x4E687BC376C8CE37ULL,
		0x698D57F973EB0E14ULL,
		0xCCCF3D4F3874D56AULL,
		0x70F182E069C45F5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7805920C23B5274ULL,
		0x39A7ABF5AEA65A40ULL,
		0x4889F22DC6254689ULL,
		0x32BECF604640AA60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x062EFB4AE69D0582ULL,
		0xEC112BFEFBD59222ULL,
		0xC408A900E62774A2ULL,
		0xC337711A2298179FULL,
		0xF3B924FED1838CFDULL,
		0xA55F7140692F589EULL,
		0x919AB5AE37840984ULL,
		0xA788D0820C6758BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33AA791E0023F6D9ULL,
		0x783BFB8E98DCB9BAULL,
		0x60FFA0DD23C0DE53ULL,
		0x21866467F9EF43E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x80ADC9920957CD1AULL,
		0xA967E3D81AF3F98DULL,
		0x72FB4111C55175DEULL,
		0xC1A197B66E4BED33ULL,
		0x89B5F6CB4F5EF76FULL,
		0x0257CA95F22269DFULL,
		0x79E01C077D7671F2ULL,
		0xF18A7F4D484FF8D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B06BBFD1708CFFULL,
		0x026FF61A0C0FB0BBULL,
		0x8A3F6A2E64E65FCBULL,
		0x1C307D2F2A2ADD7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x170DAB9A412E74FBULL,
		0xCDC434DAA0A4F184ULL,
		0x83E9C43D9ED9EF8CULL,
		0x3A470D71848E1C77ULL,
		0x75978B7F6D5A262CULL,
		0xF1E90A2AA3EFD1F6ULL,
		0x5EF4AEB7A69E9A57ULL,
		0xC2E7766D09469FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8C60847C9023D1ULL,
		0xB65BB72EF63E1C19ULL,
		0x9C3BB3805A64D89AULL,
		0x28A2A1A0E509DC13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8D2847A21370CA97ULL,
		0xC1B41568EEADC005ULL,
		0x9E8F4651F32DFD6CULL,
		0xED394B89B8258F83ULL,
		0xDC60877B15EE791BULL,
		0x35B6C4167FF244D1ULL,
		0x915FED927BBC8EBEULL,
		0x4824BC1B531741DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437C63E754D6C64EULL,
		0xBAD530BFECA3F72CULL,
		0x32CC8A10512B2DA8ULL,
		0x22AD37980D9956B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE5DC49C1FCDCE903ULL,
		0xA24F9B9B1E4BF167ULL,
		0x6A02B383597C0079ULL,
		0x31ED197EB1883740ULL,
		0x28ACC799A8813DE7ULL,
		0x1AB3CE66D12EDB2BULL,
		0xBD7A3341A7BCF61DULL,
		0x4E72649FE0F12017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF81EA91000C1B02ULL,
		0x99003EDE2B4079CFULL,
		0x8A264F423F8888CBULL,
		0x56E8093A1552FAC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x242D15CE16DB923FULL,
		0xF1066C0D7BC14C24ULL,
		0x32F0B61CAE0D23E5ULL,
		0xBE5C8318A3D87FE5ULL,
		0xB40B7233BE45E720ULL,
		0xFBAD879E504091ADULL,
		0xFF5797E2E5B4060AULL,
		0xD5C7FBE1EA719514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDE0097C553BE5BFULL,
		0x4CC88D8D6556EBECULL,
		0x19F141CAC6C60987ULL,
		0x7A0BE6A170B4A103ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA34C10D759C95548ULL,
		0x88FF659CA0EE0712ULL,
		0x5526C70BC8A8102EULL,
		0x4864A15AFF3AF569ULL,
		0x7E2A0310A82C4C42ULL,
		0xCED1466D76DDCDA6ULL,
		0x43CAD073B254D425ULL,
		0x2639E15F306ABE6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D888550505CA7E5ULL,
		0x3C0FD9DC45DA8DC9ULL,
		0x6541B838413F8DCBULL,
		0x74FC157C2F133955ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6BE6EACEA79C35C6ULL,
		0x7BA8D7A4F27D4299ULL,
		0x67FEBEF3017601E5ULL,
		0x336C54742F3510E5ULL,
		0x94E0C387BC5306F7ULL,
		0x4E20349CD3C65465ULL,
		0x76CC728AFDB1AB94ULL,
		0xF8061047539A7170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8543F0F49BEF43EEULL,
		0x1470A6EC61EDC9ADULL,
		0x0A57BF94A9D579E9ULL,
		0x0452BF0A9821E797ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDD445A56AF4E7A43ULL,
		0x946A555266B60867ULL,
		0x12ABE295D78E71E1ULL,
		0xFC2CEC3300726D00ULL,
		0xF6980D60202109A5ULL,
		0xF72F7B32298ECB19ULL,
		0x57351A745811B27BULL,
		0xA18A3D349841427EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D6569B7435EC64ULL,
		0x45769EC491E82E42ULL,
		0x048DCFDAEA2EF048ULL,
		0x76B202019A224BC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x22415FB507389F88ULL,
		0xB52E61CE20253561ULL,
		0x2329CA60EC0473FDULL,
		0x50AAE296C8EF81D5ULL,
		0xDB90E75CFF84CFB5ULL,
		0x22DB88869B40AC4BULL,
		0x6CB751A18AA48E06ULL,
		0xE7BDA1497D92D7EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C3B782F4EF7985ULL,
		0xE1C4A5C92BBEC8A3ULL,
		0x465FE85B807188E6ULL,
		0x36D0D37F6CBB8EA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x27EADDD292D6E110ULL,
		0xFF9E6F49933A1697ULL,
		0xBFAFA20415F408FBULL,
		0xB1AF9A8A6924F722ULL,
		0xC08CB9D4E58AB8DEULL,
		0xA42B897CBA7B09B2ULL,
		0x1038FA7377F3CDF5ULL,
		0x35F49DC3A4B68B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCCE736CA56E5347ULL,
		0x5E14D7CD417D871FULL,
		0x2824CF27E4249B72ULL,
		0x33FF0594DC3DA5C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6A33AB262592D837ULL,
		0x32C52EF2DD79BF10ULL,
		0x0CE9B3AFD7F4B569ULL,
		0x146A9D83197CABCEULL,
		0x81FEE7DF1ECF5C57ULL,
		0x7C240FCACD144C04ULL,
		0xA5A05B071607145EULL,
		0x8055E4903E204A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB60A1644B85A8FF3ULL,
		0xA01F870D4E7D07BBULL,
		0xA2B736BD1D01BB6FULL,
		0x212A8AEC5247A9FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE424CDA725C9BD37ULL,
		0x8F90DC4AFF4E6F95ULL,
		0x3CA7DC13FF7368BCULL,
		0xE89207909A53D191ULL,
		0x01CD0E464387AE1BULL,
		0x76C571B3B5FA477EULL,
		0xA643CBEEAA07A57BULL,
		0x7318BC3B11B65241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2894EC152BED97D2ULL,
		0x30DFBCF802750C4AULL,
		0xEAB821813C95F910ULL,
		0x7E3DF8553B64074FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x15076279111987CDULL,
		0x24F7A3CC2FCF58D3ULL,
		0x48701DE804EBCE71ULL,
		0x6231840ADBB99CFAULL,
		0x2A126B8EB4AB0E74ULL,
		0x997BA7938DB5C894ULL,
		0x45ABF80FB6F918BBULL,
		0x48ABBA97C0DC3F16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C359A7E27DAEA7ULL,
		0xED5283B338CB1ED1ULL,
		0x9FF6F03D2DE57A49ULL,
		0x2BAF36917C6AFA48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA90BE03FA14FBB05ULL,
		0x8756EBBD82461CE5ULL,
		0x9DB445786B986B1AULL,
		0xD4F675924C252E99ULL,
		0x04096D7E0C42F894ULL,
		0x0D035EF9DA0AB035ULL,
		0xC45BEEB469F1F8C4ULL,
		0x10FC4CBD1699C0F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427220F57340A16FULL,
		0x75D704D3DFDC44C4ULL,
		0xC359B44025835834ULL,
		0x5A69D9A3A6F7D2A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x558A8F682BB8C5BAULL,
		0xAC319768D87A0436ULL,
		0xEB808A01C6480FCFULL,
		0x7D76D21ECA45F74FULL,
		0x5E923D1F3EB7F065ULL,
		0x3D6D53354B03514BULL,
		0x04E236C8E7E8F2CEULL,
		0x8C65C341327EEA54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F3FA20B7B0677D6ULL,
		0xCA6BF151FAF81566ULL,
		0xA514ABD432DC1A6CULL,
		0x5491CDCC491CBFC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x82119B2522663DD9ULL,
		0x63EF8DEEC952D533ULL,
		0x5CDA3712EDCB15FAULL,
		0x010D03EE3BA6060DULL,
		0x13567BC4C21CB587ULL,
		0x026A4FA69FB8B7F4ULL,
		0x0A701320A099C269ULL,
		0x56E01D31ECAC4FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60E7FA59F2A931BEULL,
		0xBFB760AA7EBE236EULL,
		0xE97D0DEAC49DF190ULL,
		0x665159575D39DD72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEB85A174831C05C4ULL,
		0x001E3147D3CCC511ULL,
		0x30D955A872F633C3ULL,
		0xF05295CF6DDB3232ULL,
		0x7C949ED59DACFB33ULL,
		0x4540ADAA4FDD1018ULL,
		0x3E0A8B7B11E387DCULL,
		0x64735E5519BE3BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69953529EAC951A3ULL,
		0x47B7F88FAE9D28B4ULL,
		0x666A09ED1ABC5E75ULL,
		0x5972967140180EF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5E40DA29C1C0DE6DULL,
		0xEB19F558B6593FEFULL,
		0x75089B09946CFC96ULL,
		0x94364E0C56CAFEFFULL,
		0xA159BA632024192BULL,
		0x4BDCDA2959EB1873ULL,
		0xDC9A98609A0F482DULL,
		0x4576327C5716BFF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519284E0871C9C5EULL,
		0x2DE2577C0F3EE119ULL,
		0x33FB396072B1B350ULL,
		0x63C1CC81442B7DF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x02745651364BD6FCULL,
		0xB0392060238D157FULL,
		0x83E360BB9AD8CCA7ULL,
		0x9FD98FF6BBF8BB2BULL,
		0x07C376AD5F226788ULL,
		0xC337F61DFD9DE2E4ULL,
		0x51212781492A4ABEULL,
		0x820C191B6F6792F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2977F40D55673811ULL,
		0xAA87A8D3C8FCC358ULL,
		0x8ECF3DEC771FE4F8ULL,
		0x6DA54A0945588C07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x322A6C13CCE4B4CAULL,
		0x742A754E6EA69B99ULL,
		0x43E8FE34509CC91DULL,
		0x6927350B2A99F750ULL,
		0xEC0DE78E88D04244ULL,
		0xB4F4EE1D13676F5CULL,
		0x0B01F26583709D2FULL,
		0x625B8EB141D7AE15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C3ACB3C1BCE8D1CULL,
		0x5085CD9F50012364ULL,
		0xE632F945D3541E32ULL,
		0x02BE635AF09DCE6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x39B7701F3F6C5EDAULL,
		0x50C1B5E95A6DEF39ULL,
		0xD3EB8BD6BA6D71B3ULL,
		0x6C3AB6373ECE6695ULL,
		0xF68EC8437A551723ULL,
		0xBE4B96533DF308FAULL,
		0x81F38A6C16BE9923ULL,
		0xC83347429CEB8B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E92A23680DD280ULL,
		0x8FFA06448C814479ULL,
		0x1E1217E21AB82D01ULL,
		0x23D74A1A89C50C39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9C6AA2096A18A88DULL,
		0xD8A19860839A36BAULL,
		0x8540837639E16AB1ULL,
		0x10AFDE814F7CFE0CULL,
		0xB887D6A4DF5F68B0ULL,
		0x53D21AEE26E73D77ULL,
		0x54C41321C3BE1B24ULL,
		0x0EB887E95B93886DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00947E82924232F9ULL,
		0x49D197BA49ED5680ULL,
		0x1A5B5A7948197216ULL,
		0x40140B24E7633E47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x44D8BA42866F2B3DULL,
		0xEDE8E5817C799AD4ULL,
		0xAEADECE125DF2588ULL,
		0x04009FC5EC594024ULL,
		0xF48282A95B9EBED4ULL,
		0x06FA475FF59419D3ULL,
		0xB32C8364E036CAE4ULL,
		0x37C44F26E89F5CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90381F661FFF7FE5ULL,
		0xF70F7DBFF075704AULL,
		0x47496DDA6E014361ULL,
		0x4B245F8C74010CE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4DE451F126E5796FULL,
		0xC00CD82B13FE0EE0ULL,
		0x3A62C5F0B10AF88DULL,
		0x35AC5A9312DD6CA4ULL,
		0x06B98537E31AEBEDULL,
		0x5138123502B13D9DULL,
		0x6B0C7F98829BD971ULL,
		0x40B1969AC4AC605BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6E183CDCE48006ULL,
		0xCE5F8C097A4D342FULL,
		0x1E3DB694142D3F5FULL,
		0x5008B58C4473BA36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x394B4876B81CFA5FULL,
		0x56A1F7EB2E7F8AAEULL,
		0x9E4F66958ED21AFBULL,
		0xAFC7B1E427292D5AULL,
		0xF215332B3097DC80ULL,
		0x69B8F6D4425DAF55ULL,
		0x8287C4163F33F54CULL,
		0x5B0E6FA01E8BA7B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2870E0DFEEA7B773ULL,
		0x08169B6D08679170ULL,
		0xFE7681E2F0888453ULL,
		0x33EC43A8AFE412BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4D91254DAB66515CULL,
		0x02A8D787D84B03D0ULL,
		0xF8DB93F3A130EF40ULL,
		0xBD7D871B097A911FULL,
		0x5D5C3E4935094326ULL,
		0xDE7E21194F4CB6BEULL,
		0xBB3FFA7F84225388ULL,
		0xA1AF7126400A6300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2942642B8AC64CA3ULL,
		0x0961C1499DAE2412ULL,
		0xC45AC2E13E495591ULL,
		0x3D8852C88B05433BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB4A81AB8C3CC3924ULL,
		0xCAA0B022F6EA0C0BULL,
		0xC97968F647EAA275ULL,
		0x27CA97A520A143B9ULL,
		0x17CFB0D77217CC28ULL,
		0x318F6E64D84B68F0ULL,
		0x613DC2158AAD16AEULL,
		0xACD5135570B42745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D7C5AB3B3548ADDULL,
		0x25EB131B121B9FAFULL,
		0x38A43828DD9C0051ULL,
		0x4F6B7653DB5F1806ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x786498B9B4E85F1FULL,
		0x4166C29E6D3D4FBDULL,
		0x1895B2AEBC2D501DULL,
		0x7168BBCBE034B607ULL,
		0x24AF080F1F04608AULL,
		0x5986A87EB765C71DULL,
		0x4B69A0C78E838C4EULL,
		0x6B70C3DFD155E132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA5FCAF84F8EB5FBULL,
		0x8B63C56DA658DE10ULL,
		0x4A43904DE3B423BEULL,
		0x6425CF04F2F4237EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA4B6BA88A1582782ULL,
		0x0DF95E73A8AED5DCULL,
		0xDE5CA7FC48B7354EULL,
		0xA0719F5BE30C8AE1ULL,
		0xB230A88110F3F210ULL,
		0x089880569EB147ACULL,
		0x188D21E5E756E307ULL,
		0xC6F236DE566CA36BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17EFBDB1258E1A56ULL,
		0x549C6B4F36FF797FULL,
		0x834FB01C9F9CE859ULL,
		0x2865C45CB72CCCC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8D1DCACD89F4A4C8ULL,
		0x4CEE9F2F95FF666FULL,
		0x217EC6181CCEA776ULL,
		0x683A2FA570A6B06FULL,
		0xB2C0DE38C9671796ULL,
		0xDF03A684440B4E81ULL,
		0x9113E28993F4B59EULL,
		0x061B99826F666C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15BEC73B6F422532ULL,
		0x677956D1AFAD0DB0ULL,
		0xAA72668413219D0BULL,
		0x5052F901F9DABA26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x67700260DA1FBE3AULL,
		0xD57AE5265FD6E15AULL,
		0x34C5C6D742E7BB57ULL,
		0xE4965B04967F4850ULL,
		0xFE3CEA6B002EA28FULL,
		0x40F6DD8814A0526DULL,
		0xE659A3026145616FULL,
		0x5475CF11F4F67730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247ACE42E10BE162ULL,
		0x7A1FC7596FA31DAEULL,
		0x6613F931B33431DBULL,
		0x6E1317AEF314F992ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4F9EE2447B279FEDULL,
		0x4B462A7A6350BC76ULL,
		0xB0078BF46F88F6AAULL,
		0x8BC3F348E75C8DF0ULL,
		0xDDB946D37910C4A7ULL,
		0x0353CE9858F7A9BFULL,
		0xA936303C76A9AD23ULL,
		0x69A8882F8D7781AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x391F65A873A4D317ULL,
		0xC9B6D5179813EEF1ULL,
		0xCE12B4EE0CB8A9DCULL,
		0x3AC82A57E719CDDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDF481917D434DEB5ULL,
		0x2AB6371929C9F388ULL,
		0xB6797648191CE9C5ULL,
		0xC4C6C9DB9F4CDBBDULL,
		0x7AFE1C8890205360ULL,
		0x292135B8FF877BACULL,
		0x6B0990AA96537DCBULL,
		0x06DBE90B4652BE93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2100555D39013F2EULL,
		0x45A4308F17E64F23ULL,
		0x99E4EF9A698195EDULL,
		0x496B61880F95259FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD555E9C768117119ULL,
		0x1C927C1FAB5B9877ULL,
		0x111DD15DA8C546D3ULL,
		0x4AC9106669DEFCBFULL,
		0xDBF78D91F52FD52DULL,
		0x8206561753499BAEULL,
		0xB78ECEC9245C502BULL,
		0xC314692EF60865E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C14ED71CD2B1A15ULL,
		0x698343960848B46CULL,
		0x505083390E792D48ULL,
		0x3FD0AD5EEF1E1CD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB0A5AD4FCD67E3B8ULL,
		0x74D7034B4589558CULL,
		0x48212A7FE10DDE23ULL,
		0xDA9BCC8EA4ACDF75ULL,
		0x12CFBB4BA6C216C4ULL,
		0x13E1C2A326DC877BULL,
		0xBAA290CDF9CEA320ULL,
		0x052B60FA4F9ADF25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7B7A8A8E374509ULL,
		0x6859E7830A4571D1ULL,
		0xFC42A912F5BA14E6ULL,
		0x1F0C31B675A9FF0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDE7C0A1F1CA54354ULL,
		0x3AF0C910E2136576ULL,
		0x519B1E00B67DEB01ULL,
		0x7C0DBEB66679C1A8ULL,
		0xD8D44D5991FD4AE4ULL,
		0x6CE9741458B54953ULL,
		0xA8D999FEABC93EA2ULL,
		0x8F27F8733E9272AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DFF856AC83E645DULL,
		0x659804160CFC47E9ULL,
		0x61E7F9CE365D371DULL,
		0x3BFC9FD1B036C7BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF8CCB39260ACAD9DULL,
		0xFCE606B2E76D795EULL,
		0xB2F971F51C3CF69BULL,
		0x58EBC2916D612ACCULL,
		0x6D8C8CEBB8DCFCA3ULL,
		0xFAA87EE02538BDE0ULL,
		0xA7BC33293C279597ULL,
		0x61CD0A86366DCE38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA99E8FD17A2FF6ULL,
		0x31E8DBF86DD9A8AFULL,
		0x98E90A140A1D2B2BULL,
		0x5D5B527D81ADC735ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC06ADC65520FA994ULL,
		0xB2DAFD27D0A9581FULL,
		0x44FE453A0D64E015ULL,
		0x44E8383E46441D2DULL,
		0xE0D1E0D063CF06BEULL,
		0xAFD03DEDA404BCB4ULL,
		0xAADDA959FB512073ULL,
		0x3FCE4176DBC81FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F923B5422CAAB31ULL,
		0xCBC42E6E295D5AF9ULL,
		0xA1E568955B6FB141ULL,
		0x3D85EFE2E5F8D11AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3B099C19D21EE9B5ULL,
		0x78C5043CD75AD2D4ULL,
		0x5B25F424A4BAF6C2ULL,
		0x400B250ADCCF205BULL,
		0x1A0B9638DA022AC7ULL,
		0x1EDB39284138D6D9ULL,
		0x749546F4B9D7CC76ULL,
		0x28E4B39733D111B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C1E88A2E714423ULL,
		0x0D4F803685CAB70EULL,
		0xA94E7C783AC3504BULL,
		0x51FDCD7C8DD7C196ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x06C3E73B57509CB6ULL,
		0x5CA6EE69FB27E32AULL,
		0x8F613043421FC1B9ULL,
		0x5C1B8E56EFB29FE7ULL,
		0xF23125EF47D7AAAAULL,
		0xD04144E3BCE4627DULL,
		0x0636B44CF8F12BDDULL,
		0x1186BDF06DED90E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA0F88C00153F251ULL,
		0x46572838050E81DBULL,
		0x7B7FF3B035EC44A6ULL,
		0x761BC00740F6219AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4FD49028F58F0ABFULL,
		0x4EDEF2FDDBB2F1FDULL,
		0xACBD847D9992271CULL,
		0x0181F1D2F8334576ULL,
		0x22620B86B356B9F0ULL,
		0xAE5B0B8A77ADD9DDULL,
		0x83E48C84C7D798D4ULL,
		0x31E8BAD30B59F6BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A624627946EA569ULL,
		0x3062A98B9F8148D0ULL,
		0x40AA60334392D6AEULL,
		0x6A0DAD26A78DE54CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x28A9A5151C160262ULL,
		0xAC27F03F5F898909ULL,
		0xB3E81D04EA50A504ULL,
		0xB0407536B7835684ULL,
		0xC1D12FE126D5DDCFULL,
		0x5371DAB6D6558A79ULL,
		0x2E3A0F471693B122ULL,
		0x0B4F1E6E496D2A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB6C080DFD4EF68ULL,
		0x0F0E6763303C171BULL,
		0x90866192443CF01DULL,
		0x5DFEF9959DB7A623ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3072EA08A4EA8EFCULL,
		0x6038C000FC68AAD4ULL,
		0x29BF65C0F84D99F7ULL,
		0x629EE5E7241EBFC8ULL,
		0x01B648B66C4C8121ULL,
		0x2B63EF8DE5EA5AD8ULL,
		0x040C109F84C55BBAULL,
		0xF724B9D68569F86BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7181B51CB845BF60ULL,
		0xD10E4F111D3226E4ULL,
		0xC389DD6EAD993799ULL,
		0x12127BBEF1D99FAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x33A92670E82757A4ULL,
		0x282EC444E4E0077CULL,
		0xE65735CCA7E86069ULL,
		0xD7FA7DA39C83FCB3ULL,
		0x871C57564EFD1E20ULL,
		0xDFE6744575DB8927ULL,
		0xA7BE14E1AB0BF4D8ULL,
		0x66D3B08319F18139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41DE1D40A1B9D2C4ULL,
		0x646406946376635AULL,
		0xCC8E4F4C0BAEB89AULL,
		0x1B66B119765D2B42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFC1CE248D8BEEDE0ULL,
		0x704A84ADCD0B951EULL,
		0x5B0F59B696134799ULL,
		0x7E66625A8230D995ULL,
		0x2E35AA0A9D2EC660ULL,
		0x7D9538F0085D5BD3ULL,
		0x9829143777D67D58ULL,
		0x3091534A686BE2CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8141FDC2DB0613DULL,
		0x1470F84F0AE73677ULL,
		0xF12859F25FE9E2BCULL,
		0x33F8BF660234843FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x419BE4E8584FD95CULL,
		0xDF28DA32AD451133ULL,
		0x6B57AEAAB85F187BULL,
		0x924305E9018B1D5EULL,
		0x111AA52B19BD0A4CULL,
		0x6243E14606DE8685ULL,
		0xE74004507746E2F9ULL,
		0x56A2E9E905041CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB90694E2A5F6292ULL,
		0x753C4A97B24D08F3ULL,
		0xBED8529C6CE4C980ULL,
		0x6E71BE7FC02767CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3A4B014D11489C29ULL,
		0x682BD333589A790EULL,
		0x836FAAAF336F2988ULL,
		0xFE2D199F2094100DULL,
		0x357FCD0C63DBBF8AULL,
		0x43CA5D2C35ED4AADULL,
		0x0A693829DEDD2B55ULL,
		0xE633EA39D7295511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B437123E3E70FD7ULL,
		0x7835A7C359D38EC4ULL,
		0x0F0E00E648439830ULL,
		0x29E1DE3510B6B095ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0DDDBF8DDE287F30ULL,
		0xD33446AE246013EEULL,
		0xA9F538ABFB1EFEC9ULL,
		0xC63A304607DDF9DBULL,
		0xE2309FC9214E0CDCULL,
		0x91A146D0B79F3662ULL,
		0x694BD0E9AC0F1429ULL,
		0xE0399FE9A383BBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1157768CFBE6CE4ULL,
		0x7124C9A96602269BULL,
		0x4B363B5B855BFCF5ULL,
		0x0EC7ECF44D6BD469ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x029EA0E599547222ULL,
		0x197964B584ADAC5EULL,
		0x86716B07282EC113ULL,
		0x5EC209477B88C3ACULL,
		0x3E87F62028B7FE28ULL,
		0xDA93C194CA6B0509ULL,
		0xB423EEF84AF4EF3BULL,
		0xAD747F2ECB469155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ACD29ABA4A42FEEULL,
		0x8B6820CB90906BBDULL,
		0x43C6E3E2488A43F5ULL,
		0x1E0CEA39A8025665ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBB4537B50CF4D844ULL,
		0x30422D27CD11F315ULL,
		0x42AB5FD0A89A1FE5ULL,
		0xFD26F86CF243B330ULL,
		0xF6F1AA6A64E4188FULL,
		0x6613AA301D77BE49ULL,
		0x1D5BCE22E5D297A6ULL,
		0xA914D577834579B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6324838006D0815AULL,
		0x572D704C2CD83210ULL,
		0x9E4BF8FEC5DCA298ULL,
		0x163EA82A6E93C3ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x76738C7D2C1D3E51ULL,
		0x491A810924A4C4C4ULL,
		0xC0EDEA7C506B3CA6ULL,
		0xAE2939E337104795ULL,
		0xFC063B951A9F24FFULL,
		0x14016CE92FDB69DCULL,
		0xFD7AA9E641CFBE0DULL,
		0x43E30B63D429387EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF60649F1FBCBDBAULL,
		0x4150ABA63F367B91ULL,
		0x612322AA15417297ULL,
		0x41DCEAB4B52EAA6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB88DD95995ABC030ULL,
		0x840FDE38B330F701ULL,
		0x4EC57AC773FA5F32ULL,
		0x72F43BDE14993B74ULL,
		0x9F1F578E282F2E0BULL,
		0xC0AAD5A5D94B5BB9ULL,
		0xCEEF1C97F3A769FFULL,
		0x2A8C5D662F9511ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5734D8738CAC96C9ULL,
		0x1D6B94D6F460948FULL,
		0x0643B9559ED41B29ULL,
		0x43CA190924B9DAF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC86C187DE0FF63AFULL,
		0x3C68429F77DF2E46ULL,
		0x0D7E1E95504947CAULL,
		0x27871F86FAD8D865ULL,
		0xE70F6030B5A1B1F2ULL,
		0xF3F6FDE6DAA33475ULL,
		0xB2415DADF57BFFFCULL,
		0xEFA33E08FA50D182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14B45FB8D6FFD2E0ULL,
		0x7311F2E3EC18F7C7ULL,
		0x83320667C0B14756ULL,
		0x39C254DC22D7F1CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3EF3D6A26025DB14ULL,
		0x58FC607AC5409A85ULL,
		0x2048429EE3039E7BULL,
		0xBAC6706BF0600670ULL,
		0xABC36FFE0659DED9ULL,
		0x171C960209F62C9AULL,
		0xC994C9CDD6FC4B24ULL,
		0xA0D5A23D6AD85B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF67657517CF2EDULL,
		0xC73AA4C83FCB397AULL,
		0x0C5E372CCC76C5D6ULL,
		0x1A7C8589CC7D8D4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAFADAA0044A3E430ULL,
		0x734F490217CC13A8ULL,
		0x5CDAED55C7AF7E6DULL,
		0x9FB42415FE711640ULL,
		0x30833BD7B30F0D10ULL,
		0x35795C9C222B93A6ULL,
		0x03CAE7F2046767D9ULL,
		0x13960ACC0509255AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3288C04D8DFD515ULL,
		0x6353082F2A43FE53ULL,
		0xECF95B426F08E8ABULL,
		0x07F9BE5EBDCCA19CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD1FFC0633CBEFE91ULL,
		0x50A25B709467DB10ULL,
		0x1AEF5DF2783DAD36ULL,
		0x812710BC36C0D6ABULL,
		0x029B76BC4E21CBC7ULL,
		0x08B57E85EE21D51AULL,
		0x53FB3476015041FDULL,
		0x86C312310CC01EBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35136056D5C34126ULL,
		0x9B932351ED6D7CEDULL,
		0x92392776AA2778C5ULL,
		0x021BC4041B4566EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8B5DAF74350C2316ULL,
		0x5BC79CB19E84B953ULL,
		0x8F3967AF7F115F7CULL,
		0x8917C5B092A9A964ULL,
		0xE0E6FCFBE92EB1BEULL,
		0x28A80ECFA0A051CEULL,
		0x43DE0B0B368F9612ULL,
		0x351BC3FAB248B017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDA73CD8D1FA867AULL,
		0x64B9CF837650DE08ULL,
		0xA22F0B599861A62EULL,
		0x6B36DCE70973CCD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x63902A1B9F172C3FULL,
		0xD6FADC121DECC99AULL,
		0xA986DEC67A98A4DDULL,
		0xDEE95609BCE83575ULL,
		0xFC889FF98033E2BBULL,
		0x27CF151683726AA0ULL,
		0x8A4DCF5B9CA4981CULL,
		0x9AA232C225DE3207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFD7E924A6CAD77EULL,
		0xBFB7FD69A0E89D7FULL,
		0x3113A65FBB07390BULL,
		0x52FCDEDB5BE3A294ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6B06D19CB31F25C5ULL,
		0xBB11025FF5C2642CULL,
		0x79003B67B53C63AEULL,
		0x6CF88052DA84BC76ULL,
		0x33380155928D5199ULL,
		0xBBD8CDE4F9B3BF76ULL,
		0x381490F163A4487CULL,
		0xCD681B371A49C3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0557045074194702ULL,
		0x9D3F925D0670CFB8ULL,
		0xCC0DBF3C7F9F2632ULL,
		0x6A6C8A80C177CDF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4188A9AE68B35EE1ULL,
		0x626B3041C56A3FD1ULL,
		0x1EF940CF52CD76ABULL,
		0x5B9D1C99C383E7C4ULL,
		0xFB8BC19D090F6185ULL,
		0x477972BBACEC86E2ULL,
		0x15415CF3CE4543F4ULL,
		0x31AD5FCFF18B2E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984766FDC0FBD9BCULL,
		0xFE72381D70864582ULL,
		0x46AD0CFFF1158CEDULL,
		0x3B5955779E2CD199ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0B4401599D893CABULL,
		0x661FF691044FEF3FULL,
		0x4B725FDD58159400ULL,
		0xC89C144EE7BE3503ULL,
		0x7516AE8A2B20A8F7ULL,
		0xCB7105CC050224D9ULL,
		0x7039419576860FB3ULL,
		0xA78E4C9B3478E66AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA1E9DC0462551EULL,
		0x98E6D2D9C2A16786ULL,
		0xF3F21C0CEFFBE8B0ULL,
		0x27BB7358B1B068CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x064DD32DDB2204C1ULL,
		0x4F20D0CD0C91A32CULL,
		0x3F12E42B64F316E3ULL,
		0xD82F8EDC70A8E522ULL,
		0x9EFD350153A1CCF3ULL,
		0x91C541CAE368D76BULL,
		0x3CEB469EFC725307ULL,
		0xAA1898476BA999B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FE3B160452674AFULL,
		0xF26894EACE219D25ULL,
		0x49FF5FC4DDEB6A02ULL,
		0x17D629766BD5B54BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC53C578C5F99DC19ULL,
		0x4C083CD2279A075CULL,
		0xBF12E731311D91B1ULL,
		0xD0D42B311514E51BULL,
		0x55CE3AE5D021B89FULL,
		0x34B2854B4395E4A6ULL,
		0x95296661C1D25AD1ULL,
		0x8CCEA0991009C8A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D915A9449B46E4ULL,
		0x1E8805FE2FD9F80DULL,
		0xE33819B3F6570CBFULL,
		0x378001E97688ACF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEFC534ADD280880BULL,
		0x43D973A1A8DB6AEDULL,
		0x782EBD5BED2C1665ULL,
		0xF148E88309811E54ULL,
		0x4DA0E6E0C8DA931BULL,
		0x74FFC1C943BC8D17ULL,
		0x5BDE7B6EBA6F46D6ULL,
		0x4ED2C1E47D5EE892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A77A0BA2F25FE8ULL,
		0xA1D03781B6D85C63ULL,
		0x1B350FCB99B09A3AULL,
		0x2491B06DA597A40EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8F9890E2481CBD6EULL,
		0x0DB414BDA5FE01D2ULL,
		0x9CA1D325A9953C26ULL,
		0xE96B799DC187660CULL,
		0xA48F4884570C9E8BULL,
		0x68B9F47F80E71893ULL,
		0xB70636EA9E823025ULL,
		0x084EFD46795DAA58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDD548733FC465CULL,
		0x994E5FAAC84BA7BCULL,
		0xC78DF9F930E861B3ULL,
		0x25251213C56EAF37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3D6783FCE7CD054BULL,
		0xE10010540974AD4AULL,
		0x3EC1E0BC3484AA46ULL,
		0x8A688040728A4C3BULL,
		0x99C95A9880140FA8ULL,
		0x5AF75CB6CB655030ULL,
		0x7A8CE3B54A604E35ULL,
		0x63D25DB0C6C2500FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x114AF69FEAC75A75ULL,
		0x61B7D3763A7E9481ULL,
		0x6FABADA53ED04632ULL,
		0x5BA2687DF3622E87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6EF0424235CD490FULL,
		0x7A216A5AEF79C1F1ULL,
		0x7C38BE731A66F67AULL,
		0x9114E1B152479BD5ULL,
		0x0FF6F4057EA0CBF0ULL,
		0xC03302E1C6B35D04ULL,
		0x9F68B674DD8E92DEULL,
		0x767F789E9FB33FFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD987B1301AB915BULL,
		0x01B3D7DE6E19908BULL,
		0x25C3D3CBFD90C38BULL,
		0x2800C93D06E31BC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB44F3577959B54C9ULL,
		0x9D31DA6973C3039FULL,
		0x3BAEF4AFCFAD9A00ULL,
		0xD854B7F17EB5C38BULL,
		0x272083A046F6ED3EULL,
		0x97AB7605B4A62ECBULL,
		0x67DC50682E6379BCULL,
		0x6D9CFEAF343210B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8322BF421E428E83ULL,
		0x20A55F42446DF5C7ULL,
		0xA662E426B271ABFFULL,
		0x1DA285F33E243DE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3F247E9EA05847FBULL,
		0x597D8225520DDD81ULL,
		0x51E390C9CB663098ULL,
		0xBD6276B07CB218E8ULL,
		0x471902529ABA8589ULL,
		0x438D01411A949CFFULL,
		0xA07CFC5AF19BF9B7ULL,
		0x44706B8B49405BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCDAD6E198081BE0ULL,
		0x606BB1CF441D2B65ULL,
		0x24710649A88D41CCULL,
		0x66126D5D5C3FBB36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8CA4A0EFECDA69A1ULL,
		0x408998A24E00BCDCULL,
		0xA8AB3304CF418EF6ULL,
		0xDD24217B07FE82BEULL,
		0xF8066AB1306F91E9ULL,
		0x95D40C2515CB1E1DULL,
		0x2B4E354EC83F7916ULL,
		0x9F6AEFE1E5B4A9C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D98773D1D6A15DAULL,
		0x7E0366238A27354FULL,
		0x16471CB688AD8850ULL,
		0x0703BD0320CFB5B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x37386A915BEC0662ULL,
		0xCA6DEF23EA821DB4ULL,
		0x7253F1B526D30AADULL,
		0xB05CCC576DAA15F6ULL,
		0x2E97EC634CD8A2C9ULL,
		0x4B72412D800D31D0ULL,
		0x994847443EE3FA02ULL,
		0x75939F092ADAA378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C5814EC41432E4ULL,
		0xFD639BE4EC77829BULL,
		0x330E85D67CAA2704ULL,
		0x244667B3CA1E59DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2C75C2ACEF51260AULL,
		0x39D312CF1EFFBAD9ULL,
		0x91398D18FD5C008AULL,
		0xC790E82BDBCC4EE3ULL,
		0x653D452F0724D9B5ULL,
		0xF942B0417D479D1AULL,
		0x2737A0BBFFB1974AULL,
		0x12A36B53BA3DCB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x338E07A7FEC9776DULL,
		0x39B93C87B7A10CC4ULL,
		0x637B6900F1B875ABULL,
		0x0BD2D69980F88221ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC06C0F32CE36C1C5ULL,
		0x8F80715A6E2D5EBCULL,
		0xD7AD2FD391FC412FULL,
		0x65C76F6A9640BD61ULL,
		0x0D071328E55898C7ULL,
		0x21BC1CCB9A81764EULL,
		0xDDF4A394500F208DULL,
		0x66106C68C9B77003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF78E744D95D719CULL,
		0x916CB7935D64EE52ULL,
		0xC9FD77D7743B1622ULL,
		0x0C3786F8877B5DF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCB7BB926CB2F350CULL,
		0x8D0D8CBE6CCCA1E1ULL,
		0xC1495076A2C73086ULL,
		0x76233D2AAB032246ULL,
		0xE1614C53089F33E3ULL,
		0xB189A0841D01DAD3ULL,
		0xFE6431A8A769B0D7ULL,
		0x268D33F151DF7E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FED0D7A12D0E9A2ULL,
		0xE77B605ABB131D55ULL,
		0x8428AF7F7C77708AULL,
		0x2F18F2FCD22FE9DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6F64DB51E8DAC81CULL,
		0x56F2C8BADFDC6E85ULL,
		0x360C023494D56F47ULL,
		0x899513EDA7145B49ULL,
		0x0A242913C60B1835ULL,
		0xDA57DFCBD2B3ECD2ULL,
		0xE08143FC40620A33ULL,
		0xC51AC146EB248C84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0C2F4414E80645BULL,
		0xBFFE00FC269195B2ULL,
		0x893C19A62362F2F9ULL,
		0x4B8DC4748E813702ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEE60A4A7A85D791CULL,
		0x84AEDBA1321735F8ULL,
		0xD6146847CDECEAE9ULL,
		0xEF9078718E1AD75FULL,
		0x83FA7F68035B15B4ULL,
		0x586D26CF7A2396FAULL,
		0xF399AF0F95500B09ULL,
		0xBB82F9B09291006CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858F8E1827E2B60FULL,
		0xA4E29E6D535F9F28ULL,
		0xFEE46497F7CE8E4CULL,
		0x450188A74FA0E78BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5CF20F3C24A6DE3BULL,
		0x038D3EF33B7E45DFULL,
		0x7B10EE6922CA6533ULL,
		0xE7FECF2695775F0FULL,
		0x741BFAC2ECEEF3F5ULL,
		0x68EA103ED22004C0ULL,
		0x5A76A37068F98DDFULL,
		0xA2BCB55A7DEEB11EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9919482B501F184FULL,
		0x964BA8466C3EFA70ULL,
		0xE8AD3118B7D5745CULL,
		0x1001BA9546E5A990ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2BC3201A57E18B7EULL,
		0x2A56A0C89920DCEDULL,
		0x06AB478C844EC679ULL,
		0xCFF621300A54BB46ULL,
		0x2D4071EF9A60B45CULL,
		0x19D176980E45B8C6ULL,
		0xDF918134A543F039ULL,
		0x6EA56FD53749313AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35409AB423C53ACULL,
		0xFF6E3B5AB77A4A57ULL,
		0x3644755D0C646EF2ULL,
		0x3C84BAD63F320A03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1680911D3FF044A9ULL,
		0xDDE63D0F28A42190ULL,
		0xE140B771D3D39FB4ULL,
		0x811E4B2272804691ULL,
		0xF7E61C360CE30344ULL,
		0x79C392C169A0285FULL,
		0x6990564B10146F02ULL,
		0xA86F0639626B3B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2A8C12329A2C48AULL,
		0xF0EE05C4D66A1FCEULL,
		0x8CAD869636DC1A12ULL,
		0x019937A70E6B0A1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5CBF71A14076CAD1ULL,
		0x068061A4F74637E8ULL,
		0x792C852875C0C7B5ULL,
		0x189E8292711B7542ULL,
		0xDE29888866AA67E0ULL,
		0x23D24EC0FE57DD08ULL,
		0x49E0B3E7F79BFF3BULL,
		0x152DF7DC7794D1B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E9B5E07DC23683ULL,
		0x57B8124AB8510739ULL,
		0x7087399736E8AA7CULL,
		0x3D714D4C313295DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x09D3613704AF4662ULL,
		0x9B6C9C26BDA11F7EULL,
		0xBBBCE53B5671291DULL,
		0xBDE7FC6EC7522015ULL,
		0x26E9F5417DF7748AULL,
		0x91A7DEBBF2D606F4ULL,
		0x616AFD5DC34BD50EULL,
		0x6D229C96C43B80FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD08DC8EFB76A9551ULL,
		0x3A57AC0CC96627BBULL,
		0x319E812653B2C947ULL,
		0x710B3ACFE82745B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCCDE1043F7730F31ULL,
		0x88ACF9762C8FD6ECULL,
		0xB1057989B7F41EC7ULL,
		0xADEDC309A2532E58ULL,
		0xF0A8B95D0A1C1D27ULL,
		0x1BE647FFAF482DDCULL,
		0x6DA34D1B2984388EULL,
		0x4F544B2E90DBC55FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E99413779F64C3ULL,
		0xACDBA96A3146A5B8ULL,
		0xF742EB91E19483DFULL,
		0x7470EBF322F27A82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x554906CDA27ED0CDULL,
		0x46D21E50A2689BB5ULL,
		0x0705B4832D061D33ULL,
		0x0D7FC21104905179ULL,
		0x5CEBEE965D59ACEFULL,
		0xE35EA53466340CBBULL,
		0x6E5D332FC792A83EULL,
		0x4E883F1D77846051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x204E711F7DCE7DFCULL,
		0x06DEA417CE227F85ULL,
		0x68DB4D9ACCCB1689ULL,
		0x35B92070C2369D8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAE68A43DA711E2E6ULL,
		0xC6C122207892252CULL,
		0xB7369A5D9FA47ED5ULL,
		0xC3A940D08D40C5F1ULL,
		0x05648AB382F0A891ULL,
		0x6FA26A4598C3E688ULL,
		0x88EE257783901543ULL,
		0xB564256E4F5819F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B553AE316CAEC81ULL,
		0x58DCE87525A65D5DULL,
		0x0A902A1B2707A6D8ULL,
		0x3086CF305454A0D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA75C3CC83CDD3E24ULL,
		0x6BD55D1396F0E77BULL,
		0xF0570DD6106684B9ULL,
		0xAA57875DB2D81DF2ULL,
		0x63BECC23A5F838E0ULL,
		0x9AC1A0DB8A2D9EE9ULL,
		0xB6FC5B3F8C926F6BULL,
		0x94A67527F7812071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75AE8A12DFB5B2BBULL,
		0x64933DAA19B67E20ULL,
		0x19CC9944EE230EB2ULL,
		0x3B0CEB4C7002EED4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC49A3235A8829919ULL,
		0x0332FB7BB7202779ULL,
		0xF5205173B76D3C50ULL,
		0x4183744ACFC8B943ULL,
		0xFC57916E02627D27ULL,
		0xDCA78CED240D56EAULL,
		0x93A7020FAD67E6A0ULL,
		0x16C3A5CB6CCE31B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3999C88A03212D68ULL,
		0xC411E6AF111B0E5BULL,
		0xDFEA9FC774D97830ULL,
		0x228E107CF6641AA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD9ED36325E188944ULL,
		0x25409A9F54EEAE78ULL,
		0x62F8A89F19EB85B8ULL,
		0xF9258DD72DB2FC7BULL,
		0xC7B3B0D6F81BD395ULL,
		0x6202BB4DDEAC09A5ULL,
		0x9F661A9CEF74C229ULL,
		0x57E8368F65E987EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E99761B3239F376ULL,
		0xB1A8682E62781D14ULL,
		0x0C209BEAA54057DCULL,
		0x059DA7204E5D29C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE5D6C0E19F53F39CULL,
		0xD411C60681432940ULL,
		0x53E444451E3D2DFAULL,
		0xD3A222D4A9839726ULL,
		0x9A4D24550E0F0A6EULL,
		0x6D31E082A5D6BE4FULL,
		0x9533C81DAD6B17E0ULL,
		0x74AA40926C7F8100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4A2581B58F829CULL,
		0x0979196B1F236911ULL,
		0x7993F8ACDC22B94BULL,
		0x24E7B890C470BD3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD7EC5E2EDBCDED70ULL,
		0xCC7F8B1446795697ULL,
		0xBBF00D174A78FC62ULL,
		0x43D237DD255F0BCAULL,
		0xD100DF46A1299996ULL,
		0x09AB9D7DBA967EBEULL,
		0x4185C8A46B3E88EFULL,
		0x7129C94A8A3C2D81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0D82AAC7FABC3AULL,
		0x3BF8EBBDF8D026EAULL,
		0x75CBD57F35C14FDEULL,
		0x100618EDAA4DCCFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2CFA578C49AF2C4EULL,
		0x3448320E72F90190ULL,
		0xB29904B3BCEAB9AFULL,
		0xC02F6CB5A635B73AULL,
		0x6EB083A9C5359E8CULL,
		0xB453F2C979356425ULL,
		0xC5AFB7EAFCDB07FCULL,
		0xEE79B3EE5D72EE85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B2DE2BF8FA4BA6EULL,
		0xF8BE3BF670E5DF1EULL,
		0x0AAE5195456DE931ULL,
		0x2640221785451F16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1B85CBC61FAB333EULL,
		0xA6FAAE4AC46B7517ULL,
		0x0CEB16DA1FCFF6C8ULL,
		0x395DF1D609A75708ULL,
		0xCD28A72DDA809B20ULL,
		0xE4E81EFF687ADFC0ULL,
		0x343674AB6EE722EBULL,
		0x54B79E4DD49D4581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F8E9C948EC23BD9ULL,
		0xA16F483446A8ABB5ULL,
		0xCD00684C961F25CCULL,
		0x4C9F716398FFA835ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x91328AF8EE0382DEULL,
		0x40E953508BB3D89BULL,
		0x4A875AE4FA19BF40ULL,
		0x0EC80E158EDBEE51ULL,
		0xF8A813D7E3455B87ULL,
		0x341D561294E933BAULL,
		0xD812BF581B6DA9BAULL,
		0x9DEBAF946A2F45DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A257D04AA4F1C52ULL,
		0xFD441A12A651865CULL,
		0x5D4FC1F90C60F0E3ULL,
		0x7FC41E1D51E04D65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF2EE00F9601F07D8ULL,
		0xD7B5A12543D26EEAULL,
		0x049E2FAA2E184E34ULL,
		0x860BC1ECA3FCEC2DULL,
		0xB49879A42BE7B396ULL,
		0x78EB25CBB7995E21ULL,
		0x2CA97C56FA2E0A90ULL,
		0x0FF1D677788B5797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1900F57E483B07BULL,
		0xCA9D3D62849667EBULL,
		0xA5C6A49350EDDFA6ULL,
		0x63F197A888ABEC9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x37D11189860EF599ULL,
		0x454A0DDD90E323FBULL,
		0x50DE2AA90BAFF4DDULL,
		0x59A308840BF9CA4FULL,
		0x783A26D5978078B8ULL,
		0x3139F1647A424244ULL,
		0x71D768E4CBE36B33ULL,
		0x7F961D2EA9834300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1072D53E0320E3BBULL,
		0x93E3E2C7B6B8FA25ULL,
		0x36D7BC9F4F71DE76ULL,
		0x49EB5D713575BC60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8C92E57F513D9F97ULL,
		0xAA1A0D5AF97D6A2DULL,
		0xB830C21E97B94E00ULL,
		0x6F0AFAA48C521CD3ULL,
		0xFB0CFCCB65256D10ULL,
		0xF4F8EB1434974866ULL,
		0x68529A5B04AC4D94ULL,
		0xDDDAF0C042F1E6A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0806BB054CBD4DDULL,
		0x070CF25AC7F22976ULL,
		0x3473ABA1494CD21DULL,
		0x5D8AB72E7C3A59ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9127E64340867B37ULL,
		0xF348572A186354E6ULL,
		0x9F884D4A6DDD773AULL,
		0x477BEF172DB27E8BULL,
		0x17684665DCBE3006ULL,
		0xDB4A7DA3A190DB24ULL,
		0x376F44D7C66F115BULL,
		0x1BF9CD6CC3E4BBA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA2596204C19CB3ULL,
		0x8056FD7413E3DC42ULL,
		0xDA0C8551E25A0ADDULL,
		0x6E906D3C41A65879ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x46378FD40B06500DULL,
		0x5B4C8F7C223D98EBULL,
		0xDED06D35885B421AULL,
		0x6DC2E1992D452DE5ULL,
		0xC9BE5A0C680DEBECULL,
		0x793C972C14335370ULL,
		0xC45D659990588E17ULL,
		0x4248980027C786A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3878EDAB7D175691ULL,
		0x5A4B000721DBFBA9ULL,
		0x04AD8200F5805996ULL,
		0x4489719F14E32ACDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x65F21D62E0790048ULL,
		0x8F2A0291F3F15787ULL,
		0xB50893A8062E2036ULL,
		0xEABE958E0A960583ULL,
		0x16756731645339C0ULL,
		0xF61F98A08CA6B353ULL,
		0x810186920779F84EULL,
		0x3E78891F27928076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB5F6EB7C4D39444ULL,
		0x17DAAA66D4AFF5DCULL,
		0xDB428D552248FBEFULL,
		0x30A2F02DEA55171AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6F0F16685C393DA4ULL,
		0x2330599AC4BFB9B5ULL,
		0xC38050B5C624FB6EULL,
		0x8D97B6EFF7CB37E2ULL,
		0x01A83382FD758CE1ULL,
		0xC3DBA01AA9EA4F40ULL,
		0x6A4433CB586426C4ULL,
		0x04E3459ADFA9A41AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE06BBD9FBAC2730ULL,
		0x35CA1D8FFD877D35ULL,
		0x89A000E4E502BCA3ULL,
		0x47540BED2AF993CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x381DED80136E139FULL,
		0xBF26A9FB21C13F3CULL,
		0x994C1394FA3EAE15ULL,
		0x551FAD5A5DF312F6ULL,
		0xF6E5E184B96A4A46ULL,
		0x38E57E0FE2A05643ULL,
		0xDD064012DCA2A617ULL,
		0x31F12D887DF4CA05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3D673399351B20ULL,
		0x31376056C58E0D52ULL,
		0x68399661BA635588ULL,
		0x3EEC6F9D10490FD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x63AEE264C0CCD20AULL,
		0xC28E7C4EBFE55A09ULL,
		0xAA17780B9E28DEBDULL,
		0xE05D7318A50FA66EULL,
		0x2710C54B29F31E82ULL,
		0x7673378BB32CB401ULL,
		0x421CBBA456FA8C1FULL,
		0x5078809CA30EC22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x302C2B8CFAE35B31ULL,
		0x57A8BB0B58881235ULL,
		0x7A5B52708759AB69ULL,
		0x52408A58D940794CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA0D29D7E3A881046ULL,
		0xBB8A49D180D260A9ULL,
		0x19B46AD2CD5766B2ULL,
		0xDBFD0A48CA708F1CULL,
		0x25B6AB836B63ED66ULL,
		0x355538AAC6085A4DULL,
		0x6C9842CD5F06091BULL,
		0x26F6B6DB8F86F17AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F013002B5D4E61ULL,
		0xA630B32AE60FC81DULL,
		0x384E554EE83CC0BCULL,
		0x249C2EE018786748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1F71FC2719D6398AULL,
		0x3A8F5F7E71038593ULL,
		0xFF212E920E5F6DEAULL,
		0x57A4C2C3D450267EULL,
		0x79972E0488BFCE49ULL,
		0xC50AD0B11BFD2764ULL,
		0xCB379D3D455188DEULL,
		0xEE028654D8E1014EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BE2D0D3664EDDA5ULL,
		0x7A2A59C898975E7DULL,
		0x296285AA5879BEFBULL,
		0x2C04B35C05B65831ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x956837422A68CADDULL,
		0x68A24AA5305073B5ULL,
		0x34245718831C727AULL,
		0xC2D966CE849B3B50ULL,
		0x9123DB63CD27E24FULL,
		0xF8D5DB7661558783ULL,
		0x19EA87D550E1E968ULL,
		0x3C9450FAAC4C2B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20BAC8129E546400ULL,
		0x5860DE37A302913DULL,
		0x0CF480C284A5180FULL,
		0x40DD6C0417E9AD82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9928389159975FF6ULL,
		0x980FEDEDEB6176EBULL,
		0xBE9A47A7E8D64194ULL,
		0xDA714C78669AFBBFULL,
		0x40B2393068F25C60ULL,
		0x2B838076AF7B84D3ULL,
		0x48717F94F4864704ULL,
		0x84837205430791EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339CB5C0ED911941ULL,
		0x0D94FF8BF7B72E47ULL,
		0x7F7337C434C4CC33ULL,
		0x05F4394059BAA544ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x13DD75CF83BEDD7FULL,
		0x487F1EB9975CF517ULL,
		0x9E3B4B5BB6847BA2ULL,
		0x9875D9F79FF9AE27ULL,
		0x23285B79FFF87047ULL,
		0x370771093B78834FULL,
		0x9EEE99F2D44539BBULL,
		0x7A5140E2E4AAB0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BDB09EB829F8AC8ULL,
		0x7399E6186B4072D6ULL,
		0x35A6256738CB0D6CULL,
		0x40857BA5914FF419ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD582490BD8BE2A41ULL,
		0x481C54A4AA5035A8ULL,
		0x566C595FC51DB46EULL,
		0x93B11FDF548EB819ULL,
		0xFCC057DA23B3AE1CULL,
		0x0ED8DF82262719D0ULL,
		0xE5B0DC7CB601180DULL,
		0x9E397D2316B2E9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A0F536D256A05F9ULL,
		0x7C4D81F6541E0AAEULL,
		0x6EAD13E2C947465EULL,
		0x1039B314B31D71DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x59602EA5B8E9C164ULL,
		0xBA2DCBF145B4C712ULL,
		0xA89C8A4FA13B2F62ULL,
		0x10941F0959CE8B41ULL,
		0x754A5907FFF038E1ULL,
		0xC7D9DA06358A2696ULL,
		0x6AD822E661257BF0ULL,
		0x11ECA472CE76F63CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC26965D5B6923329ULL,
		0x648428DD38368167ULL,
		0x84B1B8820CCB9520ULL,
		0x39B48813FF771839ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x96339B0B344B9CA9ULL,
		0xCFFE2F3408C8E4B9ULL,
		0xC53A54DC0093D621ULL,
		0x59C71AAF43CC30B6ULL,
		0x02FB1E477D002043ULL,
		0xB0BC99BA13E6A537ULL,
		0x6883EBFDC504A9C7ULL,
		0x15E99080433C5B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x077A19A7C2506720ULL,
		0x0BFD00D2FD056AE4ULL,
		0x48CF5C873F4509C6ULL,
		0x1A728DB93EC1C38CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1935A6DC7C140C6CULL,
		0x247387C6737D8CFCULL,
		0xBE015F30FD3BB6DDULL,
		0x506BA82112C1DA21ULL,
		0x56D0BC7A53952967ULL,
		0x780B8F76A6E97782ULL,
		0xACB92840490EF1BEULL,
		0xA32F262D54AD7365ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC31A104E4383559ULL,
		0xF62AD3633A254A54ULL,
		0x617D58BBD5739922ULL,
		0x096B52DBA480FB39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFA7032F7514BF5C6ULL,
		0x528F0CC101F64972ULL,
		0x85C5891D5153DE6FULL,
		0x2E61CFE3A8485BD3ULL,
		0xCB16E594CCCB0ACAULL,
		0x088E0E1FBC4263F8ULL,
		0x6F71E39DC05D0406ULL,
		0xE5FBFA5B6E0CAC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD6470DB76F94CEULL,
		0x97A52576F3D12061ULL,
		0x10AD5287DF227754ULL,
		0x51C8F975FE29F9DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x19039304E1EECE68ULL,
		0xF304B7763873561AULL,
		0x73DF27B475B54D26ULL,
		0xE219D8FAB10D92D5ULL,
		0xF4207E908584FAB6ULL,
		0x6E3255D657CE4CC9ULL,
		0xF6AC15660E10E655ULL,
		0x1D072CF29AA11530ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D65C78B3AC062AULL,
		0x4E7D75474112BC14ULL,
		0x116A54DA8C377DD5ULL,
		0x312A84FDA4F6B81AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAD3D1E7D30B5C64AULL,
		0x2112567CF166E52FULL,
		0x04C52C687D257EB9ULL,
		0x494DE41FFC4603DFULL,
		0xA2825DF07878E48EULL,
		0x6065D32AC8005879ULL,
		0x2D353344D41BF8FFULL,
		0x196E925AA84CE61FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC97102F12A7B3F6ULL,
		0x702FAED6A174073DULL,
		0xBAAAC89FF94C74A1ULL,
		0x0FB79D94F7B02C7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1819E5CF8DF64A63ULL,
		0x515ABAAB0C6968BBULL,
		0xC6F5CBFE2FE3772DULL,
		0x9C4BBBDA3B4BA56DULL,
		0x10C2254C23284C40ULL,
		0xF31EA8479BCB3FC0ULL,
		0xAB9CFB23268A1D71ULL,
		0xE8CC624986D82980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94EB6F1CC5F1A115ULL,
		0x67E7B54C2C94DF3DULL,
		0x40431335E863D617ULL,
		0x2AA252C43F61CE87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC360045EE2D6B8F0ULL,
		0x6EE32481FA6C42AAULL,
		0x7F7C040366CEBD5DULL,
		0x9BDAD8B9D7731DBBULL,
		0x6F679904269AC42AULL,
		0xCFD3D02D0F56E5B0ULL,
		0x15CBEA95E1DC654CULL,
		0x755DABFFD306217EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC0BAFC9DCFD9D8ULL,
		0x48540B3241525ADBULL,
		0xBBC0D642ED85C6C4ULL,
		0x07C260B32A5C1672ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDC23B865FBEF99D8ULL,
		0xD0575C71A527F38AULL,
		0x4EBFFA9BD44BF14EULL,
		0x1A7CD3D6A076F54BULL,
		0x6460ACBC7BAF25FFULL,
		0x0B80B3A7BC0B17B7ULL,
		0x92D3F440D29340B5ULL,
		0x4932371C669BEAAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC27D5C6057EF3F41ULL,
		0x857207578ECD78C3ULL,
		0x1A363C3B16278C2EULL,
		0x77F1020DDB9BCA9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF09A4FE6C1141112ULL,
		0x819EE1E45AFD1CFEULL,
		0xD467A4E30CFD5257ULL,
		0x497E04406D4A87E0ULL,
		0x1D9A692E37FE2C3AULL,
		0xCC239ED3CE6565C5ULL,
		0xB8F47C9BF8D43475ULL,
		0x8B313EE524454FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5585ECC310CEA4B9ULL,
		0xCEE87554FE0A3841ULL,
		0x48B22409FC7D1BD3ULL,
		0x72CD5A43CF9462A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4F0AA8611772ED32ULL,
		0x322B496D9C368262ULL,
		0xDE16497CAC6DC39AULL,
		0x667F03551CA61B56ULL,
		0xC489CAC615A1CB17ULL,
		0x396E8B1EFBBEA28FULL,
		0x3CD4652BB3A8DC16ULL,
		0xD5CE410CF02847D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7EC1C84D77175CULL,
		0xB893F006FA82A3B9ULL,
		0xE59D4DF9577E6EE6ULL,
		0x231CAB40C2A0C56FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7CEEE35047C3D7D1ULL,
		0xB8641BA823C5662CULL,
		0x56E07940CFC4185BULL,
		0xB5CEAC3E03C58405ULL,
		0x3DBBCC30027B22D7ULL,
		0x9AAA94D875929CD3ULL,
		0xF05135FB3198E53CULL,
		0x76CE613BEA484C8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6CF3270A60B0667ULL,
		0xADB633C99788AD87ULL,
		0x02EE7C8A2C761F5AULL,
		0x58711B22CA80E163ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x959A39C3E85896FFULL,
		0xE7A45A798C3A3015ULL,
		0x64CA441B620C7951ULL,
		0xF888801A73619C35ULL,
		0x0A9F73579911A82CULL,
		0xEFD0F3A310683219ULL,
		0xADA922C2F9747EADULL,
		0xD4C26CE500DC9FD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x294558C4A0F7925AULL,
		0x80A884ADFBB19FCDULL,
		0x2BE56D0C69574723ULL,
		0x0D64AA1894215685ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}