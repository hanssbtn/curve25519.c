#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x01EB35380E9E4EF7ULL,
		0x0F4D33E227317583ULL,
		0xAFCDAF6BB1923102ULL,
		0x450541BC0B36E037ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x03D66A701D3C9E01ULL,
		0x1E9A67C44E62EB06ULL,
		0x5F9B5ED763246204ULL,
		0x0A0A8378166DC06FULL
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
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0A7AF41BE44E7F5ULL,
		0x19EE23EFD247D531ULL,
		0x392E8B25E40F13BBULL,
		0x2F178E3D71ADE0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x614F5E837C89CFEAULL,
		0x33DC47DFA48FAA63ULL,
		0x725D164BC81E2776ULL,
		0x5E2F1C7AE35BC1C4ULL
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
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EDBA57BDC496F2DULL,
		0xB37BF16561281FCAULL,
		0xF5FD44D0D8941AD9ULL,
		0x2DE362F813746EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB74AF7B892DE5AULL,
		0x66F7E2CAC2503F94ULL,
		0xEBFA89A1B12835B3ULL,
		0x5BC6C5F026E8DD91ULL
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
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DA4D496CFFF016DULL,
		0x54C2943FA6AED2FFULL,
		0xAD05DFF515F7CC11ULL,
		0x619BB7A6D63B775AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B49A92D9FFE02EDULL,
		0xA985287F4D5DA5FEULL,
		0x5A0BBFEA2BEF9822ULL,
		0x43376F4DAC76EEB5ULL
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
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75605B1ACB6F6A0AULL,
		0x633E63B0693CCF2DULL,
		0x94586C230DEAA694ULL,
		0x41E4EC404387B7B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAC0B63596DED427ULL,
		0xC67CC760D2799E5AULL,
		0x28B0D8461BD54D28ULL,
		0x03C9D880870F6F6DULL
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
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCF9B1B1A22F0F92ULL,
		0x0B9E1EEF14C99BF3ULL,
		0x4364CAE9892E0BCFULL,
		0x5D46CF3732B42329ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9F36363445E1F37ULL,
		0x173C3DDE299337E7ULL,
		0x86C995D3125C179EULL,
		0x3A8D9E6E65684652ULL
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
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE3286519D2B0C17ULL,
		0x40F5D58BB5072754ULL,
		0xD04C60EFC11BB49BULL,
		0x56AC8D27B69DEF33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C650CA33A561841ULL,
		0x81EBAB176A0E4EA9ULL,
		0xA098C1DF82376936ULL,
		0x2D591A4F6D3BDE67ULL
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
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96D4DCD865182FA8ULL,
		0x37D2CA2BDDA245EBULL,
		0x440B920A93813247ULL,
		0x6BD5230879436DDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DA9B9B0CA305F63ULL,
		0x6FA59457BB448BD7ULL,
		0x881724152702648EULL,
		0x57AA4610F286DBB6ULL
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
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1791ECF8584CC7F7ULL,
		0x9AFA3C93D80A2039ULL,
		0x3E595C76B982EE2EULL,
		0x4BEC947A2B6C560BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F23D9F0B0999001ULL,
		0x35F47927B0144072ULL,
		0x7CB2B8ED7305DC5DULL,
		0x17D928F456D8AC16ULL
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
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC98E3EBAA19F7F88ULL,
		0xC029B4A958BAAA6DULL,
		0xB6726D1005952BBEULL,
		0x4A25D3A9F1A83055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x931C7D75433EFF23ULL,
		0x80536952B17554DBULL,
		0x6CE4DA200B2A577DULL,
		0x144BA753E35060ABULL
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
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44F0B4B79E585D28ULL,
		0x65BAC5A10F0BAF69ULL,
		0xFB3481CA984A820EULL,
		0x69B4F70DB5E07374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E1696F3CB0BA63ULL,
		0xCB758B421E175ED2ULL,
		0xF66903953095041CULL,
		0x5369EE1B6BC0E6E9ULL
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
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x373EE99D3F03A23BULL,
		0xC3F32495DA1EF39FULL,
		0x00E892B748981E06ULL,
		0x4E3B7B8F60425D76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E7DD33A7E074489ULL,
		0x87E6492BB43DE73EULL,
		0x01D1256E91303C0DULL,
		0x1C76F71EC084BAECULL
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
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2607B3FF10BD47E9ULL,
		0x89A646A854499400ULL,
		0x71163C04B6EA5873ULL,
		0x22D64D3931C8C04AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0F67FE217A8FD2ULL,
		0x134C8D50A8932800ULL,
		0xE22C78096DD4B0E7ULL,
		0x45AC9A7263918094ULL
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
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78EECF372E2945C7ULL,
		0x3AA3825A760B3149ULL,
		0xCEC992F0C050C899ULL,
		0x552A5FE4FBB2BAACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DD9E6E5C528BA1ULL,
		0x754704B4EC166292ULL,
		0x9D9325E180A19132ULL,
		0x2A54BFC9F7657559ULL
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
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5D18249DE4E864EULL,
		0x665599932AC5AED3ULL,
		0x6B630710F5226498ULL,
		0x5C0E0DFB3A563F4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA30493BC9D0CAFULL,
		0xCCAB3326558B5DA7ULL,
		0xD6C60E21EA44C930ULL,
		0x381C1BF674AC7E98ULL
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
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B4D513E567D7CD8ULL,
		0x1E9BA5B3642CBDC2ULL,
		0x1EE77F507BCB7DCCULL,
		0x137341E0E63A01A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x969AA27CACFAF9B0ULL,
		0x3D374B66C8597B84ULL,
		0x3DCEFEA0F796FB98ULL,
		0x26E683C1CC740340ULL
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
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BA5529EDF16AFE0ULL,
		0x0CB9226C70F5527AULL,
		0xFDC720C1A5E8E8F8ULL,
		0x607866611380BC58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574AA53DBE2D5FD3ULL,
		0x197244D8E1EAA4F4ULL,
		0xFB8E41834BD1D1F0ULL,
		0x40F0CCC2270178B1ULL
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
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62FAA4D2293AFE5BULL,
		0xE1CA3D4BDEC13854ULL,
		0x6696C2C07BCC9223ULL,
		0x534AA1211E224540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F549A45275FCC9ULL,
		0xC3947A97BD8270A8ULL,
		0xCD2D8580F7992447ULL,
		0x269542423C448A80ULL
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
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAEA82298F69BAE1ULL,
		0x9A6F1D252986300DULL,
		0xA6BE5DE5EB0FBA62ULL,
		0x7CF539B662241CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D504531ED375D5ULL,
		0x34DE3A4A530C601BULL,
		0x4D7CBBCBD61F74C5ULL,
		0x79EA736CC44839BFULL
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
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5520A754D7D09B7ULL,
		0xF6C515C5340F61DBULL,
		0xF0D3B37EFBA288CFULL,
		0x717BFFE8B8826E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA414EA9AFA1381ULL,
		0xED8A2B8A681EC3B7ULL,
		0xE1A766FDF745119FULL,
		0x62F7FFD17104DCDFULL
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
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6605E6DDFBCC8C8ULL,
		0xDB0A6FD1E757168BULL,
		0xA287486781BCFF73ULL,
		0x461FD7E19B09EECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC0BCDBBF7991A3ULL,
		0xB614DFA3CEAE2D17ULL,
		0x450E90CF0379FEE7ULL,
		0x0C3FAFC33613DD99ULL
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
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13DEF71C75EA321DULL,
		0xBA73FC67E3E0E2FBULL,
		0xB74DF250DC55DD69ULL,
		0x648686364A9B852EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27BDEE38EBD4644DULL,
		0x74E7F8CFC7C1C5F6ULL,
		0x6E9BE4A1B8ABBAD3ULL,
		0x490D0C6C95370A5DULL
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
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8AF3133FB6E05BDULL,
		0xD011FFCC0E243991ULL,
		0xCA1FEC54C9FC30B8ULL,
		0x5DCF8B8249F521C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF15E6267F6DC0B8DULL,
		0xA023FF981C487323ULL,
		0x943FD8A993F86171ULL,
		0x3B9F170493EA4387ULL
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
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA587D01339D79EBBULL,
		0x1A8B5B21A5036EDCULL,
		0x9552089B202EFC59ULL,
		0x4C7EA576BE9CC1D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0FA02673AF3D89ULL,
		0x3516B6434A06DDB9ULL,
		0x2AA41136405DF8B2ULL,
		0x18FD4AED7D3983B1ULL
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
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D2C9C045BB86A1EULL,
		0xAA26BDAD7DD6482AULL,
		0x679C6805C5E8EF2EULL,
		0x66776292057E8524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A593808B770D44FULL,
		0x544D7B5AFBAC9054ULL,
		0xCF38D00B8BD1DE5DULL,
		0x4CEEC5240AFD0A48ULL
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
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAFFEB6237399A49ULL,
		0xDD28EA6AB3C4DFD3ULL,
		0x1FEF94AC5103B802ULL,
		0x108A4E38BFDBF762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FFD6C46E733492ULL,
		0xBA51D4D56789BFA7ULL,
		0x3FDF2958A2077005ULL,
		0x21149C717FB7EEC4ULL
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
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x393599E266B83077ULL,
		0x029547D08E810C3BULL,
		0x54A2CC8EEC2E4B6BULL,
		0x6606A79063AF5335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726B33C4CD706101ULL,
		0x052A8FA11D021876ULL,
		0xA945991DD85C96D6ULL,
		0x4C0D4F20C75EA66AULL
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
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB2246DC27290337ULL,
		0x227DFF0933BA342AULL,
		0x2148EEAFE18AF5F9ULL,
		0x765DD1C7C3160D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96448DB84E520681ULL,
		0x44FBFE1267746855ULL,
		0x4291DD5FC315EBF2ULL,
		0x6CBBA38F862C1A02ULL
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
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x497F496DFC35C812ULL,
		0xCBBD90C240B2DF42ULL,
		0xA4F3F0883950C1AEULL,
		0x3EEE9287DE84CF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92FE92DBF86B9024ULL,
		0x977B21848165BE84ULL,
		0x49E7E11072A1835DULL,
		0x7DDD250FBD099E23ULL
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
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C76D60D83F27AB7ULL,
		0xD0F186C793E7C42EULL,
		0xCA068BEBFF22872AULL,
		0x396AE13A62B804DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8EDAC1B07E4F56EULL,
		0xA1E30D8F27CF885CULL,
		0x940D17D7FE450E55ULL,
		0x72D5C274C57009BBULL
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
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF4F79378AB3078CULL,
		0x4C3E57708E1CD4B1ULL,
		0x3C4D57FF38485DBBULL,
		0x33A58DBE1A821CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E9EF26F15660F18ULL,
		0x987CAEE11C39A963ULL,
		0x789AAFFE7090BB76ULL,
		0x674B1B7C350439C4ULL
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
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x653089F8EBE2CAF9ULL,
		0x4775FAB73C03BF8BULL,
		0xF77AD3B022DF71BBULL,
		0x4B6B1A78683526E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA6113F1D7C59605ULL,
		0x8EEBF56E78077F16ULL,
		0xEEF5A76045BEE376ULL,
		0x16D634F0D06A4DD1ULL
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
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E9882E8A855E4F7ULL,
		0xF3FDF38F69FC3469ULL,
		0x4DED34E7BD8A0B1CULL,
		0x7CD3278FEB29A86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3105D150ABCA01ULL,
		0xE7FBE71ED3F868D2ULL,
		0x9BDA69CF7B141639ULL,
		0x79A64F1FD65350DEULL
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
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x751880AF53EE053AULL,
		0x6BDB32BA90ED43EEULL,
		0x82D0DCE22E468DE7ULL,
		0x3CB32F3079349394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA31015EA7DC0A74ULL,
		0xD7B6657521DA87DCULL,
		0x05A1B9C45C8D1BCEULL,
		0x79665E60F2692729ULL
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
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5102EEE66620E2C1ULL,
		0x4CB417ABB56A8A91ULL,
		0x8D8BB9194CF8C4EBULL,
		0x3DD14B52B64AAAF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA205DDCCCC41C582ULL,
		0x99682F576AD51522ULL,
		0x1B17723299F189D6ULL,
		0x7BA296A56C9555E1ULL
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
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E5942DBE378110BULL,
		0x7588F8661CA84B2BULL,
		0xEA57196FCAC30A37ULL,
		0x3A0348D96FB1F8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB285B7C6F02216ULL,
		0xEB11F0CC39509656ULL,
		0xD4AE32DF9586146EULL,
		0x740691B2DF63F1E9ULL
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
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x480942FECDE2B00FULL,
		0xD873AF9024DF505CULL,
		0x166F9DD01E0DC15AULL,
		0x3F36F273B2480553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x901285FD9BC5601EULL,
		0xB0E75F2049BEA0B8ULL,
		0x2CDF3BA03C1B82B5ULL,
		0x7E6DE4E764900AA6ULL
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
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCD3655B558D1D02ULL,
		0xA45C545AB0A77887ULL,
		0x5300C777148124B5ULL,
		0x09EE1652278BF936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99A6CAB6AB1A3A04ULL,
		0x48B8A8B5614EF10FULL,
		0xA6018EEE2902496BULL,
		0x13DC2CA44F17F26CULL
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
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ECB1C916F4A26EFULL,
		0x94959E32834CBAB3ULL,
		0x284684692B5F27B9ULL,
		0x100FBE367204AB13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D963922DE944DDEULL,
		0x292B3C6506997567ULL,
		0x508D08D256BE4F73ULL,
		0x201F7C6CE4095626ULL
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
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0293EE6683AB0C7AULL,
		0x29CC592CFFC3A098ULL,
		0xC100D55CD460F31BULL,
		0x5005330BF355977BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0527DCCD07561907ULL,
		0x5398B259FF874130ULL,
		0x8201AAB9A8C1E636ULL,
		0x200A6617E6AB2EF7ULL
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
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60AA17B87F243835ULL,
		0x9C641AC331F00510ULL,
		0x35F4493D30F282C0ULL,
		0x4257446B33072B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1542F70FE48707DULL,
		0x38C8358663E00A20ULL,
		0x6BE8927A61E50581ULL,
		0x04AE88D6660E5700ULL
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
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x202AE0E5E045F986ULL,
		0x84A84351994BA4F4ULL,
		0x43016ACC69C87E13ULL,
		0x448F2655798FC97FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4055C1CBC08BF31FULL,
		0x095086A3329749E8ULL,
		0x8602D598D390FC27ULL,
		0x091E4CAAF31F92FEULL
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
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFF5416EA1D0DCAFULL,
		0x2807595F5CB4E694ULL,
		0xC049159DBC7538C5ULL,
		0x4F1E6E74DFD1A945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFEA82DD43A1B971ULL,
		0x500EB2BEB969CD29ULL,
		0x80922B3B78EA718AULL,
		0x1E3CDCE9BFA3528BULL
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
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9855D3457E89AB30ULL,
		0x7845AD7B9232F99FULL,
		0x70F99AE75FFE7516ULL,
		0x361BDCF33E89A9C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30ABA68AFD135660ULL,
		0xF08B5AF72465F33FULL,
		0xE1F335CEBFFCEA2CULL,
		0x6C37B9E67D13538CULL
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
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x443E555928C01497ULL,
		0xCE2BB13534B9773BULL,
		0x47E375AEA6670828ULL,
		0x5B9BF9D554436227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x887CAAB251802941ULL,
		0x9C57626A6972EE76ULL,
		0x8FC6EB5D4CCE1051ULL,
		0x3737F3AAA886C44EULL
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
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8780B53C9B201E27ULL,
		0x8BA81C0E95061139ULL,
		0x3108865FB5253EBDULL,
		0x63E3787543C9662FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F016A7936403C61ULL,
		0x1750381D2A0C2273ULL,
		0x62110CBF6A4A7D7BULL,
		0x47C6F0EA8792CC5EULL
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
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x035B1F4C5F4BE18AULL,
		0xF6C624BB8C39B514ULL,
		0xB96268139D229668ULL,
		0x023465BFD1A98CECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B63E98BE97C314ULL,
		0xED8C497718736A28ULL,
		0x72C4D0273A452CD1ULL,
		0x0468CB7FA35319D9ULL
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
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C67E79C9ED3653FULL,
		0xFBC0939ADD014F94ULL,
		0x5E892846E3F18722ULL,
		0x0FD6DC4F01ADD0AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98CFCF393DA6CA7EULL,
		0xF7812735BA029F28ULL,
		0xBD12508DC7E30E45ULL,
		0x1FADB89E035BA154ULL
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
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x292903ADD029BE4DULL,
		0x52C675C7314736ADULL,
		0xFA8910E9C9ED2482ULL,
		0x4F0815975789B344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5252075BA0537CADULL,
		0xA58CEB8E628E6D5AULL,
		0xF51221D393DA4904ULL,
		0x1E102B2EAF136689ULL
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
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x506D3926FECB3CD3ULL,
		0xD799006FA4CBA948ULL,
		0x3CBCFA557B3F5D3DULL,
		0x10A84E4842BCBAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0DA724DFD9679A6ULL,
		0xAF3200DF49975290ULL,
		0x7979F4AAF67EBA7BULL,
		0x21509C90857975C4ULL
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
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}