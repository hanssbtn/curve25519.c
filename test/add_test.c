#include "tests.h"

int32_t curve25519_key_add_test(void) {
	printf("Add Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {
		0xCEB7840E8446D3FB,
		0x0059B3F359CB31CB,
		0x1229F73CD7392FB8,
		0x4146B329F1D26D27
	};
	curve25519_key_t k2 = {
		0x129B8BFC2AF4E945,
		0xD562C132DD7C981F,
		0x064A618AD0FD9C58,
		0x120D33FEB34C385F
	};
	curve25519_key_t k3 = {
		0xE153100AAF3BBD40,
		0xD5BC75263747C9EA,
		0x187458C7A836CC10,
		0x5353E728A51EA586
	};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x09B6BB4EBE8C36A1,
		0xA8F78B12AC1F2B25,
		0x3AB437B4021C015A,
		0x5CBE769E25B98544
	};
	k2 = (curve25519_key_t){
		0xC3C01ADFDB4B360C,
		0x2D5E1B16AE6BD7FB,
		0xBBB52735B5D64B9E,
		0x4A488BBAB2293316
	};
	k3 = (curve25519_key_t){
		0xCD76D62E99D76CC0,
		0xD655A6295A8B0320,
		0xF6695EE9B7F24CF8,
		0x27070258D7E2B85A
	};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xB39D09714A1970C4,
		0x7B77F08058A854DC,
		0x10E20F3FA8811BC9,
		0x26020696515AB580
	};
	k2 = (curve25519_key_t){
		0x03E09990DCE1CB29,
		0x7F4C60055DE998BC,
		0x9B6F74E986AD5565,
		0x10CCD55CD4FF06DC
	};
	k3 = (curve25519_key_t){
		0xB77DA30226FB3BED,
		0xFAC45085B691ED98,
		0xAC5184292F2E712E,
		0x36CEDBF32659BC5C
	};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC4DD2E12361ABDAB,
		0xE97F86481856DA40,
		0xE5ECE431C766328E,
		0x4A3CE97B2B9AAB0D
	};
	k2 = (curve25519_key_t){
		0x9C15D1269BC1B466,
		0xF305345A2F9128CE,
		0x326B3CB8507A452B,
		0x5FEC1468A64363F9
	};
	k3 = (curve25519_key_t){
		0x60F2FF38D1DC7224,
		0xDC84BAA247E8030F,
		0x185820EA17E077BA,
		0x2A28FDE3D1DE0F07
	};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x106531D19220C45C,
		0xC4DF8000F051D2FC,
		0x809490C70308FE53,
		0x149E08F681BD334C
	};
	k2 = (curve25519_key_t){
		0x7F7D58CB45C05E0B,
		0x69751E00DE66D378,
		0x4FEBF7D9497FD11E,
		0x19359068C9FEF1AA
	};
	k3 = (curve25519_key_t){
		0x8FE28A9CD7E12267,
		0x2E549E01CEB8A674,
		0xD08088A04C88CF72,
		0x2DD3995F4BBC24F6
	};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x3220333DBC11714A,
		0xB1BEDEE192610994,
		0x6314CBF434A20DE5,
		0x755EBFA1E51168BA
	};
	k2 = (curve25519_key_t){
		0x3210655F027F2C71,
		0xEB7CAC682AD65753,
		0x26B3230DE0EBA1FC,
		0x0A58ACD12F5D272B
	};
	k3 = (curve25519_key_t){
		0x6430989CBE909DBB,
		0x9D3B8B49BD3760E7,
		0x89C7EF02158DAFE2,
		0x7FB76C73146E8FE5
	};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x55CA5E3A37BF89F7,
		0xE76910CDB48ACC4F,
		0xD1748BC89467D97D,
		0x170271BE4D3DDE00
	};
	k2 = (curve25519_key_t){
		0x596EF0A2638BEF0F,
		0x6CDBE93267A74826,
		0xB7A63458E6BEF606,
		0x10B8758838BDCEAB
	};
	k3 = (curve25519_key_t){
		0xAF394EDC9B4B7906,
		0x5444FA001C321475,
		0x891AC0217B26CF84,
		0x27BAE74685FBACAC
	};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xCC50579A9CC019CB,
		0x2FECCE37BB6EB350,
		0x1CD74564FC33585B,
		0x5C1E059F833DF59E
	};
	k2 = (curve25519_key_t){
		0xB1AE6D0D81B0E3DC,
		0x2CB7D544F5DE1E65,
		0x99BD95852D723C19,
		0x0337E9DE65DBF21E
	};
	k3 = (curve25519_key_t){
		0x7DFEC4A81E70FDA7,
		0x5CA4A37CB14CD1B6,
		0xB694DAEA29A59474,
		0x5F55EF7DE919E7BC
	};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xEEB5713ECC0E53A2,
		0xCD5046FFB15DA078,
		0xE6ECDD7C3A97CCE7,
		0x1B07D601B8B9D9C5
	};
	k2 = (curve25519_key_t){
		0xDF7348E2DA2587C9,
		0xE28023F8C3E5F447,
		0xF41123355C03EFE4,
		0x2611E18EA48EE49C
	};
	k3 = (curve25519_key_t){
		0xCE28BA21A633DB6B,
		0xAFD06AF8754394C0,
		0xDAFE00B1969BBCCC,
		0x4119B7905D48BE62
	};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6D8D9730DC6E8EF2,
		0x6B1C1F71CE689A67,
		0xCC484BEDCF079E8E,
		0x1CB20D09723A8401
	};
	k2 = (curve25519_key_t){
		0xD46DEB110F06F44C,
		0x23B79378252F0FC1,
		0x01511D9C044A92A6,
		0x284146E0804A84A5
	};
	k3 = (curve25519_key_t){
		0x41FB8241EB75833E,
		0x8ED3B2E9F397AA29,
		0xCD996989D3523134,
		0x44F353E9F28508A6
	};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x2B43D0CBCC503D32,
		0x51955329BEF76207,
		0x7600D1191429F174,
		0x4B53F0A29CA2184B
	};
	k2 = (curve25519_key_t){
		0xC582925C484E2C1D,
		0x43F5A93090A183A0,
		0x28AFDDDDB415FA62,
		0x28791F2FCAE7C877
	};
	k3 = (curve25519_key_t){
		0xF0C66328149E694F,
		0x958AFC5A4F98E5A7,
		0x9EB0AEF6C83FEBD6,
		0x73CD0FD26789E0C2
	};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x2A52289DB420E655,
		0xF3EEBB96345E5157,
		0xCB1C801F0134BA6E,
		0x2DCEE2D69A55095B
	};
	k2 = (curve25519_key_t){
		0x563CEBBBF1047F98,
		0xF5513B7FED631B60,
		0xDFBD0294A9D5C769,
		0x3498A00355B5FA04
	};
	k3 = (curve25519_key_t){
		0x808F1459A52565ED,
		0xE93FF71621C16CB7,
		0xAAD982B3AB0A81D8,
		0x626782D9F00B0360
	};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC1429F7EC371D079,
		0xC3A2962BD80C7C05,
		0x574A4D08DD0D88AF,
		0x185D61CF9483351A
	};
	k2 = (curve25519_key_t){
		0x6466825E26E342EE,
		0x32849D8F45E063D5,
		0xB07E40076C915549,
		0x34DEE10E5568142E
	};
	k3 = (curve25519_key_t){
		0x25A921DCEA551367,
		0xF62733BB1DECDFDB,
		0x07C88D10499EDDF8,
		0x4D3C42DDE9EB4949
	};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6AE28602E9B60924,
		0x3F28AB0C3326D926,
		0xE0141A4356855B3B,
		0x65E8EFB7F756BAF6
	};
	k2 = (curve25519_key_t){
		0x16E4F3F04D2127BD,
		0xC7A74D7D105F2953,
		0xB7337A4251F2D6DF,
		0x6754C82A86D08896
	};
	k3 = (curve25519_key_t){
		0x81C779F336D730F4,
		0x06CFF88943860279,
		0x97479485A878321B,
		0x4D3DB7E27E27438D
	};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA221C317787CFB16,
		0x3E3074A2591B72F9,
		0x89091C7C84862B44,
		0x40DF0A2195F703B6
	};
	k2 = (curve25519_key_t){
		0xCD8D67685CEBCDAC,
		0x31DB6305930F3EB5,
		0x1C422B51F921BABA,
		0x045EAA4D2DCEF707
	};
	k3 = (curve25519_key_t){
		0x6FAF2A7FD568C8C2,
		0x700BD7A7EC2AB1AF,
		0xA54B47CE7DA7E5FE,
		0x453DB46EC3C5FABD
	};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x82311BADC57B1F75,
		0xE76001D8D03C93F5,
		0xA7308B7990B10EA7,
		0x6A9DA486CAE10BF1
	};
	k2 = (curve25519_key_t){
		0xF4E2D80F28303571,
		0x4DEBEBAE725D2AE9,
		0x469F6498623458CA,
		0x6B2A471DD7A3AA7B
	};
	k3 = (curve25519_key_t){
		0x7713F3BCEDAB54F9,
		0x354BED874299BEDF,
		0xEDCFF011F2E56772,
		0x55C7EBA4A284B66C
	};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD036563EF8CCA506,
		0x21A0B194B1DDED8B,
		0x34CBB88B288D8600,
		0x62FE96F7AF33C69C
	};
	k2 = (curve25519_key_t){
		0x169C9F85471E5BC2,
		0x3C6951CC450D3624,
		0x7931114B068191B9,
		0x5A47A9B04DE60AD0
	};
	k3 = (curve25519_key_t){
		0xE6D2F5C43FEB00DB,
		0x5E0A0360F6EB23AF,
		0xADFCC9D62F0F17B9,
		0x3D4640A7FD19D16C
	};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x92D2F736A0B29F90,
		0x73E0773DE2218AFA,
		0xDA032EC90302A20C,
		0x01297C712941F75E
	};
	k2 = (curve25519_key_t){
		0xEA96B77353AD1AE2,
		0x524208B4314B0D74,
		0x8B212E1751AD50D5,
		0x724CF76E03F194F8
	};
	k3 = (curve25519_key_t){
		0x7D69AEA9F45FBA72,
		0xC6227FF2136C986F,
		0x65245CE054AFF2E1,
		0x737673DF2D338C57
	};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xF4BC84880B02AE4B,
		0x3CBB5A3F4A043CA9,
		0xBCA015A1D56ED81C,
		0x20F94B769B114EC0
	};
	k2 = (curve25519_key_t){
		0x4FA2591ED9B3B63B,
		0x01BCABDE6778F70B,
		0x20EE9C8536CADC40,
		0x6B2F8A4F2B6B7752
	};
	k3 = (curve25519_key_t){
		0x445EDDA6E4B66499,
		0x3E78061DB17D33B5,
		0xDD8EB2270C39B45C,
		0x0C28D5C5C67CC612
	};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x3DD219A682911B48,
		0x75FB2AD93586E988,
		0x4FFA35FB33AB2DC2,
		0x39A8157938E627A9
	};
	k2 = (curve25519_key_t){
		0xF1749420985A0806,
		0x7262D45433956FBE,
		0x0BAAFB708B2B92F8,
		0x786B7A30C845F58A
	};
	k3 = (curve25519_key_t){
		0x2F46ADC71AEB2361,
		0xE85DFF2D691C5947,
		0x5BA5316BBED6C0BA,
		0x32138FAA012C1D33
	};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA4B51EEBD0E8C786,
		0x67818A1B0BDA0EF0,
		0x57E0B0E231669B8C,
		0x516144EA6A9E04BE
	};
	k2 = (curve25519_key_t){
		0xA9581E5A6B7390ED,
		0xFB3D59BE9D145F11,
		0x009864976DF73A83,
		0x4CE4255AEEC54596
	};
	k3 = (curve25519_key_t){
		0x4E0D3D463C5C5886,
		0x62BEE3D9A8EE6E02,
		0x587915799F5DD610,
		0x1E456A4559634A54
	};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x005A3584606C404B,
		0xC40E1038CB71576F,
		0x1803DA26DD090FF6,
		0x0839DC8639C6E131
	};
	k2 = (curve25519_key_t){
		0x097673C7ADB2CC5A,
		0x11887EF46056E987,
		0x417A0DE23115164D,
		0x10BF22FB515A0696
	};
	k3 = (curve25519_key_t){
		0x09D0A94C0E1F0CA5,
		0xD5968F2D2BC840F6,
		0x597DE8090E1E2643,
		0x18F8FF818B20E7C7
	};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x7E0A9C7B865A2CAB,
		0x2D0261136C69E492,
		0x79D0F56AEA87C991,
		0x3069E9B49CFB5EA6
	};
	k2 = (curve25519_key_t){
		0xF3D25A4B3040112F,
		0x4AC929EAE3986ED6,
		0xED0B922B3DEB4CDC,
		0x0F477135B449235B
	};
	k3 = (curve25519_key_t){
		0x71DCF6C6B69A3DDA,
		0x77CB8AFE50025369,
		0x66DC87962873166D,
		0x3FB15AEA51448202
	};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE01B50E5C6BFC149,
		0x2E65255F0929B15C,
		0xC20858545C0C516E,
		0x114801699F8BF7A7
	};
	k2 = (curve25519_key_t){
		0xE685BEAD4479C728,
		0x13E829ADEAA8B206,
		0x10A415E1FA870911,
		0x598AFFAC09589764
	};
	k3 = (curve25519_key_t){
		0xC6A10F930B398871,
		0x424D4F0CF3D26363,
		0xD2AC6E3656935A7F,
		0x6AD30115A8E48F0B
	};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x15185F6DA30304F0,
		0x7574DB621AD5F635,
		0xB20A3BFE4ED8DBD4,
		0x767D293BC3B2E50B
	};
	k2 = (curve25519_key_t){
		0x0FB54A748600C64D,
		0x721C00F81FB290EE,
		0xAD7A73739A795A54,
		0x62588B856B248ECE
	};
	k3 = (curve25519_key_t){
		0x24CDA9E22903CB50,
		0xE790DC5A3A888723,
		0x5F84AF71E9523628,
		0x58D5B4C12ED773DA
	};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x0732D4B26D70C5EE,
		0xDB3029FD1CEF1CAA,
		0xBE081BC9487BE69C,
		0x45D96F079A6C5DBF
	};
	k2 = (curve25519_key_t){
		0xF8C6971259D5D130,
		0x3D1DBD8242EF9578,
		0x1444ABE74A121E7E,
		0x7B5D4FC8A7B9C6BE
	};
	k3 = (curve25519_key_t){
		0xFFF96BC4C7469731,
		0x184DE77F5FDEB222,
		0xD24CC7B0928E051B,
		0x4136BED04226247D
	};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE5A43242E75BBA48,
		0x80968B174B5CFD73,
		0x6C1671A7F24CBE21,
		0x343E78ACB808C209
	};
	k2 = (curve25519_key_t){
		0xAA1E98025D5A76B5,
		0x3A1968F7749D0A9B,
		0xB7CBB25C92C4D4BF,
		0x163F4AB48C5F493E
	};
	k3 = (curve25519_key_t){
		0x8FC2CA4544B630FD,
		0xBAAFF40EBFFA080F,
		0x23E22404851192E0,
		0x4A7DC36144680B48
	};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x34A5B1ECB2BE07B5,
		0xB1EC6207D59ABBED,
		0xBDE0C02E500AB22D,
		0x12617D86E7297EC7
	};
	k2 = (curve25519_key_t){
		0x30B65B8786EA1872,
		0xDAC57252691FFD9C,
		0x3A7004652C50F146,
		0x21EEC641A3ACF700
	};
	k3 = (curve25519_key_t){
		0x655C0D7439A82027,
		0x8CB1D45A3EBAB989,
		0xF850C4937C5BA374,
		0x345043C88AD675C7
	};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x856711EC0C45CD6E,
		0x804C5422D0A28D2B,
		0x27156CD7B1B2B861,
		0x23D072294D4D98F5
	};
	k2 = (curve25519_key_t){
		0x5900327225C66486,
		0x32E860B2359BF78F,
		0x975468CE3509B8D0,
		0x3663DD7C9AAB8205
	};
	k3 = (curve25519_key_t){
		0xDE67445E320C31F4,
		0xB334B4D5063E84BA,
		0xBE69D5A5E6BC7131,
		0x5A344FA5E7F91AFA
	};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x8C9B84EF128BDB87,
		0x8EDDF0F52FC12F3C,
		0xE8D3E89EB86E2BC6,
		0x33BE3977F04BA289
	};
	k2 = (curve25519_key_t){
		0xDBAB3591A77D85D1,
		0x1C0355EB53A19827,
		0x11E14DE57B3C4C3B,
		0x08E8700E156BA98A
	};
	k3 = (curve25519_key_t){
		0x6846BA80BA096158,
		0xAAE146E08362C764,
		0xFAB5368433AA7801,
		0x3CA6A98605B74C13
	};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x1F04720AE0E4ACB3,
		0xD13F1CB825809C82,
		0x42722BF7E28FE818,
		0x01D39753850B96F5
	};
	k2 = (curve25519_key_t){
		0x43F070306ECD1F0B,
		0x3295FDCFF8A48992,
		0x568D582F83BAFF6A,
		0x138F849FAFAE8EDB
	};
	k3 = (curve25519_key_t){
		0x62F4E23B4FB1CBBE,
		0x03D51A881E252614,
		0x98FF8427664AE783,
		0x15631BF334BA25D0
	};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x94447AE5AEEEC563,
		0xD86E578BDFED6F3C,
		0xD68717425CC44740,
		0x6A059D8AFBEAA4ED
	};
	k2 = (curve25519_key_t){
		0x5508FE9B98DAE2EE,
		0x58670F1A454F2D5E,
		0xA037D2711A1EBA8F,
		0x49B5454EDAE5E704
	};
	k3 = (curve25519_key_t){
		0xE94D798147C9A864,
		0x30D566A6253C9C9A,
		0x76BEE9B376E301D0,
		0x33BAE2D9D6D08BF2
	};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x0D15BB6AEF2A4FB8,
		0x289E75C08CD3D553,
		0xF1B447B096C4F1AF,
		0x0DDC6719F1C61F89
	};
	k2 = (curve25519_key_t){
		0x30AEAF3A9B285347,
		0x827AF0B3FC40D812,
		0xF476EC164B189C5B,
		0x19101B638A418C7E
	};
	k3 = (curve25519_key_t){
		0x3DC46AA58A52A2FF,
		0xAB1966748914AD65,
		0xE62B33C6E1DD8E0A,
		0x26EC827D7C07AC08
	};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x442A9EC94524DDF7,
		0x46CA4ABF74D60147,
		0xB9CE6FD9CDF0FA32,
		0x4120C46AB162061D
	};
	k2 = (curve25519_key_t){
		0xA430EE0E419D97BE,
		0xFC7C7F26D33384F7,
		0xA0157A4AE5801D92,
		0x3E4B0FBC0B5A957A
	};
	k3 = (curve25519_key_t){
		0xE85B8CD786C275B5,
		0x4346C9E64809863E,
		0x59E3EA24B37117C5,
		0x7F6BD426BCBC9B98
	};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xDC6429B417B8A438,
		0xDFC2A97FC02590BD,
		0x490AFC95E2503A72,
		0x58650A7B9B2AB0B4
	};
	k2 = (curve25519_key_t){
		0xD00B1EE8A4812666,
		0xEC3E17438819B56D,
		0x97D00E782F560111,
		0x790627F2303F3CE1
	};
	k3 = (curve25519_key_t){
		0xAC6F489CBC39CAB1,
		0xCC00C0C3483F462B,
		0xE0DB0B0E11A63B84,
		0x516B326DCB69ED95
	};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6F67BF70C2B93704,
		0x38547EE60A4453C2,
		0x18DB1E32433CB6B3,
		0x2B927B6008A2D82D
	};
	k2 = (curve25519_key_t){
		0x534905F6A554E4C9,
		0x75BA686C30B8A0F3,
		0x44F569E2B54C0C2A,
		0x242AFE80A3BBFE9E
	};
	k3 = (curve25519_key_t){
		0xC2B0C567680E1BCD,
		0xAE0EE7523AFCF4B5,
		0x5DD08814F888C2DD,
		0x4FBD79E0AC5ED6CB
	};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x67E988E0BBD0530D,
		0x627481A7F916650C,
		0x9A3C5D59E45082C2,
		0x6908BC4D017B8239
	};
	k2 = (curve25519_key_t){
		0xD175DEBCEC24D078,
		0xBE8733747E5250C5,
		0x7912EFAC720F70A8,
		0x326568EC75CD1576
	};
	k3 = (curve25519_key_t){
		0x395F679DA7F52398,
		0x20FBB51C7768B5D2,
		0x134F4D06565FF36B,
		0x1B6E2539774897B0
	};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x2F6EA4A82F99BF30,
		0x3983CE471A8B8F59,
		0x658ED192451E9679,
		0x1D7356E972DD6133
	};
	k2 = (curve25519_key_t){
		0xBC755FDF9D8F3A09,
		0x56C71909B8D8961D,
		0x6D38776DF8DBD649,
		0x61B33B4756ED099A
	};
	k3 = (curve25519_key_t){
		0xEBE40487CD28F939,
		0x904AE750D3642576,
		0xD2C749003DFA6CC2,
		0x7F269230C9CA6ACD
	};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x0758C9585BBD06FD,
		0x7FB8181D5859AF19,
		0xFE61E7C0F6FCED3A,
		0x52C29E4C3BC14C4E
	};
	k2 = (curve25519_key_t){
		0x1EAAA3ECC86A7597,
		0x99B94E45F4FC5FBD,
		0x92231EA42D09244F,
		0x4C922E1BE496E9D4
	};
	k3 = (curve25519_key_t){
		0x26036D4524277CA7,
		0x197166634D560ED6,
		0x908506652406118A,
		0x1F54CC6820583623
	};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD6FAAB6C33E1C7D7,
		0xB53CB63A7EE2D950,
		0xCCC274C8DCFCA353,
		0x5FC7263DF1A8FBAE
	};
	k2 = (curve25519_key_t){
		0x46F86D3AA53C5B60,
		0x1B47F9035407FC8C,
		0x9B78885B4CE85B5C,
		0x0F899650629189D6
	};
	k3 = (curve25519_key_t){
		0x1DF318A6D91E2337,
		0xD084AF3DD2EAD5DD,
		0x683AFD2429E4FEAF,
		0x6F50BC8E543A8585
	};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x707E7BDEF86DA4CF,
		0xDA78E0AED5D7FD3D,
		0x6375ECA515E8769D,
		0x6A395169057DD6F5
	};
	k2 = (curve25519_key_t){
		0x9208DBB0E932B970,
		0xAFDEB4E8FF097201,
		0xDBB6CB9F48FA5057,
		0x5712AC58A51F5BA2
	};
	k3 = (curve25519_key_t){
		0x0287578FE1A05E52,
		0x8A579597D4E16F3F,
		0x3F2CB8445EE2C6F5,
		0x414BFDC1AA9D3298
	};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD0F997A5EDE786D5,
		0x97DECE5992B47CB1,
		0x9DEA8C9AF7983029,
		0x49C3BB5E33BDC5D1
	};
	k2 = (curve25519_key_t){
		0x18112223043AFAEC,
		0xFB4259B66537FF71,
		0x1E17F426C64216EA,
		0x027B5ED378CA4BA6
	};
	k3 = (curve25519_key_t){
		0xE90AB9C8F22281C1,
		0x9321280FF7EC7C22,
		0xBC0280C1BDDA4714,
		0x4C3F1A31AC881177
	};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD9B767A5909A1D57,
		0xD4238F1C3531EDF4,
		0xF0A78D1F5AEB182A,
		0x780F46C5815D549C
	};
	k2 = (curve25519_key_t){
		0xF5CD6FC04AE07145,
		0x6D76337077A332F1,
		0x96AF977FE06A59F0,
		0x3809FBB042EDECF3
	};
	k3 = (curve25519_key_t){
		0xCF84D765DB7A8EAF,
		0x4199C28CACD520E6,
		0x8757249F3B55721B,
		0x30194275C44B4190
	};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xCA1E8C153D5EA8BB,
		0xE68648C52DF96EC1,
		0xF2D02C6063160AB4,
		0x7033EADC4AAB5609
	};
	k2 = (curve25519_key_t){
		0xB6770C7F8CE7C263,
		0x2C6A369B591994B0,
		0xF05C513B34BED485,
		0x05F81864E3374D3D
	};
	k3 = (curve25519_key_t){
		0x80959894CA466B1E,
		0x12F07F6087130372,
		0xE32C7D9B97D4DF3A,
		0x762C03412DE2A347
	};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE05843404949DC1C,
		0xA71CAC6B2669D620,
		0x06FA946A673DBC95,
		0x211A5EDDEC4D7F1F
	};
	k2 = (curve25519_key_t){
		0x5214210807938FFE,
		0xC9FC5EED4FBF171A,
		0x96A2EC24F59C15F2,
		0x6402D108125D5657
	};
	k3 = (curve25519_key_t){
		0x326C644850DD6C2D,
		0x71190B587628ED3B,
		0x9D9D808F5CD9D288,
		0x051D2FE5FEAAD576
	};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x3ED5763A96FA1D96,
		0x606611F3E3FB9C80,
		0x8618EE2694F16042,
		0x0E90F16388327423
	};
	k2 = (curve25519_key_t){
		0x66C07A80523B8C18,
		0xF4880312EA4690D1,
		0x208F2025C6EA4FB2,
		0x24DB5F3304CD9C2A
	};
	k3 = (curve25519_key_t){
		0xA595F0BAE935A9AE,
		0x54EE1506CE422D51,
		0xA6A80E4C5BDBAFF5,
		0x336C50968D00104D
	};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6298C71E9F76CE66,
		0xD9615115204A6CD7,
		0x48FEAFF988FA0F79,
		0x7405E18D22BA9F4C
	};
	k2 = (curve25519_key_t){
		0x8C7280A4D4B237D5,
		0x7B0001DCC22DA391,
		0x2A174033B4BFFA02,
		0x1D296DD8F1076C25
	};
	k3 = (curve25519_key_t){
		0xEF0B47C37429064E,
		0x546152F1E2781068,
		0x7315F02D3DBA097C,
		0x112F4F6613C20B71
	};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x7D038B30BFCD8A38,
		0x05973C69FC57A56E,
		0x8BDA9DB15E9A2E8F,
		0x7400B458B25E6AB3
	};
	k2 = (curve25519_key_t){
		0x44D5F4AFBCA09C9D,
		0x2E1F492CA6F1517B,
		0xD8347860192E6211,
		0x6C3D3B4985995093
	};
	k3 = (curve25519_key_t){
		0xC1D97FE07C6E26E8,
		0x33B68596A348F6E9,
		0x640F161177C890A0,
		0x603DEFA237F7BB47
	};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x0A619C8A5EA5B722,
		0x55C813DE4227AAB5,
		0x976C1DA12A37359F,
		0x0B421AB0D200865D
	};
	k2 = (curve25519_key_t){
		0x61D2F886A64628C3,
		0xC2311B25C3A65148,
		0xFC6E22A2800E2144,
		0x5E3D13D89BAF4596
	};
	k3 = (curve25519_key_t){
		0x6C34951104EBDFE5,
		0x17F92F0405CDFBFD,
		0x93DA4043AA4556E4,
		0x697F2E896DAFCBF4
	};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x203D27F57808291D,
		0x9DD0C761EDD5D060,
		0x25C73F53A8E639D5,
		0x461A79FF679750E4
	};
	k2 = (curve25519_key_t){
		0x477DAD5713BF0075,
		0x78A094F12963F67A,
		0x3C9FBA54544C4705,
		0x69B9DB7BD992B5BE
	};
	k3 = (curve25519_key_t){
		0x67BAD54C8BC729A5,
		0x16715C531739C6DA,
		0x6266F9A7FD3280DB,
		0x2FD4557B412A06A2
	};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xB50EC51348445B9D,
		0xF33834E6E16CD527,
		0xAFD843912AE42386,
		0x0B641CA44000A4A8
	};
	k2 = (curve25519_key_t){
		0x14D1CE06D38AE87A,
		0x93F17C1E84F02CE6,
		0xE3A2F84D6068C1CF,
		0x73397CBEC5F0027B
	};
	k3 = (curve25519_key_t){
		0xC9E0931A1BCF4417,
		0x8729B105665D020D,
		0x937B3BDE8B4CE556,
		0x7E9D996305F0A724
	};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x750FE48CE350D73E,
		0x720C0EA347741609,
		0xD30639A7A4B24BFB,
		0x4332BFCA818927A9
	};
	k2 = (curve25519_key_t){
		0x7383843BD3D91540,
		0xB5C4AE6D605048B6,
		0xD2FE0467E9DC78B9,
		0x100F70D1B599BECB
	};
	k3 = (curve25519_key_t){
		0xE89368C8B729EC7E,
		0x27D0BD10A7C45EBF,
		0xA6043E0F8E8EC4B5,
		0x5342309C3722E675
	};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x23AF27FD2400D2CA,
		0x33999F3956E18039,
		0x900AB65CB213E4A9,
		0x3E8B889FA6CA912E
	};
	k2 = (curve25519_key_t){
		0x8165A545F333B003,
		0xC8D4C96079BE0FD9,
		0x4CF66DAEDC4D8C5B,
		0x7F17020C22D990EB
	};
	k3 = (curve25519_key_t){
		0xA514CD43173482E0,
		0xFC6E6899D09F9012,
		0xDD01240B8E617104,
		0x3DA28AABC9A42219
	};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x07E66E9717FB5A94,
		0x3F31F8829146B830,
		0x8A66B29D64AEC02F,
		0x215379A9839C3319
	};
	k2 = (curve25519_key_t){
		0x8E77A1AB84D33953,
		0xBF6776465E731860,
		0x865FAB20E7D4B658,
		0x0C1801FCE08ED6DC
	};
	k3 = (curve25519_key_t){
		0x965E10429CCE93E7,
		0xFE996EC8EFB9D090,
		0x10C65DBE4C837687,
		0x2D6B7BA6642B09F6
	};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x464C7AD5377A568B,
		0x52C0CEDBA733A07E,
		0xFC2ACEEF3BE33523,
		0x27EF18E2A10C0923
	};
	k2 = (curve25519_key_t){
		0x568991FEF1E1D76E,
		0x3BF6496B25DC7EB3,
		0x9B893561731DE1E3,
		0x4611DBC40F2B32B7
	};
	k3 = (curve25519_key_t){
		0x9CD60CD4295C2DF9,
		0x8EB71846CD101F31,
		0x97B40450AF011706,
		0x6E00F4A6B0373BDB
	};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x07FCEEE494FE10DD,
		0x39DB5D0BF1DDA415,
		0x88040DFC1D8FE72D,
		0x7712F8763103A0CA
	};
	k2 = (curve25519_key_t){
		0xCEFDC5BBAE5110BF,
		0x78D9DCD1F60FDB0F,
		0xE6669B3101D2C210,
		0x1711E129DC4422EE
	};
	k3 = (curve25519_key_t){
		0xD6FAB4A0434F21AF,
		0xB2B539DDE7ED7F24,
		0x6E6AA92D1F62A93D,
		0x0E24D9A00D47C3B9
	};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xCFB6A3C021B6F28F,
		0xBA1DA2CA4AB02843,
		0x0BEA5D45BA2CC327,
		0x49A947A14CF13BF5
	};
	k2 = (curve25519_key_t){
		0x57A67D78FB33BC91,
		0xDECC0EAFC4AD4EFF,
		0x5EE526EB90A5307C,
		0x357D06C92B471A42
	};
	k3 = (curve25519_key_t){
		0x275D21391CEAAF20,
		0x98E9B17A0F5D7743,
		0x6ACF84314AD1F3A4,
		0x7F264E6A78385637
	};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x927A128BEC2D4998,
		0x4B9567306E4FD5A0,
		0x87FD240B30F37AE3,
		0x3BAD1C386F7D5E56
	};
	k2 = (curve25519_key_t){
		0xEC001D891CEE0F14,
		0xAF4EDEC3747C071E,
		0x4E999ADD66DD5F8A,
		0x3647D8FA72F31D36
	};
	k3 = (curve25519_key_t){
		0x7E7A3015091B58AC,
		0xFAE445F3E2CBDCBF,
		0xD696BEE897D0DA6D,
		0x71F4F532E2707B8C
	};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xBB64311DA6417B68,
		0x7D14099FAB73149C,
		0x6A3B60B599346F59,
		0x712E05EAD096C8C0
	};
	k2 = (curve25519_key_t){
		0xB95C7A7F15E82CAC,
		0x4EEA492C3A37D839,
		0x63566E647D0F3283,
		0x38C80F430E8E10ED
	};
	k3 = (curve25519_key_t){
		0x74C0AB9CBC29A827,
		0xCBFE52CBE5AAECD6,
		0xCD91CF1A1643A1DC,
		0x29F6152DDF24D9AD
	};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x007B555D0916F4E3,
		0x9D53D49F68866714,
		0x112A8B78D4D68FFE,
		0x4E616AF712B2999F
	};
	k2 = (curve25519_key_t){
		0xA830804071221DA7,
		0x003D75E6FE9DD7D1,
		0xEFF8D224E8B06704,
		0x4A01BD1043AA0D2B
	};
	k3 = (curve25519_key_t){
		0xA8ABD59D7A39129D,
		0x9D914A8667243EE5,
		0x01235D9DBD86F702,
		0x18632807565CA6CB
	};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE39E8EAE0E5655DA,
		0x6CCD43D2129FFBB6,
		0x5C13546141F5FD1F,
		0x62DE0BEB5577AD54
	};
	k2 = (curve25519_key_t){
		0xAF55A07EB0A1CDA3,
		0x31AD56C8B7AEC9AC,
		0x2230A2F6B6EF3894,
		0x7B9A775C187D6A20
	};
	k3 = (curve25519_key_t){
		0x92F42F2CBEF82390,
		0x9E7A9A9ACA4EC563,
		0x7E43F757F8E535B3,
		0x5E7883476DF51774
	};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC1AE2A826E9E4CC0,
		0xB13A3C1D1C6E4C60,
		0xB613BA7AEF9C9F98,
		0x0A72ADA324E2AF63
	};
	k2 = (curve25519_key_t){
		0xD78654DD115950C7,
		0xD2BC4F49E762592C,
		0x9C583DFCD2E27DD6,
		0x30ED946DBC15EDDC
	};
	k3 = (curve25519_key_t){
		0x99347F5F7FF79D87,
		0x83F68B6703D0A58D,
		0x526BF877C27F1D6F,
		0x3B604210E0F89D40
	};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x2F68E62493541353,
		0xD63D5A1641EB4396,
		0x6FDCADE02A0A957B,
		0x496BC68DA638517F
	};
	k2 = (curve25519_key_t){
		0xF347E35A440FAC12,
		0x9A2E0548CD7EBD1D,
		0x89F1908DAD276616,
		0x5F1885CF803F1EC1
	};
	k3 = (curve25519_key_t){
		0x22B0C97ED763BF78,
		0x706B5F5F0F6A00B4,
		0xF9CE3E6DD731FB92,
		0x28844C5D26777040
	};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x49C5A94CA4A83146,
		0x961E6E3E20E242B0,
		0xE0DDE01114BD7C6B,
		0x4AFF23F565D75A32
	};
	k2 = (curve25519_key_t){
		0xCEA671A97BB41D0A,
		0xF476622B32437716,
		0x61175AEDA9D446E2,
		0x31A730FCFFF0986C
	};
	k3 = (curve25519_key_t){
		0x186C1AF6205C4E50,
		0x8A94D0695325B9C7,
		0x41F53AFEBE91C34E,
		0x7CA654F265C7F29F
	};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x7543570240F39270,
		0x70B98F742337AA00,
		0x8241B97E51CD038F,
		0x12A1436AA64D678A
	};
	k2 = (curve25519_key_t){
		0x7420EEC897DEA49B,
		0x6E7DFDE744E3E767,
		0x18857D1AA0335C8C,
		0x3210511EC412B4A9
	};
	k3 = (curve25519_key_t){
		0xE96445CAD8D2370B,
		0xDF378D5B681B9167,
		0x9AC73698F200601B,
		0x44B194896A601C33
	};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE2C2C02CF22A918D,
		0x192A846CE10BB462,
		0xC5126055CDEED765,
		0x0478FEB107EB61CB
	};
	k2 = (curve25519_key_t){
		0x356D39075F804284,
		0x2E55868032ADD99C,
		0x55620DE7F022D7CD,
		0x67DADF7C4D155B04
	};
	k3 = (curve25519_key_t){
		0x182FF93451AAD411,
		0x47800AED13B98DFF,
		0x1A746E3DBE11AF32,
		0x6C53DE2D5500BCD0
	};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x73011DA1203822BD,
		0x7B636AF187EE4F17,
		0x6CEB99345A281BB7,
		0x6F4B6A5216FE6F6F
	};
	k2 = (curve25519_key_t){
		0xF2992317522610CB,
		0xE06DC28E320EC446,
		0xF9ADCDA1507B883E,
		0x299FBE999FD5B73D
	};
	k3 = (curve25519_key_t){
		0x659A40B8725E339B,
		0x5BD12D7FB9FD135E,
		0x669966D5AAA3A3F6,
		0x18EB28EBB6D426AD
	};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE57A9D42BF7F1132,
		0x360CECE67635361C,
		0xAD24CE326F3082AB,
		0x02B292933AEED1DB
	};
	k2 = (curve25519_key_t){
		0xE5541AD66AAA944A,
		0x9A9C55D3323D4B76,
		0x0EEFD7D0580C0331,
		0x5D3A3E317CDF97DA
	};
	k3 = (curve25519_key_t){
		0xCACEB8192A29A57C,
		0xD0A942B9A8728193,
		0xBC14A602C73C85DC,
		0x5FECD0C4B7CE69B5
	};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x325F410EF39A3608,
		0x3D7FD6EDDC9179B6,
		0xDDD0754BE3ED9268,
		0x06F8215C0F347223
	};
	k2 = (curve25519_key_t){
		0xEE08180C00BCDA11,
		0x7FCD35E3A41E89AB,
		0xD06074FDEC4E5EC1,
		0x013FB7AE0500B785
	};
	k3 = (curve25519_key_t){
		0x2067591AF4571019,
		0xBD4D0CD180B00362,
		0xAE30EA49D03BF129,
		0x0837D90A143529A9
	};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x1F2CD18EF673443A,
		0xA16DF92406F6B70F,
		0x0F950D9CA8807507,
		0x2CDD4525C9CBC35C
	};
	k2 = (curve25519_key_t){
		0xB31D9750FCDD11AC,
		0xCE0F06799E28620D,
		0x4A7CEA8B42902166,
		0x7DB44B2CFBB32135
	};
	k3 = (curve25519_key_t){
		0xD24A68DFF35055F9,
		0x6F7CFF9DA51F191C,
		0x5A11F827EB10966E,
		0x2A919052C57EE491
	};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xEFC993AE6CF43E39,
		0x00D0EEAE028A9087,
		0x1E2D80E6B31D355B,
		0x514F778055F0EF3D
	};
	k2 = (curve25519_key_t){
		0x495A5090BBEF85A1,
		0x8509285269DF76B4,
		0x215D0754AE957643,
		0x4E6ED170BDC11074
	};
	k3 = (curve25519_key_t){
		0x3923E43F28E3C3ED,
		0x85DA17006C6A073C,
		0x3F8A883B61B2AB9E,
		0x1FBE48F113B1FFB1
	};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xA9C7F811911CE0C2,
		0xDDA5FF21395EB6BB,
		0xF2109F4BF508B6B0,
		0x269DED4EBBB5B5C6
	};
	k2 = (curve25519_key_t){
		0x07B2A22D8C89C66A,
		0x17F29A9439397DCB,
		0x499033DB30D322F8,
		0x79C3C2128A95A0E6
	};
	k3 = (curve25519_key_t){
		0xB17A9A3F1DA6A73F,
		0xF59899B572983486,
		0x3BA0D32725DBD9A8,
		0x2061AF61464B56AD
	};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x525607A6A9D96165,
		0x68CA7DD00B364E29,
		0x1CCEC85853634349,
		0x45F6CFC585F44536
	};
	k2 = (curve25519_key_t){
		0x4864CF688C5B7A3F,
		0x09CBD021CD1C06BA,
		0x180BF2608D803AE6,
		0x059B0C837E9119EC
	};
	k3 = (curve25519_key_t){
		0x9ABAD70F3634DBA4,
		0x72964DF1D85254E3,
		0x34DABAB8E0E37E2F,
		0x4B91DC4904855F22
	};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x4D162818084772B6,
		0x764FD3C6D5EA5A8C,
		0x6CFE30B51FBEE54E,
		0x2FC84A4021237D32
	};
	k2 = (curve25519_key_t){
		0x0351FBDBA9DD08B0,
		0x54A5F5ED4562BA58,
		0x4AE48E717574169E,
		0x020B63B634CFED8A
	};
	k3 = (curve25519_key_t){
		0x506823F3B2247B66,
		0xCAF5C9B41B4D14E4,
		0xB7E2BF269532FBEC,
		0x31D3ADF655F36ABC
	};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xABC46B59A854CCA5,
		0xADED330ABFC07190,
		0x456DA208FE7004D7,
		0x2905F9126D3ACF24
	};
	k2 = (curve25519_key_t){
		0xE3B31682F9296A07,
		0x9C1BAA7124D36069,
		0x7ECF0CCC5C503510,
		0x593141DFBCEFAB94
	};
	k3 = (curve25519_key_t){
		0x8F7781DCA17E36BF,
		0x4A08DD7BE493D1FA,
		0xC43CAED55AC039E8,
		0x02373AF22A2A7AB8
	};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x9F7416061C37F446,
		0x0776ABF5FDC656D6,
		0x0022B380AEDF7935,
		0x502269883050BBC9
	};
	k2 = (curve25519_key_t){
		0x4EDA334C8CBB59F3,
		0xF594F7213301CD9C,
		0xF5082DBDB0109885,
		0x29E459B5468BF53E
	};
	k3 = (curve25519_key_t){
		0xEE4E4952A8F34E39,
		0xFD0BA31730C82472,
		0xF52AE13E5EF011BA,
		0x7A06C33D76DCB107
	};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x750992EF8386C44E,
		0x173E3C45845AA5DA,
		0x7E3946E96DAE5BE4,
		0x3598B1E350A64B63
	};
	k2 = (curve25519_key_t){
		0x5EB1CEC1228E3655,
		0xC01A964C9D21AC8A,
		0x0E8DFEF85C99D67C,
		0x43BDD139FFB03033
	};
	k3 = (curve25519_key_t){
		0xD3BB61B0A614FAA3,
		0xD758D292217C5264,
		0x8CC745E1CA483260,
		0x7956831D50567B96
	};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xAAFF7C7F66893BDD,
		0x7050B833DEA0DA98,
		0x6867DC4EBEC36CA1,
		0x39A6C0E2C977D4D3
	};
	k2 = (curve25519_key_t){
		0x44C143B6ED61A0F0,
		0x4323E5E91E61AA07,
		0xCB943D5BF1A33F37,
		0x5413F10D7CE03351
	};
	k3 = (curve25519_key_t){
		0xEFC0C03653EADCE0,
		0xB3749E1CFD02849F,
		0x33FC19AAB066ABD8,
		0x0DBAB1F046580825
	};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x1B09FA263B23E2C0,
		0x8E3B27BD870E2DAC,
		0x8B7D47B96A8E0F0D,
		0x6785CB83B1E346C4
	};
	k2 = (curve25519_key_t){
		0x5B423806C2896347,
		0x38F1B2F055530CB6,
		0x9FC74597B69F8865,
		0x5A46A682A772BCB4
	};
	k3 = (curve25519_key_t){
		0x764C322CFDAD461A,
		0xC72CDAADDC613A62,
		0x2B448D51212D9772,
		0x41CC720659560379
	};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x274B785BED95F6CA,
		0xB4383584658FD6A8,
		0x11FD0B0A2FDBC01F,
		0x58DADEB6F3D287A8
	};
	k2 = (curve25519_key_t){
		0xA98269394BF7A5CF,
		0xB275608D1EF72714,
		0x23937DE154D7D619,
		0x15DDAC2DB94B9A89
	};
	k3 = (curve25519_key_t){
		0xD0CDE195398D9C99,
		0x66AD96118486FDBC,
		0x359088EB84B39639,
		0x6EB88AE4AD1E2231
	};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xEFC78FF7AAC5725D,
		0x1F00AF1D2B61054C,
		0x13D8164C62F1E164,
		0x7FFF37B36561F066
	};
	k2 = (curve25519_key_t){
		0xFCD0ABFAD02DD89F,
		0x7A5C80A1CAA4FC53,
		0xF8C6B93ED04A9AB2,
		0x016B0D025744A46B
	};
	k3 = (curve25519_key_t){
		0xEC983BF27AF34B0F,
		0x995D2FBEF60601A0,
		0x0C9ECF8B333C7C16,
		0x016A44B5BCA694D2
	};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x36D69468C141CE4A,
		0xED2B738BB0BE9592,
		0x5C7C4362F6CC0CB4,
		0x7720F5EA0EE86F3C
	};
	k2 = (curve25519_key_t){
		0xEBA1164478298BA1,
		0xAB7FEC37510D4E63,
		0x1271AD41C7012B60,
		0x1EF9C9FAD8431674
	};
	k3 = (curve25519_key_t){
		0x2277AAAD396B59FE,
		0x98AB5FC301CBE3F6,
		0x6EEDF0A4BDCD3815,
		0x161ABFE4E72B85B0
	};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xABC98849B53682EF,
		0x7312F5E61BE06E35,
		0x3D34EB4E470A6131,
		0x073E23A8B375FF4E
	};
	k2 = (curve25519_key_t){
		0x47724980E113921D,
		0xFD21E2CCBD6F7139,
		0x8CBE9032BF3573D5,
		0x0299B3D3477F63C2
	};
	k3 = (curve25519_key_t){
		0xF33BD1CA964A150C,
		0x7034D8B2D94FDF6E,
		0xC9F37B81063FD507,
		0x09D7D77BFAF56310
	};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD8EDD6EA471B391B,
		0xE189C7E9DC3F5E71,
		0x885EE2EA36C4E41E,
		0x2BBA930EF214C277
	};
	k2 = (curve25519_key_t){
		0xF5B9537ADCB662D2,
		0xA4A3C3F06EDA9224,
		0x0A2EDE6C58CFA862,
		0x5767300F9A23B23F
	};
	k3 = (curve25519_key_t){
		0xCEA72A6523D19C00,
		0x862D8BDA4B19F096,
		0x928DC1568F948C81,
		0x0321C31E8C3874B6
	};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x673C1CE02E6D0E88,
		0xB54E223E5CE2EA45,
		0x6DC55CCA8DCF84FF,
		0x4DDFE32005C18749
	};
	k2 = (curve25519_key_t){
		0x3079B37F3FC62060,
		0x1408915CDC9AB2A4,
		0x26181AC0AD41295C,
		0x18F843C513ED87A9
	};
	k3 = (curve25519_key_t){
		0x97B5D05F6E332EE8,
		0xC956B39B397D9CE9,
		0x93DD778B3B10AE5B,
		0x66D826E519AF0EF2
	};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x85C2E81F741711DA,
		0x982D50A407DF01FA,
		0x684444C597FC0DB5,
		0x3E3769C1ACAC3C25
	};
	k2 = (curve25519_key_t){
		0x38C718175DBD898F,
		0xDEE08552058D7A4D,
		0x5823D4BF92560F8F,
		0x37E254581C0819A3
	};
	k3 = (curve25519_key_t){
		0xBE8A0036D1D49B69,
		0x770DD5F60D6C7C47,
		0xC06819852A521D45,
		0x7619BE19C8B455C8
	};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD1D7928279B5E9FD,
		0xAC0614C6EE14CD28,
		0xAD1798FAD8D7DE2C,
		0x77367EC68E73919B
	};
	k2 = (curve25519_key_t){
		0x85F7E89584E8781C,
		0xD4184A91560962AF,
		0x6FE5CBBE7F75DCDA,
		0x031C35DBFC9C6CD7
	};
	k3 = (curve25519_key_t){
		0x57CF7B17FE9E6219,
		0x801E5F58441E2FD8,
		0x1CFD64B9584DBB07,
		0x7A52B4A28B0FFE73
	};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x6EBA18B14C5D2D0F,
		0x4B056C26AE462C22,
		0xE9EF19A397E61E19,
		0x0DC640B02664C3FC
	};
	k2 = (curve25519_key_t){
		0x2B40073AC8DB5558,
		0x3C9C89CA4E6D5AF4,
		0x40AFA29C5CC8AEA1,
		0x6470695B4C799178
	};
	k3 = (curve25519_key_t){
		0x99FA1FEC15388267,
		0x87A1F5F0FCB38716,
		0x2A9EBC3FF4AECCBA,
		0x7236AA0B72DE5575
	};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x1295A19FE98C4DE9,
		0xD49EA356C6CE07CD,
		0xF881A4801A7801EE,
		0x5DC47FBED46E3516
	};
	k2 = (curve25519_key_t){
		0x30792EE59556BD0B,
		0xEAC594CD31C45B47,
		0x4D599A2F669744FB,
		0x0F0C41CAA27DF56B
	};
	k3 = (curve25519_key_t){
		0x430ED0857EE30AF4,
		0xBF643823F8926314,
		0x45DB3EAF810F46EA,
		0x6CD0C18976EC2A82
	};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xEB6695C80E69A584,
		0xCE856C89DE309942,
		0xFA41F02A3344E5B0,
		0x781EF6CE6B4C47CC
	};
	k2 = (curve25519_key_t){
		0x62C108496F3C015E,
		0x47985282BA2F32B3,
		0xABA093F7BD92668C,
		0x71EF82C5161473F9
	};
	k3 = (curve25519_key_t){
		0x4E279E117DA5A6F5,
		0x161DBF0C985FCBF6,
		0xA5E28421F0D74C3D,
		0x6A0E79938160BBC6
	};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xCA0CA0F550C37CA1,
		0xD72AF5BB57E26724,
		0x7FFE48168CDE26E0,
		0x1BB95705EDDBD1B6
	};
	k2 = (curve25519_key_t){
		0x30E653A2A1A97CE9,
		0x8C010D11E3C875B0,
		0x74E4166D7572E85D,
		0x535120DC3D6EE2B1
	};
	k3 = (curve25519_key_t){
		0xFAF2F497F26CF98A,
		0x632C02CD3BAADCD4,
		0xF4E25E8402510F3E,
		0x6F0A77E22B4AB467
	};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x085752038D0AD95B,
		0xA923C561653C44B6,
		0xBDC56E46A91F2028,
		0x24F7CEB2BE3FE03F
	};
	k2 = (curve25519_key_t){
		0x3AC2582CE467AD89,
		0xF26D2ABA037413F5,
		0xABADAB533E4C669C,
		0x148CF1497195F2A9
	};
	k3 = (curve25519_key_t){
		0x4319AA30717286E4,
		0x9B90F01B68B058AB,
		0x69731999E76B86C5,
		0x3984BFFC2FD5D2E9
	};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x926EABCBEFBC5A66,
		0xC75025177CFA7110,
		0x002AAD5377047D6E,
		0x3760894C17B8312A
	};
	k2 = (curve25519_key_t){
		0x48F25737A33C548E,
		0x126859E98DC9181F,
		0x5854B0019AA2C0E5,
		0x7832166DD71671BD
	};
	k3 = (curve25519_key_t){
		0xDB61030392F8AF07,
		0xD9B87F010AC3892F,
		0x587F5D5511A73E53,
		0x2F929FB9EECEA2E7
	};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xC13D0D7E9EBA21FE,
		0xD48231DF05DB31D9,
		0x140982793BCF5EC8,
		0x42DEB346D153C012
	};
	k2 = (curve25519_key_t){
		0xD41DC4B9F39CE4BC,
		0x76DDC82DB2CC8278,
		0x02681084102E8E53,
		0x3D58AE0BBAD852CF
	};
	k3 = (curve25519_key_t){
		0x955AD238925706CD,
		0x4B5FFA0CB8A7B452,
		0x167192FD4BFDED1C,
		0x003761528C2C12E1
	};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xDBCF5699F7948EF7,
		0xB2F395E0A4B57489,
		0x2B3AF39F247522EC,
		0x0FDF0BB332DA6F7B
	};
	k2 = (curve25519_key_t){
		0xEE70D5AD47002C31,
		0x64EA58D5A1550DE3,
		0x707C5093C573DCC6,
		0x4053FB45BEC54AB1
	};
	k3 = (curve25519_key_t){
		0xCA402C473E94BB28,
		0x17DDEEB6460A826D,
		0x9BB74432E9E8FFB3,
		0x503306F8F19FBA2C
	};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x98E0467CE1330B6F,
		0x3554ECE4D35ECEE9,
		0xD2E4092007D4FA37,
		0x7E772FBD6487ABC5
	};
	k2 = (curve25519_key_t){
		0x4E91B5C8838691F0,
		0xC3F1CF74E349A97E,
		0xBBDD2D178B08170E,
		0x47E966D4EB29C920
	};
	k3 = (curve25519_key_t){
		0xE771FC4564B99D72,
		0xF946BC59B6A87867,
		0x8EC1363792DD1145,
		0x466096924FB174E6
	};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xD31D0A3301D197F6,
		0xC62DE5CF9A0E076D,
		0xA0F9773E47024C81,
		0x2239A0E3BDA84BE1
	};
	k2 = (curve25519_key_t){
		0x63C6336B921CD380,
		0x5478310E05B2C8CA,
		0xA1EE965CCE48D3B3,
		0x08B3335F0AE24D49
	};
	k3 = (curve25519_key_t){
		0x36E33D9E93EE6B76,
		0x1AA616DD9FC0D038,
		0x42E80D9B154B2035,
		0x2AECD442C88A992B
	};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x8544DC6CC5A829DC,
		0x03099CCF9EF85E6F,
		0xCE78E89BF13E4D43,
		0x595AB3C8D923481A
	};
	k2 = (curve25519_key_t){
		0x561DF866A87F1DBF,
		0xD08B873DE5B75D0F,
		0x815CF1E2E539B50B,
		0x6B12230FCEDBB596
	};
	k3 = (curve25519_key_t){
		0xDB62D4D36E2747AE,
		0xD395240D84AFBB7E,
		0x4FD5DA7ED678024E,
		0x446CD6D8A7FEFDB1
	};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0x10EFC35662D31E45,
		0xC7CC794550894D98,
		0xB24DF3B7F6D8E6C9,
		0x0EB7DD164CAA0C79
	};
	k2 = (curve25519_key_t){
		0xD2678E524761C71F,
		0x011B9C27EBF9281D,
		0xBA7A20F50D546910,
		0x24A331C34A163513
	};
	k3 = (curve25519_key_t){
		0xE35751A8AA34E564,
		0xC8E8156D3C8275B5,
		0x6CC814AD042D4FD9,
		0x335B0ED996C0418D
	};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){
		0xE404219B2DF0A62A,
		0xF69F9F49B0ACFDE0,
		0x0C412A102BDDCE23,
		0x22FCB0F0AD50D41C
	};
	k2 = (curve25519_key_t){
		0x5A05972598ACF5EA,
		0x741360409A0C3017,
		0xFC630AA0572E9F19,
		0x15C9456DCDC3D9C7
	};
	k3 = (curve25519_key_t){
		0x3E09B8C0C69D9C14,
		0x6AB2FF8A4AB92DF8,
		0x08A434B0830C6D3D,
		0x38C5F65E7B14ADE4
	};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}