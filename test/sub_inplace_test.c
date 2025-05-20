#include "tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Sub Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD785D8DEC809DA5C,
		0x14D2EA5F390B6988,
		0xA02828019EF3482E,
		0x31DC22F8DDE5F4A2
	}};
	curve25519_key_t k2 = {.key64 = {
		0x10BFF6138D043A8D,
		0xE80A0B7A28B76738,
		0x6543EFEEB76008B3,
		0x08415368FA2EA31E
	}};
	curve25519_key_t k3 = {.key64 = {
		0xC6C5E2CB3B059FCF,
		0x2CC8DEE510540250,
		0x3AE43812E7933F7A,
		0x299ACF8FE3B75184
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x57D959E167F0986A,
		0x5D871DA7172D8223,
		0x3C394F156C695CFC,
		0x6E111DE360FCC28F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA79D617614CEC93D,
		0xA3804E7860B9B939,
		0x6B7193A1C238505D,
		0x0D2D80C268D8FC9F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB03BF86B5321CF2D,
		0xBA06CF2EB673C8E9,
		0xD0C7BB73AA310C9E,
		0x60E39D20F823C5EF
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5035AED08E41BDE6,
		0xF863E0DF3AB3FF8B,
		0x8D2C004B70822AC5,
		0x5220AB7481A9457C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AC2DCBB61640D13,
		0xF3A8F8FD4677151F,
		0x93051F26F1DECB02,
		0x7CEB11DE5453CD6C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4572D2152CDDB0C0,
		0x04BAE7E1F43CEA6C,
		0xFA26E1247EA35FC3,
		0x553599962D55780F
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xEF9DE2C6264FA04A,
		0x4E569776C24B7DE4,
		0x8C69F635553F4905,
		0x79DFA2BBB1DD2610
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17074E4041CBB68D,
		0xA8DBA4B1BE73FC20,
		0x7C62D30077436ED1,
		0x05213F8D900E2FA3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8969485E483E9BD,
		0xA57AF2C503D781C4,
		0x10072334DDFBDA33,
		0x74BE632E21CEF66D
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3B2EBF084C2C5366,
		0x3C071C22EE822EF8,
		0xD76AA85E84528190,
		0x0CE2E903689DA4D1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA7643859C0CBD1,
		0x48727ADF19A1B787,
		0x7011B0A3A68EAD6A,
		0x0B20138B4A21BF73
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E875ACFF26B8795,
		0xF394A143D4E07771,
		0x6758F7BADDC3D425,
		0x01C2D5781E7BE55E
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8DBB54A5DC9BE0ED,
		0xC74D2D27A6403560,
		0x1571660972A66E30,
		0x42EC231C1E12F42F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF96431787F08B493,
		0xD8A36D247929E6B6,
		0x99708A09372E7664,
		0x5412676C906FAFB0
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9457232D5D932C47,
		0xEEA9C0032D164EA9,
		0x7C00DC003B77F7CB,
		0x6ED9BBAF8DA3447E
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x38BAEAC0EE9FF89C,
		0x9567D84B086375FF,
		0x2723061C6F4F1AE7,
		0x4712FAE720E52E39
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE96D9D5A986553A6,
		0xBD09035CFB1D1D18,
		0xB3E56065F9D363F3,
		0x621CE9277B78D968
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F4D4D66563AA4E3,
		0xD85ED4EE0D4658E6,
		0x733DA5B6757BB6F3,
		0x64F611BFA56C54D0
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xD0487A2D6AC0DD71,
		0x4AC3BF9990ABD721,
		0x34B33B0B64BEE1C5,
		0x5C49F205C38907B4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF546E49F2B49C899,
		0xD37D0680AC0A705A,
		0x2C2B2B4076245C30,
		0x6A0F6F137D14D510
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB01958E3F7714C5,
		0x7746B918E4A166C6,
		0x08880FCAEE9A8594,
		0x723A82F2467432A4
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE68219FA729634B1,
		0x3EE14B85E067A223,
		0x427BCC2A7A5331DB,
		0x78312BD445005A72
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6AB0DFDC792E82,
		0x7B0016AD3DAEA0F1,
		0x5351A90114AB9337,
		0x6966A815AB08D5EE
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB17691A961D062F,
		0xC3E134D8A2B90131,
		0xEF2A232965A79EA3,
		0x0ECA83BE99F78483
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x43F3E6F39AFFF186,
		0xB25EC240DEE76F74,
		0x67BFBE08125E1428,
		0x12E4CECC792257B4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F198598A927F360,
		0x67D808915F5DA330,
		0x9F3D9D21F5F05917,
		0x16AA14F16AA14408
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4DA615AF1D7FE13,
		0x4A86B9AF7F89CC43,
		0xC88220E61C6DBB11,
		0x7C3AB9DB0E8113AB
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
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
	k1 = (curve25519_key_t){.key64 = {
		0x087C31E171016B98,
		0x946A6999ED4C6C2B,
		0xADF9D28D2660C0F4,
		0x627452E471B53FC4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28061C9BB01FC036,
		0x02D341418CBC9907,
		0x82761465EF2081AE,
		0x2922A7C6AB5373A1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0761545C0E1AB62,
		0x91972858608FD323,
		0x2B83BE2737403F46,
		0x3951AB1DC661CC23
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5735C3DD1D0F8BB5,
		0x44895AC99A214D86,
		0x918BE57EEE9AC1D1,
		0x0FDBC4F1DACD014D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x097931FC6F1B6E0E,
		0xEBA95ADD4DD9C821,
		0x08A7C4B127958656,
		0x6DC226EB558B07FF
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DBC91E0ADF41D94,
		0x58DFFFEC4C478565,
		0x88E420CDC7053B7A,
		0x22199E068541F94E
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42A7D5EDD5B4901D,
		0xB9C89DBF3395714A,
		0x5F4FA6DA281272BD,
		0x70C0E769ECA24518
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6E4DA49D7F46BB,
		0x39E0D4C8FDA19D01,
		0x2B3C7DCCD9C3A2BE,
		0x2BAF7D4E0FCB28FF
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7739884938354962,
		0x7FE7C8F635F3D448,
		0x3413290D4E4ECFFF,
		0x45116A1BDCD71C19
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14D172432D77E59D,
		0x76EDAA240F121394,
		0x50FCFA73053E86AA,
		0x088E98ED9791E459
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CC9369AC03C6E90,
		0x79DAC30788A7C646,
		0xB2BD5A6C144C9634,
		0x7FCFDDE90301624E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78083BA86D3B76FA,
		0xFD12E71C866A4D4D,
		0x9E3FA006F0F1F075,
		0x08BEBB049490820A
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x866EF2860171D37E,
		0x5213449866830D00,
		0x7B014EEE9B6E1AEE,
		0x1EA26E58FFC2C08F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E51CBFE6F829842,
		0x1BF7113FFE4CF989,
		0x11CCECE883ABF0B3,
		0x6D029C6BCD38ADEF
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF81D268791EF3B29,
		0x361C335868361376,
		0x6934620617C22A3B,
		0x319FD1ED328A12A0
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46229678FF6E5847,
		0x1B33F4824DCDF87D,
		0xA84D2E090DC36C1B,
		0x7A9220827A648B82
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F6BE8DAA02F47BC,
		0xFE32C0CEDAE46DE7,
		0xC34718F29B1FB5D3,
		0x4773DDEA4DB2E689
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6B6AD9E5F3F108B,
		0x1D0133B372E98A95,
		0xE506151672A3B647,
		0x331E42982CB1A4F8
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96776EF1A1FAFE0F,
		0x069302CA7262001E,
		0x9779A216CE512F7A,
		0x7A16B1E0CDEAA40B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CC782CEF8E4A9B,
		0x86B939579E43E906,
		0xBBA43DCBB9CB78C7,
		0x37BEE9B8AF6E7DF1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECAAF6C4B26CB374,
		0x7FD9C972D41E1717,
		0xDBD5644B1485B6B2,
		0x4257C8281E7C2619
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04902A4EB7023D12,
		0x39B0F6BA6C26830C,
		0xAC841A361C846D51,
		0x28B5F7D15227A046
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC245A2250034308F,
		0xC308C8B096185B82,
		0x7D9312211409B12E,
		0x1FFF480DEBDD8E17
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424A8829B6CE0C83,
		0x76A82E09D60E2789,
		0x2EF10815087ABC22,
		0x08B6AFC3664A122F
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB261FE8009DEEFE1,
		0x7DB4B05A46898D00,
		0xE56F9F3C6904F389,
		0x0517DE2B2086A933
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6618C1A8FF5AA56D,
		0x5DC0D72A7D9647C6,
		0x0178305BE9BF778C,
		0x69C1A63631F34C3A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C493CD70A844A61,
		0x1FF3D92FC8F3453A,
		0xE3F76EE07F457BFD,
		0x1B5637F4EE935CF9
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9368AE32C724F00,
		0xB42B754647C6A015,
		0x6B130C5F8200DF5A,
		0x141E0060560D52F2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE1103F3B84ACD0,
		0xC45216C5C3949066,
		0xC584F98CFF1A7F1C,
		0x29767F54291C9674
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E557AA3F0EDA21D,
		0xEFD95E8084320FAF,
		0xA58E12D282E6603D,
		0x6AA7810C2CF0BC7D
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4329159A0F501011,
		0x6EEFF94AB0CC7116,
		0x62209485C5E5183E,
		0x5180AA9C450AE097
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB53DF70F087F0403,
		0x4359F684CFCA6F06,
		0xFC5C44A76462E3A3,
		0x32D03D64746ED932
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DEB1E8B06D10C0E,
		0x2B9602C5E102020F,
		0x65C44FDE6182349B,
		0x1EB06D37D09C0764
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AFEB750910FEB26,
		0xB1A5D342AF7B9CE7,
		0x4EE163E0C2B97FDE,
		0x4C035DDF088F7F6E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x076746CC29597CBB,
		0x9C65C5BD8E1DC96B,
		0x7B4483E019047E43,
		0x48A84B54D09C156C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4397708467B66E6B,
		0x15400D85215DD37C,
		0xD39CE000A9B5019B,
		0x035B128A37F36A01
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A32404F6A49BB72,
		0xDE69D5F66BB08C7F,
		0x01063F85AF4B3F7A,
		0x38AC61C429406F9A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A5C03400578EC4,
		0xF1782B8CB61873F4,
		0xC526D83E16248720,
		0x34E68000022A123A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288C801B69F22CAE,
		0xECF1AA69B598188B,
		0x3BDF67479926B859,
		0x03C5E1C427165D5F
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB16C0C57E4BB39D5,
		0x0FF5CF878AD71BFE,
		0x3FADC5452FFC7BF3,
		0x10CD30963FDE55C6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD845A35DCFCE6821,
		0xB01B2475EA7E2206,
		0xFC8DED788EADAF3E,
		0x42A3120FE3BF5C81
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD92668FA14ECD1A1,
		0x5FDAAB11A058F9F7,
		0x431FD7CCA14ECCB4,
		0x4E2A1E865C1EF944
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAC5DA5710376BBB,
		0x62EC37A96AF5AF89,
		0x91A5F2963E67EC3E,
		0x2C0B201DF7F379B8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC34E7137AF96D9F6,
		0xE6BE733AF70D1B2C,
		0x5271206EFB8963AC,
		0x2C61F28FABA38A1E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1777691F60A091B2,
		0x7C2DC46E73E8945D,
		0x3F34D22742DE8891,
		0x7FA92D8E4C4FEF9A
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x384272FDA56A0E52,
		0x68C6988467C27146,
		0x55F321485BD2A6DF,
		0x014858DCAC7099D3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67A42133063CB7C,
		0x4982EEB08E2E954B,
		0x7DA7FC3C11CBE439,
		0x11F1D4F6A14CCC34
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61C830EA750642C3,
		0x1F43A9D3D993DBFA,
		0xD84B250C4A06C2A6,
		0x6F5683E60B23CD9E
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BEB4F489BB45D34,
		0x36C1A61CF335741D,
		0x54049BC47FFEB4E7,
		0x73B0250EBCF9D70D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D692F9DF41B392A,
		0x9478C5536F98F201,
		0xD1512CBC8CD0A733,
		0x54E986023AC4EC28
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE821FAAA799240A,
		0xA248E0C9839C821B,
		0x82B36F07F32E0DB3,
		0x1EC69F0C8234EAE4
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA233B931F56364E0,
		0xAB04A10F5787B9F9,
		0xF0BE9D41743564F5,
		0x1DA314E40199EA1E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E39FEF44121BD4,
		0x24953D85DAA73B8C,
		0xD5CC2B7A9607BB8D,
		0x13CE4422C00E141B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61501942B151490C,
		0x866F63897CE07E6D,
		0x1AF271C6DE2DA968,
		0x09D4D0C1418BD603
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC204264C9FE7E9A9,
		0xC475F7CE33DC6777,
		0x4453EEFAF0660238,
		0x31E81A1F63B9779B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88FC28F99372E924,
		0x8265D0A342561943,
		0x367FF4B1A1515343,
		0x37885A7F30C35DDD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3907FD530C750072,
		0x4210272AF1864E34,
		0x0DD3FA494F14AEF5,
		0x7A5FBFA032F619BE
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x976A03FDC132F515,
		0x2545B86921FA3FF9,
		0x994427D49DAE9A45,
		0x2C2FF92A264572ED
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6913EEACAAE31846,
		0x0FB1DBC07D285540,
		0x658A67CBC58C85EC,
		0x0615FDC277046220
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E561551164FDCCF,
		0x1593DCA8A4D1EAB9,
		0x33B9C008D8221459,
		0x2619FB67AF4110CD
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A649A88B8ED0E6A,
		0x2DE802DAB6CA8DD8,
		0x4219BCD6326C4C50,
		0x1D21558A8700EE81
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD40BA829DF748D85,
		0x32C0E7923B1BD2C5,
		0x60CDF2E7F9F79C10,
		0x30249E4406F5D91B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB658F25ED97880D2,
		0xFB271B487BAEBB12,
		0xE14BC9EE3874B03F,
		0x6CFCB746800B1565
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBAFC64F53EFA222,
		0x20F2304680545ABA,
		0x27B81F6F295EBA84,
		0x085BBCF2065F57A0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7C63729BBE18091,
		0xD4FADE3FCB55A1FC,
		0x25F303D963747012,
		0x236AAC7BD2BFFEE9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53E98F25980E217E,
		0x4BF75206B4FEB8BE,
		0x01C51B95C5EA4A71,
		0x64F11076339F58B7
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD20D3EFF0F1C41A,
		0xF424CE7E348C726D,
		0xA736AF215E99528A,
		0x7C8C0751ACFAF35E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D2009639A7260EC,
		0x16A0411544473163,
		0xA05548D820598BE4,
		0x78550B24189D71EB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD000CA8C567F632E,
		0xDD848D68F045410A,
		0x06E166493E3FC6A6,
		0x0436FC2D945D8173
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89D64E8E31593A1B,
		0xB91B2E2911447550,
		0xFFA60F03E54359BF,
		0x08999CFA40D53A12
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9DA27CFC69CDAA3,
		0xEE32910CC4E4FD71,
		0xBF90911F4A4E76B1,
		0x5BCBB2C60D62A103
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFFC26BE6ABC5F65,
		0xCAE89D1C4C5F77DE,
		0x40157DE49AF4E30D,
		0x2CCDEA343372990F
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45979F36E0727C06,
		0xCA17E9F42573763D,
		0x1834BCFDB12C15D4,
		0x57F7F253B98A89DD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3AC941A7585509,
		0x2CDA8736C40C51AA,
		0x45E2A78BF81B533E,
		0x6F2B2713162B8C63
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x585CD5F5391A26EA,
		0x9D3D62BD61672492,
		0xD2521571B910C296,
		0x68CCCB40A35EFD79
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE98E2488BD653F5E,
		0x4C3D85DB84A24DC2,
		0x3CCB985B0739AEB6,
		0x7F7F0D548727B545
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA970BFD0AF89DAD,
		0x9EDD8AC0545D6548,
		0x822F2C38048E488C,
		0x3F25FF98E096D40E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EF7188BB26CA1B1,
		0xAD5FFB1B3044E87A,
		0xBA9C6C2302AB6629,
		0x40590DBBA690E136
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE75BAC86A33C25AF,
		0x24D69DBBE267383E,
		0xB298835A4B76A9C8,
		0x64633E20F1F5A0BC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x506B5ADEFF9E1041,
		0x34A9C4CB8FD36D5D,
		0xE17CC8D52DA73CC4,
		0x002E2867DA614C71
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96F051A7A39E156E,
		0xF02CD8F05293CAE1,
		0xD11BBA851DCF6D03,
		0x643515B91794544A
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03AF42487B23FC52,
		0xA5A07DAE5DC93ACD,
		0xAEBE1B6910FBB168,
		0x061E88C11F770DC4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8012D2EF261FD452,
		0x84CE2E84ACA83ED3,
		0x21267CDF03EC1A1C,
		0x7A5E934F15A20725
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x839C6F59550427ED,
		0x20D24F29B120FBF9,
		0x8D979E8A0D0F974C,
		0x0BBFF57209D5069F
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEEB7020F3ECD4CD,
		0x7B0A4B5A73ADE7E0,
		0x087532AEFA8006F1,
		0x487A71032995BB8F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAC6E9A2A8AD30C3,
		0x951127C8535D4158,
		0xEA7496D8E352231E,
		0x0DE7BAD2A7FCD529
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2424867E4B3FA40A,
		0xE5F923922050A688,
		0x1E009BD6172DE3D2,
		0x3A92B6308198E665
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A59BC4C84DC8E9A,
		0xAF6A0AD27E751C36,
		0x89FB2AACD199BD07,
		0x7A06CEF7734B98E0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46AC70AE0111C06E,
		0x1C8BAA26D4C92900,
		0x3F2967C93F1EAE95,
		0x7FEC22EC9021E92D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3AD4B9E83CACE19,
		0x92DE60ABA9ABF335,
		0x4AD1C2E3927B0E72,
		0x7A1AAC0AE329AFB3
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x685D90CD299BBFC4,
		0x91E185D2A7C16D99,
		0x69DAC6B78A2422BF,
		0x0EA01FB57D0FCB55
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE47AFA0396BF5DE,
		0x157B25E693C3DF17,
		0x787B59A47A717EEC,
		0x54974399ACEE5AF2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A15E12CF02FC9D3,
		0x7C665FEC13FD8E81,
		0xF15F6D130FB2A3D3,
		0x3A08DC1BD0217062
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65E3BFFBD2DB314C,
		0x198B5DC5730B5159,
		0x6B0641D2CFADF3D6,
		0x789B3932340BA432
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE352706DCDA2089D,
		0x99502A7ECE8D92AD,
		0x7A30E395839DBE4A,
		0x572CC35C25C446EA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82914F8E053928AF,
		0x803B3346A47DBEAB,
		0xF0D55E3D4C10358B,
		0x216E75D60E475D47
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF4ED9E54208FD1,
		0x523DB13341BADF47,
		0x49F61047E351AD4E,
		0x31B434018F9ECF1B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0DC868D1F5FB6D,
		0x86533599A646F977,
		0xBEE34BBEB07344D6,
		0x25D19E5C6541A201
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BE72535822A9464,
		0xCBEA7B999B73E5D0,
		0x8B12C48932DE6877,
		0x0BE295A52A5D2D19
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE0624C05E28E685,
		0x8B8296FBB6C46E34,
		0x45E3C40427D3D558,
		0x00549BAB154538FD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FDCDDBCB599FF3E,
		0x672C7911D9ECE0FB,
		0xD6E920C4F0C7C203,
		0x38D3D90C1EE672BD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E294703A88EE734,
		0x24561DE9DCD78D39,
		0x6EFAA33F370C1355,
		0x4780C29EF65EC63F
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD585ADB142AF853A,
		0x89023F1D531B8EB2,
		0x941BB47962D1644F,
		0x68DE5B14D160A8A2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F9B01D932261A40,
		0xD1872F90FD745450,
		0x92E675AF3113274C,
		0x3E4105EA8D51E942
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95EAABD810896AFA,
		0xB77B0F8C55A73A62,
		0x01353ECA31BE3D02,
		0x2A9D552A440EBF60
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08AAEDF643C664AE,
		0x6D5AB55CD2693CDE,
		0xF3B1000A97812FAE,
		0x218EBAE63499380D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FB481F5AC3E8E61,
		0x70F35D56E40FC121,
		0x44A48C5BD78C7D3C,
		0x149BAB00F0631280
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8F66C009787D64D,
		0xFC675805EE597BBC,
		0xAF0C73AEBFF4B271,
		0x0CF30FE54436258D
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x999DA02DB507F885,
		0x416CAC880626CEB5,
		0xF30D8DA6913FAF72,
		0x7D9F5B28F66559A5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF64A3858C158F2,
		0x415C3A8E476FA546,
		0xE4E24920F8FDBCB1,
		0x29024DF17E944099
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EA755F55C469F93,
		0x001071F9BEB7296E,
		0x0E2B44859841F2C1,
		0x549D0D3777D1190C
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF48898390D84056,
		0x823C25EC2220B2E7,
		0xBC0DE25207F37B14,
		0x0CF646638EA01862
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27DC109DA33FA92E,
		0xF1EBEC797F02BC6A,
		0xD5C41AE675759F4E,
		0x7FB0E1283ABF2940
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD76C78E5ED989715,
		0x90503972A31DF67D,
		0xE649C76B927DDBC5,
		0x0D45653B53E0EF21
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDAA30179580415C,
		0x932FB7F2523BD211,
		0x75453BCE07890582,
		0x1415B84E79DD5835
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABF29BB9934893D7,
		0x1AE8716F9E42914D,
		0xF076DBE4B1F73A85,
		0x1F205055F6C41895
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11B7945E0237AD72,
		0x78474682B3F940C4,
		0x84CE5FE95591CAFD,
		0x74F567F883193F9F
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7606369DA1A9FAE6,
		0x846E0CBFB2E416E1,
		0x825095EACA2C8C59,
		0x019875464E964944
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C408E082A34D58,
		0x829C2E79F83C2477,
		0x54EC61D72D100C60,
		0x681C78D172978695
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05422DBD1F06AD7B,
		0x01D1DE45BAA7F26A,
		0x2D6434139D1C7FF9,
		0x197BFC74DBFEC2AF
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F42C6B5B881CDAE,
		0x019E4DCF0F84FBCC,
		0x6F74FD059A231656,
		0x5BE9CEF849D214B9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E1F05B985C78CD,
		0x628D693A716D53F1,
		0xB6B3EF0BA82B76CB,
		0x6659008362AE9B47
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA860D65A202554CE,
		0x9F10E4949E17A7DA,
		0xB8C10DF9F1F79F8A,
		0x7590CE74E7237971
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90477CA6BD966C4D,
		0x1B0B010D875CF454,
		0xCA91F94A14B0FF4B,
		0x2BED765F037988BD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC0001241051A3F7,
		0xC527177BF37F2188,
		0xAB491EA4165B7975,
		0x0788D9AEBEA0D28D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4477B82AD44C856,
		0x55E3E99193DDD2CB,
		0x1F48DAA5FE5585D5,
		0x24649CB044D8B630
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EA709CC0D03B1AD,
		0x08FAF0CD51FAD2E0,
		0x1D7051C9C5AE1CD7,
		0x2376CF4A6E9622DA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B8AE3A2529D92D,
		0x15FA3FB627A68D45,
		0xA12B384B96E85508,
		0x058F9EF21495376D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58EE5B91E7D9D880,
		0xF300B1172A54459B,
		0x7C45197E2EC5C7CE,
		0x1DE730585A00EB6C
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE9AA4694BE6B272,
		0x2F6B4264717328F9,
		0xD9ECE2E6468006ED,
		0x5F998EA0C9954B95
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB28E1A5548A9F660,
		0xA5F7E0729C0D0C14,
		0xDBC0B89B531C054F,
		0x4ECF2D9FBF6D6CC3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0C8A14033CBC12,
		0x897361F1D5661CE5,
		0xFE2C2A4AF364019D,
		0x10CA61010A27DED1
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DBC6E4D1A338451,
		0xF32F9320A584FCD1,
		0xAA87408552A8CDB4,
		0x76D9E2D157FC678F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D22B371C8408218,
		0x934953DCBCD4E940,
		0x158BDD375FA9E643,
		0x22203F803B3DD5EC
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE099BADB51F30239,
		0x5FE63F43E8B01390,
		0x94FB634DF2FEE771,
		0x54B9A3511CBE91A3
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CB3806F98DB9D3A,
		0xC31F57F6B81FA08C,
		0x694A603141470536,
		0x7035490C063374D9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92729A2EB1AD6B97,
		0xFB6576689D7E653E,
		0xE5756E8F5FC81E5A,
		0x7A77699065FD97F7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A40E640E72E3190,
		0xC7B9E18E1AA13B4D,
		0x83D4F1A1E17EE6DB,
		0x75BDDF7BA035DCE1
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x556C3782E0A55D4C,
		0xB4E34B904ABBADD2,
		0x3E680B14CF7444FC,
		0x06A479BB65603F1A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7163E722FC1EDA3,
		0x94D839073FD18268,
		0xD0B806B858570A5C,
		0x76CC937BCDD52948
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E55F910B0E36F96,
		0x200B12890AEA2B69,
		0x6DB0045C771D3AA0,
		0x0FD7E63F978B15D1
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x515749D5D8706A5F,
		0x0BA0F703F774B0AE,
		0x096355D40D40E6E2,
		0x58B08B1DCA6DE5FE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E3C90C9A034335,
		0x572BECFFDF5F0D8D,
		0x7753AFBE0779C2D7,
		0x5FF43B8804AFAE52
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B7380C93E6D2717,
		0xB4750A041815A321,
		0x920FA61605C7240A,
		0x78BC4F95C5BE37AB
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C9473D3883C91EF,
		0x63E1861940CA8F65,
		0xF98EAEA631E81B27,
		0x79362698D04B8775
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DEAC701A0083E11,
		0xBAD8F9DB12C4F773,
		0x2D8C02B72CDDAD77,
		0x220D8E60A7BC78DA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EA9ACD1E83453DE,
		0xA9088C3E2E0597F2,
		0xCC02ABEF050A6DAF,
		0x57289838288F0E9B
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA34BE59F7EA061,
		0x2BF04EBCA4351B06,
		0x92710172BD81A7FA,
		0x41C816421385C895
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF04CCF0B0B82166F,
		0x44D9C5EA3AC1AED5,
		0xDE9085D2B3233A41,
		0x192A287481AF1DE9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D567CDA93FC89F2,
		0xE71688D269736C30,
		0xB3E07BA00A5E6DB8,
		0x289DEDCD91D6AAAB
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E6A9EDEFF8D7D02,
		0x11D2FFB6352B1439,
		0xB3EA2C20C166CF76,
		0x14F628FF1B05CDF4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF068945097335263,
		0xB4868A2B2CA4B734,
		0xF3EE3D4A4FF590E9,
		0x5047C2706BC8845D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E020A8E685A2A8C,
		0x5D4C758B08865D04,
		0xBFFBEED671713E8C,
		0x44AE668EAF3D4996
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B080677AC9EB1D7,
		0x40CDD607BD9855A8,
		0x83E0D8F24D70CBEF,
		0x7BD45F060D8EAD7E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3265D1A33665CB02,
		0x7E2DD77E9A361CBA,
		0x943476B675A80D7B,
		0x640ED72F28B135BA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28A234D47638E6D5,
		0xC29FFE89236238EE,
		0xEFAC623BD7C8BE73,
		0x17C587D6E4DD77C3
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2992265ADE4C0B4,
		0x74F0954F71341834,
		0xB3CD3E7DE73FEA65,
		0x5DD943A862FFDDDD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4C4C9D9DD14F04,
		0xFA8E9FF6C7C63443,
		0xBB4433BB7147A5B0,
		0x110BC8E1A550C612
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE74CD5C8101371B0,
		0x7A61F558A96DE3F1,
		0xF8890AC275F844B4,
		0x4CCD7AC6BDAF17CA
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x860C4674F1C0C133,
		0xFBDC812192100010,
		0x7F1B43F53489D081,
		0x4216D6D4BEBCF244
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA571F90A5A5EFA2E,
		0xB9A369EB08EF8258,
		0x87A703231B88B4CA,
		0x3EB2AE4525FBAEAB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE09A4D6A9761C705,
		0x4239173689207DB7,
		0xF77440D219011BB7,
		0x0364288F98C14398
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26065F23DC7664DA,
		0xCC98A048676DC25E,
		0x606A7DD925A1865E,
		0x6ABE95892BC69FD7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C2B194C76F78DF,
		0x57598B9EBAAE9CC1,
		0x24A20D7175089D02,
		0x3A58CEB2713DB513
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0043AD8F1506EBFB,
		0x753F14A9ACBF259D,
		0x3BC87067B098E95C,
		0x3065C6D6BA88EAC4
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD11227C0BFA22929,
		0xFBC76C552DB55BE7,
		0x2AD9DAA518D9DDEA,
		0x50BEBD4993A14756
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF794BC7C34E6C9E,
		0x0648C5A1A2F8157C,
		0xCA968FB742054798,
		0x1D5D923E2CE86DDD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE198DBF8FC53BC8B,
		0xF57EA6B38ABD466A,
		0x60434AEDD6D49652,
		0x33612B0B66B8D978
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA452D37409DDB39F,
		0x543F671EEF51F7FF,
		0xB99FD48C021117D6,
		0x7C1103D0C70DEEBF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2556DFF8D6C6F10F,
		0xD31EFFEF169BA528,
		0x4B25806900DB556F,
		0x57A59673FB3EE566
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EFBF37B3316C290,
		0x8120672FD8B652D7,
		0x6E7A54230135C266,
		0x246B6D5CCBCF0959
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DCEB1B25A081CA5,
		0xD1D876E4067EBCEE,
		0xB7A0D3B7D2E7EC48,
		0x33A22C032D8670AD
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8D6E3E7AD7E1E7B,
		0x4BD1FB916E40A302,
		0x474A1E3A064A8273,
		0x32BEFE825106A3C0
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14F7CDCAAC89FE2A,
		0x86067B52983E19EB,
		0x7056B57DCC9D69D5,
		0x00E32D80DC7FCCED
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDE6E32B8CAC97A6,
		0x4598518A5CD648CC,
		0x91B911600AA0EF41,
		0x40244DE884078AF3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A5B2D56511645D,
		0xB2CFC73C5FADF8D3,
		0x19F372F0FFCA7196,
		0x12C351714228A867
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC413056279B3349,
		0x92C88A4DFD284FF8,
		0x77C59E6F0AD67DAA,
		0x2D60FC7741DEE28C
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F2F6514721869D2,
		0xA10276A0EB79B44F,
		0xC2BDA9C4B60EB1A1,
		0x27BE481F397825C7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5C990321B5D45B,
		0x9FE78873862F499B,
		0x70D84ECD888489B0,
		0x0E2C10469BD1D36A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04D2CC1150629577,
		0x011AEE2D654A6AB4,
		0x51E55AF72D8A27F1,
		0x199237D89DA6525D
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8AC943412218608,
		0xCD59CFD3BCC05880,
		0x0C513AB356903C7D,
		0x7A29539689C277E3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4FAAAA85AAAFC14,
		0x4B08D1057DECA7E0,
		0x72EAB0CCB644A634,
		0x295CC38DB37ABFB6
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03B1E98BB77689F4,
		0x8250FECE3ED3B0A0,
		0x996689E6A04B9649,
		0x50CC9008D647B82C
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C57B6465FE48FB5,
		0x4625A65C812C5FB1,
		0x2AB3F3EFA6C2DB0F,
		0x08F8F5EEC73701D6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC315BE50E634929D,
		0xA073F0C7D2DD8698,
		0x0DAF269E2F6FB3C0,
		0x4ECC7ADCD0153BE8
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9941F7F579AFFD05,
		0xA5B1B594AE4ED918,
		0x1D04CD517753274E,
		0x3A2C7B11F721C5EE
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6705EE78624E8057,
		0x53F3DBE2303F6CC4,
		0x006CF6D60928A300,
		0x160AD3147DBA7BE1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0BCB8103C5D8BB,
		0xB660D7BC17B54878,
		0xC789A7CD9AFB7C31,
		0x5D823C5E730FC1FD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BFA22F75E88A789,
		0x9D930426188A244C,
		0x38E34F086E2D26CE,
		0x388896B60AAAB9E3
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E18480A45B1EB64,
		0xC6183A7EF9A00973,
		0x473D3DDB17A73C1C,
		0x0137DE4732C2C2A7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DBBEB0E479AB986,
		0xF78606BB04074131,
		0xF7C9D46A6AE67B51,
		0x064A4EDB577D8E66
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB05C5CFBFE1731CB,
		0xCE9233C3F598C841,
		0x4F736970ACC0C0CA,
		0x7AED8F6BDB453440
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x851412324F2A6340,
		0x24A814D39EBE22B2,
		0xDABE11D33FBF255F,
		0x3731F471D812810A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76E6B01C025F47F,
		0x0A18CD779778562E,
		0x470DF30BDD06C0DB,
		0x3235FDF088AF8C00
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA5A7308F046EC1,
		0x1A8F475C0745CC83,
		0x93B01EC762B86484,
		0x04FBF6814F62F50A
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x638DDA96C4707B4C,
		0xCF0D44B0C0FD8D99,
		0x0F60A736F053065F,
		0x3F8245BEBDE7F398
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8DD373E8EE198AC,
		0x9C1F32E7B205048B,
		0x673486CE5E9B9259,
		0x396A3ECFCD2E33C1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB0A358358EE2A0,
		0x32EE11C90EF8890D,
		0xA82C206891B77406,
		0x061806EEF0B9BFD6
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C32FF85D013CE2E,
		0xE9E38BC24228300C,
		0x9786559DCAA8D0C3,
		0x6438A447238B40FB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x898FB1BD761C6EBC,
		0x964C59503D513191,
		0x7E19FF1B2CA58FE5,
		0x700434C994A863DA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2A34DC859F75F5F,
		0x5397327204D6FE7A,
		0x196C56829E0340DE,
		0x74346F7D8EE2DD21
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61E46A7A02400A11,
		0x4996C74E35B55A4B,
		0x481D43AF73CD3AD4,
		0x0926A32EFE64C481
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9F4D5D8C409B131,
		0xFB9A7A462738BA90,
		0x73C10231FEE75DC4,
		0x30E5A0871E9AC430
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87EF94A13E3658CD,
		0x4DFC4D080E7C9FBA,
		0xD45C417D74E5DD0F,
		0x584102A7DFCA0050
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0236BB0495DFE850,
		0xD988D94868101E20,
		0x72B3DCF951922766,
		0x72597B352A66EC4C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90EC338482AAC1F5,
		0xBD04627FF5CFD09E,
		0xC1950DDDE11C1462,
		0x13082BA9686F2A51
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x714A87801335265B,
		0x1C8476C872404D81,
		0xB11ECF1B70761304,
		0x5F514F8BC1F7C1FA
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29D5395DA74D0941,
		0xFBFD359A9DF07F0D,
		0xC0C78F30FC6D52BF,
		0x0778B389748874C8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B93CD69EDDBDE87,
		0x84FD040311B73157,
		0xBEA8AF85E4A0866C,
		0x761E7CD014319228
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE416BF3B9712AA7,
		0x770031978C394DB5,
		0x021EDFAB17CCCC53,
		0x115A36B96056E2A0
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F0452624E38A867,
		0xC2B19953C8FC960C,
		0xA065A9E3A51F9A6E,
		0x5532476F8CFF97A4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA227CF39888F4E8,
		0xFA94E944A2F33AFD,
		0xB70FEE406468D57B,
		0x4852EB2873D5A956
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44E1D56EB5AFB37F,
		0xC81CB00F26095B0E,
		0xE955BBA340B6C4F2,
		0x0CDF5C471929EE4D
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB49EEAFF0A27C90,
		0x0EFCA7D53A39E783,
		0x4236E68203666ACC,
		0x66E19A53B29EBE4A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76C03E4E7E3B00E,
		0x9F32435727128269,
		0xD741F1E315E1BE60,
		0x6AA875451E8EA81B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43DDEACB08BECC6F,
		0x6FCA647E1327651A,
		0x6AF4F49EED84AC6B,
		0x7C39250E9410162E
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5C2333AB8DB563E,
		0x7159BAF1801459AC,
		0xC1D04D128E358D28,
		0x33D2EC32587AA3E4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79F1FECEA1AA85C8,
		0x57849B61CD499F17,
		0xC1D87185ED0BBB88,
		0x549325CF3F8D86B9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD0346C1730D063,
		0x19D51F8FB2CABA95,
		0xFFF7DB8CA129D1A0,
		0x5F3FC66318ED1D2A
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1895BBBB2B27862D,
		0x1106D3A8FADD1098,
		0xB30805E75248327B,
		0x35BD8A6938A50898
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1456AF039FAF1472,
		0x6B29C6310B4447D0,
		0x03F08867D86535CF,
		0x532868A718893015
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x043F0CB78B7871A8,
		0xA5DD0D77EF98C8C8,
		0xAF177D7F79E2FCAB,
		0x629521C2201BD883
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9E64AC5D00A642A,
		0xEF35F8A3626B5CD2,
		0xB34B7C7E100719ED,
		0x59A8E81A8C1F9780
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA053A3ABAF5E40,
		0x82842EEC171F65A7,
		0xF1F4E2E382516072,
		0x61BCC0DA7E39C793
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A45F722245B05D7,
		0x6CB1C9B74B4BF72B,
		0xC156999A8DB5B97B,
		0x77EC27400DE5CFEC
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F41736FB44452D5,
		0x74C42DA34BA4B19A,
		0x8C9C368AFC7FEAF7,
		0x695F8A4014B4E456
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14923F78F6EE2AB3,
		0x181B4DD12978FCA2,
		0xA4172CFD866F464B,
		0x1D8C4001944E9250
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AAF33F6BD562822,
		0x5CA8DFD2222BB4F8,
		0xE885098D7610A4AC,
		0x4BD34A3E80665205
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81764B4760375290,
		0x8F82EB0A981DE050,
		0x85152CEB81254518,
		0x653720B701CA6D0A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC374B84EA8C888DD,
		0x6E0326102A1734D2,
		0x7E0398227F8E88AB,
		0x4D2656D80EBBB7E8
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE0192F8B76EC9B3,
		0x217FC4FA6E06AB7D,
		0x071194C90196BC6D,
		0x1810C9DEF30EB522
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FCF2C4235CBE9A3,
		0x4E7D73924A3E6924,
		0xF4816CD3A040285A,
		0x1EF1F50B6F68BE47
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F965CEE07D3DE9,
		0x15DD1A6BC0E975D3,
		0x3AF3C057CF8B3D77,
		0x41AC6C8C512B519E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CD5C673554EABA7,
		0x38A059268954F350,
		0xB98DAC7BD0B4EAE3,
		0x5D45887F1E3D6CA9
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B09B457D9D25A3E,
		0x3C6A14795259F144,
		0x4BD0F790CDC6D270,
		0x62CA28FD9E7448F4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x179D769C956FC959,
		0xB0ACA2CFAB00E192,
		0x56027221CB317760,
		0x6C1A718109E40C2A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x836C3DBB446290D2,
		0x8BBD71A9A7590FB2,
		0xF5CE856F02955B0F,
		0x76AFB77C94903CC9
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD64ECEEEC1981828,
		0xE60B0B741758BA7F,
		0x93225E01463B9497,
		0x2B4E368E2F8B8010
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AACE4564ADFD334,
		0x6DD1CB3CA4F89FEC,
		0x8154E5E04555F8CF,
		0x32C8C0D96ABB23CD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BA1EA9876B844E1,
		0x7839403772601A93,
		0x11CD782100E59BC8,
		0x788575B4C4D05C43
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0147FF9339E030E0,
		0x0B28BC13CB06F073,
		0x6071112227397130,
		0x62945534D8A1C589
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE7451A6B1874E0F,
		0xEEC3EE3A4B673009,
		0x9F2A0EDDB6F1EC90,
		0x3FAD4B117F2CDB67
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22D3ADEC8858E2D1,
		0x1C64CDD97F9FC069,
		0xC14702447047849F,
		0x22E70A235974EA21
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D900B5B59D1409B,
		0x9F28557A1E329FB4,
		0xE1290E1385F6A83D,
		0x45A733F4956F0332
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B1546BD579B315,
		0x1311902EBDF65637,
		0x6F7A21A4B36EB277,
		0x2D4BECE3754C0732
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7DEB6EF84578D86,
		0x8C16C54B603C497C,
		0x71AEEC6ED287F5C6,
		0x185B47112022FC00
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x141D80CA28D8D5AC,
		0xE3195A4E2F20BB60,
		0x6AF4DE61C64A305C,
		0x1B300B7421B0AF2C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC3F2591809E13C0,
		0xA58375A5FBDE095A,
		0xB0F2F1141DE9BA79,
		0x06461524C9E8F952
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47DE5B38A83AC1EC,
		0x3D95E4A83342B205,
		0xBA01ED4DA86075E3,
		0x14E9F64F57C7B5D9
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6736FA166F868701,
		0x02F9DC05A5CA7C65,
		0x898D8A635C9A4D55,
		0x39FAEE97D1657C06
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63CF2F63B6E0E8F8,
		0x691F4FD1D9128B5D,
		0xFE438FFB7AF1005B,
		0x506617DBFEE54101
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0367CAB2B8A59DF6,
		0x99DA8C33CCB7F108,
		0x8B49FA67E1A94CF9,
		0x6994D6BBD2803B04
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE163BDB00103350E,
		0xD7427D79D2827F66,
		0x05FFBFEF46F490A6,
		0x6D7BA3C0B73C9BB9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BC8BF1998150182,
		0xADC9401838BED414,
		0xA9800A2C45F4806F,
		0x59ACE4B1E92E376C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x959AFE9668EE338C,
		0x29793D6199C3AB52,
		0x5C7FB5C301001037,
		0x13CEBF0ECE0E644C
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCB0D178270A1A37,
		0xFE182CEE8D8B610A,
		0x225E3772370CFA79,
		0x28217E646B675373
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1F6D8170458B902,
		0x2AC5F79F470C6539,
		0x6878E4A4EFD2F849,
		0x480462B11DD1D1C2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAB9F96122B16122,
		0xD352354F467EFBD0,
		0xB9E552CD473A0230,
		0x601D1BB34D9581B0
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3DD687F33DFD360,
		0x423776DCCE285E50,
		0x0E0BE8D972D2D438,
		0x1743846DFA37BAF2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20133453429E96FB,
		0x453E3D29A1E05964,
		0xACA82C93AD2FDF05,
		0x64926D575AFE760C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83CA342BF1413C52,
		0xFCF939B32C4804EC,
		0x6163BC45C5A2F532,
		0x32B117169F3944E5
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E8071D83E608CEC,
		0x48C6E03B6861FDC3,
		0xA009A65E79DBFACA,
		0x45E6B52783A52B63
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86872E71558CB405,
		0xE0761DC0C7F0A40C,
		0xD700E052BAA7F555,
		0x310F01CA6F670C93
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7F94366E8D3D8E7,
		0x6850C27AA07159B6,
		0xC908C60BBF340574,
		0x14D7B35D143E1ECF
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA54742EDD0DC797,
		0xDC9C87FF7057A711,
		0x0909687907A78A22,
		0x022F16E0E34A21ED
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7466C241BCEBEAD,
		0x6596E6CAA0C1292E,
		0x2B3A94EFF6850D51,
		0x4B8E9283FE49FE09
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF30E080AC13F08D7,
		0x7705A134CF967DE2,
		0xDDCED38911227CD1,
		0x36A0845CE50023E3
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D720B38036AC3F9,
		0x878B9D2F6408199F,
		0x7609362B2F405382,
		0x1A1F0178A8DAB98C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BD988C3A2CA79BA,
		0x18AE40E09BF485EF,
		0xDADF86DCF05E9F9A,
		0x4CB605853D9897C1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4198827460A04A2C,
		0x6EDD5C4EC81393B0,
		0x9B29AF4E3EE1B3E8,
		0x4D68FBF36B4221CA
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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