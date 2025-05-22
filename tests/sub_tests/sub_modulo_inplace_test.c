#include "../tests.h"

int32_t curve25519_key_sub_modulo_inplace_test(void) {
	printf("Inplace Modular Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5A5A03155FF069E0ULL,
		0xFDEC8E0E0B356C5BULL,
		0xF8D96CF40F41D298ULL,
		0x2EDC1BDE58FC0293ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x9AAE6F191B9F1841ULL,
		0x6BDD8DCECABB4682ULL,
		0x61BE1734D34974D7ULL,
		0x215886C2CA980EF7ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xBFAB93FC4451519FULL,
		0x920F003F407A25D8ULL,
		0x971B55BF3BF85DC1ULL,
		0x0D83951B8E63F39CULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303632AD7519DC88ULL,
		0x411F8306218A113BULL,
		0x2242FCC3688052E3ULL,
		0x4071BB5BC6533CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76BECA4D9A57466DULL,
		0x72ED0A80EF1ACD89ULL,
		0xA7428ACF82C85B2FULL,
		0x74835CFAB967EDE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB977685FDAC29608ULL,
		0xCE327885326F43B1ULL,
		0x7B0071F3E5B7F7B3ULL,
		0x4BEE5E610CEB4EF9ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6E44086BFE0D5C1ULL,
		0x0A5D61E64D338A23ULL,
		0x6AE85F817A70C356ULL,
		0x4B5FC1DC97F1F4D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2952B7F346A691A2ULL,
		0x00B5CCEDFEB01767ULL,
		0x781ECC558069886BULL,
		0x5AA2ACEB04DD048AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D918893793A440CULL,
		0x09A794F84E8372BCULL,
		0xF2C9932BFA073AEBULL,
		0x70BD14F19314F04EULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FBDA43BE37BE490ULL,
		0xEE682FBEF140A0ACULL,
		0xDB72396D62006940ULL,
		0x49F485439D1F60E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3D051F1295F5A9ULL,
		0xAD11C42B36484963ULL,
		0x4F224E0C0D1E354DULL,
		0x7557D6334A5796ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33809F1CD0E5EED4ULL,
		0x41566B93BAF85749ULL,
		0x8C4FEB6154E233F3ULL,
		0x549CAF1052C7CA3DULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1440E0C4F9994486ULL,
		0x401C0C398C524C6FULL,
		0x0A08CD76356B6627ULL,
		0x2923F3191D55BEB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95184A870AF7C2DDULL,
		0x60CA811514A33C0BULL,
		0xC5447B0DF7EF0166ULL,
		0x6A288815FF100989ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F28963DEEA18196ULL,
		0xDF518B2477AF1063ULL,
		0x44C452683D7C64C0ULL,
		0x3EFB6B031E45B527ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE5D2CCF5328F348ULL,
		0x788854EF58204C43ULL,
		0xB19AB369B03F3841ULL,
		0x7F70652CE4FB3C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1264FA74129AD8F2ULL,
		0xF69157408E8D6674ULL,
		0xFF3D3455FF7B38E5ULL,
		0x1705965EA5EF0C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBF8325B408E1A56ULL,
		0x81F6FDAEC992E5CFULL,
		0xB25D7F13B0C3FF5BULL,
		0x686ACECE3F0C2FF4ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59B65C4A1355EEA8ULL,
		0x3AEA5716AF20187DULL,
		0x841B01EB84DA5F1FULL,
		0x6E6E72E6AFF257E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C299C329B8F92EBULL,
		0x835E9006C0E56A69ULL,
		0xB16733CDF63F418AULL,
		0x210D8ECD0542A1F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD8CC01777C65BBDULL,
		0xB78BC70FEE3AAE13ULL,
		0xD2B3CE1D8E9B1D94ULL,
		0x4D60E419AAAFB5EBULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA3FCFEA73743FA0ULL,
		0x376EBC8B590F8E32ULL,
		0xB74287F86580181BULL,
		0x2E58EE8B4C9EF5BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F3084508163BF54ULL,
		0xA5559EF2E3D4CCE1ULL,
		0xB08AEA2CE68D596EULL,
		0x780A28766A73567FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB0F4B99F2108039ULL,
		0x92191D98753AC151ULL,
		0x06B79DCB7EF2BEACULL,
		0x364EC614E22B9F3FULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58F16A8461F19F58ULL,
		0x4B1EBF709DA39270ULL,
		0x92E45E9FF7A8AE5EULL,
		0x503C45A0E76EE611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88BFDFEBAB748091ULL,
		0xF4B952399A87FCEAULL,
		0xFF05D045B35F0C1DULL,
		0x265D838424A6DA2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0318A98B67D1EC7ULL,
		0x56656D37031B9585ULL,
		0x93DE8E5A4449A240ULL,
		0x29DEC21CC2C80BE3ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA5F331754418633ULL,
		0x8FB9233C765C0746ULL,
		0x7FA6EA2A1758CE7BULL,
		0x34CA082E95498C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEADFBE1EE3857431ULL,
		0x18D90E12A7FEA0ADULL,
		0x0A7C789E50DFA2D8ULL,
		0x2CFBA6C882B8594EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F7F74F870BC1202ULL,
		0x76E01529CE5D6699ULL,
		0x752A718BC6792BA3ULL,
		0x07CE6166129132DFULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA720F3CA64826CEULL,
		0x6447393EEEDDA892ULL,
		0xBA8D7C2C5F31E1F8ULL,
		0x756442C020F7E142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26AFC02548861EFEULL,
		0x59CF34EC283909EBULL,
		0x82541E1014AA9371ULL,
		0x4F4D23CB1873CFF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3C24F175DC207D0ULL,
		0x0A780452C6A49EA7ULL,
		0x38395E1C4A874E87ULL,
		0x26171EF50884114DULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93FD2F9A650B18B5ULL,
		0x07E1738C429BC881ULL,
		0x3768FD730110DB83ULL,
		0x263CF059E7046C06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E2241AE4232F39CULL,
		0x9648265CD6FA63E9ULL,
		0x088ED28BCA469C16ULL,
		0x1A83B242EC6BC4EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15DAEDEC22D82519ULL,
		0x71994D2F6BA16498ULL,
		0x2EDA2AE736CA3F6CULL,
		0x0BB93E16FA98A71CULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE5EDDFC1E54B538ULL,
		0xBF9B3EBCF738B6EBULL,
		0x7BF83F3D737B8AFBULL,
		0x76A6C69F0F4323A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A316F193B02D48ULL,
		0xF35AB90BB9E8575BULL,
		0x5B76095229C323D1ULL,
		0x1F1A098C3D696A72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09BBC70A8AA487F0ULL,
		0xCC4085B13D505F90ULL,
		0x208235EB49B86729ULL,
		0x578CBD12D1D9B92EULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE687260BFA86A4ADULL,
		0xD484AEBA98F0583FULL,
		0x2BAD15CC8CE65E90ULL,
		0x62FF3883C55792CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x785755D0ABFD6FDEULL,
		0xD4F170CF8AF24BEBULL,
		0x74F2DFFCC0CAD9A9ULL,
		0x28E5B8CB5B98B48DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E2FD03B4E8934CFULL,
		0xFF933DEB0DFE0C54ULL,
		0xB6BA35CFCC1B84E6ULL,
		0x3A197FB869BEDE3CULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3FF2AD1E8E755FDULL,
		0x2B0356FDC4E4F9ABULL,
		0x173C7FF7578C2FF3ULL,
		0x13B4ED08538916EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F1AF4E9B29AEF36ULL,
		0x812C0A9F56C1B0CEULL,
		0x1BD6FD8AD5D542DAULL,
		0x549F7D38F4D0DFACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24E435E8364C66B4ULL,
		0xA9D74C5E6E2348DDULL,
		0xFB65826C81B6ED18ULL,
		0x3F156FCF5EB83741ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECDA717791BED551ULL,
		0xE8FEA5C5FD09D471ULL,
		0x27908246A938216BULL,
		0x09893A75EA39E8A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28C762FE9676E353ULL,
		0x4D003CFEABBD7353ULL,
		0xF93E32AE7CFD55E2ULL,
		0x1AEB3DD64C91B786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4130E78FB47F1EBULL,
		0x9BFE68C7514C611EULL,
		0x2E524F982C3ACB89ULL,
		0x6E9DFC9F9DA8311CULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C310D33D3315686ULL,
		0x7711CA154F9AF8A0ULL,
		0xD54A7E2E420B1C93ULL,
		0x2867C63D4EA8AEF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B1D21481CE70CC2ULL,
		0x6F2D6342CED5832CULL,
		0xCDE8017D1EB307EAULL,
		0x63EC98D55B9CB4B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0113EBEBB64A49B1ULL,
		0x07E466D280C57574ULL,
		0x07627CB1235814A9ULL,
		0x447B2D67F30BFA44ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x037555AE9507FC6AULL,
		0xA12F39845ED3C1AAULL,
		0x499932AEEE563B41ULL,
		0x41B9429135E777A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x030D726360C79F47ULL,
		0x616CEA6F5588A4E8ULL,
		0xE16162F53880B043ULL,
		0x564B7165F11CDE25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0067E34B34405D10ULL,
		0x3FC24F15094B1CC2ULL,
		0x6837CFB9B5D58AFEULL,
		0x6B6DD12B44CA997AULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E0EBBDCA2ADDAA5ULL,
		0x3AD3BC33C57B0486ULL,
		0x40D6A24AEE0BED1FULL,
		0x26E33AB8BB5631BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9600EFC7837CC16ULL,
		0x7EACC6E46E864E10ULL,
		0x39B2E2F060332F9CULL,
		0x168D1D5CC8CE5AE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64AEACE02A760E8FULL,
		0xBC26F54F56F4B675ULL,
		0x0723BF5A8DD8BD82ULL,
		0x10561D5BF287D6D9ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3815D455809B4422ULL,
		0xC4FB934C9575329DULL,
		0x10CC0EEB3B5791F1ULL,
		0x1C856950DEA95066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BCAB90A57CE2F1ULL,
		0xDB7EFF32C242ABB3ULL,
		0xDF9155F8F82069EEULL,
		0x62D0DD38B2A3CCF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE5928C4DB1E611EULL,
		0xE97C9419D33286E9ULL,
		0x313AB8F243372802ULL,
		0x39B48C182C058374ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0503046914EC4DE5ULL,
		0xC4312236969E6D01ULL,
		0xBF36BB147D46DE22ULL,
		0x092CABA173B531EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD3FDD98F3FA39AULL,
		0x4BBC8A7385933EABULL,
		0xFEA352FAEFF23F87ULL,
		0x7B1471894719770DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA82F068F85ACAA38ULL,
		0x787497C3110B2E55ULL,
		0xC09368198D549E9BULL,
		0x0E183A182C9BBADFULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x750DC1866F843D38ULL,
		0x6A5D6590A9B65C04ULL,
		0xD7D6A4F7529047D8ULL,
		0x191A83D4F07E5CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8761A66C195DF51CULL,
		0xCAC49EF0A39D34ADULL,
		0x5D61D0C383E8099FULL,
		0x6EC0A9E2B7EEFB42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDAC1B1A56264809ULL,
		0x9F98C6A006192756ULL,
		0x7A74D433CEA83E38ULL,
		0x2A59D9F2388F61ACULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8067E1749632DC0BULL,
		0x3E0E65B6DC13A437ULL,
		0x7C17877C624EBA53ULL,
		0x4CC5621BC3DD8726ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x394B57F4E83E77D3ULL,
		0x851FA6F262B23731ULL,
		0xE841924471690551ULL,
		0x6BABB5A36A06A206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x471C897FADF46425ULL,
		0xB8EEBEC479616D06ULL,
		0x93D5F537F0E5B501ULL,
		0x6119AC7859D6E51FULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD594A7F236C996BULL,
		0xBD67EC918938FC3AULL,
		0xC4EB9CAD6EADEF24ULL,
		0x590C71F7B1315A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67BB1D4CE91DAF2ULL,
		0x3B790C66086DAD7DULL,
		0x886E84FC823966FEULL,
		0x183520226AAE183BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06DD98AA54DABE79ULL,
		0x81EEE02B80CB4EBDULL,
		0x3C7D17B0EC748826ULL,
		0x40D751D546834215ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x036B25EFB0BA7D47ULL,
		0xB22C9DD629158E50ULL,
		0xAA6D38FA16976245ULL,
		0x550737684DD352DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2278AB4D06DBF379ULL,
		0x4AD892B824278DF4ULL,
		0x8C122FEAC336DE07ULL,
		0x07F526DFE9277260ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0F27AA2A9DE89CEULL,
		0x67540B1E04EE005BULL,
		0x1E5B090F5360843EULL,
		0x4D12108864ABE07AULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61168A004DAE91C7ULL,
		0x264CCDB947DA85B0ULL,
		0xA3135F709CC2C8A1ULL,
		0x79F040C78BEEE562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342592B41001DA2EULL,
		0xC958A2726D114A6BULL,
		0x674164AC5DBB98B1ULL,
		0x6814D084EAF63999ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CF0F74C3DACB799ULL,
		0x5CF42B46DAC93B45ULL,
		0x3BD1FAC43F072FEFULL,
		0x11DB7042A0F8ABC9ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CE5DFF59464A4A9ULL,
		0xFF8F5F6670B6899FULL,
		0xA926245B97B3A6C7ULL,
		0x530AA6E0AEE9E3A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF83D96FFE6896BULL,
		0x6625CFEB499C6F7EULL,
		0xD3854EAEF657A140ULL,
		0x5FD087A38ECA24D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFEDA25E947E1B2BULL,
		0x99698F7B271A1A20ULL,
		0xD5A0D5ACA15C0587ULL,
		0x733A1F3D201FBED8ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FCFD6EEB6A5D2F1ULL,
		0xE4818528E92A45EAULL,
		0xD902BDEEE1204E30ULL,
		0x607355E7D11D0D73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7EB91F780DA78D4ULL,
		0x006629C0CC238B28ULL,
		0xFBC140F2609315B8ULL,
		0x74C0E376584FA115ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67E444F735CB5A0AULL,
		0xE41B5B681D06BAC1ULL,
		0xDD417CFC808D3878ULL,
		0x6BB2727178CD6C5DULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABB6475286C30DC3ULL,
		0x529761E63BA4CA08ULL,
		0xBC098F4BA40739D1ULL,
		0x490172CE7C265BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14DDC4BBB2D0A35CULL,
		0x7DC433B75427812CULL,
		0x3F7508EE0C3EE08EULL,
		0x3539D43E4BA37231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96D88296D3F26A67ULL,
		0xD4D32E2EE77D48DCULL,
		0x7C94865D97C85942ULL,
		0x13C79E903082E9A8ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39D1B7D23703EAC3ULL,
		0x3E2A0639E5C95DEDULL,
		0x26CA070C2AF6495CULL,
		0x784340882BAE5C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C6F29C7CBBE868ULL,
		0x4A6B31A200926B79ULL,
		0x4717C034BD430174ULL,
		0x56CFB0DBB84980FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x180AC535BA48025BULL,
		0xF3BED497E536F274ULL,
		0xDFB246D76DB347E7ULL,
		0x21738FAC7364DB35ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x917B40BC0D443DC1ULL,
		0x604A58FB1D449520ULL,
		0xEDB1049786B5B7BCULL,
		0x5010EF3EAB9BE99EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x016873CE0783B394ULL,
		0x989AD3389B8C0858ULL,
		0x7F5137DC1A4718D4ULL,
		0x433B5959A0CD6B70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9012CCEE05C08A2DULL,
		0xC7AF85C281B88CC8ULL,
		0x6E5FCCBB6C6E9EE7ULL,
		0x0CD595E50ACE7E2EULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC873C7B83E765FC6ULL,
		0xC37F60F52BEDC7D6ULL,
		0xA1A4D33B60460FF1ULL,
		0x77DFE7CF91CD8C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x470FB8E374CF4F9AULL,
		0x573619C0F7225489ULL,
		0x60BF2A99928928C9ULL,
		0x70126A00568F613EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81640ED4C9A7102CULL,
		0x6C49473434CB734DULL,
		0x40E5A8A1CDBCE728ULL,
		0x07CD7DCF3B3E2B29ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F2B9639B2CFF365ULL,
		0x5E60ECCA1ACDB249ULL,
		0xFBFA644F3EA57AA7ULL,
		0x1DBFA5B3EF3FE87CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B71779B78F18097ULL,
		0x4241B112BA315EECULL,
		0x54BB9F7A4EC8B978ULL,
		0x09DAD752D0FBA17BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93BA1E9E39DE72CEULL,
		0x1C1F3BB7609C535CULL,
		0xA73EC4D4EFDCC12FULL,
		0x13E4CE611E444701ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB322B3E7595824BBULL,
		0x5C8924F13DD9930DULL,
		0x31BC4429CF1857AFULL,
		0x79CECC2B8958078AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA751B1B6F187DF9AULL,
		0x2E52D3025B2D6057ULL,
		0xE0D044ECF0F4CCEAULL,
		0x6BFDD76B1CA21A27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BD1023067D04521ULL,
		0x2E3651EEE2AC32B6ULL,
		0x50EBFF3CDE238AC5ULL,
		0x0DD0F4C06CB5ED62ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x843C9D1307215E80ULL,
		0x058C789D5D164916ULL,
		0x80D8778613A909FFULL,
		0x6B3FCCE33EB2970CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22C2EEF5D36228FDULL,
		0x84D8FE01202507C1ULL,
		0xCE711F44E9F8CC9AULL,
		0x12F844EC0C69039DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6179AE1D33BF3583ULL,
		0x80B37A9C3CF14155ULL,
		0xB267584129B03D64ULL,
		0x584787F73249936EULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEA175514030FFDAULL,
		0x3ACE0865A7838D9CULL,
		0x363E54B5BF68262DULL,
		0x1263BA2642041717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCE593CD9BF19B86ULL,
		0x76E521784FC17539ULL,
		0x77059BC0032DEFEEULL,
		0x17F55EAF52352508ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11BBE183A43F6441ULL,
		0xC3E8E6ED57C21863ULL,
		0xBF38B8F5BC3A363EULL,
		0x7A6E5B76EFCEF20EULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92DD4388EB4386D4ULL,
		0x217674FEA50278C9ULL,
		0xC44092F6FAC13D83ULL,
		0x0D31407B4699AF2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE19AC3A6439EF17ULL,
		0xD782DDBE15A03BD5ULL,
		0xF8ED0A9E29AC1122ULL,
		0x7EEC39FB22EB7DE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C3974E870997AAULL,
		0x49F397408F623CF3ULL,
		0xCB538858D1152C60ULL,
		0x0E45068023AE3145ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B96556DC2A6C25CULL,
		0x1735301CA6F56BB3ULL,
		0x03D38081AEB96235ULL,
		0x2330B529C0C14F83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E10AA48BE09502ULL,
		0xBA84F24BD35163BDULL,
		0x09479E62EB0C191BULL,
		0x2B330CAD9A9B2968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7B54AC936C62D47ULL,
		0x5CB03DD0D3A407F5ULL,
		0xFA8BE21EC3AD4919ULL,
		0x77FDA87C2626261AULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD9CEB8C33EC9D75ULL,
		0x8BC0BA2F74912D9FULL,
		0x49CBA397E8B70D34ULL,
		0x58C9C47DFC310092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA564CB0B3A4E72ULL,
		0xB32E3520DEF6C58EULL,
		0x8910CBBFCE376285ULL,
		0x24D1DDF0AB88624BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91F786C128B24F03ULL,
		0xD892850E959A6811ULL,
		0xC0BAD7D81A7FAAAEULL,
		0x33F7E68D50A89E46ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62DAC254BF48BC87ULL,
		0x1BA1E9DA083620D5ULL,
		0x2D95BC7501120BE0ULL,
		0x43F679BFEB3ACE90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF12A48C5CCAA0CC7ULL,
		0x3FAC5087BC22F66FULL,
		0x0B4379972924E699ULL,
		0x32E1C74966743EBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71B0798EF29EAFC0ULL,
		0xDBF599524C132A65ULL,
		0x225242DDD7ED2546ULL,
		0x1114B27684C68FD6ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50A56FE127E843E9ULL,
		0x57C175975FBCB1C7ULL,
		0xEB5D79400920B46DULL,
		0x0E342CDA905B35B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72124B398726E9F6ULL,
		0xC0B5FE31FA200B77ULL,
		0x9B25220734A433CEULL,
		0x68D8CE484917C503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE9324A7A0C159E0ULL,
		0x970B7765659CA64FULL,
		0x50385738D47C809EULL,
		0x255B5E92474370B6ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4A0833D9B2FD292ULL,
		0x4F4827A6BDF272D3ULL,
		0x86F3DFCE3DFF9C3FULL,
		0x7C14DCF1ADCE0E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0B8D8F6206094B8ULL,
		0x6D4F7E95E82BA191ULL,
		0x56FFB7486010C5A0ULL,
		0x06FCCAB22ECD4F8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03E7AA477ACF3DDAULL,
		0xE1F8A910D5C6D142ULL,
		0x2FF42885DDEED69EULL,
		0x7518123F7F00BEB3ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94673428B600FB7BULL,
		0xEB7C8B05EF6A33C7ULL,
		0x2F5DD02823A92ECDULL,
		0x28BE7BEFB6979BB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A18E491D1B2807ULL,
		0xFC97AB5D2DEAE583ULL,
		0xE1B0421558EF8855ULL,
		0x77D87B0721948890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CC5A5DF98E5D361ULL,
		0xEEE4DFA8C17F4E44ULL,
		0x4DAD8E12CAB9A677ULL,
		0x30E600E89503131FULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7D3CB1903500020ULL,
		0xF5AEC7AC2EE7241FULL,
		0xF5E7295DD7DA96AAULL,
		0x5AA258309B15A79EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x882D808275E3A12FULL,
		0x08EB6E7201428ED2ULL,
		0x429484D7CC7BF9DDULL,
		0x37820DFB6C3A74B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FA64A968D6C5EF1ULL,
		0xECC3593A2DA4954DULL,
		0xB352A4860B5E9CCDULL,
		0x23204A352EDB32E5ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE1B808CB4AAF63EULL,
		0xDD9A92515A27528EULL,
		0x730394622D4D41F6ULL,
		0x535ED0BA3A4B8A4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A0243B359054BCULL,
		0xCBE26FC4687B6D56ULL,
		0x974D15978B88B03BULL,
		0x6C5D3865AB5543C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C7B5C517F1AA16FULL,
		0x11B8228CF1ABE538ULL,
		0xDBB67ECAA1C491BBULL,
		0x670198548EF64685ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8970358545493589ULL,
		0xC80EA045967ADC96ULL,
		0xB082DB01DBDF4A65ULL,
		0x5FEA238EE958F6CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA12E54F89448FEULL,
		0x5353D93FCB6B5183ULL,
		0x7A1B0F93419C86C4ULL,
		0x22A0B422E776125EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BCF07304CB4EC8BULL,
		0x74BAC705CB0F8B12ULL,
		0x3667CB6E9A42C3A1ULL,
		0x3D496F6C01E2E46DULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2B6A848549E733DULL,
		0x57C46313E2969740ULL,
		0x341ECEF16E28DB6DULL,
		0x4CB7C8A5E869C686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97F43AF3DE8A45FULL,
		0x498E2DEEDCCBD2B4ULL,
		0x50FADAEF54CD26F3ULL,
		0x328ED9B2FEC19808ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC937649916B5CEDEULL,
		0x0E36352505CAC48BULL,
		0xE323F402195BB47AULL,
		0x1A28EEF2E9A82E7DULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF38E372A5C72DA5DULL,
		0xEC06F87FE8052177ULL,
		0x0D33551BB203873CULL,
		0x14E83CC2D6EE677FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF9CFC79160E3FCULL,
		0xAAD069B73ADD0EA4ULL,
		0x3ACF50AD74D01394ULL,
		0x166FA59D5B95EAF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13946762CB11F64EULL,
		0x41368EC8AD2812D3ULL,
		0xD264046E3D3373A8ULL,
		0x7E7897257B587C8BULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDAA3F4DC5D27E25ULL,
		0x789E6D148AC2AE84ULL,
		0x5F5A35B35C3F8132ULL,
		0x558376835CFBEC07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55AB9DE38BA86A07ULL,
		0xC3533B18765866A8ULL,
		0xC6537AAC55693B16ULL,
		0x46D3B5FEC7ED80FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97FEA16A3A2A141EULL,
		0xB54B31FC146A47DCULL,
		0x9906BB0706D6461BULL,
		0x0EAFC084950E6B08ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C36B3589BF87B09ULL,
		0xF59D24ABFA0AE707ULL,
		0x2888F2689396CA9BULL,
		0x06D11EA6F542500AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA39E5AA86AAFDD7ULL,
		0x20CF1F18C8FECD47ULL,
		0xF962E42533ECAE0DULL,
		0x738FDE7F79D87BF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61FCCDAE154D7D1FULL,
		0xD4CE0593310C19BFULL,
		0x2F260E435FAA1C8EULL,
		0x134140277B69D417ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE49BCD70BC7F80B8ULL,
		0xBA077BEF68871000ULL,
		0x7DF135D6A8E6E85BULL,
		0x61640EE25C2772C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2329A8AB141D554EULL,
		0x0DD9A3FF296C390BULL,
		0xEC84532DD6412731ULL,
		0x5418AB10F08CE3C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC17224C5A8622B6AULL,
		0xAC2DD7F03F1AD6F5ULL,
		0x916CE2A8D2A5C12AULL,
		0x0D4B63D16B9A8EFBULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x784C479DE5224C2BULL,
		0xA9A23ACF8AE5F8D4ULL,
		0x4B4F09AC7A95C845ULL,
		0x5052105D2406C982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DA8FD4053B3888FULL,
		0x74A37642CD8F4C61ULL,
		0xDE6A4F2E39B15637ULL,
		0x11B9666BC5542F53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AA34A5D916EC39CULL,
		0x34FEC48CBD56AC73ULL,
		0x6CE4BA7E40E4720EULL,
		0x3E98A9F15EB29A2EULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE33EFD898BFE59ACULL,
		0x0825E504CEA0E98DULL,
		0xC26041655E19313EULL,
		0x1C41DAD992ADE423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA01883BA495B5724ULL,
		0x93815851B45AF429ULL,
		0x88D56CBAB95C1D15ULL,
		0x70707EBFE000C412ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x432679CF42A30275ULL,
		0x74A48CB31A45F564ULL,
		0x398AD4AAA4BD1428ULL,
		0x2BD15C19B2AD2011ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6123C561F6B1899CULL,
		0xE01767E223DF5F6DULL,
		0x62F3BA620ACD3C04ULL,
		0x3ACE0595CAF72574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBA09CC0AEF380FBULL,
		0x60A6009A535F7DFFULL,
		0x9D46AB7AE1B199D5ULL,
		0x68C82F434424CFAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x958328A147BE088EULL,
		0x7F716747D07FE16DULL,
		0xC5AD0EE7291BA22FULL,
		0x5205D65286D255C9ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6396A69B083BB960ULL,
		0xD26F1265D1D719B0ULL,
		0xC31683F2F43F6B96ULL,
		0x1ADAE2749052EDB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4AAF95BAACDCC96ULL,
		0x206F701F90C35138ULL,
		0xBCA7354EECB8A7EAULL,
		0x4C64AC5B7F43157AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEEBAD3F5D6DECB7ULL,
		0xB1FFA2464113C877ULL,
		0x066F4EA40786C3ACULL,
		0x4E763619110FD83EULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67BE3FC37762B9DCULL,
		0x3FB459FCBF4C6405ULL,
		0x78996867C49AFB8DULL,
		0x6BE49CBBDDC8EC14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC3F0307531430C3ULL,
		0xE3F035E27C2FB5B2ULL,
		0xC0C0EF813A1DDE9CULL,
		0x24F388DAFE47D689ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB7F3CBC244E8919ULL,
		0x5BC4241A431CAE52ULL,
		0xB7D878E68A7D1CF0ULL,
		0x46F113E0DF81158AULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEC6504F7C096B9FULL,
		0x4A9EF125EA82088AULL,
		0x2427A838590C725FULL,
		0x2673AD790AD517D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B9C5DFE1B6C993DULL,
		0xC42179B8ABA2DA7BULL,
		0x401C974F2322037FULL,
		0x11C0629933D8F27CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA329F251609CD262ULL,
		0x867D776D3EDF2E0FULL,
		0xE40B10E935EA6EDFULL,
		0x14B34ADFD6FC2553ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6095763C47480A57ULL,
		0x73C8F2255EEF7C80ULL,
		0xCA864A32A145B243ULL,
		0x7D38749566C8EFBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BE2F53BC966152FULL,
		0x83D1B6229C9754DAULL,
		0x759AB2CE5E7BE659ULL,
		0x52A76D68E85502ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14B281007DE1F528ULL,
		0xEFF73C02C25827A6ULL,
		0x54EB976442C9CBE9ULL,
		0x2A91072C7E73ED11ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DB0B73BF83F861CULL,
		0xD9AA6BEC3D84178AULL,
		0x2CC5589971DC4B58ULL,
		0x09E96D5F07D62FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD40741C1580D4AEAULL,
		0xDF7EE928877AD805ULL,
		0x9C11416975759D00ULL,
		0x62066EFE078B4F18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9A9757AA0323B1FULL,
		0xFA2B82C3B6093F84ULL,
		0x90B4172FFC66AE57ULL,
		0x27E2FE61004AE0A1ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64F97DFC4CCB1CFEULL,
		0x92061C23E901FC2FULL,
		0x7D35E58C0A674B6CULL,
		0x2B627669FDCA8141ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE5FC0A8C783809ULL,
		0x56B15D9F69234772ULL,
		0xEB9FFA1B8FB905B2ULL,
		0x207A999161556651ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x751381F1C052E4F5ULL,
		0x3B54BE847FDEB4BCULL,
		0x9195EB707AAE45BAULL,
		0x0AE7DCD89C751AEFULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DBAEAD0F21107FAULL,
		0x06CB1301855AB6D6ULL,
		0xF78A6B7650224DA5ULL,
		0x7E6CA61A950AA0A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E72B4ECD7B358C0ULL,
		0xB7903E694778597FULL,
		0xE9376D9E8A0C2937ULL,
		0x0E90D82E181DB16AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F4835E41A5DAF3AULL,
		0x4F3AD4983DE25D57ULL,
		0x0E52FDD7C616246DULL,
		0x6FDBCDEC7CECEF36ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8ABE5827A6049D2ULL,
		0x2AC5A690370EE088ULL,
		0x5470548B0233FB39ULL,
		0x13782D0C5CA3F10AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2787DCE2DCEA718AULL,
		0x2711F76CA5EA9E18ULL,
		0x2F8A833B3CFE362CULL,
		0x00720A6471BFE888ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA124089F9D75D848ULL,
		0x03B3AF2391244270ULL,
		0x24E5D14FC535C50DULL,
		0x130622A7EAE40882ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8A1654D896BA6A3ULL,
		0x7ED5AB63F4540CF7ULL,
		0xCF4F01E926109EA8ULL,
		0x369FCFF8C5A2C9C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA66E23DC85CBF4ULL,
		0x94A0D2FDCF0BFD7DULL,
		0xAC2CA0346ECA0CC1ULL,
		0x3AE86CFB7B8F7AB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BFAF729ACE5DA9CULL,
		0xEA34D86625480F7AULL,
		0x232261B4B74691E6ULL,
		0x7BB762FD4A134F17ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ACD99B5B97B9ACFULL,
		0x8D8461D0C7676D34ULL,
		0xEF0A2B10C61020A1ULL,
		0x0277038BE3115D15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD4AC91276F21F1ULL,
		0x62F383240E4BA84EULL,
		0x6FE768D576CBFD61ULL,
		0x0DFEF526AAE223CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEF8ED24920C78CBULL,
		0x2A90DEACB91BC4E5ULL,
		0x7F22C23B4F442340ULL,
		0x74780E65382F394AULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB84BC57C3CCF7865ULL,
		0x8D88BF50DE464AD1ULL,
		0x2373F0382120FF8DULL,
		0x4A02E33C1C8961D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21797988AE7356F4ULL,
		0x7C90087EED7E99BFULL,
		0x1109AAC9B6966E7AULL,
		0x46ADF744C35E2017ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96D24BF38E5C2171ULL,
		0x10F8B6D1F0C7B112ULL,
		0x126A456E6A8A9113ULL,
		0x0354EBF7592B41BAULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41943C93CB62430EULL,
		0x379C04AB6066370DULL,
		0xA260E775D486BA6FULL,
		0x4CBA9A0786C77087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFCEB5BC9F96C49AULL,
		0x201F4FBDFA38E976ULL,
		0xC8BDC35573296E07ULL,
		0x29420CEE0736174CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81C586D72BCB7E74ULL,
		0x177CB4ED662D4D96ULL,
		0xD9A32420615D4C68ULL,
		0x23788D197F91593AULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE6B7E4C10B5221EULL,
		0x287A564497446C99ULL,
		0xB0BEF2D9B96CC74AULL,
		0x478B06E144EA0C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC781F0317A2C9E43ULL,
		0xCBA594607FDCA292ULL,
		0x9F03B1B592AA3097ULL,
		0x517478AFA69A2BB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16E98E1A968883C8ULL,
		0x5CD4C1E41767CA07ULL,
		0x11BB412426C296B2ULL,
		0x76168E319E4FE056ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6CABB900A6EE255ULL,
		0xC799ECE2906C7990ULL,
		0xECF7AF868680C9A4ULL,
		0x7FA21BE1B36937B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFCA1620DE9414BDULL,
		0x03749A1A3EC8D63EULL,
		0x7532D048A5466820ULL,
		0x4A841CA0B1934126ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1700A56F2BDACD98ULL,
		0xC42552C851A3A352ULL,
		0x77C4DF3DE13A6184ULL,
		0x351DFF4101D5F68DULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9522992D966AC9ABULL,
		0x986F318CBAA48688ULL,
		0xF033DBEC8C9B62CEULL,
		0x3A9BF21C0C7F6BE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA69CA0E5C66EE6ADULL,
		0x2FEF73D9FEF4D3AAULL,
		0x8CA49896ECBD5FE6ULL,
		0x1CB355E9013727B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE85F847CFFBE2FEULL,
		0x687FBDB2BBAFB2DDULL,
		0x638F43559FDE02E8ULL,
		0x1DE89C330B484430ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ED56467E0F2A8AAULL,
		0x8B9BBCF69B6E54E4ULL,
		0xD13DC2251D97373DULL,
		0x397CF0CD97559790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F709CFC6081B09ULL,
		0xBE3B60D01C549E58ULL,
		0x03017B185B9DAEEBULL,
		0x6DE2D78E95050C1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCDE5A981AEA8D8EULL,
		0xCD605C267F19B68BULL,
		0xCE3C470CC1F98851ULL,
		0x4B9A193F02508B73ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF40D8E845C785B7DULL,
		0x619A1F187903CA7AULL,
		0x7E43FCB064F59AA3ULL,
		0x4F4403903CCF1DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40CE41B6D59DDDA2ULL,
		0x1A72278FCC7B90BDULL,
		0xCE507C0988A918A1ULL,
		0x7E157B1026B17B1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB33F4CCD86DA7DC8ULL,
		0x4727F788AC8839BDULL,
		0xAFF380A6DC4C8202ULL,
		0x512E8880161DA28EULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AE216CF14D8C50EULL,
		0xE64BD903DF8E7823ULL,
		0x08ACCC0948DE5D36ULL,
		0x1D775ADA931DFB37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFC87DCCAD7F8AAFULL,
		0xD2CFA3693048F788ULL,
		0x4C5BDB0B9287C601ULL,
		0x4B693662DB1256C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B19990267593A4CULL,
		0x137C359AAF45809AULL,
		0xBC50F0FDB6569735ULL,
		0x520E2477B80BA46DULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90503B1E08F88BD4ULL,
		0x342C6A250E8FB74BULL,
		0x1C1D7802F1AA48D7ULL,
		0x14492F07D16EC1B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AF273F4E607BE98ULL,
		0x0FBDE7D97190EFC3ULL,
		0x6FF08D608EDE8852ULL,
		0x6D41A8D6EC18A372ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x355DC72922F0CD29ULL,
		0x246E824B9CFEC788ULL,
		0xAC2CEAA262CBC085ULL,
		0x27078630E5561E45ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35CE58606BB7F2DAULL,
		0xA000C41301A71769ULL,
		0xE7C29BCF94B90634ULL,
		0x3018676ABD28E5FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E25DEF2CFDB3AFULL,
		0xEA8563C476F6961EULL,
		0x53E11D087474ADCBULL,
		0x48E6160E250EB090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4EBFA713EBA3F18ULL,
		0xB57B604E8AB0814AULL,
		0x93E17EC720445868ULL,
		0x6732515C981A356EULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7739ACF485F35ECFULL,
		0x82C242F574E8BA5EULL,
		0xADB20FEECDE47B93ULL,
		0x3791EB4EBFB21AC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D45E4DE5578760CULL,
		0x6E06E87F4734266CULL,
		0x514385738E5FA2EEULL,
		0x600EECB55C34EDA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19F3C816307AE8B0ULL,
		0x14BB5A762DB493F2ULL,
		0x5C6E8A7B3F84D8A5ULL,
		0x5782FE99637D2D20ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD24F4A04A1C9B1EULL,
		0xB75C97A946D9FCADULL,
		0x0810108A0CD2FCEFULL,
		0x69573A65268FBC90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2C30DC54AFE28D2ULL,
		0xE12E03E290D99902ULL,
		0x699597E0AE47B8C9ULL,
		0x1A307BA5B9F816BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA61E6DAFF1E724CULL,
		0xD62E93C6B60063AAULL,
		0x9E7A78A95E8B4425ULL,
		0x4F26BEBF6C97A5D0ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x980BA72BD87E2A4BULL,
		0x80D691BBFAC4DA61ULL,
		0x2F42C92B25FDAF60ULL,
		0x00B4B07C60D97E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810A0B1695255C14ULL,
		0xE7A8758FA2979C0FULL,
		0xF8B506F580646283ULL,
		0x2FA7C55FF536A4A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17019C154358CE24ULL,
		0x992E1C2C582D3E52ULL,
		0x368DC235A5994CDCULL,
		0x510CEB1C6BA2D979ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AA3F667F2BACF37ULL,
		0x5F2389AFF74F263DULL,
		0x810086E2D636E270ULL,
		0x41222A3360899274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x838610E97D80B623ULL,
		0x32E4CC171A95A4CFULL,
		0x612A4ACBE19D7777ULL,
		0x4F3ED34F2A9A4A5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x971DE57E753A1901ULL,
		0x2C3EBD98DCB9816DULL,
		0x1FD63C16F4996AF9ULL,
		0x71E356E435EF4818ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2D2C9E2BFDFDC63ULL,
		0x4FFD087B87CFB9FAULL,
		0xBC2E3DE443A5640FULL,
		0x0B4166EA80A9C839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B737D5C921FE7F7ULL,
		0x78EF212E54504757ULL,
		0x2515D1F67984769DULL,
		0x2579469798F688DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x875F4C862DBFF459ULL,
		0xD70DE74D337F72A3ULL,
		0x97186BEDCA20ED71ULL,
		0x65C82052E7B33F5AULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0A873FE1E7964F1ULL,
		0x7D5CC86FAF0C64DFULL,
		0xB5351607BBD83342ULL,
		0x7E70290E9ED95C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48B20425FCDC9644ULL,
		0x6F382B5641408E3EULL,
		0x214A658994BAD9CFULL,
		0x52857D49AB91DFA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97F66FD8219CCEADULL,
		0x0E249D196DCBD6A1ULL,
		0x93EAB07E271D5973ULL,
		0x2BEAABC4F3477CE9ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9344BDB984F7E7DULL,
		0x097D6885E47CCDD2ULL,
		0x333A26601AECACD4ULL,
		0x2B5380DB45E28491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38A64F5DD0ECAAA1ULL,
		0x6B2F9DA282C5F4D1ULL,
		0xD431F33C91ACFC48ULL,
		0x3E359D8D5D67705FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB08DFC7DC762D3C9ULL,
		0x9E4DCAE361B6D901ULL,
		0x5F083323893FB08BULL,
		0x6D1DE34DE87B1431ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB27D8DC66AC6B19ULL,
		0x2974851E4696713AULL,
		0x380578899C331111ULL,
		0x6B973501C0F96093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB70A5D976EBAC5DFULL,
		0x6908EFEDCF4DC1E6ULL,
		0xF70FB975FD141FEBULL,
		0x5555B541D03354BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041D7B44F7F1A53AULL,
		0xC06B95307748AF54ULL,
		0x40F5BF139F1EF125ULL,
		0x16417FBFF0C60BD8ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x368C4BFB4E4838B3ULL,
		0xB2BD11798A17956EULL,
		0xE3CDF1F6C4C7DB0FULL,
		0x5D0A48087F901B3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB39BF695AA251C6DULL,
		0x3B812C40387C5481ULL,
		0x9D89642788B2FDD7ULL,
		0x3BC897F88D65AAFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82F05565A4231C46ULL,
		0x773BE539519B40ECULL,
		0x46448DCF3C14DD38ULL,
		0x2141B00FF22A7040ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x877A50ADC241122AULL,
		0x2267341DA61CB150ULL,
		0x0BD786A6048E9220ULL,
		0x17F39D4BAA9DEFC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6793B18B2E2F01ULL,
		0x5CC060977E128288ULL,
		0x196F9A9791C76DA8ULL,
		0x02CAEB5A49C6555FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B12BCFC3712E329ULL,
		0xC5A6D386280A2EC8ULL,
		0xF267EC0E72C72477ULL,
		0x1528B1F160D79A61ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF28A297A5402E450ULL,
		0x55EE169840048454ULL,
		0x1DB8B05A2A7B7F80ULL,
		0x64416520E475EC10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFEC84DE39E1E6CULL,
		0x261BA2FFD83F987BULL,
		0x9322D26A65C97074ULL,
		0x06F8DC3A1D784888ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x758B612C7064C5E4ULL,
		0x2FD2739867C4EBD9ULL,
		0x8A95DDEFC4B20F0CULL,
		0x5D4888E6C6FDA387ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BEE8FB2888A36A0ULL,
		0x2B95B36EC09F7743ULL,
		0x0F22420FB1BFFD2AULL,
		0x6D4D6C496F9266B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B15D5F7222C71BULL,
		0xE62171987E8CC9EBULL,
		0x663C5DC99E23029EULL,
		0x6F833AE9CABB6EF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x543D325316676F72ULL,
		0x457441D64212AD58ULL,
		0xA8E5E446139CFA8BULL,
		0x7DCA315FA4D6F7BBULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFC05A8FF4A175EBULL,
		0xE96E0B7A419F08E0ULL,
		0xF851929EF09B688EULL,
		0x4F1B4DA9E4F1EBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D54467F05507B44ULL,
		0xA1C255706569520EULL,
		0x7EBAC2CB404ADFD5ULL,
		0x3D2E220F61F4F881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA26C1410EF50FAA7ULL,
		0x47ABB609DC35B6D2ULL,
		0x7996CFD3B05088B9ULL,
		0x11ED2B9A82FCF326ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8D6ED5B236360DEULL,
		0x7F8AC4DF565D2601ULL,
		0x39EB5DEF8EFA5EDFULL,
		0x67C1D29528310F2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE53813FA1029B32ULL,
		0x54422B9587954B26ULL,
		0x2C39396F175DA59CULL,
		0x799A80B4E693772DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A836C1B8260C599ULL,
		0x2B489949CEC7DADBULL,
		0x0DB22480779CB943ULL,
		0x6E2751E0419D9801ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x430751D988D09BFAULL,
		0x6358D8E04F13CA15ULL,
		0x689FDF6EC9983AB0ULL,
		0x12163F11B8E49775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA7B3807D5026219ULL,
		0x0BD30EA8912601B6ULL,
		0x05F9651DD1C442C9ULL,
		0x4521FE256DDBF98FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x888C19D1B3CE39CEULL,
		0x5785CA37BDEDC85EULL,
		0x62A67A50F7D3F7E7ULL,
		0x4CF440EC4B089DE6ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAED7D4FB1F35307ULL,
		0x2B002FB4C5D416F4ULL,
		0xB2FDD6096331AFB9ULL,
		0x16C17F75F31D446DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA2123A232B2790ULL,
		0x5F6179815A2413F4ULL,
		0x82D48BF2A705E8FBULL,
		0x6C4AC6E276D2B9DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB4B6B158EC82B64ULL,
		0xCB9EB6336BB002FFULL,
		0x30294A16BC2BC6BDULL,
		0x2A76B8937C4A8A8EULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B362B335A47032DULL,
		0x56A30FC59A007A3AULL,
		0x29178E14BAE48AA6ULL,
		0x59BA7A39FD6FACB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC45B7D730D73637BULL,
		0x95B3C4DC72A89487ULL,
		0xD6768FB4C90FDD04ULL,
		0x63403E79C7EA2894ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86DAADC04CD39F9FULL,
		0xC0EF4AE92757E5B2ULL,
		0x52A0FE5FF1D4ADA1ULL,
		0x767A3BC03585841CULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC34DED6DB6D3264FULL,
		0x3815979AED0BB27BULL,
		0xC28E3E40F2397CB6ULL,
		0x185A0288A3191805ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0D466752B1B94CDULL,
		0xEEF10E97394B7378ULL,
		0x49741FF79297B22AULL,
		0x6C635213A63315FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE27986F88BB7916FULL,
		0x49248903B3C03F02ULL,
		0x791A1E495FA1CA8BULL,
		0x2BF6B074FCE6020BULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D99ACD16519CD13ULL,
		0x36D66CBA6959F9ACULL,
		0xB683BB44747E00A6ULL,
		0x5FB81222EE517C03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849C35A0294392F5ULL,
		0x9FCB780D1363B532ULL,
		0x4C87F3BA9CB5EF31ULL,
		0x65E500FBBC9F76CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08FD77313BD63A0BULL,
		0x970AF4AD55F6447AULL,
		0x69FBC789D7C81174ULL,
		0x79D3112731B20539ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54BE7C6FEDA6742CULL,
		0x22DAC4D58AB3E39AULL,
		0x2F319C4F94418FD6ULL,
		0x5F152020A2F9BD67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07BF5505815B9A2DULL,
		0x979BF3F766DC9227ULL,
		0x828CC6511E3AA574ULL,
		0x35B787C4F3681363ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CFF276A6C4AD9FFULL,
		0x8B3ED0DE23D75173ULL,
		0xACA4D5FE7606EA61ULL,
		0x295D985BAF91AA03ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72C76CDF1E1C704AULL,
		0xC44FD1B6A2CC9B5AULL,
		0x65EBD984BFEF0044ULL,
		0x0CE45365D778C9ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEC9F079C304EEFULL,
		0xA111AF5A68ECF33BULL,
		0xD2505078EBD8581AULL,
		0x185690B85B8738FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57DACDD781EC2148ULL,
		0x233E225C39DFA81FULL,
		0x939B890BD416A82AULL,
		0x748DC2AD7BF190F0ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61E66EEA022A519FULL,
		0x5237512E8A2D7483ULL,
		0xBEEDBCD6BA1FB103ULL,
		0x4549E4758A5BA3AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9FC1A5BC2C50FF5ULL,
		0x345B4E26C8A9B596ULL,
		0x747465A4392C6DBAULL,
		0x07589C7A084709C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87EA548E3F6541AAULL,
		0x1DDC0307C183BEECULL,
		0x4A79573280F34349ULL,
		0x3DF147FB821499EBULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A157627584301FDULL,
		0x4A84F01A3DEEEDC4ULL,
		0xCE9D2B82E5A692F1ULL,
		0x6B2E4B875EC88E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5726F52DC8730D71ULL,
		0xCB56785B54B7948CULL,
		0x7DBE2167F5CCD8D4ULL,
		0x7A5B39A4CAF729F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12EE80F98FCFF479ULL,
		0x7F2E77BEE9375938ULL,
		0x50DF0A1AEFD9BA1CULL,
		0x70D311E293D1640CULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3052444E2DB3E28BULL,
		0xD8E656D4F2F6EAF4ULL,
		0x4ABB79D7A13098EBULL,
		0x62AF10C2B50F1A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBFEDBB498E3FD55ULL,
		0x2BA1F24C649BF32AULL,
		0xB3312A3D9FF9F469ULL,
		0x5B0CACB68D919775ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5453689994CFE536ULL,
		0xAD4464888E5AF7C9ULL,
		0x978A4F9A0136A482ULL,
		0x07A2640C277D82E6ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CB06FBCB97B3073ULL,
		0xA98E22E4533BCBF7ULL,
		0xD98004A5309D2196ULL,
		0x2187C07DD3E11503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CADF572ED81E637ULL,
		0x654FB9C35A5FC27EULL,
		0xE68629D73923D10DULL,
		0x44194D76E9704D6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40027A49CBF94A29ULL,
		0x443E6920F8DC0979ULL,
		0xF2F9DACDF7795089ULL,
		0x5D6E7306EA70C797ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B4D7AC51538E0B3ULL,
		0x3EB7ABDD3BE6A3ADULL,
		0x485DBA4B5811644EULL,
		0x1E62FC02F8A19B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD1466000428923CULL,
		0x451BA20F81AC3FF7ULL,
		0xAA2C8B7C5ADEA52DULL,
		0x435A7793032B459FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E3914C511104E64ULL,
		0xF99C09CDBA3A63B5ULL,
		0x9E312ECEFD32BF20ULL,
		0x5B08846FF5765583ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62D6428BDB7E2404ULL,
		0xA0B8050DDE443D81ULL,
		0x7136FF5B9D12F279ULL,
		0x556F5395F33BA8CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A731A7FE2EDCB39ULL,
		0x1F66D0C994918C1FULL,
		0x9A6F8E7CE888EE6DULL,
		0x4B272FEB317D7863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE863280BF89058CBULL,
		0x8151344449B2B161ULL,
		0xD6C770DEB48A040CULL,
		0x0A4823AAC1BE306BULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AAE9E26BFE9266DULL,
		0x954A4FC28711E36BULL,
		0xB906498779228DF2ULL,
		0x26BABAAF0ABFC834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3FC060B316825CAULL,
		0x6EBBDFA54984F7AEULL,
		0x2B8EC6895B3A843AULL,
		0x4D3851F4873E0E2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86B2981B8E810090ULL,
		0x268E701D3D8CEBBCULL,
		0x8D7782FE1DE809B8ULL,
		0x598268BA8381BA0AULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD893CF9B90A14316ULL,
		0x3556001D3A6CBD51ULL,
		0x5CA7285094E98D82ULL,
		0x47E5A5BA2739C8BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C1F59BFECB6F93ULL,
		0x042467B039666948ULL,
		0x031E88089B8E15A5ULL,
		0x16E168620B8841D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2D1D9FF91D5D383ULL,
		0x3131986D01065408ULL,
		0x5988A047F95B77DDULL,
		0x31043D581BB186E8ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA46AA543792FD632ULL,
		0x877275F6381476B8ULL,
		0x0DEC8B43D44072DFULL,
		0x6C109AC65F1BF225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043210D6542422E7ULL,
		0xD69D6E3F05C50499ULL,
		0x323B3193D7F31AE2ULL,
		0x0A74F376F46EA9F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA038946D250BB34BULL,
		0xB0D507B7324F721FULL,
		0xDBB159AFFC4D57FCULL,
		0x619BA74F6AAD482FULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF866C8F8F269BC39ULL,
		0x2770DF3966186499ULL,
		0xC4295DE2E01D3F4FULL,
		0x02D7AD9BDC4411A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E844A5559C38ABULL,
		0x31D6C47455CE4330ULL,
		0xE69BBA8B9479CD46ULL,
		0x3696A8724CEFCC54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA07E84539CCD837BULL,
		0xF59A1AC5104A2169ULL,
		0xDD8DA3574BA37208ULL,
		0x4C4105298F544553ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x655A749CFE338187ULL,
		0x38D4C04F79A3026CULL,
		0xFEF0F41D57D59AB0ULL,
		0x596B1AFF419FB7F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9053E66C0F52B99FULL,
		0xDD445B3A6580CEFAULL,
		0x2ECA73111B7F7BACULL,
		0x7DA33882E0B2C2B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5068E30EEE0C7D5ULL,
		0x5B90651514223371ULL,
		0xD026810C3C561F03ULL,
		0x5BC7E27C60ECF539ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F7745AE5866857EULL,
		0x81F55463840332C0ULL,
		0x3460CE5F07B99D8DULL,
		0x353065797A009882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA180F0BD92DDFCULL,
		0xD664F1D314415C7FULL,
		0xC0EFB2B9B121CA04ULL,
		0x22B16FA1BE93571BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFD5C4BD9AD3A782ULL,
		0xAB9062906FC1D640ULL,
		0x73711BA55697D388ULL,
		0x127EF5D7BB6D4166ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BFF2F42C3ADB702ULL,
		0xB8DC6CCFB4A00FE8ULL,
		0x5B727F57B0B01BD5ULL,
		0x12DEA5B1F3592268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD733807288A5CC9ULL,
		0x31351412023083F8ULL,
		0x56E35194443D80B3ULL,
		0x6E96D494DF7349EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E8BF73B9B235A26ULL,
		0x87A758BDB26F8BEFULL,
		0x048F2DC36C729B22ULL,
		0x2447D11D13E5D879ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x761A26E07F17E72AULL,
		0x905BDFF74D4B87BAULL,
		0xFE57641EC829A1D1ULL,
		0x7816D176F820502DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF623A03EEC292FULL,
		0x4642703CD5B94254ULL,
		0x3BFEF318BB427E80ULL,
		0x723995DAF0B83582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99240340402BBDFBULL,
		0x4A196FBA77924565ULL,
		0xC25871060CE72351ULL,
		0x05DD3B9C07681AABULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34FAC5B9111FF8BBULL,
		0xD60DC0CAC356F847ULL,
		0x92B7DE6A8EE839F0ULL,
		0x15DB7686EA8D4760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE39E2EE15A42AE2ULL,
		0x206C7F93F6A49CC7ULL,
		0xAF02ECEC0CE34D92ULL,
		0x0EEBF91ECC6CD721ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76C0E2CAFB7BCDD9ULL,
		0xB5A14136CCB25B7FULL,
		0xE3B4F17E8204EC5EULL,
		0x06EF7D681E20703EULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D227F7A08459E1AULL,
		0xE431BC7F967E9972ULL,
		0x1C6E765C00AED651ULL,
		0x14850241B6CC200BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863D7439A2BBC35DULL,
		0x702F2F7F6C95D504ULL,
		0x5A285324CB33C62FULL,
		0x5BFFEA67A1DEDCA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06E50B406589DAAAULL,
		0x74028D0029E8C46EULL,
		0xC2462337357B1022ULL,
		0x388517DA14ED4365ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5BF151B83DC520DULL,
		0x98DBF8CF5C144A20ULL,
		0x530E35F2425F860FULL,
		0x0E10E1A6B94A3BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619E1F6B3CC5D3A5ULL,
		0x7F0FC80BFA0CC971ULL,
		0x652F7734691B9943ULL,
		0x0F47F99AF7587D31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8420F5B047167E55ULL,
		0x19CC30C3620780AFULL,
		0xEDDEBEBDD943ECCCULL,
		0x7EC8E80BC1F1BE8AULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEC24421CE1A7B3EULL,
		0x9A6BEDBA546ADDA6ULL,
		0x8EA0B4CB72AC28E4ULL,
		0x28A9F30AF70E9CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE581F7C8E0E6080ULL,
		0x16E6B5166CCE06DDULL,
		0x048108A922F4C755ULL,
		0x76E7F855D8E9A971ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x206A24A5400C1AABULL,
		0x838538A3E79CD6C9ULL,
		0x8A1FAC224FB7618FULL,
		0x31C1FAB51E24F34AULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19BAAEA2747E9974ULL,
		0xD23F18CE45F16D6EULL,
		0xB23927418FF3A062ULL,
		0x10439A809CA89DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE613CF1F6231DD9EULL,
		0x3DB320A6753337E0ULL,
		0x67B552234145E145ULL,
		0x0CC3956C0A46234AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33A6DF83124CBBD6ULL,
		0x948BF827D0BE358DULL,
		0x4A83D51E4EADBF1DULL,
		0x0380051492627A7CULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6BE3FFEAF3B68D7ULL,
		0xEDC902840993259EULL,
		0xDE685E9A0B38A57EULL,
		0x20E7E004BF005BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x827027079CCA29DEULL,
		0x73FDA79860CDDE20ULL,
		0xCD4F9648C4256721ULL,
		0x1E30C8E922749959ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x744E18F712713EF9ULL,
		0x79CB5AEBA8C5477EULL,
		0x1118C85147133E5DULL,
		0x02B7171B9C8BC259ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F132590CD4DE63CULL,
		0xB162D30021950C00ULL,
		0xBA7476648A440AE8ULL,
		0x02BF7AFB2EB3D81DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79BBF3696293EA94ULL,
		0x67363590C86D9E68ULL,
		0x4E8CC39A9E98B53EULL,
		0x753863B639A700B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE55732276AB9FB95ULL,
		0x4A2C9D6F59276D97ULL,
		0x6BE7B2C9EBAB55AAULL,
		0x0D871744F50CD764ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9F534A6A5060C9FULL,
		0xD12765DC2B52BE9DULL,
		0x7DD8A95EBCD47812ULL,
		0x0F5BAF0FDF190B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA81322C517EC2286ULL,
		0x848C47D0CCDEEEA3ULL,
		0x9D5889F351ECF190ULL,
		0x7FECB0779AA4D519ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41E211E18D19EA06ULL,
		0x4C9B1E0B5E73CFFAULL,
		0xE0801F6B6AE78682ULL,
		0x0F6EFE9844743659ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34242ED87808004ULL,
		0x670B872C2FBB7FBFULL,
		0x612EB03FE094A4CBULL,
		0x5E381C79311933B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7BE2DC6AFD4B5AULL,
		0xEDC905D19067AA58ULL,
		0xF5FB822EAE790F94ULL,
		0x398EC90A7213A0B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67C660111C8334AAULL,
		0x7942815A9F53D567ULL,
		0x6B332E11321B9536ULL,
		0x24A9536EBF0592FFULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8601931EB485725ULL,
		0xB02D1A24EE7918A0ULL,
		0xF8A8422F3B29E047ULL,
		0x569AEFDE143CEC23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48F492D597F84CDULL,
		0xE2C4A63790E04013ULL,
		0xB33FD12A77B32E9EULL,
		0x6B4F97BEFBB63A18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03D0D00491C8D245ULL,
		0xCD6873ED5D98D88DULL,
		0x45687104C376B1A8ULL,
		0x6B4B581F1886B20BULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4575415C5FB3A51ULL,
		0x5CA1109D19D9D705ULL,
		0x8845F9E8E03C6912ULL,
		0x026231590B11ED30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35ABC38DF3681D6ULL,
		0x11E6FAE37EDB7DAEULL,
		0x1C7DF7CF6A7737FDULL,
		0x261044E14576B436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0FC97DCE6C4B868ULL,
		0x4ABA15B99AFE5956ULL,
		0x6BC8021975C53115ULL,
		0x5C51EC77C59B38FAULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4904DD55946356B8ULL,
		0x657DE12A2FFCCE3DULL,
		0x89D145EB33C2108EULL,
		0x51812AFB8E85A94DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1483577843FF0B9BULL,
		0xE7FE27ECEAE5419BULL,
		0xCA2A2377AD648ED3ULL,
		0x2D43B405D17CE056ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x348185DD50644B1DULL,
		0x7D7FB93D45178CA2ULL,
		0xBFA72273865D81BAULL,
		0x243D76F5BD08C8F6ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B58F95C83BD9554ULL,
		0xEC31447A4D98BF00ULL,
		0x9404116CC2A5459FULL,
		0x0E0C63411C1CFF93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69FF29F1B51BEB9ULL,
		0xBC929FBB2BB9C7F1ULL,
		0x584EED7DE7212F38ULL,
		0x6861167998BB3274ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44B906BD686BD688ULL,
		0x2F9EA4BF21DEF70EULL,
		0x3BB523EEDB841667ULL,
		0x25AB4CC78361CD1FULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CA5E9F831920C31ULL,
		0x663F1D55CF8196DAULL,
		0xE5741686AC0DE68CULL,
		0x7244F92F186D3C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B1DB22D3D696FCCULL,
		0xCDB9E56514984D0FULL,
		0xA91CE223E7450763ULL,
		0x507984D98D3A9A5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x518837CAF4289C65ULL,
		0x988537F0BAE949CBULL,
		0x3C573462C4C8DF28ULL,
		0x21CB74558B32A202ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2310AB4B479847A4ULL,
		0xD168E2F3CBB917C2ULL,
		0xD34D7787560BCB9FULL,
		0x5B45E70D67334E9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAA25C183BA31672ULL,
		0x8C1BF9A3A068D216ULL,
		0x3BE028B481FF6B87ULL,
		0x1B4F6BEE2084B522ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x286E4F330BF53132ULL,
		0x454CE9502B5045ABULL,
		0x976D4ED2D40C6018ULL,
		0x3FF67B1F46AE997BULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B20AE42FD83D8AULL,
		0x93A4F449DAF4A555ULL,
		0xD038C30962423581ULL,
		0x66FE13858A5C9DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B253F084572F95ULL,
		0xC7670D214E1C61A6ULL,
		0xD30E600F2A7A6C8BULL,
		0x784D528890E132C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBFFB6F3AB810DE2ULL,
		0xCC3DE7288CD843AEULL,
		0xFD2A62FA37C7C8F5ULL,
		0x6EB0C0FCF97B6ADEULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B6DB6C3C48D3BF2ULL,
		0x42A636B9D4D8B97EULL,
		0xC5A75488AB52252CULL,
		0x49E9BDEAAD95736BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26E1ECFCA36BBCCAULL,
		0xE733D37BB16390FAULL,
		0x5EFBAD32256819A4ULL,
		0x75790BD8398C4B40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x448BC9C721217F15ULL,
		0x5B72633E23752884ULL,
		0x66ABA75685EA0B87ULL,
		0x5470B2127409282BULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB303906C8B22A9DCULL,
		0x907AFF1FC02DCA9EULL,
		0xE6323B217A1D58D5ULL,
		0x44C100467C379D96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA29E31AF5437FA6ULL,
		0x13D0A7FF8D2BC468ULL,
		0x61A277CB60CB40E1ULL,
		0x47D2D63535F5C63BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8D9AD5195DF2A23ULL,
		0x7CAA572033020635ULL,
		0x848FC356195217F4ULL,
		0x7CEE2A114641D75BULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2861F8B21796E8E0ULL,
		0xCDCD86F37BA163D6ULL,
		0xEAA84B1EEDCAD413ULL,
		0x626111A36B835E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20D6FDE69237751AULL,
		0xD0F7E6734F2D1E75ULL,
		0x6AD5086C64AF6541ULL,
		0x7989857B6908BB7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x078AFACB855F73B3ULL,
		0xFCD5A0802C744561ULL,
		0x7FD342B2891B6ED1ULL,
		0x68D78C28027AA2EDULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B1BB9D4CBEEAFE2ULL,
		0x8609113BF946E7B7ULL,
		0xFB7F8DF04D181485ULL,
		0x1FDD8F15F992BBB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8090FEE11247100BULL,
		0x3B3CAC3E73CE82EBULL,
		0x8C5C8FF10DF6F5CCULL,
		0x75717438CAC95E64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA8ABAF3B9A79FC4ULL,
		0x4ACC64FD857864CBULL,
		0x6F22FDFF3F211EB9ULL,
		0x2A6C1ADD2EC95D4CULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6912895D5B23D2BFULL,
		0x4A42B025BDFA546DULL,
		0xB1F2996CFAB32FD9ULL,
		0x423481274070FCAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17DCBB10AB4D3824ULL,
		0xB4FF5979DE752458ULL,
		0x1153FD10B5A56073ULL,
		0x691771E0A729CBCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5135CE4CAFD69A88ULL,
		0x954356ABDF853015ULL,
		0xA09E9C5C450DCF65ULL,
		0x591D0F46994730E5ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9949C6964FA9F11ULL,
		0x4B0E9B12E6E23B06ULL,
		0xAAB61645AECFEF90ULL,
		0x1F61578818F77067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA96EE0FB83A8A9F5ULL,
		0x486EFFE181735ED0ULL,
		0x229783C3954C968EULL,
		0x07D2CE3CA0E84FC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4025BB6DE151F51CULL,
		0x029F9B31656EDC36ULL,
		0x881E928219835902ULL,
		0x178E894B780F20A2ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9944589C5244E579ULL,
		0x9C11C47C8846DCDAULL,
		0x5079530D1A055B87ULL,
		0x497C9B210D713B1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597889D53609AE75ULL,
		0x4D0F76FC6922E380ULL,
		0x1F0CA97DD3EC3C74ULL,
		0x60296AE24FDE045CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FCBCEC71C3B36F1ULL,
		0x4F024D801F23F95AULL,
		0x316CA98F46191F13ULL,
		0x6953303EBD9336C1ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7B720CAD3A93A53ULL,
		0x9AAC7AF6DF9E5B36ULL,
		0x2E9E637C89B08A44ULL,
		0x15E5DF406A8EEE3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D313D98B00198CULL,
		0xFB2114993164EC20ULL,
		0x83721F6B1C12EDBAULL,
		0x58846FF59502A39BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DE40CF148A920B4ULL,
		0x9F8B665DAE396F16ULL,
		0xAB2C44116D9D9C89ULL,
		0x3D616F4AD58C4AA2ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF647ED99B41AA41DULL,
		0xB5E3FC486A669BAFULL,
		0x3F1BAC2CB96792A6ULL,
		0x77C9F5972859E5C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5155CF211EB328D5ULL,
		0xBBFB90937587AAAFULL,
		0x66413D4C4D5B98CEULL,
		0x1FBB638D63D37131ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4F21E7895677B48ULL,
		0xF9E86BB4F4DEF100ULL,
		0xD8DA6EE06C0BF9D7ULL,
		0x580E9209C4867492ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50701A73CFED29FEULL,
		0xFDF7E21FACF38C48ULL,
		0xA7EAB5ED6C4B64F0ULL,
		0x60ABEAF665B0624AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675BE8ADBD2C57D9ULL,
		0x3C5D79CB57A713A3ULL,
		0xFEAF60A931876E25ULL,
		0x6AB96859F8DED2BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE91431C612C0D212ULL,
		0xC19A6854554C78A4ULL,
		0xA93B55443AC3F6CBULL,
		0x75F2829C6CD18F8EULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BC9672DF14AB391ULL,
		0x4EF897DC8055E2DDULL,
		0x7D35463B6E0D455BULL,
		0x68987CAF693F0C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85CF5177868989F4ULL,
		0xA2797EB6C0DBA17AULL,
		0xCFCFD6414F5D1AA2ULL,
		0x2CBC65A585EC9BB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5FA15B66AC1299DULL,
		0xAC7F1925BF7A4162ULL,
		0xAD656FFA1EB02AB8ULL,
		0x3BDC1709E35270EAULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B6055E6CEB9F86DULL,
		0xFD436E966C3CCB11ULL,
		0x8544AF6D7F7624F0ULL,
		0x4E8A6F101AFABE10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0429B491FED89BULL,
		0xFE5726412E973B49ULL,
		0x20F36B141AA92D78ULL,
		0x53FC7952A8008C71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA15C2C323CBB1FBFULL,
		0xFEEC48553DA58FC7ULL,
		0x6451445964CCF777ULL,
		0x7A8DF5BD72FA319FULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14093FCFA06AE049ULL,
		0x5B674F4AA8CA6A3FULL,
		0xFDBA0336D9F19DD1ULL,
		0x656F8DAD2883E8CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1B6AAA53A047ACULL,
		0x9C91A171A4762C89ULL,
		0xFE9593F206247682ULL,
		0x2C7E4F59859E8CB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9EDD5254CCA989DULL,
		0xBED5ADD904543DB5ULL,
		0xFF246F44D3CD274EULL,
		0x38F13E53A2E55C1AULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FD8AD5F35844A02ULL,
		0x50888B0605B08269ULL,
		0xF14BC8B6A4B3F68AULL,
		0x443318065ACC0A17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB5EA94BF2C547AULL,
		0x83E41323DB5C6040ULL,
		0xC99B42E4B7E9565DULL,
		0x73B6921CC4434F0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5222C2CA7657F575ULL,
		0xCCA477E22A542228ULL,
		0x27B085D1ECCAA02CULL,
		0x507C85E99688BB0DULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69CD0D8261BA6C3DULL,
		0xC73EE9894143029AULL,
		0xD3628799680B8211ULL,
		0x236C9E62B6F89949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBA3D2BB8CE10921ULL,
		0x34D117F71D71520DULL,
		0x1F5FD922EF1D1330ULL,
		0x1FF3D60990FDCDD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E293AC6D4D9631CULL,
		0x926DD19223D1B08CULL,
		0xB402AE7678EE6EE1ULL,
		0x0378C85925FACB79ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x795DB3E3F12DC7D4ULL,
		0xFAF845ABDCEDC5BCULL,
		0x3A33C0DDB0FE07B9ULL,
		0x3108CF91110033C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78ACBF97616CEFC5ULL,
		0xBADCCD72DEEB1140ULL,
		0x40806CF9BC8B554EULL,
		0x6D4C4D9C88B759B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00B0F44C8FC0D7FCULL,
		0x401B7838FE02B47CULL,
		0xF9B353E3F472B26BULL,
		0x43BC81F48848DA15ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C93C10799AB2D9FULL,
		0xAD6BEB4A20F39959ULL,
		0x5608D50665A4083FULL,
		0x28EC948AF54F7232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBC146C461A9E9AULL,
		0x7E390627AC4F1D34ULL,
		0xB8F54E1B040D743EULL,
		0x7E18678F5F76C2B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FD7AC9B53908EF2ULL,
		0x2F32E52274A47C25ULL,
		0x9D1386EB61969401ULL,
		0x2AD42CFB95D8AF7AULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00A245439EC1924CULL,
		0x662823D0C1777C98ULL,
		0x72136F532ACBE5BCULL,
		0x132F4DA63ECECA22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51486B72BA0D3488ULL,
		0x0779D8B853BD75C1ULL,
		0x8728CC25F71A18CDULL,
		0x33D7171A3CC148BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF59D9D0E4B45DB1ULL,
		0x5EAE4B186DBA06D6ULL,
		0xEAEAA32D33B1CCEFULL,
		0x5F58368C020D8164ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x038A377B1B601C47ULL,
		0xC12D278BC44FDF0CULL,
		0xE163891ECB242FA4ULL,
		0x198589623CCA2290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675FEE85B143C42FULL,
		0xE14FCABDE0E2189BULL,
		0xAD7E7BA43BBFCD97ULL,
		0x044EB3CC90794773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C2A48F56A1C5818ULL,
		0xDFDD5CCDE36DC670ULL,
		0x33E50D7A8F64620CULL,
		0x1536D595AC50DB1DULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6EC91F0EF835188ULL,
		0x0DBCE6EB7C032F18ULL,
		0x3BE89A4F61FE93E3ULL,
		0x41036CCFE6103F47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75E4B127D5B42203ULL,
		0x9046BA29481E99EBULL,
		0x8763F390E1F1C64DULL,
		0x780C4DAEBBD8FD30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3107E0C919CF2F72ULL,
		0x7D762CC233E4952DULL,
		0xB484A6BE800CCD95ULL,
		0x48F71F212A374216ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6CE62E542E80E25ULL,
		0x1EEA00BC31E28976ULL,
		0xB12E91012B15646BULL,
		0x4F5536D5538EFEC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518D2C1CB11835A3ULL,
		0x3FA04E3910A10ABAULL,
		0x46038C9EFED741FFULL,
		0x0E3AB0B553C166C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x554136C891CFD882ULL,
		0xDF49B28321417EBCULL,
		0x6B2B04622C3E226BULL,
		0x411A861FFFCD9801ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB21CD4A9AC982EEULL,
		0x7CDD56326263770CULL,
		0xD8DA2D71D2F4519FULL,
		0x1205BF1C92B5BCBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03BBE8C9C5FBA4C8ULL,
		0xE79472CBC02053DEULL,
		0x6F84BD08AFAC4819ULL,
		0x675F3B803CC42EB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB765E480D4CDDE13ULL,
		0x9548E366A243232EULL,
		0x6955706923480985ULL,
		0x2AA6839C55F18E02ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC375BA2A1238698ULL,
		0xEF422FE6633BE4AAULL,
		0x4D758C39FE9602A8ULL,
		0x11E7575CFD06E508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD1363B6B5A637BULL,
		0xF119FA49EB418B63ULL,
		0xBDE0F5603A71F2DBULL,
		0x3890B7421957ECDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0066256735C9230AULL,
		0xFE28359C77FA5947ULL,
		0x8F9496D9C4240FCCULL,
		0x5956A01AE3AEF82CULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA21D6CD6FEF5AA4ULL,
		0x50DB13837E0A044CULL,
		0x43508CC8616F2FDEULL,
		0x18E207890FB60B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x788B6C337F5BE838ULL,
		0x532836DB4CBD9A37ULL,
		0x417ABDC0076BDA37ULL,
		0x58404FD8523C7348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31966A99F0937259ULL,
		0xFDB2DCA8314C6A15ULL,
		0x01D5CF085A0355A6ULL,
		0x40A1B7B0BD79982FULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB46A86A0517FBCA0ULL,
		0xEDE9C3EB8E4A1A55ULL,
		0x469A6CFB443725B1ULL,
		0x66191B2EEFB2643EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5FEAD761D15310ULL,
		0x67C85315B502AF73ULL,
		0x83F8FF5BF725D3D3ULL,
		0x26BA591DEA9F638AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE70A9BC8EFAE6990ULL,
		0x862170D5D9476AE1ULL,
		0xC2A16D9F4D1151DEULL,
		0x3F5EC211051300B3ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFE5CAE485089A96ULL,
		0x290A2ECD384F93A5ULL,
		0xDF6894B3D7E4D356ULL,
		0x4F8416CF6C3B2359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC275597170AC978ULL,
		0x3D5D862B671A2BD9ULL,
		0xB7DDF1E16F5C8A1DULL,
		0x3B022D4E00810158ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3BE754D6DFDD11EULL,
		0xEBACA8A1D13567CBULL,
		0x278AA2D268884938ULL,
		0x1481E9816BBA2201ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E2D31EDAA24323CULL,
		0xE3FA0E7CBB7BCEE3ULL,
		0xB1E960CB85B6FD98ULL,
		0x488814B18E9E1BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B8842322473CEF8ULL,
		0x8747B81D9C421738ULL,
		0xCEE75C01A6EE485AULL,
		0x24E304C69D6B3AF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22A4EFBB85B06344ULL,
		0x5CB2565F1F39B7ABULL,
		0xE30204C9DEC8B53EULL,
		0x23A50FEAF132E0F3ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A301DD1A0D3E118ULL,
		0x95A0C5A943F3D2DAULL,
		0x99F7C10ED2308B4BULL,
		0x27DF5058A7A888CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE6AE4B4F96189FULL,
		0x8C2C3064EE18F5E9ULL,
		0x060CC670E304395FULL,
		0x57ACAF49E6BF0112ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF496F86513DC866ULL,
		0x0974954455DADCF0ULL,
		0x93EAFA9DEF2C51ECULL,
		0x5032A10EC0E987BDULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FE947D445C781D2ULL,
		0xA4ADB7E9DEBAAD6DULL,
		0x0C973756E9EB590BULL,
		0x144A763E6C7DDF4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47FA62C00FA92302ULL,
		0x7EEB96B7927EC31CULL,
		0x23526467D1F06262ULL,
		0x5F507C57C0E23409ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7EEE514361E5EBDULL,
		0x25C221324C3BEA50ULL,
		0xE944D2EF17FAF6A9ULL,
		0x34F9F9E6AB9BAB44ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71B19BB8B05B7EDCULL,
		0x9B8E205C63F4E2A4ULL,
		0xED206C57BB51B35CULL,
		0x6781177D9FA7319FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DDF0F4FFD056653ULL,
		0x47AB5E718504E1FCULL,
		0x988EB3B135593DFFULL,
		0x5AA92F60086EF2A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53D28C68B3561889ULL,
		0x53E2C1EADEF000A8ULL,
		0x5491B8A685F8755DULL,
		0x0CD7E81D97383EFDULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EA61252BF1CC0C6ULL,
		0xE28071062062B35DULL,
		0x2CC7DC0797C8418CULL,
		0x5C4748B962400AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF30A62E253488B3ULL,
		0x202B7877E9DE8B7FULL,
		0xF086CA975B135B95ULL,
		0x0F43AA56104BFE34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F756C2499E83813ULL,
		0xC254F88E368427DDULL,
		0x3C4111703CB4E5F7ULL,
		0x4D039E6351F40C77ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24B08767B94C8B75ULL,
		0xF7D0FFFFD34E9A2DULL,
		0xE98C94D9CC05EA19ULL,
		0x6799021488C49519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4D0D28CC654BCC3ULL,
		0x08EE5FFCEAA1E454ULL,
		0x9A8C41DA1C13F38CULL,
		0x71C95242958922B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FDFB4DAF2F7CE9FULL,
		0xEEE2A002E8ACB5D8ULL,
		0x4F0052FFAFF1F68DULL,
		0x75CFAFD1F33B7260ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A276C52C808A639ULL,
		0x3278354E9B0F5AB2ULL,
		0x89F524BD26D5216EULL,
		0x52850CB74441B2A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFFA1889CFF53B4FULL,
		0xA85E075114233181ULL,
		0x84941EBCE2C4BD18ULL,
		0x570ECFA55BCC9EA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA2D53C8F8136AD7ULL,
		0x8A1A2DFD86EC2930ULL,
		0x0561060044106455ULL,
		0x7B763D11E8751403ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4F9DA2A94525026ULL,
		0xD707C72E5A336AC9ULL,
		0xD88C8CC1D9D03F83ULL,
		0x7C063E19D4BA4D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A7E7C198F94CEA7ULL,
		0x520DCEAEEEA9C9A1ULL,
		0x1855A78C2CDE6B01ULL,
		0x53603B393845CFDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A7B5E1104BD817FULL,
		0x84F9F87F6B89A128ULL,
		0xC036E535ACF1D482ULL,
		0x28A602E09C747D68ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD766F47E6B493F6CULL,
		0x05CE0C53B00A4B9CULL,
		0x2DBB721667CC71E3ULL,
		0x3469970614DB4CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA62D9A22FB08EBULL,
		0x0FF2286F54E3CEB8ULL,
		0xFC377BDBCD355E8CULL,
		0x3BCF36A7222136FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CC0C6E4484E366EULL,
		0xF5DBE3E45B267CE4ULL,
		0x3183F63A9A971356ULL,
		0x789A605EF2BA15F9ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EF1CB760572544EULL,
		0x40CE434131EAA833ULL,
		0xE26A0E440FA51654ULL,
		0x4C3AB6954E2C9F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730607998D219593ULL,
		0x12C0F337D581F372ULL,
		0xC7B9CC950C6FCF0BULL,
		0x476F920ABE211F9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BEBC3DC7850BEBBULL,
		0x2E0D50095C68B4C1ULL,
		0x1AB041AF03354749ULL,
		0x04CB248A900B7F87ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7260A30C5CC25CF1ULL,
		0x2EE9D739362B4C79ULL,
		0x7E4B624B6DE32CFAULL,
		0x784FB6D56E2510E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE348EECFAC3C83D7ULL,
		0xE811253998CC4B9AULL,
		0x066288E3C9F382C8ULL,
		0x01EDC79DABFBE01BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F17B43CB085D91AULL,
		0x46D8B1FF9D5F00DEULL,
		0x77E8D967A3EFAA31ULL,
		0x7661EF37C22930C5ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x958A147A9129EE55ULL,
		0x52459F807DAB1051ULL,
		0x0F88128D100DD9A5ULL,
		0x11C66726097C8804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B9417288327614ULL,
		0x3E95F4FEE7EB0910ULL,
		0xB28D9BFA4AE5B7C7ULL,
		0x22303D28C3970C63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDD0D30808F7782EULL,
		0x13AFAA8195C00740ULL,
		0x5CFA7692C52821DEULL,
		0x6F9629FD45E57BA0ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x975E73E47F199D2FULL,
		0x215F07042A05C650ULL,
		0x898CFCB61A886212ULL,
		0x44FB87098158C15AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE923A1837B79A884ULL,
		0x78694334B88B7BBFULL,
		0x88C9E27456E60216ULL,
		0x77DAB78DC698C9CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE3AD261039FF498ULL,
		0xA8F5C3CF717A4A90ULL,
		0x00C31A41C3A25FFBULL,
		0x4D20CF7BBABFF78EULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ED918BFAB682786ULL,
		0xC28025D4C86D75A0ULL,
		0x0341E5A89A8E310EULL,
		0x59E023A11E7F4591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C72A3E96BEF02DULL,
		0x88CBDB77CF553B29ULL,
		0x3403A007E5567AC4ULL,
		0x0F77B7D70F983059ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9711EE8114A93759ULL,
		0x39B44A5CF9183A76ULL,
		0xCF3E45A0B537B64AULL,
		0x4A686BCA0EE71537ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5017383EF6CF1706ULL,
		0x8A768D946802E107ULL,
		0x53AC315B8A9510D5ULL,
		0x27FA69F0894004A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0FBBF65886E373EULL,
		0xCFE04CB53C1018D2ULL,
		0x2AC38EBBEE3CD107ULL,
		0x558E4340E6A1468DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F1B78D96E60DFB5ULL,
		0xBA9640DF2BF2C834ULL,
		0x28E8A29F9C583FCDULL,
		0x526C26AFA29EBE13ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA47B12EBC3978E88ULL,
		0x090311C8AB1D9DF9ULL,
		0xB3CA4C51CDDEA4B9ULL,
		0x075CA31CEE51E641ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x374947A806D71DB9ULL,
		0x90845CB47BC24AB1ULL,
		0x75B1CE9D393FE6D8ULL,
		0x72543E91DAD69C16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D31CB43BCC070BCULL,
		0x787EB5142F5B5348ULL,
		0x3E187DB4949EBDE0ULL,
		0x1508648B137B4A2BULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1848FE95D36D6421ULL,
		0xD92BF5C809840CDFULL,
		0xA67151FCCCAFC752ULL,
		0x21CD43BF9586821BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863CAED2B95BB161ULL,
		0xEC51B840DAD008A0ULL,
		0x9CEA961BFF10F640ULL,
		0x22D08598EF484F6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x920C4FC31A11B2ADULL,
		0xECDA3D872EB4043EULL,
		0x0986BBE0CD9ED111ULL,
		0x7EFCBE26A63E32AEULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF4EBBE24CF0870AULL,
		0xD908442E8C63E1C8ULL,
		0x9A9AA666AB7B66CBULL,
		0x238F2C8AFC53DCB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x612303D5648D08A2ULL,
		0xEE1E55D1C2B060DBULL,
		0x4CA8229732C5A92BULL,
		0x16DD7FC9EB044C81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E2BB80CE8637E68ULL,
		0xEAE9EE5CC9B380EDULL,
		0x4DF283CF78B5BD9FULL,
		0x0CB1ACC1114F9036ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEEAF3DCE065FFA0ULL,
		0x69933FC1B93FD264ULL,
		0x965AE437CA4F051CULL,
		0x4AA987199FBB0729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46C5488252655BC9ULL,
		0x370055CA3521ADD4ULL,
		0x3448076CDE0FEF1BULL,
		0x3FF392DF29D7A8A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7825AB5A8E00A3D7ULL,
		0x3292E9F7841E2490ULL,
		0x6212DCCAEC3F1601ULL,
		0x0AB5F43A75E35E84ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03BA956DAB17F268ULL,
		0xFC82A05BB4770927ULL,
		0x787BC9C9ECC87230ULL,
		0x614C6D706009D336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EDFBC7B217AA9F4ULL,
		0xE8C9B2E32FE3CF15ULL,
		0xD5397DEE04099C65ULL,
		0x1D768D80C54D38A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4DAD8F2899D4874ULL,
		0x13B8ED7884933A11ULL,
		0xA3424BDBE8BED5CBULL,
		0x43D5DFEF9ABC9A8CULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x846FD1A1A6197AE5ULL,
		0x3C6D127DA3907DBAULL,
		0xE0DD3B486609A2BDULL,
		0x23ECA4F585330C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD7F8FC35B7CC3BULL,
		0xC93B6250E803837EULL,
		0x416E737FD1AC5107ULL,
		0x583FB3EB2C3B7FA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2797D8A57061AE97ULL,
		0x7331B02CBB8CFA3CULL,
		0x9F6EC7C8945D51B5ULL,
		0x4BACF10A58F78CE7ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6185486207980332ULL,
		0x4B26A444D5DCBEC0ULL,
		0x41C63A1464339224ULL,
		0x0ADD103E5357FE01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63F3ECC1E110DEFULL,
		0xB738B4098DDF3150ULL,
		0x2EFB1C179A63E770ULL,
		0x592EDF757F878A74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B460995E986F530ULL,
		0x93EDF03B47FD8D6FULL,
		0x12CB1DFCC9CFAAB3ULL,
		0x31AE30C8D3D0738DULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x200E923AD0A97E0DULL,
		0xD01903B545618888ULL,
		0xC516F7816DFB645BULL,
		0x4EF693E2C0893425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C0F6973BFAF3FBULL,
		0x2BA1AAACFC620B6AULL,
		0x09985BE9BFBC0A94ULL,
		0x453B721932D3939CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4D9BA394AE8A12ULL,
		0xA477590848FF7D1DULL,
		0xBB7E9B97AE3F59C7ULL,
		0x09BB21C98DB5A089ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A0BE1947BACB125ULL,
		0x7952D02A3A4C993FULL,
		0xE45EF77FB4A3E190ULL,
		0x37112C9BF7B24D9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7FEB1D17835F75ULL,
		0x6A0F80EBE089EBE4ULL,
		0x563C9F3AEF25BEC8ULL,
		0x7EF6B3C58BFCC2BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8BF6776429519DULL,
		0x0F434F3E59C2AD5AULL,
		0x8E225844C57E22C8ULL,
		0x381A78D66BB58ADDULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A4A4B0A165E9306ULL,
		0x647DF341432F4A79ULL,
		0x4B1AF3AB65E5ECF3ULL,
		0x35CB794B804AEE48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13407B8679560369ULL,
		0x50165DB4154C8136ULL,
		0xB26FFB03E636C34DULL,
		0x1D75FAFF70D46C9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4709CF839D088F9DULL,
		0x1467958D2DE2C943ULL,
		0x98AAF8A77FAF29A6ULL,
		0x18557E4C0F7681A9ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC1FF4A462DAC8A2ULL,
		0x13DA527F1CA828C5ULL,
		0x94BC37AA174EEBAEULL,
		0x3D465246A12744A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F2D3ADE114984FULL,
		0x4BF7C8FCEF247BBDULL,
		0x11B3176C6A8C8DD4ULL,
		0x6AD9494651EC19CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x032D20F681C63040ULL,
		0xC7E289822D83AD08ULL,
		0x8309203DACC25DD9ULL,
		0x526D09004F3B2AD9ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BE1EFF59B6BC697ULL,
		0x8C8B27AB17C8C38DULL,
		0x3FC7313B39729B1DULL,
		0x6E3D2BE9551B1B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851C3B895D4A7F4EULL,
		0x5FF655B4617DC305ULL,
		0xD274DA8DBF99F9A5ULL,
		0x0A60EE972BABC9B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16C5B46C3E214749ULL,
		0x2C94D1F6B64B0088ULL,
		0x6D5256AD79D8A178ULL,
		0x63DC3D52296F51A3ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69C15BFFAB94E852ULL,
		0x5C9BF24632210E19ULL,
		0xA9CBFF3B45D0379DULL,
		0x3C7F7CB729A58D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8C3A2D6CEE3C773ULL,
		0x09C88B0288EAAA42ULL,
		0x7270B95790F7CDC8ULL,
		0x348AF3F6C338A978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70FDB928DCB120DFULL,
		0x52D36743A93663D6ULL,
		0x375B45E3B4D869D5ULL,
		0x07F488C0666CE3D0ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42280EFF9C2DE4B2ULL,
		0x7ED495FFE39B016FULL,
		0x61254DC392A0DBFBULL,
		0x406E1C24B6A6A789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C1807D6F70D6FBULL,
		0x7E277BC67312A921ULL,
		0xAB2B105AEA1A46B8ULL,
		0x27D1EE8F5FA0874BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C668E822CBD0DB7ULL,
		0x00AD1A397088584EULL,
		0xB5FA3D68A8869543ULL,
		0x189C2D955706203DULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E61ED4F0CF58BAEULL,
		0x5800F546B9106926ULL,
		0x43AFAD6C77E1B206ULL,
		0x0969B254D97366CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67AF76ED6E5BD730ULL,
		0xC2432E1470F5AF2BULL,
		0x4216A3B81EF5211DULL,
		0x11426B393B827A31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26B276619E99B46BULL,
		0x95BDC732481AB9FBULL,
		0x019909B458EC90E8ULL,
		0x7827471B9DF0EC9BULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62DE0536F4B761E0ULL,
		0xE8FBDCC3FD99E186ULL,
		0x5DE8EA05C1BC24C3ULL,
		0x14F35C8069370439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4096F6F65C71694ULL,
		0x97991DF20D02FDBFULL,
		0x0B160B1E9F6452FAULL,
		0x32C7EDBA58594175ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ED495C78EF04B39ULL,
		0x5162BED1F096E3C6ULL,
		0x52D2DEE72257D1C9ULL,
		0x622B6EC610DDC2C4ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA175DBC6683F70DULL,
		0xC079D3DEC1E9B3FFULL,
		0x016B69923381D8BBULL,
		0x49A242CB75B8C843ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5D016CF056C6C8ULL,
		0x07E6ADE945E1F5E6ULL,
		0x6B8D826211F7FE14ULL,
		0x6D09E6A5146BF2AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDBA5C4F762D3032ULL,
		0xB89325F57C07BE18ULL,
		0x95DDE7302189DAA7ULL,
		0x5C985C26614CD598ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5881FC6C70339430ULL,
		0x0F9A31F5459D8D92ULL,
		0x9257CB1FD98C7856ULL,
		0x74B805AF7D7E5034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x822F3CBAFBCFBCFDULL,
		0x172C4CF5952CD3E4ULL,
		0x5484ADDEF45B4848ULL,
		0x3914DC52A13700D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD652BFB17463D733ULL,
		0xF86DE4FFB070B9ADULL,
		0x3DD31D40E531300DULL,
		0x3BA3295CDC474F63ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A586A088FF859ABULL,
		0x35FE4B383CD0255DULL,
		0x3FDD8315C0587EF9ULL,
		0x4B3B22A718BF9E9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF275734D5E24350ULL,
		0x99C3286A50A035A3ULL,
		0x7688B91EA7A6CC63ULL,
		0x185D710474B765E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B3112D3BA16165BULL,
		0x9C3B22CDEC2FEFB9ULL,
		0xC954C9F718B1B295ULL,
		0x32DDB1A2A40838B4ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71441228DE763B48ULL,
		0x5AA4EA92BF8C95B5ULL,
		0xEEB587382B4E5343ULL,
		0x2429356EFEF77F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD1839378E3C0A7ULL,
		0x7F9246829DEA322AULL,
		0x20DE34843915AAB8ULL,
		0x2B295CC92F41FF25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73728E9565927A8EULL,
		0xDB12A41021A2638AULL,
		0xCDD752B3F238A88AULL,
		0x78FFD8A5CFB57FF7ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB48A6BF5938CF463ULL,
		0x174078C287CC56C5ULL,
		0x70FDCAEC7F14D974ULL,
		0x6B2DC4752E5C6DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7224B70D5245A353ULL,
		0x7ADD0E45DFA732EEULL,
		0x66280A23FCF15173ULL,
		0x015914D1B08C659EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4265B4E841475110ULL,
		0x9C636A7CA82523D7ULL,
		0x0AD5C0C882238800ULL,
		0x69D4AFA37DD0082AULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB871C7EEECC8E3F9ULL,
		0xF3287926AD79D9B3ULL,
		0x514CAD4ED589E455ULL,
		0x659FE43582538EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39665F9B9D48A9AAULL,
		0xC2D4790655E17526ULL,
		0x320D5AD285351D2CULL,
		0x2D423B8BC3341924ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F0B68534F803A4FULL,
		0x305400205798648DULL,
		0x1F3F527C5054C729ULL,
		0x385DA8A9BF1F75D2ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD41DE70C03E4B562ULL,
		0x399DC38968D1816BULL,
		0xA473E5D96FC1BF08ULL,
		0x2F503BDE6DF9B91DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9750ED32CCE4A4D8ULL,
		0xCDF04F2D9D8E1A8FULL,
		0x22451E811B90E034ULL,
		0x623C456779AEA09AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CCCF9D937001077ULL,
		0x6BAD745BCB4366DCULL,
		0x822EC7585430DED3ULL,
		0x4D13F676F44B1883ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8993B4342A7ECEC0ULL,
		0x196A3EE0B19A9399ULL,
		0x76EDEEE2C4CE455FULL,
		0x2CAE947CADF69A34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8285077D3AEE7F19ULL,
		0xA6A80CCC504AD995ULL,
		0x7C0047D98ED1B769ULL,
		0x631EC6574EF1FF03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x070EACB6EF904F94ULL,
		0x72C23214614FBA04ULL,
		0xFAEDA70935FC8DF5ULL,
		0x498FCE255F049B30ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2C495445DA5911EULL,
		0x100172676078FE7DULL,
		0xA0B2DE2F37D56C4EULL,
		0x7BF64A72AFF26AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88118BB3E3C3EB54ULL,
		0x7D4402D12FE93E42ULL,
		0x8673A7F9DCB8D42AULL,
		0x21D4C2934FEEE7CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AB3099079E1A5CAULL,
		0x92BD6F96308FC03BULL,
		0x1A3F36355B1C9823ULL,
		0x5A2187DF60038330ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C7B23751721BD6FULL,
		0xFBA705CEA4193AD6ULL,
		0x96B20F48B2F66AC9ULL,
		0x712BF4FF209FF9B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE747F7567684BFCULL,
		0xE02AE06578ED8B63ULL,
		0x35129249E94E1FA4ULL,
		0x662DFA10E67A1E06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E06A3FFAFB97173ULL,
		0x1B7C25692B2BAF72ULL,
		0x619F7CFEC9A84B25ULL,
		0x0AFDFAEE3A25DBB3ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3A3635FAE46BB72ULL,
		0x39ED0134006433F7ULL,
		0xC933E6B592C9168DULL,
		0x168A27C0C7B07153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61DD791E9D745342ULL,
		0x5DD1186A4F2E10ECULL,
		0xBC0F89237494BB5AULL,
		0x6DB89B7D931AC8B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41C5EA4110D2681DULL,
		0xDC1BE8C9B136230BULL,
		0x0D245D921E345B32ULL,
		0x28D18C433495A89CULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D7B26CD8A22E4E0ULL,
		0x5D00AF59ABA0FAA3ULL,
		0xA38D87D1FF62BAABULL,
		0x62E3DAAB6DA4D664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7031FB32F84CE398ULL,
		0xC463B962B9D2340FULL,
		0x112610F9E4C54B3CULL,
		0x7934BD80E309B0E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D492B9A91D60135ULL,
		0x989CF5F6F1CEC694ULL,
		0x926776D81A9D6F6EULL,
		0x69AF1D2A8A9B257CULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2BD59A796944B1BULL,
		0x7AD36CD175FAB756ULL,
		0x61A28E5DC5688CDFULL,
		0x5B7A8096F51EDC9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFABB6B72EF05316ULL,
		0xF8542076F266DCA0ULL,
		0x372B4A4F6ABEF63BULL,
		0x79672621DEAE5925ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1311A2F067A3F7F2ULL,
		0x827F4C5A8393DAB6ULL,
		0x2A77440E5AA996A3ULL,
		0x62135A7516708377ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB6DE1BCDC34F3D5ULL,
		0x191C274F6BCA145EULL,
		0xFF4C27EECD4E550FULL,
		0x58F111BB2E490C16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9260E892CA8CD013ULL,
		0xDED13749A8770C82ULL,
		0xFEA2167A01D4C4ADULL,
		0x0083E6976C638814ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x190CF92A11A823C2ULL,
		0x3A4AF005C35307DCULL,
		0x00AA1174CB799061ULL,
		0x586D2B23C1E58402ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8150F54F7F6C70F7ULL,
		0xB28F42A3F652413EULL,
		0xF55BF70033D5CCACULL,
		0x5851766F13E3BBFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6009572B6A4B1534ULL,
		0x59A33315EB4E2D53ULL,
		0x0AAE4314BDA68FD7ULL,
		0x0F9D7ADE040D1CE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21479E2415215BC3ULL,
		0x58EC0F8E0B0413EBULL,
		0xEAADB3EB762F3CD5ULL,
		0x48B3FB910FD69F11ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EF1636EE55BCA14ULL,
		0xF5B4EC47465B2CC6ULL,
		0x7D4386D326958618ULL,
		0x54A3A875DB15505AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD54892B889D36BULL,
		0x58E27CE4CA9DCE70ULL,
		0xB14E4A991E965A51ULL,
		0x540067125DBE11E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x411C1ADC2CD1F6A9ULL,
		0x9CD26F627BBD5E56ULL,
		0xCBF53C3A07FF2BC7ULL,
		0x00A341637D573E78ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE4890083671494CULL,
		0x3008465F0F719F5BULL,
		0x77C036B1268C48C8ULL,
		0x777B3FCBF5E5A330ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDBDFCDFC58D0ADULL,
		0xADD56EB4272C68ABULL,
		0xF8694961B046064EULL,
		0x3F54511F5AAB819AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E6CB03A3A18789FULL,
		0x8232D7AAE84536B0ULL,
		0x7F56ED4F76464279ULL,
		0x3826EEAC9B3A2195ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FFA055F5F2DA2EEULL,
		0x2B89C1D46B79CDBDULL,
		0xF7061DC807842177ULL,
		0x389AB81B0575EB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424BB7BA042F318EULL,
		0x3E62333CE987C94FULL,
		0x743060DEAE6B1500ULL,
		0x2EC6FAEC8F3E3A48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DAE4DA55AFE7160ULL,
		0xED278E9781F2046EULL,
		0x82D5BCE959190C76ULL,
		0x09D3BD2E7637B123ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}