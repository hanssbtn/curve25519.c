#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Inplace Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD3F78C0640D00CE3ULL,
		0x62C282BF4ECFA891ULL,
		0xAC6C2F022CE04A38ULL,
		0xF9BEF9BAB1F35A19ULL,
		0x1DFFCD2A5BDB5EB3ULL,
		0xC7CD5B4F1A363598ULL,
		0x99C4AA758564BDFFULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x80C81A019C600000ULL,
		0x57E9D9F5123A7EF1ULL,
		0xE0459C09470C5850ULL,
		0x37563E6B43358D85ULL,
		0xA54B7B6BD67F37DFULL,
		0x69E346C6B303BFF9ULL,
		0x4EB0AC97BFF8F9ABULL,
		0x0000000000133895ULL
	}};
	int shift = 21;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x58B872457A9F47D5ULL,
		0x61D309DA924550F5ULL,
		0xBF4ABC2A7944859DULL,
		0x0573B844B27D4F18ULL,
		0xC9C2096C48AAAC42ULL,
		0x889B0C09C79E4B05ULL,
		0x10F905AEC3A211D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57A9F47D50000000ULL,
		0xA924550F558B8724ULL,
		0xA7944859D61D309DULL,
		0x4B27D4F18BF4ABC2ULL,
		0xC48AAAC420573B84ULL,
		0x9C79E4B05C9C2096ULL,
		0xEC3A211D7889B0C0ULL,
		0x00000000010F905AULL
	}};
	shift = 28;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD8A46C60EBBFC904ULL,
		0x8F0367D863901762ULL,
		0x85A38080E4611887ULL,
		0x7839494B5B40C97BULL,
		0x85A5C9C63DA469F4ULL,
		0x57DC7CDB903D3A64ULL,
		0x77704593070611E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE4820000000000ULL,
		0xC80BB16C52363075ULL,
		0x308C43C781B3EC31ULL,
		0xA064BDC2D1C04072ULL,
		0xD234FA3C1CA4A5ADULL,
		0x1E9D3242D2E4E31EULL,
		0x8308F02BEE3E6DC8ULL,
		0x0000003BB822C983ULL
	}};
	shift = 39;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x71F540285DC79F0FULL,
		0x2ADD64992EF95160ULL,
		0xC20A3633CCC00C2FULL,
		0x4C9F4BDE8255A253ULL,
		0x313981FDDC087E2CULL,
		0x9C2B2F0FF599F18CULL,
		0x0A5904D569BEFD14ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79F0F0000000000ULL,
		0xF9516071F540285DULL,
		0xC00C2F2ADD64992EULL,
		0x55A253C20A3633CCULL,
		0x087E2C4C9F4BDE82ULL,
		0x99F18C313981FDDCULL,
		0xBEFD149C2B2F0FF5ULL,
		0x0000000A5904D569ULL
	}};
	shift = 40;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6278CEDB285EC46DULL,
		0xC3F07AF2B74843B8ULL,
		0x1E06A018A7213504ULL,
		0x1334EC65D51397CBULL,
		0xA960988BCD01ADD1ULL,
		0x0115F0E02BAE189FULL,
		0x90671752C017A35CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB285EC46D00000ULL,
		0xAF2B74843B86278CULL,
		0x018A7213504C3F07ULL,
		0xC65D51397CB1E06AULL,
		0x88BCD01ADD11334EULL,
		0x0E02BAE189FA9609ULL,
		0x752C017A35C0115FULL,
		0x0000000000090671ULL
	}};
	shift = 20;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x913B08BC579F4A59ULL,
		0xE17A743FF546F040ULL,
		0xB109FCB708398C66ULL,
		0x1ECD816D39F28EA6ULL,
		0xFC9C1278C5BA6058ULL,
		0xDECE0A3710219A73ULL,
		0xD0361CEA919120D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E7D29640000000ULL,
		0xFD51BC10244EC22FULL,
		0xC20E6319B85E9D0FULL,
		0x4E7CA3A9AC427F2DULL,
		0x316E981607B3605BULL,
		0xC408669CFF27049EULL,
		0xA464483537B3828DULL,
		0x00000000340D873AULL
	}};
	shift = 30;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x43B15D560CAC3CD0ULL,
		0x6809329286B06BECULL,
		0x66DC0D760C033D3BULL,
		0x70D3129809C5BDB8ULL,
		0x23C529C55DF56F7FULL,
		0x1482AFF14E68F830ULL,
		0xDFF2A959D69254E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEAB06561E680000ULL,
		0x9949435835F621D8ULL,
		0x06BB06019E9DB404ULL,
		0x894C04E2DEDC336EULL,
		0x94E2AEFAB7BFB869ULL,
		0x57F8A7347C1811E2ULL,
		0x54ACEB492A740A41ULL,
		0x0000000000006FF9ULL
	}};
	shift = 15;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCEE46E44A26FB6EAULL,
		0x6318BE05C5635F14ULL,
		0x2DA579720C0D4C5EULL,
		0x527283FBCEDD90D1ULL,
		0xADEBD17242FD1D1BULL,
		0x8B1BA8B410DE2E5CULL,
		0xCA377CD1453E0A41ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B91B91289BEDBA8ULL,
		0x8C62F817158D7C53ULL,
		0xB695E5C830353179ULL,
		0x49CA0FEF3B764344ULL,
		0xB7AF45C90BF4746DULL,
		0x2C6EA2D04378B972ULL,
		0x28DDF34514F82906ULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x07500FD3E454DB22ULL,
		0xC8BCB2F722E302B4ULL,
		0xC62A56F9BE0AAEEDULL,
		0xD60D74D2FC374CC5ULL,
		0x8184C65235525EBCULL,
		0x49A455F75E4B5E23ULL,
		0x3DF58105FABE5018ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07500FD3E454DB22ULL,
		0xC8BCB2F722E302B4ULL,
		0xC62A56F9BE0AAEEDULL,
		0xD60D74D2FC374CC5ULL,
		0x8184C65235525EBCULL,
		0x49A455F75E4B5E23ULL,
		0x3DF58105FABE5018ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x355A44C552D81E77ULL,
		0x0B5F108DF301C509ULL,
		0x5AFA58A8034AD988ULL,
		0x71BA426DB7F79CF3ULL,
		0x52DC4E21381D5AFCULL,
		0x849D5F238F7B5B5AULL,
		0xEF9BC7AB3183895CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x079DC00000000000ULL,
		0x71424D56913154B6ULL,
		0xB66202D7C4237CC0ULL,
		0xE73CD6BE962A00D2ULL,
		0x56BF1C6E909B6DFDULL,
		0xD6D694B713884E07ULL,
		0xE257212757C8E3DEULL,
		0x00003BE6F1EACC60ULL
	}};
	shift = 46;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9DBEE5CFBAFF0F8ULL,
		0x9062579D83E7BE20ULL,
		0x21AA0042FA297051ULL,
		0xAD010B102FB9733DULL,
		0x2D136C9C0C3D48AFULL,
		0x0FB5501059305802ULL,
		0xACD7F1B13C503A18ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DBEE5CFBAFF0F80ULL,
		0x062579D83E7BE20EULL,
		0x1AA0042FA2970519ULL,
		0xD010B102FB9733D2ULL,
		0xD136C9C0C3D48AFAULL,
		0xFB55010593058022ULL,
		0xCD7F1B13C503A180ULL,
		0x000000000000000AULL
	}};
	shift = 4;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7649589597E3C9A0ULL,
		0x647F2A1ACA2AEFDBULL,
		0xA6F6EB677B958D5EULL,
		0x429A99820696AF30ULL,
		0x7431D926E864208BULL,
		0xB93D5ED870864C99ULL,
		0xAA34F70DA23BBAB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7934000000000000ULL,
		0x5DFB6EC92B12B2FCULL,
		0xB1ABCC8FE5435945ULL,
		0xD5E614DEDD6CEF72ULL,
		0x84116853533040D2ULL,
		0xC9932E863B24DD0CULL,
		0x77567727ABDB0E10ULL,
		0x000015469EE1B447ULL
	}};
	shift = 45;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x998B77E243B47FCDULL,
		0x7124ACE8955FB086ULL,
		0x890BDE6F0E22884FULL,
		0x56AE245803D7F327ULL,
		0xB571AD1FFFF628EFULL,
		0xA1FB31BD846AF96FULL,
		0xCDDB90ADADB785E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47FCD0000000000ULL,
		0x5FB086998B77E243ULL,
		0x22884F7124ACE895ULL,
		0xD7F327890BDE6F0EULL,
		0xF628EF56AE245803ULL,
		0x6AF96FB571AD1FFFULL,
		0xB785E9A1FB31BD84ULL,
		0x000000CDDB90ADADULL
	}};
	shift = 40;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBEA621A50954DB88ULL,
		0xD1A37B5555D1DA21ULL,
		0xA474B9FCFC369BB6ULL,
		0xCDA12950DD619B5DULL,
		0x7940393CB46DA23AULL,
		0xCC26B472259C7CBCULL,
		0xDC1B70C99AD1A46BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10D284AA6DC40000ULL,
		0xBDAAAAE8ED10DF53ULL,
		0x5CFE7E1B4DDB68D1ULL,
		0x94A86EB0CDAED23AULL,
		0x1C9E5A36D11D66D0ULL,
		0x5A3912CE3E5E3CA0ULL,
		0xB864CD68D235E613ULL,
		0x0000000000006E0DULL
	}};
	shift = 15;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B3626F201226668ULL,
		0x4DFFDEAF06E3D4BEULL,
		0x8815B622C4933678ULL,
		0xDA75C87B1B9B3977ULL,
		0x9F2C7FB7574670ECULL,
		0x14BCA5C50C97FFEAULL,
		0xB6DD957DA20A5984ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2266680000000000ULL,
		0xE3D4BE3B3626F201ULL,
		0x9336784DFFDEAF06ULL,
		0x9B39778815B622C4ULL,
		0x4670ECDA75C87B1BULL,
		0x97FFEA9F2C7FB757ULL,
		0x0A598414BCA5C50CULL,
		0x000000B6DD957DA2ULL
	}};
	shift = 40;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA6B856AAABF702B5ULL,
		0x098C34279D03F608ULL,
		0x20201A382429733CULL,
		0x6258C8FFB53D127AULL,
		0xBD96AC8C81D051A3ULL,
		0x8894F12FC0537E57ULL,
		0x0E2A8936B4FADD4BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD400000000000000ULL,
		0x229AE15AAAAFDC0AULL,
		0xF02630D09E740FD8ULL,
		0xE8808068E090A5CCULL,
		0x8D896323FED4F449ULL,
		0x5EF65AB232074146ULL,
		0x2E2253C4BF014DF9ULL,
		0x0038AA24DAD3EB75ULL
	}};
	shift = 58;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE93EB4939C7E8EB8ULL,
		0xFFF96E5DA92A373FULL,
		0x7AFEC13D8B9F5D4DULL,
		0xDF7DBA6FFB0A1268ULL,
		0x9B916BB4A33E2DE6ULL,
		0x722F266648762419ULL,
		0x271C9B02D062898AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE0000000000000ULL,
		0xDCFFA4FAD24E71FAULL,
		0x7537FFE5B976A4A8ULL,
		0x49A1EBFB04F62E7DULL,
		0xB79B7DF6E9BFEC28ULL,
		0x90666E45AED28CF8ULL,
		0x2629C8BC999921D8ULL,
		0x00009C726C0B418AULL
	}};
	shift = 50;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF23F54346CA5926FULL,
		0x70FDE1C3B5786923ULL,
		0xBDF3780D1D6D7E11ULL,
		0x8BD03C3ADC348D42ULL,
		0x286BEF4C8AA43C0AULL,
		0x2555035F1A2CD27CULL,
		0xA04E427DADE36C47ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x868D94B24DE00000ULL,
		0x3876AF0D247E47EAULL,
		0x01A3ADAFC22E1FBCULL,
		0x875B8691A857BE6FULL,
		0xE991548781517A07ULL,
		0x6BE3459A4F850D7DULL,
		0x4FB5BC6D88E4AAA0ULL,
		0x00000000001409C8ULL
	}};
	shift = 21;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAF02D3DD3D44EF46ULL,
		0xBB0300AAAC04AFC2ULL,
		0x3F1977892DE87056ULL,
		0x288B5271853A8B3FULL,
		0x06B771065222A5F4ULL,
		0xB84980E7B0A9F767ULL,
		0x248370441E28A4E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77A3000000000000ULL,
		0x57E1578169EE9EA2ULL,
		0x382B5D8180555602ULL,
		0x459F9F8CBBC496F4ULL,
		0x52FA1445A938C29DULL,
		0xFBB3835BB8832911ULL,
		0x52705C24C073D854ULL,
		0x00001241B8220F14ULL
	}};
	shift = 47;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x20A20D6016E599DAULL,
		0x7A07432CF00D9A69ULL,
		0x49AF15EE5FB395D7ULL,
		0x5D12BDD04748560BULL,
		0xC223EF5FA04FB5FBULL,
		0x744697D7C74B63ABULL,
		0x09286619F1D25CA5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB33B40000000000ULL,
		0x1B34D241441AC02DULL,
		0x672BAEF40E8659E0ULL,
		0x90AC16935E2BDCBFULL,
		0x9F6BF6BA257BA08EULL,
		0x96C7578447DEBF40ULL,
		0xA4B94AE88D2FAF8EULL,
		0x0000001250CC33E3ULL
	}};
	shift = 41;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E906828605566BCULL,
		0x1054157ADEBD28FFULL,
		0xF15693A5082F2BF0ULL,
		0x6FE577A899B7268DULL,
		0x8EBFA45364D6A12BULL,
		0x85261DD7B8E08374ULL,
		0xE135D92654CEE0E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4302AB35E0000000ULL,
		0xD6F5E947FCF48341ULL,
		0x2841795F8082A0ABULL,
		0x44CDB9346F8AB49DULL,
		0x9B26B5095B7F2BBDULL,
		0xBDC7041BA475FD22ULL,
		0x32A677073C2930EEULL,
		0x000000000709AEC9ULL
	}};
	shift = 27;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD999DF137F9010B6ULL,
		0x76F27FC7A4637BC9ULL,
		0x15D56CE466BDBD42ULL,
		0x665FA025DCA4D950ULL,
		0x939D2286BD2A19F9ULL,
		0xB6DC87B883C47EAAULL,
		0xA9EE331849B580ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x677C4DFE4042D800ULL,
		0xC9FF1E918DEF2766ULL,
		0x55B3919AF6F509DBULL,
		0x7E80977293654057ULL,
		0x748A1AF4A867E599ULL,
		0x721EE20F11FAAA4EULL,
		0xB8CC6126D602B6DBULL,
		0x00000000000002A7ULL
	}};
	shift = 10;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x063CA3C4669C3110ULL,
		0x36BF7B474B630F36ULL,
		0x4781A53E6A99BB11ULL,
		0xF11C3B959C0C3F15ULL,
		0x436AE5D21A7A74F3ULL,
		0x306DF8505CACFDCDULL,
		0x8FDF404E4ABC6B02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4400000000000000ULL,
		0xCD818F28F119A70CULL,
		0xC44DAFDED1D2D8C3ULL,
		0xC551E0694F9AA66EULL,
		0x3CFC470EE567030FULL,
		0x7350DAB974869E9DULL,
		0xC08C1B7E14172B3FULL,
		0x0023F7D01392AF1AULL
	}};
	shift = 54;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD94E753EEC9FF54DULL,
		0x099473CCCBBB95E0ULL,
		0x957EAD0215ED8C38ULL,
		0x5064F0FF857189E4ULL,
		0x4E004928614A88B4ULL,
		0x7D555FF52D85BCF7ULL,
		0x2D7C71D4EF30E266ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC9FF54D00000000ULL,
		0xCBBB95E0D94E753EULL,
		0x15ED8C38099473CCULL,
		0x857189E4957EAD02ULL,
		0x614A88B45064F0FFULL,
		0x2D85BCF74E004928ULL,
		0xEF30E2667D555FF5ULL,
		0x000000002D7C71D4ULL
	}};
	shift = 32;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x73D59FB2E89126D8ULL,
		0x63B50BE344FB96F1ULL,
		0xE0E4A44E1901DCBEULL,
		0x8F3C8A5C1DB1F41EULL,
		0x983295F085744F9AULL,
		0x0260D5B9DCC28C90ULL,
		0x96B09E8094DE3D1DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89126D8000000000ULL,
		0x4FB96F173D59FB2EULL,
		0x901DCBE63B50BE34ULL,
		0xDB1F41EE0E4A44E1ULL,
		0x5744F9A8F3C8A5C1ULL,
		0xCC28C90983295F08ULL,
		0x4DE3D1D0260D5B9DULL,
		0x000000096B09E809ULL
	}};
	shift = 36;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0C1D9851EA51E189ULL,
		0xF722F0DCC08E61C7ULL,
		0x293A5B7CCFBF0992ULL,
		0x648C9347EEBC9BC9ULL,
		0x7B8F3D15C9384C9DULL,
		0x84EF272DA31823A9ULL,
		0x46EEDAF38ECD5C51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C3120000000000ULL,
		0x1CC38E183B30A3D4ULL,
		0x7E1325EE45E1B981ULL,
		0x7937925274B6F99FULL,
		0x70993AC919268FDDULL,
		0x304752F71E7A2B92ULL,
		0x9AB8A309DE4E5B46ULL,
		0x0000008DDDB5E71DULL
	}};
	shift = 41;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC2E3CD781FE0813ULL,
		0xE37535FFAA963034ULL,
		0x750E0D426DA684E1ULL,
		0xE9611B02C82E643BULL,
		0x514B62F122FDA68DULL,
		0x27B01EB9B7DFC50AULL,
		0x9C023D2836A9EF04ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC102600000000000ULL,
		0xC6069F85C79AF03FULL,
		0xD09C3C6EA6BFF552ULL,
		0xCC876EA1C1A84DB4ULL,
		0xB4D1BD2C23605905ULL,
		0xF8A14A296C5E245FULL,
		0x3DE084F603D736FBULL,
		0x0000138047A506D5ULL
	}};
	shift = 45;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF71CAFBB66560DEFULL,
		0xA560F5B27A1B8673ULL,
		0x64E28FE524E9B3E5ULL,
		0x36279A301FE62853ULL,
		0xD9B0F3CB261F5186ULL,
		0xF835C44FDAF68C55ULL,
		0x4469EB61D43AE32EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xFB8E57DDB32B06F7ULL,
		0xD2B07AD93D0DC339ULL,
		0xB27147F29274D9F2ULL,
		0x1B13CD180FF31429ULL,
		0xECD879E5930FA8C3ULL,
		0x7C1AE227ED7B462AULL,
		0x2234F5B0EA1D7197ULL
	}};
	shift = 63;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF73F992FCCBD21A3ULL,
		0xD967A2A786712454ULL,
		0x4B7FD6AE0D76838BULL,
		0xD6F5744F6EE4E5FAULL,
		0x62FEB8145925C93AULL,
		0x3797C6415257BFA1ULL,
		0x22FC55E312C3521DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FCCBD21A3000000ULL,
		0xA786712454F73F99ULL,
		0xAE0D76838BD967A2ULL,
		0x4F6EE4E5FA4B7FD6ULL,
		0x145925C93AD6F574ULL,
		0x415257BFA162FEB8ULL,
		0xE312C3521D3797C6ULL,
		0x000000000022FC55ULL
	}};
	shift = 24;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x82ED0AE83A943FB3ULL,
		0x64BCEE3F6CA7E9FEULL,
		0xCDDB561EE70BA9CDULL,
		0x9DBB8E9E0CB58DBEULL,
		0x5A73AF610BCC0B6DULL,
		0xEB1AFED71ADAD06FULL,
		0xA03D4A4C0DB8EBE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5741D4A1FD980000ULL,
		0x71FB653F4FF41768ULL,
		0xB0F7385D4E6B25E7ULL,
		0x74F065AC6DF66EDAULL,
		0x7B085E605B6CEDDCULL,
		0xF6B8D6D6837AD39DULL,
		0x52606DC75F0758D7ULL,
		0x00000000000501EAULL
	}};
	shift = 19;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB3605D05675ECB3EULL,
		0x75FD27ECBEA9CD63ULL,
		0x939B00B8984059C8ULL,
		0x1B7402C76E44F8F4ULL,
		0x7471DFAB94587225ULL,
		0x980A043CA8EBC7B1ULL,
		0xAD2BFECF0FF59FB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B2CF8000000000ULL,
		0xAA7358ECD8174159ULL,
		0x1016721D7F49FB2FULL,
		0x913E3D24E6C02E26ULL,
		0x161C8946DD00B1DBULL,
		0x3AF1EC5D1C77EAE5ULL,
		0xFD67ECA602810F2AULL,
		0x0000002B4AFFB3C3ULL
	}};
	shift = 38;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDC422D524E55D5CDULL,
		0xB8CD0CC03ADF9599ULL,
		0xD300C2FBE2A44721ULL,
		0x1CAE9A33138BB7A8ULL,
		0x7A60F439038738EBULL,
		0xD9C21EA9159C626DULL,
		0x95A113CBF3A9A115ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9272AEAE68000000ULL,
		0x01D6FCACCEE2116AULL,
		0xDF1522390DC66866ULL,
		0x989C5DBD46980617ULL,
		0xC81C39C758E574D1ULL,
		0x48ACE3136BD307A1ULL,
		0x5F9D4D08AECE10F5ULL,
		0x0000000004AD089EULL
	}};
	shift = 27;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD9C34CBB7C26018EULL,
		0xFE1F72846AE3BF85ULL,
		0x753092EA85272B4BULL,
		0x3A073F5599842DC0ULL,
		0x6FC24F1939384EB5ULL,
		0x516D76E536BAFA31ULL,
		0x88F5873BC5148D45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x976F84C031C00000ULL,
		0x508D5C77F0BB3869ULL,
		0x5D50A4E5697FC3EEULL,
		0xEAB33085B80EA612ULL,
		0xE3272709D6A740E7ULL,
		0xDCA6D75F462DF849ULL,
		0xE778A291A8AA2DAEULL,
		0x0000000000111EB0ULL
	}};
	shift = 21;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA8392184731F20B1ULL,
		0x314CB83FDD1FB5C1ULL,
		0x160052A8565907EDULL,
		0xBDFE652DB1D026C9ULL,
		0x3D869530DD7FEE8CULL,
		0x00033CC79461FB31ULL,
		0x55602B9B1507C427ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24308E63E4162000ULL,
		0x9707FBA3F6B83507ULL,
		0x0A550ACB20FDA629ULL,
		0xCCA5B63A04D922C0ULL,
		0xD2A61BAFFDD197BFULL,
		0x6798F28C3F6627B0ULL,
		0x057362A0F884E000ULL,
		0x0000000000000AACULL
	}};
	shift = 13;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8516504BB1C8941FULL,
		0xB54872340CECCD13ULL,
		0x392E4EBD0CB261E2ULL,
		0x7953FBD4071EAC18ULL,
		0x96035ACD0652D37DULL,
		0x93599CF85F2336D9ULL,
		0xFC53A7BD34DD4E46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x412EC722507C0000ULL,
		0xC8D033B3344E1459ULL,
		0x3AF432C9878AD521ULL,
		0xEF501C7AB060E4B9ULL,
		0x6B34194B4DF5E54FULL,
		0x73E17C8CDB66580DULL,
		0x9EF4D375391A4D66ULL,
		0x000000000003F14EULL
	}};
	shift = 18;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x49DA373485ED1A3CULL,
		0xE7C6DF1C974A963BULL,
		0x84613900BAA198AAULL,
		0x104683159447F1C2ULL,
		0x4FAB688B83459BC7ULL,
		0x8F9E4AA2088CEE35ULL,
		0x0B263C34BF47C4CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA373485ED1A3C0ULL,
		0x7C6DF1C974A963B4ULL,
		0x4613900BAA198AAEULL,
		0x04683159447F1C28ULL,
		0xFAB688B83459BC71ULL,
		0xF9E4AA2088CEE354ULL,
		0xB263C34BF47C4CA8ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x03338E5B5974500FULL,
		0x8E187FC54DE036E4ULL,
		0x91D7DB592F325F81ULL,
		0xF18FDB8527259581ULL,
		0x3B5311A0A94F13C9ULL,
		0xF8663C34414965A7ULL,
		0xB86A2D7E8378C3B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x0199C72DACBA2807ULL,
		0xC70C3FE2A6F01B72ULL,
		0xC8EBEDAC97992FC0ULL,
		0xF8C7EDC29392CAC0ULL,
		0x9DA988D054A789E4ULL,
		0xFC331E1A20A4B2D3ULL,
		0x5C3516BF41BC61D9ULL
	}};
	shift = 63;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x464476F7C45A61BCULL,
		0x0F3707B045FD2DBEULL,
		0x426252F282D81332ULL,
		0x48089B1A07C16566ULL,
		0x56DF6C7663A49895ULL,
		0xCA865A6C5C0BA119ULL,
		0xB39B13284E5EBF40ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC88EDEF88B4C3780ULL,
		0xE6E0F608BFA5B7C8ULL,
		0x4C4A5E505B026641ULL,
		0x01136340F82CACC8ULL,
		0xDBED8ECC749312A9ULL,
		0x50CB4D8B8174232AULL,
		0x73626509CBD7E819ULL,
		0x0000000000000016ULL
	}};
	shift = 5;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA7D2B87F9847F35DULL,
		0xB68F7F30119EA828ULL,
		0xA01CADF843FA4EBCULL,
		0xC61AD952E421E9FBULL,
		0xB06D8C5008ABE9DEULL,
		0xBF2B9205D2C22A0FULL,
		0xF985A1284B55FB9AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B87F9847F35D000ULL,
		0xF7F30119EA828A7DULL,
		0xCADF843FA4EBCB68ULL,
		0xAD952E421E9FBA01ULL,
		0xD8C5008ABE9DEC61ULL,
		0xB9205D2C22A0FB06ULL,
		0x5A1284B55FB9ABF2ULL,
		0x0000000000000F98ULL
	}};
	shift = 12;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x900A711C157EB0C2ULL,
		0x21392EB87B1674BEULL,
		0x51981A21C06C2BBBULL,
		0x7BDD662ADD8BDF08ULL,
		0xB142FF104D950F54ULL,
		0x387DC4507FFE8933ULL,
		0x619E921275FF668FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0C2000000000000ULL,
		0x74BE900A711C157EULL,
		0x2BBB21392EB87B16ULL,
		0xDF0851981A21C06CULL,
		0x0F547BDD662ADD8BULL,
		0x8933B142FF104D95ULL,
		0x668F387DC4507FFEULL,
		0x0000619E921275FFULL
	}};
	shift = 48;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD20C0C633C99BBAAULL,
		0xED81E31024E281AAULL,
		0xCA8A4705C67DC64FULL,
		0x8E5BC71BBB86D527ULL,
		0xE9DE0F3C1B9FAC93ULL,
		0x7101AF673631C330ULL,
		0x30667F4B3A9BF81AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x5A41818C67933775ULL,
		0xFDB03C62049C5035ULL,
		0xF95148E0B8CFB8C9ULL,
		0x71CB78E37770DAA4ULL,
		0x1D3BC1E78373F592ULL,
		0x4E2035ECE6C63866ULL,
		0x060CCFE967537F03ULL
	}};
	shift = 61;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5AE910DC1123BB0BULL,
		0xEC6D1FD33D96D031ULL,
		0x150E0C5D0D97AF21ULL,
		0xEA06047873AFE8D4ULL,
		0x6B3FDDAD86A2FD04ULL,
		0xA16408587D10AE8CULL,
		0x5109649D62C8B905ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x221B822477616000ULL,
		0xA3FA67B2DA062B5DULL,
		0xC18BA1B2F5E43D8DULL,
		0xC08F0E75FD1A82A1ULL,
		0xFBB5B0D45FA09D40ULL,
		0x810B0FA215D18D67ULL,
		0x2C93AC591720B42CULL,
		0x0000000000000A21ULL
	}};
	shift = 13;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x00B10F77980BE17CULL,
		0xB08C008E1B56185BULL,
		0xAFF5D4ED2002C144ULL,
		0x59DD026DED6A4945ULL,
		0x3A7A57F73C30B8BCULL,
		0x9D6894BFC11DBA15ULL,
		0xF98D4E164EC0ECD5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0BE000000000000ULL,
		0x0C2D805887BBCC05ULL,
		0x60A2584600470DABULL,
		0x24A2D7FAEA769001ULL,
		0x5C5E2CEE8136F6B5ULL,
		0xDD0A9D3D2BFB9E18ULL,
		0x766ACEB44A5FE08EULL,
		0x00007CC6A70B2760ULL
	}};
	shift = 47;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7603F37322F9A66FULL,
		0x205902EF33B10EE0ULL,
		0xC9B86930944BABC1ULL,
		0x21CF55C021E08A8FULL,
		0x7F659374C63ECE7AULL,
		0xD62D7F565E16DDE8ULL,
		0x541803906916B051ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37322F9A66F00000ULL,
		0x2EF33B10EE07603FULL,
		0x930944BABC120590ULL,
		0x5C021E08A8FC9B86ULL,
		0x374C63ECE7A21CF5ULL,
		0xF565E16DDE87F659ULL,
		0x3906916B051D62D7ULL,
		0x0000000000054180ULL
	}};
	shift = 20;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA603F3D09842AC9DULL,
		0x7C676960E3DB4898ULL,
		0x157EBF13EF681C27ULL,
		0x564B2141498B8ADAULL,
		0xD260891FCA6651AAULL,
		0x8CDE17D388F0AC9BULL,
		0xE6F964F098DCE914ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C21564E80000000ULL,
		0x71EDA44C5301F9E8ULL,
		0xF7B40E13BE33B4B0ULL,
		0xA4C5C56D0ABF5F89ULL,
		0xE53328D52B2590A0ULL,
		0xC478564DE930448FULL,
		0x4C6E748A466F0BE9ULL,
		0x00000000737CB278ULL
	}};
	shift = 31;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5DF5EE295B31C21DULL,
		0x8BD2D57BB23A9A64ULL,
		0xBE294ED9B3164016ULL,
		0xC67F56B8BAB86D7AULL,
		0xD2B608CBAB03C33CULL,
		0x759C303777564EF6ULL,
		0xFAB11B640B588901ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBEBDC52B663843AULL,
		0x17A5AAF7647534C8ULL,
		0x7C529DB3662C802DULL,
		0x8CFEAD717570DAF5ULL,
		0xA56C119756078679ULL,
		0xEB38606EEEAC9DEDULL,
		0xF56236C816B11202ULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x14769563F253E1A4ULL,
		0xB3B91037E2FE479EULL,
		0xCD09587062B478F0ULL,
		0x971A0C461D627EE4ULL,
		0x410EF379BA406690ULL,
		0x875A2845C9313A33ULL,
		0x2EBF538A277ACC32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB1F929F0D20000ULL,
		0x881BF17F23CF0A3BULL,
		0xAC38315A3C7859DCULL,
		0x06230EB13F726684ULL,
		0x79BCDD2033484B8DULL,
		0x1422E4989D19A087ULL,
		0xA9C513BD661943ADULL,
		0x000000000000175FULL
	}};
	shift = 15;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x692093E5AFDF764DULL,
		0x549788B576EC0B11ULL,
		0xC85052B92C50F11FULL,
		0x58E510B98455D915ULL,
		0x5A3AE8CBF79928AFULL,
		0xD7FC23EF3D4EC24BULL,
		0x7E7E97B8916B6FA9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49F2D7EFBB268000ULL,
		0xC45ABB760588B490ULL,
		0x295C9628788FAA4BULL,
		0x885CC22AEC8AE428ULL,
		0x7465FBCC9457AC72ULL,
		0x11F79EA76125AD1DULL,
		0x4BDC48B5B7D4EBFEULL,
		0x0000000000003F3FULL
	}};
	shift = 15;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC2B90CB88FA148FULL,
		0x92B4C1529C3809BAULL,
		0x2A3543E87BD4F1DAULL,
		0xE3BF96CE23506CFAULL,
		0xE946107B944D0398ULL,
		0x2FBC84BB127D7C44ULL,
		0x6F4DC6FB26D6A07BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15C865C47D0A478ULL,
		0x95A60A94E1C04DD7ULL,
		0x51AA1F43DEA78ED4ULL,
		0x1DFCB6711A8367D1ULL,
		0x4A3083DCA2681CC7ULL,
		0x7DE425D893EBE227ULL,
		0x7A6E37D936B503D9ULL,
		0x0000000000000003ULL
	}};
	shift = 3;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB7D0DDD1DEB5CB3EULL,
		0x0137177AD4171D3FULL,
		0x0B01A32E8F9A5149ULL,
		0xECF730231461761CULL,
		0xC1CDB8FA4990F20FULL,
		0xC90E0DF318B7D320ULL,
		0xD4E5A9099094EFC7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD72CF8000000000ULL,
		0x05C74FEDF4377477ULL,
		0xE69452404DC5DEB5ULL,
		0x185D8702C068CBA3ULL,
		0x643C83FB3DCC08C5ULL,
		0x2DF4C830736E3E92ULL,
		0x253BF1F243837CC6ULL,
		0x00000035396A4264ULL
	}};
	shift = 38;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD7325715624C974CULL,
		0x75188E8175E16D36ULL,
		0x4ABF71AD9A83DEC0ULL,
		0xDA567B41903B8070ULL,
		0xC5BE95EED3530BA0ULL,
		0xD8689CDBE0B4E97DULL,
		0xCFFE0CC280763B16ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E98000000000000ULL,
		0xDA6DAE64AE2AC499ULL,
		0xBD80EA311D02EBC2ULL,
		0x00E0957EE35B3507ULL,
		0x1741B4ACF6832077ULL,
		0xD2FB8B7D2BDDA6A6ULL,
		0x762DB0D139B7C169ULL,
		0x00019FFC198500ECULL
	}};
	shift = 49;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4139B4AED233C16DULL,
		0xAD4FF9296B8DA545ULL,
		0x3915BC2CCF723E78ULL,
		0x164EA1FDCD0E879EULL,
		0x5BE60DB26C27E740ULL,
		0x45B8ECC567D62E83ULL,
		0xB6F793509519F66DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C16D00000000000ULL,
		0xDA5454139B4AED23ULL,
		0x23E78AD4FF9296B8ULL,
		0xE879E3915BC2CCF7ULL,
		0x7E740164EA1FDCD0ULL,
		0x62E835BE60DB26C2ULL,
		0x9F66D45B8ECC567DULL,
		0x00000B6F79350951ULL
	}};
	shift = 44;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0EC87A4B3361F20EULL,
		0xEBC89F12D2A130E7ULL,
		0xF7380567924B64CBULL,
		0xDFEDC50BB03EFEE5ULL,
		0x78001803B7C6DB46ULL,
		0xCDC855E3188AD00AULL,
		0xA65FF2AC94582918ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8380000000000000ULL,
		0x39C3B21E92CCD87CULL,
		0x32FAF227C4B4A84CULL,
		0xB97DCE0159E492D9ULL,
		0xD1B7FB7142EC0FBFULL,
		0x029E000600EDF1B6ULL,
		0x4633721578C622B4ULL,
		0x002997FCAB25160AULL
	}};
	shift = 54;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD281A6ED7A609A3EULL,
		0x40DFDE51BD955B6EULL,
		0x4399ACCF66B2ED27ULL,
		0xD96E311B8AA139C0ULL,
		0xC53ABD0C038E71E0ULL,
		0x9BF80B244F1D3893ULL,
		0x3F8022DAA8F5DA65ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BB5E98268F8000ULL,
		0xF7946F6556DBB4A0ULL,
		0x6B33D9ACBB49D037ULL,
		0x8C46E2A84E7010E6ULL,
		0xAF4300E39C78365BULL,
		0x02C913C74E24F14EULL,
		0x08B6AA3D769966FEULL,
		0x0000000000000FE0ULL
	}};
	shift = 14;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x78FB393DDA6DCD4BULL,
		0xCA45DB3FE183C026ULL,
		0x95A99626DB671DA9ULL,
		0xD29CE1E215544709ULL,
		0x6C410457613FDA13ULL,
		0x25258BF963359889ULL,
		0x9069D6D29C5D9AB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA6DCD4B00000000ULL,
		0xE183C02678FB393DULL,
		0xDB671DA9CA45DB3FULL,
		0x1554470995A99626ULL,
		0x613FDA13D29CE1E2ULL,
		0x633598896C410457ULL,
		0x9C5D9AB525258BF9ULL,
		0x000000009069D6D2ULL
	}};
	shift = 32;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFFDC8C37C4516DFBULL,
		0x000BE7BB7EA2684BULL,
		0xEB19A4246BD9ECABULL,
		0x5DBD5C5634C7A062ULL,
		0xA7E35C64FC2BF227ULL,
		0x4648E20F0E85E9ADULL,
		0xB0791BD53AB578E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B6FD8000000000ULL,
		0x513425FFEE461BE2ULL,
		0xECF6558005F3DDBFULL,
		0x63D031758CD21235ULL,
		0x15F913AEDEAE2B1AULL,
		0x42F4D6D3F1AE327EULL,
		0x5ABC70A324710787ULL,
		0x000000583C8DEA9DULL
	}};
	shift = 39;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2933EAFB6A1A12AFULL,
		0x6C4FE2865E1CD886ULL,
		0x0BE015F9540EFF54ULL,
		0x8CCF41BCB8ADA93FULL,
		0x47626BC24EEF124BULL,
		0xDB801E084FEE369AULL,
		0x6CD9E482000B1EFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDA8684ABC000000ULL,
		0x1978736218A4CFABULL,
		0xE5503BFD51B13F8AULL,
		0xF2E2B6A4FC2F8057ULL,
		0x093BBC492E333D06ULL,
		0x213FB8DA691D89AFULL,
		0x08002C7BEB6E0078ULL,
		0x0000000001B36792ULL
	}};
	shift = 26;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E8011C0015EFDBEULL,
		0xEC7167DEF9FC0F45ULL,
		0x8FE32DE48B39FF9AULL,
		0xFD498300ADD7DCEAULL,
		0xD8B64842566D4D6BULL,
		0x089330029B8C25D7ULL,
		0xAF7373D1EE632186ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A004700057BF6F8ULL,
		0xB1C59F7BE7F03D16ULL,
		0x3F8CB7922CE7FE6BULL,
		0xF5260C02B75F73AAULL,
		0x62D9210959B535AFULL,
		0x224CC00A6E30975FULL,
		0xBDCDCF47B98C8618ULL,
		0x0000000000000002ULL
	}};
	shift = 2;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB05BB6F978595DFEULL,
		0x14D0FD896563D8BDULL,
		0xE193E04DC0A47AEBULL,
		0x05FC43CE1A6D177EULL,
		0x3C16EA7AACD565D8ULL,
		0x7C9DF7D5B57135F5ULL,
		0x3C37035CD36163B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC16EDBE5E16577F8ULL,
		0x5343F625958F62F6ULL,
		0x864F81370291EBACULL,
		0x17F10F3869B45DFBULL,
		0xF05BA9EAB3559760ULL,
		0xF277DF56D5C4D7D4ULL,
		0xF0DC0D734D858ED9ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB2933027981CE382ULL,
		0x5DFA0C8CBC6C00A1ULL,
		0xB0A05634AB3F74DFULL,
		0x1959F67AF4ED737BULL,
		0x476D0C7F701DE569ULL,
		0x581AAB63F74F41F4ULL,
		0x2068B6C7EB8330FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC09E60738E08000ULL,
		0x83232F1B00286CA4ULL,
		0x158D2ACFDD37D77EULL,
		0x7D9EBD3B5CDEEC28ULL,
		0x431FDC07795A4656ULL,
		0xAAD8FDD3D07D11DBULL,
		0x2DB1FAE0CC3F9606ULL,
		0x000000000000081AULL
	}};
	shift = 14;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x635B32F490349415ULL,
		0x7C27540B4A11A716ULL,
		0xD83281867D10B85AULL,
		0x2AC39733C64184C1ULL,
		0xC36DFC8A05A9B57DULL,
		0x6C6F1539D9C81D53ULL,
		0x2D534CED1F1B69E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0349415000000000ULL,
		0xA11A716635B32F49ULL,
		0xD10B85A7C27540B4ULL,
		0x64184C1D83281867ULL,
		0x5A9B57D2AC39733CULL,
		0x9C81D53C36DFC8A0ULL,
		0xF1B69E36C6F1539DULL,
		0x00000002D534CED1ULL
	}};
	shift = 36;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x086C264DFF8C7D57ULL,
		0x7BDCDF5593E88C51ULL,
		0x63FD99CC7CA2C50DULL,
		0x56D128B578618F70ULL,
		0x73FFD752853115D8ULL,
		0xC0526A1F23596FC6ULL,
		0x2380AC40B28B0860ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FE31F55C0000000ULL,
		0x64FA2314421B0993ULL,
		0x1F28B1435EF737D5ULL,
		0x5E1863DC18FF6673ULL,
		0xA14C457615B44A2DULL,
		0xC8D65BF19CFFF5D4ULL,
		0x2CA2C21830149A87ULL,
		0x0000000008E02B10ULL
	}};
	shift = 30;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9753A43F68A80BA2ULL,
		0x2599E24A0BAADE1FULL,
		0x9430C859B9BA8E9CULL,
		0xF805C93659D80A3BULL,
		0xBE4EBAF896049932ULL,
		0xC7AADCA8B1CFA274ULL,
		0x9CC4C2E397696CE1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA7487ED15017440ULL,
		0xB33C4941755BC3F2ULL,
		0x86190B373751D384ULL,
		0x00B926CB3B014772ULL,
		0xC9D75F12C093265FULL,
		0xF55B951639F44E97ULL,
		0x98985C72ED2D9C38ULL,
		0x0000000000000013ULL
	}};
	shift = 5;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x46361689C77D2206ULL,
		0x6089F88FB50C80D8ULL,
		0xE94EDA3D3B138C78ULL,
		0xFE68A4DEDBDC3FE4ULL,
		0xB8B11BED05A4A63DULL,
		0xD6A69652589A7FCFULL,
		0x353C481D3C65A2B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C2D138EFA440C0ULL,
		0x113F11F6A1901B08ULL,
		0x29DB47A762718F0CULL,
		0xCD149BDB7B87FC9DULL,
		0x16237DA0B494C7BFULL,
		0xD4D2CA4B134FF9F7ULL,
		0xA78903A78CB456BAULL,
		0x0000000000000006ULL
	}};
	shift = 5;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9F011070C1DCD00ULL,
		0x2FDE1661B5FDB39FULL,
		0x8C9D1031461845F8ULL,
		0xC1C41FCAC9D4E02DULL,
		0xC7A154ECC490C5D1ULL,
		0xEAF63DA678C3462EULL,
		0x9AA4E206A20CC54EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE6800000000000ULL,
		0xFED9CFF4F8088386ULL,
		0x0C22FC17EF0B30DAULL,
		0xEA7016C64E8818A3ULL,
		0x4862E8E0E20FE564ULL,
		0x61A31763D0AA7662ULL,
		0x0662A7757B1ED33CULL,
		0x0000004D52710351ULL
	}};
	shift = 39;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4CF6BDEE83332A55ULL,
		0xB90C2B04C747C906ULL,
		0xAAB736C694FF46D8ULL,
		0x389D41478A3300ECULL,
		0xEF258EC3F885ADE4ULL,
		0xD32C4958673F3E1FULL,
		0x40E24630AFAEF5A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x933DAF7BA0CCCA95ULL,
		0x2E430AC131D1F241ULL,
		0x2AADCDB1A53FD1B6ULL,
		0x0E275051E28CC03BULL,
		0xFBC963B0FE216B79ULL,
		0xF4CB125619CFCF87ULL,
		0x1038918C2BEBBD68ULL
	}};
	shift = 62;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x25924C0F82E34E08ULL,
		0x59B8AC63313B8860ULL,
		0xF1DD9DE4A1027831ULL,
		0x230BF8C4A626EA6CULL,
		0xC17368B0B55D74DAULL,
		0x7F8595A21A5177BFULL,
		0x5BBEC043160BF8B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B8D382000000000ULL,
		0xC4EE21809649303EULL,
		0x8409E0C566E2B18CULL,
		0x989BA9B3C7767792ULL,
		0xD575D3688C2FE312ULL,
		0x6945DEFF05CDA2C2ULL,
		0x582FE2E5FE165688ULL,
		0x000000016EFB010CULL
	}};
	shift = 34;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB1CD9F33DAF28E97ULL,
		0x9E71C8DED956CA42ULL,
		0x2AD73637AD056073ULL,
		0x0EF7CA7F80DC2343ULL,
		0x52E1895020BACD3EULL,
		0x13C61BCA9198891CULL,
		0x0A74B7DDCC3D9587ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF28E970000000000ULL,
		0x56CA42B1CD9F33DAULL,
		0x0560739E71C8DED9ULL,
		0xDC23432AD73637ADULL,
		0xBACD3E0EF7CA7F80ULL,
		0x98891C52E1895020ULL,
		0x3D958713C61BCA91ULL,
		0x0000000A74B7DDCCULL
	}};
	shift = 40;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA30553E9D9CF6C16ULL,
		0x1C37F186092CC7D4ULL,
		0xBE429B35D361D4ABULL,
		0xA62F766CB4D872E6ULL,
		0x9E7FCE54983E5BDBULL,
		0x46CA183598D5DB94ULL,
		0xFF23097E9A760E21ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ED82C0000000000ULL,
		0x598FA9460AA7D3B3ULL,
		0xC3A956386FE30C12ULL,
		0xB0E5CD7C85366BA6ULL,
		0x7CB7B74C5EECD969ULL,
		0xABB7293CFF9CA930ULL,
		0xEC1C428D94306B31ULL,
		0x000001FE4612FD34ULL
	}};
	shift = 41;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA3BD3C93BC0F77AEULL,
		0x7D981721891DDC32ULL,
		0xA902F9DE0BEB96C4ULL,
		0xF7952A9C96117ADAULL,
		0x32563F63DB893189ULL,
		0xA828EFD511B5C8FBULL,
		0xE4E5946C4282B6F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EEF5C0000000000ULL,
		0x3BB865477A792778ULL,
		0xD72D88FB302E4312ULL,
		0x22F5B55205F3BC17ULL,
		0x126313EF2A55392CULL,
		0x6B91F664AC7EC7B7ULL,
		0x056DF15051DFAA23ULL,
		0x000001C9CB28D885ULL
	}};
	shift = 41;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF7B916BA141AC54FULL,
		0x579A3F00A28689A1ULL,
		0xBD9B052AA575CCA9ULL,
		0xF098773098D8DB20ULL,
		0x0A7EB70CCDDA9213ULL,
		0x94882B13C793A471ULL,
		0xBA7166A05BA1ABA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F00000000000000ULL,
		0xA1F7B916BA141AC5ULL,
		0xA9579A3F00A28689ULL,
		0x20BD9B052AA575CCULL,
		0x13F098773098D8DBULL,
		0x710A7EB70CCDDA92ULL,
		0xA294882B13C793A4ULL,
		0x00BA7166A05BA1ABULL
	}};
	shift = 56;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBA6142BD7F07474FULL,
		0xD7F4EC70DFCB110CULL,
		0x209B93E3133922EDULL,
		0x61BC82ECF130B2A8ULL,
		0xC22810C5F7FFB063ULL,
		0xAF60AF2929A0652EULL,
		0xC878AB0C0585652CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BD7F07474F00000ULL,
		0xC70DFCB110CBA614ULL,
		0x3E3133922EDD7F4EULL,
		0x2ECF130B2A8209B9ULL,
		0x0C5F7FFB06361BC8ULL,
		0xF2929A0652EC2281ULL,
		0xB0C0585652CAF60AULL,
		0x00000000000C878AULL
	}};
	shift = 20;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x801E8EBEDF424F5EULL,
		0x1C8D2A4951BFA1CAULL,
		0x07052561338CC0FEULL,
		0x30BCD092D311F9F3ULL,
		0x20757A6C17EB682EULL,
		0x3AFC71FBDD3B7DE1ULL,
		0x270C6802E87F6749ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A3AFB7D093D780ULL,
		0x234A92546FE872A0ULL,
		0xC149584CE3303F87ULL,
		0x2F3424B4C47E7CC1ULL,
		0x1D5E9B05FADA0B8CULL,
		0xBF1C7EF74EDF7848ULL,
		0xC31A00BA1FD9D24EULL,
		0x0000000000000009ULL
	}};
	shift = 6;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0D4DB631BE1C2203ULL,
		0x2D400968559B323CULL,
		0xCEC95636EC5C4EADULL,
		0x2C0566C03B204E66ULL,
		0x1D45B5FF56109E3AULL,
		0x1D7865B2783A8628ULL,
		0x3AEFDDF9D43B681DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536D8C6F870880C0ULL,
		0x50025A1566CC8F03ULL,
		0xB2558DBB1713AB4BULL,
		0x0159B00EC81399B3ULL,
		0x516D7FD584278E8BULL,
		0x5E196C9E0EA18A07ULL,
		0xBBF77E750EDA0747ULL,
		0x000000000000000EULL
	}};
	shift = 6;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9EE9F05C4BD57A07ULL,
		0x2C42605DDECB4D7BULL,
		0x3CF9B9A73E8D0DBEULL,
		0x6B6909D2FA6BF52AULL,
		0xAE9DB458E6AB1B50ULL,
		0xCF0A5FC9A2F530DCULL,
		0x83AB9689D07F0942ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DD3E0B897AAF40EULL,
		0x5884C0BBBD969AF7ULL,
		0x79F3734E7D1A1B7CULL,
		0xD6D213A5F4D7EA54ULL,
		0x5D3B68B1CD5636A0ULL,
		0x9E14BF9345EA61B9ULL,
		0x07572D13A0FE1285ULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCD9FDDB6FAA06AF2ULL,
		0xEE5710528AC98A52ULL,
		0xE0D869E5A3812B5DULL,
		0x5115D2F394EBD540ULL,
		0x3219BAEA3B29B1A3ULL,
		0xD1727B4066E4DD7DULL,
		0xF0F60A51D93911B0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE400000000000000ULL,
		0xA59B3FBB6DF540D5ULL,
		0xBBDCAE20A5159314ULL,
		0x81C1B0D3CB470256ULL,
		0x46A22BA5E729D7AAULL,
		0xFA643375D4765363ULL,
		0x61A2E4F680CDC9BAULL,
		0x01E1EC14A3B27223ULL
	}};
	shift = 57;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2A5C626F457FA4F5ULL,
		0x0715AD93DC213B9CULL,
		0xA656895DE30EA007ULL,
		0x3DDA8C51F0B475D6ULL,
		0x487FB238ABFB4132ULL,
		0xBB0CBCAEEEDC6998ULL,
		0xBB59EAA74D9C8E67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE8AFF49EA00000ULL,
		0xB27B842773854B8CULL,
		0x2BBC61D400E0E2B5ULL,
		0x8A3E168EBAD4CAD1ULL,
		0x47157F682647BB51ULL,
		0x95DDDB8D33090FF6ULL,
		0x54E9B391CCF76197ULL,
		0x0000000000176B3DULL
	}};
	shift = 21;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x791726C26C4A02DEULL,
		0xC71138B6AA9E3EA2ULL,
		0x100BDB13755F60ABULL,
		0x2F00E2A3A4957957ULL,
		0x3C848163AA08D19CULL,
		0x227A8F17F1A56399ULL,
		0x524FB076C7679543ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F00000000000000ULL,
		0x513C8B9361362501ULL,
		0x55E3889C5B554F1FULL,
		0xAB8805ED89BAAFB0ULL,
		0xCE17807151D24ABCULL,
		0xCC9E4240B1D50468ULL,
		0xA1913D478BF8D2B1ULL,
		0x002927D83B63B3CAULL
	}};
	shift = 55;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFE101707C4F5F045ULL,
		0x762B50C3F174175CULL,
		0x514303F71ABA4163ULL,
		0x9FE5561AF0209F88ULL,
		0xEF506FF335F1A7CEULL,
		0x2E5D5614D40E479AULL,
		0x31476E9070E3549CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF822800000000000ULL,
		0x0BAE7F080B83E27AULL,
		0x20B1BB15A861F8BAULL,
		0x4FC428A181FB8D5DULL,
		0xD3E74FF2AB0D7810ULL,
		0x23CD77A837F99AF8ULL,
		0xAA4E172EAB0A6A07ULL,
		0x000018A3B7483871ULL
	}};
	shift = 47;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF4D910750C8FD42FULL,
		0x9B97AD47AC039419ULL,
		0xF2B04AF8D77542E2ULL,
		0x4C9C29036BF77579ULL,
		0x7CAA3A2FBBCC11E0ULL,
		0x8143F040679A407DULL,
		0x9454E0E6C968169DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D4323F50BC00000ULL,
		0x51EB00E5067D3644ULL,
		0xBE35DD50B8A6E5EBULL,
		0x40DAFDDD5E7CAC12ULL,
		0x8BEEF3047813270AULL,
		0x1019E6901F5F2A8EULL,
		0x39B25A05A76050FCULL,
		0x0000000000251538ULL
	}};
	shift = 22;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x76398CC16F81E289ULL,
		0xD19CD3689E00A6D3ULL,
		0x88670C5209CC9436ULL,
		0xA9EF5D9D7EA74D4EULL,
		0xAF6C60ECE1F4BCCEULL,
		0x8CD14B984252B4B4ULL,
		0xD47C12F3FFE78680ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3305BE078A240000ULL,
		0x4DA278029B4DD8E6ULL,
		0x3148273250DB4673ULL,
		0x7675FA9D353A219CULL,
		0x83B387D2F33AA7BDULL,
		0x2E61094AD2D2BDB1ULL,
		0x4BCFFF9E1A023345ULL,
		0x00000000000351F0ULL
	}};
	shift = 18;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEAA9FD21E84E5280ULL,
		0x4A376B922A3D492AULL,
		0xE1B56CA70E731F60ULL,
		0x6EE27CFE947572E0ULL,
		0x83DF6888DA47D774ULL,
		0x04CB4921F2CDFD43ULL,
		0x049A4E2EED444590ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAA9FD21E84E5280ULL,
		0x4A376B922A3D492AULL,
		0xE1B56CA70E731F60ULL,
		0x6EE27CFE947572E0ULL,
		0x83DF6888DA47D774ULL,
		0x04CB4921F2CDFD43ULL,
		0x049A4E2EED444590ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBFD4D4DBDD8F53F6ULL,
		0x5FD432D75726496AULL,
		0xD8680B4DB37D61CAULL,
		0x1B30AED890C999FBULL,
		0x6ED7AE086487ABE3ULL,
		0x8679AD5A406B88DCULL,
		0x31C4B14E5C98C418ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F53F6000000000ULL,
		0x726496ABFD4D4DBDULL,
		0x37D61CA5FD432D75ULL,
		0x0C999FBD8680B4DBULL,
		0x487ABE31B30AED89ULL,
		0x06B88DC6ED7AE086ULL,
		0xC98C4188679AD5A4ULL,
		0x000000031C4B14E5ULL
	}};
	shift = 36;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x179D3DFAF4A52182ULL,
		0x45279E7285B6ABE6ULL,
		0xB216B33D21ED07B2ULL,
		0xA4C365A9624AA790ULL,
		0xF42511FCD77E6FEDULL,
		0x69FEFCD2168687A4ULL,
		0x3BC25C8250116844ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1820000000000000ULL,
		0xBE6179D3DFAF4A52ULL,
		0x7B245279E7285B6AULL,
		0x790B216B33D21ED0ULL,
		0xFEDA4C365A9624AAULL,
		0x7A4F42511FCD77E6ULL,
		0x84469FEFCD216868ULL,
		0x0003BC25C8250116ULL
	}};
	shift = 52;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x25D203CE67C885A8ULL,
		0xCD1FDF719879FBB2ULL,
		0xC32C4BFD3F7EC56AULL,
		0x5494524ABB7012B1ULL,
		0x7FF63556CAE37DD8ULL,
		0x53B7244AD69A6DB1ULL,
		0xEA721F726392C61EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4079CCF910B5000ULL,
		0x3FBEE330F3F7644BULL,
		0x5897FA7EFD8AD59AULL,
		0x28A49576E0256386ULL,
		0xEC6AAD95C6FBB0A9ULL,
		0x6E4895AD34DB62FFULL,
		0xE43EE4C7258C3CA7ULL,
		0x00000000000001D4ULL
	}};
	shift = 9;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x41549433E88FD53EULL,
		0x7653B92E79B54716ULL,
		0x6CF045FFD5FEF1DFULL,
		0x3D7E065482F9966DULL,
		0xF5927622B21F7808ULL,
		0xA942F7E2711BA5AAULL,
		0xC1381683EE3BE295ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D11FAA7C0000000ULL,
		0xCF36A8E2C82A9286ULL,
		0xFABFDE3BEECA7725ULL,
		0x905F32CDAD9E08BFULL,
		0x5643EF0107AFC0CAULL,
		0x4E2374B55EB24EC4ULL,
		0x7DC77C52B5285EFCULL,
		0x00000000182702D0ULL
	}};
	shift = 29;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3461044BEDF39EE0ULL,
		0xB910A328A3468880ULL,
		0xFA509B724F6A0CB7ULL,
		0x4F15CB6532022CC2ULL,
		0x98FFD52F3E5361E3ULL,
		0x5B6C46266B5D3961ULL,
		0x8DBFA5121F5E9739ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0x803461044BEDF39EULL,
		0xB7B910A328A34688ULL,
		0xC2FA509B724F6A0CULL,
		0xE34F15CB6532022CULL,
		0x6198FFD52F3E5361ULL,
		0x395B6C46266B5D39ULL,
		0x008DBFA5121F5E97ULL
	}};
	shift = 56;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x491C4D2AFE56072BULL,
		0xBC94274018668921ULL,
		0xC34D989B455ED871ULL,
		0xC24D8F6DAEAFA0F1ULL,
		0xB971B87752DC3FBAULL,
		0x79544190C30D2AC0ULL,
		0x84AFDAAC15579797ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF9581CAC0000000ULL,
		0x0619A2485247134AULL,
		0xD157B61C6F2509D0ULL,
		0x6BABE83C70D36626ULL,
		0xD4B70FEEB09363DBULL,
		0x30C34AB02E5C6E1DULL,
		0x0555E5E5DE551064ULL,
		0x00000000212BF6ABULL
	}};
	shift = 30;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x581C2FA7D14E4635ULL,
		0x8712681FC7BBABDCULL,
		0xF2C34293E47662C7ULL,
		0xFFD7344A624783C3ULL,
		0xC54FD7ADE65EB723ULL,
		0xFEC45408EEF0FACCULL,
		0x2C2BF44FE9024B3AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385F4FA29C8C6A00ULL,
		0x24D03F8F7757B8B0ULL,
		0x868527C8ECC58F0EULL,
		0xAE6894C48F0787E5ULL,
		0x9FAF5BCCBD6E47FFULL,
		0x88A811DDE1F5998AULL,
		0x57E89FD2049675FDULL,
		0x0000000000000058ULL
	}};
	shift = 9;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x920EE0A590D99033ULL,
		0xA2ECA57755FEE981ULL,
		0x614C03CDED616C71ULL,
		0x8A6C23E006B46107ULL,
		0xD63A0C44DAED3FB2ULL,
		0x5BBB802A28377EDBULL,
		0xB20F4E5D981C55B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x241DC14B21B32066ULL,
		0x45D94AEEABFDD303ULL,
		0xC298079BDAC2D8E3ULL,
		0x14D847C00D68C20EULL,
		0xAC741889B5DA7F65ULL,
		0xB7770054506EFDB7ULL,
		0x641E9CBB3038AB66ULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC8FE2525338BCC46ULL,
		0x17BCBF2864474ED0ULL,
		0x599B343927D98554ULL,
		0x00B606F8047B95EBULL,
		0xCE429638DC832AF9ULL,
		0x5065D544A4C1213BULL,
		0x8AEFEBA7CD154274ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7988C00000000000ULL,
		0xE9DA191FC4A4A671ULL,
		0x30AA82F797E50C88ULL,
		0x72BD6B33668724FBULL,
		0x655F2016C0DF008FULL,
		0x242779C852C71B90ULL,
		0xA84E8A0CBAA89498ULL,
		0x0000115DFD74F9A2ULL
	}};
	shift = 45;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB0005EABCA4D6AA8ULL,
		0x31F6E5ED92E5073BULL,
		0xC8D5E6FB0F221D84ULL,
		0x54A94DE691F20867ULL,
		0xAE5817723E43775AULL,
		0x9B0085DD663D7C47ULL,
		0x95E166A0DA11C675ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE526B55400000000ULL,
		0xC972839DD8002F55ULL,
		0x87910EC218FB72F6ULL,
		0x48F90433E46AF37DULL,
		0x1F21BBAD2A54A6F3ULL,
		0xB31EBE23D72C0BB9ULL,
		0x6D08E33ACD8042EEULL,
		0x000000004AF0B350ULL
	}};
	shift = 31;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCF69575726FE0C13ULL,
		0xA63314C4DEBF8455ULL,
		0xE3ED9B867ABDFF5CULL,
		0xF3691B60324DFB99ULL,
		0x29106D3E3CB0D8E3ULL,
		0xDA32474DFD48D5F5ULL,
		0x2D9833FDF856D380ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF69575726FE0C13ULL,
		0xA63314C4DEBF8455ULL,
		0xE3ED9B867ABDFF5CULL,
		0xF3691B60324DFB99ULL,
		0x29106D3E3CB0D8E3ULL,
		0xDA32474DFD48D5F5ULL,
		0x2D9833FDF856D380ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8C5F7D04428EB34FULL,
		0xC4C805701C9B4A81ULL,
		0x33E9BF86A59B0204ULL,
		0xCC62CF79FF6BC3FCULL,
		0xC17CD8E55512924CULL,
		0x9D973A868A419CCBULL,
		0x72C79122B6E87B67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD3C000000000000ULL,
		0x2A06317DF4110A3AULL,
		0x0813132015C0726DULL,
		0x0FF0CFA6FE1A966CULL,
		0x4933318B3DE7FDAFULL,
		0x732F05F36395544AULL,
		0xED9E765CEA1A2906ULL,
		0x0001CB1E448ADBA1ULL
	}};
	shift = 50;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0C0BE505A30B6EF6ULL,
		0xA3B6FBDB338A129CULL,
		0x70117D4C025EB244ULL,
		0x186D489AE13F4EF0ULL,
		0x733A12067EEEBFA7ULL,
		0xCFA403CEC2870CC2ULL,
		0xF08952768ABC5C1FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB77B000000000000ULL,
		0x094E0605F282D185ULL,
		0x592251DB7DED99C5ULL,
		0xA7783808BEA6012FULL,
		0x5FD38C36A44D709FULL,
		0x8661399D09033F77ULL,
		0x2E0FE7D201E76143ULL,
		0x00007844A93B455EULL
	}};
	shift = 47;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF35F3C2495F54A11ULL,
		0x57527BCFAE944CA2ULL,
		0x4CA8B16F953DCB56ULL,
		0x655059C626F6B6E0ULL,
		0x5A4F6E2DD8144009ULL,
		0x9B160610CCCED7B2ULL,
		0xF293819E411C1B16ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF9E124AFAA50880ULL,
		0xA93DE7D74A265179ULL,
		0x5458B7CA9EE5AB2BULL,
		0xA82CE3137B5B7026ULL,
		0x27B716EC0A2004B2ULL,
		0x8B030866676BD92DULL,
		0x49C0CF208E0D8B4DULL,
		0x0000000000000079ULL
	}};
	shift = 7;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x175701751361FB4DULL,
		0xE2F8A292AC687868ULL,
		0x344DA32F1166D0BDULL,
		0xAABE70FBF653838BULL,
		0xFBFDE379751774FDULL,
		0xFB64DB1F3B96BB3DULL,
		0x9A4179FE597394B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02EA26C3F69A000ULL,
		0x1452558D0F0D02EAULL,
		0xB465E22CDA17BC5FULL,
		0xCE1F7ECA70716689ULL,
		0xBC6F2EA2EE9FB557ULL,
		0x9B63E772D767BF7FULL,
		0x2F3FCB2E72963F6CULL,
		0x0000000000001348ULL
	}};
	shift = 13;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD49F6D54456F5069ULL,
		0xA1BBE44FAA27954CULL,
		0x10CEDCCC25031DC9ULL,
		0x6EEB69608B1D1E21ULL,
		0x759CC8980C7E3212ULL,
		0x5A4A6169E884218DULL,
		0xC7FBD9A4DEB55C4AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7A834800000000ULL,
		0x513CAA66A4FB6AA2ULL,
		0x2818EE4D0DDF227DULL,
		0x58E8F1088676E661ULL,
		0x63F19093775B4B04ULL,
		0x44210C6BACE644C0ULL,
		0xF5AAE252D2530B4FULL,
		0x000000063FDECD26ULL
	}};
	shift = 35;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3015F06360253F81ULL,
		0x8E84889AAEE0CA08ULL,
		0xD82F8981E8E50202ULL,
		0x50386ECA1ACABEB7ULL,
		0x06E4AF15A763C6EFULL,
		0xCABD1C5FF0C0D177ULL,
		0x4BBD3F34A94B5C11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x0602BE0C6C04A7F0ULL,
		0x51D0911355DC1941ULL,
		0xFB05F1303D1CA040ULL,
		0xEA070DD9435957D6ULL,
		0xE0DC95E2B4EC78DDULL,
		0x3957A38BFE181A2EULL,
		0x0977A7E695296B82ULL
	}};
	shift = 61;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9A24332FC45984ECULL,
		0x41D91167462B9234ULL,
		0x8F16F4BF56403F1EULL,
		0x02F9C33FC465BF21ULL,
		0xA00C1141C399C6BCULL,
		0x6B9D74BD2F789C87ULL,
		0xB76F4D24153EA45BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CC276000000000ULL,
		0x315C91A4D121997EULL,
		0xB201F8F20EC88B3AULL,
		0x232DF90C78B7A5FAULL,
		0x1CCE35E017CE19FEULL,
		0x7BC4E43D00608A0EULL,
		0xA9F522DB5CEBA5E9ULL,
		0x00000005BB7A6920ULL
	}};
	shift = 35;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4D9E3DFB2F8D8E6DULL,
		0x6F711219506E7BE2ULL,
		0x4DA398B08FEE6F55ULL,
		0x870E9238592AF125ULL,
		0x2E7EF3513D77887AULL,
		0x8F1CE2A93A3FA187ULL,
		0xD4A6AB125CABD62CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678F7ECBE3639B40ULL,
		0xDC4486541B9EF893ULL,
		0x68E62C23FB9BD55BULL,
		0xC3A48E164ABC4953ULL,
		0x9FBCD44F5DE21EA1ULL,
		0xC738AA4E8FE861CBULL,
		0x29AAC4972AF58B23ULL,
		0x0000000000000035ULL
	}};
	shift = 6;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF4E42146343EDF9EULL,
		0x594B2C42F7B53505ULL,
		0xA9FD715F71DDE6DBULL,
		0x3F63B64FFDCAA93CULL,
		0x4D04CF555AD4CA04ULL,
		0x7FC602B6F4002FE6ULL,
		0x79F21CED0C005686ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7210A31A1F6FCF00ULL,
		0xA596217BDA9A82FAULL,
		0xFEB8AFB8EEF36DACULL,
		0xB1DB27FEE5549E54ULL,
		0x8267AAAD6A65021FULL,
		0xE3015B7A0017F326ULL,
		0xF90E7686002B433FULL,
		0x000000000000003CULL
	}};
	shift = 7;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B33826C5B8FD87BULL,
		0xE6ED76CAC5A4B7F9ULL,
		0x80ABE7F44E0E82F9ULL,
		0x34616C383DD89919ULL,
		0x7523585B419CE8FAULL,
		0xEAA997D0530AC5E5ULL,
		0x4258CDEA5733D882ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D80000000000000ULL,
		0xFC9D99C1362DC7ECULL,
		0x7CF376BB6562D25BULL,
		0x8CC055F3FA270741ULL,
		0x7D1A30B61C1EEC4CULL,
		0xF2BA91AC2DA0CE74ULL,
		0x417554CBE8298562ULL,
		0x00212C66F52B99ECULL
	}};
	shift = 55;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x83BF74743B0516ECULL,
		0x8D3C135C6F60CD09ULL,
		0x7E0AD6A7BA85C6BDULL,
		0xD26FCF7D4DC37546ULL,
		0x743AB95B5D394513ULL,
		0x91C93DDC8E6BE20EULL,
		0xD2BF87DF5E503C42ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2DD80000000000ULL,
		0xC19A13077EE8E876ULL,
		0x0B8D7B1A7826B8DEULL,
		0x86EA8CFC15AD4F75ULL,
		0x728A27A4DF9EFA9BULL,
		0xD7C41CE87572B6BAULL,
		0xA0788523927BB91CULL,
		0x000001A57F0FBEBCULL
	}};
	shift = 41;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xED07CAAA3F8AF153ULL,
		0xBF501583D6ADB216ULL,
		0x1AB0B8A05E02BCEFULL,
		0x8571A680C7F5AF8AULL,
		0x59BEB124B6FEBAB6ULL,
		0x10638B6420976315ULL,
		0x87E16DAE892EDC04ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF15E2A6000000000ULL,
		0xD5B642DDA0F95547ULL,
		0xC0579DF7EA02B07AULL,
		0xFEB5F1435617140BULL,
		0xDFD756D0AE34D018ULL,
		0x12EC62AB37D62496ULL,
		0x25DB80820C716C84ULL,
		0x00000010FC2DB5D1ULL
	}};
	shift = 37;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6AA23ED5875EEC2EULL,
		0x7DD07DB6809293BEULL,
		0xC65ED658C97CE37DULL,
		0x177769F92348319AULL,
		0x89F3AF57F4C9B5ABULL,
		0xB3F4DE2A1DBBA9D7ULL,
		0x510D452E9431F0ABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5447DAB0EBDD85CULL,
		0xFBA0FB6D0125277CULL,
		0x8CBDACB192F9C6FAULL,
		0x2EEED3F246906335ULL,
		0x13E75EAFE9936B56ULL,
		0x67E9BC543B7753AFULL,
		0xA21A8A5D2863E157ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4CB4B1A065473D78ULL,
		0xFFB9E79C17225D15ULL,
		0xBF9B8F3DE3C78C4AULL,
		0xC9B8A6D9C70CB436ULL,
		0x781A7FDDE754C11BULL,
		0x71C5293F6B815B97ULL,
		0x64A5B5873982E164ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A39EBC00000000ULL,
		0x0B912E8AA65A58D0ULL,
		0xF1E3C6257FDCF3CEULL,
		0xE3865A1B5FCDC79EULL,
		0xF3AA608DE4DC536CULL,
		0xB5C0ADCBBC0D3FEEULL,
		0x9CC170B238E2949FULL,
		0x000000003252DAC3ULL
	}};
	shift = 31;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEB16FE2B855497F2ULL,
		0xEFB11E5BAC66254CULL,
		0x9BE04825978AF550ULL,
		0x997EA9182A787536ULL,
		0x7FEDA6DE87912408ULL,
		0x8EE1C722B6793DE8ULL,
		0x2D62C55CB0025FB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855497F200000000ULL,
		0xAC66254CEB16FE2BULL,
		0x978AF550EFB11E5BULL,
		0x2A7875369BE04825ULL,
		0x87912408997EA918ULL,
		0xB6793DE87FEDA6DEULL,
		0xB0025FB48EE1C722ULL,
		0x000000002D62C55CULL
	}};
	shift = 32;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x835098A4E241AC37ULL,
		0x6CD08406CBBD36CAULL,
		0x98C31AFB45CBD813ULL,
		0xB880F8881DB5FA67ULL,
		0x9876678D7A8CBC20ULL,
		0xC43CE7B0BA80270DULL,
		0xEDBD822180847A0EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149C483586E00000ULL,
		0x80D977A6D9506A13ULL,
		0x5F68B97B026D9A10ULL,
		0x1103B6BF4CF31863ULL,
		0xF1AF51978417101FULL,
		0xF6175004E1B30ECCULL,
		0x4430108F41D8879CULL,
		0x00000000001DB7B0ULL
	}};
	shift = 21;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4EBF5108F65F53A7ULL,
		0x382A3806BF0A7D24ULL,
		0xE671E3B2790D7CF3ULL,
		0xFAF892F9A5030041ULL,
		0x5C67D258441EF096ULL,
		0x7BD108B7FD85C648ULL,
		0xF322ADBF7A23C856ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08F65F53A7000000ULL,
		0x06BF0A7D244EBF51ULL,
		0xB2790D7CF3382A38ULL,
		0xF9A5030041E671E3ULL,
		0x58441EF096FAF892ULL,
		0xB7FD85C6485C67D2ULL,
		0xBF7A23C8567BD108ULL,
		0x0000000000F322ADULL
	}};
	shift = 24;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6D0CBEEDB3B24622ULL,
		0x3EAB8676EE72AB20ULL,
		0x34EA8CDDDCD235FCULL,
		0x0C9F26D2C95CAE3FULL,
		0xCE7254127A2A7008ULL,
		0x5E07FFB195660014ULL,
		0x09C31995FDE46D24ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x197DDB67648C4400ULL,
		0x570CEDDCE55640DAULL,
		0xD519BBB9A46BF87DULL,
		0x3E4DA592B95C7E69ULL,
		0xE4A824F454E01019ULL,
		0x0FFF632ACC00299CULL,
		0x86332BFBC8DA48BCULL,
		0x0000000000000013ULL
	}};
	shift = 9;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x88D564B87F5FCEECULL,
		0x18761D2054FC4F71ULL,
		0x7D54582F080AD2DEULL,
		0xD00BFA5EC2D5926BULL,
		0xFA123580DC2B8E94ULL,
		0xAB740409B11B73E9ULL,
		0x6082DE255C326C00ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD800000000000000ULL,
		0xE311AAC970FEBF9DULL,
		0xBC30EC3A40A9F89EULL,
		0xD6FAA8B05E1015A5ULL,
		0x29A017F4BD85AB24ULL,
		0xD3F4246B01B8571DULL,
		0x0156E808136236E7ULL,
		0x00C105BC4AB864D8ULL
	}};
	shift = 57;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC56A523FC8A28D0AULL,
		0xC8ABA1580065AC8FULL,
		0x907B04E6FD68CB10ULL,
		0xD5D3B610A247FAC8ULL,
		0x1D4628012A1EC26BULL,
		0x49E3A2F585579126ULL,
		0xCE728F2A6D739803ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF91451A140000000ULL,
		0x000CB591F8AD4A47ULL,
		0xDFAD19621915742BULL,
		0x1448FF59120F609CULL,
		0x2543D84D7ABA76C2ULL,
		0xB0AAF224C3A8C500ULL,
		0x4DAE7300693C745EULL,
		0x0000000019CE51E5ULL
	}};
	shift = 29;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x87889D96D694EEC2ULL,
		0xA29E75FB0C918409ULL,
		0x45F3A08722885028ULL,
		0x8EBA717E1A6FCBD5ULL,
		0xF89E29F375D4FFF2ULL,
		0xB2A4CD6B377F19F6ULL,
		0x22F5F5915F89087DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B2DAD29DD84000ULL,
		0xCEBF6192308130F1ULL,
		0x7410E4510A051453ULL,
		0x4E2FC34DF97AA8BEULL,
		0xC53E6EBA9FFE51D7ULL,
		0x99AD66EFE33EDF13ULL,
		0xBEB22BF1210FB654ULL,
		0x000000000000045EULL
	}};
	shift = 13;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFCB06C56DAED36C0ULL,
		0xA1B120184F78B11AULL,
		0x91F630BFC6716097ULL,
		0xD3BBD844502B3670ULL,
		0xA55F421CBA1D121CULL,
		0x5BCE4A546A986D3EULL,
		0xB50665AE621DA3BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6BF2C1B15B6BB4DBULL,
		0x5E86C480613DE2C4ULL,
		0xC247D8C2FF19C582ULL,
		0x734EEF611140ACD9ULL,
		0xFA957D0872E87448ULL,
		0xFD6F392951AA61B4ULL,
		0x02D41996B988768EULL
	}};
	shift = 58;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x43101C8616E12043ULL,
		0xB1B79009F06EEB97ULL,
		0x2E21BB7DC715CF9AULL,
		0xC016CE0883973E2BULL,
		0x7DE3E5A4F47C98B0ULL,
		0x8897E5939D1650EBULL,
		0xDBBBA0BCE43DEF9FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8616E12043000000ULL,
		0x09F06EEB9743101CULL,
		0x7DC715CF9AB1B790ULL,
		0x0883973E2B2E21BBULL,
		0xA4F47C98B0C016CEULL,
		0x939D1650EB7DE3E5ULL,
		0xBCE43DEF9F8897E5ULL,
		0x0000000000DBBBA0ULL
	}};
	shift = 24;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4F3AA729138B6CA7ULL,
		0x32AF5B772F4BC1D4ULL,
		0xDB2427FFFD16991AULL,
		0x514594289DEC9FBBULL,
		0x17A51DBC9C355311ULL,
		0x53958C0ED25C4EFAULL,
		0xBADFD6383A737051ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD94E000000000000ULL,
		0x83A89E754E522716ULL,
		0x3234655EB6EE5E97ULL,
		0x3F77B6484FFFFA2DULL,
		0xA622A28B28513BD9ULL,
		0x9DF42F4A3B79386AULL,
		0xE0A2A72B181DA4B8ULL,
		0x000175BFAC7074E6ULL
	}};
	shift = 49;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE99D0FC907F453B4ULL,
		0xBE02CE5EEABCA2ADULL,
		0x3CE3035DB1B1F2C3ULL,
		0xEA407AA649DC7FCCULL,
		0x20C7064CF03B1CFCULL,
		0x6C439D997F062916ULL,
		0x512AAE4CF865CED6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33A1F920FE8A768ULL,
		0x7C059CBDD579455BULL,
		0x79C606BB6363E587ULL,
		0xD480F54C93B8FF98ULL,
		0x418E0C99E07639F9ULL,
		0xD8873B32FE0C522CULL,
		0xA2555C99F0CB9DACULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA9638DDFE3226855ULL,
		0xA86F11D584D1974DULL,
		0xE51EB91FA8A6AB79ULL,
		0x2C272555D54016E0ULL,
		0x0442DED1BA7D0671ULL,
		0xAD8AD06E256A8D6CULL,
		0x34E315BF832525A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDFE322685500000ULL,
		0x1D584D1974DA9638ULL,
		0x91FA8A6AB79A86F1ULL,
		0x555D54016E0E51EBULL,
		0xED1BA7D06712C272ULL,
		0x06E256A8D6C0442DULL,
		0x5BF832525A6AD8ADULL,
		0x0000000000034E31ULL
	}};
	shift = 20;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6ABC5B4CBBF39061ULL,
		0x43FF5FCC5057582EULL,
		0x25D49B1497812E68ULL,
		0xE3A2BEA4D80A9B74ULL,
		0x85D477A49E81903BULL,
		0x9ECE870272301FA5ULL,
		0x0938789382556A67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8308000000000000ULL,
		0xC17355E2DA65DF9CULL,
		0x73421FFAFE6282BAULL,
		0xDBA12EA4D8A4BC09ULL,
		0x81DF1D15F526C054ULL,
		0xFD2C2EA3BD24F40CULL,
		0x533CF67438139180ULL,
		0x000049C3C49C12ABULL
	}};
	shift = 51;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x061BFCAA71A33853ULL,
		0x7602E51483FCC722ULL,
		0xC63D472D5B25D497ULL,
		0x9E6CE1E56122A1B7ULL,
		0x0899EF07925E6689ULL,
		0x128E6BBBD9B24D46ULL,
		0x8B2CCEA683E2E8B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68CE14C00000000ULL,
		0x0FF31C88186FF2A9ULL,
		0x6C97525DD80B9452ULL,
		0x848A86DF18F51CB5ULL,
		0x49799A2679B38795ULL,
		0x66C935182267BC1EULL,
		0x0F8BA2E04A39AEEFULL,
		0x000000022CB33A9AULL
	}};
	shift = 34;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x47C4C61FF48CFC14ULL,
		0xD18D2F9CF25AEF80ULL,
		0xEF24B6D5D257D003ULL,
		0x490E3E1287D73A51ULL,
		0x012B4BFCD4A27057ULL,
		0x0E4D9806EF402306ULL,
		0x63C0F26E7FE441EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF48CFC14000000ULL,
		0x9CF25AEF8047C4C6ULL,
		0xD5D257D003D18D2FULL,
		0x1287D73A51EF24B6ULL,
		0xFCD4A27057490E3EULL,
		0x06EF402306012B4BULL,
		0x6E7FE441EF0E4D98ULL,
		0x000000000063C0F2ULL
	}};
	shift = 24;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x50E0397E7E0FD213ULL,
		0x69482E3B0955995BULL,
		0x7D17B44557EB1776ULL,
		0x049532B678CD83EBULL,
		0xC4352220CBC7369AULL,
		0x824D9C7D3461DE99ULL,
		0xDC1CA9C0890CF423ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9800000000000000ULL,
		0xDA8701CBF3F07E90ULL,
		0xB34A4171D84AACCAULL,
		0x5BE8BDA22ABF58BBULL,
		0xD024A995B3C66C1FULL,
		0xCE21A911065E39B4ULL,
		0x1C126CE3E9A30EF4ULL,
		0x06E0E54E044867A1ULL
	}};
	shift = 59;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4EE904322C2283D3ULL,
		0xBB0D5C078A8FCC6CULL,
		0xDE162F6A699E2C28ULL,
		0xBCCBBD486FCC9480ULL,
		0x633500C7BC1738A9ULL,
		0xFC825BB397828B92ULL,
		0x2B51B8E03FEA4398ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61141E9800000000ULL,
		0x547E636277482191ULL,
		0x4CF16145D86AE03CULL,
		0x7E64A406F0B17B53ULL,
		0xE0B9C54DE65DEA43ULL,
		0xBC145C9319A8063DULL,
		0xFF521CC7E412DD9CULL,
		0x000000015A8DC701ULL
	}};
	shift = 35;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEA8A540D89C47C09ULL,
		0xC99CD6DB96841F50ULL,
		0xCA1975CB835B3F5EULL,
		0x8E4040724825D083ULL,
		0x7A52E6942652B303ULL,
		0xADEE6BBAE8581142ULL,
		0xE7A57171C85E4516ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362711F024000000ULL,
		0x6E5A107D43AA2950ULL,
		0x2E0D6CFD7B26735BULL,
		0xC92097420F2865D7ULL,
		0x50994ACC0E390101ULL,
		0xEBA1604509E94B9AULL,
		0xC72179145AB7B9AEULL,
		0x00000000039E95C5ULL
	}};
	shift = 26;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x23D4CDF01B6D9222ULL,
		0x9F78A76537F7CB19ULL,
		0xF81FE41787FF1EDFULL,
		0xBCE031DE7E7E065CULL,
		0x16AEAEE747A52E94ULL,
		0xF363271C50B13A27ULL,
		0xCF8D42DE2B6CEFE9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F5337C06DB64888ULL,
		0x7DE29D94DFDF2C64ULL,
		0xE07F905E1FFC7B7EULL,
		0xF380C779F9F81973ULL,
		0x5ABABB9D1E94BA52ULL,
		0xCD8C9C7142C4E89CULL,
		0x3E350B78ADB3BFA7ULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD9252E81AF8A3F6EULL,
		0x8AD810B1DB81FCFFULL,
		0x7F64652A133F5D26ULL,
		0x4F74EBA6C3EE4463ULL,
		0x6EC13923D151EBE8ULL,
		0xB53F99F1280550D2ULL,
		0x0231810955334B5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xFB24A5D035F147EDULL,
		0xD15B02163B703F9FULL,
		0x6FEC8CA54267EBA4ULL,
		0x09EE9D74D87DC88CULL,
		0x4DD827247A2A3D7DULL,
		0x76A7F33E2500AA1AULL,
		0x004630212AA6696BULL
	}};
	shift = 61;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAA957D6B3946BE7FULL,
		0x1C1B67B74EA5607FULL,
		0x1FD75607CBCA57DFULL,
		0xD9F0EFBB0024499BULL,
		0x1B934FA83A98DE40ULL,
		0xA72C8198A9EFEE5CULL,
		0xB2C21CE0417C6E5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728D7CFE00000000ULL,
		0x9D4AC0FF552AFAD6ULL,
		0x9794AFBE3836CF6EULL,
		0x004893363FAEAC0FULL,
		0x7531BC81B3E1DF76ULL,
		0x53DFDCB837269F50ULL,
		0x82F8DCB94E590331ULL,
		0x00000001658439C0ULL
	}};
	shift = 33;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBC8CBFB6EF53FFA1ULL,
		0xEE0538308EDC2D5FULL,
		0xB380B7FBEF6980FBULL,
		0x94C9BFF97FCB6C1BULL,
		0x0BD4E628B82EA5F5ULL,
		0x1AF850337E03893FULL,
		0x2F009B6EDA17D451ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB77A9FFD080000ULL,
		0xC18476E16AFDE465ULL,
		0xBFDF7B4C07DF7029ULL,
		0xFFCBFE5B60DD9C05ULL,
		0x3145C1752FACA64DULL,
		0x819BF01C49F85EA7ULL,
		0xDB76D0BEA288D7C2ULL,
		0x0000000000017804ULL
	}};
	shift = 19;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x791B3330961CE06FULL,
		0x4BCC5CECF50D180CULL,
		0x71C60FC1FCD2893CULL,
		0x0DE52547BAEBC462ULL,
		0x1E0BA3AF76BBCB70ULL,
		0x993C897996D57141ULL,
		0xE612AC2CE1E5336BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCCC2587381BC000ULL,
		0x173B3D4346031E46ULL,
		0x83F07F34A24F12F3ULL,
		0x4951EEBAF1189C71ULL,
		0xE8EBDDAEF2DC0379ULL,
		0x225E65B55C504782ULL,
		0xAB0B38794CDAE64FULL,
		0x0000000000003984ULL
	}};
	shift = 14;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB73AD1E22638C44CULL,
		0x6BE70BD2F5DF9BA8ULL,
		0x48D9C6150CA7C7F0ULL,
		0x3E0F79BCBFF440CFULL,
		0xE6238AB2285F6C2FULL,
		0xB7046575745924B2ULL,
		0x06F3586C6BF55C83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1131C62260000000ULL,
		0x97AEFCDD45B9D68FULL,
		0xA8653E3F835F385EULL,
		0xE5FFA2067A46CE30ULL,
		0x9142FB6179F07BCDULL,
		0xABA2C92597311C55ULL,
		0x635FAAE41DB8232BULL,
		0x0000000000379AC3ULL
	}};
	shift = 27;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x87355C75C12AACF9ULL,
		0x3B932B427794EB57ULL,
		0xF2B5BA8AE219E153ULL,
		0x4E7E8875BC0C20FBULL,
		0x4BA7B9C8B88152F3ULL,
		0xEB985726C4C84161ULL,
		0x14EAC2CA81F570D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF90000000000000ULL,
		0xB5787355C75C12AAULL,
		0x1533B932B427794EULL,
		0x0FBF2B5BA8AE219EULL,
		0x2F34E7E8875BC0C2ULL,
		0x1614BA7B9C8B8815ULL,
		0x0D4EB985726C4C84ULL,
		0x00014EAC2CA81F57ULL
	}};
	shift = 52;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEE56A2C59DF6D90DULL,
		0xE8CA24B1217DFE11ULL,
		0x9D37441584B8C5A6ULL,
		0xE5E111EEEA232BA0ULL,
		0x92F2E70572870FD9ULL,
		0xF06088AD21C24B3AULL,
		0x3E6B482303AE6D3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xF72B5162CEFB6C86ULL,
		0x7465125890BEFF08ULL,
		0x4E9BA20AC25C62D3ULL,
		0xF2F088F7751195D0ULL,
		0x49797382B94387ECULL,
		0xF830445690E1259DULL,
		0x1F35A41181D7369DULL
	}};
	shift = 63;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7C1A0C67DCE041FBULL,
		0xA948899ADA6116ACULL,
		0xCCF4EF8415BC1325ULL,
		0x3227758C5FB478BCULL,
		0x37FBBB63A9543883ULL,
		0x50666D720A222631ULL,
		0xE82BEED1C89A57DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D0633EE7020FD80ULL,
		0xA444CD6D308B563EULL,
		0x7A77C20ADE0992D4ULL,
		0x13BAC62FDA3C5E66ULL,
		0xFDDDB1D4AA1C4199ULL,
		0x3336B9051113189BULL,
		0x15F768E44D2BEF28ULL,
		0x0000000000000074ULL
	}};
	shift = 7;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFBD00B952FEBB6EDULL,
		0x4485A00981470D60ULL,
		0x11C8B6393B181FACULL,
		0x0902D5923F481FA3ULL,
		0xA485988D27A33DDDULL,
		0x5C42DD9D963026C9ULL,
		0xD760550FCACF866FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ED0000000000000ULL,
		0xD60FBD00B952FEBBULL,
		0xFAC4485A00981470ULL,
		0xFA311C8B6393B181ULL,
		0xDDD0902D5923F481ULL,
		0x6C9A485988D27A33ULL,
		0x66F5C42DD9D96302ULL,
		0x000D760550FCACF8ULL
	}};
	shift = 52;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9CC7E4B8CC9D2235ULL,
		0xFEA0FD1FB9796806ULL,
		0x46C6B806E44D410BULL,
		0x8CA849185ED2CBD7ULL,
		0xA61482BC8B7A9B76ULL,
		0x848F2D45FF3CD129ULL,
		0x3A4977D4B76B40BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D22350000000000ULL,
		0x7968069CC7E4B8CCULL,
		0x4D410BFEA0FD1FB9ULL,
		0xD2CBD746C6B806E4ULL,
		0x7A9B768CA849185EULL,
		0x3CD129A61482BC8BULL,
		0x6B40BE848F2D45FFULL,
		0x0000003A4977D4B7ULL
	}};
	shift = 40;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3A16D0EBF1009CC0ULL,
		0x944F26C482DEE10DULL,
		0xD206A7EBE1F59061ULL,
		0x5D8D7753986264C4ULL,
		0xBE6FC87AF71760B0ULL,
		0xFEB8A83894079036ULL,
		0xBFDC24006F1C0FD1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E6000000000000ULL,
		0xF70869D0B6875F88ULL,
		0xAC830CA279362416ULL,
		0x13262690353F5F0FULL,
		0xBB0582EC6BBA9CC3ULL,
		0x3C81B5F37E43D7B8ULL,
		0xE07E8FF5C541C4A0ULL,
		0x000005FEE1200378ULL
	}};
	shift = 43;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2975E63A383E2F0BULL,
		0xAB56A353D760A1B8ULL,
		0x22FAEC00BE9B454DULL,
		0xAB4A4EC60734D9F5ULL,
		0x15D7394B6BAABD57ULL,
		0xDD2DDF2B02209F3EULL,
		0x8DB077250A96673DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B00000000000000ULL,
		0xB82975E63A383E2FULL,
		0x4DAB56A353D760A1ULL,
		0xF522FAEC00BE9B45ULL,
		0x57AB4A4EC60734D9ULL,
		0x3E15D7394B6BAABDULL,
		0x3DDD2DDF2B02209FULL,
		0x008DB077250A9667ULL
	}};
	shift = 56;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2970FDB281F89650ULL,
		0x097CB25EE9DA929FULL,
		0x7C4B34933EB5ADBDULL,
		0xCCCD532D4D14F438ULL,
		0x9DA9F2F331352B66ULL,
		0x92C1389D04A578E2ULL,
		0x72C6F0BD0E2028F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C3F6CA07E259400ULL,
		0x5F2C97BA76A4A7CAULL,
		0x12CD24CFAD6B6F42ULL,
		0x3354CB53453D0E1FULL,
		0x6A7CBCCC4D4AD9B3ULL,
		0xB04E2741295E38A7ULL,
		0xB1BC2F43880A3E24ULL,
		0x000000000000001CULL
	}};
	shift = 6;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC8B4E7D58F554722ULL,
		0x2AAA16620C05C080ULL,
		0x149172D83594C7BFULL,
		0xAE5617C43B42B2CDULL,
		0xFE28206AAB507B3FULL,
		0xBDDB9C9773EDB7EEULL,
		0xECA5C36454C5C65FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F563D551C88000ULL,
		0x859883017020322DULL,
		0x5CB60D6531EFCAAAULL,
		0x85F10ED0ACB34524ULL,
		0x081AAAD41ECFEB95ULL,
		0xE725DCFB6DFBBF8AULL,
		0x70D915317197EF76ULL,
		0x0000000000003B29ULL
	}};
	shift = 14;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8CF6BCDABE255E5BULL,
		0x1C27E7069488E1D8ULL,
		0x39DC8D4522CFD3DDULL,
		0xA2DA0949A3A07EA9ULL,
		0xE77D6805C7255AD5ULL,
		0xD400D1FDBEC3ED90ULL,
		0x6FA505E56B502454ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF36AF895796C0000ULL,
		0x9C1A5223876233DAULL,
		0x35148B3F4F74709FULL,
		0x25268E81FAA4E772ULL,
		0xA0171C956B568B68ULL,
		0x47F6FB0FB6439DF5ULL,
		0x1795AD4091535003ULL,
		0x000000000001BE94ULL
	}};
	shift = 18;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF3B78088B342634BULL,
		0xE610FE9B55DF1DBDULL,
		0x08CBB0F41B43864AULL,
		0x18E3C8FD64DD26F7ULL,
		0xD439EBFC75D90CB8ULL,
		0xA470D2C49724A55EULL,
		0xD93A3FC89AD2F12CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A58000000000000ULL,
		0xEDEF9DBC04459A13ULL,
		0x32573087F4DAAEF8ULL,
		0x37B8465D87A0DA1CULL,
		0x65C0C71E47EB26E9ULL,
		0x2AF6A1CF5FE3AEC8ULL,
		0x896523869624B925ULL,
		0x0006C9D1FE44D697ULL
	}};
	shift = 51;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA29B5814A87D304DULL,
		0x15A283FBF9211A25ULL,
		0x7633A0C0AECE9D31ULL,
		0x5CCF07829F92854BULL,
		0x5A25D2E6CE9A5C9DULL,
		0x1DDAAE03D236250AULL,
		0x3757111CE11AD34CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8268000000000000ULL,
		0xD12D14DAC0A543E9ULL,
		0xE988AD141FDFC908ULL,
		0x2A5BB19D06057674ULL,
		0xE4EAE6783C14FC94ULL,
		0x2852D12E973674D2ULL,
		0x9A60EED5701E91B1ULL,
		0x0001BAB888E708D6ULL
	}};
	shift = 51;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0B244A7C9DDBDF76ULL,
		0x9AD41D30DC554E3BULL,
		0x69B85CCA58B2DE16ULL,
		0x04CA060A9466516CULL,
		0x8676B7E7B8E52A12ULL,
		0xFF25ACD5AAEBF07CULL,
		0xD25B41853A485DF4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0xD8592253E4EEDEFBULL,
		0xB4D6A0E986E2AA71ULL,
		0x634DC2E652C596F0ULL,
		0x9026503054A3328BULL,
		0xE433B5BF3DC72950ULL,
		0xA7F92D66AD575F83ULL,
		0x0692DA0C29D242EFULL
	}};
	shift = 59;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEC2F2ABD3B4115E6ULL,
		0x8AD655D6ABCACB47ULL,
		0x424AB757F2CDBDDEULL,
		0xF8691C15E768D6C7ULL,
		0x8E91CF25EDB6788EULL,
		0x6A8C1A32B92B0695ULL,
		0x0F3571C56B445354ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED04579800000000ULL,
		0xAF2B2D1FB0BCAAF4ULL,
		0xCB36F77A2B59575AULL,
		0x9DA35B1D092ADD5FULL,
		0xB6D9E23BE1A47057ULL,
		0xE4AC1A563A473C97ULL,
		0xAD114D51AA3068CAULL,
		0x000000003CD5C715ULL
	}};
	shift = 34;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCAF8C861C1B0742BULL,
		0x229339B82E4B604FULL,
		0x41F1F5D676BC540FULL,
		0x5C719F6E6E85B968ULL,
		0x243F31F64A3CA495ULL,
		0x2FEDC302D0914C48ULL,
		0x11C339B6E8F3F03BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0742B000000000ULL,
		0xE4B604FCAF8C861CULL,
		0x6BC540F229339B82ULL,
		0xE85B96841F1F5D67ULL,
		0xA3CA4955C719F6E6ULL,
		0x0914C48243F31F64ULL,
		0x8F3F03B2FEDC302DULL,
		0x000000011C339B6EULL
	}};
	shift = 36;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD3F70E202DC49973ULL,
		0x51E4A5AC76DD9B5DULL,
		0x594996F776BC9B82ULL,
		0x1E1F08C16A2571E3ULL,
		0x1F8EEB4CFA04F5DCULL,
		0xD0B6F0BDB96DA508ULL,
		0x719D969435BD3764ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F70E202DC499730ULL,
		0x1E4A5AC76DD9B5DDULL,
		0x94996F776BC9B825ULL,
		0xE1F08C16A2571E35ULL,
		0xF8EEB4CFA04F5DC1ULL,
		0x0B6F0BDB96DA5081ULL,
		0x19D969435BD3764DULL,
		0x0000000000000007ULL
	}};
	shift = 4;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7451E7E629C44298ULL,
		0x384F4A95C59A7C4DULL,
		0x85F472EE67B20FB4ULL,
		0x61733A07C255C66CULL,
		0x65D595E282BE50E7ULL,
		0xE0A90117504A6D99ULL,
		0xB2FD993BB70C410EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAE8A3CFCC5388853ULL,
		0x8709E952B8B34F89ULL,
		0x90BE8E5DCCF641F6ULL,
		0xEC2E6740F84AB8CDULL,
		0x2CBAB2BC5057CA1CULL,
		0xDC152022EA094DB3ULL,
		0x165FB32776E18821ULL
	}};
	shift = 61;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x87A52F5D5EEDE075ULL,
		0xACE1D52E8FFC6139ULL,
		0x2E24A637D47CCCC0ULL,
		0x9184919EA304636FULL,
		0xA401F8A956325C88ULL,
		0xEBAC45AACAF999D7ULL,
		0x7119B7EC4C58E299ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC0EA00000000000ULL,
		0x8C2730F4A5EBABDDULL,
		0x9998159C3AA5D1FFULL,
		0x8C6DE5C494C6FA8FULL,
		0x4B9112309233D460ULL,
		0x333AF4803F152AC6ULL,
		0x1C533D7588B5595FULL,
		0x00000E2336FD898BULL
	}};
	shift = 45;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x31D44C696F0135DAULL,
		0xE669330287F0F381ULL,
		0xDB276194CF06B033ULL,
		0x30EBC52B9EC1DA09ULL,
		0x05367CB98DBEBB45ULL,
		0x11926AB18AC94EBBULL,
		0x12B0CACB3B3A5978ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135DA00000000000ULL,
		0x0F38131D44C696F0ULL,
		0x6B033E669330287FULL,
		0x1DA09DB276194CF0ULL,
		0xEBB4530EBC52B9ECULL,
		0x94EBB05367CB98DBULL,
		0xA597811926AB18ACULL,
		0x0000012B0CACB3B3ULL
	}};
	shift = 44;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B40AFCE635625D7ULL,
		0xA4985D1381C50F03ULL,
		0x24C6851803F7B7BCULL,
		0x196528DF38F4AC61ULL,
		0xBF4C680B5702A1B2ULL,
		0x95AF8DC22AD7AFB4ULL,
		0xABFAD0EE0E1B80C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40AFCE635625D700ULL,
		0x985D1381C50F033BULL,
		0xC6851803F7B7BCA4ULL,
		0x6528DF38F4AC6124ULL,
		0x4C680B5702A1B219ULL,
		0xAF8DC22AD7AFB4BFULL,
		0xFAD0EE0E1B80C595ULL,
		0x00000000000000ABULL
	}};
	shift = 8;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7EEFA1DBCC311BBDULL,
		0x3AF568150558E6F3ULL,
		0x2358C3D65B09D329ULL,
		0xC94B2A1FC7A21CC7ULL,
		0x4BE80167BE727629ULL,
		0xB53DDE50E9294BBDULL,
		0xE6F3C7DA9375AC32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30C46EF400000000ULL,
		0x15639BCDFBBE876FULL,
		0x6C274CA4EBD5A054ULL,
		0x1E88731C8D630F59ULL,
		0xF9C9D8A7252CA87FULL,
		0xA4A52EF52FA0059EULL,
		0x4DD6B0CAD4F77943ULL,
		0x000000039BCF1F6AULL
	}};
	shift = 34;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC227C0282DDFC595ULL,
		0x10F1ACF5CCEBD89FULL,
		0x2B27F11C6CEDC260ULL,
		0xD1FFDF3EB1FC86E7ULL,
		0xAF5A8589982372F0ULL,
		0xDB657736350F92ADULL,
		0x8B2C8E288B7E5233ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B77F16540000000ULL,
		0x733AF627F089F00AULL,
		0x1B3B7098043C6B3DULL,
		0xAC7F21B9CAC9FC47ULL,
		0x6608DCBC347FF7CFULL,
		0x8D43E4AB6BD6A162ULL,
		0x22DF948CF6D95DCDULL,
		0x0000000022CB238AULL
	}};
	shift = 30;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9A6FA30C4D2F70F9ULL,
		0x333801ECA7E8C933ULL,
		0x7BDA032FA991F9B4ULL,
		0x17CFB29811216203ULL,
		0x121CA653FCB357A2ULL,
		0x52179F425C7EB444ULL,
		0x4902B15DE413A432ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF200000000000000ULL,
		0x6734DF46189A5EE1ULL,
		0x68667003D94FD192ULL,
		0x06F7B4065F5323F3ULL,
		0x442F9F65302242C4ULL,
		0x8824394CA7F966AFULL,
		0x64A42F3E84B8FD68ULL,
		0x00920562BBC82748ULL
	}};
	shift = 57;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x338593FC9C76F49EULL,
		0xB3B6AFCD2CDD3B3FULL,
		0x2419FC5E48CE3390ULL,
		0x16CCFF401B9E3C79ULL,
		0xF7E2858C1ED2FCE3ULL,
		0xF7C03501F237BCA2ULL,
		0xE957A213B807B356ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF271DBD278000000ULL,
		0x34B374ECFCCE164FULL,
		0x792338CE42CEDABFULL,
		0x006E78F1E49067F1ULL,
		0x307B4BF38C5B33FDULL,
		0x07C8DEF28BDF8A16ULL,
		0x4EE01ECD5BDF00D4ULL,
		0x0000000003A55E88ULL
	}};
	shift = 26;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE1CA41156E6430A0ULL,
		0xBBD629EF55988E53ULL,
		0xD0F054FA8E387994ULL,
		0xB023661F8745F183ULL,
		0xACAECC5CAFB7E368ULL,
		0x412908FC1A52145FULL,
		0x112912B072E995E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x455B990C28000000ULL,
		0x7BD5662394F87290ULL,
		0x3EA38E1E652EF58AULL,
		0x87E1D17C60F43C15ULL,
		0x172BEDF8DA2C08D9ULL,
		0x3F06948517EB2BB3ULL,
		0xAC1CBA6578504A42ULL,
		0x0000000000044A44ULL
	}};
	shift = 22;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1D54D200E18FCD2EULL,
		0xEEA7856AD1CD0742ULL,
		0xADACDE912EA16519ULL,
		0xB01F1F6DCBEAF7E0ULL,
		0xE66A2234F75EC69FULL,
		0x3D95D68FED19E5D2ULL,
		0xE8C02E4156DB40E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x43AA9A401C31F9A5ULL,
		0x3DD4F0AD5A39A0E8ULL,
		0x15B59BD225D42CA3ULL,
		0xF603E3EDB97D5EFCULL,
		0x5CCD44469EEBD8D3ULL,
		0xE7B2BAD1FDA33CBAULL,
		0x1D1805C82ADB681CULL
	}};
	shift = 61;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD06DF5BA158658C6ULL,
		0x9E6FA6AAFFC6A55AULL,
		0xED78F065ECC75DE5ULL,
		0x7C4F389189A5A3D9ULL,
		0x17EA2832F23B4B0BULL,
		0xF259F3F8084EF6C7ULL,
		0xB4EE070DEBDCB4DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C6300000000000ULL,
		0x352AD6836FADD0ACULL,
		0x3AEF2CF37D3557FEULL,
		0x2D1ECF6BC7832F66ULL,
		0xDA585BE279C48C4DULL,
		0x77B638BF51419791ULL,
		0xE5A6FF92CF9FC042ULL,
		0x000005A770386F5EULL
	}};
	shift = 43;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x04DA868261B0FB84ULL,
		0x94C72DFA846B2650ULL,
		0x53226511CA63C484ULL,
		0x458E90870A0D9604ULL,
		0xFE96F02E7CC6E748ULL,
		0xDCB54B19D74CCF33ULL,
		0x7F4688FD173C7804ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7080000000000000ULL,
		0xCA009B50D04C361FULL,
		0x909298E5BF508D64ULL,
		0xC08A644CA2394C78ULL,
		0xE908B1D210E141B2ULL,
		0xE67FD2DE05CF98DCULL,
		0x009B96A9633AE999ULL,
		0x000FE8D11FA2E78FULL
	}};
	shift = 53;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7563141DD41868F5ULL,
		0x1BF9D81DB6F17413ULL,
		0x3939E34B13341F6EULL,
		0x65661410C4EF6713ULL,
		0xED2B8D257BC4D3E7ULL,
		0xCC0C7D57167F9325ULL,
		0x82D0A7C1F92E1C7FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D4000000000000ULL,
		0xD04DD58C50775061ULL,
		0x7DB86FE76076DBC5ULL,
		0x9C4CE4E78D2C4CD0ULL,
		0x4F9D9598504313BDULL,
		0x4C97B4AE3495EF13ULL,
		0x71FF3031F55C59FEULL,
		0x00020B429F07E4B8ULL
	}};
	shift = 50;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3DDB4DC3EEFFEA87ULL,
		0x6858B60CB2D652D4ULL,
		0xDB960D2410396701ULL,
		0xD2D02826ECAD983DULL,
		0x218FEE4106994563ULL,
		0xD96A083F034A7579ULL,
		0xED17AF1F66587051ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7000000000000000ULL,
		0x43DDB4DC3EEFFEA8ULL,
		0x16858B60CB2D652DULL,
		0xDDB960D241039670ULL,
		0x3D2D02826ECAD983ULL,
		0x9218FEE410699456ULL,
		0x1D96A083F034A757ULL,
		0x0ED17AF1F6658705ULL
	}};
	shift = 60;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x28F1D2B1451B7F5AULL,
		0x4249CDA6942E3891ULL,
		0xBDBD61C99D748E66ULL,
		0xF1DD5A2612CFF6E3ULL,
		0xF7C4F5D0D0FF2417ULL,
		0xF5607363BCFCE250ULL,
		0x257C0AFA1A1BC965ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5628A36FEB40000ULL,
		0x9B4D285C712251E3ULL,
		0xC3933AE91CCC8493ULL,
		0xB44C259FEDC77B7AULL,
		0xEBA1A1FE482FE3BAULL,
		0xE6C779F9C4A1EF89ULL,
		0x15F4343792CBEAC0ULL,
		0x0000000000004AF8ULL
	}};
	shift = 17;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0DCD61E16A114C3BULL,
		0x5AFB4720AF513439ULL,
		0xD8353AAFAB79E9A0ULL,
		0x8E1FA4BD21BB186AULL,
		0xD63749A9A0443621ULL,
		0xF9B4F94FE8915E19ULL,
		0x687FD02EAEAD3E79ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A84530EC0000000ULL,
		0x2BD44D0E43735878ULL,
		0xEADE7A6816BED1C8ULL,
		0x486EC61AB60D4EABULL,
		0x68110D886387E92FULL,
		0xFA245786758DD26AULL,
		0xABAB4F9E7E6D3E53ULL,
		0x000000001A1FF40BULL
	}};
	shift = 30;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC92A47AF45A48C4AULL,
		0xB0134BB8DA1319CDULL,
		0x6548F8144C04F240ULL,
		0x0B7BDF94ACFD7CBCULL,
		0x5479DBA0C149F766ULL,
		0xB47E199A177B8978ULL,
		0x67010B151427318BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AF45A48C4A0000ULL,
		0x4BB8DA1319CDC92AULL,
		0xF8144C04F240B013ULL,
		0xDF94ACFD7CBC6548ULL,
		0xDBA0C149F7660B7BULL,
		0x199A177B89785479ULL,
		0x0B151427318BB47EULL,
		0x0000000000006701ULL
	}};
	shift = 16;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD3A289A61559019EULL,
		0xDC20FB3E40D3FF89ULL,
		0xB33C984C5FB560ADULL,
		0x0A93392C64B44F76ULL,
		0x032488FAE018C110ULL,
		0x8743676BAC9930DFULL,
		0x5C7845B2156A4F0DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD144D30AAC80CF00ULL,
		0x107D9F2069FFC4E9ULL,
		0x9E4C262FDAB056EEULL,
		0x499C96325A27BB59ULL,
		0x92447D700C608805ULL,
		0xA1B3B5D64C986F81ULL,
		0x3C22D90AB52786C3ULL,
		0x000000000000002EULL
	}};
	shift = 7;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD0293F83E7D12135ULL,
		0x098B54CC2D65237FULL,
		0x495DC89BB9B337C6ULL,
		0x7E6DEC5864AE1C0FULL,
		0x248F30D71F180B14ULL,
		0x55AB9343012147B1ULL,
		0xF2AE8F7409112424ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E7D12135000000ULL,
		0xCC2D65237FD0293FULL,
		0x9BB9B337C6098B54ULL,
		0x5864AE1C0F495DC8ULL,
		0xD71F180B147E6DECULL,
		0x43012147B1248F30ULL,
		0x740911242455AB93ULL,
		0x0000000000F2AE8FULL
	}};
	shift = 24;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFF42625FDA2EEA7BULL,
		0x86E12F3218CE4953ULL,
		0x5545B2B6363E62F4ULL,
		0xAF9E6C2AD04DF46AULL,
		0xA5F81646B990DF2AULL,
		0x3CF99C42FE5F2B26ULL,
		0x94A0442898953D71ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x753D800000000000ULL,
		0x24A9FFA1312FED17ULL,
		0x317A437097990C67ULL,
		0xFA352AA2D95B1B1FULL,
		0x6F9557CF36156826ULL,
		0x959352FC0B235CC8ULL,
		0x9EB89E7CCE217F2FULL,
		0x00004A5022144C4AULL
	}};
	shift = 47;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9CE32C5A5CCCDB39ULL,
		0x8968EE72CBA30431ULL,
		0x6EA3B66BE56B63B7ULL,
		0x6FBF05A7C7F3D6E3ULL,
		0xAC9F642109CB7F32ULL,
		0xBA9D9B8CE50DBAD5ULL,
		0x351E1C7B75D487DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B999B6720000000ULL,
		0x59746086339C658BULL,
		0x7CAD6C76F12D1DCEULL,
		0xF8FE7ADC6DD476CDULL,
		0x21396FE64DF7E0B4ULL,
		0x9CA1B75AB593EC84ULL,
		0x6EBA90FBD753B371ULL,
		0x0000000006A3C38FULL
	}};
	shift = 29;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5D1BA57886C943CBULL,
		0x359FA185CAAF581DULL,
		0x4D003D3AEE146B25ULL,
		0x16F0F39915FEB071ULL,
		0xC4C96E74BF4F54C6ULL,
		0xBAFA9E3FE1A8D6BCULL,
		0x4A14BCB579EDADA9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8796000000000000ULL,
		0xB03ABA374AF10D92ULL,
		0xD64A6B3F430B955EULL,
		0x60E29A007A75DC28ULL,
		0xA98C2DE1E7322BFDULL,
		0xAD798992DCE97E9EULL,
		0x5B5375F53C7FC351ULL,
		0x00009429796AF3DBULL
	}};
	shift = 49;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xABE373B720695A1FULL,
		0xACF4F30E4DF37148ULL,
		0xAE2912E09D9C4861ULL,
		0xCB13888BBF633B24ULL,
		0x61410AD3D83FA0E5ULL,
		0x56E29EABC38701EFULL,
		0x02A7877F0C828E02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E0000000000000ULL,
		0x29157C6E76E40D2BULL,
		0x0C359E9E61C9BE6EULL,
		0x6495C5225C13B389ULL,
		0x1CB962711177EC67ULL,
		0x3DEC28215A7B07F4ULL,
		0xC04ADC53D57870E0ULL,
		0x000054F0EFE19051ULL
	}};
	shift = 53;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5219698A69449A50ULL,
		0x66DD0ADB7ED3A8B7ULL,
		0xD2987623B1A3CA6FULL,
		0x60BE247CFD79DEB3ULL,
		0x0D289A53B3066C6AULL,
		0x112F4CDD8F5ED957ULL,
		0xC5C3553E01241B3DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9698A69449A50000ULL,
		0xD0ADB7ED3A8B7521ULL,
		0x87623B1A3CA6F66DULL,
		0xE247CFD79DEB3D29ULL,
		0x89A53B3066C6A60BULL,
		0xF4CDD8F5ED9570D2ULL,
		0x3553E01241B3D112ULL,
		0x0000000000000C5CULL
	}};
	shift = 12;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x46957089043512BCULL,
		0x1BA025B8BBA4A6BFULL,
		0x75374CC099784CB3ULL,
		0xE1E2F658BBD64CBCULL,
		0x22686C07C8052FA7ULL,
		0xAE688423FC569955ULL,
		0xFE35E0DADA6A6296ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AE112086A257800ULL,
		0x404B7177494D7E8DULL,
		0x6E998132F0996637ULL,
		0xC5ECB177AC9978EAULL,
		0xD0D80F900A5F4FC3ULL,
		0xD10847F8AD32AA44ULL,
		0x6BC1B5B4D4C52D5CULL,
		0x00000000000001FCULL
	}};
	shift = 9;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x464568CD80AA5A9EULL,
		0x1F654741EA61996BULL,
		0x95B44F11BDDFF88FULL,
		0x1C52C518BF69D941ULL,
		0x2741FAB09B56036EULL,
		0x0408632A7DA3EECFULL,
		0xC6383D172452E5E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4568CD80AA5A9E00ULL,
		0x654741EA61996B46ULL,
		0xB44F11BDDFF88F1FULL,
		0x52C518BF69D94195ULL,
		0x41FAB09B56036E1CULL,
		0x08632A7DA3EECF27ULL,
		0x383D172452E5E304ULL,
		0x00000000000000C6ULL
	}};
	shift = 8;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE7FE5EB8FDACF093ULL,
		0x9953D726BF01149FULL,
		0xCBF58FCD59569D62ULL,
		0xE2DE0186997B1993ULL,
		0x0AF8D6C2E9163D73ULL,
		0x5192FF9B02BBF28BULL,
		0xA1224053879C67D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6B3C24C0000000ULL,
		0xAFC04527F9FF97AEULL,
		0x5655A758A654F5C9ULL,
		0xA65EC664F2FD63F3ULL,
		0xBA458F5CF8B78061ULL,
		0xC0AEFCA2C2BE35B0ULL,
		0xE1E719F55464BFE6ULL,
		0x0000000028489014ULL
	}};
	shift = 30;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4367DEA6B2B22600ULL,
		0xE6A6BA642F340459ULL,
		0x8AC4BD9B6301A2CDULL,
		0xF0373BB2A50C8156ULL,
		0x62BF6839F976722AULL,
		0x97315E24564B36AFULL,
		0x476963C1407984DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2CA1B3EF53595913ULL,
		0x66F3535D32179A02ULL,
		0xAB45625ECDB180D1ULL,
		0x15781B9DD9528640ULL,
		0x57B15FB41CFCBB39ULL,
		0x6D4B98AF122B259BULL,
		0x0023B4B1E0A03CC2ULL
	}};
	shift = 55;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0429A95331EADD13ULL,
		0x1324E7AC12609B30ULL,
		0xA1258479A2415AAFULL,
		0xECCC88A5B6C0366BULL,
		0x6D8D2F82EE0917ABULL,
		0xE5FAFB1AD5BF3941ULL,
		0xCC5036C5BC1E5CE8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x0214D4A998F56E89ULL,
		0x899273D609304D98ULL,
		0xD092C23CD120AD57ULL,
		0xF6664452DB601B35ULL,
		0xB6C697C177048BD5ULL,
		0x72FD7D8D6ADF9CA0ULL,
		0x66281B62DE0F2E74ULL
	}};
	shift = 63;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD7F4E31A071F0490ULL,
		0x7D156B1BE0960B51ULL,
		0xE02C0A642F0B4419ULL,
		0xDC6F55A107E3FD8BULL,
		0x4FF3F6853DB5F8CFULL,
		0x790F57F72E9E270CULL,
		0xFC8B5171EB5B056EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681C7C1240000000ULL,
		0x6F82582D475FD38CULL,
		0x90BC2D1065F455ACULL,
		0x841F8FF62F80B029ULL,
		0x14F6D7E33F71BD56ULL,
		0xDCBA789C313FCFDAULL,
		0xC7AD6C15B9E43D5FULL,
		0x0000000003F22D45ULL
	}};
	shift = 26;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBCEEFC11403730E7ULL,
		0xFE6D61562ABBDA6CULL,
		0x94236DABAC9E9150ULL,
		0x8ABF6D20651AB714ULL,
		0xE1C477BCF84677B1ULL,
		0xCF19165ABAF7F697ULL,
		0xB5999D5417F24447ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4500DCC39C000000ULL,
		0x58AAEF69B2F3BBF0ULL,
		0xAEB27A4543F9B585ULL,
		0x81946ADC52508DB6ULL,
		0xF3E119DEC62AFDB4ULL,
		0x6AEBDFDA5F8711DEULL,
		0x505FC9111F3C6459ULL,
		0x0000000002D66675ULL
	}};
	shift = 26;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC4BFC61F3B3BF89AULL,
		0xEEEE170A373D98CDULL,
		0xB69A151FAB9D6C16ULL,
		0xEE8879CDAED0817BULL,
		0xDC068CC7169C4F66ULL,
		0xB1C6CC0BE0EB2AF9ULL,
		0xAFEADD141C303429ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E7677F134000000ULL,
		0x146E7B319B897F8CULL,
		0x3F573AD82DDDDC2EULL,
		0x9B5DA102F76D342AULL,
		0x8E2D389ECDDD10F3ULL,
		0x17C1D655F3B80D19ULL,
		0x2838606853638D98ULL,
		0x00000000015FD5BAULL
	}};
	shift = 25;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2926907F81DFAE82ULL,
		0xA2B1D71D4B3C6F10ULL,
		0xA54872B45C915CA8ULL,
		0x38440116984EB566ULL,
		0xDC96B9DB97F9B9EFULL,
		0x414A52E848FCC5BCULL,
		0xF7B7124382B4004EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24D20FF03BF5D040ULL,
		0x563AE3A9678DE205ULL,
		0xA90E568B922B9514ULL,
		0x088022D309D6ACD4ULL,
		0x92D73B72FF373DE7ULL,
		0x294A5D091F98B79BULL,
		0xF6E24870568009C8ULL,
		0x000000000000001EULL
	}};
	shift = 5;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5FEDCA9DC1249DB9ULL,
		0x59F9C6ACC373A46DULL,
		0x85A49C3548FE1142ULL,
		0x16BBAE03C1B8BEE7ULL,
		0x1AFD536D8655C7FCULL,
		0x07D838E880A771ECULL,
		0xE1478C9408C49605ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7049276E40000000ULL,
		0x30DCE91B57FB72A7ULL,
		0x523F8450967E71ABULL,
		0xF06E2FB9E169270DULL,
		0x619571FF05AEEB80ULL,
		0x2029DC7B06BF54DBULL,
		0x0231258141F60E3AULL,
		0x000000003851E325ULL
	}};
	shift = 30;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x679FEFD846BA0AD3ULL,
		0xDAE712B95870B542ULL,
		0x52B4410E815666D8ULL,
		0x0AB54A4B7FD55507ULL,
		0x3BD42FD99575AEFCULL,
		0x17F3BA748986D54DULL,
		0x9440030D3EE340A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x4CF3FDFB08D7415AULL,
		0x1B5CE2572B0E16A8ULL,
		0xEA568821D02ACCDBULL,
		0x8156A9496FFAAAA0ULL,
		0xA77A85FB32AEB5DFULL,
		0x22FE774E9130DAA9ULL,
		0x12880061A7DC6814ULL
	}};
	shift = 61;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x453C6BA83D5846CEULL,
		0x783A12E2E11FB75FULL,
		0xA22966E7419E8E1EULL,
		0x52DEE4D70DD69CD4ULL,
		0xC36AC1BBE82CD77FULL,
		0x998E4A93D8408464ULL,
		0xA389F550756DCC9BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x453C6BA83D5846CEULL,
		0x783A12E2E11FB75FULL,
		0xA22966E7419E8E1EULL,
		0x52DEE4D70DD69CD4ULL,
		0xC36AC1BBE82CD77FULL,
		0x998E4A93D8408464ULL,
		0xA389F550756DCC9BULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7ACB7BAE5F59EDE9ULL,
		0x1181EC412714ABEAULL,
		0x0A8278BBC873B5C9ULL,
		0x7628702EBA348387ULL,
		0x862C83CFF93B6F23ULL,
		0xE62791D35AAC5E94ULL,
		0xE2CDBB6DBA67F75DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF480000000000000ULL,
		0xF53D65BDD72FACF6ULL,
		0xE488C0F620938A55ULL,
		0xC385413C5DE439DAULL,
		0x91BB1438175D1A41ULL,
		0x4A431641E7FC9DB7ULL,
		0xAEF313C8E9AD562FULL,
		0x007166DDB6DD33FBULL
	}};
	shift = 55;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x21701B34B0CE1536ULL,
		0xE0D3EDF2FE322565ULL,
		0x710ABE69C680BF08ULL,
		0xBBCA5E7101B53C0EULL,
		0xEA6262A56CB6C1D3ULL,
		0x7E5D088CF8081C3BULL,
		0xC30F24F27C0A5103ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669619C2A6C00000ULL,
		0xBE5FC644ACA42E03ULL,
		0xCD38D017E11C1A7DULL,
		0xCE2036A781CE2157ULL,
		0x54AD96D83A77794BULL,
		0x119F0103877D4C4CULL,
		0x9E4F814A206FCBA1ULL,
		0x00000000001861E4ULL
	}};
	shift = 21;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x55B03CF796B0E125ULL,
		0xACE88725857FFADDULL,
		0x712CFE88A4BD96B7ULL,
		0xCCBE89850209AAFAULL,
		0xDA3F3772A01A5939ULL,
		0x670DBCE95ABF4A4EULL,
		0x66E1E76AAC459446ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF796B0E1250000ULL,
		0x8725857FFADD55B0ULL,
		0xFE88A4BD96B7ACE8ULL,
		0x89850209AAFA712CULL,
		0x3772A01A5939CCBEULL,
		0xBCE95ABF4A4EDA3FULL,
		0xE76AAC459446670DULL,
		0x00000000000066E1ULL
	}};
	shift = 16;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCCC4216F20D548DDULL,
		0xE2ED7C987128A686ULL,
		0xFD5B58BE981851AFULL,
		0x00281D5047C3969FULL,
		0xBC1849760F6CFAACULL,
		0xD6C4475C6778026DULL,
		0x847363441AB274B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66210B7906AA46E8ULL,
		0x176BE4C389453436ULL,
		0xEADAC5F4C0C28D7FULL,
		0x0140EA823E1CB4FFULL,
		0xE0C24BB07B67D560ULL,
		0xB6223AE33BC0136DULL,
		0x239B1A20D593A5CEULL,
		0x0000000000000004ULL
	}};
	shift = 3;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCDC47914016B0155ULL,
		0xFF655949D46321B0ULL,
		0x484D81C651DDB2B4ULL,
		0x7E9F51CFA2A31DDBULL,
		0xEBBA87CB11440451ULL,
		0xEBE0370363D194FCULL,
		0xC90773CDEE6BA4C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22802D602AA00000ULL,
		0x293A8C643619B88FULL,
		0x38CA3BB6569FECABULL,
		0x39F45463BB6909B0ULL,
		0xF96228808A2FD3EAULL,
		0xE06C7A329F9D7750ULL,
		0x79BDCD74987D7C06ULL,
		0x00000000001920EEULL
	}};
	shift = 21;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBE9CE1BB066D4EEBULL,
		0x8142B80C00CD00C5ULL,
		0x8A159CB0AA76DF2FULL,
		0x193307479C114188ULL,
		0x2870500932197065ULL,
		0x8735D83A9D043550ULL,
		0xD0ED6B4D7F35C3EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8336A7758000000ULL,
		0x600668062DF4E70DULL,
		0x8553B6F97C0A15C0ULL,
		0x3CE08A0C4450ACE5ULL,
		0x4990CB8328C9983AULL,
		0xD4E821AA81438280ULL,
		0x6BF9AE1F5439AEC1ULL,
		0x0000000006876B5AULL
	}};
	shift = 27;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6F5204C66F4D0957ULL,
		0x4F6BA874DD2A4A76ULL,
		0xB7BF9DE7B4D572C8ULL,
		0x9107213804BDD74BULL,
		0xBE77E44E05224146ULL,
		0x30AEB8A2BF0DF6D2ULL,
		0x88EF87560A9AC259ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04C66F4D09570000ULL,
		0xA874DD2A4A766F52ULL,
		0x9DE7B4D572C84F6BULL,
		0x213804BDD74BB7BFULL,
		0xE44E052241469107ULL,
		0xB8A2BF0DF6D2BE77ULL,
		0x87560A9AC25930AEULL,
		0x00000000000088EFULL
	}};
	shift = 16;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x81749908B687E73FULL,
		0x501E55788B38A74AULL,
		0x3C3C933B082F075FULL,
		0x3E878684CB0AAC47ULL,
		0xDAFE9F0FB5810DB7ULL,
		0x959B30A2663F42D4ULL,
		0x74CDCA67974DF3CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26422DA1F9CFC000ULL,
		0x955E22CE29D2A05DULL,
		0x24CEC20BC1D7D407ULL,
		0xE1A132C2AB11CF0FULL,
		0xA7C3ED60436DCFA1ULL,
		0xCC28998FD0B536BFULL,
		0x7299E5D37CF3E566ULL,
		0x0000000000001D33ULL
	}};
	shift = 14;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4F3F02DEDE9E88AAULL,
		0x9A24009A10C4DBEAULL,
		0xF0B5BF07118CBDC7ULL,
		0xD610227AF4F99749ULL,
		0x139973C90BAC5FE2ULL,
		0x034F1D2B5E7997F5ULL,
		0x3177F289155B0887ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF02DEDE9E88AA000ULL,
		0x4009A10C4DBEA4F3ULL,
		0x5BF07118CBDC79A2ULL,
		0x0227AF4F99749F0BULL,
		0x973C90BAC5FE2D61ULL,
		0xF1D2B5E7997F5139ULL,
		0x7F289155B0887034ULL,
		0x0000000000000317ULL
	}};
	shift = 12;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x915BA6A7170DD79BULL,
		0xF8F513B1E00AAEBDULL,
		0xCBE237A78597329CULL,
		0xFD6881AFF33187C8ULL,
		0x147AC6B053F4B961ULL,
		0xDD2FE47D57F99A3AULL,
		0x301383A6501E9D9DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C375E6C0000000ULL,
		0x7802ABAF6456E9A9ULL,
		0xE165CCA73E3D44ECULL,
		0xFCCC61F232F88DE9ULL,
		0x14FD2E587F5A206BULL,
		0x55FE668E851EB1ACULL,
		0x9407A767774BF91FULL,
		0x000000000C04E0E9ULL
	}};
	shift = 30;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9DA9D2BD2DAD512AULL,
		0xA0CDB1D8F6B2219EULL,
		0x48A4BB461B13BD67ULL,
		0x8816169FF2CF3F1EULL,
		0x3981906899046351ULL,
		0x4D1E099B4C80858EULL,
		0x8E82349F993389A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA254000000000000ULL,
		0x433D3B53A57A5B5AULL,
		0x7ACF419B63B1ED64ULL,
		0x7E3C9149768C3627ULL,
		0xC6A3102C2D3FE59EULL,
		0x0B1C730320D13208ULL,
		0x134E9A3C13369901ULL,
		0x00011D04693F3267ULL
	}};
	shift = 49;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0E9D83F9B6D67EE8ULL,
		0x2F05BB1831F9E251ULL,
		0xE9E698B67C441065ULL,
		0x7935B25E604FB21DULL,
		0xC8A526536FA4EF6FULL,
		0x53DBCCB93026EC90ULL,
		0x305323467DFA6ECEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE80000000000000ULL,
		0x2510E9D83F9B6D67ULL,
		0x0652F05BB1831F9EULL,
		0x21DE9E698B67C441ULL,
		0xF6F7935B25E604FBULL,
		0xC90C8A526536FA4EULL,
		0xECE53DBCCB93026EULL,
		0x000305323467DFA6ULL
	}};
	shift = 52;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3C62AF1BED22BF95ULL,
		0x3D2968FB86083E35ULL,
		0xB4BD6C326B43910EULL,
		0xE2434DBC265FF0E2ULL,
		0x26EE59A12B922FEFULL,
		0x9B434DF96028FD3FULL,
		0x0E56832D39E5EAC4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB48AFE540000000ULL,
		0xE1820F8D4F18ABC6ULL,
		0x9AD0E4438F4A5A3EULL,
		0x0997FC38AD2F5B0CULL,
		0x4AE48BFBF890D36FULL,
		0x580A3F4FC9BB9668ULL,
		0x4E797AB126D0D37EULL,
		0x000000000395A0CBULL
	}};
	shift = 30;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x95A8323E549C406EULL,
		0x7BD9D7EA0A7957E5ULL,
		0x1C9E6CE810C94FC8ULL,
		0x9C46905DB1DCDF95ULL,
		0x39B7D85207790DD3ULL,
		0xD677E56544D11846ULL,
		0xB7F690D18ECFC45BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C8F9527101B8000ULL,
		0x75FA829E55F9656AULL,
		0x9B3A043253F21EF6ULL,
		0xA4176C7737E54727ULL,
		0xF61481DE4374E711ULL,
		0xF959513446118E6DULL,
		0xA43463B3F116F59DULL,
		0x0000000000002DFDULL
	}};
	shift = 14;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7F86BDFF410E538EULL,
		0xFC84C24116354ADBULL,
		0xAE7776E4D93E4224ULL,
		0x3EC6347070C5B880ULL,
		0x336D1C1F05BD13BAULL,
		0xD250AC254A74F641ULL,
		0xAE8C853C137C924CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EFFA08729C7000ULL,
		0x261208B1AA56DBFCULL,
		0xBBB726C9F21127E4ULL,
		0x31A383862DC40573ULL,
		0x68E0F82DE89DD1F6ULL,
		0x85612A53A7B2099BULL,
		0x6429E09BE4926692ULL,
		0x0000000000000574ULL
	}};
	shift = 11;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x09B9E84CE87D4F86ULL,
		0xE25BEE5E74E6D660ULL,
		0xA1C4A57148A6949BULL,
		0x1F9A8F176341F79FULL,
		0xF0634877D164088AULL,
		0xD3719A1B685FD7E0ULL,
		0x0B84BBA5FF085AF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x04DCF426743EA7C3ULL,
		0xF12DF72F3A736B30ULL,
		0xD0E252B8A4534A4DULL,
		0x0FCD478BB1A0FBCFULL,
		0x7831A43BE8B20445ULL,
		0xE9B8CD0DB42FEBF0ULL,
		0x05C25DD2FF842D7BULL
	}};
	shift = 63;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBAE96B4CC97B8B48ULL,
		0xC8D05EAD8133FB4CULL,
		0x81584C3591EBC07EULL,
		0x88924C6C155456B9ULL,
		0x2B454C6D5F7C8BE7ULL,
		0x334E50B3235296A2ULL,
		0x57FE31FD8A8B9F32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4CC97B8B480000ULL,
		0x5EAD8133FB4CBAE9ULL,
		0x4C3591EBC07EC8D0ULL,
		0x4C6C155456B98158ULL,
		0x4C6D5F7C8BE78892ULL,
		0x50B3235296A22B45ULL,
		0x31FD8A8B9F32334EULL,
		0x00000000000057FEULL
	}};
	shift = 16;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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