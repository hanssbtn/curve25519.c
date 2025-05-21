#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x2348BC17E61887F6ULL,
		0x40448CF15742E664ULL,
		0x9A88B82F7E48DA6EULL,
		0x3256011CC48B9132ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x72C3F1FA92B2EDE3ULL,
		0xAF1C28477F66D683ULL,
		0x4A5FC263E3676B7BULL,
		0x3898586FC81B5DB9ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xB084CA1D53659A00ULL,
		0x912864A9D7DC0FE0ULL,
		0x5028F5CB9AE16EF2ULL,
		0x79BDA8ACFC703379ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x32F5DA2B3F60F8DAULL,
		0x0626AAD8B4490979ULL,
		0x3C9CA0A2CC5178BBULL,
		0x58C5D52DD027A244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB36E5D36A36065ULL,
		0xAD9F3EF2DEA2DD26ULL,
		0xBB5B5F0FFB0A6EEDULL,
		0x0DE0DA1B382516BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96426BCE08BD9875ULL,
		0x58876BE5D5A62C52ULL,
		0x81414192D14709CDULL,
		0x4AE4FB1298028B87ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB0B6ABDB15FF8ABDULL,
		0x457FAD6D3A02859BULL,
		0x475581D4B64915B5ULL,
		0x4D7F5199BD83CC82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BAD05539439622FULL,
		0xD90FEAA38A1FA199ULL,
		0xC41B18C679C5D004ULL,
		0x3451AA100B4EEDB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA509A68781C6288EULL,
		0x6C6FC2C9AFE2E402ULL,
		0x833A690E3C8345B0ULL,
		0x192DA789B234DECDULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x70FE9EF07BDBFC3EULL,
		0x2A1B9D022542C99DULL,
		0xB772F2C803206BABULL,
		0x269763214B5B497DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F0D4F0D05FE86AULL,
		0x172CEEC274FA5B1AULL,
		0x7245AE8E4147EA1AULL,
		0x2F5524F34B64794CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x700DC9FFAB7C13C1ULL,
		0x12EEAE3FB0486E83ULL,
		0x452D4439C1D88191ULL,
		0x77423E2DFFF6D031ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x42BD6228C385D404ULL,
		0xF337DF98CDB0129CULL,
		0x7316FD28DC703555ULL,
		0x154DB6EF94EA71A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115FFF2136646AB1ULL,
		0x3DEC6FAEA03DA81EULL,
		0xE0D9775E0AF68313ULL,
		0x6FA6CE434CBA4ED6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x315D63078D216940ULL,
		0xB54B6FEA2D726A7EULL,
		0x923D85CAD179B242ULL,
		0x25A6E8AC483022C9ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x39C4EB8A476CB290ULL,
		0x0ED6C84ECDE72A2FULL,
		0x58BAE2935DDEEEE0ULL,
		0x2FF95664A91BE2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97E6CA32F79CB01ULL,
		0x8BB9F975772351F6ULL,
		0xD26F2EBB8897B779ULL,
		0x2D5E7ADB9B60FE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80467EE717F2E78FULL,
		0x831CCED956C3D838ULL,
		0x864BB3D7D5473766ULL,
		0x029ADB890DBAE46CULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x040E2093E58F44F8ULL,
		0x2EA0291578CACB6BULL,
		0xBB265EE876E1CF44ULL,
		0x080F75690B9DA2BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A391B1DD3B9524CULL,
		0x82D8C12D16F44368ULL,
		0xBFF37FA9446869D5ULL,
		0x02373EDDA45EB145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89D5057611D5F2ACULL,
		0xABC767E861D68802ULL,
		0xFB32DF3F3279656EULL,
		0x05D8368B673EF177ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF1FD71F020834525ULL,
		0x0F3D91D868522B41ULL,
		0x47D8EA9A92BFC572ULL,
		0x3E180B243A829828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0B0AEFEF53A9F1ULL,
		0xA921E475269B1F50ULL,
		0x783ABD74B0DC3C00ULL,
		0x55B6C9136A0A3C20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42F26700312F9B21ULL,
		0x661BAD6341B70BF1ULL,
		0xCF9E2D25E1E38971ULL,
		0x68614210D0785C07ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0CCAED362AE0589DULL,
		0x719111A3932039DAULL,
		0x37DBC76CF4A36F60ULL,
		0x6CF619B893B99CD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75FDF718D023894ULL,
		0xD906C82E86B592E2ULL,
		0x14DCC25C1C9403D9ULL,
		0x7B0924DB0025F109ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x156B0DC49DDE1FF6ULL,
		0x988A49750C6AA6F7ULL,
		0x22FF0510D80F6B86ULL,
		0x71ECF4DD9393ABD0ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x05E11859BCB969B2ULL,
		0xA94E78538E79AB57ULL,
		0xD16B277A22708693ULL,
		0x189173DB7B13BD27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4273C414C92262CULL,
		0xC81E484202B6D204ULL,
		0x748212757FA87744ULL,
		0x3A6A3B16B8FBFA8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21B9DC1870274373ULL,
		0xE13030118BC2D952ULL,
		0x5CE91504A2C80F4EULL,
		0x5E2738C4C217C29CULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x495FF8E4BB0A015BULL,
		0x853C3D70466E2E76ULL,
		0x3481358D64332BBEULL,
		0x4352F72535635C9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB1CB445FACEE45ULL,
		0x088E6BF64BE6F232ULL,
		0x765EE40B53635B7DULL,
		0x48D3A0781212708AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAAE2DA05B5D1303ULL,
		0x7CADD179FA873C43ULL,
		0xBE22518210CFD041ULL,
		0x7A7F56AD2350EC0FULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4372833ABA8E3BCFULL,
		0xFC9A36120643312AULL,
		0x9000BC01317F5BB1ULL,
		0x67ED0BD42CF76E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1376A2EC48FE605ULL,
		0x4AEDCF543FC18A46ULL,
		0xCE55DC10FC482D4EULL,
		0x5413243731280654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA23B190BF5FE55CAULL,
		0xB1AC66BDC681A6E3ULL,
		0xC1AADFF035372E63ULL,
		0x13D9E79CFBCF67FFULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE11A4F2A64EBF48CULL,
		0x5F4FD72B1FAA426CULL,
		0x02EE6BD14CC38321ULL,
		0x0290AF5993E8ACB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE724940AF1253C6ULL,
		0xE5A83D3B3F57F750ULL,
		0xA7B81354FF908A87ULL,
		0x54FA123FE6852332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22A805E9B5D9A0B3ULL,
		0x79A799EFE0524B1CULL,
		0x5B36587C4D32F899ULL,
		0x2D969D19AD638981ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xBD30CCD410C7D0A3ULL,
		0x3A11D09A2174FE49ULL,
		0x028EDDEE70D55DA9ULL,
		0x38E3780A8FBB41A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x196495DEBAFBCEE6ULL,
		0x5CB19CA5C961F7B4ULL,
		0xD7B955410A989E1AULL,
		0x676D5B63DC296B6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3CC36F555CC01AAULL,
		0xDD6033F458130695ULL,
		0x2AD588AD663CBF8EULL,
		0x51761CA6B391D63AULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6DD9A86882295F94ULL,
		0x55FD93B0592574C1ULL,
		0x2A31EEF10B22BC14ULL,
		0x2D0CABC1920E97AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D62A2ED2D66FFDFULL,
		0x1DBADD2B34AB5B76ULL,
		0x2791BF59A2B0CC6EULL,
		0x1E28285354A1397DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD077057B54C25FB5ULL,
		0x3842B685247A194AULL,
		0x02A02F976871EFA6ULL,
		0x0EE4836E3D6D5E31ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xCA0094E07A6F8119ULL,
		0x90A196FE3A94B136ULL,
		0x0733248790627B78ULL,
		0x7A12DBA7B8E6F2C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA240BF1569E59945ULL,
		0x4F1DBB8A1249FCF0ULL,
		0x3F088F66969A4673ULL,
		0x7A606BE2B287C198ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27BFD5CB1089E7C1ULL,
		0x4183DB74284AB446ULL,
		0xC82A9520F9C83505ULL,
		0x7FB26FC5065F3127ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE82284763F337DF5ULL,
		0x6AC290C91F438640ULL,
		0x1E43809760AEDE82ULL,
		0x5258B2FD8E104353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA7B45ADBA03694ULL,
		0x8F641EF2619243C9ULL,
		0x651DB66D39C66ABFULL,
		0x4906EC5C18FE5011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A7AD01B63934761ULL,
		0xDB5E71D6BDB14277ULL,
		0xB925CA2A26E873C2ULL,
		0x0951C6A17511F341ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB43DAB2A130A3631ULL,
		0x4D54785B3B80EE2CULL,
		0x55E1E7A6DCCB0735ULL,
		0x35455E22CFB6C500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A781BDF2FCBFF99ULL,
		0xD6EF2EAF8B9CD279ULL,
		0xDFA2F48BE735ECBEULL,
		0x53131D25C2F3D365ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89C58F4AE33E3685ULL,
		0x766549ABAFE41BB3ULL,
		0x763EF31AF5951A76ULL,
		0x623240FD0CC2F19AULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x151FB433889AC850ULL,
		0xEF2372696BBB48C0ULL,
		0x317BCE93531C0182ULL,
		0x1CED9919245AD157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x295A2D22B0CFB3A6ULL,
		0x53EF72966BF81769ULL,
		0x3A0DF52C6B366A43ULL,
		0x79DA31E2C22999BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBC58710D7CB1497ULL,
		0x9B33FFD2FFC33156ULL,
		0xF76DD966E7E5973FULL,
		0x231367366231379AULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF57BD1B122B226CBULL,
		0x9518B59E562E38A0ULL,
		0x6632691A581B02A5ULL,
		0x4EACC353797E580AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE00993C3BEA8C0FULL,
		0xF2276AFFA616AE03ULL,
		0x7F73C5F36A45B250ULL,
		0x036F0CE022866E2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x077B3874E6C79ABCULL,
		0xA2F14A9EB0178A9DULL,
		0xE6BEA326EDD55054ULL,
		0x4B3DB67356F7E9DAULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9D3E0EB9E847600EULL,
		0xD97D281C73F8B341ULL,
		0x24AA7B9CC6A63D90ULL,
		0x1770C80C8B45DE30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8170AEEA26E70B1ULL,
		0xD0C55FD2AB757F2AULL,
		0xC2E778DE5186DDE8ULL,
		0x051898381A22E27EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB52703CB45D8EF5DULL,
		0x08B7C849C8833416ULL,
		0x61C302BE751F5FA8ULL,
		0x12582FD47122FBB1ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x742F1810A8AC117CULL,
		0xCF0175DF2E7AEC90ULL,
		0x5EC3EFA203F97D0EULL,
		0x3242A30A0340F6E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD40502CCD2BB50ULL,
		0xEA94F934CBF60C12ULL,
		0xCCADCFD2EE80A1B0ULL,
		0x3B4EAA7D717EC088ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x275B130DDBD95619ULL,
		0xE46C7CAA6284E07EULL,
		0x92161FCF1578DB5DULL,
		0x76F3F88C91C23660ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3BAC2881D4520F26ULL,
		0xBFFD3B9ED8BD8080ULL,
		0xAA721487BC5A8F5FULL,
		0x02D19ED645600D18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0810BADDAA558054ULL,
		0x3FBC3C67BB8FF2A3ULL,
		0xF946F97C6164BAD2ULL,
		0x05CDC2A021FD866EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x339B6DA429FC8EBFULL,
		0x8040FF371D2D8DDDULL,
		0xB12B1B0B5AF5D48DULL,
		0x7D03DC36236286A9ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4BF32925A659814CULL,
		0x4D010B03C06E6E0CULL,
		0xAD9520C51FB0AE6BULL,
		0x3680139B1200A608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A892027CE783CFULL,
		0x995885A684E265C1ULL,
		0x98165E454FFD1F7DULL,
		0x0366551F9EE0F180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A4A97232971FD7DULL,
		0xB3A8855D3B8C084BULL,
		0x157EC27FCFB38EEDULL,
		0x3319BE7B731FB488ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3CAFCE75C8422580ULL,
		0x24ECBAD67BFEDD3DULL,
		0x81BD70A38C2B2088ULL,
		0x450C6CF64EA13609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE30EA46F56C96A6AULL,
		0xEB16466C9C44C04DULL,
		0xBEBB9098440024B2ULL,
		0x749F9972A1747A9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59A12A067178BB03ULL,
		0x39D67469DFBA1CEFULL,
		0xC301E00B482AFBD5ULL,
		0x506CD383AD2CBB69ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4568A5A91446BE2AULL,
		0x7F0DAC553C32CDF3ULL,
		0x46B29713B457B896ULL,
		0x2EB9FFC81AB29E9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783DE353F3B27B5DULL,
		0xFF692B49EE6813E2ULL,
		0xCF11306ADED04DB8ULL,
		0x5141269D89F07C37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD2AC255209442BAULL,
		0x7FA4810B4DCABA10ULL,
		0x77A166A8D5876ADDULL,
		0x5D78D92A90C22267ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9DBCC0AD0294AB20ULL,
		0xFA1C431DB358EEF0ULL,
		0x8F3C9EE6382F869AULL,
		0x434EA8CE493591DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1660C6DA3CD3C3BULL,
		0xFFAF91BF18704F19ULL,
		0x67083B9F51F44328ULL,
		0x4A4C17608E398DBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC56B43F5EC76ED2ULL,
		0xFA6CB15E9AE89FD6ULL,
		0x28346346E63B4371ULL,
		0x7902916DBAFC0421ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF585F2C9001E6CB7ULL,
		0xAAD3578BD8243670ULL,
		0xBA3FFA87940821FEULL,
		0x1D3F51599E07AF63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597EE01657F9E381ULL,
		0x0B30873938959D17ULL,
		0xDF7A1EE49CF9AF0CULL,
		0x09107EC40D29770CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C0712B2A8248936ULL,
		0x9FA2D0529F8E9959ULL,
		0xDAC5DBA2F70E72F2ULL,
		0x142ED29590DE3856ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xED57411A5F12E9C4ULL,
		0x01AB98CC9D13653DULL,
		0x0E11E44022A535D2ULL,
		0x325A089CA4EBD373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A89F8DB2C3487A2ULL,
		0xA21DE29796033A09ULL,
		0x6EFC02DB674CCC86ULL,
		0x1B62B4313688EA5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2CD483F32DE6222ULL,
		0x5F8DB63507102B34ULL,
		0x9F15E164BB58694BULL,
		0x16F7546B6E62E914ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x444FC7D1869DBDC2ULL,
		0x008168F9968377ACULL,
		0x437738685C4F96E0ULL,
		0x0BE66A05D89301B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC90C27EE45DAB7EULL,
		0x6F4A3AE74DFA77F9ULL,
		0xBA6424C3AD37FCB6ULL,
		0x226FD97F858EB925ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87BF0552A2401231ULL,
		0x91372E124888FFB2ULL,
		0x891313A4AF179A29ULL,
		0x697690865304488AULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x20E9D9BBC746E369ULL,
		0xE539E8696419B498ULL,
		0x315A4C01B7AC071FULL,
		0x37A6FE642C48B34EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86B41769C09B1AF8ULL,
		0x671212FA39CD1DA4ULL,
		0x58CE3BA444C2E37CULL,
		0x14B246D271502FF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A35C25206ABC871ULL,
		0x7E27D56F2A4C96F3ULL,
		0xD88C105D72E923A3ULL,
		0x22F4B791BAF88358ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC6FF57C3F06CB2E9ULL,
		0xE3B25C2C7C99D3A9ULL,
		0xF9ACFBAFAE566536ULL,
		0x7305413749C7D6CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFAC157DB70B0906ULL,
		0x73EFBB397A48DD19ULL,
		0xC5C68FC9F294138CULL,
		0x1C0931493C2DC124ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE75342463961A9E3ULL,
		0x6FC2A0F30250F68FULL,
		0x33E66BE5BBC251AAULL,
		0x56FC0FEE0D9A15A6ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF7BAF58680175600ULL,
		0x351067484B5D758FULL,
		0x9033E269B3E7E4B8ULL,
		0x458D891B2E8D0A16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E4F25B57F926940ULL,
		0xCA189942E1FA4A53ULL,
		0x9E444EBD7798FC44ULL,
		0x5124E77AF73563A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB96BCFD10084ECADULL,
		0x6AF7CE0569632B3CULL,
		0xF1EF93AC3C4EE873ULL,
		0x7468A1A03757A674ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7939234302B34B1EULL,
		0x61D34369602A4DC0ULL,
		0x3AFEA02CE5931B05ULL,
		0x20BEF837D3039ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7B7CE93AF1CB114ULL,
		0x6B7F22F4E1361B11ULL,
		0xD8BE61C9E0D6846CULL,
		0x50ABBDC391CCCFD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC18154AF539699F7ULL,
		0xF65420747EF432AEULL,
		0x62403E6304BC9698ULL,
		0x50133A744136CEF3ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB57C336A127F6085ULL,
		0xF656590DC1F58E75ULL,
		0x56935BB9ADAAF3EFULL,
		0x4149DBFDAD98CF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E78EB97B585FB72ULL,
		0xFCB24A4BB953C387ULL,
		0x32C3A2A45A22144BULL,
		0x51F7F8A5942BD6B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x670347D25CF96500ULL,
		0xF9A40EC208A1CAEEULL,
		0x23CFB9155388DFA3ULL,
		0x6F51E358196CF8A3ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xDC3BD02EBE209162ULL,
		0xD39CA99607BB40A9ULL,
		0x19CF70CE2A130F72ULL,
		0x5C5E6C69B3E14BAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x383ACD45246825C7ULL,
		0xA03FBA52841426D7ULL,
		0xA54D78F0C44BAF68ULL,
		0x3393DD028E985E8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA40102E999B86B9BULL,
		0x335CEF4383A719D2ULL,
		0x7481F7DD65C7600AULL,
		0x28CA8F672548ED22ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0839CDC14E56C402ULL,
		0xD189F1D4DE61849BULL,
		0x05F7304C3F3EDFDBULL,
		0x6EBA785A5FEE229DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F9908D634333E8BULL,
		0xCAA2871E7ABF5BD5ULL,
		0x4EC6BA5CC670C7E4ULL,
		0x1789929488DED576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8A0C4EB1A238577ULL,
		0x06E76AB663A228C5ULL,
		0xB73075EF78CE17F7ULL,
		0x5730E5C5D70F4D26ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0456D256CF1C4A9FULL,
		0x6DF08B02820AED79ULL,
		0x5F52075F39C2F1F7ULL,
		0x7E1FAA6FA89092CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAA12E5BEBFF5FB8ULL,
		0x2C27972B615D771DULL,
		0xA5AE9BFE6D8D4798ULL,
		0x4BD81D56F890E052ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19B5A3FAE31CEAE7ULL,
		0x41C8F3D720AD765BULL,
		0xB9A36B60CC35AA5FULL,
		0x32478D18AFFFB277ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xBA2BAD4533F1EFC7ULL,
		0x41F92EB75109AA74ULL,
		0xBB6F2A82A72F4025ULL,
		0x22435EA171F9A6DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB454E4976251003ULL,
		0x900E776F3C810779ULL,
		0xF256565CF84649BEULL,
		0x743F6ECF61B9F638ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEE65EFBBDCCDFB1ULL,
		0xB1EAB7481488A2FAULL,
		0xC918D425AEE8F666ULL,
		0x2E03EFD2103FB0A5ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x34584B0E9589043FULL,
		0x906F80DEA6382EE2ULL,
		0x96DB334166B83612ULL,
		0x01E5809D8B84C7F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF7ABA3DB211652ULL,
		0xF7E1BB0F70985CC9ULL,
		0x9A0D21ADC0971803ULL,
		0x51878025C4B2EB92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25609F6ABA67EDDAULL,
		0x988DC5CF359FD219ULL,
		0xFCCE1193A6211E0EULL,
		0x305E0077C6D1DC60ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0284F41F0326CDBFULL,
		0xD2CF730CF0EC0F1EULL,
		0xAB65C7D0476E35D2ULL,
		0x0398620A8ADC2EEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAA7FDFC78EB7BFEULL,
		0xB316EC80222C5F1CULL,
		0x2CD2166221E011A9ULL,
		0x3784E81E22A277C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57DCF6228A3B51AEULL,
		0x1FB8868CCEBFB001ULL,
		0x7E93B16E258E2429ULL,
		0x4C1379EC6839B726ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB1CEA30E7819D769ULL,
		0xFAF63297B015DB6FULL,
		0xDAB26AED411737ADULL,
		0x6A48F9679B8DDB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BED0216774AF362ULL,
		0xD9ABCFC93B328EAAULL,
		0xA34660D98CC13199ULL,
		0x729C75F19FAEF5D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75E1A0F800CEE3F4ULL,
		0x214A62CE74E34CC5ULL,
		0x376C0A13B4560614ULL,
		0x77AC8375FBDEE56AULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB88EFE0A175BA902ULL,
		0xE9C889035613368FULL,
		0x8A4485FDD3516411ULL,
		0x4630D2D7DA4B3A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4902C365568AA0BULL,
		0x31EA9879C6EE2075ULL,
		0xC98E5D602FDE1D41ULL,
		0x79BA5EB303F404FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13FED1D3C1F2FEE4ULL,
		0xB7DDF0898F25161AULL,
		0xC0B6289DA37346D0ULL,
		0x4C767424D6573577ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9EF379F102D3A166ULL,
		0xB1B581012FC3E8BAULL,
		0xCB1A6E07DF55C8A1ULL,
		0x2A3CF93FEA3AF689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33260A5C2B2F8258ULL,
		0x47F7AAC3FABA8631ULL,
		0x070137BB64E60BD7ULL,
		0x63D8D75E4AC6F498ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BCD6F94D7A41EFBULL,
		0x69BDD63D35096289ULL,
		0xC419364C7A6FBCCAULL,
		0x466421E19F7401F1ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9BBA6783AC4DDA3DULL,
		0xD77EDE535CDAFFEFULL,
		0xBD565E3AC52197D7ULL,
		0x47D21BE67234C2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF991F8EE7340410CULL,
		0x2C75BE6DAEBB8467ULL,
		0x2C266D69F9018D94ULL,
		0x2764F4D1091450BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2286E95390D9931ULL,
		0xAB091FE5AE1F7B87ULL,
		0x912FF0D0CC200A43ULL,
		0x206D2715692071F1ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x269124E919EA8A6CULL,
		0x90117E885AC74951ULL,
		0xFD33376E7873BD79ULL,
		0x717D1C649565A2ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63173F1DB0DC2FFAULL,
		0x454419C731AAB0D8ULL,
		0xB689B68048D0ADC8ULL,
		0x2D9C1B1E48E5EB9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC379E5CB690E5A72ULL,
		0x4ACD64C1291C9878ULL,
		0x46A980EE2FA30FB1ULL,
		0x43E101464C7FB712ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3899ADE38E4B7A2DULL,
		0x69D5CA3326752654ULL,
		0x7F13C691F665D147ULL,
		0x14F72D2ECCFBB6AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBAA54ED90B0CED6ULL,
		0xB6A17EBA8132526AULL,
		0xB690B111A5BE0E74ULL,
		0x5A2B07F885AB2C58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CEF58F5FD9AAB44ULL,
		0xB3344B78A542D3E9ULL,
		0xC883158050A7C2D2ULL,
		0x3ACC253647508A51ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x657CD873539A0BDBULL,
		0xA77ADB5D6A10CBDDULL,
		0x2489AD33CC851AA8ULL,
		0x26278301A096B673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CB7C40EDC984166ULL,
		0x03F470191DDE9198ULL,
		0xDA1CAD5B51B9EC65ULL,
		0x4138FF10D0E5A55EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18C514647701CA62ULL,
		0xA3866B444C323A45ULL,
		0x4A6CFFD87ACB2E43ULL,
		0x64EE83F0CFB11114ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5CF228B251CB7220ULL,
		0x6DA3CCFC3B0B5B62ULL,
		0xCEBC049691D62E99ULL,
		0x5AE94CA89D63A4FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC5BBE3708089EBBULL,
		0x863AEA6775CDDABEULL,
		0xCB24ED49DBA6BC0AULL,
		0x45969563C43E2FAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70966A7B49C2D365ULL,
		0xE768E294C53D80A3ULL,
		0x0397174CB62F728EULL,
		0x1552B744D9257551ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x94BF9023C8B265A1ULL,
		0xEC52E543963ECA88ULL,
		0xE3E2A1DEA0CF8F4CULL,
		0x6E860B00F83E598FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C55DDAF190875C2ULL,
		0x7E62DDD70631EE11ULL,
		0x96C419E402050F4DULL,
		0x0146242D29688568ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5869B274AFA9EFDFULL,
		0x6DF0076C900CDC77ULL,
		0x4D1E87FA9ECA7FFFULL,
		0x6D3FE6D3CED5D427ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC245F9616C2D7ADBULL,
		0xE808380FD0C67904ULL,
		0xEA9A4351430BB34DULL,
		0x16ED2B87B82E5B6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE45BA32B743B609AULL,
		0x6B8DE0037097E8E6ULL,
		0x18F3968094A0989AULL,
		0x355D953DB8E8AA9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDEA5635F7F21A2EULL,
		0x7C7A580C602E901DULL,
		0xD1A6ACD0AE6B1AB3ULL,
		0x618F9649FF45B0CEULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1B7D679489D2E942ULL,
		0x7DC18A7326AA42A0ULL,
		0x9595BD3920FBB648ULL,
		0x3984D01D62285703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA05E8453C60227ULL,
		0x0ED891C9BA48585BULL,
		0x3CEE3CB1610B3D6CULL,
		0x0AE1491A7CC2F0D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADDD0910360CE71BULL,
		0x6EE8F8A96C61EA44ULL,
		0x58A78087BFF078DCULL,
		0x2EA38702E5656631ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5F8062D56AA568B9ULL,
		0xBDB6099838303E6AULL,
		0x840D3F9682CFBC9AULL,
		0x017158D7E5CB756BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E403AC6AA0BF3A4ULL,
		0xE37649FA828E265FULL,
		0x49DE8DDDC9E8FF75ULL,
		0x411898AC359CD357ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF140280EC0997502ULL,
		0xDA3FBF9DB5A2180AULL,
		0x3A2EB1B8B8E6BD24ULL,
		0x4058C02BB02EA214ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xFF9C95BC854802F0ULL,
		0x80876B122E1F5FA9ULL,
		0xFF11DD370AFA5E91ULL,
		0x6FCA4F8D6B2E0B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A4449AD8670EDCBULL,
		0x30AEBB19169BD920ULL,
		0x19D7E5F0863A5F8EULL,
		0x23E57AD732441C83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5584C0EFED71525ULL,
		0x4FD8AFF917838689ULL,
		0xE539F74684BFFF03ULL,
		0x4BE4D4B638E9EF03ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1B291234FD2D7355ULL,
		0x228DB2763315A123ULL,
		0xB7016CD95E52D406ULL,
		0x4BEC8797A3B9B049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0482E9CCA6D31B89ULL,
		0x971324BFA72D8E41ULL,
		0xC2C9FDF95FA57CA7ULL,
		0x5B6A6F1E1FE564C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A62868565A57B9ULL,
		0x8B7A8DB68BE812E2ULL,
		0xF4376EDFFEAD575EULL,
		0x7082187983D44B80ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4B9FC94360BB928EULL,
		0x4CDEB14C24CC60F9ULL,
		0xB560FF99CE1E1EB9ULL,
		0x21C232A6C2AA5775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7160505B2B023CA4ULL,
		0xFF48D2A8AE376B64ULL,
		0x0F0B747A5A9E5016ULL,
		0x686ED195208FABCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA3F78E835B955D7ULL,
		0x4D95DEA37694F594ULL,
		0xA6558B1F737FCEA2ULL,
		0x39536111A21AABA7ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7DF0596D02FE77ACULL,
		0x25EF1C6C79652308ULL,
		0x71595D6B43330C0AULL,
		0x7E9E7D11D02E4203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F578FB72768D669ULL,
		0xA701D652DFC03C21ULL,
		0x6A9C7B8C0F3ECAE5ULL,
		0x37756AA6915EA9ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E98C9B5DB95A143ULL,
		0x7EED461999A4E6E7ULL,
		0x06BCE1DF33F44124ULL,
		0x4729126B3ECF9856ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE5F09DE8E2A4D210ULL,
		0x7CDB107A13065DC5ULL,
		0x0ADB68D5274072F2ULL,
		0x65B56C9321A97297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EA190A4D3A5F3DBULL,
		0x2ACA4EB2C34A6914ULL,
		0x0A56F658FFEC5830ULL,
		0x766C2186683A06B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x674F0D440EFEDE22ULL,
		0x5210C1C74FBBF4B1ULL,
		0x0084727C27541AC2ULL,
		0x6F494B0CB96F6BE4ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8C0BBB7EA967F3A8ULL,
		0xD6A0461748DF54BAULL,
		0xE9E0C4CBDED9BE59ULL,
		0x28C605DD82BB4A17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA7113B56DD4C320ULL,
		0xC668A993251CB5EEULL,
		0x09866A26BC5CF803ULL,
		0x7BCA47534483DBC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA19AA7C93B933075ULL,
		0x10379C8423C29ECBULL,
		0xE05A5AA5227CC656ULL,
		0x2CFBBE8A3E376E53ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9AAF6E4C504E1B08ULL,
		0xBF2F8981E9178DE5ULL,
		0x4B7FAB0FC2B6DC72ULL,
		0x13587FB8123889A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC53594CA5DD09FF6ULL,
		0x8312D2C42B6DE7D1ULL,
		0xC6E117B8723073EEULL,
		0x3ED9F8211938DAAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD579D981F27D7AFFULL,
		0x3C1CB6BDBDA9A613ULL,
		0x849E935750866884ULL,
		0x547E8796F8FFAEF4ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8EBE3D4256D5BDA6ULL,
		0x40065E0F67CE5A0CULL,
		0x28F972AB5E064CCDULL,
		0x3E29725924BD3F6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E3B91B4E2CEC05ULL,
		0xD84140ABC6A13C33ULL,
		0x27520059C67564EFULL,
		0x14513396EBDF0232ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5DA842708A8D1A1ULL,
		0x67C51D63A12D1DD8ULL,
		0x01A772519790E7DDULL,
		0x29D83EC238DE3D3BULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF7BCE24AEB06ADC1ULL,
		0x9A0759CB1ECDA4B1ULL,
		0x93A2EB9112042B29ULL,
		0x1DADEBC2BF780AECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7493E28A101BF0ULL,
		0x1AF5F431FF5639D0ULL,
		0x6381B80ED2BDE95AULL,
		0x3854C3BAC6D12130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C484E6860F691BEULL,
		0x7F1165991F776AE1ULL,
		0x302133823F4641CFULL,
		0x65592807F8A6E9BCULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8C826DC59F4B75A2ULL,
		0x99CF80462CEA5885ULL,
		0x518CE5CE3C0ADD5CULL,
		0x2D26CEA730B5F864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3177DEA74047F0ULL,
		0xD71BDAF7F4516AFEULL,
		0x831E555F8C5D5F5FULL,
		0x5B3BD3E5B460AD92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1050F5E6F80B2D9FULL,
		0xC2B3A54E3898ED87ULL,
		0xCE6E906EAFAD7DFCULL,
		0x51EAFAC17C554AD1ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x82012F40ED8651CEULL,
		0xC2C053354B764324ULL,
		0xCB4E0744A2D7D196ULL,
		0x78985FEB58746E99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EBE9FC881FEDE0FULL,
		0x3FEBDF6A6820E9F4ULL,
		0x4DEBE506B478B8F6ULL,
		0x494FF98B3F0FFFAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53428F786B8773BFULL,
		0x82D473CAE3555930ULL,
		0x7D62223DEE5F18A0ULL,
		0x2F48666019646EEAULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7AA4ED24CAA39D20ULL,
		0xEF59054EFF0272BEULL,
		0x9A690B76B4D9AA59ULL,
		0x26AC153E6D25FAF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D1C7A1A1F2400D9ULL,
		0x114845DDD5AA4096ULL,
		0x40BA2E410A35A5AEULL,
		0x6AF09ADA369BBA29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D88730AAB7F9C34ULL,
		0xDE10BF7129583228ULL,
		0x59AEDD35AAA404ABULL,
		0x3BBB7A64368A40CEULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1FAA3E960BF2447BULL,
		0xFFDCE1EDA735CBEAULL,
		0x8BFB19F433D95B69ULL,
		0x01E6D5EB754E3457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x358CD2612A345A82ULL,
		0x56315D837C63F607ULL,
		0x4CED6BA3E1AE8CA0ULL,
		0x2FAA349CB205258EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA1D6C34E1BDE9E6ULL,
		0xA9AB846A2AD1D5E2ULL,
		0x3F0DAE50522ACEC9ULL,
		0x523CA14EC3490EC9ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA65B2F41A526952AULL,
		0x8103B8674BD87F42ULL,
		0x29E1C6EF9627BAB8ULL,
		0x333F6FAE20FC8041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAEDFFBBE81A700AULL,
		0xF3112D4EB8EC690AULL,
		0x9443884F7B3B6785ULL,
		0x0744469720D47752ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB6D2F85BD0C2520ULL,
		0x8DF28B1892EC1637ULL,
		0x959E3EA01AEC5332ULL,
		0x2BFB2917002808EEULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1C0E91068621E79FULL,
		0xF74CFC21D21679BCULL,
		0x465F5D94A60AD472ULL,
		0x3534EBBCF0F5A0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C1A108648733993ULL,
		0x5AFBC570D46D7525ULL,
		0x104D032247311F42ULL,
		0x7EC97AFFC20813CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFF480803DAEADF9ULL,
		0x9C5136B0FDA90496ULL,
		0x36125A725ED9B530ULL,
		0x366B70BD2EED8CF5ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xAA9492B1663821EAULL,
		0x865124FA5F0C3088ULL,
		0x1D7E813AF63DB06BULL,
		0x36443F77004676F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12A5627A5A09F15ULL,
		0x9E9CA25882D4C803ULL,
		0x539E3B87C6FEC8FEULL,
		0x5140C2D47DAD8FE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x096A3C89C09782C2ULL,
		0xE7B482A1DC376885ULL,
		0xC9E045B32F3EE76CULL,
		0x65037CA28298E710ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x11BED4111C3AB79FULL,
		0x6D52B98EE100359EULL,
		0xE0C718D55FFFD9B0ULL,
		0x7EACB27AB59CA79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB64D509B940B0FULL,
		0xF045B72F481BB586ULL,
		0x4420D538B1E03370ULL,
		0x5661FD99226B6CD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x820886C080A6AC90ULL,
		0x7D0D025F98E48017ULL,
		0x9CA6439CAE1FA63FULL,
		0x284AB4E193313AC4ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE60FA8A0907628D2ULL,
		0xC327684BA3801447ULL,
		0xB7C52B74D4B0B596ULL,
		0x0CB5347AB20AEAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4C5AB75B9658EF9ULL,
		0x3138AC16E0B9F9F9ULL,
		0x90BDE129FCBD1D58ULL,
		0x550AEBD5DEC2A68EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4149FD2AD71099C6ULL,
		0x91EEBC34C2C61A4EULL,
		0x27074A4AD7F3983EULL,
		0x37AA48A4D3484460ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6A7BA581F364F4A2ULL,
		0x096AE9CA8B7184E8ULL,
		0x376D9945C9D799DAULL,
		0x5B3166CAE1AC2252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AD56C1E8D3FD5D2ULL,
		0xFAB6348733A25DF4ULL,
		0xDF5C0D6E1A90F43EULL,
		0x23D976678BABB6FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FA6396366251ED0ULL,
		0x0EB4B54357CF26F4ULL,
		0x58118BD7AF46A59BULL,
		0x3757F06356006B57ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xCF58A0475AD91DD0ULL,
		0xE3A19D1D989507BFULL,
		0xA9E598B25DB2DC99ULL,
		0x298E2F6C544B0AA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94A50B3E42CE4252ULL,
		0xF69E5AFA7C34517DULL,
		0xEA2F4E3E97588BC5ULL,
		0x0328941AA028E9FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AB39509180ADB7EULL,
		0xED0342231C60B642ULL,
		0xBFB64A73C65A50D3ULL,
		0x26659B51B42220A2ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xBF533A34F9B8A14DULL,
		0xB99F99375A4D797EULL,
		0x1B693B69E361F271ULL,
		0x0A0928C22FD001A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4F30575EF62760ULL,
		0x2C29923C6357F581ULL,
		0x3223A19687FB5673ULL,
		0x04F4F5B50EF8F69BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x420409DD9AC279EDULL,
		0x8D7606FAF6F583FDULL,
		0xE94599D35B669BFEULL,
		0x0514330D20D70B0DULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1EB3DF66D04CA983ULL,
		0xC5B6B379BB21CBA7ULL,
		0x22F47820E07345A6ULL,
		0x48154A6707F63FCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63548CB7359BB1DFULL,
		0x74E7310A1E1C7373ULL,
		0x3BEE54B677AAAB91ULL,
		0x1535F1CBD3DE0676ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB5F52AF9AB0F7A4ULL,
		0x50CF826F9D055833ULL,
		0xE706236A68C89A15ULL,
		0x32DF589B34183955ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7E979E21F78A5701ULL,
		0x6324E2C3E04F5483ULL,
		0xB8641B614ADB39CBULL,
		0x72F4EB16B960D8A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38FBD53189F7F1D5ULL,
		0x148B8E23FCBE3194ULL,
		0xDE993A431B9CBE6EULL,
		0x4479808EB95C4AE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x459BC8F06D92652CULL,
		0x4E99549FE39122EFULL,
		0xD9CAE11E2F3E7B5DULL,
		0x2E7B6A8800048DC0ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9795DA15CA4A8B1DULL,
		0x3871626F6F5E568EULL,
		0xACF91D765E5C84BEULL,
		0x2A3C1BB2A2CFE93BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7492ABE7EB078B8ULL,
		0xA2672160C548E764ULL,
		0x69F9EA6671632880ULL,
		0x7CC1FE256D5A4EFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB04CAF574B9A1252ULL,
		0x960A410EAA156F29ULL,
		0x42FF330FECF95C3DULL,
		0x2D7A1D8D35759A3DULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6B149D9D25CAECE0ULL,
		0x5BFAB1263FE565F6ULL,
		0xC60F4063032AB966ULL,
		0x6D4EA2455565F184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C22DBE0A2C8837CULL,
		0xFFB366C20A0633FAULL,
		0xB31CE8D90227B1CAULL,
		0x21368D0212C3D889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EF1C1BC83026964ULL,
		0x5C474A6435DF31FCULL,
		0x12F2578A0103079BULL,
		0x4C18154342A218FBULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC1129A9E2C4C0F3DULL,
		0x47C0C48B386EF3A8ULL,
		0x85B45A1AC7B38193ULL,
		0x7CA2D9C324B2CEC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9818FE0F06FDFDDCULL,
		0xCB3B7D04EF8E0C84ULL,
		0xF134096EF45B8A5CULL,
		0x310DB492F22AA627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28F99C8F254E1161ULL,
		0x7C85478648E0E724ULL,
		0x948050ABD357F736ULL,
		0x4B9525303288289EULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF1F4FB207122A0C4ULL,
		0xF6D549658BF599CDULL,
		0x81D3247499AD5C9AULL,
		0x0187441F0DA6104CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x832567C61D9277CDULL,
		0x17EA0D5DFF5B4E6FULL,
		0xA336722DDE2AB3A3ULL,
		0x65C930CEA1A65F59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ECF935A539028E4ULL,
		0xDEEB3C078C9A4B5EULL,
		0xDE9CB246BB82A8F7ULL,
		0x1BBE13506BFFB0F2ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1E77ADA71122937AULL,
		0x0D828183C11B01A5ULL,
		0xA511CF1E10801C97ULL,
		0x351DC0787CAD7EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF384ED2CFD3C6D01ULL,
		0x51C515DDCAAF1092ULL,
		0x63CE3B5D8ADCCFB3ULL,
		0x4F9E7C8F4897A7CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AF2C07A13E62666ULL,
		0xBBBD6BA5F66BF112ULL,
		0x414393C085A34CE3ULL,
		0x657F43E93415D732ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x989A7D4DE0330061ULL,
		0x4F27B9A6C79C7359ULL,
		0x081F2505559A5C9CULL,
		0x3D73713495AF24BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B73EB44B653279EULL,
		0x5A691BCEF939927EULL,
		0xC0CF52CC72174044ULL,
		0x5A0E44772393FE04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D26920929DFD8B0ULL,
		0xF4BE9DD7CE62E0DBULL,
		0x474FD238E3831C57ULL,
		0x63652CBD721B26B8ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0E8E5480EB2076D6ULL,
		0xABA5B037FFAF0059ULL,
		0x39F26EF4B83C7D72ULL,
		0x3079643D8CD4F6CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4BED76174885D0ULL,
		0xDB22B042AA50886DULL,
		0x6D17A8A75B611A01ULL,
		0x0036BD1269E5551BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB142670AD3D7F106ULL,
		0xD082FFF5555E77EBULL,
		0xCCDAC64D5CDB6370ULL,
		0x3042A72B22EFA1AEULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC756C170595DB59BULL,
		0x25E76F747FE308F3ULL,
		0xC87078136FD48AFCULL,
		0x5CCA2A601D7DA40CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEDCF3A7A7D01F9CULL,
		0xE99E6E2EE525E769ULL,
		0xBC2248BDCA357700ULL,
		0x28FA56BDC0C5958BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1879CDC8B18D95FFULL,
		0x3C4901459ABD218AULL,
		0x0C4E2F55A59F13FBULL,
		0x33CFD3A25CB80E81ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x093564B8F37B1F1BULL,
		0xDAF69280D8425257ULL,
		0x3EA878FEE1C3F08BULL,
		0x1C60224DE9C5CE2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7019975CE6D07BBULL,
		0x4585466952F7D768ULL,
		0xF8914BE2A27CFA83ULL,
		0x4B67D1B195756430ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5233CB43250E174DULL,
		0x95714C17854A7AEEULL,
		0x46172D1C3F46F608ULL,
		0x50F8509C545069FDULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE8DA6CAC7AF05B2BULL,
		0xA58EF793D00EC67EULL,
		0x4D991298E85D1CE2ULL,
		0x45C1D322275887C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDEC05D17AEE4FC2ULL,
		0x0DA3579C7035A102ULL,
		0xA8266445680DE6FBULL,
		0x6B095B06BB67F0CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AEE66DB00020B56ULL,
		0x97EB9FF75FD9257CULL,
		0xA572AE53804F35E7ULL,
		0x5AB8781B6BF096FBULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF91063F1B744EBCAULL,
		0xFB26340F562BE7D3ULL,
		0xBAA680D1EFBF8B7FULL,
		0x63E6D82CA9287AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EFA83F300C1E4E3ULL,
		0x327882D7BD5D2B2AULL,
		0xE937C54E86B43754ULL,
		0x38702EF058EA8601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A15DFFEB68306E7ULL,
		0xC8ADB13798CEBCA9ULL,
		0xD16EBB83690B542BULL,
		0x2B76A93C503DF4F9ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE59AEF0BD03AEBC8ULL,
		0x40776676EBEBD5A9ULL,
		0xCCAA019D0E8EB4D6ULL,
		0x49FC6F835BBD1836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B858DC5DFC801CULL,
		0xD7788DFB5F19F57BULL,
		0xE97D05527ED73F71ULL,
		0x441B0C0DCF03E975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FE2962F723E6BACULL,
		0x68FED87B8CD1E02EULL,
		0xE32CFC4A8FB77564ULL,
		0x05E163758CB92EC0ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3F0CECA5D0D502ADULL,
		0x32DE3F5845AD6A41ULL,
		0x56097664DEA9EA73ULL,
		0x7E40EEA3A755ABD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146E5CED6A9AAFF9ULL,
		0x8DAA6935BEC52734ULL,
		0xBDCE509E42B67AECULL,
		0x1E07805B1A56F0D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A9E8FB8663A52B4ULL,
		0xA533D62286E8430DULL,
		0x983B25C69BF36F86ULL,
		0x60396E488CFEBAFFULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA5A5857B5C5500FCULL,
		0x6DC6E1951CB706A4ULL,
		0x714FE77A50B221DAULL,
		0x22E32808B3554CC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86FB3DE624610977ULL,
		0x7CF9FECF85301397ULL,
		0xA0934D4C33173294ULL,
		0x0F0C7F6E5D4758E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EAA479537F3F785ULL,
		0xF0CCE2C59786F30DULL,
		0xD0BC9A2E1D9AEF45ULL,
		0x13D6A89A560DF3DBULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x664CCD68316FC1EEULL,
		0x0FD878C288E919EBULL,
		0x86E7DE2DAAEFD92CULL,
		0x048975708913F940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50442BF44B9FAA23ULL,
		0xA3FC94FC302569CBULL,
		0x3274009351C67E58ULL,
		0x5925BF99A2E22959ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1608A173E5D017B8ULL,
		0x6BDBE3C658C3B020ULL,
		0x5473DD9A59295AD3ULL,
		0x2B63B5D6E631CFE7ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF103685B06A37323ULL,
		0x4D88C5C0B7B7C2C2ULL,
		0xB31111CE81AAF871ULL,
		0x61C1299509300911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00833E87DF5FEFFULL,
		0x5EC06E65713CD40AULL,
		0x3E6188B2F1880696ULL,
		0x557D2152CB650702ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00FB347288AD7424ULL,
		0xEEC8575B467AEEB8ULL,
		0x74AF891B9022F1DAULL,
		0x0C4408423DCB020FULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x131D7B6909A4A79AULL,
		0xD165E2FE11BB6878ULL,
		0x5FF746E13AC649D2ULL,
		0x43B8CF8331E0DEFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3412A487813A09ULL,
		0x66E50F938D11D2B6ULL,
		0xDD77D9FA53FDA93DULL,
		0x2105C9CD64072315ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8E968C482236D91ULL,
		0x6A80D36A84A995C1ULL,
		0x827F6CE6E6C8A095ULL,
		0x22B305B5CDD9BBE6ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5DFB22A0DB4A615AULL,
		0x28C7B381CCD39686ULL,
		0x77F5B617E3EFEE23ULL,
		0x483CE11F939596CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AFF539685196830ULL,
		0xBD8C6EA4194D4B19ULL,
		0x19ADAA0A36B4098EULL,
		0x3FED668239638E54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2FBCF0A5630F92AULL,
		0x6B3B44DDB3864B6CULL,
		0x5E480C0DAD3BE494ULL,
		0x084F7A9D5A320876ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3A35E891207AD62CULL,
		0xE37D21A6D55A7117ULL,
		0x85BB76A2A0402E43ULL,
		0x7F02FD56E20B47C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6506C0A1A2741D4FULL,
		0x57C76948E8CFFD31ULL,
		0xAE618117E73AEA96ULL,
		0x206FBA56A0AEE889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD52F27EF7E06B8DDULL,
		0x8BB5B85DEC8A73E5ULL,
		0xD759F58AB90543ADULL,
		0x5E934300415C5F39ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7AAC94E2DF32132AULL,
		0x9A59A1372EBCAB8CULL,
		0xB713547E433B867BULL,
		0x48BA805B411273B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516944247EC3374AULL,
		0x7AA9EDFC83B5E5CCULL,
		0x24DF4A334CE27BBCULL,
		0x30CCFCA7699FC84EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x294350BE606EDBE0ULL,
		0x1FAFB33AAB06C5C0ULL,
		0x92340A4AF6590ABFULL,
		0x17ED83B3D772AB6BULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x261447AEFC222AD0ULL,
		0x55DA2C79DAE8B2E8ULL,
		0x91DB6EB3B4B622B6ULL,
		0x2092D440058D898BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE0D76561C1E3453ULL,
		0xA4511F175D13882EULL,
		0xF47D49B1F0667852ULL,
		0x0AC666C7819448E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7806D158E003F67DULL,
		0xB1890D627DD52AB9ULL,
		0x9D5E2501C44FAA63ULL,
		0x15CC6D7883F940A2ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x61AC20469D2A90DFULL,
		0x5A7228748013C904ULL,
		0x8A9F59F92CF88802ULL,
		0x5200F5B568A8C798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A663A97B9CD4DE1ULL,
		0x245CC4BCD15B9009ULL,
		0xCCEF3169FAD4E346ULL,
		0x695BE9DFEFC91B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF745E5AEE35D42EBULL,
		0x361563B7AEB838FAULL,
		0xBDB0288F3223A4BCULL,
		0x68A50BD578DFAC6CULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7349DFF183112F8BULL,
		0x6F688EEAB585B247ULL,
		0x356D46CAF0832774ULL,
		0x08648B69B501ED4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97096798657BFD1CULL,
		0x3AB080F487515D81ULL,
		0x9169B1FF72EEEE47ULL,
		0x577D3A50122328C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC4078591D95325CULL,
		0x34B80DF62E3454C5ULL,
		0xA40394CB7D94392DULL,
		0x30E75119A2DEC487ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE6F0D1A71EFAB107ULL,
		0x50F7F876002830ACULL,
		0x0318791A6391F774ULL,
		0x660021322F7BFA4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F9BB6A8F188B7CULL,
		0x8C1F5163CC02B386ULL,
		0xC57101710AEE6D97ULL,
		0x7E2EC8F389FBCD4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DF7163C8FE22578ULL,
		0xC4D8A71234257D26ULL,
		0x3DA777A958A389DCULL,
		0x67D1583EA5802D02ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB1FEB624CB7C8F48ULL,
		0x857498EFEB476179ULL,
		0x894C5B5A086F4452ULL,
		0x332F28A8C67D1004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71243370D699A7DULL,
		0x7B1F9CE7F49505B6ULL,
		0x9C048A3EB6F4894EULL,
		0x7B12684C5901B71EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAEC72EDBE12F4B8ULL,
		0x0A54FC07F6B25BC2ULL,
		0xED47D11B517ABB04ULL,
		0x381CC05C6D7B58E5ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x81F50110DA5A22EEULL,
		0xD1C29764AF22F57EULL,
		0xDB06C6BF274DEE28ULL,
		0x2FBA7F9446B2A9F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF5EA91B5D49F3EULL,
		0xDEC00EF75DDFD153ULL,
		0x047983668404C736ULL,
		0x3D70E646BD92D85DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4FF167F2485839DULL,
		0xF302886D5143242AULL,
		0xD68D4358A34926F1ULL,
		0x7249994D891FD19CULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6E9360E4D14FFCD1ULL,
		0x13C37370A7DD9137ULL,
		0x0923B1698BD94BD2ULL,
		0x1EE09959E5A37B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADF6104B030E963ULL,
		0x9FB6A059373930B5ULL,
		0x33F3E54F49B178EDULL,
		0x62F31926A614377FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3B3FFE0211F135BULL,
		0x740CD31770A46081ULL,
		0xD52FCC1A4227D2E4ULL,
		0x3BED80333F8F43A1ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE79761D7EE8D7CC8ULL,
		0x3B48A3591D02CE9FULL,
		0x78FF57A0B635BB20ULL,
		0x7C246D775E20232FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BAC20D4CCEA3F4ULL,
		0xB0944252E7A18D16ULL,
		0xA3BC8033247533B2ULL,
		0x6043200BAD7F4654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24DC9FCAA1BED8D4ULL,
		0x8AB4610635614189ULL,
		0xD542D76D91C0876DULL,
		0x1BE14D6BB0A0DCDAULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xAF2369E6F156CDCAULL,
		0x6169EE9C73940BC5ULL,
		0xC8C55C621F730E22ULL,
		0x13232BD176E778C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x275296D696CC206FULL,
		0x6F88E9B0BBDAFF63ULL,
		0x08748298938B5602ULL,
		0x3C2DFBC42B7921AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87D0D3105A8AAD48ULL,
		0xF1E104EBB7B90C62ULL,
		0xC050D9C98BE7B81FULL,
		0x56F5300D4B6E5715ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x82BEAFDD93236B37ULL,
		0xAF0EFA90985F4A14ULL,
		0x78AEA8BBB2AC9B3BULL,
		0x5D1B99E59700FFDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB24268157C55869FULL,
		0x70A231CF51A61880ULL,
		0xBB8A759DB249555EULL,
		0x22A9D05C02ACCE14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD07C47C816CDE498ULL,
		0x3E6CC8C146B93193ULL,
		0xBD24331E006345DDULL,
		0x3A71C989945431C6ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x13E07BFF4B482AF3ULL,
		0xBF2F88C0D19F1C13ULL,
		0x628EA70A0C672F3FULL,
		0x321C9FE306EBA825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x271CA395DA480261ULL,
		0x746AA034D30C73C9ULL,
		0x75D359A89506C2B0ULL,
		0x1D754AE4FE80EA6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECC3D86971002892ULL,
		0x4AC4E88BFE92A849ULL,
		0xECBB4D6177606C8FULL,
		0x14A754FE086ABDB8ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x974EA9EB7A8D7C47ULL,
		0x5C47FF7627F3C60EULL,
		0xD91890058AFD6D13ULL,
		0x089567CA369C94E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342F33B6F5E390E4ULL,
		0x785B8EC97937D262ULL,
		0x339389AAED25D499ULL,
		0x1EE6AE1283252B4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x631F763484A9EB50ULL,
		0xE3EC70ACAEBBF3ACULL,
		0xA585065A9DD79879ULL,
		0x69AEB9B7B3776998ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7394EF864D87CAD2ULL,
		0xFAF1E320CA983E32ULL,
		0xAE04E2B709E74D17ULL,
		0x5EF85F981EB2D934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0209194A7540A5CBULL,
		0x0C8E7975F64F571AULL,
		0x40FCA152972A9232ULL,
		0x26E2CD470B4A7F62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x718BD63BD8472507ULL,
		0xEE6369AAD448E718ULL,
		0x6D08416472BCBAE5ULL,
		0x38159251136859D2ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x929226DC4401CE97ULL,
		0x1AA19BDA07163F49ULL,
		0x6E00C1951EF8DABCULL,
		0x295B943507C1BD73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D13F19282C75C60ULL,
		0x3D5F5E1F110AD21BULL,
		0xA5A63C1E2E4EF8EEULL,
		0x3F2716E66D6C57CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF57E3549C13A7224ULL,
		0xDD423DBAF60B6D2DULL,
		0xC85A8576F0A9E1CDULL,
		0x6A347D4E9A5565A3ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4A95CBDFD1821862ULL,
		0xF30AB560336038CDULL,
		0xAF288EC4FBFF9F1BULL,
		0x0D3A1EE46E1B8B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C1CF1607C3F6B3ULL,
		0x268DB260249C2D9FULL,
		0xDE6A66F84C8D5FEAULL,
		0x51CF4034E68BA4A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D3FCC9C9BE219CULL,
		0xCC7D03000EC40B2DULL,
		0xD0BE27CCAF723F31ULL,
		0x3B6ADEAF878FE660ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4D3D5AC68B4A8ED0ULL,
		0x60F3425A4F1BD80AULL,
		0xCBD818EFC98116A1ULL,
		0x1936AD3756FB9D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303B3FCD8E9AEA33ULL,
		0x5180D172E35D4A45ULL,
		0x91DD489B56C482A5ULL,
		0x13B816FEC94344DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D021AF8FCAFA49DULL,
		0x0F7270E76BBE8DC5ULL,
		0x39FAD05472BC93FCULL,
		0x057E96388DB8587EULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x33DCC2983FF6FF72ULL,
		0x20BBEA75563869AFULL,
		0x42E56AB8139315DEULL,
		0x65CAFA411FF9D2A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA21D4B27F549A041ULL,
		0xE1A8F3F20580DC42ULL,
		0x6E0474061E680386ULL,
		0x02410DEDE6CAEDAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91BF77704AAD5F31ULL,
		0x3F12F68350B78D6CULL,
		0xD4E0F6B1F52B1257ULL,
		0x6389EC53392EE4F8ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x064D73E790FA6D91ULL,
		0xEEBA8A03F20B7707ULL,
		0x23DADE4151201414ULL,
		0x1B45CE149638A83DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCF25509145DA88ULL,
		0xCBAE28F0BA3279AEULL,
		0x12D2487BA61279FFULL,
		0x0E4EB4473753713AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA7E4E96FFB49309ULL,
		0x230C611337D8FD58ULL,
		0x110895C5AB0D9A15ULL,
		0x0CF719CD5EE53703ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5FE5BFCDF13478FEULL,
		0xE619B9A6EE596422ULL,
		0xDE7CDE42E15F31F9ULL,
		0x3814E9983EC1505EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x155BFA194F4D33D4ULL,
		0x273A19A49AD8A715ULL,
		0x49D1C035ABEA52F2ULL,
		0x7B1AA7327B373025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A89C5B4A1E74517ULL,
		0xBEDFA0025380BD0DULL,
		0x94AB1E0D3574DF07ULL,
		0x3CFA4265C38A2039ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x39BF2894B5C803C8ULL,
		0x0344357D58FB3F06ULL,
		0x8CC57D43F8164105ULL,
		0x6600A8F15E5E0414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAFC3D386D3CEEE1ULL,
		0x8CD93F045727B90FULL,
		0x5CD293C419AAF283ULL,
		0x53A338890A8DAE2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EC2EB5C488B14E7ULL,
		0x766AF67901D385F6ULL,
		0x2FF2E97FDE6B4E81ULL,
		0x125D706853D055E6ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x15BCB3D85FDF8223ULL,
		0x2E41F6AB3519E3B0ULL,
		0x61E592DE94AB4BD3ULL,
		0x3AF366B5538B6A69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78EBED47A5B8C64EULL,
		0x6844A265EB7DB460ULL,
		0x42613AF6472C25F7ULL,
		0x498376BDD14345CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CD0C690BA26BBC2ULL,
		0xC5FD5445499C2F4FULL,
		0x1F8457E84D7F25DBULL,
		0x716FEFF78248249FULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x82F50C5E81A4A837ULL,
		0xB43E5AD2AE771C7AULL,
		0xDE0C3060170A1D8BULL,
		0x4DB6967806C9C78CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A9BFB724D10D02ULL,
		0xBD94C1CEF35B99CDULL,
		0xB6A00809A9EF7FC0ULL,
		0x74FD90E5048B7234ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x924B4CA75CD39B22ULL,
		0xF6A99903BB1B82ACULL,
		0x276C28566D1A9DCAULL,
		0x58B90593023E5558ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x56ABE939B163927DULL,
		0x472994240A05B4F2ULL,
		0xAE41892B01DD1510ULL,
		0x580A0FE8B17F7526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E696732C38949D2ULL,
		0x86F69B7C993D04C5ULL,
		0x949583283A6B84E8ULL,
		0x0474A4E349CCCCB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8428206EDDA48ABULL,
		0xC032F8A770C8B02CULL,
		0x19AC0602C7719027ULL,
		0x53956B0567B2A870ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB914C5055EA94EC5ULL,
		0xB293B79AA0248577ULL,
		0xB9B352CC0742690FULL,
		0x2F0AFDC2CAEF78B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4654A39B2B7D85FCULL,
		0x97088BCA17C04285ULL,
		0xFFE244AC2F5C3705ULL,
		0x3B050EE514688200ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72C0216A332BC8B6ULL,
		0x1B8B2BD0886442F2ULL,
		0xB9D10E1FD7E6320AULL,
		0x7405EEDDB686F6B6ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9D98304F49051C4BULL,
		0x8B6B4286C6C905B3ULL,
		0x1C2A0F5C782FB20DULL,
		0x0384A942AD043B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BCEB43D80B3095CULL,
		0xD7666A6CA2276847ULL,
		0xBCD27E07AB19F962ULL,
		0x0C5632222E577788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51C97C11C85212DCULL,
		0xB404D81A24A19D6CULL,
		0x5F579154CD15B8AAULL,
		0x772E77207EACC3F5ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x39A128FD7FCBCD49ULL,
		0x6401FA5391F0B12AULL,
		0xE15B15D2561789F9ULL,
		0x58200053F3AE9D14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C27063FBC0E7D65ULL,
		0x92751B2D4A43C1F3ULL,
		0xA79F1AF909EB48FFULL,
		0x1B59986099B79DFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D7A22BDC3BD4FE4ULL,
		0xD18CDF2647ACEF37ULL,
		0x39BBFAD94C2C40F9ULL,
		0x3CC667F359F6FF17ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4F04F30173363DEBULL,
		0x885DD30DC0940BC8ULL,
		0xF55A94AB697838B3ULL,
		0x7598A475AB5AAD63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428DFC627B5CBFE9ULL,
		0xF06B67070828A501ULL,
		0x3A71DA48F4AD5A79ULL,
		0x0A62510B0D095795ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C76F69EF7D97E02ULL,
		0x97F26C06B86B66C7ULL,
		0xBAE8BA6274CADE39ULL,
		0x6B36536A9E5155CEULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA3AA56B9015B1F14ULL,
		0xEC3E1C255724AE68ULL,
		0x7399ED853FDB6324ULL,
		0x1851BC4F2E84E139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BB8D78EAB8D27FFULL,
		0x2F5BCE40FD814A87ULL,
		0xB1B923C17DA5D795ULL,
		0x211F90E888CB1F87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77F17F2A55CDF702ULL,
		0xBCE24DE459A363E1ULL,
		0xC1E0C9C3C2358B8FULL,
		0x77322B66A5B9C1B1ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xEB59E775C22F2A44ULL,
		0x5C1660742166420EULL,
		0x75E26A6569B3EB20ULL,
		0x1B8A3FC56D01A202ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79723197463B5C1CULL,
		0xF2C3099C3BD9516FULL,
		0x03563AED9EDE21BEULL,
		0x26C9EA81CBBF9D87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71E7B5DE7BF3CE15ULL,
		0x695356D7E58CF09FULL,
		0x728C2F77CAD5C961ULL,
		0x74C05543A142047BULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x20A58D073F4AE876ULL,
		0x5D96920B34AF4D8FULL,
		0x1BB3E9382F5FDC2BULL,
		0x61222F693C0AE507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16403208DE89B5A7ULL,
		0xD7ECEB5260A7317EULL,
		0x1ADC10F87A42B212ULL,
		0x649858668A81CEC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A655AFE60C132BCULL,
		0x85A9A6B8D4081C11ULL,
		0x00D7D83FB51D2A18ULL,
		0x7C89D702B1891643ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA3CF08598226CB6DULL,
		0xA39B2BF7374B9C37ULL,
		0xD85F0C534D6CC9AFULL,
		0x461513CE87F54511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F68369DC75711A0ULL,
		0x4B9B2E972BD269DCULL,
		0x5F09FFB3512F5C64ULL,
		0x7A3685DDA3770D00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2466D1BBBACFB9BAULL,
		0x57FFFD600B79325BULL,
		0x79550C9FFC3D6D4BULL,
		0x4BDE8DF0E47E3811ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x05D1F53404FB469DULL,
		0x6F273D6C035098D7ULL,
		0x0E175D4BB3BF43A1ULL,
		0x40CD3ACF3BFEAB0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD713BEDAF957973ULL,
		0xE49CC263C557C97FULL,
		0x0A37EAC4B69B68B3ULL,
		0x62059E048CEE4B04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3860B9465565CD17ULL,
		0x8A8A7B083DF8CF57ULL,
		0x03DF7286FD23DAEDULL,
		0x5EC79CCAAF106007ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8DA09F0274F95631ULL,
		0x9107D2D552B11243ULL,
		0x42792F69767FF536ULL,
		0x6836AA54B7D4018DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D35490E038F7312ULL,
		0xD250BFFB4EE3ADD4ULL,
		0xFE4BA1A27682085BULL,
		0x3B4025511518F773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x206B55F47169E31FULL,
		0xBEB712DA03CD646FULL,
		0x442D8DC6FFFDECDAULL,
		0x2CF68503A2BB0A19ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1865E159DC3C46CDULL,
		0xE5F57EF811E9CD14ULL,
		0x955E75A4FCD4564DULL,
		0x77815612DB54BDD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DBB13C580CC38F3ULL,
		0x30CA31AE551B2FBFULL,
		0xD26915A5128508A1ULL,
		0x1103492CDE559B4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAAACD945B700DDAULL,
		0xB52B4D49BCCE9D54ULL,
		0xC2F55FFFEA4F4DACULL,
		0x667E0CE5FCFF2280ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6EBD29758F08FCC9ULL,
		0xC9E4EF608DB0B995ULL,
		0xDB96A8FDD8E98BC1ULL,
		0x1711DB7C441FF8C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13617A4E593CCC9ULL,
		0x4C4BDC3D20A4098AULL,
		0x543C80D4EE2C96AAULL,
		0x36B217A95AE3158AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D8711D0A9752FEDULL,
		0x7D9913236D0CB00AULL,
		0x875A2828EABCF517ULL,
		0x605FC3D2E93CE33DULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xFED628EDE08CC41AULL,
		0x770FCEEC4EFF60B8ULL,
		0x208E7786B30C38E7ULL,
		0x52770C296BC17BDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C92B02A6C0430B6ULL,
		0x93E25A0B901BF7CFULL,
		0x7740F58800C97D3CULL,
		0x0868EC62B78897C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x624378C374889364ULL,
		0xE32D74E0BEE368E9ULL,
		0xA94D81FEB242BBAAULL,
		0x4A0E1FC6B438E414ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4A36DFC23FA8C524ULL,
		0x5E1876D8B49FE56CULL,
		0xF121AFA5349C8988ULL,
		0x029139B1140BAD64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1283ABFC49BE6200ULL,
		0x651C9F8269B552A4ULL,
		0x2ABA3C6B4685BB79ULL,
		0x2FA0E20380998752ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37B333C5F5EA6311ULL,
		0xF8FBD7564AEA92C8ULL,
		0xC6677339EE16CE0EULL,
		0x52F057AD93722612ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x29E1C6DD57BA45EDULL,
		0x90D54AC4F64B9DD9ULL,
		0x60AB7AB4ACFFCFD0ULL,
		0x330C0A75F94824EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EF24BF63BA70D1ULL,
		0x675CAB4D5F5F73CBULL,
		0x7CC0C5DD192F60C2ULL,
		0x68ABF842D786738FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5F2A21DF3FFD509ULL,
		0x29789F7796EC2A0DULL,
		0xE3EAB4D793D06F0EULL,
		0x4A60123321C1B15EULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x34D127B64D8E1D66ULL,
		0x7C1DD71728B674D0ULL,
		0xC3FD6840ACF7EC49ULL,
		0x392FFFF9591CD728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x656956FC03546875ULL,
		0x05F6E8130CAD06A3ULL,
		0xBEDF7B64C4A7A22CULL,
		0x63AD8CD5500516FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF67D0BA4A39B4DEULL,
		0x7626EF041C096E2CULL,
		0x051DECDBE8504A1DULL,
		0x558273240917C02AULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA5D0D689F89A60D3ULL,
		0xE8E17EB820F7B104ULL,
		0xCE245AAB2EF7990AULL,
		0x475610831B6C57F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B5AE155A2FD2BEBULL,
		0xC8F572891458888CULL,
		0x7D252C657C788DFFULL,
		0x7DF36B732454DC57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A75F534559D34D5ULL,
		0x1FEC0C2F0C9F2878ULL,
		0x50FF2E45B27F0B0BULL,
		0x4962A50FF7177B9CULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9A9BFCFF5C5A115EULL,
		0x2CF8F3FC88456E9AULL,
		0x158E3CD7430BCD64ULL,
		0x48FAE59A67EF2072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x560275DAA63744BEULL,
		0x7C688C1D16ECB2BDULL,
		0x047FF77107A1ADC9ULL,
		0x197E976A87C11620ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44998724B622CCA0ULL,
		0xB09067DF7158BBDDULL,
		0x110E45663B6A1F9AULL,
		0x2F7C4E2FE02E0A52ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xCD3F34C2A7B5747BULL,
		0xEE0A2936B765AD9BULL,
		0x5CD44C11892ABD91ULL,
		0x4D8B985B90221B9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12B4B016A1496C9CULL,
		0x467758EC75B00152ULL,
		0xCACD14B8FF92B45FULL,
		0x45CB5BDBE38E3B72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA8A84AC066C07DFULL,
		0xA792D04A41B5AC49ULL,
		0x9207375889980932ULL,
		0x07C03C7FAC93E027ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA831F323F230B6BAULL,
		0x9CE1AE4A7211B787ULL,
		0x485FC4888CF2B771ULL,
		0x08EB5BA8B4606AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5463499CAB9DC19ULL,
		0x2ED738B18A1C9B92ULL,
		0x2E1C1B8DC2DBAE2BULL,
		0x512F09497D600DC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2EBBE8A2776DA8EULL,
		0x6E0A7598E7F51BF4ULL,
		0x1A43A8FACA170946ULL,
		0x37BC525F37005CE8ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7121A3BD3AC0982CULL,
		0x75F569A8B0B22A0FULL,
		0x016A41BAB7962146ULL,
		0x600FBFE57B46E407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B98FEB7ACED4DEULL,
		0x3A20174E990DF872ULL,
		0xAB4286A87135108AULL,
		0x707473EADF5A2772ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD06813D1BFF1C33BULL,
		0x3BD5525A17A4319CULL,
		0x5627BB12466110BCULL,
		0x6F9B4BFA9BECBC94ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9EDF8908EC3FC4B6ULL,
		0x594B87F54843B293ULL,
		0x95ADDDE45CB9523BULL,
		0x397C4D4D219A2DCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD23C6F3879B976B5ULL,
		0x22A7A36360B1824DULL,
		0xF4209CB598EF0709ULL,
		0x2013BD1D775501A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCA319D072864E01ULL,
		0x36A3E491E7923045ULL,
		0xA18D412EC3CA4B32ULL,
		0x1968902FAA452C20ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xCE142F71A54DF9DEULL,
		0x6C0CA1254D7773CDULL,
		0x129ED889136F9402ULL,
		0x10927CC4215569C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x443C5686A01B4698ULL,
		0x7CE02DF4001CF168ULL,
		0x8D23E89FE9568AFDULL,
		0x430A5BEBBA11218DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89D7D8EB0532B333ULL,
		0xEF2C73314D5A8265ULL,
		0x857AEFE92A190904ULL,
		0x4D8820D867444832ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x522798D0D5B5A907ULL,
		0xFFEAB6E395EB95FAULL,
		0xA1C83D0EC4206C6DULL,
		0x2F465F927D40CD7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C624BF69F4542EULL,
		0x9CDEC051603BA2ACULL,
		0x89099F222DF43850ULL,
		0x0863DFA5C438D7E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x686174116BC154D9ULL,
		0x630BF69235AFF34DULL,
		0x18BE9DEC962C341DULL,
		0x26E27FECB907F596ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x09D2B3D13E0B3925ULL,
		0xC1E56DFA5BBDF78DULL,
		0x0E17051504D6B0D5ULL,
		0x5F87097742F2A4F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB3406A311D53B5ULL,
		0x353E41B6523912D5ULL,
		0x092E040366178965ULL,
		0x75B7CF9B2A8DDC98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B1F73670CEDE55DULL,
		0x8CA72C440984E4B7ULL,
		0x04E901119EBF2770ULL,
		0x69CF39DC1864C85DULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x2627E6DB874FCE9CULL,
		0x17DD300283F7A4B1ULL,
		0x125ED7A3B7E1B523ULL,
		0x3B06CA360434D6CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F110C16C91738AULL,
		0x7603F0FDE63C5D4DULL,
		0x1C3AB97B10347F9BULL,
		0x2E0D67BB10581AC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C36D61A1ABE5B12ULL,
		0xA1D93F049DBB4763ULL,
		0xF6241E28A7AD3587ULL,
		0x0CF9627AF3DCBC09ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8A347DCC48100CD5ULL,
		0x78747DB7FD4A635BULL,
		0xA14DCA5BCA84E724ULL,
		0x1D153C0F0528C2D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x741F1F294DF9F84EULL,
		0x431B14C992A12B0BULL,
		0xFACD23D57DDE1F17ULL,
		0x463111B9646E9D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16155EA2FA161474ULL,
		0x355968EE6AA93850ULL,
		0xA680A6864CA6C80DULL,
		0x56E42A55A0BA2562ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE328CCDEAB418894ULL,
		0x756ACC0B9A3FD04DULL,
		0x43ABE4C01E5D7C70ULL,
		0x1E6DE5B33C2B8563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF73586D8C06F7BBULL,
		0xD92AC5CD8FE6120AULL,
		0xE29B61A462AB24D1ULL,
		0x4D8920D505A59BB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3B574711F3A90C6ULL,
		0x9C40063E0A59BE42ULL,
		0x6110831BBBB2579EULL,
		0x50E4C4DE3685E9A9ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x34E28906588FF4F1ULL,
		0xFC9A91121840B17CULL,
		0x7994F562B00B1CF5ULL,
		0x1A199AE4B2F27FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDDD98CFD99DA830ULL,
		0x672C832EDD0BCC16ULL,
		0x5DCBF4FFF1A021DAULL,
		0x20E731F2976F3DB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5704F0367EF24CAEULL,
		0x956E0DE33B34E565ULL,
		0x1BC90062BE6AFB1BULL,
		0x793268F21B834227ULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x8BBE5AC7380DC9D2ULL,
		0x278829D370029918ULL,
		0x601CB87B12F66675ULL,
		0x79227314C9D5D8DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0A26762BF2E7CD6ULL,
		0xF0DE5069F187C03EULL,
		0xD4ABE6A162F0F528ULL,
		0x1F335701FFB633D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB1BF36478DF4CFCULL,
		0x36A9D9697E7AD8D9ULL,
		0x8B70D1D9B005714CULL,
		0x59EF1C12CA1FA508ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x95A018DDDA74073AULL,
		0x60FCEF2B6BF2A293ULL,
		0x78FC9B09592DFAB1ULL,
		0x333DE4999C8605F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6989A05F422A07E5ULL,
		0xB5164D4FDACD4F8DULL,
		0xC3E71326B0206AF3ULL,
		0x57B91DB161DBD321ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C16787E9849FF42ULL,
		0xABE6A1DB91255306ULL,
		0xB51587E2A90D8FBDULL,
		0x5B84C6E83AAA32D2ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xED527AF0C61E3366ULL,
		0xACBAAF46C451D1A8ULL,
		0xD07C502E99FE1823ULL,
		0x1F4E2EB6371A3970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9259609BD7BDFCBULL,
		0x86EF974BD646E43CULL,
		0x6DAD37A8F5500731ULL,
		0x0592FD94B3B8B2E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x242CE4E708A2539BULL,
		0x25CB17FAEE0AED6CULL,
		0x62CF1885A4AE10F2ULL,
		0x19BB31218361868FULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF7DF1C776A6D675EULL,
		0x89B8BBF622508905ULL,
		0xD3BD2A419CD868B2ULL,
		0x3A67CE427A0B016FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9907EA8B1E655024ULL,
		0x81EFB6F29D598DA3ULL,
		0xBFFF898637521A25ULL,
		0x5C7DE80401DF67B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ED731EC4C081727ULL,
		0x07C9050384F6FB62ULL,
		0x13BDA0BB65864E8DULL,
		0x5DE9E63E782B99BEULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x87AF13B176694AF5ULL,
		0x15AD9A6E8D1F7878ULL,
		0xB4D45966539E7E1AULL,
		0x4C63514785504D04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A122D192CFFE74ULL,
		0x38E3213BEAE26AE7ULL,
		0x3BC9E559F4DC0758ULL,
		0x07BF41E802650D77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E0DF0DFE3994C81ULL,
		0xDCCA7932A23D0D91ULL,
		0x790A740C5EC276C1ULL,
		0x44A40F5F82EB3F8DULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x05F4047E1DC1CE73ULL,
		0x95038BC2A603FC92ULL,
		0xA92E2F562B089499ULL,
		0x0B699FBA0BEA50A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CFD3CB155BB0FA0ULL,
		0x63A9EE83385AB945ULL,
		0x37247C8C8E715D39ULL,
		0x2CB20148B63A15B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98F6C7CCC806BEC0ULL,
		0x31599D3F6DA9434CULL,
		0x7209B2C99C973760ULL,
		0x5EB79E7155B03AEFULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0DA9CB52E1711BACULL,
		0x1031517CDDEF2B5AULL,
		0xFC1303CF16EB18BCULL,
		0x033F5F5A3EE07FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EDAC5F9DAB08A33ULL,
		0x72F41652EA56FB1EULL,
		0x04639936F4C918FDULL,
		0x5C95A9FDC4E42483ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEECF055906C09166ULL,
		0x9D3D3B29F398303BULL,
		0xF7AF6A982221FFBEULL,
		0x26A9B55C79FC5B2BULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x6E9ECD20E7BBCEC8ULL,
		0x5339BA23A3C2DAFDULL,
		0x52DF1EEB38A5DE4EULL,
		0x309C9E14C768CAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7A49EE34B464A14ULL,
		0x4B886B62729F057DULL,
		0x95590874374FC6EDULL,
		0x5C740353979CA005ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96FA2E3D9C7584A1ULL,
		0x07B14EC13123D57FULL,
		0xBD86167701561761ULL,
		0x54289AC12FCC2AEBULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x325C14E48E3B66FBULL,
		0xD6A29455BFA00A6FULL,
		0xAB65A18F4041C778ULL,
		0x03BB7EEFC4134A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD114B222C919AD6ULL,
		0xB36851E8C449EF8DULL,
		0x5CAB5183C8B67673ULL,
		0x6EA3FB1CB969BE18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x754AC9C261A9CC12ULL,
		0x233A426CFB561AE1ULL,
		0x4EBA500B778B5105ULL,
		0x151783D30AA98C86ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x78D1CA6FD31DA667ULL,
		0x01B4C5B9AC39B88DULL,
		0x141BE1D16D29A23BULL,
		0x571D6DC95B1A2F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA83EA655C039BC4ULL,
		0x33CE8AB85A7E4529ULL,
		0x6AC462C8365F595EULL,
		0x41CABD575F596450ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E4DE00A771A0AA3ULL,
		0xCDE63B0151BB7363ULL,
		0xA9577F0936CA48DCULL,
		0x1552B071FBC0CADFULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xA56F21169B09D063ULL,
		0x5611DB6470869B81ULL,
		0x611B380C335C75D5ULL,
		0x543807CED4E06BCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D9A0CDD58A6B98ULL,
		0xC7D6A606843F67B5ULL,
		0xE3FB8E78179F4FF0ULL,
		0x0F6B2A8060806C4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD958048C57F64CBULL,
		0x8E3B355DEC4733CBULL,
		0x7D1FA9941BBD25E4ULL,
		0x44CCDD4E745FFF7DULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x2F2CAF5F0B710A47ULL,
		0x007B1C0590BA1871ULL,
		0x9702895F3779967DULL,
		0x694E0224796BB4A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224D8FA08673A186ULL,
		0x80E39EE6041958D6ULL,
		0x369A4C0288BA6459ULL,
		0x5ABAEEAC32E56DEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CDF1FBE84FD68C1ULL,
		0x7F977D1F8CA0BF9BULL,
		0x60683D5CAEBF3223ULL,
		0x0E931378468646BBULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xAE6C6596F838B562ULL,
		0x3572A96F3CC27F25ULL,
		0x512DEFB686A9F735ULL,
		0x6141AB9626B12259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EA1662687D232EULL,
		0x9B405668C7FEF546ULL,
		0x7FAB97D14279AB20ULL,
		0x4E3A8F76A74EFDC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78824F348FBB9234ULL,
		0x9A32530674C389DFULL,
		0xD18257E544304C14ULL,
		0x13071C1F7F622492ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x2E5300BBFA86F28AULL,
		0x13853B6399447CA2ULL,
		0xD1F758C26CC896B2ULL,
		0x4D5FEBF6A128AE37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3099DACE057E08EULL,
		0x52976DF67E3CBE6AULL,
		0x95F261835CE867E8ULL,
		0x70450E81E87618B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B49630F1A2F11E9ULL,
		0xC0EDCD6D1B07BE37ULL,
		0x3C04F73F0FE02EC9ULL,
		0x5D1ADD74B8B2957FULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xFE60E72D9BD8CEA5ULL,
		0x48998257BE386D50ULL,
		0xE846EE45FE8512B1ULL,
		0x206BAD95CD413FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7643C42B06D6F9EULL,
		0x48F3985F1E4AED85ULL,
		0x5C4538D4628A48B6ULL,
		0x521958CF45057DC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26FCAAEAEB6B5EF4ULL,
		0xFFA5E9F89FED7FCBULL,
		0x8C01B5719BFAC9FAULL,
		0x4E5254C6883BC204ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5F5DDE4C925D5120ULL,
		0x9D14BF44F823FC74ULL,
		0xC08FD12406DC62CCULL,
		0x1BD60846CAEAA0FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB35CE58E60A7DA4DULL,
		0xDBDD02EBCD4ADDDBULL,
		0xA42F0AC837ACA6CAULL,
		0x6B8696CB0C16FE56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC00F8BE31B576C0ULL,
		0xC137BC592AD91E98ULL,
		0x1C60C65BCF2FBC01ULL,
		0x304F717BBED3A2A7ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xC4B2A660F1DC94D2ULL,
		0xED34AF521793368CULL,
		0x81FF9481C304F38FULL,
		0x70DFCEF002243278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2596DCB8F6682667ULL,
		0xB7177ED863AA569BULL,
		0xFEA2D47E181298A3ULL,
		0x680AD407C6BBE7FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F1BC9A7FB746E6BULL,
		0x361D3079B3E8DFF1ULL,
		0x835CC003AAF25AECULL,
		0x08D4FAE83B684A79ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB80BF4F674BA8938ULL,
		0x6E4BE3718E54EFE4ULL,
		0xB38B2605CB7B9F7CULL,
		0x57600B399075C929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAE59D8921C5A708ULL,
		0x2739D3A41A34442EULL,
		0x14D0BD2661AD1CD9ULL,
		0x0782F8CB22CD42DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD26576D52F4E230ULL,
		0x47120FCD7420ABB5ULL,
		0x9EBA68DF69CE82A3ULL,
		0x4FDD126E6DA8864EULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x699AC42881B8B97EULL,
		0xA6F24DAA74477818ULL,
		0xB3755818CB479E6CULL,
		0x036DC2244063E22AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E099347974AD9ACULL,
		0x4398D8A2B489B696ULL,
		0x19C59AB84D10F399ULL,
		0x567C1EFE94E0D839ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B9130E0EA6DDFBFULL,
		0x63597507BFBDC182ULL,
		0x99AFBD607E36AAD3ULL,
		0x2CF1A325AB8309F1ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xF054AB4C03EC78ACULL,
		0x7B642BDD7C2E540FULL,
		0xECEFE415C5AFF653ULL,
		0x0B7B793DDB3B2169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C389B633E6B462FULL,
		0x911E68B466AD4DF5ULL,
		0x54642359C276D40BULL,
		0x0D52086B932B8723ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB41C0FE8C581326AULL,
		0xEA45C3291581061AULL,
		0x988BC0BC03392247ULL,
		0x7E2970D2480F9A46ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x56B590A624B90E95ULL,
		0xBA0565F8D1EE09D4ULL,
		0x7AE9F310246520D1ULL,
		0x6420CD27CE9FAFAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A5C3AF4C72E87A8ULL,
		0x696FF59ECF72E2CEULL,
		0x3CBDF90008B33D3CULL,
		0x30EDEE077A713E8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC5955B15D8A86EDULL,
		0x5095705A027B2705ULL,
		0x3E2BFA101BB1E395ULL,
		0x3332DF20542E7122ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x26A598661FD6E792ULL,
		0x2F817EFBE3DE79AAULL,
		0x63476E3C3C6447DBULL,
		0x1437AE4A16BF781EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE05A8B2C23799A92ULL,
		0x546273180CCDCA1EULL,
		0xD1B535E703F6B5DAULL,
		0x1E2FBEE99F426212ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x464B0D39FC5D4CEDULL,
		0xDB1F0BE3D710AF8BULL,
		0x91923855386D9200ULL,
		0x7607EF60777D160BULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x1D225AE9AC218CCFULL,
		0x50BC525BEB8D5BB3ULL,
		0x2100F5923237B725ULL,
		0x70B34616C3B1E502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258ECB5D06CD80F5ULL,
		0x44AE7FDE1DB47AD5ULL,
		0x6A39454A0087046BULL,
		0x1D2137F1356A1B54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7938F8CA5540BDAULL,
		0x0C0DD27DCDD8E0DDULL,
		0xB6C7B04831B0B2BAULL,
		0x53920E258E47C9ADULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x7CCC5B94045B50EBULL,
		0x9D12FE7330F289A7ULL,
		0x5D409C29FD407BBDULL,
		0x25A044A72DEB3764ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8656E82C56A827DULL,
		0xE85757BD7A9A348AULL,
		0x7817C309EB7FE038ULL,
		0x37DDA4B678DB6101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA466ED113EF0CE5BULL,
		0xB4BBA6B5B658551CULL,
		0xE528D92011C09B84ULL,
		0x6DC29FF0B50FD662ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x77848E822D2F9C33ULL,
		0xE330F093DD9E317AULL,
		0x36827F172240415BULL,
		0x2980A603227D3DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D452FE30067AF84ULL,
		0x93A5C917EDCA547FULL,
		0xB525514405AAFC67ULL,
		0x4D41A7166A3B7449ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A3F5E9F2CC7EC9CULL,
		0x4F8B277BEFD3DCFBULL,
		0x815D2DD31C9544F4ULL,
		0x5C3EFEECB841C9A3ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x09FB81660A76D493ULL,
		0x4E287091DFC42BEAULL,
		0xFEC2CFD11FAD02E0ULL,
		0x5266462307BF4CE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7792809B6A4AAD17ULL,
		0x7906E3258C4E3653ULL,
		0xB07EE9705841FAC3ULL,
		0x7F1C4F4335507415ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x926900CAA02C2769ULL,
		0xD5218D6C5375F596ULL,
		0x4E43E660C76B081CULL,
		0x5349F6DFD26ED8CFULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x23B70C2C126D6794ULL,
		0xD611AF3A3EEA55F8ULL,
		0x29F3CFB4CDBBD43BULL,
		0x6A86144D1F8B33B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3654D16494C73A97ULL,
		0xE6D684FD94161B99ULL,
		0x80330BDDA379E350ULL,
		0x4D4B4E816270E3E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED623AC77DA62CFDULL,
		0xEF3B2A3CAAD43A5EULL,
		0xA9C0C3D72A41F0EAULL,
		0x1D3AC5CBBD1A4FCFULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x721E6E1728405B5AULL,
		0xBCC06448B79B28B6ULL,
		0x8319A6B11C237DFDULL,
		0x431D671EC9711F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9A8635DA92A6258ULL,
		0xACBD0D11C31AE024ULL,
		0x1DE049759958A4C6ULL,
		0x179E4FFE6F95476CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8760AB97F15F902ULL,
		0x10035736F4804891ULL,
		0x65395D3B82CAD937ULL,
		0x2B7F172059DBD7A0ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xD03B134341CC961DULL,
		0x5B1C30C7E96AF9D9ULL,
		0x8BDF1B607419A121ULL,
		0x714882A5C0E21995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F49D991FF50BD30ULL,
		0x45F58EAC11418C6EULL,
		0x5A21B917AC52914AULL,
		0x5DE00AB9BEA408DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0F139B1427BD8EDULL,
		0x1526A21BD8296D6BULL,
		0x31BD6248C7C70FD7ULL,
		0x136877EC023E10B7ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xD17FED9EB836849FULL,
		0x0B9D0C1B210FDC33ULL,
		0x55339CE41338F693ULL,
		0x564059399810B305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1D383F921014AFDULL,
		0x074509CC89A30110ULL,
		0xF3CEFF32601AD9DAULL,
		0x6FD1FE9B69173511ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FAC69A59735398FULL,
		0x0458024E976CDB23ULL,
		0x61649DB1B31E1CB9ULL,
		0x666E5A9E2EF97DF3ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xE80039CB1527718CULL,
		0xC26243883ED6D9FCULL,
		0x4468BFD03CAFC097ULL,
		0x095F6826D67DDEBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA84C708A7A21FC7ULL,
		0x28065316D2B4BB09ULL,
		0x8EBE4C8CE499A6C7ULL,
		0x3D04D733BB5217F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D7B72C26D8551B2ULL,
		0x9A5BF0716C221EF3ULL,
		0xB5AA7343581619D0ULL,
		0x4C5A90F31B2BC6C7ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x90CDF7ABBA0A1FCBULL,
		0xD474B388DCF9AD61ULL,
		0xD9BF54818511D37EULL,
		0x494ECA15E93E72ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9173201447DAEAAULL,
		0x6CE9BCEE33E1B77CULL,
		0xFA91EF3979F0B0D2ULL,
		0x2507C1BFE41388EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7B6C5AA758C7121ULL,
		0x678AF69AA917F5E4ULL,
		0xDF2D65480B2122ACULL,
		0x24470856052AEA00ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xDBD2E8D4E9E5B111ULL,
		0x38149E70857079ADULL,
		0x654F5C99CDB95FFEULL,
		0x17AD3B99671169A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48933428735B0B97ULL,
		0x2B7186C3FA2CD412ULL,
		0xCD9B4F16F9D0C3D3ULL,
		0x285BB50E169F8037ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x933FB4AC768AA567ULL,
		0x0CA317AC8B43A59BULL,
		0x97B40D82D3E89C2BULL,
		0x6F51868B5071E96AULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x568D10E2BF684192ULL,
		0x58F7399823A0D60CULL,
		0x03E60A28272A1C64ULL,
		0x3F06D64AEB070524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74FCFF49ED680FEDULL,
		0x90801D431A728205ULL,
		0x85E11E936101DFD4ULL,
		0x039A56E36BB0E581ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1901198D20031A5ULL,
		0xC8771C55092E5406ULL,
		0x7E04EB94C6283C8FULL,
		0x3B6C7F677F561FA2ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x0F850839869BD350ULL,
		0xC34A178EDBDAD3C8ULL,
		0x232F5F003C9DF82DULL,
		0x108DDE928531C0FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1448FBBF01CEF106ULL,
		0x572286AF0F9E18BDULL,
		0x34CFCEB570432B57ULL,
		0x526058A6E6EED7CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB3C0C7A84CCE237ULL,
		0x6C2790DFCC3CBB0AULL,
		0xEE5F904ACC5ACCD6ULL,
		0x3E2D85EB9E42E931ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x9DBC011027CF89BCULL,
		0x8C601B3FE0B9E8E1ULL,
		0x0AD4784834A86D36ULL,
		0x1962CE737FD71555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x985E8C0E340532BBULL,
		0xC704FB2B9B99265FULL,
		0xB5490B5C6FF0CABCULL,
		0x44476A57EAE523ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x055D7501F3CA56EEULL,
		0xC55B20144520C282ULL,
		0x558B6CEBC4B7A279ULL,
		0x551B641B94F1F168ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x5BFA8831AAA574C3ULL,
		0x6E7A97DBDC7DF728ULL,
		0x4C0456DFB92B57A6ULL,
		0x4D7FF95C83EB7EE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x471CDE715FCE62C9ULL,
		0x5B355AE5A87006A8ULL,
		0xF77A3B91E2A32DA5ULL,
		0x7B992FC7D13432ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14DDA9C04AD711E7ULL,
		0x13453CF6340DF080ULL,
		0x548A1B4DD6882A01ULL,
		0x51E6C994B2B74C36ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4322186E819000AAULL,
		0x7906ABBC0D300F1DULL,
		0xA255507AC2E1868AULL,
		0x0310D7BDE483CC4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB36381B664DAB8B1ULL,
		0x74E90CF7E1EC6DB7ULL,
		0x605ECB536265794AULL,
		0x01A516B076F6A40EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FBE96B81CB547F9ULL,
		0x041D9EC42B43A165ULL,
		0x41F68527607C0D40ULL,
		0x016BC10D6D8D283CULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xBF4587190914459FULL,
		0x61C70AA1F8A83838ULL,
		0x56A0B7CDF72DBAEBULL,
		0x3D7F406013C9DF55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D068E509E51E6EULL,
		0xCBC9FFC37E8A12BAULL,
		0x79FEE444E2A661D4ULL,
		0x34B0678928343BD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D751E33FF2F2731ULL,
		0x95FD0ADE7A1E257EULL,
		0xDCA1D38914875916ULL,
		0x08CED8D6EB95A37EULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x319E642C55FF882FULL,
		0x57ADC281EE0E46D4ULL,
		0x1EBB13A8BBD0E0D2ULL,
		0x0C289F863AB9DB52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE93AD40E0D6684BULL,
		0x5EAA66ACABD65BE0ULL,
		0x320B339EF81F0A7DULL,
		0x26854128F9267A0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x830AB6EB75291FD1ULL,
		0xF9035BD54237EAF3ULL,
		0xECAFE009C3B1D654ULL,
		0x65A35E5D41936146ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x2AC5C34E7F1E5C7BULL,
		0xF9B5978ADEC08CF7ULL,
		0x670C47ABD233EA1FULL,
		0x0322B831656FB707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBAD3A0D10801E7ULL,
		0x45AB316228D5145CULL,
		0x3783765E0BDDCF60ULL,
		0x19DEF4C9C95D2EF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF0AEFADAE165A81ULL,
		0xB40A6628B5EB789AULL,
		0x2F88D14DC6561ABFULL,
		0x6943C3679C128817ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x995D0076C4335322ULL,
		0xB33877B792BE0348ULL,
		0x0E7CE45D952C4983ULL,
		0x66946B13B96BDD99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE854E39A26A34DFFULL,
		0xF80E872A41FEA0DEULL,
		0x5AB5A888B383363FULL,
		0x24DF9406A9FA4E38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1081CDC9D900523ULL,
		0xBB29F08D50BF6269ULL,
		0xB3C73BD4E1A91343ULL,
		0x41B4D70D0F718F60ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x222E85C309BFBCA2ULL,
		0x861C347521546A80ULL,
		0x1053C4686E969A3FULL,
		0x33898312EE6C2C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D49E2C58A96CDD7ULL,
		0xF4CA3D0A0FA8A350ULL,
		0xA24762CC860A14BDULL,
		0x04E599923A3ADF5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E4A2FD7F28EECBULL,
		0x9151F76B11ABC730ULL,
		0x6E0C619BE88C8581ULL,
		0x2EA3E980B4314D23ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x89E4C5511F322611ULL,
		0xE8D16DD1B705BEC2ULL,
		0xE4B1CF744E51C4BCULL,
		0x028C2E5D6A699089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20AC80C5C0C72785ULL,
		0x32A3BFBC8D7C4DFEULL,
		0xDD7D3E19006D1683ULL,
		0x0DCC622729CC56E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6938448B5E6AFE79ULL,
		0xB62DAE15298970C4ULL,
		0x0734915B4DE4AE39ULL,
		0x74BFCC36409D39A5ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xCAE2B3E5446CB09BULL,
		0x4EDD1C6AFC8A0D8CULL,
		0x34EFC69FA29599E9ULL,
		0x0E8170FBF0FCC99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA4EB65586F4AA9ULL,
		0x39A98E24153C5903ULL,
		0xBFB9641D0C886E20ULL,
		0x0A9FA8AD8F4BB3BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E3DC87FEBFD65F2ULL,
		0x15338E46E74DB489ULL,
		0x75366282960D2BC9ULL,
		0x03E1C84E61B115E0ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3DA0455764C34B46ULL,
		0x80BCDE654F001D0AULL,
		0x75436FCD42B998DAULL,
		0x325281E805CBA824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x565AA879593B2447ULL,
		0xE7EF90207F57DB24ULL,
		0xF7E7E020BFC5F222ULL,
		0x70DC008ADBB56A55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7459CDE0B8826ECULL,
		0x98CD4E44CFA841E5ULL,
		0x7D5B8FAC82F3A6B7ULL,
		0x4176815D2A163DCEULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x3E5BE63FC807891FULL,
		0xD641BA42620FCB02ULL,
		0xF231A4612B3A44C0ULL,
		0x4A23B3399BB9060BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61A090631D6882EFULL,
		0xCF0B8C9C9F4B4560ULL,
		0x762D182AFF75C7C0ULL,
		0x021C2613E9956894ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCBB55DCAA9F0630ULL,
		0x07362DA5C2C485A1ULL,
		0x7C048C362BC47D00ULL,
		0x48078D25B2239D77ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0xB52EFBD8B674B470ULL,
		0xC8E73A61F6878F07ULL,
		0xAD4F2CFA3D509A3EULL,
		0x71A148F68CA083CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B74F3B70F3FA2ADULL,
		0x57EE16D48BECA969ULL,
		0xE031B17D5F195EA4ULL,
		0x2500FACDD5CB0402ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19BA0821A73511C3ULL,
		0x70F9238D6A9AE59EULL,
		0xCD1D7B7CDE373B9AULL,
		0x4CA04E28B6D57FCAULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x4DEC651774E5FC52ULL,
		0xD531672F12DAB010ULL,
		0x03A884AFC15DDC24ULL,
		0x0B0F22AB0F084C50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19E3A39198F788D4ULL,
		0x78CE81DE539A9DB2ULL,
		0x585BD50F58B33DB4ULL,
		0x77D7D9A230E375C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3408C185DBEE736BULL,
		0x5C62E550BF40125EULL,
		0xAB4CAFA068AA9E70ULL,
		0x13374908DE24D68BULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x53A2040687748274ULL,
		0x9233D8C2B66A9ED4ULL,
		0x95FEC78A2EF9AD64ULL,
		0x5683664100DBD438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81B3705815D1029DULL,
		0xEB0585B06BDA10ADULL,
		0x440FC704A5727986ULL,
		0x1EE5BFC4F07F36D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1EE93AE71A37FD7ULL,
		0xA72E53124A908E26ULL,
		0x51EF0085898733DDULL,
		0x379DA67C105C9D60ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x646F2BA1C555B56BULL,
		0x5253CFEFAC332FCEULL,
		0xD981CAE7F02B2403ULL,
		0x0B4457C3B09554D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC9BD422A56E025ULL,
		0x7FC9A1053346D974ULL,
		0x2C881775066752B4ULL,
		0x0803FEF2990DD3A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75A56E5F9AFED546ULL,
		0xD28A2EEA78EC5659ULL,
		0xACF9B372E9C3D14EULL,
		0x034058D11787812FULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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
		0x83D03B58DDD8E236ULL,
		0x4191DE25FDDC508FULL,
		0x91D835D4703C615EULL,
		0x705E8FB4EFF72663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF7F75E04A2623FDULL,
		0xD326F077D594F640ULL,
		0xB5E637FF8A406723ULL,
		0x0CCC0C35CB6A516BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9450C57893B2BE39ULL,
		0x6E6AEDAE28475A4EULL,
		0xDBF1FDD4E5FBFA3AULL,
		0x6392837F248CD4F7ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
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