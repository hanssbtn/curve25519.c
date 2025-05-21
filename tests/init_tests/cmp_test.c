#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9B0AB518262D5AFDULL,
		0x8102F844F99DB318ULL,
		0x33F73150747ED9A0ULL,
		0x23714B163EAF2AF4ULL,
		0xD2BB7A00F9895AA1ULL,
		0x085C9CD9809C1CE0ULL,
		0xC45989B5A1B1D973ULL,
		0xF49D80B5305D5E51ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE335D0CCF136775BULL,
		0x25D5DCE5945ED680ULL,
		0x8EC36FBEE43B4918ULL,
		0xB6B9C9243DC87B39ULL,
		0x8D14FFAFE1B3A69BULL,
		0xD37E5FE324094A8FULL,
		0xF481F4745B728760ULL,
		0x7E301B41653C982EULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC70D852C8BFB47B9ULL,
		0x8B3CC07EC4D36411ULL,
		0x7F81F2C985905DF4ULL,
		0xA7251BDEBA50854CULL,
		0x692E497FEB3C1AAEULL,
		0xB66BAB2B540A0E91ULL,
		0xA563C6E2A8F2FD62ULL,
		0xF535F7EF49ED3629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x570BC01BCA6138CFULL,
		0x2301B9A7849123ECULL,
		0x883534ABB5A08EB3ULL,
		0x8A7DE11D8F3CF3FFULL,
		0xD033A5CD017DAEFBULL,
		0x094265B72C16C1E6ULL,
		0x7AEB5D82C0520D63ULL,
		0x15FFA40B92C6BAB1ULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3335B9CD44D3D4FEULL,
		0xC6683A45F4E2BC96ULL,
		0xC92A5BE19C37A388ULL,
		0xC82EDA8F046BC2E9ULL,
		0x232AE51D2929B2BEULL,
		0xC663FD392F65C02FULL,
		0xF2A83588375E4936ULL,
		0x8A7683A096A452D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5FC6871036CBBC7ULL,
		0xFFF1FE300DF67114ULL,
		0x532BCF4A7EEE84CEULL,
		0x03CF859E12A61C83ULL,
		0xA1CC81D60070031DULL,
		0x3463F291FB2D5B82ULL,
		0x9A783CDBA64A667DULL,
		0xDC5ED5A6F33F1B98ULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99B6984FB9D0659CULL,
		0xCA7EB158162E5FB8ULL,
		0xDB70D2A35D2E2CB3ULL,
		0x3D66B4E9788AAD22ULL,
		0xC21C141FC1A4D443ULL,
		0x57A6DC2D9EB1328EULL,
		0x09591673C7A37705ULL,
		0x3A18178961E42EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB28A2C0A1D6B4AF7ULL,
		0xF8245A49FC18F416ULL,
		0x4770C91DC2444422ULL,
		0xAB994AA4250E62DEULL,
		0x52F0932B8F4062B2ULL,
		0xE03FEAE6E82C3276ULL,
		0x8E0C28EC3A716712ULL,
		0x523097B6A93C24C3ULL
	}};
	t = -1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB705A5576A468245ULL,
		0x2FFB76D2C9AF0E6CULL,
		0xE07139A5FD6F5115ULL,
		0x14625489B1BB32ECULL,
		0x3EE6E7389FEADC62ULL,
		0xF067166910B1B46CULL,
		0x8176D5A30D502597ULL,
		0x4E5FA568999BF5FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB705A5576A468245ULL,
		0x2FFB76D2C9AF0E6CULL,
		0xE07139A5FD6F5115ULL,
		0x14625489B1BB32ECULL,
		0x3EE6E7389FEADC62ULL,
		0xF067166910B1B46CULL,
		0x8176D5A30D502597ULL,
		0x4E5FA568999BF5FDULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6F5784B29839DD2ULL,
		0x5E3A9ADB888B04D0ULL,
		0xDBCBBF4B90B8C504ULL,
		0xB01F8B5EA4C9EFEAULL,
		0xFCD17AE56D388ED9ULL,
		0x68769B201DF628AEULL,
		0x39A0AB98374B2C55ULL,
		0x35D59125ED610E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED87097E0DBC9656ULL,
		0x66407CAF7356BDFFULL,
		0x099042DF0B2C4046ULL,
		0x7262177B823D2BDDULL,
		0x22D507B1A23C0C28ULL,
		0xAE66B171F306F5ACULL,
		0x771910F534B0C44CULL,
		0xD25E94C0674197BEULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B22C114F1B079B3ULL,
		0x6F8387F278006C54ULL,
		0xCB608CD9FDB84F39ULL,
		0xDC6A833259C942A3ULL,
		0xCE6957EBCD49344DULL,
		0xDA3FC968020172AEULL,
		0xEB2FBE5CC00E3514ULL,
		0xAB9F3E19EDD6833CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB8C0E32AF11F8AULL,
		0x6AF2C0D55B4FFFA5ULL,
		0x836879C434A20ECBULL,
		0x3B10EBE416314842ULL,
		0xCD3B6282F152BB4BULL,
		0x00B896B6EF76AE7CULL,
		0x2DF5162FC630A570ULL,
		0x6A396CA284480109ULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x517ECE0958CD288EULL,
		0x2529FA094F04EC2EULL,
		0x29979118783F24A2ULL,
		0xB0649A6E5618DD42ULL,
		0xF1F30697B8AA29B2ULL,
		0xAFA03F2FA055EF8FULL,
		0xE7CB1DA687C74E00ULL,
		0x8EA8A9F42D17EA7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAFD5C49CAD050E1ULL,
		0x5755C0C32A71312DULL,
		0x930A521ADAAF365AULL,
		0x5F0B3BC04BD69B5FULL,
		0x86FC504BC28AA970ULL,
		0x950A1345A293EAE6ULL,
		0xB39B80644513FB90ULL,
		0x79EDBF4F6245F920ULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC043923BBF792317ULL,
		0x1D3117D3FCD4FCCFULL,
		0x3308E629F2CF8CB3ULL,
		0x9E917A4BCB282278ULL,
		0xD479A33C6E1FF3A0ULL,
		0x1D5002A20D7668F7ULL,
		0xDDB2C0D4E4DA552AULL,
		0x3F6487B9B96A03E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC043923BBF792317ULL,
		0x1D3117D3FCD4FCCFULL,
		0x3308E629F2CF8CB3ULL,
		0x9E917A4BCB282278ULL,
		0xD479A33C6E1FF3A0ULL,
		0x1D5002A20D7668F7ULL,
		0xDDB2C0D4E4DA552AULL,
		0x3F6487B9B96A03E2ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x274FD46777FB544DULL,
		0x5374A4D5B83C9D4EULL,
		0x5651E1084C926EE8ULL,
		0x9B8CD340EA3117FEULL,
		0x3005374A43BABACCULL,
		0x7EB94E2BAD7E0EB2ULL,
		0xCB4CDA3865070A3DULL,
		0x5EFEF5655743A8ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F611751B9714C1AULL,
		0x6DE3ED1C83E09DF4ULL,
		0x2DA26A9CDD140E22ULL,
		0xD4711D6C520896E5ULL,
		0x25965775C70E4E0AULL,
		0xBD4B73EB4925BCEEULL,
		0xBC8F33531F293B6AULL,
		0x906DCE4D0125C85BULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF1333B4A26DD3BBULL,
		0x5217D137C2E1AD78ULL,
		0x189DC450DB9161C3ULL,
		0xCBC8E563136236C1ULL,
		0x5D61E398CD97BC16ULL,
		0x1948D5272B6C94DCULL,
		0x6B17BB4E56B27597ULL,
		0xFEC3BCF55F4405EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C54D5EEC6DB8C9ULL,
		0x05BBE29620027DCEULL,
		0x9894D5E5BC9560D1ULL,
		0x5031ADDB5D3576C2ULL,
		0xF89DF0FD2BB3D489ULL,
		0xD230829ED3AF241EULL,
		0x7A78B581CE039144ULL,
		0x19EA8F620E0033E3ULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A138CA5FF9285EDULL,
		0xD2998B8D76F7647DULL,
		0x941B5F07B0B28AC1ULL,
		0x8E2363C006C867ECULL,
		0x2C24219283E7861BULL,
		0x7FCC977773E77CF6ULL,
		0x326AE9463A9D7FB8ULL,
		0x8974B00B836B5C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D3F279BC033E72ULL,
		0x2C798DF8F4DB102EULL,
		0x912E6E5B73652E66ULL,
		0x24EE9E4C3D2039F9ULL,
		0xE9057D26C2AB599FULL,
		0x5437D11278DE947FULL,
		0x6CB90FDD796EF9C2ULL,
		0x0074B57360CFD9AEULL
	}};
	t = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x291D0B402415F834ULL,
		0x686E6A78724FA853ULL,
		0xFF2CD13812589F59ULL,
		0x2D72DB9F9FE89F35ULL,
		0xD66FE42A40DEC4F1ULL,
		0xBF9313367E75CF7BULL,
		0x7F883C4B203E1A19ULL,
		0xE6D987DF8B02DF63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291D0B402415F834ULL,
		0x686E6A78724FA853ULL,
		0xFF2CD13812589F59ULL,
		0x2D72DB9F9FE89F35ULL,
		0xD66FE42A40DEC4F1ULL,
		0xBF9313367E75CF7BULL,
		0x7F883C4B203E1A19ULL,
		0xE6D987DF8B02DF63ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE76A1EBDB2A594FULL,
		0x72D91279C7027B91ULL,
		0x6CAADB4115E87A82ULL,
		0xB5EB32848A28B2ABULL,
		0x2AA1E70795D5BBF3ULL,
		0x4C6F42A91A62F124ULL,
		0x3280E2C42D8C3658ULL,
		0xF5412F60754B1EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C5556E0EABD2EDBULL,
		0xB9A9700FDCDE1C1BULL,
		0x8F034C6DC148FB24ULL,
		0x1EAAF8F552CC3048ULL,
		0xE14FD0B6FAEAF1DDULL,
		0xF47F7F316C5474F5ULL,
		0x6767E8D0B1DDFF1FULL,
		0xCC8C73609CC34EA4ULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11B8B4D6DF49F87EULL,
		0xB207F6E9B9F398B1ULL,
		0x7FA6AC340DEAD4E4ULL,
		0xFDF654922E407852ULL,
		0xBA846D9E05182929ULL,
		0x096226E3EF8CA58FULL,
		0xDE1794CABE7F01C7ULL,
		0xFD5E0CE1931DFDEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97BC75CB9657A7BULL,
		0x8923981DA2D4AEB5ULL,
		0x1C2FAF3A81500F29ULL,
		0x8F34EB82B040E17EULL,
		0x1E54AAD5C6E53788ULL,
		0xA108DC63EAE72071ULL,
		0x873EB71CF381F21EULL,
		0x0C427C285F3F5303ULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x110D87E6AD8E0DE7ULL,
		0xBFB2C59E51F567EFULL,
		0x23D0596346E4E4C8ULL,
		0x781F7F25504AF16DULL,
		0xA494826878456353ULL,
		0x6CEF94EC308E0F40ULL,
		0x40C146E7677B6F68ULL,
		0x7C047E3A5651E4E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1ED785E45E6558BULL,
		0x88B66583A0EE15B5ULL,
		0x6FE9365C5BA4A843ULL,
		0x6A75F6A5F19E2D03ULL,
		0xA862946D2FDB6730ULL,
		0x973938DEF1033EDBULL,
		0x4BA60AAFC83317D3ULL,
		0x73C1C15CEC8251D6ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A65A9BF55FC4672ULL,
		0xBFD4F44B91C78346ULL,
		0x430EFC574EBFBCA0ULL,
		0x1F5F2845AE6283C1ULL,
		0xF41B31F460973726ULL,
		0xDA0791C8315BBAAFULL,
		0xB16A1FD1E0C890BDULL,
		0x62D239B403A67191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A65A9BF55FC4672ULL,
		0xBFD4F44B91C78346ULL,
		0x430EFC574EBFBCA0ULL,
		0x1F5F2845AE6283C1ULL,
		0xF41B31F460973726ULL,
		0xDA0791C8315BBAAFULL,
		0xB16A1FD1E0C890BDULL,
		0x62D239B403A67191ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x865498B385346B2EULL,
		0xDA626652D4593019ULL,
		0xC931F440A1989151ULL,
		0xE21C79DC01F5803BULL,
		0x760F616BD01D2B6CULL,
		0x7E7AD695550010C4ULL,
		0x8FCB5C82CBDF4C88ULL,
		0x9E3F4DDCB67FF472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7516505DBF6234ULL,
		0x0335F038BB77FEB0ULL,
		0xFE0E8FD5E9B88E42ULL,
		0x1C5ADCFDCFB86648ULL,
		0x7DD2E51FA79B1772ULL,
		0xFEA1EDF2A1BFD848ULL,
		0x0CB78740A8C6302BULL,
		0x8BE59A7F5878B5CEULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F4BDC30096AC1FEULL,
		0xA08B0D4949C74CBFULL,
		0x7E9D3E5196D6CA82ULL,
		0x543A7CBFBE8CAEB1ULL,
		0xB555AEA08C046991ULL,
		0x28F86CDC0CA6935AULL,
		0xF6930F47C9DAF955ULL,
		0x25458B9501BE871DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3416770097BC69B8ULL,
		0x1D8FF35290EDD51EULL,
		0x71853B3EA137008BULL,
		0x7ED2A161795D923CULL,
		0x7A5CA7FCDF01C642ULL,
		0x48B4C6A4F5141661ULL,
		0x95D181BFFED65183ULL,
		0x87E9B98663EE378BULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E81DDC9819CE155ULL,
		0xD322F1DA88F20AABULL,
		0x1AB025876D96EAFFULL,
		0xD0E96AE728A95172ULL,
		0x1EF7E8EC4AB82E93ULL,
		0x79556516642435C0ULL,
		0xDA2F1375BAA66B22ULL,
		0xDACF744B51660618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89570F796F46FE86ULL,
		0x7668567DDF1C8AEEULL,
		0xF75ABB305D4DC1C2ULL,
		0xACE41257C0B6912BULL,
		0x35526F71D2925480ULL,
		0x57FC893FDE984CCBULL,
		0x5595A869BB092BE2ULL,
		0xD0ED936F3B8B8879ULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3A3EC9683470D02ULL,
		0x255307687BCB71DAULL,
		0x9D7FF8D6CDBFD84EULL,
		0xCB51049B19F93199ULL,
		0x35B8B5D58E0128B7ULL,
		0xB9F10A7D3D8CEA6DULL,
		0x237134DC75AFBB9AULL,
		0x312DBA8188A7ADD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A3EC9683470D02ULL,
		0x255307687BCB71DAULL,
		0x9D7FF8D6CDBFD84EULL,
		0xCB51049B19F93199ULL,
		0x35B8B5D58E0128B7ULL,
		0xB9F10A7D3D8CEA6DULL,
		0x237134DC75AFBB9AULL,
		0x312DBA8188A7ADD6ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x792C13F2A37E677AULL,
		0xB6D5E73407E23581ULL,
		0x2B59D803FA4CF9B1ULL,
		0xFBD0C27140714B35ULL,
		0x0C06D83BA9370130ULL,
		0x68718441B139F8DBULL,
		0x344DDC7F5EF26C56ULL,
		0xE5D68548CEAF4FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AB5D2D3ACA512E6ULL,
		0x22F79F9DB60D4E1AULL,
		0xE0A2D6588B8B72BCULL,
		0x00DBCE31E7BFD6F8ULL,
		0x612A981692F27AEFULL,
		0xFA65D7D17F9F39B8ULL,
		0x17A8799C78DD2A2FULL,
		0x8918F436588EDFDCULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D4C62EB4493EAF0ULL,
		0xD4D1F6030EB3ED72ULL,
		0xA7FB8BB01D120921ULL,
		0x72C4880086EC703FULL,
		0xA143DA82DF3D7BCAULL,
		0x139B079358B4C88BULL,
		0xD25304D54A2450EFULL,
		0xFB26C0C227C32E76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4980E2C4FA6FEA94ULL,
		0xDAC713BF0C6DA74AULL,
		0x700B380C29380D94ULL,
		0xA106EC7EC20493BEULL,
		0xDE8EE4D6AC44E5B2ULL,
		0x07B3D71CED2DC291ULL,
		0x0DC53EA6FED72292ULL,
		0x763DD7C6AE6E5BCCULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D2F997CB9C4CB2AULL,
		0x32F4EE9BDAC3C93CULL,
		0xF6F25B9579536DD7ULL,
		0x0C387886AC4713C3ULL,
		0x5AAFB3D83EC0F48FULL,
		0x0F730511038FA2C7ULL,
		0x57E8B2E6EDDA6550ULL,
		0x3ACA7DDDFDB318E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42F7881754248151ULL,
		0xEB8B9AC15549B492ULL,
		0xB183B98926F357A6ULL,
		0xD29285225DC1FE09ULL,
		0x9FD1122E685A3A73ULL,
		0x601E5933B0A1E36DULL,
		0xF69EDD051B4FBD15ULL,
		0xA3EB2C56272E730CULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E59B4CB6FDCB3FCULL,
		0x6C93566A98957F9CULL,
		0x741F1A06A31E9D16ULL,
		0xED61807FC119B216ULL,
		0xE7A52F66C4C5A286ULL,
		0xA84010CE58DCE002ULL,
		0x5A9DF4772F810A3AULL,
		0xF0B3D5A33C6D0769ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E59B4CB6FDCB3FCULL,
		0x6C93566A98957F9CULL,
		0x741F1A06A31E9D16ULL,
		0xED61807FC119B216ULL,
		0xE7A52F66C4C5A286ULL,
		0xA84010CE58DCE002ULL,
		0x5A9DF4772F810A3AULL,
		0xF0B3D5A33C6D0769ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1AC46E7C836DFE6ULL,
		0x4ECDF0111180E3B9ULL,
		0x1E085D2C6EF7E0C2ULL,
		0x1AA1F20CF25044CEULL,
		0x7CA483CD9BFCC18BULL,
		0x13F1A795B404E48DULL,
		0xE165769DE98F53CFULL,
		0x9A779A9194222601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA380300D8D216EULL,
		0x85BAB59B29FD977BULL,
		0xDCA2AD6CB40BFD0EULL,
		0xF2CEF23AD28547CDULL,
		0x210C34BF54B5BC0AULL,
		0xE0447B918B81EF4FULL,
		0xEED2A9BD5E0E6963ULL,
		0xA77455B9BF1999F9ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8B6AC6657B33C28ULL,
		0x252D914840A50868ULL,
		0x2F81F410296ABD3CULL,
		0xA6CAFE67F49AC2A4ULL,
		0x04058D80EB1B1542ULL,
		0x4C2A8D00FD36DB95ULL,
		0x7B5406D1F04B096AULL,
		0x9BEFF16ED350FD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2920EB77BC6F724EULL,
		0xB66D899306A41F79ULL,
		0xBF13C78FF623A05AULL,
		0xCE3B579A39272355ULL,
		0x62D83EFD4B491181ULL,
		0x65CF92EF61553A98ULL,
		0x8A281072E8AD0A6DULL,
		0xDC6C3651E65820B0ULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC19D6764D18E0F94ULL,
		0xE4CB52E3E0ADE53DULL,
		0xF999F7DB30D9C2F2ULL,
		0xD75F384FAD3ABA88ULL,
		0xD1EBCC986AF51FF3ULL,
		0xC664676D7CA288A8ULL,
		0x456A1FEBF90AB824ULL,
		0xBBC6E7B522B5FB26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEF1BD10DC743AD2ULL,
		0xBFC65B05455B36B6ULL,
		0x57DC6C84C156E086ULL,
		0x81CA159B508022FEULL,
		0x6FE67878E844AD12ULL,
		0xDDD7F76D0A0D8EDEULL,
		0xD18C9C36F11F5C5CULL,
		0x603128D931A61F98ULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D1E83A6E9F2BD83ULL,
		0x6C4F6D3AACDB1A46ULL,
		0x18CC7ADA78903114ULL,
		0x5D23CFCE0069A52BULL,
		0xAB3E5B27DFF234E9ULL,
		0xCAFCB8525FB63068ULL,
		0x585F477C95DEC99EULL,
		0x5EA3565A81DE8CD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1E83A6E9F2BD83ULL,
		0x6C4F6D3AACDB1A46ULL,
		0x18CC7ADA78903114ULL,
		0x5D23CFCE0069A52BULL,
		0xAB3E5B27DFF234E9ULL,
		0xCAFCB8525FB63068ULL,
		0x585F477C95DEC99EULL,
		0x5EA3565A81DE8CD2ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE75DEFAEAC32D37EULL,
		0x8E42BD37C5C7D07AULL,
		0x9159673211A7D962ULL,
		0x61B8ACE6ABE761F6ULL,
		0x46AA4BF45F394BC1ULL,
		0x8F93D9B138D73898ULL,
		0xB0CFC755091DB7E4ULL,
		0xB120DBBEDBD2D52AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933668E2FD56932CULL,
		0xD979F54BC97E9744ULL,
		0x5C408E0D243CF019ULL,
		0x2305B46273A0C327ULL,
		0xBD5E37E2C8BBDC40ULL,
		0x24460E264187C0A4ULL,
		0x94DAF833D3CD7783ULL,
		0xE1B590238063460AULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA719C7BFDCC136B9ULL,
		0xCBA90D4B6DFB8982ULL,
		0x18280881CCFA71A0ULL,
		0x3521A8B9513CAA0BULL,
		0x1835ABE543FAA53AULL,
		0x33C7C2E569443E50ULL,
		0x7E40480CE5737929ULL,
		0xD8A91548B3202A89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFD3D9A195B4C1AULL,
		0x9FFCF99179F4DA47ULL,
		0x29E7585F917021B6ULL,
		0xA0D89DDDB1023C47ULL,
		0xE8F34282026851B7ULL,
		0xF1CE141011F005F1ULL,
		0x9B2DBEBBB7691FEEULL,
		0xEF82541F0356C803ULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61C5B03AF96430DDULL,
		0x35FF9EE9B986D03EULL,
		0xDF00F64E8D3419B7ULL,
		0xB70D54EAD3D2EE4BULL,
		0x3DB5B3422822AFFCULL,
		0x706C4CD22C1D6C33ULL,
		0xB4CC9597A1BDF6B0ULL,
		0xCADDBAC6228E175EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0140725EB3906E97ULL,
		0x51DBE3A5F1F1A047ULL,
		0xDADA572360CF9145ULL,
		0x2D2A03B6CBE23DC7ULL,
		0x0320F88A3312EB02ULL,
		0x2BC3D2E68A880128ULL,
		0xEA57B349F93752BBULL,
		0xFC307F479D5CC7B8ULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC253968E324F7FFULL,
		0x09C8B6CA6D7031F7ULL,
		0x144E2D0EFC8919C6ULL,
		0x062DEA0DC927818AULL,
		0xE4315CBE9D36D757ULL,
		0xEB25E1B365151395ULL,
		0xD09D115E15E882FDULL,
		0xA25DC14D367F1E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC253968E324F7FFULL,
		0x09C8B6CA6D7031F7ULL,
		0x144E2D0EFC8919C6ULL,
		0x062DEA0DC927818AULL,
		0xE4315CBE9D36D757ULL,
		0xEB25E1B365151395ULL,
		0xD09D115E15E882FDULL,
		0xA25DC14D367F1E4EULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8F5D0942152A8AEULL,
		0x9C6836E5E0ABD23CULL,
		0x9138E7FB3F1BA252ULL,
		0x83635C841C9F954BULL,
		0xCA0D57B84FB5012FULL,
		0x275A42AF66B3B3A7ULL,
		0x3267ECC259160200ULL,
		0x957B4BB98BB3794EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6BFFB95D0038D11ULL,
		0x095F514D21C9FF9AULL,
		0xA7E47E48A67EC40EULL,
		0x34FCBD1AFF6DF7E4ULL,
		0x3B5DA0B46C8B6A7FULL,
		0x85F8A10139F1A1BCULL,
		0xDFF991E757B54688ULL,
		0x8FD86468369DF260ULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1885894E1B678820ULL,
		0x1BAE82AB9942CF70ULL,
		0xD6FED79E0134AF16ULL,
		0x06BF6033FE3A01B8ULL,
		0x2D6CF2B08291EFB9ULL,
		0x9B7AF96FA764A358ULL,
		0xE70BE86D0DB8A425ULL,
		0x8EEB42D7EEDB1EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x772B3308FCE5B91AULL,
		0xD82A3D3D0B7E776BULL,
		0xCA931A3B21FB3290ULL,
		0x1B26383B7E119361ULL,
		0x5F888D04A4AD74BEULL,
		0x831C211F5F7AB01CULL,
		0x02000923A964223AULL,
		0xCE084D60210E414FULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72B5A552CBEEC2B5ULL,
		0xA828980A7814B1CEULL,
		0xB99E4490AA99923EULL,
		0xA0F4CFD2012AB8BAULL,
		0x401C7D75358C7FB9ULL,
		0xFA6E3DB987A524D9ULL,
		0xEAA3B1AD12381F51ULL,
		0x6F302A5120B142C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC0A6118D83B821FULL,
		0x7DD54FF2C27D86DCULL,
		0x59B7485B44AB6DFCULL,
		0x6F23A75966D30215ULL,
		0xCCBCD77A800C2CCBULL,
		0x9E3FDC1AE96673D7ULL,
		0xE5ED7BD9A7528EA9ULL,
		0x5F21B3E762326A1AULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86A72130CB86CC94ULL,
		0x44ED8C19C3F9DFEDULL,
		0xAE728A6DA69F878EULL,
		0xA36026BBEEA47998ULL,
		0x97864CA5E4E52650ULL,
		0x1204BD59C4455CBEULL,
		0xE1235D3B5B2DEDC6ULL,
		0x754145047B97983BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A72130CB86CC94ULL,
		0x44ED8C19C3F9DFEDULL,
		0xAE728A6DA69F878EULL,
		0xA36026BBEEA47998ULL,
		0x97864CA5E4E52650ULL,
		0x1204BD59C4455CBEULL,
		0xE1235D3B5B2DEDC6ULL,
		0x754145047B97983BULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1179B33A4F6CF471ULL,
		0xA7347B52E73274B8ULL,
		0x52D110525BF3B52EULL,
		0x8488D9F63F5E0543ULL,
		0xA09D92F958B4881AULL,
		0x865F9DDE93057C9DULL,
		0x256408B06E489845ULL,
		0xD5477DF6C6F1D722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6BF60409725E124ULL,
		0x8440A44E13A318B6ULL,
		0xC3DEF0C4B8592801ULL,
		0xD15C30F5A4C85A8DULL,
		0x8632903B24D712E0ULL,
		0x39F8874B60CCA629ULL,
		0x3AC310048752D8DBULL,
		0x20F829E16E75C39CULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4097006DBADB2D9ULL,
		0xF9049526027E6C71ULL,
		0xA6CDFC5081C5BB1CULL,
		0xF66B4A680F11DA78ULL,
		0xB9C47D15EFCB0B40ULL,
		0x1B96998A1147177CULL,
		0xEB6416550C8AA8E1ULL,
		0x9607D7476BB79B1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29100432EFAE543BULL,
		0x9708AEB511B8AA16ULL,
		0x252CB99559DFC865ULL,
		0xCD8489492398451BULL,
		0xD245E8C389981552ULL,
		0xCAB9B76D89553281ULL,
		0x3DA31582A65DEBE3ULL,
		0xE97151C11C084268ULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9E0E04351774217ULL,
		0x14F8E9A5FA7702E5ULL,
		0x0EF6FBC0F7A6A508ULL,
		0xD123DD264A60A663ULL,
		0x657413E10E17B1A9ULL,
		0x83B0C1034A22193DULL,
		0x5C9F8EE72B55E9B3ULL,
		0xB644CB552BE2B2E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x130B058657C0785DULL,
		0xFA75625A77A56A40ULL,
		0x261C82047944D423ULL,
		0x8EED6B9045AA1957ULL,
		0xAEC5A68B26BD9021ULL,
		0x0FB56651DFF755D7ULL,
		0xE39B367C9290381DULL,
		0xB2AD690506D864A9ULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BD66B2B07407E5EULL,
		0x72CA5BFB5A0B9D65ULL,
		0x9B64C1AC0791FEBDULL,
		0x937221B3ABA406F1ULL,
		0xA5E40E4CE88699C4ULL,
		0xCD87D200A26CB799ULL,
		0x35A3D9C531DDC6EBULL,
		0x4813590F923302E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BD66B2B07407E5EULL,
		0x72CA5BFB5A0B9D65ULL,
		0x9B64C1AC0791FEBDULL,
		0x937221B3ABA406F1ULL,
		0xA5E40E4CE88699C4ULL,
		0xCD87D200A26CB799ULL,
		0x35A3D9C531DDC6EBULL,
		0x4813590F923302E4ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85A72B22CCDE7091ULL,
		0x8577120BD5942422ULL,
		0x967A5EF583FD11E1ULL,
		0x7B147F3E26B79E67ULL,
		0x3FBF427FAFCE9CFCULL,
		0x9E6CA3C39EBFE297ULL,
		0x5A63706F09780D47ULL,
		0x0A762D3C07CAA97BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB4DCD545F898891ULL,
		0x7DFFA72E40E6FD0FULL,
		0x3929323C49A82946ULL,
		0xDC668AB518DB9E50ULL,
		0x1200CEB60EF6E6CBULL,
		0xDAE6539F06E116F9ULL,
		0x64624C9920313A8AULL,
		0xD4B2F688616D4646ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF20C93E7545E98AFULL,
		0x9891744E213D70E3ULL,
		0xCBFC742285710B24ULL,
		0x2AE9DDB396D10D22ULL,
		0x50FA24A3D5EB9E3EULL,
		0x80A360E8D736D013ULL,
		0x535F1C0C2299AEFFULL,
		0xACB6369F5E5AC1D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9CC331024CB60ECULL,
		0xE0FDA066C3ACACACULL,
		0xAA37E16E5CF35672ULL,
		0xCF3B8A0E13E309BBULL,
		0xAEB5E81E6D8B3E64ULL,
		0x713236179FACDC15ULL,
		0x94994B27E0F21FAEULL,
		0x416CE90A209BB3C4ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A8ED8D57FD36CCAULL,
		0x5B34A171D88BBF95ULL,
		0x3CC0C6611181842AULL,
		0xAEE187F989998059ULL,
		0xB2FF02FA104BBE51ULL,
		0xA341A8674AA45579ULL,
		0x3F6F3414C041E4F2ULL,
		0xA8870513B55A8F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AE9EEA44008FCC7ULL,
		0xA432CE89C4750B64ULL,
		0xFA3C10903754BCE2ULL,
		0x62413BF62AB7C1D6ULL,
		0x56928B644B74DBD6ULL,
		0x3FA6E88B409F3A45ULL,
		0xE6C67169AE13438DULL,
		0x492E48CA1E66D4FFULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D2DDA793E991809ULL,
		0xB926BF920F69D22CULL,
		0xAEDD1F44BFD866CEULL,
		0xEC0DC6E7FF86BCA4ULL,
		0x5BC16089E5978E24ULL,
		0x3DBBC96D2B94A7B3ULL,
		0x75DA17E15034E691ULL,
		0xB51AB1462B605CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D2DDA793E991809ULL,
		0xB926BF920F69D22CULL,
		0xAEDD1F44BFD866CEULL,
		0xEC0DC6E7FF86BCA4ULL,
		0x5BC16089E5978E24ULL,
		0x3DBBC96D2B94A7B3ULL,
		0x75DA17E15034E691ULL,
		0xB51AB1462B605CEBULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AA8452934234759ULL,
		0x90194932FAA8484FULL,
		0x5F259B917F6CCFB4ULL,
		0x01EC264557F9D99DULL,
		0x1215A767A374DE40ULL,
		0x4666265BF7690BE8ULL,
		0x7D212FF399151C65ULL,
		0x92E06A99CC378B50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F72DEA0D508974ULL,
		0xB365947380EB3E3DULL,
		0x423FA1B65DD69AFBULL,
		0x17E92D2A0467618DULL,
		0xA118F69E0DB3A0FBULL,
		0x3EAE2B6A51EC349FULL,
		0x7145C826B9E4FF29ULL,
		0xAC7AE7C90E44FD91ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03647EDB6AC9C84EULL,
		0x97B8C9CD12F0686CULL,
		0xF3FC0640D28B267CULL,
		0x2E5E661F6B78414FULL,
		0x007CE18B6CC2C0A8ULL,
		0xBB08154D78CC82DAULL,
		0x4E4D5D354FC3E979ULL,
		0x89EA546E6D597FD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x935CE289378E8A2BULL,
		0xEE30550A31970B09ULL,
		0xA77EB25C734F6140ULL,
		0x4AE8DEA6CEFB58FCULL,
		0xB7FCDB4B27B493D6ULL,
		0xD6D9F68B36F253EDULL,
		0x60FDC310CBD6B4D7ULL,
		0x95C96EECBAE57EA7ULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40CD9EDC9BF2C030ULL,
		0x535165F2BAE36C6CULL,
		0xE3D9A094923F5DFAULL,
		0x14826B4C66F5B36AULL,
		0xE6A871DCC47568B8ULL,
		0x73E11B1D0B8C7669ULL,
		0xA4FCB29BD0D9F437ULL,
		0xA6FAE52FC2DB6066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE3F6864A33CB79ULL,
		0xD94FE23FB6B79A45ULL,
		0x5DE475219584E20BULL,
		0x58667F4FB9AFAD53ULL,
		0xE7E47CD7F18D8A85ULL,
		0xD00BD2F0FE5D5F48ULL,
		0x39BD491B5FBF1813ULL,
		0x527E1575B2208D99ULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDC10BBC25E9B8F1ULL,
		0x20B0191A08946B17ULL,
		0x0E49FFAAF167F625ULL,
		0xF67789762EA41CF5ULL,
		0x7286C3983E3CDE1FULL,
		0xF5304A2B0A007746ULL,
		0xD8C5251F6A947CA0ULL,
		0xF1BBB1DD5EA4A1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDC10BBC25E9B8F1ULL,
		0x20B0191A08946B17ULL,
		0x0E49FFAAF167F625ULL,
		0xF67789762EA41CF5ULL,
		0x7286C3983E3CDE1FULL,
		0xF5304A2B0A007746ULL,
		0xD8C5251F6A947CA0ULL,
		0xF1BBB1DD5EA4A1BDULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x792676193E3255DAULL,
		0x42A87150582B5164ULL,
		0x0C2990C8D28C6740ULL,
		0x8F4832546FC64A43ULL,
		0xFD83EED495FC62B8ULL,
		0xA986A9D489179B17ULL,
		0x27448ECF01ABEA7CULL,
		0x934E97478F8573CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213A2A7616FDC618ULL,
		0x135369C54CD70C5EULL,
		0x558E124FAD25F8E6ULL,
		0x599F7CCB4A69047BULL,
		0xFE5900951137615AULL,
		0x53B7AC91D46F6ED1ULL,
		0x74B300FB64B89453ULL,
		0xE6CCAA07792EFD21ULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}