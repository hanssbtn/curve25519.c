#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xF9889CAEE815F946ULL,
		0x688AF475D982CE16ULL,
		0x3E38BD0A35BE93F5ULL,
		0xBF0C04DDB90F37FBULL,
		0x33AF4F69A1FC7933ULL,
		0x776D1EA63D15DBD3ULL,
		0xC972CB61AC158DC2ULL,
		0x34FFE2A1B6410390ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF311395DD02BF28CULL,
		0xD115E8EBB3059C2DULL,
		0x7C717A146B7D27EAULL,
		0x7E1809BB721E6FF6ULL,
		0x675E9ED343F8F267ULL,
		0xEEDA3D4C7A2BB7A6ULL,
		0x92E596C3582B1B84ULL,
		0x69FFC5436C820721ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35C3A830E9C962E2ULL,
		0x8E66D554733513FAULL,
		0xBC4F8762156FAD7FULL,
		0xD92F14EFFF63324BULL,
		0xFC06EF51156F522FULL,
		0x672BB1BBD0B06BE9ULL,
		0x38BEFF2981F12229ULL,
		0x32F8BB48B076D2A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B875061D392C5C4ULL,
		0x1CCDAAA8E66A27F4ULL,
		0x789F0EC42ADF5AFFULL,
		0xB25E29DFFEC66497ULL,
		0xF80DDEA22ADEA45FULL,
		0xCE576377A160D7D3ULL,
		0x717DFE5303E24452ULL,
		0x65F1769160EDA544ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC834E1B903593465ULL,
		0xCA6090282770E683ULL,
		0xE26821554DAF2013ULL,
		0xE9E31E587751A423ULL,
		0xADC0B08EBF84ADF1ULL,
		0xAF89E46F68AF6977ULL,
		0xF0928627F72EB537ULL,
		0x3E50A464DEDCC155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9069C37206B268CAULL,
		0x94C120504EE1CD07ULL,
		0xC4D042AA9B5E4027ULL,
		0xD3C63CB0EEA34847ULL,
		0x5B81611D7F095BE3ULL,
		0x5F13C8DED15ED2EFULL,
		0xE1250C4FEE5D6A6FULL,
		0x7CA148C9BDB982ABULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59A772EFFE60A94DULL,
		0xDEDBC10800A1577DULL,
		0x43DB5C202A2B92E2ULL,
		0xF31FA061E070533AULL,
		0x1284EE44C78362B6ULL,
		0x3EC27103FFA592C2ULL,
		0x9968888728BDB2DEULL,
		0x1F330C1A33F7C99EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB34EE5DFFCC1529AULL,
		0xBDB782100142AEFAULL,
		0x87B6B840545725C5ULL,
		0xE63F40C3C0E0A674ULL,
		0x2509DC898F06C56DULL,
		0x7D84E207FF4B2584ULL,
		0x32D1110E517B65BCULL,
		0x3E66183467EF933DULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB47C9E296F0C2C00ULL,
		0x869619D8856CFCA5ULL,
		0x0DEF7DDA89FF770FULL,
		0x6FDC532BFD0B78ACULL,
		0xC01FF5C24E02B7FDULL,
		0x25113592B722C641ULL,
		0xBD0BCF05D4840E80ULL,
		0x3EEB8F30FDAE3B47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F93C52DE185800ULL,
		0x0D2C33B10AD9F94BULL,
		0x1BDEFBB513FEEE1FULL,
		0xDFB8A657FA16F158ULL,
		0x803FEB849C056FFAULL,
		0x4A226B256E458C83ULL,
		0x7A179E0BA9081D00ULL,
		0x7DD71E61FB5C768FULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB143D6828A2B5021ULL,
		0xBC459519139E3119ULL,
		0x25C9D071FDAF329CULL,
		0x22F4D67E547443EFULL,
		0x42AD3A45C6BDD634ULL,
		0xB789C1D54FC5E6B8ULL,
		0x6CA1E213295BA873ULL,
		0x30A63D46F83A6637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6287AD051456A042ULL,
		0x788B2A32273C6233ULL,
		0x4B93A0E3FB5E6539ULL,
		0x45E9ACFCA8E887DEULL,
		0x855A748B8D7BAC68ULL,
		0x6F1383AA9F8BCD70ULL,
		0xD943C42652B750E7ULL,
		0x614C7A8DF074CC6EULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21C6FF9B5CC9496EULL,
		0x455DF6C00F507705ULL,
		0xFEC81972DFD8FAFEULL,
		0xD3707877545D4BDDULL,
		0xA17059F12B25B9AEULL,
		0xE3C45A14E4C253EBULL,
		0x8D680C65E4CAC043ULL,
		0x2E02557AF96B5AF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x438DFF36B99292DCULL,
		0x8ABBED801EA0EE0AULL,
		0xFD9032E5BFB1F5FCULL,
		0xA6E0F0EEA8BA97BBULL,
		0x42E0B3E2564B735DULL,
		0xC788B429C984A7D7ULL,
		0x1AD018CBC9958087ULL,
		0x5C04AAF5F2D6B5E9ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5141EDA93C339623ULL,
		0x0E02C4DECAC6F433ULL,
		0x91C9195C08C07451ULL,
		0x2F84AC1FF19B8BC3ULL,
		0x28094D7FE13B096EULL,
		0x995DD5440F25C4D0ULL,
		0x538EB905BDCAF000ULL,
		0x150BC398C1835DF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA283DB5278672C46ULL,
		0x1C0589BD958DE866ULL,
		0x239232B81180E8A2ULL,
		0x5F09583FE3371787ULL,
		0x50129AFFC27612DCULL,
		0x32BBAA881E4B89A0ULL,
		0xA71D720B7B95E001ULL,
		0x2A1787318306BBE6ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51BC0FB0F9B8A136ULL,
		0xA8ED01D86F697FC0ULL,
		0x8537E7C3C49BF8F9ULL,
		0x44D573A2DD46DA8AULL,
		0x2DA000395E80E3E1ULL,
		0x3153F89D2518D463ULL,
		0xC440C8FBB6AE9DB7ULL,
		0x06B710C823D07D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3781F61F371426CULL,
		0x51DA03B0DED2FF80ULL,
		0x0A6FCF878937F1F3ULL,
		0x89AAE745BA8DB515ULL,
		0x5B400072BD01C7C2ULL,
		0x62A7F13A4A31A8C6ULL,
		0x888191F76D5D3B6EULL,
		0x0D6E219047A0FA87ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E7A7266ED55D76AULL,
		0x83A4C64066605A64ULL,
		0xBD2ABE5E95C8FA9EULL,
		0xEFC1921C8C59B244ULL,
		0xC59B0003ED8C4092ULL,
		0x999102EB62C0581CULL,
		0x49E5AFD4360217EDULL,
		0x1B072382184BE719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF4E4CDDAABAED4ULL,
		0x07498C80CCC0B4C8ULL,
		0x7A557CBD2B91F53DULL,
		0xDF83243918B36489ULL,
		0x8B360007DB188125ULL,
		0x332205D6C580B039ULL,
		0x93CB5FA86C042FDBULL,
		0x360E47043097CE32ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1040249DF0074F11ULL,
		0x91325A25CE3B7FE9ULL,
		0xDB0FC5D06CC1864AULL,
		0x9A9AF1E22F7B5333ULL,
		0x15F28AE96279C238ULL,
		0x120FBDA38BBD08D7ULL,
		0xE6AF962242ED7F5FULL,
		0x3B33A4C5924F0C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2080493BE00E9E22ULL,
		0x2264B44B9C76FFD2ULL,
		0xB61F8BA0D9830C95ULL,
		0x3535E3C45EF6A667ULL,
		0x2BE515D2C4F38471ULL,
		0x241F7B47177A11AEULL,
		0xCD5F2C4485DAFEBEULL,
		0x7667498B249E1887ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x496AB82ABE6B3F3AULL,
		0xB51ED6AC648D5EB1ULL,
		0x0B68966256E41E80ULL,
		0x49DEFE2B9582F771ULL,
		0xB814E98A666FBD4FULL,
		0xB5695824FA5A049FULL,
		0xA079EB2C3A9F022EULL,
		0x3622DBD40CC81E89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92D570557CD67E74ULL,
		0x6A3DAD58C91ABD62ULL,
		0x16D12CC4ADC83D01ULL,
		0x93BDFC572B05EEE2ULL,
		0x7029D314CCDF7A9EULL,
		0x6AD2B049F4B4093FULL,
		0x40F3D658753E045DULL,
		0x6C45B7A819903D13ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5EB82C6F6C8B44CULL,
		0x29A25E29D7BEE962ULL,
		0x8DF3D72739F706B2ULL,
		0x91ECCA21F1EC3F4AULL,
		0x27C922568622058EULL,
		0xCDBA44B896526161ULL,
		0xC08708F15CD842FDULL,
		0x227CB2B73B0E573EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD7058DED916898ULL,
		0x5344BC53AF7DD2C5ULL,
		0x1BE7AE4E73EE0D64ULL,
		0x23D99443E3D87E95ULL,
		0x4F9244AD0C440B1DULL,
		0x9B7489712CA4C2C2ULL,
		0x810E11E2B9B085FBULL,
		0x44F9656E761CAE7DULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98DD667A017AD354ULL,
		0xFC2EB1352DACCBA3ULL,
		0xF9CEB1870278159FULL,
		0x9B919E3F2F67D8E0ULL,
		0xBB8FE0A333CF3342ULL,
		0x66671D79330C4909ULL,
		0x36A11C452CB3F67FULL,
		0x2297EC86B8AFD26FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31BACCF402F5A6A8ULL,
		0xF85D626A5B599747ULL,
		0xF39D630E04F02B3FULL,
		0x37233C7E5ECFB1C1ULL,
		0x771FC146679E6685ULL,
		0xCCCE3AF266189213ULL,
		0x6D42388A5967ECFEULL,
		0x452FD90D715FA4DEULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ED24C8D804F2A31ULL,
		0xED5D9B535799EAF3ULL,
		0xA2BFB3A5B58441B7ULL,
		0xD49B484A295F924DULL,
		0xFCA5A60111A65E9AULL,
		0x41DF924DDA019413ULL,
		0x84A6610A9183F310ULL,
		0x33464E8E9E19C6CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA4991B009E5462ULL,
		0xDABB36A6AF33D5E6ULL,
		0x457F674B6B08836FULL,
		0xA936909452BF249BULL,
		0xF94B4C02234CBD35ULL,
		0x83BF249BB4032827ULL,
		0x094CC2152307E620ULL,
		0x668C9D1D3C338D9FULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x907A1ABE7EDD7ACDULL,
		0x46F9068B0E03F2EBULL,
		0x0D73A9B139751621ULL,
		0xF7F08FF5B051D6F9ULL,
		0x3B7AD046D5A9F9E5ULL,
		0x989A27031D109436ULL,
		0xF4C60F737FC3F109ULL,
		0x311B85C55081A822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20F4357CFDBAF59AULL,
		0x8DF20D161C07E5D7ULL,
		0x1AE7536272EA2C42ULL,
		0xEFE11FEB60A3ADF2ULL,
		0x76F5A08DAB53F3CBULL,
		0x31344E063A21286CULL,
		0xE98C1EE6FF87E213ULL,
		0x62370B8AA1035045ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA9A4DE5845C32C5ULL,
		0x3F668A8833A104E0ULL,
		0xBCBC2563D7956846ULL,
		0x0DA195462B5DE616ULL,
		0x5966CA3171432BFDULL,
		0xC87085C91DE0E6B7ULL,
		0xAE215D0001C14412ULL,
		0x32160B41BEA47650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5349BCB08B8658AULL,
		0x7ECD1510674209C1ULL,
		0x79784AC7AF2AD08CULL,
		0x1B432A8C56BBCC2DULL,
		0xB2CD9462E28657FAULL,
		0x90E10B923BC1CD6EULL,
		0x5C42BA0003828825ULL,
		0x642C16837D48ECA1ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC14C621CF63F1332ULL,
		0x63C9DB1917DEA3D6ULL,
		0x2ACA16A267D7CBCEULL,
		0x4C047C1467AC8125ULL,
		0x96D6C0E0B3321317ULL,
		0xB9CDD72E1726552EULL,
		0x9DC05AA7741B1732ULL,
		0x099A0C96E86F49ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8298C439EC7E2664ULL,
		0xC793B6322FBD47ADULL,
		0x55942D44CFAF979CULL,
		0x9808F828CF59024AULL,
		0x2DAD81C16664262EULL,
		0x739BAE5C2E4CAA5DULL,
		0x3B80B54EE8362E65ULL,
		0x1334192DD0DE9357ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F5045AB71EC5011ULL,
		0x685F89DC83FD104AULL,
		0x64A91E25790481A9ULL,
		0x172AC1B0A839108FULL,
		0x896FB0D1E330110BULL,
		0xE978BD64B463C2E7ULL,
		0x1EDE4869A2328C75ULL,
		0x1B460A9C854AB490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA08B56E3D8A022ULL,
		0xD0BF13B907FA2094ULL,
		0xC9523C4AF2090352ULL,
		0x2E5583615072211EULL,
		0x12DF61A3C6602216ULL,
		0xD2F17AC968C785CFULL,
		0x3DBC90D3446518EBULL,
		0x368C15390A956920ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF055E812CB92752ULL,
		0x5055843D84249968ULL,
		0x126C11763B3C4A9CULL,
		0xC66624EA25C93EBAULL,
		0x26DAF1174180C461ULL,
		0x0417ACB77578E220ULL,
		0x1F47A9AA9F06881CULL,
		0x1C9B6B49251491C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0ABD0259724EA4ULL,
		0xA0AB087B084932D1ULL,
		0x24D822EC76789538ULL,
		0x8CCC49D44B927D74ULL,
		0x4DB5E22E830188C3ULL,
		0x082F596EEAF1C440ULL,
		0x3E8F53553E0D1038ULL,
		0x3936D6924A292380ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8A54DD3C175D285ULL,
		0x9E4744E78A98F31BULL,
		0x459364C5E3BCE03EULL,
		0xD9230BCECF8FBA2CULL,
		0x7B296A79DCBED2E5ULL,
		0xE2AEC825735D8559ULL,
		0xC4D876C5ECF1BD62ULL,
		0x372B2B76BEF08137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB14A9BA782EBA50AULL,
		0x3C8E89CF1531E637ULL,
		0x8B26C98BC779C07DULL,
		0xB246179D9F1F7458ULL,
		0xF652D4F3B97DA5CBULL,
		0xC55D904AE6BB0AB2ULL,
		0x89B0ED8BD9E37AC5ULL,
		0x6E5656ED7DE1026FULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC67E2DD27429B8C5ULL,
		0x84A263EF490672B4ULL,
		0xEA7440B0AE743047ULL,
		0xD9E971DFEE84F608ULL,
		0xDD88B26876235F4DULL,
		0x0D7AB46BF3AAAD07ULL,
		0xF71B9A54D6051EC8ULL,
		0x288105648F723357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CFC5BA4E853718AULL,
		0x0944C7DE920CE569ULL,
		0xD4E881615CE8608FULL,
		0xB3D2E3BFDD09EC11ULL,
		0xBB1164D0EC46BE9BULL,
		0x1AF568D7E7555A0FULL,
		0xEE3734A9AC0A3D90ULL,
		0x51020AC91EE466AFULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CD1F731FD45FC65ULL,
		0xF06282295317D943ULL,
		0xE7A02C0171807D13ULL,
		0x61200987B0F5CE80ULL,
		0xD06B1CA96F61FDE9ULL,
		0x623EFBD22BB2230DULL,
		0x44A2B6A4030E7154ULL,
		0x0E0CC09540836023ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A3EE63FA8BF8CAULL,
		0xE0C50452A62FB286ULL,
		0xCF405802E300FA27ULL,
		0xC240130F61EB9D01ULL,
		0xA0D63952DEC3FBD2ULL,
		0xC47DF7A45764461BULL,
		0x89456D48061CE2A8ULL,
		0x1C19812A8106C046ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD81BA3A851B3CC46ULL,
		0xE600C6CC06ABF543ULL,
		0x53038F6B6EBA822CULL,
		0x03B66F5762AEEFA7ULL,
		0x530DC00A1988DE67ULL,
		0xBECC4D7736BEB6A4ULL,
		0x5A54FF8DACE7682BULL,
		0x3CF1A2B58A293F85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0374750A367988CULL,
		0xCC018D980D57EA87ULL,
		0xA6071ED6DD750459ULL,
		0x076CDEAEC55DDF4EULL,
		0xA61B80143311BCCEULL,
		0x7D989AEE6D7D6D48ULL,
		0xB4A9FF1B59CED057ULL,
		0x79E3456B14527F0AULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB964D76DAF1ABAECULL,
		0x743E89264B6F13AAULL,
		0xFBEB9988DC9573F9ULL,
		0xC6C245BAC77EE999ULL,
		0x7097AF4F9B050491ULL,
		0xB9DF41A63AAF279AULL,
		0x526FB6EB8272E5ECULL,
		0x3B9C7F6192691B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72C9AEDB5E3575D8ULL,
		0xE87D124C96DE2755ULL,
		0xF7D73311B92AE7F2ULL,
		0x8D848B758EFDD333ULL,
		0xE12F5E9F360A0923ULL,
		0x73BE834C755E4F34ULL,
		0xA4DF6DD704E5CBD9ULL,
		0x7738FEC324D2366EULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x089F1198939E172FULL,
		0xE8D2366D82C63104ULL,
		0xE43D228C113952D5ULL,
		0xDC6C71D65BECCDE8ULL,
		0xF5D883C24000C7B7ULL,
		0xF769C96CCDC37C9AULL,
		0x38A747E80548CF0DULL,
		0x03042F6C2B3B9C8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x113E2331273C2E5EULL,
		0xD1A46CDB058C6208ULL,
		0xC87A45182272A5ABULL,
		0xB8D8E3ACB7D99BD1ULL,
		0xEBB1078480018F6FULL,
		0xEED392D99B86F935ULL,
		0x714E8FD00A919E1BULL,
		0x06085ED856773918ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDC4DEFF0BA197BCULL,
		0xABBB40DAD269B187ULL,
		0x20576F705E38ECBAULL,
		0x78836555B53A7F6BULL,
		0x383E3139B5A05FBEULL,
		0x73E8194693F084C2ULL,
		0xCFD742BC4207D959ULL,
		0x10B633C04FF88804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB89BDFE17432F78ULL,
		0x577681B5A4D3630FULL,
		0x40AEDEE0BC71D975ULL,
		0xF106CAAB6A74FED6ULL,
		0x707C62736B40BF7CULL,
		0xE7D0328D27E10984ULL,
		0x9FAE8578840FB2B2ULL,
		0x216C67809FF11009ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8945DB33DC243BF6ULL,
		0x8ECD210C994FFC64ULL,
		0xF8604E2D6B0913BCULL,
		0xC767BE8602B3E542ULL,
		0xA7CF1991DBF89A82ULL,
		0xB7042DFE4C476DF9ULL,
		0x89EF871F2058C3E6ULL,
		0x263DC4A1029510BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128BB667B84877ECULL,
		0x1D9A4219329FF8C9ULL,
		0xF0C09C5AD6122779ULL,
		0x8ECF7D0C0567CA85ULL,
		0x4F9E3323B7F13505ULL,
		0x6E085BFC988EDBF3ULL,
		0x13DF0E3E40B187CDULL,
		0x4C7B8942052A217FULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96C8B57A4D7141B3ULL,
		0x033EDD66B7B5EB2AULL,
		0x078503967D00D529ULL,
		0x2F776F46A4430338ULL,
		0x3147688D06B7CF44ULL,
		0x82DDDB7FCA3B5D0AULL,
		0x499D25818ADB5D3FULL,
		0x321823F74832983BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D916AF49AE28366ULL,
		0x067DBACD6F6BD655ULL,
		0x0F0A072CFA01AA52ULL,
		0x5EEEDE8D48860670ULL,
		0x628ED11A0D6F9E88ULL,
		0x05BBB6FF9476BA14ULL,
		0x933A4B0315B6BA7FULL,
		0x643047EE90653076ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EE2CDC72C4C1795ULL,
		0x31E07D8DB3474A8BULL,
		0x37722AD74E5EA3C6ULL,
		0x82242F960FF78459ULL,
		0xB4CB03E6D50445E8ULL,
		0x4BBC654A12CDB1E1ULL,
		0xF8EFCB76B37CCA63ULL,
		0x13438BFAE519265DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC59B8E58982F2AULL,
		0x63C0FB1B668E9516ULL,
		0x6EE455AE9CBD478CULL,
		0x04485F2C1FEF08B2ULL,
		0x699607CDAA088BD1ULL,
		0x9778CA94259B63C3ULL,
		0xF1DF96ED66F994C6ULL,
		0x268717F5CA324CBBULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71A9177E2D538C54ULL,
		0x6B66391AD84F95F7ULL,
		0x41726AF0C326DD42ULL,
		0x6C93492FCB141A4FULL,
		0x3BE62A069DA1948AULL,
		0x74ED358C426416FEULL,
		0x6EF3A267920F878AULL,
		0x002FA929BE3C18F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3522EFC5AA718A8ULL,
		0xD6CC7235B09F2BEEULL,
		0x82E4D5E1864DBA84ULL,
		0xD926925F9628349EULL,
		0x77CC540D3B432914ULL,
		0xE9DA6B1884C82DFCULL,
		0xDDE744CF241F0F14ULL,
		0x005F52537C7831EAULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3EF987A71032ACFULL,
		0x7C24184D69FACD76ULL,
		0xE835598C43A2C6C5ULL,
		0xCDB30DD1031F60A6ULL,
		0xBA91281446BEAF2CULL,
		0x5A96921B573ABA70ULL,
		0x262691C353FF14B0ULL,
		0x3D4318F4DCBD61D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DF30F4E206559EULL,
		0xF848309AD3F59AEDULL,
		0xD06AB31887458D8AULL,
		0x9B661BA2063EC14DULL,
		0x752250288D7D5E59ULL,
		0xB52D2436AE7574E1ULL,
		0x4C4D2386A7FE2960ULL,
		0x7A8631E9B97AC3AAULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF288AA205093E03ULL,
		0x2394AC13DC39271FULL,
		0x69335AD042CB3970ULL,
		0x6ED338E8B10DFAE2ULL,
		0x91DEF2C0F427FA88ULL,
		0xE598DA38E1463C0AULL,
		0xB69F22CE2F9439BFULL,
		0x0A94CCE122BF09EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE5115440A127C06ULL,
		0x47295827B8724E3FULL,
		0xD266B5A0859672E0ULL,
		0xDDA671D1621BF5C4ULL,
		0x23BDE581E84FF510ULL,
		0xCB31B471C28C7815ULL,
		0x6D3E459C5F28737FULL,
		0x152999C2457E13D5ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BFB8134D9F3491EULL,
		0xAD29DC970F863234ULL,
		0x91BCD337A7CB6869ULL,
		0x31681ECAF158FD85ULL,
		0x145F3F8A123158C3ULL,
		0x03D823C055C0D9ACULL,
		0xFD47750E4A33DD23ULL,
		0x3FA78E0EB74DD340ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F70269B3E6923CULL,
		0x5A53B92E1F0C6468ULL,
		0x2379A66F4F96D0D3ULL,
		0x62D03D95E2B1FB0BULL,
		0x28BE7F142462B186ULL,
		0x07B04780AB81B358ULL,
		0xFA8EEA1C9467BA46ULL,
		0x7F4F1C1D6E9BA681ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46536900AFABCC2BULL,
		0x3D28E1003BC2DB81ULL,
		0xAC404FD40BBF2FFDULL,
		0x137B4763032B3240ULL,
		0x0BB939ED57CFE98EULL,
		0x12510D113123E131ULL,
		0x6C7B43675125730DULL,
		0x0B42D070552EE8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CA6D2015F579856ULL,
		0x7A51C2007785B702ULL,
		0x58809FA8177E5FFAULL,
		0x26F68EC606566481ULL,
		0x177273DAAF9FD31CULL,
		0x24A21A226247C262ULL,
		0xD8F686CEA24AE61AULL,
		0x1685A0E0AA5DD16AULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF012E4D974B4E1CBULL,
		0x88B2DBE1B75D37ABULL,
		0x7FEE4C7EFFBE44AEULL,
		0xFBD4A6C6DC1F5D41ULL,
		0xC1810ED53A1CDBFDULL,
		0x26D8E7757E39DD0BULL,
		0xB11A3B98CA156CFFULL,
		0x0C998A321297FF02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE025C9B2E969C396ULL,
		0x1165B7C36EBA6F57ULL,
		0xFFDC98FDFF7C895DULL,
		0xF7A94D8DB83EBA82ULL,
		0x83021DAA7439B7FBULL,
		0x4DB1CEEAFC73BA17ULL,
		0x62347731942AD9FEULL,
		0x19331464252FFE05ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBACA68F42F57DCFCULL,
		0x601E4EBA75BD23E2ULL,
		0xD04292AC660E9C29ULL,
		0xF9423F4CF4666949ULL,
		0xCFF7E678B00E1004ULL,
		0x915C6E6FD8EA76ABULL,
		0x452078D779869A1EULL,
		0x1AFB9E35009B8393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7594D1E85EAFB9F8ULL,
		0xC03C9D74EB7A47C5ULL,
		0xA0852558CC1D3852ULL,
		0xF2847E99E8CCD293ULL,
		0x9FEFCCF1601C2009ULL,
		0x22B8DCDFB1D4ED57ULL,
		0x8A40F1AEF30D343DULL,
		0x35F73C6A01370726ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5A659057B6585C9ULL,
		0x9E5696143A87AAB9ULL,
		0xCDADFFFC8D78DDE7ULL,
		0xED5F08779F9EF18DULL,
		0xA51915B851611034ULL,
		0xDA1249C565418DFEULL,
		0xD8346A8A9DB6B4C2ULL,
		0x2F68DE6F8391CEE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B4CB20AF6CB0B92ULL,
		0x3CAD2C28750F5573ULL,
		0x9B5BFFF91AF1BBCFULL,
		0xDABE10EF3F3DE31BULL,
		0x4A322B70A2C22069ULL,
		0xB424938ACA831BFDULL,
		0xB068D5153B6D6985ULL,
		0x5ED1BCDF07239DCDULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51E3663E71E37193ULL,
		0x744E9AD02756D24EULL,
		0xC36FC52FBF015A3AULL,
		0xF8A1DB80D716C715ULL,
		0xC7CA506B27B27F99ULL,
		0x677C9241F8A2660FULL,
		0xC76FE4F7E7F37BCAULL,
		0x1C63E74E6B980135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C6CC7CE3C6E326ULL,
		0xE89D35A04EADA49CULL,
		0x86DF8A5F7E02B474ULL,
		0xF143B701AE2D8E2BULL,
		0x8F94A0D64F64FF33ULL,
		0xCEF92483F144CC1FULL,
		0x8EDFC9EFCFE6F794ULL,
		0x38C7CE9CD730026BULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57C09EAF472D0694ULL,
		0xDA976EA04FD39705ULL,
		0x6BF7EB94B50593F5ULL,
		0x5349EEA6208C813CULL,
		0xFEBCFE3E249506AEULL,
		0x074314C4DDC78D42ULL,
		0x8BE1FA1201597A75ULL,
		0x370769164B382544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF813D5E8E5A0D28ULL,
		0xB52EDD409FA72E0AULL,
		0xD7EFD7296A0B27EBULL,
		0xA693DD4C41190278ULL,
		0xFD79FC7C492A0D5CULL,
		0x0E862989BB8F1A85ULL,
		0x17C3F42402B2F4EAULL,
		0x6E0ED22C96704A89ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2FE50A6EC792536ULL,
		0x5DBD5F29E72D3812ULL,
		0x4A365599DFC2EF4FULL,
		0x4385C82624020E2FULL,
		0x4CCEEAFDC3E82BB7ULL,
		0x2F4DCD6F4CA88027ULL,
		0x1414D7A459901051ULL,
		0x3C542D97EE8F05B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65FCA14DD8F24A6CULL,
		0xBB7ABE53CE5A7025ULL,
		0x946CAB33BF85DE9EULL,
		0x870B904C48041C5EULL,
		0x999DD5FB87D0576EULL,
		0x5E9B9ADE9951004EULL,
		0x2829AF48B32020A2ULL,
		0x78A85B2FDD1E0B66ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40B85CF2B6578D4FULL,
		0x1E7FCEDCAFFC8912ULL,
		0xC1A06B6490128041ULL,
		0xF3E7708F5E2B5A6CULL,
		0x4479185EFA48AB91ULL,
		0x3BF0DBFEC82FCE9BULL,
		0x30693103107449BEULL,
		0x1B7C96FBAA2F2D14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8170B9E56CAF1A9EULL,
		0x3CFF9DB95FF91224ULL,
		0x8340D6C920250082ULL,
		0xE7CEE11EBC56B4D9ULL,
		0x88F230BDF4915723ULL,
		0x77E1B7FD905F9D36ULL,
		0x60D2620620E8937CULL,
		0x36F92DF7545E5A28ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x805F3BAED64AD67CULL,
		0xAC597884AA57C8F0ULL,
		0x2CDEB1E31055D27FULL,
		0xE21C0EC52C623162ULL,
		0xF0E3A845F64B869EULL,
		0xBC78F486EBE06DFAULL,
		0x3828FBFF79F4388FULL,
		0x320F41A94DF5AB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00BE775DAC95ACF8ULL,
		0x58B2F10954AF91E1ULL,
		0x59BD63C620ABA4FFULL,
		0xC4381D8A58C462C4ULL,
		0xE1C7508BEC970D3DULL,
		0x78F1E90DD7C0DBF5ULL,
		0x7051F7FEF3E8711FULL,
		0x641E83529BEB5730ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9547E541451F3A0ULL,
		0xFFB800990CB49F97ULL,
		0x9EB44EC916AF6CC4ULL,
		0x92752EFBE1BE8DBDULL,
		0xC26B57F3FCECAB92ULL,
		0x79F3EE0CC5DB9582ULL,
		0xEC93856002383AF0ULL,
		0x3E645A538C6CA8A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A8FCA828A3E740ULL,
		0xFF70013219693F2FULL,
		0x3D689D922D5ED989ULL,
		0x24EA5DF7C37D1B7BULL,
		0x84D6AFE7F9D95725ULL,
		0xF3E7DC198BB72B05ULL,
		0xD9270AC0047075E0ULL,
		0x7CC8B4A718D95147ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66BCB482CB1FDB2AULL,
		0x53F49D8F4806F3ACULL,
		0x6919AE5BB8B07C30ULL,
		0xC824688F204E5471ULL,
		0xCAD690DB755FCB0CULL,
		0xD1BD7FDFA838A3DEULL,
		0xAEF72D8633D8B854ULL,
		0x3C9D096EF2B43B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD796905963FB654ULL,
		0xA7E93B1E900DE758ULL,
		0xD2335CB77160F860ULL,
		0x9048D11E409CA8E2ULL,
		0x95AD21B6EABF9619ULL,
		0xA37AFFBF507147BDULL,
		0x5DEE5B0C67B170A9ULL,
		0x793A12DDE5687709ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x173FC9D40AD8B818ULL,
		0x7CDD0F3CE1D2FFBCULL,
		0x642184ACFEB3B44DULL,
		0xCDDE906043EE392AULL,
		0xE380792CBF2BE894ULL,
		0x2FE260CA51F7D7BBULL,
		0xB26E18F27CEDB69DULL,
		0x1A456FD79E7F935DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E7F93A815B17030ULL,
		0xF9BA1E79C3A5FF78ULL,
		0xC8430959FD67689AULL,
		0x9BBD20C087DC7254ULL,
		0xC700F2597E57D129ULL,
		0x5FC4C194A3EFAF77ULL,
		0x64DC31E4F9DB6D3AULL,
		0x348ADFAF3CFF26BBULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C160E3E3C9037D2ULL,
		0xC5610D6989F84AC1ULL,
		0x1A7D841CCD8F511CULL,
		0xD8D6CF677A944165ULL,
		0x7A2C9AAFF8AD7500ULL,
		0xC734C5754D19AD53ULL,
		0x10E6272288CADBF6ULL,
		0x01FE7F50DA92D507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82C1C7C79206FA4ULL,
		0x8AC21AD313F09582ULL,
		0x34FB08399B1EA239ULL,
		0xB1AD9ECEF52882CAULL,
		0xF459355FF15AEA01ULL,
		0x8E698AEA9A335AA6ULL,
		0x21CC4E451195B7EDULL,
		0x03FCFEA1B525AA0EULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6C85B339BB1A4E3ULL,
		0x29F611795E47E3B1ULL,
		0x16F3164427369989ULL,
		0x203CD6BDEAA9ACB5ULL,
		0xD4F7F33CAC7AADAEULL,
		0xC3CB31B380C60DCCULL,
		0x40CA7EBC42250E21ULL,
		0x22DA78F8451C80B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD90B667376349C6ULL,
		0x53EC22F2BC8FC763ULL,
		0x2DE62C884E6D3312ULL,
		0x4079AD7BD553596AULL,
		0xA9EFE67958F55B5CULL,
		0x87966367018C1B99ULL,
		0x8194FD78844A1C43ULL,
		0x45B4F1F08A390164ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD509D39064BD678ULL,
		0x21D32C0AF55C41DEULL,
		0xB91DB2567A636B86ULL,
		0xE3D8A1159244B264ULL,
		0x656A2286568345DFULL,
		0xC455F91E02D2D08EULL,
		0x92E659850240AC05ULL,
		0x352CABF80076021EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAA13A720C97ACF0ULL,
		0x43A65815EAB883BDULL,
		0x723B64ACF4C6D70CULL,
		0xC7B1422B248964C9ULL,
		0xCAD4450CAD068BBFULL,
		0x88ABF23C05A5A11CULL,
		0x25CCB30A0481580BULL,
		0x6A5957F000EC043DULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BF878F317ED99CDULL,
		0xB8BA40F5311841B3ULL,
		0x3A5BA1DC18EE96E6ULL,
		0x635E720CBD4EEC3CULL,
		0xE8581C05929875A9ULL,
		0x15DECBB662EEC151ULL,
		0xCD3F84EBB3C35088ULL,
		0x34E432B34C14A0D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F0F1E62FDB339AULL,
		0x717481EA62308366ULL,
		0x74B743B831DD2DCDULL,
		0xC6BCE4197A9DD878ULL,
		0xD0B0380B2530EB52ULL,
		0x2BBD976CC5DD82A3ULL,
		0x9A7F09D76786A110ULL,
		0x69C86566982941A9ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B2AF76D42014E66ULL,
		0x4BAC795771A4C844ULL,
		0x5547B3DDFA6A1E80ULL,
		0x54A477E9C14605C2ULL,
		0x6F46A78CAC19AFBDULL,
		0x80744F573C343C67ULL,
		0x3EE00D344320BD1DULL,
		0x358A9770BA10414DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF655EEDA84029CCCULL,
		0x9758F2AEE3499088ULL,
		0xAA8F67BBF4D43D00ULL,
		0xA948EFD3828C0B84ULL,
		0xDE8D4F1958335F7AULL,
		0x00E89EAE786878CEULL,
		0x7DC01A6886417A3BULL,
		0x6B152EE17420829AULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4400CEAE5DD357FULL,
		0x2E7D05289B288BCFULL,
		0x316DC59B82B3862DULL,
		0xC6A0DC9257DEC7DBULL,
		0x729D20BE09EDE777ULL,
		0x7CE2B438D7F89DFCULL,
		0x6BE62AA051EC80EDULL,
		0x209B13DE0171030DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88019D5CBBA6AFEULL,
		0x5CFA0A513651179FULL,
		0x62DB8B3705670C5AULL,
		0x8D41B924AFBD8FB6ULL,
		0xE53A417C13DBCEEFULL,
		0xF9C56871AFF13BF8ULL,
		0xD7CC5540A3D901DAULL,
		0x413627BC02E2061AULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21D0635B5E5BDA77ULL,
		0x40CF1718BECCE6B3ULL,
		0x12495AD5390C93B6ULL,
		0x0E40A5F253578EF2ULL,
		0x5A676365FE85E83CULL,
		0x4005EC1D402A4FD2ULL,
		0xCAD950FAA1BB9841ULL,
		0x0CC5B0D85C4580C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A0C6B6BCB7B4EEULL,
		0x819E2E317D99CD66ULL,
		0x2492B5AA7219276CULL,
		0x1C814BE4A6AF1DE4ULL,
		0xB4CEC6CBFD0BD078ULL,
		0x800BD83A80549FA4ULL,
		0x95B2A1F543773082ULL,
		0x198B61B0B88B0181ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB7BAFC7FD82A790ULL,
		0x5B880256629F9DB4ULL,
		0x8C926F589DE2F46BULL,
		0xC9BF682BBCDE45CDULL,
		0xD3C868648A188232ULL,
		0x56E8AD891FDDE557ULL,
		0xDF74D843D1B02865ULL,
		0x28BD1A7A311F1525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F75F8FFB054F20ULL,
		0xB71004ACC53F3B69ULL,
		0x1924DEB13BC5E8D6ULL,
		0x937ED05779BC8B9BULL,
		0xA790D0C914310465ULL,
		0xADD15B123FBBCAAFULL,
		0xBEE9B087A36050CAULL,
		0x517A34F4623E2A4BULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x834E426532F1364FULL,
		0x6FC494E70F7C765BULL,
		0x6F16FE2AB2CC9C9CULL,
		0x0DDAE907F9750F5FULL,
		0x40E6022F3F92D6F5ULL,
		0x6C9FEB5691C6402DULL,
		0x11159C801FFA22D8ULL,
		0x1C3299DB2D6C0AA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x069C84CA65E26C9EULL,
		0xDF8929CE1EF8ECB7ULL,
		0xDE2DFC5565993938ULL,
		0x1BB5D20FF2EA1EBEULL,
		0x81CC045E7F25ADEAULL,
		0xD93FD6AD238C805AULL,
		0x222B39003FF445B0ULL,
		0x386533B65AD81550ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DC24C2D0C9B9CE6ULL,
		0x0370935E5557A9B5ULL,
		0xAC406FDD6B72976FULL,
		0xBF858C7B5DCE1CA7ULL,
		0x1F15BE4DA4A90412ULL,
		0x8E67D9620D4D94C6ULL,
		0xC6DC68D2E2DE7FFAULL,
		0x2396C85816556E16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B84985A193739CCULL,
		0x06E126BCAAAF536BULL,
		0x5880DFBAD6E52EDEULL,
		0x7F0B18F6BB9C394FULL,
		0x3E2B7C9B49520825ULL,
		0x1CCFB2C41A9B298CULL,
		0x8DB8D1A5C5BCFFF5ULL,
		0x472D90B02CAADC2DULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x387072D3DC8612DFULL,
		0xE74D1FE01FD12B1BULL,
		0xC4DAAEB402B4111CULL,
		0x47B559E3B0542D4DULL,
		0xEA0031490010BD3AULL,
		0x7556FB0AA74A4337ULL,
		0x66739B46CB74CD8BULL,
		0x23140ED4F4A95E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E0E5A7B90C25BEULL,
		0xCE9A3FC03FA25636ULL,
		0x89B55D6805682239ULL,
		0x8F6AB3C760A85A9BULL,
		0xD400629200217A74ULL,
		0xEAADF6154E94866FULL,
		0xCCE7368D96E99B16ULL,
		0x46281DA9E952BD34ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBB9D658B7501D97ULL,
		0xD1C9F532EE4D4357ULL,
		0xFF15EB3662CE63BCULL,
		0xECC3C2352FD14A3EULL,
		0x4F500C391AD38615ULL,
		0x3C71D589AF3AFBFCULL,
		0xAFAEB57E0E7CE3D0ULL,
		0x2B3F13CDA77A8C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7773ACB16EA03B2EULL,
		0xA393EA65DC9A86AFULL,
		0xFE2BD66CC59CC779ULL,
		0xD987846A5FA2947DULL,
		0x9EA0187235A70C2BULL,
		0x78E3AB135E75F7F8ULL,
		0x5F5D6AFC1CF9C7A0ULL,
		0x567E279B4EF51869ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA44DD59AE017764ULL,
		0x715236193B0C4CB7ULL,
		0xFBDA34BF7F3C341DULL,
		0xF0CFF1268B1BDDCDULL,
		0x7E8D61FE25EEC976ULL,
		0xB3CC2D4FF2F9DC61ULL,
		0xD6262412AA14B65FULL,
		0x105B98657A511572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9489BAB35C02EEC8ULL,
		0xE2A46C327618996FULL,
		0xF7B4697EFE78683AULL,
		0xE19FE24D1637BB9BULL,
		0xFD1AC3FC4BDD92EDULL,
		0x67985A9FE5F3B8C2ULL,
		0xAC4C482554296CBFULL,
		0x20B730CAF4A22AE5ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96E5070EE1C3FF36ULL,
		0x0B8F152CE21518D0ULL,
		0x8341A7765D4629DAULL,
		0x48BB4EE3EBB7D5A5ULL,
		0xE18C69BC15C92E4FULL,
		0x68A9DE92CAD71D2CULL,
		0x46C585F2810FCBFFULL,
		0x0D6C09FB1DE21DB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DCA0E1DC387FE6CULL,
		0x171E2A59C42A31A1ULL,
		0x06834EECBA8C53B4ULL,
		0x91769DC7D76FAB4BULL,
		0xC318D3782B925C9EULL,
		0xD153BD2595AE3A59ULL,
		0x8D8B0BE5021F97FEULL,
		0x1AD813F63BC43B66ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF41A628725DC2D1ULL,
		0x7C4B8BC027BD9C54ULL,
		0x273F9AADAEB8FF8AULL,
		0x7A27CCD423330B26ULL,
		0xFCC0714697D9A570ULL,
		0x36BDA36062D6D73DULL,
		0xF7D75E2C07EAE7DEULL,
		0x3B72AED940AF6B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE834C50E4BB85A2ULL,
		0xF89717804F7B38A9ULL,
		0x4E7F355B5D71FF14ULL,
		0xF44F99A84666164CULL,
		0xF980E28D2FB34AE0ULL,
		0x6D7B46C0C5ADAE7BULL,
		0xEFAEBC580FD5CFBCULL,
		0x76E55DB2815ED6A5ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93DA401690AFDE72ULL,
		0x29AA1155DAE96C14ULL,
		0x64B7C45AAC301B39ULL,
		0x58A25934A2076AA2ULL,
		0x72451377B128A72BULL,
		0x4600EA3B5B1119D1ULL,
		0xC0D05041F1A81DE4ULL,
		0x11244F946B835C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27B4802D215FBCE4ULL,
		0x535422ABB5D2D829ULL,
		0xC96F88B558603672ULL,
		0xB144B269440ED544ULL,
		0xE48A26EF62514E56ULL,
		0x8C01D476B62233A2ULL,
		0x81A0A083E3503BC8ULL,
		0x22489F28D706B88BULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81D153B5218910F2ULL,
		0x40C4EB9AF0CD06E5ULL,
		0xF8BA78211A8CF492ULL,
		0xA38C10BFCDE64C5AULL,
		0xA0E18388D88B5017ULL,
		0x19BB6651EB9FA366ULL,
		0xE39D079AE37E338FULL,
		0x1C8B6C02A00F925AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A2A76A431221E4ULL,
		0x8189D735E19A0DCBULL,
		0xF174F0423519E924ULL,
		0x4718217F9BCC98B5ULL,
		0x41C30711B116A02FULL,
		0x3376CCA3D73F46CDULL,
		0xC73A0F35C6FC671EULL,
		0x3916D805401F24B5ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A55F86E606B54BCULL,
		0xCD15ED54568A3873ULL,
		0xDE5C07C11E763FE0ULL,
		0xD660206DEE94BAB2ULL,
		0x8A8F1914E2F016C3ULL,
		0x858A9B9C0B078BB2ULL,
		0xC1F93F026C5C2575ULL,
		0x0C0AF3379B0DDAC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34ABF0DCC0D6A978ULL,
		0x9A2BDAA8AD1470E6ULL,
		0xBCB80F823CEC7FC1ULL,
		0xACC040DBDD297565ULL,
		0x151E3229C5E02D87ULL,
		0x0B153738160F1765ULL,
		0x83F27E04D8B84AEBULL,
		0x1815E66F361BB58DULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x104D2711BD955CDEULL,
		0x8DE1D21347F008F3ULL,
		0x44AB190787C1D01FULL,
		0xB837280C8534AD9EULL,
		0x63DA27599C232697ULL,
		0x5C45140CF75588CEULL,
		0xE149D099213895FAULL,
		0x2AB7463299233BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209A4E237B2AB9BCULL,
		0x1BC3A4268FE011E6ULL,
		0x8956320F0F83A03FULL,
		0x706E50190A695B3CULL,
		0xC7B44EB338464D2FULL,
		0xB88A2819EEAB119CULL,
		0xC293A13242712BF4ULL,
		0x556E8C65324677B3ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2211C083704B0DD9ULL,
		0x0969EB81A6F72CA7ULL,
		0x6DAB637423E2FBF0ULL,
		0xE699468521BBC623ULL,
		0xFDDC658D7B22505AULL,
		0x4368653A1C6985FEULL,
		0xA2C5648737FEF902ULL,
		0x27039F58E899B3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44238106E0961BB2ULL,
		0x12D3D7034DEE594EULL,
		0xDB56C6E847C5F7E0ULL,
		0xCD328D0A43778C46ULL,
		0xFBB8CB1AF644A0B5ULL,
		0x86D0CA7438D30BFDULL,
		0x458AC90E6FFDF204ULL,
		0x4E073EB1D1336779ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3AE2A280F3697A5ULL,
		0xFF07FE563DF8394BULL,
		0x22C39F8ED7E54B8CULL,
		0x86D7F77EA2144888ULL,
		0xDA41FE8AECF93081ULL,
		0x6F3800E2AF007534ULL,
		0xC124E31C15AE2E6CULL,
		0x383B7B7A42825A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE75C54501E6D2F4AULL,
		0xFE0FFCAC7BF07297ULL,
		0x45873F1DAFCA9719ULL,
		0x0DAFEEFD44289110ULL,
		0xB483FD15D9F26103ULL,
		0xDE7001C55E00EA69ULL,
		0x8249C6382B5C5CD8ULL,
		0x7076F6F48504B4C3ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCECE56C14CA50901ULL,
		0xDD20F2CC2F84379BULL,
		0xAE34338A0B7BEA75ULL,
		0xEFBCC2816C506C64ULL,
		0xF66081A00294CBB7ULL,
		0x33C753C1874C233AULL,
		0x3A3B84F57EE87416ULL,
		0x0F5EBA77EB5C784FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9CAD82994A1202ULL,
		0xBA41E5985F086F37ULL,
		0x5C68671416F7D4EBULL,
		0xDF798502D8A0D8C9ULL,
		0xECC103400529976FULL,
		0x678EA7830E984675ULL,
		0x747709EAFDD0E82CULL,
		0x1EBD74EFD6B8F09EULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54F77EBB48757A35ULL,
		0x026A5601B6A6DC0DULL,
		0x2F16D493612F09B8ULL,
		0xD07EB4248D81CE39ULL,
		0x3DE865184E538158ULL,
		0xFC29B845C73DA92CULL,
		0x411C9F569C38BEFEULL,
		0x21D9148DAB2519E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EEFD7690EAF46AULL,
		0x04D4AC036D4DB81AULL,
		0x5E2DA926C25E1370ULL,
		0xA0FD68491B039C72ULL,
		0x7BD0CA309CA702B1ULL,
		0xF853708B8E7B5258ULL,
		0x82393EAD38717DFDULL,
		0x43B2291B564A33CAULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60DAB13736518092ULL,
		0x3A45721DDA06D9B5ULL,
		0xE9A7B24C0B4FAC91ULL,
		0xAB65D3521C66C817ULL,
		0xA7A518CE4FC18DCBULL,
		0x398147D54B9C28E6ULL,
		0x361FDD2F48A2238DULL,
		0x106DB3696E7F46E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1B5626E6CA30124ULL,
		0x748AE43BB40DB36AULL,
		0xD34F6498169F5922ULL,
		0x56CBA6A438CD902FULL,
		0x4F4A319C9F831B97ULL,
		0x73028FAA973851CDULL,
		0x6C3FBA5E9144471AULL,
		0x20DB66D2DCFE8DD0ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF987AB2FE9A9B70FULL,
		0x1661B779DD406706ULL,
		0xF5414C86615A9519ULL,
		0x47B68A94A5A4480DULL,
		0xE11E03407739F85DULL,
		0xF33E301680BCD2B7ULL,
		0xFBE716A8086E803EULL,
		0x1A3A82A38DF6CE6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF30F565FD3536E1EULL,
		0x2CC36EF3BA80CE0DULL,
		0xEA82990CC2B52A32ULL,
		0x8F6D15294B48901BULL,
		0xC23C0680EE73F0BAULL,
		0xE67C602D0179A56FULL,
		0xF7CE2D5010DD007DULL,
		0x347505471BED9CD5ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6636033C3AC78EDFULL,
		0x0B5803BDF6509F61ULL,
		0x31DB97A23212A435ULL,
		0x394DD6DCEBBAEA49ULL,
		0x45A6664E98B0410DULL,
		0x8D55AE592B7AD7F4ULL,
		0xAF6BDF43B98DCE7AULL,
		0x10D5C5EAEA59CD82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6C0678758F1DBEULL,
		0x16B0077BECA13EC2ULL,
		0x63B72F446425486AULL,
		0x729BADB9D775D492ULL,
		0x8B4CCC9D3160821AULL,
		0x1AAB5CB256F5AFE8ULL,
		0x5ED7BE87731B9CF5ULL,
		0x21AB8BD5D4B39B05ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x151CED070D8B2E92ULL,
		0x768F70039975ECFAULL,
		0x816B834E74AEDD4FULL,
		0xAC679F2C6BD21DF1ULL,
		0x456B6876BA5ABCD1ULL,
		0xDCBB8C7D35F1493BULL,
		0xB3013796F57E06A4ULL,
		0x16D44A6BBC26683BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A39DA0E1B165D24ULL,
		0xED1EE00732EBD9F4ULL,
		0x02D7069CE95DBA9EULL,
		0x58CF3E58D7A43BE3ULL,
		0x8AD6D0ED74B579A3ULL,
		0xB97718FA6BE29276ULL,
		0x66026F2DEAFC0D49ULL,
		0x2DA894D7784CD077ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D1C3E5992377915ULL,
		0xF64DFD953317CFE7ULL,
		0x44EF5DE2D4E414ECULL,
		0x89910AD80F182DDEULL,
		0xC78854566BCF6014ULL,
		0x4C42DA8F64B88061ULL,
		0x41873C87E5A02D82ULL,
		0x2EC5A0A20701B531ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A387CB3246EF22AULL,
		0xEC9BFB2A662F9FCFULL,
		0x89DEBBC5A9C829D9ULL,
		0x132215B01E305BBCULL,
		0x8F10A8ACD79EC029ULL,
		0x9885B51EC97100C3ULL,
		0x830E790FCB405B04ULL,
		0x5D8B41440E036A62ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B4B8C27C8CC0A17ULL,
		0x39009DE6ADE5F917ULL,
		0xA1F6CC2C8F9007D7ULL,
		0x8FC2C1E96D483A10ULL,
		0x1E3EE467A24FFCA2ULL,
		0x5312F2B63A11BB78ULL,
		0x3DD9A1A4E12FDD1BULL,
		0x2C3A5272B81AA6A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3697184F9198142EULL,
		0x72013BCD5BCBF22EULL,
		0x43ED98591F200FAEULL,
		0x1F8583D2DA907421ULL,
		0x3C7DC8CF449FF945ULL,
		0xA625E56C742376F0ULL,
		0x7BB34349C25FBA36ULL,
		0x5874A4E570354D42ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDCD07451EF4838EULL,
		0xA9EF2F3E5D78B157ULL,
		0x17D9B439726E0625ULL,
		0x38E401CFD819BDFEULL,
		0xA4599A748E4A802EULL,
		0xBF890E35531272C4ULL,
		0x2DD988F94035BBADULL,
		0x0E0D298201F9169AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB9A0E8A3DE9071CULL,
		0x53DE5E7CBAF162AFULL,
		0x2FB36872E4DC0C4BULL,
		0x71C8039FB0337BFCULL,
		0x48B334E91C95005CULL,
		0x7F121C6AA624E589ULL,
		0x5BB311F2806B775BULL,
		0x1C1A530403F22D34ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC6CBFB24F078BCBULL,
		0xBF2344449EA5C514ULL,
		0x61F2511F5DCF5270ULL,
		0xD3AA88A4737CE3ADULL,
		0xBE1FB373FA41DB60ULL,
		0xA2914E867D0F68FFULL,
		0x4DBAA82734175C7FULL,
		0x2A5F73CE311827DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D97F649E0F1796ULL,
		0x7E4688893D4B8A29ULL,
		0xC3E4A23EBB9EA4E1ULL,
		0xA7551148E6F9C75AULL,
		0x7C3F66E7F483B6C1ULL,
		0x45229D0CFA1ED1FFULL,
		0x9B75504E682EB8FFULL,
		0x54BEE79C62304FB6ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC272A3C837224F5FULL,
		0xE2186714D9555CBDULL,
		0xC61284740E6F7A9AULL,
		0xE5B5D223E0DAA9BAULL,
		0x8706A5053E9A9E35ULL,
		0xAF437C7D7A1EFE74ULL,
		0x3F320ADF3516402DULL,
		0x07C004A151E13A2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84E547906E449EBEULL,
		0xC430CE29B2AAB97BULL,
		0x8C2508E81CDEF535ULL,
		0xCB6BA447C1B55375ULL,
		0x0E0D4A0A7D353C6BULL,
		0x5E86F8FAF43DFCE9ULL,
		0x7E6415BE6A2C805BULL,
		0x0F800942A3C27454ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEF7C4C92AF1E0E6ULL,
		0xFD00BEA18BEB6F6DULL,
		0xB6C115F0011EA3B1ULL,
		0x9A7EC53CA572380DULL,
		0xCBBE9AACDEE91B1FULL,
		0x295A4B51718C00A1ULL,
		0x512E0F5C04FF3F2CULL,
		0x31438AF8982EB939ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DEF899255E3C1CCULL,
		0xFA017D4317D6DEDBULL,
		0x6D822BE0023D4763ULL,
		0x34FD8A794AE4701BULL,
		0x977D3559BDD2363FULL,
		0x52B496A2E3180143ULL,
		0xA25C1EB809FE7E58ULL,
		0x628715F1305D7272ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5699DC9BC9271587ULL,
		0x8D755309E0C76AA4ULL,
		0xADB091683097A2A8ULL,
		0x809A7A81DC6FF62AULL,
		0x584925D084908114ULL,
		0xA9609FD9273AB8B3ULL,
		0x5B3FDA6AB2C6175BULL,
		0x0B8246E46FEA2B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD33B937924E2B0EULL,
		0x1AEAA613C18ED548ULL,
		0x5B6122D0612F4551ULL,
		0x0134F503B8DFEC55ULL,
		0xB0924BA109210229ULL,
		0x52C13FB24E757166ULL,
		0xB67FB4D5658C2EB7ULL,
		0x17048DC8DFD4563CULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41F10499CABE6DF7ULL,
		0x7D193D0507441A99ULL,
		0x7B06F787DBF299F0ULL,
		0x9AB17298CA2348A4ULL,
		0x8C8D99663BFD4D61ULL,
		0x16B9600007C82871ULL,
		0x8AF2BA47C2F4D722ULL,
		0x22D0806871AAF686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E20933957CDBEEULL,
		0xFA327A0A0E883532ULL,
		0xF60DEF0FB7E533E0ULL,
		0x3562E53194469148ULL,
		0x191B32CC77FA9AC3ULL,
		0x2D72C0000F9050E3ULL,
		0x15E5748F85E9AE44ULL,
		0x45A100D0E355ED0DULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9408A7B124AD1BE2ULL,
		0x3260304CC4A529B1ULL,
		0xEB73071B20A1D079ULL,
		0xCCFD4712ED66F57CULL,
		0x816FE9630DF8EC07ULL,
		0xBB12CA2F79193BADULL,
		0x25BDCEB4CA61A91AULL,
		0x0BB16D91737E24F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28114F62495A37C4ULL,
		0x64C06099894A5363ULL,
		0xD6E60E364143A0F2ULL,
		0x99FA8E25DACDEAF9ULL,
		0x02DFD2C61BF1D80FULL,
		0x7625945EF232775BULL,
		0x4B7B9D6994C35235ULL,
		0x1762DB22E6FC49E4ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A503ED1240C5071ULL,
		0xB2E189E7A7F9AD06ULL,
		0x4F3A194AD729E6B7ULL,
		0x23C68E5F111BCE6EULL,
		0x6DF9195DAFA33F4AULL,
		0xF19F7B5D94AC9461ULL,
		0x5C82735632957DACULL,
		0x29ACF228CB76A30FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4A07DA24818A0E2ULL,
		0x65C313CF4FF35A0CULL,
		0x9E743295AE53CD6FULL,
		0x478D1CBE22379CDCULL,
		0xDBF232BB5F467E94ULL,
		0xE33EF6BB295928C2ULL,
		0xB904E6AC652AFB59ULL,
		0x5359E45196ED461EULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5B733D79F799719ULL,
		0xFB1C9FCF16F06E6AULL,
		0x84F3F8B9A1FCAB79ULL,
		0x3F0C7E6CDC344742ULL,
		0x3564F2BFA4B23CF7ULL,
		0x5C7DFBF5A1951836ULL,
		0xAA41AE0C200296FAULL,
		0x2F40AFDECA7FCB30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6E67AF3EF32E32ULL,
		0xF6393F9E2DE0DCD5ULL,
		0x09E7F17343F956F3ULL,
		0x7E18FCD9B8688E85ULL,
		0x6AC9E57F496479EEULL,
		0xB8FBF7EB432A306CULL,
		0x54835C1840052DF4ULL,
		0x5E815FBD94FF9661ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x231E4654E86E287EULL,
		0x13EDC1672B807FEFULL,
		0xDC1927F8BE841D3DULL,
		0x43322BAC0D7B85F4ULL,
		0xB49EDC20173FF0B6ULL,
		0x1F8B8A6B3D99ED06ULL,
		0x4A530AED6EB102DFULL,
		0x215460A269908031ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x463C8CA9D0DC50FCULL,
		0x27DB82CE5700FFDEULL,
		0xB8324FF17D083A7AULL,
		0x866457581AF70BE9ULL,
		0x693DB8402E7FE16CULL,
		0x3F1714D67B33DA0DULL,
		0x94A615DADD6205BEULL,
		0x42A8C144D3210062ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5775C15555AF8E2EULL,
		0xF052E5CC2BD37D53ULL,
		0xE530C45956DF1BCEULL,
		0x7F0E7A27C3C519B3ULL,
		0xC2011A6DC9ECE2BDULL,
		0x57C1AA7AEA4C6109ULL,
		0x2CE3EF03B3012EAAULL,
		0x12ECF1DE12F67A2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEEB82AAAB5F1C5CULL,
		0xE0A5CB9857A6FAA6ULL,
		0xCA6188B2ADBE379DULL,
		0xFE1CF44F878A3367ULL,
		0x840234DB93D9C57AULL,
		0xAF8354F5D498C213ULL,
		0x59C7DE0766025D54ULL,
		0x25D9E3BC25ECF45CULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF655EDD8BCA83FFAULL,
		0x91B950BC652F52B7ULL,
		0xD5CBC45331D111C8ULL,
		0x2407A63DE6DF17CEULL,
		0xCA167E3EAEB84BFAULL,
		0xCE7A068DB31A6813ULL,
		0xEE726A61057ABBFCULL,
		0x1266EEBA3A233907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECABDBB179507FF4ULL,
		0x2372A178CA5EA56FULL,
		0xAB9788A663A22391ULL,
		0x480F4C7BCDBE2F9DULL,
		0x942CFC7D5D7097F4ULL,
		0x9CF40D1B6634D027ULL,
		0xDCE4D4C20AF577F9ULL,
		0x24CDDD747446720FULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FB27EDA5E986486ULL,
		0x3C4478CF60E27DB4ULL,
		0x0BA742B813A4F3BFULL,
		0xDAFF57DC2CEBDF0DULL,
		0xF31AA30AEE7ACAE0ULL,
		0xE5E8109750462D21ULL,
		0xB15B94D8A1643E73ULL,
		0x0F8E763F7C88AADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F64FDB4BD30C90CULL,
		0x7888F19EC1C4FB68ULL,
		0x174E85702749E77EULL,
		0xB5FEAFB859D7BE1AULL,
		0xE6354615DCF595C1ULL,
		0xCBD0212EA08C5A43ULL,
		0x62B729B142C87CE7ULL,
		0x1F1CEC7EF91155B7ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A25388B3F72337CULL,
		0x74A1AD6B5D2A4DE1ULL,
		0xDFA3FDF1F08431F1ULL,
		0x0D02BB7D5951A45FULL,
		0x9962C6260D86D0F9ULL,
		0x39387843DFBFA2D6ULL,
		0x291FB21339AF8A18ULL,
		0x1353183CD83772A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144A71167EE466F8ULL,
		0xE9435AD6BA549BC3ULL,
		0xBF47FBE3E10863E2ULL,
		0x1A0576FAB2A348BFULL,
		0x32C58C4C1B0DA1F2ULL,
		0x7270F087BF7F45ADULL,
		0x523F6426735F1430ULL,
		0x26A63079B06EE546ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E76152513004248ULL,
		0x809265D3BE1812A8ULL,
		0xEAA017E13BFFCC8FULL,
		0xF72EE9E83C02DE6CULL,
		0xA24BE25FCB5A3D3EULL,
		0xE2424DCFDD8C5FB0ULL,
		0x90B7F0C0BA18BDA2ULL,
		0x2974413486160436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CEC2A4A26008490ULL,
		0x0124CBA77C302550ULL,
		0xD5402FC277FF991FULL,
		0xEE5DD3D07805BCD9ULL,
		0x4497C4BF96B47A7DULL,
		0xC4849B9FBB18BF61ULL,
		0x216FE18174317B45ULL,
		0x52E882690C2C086DULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE75618F39F10117FULL,
		0xD2DE7FBDA96D08C6ULL,
		0xCD6C64B9204FD913ULL,
		0x8D9700A95A92927CULL,
		0x87E28A0B53A2E7C7ULL,
		0xD1E2BE435471BCD2ULL,
		0x03AB82BE9B709644ULL,
		0x39AA3598D3D53DE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEAC31E73E2022FEULL,
		0xA5BCFF7B52DA118DULL,
		0x9AD8C972409FB227ULL,
		0x1B2E0152B52524F9ULL,
		0x0FC51416A745CF8FULL,
		0xA3C57C86A8E379A5ULL,
		0x0757057D36E12C89ULL,
		0x73546B31A7AA7BCCULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC4C3C0E09863036ULL,
		0xAD3CAF2BBDCA2142ULL,
		0x9A9A7DD4F88AE6DCULL,
		0x9530F2C34DC7D21BULL,
		0xAE61E1F89984546FULL,
		0x9B2193C5621FDD8EULL,
		0x43AFBAF95BECE750ULL,
		0x241246406E8CB754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9898781C130C606CULL,
		0x5A795E577B944285ULL,
		0x3534FBA9F115CDB9ULL,
		0x2A61E5869B8FA437ULL,
		0x5CC3C3F13308A8DFULL,
		0x3643278AC43FBB1DULL,
		0x875F75F2B7D9CEA1ULL,
		0x48248C80DD196EA8ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FCD42A11733A413ULL,
		0x84E4C62A5866F14EULL,
		0xBCFDBE1CAEB632AEULL,
		0xE49832C33BD3E67EULL,
		0x3794C5E4F6DDDB75ULL,
		0x74231FE996EB6389ULL,
		0x7D5E02EDA1DC4732ULL,
		0x36BA6244576D01B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF9A85422E674826ULL,
		0x09C98C54B0CDE29CULL,
		0x79FB7C395D6C655DULL,
		0xC930658677A7CCFDULL,
		0x6F298BC9EDBBB6EBULL,
		0xE8463FD32DD6C712ULL,
		0xFABC05DB43B88E64ULL,
		0x6D74C488AEDA036EULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62B1DC5CCB6C3517ULL,
		0x8A3074954483098BULL,
		0x19A259B543C3F2FAULL,
		0x5AF0B0F9B2A1C0CDULL,
		0xEC8E087566997A60ULL,
		0x4D3B3D249DEE6CEDULL,
		0xA07F1012345736BCULL,
		0x234669D3F39AE1C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC563B8B996D86A2EULL,
		0x1460E92A89061316ULL,
		0x3344B36A8787E5F5ULL,
		0xB5E161F36543819AULL,
		0xD91C10EACD32F4C0ULL,
		0x9A767A493BDCD9DBULL,
		0x40FE202468AE6D78ULL,
		0x468CD3A7E735C393ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF4C2C0E41C64B73ULL,
		0x5AC143F1C9E90B2BULL,
		0xFF83810BB077DE97ULL,
		0xD93F969666105BC3ULL,
		0x511735AA8F967667ULL,
		0x2013197CCA5C871EULL,
		0xF498E1A47F772523ULL,
		0x39B75907DB29EF1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E98581C838C96E6ULL,
		0xB58287E393D21657ULL,
		0xFF07021760EFBD2EULL,
		0xB27F2D2CCC20B787ULL,
		0xA22E6B551F2CECCFULL,
		0x402632F994B90E3CULL,
		0xE931C348FEEE4A46ULL,
		0x736EB20FB653DE3DULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8295B51C4B18670ULL,
		0x92D372E5A3B0B445ULL,
		0x581C8F7A6D2863F1ULL,
		0xB0513213FE7E7385ULL,
		0x6F70F9CBDCCE8A19ULL,
		0x883DE75D30B33EEEULL,
		0x93F60987FD8A03B7ULL,
		0x10E468E19CF62B7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF052B6A389630CE0ULL,
		0x25A6E5CB4761688BULL,
		0xB0391EF4DA50C7E3ULL,
		0x60A26427FCFCE70AULL,
		0xDEE1F397B99D1433ULL,
		0x107BCEBA61667DDCULL,
		0x27EC130FFB14076FULL,
		0x21C8D1C339EC56F9ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEEC5BBD752E0B4BULL,
		0x0237D0F1D286ECBEULL,
		0x0D7957C34A8EC45FULL,
		0x6257D6B111BCE9BBULL,
		0x5272BA2DC0B96C1CULL,
		0xEAF46FF8ACE9459EULL,
		0x62C9838DD63EA8EFULL,
		0x2A2DB3152DE95E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDD8B77AEA5C1696ULL,
		0x046FA1E3A50DD97DULL,
		0x1AF2AF86951D88BEULL,
		0xC4AFAD622379D376ULL,
		0xA4E5745B8172D838ULL,
		0xD5E8DFF159D28B3CULL,
		0xC593071BAC7D51DFULL,
		0x545B662A5BD2BC08ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDED9E93F2358A56ULL,
		0x1099D588341E1D27ULL,
		0xEF9FCF743C5FE580ULL,
		0xB5A2EF289943D1DBULL,
		0x0A82420928BA59C5ULL,
		0xE8EE550D40DF0C46ULL,
		0x09511B3D6A9BA94DULL,
		0x10A37A4C0C23A685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BDB3D27E46B14ACULL,
		0x2133AB10683C3A4FULL,
		0xDF3F9EE878BFCB00ULL,
		0x6B45DE513287A3B7ULL,
		0x150484125174B38BULL,
		0xD1DCAA1A81BE188CULL,
		0x12A2367AD537529BULL,
		0x2146F49818474D0AULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42F7993112C9C9FCULL,
		0x8D272EA980246A15ULL,
		0x517613BF84EFC5FBULL,
		0xF0E023334194BF96ULL,
		0x87B674CB42A27D79ULL,
		0x3C3F62A84AFD32CAULL,
		0xF98AC1A7C88439C7ULL,
		0x26F9304AA6E66479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85EF3262259393F8ULL,
		0x1A4E5D530048D42AULL,
		0xA2EC277F09DF8BF7ULL,
		0xE1C0466683297F2CULL,
		0x0F6CE9968544FAF3ULL,
		0x787EC55095FA6595ULL,
		0xF315834F9108738EULL,
		0x4DF260954DCCC8F3ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A020EC825727490ULL,
		0xD4C2CD67F1A0615FULL,
		0xBB2D75502B0A4F7BULL,
		0x1F62E862EB73EA23ULL,
		0xF9B3C5A3D20FF32DULL,
		0x7C3F60924D84656BULL,
		0x7F95858371C9067AULL,
		0x1A3E344E35D9D737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94041D904AE4E920ULL,
		0xA9859ACFE340C2BEULL,
		0x765AEAA056149EF7ULL,
		0x3EC5D0C5D6E7D447ULL,
		0xF3678B47A41FE65AULL,
		0xF87EC1249B08CAD7ULL,
		0xFF2B0B06E3920CF4ULL,
		0x347C689C6BB3AE6EULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD37E1BD2B5AEC320ULL,
		0xDA3AC64D7BB1AB24ULL,
		0x997331383EE14C8EULL,
		0x44773151F5E0FE6DULL,
		0x6C48D7A1BC0DF518ULL,
		0x9382E0BA53C65F99ULL,
		0xC462DFDF2A7B4B5FULL,
		0x00A0049237AA270AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FC37A56B5D8640ULL,
		0xB4758C9AF7635649ULL,
		0x32E662707DC2991DULL,
		0x88EE62A3EBC1FCDBULL,
		0xD891AF43781BEA30ULL,
		0x2705C174A78CBF32ULL,
		0x88C5BFBE54F696BFULL,
		0x014009246F544E15ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EAD458662357599ULL,
		0x7065EF2850AB89B1ULL,
		0x944CC2870AB1AC14ULL,
		0x5FFBABBBD4129EBDULL,
		0xD339B930C85E1ED7ULL,
		0xE74399067778342BULL,
		0xC7F7E1A123C375C2ULL,
		0x3E895C8E82ECFF16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D5A8B0CC46AEB32ULL,
		0xE0CBDE50A1571362ULL,
		0x2899850E15635828ULL,
		0xBFF75777A8253D7BULL,
		0xA673726190BC3DAEULL,
		0xCE87320CEEF06857ULL,
		0x8FEFC3424786EB85ULL,
		0x7D12B91D05D9FE2DULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CFC2527AF2770FAULL,
		0x5941DEC78C9D3F1EULL,
		0xB782874948D1D0D4ULL,
		0xAF3CD9A90F233178ULL,
		0x7024167B989CE96CULL,
		0xEDE2EF515B18CE04ULL,
		0x4E1A59FD87991B26ULL,
		0x03445C8A6DB0984BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F84A4F5E4EE1F4ULL,
		0xB283BD8F193A7E3CULL,
		0x6F050E9291A3A1A8ULL,
		0x5E79B3521E4662F1ULL,
		0xE0482CF73139D2D9ULL,
		0xDBC5DEA2B6319C08ULL,
		0x9C34B3FB0F32364DULL,
		0x0688B914DB613096ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x370BF162A4E69525ULL,
		0xDF26053F2ADCF961ULL,
		0x9C5B9DD84CB8A0C0ULL,
		0x460B16FD238E3B1DULL,
		0x7BDC71D6F5A64637ULL,
		0xAAD906846B192A2BULL,
		0x1A24719BC4BD1F47ULL,
		0x2552AEC6A371F97CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E17E2C549CD2A4AULL,
		0xBE4C0A7E55B9F2C2ULL,
		0x38B73BB099714181ULL,
		0x8C162DFA471C763BULL,
		0xF7B8E3ADEB4C8C6EULL,
		0x55B20D08D6325456ULL,
		0x3448E337897A3E8FULL,
		0x4AA55D8D46E3F2F8ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D3611BAD0DC2519ULL,
		0x5FC6CD879533A8C5ULL,
		0x671BED3D31C34190ULL,
		0xDE38E547DED8ABEDULL,
		0xD8B74A875073874AULL,
		0xE25779CDDA0B57BEULL,
		0x54631C9B12D704DDULL,
		0x1510FDEFBBE844B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A6C2375A1B84A32ULL,
		0xBF8D9B0F2A67518BULL,
		0xCE37DA7A63868320ULL,
		0xBC71CA8FBDB157DAULL,
		0xB16E950EA0E70E95ULL,
		0xC4AEF39BB416AF7DULL,
		0xA8C6393625AE09BBULL,
		0x2A21FBDF77D08970ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD53C0A06A39CB112ULL,
		0x5AEC73DF7AFE547EULL,
		0x4A5ED8A81057585EULL,
		0x28911AC58A10880CULL,
		0xD560E64875CCA68CULL,
		0xFD80392D7E3059DCULL,
		0xB47B087EC9413193ULL,
		0x318AE41FAED4F559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA78140D47396224ULL,
		0xB5D8E7BEF5FCA8FDULL,
		0x94BDB15020AEB0BCULL,
		0x5122358B14211018ULL,
		0xAAC1CC90EB994D18ULL,
		0xFB00725AFC60B3B9ULL,
		0x68F610FD92826327ULL,
		0x6315C83F5DA9EAB3ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x849F5A243D831E02ULL,
		0x0E545EDF204FE388ULL,
		0x32CD59152E8C7B32ULL,
		0xA31DC5843AD619D8ULL,
		0x0AC22647D9E3F547ULL,
		0x0B156D985FE5FF84ULL,
		0x73615FA7607729E1ULL,
		0x22BF3C7BCED1979DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x093EB4487B063C04ULL,
		0x1CA8BDBE409FC711ULL,
		0x659AB22A5D18F664ULL,
		0x463B8B0875AC33B0ULL,
		0x15844C8FB3C7EA8FULL,
		0x162ADB30BFCBFF08ULL,
		0xE6C2BF4EC0EE53C2ULL,
		0x457E78F79DA32F3AULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B28D63D955139E4ULL,
		0x0217D370F2B779C3ULL,
		0xB465B75EF7521646ULL,
		0xAF7B31B270F326F8ULL,
		0xB5E2C0E5020C72EFULL,
		0x519B4758B50AEC29ULL,
		0xE07DA31F283E1A91ULL,
		0x378722CBC06FAB0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3651AC7B2AA273C8ULL,
		0x042FA6E1E56EF386ULL,
		0x68CB6EBDEEA42C8CULL,
		0x5EF66364E1E64DF1ULL,
		0x6BC581CA0418E5DFULL,
		0xA3368EB16A15D853ULL,
		0xC0FB463E507C3522ULL,
		0x6F0E459780DF561FULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58B924D2D137EDC9ULL,
		0x968BB901B587E364ULL,
		0x262916DCC924DCC6ULL,
		0x7F76DBC3F429D44EULL,
		0xCBC44DF63B979414ULL,
		0xD36630C9DA57AA9FULL,
		0x6B3BA975F20F0871ULL,
		0x09A4232A6F0214DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17249A5A26FDB92ULL,
		0x2D1772036B0FC6C8ULL,
		0x4C522DB99249B98DULL,
		0xFEEDB787E853A89CULL,
		0x97889BEC772F2828ULL,
		0xA6CC6193B4AF553FULL,
		0xD67752EBE41E10E3ULL,
		0x13484654DE0429BAULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC34B01E426B24E09ULL,
		0xB470786E937A6D0EULL,
		0x0273F58776ECB58BULL,
		0x7AE0D00ADEBE5002ULL,
		0x4EB3D7B34440F42EULL,
		0x8D48F62AEAF7E3DFULL,
		0x6230EC4CBA82B996ULL,
		0x3125C043B8BDCEA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869603C84D649C12ULL,
		0x68E0F0DD26F4DA1DULL,
		0x04E7EB0EEDD96B17ULL,
		0xF5C1A015BD7CA004ULL,
		0x9D67AF668881E85CULL,
		0x1A91EC55D5EFC7BEULL,
		0xC461D8997505732DULL,
		0x624B8087717B9D4CULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x594C83610CD4FA1EULL,
		0xCF3EA89EBB6DE5CDULL,
		0x2582B0EC23010565ULL,
		0x424148F5CBCA0F09ULL,
		0xA2F3E37D6CF4C8BAULL,
		0x7ECC428415DE4CD5ULL,
		0x8D6F263C24C48CC5ULL,
		0x39D153924D054D72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29906C219A9F43CULL,
		0x9E7D513D76DBCB9AULL,
		0x4B0561D846020ACBULL,
		0x848291EB97941E12ULL,
		0x45E7C6FAD9E99174ULL,
		0xFD9885082BBC99ABULL,
		0x1ADE4C784989198AULL,
		0x73A2A7249A0A9AE5ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB700942DC4EA1B6CULL,
		0xD5D3FA9D3B53367FULL,
		0x31667EBB4B62FEF3ULL,
		0xB983BC14D91710B1ULL,
		0xCFF25794A3B129E9ULL,
		0xB7EB3F2C3C09642BULL,
		0x2B1879AE80DA6DFDULL,
		0x3089926BF30890C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E01285B89D436D8ULL,
		0xABA7F53A76A66CFFULL,
		0x62CCFD7696C5FDE7ULL,
		0x73077829B22E2162ULL,
		0x9FE4AF29476253D3ULL,
		0x6FD67E587812C857ULL,
		0x5630F35D01B4DBFBULL,
		0x611324D7E6112192ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26500508920FA3ACULL,
		0x210955EFC045FD4BULL,
		0x71319015393635EDULL,
		0x63FB588D55D0A1CAULL,
		0x9BBBB47A620895F3ULL,
		0x13958E88A01E1603ULL,
		0x1F71E191718EE6B6ULL,
		0x1CBA4093204F0253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CA00A11241F4758ULL,
		0x4212ABDF808BFA96ULL,
		0xE263202A726C6BDAULL,
		0xC7F6B11AABA14394ULL,
		0x377768F4C4112BE6ULL,
		0x272B1D11403C2C07ULL,
		0x3EE3C322E31DCD6CULL,
		0x39748126409E04A6ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2F258823FA02817ULL,
		0x9479B3428DA231A2ULL,
		0x4BDBDAA95D5D4D77ULL,
		0xFB81BD019C878A3AULL,
		0xFFF19DB42A258DAFULL,
		0xD72C54CDA61FA984ULL,
		0xFADDD067DC9EFA48ULL,
		0x1AF1DB88D66F84FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E4B1047F40502EULL,
		0x28F366851B446345ULL,
		0x97B7B552BABA9AEFULL,
		0xF7037A03390F1474ULL,
		0xFFE33B68544B1B5FULL,
		0xAE58A99B4C3F5309ULL,
		0xF5BBA0CFB93DF491ULL,
		0x35E3B711ACDF09FDULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x805D891272A9C61EULL,
		0xB7F9362383961801ULL,
		0x69AB165E074C72B0ULL,
		0x96595A7E50A04BD9ULL,
		0x04F1F12907A842F6ULL,
		0xE20D5F486FD6FE92ULL,
		0x1D0BFE5867728021ULL,
		0x3C23590BFD6C7BCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00BB1224E5538C3CULL,
		0x6FF26C47072C3003ULL,
		0xD3562CBC0E98E561ULL,
		0x2CB2B4FCA14097B2ULL,
		0x09E3E2520F5085EDULL,
		0xC41ABE90DFADFD24ULL,
		0x3A17FCB0CEE50043ULL,
		0x7846B217FAD8F796ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30EDDAC562C3632AULL,
		0x2B1AA593F5BAFB42ULL,
		0x4D6BADF81B09C5D7ULL,
		0x439D30A7A7CC402CULL,
		0xFCA79707D7D4211BULL,
		0x6889C2DF50EB13EEULL,
		0x694CB6615156B44FULL,
		0x2EA9DDC4D2DC1F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61DBB58AC586C654ULL,
		0x56354B27EB75F684ULL,
		0x9AD75BF036138BAEULL,
		0x873A614F4F988058ULL,
		0xF94F2E0FAFA84236ULL,
		0xD11385BEA1D627DDULL,
		0xD2996CC2A2AD689EULL,
		0x5D53BB89A5B83F26ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07FB866EA0FC3180ULL,
		0x3E0D5D39E84F3DEAULL,
		0x996913A577FECC56ULL,
		0x2558C7BF2477B0E4ULL,
		0x31F85277170F0941ULL,
		0x4312747277B3D855ULL,
		0xA4AE724033FEB58DULL,
		0x1427F3D20C6B8C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF70CDD41F86300ULL,
		0x7C1ABA73D09E7BD4ULL,
		0x32D2274AEFFD98ACULL,
		0x4AB18F7E48EF61C9ULL,
		0x63F0A4EE2E1E1282ULL,
		0x8624E8E4EF67B0AAULL,
		0x495CE48067FD6B1AULL,
		0x284FE7A418D71923ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59B27640F4430498ULL,
		0x6D235E6649997BB8ULL,
		0x84F9AE00FF614F58ULL,
		0xEEE717455156CAFBULL,
		0xC33A3DD1FB7EE0F0ULL,
		0x1390113A30674A25ULL,
		0xB977C8E035940A0FULL,
		0x3B9008B55AE41FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB364EC81E8860930ULL,
		0xDA46BCCC9332F770ULL,
		0x09F35C01FEC29EB0ULL,
		0xDDCE2E8AA2AD95F7ULL,
		0x86747BA3F6FDC1E1ULL,
		0x2720227460CE944BULL,
		0x72EF91C06B28141EULL,
		0x7720116AB5C83FB7ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3838A6ED474FEF1FULL,
		0xEF8B2983E872DC37ULL,
		0x58A8177BFE528028ULL,
		0x3BAF1F13E2E71315ULL,
		0x926748756F4F0649ULL,
		0x967506F7DA1F2B87ULL,
		0x6F4F5B9D0B244438ULL,
		0x0CA2688B7757D085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70714DDA8E9FDE3EULL,
		0xDF165307D0E5B86EULL,
		0xB1502EF7FCA50051ULL,
		0x775E3E27C5CE262AULL,
		0x24CE90EADE9E0C92ULL,
		0x2CEA0DEFB43E570FULL,
		0xDE9EB73A16488871ULL,
		0x1944D116EEAFA10AULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47402636862D6E73ULL,
		0xF6CEB2C0D208A286ULL,
		0x3DE324E6E6D3F697ULL,
		0x39C49675C1A1F216ULL,
		0x2696F72C8C230555ULL,
		0x14745DA4743B03F1ULL,
		0x426E1ABD9AD7A518ULL,
		0x20CDEE8A323A9232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E804C6D0C5ADCE6ULL,
		0xED9D6581A411450CULL,
		0x7BC649CDCDA7ED2FULL,
		0x73892CEB8343E42CULL,
		0x4D2DEE5918460AAAULL,
		0x28E8BB48E87607E2ULL,
		0x84DC357B35AF4A30ULL,
		0x419BDD1464752464ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDB041CCA83B42F7ULL,
		0x34F5C437A4BB76FBULL,
		0x2EC87B3292CD9093ULL,
		0x34C1A3142623C794ULL,
		0xF332E194D5CCC849ULL,
		0xA11693723D4488A7ULL,
		0x475619B7B048BFC8ULL,
		0x2C2C2E2840B70942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB608399507685EEULL,
		0x69EB886F4976EDF7ULL,
		0x5D90F665259B2126ULL,
		0x698346284C478F28ULL,
		0xE665C329AB999092ULL,
		0x422D26E47A89114FULL,
		0x8EAC336F60917F91ULL,
		0x58585C50816E1284ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2396EDB5A58748BULL,
		0x7D77425A20F17C02ULL,
		0xD01F4934EB0ECE76ULL,
		0xCAE46EB31525BC6BULL,
		0x1ACD3452D2C10726ULL,
		0x5FD96817A160DD29ULL,
		0xBD6DD2594B76D0FBULL,
		0x26570A8801B4175DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA472DDB6B4B0E916ULL,
		0xFAEE84B441E2F805ULL,
		0xA03E9269D61D9CECULL,
		0x95C8DD662A4B78D7ULL,
		0x359A68A5A5820E4DULL,
		0xBFB2D02F42C1BA52ULL,
		0x7ADBA4B296EDA1F6ULL,
		0x4CAE151003682EBBULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42E71E8F0358320BULL,
		0x8C3F2FC149BABE40ULL,
		0xF7432F7B2953952AULL,
		0xE2998804A774C469ULL,
		0x1B28962EF24FF0FFULL,
		0x7148F55E3A95D107ULL,
		0x44BB383319F99E37ULL,
		0x276848FAB08C99A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85CE3D1E06B06416ULL,
		0x187E5F8293757C80ULL,
		0xEE865EF652A72A55ULL,
		0xC53310094EE988D3ULL,
		0x36512C5DE49FE1FFULL,
		0xE291EABC752BA20EULL,
		0x8976706633F33C6EULL,
		0x4ED091F56119334EULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B149FD600DD454CULL,
		0x9F5A8974DB6B3418ULL,
		0x941F87028EA57229ULL,
		0x3748F6574AFCD734ULL,
		0xD44ABB8F9F421EC1ULL,
		0xDC4E225439309333ULL,
		0x5300B5C88F9382CEULL,
		0x2E39817B2CBD7A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6293FAC01BA8A98ULL,
		0x3EB512E9B6D66830ULL,
		0x283F0E051D4AE453ULL,
		0x6E91ECAE95F9AE69ULL,
		0xA895771F3E843D82ULL,
		0xB89C44A872612667ULL,
		0xA6016B911F27059DULL,
		0x5C7302F6597AF470ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B32CD1F5F822964ULL,
		0x02B297B2FEA7C227ULL,
		0x2AC5058612FB8A46ULL,
		0xDEB663EB6B871F0BULL,
		0xB31D8D38E836DAFEULL,
		0xFE3C75BDF9640C30ULL,
		0x845B533DF96E2B47ULL,
		0x368ED6963BC0FCCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56659A3EBF0452C8ULL,
		0x05652F65FD4F844EULL,
		0x558A0B0C25F7148CULL,
		0xBD6CC7D6D70E3E16ULL,
		0x663B1A71D06DB5FDULL,
		0xFC78EB7BF2C81861ULL,
		0x08B6A67BF2DC568FULL,
		0x6D1DAD2C7781F999ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x503592C0BC64F318ULL,
		0x04A21DE9936208E0ULL,
		0x21354ED3374524ECULL,
		0x4C23DA09D4E8B504ULL,
		0xC82F23D56F0C96F5ULL,
		0xD449948F2462E525ULL,
		0x1EF9B690F9E9FAE5ULL,
		0x05618E4EC9FDD56EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA06B258178C9E630ULL,
		0x09443BD326C411C0ULL,
		0x426A9DA66E8A49D8ULL,
		0x9847B413A9D16A08ULL,
		0x905E47AADE192DEAULL,
		0xA893291E48C5CA4BULL,
		0x3DF36D21F3D3F5CBULL,
		0x0AC31C9D93FBAADCULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ED8F07B2589DE58ULL,
		0x2EA8A2AEEC690C52ULL,
		0x52D51E34C6907C19ULL,
		0x1561CE8E29BE9FB3ULL,
		0x837DC4F9302FBEB4ULL,
		0x586D4DB6B524208CULL,
		0x6F5E236F755AA74CULL,
		0x074687A28E3AEB52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB1E0F64B13BCB0ULL,
		0x5D51455DD8D218A4ULL,
		0xA5AA3C698D20F832ULL,
		0x2AC39D1C537D3F66ULL,
		0x06FB89F2605F7D68ULL,
		0xB0DA9B6D6A484119ULL,
		0xDEBC46DEEAB54E98ULL,
		0x0E8D0F451C75D6A4ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36BFF73322BEB62AULL,
		0xFDD46A62B4560E49ULL,
		0xBA72C593FF859693ULL,
		0x458D93C6DC47D013ULL,
		0xA97BF4D0F8084EABULL,
		0xC7919D72048B4DCCULL,
		0xB272F201134EBAF8ULL,
		0x0AAA44723065C947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D7FEE66457D6C54ULL,
		0xFBA8D4C568AC1C92ULL,
		0x74E58B27FF0B2D27ULL,
		0x8B1B278DB88FA027ULL,
		0x52F7E9A1F0109D56ULL,
		0x8F233AE409169B99ULL,
		0x64E5E402269D75F1ULL,
		0x155488E460CB928FULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99BF155494C73DF4ULL,
		0x9A7DD45AC3733B36ULL,
		0xE42E3059911FEBA6ULL,
		0x34CCD4EDE111B401ULL,
		0xC4879B30A615D197ULL,
		0x7C855CAF82BD1028ULL,
		0xD1318F328433222FULL,
		0x1CE7A4A161495502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x337E2AA9298E7BE8ULL,
		0x34FBA8B586E6766DULL,
		0xC85C60B3223FD74DULL,
		0x6999A9DBC2236803ULL,
		0x890F36614C2BA32EULL,
		0xF90AB95F057A2051ULL,
		0xA2631E650866445EULL,
		0x39CF4942C292AA05ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB68330D2BF67FBDULL,
		0x29CB0C21BA301384ULL,
		0xFDF05A75AD33AEC3ULL,
		0x71A61A62E7F7A307ULL,
		0x93383D3F6B54AD4EULL,
		0x53707C7E010D9C97ULL,
		0x35C03FA431DF7073ULL,
		0x2AB7DCC33D9FD0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D0661A57ECFF7AULL,
		0x5396184374602709ULL,
		0xFBE0B4EB5A675D86ULL,
		0xE34C34C5CFEF460FULL,
		0x26707A7ED6A95A9CULL,
		0xA6E0F8FC021B392FULL,
		0x6B807F4863BEE0E6ULL,
		0x556FB9867B3FA1FEULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FB707D184E23A8DULL,
		0xD07E7C5FA5102BCFULL,
		0x9ECB4D3789F7019DULL,
		0xE165D17753CC6C4EULL,
		0x5D47F9254563D997ULL,
		0x7E3EF6513D66AF3FULL,
		0x2C255042E25E625EULL,
		0x32EA83ADF4308332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6E0FA309C4751AULL,
		0xA0FCF8BF4A20579FULL,
		0x3D969A6F13EE033BULL,
		0xC2CBA2EEA798D89DULL,
		0xBA8FF24A8AC7B32FULL,
		0xFC7DECA27ACD5E7EULL,
		0x584AA085C4BCC4BCULL,
		0x65D5075BE8610664ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87BDA80FF11E9D05ULL,
		0xC1CA65BBBD89E346ULL,
		0xF62555DB30BCCC52ULL,
		0xD74786B05CDBDBE3ULL,
		0xD8EF674C4F11D8BAULL,
		0x730451450E5EB65BULL,
		0x3F4F0F9026F4B3B6ULL,
		0x3F86D282EE294C48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F7B501FE23D3A0AULL,
		0x8394CB777B13C68DULL,
		0xEC4AABB6617998A5ULL,
		0xAE8F0D60B9B7B7C7ULL,
		0xB1DECE989E23B175ULL,
		0xE608A28A1CBD6CB7ULL,
		0x7E9E1F204DE9676CULL,
		0x7F0DA505DC529890ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16D85D083EB4E221ULL,
		0xD1C1EE7004CBC271ULL,
		0x220121D962C91FB6ULL,
		0x55E8BFEC16C275B3ULL,
		0x2668B734092A4F30ULL,
		0x9CC6EF3FE36773DDULL,
		0xD5312F1B615C1CB4ULL,
		0x3245466D5791F40BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB0BA107D69C442ULL,
		0xA383DCE0099784E2ULL,
		0x440243B2C5923F6DULL,
		0xABD17FD82D84EB66ULL,
		0x4CD16E6812549E60ULL,
		0x398DDE7FC6CEE7BAULL,
		0xAA625E36C2B83969ULL,
		0x648A8CDAAF23E817ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA22C679E253F93DULL,
		0x00D6960835E97917ULL,
		0x43DE435956D430AFULL,
		0xB8677E320ADD49E8ULL,
		0x361800352789EB4BULL,
		0x8EF8705582416C28ULL,
		0x76A09ABDDD98872EULL,
		0x36688EDA5028AA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4458CF3C4A7F27AULL,
		0x01AD2C106BD2F22FULL,
		0x87BC86B2ADA8615EULL,
		0x70CEFC6415BA93D0ULL,
		0x6C30006A4F13D697ULL,
		0x1DF0E0AB0482D850ULL,
		0xED41357BBB310E5DULL,
		0x6CD11DB4A051544EULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9773FBC71A1056AULL,
		0x684E973E42DA1539ULL,
		0x5E5A6ACE1C89407CULL,
		0x834082E5811992C6ULL,
		0x5215A6311715218EULL,
		0x863102D58DA33B65ULL,
		0x913240934B0F85A6ULL,
		0x32D7EA839E39E881ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92EE7F78E3420AD4ULL,
		0xD09D2E7C85B42A73ULL,
		0xBCB4D59C391280F8ULL,
		0x068105CB0233258CULL,
		0xA42B4C622E2A431DULL,
		0x0C6205AB1B4676CAULL,
		0x22648126961F0B4DULL,
		0x65AFD5073C73D103ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC1B6FA6C1E6DCD1ULL,
		0xCD0DD2692F1E6A75ULL,
		0x4C2864DE39272E5BULL,
		0xE093BB410AEFB1AEULL,
		0xA0EDDA0274A83B01ULL,
		0xA9EBDA15549F12CFULL,
		0x6456CE12A5416EA7ULL,
		0x18880540E1F9DD2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF836DF4D83CDB9A2ULL,
		0x9A1BA4D25E3CD4EBULL,
		0x9850C9BC724E5CB7ULL,
		0xC127768215DF635CULL,
		0x41DBB404E9507603ULL,
		0x53D7B42AA93E259FULL,
		0xC8AD9C254A82DD4FULL,
		0x31100A81C3F3BA56ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC3B202EC016B6BAULL,
		0x45A8D33CCCCE6B59ULL,
		0xC45CF375BEF4DF02ULL,
		0x92FECAF44A566F7BULL,
		0x611292C1F1BA06D1ULL,
		0xB4C260697831D4B5ULL,
		0xC1057C65D90D871AULL,
		0x2FB98035FA004F44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB876405D802D6D74ULL,
		0x8B51A679999CD6B3ULL,
		0x88B9E6EB7DE9BE04ULL,
		0x25FD95E894ACDEF7ULL,
		0xC2252583E3740DA3ULL,
		0x6984C0D2F063A96AULL,
		0x820AF8CBB21B0E35ULL,
		0x5F73006BF4009E89ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D1E67847ECC4621ULL,
		0x552A9251A188D212ULL,
		0xF570E1EE3C5FF575ULL,
		0xF6D5DBD4EBEF2E55ULL,
		0x389F66D6E61DF891ULL,
		0x4573543E3F33DE13ULL,
		0x287E14C9F7834896ULL,
		0x244587F0E6B82B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A3CCF08FD988C42ULL,
		0xAA5524A34311A425ULL,
		0xEAE1C3DC78BFEAEAULL,
		0xEDABB7A9D7DE5CABULL,
		0x713ECDADCC3BF123ULL,
		0x8AE6A87C7E67BC26ULL,
		0x50FC2993EF06912CULL,
		0x488B0FE1CD705602ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x632A2A8642147AE0ULL,
		0xA9BB7A762DFFBC09ULL,
		0xEE54E6ED2B45F146ULL,
		0xE1AAE98C0F5A5ADCULL,
		0xD71D0BA8CE5845CFULL,
		0x84D84CC1F58146E1ULL,
		0x50352E4D7A2BBE8FULL,
		0x3C14DBBB2D3B657FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC654550C8428F5C0ULL,
		0x5376F4EC5BFF7812ULL,
		0xDCA9CDDA568BE28DULL,
		0xC355D3181EB4B5B9ULL,
		0xAE3A17519CB08B9FULL,
		0x09B09983EB028DC3ULL,
		0xA06A5C9AF4577D1FULL,
		0x7829B7765A76CAFEULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF9FBE766CE0CA9CULL,
		0x3DDEEA24F7FE398BULL,
		0x0BB72A1F1A928792ULL,
		0x3A25EE798C8F6B8DULL,
		0xD691C82EC44F1D14ULL,
		0xBA1E86589E169829ULL,
		0x2E05CACC7BC5698CULL,
		0x221CF010F6EE789AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F3F7CECD9C19538ULL,
		0x7BBDD449EFFC7317ULL,
		0x176E543E35250F24ULL,
		0x744BDCF3191ED71AULL,
		0xAD23905D889E3A28ULL,
		0x743D0CB13C2D3053ULL,
		0x5C0B9598F78AD319ULL,
		0x4439E021EDDCF134ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29F1B22950A42951ULL,
		0x7CCF33554298B925ULL,
		0xC479CA8309FBEB79ULL,
		0x1E92B930EA71A9B3ULL,
		0x352DD12D851E90B9ULL,
		0x8E106322E0151638ULL,
		0x43413B83D6A4F9E8ULL,
		0x0401DFD06551C8A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53E36452A14852A2ULL,
		0xF99E66AA8531724AULL,
		0x88F3950613F7D6F2ULL,
		0x3D257261D4E35367ULL,
		0x6A5BA25B0A3D2172ULL,
		0x1C20C645C02A2C70ULL,
		0x86827707AD49F3D1ULL,
		0x0803BFA0CAA39142ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x096A68DAC7BBC913ULL,
		0x1CDE60C2E6E5C1FEULL,
		0x13EC47B6CD634199ULL,
		0x48A9AC3DFD330AE8ULL,
		0x3889B5C174B93AD1ULL,
		0x6EF6C67436DCCD46ULL,
		0x6EBDAA5B90B0E35FULL,
		0x3624B4C0744050B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D4D1B58F779226ULL,
		0x39BCC185CDCB83FCULL,
		0x27D88F6D9AC68332ULL,
		0x9153587BFA6615D0ULL,
		0x71136B82E97275A2ULL,
		0xDDED8CE86DB99A8CULL,
		0xDD7B54B72161C6BEULL,
		0x6C496980E880A162ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x524EDDA6267D0152ULL,
		0xBF5DC22C6858F0C6ULL,
		0xDCD68DE92DD601E0ULL,
		0x608C6AA4283AD3FDULL,
		0x87BC2C9C4F55901EULL,
		0xBBDE8C983AE64DFEULL,
		0x2705B996B0C9F92AULL,
		0x3922EB972A8A1608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA49DBB4C4CFA02A4ULL,
		0x7EBB8458D0B1E18CULL,
		0xB9AD1BD25BAC03C1ULL,
		0xC118D5485075A7FBULL,
		0x0F7859389EAB203CULL,
		0x77BD193075CC9BFDULL,
		0x4E0B732D6193F255ULL,
		0x7245D72E55142C10ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1CD36EE4C4FAED6ULL,
		0xB62A5373D28ACA79ULL,
		0x31BD9EC36D39F824ULL,
		0x0378CC33CBCF4D84ULL,
		0x71677B3D9849D5CEULL,
		0x8620DB6ED08613CFULL,
		0x9BAB9F9F58EBCBCAULL,
		0x39A2605562D0A840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x439A6DDC989F5DACULL,
		0x6C54A6E7A51594F3ULL,
		0x637B3D86DA73F049ULL,
		0x06F19867979E9B08ULL,
		0xE2CEF67B3093AB9CULL,
		0x0C41B6DDA10C279EULL,
		0x37573F3EB1D79795ULL,
		0x7344C0AAC5A15081ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E5AFD2EFE4462A1ULL,
		0x7D944F7CD82FD148ULL,
		0x7C0A68CDC7E08C52ULL,
		0x565E36489C1EFF77ULL,
		0x36C042252AD898F2ULL,
		0xF734F16A6C2B150BULL,
		0x0998213FC96DC3D6ULL,
		0x0515E3FB116995B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCB5FA5DFC88C542ULL,
		0xFB289EF9B05FA290ULL,
		0xF814D19B8FC118A4ULL,
		0xACBC6C91383DFEEEULL,
		0x6D80844A55B131E4ULL,
		0xEE69E2D4D8562A16ULL,
		0x1330427F92DB87ADULL,
		0x0A2BC7F622D32B6CULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C1094392A8A2A0ULL,
		0x6D648613A3DA6A8EULL,
		0x987B98CC69BA50DDULL,
		0x3DA0434AE22EEB23ULL,
		0xCC99E3C4093EB0EFULL,
		0x1D9F29E765CA68FDULL,
		0x760E521BC812BF0CULL,
		0x047D7259DD5E673BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3382128725514540ULL,
		0xDAC90C2747B4D51CULL,
		0x30F73198D374A1BAULL,
		0x7B408695C45DD647ULL,
		0x9933C788127D61DEULL,
		0x3B3E53CECB94D1FBULL,
		0xEC1CA43790257E18ULL,
		0x08FAE4B3BABCCE76ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9A3A69D7A866B59ULL,
		0xD0747D911085C517ULL,
		0x819E9A0F280E7B17ULL,
		0x75D63A4718FF4809ULL,
		0x4B38AFF1826F3A4CULL,
		0xB55F98AB48F05CB5ULL,
		0xF1F7FFF3627C2BB1ULL,
		0x1AD124FCEC9285FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53474D3AF50CD6B2ULL,
		0xA0E8FB22210B8A2FULL,
		0x033D341E501CF62FULL,
		0xEBAC748E31FE9013ULL,
		0x96715FE304DE7498ULL,
		0x6ABF315691E0B96AULL,
		0xE3EFFFE6C4F85763ULL,
		0x35A249F9D9250BFFULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9F911D392C74FD1ULL,
		0x75057F26EF0D03EBULL,
		0x42511412D8EEC9A8ULL,
		0xAF060AAA830F0438ULL,
		0xF01CB9DD32E0D41CULL,
		0x75E58C60BCC7AC5BULL,
		0x97570BA33A41963EULL,
		0x2A1C3C3138995E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F223A7258E9FA2ULL,
		0xEA0AFE4DDE1A07D7ULL,
		0x84A22825B1DD9350ULL,
		0x5E0C1555061E0870ULL,
		0xE03973BA65C1A839ULL,
		0xEBCB18C1798F58B7ULL,
		0x2EAE174674832C7CULL,
		0x543878627132BC97ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEA40C25155F8210ULL,
		0x90F16526D3599AA5ULL,
		0x413C6F5621A29BC4ULL,
		0xAD438658BAE73D04ULL,
		0x9890209594714AC2ULL,
		0x2CB1297C924F6553ULL,
		0xDBE5DEF09F920A79ULL,
		0x36A41837923D624AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD48184A2ABF0420ULL,
		0x21E2CA4DA6B3354BULL,
		0x8278DEAC43453789ULL,
		0x5A870CB175CE7A08ULL,
		0x3120412B28E29585ULL,
		0x596252F9249ECAA7ULL,
		0xB7CBBDE13F2414F2ULL,
		0x6D48306F247AC495ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3F847FAF26F8B14ULL,
		0xDDDAC105827E81ADULL,
		0xEE15180A94414876ULL,
		0x429BCDFE1BB1A7FDULL,
		0x4A75389024C3CB44ULL,
		0x0BDF1B26812D353CULL,
		0xE45BBD271B8B0FA8ULL,
		0x25BED8B8A66D0638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47F08FF5E4DF1628ULL,
		0xBBB5820B04FD035BULL,
		0xDC2A3015288290EDULL,
		0x85379BFC37634FFBULL,
		0x94EA712049879688ULL,
		0x17BE364D025A6A78ULL,
		0xC8B77A4E37161F50ULL,
		0x4B7DB1714CDA0C71ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0BA4DEEB1422BA8ULL,
		0xD1D23957765BAFA9ULL,
		0x8F6700805568038BULL,
		0x31AAC85E17CC139FULL,
		0x6C50BB2E9EA21AB7ULL,
		0xCB257E5343FE425FULL,
		0x4BCFAE8FC386DBD0ULL,
		0x029B33372D12134EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1749BDD62845750ULL,
		0xA3A472AEECB75F53ULL,
		0x1ECE0100AAD00717ULL,
		0x635590BC2F98273FULL,
		0xD8A1765D3D44356EULL,
		0x964AFCA687FC84BEULL,
		0x979F5D1F870DB7A1ULL,
		0x0536666E5A24269CULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x755CDEBEEE8D8180ULL,
		0x9EED0BF932CE1102ULL,
		0x843DACA02BB8B841ULL,
		0x6665D9032E1B1064ULL,
		0x8DFCFC9AD4AFD09AULL,
		0x22D274C1B02C361CULL,
		0xF19E7898F60E9714ULL,
		0x074F8F010FA721B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB9BD7DDD1B0300ULL,
		0x3DDA17F2659C2204ULL,
		0x087B594057717083ULL,
		0xCCCBB2065C3620C9ULL,
		0x1BF9F935A95FA134ULL,
		0x45A4E98360586C39ULL,
		0xE33CF131EC1D2E28ULL,
		0x0E9F1E021F4E4371ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC106CE42C5D8163FULL,
		0x2EA0C4DD3E983F44ULL,
		0x4C4A162934BF3BC5ULL,
		0xDD3E46CB2E73C234ULL,
		0xA53A45CCBA1BE793ULL,
		0x1DF46E53B1658CBCULL,
		0x6D07C13204EA2974ULL,
		0x119E1C709A183010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x820D9C858BB02C7EULL,
		0x5D4189BA7D307E89ULL,
		0x98942C52697E778AULL,
		0xBA7C8D965CE78468ULL,
		0x4A748B997437CF27ULL,
		0x3BE8DCA762CB1979ULL,
		0xDA0F826409D452E8ULL,
		0x233C38E134306020ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC43745314B75FE6ULL,
		0x8C06B3D48580AB37ULL,
		0x8A078004C25AE354ULL,
		0x6853FFACFE4FC87DULL,
		0x988565FC85EAD4C2ULL,
		0x19713BE5295B0983ULL,
		0x758CA4879C7DB7D1ULL,
		0x233756135753304DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF886E8A6296EBFCCULL,
		0x180D67A90B01566FULL,
		0x140F000984B5C6A9ULL,
		0xD0A7FF59FC9F90FBULL,
		0x310ACBF90BD5A984ULL,
		0x32E277CA52B61307ULL,
		0xEB19490F38FB6FA2ULL,
		0x466EAC26AEA6609AULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x198229572A361D3FULL,
		0xD392581FF849FEA4ULL,
		0x6409D1AEBE09B54FULL,
		0xAA68F06ADA019AC6ULL,
		0x2AB16F690F5EF094ULL,
		0xC9CE024918569CF6ULL,
		0xB5705FF39BEDA004ULL,
		0x09ED612C4A6267EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330452AE546C3A7EULL,
		0xA724B03FF093FD48ULL,
		0xC813A35D7C136A9FULL,
		0x54D1E0D5B403358CULL,
		0x5562DED21EBDE129ULL,
		0x939C049230AD39ECULL,
		0x6AE0BFE737DB4009ULL,
		0x13DAC25894C4CFD7ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC145EB51A028A491ULL,
		0x3443003035F226ABULL,
		0x13507C2F9E245F7FULL,
		0x101ED00792603C59ULL,
		0x277692E5318D9523ULL,
		0x1DA020AEDB5A4253ULL,
		0x122B437E9114CAD3ULL,
		0x2EAD30147D12567BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x828BD6A340514922ULL,
		0x688600606BE44D57ULL,
		0x26A0F85F3C48BEFEULL,
		0x203DA00F24C078B2ULL,
		0x4EED25CA631B2A46ULL,
		0x3B40415DB6B484A6ULL,
		0x245686FD222995A6ULL,
		0x5D5A6028FA24ACF6ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0E3B0F61DFD8F9DULL,
		0xC7EDA1765DDA1944ULL,
		0x2BA773A7625D5BBDULL,
		0xED15A24E33069F0DULL,
		0x0A0BA0269994FFF6ULL,
		0xFBDFE6092EA6D308ULL,
		0xA9D63503B90D0867ULL,
		0x0E1EB00AB7BDD2A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C761EC3BFB1F3AULL,
		0x8FDB42ECBBB43289ULL,
		0x574EE74EC4BAB77BULL,
		0xDA2B449C660D3E1AULL,
		0x1417404D3329FFEDULL,
		0xF7BFCC125D4DA610ULL,
		0x53AC6A07721A10CFULL,
		0x1C3D60156F7BA547ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1553422B94CC0C9CULL,
		0xE766638B2349FB96ULL,
		0xF6DDEAF35B1AA9FAULL,
		0x07FFDD9169DE453BULL,
		0xFCDD5B89D5BAFDFDULL,
		0xD4E7F9DD409DC0B6ULL,
		0x0593942272861F2BULL,
		0x1D36C6CEFBF8C757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA6845729981938ULL,
		0xCECCC7164693F72CULL,
		0xEDBBD5E6B63553F5ULL,
		0x0FFFBB22D3BC8A77ULL,
		0xF9BAB713AB75FBFAULL,
		0xA9CFF3BA813B816DULL,
		0x0B272844E50C3E57ULL,
		0x3A6D8D9DF7F18EAEULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BF5D80B5C72CC1AULL,
		0x9050233CDD8F61A4ULL,
		0x658A029ED0CBFB8CULL,
		0xF8F3F0B1B75D30CCULL,
		0x8473BE9A5E44CA13ULL,
		0x3BADC1704B521117ULL,
		0x21A16437C33473CBULL,
		0x38546D2B90F3E961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17EBB016B8E59834ULL,
		0x20A04679BB1EC349ULL,
		0xCB14053DA197F719ULL,
		0xF1E7E1636EBA6198ULL,
		0x08E77D34BC899427ULL,
		0x775B82E096A4222FULL,
		0x4342C86F8668E796ULL,
		0x70A8DA5721E7D2C2ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5614AB8A15FFE03FULL,
		0x7E799ECD2F5F252AULL,
		0x1CEB7205968D32D0ULL,
		0xAA2A52242C274851ULL,
		0x91D9C9A5E3CB69C5ULL,
		0x7E46905C43D46C8CULL,
		0x2C4A8FEAF1F0F02FULL,
		0x3B0CE892AC49BB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2957142BFFC07EULL,
		0xFCF33D9A5EBE4A54ULL,
		0x39D6E40B2D1A65A0ULL,
		0x5454A448584E90A2ULL,
		0x23B3934BC796D38BULL,
		0xFC8D20B887A8D919ULL,
		0x58951FD5E3E1E05EULL,
		0x7619D1255893773AULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CEC2D810415D6F7ULL,
		0x429C1245331ADBD6ULL,
		0xCCE2B356F96A60F6ULL,
		0x2D1B8619F25C5B9EULL,
		0xAE636356B547C340ULL,
		0x9ABA81A32908CAC0ULL,
		0xAB2623D8B9FC2D41ULL,
		0x379AB774A3FE8639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D85B02082BADEEULL,
		0x8538248A6635B7ACULL,
		0x99C566ADF2D4C1ECULL,
		0x5A370C33E4B8B73DULL,
		0x5CC6C6AD6A8F8680ULL,
		0x3575034652119581ULL,
		0x564C47B173F85A83ULL,
		0x6F356EE947FD0C73ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE3B1B8BC04B7907ULL,
		0x7C81E67FF2A0026EULL,
		0xFE2FC930192F753AULL,
		0xAC7A2BBB208E4FDCULL,
		0xFA079D2BAF438B6DULL,
		0x98B9D7A73D991B8BULL,
		0x27076420BED65BA1ULL,
		0x251AD8F2519AF276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C7637178096F20EULL,
		0xF903CCFFE54004DDULL,
		0xFC5F9260325EEA74ULL,
		0x58F45776411C9FB9ULL,
		0xF40F3A575E8716DBULL,
		0x3173AF4E7B323717ULL,
		0x4E0EC8417DACB743ULL,
		0x4A35B1E4A335E4ECULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FDCE67BB73EF2B9ULL,
		0x0FBA992090985464ULL,
		0x7EE84685658D07E4ULL,
		0xA90A146FB6465009ULL,
		0x880802C0AF9616F2ULL,
		0xB858D9DD3EBDD9C4ULL,
		0xC5C378B21C301139ULL,
		0x2AFA0E49ECEAACC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB9CCF76E7DE572ULL,
		0x1F7532412130A8C8ULL,
		0xFDD08D0ACB1A0FC8ULL,
		0x521428DF6C8CA012ULL,
		0x101005815F2C2DE5ULL,
		0x70B1B3BA7D7BB389ULL,
		0x8B86F16438602273ULL,
		0x55F41C93D9D55993ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82ADF92960A0C708ULL,
		0x8B13BB7EFE2467FFULL,
		0xF7DAB3F8FC5A6F00ULL,
		0x618E19BCA950E784ULL,
		0x37138DA181D68EC5ULL,
		0x54664DAA514C35DBULL,
		0x696FAE7B87909A3CULL,
		0x1F412340DDE258CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055BF252C1418E10ULL,
		0x162776FDFC48CFFFULL,
		0xEFB567F1F8B4DE01ULL,
		0xC31C337952A1CF09ULL,
		0x6E271B4303AD1D8AULL,
		0xA8CC9B54A2986BB6ULL,
		0xD2DF5CF70F213478ULL,
		0x3E824681BBC4B194ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7352296BD4406307ULL,
		0x69683135319F8052ULL,
		0x35DD279E18DA2470ULL,
		0x3A1EC6040661887BULL,
		0x77C5858A2F1200BBULL,
		0x499C1DBE081C86F4ULL,
		0x8E2CE6E3E2D2DCD0ULL,
		0x080F9108C0385679ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6A452D7A880C60EULL,
		0xD2D0626A633F00A4ULL,
		0x6BBA4F3C31B448E0ULL,
		0x743D8C080CC310F6ULL,
		0xEF8B0B145E240176ULL,
		0x93383B7C10390DE8ULL,
		0x1C59CDC7C5A5B9A0ULL,
		0x101F22118070ACF3ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10B102CBA0B0BAF6ULL,
		0xD36D302F88842CADULL,
		0x661BEE909C1461ECULL,
		0x6F627DE8D5855C01ULL,
		0xF635A484B66D8EEEULL,
		0x34ECB107FD601B54ULL,
		0x3BBE45960D7239ACULL,
		0x10534C6354EC14A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21620597416175ECULL,
		0xA6DA605F1108595AULL,
		0xCC37DD213828C3D9ULL,
		0xDEC4FBD1AB0AB802ULL,
		0xEC6B49096CDB1DDCULL,
		0x69D9620FFAC036A9ULL,
		0x777C8B2C1AE47358ULL,
		0x20A698C6A9D82950ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD99685D3654685E0ULL,
		0xA0E35201069975A4ULL,
		0x87D4775FCE4B0C9FULL,
		0x038B061CD967313EULL,
		0xE4DD6F6832AB121FULL,
		0xD6D95E3F61A19A27ULL,
		0x3DB5CDEEE89C3CABULL,
		0x110AA91919756F0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32D0BA6CA8D0BC0ULL,
		0x41C6A4020D32EB49ULL,
		0x0FA8EEBF9C96193FULL,
		0x07160C39B2CE627DULL,
		0xC9BADED06556243EULL,
		0xADB2BC7EC343344FULL,
		0x7B6B9BDDD1387957ULL,
		0x2215523232EADE16ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BC4245B779BE781ULL,
		0x8A3512BFA0C07504ULL,
		0xFC3B423BDC0DF920ULL,
		0xB3B1D2EED7B8691DULL,
		0xA27046F162FA4B73ULL,
		0xDBBCFF4F08E7F28FULL,
		0xB4E1DC45ACED3D90ULL,
		0x242042C15683A260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD78848B6EF37CF02ULL,
		0x146A257F4180EA08ULL,
		0xF8768477B81BF241ULL,
		0x6763A5DDAF70D23BULL,
		0x44E08DE2C5F496E7ULL,
		0xB779FE9E11CFE51FULL,
		0x69C3B88B59DA7B21ULL,
		0x48408582AD0744C1ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDED699E10AC23936ULL,
		0xC966A6EC84E4EDA9ULL,
		0x7EFBFBBCCA7A4F6DULL,
		0x197056D555068F36ULL,
		0x8498760A2E2446D4ULL,
		0x9B226A89A22D3BE3ULL,
		0x2117196AB46464B6ULL,
		0x3E8CFE3A53983149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDAD33C21584726CULL,
		0x92CD4DD909C9DB53ULL,
		0xFDF7F77994F49EDBULL,
		0x32E0ADAAAA0D1E6CULL,
		0x0930EC145C488DA8ULL,
		0x3644D513445A77C7ULL,
		0x422E32D568C8C96DULL,
		0x7D19FC74A7306292ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x098A7694722EF33AULL,
		0x476374B3C110893AULL,
		0x45230B81559B7A64ULL,
		0xE446B440EB8A8AD5ULL,
		0x25AD8D50FD44AD90ULL,
		0x1D18A322CAC6E7DEULL,
		0x15B2F63F0E2E45D6ULL,
		0x039EFB4A7EE21310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1314ED28E45DE674ULL,
		0x8EC6E96782211274ULL,
		0x8A461702AB36F4C8ULL,
		0xC88D6881D71515AAULL,
		0x4B5B1AA1FA895B21ULL,
		0x3A314645958DCFBCULL,
		0x2B65EC7E1C5C8BACULL,
		0x073DF694FDC42620ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C7A507AADE7D07DULL,
		0x25110991597E574CULL,
		0xAE28D692A330D1E2ULL,
		0x833D0E93D9F60700ULL,
		0x14B0BD066A15B6B0ULL,
		0xEB0B4BDD74B4C3E4ULL,
		0xC74DF75A0E7C11DAULL,
		0x02D50CCD17E4D388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F4A0F55BCFA0FAULL,
		0x4A221322B2FCAE99ULL,
		0x5C51AD254661A3C4ULL,
		0x067A1D27B3EC0E01ULL,
		0x29617A0CD42B6D61ULL,
		0xD61697BAE96987C8ULL,
		0x8E9BEEB41CF823B5ULL,
		0x05AA199A2FC9A711ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F3869E3084AC9F2ULL,
		0xAD36152917A026DFULL,
		0x62E0F33DA64D8E00ULL,
		0xDBC626B9FA5AC146ULL,
		0xB8FE95F195255193ULL,
		0xD6E332D30C67BAF0ULL,
		0x4C0C6AA55F12CB91ULL,
		0x33A8137FC05B150AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E70D3C6109593E4ULL,
		0x5A6C2A522F404DBEULL,
		0xC5C1E67B4C9B1C01ULL,
		0xB78C4D73F4B5828CULL,
		0x71FD2BE32A4AA327ULL,
		0xADC665A618CF75E1ULL,
		0x9818D54ABE259723ULL,
		0x675026FF80B62A14ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA20D525C6A16EBFBULL,
		0xF7CB65B0A20548D3ULL,
		0x4B39412F1CFBBD9FULL,
		0x4E17252F08A385D5ULL,
		0x1CCC453DF37FB873ULL,
		0x71A089CEBE68456BULL,
		0x6D7D6ECAE38154E5ULL,
		0x088E54B032A6A573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x441AA4B8D42DD7F6ULL,
		0xEF96CB61440A91A7ULL,
		0x9672825E39F77B3FULL,
		0x9C2E4A5E11470BAAULL,
		0x39988A7BE6FF70E6ULL,
		0xE341139D7CD08AD6ULL,
		0xDAFADD95C702A9CAULL,
		0x111CA960654D4AE6ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CE840296BB8A801ULL,
		0x66E60AD69E5251F3ULL,
		0xCD5431A19BA7F24AULL,
		0x23C8682D63E4E5F0ULL,
		0x2865E40790637034ULL,
		0x176A3356F4B97525ULL,
		0xBEABD5945EB5DDD1ULL,
		0x0D059292EEA899C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D08052D7715002ULL,
		0xCDCC15AD3CA4A3E6ULL,
		0x9AA86343374FE494ULL,
		0x4790D05AC7C9CBE1ULL,
		0x50CBC80F20C6E068ULL,
		0x2ED466ADE972EA4AULL,
		0x7D57AB28BD6BBBA2ULL,
		0x1A0B2525DD513387ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EB512326A70CB7DULL,
		0x934A67A9B2C50DE2ULL,
		0xCDD058AEC24A998BULL,
		0xF0F18C0CE6FB56E7ULL,
		0x1A344F39D0B8611CULL,
		0x6505DC223E074329ULL,
		0x3DD1481C7FA95D67ULL,
		0x034C93BB655F2D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6A2464D4E196FAULL,
		0x2694CF53658A1BC4ULL,
		0x9BA0B15D84953317ULL,
		0xE1E31819CDF6ADCFULL,
		0x34689E73A170C239ULL,
		0xCA0BB8447C0E8652ULL,
		0x7BA29038FF52BACEULL,
		0x06992776CABE5A2CULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A4B98E1E3BBF26FULL,
		0x7BF3F73F60C386D2ULL,
		0x1CF7ABC56FF28301ULL,
		0x838A96450C8B68D1ULL,
		0xA617522F65BA7E9EULL,
		0x1B66DFC1620A9F82ULL,
		0xDC27BF4F3609D473ULL,
		0x33507691B00193BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149731C3C777E4DEULL,
		0xF7E7EE7EC1870DA4ULL,
		0x39EF578ADFE50602ULL,
		0x07152C8A1916D1A2ULL,
		0x4C2EA45ECB74FD3DULL,
		0x36CDBF82C4153F05ULL,
		0xB84F7E9E6C13A8E6ULL,
		0x66A0ED236003277DULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAF768DCA67074DCULL,
		0x2FEB313D219DBCB0ULL,
		0xE796EA7008BD7433ULL,
		0x67F6A27133F85D40ULL,
		0x400AD0B51E8623EFULL,
		0xA28AF28E1FFC16AAULL,
		0x5A80C05CA857E575ULL,
		0x1BCE406234EF733BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5EED1B94CE0E9B8ULL,
		0x5FD6627A433B7961ULL,
		0xCF2DD4E0117AE866ULL,
		0xCFED44E267F0BA81ULL,
		0x8015A16A3D0C47DEULL,
		0x4515E51C3FF82D54ULL,
		0xB50180B950AFCAEBULL,
		0x379C80C469DEE676ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF567F9D875DF5C93ULL,
		0x0D5D647C28A9B5F9ULL,
		0x9D5313279EB9CC90ULL,
		0xD87A69646B904764ULL,
		0x4235F5941F072F38ULL,
		0x8CE5A982549D7FC3ULL,
		0x185FBCC7E79CE1EBULL,
		0x007A6E9C4D6C2B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACFF3B0EBBEB926ULL,
		0x1ABAC8F851536BF3ULL,
		0x3AA6264F3D739920ULL,
		0xB0F4D2C8D7208EC9ULL,
		0x846BEB283E0E5E71ULL,
		0x19CB5304A93AFF86ULL,
		0x30BF798FCF39C3D7ULL,
		0x00F4DD389AD8573AULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x070FA40204B9E2CFULL,
		0x7DEC4477420784ABULL,
		0x36330C6E267F94D9ULL,
		0x5AB956624BE920A4ULL,
		0x34F1B20974DFA99BULL,
		0xB0F5E1BC4C414F75ULL,
		0x96EBEB99E671E548ULL,
		0x35C45195F487039FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E1F48040973C59EULL,
		0xFBD888EE840F0956ULL,
		0x6C6618DC4CFF29B2ULL,
		0xB572ACC497D24148ULL,
		0x69E36412E9BF5336ULL,
		0x61EBC37898829EEAULL,
		0x2DD7D733CCE3CA91ULL,
		0x6B88A32BE90E073FULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0A19F17B174D516ULL,
		0x7539CF9ECE9AF039ULL,
		0xC8CD9CE8C8928C4DULL,
		0x10D9B2E9C1B34ED2ULL,
		0xEC98E818D861E3F4ULL,
		0x8115D550909C9E8DULL,
		0x8F4A672D9A5C8BBEULL,
		0x1529C6EB8E2552D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1433E2F62E9AA2CULL,
		0xEA739F3D9D35E073ULL,
		0x919B39D19125189AULL,
		0x21B365D383669DA5ULL,
		0xD931D031B0C3C7E8ULL,
		0x022BAAA121393D1BULL,
		0x1E94CE5B34B9177DULL,
		0x2A538DD71C4AA5A9ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B623FE11A368DFDULL,
		0x2FD8EB2E46088BADULL,
		0x7A2E4C12BA61CDC8ULL,
		0xC37AC1EC8FC8A300ULL,
		0xA38A86F456451343ULL,
		0x3C08DB878B6A1A80ULL,
		0xECB3D7F3580930EEULL,
		0x3D226BA2BEA68ABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C47FC2346D1BFAULL,
		0x5FB1D65C8C11175BULL,
		0xF45C982574C39B90ULL,
		0x86F583D91F914600ULL,
		0x47150DE8AC8A2687ULL,
		0x7811B70F16D43501ULL,
		0xD967AFE6B01261DCULL,
		0x7A44D7457D4D1577ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6C8CCC54CA20D38ULL,
		0x27DFF39A6CDA0467ULL,
		0xE39480A1BAA7AD24ULL,
		0xE978B01177021571ULL,
		0x6702155095BB2222ULL,
		0x233520C57AA7885CULL,
		0xCB50E4B70A10544BULL,
		0x0A9064E6BADB84A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D91998A99441A70ULL,
		0x4FBFE734D9B408CFULL,
		0xC7290143754F5A48ULL,
		0xD2F16022EE042AE3ULL,
		0xCE042AA12B764445ULL,
		0x466A418AF54F10B8ULL,
		0x96A1C96E1420A896ULL,
		0x1520C9CD75B70943ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x438F19C7A72052BBULL,
		0x092690FAB1BDF53DULL,
		0x3B5BD574AA86B1EAULL,
		0x3553FC4954C9FEB1ULL,
		0x712339015B4ECD2AULL,
		0xC5483BBE1B2312B2ULL,
		0xD558434468FAECE8ULL,
		0x3B54041843BE485CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x871E338F4E40A576ULL,
		0x124D21F5637BEA7AULL,
		0x76B7AAE9550D63D4ULL,
		0x6AA7F892A993FD62ULL,
		0xE2467202B69D9A54ULL,
		0x8A90777C36462564ULL,
		0xAAB08688D1F5D9D1ULL,
		0x76A80830877C90B9ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2F04F3BAA2BB7B0ULL,
		0xC71B3D6B2E6214F8ULL,
		0xE9362642927E3A4EULL,
		0xE249DAFB363EF982ULL,
		0x9A0531F6ED74431EULL,
		0x9B74D8D3E7180E4DULL,
		0x296B6EC3FEEA0B24ULL,
		0x100485776432915DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5E09E7754576F60ULL,
		0x8E367AD65CC429F1ULL,
		0xD26C4C8524FC749DULL,
		0xC493B5F66C7DF305ULL,
		0x340A63EDDAE8863DULL,
		0x36E9B1A7CE301C9BULL,
		0x52D6DD87FDD41649ULL,
		0x20090AEEC86522BAULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA04D25C169BC8E5ULL,
		0xA05B2FC287A3D17AULL,
		0xB476B89379065385ULL,
		0x86A07C9F1204FF8CULL,
		0x2875972E7CBBE78EULL,
		0x90295BF29340BDCCULL,
		0xAA1D10318E11D862ULL,
		0x1BC3268C0087D333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB409A4B82D3791CAULL,
		0x40B65F850F47A2F5ULL,
		0x68ED7126F20CA70BULL,
		0x0D40F93E2409FF19ULL,
		0x50EB2E5CF977CF1DULL,
		0x2052B7E526817B98ULL,
		0x543A20631C23B0C5ULL,
		0x37864D18010FA667ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEDB50DCB08CE4D9ULL,
		0x27D0BF9E6CDABA5BULL,
		0xDD08BEEE66CAE7E2ULL,
		0x2D9D345F508EA017ULL,
		0x4A18CA52AF0BF318ULL,
		0x20CDF9B765F4AECBULL,
		0xD07F1312F0C407B8ULL,
		0x1D38CB37EBE4C40BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB6A1B96119C9B2ULL,
		0x4FA17F3CD9B574B7ULL,
		0xBA117DDCCD95CFC4ULL,
		0x5B3A68BEA11D402FULL,
		0x943194A55E17E630ULL,
		0x419BF36ECBE95D96ULL,
		0xA0FE2625E1880F70ULL,
		0x3A71966FD7C98817ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x864045D1F7464BA8ULL,
		0x78B7D45A99F40590ULL,
		0x756EF3B4075CD8CBULL,
		0xAE1F013D3C0FEA7DULL,
		0x52BFDF2E75F4ADB8ULL,
		0x549BA11404D19B52ULL,
		0x83B20E2243A8D85FULL,
		0x05B5F6F4834939D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C808BA3EE8C9750ULL,
		0xF16FA8B533E80B21ULL,
		0xEADDE7680EB9B196ULL,
		0x5C3E027A781FD4FAULL,
		0xA57FBE5CEBE95B71ULL,
		0xA937422809A336A4ULL,
		0x07641C448751B0BEULL,
		0x0B6BEDE9069273A1ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6EBAAD039140716ULL,
		0xB06F6B6BB78246EAULL,
		0x9F1B4076F7783D01ULL,
		0x1D67C4DC4CE596D2ULL,
		0x156B28B3553818A2ULL,
		0x5B92C40F3394E912ULL,
		0x729EE68E3622E29BULL,
		0x3D752E11DBB1C255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD755A072280E2CULL,
		0x60DED6D76F048DD5ULL,
		0x3E3680EDEEF07A03ULL,
		0x3ACF89B899CB2DA5ULL,
		0x2AD65166AA703144ULL,
		0xB725881E6729D224ULL,
		0xE53DCD1C6C45C536ULL,
		0x7AEA5C23B76384AAULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EEC608240449CADULL,
		0x03033E121E170732ULL,
		0xABB66A3F25DEC0EFULL,
		0x620998E8B6260117ULL,
		0x31A741024B6E180EULL,
		0x092856149BB04E74ULL,
		0x015B93EF3EADA847ULL,
		0x03AD0FB7B97AC8DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD8C1048089395AULL,
		0x06067C243C2E0E64ULL,
		0x576CD47E4BBD81DEULL,
		0xC41331D16C4C022FULL,
		0x634E820496DC301CULL,
		0x1250AC2937609CE8ULL,
		0x02B727DE7D5B508EULL,
		0x075A1F6F72F591B4ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x838FE07D5BB3CC2DULL,
		0xF9B43E8DE896CC9CULL,
		0x4BB34B717B6C6144ULL,
		0x087CE1ADB593ABBDULL,
		0x3EDC65148D2C0667ULL,
		0x3CDF711FA57E1D35ULL,
		0x08D65CF9D65F8D03ULL,
		0x32CF47BB6AA4401BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x071FC0FAB767985AULL,
		0xF3687D1BD12D9939ULL,
		0x976696E2F6D8C289ULL,
		0x10F9C35B6B27577AULL,
		0x7DB8CA291A580CCEULL,
		0x79BEE23F4AFC3A6AULL,
		0x11ACB9F3ACBF1A06ULL,
		0x659E8F76D5488036ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C8FF5460067CBAULL,
		0xA8ED27ECD4755AA8ULL,
		0x096243FE233D00F0ULL,
		0x0D76CBD98E9DDDADULL,
		0xADB152199B73C3FBULL,
		0x43D9B17ACB8F5F5CULL,
		0xA524483DF630C284ULL,
		0x1E68ECBB0987B5A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1391FEA8C00CF974ULL,
		0x51DA4FD9A8EAB550ULL,
		0x12C487FC467A01E1ULL,
		0x1AED97B31D3BBB5AULL,
		0x5B62A43336E787F6ULL,
		0x87B362F5971EBEB9ULL,
		0x4A48907BEC618508ULL,
		0x3CD1D976130F6B53ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x434C9B6B24E18005ULL,
		0xC3E707A1C54E31EEULL,
		0xF38DDAADA49683F9ULL,
		0x72137670F4FCD69FULL,
		0x0EB44256802C02B9ULL,
		0x0FB92EB079DB3C1BULL,
		0x317B9D38AA501E74ULL,
		0x2628A5B2EE94B4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869936D649C3000AULL,
		0x87CE0F438A9C63DCULL,
		0xE71BB55B492D07F3ULL,
		0xE426ECE1E9F9AD3FULL,
		0x1D6884AD00580572ULL,
		0x1F725D60F3B67836ULL,
		0x62F73A7154A03CE8ULL,
		0x4C514B65DD2969E2ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4DB791B7523A7B0ULL,
		0x5D54EDD51A67E1B9ULL,
		0x4BE904A79B855322ULL,
		0x1D0E8CD97041D9C0ULL,
		0xCD7E00E2944CD05FULL,
		0xB6B860E5FC27AD59ULL,
		0x76DB4216FC24A5CEULL,
		0x3F8054516D02C274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B6F236EA474F60ULL,
		0xBAA9DBAA34CFC373ULL,
		0x97D2094F370AA644ULL,
		0x3A1D19B2E083B380ULL,
		0x9AFC01C52899A0BEULL,
		0x6D70C1CBF84F5AB3ULL,
		0xEDB6842DF8494B9DULL,
		0x7F00A8A2DA0584E8ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AEEF5DE37F5B985ULL,
		0x4CECE31FC4B1BD49ULL,
		0xD86EE76E16A66FC0ULL,
		0xEADD8DBF47944704ULL,
		0x415A3B5979A45310ULL,
		0xA545F74B526D6390ULL,
		0x1769F909D1C60291ULL,
		0x292644F2C73F82BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35DDEBBC6FEB730AULL,
		0x99D9C63F89637A92ULL,
		0xB0DDCEDC2D4CDF80ULL,
		0xD5BB1B7E8F288E09ULL,
		0x82B476B2F348A621ULL,
		0x4A8BEE96A4DAC720ULL,
		0x2ED3F213A38C0523ULL,
		0x524C89E58E7F0578ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7331CBA89D2CB0BULL,
		0x134B8E593904CE56ULL,
		0x841AA70900BC39ABULL,
		0x701AB6BF76679741ULL,
		0x00436EA95A3B458BULL,
		0x1088503B074C47CBULL,
		0x852C504E3AADAB0EULL,
		0x280E89D6E41DA77DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E66397513A59616ULL,
		0x26971CB272099CADULL,
		0x08354E1201787356ULL,
		0xE0356D7EECCF2E83ULL,
		0x0086DD52B4768B16ULL,
		0x2110A0760E988F96ULL,
		0x0A58A09C755B561CULL,
		0x501D13ADC83B4EFBULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83858E6AE286F6D0ULL,
		0x674B3B9E2DE1849DULL,
		0x315FFEA9DE57F28CULL,
		0x2CA475E4762F4BA3ULL,
		0x9E5C9E7FC49FA478ULL,
		0x8434BC53B7C7A308ULL,
		0x2ED5E6AF8D2E7DE0ULL,
		0x3A454C670678B604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x070B1CD5C50DEDA0ULL,
		0xCE96773C5BC3093BULL,
		0x62BFFD53BCAFE518ULL,
		0x5948EBC8EC5E9746ULL,
		0x3CB93CFF893F48F0ULL,
		0x086978A76F8F4611ULL,
		0x5DABCD5F1A5CFBC1ULL,
		0x748A98CE0CF16C08ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71D9CB8A28340211ULL,
		0x5895AA811124A4E9ULL,
		0x2CC1ACC46F477D1EULL,
		0xFB12104F452A744EULL,
		0x77931A6F1B5842ABULL,
		0xAC6A44EF7B3CE5E9ULL,
		0x98C506DF990B9828ULL,
		0x184E30A6D233692FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B3971450680422ULL,
		0xB12B5502224949D2ULL,
		0x59835988DE8EFA3CULL,
		0xF624209E8A54E89CULL,
		0xEF2634DE36B08557ULL,
		0x58D489DEF679CBD2ULL,
		0x318A0DBF32173051ULL,
		0x309C614DA466D25FULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE080DA30387A6DBEULL,
		0x8E16E1A9ACEF9ED1ULL,
		0xBC050F65B88A2D5BULL,
		0x3581C8B96BF1F057ULL,
		0x85E0511DF2435B95ULL,
		0xB9B7362D205E9C3AULL,
		0xBF595EFADC92A3BCULL,
		0x0A4E924E9D55F66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC101B46070F4DB7CULL,
		0x1C2DC35359DF3DA3ULL,
		0x780A1ECB71145AB7ULL,
		0x6B039172D7E3E0AFULL,
		0x0BC0A23BE486B72AULL,
		0x736E6C5A40BD3875ULL,
		0x7EB2BDF5B9254779ULL,
		0x149D249D3AABECDDULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303A0E61CD12291AULL,
		0xCE1EDCF4C75A8067ULL,
		0x2B240FF779BC2DEDULL,
		0xEC26B3967BA50CEAULL,
		0x8A770EA50DC434D6ULL,
		0x75BA626ED0007F91ULL,
		0xFAB2BB7E35CCEE3CULL,
		0x277227A9774C2A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60741CC39A245234ULL,
		0x9C3DB9E98EB500CEULL,
		0x56481FEEF3785BDBULL,
		0xD84D672CF74A19D4ULL,
		0x14EE1D4A1B8869ADULL,
		0xEB74C4DDA000FF23ULL,
		0xF56576FC6B99DC78ULL,
		0x4EE44F52EE985483ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBBEC6759C1F286CULL,
		0xA40D32E66DA57621ULL,
		0x3BF4FC5429DCFDE3ULL,
		0xCC58CB47D9AA336FULL,
		0xBCD50E89A845E313ULL,
		0xFB277F45B1E6F4CEULL,
		0xC847360D7915A659ULL,
		0x02FE4B7DB3C54D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD77D8CEB383E50D8ULL,
		0x481A65CCDB4AEC43ULL,
		0x77E9F8A853B9FBC7ULL,
		0x98B1968FB35466DEULL,
		0x79AA1D13508BC627ULL,
		0xF64EFE8B63CDE99DULL,
		0x908E6C1AF22B4CB3ULL,
		0x05FC96FB678A9AB1ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45C7C160796C575DULL,
		0xF0CA5AFAFEC4873BULL,
		0x234E5501758B8EBEULL,
		0x63E7C9B2D4BC2303ULL,
		0x79EA68328C2AA1F9ULL,
		0x999D7CE18F53B1EAULL,
		0x74A0F0461911F63CULL,
		0x2797C214BCC5F9E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8F82C0F2D8AEBAULL,
		0xE194B5F5FD890E76ULL,
		0x469CAA02EB171D7DULL,
		0xC7CF9365A9784606ULL,
		0xF3D4D065185543F2ULL,
		0x333AF9C31EA763D4ULL,
		0xE941E08C3223EC79ULL,
		0x4F2F8429798BF3C6ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F551676F25D039FULL,
		0xA5267BD0CDD191F5ULL,
		0xAF90CF6B174706ADULL,
		0x8C64588D2E797AB8ULL,
		0xB744AE8673F88EE6ULL,
		0xA3A2D6174E842E48ULL,
		0xD3BA136930FF20FEULL,
		0x1277C3EFDF9C6C6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EAA2CEDE4BA073EULL,
		0x4A4CF7A19BA323EBULL,
		0x5F219ED62E8E0D5BULL,
		0x18C8B11A5CF2F571ULL,
		0x6E895D0CE7F11DCDULL,
		0x4745AC2E9D085C91ULL,
		0xA77426D261FE41FDULL,
		0x24EF87DFBF38D8D5ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04631153D7824388ULL,
		0x862355F6868B04CDULL,
		0x0B26C5DF47E23C46ULL,
		0x933443440F296837ULL,
		0xB0B0707680194CEFULL,
		0xB8B80D179ECC8740ULL,
		0x3230EA04E42F7339ULL,
		0x04302B45C24DC865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C622A7AF048710ULL,
		0x0C46ABED0D16099AULL,
		0x164D8BBE8FC4788DULL,
		0x266886881E52D06EULL,
		0x6160E0ED003299DFULL,
		0x71701A2F3D990E81ULL,
		0x6461D409C85EE673ULL,
		0x0860568B849B90CAULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x230A051CA9883B8DULL,
		0xFB8031CB74C4997EULL,
		0x44E47BB19C4B6AB8ULL,
		0x843A26EE58FEA717ULL,
		0x2ED9D3D651B06845ULL,
		0x40638B4F6B037F97ULL,
		0x2DB8E4B645FA4169ULL,
		0x0871061003CC8484ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46140A395310771AULL,
		0xF7006396E98932FCULL,
		0x89C8F7633896D571ULL,
		0x08744DDCB1FD4E2EULL,
		0x5DB3A7ACA360D08BULL,
		0x80C7169ED606FF2EULL,
		0x5B71C96C8BF482D2ULL,
		0x10E20C2007990908ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FD573015AE7D2C6ULL,
		0xE03C678069B68937ULL,
		0x72324AC040385323ULL,
		0x0B3EA60AAD57CCD3ULL,
		0x53BB2CABD14AD930ULL,
		0xA4E3382E4A2F8911ULL,
		0x7A02E27FCFE81373ULL,
		0x21876725874A65B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FAAE602B5CFA58CULL,
		0xC078CF00D36D126EULL,
		0xE46495808070A647ULL,
		0x167D4C155AAF99A6ULL,
		0xA7765957A295B260ULL,
		0x49C6705C945F1222ULL,
		0xF405C4FF9FD026E7ULL,
		0x430ECE4B0E94CB60ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x129309ED4CAD934DULL,
		0x81C082C21DC3EFE1ULL,
		0x5224EE4714C68D5CULL,
		0x52FBE9316748453CULL,
		0xF3CAF2FC8BA65A48ULL,
		0x18C4D38CA74DB6A3ULL,
		0xD73EF689113EA435ULL,
		0x109FB823CE0D1D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252613DA995B269AULL,
		0x038105843B87DFC2ULL,
		0xA449DC8E298D1AB9ULL,
		0xA5F7D262CE908A78ULL,
		0xE795E5F9174CB490ULL,
		0x3189A7194E9B6D47ULL,
		0xAE7DED12227D486AULL,
		0x213F70479C1A3AD7ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9E3DAB6B37C5F25ULL,
		0x8B4F57FA52F430C4ULL,
		0xC25A304643418B27ULL,
		0xE9D6E259E161E810ULL,
		0x6BFF0AF4624DD5F1ULL,
		0xBEC58C21D0DAB37CULL,
		0x9B69CA237023AA4BULL,
		0x2A08467195AB9672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C7B56D66F8BE4AULL,
		0x169EAFF4A5E86189ULL,
		0x84B4608C8683164FULL,
		0xD3ADC4B3C2C3D021ULL,
		0xD7FE15E8C49BABE3ULL,
		0x7D8B1843A1B566F8ULL,
		0x36D39446E0475497ULL,
		0x54108CE32B572CE5ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07E94FCF0F171E4FULL,
		0xA736FF8CE7A8C57DULL,
		0xE0C5C4AF11FCD0D2ULL,
		0xFAB3072BA9FB2717ULL,
		0xF882B975AD3398AFULL,
		0x90ED04553ECEAEDBULL,
		0xC6C81DAECB972DF4ULL,
		0x3F3439C13C62DE39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD29F9E1E2E3C9EULL,
		0x4E6DFF19CF518AFAULL,
		0xC18B895E23F9A1A5ULL,
		0xF5660E5753F64E2FULL,
		0xF10572EB5A67315FULL,
		0x21DA08AA7D9D5DB7ULL,
		0x8D903B5D972E5BE9ULL,
		0x7E68738278C5BC73ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF4F58D66DDE3516ULL,
		0x625AD3A120E0F8A0ULL,
		0x7EAB7F2FB197557EULL,
		0xCF81860DE5495478ULL,
		0x7BED8754EA278712ULL,
		0xBF36BFEF3EB7EE26ULL,
		0x0018BD0304E1B7A1ULL,
		0x11B942270C62AD9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE9EB1ACDBBC6A2CULL,
		0xC4B5A74241C1F141ULL,
		0xFD56FE5F632EAAFCULL,
		0x9F030C1BCA92A8F0ULL,
		0xF7DB0EA9D44F0E25ULL,
		0x7E6D7FDE7D6FDC4CULL,
		0x00317A0609C36F43ULL,
		0x2372844E18C55B34ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6966C06A5B1FD239ULL,
		0x71F232536C9F8159ULL,
		0x738FF6F810384540ULL,
		0x636A26995D45627AULL,
		0x3DF8F33BC9FA415CULL,
		0x9EB88A935C7B61D5ULL,
		0xB311F545117D8BFAULL,
		0x2385AD6520EEF514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2CD80D4B63FA472ULL,
		0xE3E464A6D93F02B2ULL,
		0xE71FEDF020708A80ULL,
		0xC6D44D32BA8AC4F4ULL,
		0x7BF1E67793F482B8ULL,
		0x3D711526B8F6C3AAULL,
		0x6623EA8A22FB17F5ULL,
		0x470B5ACA41DDEA29ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F623950B94ADD1EULL,
		0xECC9716EC592E9C7ULL,
		0x651867473DBAEC10ULL,
		0x1B2E3BA0D1614591ULL,
		0xA693C814ABFA7424ULL,
		0x297E15482FB3DE12ULL,
		0x1803FFE1BFFE7D27ULL,
		0x17BD633A1E7D6281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EC472A17295BA3CULL,
		0xD992E2DD8B25D38FULL,
		0xCA30CE8E7B75D821ULL,
		0x365C7741A2C28B22ULL,
		0x4D27902957F4E848ULL,
		0x52FC2A905F67BC25ULL,
		0x3007FFC37FFCFA4EULL,
		0x2F7AC6743CFAC502ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x106DFD11342B5002ULL,
		0xFD8589D1130F62B7ULL,
		0x11332F186B2C096BULL,
		0x85A4C9468F7A876EULL,
		0xE3FBFB6D8AADF701ULL,
		0x1A88F6E5C7970226ULL,
		0x4AD3A6F432FC5619ULL,
		0x2F81FEEB4E6F6235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DBFA226856A004ULL,
		0xFB0B13A2261EC56EULL,
		0x22665E30D65812D7ULL,
		0x0B49928D1EF50EDCULL,
		0xC7F7F6DB155BEE03ULL,
		0x3511EDCB8F2E044DULL,
		0x95A74DE865F8AC32ULL,
		0x5F03FDD69CDEC46AULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2BDE76714FCE813ULL,
		0x4119E889A2901BA4ULL,
		0x271D73FB9BA518FCULL,
		0x4A8B577F74180293ULL,
		0x57B3832A7061EBA9ULL,
		0x85363B9DEE2A8953ULL,
		0xD8F3C190F74A343CULL,
		0x019EC1CAD36839FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA57BCECE29F9D026ULL,
		0x8233D11345203749ULL,
		0x4E3AE7F7374A31F8ULL,
		0x9516AEFEE8300526ULL,
		0xAF670654E0C3D752ULL,
		0x0A6C773BDC5512A6ULL,
		0xB1E78321EE946879ULL,
		0x033D8395A6D073FBULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D72F4A762188112ULL,
		0x7B13F42ABBA9CA41ULL,
		0x04C97ADF05A769D7ULL,
		0xB1DCBDFA3CCE1587ULL,
		0x45039A1152C9AFC1ULL,
		0xD4A05C2CFF2D88A2ULL,
		0x92D15663B7B222ADULL,
		0x3C716D096093E271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE5E94EC4310224ULL,
		0xF627E85577539483ULL,
		0x0992F5BE0B4ED3AEULL,
		0x63B97BF4799C2B0EULL,
		0x8A073422A5935F83ULL,
		0xA940B859FE5B1144ULL,
		0x25A2ACC76F64455BULL,
		0x78E2DA12C127C4E3ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70E15F292E032B2CULL,
		0x8012383C07DA8ADDULL,
		0xE5E0BD82B4BDC20BULL,
		0xDF6D3EB6AFC61FAAULL,
		0x4719046A19A78EEEULL,
		0x80A7C72B4FE2EA3FULL,
		0xE90C1A22A5855FC3ULL,
		0x094CE1E55402FE0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C2BE525C065658ULL,
		0x002470780FB515BAULL,
		0xCBC17B05697B8417ULL,
		0xBEDA7D6D5F8C3F55ULL,
		0x8E3208D4334F1DDDULL,
		0x014F8E569FC5D47EULL,
		0xD21834454B0ABF87ULL,
		0x1299C3CAA805FC19ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB4E27AA48536E0AULL,
		0xEC1EBA010841A174ULL,
		0xA540CE8E4D0B0E6BULL,
		0x18CD06E8C3D18BE2ULL,
		0x1A920A688940AB44ULL,
		0x09612FF0F505F78AULL,
		0x186184F1EB963A85ULL,
		0x1DEC7A3799656445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF69C4F5490A6DC14ULL,
		0xD83D7402108342E9ULL,
		0x4A819D1C9A161CD7ULL,
		0x319A0DD187A317C5ULL,
		0x352414D112815688ULL,
		0x12C25FE1EA0BEF14ULL,
		0x30C309E3D72C750AULL,
		0x3BD8F46F32CAC88AULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6113469460E014DULL,
		0x1C3E1C31A731EF53ULL,
		0x94694EB55C16A1B7ULL,
		0xA358581DC6C836F1ULL,
		0xA14CCFDCEE87BF32ULL,
		0x1C73D3BA90008A14ULL,
		0x829E78FEC096505EULL,
		0x3198F486E42EC7B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C2268D28C1C029AULL,
		0x387C38634E63DEA7ULL,
		0x28D29D6AB82D436EULL,
		0x46B0B03B8D906DE3ULL,
		0x42999FB9DD0F7E65ULL,
		0x38E7A77520011429ULL,
		0x053CF1FD812CA0BCULL,
		0x6331E90DC85D8F6FULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63A6228AC63755A5ULL,
		0x8254AE598B2DE76AULL,
		0xFCEAE293FC7C1FF9ULL,
		0x6CB5A5D1636A53DEULL,
		0x8942D1439F342AD6ULL,
		0x4110624E6C52BA74ULL,
		0x8AB7F5255AD1D44CULL,
		0x202F6A45C7DF5728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC74C45158C6EAB4AULL,
		0x04A95CB3165BCED4ULL,
		0xF9D5C527F8F83FF3ULL,
		0xD96B4BA2C6D4A7BDULL,
		0x1285A2873E6855ACULL,
		0x8220C49CD8A574E9ULL,
		0x156FEA4AB5A3A898ULL,
		0x405ED48B8FBEAE51ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8554812D8E02A74EULL,
		0x3A14AD8EABC332E1ULL,
		0xC38831679AFD99E6ULL,
		0x5109C49951825009ULL,
		0xFE4BADC1B10B5E11ULL,
		0x1BC1000F8C0ECD45ULL,
		0xC7AFB2D6F174EEEEULL,
		0x0430BA12E4CC7BEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA9025B1C054E9CULL,
		0x74295B1D578665C3ULL,
		0x871062CF35FB33CCULL,
		0xA2138932A304A013ULL,
		0xFC975B836216BC22ULL,
		0x3782001F181D9A8BULL,
		0x8F5F65ADE2E9DDDCULL,
		0x08617425C998F7DFULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6351938BBBA6784ULL,
		0x0D36F3CA04F5F841ULL,
		0x9473B17469383A0BULL,
		0x309833A2761E5E65ULL,
		0x3033584FB0915128ULL,
		0x4C0C149D0CEE95B6ULL,
		0x13F28D85BDD3D79CULL,
		0x231D9749AF4F8A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6A32717774CF08ULL,
		0x1A6DE79409EBF083ULL,
		0x28E762E8D2707416ULL,
		0x61306744EC3CBCCBULL,
		0x6066B09F6122A250ULL,
		0x9818293A19DD2B6CULL,
		0x27E51B0B7BA7AF38ULL,
		0x463B2E935E9F14E4ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D618F11AFA23E9CULL,
		0x1EAEF4D76CA5FA05ULL,
		0xC64CC8BB54956180ULL,
		0xA21D61D6DB17E242ULL,
		0x83B7269F626D3A03ULL,
		0xEC34CCC8CFD1AA95ULL,
		0xAADF887F463F5275ULL,
		0x253F7481E740E3CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AC31E235F447D38ULL,
		0x3D5DE9AED94BF40AULL,
		0x8C999176A92AC300ULL,
		0x443AC3ADB62FC485ULL,
		0x076E4D3EC4DA7407ULL,
		0xD86999919FA3552BULL,
		0x55BF10FE8C7EA4EBULL,
		0x4A7EE903CE81C79BULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D9CDD1FE4B2CD0EULL,
		0x71A63C867B766889ULL,
		0xB6966433D7192BEBULL,
		0x05C5E460D4327E83ULL,
		0x2BAE913F075BCAE5ULL,
		0x0F8BFEEAEEBBEB16ULL,
		0xA1787CE6E6E5542CULL,
		0x303EDE1EE58DB41FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B39BA3FC9659A1CULL,
		0xE34C790CF6ECD112ULL,
		0x6D2CC867AE3257D6ULL,
		0x0B8BC8C1A864FD07ULL,
		0x575D227E0EB795CAULL,
		0x1F17FDD5DD77D62CULL,
		0x42F0F9CDCDCAA858ULL,
		0x607DBC3DCB1B683FULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2D9B2277B5E9F81ULL,
		0xAE471ED871619E36ULL,
		0xDDC149E70C0F4BC1ULL,
		0x3FF8AF4D925E26D4ULL,
		0xEBA50CC6626B5B2DULL,
		0xDAA7B4FD0D48C838ULL,
		0xC718A0258873D8F6ULL,
		0x2C11833A1A1C3500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B3644EF6BD3F02ULL,
		0x5C8E3DB0E2C33C6DULL,
		0xBB8293CE181E9783ULL,
		0x7FF15E9B24BC4DA9ULL,
		0xD74A198CC4D6B65AULL,
		0xB54F69FA1A919071ULL,
		0x8E31404B10E7B1EDULL,
		0x5823067434386A01ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9E88978AF07F1EAULL,
		0x8F3FB0D3BA75C150ULL,
		0x1ABE8017918CD517ULL,
		0xE1EFAD65C5E55C0DULL,
		0x24C275956B5C87DCULL,
		0xEFB1CCBDCF50CE6BULL,
		0xA9C4F1B3748951BCULL,
		0x119F71B1A8BD6EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D112F15E0FE3D4ULL,
		0x1E7F61A774EB82A1ULL,
		0x357D002F2319AA2FULL,
		0xC3DF5ACB8BCAB81AULL,
		0x4984EB2AD6B90FB9ULL,
		0xDF63997B9EA19CD6ULL,
		0x5389E366E912A379ULL,
		0x233EE363517ADD47ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x233ADC1786AE1D1FULL,
		0x09919A0076011D6EULL,
		0x247086A501FD3321ULL,
		0x24F132AFED9677ECULL,
		0x8CC664A34F1B34ADULL,
		0xB8B22D72B649893BULL,
		0xB2986FE8703D0F79ULL,
		0x11B65104C93139A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4675B82F0D5C3A3EULL,
		0x13233400EC023ADCULL,
		0x48E10D4A03FA6642ULL,
		0x49E2655FDB2CEFD8ULL,
		0x198CC9469E36695AULL,
		0x71645AE56C931277ULL,
		0x6530DFD0E07A1EF3ULL,
		0x236CA20992627341ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E31FB6D1F23FC49ULL,
		0x14B271AA3E494C3CULL,
		0xFFFDF6B4BF01B87DULL,
		0x2C4884D9F17C3332ULL,
		0x1071741FA0617385ULL,
		0x52F97D47A70D1775ULL,
		0x7771E21EF6D1D8C0ULL,
		0x000A0AB1191800B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C63F6DA3E47F892ULL,
		0x2964E3547C929878ULL,
		0xFFFBED697E0370FAULL,
		0x589109B3E2F86665ULL,
		0x20E2E83F40C2E70AULL,
		0xA5F2FA8F4E1A2EEAULL,
		0xEEE3C43DEDA3B180ULL,
		0x0014156232300164ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93E3F51A34D9FF0AULL,
		0xDCBA1AE43733F312ULL,
		0xD43549718D0BFA1BULL,
		0xC90273A380ACAD2FULL,
		0x8C87138F4D0AA7CAULL,
		0x9496C1DD6E9A2FCEULL,
		0x88E666FC7156DFC7ULL,
		0x0A382F70B027ED89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27C7EA3469B3FE14ULL,
		0xB97435C86E67E625ULL,
		0xA86A92E31A17F437ULL,
		0x9204E74701595A5FULL,
		0x190E271E9A154F95ULL,
		0x292D83BADD345F9DULL,
		0x11CCCDF8E2ADBF8FULL,
		0x14705EE1604FDB13ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x498692DDDE1C4CBEULL,
		0x3FE643E8920C89DCULL,
		0xFB45E9B579D20C2FULL,
		0xECBF43BBC7770386ULL,
		0xFF30353467D0BC6CULL,
		0x4319D40AAE1D85A5ULL,
		0x7D11FA6F1AB5DD29ULL,
		0x0BDB8B3CB1EC2787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930D25BBBC38997CULL,
		0x7FCC87D1241913B8ULL,
		0xF68BD36AF3A4185EULL,
		0xD97E87778EEE070DULL,
		0xFE606A68CFA178D9ULL,
		0x8633A8155C3B0B4BULL,
		0xFA23F4DE356BBA52ULL,
		0x17B7167963D84F0EULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A448BD8A94C4802ULL,
		0xACC2719368B07F40ULL,
		0x429F4CA00F107C12ULL,
		0xDE22833AFB603BB9ULL,
		0x1526E6EE26F4B0D6ULL,
		0x4288B426CE988DDFULL,
		0xBCD6D72B224ED610ULL,
		0x365E9F9857A4B9B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348917B152989004ULL,
		0x5984E326D160FE80ULL,
		0x853E99401E20F825ULL,
		0xBC450675F6C07772ULL,
		0x2A4DCDDC4DE961ADULL,
		0x8511684D9D311BBEULL,
		0x79ADAE56449DAC20ULL,
		0x6CBD3F30AF497365ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02071117869B36D4ULL,
		0x5E9AC2675D2A4AB9ULL,
		0xE8E2B390891E726DULL,
		0x6E5B9DEC44B10021ULL,
		0x7376899D009F2603ULL,
		0x32FD6F661238B593ULL,
		0x39C1BA16B9154F33ULL,
		0x3CD19009EC2BE1E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040E222F0D366DA8ULL,
		0xBD3584CEBA549572ULL,
		0xD1C56721123CE4DAULL,
		0xDCB73BD889620043ULL,
		0xE6ED133A013E4C06ULL,
		0x65FADECC24716B26ULL,
		0x7383742D722A9E66ULL,
		0x79A32013D857C3C0ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43F08AB76046666DULL,
		0x03D270545C51F8C2ULL,
		0x1BDA08F029A6ED23ULL,
		0xBDEB7158E098AB62ULL,
		0xABB485D83F471843ULL,
		0xBF978906FA5C583AULL,
		0xF7F2540B7D8FBC96ULL,
		0x0B2662883E256E16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E1156EC08CCCDAULL,
		0x07A4E0A8B8A3F184ULL,
		0x37B411E0534DDA46ULL,
		0x7BD6E2B1C13156C4ULL,
		0x57690BB07E8E3087ULL,
		0x7F2F120DF4B8B075ULL,
		0xEFE4A816FB1F792DULL,
		0x164CC5107C4ADC2DULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC3AAF6B1AE706FFULL,
		0xAC85A528485C799CULL,
		0x4D014009D94FB25EULL,
		0x6CFCC5367D05B0C0ULL,
		0xD0D5A2190C675F67ULL,
		0x85F2A58D49A3FAF1ULL,
		0xD3F3614FFB1ADF4CULL,
		0x3A643AFAFB33CAA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8755ED635CE0DFEULL,
		0x590B4A5090B8F339ULL,
		0x9A028013B29F64BDULL,
		0xD9F98A6CFA0B6180ULL,
		0xA1AB443218CEBECEULL,
		0x0BE54B1A9347F5E3ULL,
		0xA7E6C29FF635BE99ULL,
		0x74C875F5F6679549ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAB4A3002461DE62ULL,
		0xD6D3BC0E976508B9ULL,
		0xC1311B6D80CE95B1ULL,
		0x5B29F36F8DCDCEB5ULL,
		0x10FC9B136361B853ULL,
		0x9C50763782DD1BE1ULL,
		0x30F2924AA6A15152ULL,
		0x0BF9415F65394ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD569460048C3BCC4ULL,
		0xADA7781D2ECA1173ULL,
		0x826236DB019D2B63ULL,
		0xB653E6DF1B9B9D6BULL,
		0x21F93626C6C370A6ULL,
		0x38A0EC6F05BA37C2ULL,
		0x61E524954D42A2A5ULL,
		0x17F282BECA729D9CULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1B4E6333EF349BAULL,
		0x07D7355D5BA53F14ULL,
		0x8ECFFEEADD56A06EULL,
		0x4A332F42112A7898ULL,
		0xCF33826BCCE41C4DULL,
		0x50CEF2AD554FF1D2ULL,
		0x4D11833D7133C484ULL,
		0x050FA9A74F0993BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA369CC667DE69374ULL,
		0x0FAE6ABAB74A7E29ULL,
		0x1D9FFDD5BAAD40DCULL,
		0x94665E842254F131ULL,
		0x9E6704D799C8389AULL,
		0xA19DE55AAA9FE3A5ULL,
		0x9A23067AE2678908ULL,
		0x0A1F534E9E13277EULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6BC0ABCF1E5B7CCULL,
		0x222D9B3396C50EE5ULL,
		0xC1227270310348F6ULL,
		0x62B8062DB1582445ULL,
		0x4D721CE794E72DACULL,
		0x9D9FF72333FF8BC8ULL,
		0xA7B18FC0FBAB8A95ULL,
		0x0AEF6754E7803FC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD781579E3CB6F98ULL,
		0x445B36672D8A1DCBULL,
		0x8244E4E0620691ECULL,
		0xC5700C5B62B0488BULL,
		0x9AE439CF29CE5B58ULL,
		0x3B3FEE4667FF1790ULL,
		0x4F631F81F757152BULL,
		0x15DECEA9CF007F93ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A557591AB3E1EF9ULL,
		0x79779D91A0A42841ULL,
		0xA37A2D083FE17F7AULL,
		0x55B0143F6E5AF9B5ULL,
		0x2D48A1877CBF95BCULL,
		0xB7ABF425E047B7BAULL,
		0x9CC7C4D1A1B51A4EULL,
		0x009E0D360A9752CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14AAEB23567C3DF2ULL,
		0xF2EF3B2341485082ULL,
		0x46F45A107FC2FEF4ULL,
		0xAB60287EDCB5F36BULL,
		0x5A91430EF97F2B78ULL,
		0x6F57E84BC08F6F74ULL,
		0x398F89A3436A349DULL,
		0x013C1A6C152EA59DULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x912A0B438B040371ULL,
		0x3210256715492501ULL,
		0xDAC3494B4BD21D57ULL,
		0x59AF8C6B1B9B8503ULL,
		0x50C875271B38792BULL,
		0xA321D07A1736EC17ULL,
		0x618E575465870B91ULL,
		0x172888094A6019FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22541687160806E2ULL,
		0x64204ACE2A924A03ULL,
		0xB586929697A43AAEULL,
		0xB35F18D637370A07ULL,
		0xA190EA4E3670F256ULL,
		0x4643A0F42E6DD82EULL,
		0xC31CAEA8CB0E1723ULL,
		0x2E51101294C033FCULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABAAD8BC6C43674DULL,
		0x103E722C61A733E8ULL,
		0xBE68BCDF083FEA12ULL,
		0x0490770A147C02C5ULL,
		0x744CC4A6820B3C26ULL,
		0x93D3B998183739DAULL,
		0xDF8AB51419D099F1ULL,
		0x14D729CFB8952556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5755B178D886CE9AULL,
		0x207CE458C34E67D1ULL,
		0x7CD179BE107FD424ULL,
		0x0920EE1428F8058BULL,
		0xE899894D0416784CULL,
		0x27A77330306E73B4ULL,
		0xBF156A2833A133E3ULL,
		0x29AE539F712A4AADULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5EA421B13DD85F8ULL,
		0xAD45092F54CFC390ULL,
		0x06D2B7D118477695ULL,
		0x31A59B36D60C30C6ULL,
		0xA7BA04FCD22F46ECULL,
		0x04292A26035C2FCBULL,
		0xAB0CA3B7C0FF25EAULL,
		0x2AB417308704F59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD4843627BB0BF0ULL,
		0x5A8A125EA99F8721ULL,
		0x0DA56FA2308EED2BULL,
		0x634B366DAC18618CULL,
		0x4F7409F9A45E8DD8ULL,
		0x0852544C06B85F97ULL,
		0x5619476F81FE4BD4ULL,
		0x55682E610E09EB35ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC39E928755D79A73ULL,
		0xE0E4AA1F2D145D85ULL,
		0x161E443F1FEF703AULL,
		0x67D0D3F00FA1EF0BULL,
		0x9BAF38507C072827ULL,
		0xBFDD9056E4ED3A33ULL,
		0x202BE955E6C5B3CCULL,
		0x3DBD41D37F3DB015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x873D250EABAF34E6ULL,
		0xC1C9543E5A28BB0BULL,
		0x2C3C887E3FDEE075ULL,
		0xCFA1A7E01F43DE16ULL,
		0x375E70A0F80E504EULL,
		0x7FBB20ADC9DA7467ULL,
		0x4057D2ABCD8B6799ULL,
		0x7B7A83A6FE7B602AULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD6731E42B24F053ULL,
		0x3960F593920F2340ULL,
		0xF4C9E7B64D72B139ULL,
		0x9D4C664F98388647ULL,
		0x6C5305EDF4E2752FULL,
		0x53D7265D2493FF31ULL,
		0xDAF8BB199BBB4443ULL,
		0x22C1F0992314C711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ACE63C85649E0A6ULL,
		0x72C1EB27241E4681ULL,
		0xE993CF6C9AE56272ULL,
		0x3A98CC9F30710C8FULL,
		0xD8A60BDBE9C4EA5FULL,
		0xA7AE4CBA4927FE62ULL,
		0xB5F1763337768886ULL,
		0x4583E13246298E23ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x282CF5B55107E861ULL,
		0x2B8DDFCC7C2C0F4DULL,
		0x0D3093E43BE8A84DULL,
		0x077B68F81A4C3906ULL,
		0xF1CA97D981D418F5ULL,
		0x7D86C6296560C959ULL,
		0x65E3A3E815BF899AULL,
		0x3C442DBD4A953E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5059EB6AA20FD0C2ULL,
		0x571BBF98F8581E9AULL,
		0x1A6127C877D1509AULL,
		0x0EF6D1F03498720CULL,
		0xE3952FB303A831EAULL,
		0xFB0D8C52CAC192B3ULL,
		0xCBC747D02B7F1334ULL,
		0x78885B7A952A7CE6ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3FF4CE41463935CULL,
		0x6D1C620A74FC5542ULL,
		0x44F0B18D9F8B6AA6ULL,
		0xFBC257722CF8FF24ULL,
		0x06B316EFDAC19E87ULL,
		0x02C4B4117973C7CCULL,
		0x500BD580E7FCD9B4ULL,
		0x00F60062BFF15A29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7FE99C828C726B8ULL,
		0xDA38C414E9F8AA85ULL,
		0x89E1631B3F16D54CULL,
		0xF784AEE459F1FE48ULL,
		0x0D662DDFB5833D0FULL,
		0x05896822F2E78F98ULL,
		0xA017AB01CFF9B368ULL,
		0x01EC00C57FE2B452ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B9B9390CB849CCCULL,
		0xA919A0AB7680EED1ULL,
		0xF640F22024872291ULL,
		0xC4414F0B4C8485C2ULL,
		0x1678BDDE44AC35E1ULL,
		0x52D4F7DCB670B3A4ULL,
		0x67D24711B63F0E39ULL,
		0x1488AB13E1421448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1737272197093998ULL,
		0x52334156ED01DDA3ULL,
		0xEC81E440490E4523ULL,
		0x88829E1699090B85ULL,
		0x2CF17BBC89586BC3ULL,
		0xA5A9EFB96CE16748ULL,
		0xCFA48E236C7E1C72ULL,
		0x29115627C2842890ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D5C25B5D81A7484ULL,
		0xCF09E581BFFA2ED0ULL,
		0x0F012EA869A9CCC6ULL,
		0x9E582185567CDA38ULL,
		0xCB10323860CC70B2ULL,
		0xF53C66607D03B3B5ULL,
		0xC860FBC13FD290E2ULL,
		0x241770A7D544CF7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AB84B6BB034E908ULL,
		0x9E13CB037FF45DA0ULL,
		0x1E025D50D353998DULL,
		0x3CB0430AACF9B470ULL,
		0x96206470C198E165ULL,
		0xEA78CCC0FA07676BULL,
		0x90C1F7827FA521C5ULL,
		0x482EE14FAA899EF7ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x474B5E31B55F560EULL,
		0x5400857DC7B6623EULL,
		0xC94374B6D5A39165ULL,
		0x80131A38D9D5DD6AULL,
		0xD01F5DEA682EE187ULL,
		0xC81950D0D8825DE1ULL,
		0xE8DA4F23CB7F4ECFULL,
		0x02DAC34526C345E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E96BC636ABEAC1CULL,
		0xA8010AFB8F6CC47CULL,
		0x9286E96DAB4722CAULL,
		0x00263471B3ABBAD5ULL,
		0xA03EBBD4D05DC30FULL,
		0x9032A1A1B104BBC3ULL,
		0xD1B49E4796FE9D9FULL,
		0x05B5868A4D868BCFULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB92774E3AD9F21C7ULL,
		0xC4195023DB346969ULL,
		0x459517B87906896AULL,
		0x66972D16EEF6BA4DULL,
		0x5C9D271CED5AF3D4ULL,
		0xE63C72CC3981B73BULL,
		0x3C443497EF9FB7C5ULL,
		0x0E90E3141B89C2D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x724EE9C75B3E438EULL,
		0x8832A047B668D2D3ULL,
		0x8B2A2F70F20D12D5ULL,
		0xCD2E5A2DDDED749AULL,
		0xB93A4E39DAB5E7A8ULL,
		0xCC78E59873036E76ULL,
		0x7888692FDF3F6F8BULL,
		0x1D21C628371385A0ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C4510DD20D44481ULL,
		0x9BFEB8B443B0C37BULL,
		0xC55BE6BE20506B48ULL,
		0xEB14E2BA9116935BULL,
		0x22A1C47F947A7D50ULL,
		0xBD070A705440684FULL,
		0xE03B7E07E20CB6E6ULL,
		0x3B3BBA51F978E8DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD88A21BA41A88902ULL,
		0x37FD7168876186F6ULL,
		0x8AB7CD7C40A0D691ULL,
		0xD629C575222D26B7ULL,
		0x454388FF28F4FAA1ULL,
		0x7A0E14E0A880D09EULL,
		0xC076FC0FC4196DCDULL,
		0x767774A3F2F1D1B5ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E3EA60405DB059FULL,
		0x46A0EB3A4C8B5B2CULL,
		0x542FEC0AF29DD279ULL,
		0x01B9E08078DD7727ULL,
		0x34027BFF2062D00BULL,
		0xF85AB81187D304A9ULL,
		0x36FC48964D77652FULL,
		0x1E0815E61F789813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C7D4C080BB60B3EULL,
		0x8D41D6749916B659ULL,
		0xA85FD815E53BA4F2ULL,
		0x0373C100F1BAEE4EULL,
		0x6804F7FE40C5A016ULL,
		0xF0B570230FA60952ULL,
		0x6DF8912C9AEECA5FULL,
		0x3C102BCC3EF13026ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA049970902D782AULL,
		0x821E388E91C603E2ULL,
		0x01B33DE9A1D34030ULL,
		0x4E6DADBD9732C075ULL,
		0xACD98B23262045CFULL,
		0x79E489860D4FBD02ULL,
		0xF9B393813A44D5BDULL,
		0x1C6B45611A79B2F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740932E1205AF054ULL,
		0x043C711D238C07C5ULL,
		0x03667BD343A68061ULL,
		0x9CDB5B7B2E6580EAULL,
		0x59B316464C408B9EULL,
		0xF3C9130C1A9F7A05ULL,
		0xF36727027489AB7AULL,
		0x38D68AC234F365E5ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x148DFB72F9836185ULL,
		0xF735A8E45939001AULL,
		0xDC68691100A33AC2ULL,
		0x925B7C29EFA94FDEULL,
		0x0BB8482A617517E6ULL,
		0xAEBA85D1FA15382FULL,
		0xCAE00A35599E681BULL,
		0x11B28F35525CFABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291BF6E5F306C30AULL,
		0xEE6B51C8B2720034ULL,
		0xB8D0D22201467585ULL,
		0x24B6F853DF529FBDULL,
		0x17709054C2EA2FCDULL,
		0x5D750BA3F42A705EULL,
		0x95C0146AB33CD037ULL,
		0x23651E6AA4B9F577ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5287FAC1E47040BULL,
		0xE98EFC7446EA1E58ULL,
		0x961B91C45FA480E8ULL,
		0x748C97EF58C697BCULL,
		0x70E556CF35FFB190ULL,
		0xEBCA8E68DAB579EBULL,
		0x3A478B5CA1B4630EULL,
		0x07F0EC6F92131733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A50FF583C8E0816ULL,
		0xD31DF8E88DD43CB1ULL,
		0x2C372388BF4901D1ULL,
		0xE9192FDEB18D2F79ULL,
		0xE1CAAD9E6BFF6320ULL,
		0xD7951CD1B56AF3D6ULL,
		0x748F16B94368C61DULL,
		0x0FE1D8DF24262E66ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC11CAE2D478579CULL,
		0x18E91EEAE81E451BULL,
		0xF0881F9225BD9AB8ULL,
		0x7EC21B04AB3DD47EULL,
		0x71356FB5CFE53474ULL,
		0x60641D9E5C79208AULL,
		0x62BAFFD8003854FEULL,
		0x3CB6115F186B0915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82395C5A8F0AF38ULL,
		0x31D23DD5D03C8A37ULL,
		0xE1103F244B7B3570ULL,
		0xFD843609567BA8FDULL,
		0xE26ADF6B9FCA68E8ULL,
		0xC0C83B3CB8F24114ULL,
		0xC575FFB00070A9FCULL,
		0x796C22BE30D6122AULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A843EE6B57061E0ULL,
		0xCD25D79496C08690ULL,
		0xAE2353A57C3AC393ULL,
		0xBD68485108DEB8AEULL,
		0xDB8BF722383C7928ULL,
		0x5D3A66F05A736F99ULL,
		0x0CC8E1F554A6F6ABULL,
		0x038ECC9FB3DA603BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95087DCD6AE0C3C0ULL,
		0x9A4BAF292D810D20ULL,
		0x5C46A74AF8758727ULL,
		0x7AD090A211BD715DULL,
		0xB717EE447078F251ULL,
		0xBA74CDE0B4E6DF33ULL,
		0x1991C3EAA94DED56ULL,
		0x071D993F67B4C076ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33A3FEC99E8D6349ULL,
		0x2B331682A31B1335ULL,
		0xCE80AC68A8822EF2ULL,
		0xBAF58D52C3F58AD2ULL,
		0x157F85FAA53BC4ACULL,
		0xCAA1628F895148D5ULL,
		0x10AB837895FC37FBULL,
		0x37B6AE6DACFC5A87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6747FD933D1AC692ULL,
		0x56662D054636266AULL,
		0x9D0158D151045DE4ULL,
		0x75EB1AA587EB15A5ULL,
		0x2AFF0BF54A778959ULL,
		0x9542C51F12A291AAULL,
		0x215706F12BF86FF7ULL,
		0x6F6D5CDB59F8B50EULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3D905AD02D956A7ULL,
		0xDA4F68231E487262ULL,
		0x65187A61DE633431ULL,
		0xDB6756E755CE3DB0ULL,
		0xE3FC80299D5050B2ULL,
		0x8FCCC2C79D838D95ULL,
		0xDAF8B4E1EB038907ULL,
		0x3B0D037B267F4196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67B20B5A05B2AD4EULL,
		0xB49ED0463C90E4C5ULL,
		0xCA30F4C3BCC66863ULL,
		0xB6CEADCEAB9C7B60ULL,
		0xC7F900533AA0A165ULL,
		0x1F99858F3B071B2BULL,
		0xB5F169C3D607120FULL,
		0x761A06F64CFE832DULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A139CC210EA9B5BULL,
		0xEB2C857CC7BE1873ULL,
		0xE6DA1549DB186849ULL,
		0xF74F12DA08519927ULL,
		0x56E63C5AE8BD87D7ULL,
		0x2AAD7FE0841A7101ULL,
		0xF4F6974B1FFF4E31ULL,
		0x00ECD18265EC0586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD427398421D536B6ULL,
		0xD6590AF98F7C30E6ULL,
		0xCDB42A93B630D093ULL,
		0xEE9E25B410A3324FULL,
		0xADCC78B5D17B0FAFULL,
		0x555AFFC10834E202ULL,
		0xE9ED2E963FFE9C62ULL,
		0x01D9A304CBD80B0DULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05110990FC1267F3ULL,
		0x0B53D25C4C35F67DULL,
		0xFB5E029BD87EC6EBULL,
		0x14517604CAC944F2ULL,
		0x26EF2CB2D79907BFULL,
		0x91DDB06DFA530B79ULL,
		0x183B8C586985DBB6ULL,
		0x0A69E0281E0B8ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A221321F824CFE6ULL,
		0x16A7A4B8986BECFAULL,
		0xF6BC0537B0FD8DD6ULL,
		0x28A2EC09959289E5ULL,
		0x4DDE5965AF320F7EULL,
		0x23BB60DBF4A616F2ULL,
		0x307718B0D30BB76DULL,
		0x14D3C0503C171DAEULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x400F9DA549E5D186ULL,
		0xD40083A95B68D79CULL,
		0x138A89F4905A0989ULL,
		0xF165C03AEE7E931EULL,
		0x2A155A6DF7475F11ULL,
		0x54386CB232B4B9B8ULL,
		0xF9BBDF4200C8ED7BULL,
		0x10A3B60306569C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801F3B4A93CBA30CULL,
		0xA8010752B6D1AF38ULL,
		0x271513E920B41313ULL,
		0xE2CB8075DCFD263CULL,
		0x542AB4DBEE8EBE23ULL,
		0xA870D96465697370ULL,
		0xF377BE840191DAF6ULL,
		0x21476C060CAD385DULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D2F44F78FE01A45ULL,
		0x9624EDC22FBFC9D9ULL,
		0xE9EC822BCF5F48A0ULL,
		0x2CA91A6BF9007ED5ULL,
		0xBD98A5C00154D90AULL,
		0x9B42D568D51025DAULL,
		0x1592F3A2C3E0B871ULL,
		0x287589BDD48435A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5E89EF1FC0348AULL,
		0x2C49DB845F7F93B2ULL,
		0xD3D904579EBE9141ULL,
		0x595234D7F200FDABULL,
		0x7B314B8002A9B214ULL,
		0x3685AAD1AA204BB5ULL,
		0x2B25E74587C170E3ULL,
		0x50EB137BA9086B46ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4728E288DB5F00DULL,
		0x0000ACF621590E2EULL,
		0x6B41F43A408B0BC3ULL,
		0xE3DAF3CD2DD7FC98ULL,
		0x66B08949EAD50482ULL,
		0x6417220D277F56A1ULL,
		0x9AF7D1119D0D1124ULL,
		0x24529A04735517BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E51C511B6BE01AULL,
		0x000159EC42B21C5DULL,
		0xD683E87481161786ULL,
		0xC7B5E79A5BAFF930ULL,
		0xCD611293D5AA0905ULL,
		0xC82E441A4EFEAD42ULL,
		0x35EFA2233A1A2248ULL,
		0x48A53408E6AA2F7BULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46C7D87DEBBB1329ULL,
		0xA839F25BDBF05EDBULL,
		0x114FE6251FD2B6B3ULL,
		0x5D0F4D4DB4D93AADULL,
		0xFFC8B5D9C64F81E5ULL,
		0xFE16777709EA0E2FULL,
		0x60273D55BF6DF33DULL,
		0x291958AA2198012BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D8FB0FBD7762652ULL,
		0x5073E4B7B7E0BDB6ULL,
		0x229FCC4A3FA56D67ULL,
		0xBA1E9A9B69B2755AULL,
		0xFF916BB38C9F03CAULL,
		0xFC2CEEEE13D41C5FULL,
		0xC04E7AAB7EDBE67BULL,
		0x5232B15443300256ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51516476F830BE4DULL,
		0xBC280E5909D45C85ULL,
		0x0A66A12DAF6A1444ULL,
		0x48D607E77E2DBF5FULL,
		0xE52263479FFDE9ECULL,
		0x5A414D4CFCD2857BULL,
		0x6F3B689CE03D86D8ULL,
		0x15A5D4230BCFEE11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2A2C8EDF0617C9AULL,
		0x78501CB213A8B90AULL,
		0x14CD425B5ED42889ULL,
		0x91AC0FCEFC5B7EBEULL,
		0xCA44C68F3FFBD3D8ULL,
		0xB4829A99F9A50AF7ULL,
		0xDE76D139C07B0DB0ULL,
		0x2B4BA846179FDC22ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x859ED214E8FD013AULL,
		0xD80173474B545B3EULL,
		0x1828D2D40832BE61ULL,
		0x9D11713CBD00EE40ULL,
		0x7B81F404303C76C3ULL,
		0xF773A5A079F1F475ULL,
		0x97E4675ECEC4E383ULL,
		0x283626F4E8A16E05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B3DA429D1FA0274ULL,
		0xB002E68E96A8B67DULL,
		0x3051A5A810657CC3ULL,
		0x3A22E2797A01DC80ULL,
		0xF703E8086078ED87ULL,
		0xEEE74B40F3E3E8EAULL,
		0x2FC8CEBD9D89C707ULL,
		0x506C4DE9D142DC0BULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303C7034C12EACDFULL,
		0x150EDC384B82D584ULL,
		0xE60B84697E86A0DCULL,
		0xA4ACFB4F4F5B91DAULL,
		0x6050DEFB9A10E04EULL,
		0x00B775650D19B345ULL,
		0x563BF817FDDD2F9BULL,
		0x1D14108F865A5E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6078E069825D59BEULL,
		0x2A1DB8709705AB08ULL,
		0xCC1708D2FD0D41B8ULL,
		0x4959F69E9EB723B5ULL,
		0xC0A1BDF73421C09DULL,
		0x016EEACA1A33668AULL,
		0xAC77F02FFBBA5F36ULL,
		0x3A28211F0CB4BC0EULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D022783FBD9960AULL,
		0xE264A3EF1E654C9AULL,
		0xDE00EAA932B2283DULL,
		0xDA260E8567F7A7DBULL,
		0xEC0BB8BB3236DC51ULL,
		0xBA989700C0D421CCULL,
		0x9DB13DA353B0B871ULL,
		0x1DEF01D4E6215FE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A044F07F7B32C14ULL,
		0xC4C947DE3CCA9934ULL,
		0xBC01D5526564507BULL,
		0xB44C1D0ACFEF4FB7ULL,
		0xD8177176646DB8A3ULL,
		0x75312E0181A84399ULL,
		0x3B627B46A76170E3ULL,
		0x3BDE03A9CC42BFCFULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E620F40F08E01F9ULL,
		0x754D423C7C217E46ULL,
		0xDB79E42F8215B698ULL,
		0x3941AB4B2011899EULL,
		0x4ECEE7DA13261E05ULL,
		0xE0BCB3602AD8082DULL,
		0x152F9F680A4A3E76ULL,
		0x1564913F31C4872BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC41E81E11C03F2ULL,
		0xEA9A8478F842FC8CULL,
		0xB6F3C85F042B6D30ULL,
		0x728356964023133DULL,
		0x9D9DCFB4264C3C0AULL,
		0xC17966C055B0105AULL,
		0x2A5F3ED014947CEDULL,
		0x2AC9227E63890E56ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F226371EC353FD6ULL,
		0x53971232314B5009ULL,
		0xD168ED8A7B08BD46ULL,
		0x24AD248A827F67D2ULL,
		0x2BACD30E8B6962E4ULL,
		0xFDC127D6FCAAFE2AULL,
		0x32DF175FC8178A4AULL,
		0x2ECBC69CCDDF9E5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E44C6E3D86A7FACULL,
		0xA72E24646296A012ULL,
		0xA2D1DB14F6117A8CULL,
		0x495A491504FECFA5ULL,
		0x5759A61D16D2C5C8ULL,
		0xFB824FADF955FC54ULL,
		0x65BE2EBF902F1495ULL,
		0x5D978D399BBF3CBEULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A26E93406A1DB6DULL,
		0x4CD2774B8DEE2829ULL,
		0x9CC5204D1BDF0D4BULL,
		0x214C9693396518E3ULL,
		0x1B4B547AB20C7CA2ULL,
		0x4CEC13E2E928A940ULL,
		0x358EB217A769BF85ULL,
		0x09920E4AE5FD4AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144DD2680D43B6DAULL,
		0x99A4EE971BDC5052ULL,
		0x398A409A37BE1A96ULL,
		0x42992D2672CA31C7ULL,
		0x3696A8F56418F944ULL,
		0x99D827C5D2515280ULL,
		0x6B1D642F4ED37F0AULL,
		0x13241C95CBFA95C6ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B04245B11BE2B91ULL,
		0x22FA7D8A8793BFB7ULL,
		0x822D4DD9E9FF15A7ULL,
		0x643CF5EFC368C9FBULL,
		0x0E46C40DDCFD6EC2ULL,
		0x941ADE5A5364BF56ULL,
		0xE8EC65C129F2DB91ULL,
		0x314BB1998566B467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x160848B6237C5722ULL,
		0x45F4FB150F277F6EULL,
		0x045A9BB3D3FE2B4EULL,
		0xC879EBDF86D193F7ULL,
		0x1C8D881BB9FADD84ULL,
		0x2835BCB4A6C97EACULL,
		0xD1D8CB8253E5B723ULL,
		0x629763330ACD68CFULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x792B234654C33354ULL,
		0xAEFC57987B44CF74ULL,
		0xBFA144BD8904A8AAULL,
		0x52FCF98FE2E71D03ULL,
		0x1C81B956200E33A3ULL,
		0x406F68EF47A5B591ULL,
		0x6C3BA93D3374166EULL,
		0x16090F6CB97C7292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF256468CA98666A8ULL,
		0x5DF8AF30F6899EE8ULL,
		0x7F42897B12095155ULL,
		0xA5F9F31FC5CE3A07ULL,
		0x390372AC401C6746ULL,
		0x80DED1DE8F4B6B22ULL,
		0xD877527A66E82CDCULL,
		0x2C121ED972F8E524ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C5CD55A0A387827ULL,
		0x91A546DFF29B0757ULL,
		0xC60F86D94A93E7A0ULL,
		0x9A19D3BECED658AFULL,
		0xB9E89011C4030BDAULL,
		0x46AFA30F3A313DCDULL,
		0x96780EFAA5795EECULL,
		0x322EA10C02041299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B9AAB41470F04EULL,
		0x234A8DBFE5360EAEULL,
		0x8C1F0DB29527CF41ULL,
		0x3433A77D9DACB15FULL,
		0x73D12023880617B5ULL,
		0x8D5F461E74627B9BULL,
		0x2CF01DF54AF2BDD8ULL,
		0x645D421804082533ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC69BAB8A894DCDCULL,
		0x15B2E1CEA6F41123ULL,
		0x141BCEA95651D797ULL,
		0xC22757AC87EA7834ULL,
		0x21D687BD88DA3E33ULL,
		0x455CAFF301CFAADFULL,
		0xA09AB504F9364F90ULL,
		0x360D54F75D248E74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D375715129B9B8ULL,
		0x2B65C39D4DE82247ULL,
		0x28379D52ACA3AF2EULL,
		0x844EAF590FD4F068ULL,
		0x43AD0F7B11B47C67ULL,
		0x8AB95FE6039F55BEULL,
		0x41356A09F26C9F20ULL,
		0x6C1AA9EEBA491CE9ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F3B42DFBCB3B549ULL,
		0xAD13486B591BAE7FULL,
		0xD8D20182A82A44AAULL,
		0xC383CA9D4C8501A2ULL,
		0xD70ADB0CEFBBC8A3ULL,
		0xC7EBDA133BD7E696ULL,
		0x5F57F956216958EAULL,
		0x36ECAA7F3E917A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7685BF79676A92ULL,
		0x5A2690D6B2375CFEULL,
		0xB1A4030550548955ULL,
		0x8707953A990A0345ULL,
		0xAE15B619DF779147ULL,
		0x8FD7B42677AFCD2DULL,
		0xBEAFF2AC42D2B1D5ULL,
		0x6DD954FE7D22F504ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AD63A03013ED942ULL,
		0x0C2548A8B5FC9318ULL,
		0x1A9C590EDD3AF711ULL,
		0x10850B00FA133352ULL,
		0x3E3E7777BCEA81FAULL,
		0x0DC859DDEA4399C5ULL,
		0x80633ADA9F5B3EC3ULL,
		0x27CB2E0FF13A2C24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15AC7406027DB284ULL,
		0x184A91516BF92631ULL,
		0x3538B21DBA75EE22ULL,
		0x210A1601F42666A4ULL,
		0x7C7CEEEF79D503F4ULL,
		0x1B90B3BBD487338AULL,
		0x00C675B53EB67D86ULL,
		0x4F965C1FE2745849ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29ADA5EAB8F8AE56ULL,
		0x6DB87DB8C1BFE557ULL,
		0x2EB4FB38D9501CA5ULL,
		0x4FEA1146FED3FFA8ULL,
		0xD88421D7D12683F5ULL,
		0x91A7F42E87D9AB21ULL,
		0x1399548079C8DE02ULL,
		0x3DD52FC57FC60D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x535B4BD571F15CACULL,
		0xDB70FB71837FCAAEULL,
		0x5D69F671B2A0394AULL,
		0x9FD4228DFDA7FF50ULL,
		0xB10843AFA24D07EAULL,
		0x234FE85D0FB35643ULL,
		0x2732A900F391BC05ULL,
		0x7BAA5F8AFF8C1B0AULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x537E1D5BA70F6034ULL,
		0xA188796D4D259E61ULL,
		0xEB9E137A36544555ULL,
		0xF9DCA6BBE7312A08ULL,
		0x3846B1A7805FA239ULL,
		0xF016FC9439948C01ULL,
		0xCCCE7005EAA5C914ULL,
		0x27EA8E1E6F38946EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FC3AB74E1EC068ULL,
		0x4310F2DA9A4B3CC2ULL,
		0xD73C26F46CA88AABULL,
		0xF3B94D77CE625411ULL,
		0x708D634F00BF4473ULL,
		0xE02DF92873291802ULL,
		0x999CE00BD54B9229ULL,
		0x4FD51C3CDE7128DDULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CE7F903274E3971ULL,
		0xFF779D9A2AEF1665ULL,
		0x71DCF337D24EA592ULL,
		0x0C73EACB56313BEDULL,
		0x45A182E61CAC54B5ULL,
		0x41796071CD996CC1ULL,
		0xD888578FBABF08B8ULL,
		0x153310C0601E8601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19CFF2064E9C72E2ULL,
		0xFEEF3B3455DE2CCBULL,
		0xE3B9E66FA49D4B25ULL,
		0x18E7D596AC6277DAULL,
		0x8B4305CC3958A96AULL,
		0x82F2C0E39B32D982ULL,
		0xB110AF1F757E1170ULL,
		0x2A662180C03D0C03ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B9CB8E3F78B3675ULL,
		0x85FE8302FF5419EAULL,
		0xB197D0F9E708DC6CULL,
		0xE944573F23DDB58EULL,
		0xB1BABAAFC4A5DA16ULL,
		0x0AD2E949914061A4ULL,
		0x03D91398FB37A804ULL,
		0x09425018436411A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x173971C7EF166CEAULL,
		0x0BFD0605FEA833D5ULL,
		0x632FA1F3CE11B8D9ULL,
		0xD288AE7E47BB6B1DULL,
		0x6375755F894BB42DULL,
		0x15A5D2932280C349ULL,
		0x07B22731F66F5008ULL,
		0x1284A03086C82340ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74BDB19FCABA8660ULL,
		0xCBD9F2785ABA64A0ULL,
		0xEBDEC4D918F23BF4ULL,
		0xB593DD77F2401721ULL,
		0x178CB0C6E68F77B6ULL,
		0xF252545EBF75A685ULL,
		0x7F511CC7643495A7ULL,
		0x2647AA60CE4586ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97B633F95750CC0ULL,
		0x97B3E4F0B574C940ULL,
		0xD7BD89B231E477E9ULL,
		0x6B27BAEFE4802E43ULL,
		0x2F19618DCD1EEF6DULL,
		0xE4A4A8BD7EEB4D0AULL,
		0xFEA2398EC8692B4FULL,
		0x4C8F54C19C8B0D5AULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x557E6A93E0E030A8ULL,
		0xDDA081602A8C4602ULL,
		0x9F201C0CD37D911AULL,
		0x765262809B2B84B6ULL,
		0x1489CCF84F56DC31ULL,
		0x39E91AC506AF4D5DULL,
		0xDDED960B4B36CAA5ULL,
		0x18114AE737ED1A64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAFCD527C1C06150ULL,
		0xBB4102C055188C04ULL,
		0x3E403819A6FB2235ULL,
		0xECA4C5013657096DULL,
		0x291399F09EADB862ULL,
		0x73D2358A0D5E9ABAULL,
		0xBBDB2C16966D954AULL,
		0x302295CE6FDA34C9ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E2258E58989F5C5ULL,
		0x62FC3E8F961F39F9ULL,
		0x52DCE3288BC9CF1AULL,
		0xB580A276AD03AC9FULL,
		0xF1D726B98676D665ULL,
		0x3AFF0E646CDF44C6ULL,
		0xEDF8C09D1FFE8B12ULL,
		0x18BBB7A83DBF9F3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC44B1CB1313EB8AULL,
		0xC5F87D1F2C3E73F2ULL,
		0xA5B9C65117939E34ULL,
		0x6B0144ED5A07593EULL,
		0xE3AE4D730CEDACCBULL,
		0x75FE1CC8D9BE898DULL,
		0xDBF1813A3FFD1624ULL,
		0x31776F507B7F3E7DULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE244210D7F7AB2EULL,
		0xA85C090ACD370E89ULL,
		0x32E4545ABE9F1A8BULL,
		0x116EF84B182B2CF1ULL,
		0x347B58B806D34AE8ULL,
		0xE879432DAA06BDB5ULL,
		0xC70FB0C5711978DCULL,
		0x3CC6DF844CE98B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC488421AFEF565CULL,
		0x50B812159A6E1D13ULL,
		0x65C8A8B57D3E3517ULL,
		0x22DDF096305659E2ULL,
		0x68F6B1700DA695D0ULL,
		0xD0F2865B540D7B6AULL,
		0x8E1F618AE232F1B9ULL,
		0x798DBF0899D31711ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB156C39795C562BDULL,
		0x9CFC1FDEA73B17DCULL,
		0x18FEB67F94191861ULL,
		0xC3A32B303D825D9DULL,
		0x92F9C3EC400F9566ULL,
		0xF2F36F4AE9E192CFULL,
		0x34BCD3351468F22AULL,
		0x1B9135B6063C2997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62AD872F2B8AC57AULL,
		0x39F83FBD4E762FB9ULL,
		0x31FD6CFF283230C3ULL,
		0x874656607B04BB3AULL,
		0x25F387D8801F2ACDULL,
		0xE5E6DE95D3C3259FULL,
		0x6979A66A28D1E455ULL,
		0x37226B6C0C78532EULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F49CBC572B3BC67ULL,
		0x093C02249A8471BBULL,
		0x465E8534C7639627ULL,
		0xD498A30B5EED2ECBULL,
		0x9583B033488A4188ULL,
		0xCF2FB2630C02BF92ULL,
		0xA194CABF8669C026ULL,
		0x2C4266E86F39B51DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E93978AE56778CEULL,
		0x127804493508E377ULL,
		0x8CBD0A698EC72C4EULL,
		0xA9314616BDDA5D96ULL,
		0x2B07606691148311ULL,
		0x9E5F64C618057F25ULL,
		0x4329957F0CD3804DULL,
		0x5884CDD0DE736A3BULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74CD072CF54A0AB4ULL,
		0xACDCA7827CBE380EULL,
		0xE8743D1420BB4C4DULL,
		0x156361D47D02EB6FULL,
		0xF660FEEF1A8AD06CULL,
		0xC9B9136C1345A488ULL,
		0x6181C5B8F3262BA8ULL,
		0x07E8EB92E9D18C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99A0E59EA941568ULL,
		0x59B94F04F97C701CULL,
		0xD0E87A284176989BULL,
		0x2AC6C3A8FA05D6DFULL,
		0xECC1FDDE3515A0D8ULL,
		0x937226D8268B4911ULL,
		0xC3038B71E64C5751ULL,
		0x0FD1D725D3A31870ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43892EF1F7FE3734ULL,
		0xE5367E53E628253BULL,
		0x46923735E54C3F05ULL,
		0x14BFFA8B7F5FAA8AULL,
		0x771ADA2E7483F06DULL,
		0x31E76E0E0BA74E5DULL,
		0x2D72EBB2F8D4E7F0ULL,
		0x13390B6681493F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87125DE3EFFC6E68ULL,
		0xCA6CFCA7CC504A76ULL,
		0x8D246E6BCA987E0BULL,
		0x297FF516FEBF5514ULL,
		0xEE35B45CE907E0DAULL,
		0x63CEDC1C174E9CBAULL,
		0x5AE5D765F1A9CFE0ULL,
		0x267216CD02927E00ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD32DDD38514D8B74ULL,
		0x00BA58A4322B3090ULL,
		0x09634AE9AD86EAB0ULL,
		0x876AD2FAD6114A15ULL,
		0x7CF1EA51052E1042ULL,
		0x704B9DAF295792EBULL,
		0x9860D0DDE8749E07ULL,
		0x3FDF7A4F9CD58C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA65BBA70A29B16E8ULL,
		0x0174B14864566121ULL,
		0x12C695D35B0DD560ULL,
		0x0ED5A5F5AC22942AULL,
		0xF9E3D4A20A5C2085ULL,
		0xE0973B5E52AF25D6ULL,
		0x30C1A1BBD0E93C0EULL,
		0x7FBEF49F39AB1829ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE309CFA47559F46DULL,
		0x5444693EDB2F859DULL,
		0x17F18507CB3B20B3ULL,
		0x1769D266B578B06CULL,
		0x149536D294CD8FD0ULL,
		0xC0F3BA6AF8ADF27CULL,
		0x8AC997980EF321BBULL,
		0x3D2D81F0CC6594C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6139F48EAB3E8DAULL,
		0xA888D27DB65F0B3BULL,
		0x2FE30A0F96764166ULL,
		0x2ED3A4CD6AF160D8ULL,
		0x292A6DA5299B1FA0ULL,
		0x81E774D5F15BE4F8ULL,
		0x15932F301DE64377ULL,
		0x7A5B03E198CB2983ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97A3ABA8580BC7A8ULL,
		0x2C532E893A19E6EDULL,
		0x2A7668BF3D447A5CULL,
		0x0884E3CDB062EB51ULL,
		0x2B3EB44F604BFCE5ULL,
		0x96E165731A406ED3ULL,
		0x23CCFC32F7DF3707ULL,
		0x0405C84E8709BEB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F475750B0178F50ULL,
		0x58A65D127433CDDBULL,
		0x54ECD17E7A88F4B8ULL,
		0x1109C79B60C5D6A2ULL,
		0x567D689EC097F9CAULL,
		0x2DC2CAE63480DDA6ULL,
		0x4799F865EFBE6E0FULL,
		0x080B909D0E137D6CULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FD6BBB93DF39AA0ULL,
		0x1172B322A8E93B79ULL,
		0xFB5867319C93E401ULL,
		0xEB60B5AF00DD255EULL,
		0x88A71287F514596AULL,
		0xEEC7E4EE43EDF6FAULL,
		0x8E7075E3F373C585ULL,
		0x27BE7170EC0E1175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FAD77727BE73540ULL,
		0x22E5664551D276F2ULL,
		0xF6B0CE633927C802ULL,
		0xD6C16B5E01BA4ABDULL,
		0x114E250FEA28B2D5ULL,
		0xDD8FC9DC87DBEDF5ULL,
		0x1CE0EBC7E6E78B0BULL,
		0x4F7CE2E1D81C22EBULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A3736EAE4102E08ULL,
		0x8ADD8E3E22777A2CULL,
		0x8DF819F174086FA9ULL,
		0xEF02BD0EC4A3BC35ULL,
		0x5230C42791FDDB8AULL,
		0x2A0B9A2DA3B75770ULL,
		0x89E04ED14609AC37ULL,
		0x02ADFEAB32E0E5BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46E6DD5C8205C10ULL,
		0x15BB1C7C44EEF458ULL,
		0x1BF033E2E810DF53ULL,
		0xDE057A1D8947786BULL,
		0xA461884F23FBB715ULL,
		0x5417345B476EAEE0ULL,
		0x13C09DA28C13586EULL,
		0x055BFD5665C1CB77ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FC9492D3D91492AULL,
		0xB59698B53043BD0FULL,
		0x70B5631E40061F53ULL,
		0x7EC07D04340AFC3AULL,
		0x1FF0B20E0845BB24ULL,
		0xFDA1105F54A3F850ULL,
		0x921E5655DB1015EFULL,
		0x11A1B23587A4FB24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF92925A7B229254ULL,
		0x6B2D316A60877A1EULL,
		0xE16AC63C800C3EA7ULL,
		0xFD80FA086815F874ULL,
		0x3FE1641C108B7648ULL,
		0xFB4220BEA947F0A0ULL,
		0x243CACABB6202BDFULL,
		0x2343646B0F49F649ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD98226FB837397AULL,
		0x3A9859C8C0CC33FCULL,
		0xDCA464B969EF892FULL,
		0x6FA5A8500A759F6DULL,
		0xAFD2B5455A77F4E8ULL,
		0x29486C053E1DAB0EULL,
		0xD527E8CD73353EC1ULL,
		0x18D506CDF05AE654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB3044DF706E72F4ULL,
		0x7530B391819867F9ULL,
		0xB948C972D3DF125EULL,
		0xDF4B50A014EB3EDBULL,
		0x5FA56A8AB4EFE9D0ULL,
		0x5290D80A7C3B561DULL,
		0xAA4FD19AE66A7D82ULL,
		0x31AA0D9BE0B5CCA9ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB145DF956C7C2D28ULL,
		0x56E601F49E08FE57ULL,
		0xC68979A22124FA9FULL,
		0xADB4CCDBC651EF4AULL,
		0x7AFAA1B1561E92E1ULL,
		0xCC1674C2A416BEC2ULL,
		0xEC8D26D82488B417ULL,
		0x209986929ADB3139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x628BBF2AD8F85A50ULL,
		0xADCC03E93C11FCAFULL,
		0x8D12F3444249F53EULL,
		0x5B6999B78CA3DE95ULL,
		0xF5F54362AC3D25C3ULL,
		0x982CE985482D7D84ULL,
		0xD91A4DB04911682FULL,
		0x41330D2535B66273ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD8D4D32A0055BD2ULL,
		0xDAE11AD1170BF11FULL,
		0x5FDE7F994FA85F38ULL,
		0x0E814CB4585E12AAULL,
		0x01585B035B4DAD7DULL,
		0xC8F5C5EB6E098BB8ULL,
		0x530E580CDF4365A7ULL,
		0x2425D30E719FA68EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B1A9A65400AB7A4ULL,
		0xB5C235A22E17E23FULL,
		0xBFBCFF329F50BE71ULL,
		0x1D029968B0BC2554ULL,
		0x02B0B606B69B5AFAULL,
		0x91EB8BD6DC131770ULL,
		0xA61CB019BE86CB4FULL,
		0x484BA61CE33F4D1CULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE99154F74475798ULL,
		0xAE45F03874C7136CULL,
		0x52D457189608573DULL,
		0xA8D8673F70F717E1ULL,
		0xBE3C138BDB0B9CE5ULL,
		0x9944D826317BEB8AULL,
		0x48BC34F1CB1E6283ULL,
		0x15CA46096170948AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D322A9EE88EAF30ULL,
		0x5C8BE070E98E26D9ULL,
		0xA5A8AE312C10AE7BULL,
		0x51B0CE7EE1EE2FC2ULL,
		0x7C782717B61739CBULL,
		0x3289B04C62F7D715ULL,
		0x917869E3963CC507ULL,
		0x2B948C12C2E12914ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1B340B417D32BA1ULL,
		0x310F1880441300C7ULL,
		0xDE865DB327E33078ULL,
		0xBE1293839ABB0DF7ULL,
		0x3372B4A27F43EAADULL,
		0x58DE40FF05904B62ULL,
		0x0D0CA9E9D7956B21ULL,
		0x0E6FEA30123F1A2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36681682FA65742ULL,
		0x621E31008826018FULL,
		0xBD0CBB664FC660F0ULL,
		0x7C25270735761BEFULL,
		0x66E56944FE87D55BULL,
		0xB1BC81FE0B2096C4ULL,
		0x1A1953D3AF2AD642ULL,
		0x1CDFD460247E345EULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8616E506E219FF0BULL,
		0x0B4CB72ABC34B6A0ULL,
		0x20397A1EA9918A5BULL,
		0xD4315ED5C9EF1FB9ULL,
		0x1F8FC615CDC1CB00ULL,
		0xE9782DF0A2BDAB5EULL,
		0xCDAF7A71E314323CULL,
		0x3F60DBDB9B6EA073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2DCA0DC433FE16ULL,
		0x16996E5578696D41ULL,
		0x4072F43D532314B6ULL,
		0xA862BDAB93DE3F72ULL,
		0x3F1F8C2B9B839601ULL,
		0xD2F05BE1457B56BCULL,
		0x9B5EF4E3C6286479ULL,
		0x7EC1B7B736DD40E7ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A0EF225D39715ECULL,
		0x943A1211E456E50DULL,
		0x205B58C8A9B02ACFULL,
		0x35192EB7014850F3ULL,
		0x436A16CAC32566F2ULL,
		0xEDC29A04727570DCULL,
		0x95ED5896C7926045ULL,
		0x22E1C97A8A8E3581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41DE44BA72E2BD8ULL,
		0x28742423C8ADCA1AULL,
		0x40B6B1915360559FULL,
		0x6A325D6E0290A1E6ULL,
		0x86D42D95864ACDE4ULL,
		0xDB853408E4EAE1B8ULL,
		0x2BDAB12D8F24C08BULL,
		0x45C392F5151C6B03ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75F563AB05F69C0AULL,
		0x0AEE2113909854EDULL,
		0xA1B72E98B2442B70ULL,
		0xA9193CE224F537EDULL,
		0x5CAA4454179B9BEBULL,
		0x4BE1FD0F635AFF8BULL,
		0xF570040EA18C2825ULL,
		0x1C9AD81DAD6C55BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBEAC7560BED3814ULL,
		0x15DC42272130A9DAULL,
		0x436E5D31648856E0ULL,
		0x523279C449EA6FDBULL,
		0xB95488A82F3737D7ULL,
		0x97C3FA1EC6B5FF16ULL,
		0xEAE0081D4318504AULL,
		0x3935B03B5AD8AB7BULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE512E027F31DB9F1ULL,
		0xD29004858833AD8CULL,
		0xE6BF35963B83DBC9ULL,
		0x5881C171092D24A8ULL,
		0x401CD6382D394F38ULL,
		0xDDE0399328F2F4BBULL,
		0x02E583BF39B01628ULL,
		0x36A1AECCE998514FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA25C04FE63B73E2ULL,
		0xA520090B10675B19ULL,
		0xCD7E6B2C7707B793ULL,
		0xB10382E2125A4951ULL,
		0x8039AC705A729E70ULL,
		0xBBC0732651E5E976ULL,
		0x05CB077E73602C51ULL,
		0x6D435D99D330A29EULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0205D795D1D41280ULL,
		0xB1F3A23115ABD5A0ULL,
		0xB197BFB31EC77A71ULL,
		0x520E0A9885D8EA65ULL,
		0x3B3593F26D3A57C7ULL,
		0x8A4C39A0B2772A1FULL,
		0x63638290B289E28FULL,
		0x3E3EDDDCC8016DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040BAF2BA3A82500ULL,
		0x63E744622B57AB40ULL,
		0x632F7F663D8EF4E3ULL,
		0xA41C15310BB1D4CBULL,
		0x766B27E4DA74AF8EULL,
		0x1498734164EE543EULL,
		0xC6C705216513C51FULL,
		0x7C7DBBB99002DB5AULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD715A8AF0F99A411ULL,
		0x44FFE26B43D73A66ULL,
		0x7082E104ECFBE602ULL,
		0x8393D345E1346DE2ULL,
		0x0001EAC1FB98F33AULL,
		0x909471A47A4715D9ULL,
		0xA6DB3A7D162ADCCFULL,
		0x0DACCEDAB61CFF50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2B515E1F334822ULL,
		0x89FFC4D687AE74CDULL,
		0xE105C209D9F7CC04ULL,
		0x0727A68BC268DBC4ULL,
		0x0003D583F731E675ULL,
		0x2128E348F48E2BB2ULL,
		0x4DB674FA2C55B99FULL,
		0x1B599DB56C39FEA1ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96EEAAC735A5FB09ULL,
		0xFE06BC551B4A33D4ULL,
		0x87F9E62E54F4ABA5ULL,
		0xB79266E6097D7D6EULL,
		0xF40C999F3AD9DACDULL,
		0xB854CC7D8D7F997BULL,
		0x1D2BBEF5A68350E0ULL,
		0x2F30AF013AE10431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDD558E6B4BF612ULL,
		0xFC0D78AA369467A9ULL,
		0x0FF3CC5CA9E9574BULL,
		0x6F24CDCC12FAFADDULL,
		0xE819333E75B3B59BULL,
		0x70A998FB1AFF32F7ULL,
		0x3A577DEB4D06A1C1ULL,
		0x5E615E0275C20862ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x674FD282BCFD452CULL,
		0xDBB81AE5358BEC20ULL,
		0xBBB42D5855081554ULL,
		0xE628774729091086ULL,
		0xEE3C6656283F72F4ULL,
		0x29FC07B1342FBFA2ULL,
		0x80334EBC9E5512EFULL,
		0x2A9DC0615FF11ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9FA50579FA8A58ULL,
		0xB77035CA6B17D840ULL,
		0x77685AB0AA102AA9ULL,
		0xCC50EE8E5212210DULL,
		0xDC78CCAC507EE5E9ULL,
		0x53F80F62685F7F45ULL,
		0x00669D793CAA25DEULL,
		0x553B80C2BFE23DADULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A1C80200BCD5046ULL,
		0x849B82E33899608DULL,
		0x5FF57404C6E4AEC7ULL,
		0xB878599AE57D8756ULL,
		0xB8EFFF83B5E7B2B1ULL,
		0x6FB54F3F7BC40CDFULL,
		0x4BEE611793B2B1A3ULL,
		0x1A73040C3CDAB69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34390040179AA08CULL,
		0x093705C67132C11BULL,
		0xBFEAE8098DC95D8FULL,
		0x70F0B335CAFB0EACULL,
		0x71DFFF076BCF6563ULL,
		0xDF6A9E7EF78819BFULL,
		0x97DCC22F27656346ULL,
		0x34E6081879B56D38ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D9D94838405BE04ULL,
		0xA8F000DCE522EFC2ULL,
		0x1E02A39215601BA6ULL,
		0x1D76411018B3FB6BULL,
		0x1B899217C2A9E26EULL,
		0x96BE3935FB684C06ULL,
		0xF2C644F6AB25638BULL,
		0x33055EDDF3186E4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3B2907080B7C08ULL,
		0x51E001B9CA45DF84ULL,
		0x3C0547242AC0374DULL,
		0x3AEC82203167F6D6ULL,
		0x3713242F8553C4DCULL,
		0x2D7C726BF6D0980CULL,
		0xE58C89ED564AC717ULL,
		0x660ABDBBE630DC99ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E6D2E30344E3213ULL,
		0xC3A2307AE42B983BULL,
		0xEE0123CC7A92DA00ULL,
		0xF6653EF1E0F26201ULL,
		0x86A8EB73B32F6205ULL,
		0x85E942E32F9911B7ULL,
		0xEED77E2449752B66ULL,
		0x18BFFEBCAAB7AAF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CDA5C60689C6426ULL,
		0x874460F5C8573076ULL,
		0xDC024798F525B401ULL,
		0xECCA7DE3C1E4C403ULL,
		0x0D51D6E7665EC40BULL,
		0x0BD285C65F32236FULL,
		0xDDAEFC4892EA56CDULL,
		0x317FFD79556F55EBULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CFFF86BC60426B5ULL,
		0x415AEB79E5C4C13AULL,
		0x8A842821815286EFULL,
		0xE115014799A9309BULL,
		0x7BA8D46BEC6E4487ULL,
		0x80999A1180863B06ULL,
		0x2B84A5FD01267B8CULL,
		0x3ABCA2259999A8EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9FFF0D78C084D6AULL,
		0x82B5D6F3CB898274ULL,
		0x1508504302A50DDEULL,
		0xC22A028F33526137ULL,
		0xF751A8D7D8DC890FULL,
		0x01333423010C760CULL,
		0x57094BFA024CF719ULL,
		0x7579444B333351DAULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3EB9EE2910930EBULL,
		0x6BB7EBE6AFB70A60ULL,
		0x7C7A604E2B7ABB1AULL,
		0x64F7C26F9A7D4BAAULL,
		0x35683A2F22C5F9A0ULL,
		0x35DB7008AA8142B2ULL,
		0xF07DD6C7840351B6ULL,
		0x1652084A8C3B767EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D73DC5221261D6ULL,
		0xD76FD7CD5F6E14C1ULL,
		0xF8F4C09C56F57634ULL,
		0xC9EF84DF34FA9754ULL,
		0x6AD0745E458BF340ULL,
		0x6BB6E01155028564ULL,
		0xE0FBAD8F0806A36CULL,
		0x2CA410951876ECFDULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85E24128B0D8A8B9ULL,
		0xFC9BD0B2ADAFA91FULL,
		0x0192998961FA1DF8ULL,
		0x0C8AC0A9950A3E1AULL,
		0x6950181259689EE5ULL,
		0x276D91082C301410ULL,
		0x8C3548D5FA4A55B4ULL,
		0x201DE2AA97B8950FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BC4825161B15172ULL,
		0xF937A1655B5F523FULL,
		0x03253312C3F43BF1ULL,
		0x191581532A147C34ULL,
		0xD2A03024B2D13DCAULL,
		0x4EDB221058602820ULL,
		0x186A91ABF494AB68ULL,
		0x403BC5552F712A1FULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB20CC27F81174027ULL,
		0xFFAEE736EA609128ULL,
		0xC9162269408AA2FAULL,
		0x9172D9CCFC224A8FULL,
		0x2C793F640D7F37A8ULL,
		0xCD594F7EC35EF6BAULL,
		0x41AC6089E8FE0C48ULL,
		0x35880CAD9BD0EF1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x641984FF022E804EULL,
		0xFF5DCE6DD4C12251ULL,
		0x922C44D2811545F5ULL,
		0x22E5B399F844951FULL,
		0x58F27EC81AFE6F51ULL,
		0x9AB29EFD86BDED74ULL,
		0x8358C113D1FC1891ULL,
		0x6B10195B37A1DE34ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D743E4FF0A481A1ULL,
		0x1A78A73163347018ULL,
		0xE6A016DB8AED74C0ULL,
		0x4EC0A13A7A6AC655ULL,
		0x86D4D5FE7AEA4E18ULL,
		0x81884ADAE58E3E05ULL,
		0xC1204CBC32366235ULL,
		0x0F1474F21A0B958DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE87C9FE1490342ULL,
		0x34F14E62C668E030ULL,
		0xCD402DB715DAE980ULL,
		0x9D814274F4D58CABULL,
		0x0DA9ABFCF5D49C30ULL,
		0x031095B5CB1C7C0BULL,
		0x82409978646CC46BULL,
		0x1E28E9E434172B1BULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AED9705C5A60E4DULL,
		0x6C708F5347A9C543ULL,
		0xD6DB753A2BB20930ULL,
		0xDED5D3C3AAAE255DULL,
		0x2E5EE5EC0C17A6C2ULL,
		0x9BDC118B44BC0B21ULL,
		0x79A338464B37F000ULL,
		0x389AC52B03D46B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35DB2E0B8B4C1C9AULL,
		0xD8E11EA68F538A87ULL,
		0xADB6EA7457641260ULL,
		0xBDABA787555C4ABBULL,
		0x5CBDCBD8182F4D85ULL,
		0x37B8231689781642ULL,
		0xF346708C966FE001ULL,
		0x71358A5607A8D6D6ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD64310ABC0EBB9E3ULL,
		0xCA8A76BD2971EABEULL,
		0x3B05ACEA97E5785DULL,
		0xD1DAFC81D9FAAE70ULL,
		0xDAC64860EAD4D19EULL,
		0x7676ED75A7169A9CULL,
		0x2A7CDBC8BF3950A3ULL,
		0x097BC87B61837D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC86215781D773C6ULL,
		0x9514ED7A52E3D57DULL,
		0x760B59D52FCAF0BBULL,
		0xA3B5F903B3F55CE0ULL,
		0xB58C90C1D5A9A33DULL,
		0xECEDDAEB4E2D3539ULL,
		0x54F9B7917E72A146ULL,
		0x12F790F6C306FA86ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D8716EEC3605243ULL,
		0xC9433C6570CC7141ULL,
		0x79A961D098D1D680ULL,
		0x086BE6DCC01D1F61ULL,
		0x3EF8F7F79E81C978ULL,
		0x872F0EC0FDFBB0B2ULL,
		0xF804A349FE40DB39ULL,
		0x308D3AF8652E0520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0E2DDD86C0A486ULL,
		0x928678CAE198E282ULL,
		0xF352C3A131A3AD01ULL,
		0x10D7CDB9803A3EC2ULL,
		0x7DF1EFEF3D0392F0ULL,
		0x0E5E1D81FBF76164ULL,
		0xF0094693FC81B673ULL,
		0x611A75F0CA5C0A41ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BF67B8F98192505ULL,
		0x2FC36219E8B11F1FULL,
		0x9D987A40465157B0ULL,
		0x77CE5890530E88A0ULL,
		0xD1B93E3B70DFBA33ULL,
		0x5C8301D87265C786ULL,
		0xE3E94F4EC433DEB3ULL,
		0x360C5479B31AB597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7ECF71F30324A0AULL,
		0x5F86C433D1623E3EULL,
		0x3B30F4808CA2AF60ULL,
		0xEF9CB120A61D1141ULL,
		0xA3727C76E1BF7466ULL,
		0xB90603B0E4CB8F0DULL,
		0xC7D29E9D8867BD66ULL,
		0x6C18A8F366356B2FULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4298FAF6029BE935ULL,
		0xE1F975B30416F605ULL,
		0xCB4C5E4DECFAC2D5ULL,
		0x333C301DC2B4BAF9ULL,
		0xE9E9D5E79999072DULL,
		0x9F919D4A24CE939DULL,
		0xEAE7C24A3DF84EABULL,
		0x0AD4A1A54E48C718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8531F5EC0537D26AULL,
		0xC3F2EB66082DEC0AULL,
		0x9698BC9BD9F585ABULL,
		0x6678603B856975F3ULL,
		0xD3D3ABCF33320E5AULL,
		0x3F233A94499D273BULL,
		0xD5CF84947BF09D57ULL,
		0x15A9434A9C918E31ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD502C4903CA02D38ULL,
		0xCCD50FCD1D32CF7CULL,
		0xFFB312905BE4B14AULL,
		0xF6BFF602CD0665C0ULL,
		0x24B98811DDBEA4B7ULL,
		0xAA89F324012E1C50ULL,
		0x7723B4274D791776ULL,
		0x2F302E16092802CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA05892079405A70ULL,
		0x99AA1F9A3A659EF9ULL,
		0xFF662520B7C96295ULL,
		0xED7FEC059A0CCB81ULL,
		0x49731023BB7D496FULL,
		0x5513E648025C38A0ULL,
		0xEE47684E9AF22EEDULL,
		0x5E605C2C12500594ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3A667353E34EE82ULL,
		0xC4B438257E9AFEEFULL,
		0xD5DDCDF3B3B0610DULL,
		0x775B855443AB646DULL,
		0xABAC675A96322F5AULL,
		0xB393EC1A577C23BFULL,
		0x10383F01F949CADBULL,
		0x1D21D4F19A6E3505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x474CCE6A7C69DD04ULL,
		0x8968704AFD35FDDFULL,
		0xABBB9BE76760C21BULL,
		0xEEB70AA88756C8DBULL,
		0x5758CEB52C645EB4ULL,
		0x6727D834AEF8477FULL,
		0x20707E03F29395B7ULL,
		0x3A43A9E334DC6A0AULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8FA7C76E355E4FCULL,
		0xB1CB60E185FF5FF1ULL,
		0xC546BB2FF89D8172ULL,
		0xFC9ED177EEF16B54ULL,
		0x6E1DE05AF6D65AF4ULL,
		0xCDDEA237BA936DF9ULL,
		0x26DD4EFBDFE7220FULL,
		0x377BAB3723CEA0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51F4F8EDC6ABC9F8ULL,
		0x6396C1C30BFEBFE3ULL,
		0x8A8D765FF13B02E5ULL,
		0xF93DA2EFDDE2D6A9ULL,
		0xDC3BC0B5EDACB5E9ULL,
		0x9BBD446F7526DBF2ULL,
		0x4DBA9DF7BFCE441FULL,
		0x6EF7566E479D4184ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1D4283F6038B261ULL,
		0x1919DE3584416D53ULL,
		0xB157B95A1D2DBB89ULL,
		0x09B3A8739ECDDECDULL,
		0x5D4594F739966449ULL,
		0xABB086F335F1DA6FULL,
		0x1F16D8D1B1175858ULL,
		0x08793C799BF973C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A8507EC07164C2ULL,
		0x3233BC6B0882DAA7ULL,
		0x62AF72B43A5B7712ULL,
		0x136750E73D9BBD9BULL,
		0xBA8B29EE732CC892ULL,
		0x57610DE66BE3B4DEULL,
		0x3E2DB1A3622EB0B1ULL,
		0x10F278F337F2E786ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97A1CABD5E8B56B1ULL,
		0x3AE742FB90AE2BD9ULL,
		0x7EBC275C328F782FULL,
		0xB8681CBDD2B0789CULL,
		0x827E4CA716266429ULL,
		0x945FC755088D46BCULL,
		0x58C31BF7D7B96FCBULL,
		0x265C8FFA2A5D3391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F43957ABD16AD62ULL,
		0x75CE85F7215C57B3ULL,
		0xFD784EB8651EF05EULL,
		0x70D0397BA560F138ULL,
		0x04FC994E2C4CC853ULL,
		0x28BF8EAA111A8D79ULL,
		0xB18637EFAF72DF97ULL,
		0x4CB91FF454BA6722ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30C12C227C22CD92ULL,
		0x230353D1FA9BC796ULL,
		0xF6409A8347C1DC2CULL,
		0xD5610B32FCA75D64ULL,
		0x05EB88232B2F69E0ULL,
		0x0C5954BE2E6B00C9ULL,
		0x37DF7A8AEDAE96F2ULL,
		0x3C059645FB170A62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61825844F8459B24ULL,
		0x4606A7A3F5378F2CULL,
		0xEC8135068F83B858ULL,
		0xAAC21665F94EBAC9ULL,
		0x0BD71046565ED3C1ULL,
		0x18B2A97C5CD60192ULL,
		0x6FBEF515DB5D2DE4ULL,
		0x780B2C8BF62E14C4ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x149E87069EEF76AAULL,
		0x21A44F0499067736ULL,
		0xE0BD15B53C077859ULL,
		0xAF18A9A6184F7F55ULL,
		0x9076B41F29085D12ULL,
		0x9B1993DB55BC5A1FULL,
		0x93DAE0C36C2850BBULL,
		0x078007EF77BA6724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x293D0E0D3DDEED54ULL,
		0x43489E09320CEE6CULL,
		0xC17A2B6A780EF0B2ULL,
		0x5E31534C309EFEABULL,
		0x20ED683E5210BA25ULL,
		0x363327B6AB78B43FULL,
		0x27B5C186D850A177ULL,
		0x0F000FDEEF74CE49ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEFCC09AB96238F0ULL,
		0x7C404BDA04C0A743ULL,
		0x16C180C1230B4E26ULL,
		0x1C1A0853683C260BULL,
		0x51C955639247B74BULL,
		0x1DBEB05C344DA854ULL,
		0x0D99AD928CC7A820ULL,
		0x10AADAF2E9EF9523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDF9813572C471E0ULL,
		0xF88097B409814E87ULL,
		0x2D83018246169C4CULL,
		0x383410A6D0784C16ULL,
		0xA392AAC7248F6E96ULL,
		0x3B7D60B8689B50A8ULL,
		0x1B335B25198F5040ULL,
		0x2155B5E5D3DF2A46ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11A241AD8259F247ULL,
		0xA233F4330BD6C754ULL,
		0xCCEE59F7155F39B1ULL,
		0xC0C9ABF8E4C91E43ULL,
		0x5E5B1CB25B87FDA9ULL,
		0xE142D831755E7F76ULL,
		0x25A8A9E0024FB384ULL,
		0x01D90E9FEA2074C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2344835B04B3E48EULL,
		0x4467E86617AD8EA8ULL,
		0x99DCB3EE2ABE7363ULL,
		0x819357F1C9923C87ULL,
		0xBCB63964B70FFB53ULL,
		0xC285B062EABCFEECULL,
		0x4B5153C0049F6709ULL,
		0x03B21D3FD440E98EULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x936D7B21F9CC40EEULL,
		0xB50549A37F42C1CBULL,
		0x7230DBC17E9942C0ULL,
		0x73DD25D970AC54DBULL,
		0x9C5BF9481BDE393BULL,
		0x83D1E902F242BD0AULL,
		0x148858DF9037751FULL,
		0x3E14D8CDC1DD2D9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26DAF643F39881DCULL,
		0x6A0A9346FE858397ULL,
		0xE461B782FD328581ULL,
		0xE7BA4BB2E158A9B6ULL,
		0x38B7F29037BC7276ULL,
		0x07A3D205E4857A15ULL,
		0x2910B1BF206EEA3FULL,
		0x7C29B19B83BA5B38ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BF89901E9EB5172ULL,
		0x429CC4E5A3A8D7A8ULL,
		0x9D072D57949C752FULL,
		0x49B98154F8D29519ULL,
		0xB72C6685D930F0F9ULL,
		0x095CB4D931C98BA3ULL,
		0x2D4165FB56B37D82ULL,
		0x2A8E07D9C0A0F9B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F13203D3D6A2E4ULL,
		0x853989CB4751AF50ULL,
		0x3A0E5AAF2938EA5EULL,
		0x937302A9F1A52A33ULL,
		0x6E58CD0BB261E1F2ULL,
		0x12B969B263931747ULL,
		0x5A82CBF6AD66FB04ULL,
		0x551C0FB38141F36EULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x919321167E29B267ULL,
		0xF2146F8B2F83F571ULL,
		0xB02AE2B6871838CEULL,
		0xA4307B021D8CAEF8ULL,
		0x46EE111A91E93B55ULL,
		0xFA15968ECEA716F8ULL,
		0xB3766219A432EF51ULL,
		0x2E765E1E26590FD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2326422CFC5364CEULL,
		0xE428DF165F07EAE3ULL,
		0x6055C56D0E30719DULL,
		0x4860F6043B195DF1ULL,
		0x8DDC223523D276ABULL,
		0xF42B2D1D9D4E2DF0ULL,
		0x66ECC4334865DEA3ULL,
		0x5CECBC3C4CB21FA9ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00FAA11A6A02EE2EULL,
		0x28438F7357F43533ULL,
		0x4B00036FADE29953ULL,
		0x42DB320148866792ULL,
		0xB77ECE49B0345752ULL,
		0x4C98193E2049B72AULL,
		0xC03B427E65CDCB86ULL,
		0x3358BFF5C167375BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F54234D405DC5CULL,
		0x50871EE6AFE86A66ULL,
		0x960006DF5BC532A6ULL,
		0x85B66402910CCF24ULL,
		0x6EFD9C936068AEA4ULL,
		0x9930327C40936E55ULL,
		0x807684FCCB9B970CULL,
		0x66B17FEB82CE6EB7ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3822CDFD6AAFD93ULL,
		0xB7568DA53E241A55ULL,
		0x95A5B5D8F7714F0DULL,
		0x406425886827C258ULL,
		0x83BA78BE5B23394EULL,
		0xAC029A4D67D523CCULL,
		0xD511D24B25F16923ULL,
		0x05A6DCAA4543D28FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x870459BFAD55FB26ULL,
		0x6EAD1B4A7C4834ABULL,
		0x2B4B6BB1EEE29E1BULL,
		0x80C84B10D04F84B1ULL,
		0x0774F17CB646729CULL,
		0x5805349ACFAA4799ULL,
		0xAA23A4964BE2D247ULL,
		0x0B4DB9548A87A51FULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0C40C5805447140ULL,
		0x57E0AE4A1AB0B18BULL,
		0x18CAC1A49FCBA76BULL,
		0x5902ABC009D5F59FULL,
		0x20C4449344A2D75AULL,
		0xE6CD99B17945A7DFULL,
		0x973D269A5506930AULL,
		0x1F01FD80EB14EA6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18818B00A88E280ULL,
		0xAFC15C9435616317ULL,
		0x319583493F974ED6ULL,
		0xB205578013ABEB3EULL,
		0x418889268945AEB4ULL,
		0xCD9B3362F28B4FBEULL,
		0x2E7A4D34AA0D2615ULL,
		0x3E03FB01D629D4D7ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4130FFE20A76F953ULL,
		0x148EF6C5393DE21BULL,
		0x6E8F20BD4992700FULL,
		0x4BD23E0BCA7C0C54ULL,
		0xF1CB8C6884E9541DULL,
		0x775683F866640F70ULL,
		0x02A626B47347B38EULL,
		0x05B4150EE0176934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8261FFC414EDF2A6ULL,
		0x291DED8A727BC436ULL,
		0xDD1E417A9324E01EULL,
		0x97A47C1794F818A8ULL,
		0xE39718D109D2A83AULL,
		0xEEAD07F0CCC81EE1ULL,
		0x054C4D68E68F671CULL,
		0x0B682A1DC02ED268ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC10544F8EFC95280ULL,
		0xA52CC1FD92BFCFDDULL,
		0x28A451000D3EE8D8ULL,
		0x5CEB54BCFD3AE050ULL,
		0x02C9D6B0ACC46B04ULL,
		0x4AC84CD14CCC6AD1ULL,
		0x7FEBFA05A4A92151ULL,
		0x0E419B251E71692AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x820A89F1DF92A500ULL,
		0x4A5983FB257F9FBBULL,
		0x5148A2001A7DD1B1ULL,
		0xB9D6A979FA75C0A0ULL,
		0x0593AD615988D608ULL,
		0x959099A29998D5A2ULL,
		0xFFD7F40B495242A2ULL,
		0x1C83364A3CE2D254ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB274ED91AA2CB88ULL,
		0xA6E4AA5F98812725ULL,
		0xAD8A86CD5ADEEE3DULL,
		0x01293B7609E3A5C8ULL,
		0xB3C124443A09DA32ULL,
		0xDC77C3537974AF26ULL,
		0xEE544BD60291FED7ULL,
		0x09C0B7D6D521B6C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF64E9DB235459710ULL,
		0x4DC954BF31024E4BULL,
		0x5B150D9AB5BDDC7BULL,
		0x025276EC13C74B91ULL,
		0x678248887413B464ULL,
		0xB8EF86A6F2E95E4DULL,
		0xDCA897AC0523FDAFULL,
		0x13816FADAA436D93ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE77B67F9DCD9AE6ULL,
		0x3DA166EDFAD114DFULL,
		0x283436D7DDA16535ULL,
		0x13519060885E5AB0ULL,
		0x38E2DFB0242179C9ULL,
		0x4015BDD0EFAD6B1BULL,
		0x81AA0FA1EFE06284ULL,
		0x0B1D5D2DFD077405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CEF6CFF3B9B35CCULL,
		0x7B42CDDBF5A229BFULL,
		0x50686DAFBB42CA6AULL,
		0x26A320C110BCB560ULL,
		0x71C5BF604842F392ULL,
		0x802B7BA1DF5AD636ULL,
		0x03541F43DFC0C508ULL,
		0x163ABA5BFA0EE80BULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C0557A869AA2FBULL,
		0x7E9AC5ADC6258339ULL,
		0x529818CF7F01A23DULL,
		0x8A88BDEA0FA39541ULL,
		0x3B003FA4BDEE5A29ULL,
		0x285E09AC6DB2FDF5ULL,
		0x88E46A7B3C2E61E4ULL,
		0x3BCD5C1957DD7453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3380AAF50D3545F6ULL,
		0xFD358B5B8C4B0672ULL,
		0xA530319EFE03447AULL,
		0x15117BD41F472A82ULL,
		0x76007F497BDCB453ULL,
		0x50BC1358DB65FBEAULL,
		0x11C8D4F6785CC3C8ULL,
		0x779AB832AFBAE8A7ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF62B2188E7D5112AULL,
		0x567ACA769DD13BB3ULL,
		0xB5D50223D9E02A63ULL,
		0x377994C099861617ULL,
		0x4C476CB9B33D756AULL,
		0xB6876B527FB737B6ULL,
		0xABF6B637DF88EFC9ULL,
		0x3DB2FE460E18E4A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC564311CFAA2254ULL,
		0xACF594ED3BA27767ULL,
		0x6BAA0447B3C054C6ULL,
		0x6EF32981330C2C2FULL,
		0x988ED973667AEAD4ULL,
		0x6D0ED6A4FF6E6F6CULL,
		0x57ED6C6FBF11DF93ULL,
		0x7B65FC8C1C31C949ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4639CC8418B9D66AULL,
		0xEF947AD041CFED56ULL,
		0x953E088D4A3547F4ULL,
		0x6FCAE2AD12BB1AC5ULL,
		0xE3967A629A35386AULL,
		0xBF037471FC882FC2ULL,
		0x7C8BE7B1DB45228AULL,
		0x17E5D1E138E46ECBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7399083173ACD4ULL,
		0xDF28F5A0839FDAACULL,
		0x2A7C111A946A8FE9ULL,
		0xDF95C55A2576358BULL,
		0xC72CF4C5346A70D4ULL,
		0x7E06E8E3F9105F85ULL,
		0xF917CF63B68A4515ULL,
		0x2FCBA3C271C8DD96ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x946D87EFF9A63E17ULL,
		0x8107E939387E5653ULL,
		0xD2C325118E2B0F6DULL,
		0xDFE7F8524CEAE448ULL,
		0x780A9AB2320BC511ULL,
		0x96E000A68F2E0C11ULL,
		0xCBFA63003548DB52ULL,
		0x3CF38077492BF284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DB0FDFF34C7C2EULL,
		0x020FD27270FCACA7ULL,
		0xA5864A231C561EDBULL,
		0xBFCFF0A499D5C891ULL,
		0xF015356464178A23ULL,
		0x2DC0014D1E5C1822ULL,
		0x97F4C6006A91B6A5ULL,
		0x79E700EE9257E509ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC52DEE8D99DFC581ULL,
		0x2B06D7C2B8316C4BULL,
		0x6FA1A6E4E8008721ULL,
		0xAB52645C9854F367ULL,
		0x3005915589B5D549ULL,
		0xED60197698A77587ULL,
		0xE611C4B51841D422ULL,
		0x16F569358E6960CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5BDD1B33BF8B02ULL,
		0x560DAF857062D897ULL,
		0xDF434DC9D0010E42ULL,
		0x56A4C8B930A9E6CEULL,
		0x600B22AB136BAA93ULL,
		0xDAC032ED314EEB0EULL,
		0xCC23896A3083A845ULL,
		0x2DEAD26B1CD2C19FULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E2E902A64505E57ULL,
		0xB010E909C65A8D16ULL,
		0xB187D5B214080115ULL,
		0xC09CB6D2D218508CULL,
		0xA0C6570E0583A971ULL,
		0x4374EF81AD3C0408ULL,
		0xEC9B39F37FE910E2ULL,
		0x3E87048ADF0F509EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C5D2054C8A0BCAEULL,
		0x6021D2138CB51A2CULL,
		0x630FAB642810022BULL,
		0x81396DA5A430A119ULL,
		0x418CAE1C0B0752E3ULL,
		0x86E9DF035A780811ULL,
		0xD93673E6FFD221C4ULL,
		0x7D0E0915BE1EA13DULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C95629BCCDF193DULL,
		0xD4E89D5CC9B63143ULL,
		0xE2347A7EB96C67B3ULL,
		0xEC6657E5B1AC9C0AULL,
		0x99135ECB569D74FEULL,
		0x161809DD2122F868ULL,
		0x171DEC830B59992FULL,
		0x029DAD6494A05CAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x592AC53799BE327AULL,
		0xA9D13AB9936C6286ULL,
		0xC468F4FD72D8CF67ULL,
		0xD8CCAFCB63593815ULL,
		0x3226BD96AD3AE9FDULL,
		0x2C3013BA4245F0D1ULL,
		0x2E3BD90616B3325EULL,
		0x053B5AC92940B95EULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CF07FA227391D99ULL,
		0xB617CB14CD15E5E9ULL,
		0x06EF0B7865AB80BBULL,
		0x6214C003085EDDB6ULL,
		0xDFB29781E3F3AD8FULL,
		0x6C8B8E5386FA48A9ULL,
		0x6A6144BC2420AA68ULL,
		0x017F1F52267416A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E0FF444E723B32ULL,
		0x6C2F96299A2BCBD2ULL,
		0x0DDE16F0CB570177ULL,
		0xC429800610BDBB6CULL,
		0xBF652F03C7E75B1EULL,
		0xD9171CA70DF49153ULL,
		0xD4C28978484154D0ULL,
		0x02FE3EA44CE82D4AULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EA19A2602E6CE3BULL,
		0x28F225B320B73C99ULL,
		0x8196BADA066F4B2DULL,
		0x60B367D67564AF4FULL,
		0x02B6D492406C5790ULL,
		0x4C7C1DF1D8CD296FULL,
		0x61AEFEDE8685A15BULL,
		0x01D70F8292460D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D43344C05CD9C76ULL,
		0x51E44B66416E7932ULL,
		0x032D75B40CDE965AULL,
		0xC166CFACEAC95E9FULL,
		0x056DA92480D8AF20ULL,
		0x98F83BE3B19A52DEULL,
		0xC35DFDBD0D0B42B6ULL,
		0x03AE1F05248C1A4AULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x277DA391DCD0DD67ULL,
		0x8413CF0E9B29A044ULL,
		0x96D14784575865D0ULL,
		0x89B73413684DAD5CULL,
		0xD1077AC36D1F78B4ULL,
		0xE1D1DB129855BB50ULL,
		0x66BA740C1E8478C2ULL,
		0x35427D64AFD4BE19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EFB4723B9A1BACEULL,
		0x08279E1D36534088ULL,
		0x2DA28F08AEB0CBA1ULL,
		0x136E6826D09B5AB9ULL,
		0xA20EF586DA3EF169ULL,
		0xC3A3B62530AB76A1ULL,
		0xCD74E8183D08F185ULL,
		0x6A84FAC95FA97C32ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x240B40007A606C2EULL,
		0xF9844F7B8CD60B2AULL,
		0xE9CD411FD440FFFEULL,
		0x7E95F249B4D1D79AULL,
		0xEEEC61232EDE80E0ULL,
		0x5856DAD986E1FD9CULL,
		0x027504B8B5B95AB3ULL,
		0x3B38C59CA55833A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48168000F4C0D85CULL,
		0xF3089EF719AC1654ULL,
		0xD39A823FA881FFFDULL,
		0xFD2BE49369A3AF35ULL,
		0xDDD8C2465DBD01C0ULL,
		0xB0ADB5B30DC3FB39ULL,
		0x04EA09716B72B566ULL,
		0x76718B394AB0674EULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F65936EBBFDDBEEULL,
		0x1AED462BE774255CULL,
		0x8B11C72598AE393AULL,
		0xB5705A033FA15E77ULL,
		0x89BB98B0460D2C50ULL,
		0x1EBF0708A2D9880FULL,
		0x764592CB9166E67EULL,
		0x1044E3BC69FFD6E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECB26DD77FBB7DCULL,
		0x35DA8C57CEE84AB8ULL,
		0x16238E4B315C7274ULL,
		0x6AE0B4067F42BCEFULL,
		0x137731608C1A58A1ULL,
		0x3D7E0E1145B3101FULL,
		0xEC8B259722CDCCFCULL,
		0x2089C778D3FFADD2ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x030BB24E051915D8ULL,
		0xC8AE9C48EACCCAACULL,
		0x821DAD6779FAAE91ULL,
		0xF02D8D1E0371A23FULL,
		0x8563192FFBFC56BAULL,
		0xAAF7821ED8D9D5A3ULL,
		0xA0A8D961D2FDFDE7ULL,
		0x24729CAC6A0CC35FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0617649C0A322BB0ULL,
		0x915D3891D5999558ULL,
		0x043B5ACEF3F55D23ULL,
		0xE05B1A3C06E3447FULL,
		0x0AC6325FF7F8AD75ULL,
		0x55EF043DB1B3AB47ULL,
		0x4151B2C3A5FBFBCFULL,
		0x48E53958D41986BFULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF79052F474552728ULL,
		0xD08331906DD56189ULL,
		0x6A314BE4EE7DBF6BULL,
		0xA46C29B4B2018A84ULL,
		0xE5501B8511DB6B58ULL,
		0xC18B6658BBE70C59ULL,
		0x6291806AE5C33D40ULL,
		0x0B2A1B2470C70AF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF20A5E8E8AA4E50ULL,
		0xA1066320DBAAC313ULL,
		0xD46297C9DCFB7ED7ULL,
		0x48D8536964031508ULL,
		0xCAA0370A23B6D6B1ULL,
		0x8316CCB177CE18B3ULL,
		0xC52300D5CB867A81ULL,
		0x16543648E18E15E4ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x743DA22890CB80B9ULL,
		0x8FA8374AF69F8E51ULL,
		0x63C3D7E74BC62A82ULL,
		0x1494B809D6AA9664ULL,
		0xD0A5F8B3139A426AULL,
		0x6D53755AC462B70CULL,
		0x3BD9956118B73433ULL,
		0x123A7FC390E629A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87B445121970172ULL,
		0x1F506E95ED3F1CA2ULL,
		0xC787AFCE978C5505ULL,
		0x29297013AD552CC8ULL,
		0xA14BF166273484D4ULL,
		0xDAA6EAB588C56E19ULL,
		0x77B32AC2316E6866ULL,
		0x2474FF8721CC534AULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77119E74A9CFD76EULL,
		0xF326B5B1C67401D1ULL,
		0xB6714B200EE79EFDULL,
		0x6E2284B046F2F4A6ULL,
		0xC40CD8BB9F8B9600ULL,
		0x5237AD0E700D16EAULL,
		0xFBA593B4FF5FDAE8ULL,
		0x04DCD3169C35FAE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE233CE9539FAEDCULL,
		0xE64D6B638CE803A2ULL,
		0x6CE296401DCF3DFBULL,
		0xDC4509608DE5E94DULL,
		0x8819B1773F172C00ULL,
		0xA46F5A1CE01A2DD5ULL,
		0xF74B2769FEBFB5D0ULL,
		0x09B9A62D386BF5C9ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08E02DEB3D0B6DD5ULL,
		0x5DF7D5A238D41819ULL,
		0x39D9BED46F5CEA41ULL,
		0x2EA296CDD8AE0EA5ULL,
		0x9B13C00A2CEB0DD0ULL,
		0x33A2D4F94471A837ULL,
		0x0C161CFD9DCD789FULL,
		0x26C5B496A153E2EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C05BD67A16DBAAULL,
		0xBBEFAB4471A83032ULL,
		0x73B37DA8DEB9D482ULL,
		0x5D452D9BB15C1D4AULL,
		0x3627801459D61BA0ULL,
		0x6745A9F288E3506FULL,
		0x182C39FB3B9AF13EULL,
		0x4D8B692D42A7C5DEULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6DC237CEEA1003CULL,
		0x2FCBDED650363B7CULL,
		0xC6A4729F04D7709CULL,
		0x8365CF5253F31E67ULL,
		0x66138D59F70AB54EULL,
		0xACA44DE733A23406ULL,
		0xF66324B751BD5B32ULL,
		0x3960F6DA8E9112CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB846F9DD420078ULL,
		0x5F97BDACA06C76F9ULL,
		0x8D48E53E09AEE138ULL,
		0x06CB9EA4A7E63CCFULL,
		0xCC271AB3EE156A9DULL,
		0x59489BCE6744680CULL,
		0xECC6496EA37AB665ULL,
		0x72C1EDB51D22259BULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FB8D0306142F0DEULL,
		0xC271AC31969DF43FULL,
		0x5B4C226542257D15ULL,
		0xF551873EBD21A83AULL,
		0x7E9697D18A622FFEULL,
		0xF9E4A60B643035B1ULL,
		0xEA9C51E1BDDC64F9ULL,
		0x329361786600D09BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF71A060C285E1BCULL,
		0x84E358632D3BE87EULL,
		0xB69844CA844AFA2BULL,
		0xEAA30E7D7A435074ULL,
		0xFD2D2FA314C45FFDULL,
		0xF3C94C16C8606B62ULL,
		0xD538A3C37BB8C9F3ULL,
		0x6526C2F0CC01A137ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3D24421ACFC626FULL,
		0xE4F75A4B111A41C2ULL,
		0x53B02D0F48784739ULL,
		0xC50B0079FBF0D118ULL,
		0x793BCBDABD6C6406ULL,
		0x19D50E87D30F46E1ULL,
		0xDF505256C763AE5EULL,
		0x1BEF407F31F8500BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A4884359F8C4DEULL,
		0xC9EEB49622348385ULL,
		0xA7605A1E90F08E73ULL,
		0x8A1600F3F7E1A230ULL,
		0xF27797B57AD8C80DULL,
		0x33AA1D0FA61E8DC2ULL,
		0xBEA0A4AD8EC75CBCULL,
		0x37DE80FE63F0A017ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEBFE5A3D801ED74ULL,
		0x32F6ECE7E5DF62ECULL,
		0xA88D020D8D5C541EULL,
		0x97B884A3F0BBED97ULL,
		0xB2EDB617E98A0087ULL,
		0x1FBE39EB9C69C6A5ULL,
		0xCD19366FAADE0A46ULL,
		0x35AD5A96F14003FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD7FCB47B003DAE8ULL,
		0x65EDD9CFCBBEC5D9ULL,
		0x511A041B1AB8A83CULL,
		0x2F710947E177DB2FULL,
		0x65DB6C2FD314010FULL,
		0x3F7C73D738D38D4BULL,
		0x9A326CDF55BC148CULL,
		0x6B5AB52DE28007FFULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26D2A59E6D69A0F0ULL,
		0xAB4C957DB7B90B2DULL,
		0xA4394421408274B5ULL,
		0xB14D856936F7D2A4ULL,
		0xCA7F3B47CB9887F4ULL,
		0xB8D894084C87C311ULL,
		0x29380F163BFDD2D5ULL,
		0x2A8DE6BC982B2D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA54B3CDAD341E0ULL,
		0x56992AFB6F72165AULL,
		0x487288428104E96BULL,
		0x629B0AD26DEFA549ULL,
		0x94FE768F97310FE9ULL,
		0x71B12810990F8623ULL,
		0x52701E2C77FBA5ABULL,
		0x551BCD7930565B10ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47FF4549C91B820FULL,
		0x5C97734D4CEFCD85ULL,
		0x8EE7877935EDCC4AULL,
		0xDC8C3E75FC9CA6C9ULL,
		0x2D3FB8FE6B10FD9CULL,
		0x406AA0EA416BA249ULL,
		0x6D0BA90F455EE287ULL,
		0x1DBABC6DBE87D0D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFE8A939237041EULL,
		0xB92EE69A99DF9B0AULL,
		0x1DCF0EF26BDB9894ULL,
		0xB9187CEBF9394D93ULL,
		0x5A7F71FCD621FB39ULL,
		0x80D541D482D74492ULL,
		0xDA17521E8ABDC50EULL,
		0x3B7578DB7D0FA1A8ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7B343F0D206CC91ULL,
		0x021C043556B6FA8BULL,
		0xB1300BFDC92F3342ULL,
		0xEE97A2FC8A353C48ULL,
		0x96D91DB05F22DDABULL,
		0x138E2D1756107035ULL,
		0x70AC46B054A4A468ULL,
		0x2FE49061B6FB02DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F6687E1A40D9922ULL,
		0x0438086AAD6DF517ULL,
		0x626017FB925E6684ULL,
		0xDD2F45F9146A7891ULL,
		0x2DB23B60BE45BB57ULL,
		0x271C5A2EAC20E06BULL,
		0xE1588D60A94948D0ULL,
		0x5FC920C36DF605BCULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD975D8C89A4DC9DBULL,
		0xD11108FD44A06758ULL,
		0x4A07C5CF35A4919BULL,
		0x4E6C54ECD54E8193ULL,
		0xF0E26119236449A9ULL,
		0x56091A8749D5CB71ULL,
		0xAF8C2AC46B6E9760ULL,
		0x3D3EF4998D8F5BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2EBB191349B93B6ULL,
		0xA22211FA8940CEB1ULL,
		0x940F8B9E6B492337ULL,
		0x9CD8A9D9AA9D0326ULL,
		0xE1C4C23246C89352ULL,
		0xAC12350E93AB96E3ULL,
		0x5F185588D6DD2EC0ULL,
		0x7A7DE9331B1EB77BULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B3C69EFBAC66B54ULL,
		0x98859597C8ECD6B8ULL,
		0x733155620A31B572ULL,
		0x0F6610D4A01FEF22ULL,
		0xEFD54E4A8BCDA2B7ULL,
		0xB3CBD6E40074B496ULL,
		0x82BB1384B6D95196ULL,
		0x3E674C22A7E7AA5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB678D3DF758CD6A8ULL,
		0x310B2B2F91D9AD70ULL,
		0xE662AAC414636AE5ULL,
		0x1ECC21A9403FDE44ULL,
		0xDFAA9C95179B456EULL,
		0x6797ADC800E9692DULL,
		0x057627096DB2A32DULL,
		0x7CCE98454FCF54BDULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA42E65AF4325238AULL,
		0x2B86F1D3955F345DULL,
		0x82383DB28E236349ULL,
		0x9362EB9F1302F393ULL,
		0x692E1659E75129FCULL,
		0x1041D084E80BE190ULL,
		0xE7E6D789CE2344A5ULL,
		0x23FD327C1D677BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x485CCB5E864A4714ULL,
		0x570DE3A72ABE68BBULL,
		0x04707B651C46C692ULL,
		0x26C5D73E2605E727ULL,
		0xD25C2CB3CEA253F9ULL,
		0x2083A109D017C320ULL,
		0xCFCDAF139C46894AULL,
		0x47FA64F83ACEF75BULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC109921CB620008ULL,
		0xD3EE41FD70825007ULL,
		0xEF578B62C0C4E1D9ULL,
		0xCB820B7937197A9CULL,
		0xDB5E33B022D19D14ULL,
		0x5F910C4B7DD0FDCBULL,
		0xFAB69FA1B483E58BULL,
		0x201B0312D714A68EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7821324396C40010ULL,
		0xA7DC83FAE104A00FULL,
		0xDEAF16C58189C3B3ULL,
		0x970416F26E32F539ULL,
		0xB6BC676045A33A29ULL,
		0xBF221896FBA1FB97ULL,
		0xF56D3F436907CB16ULL,
		0x40360625AE294D1DULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7823F71282F1CBD0ULL,
		0xA208FEB385F17012ULL,
		0x36EF51B5BF7641D5ULL,
		0xAD2063D6790962CEULL,
		0x6585A3FFB96D2DDEULL,
		0xAD48D195E29DCDFBULL,
		0x29319ABF23B661FBULL,
		0x1ED985B2FC4DF086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF047EE2505E397A0ULL,
		0x4411FD670BE2E024ULL,
		0x6DDEA36B7EEC83ABULL,
		0x5A40C7ACF212C59CULL,
		0xCB0B47FF72DA5BBDULL,
		0x5A91A32BC53B9BF6ULL,
		0x5263357E476CC3F7ULL,
		0x3DB30B65F89BE10CULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD53EA657B19EB1C4ULL,
		0xD34FEBB42B94B869ULL,
		0xF004143509BF4670ULL,
		0x982C00E0B18B700DULL,
		0x180FC75476A381BBULL,
		0x624C4578EC1AE80CULL,
		0xFF81E33C5CE85875ULL,
		0x184C023DB54B87C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA7D4CAF633D6388ULL,
		0xA69FD768572970D3ULL,
		0xE008286A137E8CE1ULL,
		0x305801C16316E01BULL,
		0x301F8EA8ED470377ULL,
		0xC4988AF1D835D018ULL,
		0xFF03C678B9D0B0EAULL,
		0x3098047B6A970F93ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x020C27027D8B7349ULL,
		0x235D42446F4529F7ULL,
		0xC491CE97FE3B459FULL,
		0x03D99F7A184741D3ULL,
		0xD2D14EDBE78B282EULL,
		0x67FE77CB6255FF37ULL,
		0x7CE9525713C95DA9ULL,
		0x3B134F8015DE9F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04184E04FB16E692ULL,
		0x46BA8488DE8A53EEULL,
		0x89239D2FFC768B3EULL,
		0x07B33EF4308E83A7ULL,
		0xA5A29DB7CF16505CULL,
		0xCFFCEF96C4ABFE6FULL,
		0xF9D2A4AE2792BB52ULL,
		0x76269F002BBD3EA6ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x819BC49C681BDBC7ULL,
		0xF7B09FB59445B989ULL,
		0x9D21CD7D384E4E86ULL,
		0xC4E7738EEE82C603ULL,
		0x29AB33505EE489D6ULL,
		0x80212BA3331D1789ULL,
		0xC0514E129D947093ULL,
		0x34FABF4E0B861BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03378938D037B78EULL,
		0xEF613F6B288B7313ULL,
		0x3A439AFA709C9D0DULL,
		0x89CEE71DDD058C07ULL,
		0x535666A0BDC913ADULL,
		0x00425746663A2F12ULL,
		0x80A29C253B28E127ULL,
		0x69F57E9C170C37C3ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA51239CA3420D8FCULL,
		0xEA4BA3C98F527BADULL,
		0x992A81CB7F59951FULL,
		0xEF781E2D976EF0A4ULL,
		0x152311A6B93E0EB2ULL,
		0xDF0E1BD62984644EULL,
		0xCFDC09028A170FC9ULL,
		0x200BC8F60BCEFD87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2473946841B1F8ULL,
		0xD49747931EA4F75BULL,
		0x32550396FEB32A3FULL,
		0xDEF03C5B2EDDE149ULL,
		0x2A46234D727C1D65ULL,
		0xBE1C37AC5308C89CULL,
		0x9FB81205142E1F93ULL,
		0x401791EC179DFB0FULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BB86D52CD8A7BFBULL,
		0xFDE70E487ADD30B4ULL,
		0xB9A7B385AA0C964EULL,
		0x181AA562937ECC68ULL,
		0xA993A195F76CE959ULL,
		0x2CD9C5844E24DE1DULL,
		0x34EC1E7F944DB789ULL,
		0x32316C7F2F49F927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7770DAA59B14F7F6ULL,
		0xFBCE1C90F5BA6168ULL,
		0x734F670B54192C9DULL,
		0x30354AC526FD98D1ULL,
		0x5327432BEED9D2B2ULL,
		0x59B38B089C49BC3BULL,
		0x69D83CFF289B6F12ULL,
		0x6462D8FE5E93F24EULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A46B1FE5CBF8390ULL,
		0x68F7D00C1584FB61ULL,
		0x557DCDB14617CDC2ULL,
		0xB3F9240E61E5C6E3ULL,
		0xDDDD8EC0D01AC7B0ULL,
		0x31669010C52995CFULL,
		0x133571EC6EF1A0B3ULL,
		0x39AC701C9D1F8D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548D63FCB97F0720ULL,
		0xD1EFA0182B09F6C2ULL,
		0xAAFB9B628C2F9B84ULL,
		0x67F2481CC3CB8DC6ULL,
		0xBBBB1D81A0358F61ULL,
		0x62CD20218A532B9FULL,
		0x266AE3D8DDE34166ULL,
		0x7358E0393A3F1B06ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0376091183CA3B8CULL,
		0x60FF7F2945AC9BA6ULL,
		0x93ED0D9D40C5B15DULL,
		0x6CBFACE98E429781ULL,
		0xF37A25BAFDAF5B80ULL,
		0x7B5BDCE225CA1357ULL,
		0x359FCCC67F26F516ULL,
		0x2AD1C7B03E160974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06EC122307947718ULL,
		0xC1FEFE528B59374CULL,
		0x27DA1B3A818B62BAULL,
		0xD97F59D31C852F03ULL,
		0xE6F44B75FB5EB700ULL,
		0xF6B7B9C44B9426AFULL,
		0x6B3F998CFE4DEA2CULL,
		0x55A38F607C2C12E8ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D1560B7878692A5ULL,
		0x5DC4427A32E6E51FULL,
		0x7E123E7C62A709CBULL,
		0xA68AE5C9440BB529ULL,
		0x12070C5731649651ULL,
		0x731A43630C35C8E3ULL,
		0x69A3E7E99B80EF27ULL,
		0x014882501B5C920DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA2AC16F0F0D254AULL,
		0xBB8884F465CDCA3EULL,
		0xFC247CF8C54E1396ULL,
		0x4D15CB9288176A52ULL,
		0x240E18AE62C92CA3ULL,
		0xE63486C6186B91C6ULL,
		0xD347CFD33701DE4EULL,
		0x029104A036B9241AULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA849E1EC4D0C1D06ULL,
		0x583467910AC9D6CCULL,
		0x3EDB5F48B7228D8AULL,
		0x6AB008B410100561ULL,
		0x84FB1B8657784E7CULL,
		0x09040BDBB8CA8985ULL,
		0x4888F61326B3394BULL,
		0x1D114DF685D3670DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5093C3D89A183A0CULL,
		0xB068CF221593AD99ULL,
		0x7DB6BE916E451B14ULL,
		0xD560116820200AC2ULL,
		0x09F6370CAEF09CF8ULL,
		0x120817B77195130BULL,
		0x9111EC264D667296ULL,
		0x3A229BED0BA6CE1AULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE35E6F0BBC4FCFF9ULL,
		0xD30F92ACF6EE7313ULL,
		0x5A7C557C1819C27EULL,
		0x258C3DB15EACCC48ULL,
		0x912BD1BBA5F6F6F7ULL,
		0x3E8B3F6CA6F63829ULL,
		0xF152C4BB7842D15DULL,
		0x0FC058F7438E1D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BCDE17789F9FF2ULL,
		0xA61F2559EDDCE627ULL,
		0xB4F8AAF8303384FDULL,
		0x4B187B62BD599890ULL,
		0x2257A3774BEDEDEEULL,
		0x7D167ED94DEC7053ULL,
		0xE2A58976F085A2BAULL,
		0x1F80B1EE871C3AF7ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B1E7A087EABA2C1ULL,
		0x89D631679F5C854BULL,
		0x1ABD21383A6A4FCEULL,
		0xCD853FFF4B746B86ULL,
		0x9952967D0EB00BB0ULL,
		0xEABE411507328A95ULL,
		0x16B368F5A3F569E3ULL,
		0x31973306D9BCF425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x163CF410FD574582ULL,
		0x13AC62CF3EB90A97ULL,
		0x357A427074D49F9DULL,
		0x9B0A7FFE96E8D70CULL,
		0x32A52CFA1D601761ULL,
		0xD57C822A0E65152BULL,
		0x2D66D1EB47EAD3C7ULL,
		0x632E660DB379E84AULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA664359D82F3485EULL,
		0x0114CC8292B5E8FFULL,
		0xDA592227C883BCAFULL,
		0x4B1162DE465563A8ULL,
		0x2F075C7F232E176AULL,
		0x5EF7434001DD7089ULL,
		0x937FC45C0D98A4D8ULL,
		0x1791A667BEE431F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC86B3B05E690BCULL,
		0x02299905256BD1FFULL,
		0xB4B2444F9107795EULL,
		0x9622C5BC8CAAC751ULL,
		0x5E0EB8FE465C2ED4ULL,
		0xBDEE868003BAE112ULL,
		0x26FF88B81B3149B0ULL,
		0x2F234CCF7DC863F1ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69B424024E1786B9ULL,
		0x2EEB3ADF77A46F76ULL,
		0xF70DC611C475E159ULL,
		0xAB22B8DAF873973CULL,
		0xA9FAB81D5B6586EDULL,
		0x17272E840D220E00ULL,
		0x74CEF375945A0DB1ULL,
		0x3027794C2982A17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD36848049C2F0D72ULL,
		0x5DD675BEEF48DEECULL,
		0xEE1B8C2388EBC2B2ULL,
		0x564571B5F0E72E79ULL,
		0x53F5703AB6CB0DDBULL,
		0x2E4E5D081A441C01ULL,
		0xE99DE6EB28B41B62ULL,
		0x604EF298530542FCULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2B89EC3379D4091ULL,
		0x2E98BA3083CE6157ULL,
		0x3DE7AC67CF7DCF1CULL,
		0x7D3A04067E2166ACULL,
		0x8B683D3BE6E1DEA7ULL,
		0xDD6E8A97E38AF23AULL,
		0x7B56FF27FD9DD086ULL,
		0x16253CD2AB248798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85713D866F3A8122ULL,
		0x5D317461079CC2AFULL,
		0x7BCF58CF9EFB9E38ULL,
		0xFA74080CFC42CD58ULL,
		0x16D07A77CDC3BD4EULL,
		0xBADD152FC715E475ULL,
		0xF6ADFE4FFB3BA10DULL,
		0x2C4A79A556490F30ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x828BAA9D67EC176BULL,
		0x2CACA058DC073150ULL,
		0x365D5C6BB652F443ULL,
		0x7454EB98ECDB365CULL,
		0x23A641983ABE6878ULL,
		0xC2609C5B8B4AC9E7ULL,
		0x832B272A54294685ULL,
		0x21A00F6368514327ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0517553ACFD82ED6ULL,
		0x595940B1B80E62A1ULL,
		0x6CBAB8D76CA5E886ULL,
		0xE8A9D731D9B66CB8ULL,
		0x474C8330757CD0F0ULL,
		0x84C138B7169593CEULL,
		0x06564E54A8528D0BULL,
		0x43401EC6D0A2864FULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE16B39C88B1EFF8BULL,
		0x8D45BDF8B68EEB97ULL,
		0x591916E5408E4AC2ULL,
		0x774497885C1603ACULL,
		0x2C822A81C1A248CDULL,
		0xE879E85E875494F7ULL,
		0x87C0D5F5FC39D14BULL,
		0x3B9B3DD1C78B6001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D67391163DFF16ULL,
		0x1A8B7BF16D1DD72FULL,
		0xB2322DCA811C9585ULL,
		0xEE892F10B82C0758ULL,
		0x590455038344919AULL,
		0xD0F3D0BD0EA929EEULL,
		0x0F81ABEBF873A297ULL,
		0x77367BA38F16C003ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13CCD6C087CCB5C1ULL,
		0xB71865BA175A4D76ULL,
		0x753C34EE3DF5D63EULL,
		0x5D9B4656AEB357C2ULL,
		0x26A3841B65C49B8AULL,
		0xB3462302C7BD41B5ULL,
		0x28A9B92EEE897273ULL,
		0x3EB280F9456CD5BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2799AD810F996B82ULL,
		0x6E30CB742EB49AECULL,
		0xEA7869DC7BEBAC7DULL,
		0xBB368CAD5D66AF84ULL,
		0x4D470836CB893714ULL,
		0x668C46058F7A836AULL,
		0x5153725DDD12E4E7ULL,
		0x7D6501F28AD9AB7CULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD79A3BF942D1A834ULL,
		0x07EC99EE47752F16ULL,
		0xF9E74190AC87AE0EULL,
		0xF45C01A7DD0AE3DAULL,
		0xC74360ADCFDD2849ULL,
		0x890E0B0E0F164587ULL,
		0x4DB83EDDA5009BBCULL,
		0x394C61A26B20F04FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3477F285A35068ULL,
		0x0FD933DC8EEA5E2DULL,
		0xF3CE8321590F5C1CULL,
		0xE8B8034FBA15C7B5ULL,
		0x8E86C15B9FBA5093ULL,
		0x121C161C1E2C8B0FULL,
		0x9B707DBB4A013779ULL,
		0x7298C344D641E09EULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EB792CABADFB905ULL,
		0xA2C53DBA7CBD4AFAULL,
		0x6795BE24D62BC3E0ULL,
		0x86DD2B36EB50C898ULL,
		0xC41F031E14860A5BULL,
		0xD6EDC88DCDC07BAAULL,
		0x1127654E16D9F05DULL,
		0x00F501B3CC18B79BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6F259575BF720AULL,
		0x458A7B74F97A95F4ULL,
		0xCF2B7C49AC5787C1ULL,
		0x0DBA566DD6A19130ULL,
		0x883E063C290C14B7ULL,
		0xADDB911B9B80F755ULL,
		0x224ECA9C2DB3E0BBULL,
		0x01EA036798316F36ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B13C7BF7439CAEDULL,
		0x81DD580228A9AB28ULL,
		0x11DB501117ADD6D5ULL,
		0x976414A7E6E16536ULL,
		0xA96B9E6B3914516AULL,
		0xAB129E03DBFF4375ULL,
		0x3ED298C7036AE73CULL,
		0x02692B6F13F66C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16278F7EE87395DAULL,
		0x03BAB00451535650ULL,
		0x23B6A0222F5BADABULL,
		0x2EC8294FCDC2CA6CULL,
		0x52D73CD67228A2D5ULL,
		0x56253C07B7FE86EBULL,
		0x7DA5318E06D5CE79ULL,
		0x04D256DE27ECD938ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A3450CF0C754774ULL,
		0xCD36A18DA627AC5BULL,
		0x39108517908BC958ULL,
		0x15C2413EB8BEC6CFULL,
		0x4C0940018D22D62BULL,
		0x8046AA5463882D0BULL,
		0x3E48048F6159AA60ULL,
		0x127D199A8367D1C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF468A19E18EA8EE8ULL,
		0x9A6D431B4C4F58B6ULL,
		0x72210A2F211792B1ULL,
		0x2B84827D717D8D9EULL,
		0x981280031A45AC56ULL,
		0x008D54A8C7105A16ULL,
		0x7C90091EC2B354C1ULL,
		0x24FA333506CFA382ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B861A10E9FFE30CULL,
		0xE947E2DD731DAC9CULL,
		0x0C4307B97E85C2E3ULL,
		0xC9503C56223913EAULL,
		0x64FCB4416C18D211ULL,
		0x7E36CD56783C5BF7ULL,
		0x169AD8CA164B9E69ULL,
		0x1D3BAB9E7E8B5754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x970C3421D3FFC618ULL,
		0xD28FC5BAE63B5938ULL,
		0x18860F72FD0B85C7ULL,
		0x92A078AC447227D4ULL,
		0xC9F96882D831A423ULL,
		0xFC6D9AACF078B7EEULL,
		0x2D35B1942C973CD2ULL,
		0x3A77573CFD16AEA8ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x605FD1020F28D344ULL,
		0xC8AFA89021876F99ULL,
		0x37A6C56F915D5159ULL,
		0x36407DF93588147DULL,
		0x7EFE7F19D5221104ULL,
		0xD338DFC03509C3CBULL,
		0xE6CB87EB5F58F042ULL,
		0x0E4656ED5D090539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0BFA2041E51A688ULL,
		0x915F5120430EDF32ULL,
		0x6F4D8ADF22BAA2B3ULL,
		0x6C80FBF26B1028FAULL,
		0xFDFCFE33AA442208ULL,
		0xA671BF806A138796ULL,
		0xCD970FD6BEB1E085ULL,
		0x1C8CADDABA120A73ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE8924ECF6C97F42ULL,
		0x04641E89D22F25D1ULL,
		0x63CF84596B56BDBDULL,
		0xF8270466BBCF5442ULL,
		0x4CE7718AD46FA699ULL,
		0x790C9A98109D9768ULL,
		0x2FEA5486FA30369AULL,
		0x215E3A773964B402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1249D9ED92FE84ULL,
		0x08C83D13A45E4BA3ULL,
		0xC79F08B2D6AD7B7AULL,
		0xF04E08CD779EA884ULL,
		0x99CEE315A8DF4D33ULL,
		0xF2193530213B2ED0ULL,
		0x5FD4A90DF4606D34ULL,
		0x42BC74EE72C96804ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x338B7048E53777F1ULL,
		0xB301641B947ABE1BULL,
		0xBD4F78E12387072CULL,
		0x8A99B4FD5428C4C7ULL,
		0x0577EB45F1A9D930ULL,
		0x0E2E971837FFB7E6ULL,
		0x56692844E7F901DCULL,
		0x29888984E5FDF95FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6716E091CA6EEFE2ULL,
		0x6602C83728F57C36ULL,
		0x7A9EF1C2470E0E59ULL,
		0x153369FAA851898FULL,
		0x0AEFD68BE353B261ULL,
		0x1C5D2E306FFF6FCCULL,
		0xACD25089CFF203B8ULL,
		0x53111309CBFBF2BEULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52100AA167B80C26ULL,
		0xBF23D88828F63A47ULL,
		0xE0AF173D24798B44ULL,
		0x4F09E8752A3C109DULL,
		0x99EE1C3BD35938BBULL,
		0x76649D67E65700C7ULL,
		0x1C421413B5E2D928ULL,
		0x17FA013386BDD0D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4201542CF70184CULL,
		0x7E47B11051EC748EULL,
		0xC15E2E7A48F31689ULL,
		0x9E13D0EA5478213BULL,
		0x33DC3877A6B27176ULL,
		0xECC93ACFCCAE018FULL,
		0x388428276BC5B250ULL,
		0x2FF402670D7BA1A2ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C10CA1A7461BEB2ULL,
		0x06FC89C8D0F79BD4ULL,
		0x46005ED83B00C07EULL,
		0x9BF84D4F50011297ULL,
		0x5CAEDF1701D2EC08ULL,
		0xD03FA784E75DE38DULL,
		0xCD55D780D44FD48CULL,
		0x368D79B85679415CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18219434E8C37D64ULL,
		0x0DF91391A1EF37A8ULL,
		0x8C00BDB0760180FCULL,
		0x37F09A9EA002252EULL,
		0xB95DBE2E03A5D811ULL,
		0xA07F4F09CEBBC71AULL,
		0x9AABAF01A89FA919ULL,
		0x6D1AF370ACF282B9ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2507C9A7ECC2C0D3ULL,
		0x37D9655D4F5EB018ULL,
		0xACD9EB1FD0B7F65BULL,
		0x666B801F5670130FULL,
		0xB30B7011536368E8ULL,
		0xF330093DD596F983ULL,
		0xFF4DC0B6BA1D0178ULL,
		0x1AD81D6D321F404FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A0F934FD98581A6ULL,
		0x6FB2CABA9EBD6030ULL,
		0x59B3D63FA16FECB6ULL,
		0xCCD7003EACE0261FULL,
		0x6616E022A6C6D1D0ULL,
		0xE660127BAB2DF307ULL,
		0xFE9B816D743A02F1ULL,
		0x35B03ADA643E809FULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8F1CAE824CDF8AEULL,
		0xE9D9E728B9A70C12ULL,
		0x2EF392D42250B570ULL,
		0x88A8A4CE426E7E5DULL,
		0x3873CD213F2ED244ULL,
		0x69A4EDB012C8A286ULL,
		0x4E24F8F1DE2CCF90ULL,
		0x0A904A6D68B5E49EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1E395D0499BF15CULL,
		0xD3B3CE51734E1825ULL,
		0x5DE725A844A16AE1ULL,
		0x1151499C84DCFCBAULL,
		0x70E79A427E5DA489ULL,
		0xD349DB602591450CULL,
		0x9C49F1E3BC599F20ULL,
		0x152094DAD16BC93CULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38E2C1806F753517ULL,
		0xC963AC476FB13EB0ULL,
		0x86E23C37C34EA039ULL,
		0x09A8DD2CBC8B909FULL,
		0x2E41AEA879964445ULL,
		0x7F571C7A8D47C4B8ULL,
		0x6C38681F3B427D30ULL,
		0x25646BB4E73EB7CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C58300DEEA6A2EULL,
		0x92C7588EDF627D60ULL,
		0x0DC4786F869D4073ULL,
		0x1351BA597917213FULL,
		0x5C835D50F32C888AULL,
		0xFEAE38F51A8F8970ULL,
		0xD870D03E7684FA60ULL,
		0x4AC8D769CE7D6F9CULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4692A94A93B3E9A6ULL,
		0x616AC78C4B7C6FE5ULL,
		0x8A93CE98745687F8ULL,
		0xA00C203B216AB489ULL,
		0xA5453D6991C63CCFULL,
		0x899079EEE050A26FULL,
		0x977E03921FA0B5C6ULL,
		0x133E0EBC88FC0A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D2552952767D34CULL,
		0xC2D58F1896F8DFCAULL,
		0x15279D30E8AD0FF0ULL,
		0x4018407642D56913ULL,
		0x4A8A7AD3238C799FULL,
		0x1320F3DDC0A144DFULL,
		0x2EFC07243F416B8DULL,
		0x267C1D7911F8153DULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48D05570E52AD4DBULL,
		0xE82DB581BEA0F1E2ULL,
		0x033F6081BDC5FE39ULL,
		0xE72FA2ED20240801ULL,
		0x68F52ABD4FF149B0ULL,
		0xD159C97D7057703AULL,
		0xB4F98E3D7ED31865ULL,
		0x2FA8A81EA43F3075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91A0AAE1CA55A9B6ULL,
		0xD05B6B037D41E3C4ULL,
		0x067EC1037B8BFC73ULL,
		0xCE5F45DA40481002ULL,
		0xD1EA557A9FE29361ULL,
		0xA2B392FAE0AEE074ULL,
		0x69F31C7AFDA630CBULL,
		0x5F51503D487E60EBULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6607E4903BA2A480ULL,
		0xC70D2AA99DE23288ULL,
		0xB9A84EC8FC544012ULL,
		0xD09FE5E1DA53A7FDULL,
		0x11190BC38C861178ULL,
		0xC5A533FB267C6766ULL,
		0xE42CF32B0DB40C5BULL,
		0x367CDBB55DAC6852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC0FC92077454900ULL,
		0x8E1A55533BC46510ULL,
		0x73509D91F8A88025ULL,
		0xA13FCBC3B4A74FFBULL,
		0x22321787190C22F1ULL,
		0x8B4A67F64CF8CECCULL,
		0xC859E6561B6818B7ULL,
		0x6CF9B76ABB58D0A5ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2327670E26F60DFDULL,
		0x4CA9F144AF31D666ULL,
		0x4D0FF92AABAFB008ULL,
		0x67DE9738DB28F653ULL,
		0xA5DD0B6103FCC91BULL,
		0x8AE1803E2C145381ULL,
		0x7100A67A68D452C0ULL,
		0x1A5F96872311B3F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464ECE1C4DEC1BFAULL,
		0x9953E2895E63ACCCULL,
		0x9A1FF255575F6010ULL,
		0xCFBD2E71B651ECA6ULL,
		0x4BBA16C207F99236ULL,
		0x15C3007C5828A703ULL,
		0xE2014CF4D1A8A581ULL,
		0x34BF2D0E462367E4ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7BA76B708776764ULL,
		0xC8F104AC4195F8E4ULL,
		0x8910CDF661CEEC16ULL,
		0xD6B27127014DCCE8ULL,
		0x7A6F5BF99E7C3F55ULL,
		0x5B5BE9A89DD585F9ULL,
		0x66A0A5AE8401CE19ULL,
		0x2E450CA2600AC4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF74ED6E10EECEC8ULL,
		0x91E20958832BF1C9ULL,
		0x12219BECC39DD82DULL,
		0xAD64E24E029B99D1ULL,
		0xF4DEB7F33CF87EABULL,
		0xB6B7D3513BAB0BF2ULL,
		0xCD414B5D08039C32ULL,
		0x5C8A1944C01589C4ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6D6676597538C10ULL,
		0xE125920C00741518ULL,
		0x2824E5C9547DD0B9ULL,
		0xDED5EE9C186DB651ULL,
		0x56DC811F3B43282FULL,
		0x386E711C1B4AF05BULL,
		0x729904040A697EF1ULL,
		0x1A85AF55E504A064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DACCECB2EA71820ULL,
		0xC24B241800E82A31ULL,
		0x5049CB92A8FBA173ULL,
		0xBDABDD3830DB6CA2ULL,
		0xADB9023E7686505FULL,
		0x70DCE2383695E0B6ULL,
		0xE532080814D2FDE2ULL,
		0x350B5EABCA0940C8ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E7B5A24C02EE235ULL,
		0x0089608CA54C7E42ULL,
		0x6275A5457FDB4034ULL,
		0xC962120B566A4C0BULL,
		0xE24BA8C4B968311CULL,
		0x75253E9A6E65A4BAULL,
		0x13829C5A8DBB28F0ULL,
		0x1E95751ADDF9A876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CF6B449805DC46AULL,
		0x0112C1194A98FC84ULL,
		0xC4EB4A8AFFB68068ULL,
		0x92C42416ACD49816ULL,
		0xC497518972D06239ULL,
		0xEA4A7D34DCCB4975ULL,
		0x270538B51B7651E0ULL,
		0x3D2AEA35BBF350ECULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB68330080E651ADBULL,
		0xEEA369ACC7A0CA52ULL,
		0xFAFFC0C898783582ULL,
		0x5E2E1233A79CBBB2ULL,
		0xE2E5EBDE37B9EA37ULL,
		0xF26396C619132D75ULL,
		0x2FF0749F99155570ULL,
		0x365EE4BF57B36616ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D0660101CCA35B6ULL,
		0xDD46D3598F4194A5ULL,
		0xF5FF819130F06B05ULL,
		0xBC5C24674F397765ULL,
		0xC5CBD7BC6F73D46EULL,
		0xE4C72D8C32265AEBULL,
		0x5FE0E93F322AAAE1ULL,
		0x6CBDC97EAF66CC2CULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x285A943317923FDCULL,
		0x7316657D7ECF4523ULL,
		0xA0D52C766D27C864ULL,
		0x628702A767F650E9ULL,
		0x93535AB712DAABCBULL,
		0xA0326914496EE8A3ULL,
		0x79CE06E00BA33C49ULL,
		0x0CDAF9E8211B9CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50B528662F247FB8ULL,
		0xE62CCAFAFD9E8A46ULL,
		0x41AA58ECDA4F90C8ULL,
		0xC50E054ECFECA1D3ULL,
		0x26A6B56E25B55796ULL,
		0x4064D22892DDD147ULL,
		0xF39C0DC017467893ULL,
		0x19B5F3D0423739BAULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10B169039A5A16C4ULL,
		0x4D3554035BF95A5DULL,
		0xEAF89D33188AD454ULL,
		0xDEDE5F246355E420ULL,
		0xEDC108676FD274C0ULL,
		0x29F9853D05558CD7ULL,
		0x3034E4D26E29FAA4ULL,
		0x25FB53DF11988005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2162D20734B42D88ULL,
		0x9A6AA806B7F2B4BAULL,
		0xD5F13A663115A8A8ULL,
		0xBDBCBE48C6ABC841ULL,
		0xDB8210CEDFA4E981ULL,
		0x53F30A7A0AAB19AFULL,
		0x6069C9A4DC53F548ULL,
		0x4BF6A7BE2331000AULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56C9A116666C5918ULL,
		0x54FA2FDC9A389432ULL,
		0xE53445C53B99A1A8ULL,
		0x0BEBE0EB5D9CE49FULL,
		0x1E639A5E91BC3A89ULL,
		0x1CE7E661A698780DULL,
		0xFB11A08CF04EFE90ULL,
		0x02B494E2174D7011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD93422CCCD8B230ULL,
		0xA9F45FB934712864ULL,
		0xCA688B8A77334350ULL,
		0x17D7C1D6BB39C93FULL,
		0x3CC734BD23787512ULL,
		0x39CFCCC34D30F01AULL,
		0xF6234119E09DFD20ULL,
		0x056929C42E9AE023ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63DA733174C3E251ULL,
		0x5BCF1D53984E465BULL,
		0x6F5A5B41F2B02410ULL,
		0xD82957C2BAC03FC9ULL,
		0x9C2228F5AE5DEEEAULL,
		0xC853CD16EA86BB78ULL,
		0x0C40563FD878D44EULL,
		0x0C27F85AE51F3897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B4E662E987C4A2ULL,
		0xB79E3AA7309C8CB6ULL,
		0xDEB4B683E5604820ULL,
		0xB052AF8575807F92ULL,
		0x384451EB5CBBDDD5ULL,
		0x90A79A2DD50D76F1ULL,
		0x1880AC7FB0F1A89DULL,
		0x184FF0B5CA3E712EULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1AFB99644AA12C1ULL,
		0x916300E19A2424C2ULL,
		0x9EF512B98AE4C5EDULL,
		0x2862BAC2069E4789ULL,
		0x4DEF636A0704FE17ULL,
		0xA539E62EEBB88F40ULL,
		0x3390886A1BB2C5EBULL,
		0x20B00B7B6ED0CC4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835F732C89542582ULL,
		0x22C601C334484985ULL,
		0x3DEA257315C98BDBULL,
		0x50C575840D3C8F13ULL,
		0x9BDEC6D40E09FC2EULL,
		0x4A73CC5DD7711E80ULL,
		0x672110D437658BD7ULL,
		0x416016F6DDA1989AULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB51EB17CC242527FULL,
		0x15EFB1DEEB2EED34ULL,
		0xBCD973F1DDAA4F24ULL,
		0xADB0F147E5CFAFDEULL,
		0x799EA21095327432ULL,
		0x35ECBA96721DDD51ULL,
		0x3069DA8037A92539ULL,
		0x31742142B3649F11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3D62F98484A4FEULL,
		0x2BDF63BDD65DDA69ULL,
		0x79B2E7E3BB549E48ULL,
		0x5B61E28FCB9F5FBDULL,
		0xF33D44212A64E865ULL,
		0x6BD9752CE43BBAA2ULL,
		0x60D3B5006F524A72ULL,
		0x62E8428566C93E22ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD59171E72779EB2ULL,
		0xAA5B383F9FD3B053ULL,
		0x145F66A90DF8BB2EULL,
		0xCA09697D0937B0AAULL,
		0x59F779AC48326F2BULL,
		0x265A78265D9AB473ULL,
		0xBC4451086B480973ULL,
		0x38A0B6AC20082FEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AB22E3CE4EF3D64ULL,
		0x54B6707F3FA760A7ULL,
		0x28BECD521BF1765DULL,
		0x9412D2FA126F6154ULL,
		0xB3EEF3589064DE57ULL,
		0x4CB4F04CBB3568E6ULL,
		0x7888A210D69012E6ULL,
		0x71416D5840105FDDULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FBE8A2181E1A69AULL,
		0xCDF682132FC5017EULL,
		0x213DA84D356D872CULL,
		0xC7EA4A07D13CC4EFULL,
		0xDBC5C7E2850114BCULL,
		0x4922FDE2E6A89BDFULL,
		0xB6F05EAB93A2BCF8ULL,
		0x36AC4E771D2644ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7D144303C34D34ULL,
		0x9BED04265F8A02FDULL,
		0x427B509A6ADB0E59ULL,
		0x8FD4940FA27989DEULL,
		0xB78B8FC50A022979ULL,
		0x9245FBC5CD5137BFULL,
		0x6DE0BD57274579F0ULL,
		0x6D589CEE3A4C8957ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB918FF26C38881D1ULL,
		0x233972973608C816ULL,
		0x4880284C962D612FULL,
		0xF7C40FF248AA57B5ULL,
		0x730A11DC6E54CADCULL,
		0x528AC691743E7F12ULL,
		0x61860875F0C5587DULL,
		0x094A4C0703AE263DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7231FE4D871103A2ULL,
		0x4672E52E6C11902DULL,
		0x910050992C5AC25EULL,
		0xEF881FE49154AF6AULL,
		0xE61423B8DCA995B9ULL,
		0xA5158D22E87CFE24ULL,
		0xC30C10EBE18AB0FAULL,
		0x1294980E075C4C7AULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B2A4705B4D0AA22ULL,
		0x7D8F5B82A75BF9FBULL,
		0xB7BF7CFEA1AFD253ULL,
		0x8DEE2980B8F5C15FULL,
		0x97172E0E7D5B912AULL,
		0x844C69445422FB8AULL,
		0x6771DE24A52A804DULL,
		0x298CEA63B5A10A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6548E0B69A15444ULL,
		0xFB1EB7054EB7F3F6ULL,
		0x6F7EF9FD435FA4A6ULL,
		0x1BDC530171EB82BFULL,
		0x2E2E5C1CFAB72255ULL,
		0x0898D288A845F715ULL,
		0xCEE3BC494A55009BULL,
		0x5319D4C76B421496ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33536DFF3A0AEA56ULL,
		0xDF47AC94BE9F505BULL,
		0x7E061778C963D179ULL,
		0xFA6810F3F7DCF0C7ULL,
		0xB78B8C93E519704CULL,
		0xB469F67FA6991183ULL,
		0x0DA4C32912152450ULL,
		0x066993C1645B802FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A6DBFE7415D4ACULL,
		0xBE8F59297D3EA0B6ULL,
		0xFC0C2EF192C7A2F3ULL,
		0xF4D021E7EFB9E18EULL,
		0x6F171927CA32E099ULL,
		0x68D3ECFF4D322307ULL,
		0x1B498652242A48A1ULL,
		0x0CD32782C8B7005EULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67B9B140144B51FAULL,
		0xDC643E3EF2ACB826ULL,
		0x3A1786A436ED8D60ULL,
		0xABBD3B0ED0983DACULL,
		0x71429DF6F935A1D9ULL,
		0xF2732A258664A9EDULL,
		0x29EC8D57AF0B7D86ULL,
		0x29994312E6137984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7362802896A3F4ULL,
		0xB8C87C7DE559704CULL,
		0x742F0D486DDB1AC1ULL,
		0x577A761DA1307B58ULL,
		0xE2853BEDF26B43B3ULL,
		0xE4E6544B0CC953DAULL,
		0x53D91AAF5E16FB0DULL,
		0x53328625CC26F308ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48BFACEAB7A03A48ULL,
		0xCE33F27C9C58222FULL,
		0xCC63F057EDEC3D90ULL,
		0x2271C587B855F236ULL,
		0xC2E9ECD4AD8485AFULL,
		0x3E6EFBCB063B43AAULL,
		0x9592706E0AB3B732ULL,
		0x23056BC1B16ABC07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x917F59D56F407490ULL,
		0x9C67E4F938B0445EULL,
		0x98C7E0AFDBD87B21ULL,
		0x44E38B0F70ABE46DULL,
		0x85D3D9A95B090B5EULL,
		0x7CDDF7960C768755ULL,
		0x2B24E0DC15676E64ULL,
		0x460AD78362D5780FULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE5688126203A6CDULL,
		0x59F92357DBB91DE0ULL,
		0x003B67242B439E11ULL,
		0x187005D3BFDE307AULL,
		0x77180C7E34FA82B8ULL,
		0x707FE655B02ECD55ULL,
		0x9DA2C91F1A79B35AULL,
		0x3086DB70A5102C90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CAD1024C4074D9AULL,
		0xB3F246AFB7723BC1ULL,
		0x0076CE4856873C22ULL,
		0x30E00BA77FBC60F4ULL,
		0xEE3018FC69F50570ULL,
		0xE0FFCCAB605D9AAAULL,
		0x3B45923E34F366B4ULL,
		0x610DB6E14A205921ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7FD13D7CA9723B0ULL,
		0x2076DC840EF54F1FULL,
		0x865B5BDDF2D3E3D7ULL,
		0xF132792E1F96F6B0ULL,
		0x1ABD1ED78E4B7061ULL,
		0x3699D822133CE466ULL,
		0x7EC2C7A09B3454D7ULL,
		0x20BF3A0740CE8F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFA27AF952E4760ULL,
		0x40EDB9081DEA9E3FULL,
		0x0CB6B7BBE5A7C7AEULL,
		0xE264F25C3F2DED61ULL,
		0x357A3DAF1C96E0C3ULL,
		0x6D33B0442679C8CCULL,
		0xFD858F413668A9AEULL,
		0x417E740E819D1F28ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE13C93EBA74DED1ULL,
		0x78A41750074BC3D1ULL,
		0x155E97C133B2B43DULL,
		0x0020F4D5D799DDE7ULL,
		0x33C03D9683A5DF9CULL,
		0xE4B7BE1EBEA4019BULL,
		0xE8ACA2B9AE733632ULL,
		0x2B20883814655884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC27927D74E9BDA2ULL,
		0xF1482EA00E9787A3ULL,
		0x2ABD2F826765687AULL,
		0x0041E9ABAF33BBCEULL,
		0x67807B2D074BBF38ULL,
		0xC96F7C3D7D480336ULL,
		0xD15945735CE66C65ULL,
		0x5641107028CAB109ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D6AED23E075348BULL,
		0x360EAD79544DB882ULL,
		0xA49B998E2E2537BCULL,
		0xE864750C4EF18D7BULL,
		0xD9C102D049D5366DULL,
		0xB883F6A48D78ED26ULL,
		0xAFA58A7393A2E26CULL,
		0x0616D5D14C0174FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD5DA47C0EA6916ULL,
		0x6C1D5AF2A89B7104ULL,
		0x4937331C5C4A6F78ULL,
		0xD0C8EA189DE31AF7ULL,
		0xB38205A093AA6CDBULL,
		0x7107ED491AF1DA4DULL,
		0x5F4B14E72745C4D9ULL,
		0x0C2DABA29802E9FDULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7D5912E7793C675ULL,
		0xBAC498F8F5D6803DULL,
		0x61530AE29FF1C5E2ULL,
		0x76898DEA859ECE5FULL,
		0x4F4AAE06775A0211ULL,
		0x8EB8C3322F643938ULL,
		0x6FBE344D64578E6AULL,
		0x23277A1FC2B18404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFAB225CEF278CEAULL,
		0x758931F1EBAD007BULL,
		0xC2A615C53FE38BC5ULL,
		0xED131BD50B3D9CBEULL,
		0x9E955C0CEEB40422ULL,
		0x1D7186645EC87270ULL,
		0xDF7C689AC8AF1CD5ULL,
		0x464EF43F85630808ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5CFBF06675A6E36ULL,
		0x4A8F6F569BC177BFULL,
		0x09B29B228CEE4D72ULL,
		0x76EACFF899E4E5D1ULL,
		0xD8C543BE12D1E44EULL,
		0x7C0E51E24B76C7E1ULL,
		0x69E40E1D2EC2F4F1ULL,
		0x29C05367A4BA48ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B9F7E0CCEB4DC6CULL,
		0x951EDEAD3782EF7FULL,
		0x1365364519DC9AE4ULL,
		0xEDD59FF133C9CBA2ULL,
		0xB18A877C25A3C89CULL,
		0xF81CA3C496ED8FC3ULL,
		0xD3C81C3A5D85E9E2ULL,
		0x5380A6CF49749158ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FB337BF443022F1ULL,
		0x3EAF8EF1E1F2DF67ULL,
		0x67207358F3D4236EULL,
		0x40B0E616D0AB058FULL,
		0x27DE5AFEAADD1E75ULL,
		0x579133E66EB1729CULL,
		0x4514979DB25B94EBULL,
		0x38F968C6DED55A8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF666F7E886045E2ULL,
		0x7D5F1DE3C3E5BECEULL,
		0xCE40E6B1E7A846DCULL,
		0x8161CC2DA1560B1EULL,
		0x4FBCB5FD55BA3CEAULL,
		0xAF2267CCDD62E538ULL,
		0x8A292F3B64B729D6ULL,
		0x71F2D18DBDAAB518ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D58009F329B9108ULL,
		0x0DD42545BBAECEA7ULL,
		0x845FEC3E0B75B566ULL,
		0x6431E70B29338893ULL,
		0xDC205FAA185E93F1ULL,
		0x7D4E6807CD49230EULL,
		0xAC7C5133F86A66B2ULL,
		0x38DCAC42149F567DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB0013E65372210ULL,
		0x1BA84A8B775D9D4FULL,
		0x08BFD87C16EB6ACCULL,
		0xC863CE1652671127ULL,
		0xB840BF5430BD27E2ULL,
		0xFA9CD00F9A92461DULL,
		0x58F8A267F0D4CD64ULL,
		0x71B95884293EACFBULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7658595A279B9517ULL,
		0x05C5F8E7E516777DULL,
		0xB7106B3BFC48A7B5ULL,
		0xB983732FB4597A96ULL,
		0xD3D886E2CDE68F73ULL,
		0x975711FB65E5C3AFULL,
		0x7130D7FC0A61460CULL,
		0x2D4B3C1A6495E944ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECB0B2B44F372A2EULL,
		0x0B8BF1CFCA2CEEFAULL,
		0x6E20D677F8914F6AULL,
		0x7306E65F68B2F52DULL,
		0xA7B10DC59BCD1EE7ULL,
		0x2EAE23F6CBCB875FULL,
		0xE261AFF814C28C19ULL,
		0x5A967834C92BD288ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18437C567102A226ULL,
		0x382FD450470E06BFULL,
		0xB288E8CD42069EBCULL,
		0x514651BED6D3486CULL,
		0x600FD6290D913237ULL,
		0x0DBF431BC00B7FACULL,
		0x8094DBC3FC6BD0FBULL,
		0x0221FEB89D4DDC80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3086F8ACE205444CULL,
		0x705FA8A08E1C0D7EULL,
		0x6511D19A840D3D78ULL,
		0xA28CA37DADA690D9ULL,
		0xC01FAC521B22646EULL,
		0x1B7E86378016FF58ULL,
		0x0129B787F8D7A1F6ULL,
		0x0443FD713A9BB901ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD5E0F34CB917673ULL,
		0x2AB0A3F42A2F270BULL,
		0x5BC0AF92F4322500ULL,
		0x0AB7FBB3E3A77C7CULL,
		0x9AFCFB9015294D88ULL,
		0xEEF2A30A2496E290ULL,
		0xCD6DBD6DCC5306FAULL,
		0x11188959CE7B7878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ABC1E699722ECE6ULL,
		0x556147E8545E4E17ULL,
		0xB7815F25E8644A00ULL,
		0x156FF767C74EF8F8ULL,
		0x35F9F7202A529B10ULL,
		0xDDE54614492DC521ULL,
		0x9ADB7ADB98A60DF5ULL,
		0x223112B39CF6F0F1ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF27AC790657C0680ULL,
		0x079E3BCEBAA01029ULL,
		0xBFC6E1157BF14C4BULL,
		0x468C5BC3E68F0611ULL,
		0xA9748A437F167FECULL,
		0x61D985BE1EAA7F6EULL,
		0x55C291F18CE9F0F5ULL,
		0x394A64F0A5C79614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4F58F20CAF80D00ULL,
		0x0F3C779D75402053ULL,
		0x7F8DC22AF7E29896ULL,
		0x8D18B787CD1E0C23ULL,
		0x52E91486FE2CFFD8ULL,
		0xC3B30B7C3D54FEDDULL,
		0xAB8523E319D3E1EAULL,
		0x7294C9E14B8F2C28ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE54A59E0DE836135ULL,
		0xC2BC67A830CF20BBULL,
		0x31A9B1414CFA7CC9ULL,
		0xBF4509272CCB28B1ULL,
		0x6E4E3E1CB71A54EBULL,
		0x55831E653B6651B1ULL,
		0x0B35B7E00296BF25ULL,
		0x06DC3FCDED53BB28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA94B3C1BD06C26AULL,
		0x8578CF50619E4177ULL,
		0x6353628299F4F993ULL,
		0x7E8A124E59965162ULL,
		0xDC9C7C396E34A9D7ULL,
		0xAB063CCA76CCA362ULL,
		0x166B6FC0052D7E4AULL,
		0x0DB87F9BDAA77650ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E3BB67AC1FF9101ULL,
		0x466706DD0B4C8CA0ULL,
		0xB597F49C6AB8A329ULL,
		0xE6C455653E77AB3FULL,
		0xFFB82BE4501EDA68ULL,
		0x095E17F85516A5A1ULL,
		0x7510FA5F3A10BBABULL,
		0x06F4C28F658F89E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C776CF583FF2202ULL,
		0x8CCE0DBA16991941ULL,
		0x6B2FE938D5714652ULL,
		0xCD88AACA7CEF567FULL,
		0xFF7057C8A03DB4D1ULL,
		0x12BC2FF0AA2D4B43ULL,
		0xEA21F4BE74217756ULL,
		0x0DE9851ECB1F13D2ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA93314DDB729790ULL,
		0xBBC4DA636B833A52ULL,
		0xE1DC95F209D70717ULL,
		0xEF15C43AAB3B667FULL,
		0x4706F7E18344FBACULL,
		0x9897C9E5C0AFBAE1ULL,
		0xC77A4A61FC381CD5ULL,
		0x3670A9A1BFD3D181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7526629BB6E52F20ULL,
		0x7789B4C6D70674A5ULL,
		0xC3B92BE413AE0E2FULL,
		0xDE2B88755676CCFFULL,
		0x8E0DEFC30689F759ULL,
		0x312F93CB815F75C2ULL,
		0x8EF494C3F87039ABULL,
		0x6CE153437FA7A303ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEE1E7027A7FFC52ULL,
		0xBB31C362058DE0B1ULL,
		0xDD36A92FB0B9DE52ULL,
		0x54FC7844B2C075ABULL,
		0xBB9E8041EEB72E06ULL,
		0x9ABD6A2AFE863C7BULL,
		0x859957AB39AF45A8ULL,
		0x32740A2A5FFD5945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC3CE04F4FFF8A4ULL,
		0x766386C40B1BC163ULL,
		0xBA6D525F6173BCA5ULL,
		0xA9F8F0896580EB57ULL,
		0x773D0083DD6E5C0CULL,
		0x357AD455FD0C78F7ULL,
		0x0B32AF56735E8B51ULL,
		0x64E81454BFFAB28BULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2656EE8616BF12D5ULL,
		0xF4D83FC1986F5594ULL,
		0xCE08222BD1C0567EULL,
		0xB3616E47DE7691DFULL,
		0xBE474CC328CA147AULL,
		0x33D5AB4D94EEFE4AULL,
		0xFE3F376D1F7BCA4DULL,
		0x19891DA28BC65D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CADDD0C2D7E25AAULL,
		0xE9B07F8330DEAB28ULL,
		0x9C104457A380ACFDULL,
		0x66C2DC8FBCED23BFULL,
		0x7C8E9986519428F5ULL,
		0x67AB569B29DDFC95ULL,
		0xFC7E6EDA3EF7949AULL,
		0x33123B45178CBB23ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4B8AB1D7AC458B6ULL,
		0xCB0A4EA1E25B0CD1ULL,
		0x0810E8427CF8BA40ULL,
		0x38EBC256B53E66DFULL,
		0x805DC02D7000E77DULL,
		0x20DC6DDF8FB971A5ULL,
		0x785DB72F6B46A6F0ULL,
		0x3605A4FB4314601AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8971563AF588B16CULL,
		0x96149D43C4B619A3ULL,
		0x1021D084F9F17481ULL,
		0x71D784AD6A7CCDBEULL,
		0x00BB805AE001CEFAULL,
		0x41B8DBBF1F72E34BULL,
		0xF0BB6E5ED68D4DE0ULL,
		0x6C0B49F68628C034ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40E905D91837C260ULL,
		0x44339EAB29B6941CULL,
		0xE6ADCE4A14BC87A3ULL,
		0x2A7A1C16575B7ECAULL,
		0x115F4FDB5F6A5639ULL,
		0x35E34228542BC807ULL,
		0x6730373D166C9A29ULL,
		0x3072D0334AEFB781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D20BB2306F84C0ULL,
		0x88673D56536D2838ULL,
		0xCD5B9C9429790F46ULL,
		0x54F4382CAEB6FD95ULL,
		0x22BE9FB6BED4AC72ULL,
		0x6BC68450A857900EULL,
		0xCE606E7A2CD93452ULL,
		0x60E5A06695DF6F02ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39041005D958BE1FULL,
		0xAD1F314A4FD17FE8ULL,
		0x8BD373BF52813B72ULL,
		0xE105EA2E616C34F4ULL,
		0xD093BD1272F83DB0ULL,
		0x798BFC790EBB92F0ULL,
		0x0A38D2C6F8C1FAFEULL,
		0x22CB917D664E9193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7208200BB2B17C3EULL,
		0x5A3E62949FA2FFD0ULL,
		0x17A6E77EA50276E5ULL,
		0xC20BD45CC2D869E9ULL,
		0xA1277A24E5F07B61ULL,
		0xF317F8F21D7725E1ULL,
		0x1471A58DF183F5FCULL,
		0x459722FACC9D2326ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80F73747E641B73CULL,
		0xAACE9244D15A5074ULL,
		0xB5637AB7D590D0AFULL,
		0x8F94C45BC5BEFC1FULL,
		0xD0A32EB1A61050DFULL,
		0x72DFB7278B89A458ULL,
		0xFD6905B6BB65C589ULL,
		0x308FD3E6511D63D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01EE6E8FCC836E78ULL,
		0x559D2489A2B4A0E9ULL,
		0x6AC6F56FAB21A15FULL,
		0x1F2988B78B7DF83FULL,
		0xA1465D634C20A1BFULL,
		0xE5BF6E4F171348B1ULL,
		0xFAD20B6D76CB8B12ULL,
		0x611FA7CCA23AC7B3ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE507C22D8AEB9708ULL,
		0xC719AC9050C86767ULL,
		0x172E818B3A7DE022ULL,
		0xC81F4D0735F87DE9ULL,
		0xFD1AB0DBB563A1B3ULL,
		0xB40B81DE6D101580ULL,
		0x4D3946405051F862ULL,
		0x26376C183CB69D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0F845B15D72E10ULL,
		0x8E335920A190CECFULL,
		0x2E5D031674FBC045ULL,
		0x903E9A0E6BF0FBD2ULL,
		0xFA3561B76AC74367ULL,
		0x681703BCDA202B01ULL,
		0x9A728C80A0A3F0C5ULL,
		0x4C6ED830796D3B22ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82D852A527272009ULL,
		0xD0D5EBB60B3E3452ULL,
		0x76EEB91E9F9E7872ULL,
		0x809B512DAF6CF0C8ULL,
		0x76A2BA6EDD685EDDULL,
		0x75C832B4B0D1D344ULL,
		0x1A628A3ED5740D83ULL,
		0x17B108E32E69F5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B0A54A4E4E4012ULL,
		0xA1ABD76C167C68A5ULL,
		0xEDDD723D3F3CF0E5ULL,
		0x0136A25B5ED9E190ULL,
		0xED4574DDBAD0BDBBULL,
		0xEB90656961A3A688ULL,
		0x34C5147DAAE81B06ULL,
		0x2F6211C65CD3EBB6ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17BE9E4C8BFFF627ULL,
		0x6A752FA805853823ULL,
		0xA5C723E1A85357B2ULL,
		0xE0D5EDFE48F899F8ULL,
		0xB871FD89DBFE90C4ULL,
		0xF0785EF15B2DD82EULL,
		0x16BA6FD2CE315977ULL,
		0x32226E57CF707481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F7D3C9917FFEC4EULL,
		0xD4EA5F500B0A7046ULL,
		0x4B8E47C350A6AF64ULL,
		0xC1ABDBFC91F133F1ULL,
		0x70E3FB13B7FD2189ULL,
		0xE0F0BDE2B65BB05DULL,
		0x2D74DFA59C62B2EFULL,
		0x6444DCAF9EE0E902ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28E7BE226A4D2728ULL,
		0xF309727D7F35AB91ULL,
		0x72AC59A367E55A3FULL,
		0x95CD635CDCDDBA86ULL,
		0x567833134E97A225ULL,
		0x270BA14F47412DE7ULL,
		0xFA485AA385EB9C88ULL,
		0x1C48FD6174408891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51CF7C44D49A4E50ULL,
		0xE612E4FAFE6B5722ULL,
		0xE558B346CFCAB47FULL,
		0x2B9AC6B9B9BB750CULL,
		0xACF066269D2F444BULL,
		0x4E17429E8E825BCEULL,
		0xF490B5470BD73910ULL,
		0x3891FAC2E8811123ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03E55A42629E7045ULL,
		0x8A75518CE1A2A415ULL,
		0x18C49193357DE1E3ULL,
		0x4131E55764A29894ULL,
		0x0798C78CA7DD7760ULL,
		0x32066D3BA95AA099ULL,
		0xAC0843F221593A70ULL,
		0x1CCC42D501FC67E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07CAB484C53CE08AULL,
		0x14EAA319C345482AULL,
		0x318923266AFBC3C7ULL,
		0x8263CAAEC9453128ULL,
		0x0F318F194FBAEEC0ULL,
		0x640CDA7752B54132ULL,
		0x581087E442B274E0ULL,
		0x399885AA03F8CFCFULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7691FEC068CB2DA8ULL,
		0x662E1A81B704D796ULL,
		0xA5AB64686878C84DULL,
		0x89B7B22D8BA32C25ULL,
		0x2365BF6F435DFF44ULL,
		0x91F61F0958C0544AULL,
		0x7C278EECD04F1915ULL,
		0x38F817A66EC0B988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED23FD80D1965B50ULL,
		0xCC5C35036E09AF2CULL,
		0x4B56C8D0D0F1909AULL,
		0x136F645B1746584BULL,
		0x46CB7EDE86BBFE89ULL,
		0x23EC3E12B180A894ULL,
		0xF84F1DD9A09E322BULL,
		0x71F02F4CDD817310ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95DD0B9A7D267533ULL,
		0xD547E09445BB1AA0ULL,
		0xACF94677BED9798DULL,
		0x70CEDF2E35FE2AB2ULL,
		0x6610CE2E7F223A7AULL,
		0x5E7B60E6F3D53209ULL,
		0x6F3D04939E628774ULL,
		0x083252351893A789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BBA1734FA4CEA66ULL,
		0xAA8FC1288B763541ULL,
		0x59F28CEF7DB2F31BULL,
		0xE19DBE5C6BFC5565ULL,
		0xCC219C5CFE4474F4ULL,
		0xBCF6C1CDE7AA6412ULL,
		0xDE7A09273CC50EE8ULL,
		0x1064A46A31274F12ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F111259906D3052ULL,
		0xDA42C4B20CCBFF41ULL,
		0x9FD6D7F203230165ULL,
		0x1F7A344FF69D1C7DULL,
		0x5F073B657FA1D847ULL,
		0xD22C5B3EB945A04BULL,
		0xBA616E338A33CEC1ULL,
		0x165B19CE3A3BA411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2224B320DA60A4ULL,
		0xB48589641997FE83ULL,
		0x3FADAFE4064602CBULL,
		0x3EF4689FED3A38FBULL,
		0xBE0E76CAFF43B08EULL,
		0xA458B67D728B4096ULL,
		0x74C2DC6714679D83ULL,
		0x2CB6339C74774823ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFFB38E601641FC5ULL,
		0x5510D6D76E00B3ECULL,
		0xE7F9ACD0832600B1ULL,
		0x4DBA7EEC4E92EBA7ULL,
		0xBD0762F6D51F24D2ULL,
		0x3C20AAC21B2FD4B1ULL,
		0x8F2201B39CF7CACCULL,
		0x38848A9C8BD61C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FF671CC02C83F8AULL,
		0xAA21ADAEDC0167D9ULL,
		0xCFF359A1064C0162ULL,
		0x9B74FDD89D25D74FULL,
		0x7A0EC5EDAA3E49A4ULL,
		0x78415584365FA963ULL,
		0x1E44036739EF9598ULL,
		0x7109153917AC393FULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6020B21E2056322FULL,
		0x4A6FF602725A4D1EULL,
		0xCFF16AE46CB2F2F4ULL,
		0x320D64E621356657ULL,
		0xEA647AC56373953DULL,
		0x6B65D19BE65011F2ULL,
		0x660D2007C849E7CEULL,
		0x15CD0968CCFAC7A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC041643C40AC645EULL,
		0x94DFEC04E4B49A3CULL,
		0x9FE2D5C8D965E5E8ULL,
		0x641AC9CC426ACCAFULL,
		0xD4C8F58AC6E72A7AULL,
		0xD6CBA337CCA023E5ULL,
		0xCC1A400F9093CF9CULL,
		0x2B9A12D199F58F52ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2847DFEE54E536CULL,
		0xBA5D907E19C56F28ULL,
		0xACA2083087AF047BULL,
		0x0DBCD32ECDB80AD8ULL,
		0x5FEA1C48B428A4B7ULL,
		0x0025AE94FE8B2431ULL,
		0x301B77A94B2D3D3CULL,
		0x3021193555491745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA508FBFDCA9CA6D8ULL,
		0x74BB20FC338ADE51ULL,
		0x594410610F5E08F7ULL,
		0x1B79A65D9B7015B1ULL,
		0xBFD438916851496EULL,
		0x004B5D29FD164862ULL,
		0x6036EF52965A7A78ULL,
		0x6042326AAA922E8AULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92A3032D7766E38CULL,
		0x09ED8E3E740CECB6ULL,
		0x7CEC41F97023D5B4ULL,
		0x8D6EF684B7DF8726ULL,
		0xAFBCA170B8E83A73ULL,
		0x7671C8A601F3422CULL,
		0x8F81415278E49BB0ULL,
		0x273110DCE491F675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2546065AEECDC718ULL,
		0x13DB1C7CE819D96DULL,
		0xF9D883F2E047AB68ULL,
		0x1ADDED096FBF0E4CULL,
		0x5F7942E171D074E7ULL,
		0xECE3914C03E68459ULL,
		0x1F0282A4F1C93760ULL,
		0x4E6221B9C923ECEBULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C6E26A6D3343F5BULL,
		0xE30E9D382D4EAF93ULL,
		0x96D0CCB162F2D679ULL,
		0x9DA33A0D3E5D7524ULL,
		0xEA92AF384B55DFD7ULL,
		0xC4188D49AB5EE7EDULL,
		0x115F1931A3A6FD94ULL,
		0x33F9858979850703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38DC4D4DA6687EB6ULL,
		0xC61D3A705A9D5F26ULL,
		0x2DA19962C5E5ACF3ULL,
		0x3B46741A7CBAEA49ULL,
		0xD5255E7096ABBFAFULL,
		0x88311A9356BDCFDBULL,
		0x22BE3263474DFB29ULL,
		0x67F30B12F30A0E06ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27D053772884EAD9ULL,
		0x96E1F50F08BCEC7FULL,
		0x54FA16139A23E08DULL,
		0x0C92FE0B0E7C82A9ULL,
		0x59BB1A1956BED406ULL,
		0x24F4060908AA7504ULL,
		0x213C7D57A1E53FEAULL,
		0x0B7FCCDB79DBA905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FA0A6EE5109D5B2ULL,
		0x2DC3EA1E1179D8FEULL,
		0xA9F42C273447C11BULL,
		0x1925FC161CF90552ULL,
		0xB3763432AD7DA80CULL,
		0x49E80C121154EA08ULL,
		0x4278FAAF43CA7FD4ULL,
		0x16FF99B6F3B7520AULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC511878C5E988724ULL,
		0xF915AFA2F148F976ULL,
		0xAEC0F7D437C3EF1DULL,
		0xDE7F031C0A00866BULL,
		0x522B33DCDBD0B2D8ULL,
		0x8C0D9AABBCE99498ULL,
		0x2307281DB7AE3D8AULL,
		0x3DD190E1E3BA5432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A230F18BD310E48ULL,
		0xF22B5F45E291F2EDULL,
		0x5D81EFA86F87DE3BULL,
		0xBCFE063814010CD7ULL,
		0xA45667B9B7A165B1ULL,
		0x181B355779D32930ULL,
		0x460E503B6F5C7B15ULL,
		0x7BA321C3C774A864ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x065651D73F50828FULL,
		0xE9368A5DF752C22BULL,
		0x52EE08BE1EEAB8DCULL,
		0x25DF67AE076C2465ULL,
		0xF733538DB108F156ULL,
		0x874FCD7ECF130374ULL,
		0xCCD5B9D06D48CCB4ULL,
		0x313E66E5BC17A83CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CACA3AE7EA1051EULL,
		0xD26D14BBEEA58456ULL,
		0xA5DC117C3DD571B9ULL,
		0x4BBECF5C0ED848CAULL,
		0xEE66A71B6211E2ACULL,
		0x0E9F9AFD9E2606E9ULL,
		0x99AB73A0DA919969ULL,
		0x627CCDCB782F5079ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1368D0A71ED6D0AULL,
		0xA252FDA838328229ULL,
		0x1BB35BEB080F75F0ULL,
		0xA4DEFE5BC08BD5A7ULL,
		0x13E5D605FBB71D2EULL,
		0x94EA3923E0DFBFA9ULL,
		0x78B470C8623914C4ULL,
		0x06D3B6AC3AB97F21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x826D1A14E3DADA14ULL,
		0x44A5FB5070650453ULL,
		0x3766B7D6101EEBE1ULL,
		0x49BDFCB78117AB4EULL,
		0x27CBAC0BF76E3A5DULL,
		0x29D47247C1BF7F52ULL,
		0xF168E190C4722989ULL,
		0x0DA76D587572FE42ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7240351158F1672BULL,
		0x6E4CE8D43D83CDAFULL,
		0x1DE2A0BC27372DB1ULL,
		0x24742C3C7AC80709ULL,
		0x4F59367599A394D7ULL,
		0x8C84F8A7F3D9C1B8ULL,
		0x0049414B2F614750ULL,
		0x3D945B801FB4BC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4806A22B1E2CE56ULL,
		0xDC99D1A87B079B5EULL,
		0x3BC541784E6E5B62ULL,
		0x48E85878F5900E12ULL,
		0x9EB26CEB334729AEULL,
		0x1909F14FE7B38370ULL,
		0x009282965EC28EA1ULL,
		0x7B28B7003F697852ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC948A69DBA3D8FF4ULL,
		0x47207643E6CF22A8ULL,
		0x9FEEF5003E20AE26ULL,
		0x764C022595B3D313ULL,
		0x0C48A78128EB2C0DULL,
		0x0EF0F6C9F8F42683ULL,
		0x3F7027B098AEAABAULL,
		0x06C403182EC0B569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92914D3B747B1FE8ULL,
		0x8E40EC87CD9E4551ULL,
		0x3FDDEA007C415C4CULL,
		0xEC98044B2B67A627ULL,
		0x18914F0251D6581AULL,
		0x1DE1ED93F1E84D06ULL,
		0x7EE04F61315D5574ULL,
		0x0D8806305D816AD2ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA7B169E60FCE5DBULL,
		0x06DF7415CD099F9DULL,
		0xF3FD1E0BCBE18930ULL,
		0xA936D86E20677122ULL,
		0x4E2565509F6C2FACULL,
		0xD293E6BAC865FCD2ULL,
		0x9E6463F05DB2C8D2ULL,
		0x1D74E307BA1D8CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54F62D3CC1F9CBB6ULL,
		0x0DBEE82B9A133F3BULL,
		0xE7FA3C1797C31260ULL,
		0x526DB0DC40CEE245ULL,
		0x9C4ACAA13ED85F59ULL,
		0xA527CD7590CBF9A4ULL,
		0x3CC8C7E0BB6591A5ULL,
		0x3AE9C60F743B19D5ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F85681872758FECULL,
		0x8BE6D5E2F2A42235ULL,
		0xB155F3DB9CA7650FULL,
		0x0924D688944A9FF9ULL,
		0xD875DF003BCFF7C0ULL,
		0xF27F2B33D9F68F70ULL,
		0xCCD8D6444418AE65ULL,
		0x14AE30B00B07F550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0AD030E4EB1FD8ULL,
		0x17CDABC5E548446AULL,
		0x62ABE7B7394ECA1FULL,
		0x1249AD1128953FF3ULL,
		0xB0EBBE00779FEF80ULL,
		0xE4FE5667B3ED1EE1ULL,
		0x99B1AC8888315CCBULL,
		0x295C6160160FEAA1ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ABB158B59B19505ULL,
		0x0D68A4499385DDB2ULL,
		0xA0F00AECB85B3A96ULL,
		0x475A533E72E07919ULL,
		0x3E1755637B065C96ULL,
		0x8C6E73BF04B0FFFFULL,
		0x44BF84030C1E4EA7ULL,
		0x0BBEE6CC70CDAFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35762B16B3632A0AULL,
		0x1AD14893270BBB65ULL,
		0x41E015D970B6752CULL,
		0x8EB4A67CE5C0F233ULL,
		0x7C2EAAC6F60CB92CULL,
		0x18DCE77E0961FFFEULL,
		0x897F0806183C9D4FULL,
		0x177DCD98E19B5FDEULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x737AB8E5C6CDB3B5ULL,
		0xBF7E1185123E1E89ULL,
		0xE9EE7CC2F9A791AAULL,
		0xD5604B03A37C3368ULL,
		0x669735DF195C6DDAULL,
		0x19C1A19ABD7CC2DAULL,
		0xDDF0C21B322A3E6CULL,
		0x167CAE1F474025F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6F571CB8D9B676AULL,
		0x7EFC230A247C3D12ULL,
		0xD3DCF985F34F2355ULL,
		0xAAC0960746F866D1ULL,
		0xCD2E6BBE32B8DBB5ULL,
		0x338343357AF985B4ULL,
		0xBBE1843664547CD8ULL,
		0x2CF95C3E8E804BEDULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED77DC50C9ED3F33ULL,
		0x9B3CCED859753258ULL,
		0x08A85A76F08D5E5BULL,
		0xB49E0802C37578ACULL,
		0x9CACBBE6277D7E89ULL,
		0x292F5D03BA27AC95ULL,
		0xA07285723D008967ULL,
		0x175F218FABB84603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAEFB8A193DA7E66ULL,
		0x36799DB0B2EA64B1ULL,
		0x1150B4EDE11ABCB7ULL,
		0x693C100586EAF158ULL,
		0x395977CC4EFAFD13ULL,
		0x525EBA07744F592BULL,
		0x40E50AE47A0112CEULL,
		0x2EBE431F57708C07ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93E7C7231E029EEDULL,
		0xF9CA1F402087AC61ULL,
		0x4F39AB052E32539BULL,
		0x97B1AA9D0171C928ULL,
		0xB9693A3D9BC54C2DULL,
		0xC3258D432E3C484FULL,
		0x4278049819E3AFEFULL,
		0x082EE0232312C661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27CF8E463C053DDAULL,
		0xF3943E80410F58C3ULL,
		0x9E73560A5C64A737ULL,
		0x2F63553A02E39250ULL,
		0x72D2747B378A985BULL,
		0x864B1A865C78909FULL,
		0x84F0093033C75FDFULL,
		0x105DC04646258CC2ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E2F44BAAB08C580ULL,
		0xE60F8582A5F5B7DAULL,
		0x7B503BCE4BB96EF6ULL,
		0x97D5DF3A209E5AA1ULL,
		0xF0E1DE8E599E5474ULL,
		0xECE8FE6EEEC3558CULL,
		0xB16893273291B22DULL,
		0x130C247DA847EE81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C5E897556118B00ULL,
		0xCC1F0B054BEB6FB5ULL,
		0xF6A0779C9772DDEDULL,
		0x2FABBE74413CB542ULL,
		0xE1C3BD1CB33CA8E9ULL,
		0xD9D1FCDDDD86AB19ULL,
		0x62D1264E6523645BULL,
		0x261848FB508FDD03ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79132F406F8C6A37ULL,
		0x2E5B45939CF60F7CULL,
		0xC34A5FD28A933DA6ULL,
		0x1FEB97BA450C6BDFULL,
		0x2A7F7D8E1F8E67A5ULL,
		0xD8487C5A305E57ACULL,
		0x36A3D5ABF70CA187ULL,
		0x3816DFA4D2237B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2265E80DF18D46EULL,
		0x5CB68B2739EC1EF8ULL,
		0x8694BFA515267B4CULL,
		0x3FD72F748A18D7BFULL,
		0x54FEFB1C3F1CCF4AULL,
		0xB090F8B460BCAF58ULL,
		0x6D47AB57EE19430FULL,
		0x702DBF49A446F63CULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7687527D5EA5A66CULL,
		0x4C3099AA0C1FFF34ULL,
		0x29E4FB8C196AD267ULL,
		0x4628EEAFBE245140ULL,
		0x8A9A6DC7CB900B15ULL,
		0x1D11695D11D04461ULL,
		0x305AD211F9B23668ULL,
		0x11962863E27DFB4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED0EA4FABD4B4CD8ULL,
		0x98613354183FFE68ULL,
		0x53C9F71832D5A4CEULL,
		0x8C51DD5F7C48A280ULL,
		0x1534DB8F9720162AULL,
		0x3A22D2BA23A088C3ULL,
		0x60B5A423F3646CD0ULL,
		0x232C50C7C4FBF694ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD27E752CEBD6BC55ULL,
		0x9C9D6FEA641EF4F0ULL,
		0xC32E52E51D9BB59FULL,
		0x323D7A83BB26D368ULL,
		0xCE4B5AAAFA4A30E8ULL,
		0x5C087059D046B400ULL,
		0xD8A084B026F2E471ULL,
		0x2A9FD8347DE9812DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4FCEA59D7AD78AAULL,
		0x393ADFD4C83DE9E1ULL,
		0x865CA5CA3B376B3FULL,
		0x647AF507764DA6D1ULL,
		0x9C96B555F49461D0ULL,
		0xB810E0B3A08D6801ULL,
		0xB14109604DE5C8E2ULL,
		0x553FB068FBD3025BULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B57A040F6C92169ULL,
		0xEE42C719FF1B74C7ULL,
		0x7CE3139EFDA9E413ULL,
		0x85765326ACFD7356ULL,
		0xCD9A1BBA26A6956AULL,
		0xB0BA9C5403B60599ULL,
		0xD7DC76FC23C5F1F9ULL,
		0x01AD1E101106E820ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36AF4081ED9242D2ULL,
		0xDC858E33FE36E98EULL,
		0xF9C6273DFB53C827ULL,
		0x0AECA64D59FAE6ACULL,
		0x9B3437744D4D2AD5ULL,
		0x617538A8076C0B33ULL,
		0xAFB8EDF8478BE3F3ULL,
		0x035A3C20220DD041ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5555F161209C9E1BULL,
		0xA06F3351AE791E3EULL,
		0x3E2087E5739017F6ULL,
		0xE9011865388D75E4ULL,
		0x74A28F19F8EAE573ULL,
		0x046E1D18AF8C184DULL,
		0x354482B800D9B455ULL,
		0x22AF1DA46D4823FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAABE2C241393C36ULL,
		0x40DE66A35CF23C7CULL,
		0x7C410FCAE7202FEDULL,
		0xD20230CA711AEBC8ULL,
		0xE9451E33F1D5CAE7ULL,
		0x08DC3A315F18309AULL,
		0x6A89057001B368AAULL,
		0x455E3B48DA9047FEULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFFEE8C031A3023EULL,
		0xAE7992C3BD6BFCD3ULL,
		0xED6003463D824314ULL,
		0x96D35F3F31962901ULL,
		0xBF4582516776B49CULL,
		0x9745717038ADBD54ULL,
		0xEB51FA167422FAAFULL,
		0x027BA687098F4F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFFDD1806346047CULL,
		0x5CF325877AD7F9A7ULL,
		0xDAC0068C7B048629ULL,
		0x2DA6BE7E632C5203ULL,
		0x7E8B04A2CEED6939ULL,
		0x2E8AE2E0715B7AA9ULL,
		0xD6A3F42CE845F55FULL,
		0x04F74D0E131E9E81ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C16F1511F354469ULL,
		0x3B89A0E1B6F720E0ULL,
		0x8E7B47D493ADA7A6ULL,
		0xAA3A4E976D6A0BA7ULL,
		0x2A3E091527DDA01CULL,
		0x279B6AFC1A8D9EF5ULL,
		0x1A2D09069702F14CULL,
		0x2267E6E6D2034186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182DE2A23E6A88D2ULL,
		0x771341C36DEE41C1ULL,
		0x1CF68FA9275B4F4CULL,
		0x54749D2EDAD4174FULL,
		0x547C122A4FBB4039ULL,
		0x4F36D5F8351B3DEAULL,
		0x345A120D2E05E298ULL,
		0x44CFCDCDA406830CULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3DDC30EC744DD60ULL,
		0xAD9D32BDE8C3AFC2ULL,
		0x8EB012777695A35DULL,
		0x0C527AC93170E6CAULL,
		0x9B47FFCEB2E9709DULL,
		0xD3D61CEAD8CCB65BULL,
		0x0E6A93C509D8DE89ULL,
		0x2F8849C23A54C4A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BB861D8E89BAC0ULL,
		0x5B3A657BD1875F85ULL,
		0x1D6024EEED2B46BBULL,
		0x18A4F59262E1CD95ULL,
		0x368FFF9D65D2E13AULL,
		0xA7AC39D5B1996CB7ULL,
		0x1CD5278A13B1BD13ULL,
		0x5F10938474A9894AULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x344C823062AB4B8AULL,
		0x69536CEB7F4D4748ULL,
		0xF2E0B4CCBBA90D87ULL,
		0xD44868107FB49930ULL,
		0xC8044C5B333DE321ULL,
		0x85A47A533CD26429ULL,
		0x3C87D19CFB986B0AULL,
		0x2F0CE4AB03A8B50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68990460C5569714ULL,
		0xD2A6D9D6FE9A8E90ULL,
		0xE5C1699977521B0EULL,
		0xA890D020FF693261ULL,
		0x900898B6667BC643ULL,
		0x0B48F4A679A4C853ULL,
		0x790FA339F730D615ULL,
		0x5E19C95607516A1CULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AF346CEEBF2BE57ULL,
		0xEE376292E4FFE9A0ULL,
		0x29BCB2F4B557AF9AULL,
		0x727C08E1D9A66E4CULL,
		0x52EB3DB710350F09ULL,
		0x2C88EA6CE31C30DBULL,
		0x614FCB2F791FDC3DULL,
		0x090ED2A4686AB503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5E68D9DD7E57CAEULL,
		0xDC6EC525C9FFD340ULL,
		0x537965E96AAF5F35ULL,
		0xE4F811C3B34CDC98ULL,
		0xA5D67B6E206A1E12ULL,
		0x5911D4D9C63861B6ULL,
		0xC29F965EF23FB87AULL,
		0x121DA548D0D56A06ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AA0CA0C343C9F5BULL,
		0xA0151F0C41BEDBB9ULL,
		0x910CCECB233C0F44ULL,
		0x147507A66FFB0EE0ULL,
		0x39CA9A03687D4D29ULL,
		0xCCA3AEB5E00FB5F0ULL,
		0x987080CDFABECCA4ULL,
		0x2F8AEF1060C12A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5541941868793EB6ULL,
		0x402A3E18837DB772ULL,
		0x22199D9646781E89ULL,
		0x28EA0F4CDFF61DC1ULL,
		0x73953406D0FA9A52ULL,
		0x99475D6BC01F6BE0ULL,
		0x30E1019BF57D9949ULL,
		0x5F15DE20C182540BULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAB7BD8531EE3277ULL,
		0x93D3CAD54AE610FEULL,
		0x64A822B8835E1FBFULL,
		0x4C2FF53D8D40CEF9ULL,
		0x2BC5DFAFFF993BE8ULL,
		0x4654B524EB281F6BULL,
		0x9FAAE1F64488F5CBULL,
		0x1CAB286452253D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56F7B0A63DC64EEULL,
		0x27A795AA95CC21FDULL,
		0xC950457106BC3F7FULL,
		0x985FEA7B1A819DF2ULL,
		0x578BBF5FFF3277D0ULL,
		0x8CA96A49D6503ED6ULL,
		0x3F55C3EC8911EB96ULL,
		0x395650C8A44A7ABFULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75529E61205AA70CULL,
		0xD19A8F2E8CD4F3ECULL,
		0xC6717A2D8A30E628ULL,
		0x897C3225E8D2D010ULL,
		0xAD76D8BD0D51E7DAULL,
		0x2041C3643CDFE4C7ULL,
		0xD6407D56BB794B86ULL,
		0x2C128CF7623A8AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAA53CC240B54E18ULL,
		0xA3351E5D19A9E7D8ULL,
		0x8CE2F45B1461CC51ULL,
		0x12F8644BD1A5A021ULL,
		0x5AEDB17A1AA3CFB5ULL,
		0x408386C879BFC98FULL,
		0xAC80FAAD76F2970CULL,
		0x582519EEC475158FULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA97BA811BFDF4A0EULL,
		0x6D210E1416C7C373ULL,
		0xDBE3409D5A102795ULL,
		0x1FCAA55F440D87CBULL,
		0x4F25772D0FC5F12CULL,
		0x34C9A49A19471FF0ULL,
		0x589AC90DA3242178ULL,
		0x156C13C1013CCE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F750237FBE941CULL,
		0xDA421C282D8F86E7ULL,
		0xB7C6813AB4204F2AULL,
		0x3F954ABE881B0F97ULL,
		0x9E4AEE5A1F8BE258ULL,
		0x69934934328E3FE0ULL,
		0xB135921B464842F0ULL,
		0x2AD8278202799CF0ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB775F7437E40BD24ULL,
		0xFC63F10F92000979ULL,
		0xD3B9C0AFF5728203ULL,
		0x5F5C7DD66949595BULL,
		0xFA5AE7B2765585BFULL,
		0x0ADC9E57B8E30D52ULL,
		0x98D767A79A02EB0BULL,
		0x1B1FD64D6D7F66C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EEBEE86FC817A48ULL,
		0xF8C7E21F240012F3ULL,
		0xA773815FEAE50407ULL,
		0xBEB8FBACD292B2B7ULL,
		0xF4B5CF64ECAB0B7EULL,
		0x15B93CAF71C61AA5ULL,
		0x31AECF4F3405D616ULL,
		0x363FAC9ADAFECD91ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x083454F3F1213413ULL,
		0x49F0A1A32A7CBBC2ULL,
		0x39AF13725C4D2CCEULL,
		0xAA69817A789DFBEDULL,
		0xA1367DFF3B5E86E1ULL,
		0x9661609D11F206A7ULL,
		0xD96520A2A9CF9865ULL,
		0x297CBCD929A52906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1068A9E7E2426826ULL,
		0x93E1434654F97784ULL,
		0x735E26E4B89A599CULL,
		0x54D302F4F13BF7DAULL,
		0x426CFBFE76BD0DC3ULL,
		0x2CC2C13A23E40D4FULL,
		0xB2CA4145539F30CBULL,
		0x52F979B2534A520DULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C20A8B38DD2EFDULL,
		0xE54D6F90073CCE01ULL,
		0xAC764C72D9381579ULL,
		0xFBD7E185D632F796ULL,
		0xBD46B4629DAC820AULL,
		0x63F661B741AC6628ULL,
		0xF2F96366F96B493AULL,
		0x05D7F93AFAD52980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3384151671BA5DFAULL,
		0xCA9ADF200E799C02ULL,
		0x58EC98E5B2702AF3ULL,
		0xF7AFC30BAC65EF2DULL,
		0x7A8D68C53B590415ULL,
		0xC7ECC36E8358CC51ULL,
		0xE5F2C6CDF2D69274ULL,
		0x0BAFF275F5AA5301ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8787CCC84E24008CULL,
		0x0DEF11B742418716ULL,
		0x4240A306F265B95DULL,
		0x38387FFCC92185C5ULL,
		0xB69B216826577E86ULL,
		0x52DCCDAE0E0EF8ECULL,
		0xFF6C6D63D8B8168AULL,
		0x0F17025402C98ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0F99909C480118ULL,
		0x1BDE236E84830E2DULL,
		0x8481460DE4CB72BAULL,
		0x7070FFF992430B8AULL,
		0x6D3642D04CAEFD0CULL,
		0xA5B99B5C1C1DF1D9ULL,
		0xFED8DAC7B1702D14ULL,
		0x1E2E04A805931599ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EE3B332DAADDD12ULL,
		0x1ACCCD6617633D31ULL,
		0x0D9C75A88ECDF4CFULL,
		0x2E68B3816F14D8AFULL,
		0xE326ABFA84C71F07ULL,
		0x6E0E17C997754742ULL,
		0xBB57952E33380F4DULL,
		0x0540D3758D11C13EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC76665B55BBA24ULL,
		0x35999ACC2EC67A62ULL,
		0x1B38EB511D9BE99EULL,
		0x5CD16702DE29B15EULL,
		0xC64D57F5098E3E0EULL,
		0xDC1C2F932EEA8E85ULL,
		0x76AF2A5C66701E9AULL,
		0x0A81A6EB1A23827DULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7566D1933A810F7FULL,
		0x2B8B8369E5190391ULL,
		0xFBAA7A8C9117E8D7ULL,
		0x0470E678B2B3913FULL,
		0x7BDC54A401B7EE6FULL,
		0xAFDEEFC0E2E570C7ULL,
		0x4F653930D9439437ULL,
		0x29011D30E1CF0028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACDA32675021EFEULL,
		0x571706D3CA320722ULL,
		0xF754F519222FD1AEULL,
		0x08E1CCF16567227FULL,
		0xF7B8A948036FDCDEULL,
		0x5FBDDF81C5CAE18EULL,
		0x9ECA7261B287286FULL,
		0x52023A61C39E0050ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB49377B795F43831ULL,
		0xAD0DA171D2A80815ULL,
		0x83521CAD08148992ULL,
		0x0F242A93E4071FC3ULL,
		0xA2AEFBDBFF43E4C8ULL,
		0x36676314D78CFE29ULL,
		0x21C895E21EE979FCULL,
		0x02041A43D6EAE3D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6926EF6F2BE87062ULL,
		0x5A1B42E3A550102BULL,
		0x06A4395A10291325ULL,
		0x1E485527C80E3F87ULL,
		0x455DF7B7FE87C990ULL,
		0x6CCEC629AF19FC53ULL,
		0x43912BC43DD2F3F8ULL,
		0x04083487ADD5C7B0ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DBFFA160D56CD54ULL,
		0xC653D119C54BADA5ULL,
		0xD068FD29CDDF8AD0ULL,
		0x2BB7799FE4A276B3ULL,
		0x241B162DCA533D1DULL,
		0xCC04C59E5D8D9992ULL,
		0x48ED95E62395294EULL,
		0x218F7B3B82BDE902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7FF42C1AAD9AA8ULL,
		0x8CA7A2338A975B4AULL,
		0xA0D1FA539BBF15A1ULL,
		0x576EF33FC944ED67ULL,
		0x48362C5B94A67A3AULL,
		0x98098B3CBB1B3324ULL,
		0x91DB2BCC472A529DULL,
		0x431EF677057BD204ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36D18F404B82077DULL,
		0xF2746F51F9151583ULL,
		0x0A1E3CD8B3A24B47ULL,
		0x619AA5BB6056E3D8ULL,
		0x5BD79D9B775875C5ULL,
		0x2C1C7B070D80EB43ULL,
		0x7AEDDF64C731B254ULL,
		0x0F1BE5D810B8AB2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA31E8097040EFAULL,
		0xE4E8DEA3F22A2B06ULL,
		0x143C79B16744968FULL,
		0xC3354B76C0ADC7B0ULL,
		0xB7AF3B36EEB0EB8AULL,
		0x5838F60E1B01D686ULL,
		0xF5DBBEC98E6364A8ULL,
		0x1E37CBB021715656ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92D384F56A8A9570ULL,
		0xAB068DEBE21F4213ULL,
		0x3F5CAE13D3263D37ULL,
		0xA3DB76EE4F5EC7E1ULL,
		0x2F9A4F83DB203243ULL,
		0x79530A22D3FE27C6ULL,
		0x19EDAAACDA8A3EF1ULL,
		0x2F251C9FFD381CB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A709EAD5152AE0ULL,
		0x560D1BD7C43E8427ULL,
		0x7EB95C27A64C7A6FULL,
		0x47B6EDDC9EBD8FC2ULL,
		0x5F349F07B6406487ULL,
		0xF2A61445A7FC4F8CULL,
		0x33DB5559B5147DE2ULL,
		0x5E4A393FFA703964ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF71B55F14BF04D1ULL,
		0x28AA11A0C46950AEULL,
		0x5ADF1C4932230684ULL,
		0xA250157BA6E8F4D5ULL,
		0x5B0163BF2D0A740CULL,
		0x4E90935FB2A65D46ULL,
		0x2D6915410CF1DFDDULL,
		0x2956EEC503899F9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EE36ABE297E09A2ULL,
		0x5154234188D2A15DULL,
		0xB5BE389264460D08ULL,
		0x44A02AF74DD1E9AAULL,
		0xB602C77E5A14E819ULL,
		0x9D2126BF654CBA8CULL,
		0x5AD22A8219E3BFBAULL,
		0x52ADDD8A07133F3CULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75FE4D2A467D3F99ULL,
		0x59045E6F3D6892ACULL,
		0x89B691B3726B5B39ULL,
		0x828EB9CA749904F5ULL,
		0x7F19D8729AEBE7AFULL,
		0x2E78CD272A508345ULL,
		0x453F3596DDA93507ULL,
		0x2A9455D2435AD308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBFC9A548CFA7F32ULL,
		0xB208BCDE7AD12558ULL,
		0x136D2366E4D6B672ULL,
		0x051D7394E93209EBULL,
		0xFE33B0E535D7CF5FULL,
		0x5CF19A4E54A1068AULL,
		0x8A7E6B2DBB526A0EULL,
		0x5528ABA486B5A610ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CDA90811F30EC51ULL,
		0xC37D88CE911EA9ADULL,
		0x0218080D2ABEE14CULL,
		0x81F7CC4D2F30A7D3ULL,
		0x57568DE66173E816ULL,
		0x0250FE5AEB096022ULL,
		0x30C640B803FC8D93ULL,
		0x2FBEBDDBE87869E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B521023E61D8A2ULL,
		0x86FB119D223D535AULL,
		0x0430101A557DC299ULL,
		0x03EF989A5E614FA6ULL,
		0xAEAD1BCCC2E7D02DULL,
		0x04A1FCB5D612C044ULL,
		0x618C817007F91B26ULL,
		0x5F7D7BB7D0F0D3C6ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84304D9ED94740BAULL,
		0x89387AC83589839FULL,
		0x0C879F567720E8B5ULL,
		0x5E4EB8DD716946CEULL,
		0xCFBCC53FD63385C2ULL,
		0xE11D2FA322DE1ECEULL,
		0x283510C236841962ULL,
		0x0E1B7823F57A4BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08609B3DB28E8174ULL,
		0x1270F5906B13073FULL,
		0x190F3EACEE41D16BULL,
		0xBC9D71BAE2D28D9CULL,
		0x9F798A7FAC670B84ULL,
		0xC23A5F4645BC3D9DULL,
		0x506A21846D0832C5ULL,
		0x1C36F047EAF497AAULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C4AFF1AEEF6097EULL,
		0x06DEA530A8872C40ULL,
		0x3FCB5D54340E2D96ULL,
		0x245E488BBF3242F7ULL,
		0xAAE308A079AA6D4BULL,
		0x3EB085F50568944DULL,
		0x3CCB56CD563B1098ULL,
		0x20FC0A639E6593E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9895FE35DDEC12FCULL,
		0x0DBD4A61510E5880ULL,
		0x7F96BAA8681C5B2CULL,
		0x48BC91177E6485EEULL,
		0x55C61140F354DA96ULL,
		0x7D610BEA0AD1289BULL,
		0x7996AD9AAC762130ULL,
		0x41F814C73CCB27CAULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6D52F701AB7685CULL,
		0xD0DADB54A07C98E0ULL,
		0xE0A03AF732269534ULL,
		0x1476FFE10BB956CEULL,
		0xAC2F688E2A50C3F3ULL,
		0xBA9FE57D081556E0ULL,
		0x65D7E2A921C8A6BBULL,
		0x1B7E9D08153436F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAA5EE0356ED0B8ULL,
		0xA1B5B6A940F931C1ULL,
		0xC14075EE644D2A69ULL,
		0x28EDFFC21772AD9DULL,
		0x585ED11C54A187E6ULL,
		0x753FCAFA102AADC1ULL,
		0xCBAFC55243914D77ULL,
		0x36FD3A102A686DF2ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ABDCD67496F5020ULL,
		0x6FCBB406F7B5EF97ULL,
		0x9E3EA85CB7AA03F3ULL,
		0x8A24D521486F3E08ULL,
		0x0FA56ED419256E7EULL,
		0x60A1EE445BDEC5C4ULL,
		0x3C6D55BAD06E7BC4ULL,
		0x3F278C5C6CF3AEBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF57B9ACE92DEA040ULL,
		0xDF97680DEF6BDF2EULL,
		0x3C7D50B96F5407E6ULL,
		0x1449AA4290DE7C11ULL,
		0x1F4ADDA8324ADCFDULL,
		0xC143DC88B7BD8B88ULL,
		0x78DAAB75A0DCF788ULL,
		0x7E4F18B8D9E75D78ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00FB2B0F2583D856ULL,
		0x94F2DA271DB79554ULL,
		0x61E29C482E3B4653ULL,
		0x38CD352C6C29BED4ULL,
		0x8CBB603532BF3CF9ULL,
		0x8019C0549D655151ULL,
		0x1D68B719BF282E32ULL,
		0x1816BA82F6E03DFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F6561E4B07B0ACULL,
		0x29E5B44E3B6F2AA8ULL,
		0xC3C538905C768CA7ULL,
		0x719A6A58D8537DA8ULL,
		0x1976C06A657E79F2ULL,
		0x003380A93ACAA2A3ULL,
		0x3AD16E337E505C65ULL,
		0x302D7505EDC07BF4ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE9DAF3F73DBD04EULL,
		0xE3D0ABE0C0DBE422ULL,
		0x5201297D242801FAULL,
		0x65B322A26D285407ULL,
		0x967C11502EBAD24DULL,
		0x48D12E5D96D47121ULL,
		0x74DD4297E61CB0C0ULL,
		0x2C4FA68DAD5F97E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D3B5E7EE7B7A09CULL,
		0xC7A157C181B7C845ULL,
		0xA40252FA485003F5ULL,
		0xCB664544DA50A80EULL,
		0x2CF822A05D75A49AULL,
		0x91A25CBB2DA8E243ULL,
		0xE9BA852FCC396180ULL,
		0x589F4D1B5ABF2FD2ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6574D1694CA1456FULL,
		0x670BB08EFC1468DFULL,
		0x29F6751FA018BFC2ULL,
		0x5E899E20E409CAA9ULL,
		0x1F6C52C78228206BULL,
		0xC4C1F8435FF6124FULL,
		0x4AF2E54A455BA075ULL,
		0x180D35B519F3B0FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE9A2D299428ADEULL,
		0xCE17611DF828D1BEULL,
		0x53ECEA3F40317F84ULL,
		0xBD133C41C8139552ULL,
		0x3ED8A58F045040D6ULL,
		0x8983F086BFEC249EULL,
		0x95E5CA948AB740EBULL,
		0x301A6B6A33E761F8ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5863A62A12360BFFULL,
		0xCD6184545EC47D3BULL,
		0x2B7799BBE2DF474CULL,
		0x14CD4F069708B684ULL,
		0x9D9EBF4550BABCA4ULL,
		0x9DEEB2B35EB23FA4ULL,
		0x4DF7745926505972ULL,
		0x351C57A4A08BAFE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0C74C54246C17FEULL,
		0x9AC308A8BD88FA76ULL,
		0x56EF3377C5BE8E99ULL,
		0x299A9E0D2E116D08ULL,
		0x3B3D7E8AA1757948ULL,
		0x3BDD6566BD647F49ULL,
		0x9BEEE8B24CA0B2E5ULL,
		0x6A38AF4941175FD2ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}