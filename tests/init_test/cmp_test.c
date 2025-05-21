#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x4B6FDE33ADAD5FB7ULL,
		0x3BE858773607B5E4ULL,
		0x92B0E088CA66A496ULL,
		0xC2045B215CE40D4AULL,
		0xB831E4DAD9F3555BULL,
		0xF31AC10AEA7BA1C1ULL,
		0x384F2114E6374DCFULL,
		0x0B93C5D8B66AA831ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x997F59A266C458C0ULL,
		0x8F80A01D7E09E502ULL,
		0xF0C0F86807BF9A13ULL,
		0xBE76F50184ABE130ULL,
		0x1A05ED1098BDBBCCULL,
		0x9CEFD4A9CC3127C4ULL,
		0xFB49E29BE63C1BE2ULL,
		0x27C812B3C0702F61ULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD8C474D448A9ECF6ULL,
		0x3E02B54F74DC0002ULL,
		0x6BF7D9C706D5D672ULL,
		0xF5FA10A4E2B9834EULL,
		0x2957D5D713641CBFULL,
		0xA0B76F8EC430AFF6ULL,
		0x4B3788CFDC54C81AULL,
		0x16237A250CC4D990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82BEE4C557113A7ULL,
		0x04572C53E4A7BA51ULL,
		0x5F5299DBF4DFA35BULL,
		0xAD99AFD0C4A951E2ULL,
		0x1288C73F0A828B87ULL,
		0x0296FDD6CEC8A62FULL,
		0x72A627815C467F3AULL,
		0xE4911840BAB5AA9AULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA5BB1896698D582AULL,
		0xE5CC4A0C79300A45ULL,
		0x83344AA10ADE8120ULL,
		0xE9FC6C7EDB8E8F36ULL,
		0x2C6B6A776D52B555ULL,
		0x15314142D1635006ULL,
		0x2C973B9C9C3AF6FFULL,
		0x6AE382BFF1E18320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1562328B66C1584ULL,
		0x4F018C4554E0EF9DULL,
		0x45EEA24DDE9D4AF9ULL,
		0x068B6C320BC75B30ULL,
		0x8B07CB7F5B2FD146ULL,
		0x1A0077772A38A0F8ULL,
		0x515B7CE1E4255F03ULL,
		0x7B6348375ECA1435ULL
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
		0x0C43C570FBCB92E7ULL,
		0xAE0AA1E714E98E0AULL,
		0x501EBE9A3000669BULL,
		0x5C52979BC92E18C0ULL,
		0x0D7F4DDC6C0F8E8BULL,
		0x57F29EF111053A94ULL,
		0x31F28A93B3CF8025ULL,
		0x0F7BC81DAA9AE392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x604BE2B5D089D99BULL,
		0xC2713C317A694784ULL,
		0xB279EC7BB1374F7BULL,
		0x8537ED495E3E2DDCULL,
		0xE2F8FB151C715380ULL,
		0xD6AEFEFDA5860F26ULL,
		0xAEB7077E1BECDFF7ULL,
		0xFFB87BB1AEB1CFABULL
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
		0x501417073B26AD0BULL,
		0x3417FCA947490BEFULL,
		0x95485377CA62EA06ULL,
		0xE4939FEBC5AD7F60ULL,
		0x002CC5B8A303EDA7ULL,
		0x66A142833AD8DD17ULL,
		0xC408953521C429F3ULL,
		0xF54B4AD5FB8C11BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x501417073B26AD0BULL,
		0x3417FCA947490BEFULL,
		0x95485377CA62EA06ULL,
		0xE4939FEBC5AD7F60ULL,
		0x002CC5B8A303EDA7ULL,
		0x66A142833AD8DD17ULL,
		0xC408953521C429F3ULL,
		0xF54B4AD5FB8C11BDULL
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
		0x4AA19A8371776048ULL,
		0x6C038D4ED09858C8ULL,
		0x6ECAE13FB74212E1ULL,
		0x0D65993485C27714ULL,
		0x2041FB84635077F7ULL,
		0xED55C4C86053392FULL,
		0x5BE6D517190BFBD2ULL,
		0xB34C6B10C86CEF2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDED44E44F84BAFA5ULL,
		0x0D4D3E8D3128C267ULL,
		0x26847037F62D1EC7ULL,
		0x01E9A8F3D428C849ULL,
		0xBD2C5F9627A7239CULL,
		0xAE0780846FC2F56EULL,
		0x1F4F3EBBD532589FULL,
		0x8C6BEDCA01AA6ED0ULL
	}};
	t = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x63C6B35C07910F16ULL,
		0x4663CB486A298C30ULL,
		0x8B312B03460AE507ULL,
		0x51D7BCD2A687CCD6ULL,
		0xF8C330D4E06D7060ULL,
		0x28FB9EB159DEAFAEULL,
		0x3B2A9ED59144F007ULL,
		0x78DBC403245825CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD285A2209D9474ULL,
		0x2DB5982C725E8943ULL,
		0x5C2FFB3154450589ULL,
		0x127E52237225B6D1ULL,
		0x10FC9C7FDFFCE642ULL,
		0xDFD0748724D8F5E7ULL,
		0xDFF8FD021C7102C2ULL,
		0xEB66353E06B791D1ULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCAD508C268C44102ULL,
		0x2435B08C1D2CDDDBULL,
		0x723BEB9EFB948624ULL,
		0xAFBE2094F6C7DBB7ULL,
		0x1D8019BF4A0CEE33ULL,
		0x3B05D479114B9ED2ULL,
		0x16C844B30CA41892ULL,
		0x3F15CBA59A23AFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE7DFEBC9D186763ULL,
		0x84B08B3D44176527ULL,
		0x9B6156DBF33F47D1ULL,
		0x70717DD7F3CDC3BFULL,
		0xFD72767D75C5F47AULL,
		0x39CEFA106F2A8FFEULL,
		0x49C61C070A4500E5ULL,
		0x92CDE0999E6910FFULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE8D690BDFD1AB179ULL,
		0x6C749C218402C5B5ULL,
		0x1EBFEDC41F0C6C5BULL,
		0x7636AE5EDA77ED72ULL,
		0xB024D3C8395E0B05ULL,
		0x341E0389E16CBFDEULL,
		0xA2CB2D5E5EB8FD5AULL,
		0xC12AD18D0EF6D9D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D690BDFD1AB179ULL,
		0x6C749C218402C5B5ULL,
		0x1EBFEDC41F0C6C5BULL,
		0x7636AE5EDA77ED72ULL,
		0xB024D3C8395E0B05ULL,
		0x341E0389E16CBFDEULL,
		0xA2CB2D5E5EB8FD5AULL,
		0xC12AD18D0EF6D9D6ULL
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
		0x9006399521DBE39CULL,
		0x719A91ED11A0CC1DULL,
		0xDFB79A7FAB4E2B43ULL,
		0x40114E0E10D43442ULL,
		0x78D6CE5D8EA5EDC7ULL,
		0x091D5AA8A8ED7B62ULL,
		0x4920F553591BDBE2ULL,
		0x59A7FF27505B4375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF72791977C2574ULL,
		0x86654C399425DE98ULL,
		0x8C01AA373E3BC254ULL,
		0x5193DADF3D4FA7BEULL,
		0x8D4208CFEF068EBDULL,
		0xEB229A1E88BA0C27ULL,
		0x0AAB312292367C3FULL,
		0xE6AF5C3ABC332757ULL
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
		0x3420B558F4C3C13DULL,
		0xD6384245832B19F0ULL,
		0x49862D123B8D2E95ULL,
		0x5B7F5D237F06CC34ULL,
		0xFDDF45233BFBE4C4ULL,
		0x6E9C505C4767FA8AULL,
		0x92EB06B19FC3EE25ULL,
		0x0B81B2743B4D5DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D0283AD0AC736D0ULL,
		0x16AE6826D4A7563DULL,
		0xEE5204A6ABC1765AULL,
		0xF81950E74B7CA80DULL,
		0xB7EA01F775FD2548ULL,
		0x6974EE9D39B9EEE4ULL,
		0x139877AC3354BCB9ULL,
		0xC74F5A1CE8CBAC84ULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x621E2DFB041AFCE9ULL,
		0xEE6BACDE834C2A66ULL,
		0xF7B38FF6CF846989ULL,
		0xA9EB5E2AF2E723D7ULL,
		0x13D5B8AD467DA4AFULL,
		0x96384D27A98D9F33ULL,
		0x35C8E475FFA106F2ULL,
		0x7D92A222BE3F8120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF37646EE130AAF1ULL,
		0xCF6896543DBAB509ULL,
		0x630A8F2E2B6B33A3ULL,
		0x11280E476587AAE6ULL,
		0xCB421E93A7569C45ULL,
		0xFD2EDD02AC6FCCDCULL,
		0x9C8C2F59A79BA977ULL,
		0xCA33A9168204907DULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF050E6AC2B83FD37ULL,
		0x19870E1942CCB207ULL,
		0xF549826746271CC3ULL,
		0xCB761E05C9043209ULL,
		0x88CDB217B99EB4ABULL,
		0xBF2998DD89FCBCA5ULL,
		0xFD85FEC7121230BDULL,
		0x9D2D635CF9EE27F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF050E6AC2B83FD37ULL,
		0x19870E1942CCB207ULL,
		0xF549826746271CC3ULL,
		0xCB761E05C9043209ULL,
		0x88CDB217B99EB4ABULL,
		0xBF2998DD89FCBCA5ULL,
		0xFD85FEC7121230BDULL,
		0x9D2D635CF9EE27F6ULL
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
		0x3A0617AFE58F4133ULL,
		0x4153A64D6D1E180DULL,
		0xF02011B35F48B288ULL,
		0xBC7D855A19C6DF9BULL,
		0xA0AB50F024AB1C10ULL,
		0xDA0A645BA4D755BFULL,
		0x8FD47EF9510E9717ULL,
		0x3432869E1865E1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A99E14ABA539884ULL,
		0xCB5093DACDF1297CULL,
		0xFD6B556CD37EF513ULL,
		0xA0721621535A3281ULL,
		0x01E08BBC1668CE71ULL,
		0xD0EB02401325B597ULL,
		0x3AFD3723EF345E6CULL,
		0xAA8EEC80F91D39DEULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA43F3FDFFC6BA9B5ULL,
		0x528D2E39AB0BFAE6ULL,
		0xB64D9A8107FF9DA7ULL,
		0x2B6ADA0F8C706CA1ULL,
		0xF04271181D17AF1CULL,
		0x6D225F0D260695E4ULL,
		0x79F656CFE4A28D42ULL,
		0xA622F5FA81AD616FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x656D48E60CFF8959ULL,
		0x9D749824C8DB1703ULL,
		0x3568A4F053F5A546ULL,
		0x43B7ED9F2B8A6932ULL,
		0x2FE90FAD6CB6D36EULL,
		0x8E1D8CDD09EE40C1ULL,
		0x0F6B042D3336355AULL,
		0x17BC426D1E01747EULL
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
		0x0F9F9D6B73B93A63ULL,
		0x18229AA893BFDBA5ULL,
		0xB0649E08C304A6F6ULL,
		0x181EFCC6A211B961ULL,
		0xA4DDE54B57C44EDCULL,
		0x172035C9CC1F8EEBULL,
		0x15A1128E0FE8B6DEULL,
		0x48EF5391EC021EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B30C78BE9F044DAULL,
		0x32DE2960AED42C77ULL,
		0x83DACE6AB8948223ULL,
		0xA559A641D78843E8ULL,
		0x3A6DA0B53828274EULL,
		0x92E603BFCBEF3BB4ULL,
		0x8C1EB6862D167D2AULL,
		0x41207C2862B08802ULL
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
		0xD5034171813E0645ULL,
		0xD5946CECDD50621BULL,
		0x136D62059B3ACF60ULL,
		0x2ABAD95A397492EEULL,
		0xBFB47B62162D9AE9ULL,
		0x81E106BD70D76F28ULL,
		0xFC55C12FA22AA5E1ULL,
		0x654FA039211192BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5034171813E0645ULL,
		0xD5946CECDD50621BULL,
		0x136D62059B3ACF60ULL,
		0x2ABAD95A397492EEULL,
		0xBFB47B62162D9AE9ULL,
		0x81E106BD70D76F28ULL,
		0xFC55C12FA22AA5E1ULL,
		0x654FA039211192BBULL
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
		0x066DD67AD7A38EDBULL,
		0xAEEDD8A6973A988FULL,
		0x4BB3B4A40E7A3BEDULL,
		0x3B13D4C719939E9CULL,
		0x7A996D47FF214F69ULL,
		0x57818E357089E59EULL,
		0xEA94F04F59A79933ULL,
		0x4A7C15A9C3535ACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50DB51FE2656F618ULL,
		0xC3F8007F8262C153ULL,
		0x4D735F01C752D170ULL,
		0x157DCC83260C3636ULL,
		0x5DD4F2CFE7AD7D38ULL,
		0xEB44647EE2AC364BULL,
		0x7F03A06217DE1728ULL,
		0x86BFD89090F38335ULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD9B96E4B236E4C1DULL,
		0x926C0FB6FA049D2DULL,
		0xA4DC638EC481952BULL,
		0xE5C5B4FB5F5964D3ULL,
		0x95B0ADFF23914B9AULL,
		0x45825596C2028F9FULL,
		0x119AEE1F8D49EB2EULL,
		0x3193A3F6C566AADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BD45CF105D02589ULL,
		0x01034B2706DFF4F3ULL,
		0xCABF5A32CAD379CBULL,
		0x5BD3AE2F0DA34886ULL,
		0x8B47B89D6C240CDAULL,
		0xB800039ED68F2CC5ULL,
		0xA581DB9455FF77F2ULL,
		0xFAA31E0A935F31F5ULL
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
		0x5FEBEF13BA3D4D26ULL,
		0x4BE794330DCE6C4EULL,
		0xB0A25C4F37E8C361ULL,
		0xB573FD22A16A288FULL,
		0xBF0EAB126514F8BDULL,
		0x691C871A7B5CBA55ULL,
		0x231E9EBED8355AE5ULL,
		0xDD990FF5C9FFB440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07298A989578807CULL,
		0x58498B0247AB9421ULL,
		0x887764196F39AA64ULL,
		0x0417D41CD2A76101ULL,
		0xFC51527A2216675BULL,
		0x5D552738967806A0ULL,
		0xC99E73E1D4AE8605ULL,
		0xC87C5ADECB5D2B5EULL
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
		0xA88B7B6C821090F3ULL,
		0xFCFFE645076F13A7ULL,
		0x0FBFBC1F9109A3FAULL,
		0x8287F4DE6FC40DDBULL,
		0xEF146E6F6595295BULL,
		0xE9B63A88D7D9E0DAULL,
		0x055DD519DC06A40DULL,
		0xF27713C80DDE16D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88B7B6C821090F3ULL,
		0xFCFFE645076F13A7ULL,
		0x0FBFBC1F9109A3FAULL,
		0x8287F4DE6FC40DDBULL,
		0xEF146E6F6595295BULL,
		0xE9B63A88D7D9E0DAULL,
		0x055DD519DC06A40DULL,
		0xF27713C80DDE16D2ULL
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
		0x27EA93DFF5842C17ULL,
		0x59A756F05C661619ULL,
		0x34E0883121FAAD20ULL,
		0xA54D9858EC833B28ULL,
		0xF686A8DB9E1CB41BULL,
		0x0269615F98C7F49DULL,
		0x04B6A7DA5E04DA54ULL,
		0x34F3FD7BF963B3AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4BA8F2724087005ULL,
		0x52CA4F967481852DULL,
		0xA904D397C9739A9EULL,
		0xC271232E2C82BF19ULL,
		0x7E710EAA06D461E9ULL,
		0x8A37DE76587E48EAULL,
		0xC130F95AE70EA988ULL,
		0x89C0F7619200B350ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xED623CB4D8C89C72ULL,
		0x55370DA63DA81323ULL,
		0xE8E639D3AA1A7558ULL,
		0x880A16B3B6C163D8ULL,
		0x0AFD0EA818282D44ULL,
		0xFD8ED7CB376B9220ULL,
		0xBB04066797875006ULL,
		0xD525A66EC9F76582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5589925E3A70176ULL,
		0x01119A26D259094EULL,
		0xAB36EDC304276109ULL,
		0x0094D3AEE3A189F1ULL,
		0x71B23505D7977CF8ULL,
		0x9B8F3905C0844EB9ULL,
		0x938AD17E17CA2422ULL,
		0x15DB1CCCAA81B887ULL
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
		0x3DD376D5E3E059EAULL,
		0x781E2B0BA233CBFAULL,
		0x43D8A155395FF1FAULL,
		0x7BEEAFB5F4A7B136ULL,
		0x07FC0A1F4DC19C1DULL,
		0x3DAAF96AF89ED520ULL,
		0x805E8093396F61A4ULL,
		0xD4277A04270F0114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5676F28E96B14EACULL,
		0xBA1D4719759A6645ULL,
		0xA8A4BE3676B5B0A9ULL,
		0xFB284396698E21BBULL,
		0x21CCC0C29D1274CCULL,
		0xB32E2DE217172A05ULL,
		0x360727C44128EDEEULL,
		0x74FE647CB9D82F1CULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAB7C4F360DBE2550ULL,
		0x7CFE4623B79CF076ULL,
		0xB2852A11FB2D0705ULL,
		0x27276375A2E63907ULL,
		0xAFF1E814A156F8C2ULL,
		0xC0A6EE325EC064E2ULL,
		0x1C6ADFE88AEEDF76ULL,
		0xF5A17FE5330DF404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB7C4F360DBE2550ULL,
		0x7CFE4623B79CF076ULL,
		0xB2852A11FB2D0705ULL,
		0x27276375A2E63907ULL,
		0xAFF1E814A156F8C2ULL,
		0xC0A6EE325EC064E2ULL,
		0x1C6ADFE88AEEDF76ULL,
		0xF5A17FE5330DF404ULL
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
		0xDC44DE4EE25FE78DULL,
		0x3E798BFE5DF1D065ULL,
		0x217AA593E69C38C9ULL,
		0x17C509809C9AD80FULL,
		0xC8E8C6B97877798AULL,
		0x9461D1061E753ED5ULL,
		0x8C3987CCAD9D6740ULL,
		0xD7FF467AA0AE6AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB1BFFECBFAC411ULL,
		0x6A44456EB1BB8FDDULL,
		0x9EE688CF18B87C44ULL,
		0x4B34140667238F3CULL,
		0xC6CA72F0C3F2335AULL,
		0xD36489E874F0BB29ULL,
		0xFE02D1C3ABB00826ULL,
		0x8BCFBA973F5D375AULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x81E50AB1822075DEULL,
		0x902BEBEF7DD6537EULL,
		0x09657901949DF21AULL,
		0x92941AE952759409ULL,
		0x201862FBE4F6157AULL,
		0x4451078332D781B2ULL,
		0xB2AA5D16706215FEULL,
		0x7486E5D9324CCFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC56FFE2CEAB4D966ULL,
		0x80271C424F16629FULL,
		0x8BA680E8C08004FAULL,
		0x4631F27E2448ED7FULL,
		0xA10F45E2644F90F1ULL,
		0xADB5D0E7DA9B22E3ULL,
		0x749A836B113D29E1ULL,
		0xB4BC421A1DEFCD26ULL
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
		0xB48E863BB85D3689ULL,
		0x3852004AC11A29CFULL,
		0x3F35F9C2CC106F08ULL,
		0xDED2CCF3E818C7C4ULL,
		0x06406D949D1B5918ULL,
		0x4B1312CD0CC4A7E2ULL,
		0xB0EBF9C4E65595E9ULL,
		0x31E698985AB2C175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB937D292828AD3A9ULL,
		0xEB3C19C069825C24ULL,
		0x4F93763434329300ULL,
		0x748DBB1478A7ED58ULL,
		0xBB99A4FB1902F585ULL,
		0x8DD6C4C81085D764ULL,
		0x9C9906875C4817BCULL,
		0x6074E1CE8F923392ULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x289CDEAAB80AE33FULL,
		0x141318CBC06B1311ULL,
		0xEFBE861955B7192DULL,
		0xEFC5B8CD1A0F276BULL,
		0x16F86D6BE340647BULL,
		0x8BD2CD7AF3134F88ULL,
		0x1A9B8B221F1AD4F4ULL,
		0x964768066D8097F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x289CDEAAB80AE33FULL,
		0x141318CBC06B1311ULL,
		0xEFBE861955B7192DULL,
		0xEFC5B8CD1A0F276BULL,
		0x16F86D6BE340647BULL,
		0x8BD2CD7AF3134F88ULL,
		0x1A9B8B221F1AD4F4ULL,
		0x964768066D8097F5ULL
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
		0x4E9BE8B727C81D72ULL,
		0x2F1333E94E47CD19ULL,
		0x228CD9DC0A1DAC30ULL,
		0xBB3476ADC7BF17D0ULL,
		0xF806472DC0A063CDULL,
		0x17D52E6295D9A165ULL,
		0xA3A407FE8C8F03B9ULL,
		0xDDD2489C676507F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A3B44255EADA26CULL,
		0xBD249B6DDF41CFD2ULL,
		0x064708F39745EADBULL,
		0x132C9D5629969DB0ULL,
		0x5C6BF223D7465AF5ULL,
		0x63E1E04F62336773ULL,
		0x3F6AB01767178169ULL,
		0x8339A36E78C529D4ULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBB4F487E0682AF0AULL,
		0x58FD24B18FA8989FULL,
		0xBF4C7005F53417F5ULL,
		0x616983657BB75198ULL,
		0x5DA49EFAF8296DA6ULL,
		0xFADD25A5D854CD3BULL,
		0x0C260ED5BF684D1FULL,
		0x632E854AA9FE3858ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x208E08EE95DCC24DULL,
		0x92F6AFC0612C18ADULL,
		0x712AB15E6443238EULL,
		0xD238DA5B56EB0745ULL,
		0x9A6C93EBB4687329ULL,
		0xF41B63CAC299A4A7ULL,
		0xAF5C0FC92ADC020CULL,
		0xA2BD9115909BFF65ULL
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
		0xE4F65CA4F064F54DULL,
		0x6AA39026FC1B7502ULL,
		0xA4504CE258B61E7AULL,
		0xBCFFD44416450662ULL,
		0x121C42576C42D23CULL,
		0xEBB076B5C92DD02FULL,
		0x1589AA03B3EF8D2EULL,
		0xD9879BAB977C8C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB8CA5D67349252BULL,
		0x0CD1A43FD6CBF9FEULL,
		0xCD52E0117FC48C58ULL,
		0x43AA87B3B46AA0B2ULL,
		0xA1146D8DB43D5922ULL,
		0x83896C2F1EA99B86ULL,
		0x330515CA44787570ULL,
		0xFBFA6D1899EEB16BULL
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
		0x38E91DC8CA6E0607ULL,
		0x2FAD2E60EAE2B671ULL,
		0xBA054C0E61583E10ULL,
		0x6F29A7BD58D678E1ULL,
		0x9035F9754855358EULL,
		0x86D836BA2D853086ULL,
		0xB448F8E0663B354AULL,
		0x90A20CA33EA393D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38E91DC8CA6E0607ULL,
		0x2FAD2E60EAE2B671ULL,
		0xBA054C0E61583E10ULL,
		0x6F29A7BD58D678E1ULL,
		0x9035F9754855358EULL,
		0x86D836BA2D853086ULL,
		0xB448F8E0663B354AULL,
		0x90A20CA33EA393D0ULL
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
		0x0EAFB626214D60E6ULL,
		0x551651F56D91474EULL,
		0x44A67BC9F08FAE70ULL,
		0x27F3E3F4E01A10F4ULL,
		0x7B8A13591E119D77ULL,
		0xFC5469C255B279D4ULL,
		0xFE7D7514A8CE6C49ULL,
		0x370113F83E698795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5701F20419E0BFAULL,
		0x36E5345EC2B67198ULL,
		0x3D1914821BB283DBULL,
		0x4DB5C7DBB190B84CULL,
		0x3BF89DE1D71DF142ULL,
		0x17FECEA812BE2176ULL,
		0x295CFF90F7858DD0ULL,
		0x4BA1E3F5DFC56B8BULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x831715424886BCBBULL,
		0xC5746897F7A7A469ULL,
		0x4AE49B9178FF5C3BULL,
		0x22A9004751E06D56ULL,
		0x3A0BFE9DB0946DC1ULL,
		0x82F8D2A20625ACAAULL,
		0xDA3E836AD1875317ULL,
		0x04A03F52D932A04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C00AAB5E2BF0317ULL,
		0x9EE267216865E8A8ULL,
		0x0083D7D6B839AF99ULL,
		0xC04C3F80DD36AC2BULL,
		0xED3B6FC952CA8A5CULL,
		0x1A40338E0F9A48D8ULL,
		0x116C9D2B33AFA1CCULL,
		0x8B4CE1E75D4138B8ULL
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
		0xF5805E77D3F7C376ULL,
		0xEC8DCDAAA6614229ULL,
		0x386BC11D20BFE597ULL,
		0x78DFD90C8E601420ULL,
		0x77CB706C4CD37894ULL,
		0x0CAAAB747023BD7CULL,
		0xF62F1ED9362CD0C8ULL,
		0xBF02954EFB5A1E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D0407E14FACB45ULL,
		0x91FD7642D5043FCBULL,
		0xF72DF0655FAD96BEULL,
		0x9354719F33D0AF49ULL,
		0xC70D97E50F5CD2A7ULL,
		0x3A9371F5296B501EULL,
		0x647424119F549E3BULL,
		0x5145D4E6E8AB72FDULL
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
		0xC94A0292651D50A9ULL,
		0xB6D16DC3E481DA06ULL,
		0x09160A3BFA42AF1FULL,
		0x60E56723B7475434ULL,
		0xFDDD397C993BCE9CULL,
		0x6EE432F9BF7CFBA1ULL,
		0x8945ED21E6638154ULL,
		0x4BAFB4C10F0D6026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94A0292651D50A9ULL,
		0xB6D16DC3E481DA06ULL,
		0x09160A3BFA42AF1FULL,
		0x60E56723B7475434ULL,
		0xFDDD397C993BCE9CULL,
		0x6EE432F9BF7CFBA1ULL,
		0x8945ED21E6638154ULL,
		0x4BAFB4C10F0D6026ULL
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
		0xB6BBEF2728AF6702ULL,
		0xBBA2D910D47A7BF7ULL,
		0xDE160B23A9E60AF3ULL,
		0xCF96AFF451DB625FULL,
		0x12DB74B36DEA5AF1ULL,
		0x87B4BBA7C1B88DC6ULL,
		0xA995628F9FFF193DULL,
		0xB1365D6B046D8B56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x507AEBA6B3F1A472ULL,
		0xC47BF1A8E9940E7BULL,
		0x2689D18625D620A4ULL,
		0x4CD6D594BBD9D687ULL,
		0x5F153F7596231D5CULL,
		0x38F3A931868305C7ULL,
		0x7C6E72100007FC0DULL,
		0xD38EE62FD304D944ULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x08D2A79CA8AD3237ULL,
		0x875DE5B59DFF42B6ULL,
		0x9021B27BB2892D7CULL,
		0x97C0728E478453C2ULL,
		0x2D5608DC3E58B646ULL,
		0xE69B95C59A80AE94ULL,
		0x8DDDD64B784649F2ULL,
		0x02C958F372863D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x848B07182CE6406CULL,
		0x78EB444E34A45306ULL,
		0x7444113E1D8B4CEDULL,
		0xD7D57FE9A302AF3DULL,
		0xC29CCFCE0B5187B9ULL,
		0x5F0DED9A181BAAB1ULL,
		0xA8AB58D9C6B0D651ULL,
		0x4833B93A0CB40220ULL
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
		0x01FB054B236855B1ULL,
		0xFA80175B64F8C050ULL,
		0xBD1F37222243FB46ULL,
		0x57ACD9485A21917BULL,
		0xE805C0122D083348ULL,
		0x0C1CAA861973DA22ULL,
		0x9C3F8CF8541CD080ULL,
		0x87B25CF93671AD3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0E3AEB06357CA74ULL,
		0xF869322A97E00C20ULL,
		0x2A15D643246FB8CAULL,
		0x55CC1E41722B17D9ULL,
		0x7C23FE138DEF5E1EULL,
		0x9D7D64FF061368B1ULL,
		0x4F0AC91D09328AA3ULL,
		0x9FD9BB807820E119ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5B450B17C0A4CBB9ULL,
		0x5E19DE7D99669C6DULL,
		0x317FCD6E1A380636ULL,
		0x983E5ABF1C3B86ACULL,
		0xED7A6F20ECB636D4ULL,
		0xA89708438427C154ULL,
		0x83C89E10EC6EE6BFULL,
		0x1CCAEA400F6E016FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B450B17C0A4CBB9ULL,
		0x5E19DE7D99669C6DULL,
		0x317FCD6E1A380636ULL,
		0x983E5ABF1C3B86ACULL,
		0xED7A6F20ECB636D4ULL,
		0xA89708438427C154ULL,
		0x83C89E10EC6EE6BFULL,
		0x1CCAEA400F6E016FULL
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
		0x63BEA9D343BB9A6DULL,
		0x177A9AECC15FA5D8ULL,
		0x50CD2EA633D23018ULL,
		0xC71F83A44238AC1DULL,
		0xE560724CB906B73BULL,
		0x3574E1155EFB28A7ULL,
		0x8DAE64E917730181ULL,
		0xEEC919E4263CF55BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF4AB984736DEDEULL,
		0x995D47804D4E6CD5ULL,
		0x7D1752C0828BF462ULL,
		0xE8F12AC5C2436611ULL,
		0xD4C2C8622B3DABBBULL,
		0x7CF062E177094E05ULL,
		0x6F0B738AAEC242E4ULL,
		0x4504B0202F3C4BCBULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE8C42A7C16212348ULL,
		0x4C7454963C39CCC2ULL,
		0xC01A3232D4E27428ULL,
		0xB8F3024A8E97FC29ULL,
		0x270C2537E2209B7BULL,
		0x678A16AA0BEB33B2ULL,
		0xDF85A30FAB148DDCULL,
		0x171F79C4182E9B41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EBE9B0B1174D39FULL,
		0xF3C6441C6F8CFAEBULL,
		0x68A8F36F14E3896AULL,
		0xBDE1C592E67CB7CCULL,
		0x3574BAA3A6764C8AULL,
		0xA414124A91310A06ULL,
		0x589408838CBBF44AULL,
		0xD381ADC7E50B80D5ULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x69A407EFA0AB026FULL,
		0xF9EFB225652408B1ULL,
		0xA651B42286D14CC0ULL,
		0x80F6C14EB7829AD0ULL,
		0x97653BA7D24BC09BULL,
		0xF0B8D104126E55C9ULL,
		0xDE49B5E508C95CA1ULL,
		0x3A2B37665965E2E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11AE8873729D12B6ULL,
		0x8EBA9110F4FB272EULL,
		0xEA472DEA66AE1529ULL,
		0x499FA6C9378813B8ULL,
		0x3E9379235CB3D44BULL,
		0xFD7592BFE5932B47ULL,
		0x3F83515877789838ULL,
		0xD4FE666541D5F890ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCDB93EEFDA4FAA5FULL,
		0xE8F6EB844CBD6D70ULL,
		0x99730596E644C18FULL,
		0x1C870DB22910A5C3ULL,
		0x07E9352F603A6FE2ULL,
		0x90A6932EB10CC024ULL,
		0x9F21370475C60269ULL,
		0xC8BC79DD14228FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB93EEFDA4FAA5FULL,
		0xE8F6EB844CBD6D70ULL,
		0x99730596E644C18FULL,
		0x1C870DB22910A5C3ULL,
		0x07E9352F603A6FE2ULL,
		0x90A6932EB10CC024ULL,
		0x9F21370475C60269ULL,
		0xC8BC79DD14228FCEULL
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
		0x311D7CDB0047285AULL,
		0x4834FAED1DD3A787ULL,
		0x0A6444637746B242ULL,
		0x318965EFFEAFE86CULL,
		0x23C93C9B27033BDBULL,
		0x40675D657EDBAF59ULL,
		0x8C053633C3BD7487ULL,
		0x850B098A7DDF6626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB338DE83328289B1ULL,
		0xE81222C61DD034CEULL,
		0x1A83BDC5E52FF6DDULL,
		0x01BCB94A08358316ULL,
		0x3005F9F658E8E762ULL,
		0xA60C04D40B0F131DULL,
		0x97D3643D8CFB5CC0ULL,
		0x17BAC336E6C88397ULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1BE36BD89A6C1B5AULL,
		0x2CC3ADFF0FF2062FULL,
		0x77FD8FE7B70F8CFFULL,
		0x02219A66874B5019ULL,
		0xC16AD9823FB53C51ULL,
		0x5CE5D0642A3C5B69ULL,
		0xE0B4E1741AFB82CBULL,
		0x35D2B475684DE948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C93F5D91414B62ULL,
		0xEDD3139A415C7FEDULL,
		0x06AE26128B87AFE7ULL,
		0x06AACF9DCE74E687ULL,
		0x4D9A8BD5A426C2CDULL,
		0x2BEABCA1CB4A4CEDULL,
		0x82DE762EDD9B4102ULL,
		0xCB0076237699D97FULL
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
		0x9078E92D2CD9EF0FULL,
		0xBBF999647E8926DAULL,
		0x7643D59760FCD691ULL,
		0x97FE1B28AFEE1249ULL,
		0xB9D325D9E95750EDULL,
		0x0686D58A0CE1EF23ULL,
		0x8585C7E0E43CBFB2ULL,
		0xE688455F12D7BEE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3DC9742F33DFE33ULL,
		0xC1A314102824C0DCULL,
		0x1B6B237F2A60F54CULL,
		0xAE32398D2BDFDD93ULL,
		0x8BE9CCF71F767DCDULL,
		0x4BABDC1CE3490558ULL,
		0xB5C38197679D35D8ULL,
		0x42C4C6CB36CD3D61ULL
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
		0x6C0AFDDB914DFA19ULL,
		0x66E8D97B71D38B74ULL,
		0x9AD332A49C404F43ULL,
		0x0AE2A6CAE642B93EULL,
		0x58DBA67EC218DDDCULL,
		0x0F19C336CD7CF3ADULL,
		0x14B1D1FB2B4785C8ULL,
		0x70DDFE40DC2CD86BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C0AFDDB914DFA19ULL,
		0x66E8D97B71D38B74ULL,
		0x9AD332A49C404F43ULL,
		0x0AE2A6CAE642B93EULL,
		0x58DBA67EC218DDDCULL,
		0x0F19C336CD7CF3ADULL,
		0x14B1D1FB2B4785C8ULL,
		0x70DDFE40DC2CD86BULL
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
		0x8BE69E7C01EEC9A6ULL,
		0x38F98FFB16BFF7DCULL,
		0x9177F93B9525E935ULL,
		0xD5D20AF68872B950ULL,
		0x27E6E103C58BAD8AULL,
		0x403056A9D254E978ULL,
		0xA83F0CBC1832245EULL,
		0x368FD56F289979F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC5B301600CE3B2ULL,
		0x76D0F32AF710F900ULL,
		0x2AD8314441E013FEULL,
		0x3141959D8D9A2E9DULL,
		0x272DB38F8EA31FADULL,
		0x1164942532C92F51ULL,
		0x96172B1C88D0E624ULL,
		0xD2B6099D9F9EC761ULL
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