#include "tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Compare Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x2E2065D25ACD138DULL,
		0x3AAB86A595C64C03ULL,
		0x1344BB5892D1416FULL,
		0xB8831AC3E325FC59ULL,
		0xFAF5180A98B1FF95ULL,
		0x92EF2B058D26B961ULL,
		0x9348DFF7EC13D492ULL,
		0x99291056B32ABFCFULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xDA5A201CDC0D79ADULL,
		0xC228D3F325C34F0EULL,
		0xE7C6C360295EDB5AULL,
		0x6BCA405D2D360D36ULL,
		0xA294A91C4ADD1004ULL,
		0x8E68D30CAEFBE795ULL,
		0x66BD9577716B32FCULL,
		0x0814E88B38044C56ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xE2590A38B3609E02ULL,
		0xF57D596C60A15CD5ULL,
		0x6102D83E70C0A8EEULL,
		0x158A83ACC5084C6DULL,
		0xBE7EBD63AF6B8A27ULL,
		0xB1F6BE9AB7B76AA1ULL,
		0x5DB52D0E2D113088ULL,
		0x9C74E41C941642AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA7AF1C26039F76BULL,
		0xD94F088319E8200FULL,
		0xB0E2572287DE2832ULL,
		0x794D3F3A986B4B44ULL,
		0xCC430526EDED3199ULL,
		0xB8F091FE4555EC12ULL,
		0xC6B87563630DED16ULL,
		0xB7AA6DD88C31469BULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xC908EBC884D84ECFULL,
		0x7FCCD7D726B92596ULL,
		0x9F145BAF19101098ULL,
		0xB71F6A9DC4A2D89EULL,
		0x344B75F5FE5D826CULL,
		0xA19BDEBDB889B61BULL,
		0x3CD8B6D766302672ULL,
		0x66F520FAC34841E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84829DB56A295927ULL,
		0x30D9BB35450DECC8ULL,
		0xAAB92BF03821C20CULL,
		0xBF435A130655063FULL,
		0x4481C5C5317F8BFDULL,
		0x49F3A525BF008699ULL,
		0xFDA4FE2DF943412BULL,
		0x7D215C4FE0A28C1BULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x805E88489856AED0ULL,
		0x031E0D79E18F53F1ULL,
		0x6E06EBBFB5088798ULL,
		0x84D567DF61D06F6EULL,
		0xB58B7E6E39FC8632ULL,
		0xF2E8DF2179090129ULL,
		0x9DBCB3306AC3F112ULL,
		0xE086F5CA42F245BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CE14B272E2673CULL,
		0xB268744516B8B4E7ULL,
		0x5E19A50B6F5FB0F9ULL,
		0x725F551B426002C0ULL,
		0xF5C4206A38AC3D75ULL,
		0xC875A480850C9F76ULL,
		0xFD961EFB5684BBC1ULL,
		0x9A73B0BE3F90408DULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
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
		0xB57D30D78A40A603ULL,
		0x7AE8A3F9894632B7ULL,
		0x2795108880817BD6ULL,
		0xA7FFC7A295F81301ULL,
		0x56FC26B323A6D2EEULL,
		0xCDAC5C5830A70D9BULL,
		0x9113F29F0A646922ULL,
		0xEEFBFAD2AC3DDC08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB57D30D78A40A603ULL,
		0x7AE8A3F9894632B7ULL,
		0x2795108880817BD6ULL,
		0xA7FFC7A295F81301ULL,
		0x56FC26B323A6D2EEULL,
		0xCDAC5C5830A70D9BULL,
		0x9113F29F0A646922ULL,
		0xEEFBFAD2AC3DDC08ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xFE73674F55624C33ULL,
		0xA50A145D1D43AF6BULL,
		0x510D044D4EDC6732ULL,
		0x434E9C7AD622A282ULL,
		0xC3A414F76CC99628ULL,
		0xCA2573D08E766BE8ULL,
		0xA74D10F34FB28749ULL,
		0xBFDA30C5414BC1F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B45FE27C06A0FD7ULL,
		0x62201EE7F4000151ULL,
		0x88138A7167241004ULL,
		0x83710056A2954EA6ULL,
		0x752AD6AA32B520E0ULL,
		0x37D62321BE8BF3BAULL,
		0xFF2E5D7854905076ULL,
		0xEAA0D991909A5E72ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xE36B3C08C07FB9A6ULL,
		0xD971CB3D3CF692B6ULL,
		0xADAF00FE5528A8CEULL,
		0xA98A4454F77A31BEULL,
		0x229902F29BD72805ULL,
		0xE72AA13E94E79F3BULL,
		0x5E1A7F382160A447ULL,
		0x48A3827C53E24B0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8293F04ADB2ECACULL,
		0xFC75AA2002C25047ULL,
		0x0C1C60604A502A05ULL,
		0x1BBCD723BF72BB2EULL,
		0xFC51877CD5E83619ULL,
		0xA14282BD7860C054ULL,
		0xA2777AFEEE43D30BULL,
		0x51479DB4B7CBBEB0ULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xE42BF3C6E72C0EBAULL,
		0x9321DC3CB3F7970BULL,
		0x855C0B971667EDEAULL,
		0x53C04A6387C3B655ULL,
		0xC687EEFD6FFD435AULL,
		0xFD41FDD054F020A6ULL,
		0xCEACB1BFA88A44E6ULL,
		0xD44BC82D8CCEFD7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C74F435C659489ULL,
		0x3D8F772EF9A808C3ULL,
		0xAC7AC61451C2C37DULL,
		0xE2B864C2D9E13F0DULL,
		0x0AD1EE18FA868FA3ULL,
		0xB4DE6A22A0451BE2ULL,
		0x82393010E49AB097ULL,
		0x56C69BC38EB85AD1ULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x24921776D32CFF13ULL,
		0xD344DDB7FEAA9617ULL,
		0xAC6192A7DE3A8826ULL,
		0x9D66F2D71605B42DULL,
		0x49C4EAB8CDE7ABCAULL,
		0xFBBB76DD48D3E82EULL,
		0x9062CD2F0AD41DC5ULL,
		0xAD91C22AB39A54C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24921776D32CFF13ULL,
		0xD344DDB7FEAA9617ULL,
		0xAC6192A7DE3A8826ULL,
		0x9D66F2D71605B42DULL,
		0x49C4EAB8CDE7ABCAULL,
		0xFBBB76DD48D3E82EULL,
		0x9062CD2F0AD41DC5ULL,
		0xAD91C22AB39A54C8ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x6B2B717187749801ULL,
		0x768F059D86810E3EULL,
		0xDF782426E6662B8FULL,
		0x6BC9901D3769E78BULL,
		0xA48605A54BE02FB9ULL,
		0x6D46D8C0DBD8FCE5ULL,
		0x5F67190EF0EFA4C4ULL,
		0xA089D331FF54A8B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5584E6BF4176636ULL,
		0x9305FC868DC00754ULL,
		0xD7A678139995CC0AULL,
		0xF4D3BDFBCAB1CA18ULL,
		0xFF757CB1E0ACE437ULL,
		0xAD293CA1F6F49DA1ULL,
		0x393C2BCAF0777A6DULL,
		0xBAECF18D60B2D708ULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x7563F1E61B321C00ULL,
		0x3AF87328C9AFE944ULL,
		0xC6F0E525AE767D37ULL,
		0x818FC9FDC6058943ULL,
		0x5A2D6F8649F2FCC6ULL,
		0x43D597B85BFCF583ULL,
		0xF4B054BB313EF129ULL,
		0xD7438232981B5134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45DBAF42A746CD9CULL,
		0x16BE67F95EF4CBCCULL,
		0xE0CF162F72B585DAULL,
		0xDBF02C12A3969A29ULL,
		0x6C9E0400A4572D9FULL,
		0x151622483AFC4A60ULL,
		0x08B895165481BD06ULL,
		0x5170EA64377E1B6BULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x4EEE7B347A46CBB7ULL,
		0x3C51C8E7706683E0ULL,
		0x452A0F1A6780661CULL,
		0x3D12D74E17ECA5D4ULL,
		0x21C070B788488E58ULL,
		0xDC83BA5FE5818EBEULL,
		0x028A455B1B0762C8ULL,
		0x219918E4400216E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE5F8139B201870ULL,
		0x38A99696D8D721E0ULL,
		0x519FF62BF12BBA2CULL,
		0x898CF375F21E689CULL,
		0x7EE141EB1C8681FFULL,
		0xAC94DE848D6D7D71ULL,
		0x01659BC712C5BD33ULL,
		0xD8F7C337195CDB5EULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x0E9D24A5758D2DCAULL,
		0x83F47BCD9DA77113ULL,
		0x8BEF0A0B3576484CULL,
		0x73CB9E304550B594ULL,
		0x8153CF49239B37F5ULL,
		0x1371F88ED902B612ULL,
		0xDDD3DC09E8C669E9ULL,
		0x69DAEF6F7886B566ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E9D24A5758D2DCAULL,
		0x83F47BCD9DA77113ULL,
		0x8BEF0A0B3576484CULL,
		0x73CB9E304550B594ULL,
		0x8153CF49239B37F5ULL,
		0x1371F88ED902B612ULL,
		0xDDD3DC09E8C669E9ULL,
		0x69DAEF6F7886B566ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xA918C3510E74013FULL,
		0x11E94BB56960F07CULL,
		0xC6A4099A382A0619ULL,
		0xC02E227DF7448EDEULL,
		0x967604D651923A13ULL,
		0x8AAB59E0801E99E9ULL,
		0x0C694D753D65DFEEULL,
		0x9C2D32C0798F2C71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72BE462AAEE270E1ULL,
		0x7983E396EC00CB52ULL,
		0x67D5A6971A87DBC4ULL,
		0xF75C0DA1E19BC077ULL,
		0xAFDDE89F868C7780ULL,
		0x1723476A59CF5F73ULL,
		0x568FF06CD4F6701CULL,
		0x78A0E35A3084689DULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xBA269280EDF5211CULL,
		0xF6271DAFF630B919ULL,
		0x127E61704B59A4B8ULL,
		0x678087815D0A1140ULL,
		0x090505A220A487D5ULL,
		0x80DAA4AE9E0B9131ULL,
		0x1BD1EC478253BB55ULL,
		0xFCA41047F9D70BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF94B4299529A19DULL,
		0x746A23CA504D0145ULL,
		0x9C0849AE155897ADULL,
		0x506C2AB429CF36D8ULL,
		0xB9D5C41A6AF2170AULL,
		0xD84B22172E1D185AULL,
		0x1077AF6F840FD1E1ULL,
		0x0E9E2AD53BD3F578ULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x8DD37F8D12BB6ED2ULL,
		0x3050B70E876DBF51ULL,
		0xF19DE8B739FD72F4ULL,
		0x2B21AC82D6F89BD2ULL,
		0x7DE4A294F8D8B832ULL,
		0xE7A5ACBCF7BB3BDBULL,
		0x1FAB179F0B7BD729ULL,
		0x9CBDFA590F55CD07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26BC643F1BC9EAADULL,
		0x790F2E2A963DC58AULL,
		0x700E92E4F4734563ULL,
		0x157106E9B0B2449AULL,
		0x0AA4086C4E902543ULL,
		0x4D82745B59D92311ULL,
		0xDE80332088B5ED06ULL,
		0x9C5686DEEF9C0236ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x2DA796E01702DBF6ULL,
		0x3709AB7E2EFF5217ULL,
		0x8DBDC8D3F0F8132EULL,
		0x527FC8EE4896B954ULL,
		0xDA2AF88F6DE3B91FULL,
		0x6524922FD75FA013ULL,
		0xE81DA0C267138F27ULL,
		0xD679FF10D28E0034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DA796E01702DBF6ULL,
		0x3709AB7E2EFF5217ULL,
		0x8DBDC8D3F0F8132EULL,
		0x527FC8EE4896B954ULL,
		0xDA2AF88F6DE3B91FULL,
		0x6524922FD75FA013ULL,
		0xE81DA0C267138F27ULL,
		0xD679FF10D28E0034ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x7E06697D0E40157BULL,
		0xC182CD7BD0754CD3ULL,
		0xA8D358599266EB09ULL,
		0x9DD6590DD0900ECDULL,
		0x69EF9E8C6019D38FULL,
		0x9B93247F08A77290ULL,
		0xF9281BFADF006517ULL,
		0xED8D537EC82D6B2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE04CC7811F7C975CULL,
		0x23004FB94AB7C8A4ULL,
		0x8ECAF5A5C891248BULL,
		0x9FC63685D65DED64ULL,
		0xC9A466A0CD115D55ULL,
		0xA12F530DE5367192ULL,
		0xD1B0E86A8ED167F0ULL,
		0x1D8974A7DDAE9A48ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xFCF8816A7E9A59DDULL,
		0x4411D5B585F79072ULL,
		0xBD9EDAA0AF57AFBBULL,
		0x3D5D5B76DFD6191FULL,
		0xB8B75CBCAA51CBB2ULL,
		0xE2BDF6C3E884A2F1ULL,
		0xC1DEFE6BFA489783ULL,
		0x103F93EB1C3044D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7451CD64D9F8C23ULL,
		0x5FB2C231B6271E64ULL,
		0x0ED8E4C40A41C551ULL,
		0x4524E999880E9171ULL,
		0xBE537737A8B6474FULL,
		0x4AC19B457A15DE87ULL,
		0xA19042DA383342A1ULL,
		0x50FBA28A58863BCDULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xB405ACF3E0D3DCFBULL,
		0xA9389F45E171C611ULL,
		0xC212DB30F9771BD2ULL,
		0x70C30577B240DDA3ULL,
		0x3733D8B769FF050BULL,
		0xF529A821FBD1ADC2ULL,
		0x7EC247781AABF47FULL,
		0x668A2C6EEE59DCBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE12B2D11C9D58FULL,
		0xB5062E8CEE833CAFULL,
		0x15AE40102C35338BULL,
		0xE5A709AD8B5DFB56ULL,
		0x38F63AA0856F4279ULL,
		0xBE5D82CFE7D48421ULL,
		0x9AB95B771D4329D6ULL,
		0xC7ABECE514E86766ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
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
		0x04EA8C163634F335ULL,
		0xD7DF01416DD79067ULL,
		0xB0CF8B361FCA20C8ULL,
		0x1020819A52084EDAULL,
		0x82D12A03B077E701ULL,
		0x2637B34818F9B3B2ULL,
		0x3D3C3D5AC15556CCULL,
		0x95C9EEA17C315C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04EA8C163634F335ULL,
		0xD7DF01416DD79067ULL,
		0xB0CF8B361FCA20C8ULL,
		0x1020819A52084EDAULL,
		0x82D12A03B077E701ULL,
		0x2637B34818F9B3B2ULL,
		0x3D3C3D5AC15556CCULL,
		0x95C9EEA17C315C6EULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x2E65415F8F0DF6A2ULL,
		0x00B14FEFA82EA958ULL,
		0x5ED2700E0E81C6A4ULL,
		0xCF4AED04BE99E774ULL,
		0xA35C74FF100D223EULL,
		0xF6371DDB623D7CC6ULL,
		0xF6667C21E5600D9DULL,
		0x7209ECFFCDDB9B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E1A6D141F17E133ULL,
		0x7A0B7172837962A2ULL,
		0x5BDB1AFB4FDB6FC6ULL,
		0x0B30120AD731FC31ULL,
		0x35B5D19AD5DEFE68ULL,
		0xAB9D452E0775D0DFULL,
		0xD97B85D180B3CEF3ULL,
		0xD0222C7C23F524D2ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x4A908264352E287AULL,
		0xA10F7074EE8AA991ULL,
		0xA63F5C50F5C2B4A6ULL,
		0x4492C6FE239E8C95ULL,
		0x6B4694519FCC0011ULL,
		0x5828863A7E64163FULL,
		0x7389B947BA07A2CEULL,
		0x0BDB8223D7E3B5A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x977C3A44B0EC88E8ULL,
		0x511399F6EAC58C98ULL,
		0xF11E7606CB4A2ADDULL,
		0xC921EA18A10D83DFULL,
		0x666C86581B5A60B7ULL,
		0xFEA441562FC6E800ULL,
		0x9A20592FB0988C45ULL,
		0xF0F07A9CE88CB664ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
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
		0xBB6FEAA74F5898BFULL,
		0xA7DEBE939F15BFA1ULL,
		0x6E9B90CE64B84C9BULL,
		0x578308223DE2CFEDULL,
		0xCCC8001775D5C787ULL,
		0xEE3E8F90C38A615DULL,
		0x7188FA7650E36F82ULL,
		0xE56F0BE8B3464885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42820C9E67772336ULL,
		0x7E40F403413C5879ULL,
		0xB634207655AFB9E4ULL,
		0x2D6F183427BB5B16ULL,
		0x155DD8E53380697AULL,
		0x03D8C384DBCE616BULL,
		0xDD7B79FAFC6968CCULL,
		0xDEE0329B07ECA597ULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xA4E55D8C9BEFBBE2ULL,
		0x5BB4682511DF1725ULL,
		0x8246F19D488B6437ULL,
		0x0A9B9604C32D39A6ULL,
		0xE3762C1D6555D8CDULL,
		0xFA411393FA4F2E42ULL,
		0x099D3E636408995BULL,
		0x0E4F0971F583F036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4E55D8C9BEFBBE2ULL,
		0x5BB4682511DF1725ULL,
		0x8246F19D488B6437ULL,
		0x0A9B9604C32D39A6ULL,
		0xE3762C1D6555D8CDULL,
		0xFA411393FA4F2E42ULL,
		0x099D3E636408995BULL,
		0x0E4F0971F583F036ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x26B08EE7F8C2F484ULL,
		0x8ABCE43B19579A2EULL,
		0x376AFA5DBD4E787DULL,
		0x331E2FCFCCD14740ULL,
		0xACB23A832E81E397ULL,
		0x3A4D999C9E9684A7ULL,
		0x0DC166C388DC6D3FULL,
		0x39F92FF3945623ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258144BA7C9767D0ULL,
		0x1A18A600673ADD93ULL,
		0x141028D937AA3D2EULL,
		0x758BB4926A3F2080ULL,
		0x1C9F69D4E8049810ULL,
		0x5CEEDCDFEB26B363ULL,
		0x6C53A9AC1FB14690ULL,
		0xBCF5A539223D5C50ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x7D8DD27D95585FA6ULL,
		0x08DDFEF01CFC1655ULL,
		0x741495B1F9D522BDULL,
		0xEBDB66083678743AULL,
		0x8443AE05EC181486ULL,
		0x4400FEF962E14DC9ULL,
		0x624BC7CC2FC04F7AULL,
		0xF6BE7DCBF7013519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABE2B8E646549D3BULL,
		0xA083E46D2815FEB3ULL,
		0x337C5C0BB5EAE586ULL,
		0x49F08FE88D900B20ULL,
		0x4C51B4D8F1CD16EFULL,
		0x128161E08B07D345ULL,
		0xD2CF02C91A8D7634ULL,
		0x50659F578600CACEULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
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
		0xB31C5D8FDC04E161ULL,
		0xFE46F5EFCCEF6352ULL,
		0x6A0D1B9C25E2FFCCULL,
		0xD0C6BC2F6FAAF2F1ULL,
		0x7B2665E1AC44219EULL,
		0x1CBEEE51DB5520DCULL,
		0xEE44355332BADCBBULL,
		0xBD6691ACE9C62425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA8EEFDCEAB4E8CULL,
		0x1152D75512A05342ULL,
		0x73A5C83BC946530BULL,
		0x6AFE1FA27474AD06ULL,
		0x2C7789FFC3505BEBULL,
		0xB4D6E3B3F74B14D0ULL,
		0x974BBE70AD6E5B9DULL,
		0x45CD660696BC4AA6ULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x34E4577717926808ULL,
		0x077E3EEB7616B92EULL,
		0xE7746F80D89A3948ULL,
		0xA3AEEF7247A4A2AEULL,
		0xC52C6C3691231F07ULL,
		0xE46623B93090EC23ULL,
		0x45EFF38954E95B66ULL,
		0x08762D9B80B7D6ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E4577717926808ULL,
		0x077E3EEB7616B92EULL,
		0xE7746F80D89A3948ULL,
		0xA3AEEF7247A4A2AEULL,
		0xC52C6C3691231F07ULL,
		0xE46623B93090EC23ULL,
		0x45EFF38954E95B66ULL,
		0x08762D9B80B7D6ADULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xC183D2144EDAF4E7ULL,
		0xEA87D367C7CBF465ULL,
		0xC4DD725E8CA5E994ULL,
		0x28343D9C683846D7ULL,
		0xB8562A200D0B5B62ULL,
		0x14F448AEAD662FB6ULL,
		0x0311F2B94CF1CE3EULL,
		0x6925AA60A1299A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84D7253D6B60B1EBULL,
		0x7337BBCB57571B02ULL,
		0x5F954D2D1B87A23FULL,
		0x4DEA85E13C1313F9ULL,
		0x5051467FE10BAFC5ULL,
		0x4FA187F354F27F8AULL,
		0x5F17032D4DD428F4ULL,
		0xE79ADAE335D5D0FBULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x734F17A5616AB5E7ULL,
		0x5C7D2D0D6E7A7995ULL,
		0xA2D00DFF568F43D1ULL,
		0x326BFBEA3CCA79E8ULL,
		0x067E23ECBE07C2BAULL,
		0x6E69C9B24F0EA98EULL,
		0x9988518769B82ED7ULL,
		0xB6A6A04948B8D52DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4F35ED4CD04E0D2ULL,
		0xF69045B1F98466A2ULL,
		0x12BB354FD506E71EULL,
		0xC7E9DBD00CAC5174ULL,
		0x9EB90E7071A73C31ULL,
		0x1C142592ABD182E4ULL,
		0xDBE98E59FBAC9DE5ULL,
		0xEBCF5E79F9FB8084ULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x7CB5B0A23B541A4DULL,
		0x59726DA752ABF0D7ULL,
		0x35B4E74FE1AADD28ULL,
		0x2ED62B1952DCFF2CULL,
		0xACA166814775014CULL,
		0x189C908DAE0C9A40ULL,
		0x5655EB3998DA58C9ULL,
		0xD03B91526041C5C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x477E320EBD21501CULL,
		0x6A38B5A708975911ULL,
		0x21BB7E75B1D2EA61ULL,
		0x54BCBEA7CB2CA486ULL,
		0x1FFDDC72A936FE13ULL,
		0xD938849B5480BDB1ULL,
		0x70881D8547F9A7BBULL,
		0x44EE01763C4C363DULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
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
		0x6FDD611CE0224CF0ULL,
		0xE55C616B0F76D477ULL,
		0x22E9F4A0C88D4F20ULL,
		0x9ABC3C9037CAB9CFULL,
		0x59E309002FF34644ULL,
		0xDB7CA41CBA9BBF3AULL,
		0x5825022AE87F1F52ULL,
		0xDAD9FB6FAA983B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FDD611CE0224CF0ULL,
		0xE55C616B0F76D477ULL,
		0x22E9F4A0C88D4F20ULL,
		0x9ABC3C9037CAB9CFULL,
		0x59E309002FF34644ULL,
		0xDB7CA41CBA9BBF3AULL,
		0x5825022AE87F1F52ULL,
		0xDAD9FB6FAA983B67ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x444129666B285139ULL,
		0xE0B0D52E23F30183ULL,
		0xB397E5C77A0D54ACULL,
		0x574CDF83DCA11B1DULL,
		0xFC05A225715DF81EULL,
		0xE1E35D281C35076BULL,
		0xC819AD60C9D51E47ULL,
		0xBBBF0A5C75B105E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E1C5854F4E29C22ULL,
		0x4A0689D10264D96EULL,
		0x0058F72168B3364CULL,
		0x98AFD429DA798DA3ULL,
		0x1A51F949CC96B8C0ULL,
		0x9B6691E54809E9DAULL,
		0xEA92D54A98EF786EULL,
		0x0C54A429B50FD37DULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x2BF4EBD15C161799ULL,
		0x257B5FCA977950B1ULL,
		0xD7E2F304B53B4250ULL,
		0xCBFB7A589D13FBADULL,
		0x428125154B130A65ULL,
		0x93143BF2687A3942ULL,
		0x82A07F2EC7F3C3EDULL,
		0x57E7B89B83A854E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B531B5B61B9178ULL,
		0x4F27D06A992881B2ULL,
		0xEDF722A163FDE789ULL,
		0x599CE07605AA11CEULL,
		0xF7ABF6E22C54D871ULL,
		0x44AF18664E8E7C1DULL,
		0x50383BAC11A0E6B9ULL,
		0xDE7251FC7868B6EEULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x3C146407E833F366ULL,
		0x5A45BED201450219ULL,
		0x8FA6DCD2592F1204ULL,
		0x253BD0240A88F9C4ULL,
		0xE27E9F68864C0734ULL,
		0xDE1AB34D4B2E9D42ULL,
		0xDE26FC6793E9E2ACULL,
		0xA502C0037F1DBF2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD391F153BE3BF449ULL,
		0xA8633642A445D8B7ULL,
		0x3E63764CC57A246BULL,
		0xD53DB492E7491F9AULL,
		0x30804EDE9A41A55AULL,
		0xA9788CA39E142D13ULL,
		0x8B1AC050A8953235ULL,
		0xB608D40CECAC9440ULL
	}};
	t = -1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
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
		0xE4EFD3BE84280040ULL,
		0x6E426622310AA626ULL,
		0xD1AAEAC09537A133ULL,
		0xB70EF9D07A429AAAULL,
		0xF6FC955E5A3046B6ULL,
		0x82F68B9117CF16E5ULL,
		0x06E6AFDF2C6EF2E1ULL,
		0x39B5A824A0682D4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4EFD3BE84280040ULL,
		0x6E426622310AA626ULL,
		0xD1AAEAC09537A133ULL,
		0xB70EF9D07A429AAAULL,
		0xF6FC955E5A3046B6ULL,
		0x82F68B9117CF16E5ULL,
		0x06E6AFDF2C6EF2E1ULL,
		0x39B5A824A0682D4FULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x472401036FE0C110ULL,
		0x10432B3A718175D0ULL,
		0x9902B4F276CF580EULL,
		0xAB09EFF8128CBE42ULL,
		0xFB31ACF00C321C63ULL,
		0x8BE1A9A8ACB0E536ULL,
		0x0D2387548342B869ULL,
		0x37A6F3E4C49C0BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70BA626AB0D311FBULL,
		0x3AD9D3DB10BA67D6ULL,
		0xAF0289BF5FED4B30ULL,
		0x54C8AB372F3EF18AULL,
		0x24F0230B8354AC3CULL,
		0x0F22C611911BE513ULL,
		0x4AB4CE927FE15428ULL,
		0xCF5FDB32150D406FULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x12497ADE771A5E26ULL,
		0xFCFB4D4FAD837044ULL,
		0xB340CD94A73A7C31ULL,
		0x79B440573BEE3D68ULL,
		0xFEA634B37B67506AULL,
		0x6740731E22B9B1B8ULL,
		0x35F4D348740E4875ULL,
		0x87FD69EEFC7C5FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE84DFCE4CF94A479ULL,
		0x93EC5DE1D7407F80ULL,
		0xBBD361998FF018F7ULL,
		0x39AA1AC5971DA2C4ULL,
		0x3E36C8927B512BFBULL,
		0x22F630C93FCFC347ULL,
		0x340ACA4CC0A12288ULL,
		0x4897C4972553052EULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
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
		0xD44B3B3256579D18ULL,
		0xEDF269BA26CC4958ULL,
		0x1817C1FF6B08EB1DULL,
		0xCA96E4875A08E6D5ULL,
		0xD4EBFCEC91A61035ULL,
		0x1E3ED4056D55359EULL,
		0x4A2E2A4DBB4131E8ULL,
		0x58F3C331F17006C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41E965BCFA05891ULL,
		0xD161AD6FEC240162ULL,
		0x579323E2C3AEBB01ULL,
		0x0C0AB8DF3CF7EFA0ULL,
		0x88DA7C95E7819573ULL,
		0xBC92B78630B338ECULL,
		0x93C5E3EB449B2378ULL,
		0xBC6B590BD14DF9F4ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x76C5E51839DFD0BBULL,
		0x0393027CE80A3CD9ULL,
		0xD46E3C05CC9923A8ULL,
		0x903F63788CFB37CCULL,
		0x43F0FCEC52ECC598ULL,
		0x0690542A24717EB5ULL,
		0x4BC9C82351CEA772ULL,
		0x28364FEA09D8A57DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76C5E51839DFD0BBULL,
		0x0393027CE80A3CD9ULL,
		0xD46E3C05CC9923A8ULL,
		0x903F63788CFB37CCULL,
		0x43F0FCEC52ECC598ULL,
		0x0690542A24717EB5ULL,
		0x4BC9C82351CEA772ULL,
		0x28364FEA09D8A57DULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x013997078A79D4B9ULL,
		0xF6658F1D96FF497BULL,
		0x2E611200EE15A8A6ULL,
		0x44ACAB33C4058B3FULL,
		0xC74690703DF8EF70ULL,
		0x730A338543986AADULL,
		0x5C445ED3BD6A57A1ULL,
		0x48674B990A15D9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A86D63FC36FC274ULL,
		0x1DB25FB053A73850ULL,
		0x0703F8812457C2E2ULL,
		0x4D6B875DBA3D2708ULL,
		0xA27C8021E6519241ULL,
		0x78A43AAA35A4BF60ULL,
		0xFE8AA5F3366E5D01ULL,
		0x72056DB0335805F8ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x51324FEC38E06A97ULL,
		0xE7DA0812C32DFCF2ULL,
		0xECD489B39E1959E4ULL,
		0x900A2B3D9974A37FULL,
		0x9660260FD4D2D52EULL,
		0x24EF92242381267CULL,
		0x3113F42EFC823B8DULL,
		0xF6E013537042938BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x862B811877BBFC77ULL,
		0xE852864973D3324CULL,
		0x16B6444836E980F0ULL,
		0x1F4116553850EC2FULL,
		0x27714A8BE61E3081ULL,
		0xF249BB4C12402FCBULL,
		0x3EB5F758507920EAULL,
		0x9ACCBB16ACBCCD02ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xA4F27A85520B20C2ULL,
		0x91A29F99367EC518ULL,
		0xD69E7103861649ECULL,
		0xA061D1B6A3C66C5FULL,
		0x6ECABA894741AAAFULL,
		0xFA32E5CCB9AAE454ULL,
		0x631A78522B87B6C1ULL,
		0x5CE71AC3BB62CF18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291D270995B8B0F1ULL,
		0xC834470B9F19FB70ULL,
		0x8E9F71DD5B902A70ULL,
		0x9E6C34B4D9157E9EULL,
		0x0171FEB649569143ULL,
		0x2020E456723934D7ULL,
		0xC9380F6AB0BD57D7ULL,
		0x68B09C53D7CB7AA2ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x2956176BCD945155ULL,
		0xB632A71D0D6A6E54ULL,
		0x8A50331FE949AB5CULL,
		0x51CA916249DE9E9EULL,
		0x499DF92388B2C144ULL,
		0x6020F365F99F2A25ULL,
		0x6D0B106220FB0959ULL,
		0xB98211C34660D08EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2956176BCD945155ULL,
		0xB632A71D0D6A6E54ULL,
		0x8A50331FE949AB5CULL,
		0x51CA916249DE9E9EULL,
		0x499DF92388B2C144ULL,
		0x6020F365F99F2A25ULL,
		0x6D0B106220FB0959ULL,
		0xB98211C34660D08EULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xC5AAF661F61A33D4ULL,
		0x42E1AF73669D55C8ULL,
		0x154FE2B094F9CD95ULL,
		0x229BFD5835A8D7E3ULL,
		0x79AF01AD016E9FEFULL,
		0x49AAA167D5D7A2F4ULL,
		0xBDDA29CF4713EF82ULL,
		0x9113A503A919848AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76DDF83BC4D29947ULL,
		0xC2D3CC05D3C89340ULL,
		0x4DC0D9BB0650AE39ULL,
		0x46CE5D7844712EB0ULL,
		0x886973E1B0DA14D8ULL,
		0x3DD1389E0123EA12ULL,
		0x24F680EC21EC754BULL,
		0xDA4F9EADC4383048ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0xC48B3FCA0E895D2AULL,
		0xACB22F96807521C9ULL,
		0x5B908664D6D026FEULL,
		0x604E8CCB5282B8E5ULL,
		0x0A95BE791F2662D5ULL,
		0x9395AD32F3CE0871ULL,
		0xA4B1F689D7D7AED7ULL,
		0x4C7B7F168F6F6476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8FAD8BE3B8688CULL,
		0x43DC2DD4AE2F8639ULL,
		0xE31F12E17FDA8CACULL,
		0x14EF8A56EEEDE303ULL,
		0x07454A08E90DAC98ULL,
		0x92EE102BCB3D7564ULL,
		0x98DF08DD491DAE4CULL,
		0xA68A39A664AEC3B3ULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x4BEA5961CE636E20ULL,
		0x92138E5556626A49ULL,
		0x9A85206EA49CB24FULL,
		0x14EF0299607CBE76ULL,
		0xE40CF300F395200EULL,
		0xB4CE656971B66546ULL,
		0x1C1783FA2F2CEC20ULL,
		0x6787DBB532B74C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03CE4AB3BBC0DD3DULL,
		0xA6D31B9DEE3C2C1EULL,
		0x26CA8C2B5D063847ULL,
		0xC8FF42FE86EC64ADULL,
		0xF91EA07281239170ULL,
		0x4882079EC12559F5ULL,
		0x40E4C38CBB678542ULL,
		0x78A4E2DED1C71D4EULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
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
		0xA3BA81E82838AFF6ULL,
		0xFEBDF057D9E7EA9AULL,
		0x5712D61800E01D52ULL,
		0x4BD7A85BB48C2A77ULL,
		0x98F0E145CEBDE5B4ULL,
		0x27530C00F567CB57ULL,
		0x94DFB3A24E46AA18ULL,
		0x4037AC87FE993E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BA81E82838AFF6ULL,
		0xFEBDF057D9E7EA9AULL,
		0x5712D61800E01D52ULL,
		0x4BD7A85BB48C2A77ULL,
		0x98F0E145CEBDE5B4ULL,
		0x27530C00F567CB57ULL,
		0x94DFB3A24E46AA18ULL,
		0x4037AC87FE993E38ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
		0x12149F0056FED8A3ULL,
		0xDD6161516277FBAFULL,
		0xBD14A50BB1D2EAB0ULL,
		0x1A55F2F47C7CB43FULL,
		0x547D5DAF89BC011CULL,
		0xD8128B9E4C3127B7ULL,
		0xF4BF49BD9FC4435BULL,
		0x22B8179D131C5A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08BF9C71B6730DCDULL,
		0x85207768829097C6ULL,
		0x3A522FC1E61BFB71ULL,
		0x94043216EF44F57DULL,
		0x9E6CA9C6465D7D8BULL,
		0x4BE60DE311D221ACULL,
		0x7EE3E2EB49843384ULL,
		0x53A70D141380BDCEULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
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
	k1 = (curve25519_key_t){.key64 = {
		0x649B16E31D6C3C5AULL,
		0x9AF29B5AB88BAACDULL,
		0x54FA141F9F0FB4CAULL,
		0x7841F2557E2C59EFULL,
		0x2D009FE6E9BD9FA4ULL,
		0x50FEBF47710EF166ULL,
		0x7F1EE34D887C57B5ULL,
		0x32119EE851355DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B0DE5349A9C057DULL,
		0xD795825B86A04D6FULL,
		0x0B21EF739722A05EULL,
		0x4799743315EE492BULL,
		0x7B535E2E806A49BDULL,
		0x95CC84DABAE58B0AULL,
		0x048866DE0DCFFE86ULL,
		0x25AD4D70AD984096ULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F887D6175BCB0AAULL,
		0x6B7A90A1759EA4CCULL,
		0x4475171F185241A5ULL,
		0xD64FA6397AF3BA93ULL,
		0xF290A15707E13938ULL,
		0xD4C4778188F0AF67ULL,
		0xB4819E0552B5AE3EULL,
		0x80056EB4B77BAAF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003BDF927A3A460AULL,
		0xC5DD32FA0BEEDC6FULL,
		0xCB206C7507D0124EULL,
		0x1E8B9BE5FF708FF7ULL,
		0xA1248830ED232FEDULL,
		0xE61178E05ABE48DBULL,
		0x4FC8C6D81FA10215ULL,
		0xE9D1E82622DBC4F7ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAA0AC5248B5952FULL,
		0xEC971F81E2AE5AA4ULL,
		0xB48F31CBA37BB40AULL,
		0xFCD652FC254B84CBULL,
		0xC1229657ED7EA34FULL,
		0x4C76B16AEA3445A7ULL,
		0x974E96C479990CE7ULL,
		0x5EE6ABCDFFE2968BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA0AC5248B5952FULL,
		0xEC971F81E2AE5AA4ULL,
		0xB48F31CBA37BB40AULL,
		0xFCD652FC254B84CBULL,
		0xC1229657ED7EA34FULL,
		0x4C76B16AEA3445A7ULL,
		0x974E96C479990CE7ULL,
		0x5EE6ABCDFFE2968BULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB5D1EAAD91119F5ULL,
		0x83CD25026D757F82ULL,
		0x2FE16FBBE8CA2281ULL,
		0x308FD692791DE37CULL,
		0x50803189A2AF1285ULL,
		0x674133EFA9CF7D7CULL,
		0xCA2121DC5D1FA5ECULL,
		0x15FE6E5A570557C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x639A9C3C61E52B03ULL,
		0xBB6559FD886BC058ULL,
		0x56AB9B652FF3FF6AULL,
		0xB166EE5A495D77EEULL,
		0x11C24D2F787AE3A2ULL,
		0x86506A07FF3AD2F8ULL,
		0x13B078C0E5763CC7ULL,
		0x42C74F450FF7B95CULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25B929439EAE7A64ULL,
		0x1BE2F97BA2C191A5ULL,
		0xFC91B4EEEE395CB2ULL,
		0xE11046D79F6E070BULL,
		0x28D4F603297D7C5DULL,
		0xBD5156971D2BF50EULL,
		0x740AD81A7562A80AULL,
		0x5B509843A3F89EDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD48231BB84D00583ULL,
		0xE719ACA52448FAEEULL,
		0x2294EE4EBBF377E1ULL,
		0x6DDEFBABB0237F5DULL,
		0xEA66AD428AA77C42ULL,
		0xBA3DBC55383A2C6AULL,
		0x2AA3AB203DC68D33ULL,
		0xF33EFE3EEFE12A27ULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AA4B6C5C9714EF2ULL,
		0x4CC0929C74537B4EULL,
		0x893D635FBC12CE39ULL,
		0x5AFE2EFD26FBE149ULL,
		0x1A5BB35543714884ULL,
		0x9F2330EF2D71EF6FULL,
		0x9B9E43938D6C9C6DULL,
		0x3112D1432CD44452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D27EB8718BFEEEULL,
		0x5E6872FE4A7B23A1ULL,
		0x18EBE52BB1C2CA81ULL,
		0xEC09CC3D4EAE5CF4ULL,
		0x257F69BE446618D1ULL,
		0x26948C917D7CA479ULL,
		0x4BE2EFB8A911B98FULL,
		0x6B12E36840BB6585ULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02FA86F2B7C2B4CEULL,
		0x45360BCB505BD430ULL,
		0xE7431ECB287524D3ULL,
		0x0CD1B7B4A7D0D1C9ULL,
		0xD1F54C1500EFE570ULL,
		0x45723D5C6AD29C0BULL,
		0x2AE612A41F504E87ULL,
		0xB306C2034B9E53BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02FA86F2B7C2B4CEULL,
		0x45360BCB505BD430ULL,
		0xE7431ECB287524D3ULL,
		0x0CD1B7B4A7D0D1C9ULL,
		0xD1F54C1500EFE570ULL,
		0x45723D5C6AD29C0BULL,
		0x2AE612A41F504E87ULL,
		0xB306C2034B9E53BBULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06EE20202DBA0D56ULL,
		0x6BE89F5E5E7F4CDDULL,
		0x7BB7D6600C78B56DULL,
		0x91A7E954573A0323ULL,
		0xF49B3BE1254AE5E1ULL,
		0xD7F49497904CFEFAULL,
		0x4F991555DF3DE0B6ULL,
		0x21C6F162E3CA7EB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F85A60F6216F24ULL,
		0xA4F47DD8C8E0252CULL,
		0x0E2CE70CB80B211EULL,
		0x7E673196C68670CBULL,
		0xD5423542ED2B42B5ULL,
		0x43B00E709ECD93C8ULL,
		0xD3F79D369D11F0ADULL,
		0x208F0E51E8A3CE80ULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09265891916C6855ULL,
		0x32810969C30D0CD5ULL,
		0xE3F7F75ED67D44A3ULL,
		0x98A392CEE446B0F9ULL,
		0x890C987FD71CE0C3ULL,
		0x891E6E9E51BB86FEULL,
		0x869F36411364AB0DULL,
		0xF81D419209DC5257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6FA5B6E8F2E1FFEULL,
		0x28EB7F91A8157C53ULL,
		0x8A1064B29A6BB332ULL,
		0xCB862E7535666D45ULL,
		0x0CB834A06605031EULL,
		0x8685F6988BCB62B9ULL,
		0x14AEB65814C888A8ULL,
		0xCC7F7F1E2DC1C1D2ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1193EDD00162D1DCULL,
		0x9592B684C8819460ULL,
		0xB44A13E8D0136CC4ULL,
		0x4CB1296AE40334F4ULL,
		0xFA96DE98735A0076ULL,
		0x62B0A05C42AA8345ULL,
		0x200FDE06B0E6FC73ULL,
		0x9EA08F6CD779D6C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6B8EFA6B76F8D1ULL,
		0xE9E55521327477B8ULL,
		0xC751DC5AFDF85EC0ULL,
		0x5B8FE6AB59D61A88ULL,
		0xB48A25E6FDB6E1F5ULL,
		0x8024FE836ACEE035ULL,
		0xAC388258D3E0CEC5ULL,
		0x466A0834D2FAE3CCULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB44E3D38D9124BBDULL,
		0x4900552265D58A12ULL,
		0xDF99D0722A0BB3DDULL,
		0x00E950626882E141ULL,
		0xBCD34768A01F6B11ULL,
		0xF639E08FAB388EAEULL,
		0x7A9C9A7ABD1DE730ULL,
		0xE48F1967EA5E688DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44E3D38D9124BBDULL,
		0x4900552265D58A12ULL,
		0xDF99D0722A0BB3DDULL,
		0x00E950626882E141ULL,
		0xBCD34768A01F6B11ULL,
		0xF639E08FAB388EAEULL,
		0x7A9C9A7ABD1DE730ULL,
		0xE48F1967EA5E688DULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0115F5B1CAA1DC02ULL,
		0xB45AC8E204B947B4ULL,
		0x732BB595519AB8ABULL,
		0xBE1EC811A9AE3E2BULL,
		0x711390991C672045ULL,
		0x24A673E6442A7D18ULL,
		0x74CCA2605C279257ULL,
		0xC8FC69B381C05822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9548592DB931AE84ULL,
		0x26195FC98A0CCDE6ULL,
		0x250D25E729B17634ULL,
		0xE4F1C1E549CBED4EULL,
		0x3FD4EEEEF15E4BFEULL,
		0x274F5C2EF2C9A168ULL,
		0x66D538DC98828007ULL,
		0x6B8F2C2D8727BCA6ULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA02957C0CFFDB3F7ULL,
		0xE867D092AD37579BULL,
		0x611F23C0DA46F74FULL,
		0x934955A59FD6BA92ULL,
		0x671A4515B4C8B849ULL,
		0x2F70F4FECE87BD8CULL,
		0xDD995C4ABD89AED2ULL,
		0x64E12C2E704E0CA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE13012A8C4CCE492ULL,
		0x650AF7BA70DA15C0ULL,
		0x097138B452A395BFULL,
		0x5E828467488C3759ULL,
		0xFA1BCC0F147ADA52ULL,
		0x2398027754350ADBULL,
		0x1045BFD722C8A850ULL,
		0x9480B9E4DF8E9DE3ULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE7885EE82B0CF82ULL,
		0x08C45BEC74519FBBULL,
		0xAF0475BF02B32DF4ULL,
		0xD5DA3864A9E7588DULL,
		0x529779401E406DCAULL,
		0x3B180944F36E6864ULL,
		0x62FE03E08FC9134BULL,
		0x8DD96E2F5368492BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3461EE30D87ECBDDULL,
		0x27F5478187B6554FULL,
		0xF51E88F1371DD028ULL,
		0xACA3E50FB62AABF4ULL,
		0xFCCD6DDE9C90CCB6ULL,
		0x952AC4B315E6AB15ULL,
		0x8C9CF925C6CC54AEULL,
		0x208E7C688200339CULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DC7DACCE433E9B3ULL,
		0xA007863862FC6E89ULL,
		0x2CB1A47509100462ULL,
		0xA6B4D1222AEB0C69ULL,
		0x317A13FDCE002964ULL,
		0x67C65BE4C994F1E5ULL,
		0xDC5265097694C7E2ULL,
		0x90194E5F9D5F5DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC7DACCE433E9B3ULL,
		0xA007863862FC6E89ULL,
		0x2CB1A47509100462ULL,
		0xA6B4D1222AEB0C69ULL,
		0x317A13FDCE002964ULL,
		0x67C65BE4C994F1E5ULL,
		0xDC5265097694C7E2ULL,
		0x90194E5F9D5F5DE1ULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB13F13512903EA9ULL,
		0x78474C899E78D3F4ULL,
		0x7791026D37942298ULL,
		0x767C9C1DCA1401E9ULL,
		0xC8BE8F232028E6DDULL,
		0x2BF4AD61673B4E5DULL,
		0x9DEEE4C871F1B6E8ULL,
		0x540235907BD68BB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6DB9C7CF8689688ULL,
		0xE191883D412F944AULL,
		0xC4E7000D83BDF736ULL,
		0xEF65D9FF16500E53ULL,
		0x81717A811A4DABCBULL,
		0x3D0490CF02945853ULL,
		0x065A7E02C16C740EULL,
		0xBB4493FAEA225BB5ULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC00040FBCFF36DFBULL,
		0xBBFC371F6D5CF44EULL,
		0xD466864C5648B5FCULL,
		0x3ED188D99CC1DF6FULL,
		0xE1E5DE9848D6DD63ULL,
		0x9EAEC5CECE7A3790ULL,
		0xF37BE67D4D9489E4ULL,
		0xDFE6F026F57C8CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09FE8ACD750CAA4BULL,
		0xA88D08D23AB0B209ULL,
		0x927A34CF1E482915ULL,
		0x27C72BB3C662B591ULL,
		0xDCC76F99A33D8080ULL,
		0xCE78C633C83EF2EAULL,
		0x00E7B20D624CCFE8ULL,
		0x47861633285220B4ULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92C8BC48A345B4A7ULL,
		0x49E9D633089BAADCULL,
		0xAEB8559DDA7D5B84ULL,
		0x4B98F708DBEB18ACULL,
		0x4335C7D0DBCC868FULL,
		0x735A9B904FF7B909ULL,
		0xC59A59CF017A2A6BULL,
		0xDBE85189F76A88C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x272EFB70EA9DC5A2ULL,
		0x22A25802F6EBC267ULL,
		0x80EAB9D9ADFA8A22ULL,
		0xFDA4BA85AFBC822FULL,
		0x9955D874FD7F6A91ULL,
		0xDC33D63659B4E725ULL,
		0x5E3691C2387299A8ULL,
		0xA4821AE270A61A61ULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x279819E4B1524ACCULL,
		0x3D51DDFE6144C899ULL,
		0x8C10D1F1B83ED39EULL,
		0xB4A4E9412E1B9FB9ULL,
		0xF0BF558EE7824855ULL,
		0xE0D45549B42EEF9FULL,
		0x396099C8B4F887A5ULL,
		0x9127260653452275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279819E4B1524ACCULL,
		0x3D51DDFE6144C899ULL,
		0x8C10D1F1B83ED39EULL,
		0xB4A4E9412E1B9FB9ULL,
		0xF0BF558EE7824855ULL,
		0xE0D45549B42EEF9FULL,
		0x396099C8B4F887A5ULL,
		0x9127260653452275ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA207B6DF13F22A73ULL,
		0x7225603AF9072B9FULL,
		0xF301DB094B9508C5ULL,
		0x747F6FCF39AF5FE2ULL,
		0xF08BC7A90D819FC0ULL,
		0x632BC40303743AA7ULL,
		0x15BB4B1D47121237ULL,
		0x75B234550793FA31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CAE770EAE0527FULL,
		0x156CAC77B6DCEA9BULL,
		0x96D516713FDD4DC3ULL,
		0x903D273DE696C576ULL,
		0xC8A80882B13FA03DULL,
		0xAA24A790855BBB2DULL,
		0x6603369D0856AE59ULL,
		0x2565199F37B1D74BULL
	}};
	t = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3327026B70BE376ULL,
		0x016B1D76BB88D130ULL,
		0x7630AD0B5921CF6CULL,
		0x7F7D4F94CF3D8DB8ULL,
		0x634621758F49E151ULL,
		0xEC38F2EE0DA3C3A7ULL,
		0xC6842CE68969D408ULL,
		0x798BFC30431544C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28FA96931AD7F522ULL,
		0x1E74408ED804D6EEULL,
		0xE13EB73A398CBB83ULL,
		0x0940A6962E0AE4ABULL,
		0xB6B34CF6098F70A5ULL,
		0x9313C396D7EDF684ULL,
		0x856DD0E8F4230A7EULL,
		0x7A7276C32F889548ULL
	}};
	t = -1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BE796E66E064B4DULL,
		0x291E34181ADE6733ULL,
		0xA7CE23A5FAC0FFBCULL,
		0xF80901C7105EA182ULL,
		0x4669A08C9D2B9B09ULL,
		0xA5284F92B6884BD7ULL,
		0x77CCDF119C365C1DULL,
		0xBDD03629CFE50ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8565553C51643A5AULL,
		0x1414AAF9491D9A5EULL,
		0xD4AF49979D2CDA67ULL,
		0x334AF052FFEA27DCULL,
		0x7B4161089C348D9AULL,
		0x79E62532A60AFBA4ULL,
		0x7B4740885C8D8750ULL,
		0xB3AE75AD0F37B00AULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE58EDEC3D45D53DAULL,
		0x0DE3AB7384570A74ULL,
		0x80CF366FB1630B73ULL,
		0xE3B6AEEAC7DFB5FFULL,
		0xE276F91D17876E41ULL,
		0xEA0A464F7E0D9033ULL,
		0xFC0EC6F5CC64B56EULL,
		0x7D4D4B72A1EF3E6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE58EDEC3D45D53DAULL,
		0x0DE3AB7384570A74ULL,
		0x80CF366FB1630B73ULL,
		0xE3B6AEEAC7DFB5FFULL,
		0xE276F91D17876E41ULL,
		0xEA0A464F7E0D9033ULL,
		0xFC0EC6F5CC64B56EULL,
		0x7D4D4B72A1EF3E6EULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD278614B14DCD907ULL,
		0xC4CFB0FFB170B6ACULL,
		0x4959D69A4F0160D5ULL,
		0x286D6CE222AF508AULL,
		0x263C1F820CDF3444ULL,
		0x5C91BE3F8E8FC5C7ULL,
		0x850BF05CCEB93710ULL,
		0x91AF14843FFDEA29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23B4D59C92299236ULL,
		0xF90577D729CDF2ADULL,
		0x74BB85E34BEC2F2CULL,
		0x7D395F01AFECE7CAULL,
		0xD84E5A38C86F51D1ULL,
		0x13FF77D00A15CCE6ULL,
		0x87BA92DAD37E4AFBULL,
		0xD6D6281C2097BF03ULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F7B0D803942BAE9ULL,
		0xE0ACB8DAE0E558D3ULL,
		0xD69894FFC5DAC239ULL,
		0xA84325F72F8B8AC5ULL,
		0x837F06BBC9D08623ULL,
		0xE2580C023245C1DBULL,
		0xEFF5996F956397C8ULL,
		0x873E49644551EB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3008CBFA277CF109ULL,
		0x77AE2A791A994803ULL,
		0x72490AF412A4129AULL,
		0x005C19675F174BCEULL,
		0x75686A439398E26DULL,
		0xC7A6763C6873A8EAULL,
		0x9F0A5DB0A307B95AULL,
		0xF5A9AFD17351F2ADULL
	}};
	t = -1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC4ED8043BC4E638ULL,
		0x88DFDCD19138A977ULL,
		0xEE4FD2447AAE2FC8ULL,
		0x0E90965AC36DCB52ULL,
		0x2228D8F34A627FD1ULL,
		0xBDBF00E96C58A2C5ULL,
		0x88A7C04021381D60ULL,
		0x128A27B789CC0C7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x913D8C41BD8CF30CULL,
		0x287643E42EC7ACF0ULL,
		0xCF0390C5F9E5AB88ULL,
		0x8EE075DFB6A16F27ULL,
		0x229DA06AB98BC86FULL,
		0x3228DEFE58289881ULL,
		0x2DDE41F86620F088ULL,
		0x5DF6BCF96FDD8100ULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x007E06EB80B7EF1AULL,
		0x7CA81014A05F2AFCULL,
		0x82E0F5A2F71DC68AULL,
		0x76AE2506EC1019F6ULL,
		0xB5AAA48D7271BDFBULL,
		0x1C12C9C3F338E280ULL,
		0x85F15DEBBD089A73ULL,
		0x88F0DB6FECBE7B36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x007E06EB80B7EF1AULL,
		0x7CA81014A05F2AFCULL,
		0x82E0F5A2F71DC68AULL,
		0x76AE2506EC1019F6ULL,
		0xB5AAA48D7271BDFBULL,
		0x1C12C9C3F338E280ULL,
		0x85F15DEBBD089A73ULL,
		0x88F0DB6FECBE7B36ULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD95B7732E0203EBAULL,
		0xB116F53690B1D291ULL,
		0xE213BF636F7D30B6ULL,
		0xF1D4D127991458E7ULL,
		0xD02F6C8170C27D77ULL,
		0x28D97B01CA9A48A3ULL,
		0x8EE5E46B2B77B75CULL,
		0xC28CE176F3BB6AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12431E540BB106C7ULL,
		0xE363EB981DE3378EULL,
		0xFF2A3698AFD31848ULL,
		0xA73BB7AC386B7FB3ULL,
		0x2AD4DD9DD2083EA0ULL,
		0x1CB58248FEE67C1AULL,
		0x6A842C87749A5B46ULL,
		0xFF2B3BE67FBDD77EULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26DF29B64D2136DAULL,
		0x80ABD232EF6874D9ULL,
		0xB467ACDABABA8C2AULL,
		0x623A84445862030DULL,
		0x5E7B22EE2274ADC5ULL,
		0x8D86682677F070ACULL,
		0x0DB57D80175544F3ULL,
		0xEE0649537F022A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F85F5E156824E98ULL,
		0xB6C79FD2B116D1A1ULL,
		0xC2A3434B25298B9BULL,
		0x99AC285E0B98F4F0ULL,
		0x217E004E8FD6D75EULL,
		0xF0203B73D104A8B9ULL,
		0x9A5D94F5447071CFULL,
		0x1F1832FA67AD47C2ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC49103788158A81FULL,
		0x2758AE206442A3FAULL,
		0x223817F2A92AD77CULL,
		0x95B313A58F5ADFDCULL,
		0x20A5B59FA9A569EDULL,
		0xBB2217D050DD3C87ULL,
		0x3EA400A0312F4919ULL,
		0xEB202D87339DDB2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1104BA9FCA7D72D3ULL,
		0xD55FB7A3BDCB9A21ULL,
		0x02EAE9332B9E589DULL,
		0x07B3486B6E6C5228ULL,
		0x71BE37F8BF452DFEULL,
		0xF7243869F137D23DULL,
		0x21C96E44F4108B68ULL,
		0x3CCC3EB1182483B1ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x465AA6C45C1B94ABULL,
		0x96F8016D39073154ULL,
		0x3092EEDABED653ABULL,
		0x49C53C41755897C2ULL,
		0x6EB8305F682284A2ULL,
		0x4C99E7C3D2068D20ULL,
		0x4FA3F522EEC1A9BBULL,
		0x286151117C3DF5AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x465AA6C45C1B94ABULL,
		0x96F8016D39073154ULL,
		0x3092EEDABED653ABULL,
		0x49C53C41755897C2ULL,
		0x6EB8305F682284A2ULL,
		0x4C99E7C3D2068D20ULL,
		0x4FA3F522EEC1A9BBULL,
		0x286151117C3DF5AFULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1BA8DBA37C66873ULL,
		0x471BDA1AA20C7A84ULL,
		0x68BFC85BC5CEA07FULL,
		0x3D5A5AC4C6C2596DULL,
		0xC626DF8A6716ACD1ULL,
		0xB5FF36B239C62361ULL,
		0x1C257D344205DE11ULL,
		0xDE2A905739F14546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD325455C5F8B7A15ULL,
		0xB492C09D2EDF9699ULL,
		0x931E8858C6FBFF0CULL,
		0xB1BC0C211A47F478ULL,
		0x3BEFBCA670ADE5ADULL,
		0x01D7BF6F7E9631C4ULL,
		0xEF6E597E1928588CULL,
		0xCCEE5579730C5154ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A5C64DC7CA14928ULL,
		0x4EF78B76C5AAE8ADULL,
		0x573AD6CA525B97BCULL,
		0x982029CD1957E090ULL,
		0x950824A0DED22767ULL,
		0xDF5E326F34E54C86ULL,
		0xF3AA057032CEA5E0ULL,
		0x6484E751ACEC7BDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3A105E01287052ULL,
		0xE4C4F2BBEFDF614CULL,
		0x6D99385DE77F7627ULL,
		0x349BB97A37550625ULL,
		0x217CB8063E649667ULL,
		0x89DC852F5F8BF78DULL,
		0x0CAAFF1916A20043ULL,
		0xC04A023A6255CD44ULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B715BB3A6410FC2ULL,
		0xD7614759C713207EULL,
		0xF1B74C5EBCC3C75CULL,
		0x4B746A8779968D97ULL,
		0x630DD0064497E593ULL,
		0x558A0151C40385F9ULL,
		0x2F49238C5F3F6558ULL,
		0xE178879AEDE8FD56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A8051409C8A471BULL,
		0x8073F1C9306C304FULL,
		0x87D6E425333E5500ULL,
		0xCA984CD824B44D79ULL,
		0x498600B6E046EF64ULL,
		0x42A0EE093DE14D35ULL,
		0x57C343EE6514587EULL,
		0x8CCC739D4A15C587ULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4568F0FF2C65A03AULL,
		0xF564538C6E0B471BULL,
		0x5CE06778E53E3946ULL,
		0x400F945D3F05FCC0ULL,
		0xAD0AB5E28841E18DULL,
		0x9B7009FD1CD4AF99ULL,
		0x02738D556D603420ULL,
		0xFF67DC39129F60C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4568F0FF2C65A03AULL,
		0xF564538C6E0B471BULL,
		0x5CE06778E53E3946ULL,
		0x400F945D3F05FCC0ULL,
		0xAD0AB5E28841E18DULL,
		0x9B7009FD1CD4AF99ULL,
		0x02738D556D603420ULL,
		0xFF67DC39129F60C3ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA20DD71BFA31AACFULL,
		0x62E382863048311BULL,
		0xCD23286885B601BFULL,
		0x86B2018402FFDF7DULL,
		0x174F013D2CE832D7ULL,
		0x4BC7A0C30FEBB177ULL,
		0x41FBF5B9D86E8CE8ULL,
		0x8DF839D217C1ADABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1DE5D32EC151E0ULL,
		0x9250E352A35DFBBCULL,
		0x8586C0237003CEEAULL,
		0xEBB58A17169E0D32ULL,
		0xC5FB11A69FD66A6FULL,
		0x45897D80B9CDBD7DULL,
		0x8AEE9A3A4B19FF46ULL,
		0x92D65FE21F99E3FBULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D61DB2AE6E3364AULL,
		0x411F8E8D1C72BF18ULL,
		0xD6C3ED1ED7383BFAULL,
		0xFBCF26229BE4D5E7ULL,
		0xE6D4BC8D236646B8ULL,
		0xB0EF78C2B709FDD4ULL,
		0x35D9CDDFC5E48D9CULL,
		0xBAE2B851D98AAD5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA50616754109BAFFULL,
		0x709A5B6E04F4C416ULL,
		0xC1F107841B16ABC2ULL,
		0xE8CAF83FAB4D7619ULL,
		0x7797696569CAA87CULL,
		0x5EF0F880BE60A175ULL,
		0x4BB0365B2556CB9FULL,
		0x7D7D37F1F89474FCULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11CE2B653A8A1D09ULL,
		0xA93E238B96EAC1A4ULL,
		0x42591B66C1C38227ULL,
		0x2D70C66D1D729CBCULL,
		0x6FDADBFB0E8C9EBAULL,
		0xAB0B69FAFD3E144CULL,
		0x1688FEBFAA669F26ULL,
		0x1D1CE1EF96107724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x263945223C8B1E5EULL,
		0x5A9F6EAA98B6F180ULL,
		0xBA9E3E4EB7B04BEFULL,
		0x84B65BEBA7CC330DULL,
		0xD95CA9FD3747C621ULL,
		0x4DC8A3971C8F95B6ULL,
		0xF7CE939EDE72E22EULL,
		0xA9CCAF34E6722A11ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x431071D8BE5E5A4CULL,
		0x00D43D9B17D1C5F9ULL,
		0xD6B04006CFB5E1DCULL,
		0x51213CAA1D016791ULL,
		0x8CB3D078BD16EB96ULL,
		0x2FC0AF4FB22427AAULL,
		0x665F4A152AFC231BULL,
		0x3D23742DD398F320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x431071D8BE5E5A4CULL,
		0x00D43D9B17D1C5F9ULL,
		0xD6B04006CFB5E1DCULL,
		0x51213CAA1D016791ULL,
		0x8CB3D078BD16EB96ULL,
		0x2FC0AF4FB22427AAULL,
		0x665F4A152AFC231BULL,
		0x3D23742DD398F320ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36CCBFFB547952BAULL,
		0xDACD19E03F7B740AULL,
		0x88A8440DF20F962AULL,
		0xBEBDA37525A55CBBULL,
		0x3D93CD156D54ED05ULL,
		0x0F5A5423EE041688ULL,
		0x94F9555BCC96C009ULL,
		0x2AC469B80295BCFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2666F14EAD917D9ULL,
		0x22140846D6BA0C48ULL,
		0x4C3EAB4FEF6B5189ULL,
		0xCC1C4837573246A3ULL,
		0x3C5DF5400A1E8127ULL,
		0x4233B3922B8DA24FULL,
		0xA95861BAA86DE521ULL,
		0x1C836B8921ED4A8AULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC80E8E659E549CB0ULL,
		0xB308FD29E83C4F6EULL,
		0x28B40443C55956C3ULL,
		0x0372B51AD3982584ULL,
		0x7C05108CD932A252ULL,
		0xD84B049FF001E373ULL,
		0x819DF34BA2708109ULL,
		0x1C0AB9BA14EBC5AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B2E8125B7DA332EULL,
		0x7E4C8B65762888A1ULL,
		0x2B51F44305A86221ULL,
		0x7C51A83A33CBC6CCULL,
		0x53628BBF20188594ULL,
		0xE85441A1E7B795B6ULL,
		0x62118C59AB2861ECULL,
		0x6F63B86B5AC844B4ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FAD3CA51078D172ULL,
		0x3FB7303BB3D956A6ULL,
		0x7D7B18C20DFA33EBULL,
		0x07FF66B59859A13EULL,
		0xD27425B344A6BBD1ULL,
		0x40E9F17C24F0AE0BULL,
		0xF5E05C436CF3FF32ULL,
		0x36F1AC6C4A708752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6B2021F3DC82379ULL,
		0x61ADCCCAB5772F0DULL,
		0x3B494555C5AC523DULL,
		0x766FB71CB53C5829ULL,
		0x2B72F3216AB63B3CULL,
		0x294AF8AC8B8715DDULL,
		0x071A27F065868F19ULL,
		0xAFE873ED64295549ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAF032D62C65443DULL,
		0x8FDB702581068B0BULL,
		0xA0807F1B21B8285CULL,
		0x07B8347DAECD9600ULL,
		0x4068F2BDAC163548ULL,
		0xD1680356EF833B57ULL,
		0x177E11BAF48BB0F5ULL,
		0x258FC7F45BB7FBB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF032D62C65443DULL,
		0x8FDB702581068B0BULL,
		0xA0807F1B21B8285CULL,
		0x07B8347DAECD9600ULL,
		0x4068F2BDAC163548ULL,
		0xD1680356EF833B57ULL,
		0x177E11BAF48BB0F5ULL,
		0x258FC7F45BB7FBB8ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66A7E112A11A823FULL,
		0x617A5C87083BB812ULL,
		0xB73D0ADA8520F555ULL,
		0x45EFDE2A5E5DCDF3ULL,
		0xC08C1CCC09B9115CULL,
		0x4442696318F1CEBAULL,
		0x0EA341AD09A493CBULL,
		0x285E35A73E261DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF903C2962AB5AACULL,
		0x020DA25991B8EEBFULL,
		0x4D5FAA6691E1EAE9ULL,
		0x6F83D90C8F50BAAFULL,
		0xDF15DD2A2F586355ULL,
		0xAFEF64BD17D3F8B3ULL,
		0x5AB778FFCF39B287ULL,
		0x9E3879E6AA0A2C62ULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E7C121D062FEF89ULL,
		0x8A1BC3BD43C1925EULL,
		0x2AA36073483C7AE3ULL,
		0xCF57E207D11E6D3BULL,
		0x6F9664FE97E971C6ULL,
		0x2BC31BE4211EB3DCULL,
		0x7A272BBF8B161638ULL,
		0x2296D93E8093A681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38BA76526F4AFC84ULL,
		0x989382603527F85BULL,
		0x401A7A2FA5C9C4F5ULL,
		0x8C9CD689181D9C3CULL,
		0xB2AE3E7C8C31B2D0ULL,
		0x009A88C1609294A1ULL,
		0x032284DAF530BEDBULL,
		0x9FD7A5B0168F14C5ULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A1B1458EA48D0AULL,
		0xB54680EB4041EDEBULL,
		0x79A824316338CF81ULL,
		0x2854D0F434E19588ULL,
		0xC7B012C8F2B14C52ULL,
		0x327816FA5D9387C8ULL,
		0x5386FA7662D3C5EDULL,
		0x0DFE570B8DD32666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AAD0FC76C8A4996ULL,
		0x3C3AFFD5EF0BA505ULL,
		0x9F20ED35BE240378ULL,
		0x076BFA1C7DE65FB5ULL,
		0x0F876558D61D10C2ULL,
		0x7B5FB8C2657C8834ULL,
		0x9FBB2959EF0F9A7DULL,
		0x9E40846F08023908ULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01D84A332E5A5708ULL,
		0x96EA306888A15158ULL,
		0x165A2BA1DDAEF6D5ULL,
		0xF7C316C0FC881DC8ULL,
		0xAFFC64D2A1C31CF5ULL,
		0xF1272169343DA364ULL,
		0x7743FF59006B6D24ULL,
		0x1472B5BA0C689DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01D84A332E5A5708ULL,
		0x96EA306888A15158ULL,
		0x165A2BA1DDAEF6D5ULL,
		0xF7C316C0FC881DC8ULL,
		0xAFFC64D2A1C31CF5ULL,
		0xF1272169343DA364ULL,
		0x7743FF59006B6D24ULL,
		0x1472B5BA0C689DAEULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69E1FD72955D0790ULL,
		0x22084779BD1D2F07ULL,
		0xB12E7CF724C23036ULL,
		0xD3808BAD95E8F669ULL,
		0x658CB459E371C06FULL,
		0xFFEF90D5D886ED5CULL,
		0xF15ED665C40E2C1DULL,
		0xC403BB95A657900EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA826C3DC96A5136ULL,
		0xCE89887183EB634EULL,
		0xAE84D1405242C616ULL,
		0x9C2197A6D38BDEF1ULL,
		0x2F25A35F0E77EEFBULL,
		0xF2748D550251E3D9ULL,
		0x689AF8D5AA1CC69FULL,
		0x0C60FCEB2424AA1DULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2C07D44D5768BC9ULL,
		0x5EE017FC21F84A3CULL,
		0x28600EC32E0CDDFCULL,
		0x6C568C5C717E09D3ULL,
		0x2FCDFEA747CDE36EULL,
		0x8A7579856C2CD675ULL,
		0x0024206AF2AD397DULL,
		0x88FA671DA6609F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021C25F516A5E8BCULL,
		0x2E3DC1D68708AE69ULL,
		0x3E28735F953E950BULL,
		0x8EC8556F78DC41B2ULL,
		0x29F3120B114CFC8FULL,
		0x4BF5C545FDE7183BULL,
		0xBA59A20E55328B75ULL,
		0xF036CE1A0D145E95ULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C38F1245EC75B68ULL,
		0xEEB84D43CAD296D9ULL,
		0x1EBBADDB6356708CULL,
		0x8B833EC8C1E56F25ULL,
		0x3CEC14FEC1379F4BULL,
		0xF6B1647A12EA4621ULL,
		0x0F022212AFC9343AULL,
		0xC802668D60B1277BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1736336E924DA7AEULL,
		0x363F5C00A9FB68B3ULL,
		0x0B1300D31D8C51C0ULL,
		0x941C1A0D71CC14E6ULL,
		0x2DDDBBD141063F7BULL,
		0x8E61F5842C2169DFULL,
		0xFC2952A878BC8E91ULL,
		0xEB0F3F827F5FBDAEULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
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