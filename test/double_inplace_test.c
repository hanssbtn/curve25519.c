#include "tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Double Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9614C6B6AEE361AEULL,
		0xE304F1DA2D394A9CULL,
		0xE83F9C99B8286F0CULL,
		0x146C990B695945EDULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x2C298D6D5DC6C35CULL,
		0xC609E3B45A729539ULL,
		0xD07F39337050DE19ULL,
		0x28D93216D2B28BDBULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x456151B1AA071BBFULL,
		0x381867BCFF0CCDFBULL,
		0x6BFB0A72623A8B7DULL,
		0x62FB2A6C6A5D522AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AC2A363540E3791ULL,
		0x7030CF79FE199BF6ULL,
		0xD7F614E4C47516FAULL,
		0x45F654D8D4BAA454ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xD3A3655A1DD2A3B0ULL,
		0xC63FE118D3D5E833ULL,
		0x666F0E081FCB51E8ULL,
		0x515F43EBCEACC1DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA746CAB43BA54773ULL,
		0x8C7FC231A7ABD067ULL,
		0xCCDE1C103F96A3D1ULL,
		0x22BE87D79D5983B8ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xF55AA2109F320BBEULL,
		0xC5C4CA6AF84D221CULL,
		0x63831A1E87A1862DULL,
		0x1382AF6EE18E11BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB544213E64177CULL,
		0x8B8994D5F09A4439ULL,
		0xC706343D0F430C5BULL,
		0x27055EDDC31C2376ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x8421CB17810C67E1ULL,
		0x9A86D345957273B6ULL,
		0x4748B519C1B37965ULL,
		0x41B244EB63AECFE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0843962F0218CFD5ULL,
		0x350DA68B2AE4E76DULL,
		0x8E916A338366F2CBULL,
		0x036489D6C75D9FC4ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xB8D8EA8C7B711A58ULL,
		0xB53896F4561508A8ULL,
		0xF2691F9A0C61EFA3ULL,
		0x6482BFBB45E31C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B1D518F6E234C3ULL,
		0x6A712DE8AC2A1151ULL,
		0xE4D23F3418C3DF47ULL,
		0x49057F768BC63801ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x4FA61DE21D3DA0F1ULL,
		0x1BEB3ADE964E33E6ULL,
		0xA77D1E05CF41146DULL,
		0x3CD987C8E22C4AF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F4C3BC43A7B41E2ULL,
		0x37D675BD2C9C67CCULL,
		0x4EFA3C0B9E8228DAULL,
		0x79B30F91C45895E5ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xDB4522A36F5281ABULL,
		0x0B90E46E44964D5AULL,
		0x4BB54025CB7C2ECEULL,
		0x29690453355AAADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB68A4546DEA50356ULL,
		0x1721C8DC892C9AB5ULL,
		0x976A804B96F85D9CULL,
		0x52D208A66AB555B4ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xF63B1EA92EB256E5ULL,
		0x0E0A490293ACDD62ULL,
		0xB23A1DE8F9FBB661ULL,
		0x71CC0775D9CE09B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC763D525D64ADDDULL,
		0x1C1492052759BAC5ULL,
		0x64743BD1F3F76CC2ULL,
		0x63980EEBB39C1369ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xEB5443BFCCB2A2A5ULL,
		0xEE4D3A27A8B159F2ULL,
		0x6F53DE8D757B8D06ULL,
		0x6CAAA1915786A995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A8877F9965455DULL,
		0xDC9A744F5162B3E5ULL,
		0xDEA7BD1AEAF71A0DULL,
		0x59554322AF0D532AULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x9C37416E5FBDF8D6ULL,
		0xF21D018C23E67C75ULL,
		0x3FFC80E2179388C8ULL,
		0x7BCEDEECCAE5B4C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x386E82DCBF7BF1BFULL,
		0xE43A031847CCF8EBULL,
		0x7FF901C42F271191ULL,
		0x779DBDD995CB6988ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xC94B0DB760B76761ULL,
		0x2AE855BCF06A3903ULL,
		0x3BAFE0159BEAD49DULL,
		0x7B9968520C8866EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92961B6EC16ECED5ULL,
		0x55D0AB79E0D47207ULL,
		0x775FC02B37D5A93AULL,
		0x7732D0A41910CDD4ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xF78ADE4CEA26ED98ULL,
		0xB79416D8DFD6F19AULL,
		0xEC473F86CFB0ED76ULL,
		0x6A9D1BC5912AAF5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF15BC99D44DDB43ULL,
		0x6F282DB1BFADE335ULL,
		0xD88E7F0D9F61DAEDULL,
		0x553A378B22555EBBULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x3694B67DBB05102BULL,
		0x5903E0D0160D4844ULL,
		0x4615C67B022C94C2ULL,
		0x72B47A8EF06AD0B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D296CFB760A2069ULL,
		0xB207C1A02C1A9088ULL,
		0x8C2B8CF604592984ULL,
		0x6568F51DE0D5A164ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xB27B4ADF21967B90ULL,
		0xF341890AF1E2AA70ULL,
		0x55244292535BA3D1ULL,
		0x1DE23138F4068F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F695BE432CF720ULL,
		0xE6831215E3C554E1ULL,
		0xAA488524A6B747A3ULL,
		0x3BC46271E80D1E6AULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xB09B0CCCB4D28C04ULL,
		0xB76AFEB51E9C1ECAULL,
		0x62F64CDE473841A3ULL,
		0x4CFCE8A2DA9D896EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6136199969A5181BULL,
		0x6ED5FD6A3D383D95ULL,
		0xC5EC99BC8E708347ULL,
		0x19F9D145B53B12DCULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xD3EFBCC11F6B13DAULL,
		0x07A1F0D0816BDC3CULL,
		0x042F867CE152DCEDULL,
		0x1B55397F742879F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DF79823ED627B4ULL,
		0x0F43E1A102D7B879ULL,
		0x085F0CF9C2A5B9DAULL,
		0x36AA72FEE850F3E2ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xB008A3A2D87E7D2DULL,
		0xC50E6AB95B31827DULL,
		0x36197883C4D7A7FEULL,
		0x434A8B8321AFDF01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60114745B0FCFA6DULL,
		0x8A1CD572B66304FBULL,
		0x6C32F10789AF4FFDULL,
		0x06951706435FBE02ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x6759003B922D68E0ULL,
		0x02C4916D0EECE90AULL,
		0x95B8A969F5511128ULL,
		0x1D3FC7DA01984A21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB20077245AD1C0ULL,
		0x058922DA1DD9D214ULL,
		0x2B7152D3EAA22250ULL,
		0x3A7F8FB403309443ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xDFFFBDE3319F13C2ULL,
		0x325627ED9E33023CULL,
		0x2C8251D5C7A1B8BEULL,
		0x08E41A2E819EF888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFFF7BC6633E2784ULL,
		0x64AC4FDB3C660479ULL,
		0x5904A3AB8F43717CULL,
		0x11C8345D033DF110ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x79C3A4E2A11F2D85ULL,
		0x19EC23787425ACBDULL,
		0xB56BE3D53ACBE08FULL,
		0x251EFCD9B62D0406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38749C5423E5B0AULL,
		0x33D846F0E84B597AULL,
		0x6AD7C7AA7597C11EULL,
		0x4A3DF9B36C5A080DULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xD2E7C09030D9ED7EULL,
		0x998F5886DDA9B890ULL,
		0x2496D0CE43FFAFC8ULL,
		0x07AEFFB407C50C6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5CF812061B3DAFCULL,
		0x331EB10DBB537121ULL,
		0x492DA19C87FF5F91ULL,
		0x0F5DFF680F8A18DEULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x9B6C5B23359C6094ULL,
		0xEB4E55878F27600CULL,
		0x8DD5B95869827807ULL,
		0x61E1406D3B757335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D8B6466B38C13BULL,
		0xD69CAB0F1E4EC019ULL,
		0x1BAB72B0D304F00FULL,
		0x43C280DA76EAE66BULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xD640A30D0DEFDEB6ULL,
		0xA60875DEDEBCFFFEULL,
		0xB12667A054E4F554ULL,
		0x7853E15C294C8C42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC81461A1BDFBD7FULL,
		0x4C10EBBDBD79FFFDULL,
		0x624CCF40A9C9EAA9ULL,
		0x70A7C2B852991885ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xAB1646D9DA8AF91FULL,
		0xA821ABAE76B018D1ULL,
		0xF5E87662B7150403ULL,
		0x020B0B0F5DCBA1CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x562C8DB3B515F23EULL,
		0x5043575CED6031A3ULL,
		0xEBD0ECC56E2A0807ULL,
		0x0416161EBB974399ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x196B518B6AF40C1FULL,
		0xE9D09B52A875EA46ULL,
		0x5880FA5F6D8C4180ULL,
		0x391238631F486BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D6A316D5E8183EULL,
		0xD3A136A550EBD48CULL,
		0xB101F4BEDB188301ULL,
		0x722470C63E90D7B8ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x03138F6A433860A8ULL,
		0x8C036731DA21337BULL,
		0x25F208878586763BULL,
		0x2B8C9C4ADD21F12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06271ED48670C150ULL,
		0x1806CE63B44266F6ULL,
		0x4BE4110F0B0CEC77ULL,
		0x57193895BA43E25CULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x9B40C811525C6185ULL,
		0x7DF9B08451E6C63AULL,
		0x7C52BE6152B301C8ULL,
		0x757405710EBD37B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36819022A4B8C31DULL,
		0xFBF36108A3CD8C75ULL,
		0xF8A57CC2A5660390ULL,
		0x6AE80AE21D7A6F6EULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xAE19EA6DAF9FD96DULL,
		0xCA887DD320DD0D5CULL,
		0xB34AF3276C863376ULL,
		0x359EA63D2D2D806EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C33D4DB5F3FB2DAULL,
		0x9510FBA641BA1AB9ULL,
		0x6695E64ED90C66EDULL,
		0x6B3D4C7A5A5B00DDULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xECD88EB3547404D2ULL,
		0x7576F1E78392E747ULL,
		0x892F8C95E29F0E79ULL,
		0x37D28DF742860391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9B11D66A8E809A4ULL,
		0xEAEDE3CF0725CE8FULL,
		0x125F192BC53E1CF2ULL,
		0x6FA51BEE850C0723ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x5BB44E439552BC92ULL,
		0x51681E6C62360E81ULL,
		0x7C1AC76F93641047ULL,
		0x208F3677B892384DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7689C872AA57924ULL,
		0xA2D03CD8C46C1D02ULL,
		0xF8358EDF26C8208EULL,
		0x411E6CEF7124709AULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x7983899315332E78ULL,
		0xD6098AD6CDBDA655ULL,
		0x902BE5E063797C50ULL,
		0x2E28DA734119C4D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF30713262A665CF0ULL,
		0xAC1315AD9B7B4CAAULL,
		0x2057CBC0C6F2F8A1ULL,
		0x5C51B4E6823389A3ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x249A5251D4FCFD46ULL,
		0x98F347A9846F6E77ULL,
		0x68815F075C9849F2ULL,
		0x65619FA6EC91CD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4934A4A3A9F9FA9FULL,
		0x31E68F5308DEDCEEULL,
		0xD102BE0EB93093E5ULL,
		0x4AC33F4DD9239A38ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x56467FF3C39DF960ULL,
		0xEBC783CBE0FE780BULL,
		0x996E3D94933B0382ULL,
		0x7A71B379C2119F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC8CFFE7873BF2D3ULL,
		0xD78F0797C1FCF016ULL,
		0x32DC7B2926760705ULL,
		0x74E366F384233EC3ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x3BFE2C01D82AFF74ULL,
		0xC8B6539D26B58A17ULL,
		0x1B7D81D6D297700EULL,
		0x5E4F9D6E27A8E82DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77FC5803B055FEFBULL,
		0x916CA73A4D6B142EULL,
		0x36FB03ADA52EE01DULL,
		0x3C9F3ADC4F51D05AULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xBFCFBAE89B5AC25CULL,
		0xC1310B61DEB8759CULL,
		0x5D0FB85B4527A2F8ULL,
		0x5A1DBBFCFDE90F8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F9F75D136B584CBULL,
		0x826216C3BD70EB39ULL,
		0xBA1F70B68A4F45F1ULL,
		0x343B77F9FBD21F1EULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x2C2DA3CE344F6625ULL,
		0xFCC39F265D7632D0ULL,
		0xB93813FFEE83AAB3ULL,
		0x7B808ABE4A481EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x585B479C689ECC5DULL,
		0xF9873E4CBAEC65A0ULL,
		0x727027FFDD075567ULL,
		0x7701157C94903DF9ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x68D2668F1D233257ULL,
		0x8E8D4555A942AA1AULL,
		0x4923708C857C555EULL,
		0x56C38B2A05EDCE44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A4CD1E3A4664C1ULL,
		0x1D1A8AAB52855434ULL,
		0x9246E1190AF8AABDULL,
		0x2D8716540BDB9C88ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x0410ECACBF99461EULL,
		0x27F111554C568CC5ULL,
		0x38DFA2DC62D6CA02ULL,
		0x4838D5B1C8605182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0821D9597F328C4FULL,
		0x4FE222AA98AD198AULL,
		0x71BF45B8C5AD9404ULL,
		0x1071AB6390C0A304ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x4E83AFD57D653EDBULL,
		0x3BD14EA278FDC557ULL,
		0xDA8BC2BA6A159F5EULL,
		0x1816C4CD6A0FA1AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D075FAAFACA7DB6ULL,
		0x77A29D44F1FB8AAEULL,
		0xB5178574D42B3EBCULL,
		0x302D899AD41F4355ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x6D47D55AE1EE01C8ULL,
		0x7218FE00C1430EC1ULL,
		0x1B9EB1F6FA9B7D25ULL,
		0x73B717C106F999FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA8FAAB5C3DC03A3ULL,
		0xE431FC0182861D82ULL,
		0x373D63EDF536FA4AULL,
		0x676E2F820DF333FAULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xEA858EED84912787ULL,
		0x054C8938A798EF3AULL,
		0x50D46A5DEADCF6A8ULL,
		0x14EB1BA447944864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50B1DDB09224F0EULL,
		0x0A9912714F31DE75ULL,
		0xA1A8D4BBD5B9ED50ULL,
		0x29D637488F2890C8ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xF181CB75168EA81DULL,
		0xB11D6AF8F3A4BCA8ULL,
		0xB9783C75C97629F7ULL,
		0x4339F358507D9039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE30396EA2D1D504DULL,
		0x623AD5F1E7497951ULL,
		0x72F078EB92EC53EFULL,
		0x0673E6B0A0FB2073ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x16035DAC61ADF771ULL,
		0x4781136F008F11BEULL,
		0x5D3003D24A14487EULL,
		0x4BC0D914E9D275B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C06BB58C35BEEF5ULL,
		0x8F0226DE011E237CULL,
		0xBA6007A4942890FCULL,
		0x1781B229D3A4EB6AULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xD2426569D7D2B154ULL,
		0x60EFCFAC000CF369ULL,
		0x0F87AC9A5BD43A20ULL,
		0x3018AB19F1742989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA484CAD3AFA562A8ULL,
		0xC1DF9F580019E6D3ULL,
		0x1F0F5934B7A87440ULL,
		0x60315633E2E85312ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x7C584F3DDFF14AD7ULL,
		0x034C70E6EDB8FE2DULL,
		0x1752FC9468628C9CULL,
		0x6E24C05A9B7938B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8B09E7BBFE295C1ULL,
		0x0698E1CDDB71FC5AULL,
		0x2EA5F928D0C51938ULL,
		0x5C4980B536F2716AULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0xB4BCACC24DBC68B9ULL,
		0xFCEF85444865C65AULL,
		0xB3E423CDDBC8B23BULL,
		0x2FAE5CDB51384C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x697959849B78D172ULL,
		0xF9DF0A8890CB8CB5ULL,
		0x67C8479BB7916477ULL,
		0x5F5CB9B6A27098C7ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x9AE566414F28D4BEULL,
		0x80E655F83FCE56ABULL,
		0xF6A412B1153521AFULL,
		0x19BA24A3CED31E1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35CACC829E51A97CULL,
		0x01CCABF07F9CAD57ULL,
		0xED4825622A6A435FULL,
		0x337449479DA63C35ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x75006BE308BBDA55ULL,
		0xC12759C8EC20A7E7ULL,
		0xD315012B644F5F8BULL,
		0x4D47DDBFFA208C8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA00D7C61177B4BDULL,
		0x824EB391D8414FCEULL,
		0xA62A0256C89EBF17ULL,
		0x1A8FBB7FF441191DULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
		0x08E055BC1D35FAD7ULL,
		0xC39D4F05E4416D31ULL,
		0xBC72E8FB30C6145EULL,
		0x7DC1F4B02EF61652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C0AB783A6BF5C1ULL,
		0x873A9E0BC882DA62ULL,
		0x78E5D1F6618C28BDULL,
		0x7B83E9605DEC2CA5ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
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
	k1 = (curve25519_key_t){.key64 = {
		0x12EC53F278A7345AULL,
		0x1E120EB26B5B3D4FULL,
		0x1E25126F80956AAFULL,
		0x3B2069F4C747BEE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D8A7E4F14E68B4ULL,
		0x3C241D64D6B67A9EULL,
		0x3C4A24DF012AD55EULL,
		0x7640D3E98E8F7DC6ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11F0EEB97D760F28ULL,
		0x05C85A84BA5B1C19ULL,
		0xB937C7087E7AC7E3ULL,
		0x080B0528D5D1B815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23E1DD72FAEC1E50ULL,
		0x0B90B50974B63832ULL,
		0x726F8E10FCF58FC6ULL,
		0x10160A51ABA3702BULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB376EE366E43FDE2ULL,
		0xDC7DDC7C65213EC2ULL,
		0x30941DD04FEFB98CULL,
		0x03E1F6BFE101345AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66EDDC6CDC87FBC4ULL,
		0xB8FBB8F8CA427D85ULL,
		0x61283BA09FDF7319ULL,
		0x07C3ED7FC20268B4ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2C88B5DD928EB5BULL,
		0xDACFEDBC9BCFC161ULL,
		0xEA12CED95356BDC9ULL,
		0x4F18B97F3B73CC4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659116BBB251D6C9ULL,
		0xB59FDB79379F82C3ULL,
		0xD4259DB2A6AD7B93ULL,
		0x1E3172FE76E79899ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CA851B9985FDD0BULL,
		0x081E8A8EAFCDC77FULL,
		0x94F26D1A0D6F1B8DULL,
		0x6F60CE3BE82243ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5950A37330BFBA29ULL,
		0x103D151D5F9B8EFEULL,
		0x29E4DA341ADE371AULL,
		0x5EC19C77D044875BULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD812B5991E068D02ULL,
		0xD620D0F01E47F0F7ULL,
		0x41A45ECB2D0F7A71ULL,
		0x3772AE6E74044129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0256B323C0D1A04ULL,
		0xAC41A1E03C8FE1EFULL,
		0x8348BD965A1EF4E3ULL,
		0x6EE55CDCE8088252ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A0CE95A6BCACA68ULL,
		0x9B550E93CAA44956ULL,
		0x0ED64495E91664CDULL,
		0x482BCC11C5303653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD419D2B4D79594E3ULL,
		0x36AA1D27954892ACULL,
		0x1DAC892BD22CC99BULL,
		0x105798238A606CA6ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x372E3EFA2CC1F16CULL,
		0xEFF3ACD07AD8A0F9ULL,
		0xBDBA330ADBCB16D9ULL,
		0x321C1FC86BD377CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E5C7DF45983E2D8ULL,
		0xDFE759A0F5B141F2ULL,
		0x7B746615B7962DB3ULL,
		0x64383F90D7A6EF9BULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE272AFFFE4D08B1BULL,
		0x2E164279789E257CULL,
		0xAD8BC32A37E517E2ULL,
		0x0B58C096037A9F1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E55FFFC9A11636ULL,
		0x5C2C84F2F13C4AF9ULL,
		0x5B1786546FCA2FC4ULL,
		0x16B1812C06F53E3DULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B8B34D98C5701DDULL,
		0x36DAEAC811100C8EULL,
		0x9FB86CF7122B94C1ULL,
		0x6382D9433244BDAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171669B318AE03CDULL,
		0x6DB5D5902220191CULL,
		0x3F70D9EE24572982ULL,
		0x4705B28664897B5FULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F685C2A67014D03ULL,
		0x4B74A7B1345390BDULL,
		0xE352C7DE91E79A0DULL,
		0x2972817782DD4AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ED0B854CE029A06ULL,
		0x96E94F6268A7217AULL,
		0xC6A58FBD23CF341AULL,
		0x52E502EF05BA956BULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CFB6553976DE865ULL,
		0x55F85C6D7B70C538ULL,
		0xFACA27AB4DDDA986ULL,
		0x5929FFE112BFBFC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9F6CAA72EDBD0DDULL,
		0xABF0B8DAF6E18A70ULL,
		0xF5944F569BBB530CULL,
		0x3253FFC2257F7F81ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD34EDC6A9A6CF2EULL,
		0xE2932CC1A06021EFULL,
		0xF196B6134B950F1EULL,
		0x5EF5E4D4AB5AA2BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A69DB8D534D9E6FULL,
		0xC526598340C043DFULL,
		0xE32D6C26972A1E3DULL,
		0x3DEBC9A956B54577ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC19304B5D1ECA92ULL,
		0x2D3EDCB3C073474AULL,
		0x11C7C4BBE0118B19ULL,
		0x5798FC9AEEE18C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8326096BA3D9537ULL,
		0x5A7DB96780E68E95ULL,
		0x238F8977C0231632ULL,
		0x2F31F935DDC318F2ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA059E61DC081CC18ULL,
		0x96B1789B626D1843ULL,
		0x31A8CBB9451398C6ULL,
		0x58D12B0884C7A89EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B3CC3B81039843ULL,
		0x2D62F136C4DA3087ULL,
		0x635197728A27318DULL,
		0x31A25611098F513CULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4929EF35A606EA2ULL,
		0xFD8AFDE921FB710DULL,
		0x304B424B07B23985ULL,
		0x46173C602D42AF8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89253DE6B4C0DD57ULL,
		0xFB15FBD243F6E21BULL,
		0x609684960F64730BULL,
		0x0C2E78C05A855F1AULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52705F6A7B011FF0ULL,
		0xC48DEA1F1516A635ULL,
		0xF292C39DBB7CD88DULL,
		0x78157DABB745E376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4E0BED4F6023FF3ULL,
		0x891BD43E2A2D4C6AULL,
		0xE525873B76F9B11BULL,
		0x702AFB576E8BC6EDULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B0A7E6303E555F7ULL,
		0x65A444469F2D94F9ULL,
		0xA37D72FCFF0FED5CULL,
		0x0DC8C7AC00F65CEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5614FCC607CAABEEULL,
		0xCB48888D3E5B29F2ULL,
		0x46FAE5F9FE1FDAB8ULL,
		0x1B918F5801ECB9DFULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70D8CA3E26071491ULL,
		0x53FE17D6DCD95CADULL,
		0x9113137E66069F04ULL,
		0x3F54EA6BF10BBF16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1B1947C4C0E2922ULL,
		0xA7FC2FADB9B2B95AULL,
		0x222626FCCC0D3E08ULL,
		0x7EA9D4D7E2177E2DULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x547747A1DBFC3F95ULL,
		0x77A98B9D90C1EE45ULL,
		0xDB375005CD08660BULL,
		0x7791A23640EC639BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8EE8F43B7F87F3DULL,
		0xEF53173B2183DC8AULL,
		0xB66EA00B9A10CC16ULL,
		0x6F23446C81D8C737ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72D8CCE0864CF4DDULL,
		0x33108FC5000DC012ULL,
		0x39DCE68C3B12DE12ULL,
		0x7229E58039E29EFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B199C10C99E9CDULL,
		0x66211F8A001B8024ULL,
		0x73B9CD187625BC24ULL,
		0x6453CB0073C53DF4ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85A6D90E99AA66A3ULL,
		0xBDE32C23967AC469ULL,
		0xA913E428995DE795ULL,
		0x4B046E88EDCB6958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4DB21D3354CD59ULL,
		0x7BC658472CF588D3ULL,
		0x5227C85132BBCF2BULL,
		0x1608DD11DB96D2B1ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88221D4FB106CEDAULL,
		0x3399DDC59E595180ULL,
		0x41E62B46E28E1FCBULL,
		0x0A4908866D473E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10443A9F620D9DB4ULL,
		0x6733BB8B3CB2A301ULL,
		0x83CC568DC51C3F96ULL,
		0x1492110CDA8E7C74ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA08642599F06CDD8ULL,
		0x165CE3F8245EDCA3ULL,
		0xC5DC6F57EA72DB53ULL,
		0x0AA309C1569EC573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x410C84B33E0D9BB0ULL,
		0x2CB9C7F048BDB947ULL,
		0x8BB8DEAFD4E5B6A6ULL,
		0x15461382AD3D8AE7ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BAA66F6A757B2CFULL,
		0x63634A31E2885A53ULL,
		0xDB4F37B123F52908ULL,
		0x7A27456D4D1C4524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3754CDED4EAF65B1ULL,
		0xC6C69463C510B4A6ULL,
		0xB69E6F6247EA5210ULL,
		0x744E8ADA9A388A49ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF96AFD06599AEFCAULL,
		0x558EE0D9003B7E35ULL,
		0x33578EAFDA16827AULL,
		0x329E4B91C3BFC719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D5FA0CB335DF94ULL,
		0xAB1DC1B20076FC6BULL,
		0x66AF1D5FB42D04F4ULL,
		0x653C9723877F8E32ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x370C14331C338F99ULL,
		0x9AEF1C26679221D1ULL,
		0xE930C8701E56ED0FULL,
		0x0434526308225AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E18286638671F32ULL,
		0x35DE384CCF2443A2ULL,
		0xD26190E03CADDA1FULL,
		0x0868A4C61044B55DULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16DA8DEA4DC131ACULL,
		0xCC90D273730638F8ULL,
		0x8D408BC232A6DEA0ULL,
		0x5AEA764D896A891CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB51BD49B82636BULL,
		0x9921A4E6E60C71F0ULL,
		0x1A811784654DBD41ULL,
		0x35D4EC9B12D51239ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE993769F48332D7ULL,
		0xD6E27EC8FF25D444ULL,
		0xEB81FE6405B175A7ULL,
		0x3F539041CE0A60BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D326ED3E90665AEULL,
		0xADC4FD91FE4BA889ULL,
		0xD703FCC80B62EB4FULL,
		0x7EA720839C14C179ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60F5E2139D325FEAULL,
		0x70AF195A4D4A2C33ULL,
		0xD842AD81E5BC7AECULL,
		0x4D8474617241EA8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1EBC4273A64BFE7ULL,
		0xE15E32B49A945866ULL,
		0xB0855B03CB78F5D8ULL,
		0x1B08E8C2E483D51FULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8EFB1F00895FA70ULL,
		0x5CE58BA268C1D091ULL,
		0xE98D8C5B993AFEE5ULL,
		0x47AD946F4C772EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DF63E0112BF4F3ULL,
		0xB9CB1744D183A123ULL,
		0xD31B18B73275FDCAULL,
		0x0F5B28DE98EE5D41ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32E37A2CB7D22222ULL,
		0x6AF1451C36FA17FDULL,
		0x5AB691D3E06BF643ULL,
		0x4827250D23DDF7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C6F4596FA44457ULL,
		0xD5E28A386DF42FFAULL,
		0xB56D23A7C0D7EC86ULL,
		0x104E4A1A47BBEF7EULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C2ADA6F7665391EULL,
		0x0C0C3CDB1D4D5B51ULL,
		0x902D160AF6DBF0C9ULL,
		0x30E697ADEA369987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5855B4DEECCA723CULL,
		0x181879B63A9AB6A2ULL,
		0x205A2C15EDB7E192ULL,
		0x61CD2F5BD46D330FULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x623386FF5FDA1120ULL,
		0x846851044DAAF7D4ULL,
		0x00302DD6A5B9AE3AULL,
		0x5E95D11FBBA59C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4670DFEBFB42253ULL,
		0x08D0A2089B55EFA8ULL,
		0x00605BAD4B735C75ULL,
		0x3D2BA23F774B3838ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26BE63FDA7A5408EULL,
		0x5BD8CDBB650C2DE3ULL,
		0x91298F805FC60B45ULL,
		0x001402ABB9F93A8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D7CC7FB4F4A811CULL,
		0xB7B19B76CA185BC6ULL,
		0x22531F00BF8C168AULL,
		0x0028055773F2751DULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CB41BCD86AF257BULL,
		0xE5FE3C22BA3C7618ULL,
		0x8FE4AF70224B778EULL,
		0x0CD28569DFCAC2D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7968379B0D5E4AF6ULL,
		0xCBFC78457478EC30ULL,
		0x1FC95EE04496EF1DULL,
		0x19A50AD3BF9585A7ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7180989490E11559ULL,
		0x72459A3836BB1BA1ULL,
		0xB492585C1DA6D139ULL,
		0x5CF6DD30EAB32F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE301312921C22AC5ULL,
		0xE48B34706D763742ULL,
		0x6924B0B83B4DA272ULL,
		0x39EDBA61D5665EA7ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08D884D079739221ULL,
		0xD3D91F5B5F43384AULL,
		0x82EBBE0397868536ULL,
		0x7A51E5002ADE791DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B109A0F2E72455ULL,
		0xA7B23EB6BE867094ULL,
		0x05D77C072F0D0A6DULL,
		0x74A3CA0055BCF23BULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D16A53D38FC1BB1ULL,
		0xF4FC32D077DE2211ULL,
		0x891C41905B3EBEB8ULL,
		0x2CB0AEB7FE7EDF3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2D4A7A71F83762ULL,
		0xE9F865A0EFBC4422ULL,
		0x12388320B67D7D71ULL,
		0x59615D6FFCFDBE79ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B7C2E11205C31AFULL,
		0x18798B641D55C27DULL,
		0x6483556976E3A92AULL,
		0x4A7F82E85A8E1CA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F85C2240B86371ULL,
		0x30F316C83AAB84FBULL,
		0xC906AAD2EDC75254ULL,
		0x14FF05D0B51C3946ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73B5FD759659F1A4ULL,
		0x8A308C33A9F49308ULL,
		0x8D0A0AFE826DACD2ULL,
		0x79AE7DF5769DC1F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE76BFAEB2CB3E35BULL,
		0x1461186753E92610ULL,
		0x1A1415FD04DB59A5ULL,
		0x735CFBEAED3B83E7ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0B0962B5FCAB47BULL,
		0xAAAF58BE446FC873ULL,
		0x5E53EBDFEBC97E89ULL,
		0x5767E27EFDB33608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1612C56BF956909ULL,
		0x555EB17C88DF90E7ULL,
		0xBCA7D7BFD792FD13ULL,
		0x2ECFC4FDFB666C10ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B272745CA727136ULL,
		0xD1D572138B6C45CAULL,
		0x57C3413266B7A88BULL,
		0x656C07B270579F4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x764E4E8B94E4E27FULL,
		0xA3AAE42716D88B94ULL,
		0xAF868264CD6F5117ULL,
		0x4AD80F64E0AF3E96ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE49AC57F0682BBCFULL,
		0xDC628B1D2C85066AULL,
		0xC32813547C21A22EULL,
		0x1F9A90C128E3E03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9358AFE0D05779EULL,
		0xB8C5163A590A0CD5ULL,
		0x865026A8F843445DULL,
		0x3F35218251C7C07BULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE0478EF4E5A9552ULL,
		0xACAB8162FEF3A6C5ULL,
		0xA87EA7D2050D2187ULL,
		0x4B57750C52C2FD90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC08F1DE9CB52AB7ULL,
		0x595702C5FDE74D8BULL,
		0x50FD4FA40A1A430FULL,
		0x16AEEA18A585FB21ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCD93B895F84C71BULL,
		0x95D97E8777740F0EULL,
		0xF10A3C453698778CULL,
		0x2B5B66BC892883C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B27712BF098E36ULL,
		0x2BB2FD0EEEE81E1DULL,
		0xE214788A6D30EF19ULL,
		0x56B6CD7912510789ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD99E13ADFAFAB12BULL,
		0x0CA89504E4BFE01FULL,
		0x07567EAD7D7FAE94ULL,
		0x077B78BF58FCF01CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB33C275BF5F56256ULL,
		0x19512A09C97FC03FULL,
		0x0EACFD5AFAFF5D28ULL,
		0x0EF6F17EB1F9E038ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF83196C96F4BECE6ULL,
		0x6DDC566857F9B9FCULL,
		0x254263DBB71E9A08ULL,
		0x58E0645915137FB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0632D92DE97D9DFULL,
		0xDBB8ACD0AFF373F9ULL,
		0x4A84C7B76E3D3410ULL,
		0x31C0C8B22A26FF62ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B740DEED09F7E82ULL,
		0x6F19C19F4437FC9EULL,
		0x9AAFE675BABE187EULL,
		0x065B74AE35C54476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E81BDDA13EFD04ULL,
		0xDE33833E886FF93CULL,
		0x355FCCEB757C30FCULL,
		0x0CB6E95C6B8A88EDULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD6800A5D80F0CBFULL,
		0x3E35285646C29BC1ULL,
		0xC878E5EF84A83831ULL,
		0x1B7A586CE5D360C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD0014BB01E197EULL,
		0x7C6A50AC8D853783ULL,
		0x90F1CBDF09507062ULL,
		0x36F4B0D9CBA6C181ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}