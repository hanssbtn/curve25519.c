#include "tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Sub Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0xEC90893D1E159479ULL,
		0x428F99E71F358D82ULL,
		0x9AF3BCE413834FE9ULL,
		0x4DB5CE708D51F106ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3AEA09AFA721D6F9ULL,
		0x3AA0DBD8840BBA6CULL,
		0xAC4FCA2134708BE5ULL,
		0x5D337CAFDE827A59ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xB1A67F8D76F3BD6DULL,
		0x07EEBE0E9B29D316ULL,
		0xEEA3F2C2DF12C404ULL,
		0x708251C0AECF76ACULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x12287706D42F1EACULL,
		0x6485F0A289FAC03DULL,
		0xF107353BE0C5BE61ULL,
		0x3560CA8E8C27E650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CD78112A2BEDDCDULL,
		0x6325A0F05F2E7A2BULL,
		0x7B0E880A27D8914DULL,
		0x1C3B38EEB4A37D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8550F5F4317040DFULL,
		0x01604FB22ACC4611ULL,
		0x75F8AD31B8ED2D14ULL,
		0x1925919FD7846939ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0A0AFFDE4F883EECULL,
		0x8DB6B927524A40BDULL,
		0xFAFECA1A2B63938AULL,
		0x527C02115DD84B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50005CBEB95286B2ULL,
		0xAC299646CD94080DULL,
		0xFF1AED22BECFAA67ULL,
		0x604A948F4D578DF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA0AA31F9635B827ULL,
		0xE18D22E084B638AFULL,
		0xFBE3DCF76C93E922ULL,
		0x72316D821080BD80ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xEDA59513C45766B2ULL,
		0x123AE5D1F6CE7B98ULL,
		0xD6E12DD7811CB37BULL,
		0x7AA14E5CD60AF771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE661C15A3955B13BULL,
		0x166E1AE2A296090CULL,
		0x0CC12E0CD34F0228ULL,
		0x649A6C2AE4CA86DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0743D3B98B01B577ULL,
		0xFBCCCAEF5438728CULL,
		0xCA1FFFCAADCDB152ULL,
		0x1606E231F1407095ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xD6FD1909D5E36491ULL,
		0x4A89D72390519086ULL,
		0xA09EC82665FFA6E5ULL,
		0x0E297D587914B4EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB36A0ED7C2086EA7ULL,
		0x37BA268DBEF7353AULL,
		0xCFC11DBE2B6BBBF9ULL,
		0x6E749B6E11FF9D7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23930A3213DAF5D7ULL,
		0x12CFB095D15A5B4CULL,
		0xD0DDAA683A93EAECULL,
		0x1FB4E1EA6715176EULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x4A7726D9C168F885ULL,
		0x7292B4B618DE8422ULL,
		0x0E7138AE5FD243F5ULL,
		0x075FAF831B0B2591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94AF9895D21A6FE6ULL,
		0x71FB6E0A1DD0BF23ULL,
		0x898F88C2FF2FE9C3ULL,
		0x36164C21800B5A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5C78E43EF4E888CULL,
		0x009746ABFB0DC4FEULL,
		0x84E1AFEB60A25A32ULL,
		0x514963619AFFCB01ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x14C11945BE3449D0ULL,
		0xBAA8919A2365A757ULL,
		0x8284EB2D9B1869C0ULL,
		0x6EE6F84625E54674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B179FF74DF9B0B8ULL,
		0xFA32D83D1FD837A3ULL,
		0x3C3E16DBFA69C0E6ULL,
		0x67FB6EB8E010A044ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9A9794E703A9918ULL,
		0xC075B95D038D6FB3ULL,
		0x4646D451A0AEA8D9ULL,
		0x06EB898D45D4A630ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x1F3EC18E74C891F6ULL,
		0x336DD68950183C79ULL,
		0xEEF3B09B4EFFD65AULL,
		0x60F07500B575381FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8AE9F79DD8CC4DCULL,
		0x94A59682B9D6B165ULL,
		0xEB64C4ED291E86F4ULL,
		0x5DC7CEDA49D6A998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46902214973BCD1AULL,
		0x9EC8400696418B13ULL,
		0x038EEBAE25E14F65ULL,
		0x0328A6266B9E8E87ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xD895FCB38A8322B6ULL,
		0xF05A7AC909A8DB4EULL,
		0x440C596322780F5BULL,
		0x6C77C5594CD63F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E91F562A8DDC3BULL,
		0xE2FEFD3143E2C481ULL,
		0xA50F07AE8A2CC5A9ULL,
		0x37AE686636C37D45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87ACDD5D5FF5467BULL,
		0x0D5B7D97C5C616CDULL,
		0x9EFD51B4984B49B2ULL,
		0x34C95CF31612C213ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xEDF2C98E65C9FD3CULL,
		0x0CF69AA44B45C420ULL,
		0x5A2A0C9B0BE3FEDDULL,
		0x53C20C4C1B260CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99D2A6B23AABD30ULL,
		0x01952414D3CA7A01ULL,
		0x6C53378B3A974D8CULL,
		0x0CB0B752A1E0C44DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04559F23421F400CULL,
		0x0B61768F777B4A1FULL,
		0xEDD6D50FD14CB151ULL,
		0x471154F97945487FULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x222D03584D202AD9ULL,
		0x3894D29683AFF5DEULL,
		0x8692795A3C17946CULL,
		0x61FFF2019A9CE856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E62639B474D833ULL,
		0x2649FE5BC8EF58A5ULL,
		0xA62EF70291764C86ULL,
		0x7F844DD3C40FEC0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE46DD1E98AB5293ULL,
		0x124AD43ABAC09D38ULL,
		0xE0638257AAA147E6ULL,
		0x627BA42DD68CFC47ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xC8B29C5C6A3F70DFULL,
		0xD18E3C53A63584C3ULL,
		0x6ABF15DD174354A9ULL,
		0x063FCEA8727A9A57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9F2EA36BBE91CE8ULL,
		0x86EFFB235F8D85A0ULL,
		0x2F9D3C6C95B358F0ULL,
		0x553D7E6858F5D223ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EBFB225AE5653E4ULL,
		0x4A9E413046A7FF23ULL,
		0x3B21D970818FFBB9ULL,
		0x310250401984C834ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x21A94C4F94565429ULL,
		0xACF56845B4564E65ULL,
		0x96C0955F102F07EFULL,
		0x7E75105930665BFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C72B3483ECDBBBULL,
		0xB6371325315260A6ULL,
		0x6A9D3FC59870C776ULL,
		0x0E5008139B69317AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EE2211B1069786EULL,
		0xF6BE55208303EDBEULL,
		0x2C23559977BE4078ULL,
		0x7025084594FD2A80ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xF24AA86FEF599DEBULL,
		0xB6E305716AD3A4A4ULL,
		0x12946BA73576E1CBULL,
		0x1D2D0475B0CEF4E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0835337792F6477ULL,
		0x58EE5CCE681ACDF5ULL,
		0xA8788E43C10DE676ULL,
		0x5FB1E806EFD55A9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31C75538762A3961ULL,
		0x5DF4A8A302B8D6AFULL,
		0x6A1BDD637468FB55ULL,
		0x3D7B1C6EC0F99A4AULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xEF9B9847A300AFFAULL,
		0x4AFFC3E465A3EA9BULL,
		0x26197AA46E1A0843ULL,
		0x78A125134BFD73F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631DFE91DAC03A04ULL,
		0xD2757C8FEB838CEFULL,
		0xF015B17B82C0F807ULL,
		0x0D1EA99262594A84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C7D99B5C84075F6ULL,
		0x788A47547A205DACULL,
		0x3603C928EB59103BULL,
		0x6B827B80E9A42973ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x623E93BF0C7491D1ULL,
		0x6DE3CF53E952B12DULL,
		0x77B823844DA8547CULL,
		0x1525C7246879C654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD6D866719A4BC25ULL,
		0x2A0FE984F02B1C55ULL,
		0x258E710F1A6EDF47ULL,
		0x6C0946307BFCA396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84D10D57F2CFD599ULL,
		0x43D3E5CEF92794D7ULL,
		0x5229B27533397535ULL,
		0x291C80F3EC7D22BEULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x65D33DED81712572ULL,
		0x61021EBB20CC88D9ULL,
		0x0B4E87861EEA1A7AULL,
		0x7DF5ABD6EEFC60E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF62DC17EA9AE94FDULL,
		0x5931702FA5607ECCULL,
		0xBC7ED20F8153A30CULL,
		0x2EECF1A68BE807D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FA57C6ED7C29075ULL,
		0x07D0AE8B7B6C0A0CULL,
		0x4ECFB5769D96776EULL,
		0x4F08BA3063145914ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xFACE9F8FE5F08CF4ULL,
		0x1028FF43240DF6E6ULL,
		0x5BEB2936937B3673ULL,
		0x445A67FACAD5B3E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F94DA644CCD2C92ULL,
		0x5AD4CB38F90001D8ULL,
		0xA2FA448C24380955ULL,
		0x163563ACBDBBF28AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB39C52B99236062ULL,
		0xB554340A2B0DF50EULL,
		0xB8F0E4AA6F432D1DULL,
		0x2E25044E0D19C156ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x1464D9316271F31CULL,
		0xF772FFF78276BFFBULL,
		0xB8F34EAEB6DB1FFEULL,
		0x0BD6E6C9BA3F206EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B96F7D125FF899ULL,
		0xFE05101119CBBF08ULL,
		0x14A98A4413CFA628ULL,
		0x7B8CC8257162031DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EAB69B45011FA70ULL,
		0xF96DEFE668AB00F2ULL,
		0xA449C46AA30B79D5ULL,
		0x104A1EA448DD1D51ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x73D2E4D1894831CEULL,
		0x87024C23601E2F0CULL,
		0x4533E3E931BD397DULL,
		0x1D8DA44EBAC5A77EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42204001D7255540ULL,
		0xDEABF4F45A51D3A5ULL,
		0x280C33F5AE7C2FE4ULL,
		0x334BBBFAEB1BF5CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31B2A4CFB222DC7BULL,
		0xA856572F05CC5B67ULL,
		0x1D27AFF383410998ULL,
		0x6A41E853CFA9B1B4ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xB747C4DB7C78256AULL,
		0x774313D95AEAA5FFULL,
		0xFFFD928F38EAC71CULL,
		0x51141B2D3878B9B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB8E78D2AE5C057ULL,
		0xDFFEF93F40DC3066ULL,
		0x74C0A504CA3CBEC0ULL,
		0x4DFA278C763DF10AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB88EDD4E51926513ULL,
		0x97441A9A1A0E7598ULL,
		0x8B3CED8A6EAE085BULL,
		0x0319F3A0C23AC8A8ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xF9952C2D4560683BULL,
		0xE9E1BCB5817D581EULL,
		0x722904F9F335BE79ULL,
		0x2939B2ABEE6CBA83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8C99F250EFF2085ULL,
		0x1154556A30E4F16CULL,
		0xBF5371D924B1D107ULL,
		0x4A35B2150FAA9D3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30CB8D08366147A3ULL,
		0xD88D674B509866B2ULL,
		0xB2D59320CE83ED72ULL,
		0x5F040096DEC21D43ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x10B25DF7570BC8F7ULL,
		0x25A6FCE69B437E6DULL,
		0x0DF40A0E372AF7FCULL,
		0x5874BAE58E0CDE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8646DC90584AAF0ULL,
		0xFAB3ED8D3800BA10ULL,
		0xFA9C7339C0C02C86ULL,
		0x6BF9E487972BC351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x184DF02E51871DF4ULL,
		0x2AF30F596342C45CULL,
		0x135796D4766ACB75ULL,
		0x6C7AD65DF6E11ACBULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x16A7269FAF05C139ULL,
		0x77A21307ACFAA390ULL,
		0xF30B9942B6649439ULL,
		0x41D8ED2C82C424BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4412521C9922F080ULL,
		0xB7B80EDF68DBA69EULL,
		0x28F31B5B2F97B649ULL,
		0x70C9C334F310126BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD294D48315E2D0A6ULL,
		0xBFEA0428441EFCF1ULL,
		0xCA187DE786CCDDEFULL,
		0x510F29F78FB41254ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xC0625256BFE6604CULL,
		0xFE1981A039001B03ULL,
		0x834254DC1AB508E9ULL,
		0x39982886A3AF35E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E6BCA35E525844BULL,
		0x1B313839EBB92F35ULL,
		0xA5D1B0ED6986C555ULL,
		0x3B080314E84F13D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81F68820DAC0DBEEULL,
		0xE2E849664D46EBCEULL,
		0xDD70A3EEB12E4394ULL,
		0x7E902571BB60220CULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xC0F73D4A292B7664ULL,
		0xA342DFB4FA8585FAULL,
		0x0EE20A98642A8E1EULL,
		0x134CBA1BE5362104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43ED95713C2DEB0AULL,
		0x0343D33FA3160C6AULL,
		0x336B8AA8CF35324CULL,
		0x0A50D3441C85F3F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D09A7D8ECFD8B5AULL,
		0x9FFF0C75576F7990ULL,
		0xDB767FEF94F55BD2ULL,
		0x08FBE6D7C8B02D0DULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xFA69F4832E376F0DULL,
		0x31102CA3C5149EF2ULL,
		0xA3AEEF688E91F288ULL,
		0x042E1F23DDB58709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x715E2F9C585FB0B0ULL,
		0x2F7DCC2BF6EA5B3EULL,
		0xC2A59A8EB94F6235ULL,
		0x023DFB1B8B208C46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x890BC4E6D5D7BE5DULL,
		0x01926077CE2A43B4ULL,
		0xE10954D9D5429053ULL,
		0x01F024085294FAC2ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xD9D2D329F228C425ULL,
		0x22422A05F49A784BULL,
		0x823F2335AFF6F2A3ULL,
		0x4D908D84F5C1083BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FE543ED00D63512ULL,
		0xDEEB116CB25B9445ULL,
		0xE77E238C82765318ULL,
		0x359242ECC268B931ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9ED8F3CF1528F13ULL,
		0x43571899423EE406ULL,
		0x9AC0FFA92D809F8AULL,
		0x17FE4A9833584F09ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x43E0AC32C4E6EE49ULL,
		0x9C78FC548DCFC91BULL,
		0xBC28355F3F5239D2ULL,
		0x141FE37BE06960A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C262CC51909E0B2ULL,
		0x14325765B8DFC23CULL,
		0xD9056FCC2BF5912AULL,
		0x666C6B110ECDD996ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27BA7F6DABDD0D84ULL,
		0x8846A4EED4F006DFULL,
		0xE322C593135CA8A8ULL,
		0x2DB3786AD19B8710ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x41396571C84787E2ULL,
		0x43E8D8B08DA611D7ULL,
		0x6DB9FCAA7A7CFC2EULL,
		0x05E3A3A752E341ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBD99D70B976EE1ULL,
		0xA4A8579F2CF8194FULL,
		0x887BC431595799B5ULL,
		0x5292534A6771B5B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x417BCB9ABCB018EEULL,
		0x9F40811160ADF887ULL,
		0xE53E387921256278ULL,
		0x3351505CEB718BF9ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x7616494519912535ULL,
		0x3BC215B682BFE304ULL,
		0x05F861DCBD3F85C5ULL,
		0x5FA14570B5C1BE6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9768042B444EB114ULL,
		0xA532162694BE1DCEULL,
		0x9A341CACEC347E10ULL,
		0x497827DFC2889824ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEAE4519D5427421ULL,
		0x968FFF8FEE01C535ULL,
		0x6BC4452FD10B07B4ULL,
		0x16291D90F3392648ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x538AE3B281ECC626ULL,
		0xCDA672C4FE0850C2ULL,
		0x258170B8D2C860ADULL,
		0x62D95B6C9D330840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD399435B1303253ULL,
		0xA72DD4C237EC48CCULL,
		0xEC479688633AEC88ULL,
		0x21B731F6CFD84673ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86514F7CD0BC93D3ULL,
		0x26789E02C61C07F5ULL,
		0x3939DA306F8D7425ULL,
		0x41222975CD5AC1CCULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x89E3F72C103114B4ULL,
		0xA7C54E0524BAB43DULL,
		0x92F8161B4C50EA74ULL,
		0x4D0C4514D16EE13CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E20C040C26DCE63ULL,
		0x883CF19B933C3370ULL,
		0x5EEEBE28A57888AAULL,
		0x2DA2948ACDDC83FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BC336EB4DC34651ULL,
		0x1F885C69917E80CDULL,
		0x340957F2A6D861CAULL,
		0x1F69B08A03925D3DULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xEBF3E3693EB99BC1ULL,
		0x530B091C87C3AE65ULL,
		0x2B845190E9838CDFULL,
		0x6FB00519E4E7DFEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32AB12212223D494ULL,
		0xFFBD52E7DFACBB25ULL,
		0xEE5459E84426470BULL,
		0x0A7D006224A3A9FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB948D1481C95C72DULL,
		0x534DB634A816F340ULL,
		0x3D2FF7A8A55D45D3ULL,
		0x653304B7C04435EEULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xD1A3B73079FE8557ULL,
		0xF13CDF19014C1F32ULL,
		0x6A3A12794AE01948ULL,
		0x49411D1917074835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6F286DAEDB5BF39ULL,
		0xDDB41747A47EF2F1ULL,
		0x3A9DEA7628C417CDULL,
		0x79A700676ECFD646ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAB130558C48C60BULL,
		0x1388C7D15CCD2C40ULL,
		0x2F9C2803221C017BULL,
		0x4F9A1CB1A83771EFULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x787DDB6E43AEC86EULL,
		0x57849A5555B4E210ULL,
		0x5BD58700CE4DE2F4ULL,
		0x1846364BA3D3C502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF87B1D52BB70A856ULL,
		0x5897739D7792ED6CULL,
		0x28A9F9F81844C049ULL,
		0x0C0A42490E8C78B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8002BE1B883E2018ULL,
		0xFEED26B7DE21F4A3ULL,
		0x332B8D08B60922AAULL,
		0x0C3BF40295474C4CULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xB979DE5F8324C919ULL,
		0x6D16278D537B1D10ULL,
		0xE28A4258B3DBEAA9ULL,
		0x6BFC8EC657429F17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3C4C7EE53D3AB6ULL,
		0xCC40312424F9E565ULL,
		0x2B9028C1BBEDEC98ULL,
		0x57300C3916390348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF3D91E09DE78E63ULL,
		0xA0D5F6692E8137AAULL,
		0xB6FA1996F7EDFE10ULL,
		0x14CC828D41099BCFULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xA2589FAA762126D0ULL,
		0x6C5FD1739C9E3CB8ULL,
		0x634FED5D33199EB7ULL,
		0x5C91010D010067AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD96EECF0CD1438EULL,
		0x5B9EAF56FF2049A5ULL,
		0xBCF82698DAB24ADFULL,
		0x0AB2B794CB6577AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C1B0DB694FE342ULL,
		0x10C1221C9D7DF312ULL,
		0xA657C6C4586753D8ULL,
		0x51DE4978359AEFFFULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x11C5287823173FE0ULL,
		0x1ADCFADDD05C5B0DULL,
		0x4CEBC23718EA3C3DULL,
		0x1346FC8C412894B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F4E153D2E3F818ULL,
		0x2D7728A063F859BDULL,
		0xC0F7CBD3D5DC7C80ULL,
		0x1BCC68F641D97F1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D04724503347B5ULL,
		0xED65D23D6C640150ULL,
		0x8BF3F663430DBFBCULL,
		0x777A9395FF4F159AULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xAEA6F68564322890ULL,
		0x1460BCC70A734FA1ULL,
		0x4ACE81089528F111ULL,
		0x089406E9FCB75387ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x374754E6270A6628ULL,
		0x518E7BEAF4209578ULL,
		0x9A7EADC504A1EDF2ULL,
		0x6356100E34B7E6BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x775FA19F3D27C255ULL,
		0xC2D240DC1652BA29ULL,
		0xB04FD3439087031EULL,
		0x253DF6DBC7FF6CCCULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x9A909392A9C9218FULL,
		0x7BE679EF2AD79A2DULL,
		0x433CFCDD95B3E201ULL,
		0x6C3EE81251E522F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1280FA34FE3400F0ULL,
		0xCBFDD4C57A82D0D4ULL,
		0x01E1366A94594DF9ULL,
		0x70D50A0E52D234B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x880F995DAB95208CULL,
		0xAFE8A529B054C959ULL,
		0x415BC673015A9407ULL,
		0x7B69DE03FF12EE45ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xA5C484284F804720ULL,
		0x9A77462C71936F1CULL,
		0xE5E3A71C45A3526EULL,
		0x0E1B6262C3052893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4896B7932A500104ULL,
		0x322C8E460538E541ULL,
		0x943A5A4C4476D432ULL,
		0x2F336F136E497E4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D2DCC9525304609ULL,
		0x684AB7E66C5A89DBULL,
		0x51A94CD0012C7E3CULL,
		0x5EE7F34F54BBAA49ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x79C79C0FAE5D2F30ULL,
		0x604DC38237FD9251ULL,
		0xE81EADD6CE5CEFE3ULL,
		0x5693A59555928E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF8A33CBA2C52B5FULL,
		0x0EDDB7B3DC2957C3ULL,
		0xD2F62B882241F8C2ULL,
		0x194A81CF9FE60E16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA3D68440B9803D1ULL,
		0x51700BCE5BD43A8DULL,
		0x1528824EAC1AF721ULL,
		0x3D4923C5B5AC8007ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x8AB10640829317BBULL,
		0x2BF9D1092530D946ULL,
		0xAE3664673449FD24ULL,
		0x76B800DD0B925147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7BEA48AF95FC67ULL,
		0x20DAD4637BE4D157ULL,
		0x6A2271704816329AULL,
		0x39D9ED82A849CD57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB351BF7D2FD1B54ULL,
		0x0B1EFCA5A94C07EEULL,
		0x4413F2F6EC33CA8AULL,
		0x3CDE135A634883F0ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x3AABC68F0456B951ULL,
		0xF0F0152DDEA2F586ULL,
		0x1171F7D78E60A641ULL,
		0x513F1E3C60CAD15EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4C11A8FB678FE76ULL,
		0xEB6971D9D95E15BCULL,
		0x6297490BF1B215C4ULL,
		0x1BBCB0D5A3078B30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65EAABFF4DDDBADBULL,
		0x0586A3540544DFC9ULL,
		0xAEDAAECB9CAE907DULL,
		0x35826D66BDC3462DULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xC4F6FAB575DC4165ULL,
		0xC1A4654B8795D2B5ULL,
		0x3766711677C3EE66ULL,
		0x2BEF0E80B49795FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4CA33545A7B3029ULL,
		0x0C33FF2D57540917ULL,
		0xF659F1C8E991E4F5ULL,
		0x28D27C59469EC3C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002CC7611B61113CULL,
		0xB570661E3041C99EULL,
		0x410C7F4D8E320971ULL,
		0x031C92276DF8D239ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x218B5418C6EF1A1EULL,
		0xF4484351B277ECAFULL,
		0x7BD7AC8EF7FE91B1ULL,
		0x724901EEFBA22282ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD23E1A7A4DECEF2ULL,
		0x7ABB7FB53F1EC885ULL,
		0x925C379EC5AD9CB9ULL,
		0x62FC3CC05B057140ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2467727122104B2CULL,
		0x798CC39C73592429ULL,
		0xE97B74F03250F4F8ULL,
		0x0F4CC52EA09CB141ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x80AC6078B0E34560ULL,
		0x7B330D48F2ED60BFULL,
		0x36238D2B2B703A30ULL,
		0x4056BCAFAF83C81CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EBAB305FBFBB94CULL,
		0x5E45F09C680607B3ULL,
		0xE8EFC6860B104730ULL,
		0x0B2C42278ED33D3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71F1AD72B4E78C14ULL,
		0x1CED1CAC8AE7590CULL,
		0x4D33C6A5205FF300ULL,
		0x352A7A8820B08AE1ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xA48AAB840A69251EULL,
		0x8B3BBBFDED803111ULL,
		0x72CBD298FF2095D8ULL,
		0x2FF80735A4F53E7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1145E08DAFDB761ULL,
		0x7CE187F1720068F8ULL,
		0x073654304A343A64ULL,
		0x342F4DB0908153B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03764D7B2F6B6DAAULL,
		0x0E5A340C7B7FC819ULL,
		0x6B957E68B4EC5B74ULL,
		0x7BC8B9851473EAC7ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xE022A76E2D7AEBEFULL,
		0xB41F40765924BF97ULL,
		0xEC736210B5D3F9FAULL,
		0x0699369F288C7D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60DCB047FD9685F0ULL,
		0x243DAF3DC0E57E8EULL,
		0xE03E4741D469AC1BULL,
		0x7B995D5FF0017C21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F45F7262FE465ECULL,
		0x8FE19138983F4109ULL,
		0x0C351ACEE16A4DDFULL,
		0x0AFFD93F388B0107ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x426A39E1B7C94064ULL,
		0xA70114F39CDC9B2DULL,
		0x5B599975DC77C96CULL,
		0x4EFCBD2016EAA721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F63A5B70D1CDE51ULL,
		0x0343D8E70192A858ULL,
		0xF069E287D59A9C92ULL,
		0x1A0E9CA11A95D8C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3306942AAAAC6213ULL,
		0xA3BD3C0C9B49F2D5ULL,
		0x6AEFB6EE06DD2CDAULL,
		0x34EE207EFC54CE5EULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x1719BBF195DA5948ULL,
		0xB91838C893C915F2ULL,
		0x47CAAC1552E6377BULL,
		0x6A1E54D64DC9EABDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D895E8C28F01AFULL,
		0xDD0E8A701A3087F1ULL,
		0xD0ACA196AD9020FFULL,
		0x72239EA571D5F1C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60412608D34B5786ULL,
		0xDC09AE5879988E00ULL,
		0x771E0A7EA556167BULL,
		0x77FAB630DBF3F8F5ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x67A2879736CF8662ULL,
		0x1DF4B6F791693546ULL,
		0x92AC329B9E42A9D1ULL,
		0x7FBEB13FB6071DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF9B4B4A8F0FA46ULL,
		0x19D7D9DBA58EC904ULL,
		0xCCDC4E0A51FD967FULL,
		0x65307FA66EEDAF33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49A8D2E28DDE8C1CULL,
		0x041CDD1BEBDA6C42ULL,
		0xC5CFE4914C451352ULL,
		0x1A8E319947196EC0ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xD1DCFE26CBB25092ULL,
		0xEF9652DBD457E77DULL,
		0x40CC8C4D07FA2DC3ULL,
		0x7FCD69010266481BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C185C22AA3D5FB2ULL,
		0x313D023EE3F89CBBULL,
		0xBDC7FFC198B5316CULL,
		0x394C5651B519C7ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55C4A2042174F0E0ULL,
		0xBE59509CF05F4AC2ULL,
		0x83048C8B6F44FC57ULL,
		0x468112AF4D4C806EULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x423F17AD37585A70ULL,
		0xFF485224144FCF1DULL,
		0xD2915A991D9960ACULL,
		0x5A17901519CA7C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6BA73846F30B709ULL,
		0xB613DE737C47A906ULL,
		0xCED10E7DED4335BBULL,
		0x1D3771FCBA38EFE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B84A428C827A367ULL,
		0x493473B098082616ULL,
		0x03C04C1B30562AF1ULL,
		0x3CE01E185F918C77ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0AEC5A4A823B55ECULL,
		0x57D0EA9DD9B81FE8ULL,
		0xA9B32039D9D6ACC6ULL,
		0x3769E495965242F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5987FFEE075901DULL,
		0x6FCA51720E543CC9ULL,
		0xC3135B97381F9139ULL,
		0x199ED98CDCE228F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6553DA4BA1C5C5CFULL,
		0xE806992BCB63E31EULL,
		0xE69FC4A2A1B71B8CULL,
		0x1DCB0B08B9701A06ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xA4C33F13ED6F8CCEULL,
		0xDADE674FD70D7CF8ULL,
		0xD725EA84CE168A54ULL,
		0x42181B6295C9FC95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912CC4FE9559434EULL,
		0x0312E29D88EABD8DULL,
		0x297FFD6451292EFAULL,
		0x14E4B5E2E050C209ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13967A1558164980ULL,
		0xD7CB84B24E22BF6BULL,
		0xADA5ED207CED5B5AULL,
		0x2D33657FB5793A8CULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xA23E17535DF66E5CULL,
		0x36E166CAA513C70CULL,
		0x5E128DF7482CA22EULL,
		0x4D57EC62D83047ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF791EE7A7DACD35BULL,
		0x5C21D06E7384F25AULL,
		0x4259749353D3861CULL,
		0x190D822162C25B4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAAC28D8E0499B01ULL,
		0xDABF965C318ED4B1ULL,
		0x1BB91963F4591C11ULL,
		0x344A6A41756DEC5DULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0A014BC960F7F3DEULL,
		0xB3CC4ABE673D4143ULL,
		0xEA836DA950A32C1FULL,
		0x2DCA3EAFA4907DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DCE4CC7F759E659ULL,
		0xFF12D2C4C79F8FBBULL,
		0x24FF591B34B843EAULL,
		0x250BD8C7F3F33122ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC32FF01699E0D85ULL,
		0xB4B977F99F9DB187ULL,
		0xC584148E1BEAE834ULL,
		0x08BE65E7B09D4C88ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x3AC385A354C6F0ADULL,
		0x4C5A6217CA10D6B3ULL,
		0xF0B8FDA8892E637BULL,
		0x0365DAF1B4BBE2F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1EDACC8DF580FDBULL,
		0xF4166C6A60059E53ULL,
		0x1CCE39BA658D4A1FULL,
		0x683784242E32D154ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78D5D8DA756EE0BFULL,
		0x5843F5AD6A0B385FULL,
		0xD3EAC3EE23A1195BULL,
		0x1B2E56CD8689119DULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xFCB5B467C49B645CULL,
		0x14F7179E6BB44BEFULL,
		0x8BF2330B95C9C9F1ULL,
		0x74D2B92E85485F6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D68DD93985BF26FULL,
		0xE6EC1AAB18AE7E08ULL,
		0xDDDB7F571A968345ULL,
		0x2344D7597F225FD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F4CD6D42C3F71EDULL,
		0x2E0AFCF35305CDE7ULL,
		0xAE16B3B47B3346ABULL,
		0x518DE1D50625FF93ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xC013F69BC86C8C89ULL,
		0x8C16EF8F9AF639C5ULL,
		0x1AAC41E0409FFD44ULL,
		0x2923DE652080B491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BAFB31F3335D199ULL,
		0x227B79CBF738C5EDULL,
		0xAE47C1AE9293D740ULL,
		0x645E45199100D578ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8464437C9536BADDULL,
		0x699B75C3A3BD73D8ULL,
		0x6C648031AE0C2604ULL,
		0x44C5994B8F7FDF18ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x66E2BFA84A79324BULL,
		0x47DED7EA1481AE32ULL,
		0x8234FC32DD08D26DULL,
		0x1D8F1A6801A1A376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20953C79A75E8271ULL,
		0xF4A50B0E60A7BC73ULL,
		0x6F7CA479CDB4B453ULL,
		0x65785B2D2DFE2DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x464D832EA31AAFC7ULL,
		0x5339CCDBB3D9F1BFULL,
		0x12B857B90F541E19ULL,
		0x3816BF3AD3A375C1ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xDCCEEF8E9C418716ULL,
		0x12BCA775FED75CD4ULL,
		0xD3AF877B50856508ULL,
		0x17B4BA2B8674B2D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2634A0AB38002965ULL,
		0x81756D1B66B179E6ULL,
		0x57289F58163A2572ULL,
		0x1E3A2442C4C6E468ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB69A4EE364415D9EULL,
		0x91473A5A9825E2EEULL,
		0x7C86E8233A4B3F95ULL,
		0x797A95E8C1ADCE6DULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x2835E341860D70FFULL,
		0x67797AF7F0168847ULL,
		0x65D5990B3299694DULL,
		0x1EF3A37A19229156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1988BF6E18FF2BD9ULL,
		0x9BA63B7FC813D9E5ULL,
		0x4E8D543472ADB034ULL,
		0x09DBB1B0B26FF844ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EAD23D36D0E4526ULL,
		0xCBD33F782802AE62ULL,
		0x174844D6BFEBB918ULL,
		0x1517F1C966B29912ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xBECF3E86B3ECE663ULL,
		0xE3ABE54294EFB6AAULL,
		0x783AEE3CE116A573ULL,
		0x099F2E7F4E1AC755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x281DE18A251228CFULL,
		0x16F38B0382A5F002ULL,
		0x87FBD6449DF963F3ULL,
		0x5E8A4475B217097CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96B15CFC8EDABD81ULL,
		0xCCB85A3F1249C6A8ULL,
		0xF03F17F8431D4180ULL,
		0x2B14EA099C03BDD8ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0C86602C1BE094ABULL,
		0xCCCB81CC573856A0ULL,
		0x5CD9EC4FEEDE9DDCULL,
		0x67F8E4ECEE26ED73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACE4D3E52CD46D46ULL,
		0xA8ED57FF50361C36ULL,
		0x24F0E54ECA076DEBULL,
		0x6AF243B263BC8085ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FA18C46EF0C2752ULL,
		0x23DE29CD07023A69ULL,
		0x37E9070124D72FF1ULL,
		0x7D06A13A8A6A6CEEULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xEDB062D015E9C3EBULL,
		0x3045A1A587765A12ULL,
		0x70546F6340D7E20EULL,
		0x73E52AF57B2C89CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB7471D33F64F741ULL,
		0xD780D8DB52CBA67DULL,
		0x5822A3564D3E68A4ULL,
		0x65CD5D42DA63212CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023BF0FCD684CCAAULL,
		0x58C4C8CA34AAB395ULL,
		0x1831CC0CF3997969ULL,
		0x0E17CDB2A0C9689FULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x13A00F945E81C519ULL,
		0x2BEDF52152CA1815ULL,
		0x59B313A8AC757B94ULL,
		0x7A563B1400E37C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17AA4ABBA36399F9ULL,
		0x9796E3997BEB5F39ULL,
		0x2713856D1B669A24ULL,
		0x3D00310A0E2C7F42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBF5C4D8BB1E2B20ULL,
		0x94571187D6DEB8DBULL,
		0x329F8E3B910EE16FULL,
		0x3D560A09F2B6FCE6ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x9BBF4E90C0EDC2EEULL,
		0x4376904FBB150457ULL,
		0x726D99D35478553EULL,
		0x2400C27007B3A680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4308B18FABCAD0BULL,
		0x1AFD3C2F7FAD44D8ULL,
		0x344B478D24986AEEULL,
		0x024621D219C1C339ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA78EC377C63115E3ULL,
		0x287954203B67BF7EULL,
		0x3E2252462FDFEA50ULL,
		0x21BAA09DEDF1E347ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x6A63B7BB186A42F4ULL,
		0x474EA98999FCB002ULL,
		0xCF887916D62DEB44ULL,
		0x12D1B7AA1ED69320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297A9CE2E8529F80ULL,
		0xF43D30B42CAC9E0BULL,
		0xA9A81B168C815119ULL,
		0x3092678154B0FA31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40E91AD83017A361ULL,
		0x531178D56D5011F7ULL,
		0x25E05E0049AC9A2AULL,
		0x623F5028CA2598EFULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x99F3E6287BAC8333ULL,
		0x1AEC5B2AB22B52ABULL,
		0x664DE4A85FF4ED7AULL,
		0x78404190F1BD9CBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C33FCF0B008757ULL,
		0x890DC39A10D32280ULL,
		0x197A90A1B028EF9DULL,
		0x7D69AB0C7F2AFFDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7830A65970ABFBC9ULL,
		0x91DE9790A158302BULL,
		0x4CD35406AFCBFDDCULL,
		0x7AD6968472929CE2ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x46ACD0DE823FED13ULL,
		0x8BFB1F82CA7F6D92ULL,
		0x7C0C746DA1C530C0ULL,
		0x2F922D94A5A48857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5015376C9DA32AC0ULL,
		0x8292D0AAD79923F6ULL,
		0xC7034A371AE14D72ULL,
		0x7FE574A90A9EA6D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6979971E49CC240ULL,
		0x09684ED7F2E6499BULL,
		0xB5092A3686E3E34EULL,
		0x2FACB8EB9B05E186ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xF7D89291A78AEC7DULL,
		0x261F409DACE8DE94ULL,
		0xAD3414802AA64D48ULL,
		0x30D9BA2C6A774931ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D017157E2ADA3FULL,
		0x1E92990DA3F7CA40ULL,
		0x69F52795DDBF4DF4ULL,
		0x7A5EF5A0B59127C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90087B7C2960122BULL,
		0x078CA79008F11454ULL,
		0x433EECEA4CE6FF54ULL,
		0x367AC48BB4E6216CULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x8C522A7B8FD48397ULL,
		0xCCDCF73E37E2990BULL,
		0xB105237100CDCB8AULL,
		0x31AB532F368FC6E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F96F0D03ED90BC1ULL,
		0xE4D24F28CAA29D27ULL,
		0x25E72990B1EFB692ULL,
		0x40C045BEADB69D51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CBB39AB50FB77C3ULL,
		0xE80AA8156D3FFBE4ULL,
		0x8B1DF9E04EDE14F7ULL,
		0x70EB0D7088D92993ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x06F3618CC94FA232ULL,
		0x98644E9B0675F071ULL,
		0x7C9C54FCF1B0FB0EULL,
		0x0C2533D6A5D493A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x080DA916A28E4AE3ULL,
		0xA7AB2D50A591041AULL,
		0x98C2B9B9DAE16657ULL,
		0x4294339B8C5BD6B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEE5B87626C1573CULL,
		0xF0B9214A60E4EC56ULL,
		0xE3D99B4316CF94B6ULL,
		0x4991003B1978BCF2ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x163769F3BCD106DCULL,
		0x655E19C09EC2A78CULL,
		0xC9F706516B8427B6ULL,
		0x562961421A19A686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11A77048C0A0318BULL,
		0x1DC9AE2D7259E44CULL,
		0xA8505135650D9505ULL,
		0x36B751175658252DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x048FF9AAFC30D551ULL,
		0x47946B932C68C340ULL,
		0x21A6B51C067692B1ULL,
		0x1F72102AC3C18159ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xAC8E7EE44013CCAFULL,
		0x737055456F6C3F1DULL,
		0x00073DD9DB1A67BDULL,
		0x2D63916F282725F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC8D45B07334C35ULL,
		0xEC99654F5B3590FCULL,
		0xE247B76FCD13CB5CULL,
		0x6309B0B9B40FB34EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EC5AA8938E08067ULL,
		0x86D6EFF61436AE21ULL,
		0x1DBF866A0E069C60ULL,
		0x4A59E0B5741772A5ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x1BEFCD358F575BABULL,
		0xAD62F180744517F2ULL,
		0x85AF0BFCD7010CD8ULL,
		0x45F61BE3C595B463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC833D4F222E9CFAULL,
		0x98E1C933A3192ECDULL,
		0x02088E216D51B375ULL,
		0x0C665738A1EB2541ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F6C8FE66D28BEB1ULL,
		0x1481284CD12BE924ULL,
		0x83A67DDB69AF5963ULL,
		0x398FC4AB23AA8F22ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xE7900177A9A07AE4ULL,
		0xB803AB27E16228DCULL,
		0xB22C055C7DB0A999ULL,
		0x449D12F01586114EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94735EBCF8759465ULL,
		0xFF4DB3EFD88230ECULL,
		0x89DA36964E36B2C0ULL,
		0x0E8E8807F4CD0451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x531CA2BAB12AE67FULL,
		0xB8B5F73808DFF7F0ULL,
		0x2851CEC62F79F6D8ULL,
		0x360E8AE820B90CFDULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x7D42DF159CB82731ULL,
		0x09E07028F49207A2ULL,
		0x44631F96A7DC9CC8ULL,
		0x5E7A58CE91F88A3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094452253BD81FB0ULL,
		0xA80E472764EFB40FULL,
		0x563EDB586DBC59DBULL,
		0x26DF2807B481E74BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73FE8CF060E00781ULL,
		0x61D229018FA25393ULL,
		0xEE24443E3A2042ECULL,
		0x379B30C6DD76A2EFULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x258EE217FA61DB2FULL,
		0xBEF09A1728C2FAB6ULL,
		0x43095AF1E6337F98ULL,
		0x4307CB0DEF2FB76EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x520823A6A89EA45FULL,
		0x14A7C45153352C8AULL,
		0xFAD3C14C4E07EF1CULL,
		0x1B3D762288370CF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD386BE7151C336D0ULL,
		0xAA48D5C5D58DCE2BULL,
		0x483599A5982B907CULL,
		0x27CA54EB66F8AA7CULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x9B8B59D334D4C654ULL,
		0x764FEFE7496EE651ULL,
		0x33F3614AAF517FDDULL,
		0x2668071B79EF93D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C5AA3F77564413ULL,
		0x9D8583CFDB03BD62ULL,
		0x0DE6C05806150728ULL,
		0x0BE6D3267D7755DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66C5AF93BD7E8241ULL,
		0xD8CA6C176E6B28EFULL,
		0x260CA0F2A93C78B4ULL,
		0x1A8133F4FC783DFDULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xF28428FFEBED7B13ULL,
		0x524E2596C4F9AAF5ULL,
		0xE3CB2FD656C81181ULL,
		0x08CE83E4A53F1024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71632748706A4360ULL,
		0x78D7F1458C61D860ULL,
		0x5BA2C0639F0D85C9ULL,
		0x5C207E49534769DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x812101B77B8337A0ULL,
		0xD97634513897D295ULL,
		0x88286F72B7BA8BB7ULL,
		0x2CAE059B51F7A648ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xAF3F432E19259C5BULL,
		0xDF4EEF6397C466A3ULL,
		0xECEEB0A2222B8A0EULL,
		0x70A871A1CC6D35BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5914E594BB395E2ULL,
		0xE31BA3FE8D6A6614ULL,
		0xAA9C3B3FDE295299ULL,
		0x3FDF515F6DD504B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9ADF4D4CD720679ULL,
		0xFC334B650A5A008EULL,
		0x4252756244023774ULL,
		0x30C920425E983104ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xB6E8FB771F245141ULL,
		0x53B8CE91B163BD55ULL,
		0xF9A783B4F2E41910ULL,
		0x449D1C4B97C7BBDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51CA87836A98C463ULL,
		0xDD80109E864E7F17ULL,
		0x5061C12CDCF56946ULL,
		0x0AC7218A6E2ED5ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x651E73F3B48B8CDEULL,
		0x7638BDF32B153E3EULL,
		0xA945C28815EEAFC9ULL,
		0x39D5FAC12998E631ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xC64F7E86BEFF78E0ULL,
		0xD6B6D9540CD68AE8ULL,
		0xC6A437130B7D0B3BULL,
		0x4C664CC25C9185CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE751FAB3609123F2ULL,
		0x8E91A4D228999E90ULL,
		0x689C77B9B9FDFE08ULL,
		0x35EC94733DBA235FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEFD83D35E6E54EEULL,
		0x48253481E43CEC57ULL,
		0x5E07BF59517F0D33ULL,
		0x1679B84F1ED7626DULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x3540905F7B08D8AFULL,
		0xE9AB7BA3DB86DDE8ULL,
		0x05820F2E4A4F5261ULL,
		0x52431A807B81415FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x446B648A5120F4BDULL,
		0x76850169C0A37A16ULL,
		0x87823DD74EF66AE2ULL,
		0x6F01E80ACE7111A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0D52BD529E7E3DFULL,
		0x73267A3A1AE363D1ULL,
		0x7DFFD156FB58E77FULL,
		0x63413275AD102FB6ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x2A5C21590A90FC49ULL,
		0x06FC6A0912D7257AULL,
		0x617302A39CF0C3D5ULL,
		0x5C1671FF1813E098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428A717ED34D73EEULL,
		0x9B485B436CD9BBEAULL,
		0x5A35E41B70C5546AULL,
		0x177141243A229508ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7D1AFDA3743885BULL,
		0x6BB40EC5A5FD698FULL,
		0x073D1E882C2B6F6AULL,
		0x44A530DADDF14B90ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x78B6F29C8C9BBEFBULL,
		0x1B458081FC1EB8D0ULL,
		0xBE535EBC4A15FDA4ULL,
		0x7FD626D53A552498ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1725334828DCAB1BULL,
		0xBFDC647E70FC3872ULL,
		0x70B0E7A1622E5990ULL,
		0x5CD3744416D191D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6191BF5463BF13E0ULL,
		0x5B691C038B22805EULL,
		0x4DA2771AE7E7A413ULL,
		0x2302B291238392C2ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x8728D9A55E317AF1ULL,
		0xB45A659F75F6E1CDULL,
		0x087D2F0416116EC9ULL,
		0x224ACC438CDF30C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0AB789DC0F44DBEULL,
		0x5A99834114504385ULL,
		0x486AA5D049FC61C0ULL,
		0x12E419571DFE933FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC67D61079D3D2D33ULL,
		0x59C0E25E61A69E47ULL,
		0xC0128933CC150D09ULL,
		0x0F66B2EC6EE09D88ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x537E3CA3D17E3D81ULL,
		0x68176487161D6178ULL,
		0x4D6547ACE4D46BEAULL,
		0x080B1ABED8391CFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x959696226BAB8E57ULL,
		0xC27A69392ED4C29CULL,
		0x20537461EC367EB3ULL,
		0x3D17DBE2EFF6AB28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDE7A68165D2AF17ULL,
		0xA59CFB4DE7489EDBULL,
		0x2D11D34AF89DED36ULL,
		0x4AF33EDBE84271D7ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xE80B80327C1814ECULL,
		0x68AA8C70978A01CFULL,
		0xDB03EDAB66EE81CAULL,
		0x7D0BF8D287E87CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6258FEF20FB241FCULL,
		0x7BF3A439537E8539ULL,
		0xFDDFF48951ECDA4CULL,
		0x391A382B8C1DF08DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85B281406C65D2F0ULL,
		0xECB6E837440B7C96ULL,
		0xDD23F9221501A77DULL,
		0x43F1C0A6FBCA8C4DULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xAC37C2B1C2DF7505ULL,
		0xFA937804FE32D59FULL,
		0x9992F6FD56DFB77AULL,
		0x25B42DF3F40B9A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB650C77008A9007BULL,
		0xC03605C0BD4188BCULL,
		0x7CE621C09539904AULL,
		0x43718BB3FA6205BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5E6FB41BA367477ULL,
		0x3A5D724440F14CE2ULL,
		0x1CACD53CC1A62730ULL,
		0x6242A23FF9A99468ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x676255F9109A2111ULL,
		0x36954C23BBD377EDULL,
		0xD832467C220C78ACULL,
		0x3706BC7C86A013D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D5FC1E6B1CCE4CULL,
		0x78AF581680A2BF71ULL,
		0xDEFB30A65F0B86DFULL,
		0x4E111AF339849139ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x038C59DAA57D52B2ULL,
		0xBDE5F40D3B30B87CULL,
		0xF93715D5C300F1CCULL,
		0x68F5A1894D1B829CULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x6C491924108F6938ULL,
		0x13733CB9F31C698BULL,
		0x997D63EAF13749DFULL,
		0x5B141294A2CFE1EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A958C1BC08A070BULL,
		0x9D34187E2BBD6106ULL,
		0x11ADB12B6E53BBEDULL,
		0x32E171BCA406719DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61B38D085005622DULL,
		0x763F243BC75F0885ULL,
		0x87CFB2BF82E38DF1ULL,
		0x2832A0D7FEC9704DULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x309B10B7D873A30AULL,
		0x65647623211BB192ULL,
		0xB3C15D63FF7C3117ULL,
		0x45E50BA1009CB541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7EC1E8CD7E9015DULL,
		0x5727BD7B7201A832ULL,
		0xAD080996DFE003B4ULL,
		0x00B48BB1146B6B05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38AEF22B008AA1ADULL,
		0x0E3CB8A7AF1A095FULL,
		0x06B953CD1F9C2D63ULL,
		0x45307FEFEC314A3CULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x4FCAD432B0E43BFCULL,
		0x886BD23AD401E6B9ULL,
		0x2B474F948EDA2965ULL,
		0x5D37BF791D99AC84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC828FE0681585EULL,
		0x251D4072F4627F06ULL,
		0x61F8C520DE1278CFULL,
		0x7129511C4ECB5540ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1402AB34AA62E38BULL,
		0x634E91C7DF9F67B3ULL,
		0xC94E8A73B0C7B096ULL,
		0x6C0E6E5CCECE5743ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x50BDE3B08BA28063ULL,
		0xEA26CC03568D0422ULL,
		0x9FD103C08FBD9F04ULL,
		0x13C09FFB57CE3857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7303CDCE485E5B2AULL,
		0xC16843EA8CFDCA8AULL,
		0x92F5389FC25C50AEULL,
		0x05B8B2409ABA4AC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDBA15E243442539ULL,
		0x28BE8818C98F3997ULL,
		0x0CDBCB20CD614E56ULL,
		0x0E07EDBABD13ED95ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0xAB5F5D1B4333414BULL,
		0x8E9A83AF4ED319C4ULL,
		0x3BD1ACE5A76B7F65ULL,
		0x736DCF0ECCAA6A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01528AAA669C0017ULL,
		0x22DC39CB747890B3ULL,
		0x2E02708B003ACAE6ULL,
		0x1567E81D45BFEC1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA0CD270DC974134ULL,
		0x6BBE49E3DA5A8911ULL,
		0x0DCF3C5AA730B47FULL,
		0x5E05E6F186EA7E75ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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