#include "../tests.h"

int32_t curve25519_key_cmp_high_test(void) {
	printf("Key High Bytes Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0,
		0,
		0,
		0,
		0x8FF9BA3C3925F083ULL,
		0x30AF316F04DB4250ULL,
		0xCF7335A20CD629EDULL,
		0x3DE5CFD16702DED1ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0,
		0,
		0,
		0,
		0x78FDC54815952CF0ULL,
		0xF619CF23F4C64CA8ULL,
		0xF0EBBEEFD60D3C32ULL,
		0x73254BAE056EE1B8ULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	int32_t res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC01966639DCC5140ULL,
		0xA480A299697C1BC5ULL,
		0xC976352DABB0AB64ULL,
		0x16794B7A163DF405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCC09B07A080AEAC9ULL,
		0x0789EFBA9AB14B21ULL,
		0x987E04F84F81B008ULL,
		0x055B137835BC0818ULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41D01AA0B2DE1E17ULL,
		0x4BC89690DF15124AULL,
		0x52C522E1AEE6765AULL,
		0x4B0C98E0BA818EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB8828D5E2639269FULL,
		0xA05E9B33871128C8ULL,
		0x1DE239A34DF92885ULL,
		0x3D9AA8B675A05A6AULL
	}};
	t = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE74BE7529E0BA47FULL,
		0xFAC3D5F5E27689FFULL,
		0xAD6D70813669DA41ULL,
		0x5B76AA9C02706EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBE494E6C6EF0F8EAULL,
		0x4C7778169F8EA381ULL,
		0x001DDBF677DF7C0DULL,
		0x2EB94CA4F3212DA5ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDCE8BF41D66D055CULL,
		0x2D65DCEF65B3FE8AULL,
		0x838C3F78F3910D1BULL,
		0x78B7C446CB25F012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDCE8BF41D66D055CULL,
		0x2D65DCEF65B3FE8AULL,
		0x838C3F78F3910D1BULL,
		0x78B7C446CB25F012ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA8271AADF03DC4B3ULL,
		0x5A37CDBBE07234E8ULL,
		0xCDC4829AA75C64B6ULL,
		0x20BFB64F5E2394F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7E52BC141930EA7ULL,
		0xD7F8807F78D09B0CULL,
		0x6C2323808F8DB8D6ULL,
		0x00F96CB6A294F5F6ULL
	}};
	t = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFA61B1624CF421AAULL,
		0x7A82833F36A4D5F3ULL,
		0x1BAD8FD851D20B00ULL,
		0x5906118864AC2597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5A927FE19D5DE311ULL,
		0x06BB401C6E2E415EULL,
		0xD310D2B3C637F569ULL,
		0x62CA017E92759FACULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC14DCBB1C72B15E3ULL,
		0x8071A80060B75048ULL,
		0x23C3DCB0B90817EFULL,
		0x400893CA8AA35818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB25B765E79782638ULL,
		0x7E82E62B72450A0BULL,
		0x7D82CB0CF2D49C25ULL,
		0x47B2A77FBAD6E3D5ULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x37C34E80CE38A7EDULL,
		0x0E7DA06A8F7635C7ULL,
		0x3DFD46C8861CA1C3ULL,
		0x6CF96F58DBD6509CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x37C34E80CE38A7EDULL,
		0x0E7DA06A8F7635C7ULL,
		0x3DFD46C8861CA1C3ULL,
		0x6CF96F58DBD6509CULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F2188001911A3BBULL,
		0xA0D033712F33CCFBULL,
		0x50A7C428C21CCDAEULL,
		0x6DDEF188D08189CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14F147DE742B00C7ULL,
		0x82FFB544D1198692ULL,
		0x42E03FAD4143A1E6ULL,
		0x55A31A49ACAED319ULL
	}};
	t = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBAF41474525932BULL,
		0x7D9AD04EE45888A5ULL,
		0x4BA069B5A6314192ULL,
		0x71E419C33358F12AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF25102BB10C9DE21ULL,
		0x073910F7C7D9DEBBULL,
		0x99DD8818A176FB31ULL,
		0x405F2F39D299E78EULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD440F236B7ABA48FULL,
		0x119B63DFEEFD6AE3ULL,
		0xEE0900D9EB1B04A8ULL,
		0x2DBE43585D868CD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFD81E3249B6C4DFFULL,
		0x0E78BE4BEAEA8FCDULL,
		0x296752F4130069AFULL,
		0x352FC4255F9AD3B8ULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBA4B328FA09117E0ULL,
		0xF5B28939A259FCAFULL,
		0xE071BA5B2819FC77ULL,
		0x39D2017D9806D402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBA4B328FA09117E0ULL,
		0xF5B28939A259FCAFULL,
		0xE071BA5B2819FC77ULL,
		0x39D2017D9806D402ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x88FBFE6E853B8B41ULL,
		0xC6C22568AF7ABBFCULL,
		0x6CAD232D0547FD6CULL,
		0x527A75201C852631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE6F0E057F7FEDDC2ULL,
		0xE7EDFF8AB9D8797AULL,
		0x26B14C5DA0BD8B27ULL,
		0x03FE5B92957EAB2FULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BC5DC9491AB02FFULL,
		0xD1A7E56FA6A89179ULL,
		0x4BA6E14E118DAD8BULL,
		0x164B4BEB5EA46F06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD8E9816F6CADE1A5ULL,
		0x7AD1275F6AF168FFULL,
		0x13467DA07F6E24A8ULL,
		0x72DC6F80F49D8A60ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA90C737F00B1C0AAULL,
		0xA58A26B69FC51C73ULL,
		0x29E7C996DC0E3245ULL,
		0x3B7D477058B832D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC832C9F7C10C087BULL,
		0x000EBEA6ABB5931AULL,
		0x20E7618F6D962B11ULL,
		0x1771E1B3D8AF1D81ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x45349277B139D6B7ULL,
		0x316ABAD2DD40BEC8ULL,
		0xF7D310FA0ECE521AULL,
		0x2BC8B2208AB09C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x45349277B139D6B7ULL,
		0x316ABAD2DD40BEC8ULL,
		0xF7D310FA0ECE521AULL,
		0x2BC8B2208AB09C67ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x768A0D28D11C67DBULL,
		0x4CACFDE9D6340A6BULL,
		0x183A067AE82DC235ULL,
		0x1261A47B476119E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7A82FE997B131DF6ULL,
		0xD80F80137808639EULL,
		0x7C78ADBBD3B056BFULL,
		0x0542558622DCEEC2ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE124BBA8BCE171A7ULL,
		0x80EF85A8EED7F7E3ULL,
		0x63842505AC949CF0ULL,
		0x5FE8A7BA1EE48D87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x852F6231F0E2F49BULL,
		0x526BEB396ACA89C8ULL,
		0xC9BB61853237721DULL,
		0x3C8FB679BCBECD11ULL
	}};
	t = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x929385AB96BC60AFULL,
		0xB3581434E35854D0ULL,
		0x330E58BF11CBB4F7ULL,
		0x0186101F56C77205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0D2E65F4DF299499ULL,
		0x9FD14C12A3486ED0ULL,
		0xA13E55F82B917673ULL,
		0x0B662CC8318546C3ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5ED2D4325F3968EULL,
		0xE24903B0E32D6F51ULL,
		0x72E156E46CB5FE11ULL,
		0x315F7543F4F4BBDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5ED2D4325F3968EULL,
		0xE24903B0E32D6F51ULL,
		0x72E156E46CB5FE11ULL,
		0x315F7543F4F4BBDFULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41BE0F3EFD558BDFULL,
		0xF69A1C2643092C0FULL,
		0x46A25FC8D7605080ULL,
		0x116BD6084B702A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE5296728238DFBE2ULL,
		0x90D0ECBB36F8A370ULL,
		0x7DFAFD4C4A3154F0ULL,
		0x1A841E10A78E2911ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB00C67C6EF47C531ULL,
		0x4DA21A331F9146EEULL,
		0x49A7BD3ACA55088CULL,
		0x0738CC3BDF9991DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC29B6047118697FCULL,
		0x1B6F903E7E5254A0ULL,
		0x3B1D81F9CF10FBF3ULL,
		0x2D2030B6106169E7ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x431D9E59918EE05BULL,
		0x01525F4E2978EDFBULL,
		0x6EAECD95DBF7742FULL,
		0x18444A362EE926D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE688845D1324CEBFULL,
		0x9B66C1E1C30B7CE6ULL,
		0x5999869E9071A8F2ULL,
		0x518C257FBAD5EC24ULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BF102FC0346CC7CULL,
		0x926DAA84F0056796ULL,
		0xBEB5D763309BA35EULL,
		0x666A1211A82CB32BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BF102FC0346CC7CULL,
		0x926DAA84F0056796ULL,
		0xBEB5D763309BA35EULL,
		0x666A1211A82CB32BULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4085F1125A58A0B2ULL,
		0x09D8D317BC302563ULL,
		0xE4241C424419029EULL,
		0x4E89F300D17BB11FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCFDE9DC897363E14ULL,
		0xDD76E276DA113847ULL,
		0xBE485A3C42234847ULL,
		0x43A7EED3EF2FADD2ULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4C32FEEE2D86505BULL,
		0x6C9B3F6015E4E01CULL,
		0x9B31E777EBCB60EAULL,
		0x0FFFD04A4F5A8D5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20A6CE9F45F61DF5ULL,
		0x3751A26154BA71C1ULL,
		0xB8B68A42C310117EULL,
		0x3BE8C4325D920D16ULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC21C3033F64A725ULL,
		0x8ED5E3B134091141ULL,
		0xF5D1D2DEEAD8A00AULL,
		0x6F84CC22CA866872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x55DD454BE2198055ULL,
		0x27A88F76E2500D2EULL,
		0xC0A6C6737229111FULL,
		0x453508DBA675628FULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFBD047D550254C0ULL,
		0x30E876FD5A6EEE63ULL,
		0xE55F2A698DE88727ULL,
		0x61C5C8F64187937AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFBD047D550254C0ULL,
		0x30E876FD5A6EEE63ULL,
		0xE55F2A698DE88727ULL,
		0x61C5C8F64187937AULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x881701DA177CBF26ULL,
		0xA2A370F752C379F0ULL,
		0x9E5D7F169C814B99ULL,
		0x03317294046318BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x03BA1509DABE1746ULL,
		0xE425AC3D4EC80419ULL,
		0x6136C66BECFBCEDDULL,
		0x29F98E14ED4D07FFULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA314222B94047045ULL,
		0x042A9C8B1AADE807ULL,
		0xA9C025079F3978CEULL,
		0x39B85098F25B6CC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9E77076593ADAC6CULL,
		0x648D8E1A28015B52ULL,
		0xB425A3AD05F7E428ULL,
		0x30EFC8E924BF8CE9ULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x719F683CB386DDDCULL,
		0xC042B38AB36E8DFDULL,
		0x7A3A461068B62B89ULL,
		0x4882E2DE9DA6F2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6755E13CD70B71CDULL,
		0xE4ECD4F40F1E9F12ULL,
		0x78DCC809E5CFFB37ULL,
		0x72AA765FC5D1460FULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x789C3DCDB99AE3CEULL,
		0x7A059304E401D94DULL,
		0xA95AC3F9FF78DE59ULL,
		0x0644BD8B1C87B986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x789C3DCDB99AE3CEULL,
		0x7A059304E401D94DULL,
		0xA95AC3F9FF78DE59ULL,
		0x0644BD8B1C87B986ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4AA5513045DC5B7ULL,
		0x33450B7EFBEA3D94ULL,
		0x66EA6217797ECEE0ULL,
		0x5418AD65E0B26D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC37AB23CF34F794FULL,
		0x909AC4353705D6BDULL,
		0x54092FE9C4E736B0ULL,
		0x229A22B2E02A620CULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3AD9BF2A3CB2B34FULL,
		0x17A5D3EB5DDA97E2ULL,
		0x2302CDF5C229A190ULL,
		0x2FB83078FDBD8C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6F9D7473FC636C43ULL,
		0x089C97229D338681ULL,
		0x6EE268A223FCCEFEULL,
		0x7B030DC591827D2AULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x46361EB5D9F5E7A6ULL,
		0x2946A89A54875282ULL,
		0x5B9297B183B0C3ADULL,
		0x57803CE1EE34D877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9EEB26CB8EC1CE1DULL,
		0x05293A80609EC289ULL,
		0x793702369E6517C9ULL,
		0x24B183B12A28308EULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0422F2B613DF2176ULL,
		0x297E1DD245BC7C45ULL,
		0x64B6E6F6E8C08E2FULL,
		0x16FE68EEC22FB39BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0422F2B613DF2176ULL,
		0x297E1DD245BC7C45ULL,
		0x64B6E6F6E8C08E2FULL,
		0x16FE68EEC22FB39BULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFDDC9CF2AB3F6426ULL,
		0xBC2F0E0DCEBF9EABULL,
		0xF862EC7E106D9590ULL,
		0x6CEAD897ADCFEC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4767ED54207F0F53ULL,
		0x0B910825C2225CC3ULL,
		0xFDE96ACF2189EE57ULL,
		0x12495A7D30627914ULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC14D7370883771E1ULL,
		0x5CF264BB49032D07ULL,
		0xD0123C67A111A3F6ULL,
		0x04BC6A271EC21EC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62396B03ED200A04ULL,
		0xD8DFB35CCDA3AB8CULL,
		0xAD4A186FE7DB33BEULL,
		0x772F41EFD524571FULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7C0FAB59EE8CAA45ULL,
		0x65125B456429086AULL,
		0xC78AE90CC46E9BDEULL,
		0x77E5F6BD09220B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE93B16CACEA253E4ULL,
		0xB4812B3D3B9C1E57ULL,
		0xF7E18EC345B1BE30ULL,
		0x01896F74EB32F8DDULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14AEB96F92117883ULL,
		0x2BB97ADBE292DD74ULL,
		0x9FA6E93493EF3FB7ULL,
		0x6904FB2B98A2DC43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14AEB96F92117883ULL,
		0x2BB97ADBE292DD74ULL,
		0x9FA6E93493EF3FB7ULL,
		0x6904FB2B98A2DC43ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCE79FAEBADFE6A33ULL,
		0xD0EDEAF6F8F37B0CULL,
		0xEC25EBF75AD8B8DCULL,
		0x281192F02321B51DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x579A5FFACC7DD08AULL,
		0xA48350D9BE953DBDULL,
		0x2CD85D8D1BC25D61ULL,
		0x7A627E33FF665BE4ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x183998649C16CB56ULL,
		0x23F2215DE36050E5ULL,
		0x7314F77E8546AECEULL,
		0x0F84F381A53C5CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1174F2D8F5E118AAULL,
		0x58019B900C286B8EULL,
		0xF078E059393A552DULL,
		0x5C38260854E48CFBULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA93394D17BC2029FULL,
		0x35CCC580BC9814B6ULL,
		0x3C1296BCD94BB19BULL,
		0x74CBDD6282BADDF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6EE45D2654C0E018ULL,
		0x941BC1A526CEFDB0ULL,
		0xE506DB47CB85B942ULL,
		0x6121ED750D9453A4ULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8580AAEA5D349926ULL,
		0xF454154844DBA009ULL,
		0x05254A7236D49109ULL,
		0x6FF5CF7D004CD427ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8580AAEA5D349926ULL,
		0xF454154844DBA009ULL,
		0x05254A7236D49109ULL,
		0x6FF5CF7D004CD427ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1C042F235BD4F678ULL,
		0x24E8AAA8C3FE2A6BULL,
		0x980FB47B9A3FFA8DULL,
		0x53FE23B19861E626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDA990E08E6F824C2ULL,
		0x45065B0217A4CC07ULL,
		0x0285F8E524276A52ULL,
		0x0F96572CC7A57489ULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAF01C1C9D0A7B242ULL,
		0xF3C0584760B593D6ULL,
		0xF73CA742DE14BBF6ULL,
		0x2609DDDC67639B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB72602465FAC3A51ULL,
		0x4BECAB6E44AEA66BULL,
		0x13D0DA099BEC7627ULL,
		0x5DA25F91C518E34AULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB007BBE007A445F7ULL,
		0xC14DD34994E68D35ULL,
		0x2E3D31941CF95980ULL,
		0x104FAB860D1CA9D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x895AADDCEF08689EULL,
		0xBF683B644EB4D23DULL,
		0xD86EE6132FFB6007ULL,
		0x01E1794E12288263ULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFDB3B52B33125000ULL,
		0xF617DB857C9467C7ULL,
		0xE90D3E5E0B65CACEULL,
		0x4A060D3145DF6BA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFDB3B52B33125000ULL,
		0xF617DB857C9467C7ULL,
		0xE90D3E5E0B65CACEULL,
		0x4A060D3145DF6BA2ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x757D85457896BBE9ULL,
		0x2E25BE94CFEBDA22ULL,
		0x43BB81FA13E9432CULL,
		0x0FE300A7B1C8E0E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD56C850E047EE3D4ULL,
		0x48541A500B971A71ULL,
		0xFEE2448279E924B5ULL,
		0x280387A292C5D96CULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9D42096CBF1D1DDULL,
		0x4130130187C874F3ULL,
		0x8B85E767F9AD3EA4ULL,
		0x49619301CFD9D589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAAA8612022C818B4ULL,
		0xE81C50E4EF7A02F0ULL,
		0x778C0766452247E0ULL,
		0x6F5BEE0BF48542D2ULL
	}};
	t = -1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BDD55D8983E8410ULL,
		0x8FE98F5C2C729B91ULL,
		0x9B7C4A0140532FDAULL,
		0x371672ACA8431558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF9C73F774947BE30ULL,
		0x1EC812DC28197388ULL,
		0xAF56CB16AF2E27A5ULL,
		0x5829E846997D9E13ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x99A080D15B302AADULL,
		0x935E87EA786EAA6BULL,
		0x9DB2E4B05D559A60ULL,
		0x4B605F1A883426D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x99A080D15B302AADULL,
		0x935E87EA786EAA6BULL,
		0x9DB2E4B05D559A60ULL,
		0x4B605F1A883426D9ULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAFA1D45EDF89DCADULL,
		0xD75808C4EC0DEE24ULL,
		0xBC9FDE99F405B948ULL,
		0x41B19EFC122618BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFE12BF5099C35074ULL,
		0x7B5CCA9EAAEF05CAULL,
		0x9E3C48157C89A617ULL,
		0x40BD53EEACA2696EULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB435C714E8E73DE8ULL,
		0xBF1C4E712EF33640ULL,
		0xA04624432B5895FCULL,
		0x044672D7171C5667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDD190C4974754113ULL,
		0xE35761E8B790454BULL,
		0x77370548C6A581FFULL,
		0x5C31F7E7EF60901AULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00594E8F0137A5F6ULL,
		0x72CF5DF73996F919ULL,
		0x501787E2A15D306EULL,
		0x78CDA42C9AA77997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD1007C10EADBE768ULL,
		0x433D46873D34ECFDULL,
		0x13188C3254B88835ULL,
		0x5735065BC8A6F670ULL
	}};
	t = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF317129BA96648F7ULL,
		0xB4EAD8752C272461ULL,
		0x9A6B00641BDE7529ULL,
		0x3335FD21C64DA3E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF317129BA96648F7ULL,
		0xB4EAD8752C272461ULL,
		0x9A6B00641BDE7529ULL,
		0x3335FD21C64DA3E8ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6D707135FBE2FB22ULL,
		0x1C8515E44F1C4181ULL,
		0xA68D5AAC68C2C35FULL,
		0x4E232950708F49B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x30A4310BC4595593ULL,
		0xC5755F20A62C5ECAULL,
		0x62649005E5C98ED8ULL,
		0x490802F19B258F0EULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB36B4B98BF29A9C2ULL,
		0x2CF8BD48C56815DFULL,
		0xDA4C3971AB46CF70ULL,
		0x6E56B4275331CFF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x09236B78D57A78E8ULL,
		0x3F14EF6CDC913BF6ULL,
		0x1E733B72837F0D07ULL,
		0x3D292FBDD5EEFB27ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2066BF7350A8A15FULL,
		0xE7CA892A08AFC155ULL,
		0x86B9F6260A114E6FULL,
		0x45A29660F366FC76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x710CC6796A6AD1CAULL,
		0xE89798C71998C439ULL,
		0xE6868BBEADF6A3FDULL,
		0x10D5BDAB3B36AD04ULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00D33157E46DC181ULL,
		0xA3A9BB6E3E329E55ULL,
		0xF60A6372B9B0A933ULL,
		0x4652737166176541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00D33157E46DC181ULL,
		0xA3A9BB6E3E329E55ULL,
		0xF60A6372B9B0A933ULL,
		0x4652737166176541ULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7F882DEB1F7278CAULL,
		0x010F284BD1A50CFDULL,
		0x0A8180B9B2221800ULL,
		0x24BF5B1F9351293DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD7A2F7EC45C89B59ULL,
		0x9DE73DFE6CEE93D5ULL,
		0x32FB2611C92CE297ULL,
		0x718819871B8F7222ULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC01259366CBF29FBULL,
		0x59941E83619E0A5CULL,
		0x140848091A6B6111ULL,
		0x50C73556D66045B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB41CF9E142D3152AULL,
		0x8FE65583A5985846ULL,
		0x48755ABE36F4A6CFULL,
		0x5AD70EF230D4B7BBULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4EB554A942E617CULL,
		0xA11AF95A9F3762EFULL,
		0xA4033DD56CCC58D8ULL,
		0x45D939B68E65F5A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x972AD41E4B4905C6ULL,
		0x80029C3E29353E94ULL,
		0x8734E880C97D4FEDULL,
		0x347BB08A1D8B4A22ULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0524A5DE0D026950ULL,
		0x77BD6507033A83C2ULL,
		0xE0C63B1A4EED0B66ULL,
		0x5AA0F454A0AE741CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0524A5DE0D026950ULL,
		0x77BD6507033A83C2ULL,
		0xE0C63B1A4EED0B66ULL,
		0x5AA0F454A0AE741CULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9D565354365F1976ULL,
		0xAF4D20C09FD7518BULL,
		0xCB1DEDCF8311D3F6ULL,
		0x5985FAA2C314EDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x43EF0404F475CA51ULL,
		0x2B240FBCC1B1D59FULL,
		0x3781B09E99FA99C6ULL,
		0x4B14A29C23A19DABULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4E231525A4B9C674ULL,
		0x7DCE05F9A0E5E23EULL,
		0xABBE868CF19596ADULL,
		0x25D8CFFDE3365617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC7E7F9A782985A5ULL,
		0x299C20F26C1D7EECULL,
		0xC9026739AD07E255ULL,
		0x0EEA5E2D0DB3591AULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D0F0A9F27FE4751ULL,
		0x284EA15D6530C2DBULL,
		0x9C03293DA87F85E1ULL,
		0x753DC0B0C8CACE2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD000BD01B53727CDULL,
		0x8A0233EA8CB6811EULL,
		0x964F7AE602E7913BULL,
		0x7239C4876E70E31FULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA98FEF9FDF7A68D2ULL,
		0x8A4709F49171F000ULL,
		0x309A0696C3EEB82EULL,
		0x4574121BD85C70D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA98FEF9FDF7A68D2ULL,
		0x8A4709F49171F000ULL,
		0x309A0696C3EEB82EULL,
		0x4574121BD85C70D6ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2B357F593DC62B03ULL,
		0xC526AE2E51310F6EULL,
		0xCB7E584CD779D475ULL,
		0x045F09E46B7C5960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB6F38EAB1F98387DULL,
		0x0B8D58EA9420CD82ULL,
		0x2E258E139D018142ULL,
		0x75CBB0FD46869100ULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD6673D9AC78CE2C6ULL,
		0x4F8F1C4F50C802E9ULL,
		0x3A3C12639FFD2C7EULL,
		0x6EB006C01AF34E8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFD82955A0CA1F2C8ULL,
		0x2EA74C6C992E43EAULL,
		0xE983D275359B90EEULL,
		0x578DF940FC9F271BULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x930F661242F9F604ULL,
		0x311B3D4ECECE3426ULL,
		0x0ADBD518325F11F5ULL,
		0x66072609A754C05FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2D314AF95424DA4DULL,
		0x3B238E07B9BD667CULL,
		0x8A3356175CDA1703ULL,
		0x0E24AFF3D339103EULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9138C86B3295AECULL,
		0x693E410900602E2AULL,
		0x03C0F5E88BDA1B3AULL,
		0x58DC7D1E5D4932B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9138C86B3295AECULL,
		0x693E410900602E2AULL,
		0x03C0F5E88BDA1B3AULL,
		0x58DC7D1E5D4932B8ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF9E94F12C0A8A35ULL,
		0xD6D00CDFA58BC214ULL,
		0x9158679AFFDD520EULL,
		0x19ECB7FD8B69EA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x887E631659581314ULL,
		0x3CBC87425E4A4E11ULL,
		0x51147F7691365633ULL,
		0x47CFF0178910BD2DULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x728D547BDA841A6BULL,
		0x47AB46EFBA2923F8ULL,
		0x9D350E39B176D3F1ULL,
		0x2CE4445DA04E6930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFC9237A4474187CAULL,
		0x80CC81278305F141ULL,
		0x98B27EBE77969E7BULL,
		0x3723FB479569B399ULL
	}};
	t = -1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8DE0A3D5E0282FF5ULL,
		0xFE426EA3802E2975ULL,
		0x3F98C803E4452F6EULL,
		0x5270F7DE4C92836EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB2428A25DDC27492ULL,
		0x68D5EFD12A3EC770ULL,
		0x2C5D06713AB032CCULL,
		0x6B9E8046C089AD04ULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67BB6F266C20A918ULL,
		0xB6A52324F6B27CA2ULL,
		0xE8A7E5C6004AE627ULL,
		0x24D187F950B9C4E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67BB6F266C20A918ULL,
		0xB6A52324F6B27CA2ULL,
		0xE8A7E5C6004AE627ULL,
		0x24D187F950B9C4E3ULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF386690C499B9394ULL,
		0xB5F8C050F0C0893DULL,
		0x2F911FFD4330404DULL,
		0x057057AB62C16961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5270E04BC26C35AULL,
		0x62269AB9554687E4ULL,
		0xD4F2254EFC12BA0EULL,
		0x7BF587751F91D981ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x45978C95FBDF3917ULL,
		0x3DE7797128E563A4ULL,
		0x67C1ED78EF88AF3FULL,
		0x6D4B67A83F9770E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66CEE6777AE34E1BULL,
		0xB362112FEA4F35BDULL,
		0xDA9025A9C1A821A0ULL,
		0x47BAC070FCB17086ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB96FBF92229A32EEULL,
		0x65C98F86AE0313E7ULL,
		0x2D59B7D6DA72AEE9ULL,
		0x5D526BA563039B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAE462545FB7E7BBCULL,
		0x40093BE86ACB9662ULL,
		0x190AA644BD349CD5ULL,
		0x1F0B1C9569DE3737ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3870EDCAEE7362CBULL,
		0x047EF30FEFB0E892ULL,
		0x1B2B7C7FE1F1822DULL,
		0x75EAB687F1CAFB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3870EDCAEE7362CBULL,
		0x047EF30FEFB0E892ULL,
		0x1B2B7C7FE1F1822DULL,
		0x75EAB687F1CAFB3BULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCA93A4C5F5EB6AFFULL,
		0x82926C6AF4B11C2BULL,
		0x22155893A344ED59ULL,
		0x4F79A25EBEBCE4D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x05F5E820753FBC4CULL,
		0x56684A1C6A2B45BDULL,
		0x7201579B5BC0155BULL,
		0x594A456E045F597EULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4B02938BE0C66803ULL,
		0x1560E800F281BC10ULL,
		0x051E250BC8CEB609ULL,
		0x6B6C4B189C406EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB11FBA1C52F11F14ULL,
		0xB6652AA006F8C482ULL,
		0xDC8BDB5E86FD94C0ULL,
		0x0058789D776D6429ULL
	}};
	t = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0DA561348976912BULL,
		0x751CB27CAE29C709ULL,
		0x779CE070FDA03676ULL,
		0x329992F84ECBAB68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x74ECEBDBFDE470AFULL,
		0x797A97D217F5F929ULL,
		0x2FA4513081274A03ULL,
		0x2FEFF9B12B7F9A96ULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7A6A4BDE4D03BA8EULL,
		0x52E9F50350F93CB3ULL,
		0xC1E4AF6814649748ULL,
		0x58216903E7D44414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7A6A4BDE4D03BA8EULL,
		0x52E9F50350F93CB3ULL,
		0xC1E4AF6814649748ULL,
		0x58216903E7D44414ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F14478D622125D9ULL,
		0x21859422888F0452ULL,
		0xCE613162030DDB5DULL,
		0x62F77F82B162F2FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE0A3DA029634716DULL,
		0x47FFC3A269FE3C7DULL,
		0x4E083397FACE0D38ULL,
		0x319EDA5D67D3744EULL
	}};
	t = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC4E940CCEFB0DCC7ULL,
		0xAA33EFDA7C61F326ULL,
		0x978D5AC179C68305ULL,
		0x363C62F5C57C850BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x334F1FD5D608983FULL,
		0x9662BA373C8D0A93ULL,
		0x107C71199B03254FULL,
		0x18E4B0B2C6919BF9ULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x58A8EA9635BEE8C7ULL,
		0x75489A318FC7E50AULL,
		0x9F51C3F5F8B504CFULL,
		0x2DF759E64A44EE09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB149E030A27A9FC4ULL,
		0xE41228C47B5F7C51ULL,
		0x2A12FB2D46722292ULL,
		0x6373BC0DEB01D175ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x313AE42720B64C46ULL,
		0xFFD625486A42B5DFULL,
		0x3B7874F0E93543D0ULL,
		0x3C46355FA7172680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x313AE42720B64C46ULL,
		0xFFD625486A42B5DFULL,
		0x3B7874F0E93543D0ULL,
		0x3C46355FA7172680ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF285E0A24BA78E83ULL,
		0x429796EA4435422DULL,
		0x64A7DEA897F4F35AULL,
		0x1FFFCD4AE5CEDCACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5E4F424CCA6B19CULL,
		0x006C95091C933C9EULL,
		0x4895E9AA27307632ULL,
		0x40C5ADD7967AAA9DULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BA60B8020671674ULL,
		0x21C6DC3BDFA6A7D2ULL,
		0x26F512FFCEA2D304ULL,
		0x06C3D641545F3D68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5C883F5C16A761CFULL,
		0xCCEB4BC9FC332896ULL,
		0x6F2F97E39B57E5F5ULL,
		0x394B0FA0301539E7ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2B8BFAAE15E14AB4ULL,
		0x82D27CF29573FDACULL,
		0x236B96BB56FFE475ULL,
		0x11708A3F06543ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF5CDDFD3BA4565A7ULL,
		0x582C84CBF26256B1ULL,
		0xF0F64CAB2EECE951ULL,
		0x25B52800886B3302ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66E1580F38C25A9BULL,
		0xED90DA1D5CCD31ADULL,
		0xE4CF06BE40BEBCA6ULL,
		0x1F62ECE4F80CF254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66E1580F38C25A9BULL,
		0xED90DA1D5CCD31ADULL,
		0xE4CF06BE40BEBCA6ULL,
		0x1F62ECE4F80CF254ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x33E075E5DBA4F4A8ULL,
		0x455C2C0AC9CE6BFFULL,
		0xFC3A93F0B38AAF82ULL,
		0x5FD8D1845C0BD995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC827593EEF867B39ULL,
		0xD941BE9835E9651CULL,
		0x06BE7D57FDE169E7ULL,
		0x3DE1F2FE6549CA0DULL
	}};
	t = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC3A83B14C9103161ULL,
		0x7E2A9B5237623264ULL,
		0xFE6246B1D4190BA7ULL,
		0x465481BFCC39AE72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3FD82C9777E46C7CULL,
		0x22517BFDADA75B46ULL,
		0x2FD05BAF2EEB9116ULL,
		0x58E84179AC06F013ULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB6A27C8D43E9FAFBULL,
		0x7693DF89830DCE3CULL,
		0x4138426C8ABB765BULL,
		0x691EE71850E10D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x35BADCEDE2CE3F56ULL,
		0x8E35CE94B4E597DEULL,
		0xD5799F944B35556FULL,
		0x607BD1C7956C2E62ULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x40C9C7430B99A605ULL,
		0xCB458A2CF6463365ULL,
		0xC1BEA53979A53C35ULL,
		0x1E4151EB828D2303ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x40C9C7430B99A605ULL,
		0xCB458A2CF6463365ULL,
		0xC1BEA53979A53C35ULL,
		0x1E4151EB828D2303ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE16787E0DD79ED5DULL,
		0xD9D26ADBB8D6C54CULL,
		0xF096507CB66EE5FEULL,
		0x61E75762107E4534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFFD35CC3004DC5AULL,
		0xA77A51ADA703CF8AULL,
		0xF4B5B3D7C5B1B532ULL,
		0x0B124BBDFD832B57ULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x51DD3801B1E0A0DDULL,
		0x611F3FF91B9E98C1ULL,
		0x1A1E229FC39A13C9ULL,
		0x39C50AD1AF8FD0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8F1022A0F47DA7D9ULL,
		0x21F5104F0D8267E7ULL,
		0x79E237517B4BE210ULL,
		0x501B8E8105439CEFULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x260D898BA4F95868ULL,
		0xF31048E4B80F3339ULL,
		0xD1CF01E9932A7D73ULL,
		0x4B83DD4DFAD325C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x93F7E6F67ED8FD50ULL,
		0x1B06B107BDA535DDULL,
		0x585EBF775208E5D0ULL,
		0x5CA87EAA40F82F18ULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44470DFB28E5152CULL,
		0x820405087A2CFD72ULL,
		0xF4FA92AEA2D1A725ULL,
		0x7CB5B401D68FF1BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44470DFB28E5152CULL,
		0x820405087A2CFD72ULL,
		0xF4FA92AEA2D1A725ULL,
		0x7CB5B401D68FF1BEULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x881578CC733CC4ACULL,
		0x39ECCDEC6E55B0EDULL,
		0xA9FEFDD2A4E693C0ULL,
		0x3E21F22522FA76AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x669095AC30816EBBULL,
		0x0966BC4FD24FB4FCULL,
		0x72F1973483014033ULL,
		0x6D37E2F1E9354327ULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x574214741FF95C82ULL,
		0xC8453DD3C04B994DULL,
		0x87206C74AE507E72ULL,
		0x18C3F8A1B454A69DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F3922881E9A4508ULL,
		0x46F152B2EF7FF649ULL,
		0xA182A4C64B83EF6FULL,
		0x22CB15F3B0E35806ULL
	}};
	t = -1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x389E9B4B2AC7589DULL,
		0x6E6604D46271D349ULL,
		0x49540616F1EC9E81ULL,
		0x70740EFB9B5F36CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x47F2F4A539709E56ULL,
		0xA0F733B3E30B7603ULL,
		0xD8030E61475FBDDFULL,
		0x75A2D5EC92AE288EULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x94D3A372B57074FBULL,
		0xC853B09484DB7C74ULL,
		0x3D0C77F15BB868E6ULL,
		0x3F686A9D93C2E526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x94D3A372B57074FBULL,
		0xC853B09484DB7C74ULL,
		0x3D0C77F15BB868E6ULL,
		0x3F686A9D93C2E526ULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E9323CC1F9F01D9ULL,
		0x3839A4A6FCC1E64EULL,
		0x630EC3DEBEA6B114ULL,
		0x5CF54F3BF1F9C6F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9422F0651BEFBDABULL,
		0x60E627FF230643E1ULL,
		0x15FB0AA5505F7502ULL,
		0x67A1EC2224A6E0E2ULL
	}};
	t = -1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA533C516C7CEA08BULL,
		0x211AF559C27935D4ULL,
		0x3F0242C76AF7389CULL,
		0x71698C4E12245232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF110214D4DCAE39ULL,
		0x5A61EA72FFA6944AULL,
		0xB4A77736FBDE78F3ULL,
		0x5B58A2C50CA63E14ULL
	}};
	t = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x54FDE8B6B2BEF8E4ULL,
		0x45AB812E444C177AULL,
		0x9E443CD0932FB861ULL,
		0x092A239384F61FBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA719CD36FCE7D970ULL,
		0x02FE115256FFEA76ULL,
		0x7C60911747DC5398ULL,
		0x08598F79B42530ABULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E63EA211BEECBACULL,
		0xF5049F45529029CAULL,
		0xD9640E66A0017865ULL,
		0x32118B80B677C9F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E63EA211BEECBACULL,
		0xF5049F45529029CAULL,
		0xD9640E66A0017865ULL,
		0x32118B80B677C9F3ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1913D92EAA61B7AULL,
		0xEA3D151D4A9CAB32ULL,
		0x712DAF2430876A72ULL,
		0x65F6F0061B575607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x75C67EA50D80DD96ULL,
		0x8C998A12D3F41B00ULL,
		0x75B2F3DC1AD4067CULL,
		0x710D843C1B3ED00EULL
	}};
	t = -1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x293192B691423BB2ULL,
		0x1FC142E715763400ULL,
		0x185E2C054C24F194ULL,
		0x00EE87278E6A4C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x665FCD6AE4184F3BULL,
		0x33618696CA1C0151ULL,
		0x3771781988244BF5ULL,
		0x19F9280B7FA628E0ULL
	}};
	t = -1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEF8C66F5AFD5A0BFULL,
		0x2589FAD5AEDA7322ULL,
		0xD9CCBD896DE236D9ULL,
		0x4F29912FDAA142F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCD0069F283CDA34BULL,
		0x6BC572185734D3BCULL,
		0x28D7060A2DBEEA99ULL,
		0x731C90095081F4CEULL
	}};
	t = -1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB550BA49F8A95AF6ULL,
		0xAA3B94E8EAA8437CULL,
		0xA1307B3FDFDC6FCAULL,
		0x437BCAF9B393BD24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB550BA49F8A95AF6ULL,
		0xAA3B94E8EAA8437CULL,
		0xA1307B3FDFDC6FCAULL,
		0x437BCAF9B393BD24ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCD8EA1ACC9828B25ULL,
		0xBF5E9D1E79D0BB78ULL,
		0x0DE856117607817AULL,
		0x1B7145A1CB71384EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE2CE7E4B3A3C1F55ULL,
		0x095111D948571D7BULL,
		0x81C6342D1E48CD50ULL,
		0x67B34E034F465E90ULL
	}};
	t = -1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD1BF873F23303E06ULL,
		0x6A34606A81452D88ULL,
		0xEDA5F4BB20EBE678ULL,
		0x77223C7CEC51D75AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE9A7B451B0D09600ULL,
		0xCE20FFD1B4AC8B31ULL,
		0xC79480462E2AC853ULL,
		0x2134DC2713DEA127ULL
	}};
	t = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x496585B7C25B51DDULL,
		0xB38FF7987E6CE3B2ULL,
		0x3682300411CE861CULL,
		0x23503F22E22E9FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC7A3409A51CA0DAULL,
		0xBA011241CECFBD51ULL,
		0x770A648B0187EF17ULL,
		0x238721225B056EF1ULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67E5032203BD790FULL,
		0x0173410AAC74B894ULL,
		0x3D9414817513F1F2ULL,
		0x1FD4218A668E2320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67E5032203BD790FULL,
		0x0173410AAC74B894ULL,
		0x3D9414817513F1F2ULL,
		0x1FD4218A668E2320ULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1BA68359BDDF1129ULL,
		0x820E2D9608375101ULL,
		0xFDFEDFE0147E4A37ULL,
		0x22F2DF9EB2BA6457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9BBBF8E2B027E3F4ULL,
		0xDE430AB68A225355ULL,
		0x7B319F58B334741BULL,
		0x6C074F649E78E416ULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4074B9CBD2A34124ULL,
		0x45A754950B533C2AULL,
		0x97A315BA00FAD7C2ULL,
		0x15FA24ABE684B0F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79A5CEEAE3085C33ULL,
		0x6969AB6B78406C26ULL,
		0xC6B62A4FD2BFE36AULL,
		0x7F2BE864280970E9ULL
	}};
	t = -1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC2EB96BACA0751AULL,
		0x4C32B2FFDDF04B8FULL,
		0x8C34A6C2AEF4FCA7ULL,
		0x2804712E204B27FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF954F0E0CD7BEC28ULL,
		0x84BEA66D2BE1FABFULL,
		0x744B45D6AE979B9BULL,
		0x208456FF709C3B5FULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16FE915F244810C5ULL,
		0xA0CB2F6015A90E74ULL,
		0xCC9CD9B93457F188ULL,
		0x76F68A69A1C6754CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16FE915F244810C5ULL,
		0xA0CB2F6015A90E74ULL,
		0xCC9CD9B93457F188ULL,
		0x76F68A69A1C6754CULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1F6503F54641AEB6ULL,
		0x3AA24102F7DEAB48ULL,
		0xCEDDB07BD0F3CA93ULL,
		0x66FA9D8977FA20D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9E28E3DF36A03C60ULL,
		0x4BE453CFA60CC786ULL,
		0x67B0F315E57CE3D8ULL,
		0x0E15B0981AA82BC2ULL
	}};
	t = 1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16FC3BD51220DBA0ULL,
		0x669EFB9A9DA99158ULL,
		0xE8ADEC7ABD0A0207ULL,
		0x04EBBC6F88D74385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x938926A06740DC5DULL,
		0x7430A082BF956F8FULL,
		0x1B97C3EFAA180F5AULL,
		0x23AA4E2E189498CDULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x84C2EDF455312E7EULL,
		0x9C38D0CBC573135DULL,
		0x1DC81B4FCC8B1492ULL,
		0x7EF0E1B2D5BD1B22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF900FB94DE162A01ULL,
		0x5E86B43F490192EEULL,
		0x902C6D465B958BB0ULL,
		0x0ADAE89756C373C1ULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5BC2BFF0B3FFFF78ULL,
		0x4F00E9A2A9B4711FULL,
		0xBB8C1221F7D1090AULL,
		0x3E03A8607F5AF205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5BC2BFF0B3FFFF78ULL,
		0x4F00E9A2A9B4711FULL,
		0xBB8C1221F7D1090AULL,
		0x3E03A8607F5AF205ULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49E1DEEEA16898F7ULL,
		0x29999296F61584DBULL,
		0x65D6DB82208F776DULL,
		0x3EB53D5BB75E6014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D446C98CB35A47DULL,
		0x7FAD5C5424D38DC6ULL,
		0x724B3A8D16F8F146ULL,
		0x17BDC2341B60F0FDULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3521C7520C845C53ULL,
		0xB12AC203B1C09BCFULL,
		0x680C4D4323A6BBFCULL,
		0x4C947DE28DA82DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2AFE94811AAA86B4ULL,
		0x9AC6CF23D9C73F9FULL,
		0x0CA0172DCDC194F9ULL,
		0x6DE77F1BEB9987E1ULL
	}};
	t = -1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14C5FCC9D4DAE77DULL,
		0x849BFB03247CF361ULL,
		0x60FF3406D71216F3ULL,
		0x7489865632D41E95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3434F4B181DF3968ULL,
		0x5D062A5CE33D7BACULL,
		0x7747E45DF5214F27ULL,
		0x0CE6CA070CB10C06ULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CE60A2AA572F160ULL,
		0x012FFBEDFEEFE54FULL,
		0xB2F478AF9821C17EULL,
		0x219F58823C86A142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CE60A2AA572F160ULL,
		0x012FFBEDFEEFE54FULL,
		0xB2F478AF9821C17EULL,
		0x219F58823C86A142ULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC066245D46480D9FULL,
		0x901CC94401B85BE8ULL,
		0xF903BEDFE45573DAULL,
		0x3B8FEE8FFCED96B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x175C98FF201EE968ULL,
		0x7190E93D54D3A27BULL,
		0x9D2A9E90E0D83C7CULL,
		0x0DC3CFA90450D1ACULL
	}};
	t = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x70AD612AB376BCB2ULL,
		0x3C347F56AD351D2DULL,
		0x69949762DAFC562AULL,
		0x38B76507D104ED68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA73B0DE39C666EF7ULL,
		0xC08301C66D34A06BULL,
		0xE552B3180673068CULL,
		0x1715002747277C20ULL
	}};
	t = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x56998EA52B4C3D94ULL,
		0x34DD241AD957E445ULL,
		0x030FC96F6E11651AULL,
		0x677081288FE163EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0A9CA1C0064D8E7ULL,
		0x716D50FE9B892875ULL,
		0xEA4B18A400770097ULL,
		0x7D59E3A97D4D1AEBULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x792B3AA0CB77DAE7ULL,
		0x321A13A2CFDF330FULL,
		0xE589D73BBF54FD2AULL,
		0x537FA21FFA4DD5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x792B3AA0CB77DAE7ULL,
		0x321A13A2CFDF330FULL,
		0xE589D73BBF54FD2AULL,
		0x537FA21FFA4DD5A8ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE390E5989D1D44DAULL,
		0xE71125AFA3355C46ULL,
		0x6D542151750A12BFULL,
		0x14A07EF94DE73756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x90CE4F4027C0E5CFULL,
		0xE20AD6EB982C9CD0ULL,
		0x338300E763F0CAA4ULL,
		0x061D4030408ACC01ULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x08D21ABA650CD51CULL,
		0x4B7D8C0776F35E7DULL,
		0x7D7800D13AF4E2EDULL,
		0x7FB721C42D0C8390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x748F9C4FE6CAF9A2ULL,
		0x9C2D20B34BB12F3AULL,
		0xD296832EC487956DULL,
		0x4F24CF472068AFE4ULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x85321937EA2F05B9ULL,
		0x22BFC0FEB8AD85B0ULL,
		0x3BBFEA030228A47CULL,
		0x791A7663DAAC3479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBEF9FDA1029D1493ULL,
		0xC87F87D48457441CULL,
		0xA8E5F8A51512DE3AULL,
		0x48F720B04388D629ULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4EA691BCBB9A843AULL,
		0x4AF50088AC0F43E6ULL,
		0xF9160CBD708DE59CULL,
		0x75EB57B40537F43FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4EA691BCBB9A843AULL,
		0x4AF50088AC0F43E6ULL,
		0xF9160CBD708DE59CULL,
		0x75EB57B40537F43FULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA927277B2536480FULL,
		0x67B28FD597476803ULL,
		0x93946B234141CA98ULL,
		0x39BBD0F247EA4C6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B851B2F7441589FULL,
		0xC8E63415FC446186ULL,
		0xAD6728E8C1F45C34ULL,
		0x1523A07FD5DF9F23ULL
	}};
	t = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x91955540010A891EULL,
		0xDF9456A46B42C2E1ULL,
		0x17D547DAE4696BA7ULL,
		0x5DDEB6BC4A4EFEE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E9A18B4D10FA248ULL,
		0x2887F58F3444D79FULL,
		0xF28B31C3C74F9463ULL,
		0x724ECA61467EAF3DULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE8B634CCC7088E44ULL,
		0x3199C0E16D94645FULL,
		0x9D276AF90DE87629ULL,
		0x40FF88E177C66FF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x285C6A68F4909C82ULL,
		0xF95B2B6EC79F7195ULL,
		0xE5AEAF9E2030A144ULL,
		0x4B866AFB58430C70ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x787EE935A5F1ED71ULL,
		0xDB5E1A7050C8007EULL,
		0x62982034490BFCF1ULL,
		0x3503434187DA59BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x787EE935A5F1ED71ULL,
		0xDB5E1A7050C8007EULL,
		0x62982034490BFCF1ULL,
		0x3503434187DA59BAULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01DCC956C1B04DBBULL,
		0x3B9B8FC95B285080ULL,
		0xA5DB2385B77A9FF8ULL,
		0x1E0CA494D96C0776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCB3B76EC66B72811ULL,
		0x745A6E4708378C37ULL,
		0xCA061334B326BAA6ULL,
		0x6686CE134766176DULL
	}};
	t = -1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4296AF2581A1CA52ULL,
		0xD0448371BED14D25ULL,
		0xEBEDE677E7B6AFDDULL,
		0x373B80D2FA479C87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7FCDD6B7DBDE64FULL,
		0x1D770965E2A053FDULL,
		0xB32BD96CF57D843CULL,
		0x7E23F9D97A7DA07BULL
	}};
	t = -1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x278C8AF3138AB3DDULL,
		0xE8A5F2E56DE4E66CULL,
		0x0010C8D35AE7935DULL,
		0x3355F289EAF9E89CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD752627F951CA245ULL,
		0xEB4F31CC1B3E27E3ULL,
		0xA3FF8ADB01BC8D9EULL,
		0x69D2B0A1C06D9621ULL
	}};
	t = -1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x488273D024BB42A9ULL,
		0x9DC4BB5514A8D52AULL,
		0x242243428128D74AULL,
		0x27A7EF0C2684776BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x488273D024BB42A9ULL,
		0x9DC4BB5514A8D52AULL,
		0x242243428128D74AULL,
		0x27A7EF0C2684776BULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE3CC52761FAABA55ULL,
		0x01AF8E69B97F30F2ULL,
		0x9631D00138DBD276ULL,
		0x351C5FDE60DB2958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x346785560DB9202AULL,
		0x808D0FA56495B26DULL,
		0x764D60DADB3D4036ULL,
		0x45DD664242B522C1ULL
	}};
	t = -1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x837B1E12792F830CULL,
		0x2E14E043D3253114ULL,
		0xF13F1C053E0CFC2DULL,
		0x566D34D61AF73E2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x004D40BBF1012E4DULL,
		0xE0D0C8CAAB894842ULL,
		0x21BFEEC6EDF7AC19ULL,
		0x5744159AB4D2582EULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1C0D91CB25753221ULL,
		0x29A51C460011346FULL,
		0xF94529E3A0C45BF1ULL,
		0x540F04CFBB8673B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E73A9CD1AFB9426ULL,
		0x115EAC53E3031313ULL,
		0x7F719BF99DB4A888ULL,
		0x654F8F22132B7821ULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA1D9EA1B303E576AULL,
		0xD91F33176C4B69E8ULL,
		0x8FBE651947D0CBC0ULL,
		0x5B4B10A629DCFC30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA1D9EA1B303E576AULL,
		0xD91F33176C4B69E8ULL,
		0x8FBE651947D0CBC0ULL,
		0x5B4B10A629DCFC30ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E46CD8198586160ULL,
		0x02284BB662812365ULL,
		0xF7AD04DD11D32D86ULL,
		0x6F7D8DBE2CFA10A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7248A762EA92FC52ULL,
		0xA3A075227CC1A3B2ULL,
		0xAF8BE066ADE7C78DULL,
		0x3F9261BF2503D3B8ULL
	}};
	t = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79D504BDD7EB5937ULL,
		0x61D63F80F266BA0FULL,
		0x4A430836E4D524DCULL,
		0x1EC3B66A04BE8E0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F156DCD10B0FBA5ULL,
		0x70176EF69CA1DFFAULL,
		0xF9994A3D318DF0E0ULL,
		0x7AAA8EC9E8285FD8ULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEACB12A2588E614CULL,
		0x93A3A55888E08AF3ULL,
		0x75A39FCD55EE2EDEULL,
		0x46A7B946C6334456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x51D1008AFC015E1BULL,
		0xE03FA99711D2E912ULL,
		0x25823A5E8BCEBF0DULL,
		0x0286610AD42722BFULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5AE072EBC1E7267ULL,
		0xBFF6395EC4C0AD34ULL,
		0x45F2485BAC63DA6DULL,
		0x4315376372A71130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5AE072EBC1E7267ULL,
		0xBFF6395EC4C0AD34ULL,
		0x45F2485BAC63DA6DULL,
		0x4315376372A71130ULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEDFA57703DF08FB5ULL,
		0x908F7C71F9B01964ULL,
		0x1FCF9F6E702A8182ULL,
		0x3186719E0422751CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA1F40DF452C54754ULL,
		0x8E19B761F9C1D4C2ULL,
		0x6FEC7D61B6DE5DD9ULL,
		0x1E179E2A7DB968E3ULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x96C8BCCFAD4D0FD1ULL,
		0x97F21379ABAFE38CULL,
		0x5D3F3B40BB9626AEULL,
		0x09441B5466A4718FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5949F4B34563EA0ULL,
		0xAB5291AB842F7CFAULL,
		0x5DC3666D3779B610ULL,
		0x7AA6D4CC4CE83EF5ULL
	}};
	t = -1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE95E298E47872125ULL,
		0xAB95376B898844A2ULL,
		0x0A066B9AD3D24D43ULL,
		0x6CEA31D5140FBB22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x57C9F8125B47858FULL,
		0x91F1C1F48AF7A1C8ULL,
		0x990560B36DCA2BA2ULL,
		0x7E060341E7E57457ULL
	}};
	t = -1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5AE3D9004814F5C6ULL,
		0x6848FAAA21D95279ULL,
		0x1A946C3446E691AEULL,
		0x4912A5A8006A5819ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5AE3D9004814F5C6ULL,
		0x6848FAAA21D95279ULL,
		0x1A946C3446E691AEULL,
		0x4912A5A8006A5819ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87BCE8BDCBD13383ULL,
		0xAA7A8B488ACAEE54ULL,
		0xF198F19F2899059FULL,
		0x55946F397C624737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA6131A747F923FB2ULL,
		0xD1DA09A1FBDD5473ULL,
		0xF3DF6D2788FB00E4ULL,
		0x7E2D64AA4D8C4F62ULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3DE38BFB7BD536A8ULL,
		0x9C72EEB67F0F992FULL,
		0x7D43C06BEE144925ULL,
		0x39C7C985EC7C6870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x838C34D81BA9521CULL,
		0xB915B06236D90E3AULL,
		0xCAEAAD06D19B1DBDULL,
		0x721007F5C0E9B6F1ULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1EBF647A33B3A562ULL,
		0xAEB737E4D080D61BULL,
		0xC6D15836A41CBA9CULL,
		0x3752400DCF94FBA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x30D7281D16D68248ULL,
		0xCA05EACB232A7833ULL,
		0x696E2784DB66EE59ULL,
		0x79F40E949A6B27F6ULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x97D24B26DC91954DULL,
		0x53EC6A756C55A20AULL,
		0x7C40E64D491CEE9AULL,
		0x2A4A6F2B79789727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x97D24B26DC91954DULL,
		0x53EC6A756C55A20AULL,
		0x7C40E64D491CEE9AULL,
		0x2A4A6F2B79789727ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3262AE1B7D8BFE91ULL,
		0xDC636BA900398952ULL,
		0xB9D6C6C609E09E91ULL,
		0x60204D8566F87132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E14FA697EC999A1ULL,
		0x0455212A944C2B98ULL,
		0x325B503187403584ULL,
		0x1E7F7C29BCB55002ULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA90AE7E91E0C018DULL,
		0xC9CF34D70B4ABE01ULL,
		0x66B00D344130F6BBULL,
		0x311A0E346D1FEB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BB1759E8EA63E35ULL,
		0xB5C3CDFF1C7258B1ULL,
		0x87AEDC6956C4823AULL,
		0x3B5E6EE06B479798ULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0EF0B67D8382D927ULL,
		0x40BFA41A53039022ULL,
		0x581CB066E2B27D92ULL,
		0x43624460DAC65316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFCE980DCE3E6154FULL,
		0x160764E567183F5FULL,
		0xF2B2A2077FF48AECULL,
		0x700E8528B0A60F5AULL
	}};
	t = -1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E0B765AF1DB5187ULL,
		0x0EC0BA72C7604C1DULL,
		0x1930ACCC6FEDC33CULL,
		0x4BCD9980539DD139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E0B765AF1DB5187ULL,
		0x0EC0BA72C7604C1DULL,
		0x1930ACCC6FEDC33CULL,
		0x4BCD9980539DD139ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x651ABFC20FE84378ULL,
		0x1E779904F095CB22ULL,
		0x2C8C648F63D54B45ULL,
		0x1D56597F4705739BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BB453097133DC76ULL,
		0xCD7E149A4B955F0AULL,
		0x896D707EAF0FC136ULL,
		0x108930BB6B8BF482ULL
	}};
	t = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x076E76D2A2714E2AULL,
		0xAEAAD9AED360B121ULL,
		0x8266CD9ABFFF2C71ULL,
		0x358E32357EACC4E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC96883DDC2068DEEULL,
		0xED5033B93E808FF7ULL,
		0xDA4DB0CBAF19510CULL,
		0x2883935B9C7218A0ULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x25F7D9CDC9DA2979ULL,
		0xF7FE815EFB9A6172ULL,
		0x1288A2DD8B5D7CC6ULL,
		0x6424E59F23031836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59456776FBF51960ULL,
		0x6EA0E6761FDAEE5AULL,
		0xA570AC1F4345CE98ULL,
		0x03B57B0CD167118CULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFB3CFC8E21B3230AULL,
		0x21EDFC227A3FDC2FULL,
		0xD50B2CEF59DF8834ULL,
		0x3233E6B5FF2D6698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFB3CFC8E21B3230AULL,
		0x21EDFC227A3FDC2FULL,
		0xD50B2CEF59DF8834ULL,
		0x3233E6B5FF2D6698ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDB729823999789B8ULL,
		0x8D53F3D38A673158ULL,
		0x9428471EFDE70BE3ULL,
		0x5C95E6ACB28B1970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x30697361EA953DB4ULL,
		0x5065958682CD3E66ULL,
		0xF049849A3DC3B6B6ULL,
		0x35B787DD5F94DD55ULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF06549F6533BFF7DULL,
		0x77B95D0523EC3CA4ULL,
		0x86AB301991E0479CULL,
		0x41027220243C3892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBD6639A398198E30ULL,
		0xCCD77433BCA289FEULL,
		0xBD439B834B94948FULL,
		0x730FABD40AB311ABULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x88B8AFCC558AB3C3ULL,
		0x93B1B9753366802BULL,
		0xC73A1EE7B5AB78EFULL,
		0x7E1731317473FA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5131F01F626AAADFULL,
		0xC4F2B09C1185CDE6ULL,
		0xD30A125244F9E1A2ULL,
		0x2E48DDC671F5DACAULL
	}};
	t = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49BBDDE529754969ULL,
		0x19FAFAED9860AE98ULL,
		0x05764400DB9E851FULL,
		0x7A7A44AA99665565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49BBDDE529754969ULL,
		0x19FAFAED9860AE98ULL,
		0x05764400DB9E851FULL,
		0x7A7A44AA99665565ULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79BFBC4D32E76B8BULL,
		0x68FFD1B4A22F1DDFULL,
		0x60D77FEE04682CC8ULL,
		0x14D4DBF018FEAD22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5B3335E1D037C44CULL,
		0xB03468D6F1E76B35ULL,
		0x504B4A94A75C16FAULL,
		0x3820F0D862D49F38ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41E45551E921276AULL,
		0x38B797897405DD80ULL,
		0xF0D3E4F420C1B7B5ULL,
		0x0A4F0BA3AC8B5C55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2D3F4D968E42BD27ULL,
		0x52705383AB15C7B5ULL,
		0x46C1DB0A53A5B675ULL,
		0x035119FBC3A9032BULL
	}};
	t = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x203CAEFABBBF2F68ULL,
		0xF0C797E7198C79DAULL,
		0xE3183A8F14B93417ULL,
		0x793032CC3D3EC00DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EDB3341E7AF605BULL,
		0x114FE6169647F446ULL,
		0xE52391FA2AB41F74ULL,
		0x6BF2F0F9D6D44424ULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x034ADA219409CF10ULL,
		0xD1C1FAD63977D370ULL,
		0x223A970922396F2DULL,
		0x7CF39C53AD38A1D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x034ADA219409CF10ULL,
		0xD1C1FAD63977D370ULL,
		0x223A970922396F2DULL,
		0x7CF39C53AD38A1D3ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7D731AD8CFADA27ULL,
		0x9A14AE15DB0BE35CULL,
		0xF4D2D36F435B2DC0ULL,
		0x345276A67A076FD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE938C667CA0818B6ULL,
		0x2FDD9899BAEAEC55ULL,
		0x706298192C364A1BULL,
		0x13A16789B2E41A24ULL
	}};
	t = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83ADA5CC66DC4D65ULL,
		0x8213B3EBD10E9FA2ULL,
		0xFCAD6C43EFCC77B5ULL,
		0x49D3546255D77E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA375D2238550DC1CULL,
		0x3F7EB330DF720BF1ULL,
		0x76C3F545B5510AB6ULL,
		0x024DE3ED84426516ULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEEF9616CECB8EA22ULL,
		0x7E2710B447F9D5AAULL,
		0x7C1183C8FBDF86A1ULL,
		0x300C9CF5AD1547D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CFF8F0AC0DCB9C7ULL,
		0xE4FFD7D5F81A5FBFULL,
		0xC8E352F19186414CULL,
		0x5437419A867D811AULL
	}};
	t = -1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5CEF4E937234A5AULL,
		0x2DFB11AF692748F7ULL,
		0x5C8EB92E11C6E86CULL,
		0x492844548B40E82DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5CEF4E937234A5AULL,
		0x2DFB11AF692748F7ULL,
		0x5C8EB92E11C6E86CULL,
		0x492844548B40E82DULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA3B97713419CAA12ULL,
		0x7DA5437E0F164C47ULL,
		0xE7CB67A43F95C55AULL,
		0x47EDE783365BE7F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x615C484B1673FEBCULL,
		0x4DAE45CE7B11694EULL,
		0x5A68CC0D908E131EULL,
		0x6120F595318AF39DULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x312DE71D539A942DULL,
		0x682B0909FAEC903CULL,
		0xA9E8816CA9CEB55FULL,
		0x62A0AFE992814EABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF792ABC124D21703ULL,
		0x65F4FC17248A1046ULL,
		0x7EFAD7CA8DF5EC67ULL,
		0x74D763015E83B3D3ULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE57D7CC33C4A32F5ULL,
		0x00A844D070A5198CULL,
		0x0D678A7417C38D79ULL,
		0x491CEF01DCDE33EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xECE766EBAA52D144ULL,
		0x1239380A425CA60CULL,
		0x96ED348B00359F9AULL,
		0x0C8CAC31482F69A6ULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCDC352003FF43EE0ULL,
		0xF1BB33643B3F9AECULL,
		0x99F1009C1DD50A22ULL,
		0x27DD6D44C73CA013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCDC352003FF43EE0ULL,
		0xF1BB33643B3F9AECULL,
		0x99F1009C1DD50A22ULL,
		0x27DD6D44C73CA013ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD904F2E846DADE5DULL,
		0x9A524558444EA267ULL,
		0x8834C3FE72EF11FCULL,
		0x70AD14A1C69E5DD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1700AEE0D33C93C5ULL,
		0x57A7E05759325D07ULL,
		0xDCA755EA0D761C1AULL,
		0x188AEA9E7308AD87ULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4E3AA285BF832770ULL,
		0xE1FDC6B8C45490DFULL,
		0xE1BAAF568DB822B3ULL,
		0x5FAB4227A549B257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB17B4D756CA8C979ULL,
		0xA333A03C99008F74ULL,
		0xE998C11AA43A0DD7ULL,
		0x055D09F532E10753ULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD885A1E25EE46294ULL,
		0x691827AC17A8F828ULL,
		0x2BFDE75DE14068AFULL,
		0x26FC709FBD88337CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBB37002DFD1A80EBULL,
		0xF0E0AC1615D70D18ULL,
		0xA46034B7ED9ED3F8ULL,
		0x3BB29AB37D8310C8ULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE7266536D27E1901ULL,
		0xB6A1AD1F75F54A28ULL,
		0x771221C89D71E547ULL,
		0x5220C0B2D77F612DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE7266536D27E1901ULL,
		0xB6A1AD1F75F54A28ULL,
		0x771221C89D71E547ULL,
		0x5220C0B2D77F612DULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBD477A5B8F8E8174ULL,
		0x64F7CE33E88098FCULL,
		0x3F615FB13E79D8F1ULL,
		0x76A63ECF927A3325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x36280A21471771C1ULL,
		0x8DAC511302CFA98AULL,
		0xBCA86DDD9BC46DA2ULL,
		0x3C2F65DF907D73E2ULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x92EE118F8DC01BCAULL,
		0xFCCD2856AC28B89EULL,
		0x2CEFD9BCDB3F86D2ULL,
		0x0BB369A09C3621D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB487DEF87C957F83ULL,
		0x06A60C6088EA8B06ULL,
		0x1E0EE9BC3E46817DULL,
		0x4ED29C1CB27A8A2DULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC928A5B3E393C0A7ULL,
		0xB6EA110B3758E4A7ULL,
		0x824FB35B9B4F31DAULL,
		0x239A6F99575F7182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F4C3D8825031A43ULL,
		0xBA94817E50DEB95DULL,
		0xCA80E78A149D6914ULL,
		0x0559E52D03B9AC9AULL
	}};
	t = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCAEE553DFEE0EB1DULL,
		0xA671202A9496B080ULL,
		0x8897E48EC8E7DF0AULL,
		0x288F9F003F29E37BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCAEE553DFEE0EB1DULL,
		0xA671202A9496B080ULL,
		0x8897E48EC8E7DF0AULL,
		0x288F9F003F29E37BULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x697EC32AFB0F3281ULL,
		0xB8A1CBC1BD8A0357ULL,
		0x906F08954FB5FEF8ULL,
		0x34C634B47209AB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x392B452726BAC808ULL,
		0x01A4F0B72DCD6EB3ULL,
		0xF80D189DCB93431FULL,
		0x5B632FDE070FB35BULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFA0E482FA87FC246ULL,
		0x8520DBEFF6868671ULL,
		0x129FBB7023828568ULL,
		0x71B49BBBAF24C42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCE889C5EE5BE96F9ULL,
		0xC7725A26F98204C3ULL,
		0x53215C68FABFB185ULL,
		0x57169DCA8C4207A1ULL
	}};
	t = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x22639459CA06E728ULL,
		0xDDD1858670E4B439ULL,
		0xDFB0C1BB3074ED12ULL,
		0x3ECFC62D490DBBB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5C6BA4F280AB20FCULL,
		0xA6F5B743ECC5B115ULL,
		0x4471BF1E1CB7B370ULL,
		0x5557E3AA6621B892ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0FDB28F676C28617ULL,
		0xE153838EADAAD700ULL,
		0x964632B5B5D967BBULL,
		0x199FBD5AE0E00882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0FDB28F676C28617ULL,
		0xE153838EADAAD700ULL,
		0x964632B5B5D967BBULL,
		0x199FBD5AE0E00882ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8302AB8C9E5CF82BULL,
		0x78FFE7C176B3BA84ULL,
		0xECD26EE643AD0363ULL,
		0x68E5D002A1CEF273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA08BCC3CB26A5636ULL,
		0xC8EEDCFA51E50FECULL,
		0x53F7A48A1392AEA1ULL,
		0x58B1E0E3C4277C75ULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8394D3DC3C07FAAEULL,
		0xBFD6AE72544D2465ULL,
		0xCC332B9EA01D65A9ULL,
		0x0D1526DBEFF34CC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3322551326A366D4ULL,
		0xFA5A968231DA86DCULL,
		0x711484991A9B2CF9ULL,
		0x77B711F83BFEC488ULL
	}};
	t = -1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCE85A64DF9BEF1AEULL,
		0xFC216A28F91CC6A6ULL,
		0x1B260FBAB9E97336ULL,
		0x6100093A94524F9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF75C3DAEAAAC1DF8ULL,
		0x4E320A96BAAFCDAFULL,
		0xE52F9FB573906B63ULL,
		0x0E06A94843A94E81ULL
	}};
	t = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
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