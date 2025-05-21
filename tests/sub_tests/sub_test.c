#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0xCDAB49627D4CE4F5ULL,
		0x04A0711F2F021042ULL,
		0x8601FF1DB1B29969ULL,
		0x3D9C47FAED70006AULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF14BB059CBD38EB0ULL,
		0x12106405D32DA466ULL,
		0x9533845B6E0DADCFULL,
		0x640B72A9D7DF503FULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xDC5F9908B1795632ULL,
		0xF2900D195BD46BDBULL,
		0xF0CE7AC243A4EB99ULL,
		0x5990D5511590B02AULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
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
		0x52CB96065C9910D8ULL,
		0x95C984AC43BDDD8CULL,
		0xD8DFB753AAF45E91ULL,
		0x7037E5AD7C54E005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE74AB36C1574852ULL,
		0xF1142188B5AB7301ULL,
		0x78C45BBE1DC025F6ULL,
		0x1CF6F871A190C0F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9456EACF9B41C886ULL,
		0xA4B563238E126A8AULL,
		0x601B5B958D34389AULL,
		0x5340ED3BDAC41F10ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x63C98C495CD1E015ULL,
		0x192AF9F737A76957ULL,
		0xC5C49A3A6B7D1EAEULL,
		0x2127DAE12F87F532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1252950E6FB1B7C0ULL,
		0x51F3115F5BBC4642ULL,
		0x775D40E05F4C6FBEULL,
		0x2C71C470A701A71EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5176F73AED202842ULL,
		0xC737E897DBEB2315ULL,
		0x4E67595A0C30AEEFULL,
		0x74B6167088864E14ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xBB6EEFAF3D12EF99ULL,
		0xFC79E15E1D5A3643ULL,
		0x72373670056B9849ULL,
		0x4A08D392568B988CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA9753ADF927940ULL,
		0x09F9BC9635EDE755ULL,
		0xFFCFE4F8844162F5ULL,
		0x35E3B7224FBBA127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEC57A745D807659ULL,
		0xF28024C7E76C4EEDULL,
		0x72675177812A3554ULL,
		0x14251C7006CFF764ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x48DE09781ED9400AULL,
		0xFC3EAF8B95B2BBECULL,
		0x0C8A3DFECBD316E9ULL,
		0x25E99477A37197E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB50A7DD05ABFB3CDULL,
		0xC69070CC7633827FULL,
		0x691A62C50C2CF30FULL,
		0x372D84F6249C497CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93D38BA7C4198C2AULL,
		0x35AE3EBF1F7F396CULL,
		0xA36FDB39BFA623DAULL,
		0x6EBC0F817ED54E68ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x58C7DB2B0C5E26DCULL,
		0xFD02EFD628CBA2CAULL,
		0xB382EF2D336FA738ULL,
		0x7AA1235E608D728AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFBFFCCAA23E6620ULL,
		0x30B5A10470D88AE0ULL,
		0xF135D19DDBA8CF6FULL,
		0x2AAA8B0BBB0F232BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7907DE606A1FC0BCULL,
		0xCC4D4ED1B7F317E9ULL,
		0xC24D1D8F57C6D7C9ULL,
		0x4FF69852A57E4F5EULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3BE158C461D5DF14ULL,
		0xDD0A72672C653F3FULL,
		0xD054A63597AFB79AULL,
		0x512C6C2AC93AF5CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x875A1C1BDF0FCCB0ULL,
		0xABB7C938CBB300A0ULL,
		0x35433183B179E473ULL,
		0x120044917E3E8852ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4873CA882C61264ULL,
		0x3152A92E60B23E9EULL,
		0x9B1174B1E635D327ULL,
		0x3F2C27994AFC6D78ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3FAA7E1E099BEFE4ULL,
		0x986FF019C5AC7246ULL,
		0xC5FC95C93E11BAE2ULL,
		0x5AE9EB48A72DC6D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA0B393397D3263BULL,
		0xB339ECC59A52012EULL,
		0xEA5AC395A275D5EBULL,
		0x7C91EC1FF8E65693ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x559F44EA71C8C996ULL,
		0xE53603542B5A7117ULL,
		0xDBA1D2339B9BE4F6ULL,
		0x5E57FF28AE477041ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x55BF46AED5A1C83CULL,
		0x28D20583FCF49D3DULL,
		0x0A202681D03FA6FCULL,
		0x31121D2E1385967EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028D45782AE36B96ULL,
		0x9540A73477151578ULL,
		0x0C2ABF9DCF432AA8ULL,
		0x43DF0782335B7A85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53320136AABE5C93ULL,
		0x93915E4F85DF87C5ULL,
		0xFDF566E400FC7C53ULL,
		0x6D3315ABE02A1BF8ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x327DFB75142E353FULL,
		0x8BEDDB1C8F11AD7BULL,
		0xC1DDBE41D8591996ULL,
		0x21E91C20C6ACF1F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF671AD0ED31843E8ULL,
		0x1B8ECE50B2658F3DULL,
		0x550DDD6204698BD7ULL,
		0x4450DA02D3F8618FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C0C4E664115F144ULL,
		0x705F0CCBDCAC1E3DULL,
		0x6CCFE0DFD3EF8DBFULL,
		0x5D98421DF2B49064ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xCC9CC957C5549AC5ULL,
		0x8F905AC9AB4306DEULL,
		0x6794E0E5B134C348ULL,
		0x77A02AC1FED6028AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91F9D610DC530BB2ULL,
		0x0ED9E373312FBE62ULL,
		0x3DA85EA82D441529ULL,
		0x2C8A41E589A54F12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AA2F346E9018F13ULL,
		0x80B677567A13487CULL,
		0x29EC823D83F0AE1FULL,
		0x4B15E8DC7530B378ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9D9E6C94764D5519ULL,
		0xC39D23DFE5A93094ULL,
		0x8826933DB21D867EULL,
		0x106190C15B69F7F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x192700E6A7D3168FULL,
		0x62BEBC07D3BE7E67ULL,
		0xD33CDA326D8A4BC7ULL,
		0x0B829A4E75BD30A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84776BADCE7A3E8AULL,
		0x60DE67D811EAB22DULL,
		0xB4E9B90B44933AB7ULL,
		0x04DEF672E5ACC750ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x619737E8BB9FBC43ULL,
		0xBC48768D63411A6BULL,
		0x190BD6EA72AF79A7ULL,
		0x281E4281D7FFC628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F6672F63974972ULL,
		0xC1C8B4E6C95744E1ULL,
		0x90BF64278F58B03EULL,
		0x64BC7DF29B044CFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFA0D0B9580872BEULL,
		0xFA7FC1A699E9D589ULL,
		0x884C72C2E356C968ULL,
		0x4361C48F3CFB7929ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6F8C1059E744F163ULL,
		0x0CCE14D98DD478A6ULL,
		0x0D8A4BF2F3CEE8F9ULL,
		0x050D83A6DE201064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52158853DE466FBULL,
		0xA2C58950130CB052ULL,
		0x8A61FF89D939ACCFULL,
		0x59088BF8B1AF1EDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A6AB7D4A9608A55ULL,
		0x6A088B897AC7C853ULL,
		0x83284C691A953C29ULL,
		0x2C04F7AE2C70F185ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x316938F0CD7B9D6AULL,
		0xA46CCBADE43BC5D2ULL,
		0x90D0691DA3DF561CULL,
		0x10B9EEF26F142D20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0E0EFAA7499612DULL,
		0xDEDB5B35414FD8DAULL,
		0xA57E436AFB9979CEULL,
		0x537CD0D638A9F69FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7088494658E23C2AULL,
		0xC5917078A2EBECF7ULL,
		0xEB5225B2A845DC4DULL,
		0x3D3D1E1C366A3680ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x87348F2AA8826E99ULL,
		0x7F70FD6470001AABULL,
		0x985D09C5B20DA90AULL,
		0x78516E3B86052BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x320BDB90C0F368D9ULL,
		0x4FCA530A47A2516CULL,
		0x1E91ED4489A3A00CULL,
		0x64B4789FA62148DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5528B399E78F05C0ULL,
		0x2FA6AA5A285DC93FULL,
		0x79CB1C81286A08FEULL,
		0x139CF59BDFE3E2F1ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xCAD4695764720731ULL,
		0x2E36AED1456D31E9ULL,
		0xF34ABA4EA8591FE5ULL,
		0x2803E381C5229921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF3784BA96872969ULL,
		0x7FD22963E74FA16BULL,
		0xFFD37DC09FF085AAULL,
		0x6FB2C5F35CECBCA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB9CE49CCDEADDB5ULL,
		0xAE64856D5E1D907DULL,
		0xF3773C8E08689A3AULL,
		0x38511D8E6835DC77ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA3C1B3270A7F5E16ULL,
		0xA5227AE0AA8D9D14ULL,
		0xECC25207D16D4B06ULL,
		0x4DC0DFFC450A9DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A3366EF0A02A83AULL,
		0x41BD8AFAC8FD249BULL,
		0xA22FB7A13EADC82DULL,
		0x106BF423DE505BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x498E4C38007CB5DCULL,
		0x6364EFE5E1907879ULL,
		0x4A929A6692BF82D9ULL,
		0x3D54EBD866BA41BAULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE5A0171C4F84EA12ULL,
		0xE37EB89F73789FD0ULL,
		0x5809AAEE2C5394C1ULL,
		0x3E66F4C376B1A179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C2CEC5F4F00435DULL,
		0x4199F0282DA8976CULL,
		0x91575FD22C60FE82ULL,
		0x615853F07F7AB5B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49732ABD0084A6A2ULL,
		0xA1E4C87745D00864ULL,
		0xC6B24B1BFFF2963FULL,
		0x5D0EA0D2F736EBC1ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x21BEEF61203A5FCBULL,
		0x25AEA81D0FA90289ULL,
		0xF403E1A34DCD4DEFULL,
		0x276ED7DAF02E8AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA97A5D7F762458DULL,
		0x6F689F6AF6A82B4CULL,
		0x02150449D0A8EC1AULL,
		0x0B6368BDC947CA0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6727498928D81A3EULL,
		0xB64608B21900D73CULL,
		0xF1EEDD597D2461D4ULL,
		0x1C0B6F1D26E6C0A4ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x98C5A6BCCEBDC380ULL,
		0x5C200214A026FA84ULL,
		0xA3B6AB27310297CCULL,
		0x6E6A341FCC6D9BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF557814958A2A4FFULL,
		0x58A10F0B8F276881ULL,
		0xB16A1DFDED1D5E42ULL,
		0x2754C21B6101DD68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA36E2573761B1E81ULL,
		0x037EF30910FF9202ULL,
		0xF24C8D2943E5398AULL,
		0x471572046B6BBE41ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x7746E4F979F68439ULL,
		0xCCE97CFC90FDAC29ULL,
		0xA3E3FD3CA3EA72A2ULL,
		0x2FB64D195F6E38BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DDCCF24A2C8CA5FULL,
		0x137940CB3EAF6356ULL,
		0x6E49C0D8AC2A9E8DULL,
		0x00A4C581AD2AF455ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF96A15D4D72DB9DAULL,
		0xB9703C31524E48D2ULL,
		0x359A3C63F7BFD415ULL,
		0x2F118797B2434467ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9B2B5B6E1F88ABE6ULL,
		0x429A0874924D7CFCULL,
		0x47855B6D80361E72ULL,
		0x3C8A8099E7EF2908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9594E57E0BD76BAULL,
		0x2FDCEDC010F60F9EULL,
		0x91FC19776BAF92A0ULL,
		0x46A8C0E61E0BC261ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1D20D163ECB3519ULL,
		0x12BD1AB481576D5DULL,
		0xB58941F614868BD2ULL,
		0x75E1BFB3C9E366A6ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA858C53FAF6E8ABFULL,
		0xD173D6E673B44A00ULL,
		0x1F946E6960FC669AULL,
		0x114A9F91806E0CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E888AF8960CA2EULL,
		0xF92CFD41C5DEFA95ULL,
		0x492A9044B0EEDB8BULL,
		0x25BA0AD466D883E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F703C90260DC07EULL,
		0xD846D9A4ADD54F6BULL,
		0xD669DE24B00D8B0EULL,
		0x6B9094BD199588FCULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x771A2E9E13A94CD2ULL,
		0xD417411A5D352D79ULL,
		0xD37845BF2614D103ULL,
		0x548F7A0F427F49F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x674F6E04C75463F6ULL,
		0x3AC149697F4C9B4CULL,
		0xD63D50E06C035ADEULL,
		0x77424F2406F940B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FCAC0994C54E8C9ULL,
		0x9955F7B0DDE8922DULL,
		0xFD3AF4DEBA117625ULL,
		0x5D4D2AEB3B86093BULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD07E9A6FEAD90959ULL,
		0x36FF99573271FE9FULL,
		0x8B41D66DE0F1E119ULL,
		0x155EA2F2FB22EC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE39F5E6847F5DE2ULL,
		0x3E04A8A438542519ULL,
		0x8ADB6F049BE7B432ULL,
		0x2989BE9C4E170688ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE244A4896659AB64ULL,
		0xF8FAF0B2FA1DD985ULL,
		0x00666769450A2CE6ULL,
		0x6BD4E456AD0BE58AULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB8F77877E5BC3DFAULL,
		0xCE03FD59451390C0ULL,
		0xA0046B3CF7A58465ULL,
		0x2B39D54DA80F2861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDED081A0A7D5A7B4ULL,
		0xE687C82910AC9B96ULL,
		0xF0A3617028B47BEBULL,
		0x50EF28A4FA6D30CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA26F6D73DE69633ULL,
		0xE77C35303466F529ULL,
		0xAF6109CCCEF10879ULL,
		0x5A4AACA8ADA1F792ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x169B2E8D6CC7AF34ULL,
		0xFA3AEC6D5315F8B2ULL,
		0x18E38DA1F882550CULL,
		0x29286C232864BD9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36699B353B773B40ULL,
		0xC93FDED986874AE0ULL,
		0xA1D3A8D8A9608CA2ULL,
		0x14BD220FDE23F713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0319358315073F4ULL,
		0x30FB0D93CC8EADD1ULL,
		0x770FE4C94F21C86AULL,
		0x146B4A134A40C68BULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB5649F82F73D0B64ULL,
		0xB6CB2D2EB6D42FE3ULL,
		0xC1667CC4CAEE8C84ULL,
		0x4CF85C24EFD348B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9266A6E8E62E9F5ULL,
		0x6C271F12F3D875DFULL,
		0x291A90F86EA02770ULL,
		0x2371A782C1FC553BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC3E351468DA216FULL,
		0x4AA40E1BC2FBBA03ULL,
		0x984BEBCC5C4E6514ULL,
		0x2986B4A22DD6F37AULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xFEFD766EFC4CDEABULL,
		0x4A95481F7E45CF90ULL,
		0x646E9C6C0FEEF551ULL,
		0x2D968822CEF7B905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x706B3557C8626746ULL,
		0x00E9032CC44B2389ULL,
		0x87B40A2978F44ED9ULL,
		0x382824838EDDFCF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E92411733EA7752ULL,
		0x49AC44F2B9FAAC07ULL,
		0xDCBA924296FAA678ULL,
		0x756E639F4019BC11ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA35AF9F987F57819ULL,
		0x1724A2622033241EULL,
		0xDF0FE8C22F870CFDULL,
		0x1AC24C70EA07F356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7BBDBA1BB1EECABULL,
		0xF12B4CF9901C9143ULL,
		0xC58C962E38C33959ULL,
		0x1AA68770C81AE4F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB9F1E57CCD68B6EULL,
		0x25F95568901692DAULL,
		0x19835293F6C3D3A3ULL,
		0x001BC50021ED0E5EULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB56AB3869FD4C524ULL,
		0x91FECA589CBAEEECULL,
		0xB74E5378F73EB00CULL,
		0x1A3305FEC1FEBE19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B21ECC43435229ULL,
		0xDC34E2F92E12310FULL,
		0xD78280C5412EAE5AULL,
		0x119F0104203BE707ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51B894BA5C9172FBULL,
		0xB5C9E75F6EA8BDDDULL,
		0xDFCBD2B3B61001B1ULL,
		0x089404FAA1C2D711ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x0A3B6B60E11F3E69ULL,
		0xEBDEA32D1F59D5AEULL,
		0x289D6B45C8A7186DULL,
		0x73D253E4E9767276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA33674EEFC3F8CDULL,
		0x6F0F84746507F4DFULL,
		0xF68E483E8BEE687FULL,
		0x56C36D80072FD0D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30080411F15B459CULL,
		0x7CCF1EB8BA51E0CEULL,
		0x320F23073CB8AFEEULL,
		0x1D0EE664E246A1A3ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x15A792A8516C890FULL,
		0x3A32BC3FC42D56B2ULL,
		0x5B17703ED77C2F88ULL,
		0x374E0CF466E5B7AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDABA96ACD1C8CBD1ULL,
		0xC7DB0367BB97E1D6ULL,
		0xBA1F116AFFF29C41ULL,
		0x7401DD37D7C55E17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AECFBFB7FA3BD2BULL,
		0x7257B8D8089574DBULL,
		0xA0F85ED3D7899346ULL,
		0x434C2FBC8F205997ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8BA6305131A6E55AULL,
		0x62EB3F13966F2CC7ULL,
		0x8C26ED0560BBFBCAULL,
		0x4D5437F9F0E337E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A6F986D162AFF4ULL,
		0x3C7293B09B37093AULL,
		0x31FE00D9AC63EA15ULL,
		0x01D9971C4CEC8EC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4FF36CA60443566ULL,
		0x2678AB62FB38238CULL,
		0x5A28EC2BB45811B5ULL,
		0x4B7AA0DDA3F6A91CULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9675E6F3781AAC8BULL,
		0x23426A3B99C0580AULL,
		0x75B864DD2086288BULL,
		0x7BF8121D3F408D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C232094C061D24AULL,
		0x2406B5C933CDCDD4ULL,
		0x103E15FAF3A016B0ULL,
		0x21268815AB7917DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A52C65EB7B8DA41ULL,
		0xFF3BB47265F28A36ULL,
		0x657A4EE22CE611DAULL,
		0x5AD18A0793C775B5ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5FF48890404A1667ULL,
		0x3C8FB966A130CDB7ULL,
		0x360CB058889F3AA5ULL,
		0x1EC2A4873B3022FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBADBCEB08673212ULL,
		0x5D5D31EAE4F78174ULL,
		0x8A22AA7D7AB78E77ULL,
		0x38D8AD28C71B5B7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7446CBA537E2E442ULL,
		0xDF32877BBC394C42ULL,
		0xABEA05DB0DE7AC2DULL,
		0x65E9F75E7414C77EULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x880FD73905626CF3ULL,
		0xE71527ED3EACD493ULL,
		0x60BA837806EFCB31ULL,
		0x7B145C30AADEE3E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E7A806CC6D1296ULL,
		0x7EB8554D922E97BEULL,
		0x022E4410E37D1E61ULL,
		0x15300A820F99C6FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F282F3238F55A5DULL,
		0x685CD29FAC7E3CD4ULL,
		0x5E8C3F672372ACD0ULL,
		0x65E451AE9B451CECULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x445E5C64665388FDULL,
		0x345F9C6B98DF25D7ULL,
		0xE0B1F9B0520B8CFCULL,
		0x3782986A8262BB49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2E11B94F763853ULL,
		0x7BF478F29014D41BULL,
		0xC9716EAEF6824433ULL,
		0x167185581A603998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89304AAB16DD50AAULL,
		0xB86B237908CA51BBULL,
		0x17408B015B8948C8ULL,
		0x21111312680281B1ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x628A34EA96E528AEULL,
		0xE226E5EDD5C88714ULL,
		0xBB868CF9EDFEAA48ULL,
		0x6F35D1D55791754BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84B532E11F81C0D1ULL,
		0x7758AB0D946EB2BEULL,
		0xA51BC0AE30CAA258ULL,
		0x49CB5B8816649AE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDD50209776367DDULL,
		0x6ACE3AE04159D455ULL,
		0x166ACC4BBD3407F0ULL,
		0x256A764D412CDA6BULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x13AB8F96652BB8A2ULL,
		0x8248C258C230211DULL,
		0xD70F8FCF17AE1F5AULL,
		0x56DC088E529A5EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC18BE9143E1CC2CULL,
		0x614CA6C4960770EDULL,
		0xB1E516856C541B4FULL,
		0x6AF4D8AB434FDFFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6792D1052149EC63ULL,
		0x20FC1B942C28B02FULL,
		0x252A7949AB5A040BULL,
		0x6BE72FE30F4A7EB2ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x53C450327A94503CULL,
		0x066D0BF38E72D8D4ULL,
		0x3E97DD32FF9CE4E0ULL,
		0x7BEE5F88D0BEF2D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47838770701EBBE6ULL,
		0xA945CFF3F30990FAULL,
		0x0F509A7A131F847AULL,
		0x0DBE103DF1346E6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C40C8C20A759456ULL,
		0x5D273BFF9B6947DAULL,
		0x2F4742B8EC7D6065ULL,
		0x6E304F4ADF8A8464ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xEE1B86D7ED465321ULL,
		0xB8E96591A3B3F0ECULL,
		0x03ED58F3E34FD77FULL,
		0x570A69906BF32EE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5690C3332EE771ULL,
		0xC8ECD5BA74816007ULL,
		0xC185B06C7DBC1B44ULL,
		0x56E9C7BCAA38F738ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71C4F614BA176BB0ULL,
		0xEFFC8FD72F3290E5ULL,
		0x4267A8876593BC3AULL,
		0x0020A1D3C1BA37AFULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9CBF2D2B8A31112FULL,
		0xC238667876602ECDULL,
		0xAB5C9C432A07693EULL,
		0x03515C4FD2CD1486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BFE1E706905D66ULL,
		0x174D29FAF1CEC780ULL,
		0x30D6DF0A7783DD65ULL,
		0x62A4FF217840B4D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7FF4B4483A0B3B6ULL,
		0xAAEB3C7D8491674CULL,
		0x7A85BD38B2838BD9ULL,
		0x20AC5D2E5A8C5FAEULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA2B1CADD8C29AAD6ULL,
		0xFA88EA7778FB8C35ULL,
		0xE7D07DBB1702E449ULL,
		0x45FCCDBDDD0B7392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83E8133047352E2ULL,
		0x01462AF6E9AACE7EULL,
		0x342146B82D2F7FECULL,
		0x5F836B7AD4F64D1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA7349AA87B657E1ULL,
		0xF942BF808F50BDB6ULL,
		0xB3AF3702E9D3645DULL,
		0x6679624308152674ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x7DF68F59E1FEEC78ULL,
		0x2328CA1F7E3500CFULL,
		0xE039264732FF063AULL,
		0x285F26ADE362C28FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27AE0FABD040051DULL,
		0x614B42B46C759CC5ULL,
		0x6B883EC73CF583B4ULL,
		0x54ABC569FDAF3B9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56487FAE11BEE748ULL,
		0xC1DD876B11BF640AULL,
		0x74B0E77FF6098285ULL,
		0x53B36143E5B386F1ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x0C73718A9665000FULL,
		0x1A7E8382A2CF1318ULL,
		0x4B27A7F723901ED1ULL,
		0x28FBD4940173DEB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DAB241C6B3CB635ULL,
		0x5886762707B95B72ULL,
		0x38092A007C6B87D0ULL,
		0x1214C0E1DCBCF88CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEC84D6E2B2849DAULL,
		0xC1F80D5B9B15B7A5ULL,
		0x131E7DF6A7249700ULL,
		0x16E713B224B6E62AULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xDEEA62EA71E9905AULL,
		0xE0BF7131E3450AFAULL,
		0x9DAA8C5CE7384902ULL,
		0x134312D9837BD258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6DFDFF672258C5FULL,
		0x88EF0D4B99508A08ULL,
		0x60F658E7B9F700BDULL,
		0x40A3570F9FA9E381ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x280A82F3FFC403E8ULL,
		0x57D063E649F480F2ULL,
		0x3CB433752D414845ULL,
		0x529FBBC9E3D1EED7ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xFE954B95D56989D5ULL,
		0x0C2FC8B1C3A475EDULL,
		0x6D0D6633BD2FF768ULL,
		0x3266BD6A1FC47BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C892BC774A3F17ULL,
		0x1D5D48DDB8D2B748ULL,
		0x9ECF5EBCAC0A3B7DULL,
		0x5E48321EBD2D93ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77CCB8D95E1F4AABULL,
		0xEED27FD40AD1BEA5ULL,
		0xCE3E07771125BBEAULL,
		0x541E8B4B6296E7CFULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x058E0B17B9119693ULL,
		0x1CA3A3947A1ADC3AULL,
		0x27E3D194E51A13E1ULL,
		0x404DAE3C8F15E7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53F0B2A004AA4D7AULL,
		0x49C5E362501A0C8EULL,
		0x82512BCEB0089EB6ULL,
		0x18B1AD7E8B276FEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB19D5877B4674919ULL,
		0xD2DDC0322A00CFABULL,
		0xA592A5C63511752AULL,
		0x279C00BE03EE77C7ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x67DADD8B4E90AE34ULL,
		0x74D5073564EC7CFBULL,
		0xDA63BE3B344A87E5ULL,
		0x0B5310DB0B24AFE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55453C25AC7E1C53ULL,
		0x78130CF0499A1E4CULL,
		0x2D1355E9FFB3069BULL,
		0x4E7EB65EC447627BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1295A165A21291CEULL,
		0xFCC1FA451B525EAFULL,
		0xAD50685134978149ULL,
		0x3CD45A7C46DD4D6EULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8D48113DB9DDA560ULL,
		0x42A48E845083FE31ULL,
		0x5C11B55EFD9DDF40ULL,
		0x2B5FF149F1F92795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15D05A7E309FFC58ULL,
		0x24D1194D5FED3244ULL,
		0xC6EB9A5062282EB1ULL,
		0x40CD528D44D36CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7777B6BF893DA8F5ULL,
		0x1DD37536F096CBEDULL,
		0x95261B0E9B75B08FULL,
		0x6A929EBCAD25BA9BULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x350DB177829E0D61ULL,
		0x25DB27D379AF62D0ULL,
		0xFA6982C587356CF6ULL,
		0x36C7E547A3D071BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E0E0E11085F752ULL,
		0xCC7F00D87B77D6AEULL,
		0xD56E515F21AF6898ULL,
		0x701A4798EB2E6E99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA02CD096721815FCULL,
		0x595C26FAFE378C21ULL,
		0x24FB31666586045DULL,
		0x46AD9DAEB8A20321ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xEAF2CED25AB5F88AULL,
		0x10F0AEAB9F02FBDFULL,
		0x376BBD8E7277AB48ULL,
		0x753AEA2E66751497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0ACAC80D4274911ULL,
		0x135528705BA24A71ULL,
		0xFFBA8C18621AC659ULL,
		0x213F883954CEF1ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A462251868EAF79ULL,
		0xFD9B863B4360B16EULL,
		0x37B13176105CE4EEULL,
		0x53FB61F511A622EAULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xBD0CBBAFCE5D4185ULL,
		0x0E2D20E7AF773F7BULL,
		0x4B24B2300564BC05ULL,
		0x6A64B51A37217ED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7D8DDD38F61B38ULL,
		0x099106B72A950BE0ULL,
		0x0DC5463F645A41F1ULL,
		0x3061FF5DC4E506BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D8F2DD29567264DULL,
		0x049C1A3084E2339BULL,
		0x3D5F6BF0A10A7A14ULL,
		0x3A02B5BC723C7817ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2E85785692729E58ULL,
		0x744340ECDF42D268ULL,
		0x6A598DAA6FFC3972ULL,
		0x56AF805E41697BFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5818E5ED6FF36B23ULL,
		0x931C12F1327DA62EULL,
		0x0FBE4BD74268FF59ULL,
		0x039A0E5FC6738EF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD66C9269227F3335ULL,
		0xE1272DFBACC52C39ULL,
		0x5A9B41D32D933A18ULL,
		0x531571FE7AF5ED0AULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5D37D37673FF1D8DULL,
		0x5C6060E0C41896C9ULL,
		0x266B5A624B22238BULL,
		0x7A90A8D5709DC583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08BC946984AB2CADULL,
		0x35A6B1F6DB4477C0ULL,
		0xA4788B89303CD185ULL,
		0x399E878A497D2182ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x547B3F0CEF53F0E0ULL,
		0x26B9AEE9E8D41F09ULL,
		0x81F2CED91AE55206ULL,
		0x40F2214B2720A400ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5A7A1E664CC54C4FULL,
		0x3197A55F426167F7ULL,
		0x62A0359EE6A0D4DAULL,
		0x48BA5C9FF0F553E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FE5A506E7E26A8FULL,
		0xEDE479C374EC8007ULL,
		0x20564BDBC6EF0170ULL,
		0x7DEC4CEC2C15BE36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA94795F64E2E1ADULL,
		0x43B32B9BCD74E7EFULL,
		0x4249E9C31FB1D369ULL,
		0x4ACE0FB3C4DF95B0ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6D539CA4DEF8D686ULL,
		0x4377C613D396FE56ULL,
		0x1C20C29E27FDD856ULL,
		0x53AB2940DB0A681EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B183C668EA1205ULL,
		0x8786C763B45CBF8DULL,
		0x7639F5BDBB9AFFF5ULL,
		0x71A675667DEB6CE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAA218DE760EC46EULL,
		0xBBF0FEB01F3A3EC8ULL,
		0xA5E6CCE06C62D860ULL,
		0x6204B3DA5D1EFB37ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x827C30BA02DD5F48ULL,
		0x8FE4DB25D49E2633ULL,
		0x160DC2D9AA6A5E92ULL,
		0x0A6B44B437BE89B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23F4D247433DD588ULL,
		0x27583E50A15DC0BCULL,
		0xABC507BDEF65B9C3ULL,
		0x5EA5C702B13DB787ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E875E72BF9F89ADULL,
		0x688C9CD533406577ULL,
		0x6A48BB1BBB04A4CFULL,
		0x2BC57DB18680D230ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x21BECD117D910FD5ULL,
		0x8D063FFBB323FFA1ULL,
		0x033C805E630BF1B6ULL,
		0x21B152A6FE97718BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70C995E3EADE67CULL,
		0x85E09681A14271B0ULL,
		0xA7C37923D6F5BFEEULL,
		0x3C91EDB6484BBD89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AB233B33EE32946ULL,
		0x0725A97A11E18DF0ULL,
		0x5B79073A8C1631C8ULL,
		0x651F64F0B64BB401ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x244E860E1A37F55DULL,
		0xB225824B68AFE6A6ULL,
		0x63C16B2BBC0BFE14ULL,
		0x5444E2993AAB89E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69EAA5ED210E3948ULL,
		0x4C0077330FC86B20ULL,
		0x7A8508CC4323BC0DULL,
		0x657ECB649A822076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA63E020F929BC02ULL,
		0x66250B1858E77B85ULL,
		0xE93C625F78E84207ULL,
		0x6EC61734A0296969ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2E4AFDCF266783DEULL,
		0xBF24A543F5D6A78FULL,
		0xC43D7E37D87417EBULL,
		0x026A4911A940FCCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7EABAACA7E07F8ULL,
		0x12B131B1B8889ED4ULL,
		0xEA570F49E5B4CAE4ULL,
		0x78D1BF210AE3E526ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAECC52245BE97BD3ULL,
		0xAC7373923D4E08BAULL,
		0xD9E66EEDF2BF4D07ULL,
		0x099889F09E5D17A4ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE727C03DC6CE0510ULL,
		0xAC50DE0052197B8CULL,
		0xB0BE1B25CE327908ULL,
		0x7B7AC5AB7DE0801BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A69742A9D26C447ULL,
		0xA3D1649FD88EAAE9ULL,
		0xF066E4553230B4EEULL,
		0x5892B1EEA4C9DC5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CBE4C1329A740C9ULL,
		0x087F7960798AD0A3ULL,
		0xC05736D09C01C41AULL,
		0x22E813BCD916A3BFULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x1C7F93FCB8C86E63ULL,
		0x6154F54B4D5E6A71ULL,
		0xAE2EC6EF07F8E7D4ULL,
		0x63CA113B2D64DE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA0DC3254BD2B03DULL,
		0x11D23FD4C5FFECEBULL,
		0xB2971E0019593032ULL,
		0x1C48196F871D0185ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3271D0D76CF5BE26ULL,
		0x4F82B576875E7D85ULL,
		0xFB97A8EEEE9FB7A2ULL,
		0x4781F7CBA647DCFCULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x68C83DD3C1270008ULL,
		0xF91408B95D7E94FBULL,
		0xCD4C40F3D3D09F0CULL,
		0x74502F19CCF5D758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7637D1B155C33C7CULL,
		0x393B621B080B9411ULL,
		0x00534288EB804A0FULL,
		0x737001A6CF41A826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2906C226B63C38CULL,
		0xBFD8A69E557300E9ULL,
		0xCCF8FE6AE85054FDULL,
		0x00E02D72FDB42F32ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xF936887BA5747FE2ULL,
		0x3ADB8AAF33003FCFULL,
		0x02CC464BDFF20A44ULL,
		0x48BC55D356D0F52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9411B9AADC839CA1ULL,
		0xC169ACD4DE9F0C9AULL,
		0x57B2391283980C69ULL,
		0x4459E2706F21F39FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6524CED0C8F0E341ULL,
		0x7971DDDA54613335ULL,
		0xAB1A0D395C59FDDAULL,
		0x04627362E7AF018CULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x559680D5350FF1A3ULL,
		0x9CAA6E9BEEC2C560ULL,
		0xCE6B266559F6C11DULL,
		0x39B0C004D6DAFC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x050C95D4CB33854BULL,
		0xF3496AA6FF6ABB3EULL,
		0xA2DAC2C4A0F6CC49ULL,
		0x2230CA8FB88A90A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5089EB0069DC6C58ULL,
		0xA96103F4EF580A22ULL,
		0x2B9063A0B8FFF4D3ULL,
		0x177FF5751E506B84ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xACC407EE7CFA5C60ULL,
		0x536A351D871B206DULL,
		0x330D247074C6B6A6ULL,
		0x0495FE2CCF80F5A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7F30C6FB15AEA6ULL,
		0xD9AD321C60CAA6F3ULL,
		0xC5C88E953894F4C5ULL,
		0x65146119F930EAD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4044D72781E4ADA7ULL,
		0x79BD03012650797AULL,
		0x6D4495DB3C31C1E0ULL,
		0x1F819D12D6500AD3ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x61A5682EBB896B0EULL,
		0xE33C448505BBE93EULL,
		0xBA09AF58B1A0D05FULL,
		0x6ACA60099E17BA50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x684E7A109AF2AE2EULL,
		0x02029398A2C609DDULL,
		0x6522304FE2783CDAULL,
		0x1E83A011A0C30AAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF956EE1E2096BCE0ULL,
		0xE139B0EC62F5DF60ULL,
		0x54E77F08CF289385ULL,
		0x4C46BFF7FD54AFA6ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x27E4A2F56503FE72ULL,
		0x4C35D1E0FD119A67ULL,
		0x7C0CE67F9D62D4F6ULL,
		0x49A06B5E71BDA6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E12090953A7DB9ULL,
		0xAA8A5C5A05185584ULL,
		0xB5FBFBABB55B5D8BULL,
		0x007A7703EE2EA82CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60038264CFC980B9ULL,
		0xA1AB7586F7F944E2ULL,
		0xC610EAD3E807776AULL,
		0x4925F45A838EFE81ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x35721EF441867F81ULL,
		0x968A2BB719304285ULL,
		0x4F8FBD107B6CFE12ULL,
		0x70EC7D97EBE8F048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB1E7F8DFC61802ULL,
		0xCE21B1F4F16525BAULL,
		0xBB48EA6B2E1FCEF6ULL,
		0x681A4D5ECD13C1E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7C036FB61C0677FULL,
		0xC86879C227CB1CCAULL,
		0x9446D2A54D4D2F1BULL,
		0x08D230391ED52E61ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE43773A25105CC42ULL,
		0x118608FB3A310882ULL,
		0x3E83179884240944ULL,
		0x41853A67A10187DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362FD80E3B959BF2ULL,
		0x4409D0EA847D54F4ULL,
		0x57429E705682A535ULL,
		0x5BAFDFA1DF7CD9CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE079B941570303DULL,
		0xCD7C3810B5B3B38EULL,
		0xE74079282DA1640EULL,
		0x65D55AC5C184AE0DULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8F5B81E49BC93ED4ULL,
		0xEC96396157E4722BULL,
		0x7CC72982EB4B99B8ULL,
		0x5CD792A2E37FFB55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF455A63048BD92B5ULL,
		0x34AD49AA6E56EFA4ULL,
		0x6F65E10B45673179ULL,
		0x1685E304224B7968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B05DBB4530BAC1FULL,
		0xB7E8EFB6E98D8286ULL,
		0x0D614877A5E4683FULL,
		0x4651AF9EC13481EDULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3F8BB79774115D49ULL,
		0x4DBDEE42E66B15CDULL,
		0x70BBBE27888B420CULL,
		0x0C5212B7B5903F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8618E6FBC5924B3BULL,
		0x3BE4334B60282CA4ULL,
		0xC9BCB58E96BED088ULL,
		0x6C4DAF3AD3D6C622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB972D09BAE7F11FBULL,
		0x11D9BAF78642E928ULL,
		0xA6FF0898F1CC7184ULL,
		0x2004637CE1B9794CULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB987AFC78B9D919EULL,
		0xCA826DB11DF8DAC7ULL,
		0x82A61375B6997DDFULL,
		0x19C9171741B982F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21F5B61A1537B596ULL,
		0xBA1636578E589F49ULL,
		0xDC2C330D0BE3311CULL,
		0x3B60DC085F9EA292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9791F9AD7665DBF5ULL,
		0x106C37598FA03B7EULL,
		0xA679E068AAB64CC3ULL,
		0x5E683B0EE21AE064ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8E75D19E0676A200ULL,
		0x8C4DB9D82969AA3CULL,
		0x8C0789538B6719E6ULL,
		0x2AFC0F868B939454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7751AD56EBBB25CULL,
		0x75BD96CA4ADBB3C5ULL,
		0xF0F6DE4CBE9DBD5FULL,
		0x6F2578B4605A5B6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD700B6C897BAEF91ULL,
		0x1690230DDE8DF676ULL,
		0x9B10AB06CCC95C87ULL,
		0x3BD696D22B3938E7ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAF3435A31C21BDF7ULL,
		0x9DBB173B64C4D8D3ULL,
		0x3AAE78098AED8BC8ULL,
		0x3EE5C433BEDE25AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED97D989F7709CA6ULL,
		0x3506430FCAC1FB02ULL,
		0xAEB4E8E78B2833CAULL,
		0x4F0065B3A4F09435ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC19C5C1924B1213EULL,
		0x68B4D42B9A02DDD0ULL,
		0x8BF98F21FFC557FEULL,
		0x6FE55E8019ED9179ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA2DB4825B936257FULL,
		0xFFCA5ACBAFAD6EDAULL,
		0x2DE7CBC80B10C32BULL,
		0x06839D1B376FC480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E451D91ECDAFBFDULL,
		0x475DFCBC25BDBA42ULL,
		0x0B6439F81C0A7250ULL,
		0x60C353E975462BC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24962A93CC5B296FULL,
		0xB86C5E0F89EFB498ULL,
		0x228391CFEF0650DBULL,
		0x25C04931C22998BBULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x56217942EB7245A1ULL,
		0x24C9ED224A2C6D13ULL,
		0x66B19F4C307B22B0ULL,
		0x2F32760419FB8717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB67390AE90546EAULL,
		0xC332D8314AB17A2AULL,
		0x0C5F3B135365ADD2ULL,
		0x13E17251B9ABE3FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ABA4038026CFEB7ULL,
		0x619714F0FF7AF2E8ULL,
		0x5A526438DD1574DDULL,
		0x1B5103B2604FA31AULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAAC29CE2CA5E97F6ULL,
		0xAAD9704A694CBA1DULL,
		0x6B0DA27A27A85357ULL,
		0x68F7F42624E8C15AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBE5D9344B066E38ULL,
		0x4781777FE356E578ULL,
		0xF71D27EA497D7EEFULL,
		0x4863EA312072D9BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEDCC3AE7F5829BEULL,
		0x6357F8CA85F5D4A4ULL,
		0x73F07A8FDE2AD468ULL,
		0x209409F50475E79EULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x97D5F4EB8709A7D4ULL,
		0xC3BC879028571466ULL,
		0x7D21ABDB95721CE8ULL,
		0x5261263BD66693C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D92BBFA008DAF2ULL,
		0x8B226AD358493EB3ULL,
		0x4F3194735F60B740ULL,
		0x274DE5266ED3600AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1FCC92BE700CCE2ULL,
		0x389A1CBCD00DD5B2ULL,
		0x2DF01768361165A8ULL,
		0x2B134115679333BEULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xF7AFEF8B5091AF1DULL,
		0xC10C8F0275D61CC4ULL,
		0xF56881AB32775E08ULL,
		0x466E5CFE4ABC89E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07B1E69322D0F676ULL,
		0x00457145ACBEBF3BULL,
		0xE267367556F93A38ULL,
		0x3A1595887260CE62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFFE08F82DC0B8A7ULL,
		0xC0C71DBCC9175D89ULL,
		0x13014B35DB7E23D0ULL,
		0x0C58C775D85BBB83ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x54BD2874FA239971ULL,
		0x999052F9164D22E5ULL,
		0xD9059D30DF045461ULL,
		0x31F2F82BAF1FCC25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x307FEEC07EB388E8ULL,
		0x439C2BE6E4827F08ULL,
		0xFAE0DE4C1778AC05ULL,
		0x2AECB53BED25229CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x243D39B47B701089ULL,
		0x55F4271231CAA3DDULL,
		0xDE24BEE4C78BA85CULL,
		0x070642EFC1FAA988ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x4F043B33F0EF8167ULL,
		0xFAD75DA8030AD359ULL,
		0xF3D80477DBE22290ULL,
		0x4A5398FCA17B9527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99B374BE053D248ULL,
		0x0A429C7C5C790F92ULL,
		0xE062F3E0C4A3CE5BULL,
		0x511C93D1E2A043F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x656903E8109BAF0CULL,
		0xF094C12BA691C3C6ULL,
		0x13751097173E5435ULL,
		0x7937052ABEDB512FULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x90A3629AAF2761D7ULL,
		0x2CC497C2BDF05FAFULL,
		0xBBDC68823A048A36ULL,
		0x19AC8C5F2EAA1723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1B797ACD975BC0ULL,
		0xD7B63C5F45764172ULL,
		0xC1F6D3C6BFF541E8ULL,
		0x7E4BC4F45C12EE4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA287E91FE1900604ULL,
		0x550E5B63787A1E3CULL,
		0xF9E594BB7A0F484DULL,
		0x1B60C76AD29728D8ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x20E94B4D84364E55ULL,
		0x992F220A570556DFULL,
		0xA74DF71E7B9A991BULL,
		0x5EFC1750C7B78633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB8EC2506444C849ULL,
		0x9D4BC06CF774FC63ULL,
		0x685E6040DCB0F644ULL,
		0x4CB78CBD2806D4F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x655A88FD1FF1860CULL,
		0xFBE3619D5F905A7BULL,
		0x3EEF96DD9EE9A2D6ULL,
		0x12448A939FB0B140ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x4BB79F7F731C2192ULL,
		0x17B4D91AFA7E7E88ULL,
		0x259AB49BB354B916ULL,
		0x2CD05D3524F6CA09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81B1F258BC55D4E8ULL,
		0xEDFA5B451F8C9078ULL,
		0xD01CC2ECA866B932ULL,
		0x323F304DB4B81A69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA05AD26B6C64C97ULL,
		0x29BA7DD5DAF1EE0FULL,
		0x557DF1AF0AEDFFE3ULL,
		0x7A912CE7703EAF9FULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x625CF07A9DB210CDULL,
		0xE5E0B090FBDED245ULL,
		0x3C94DCC9A4C16473ULL,
		0x5455625DC87FECACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D2F2D0430F13D65ULL,
		0xBB14F58985D48C9FULL,
		0x29F6058B3D76190DULL,
		0x346A12F6A6455043ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x152DC3766CC0D368ULL,
		0x2ACBBB07760A45A6ULL,
		0x129ED73E674B4B66ULL,
		0x1FEB4F67223A9C69ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x1680B597B5F4F5F5ULL,
		0x9A77CD4A04253820ULL,
		0x88D73455937469EAULL,
		0x6EB8F43850FAF3E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB297F8F5803EC66ULL,
		0xC93963EE05E2512EULL,
		0xFA34A62E4D58DE6EULL,
		0x2463B3E1C43EFE34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B5736085DF1098FULL,
		0xD13E695BFE42E6F1ULL,
		0x8EA28E27461B8B7BULL,
		0x4A5540568CBBF5B3ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA8794E234DD13785ULL,
		0x1B46AA3BDB098244ULL,
		0x7FF76AAEE3110F6AULL,
		0x3D5A24DF94B2E2E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB09790C360B5DD8DULL,
		0xEC64706AA780B8A5ULL,
		0x9E0169554A455DA5ULL,
		0x4D29C6D1C3BE3795ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7E1BD5FED1B59E5ULL,
		0x2EE239D13388C99EULL,
		0xE1F6015998CBB1C4ULL,
		0x70305E0DD0F4AB4BULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAFE40F5718C8E210ULL,
		0x2AFD7A0E7063C177ULL,
		0x1F7FBB1AFEE81F72ULL,
		0x4F5CEA94EC8017C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71141BED71558912ULL,
		0x605B15D547A4E709ULL,
		0x608AEF39F626392EULL,
		0x3819C1D56FEC1DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ECFF369A77358FEULL,
		0xCAA2643928BEDA6EULL,
		0xBEF4CBE108C1E643ULL,
		0x174328BF7C93F9CCULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xFF9EC92120A37DAFULL,
		0x1F175707CC3715F5ULL,
		0xE9DDB94395545DA5ULL,
		0x460A9F28B3EF6A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20973E3BE9F1B058ULL,
		0x69977548450A32EBULL,
		0x2D981A8D4BD2E1C6ULL,
		0x0AE71F2B182736D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF078AE536B1CD57ULL,
		0xB57FE1BF872CE30AULL,
		0xBC459EB649817BDEULL,
		0x3B237FFD9BC83399ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x670C8C84B564B05AULL,
		0x9CE753C543DC9398ULL,
		0x922E5294E3B7181BULL,
		0x5B99738A3DB9FC7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF3F920D15654C38ULL,
		0xC4DB782E719ED706ULL,
		0xB93549812F4B3A6FULL,
		0x635818F63D236F57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87CCFA779FFF640FULL,
		0xD80BDB96D23DBC91ULL,
		0xD8F90913B46BDDABULL,
		0x78415A9400968D27ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6B86C9AA7868C238ULL,
		0x491E727C69F06A62ULL,
		0x74C240EED45CD092ULL,
		0x01F0FBB7BC0BE244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D03C8C64518098ULL,
		0x5D604C806C34C38DULL,
		0x4E4BBD8071330ED4ULL,
		0x6DB46316627DB055ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3B68D1E1417418DULL,
		0xEBBE25FBFDBBA6D4ULL,
		0x2676836E6329C1BDULL,
		0x143C98A1598E31EFULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x7137CFCD77FD1C59ULL,
		0x3ADF3589917F9B8AULL,
		0xB212B725FD4C3BB1ULL,
		0x6499EA4A0E5716DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58C0F4A93416E335ULL,
		0x5D5CEBCF2BE2B69DULL,
		0x24453857B537B246ULL,
		0x125D56305CF187D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1876DB2443E63924ULL,
		0xDD8249BA659CE4EDULL,
		0x8DCD7ECE4814896AULL,
		0x523C9419B1658F03ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xEAAA8363D22D5E14ULL,
		0xE8287E43ECFFBA9EULL,
		0xFED2DD28D527697BULL,
		0x2B4B2C3C5878570EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E588ADC9DD4E39ULL,
		0xFFD89CCD24F84986ULL,
		0xEB5FCDD36F7BACC6ULL,
		0x682EDC583351C4C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8C4FAB608500FC8ULL,
		0xE84FE176C8077118ULL,
		0x13730F5565ABBCB4ULL,
		0x431C4FE42526924CULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA1EA4650FC528E00ULL,
		0xA552FB5FC56750B3ULL,
		0x716F21438277CFC4ULL,
		0x47398EF80EBF8167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF36DB6F43B3D2C9EULL,
		0xAB056485C56E6384ULL,
		0xE1DAA290940D1F05ULL,
		0x2B61713C02846EE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE7C8F5CC1156162ULL,
		0xFA4D96D9FFF8ED2EULL,
		0x8F947EB2EE6AB0BEULL,
		0x1BD81DBC0C3B127FULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE4EF6C64A8C7EBAAULL,
		0xD6DD67A6C68E1204ULL,
		0xEBBF4BD63C7690C2ULL,
		0x7B826CA200AC1CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08769EDCFFB9FFEULL,
		0xBF1AD55EB186DC4AULL,
		0x3DF5AA150D72C9D7ULL,
		0x6847417AE548472BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04680276D8CC4BACULL,
		0x17C29248150735BAULL,
		0xADC9A1C12F03C6EBULL,
		0x133B2B271B63D5BDULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x380631EC4A40E66AULL,
		0xD382020D0069A551ULL,
		0x6BFF11F2043103B6ULL,
		0x7F92CF31367E0C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D3E927F945F366CULL,
		0x820C6CEB02C75870ULL,
		0x0D95C0471F912CF8ULL,
		0x29FD3CCB392D0779ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAC79F6CB5E1AFFEULL,
		0x51759521FDA24CE0ULL,
		0x5E6951AAE49FD6BEULL,
		0x55959265FD510510ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x1F49D4D3DCF12300ULL,
		0xACCEE960F7032147ULL,
		0xE1B0E8571AEA7DA9ULL,
		0x0ED0C17249050DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA248967C7FDBECULL,
		0xEAC9F9815E2FDCF4ULL,
		0x5A5F348BB042A79CULL,
		0x69E7DABB2318BA25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A78C3D60714701ULL,
		0xC204EFDF98D34452ULL,
		0x8751B3CB6AA7D60CULL,
		0x24E8E6B725EC539FULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x27A473AF78DE2A21ULL,
		0xBE537F57C67FCBCAULL,
		0xC11DCA946420AA4FULL,
		0x183820B96473A1EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1670761A0B90D876ULL,
		0xA09FEA5EB2027006ULL,
		0x61301998902F19D1ULL,
		0x3E767B6E27AFCC1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1133FD956D4D5198ULL,
		0x1DB394F9147D5BC4ULL,
		0x5FEDB0FBD3F1907EULL,
		0x59C1A54B3CC3D5D4ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5D71025701087766ULL,
		0x3B083D21F2BDEAAEULL,
		0xC2C33E3A56C3A658ULL,
		0x16A358EC8B6D6E80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9E28E2E2D845FE8ULL,
		0x161CA511F16000ACULL,
		0x3490223A7AA75DC0ULL,
		0x57DDCE5F58123B64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA38E7428D384176BULL,
		0x24EB9810015DEA01ULL,
		0x8E331BFFDC1C4898ULL,
		0x3EC58A8D335B331CULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAA39264FD2963CABULL,
		0x45E7673AEBB7360EULL,
		0x1454D758CFB37920ULL,
		0x7148358AC9389D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E15B6D0D792B6D7ULL,
		0xB8398313F57C5250ULL,
		0x8524F1BE1BC3DFA7ULL,
		0x14CCB5226D95BDF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C236F7EFB0385D4ULL,
		0x8DADE426F63AE3BEULL,
		0x8F2FE59AB3EF9978ULL,
		0x5C7B80685BA2DF4AULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8B18C52F90E72276ULL,
		0x3AB8D6EAF04375DEULL,
		0xFA5A4162F1F70990ULL,
		0x49F12057FE7FAB33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD4E678AFCC610AULL,
		0x5404F1E1B44085F3ULL,
		0x15E8F10DA713116CULL,
		0x301D90E5A79A20A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E43DEB6E11AC16CULL,
		0xE6B3E5093C02EFEBULL,
		0xE47150554AE3F823ULL,
		0x19D38F7256E58A8BULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x4FF0B988297F1224ULL,
		0x63105B7345F802A9ULL,
		0x840FA820F0A607FBULL,
		0x57B455ECDE11CC82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E50C7AD452C4A6CULL,
		0x106D53929524E684ULL,
		0x635B2FDD0E322FDBULL,
		0x6A2BF85D1A997E1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE19FF1DAE452C7A5ULL,
		0x52A307E0B0D31C24ULL,
		0x20B47843E273D820ULL,
		0x6D885D8FC3784E63ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x339C94C7C74A356BULL,
		0xDB77A5902B6578DBULL,
		0x290BF9BE0FD1F744ULL,
		0x4A04D072636AE265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80CB1DC9F81EF2CBULL,
		0xC2A000FFC924FF90ULL,
		0x01955C0976044226ULL,
		0x62ED6AEF5678EE3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2D176FDCF2B428DULL,
		0x18D7A4906240794AULL,
		0x27769DB499CDB51EULL,
		0x671765830CF1F42AULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6E4AE3577C9D0D76ULL,
		0xE5C8B4677B249731ULL,
		0xFC6DCED71A7BDE09ULL,
		0x1758D88B6587F259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x485EAE2641B7A7F1ULL,
		0x092D0E5A468D3E7DULL,
		0xB6DC7C509E988457ULL,
		0x5D1C55FFD1D1910BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25EC35313AE56572ULL,
		0xDC9BA60D349758B4ULL,
		0x459152867BE359B2ULL,
		0x3A3C828B93B6614EULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x50D7414BE4390268ULL,
		0x7BDF9113F903C58CULL,
		0xE0EB06C73549BF3DULL,
		0x606C481E6C855A87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA57678E4CF257ED6ULL,
		0x31FB5399E55DEF10ULL,
		0xF3A151A5A8924E1FULL,
		0x06C8502CAAA5EEE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB60C86715138392ULL,
		0x49E43D7A13A5D67BULL,
		0xED49B5218CB7711EULL,
		0x59A3F7F1C1DF6B9DULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x0C1AC4D42492B3B0ULL,
		0x048510CFC5BFB122ULL,
		0x473CB67344993651ULL,
		0x39731ECA17CF8A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2CD46DD275AAD4ULL,
		0xC391A6B3CAE733E0ULL,
		0xAB3496BB2237C177ULL,
		0x3756FD2EFEE48DEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1EDF066521D08DCULL,
		0x40F36A1BFAD87D41ULL,
		0x9C081FB8226174D9ULL,
		0x021C219B18EAFCAFULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x99598496DB4C6654ULL,
		0x871CFE205C8767CCULL,
		0xB4D23005A13C8F76ULL,
		0x5A96AA512C771682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CA8860B850D1895ULL,
		0xDFE100078576FB8DULL,
		0x34264929B5C20EF1ULL,
		0x241D9EE1B849E285ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CB0FE8B563F4DBFULL,
		0xA73BFE18D7106C3FULL,
		0x80ABE6DBEB7A8084ULL,
		0x36790B6F742D33FDULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAF086153202086E5ULL,
		0x7F5B8BA43713E95AULL,
		0x5577337006BA3AD1ULL,
		0x405FA54CFB44BD10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4066A5AD4BE98473ULL,
		0xCCF94C70F2A2EE23ULL,
		0xA2EE096C05C173C6ULL,
		0x0AA29D3D43B73FC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EA1BBA5D4370272ULL,
		0xB2623F334470FB37ULL,
		0xB2892A0400F8C70AULL,
		0x35BD080FB78D7D4AULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5E123EAB420482CAULL,
		0x1215995F94AB6EECULL,
		0xC5F1939E2BF71D72ULL,
		0x0E217D51A5E4292AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC236593DB31366EULL,
		0x8C57C25962E4E8FBULL,
		0x91471007B9EC6317ULL,
		0x67267FDB73490C58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1EED91766D34C49ULL,
		0x85BDD70631C685F0ULL,
		0x34AA8396720ABA5AULL,
		0x26FAFD76329B1CD2ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x79351696A3876CF3ULL,
		0x57D458A5B5BAC1D3ULL,
		0xA766701E317C17BFULL,
		0x323F06DAC3DC8342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA784CE696941DAEAULL,
		0x1E7ED2FE72894B67ULL,
		0x0466E03AE4E0BFB8ULL,
		0x3C76A4B72A12B4B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1B0482D3A4591F6ULL,
		0x395585A74331766BULL,
		0xA2FF8FE34C9B5807ULL,
		0x75C8622399C9CE8AULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC3C71B5FD810894FULL,
		0xA0267D00FD3A4232ULL,
		0x80D3F1BF50307EAAULL,
		0x44B58693123B272FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6667331FAEE46AULL,
		0x993F027B0B2DF8E4ULL,
		0xAEC2127CC2FD5142ULL,
		0x5C4A05EF2B759486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF760B42CB861A4D2ULL,
		0x06E77A85F20C494DULL,
		0xD211DF428D332D68ULL,
		0x686B80A3E6C592A8ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5D52B94DD60DCE5EULL,
		0x382D1F24E68304C7ULL,
		0xE7B5E1A91DDE69D1ULL,
		0x1821ED35D5311B53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E219731A30F292ULL,
		0x3255F627A8727570ULL,
		0x9764D12BEBA70417ULL,
		0x0A24DB251197CFABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25709FDABBDCDBCCULL,
		0x05D728FD3E108F57ULL,
		0x5051107D323765BAULL,
		0x0DFD1210C3994BA8ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2A8DD7234176D277ULL,
		0x489F180608A92EFAULL,
		0xF85CE91A3159DFC5ULL,
		0x6288723E63A76B06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5DC383C4C1600C3ULL,
		0x88103E30EB64A473ULL,
		0xA3BDFF9616C894C1ULL,
		0x40AE1E929D4F5575ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84B19EE6F560D1B4ULL,
		0xC08ED9D51D448A86ULL,
		0x549EE9841A914B03ULL,
		0x21DA53ABC6581591ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x86571764879E6F4CULL,
		0xBC471E2807B4A499ULL,
		0x2771401B93C11160ULL,
		0x5891D90426FF7828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB48F83E04E1874FULL,
		0xEF43D6CAC91B40A2ULL,
		0x466240DD3D221684ULL,
		0x4BAC809576E64108ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB0E1F2682BCE7FDULL,
		0xCD03475D3E9963F6ULL,
		0xE10EFF3E569EFADBULL,
		0x0CE5586EB019371FULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x23ADF5B0EA566C9AULL,
		0xFEBE526B70038F50ULL,
		0x0506F07B18C7CFE1ULL,
		0x36987B97C783B740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD64434FEB09A59B2ULL,
		0x839302EC92608AC4ULL,
		0xF7D5E35436786DD1ULL,
		0x0B06E09ABE5BAD2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D69C0B239BC12E8ULL,
		0x7B2B4F7EDDA3048BULL,
		0x0D310D26E24F6210ULL,
		0x2B919AFD09280A14ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xBBCAB3522EF2653EULL,
		0xC403DC1907C1F825ULL,
		0x5ABE79481DE7A858ULL,
		0x2C0CE7A4EA1A6FB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E21FB185CEE38D1ULL,
		0x412B04493F09D94CULL,
		0x0B53354316C57DDEULL,
		0x49DBD8AA0661570CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DA8B839D2042C5AULL,
		0x82D8D7CFC8B81ED9ULL,
		0x4F6B440507222A7AULL,
		0x62310EFAE3B918A9ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xAAFB34B7B25B63EEULL,
		0x1CDBA72FD51704A4ULL,
		0x97E23092D54073F9ULL,
		0x18C0BEAE84B0F6B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x066C67348FCD4F2BULL,
		0x1CB2BFDF9D53C56AULL,
		0xFE35F742161EB663ULL,
		0x3072E2670F11C8A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA48ECD83228E14B0ULL,
		0x0028E75037C33F3AULL,
		0x99AC3950BF21BD96ULL,
		0x684DDC47759F2E0FULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x73A87E9E61FAB535ULL,
		0x0E8C68A466596422ULL,
		0x0D8742F5D1F08E81ULL,
		0x1A4C94AF50E31396ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF475992FF44F97E9ULL,
		0x7B2F8A72CCF8F680ULL,
		0xA0F9521D8849F51CULL,
		0x2BCBDA213B14BE12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F32E56E6DAB1D39ULL,
		0x935CDE3199606DA1ULL,
		0x6C8DF0D849A69964ULL,
		0x6E80BA8E15CE5583ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x932D9AC63FDCB47DULL,
		0xDA04817E98E97B8CULL,
		0xF1DB99825C63EB9EULL,
		0x60B130E1AFCBFBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D5C79E5569E1ABCULL,
		0x60DF5505ADB006A9ULL,
		0xD57FEFFBC8032EC3ULL,
		0x2742E645F60888ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45D120E0E93E99C1ULL,
		0x79252C78EB3974E3ULL,
		0x1C5BA9869460BCDBULL,
		0x396E4A9BB9C37311ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC8F4DB70445554A1ULL,
		0x2A747774912EA11BULL,
		0x5F2BE032F8D4E5E7ULL,
		0x760FDADA7B06D21BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x435FE7B4D7627DB2ULL,
		0xC3C22DD5CA5E813EULL,
		0xF03681B54C040552ULL,
		0x5CECAB0720D56D60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8594F3BB6CF2D6EFULL,
		0x66B2499EC6D01FDDULL,
		0x6EF55E7DACD0E094ULL,
		0x19232FD35A3164BAULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x0EF7480B1916E0A3ULL,
		0x57030AC92F72899EULL,
		0x21EFA3DB4FBAAF54ULL,
		0x025523C8B37A6E6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A0D0ECBB6E579BFULL,
		0xEE6F454E85BBD5C3ULL,
		0x67133B7A6A1067F1ULL,
		0x3AD09BD003379301ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4EA393F623166D1ULL,
		0x6893C57AA9B6B3DAULL,
		0xBADC6860E5AA4762ULL,
		0x478487F8B042DB68ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA59601FD8A17BAF1ULL,
		0x226898FE9D8DD7ACULL,
		0xDE8AA81A61B5ACDAULL,
		0x2633FB16A6DB713AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BBA3B03CF186C1ULL,
		0x5E89B98C9B98D8EBULL,
		0xAC6FAA69C8115A12ULL,
		0x417110369E3CF309ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0DA5E4D4D26341DULL,
		0xC3DEDF7201F4FEC0ULL,
		0x321AFDB099A452C7ULL,
		0x64C2EAE0089E7E31ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xBF4D053035E38EF9ULL,
		0x8E797EC0B5B0340BULL,
		0x1DF2B56902CFFF6BULL,
		0x42C28781CA7DB405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC6E384517144350ULL,
		0x3BF22F0B33184EC2ULL,
		0xA27E67F7567D3CB1ULL,
		0x0B9D3C1B01BA4FC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2DECCEB1ECF4BA9ULL,
		0x52874FB58297E548ULL,
		0x7B744D71AC52C2BAULL,
		0x37254B66C8C36441ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6EFF84A5B17A753EULL,
		0xA6326EB6C15BBFF9ULL,
		0xC5533E7035E9C01EULL,
		0x22DA072861716BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF37FB54422E628ULL,
		0x94E12FE3EA11D93EULL,
		0x6F525131A51761FFULL,
		0x6B45F5DE5C6771C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x920C04F06D578F03ULL,
		0x11513ED2D749E6BAULL,
		0x5600ED3E90D25E1FULL,
		0x3794114A0509FA1AULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x051A4BAEBFCC6E55ULL,
		0xCB7A13F483922B65ULL,
		0x6182637720B365FBULL,
		0x13557F89763D4ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE280F3E3D644320BULL,
		0xDF34FED0389EAC00ULL,
		0x5ED4E6C7DBA9F318ULL,
		0x1AA61C250D80E668ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x229957CAE9883C37ULL,
		0xEC4515244AF37F64ULL,
		0x02AD7CAF450972E2ULL,
		0x78AF636468BC6465ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6437A9DCF1FB9AFFULL,
		0xE063E4DB28A4A368ULL,
		0x01430F91C36550A9ULL,
		0x6C7E179B882266A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x165FC7232B253591ULL,
		0xDF0D2947B8CA493FULL,
		0x2769098B494A61BAULL,
		0x5124A56FFB957A5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DD7E2B9C6D6656EULL,
		0x0156BB936FDA5A29ULL,
		0xD9DA06067A1AEEEFULL,
		0x1B59722B8C8CEC48ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x7BD297040AE7CD9CULL,
		0xBD3ACD007CF1A7C1ULL,
		0xD715C3EF21B11ACEULL,
		0x3282645035C4DE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBEACB2CCC795A8EULL,
		0x64EC011D3947B2ECULL,
		0xCF828E0A14EADE75ULL,
		0x12AB974A83DD5AA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFE7CBD73E6E730EULL,
		0x584ECBE343A9F4D4ULL,
		0x079335E50CC63C59ULL,
		0x1FD6CD05B1E783D5ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x55771D4E232C4018ULL,
		0x2185938E7E5A7C87ULL,
		0x7264CFA0BF0340E2ULL,
		0x301AF58443985E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDDA0775BBFFF9B7ULL,
		0xB1634A0C53D12502ULL,
		0xAE2B204FA2E4B260ULL,
		0x12FF167CF451EF0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x979D15D8672C4661ULL,
		0x702249822A895784ULL,
		0xC439AF511C1E8E81ULL,
		0x1D1BDF074F466EFBULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6F717F1A660AA700ULL,
		0xF4EF139B577A20DEULL,
		0xEE6CE04A8AE81467ULL,
		0x02E0E0D16A6B8CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E68AA927D68FFAULL,
		0xF00D49403463BBA5ULL,
		0x6DA3F5B2506802DAULL,
		0x30BCDAF6DCA0C879ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x278AF4713E3416F3ULL,
		0x04E1CA5B23166539ULL,
		0x80C8EA983A80118DULL,
		0x522405DA8DCAC46FULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB961442346610315ULL,
		0xC152B8084FD2383BULL,
		0x1CA09C97C7DB2270ULL,
		0x7743CA7EFAA1EE94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE022EF300C5EE23ULL,
		0x4B544555440D5101ULL,
		0x73FAFBDC64E21621ULL,
		0x71807DDA20BF1CD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB5F1530459B14F2ULL,
		0x75FE72B30BC4E739ULL,
		0xA8A5A0BB62F90C4FULL,
		0x05C34CA4D9E2D1C2ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xEC51E72A2EDF60A9ULL,
		0x018D75DF297B309DULL,
		0x166A3A157CEFD1EBULL,
		0x2D62E3A095AE35C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A6D6B355A01A3C2ULL,
		0xB6A4EE3493F73366ULL,
		0x7F3A0C825D986DA3ULL,
		0x34620B39B872E335ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1E47BF4D4DDBCD4ULL,
		0x4AE887AA9583FD37ULL,
		0x97302D931F576447ULL,
		0x7900D866DD3B528EULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x26719F2841750192ULL,
		0xA720F34421F1212AULL,
		0x94E6E94CD74C03E9ULL,
		0x3445384B56D8C446ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B30F9E1FFD6A48ULL,
		0x82C1C08F1ED488D4ULL,
		0x922F00BE56F4DE44ULL,
		0x745202D9EC432D09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14BE8F8A21779737ULL,
		0x245F32B5031C9856ULL,
		0x02B7E88E805725A5ULL,
		0x3FF335716A95973DULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xEF4F4371F8DE7B81ULL,
		0x23DEE5D8BA82B7B6ULL,
		0x7BB16777D41C5186ULL,
		0x02F47C19A660C935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291E33AE6781859DULL,
		0x2E4C4D4213B74F4BULL,
		0x8636FFA288FDE937ULL,
		0x6FA9AE7AF2D3703DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6310FC3915CF5D1ULL,
		0xF5929896A6CB686BULL,
		0xF57A67D54B1E684EULL,
		0x134ACD9EB38D58F7ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x68A6F7540DCD06B8ULL,
		0xB3A97371CB205015ULL,
		0xF78D735B3B38E616ULL,
		0x7C09E2D30D654711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B2482ABF56D482ULL,
		0x45013CAF270497D4ULL,
		0x866B44061112ACDAULL,
		0x01E2A8C1A8B42734ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62F4AF294E763236ULL,
		0x6EA836C2A41BB841ULL,
		0x71222F552A26393CULL,
		0x7A273A1164B11FDDULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9399E3D6E7091798ULL,
		0xF4E5A34B2084B62BULL,
		0x3F171DC5320476B8ULL,
		0x39416797E8574836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8ABC4BEE5414534ULL,
		0x69BD4BAEE4DEF117ULL,
		0x45F4F8803FBFBAB6ULL,
		0x69F2155EB7ACE564ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAEE1F1801C7D251ULL,
		0x8B28579C3BA5C513ULL,
		0xF9222544F244BC02ULL,
		0x4F4F523930AA62D1ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD5C2FC76C897996EULL,
		0x163311D7E553F9D9ULL,
		0x35BBE66A7CBDA623ULL,
		0x004347443D41CFD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3223CC7B1E86B4B9ULL,
		0xBEDC57C5713B438DULL,
		0x1C5CB8ABBF8EE03AULL,
		0x6CEA6570BBB24023ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA39F2FFBAA10E4A2ULL,
		0x5756BA127418B64CULL,
		0x195F2DBEBD2EC5E8ULL,
		0x1358E1D3818F8FB4ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC13BF9EB13717C57ULL,
		0x1F157971BA3F430DULL,
		0xBEC00367230A1EC1ULL,
		0x3AC368A2900877C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD497BC7C68ABF07CULL,
		0x68F5B6A8B6B692A9ULL,
		0xCB53CE68EC5C94EAULL,
		0x1262A73701A2C26FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECA43D6EAAC58BDBULL,
		0xB61FC2C90388B063ULL,
		0xF36C34FE36AD89D6ULL,
		0x2860C16B8E65B557ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x935B75727F96BADBULL,
		0xFB8BC676647946D3ULL,
		0x7734D5C635F3E0EAULL,
		0x5A9929D1646764C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA461AC9635D892C3ULL,
		0xB966D5C48E1E8C9BULL,
		0x1B0D7E80566BDA55ULL,
		0x7700A5B4FA9A74E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEF9C8DC49BE2805ULL,
		0x4224F0B1D65ABA37ULL,
		0x5C275745DF880695ULL,
		0x6398841C69CCEFE8ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x49C93F549BF32F83ULL,
		0x50B6C1FA0A7E6671ULL,
		0x047821E6851133CAULL,
		0x1511B0836D778FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x995FF21B1EB7D550ULL,
		0x88DD6A7CE37ED04DULL,
		0x111170E86B4FA42BULL,
		0x77899AF4CE6E86CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0694D397D3B5A20ULL,
		0xC7D9577D26FF9623ULL,
		0xF366B0FE19C18F9EULL,
		0x1D88158E9F090903ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xF7DDD8D17A48C467ULL,
		0x933E94A264568BF2ULL,
		0x510A5E55D62A12E8ULL,
		0x7690395691CB5964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5483D48EE9DEEC9ULL,
		0x641692E6FBEB8D47ULL,
		0xFF53D8B718C6837EULL,
		0x0436EF421159FC23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22959B888BAAD59EULL,
		0x2F2801BB686AFEABULL,
		0x51B6859EBD638F6AULL,
		0x72594A1480715D40ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xCD9BFEBB11B64C19ULL,
		0xC24A96DE84D9DC0BULL,
		0x921DF530DD2712E8ULL,
		0x4FE69D1BF17F1B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9747C67E188C672FULL,
		0xC8BF785434135B39ULL,
		0x02AAD942739F0274ULL,
		0x74BFC4A5D92CDAC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3654383CF929E4D7ULL,
		0xF98B1E8A50C680D2ULL,
		0x8F731BEE69881073ULL,
		0x5B26D87618524052ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE3A02E74EEF91720ULL,
		0x7AC8803981A90B6CULL,
		0x97383640DEE06E1CULL,
		0x7E44EE6581DBD620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7683B4A956EF04BFULL,
		0xDA195294EF803AC0ULL,
		0x03FE059B1A9C4CDBULL,
		0x51A3169335970252ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D1C79CB980A1261ULL,
		0xA0AF2DA49228D0ACULL,
		0x933A30A5C4442140ULL,
		0x2CA1D7D24C44D3CEULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x70DDF6D14C9D75D3ULL,
		0xF8E068DCAFBBCFAEULL,
		0x22985173E14ED573ULL,
		0x11F785B9A7F3D9FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8524A092C6277D8ULL,
		0x9E96AC0F026862BBULL,
		0x69F603BF9D6E1871ULL,
		0x3FA008522A30B7DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x788BACC8203AFDE8ULL,
		0x5A49BCCDAD536CF2ULL,
		0xB8A24DB443E0BD02ULL,
		0x52577D677DC32220ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC6A2421F5182D8CCULL,
		0xCFB4C1971B5F9BB5ULL,
		0x246E3ECE49B3FA29ULL,
		0x5706C508746D9C05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC16E3A8442303AE6ULL,
		0xB3DF0971D04D158EULL,
		0x086FB03917D9DB63ULL,
		0x2F347C9E7F5D0518ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0534079B0F529DE6ULL,
		0x1BD5B8254B128627ULL,
		0x1BFE8E9531DA1EC6ULL,
		0x27D24869F51096EDULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB24E1C42E7AC1CFCULL,
		0x90517438352C48CFULL,
		0x1F3FA3BACF450478ULL,
		0x0CF237C219C9DE05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE41D7D3053F6A46ULL,
		0x62D435E77A48DDC8ULL,
		0x037F8EA65307E79DULL,
		0x27525FD80D4C613AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE40C446FE26CB2A3ULL,
		0x2D7D3E50BAE36B06ULL,
		0x1BC015147C3D1CDBULL,
		0x659FD7EA0C7D7CCBULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD68059BF318EFE4FULL,
		0x0548FAE5A320ED93ULL,
		0xD225D6D0B1110D61ULL,
		0x63BDC7BED4FC9CC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3272514DEA15017CULL,
		0x172BECB4864727BDULL,
		0x13A76803183827ECULL,
		0x1CB29F3851099347ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA40E08714779FCD3ULL,
		0xEE1D0E311CD9C5D6ULL,
		0xBE7E6ECD98D8E574ULL,
		0x470B288683F30982ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x06981539BA0AFF09ULL,
		0x1F5C221E6D84075CULL,
		0x90B779D25B6DD42FULL,
		0x72BCB7E339055D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98E9AF12B0176257ULL,
		0xBB0C267200DB92B5ULL,
		0x677958A5631BB14DULL,
		0x2E9AA435EC05B213ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DAE662709F39CB2ULL,
		0x644FFBAC6CA874A6ULL,
		0x293E212CF85222E1ULL,
		0x442213AD4CFFAAF0ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x976DBD3107E4A281ULL,
		0xC4402B95DFF51800ULL,
		0xC2866695480E168FULL,
		0x7E478AD10610307AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F8E9DE91F51E14ULL,
		0x8ABBA64FE40CB03DULL,
		0x9BD81026624B0B36ULL,
		0x170D2BD4E9462037ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5574D35275EF846DULL,
		0x39848545FBE867C3ULL,
		0x26AE566EE5C30B59ULL,
		0x673A5EFC1CCA1043ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC26193D61F0027B8ULL,
		0x6B1A94380416DB14ULL,
		0xD2F04B653AD9B4A5ULL,
		0x53E0A21C256D2743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792296C9FE42EB1DULL,
		0x13291BFB59DE4D40ULL,
		0x41EF5F0C4178F69BULL,
		0x430E634F62C3A16DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x493EFD0C20BD3C9BULL,
		0x57F1783CAA388DD4ULL,
		0x9100EC58F960BE0AULL,
		0x10D23ECCC2A985D6ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC3394EB6757BDDBDULL,
		0x6FE4AC5435F6BDD2ULL,
		0xD0E62D24DCE48373ULL,
		0x5CFA9FB2F0AB4B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BC0DBFADC737A9ULL,
		0xF752B6244759E998ULL,
		0x836051BF396E7607ULL,
		0x4D08A17C23CBB1F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B7D40F6C7B4A614ULL,
		0x7891F62FEE9CD43AULL,
		0x4D85DB65A3760D6BULL,
		0x0FF1FE36CCDF9970ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA920A3F4D2D42D1FULL,
		0x7FE2ACFAE83A505AULL,
		0xDEF0E8F15645F45FULL,
		0x776F5457AF2ACDA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28A22F5B9C4ED41BULL,
		0x0A874A088330624EULL,
		0xD3B61F8EC869FDBAULL,
		0x74802E0108E4AB7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x807E749936855904ULL,
		0x755B62F26509EE0CULL,
		0x0B3AC9628DDBF6A5ULL,
		0x02EF2656A6462226ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x94C8455DFE174DF9ULL,
		0xABF9F793B2BF2250ULL,
		0xF15383AECF5468B7ULL,
		0x2055A11986E8C960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE18E4CB1982B60EULL,
		0x82C88B0D6309D1E6ULL,
		0x31F7C6BB370CCAF8ULL,
		0x1C43DA307C002AC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6AF6092E49497EBULL,
		0x29316C864FB55069ULL,
		0xBF5BBCF398479DBFULL,
		0x0411C6E90AE89E98ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5C6D52E765153377ULL,
		0xBA2FD9CF13B76845ULL,
		0x5C6B5BB66302C0C5ULL,
		0x69D71FB03D53B05AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1C4FDC587408817ULL,
		0x3E9DA0BC484E35D9ULL,
		0x4AB3D82654E79897ULL,
		0x252F4D73ED6E37AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AA85521DDD4AB60ULL,
		0x7B923912CB69326BULL,
		0x11B783900E1B282EULL,
		0x44A7D23C4FE578ABULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x1AC32E4D37A1F33CULL,
		0x363292EB2A7DCA6BULL,
		0x6B98B6184BA2C3D3ULL,
		0x1E558A7426E96BC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EDC3C8F0071337CULL,
		0xB6E8F933FED1AA42ULL,
		0xD9DC9C9DFEB8D0A4ULL,
		0x5440A2D4CDEE283CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BE6F1BE3730BFADULL,
		0x7F4999B72BAC2029ULL,
		0x91BC197A4CE9F32EULL,
		0x4A14E79F58FB4389ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x23A65936FBB32A16ULL,
		0xDB60142A1C997BA5ULL,
		0xBF8F41CE3EA0790FULL,
		0x5DF3645F2E881734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12D0C8298033E12ULL,
		0xEC3A0A8F553CC425ULL,
		0xA706F1B6009CE8CAULL,
		0x7AAE239706425ECCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52794CB463AFEBF1ULL,
		0xEF26099AC75CB77FULL,
		0x188850183E039044ULL,
		0x634540C82845B868ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x060F2DBE7DDABC93ULL,
		0xA9F6F893236E051DULL,
		0xE3E43D75EB06AB21ULL,
		0x72B7122C4C603115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C18D086B2E8D0FDULL,
		0x54EEF1849D4C6357ULL,
		0xD223A95EBE5DA670ULL,
		0x1EC66E633859F4B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9F65D37CAF1EB96ULL,
		0x5508070E8621A1C5ULL,
		0x11C094172CA904B1ULL,
		0x53F0A3C914063C65ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x410B19E66C373266ULL,
		0xE26A1E436CAE4D93ULL,
		0x603B1619EB2CC0AEULL,
		0x2628F81E1374D36EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6CAD2EA3B595CE6ULL,
		0xF3A83F647CEC78E3ULL,
		0x4AA73D235DFB23FBULL,
		0x1145F3772B38A884ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A4046FC30DDD580ULL,
		0xEEC1DEDEEFC1D4AFULL,
		0x1593D8F68D319CB2ULL,
		0x14E304A6E83C2AEAULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xEDB49029AD53CCE3ULL,
		0x1AEFC09DE4EF38BEULL,
		0x8D5B77F358D2CA79ULL,
		0x432ABBC295588743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA90139B5E239C3CBULL,
		0xC74C505145B72BBDULL,
		0x4C2031A207CD1A37ULL,
		0x40D6017A9BE131F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44B35673CB1A0918ULL,
		0x53A3704C9F380D01ULL,
		0x413B46515105B041ULL,
		0x0254BA47F977554FULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5A661AFE73A97E7AULL,
		0x1D17EE674B3C0328ULL,
		0x836937B386C043D4ULL,
		0x2A262195A96D38D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F126969D700058ULL,
		0x50F695E1221FAEE2ULL,
		0x092F06FB8DCCF5ECULL,
		0x62DA745055856B2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7174F467D6397E0FULL,
		0xCC215886291C5445ULL,
		0x7A3A30B7F8F34DE7ULL,
		0x474BAD4553E7CDA5ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xF88AD8A30E749109ULL,
		0x8A8DA2522A49935AULL,
		0x2830C30DD47A3198ULL,
		0x57A56A06367F12C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B84C8E00B6A919ULL,
		0x28127212463564F6ULL,
		0xC3DA5B7562912CE3ULL,
		0x14C5DC3E08F52DB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ED28C150DBDE7F0ULL,
		0x627B303FE4142E64ULL,
		0x6456679871E904B5ULL,
		0x42DF8DC82D89E50DULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xDB9E5845DAD26A25ULL,
		0x959D228869382621ULL,
		0x14D54107DD4B0011ULL,
		0x2912710EB3161188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8EA373E5E35A8BDULL,
		0xF1D716F6EB0CBA51ULL,
		0x341B010FCFADF3B3ULL,
		0x1E370A493A634BD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2B421077C9CC168ULL,
		0xA3C60B917E2B6BCFULL,
		0xE0BA3FF80D9D0C5DULL,
		0x0ADB66C578B2C5B2ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5F86EB80F8BDF2F8ULL,
		0x4B9AEF3B03F17440ULL,
		0xBE97E795C521D5E8ULL,
		0x753FF3F61B9D2BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0985139D55761159ULL,
		0x8388C78979C41343ULL,
		0xFAFD0C5EF95DB843ULL,
		0x1564424D564A230DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5601D7E3A347E19FULL,
		0xC81227B18A2D60FDULL,
		0xC39ADB36CBC41DA4ULL,
		0x5FDBB1A8C55308ACULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x69208E391F41BA0DULL,
		0x28C795FB35C86C78ULL,
		0x3504F6875343790CULL,
		0x6078919DA01F11FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43BE76E32833D1D1ULL,
		0x6D27471953F633B4ULL,
		0xA500F498D13880FDULL,
		0x173D5ADB31775062ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25621755F70DE83CULL,
		0xBBA04EE1E1D238C4ULL,
		0x900401EE820AF80EULL,
		0x493B36C26EA7C19CULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE8371319CBC86104ULL,
		0x384AF893A1E4D6A9ULL,
		0x77B856608E3F05BCULL,
		0x29D6A44B0B514DD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B82DC371CCC0B4FULL,
		0x50C043D800478953ULL,
		0xFCA9F5E05535F06DULL,
		0x4D479CC425B2BEDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCB436E2AEFC55A2ULL,
		0xE78AB4BBA19D4D56ULL,
		0x7B0E60803909154EULL,
		0x5C8F0786E59E8EFCULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x17A3980D24FFB470ULL,
		0x88ED42F322E34427ULL,
		0xEBDB7A37842B7F16ULL,
		0x0727E75539F95F77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C6B29D025A1381ULL,
		0x4F43A13F0CD2C4FAULL,
		0x7A8FF3BEA70AB8D9ULL,
		0x11269072837C6965ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEDCE57022A5A0DCULL,
		0x39A9A1B416107F2CULL,
		0x714B8678DD20C63DULL,
		0x760156E2B67CF612ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xF09354593D5EC985ULL,
		0x042807EEFDEC4CFDULL,
		0x8A7D25A4A732BA36ULL,
		0x2AD95455B31EF9D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C42EB5DC6B8F8BULL,
		0x8583582080688C85ULL,
		0x60F879307D03F678ULL,
		0x107B26C54B9ADDE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ACF25A360F339FAULL,
		0x7EA4AFCE7D83C078ULL,
		0x2984AC742A2EC3BDULL,
		0x1A5E2D9067841BF2ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2FA96BEA770DA285ULL,
		0x7FD11F9E0F559F8BULL,
		0xFE584D48837B60FEULL,
		0x28DABCDE4BE8F9FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C656C467CBB4D6ULL,
		0x1F34F726096474FFULL,
		0x8D853C6FE7EDF9A4ULL,
		0x0119AB9FC095D3D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCE315260F41EDAFULL,
		0x609C287805F12A8BULL,
		0x70D310D89B8D675AULL,
		0x27C1113E8B532629ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC4C4B20CED627231ULL,
		0x4B67377FAD75057CULL,
		0x3933CC48D3EB25AFULL,
		0x753A5EB5F862F90BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49CA735930CDB965ULL,
		0xA47D211FA98C98AAULL,
		0x61AF86753ECBF367ULL,
		0x6436AB482CAAB08FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AFA3EB3BC94B8CCULL,
		0xA6EA166003E86CD2ULL,
		0xD78445D3951F3247ULL,
		0x1103B36DCBB8487BULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x4AEC4DDB3BBDF8C4ULL,
		0x38AFF2926E4EFD79ULL,
		0x72F4852065269DC0ULL,
		0x30B4A903D50095E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BD6AAE2BF583195ULL,
		0x6673B4E60F713B3FULL,
		0x2701BA1CBEB7F93CULL,
		0x3A24366B4701A955ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF15A2F87C65C71CULL,
		0xD23C3DAC5EDDC239ULL,
		0x4BF2CB03A66EA483ULL,
		0x769072988DFEEC90ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x971DF73AD3510F4FULL,
		0xA5BC8CAB6CDA049DULL,
		0x7B50128565D16B4EULL,
		0x55E8C284D55E7A8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE02FB102BBDE75ULL,
		0xA3882DD90BF028F3ULL,
		0x594089C9EE0CBCA5ULL,
		0x513888F1544FCAFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x373DC789D09530DAULL,
		0x02345ED260E9DBAAULL,
		0x220F88BB77C4AEA9ULL,
		0x04B03993810EAF90ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9BEE1D7603067B4DULL,
		0xA142C3DACB5D3743ULL,
		0xBFCE6DB3794899C5ULL,
		0x1EA506D7FE9B121BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8B30B26D11CC33CULL,
		0xED3550F4AA2526C2ULL,
		0x1B59CE424ADF87FCULL,
		0x16715E42672A44E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC33B124F31E9B811ULL,
		0xB40D72E621381080ULL,
		0xA4749F712E6911C8ULL,
		0x0833A8959770CD39ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6D01654899754862ULL,
		0x4C65C69D13D619CDULL,
		0x1651A84E828DA6A3ULL,
		0x1DEFF8CA7D211B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E6871DCD0E9F162ULL,
		0xC5756F9C73AF7582ULL,
		0xA864B6CDFBF16BDEULL,
		0x51D408DD3C1B1505ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE98F36BC88B56EDULL,
		0x86F05700A026A44AULL,
		0x6DECF180869C3AC4ULL,
		0x4C1BEFED4106066FULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xBD4C1C71CDDC1A36ULL,
		0xEA33186DC5E31E73ULL,
		0x7B096848628E9F98ULL,
		0x07139E823A929867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD8667506F4B6BEULL,
		0xCF266502405A0174ULL,
		0x915BE0FFD661FEFCULL,
		0x791B6E3A9881FFE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4273B5FCC6E76365ULL,
		0x1B0CB36B85891CFFULL,
		0xE9AD87488C2CA09CULL,
		0x0DF83047A2109886ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3432F98C32DFA7B2ULL,
		0xC878B029C6CE8EECULL,
		0xD3AA3CF3E08957A3ULL,
		0x5B4B65656F5E6E05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4AA426397EA36C4ULL,
		0x074AD3438A4B85DDULL,
		0xA42FECBE8A5551CBULL,
		0x59AA5F5B67293ECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F88B7289AF570EEULL,
		0xC12DDCE63C83090EULL,
		0x2F7A5035563405D8ULL,
		0x01A1060A08352F38ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x91523F9E8CC06DC3ULL,
		0xF33028A56C97A98EULL,
		0x195E0EF240671F70ULL,
		0x4766EB90C9B60661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CEE101E0518B9E0ULL,
		0x52FB4D6B362A7679ULL,
		0x0CB17050354CE7C0ULL,
		0x24A4A4748F7036FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74642F8087A7B3E3ULL,
		0xA034DB3A366D3315ULL,
		0x0CAC9EA20B1A37B0ULL,
		0x22C2471C3A45CF67ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8D96B0698B8A5630ULL,
		0x9377169F9B9AB978ULL,
		0xA7CC25ED8781DE2AULL,
		0x5E1CC6C52EB084B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90F2C2AA7B626604ULL,
		0x405F1EB28B4A3F61ULL,
		0xD36BAC62CC3424E6ULL,
		0x56B87D25DFEF1DCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCA3EDBF1027F02CULL,
		0x5317F7ED10507A16ULL,
		0xD460798ABB4DB944ULL,
		0x0764499F4EC166E2ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5C45DF2845F1E262ULL,
		0x44E8EAE5232EB695ULL,
		0x334D8771C7D0E140ULL,
		0x1A63A06EE8DC5786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3420F3370665592BULL,
		0x3DDD628D415CA15AULL,
		0x0BFFC45C9E72CD71ULL,
		0x02E5A485A31FF0E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2824EBF13F8C8937ULL,
		0x070B8857E1D2153BULL,
		0x274DC315295E13CFULL,
		0x177DFBE945BC66A2ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x64A94EE2BCAF2DE0ULL,
		0xE0AE17A696B34593ULL,
		0xAB09CADCA93F2F27ULL,
		0x4FF1C1F148837F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB7EDAE493977C2ULL,
		0x12623ED15C65D88BULL,
		0x54CDB39BA4BCB5E7ULL,
		0x0FC54F7BCF69E239ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7F161347375B61EULL,
		0xCE4BD8D53A4D6D07ULL,
		0x563C174104827940ULL,
		0x402C727579199D49ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE0C70A7DD4A991BAULL,
		0xAF2ADDB478FE2595ULL,
		0xC5D186E06AE98794ULL,
		0x0D14EE6E11468F29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1716151B95316500ULL,
		0xB6C80DC2757933BAULL,
		0x7FC6CC0CC58F0EBEULL,
		0x741B90E89CB3D324ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9B0F5623F782CA7ULL,
		0xF862CFF20384F1DBULL,
		0x460ABAD3A55A78D5ULL,
		0x18F95D857492BC05ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x53A81BC74E4A987BULL,
		0x6C65075B99352519ULL,
		0x72828D4598C0EB56ULL,
		0x6FA620055B96AAB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8005A603C5985B03ULL,
		0xC9D5D424D140F34EULL,
		0x1972088C7E1B30B6ULL,
		0x411963E71616E080ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3A275C388B23D78ULL,
		0xA28F3336C7F431CAULL,
		0x591084B91AA5BA9FULL,
		0x2E8CBC1E457FCA39ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5A9AD8EA3E8A95BEULL,
		0xD7C11A2D6D5D7609ULL,
		0x33D2AB48EBD3E7FAULL,
		0x2312742F7FF60A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA28951FE9ABFC83ULL,
		0x8B0562925D8A1703ULL,
		0xB778B123F427E987ULL,
		0x00D24AD8AE0946D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x807243CA54DE993BULL,
		0x4CBBB79B0FD35F05ULL,
		0x7C59FA24F7ABFE73ULL,
		0x22402956D1ECC398ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x41F811ADDF373179ULL,
		0xB17F5BA62540B0FBULL,
		0x3465FAFB40283FD4ULL,
		0x68E7D04562059CC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x355ED314CC97EE82ULL,
		0x45B8F32D0DA36DC6ULL,
		0xE76455722954C256ULL,
		0x148196A33446BF05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C993E99129F42F7ULL,
		0x6BC66879179D4335ULL,
		0x4D01A58916D37D7EULL,
		0x546639A22DBEDDBFULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xDBEF1B6FA80BC007ULL,
		0x0AC7318D9590F29CULL,
		0x1E82B10C01E9C4F9ULL,
		0x38EB524F19BC82F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9C8A851BA48FEEULL,
		0x23ABFCB482A256C5ULL,
		0x3DB4AB297A96A66AULL,
		0x2629AD1ABE3218D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x305290EA8C673019ULL,
		0xE71B34D912EE9BD7ULL,
		0xE0CE05E287531E8EULL,
		0x12C1A5345B8A6A1BULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x80210E16C31D5A8DULL,
		0x224435A48D824FDDULL,
		0x57C60EE821A8E0A4ULL,
		0x2E46645C6C308937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB91815B5810D8C7ULL,
		0xDF8D459692C49166ULL,
		0x095E212C3B7618A1ULL,
		0x2C7ADC2E4127FA3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC48F8CBB6B0C81C6ULL,
		0x42B6F00DFABDBE76ULL,
		0x4E67EDBBE632C802ULL,
		0x01CB882E2B088EFAULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x802C3CC0E84FB645ULL,
		0x4F0844D5EACB9616ULL,
		0xFDE3C6DE9A4F0D3BULL,
		0x7D717C3DEEB24BCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15AE77891B493E4DULL,
		0x17EF4FAD59506B5CULL,
		0x5A0F6D431282B75FULL,
		0x0B6FC2AA105CE3EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A7DC537CD0677F8ULL,
		0x3718F528917B2ABAULL,
		0xA3D4599B87CC55DCULL,
		0x7201B993DE5567E1ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x12F77ACBCB70F5DAULL,
		0xAFCE999B4168FC69ULL,
		0x700CF81A743A4570ULL,
		0x060C30E3E08F2C48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x471309316E073AE2ULL,
		0x61319C58ACD029D4ULL,
		0xD95C0A7EE6988B9DULL,
		0x76B0B07B9961AED9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBE4719A5D69BAE5ULL,
		0x4E9CFD429498D294ULL,
		0x96B0ED9B8DA1B9D3ULL,
		0x0F5B8068472D7D6EULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB6CEFD0E961F9902ULL,
		0xC1F5EF26B0D73C9FULL,
		0x0B099DFF8B9A37DEULL,
		0x39732959942F4803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x156C4FCEDA688189ULL,
		0x9568728B5AC673C7ULL,
		0x283A0FDF71004BEBULL,
		0x1CEDC06344F7E53DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA162AD3FBBB71779ULL,
		0x2C8D7C9B5610C8D8ULL,
		0xE2CF8E201A99EBF3ULL,
		0x1C8568F64F3762C5ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x0A2C92037B9D8F20ULL,
		0x0A5A853E52411E13ULL,
		0x097E2E0C2D749471ULL,
		0x72AECD652591E921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E1C6B8C426A86CULL,
		0x1BD8A2D6B3C19C9FULL,
		0x1BA52808B40D5178ULL,
		0x16A77B0F34FB5220ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x704ACB4AB776E6B4ULL,
		0xEE81E2679E7F8173ULL,
		0xEDD90603796742F8ULL,
		0x5C075255F0969700ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8B8481386B32A91FULL,
		0x8E4DF2FFFCC691DFULL,
		0x1BDCABF33621AAC5ULL,
		0x61A558256541BD36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA61E333258C2001ULL,
		0x1E38962B6BC62C09ULL,
		0x64EB0A4279174813ULL,
		0x7B0094CFFD1A320CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1229E0545A6890BULL,
		0x70155CD4910065D5ULL,
		0xB6F1A1B0BD0A62B2ULL,
		0x66A4C35568278B29ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x106DE45EEC3661AFULL,
		0x94E9D08F5B2257DDULL,
		0x5DFFE354F2526437ULL,
		0x634AFA55A9F418B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11DF5FE229D6BD5BULL,
		0x50CB3677A6728183ULL,
		0x41D5FCEEDBFBBD19ULL,
		0x21AABBBFA098921AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE8E847CC25FA454ULL,
		0x441E9A17B4AFD659ULL,
		0x1C29E6661656A71EULL,
		0x41A03E96095B8696ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x63C87D31184E976FULL,
		0xCA01B48217F82FCAULL,
		0x0E83285ABCA59124ULL,
		0x4AF0A3BFE9E15421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FC11D5DE62AADCULL,
		0x9118A6D3F548A3BBULL,
		0x76FB131E8E87DC34ULL,
		0x1A29A0B7564EDEF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50CC6B5B39EBEC93ULL,
		0x38E90DAE22AF8C0FULL,
		0x9788153C2E1DB4F0ULL,
		0x30C7030893927527ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x61665E2E1FE41EB7ULL,
		0x5E8D582AAE4B050CULL,
		0x32F1F28420A805FDULL,
		0x0FDC23BC877B08B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A540C5266EEF47FULL,
		0x7E06007E39C16F30ULL,
		0x5EFA361FB92C210DULL,
		0x42E1B619526980CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x571251DBB8F52A25ULL,
		0xE08757AC748995DCULL,
		0xD3F7BC64677BE4EFULL,
		0x4CFA6DA3351187E8ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC15A3CCFDD0318E9ULL,
		0x7C036A84BD2775B0ULL,
		0xD608775F43544966ULL,
		0x604EB1C48202584EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807B1C1DFBB9DAF9ULL,
		0x2A88A8A2B9E77C1FULL,
		0xD5CAB2BCC43D996DULL,
		0x59356A24FAF9342CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40DF20B1E1493DF0ULL,
		0x517AC1E2033FF991ULL,
		0x003DC4A27F16AFF9ULL,
		0x0719479F87092422ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE512A684C2E89E68ULL,
		0x996B9F339DD78762ULL,
		0x190E2EDC11E49502ULL,
		0x10B9CC3EEA5CF784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F788FB7B5A9E5F5ULL,
		0xBA52FC8E251B4A2AULL,
		0xFEFE820F4969C5A3ULL,
		0x5EE0C5736F926B62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD59A16CD0D3EB860ULL,
		0xDF18A2A578BC3D38ULL,
		0x1A0FACCCC87ACF5EULL,
		0x31D906CB7ACA8C21ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x93C563DE51E2A209ULL,
		0x880E5DB30923211EULL,
		0x967C78878B598F5CULL,
		0x31999B40C4A74CBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD6D0EECCDC9B4BULL,
		0x9ECE7C9AAD27DD74ULL,
		0x647218E7CEE62B47ULL,
		0x5B6CD633041FC474ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6EE92EF850606ABULL,
		0xE93FE1185BFB43A9ULL,
		0x320A5F9FBC736414ULL,
		0x562CC50DC0878849ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x626DA7D8A64658BEULL,
		0xB8826CE6CAD48A3CULL,
		0xE53972B5B0328F14ULL,
		0x1D85A0FD7EF9B0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC5FE8BF89B6FE36ULL,
		0xD454A614D8DD4945ULL,
		0xDF5F18DCEDFF1279ULL,
		0x037C7A1ED2F4A1A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB60DBF191C8F5A88ULL,
		0xE42DC6D1F1F740F6ULL,
		0x05DA59D8C2337C9AULL,
		0x1A0926DEAC050F20ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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