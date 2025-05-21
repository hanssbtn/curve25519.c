#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xFB4B03AEEB070EF2ULL,
		0x78F0077288657B6CULL,
		0xC725B8B66FFF425AULL,
		0x3BF52AC4EC86168CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0387D88CE3F5664AULL,
		0x1D12F42EC4BFD717ULL,
		0x3A12F5D3A9BB09A6ULL,
		0x28138BF6563232B1ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xF7C32B220711A8A8ULL,
		0x5BDD1343C3A5A455ULL,
		0x8D12C2E2C64438B4ULL,
		0x13E19ECE9653E3DBULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD78750718C38BD57ULL,
		0x0E0E657FF76899A8ULL,
		0x17F21156128866FCULL,
		0x00B0CBC90EB454BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47596442205BDCCFULL,
		0xE12DEAFCA35D95C2ULL,
		0xA36EAB0C2ED1DF06ULL,
		0x04768142DA30C203ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902DEC2F6BDCE075ULL,
		0x2CE07A83540B03E6ULL,
		0x74836649E3B687F5ULL,
		0x7C3A4A86348392B6ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05CBE0CC3C45FCC6ULL,
		0x5C5D3847719F1B1CULL,
		0xFD37D4FAA2C8F8ABULL,
		0x73E9E024181B3CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x765351F9CF3DE7D8ULL,
		0x90AFC967CC5FDF3AULL,
		0xD835A278C7EBB2DFULL,
		0x72E5DA15437588C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F788ED26D0814EEULL,
		0xCBAD6EDFA53F3BE1ULL,
		0x25023281DADD45CBULL,
		0x0104060ED4A5B438ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FF321E971CF702FULL,
		0x699DD5DBDD48370EULL,
		0x0F0A8975ED920303ULL,
		0x59D3D3B0F646BC8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543968B8AF77015CULL,
		0x0E69ACBBF84E2433ULL,
		0x360D74F1BB8A7B70ULL,
		0x19967B855B2900E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBB9B930C2586ED3ULL,
		0x5B34291FE4FA12DAULL,
		0xD8FD148432078793ULL,
		0x403D582B9B1DBBA9ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ACA1E2651FBD4A6ULL,
		0x8BE470E08D48D82BULL,
		0x78B3DC71ED454450ULL,
		0x20FAA44C9CA748B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x907D7B2774AC01D3ULL,
		0x03A820FFC9384A19ULL,
		0xE12F2FEF8641B8ADULL,
		0x7CDB0A2A16F888BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A4CA2FEDD4FD2C0ULL,
		0x883C4FE0C4108E11ULL,
		0x9784AC8267038BA3ULL,
		0x241F9A2285AEBFF2ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C7E02F0BB7367BFULL,
		0x9EAF4FBD90E9F9D7ULL,
		0x0E271508AE93A40EULL,
		0x32670757E1A8B376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CF3846A28645536ULL,
		0x2B13F41C270DE460ULL,
		0x3742EAACE56542EAULL,
		0x00FD2A67C0ABEB8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F8A7E86930F1289ULL,
		0x739B5BA169DC1577ULL,
		0xD6E42A5BC92E6124ULL,
		0x3169DCF020FCC7EAULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6D852662D99B8E7ULL,
		0xBFD9C5063D062CBBULL,
		0x3628EA5BE05C98B4ULL,
		0x46A1F1E54C10AF5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD23970754742F0BULL,
		0x8DCB0589A27BB144ULL,
		0x9653F7BB91F266E9ULL,
		0x614DA187B379C571ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9B4BB5ED92589C9ULL,
		0x320EBF7C9A8A7B76ULL,
		0x9FD4F2A04E6A31CBULL,
		0x6554505D9896E9E8ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x948FAEE3FF901052ULL,
		0x4F2F6AEEA9E75E77ULL,
		0xFF14EA193B96A250ULL,
		0x6F6216D8DB16C239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF180C73862A074B8ULL,
		0x0238043B7B3C9CCCULL,
		0xE5B9903CD881D8B8ULL,
		0x298C0441C8A93EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA30EE7AB9CEF9B9AULL,
		0x4CF766B32EAAC1AAULL,
		0x195B59DC6314C998ULL,
		0x45D61297126D8385ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AC7C32C82FFDF02ULL,
		0x09F57C2F2D3E31F1ULL,
		0xD8D8AD4B12D0203CULL,
		0x484A650891681056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA01F364E15EB69ULL,
		0x42A3AA2CA2F7EA41ULL,
		0x7FDEA3C9F68D765AULL,
		0x3EF41A4388030E1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF027A3F634E9F399ULL,
		0xC751D2028A4647AFULL,
		0x58FA09811C42A9E1ULL,
		0x09564AC50965023CULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x439D250F60F1F328ULL,
		0x3B7AF60203172CC1ULL,
		0x9422840176E37008ULL,
		0x31C778161366519FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87F97AE67B608315ULL,
		0x10B1A491E0A8AC4FULL,
		0x21821A279F50EC3EULL,
		0x3ECE0BD31104E6C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBA3AA28E5917000ULL,
		0x2AC95170226E8071ULL,
		0x72A069D9D79283CAULL,
		0x72F96C4302616ADAULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD3714A0871B9C05ULL,
		0x9DFA5B451C530330ULL,
		0x554D2E26B38A815BULL,
		0x2F9CFAACD491050AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF1479DCDB5585CEULL,
		0xEACED7DF19AAC85FULL,
		0x9DA7C0BABB914B7BULL,
		0x53A4475EE2CBC8BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE229AC3ABC61624ULL,
		0xB32B836602A83AD0ULL,
		0xB7A56D6BF7F935DFULL,
		0x5BF8B34DF1C53C4AULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42F588F47D4CB472ULL,
		0xFA4B672E95062A13ULL,
		0x13658D7F5A9826E3ULL,
		0x7C5374745D6E0B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0730594DBD569ADULL,
		0x2BE0501C3CDF4263ULL,
		0x315A8844B493B9CAULL,
		0x037FA735761C7311ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7282835FA1774AC5ULL,
		0xCE6B17125826E7AFULL,
		0xE20B053AA6046D19ULL,
		0x78D3CD3EE75197F2ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D47F8F2D3649803ULL,
		0x0006064CEB83110DULL,
		0x332CD404E3480060ULL,
		0x11427011C26CB855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x522DBFC6D4F9B705ULL,
		0x969EBAEDC08C44E4ULL,
		0x7F1F0D5BC134E9D7ULL,
		0x34405D4834FD5DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB1A392BFE6AE0EBULL,
		0x69674B5F2AF6CC28ULL,
		0xB40DC6A922131688ULL,
		0x5D0212C98D6F5A9FULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD04679A1CEAB366ULL,
		0x97C9B9C6B9C3278EULL,
		0x6A79362E6AB5CF58ULL,
		0x0E5A5B1CED772353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x324CE0956F499D6AULL,
		0xF314772F12757C21ULL,
		0x0038E37C5DD45651ULL,
		0x098444D287E55721ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAB78704ADA115FCULL,
		0xA4B54297A74DAB6DULL,
		0x6A4052B20CE17906ULL,
		0x04D6164A6591CC32ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DFE727F4CA93A82ULL,
		0xA9A0BEDF76747612ULL,
		0x6FC107238A8D8A48ULL,
		0x056CCCBF2417549DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8554FFE304D7961ULL,
		0x29D446B3BB02373AULL,
		0x519A1C3BF4CC75B5ULL,
		0x3E511C664C62376DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5A922811C5BC10EULL,
		0x7FCC782BBB723ED7ULL,
		0x1E26EAE795C11493ULL,
		0x471BB058D7B51D30ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x470710B13DF0612BULL,
		0x6D22AC6837D0E95EULL,
		0x2C2F845C0806C647ULL,
		0x3810EE9FA1C69AB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECA7AB3436BD41F4ULL,
		0xB58715F47CE5DA9FULL,
		0xA0E072D9936623C6ULL,
		0x498AB3D4985A14CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A5F657D07331F24ULL,
		0xB79B9673BAEB0EBEULL,
		0x8B4F118274A0A280ULL,
		0x6E863ACB096C85E3ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8627F1550390AFB1ULL,
		0x85832F901C6E9C1EULL,
		0xD2C70F016768AA8DULL,
		0x08CFE964DF65D4FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC58D1B185E976EEULL,
		0xB1F0A8586F249750ULL,
		0x0B796E0231EE604DULL,
		0x3E930C154FF4D9E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9CF1FA37DA738B0ULL,
		0xD3928737AD4A04CDULL,
		0xC74DA0FF357A4A3FULL,
		0x4A3CDD4F8F70FB1AULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C6D8D2D6561768FULL,
		0x19FC083C007FF251ULL,
		0x602152226D5D8025ULL,
		0x09DD8F0E4049CF8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2DD14EA8CD6C9FEULL,
		0x888AD89F5571B857ULL,
		0x127D11F0C2E67017ULL,
		0x643647418563016CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69907842D88AAC7EULL,
		0x91712F9CAB0E39F9ULL,
		0x4DA44031AA77100DULL,
		0x25A747CCBAE6CE21ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A989ACC32F65F37ULL,
		0x80771E48D1F0AEE3ULL,
		0x18D6A3DFF6132C1BULL,
		0x46E881F9E76A00C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A4C751FD33E5EC1ULL,
		0xB8826A5C4ABB4531ULL,
		0xC8D07C6BAE771BB6ULL,
		0x0C8424689ED606A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x204C25AC5FB80076ULL,
		0xC7F4B3EC873569B2ULL,
		0x50062774479C1064ULL,
		0x3A645D914893FA1DULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43C11A91A90484F1ULL,
		0xE75403D59C42053EULL,
		0xD3C9F6ECFF2F551CULL,
		0x71EE78511E08BBCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5D85FECB0535B24ULL,
		0xF6B0FB09EE5A9C5DULL,
		0x55CB92A40D4108AEULL,
		0x6AE7C145358FC91DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DE8BAA4F8B129CDULL,
		0xF0A308CBADE768E0ULL,
		0x7DFE6448F1EE4C6DULL,
		0x0706B70BE878F2ADULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00E978D7CA934415ULL,
		0x88FCAC5E723DB0CEULL,
		0x0C5F8E97349F2633ULL,
		0x25875234B6300BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B1A8F352690CAFULL,
		0xC78E14CC40866B00ULL,
		0x737171C829910DCBULL,
		0x4653F33D72E49D59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B37CFE4782A3753ULL,
		0xC16E979231B745CDULL,
		0x98EE1CCF0B0E1867ULL,
		0x5F335EF7434B6E50ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3326134854B4D5E7ULL,
		0x5C0A5EBF9FB7D162ULL,
		0xA42AB1EEA43162B2ULL,
		0x1CCDAD3DCA2BD0D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437FDC1DC89CE061ULL,
		0x217A820C60FD0C0FULL,
		0xBF95DF4FBC444DE8ULL,
		0x0ED19023FC5506ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFA6372A8C17F586ULL,
		0x3A8FDCB33EBAC552ULL,
		0xE494D29EE7ED14CAULL,
		0x0DFC1D19CDD6CA2CULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE49D613D1B2300D1ULL,
		0xE13A0CD3C6FBC5A8ULL,
		0x21D3FFA2D1A154F6ULL,
		0x7F9CB8460319292FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98990792BC2E8929ULL,
		0x566211951361A1B2ULL,
		0x38DF9FB162DA12D5ULL,
		0x634091146DD6712CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C0459AA5EF477A8ULL,
		0x8AD7FB3EB39A23F6ULL,
		0xE8F45FF16EC74221ULL,
		0x1C5C27319542B802ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9C4D3957937AC65ULL,
		0x45D5D5194D82A057ULL,
		0xDE6503C46FFA8E2EULL,
		0x229B5A7FF7BD1A71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23FCE5E31AF1997EULL,
		0x802FBCEA55F92E0BULL,
		0xBD3672453194630CULL,
		0x101F2213F3119C66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5C7EDB25E4612E7ULL,
		0xC5A6182EF789724CULL,
		0x212E917F3E662B21ULL,
		0x127C386C04AB7E0BULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5385E653504D6E0DULL,
		0x518B10B85FED1A68ULL,
		0xF5C95EEB3B38347EULL,
		0x112818ACE4280941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC250FD09BCA6744FULL,
		0xF0AB05B5BFDB5A70ULL,
		0xCFB65CE65A2EBA45ULL,
		0x6CC913DA60C57229ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9134E94993A6F9ABULL,
		0x60E00B02A011BFF7ULL,
		0x26130204E1097A38ULL,
		0x245F04D283629718ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BD9A6C309C60416ULL,
		0x3F6481DE59B15939ULL,
		0x8053C573D748EB66ULL,
		0x17EC62E1EA5200C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9949900612989E93ULL,
		0xE3EEE061B68922E3ULL,
		0xB8044D0F6DAE3778ULL,
		0x7365F396843A93D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD29016BCF72D6570ULL,
		0x5B75A17CA3283655ULL,
		0xC84F7864699AB3EDULL,
		0x24866F4B66176CF1ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43A64C9B546D4ADDULL,
		0xF3D7F8DED35A7FA1ULL,
		0x00B6B677A62560D1ULL,
		0x3D4462A5FDCB886CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x276E0D2356B314A2ULL,
		0xD2017207937FBB09ULL,
		0xB1B448CAB11413C6ULL,
		0x443C1ABF87453C5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C383F77FDBA3628ULL,
		0x21D686D73FDAC498ULL,
		0x4F026DACF5114D0BULL,
		0x790847E676864C0FULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1106C758C905FFFULL,
		0x02E1575C48BFC78AULL,
		0x2440B736FF968335ULL,
		0x3B747D14E6E43848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A63BD1DA41A7F57ULL,
		0x50A00B61FD176B16ULL,
		0xC603ECE1D693114BULL,
		0x12D1ACF3536148DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56ACAF57E875E0A8ULL,
		0xB2414BFA4BA85C74ULL,
		0x5E3CCA55290371E9ULL,
		0x28A2D0219382EF6DULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBC9A6179D68B54CULL,
		0xF430ACA45A0ED694ULL,
		0x2FD875AF5D5BAEBFULL,
		0x1070E61FE419C69FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D3EB435A133B6C0ULL,
		0xC6EE2E90910A3206ULL,
		0xB43EFBAC19028028ULL,
		0x79344BC6504FDD3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE8AF1E1FC34FE79ULL,
		0x2D427E13C904A48EULL,
		0x7B997A0344592E97ULL,
		0x173C9A5993C9E95FULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08B8009666BE119CULL,
		0xA5E35F33378B9827ULL,
		0xF9A7AAE5BB573197ULL,
		0x6118AD1725FD2041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x712ACA785BC790FEULL,
		0x91E6F65B463406B8ULL,
		0xA4A257672B500C0EULL,
		0x1650EBB754BA5FF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x978D361E0AF6809EULL,
		0x13FC68D7F157916EULL,
		0x5505537E90072589ULL,
		0x4AC7C15FD142C049ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5945E5E0D08E57BULL,
		0x21517AA877BC41DDULL,
		0xF857F594A8091B44ULL,
		0x3B1D9EB6E7A3F00CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807DF8A90853B75BULL,
		0x30C2E0FCF0478BD6ULL,
		0x66353574F8601C14ULL,
		0x038145371D8BD6E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x451665B504B52E20ULL,
		0xF08E99AB8774B607ULL,
		0x9222C01FAFA8FF2FULL,
		0x379C597FCA181929ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1019F3CF13D31A88ULL,
		0xFC93D1FECCBE003BULL,
		0xA33E4313D5F56DF6ULL,
		0x629E6BCFE9ABB9F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80D3C636C5120144ULL,
		0x24101C3A1082CA56ULL,
		0x5102B2F9455600B6ULL,
		0x54A3695101216C3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F462D984EC11944ULL,
		0xD883B5C4BC3B35E4ULL,
		0x523B901A909F6D40ULL,
		0x0DFB027EE88A4DB7ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2632BE57F45B5D0ULL,
		0x66E4F8A71B618FC6ULL,
		0xC578E177F36F0352ULL,
		0x2CE56E1F7646E077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1813620DE70B77ACULL,
		0xED2D8B0F36CEEA97ULL,
		0x0B73F1D0B016CA8BULL,
		0x0D9B3A29644A2CE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA4FC9D7983A3E24ULL,
		0x79B76D97E492A52FULL,
		0xBA04EFA7435838C6ULL,
		0x1F4A33F611FCB390ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FAE7914D1F3E9B9ULL,
		0x25D67CAC41D8580BULL,
		0x5825594D25831BBAULL,
		0x766BE93C427A045DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF7A523D12BD26AULL,
		0xFED536359AD69332ULL,
		0xDD0507DFAB8DB458ULL,
		0x3A7D879771D5A1F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32B6D3F100C8174FULL,
		0x27014676A701C4D8ULL,
		0x7B20516D79F56761ULL,
		0x3BEE61A4D0A46268ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1787E1D86175539AULL,
		0xA5E5908D79CE9EC8ULL,
		0xF2B463DFEF70A733ULL,
		0x03A7CCD7BF63AB65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE846CC1C06827CFEULL,
		0xE57A22DD58DCF6EEULL,
		0x38FD35C2F0E29991ULL,
		0x03199D271361573EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F4115BC5AF2D69CULL,
		0xC06B6DB020F1A7D9ULL,
		0xB9B72E1CFE8E0DA1ULL,
		0x008E2FB0AC025427ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB0BC0985C3D67FCULL,
		0x3B9083D7C82993E9ULL,
		0x9FED8FB2F630043EULL,
		0x334226B13BF745D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EEA20E0C599EAAULL,
		0x31C02C1952AB7C6CULL,
		0xFDE65896F917C80EULL,
		0x04C3B9FAF6ACE135ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x551D1E8A4FE3C952ULL,
		0x09D057BE757E177DULL,
		0xA207371BFD183C30ULL,
		0x2E7E6CB6454A64A1ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x571BD90020BFF0B3ULL,
		0x976B9B8F2F1BCB03ULL,
		0xD43E977F0440092CULL,
		0x15AE71055EE66927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BBD1883616B57A3ULL,
		0xA35C9BA47EB29360ULL,
		0xAD1DA674B192E81DULL,
		0x0B705029F49F3D3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B5EC07CBF549910ULL,
		0xF40EFFEAB06937A3ULL,
		0x2720F10A52AD210EULL,
		0x0A3E20DB6A472BEBULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E6A6C1B146DCFA9ULL,
		0x03EBDC42024649E4ULL,
		0xB48CB91233164AD1ULL,
		0x26BC5413BBF1DF10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9999C4EC33AB7DC4ULL,
		0x91BEAE6D3E1FB9A4ULL,
		0x76760B3E84922A97ULL,
		0x0D92ED4A15EC6CF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4D0A72EE0C251E5ULL,
		0x722D2DD4C426903FULL,
		0x3E16ADD3AE842039ULL,
		0x192966C9A605721EULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49E00DD106A227BEULL,
		0xB06289FA1C90765AULL,
		0xCC5DCCACE816BF7FULL,
		0x27B09BE5D38DCBB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB44D0C3EE4B1891ULL,
		0xA726D0FF3BD38A79ULL,
		0x723BA13E2B14E721ULL,
		0x5EE6D8E72EC2A756ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E9B3D0D18570F1AULL,
		0x093BB8FAE0BCEBE0ULL,
		0x5A222B6EBD01D85EULL,
		0x48C9C2FEA4CB245EULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x346763B282948C10ULL,
		0x8C82C0D5AAF27F73ULL,
		0x2AC6CF3B253C0C05ULL,
		0x434784C93A8A3EF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B1E0ED5C33271DULL,
		0x4B6ABC51A8956C0AULL,
		0x0E9AA77075AFA354ULL,
		0x594FB0ACBDAC8EC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB582C5266164E0ULL,
		0x41180484025D1368ULL,
		0x1C2C27CAAF8C68B1ULL,
		0x69F7D41C7CDDB038ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57753CF486FC4130ULL,
		0x087C79610850166CULL,
		0x9BD2F681CDAF4DCCULL,
		0x570377FDAE0B1652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC5F2ACDD3F5EF2ULL,
		0x579FD21D4C8FBA4CULL,
		0x7136F81C218BCDF8ULL,
		0x527E9A4DCACF01DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAAF4A47A9BCE23EULL,
		0xB0DCA743BBC05C1FULL,
		0x2A9BFE65AC237FD3ULL,
		0x0484DDAFE33C1477ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FC93C4BCC9CCAF2ULL,
		0x1AD836211A1CEE9FULL,
		0xEECABBE109CB3B11ULL,
		0x0C7075491FC55EB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7FF2611EF7DCFC6ULL,
		0x735EE2543E0F0EA5ULL,
		0xCD8AAE3F13D3B942ULL,
		0x2FEB8C3BF3D3F9EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77CA1639DD1EFB19ULL,
		0xA77953CCDC0DDFF9ULL,
		0x21400DA1F5F781CEULL,
		0x5C84E90D2BF164C8ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A578AF078FAA45CULL,
		0xAE7A9C0E051023DDULL,
		0x53D9F0AC851C2070ULL,
		0x7EC8C35820580A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB4E82468ABB73BULL,
		0xE48D3CC250E1BCA2ULL,
		0xBBDEBB264CF19536ULL,
		0x56F19FABA687607AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FA2A2CC104EED21ULL,
		0xC9ED5F4BB42E673BULL,
		0x97FB3586382A8B39ULL,
		0x27D723AC79D0A9E1ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x885A3F8F4C7B3BD1ULL,
		0x008902983CC277F7ULL,
		0xACB198AD91D327EBULL,
		0x60F4E483AA78066CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22E145E10877331ULL,
		0xD44FC79ED24E61C1ULL,
		0x80EDC4870C93E28DULL,
		0x5B7FE8BDAA91F241ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB62C2B313BF3C8A0ULL,
		0x2C393AF96A741635ULL,
		0x2BC3D426853F455DULL,
		0x0574FBC5FFE6142BULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62DDE5D77CEBFD0BULL,
		0xEC937248FB479430ULL,
		0x5DD09E81152FE170ULL,
		0x5B6D448023064B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E8BB0651C14DDAULL,
		0x449F5571EE1A609BULL,
		0xC917F55B40F6337CULL,
		0x2C6749056DB2668CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBF52AD12B2AAF31ULL,
		0xA7F41CD70D2D3394ULL,
		0x94B8A925D439ADF4ULL,
		0x2F05FB7AB553E486ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D6B7AEF397D654EULL,
		0xD42AA6AE71FC4599ULL,
		0x544EB8E16B11CAA5ULL,
		0x1FEC1BC23875E4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD7E58ED95CB87FULL,
		0x61C9D9449D000EDCULL,
		0x316D7F3A0E1B2553ULL,
		0x326FAB1C00367990ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x209395606020ACBCULL,
		0x7260CD69D4FC36BDULL,
		0x22E139A75CF6A552ULL,
		0x6D7C70A6383F6B58ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25940BDDE5DF2A2EULL,
		0x849E051849B79BC6ULL,
		0x8AF83997FB7BEB04ULL,
		0x1A342E42ECD78CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x723755E37311301BULL,
		0x41458D733FD445C9ULL,
		0x02ED4450F5360C24ULL,
		0x0CF6772DCB364851ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB35CB5FA72CDFA13ULL,
		0x435877A509E355FCULL,
		0x880AF5470645DEE0ULL,
		0x0D3DB71521A1445AULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B220FE2CA12B34FULL,
		0x95ABCAF4CD37A1ABULL,
		0xEEF2BD8E656A8612ULL,
		0x4782C64C90B0FBB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF84FB5C069FF4E5ULL,
		0xFFC4F52448A93ACEULL,
		0x6A8EE8E0BEF7EE3CULL,
		0x4F40C5F60FDA7D09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B9D1486C372BE57ULL,
		0x95E6D5D0848E66DCULL,
		0x8463D4ADA67297D5ULL,
		0x7842005680D67EA8ULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC642CE5A74641A3AULL,
		0x1D3543064FD006DBULL,
		0xA133069D4AB9131AULL,
		0x3CCB8C7B30C72636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F913D62135EB23CULL,
		0x4DF7A60A56F2249CULL,
		0x23C86D2048C90995ULL,
		0x045F81EDD90AE2B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46B190F8610567FEULL,
		0xCF3D9CFBF8DDE23FULL,
		0x7D6A997D01F00984ULL,
		0x386C0A8D57BC437EULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x315601E8AD5A0154ULL,
		0x45E1AE4B3FBD759AULL,
		0x2B203ABCDF2DEC22ULL,
		0x556C79972EA14BB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48D38530CF47971ULL,
		0xBEE44537A7960C32ULL,
		0xEE6F8A1B0CE91F66ULL,
		0x051C1F95376F59A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CC8C995A06587E3ULL,
		0x86FD691398276967ULL,
		0x3CB0B0A1D244CCBBULL,
		0x50505A01F731F20DULL
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
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}