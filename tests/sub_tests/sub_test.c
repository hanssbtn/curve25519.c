#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0xE382EFEEC07B5693ULL,
		0x26CA882D6DCE6C8EULL,
		0x7F5EAA6B38A8C07CULL,
		0x235B9C5D6A9BECEAULL,
		0x67F021CD088287D7ULL,
		0x5149CE7E94E13E40ULL,
		0x89197454CDDD92FEULL,
		0x34FA5171AE48DC79ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE6C2918980820436ULL,
		0x65FB51C8EB844294ULL,
		0x8F23FBD9787020CDULL,
		0xC96B52CF8EEA78E0ULL,
		0x23E65105BFE331EAULL,
		0x5B725E78189A761EULL,
		0x51EA582EC967B6EFULL,
		0x87B68751AB10084CULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xFCC05E653FF9525DULL,
		0xC0CF3664824A29F9ULL,
		0xF03AAE91C0389FAEULL,
		0x59F0498DDBB17409ULL,
		0x4409D0C7489F55ECULL,
		0xF5D770067C46C822ULL,
		0x372F1C260475DC0EULL,
		0xAD43CA200338D42DULL
	}};
	printf("Underflow\n");
	int sign = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD983214CBF10E974ULL,
		0x417D3C1D16C53635ULL,
		0x586C00B599FCDEF4ULL,
		0x7CEB07657D423019ULL,
		0xD707F3A279825EBBULL,
		0x3D9FDF67914C6EC2ULL,
		0x87270FF740FB5403ULL,
		0x150D15EA5391DF5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5062E6D1DBB271ULL,
		0xBC6572C4EAECD901ULL,
		0x29FD292DEEDDC85AULL,
		0x5F901449ABC3B58FULL,
		0xAB8ECB308E5B4D1CULL,
		0x601BE4C41F3FA69EULL,
		0xDFD5464FADF44F63ULL,
		0x0940CABF0C568B92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C32BE65ED353703ULL,
		0x8517C9582BD85D34ULL,
		0x2E6ED787AB1F1699ULL,
		0x1D5AF31BD17E7A8AULL,
		0x2B792871EB27119FULL,
		0xDD83FAA3720CC824ULL,
		0xA751C9A79307049FULL,
		0x0BCC4B2B473B53C9ULL
	}};
	sign = 0;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE72D01AD864B47AULL,
		0x6142915A6E3AFBE2ULL,
		0x32DF7E8398D5FE4BULL,
		0x4008AC2EF8D59D4CULL,
		0xCFA2A2E665F4ACBDULL,
		0x67F3B26641CC8838ULL,
		0xDED8F9F36F0B716AULL,
		0xB694B8F1EE8DB13DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6131FE83BA8601ULL,
		0xAAD1B86471899CCFULL,
		0x3E47F05D2F03C806ULL,
		0x45B952F06DF26DA5ULL,
		0x7C266475962CA0E0ULL,
		0x109A1B0F1E964694ULL,
		0xF4AF37343EA3568EULL,
		0x2DD594015B7F717FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61119E1C54AA2E79ULL,
		0xB670D8F5FCB15F13ULL,
		0xF4978E2669D23644ULL,
		0xFA4F593E8AE32FA6ULL,
		0x537C3E70CFC80BDCULL,
		0x57599757233641A4ULL,
		0xEA29C2BF30681ADCULL,
		0x88BF24F0930E3FBDULL
	}};
	sign = 0;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0EBAF6C8A5215EAULL,
		0xCDE2676194247BE6ULL,
		0xD6419F8A8C1835B5ULL,
		0xED816519B7488659ULL,
		0xC11830EFD3922D87ULL,
		0xD0EE4E9E21610D9AULL,
		0xA82C2DFBC2747EF8ULL,
		0xD825E53BB13CDD9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F9035997F90AB2ULL,
		0x6C15605F4EFE4528ULL,
		0x656D4F60024E31FFULL,
		0x5411416AAC28ED5AULL,
		0x45903DCFED48CB56ULL,
		0x457AB4A7932B9FB8ULL,
		0xA62C167A27A8E7DAULL,
		0x97B1004AE72ED6A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADF2AC12F2590B38ULL,
		0x61CD0702452636BEULL,
		0x70D4502A89CA03B6ULL,
		0x997023AF0B1F98FFULL,
		0x7B87F31FE6496231ULL,
		0x8B7399F68E356DE2ULL,
		0x020017819ACB971EULL,
		0x4074E4F0CA0E06FDULL
	}};
	sign = 0;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BA0208E06B8A601ULL,
		0x2FEFE5D98D52D71FULL,
		0xC59FBD658D359B1EULL,
		0xEE140135407BF4B1ULL,
		0x9B34E3283159F78FULL,
		0x92FDBC2113A2C13CULL,
		0xCEB975B9BD68B972ULL,
		0xD4352D5E4B753826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BBC63B35132393CULL,
		0x3DCFAEA76F0AC108ULL,
		0x3FC113371AF6B156ULL,
		0x9424FCB8CA1BB01BULL,
		0xD4C892E7DB23FE5EULL,
		0x547D0EBDEE14368BULL,
		0xE52E892624318895ULL,
		0xCB6C4F8444404624ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFE3BCDAB5866CC5ULL,
		0xF22037321E481616ULL,
		0x85DEAA2E723EE9C7ULL,
		0x59EF047C76604496ULL,
		0xC66C50405635F931ULL,
		0x3E80AD63258E8AB0ULL,
		0xE98AEC93993730DDULL,
		0x08C8DDDA0734F201ULL
	}};
	sign = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E4221313F71FF66ULL,
		0xF7B1B00209CFD9B5ULL,
		0xB08F7BEB2919FE32ULL,
		0xEFB15294AD208D78ULL,
		0xF00E80F30D335D1DULL,
		0x2713EA0F033E502FULL,
		0xBA7905B5B6974E27ULL,
		0x2B6546D27FEF30FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A92E9FE14906E4ULL,
		0xA48135800E4EC2BAULL,
		0x7061D165E7AC01D2ULL,
		0xB11ABA96623E0BA8ULL,
		0x239E46F9F3A0AB39ULL,
		0x47F75383B0B42E4EULL,
		0x40AC5518E08B6574ULL,
		0x751155722E7135D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D98F2915E28F882ULL,
		0x53307A81FB8116FBULL,
		0x402DAA85416DFC60ULL,
		0x3E9697FE4AE281D0ULL,
		0xCC7039F91992B1E4ULL,
		0xDF1C968B528A21E1ULL,
		0x79CCB09CD60BE8B2ULL,
		0xB653F160517DFB24ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2ED07E200B17FE6ULL,
		0xEC67875BF13B8157ULL,
		0xF153DBC5DA0B06C9ULL,
		0x7D875977B21F3F00ULL,
		0x4F9EEE8F2D60E6C0ULL,
		0xAB285F38B8B6A80DULL,
		0xE0FEA48468E7D5DDULL,
		0xF8933471B152330AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CD20774811A30F1ULL,
		0x03AA806018BF7C4EULL,
		0x2F5D845BC0FA14EDULL,
		0xDA5D47EF0FFD967AULL,
		0xD3FCFAAFA1FD52A3ULL,
		0x67CB4404DC71F4F2ULL,
		0xC3AC89CF6D659AE1ULL,
		0x5DBBE8807751D384ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x561B006D7F974EF5ULL,
		0xE8BD06FBD87C0509ULL,
		0xC1F6576A1910F1DCULL,
		0xA32A1188A221A886ULL,
		0x7BA1F3DF8B63941CULL,
		0x435D1B33DC44B31AULL,
		0x1D521AB4FB823AFCULL,
		0x9AD74BF13A005F86ULL
	}};
	sign = 0;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x366E9F6E5192D7C9ULL,
		0xFC0A60245C59A8EDULL,
		0x66D7385AD6A8562AULL,
		0x43AF243A09443A7AULL,
		0xB97525C1650D7582ULL,
		0xB412F5F08276A1F4ULL,
		0x4D1391D2EA0AB138ULL,
		0xA5BD55217D73A2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE871A4D445529DULL,
		0x43794588ADCF4561ULL,
		0xD56AEBE782261AF5ULL,
		0xEF5C3A7A6C167CD4ULL,
		0x0C86846B2B16561BULL,
		0xC4B15C627AAB9A3EULL,
		0x517E6BB1FB6EA061ULL,
		0x32E7AA50CF8DA4CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8862DC97D4D852CULL,
		0xB8911A9BAE8A638BULL,
		0x916C4C7354823B35ULL,
		0x5452E9BF9D2DBDA5ULL,
		0xACEEA15639F71F66ULL,
		0xEF61998E07CB07B6ULL,
		0xFB952620EE9C10D6ULL,
		0x72D5AAD0ADE5FDE5ULL
	}};
	sign = 0;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD99F98227024520ULL,
		0x36F7E919B932F98DULL,
		0x5031809E02DCB995ULL,
		0xE50135B56B3DEFC6ULL,
		0x52913403D643263AULL,
		0xDEBB0F32475A365AULL,
		0xE0C882C3A6824A5EULL,
		0xB51ECB06D249B067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB886552EA5415411ULL,
		0xA969E679A5A69E2CULL,
		0xB152B9E84954BDC1ULL,
		0x61ACB210972B231FULL,
		0x0578C8393D7120EAULL,
		0x534CD6FFB8712D45ULL,
		0xA44AE14F8727543EULL,
		0xEC3A6813DFE5CDF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0513A45381C0F10FULL,
		0x8D8E02A0138C5B61ULL,
		0x9EDEC6B5B987FBD3ULL,
		0x835483A4D412CCA6ULL,
		0x4D186BCA98D20550ULL,
		0x8B6E38328EE90915ULL,
		0x3C7DA1741F5AF620ULL,
		0xC8E462F2F263E26FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3C2EC2C2F0072E7ULL,
		0x16C2B1F63DECF4A0ULL,
		0x46DFF6F512E2A6CFULL,
		0x12DACAD0691A2BC8ULL,
		0x9064D34295EF2D3DULL,
		0x343D3324787742C8ULL,
		0x323312DBE1C3FF62ULL,
		0x39F274714B1DE9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A34301761888B98ULL,
		0x3CAD8EC09499E77BULL,
		0xDADB224FDFA3FF09ULL,
		0x557818F6C51A324FULL,
		0x5729760CAB7B4FF2ULL,
		0xFE91606588D8529FULL,
		0xC58D265AAC106202ULL,
		0xA85480B1D8063FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x598EBC14CD77E74FULL,
		0xDA152335A9530D25ULL,
		0x6C04D4A5333EA7C5ULL,
		0xBD62B1D9A3FFF978ULL,
		0x393B5D35EA73DD4AULL,
		0x35ABD2BEEF9EF029ULL,
		0x6CA5EC8135B39D5FULL,
		0x919DF3BF7317AA41ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6A2BFEABF0D973ULL,
		0x083F4AF362AA55C7ULL,
		0x4A5AD47A11C353FDULL,
		0xFA684FD1F66727FDULL,
		0x93D84C46E2165016ULL,
		0xC8D637F1AF11329DULL,
		0xCEFCB051FE24B910ULL,
		0x032CBFD2DEDBC5F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4173F7B3FF70BB2ULL,
		0x82A5276CFD41F283ULL,
		0x470618B37FA34EC8ULL,
		0xED533E54C7831C5BULL,
		0x68E056557A42BC50ULL,
		0xF880930E3E533327ULL,
		0x7E1D022563461B93ULL,
		0x7864FF40C2DB828EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE652EC836BF9CDC1ULL,
		0x859A238665686343ULL,
		0x0354BBC692200534ULL,
		0x0D15117D2EE40BA2ULL,
		0x2AF7F5F167D393C6ULL,
		0xD055A4E370BDFF76ULL,
		0x50DFAE2C9ADE9D7CULL,
		0x8AC7C0921C004363ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DC434A147B41B46ULL,
		0x51FC2B90C2E778AEULL,
		0x9CD5120BCB964FEEULL,
		0xD4377AD09AEA5791ULL,
		0xD9609697AE0E7752ULL,
		0xFBA994F36EA6B819ULL,
		0x1920B1FFB2824760ULL,
		0xC5E95CEADAE1CE22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B537DB6945D90AULL,
		0xE202FE4FD37E790CULL,
		0x43DA76C25EBAB8B3ULL,
		0x5C2E51AF6C055F9AULL,
		0x4F997352BBD44C3FULL,
		0x0C6F2C26FAFD8969ULL,
		0x42A48176073086F2ULL,
		0x6D52BCA791C3B463ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x270EFCC5DE6E423CULL,
		0x6FF92D40EF68FFA2ULL,
		0x58FA9B496CDB973AULL,
		0x780929212EE4F7F7ULL,
		0x89C72344F23A2B13ULL,
		0xEF3A68CC73A92EB0ULL,
		0xD67C3089AB51C06EULL,
		0x5896A043491E19BEULL
	}};
	sign = 0;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F321706108D913AULL,
		0x6DC2D36AE148817DULL,
		0xAAC8B9BFDA75ABB0ULL,
		0x2237DD98165AD4C3ULL,
		0xBF4657663F0D0849ULL,
		0x744FF9AD0B59E0F1ULL,
		0xF39143B9DE8ACE13ULL,
		0x2D8ED49DC99FDAE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B70515B70A9C6A3ULL,
		0xB8BA0860B2B2F0C3ULL,
		0x0ED6277DE04523ACULL,
		0xDBB6726F3B5D7EE6ULL,
		0xBAC3300D429D1A08ULL,
		0xBB3CFFF0D9AED13CULL,
		0xC47FDE4AA4AC005BULL,
		0x32853450C57F7B21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23C1C5AA9FE3CA97ULL,
		0xB508CB0A2E9590BAULL,
		0x9BF29241FA308803ULL,
		0x46816B28DAFD55DDULL,
		0x04832758FC6FEE40ULL,
		0xB912F9BC31AB0FB5ULL,
		0x2F11656F39DECDB7ULL,
		0xFB09A04D04205FC2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46537AA36900BDADULL,
		0xAD04C65B07CD73C5ULL,
		0x317191AAD74B6778ULL,
		0x2CFA53690E07F6D0ULL,
		0xCF7AA2B0B8AC0E87ULL,
		0x49A717E68EC89C73ULL,
		0x20E4C3A099121AD1ULL,
		0xA762E7C15251DC1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6AC074B7C0B4540ULL,
		0x4F3AA98208F0E099ULL,
		0x3316D836FB79A0C8ULL,
		0x42108E9F089DCE67ULL,
		0x99792924AC55CA55ULL,
		0x4726083C9A4AA029ULL,
		0x889EB070B11D79A8ULL,
		0x6761D2BC9A77CF78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FA77357ECF5786DULL,
		0x5DCA1CD8FEDC932BULL,
		0xFE5AB973DBD1C6B0ULL,
		0xEAE9C4CA056A2868ULL,
		0x3601798C0C564431ULL,
		0x02810FA9F47DFC4AULL,
		0x9846132FE7F4A129ULL,
		0x40011504B7DA0CA6ULL
	}};
	sign = 0;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5253AFD11AFAACBEULL,
		0xB5491D2241217FF8ULL,
		0x95D6568B5D3B2321ULL,
		0x3115D24BB4E71DD3ULL,
		0x2D4FCD40B5A4AF13ULL,
		0xD53188322FD9840EULL,
		0x7883A63BF6C3A3A5ULL,
		0x5A052A826B0DC84AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00EDAA7A4F17670ULL,
		0xD2EACF797BE92C6DULL,
		0x124451D899BCC727ULL,
		0xBFB82C47845308FCULL,
		0xFF6CF46347883060ULL,
		0x06ED495A77756F2DULL,
		0x3A44CE06DC09B2FDULL,
		0x3107A23AE0A9ED57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6244D5297609364EULL,
		0xE25E4DA8C538538AULL,
		0x839204B2C37E5BF9ULL,
		0x715DA604309414D7ULL,
		0x2DE2D8DD6E1C7EB2ULL,
		0xCE443ED7B86414E0ULL,
		0x3E3ED8351AB9F0A8ULL,
		0x28FD88478A63DAF3ULL
	}};
	sign = 0;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BD26C08F5EE8453ULL,
		0xC121575D341D6455ULL,
		0xDABEE38169658FBBULL,
		0x6F5BE003F1F1A189ULL,
		0x7E4FE9CC0E9735B4ULL,
		0x0CC538BBC16DB085ULL,
		0x9123730445F6758AULL,
		0x50CA5316758C6DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A52C4B527568E51ULL,
		0xF7D21E26E31F7F56ULL,
		0xB503F823098406ABULL,
		0xEDB0698C433C0828ULL,
		0x62959AC780CC62F1ULL,
		0xE4F1CC3622F5057CULL,
		0xFDFFEFFF739B4635ULL,
		0xD214F5C978C571DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x217FA753CE97F602ULL,
		0xC94F393650FDE4FFULL,
		0x25BAEB5E5FE1890FULL,
		0x81AB7677AEB59961ULL,
		0x1BBA4F048DCAD2C2ULL,
		0x27D36C859E78AB09ULL,
		0x93238304D25B2F54ULL,
		0x7EB55D4CFCC6FBDCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C5FC2BF0A98857FULL,
		0x6EE280C516A24F34ULL,
		0x53A779A5B4EF47FBULL,
		0xE178DC383778E4C1ULL,
		0xB447B5E4592F0EFCULL,
		0x9E8E3F261235B1ABULL,
		0x26E2FFE62581B3D7ULL,
		0x58B69DC143AAB650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1B8C144776EAB71ULL,
		0x012783E449436876ULL,
		0xF216D23C13358D3CULL,
		0x75E6B14C2AF26F6BULL,
		0xABD0C256C43F5578ULL,
		0xC07F207536285ACBULL,
		0x834B87F5A482B90BULL,
		0xB08E2EE8817DC38DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAA7017A9329DA0EULL,
		0x6DBAFCE0CD5EE6BDULL,
		0x6190A769A1B9BABFULL,
		0x6B922AEC0C867555ULL,
		0x0876F38D94EFB984ULL,
		0xDE0F1EB0DC0D56E0ULL,
		0xA39777F080FEFACBULL,
		0xA8286ED8C22CF2C2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F58AF6A46D5BC2DULL,
		0x9D96BFB83D191268ULL,
		0x6BA4FD23F2EF05D7ULL,
		0x368C922A5C71B6E3ULL,
		0x45DAEA93D6175E80ULL,
		0x705E0CE3325EE4D0ULL,
		0x2D97F8D14F137DE6ULL,
		0x824349C7997BA24EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B3472BAE07D308ULL,
		0x1BE656371E4A3E50ULL,
		0x54FE7BCF4924C35FULL,
		0xF66EA91834F18DA8ULL,
		0xA5FC9FD26BEE8A26ULL,
		0x0F29CE03B25F35A5ULL,
		0x156A4EF5B57A5F7FULL,
		0x3E73429E8119A285ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACA5683E98CDE925ULL,
		0x81B069811ECED417ULL,
		0x16A68154A9CA4278ULL,
		0x401DE9122780293BULL,
		0x9FDE4AC16A28D459ULL,
		0x61343EDF7FFFAF2AULL,
		0x182DA9DB99991E67ULL,
		0x43D007291861FFC9ULL
	}};
	sign = 0;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80840E1DE91DE2CBULL,
		0xDF0B68A293927654ULL,
		0x5CE4B7D6D2D32F62ULL,
		0xFD2BB0A37C47AAB2ULL,
		0xA5633CD2E5A545B7ULL,
		0x6454F16A9D1889C4ULL,
		0x5A5D4912E97EA5BCULL,
		0x7E87CA9BA36DD95CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6FADC84C07EB814ULL,
		0x746DEAD20061096AULL,
		0x9B0F1D76939767C5ULL,
		0xF0D9A026F16DEF87ULL,
		0xCD90D25C50A6DCA6ULL,
		0x1869C1C199A5443AULL,
		0x4D4EEBB8281D5B76ULL,
		0x6D2B8104321C8B61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99893199289F2AB7ULL,
		0x6A9D7DD093316CE9ULL,
		0xC1D59A603F3BC79DULL,
		0x0C52107C8AD9BB2AULL,
		0xD7D26A7694FE6911ULL,
		0x4BEB2FA903734589ULL,
		0x0D0E5D5AC1614A46ULL,
		0x115C499771514DFBULL
	}};
	sign = 0;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDEA37CA749CB10EULL,
		0x21D0F6D0781E07B3ULL,
		0x6C9F9F70A558F502ULL,
		0x127D063C6D75A71FULL,
		0x763B285FCED1ACFDULL,
		0xA6C6E945CD6DB553ULL,
		0xA55C1DC5094FDDD4ULL,
		0x9B99B8183FD0BA22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF15A6725B1A17932ULL,
		0x8B1D5FAC61B917D6ULL,
		0x924E12DA5C4A634BULL,
		0x1CC903B492481D10ULL,
		0x0F2BA24758AFD7F2ULL,
		0xF4E4725B7129BCDEULL,
		0x074510FA2813BB30ULL,
		0x2A283471D7152E54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC8FD0A4C2FB37DCULL,
		0x96B397241664EFDCULL,
		0xDA518C96490E91B6ULL,
		0xF5B40287DB2D8A0EULL,
		0x670F86187621D50AULL,
		0xB1E276EA5C43F875ULL,
		0x9E170CCAE13C22A3ULL,
		0x717183A668BB8BCEULL
	}};
	sign = 0;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2BA73AA513F560FULL,
		0xD01E98C2ED005F23ULL,
		0x2E660082546CB664ULL,
		0x597CCF7C6F9B96BFULL,
		0xDFD6F6B821B2112DULL,
		0x19CAC90528778A51ULL,
		0xBCEF74F72E18A9C2ULL,
		0x3C09A986E8769485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36023DC9ADAC2264ULL,
		0x69AF3CAC119E4CDFULL,
		0xFC546F1D8CEB2F0DULL,
		0x0844A8AA950FF3A9ULL,
		0x500DF94B3DEAD531ULL,
		0x0BAD6CF5CD6F4540ULL,
		0x538C1B846DBA5BC2ULL,
		0x4B01A5EC5F888E03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACB835E0A39333ABULL,
		0x666F5C16DB621244ULL,
		0x32119164C7818757ULL,
		0x513826D1DA8BA315ULL,
		0x8FC8FD6CE3C73BFCULL,
		0x0E1D5C0F5B084511ULL,
		0x69635972C05E4E00ULL,
		0xF108039A88EE0682ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x114DF0EBDDC73A36ULL,
		0xE112E7BB046C31D1ULL,
		0x90A82CACCD7E987AULL,
		0x3A63787BA9A8528CULL,
		0x6453585FA5C57EA6ULL,
		0x539C745B04DA11D9ULL,
		0x6D39D135BCC93D7CULL,
		0xC581D6844FC2D339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A989D5E7739184ULL,
		0x63E4B60ADA460E97ULL,
		0x37B792869E63A06FULL,
		0x485ED9BF42526908ULL,
		0x47589192D27C68D1ULL,
		0x3CA7B3FF5C0070ADULL,
		0x556C8764A1BC60FCULL,
		0xCC15FC4DB4827A6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47A46715F653A8B2ULL,
		0x7D2E31B02A262339ULL,
		0x58F09A262F1AF80BULL,
		0xF2049EBC6755E984ULL,
		0x1CFAC6CCD34915D4ULL,
		0x16F4C05BA8D9A12CULL,
		0x17CD49D11B0CDC80ULL,
		0xF96BDA369B4058CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09641E327910B749ULL,
		0xB439D10CAC7B780DULL,
		0xE9C7A946EDE5022AULL,
		0xB49C57F9B8075812ULL,
		0x75A9190E6DA57BB0ULL,
		0x1E8A01E9058C9D62ULL,
		0x55724E5245CF47E3ULL,
		0x8985D5E06408B032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC7AA03A0B2C14E5ULL,
		0xF136BC5037BF4487ULL,
		0x12F15628EF142869ULL,
		0x099772DE5B1CA669ULL,
		0xBBFCC479C4A7EC5EULL,
		0xD56ABCA3DB7C502DULL,
		0xE7F0ED9C73283419ULL,
		0xCA6CAEEEBB9F7EF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CE97DF86DE4A264ULL,
		0xC30314BC74BC3385ULL,
		0xD6D6531DFED0D9C0ULL,
		0xAB04E51B5CEAB1A9ULL,
		0xB9AC5494A8FD8F52ULL,
		0x491F45452A104D34ULL,
		0x6D8160B5D2A713C9ULL,
		0xBF1926F1A869313DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2D8A8992E75D667ULL,
		0x43A103CE2FDFF6DFULL,
		0xDC8A0A967EA579DCULL,
		0xF0EDFAB019BB2EA4ULL,
		0xE594840A5192B2F4ULL,
		0xAB529C325ED62826ULL,
		0x94089FD06DE8157EULL,
		0x9B94864595B813F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06EBEDE52173F6B1ULL,
		0x35825323C7B34591ULL,
		0x4E3847761B0AE420ULL,
		0x7D8F3F3EEC1B89F3ULL,
		0xB7318AB8109DD12CULL,
		0xF33CCEE58158B0E5ULL,
		0xD2F4EA41E65682B5ULL,
		0x57021A1AE63B910DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBECBAB40D01DFB6ULL,
		0x0E1EB0AA682CB14EULL,
		0x8E51C320639A95BCULL,
		0x735EBB712D9FA4B1ULL,
		0x2E62F95240F4E1C8ULL,
		0xB815CD4CDD7D7741ULL,
		0xC113B58E879192C8ULL,
		0x44926C2AAF7C82E3ULL
	}};
	sign = 0;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA3290BB591D0587ULL,
		0x11F17F988BFC85DEULL,
		0x8991FB44AFD304EBULL,
		0x5CB9EF890F056ECDULL,
		0x70A72F98DF5A03FFULL,
		0xB303C34984578E84ULL,
		0xC8FC69ABCB6B7D00ULL,
		0xCBEF88040C388DDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FC0CACA171CE363ULL,
		0xEABE251C03C0D6D0ULL,
		0x80FE46E518CB7B18ULL,
		0x52335EF266B77496ULL,
		0xC45974BB78671291ULL,
		0xE7DAAD23843F14A9ULL,
		0x332AC278BE05B130ULL,
		0x323E193CA54EB716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A71C5F142002224ULL,
		0x27335A7C883BAF0EULL,
		0x0893B45F970789D2ULL,
		0x0A869096A84DFA37ULL,
		0xAC4DBADD66F2F16EULL,
		0xCB291626001879DAULL,
		0x95D1A7330D65CBCFULL,
		0x99B16EC766E9D6C6ULL
	}};
	sign = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE29EB2B0D686395DULL,
		0x57D5FD25BD09C410ULL,
		0xFFC3D85A2A046A0AULL,
		0xD70F31BD678DECA2ULL,
		0x95DA7C6DE6636EB1ULL,
		0x94A87796E89ADC39ULL,
		0x26EDDD95CCE6BDA3ULL,
		0x4F444357711488E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB546661A853F9326ULL,
		0x1234F12A1E561C0EULL,
		0xA88FEB521A58816DULL,
		0x81BEA4CAD97B671CULL,
		0xEE9EA36BB1E5E431ULL,
		0x64C19A047BBE11CFULL,
		0x3DC3370CF8299DAFULL,
		0x787D4AF52FB77C5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D584C965146A637ULL,
		0x45A10BFB9EB3A802ULL,
		0x5733ED080FABE89DULL,
		0x55508CF28E128586ULL,
		0xA73BD902347D8A80ULL,
		0x2FE6DD926CDCCA69ULL,
		0xE92AA688D4BD1FF4ULL,
		0xD6C6F862415D0C8BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8C928A4ECADDFE0ULL,
		0xAA9A556FC5B11EAEULL,
		0x647E5E60D7C046CFULL,
		0x9C16A676527DDBCEULL,
		0xF8041A340D57F42AULL,
		0x9C771488A2E82C2BULL,
		0xFDF34A5C8359D5DCULL,
		0x421FE7962ED04D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BA1A85C97187BDULL,
		0xCE4AE241ECD81692ULL,
		0xC6D6DF91DE47709CULL,
		0x166902AA3966FD1AULL,
		0xE9CB3B04975C2619ULL,
		0x1B7CEE5B0D4F56AFULL,
		0x959DF64EC5E0A177ULL,
		0x7A187D740DFE36F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF70F0E1F233C5823ULL,
		0xDC4F732DD8D9081BULL,
		0x9DA77ECEF978D632ULL,
		0x85ADA3CC1916DEB3ULL,
		0x0E38DF2F75FBCE11ULL,
		0x80FA262D9598D57CULL,
		0x6855540DBD793465ULL,
		0xC8076A2220D21644ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC92C9A53F141F2DDULL,
		0x6D3C8C785F56034CULL,
		0xBCBF2CE458903F3EULL,
		0x0800BA90390E3E59ULL,
		0xF8C4816B44CD090DULL,
		0x234CA706B5E8C637ULL,
		0x131FF314BE157DF6ULL,
		0xF63381B878A6CF23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A77B3A516BD5958ULL,
		0x56A008B67CF362EAULL,
		0xE6B73E9834D106FDULL,
		0xC23ADDECF89F5693ULL,
		0x9D1B836A8B75EB46ULL,
		0x75D15E09FDA62C9CULL,
		0xD0D1485C6567B529ULL,
		0x668F42A6B815D632ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EB4E6AEDA849985ULL,
		0x169C83C1E262A062ULL,
		0xD607EE4C23BF3841ULL,
		0x45C5DCA3406EE7C5ULL,
		0x5BA8FE00B9571DC6ULL,
		0xAD7B48FCB842999BULL,
		0x424EAAB858ADC8CCULL,
		0x8FA43F11C090F8F0ULL
	}};
	sign = 0;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x147D6355300C5F23ULL,
		0x6DE5F1BD2440A5A4ULL,
		0x575CB337EA79E9F8ULL,
		0x402E943CD6BA83ACULL,
		0xCA8CBFA9C1E0F0C4ULL,
		0x81AB9086A963E1E4ULL,
		0x5B9D0E01C046F57DULL,
		0x9602629DA893D31FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x626AF17ECD5DA442ULL,
		0x7EF7DB1E229E71A9ULL,
		0x69A58E61B7A9E03DULL,
		0x8E5731C1277AD99EULL,
		0xA2D6EA03DBE1A6FEULL,
		0x7AF630B3D9124A39ULL,
		0x7C6B18EB539E2E48ULL,
		0x52BBBC09904A51CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB21271D662AEBAE1ULL,
		0xEEEE169F01A233FAULL,
		0xEDB724D632D009BAULL,
		0xB1D7627BAF3FAA0DULL,
		0x27B5D5A5E5FF49C5ULL,
		0x06B55FD2D05197ABULL,
		0xDF31F5166CA8C735ULL,
		0x4346A69418498153ULL
	}};
	sign = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x997C7033B695451EULL,
		0xA3CCA887AA0B7DFFULL,
		0x97F9C26013325BD2ULL,
		0x2B561D59C0287795ULL,
		0x59CC853D1AA580B4ULL,
		0x7061CC8B5E7147ABULL,
		0x9E7DD7CB4DEC258AULL,
		0xD1F18FA27E24B0D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD6FDB3CBCC3C4FULL,
		0x4EEB3A5BC6355F72ULL,
		0x900FF959B4D6E467ULL,
		0x6E7EEDF32D4AC32AULL,
		0xA08A60607AA4812CULL,
		0xADB9B115C44D324AULL,
		0x74F8B32FB4DBFFC7ULL,
		0x34029634BBCA9CC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BA5727FEAC908CFULL,
		0x54E16E2BE3D61E8DULL,
		0x07E9C9065E5B776BULL,
		0xBCD72F6692DDB46BULL,
		0xB94224DCA000FF87ULL,
		0xC2A81B759A241560ULL,
		0x2985249B991025C2ULL,
		0x9DEEF96DC25A1412ULL
	}};
	sign = 0;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E69EDA01D364D92ULL,
		0x613C252576175352ULL,
		0x0E67F1E54702089FULL,
		0x431C17D2FB1F3A28ULL,
		0x8D74990E1C66F092ULL,
		0xA36E0A231C510BC1ULL,
		0x988819E4ECE86004ULL,
		0x27C7DF29B54C9F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889B403BDC433363ULL,
		0xFF729F749009C295ULL,
		0xA1060C69C85BDC1FULL,
		0x3C24028A0EB17A08ULL,
		0x5C4B4D76195EC641ULL,
		0x2C7E9BF48865F308ULL,
		0xCEF9AE89C5EC8014ULL,
		0xF8901069D279C135ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5CEAD6440F31A2FULL,
		0x61C985B0E60D90BCULL,
		0x6D61E57B7EA62C7FULL,
		0x06F81548EC6DC01FULL,
		0x31294B9803082A51ULL,
		0x76EF6E2E93EB18B9ULL,
		0xC98E6B5B26FBDFF0ULL,
		0x2F37CEBFE2D2DE23ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3772D77656E34DFFULL,
		0x5AF737B32BDA778BULL,
		0x7B821F4C2FDD5E93ULL,
		0x6251366E04D0A5CBULL,
		0x952EE62C5EE7868AULL,
		0x7DAF255D5B86C1D1ULL,
		0x184A454A29B024F2ULL,
		0x9F8E13BC5BF92307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x787870D2239F6596ULL,
		0x358A99593BF0D48EULL,
		0xE640F25A7B95FB19ULL,
		0xCBAA79CC709F5917ULL,
		0x2F72BE3445AA462BULL,
		0xC023D951B2D1B915ULL,
		0xAA7BCA7A09968D26ULL,
		0x38D4A8C918D2809EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEFA66A43343E869ULL,
		0x256C9E59EFE9A2FCULL,
		0x95412CF1B447637AULL,
		0x96A6BCA194314CB3ULL,
		0x65BC27F8193D405EULL,
		0xBD8B4C0BA8B508BCULL,
		0x6DCE7AD0201997CBULL,
		0x66B96AF34326A268ULL
	}};
	sign = 0;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0F4F18FDC7C4CE7ULL,
		0x0183CC02E9A22D7CULL,
		0x29A375626145B022ULL,
		0xE0BE017A01713F04ULL,
		0x4420376BE4055CB5ULL,
		0x6CACD1F34063C470ULL,
		0xC1FA6EDEE9DD34CFULL,
		0x8F6FA7F7A15B2F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC138C5315294CD99ULL,
		0xFD720CE01C2FB0C9ULL,
		0x526654A37C3E3276ULL,
		0x64A072CCF1190543ULL,
		0xFF156127CE44369EULL,
		0xDA54309E558C52C1ULL,
		0xC2C4DB14C9F28B3CULL,
		0xE561F2154F4906E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FBC2C5E89E77F4EULL,
		0x0411BF22CD727CB3ULL,
		0xD73D20BEE5077DABULL,
		0x7C1D8EAD105839C0ULL,
		0x450AD64415C12617ULL,
		0x9258A154EAD771AEULL,
		0xFF3593CA1FEAA992ULL,
		0xAA0DB5E2521228B7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B41C83A7EA708A5ULL,
		0x067E2FDF21DCC5F2ULL,
		0xE15234FF7A9E6A88ULL,
		0x1A4D0045CBE426FDULL,
		0x22035D059684B9E3ULL,
		0x3FA00BA0BFB52A6DULL,
		0x5948BF7109298FDDULL,
		0x958E8569C0F4BF1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE766A482D9F63AF6ULL,
		0x9AAAE5F5B2208AE8ULL,
		0x725391C589B450F9ULL,
		0xCCF9298E3F2CE5D6ULL,
		0xBA03B376D59D1C8AULL,
		0x07153D08E0016946ULL,
		0xFCD183CC597CEFE4ULL,
		0xF98350C93C24594CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63DB23B7A4B0CDAFULL,
		0x6BD349E96FBC3B09ULL,
		0x6EFEA339F0EA198EULL,
		0x4D53D6B78CB74127ULL,
		0x67FFA98EC0E79D58ULL,
		0x388ACE97DFB3C126ULL,
		0x5C773BA4AFAC9FF9ULL,
		0x9C0B34A084D065CDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84F05D72DE846B93ULL,
		0x8BAFCCC266BF577CULL,
		0x415A3D72EA0EC87FULL,
		0x7FBB93FC87C0FF53ULL,
		0x959890048A98FDF8ULL,
		0x558C926297442171ULL,
		0x460EB87948241D91ULL,
		0x3F4049373A394AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE869DE70DF53CC79ULL,
		0x8B57CC531239BB39ULL,
		0x6F04F5AD85D1975BULL,
		0x449170EC969A9012ULL,
		0x107C9944DF75FE07ULL,
		0xC6EC02D251B5D103ULL,
		0x3F93C5B52A13540EULL,
		0x13558A6747B2ED4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C867F01FF309F1AULL,
		0x0058006F54859C42ULL,
		0xD25547C5643D3124ULL,
		0x3B2A230FF1266F40ULL,
		0x851BF6BFAB22FFF1ULL,
		0x8EA08F90458E506EULL,
		0x067AF2C41E10C982ULL,
		0x2BEABECFF2865D5CULL
	}};
	sign = 0;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C2604B6DB5803EEULL,
		0x5621A1043B923088ULL,
		0xE52A5504C8831352ULL,
		0xB577EFDAAD82059DULL,
		0xABEA4A58A976550CULL,
		0x4D4CBF0F23B1E397ULL,
		0xE6321C8625F34C36ULL,
		0xF806ECC1D498B46CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6165E12CE13AB87CULL,
		0xBF1FE8FBA1538AFEULL,
		0xEFDA86FEC4B5EA26ULL,
		0x75468454B0AD5672ULL,
		0xC30973913D014A72ULL,
		0xACF1BEE8EB2CF0D4ULL,
		0xD98CE08A4AC56BE1ULL,
		0xA6F160C6293E18B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AC02389FA1D4B72ULL,
		0x9701B8089A3EA58AULL,
		0xF54FCE0603CD292BULL,
		0x40316B85FCD4AF2AULL,
		0xE8E0D6C76C750A9AULL,
		0xA05B00263884F2C2ULL,
		0x0CA53BFBDB2DE054ULL,
		0x51158BFBAB5A9BB5ULL
	}};
	sign = 0;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD38FE0427C73E15ULL,
		0xF9961B2F64A9391BULL,
		0x3710E8DBD776CDE4ULL,
		0x5C7F12B3FF1F11A0ULL,
		0x19A3CF5EE3CC56F5ULL,
		0x378B3E636B3E48BFULL,
		0x2F83DEBE24902039ULL,
		0xBB0F7FB7F6CEFC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC748213E8C4BF3BULL,
		0x0530CA467C2228B1ULL,
		0xF3D70A7CC6DB115CULL,
		0x275614459E30D4A0ULL,
		0x48194AD4C171C9B4ULL,
		0x7C60EA455BE4D5EFULL,
		0x22CB18AA23530105ULL,
		0x12DDFF0BB1C0A229ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C47BF03F027EDAULL,
		0xF46550E8E887106AULL,
		0x4339DE5F109BBC88ULL,
		0x3528FE6E60EE3CFFULL,
		0xD18A848A225A8D41ULL,
		0xBB2A541E0F5972CFULL,
		0x0CB8C614013D1F33ULL,
		0xA83180AC450E5A5CULL
	}};
	sign = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B8201FDF7586BC4ULL,
		0xCCD954E2E310BA17ULL,
		0xAE7A8003FC2F0300ULL,
		0x02EF9183255CABF5ULL,
		0x92FEE049A80F5F20ULL,
		0x8853C4CF940541F9ULL,
		0x469DCCD3B332FA88ULL,
		0x196590215D85D398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00BE62346F5AEB47ULL,
		0xA24A01C30D4FF772ULL,
		0x797DBF909E37D96EULL,
		0xFFEE5A1D47FAFBABULL,
		0x9F6F29BED047FA7CULL,
		0x472BC6ED35F69C48ULL,
		0x5A15ABDE855E95B1ULL,
		0x88B622CEE5C90F84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AC39FC987FD807DULL,
		0x2A8F531FD5C0C2A5ULL,
		0x34FCC0735DF72992ULL,
		0x03013765DD61B04AULL,
		0xF38FB68AD7C764A3ULL,
		0x4127FDE25E0EA5B0ULL,
		0xEC8820F52DD464D7ULL,
		0x90AF6D5277BCC413ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB070753ACEF5D58ULL,
		0x2CB0BAFB882172A8ULL,
		0xED61DACB7CC5C048ULL,
		0xF8CADB98F5B5D66BULL,
		0xA5D9DD296076252DULL,
		0xCD72A3DE69A656F7ULL,
		0x014E3859605BBFC4ULL,
		0xDACC6679F9460D89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x174951F1B4034200ULL,
		0x7A0408DA68F2AD78ULL,
		0x9B2832193955423BULL,
		0xDC50B8450743C933ULL,
		0x7A9E4DDA6BF91F9CULL,
		0xF1DEC5354144060DULL,
		0x0D64B993F2A8B78BULL,
		0xA8125B6A15B01ECAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93BDB561F8EC1B58ULL,
		0xB2ACB2211F2EC530ULL,
		0x5239A8B243707E0CULL,
		0x1C7A2353EE720D38ULL,
		0x2B3B8F4EF47D0591ULL,
		0xDB93DEA9286250EAULL,
		0xF3E97EC56DB30838ULL,
		0x32BA0B0FE395EEBEULL
	}};
	sign = 0;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA305BFA858F45B7ULL,
		0xB1D559E10A10620DULL,
		0xF76B83C6394BEC84ULL,
		0xA58635BE099E6DC6ULL,
		0x1B671982D5BFDBE3ULL,
		0x9AA9D68430964A41ULL,
		0x6558D1FFF7DAFBC0ULL,
		0x5EDAA82E974939FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF04E7B4BDA3C003ULL,
		0x8AD7D7F6CF74259AULL,
		0xC75C34F91B4A47A9ULL,
		0x837D71464939F0EAULL,
		0x471C2CADD52C6497ULL,
		0xDB6173F57D3DBB99ULL,
		0xD4BED488625E4FDAULL,
		0x3C77D31A20DE2937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB2B7445C7EB85B4ULL,
		0x26FD81EA3A9C3C72ULL,
		0x300F4ECD1E01A4DBULL,
		0x2208C477C0647CDCULL,
		0xD44AECD50093774CULL,
		0xBF48628EB3588EA7ULL,
		0x9099FD77957CABE5ULL,
		0x2262D514766B10C6ULL
	}};
	sign = 0;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84283C6764CA0FBAULL,
		0x159A6CF80657487BULL,
		0xDB0CFDFA8DE404DEULL,
		0x521EE8044F126419ULL,
		0xE79FB22E84F95E78ULL,
		0x5F6757847C5B7E06ULL,
		0x91E4E000E7961213ULL,
		0x2586A6DCB301BA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BA976CC9EA4D05ULL,
		0x7D65FA49F14F7B2FULL,
		0x2597AAF63849B68AULL,
		0x5CB44EDBEDF48EDAULL,
		0xCC371DEEEDB26658ULL,
		0xEC2F5F08158DD7C4ULL,
		0x64EFED10D6F171B7ULL,
		0x7C63268FB9434D26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC16DA4FA9ADFC2B5ULL,
		0x983472AE1507CD4BULL,
		0xB5755304559A4E53ULL,
		0xF56A9928611DD53FULL,
		0x1B68943F9746F81FULL,
		0x7337F87C66CDA642ULL,
		0x2CF4F2F010A4A05BULL,
		0xA923804CF9BE6CF8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBCC7935DED5CE1BULL,
		0x47EF06BB8837071DULL,
		0x01AEC23F36D1C68FULL,
		0x4A63DFC3E4950F91ULL,
		0x86F9858B864088DFULL,
		0x20AF22B5B53F4AB6ULL,
		0x085288982F53DA69ULL,
		0x989F1C793423E8E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AC8ABD32571431AULL,
		0x6360DE5502B16D83ULL,
		0xA961DF6FEF777BECULL,
		0xB5373F4E167EE3F6ULL,
		0x546ECEEF1DD97228ULL,
		0xAE366D1F7A9B99C2ULL,
		0xB208243D1816F759ULL,
		0xADCC776E293682A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4103CD62B9648B01ULL,
		0xE48E28668585999AULL,
		0x584CE2CF475A4AA2ULL,
		0x952CA075CE162B9AULL,
		0x328AB69C686716B6ULL,
		0x7278B5963AA3B0F4ULL,
		0x564A645B173CE30FULL,
		0xEAD2A50B0AED663FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB60E38395903AEEULL,
		0x2674893A93E41A4CULL,
		0xB2DAB64431739FA9ULL,
		0x503FA606981E2616ULL,
		0x935805D21C08EAC6ULL,
		0xBF1B85777144C66AULL,
		0x932D96302EBDCC74ULL,
		0xB7102FBA0ADA08D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28C53DEF0C2745D4ULL,
		0xF1FAE77FF99F2CB4ULL,
		0x3F740992B29FA608ULL,
		0x48776B17EBAECB1BULL,
		0x73203D98B86BB465ULL,
		0x58F6550D603EE3F9ULL,
		0xFA9DEA379E5B0D2CULL,
		0x8AEFBDDDC0B408E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB29BA5948968F51AULL,
		0x3479A1BA9A44ED98ULL,
		0x7366ACB17ED3F9A0ULL,
		0x07C83AEEAC6F5AFBULL,
		0x2037C839639D3661ULL,
		0x6625306A1105E271ULL,
		0x988FABF89062BF48ULL,
		0x2C2071DC4A25FFF8ULL
	}};
	sign = 0;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3FD78302481C96FULL,
		0x901D8F5BE7F26F67ULL,
		0x0221E4836D9F1918ULL,
		0xD5C792443D535A39ULL,
		0x4168AFED88A5498CULL,
		0xAC4D5085FF914BDDULL,
		0xBD7E7CE711494A53ULL,
		0xCFB9365AE6FC7953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA00C866796DB9DEULL,
		0x7B65BCD5FC437FDFULL,
		0x3C2C1A7D7711D113ULL,
		0x72E60E075EA8FC7AULL,
		0xB29D4C037428FE1BULL,
		0xA2B5D7612CD27469ULL,
		0x84AE91D460D7DD64ULL,
		0x5F4B9118D85003F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19FCAFC9AB140F91ULL,
		0x14B7D285EBAEEF88ULL,
		0xC5F5CA05F68D4805ULL,
		0x62E1843CDEAA5DBEULL,
		0x8ECB63EA147C4B71ULL,
		0x09977924D2BED773ULL,
		0x38CFEB12B0716CEFULL,
		0x706DA5420EAC755DULL
	}};
	sign = 0;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E8F3BA3495D2852ULL,
		0xD1EF947C69FB7792ULL,
		0x698D42ED3F190336ULL,
		0x7F3950C8C7803BC2ULL,
		0x62259C3103F895BCULL,
		0x1B946597C5102A1FULL,
		0xA086E7F24CAD9C04ULL,
		0xC5C6DC4B64A8B9E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE883A3B32D9174ULL,
		0xF220FC9C1E1684DCULL,
		0xF53E96C7C49FC869ULL,
		0x0C8E3E14C300862EULL,
		0x50C57DE22BC93639ULL,
		0x4B756A348A009671ULL,
		0x197DD47CF0F70486ULL,
		0xBBE6AE2273E8C21EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41A6B7FF962F96DEULL,
		0xDFCE97E04BE4F2B5ULL,
		0x744EAC257A793ACCULL,
		0x72AB12B4047FB593ULL,
		0x11601E4ED82F5F83ULL,
		0xD01EFB633B0F93AEULL,
		0x870913755BB6977DULL,
		0x09E02E28F0BFF7CAULL
	}};
	sign = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB044D3A53EB298DULL,
		0x3010B01328FD39CFULL,
		0xF6D3407CFE735BBFULL,
		0x290D211EB9EED4BEULL,
		0xD27F454003BD9C1AULL,
		0xE4639CBA80189C7FULL,
		0x91C19F76EDB74E0CULL,
		0xD05D71602B2408BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AE4DE00D55FA996ULL,
		0xF4A6067695A4CF4EULL,
		0x9375D5388FBB29B2ULL,
		0xDD1BFD57276CF6B0ULL,
		0xEC8C208110A8FAEAULL,
		0xBDBA4540055187C6ULL,
		0xBCC3CFA49260503CULL,
		0x8C8FFFFB95EA96B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA01F6F397E8B7FF7ULL,
		0x3B6AA99C93586A81ULL,
		0x635D6B446EB8320CULL,
		0x4BF123C79281DE0EULL,
		0xE5F324BEF314A12FULL,
		0x26A9577A7AC714B8ULL,
		0xD4FDCFD25B56FDD0ULL,
		0x43CD716495397204ULL
	}};
	sign = 0;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0708D214659A8E9ULL,
		0xCE25959B4B748AD3ULL,
		0xB14345B8B3E83F9EULL,
		0x18949494767A72DBULL,
		0xB79495BA47D4A79BULL,
		0x60369F464CA48FFDULL,
		0x9AD81B14DD167C83ULL,
		0xDF6917EABF5E47C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6D1F6DDF27F7173ULL,
		0x013A6A61B7AE6161ULL,
		0x593F1C851BBB0FBEULL,
		0xEC6BFBFE97C9A8F9ULL,
		0x0F7130D74A501C97ULL,
		0xABF53B9136DC5E84ULL,
		0xF796B136E947A812ULL,
		0x5BE027471548462CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x299E964353DA3776ULL,
		0xCCEB2B3993C62972ULL,
		0x58042933982D2FE0ULL,
		0x2C289895DEB0C9E2ULL,
		0xA82364E2FD848B03ULL,
		0xB44163B515C83179ULL,
		0xA34169DDF3CED470ULL,
		0x8388F0A3AA16019CULL
	}};
	sign = 0;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51DF2B55D5BE871DULL,
		0x5288D78E09F7403CULL,
		0x30BFDC9B28792CE0ULL,
		0x7F00986A7FEA8D1CULL,
		0x0E6420FE58280625ULL,
		0xE6EC8CC5C1FB1003ULL,
		0xBA369E464FE53E04ULL,
		0xCC887944D8ABBAB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A12D65E31D8A52ULL,
		0x6C30010979E0A0EEULL,
		0x56F20941EC0CF7B1ULL,
		0x89B4D7AB60184784ULL,
		0x375DE5E79D245796ULL,
		0xDDB784A6F1675190ULL,
		0xBF2A6D30FF8AA4F2ULL,
		0x8762CB196E34EC09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB3DFDEFF2A0FCCBULL,
		0xE658D68490169F4DULL,
		0xD9CDD3593C6C352EULL,
		0xF54BC0BF1FD24597ULL,
		0xD7063B16BB03AE8EULL,
		0x0935081ED093BE72ULL,
		0xFB0C3115505A9912ULL,
		0x4525AE2B6A76CEABULL
	}};
	sign = 0;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF40F0E85ACE3A23ULL,
		0xD2C1AB7C6A5F1CD8ULL,
		0x6DAD93123D3E8E8DULL,
		0xF3DFEB0663DE46D4ULL,
		0x5E93226E8500AFCFULL,
		0x8AFB4A2F6ADBC16AULL,
		0x3439D1122CF7A5F9ULL,
		0x43F8AC972EA629EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63CCFD4F46A50E9ULL,
		0xA6A0DCA828CBB81FULL,
		0x43D01BD47C710032ULL,
		0xDA8F45951072A857ULL,
		0x3B0B6D7083711885ULL,
		0x049CA60827CC2230ULL,
		0xD93067C9E2F2DB2BULL,
		0x00580E5DD8060DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x490421136663E93AULL,
		0x2C20CED4419364B9ULL,
		0x29DD773DC0CD8E5BULL,
		0x1950A571536B9E7DULL,
		0x2387B4FE018F974AULL,
		0x865EA427430F9F3AULL,
		0x5B0969484A04CACEULL,
		0x43A09E3956A01C37ULL
	}};
	sign = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31C4FB6E372A4F96ULL,
		0x250D26E0EF13AB69ULL,
		0x4FFF5576520EAEBCULL,
		0x04BD4911ED6D0C83ULL,
		0xC624C474C7DA4AECULL,
		0x2466C4AC4E9D5053ULL,
		0xB01C8266CA85B5A4ULL,
		0x914E066E3C2A7068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B14CE1BDF2B553ULL,
		0xC7710E6EDA5BA794ULL,
		0x9CF9AE5A53D4125CULL,
		0x3CEB6BD9CFF65B7FULL,
		0xEAA95870D32F8E24ULL,
		0x2E40F1F05F7C43A9ULL,
		0xDC6740230E1F4CB4ULL,
		0xE8A6AE6AD799A9BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC13AE8C79379A43ULL,
		0x5D9C187214B803D4ULL,
		0xB305A71BFE3A9C5FULL,
		0xC7D1DD381D76B103ULL,
		0xDB7B6C03F4AABCC7ULL,
		0xF625D2BBEF210CA9ULL,
		0xD3B54243BC6668EFULL,
		0xA8A758036490C6ADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4E5FF7F19CA93E5ULL,
		0xF099FE64BEC6C883ULL,
		0xC989B12BF9FE64A4ULL,
		0x9A5A942BC0FA082AULL,
		0x5845CFB4279F59DEULL,
		0x5C2A5DD8B7A70F20ULL,
		0x136A17BF2DF4C2D8ULL,
		0x4F6C1570941678F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6909CC190C92C000ULL,
		0x3F058EBFA49C28DDULL,
		0x45F1CB45FEE779C0ULL,
		0x2F96636BB4ACF193ULL,
		0x84DFED7FF1C5E43DULL,
		0x3A8FDF7DBE6978F6ULL,
		0x9A954A0DADB3EB2DULL,
		0x839E2F4E51381124ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BDC33660D37D3E5ULL,
		0xB1946FA51A2A9FA6ULL,
		0x8397E5E5FB16EAE4ULL,
		0x6AC430C00C4D1697ULL,
		0xD365E23435D975A1ULL,
		0x219A7E5AF93D9629ULL,
		0x78D4CDB18040D7ABULL,
		0xCBCDE62242DE67D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4ADE56EC102667D9ULL,
		0x6A057A33BEED1AE5ULL,
		0x26208AFC3F72F7F0ULL,
		0x9BDBA4AFBB763780ULL,
		0x447F4CE49FA45D93ULL,
		0x6FC1B9D3A98EE589ULL,
		0xCEA94324E799742CULL,
		0xA92A31D003E30DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0FCC2775E25054AULL,
		0x6D6E9B542462CFDAULL,
		0xEAA8725F5C748DC8ULL,
		0x2527FA94A0E081C6ULL,
		0x141E9494EFE16EC8ULL,
		0x628E5A7D37D661AEULL,
		0x8F9B90F8990D9D89ULL,
		0x501DD86BE2FC5E09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99E19474B201628FULL,
		0xFC96DEDF9A8A4B0AULL,
		0x3B78189CE2FE6A27ULL,
		0x76B3AA1B1A95B5B9ULL,
		0x3060B84FAFC2EECBULL,
		0x0D335F5671B883DBULL,
		0x3F0DB22C4E8BD6A3ULL,
		0x590C596420E6AFEBULL
	}};
	sign = 0;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2B08C60B21B2C93ULL,
		0x0A6A5511EAE2CEBDULL,
		0xBD62E16A58749032ULL,
		0x69001D24A56BD9BFULL,
		0xC8DF56EA853BCB77ULL,
		0x90E6B46C14770D85ULL,
		0x97A07F498D066E0CULL,
		0xF46D82FCC46FD516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD1368192BC9F15ULL,
		0x084E584C41E8522DULL,
		0x9DC0131C18A7DC05ULL,
		0x300C8DB770F59189ULL,
		0xF711F526A0C53256ULL,
		0xDBEC9E798BCBFAC7ULL,
		0xADCF56FB43C5E24BULL,
		0xFF794DFF7D9525CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64DF55DF1F5E8D7EULL,
		0x021BFCC5A8FA7C90ULL,
		0x1FA2CE4E3FCCB42DULL,
		0x38F38F6D34764836ULL,
		0xD1CD61C3E4769921ULL,
		0xB4FA15F288AB12BDULL,
		0xE9D1284E49408BC0ULL,
		0xF4F434FD46DAAF47ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEDACB4588112DB4ULL,
		0x35397D32C6A82C54ULL,
		0x49C5DA31CC78E582ULL,
		0xD6923E3F13F8D6FDULL,
		0xB823B86ED395EE76ULL,
		0x163483FE76A2D576ULL,
		0xB7207E37F57DB235ULL,
		0x5A95AAB3E8D2D722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE682164DEF325B9ULL,
		0xF96AE2814714EEA1ULL,
		0xE11C135C5FFF8F04ULL,
		0x1A17E0B341966D8AULL,
		0x9B5B818DB193249FULL,
		0xD97C5B909B0A10AFULL,
		0x3ED0F6935BA80D9CULL,
		0x7E7D394A94B3DBBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1072A9E0A91E07FBULL,
		0x3BCE9AB17F933DB3ULL,
		0x68A9C6D56C79567DULL,
		0xBC7A5D8BD2626972ULL,
		0x1CC836E12202C9D7ULL,
		0x3CB8286DDB98C4C7ULL,
		0x784F87A499D5A498ULL,
		0xDC187169541EFB68ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B8402CDF84D8D3CULL,
		0x8E27632CBC1F1D32ULL,
		0x80B080FE4FF197A1ULL,
		0x4212735EAF7FFD5EULL,
		0x2D492283396831CAULL,
		0x8BCBBD18AE66CDC7ULL,
		0xEBE14D560E03F18FULL,
		0xE5DA975E15878E8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B76413DC15D17CAULL,
		0x2798774AC21654ECULL,
		0x011161A54C70D93FULL,
		0x26AE5BB89DC508BEULL,
		0xC5AEE7945BE712D5ULL,
		0x1C925097FA358865ULL,
		0xF44340FCE9848054ULL,
		0x09F3D5F5D4A30ACAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA00DC19036F07572ULL,
		0x668EEBE1FA08C845ULL,
		0x7F9F1F590380BE62ULL,
		0x1B6417A611BAF4A0ULL,
		0x679A3AEEDD811EF5ULL,
		0x6F396C80B4314561ULL,
		0xF79E0C59247F713BULL,
		0xDBE6C16840E483C4ULL
	}};
	sign = 0;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1453200D7202381ULL,
		0x0FFEA22AAA506ECBULL,
		0x610797622007DDBDULL,
		0x93E24B2364467E56ULL,
		0x472F0F274AFA9AE7ULL,
		0x007C663889BA4A75ULL,
		0x5C672CF0BC4569EFULL,
		0x5EA55B9F31DD9CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA871614975DDF14EULL,
		0x6EE8F35C1FFBF9B2ULL,
		0x539F0839BC460B4CULL,
		0x83C4095C682604DFULL,
		0x3C71966FC461466AULL,
		0x3F2E465CFDEA95CCULL,
		0x41C1C3E11137D8D0ULL,
		0xD86702C2A48E7BB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48D3D0B761423233ULL,
		0xA115AECE8A547519ULL,
		0x0D688F2863C1D270ULL,
		0x101E41C6FC207977ULL,
		0x0ABD78B78699547DULL,
		0xC14E1FDB8BCFB4A9ULL,
		0x1AA5690FAB0D911EULL,
		0x863E58DC8D4F2125ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9BB5A4698696898ULL,
		0x55B7FFC4CC25CD0EULL,
		0x9D3287777C10A656ULL,
		0xFC23D48A2C8F9B01ULL,
		0x5D7DD1C56095C645ULL,
		0xFDD594C75BA05138ULL,
		0x36D4E8643E5AA32EULL,
		0x4DEA6EBFEE90B386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93EE0E304342DE7FULL,
		0xCE3717678307C416ULL,
		0xC5ADD9B87E0B6281ULL,
		0xC28431104C357D6AULL,
		0xBB471D66CA43E40FULL,
		0xD40FF5CE95897365ULL,
		0xBDAA85208F4F27FAULL,
		0x99B1C01E0649F987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45CD4C1655268A19ULL,
		0x8780E85D491E08F8ULL,
		0xD784ADBEFE0543D4ULL,
		0x399FA379E05A1D96ULL,
		0xA236B45E9651E236ULL,
		0x29C59EF8C616DDD2ULL,
		0x792A6343AF0B7B34ULL,
		0xB438AEA1E846B9FEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A9E68ABBA639926ULL,
		0x2C9CAC4872823D42ULL,
		0xA60B5B93E08DA20BULL,
		0xE4E168DCFA87B790ULL,
		0xE9BC27A12032E07EULL,
		0xE6E10A7271B9F9C9ULL,
		0x813EA47D103977C6ULL,
		0x7C4B554683997285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AB10245FC17DE29ULL,
		0x67499C43ED7130DCULL,
		0xD8AA569ADF7A80C5ULL,
		0xF45A29F77AA08583ULL,
		0x0790DE93507801C8ULL,
		0xE1344768CBFF32B0ULL,
		0x2276321D59BAC6A3ULL,
		0x74B7FFA58B81EBDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FED6665BE4BBAFDULL,
		0xC553100485110C66ULL,
		0xCD6104F901132145ULL,
		0xF0873EE57FE7320CULL,
		0xE22B490DCFBADEB5ULL,
		0x05ACC309A5BAC719ULL,
		0x5EC8725FB67EB123ULL,
		0x079355A0F81786AAULL
	}};
	sign = 0;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D77D1DCD771DBA5ULL,
		0x03DFDC90085FE71AULL,
		0xE696F04A19265CBBULL,
		0x8859D54245849772ULL,
		0x3D46DD6B5D75159EULL,
		0x47CA465843CEBE8BULL,
		0x122DAF32BF00CA97ULL,
		0x9A6439700E11C090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FD31EFCEC71F5E0ULL,
		0x1645D3B9C8EDF66BULL,
		0xF68851B995EE113DULL,
		0xBD2063DB5CD559DCULL,
		0x23329B00E05A5EC7ULL,
		0x6C6EF5F9370A0F88ULL,
		0xAE79C0D372A0E12FULL,
		0xF53E09F019EAAA21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DA4B2DFEAFFE5C5ULL,
		0xED9A08D63F71F0AEULL,
		0xF00E9E9083384B7DULL,
		0xCB397166E8AF3D95ULL,
		0x1A14426A7D1AB6D6ULL,
		0xDB5B505F0CC4AF03ULL,
		0x63B3EE5F4C5FE967ULL,
		0xA5262F7FF427166EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A1F5AD2EE3ED9EBULL,
		0xD4726974B2966AA8ULL,
		0xB8E8D724DFC00962ULL,
		0x6650171C037F6E91ULL,
		0x743FDF4807315C82ULL,
		0x989D96F8E7B9F55CULL,
		0x01078D108F597E18ULL,
		0xFADB58BFF2A9B675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC238DCBDBBA703BEULL,
		0x01B8348E964FCB3BULL,
		0x03D42C0CD37918F7ULL,
		0x3F883BED5304E556ULL,
		0x1CDBAB432F127F45ULL,
		0x23F97AE2D53A2194ULL,
		0xB181DFF337CF9B6DULL,
		0x39606BD4CE3F54DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57E67E153297D62DULL,
		0xD2BA34E61C469F6CULL,
		0xB514AB180C46F06BULL,
		0x26C7DB2EB07A893BULL,
		0x57643404D81EDD3DULL,
		0x74A41C16127FD3C8ULL,
		0x4F85AD1D5789E2ABULL,
		0xC17AECEB246A619AULL
	}};
	sign = 0;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1138151280DDAB97ULL,
		0x24B42B98D46024F8ULL,
		0x2784D24563D5750FULL,
		0xF7A95DA5F5041C46ULL,
		0xDE6F050BC7A3A350ULL,
		0xFDA5673F41D25C67ULL,
		0xF049CDBEC4BC759CULL,
		0x19CBC90645E24E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x834D1B4D123AD65BULL,
		0xDF6A79CB3A7DBC60ULL,
		0xD4F4A94AA70A5316ULL,
		0x92334C59C82AA9F5ULL,
		0x7DB58D3E3855DA54ULL,
		0xAF3853E217B75314ULL,
		0xD8055ED3657E0F0BULL,
		0xC44B9EC7286B3A33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DEAF9C56EA2D53CULL,
		0x4549B1CD99E26897ULL,
		0x529028FABCCB21F8ULL,
		0x6576114C2CD97250ULL,
		0x60B977CD8F4DC8FCULL,
		0x4E6D135D2A1B0953ULL,
		0x18446EEB5F3E6691ULL,
		0x55802A3F1D7713CDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FA82A2B7C190F98ULL,
		0xCE7A0CE92443988AULL,
		0x338875A361598B21ULL,
		0x9CD7990EADF31751ULL,
		0xBA9B629528976F44ULL,
		0x41D6024B2C72BA46ULL,
		0xDBE859D9DCBDC228ULL,
		0xF6B9A0E464B558C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x925ABD62AB3D430CULL,
		0x09F664130B3E303DULL,
		0xF512A82CD15ACF06ULL,
		0x217FC59E3DA05DC9ULL,
		0x189EBD7C8C23C622ULL,
		0x60E5AB389C32794EULL,
		0x991479131874155FULL,
		0x252205534E575899ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D4D6CC8D0DBCC8CULL,
		0xC483A8D61905684CULL,
		0x3E75CD768FFEBC1BULL,
		0x7B57D3707052B987ULL,
		0xA1FCA5189C73A922ULL,
		0xE0F05712904040F8ULL,
		0x42D3E0C6C449ACC8ULL,
		0xD1979B91165E0027ULL
	}};
	sign = 0;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7388BEA98454B296ULL,
		0xE13337DB2A33058CULL,
		0x049C94C936AE311DULL,
		0x9A5AD69C84177CD5ULL,
		0x30966B19BA9BE52DULL,
		0xF5BED9A2A092FF2EULL,
		0xC45C8163C7F23411ULL,
		0xCDFB712E7FE0EFECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D477139C97F6D58ULL,
		0xF758B85949130B95ULL,
		0xA8DB078C4E9E5F7EULL,
		0xA8B827A8B9B67851ULL,
		0xB675705E5A6C185EULL,
		0xF558182DD51211EBULL,
		0xD2B5876DD262E837ULL,
		0xB81FB55110507710ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06414D6FBAD5453EULL,
		0xE9DA7F81E11FF9F7ULL,
		0x5BC18D3CE80FD19EULL,
		0xF1A2AEF3CA610483ULL,
		0x7A20FABB602FCCCEULL,
		0x0066C174CB80ED42ULL,
		0xF1A6F9F5F58F4BDAULL,
		0x15DBBBDD6F9078DBULL
	}};
	sign = 0;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79C1280B65828E02ULL,
		0x92294CEA436B214EULL,
		0x027FFF70AAE811A9ULL,
		0xC0BF49FCAA31E4FAULL,
		0x24FE06BA77C2F1D0ULL,
		0x3B5A465E4A7A77FAULL,
		0x93F0015D4FEF90DEULL,
		0x3C78CAAD5DA84F3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD051A689878E8D7BULL,
		0x47F0652B3AEC82BDULL,
		0x99121A4B6243BF9CULL,
		0xBD089D29B86739B9ULL,
		0x06EB16B01E3CD449ULL,
		0x8D6E5B933E1A630EULL,
		0x0F1AE0693F45DA06ULL,
		0xD109763DDF1ACD16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA96F8181DDF40087ULL,
		0x4A38E7BF087E9E90ULL,
		0x696DE52548A4520DULL,
		0x03B6ACD2F1CAAB40ULL,
		0x1E12F00A59861D87ULL,
		0xADEBEACB0C6014ECULL,
		0x84D520F410A9B6D7ULL,
		0x6B6F546F7E8D8227ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99693EEA6A4D399CULL,
		0x1740CA00B294AFDDULL,
		0x38CC986F1B9B7D2EULL,
		0xB50339CD8604F5B5ULL,
		0xA98BE56BF81FAC3FULL,
		0xD3AF4C045069E1CAULL,
		0x69D97CEAE262E487ULL,
		0xF68C78594F41A1FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D39A2F795D2C11ULL,
		0x4DE6688469342BD2ULL,
		0xA11D4FE55DE5043DULL,
		0xF83C8F67D6D850C9ULL,
		0xFA9AC7F1B9F776ABULL,
		0xA9B42802E8B3949CULL,
		0x6DAFF296F0137F70ULL,
		0x7F9F110AE65F99C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE295A4BAF0F00D8BULL,
		0xC95A617C4960840AULL,
		0x97AF4889BDB678F0ULL,
		0xBCC6AA65AF2CA4EBULL,
		0xAEF11D7A3E283593ULL,
		0x29FB240167B64D2DULL,
		0xFC298A53F24F6517ULL,
		0x76ED674E68E20834ULL
	}};
	sign = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F389226DF87BE34ULL,
		0xE6BC92B16F3B9129ULL,
		0xC21407B4AF4385AAULL,
		0xD078218CF8FC2310ULL,
		0x81704186A2AA8414ULL,
		0x8C64328834C813B8ULL,
		0x176477C979AA191AULL,
		0x52CC85D20E038E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C880A19528BB2DULL,
		0x711B5741F212F4E4ULL,
		0x2AC45D4A9F4F0366ULL,
		0x9CFA84864D0B8072ULL,
		0x22903D27AC3D2EFBULL,
		0xE23A0A3C1F54AD6AULL,
		0xE5720A99BFB31F38ULL,
		0x8CA3D4106749BE61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE67011854A5F0307ULL,
		0x75A13B6F7D289C44ULL,
		0x974FAA6A0FF48244ULL,
		0x337D9D06ABF0A29EULL,
		0x5EE0045EF66D5519ULL,
		0xAA2A284C1573664EULL,
		0x31F26D2FB9F6F9E1ULL,
		0xC628B1C1A6B9CFE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1DF9AE9E6394937ULL,
		0x70FAFBBBAD600330ULL,
		0x319F3966A97AC3EEULL,
		0x1125C853FACEBBA9ULL,
		0xFD55144204080159ULL,
		0xEC6A9FB5B534273AULL,
		0xFCDF5AF36BA55F4EULL,
		0x206A106D209F38AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD2144B57224F88ULL,
		0xECEEB893E6AE7734ULL,
		0x636386832175F47DULL,
		0x82A3F81FF7FFF703ULL,
		0x206C54F277B75967ULL,
		0xE9C7854E020CE6FAULL,
		0xD73F37D35700F110ULL,
		0x1D4C4DC76271837AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x820D869E8F16F9AFULL,
		0x840C4327C6B18BFCULL,
		0xCE3BB2E38804CF70ULL,
		0x8E81D03402CEC4A5ULL,
		0xDCE8BF4F8C50A7F1ULL,
		0x02A31A67B3274040ULL,
		0x25A0232014A46E3EULL,
		0x031DC2A5BE2DB534ULL
	}};
	sign = 0;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x010FC8947265B765ULL,
		0x3495CC5CC8637BD6ULL,
		0x41064EE070EE1E59ULL,
		0xAD3A6B1BBDB0D3F3ULL,
		0xBC0DE8A0B61C0E3BULL,
		0x615F562E2FB2E286ULL,
		0x23568B4D3089F606ULL,
		0x9BFA854CEF8E0695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E14F61A23DFD0C7ULL,
		0x49E22585242FADD0ULL,
		0x77CF7D94FAADFD49ULL,
		0x0F56EACFA5860581ULL,
		0xF957E80DF6D29EEFULL,
		0x542AF260CAF8EA63ULL,
		0x85657782CB099ED6ULL,
		0x2CBD77422669C28BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92FAD27A4E85E69EULL,
		0xEAB3A6D7A433CE05ULL,
		0xC936D14B7640210FULL,
		0x9DE3804C182ACE71ULL,
		0xC2B60092BF496F4CULL,
		0x0D3463CD64B9F822ULL,
		0x9DF113CA65805730ULL,
		0x6F3D0E0AC9244409ULL
	}};
	sign = 0;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63B7D89225E0F30EULL,
		0x7662CB11E92BAF1FULL,
		0xC61F13B1FD4A5303ULL,
		0x0E68EDC85EE0DCD4ULL,
		0x1C7F7E13FA7E4FCEULL,
		0x5DA4934A4C774238ULL,
		0x7AC6DF31303A29BFULL,
		0x1AB5C7842137F8DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BDB154EF6F4AB7ULL,
		0x4FC50AEDA6C2BEA2ULL,
		0xDFB4EAF3DD8AD8DBULL,
		0xD869B44722681222ULL,
		0x8F5478C7701DAED1ULL,
		0xB6C7BF10C3D3D6AFULL,
		0x4B6AFEE084AAF501ULL,
		0xACE989E672D793EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CFA273D3671A857ULL,
		0x269DC0244268F07CULL,
		0xE66A28BE1FBF7A28ULL,
		0x35FF39813C78CAB1ULL,
		0x8D2B054C8A60A0FCULL,
		0xA6DCD43988A36B88ULL,
		0x2F5BE050AB8F34BDULL,
		0x6DCC3D9DAE6064F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9052C0549686FC3ULL,
		0x5509589CD37B1ED5ULL,
		0xABB5E46584DF1ECEULL,
		0x366520D111217427ULL,
		0x9C63983A0A3BC7C4ULL,
		0x0B5202060C489628ULL,
		0xBFEEF696CAE677D1ULL,
		0x934DFB7C348A4647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E017BCEA557C42ULL,
		0x2A7E6C35EFC78800ULL,
		0x76E91D61DC2439CCULL,
		0xF34A211ECD673781ULL,
		0xF6C5EAA934E28510ULL,
		0xFA851DF64B430EBFULL,
		0xF1BF4A3801512D65ULL,
		0xE692CD992819F1A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB12514485F12F381ULL,
		0x2A8AEC66E3B396D5ULL,
		0x34CCC703A8BAE502ULL,
		0x431AFFB243BA3CA6ULL,
		0xA59DAD90D55942B3ULL,
		0x10CCE40FC1058768ULL,
		0xCE2FAC5EC9954A6BULL,
		0xACBB2DE30C7054A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82FDFA8F83C29994ULL,
		0xD27D3C818BF82497ULL,
		0x9C3B54C6E7801B8EULL,
		0x1D31C1794C096EA5ULL,
		0xE08BD1AB4FAA1A21ULL,
		0x0324E9C0CDA2029DULL,
		0xCBAE0DBA669E8876ULL,
		0x1AC7153535A8DF3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0441B03A533DD8ULL,
		0x548CCCAD7A819283ULL,
		0x605738B4AB6CA4FCULL,
		0x445842EE17A18453ULL,
		0x8162288D82D3EE86ULL,
		0x0792044750985F9CULL,
		0x0B60A9D6D6416E14ULL,
		0xCB377EBB2B0D1B46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74F9B8DF496F5BBCULL,
		0x7DF06FD411769214ULL,
		0x3BE41C123C137692ULL,
		0xD8D97E8B3467EA52ULL,
		0x5F29A91DCCD62B9AULL,
		0xFB92E5797D09A301ULL,
		0xC04D63E3905D1A61ULL,
		0x4F8F967A0A9BC3F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5EB9C4B945EA19CULL,
		0x8878593BF1471FE9ULL,
		0xF82C41455D9DE3A4ULL,
		0xF4E8752361467B2FULL,
		0xA4BE2ABFC107AA14ULL,
		0xC1CB0F2FF63EE8A4ULL,
		0xFA72D59745AB426CULL,
		0xC56D9D471C0D5593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7491F4489F0FF570ULL,
		0x43164854F8D6C583ULL,
		0xD7873005AD94F767ULL,
		0xC1D6FA6D17672496ULL,
		0xE1C2280AEF502E11ULL,
		0x42FF1F8FEDF2F77EULL,
		0x44256CFF8EE72AB7ULL,
		0x4413632DF5C9B92EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6159A802F54EAC2CULL,
		0x456210E6F8705A66ULL,
		0x20A5113FB008EC3DULL,
		0x33117AB649DF5699ULL,
		0xC2FC02B4D1B77C03ULL,
		0x7ECBEFA0084BF125ULL,
		0xB64D6897B6C417B5ULL,
		0x815A3A1926439C65ULL
	}};
	sign = 0;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EEEB70ED5F5C673ULL,
		0x3CF8B7B4CEE8F0F1ULL,
		0x89C9D606FE4E7C04ULL,
		0xD9EDF9BBB3307F41ULL,
		0x862928B632D6E775ULL,
		0x590C6F20CD4B8748ULL,
		0xADF7752B54A27F7FULL,
		0x8C9CCF8F39D88EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9120DAF161DF0ADEULL,
		0xE011E82D9945120EULL,
		0x7B8E9F4210107EB7ULL,
		0xCC4C2B66922BFBC9ULL,
		0xB895ECFAFE3CBAC7ULL,
		0x2FE9913B600B110AULL,
		0x84CAB88616754421ULL,
		0x46538902BD801310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DCDDC1D7416BB95ULL,
		0x5CE6CF8735A3DEE2ULL,
		0x0E3B36C4EE3DFD4CULL,
		0x0DA1CE5521048378ULL,
		0xCD933BBB349A2CAEULL,
		0x2922DDE56D40763DULL,
		0x292CBCA53E2D3B5EULL,
		0x4649468C7C587BA7ULL
	}};
	sign = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E6F47D3CAA6EEDAULL,
		0xC4009104EAC0B725ULL,
		0x96C7BFA7980FFDD0ULL,
		0x93C280B46404001FULL,
		0x4E4561B4C9C6A01DULL,
		0xBA0CABAA4EE0B885ULL,
		0x36A2DD1471C1F77DULL,
		0xEDF2CE8CACEEDCF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x899273FE771C7315ULL,
		0xAFE786D7A4C09855ULL,
		0x9E16575393418ECFULL,
		0x686848BB549406A9ULL,
		0x1CA67E3314E95BC9ULL,
		0x11C04D74930B9E49ULL,
		0x371C57C9ECFDB581ULL,
		0xE51CDE508388C0C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4DCD3D5538A7BC5ULL,
		0x14190A2D46001ECFULL,
		0xF8B1685404CE6F01ULL,
		0x2B5A37F90F6FF975ULL,
		0x319EE381B4DD4454ULL,
		0xA84C5E35BBD51A3CULL,
		0xFF86854A84C441FCULL,
		0x08D5F03C29661C2DULL
	}};
	sign = 0;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F6D5F00E8B1BA89ULL,
		0xEDA8080E84A37DEAULL,
		0xA3E2A71123B7288AULL,
		0xF50B617F8E993A5FULL,
		0x6A25D02BEB0C12DDULL,
		0x0CE150DEC18F172FULL,
		0x7019121D8C10F618ULL,
		0xEA962EACE8A10A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E336E17B7DFB66ULL,
		0x6BCE9054C7174294ULL,
		0xB3CDCA4B7C6D5DD5ULL,
		0x3DF969B9B6E57969ULL,
		0x799522484BEBC4EBULL,
		0xB49510814629E243ULL,
		0x54072C8A36C61E5DULL,
		0xC05E931615B09CD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD8A281F6D33BF23ULL,
		0x81D977B9BD8C3B55ULL,
		0xF014DCC5A749CAB5ULL,
		0xB711F7C5D7B3C0F5ULL,
		0xF090ADE39F204DF2ULL,
		0x584C405D7B6534EBULL,
		0x1C11E593554AD7BAULL,
		0x2A379B96D2F06DC8ULL
	}};
	sign = 0;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D273E7E84CD724BULL,
		0xE95EE74FB015C8D2ULL,
		0x41C7BFCF55876EF1ULL,
		0x87B17FCD18AB8D35ULL,
		0xD15D52A919C64177ULL,
		0x89ED6D6D0F9F59F7ULL,
		0x198D7B4CB6142C48ULL,
		0x51FB6347CBE4ED3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4E3902B01E86DAULL,
		0x0E9EAFAB0163E92CULL,
		0x336D5B58BF4706BEULL,
		0xCF65FE19981EAA5AULL,
		0x9F03BFD925461382ULL,
		0x1B311B0F744AF35FULL,
		0x89665DDA1DBDAF9CULL,
		0xF7D087486189E561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FD9057BD4AEEB71ULL,
		0xDAC037A4AEB1DFA6ULL,
		0x0E5A647696406833ULL,
		0xB84B81B3808CE2DBULL,
		0x325992CFF4802DF4ULL,
		0x6EBC525D9B546698ULL,
		0x90271D7298567CACULL,
		0x5A2ADBFF6A5B07DCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x348165D44177F9C2ULL,
		0xCBAF9133E39DE587ULL,
		0xE32A9C3271123FE0ULL,
		0x4EBC1790816F211DULL,
		0xB13B03ABE364F703ULL,
		0xD90C595D12FBD8D0ULL,
		0xBAD4B78CFECB107CULL,
		0xBC02DC37D3F6DB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1ACC6361BAD2CC9ULL,
		0x67AE4F611BE52668ULL,
		0xB23A37A7C4F66378ULL,
		0xE7548AE0A42F9E53ULL,
		0xD9E289B33B44716DULL,
		0xE749AD576342EC79ULL,
		0x2E505343F5B6A4ECULL,
		0x41E384DF8D37B030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72D49F9E25CACCF9ULL,
		0x640141D2C7B8BF1EULL,
		0x30F0648AAC1BDC68ULL,
		0x67678CAFDD3F82CAULL,
		0xD75879F8A8208595ULL,
		0xF1C2AC05AFB8EC56ULL,
		0x8C84644909146B8FULL,
		0x7A1F575846BF2B66ULL
	}};
	sign = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC50CFA6DC05A0F3CULL,
		0x178383C94BA5B515ULL,
		0x16D22688DE932485ULL,
		0xE1C165755C6FD87CULL,
		0xF327F08960947996ULL,
		0x6EEE6B5655A8858DULL,
		0x380CB7AB419511E5ULL,
		0xB397A3014F60FEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF26765A0F87D1B0ULL,
		0xBC2E0DBEEF542AEBULL,
		0x61A826C92C0BA14DULL,
		0x3629C745CC0A916FULL,
		0xE1E8F2FD469781D0ULL,
		0x91A9387A905D34BAULL,
		0x21ADE75BCDE57779ULL,
		0x42E94409638A4AF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5E68413B0D23D8CULL,
		0x5B55760A5C518A29ULL,
		0xB529FFBFB2878337ULL,
		0xAB979E2F9065470CULL,
		0x113EFD8C19FCF7C6ULL,
		0xDD4532DBC54B50D3ULL,
		0x165ED04F73AF9A6BULL,
		0x70AE5EF7EBD6B3E7ULL
	}};
	sign = 0;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38D83CD2F603480AULL,
		0xF1F7661C7AB26487ULL,
		0x44178D89F2E98746ULL,
		0x87932746EB09B627ULL,
		0x750B6F99E8BBA8CFULL,
		0xA9935A7B6C8AC983ULL,
		0x14A267A76B3648F2ULL,
		0xE70D02F767B9312CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF58AE49A9F25A1DULL,
		0x430E2CF0E3C6A2D9ULL,
		0xBEBA72BF8692F1C7ULL,
		0xEAC8CCDECE9B993AULL,
		0x67F5F26B0CE60377ULL,
		0xAA00356B5FD51042ULL,
		0x367EC47B8FFF816DULL,
		0xF5E3D71DB41AB172ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x897F8E894C10EDEDULL,
		0xAEE9392B96EBC1ADULL,
		0x855D1ACA6C56957FULL,
		0x9CCA5A681C6E1CECULL,
		0x0D157D2EDBD5A557ULL,
		0xFF9325100CB5B941ULL,
		0xDE23A32BDB36C784ULL,
		0xF1292BD9B39E7FB9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99FBA83F3A5729BAULL,
		0x1EC49FA228688F0AULL,
		0x8A3FDCCF4A2AAC03ULL,
		0x637F614854F24338ULL,
		0x3CCEB71AAA84E0E6ULL,
		0x6FEC1EF43993A8E3ULL,
		0x6146BFE8B2BD989AULL,
		0xCA41205E389D2482ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD0FEC54A661161ULL,
		0xDBCC3B6E47E3E14AULL,
		0xB409BD57A2E9D2D1ULL,
		0x9ECA6D1432138803ULL,
		0x4F931B275B0D2A2AULL,
		0x5F1EBC16D45E4180ULL,
		0x2C6C71AF3FB85CE7ULL,
		0xD5FD08E98CBB0355ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E2AA979EFF11859ULL,
		0x42F86433E084ADC0ULL,
		0xD6361F77A740D931ULL,
		0xC4B4F43422DEBB34ULL,
		0xED3B9BF34F77B6BBULL,
		0x10CD62DD65356762ULL,
		0x34DA4E3973053BB3ULL,
		0xF4441774ABE2212DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A643B1F5084A093ULL,
		0x5E84C3B852FF5A28ULL,
		0x0C854BC2C0FDC2C5ULL,
		0x4B0D1370F031E86BULL,
		0xE563977A5FFEA549ULL,
		0xDA636F9760DA5C2DULL,
		0x854D3A3A2029FAC6ULL,
		0x26279A027DAE18E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B135D459756B5C9ULL,
		0xBBC5F458018742A3ULL,
		0xD035E7772554142FULL,
		0x0E15B62344ED9A81ULL,
		0x4DD6D99D5095EE2AULL,
		0xB9413EA9E4D9BA41ULL,
		0x0B6841E7A28FDBA1ULL,
		0xE18687B7BC692D72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F50DDD9B92DEACAULL,
		0xA2BECF6051781785ULL,
		0x3C4F644B9BA9AE95ULL,
		0x3CF75D4DAB444DE9ULL,
		0x978CBDDD0F68B71FULL,
		0x212230ED7C00A1ECULL,
		0x79E4F8527D9A1F25ULL,
		0x44A1124AC144EB76ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D7C1BC42D31B5F1ULL,
		0x63A2B1E5DDA12F81ULL,
		0xDA4B4B407C4C497CULL,
		0x1A5E9CE5838DA527ULL,
		0x61CDEB62485BB492ULL,
		0x26E9ADCCFA49DB6FULL,
		0x0737C207E4675CD9ULL,
		0x53ED1DAF1CA67602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6A51BD43432B7BBULL,
		0x7CD5C95793772796ULL,
		0xEDBA92D7B763E17FULL,
		0xFD650DDBD584120AULL,
		0xD55C4A8213139CE2ULL,
		0xB92476A7C1B7358CULL,
		0x8F7378563001A05EULL,
		0x48251AEFA06375DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46D6FFEFF8FEFE36ULL,
		0xE6CCE88E4A2A07EAULL,
		0xEC90B868C4E867FCULL,
		0x1CF98F09AE09931CULL,
		0x8C71A0E0354817AFULL,
		0x6DC537253892A5E2ULL,
		0x77C449B1B465BC7AULL,
		0x0BC802BF7C430024ULL
	}};
	sign = 0;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x320098D9A53EBDF0ULL,
		0x94A39135E6244CC6ULL,
		0x7A5BDC5FA923206BULL,
		0xF29251168A7998C5ULL,
		0xADCBBBFA208F59BCULL,
		0x202C289A0A4132CCULL,
		0x1731F217B5883735ULL,
		0xE83528F1059A0312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E43334B231F65EULL,
		0xE0A33EF573621298ULL,
		0x379BCB602BAA828CULL,
		0x4F1444BA36A09CC4ULL,
		0x23253A6F87B930EFULL,
		0xF3088EC33EFD1372ULL,
		0xC1D9C7D0024C1753ULL,
		0x83ECFA444DCEF5E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED1C65A4F30CC792ULL,
		0xB400524072C23A2DULL,
		0x42C010FF7D789DDEULL,
		0xA37E0C5C53D8FC01ULL,
		0x8AA6818A98D628CDULL,
		0x2D2399D6CB441F5AULL,
		0x55582A47B33C1FE1ULL,
		0x64482EACB7CB0D31ULL
	}};
	sign = 0;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA948025DAD45071ULL,
		0xF768938AFECA7FECULL,
		0x9A1E1837B2D37B87ULL,
		0xEDD2D5FA28CC1D57ULL,
		0x54C80230EB008074ULL,
		0xBB048B796736C4DFULL,
		0x3EF89AB85F67002BULL,
		0xF1B4E3E4D45213BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2290FA734DC1FF58ULL,
		0x76CAFA747233291AULL,
		0x8FD2647F39787364ULL,
		0x7855894CAA86F72DULL,
		0x3E173635D055A8F8ULL,
		0xB405CC3BB7EFEE30ULL,
		0xE71CC8B0F02B158FULL,
		0xA2CEECD808F41D8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC80385B28D125119ULL,
		0x809D99168C9756D2ULL,
		0x0A4BB3B8795B0823ULL,
		0x757D4CAD7E45262AULL,
		0x16B0CBFB1AAAD77CULL,
		0x06FEBF3DAF46D6AFULL,
		0x57DBD2076F3BEA9CULL,
		0x4EE5F70CCB5DF62FULL
	}};
	sign = 0;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01C0CE0222621A0BULL,
		0xEB3E080E50AFE032ULL,
		0xC784D962C67DF4A9ULL,
		0x2418568509BD84F2ULL,
		0x71A02857D8701C4BULL,
		0x2000950985DD91CCULL,
		0x48FD923E18F0B68BULL,
		0x2A464FF2F61D0615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA9E214B6177390ULL,
		0x8CC83ADE17314F6EULL,
		0x1AEEA59B6BAFF9E9ULL,
		0x6381C970326E4067ULL,
		0xAC8373C116747F53ULL,
		0x14C6CAFCAFA878E4ULL,
		0xEA879D6FD9D914B0ULL,
		0xC80200F343F73C1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE616EBED6C4AA67BULL,
		0x5E75CD30397E90C3ULL,
		0xAC9633C75ACDFAC0ULL,
		0xC0968D14D74F448BULL,
		0xC51CB496C1FB9CF7ULL,
		0x0B39CA0CD63518E7ULL,
		0x5E75F4CE3F17A1DBULL,
		0x62444EFFB225C9F7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFAEC485B8878298ULL,
		0x089E3DFE0DAF939BULL,
		0xFC9BC095AD59BBC6ULL,
		0x2555981A541E72BAULL,
		0xEDE4EF032B3FCC42ULL,
		0x9948CC9014E5E30BULL,
		0x8FF5BB0CDB8CD9D3ULL,
		0x9516C3669476E29EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67033D36830567C8ULL,
		0xBC5692E59F76FB22ULL,
		0xD4DA7C5A6098B230ULL,
		0x73552D12667D1268ULL,
		0x1C5E957080D05827ULL,
		0x9E45CCCCABAB5258ULL,
		0x9732BA7FEE3B13FAULL,
		0x45635BA35975ED04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98AB874F35821AD0ULL,
		0x4C47AB186E389879ULL,
		0x27C1443B4CC10995ULL,
		0xB2006B07EDA16052ULL,
		0xD1865992AA6F741AULL,
		0xFB02FFC3693A90B3ULL,
		0xF8C3008CED51C5D8ULL,
		0x4FB367C33B00F599ULL
	}};
	sign = 0;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x782D75B9CB78BB25ULL,
		0xA2DFF988630CDB72ULL,
		0x328784868E2B836FULL,
		0x4B8EFBE626D5A574ULL,
		0xB947E2604133D838ULL,
		0x7997470312FC1A3EULL,
		0x9F67E06493DC18D0ULL,
		0x5007DD834FFAC3F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD80C3D9389A7B9ULL,
		0x554EDA5356B04ED7ULL,
		0xEFF36588E57E3B37ULL,
		0x7D454CAD6F4BD66CULL,
		0xA9AF57900F5F3893ULL,
		0x66ED04091F74034EULL,
		0x7DC9FD973CAC2224ULL,
		0x6EE9A8AB7C3F8987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD55697C37EF136CULL,
		0x4D911F350C5C8C9AULL,
		0x42941EFDA8AD4838ULL,
		0xCE49AF38B789CF07ULL,
		0x0F988AD031D49FA4ULL,
		0x12AA42F9F38816F0ULL,
		0x219DE2CD572FF6ACULL,
		0xE11E34D7D3BB3A6BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A68C44C0EAE9F59ULL,
		0x7A0DE609A836846CULL,
		0x528E7444E0429C65ULL,
		0xCC60E48F36D9E9A2ULL,
		0x8B528F9DC60D5305ULL,
		0x4DC2A78554E03FBEULL,
		0x6C5F0B8DC132F48AULL,
		0xB1AEBE1C9B36F8B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59117B64D2EC2764ULL,
		0x52E25385341920C0ULL,
		0x44CC6F47B7D1EAEEULL,
		0x7FEF4E69B9879761ULL,
		0x47575BBDB399021AULL,
		0x3624A91E19200C76ULL,
		0x8319AA310135CA65ULL,
		0xCD36F4B0FCAC724FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x315748E73BC277F5ULL,
		0x272B9284741D63ACULL,
		0x0DC204FD2870B177ULL,
		0x4C7196257D525241ULL,
		0x43FB33E0127450EBULL,
		0x179DFE673BC03348ULL,
		0xE945615CBFFD2A25ULL,
		0xE477C96B9E8A8664ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE573E174B27AB31EULL,
		0x97F57595F7634B80ULL,
		0xF634D171494EFC8EULL,
		0x6D8074ADD2AB69C9ULL,
		0x21884A4B3DB71BB6ULL,
		0xA37919C6FE22B1A3ULL,
		0x4642934BCA86BB2DULL,
		0x7EE500F5F1807C78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15625F238B457C5ULL,
		0x17FB7CF5510ECE78ULL,
		0xB4317AF9B27DC9A6ULL,
		0x0D867DE356ED057DULL,
		0x9853D22B9E611930ULL,
		0x66672E42F2383AE5ULL,
		0xE279618D9B9F998DULL,
		0x64C1D68C07D1FF0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x141DBB8279C65B59ULL,
		0x7FF9F8A0A6547D08ULL,
		0x4203567796D132E8ULL,
		0x5FF9F6CA7BBE644CULL,
		0x8934781F9F560286ULL,
		0x3D11EB840BEA76BDULL,
		0x63C931BE2EE721A0ULL,
		0x1A232A69E9AE7D6AULL
	}};
	sign = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E9B1E928B88654AULL,
		0x69904DB085FA324DULL,
		0xCE2BF0A97E87CA1CULL,
		0x21F84E497B22007AULL,
		0x4994CA809F9A9FEAULL,
		0x23AE76E5521A4816ULL,
		0x0B8953E4B84EE539ULL,
		0x45CA0E97B25F8E11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D762E5DD671235FULL,
		0xC2B0E2C9D04CA760ULL,
		0xC48A1D3855C62BD1ULL,
		0xC80A3B0844890CECULL,
		0x62D4CC6317DBA2BDULL,
		0xCF723E75F3A47F52ULL,
		0x449384CAE0646157ULL,
		0x127B0EB159D24CB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF124F034B51741EBULL,
		0xA6DF6AE6B5AD8AECULL,
		0x09A1D37128C19E4AULL,
		0x59EE13413698F38EULL,
		0xE6BFFE1D87BEFD2CULL,
		0x543C386F5E75C8C3ULL,
		0xC6F5CF19D7EA83E1ULL,
		0x334EFFE6588D4159ULL
	}};
	sign = 0;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77FC15BDA94005E7ULL,
		0xE18EE53D48E9C5C2ULL,
		0x005ECC54EB80CD39ULL,
		0x3244B03BEC68C0B6ULL,
		0x22EE568291080BD8ULL,
		0x4D94B05A1CF3A3A3ULL,
		0x439104746D1B1843ULL,
		0xED17BB7B7CDFD47DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0445DA651524FDDEULL,
		0xE65F3F1EE4146717ULL,
		0xDCD2BBD4D5427CE9ULL,
		0x15448001B6271F4AULL,
		0x9DE62DE9D6A6C2A3ULL,
		0x8659557854B8BDD0ULL,
		0x40528BDE9553DCE8ULL,
		0xBE70E380CF9C01D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73B63B58941B0809ULL,
		0xFB2FA61E64D55EABULL,
		0x238C1080163E504FULL,
		0x1D00303A3641A16BULL,
		0x85082898BA614935ULL,
		0xC73B5AE1C83AE5D2ULL,
		0x033E7895D7C73B5AULL,
		0x2EA6D7FAAD43D2AAULL
	}};
	sign = 0;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4C7E79291F0ADF4ULL,
		0x584DBF487D642673ULL,
		0xEFCD2E8DAF2DCB02ULL,
		0xA16B6387486341D5ULL,
		0x7EB6FFB1D6361CFAULL,
		0x6AC8F5E2B3E1B8E3ULL,
		0x188BB4FE35DDFA33ULL,
		0x66E4C440251ED053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A093475F8983C74ULL,
		0xC652DEC3C2F7DC52ULL,
		0x2D982942A5E7FFF4ULL,
		0xBCD91C9DA4AB726FULL,
		0xF5B87A5685629EAFULL,
		0x6FEA61DF7D458AB0ULL,
		0x43DBC69136A7EFE3ULL,
		0x950953D9DF82A679ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ABEB31C99587180ULL,
		0x91FAE084BA6C4A21ULL,
		0xC235054B0945CB0DULL,
		0xE49246E9A3B7CF66ULL,
		0x88FE855B50D37E4AULL,
		0xFADE9403369C2E32ULL,
		0xD4AFEE6CFF360A4FULL,
		0xD1DB7066459C29D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B0095CF9696243EULL,
		0x456E593253BD3301ULL,
		0xFD5830C7B3E1DF06ULL,
		0xBC6FAD2F4C38C8E4ULL,
		0x780E68736E8C10BFULL,
		0x10280F59FFAB7385ULL,
		0x37B43CAE30892CCBULL,
		0x2431B4C58129F60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0211C48D9EC5D02DULL,
		0x9B430DB93F3FB8EEULL,
		0xB2A46C10B88FC25EULL,
		0xA24507F81F812C7BULL,
		0xC7ADD78BFEF1E682ULL,
		0xEA84033DB0FCE265ULL,
		0x0D5571017E1D1DF7ULL,
		0x91D30FE99A38CB2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58EED141F7D05411ULL,
		0xAA2B4B79147D7A13ULL,
		0x4AB3C4B6FB521CA7ULL,
		0x1A2AA5372CB79C69ULL,
		0xB06090E76F9A2A3DULL,
		0x25A40C1C4EAE911FULL,
		0x2A5ECBACB26C0ED3ULL,
		0x925EA4DBE6F12ADFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB24F462C8803497ULL,
		0x2630A5F12973DFB0ULL,
		0x41E86E44485CA107ULL,
		0x1D2114147A443BF7ULL,
		0xC90D964E7F953A86ULL,
		0xCE8DC441A675A51AULL,
		0x34CF9E2E490527BEULL,
		0x758DE8568CE3B95CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02414E7D4A3AB6D7ULL,
		0xBB1CD12684D2A804ULL,
		0x534D4A5D25AB3C55ULL,
		0x6720DF66BF44638FULL,
		0xAD05245958AB858FULL,
		0x7C6A0BD0835CA358ULL,
		0x0F86676151F5CA4BULL,
		0x819966BC6BA9F855ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8E3A5E57E457DC0ULL,
		0x6B13D4CAA4A137ACULL,
		0xEE9B23E722B164B1ULL,
		0xB60034ADBAFFD867ULL,
		0x1C0871F526E9B4F6ULL,
		0x5223B871231901C2ULL,
		0x254936CCF70F5D73ULL,
		0xF3F4819A2139C107ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4A7BB008F96500CULL,
		0xEEF137A99BC5D973ULL,
		0xEA600A91898A1BE8ULL,
		0x07136AF9C81FBD67ULL,
		0xB0DD61872757DE64ULL,
		0x31DF1E07AE190BC3ULL,
		0x6C261153E0249C0CULL,
		0x11D7E0469655A0A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46908C80D8E39EBULL,
		0x5489DF35E6B78156ULL,
		0x1CB38AA56EB2199AULL,
		0xE474494D0438C163ULL,
		0x5641D0D13E07FF0AULL,
		0xD4BA4A741F46B448ULL,
		0xC28904BF30D2910BULL,
		0xF62262C773556F9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x103EB23882081621ULL,
		0x9A675873B50E581DULL,
		0xCDAC7FEC1AD8024EULL,
		0x229F21ACC3E6FC04ULL,
		0x5A9B90B5E94FDF59ULL,
		0x5D24D3938ED2577BULL,
		0xA99D0C94AF520B00ULL,
		0x1BB57D7F23003101ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDAAD3B447BF6D39ULL,
		0xA09D8F993F454A63ULL,
		0x32DB09803322EAA8ULL,
		0x930BD3B676D20E75ULL,
		0x90BAEA62FD0B3BF2ULL,
		0x9BB02FC7A1E54CDCULL,
		0x378C1D891FC13AD8ULL,
		0x91E21CFB68198E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E332D9992D2DEAULL,
		0x841BD57595394AA7ULL,
		0x94EFFB6A8DC089E2ULL,
		0x061E229A08678184ULL,
		0x156BE22BE39874E8ULL,
		0x396003DEA2C0F174ULL,
		0xC6B6EDFA8C98228CULL,
		0xA09CDF95B81CD8CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98C7A0DAAE923F4FULL,
		0x1C81BA23AA0BFFBCULL,
		0x9DEB0E15A56260C6ULL,
		0x8CEDB11C6E6A8CF0ULL,
		0x7B4F08371972C70AULL,
		0x62502BE8FF245B68ULL,
		0x70D52F8E9329184CULL,
		0xF1453D65AFFCB53AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F98B05E6A1DD8B3ULL,
		0xE67A66542D691A6AULL,
		0xB149B0CD751C75A7ULL,
		0x26955B8F65077A4FULL,
		0x298CB38C8418ED00ULL,
		0xED5C5A922CCA534EULL,
		0x80AB1D0D07CBE0BCULL,
		0xA2A1B49739096696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D07FE7026E3A1E0ULL,
		0x633F3A95772C3C33ULL,
		0xA807F248110DB494ULL,
		0x48F050856FC4D31FULL,
		0xF01C707ADB3C39BCULL,
		0xB8B6BCEF9753D8A1ULL,
		0x7D2F6B7241C8F070ULL,
		0x4094414AA82A9951ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA290B1EE433A36D3ULL,
		0x833B2BBEB63CDE36ULL,
		0x0941BE85640EC113ULL,
		0xDDA50B09F542A730ULL,
		0x39704311A8DCB343ULL,
		0x34A59DA295767AACULL,
		0x037BB19AC602F04CULL,
		0x620D734C90DECD45ULL
	}};
	sign = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6AAF33F4CFCE2D8ULL,
		0xFDBEF43F57C903C7ULL,
		0x95C24FB726D5C32FULL,
		0xB9E9F9904A56EE25ULL,
		0xD8F899CDE7F1913CULL,
		0xC87D6ACC4701F22BULL,
		0x056C7C4672912C4CULL,
		0x03650CD0C20BE06DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4CC9CC9DCC1391ULL,
		0xF2D0B194E3F1F8FBULL,
		0xB60C79EAF1D50847ULL,
		0x7B97866CC9F94A6FULL,
		0x06F2526F25AB2827ULL,
		0xCF671545A2DFE561ULL,
		0xF016301A9A461C86ULL,
		0x4522E884234F79EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x895E2972AF30CF47ULL,
		0x0AEE42AA73D70ACCULL,
		0xDFB5D5CC3500BAE8ULL,
		0x3E527323805DA3B5ULL,
		0xD206475EC2466915ULL,
		0xF9165586A4220CCAULL,
		0x15564C2BD84B0FC5ULL,
		0xBE42244C9EBC667EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFD55CD5482C5B87ULL,
		0x70CE10031329FA0FULL,
		0x86BEE8CB581C866CULL,
		0x0B0026E754870B05ULL,
		0x7C7B578158EF4647ULL,
		0x9C1DFBB9769ED406ULL,
		0xDED425DD63953042ULL,
		0x562F1898AD0DDD28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B910431B55BBDA3ULL,
		0xBB90A6FB076761A0ULL,
		0x90803784513B04D0ULL,
		0xACCEA95D491A041AULL,
		0x20AB81EC12D2878DULL,
		0xAB9EB7037D764FB1ULL,
		0x03B7DC575700982DULL,
		0x3F20907E45B3D3AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x744458A392D09DE4ULL,
		0xB53D69080BC2986FULL,
		0xF63EB14706E1819BULL,
		0x5E317D8A0B6D06EAULL,
		0x5BCFD595461CBEB9ULL,
		0xF07F44B5F9288455ULL,
		0xDB1C49860C949814ULL,
		0x170E881A675A097AULL
	}};
	sign = 0;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2BF7DEFD417B73AULL,
		0xFF1F2EE059C82367ULL,
		0x5A75F2F035A6A645ULL,
		0x37DAAD75657788AEULL,
		0x437D21F779EC5002ULL,
		0x7ACF89221DF951ABULL,
		0xC4B504F60C80B043ULL,
		0x79009D39EA361FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA95BE148628151ULL,
		0xEEFF09DEE5C01FBCULL,
		0xE5D188EFF4B690DCULL,
		0x1AAD9E0D0DA9E41AULL,
		0x6E2836DCDBF7A9D5ULL,
		0xD573F14DD72802ADULL,
		0xB9C3A32B0086C6FCULL,
		0x5F8C8DD4CB57824CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2616220E8BB535E9ULL,
		0x10202501740803ABULL,
		0x74A46A0040F01569ULL,
		0x1D2D0F6857CDA493ULL,
		0xD554EB1A9DF4A62DULL,
		0xA55B97D446D14EFDULL,
		0x0AF161CB0BF9E946ULL,
		0x19740F651EDE9D90ULL
	}};
	sign = 0;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD8C826E9DF96DE3ULL,
		0x61644CD35923D8C1ULL,
		0xD6CC9C4BAD4A44C4ULL,
		0xBF75400A22F4C2DAULL,
		0xF255A5884616E786ULL,
		0x532288AAB43A7F27ULL,
		0x5BD6D60FEFB4D33EULL,
		0xBB0D1C6B0E91DE2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4086CB38DA8A7C7BULL,
		0x3E55B93BACE7EBCAULL,
		0xC49ADEBD26155848ULL,
		0xCB1FF5BAAAD584EDULL,
		0xCBEA04530C8FC065ULL,
		0x1F38568B18A6DA75ULL,
		0xCB5834457CC15404ULL,
		0xEAB461496D9BDE06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D05B735C36EF168ULL,
		0x230E9397AC3BECF7ULL,
		0x1231BD8E8734EC7CULL,
		0xF4554A4F781F3DEDULL,
		0x266BA13539872720ULL,
		0x33EA321F9B93A4B2ULL,
		0x907EA1CA72F37F3AULL,
		0xD058BB21A0F60026ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ECA1468C2562D22ULL,
		0xC7FCAD85C81C5225ULL,
		0xA9C86BCCE2637B64ULL,
		0xBB77078DDF338218ULL,
		0x97647009F2F1661FULL,
		0xC7A7F0BE92EA5A70ULL,
		0x0193DF833F195A7AULL,
		0x667EFA05CBBE9D6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE999217D828581DEULL,
		0xDAC5A1E82CACC51FULL,
		0x8F62A7871C431AAFULL,
		0x1808E93B8426B147ULL,
		0xAE82B3AA8FCE463EULL,
		0xAF94E385ED4E5F0BULL,
		0x5706BA62388D644FULL,
		0xE4847DF7C0022E6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3530F2EB3FD0AB44ULL,
		0xED370B9D9B6F8D05ULL,
		0x1A65C445C62060B4ULL,
		0xA36E1E525B0CD0D1ULL,
		0xE8E1BC5F63231FE1ULL,
		0x18130D38A59BFB64ULL,
		0xAA8D2521068BF62BULL,
		0x81FA7C0E0BBC6EFEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD76E51B03CEA0B61ULL,
		0x611EEC6B5DD6DE14ULL,
		0x493446493A31FDD8ULL,
		0x6E79C07787C50579ULL,
		0xA08FA4C4C4AF5187ULL,
		0x951D5A17D8286D77ULL,
		0x2049CE778E1F7F98ULL,
		0xA78A16A8CB195B72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24367DE4DCD45A1FULL,
		0x2288C45AFB784575ULL,
		0x04C1E922D15A24EFULL,
		0xE357E21DD0A643D4ULL,
		0x319570B8F4547D0CULL,
		0x23DFB380D917FECDULL,
		0xC751D34440E92901ULL,
		0x204AF7AC1C3FF044ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB337D3CB6015B142ULL,
		0x3E962810625E989FULL,
		0x44725D2668D7D8E9ULL,
		0x8B21DE59B71EC1A5ULL,
		0x6EFA340BD05AD47AULL,
		0x713DA696FF106EAAULL,
		0x58F7FB334D365697ULL,
		0x873F1EFCAED96B2DULL
	}};
	sign = 0;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0367DC12D7A38514ULL,
		0x9AFF9696E930CF9DULL,
		0x1FA1191E331E0533ULL,
		0x143DBAD9666CF9BDULL,
		0xFEBF38CD94F4497AULL,
		0x3931C28104E3EF0FULL,
		0xCE962841D5F05CA1ULL,
		0xE88903AC34D33604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5654E880D3D45D1ULL,
		0x1837D4078696B4BAULL,
		0x23F7EF0B8C005BF9ULL,
		0x10FD414A2ADE92A5ULL,
		0xDBF9FFC42515339AULL,
		0xA396A744BECA43CFULL,
		0x162301B4C7529DE9ULL,
		0x4A4478D94255D826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E028D8ACA663F43ULL,
		0x82C7C28F629A1AE2ULL,
		0xFBA92A12A71DA93AULL,
		0x0340798F3B8E6717ULL,
		0x22C539096FDF15E0ULL,
		0x959B1B3C4619AB40ULL,
		0xB873268D0E9DBEB7ULL,
		0x9E448AD2F27D5DDEULL
	}};
	sign = 0;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24D037BE09216CC7ULL,
		0x02D34052525CE547ULL,
		0xAFCEF3F128E20C74ULL,
		0xC0132330D2EDA66AULL,
		0x28DB9E81B4AE2695ULL,
		0x49641A7A0E11E2C8ULL,
		0x1ED79F6723F5D020ULL,
		0x8DCB1CCF3A9053CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DFD82933D78096ULL,
		0xCD7CEBF58E1BB16AULL,
		0x634BA64BB44095DFULL,
		0xE6DBEF825A0B22C5ULL,
		0xF0606ED9B415DA98ULL,
		0x88C4EDAD9EE62F98ULL,
		0x27A332768F0EA028ULL,
		0x155329CE609BB022ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CF05F94D549EC31ULL,
		0x3556545CC44133DCULL,
		0x4C834DA574A17694ULL,
		0xD93733AE78E283A5ULL,
		0x387B2FA800984BFCULL,
		0xC09F2CCC6F2BB32FULL,
		0xF7346CF094E72FF7ULL,
		0x7877F300D9F4A3ABULL
	}};
	sign = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33230E4A69FD6CD2ULL,
		0x0F98CFA883002EBDULL,
		0x0E702562AD2321DEULL,
		0xEFAD6600949A357CULL,
		0x48B49CD0D7608C4FULL,
		0x56EA19B5999A57E6ULL,
		0xC195A5613EB39163ULL,
		0xE86F0A8126526C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9FD5148CACE81AULL,
		0x66C74076A3A5A0A5ULL,
		0x1407A358E029DF0CULL,
		0x968A194F64FC84E2ULL,
		0x444E084F36120131ULL,
		0x7FF87E5D5649B786ULL,
		0x21A5E4CAE112CA55ULL,
		0x4927FF8027571070ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7833935DD5084B8ULL,
		0xA8D18F31DF5A8E17ULL,
		0xFA688209CCF942D1ULL,
		0x59234CB12F9DB099ULL,
		0x04669481A14E8B1EULL,
		0xD6F19B584350A060ULL,
		0x9FEFC0965DA0C70DULL,
		0x9F470B00FEFB5C27ULL
	}};
	sign = 0;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4A5A69684B1E813ULL,
		0xC0B77E6F7735A5FBULL,
		0xE63D528C9AD1D1CEULL,
		0xC68A562C3F98CA3FULL,
		0x933666FE91C3F769ULL,
		0x0CE13A06DE4DA000ULL,
		0x89E94AA2131F0894ULL,
		0x9309E558F38F16BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB897640411CC7743ULL,
		0xACFED70CCD4C6CEFULL,
		0xC806368E541F487FULL,
		0x2646E1EA0205C9A2ULL,
		0x143D03F5AA5D68A1ULL,
		0xC9302BCE405E1AC2ULL,
		0x4515755E9AF3A727ULL,
		0xBD0260FB3ACE6B10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C0E429272E570D0ULL,
		0x13B8A762A9E9390CULL,
		0x1E371BFE46B2894FULL,
		0xA04374423D93009DULL,
		0x7EF96308E7668EC8ULL,
		0x43B10E389DEF853EULL,
		0x44D3D543782B616CULL,
		0xD607845DB8C0ABAAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2207F72D0CE92B1ULL,
		0x5FFA2F275770C135ULL,
		0x51DD93378BF5A9CAULL,
		0x22B9CD46297F929CULL,
		0x50BC039EFEFD2B73ULL,
		0xAF29E5947F2A2796ULL,
		0x0CE0FBEA1209906DULL,
		0xE98C2839DD249595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E23A464E9D51E9BULL,
		0x2BBA2219C2706749ULL,
		0x7E78091CFE93AFC3ULL,
		0x202AC76A963920CFULL,
		0x173EC4427BC12D76ULL,
		0xD85FD0979F38E976ULL,
		0x3372F48C5990A029ULL,
		0x09B11DACDF41B833ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93FCDB0DE6F97416ULL,
		0x34400D0D950059ECULL,
		0xD3658A1A8D61FA07ULL,
		0x028F05DB934671CCULL,
		0x397D3F5C833BFDFDULL,
		0xD6CA14FCDFF13E20ULL,
		0xD96E075DB878F043ULL,
		0xDFDB0A8CFDE2DD61ULL
	}};
	sign = 0;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4F2B18138859CE8ULL,
		0xF14CBF3837145F2DULL,
		0xAA1BF3476AE7FFD9ULL,
		0x1FFE261ECFDDB04CULL,
		0x15E85E122E049DE0ULL,
		0xA643214F923717B9ULL,
		0xC314AD33FF817730ULL,
		0xA16AE37B3F579115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x399FC4BDFFCEFEC7ULL,
		0x9B532035800C483AULL,
		0x82C3CD5D00F3473FULL,
		0x21BA9D9E8C7CBA9DULL,
		0x2A8590A7D92C126FULL,
		0x3213445CAA9B2E51ULL,
		0x7FB88B759B1757CCULL,
		0xA34A0C5666DA8764ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B52ECC338B69E21ULL,
		0x55F99F02B70816F3ULL,
		0x275825EA69F4B89AULL,
		0xFE4388804360F5AFULL,
		0xEB62CD6A54D88B70ULL,
		0x742FDCF2E79BE967ULL,
		0x435C21BE646A1F64ULL,
		0xFE20D724D87D09B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5501E40873FD2ECULL,
		0xA424CF4B2362C935ULL,
		0x07E137FE477AB271ULL,
		0xC22460B8194E6333ULL,
		0x5A635F0DE51332ABULL,
		0x1BC61B7AAF62BEA5ULL,
		0x2F336D108588CBBBULL,
		0xB7D02BF0F26C3A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5661EBD085FDF3BBULL,
		0xCC007186D22DE5A7ULL,
		0xCDD08940906CD35AULL,
		0x65A87A9E8C6F4C7FULL,
		0xEF8D4ED82AAF34ACULL,
		0x1EDF7225D7770603ULL,
		0x08827F8DFAF63961ULL,
		0x78BB8BD711B17284ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EEE32700141DF31ULL,
		0xD8245DC45134E38EULL,
		0x3A10AEBDB70DDF16ULL,
		0x5C7BE6198CDF16B3ULL,
		0x6AD61035BA63FDFFULL,
		0xFCE6A954D7EBB8A1ULL,
		0x26B0ED828A929259ULL,
		0x3F14A019E0BAC7D1ULL
	}};
	sign = 0;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04FC08B42F4C59F9ULL,
		0x4DBCCB0F2F52A227ULL,
		0xA1CB5402980351F2ULL,
		0xE2B50A5CD1E647B1ULL,
		0xDE67BE40297BE0A9ULL,
		0x5E453F4180781C3FULL,
		0x2E20F1A5CEDBDCF8ULL,
		0x038D98B3A43E86CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x332363ED2027F67CULL,
		0x98B380960B464E7BULL,
		0x2781B110C45950B1ULL,
		0x07CC107170353EA9ULL,
		0x66526F4BC219A27EULL,
		0xE45D7C2344A777F4ULL,
		0x646D89A57AB6EEB0ULL,
		0xF35A8542EBFA87E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1D8A4C70F24637DULL,
		0xB5094A79240C53ABULL,
		0x7A49A2F1D3AA0140ULL,
		0xDAE8F9EB61B10908ULL,
		0x78154EF467623E2BULL,
		0x79E7C31E3BD0A44BULL,
		0xC9B368005424EE47ULL,
		0x10331370B843FEE8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70FD3B3B86D7787BULL,
		0x37D45C35B415906FULL,
		0x798A3350BA1D081FULL,
		0xCD9C3710CD4077EAULL,
		0xBBD0FBDC6206AF1FULL,
		0xFB0DD4D886FAF391ULL,
		0x5054F9D507D747B1ULL,
		0x1A5A9A46CC94848BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DA8753EE8B957F2ULL,
		0x59621E44DC69C19AULL,
		0xC645B6087855AC43ULL,
		0x189E2B2F3A79CF67ULL,
		0x3D15A4F54AD08B15ULL,
		0xB97951F7879986BBULL,
		0x024AF393F675D274ULL,
		0x3C69123F9249B0E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1354C5FC9E1E2089ULL,
		0xDE723DF0D7ABCED5ULL,
		0xB3447D4841C75BDBULL,
		0xB4FE0BE192C6A882ULL,
		0x7EBB56E71736240AULL,
		0x419482E0FF616CD6ULL,
		0x4E0A06411161753DULL,
		0xDDF188073A4AD3A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A23C4158D140FD6ULL,
		0xE61D845494F7311AULL,
		0xC8393837AA4D040DULL,
		0xB42C8682D737C33EULL,
		0x059262933C96C2EBULL,
		0x276A2D75E3D01CD1ULL,
		0xC70AAA997194EBFBULL,
		0x0A9E92F334ACD1AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B62D42DE7C21C28ULL,
		0x2D3908BE7B404534ULL,
		0x975933E05734FCA1ULL,
		0x462CC9B5C55AB43FULL,
		0xB38D76BD842FA15DULL,
		0x24FDC2B5681370D1ULL,
		0x099374426894AFB7ULL,
		0xFB247FFD86840291ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC0EFE7A551F3AEULL,
		0xB8E47B9619B6EBE5ULL,
		0x30E004575318076CULL,
		0x6DFFBCCD11DD0EFFULL,
		0x5204EBD5B867218EULL,
		0x026C6AC07BBCABFFULL,
		0xBD77365709003C44ULL,
		0x0F7A12F5AE28CF19ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4902419BEB67D38ULL,
		0xC126DB60882C3D3BULL,
		0xE7C8B26BD2F7FC8CULL,
		0x840D56EBCAF1E360ULL,
		0xE2E0282FED2E468DULL,
		0xBB461F53F547603AULL,
		0xA4C4423DE3CABDC8ULL,
		0x306C61FC3BDE756DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AB07EFDE408BE8EULL,
		0xEDF334098DF994E7ULL,
		0x3F7E1A9A56BF67CAULL,
		0x0ABF2D0657F03111ULL,
		0xAD8F966BD8D92D28ULL,
		0x6DE1FF4559B2BE66ULL,
		0xBA498B9D577FD7C1ULL,
		0x458EADBCCC37F456ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59DFA51BDAADBEAAULL,
		0xD333A756FA32A854ULL,
		0xA84A97D17C3894C1ULL,
		0x794E29E57301B24FULL,
		0x355091C414551965ULL,
		0x4D64200E9B94A1D4ULL,
		0xEA7AB6A08C4AE607ULL,
		0xEADDB43F6FA68116ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4C45966BEC0768BULL,
		0x2352A2CD06218EF8ULL,
		0x32D2546266641DAEULL,
		0x9A26553BD24BF52AULL,
		0xB0C77C3716D51015ULL,
		0xEAFCD86584AD5AA7ULL,
		0xE4C8C80B407A6DA8ULL,
		0x733903CAEAF3AA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7E2417D5D6F7D2FULL,
		0x62F457637908670EULL,
		0x6926C175DF1C8A79ULL,
		0x6835F17B56829BEDULL,
		0x276562C31201B16DULL,
		0x082BE7188BA081DDULL,
		0x50DAE40086B0F094ULL,
		0x9BBB887A5F4CEDD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECE217E96150F95CULL,
		0xC05E4B698D1927E9ULL,
		0xC9AB92EC87479334ULL,
		0x31F063C07BC9593CULL,
		0x8962197404D35EA8ULL,
		0xE2D0F14CF90CD8CAULL,
		0x93EDE40AB9C97D14ULL,
		0xD77D7B508BA6BCB3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B7897C00D34E7E4ULL,
		0x8BAC14A2A5CF2503ULL,
		0xAF3528E22EBC8133ULL,
		0x77EF0A55A0410AFCULL,
		0x1B294DDA820A76BBULL,
		0xE7A71294DCAAA4C1ULL,
		0x4A294A9A6E541B16ULL,
		0x99B282A6E5D6F3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA370A7CDA4CE8719ULL,
		0x816AED1ED02A7507ULL,
		0xCE5EABA927740888ULL,
		0xEF1BCE0F1841A164ULL,
		0x968E8D1FDFD90A65ULL,
		0x83AF70A15EB236B7ULL,
		0x73389953C50B5C17ULL,
		0x9EC09695A534824AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE807EFF2686660CBULL,
		0x0A412783D5A4AFFBULL,
		0xE0D67D39074878ABULL,
		0x88D33C4687FF6997ULL,
		0x849AC0BAA2316C55ULL,
		0x63F7A1F37DF86E09ULL,
		0xD6F0B146A948BEFFULL,
		0xFAF1EC1140A2716FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11EF231C879D35A4ULL,
		0x58FC28B7961184ADULL,
		0xB15C65045AF1E1CCULL,
		0x04B2D9FA6FF705EAULL,
		0x8FD7102664E03440ULL,
		0x7118B261FB38C257ULL,
		0xA61C44DE86EF2B3BULL,
		0xAA38342D395A97E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D9DA3F3276EDA44ULL,
		0xBB46E891CF2ED12EULL,
		0xD71F63FA4973C8B7ULL,
		0x9811E06C6BBCCB1CULL,
		0x4CBFD57E02EAB1B7ULL,
		0x3C40442A5FE8CCA7ULL,
		0x39A3CC017CABE496ULL,
		0x736839F7B0E82AA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04517F29602E5B60ULL,
		0x9DB54025C6E2B37FULL,
		0xDA3D010A117E1914ULL,
		0x6CA0F98E043A3ACDULL,
		0x43173AA861F58288ULL,
		0x34D86E379B4FF5B0ULL,
		0x6C7878DD0A4346A5ULL,
		0x36CFFA3588726D3EULL
	}};
	sign = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2420BE23317B1B7CULL,
		0x767D0C6572F987D7ULL,
		0xFE37DB7FBF6DE16DULL,
		0x53D057A99D62E675ULL,
		0x46D9245C64D1CD24ULL,
		0x421017F18FBBA751ULL,
		0x395AE7A961B3B27AULL,
		0x09EEA8F35A5733A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9226B021EE4DE767ULL,
		0xB8C675F829649811ULL,
		0x5F19083776509A4AULL,
		0x5E241659EDFD735FULL,
		0xD17FEF22094B1B2DULL,
		0x132FDEE90C85D17CULL,
		0x7ADE6ED66FA7A94BULL,
		0xD601C5EE2F9CAC9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91FA0E01432D3415ULL,
		0xBDB6966D4994EFC5ULL,
		0x9F1ED348491D4722ULL,
		0xF5AC414FAF657316ULL,
		0x7559353A5B86B1F6ULL,
		0x2EE039088335D5D4ULL,
		0xBE7C78D2F20C092FULL,
		0x33ECE3052ABA8708ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8CD1B52981DF3DAULL,
		0x47203080ACE5F362ULL,
		0x5F15B48136139F1BULL,
		0x86C02AF4C3C5ECCFULL,
		0xAF5A7E1A16049DD0ULL,
		0x09127F25A2C81B37ULL,
		0xD67CE31879C50984ULL,
		0xD7BE4A3D57C2DDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E65EFFDDA9B29C6ULL,
		0x675EBDD4389BA6ECULL,
		0xFB898912B6BB848CULL,
		0x3532712FF2D8B162ULL,
		0x90278E93E764BB9DULL,
		0xD67F58063CE278F1ULL,
		0xEF892F1EAB2B4F57ULL,
		0x69F4CC70565A828AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A672B54BD82CA14ULL,
		0xDFC172AC744A4C76ULL,
		0x638C2B6E7F581A8EULL,
		0x518DB9C4D0ED3B6CULL,
		0x1F32EF862E9FE233ULL,
		0x3293271F65E5A246ULL,
		0xE6F3B3F9CE99BA2CULL,
		0x6DC97DCD01685B25ULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1909E73DD666EFDULL,
		0x7D56EC375C8EAB76ULL,
		0x241FB2988B18A51FULL,
		0x761CB48DF9106644ULL,
		0xE06579D0E0F5A466ULL,
		0xB2489772DC315ACDULL,
		0x70603178D91A3295ULL,
		0xEF5F6C4708D34640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE230D6403AF7A020ULL,
		0xF61F9F5DAC44B180ULL,
		0xDEC6E5EFB98D2523ULL,
		0x554872B6C4F4D0E6ULL,
		0xF6506CE025DB63C7ULL,
		0xCF3C067958C04DF6ULL,
		0xF7D62CED82A2260BULL,
		0xB7F87C095DDCB8E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF5FC833A26ECEDDULL,
		0x87374CD9B049F9F5ULL,
		0x4558CCA8D18B7FFBULL,
		0x20D441D7341B955DULL,
		0xEA150CF0BB1A409FULL,
		0xE30C90F983710CD6ULL,
		0x788A048B56780C89ULL,
		0x3766F03DAAF68D5FULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7BC272FDC7E48F5ULL,
		0x83858BD26857A9F6ULL,
		0x8E68FF86249CFE5EULL,
		0xAF4153C22093A8BAULL,
		0xA18257DBB3026104ULL,
		0x325199C84D07E802ULL,
		0xFF3AD81579BFDC38ULL,
		0xA406EF20E23F5DFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x068042ABC45D2776ULL,
		0x2C9450574AFC2DE5ULL,
		0x6C6AD62099310B42ULL,
		0xBEBDF85BC6CEFE6EULL,
		0x34F0F37D49E059D5ULL,
		0x9CE72EB06C1E748CULL,
		0x7C38754CFE02E1F2ULL,
		0xC8DF881F6612E8F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB13BE4841821217FULL,
		0x56F13B7B1D5B7C11ULL,
		0x21FE29658B6BF31CULL,
		0xF0835B6659C4AA4CULL,
		0x6C91645E6922072EULL,
		0x956A6B17E0E97376ULL,
		0x830262C87BBCFA45ULL,
		0xDB2767017C2C750BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32C174B8A8DB6674ULL,
		0x16069FA514D00607ULL,
		0x0ADBD461FC88389AULL,
		0xE9A588B1D178859BULL,
		0x1EEF3566D9E6F763ULL,
		0x2517659AA941F09BULL,
		0x6C3756F79B19BC98ULL,
		0x43D35BAF2D4C2B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0256D890BB7F921ULL,
		0x704ADACCD9075A53ULL,
		0x36DAC6BEC461769FULL,
		0x4F75E27CEFD2C19EULL,
		0xC299EE155B35C70BULL,
		0x46C92F902A3ADF19ULL,
		0x850B5BAD7F68AEB2ULL,
		0x0388AFCF45B36E12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x629C072F9D236D53ULL,
		0xA5BBC4D83BC8ABB3ULL,
		0xD4010DA33826C1FAULL,
		0x9A2FA634E1A5C3FCULL,
		0x5C5547517EB13058ULL,
		0xDE4E360A7F071181ULL,
		0xE72BFB4A1BB10DE5ULL,
		0x404AABDFE798BD18ULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C8AA8360679D39CULL,
		0x5AA22354C0F1C4D4ULL,
		0x6F2971048266650EULL,
		0x56929B741B1A38A2ULL,
		0x0940E4F848576F5DULL,
		0x60B76B0068607884ULL,
		0x58C2DBF7A685B7F9ULL,
		0x2C8F3B97F5DAD11DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x355AE931D04892A7ULL,
		0x43F6C72DCE7D6701ULL,
		0x14FAE8E937DF301DULL,
		0x97DAF609B92B4965ULL,
		0x2948A2B41CC1443FULL,
		0x071E5DFA410FC7E5ULL,
		0xBF5DDF54497ECE11ULL,
		0x396F30880F90AEE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x672FBF04363140F5ULL,
		0x16AB5C26F2745DD3ULL,
		0x5A2E881B4A8734F1ULL,
		0xBEB7A56A61EEEF3DULL,
		0xDFF842442B962B1DULL,
		0x59990D062750B09EULL,
		0x9964FCA35D06E9E8ULL,
		0xF3200B0FE64A2233ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C154E04E4218C74ULL,
		0x3934EF7B002B58AAULL,
		0xD198DDC635D9A46AULL,
		0x6783B3767B8FFF91ULL,
		0xC88AF2027EDEFEF9ULL,
		0xA561AA3719640456ULL,
		0x4E440791C54B8D9FULL,
		0x709B75689520AE4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE770AC81C491B6F1ULL,
		0x140911F271B89B3EULL,
		0x93CBCE765A88DAB7ULL,
		0x20DBBA82BDCA2DA8ULL,
		0x59856634FD287BA5ULL,
		0x0A074AA2506E2BEBULL,
		0x80655838B19DC796ULL,
		0x412DC04FD60AAC26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94A4A1831F8FD583ULL,
		0x252BDD888E72BD6BULL,
		0x3DCD0F4FDB50C9B3ULL,
		0x46A7F8F3BDC5D1E9ULL,
		0x6F058BCD81B68354ULL,
		0x9B5A5F94C8F5D86BULL,
		0xCDDEAF5913ADC609ULL,
		0x2F6DB518BF160224ULL
	}};
	sign = 0;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6E3161898816926ULL,
		0xA91070C1F80B8AB3ULL,
		0xE5BADCADDF0B5BE5ULL,
		0x89725264BF320D65ULL,
		0x7A1426B122A00033ULL,
		0x1B9ECBC29E2AB350ULL,
		0x4ACA9646A9FFE7DAULL,
		0xB1EBE133BCD04FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C02AB88EACBEDCULL,
		0xAB2B56F56AC612D7ULL,
		0xA8EDA4DE1063BE4FULL,
		0x34AF93FE1AFD7E0AULL,
		0xB307E968DCDBA7B0ULL,
		0xB2463E00DD1DC419ULL,
		0xB36CACC79294745AULL,
		0x1BDFBD8DADE44D96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF22EB6009D4AA4AULL,
		0xFDE519CC8D4577DBULL,
		0x3CCD37CFCEA79D95ULL,
		0x54C2BE66A4348F5BULL,
		0xC70C3D4845C45883ULL,
		0x69588DC1C10CEF36ULL,
		0x975DE97F176B737FULL,
		0x960C23A60EEC022EULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89FA856CF5502945ULL,
		0x967842401B990BABULL,
		0xF59CFE921AED05FFULL,
		0x82226C44E459CA21ULL,
		0x4A53CFE946B5EB47ULL,
		0x04BE117FBBD388E8ULL,
		0x55C0E3678F455DC5ULL,
		0xCFFAAD54B684232DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A8FAB84E634100ULL,
		0x4A107F9015A81850ULL,
		0x4E438DF6173118E9ULL,
		0x5BF63213D56D1656ULL,
		0x4425C69D5D497832ULL,
		0x2235382089058F3DULL,
		0x04BBD78B7A6AE125ULL,
		0x344EC85F80281C97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1518AB4A6ECE845ULL,
		0x4C67C2B005F0F35AULL,
		0xA759709C03BBED16ULL,
		0x262C3A310EECB3CBULL,
		0x062E094BE96C7315ULL,
		0xE288D95F32CDF9ABULL,
		0x51050BDC14DA7C9FULL,
		0x9BABE4F5365C0696ULL
	}};
	sign = 0;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB4C2E58254090FCULL,
		0x7468634B8DF272E1ULL,
		0xEBEE0AFF117AB1CEULL,
		0x63FCE6F4D50C5B95ULL,
		0xD5907D4E0EE2D293ULL,
		0x74D7D02A25FECC34ULL,
		0x8631E315A23C2AC2ULL,
		0xFEAD48B932A0091CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E4D230F48B9276ULL,
		0xB1E5FFF686047E3DULL,
		0x30394A3E8F698BFFULL,
		0x0EC2B39634D4E052ULL,
		0xC7790C6203BC9529ULL,
		0xB79694E3243C490DULL,
		0x1AD8EC571FF9CB2AULL,
		0xB439805AF5B61576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6675C2730B4FE86ULL,
		0xC282635507EDF4A3ULL,
		0xBBB4C0C0821125CEULL,
		0x553A335EA0377B43ULL,
		0x0E1770EC0B263D6AULL,
		0xBD413B4701C28327ULL,
		0x6B58F6BE82425F97ULL,
		0x4A73C85E3CE9F3A6ULL
	}};
	sign = 0;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E4E0BE779C970D5ULL,
		0x95597E068B5DAFD2ULL,
		0xB3C4B8BB8CF8023FULL,
		0x730513FB50B555E7ULL,
		0x6909F180236EF541ULL,
		0x666CEB709CEE8C69ULL,
		0x0DE5670BFD8D28F0ULL,
		0x7BF5058EC9B358D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0A928FAA59571AULL,
		0xAC09429AA4D8D662ULL,
		0x31C96B7C80800AC2ULL,
		0x799C9550F854F89EULL,
		0x245012530C84BBAFULL,
		0xB90EF58623734E87ULL,
		0x03B8454CEB2DF7F1ULL,
		0x98C70090D767E4C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F437957CF7019BBULL,
		0xE9503B6BE684D96FULL,
		0x81FB4D3F0C77F77CULL,
		0xF9687EAA58605D49ULL,
		0x44B9DF2D16EA3991ULL,
		0xAD5DF5EA797B3DE2ULL,
		0x0A2D21BF125F30FEULL,
		0xE32E04FDF24B7407ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D12F668A93191E3ULL,
		0x8862AD1BB541D901ULL,
		0xC823C8330133D7F2ULL,
		0xD91F2AED80D059A1ULL,
		0xDED819C8E36DF7C6ULL,
		0x5072D88BBA0A0C36ULL,
		0xAB655EB2367F71CFULL,
		0x1DF1D93A3E0B501FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79F3D2FBB9983316ULL,
		0x7B54284784B109D6ULL,
		0x0EAFD040F70B2B88ULL,
		0x3294425C3CC318FFULL,
		0x83DEED63EC541197ULL,
		0xA3704D7FE17487F9ULL,
		0xD97DD12F283A879AULL,
		0xA09F412D77BFF486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x031F236CEF995ECDULL,
		0x0D0E84D43090CF2BULL,
		0xB973F7F20A28AC6AULL,
		0xA68AE891440D40A2ULL,
		0x5AF92C64F719E62FULL,
		0xAD028B0BD895843DULL,
		0xD1E78D830E44EA34ULL,
		0x7D52980CC64B5B98ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E9CD94FA809BFC9ULL,
		0xEB6FE3391B7E7C78ULL,
		0x265513CF254DD65DULL,
		0x9BE2DDAC70CCB07CULL,
		0x9454F71EDE3C5E55ULL,
		0x5F991C40A211781DULL,
		0x5F0F23625F2D53BCULL,
		0xC9E458FD6566FCC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7BDD5BD79DE97B5ULL,
		0x003AB48BEEFCAA72ULL,
		0x5426087360215E57ULL,
		0x34BDD87EA1887A8AULL,
		0x989AA210104F7968ULL,
		0x1957E37DC45197CAULL,
		0x9B45231F667BE52EULL,
		0x8FC23DC476614CC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56DF03922E2B2814ULL,
		0xEB352EAD2C81D205ULL,
		0xD22F0B5BC52C7806ULL,
		0x6725052DCF4435F1ULL,
		0xFBBA550ECDECE4EDULL,
		0x464138C2DDBFE052ULL,
		0xC3CA0042F8B16E8EULL,
		0x3A221B38EF05B003ULL
	}};
	sign = 0;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x274E7F42DD4F1902ULL,
		0xC0EBA91C967D31D8ULL,
		0x1D9732DEFCC38E49ULL,
		0x775694FCDBA2BF9FULL,
		0xDF6970864DDB0130ULL,
		0x61B77124C827A24CULL,
		0xE8B1D6A43EE92A45ULL,
		0xC3548436C9C45D9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0DFEC48F7AC2E20ULL,
		0x3F34EA1DD45904B8ULL,
		0xC27CB9124EE409B4ULL,
		0xEDC11C63C70DCF81ULL,
		0x39564C58118C193AULL,
		0x4DCD30F7C4335275ULL,
		0xB0E2F4D67B3ABD32ULL,
		0xA5EE0164322BEB88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x566E92F9E5A2EAE2ULL,
		0x81B6BEFEC2242D1FULL,
		0x5B1A79CCADDF8495ULL,
		0x899578991494F01DULL,
		0xA613242E3C4EE7F5ULL,
		0x13EA402D03F44FD7ULL,
		0x37CEE1CDC3AE6D13ULL,
		0x1D6682D297987215ULL
	}};
	sign = 0;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60365AE97EAC43A0ULL,
		0xCB5164303F1BDECCULL,
		0xA4B4F46929527B31ULL,
		0x1B696E6D3042D558ULL,
		0xE35469DB83267CD2ULL,
		0x6A88BD8D2FFC8C53ULL,
		0xCB3A506C17912410ULL,
		0xCB8C38868C2EDCB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x637ADBFCE3DB8B45ULL,
		0xAC62D1E90E3C91A6ULL,
		0xC681DE7FB1C29A64ULL,
		0xA7EB84CA30A8B0D8ULL,
		0xB1046FA68ED9C168ULL,
		0x72CB473294647512ULL,
		0xB9CE6664FE7CC35BULL,
		0x06C137A33CAC4090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCBB7EEC9AD0B85BULL,
		0x1EEE924730DF4D25ULL,
		0xDE3315E9778FE0CDULL,
		0x737DE9A2FF9A247FULL,
		0x324FFA34F44CBB69ULL,
		0xF7BD765A9B981741ULL,
		0x116BEA07191460B4ULL,
		0xC4CB00E34F829C25ULL
	}};
	sign = 0;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13F0E3A81ED734DAULL,
		0x536EF835CDE0A0B3ULL,
		0x44842698AC8CDFE3ULL,
		0x1517D3AA1E8ED4ABULL,
		0x29708C084D92BD77ULL,
		0x35341CA71D891BA2ULL,
		0x5195EFE1964B4A7CULL,
		0x55A3477608317FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE803A25D260A4F02ULL,
		0xD92179C150C3974EULL,
		0x09D582A10B4ACFCCULL,
		0xC545631710A97F83ULL,
		0x7C9B3F1781C166D4ULL,
		0x65DFAD4369A546C6ULL,
		0x1193251CBF5C8CC5ULL,
		0xC5E8394A4E784C00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BED414AF8CCE5D8ULL,
		0x7A4D7E747D1D0964ULL,
		0x3AAEA3F7A1421016ULL,
		0x4FD270930DE55528ULL,
		0xACD54CF0CBD156A2ULL,
		0xCF546F63B3E3D4DBULL,
		0x4002CAC4D6EEBDB6ULL,
		0x8FBB0E2BB9B933C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x934F528B117003D8ULL,
		0x2701C55701B7EA92ULL,
		0x9BBCA90D996A5D33ULL,
		0x8B595F497602690CULL,
		0x8FA8CCF06A14614CULL,
		0x5B3FF6221C29265FULL,
		0xC39EB78873CDE79EULL,
		0xA58DBE3A3F405C29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA20163C55116DB37ULL,
		0x12EC84340F25D0DEULL,
		0xDCADE44BFEF51016ULL,
		0xA13362B92D8D58FCULL,
		0xDFA9064BD1140EBFULL,
		0x60F90BEAABF0DF37ULL,
		0x06F1A5E2DC391E6EULL,
		0x73D97818D59697A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF14DEEC5C05928A1ULL,
		0x14154122F29219B3ULL,
		0xBF0EC4C19A754D1DULL,
		0xEA25FC904875100FULL,
		0xAFFFC6A49900528CULL,
		0xFA46EA3770384727ULL,
		0xBCAD11A59794C92FULL,
		0x31B4462169A9C481ULL
	}};
	sign = 0;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87BEB11B5C9ACAC5ULL,
		0xEF10663CC0B31A5EULL,
		0xACA7D04A87F5D05EULL,
		0x34F9AF89EBAB1CC8ULL,
		0xC3C798A84F20768FULL,
		0x930AFDC40FECBAC8ULL,
		0xC5F51226F70676D1ULL,
		0x710771C6322E0C2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1DAC0F20DA3AD5CULL,
		0xE81827C484A4C477ULL,
		0x37C95AD0445E8D44ULL,
		0xAA96D252F507B68EULL,
		0x29C1DDCE73DC4F38ULL,
		0x44597C50EBD8593FULL,
		0x484B20EE28CD6C35ULL,
		0xA4A0BB871A986ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5E3F0294EF71D69ULL,
		0x06F83E783C0E55E6ULL,
		0x74DE757A4397431AULL,
		0x8A62DD36F6A3663AULL,
		0x9A05BAD9DB442756ULL,
		0x4EB1817324146189ULL,
		0x7DA9F138CE390A9CULL,
		0xCC66B63F1795A15BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x726459069FA194CBULL,
		0x819EEE2277C90CF1ULL,
		0x73DBB354CBD29A47ULL,
		0x41B91DD91A7F2338ULL,
		0x3AC2D6211CFB845BULL,
		0x346F01ECC410950BULL,
		0x00EB16CD12492D62ULL,
		0x867E3267632BE58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A42A29164B9B8AULL,
		0x48437D91422A24C1ULL,
		0x19025138B78C6444ULL,
		0x717540AB34C26249ULL,
		0xB1DE94FD9237EF06ULL,
		0x170E5F48036B30F0ULL,
		0x985E9829A5D6A60DULL,
		0x77CF69211B91B19FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11C02EDD8955F941ULL,
		0x395B7091359EE830ULL,
		0x5AD9621C14463603ULL,
		0xD043DD2DE5BCC0EFULL,
		0x88E441238AC39554ULL,
		0x1D60A2A4C0A5641AULL,
		0x688C7EA36C728755ULL,
		0x0EAEC946479A33EFULL
	}};
	sign = 0;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95B1A437FC31F87FULL,
		0x506274668E13ECE7ULL,
		0x87FC6F619F01AA3FULL,
		0xD989D0AA78573CC3ULL,
		0xCB88530AA33130B7ULL,
		0xC8EECB3FE194AA2CULL,
		0x419F9338A9B2F45AULL,
		0xCFC761DE9F3C57BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18B783011AF8D403ULL,
		0x0EB895FE1AA69850ULL,
		0x83E4B8E283FDDF1DULL,
		0x2CEA762406DFE1DCULL,
		0xB190B1135032EB03ULL,
		0x91E65CC0033F7E2DULL,
		0x2A20A604F2E891B3ULL,
		0x33CDF67028AD4F0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CFA2136E139247CULL,
		0x41A9DE68736D5497ULL,
		0x0417B67F1B03CB22ULL,
		0xAC9F5A8671775AE7ULL,
		0x19F7A1F752FE45B4ULL,
		0x37086E7FDE552BFFULL,
		0x177EED33B6CA62A7ULL,
		0x9BF96B6E768F08B1ULL
	}};
	sign = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8664FCA8BC599DC5ULL,
		0x093A1A702C1B6896ULL,
		0xA49191738F7B53BEULL,
		0x7A268BC6EE520313ULL,
		0xFF5ABF86A618598AULL,
		0xD947008F92AC9D5AULL,
		0xC7435A22E1867F4DULL,
		0x18F29C6D5FCE9F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68477859CFC73F89ULL,
		0x7968C11E45C4E536ULL,
		0x32CCDE829E7C7F42ULL,
		0x89D84013015FB125ULL,
		0x04DF72BEEC70E977ULL,
		0xBCDC319D98CA47D1ULL,
		0xA2683FC379A6E3AEULL,
		0x4762B0DDC4FC59D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E1D844EEC925E3CULL,
		0x8FD15951E6568360ULL,
		0x71C4B2F0F0FED47BULL,
		0xF04E4BB3ECF251EEULL,
		0xFA7B4CC7B9A77012ULL,
		0x1C6ACEF1F9E25589ULL,
		0x24DB1A5F67DF9B9FULL,
		0xD18FEB8F9AD2453BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8B42DCAF5EB18A6ULL,
		0xF28429F20DB959B0ULL,
		0x51F723D493711489ULL,
		0xFD56CB5BC4026115ULL,
		0xE31C5F6277793157ULL,
		0xBF0E8456CDE0A943ULL,
		0xCDEB6F11B33A1FF7ULL,
		0xB71E9CA81C53EA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20D69CE12D18C266ULL,
		0x9F5383CBAA40D48DULL,
		0xDF315CACB025A26DULL,
		0xA659B026C2910B19ULL,
		0x011D8F5C7014D637ULL,
		0xBEB8DBD9E7426459ULL,
		0xA60713F97A3613DAULL,
		0xEC8015EAF6C0A9F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97DD90E9C8D25640ULL,
		0x5330A62663788523ULL,
		0x72C5C727E34B721CULL,
		0x56FD1B35017155FBULL,
		0xE1FED00607645B20ULL,
		0x0055A87CE69E44EAULL,
		0x27E45B1839040C1DULL,
		0xCA9E86BD25934085ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E801D130CD50D44ULL,
		0x9684162793852256ULL,
		0x27596B794AF15C0EULL,
		0x25D744AD0DE3A564ULL,
		0x771A47E4AF2EBC81ULL,
		0x9A23830A756B69A7ULL,
		0x5B2818019C8838B3ULL,
		0x3109F190AC2A9A92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x674530639079EAFAULL,
		0x7AF78A88FC17D442ULL,
		0xE1C89B8A2908F911ULL,
		0x7F60852447DFE6F7ULL,
		0xC4C0C7F8C97D14DFULL,
		0x1E64409FDBDF2E56ULL,
		0xAB2E98DCA6D22EA8ULL,
		0x026210FADEEB1D97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x073AECAF7C5B224AULL,
		0x1B8C8B9E976D4E14ULL,
		0x4590CFEF21E862FDULL,
		0xA676BF88C603BE6CULL,
		0xB2597FEBE5B1A7A1ULL,
		0x7BBF426A998C3B50ULL,
		0xAFF97F24F5B60A0BULL,
		0x2EA7E095CD3F7CFAULL
	}};
	sign = 0;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x184812A11D04B235ULL,
		0xCF3C36055363B898ULL,
		0x5F4FCF8287847DA4ULL,
		0x0FA114172BCD85D7ULL,
		0xD168E29ABC793AD5ULL,
		0x7474C0246080A13BULL,
		0x599C138A1C7918ECULL,
		0x287A47D2E4F20CC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x417C2EFF50E42F52ULL,
		0x62F96D5994BA232CULL,
		0x7D0F10BF032E606CULL,
		0x8A6DFC74CCBD8B85ULL,
		0x637FB6E5ABE8A0FDULL,
		0x6C602C048ED01FA7ULL,
		0x51C538CFC05CDBCBULL,
		0x3E61AA1E914933A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6CBE3A1CC2082E3ULL,
		0x6C42C8ABBEA9956BULL,
		0xE240BEC384561D38ULL,
		0x853317A25F0FFA51ULL,
		0x6DE92BB5109099D7ULL,
		0x0814941FD1B08194ULL,
		0x07D6DABA5C1C3D21ULL,
		0xEA189DB453A8D923ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D5CD25A08C96AACULL,
		0xB444C7B8D631078DULL,
		0xF3A0732FBE619AE8ULL,
		0x3BB1B365CB250AE8ULL,
		0x986B2F33762AD039ULL,
		0x3D23BFF248D72713ULL,
		0x217586183D26D6EEULL,
		0x8ED5546D7EF5F86DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC75EF3029480D1B8ULL,
		0xC5FA2D08957CFA6FULL,
		0x70352A28F02D4868ULL,
		0x03EF720C58C7789BULL,
		0x5A1A8907AC61276EULL,
		0xD327696318D3FB5CULL,
		0x2F40F3A5F87BDE83ULL,
		0xB073C149B1342118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95FDDF57744898F4ULL,
		0xEE4A9AB040B40D1DULL,
		0x836B4906CE34527FULL,
		0x37C24159725D924DULL,
		0x3E50A62BC9C9A8CBULL,
		0x69FC568F30032BB7ULL,
		0xF234927244AAF86AULL,
		0xDE619323CDC1D754ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFC3C856960F5C8CULL,
		0xDD23B7577CDF9270ULL,
		0x6802041D8DCE45C7ULL,
		0x64F371C8CD391C7DULL,
		0x27A67B5458BB0136ULL,
		0xF1B7C0AF17B10B05ULL,
		0x2FEB983342A3E5F1ULL,
		0x437CBE916A369DD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0944130F37637A3ULL,
		0xF08033B627992705ULL,
		0x0C199B74216A268AULL,
		0x908599E8E05DA75DULL,
		0xAC2964B4A9F71515ULL,
		0x301908ABDCB4D3ACULL,
		0x2C811E4B3F63681BULL,
		0xB99337B6E30F5226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF2F8725A29924E9ULL,
		0xECA383A155466B6AULL,
		0x5BE868A96C641F3CULL,
		0xD46DD7DFECDB7520ULL,
		0x7B7D169FAEC3EC20ULL,
		0xC19EB8033AFC3758ULL,
		0x036A79E803407DD6ULL,
		0x89E986DA87274BADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF61930B16DB8466ULL,
		0x0052842D5B60013BULL,
		0x1902FCCEFD40BF00ULL,
		0xA8EC9C730C929700ULL,
		0xCE41A7F7C4A42794ULL,
		0x23766C578A48488BULL,
		0x790AA9D979273EB8ULL,
		0x6E3EF6F379490E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBBD988704567B9AULL,
		0x6CBE5641E2E393DCULL,
		0x5E9F904A48B2B521ULL,
		0xBA5404B37F0268C5ULL,
		0x288141EF4A7E4ED7ULL,
		0xF05E6C8A118E76AFULL,
		0xF3F4BB6EDE68D597ULL,
		0x59C98800592E2D5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3A3FA84128508CCULL,
		0x93942DEB787C6D5EULL,
		0xBA636C84B48E09DEULL,
		0xEE9897BF8D902E3AULL,
		0xA5C066087A25D8BCULL,
		0x3317FFCD78B9D1DCULL,
		0x8515EE6A9ABE6920ULL,
		0x14756EF3201AE0F4ULL
	}};
	sign = 0;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC70569573FCAFCDAULL,
		0x5F0898B37E9F76FBULL,
		0x7D5ACDDCDE113487ULL,
		0xE1C7A1D2377D1A82ULL,
		0x36A999025B820423ULL,
		0xE52F7CF8DC367A03ULL,
		0x28B84C210C561302ULL,
		0x4B3A7BAAA1469FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC19501E05C5A8C3ULL,
		0x0727085AE2A3E496ULL,
		0x9B8546FDB9947097ULL,
		0x3C64923174D2D516ULL,
		0xFD848D5483DDB471ULL,
		0x63CD7092040B7F4FULL,
		0x52BB530B665234D6ULL,
		0x0B3B7245A76C85EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AEC19393A055417ULL,
		0x57E190589BFB9265ULL,
		0xE1D586DF247CC3F0ULL,
		0xA5630FA0C2AA456BULL,
		0x39250BADD7A44FB2ULL,
		0x81620C66D82AFAB3ULL,
		0xD5FCF915A603DE2CULL,
		0x3FFF0964F9DA19C4ULL
	}};
	sign = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4F9CA874F7A464EULL,
		0x5B60D4D667E21E3EULL,
		0xD91E9C5F867EF4CBULL,
		0x18CFD9D6998618C5ULL,
		0x1F30092EAC774737ULL,
		0x729B0230B0654901ULL,
		0x294C5E2F63D89D41ULL,
		0xFB1EFD61F10F7139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD58860CCACBAA289ULL,
		0x4B31E524F4BB5260ULL,
		0x80A9DCDC723F4410ULL,
		0x96BCAB9E595038C7ULL,
		0xFA8E177B593484F1ULL,
		0xD58C1A7E854AEEE4ULL,
		0xF4B0DA3681114A53ULL,
		0x1F4B5D66BAB225D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF7169BAA2BFA3C5ULL,
		0x102EEFB17326CBDDULL,
		0x5874BF83143FB0BBULL,
		0x82132E384035DFFEULL,
		0x24A1F1B35342C245ULL,
		0x9D0EE7B22B1A5A1CULL,
		0x349B83F8E2C752EDULL,
		0xDBD39FFB365D4B66ULL
	}};
	sign = 0;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56EDC32DE85511A9ULL,
		0xECC51D5BB8B47DA9ULL,
		0x551BC9CBA0888189ULL,
		0x0CE9A3A2B7939AB8ULL,
		0x0CAD85B6164D41ABULL,
		0x834AB1BB6A609F0AULL,
		0x846E652BAF6C1CC9ULL,
		0xB91F8F455F87E480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA520EA5BA51DEDFFULL,
		0xA815942150B31056ULL,
		0x46B2FFC7DE5891C8ULL,
		0x39EE322C98A4AC48ULL,
		0xB946D878B20E0A1AULL,
		0x40D7F9BC64993726ULL,
		0xB3A9AC15F9F9B346ULL,
		0xF54230C327576AE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1CCD8D2433723AAULL,
		0x44AF893A68016D52ULL,
		0x0E68CA03C22FEFC1ULL,
		0xD2FB71761EEEEE70ULL,
		0x5366AD3D643F3790ULL,
		0x4272B7FF05C767E3ULL,
		0xD0C4B915B5726983ULL,
		0xC3DD5E823830799CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBB03A6B958D63DBULL,
		0x0A3E9A0A3840CEBEULL,
		0x018E1AEF956216A5ULL,
		0x5A9D3725518D39F2ULL,
		0xF1B024A54CAB6251ULL,
		0x400E7A9CC12ACE5EULL,
		0x9018E4DC4A435B48ULL,
		0x0E355D21C928A12AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E7EE40EE739D4FCULL,
		0x092F6A36A32E970FULL,
		0x2DED74F3FF8BD09FULL,
		0x29203D681984D553ULL,
		0xF59A6CDF842C2448ULL,
		0x72493CBD3183B104ULL,
		0x49FD11AB368D216CULL,
		0x8F014FED29EBC3C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D31565CAE538EDFULL,
		0x010F2FD3951237AFULL,
		0xD3A0A5FB95D64606ULL,
		0x317CF9BD3808649EULL,
		0xFC15B7C5C87F3E09ULL,
		0xCDC53DDF8FA71D59ULL,
		0x461BD33113B639DBULL,
		0x7F340D349F3CDD65ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC76F8ED6BCEFE406ULL,
		0xFE84CC9A0AB798E2ULL,
		0x992E1B2474DB690EULL,
		0x3AAE5B535AA71275ULL,
		0x2913D1FE3C5F9653ULL,
		0xD3A0DA91EAE62868ULL,
		0x02AAB978AD7E5887ULL,
		0x946A669868218BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9B9F92D2531D07DULL,
		0xE755634A3B37382DULL,
		0x44FE7CA10D325834ULL,
		0x3E5D3B9929B43EB1ULL,
		0x88FBE0983C7770FDULL,
		0xA62D6F4F595088F0ULL,
		0xAB633471EA35371CULL,
		0x90D125819169B8FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DB595A997BE1389ULL,
		0x172F694FCF8060B5ULL,
		0x542F9E8367A910DAULL,
		0xFC511FBA30F2D3C4ULL,
		0xA017F165FFE82555ULL,
		0x2D736B4291959F77ULL,
		0x57478506C349216BULL,
		0x03994116D6B7D302ULL
	}};
	sign = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14D4C48F59EA08A6ULL,
		0x07C53B5828E7BC6EULL,
		0xDDAC7E11148161F2ULL,
		0x5AB8672E82CEEB0DULL,
		0xE844F3CDE6A2682EULL,
		0x0C97132CFC7F3836ULL,
		0xBB0308CEC275B147ULL,
		0x820DA3FBE5D9C7AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF85902AB19677FD1ULL,
		0x3EA3A02A50E23F65ULL,
		0xE3B72F75D0B39B24ULL,
		0xA5D94A4C020EF688ULL,
		0x3560BE39742FA69EULL,
		0xEB711FC255DC6C5AULL,
		0x31EA7344507B8DE4ULL,
		0xB8DD10D1EA6CA9CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C7BC1E4408288D5ULL,
		0xC9219B2DD8057D08ULL,
		0xF9F54E9B43CDC6CDULL,
		0xB4DF1CE280BFF484ULL,
		0xB2E435947272C18FULL,
		0x2125F36AA6A2CBDCULL,
		0x8918958A71FA2362ULL,
		0xC9309329FB6D1DE0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22529326F3962D38ULL,
		0x98255ED63B92C497ULL,
		0xD60B1889CD5C9602ULL,
		0x5A98EC1ACCEE404BULL,
		0x259085F54120EA80ULL,
		0xB033C30665335FC6ULL,
		0x29A5D371306C18C2ULL,
		0x57333BF892C1A4BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5734ADCEBC2F55ABULL,
		0x74762660D7B74AE3ULL,
		0x547882DE694B56D1ULL,
		0x98E78BF97E75EB68ULL,
		0x8CED7EE8F3F3075FULL,
		0xCF14573E98F6E305ULL,
		0xBA564E06BB6BA98DULL,
		0x79D6BC28D98B5A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB1DE5583766D78DULL,
		0x23AF387563DB79B3ULL,
		0x819295AB64113F31ULL,
		0xC1B160214E7854E3ULL,
		0x98A3070C4D2DE320ULL,
		0xE11F6BC7CC3C7CC0ULL,
		0x6F4F856A75006F34ULL,
		0xDD5C7FCFB9364A2EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669796AC582E6DC0ULL,
		0x0111782F9866D953ULL,
		0xF3953740BC8500D1ULL,
		0x8830E5E0B353393DULL,
		0x3B071159CAA99813ULL,
		0x4E289B62179784CFULL,
		0x9F89D4B8D41E752DULL,
		0xF7E4CD99FA1BC4FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12617F1779E2AB94ULL,
		0x2C1C3D9CC9D1C1AEULL,
		0x995CD3ED60773099ULL,
		0xD4A31813C575CA79ULL,
		0xE72C4F892B8FE99CULL,
		0x42849F19E0110010ULL,
		0xE67189B47B4D3024ULL,
		0x4D68E81158C9D2DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54361794DE4BC22CULL,
		0xD4F53A92CE9517A5ULL,
		0x5A3863535C0DD037ULL,
		0xB38DCDCCEDDD6EC4ULL,
		0x53DAC1D09F19AE76ULL,
		0x0BA3FC48378684BEULL,
		0xB9184B0458D14509ULL,
		0xAA7BE588A151F21FULL
	}};
	sign = 0;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C7FE65F2E0DB548ULL,
		0x6E206D17390E4C05ULL,
		0xBB1309DF5B061C12ULL,
		0x90BF7B29480CBDE7ULL,
		0x12B848D49350E7DDULL,
		0xF02A90604D12CEF2ULL,
		0x9FA1DDF6B275EEC3ULL,
		0x4F59F4A347690754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9C722B5CE03921ULL,
		0xBC1A361C955ED033ULL,
		0x7E8CBEE2E00C52DCULL,
		0x1E90E7D6B4E221DFULL,
		0x0DC61D4101941AD7ULL,
		0xF96EFD587FBA78E9ULL,
		0x9F4148930D2FC5ADULL,
		0x6FF39F9BD3E97142ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E37433D12D7C27ULL,
		0xB20636FAA3AF7BD2ULL,
		0x3C864AFC7AF9C935ULL,
		0x722E9352932A9C08ULL,
		0x04F22B9391BCCD06ULL,
		0xF6BB9307CD585609ULL,
		0x00609563A5462915ULL,
		0xDF665507737F9612ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32D25EC8D8BB05D6ULL,
		0xF845CAB8EEE3F5C2ULL,
		0x080FBD88478B76C4ULL,
		0x9B74AE8B4F7C58C6ULL,
		0x2BAC42DBC4E73D24ULL,
		0xE7C46430D2A868D8ULL,
		0x542AD0BE222F9CF0ULL,
		0x1064D0732FCF116DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4487BEB0A0BBCC2DULL,
		0xA12089A8A0B1DBD2ULL,
		0xADA6B48203914686ULL,
		0xF31E0CB3C2B3875AULL,
		0xD9B3591DCA78E9D0ULL,
		0x458C833B3B07CADCULL,
		0x6C263D19E9E0293CULL,
		0xC818B06D2A30C14FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE4AA01837FF39A9ULL,
		0x572541104E3219EFULL,
		0x5A69090643FA303EULL,
		0xA856A1D78CC8D16BULL,
		0x51F8E9BDFA6E5353ULL,
		0xA237E0F597A09DFBULL,
		0xE80493A4384F73B4ULL,
		0x484C2006059E501DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x177841C7CFC5EA4CULL,
		0x13C3EDE87C346CFFULL,
		0xC19FB1A728933CFBULL,
		0x2A6A9409633534BAULL,
		0x2DC6920D2623955BULL,
		0xE90B2CF35FE2D159ULL,
		0xD86CC67BD42089BFULL,
		0x1374291DC3171ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46946A84E1C04AECULL,
		0x8F1E966C90512CDAULL,
		0x3967BFC710D695BCULL,
		0xC94F65DCE0034E2FULL,
		0x886A57A625121EC4ULL,
		0xD4A10DDAF9F892E5ULL,
		0x71BD2EE9839532AEULL,
		0xAF0ECC0059CA43A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0E3D742EE059F60ULL,
		0x84A5577BEBE34024ULL,
		0x8837F1E017BCA73EULL,
		0x611B2E2C8331E68BULL,
		0xA55C3A6701117696ULL,
		0x146A1F1865EA3E73ULL,
		0x66AF9792508B5711ULL,
		0x64655D1D694CD72CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37B13BFF32A7167DULL,
		0x3DCD7C14929ABF0BULL,
		0x8EC7274BB47AE5AFULL,
		0xA68D2DD762C6AD38ULL,
		0xBA4D6F93F284A842ULL,
		0x571A973E8E4C8EA7ULL,
		0x7ACD7E56B8D3A711ULL,
		0xD1950D8D7BAB7E7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4C23BB7DD91EF92ULL,
		0x28619D5F4711AAB0ULL,
		0x44E18333C5B735A8ULL,
		0xD6F4DE38F60E7131ULL,
		0xE9D1A2857E8DEF80ULL,
		0x01CEC84172911528ULL,
		0x87DA9B6A7E56BC15ULL,
		0x0CCBBFF4450FD750ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62EF0047551526EBULL,
		0x156BDEB54B89145AULL,
		0x49E5A417EEC3B007ULL,
		0xCF984F9E6CB83C07ULL,
		0xD07BCD0E73F6B8C1ULL,
		0x554BCEFD1BBB797EULL,
		0xF2F2E2EC3A7CEAFCULL,
		0xC4C94D99369BA729ULL
	}};
	sign = 0;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB923349C4591845BULL,
		0x94C169D499A178F5ULL,
		0x6F60657A7AC7628FULL,
		0x827B5A0BBB6F6F7DULL,
		0x01B34C23AA135085ULL,
		0x5B7BA4D5C9FD73E3ULL,
		0x27B7105F254FB7C9ULL,
		0x2082911AC923DFC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5EFD7222080F9BFULL,
		0xE2DD34463CC0589EULL,
		0xAC201DD62F66DE8FULL,
		0xDAA6A0A793DE655BULL,
		0x01C1238A3E219971ULL,
		0xF675EC9E0D8FCEB6ULL,
		0x4B7BC745DDB8983FULL,
		0xAA1E2941C421B837ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13335D7A25108A9CULL,
		0xB1E4358E5CE12057ULL,
		0xC34047A44B6083FFULL,
		0xA7D4B96427910A21ULL,
		0xFFF228996BF1B713ULL,
		0x6505B837BC6DA52CULL,
		0xDC3B491947971F89ULL,
		0x766467D905022788ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FEFFB4D3FCE04A0ULL,
		0xA3970016A9522A10ULL,
		0x70468712BA18F06CULL,
		0xF604C9215CC8679FULL,
		0xCEECFDB3D6433456ULL,
		0x25B709CF3D130764ULL,
		0xD2765F214BB8E193ULL,
		0xAB24D9FE2F33D504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A721E7FCA9EB38CULL,
		0xA182FFAABDBAAA7AULL,
		0x1FACA0E6EDF085A2ULL,
		0x18DDDCB07ABB8B1DULL,
		0xB46C6D7AC8CFDF61ULL,
		0x7D6D846D8178485DULL,
		0x0EE29D3D1A4D18FCULL,
		0x624A661C8CF5B3F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x757DDCCD752F5114ULL,
		0x0214006BEB977F96ULL,
		0x5099E62BCC286ACAULL,
		0xDD26EC70E20CDC82ULL,
		0x1A8090390D7354F5ULL,
		0xA8498561BB9ABF07ULL,
		0xC393C1E4316BC896ULL,
		0x48DA73E1A23E210CULL
	}};
	sign = 0;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE1BCC6E67A00611ULL,
		0xB4805D906D824EF2ULL,
		0x3996F4F84082A7D0ULL,
		0x6A6689B909BC0F95ULL,
		0x724067FD526DBC73ULL,
		0xDD65EE8BB99E7B39ULL,
		0xCD483D15911D6FAAULL,
		0xF0F51226AC1A840BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66BC6D4EB8A5D2EAULL,
		0xB363C7A479484338ULL,
		0xEE12CB19A2233ED9ULL,
		0x9B081563FBC60FCFULL,
		0x90E2AD6B4F9C1685ULL,
		0x2C7276A2DBF57CCEULL,
		0xB30FFD522E4DBF3DULL,
		0xD0E511F5B94E2B82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x575F5F1FAEFA3327ULL,
		0x011C95EBF43A0BBAULL,
		0x4B8429DE9E5F68F7ULL,
		0xCF5E74550DF5FFC5ULL,
		0xE15DBA9202D1A5EDULL,
		0xB0F377E8DDA8FE6AULL,
		0x1A383FC362CFB06DULL,
		0x20100030F2CC5889ULL
	}};
	sign = 0;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12214405C73AACF6ULL,
		0xB27A4A7567A605F8ULL,
		0x49C63EFE1F8FCF5FULL,
		0xF08885B1A518FAEEULL,
		0x234123240A7B6EE1ULL,
		0x4D2B4384C04BD85EULL,
		0x006BB4B3764DF86BULL,
		0xDFD2F210534C7D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7AFE70E9761393ULL,
		0xC1290131E8287A53ULL,
		0x309377D2D10A49EFULL,
		0xE9C75FC244AFDE0EULL,
		0xE8D40E9FCA30C8ADULL,
		0x1C493B907D1B28A1ULL,
		0x94F8D1CC1D2942CCULL,
		0xEA984C7CA9676BF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56A64594DDC49963ULL,
		0xF15149437F7D8BA4ULL,
		0x1932C72B4E85856FULL,
		0x06C125EF60691CE0ULL,
		0x3A6D1484404AA634ULL,
		0x30E207F44330AFBCULL,
		0x6B72E2E75924B59FULL,
		0xF53AA593A9E5114BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF7C71E68B5AAF8CULL,
		0x50DD1E5C1269B687ULL,
		0xD3EF0E54B3E2847AULL,
		0xBF9BF94A22200A96ULL,
		0xABD58E6CE65E5D81ULL,
		0xAF59F26C2ED60824ULL,
		0x7230B706F0A61A8FULL,
		0x00B3D0D110ADEAA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34507B8358A5D05BULL,
		0x3730BA3E5154BD2BULL,
		0x4D3154E22AB30657ULL,
		0x65CDA0417C6DF536ULL,
		0xA58698CDEB969C93ULL,
		0x4EAF38BF8CC432D1ULL,
		0x77715E292BA546B3ULL,
		0xD43BAD4F36C25004ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB2BF66332B4DF31ULL,
		0x19AC641DC114F95CULL,
		0x86BDB972892F7E23ULL,
		0x59CE5908A5B21560ULL,
		0x064EF59EFAC7C0EEULL,
		0x60AAB9ACA211D553ULL,
		0xFABF58DDC500D3DCULL,
		0x2C782381D9EB9AA4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4B8D975688B9D51ULL,
		0xDE0CB986332A9D1AULL,
		0xB12A152498E4053BULL,
		0x23E4A59D795E86BDULL,
		0x0BE6883AE78F62EAULL,
		0xBD1493D1E61B6140ULL,
		0x6967AF12C3DE3DB8ULL,
		0x26EC684BA8026A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD14776731446462ULL,
		0x388A62E4C0872D67ULL,
		0x1D9BF4F1B2027DEFULL,
		0x1F0F59C61257ED0DULL,
		0x4F662F8BE001BD80ULL,
		0x0B784EFBF756A4BBULL,
		0xE20E823708883B73ULL,
		0x47E95B8E267477C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7A4620E374738EFULL,
		0xA58256A172A36FB2ULL,
		0x938E2032E6E1874CULL,
		0x04D54BD7670699B0ULL,
		0xBC8058AF078DA56AULL,
		0xB19C44D5EEC4BC84ULL,
		0x87592CDBBB560245ULL,
		0xDF030CBD818DF249ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5F33657BDF04430ULL,
		0x9D3BCBBBE439BC86ULL,
		0x1BD6027DC24C0370ULL,
		0xD1033B457C1A378CULL,
		0xC18CF7EABABCE00AULL,
		0xE35A9A5DAFA8A488ULL,
		0xC1EFE434BBC248CCULL,
		0xDB2A0B07B2255618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0E4D6D165AE686EULL,
		0x438A4975C00067B4ULL,
		0xC5F9C918D28866E2ULL,
		0xF5C83FA952A81D80ULL,
		0xC1BBB8D9FFB05E14ULL,
		0x93BA58F55FA7EEA9ULL,
		0x20E35D7EAE98AC5AULL,
		0x638E87E4BBF11839ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x250E5F865841DBC2ULL,
		0x59B18246243954D2ULL,
		0x55DC3964EFC39C8EULL,
		0xDB3AFB9C29721A0BULL,
		0xFFD13F10BB0C81F5ULL,
		0x4FA041685000B5DEULL,
		0xA10C86B60D299C72ULL,
		0x779B8322F6343DDFULL
	}};
	sign = 0;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87DD6B56BA245F21ULL,
		0x32EE7E0B3DD819CEULL,
		0x623EC999AEE5ABDBULL,
		0x966A678093A8749DULL,
		0x099E9EEE2DC454BDULL,
		0xCE0E19C4527E964DULL,
		0x757AD101A59AB769ULL,
		0xAB8570A6AEF14A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD6CE634005A906FULL,
		0x1547C0C66438BBCCULL,
		0x99638F184A82A53CULL,
		0x1C4FCBE436FC855FULL,
		0xB281DF425EF3167FULL,
		0x29DFB145CBCD4AE4ULL,
		0xC6732A31F84BCA66ULL,
		0x099BC0279CEC4EC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A708522B9C9CEB2ULL,
		0x1DA6BD44D99F5E01ULL,
		0xC8DB3A816463069FULL,
		0x7A1A9B9C5CABEF3DULL,
		0x571CBFABCED13E3EULL,
		0xA42E687E86B14B68ULL,
		0xAF07A6CFAD4EED03ULL,
		0xA1E9B07F1204FB4AULL
	}};
	sign = 0;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1918B9AF55F6EE23ULL,
		0xED6223F221F41EFBULL,
		0x10C168E59C384AB6ULL,
		0x7AA72B804C8F3D44ULL,
		0x8E46DD5A3F2E35DBULL,
		0x50A853CDFD7F92C6ULL,
		0xB4C27E8BC7081558ULL,
		0x9AA99B1F29D2B253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x703BB0A5001CD827ULL,
		0x5C837CE87D7A59A7ULL,
		0x29CAB93405CC9DD5ULL,
		0xB0192C4D177E64A7ULL,
		0x7602ABF64B4E8A2FULL,
		0xA1F11F7C72676CD5ULL,
		0x38BE49585248B684ULL,
		0x8744E7E41FBC41C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8DD090A55DA15FCULL,
		0x90DEA709A479C553ULL,
		0xE6F6AFB1966BACE1ULL,
		0xCA8DFF333510D89CULL,
		0x18443163F3DFABABULL,
		0xAEB734518B1825F1ULL,
		0x7C04353374BF5ED3ULL,
		0x1364B33B0A167090ULL
	}};
	sign = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAE49D12BDD027EFULL,
		0x23DF6BC89C4D0F20ULL,
		0x8E4C6588BB000ED3ULL,
		0x009206C3B9E83592ULL,
		0x4641C37871678628ULL,
		0x8DA21B4B2DB7EA83ULL,
		0xF697E58DB76C61BBULL,
		0xF2975ADFFDF8B3BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF619FB3173CCD0ULL,
		0x2A3C3F10AE485B75ULL,
		0x032CD30F363D4321ULL,
		0x51867965F8032130ULL,
		0xA8AA3D5DF8410883ULL,
		0xDDF1B85EA1152B10ULL,
		0x7F0901482FDE79F5ULL,
		0x0058AFADDB15DB7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CEE83178C5C5B1FULL,
		0xF9A32CB7EE04B3ABULL,
		0x8B1F927984C2CBB1ULL,
		0xAF0B8D5DC1E51462ULL,
		0x9D97861A79267DA4ULL,
		0xAFB062EC8CA2BF72ULL,
		0x778EE445878DE7C5ULL,
		0xF23EAB3222E2D845ULL
	}};
	sign = 0;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98DBBD5A2D6C0ACAULL,
		0x83E42E2776533B03ULL,
		0x65C67810E39A379EULL,
		0xDE24E839C6CDA9FAULL,
		0xA2C9B9531DC578AAULL,
		0xC4A9D7C929790749ULL,
		0xC4A2F03621D8FE3DULL,
		0x0030BFE1146C17DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x982D064E21DABD5CULL,
		0x3EF5B784F0D1619BULL,
		0xC657760DEE06C769ULL,
		0xB80C429AED802F13ULL,
		0x051A6120ECFE89A4ULL,
		0x2F28F44E7EA89FDFULL,
		0x37AF2BBC1303B1CEULL,
		0xEF5C11019E709D48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00AEB70C0B914D6EULL,
		0x44EE76A28581D968ULL,
		0x9F6F0202F5937035ULL,
		0x2618A59ED94D7AE6ULL,
		0x9DAF583230C6EF06ULL,
		0x9580E37AAAD0676AULL,
		0x8CF3C47A0ED54C6FULL,
		0x10D4AEDF75FB7A94ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C634C56D551F82EULL,
		0xC2303728FD88C0C6ULL,
		0x6DD78C71CA3F7E3BULL,
		0xE03B37A4E84563EAULL,
		0x65D549900C965D16ULL,
		0xD0E402C1DBE65982ULL,
		0x4CF4B9B3661E49F4ULL,
		0x73E967CB76D25B58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0525E492A3E4ADULL,
		0xD1C391577F0A0F2BULL,
		0xDC2DFC529F1C3627ULL,
		0x0C3F925638543A52ULL,
		0xBA250CC5FB76F82EULL,
		0x0B8DE9791833F442ULL,
		0xFC1E4ED59305BD04ULL,
		0x0A13CE06F27256C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE5E267242AE1381ULL,
		0xF06CA5D17E7EB19AULL,
		0x91A9901F2B234813ULL,
		0xD3FBA54EAFF12997ULL,
		0xABB03CCA111F64E8ULL,
		0xC5561948C3B2653FULL,
		0x50D66ADDD3188CF0ULL,
		0x69D599C48460048EULL
	}};
	sign = 0;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00762B90E55A368BULL,
		0x6E133802B2EE1C75ULL,
		0xC95A59A1E5B75730ULL,
		0x08EA3381E7FCF934ULL,
		0xEE72106DA196D9D8ULL,
		0x5E245B41414CFA1CULL,
		0x69AD84BDDEFD3A68ULL,
		0xDF03D5A8EFCE9FB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D8CB59A5749ACC4ULL,
		0x47FF2A6CEC2CCFEFULL,
		0x88B0E27C560BF0D4ULL,
		0xD92DFB2E4369F195ULL,
		0x58F8147228213D38ULL,
		0x2B6F3B3625432A58ULL,
		0xE923BD031B2EA81EULL,
		0x4106209DE052E98DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92E975F68E1089C7ULL,
		0x26140D95C6C14C85ULL,
		0x40A977258FAB665CULL,
		0x2FBC3853A493079FULL,
		0x9579FBFB79759C9FULL,
		0x32B5200B1C09CFC4ULL,
		0x8089C7BAC3CE924AULL,
		0x9DFDB50B0F7BB626ULL
	}};
	sign = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x820DEB71D20D1D29ULL,
		0x479C3866E162C56DULL,
		0xC7493AD6DE03022EULL,
		0x7C4361301E1CC326ULL,
		0x0768A9CF355E282FULL,
		0x80C08BA1E161351BULL,
		0xA5A39AE075A6A8FFULL,
		0x3AAC353903D0D1C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6020EE80987223EULL,
		0x323D5A60A8D06B1FULL,
		0xFD7CD81A413B00E3ULL,
		0xF012232026C10079ULL,
		0x9B4E7975BEA8408DULL,
		0x93358E506BBC7A78ULL,
		0xFD79D2515AC8E3C0ULL,
		0x3A2D1C274B3B2186ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC0BDC89C885FAEBULL,
		0x155EDE0638925A4DULL,
		0xC9CC62BC9CC8014BULL,
		0x8C313E0FF75BC2ACULL,
		0x6C1A305976B5E7A1ULL,
		0xED8AFD5175A4BAA2ULL,
		0xA829C88F1ADDC53EULL,
		0x007F1911B895B03EULL
	}};
	sign = 0;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x516E09D0850B08C5ULL,
		0x9D73F07594B50F9DULL,
		0x6F603F1345F1603DULL,
		0xBAF67BCEA498283FULL,
		0x45F0BADEDA361DB2ULL,
		0x4884FB86B59C41C0ULL,
		0x40DFE81BF1DE413EULL,
		0xD6E013DBA450673DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1387ED9A38B4379ULL,
		0xEE2E400ABB4FF061ULL,
		0x2AAEAF940C12C3B0ULL,
		0x0F4FB81AC4C13B18ULL,
		0x5FDF1702315E4EDBULL,
		0xE02C115DE3418853ULL,
		0x5CA95BC94E394D41ULL,
		0x652BCEC86982142BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90358AF6E17FC54CULL,
		0xAF45B06AD9651F3BULL,
		0x44B18F7F39DE9C8CULL,
		0xABA6C3B3DFD6ED27ULL,
		0xE611A3DCA8D7CED7ULL,
		0x6858EA28D25AB96CULL,
		0xE4368C52A3A4F3FCULL,
		0x71B445133ACE5311ULL
	}};
	sign = 0;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D40C7C5F538DAE4ULL,
		0x93E1BFAD81F1FDB0ULL,
		0xEB7D98CBEDF292C8ULL,
		0xC18504EFEBEDD80CULL,
		0x0B1F60E3720F5BF7ULL,
		0x80EF90902EF31549ULL,
		0x8C5A55789EC1DC26ULL,
		0x7FD32182A8E1B5F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8483252FD22FA6ULL,
		0xCDE62FB924C48A0BULL,
		0x296F625038F98091ULL,
		0xED44A6335E904726ULL,
		0x923846AD845F7DA5ULL,
		0xE69680BF36799629ULL,
		0xD4AAEFA1DB32AD7CULL,
		0x1CB9433D6070A1E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EBC44A0C566AB3EULL,
		0xC5FB8FF45D2D73A5ULL,
		0xC20E367BB4F91236ULL,
		0xD4405EBC8D5D90E6ULL,
		0x78E71A35EDAFDE51ULL,
		0x9A590FD0F8797F1FULL,
		0xB7AF65D6C38F2EA9ULL,
		0x6319DE454871140CULL
	}};
	sign = 0;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0835B2DA8B4EA9ABULL,
		0xF636C0F0C5186A37ULL,
		0x0DD734F5DC056103ULL,
		0xADBC2AA5FCE330BEULL,
		0x06639D7A9A21638BULL,
		0x40AE85E09FC52057ULL,
		0x776F32E99234E44DULL,
		0x901A58D3A0A2EBF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427767E19AF41FE2ULL,
		0x6A672006EC3A7A29ULL,
		0x926FC0F96EAC6361ULL,
		0x7D4627F839E96A4EULL,
		0x7296E4657A733009ULL,
		0xDB3523EA1C5E14B3ULL,
		0x8F9A5D35DAADFB4FULL,
		0x9FF45277E32C1015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5BE4AF8F05A89C9ULL,
		0x8BCFA0E9D8DDF00DULL,
		0x7B6773FC6D58FDA2ULL,
		0x307602ADC2F9C66FULL,
		0x93CCB9151FAE3382ULL,
		0x657961F683670BA3ULL,
		0xE7D4D5B3B786E8FDULL,
		0xF026065BBD76DBE2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x969F992E99537E1FULL,
		0x76FCA79FD8476413ULL,
		0xDB48637709555B45ULL,
		0xEADD09E87BEE151FULL,
		0x337486937C91B5BDULL,
		0x6DA3E958F6C6BF2DULL,
		0x6FACF6949F56A13CULL,
		0x712D4B9E574A5F8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB38DAE14CA12F5D6ULL,
		0xA0761398236F07BAULL,
		0x011CF613BDE56A95ULL,
		0xDA46C599EC0EC8B3ULL,
		0xEA7690B7EB1B6CE0ULL,
		0x633E2C86982DCD8AULL,
		0xA83EEA37D48BE03DULL,
		0xFEC696F1B83F6222ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE311EB19CF408849ULL,
		0xD6869407B4D85C58ULL,
		0xDA2B6D634B6FF0AFULL,
		0x1096444E8FDF4C6CULL,
		0x48FDF5DB917648DDULL,
		0x0A65BCD25E98F1A2ULL,
		0xC76E0C5CCACAC0FFULL,
		0x7266B4AC9F0AFD6AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0BCE255ACE758BEULL,
		0xC12D20FC161B3D45ULL,
		0xEADF828DBC05FD00ULL,
		0x1099F61BACF913D4ULL,
		0x18FF0D49944FE5C9ULL,
		0x399B3CF99D158816ULL,
		0x3360C8C37AE523D6ULL,
		0xA7FAC1E764BB0CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73838BD3E5EFF975ULL,
		0x1F08AFDF8A4699D3ULL,
		0x5A76C9B9119AA8FEULL,
		0xFB1E7D964D80297DULL,
		0x815D0F8A9884D8B1ULL,
		0x2A33B4E4C2B909C2ULL,
		0x97D596BA2CED550CULL,
		0x3682459E167D0AF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D395681C6F75F49ULL,
		0xA224711C8BD4A372ULL,
		0x9068B8D4AA6B5402ULL,
		0x157B78855F78EA57ULL,
		0x97A1FDBEFBCB0D17ULL,
		0x0F678814DA5C7E53ULL,
		0x9B8B32094DF7CECAULL,
		0x71787C494E3E0205ULL
	}};
	sign = 0;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48422DB6579C62B6ULL,
		0x5E208B77605A6EF7ULL,
		0x0F0F39D4357ECF17ULL,
		0xBB0E4506797A095AULL,
		0xEA8F1FAEF2B48762ULL,
		0xB725EDB48EFB7A9CULL,
		0x88B0DAE39D9FA191ULL,
		0x25D776B463056EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B6CD6D68833C9CULL,
		0x65F513F434D7A566ULL,
		0x00723DABFDC95313ULL,
		0x5C806F36DD7DB4C6ULL,
		0x97B2016D50AA439DULL,
		0x8FCF3A47AD681FFAULL,
		0x2D50BE9839DDEC62ULL,
		0xE233AB566757FD6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE8B6048EF19261AULL,
		0xF82B77832B82C990ULL,
		0x0E9CFC2837B57C03ULL,
		0x5E8DD5CF9BFC5494ULL,
		0x52DD1E41A20A43C5ULL,
		0x2756B36CE1935AA2ULL,
		0x5B601C4B63C1B52FULL,
		0x43A3CB5DFBAD7137ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F5BB01806ED98D5ULL,
		0x16D4C67D3E4EA577ULL,
		0x1824B2EA3BF73EA9ULL,
		0x9E17C517682E790DULL,
		0x4AD3B0F6A6DDCFCEULL,
		0xBEB4293DA419DF67ULL,
		0x6706BDDD6F96C8B4ULL,
		0xA8083BB494A12B93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5673803C804951BULL,
		0x1AC97118811E4625ULL,
		0xE3129DB0C244EBF1ULL,
		0xC6E3D076BAA0FF5EULL,
		0x055551C5D938B60FULL,
		0x10CEBAA38BAE4057ULL,
		0xB6A7925AB545FF60ULL,
		0xA5E02116475D7A58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9F478143EE903BAULL,
		0xFC0B5564BD305F51ULL,
		0x3512153979B252B7ULL,
		0xD733F4A0AD8D79AEULL,
		0x457E5F30CDA519BEULL,
		0xADE56E9A186B9F10ULL,
		0xB05F2B82BA50C954ULL,
		0x02281A9E4D43B13AULL
	}};
	sign = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB14B1890F9AAC7D4ULL,
		0x4D3B856FFFBBE36EULL,
		0x1924AAE00E1EF983ULL,
		0x4168C33245462AFBULL,
		0x15F1C5ED385632AEULL,
		0xF2DC74367027C961ULL,
		0xC67051500102E5E0ULL,
		0x46B7EA11DFDD15DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE2C611C4CD95A2ULL,
		0x0FC99AD83813E976ULL,
		0x04EFA5F42AFBE96EULL,
		0x1AA1FF215422BA50ULL,
		0x62DB6DB18D1A17C6ULL,
		0x6A7471EEA324DE20ULL,
		0x5FF791B8D8B7D572ULL,
		0x2AAE6F8CF99771B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6468527F34DD3232ULL,
		0x3D71EA97C7A7F9F8ULL,
		0x143504EBE3231015ULL,
		0x26C6C410F12370ABULL,
		0xB316583BAB3C1AE8ULL,
		0x88680247CD02EB40ULL,
		0x6678BF97284B106EULL,
		0x1C097A84E645A427ULL
	}};
	sign = 0;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF7C47A168CF74E0ULL,
		0xD22AB901DC2D4837ULL,
		0xB840738A37DC946CULL,
		0xA77CDA5A2445C3D4ULL,
		0xFCC68156E2657FADULL,
		0xAB709E7F97C49769ULL,
		0xE16FA54F710CD2EFULL,
		0xA76D059888A47164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA4B36A8073F774ULL,
		0xA39AC5EA0989C2E8ULL,
		0xAFDF7C508784BEE2ULL,
		0xC59CE17E707BCD9EULL,
		0x3C0EBAA7E76F6C63ULL,
		0xCD7DE1117CA7CEE5ULL,
		0x5D2E09FC671A7CB8ULL,
		0x30E527A7B3F68E15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3D79436E85B7D6CULL,
		0x2E8FF317D2A3854FULL,
		0x0860F739B057D58AULL,
		0xE1DFF8DBB3C9F636ULL,
		0xC0B7C6AEFAF61349ULL,
		0xDDF2BD6E1B1CC884ULL,
		0x84419B5309F25636ULL,
		0x7687DDF0D4ADE34FULL
	}};
	sign = 0;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7FF55205ED68CE9ULL,
		0xB7EF045CE7E64CDEULL,
		0x13ECD15877936D48ULL,
		0x64371A5F41BEC642ULL,
		0x7487D094B1CD2926ULL,
		0x48434119D4755F5FULL,
		0xBDD7E105D853EC0FULL,
		0x2B77D830CC117C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AB13341ED527DBULL,
		0x704084C75FB90387ULL,
		0xFE6F7A33E063DBF3ULL,
		0xAEC1B1B8CCBC1EAFULL,
		0xB7B9D91B731EFBE0ULL,
		0x6746D8DE643374B1ULL,
		0x9A4AE2F7F7DCF072ULL,
		0x6F8329BD90F1C425ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x055441EC4001650EULL,
		0x47AE7F95882D4957ULL,
		0x157D5724972F9155ULL,
		0xB57568A67502A792ULL,
		0xBCCDF7793EAE2D45ULL,
		0xE0FC683B7041EAADULL,
		0x238CFE0DE076FB9CULL,
		0xBBF4AE733B1FB846ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EE93E5B735889C7ULL,
		0xAE7B3C214CA79493ULL,
		0xD1C56F6C29F1A9EBULL,
		0x3D7B18F57C7C3526ULL,
		0x54B46E394F8DA2D9ULL,
		0xCC82FE5D9F9A117AULL,
		0x24971D2A8A6E8126ULL,
		0x7B70F2058A042CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED4904B1D9EAAF5ULL,
		0x45B75277D8100793ULL,
		0x6E85B57C73440E58ULL,
		0xFBA8B6C207AF35DCULL,
		0x52E87AE94C2DB0FEULL,
		0x4BB8E6E6D8DBBE74ULL,
		0x5AF0D9B4A8352A42ULL,
		0x3AF81631C7644968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB014AE1055B9DED2ULL,
		0x68C3E9A974978CFFULL,
		0x633FB9EFB6AD9B93ULL,
		0x41D2623374CCFF4AULL,
		0x01CBF350035FF1DAULL,
		0x80CA1776C6BE5306ULL,
		0xC9A64375E23956E4ULL,
		0x4078DBD3C29FE368ULL
	}};
	sign = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C28654D3A79377EULL,
		0xF2B8CB176168B6F9ULL,
		0xDE214ACEC4AC575AULL,
		0xC68A942A9A21B87DULL,
		0x2AB127715DA2A5FBULL,
		0xB31584F76EB1338AULL,
		0xF0B74C5DB5675675ULL,
		0xC40668C855789FFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F28659E8DD4DD72ULL,
		0xD93E62399467F373ULL,
		0x2AB98529FED88AC1ULL,
		0x72480B5192126A5BULL,
		0xC9A1C20D98A0DA88ULL,
		0x7267095E7BE4D964ULL,
		0xAD027E6D294BFE68ULL,
		0xDD2CE5F78D9207E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CFFFFAEACA45A0CULL,
		0x197A68DDCD00C386ULL,
		0xB367C5A4C5D3CC99ULL,
		0x544288D9080F4E22ULL,
		0x610F6563C501CB73ULL,
		0x40AE7B98F2CC5A25ULL,
		0x43B4CDF08C1B580DULL,
		0xE6D982D0C7E69818ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAC7A64C65A7E152ULL,
		0xA2C066C10A27F6F5ULL,
		0x13DBEB4BADC5F164ULL,
		0x15155EB8973F79D4ULL,
		0x9A84484C828A0667ULL,
		0xE47A6966681D6B0FULL,
		0xEFBD3DA6AEB820C9ULL,
		0xD63A36E5E219D6B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8DD6F091B645306ULL,
		0x5E063CC5210C62DAULL,
		0xDBD95E17DB5CC0DCULL,
		0x6E9FFC69D183CE2DULL,
		0xFD96C915AFA08D12ULL,
		0xC69C08D7F95C62A2ULL,
		0x0274E8649B7F84F8ULL,
		0xE444AF78C446B446ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1EA37434A438E4CULL,
		0x44BA29FBE91B941AULL,
		0x38028D33D2693088ULL,
		0xA675624EC5BBABA6ULL,
		0x9CED7F36D2E97954ULL,
		0x1DDE608E6EC1086CULL,
		0xED48554213389BD1ULL,
		0xF1F5876D1DD32272ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9846E7002127576ULL,
		0xE0AE4AC2A1DAC9EEULL,
		0x57B5163036481AFCULL,
		0xC6F10480C22C08F8ULL,
		0xBD1800C21FB3E737ULL,
		0xA0D2FC3E76166E0EULL,
		0x23D6632189414484ULL,
		0x6492E25ADA463428ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x832204B023177E24ULL,
		0x2836F7CBA4DCC91DULL,
		0x6382D071AA309CFCULL,
		0x2DC21C5135955D52ULL,
		0xA999691C37EBC72BULL,
		0x1D576490C2C6AB4CULL,
		0x3C2BCD2C525FF453ULL,
		0x19E665115E02EFC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x766269BFDEFAF752ULL,
		0xB87752F6FCFE00D1ULL,
		0xF43245BE8C177E00ULL,
		0x992EE82F8C96ABA5ULL,
		0x137E97A5E7C8200CULL,
		0x837B97ADB34FC2C2ULL,
		0xE7AA95F536E15031ULL,
		0x4AAC7D497C434464ULL
	}};
	sign = 0;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CCBA6C82CE7BF16ULL,
		0x47805AC42B0BC748ULL,
		0x2C0F6E766BD0F35CULL,
		0x5CB1491FE0F0CBB1ULL,
		0x007B47DB64C8F320ULL,
		0xF788809B1107D9E0ULL,
		0xABE8D5844CF4589EULL,
		0x1D8CE24E30530ACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x713253F5ABDD8667ULL,
		0xE98E7F72BD9D0884ULL,
		0xF04A7BDD4B80C004ULL,
		0x7661DA79D161B7C1ULL,
		0xDAA7C5CFFACF4B08ULL,
		0xDEB63D1D95A2E830ULL,
		0x52D2B47DF6BD79F5ULL,
		0x918F067A87E3E536ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B9952D2810A38AFULL,
		0x5DF1DB516D6EBEC4ULL,
		0x3BC4F29920503357ULL,
		0xE64F6EA60F8F13EFULL,
		0x25D3820B69F9A817ULL,
		0x18D2437D7B64F1AFULL,
		0x591621065636DEA9ULL,
		0x8BFDDBD3A86F2599ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4255ABBD46FDAF39ULL,
		0xF6B2DDA881D51A5DULL,
		0x3D3566A0697CAF8AULL,
		0x7D07CC1AB8ED017BULL,
		0x2545E237BA5FD03FULL,
		0x06CDAA4F3AEE722FULL,
		0xED8EE7ADD330256EULL,
		0xF809616F011AAFF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43FF0070D3A13D4AULL,
		0xE1AF61F6D37FFF3AULL,
		0x0D4AEAF58ECFDEC0ULL,
		0x7C106B2AAA8EC477ULL,
		0xEF0FDC41EA2428D7ULL,
		0x32E312E56390234CULL,
		0x456F0D7D29A29AC3ULL,
		0xB6888F8007F9004FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE56AB4C735C71EFULL,
		0x15037BB1AE551B22ULL,
		0x2FEA7BAADAACD0CAULL,
		0x00F760F00E5E3D04ULL,
		0x363605F5D03BA768ULL,
		0xD3EA9769D75E4EE2ULL,
		0xA81FDA30A98D8AAAULL,
		0x4180D1EEF921AFA9ULL
	}};
	sign = 0;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFED6A0468BE70B3ULL,
		0xA857F73D4E361D06ULL,
		0xA1E5BEEE6670A68FULL,
		0x75B7E505D848F8F0ULL,
		0xCE484D8C45B8ED7EULL,
		0x97ADBBB99AA83B3AULL,
		0x64C5CE50D4128B13ULL,
		0x1A856687C50D97E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D67FC81B3D2E98ULL,
		0x3965A56D46C17CC6ULL,
		0x50E5F06D8D7E430AULL,
		0xF0EEDC0934AF7AA9ULL,
		0xFE1E8C33EB2B1B19ULL,
		0xA74A0F45008FBD57ULL,
		0x44F366F7A2077DFAULL,
		0x94B3FCA20D2BC6D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2616EA3C4D81421BULL,
		0x6EF251D00774A040ULL,
		0x50FFCE80D8F26385ULL,
		0x84C908FCA3997E47ULL,
		0xD029C1585A8DD264ULL,
		0xF063AC749A187DE2ULL,
		0x1FD26759320B0D18ULL,
		0x85D169E5B7E1D114ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0D4DC1806CEA0EDULL,
		0x79792EF6BD93A66AULL,
		0x03D4ACAC2DD1BB79ULL,
		0x770914A5F84F4009ULL,
		0x239CCA798CDEF80CULL,
		0x8693D875D5FBB398ULL,
		0xDBBBD55137C0EFC4ULL,
		0x146CF408084909AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538A33554D0753C8ULL,
		0xFCCA10CE0E1FCA54ULL,
		0xCB21A6B3D98EFDA6ULL,
		0x091A255116B1C7E2ULL,
		0x1AF5A324781AF963ULL,
		0x8F3C53119990B828ULL,
		0xFCC5D49078618AA0ULL,
		0xB8FEB77B378910DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D4AA8C2B9C74D25ULL,
		0x7CAF1E28AF73DC16ULL,
		0x38B305F85442BDD2ULL,
		0x6DEEEF54E19D7826ULL,
		0x08A7275514C3FEA9ULL,
		0xF75785643C6AFB70ULL,
		0xDEF600C0BF5F6523ULL,
		0x5B6E3C8CD0BFF8CFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08ECECB141A74114ULL,
		0x658987A973E9DD7CULL,
		0x63B53729D24406FEULL,
		0x3EB0BE45E60551CAULL,
		0x8F9FB9DF97CB9DDBULL,
		0xBE2D0A7BCB0383B7ULL,
		0x5593C4878D4F68A2ULL,
		0x25138E3D79B44E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70F950081BFFEFF6ULL,
		0x65B3C175A77DF1DFULL,
		0xDA718AE64B87B437ULL,
		0x6864349BAE8DC8C5ULL,
		0xA16F45ACCEA5182DULL,
		0xE1312EEE1D2E0100ULL,
		0x9C28E44F9E7FBB77ULL,
		0xD5CAB1EE954F49DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97F39CA925A7511EULL,
		0xFFD5C633CC6BEB9CULL,
		0x8943AC4386BC52C6ULL,
		0xD64C89AA37778904ULL,
		0xEE307432C92685ADULL,
		0xDCFBDB8DADD582B6ULL,
		0xB96AE037EECFAD2AULL,
		0x4F48DC4EE465049AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEBA537C958339F9ULL,
		0x56936C894A43729BULL,
		0xF56D1D83F750A3CBULL,
		0x0BD286B285D5FCDFULL,
		0xEF94527596085925ULL,
		0x310DD9F6BD1F71FDULL,
		0x2C08B3AE30C420D2ULL,
		0x6941117D55C23017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0757B7BA2E060F4ULL,
		0x1F9C9AD8FD23BFF7ULL,
		0xACC3F02C349A8BF4ULL,
		0x5B9898B2A8B15711ULL,
		0x3DA91FFD28EC8AC2ULL,
		0x08523F435A111910ULL,
		0xD7E9B312D24237F6ULL,
		0x18DB8055FBB42C6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E44D800F2A2D905ULL,
		0x36F6D1B04D1FB2A4ULL,
		0x48A92D57C2B617D7ULL,
		0xB039EDFFDD24A5CEULL,
		0xB1EB32786D1BCE62ULL,
		0x28BB9AB3630E58EDULL,
		0x541F009B5E81E8DCULL,
		0x506591275A0E03AAULL
	}};
	sign = 0;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7B8AE299900397BULL,
		0xBA01C361457E2FFFULL,
		0xD1B058E03CB9B529ULL,
		0x3C461839C28BCFEFULL,
		0xC35B056D496859F4ULL,
		0x0A4389A5EC379A53ULL,
		0x0A0546EFE0A97C56ULL,
		0xE40A91CA48189804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A224E9E81FCE9E8ULL,
		0x82EEBAC9EECAAD6FULL,
		0x78E0C7E0152E2070ULL,
		0xECA273E2E812A94CULL,
		0x2943C85DBF9C5F64ULL,
		0xFB5BB90519E21485ULL,
		0x38FC0AE7D6FA813AULL,
		0x6DE5285D3571EC22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD965F8B17034F93ULL,
		0x3713089756B38290ULL,
		0x58CF9100278B94B9ULL,
		0x4FA3A456DA7926A3ULL,
		0x9A173D0F89CBFA8FULL,
		0x0EE7D0A0D25585CEULL,
		0xD1093C0809AEFB1BULL,
		0x7625696D12A6ABE1ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69311B33F72A8B8ULL,
		0x34D8778E8B30AA8DULL,
		0x3CBC1F2DFD21FF3EULL,
		0xC7868FD9CD406E45ULL,
		0x9A83553603C4A91CULL,
		0x7EC7D47BFC8BAC55ULL,
		0xBDFE07EA5063EB11ULL,
		0x32FD5EA0D30FDA3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BD15DD77EBF2D7AULL,
		0x168F02B25138F29DULL,
		0x988032C95869A263ULL,
		0xC847F7FD7FBFFFD2ULL,
		0x3DFA66B4C03E5478ULL,
		0xC442C1822EF6D679ULL,
		0xD5E838835BD63E8AULL,
		0x7007E47DEB93CE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AC1B3DBC0B37B3EULL,
		0x1E4974DC39F7B7F0ULL,
		0xA43BEC64A4B85CDBULL,
		0xFF3E97DC4D806E72ULL,
		0x5C88EE81438654A3ULL,
		0xBA8512F9CD94D5DCULL,
		0xE815CF66F48DAC86ULL,
		0xC2F57A22E77C0C02ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FA0473CEBE3A9C6ULL,
		0xF0C18E53295BB0C0ULL,
		0x6DAB4B11740599D1ULL,
		0x1FEA202501B3F47CULL,
		0xD1737BCE02FC2532ULL,
		0x7F027E9A0F53E695ULL,
		0x1E0F5AF81BE9137CULL,
		0xEBCC62FD7757EC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5476C66BC5D4E6F6ULL,
		0xF315DDEF59551C28ULL,
		0xF8A45C7722F5AEE9ULL,
		0x141EFC31A69C9C55ULL,
		0x57709F46099BBF66ULL,
		0x9598B945947DA429ULL,
		0x3E65F1976FB6F710ULL,
		0xB2578B176140F8A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B2980D1260EC2D0ULL,
		0xFDABB063D0069498ULL,
		0x7506EE9A510FEAE7ULL,
		0x0BCB23F35B175826ULL,
		0x7A02DC87F96065CCULL,
		0xE969C5547AD6426CULL,
		0xDFA96960AC321C6BULL,
		0x3974D7E61616F3C4ULL
	}};
	sign = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50433F1843ECD066ULL,
		0x086DB3718C18DDA6ULL,
		0x6B2AD4D0A85601C0ULL,
		0x41240DC9115B35B3ULL,
		0x00D3AE1F8F3CE8CDULL,
		0x628FBEB57E2F18CEULL,
		0x5334860B4CE3013AULL,
		0x4307839C9864BCEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x617DE71CF3724F49ULL,
		0xAC801F7EEF76DE60ULL,
		0xAC5837DCB157A575ULL,
		0x1F9DB35F169BAF85ULL,
		0xD85BE2FD665525FAULL,
		0x999D358AB3C6504CULL,
		0x0D7E6087E0C2CD49ULL,
		0x6C967A904686B233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEC557FB507A811DULL,
		0x5BED93F29CA1FF45ULL,
		0xBED29CF3F6FE5C4AULL,
		0x21865A69FABF862DULL,
		0x2877CB2228E7C2D3ULL,
		0xC8F2892ACA68C881ULL,
		0x45B625836C2033F0ULL,
		0xD671090C51DE0AB8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EEAC70521590D8DULL,
		0x169DD6B5D7009D00ULL,
		0x534CA593BD54F9EAULL,
		0xA99DC122C7ED81F2ULL,
		0x018F6E86665D7760ULL,
		0x607894B7182D1D11ULL,
		0x638640301A0F6C7AULL,
		0xD1954CF0B39A29E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9443D8D5A8FE6A9AULL,
		0x639FFC035FA4600CULL,
		0x38BC5837DED2A8C8ULL,
		0x6D0809E9B969B04DULL,
		0x72163ADA2E60B96CULL,
		0x5797D932F432122CULL,
		0xF94203AD626105EFULL,
		0x6F0AE46DAB65B5A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAA6EE2F785AA2F3ULL,
		0xB2FDDAB2775C3CF3ULL,
		0x1A904D5BDE825121ULL,
		0x3C95B7390E83D1A5ULL,
		0x8F7933AC37FCBDF4ULL,
		0x08E0BB8423FB0AE4ULL,
		0x6A443C82B7AE668BULL,
		0x628A688308347439ULL
	}};
	sign = 0;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x458339FC98333564ULL,
		0x04DE0B73CF2E2F8BULL,
		0xC3C4A1B2E332855DULL,
		0x1EE453CD2809780BULL,
		0x3A8154BBB0C411F5ULL,
		0x06006DE3277F8CA5ULL,
		0xDEABAD88BA2E9F55ULL,
		0xF15AE2904C7F5ECBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1897EF0BBBEF477FULL,
		0x6D16AA2FD679A303ULL,
		0xACBB832DE9A334EFULL,
		0x1ACD6F199BEBFE63ULL,
		0xD43EC0501167ACCBULL,
		0x3A55EDB0DE95EB26ULL,
		0x7D8F47FCD8410CE9ULL,
		0x10118FE1FBDF9847ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CEB4AF0DC43EDE5ULL,
		0x97C76143F8B48C88ULL,
		0x17091E84F98F506DULL,
		0x0416E4B38C1D79A8ULL,
		0x6642946B9F5C652AULL,
		0xCBAA803248E9A17EULL,
		0x611C658BE1ED926BULL,
		0xE14952AE509FC684ULL
	}};
	sign = 0;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8018673900C8C813ULL,
		0x18932F0DA7C67E38ULL,
		0x87C181C9EB9E598FULL,
		0x2F6B30EC842BD940ULL,
		0xF43029B1A6E38528ULL,
		0xCB8E8B1CB3B406AAULL,
		0xE5CA93CFFC9E00C7ULL,
		0x64D62489B9B6E66FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9DC1C074550F58ULL,
		0xC7CBD0F5F7FB00CAULL,
		0xCCED13989D7AFB65ULL,
		0x23579C9AAA875363ULL,
		0xEC12F48D4EB0F9F1ULL,
		0xBC7A607EF4CC9767ULL,
		0xA9E79CB90FB8121FULL,
		0xC7BF31C8C4869CA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD47AA5788C73B8BBULL,
		0x50C75E17AFCB7D6DULL,
		0xBAD46E314E235E29ULL,
		0x0C139451D9A485DCULL,
		0x081D352458328B37ULL,
		0x0F142A9DBEE76F43ULL,
		0x3BE2F716ECE5EEA8ULL,
		0x9D16F2C0F53049C7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3418968D030B030ULL,
		0xF8F9A4EDAD552923ULL,
		0xF75ED5928991A74DULL,
		0x9C1B7208A7D4ADD9ULL,
		0x9701B9B9C81485CAULL,
		0xA94930DA13A58FF1ULL,
		0xFA1A4CB1F511FA9DULL,
		0x8038C7DB9842233FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18E85B670E479E8ULL,
		0x3D5CCECD814A5BD6ULL,
		0x64FB7BC108F3D52EULL,
		0x3F9E110F12D6730CULL,
		0x6FE4F5FD2CEF6159ULL,
		0x86111F514FCDDCE1ULL,
		0x1926991BAB536353ULL,
		0x01ECD2020420F573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31B303B25F4C3648ULL,
		0xBB9CD6202C0ACD4DULL,
		0x926359D1809DD21FULL,
		0x5C7D60F994FE3ACDULL,
		0x271CC3BC9B252471ULL,
		0x23381188C3D7B310ULL,
		0xE0F3B39649BE974AULL,
		0x7E4BF5D994212DCCULL
	}};
	sign = 0;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC86AC6E80A6E1C42ULL,
		0x1ACA8E97B804FFEAULL,
		0x438D10621C121049ULL,
		0x3A320826FAA5DD14ULL,
		0x630D097963B5EE74ULL,
		0x4794D73797DEB621ULL,
		0xE3E8C2F99A6C82DFULL,
		0x86AFC60C7755F319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x893D9FE535FE8C45ULL,
		0x32407A5AC1E9BF76ULL,
		0x5DD966BAEFE89B81ULL,
		0x7D925CF7CB58E0EEULL,
		0x55DF50EBBCCB4508ULL,
		0x966E5D684FE61FD1ULL,
		0x32B50F1E6BAF8819ULL,
		0xB86A5A9BF7F7E810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F2D2702D46F8FFDULL,
		0xE88A143CF61B4074ULL,
		0xE5B3A9A72C2974C7ULL,
		0xBC9FAB2F2F4CFC25ULL,
		0x0D2DB88DA6EAA96BULL,
		0xB12679CF47F89650ULL,
		0xB133B3DB2EBCFAC5ULL,
		0xCE456B707F5E0B09ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31C09F9EB24ADB24ULL,
		0x9695CAE7C568908DULL,
		0xF53FF119B03FBE0FULL,
		0xCAFC797575836207ULL,
		0x258AD3A5B26A9BDBULL,
		0xCB0130CFCCA815B2ULL,
		0x080F330E90F730DDULL,
		0x50712F5273C1048DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B47AD7C7BC45E73ULL,
		0x81FEB6BE278342B8ULL,
		0xC6E2D7D0670CD732ULL,
		0xE95F081E30D7FB43ULL,
		0x48734CE99476EA80ULL,
		0x18BE72F8CEF8D176ULL,
		0x21E64F2E7D75EB49ULL,
		0x1DAFD9DFBE36D182ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9678F22236867CB1ULL,
		0x149714299DE54DD4ULL,
		0x2E5D19494932E6DDULL,
		0xE19D715744AB66C4ULL,
		0xDD1786BC1DF3B15AULL,
		0xB242BDD6FDAF443BULL,
		0xE628E3E013814594ULL,
		0x32C15572B58A330AULL
	}};
	sign = 0;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB12D91B7395ADC27ULL,
		0x06F91D6E62585A19ULL,
		0x788D82114E912FCBULL,
		0x7D45B83E4F0C3BF4ULL,
		0xA6D4CCF1FD8727DBULL,
		0xEDE094D43DC068F4ULL,
		0x87AB16B74D999AC9ULL,
		0x087221A77B98B577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6192DD07F1F66911ULL,
		0xB8BF878B5747B110ULL,
		0x87FEC33147A9D4C3ULL,
		0x0342D479CACAE161ULL,
		0x901FC6FEF1B03641ULL,
		0x5575DDA430E6B551ULL,
		0x5C7927B133947C36ULL,
		0x12D47A46AAB390ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F9AB4AF47647316ULL,
		0x4E3995E30B10A909ULL,
		0xF08EBEE006E75B07ULL,
		0x7A02E3C484415A92ULL,
		0x16B505F30BD6F19AULL,
		0x986AB7300CD9B3A3ULL,
		0x2B31EF061A051E93ULL,
		0xF59DA760D0E524CBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBADAABD816FF424DULL,
		0xAA480832DDDC6179ULL,
		0x6E6154BE226A936FULL,
		0x7C0E9FECFD46622BULL,
		0xB2956F6B192AA331ULL,
		0x81936D4745D8F459ULL,
		0x860D291A1810FE7EULL,
		0xF33A86EA347C10A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43CDB365D6A9CB5ULL,
		0x84A47C8F776CAB7FULL,
		0xC3F5CDD5A3316F97ULL,
		0xCD3EAE1178B5DF3EULL,
		0xB57F4BCC485ABF71ULL,
		0x1067CA9E683EE9D1ULL,
		0xE5D63983B5476D23ULL,
		0x6D39AC5FABC54A1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD69DD0A1B994A598ULL,
		0x25A38BA3666FB5F9ULL,
		0xAA6B86E87F3923D8ULL,
		0xAECFF1DB849082ECULL,
		0xFD16239ED0CFE3BFULL,
		0x712BA2A8DD9A0A87ULL,
		0xA036EF9662C9915BULL,
		0x8600DA8A88B6C686ULL
	}};
	sign = 0;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0842792BDBE63B52ULL,
		0xFDF577D01A1D68C3ULL,
		0xF14CEC75FD55BBF9ULL,
		0x1B2101EDAFCF7699ULL,
		0x0C984215AEBBDDD5ULL,
		0x248ACC352733C849ULL,
		0xBAA19CB9AEA5198EULL,
		0xE7541B3BEC1A2411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE116615D49F2515FULL,
		0xA515C7BF07B5FE1FULL,
		0x7739ABAA49682FDAULL,
		0xE5A6D3430FF4B040ULL,
		0x8A18831ACD04ED80ULL,
		0x43E23E00F7C3EB96ULL,
		0x0D8D07B5CDE55385ULL,
		0x487A8BD78074364EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x272C17CE91F3E9F3ULL,
		0x58DFB01112676AA3ULL,
		0x7A1340CBB3ED8C1FULL,
		0x357A2EAA9FDAC659ULL,
		0x827FBEFAE1B6F054ULL,
		0xE0A88E342F6FDCB2ULL,
		0xAD149503E0BFC608ULL,
		0x9ED98F646BA5EDC3ULL
	}};
	sign = 0;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B5E1DBBFD9A69C5ULL,
		0x13FC8BE6E2C9BC34ULL,
		0x90D6236E4CD8E148ULL,
		0xEDF5A93D7AE25441ULL,
		0x0ACFEA47EC596612ULL,
		0x1C456AE3AAE62464ULL,
		0x8B574473FADCC299ULL,
		0x7614D1B2DF7232DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF14DFB447B07DEULL,
		0x4120CB98CE92B7C3ULL,
		0xC20DE078F480CCB4ULL,
		0xA26885287ADD7C69ULL,
		0x3C0905198CFE2477ULL,
		0x5AB091E078A5A89AULL,
		0x5D9EFFD71991EBD2ULL,
		0xA8D71CC5340A8CFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C6CCFC0B91F61E7ULL,
		0xD2DBC04E14370471ULL,
		0xCEC842F558581493ULL,
		0x4B8D24150004D7D7ULL,
		0xCEC6E52E5F5B419BULL,
		0xC194D90332407BC9ULL,
		0x2DB8449CE14AD6C6ULL,
		0xCD3DB4EDAB67A5E1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B287C720B5F0AC2ULL,
		0x476610DE38639DBEULL,
		0x187654AEEA0A2054ULL,
		0xB2958AD8434EE4F9ULL,
		0x292469806FF4538BULL,
		0xEF163AA7E7F645ABULL,
		0x09955A9A457F184BULL,
		0xA0A3C47BD7854F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5A2A1536212FF27ULL,
		0xDDC8884027D09F23ULL,
		0x2F36B7E9A2B0BD86ULL,
		0x34C1D83F41A499D7ULL,
		0xEB99835C9022EAC4ULL,
		0x0B98DD9CA1784B01ULL,
		0xF19FC92AD0E085DBULL,
		0x71F9B9A8C416D926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA585DB1EA94C0B9BULL,
		0x699D889E1092FE9AULL,
		0xE93F9CC5475962CDULL,
		0x7DD3B29901AA4B21ULL,
		0x3D8AE623DFD168C7ULL,
		0xE37D5D0B467DFAA9ULL,
		0x17F5916F749E9270ULL,
		0x2EAA0AD3136E7645ULL
	}};
	sign = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD10C7C8A42A7D335ULL,
		0x57705C35A813C4BAULL,
		0xE9C4A9F0B314E524ULL,
		0x614513B33D93B4D6ULL,
		0x335F9ABE21554EDCULL,
		0xE2A48EA5854348DDULL,
		0x8C91A9239779B3F7ULL,
		0xA3949CEFD0B8AB6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F3B33CEB8F4FE48ULL,
		0x812F4F71F33E7DFCULL,
		0xCA103730661DBFEFULL,
		0xE89D351D27BE4E58ULL,
		0xB53A95BEB0A2676BULL,
		0x1F3D173E86BD6CDCULL,
		0xB128FBF78A9DF4CBULL,
		0x22663B80C475F07DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91D148BB89B2D4EDULL,
		0xD6410CC3B4D546BEULL,
		0x1FB472C04CF72534ULL,
		0x78A7DE9615D5667EULL,
		0x7E2504FF70B2E770ULL,
		0xC3677766FE85DC00ULL,
		0xDB68AD2C0CDBBF2CULL,
		0x812E616F0C42BAEFULL
	}};
	sign = 0;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31C832A44DE17155ULL,
		0xB578DF8258F7FA26ULL,
		0x4C48BCCDA418888BULL,
		0xF5466B789B816072ULL,
		0x6BF43369893A0F8BULL,
		0xE33A8CBB6F2393C0ULL,
		0x916750C7CA9CD60CULL,
		0xDDEAF3FCA39BA7AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77475EE9C4C4748ULL,
		0xB21D954367FD92E5ULL,
		0x1472F5C937043149ULL,
		0x7A120461D3215F7AULL,
		0x92F3293969FE6D91ULL,
		0x3D3C6981711753EDULL,
		0xD674EAC2CE7BD174ULL,
		0x9F4E73C37DEC77E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A53BCB5B1952A0DULL,
		0x035B4A3EF0FA6740ULL,
		0x37D5C7046D145742ULL,
		0x7B346716C86000F8ULL,
		0xD9010A301F3BA1FAULL,
		0xA5FE2339FE0C3FD2ULL,
		0xBAF26604FC210498ULL,
		0x3E9C803925AF2FC8ULL
	}};
	sign = 0;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F7890B172C605FDULL,
		0xC59102FE7BE27FFBULL,
		0x7071AE34655E871FULL,
		0x3CAAECFE1036BBDFULL,
		0xF3789F86A16CF7ACULL,
		0x46A3EF4E82295F43ULL,
		0x7C946E76A6AC717FULL,
		0xA950A34C893C9041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702D36D9E2088D53ULL,
		0x8C8D56B85C633E4FULL,
		0xB50F0D67E47B1A9FULL,
		0xEC61DF2C12EFADABULL,
		0xB7218E293F08F959ULL,
		0x0DA9F0FFD1F7DB65ULL,
		0x27A6688216065749ULL,
		0xAF5E1A89D4DF977BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF4B59D790BD78AAULL,
		0x3903AC461F7F41ABULL,
		0xBB62A0CC80E36C80ULL,
		0x50490DD1FD470E33ULL,
		0x3C57115D6263FE52ULL,
		0x38F9FE4EB03183DEULL,
		0x54EE05F490A61A36ULL,
		0xF9F288C2B45CF8C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D37494D675A82E2ULL,
		0xDE7643CDB0AB9A95ULL,
		0xBFE3D1C5858466B2ULL,
		0x390B6175EC9FFB0FULL,
		0x4796AA338C218715ULL,
		0x23188E802279FEE9ULL,
		0x2A03AD21B837A868ULL,
		0xBCE088076EEB31D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58959B5E38BE045FULL,
		0x4C2A276320F067CEULL,
		0x3E53EA2C9ABE60FAULL,
		0x9DD182F5273BD282ULL,
		0x27D44B3B5E11BA64ULL,
		0x925A8740F0AD06EFULL,
		0xB406B5AC39681D9FULL,
		0xAC245E5D684BED0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24A1ADEF2E9C7E83ULL,
		0x924C1C6A8FBB32C7ULL,
		0x818FE798EAC605B8ULL,
		0x9B39DE80C564288DULL,
		0x1FC25EF82E0FCCB0ULL,
		0x90BE073F31CCF7FAULL,
		0x75FCF7757ECF8AC8ULL,
		0x10BC29AA069F44CCULL
	}};
	sign = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4999C526E2A3C06ULL,
		0x27E8A6F18388B4ACULL,
		0x304AB1887A9CCD12ULL,
		0x5DB81AB7E789F62CULL,
		0x31F0B3DC39F553D0ULL,
		0xC7CC4AF21448BC15ULL,
		0x8DC1EBF56A7CA0D8ULL,
		0x44734066341733E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A80F3AEFD34957FULL,
		0x9ADD995727D150E3ULL,
		0x165B748281E56E27ULL,
		0x2320AC563529756DULL,
		0x5B02205201E7B549ULL,
		0xA64D486CEBA7AD50ULL,
		0x2A324C2215431F7BULL,
		0x79445FA6A7756341ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A18A8A370F5A687ULL,
		0x8D0B0D9A5BB763C9ULL,
		0x19EF3D05F8B75EEAULL,
		0x3A976E61B26080BFULL,
		0xD6EE938A380D9E87ULL,
		0x217F028528A10EC4ULL,
		0x638F9FD35539815DULL,
		0xCB2EE0BF8CA1D0A2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42038DB429D4FA61ULL,
		0x634EE56451E3DC08ULL,
		0x79688378A1BFEEA6ULL,
		0xDA6EFC64E947A1ADULL,
		0xC329BB44C1DEF76AULL,
		0x8FBD05A9C203E0A0ULL,
		0xAFBC5D44DA8DE83BULL,
		0x2D5B28836D217361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53D865949C542131ULL,
		0xE296D3DE8AC92A90ULL,
		0x33AA160E11EF42BDULL,
		0xD269C8B857D24871ULL,
		0x96FA2652DD3EEEB6ULL,
		0x70F251F95A5EFB09ULL,
		0x6C2393CE6E510085ULL,
		0xB16B4DC6418B1BE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE2B281F8D80D930ULL,
		0x80B81185C71AB177ULL,
		0x45BE6D6A8FD0ABE8ULL,
		0x080533AC9175593CULL,
		0x2C2F94F1E4A008B4ULL,
		0x1ECAB3B067A4E597ULL,
		0x4398C9766C3CE7B6ULL,
		0x7BEFDABD2B965780ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8C2D066283E21EEULL,
		0xB257C2FCB89B2A57ULL,
		0x638E8352BA485A1EULL,
		0xA747E9B59DC4BD80ULL,
		0x90211A890EFEC020ULL,
		0x2D5FBF970878F8AAULL,
		0x12E39647E9FE030AULL,
		0x3DF4573F7A352B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72684B953F624E4DULL,
		0x3D93CBE68CBB2E8CULL,
		0x3FB567329024F586ULL,
		0xF3782F3B494F3E07ULL,
		0xE6A532F7CAFE989BULL,
		0x79AF3BE47C94AE07ULL,
		0x1ED0053E5D507C93ULL,
		0xFFCD70587F2DED36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x665A84D0E8DBD3A1ULL,
		0x74C3F7162BDFFBCBULL,
		0x23D91C202A236498ULL,
		0xB3CFBA7A54757F79ULL,
		0xA97BE79144002784ULL,
		0xB3B083B28BE44AA2ULL,
		0xF41391098CAD8676ULL,
		0x3E26E6E6FB073E61ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F34A6D94AC6068EULL,
		0x3E67DF66B2033143ULL,
		0x309611AB3F0363A6ULL,
		0x24EC8B13DB1F9B7CULL,
		0x3A57ED75FAB519A8ULL,
		0xE98EC29DA8F3470FULL,
		0x9B21F7B7A716412BULL,
		0x580D306D125701D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB6CF7E5832498FULL,
		0xCA78A2412B55EBA3ULL,
		0x27A55C2160C792F5ULL,
		0x6D664D791787041BULL,
		0xC9A752752A1425ADULL,
		0xBE8C38289037FDBCULL,
		0x3E46E65239661B03ULL,
		0xB50E52EC2C947273ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x717DD75AF293BCFFULL,
		0x73EF3D2586AD45A0ULL,
		0x08F0B589DE3BD0B0ULL,
		0xB7863D9AC3989761ULL,
		0x70B09B00D0A0F3FAULL,
		0x2B028A7518BB4952ULL,
		0x5CDB11656DB02628ULL,
		0xA2FEDD80E5C28F65ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75CC36C4DF6BBA4FULL,
		0xA3E8C647356B31ECULL,
		0x5E40065A5509C038ULL,
		0xBCFEFC0C5C35C6C4ULL,
		0xD9D543F9C52AB969ULL,
		0xDAFF1D8603A18677ULL,
		0xCD235B40D9EF5A03ULL,
		0xCDC3D4BFF8CCF7DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1901ED6818C51B30ULL,
		0x6A24C90425D060FBULL,
		0xDC3344529565B083ULL,
		0x9255B2A614F83818ULL,
		0x06EE764D6E999008ULL,
		0xD9D83DEDCE2C677AULL,
		0xB49CD4851119E4A2ULL,
		0x352A13FB235E025AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CCA495CC6A69F1FULL,
		0x39C3FD430F9AD0F1ULL,
		0x820CC207BFA40FB5ULL,
		0x2AA94966473D8EABULL,
		0xD2E6CDAC56912961ULL,
		0x0126DF9835751EFDULL,
		0x188686BBC8D57561ULL,
		0x9899C0C4D56EF582ULL
	}};
	sign = 0;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF30F36EF6BC66A0CULL,
		0x6308133051975E4EULL,
		0x8AB67C2CA53A9D2DULL,
		0x7473E72EA07D1A10ULL,
		0xBB321BC7B1386DC0ULL,
		0x919CDDA2E729FCFCULL,
		0x6CF4F6CB6976FABBULL,
		0x473598ADE56224E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCB64E4A04EAC127ULL,
		0xD4884F32F1BCA155ULL,
		0xEFF85EA4AEB7391EULL,
		0x64BD8005F675AA75ULL,
		0x052BE32E7809B7EBULL,
		0x6A5D142ABC23C5CDULL,
		0xF5F0D4C76509AA7BULL,
		0x4FCD41B012507CABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1658E8A566DBA8E5ULL,
		0x8E7FC3FD5FDABCF9ULL,
		0x9ABE1D87F683640EULL,
		0x0FB66728AA076F9AULL,
		0xB6063899392EB5D5ULL,
		0x273FC9782B06372FULL,
		0x77042204046D5040ULL,
		0xF76856FDD311A834ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86799895EA813395ULL,
		0x7CFFD7C13D3D3E24ULL,
		0xABC07443A4988BE7ULL,
		0xF97E5C0CD4E54875ULL,
		0x3B18F5269986027AULL,
		0xA62F0CAA4F00E425ULL,
		0xD4023C2F8039E71EULL,
		0x07EE1E876A84D51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D279BC9E7D50542ULL,
		0x39E96DBE5E334C67ULL,
		0x4C88453C824151B7ULL,
		0xFCC65E65E650DDE6ULL,
		0x3EBAF0015766F77FULL,
		0x52ECDEABF34E4D24ULL,
		0xC213BB885BBE0C3FULL,
		0xDD5B9CF5B5112805ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0951FCCC02AC2E53ULL,
		0x43166A02DF09F1BDULL,
		0x5F382F0722573A30ULL,
		0xFCB7FDA6EE946A8FULL,
		0xFC5E0525421F0AFAULL,
		0x53422DFE5BB29700ULL,
		0x11EE80A7247BDADFULL,
		0x2A928191B573AD17ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E393F0C9DA32396ULL,
		0xDAE686A12528ED5DULL,
		0xF02964251518E5EAULL,
		0x4FEB802128BA5EC2ULL,
		0x0DC08C94DC4E7844ULL,
		0xC20D39962E1779ECULL,
		0xB51E578D269B5D66ULL,
		0x0349F58BDB5D314CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x416F674F30E0A328ULL,
		0xA05BFDB973499401ULL,
		0x5885D169391B6363ULL,
		0x93AE609221095CA5ULL,
		0x614A34B013ED8793ULL,
		0xD07B3682CD29EFD9ULL,
		0x545FE9F90455F615ULL,
		0x2492A0EEC64C76C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CC9D7BD6CC2806EULL,
		0x3A8A88E7B1DF595CULL,
		0x97A392BBDBFD8287ULL,
		0xBC3D1F8F07B1021DULL,
		0xAC7657E4C860F0B0ULL,
		0xF192031360ED8A12ULL,
		0x60BE6D9422456750ULL,
		0xDEB7549D1510BA86ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64E4DA2E74ED8D76ULL,
		0xF3CEB6A717AE4051ULL,
		0x18A36C8D9D1CC385ULL,
		0x331267BCE73BF30DULL,
		0xEED7034086A1CA88ULL,
		0x218C2A7DB2D6B929ULL,
		0xEDE078EC59CB539CULL,
		0x541CD0B3836F53E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597B4E429F451783ULL,
		0xC353995F0F12980AULL,
		0xDB86825DE536C82FULL,
		0x6C21A2C296E8305DULL,
		0xF3E05D164CC738C1ULL,
		0xBDB660FF40786E9CULL,
		0x0A60FC29D4FBBE5AULL,
		0x78D5DC701A74F14BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B698BEBD5A875F3ULL,
		0x307B1D48089BA847ULL,
		0x3D1CEA2FB7E5FB56ULL,
		0xC6F0C4FA5053C2AFULL,
		0xFAF6A62A39DA91C6ULL,
		0x63D5C97E725E4A8CULL,
		0xE37F7CC284CF9541ULL,
		0xDB46F44368FA6296ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x535C99D293EF1A68ULL,
		0xCCBE7433FB2354B1ULL,
		0xA6949D81030F2F73ULL,
		0x2EFBC6AF6E6A90FAULL,
		0x2DB59F88B9C4720EULL,
		0x986AC535B88ECEFEULL,
		0xB58DB1287C1FEC9FULL,
		0xCC161C2B934D7F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x465BF4E1A35A8A5EULL,
		0xA2D5A020F853143EULL,
		0x03B1CB3D6A9F6B4AULL,
		0x3DA1F507191042EAULL,
		0x08B0CC7D9E3CE6BAULL,
		0xCF352B996D367D26ULL,
		0xA5F4FC6834AC2AFAULL,
		0xB1D24772E3DCD15FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D00A4F0F094900AULL,
		0x29E8D41302D04073ULL,
		0xA2E2D243986FC429ULL,
		0xF159D1A8555A4E10ULL,
		0x2504D30B1B878B53ULL,
		0xC935999C4B5851D8ULL,
		0x0F98B4C04773C1A4ULL,
		0x1A43D4B8AF70ADFBULL
	}};
	sign = 0;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8EDEC23B0F8A222ULL,
		0x89C1983E0825C3CBULL,
		0xF70A5373D1620F31ULL,
		0xC2A77E41DE584E0DULL,
		0x6F6BF705CB189D72ULL,
		0x77AD10ADAB4E8750ULL,
		0xAC0318F4C56984D1ULL,
		0x771F205127D63351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9DC324B2A05E29ULL,
		0xFF29C7BEEAD873F9ULL,
		0x4684C90C1F09D801ULL,
		0x89F2086582A31A00ULL,
		0x35465E696B61B9FBULL,
		0x020477F7CF128E7BULL,
		0xEA6227E813705F67ULL,
		0x539BA743E9CEA5ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A5028FEFE5843F9ULL,
		0x8A97D07F1D4D4FD2ULL,
		0xB0858A67B258372FULL,
		0x38B575DC5BB5340DULL,
		0x3A25989C5FB6E377ULL,
		0x75A898B5DC3BF8D5ULL,
		0xC1A0F10CB1F9256AULL,
		0x2383790D3E078DA4ULL
	}};
	sign = 0;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C206137CEF81545ULL,
		0x7708CFCA91C2E60DULL,
		0x944DF1C5E0F2536CULL,
		0xEBC2C3DC8D467AB1ULL,
		0xF5E4E80490D3D8C2ULL,
		0x5994B2EF8F5A08D9ULL,
		0xA3C5A627821F11D5ULL,
		0x6D74A85CC1E338F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CEC2D1A5338B2B8ULL,
		0xA07F25A454DFCBA8ULL,
		0x74A5069B89622763ULL,
		0x409B7EC80CEA8900ULL,
		0x1B7D20AE538F6293ULL,
		0x8A781CC4E55E6135ULL,
		0x0BFAE0192A592825ULL,
		0x5767E90AD179BE9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF34341D7BBF628DULL,
		0xD689AA263CE31A64ULL,
		0x1FA8EB2A57902C08ULL,
		0xAB274514805BF1B1ULL,
		0xDA67C7563D44762FULL,
		0xCF1C962AA9FBA7A4ULL,
		0x97CAC60E57C5E9AFULL,
		0x160CBF51F0697A5AULL
	}};
	sign = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93F95C2166396839ULL,
		0xFF8D4D3A57134C26ULL,
		0xA03E3324BBC79249ULL,
		0xCA7B7CC754EFD0AFULL,
		0x0838E927336A309BULL,
		0x98D80E48E89B2697ULL,
		0xDE2C8F41842C29FBULL,
		0xA367862AF3ABAFAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0E85EE97C8476C3ULL,
		0x7C51345FEAF41ECBULL,
		0x4D81786F99FEEBC2ULL,
		0x929124A3C19E75ECULL,
		0x057D37352167F413ULL,
		0xDC95FB56388A450AULL,
		0x6DF19BF22AD8C0D3ULL,
		0xE338C2A65F8E31A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD310FD37E9B4F176ULL,
		0x833C18DA6C1F2D5AULL,
		0x52BCBAB521C8A687ULL,
		0x37EA582393515AC3ULL,
		0x02BBB1F212023C88ULL,
		0xBC4212F2B010E18DULL,
		0x703AF34F59536927ULL,
		0xC02EC384941D7E05ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37C4F6B7CA7A66E0ULL,
		0x9D9085D8DC01AEBEULL,
		0xEE55CB293FC474C8ULL,
		0xF297340D6B497AF0ULL,
		0x5D624DEE2D4EB567ULL,
		0x2F51A2B1A6AEB5CDULL,
		0x9266EC959E34BECFULL,
		0xFC0CDB822E983223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DB90B10442E4492ULL,
		0xBA53A3D585B9C897ULL,
		0x3BFC6C284B90E109ULL,
		0xD176AAF8AAA44504ULL,
		0xBC8CD97F21F74250ULL,
		0xA17BBD6FFC154161ULL,
		0x96A8C31564F87C42ULL,
		0x7133BDFCBD81AEABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A0BEBA7864C224EULL,
		0xE33CE2035647E626ULL,
		0xB2595F00F43393BEULL,
		0x21208914C0A535ECULL,
		0xA0D5746F0B577317ULL,
		0x8DD5E541AA99746BULL,
		0xFBBE2980393C428CULL,
		0x8AD91D8571168377ULL
	}};
	sign = 0;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x223EA374B2BFE409ULL,
		0xF179F02390C5967AULL,
		0x4C2373F0836BF0E5ULL,
		0x9770439D5A1B498EULL,
		0xCBA4B19CEA73C37EULL,
		0xB9C1FA7CCB92B399ULL,
		0x0BD76DA3E989EDDEULL,
		0x0D34238E91DA8A1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BD8F277131AC93ULL,
		0xDA1AA17D9523B152ULL,
		0x228127AF24378EC9ULL,
		0x02B6543383BBCE76ULL,
		0x122D7BC76C2FBDE7ULL,
		0x05DD43958FED3FB3ULL,
		0x1347B10D50685C0EULL,
		0xDF8CFBF2D3C4F484ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E81144D418E3776ULL,
		0x175F4EA5FBA1E527ULL,
		0x29A24C415F34621CULL,
		0x94B9EF69D65F7B18ULL,
		0xB97735D57E440597ULL,
		0xB3E4B6E73BA573E6ULL,
		0xF88FBC96992191D0ULL,
		0x2DA7279BBE159596ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE376F46A0BE54F83ULL,
		0x00D5926DF7188715ULL,
		0xC6235D6DC143711CULL,
		0x1D8EB5C78ACF23A0ULL,
		0x12C28A1CD539EFB6ULL,
		0x70062259F43FB003ULL,
		0x4A3FDBC298264053ULL,
		0x20821C497D259A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA1BE0D30C3AEC9ULL,
		0x9242FD3B81969965ULL,
		0xAA0D0014B406A9D4ULL,
		0x9B3BA1E1671C9874ULL,
		0xE8FADA5F589151ECULL,
		0x5443DDB4975AC61AULL,
		0xC15671B634DB881BULL,
		0x47A4CFF7A6143C92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83D5365CDB21A0BAULL,
		0x6E9295327581EDB0ULL,
		0x1C165D590D3CC747ULL,
		0x825313E623B28B2CULL,
		0x29C7AFBD7CA89DC9ULL,
		0x1BC244A55CE4E9E8ULL,
		0x88E96A0C634AB838ULL,
		0xD8DD4C51D7115DA9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAB8446826E8BC42ULL,
		0xA0C1DD97B90BC253ULL,
		0xCF0937A03CF638ABULL,
		0xE29C4276E5296002ULL,
		0x577A44C76997CE39ULL,
		0x62BBB6E7FC416639ULL,
		0x0B138FE01034B676ULL,
		0x95E64EB7B1C5B292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E474F9C548976CBULL,
		0x0A5FB19945A77229ULL,
		0x49606AF24030F754ULL,
		0x233EEBC99CF6ACFCULL,
		0x94BC70CCE2E357EAULL,
		0xB3229768B21E64DBULL,
		0x28CE2EB598EE77A5ULL,
		0x3ECE2C8F37095655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C70F4CBD25F4577ULL,
		0x96622BFE7364502AULL,
		0x85A8CCADFCC54157ULL,
		0xBF5D56AD4832B306ULL,
		0xC2BDD3FA86B4764FULL,
		0xAF991F7F4A23015DULL,
		0xE245612A77463ED0ULL,
		0x571822287ABC5C3CULL
	}};
	sign = 0;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x254C61F6A09720A0ULL,
		0xF0408C4898C7E0D5ULL,
		0xCCDB2BAD48D67C4EULL,
		0x177C7CC1D3F44FC8ULL,
		0x817196139FD08EC7ULL,
		0xFDE5593824CF9075ULL,
		0xB648449717A92613ULL,
		0x0381E8CD0101F647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E7775C7F53CD1EULL,
		0x9DA50ACCD23C211DULL,
		0xD21D56A11112F09AULL,
		0x77E0F0003B6E270CULL,
		0x5D1A1703348B056AULL,
		0x7210A6CDAB60C632ULL,
		0x43E5F5C1C4D7FB2DULL,
		0x1470500F248A7ED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE64EA9A21435382ULL,
		0x529B817BC68BBFB7ULL,
		0xFABDD50C37C38BB4ULL,
		0x9F9B8CC1988628BBULL,
		0x24577F106B45895CULL,
		0x8BD4B26A796ECA43ULL,
		0x72624ED552D12AE6ULL,
		0xEF1198BDDC77776FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EBFB852C6028D19ULL,
		0xE8FA180CFBA97342ULL,
		0xA4137BF16F26ECE4ULL,
		0xB02238D5F79AC5BDULL,
		0xCA0BD8EE79D54313ULL,
		0x6FE72B2243035566ULL,
		0x0D033D202E6843DBULL,
		0x041530CD46692D76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0073DE03CECE1665ULL,
		0xFE86EEFE794C5633ULL,
		0xB2281A01872D10FDULL,
		0x7AD8398A0335D72DULL,
		0xDDB37BADA3B91B37ULL,
		0x3EB256E79B761A90ULL,
		0xBC2F0E56B0F491DCULL,
		0x021FEE45AD7D2B5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E4BDA4EF73476B4ULL,
		0xEA73290E825D1D0FULL,
		0xF1EB61EFE7F9DBE6ULL,
		0x3549FF4BF464EE8FULL,
		0xEC585D40D61C27DCULL,
		0x3134D43AA78D3AD5ULL,
		0x50D42EC97D73B1FFULL,
		0x01F5428798EC021BULL
	}};
	sign = 0;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF8264ECECE6B29ULL,
		0xC87C808BC87D39F1ULL,
		0x46A221A5715CFA54ULL,
		0xA3D53ABDA7FA1CEEULL,
		0xF88A57D4EBB53121ULL,
		0x7D60AEF2638B72D0ULL,
		0x09957411B92F553DULL,
		0x721FB3F8FBDF7923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0EC62025D8EF4FULL,
		0x64DF544F307640E2ULL,
		0x7373AECD088C83F4ULL,
		0xB0370626543CB9A1ULL,
		0x885E8F9642FC9929ULL,
		0xBEBD6A4FA7EAA174ULL,
		0xF67AD045D28EE7CBULL,
		0xE2B37E19EFEFD6FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FE9602EA8F57BDAULL,
		0x639D2C3C9806F90FULL,
		0xD32E72D868D07660ULL,
		0xF39E349753BD634CULL,
		0x702BC83EA8B897F7ULL,
		0xBEA344A2BBA0D15CULL,
		0x131AA3CBE6A06D71ULL,
		0x8F6C35DF0BEFA226ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93B61EA5745D77D7ULL,
		0xC1DFD6A636DB8567ULL,
		0x59DE1A1A68E3C9BDULL,
		0xBA041669ADC22B4AULL,
		0xE81EDDB9E5BF2353ULL,
		0x49A2DCC0295B3A88ULL,
		0x58A4DF48B505A869ULL,
		0xFD740E5C14190411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BDFE34A2E5F9548ULL,
		0x5E61B125B174FBC7ULL,
		0x6412954A566F3FF4ULL,
		0xCFD2C6D708B3F7D2ULL,
		0x9F15A878283BCC9EULL,
		0x0FB7828C55E1097EULL,
		0xD087D611E52AFC83ULL,
		0xC3448AF62DE48FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07D63B5B45FDE28FULL,
		0x637E2580856689A0ULL,
		0xF5CB84D0127489C9ULL,
		0xEA314F92A50E3377ULL,
		0x49093541BD8356B4ULL,
		0x39EB5A33D37A310AULL,
		0x881D0936CFDAABE6ULL,
		0x3A2F8365E6347465ULL
	}};
	sign = 0;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29AF0731A78B7A25ULL,
		0x21A9522F719EB4AAULL,
		0x8C97FEECE050A79DULL,
		0xFAFD0B75D33F0E23ULL,
		0xB06CB515AEE733B7ULL,
		0xD2DAF1D516BA144DULL,
		0xA22AB9BFA06E5E8DULL,
		0xF3A373ADDCD136F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x399CCB3B5BDCCA43ULL,
		0xF53C96D6692A20B4ULL,
		0xD5C7F0535C636401ULL,
		0x2D0A7DC0B89F95A7ULL,
		0xA017438E4F2C768DULL,
		0xD6D027EB5189AA9CULL,
		0xA57D1F942A0E7439ULL,
		0x43FBE829157D7B1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0123BF64BAEAFE2ULL,
		0x2C6CBB59087493F5ULL,
		0xB6D00E9983ED439BULL,
		0xCDF28DB51A9F787BULL,
		0x105571875FBABD2AULL,
		0xFC0AC9E9C53069B1ULL,
		0xFCAD9A2B765FEA53ULL,
		0xAFA78B84C753BBD9ULL
	}};
	sign = 0;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA463073CCF3ACC55ULL,
		0xE5AE5D163F12D45DULL,
		0x47382837454CA902ULL,
		0x7897037BE9DF2DD4ULL,
		0x99ED377960A171ABULL,
		0x4EE2AD63DBB0574FULL,
		0xCBBC5BDDDCDA985FULL,
		0xAB906B613A92DFE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21518649EA88F465ULL,
		0xC206E8825FF32363ULL,
		0xAD40DD04F419FBA4ULL,
		0xDADA95E86E8B5E54ULL,
		0xA03CA6ACC4A6924EULL,
		0xCCF17903EE3BFD5EULL,
		0xE2E828906498B971ULL,
		0x81AF1F0E7C0C5D10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x831180F2E4B1D7F0ULL,
		0x23A77493DF1FB0FAULL,
		0x99F74B325132AD5EULL,
		0x9DBC6D937B53CF7FULL,
		0xF9B090CC9BFADF5CULL,
		0x81F1345FED7459F0ULL,
		0xE8D4334D7841DEEDULL,
		0x29E14C52BE8682D8ULL
	}};
	sign = 0;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C5C66725D6B1670ULL,
		0xA08FBCF0D3426228ULL,
		0x34A3C80D2DDD6A1CULL,
		0xB86193532D7508A3ULL,
		0xB53301D5F1478D3DULL,
		0xB37773E589B213B8ULL,
		0xE4C3DC7B7C8B6A1AULL,
		0x1E06367069501743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC10CF75DF9AE2D9ULL,
		0x8379F50A1A0D1753ULL,
		0x05A5DA8DCA1716EDULL,
		0xA757A25CF1C48A26ULL,
		0x4E635ED65BABB586ULL,
		0x898AE70C8F48EC41ULL,
		0x332B79A1942011A6ULL,
		0x9C014D179A8DEA6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504B96FC7DD03397ULL,
		0x1D15C7E6B9354AD4ULL,
		0x2EFDED7F63C6532FULL,
		0x1109F0F63BB07E7DULL,
		0x66CFA2FF959BD7B7ULL,
		0x29EC8CD8FA692777ULL,
		0xB19862D9E86B5874ULL,
		0x8204E958CEC22CD6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD99218F4E4E37563ULL,
		0x4679A77629CD01C9ULL,
		0xEDF0AA8B3A888A28ULL,
		0x4BC9D0DEEE1E6C06ULL,
		0xB9D66378BA417070ULL,
		0xEDC28E785BF62EEEULL,
		0xF2CBA1F2F5759F43ULL,
		0x0A60D1160849B202ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE084450F0D30C6EULL,
		0x91A941188D73B208ULL,
		0x5E53BAC14F99834AULL,
		0x147865CE6C6AC726ULL,
		0xBA87A86DDACBFB98ULL,
		0x57F9544525AA1C79ULL,
		0x01F05B03E1B8E619ULL,
		0xC707BE970537F2FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB89D4A3F41068F5ULL,
		0xB4D0665D9C594FC0ULL,
		0x8F9CEFC9EAEF06DDULL,
		0x37516B1081B3A4E0ULL,
		0xFF4EBB0ADF7574D8ULL,
		0x95C93A33364C1274ULL,
		0xF0DB46EF13BCB92AULL,
		0x4359127F0311BF05ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03ADA0455D7DB714ULL,
		0x86BD18AFDBBD8FBDULL,
		0xA88BD47EA688313BULL,
		0x99BF88BF035173BAULL,
		0x1687CC91B23F9648ULL,
		0x98FA1BCD022B9E49ULL,
		0xBEFBAE8E88A5F058ULL,
		0x3E3FAE14C141996AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC03839DE4CDA445AULL,
		0x8A8246569F321AB2ULL,
		0x7025BBCF06EDFC3DULL,
		0x7BADCC5907FDD549ULL,
		0x84A4D47B4CA62052ULL,
		0x139190B53AC00615ULL,
		0xB1BCEFF5916105CEULL,
		0x4D713D2600C20BC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4375666710A372BAULL,
		0xFC3AD2593C8B750AULL,
		0x386618AF9F9A34FDULL,
		0x1E11BC65FB539E71ULL,
		0x91E2F816659975F6ULL,
		0x85688B17C76B9833ULL,
		0x0D3EBE98F744EA8AULL,
		0xF0CE70EEC07F8DA5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5001347929B31C38ULL,
		0xA7AFA022A8CA0412ULL,
		0x05B6B173BBE11487ULL,
		0x812E9E9B6B1518B2ULL,
		0x913FA12D8DBBF03DULL,
		0x9CDC15930E9D70E7ULL,
		0x2F84467A87B719D4ULL,
		0xD49C24E7FE07133AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB9D7B8DA662765ULL,
		0x5CCA7D14B957086FULL,
		0x11158E85D1517960ULL,
		0x70FB1ACBD6793082ULL,
		0xA928D2D9A01F71ADULL,
		0x238ECE5CB126E7A8ULL,
		0x14B79FE7133BA4AAULL,
		0x75D8DD96DC35FC01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04475CC04F4CF4D3ULL,
		0x4AE5230DEF72FBA3ULL,
		0xF4A122EDEA8F9B27ULL,
		0x103383CF949BE82FULL,
		0xE816CE53ED9C7E90ULL,
		0x794D47365D76893EULL,
		0x1ACCA693747B752AULL,
		0x5EC3475121D11739ULL
	}};
	sign = 0;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B052B6F83C7E6E9ULL,
		0x955B9044FBD80E1DULL,
		0x6C26206B47C4981DULL,
		0x23A29790E81B17E2ULL,
		0xB29F135DD61EC252ULL,
		0xB6325979938CB845ULL,
		0xE3785EEAEF65CED9ULL,
		0x134A789CAB31C001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47BD8BECC9B3FF46ULL,
		0x19060F36583C7724ULL,
		0x33A4FB9B36A2A54EULL,
		0x14924792CDE12930ULL,
		0x3545D761D1DE3903ULL,
		0xBD3732AA1759E47AULL,
		0xC2150CD71BC0CD87ULL,
		0x8553BD7DBC2B74F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13479F82BA13E7A3ULL,
		0x7C55810EA39B96F9ULL,
		0x388124D01121F2CFULL,
		0x0F104FFE1A39EEB2ULL,
		0x7D593BFC0440894FULL,
		0xF8FB26CF7C32D3CBULL,
		0x21635213D3A50151ULL,
		0x8DF6BB1EEF064B09ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90BE9C9AFAA57597ULL,
		0x24E07ACE8A270CABULL,
		0x2A1C2430A06E8756ULL,
		0x9C1A843E61EBEE5AULL,
		0xD4FEC55BC20EA43DULL,
		0xFD31BBF082C85631ULL,
		0xEEC52439EA42D086ULL,
		0x2377E5C223991DE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C6A4CF83284374ULL,
		0xA4E50E5521612193ULL,
		0x63BD3FA1A7FFBFB1ULL,
		0xB55998F9FD70C344ULL,
		0xE445E7BFDE1C2197ULL,
		0x6130358F48DE7CE2ULL,
		0xED15683F33A39986ULL,
		0x303B03F0A187B160ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEF7F7CB777D3223ULL,
		0x7FFB6C7968C5EB17ULL,
		0xC65EE48EF86EC7A4ULL,
		0xE6C0EB44647B2B15ULL,
		0xF0B8DD9BE3F282A5ULL,
		0x9C01866139E9D94EULL,
		0x01AFBBFAB69F3700ULL,
		0xF33CE1D182116C87ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB396CF33E4B5809DULL,
		0x5CCC091E149E3CFAULL,
		0x8E64269EF03A76CBULL,
		0x83E0403A2F15AB4FULL,
		0x771BD4D9DC4E5D82ULL,
		0xCFD31DDFAD957A58ULL,
		0xEDCB934CEA322444ULL,
		0x9481C8477BD8D42EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE957AE30836973ADULL,
		0xCC3C4D753D1B8264ULL,
		0xCEA97F386BFD7AB3ULL,
		0x6E8AE7DA68FF5D48ULL,
		0xD5EE668CCA2A2771ULL,
		0xB1CDC058B5D88C42ULL,
		0xCBF415367E17A095ULL,
		0xF7F0A4AB8D819214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA3F2103614C0CF0ULL,
		0x908FBBA8D782BA95ULL,
		0xBFBAA766843CFC17ULL,
		0x1555585FC6164E06ULL,
		0xA12D6E4D12243611ULL,
		0x1E055D86F7BCEE15ULL,
		0x21D77E166C1A83AFULL,
		0x9C91239BEE57421AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DB4E5500CFEEB94ULL,
		0xC1225B0A15930E72ULL,
		0xCAA1D104B49AF01CULL,
		0xE21DE0BDC07F40C9ULL,
		0x8EACE60336037870ULL,
		0x4E89C3D30E3ED8FFULL,
		0x129A2F5D3F8471C0ULL,
		0xE604964D2433C6A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681C4B6EE69CC633ULL,
		0x4875A68AF0BA64DBULL,
		0x1E9B97CFCD7314C6ULL,
		0xEB2608135E2BF7C8ULL,
		0xF2252BD0157AC944ULL,
		0x7968711FAD520751ULL,
		0xD4948BBF2B41603CULL,
		0x3FD975E38408DDACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x359899E126622561ULL,
		0x78ACB47F24D8A997ULL,
		0xAC063934E727DB56ULL,
		0xF6F7D8AA62534901ULL,
		0x9C87BA332088AF2BULL,
		0xD52152B360ECD1ADULL,
		0x3E05A39E14431183ULL,
		0xA62B2069A02AE8F9ULL
	}};
	sign = 0;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x273D2F8EDA4570AAULL,
		0x95860767EFD09BFEULL,
		0xB95E6C70D1BEFBA6ULL,
		0xC6D31206A2DF10A8ULL,
		0x126367A8B35A1259ULL,
		0x9F9631D518B3CFADULL,
		0xC6CF2989D665C56EULL,
		0xEE1C6C8212A75B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2A76EBA9481EBDULL,
		0xDC392041B3925246ULL,
		0x1681133E4DCD0DF4ULL,
		0x392165CDC68D12F4ULL,
		0xB316A7A8626DA81AULL,
		0xC2E3C5EACA535BFBULL,
		0xB0D6A18444CBFB1BULL,
		0xBD98BD60868CABA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD12B8A330FD51EDULL,
		0xB94CE7263C3E49B7ULL,
		0xA2DD593283F1EDB1ULL,
		0x8DB1AC38DC51FDB4ULL,
		0x5F4CC00050EC6A3FULL,
		0xDCB26BEA4E6073B1ULL,
		0x15F888059199CA52ULL,
		0x3083AF218C1AAF67ULL
	}};
	sign = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B973FA7B0FA54E8ULL,
		0xE615B25077E2A282ULL,
		0xDD8AEC35DD2643A0ULL,
		0xB5C1DB4C713351C6ULL,
		0x1119CFF5C2EA981AULL,
		0x54E726C56B936ECDULL,
		0xEF24A6AFE52611BEULL,
		0x1EDA373181CBADFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59161E20C7629CCBULL,
		0x02A1D35117750D51ULL,
		0xDC5167B2AD17F7CBULL,
		0xC8ED9DA7E073F0BEULL,
		0xE0D66E79B7E45FADULL,
		0x5749EFC1A5A98363ULL,
		0xAA30AAE24C24835DULL,
		0xD1C27B6AE68FDFF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02812186E997B81DULL,
		0xE373DEFF606D9531ULL,
		0x01398483300E4BD5ULL,
		0xECD43DA490BF6108ULL,
		0x3043617C0B06386CULL,
		0xFD9D3703C5E9EB69ULL,
		0x44F3FBCD99018E60ULL,
		0x4D17BBC69B3BCE0AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E9F51A743B08D80ULL,
		0x69622CBA177D480CULL,
		0xAC34AEF2E215E91EULL,
		0x520E77E34B97DD3EULL,
		0xBB9B5FEA49CDCC43ULL,
		0x62457135E5272141ULL,
		0x291DE9225536EEB0ULL,
		0x1E23F262E64E62A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA015ED5BF7C2AC1FULL,
		0x1A3ED2AC189819D1ULL,
		0x9E573B62129B98C5ULL,
		0x2F3517C1177A6C98ULL,
		0xA092C58FA36D4BA8ULL,
		0x0B4108EDD1BD0CD5ULL,
		0x93E754278E1C393FULL,
		0xBAEE4370747CDB01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE89644B4BEDE161ULL,
		0x4F235A0DFEE52E3AULL,
		0x0DDD7390CF7A5059ULL,
		0x22D96022341D70A6ULL,
		0x1B089A5AA660809BULL,
		0x57046848136A146CULL,
		0x953694FAC71AB571ULL,
		0x6335AEF271D187A4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97402051CDEEDF1CULL,
		0xD2D29507E119EF9BULL,
		0x728BFF05A616E26CULL,
		0x5BDDA0242E7A640AULL,
		0xF6EF8E7B6EB41B20ULL,
		0x3F3DD9103C2C0982ULL,
		0xB343ED0C9FA9B7FEULL,
		0x87C12ECDCDDA05CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF96C4876C6143C2AULL,
		0x7A1CF742F19B484DULL,
		0x28878F439988C61AULL,
		0x50386D94B2C780DDULL,
		0xAEC26337C6C97DDFULL,
		0xCB19181FD388A831ULL,
		0xFA69B585ABF96528ULL,
		0x78BACD2C1E71FD46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DD3D7DB07DAA2F2ULL,
		0x58B59DC4EF7EA74DULL,
		0x4A046FC20C8E1C52ULL,
		0x0BA5328F7BB2E32DULL,
		0x482D2B43A7EA9D41ULL,
		0x7424C0F068A36151ULL,
		0xB8DA3786F3B052D5ULL,
		0x0F0661A1AF680884ULL
	}};
	sign = 0;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8DDB80C24596DBFULL,
		0x7F2B03DEFCA88716ULL,
		0x0AE520826748E4A5ULL,
		0x9B918F04F613316CULL,
		0xDDC7C1B79AC94075ULL,
		0x6DD2241C5F2FACE8ULL,
		0x8A08EE03F5326050ULL,
		0x9822EAE2B50B1638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22BACFE77CFA0655ULL,
		0x74AE00DEB5D1A631ULL,
		0xD570357A9A02348FULL,
		0x4B817B80AD0AF04FULL,
		0x59C5FBF46B847163ULL,
		0x6EEDBD1F42B64266ULL,
		0x9C7E9E7B3CF08B49ULL,
		0x38D772EFA0B794C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8622E824A75F676AULL,
		0x0A7D030046D6E0E5ULL,
		0x3574EB07CD46B016ULL,
		0x501013844908411CULL,
		0x8401C5C32F44CF12ULL,
		0xFEE466FD1C796A82ULL,
		0xED8A4F88B841D506ULL,
		0x5F4B77F314538177ULL
	}};
	sign = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36C47510732A15BFULL,
		0x739982FA336A4E6AULL,
		0xF26710E435DB2F3CULL,
		0x2295A149B2A20286ULL,
		0x111A40AB2F427CE6ULL,
		0xE6D41E6BE3E36DEAULL,
		0x2BF16683AC8DD1FFULL,
		0x10454A9294A682D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC323BA663568DF9ULL,
		0x18538BD7031A74C4ULL,
		0x807128AD09D41E9DULL,
		0x27FC84A3ECDD3C42ULL,
		0x427BCACA9960802DULL,
		0x32DAD4F1D5784A46ULL,
		0x11A6AAD75F5EC4ABULL,
		0x5E767168EA2E0BF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A92396A0FD387C6ULL,
		0x5B45F723304FD9A5ULL,
		0x71F5E8372C07109FULL,
		0xFA991CA5C5C4C644ULL,
		0xCE9E75E095E1FCB8ULL,
		0xB3F9497A0E6B23A3ULL,
		0x1A4ABBAC4D2F0D54ULL,
		0xB1CED929AA7876DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D741129263C8276ULL,
		0x7F256DC43D969CE9ULL,
		0xACC3610DADEB51D4ULL,
		0xDEC2ABE7704BA8E5ULL,
		0x791AF52C1422028FULL,
		0x93D6B0095D27A217ULL,
		0xC70078843DF5A100ULL,
		0x7A9CEFC3E4F5A705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79CD1F0D3CDD793BULL,
		0x57392DC5F2225B94ULL,
		0x9999367E30A8E979ULL,
		0xDDCAE7DB89C189C9ULL,
		0xA3D4D6AD51B2BD7AULL,
		0x33D301C766A67297ULL,
		0xB6CA73884FB956CEULL,
		0x6DDB16F1F3C56E19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3A6F21BE95F093BULL,
		0x27EC3FFE4B744154ULL,
		0x132A2A8F7D42685BULL,
		0x00F7C40BE68A1F1CULL,
		0xD5461E7EC26F4515ULL,
		0x6003AE41F6812F7FULL,
		0x103604FBEE3C4A32ULL,
		0x0CC1D8D1F13038ECULL
	}};
	sign = 0;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0B4ECB3AED58AA9ULL,
		0xF096AF0506E8B389ULL,
		0x79D5F8C627413414ULL,
		0x334E0EB6AD78828FULL,
		0x4268D2AA20A22966ULL,
		0x4F2A2BF5E7404607ULL,
		0xDD1C5F84D676660AULL,
		0x587B3B6D585BC7C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61756EC2EB8F14A1ULL,
		0x5E86708F45373A02ULL,
		0xE07CCD7C1C758F73ULL,
		0x052CEB2AAD4C7071ULL,
		0x12094B054D2B4CAFULL,
		0xB0BAA9DD2EC15060ULL,
		0x8E199C03E0C11567ULL,
		0xD90B83379C137829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F3F7DF0C3467608ULL,
		0x92103E75C1B17987ULL,
		0x99592B4A0ACBA4A1ULL,
		0x2E21238C002C121DULL,
		0x305F87A4D376DCB7ULL,
		0x9E6F8218B87EF5A7ULL,
		0x4F02C380F5B550A2ULL,
		0x7F6FB835BC484F9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0340B16D5F14338CULL,
		0x09F16F81E06150A2ULL,
		0x44AFD1867E9ACBACULL,
		0x2690894F75DC2B77ULL,
		0x1E82FAA4B727E01EULL,
		0xD115AD513928F7CFULL,
		0xCC100527DEF2DE22ULL,
		0x37BD7531610B85A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD320696E1BE243F3ULL,
		0x3B1DDE1F953627ABULL,
		0x2AC7DBE912F5E6E7ULL,
		0x60D091EDCA99C52BULL,
		0xB7234885B804B5B1ULL,
		0x0B46FA11EEB6DB65ULL,
		0xB167B652B6AE6717ULL,
		0x10CC4EC852EB9669ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302047FF4331EF99ULL,
		0xCED391624B2B28F6ULL,
		0x19E7F59D6BA4E4C4ULL,
		0xC5BFF761AB42664CULL,
		0x675FB21EFF232A6CULL,
		0xC5CEB33F4A721C69ULL,
		0x1AA84ED52844770BULL,
		0x26F126690E1FEF3BULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E71EA80A3D5D04CULL,
		0x07C3E5228D686717ULL,
		0x0E761C78DAE2C256ULL,
		0x081BC19CA2630C2BULL,
		0x72245CD1E82EE023ULL,
		0x10C8E8A684F22FE5ULL,
		0x7C8971C30A6C8E8FULL,
		0xAE02285EE503F17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x739DD7BDAE93CFA5ULL,
		0x65E8871193FC4D77ULL,
		0xA2B4932C3753A367ULL,
		0xD62B246E47382F88ULL,
		0x26CF30C437021C30ULL,
		0x28B77795EEB03DD1ULL,
		0xD3ADFC30EFAD26D3ULL,
		0xC962BEF34B13CE1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AD412C2F54200A7ULL,
		0xA1DB5E10F96C199FULL,
		0x6BC1894CA38F1EEEULL,
		0x31F09D2E5B2ADCA2ULL,
		0x4B552C0DB12CC3F2ULL,
		0xE81171109641F214ULL,
		0xA8DB75921ABF67BBULL,
		0xE49F696B99F02362ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5416F3E4B71C6AB7ULL,
		0x4A53233F43E1B9F6ULL,
		0x05CC6B6E60CC62EAULL,
		0x76D1B57E362062B3ULL,
		0x52E199D375EDDE90ULL,
		0xB2553FC56DE89146ULL,
		0x0C475F30DAAEDB87ULL,
		0xEC7D454F89171D31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C52D96C7AF14172ULL,
		0x0C13B38A9904F34BULL,
		0x1C036573D049D7CAULL,
		0x7E35DEBD1107E3E2ULL,
		0x756FC926EBA6A2C3ULL,
		0x2681BF70F7870FD6ULL,
		0x8BF772818FDDC620ULL,
		0xAB79C6E2FAE875E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07C41A783C2B2945ULL,
		0x3E3F6FB4AADCC6ABULL,
		0xE9C905FA90828B20ULL,
		0xF89BD6C125187ED0ULL,
		0xDD71D0AC8A473BCCULL,
		0x8BD380547661816FULL,
		0x804FECAF4AD11567ULL,
		0x41037E6C8E2EA74FULL
	}};
	sign = 0;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86F291A00269BC82ULL,
		0x208A72134B5B8D15ULL,
		0x5F97A5EB04DF286FULL,
		0x9C7527505934DB3FULL,
		0xF71D330E702EA4E8ULL,
		0xD267E2FC8739D5B8ULL,
		0xCEFA581DC5641243ULL,
		0xD4D87576CF96EA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47063DC706BA5794ULL,
		0x4A54C38BD7A927A9ULL,
		0x0B1675FF34D594E7ULL,
		0x2C974DD564737FC5ULL,
		0x67F97A502FD84C95ULL,
		0x6C55860BB1A4A695ULL,
		0xFFD6DB3C0E446C71ULL,
		0x9C477172524AF68EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FEC53D8FBAF64EEULL,
		0xD635AE8773B2656CULL,
		0x54812FEBD0099387ULL,
		0x6FDDD97AF4C15B7AULL,
		0x8F23B8BE40565853ULL,
		0x66125CF0D5952F23ULL,
		0xCF237CE1B71FA5D2ULL,
		0x389104047D4BF3F0ULL
	}};
	sign = 0;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE812AF48A150D148ULL,
		0x94A1A6698766C2E9ULL,
		0x1AF52AE69C1DCB54ULL,
		0xBDA7859505B81AF6ULL,
		0xC4503C33FD85E43BULL,
		0xC6BCA007DFA9A531ULL,
		0x65E69B8C05D852A7ULL,
		0x2EA5B6D17793AAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA99C82588E4914ULL,
		0x93D506553069A1EDULL,
		0xD5A52AEBCE10E35CULL,
		0xB3497203C219801AULL,
		0x276FE32E8786BBDFULL,
		0xC720967BD02A769BULL,
		0x35E77B20C2BC745BULL,
		0x4C64998140A3C028ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA6912C648C28834ULL,
		0x00CCA01456FD20FCULL,
		0x454FFFFACE0CE7F8ULL,
		0x0A5E1391439E9ADBULL,
		0x9CE0590575FF285CULL,
		0xFF9C098C0F7F2E96ULL,
		0x2FFF206B431BDE4BULL,
		0xE2411D5036EFEAC9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EAD6235C9C4D5A6ULL,
		0xE87685FBE0FEB0F3ULL,
		0xCB1CC2558F755F0AULL,
		0x6074CCA665356F28ULL,
		0xFAD53142578678F3ULL,
		0x39995B1AFCDD9A34ULL,
		0x0AAFF7642D3A6512ULL,
		0x41335ED42425DA97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D2E62C60107DDEULL,
		0x4720BA812B57F278ULL,
		0x2C4C597101A03E71ULL,
		0x47EBED430F70D8BFULL,
		0xAB898BB35CF37AF5ULL,
		0xF05B9531B051BE84ULL,
		0x7A68EDB9749ABAAFULL,
		0x3CDAEDE910089D3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8DA7C0969B457C8ULL,
		0xA155CB7AB5A6BE7AULL,
		0x9ED068E48DD52099ULL,
		0x1888DF6355C49669ULL,
		0x4F4BA58EFA92FDFEULL,
		0x493DC5E94C8BDBB0ULL,
		0x904709AAB89FAA62ULL,
		0x045870EB141D3D5AULL
	}};
	sign = 0;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x600CDC9DEFE0152AULL,
		0xEF77D0CB96E8F28FULL,
		0x905351FC0360B76CULL,
		0x1D518AA4B693AE14ULL,
		0xF73B990DCEF3FB26ULL,
		0xC26FE49EC82D1B4FULL,
		0x8A8605CC806D322FULL,
		0x4A2ADF37FDDC8CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B4CAAC0E971253ULL,
		0x5ABF4D5B8AB14E32ULL,
		0x877763202B4321C0ULL,
		0x1AD3C6FA4C8F1F65ULL,
		0x5B1AA444C10B5F10ULL,
		0x4566FEE08073FA2FULL,
		0x72BB08AADC22CFCBULL,
		0x234750781D532F0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E5811F1E14902D7ULL,
		0x94B883700C37A45DULL,
		0x08DBEEDBD81D95ACULL,
		0x027DC3AA6A048EAFULL,
		0x9C20F4C90DE89C16ULL,
		0x7D08E5BE47B92120ULL,
		0x17CAFD21A44A6264ULL,
		0x26E38EBFE0895DE7ULL
	}};
	sign = 0;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E30D4113B00C42ULL,
		0x56A3DA7BBAB5A74BULL,
		0x84CF5B4E57D05129ULL,
		0x8D7F330045B637E3ULL,
		0x3D4AD1ABE1FA5513ULL,
		0x7A131A613182E214ULL,
		0x5C9E9F6DCB033221ULL,
		0xA332F317F3F1FD98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6110505E5CE9D64EULL,
		0xE98497D5B96B1DC4ULL,
		0x5480F834BF6EE205ULL,
		0x5E6FDB6B7EF50990ULL,
		0x5104841FC67603B8ULL,
		0x5A19E2FF3D74A1BEULL,
		0x41AAC1CDB21DA299ULL,
		0x5E1A26664238C7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01D2BCE2B6C635F4ULL,
		0x6D1F42A6014A8987ULL,
		0x304E631998616F23ULL,
		0x2F0F5794C6C12E53ULL,
		0xEC464D8C1B84515BULL,
		0x1FF93761F40E4055ULL,
		0x1AF3DDA018E58F88ULL,
		0x4518CCB1B1B935AFULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF82231C756C3627AULL,
		0x6B578F9F34903EA4ULL,
		0xF19AE50F20DFC612ULL,
		0x0882AD74F3F001BCULL,
		0x94C6985456EAEB47ULL,
		0x763E0A9554F4D4DDULL,
		0x7701C260A9FF35C7ULL,
		0xBCFE9E7DB844F198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9445A7F792C6CE03ULL,
		0xF3882B4C0A1F4522ULL,
		0x13264B18066B0512ULL,
		0xBC163320C041B3E7ULL,
		0xE4BBE9A031E50383ULL,
		0x89DC430C43313B3FULL,
		0x25F33088880021FAULL,
		0x3FC39BDEAC7410A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63DC89CFC3FC9477ULL,
		0x77CF64532A70F982ULL,
		0xDE7499F71A74C0FFULL,
		0x4C6C7A5433AE4DD5ULL,
		0xB00AAEB42505E7C3ULL,
		0xEC61C78911C3999DULL,
		0x510E91D821FF13CCULL,
		0x7D3B029F0BD0E0F5ULL
	}};
	sign = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BC91608300E784EULL,
		0x0295483B538E87B7ULL,
		0xF567EE5B87810526ULL,
		0x4CC666E0C12147BDULL,
		0x86F86CAF9C3A5E8DULL,
		0x45D541A949B429CFULL,
		0x9F99011A1A3F7ED9ULL,
		0x96EA784E54BFFC00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A68A1094CDE9E34ULL,
		0xB7C893572B9F87A8ULL,
		0xA841DA96FA3197B7ULL,
		0x62D8CA669D8B970DULL,
		0x0F5FF4E39361C7E4ULL,
		0x040DA64D7D99B4CAULL,
		0xE8F28C2E5D651ABBULL,
		0xA22C19275FA22E4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x316074FEE32FDA1AULL,
		0x4ACCB4E427EF000FULL,
		0x4D2613C48D4F6D6EULL,
		0xE9ED9C7A2395B0B0ULL,
		0x779877CC08D896A8ULL,
		0x41C79B5BCC1A7505ULL,
		0xB6A674EBBCDA641EULL,
		0xF4BE5F26F51DCDB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F101FC722EDABB5ULL,
		0x8F11EBB3A2A63261ULL,
		0x90E16580A4C81BE7ULL,
		0xD826496C79EED33FULL,
		0x43621579B20A3FFEULL,
		0x191CF065F76E360AULL,
		0x23DC793B4C188BA3ULL,
		0x1EC1583F2A7730DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C07DBD9EE9AC912ULL,
		0xD69694CBFF0CCFEBULL,
		0xA47BB6B6F3C85D6BULL,
		0x37EF879850BBF0E4ULL,
		0xE545BB79D2DF9C10ULL,
		0x68184A352D684C9BULL,
		0xC17735F4A6CDD669ULL,
		0xD70540EBAE4C906BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE30843ED3452E2A3ULL,
		0xB87B56E7A3996275ULL,
		0xEC65AEC9B0FFBE7BULL,
		0xA036C1D42932E25AULL,
		0x5E1C59FFDF2AA3EEULL,
		0xB104A630CA05E96EULL,
		0x62654346A54AB539ULL,
		0x47BC17537C2AA06EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D3F21204F4772A5ULL,
		0xE81D34564BAF4E4AULL,
		0xFA8B3D331270B4EDULL,
		0x9656AB4B4F596833ULL,
		0x3015F596B16C2AA5ULL,
		0x0491834158872F76ULL,
		0xD3E6F1F577446B3BULL,
		0x68B6C6216CC8C799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x638C2A3A8BF7D621ULL,
		0xE15C858D29A7A792ULL,
		0x4046D16000CF9308ULL,
		0xDB5EF888DC40E8E9ULL,
		0x954DE4060E9F34F4ULL,
		0x0176AA913B065708ULL,
		0x835C509F11CE6E1BULL,
		0x6FE689F3FFB807D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39B2F6E5C34F9C84ULL,
		0x06C0AEC92207A6B8ULL,
		0xBA446BD311A121E5ULL,
		0xBAF7B2C273187F4AULL,
		0x9AC81190A2CCF5B0ULL,
		0x031AD8B01D80D86DULL,
		0x508AA1566575FD20ULL,
		0xF8D03C2D6D10BFC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9088E3F33AEDA7DBULL,
		0xAF414284F5BE98D9ULL,
		0x187ABFF04E071199ULL,
		0x8DD452EBE34AA6FFULL,
		0x1C4869493D24C32DULL,
		0x07DE64F85B66B902ULL,
		0x836E1510823025E3ULL,
		0xDC3785F3A7343432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE93AEAEDF939DAE9ULL,
		0x4E335462B2A127D3ULL,
		0x332C3223C0F0EB0FULL,
		0x97D0B2F4AC6AA304ULL,
		0x59A68A17B9090070ULL,
		0x8418903D4F2D0B8CULL,
		0xECF0DBA2CAE75192ULL,
		0x164A451BCD4056BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA74DF90541B3CCF2ULL,
		0x610DEE22431D7105ULL,
		0xE54E8DCC8D16268AULL,
		0xF6039FF736E003FAULL,
		0xC2A1DF31841BC2BCULL,
		0x83C5D4BB0C39AD75ULL,
		0x967D396DB748D450ULL,
		0xC5ED40D7D9F3DD74ULL
	}};
	sign = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE416D0341870C84DULL,
		0x3EA0EEBD969672C6ULL,
		0xCF84FD4CDA4573DCULL,
		0xE718771118818AB1ULL,
		0xEE7D4D6BD43EAF88ULL,
		0x21C49DC1070480B1ULL,
		0xD4510E71A94AD726ULL,
		0xF301EC0BC858851EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E14622E5C518B79ULL,
		0x9BC19B0B7E6BF1D6ULL,
		0xBA3B24743BEBDF04ULL,
		0xCF9BFBEE462023CCULL,
		0x070154CB2323B3B3ULL,
		0x32989603AB4DE206ULL,
		0xE94475F1442AFE33ULL,
		0xB49511985128ACCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56026E05BC1F3CD4ULL,
		0xA2DF53B2182A80F0ULL,
		0x1549D8D89E5994D7ULL,
		0x177C7B22D26166E5ULL,
		0xE77BF8A0B11AFBD5ULL,
		0xEF2C07BD5BB69EABULL,
		0xEB0C9880651FD8F2ULL,
		0x3E6CDA73772FD84EULL
	}};
	sign = 0;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96E78A911CCCA418ULL,
		0x9107DA1E4327DFF8ULL,
		0x16DBE973232F8E89ULL,
		0xE522B0EC3CAD9AB7ULL,
		0x341E9B5444CB8013ULL,
		0x73C250C1665774DDULL,
		0xB15671E7E05C6B01ULL,
		0x9788BFB9D49E57E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC6054D289893DE1ULL,
		0x9AEF0F321C081589ULL,
		0x6D66AF44F084CC28ULL,
		0xD815FADD39B1B938ULL,
		0xF6CB289B4A67566DULL,
		0x8B87DDCECFAC01B4ULL,
		0x28A3679CB728287AULL,
		0x9CEB337A1379CF30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA8735BE93436637ULL,
		0xF618CAEC271FCA6EULL,
		0xA9753A2E32AAC260ULL,
		0x0D0CB60F02FBE17EULL,
		0x3D5372B8FA6429A6ULL,
		0xE83A72F296AB7328ULL,
		0x88B30A4B29344286ULL,
		0xFA9D8C3FC12488B7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBAAA6117315DF34ULL,
		0x093319BABB90EFEFULL,
		0x7A58E2208381B51EULL,
		0x352789536925D74EULL,
		0x7BEDAC5B3708F128ULL,
		0x40EEE9E403B7FBDCULL,
		0x7515C001631AD0A5ULL,
		0x9C7457F8FA9300BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0A077F6771B27BBULL,
		0xFA9A02263E7BE09FULL,
		0xEBACC33A4D6B2C61ULL,
		0x63E96B98495AA908ULL,
		0x812C16EDEE0CBEB1ULL,
		0x0174B160BA7D750EULL,
		0x03ED3F7C183265CBULL,
		0xF2309E4ACF070C4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B0A2E1AFBFAB779ULL,
		0x0E9917947D150F50ULL,
		0x8EAC1EE6361688BCULL,
		0xD13E1DBB1FCB2E45ULL,
		0xFAC1956D48FC3276ULL,
		0x3F7A3883493A86CDULL,
		0x712880854AE86ADAULL,
		0xAA43B9AE2B8BF470ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB53077593591F23DULL,
		0x404999D103AC1236ULL,
		0x35A892F87DAFDB4BULL,
		0x1A29770D6AD06BD3ULL,
		0xAE8265F0A5964DE5ULL,
		0xDE773164B2A1A32BULL,
		0x36FB2463FE6C7738ULL,
		0x883523A1F6C732C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA6F39E5CC905DEULL,
		0x7B6CC734D79E7754ULL,
		0xC29276359853FBB0ULL,
		0x3DDA051FD1992735ULL,
		0xF631B6A32975C1EDULL,
		0x02202BDAF7C7894EULL,
		0x79C84E692477A09FULL,
		0xA2F0F381DC5D37D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x558983BAD8C8EC5FULL,
		0xC4DCD29C2C0D9AE2ULL,
		0x73161CC2E55BDF9AULL,
		0xDC4F71ED9937449DULL,
		0xB850AF4D7C208BF7ULL,
		0xDC570589BADA19DCULL,
		0xBD32D5FAD9F4D699ULL,
		0xE54430201A69FAF0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6F7329FD18477EFULL,
		0x51AA5459C7C7967CULL,
		0xEBDDDEC53E06979AULL,
		0xBC4573BE25C8D2ABULL,
		0xFD4489997A6BA708ULL,
		0xCF87C16AF237CB42ULL,
		0x9C7B9C78D66E4AE5ULL,
		0x5E9743F59D0D2A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCB2E8E4C9615BAEULL,
		0x5813A52E85CD33F3ULL,
		0xBD73CD86F47EACD0ULL,
		0x093821D45E971869ULL,
		0xDACD5D56929B4372ULL,
		0x678D8E733091F139ULL,
		0x8834A6D005492391ULL,
		0x4E2D831E226F791AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A4449BB08231C41ULL,
		0xF996AF2B41FA6289ULL,
		0x2E6A113E4987EAC9ULL,
		0xB30D51E9C731BA42ULL,
		0x22772C42E7D06396ULL,
		0x67FA32F7C1A5DA09ULL,
		0x1446F5A8D1252754ULL,
		0x1069C0D77A9DB0F8ULL
	}};
	sign = 0;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8C8F744BD43228FULL,
		0x19E8B42E34C3C4DFULL,
		0x6749DCEFD6FFBFDCULL,
		0xAFD15FC7ABF791F1ULL,
		0x7F42C963AA5F422AULL,
		0xA6A8C5C4C4FE80F1ULL,
		0xF94D9670ABAEF0E5ULL,
		0xE09C0E0AD19F7101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C89480F3666953ULL,
		0xC5FBFF09B55DF0CBULL,
		0x5A1DBBD43CAD1722ULL,
		0x3157DE49656A9CF2ULL,
		0x1A97B3771DD97E56ULL,
		0x2ECE85A2741CE287ULL,
		0x132834E2472E2176ULL,
		0x1C5C3F97A402BCFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF10062C3C9DCB93CULL,
		0x53ECB5247F65D413ULL,
		0x0D2C211B9A52A8B9ULL,
		0x7E79817E468CF4FFULL,
		0x64AB15EC8C85C3D4ULL,
		0x77DA402250E19E6AULL,
		0xE625618E6480CF6FULL,
		0xC43FCE732D9CB405ULL
	}};
	sign = 0;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8F0F26351040FCFULL,
		0xAFBC5F383E7CE782ULL,
		0x854AE1F503D6C555ULL,
		0x7DBE3E8CFDF51B59ULL,
		0xB793BF684C9A9982ULL,
		0x8484DB67AB4D4574ULL,
		0xA5E4407458D033A4ULL,
		0x1335F68F71710BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35FD5D14175CF0CBULL,
		0x17848BC3A8F8737EULL,
		0xABD8EFC4CFFC0A4AULL,
		0x4B2BAF9BC23B2FD5ULL,
		0xE7725909BD49FB71ULL,
		0xD620DFBCA1EAE3B9ULL,
		0x807B8F2A496968BCULL,
		0x22DE29D9D8A10EFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82F3954F39A71F04ULL,
		0x9837D37495847404ULL,
		0xD971F23033DABB0BULL,
		0x32928EF13BB9EB83ULL,
		0xD021665E8F509E11ULL,
		0xAE63FBAB096261BAULL,
		0x2568B14A0F66CAE7ULL,
		0xF057CCB598CFFCE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66BD91F8640BBECFULL,
		0x2DE1F5CD7B5F577BULL,
		0x5AC3FB5567569901ULL,
		0xF051588124CEF88AULL,
		0x95CD3CCF5F03CFC2ULL,
		0x48CE80EA0EA6D457ULL,
		0xD822B798DFA37990ULL,
		0x27BE048776D4B1B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1E59417FD5EB5BCULL,
		0x24E9D6A0622C0EA9ULL,
		0x1D21A2D4E58C2E7AULL,
		0x26D96815C09FDDD8ULL,
		0x4AF733D55D35299BULL,
		0xF632C5FD60675612ULL,
		0x37A4F9EA46E03ECAULL,
		0x7154F46524F332BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4D7FDE066AD0913ULL,
		0x08F81F2D193348D1ULL,
		0x3DA2588081CA6A87ULL,
		0xC977F06B642F1AB2ULL,
		0x4AD608FA01CEA627ULL,
		0x529BBAECAE3F7E45ULL,
		0xA07DBDAE98C33AC5ULL,
		0xB669102251E17EF9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59632F50976B0E1EULL,
		0xCAAB4A18E684A7A0ULL,
		0x1B6F1200C3205729ULL,
		0xF88D19D0FE3CE56BULL,
		0x387770B60BFCDA08ULL,
		0xEC84BDD5DADF6DCFULL,
		0xB1966FCB6A09A935ULL,
		0x84C60D9F55B917CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x890DD584D8CD00B1ULL,
		0xAED91D1965D68672ULL,
		0x7B565703991E9C8AULL,
		0x08B59E58DF4A2FF7ULL,
		0xD962C91284F3FE1DULL,
		0xE41C972C86ACE592ULL,
		0xD33F11630EF5458DULL,
		0xCEA43D377BAF4AECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD05559CBBE9E0D6DULL,
		0x1BD22CFF80AE212DULL,
		0xA018BAFD2A01BA9FULL,
		0xEFD77B781EF2B573ULL,
		0x5F14A7A38708DBEBULL,
		0x086826A95432883CULL,
		0xDE575E685B1463A8ULL,
		0xB621D067DA09CCDDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD8BCA89C6342505ULL,
		0x6A3D5C923BA43627ULL,
		0x98C35C2ABFF0E7B7ULL,
		0x0D27076BC71586ABULL,
		0x63ACB47EC84219D8ULL,
		0x3F2C814388EC9C00ULL,
		0x2C1A74134A1CC050ULL,
		0x3C081D6D9B6D241AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72F4BD8751564156ULL,
		0x84FADBEF11BF65D2ULL,
		0x10000471518A973BULL,
		0x5D21B98B6CB196CAULL,
		0x9EBB7B4B319FB7DBULL,
		0x4865176F0373A1CCULL,
		0xFC706CC0DBAB7D5DULL,
		0xCAB376F69F9F73B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A970D0274DDE3AFULL,
		0xE54280A329E4D055ULL,
		0x88C357B96E66507BULL,
		0xB0054DE05A63EFE1ULL,
		0xC4F1393396A261FCULL,
		0xF6C769D48578FA33ULL,
		0x2FAA07526E7142F2ULL,
		0x7154A676FBCDB066ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x961C76A1D23AC9C3ULL,
		0xF93AAC370DF059FCULL,
		0xDCBE57974E673E91ULL,
		0x020B9FD3A531EABEULL,
		0xEF1532DC7B3D590AULL,
		0x6E01E5B95D64EDD1ULL,
		0xACAE05EFBF66D6E4ULL,
		0x42F36191D99CA36FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6257FF3CE953082FULL,
		0xC6A1E1AD10CA6137ULL,
		0xA37C03A0FB1DAD14ULL,
		0x2170B99C30203D99ULL,
		0x2509C7BC297EF6D4ULL,
		0xAB32499D520BEB76ULL,
		0x5E2CC8B737D00FA8ULL,
		0xFCF7D4E4CCCB4F95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C47764E8E7C194ULL,
		0x3298CA89FD25F8C5ULL,
		0x394253F65349917DULL,
		0xE09AE6377511AD25ULL,
		0xCA0B6B2051BE6235ULL,
		0xC2CF9C1C0B59025BULL,
		0x4E813D388796C73BULL,
		0x45FB8CAD0CD153DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE72EB23F490EF7ACULL,
		0x8517EBEE64227B65ULL,
		0x47499E585A5FFAF4ULL,
		0x40BD1DE25730EED7ULL,
		0xCD69CD8B6EF517B5ULL,
		0x6E8F6802E3997B50ULL,
		0x00D61FFAA73B106AULL,
		0x7B4E92CF103C4281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7EBA61C0425239ULL,
		0x1EA4C5F474E8BA50ULL,
		0x1CC94289ECE77571ULL,
		0x9BF4107200EA00C4ULL,
		0x9B819B6D6C7E23FEULL,
		0xAE06BB326CE9CF1EULL,
		0x7C51BB0FBB4BEE10ULL,
		0x68BAABC941BA04B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AAFF7DD88CCA573ULL,
		0x667325F9EF39C115ULL,
		0x2A805BCE6D788583ULL,
		0xA4C90D705646EE13ULL,
		0x31E8321E0276F3B6ULL,
		0xC088ACD076AFAC32ULL,
		0x848464EAEBEF2259ULL,
		0x1293E705CE823DCEULL
	}};
	sign = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA5FBE00D7FE51C7ULL,
		0x358D3BF0CD878610ULL,
		0x248600F60B212B46ULL,
		0xCC345FCAE28B78EAULL,
		0xB3CB7AB6682EAE97ULL,
		0xAB9A51DF5098080FULL,
		0xD60A501AE816FDE7ULL,
		0x21B724C3178F586BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ECE4C0F77992743ULL,
		0x58C3756079D09852ULL,
		0x601FBD0ACA495914ULL,
		0xB38D216ED8D297F2ULL,
		0x59E88339F7405222ULL,
		0x367D25EC15C91C2CULL,
		0x67A2DF29C7DA3B9BULL,
		0x450F01CC97D35532ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB9171F160652A84ULL,
		0xDCC9C69053B6EDBEULL,
		0xC46643EB40D7D231ULL,
		0x18A73E5C09B8E0F7ULL,
		0x59E2F77C70EE5C75ULL,
		0x751D2BF33ACEEBE3ULL,
		0x6E6770F1203CC24CULL,
		0xDCA822F67FBC0339ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F3D1DFC297F981EULL,
		0x3F2BC5CC99ACCE11ULL,
		0x2867A0EE99699372ULL,
		0xEC1AC8C6D5B36555ULL,
		0x80B510990E886F8DULL,
		0x5BCE25BF669B03D9ULL,
		0x372AE2C0CA472B1FULL,
		0x0373089B80957E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1670AF5385A64B91ULL,
		0x1D1E103C6D258F6BULL,
		0xA84594DF888A277EULL,
		0xE1159B4F4FE62034ULL,
		0xF5DA9D5EADE39D76ULL,
		0x82606C8B2C8B2D41ULL,
		0x4CBCB417B840CF29ULL,
		0x77BF0FFA11F8022EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58CC6EA8A3D94C8DULL,
		0x220DB5902C873EA6ULL,
		0x80220C0F10DF6BF4ULL,
		0x0B052D7785CD4520ULL,
		0x8ADA733A60A4D217ULL,
		0xD96DB9343A0FD697ULL,
		0xEA6E2EA912065BF5ULL,
		0x8BB3F8A16E9D7C48ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBE1FE63583A4CFEULL,
		0xF8E45FD22E0B1136ULL,
		0xD034DFF78D5D4DC3ULL,
		0xD9F486FB66CFE837ULL,
		0xBC3E9107FA248EC3ULL,
		0x3DF5C0B972EE6B1BULL,
		0x2B441A1597C11D5FULL,
		0x472A94D7ABE40D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3B2B8AE64F3B6DULL,
		0x930DB5335662579CULL,
		0x2CD653B74382A07AULL,
		0x9A6653BE7998161FULL,
		0x91EDD1741D6E507CULL,
		0xD6E33DFBBF02016EULL,
		0x8B5F43585475B3A5ULL,
		0xA9D28996A7320CD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FA6D2D871EB1191ULL,
		0x65D6AA9ED7A8B99AULL,
		0xA35E8C4049DAAD49ULL,
		0x3F8E333CED37D218ULL,
		0x2A50BF93DCB63E47ULL,
		0x671282BDB3EC69ADULL,
		0x9FE4D6BD434B69B9ULL,
		0x9D580B4104B200C3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x444DC002B6DF2147ULL,
		0x57EE9C7B01765F73ULL,
		0x907EF36C00D99FDFULL,
		0x88336BD9543B4AEEULL,
		0xD055F281D26C3CCEULL,
		0xCC1F43C49E274C07ULL,
		0x9905D82FB3A666F1ULL,
		0x1C106A9C1C1B972CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7DB2BF89E9301BEULL,
		0xF5E37D50C6EB9CDBULL,
		0x637B6163AAD1A13BULL,
		0x8466329C07918CAAULL,
		0x83E24D8CA3B3F6BBULL,
		0xE5A49AAAF6723C87ULL,
		0x91187D28BF04ABBCULL,
		0xA4FF9C076C59338EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C72940A184C1F89ULL,
		0x620B1F2A3A8AC297ULL,
		0x2D0392085607FEA3ULL,
		0x03CD393D4CA9BE44ULL,
		0x4C73A4F52EB84613ULL,
		0xE67AA919A7B50F80ULL,
		0x07ED5B06F4A1BB34ULL,
		0x7710CE94AFC2639EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x419BF306C0D0D5D8ULL,
		0x1752A9015A4B4E1EULL,
		0xCC0F3F7367EA21D2ULL,
		0x65EAB8E681553B20ULL,
		0x41CA1BCA4C460AD8ULL,
		0xB21D2C7769409C55ULL,
		0x20483771B5A60B3CULL,
		0xDB9CA17EEE9411B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18C0BC60F558148ULL,
		0x3B80828022EFC32FULL,
		0x83F376E34BA87F0CULL,
		0xE50AEEA5586AAA39ULL,
		0x7FA0C3A6698685C9ULL,
		0x7A0F3564CED7EEE7ULL,
		0x3A04D63BFB742BDEULL,
		0xDAF4FC19B17EC72EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x700FE740B17B5490ULL,
		0xDBD22681375B8AEEULL,
		0x481BC8901C41A2C5ULL,
		0x80DFCA4128EA90E7ULL,
		0xC2295823E2BF850EULL,
		0x380DF7129A68AD6DULL,
		0xE6436135BA31DF5EULL,
		0x00A7A5653D154A83ULL
	}};
	sign = 0;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E212BC899F5A7CDULL,
		0xE87D669743195DABULL,
		0x98F26B101C2426B2ULL,
		0xABC3DA6B40A8AAEBULL,
		0xF72258D346AB6D4FULL,
		0xE18A2183DCD479F4ULL,
		0x11CB0A4F13911220ULL,
		0xC7C7F03F3DD30358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC066D64890776567ULL,
		0x325F5A94FEEBFDFFULL,
		0x405D91A02FB629CCULL,
		0xEDDE965B38CA7991ULL,
		0x3CBCD7D529B74C52ULL,
		0x42BCEFD1539E881CULL,
		0xF23DA5EED2DC0C86ULL,
		0x66AED499F24DE58DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DBA5580097E4266ULL,
		0xB61E0C02442D5FABULL,
		0x5894D96FEC6DFCE6ULL,
		0xBDE5441007DE315AULL,
		0xBA6580FE1CF420FCULL,
		0x9ECD31B28935F1D8ULL,
		0x1F8D646040B5059AULL,
		0x61191BA54B851DCAULL
	}};
	sign = 0;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57493601B9CEFC63ULL,
		0xB9956ED7D598219BULL,
		0xB01C7DD62AA99DA6ULL,
		0x005BD6555BC05BFDULL,
		0x9F967513E0C22250ULL,
		0xE78018DCBF0A9320ULL,
		0xAEDCAD54F6403E2CULL,
		0x0E67B68DB103C32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BA9B676E48E1144ULL,
		0xA1CDCF560FF16E4AULL,
		0xA9613E2DCC076E41ULL,
		0x56D9F185E023A71AULL,
		0xCE973076683C8910ULL,
		0x78A888F5F2D2597CULL,
		0x7E834DF2C04112F1ULL,
		0x8F8618B06857BB10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB9F7F8AD540EB1FULL,
		0x17C79F81C5A6B350ULL,
		0x06BB3FA85EA22F65ULL,
		0xA981E4CF7B9CB4E3ULL,
		0xD0FF449D7885993FULL,
		0x6ED78FE6CC3839A3ULL,
		0x30595F6235FF2B3BULL,
		0x7EE19DDD48AC081DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4BCD08ECA14F60FULL,
		0x2E77BBB59ADD986EULL,
		0xCF5DC729E4F39ADFULL,
		0x62747FC3B2D2C4EEULL,
		0xCD4ECEF87D2D906AULL,
		0x679D742E5DD39AA7ULL,
		0xBB9E8C311EFE0434ULL,
		0xD19F75A40D988D12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9BCD561CA77A69ULL,
		0xF2BAD5EDBA5DC2BAULL,
		0x5C0986652480F1C3ULL,
		0x0E02F1CC58A7929BULL,
		0x727CA1E1820C03F4ULL,
		0x02524CDC447B3A4BULL,
		0x765ACA05784CBAEBULL,
		0x0F5E2B85C0A5E0FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99210338AD6D7BA6ULL,
		0x3BBCE5C7E07FD5B4ULL,
		0x735440C4C072A91BULL,
		0x54718DF75A2B3253ULL,
		0x5AD22D16FB218C76ULL,
		0x654B27521958605CULL,
		0x4543C22BA6B14949ULL,
		0xC2414A1E4CF2AC13ULL
	}};
	sign = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE55BD75C2D09E60ULL,
		0x8D47246F2AA99818ULL,
		0xB8B5CE752CD6B4FBULL,
		0xEE062FD4B4C3D67BULL,
		0x98028713A6309C77ULL,
		0x1233737F1CC265ABULL,
		0x6D9B8952F8AA9407ULL,
		0xB8590ECDE4344C16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55A0C0E287FB5160ULL,
		0x5FD1AEADDA1FF42FULL,
		0xBBF9C05B4A8E5F4EULL,
		0x5C5FB29B181C3CAEULL,
		0x9D57F23C472905A4ULL,
		0xC4073E4DA3E554E2ULL,
		0x3BFBFCB465002E78ULL,
		0xF779C6AF43D2250AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58B4FC933AD54D00ULL,
		0x2D7575C15089A3E9ULL,
		0xFCBC0E19E24855ADULL,
		0x91A67D399CA799CCULL,
		0xFAAA94D75F0796D3ULL,
		0x4E2C353178DD10C8ULL,
		0x319F8C9E93AA658EULL,
		0xC0DF481EA062270CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A940D7016713888ULL,
		0xC4C7E6CC5162D2C9ULL,
		0x16F691A305EFBAAEULL,
		0xF1C3CD9E1FE8B47DULL,
		0xF9DB36545CC11E1EULL,
		0x2913019FA1DC0EA6ULL,
		0xBD8E11FD41C875A0ULL,
		0x035F85C0919FA4CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDD3DD185B5552ACULL,
		0xA2454859384C7B75ULL,
		0x5293D1E3F6C7BBA7ULL,
		0x1E4CF1FC8B7A75A3ULL,
		0x42E589189E388E5CULL,
		0x3101079689CE7E7BULL,
		0x0E9D96C42BCB9516ULL,
		0xAF6F2D1DB377D0E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CC03057BB1BE5DCULL,
		0x22829E7319165753ULL,
		0xC462BFBF0F27FF07ULL,
		0xD376DBA1946E3ED9ULL,
		0xB6F5AD3BBE888FC2ULL,
		0xF811FA09180D902BULL,
		0xAEF07B3915FCE089ULL,
		0x53F058A2DE27D3E5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED325CDC7B68273AULL,
		0x12232E6C492D8FE9ULL,
		0x173452CC2D1227B4ULL,
		0x50BB85DE7ADDA34FULL,
		0xBF3B99A6350E3DAAULL,
		0xFA8456D772BC60A4ULL,
		0xC25FA55E7DC007E7ULL,
		0x1940C7A41FC1C299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E08CFC5692E380ULL,
		0xB5F4E1771776FC64ULL,
		0xD3C2D8E23A513BD3ULL,
		0x4B2D5E4DD4868C0AULL,
		0xD114EB43513B8B92ULL,
		0x0CFFF1F9DD666EA9ULL,
		0x749FC7803830A2D6ULL,
		0x1E51339FED10A418ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE951CFE024D543BAULL,
		0x5C2E4CF531B69385ULL,
		0x437179E9F2C0EBE0ULL,
		0x058E2790A6571744ULL,
		0xEE26AE62E3D2B218ULL,
		0xED8464DD9555F1FAULL,
		0x4DBFDDDE458F6511ULL,
		0xFAEF940432B11E81ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x046A041B15B1C6B0ULL,
		0xC7ED868CA61AA989ULL,
		0xA24C583FE66EFDF3ULL,
		0xB9C14AC96FB25F04ULL,
		0x0EE41A1AD56C957CULL,
		0x0C387BCF79232BB4ULL,
		0x3398CE0D7A6219EDULL,
		0x879A92BD3BD5DB92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B697B028A6401A2ULL,
		0x15A8EF3A9B1A68CFULL,
		0x4E15E1BD15891117ULL,
		0xA7DC291174D936C1ULL,
		0x43A806EE3B4133ABULL,
		0x2366F54EC8111C66ULL,
		0x684735AB027E58E2ULL,
		0xD43C3C3EC8D8A7F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA90089188B4DC50EULL,
		0xB24497520B0040B9ULL,
		0x54367682D0E5ECDCULL,
		0x11E521B7FAD92843ULL,
		0xCB3C132C9A2B61D1ULL,
		0xE8D18680B1120F4DULL,
		0xCB51986277E3C10AULL,
		0xB35E567E72FD3398ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6A06F99F74223C7ULL,
		0x359C40B91F1D5C76ULL,
		0x51E9AFF1B354CD78ULL,
		0x8F5B11CE2B0AF64EULL,
		0x20CF293C85A780F7ULL,
		0xB8F00631118E8E79ULL,
		0x4ACC71BBAD351978ULL,
		0xE3DFFD1C9599F18DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D69A6414ED026B2ULL,
		0x5D657E9BE789614FULL,
		0x54B34BEF10EF6DB4ULL,
		0xA12EB3746FF3DB26ULL,
		0x7A6C405F13B7378AULL,
		0x570CEA32D06E23C9ULL,
		0xC6805668E2F7C9DFULL,
		0x198F7417C27C28FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5936C958A871FD15ULL,
		0xD836C21D3793FB27ULL,
		0xFD366402A2655FC3ULL,
		0xEE2C5E59BB171B27ULL,
		0xA662E8DD71F0496CULL,
		0x61E31BFE41206AAFULL,
		0x844C1B52CA3D4F99ULL,
		0xCA508904D31DC88EULL
	}};
	sign = 0;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65739EC53ABF9FF7ULL,
		0xE28246F47523DFC8ULL,
		0x86B51F845A399734ULL,
		0x0F5760491B147F30ULL,
		0xCDCC61BEB21C0676ULL,
		0x5BF019823D156F07ULL,
		0xAC097557590A54A0ULL,
		0x69B975955B0BDEF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D8D7C09005C0852ULL,
		0x16ED270CDAC4AC0EULL,
		0x909507C8834A3094ULL,
		0xFBD10FE62AFAA5AAULL,
		0x0DF6627CDBA61F93ULL,
		0xAA60CF4F787743C4ULL,
		0xE957B9438FF1A0A0ULL,
		0xDB4DFEF5A64256EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07E622BC3A6397A5ULL,
		0xCB951FE79A5F33BAULL,
		0xF62017BBD6EF66A0ULL,
		0x13865062F019D985ULL,
		0xBFD5FF41D675E6E2ULL,
		0xB18F4A32C49E2B43ULL,
		0xC2B1BC13C918B3FFULL,
		0x8E6B769FB4C98808ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5131C9E92A3DC828ULL,
		0xC5CDA46338B9AFA7ULL,
		0x511651F17DBB099FULL,
		0x7C377E3FEC5421D5ULL,
		0x19F5DB06D4C631ACULL,
		0x346DD380AEC4E1BCULL,
		0xE0BC1C9636D46A84ULL,
		0xDF72B6F178A4EF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B03982BC0B76310ULL,
		0xA091200E987095C5ULL,
		0xAA3127744161645AULL,
		0xE664F8B22E38808EULL,
		0x8BAE656F0947A7A1ULL,
		0x8BD46FF71A7E7CB6ULL,
		0x1CB58E7756665966ULL,
		0xCB21CB850690C611ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x162E31BD69866518ULL,
		0x253C8454A04919E2ULL,
		0xA6E52A7D3C59A545ULL,
		0x95D2858DBE1BA146ULL,
		0x8E477597CB7E8A0AULL,
		0xA899638994466505ULL,
		0xC4068E1EE06E111DULL,
		0x1450EB6C7214298DULL
	}};
	sign = 0;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2FBEFF9FE56F6F8ULL,
		0xA89D3E7655F3632AULL,
		0x57A6F92D654FED34ULL,
		0x163B10AB98CC0C55ULL,
		0x3FADA62C15D1F8D1ULL,
		0xB406D3C386B97583ULL,
		0xA55196CE262F2710ULL,
		0xAA3BB10866A71642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x914C3E08BFA8615AULL,
		0xC0532B3AD4EA8538ULL,
		0xAB02BC1A2C649577ULL,
		0x172F399DD4FB435EULL,
		0x1CEDCC2EFE3066BCULL,
		0x4E6093ED8D972DDAULL,
		0xE79738E51DEA4F0DULL,
		0xC01EBCFEB300C912ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61AFB1F13EAE959EULL,
		0xE84A133B8108DDF2ULL,
		0xACA43D1338EB57BCULL,
		0xFF0BD70DC3D0C8F6ULL,
		0x22BFD9FD17A19214ULL,
		0x65A63FD5F92247A9ULL,
		0xBDBA5DE90844D803ULL,
		0xEA1CF409B3A64D2FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7955D0A11E245FE0ULL,
		0xF1EA9801D1EB88D5ULL,
		0x53CB2278334F8724ULL,
		0x9CA3CE648EAA072DULL,
		0xF005149318BDBD14ULL,
		0xE0384B710ABF8C94ULL,
		0x7755658E56623325ULL,
		0xCE75A942993E0F5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F368A870A9B940DULL,
		0x7650D8411CDBD126ULL,
		0xFBA7C9B8796C55BAULL,
		0xCCCB0589A316C29CULL,
		0xECE5CAD041D55371ULL,
		0xB063F96112C89599ULL,
		0xF5C72510EB6FF9B0ULL,
		0x20A0DD8D5EC3F9D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA1F461A1388CBD3ULL,
		0x7B99BFC0B50FB7AEULL,
		0x582358BFB9E3316AULL,
		0xCFD8C8DAEB934490ULL,
		0x031F49C2D6E869A2ULL,
		0x2FD4520FF7F6F6FBULL,
		0x818E407D6AF23975ULL,
		0xADD4CBB53A7A1582ULL
	}};
	sign = 0;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD51534E3751C4170ULL,
		0x448EC8663A84614FULL,
		0x002622D853B99A4FULL,
		0x08429E3E17663DD5ULL,
		0xFB57C2ECED450E2BULL,
		0x01BB0DD5B353B756ULL,
		0x66E6DA983C2EE58DULL,
		0x24761E6C4409CFD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0843141BE00DA5AULL,
		0x882B02AA56FE747EULL,
		0x973D94465D845270ULL,
		0xA8F6EDD85B4F6131ULL,
		0x5BA127CE03560C0BULL,
		0x1FB05CA72203975AULL,
		0x5188471655F8EC1AULL,
		0x9B452FF6C4071211ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x249103A1B71B6716ULL,
		0xBC63C5BBE385ECD1ULL,
		0x68E88E91F63547DEULL,
		0x5F4BB065BC16DCA3ULL,
		0x9FB69B1EE9EF021FULL,
		0xE20AB12E91501FFCULL,
		0x155E9381E635F972ULL,
		0x8930EE758002BDC8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BF4CE6305BBB514ULL,
		0x97737B2995BF0D6FULL,
		0x8626FD0EDC1C8F30ULL,
		0xAF03912DF145A3C6ULL,
		0x2338CEDCFE8F95F0ULL,
		0x2F1E6A876043EC08ULL,
		0x80BDA2402E5AE5E2ULL,
		0xFE3413CFC1DDE91AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0DA206EFE98C5B7ULL,
		0xD93E0ECCFC54B492ULL,
		0x4CE4447DE00027D4ULL,
		0x77F98F8FB042C4AFULL,
		0xD9EF049EFFB726FDULL,
		0x9767ED70BF23DEBEULL,
		0x78F1E7D0A820622BULL,
		0xEDD77A5C0B6EBC42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B1AADF40722EF5DULL,
		0xBE356C5C996A58DCULL,
		0x3942B890FC1C675BULL,
		0x370A019E4102DF17ULL,
		0x4949CA3DFED86EF3ULL,
		0x97B67D16A1200D49ULL,
		0x07CBBA6F863A83B6ULL,
		0x105C9973B66F2CD8ULL
	}};
	sign = 0;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD5B64E5B59F09E2ULL,
		0x88A38B1B7BD496E3ULL,
		0x5495736BB52F542EULL,
		0x07C9E46F4C989136ULL,
		0xA5D8E3A11CBDF66BULL,
		0xC2C241CF8F9C5566ULL,
		0x14716521C193E7A6ULL,
		0xF2C9E5D2FE6C16A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A71ADC684B950E4ULL,
		0x733BDC8F267D53FDULL,
		0x8954CADCCF5206ADULL,
		0x40F2D3B4C19BAB4EULL,
		0xC1ADD6E5FB500F7CULL,
		0xF2E3C1E7886DE8F8ULL,
		0x3E03D696425ACDD7ULL,
		0x7887AE18DC24772FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92E9B71F30E5B8FEULL,
		0x1567AE8C555742E6ULL,
		0xCB40A88EE5DD4D81ULL,
		0xC6D710BA8AFCE5E7ULL,
		0xE42B0CBB216DE6EEULL,
		0xCFDE7FE8072E6C6DULL,
		0xD66D8E8B7F3919CEULL,
		0x7A4237BA22479F75ULL
	}};
	sign = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x566292236B4A31C4ULL,
		0xDE6FA7C969E558ECULL,
		0x3993ED87455AF040ULL,
		0xAE683410B2F84025ULL,
		0xABB78A37523110C4ULL,
		0xB3F5EF337CA00104ULL,
		0xA415C0A4368D2C4EULL,
		0x94059E836D9E9D9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3C4B4E265C2D52ULL,
		0x4D575CCD5F4049E1ULL,
		0xD90EFDE94979B18FULL,
		0x584519807AF7E0A3ULL,
		0x91683BB1F1657FA7ULL,
		0xE3E1298C98288AF7ULL,
		0x1EFC3486560696CCULL,
		0x088C8803C895B758ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C2646D544EE0472ULL,
		0x91184AFC0AA50F0AULL,
		0x6084EF9DFBE13EB1ULL,
		0x56231A9038005F81ULL,
		0x1A4F4E8560CB911DULL,
		0xD014C5A6E477760DULL,
		0x85198C1DE0869581ULL,
		0x8B79167FA508E646ULL
	}};
	sign = 0;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55B0A883E224FF38ULL,
		0xC7FDA4F603896AF0ULL,
		0x43742CBBBCD7C93EULL,
		0x4E340AB29D2F235EULL,
		0x005E646F0CCCCBDAULL,
		0xA5CA3133C0D68687ULL,
		0x84A32944D187F686ULL,
		0xD367429036B8AA36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1E6E6A7C87085CULL,
		0x20A11C162FE737A8ULL,
		0x56963FBE725F8301ULL,
		0xBE1B132147326025ULL,
		0xECEFE3EB03138771ULL,
		0x4ECC23D47E0A9D02ULL,
		0xC21BD456953D5BA9ULL,
		0xEBB4CAED3763B25DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57923A19659DF6DCULL,
		0xA75C88DFD3A23347ULL,
		0xECDDECFD4A78463DULL,
		0x9018F79155FCC338ULL,
		0x136E808409B94468ULL,
		0x56FE0D5F42CBE984ULL,
		0xC28754EE3C4A9ADDULL,
		0xE7B277A2FF54F7D8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57AF2715E286C5F0ULL,
		0x7CD47FDC8124B8B5ULL,
		0x272947E08CED29F4ULL,
		0x88319438C867751BULL,
		0x9DBE33DE37397A4DULL,
		0xB7FF2F06DA0F420EULL,
		0x802BD7A23A648310ULL,
		0x096943F0423FC73CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C7480DA4531A46ULL,
		0x51C6CD755DC97D7DULL,
		0xD15553A7B09F2105ULL,
		0xE3D242B915623A95ULL,
		0x360BAFA5D02D649BULL,
		0x4EEABECFB0D8B8C1ULL,
		0x0072CE36BF8BD709ULL,
		0xD96FE9A1EA46E828ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFE7DF083E33ABAAULL,
		0x2B0DB267235B3B37ULL,
		0x55D3F438DC4E08EFULL,
		0xA45F517FB3053A85ULL,
		0x67B28438670C15B1ULL,
		0x691470372936894DULL,
		0x7FB9096B7AD8AC07ULL,
		0x2FF95A4E57F8DF14ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F50B9BF9CB9A8A9ULL,
		0x6B0FC6AD87E0D05CULL,
		0xC0DFCEF6B457127FULL,
		0x7B714FC06AE72309ULL,
		0x8647615B77A540D9ULL,
		0x359D1C6B9B31CEA1ULL,
		0xCA3AD9B0F84DB6FFULL,
		0x050B2C09307C3CB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E275692A320F923ULL,
		0x63EC9A448653F861ULL,
		0x5CF1E49F0D28E171ULL,
		0xB4ED3A7E2D38FB55ULL,
		0xC787B9FAC3637B1CULL,
		0x2204B8A6B06E7391ULL,
		0x6FDDBA17F50C7E92ULL,
		0x145FD73BEFA9E11FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0129632CF998AF86ULL,
		0x07232C69018CD7FBULL,
		0x63EDEA57A72E310EULL,
		0xC68415423DAE27B4ULL,
		0xBEBFA760B441C5BCULL,
		0x139863C4EAC35B0FULL,
		0x5A5D1F990341386DULL,
		0xF0AB54CD40D25B96ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41A4AB821DBD9CD5ULL,
		0xB1AB3F2EC8DD6CEBULL,
		0xF3D4F0839529AA23ULL,
		0x12E8ADCF98DACD40ULL,
		0xDCF3B5191F1A8FF9ULL,
		0xE3AF67D07B319B98ULL,
		0xF3D57BC66113A4A0ULL,
		0x15C0432EC05DA4B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD986374C79FE5F7EULL,
		0x8C7E8AD87BF55281ULL,
		0xD937CFE51E66756FULL,
		0xC3F507977E8916C6ULL,
		0xA91F6A85A9F718F0ULL,
		0x6A307979DD0E715FULL,
		0xAE613B547F4C51E2ULL,
		0x0F80D3F0C09AFA0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x681E7435A3BF3D57ULL,
		0x252CB4564CE81A69ULL,
		0x1A9D209E76C334B4ULL,
		0x4EF3A6381A51B67AULL,
		0x33D44A9375237708ULL,
		0x797EEE569E232A39ULL,
		0x45744071E1C752BEULL,
		0x063F6F3DFFC2AAADULL
	}};
	sign = 0;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71D3EF0632171899ULL,
		0xA36F70B803AA820CULL,
		0x49B59C357600894CULL,
		0xE69DDA061C37466EULL,
		0xBBDB3695D136B837ULL,
		0xB160631AC5B57CF6ULL,
		0x3E1A5291B01C5EE5ULL,
		0x0B9654D014289B1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB634E3DEB1EABE75ULL,
		0x4AED622C190D7391ULL,
		0xCB282BC2D3E04008ULL,
		0x0DE3099C95FBC61CULL,
		0x781D9049725D8A61ULL,
		0xA1A25DA62934C5A2ULL,
		0x51096BC2795EA24AULL,
		0xDEBC527F136686B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB9F0B27802C5A24ULL,
		0x58820E8BEA9D0E7AULL,
		0x7E8D7072A2204944ULL,
		0xD8BAD069863B8051ULL,
		0x43BDA64C5ED92DD6ULL,
		0x0FBE05749C80B754ULL,
		0xED10E6CF36BDBC9BULL,
		0x2CDA025100C21466ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F6EA350D53A3FECULL,
		0x57991A8AD018EFFDULL,
		0xD4B4E37BB3F6D034ULL,
		0x99DBA615E9AB4D80ULL,
		0xC459F1E2083AB169ULL,
		0x802A8D3720D8B304ULL,
		0x820EE7C0824D57EDULL,
		0x1E4647DFA19730F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00CDE113CA284CCULL,
		0xAE9F061503C5DCCCULL,
		0x3DEA35B5D99256C1ULL,
		0x11FE9ED61ECB7495ULL,
		0xC4B4382CD029EA96ULL,
		0x2858AFF2AA99DAC3ULL,
		0x3F114A54B7207AE4ULL,
		0xC004D6A975D4100BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F61C53F9897BB20ULL,
		0xA8FA1475CC531330ULL,
		0x96CAADC5DA647972ULL,
		0x87DD073FCADFD8EBULL,
		0xFFA5B9B53810C6D3ULL,
		0x57D1DD44763ED840ULL,
		0x42FD9D6BCB2CDD09ULL,
		0x5E4171362BC320E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6BE77967648455CULL,
		0x82C7BA5F3638B9D6ULL,
		0xEEF542B86880F9A1ULL,
		0xDD966F414EDFEBC3ULL,
		0x5BC54FC9F5C2DDACULL,
		0xAC03413423DB2158ULL,
		0x6F280D44DCD96DACULL,
		0x6E658D57E09CFB40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1601B3E9BE2F355AULL,
		0x6973C5B798F486E9ULL,
		0x595C104AF052ADF9ULL,
		0x2D2DAEA7895E87ECULL,
		0x11FD1AA5C56C1BF1ULL,
		0x85831EC8B3A8C442ULL,
		0xACE90CC3E708E233ULL,
		0x8A1E3C05043E419FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0BCC3ACB8191002ULL,
		0x1953F4A79D4432EDULL,
		0x9599326D782E4BA8ULL,
		0xB068C099C58163D7ULL,
		0x49C835243056C1BBULL,
		0x2680226B70325D16ULL,
		0xC23F0080F5D08B79ULL,
		0xE4475152DC5EB9A0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B859F8129FBE64BULL,
		0x1447685F29CDFDF6ULL,
		0xAE3A81C1915F67AAULL,
		0x100271BC434B361DULL,
		0x3F0C44526577B7CFULL,
		0xD548AA273B231418ULL,
		0xC2CAE17FA2CC7027ULL,
		0x23B01181C1C77C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6022859C559BED9ULL,
		0x5CFF88E8B10639FFULL,
		0xF2C5CDAA5F1FDCECULL,
		0xEE74691C2D899E2BULL,
		0x2C6FA893BFB98964ULL,
		0x9793E438EAEB0279ULL,
		0x6244530729D7E86AULL,
		0xF493DDBE7A9E898BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2583772764A22772ULL,
		0xB747DF7678C7C3F6ULL,
		0xBB74B417323F8ABDULL,
		0x218E08A015C197F1ULL,
		0x129C9BBEA5BE2E6AULL,
		0x3DB4C5EE5038119FULL,
		0x60868E7878F487BDULL,
		0x2F1C33C34728F2F6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF683345F67DCC858ULL,
		0x709FF2B46EB66BC9ULL,
		0xE91CF445B8905AF0ULL,
		0x36A7270FB1930E7AULL,
		0x8D124A42A259E22CULL,
		0xB7D039CC2FCE4DACULL,
		0x480294914B17614CULL,
		0x5A752AADEBB98AF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90FB55DC26817C89ULL,
		0xA76430F3D7C3D828ULL,
		0xFF26227341CAE707ULL,
		0x3CB0023A3F90B751ULL,
		0x717E3D570D68A79CULL,
		0x6FAA42F134588BA9ULL,
		0x94102B07053BEC84ULL,
		0x8C73A9E5FE4F8F1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6587DE83415B4BCFULL,
		0xC93BC1C096F293A1ULL,
		0xE9F6D1D276C573E8ULL,
		0xF9F724D572025728ULL,
		0x1B940CEB94F13A8FULL,
		0x4825F6DAFB75C203ULL,
		0xB3F2698A45DB74C8ULL,
		0xCE0180C7ED69FBD7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE63D5BDD4A9BC02ULL,
		0x73C8781642E7A9C6ULL,
		0x4451D4E53947E2B3ULL,
		0x265D8C1388F27991ULL,
		0x006DBC1A60B91DA5ULL,
		0xF9E301A568CF83CCULL,
		0x7B093948044C7003ULL,
		0xA30FE18865E5B2B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1783A1FE97B65BULL,
		0xA63857189380AFD0ULL,
		0xC0BD26E791284407ULL,
		0xFAE7A55158AFFFC1ULL,
		0x1883C48CBBE99948ULL,
		0xC6CF048D4D5CFD7BULL,
		0x44EDDDC21713F46AULL,
		0x4C622D94B8AA6629ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC04C521BD61205A7ULL,
		0xCD9020FDAF66F9F6ULL,
		0x8394ADFDA81F9EABULL,
		0x2B75E6C2304279CFULL,
		0xE7E9F78DA4CF845CULL,
		0x3313FD181B728650ULL,
		0x361B5B85ED387B99ULL,
		0x56ADB3F3AD3B4C87ULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70A6C198CCD08571ULL,
		0xA1F3D1F5F1225A05ULL,
		0x11D69292FC9A71D1ULL,
		0x4448A94FEF34117AULL,
		0xC50F80CD5609D3F6ULL,
		0x293D46477B848C9FULL,
		0xCC83781A7FB1B3DDULL,
		0xF5F27E1AEBAF0D08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD17A942FC61EAEA5ULL,
		0xA4D284EA62610DA9ULL,
		0x26FB1A84D938AA66ULL,
		0xD8FF24CF6EC8FA30ULL,
		0x493F8FEFF389340DULL,
		0x8AEF7125FD09E827ULL,
		0x5892A28D98F6C232ULL,
		0x18F2C6471D900BEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F2C2D6906B1D6CCULL,
		0xFD214D0B8EC14C5BULL,
		0xEADB780E2361C76AULL,
		0x6B498480806B1749ULL,
		0x7BCFF0DD62809FE8ULL,
		0x9E4DD5217E7AA478ULL,
		0x73F0D58CE6BAF1AAULL,
		0xDCFFB7D3CE1F011BULL
	}};
	sign = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BFAA88DBFA18369ULL,
		0x4593F07FAFCFEACBULL,
		0x2F975DEEAEEFB221ULL,
		0x2495A8D3D60F4DBFULL,
		0x1BFC38F5563F50FCULL,
		0x7F2AE6C8539A01B6ULL,
		0x80068CA3032C8E05ULL,
		0x83EFCEB5A83AC176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10AE8E3291B02BBEULL,
		0x913DCF54D5DF9C21ULL,
		0x8827E328B874571AULL,
		0xE65F9116B3E388A1ULL,
		0xDA2975498B68D6BDULL,
		0x6CAF4165985476CEULL,
		0xD316327071160861ULL,
		0x5DF44B4B899F69DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B4C1A5B2DF157ABULL,
		0xB456212AD9F04EAAULL,
		0xA76F7AC5F67B5B06ULL,
		0x3E3617BD222BC51DULL,
		0x41D2C3ABCAD67A3EULL,
		0x127BA562BB458AE7ULL,
		0xACF05A32921685A4ULL,
		0x25FB836A1E9B5798ULL
	}};
	sign = 0;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7943DCA5B4026AFCULL,
		0xF6C1FBF82430250EULL,
		0xF8C2F741B10D547EULL,
		0x057C60E22CAA0D06ULL,
		0xAC26A64F3FCF8965ULL,
		0x8E78D11EC0214209ULL,
		0x1526DC4439889FD4ULL,
		0xD60AAA6FE9FF7AD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C3A9A37112A9DCULL,
		0x1AD31A68711307CBULL,
		0x8542154487BD596EULL,
		0x8BCB90106D58CAFDULL,
		0xF215DEAD64E964C1ULL,
		0xE247B9D59C965601ULL,
		0x7996DB1B2AC61DACULL,
		0x1B614063F458B124ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF280330242EFC120ULL,
		0xDBEEE18FB31D1D42ULL,
		0x7380E1FD294FFB10ULL,
		0x79B0D0D1BF514209ULL,
		0xBA10C7A1DAE624A3ULL,
		0xAC311749238AEC07ULL,
		0x9B9001290EC28227ULL,
		0xBAA96A0BF5A6C9ACULL
	}};
	sign = 0;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA677FC06BB58B8F3ULL,
		0x62372F8B6899A552ULL,
		0x78997AB79F909721ULL,
		0x49BF5F165795875EULL,
		0xF6F505D47614F30BULL,
		0xC306EBA2F82E002EULL,
		0xC08E3717C4662D45ULL,
		0xB6CEBF96FBB8D93CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42F958EFEB4B140ULL,
		0x4B61CBFA0BA0FF07ULL,
		0x40D9BC513951FF5FULL,
		0xC7A11797BA68C7EAULL,
		0xE394CB418A5674E2ULL,
		0xB102402E75E4F774ULL,
		0x8586C3B5519464BBULL,
		0xBFFAFF57214D9BB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2486677BCA407B3ULL,
		0x16D563915CF8A64AULL,
		0x37BFBE66663E97C2ULL,
		0x821E477E9D2CBF74ULL,
		0x13603A92EBBE7E28ULL,
		0x1204AB74824908BAULL,
		0x3B07736272D1C88AULL,
		0xF6D3C03FDA6B3D84ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C3CCE57018ECB3EULL,
		0x66A2A32ADAFCEC2AULL,
		0xBBBFAF1369472995ULL,
		0xE3CECEDFA3881B4EULL,
		0x2AF873A7FEFCC073ULL,
		0xDAD254942F0F0305ULL,
		0xFE78F66E294F8142ULL,
		0x30DC40D714561515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23F1939B5CF0C9C2ULL,
		0x72390B3A4CB964BEULL,
		0xA8B22C115217BA99ULL,
		0x3E3F75F9988AC91AULL,
		0xEB28445E90B965FCULL,
		0x27B26431D5B2F6DBULL,
		0x306CB01B6C14E529ULL,
		0xFF521E5EF9EE2708ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE84B3ABBA49E017CULL,
		0xF46997F08E43876BULL,
		0x130D8302172F6EFBULL,
		0xA58F58E60AFD5234ULL,
		0x3FD02F496E435A77ULL,
		0xB31FF062595C0C29ULL,
		0xCE0C4652BD3A9C19ULL,
		0x318A22781A67EE0DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88D08F5972A28452ULL,
		0x2350A4CBCB3930B7ULL,
		0x289B3B2EC0636346ULL,
		0x87FC60E0E5819527ULL,
		0x0F8701AA55E1AE87ULL,
		0xBB0E7D0C453AAD14ULL,
		0xC21D99ECD1FC3C40ULL,
		0x21D67827C391074EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5190EA096B6EA050ULL,
		0xA0C04740409131F6ULL,
		0x43F3E022474C6519ULL,
		0x7BBBFAEF73AE4256ULL,
		0xBF74EF60B7BC3740ULL,
		0x59B4E668F41C2F45ULL,
		0x229DA0FC21A520B1ULL,
		0xC1E8069442053E62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x373FA5500733E402ULL,
		0x82905D8B8AA7FEC1ULL,
		0xE4A75B0C7916FE2CULL,
		0x0C4065F171D352D0ULL,
		0x501212499E257747ULL,
		0x615996A3511E7DCEULL,
		0x9F7FF8F0B0571B8FULL,
		0x5FEE7193818BC8ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x581F13619EC7AA4BULL,
		0xF7F82757EA49DD72ULL,
		0xDCA04D266DF561DCULL,
		0xC984382526B582B2ULL,
		0x2125E88945C80590ULL,
		0xED7E1B66D7CFED12ULL,
		0xE548752590B4EC96ULL,
		0x4775A6707C8518E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B27FC49572BA4C6ULL,
		0x5CE6EF1CF70146B1ULL,
		0x8B6523E2E54807BCULL,
		0xEE91BA00DFAD5802ULL,
		0xDFA5F546C1554114ULL,
		0xAF73F654DEF0CCF4ULL,
		0x7C06B1926E33F49EULL,
		0xF77995380300E616ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCF71718479C0585ULL,
		0x9B11383AF34896C0ULL,
		0x513B294388AD5A20ULL,
		0xDAF27E2447082AB0ULL,
		0x417FF3428472C47BULL,
		0x3E0A2511F8DF201DULL,
		0x6941C3932280F7F8ULL,
		0x4FFC1138798432D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22CB44B2CC06EFD4ULL,
		0x85E7EDD64680E6E4ULL,
		0xF1D423A7C75A438CULL,
		0x19585560063B0D7FULL,
		0x02508F18841FE29BULL,
		0x5153DEF15C614351ULL,
		0xF1B5F51FB7E3CCC9ULL,
		0xBADF1184BD5EAB8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802A566265D8BB55ULL,
		0xEA0260501855FD2AULL,
		0x0409513BEB69380CULL,
		0x62572D1FE0BCF736ULL,
		0x6436C38FAD4048C1ULL,
		0x071747021E53501BULL,
		0xFD70B126CA02327EULL,
		0x0555F8765CB9F000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2A0EE50662E347FULL,
		0x9BE58D862E2AE9B9ULL,
		0xEDCAD26BDBF10B7FULL,
		0xB7012840257E1649ULL,
		0x9E19CB88D6DF99D9ULL,
		0x4A3C97EF3E0DF335ULL,
		0xF44543F8EDE19A4BULL,
		0xB589190E60A4BB8AULL
	}};
	sign = 0;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0FC8907C051D6D9ULL,
		0x6F94D1988150E506ULL,
		0x933FB52A1242CAE7ULL,
		0x3E7FE6D19062C4C7ULL,
		0xCE6BB617BF977E60ULL,
		0x242F87D1C794CE35ULL,
		0xAED117774B9D50AFULL,
		0x8F46FD147342C4C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB16AB661F0644AEFULL,
		0x2577E6CD0DA3E4C6ULL,
		0xD0D5AFEEAEB70885ULL,
		0xDC64DC3A1CE4562EULL,
		0x77276ACF75BFEDEAULL,
		0xA00F15D283EC181DULL,
		0xB41722E258AE3C31ULL,
		0x5F86D5AE5CF7F032ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F91D2A5CFED8BEAULL,
		0x4A1CEACB73AD0040ULL,
		0xC26A053B638BC262ULL,
		0x621B0A97737E6E98ULL,
		0x57444B4849D79075ULL,
		0x842071FF43A8B618ULL,
		0xFAB9F494F2EF147DULL,
		0x2FC02766164AD494ULL
	}};
	sign = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BA69B428F304FD9ULL,
		0x0A2D1596F66E7728ULL,
		0x50B4C2A0B40EE2A3ULL,
		0x71D2B83638C50BF1ULL,
		0x8C2EBB501E1499C1ULL,
		0x46E27281B41E4C49ULL,
		0x36C915045F44EF4BULL,
		0x6986A44F308B66FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBFA1690F522363BULL,
		0x63997EBBC5C40458ULL,
		0x448E78AF3332836CULL,
		0xD8C132855A9E6B24ULL,
		0x02EFA6C9796ED13AULL,
		0x47F394B4BE2B7441ULL,
		0x444982B34050BA43ULL,
		0x408F2489497C187FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FAC84B19A0E199EULL,
		0xA69396DB30AA72CFULL,
		0x0C2649F180DC5F36ULL,
		0x991185B0DE26A0CDULL,
		0x893F1486A4A5C886ULL,
		0xFEEEDDCCF5F2D808ULL,
		0xF27F92511EF43507ULL,
		0x28F77FC5E70F4E7BULL
	}};
	sign = 0;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DA2D07BEC208FC0ULL,
		0x1E37EEAA087CC33BULL,
		0x6EB8C46E86E2C5EEULL,
		0xEE9405FADC4642CDULL,
		0xC09F16952AFF630FULL,
		0x7AE176C57D8873E8ULL,
		0xC81492A2A9E30130ULL,
		0x458B07D629ECA918ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x243D9FA3C53B47CCULL,
		0x33A116A224036658ULL,
		0xF4DCF6900976C004ULL,
		0x4EBD19A501540F6DULL,
		0x9BDE74811BA2AC97ULL,
		0xF26E6C6868657413ULL,
		0xB527605D729EA99EULL,
		0x4DE67BC784DE850CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x696530D826E547F4ULL,
		0xEA96D807E4795CE3ULL,
		0x79DBCDDE7D6C05E9ULL,
		0x9FD6EC55DAF2335FULL,
		0x24C0A2140F5CB678ULL,
		0x88730A5D1522FFD5ULL,
		0x12ED324537445791ULL,
		0xF7A48C0EA50E240CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7DCDBA8955DC36ULL,
		0xC394E0E0B1A2D143ULL,
		0x72E6888A95F2275DULL,
		0xB8EA44FF2F5F687AULL,
		0x4936A31392D488D3ULL,
		0x5974D86D0D930BFBULL,
		0xF627851A2C331D80ULL,
		0xEECFE3E835342959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BAF1B39173D6E83ULL,
		0x3311150FE0375613ULL,
		0xE9E3687953046086ULL,
		0xA54CB09ED40B1A71ULL,
		0x87310382F779AB06ULL,
		0xDF1B5E2BC0F883CEULL,
		0xC3F4C39FCA55A157ULL,
		0x94DCEB2E43E59B41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13CEB28172186DB3ULL,
		0x9083CBD0D16B7B30ULL,
		0x8903201142EDC6D7ULL,
		0x139D94605B544E08ULL,
		0xC2059F909B5ADDCDULL,
		0x7A597A414C9A882CULL,
		0x3232C17A61DD7C28ULL,
		0x59F2F8B9F14E8E18ULL
	}};
	sign = 0;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4158B89FBD2C9A4FULL,
		0xD1C5241F327EB4C3ULL,
		0x3C5684E82467C02CULL,
		0xE6E66B4C043F57F2ULL,
		0x36CB3BF948AEC3EEULL,
		0x0653CFC32510ECC1ULL,
		0xC566A87099798CE5ULL,
		0xAE7C82FD4D0F75D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424F681E6D1A6251ULL,
		0x8DC8260D5182BC90ULL,
		0x2F0B022BE005BDD7ULL,
		0x8E363E9864148AC6ULL,
		0xE413F0137B3B0642ULL,
		0x16A6F874FFAA18B6ULL,
		0x1322F4DAE3DA3712ULL,
		0xFAD256ACA29E3B44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF095081501237FEULL,
		0x43FCFE11E0FBF832ULL,
		0x0D4B82BC44620255ULL,
		0x58B02CB3A02ACD2CULL,
		0x52B74BE5CD73BDACULL,
		0xEFACD74E2566D40AULL,
		0xB243B395B59F55D2ULL,
		0xB3AA2C50AA713A8FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6E0B865D6582152ULL,
		0x46199887A51C1A8AULL,
		0x4699FEBDDD06A6F3ULL,
		0xCD3004A25CDD1BE2ULL,
		0x9CAF8A3AFD5800F0ULL,
		0x82FFEA4C9CA941D4ULL,
		0x59AE77D5792C47EDULL,
		0x893A65FB7E825391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F16ADB881C21C77ULL,
		0x0DA51C4AE697CFB0ULL,
		0xBC4559580A4CEE76ULL,
		0x7EA2AEB286B8601BULL,
		0xE49E618A73C57C72ULL,
		0x64ACBCD21F73F159ULL,
		0xAD5D4E5EF36FB53FULL,
		0x633F9F1A07A20F73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97CA0AAD549604DBULL,
		0x38747C3CBE844ADAULL,
		0x8A54A565D2B9B87DULL,
		0x4E8D55EFD624BBC6ULL,
		0xB81128B08992847EULL,
		0x1E532D7A7D35507AULL,
		0xAC51297685BC92AEULL,
		0x25FAC6E176E0441DULL
	}};
	sign = 0;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x127DF9693972F326ULL,
		0xF3DAE65B77E5DDDDULL,
		0x521A9FBA59CAC3BFULL,
		0x732198697232B918ULL,
		0x8365C756382E1237ULL,
		0xD9905BFF10FFC927ULL,
		0xF5A5E5DC83FE70B3ULL,
		0x4C84DFC1E1B66169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4793714C205D4CA9ULL,
		0xEBB1F6EB8387142DULL,
		0xF5FFD07CF3053402ULL,
		0x3312FB287E17BDA4ULL,
		0x8DBEFD6FB820A34BULL,
		0xF2A46C4E8CFD2D6BULL,
		0xE0E83377244E15B9ULL,
		0xEFC807FE3A7AACB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAEA881D1915A67DULL,
		0x0828EF6FF45EC9AFULL,
		0x5C1ACF3D66C58FBDULL,
		0x400E9D40F41AFB73ULL,
		0xF5A6C9E6800D6EECULL,
		0xE6EBEFB084029BBBULL,
		0x14BDB2655FB05AF9ULL,
		0x5CBCD7C3A73BB4B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60E3E9019802DDF3ULL,
		0xA629F655ACE42843ULL,
		0x60FC0D3EDEE28227ULL,
		0x3C590B2FE4E1B651ULL,
		0x6D90EF80957FD07AULL,
		0x551E26544E4AD12EULL,
		0xC03994E14D508558ULL,
		0x9245AE7774B21DEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F7A9DE5C208051DULL,
		0xAC3C6C79B969D121ULL,
		0xAE732D08528C8613ULL,
		0x87DB47B0A5B036A7ULL,
		0x1F657ED01A217DCFULL,
		0xB72281C96D659D29ULL,
		0xB054D9C96F55935DULL,
		0xA7804F9B1D6CC06DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31694B1BD5FAD8D6ULL,
		0xF9ED89DBF37A5722ULL,
		0xB288E0368C55FC13ULL,
		0xB47DC37F3F317FA9ULL,
		0x4E2B70B07B5E52AAULL,
		0x9DFBA48AE0E53405ULL,
		0x0FE4BB17DDFAF1FAULL,
		0xEAC55EDC57455D7EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD390B68104B838F4ULL,
		0x6007B0EB17ED7081ULL,
		0x629A9941671DA222ULL,
		0x25552E69D6355C2FULL,
		0xE91363D02DABB343ULL,
		0x3E1175310BA1517EULL,
		0x89329203C3E1B256ULL,
		0x3E89F92B931F683FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3E32DEA29BE5320ULL,
		0x39A72CED86767894ULL,
		0x5D1775825E1C570EULL,
		0xB5C084507EAAFB60ULL,
		0x1EB9C34505A9DC27ULL,
		0x84B8324C31C5EF77ULL,
		0x78F10AC6608452BCULL,
		0x04B72D7D7A38EE30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FAD8896DAF9E5D4ULL,
		0x266083FD9176F7EDULL,
		0x058323BF09014B14ULL,
		0x6F94AA19578A60CFULL,
		0xCA59A08B2801D71BULL,
		0xB95942E4D9DB6207ULL,
		0x1041873D635D5F99ULL,
		0x39D2CBAE18E67A0FULL
	}};
	sign = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x199DBE5182E4EDB4ULL,
		0xB64D140E84378F8CULL,
		0x091FACCE5CAC7875ULL,
		0x3CF1CDE644AA0444ULL,
		0xE8D9C34B961F4B83ULL,
		0x34F9B041B04F52EBULL,
		0x626E76877945ADE1ULL,
		0x16C3DAA635F36485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2EA09AF1259098ULL,
		0x63C1B451CF850395ULL,
		0x330FF714785E3A73ULL,
		0x3483D3EDF6099B1BULL,
		0x1E761E4A711177A9ULL,
		0x549146DFBCC6F66EULL,
		0x92DD9630AD5B3E28ULL,
		0xA2419A34C15AF2BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E6F1DB691BF5D1CULL,
		0x528B5FBCB4B28BF6ULL,
		0xD60FB5B9E44E3E02ULL,
		0x086DF9F84EA06928ULL,
		0xCA63A501250DD3DAULL,
		0xE0686961F3885C7DULL,
		0xCF90E056CBEA6FB8ULL,
		0x74824071749871C7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE72ECA550BB28F89ULL,
		0x0D1DFBDEEB16166EULL,
		0x0BFA7B86F3108CFCULL,
		0xD517548704144742ULL,
		0xCCA1CB530E46126FULL,
		0xF68B17A1BDF90DF6ULL,
		0x04EA056B8664B706ULL,
		0x9CD2686593CB33FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2F476913B7642CULL,
		0xA7CB5906070AD2EBULL,
		0x94F52FB50B0468E2ULL,
		0x9430934EC32E8AC2ULL,
		0xCDAB8D268F785AD6ULL,
		0x20D4372C3D1A5C25ULL,
		0xD30002943B520A96ULL,
		0x08C9288FF176C1D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89FF82EBF7FB2B5DULL,
		0x6552A2D8E40B4383ULL,
		0x77054BD1E80C2419ULL,
		0x40E6C13840E5BC7FULL,
		0xFEF63E2C7ECDB799ULL,
		0xD5B6E07580DEB1D0ULL,
		0x31EA02D74B12AC70ULL,
		0x94093FD5A2547228ULL
	}};
	sign = 0;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5194430C8F561BA5ULL,
		0x982647224CAFC7F9ULL,
		0xBFEB1BD307A1C70CULL,
		0x55CF6B1F7FB36F3FULL,
		0x2BA222038901B4A2ULL,
		0x507981C503D35057ULL,
		0xEE8FDAE7CFA3FF9FULL,
		0xED28FB9350463149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A80A71F653477B5ULL,
		0x22379E68001715E3ULL,
		0x84E0441A39F2F10BULL,
		0x55346EA1C74C888BULL,
		0x17B3C290CBC25717ULL,
		0x09DDE0A3F3255291ULL,
		0x399DEA0AC813C747ULL,
		0xD8A0EB94BC197FA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7139BED2A21A3F0ULL,
		0x75EEA8BA4C98B215ULL,
		0x3B0AD7B8CDAED601ULL,
		0x009AFC7DB866E6B4ULL,
		0x13EE5F72BD3F5D8BULL,
		0x469BA12110ADFDC6ULL,
		0xB4F1F0DD07903858ULL,
		0x14880FFE942CB1A8ULL
	}};
	sign = 0;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5BADC55ED23A722ULL,
		0xC679B607F4F3A302ULL,
		0x6C3838822AC68F38ULL,
		0x4636C8C1A7D2158DULL,
		0xA2EF63D5109C4DECULL,
		0x39CA62137AA2E509ULL,
		0xBCD49A86ED6EC45EULL,
		0x81617AB7436286D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54E18B7D73AE0C0ULL,
		0x4BF453FEAA802C11ULL,
		0xEE98A9E46082ECD1ULL,
		0x2000EFD514256218ULL,
		0x05F11E61A8F143F0ULL,
		0xED082D26865A79C4ULL,
		0x474F1BA3BE4F09EFULL,
		0x44C9EBBF62A85BF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF06CC39E15E8C662ULL,
		0x7A8562094A7376F0ULL,
		0x7D9F8E9DCA43A267ULL,
		0x2635D8EC93ACB374ULL,
		0x9CFE457367AB09FCULL,
		0x4CC234ECF4486B45ULL,
		0x75857EE32F1FBA6EULL,
		0x3C978EF7E0BA2AE2ULL
	}};
	sign = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59AA99DA60B41C68ULL,
		0x7194691556C70329ULL,
		0xF9A018201B51A6BBULL,
		0x9A17B0BB8E772D30ULL,
		0xD8FB7A4ED57E4F42ULL,
		0x812C3F65A63AC4C1ULL,
		0xB3D628B0FF4BD647ULL,
		0xCACDE948B535634DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07BAAD26F0EEA05ULL,
		0xA1DCFD97C44BDB9FULL,
		0x145B3BCC28C3A729ULL,
		0xA93FC447EDAD5FBBULL,
		0xBA98C08EF598120FULL,
		0xEE2646D8E82E94A7ULL,
		0xACE3ACBBB086FFE7ULL,
		0xDBCCC1DC5DBD8477ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x992EEF07F1A53263ULL,
		0xCFB76B7D927B2789ULL,
		0xE544DC53F28DFF91ULL,
		0xF0D7EC73A0C9CD75ULL,
		0x1E62B9BFDFE63D32ULL,
		0x9305F88CBE0C301AULL,
		0x06F27BF54EC4D65FULL,
		0xEF01276C5777DED6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE8788C64AE02C75ULL,
		0xED71A9E61481570BULL,
		0x5787E3C740502B6EULL,
		0x58E84198A514176BULL,
		0x9733DB37C7CEDDE6ULL,
		0xB481B6CB4E445343ULL,
		0xA300A0E5ADAEE0B0ULL,
		0x82C5D4EFB34D6514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B4671E5D949E9F9ULL,
		0xDBC14A4D8C9F73C2ULL,
		0x04E73BDF9B0A06F1ULL,
		0xA4C5ED46B765B053ULL,
		0x173C2C56BE845808ULL,
		0xA59D490E9ABA5599ULL,
		0x8A6A76CADCAF00B8ULL,
		0x35930E937FFCD3ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x334116E07196427CULL,
		0x11B05F9887E1E349ULL,
		0x52A0A7E7A546247DULL,
		0xB4225451EDAE6718ULL,
		0x7FF7AEE1094A85DDULL,
		0x0EE46DBCB389FDAAULL,
		0x18962A1AD0FFDFF8ULL,
		0x4D32C65C33509168ULL
	}};
	sign = 0;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x427025D44857EF82ULL,
		0x7378BD416742DBBAULL,
		0xA9EF77B95810AEDBULL,
		0x29FBA760381DDD5BULL,
		0x9F73CF7180CE644FULL,
		0x7B9B7E691190D9A6ULL,
		0xCBD0251E12C2CC07ULL,
		0xBE89BDE288EBEDD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA87E0EEDC88D6589ULL,
		0x7AACAF06520A9FCAULL,
		0x1214F813FE3E522AULL,
		0x6EFE8099FC66BAC2ULL,
		0xB3DE7DDE58FAF97CULL,
		0x5B27BF056CAE5E52ULL,
		0x16F93BF1641C105DULL,
		0xAE2CE6A0BA6BF6C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99F216E67FCA89F9ULL,
		0xF8CC0E3B15383BEFULL,
		0x97DA7FA559D25CB0ULL,
		0xBAFD26C63BB72299ULL,
		0xEB95519327D36AD2ULL,
		0x2073BF63A4E27B53ULL,
		0xB4D6E92CAEA6BBAAULL,
		0x105CD741CE7FF711ULL
	}};
	sign = 0;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48DFE808EAED4F7BULL,
		0x5ADFDCFD33011303ULL,
		0x4C53534076C65E90ULL,
		0xC2035EFEC7127DABULL,
		0x4EAE2ADEB7A4992AULL,
		0x07B1CCB7B30058FDULL,
		0xCAF1E97468C5BD4CULL,
		0x1EC2C4FD62A8D590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EC09B7EAA2AE0BULL,
		0x425E952063836170ULL,
		0xBC3EF89832E3566DULL,
		0xF0E998614472F8F2ULL,
		0x28ED3346828BBFD9ULL,
		0x702F8B7085FD8795ULL,
		0x1EE1F8FB9E0A9220ULL,
		0x952E6DB03B31A4D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26F3DE51004AA170ULL,
		0x188147DCCF7DB193ULL,
		0x90145AA843E30823ULL,
		0xD119C69D829F84B8ULL,
		0x25C0F7983518D950ULL,
		0x978241472D02D168ULL,
		0xAC0FF078CABB2B2BULL,
		0x8994574D277730B9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DF9F8B5EE3ECF7EULL,
		0x3C74889D5337CDD1ULL,
		0x29E1D18453122AB5ULL,
		0x453270AA10F7FBADULL,
		0x73524332FACAFF9DULL,
		0x4DAAA2F89C73CAD5ULL,
		0x700E647318991EB0ULL,
		0x9E4EDE38D1063CB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E7B8458524FE2BULL,
		0x3977DB8C610C5206ULL,
		0x37277EAF57B3AC00ULL,
		0xA3987034B1959DFAULL,
		0xB65B63AF7FF0005DULL,
		0x3CE3CBE4381B8418ULL,
		0x3A398FCE4EDF6349ULL,
		0xF96EA39F55F86DB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B1240706919D153ULL,
		0x02FCAD10F22B7BCAULL,
		0xF2BA52D4FB5E7EB5ULL,
		0xA19A00755F625DB2ULL,
		0xBCF6DF837ADAFF3FULL,
		0x10C6D714645846BCULL,
		0x35D4D4A4C9B9BB67ULL,
		0xA4E03A997B0DCEFDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DF8330EB619CE92ULL,
		0x451EDA89D4869F87ULL,
		0xBCDCC118A47A922AULL,
		0x04030F0423E01548ULL,
		0xB6F970C99668F924ULL,
		0xBF79DF7C4E633679ULL,
		0x7A81DDA1B5F08357ULL,
		0x9BA844FE94018861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC13F3FB578705958ULL,
		0xFFDAA9EA3C00204EULL,
		0x6633431B308313BFULL,
		0xE5EF978B70513BA3ULL,
		0x26742AA19F44B17CULL,
		0xF897C71A6A0E8D7DULL,
		0x21171173A980806CULL,
		0xE687B53316FBC17AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CB8F3593DA9753AULL,
		0x4544309F98867F38ULL,
		0x56A97DFD73F77E6AULL,
		0x1E137778B38ED9A5ULL,
		0x90854627F72447A7ULL,
		0xC6E21861E454A8FCULL,
		0x596ACC2E0C7002EAULL,
		0xB5208FCB7D05C6E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1CB2DC32A18CDDFULL,
		0xD0E21CB9A407EDD5ULL,
		0x318391924C2DB725ULL,
		0xFCC51A791DAA7AB6ULL,
		0x259D0A5098E94877ULL,
		0x16FFA4C2084469FEULL,
		0x69875BD7403100DFULL,
		0x62C8D0D8ED95161CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532161A6A58C8C4CULL,
		0x6D6B41E6AF842970ULL,
		0x0FFBB5A90350A482ULL,
		0xDCF82A4DF730D9E8ULL,
		0x13E9680310B3C0A1ULL,
		0x172FDD232BC11EC8ULL,
		0xC483F5F015FB94C2ULL,
		0xD11014C3B0384448ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EA9CC1C848C4193ULL,
		0x6376DAD2F483C465ULL,
		0x2187DBE948DD12A3ULL,
		0x1FCCF02B2679A0CEULL,
		0x11B3A24D883587D6ULL,
		0xFFCFC79EDC834B36ULL,
		0xA50365E72A356C1CULL,
		0x91B8BC153D5CD1D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x712F100B7193A280ULL,
		0x1967DB8896639994ULL,
		0xB9F075AF1C8E11BEULL,
		0x68174368CB538FBCULL,
		0x376DF3CCBDE2F333ULL,
		0xCA788C4746299855ULL,
		0x24A07620C68C76A9ULL,
		0x67D4E32AC899A8A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CFC40A6B158FB4FULL,
		0x118BFA749359C4AAULL,
		0x35111529AE38DB44ULL,
		0x537D32AD33424ED8ULL,
		0xC17335AB99BA6059ULL,
		0xB9EB8C97E3CA8B26ULL,
		0xCA4AE85B5E148D3FULL,
		0x27C1A34FED91C5EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD432CF64C03AA731ULL,
		0x07DBE1140309D4E9ULL,
		0x84DF60856E55367AULL,
		0x149A10BB981140E4ULL,
		0x75FABE21242892DAULL,
		0x108CFFAF625F0D2EULL,
		0x5A558DC56877E96AULL,
		0x40133FDADB07E2BAULL
	}};
	sign = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC347D11D624041EDULL,
		0xE0E32925C59A956EULL,
		0x6BABE3898363CE79ULL,
		0xEED2CA773BA3C601ULL,
		0x686C0C593F8BE334ULL,
		0xCE066A36782E0E44ULL,
		0x7EF8527C2D80A142ULL,
		0xF239487834A9F15DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8DD8F2BA7A269CDULL,
		0x665274DD333565C0ULL,
		0x52110B8FC5187992ULL,
		0x4A443F332DD45D27ULL,
		0x07C38ABF85C37106ULL,
		0x5EF7A5B067258189ULL,
		0xBB34748BE8774A17ULL,
		0x084D7B08A9723926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA6A41F1BA9DD820ULL,
		0x7A90B44892652FADULL,
		0x199AD7F9BE4B54E7ULL,
		0xA48E8B440DCF68DAULL,
		0x60A88199B9C8722EULL,
		0x6F0EC48611088CBBULL,
		0xC3C3DDF04509572BULL,
		0xE9EBCD6F8B37B836ULL
	}};
	sign = 0;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1F4D2CB70F27F73ULL,
		0x8648896958965D3EULL,
		0x96E6AC4F8C4D3A48ULL,
		0xD13EE46F69F3EB2FULL,
		0x817D4486D34A88E2ULL,
		0xEFA29C01F3AF7005ULL,
		0x490BB15DC9E0EC16ULL,
		0x689DC028BA18829FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8D8F38BBB4FE94BULL,
		0x10EC7AC132F502F6ULL,
		0x078BA77502F14297ULL,
		0x613F3A59316A99D5ULL,
		0x12D7D5A8126AF523ULL,
		0x63C588BCC672C1A2ULL,
		0x39315C3F2A9C564EULL,
		0xA6061134DD399326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF91BDF3FB5A29628ULL,
		0x755C0EA825A15A47ULL,
		0x8F5B04DA895BF7B1ULL,
		0x6FFFAA163889515AULL,
		0x6EA56EDEC0DF93BFULL,
		0x8BDD13452D3CAE63ULL,
		0x0FDA551E9F4495C8ULL,
		0xC297AEF3DCDEEF79ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF388453A045377EULL,
		0xAEB180C6F759F991ULL,
		0x3AD2FA0EBAA65DD6ULL,
		0x4266ACD4E572EEB0ULL,
		0x877A48490A8AC251ULL,
		0x39DE03D5F3AA6A6BULL,
		0xC9733AF474BBD023ULL,
		0x5B72AA23366656C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC30AF18A857B5F9ULL,
		0x66A9D19A14F6828EULL,
		0xE921F5E652400DE2ULL,
		0x3F256CBE100F60C7ULL,
		0x3AEBD4D6728B60D0ULL,
		0xC07976F846B0B255ULL,
		0x5049F0F94573D9BCULL,
		0xD348D83BD773AE96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4307D53AF7ED8185ULL,
		0x4807AF2CE2637703ULL,
		0x51B1042868664FF4ULL,
		0x03414016D5638DE8ULL,
		0x4C8E737297FF6181ULL,
		0x79648CDDACF9B816ULL,
		0x792949FB2F47F666ULL,
		0x8829D1E75EF2A831ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC266F2FAA67D6BDAULL,
		0x1BFE902CA8971DA1ULL,
		0x1A7DC6A2F849C424ULL,
		0xFA34ADBA5BF8FAB4ULL,
		0x0AA7BB97680F40B4ULL,
		0x1C0B6D96D561AA59ULL,
		0xB6D4914D26372AE2ULL,
		0xBB840D153E558E0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A15CBA3CECBDACULL,
		0xA2E406CB5A784BF5ULL,
		0x0745D8BE8DCD2CC2ULL,
		0xB8F334CAD40157EFULL,
		0x4233FAA555C6D4DFULL,
		0xE50563B3FC319E67ULL,
		0xD2DCB4F14EFED590ULL,
		0x6F7A81AADECB9DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EC596406990AE2EULL,
		0x791A89614E1ED1ACULL,
		0x1337EDE46A7C9761ULL,
		0x414178EF87F7A2C5ULL,
		0xC873C0F212486BD5ULL,
		0x370609E2D9300BF1ULL,
		0xE3F7DC5BD7385551ULL,
		0x4C098B6A5F89F016ULL
	}};
	sign = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC58142A5B00DC53DULL,
		0x672495EF5BEE6C6EULL,
		0xB5E7EA45A1D29F60ULL,
		0xFE7FE16357ABC229ULL,
		0xC85700EE73BF029FULL,
		0xB9D39A71C45131ACULL,
		0x61C3EB550A5F8D24ULL,
		0xCBBFBEF9B7634BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125D95AD79678B6AULL,
		0x5393BD4F74D61B37ULL,
		0x851BEC8BF002EE2DULL,
		0x5784DC29904A781EULL,
		0x5D90925F65472488ULL,
		0xE8BD40ED9DCE2EC7ULL,
		0x96D10A8124261E66ULL,
		0xEFCB1E2150D7B37AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB323ACF836A639D3ULL,
		0x1390D89FE7185137ULL,
		0x30CBFDB9B1CFB133ULL,
		0xA6FB0539C7614A0BULL,
		0x6AC66E8F0E77DE17ULL,
		0xD1165984268302E5ULL,
		0xCAF2E0D3E6396EBDULL,
		0xDBF4A0D8668B9855ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB16842EB7E979D1ULL,
		0x31678AE846345ADCULL,
		0x2E2BE3470B415469ULL,
		0xFD47AD1E567DEAA1ULL,
		0x43D3FF029D7100E7ULL,
		0x77A38039C8E626C2ULL,
		0x4CC90189116DA6C3ULL,
		0x5579F1FDBD18913DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3934AB40F252E9FEULL,
		0x59AF7902651CBE4BULL,
		0x99594E7A96473A3FULL,
		0xA6461E15E453CDF4ULL,
		0x4398B89C87A50185ULL,
		0x9BAD7D29E33C8DBCULL,
		0x4D7116C726BCAEE1ULL,
		0x8F92ED57AEC9DAE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1E1D8EDC5968FD3ULL,
		0xD7B811E5E1179C91ULL,
		0x94D294CC74FA1A29ULL,
		0x57018F08722A1CACULL,
		0x003B466615CBFF62ULL,
		0xDBF6030FE5A99906ULL,
		0xFF57EAC1EAB0F7E1ULL,
		0xC5E704A60E4EB65CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF27D02ED42C2B3BDULL,
		0x73561220FC5361A8ULL,
		0x804E167364A3B322ULL,
		0x66DDC349E2CC9288ULL,
		0xDA5A818FE7D76BABULL,
		0xF1C5D137BA3C01A2ULL,
		0x957557D01F4AF62BULL,
		0xB2A603CE726378F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A4BF9DFDCEED40ULL,
		0x0A4A8470800D3629ULL,
		0x562929A711707AF6ULL,
		0x725F180981BBD5AFULL,
		0xEC686010203FD9A8ULL,
		0xBF1B8126F9D57D54ULL,
		0x25E320D07C8CA67AULL,
		0x7700DA1DEFB76204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98D8434F44F3C67DULL,
		0x690B8DB07C462B7FULL,
		0x2A24ECCC5333382CULL,
		0xF47EAB406110BCD9ULL,
		0xEDF2217FC7979202ULL,
		0x32AA5010C066844DULL,
		0x6F9236FFA2BE4FB1ULL,
		0x3BA529B082AC16F1ULL
	}};
	sign = 0;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33BF6BED93E0ED71ULL,
		0x8B765BA49834E9B9ULL,
		0xC7900240A83D6B60ULL,
		0xFD9C4E2081212DC5ULL,
		0x70A7B18A69A719BFULL,
		0x7269050BC2CE9041ULL,
		0xF6E8AD639F688765ULL,
		0x7346647C344C03C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4A7CB1744C65821ULL,
		0x0234F7CE86388CF6ULL,
		0xBEA11592494FA502ULL,
		0x6E13301B236EB07FULL,
		0xDAC236D73CC5448DULL,
		0xD275D133DAD06D20ULL,
		0xC96242A47F6BA69BULL,
		0xF87459767069041CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F17A0D64F1A9550ULL,
		0x894163D611FC5CC2ULL,
		0x08EEECAE5EEDC65EULL,
		0x8F891E055DB27D46ULL,
		0x95E57AB32CE1D532ULL,
		0x9FF333D7E7FE2320ULL,
		0x2D866ABF1FFCE0C9ULL,
		0x7AD20B05C3E2FFA9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9BDA42F0D88F905ULL,
		0x27C3B4C476A7BAA2ULL,
		0x7A9E82B0A033AFD8ULL,
		0xAC690BBEEC05B895ULL,
		0xA4E8144F313ADC93ULL,
		0xC2BD8EE9D00A111FULL,
		0xB045CC037BC577E2ULL,
		0xE782D87CB29B7B1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEEE4C7E6EC671A8ULL,
		0x0DEB90FE9F92D0AEULL,
		0xD729FC2B89BB9B6FULL,
		0xAB271D9D25186294ULL,
		0x64AE3DE077B57B87ULL,
		0x6B82709F11A093BFULL,
		0x0489EED34836F578ULL,
		0x22FFF476BCB539C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1ACF57B09EC2875DULL,
		0x19D823C5D714E9F4ULL,
		0xA374868516781469ULL,
		0x0141EE21C6ED5600ULL,
		0x4039D66EB985610CULL,
		0x573B1E4ABE697D60ULL,
		0xABBBDD30338E826AULL,
		0xC482E405F5E6415CULL
	}};
	sign = 0;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x578B65178076D2FFULL,
		0x7F851D5F214EB59CULL,
		0x9B7C9FDC5EEFD82BULL,
		0x15000ABB26C1E97BULL,
		0xBFA07C3C223BE75BULL,
		0x357C0A44558507A9ULL,
		0x0A049F8D2EF76C00ULL,
		0x259EC452B395B959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56279A6E726B7DCULL,
		0x9B11B613173E342CULL,
		0x6FDB30EC6C5D2D57ULL,
		0x300F33C9CBD55CF3ULL,
		0xBF893EFE148D1371ULL,
		0x48BDB5A642CA38A1ULL,
		0xA68019BCBA1D5549ULL,
		0xF2C7FF2DBBF11C36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB228EB7099501B23ULL,
		0xE473674C0A10816FULL,
		0x2BA16EEFF292AAD3ULL,
		0xE4F0D6F15AEC8C88ULL,
		0x00173D3E0DAED3E9ULL,
		0xECBE549E12BACF08ULL,
		0x638485D074DA16B6ULL,
		0x32D6C524F7A49D22ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x941E9877464CE067ULL,
		0xE3FCAD88DBDA082DULL,
		0x7C17202D94D1480FULL,
		0x51CE503F9047F634ULL,
		0x8BEBB8D568196485ULL,
		0xC47134832FD75CA8ULL,
		0x4D1C2DD5FCD79834ULL,
		0xA2D3082752547DDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92CB67B3637A6732ULL,
		0x379868BC472B60FBULL,
		0x2590A33A441BF4DBULL,
		0x5066BAC480D3E6A9ULL,
		0x7E559DA3FFE91AA2ULL,
		0x314506745F0BD60DULL,
		0x74FE239A4D823A19ULL,
		0x109AE90E3DCEE136ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x015330C3E2D27935ULL,
		0xAC6444CC94AEA732ULL,
		0x56867CF350B55334ULL,
		0x0167957B0F740F8BULL,
		0x0D961B31683049E3ULL,
		0x932C2E0ED0CB869BULL,
		0xD81E0A3BAF555E1BULL,
		0x92381F1914859CA8ULL
	}};
	sign = 0;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFAF92B56FC2F844ULL,
		0xC6D0BEB2EFC8E1C7ULL,
		0x54676D0D3EA525CDULL,
		0xBF1E887C5539BFC2ULL,
		0x5F50F8BE7D97E7DEULL,
		0xC08A7525C6FAFD70ULL,
		0xCC504783F17E979CULL,
		0x8D834AF847A459EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CB4CE693A80D65DULL,
		0x63B664290469EBB4ULL,
		0x744E9507EF85A9FFULL,
		0x6FA504C3587D792BULL,
		0xF1BC6704A6F05E49ULL,
		0xA775A58ECACE6825ULL,
		0xA9D1518919E2B021ULL,
		0x0CFFC87A3485C6DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2FAC44C354221E7ULL,
		0x631A5A89EB5EF613ULL,
		0xE018D8054F1F7BCEULL,
		0x4F7983B8FCBC4696ULL,
		0x6D9491B9D6A78995ULL,
		0x1914CF96FC2C954AULL,
		0x227EF5FAD79BE77BULL,
		0x8083827E131E930CULL
	}};
	sign = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6869495340E81620ULL,
		0x27A13A46042D3628ULL,
		0x0F591BA6495AD619ULL,
		0xD5970C28C0D594C9ULL,
		0xFFF1BE9495C267E0ULL,
		0x5064FE887ADAC611ULL,
		0x8014B972CBF58B43ULL,
		0xB6368133B024A38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5887FCC68B799416ULL,
		0xE03CAC582495085BULL,
		0xC04254C20F0E545DULL,
		0x07909849C7B31DD4ULL,
		0x1C1DE70EAE817578ULL,
		0x823BE4863ADB794EULL,
		0xC4E171685123D160ULL,
		0xB8422E4BA02D492FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FE14C8CB56E820AULL,
		0x47648DEDDF982DCDULL,
		0x4F16C6E43A4C81BBULL,
		0xCE0673DEF92276F4ULL,
		0xE3D3D785E740F268ULL,
		0xCE291A023FFF4CC3ULL,
		0xBB33480A7AD1B9E2ULL,
		0xFDF452E80FF75A5FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA33F68AF9DD8913EULL,
		0xBB04645C7C4D62BEULL,
		0x7E2C3A3B0E6A4C52ULL,
		0x13D1DD6A6C51CA1AULL,
		0xE9C31159C86181BDULL,
		0xF664B0CEDA84B162ULL,
		0x773BB543AB6C76A3ULL,
		0x83BE6A1DD7E90487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4ADE5BA3DDAE216ULL,
		0xBB16601018C8E913ULL,
		0x623EB20B8F2E8117ULL,
		0x651D8D9AA2503D79ULL,
		0x6231F32CC70BF0F9ULL,
		0xBC89971EC0638501ULL,
		0x3BBD0773E0F81041ULL,
		0x003DAF4A6C776CDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE9182F55FFDAF28ULL,
		0xFFEE044C638479AAULL,
		0x1BED882F7F3BCB3AULL,
		0xAEB44FCFCA018CA1ULL,
		0x87911E2D015590C3ULL,
		0x39DB19B01A212C61ULL,
		0x3B7EADCFCA746662ULL,
		0x8380BAD36B7197AAULL
	}};
	sign = 0;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12879DA572281BDBULL,
		0x3ED36CE67057CA5EULL,
		0x365C0147F2FA0077ULL,
		0xE3B25EA20EE27ED2ULL,
		0x37658BE1FCF74C4DULL,
		0x8C78A5AC659CCDC6ULL,
		0x2B8AA7B4511FC24AULL,
		0x9F3E4D90101D13C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC312FB261FF8D30ULL,
		0x1C2D07CB55DB987EULL,
		0xFF7A8D5142848EFCULL,
		0x05DDFC878D75ABE8ULL,
		0x5F7C6D6C3D69549AULL,
		0x7892FB6653A5AD1BULL,
		0x676DBD1BBB2F6601ULL,
		0x9AF2DD6C70BDE967ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66566DF310288EABULL,
		0x22A6651B1A7C31DFULL,
		0x36E173F6B075717BULL,
		0xDDD4621A816CD2E9ULL,
		0xD7E91E75BF8DF7B3ULL,
		0x13E5AA4611F720AAULL,
		0xC41CEA9895F05C49ULL,
		0x044B70239F5F2A5BULL
	}};
	sign = 0;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C0ECBCD73A51DF3ULL,
		0xCD4E711E4401AC39ULL,
		0x9CC258057477A556ULL,
		0x4D8027C9CECB686BULL,
		0x2AA362C96560B1F8ULL,
		0x3A78395B02154215ULL,
		0x03E4D42936656AC4ULL,
		0x8D4E2C78F94B6DE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0281F762D7E9721ULL,
		0x80D169555CA0D574ULL,
		0x15F8BCB5FE861DD3ULL,
		0x513FA419B70C227DULL,
		0x5FB3DA9A69FC50A4ULL,
		0xA88EE5828DB1FD38ULL,
		0x619CB6CA32A8DD10ULL,
		0x0C49061F5B7F48B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BE6AC57462686D2ULL,
		0x4C7D07C8E760D6C4ULL,
		0x86C99B4F75F18783ULL,
		0xFC4083B017BF45EEULL,
		0xCAEF882EFB646153ULL,
		0x91E953D8746344DCULL,
		0xA2481D5F03BC8DB3ULL,
		0x810526599DCC252AULL
	}};
	sign = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12380600F8F2F7FAULL,
		0x1B3C51DBF947A979ULL,
		0x85C101B0BDC9BFB4ULL,
		0x4435990DE52F231CULL,
		0x84BCD422B840C906ULL,
		0x91B94E44D4FCEDAAULL,
		0x548DDF41089CC153ULL,
		0x4DC6C0465FCFFA43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC305D9AE85FEBE4BULL,
		0xC8B4ACA22CD2D266ULL,
		0x9F6FA1A94CF8C85EULL,
		0x0DB9A3B8E20CFB1FULL,
		0xB0D35DCB637F35F7ULL,
		0x2E98B768F5F3D267ULL,
		0xAFF0AD1FC8767788ULL,
		0x50A3C80D5D7484DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F322C5272F439AFULL,
		0x5287A539CC74D712ULL,
		0xE651600770D0F755ULL,
		0x367BF555032227FCULL,
		0xD3E9765754C1930FULL,
		0x632096DBDF091B42ULL,
		0xA49D3221402649CBULL,
		0xFD22F839025B7564ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F25AE6DFDE1F419ULL,
		0x1475EBAF241051DFULL,
		0x750028C99867E6ABULL,
		0xA5EDD31F2902A106ULL,
		0x630A29D1ADB79D92ULL,
		0x0A65FD555662C08BULL,
		0x7A239AB703308EB1ULL,
		0x6E687E3E65E4FE2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75457638A3C205B3ULL,
		0x0905A63A03083451ULL,
		0xAB51100BF1D4CD0DULL,
		0xF4F38BCE436D626CULL,
		0x338AA6482E9C98EBULL,
		0xC7958814A9AC2948ULL,
		0x88D7090695ECBF5FULL,
		0x89A2E50FC85B4486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9E038355A1FEE66ULL,
		0x0B70457521081D8DULL,
		0xC9AF18BDA693199EULL,
		0xB0FA4750E5953E99ULL,
		0x2F7F83897F1B04A6ULL,
		0x42D07540ACB69743ULL,
		0xF14C91B06D43CF51ULL,
		0xE4C5992E9D89B9A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF928D507E837E79FULL,
		0x469860F0CC1F8B38ULL,
		0x0A69A3BD8EA7681CULL,
		0xB76DE4B9EB6D12EDULL,
		0xE94AC38B4FA5C1C1ULL,
		0x56F748D8FF034C0FULL,
		0xF72201ECCD0ADF09ULL,
		0x5C2C5ABA7463499CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5236838800D237CAULL,
		0xE662EF6BFDAEEC5BULL,
		0x91624842793AAE23ULL,
		0x450108F22E36A2BFULL,
		0xFDB9143C1F088054ULL,
		0xB7E6390948974623ULL,
		0xFF908832A369D97CULL,
		0xE26A810FC5C0D58CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6F2517FE765AFD5ULL,
		0x60357184CE709EDDULL,
		0x79075B7B156CB9F8ULL,
		0x726CDBC7BD36702DULL,
		0xEB91AF4F309D416DULL,
		0x9F110FCFB66C05EBULL,
		0xF79179BA29A1058CULL,
		0x79C1D9AAAEA2740FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8483D2A8A50CF07BULL,
		0x682B81BC255AEDD1ULL,
		0xA28BEBCCFEF2D983ULL,
		0x6DD504A8E7C450AFULL,
		0x13AD8CFD7D920D66ULL,
		0x29962928367429AFULL,
		0xB8DEDD5E8246DCDDULL,
		0x2E4D369A4BC320FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD941EBD2113E1CDEULL,
		0x515A5D8EB3DA6D86ULL,
		0xC9411A535AB87838ULL,
		0x510480345F127EFBULL,
		0x49EAD2EC97AB8FD0ULL,
		0x0DB4D56D7CFB32C1ULL,
		0x75E0A97BE6945A84ULL,
		0x6EEC028885D5B7CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB41E6D693CED39DULL,
		0x16D1242D7180804AULL,
		0xD94AD179A43A614BULL,
		0x1CD0847488B1D1B3ULL,
		0xC9C2BA10E5E67D96ULL,
		0x1BE153BAB978F6EDULL,
		0x42FE33E29BB28259ULL,
		0xBF613411C5ED692FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80BC94CD703D1698ULL,
		0x7673BABE9576B6ABULL,
		0x1D649014AC6D843EULL,
		0xB8C1010A4ECBF237ULL,
		0x2F7ED3B83BA94A74ULL,
		0xCC1DED6EE613185CULL,
		0x8F6E246C5495D7E6ULL,
		0xF2DC20A8639398B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4864622943113DDBULL,
		0xFA35FEC902DC02F8ULL,
		0x8CDD407FE9961EC6ULL,
		0x7B25EE0D44393FCBULL,
		0x9664AF830C2BDAEBULL,
		0xEF888C6EA14CB73AULL,
		0x9551E201D5D6BFD3ULL,
		0x4DDBBCC519A47292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x385832A42D2BD8BDULL,
		0x7C3DBBF5929AB3B3ULL,
		0x90874F94C2D76577ULL,
		0x3D9B12FD0A92B26BULL,
		0x991A24352F7D6F89ULL,
		0xDC95610044C66121ULL,
		0xFA1C426A7EBF1812ULL,
		0xA50063E349EF2624ULL
	}};
	sign = 0;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2C821DEDFCE1FF1ULL,
		0xF018B28267BA601FULL,
		0x77B415E84D875CEEULL,
		0x78C4C32D0781F639ULL,
		0x1CB1DA909F92A6FAULL,
		0x5C148708C861AD30ULL,
		0xCE282D1F8F26E541ULL,
		0x86F1D48FBF436D31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D0FC53588E74B2ULL,
		0x70FE184694931707ULL,
		0x9AE3B9462A9C58C4ULL,
		0x4D1DF1A3943A9FE1ULL,
		0x3410AEB10130C3C8ULL,
		0xF19FE061C357763DULL,
		0xE549F88F07E80254ULL,
		0xFC00147513E4A204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0F7258B873FAB3FULL,
		0x7F1A9A3BD3274917ULL,
		0xDCD05CA222EB042AULL,
		0x2BA6D18973475657ULL,
		0xE8A12BDF9E61E332ULL,
		0x6A74A6A7050A36F2ULL,
		0xE8DE3490873EE2ECULL,
		0x8AF1C01AAB5ECB2CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA195077D3758EE1CULL,
		0xA1CB7951840FE782ULL,
		0x3138E75C7AD5502CULL,
		0x667BD6251D0E5C3CULL,
		0x5C9741404F0498C2ULL,
		0x62C4B92875D5B32FULL,
		0x134EDB6669484DCFULL,
		0x6E5AECA943CE4902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA82E5632293F876EULL,
		0x982D4AEEB5E2A8B3ULL,
		0x772EB9329B33C0EEULL,
		0x34E95A9A2429B179ULL,
		0xD411403305DBFCEBULL,
		0x62A96F4F169525B9ULL,
		0xB4C6562AB9585415ULL,
		0x59044E397EE669ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF966B14B0E1966AEULL,
		0x099E2E62CE2D3ECEULL,
		0xBA0A2E29DFA18F3EULL,
		0x31927B8AF8E4AAC2ULL,
		0x8886010D49289BD7ULL,
		0x001B49D95F408D75ULL,
		0x5E88853BAFEFF9BAULL,
		0x15569E6FC4E7DF56ULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA696F4F382183A82ULL,
		0x1832045209750CE9ULL,
		0x50362B9286666329ULL,
		0xE1EBA1EBB22D1E2DULL,
		0x06D066DFBA72D308ULL,
		0x9FD68A3438D117CDULL,
		0x2C7A17280C2C72ECULL,
		0x157AAA7C7FAB25FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC8FFE99D47417DDULL,
		0xD725613E06A04845ULL,
		0xEFD7598687DCB34FULL,
		0x033E9DDE50938D9CULL,
		0x85104E84833FF649ULL,
		0xC0969614CFE1686CULL,
		0x994DAF05AC9BCA0BULL,
		0xC331D300F5379741ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA06F659ADA422A5ULL,
		0x410CA31402D4C4A3ULL,
		0x605ED20BFE89AFD9ULL,
		0xDEAD040D61999090ULL,
		0x81C0185B3732DCBFULL,
		0xDF3FF41F68EFAF60ULL,
		0x932C68225F90A8E0ULL,
		0x5248D77B8A738EB8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC40765BEC2DECBCULL,
		0x6ADE44C9FD3FAA36ULL,
		0xECA64CF42DA4C822ULL,
		0x8B6A28C4D6B5CFFBULL,
		0xBBCD3926402BDE97ULL,
		0xADE23AB9D5D142F1ULL,
		0x8EF054C82FE21578ULL,
		0x5B8C1A4B23FBE452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F08882E8FD2EFCULL,
		0x0BC95DE489C05D85ULL,
		0x8549A7DE1E5C5C91ULL,
		0xEC97C009295F56CBULL,
		0xD365859A05E86497ULL,
		0x2E366D8DCC3BCA1DULL,
		0x37566D0BEA15C0FBULL,
		0xFFA242B08BEEB4D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD34FEDD90330BDC0ULL,
		0x5F14E6E5737F4CB0ULL,
		0x675CA5160F486B91ULL,
		0x9ED268BBAD567930ULL,
		0xE867B38C3A4379FFULL,
		0x7FABCD2C099578D3ULL,
		0x5799E7BC45CC547DULL,
		0x5BE9D79A980D2F80ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4F4512B42E3DD04ULL,
		0x7C78F19294F72DAEULL,
		0xAEB651E27D97493EULL,
		0xCB7CF05C3A0A0516ULL,
		0x4510CA4257542906ULL,
		0xFE92EFAB52D900B5ULL,
		0xF48C378CD201DE1DULL,
		0x51DAC8FB2A7FE92AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227A0B0DDA528909ULL,
		0x00F6370F2D285CC1ULL,
		0xE92945EEFB0E7FBFULL,
		0x389BD7AD72D4CFF0ULL,
		0xDE33E06803FB5328ULL,
		0xDBA6408A5990A8F5ULL,
		0x762FC2FBD7A573F4ULL,
		0x186AB265CC66499AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB27A461D689153FBULL,
		0x7B82BA8367CED0EDULL,
		0xC58D0BF38288C97FULL,
		0x92E118AEC7353525ULL,
		0x66DCE9DA5358D5DEULL,
		0x22ECAF20F94857BFULL,
		0x7E5C7490FA5C6A29ULL,
		0x397016955E199F90ULL
	}};
	sign = 0;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x078E668A675D87FBULL,
		0xCF4928762F97C981ULL,
		0x451F5F60618C5CBDULL,
		0xC93C756315F93907ULL,
		0xBC2E8F85F0E59252ULL,
		0x24E233D6A3CAD85FULL,
		0xD682306F1579A4D5ULL,
		0x7FACC723BD0B3AA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D621215AD916DEULL,
		0x47F60552B2EF8407ULL,
		0x3DFE5CC07C2F6712ULL,
		0xAB0965762442DCE2ULL,
		0x79A91BAC35476E0AULL,
		0x29C5289D8F1E7F3AULL,
		0xD435FF50470D5830ULL,
		0x26610A31ADA4C87FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FB845690C84711DULL,
		0x875323237CA84579ULL,
		0x0721029FE55CF5ABULL,
		0x1E330FECF1B65C25ULL,
		0x428573D9BB9E2448ULL,
		0xFB1D0B3914AC5925ULL,
		0x024C311ECE6C4CA4ULL,
		0x594BBCF20F667222ULL
	}};
	sign = 0;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E704ED33EDB9C63ULL,
		0x632EBDB4E209FF99ULL,
		0xB4CD1EDEAB3DDAF9ULL,
		0xBDB79DDF010AA226ULL,
		0xEC134702EED4950BULL,
		0xCB310FFB2FB2BF81ULL,
		0x0F64AF82586ACB03ULL,
		0xC132B67C566F8087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AA7F4F62698D531ULL,
		0x53025A7CDA9AB923ULL,
		0x395C7D9B33D4170EULL,
		0xBA9E772A2430701AULL,
		0x3F3E838D1129D1B1ULL,
		0x2510D5A5208FE30DULL,
		0x5DF56F093BADA531ULL,
		0x17AC4B488953555FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3C859DD1842C732ULL,
		0x102C6338076F4675ULL,
		0x7B70A1437769C3EBULL,
		0x031926B4DCDA320CULL,
		0xACD4C375DDAAC35AULL,
		0xA6203A560F22DC74ULL,
		0xB16F40791CBD25D2ULL,
		0xA9866B33CD1C2B27ULL
	}};
	sign = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA59576BB4F08637CULL,
		0x76A1896A2FB70C9CULL,
		0x10503C8CEED14721ULL,
		0x240DED398406612FULL,
		0x7714F437170B0F62ULL,
		0xF4BB67839DC2F293ULL,
		0x749DE5304374B390ULL,
		0x1EDD80CE9CF15915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A274F4F6558A2F9ULL,
		0x7DE02B6857D99953ULL,
		0xAC342CC2EE8B168DULL,
		0xA4890CA27C87952CULL,
		0x1E57D157538102BDULL,
		0x9461CD4BA3FFAD56ULL,
		0x961711FA68AE6351ULL,
		0x76CC7C5751FFC3A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B6E276BE9AFC083ULL,
		0xF8C15E01D7DD7349ULL,
		0x641C0FCA00463093ULL,
		0x7F84E097077ECC02ULL,
		0x58BD22DFC38A0CA4ULL,
		0x60599A37F9C3453DULL,
		0xDE86D335DAC6503FULL,
		0xA81104774AF19571ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F93ED28AC15FF27ULL,
		0x2EE9B619A9CDDCADULL,
		0x6DB66B6FEEB6C5B8ULL,
		0xFFDFEEC788369C4BULL,
		0xDF2A89354DF935E2ULL,
		0x33614BBCFC256336ULL,
		0xAB552D6A46DA5ADDULL,
		0x3F635DBFAD2A0E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECCD696F87702998ULL,
		0x75869F54E6D9F9F2ULL,
		0xB8606B8101307EA8ULL,
		0xDCDABBDC84CCABB9ULL,
		0x5F4F714E5ABF83C8ULL,
		0x06004FDDCB23772EULL,
		0x9EE5638068E154C6ULL,
		0x04D1E8C8C3B306C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42C683B924A5D58FULL,
		0xB96316C4C2F3E2BAULL,
		0xB555FFEEED86470FULL,
		0x230532EB0369F091ULL,
		0x7FDB17E6F339B21AULL,
		0x2D60FBDF3101EC08ULL,
		0x0C6FC9E9DDF90617ULL,
		0x3A9174F6E9770754ULL
	}};
	sign = 0;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB60415BDF238D13ULL,
		0x0188BDC8339432B0ULL,
		0x641E24F488A66A99ULL,
		0x76094CD7F38E7C93ULL,
		0x32718F1D84EE0776ULL,
		0x382D9B63D1CDD4F9ULL,
		0x1E028D52B60C5CFAULL,
		0xC3485DEF51BE5273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7F792FE674882CBULL,
		0x33BA7755837989FFULL,
		0xB22F91208E234F38ULL,
		0x8C56947976665673ULL,
		0x93B23FFAA20D65C5ULL,
		0x5D42C4F72F2D00D0ULL,
		0x7879414B45D29476ULL,
		0x4553540E68F16CC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE368AE5D77DB0A48ULL,
		0xCDCE4672B01AA8B0ULL,
		0xB1EE93D3FA831B60ULL,
		0xE9B2B85E7D28261FULL,
		0x9EBF4F22E2E0A1B0ULL,
		0xDAEAD66CA2A0D428ULL,
		0xA5894C077039C883ULL,
		0x7DF509E0E8CCE5B1ULL
	}};
	sign = 0;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95DF86E591B34DD1ULL,
		0xDB8A2DDAB041C0BEULL,
		0xBB164126A2C82CF3ULL,
		0x36767D2586D96D94ULL,
		0xDBAA113EAB3A0866ULL,
		0x1D66A6A8383923B0ULL,
		0x9C533DE7191AF12DULL,
		0x644DD5577BA14E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3022C6BC97CC8B63ULL,
		0x43B957CACBB21B5AULL,
		0xE9BFAAE466523F12ULL,
		0xC2116ECA0299B256ULL,
		0xC7E908F5BF0EE4B2ULL,
		0xF5D23C8FDAB3BC88ULL,
		0xE072E74C7D189F7EULL,
		0xEAB92BB468F207E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65BCC028F9E6C26EULL,
		0x97D0D60FE48FA564ULL,
		0xD15696423C75EDE1ULL,
		0x74650E5B843FBB3DULL,
		0x13C10848EC2B23B3ULL,
		0x27946A185D856728ULL,
		0xBBE0569A9C0251AEULL,
		0x7994A9A312AF469EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E1566EA35971F2ULL,
		0x991670FF3A5ED96DULL,
		0x8537668BE6395B71ULL,
		0x26F9C489B524131AULL,
		0x92CBE8DA44076E43ULL,
		0x4875845A59D136F3ULL,
		0xBBDEC36697EB9F9DULL,
		0xB75A59263D6FEBB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B620EFBFC8B8DBDULL,
		0x99521B64B1F805B4ULL,
		0x06E62A7CDCC79F33ULL,
		0x89A826CD83C64BC5ULL,
		0x22DEC8D3D9CD614AULL,
		0x1B5B673C47492E7BULL,
		0x07795AB1C1B2E7C7ULL,
		0xECF25391D49F5ABDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A7F4772A6CDE435ULL,
		0xFFC4559A8866D3B9ULL,
		0x7E513C0F0971BC3DULL,
		0x9D519DBC315DC755ULL,
		0x6FED20066A3A0CF8ULL,
		0x2D1A1D1E12880878ULL,
		0xB46568B4D638B7D6ULL,
		0xCA68059468D090FCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97B795F7D2F8DE8FULL,
		0x4EC03CBBB1C17F6CULL,
		0x29014EDBEC0A2829ULL,
		0x8F723E16A3CAEC78ULL,
		0x487C90AA9B0DF534ULL,
		0xEC5969CBA5C06A0BULL,
		0xA65912DBD4CF7473ULL,
		0xBAEE2D9106C79DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC0EDF683F57DF9ULL,
		0xA706278DBC8EC78BULL,
		0x154CCBDA8A59FD63ULL,
		0x1F574F3D27F63FF5ULL,
		0xD19C838588F76BD7ULL,
		0x37F671A96F693BB7ULL,
		0x40B6637BF314EF61ULL,
		0xCB0BC056F7951FE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07F6A8014F036096ULL,
		0xA7BA152DF532B7E1ULL,
		0x13B4830161B02AC5ULL,
		0x701AEED97BD4AC83ULL,
		0x76E00D251216895DULL,
		0xB462F82236572E53ULL,
		0x65A2AF5FE1BA8512ULL,
		0xEFE26D3A0F327DD7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5EB48E86DC7ABBAULL,
		0xD2A6DD12CDD055F4ULL,
		0x64BC172E529BD027ULL,
		0x3634F5126B59E818ULL,
		0xDE8635BC430512B5ULL,
		0xFCA90571B50EBDD0ULL,
		0xE3DC263E9CBDB949ULL,
		0xC7F428E94951F3C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E590056ED3513B8ULL,
		0x75C6F84AAD14BD13ULL,
		0x874957FB15DE64BBULL,
		0xB0E99ED8ECE26790ULL,
		0x18892F353F8FF05FULL,
		0xEC1E2812F91CF821ULL,
		0xA8CE044467C8CBD8ULL,
		0xB4FDD55AACFA4DC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1792489180929802ULL,
		0x5CDFE4C820BB98E1ULL,
		0xDD72BF333CBD6B6CULL,
		0x854B56397E778087ULL,
		0xC5FD068703752255ULL,
		0x108ADD5EBBF1C5AFULL,
		0x3B0E21FA34F4ED71ULL,
		0x12F6538E9C57A5FFULL
	}};
	sign = 0;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x783E1D2A6D79FEDDULL,
		0x718F61648651668EULL,
		0xC74E5CFDCF236033ULL,
		0xC3597DEE1DD35E1DULL,
		0x21766710BCE979D0ULL,
		0x1184DFD5AA4F3470ULL,
		0x3BA76CBFA04E4ABEULL,
		0xBC514C73818E9908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E6D236FD46F3882ULL,
		0xF7E57FB5E056D1E6ULL,
		0x6B912EAA4CF7FE9BULL,
		0x6641D7FDE5471C08ULL,
		0xC4EED23C2CDCC277ULL,
		0xE8FA10D90E984EFAULL,
		0x8809E83A96F4DB87ULL,
		0xDAFE4D5FD16FD853ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49D0F9BA990AC65BULL,
		0x79A9E1AEA5FA94A8ULL,
		0x5BBD2E53822B6197ULL,
		0x5D17A5F0388C4215ULL,
		0x5C8794D4900CB759ULL,
		0x288ACEFC9BB6E575ULL,
		0xB39D848509596F36ULL,
		0xE152FF13B01EC0B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA68D56F84F69835ULL,
		0xE55BD8C4FF42C5FAULL,
		0x065926CF4157FC69ULL,
		0x6283382146FF9CBEULL,
		0x22BEF0EDB8BD6E5BULL,
		0x64E08D6738C8B0E5ULL,
		0x4B4092A778052E06ULL,
		0xAD9728B7CA9BB290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DCBCBC131416774ULL,
		0x5A8FD23E17805917ULL,
		0x692C0B652D650381ULL,
		0x852E9910A5434F57ULL,
		0x0B1186075DAEFBF2ULL,
		0x9710CADD9474F258ULL,
		0x643BAF8A993C7A44ULL,
		0x764DE045CD1D26C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC9D09AE53B530C1ULL,
		0x8ACC0686E7C26CE3ULL,
		0x9D2D1B6A13F2F8E8ULL,
		0xDD549F10A1BC4D66ULL,
		0x17AD6AE65B0E7268ULL,
		0xCDCFC289A453BE8DULL,
		0xE704E31CDEC8B3C1ULL,
		0x37494871FD7E8BC7ULL
	}};
	sign = 0;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x985B0EBA7DDA43F2ULL,
		0x3F6244F67EB0CDE4ULL,
		0xF5C062F78AAFDD87ULL,
		0xB7C97DE47D2D4518ULL,
		0x7C9FE34F65095964ULL,
		0x5C3375531D5A03F2ULL,
		0xAF4C54113453A285ULL,
		0xA2D1D38478824472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A4EB950D4B5BB19ULL,
		0x3A3BA844D6513582ULL,
		0xE8800A9ACAB224FCULL,
		0x3DC182D4C076F797ULL,
		0xEE16984874148802ULL,
		0xD6623E3B3131B99BULL,
		0xC3B5B0B41F37DE80ULL,
		0xE64EDAEE6FFD7789ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E0C5569A92488D9ULL,
		0x05269CB1A85F9862ULL,
		0x0D40585CBFFDB88BULL,
		0x7A07FB0FBCB64D81ULL,
		0x8E894B06F0F4D162ULL,
		0x85D13717EC284A56ULL,
		0xEB96A35D151BC404ULL,
		0xBC82F8960884CCE8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA79A7A83CC4493CFULL,
		0x1400D8821229E320ULL,
		0x35232CB6D7B0A4F3ULL,
		0xE786CEA2CA74C9FCULL,
		0x754BFAF35E1B6C05ULL,
		0x80CF93C8E2317E4CULL,
		0x0BDC6037AAA8F65CULL,
		0x843523B3C7DC898CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094AF4F28B0D74BDULL,
		0xA558D9196187747EULL,
		0x9B0F6E5AD89E44A4ULL,
		0xDE531893587C8B95ULL,
		0xBE7056BC1E9983EFULL,
		0xB99E8A3008D4E9D4ULL,
		0x9A0CE1693D2E37B0ULL,
		0x5DBE4A1625792328ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E4F859141371F12ULL,
		0x6EA7FF68B0A26EA2ULL,
		0x9A13BE5BFF12604EULL,
		0x0933B60F71F83E66ULL,
		0xB6DBA4373F81E816ULL,
		0xC7310998D95C9477ULL,
		0x71CF7ECE6D7ABEABULL,
		0x2676D99DA2636663ULL
	}};
	sign = 0;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE11C8C69C50FB51BULL,
		0x076A4A35C02DA4B4ULL,
		0xE918B4E3F284163FULL,
		0x599D784C043EF586ULL,
		0x2DB6FE01F1073E4CULL,
		0x36D2FE6FF71B9BF1ULL,
		0xD967F103364BBB3BULL,
		0x850DCEE635C22E27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5801C699924F7EBAULL,
		0x2C19D202CC1C09AFULL,
		0xD29379A55BE9383FULL,
		0xBEE1D53C397CE872ULL,
		0x7DE445E8212DA334ULL,
		0xFEDF992F3084DFF2ULL,
		0x82E33EB1F8136532ULL,
		0x0E6D277F0BFD9D93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x891AC5D032C03661ULL,
		0xDB507832F4119B05ULL,
		0x16853B3E969ADDFFULL,
		0x9ABBA30FCAC20D14ULL,
		0xAFD2B819CFD99B17ULL,
		0x37F36540C696BBFEULL,
		0x5684B2513E385608ULL,
		0x76A0A76729C49094ULL
	}};
	sign = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFA06C9596C89F8CULL,
		0xB9DBDED68CD1BABBULL,
		0x7E611FEF4D5697A2ULL,
		0xBF125D168ECC1093ULL,
		0xF6C11B87B1552943ULL,
		0x4DAA7907BB30DC89ULL,
		0x6F6E7E1D68F10E63ULL,
		0xE5EA6CBBE172F198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE3312718AA39F1AULL,
		0xFA5250DE95F94016ULL,
		0xDA5A7192F001D744ULL,
		0x627DC265FA531B56ULL,
		0xF3EC8D677D135213ULL,
		0xB57BF2B90DFBF799ULL,
		0x90EF682F9F304F6DULL,
		0x56EFF3171EEAEDB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE16D5A240C250072ULL,
		0xBF898DF7F6D87AA4ULL,
		0xA406AE5C5D54C05DULL,
		0x5C949AB09478F53CULL,
		0x02D48E203441D730ULL,
		0x982E864EAD34E4F0ULL,
		0xDE7F15EDC9C0BEF5ULL,
		0x8EFA79A4C28803E0ULL
	}};
	sign = 0;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B9B647D72372408ULL,
		0x595E6224E9E8F692ULL,
		0x6B99ED9868DA1892ULL,
		0x089D132DCFB6C76DULL,
		0x905A4DAC86B13337ULL,
		0x25806343609FDA72ULL,
		0xC26E3B7FAFA84910ULL,
		0x7051831727B65B4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C600A7E68F21AFULL,
		0x8369AB2331D1D531ULL,
		0x9E54E1BC412CD3CBULL,
		0xD6267104B425632FULL,
		0x016E9F5E8A141397ULL,
		0xC28174DB91185761ULL,
		0xE44D8FCD61B113E1ULL,
		0x57E56903F2D639FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82D563D58BA80259ULL,
		0xD5F4B701B8172161ULL,
		0xCD450BDC27AD44C6ULL,
		0x3276A2291B91643DULL,
		0x8EEBAE4DFC9D1F9FULL,
		0x62FEEE67CF878311ULL,
		0xDE20ABB24DF7352EULL,
		0x186C1A1334E0214CULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6554B8C4E55F057CULL,
		0xFE1821944247928FULL,
		0xD53392AF912D6952ULL,
		0x3751E5A1D9D388A3ULL,
		0x189CCA4069947559ULL,
		0x1F9889A4103CAB85ULL,
		0xA67FDDBC2C4CE85AULL,
		0x1ED6BC53D88F08E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B9CD89FAE8CA797ULL,
		0x82F8207FBF855829ULL,
		0x1CA68B40010EA7F1ULL,
		0x92DE07922496C3E1ULL,
		0xD709C0270FB17CD7ULL,
		0xCDB39B1F8920EA85ULL,
		0x84542008031CE05BULL,
		0xF9FEE125DBA5031FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9B7E02536D25DE5ULL,
		0x7B20011482C23A65ULL,
		0xB88D076F901EC161ULL,
		0xA473DE0FB53CC4C2ULL,
		0x41930A1959E2F881ULL,
		0x51E4EE84871BC0FFULL,
		0x222BBDB4293007FEULL,
		0x24D7DB2DFCEA05C3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x429B545100159929ULL,
		0x0704DD957A11D2DFULL,
		0x65954393D84F541FULL,
		0xFF9ECC514672DAC6ULL,
		0xAEBFBB2DA1F348C5ULL,
		0x69C6169AF1E3B6E8ULL,
		0xB56F92C3D67F5CF6ULL,
		0x6F4E8DCFDEEEF64BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x222FEB08C028E218ULL,
		0xA56C865391271524ULL,
		0x923245999B2580D4ULL,
		0x77782241CBF5F6EFULL,
		0x4B055B0D65700391ULL,
		0x777A0B4E87E81448ULL,
		0x639DC5BD14E33208ULL,
		0xDEBD244CABECEBB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x206B69483FECB711ULL,
		0x61985741E8EABDBBULL,
		0xD362FDFA3D29D34AULL,
		0x8826AA0F7A7CE3D6ULL,
		0x63BA60203C834534ULL,
		0xF24C0B4C69FBA2A0ULL,
		0x51D1CD06C19C2AEDULL,
		0x9091698333020A95ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBACA59875316D49EULL,
		0x52A7242E90FE33E2ULL,
		0x03278C86DDE6FD93ULL,
		0x07FD402C8E0D0972ULL,
		0xE0DEFA2D2B02FD26ULL,
		0xF9EB4BAA7D427C46ULL,
		0xCA155575F1D1C5F3ULL,
		0xDF32C6CA29E3D7C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB417F7DE34F4903DULL,
		0x4C2DD79B3C797721ULL,
		0x7EEB7F66BEDE9493ULL,
		0xA17634A432421E92ULL,
		0xF94A5319C7ECF80BULL,
		0xAD949B252FFE1AD5ULL,
		0x610CC447BBAC54F8ULL,
		0x5E99D4656A147E20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06B261A91E224461ULL,
		0x06794C935484BCC1ULL,
		0x843C0D201F086900ULL,
		0x66870B885BCAEADFULL,
		0xE794A7136316051AULL,
		0x4C56B0854D446170ULL,
		0x6908912E362570FBULL,
		0x8098F264BFCF59A2ULL
	}};
	sign = 0;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD81931750CFB1327ULL,
		0x4F56CEB5276E68F6ULL,
		0x446AEE52F82DBBBCULL,
		0x28A0475C1608A14CULL,
		0xC52D446BC82C544EULL,
		0x5D533FD0A10A09B9ULL,
		0x1EF87CFF0C7D824FULL,
		0x4E2509695D0FC347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FA653A0460CEDFEULL,
		0x093196947A352DA8ULL,
		0x05FA1A54FB0E46B0ULL,
		0xCD097B7DB5D7B7ACULL,
		0x6C9F22F22156E442ULL,
		0xC5F2F0793246D228ULL,
		0x2CB932FEA8D80031ULL,
		0x73D569730B42FAE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8872DDD4C6EE2529ULL,
		0x46253820AD393B4EULL,
		0x3E70D3FDFD1F750CULL,
		0x5B96CBDE6030E9A0ULL,
		0x588E2179A6D5700BULL,
		0x97604F576EC33791ULL,
		0xF23F4A0063A5821DULL,
		0xDA4F9FF651CCC863ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x490E142297CF1E3AULL,
		0x649E0533803BABA9ULL,
		0xE8C0B8F635810818ULL,
		0x4EE3FC4BB5C9AC47ULL,
		0xB4993FD85522BDC7ULL,
		0xC2601FE58B46E48CULL,
		0x5AB48491DC8B1220ULL,
		0x3D34F0073C55E013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB35439E04834654ULL,
		0x9EA4881B2CF01EAFULL,
		0xC83040965AD9D3D0ULL,
		0x5F4B96811781FC74ULL,
		0xD183647285DE06BCULL,
		0xD52141B2302E05D4ULL,
		0xD781BCF4D7BFD8DAULL,
		0x9297C1519EEACE3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DD8D084934BD7E6ULL,
		0xC5F97D18534B8CF9ULL,
		0x2090785FDAA73447ULL,
		0xEF9865CA9E47AFD3ULL,
		0xE315DB65CF44B70AULL,
		0xED3EDE335B18DEB7ULL,
		0x8332C79D04CB3945ULL,
		0xAA9D2EB59D6B11D8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBA4764E4FC21E5FULL,
		0x2044E312234B2668ULL,
		0x9901138D672F0E50ULL,
		0xEC9E09EDBBB06683ULL,
		0x1DE75D07158B86FDULL,
		0x1DDDA30CDA17E72EULL,
		0x94510C145E249084ULL,
		0xBC8FFBEAF891AE91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A2CB1D10CBBB9BULL,
		0x24F40F857E7565F4ULL,
		0x85236DB754BAD1D6ULL,
		0xEA3E7C9B76288D5DULL,
		0x76F5DF0741965F18ULL,
		0x2C906695A00483A4ULL,
		0x3516BBBF57C57DA6ULL,
		0x07DF7D4180294011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A01AB313EF662C4ULL,
		0xFB50D38CA4D5C074ULL,
		0x13DDA5D612743C79ULL,
		0x025F8D524587D926ULL,
		0xA6F17DFFD3F527E5ULL,
		0xF14D3C773A136389ULL,
		0x5F3A5055065F12DDULL,
		0xB4B07EA978686E80ULL
	}};
	sign = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB005091EBD1FB430ULL,
		0x6DA1DCBA4E843E4CULL,
		0xD2101C2AA1E83CC6ULL,
		0x769874254FB54017ULL,
		0x80568B48BB7A0241ULL,
		0xFDA79886BF542B7FULL,
		0xB6ED7100671302C8ULL,
		0x28DA8A5D6BCF3922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x211D94096EB10767ULL,
		0x8D73611A486F1B09ULL,
		0x49B650C2A5C51366ULL,
		0x2EED7E7527A5F3C1ULL,
		0x9D70EAA55F91463BULL,
		0x7B2CA7E59B184DB0ULL,
		0x9DCFE6760A3E86DCULL,
		0x3B0A106D15F9D1F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EE775154E6EACC9ULL,
		0xE02E7BA006152343ULL,
		0x8859CB67FC23295FULL,
		0x47AAF5B0280F4C56ULL,
		0xE2E5A0A35BE8BC06ULL,
		0x827AF0A1243BDDCEULL,
		0x191D8A8A5CD47BECULL,
		0xEDD079F055D5672CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71143D64A2A1F711ULL,
		0xE4E40360D20CF16AULL,
		0xF9EC0CE974C70F65ULL,
		0x291C21642230BD22ULL,
		0x2C34BBE01CBEC38BULL,
		0xFB1C1E4DEA5EC08CULL,
		0x83EBE86B17E247C3ULL,
		0xA98CD5CE1768D72FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x015A14FD0F2059A3ULL,
		0x6A719EF0E048B5A1ULL,
		0xD9D67D8587E270F0ULL,
		0x91E0A1AC7966163BULL,
		0x52300E8D1B09DE62ULL,
		0x1E2CE90520E8B9ABULL,
		0x316AE29987D6A5F9ULL,
		0x3811121DB88708C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FBA286793819D6EULL,
		0x7A72646FF1C43BC9ULL,
		0x20158F63ECE49E75ULL,
		0x973B7FB7A8CAA6E7ULL,
		0xDA04AD5301B4E528ULL,
		0xDCEF3548C97606E0ULL,
		0x528105D1900BA1CAULL,
		0x717BC3B05EE1CE6AULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99B47A02BDCA4C67ULL,
		0x8AAA21DE724A679CULL,
		0xC45F75701AD1011FULL,
		0xC98572074B11196FULL,
		0xF0B2163B731CDB73ULL,
		0x4D6DA4AA5F711130ULL,
		0x2C31F2EB031B9FE7ULL,
		0x0C8E469D9E2C0804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2612C2EA165C0F46ULL,
		0xCF54D3A7DC9235EDULL,
		0xD719AA3A23C1510BULL,
		0x299F4067A4F39268ULL,
		0xED9E042A75C5CFC7ULL,
		0xA48AE5D322D0EEDAULL,
		0x67689CDDCEC2EBC5ULL,
		0xED84AA500F6FE269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A1B718A76E3D21ULL,
		0xBB554E3695B831AFULL,
		0xED45CB35F70FB013ULL,
		0x9FE6319FA61D8706ULL,
		0x03141210FD570BACULL,
		0xA8E2BED73CA02256ULL,
		0xC4C9560D3458B421ULL,
		0x1F099C4D8EBC259AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77C2A5E63E0B9A82ULL,
		0x6CCEE9AB0B70FBADULL,
		0xBB3909221ADDB907ULL,
		0xFCC7EC23576B4EB3ULL,
		0x9E681430A61F8DC6ULL,
		0x52AAAF502E67C33EULL,
		0xA5D4114CB951D7E6ULL,
		0x876E3DCE2FF3B221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8808E8C513B28317ULL,
		0x4095219A2BCA2960ULL,
		0xA2BD7B79A1FAF58FULL,
		0x1498846A02A99A28ULL,
		0x68544CDDFB3CA027ULL,
		0xA17DD0159E3DC195ULL,
		0x2481D2FB583349CFULL,
		0x9E2481156295AE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFB9BD212A59176BULL,
		0x2C39C810DFA6D24CULL,
		0x187B8DA878E2C378ULL,
		0xE82F67B954C1B48BULL,
		0x3613C752AAE2ED9FULL,
		0xB12CDF3A902A01A9ULL,
		0x81523E51611E8E16ULL,
		0xE949BCB8CD5E0384ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE05FE088465DFCCULL,
		0xBA72EA0469B68B36ULL,
		0xCA122B333BC14D21ULL,
		0x74C75F5A1FE3D10BULL,
		0x5F8E64B926235ABBULL,
		0x892D671B10E58138ULL,
		0xE2ABCA1C5645618FULL,
		0x10B0096D719909F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E65FA5A5DCFB0BFULL,
		0x694E5232EF88830EULL,
		0xFC184EE6DC5AD1D2ULL,
		0xDBDDFABF1AED394FULL,
		0x8E7BE43A1C5E856EULL,
		0x1A3ECF719A8F07FBULL,
		0x668E081CB5372D37ULL,
		0x0F39C64B52D249EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FA003AE26962F0DULL,
		0x512497D17A2E0828ULL,
		0xCDF9DC4C5F667B4FULL,
		0x98E9649B04F697BBULL,
		0xD112807F09C4D54CULL,
		0x6EEE97A97656793CULL,
		0x7C1DC1FFA10E3458ULL,
		0x017643221EC6C007ULL
	}};
	sign = 0;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x988F8244AA2A75D9ULL,
		0x2BFC838C934A923BULL,
		0xF3D7791FD0BA554BULL,
		0x708F10678A0077A9ULL,
		0x97640D9AC9C1468EULL,
		0xF33641D91587C1B8ULL,
		0xC34B9207A1175690ULL,
		0xD23F0C61D3FF1281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869DDDE17CA55B5CULL,
		0xEF5E9EA3832632D7ULL,
		0x0C1DDE737F7149CFULL,
		0x725645C9767E1EEBULL,
		0x9ACA93AF9B71A541ULL,
		0x7F7C3BEE6341306EULL,
		0xAECBB726ED477467ULL,
		0x8F9592A386DC1CC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11F1A4632D851A7DULL,
		0x3C9DE4E910245F64ULL,
		0xE7B99AAC51490B7BULL,
		0xFE38CA9E138258BEULL,
		0xFC9979EB2E4FA14CULL,
		0x73BA05EAB2469149ULL,
		0x147FDAE0B3CFE229ULL,
		0x42A979BE4D22F5BAULL
	}};
	sign = 0;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC50D8668BE9D4553ULL,
		0x738C50AA8498DA8FULL,
		0xFF0FC264E300E733ULL,
		0x5567901C7A60146AULL,
		0x9A4F144F3812CA82ULL,
		0x5F8820A107938AADULL,
		0xA540038C61C8BDBEULL,
		0x285FEA523B17BA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267AAB6F7740894BULL,
		0x5CA65DBD388B05A8ULL,
		0x66816274EBD6A697ULL,
		0xD5AE6266234EE4F7ULL,
		0xADED2C1D8E8CFCF3ULL,
		0xF7979FC740F356F2ULL,
		0x47399E1EBCF3492DULL,
		0x185CACCC90F981FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E92DAF9475CBC08ULL,
		0x16E5F2ED4C0DD4E7ULL,
		0x988E5FEFF72A409CULL,
		0x7FB92DB657112F73ULL,
		0xEC61E831A985CD8EULL,
		0x67F080D9C6A033BAULL,
		0x5E06656DA4D57490ULL,
		0x10033D85AA1E3889ULL
	}};
	sign = 0;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04DC4915DE80FD69ULL,
		0xDB38E7A38EA33A71ULL,
		0x4AB3D9AD0684AF19ULL,
		0xD9BC16736A3DD662ULL,
		0x0A71F781DB8E0E0EULL,
		0xBF7E70DD030665F1ULL,
		0x9851D4BA28FB9D36ULL,
		0x9ACA213A1CED306DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9C516330CE7A32ULL,
		0x83A5C73CE2BB2C8CULL,
		0x67356356532D6F69ULL,
		0x62869F8CE49AEB60ULL,
		0x7C86AFA2F684C6E6ULL,
		0x125539C001E00A59ULL,
		0x78B0B8C1A4A5992BULL,
		0xB98D56A26C8C822DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE83FF7B2ADB28337ULL,
		0x57932066ABE80DE4ULL,
		0xE37E7656B3573FB0ULL,
		0x773576E685A2EB01ULL,
		0x8DEB47DEE5094728ULL,
		0xAD29371D01265B97ULL,
		0x1FA11BF88456040BULL,
		0xE13CCA97B060AE40ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BD1388E48F43BA1ULL,
		0x45BAABF252D0ED15ULL,
		0x08645533E3C358C6ULL,
		0xE9118F5561854AD5ULL,
		0x0723AE84A424C93AULL,
		0xC56AFB3B58BA2EC1ULL,
		0xBCB11E30382791EFULL,
		0x423388BCCCE24D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB708861379E2BEF6ULL,
		0x8F531A6054E68683ULL,
		0x8090347E4CC16998ULL,
		0x653FE1D4895FDEF9ULL,
		0xF7721EEC0ABC7A22ULL,
		0x6EA6508156ABC1D8ULL,
		0x3FE05289CB6BB2F3ULL,
		0x53348F92E472660AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74C8B27ACF117CABULL,
		0xB6679191FDEA6691ULL,
		0x87D420B59701EF2DULL,
		0x83D1AD80D8256BDBULL,
		0x0FB18F9899684F18ULL,
		0x56C4AABA020E6CE8ULL,
		0x7CD0CBA66CBBDEFCULL,
		0xEEFEF929E86FE786ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B7578FB73122C6FULL,
		0x50176838484338A5ULL,
		0x22B170E70C1FBEFCULL,
		0xBD3DD6EE4DCE6A9CULL,
		0x27CC8D7307D54534ULL,
		0xC32C6A9985562C22ULL,
		0xEED096E3E1C33342ULL,
		0xA764D3179CEF9C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40EF71A87BE262A4ULL,
		0xE66ECB4CA5CC628CULL,
		0xA315FAB5F3E1CFA0ULL,
		0x9FA95659B1E81220ULL,
		0x2754F4A82BBBFBCBULL,
		0xEDD6BA3877AB079EULL,
		0x6AD7496F7B5820FBULL,
		0x13196A0C8C72967BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA860752F72FC9CBULL,
		0x69A89CEBA276D618ULL,
		0x7F9B7631183DEF5BULL,
		0x1D9480949BE6587BULL,
		0x007798CADC194969ULL,
		0xD555B0610DAB2484ULL,
		0x83F94D74666B1246ULL,
		0x944B690B107D05B9ULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA06B5A673D45D906ULL,
		0xDBBC9A6E7A49C644ULL,
		0x788B1C5F816CED08ULL,
		0xE036A090C0A3E1BAULL,
		0x251B7F9F491B413AULL,
		0xD3F14549DB6A576AULL,
		0xEB947AF941B9EDF8ULL,
		0xD3721B4241F3F97AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA078AA9F3B4C60ULL,
		0x3587BA557C207F2AULL,
		0x254550C71318555AULL,
		0x6377B023F111922EULL,
		0xCD46824104D77155ULL,
		0xD50EADF6C0BA4906ULL,
		0xF209BEF39084108DULL,
		0xAC0924DC357F9ECEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84CAE1BC9E0A8CA6ULL,
		0xA634E018FE29471AULL,
		0x5345CB986E5497AEULL,
		0x7CBEF06CCF924F8CULL,
		0x57D4FD5E4443CFE5ULL,
		0xFEE297531AB00E63ULL,
		0xF98ABC05B135DD6AULL,
		0x2768F6660C745AABULL
	}};
	sign = 0;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FA984864D9D24B0ULL,
		0x6ABA6259878CFFB4ULL,
		0x3921C54572C60FF8ULL,
		0xCC28D8A44496DCB6ULL,
		0x2AFDE165E4D6098AULL,
		0x976243B9C73C84E8ULL,
		0xEA38293936F204EBULL,
		0x454635D04B22FCEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91BABCFB3F74AF95ULL,
		0x0C3E2E3196DDF8A6ULL,
		0xA971166979084E7AULL,
		0x4922E6CE88BCB2EEULL,
		0xEBCB982D1B25C9F2ULL,
		0x717321CAE983FA5EULL,
		0x292AEBB98E2DA74CULL,
		0x0FB8B1CDEAE45CAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DEEC78B0E28751BULL,
		0x5E7C3427F0AF070DULL,
		0x8FB0AEDBF9BDC17EULL,
		0x8305F1D5BBDA29C7ULL,
		0x3F324938C9B03F98ULL,
		0x25EF21EEDDB88A89ULL,
		0xC10D3D7FA8C45D9FULL,
		0x358D8402603EA03CULL
	}};
	sign = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47A9734E1FA70AA1ULL,
		0xD98E18DBF2CADE92ULL,
		0x4A93462C69A409C5ULL,
		0x15F4B7737D1B9281ULL,
		0xE0BB5BFDE4344129ULL,
		0xB7F4B05A95E19F0FULL,
		0x6AC65F675F849CA8ULL,
		0xB8381890C0C09772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1969D2647721484ULL,
		0x48717E3BFB5C00C0ULL,
		0xD5EAA86D02245AF0ULL,
		0xED4DE0CDCB505FA5ULL,
		0xE1033A1700415070ULL,
		0xF156677C7FDC5B7AULL,
		0x712215E6ADD137D2ULL,
		0xE1142F3C0EB95D97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8612D627D834F61DULL,
		0x911C9A9FF76EDDD1ULL,
		0x74A89DBF677FAED5ULL,
		0x28A6D6A5B1CB32DBULL,
		0xFFB821E6E3F2F0B8ULL,
		0xC69E48DE16054394ULL,
		0xF9A44980B1B364D5ULL,
		0xD723E954B20739DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB80473BAD55930AULL,
		0x439CAE9A242F21F1ULL,
		0x364E8DE0CC07CF7EULL,
		0x0F46802B5C267846ULL,
		0x32328364F5943B49ULL,
		0x067ED4D6D7F4FB0CULL,
		0x78AF120EEA34E6BEULL,
		0xF22AFADADD835797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x724EB9154679FA83ULL,
		0x8AD874E1EA820425ULL,
		0x91A5E5483A2B274AULL,
		0x5C942490F8BE6888ULL,
		0xD00AEF6336AC298CULL,
		0xBE8AF1166B9FCF02ULL,
		0x86813D07313AD9F9ULL,
		0x970DDD81A6B87AB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59318E2666DB9887ULL,
		0xB8C439B839AD1DCCULL,
		0xA4A8A89891DCA833ULL,
		0xB2B25B9A63680FBDULL,
		0x62279401BEE811BCULL,
		0x47F3E3C06C552C09ULL,
		0xF22DD507B8FA0CC4ULL,
		0x5B1D1D5936CADCE0ULL
	}};
	sign = 0;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1384BF8E64C3E9DCULL,
		0x5F4C370A699F75D5ULL,
		0xD46B78A1453D2719ULL,
		0x7B1A63232BC6A34EULL,
		0x1C216B8AC326587AULL,
		0x2C9AB3CC7E93D741ULL,
		0x273E5ECDBA4EBE40ULL,
		0x3345CB06A8774E32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B83EB5BF3E171EDULL,
		0xACEF3875BBE08713ULL,
		0xEB741FD2A439EFB1ULL,
		0x24F71BCAEB381C09ULL,
		0xA16ACE1DDB2571DAULL,
		0x42AEF2511D8F9EFBULL,
		0x551B039FB338F2C8ULL,
		0x96C5F83AC9C09462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD800D43270E277EFULL,
		0xB25CFE94ADBEEEC1ULL,
		0xE8F758CEA1033767ULL,
		0x56234758408E8744ULL,
		0x7AB69D6CE800E6A0ULL,
		0xE9EBC17B61043845ULL,
		0xD2235B2E0715CB77ULL,
		0x9C7FD2CBDEB6B9CFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE11823506771671ULL,
		0x31CC06E850117B41ULL,
		0x8AC9E8D326D2BB4DULL,
		0x1B587AC69469C589ULL,
		0x0A05266C04C583FDULL,
		0x6E4EF97154108F5DULL,
		0x636531D0F704FDE9ULL,
		0xB1D7323755540E05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90AFD1648D594490ULL,
		0x724C34A1B4812C93ULL,
		0x7F51D01FFF6863ECULL,
		0x831E8D55CF462B05ULL,
		0x27BC5403CA94963BULL,
		0xC90FF7CD2B663CAAULL,
		0x8A0BA1E44DCB2AF3ULL,
		0x63339665BFCE5DD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D61B0D0791DD1E1ULL,
		0xBF7FD2469B904EAEULL,
		0x0B7818B3276A5760ULL,
		0x9839ED70C5239A84ULL,
		0xE248D2683A30EDC1ULL,
		0xA53F01A428AA52B2ULL,
		0xD9598FECA939D2F5ULL,
		0x4EA39BD19585B02CULL
	}};
	sign = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC89629A512AA753FULL,
		0x96DE018E4EB99BF0ULL,
		0xF93DC832D1A5C721ULL,
		0x2B707A964B027CC1ULL,
		0xD66ED928C641DAF7ULL,
		0x84457C19A8DF9BB6ULL,
		0x3B6D38BEBDE611B2ULL,
		0x342AAA744238FBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D1FA2DD617B2E2ULL,
		0x34B9FE696875D663ULL,
		0xC70ECC9206684FADULL,
		0x7A693AE971BE404BULL,
		0x568167C73E9B2F46ULL,
		0xAE3E9B4B42240131ULL,
		0xCC95C25337B56839ULL,
		0xC9794F0D16F63180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64C42F773C92C25DULL,
		0x62240324E643C58DULL,
		0x322EFBA0CB3D7774ULL,
		0xB1073FACD9443C76ULL,
		0x7FED716187A6ABB0ULL,
		0xD606E0CE66BB9A85ULL,
		0x6ED7766B8630A978ULL,
		0x6AB15B672B42CA7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26EE9947EF1BAD31ULL,
		0x1004D2AF740A58EDULL,
		0xE9243BB35454227DULL,
		0xE1B773BC6F773E83ULL,
		0x0A1EB00982FC3E21ULL,
		0x3CB3BDDAE26EA1C4ULL,
		0x6BBAFECE00799E2FULL,
		0x6BF42ACF157AAFA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ABA92F27C14B120ULL,
		0x68FFAF2DD925C794ULL,
		0xD4F9F8C6A3992647ULL,
		0x9FD5F6A7E32024C5ULL,
		0xFA1FC68358E32E18ULL,
		0x005AA27748CF057AULL,
		0xB2E3E393A231DD82ULL,
		0x6E50D182C2715245ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C3406557306FC11ULL,
		0xA70523819AE49158ULL,
		0x142A42ECB0BAFC35ULL,
		0x41E17D148C5719BEULL,
		0x0FFEE9862A191009ULL,
		0x3C591B63999F9C49ULL,
		0xB8D71B3A5E47C0ADULL,
		0xFDA3594C53095D62ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39FC06AEDC40AC41ULL,
		0x721745289F051346ULL,
		0xE14B7FCFCC4A78FAULL,
		0xE85EBF327DEBD3E4ULL,
		0x9BF16F09C13457C9ULL,
		0xF1A6970CDB4B8EC8ULL,
		0x0D5477FBD8858938ULL,
		0x33F84ABE05333D9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EE68B0FE70ED0AEULL,
		0xBA0F41C68791C56DULL,
		0x914EE4B5EE1368B7ULL,
		0x4208C4B5141ED495ULL,
		0x8167108DA855A69FULL,
		0x6A912210D5B82F15ULL,
		0x07C604D598E95065ULL,
		0xA8C2396367A4DE5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B157B9EF531DB93ULL,
		0xB808036217734DD9ULL,
		0x4FFC9B19DE371042ULL,
		0xA655FA7D69CCFF4FULL,
		0x1A8A5E7C18DEB12AULL,
		0x871574FC05935FB3ULL,
		0x058E73263F9C38D3ULL,
		0x8B36115A9D8E5F43ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA4B1CB8B3C114B0ULL,
		0x84E9A7479DFEBA00ULL,
		0x939B9B6D37580184ULL,
		0xF4E87468B90C26F1ULL,
		0x298D4E7FA5ADB03EULL,
		0x77063147141D18D8ULL,
		0x7626E67A527BC5F9ULL,
		0x2DFC304D1663DEADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE3E0632E2065F51ULL,
		0x12B326AADA3B4230ULL,
		0xC87D0C3CB2EDBC2FULL,
		0x17764C2B62D8D5D9ULL,
		0xD28A730618E96E8AULL,
		0x2BD4435A255758FCULL,
		0xD500612CEB0B9A08ULL,
		0x7E7C48D57CC33CECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC0D1685D1BAB55FULL,
		0x7236809CC3C377CFULL,
		0xCB1E8F30846A4555ULL,
		0xDD72283D56335117ULL,
		0x5702DB798CC441B4ULL,
		0x4B31EDECEEC5BFDBULL,
		0xA126854D67702BF1ULL,
		0xAF7FE77799A0A1C0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E40B9A0965826D6ULL,
		0x9D77F28051EB66E9ULL,
		0x10580CB1ADA27624ULL,
		0x8EB222FCE08B4D38ULL,
		0x9862F425C0E88AF5ULL,
		0x83E08574E32C7B6FULL,
		0x480016B51F7409F7ULL,
		0x67EDB31DF38F3A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98957C66D1AA95D6ULL,
		0xDB0894BC6BD92083ULL,
		0xF854E68E41CC883CULL,
		0x4F62A403F6041687ULL,
		0x78E8C41917BE85F8ULL,
		0x3C9126DE41FDC646ULL,
		0x86A1553EC4610A71ULL,
		0xAAE8EAF83FC83299ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05AB3D39C4AD9100ULL,
		0xC26F5DC3E6124666ULL,
		0x180326236BD5EDE7ULL,
		0x3F4F7EF8EA8736B0ULL,
		0x1F7A300CA92A04FDULL,
		0x474F5E96A12EB529ULL,
		0xC15EC1765B12FF86ULL,
		0xBD04C825B3C707DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35D254757F5BD4ADULL,
		0xBE3D62AEC78BC7DFULL,
		0xCBEE41F83956398BULL,
		0xCBB3C0EA79A1095BULL,
		0xAB214AB67A697E61ULL,
		0x2EFBF542FF4714F3ULL,
		0x0BFEB52113460FF2ULL,
		0xCC26F710B0843E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7989064A76A75D5CULL,
		0x677E4A96DC9DAC4AULL,
		0x92959512D46D4B53ULL,
		0xC02D2D271374AE20ULL,
		0x0BB19E5D9CFA32FAULL,
		0x7912FE871DD24772ULL,
		0x536D0E0DACBEBD12ULL,
		0x3438C22058936EC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC494E2B08B47751ULL,
		0x56BF1817EAEE1B94ULL,
		0x3958ACE564E8EE38ULL,
		0x0B8693C3662C5B3BULL,
		0x9F6FAC58DD6F4B67ULL,
		0xB5E8F6BBE174CD81ULL,
		0xB891A713668752DFULL,
		0x97EE34F057F0CFBEULL
	}};
	sign = 0;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E29B8BC4676EE3AULL,
		0xE9E1DDA98E8C47D8ULL,
		0x73C7FB1E6D82042FULL,
		0xCB7544FF4D0E6991ULL,
		0xB8E771541995A2E2ULL,
		0x569C1358F81CED66ULL,
		0x28630C18CFC8345CULL,
		0x08A14880C527223AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4955DCB4C56341DAULL,
		0x12BE05F859345543ULL,
		0x4B2913C48295EA55ULL,
		0xD5405E4F534C44A1ULL,
		0x0AAEF7EC9B15985BULL,
		0x53EDF575DA9DBA48ULL,
		0xDC1088D990D79CCCULL,
		0xFDDE19CB26B83223ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4D3DC078113AC60ULL,
		0xD723D7B13557F294ULL,
		0x289EE759EAEC19DAULL,
		0xF634E6AFF9C224F0ULL,
		0xAE3879677E800A86ULL,
		0x02AE1DE31D7F331EULL,
		0x4C52833F3EF09790ULL,
		0x0AC32EB59E6EF016ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2D737D7BBCB0C7EULL,
		0x3BC94DDFF91C65F1ULL,
		0x9EBF4230083210AEULL,
		0xB329A8F633BB3971ULL,
		0x5C608E941737E8D4ULL,
		0x3F3DCEC03AB49242ULL,
		0xD7B9537316E7856EULL,
		0xABC3FE11EBD5C4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20800A774E7F8F7EULL,
		0xCB5C9551BA97CF97ULL,
		0x03CFEE7D4FA86561ULL,
		0xDD2A696DC4125BB6ULL,
		0xC8FCCCDB9A15B6F9ULL,
		0x677B53F8C7EBE321ULL,
		0x3203263851866794ULL,
		0xFFC3F8C20F74C5F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2572D606D4B7D00ULL,
		0x706CB88E3E84965AULL,
		0x9AEF53B2B889AB4CULL,
		0xD5FF3F886FA8DDBBULL,
		0x9363C1B87D2231DAULL,
		0xD7C27AC772C8AF20ULL,
		0xA5B62D3AC5611DD9ULL,
		0xAC00054FDC60FF01ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77294C81D3FD63A8ULL,
		0x53BFC07ACBC3869AULL,
		0x23D47AA9C4553450ULL,
		0x80C76A2536D82D3CULL,
		0x42BCF15D9E90AC8CULL,
		0x54A3970B07675377ULL,
		0x991E30BD8DBCD4FEULL,
		0xEEAAFEF2993E373BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C025FB189BDCBCULL,
		0xDE57050B3AE3D3BAULL,
		0x13BA62AE09B96847ULL,
		0x941CAC5924ACFE52ULL,
		0xA77FC3FEB1861031ULL,
		0x76405AD3244E7682ULL,
		0xC96A7EE5E5A0D00FULL,
		0x3FF1B0C1FEBE3839ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11692686BB6186ECULL,
		0x7568BB6F90DFB2E0ULL,
		0x101A17FBBA9BCC08ULL,
		0xECAABDCC122B2EEAULL,
		0x9B3D2D5EED0A9C5AULL,
		0xDE633C37E318DCF4ULL,
		0xCFB3B1D7A81C04EEULL,
		0xAEB94E309A7FFF01ULL
	}};
	sign = 0;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03276E9F9B49D313ULL,
		0xA7B43D75D4CD25D6ULL,
		0xE120853CF95A5074ULL,
		0x58680C35A6A309ABULL,
		0xBEA38FA097935DB7ULL,
		0x5748984D88FC9942ULL,
		0xE823C0AA31947B93ULL,
		0x81E4171AD10D1605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F2E9F33F3D1D7DULL,
		0x474F1ECE15345569ULL,
		0x89402A69C12DD2A7ULL,
		0x8C4CE6AA2D05D7E6ULL,
		0x3B6D6AAD5ADC7A3FULL,
		0xBBA88186B30346DFULL,
		0x0F93D3BFEF6FFE28ULL,
		0x1C9AEABD7D17E693ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B3484AC5C0CB596ULL,
		0x60651EA7BF98D06CULL,
		0x57E05AD3382C7DCDULL,
		0xCC1B258B799D31C5ULL,
		0x833624F33CB6E377ULL,
		0x9BA016C6D5F95263ULL,
		0xD88FECEA42247D6AULL,
		0x65492C5D53F52F72ULL
	}};
	sign = 0;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D1B01B1A8E8B76FULL,
		0x5AC87843C4362214ULL,
		0xC0E2D255B824D0C9ULL,
		0xB0B7CE9EA02831F8ULL,
		0x049C9B7202B3B05DULL,
		0xB550234984C3B1F3ULL,
		0xBA319132770FEA37ULL,
		0x4FB662E77E6E72B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930BF212701ACB64ULL,
		0xBC5A339A81D6DFF8ULL,
		0x98A978EBFAC586CCULL,
		0xB21E6C6CB2681B92ULL,
		0xDEC784462468A8F7ULL,
		0x87AB1797A81B0CF1ULL,
		0xA2F3627747E3868BULL,
		0xBEEC9431C5011B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA0F0F9F38CDEC0BULL,
		0x9E6E44A9425F421BULL,
		0x28395969BD5F49FCULL,
		0xFE996231EDC01666ULL,
		0x25D5172BDE4B0765ULL,
		0x2DA50BB1DCA8A501ULL,
		0x173E2EBB2F2C63ACULL,
		0x90C9CEB5B96D5785ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F568298C25F5ED9ULL,
		0x11A4D278DCB3C6CCULL,
		0x3F5F05E7DA33C478ULL,
		0xE48B680D701A3644ULL,
		0x4DF69E7EF5D36D52ULL,
		0x99D2443A89101DB7ULL,
		0x8E96B84FB333B4C7ULL,
		0x2EA6A104618BC487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23F53AFA3433594DULL,
		0xD609FCEC5FAFC543ULL,
		0x26A162CE8660CD87ULL,
		0xF0252DD6FD23F6B7ULL,
		0x762DE67325F9820AULL,
		0xF77E0BBB1EE2385AULL,
		0xC5B125488BB52540ULL,
		0xF54177FEE0B10487ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B61479E8E2C058CULL,
		0x3B9AD58C7D040189ULL,
		0x18BDA31953D2F6F0ULL,
		0xF4663A3672F63F8DULL,
		0xD7C8B80BCFD9EB47ULL,
		0xA254387F6A2DE55CULL,
		0xC8E59307277E8F86ULL,
		0x3965290580DABFFFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF76725EF92BC84D8ULL,
		0xBF8EA485B861CAC9ULL,
		0xA278DC3DB8D66999ULL,
		0x8BA4FD78F9EB5E9FULL,
		0x8E00C20A7644E643ULL,
		0x0A6C8A3435E547A2ULL,
		0x28A14B016148FF9DULL,
		0x732F077D2A1ECC14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD90ABCFE258AD966ULL,
		0xBFF9387F3FAA58ADULL,
		0x8D81DD3ABE93BB69ULL,
		0x3428142BA96D18CBULL,
		0x1797012A866BF26DULL,
		0x19DDDAAA8172D190ULL,
		0x90C10D38353967DDULL,
		0x95D89865C37449B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E5C68F16D31AB72ULL,
		0xFF956C0678B7721CULL,
		0x14F6FF02FA42AE2FULL,
		0x577CE94D507E45D4ULL,
		0x7669C0DFEFD8F3D6ULL,
		0xF08EAF89B4727612ULL,
		0x97E03DC92C0F97BFULL,
		0xDD566F1766AA8263ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5023D9330793788ULL,
		0x602D9F496A456C5DULL,
		0x003E6FD9F0977E2BULL,
		0x3C6954CE4A49015AULL,
		0x41C32FD139D53F2DULL,
		0x40BD57B78127678DULL,
		0x0ADCF2A5B568AF5AULL,
		0xDC07EE445D7A9644ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19DB19A779D39C0AULL,
		0x9324936BC1E2F999ULL,
		0x633E02C1C41296D2ULL,
		0x9B8D18AD8DB5BE7DULL,
		0x445D1DBD5E10B9A6ULL,
		0xD48E10F6381A45CAULL,
		0xD7970C096D71CB15ULL,
		0x37A96944AA346C05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB2723EBB6A59B7EULL,
		0xCD090BDDA86272C4ULL,
		0x9D006D182C84E758ULL,
		0xA0DC3C20BC9342DCULL,
		0xFD661213DBC48586ULL,
		0x6C2F46C1490D21C2ULL,
		0x3345E69C47F6E444ULL,
		0xA45E84FFB3462A3EULL
	}};
	sign = 0;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06F002A03C0D4A36ULL,
		0x2BFDB0F40CB8B308ULL,
		0xBD616E12DA8D2DC3ULL,
		0x31566B8E313A73D5ULL,
		0x17E391BAFB2F9295ULL,
		0xFDDB347073BE0C80ULL,
		0x7910DA6A51CFA5CEULL,
		0x43445E2D514E2733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7274B879B54CD378ULL,
		0x4D8CF666E5F6196EULL,
		0x40950657CC33B59DULL,
		0xCDB985330103BB91ULL,
		0xB26AA0325D60ADF2ULL,
		0xC42C0555141B5051ULL,
		0xC31748C6CD8D899CULL,
		0x248BEFBAF6EFB0D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x947B4A2686C076BEULL,
		0xDE70BA8D26C29999ULL,
		0x7CCC67BB0E597825ULL,
		0x639CE65B3036B844ULL,
		0x6578F1889DCEE4A2ULL,
		0x39AF2F1B5FA2BC2EULL,
		0xB5F991A384421C32ULL,
		0x1EB86E725A5E765EULL
	}};
	sign = 0;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98ABBF8F93C6920AULL,
		0xFE654CD2A8846345ULL,
		0xD295D8EF861116DCULL,
		0xFCA1B13043704AC3ULL,
		0x53E4D9EC6D6378E2ULL,
		0x46CF4938EB1E5ED1ULL,
		0xBD506B31B4FDE0F4ULL,
		0x9172D02067983F5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x567CA8B24C7C48FEULL,
		0x62E777BC99DBD872ULL,
		0x013A9F2639B66DEBULL,
		0x1D278D3BB45B9246ULL,
		0x03BCC224C31BB3AFULL,
		0x737E156B6BA594A4ULL,
		0x4AD1BB4DA9F99734ULL,
		0xC7025B428BBE8E2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x422F16DD474A490CULL,
		0x9B7DD5160EA88AD3ULL,
		0xD15B39C94C5AA8F1ULL,
		0xDF7A23F48F14B87DULL,
		0x502817C7AA47C533ULL,
		0xD35133CD7F78CA2DULL,
		0x727EAFE40B0449BFULL,
		0xCA7074DDDBD9B133ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3D0D0E0CD53598AULL,
		0x0155E4E8AA15DF22ULL,
		0x2AFC85EB20BA987AULL,
		0x0BFD09A498CA6FACULL,
		0xF5EBEB3621EBD4ACULL,
		0x3A9F046E3BD68447ULL,
		0x9FAE1FCAB4C9E06DULL,
		0x4CDE5867334923F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E48F82EC9FAFA8ULL,
		0x8AD9F3FB211D5D5AULL,
		0xCAEC24F8D729953CULL,
		0xB9EEC6812C38396EULL,
		0x1EE1A0272ECB3C7FULL,
		0x39A0203967D3C6A9ULL,
		0x993FE1EB83A9EBCEULL,
		0x1AEB86CE5A09CEC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEEC415DE0B3A9E2ULL,
		0x767BF0ED88F881C8ULL,
		0x601060F24991033DULL,
		0x520E43236C92363DULL,
		0xD70A4B0EF320982CULL,
		0x00FEE434D402BD9EULL,
		0x066E3DDF311FF49FULL,
		0x31F2D198D93F5532ULL
	}};
	sign = 0;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD6A19C75965F541ULL,
		0x824F592697BBD69EULL,
		0x3B903F6E08767D73ULL,
		0xD4B42577CBAF0880ULL,
		0xBE7E85DF1745F24CULL,
		0xBAF3B956AA758A74ULL,
		0x6083E56F6C28D385ULL,
		0x50E722BB943312F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6047AE63D688AE6BULL,
		0x55C14CB91AA3A6C7ULL,
		0x79FAF8ECCBC00E3DULL,
		0x693F4FE218FBA849ULL,
		0xFC25207A1FD3CFF4ULL,
		0x88140A08728938BCULL,
		0x36E1B0987880C6D6ULL,
		0x638399109BCB73EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D226B6382DD46D6ULL,
		0x2C8E0C6D7D182FD7ULL,
		0xC19546813CB66F36ULL,
		0x6B74D595B2B36036ULL,
		0xC2596564F7722258ULL,
		0x32DFAF4E37EC51B7ULL,
		0x29A234D6F3A80CAFULL,
		0xED6389AAF8679F0CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AB328F256E6E16FULL,
		0xD31EB4162AC5BC55ULL,
		0x3F4EFC9006BDD3A5ULL,
		0x7A72FE68B2ADBB48ULL,
		0xCD4BB1DCA90B6291ULL,
		0x83ABCB06798FD7F8ULL,
		0xCD038E733CDF1D18ULL,
		0xDCB95DD3A5EAE531ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C8015271207D0BAULL,
		0xDE41F3A4732EB7EBULL,
		0xB758DEBE112C3E75ULL,
		0x0C131F7DD4B3C64AULL,
		0xDB158656B182CC30ULL,
		0x884BC17296C27D9EULL,
		0x0C4E65594012CA71ULL,
		0xBF70EA12B15F8592ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE3313CB44DF10B5ULL,
		0xF4DCC071B7970469ULL,
		0x87F61DD1F591952FULL,
		0x6E5FDEEADDF9F4FDULL,
		0xF2362B85F7889661ULL,
		0xFB600993E2CD5A59ULL,
		0xC0B52919FCCC52A6ULL,
		0x1D4873C0F48B5F9FULL
	}};
	sign = 0;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E95D31787906BEEULL,
		0x2C5788F9522946BDULL,
		0xADEA2388F09D9334ULL,
		0xBD5ECA7D02D7B99AULL,
		0x7F8C58FF1E85A4F4ULL,
		0xF90B1910F375B542ULL,
		0x60C2433E27E47040ULL,
		0xC2A0AAED13E0960AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBAFD9BBA50027DULL,
		0x7F606678E6DC1C5DULL,
		0xC3A170EF4B268B42ULL,
		0x4047DDE6978ECF8EULL,
		0xAE1554DC38688AD9ULL,
		0x9B72FA8E9110D3E1ULL,
		0x1308FC77DD3891F3ULL,
		0xCF54367CE425EBEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EDAD57BCD406971ULL,
		0xACF722806B4D2A5FULL,
		0xEA48B299A57707F1ULL,
		0x7D16EC966B48EA0BULL,
		0xD1770422E61D1A1BULL,
		0x5D981E826264E160ULL,
		0x4DB946C64AABDE4DULL,
		0xF34C74702FBAAA1FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE31BD5ECCA22A45ULL,
		0x0E95E7A18572C165ULL,
		0x7A9E9A3060231233ULL,
		0x01FD3F484B453B6AULL,
		0x67F0BBA185A81B06ULL,
		0x7FB53C164070F7E3ULL,
		0xD0C944A8D0F4AEA7ULL,
		0x9A2872317DD047CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA8EC88E953EA023ULL,
		0x1D6E13D82ED3456FULL,
		0x7A03C507ABA29C0DULL,
		0xF88C6673B3D6BFB6ULL,
		0xB9E25F4E407FA79FULL,
		0x758D855069961599ULL,
		0xCBEFC485ED384DF4ULL,
		0x1948A84984A7C52CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33A2F4D037638A22ULL,
		0xF127D3C9569F7BF6ULL,
		0x009AD528B4807625ULL,
		0x0970D8D4976E7BB4ULL,
		0xAE0E5C5345287366ULL,
		0x0A27B6C5D6DAE249ULL,
		0x04D98022E3BC60B3ULL,
		0x80DFC9E7F92882A0ULL
	}};
	sign = 0;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22B3E38A556F6199ULL,
		0x86743EF186AD0E45ULL,
		0xBB33B1AC2C1D47AEULL,
		0x6F7E94AF73F4CF96ULL,
		0x69C59E0EA6424091ULL,
		0x15461208E1CB36D9ULL,
		0x7B257EC352EFDAE5ULL,
		0xB84E730F8D8C48EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1AD988869C0CE76ULL,
		0x915C52C16563677BULL,
		0xF5530BC109FB955DULL,
		0x7F1F1EDDC81AFCD1ULL,
		0x76487ECE305AE3DEULL,
		0xD81C3761D7D9AF59ULL,
		0x4374EF63ECA1A457ULL,
		0x4BA1A5E16D5FC960ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61064B01EBAE9323ULL,
		0xF517EC302149A6C9ULL,
		0xC5E0A5EB2221B250ULL,
		0xF05F75D1ABD9D2C4ULL,
		0xF37D1F4075E75CB2ULL,
		0x3D29DAA709F1877FULL,
		0x37B08F5F664E368DULL,
		0x6CACCD2E202C7F8EULL
	}};
	sign = 0;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB837516651B101B4ULL,
		0x6894BCCE0B0722BBULL,
		0xFBD0AE908DCDE325ULL,
		0xE9F63EA9F593DCBDULL,
		0x25FA629C979364C4ULL,
		0x225AE5C3D2DE0BF5ULL,
		0x4717AFC39D197488ULL,
		0x3E174E6EEE721E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A07CA0CCD2231F1ULL,
		0x4A9E5BEFCC33390EULL,
		0xD723E31519ECF11AULL,
		0x855FFB3B75CD025FULL,
		0x7FADAEDD41E1281EULL,
		0x44C7032B3A57B324ULL,
		0x79A4C5B7A4EE1F80ULL,
		0xC1C91F9959CE4EDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E2F8759848ECFC3ULL,
		0x1DF660DE3ED3E9ADULL,
		0x24ACCB7B73E0F20BULL,
		0x6496436E7FC6DA5EULL,
		0xA64CB3BF55B23CA6ULL,
		0xDD93E298988658D0ULL,
		0xCD72EA0BF82B5507ULL,
		0x7C4E2ED594A3CF9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51D1FA27FEF61093ULL,
		0x9338A35A0692FBA5ULL,
		0x898D1DFAA723A344ULL,
		0xCD77EE18089E6AA8ULL,
		0x844E5D509D8737AEULL,
		0xB921C7326D6C7D17ULL,
		0x220266DCC672D4E6ULL,
		0xBF7A6668D76E917EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD7481F87A85AD3ULL,
		0xFA4200F0406F31ACULL,
		0x2A84A1B19DA3A040ULL,
		0x731EF096E30CBD26ULL,
		0xC6189E7D85707341ULL,
		0x723B24D6150FDE7FULL,
		0x4BF94B282ACCA236ULL,
		0x6A76392EB09A3BCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11FAB208774DB5C0ULL,
		0x98F6A269C623C9F9ULL,
		0x5F087C4909800303ULL,
		0x5A58FD812591AD82ULL,
		0xBE35BED31816C46DULL,
		0x46E6A25C585C9E97ULL,
		0xD6091BB49BA632B0ULL,
		0x55042D3A26D455B0ULL
	}};
	sign = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80658D6ECB3F688AULL,
		0x1E674C2F3002C0CBULL,
		0x3A657CA3841E7B17ULL,
		0x3CCBC0DEBAA58D78ULL,
		0x6F75E6EABE118E96ULL,
		0xFFF8F8DEFE82C787ULL,
		0x3D5C1C82CBD4D237ULL,
		0x87FCA5449B6014DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14CC31D1277F6D19ULL,
		0x6ADEEF113BFBF6ACULL,
		0x3AB89CD16C78F42DULL,
		0xDB1773FCEEE99AF0ULL,
		0x5D9A64007D3F5462ULL,
		0xDA3D46979052668EULL,
		0x0525D0CD9F0F16DFULL,
		0x8A6E4757063CBA87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B995B9DA3BFFB71ULL,
		0xB3885D1DF406CA1FULL,
		0xFFACDFD217A586E9ULL,
		0x61B44CE1CBBBF287ULL,
		0x11DB82EA40D23A33ULL,
		0x25BBB2476E3060F9ULL,
		0x38364BB52CC5BB58ULL,
		0xFD8E5DED95235A53ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AB6F744F6B8D1D3ULL,
		0xFDCA64807CB4C739ULL,
		0x6670E7460CB4B068ULL,
		0xE07191F42A9C98A9ULL,
		0x460A72ABD70FD1D1ULL,
		0xC576CA99822BA0DFULL,
		0x156549B4501DFB2BULL,
		0x27372DF1175B1564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A7715627E7A34B6ULL,
		0x8E1589D9A0CA302EULL,
		0x9747871889254730ULL,
		0x40A7F9940C3CA1E3ULL,
		0x6D022C9FF83FCED8ULL,
		0x331786C2B9382C88ULL,
		0xE512415A653BFF94ULL,
		0xB84B6CA68E314DB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x503FE1E2783E9D1DULL,
		0x6FB4DAA6DBEA970BULL,
		0xCF29602D838F6938ULL,
		0x9FC998601E5FF6C5ULL,
		0xD908460BDED002F9ULL,
		0x925F43D6C8F37456ULL,
		0x30530859EAE1FB97ULL,
		0x6EEBC14A8929C7ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D94D2A7F2FEA5C5ULL,
		0x4ED480C7A5654CB5ULL,
		0x484CA1D4884013A5ULL,
		0x20405DCC16270363ULL,
		0x0845B1C023CBDE2AULL,
		0x91604731AEE15FD5ULL,
		0x629D18F7DF1CAF3CULL,
		0xB5B0E4934D510A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B09F06B40FE4549ULL,
		0xD42EED7ABA457C02ULL,
		0x84ECDBDE9818137CULL,
		0xBF1B2481A1D19ECAULL,
		0xA90042D3F11584CDULL,
		0x464995B3932FBD32ULL,
		0xD106C86A0CF4CA6AULL,
		0x34857DACE89CC10CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE28AE23CB200607CULL,
		0x7AA5934CEB1FD0B2ULL,
		0xC35FC5F5F0280028ULL,
		0x6125394A74556498ULL,
		0x5F456EEC32B6595CULL,
		0x4B16B17E1BB1A2A2ULL,
		0x9196508DD227E4D2ULL,
		0x812B66E664B4494BULL
	}};
	sign = 0;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x809A4EDD778A04F5ULL,
		0xE20E1A6B05AB3680ULL,
		0x6A95E3455E8296FCULL,
		0x630CC7C6F7C3DF27ULL,
		0x8DF32223F67C2A33ULL,
		0xCEDE6D61B793BE40ULL,
		0x7E6C473F26471290ULL,
		0x524F50621A375F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x734E5397A8825796ULL,
		0xCA0D440DF06287A9ULL,
		0xFACF40AD65EE1A31ULL,
		0xB857402D5B92A26DULL,
		0x608C0BB702860216ULL,
		0xADBDA367AABA4E66ULL,
		0x488C486513069743ULL,
		0x27BBB699FB6C9044ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D4BFB45CF07AD5FULL,
		0x1800D65D1548AED7ULL,
		0x6FC6A297F8947CCBULL,
		0xAAB587999C313CB9ULL,
		0x2D67166CF3F6281CULL,
		0x2120C9FA0CD96FDAULL,
		0x35DFFEDA13407B4DULL,
		0x2A9399C81ECACEE2ULL
	}};
	sign = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E2C458F3365E422ULL,
		0x4DB9FAF8FA962C71ULL,
		0x9E40DACBF9F6F67BULL,
		0xCECFA07B9F82FCEAULL,
		0x1F65AF3A5AB181D5ULL,
		0x63F97C8C7816C214ULL,
		0x11F6B9D49F8F8803ULL,
		0xD5CC84C40A16724BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65C1A6196FE3257ULL,
		0x58B7FDBA013FA656ULL,
		0x807D3BB42C8D7533ULL,
		0x53FC0B3591A4A361ULL,
		0xC7CC0A93A7A2CF79ULL,
		0xF56241A2B0F42E28ULL,
		0x381E140BCB9B846BULL,
		0x98DCC9D82DB6697AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67D02B2D9C67B1CBULL,
		0xF501FD3EF956861AULL,
		0x1DC39F17CD698147ULL,
		0x7AD395460DDE5989ULL,
		0x5799A4A6B30EB25CULL,
		0x6E973AE9C72293EBULL,
		0xD9D8A5C8D3F40397ULL,
		0x3CEFBAEBDC6008D0ULL
	}};
	sign = 0;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2D4CF90D0F1510CULL,
		0x0BB90A09E30EB84DULL,
		0xA3493A72121E86F9ULL,
		0x0116031E663144B2ULL,
		0x72D56DA3DBA4DC7FULL,
		0xA1670209AE9EF48CULL,
		0xC892840D81484214ULL,
		0x08C5BF5CFE563584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9662B8FF17773760ULL,
		0x17324815444D7BC0ULL,
		0xE559432D0DDF8B8CULL,
		0x4E3920D7DB118215ULL,
		0x47F303385F5AB961ULL,
		0xE5745288377F20B4ULL,
		0x52352220D8E23551ULL,
		0xA2132D0E1DCC6D6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C721691B97A19ACULL,
		0xF486C1F49EC13C8DULL,
		0xBDEFF745043EFB6CULL,
		0xB2DCE2468B1FC29CULL,
		0x2AE26A6B7C4A231DULL,
		0xBBF2AF81771FD3D8ULL,
		0x765D61ECA8660CC2ULL,
		0x66B2924EE089C818ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2BE4E84403AC1F1ULL,
		0x2A3C1196E1C0ED94ULL,
		0x9C3153C02A208EB2ULL,
		0xEA816CD386C79E90ULL,
		0x8A7EC4ABFFB45106ULL,
		0x4082B79631A0A21AULL,
		0x09B6C9D4CDC5FA97ULL,
		0xA08E6BFEF19A3D10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE720C8D4D1187BFCULL,
		0x96A34FA29C13F4B3ULL,
		0x053FF01032F6C24FULL,
		0x1904F5B341513A2AULL,
		0xAA7539088612799CULL,
		0x9A13985CC0B92991ULL,
		0x50C6ED76F889A4ACULL,
		0xD0CAD39E007CB118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB9D85AF6F2245F5ULL,
		0x9398C1F445ACF8E0ULL,
		0x96F163AFF729CC62ULL,
		0xD17C772045766466ULL,
		0xE0098BA379A1D76AULL,
		0xA66F1F3970E77888ULL,
		0xB8EFDC5DD53C55EAULL,
		0xCFC39860F11D8BF7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x275A0A20015AE143ULL,
		0xF8FFE2FCC79E7A2AULL,
		0xDCD397891EF193B1ULL,
		0x2DCDC9D99E10B11DULL,
		0xEEB92A47E47DCAD9ULL,
		0x0DEA68FEEA62220FULL,
		0xEC2780F24DA46D4CULL,
		0x7F6847AAE9A4A4D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD33A97D420A746ULL,
		0xC9BD1C7FCE477E50ULL,
		0xED20BF61E137AB77ULL,
		0x59832573F18D3704ULL,
		0xEF6D2B3C2A675DEAULL,
		0xC0558C569B622E76ULL,
		0x40813533805D4EECULL,
		0xDD7B6F4013559496ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3786CF882D3A39FDULL,
		0x2F42C67CF956FBD9ULL,
		0xEFB2D8273DB9E83AULL,
		0xD44AA465AC837A18ULL,
		0xFF4BFF0BBA166CEEULL,
		0x4D94DCA84EFFF398ULL,
		0xABA64BBECD471E5FULL,
		0xA1ECD86AD64F1041ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BB712CF7F37A617ULL,
		0xB2701BC70B2579CCULL,
		0x233E6D93729FC3AAULL,
		0x09CBD045C0CC0F11ULL,
		0x19AC9D8371527129ULL,
		0x3A7A8E4CB3807E26ULL,
		0x7C050FEB7268AB37ULL,
		0x59C1D45ECE7B275AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB050B6C0F5006504ULL,
		0x12E88F15B849990FULL,
		0x28D6EBCDEA876F35ULL,
		0x5F5C6B4B91998399ULL,
		0x1B99A3A1DA0C43DAULL,
		0x0A3466137E4AE4AAULL,
		0xD8F6E5BF598F887CULL,
		0xFEA8D08667B70E08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB665C0E8A374113ULL,
		0x9F878CB152DBE0BCULL,
		0xFA6781C588185475ULL,
		0xAA6F64FA2F328B77ULL,
		0xFE12F9E197462D4EULL,
		0x304628393535997BULL,
		0xA30E2A2C18D922BBULL,
		0x5B1903D866C41951ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x155A57D2C6519222ULL,
		0xD8B55C753216A829ULL,
		0xB906146C235F18DBULL,
		0x16B5BEC03CCEC7AFULL,
		0x60894A2E1187CC3AULL,
		0x1A5B082AFBAA2C9CULL,
		0x0144A231D23D62A8ULL,
		0x0C808148BD4202A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC16C78C4AC77BA8AULL,
		0x3D2D5AC4C7A3D09BULL,
		0x36B1F17B427EE75AULL,
		0x5AF7352140EE7A2EULL,
		0xA8487812EB6ACFD7ULL,
		0x4BE8EAA5B63DE2CBULL,
		0xF69F30A782F923BAULL,
		0x27AF4220445B5A00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53EDDF0E19D9D798ULL,
		0x9B8801B06A72D78DULL,
		0x825422F0E0E03181ULL,
		0xBBBE899EFBE04D81ULL,
		0xB840D21B261CFC62ULL,
		0xCE721D85456C49D0ULL,
		0x0AA5718A4F443EEDULL,
		0xE4D13F2878E6A8A6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01BBCF8C2F259C90ULL,
		0x0317DEDA93F592FBULL,
		0x0A3369876F94E2A7ULL,
		0xC6F7107D7D700693ULL,
		0xFD94D79009A54094ULL,
		0xFF6A3D80075FD17DULL,
		0x0F80FA7AB2BAB130ULL,
		0x13F78D086F884731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EF1E2ECFB2D36B4ULL,
		0x8A8690BB8B3DAF5BULL,
		0x2B026CF7B1E150D0ULL,
		0xEABBE4B988EC42F0ULL,
		0x77C09EF28F8D8B7EULL,
		0xE3AA8C78CAC2F00DULL,
		0xC2124BD1742D15EDULL,
		0x0F02E5F2DC2E0D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C9EC9F33F865DCULL,
		0x78914E1F08B7E39FULL,
		0xDF30FC8FBDB391D6ULL,
		0xDC3B2BC3F483C3A2ULL,
		0x85D4389D7A17B515ULL,
		0x1BBFB1073C9CE170ULL,
		0x4D6EAEA93E8D9B43ULL,
		0x04F4A715935A39BCULL
	}};
	sign = 0;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A324E11621EA05EULL,
		0xF8C053C180D49CC9ULL,
		0xD71DACBBEA8CB25AULL,
		0x4F54B76E715BF930ULL,
		0x636335B451C6988FULL,
		0xFE2726D5AB58058DULL,
		0xD5DD7B0D9E0307DFULL,
		0x155EFF11499263D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB245EF4C2F29C769ULL,
		0xC80E78C137EC961BULL,
		0xC72203D77B05239DULL,
		0x5D2067FA1A88C911ULL,
		0x720627198DAE17AFULL,
		0x6B36BA7AAB867546ULL,
		0x951AF84686812E90ULL,
		0x2D15764F3F9302B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7EC5EC532F4D8F5ULL,
		0x30B1DB0048E806ADULL,
		0x0FFBA8E46F878EBDULL,
		0xF2344F7456D3301FULL,
		0xF15D0E9AC41880DFULL,
		0x92F06C5AFFD19046ULL,
		0x40C282C71781D94FULL,
		0xE84988C209FF6121ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1AA44FA33225F59ULL,
		0x17A7586BB4915B2DULL,
		0xF712BC7ACEF2FB78ULL,
		0xDE4DAA023E179AD6ULL,
		0x83E83263BDEB7E9CULL,
		0x55DC863ADAD01687ULL,
		0x243EFE4F215426D8ULL,
		0x79511CD788280029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1379FE46B1D65A9ULL,
		0xB29F782DB15560A2ULL,
		0x6640D6B68E4513FAULL,
		0x44FFF203752C4C3FULL,
		0xB2BC8503ECC4046AULL,
		0x11821A19BE90AF88ULL,
		0x8BCBC923C559ACF5ULL,
		0xF13BF7CAC6FFE1ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3072A515C804F9B0ULL,
		0x6507E03E033BFA8BULL,
		0x90D1E5C440ADE77DULL,
		0x994DB7FEC8EB4E97ULL,
		0xD12BAD5FD1277A32ULL,
		0x445A6C211C3F66FEULL,
		0x9873352B5BFA79E3ULL,
		0x8815250CC1281E7DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69F34CDDCF651784ULL,
		0xE3F9E627B6C9D49CULL,
		0x80DDCA61C68F0041ULL,
		0x60737826F812C68BULL,
		0x32C6241F0C7584A8ULL,
		0x48BB2D3E67907AD1ULL,
		0x1F8066DDAC245BADULL,
		0xB373AAD1B340E2D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25E9EA7E572258DEULL,
		0x463EB7B0D08523D4ULL,
		0xBA056E07DD67CF24ULL,
		0x1112AF567B1F39B7ULL,
		0x66DF468D604B098AULL,
		0xCEACCB64B8525110ULL,
		0x2231929FE30A990EULL,
		0xD9F9BF64C8EFF194ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4409625F7842BEA6ULL,
		0x9DBB2E76E644B0C8ULL,
		0xC6D85C59E927311DULL,
		0x4F60C8D07CF38CD3ULL,
		0xCBE6DD91AC2A7B1EULL,
		0x7A0E61D9AF3E29C0ULL,
		0xFD4ED43DC919C29EULL,
		0xD979EB6CEA50F142ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFDE4229CDD5E6F1ULL,
		0x3A142A468548FCADULL,
		0xD93EDDB12559FE5DULL,
		0x9084D404F46853A5ULL,
		0x51A2A76668156631ULL,
		0xDFDB944A77CFA3A0ULL,
		0x944EB82650D9F333ULL,
		0x60A996C3EB134227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E6AD4B69EBE9DC4ULL,
		0x0018210143DAF070ULL,
		0x8C400ECFC847DEC2ULL,
		0x33DFEE6E457DD013ULL,
		0xEF78B1B622F3EA1BULL,
		0xC6AB164501C2F44AULL,
		0x58CE6B64BDDF5397ULL,
		0xDB5F5618EE3EFBAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81736D732F17492DULL,
		0x39FC0945416E0C3DULL,
		0x4CFECEE15D121F9BULL,
		0x5CA4E596AEEA8392ULL,
		0x6229F5B045217C16ULL,
		0x19307E05760CAF55ULL,
		0x3B804CC192FA9F9CULL,
		0x854A40AAFCD44679ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4443EB265F6EBBFBULL,
		0xD3F95468E176E1DAULL,
		0x9141132314B16584ULL,
		0x5E744F782E8487C1ULL,
		0xA05525A54132BEFCULL,
		0x04CB3251898C8AFDULL,
		0x364D5BEDE3A00753ULL,
		0x7CA2DD73816F3F54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x016E48C327DE39BDULL,
		0x05CFF0EAC3BA01C2ULL,
		0x70857321D8D2EB6BULL,
		0x90CFA0D890DE888AULL,
		0x3E6353110C1B8690ULL,
		0x49BFDBB290E29599ULL,
		0xAC1B052B689123AEULL,
		0xBBB9AB4742545296ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42D5A2633790823EULL,
		0xCE29637E1DBCE018ULL,
		0x20BBA0013BDE7A19ULL,
		0xCDA4AE9F9DA5FF37ULL,
		0x61F1D2943517386BULL,
		0xBB0B569EF8A9F564ULL,
		0x8A3256C27B0EE3A4ULL,
		0xC0E9322C3F1AECBDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE208FC0621A9F52ULL,
		0xC301D1444B60223CULL,
		0x100D99CE7117378BULL,
		0x2AF8A172047A8627ULL,
		0xB5B29F0E31B59612ULL,
		0x50E81EF5680541B5ULL,
		0xDEC723CCBB1C4F3DULL,
		0xAD6AF79C7016B43DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B6FD15B5579DE64ULL,
		0xC1DCDABDB6B1F972ULL,
		0x1631F58A8FC02996ULL,
		0xC24A46DEB03C6238ULL,
		0x74E9F8BA5A2E15A3ULL,
		0xCFE2345A28C05640ULL,
		0xE55757DE4D82F1E5ULL,
		0x0EF7BE73F050AFC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62B0BE650CA0C0EEULL,
		0x0124F68694AE28CAULL,
		0xF9DBA443E1570DF5ULL,
		0x68AE5A93543E23EEULL,
		0x40C8A653D787806EULL,
		0x8105EA9B3F44EB75ULL,
		0xF96FCBEE6D995D57ULL,
		0x9E7339287FC60477ULL
	}};
	sign = 0;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81BF29E1789C0ADFULL,
		0x5D282342346C581BULL,
		0xC0B821CA0D2887EBULL,
		0xFFAC140458540C07ULL,
		0x14D7D86DEE9DE14BULL,
		0x5182E4E203B0781FULL,
		0x3415197499FE099CULL,
		0xD9C980490F156F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ACFDADD6651277BULL,
		0x8E210B15F1F5FE3DULL,
		0x16602CA095A75042ULL,
		0xCCB8A71635C88802ULL,
		0x51493BB8768AE3ADULL,
		0x92FF810C60A6109DULL,
		0x1F0BAF0EA037A0C5ULL,
		0xC718343C92516833ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56EF4F04124AE364ULL,
		0xCF07182C427659DEULL,
		0xAA57F529778137A8ULL,
		0x32F36CEE228B8405ULL,
		0xC38E9CB57812FD9EULL,
		0xBE8363D5A30A6781ULL,
		0x15096A65F9C668D6ULL,
		0x12B14C0C7CC406DFULL
	}};
	sign = 0;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x816A4AED13889EB1ULL,
		0x8DC8985BEB407D0FULL,
		0xCD3149261836A8BEULL,
		0x1B3F0B85B5DCB4B0ULL,
		0xC6F64643C5A63D0EULL,
		0xF1CA7258476CEDA4ULL,
		0xD00C3E4EB6F618BEULL,
		0x9EB359E47EA1C9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x157929ADC4C469EBULL,
		0xEC2B13EF52401D55ULL,
		0xC6CF4A9DB33AE1D6ULL,
		0x6F27BF32FE893FCBULL,
		0xD4B80DF27F50F663ULL,
		0xB1F4E3CD8B592F10ULL,
		0x3727DC358B07EE3EULL,
		0x3D5351B83DFB33DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BF1213F4EC434C6ULL,
		0xA19D846C99005FBAULL,
		0x0661FE8864FBC6E7ULL,
		0xAC174C52B75374E5ULL,
		0xF23E3851465546AAULL,
		0x3FD58E8ABC13BE93ULL,
		0x98E462192BEE2A80ULL,
		0x6160082C40A695E6ULL
	}};
	sign = 0;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AD627B530190A73ULL,
		0x1A53DE91C5BE4B55ULL,
		0x781673BEF0518045ULL,
		0x4D4FD7D9FA8E2149ULL,
		0xBBB8CE6A1CC758FBULL,
		0xA68E2D471F41C724ULL,
		0xBD7D5C5963E40642ULL,
		0xDC4885FDF79426F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x266C8854AAECA3C9ULL,
		0x011B8369381A1197ULL,
		0x5B03DF9FA8C6E54CULL,
		0x7B21BAAAEAE6258CULL,
		0x97862146450A9876ULL,
		0x1C6E78A1E1A4258CULL,
		0x97FF691BFDA81F25ULL,
		0x850F3F03AEA7AE04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64699F60852C66AAULL,
		0x19385B288DA439BEULL,
		0x1D12941F478A9AF9ULL,
		0xD22E1D2F0FA7FBBDULL,
		0x2432AD23D7BCC084ULL,
		0x8A1FB4A53D9DA198ULL,
		0x257DF33D663BE71DULL,
		0x573946FA48EC78F4ULL
	}};
	sign = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CF41F8006D5C895ULL,
		0xACA8C167BF95F732ULL,
		0x8C428F52C345C7C6ULL,
		0x899BDF52C461F454ULL,
		0x67D7E4B7DCC1BD55ULL,
		0xED776166D379E8E8ULL,
		0x7333B7346DC26F55ULL,
		0x455F2A8D3F25733FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BA5AAA104B4D9BULL,
		0x0CD6B3888AEF2086ULL,
		0x81A27F1AFC0042A0ULL,
		0x2F1C0533EE8BE420ULL,
		0x4C2814595A1FDA9CULL,
		0x8BE958BDFBBD4C56ULL,
		0xB70BF61F735EFCDBULL,
		0xE0BDC477D5B252BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF939C4D5F68A7AFAULL,
		0x9FD20DDF34A6D6ABULL,
		0x0AA01037C7458526ULL,
		0x5A7FDA1ED5D61034ULL,
		0x1BAFD05E82A1E2B9ULL,
		0x618E08A8D7BC9C92ULL,
		0xBC27C114FA63727AULL,
		0x64A1661569732081ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE05F920B778B4BBULL,
		0xC7D4FFC4274395ADULL,
		0xADD04BB41A626B2BULL,
		0x1E931D048D476B45ULL,
		0x8C12A8115E52B245ULL,
		0xA1DB46E64DF4079BULL,
		0x535FC5D785637E90ULL,
		0x1048F32A91530BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8081F58ECEAAE7ULL,
		0x8E2C193302384E17ULL,
		0x6CA6951315921722ULL,
		0x462E2234691D64AEULL,
		0x930C66F917F970C0ULL,
		0x2AA46DFA5C67BC74ULL,
		0x95691CE6133A1A8EULL,
		0x8AEAFC28CEB3F835ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0285772B28AA09D4ULL,
		0x39A8E691250B4796ULL,
		0x4129B6A104D05409ULL,
		0xD864FAD0242A0697ULL,
		0xF906411846594184ULL,
		0x7736D8EBF18C4B26ULL,
		0xBDF6A8F172296402ULL,
		0x855DF701C29F137CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8F78EDC9A5ABAD5ULL,
		0xF226D69429E63ACEULL,
		0xFEC310E8902EBA0FULL,
		0x7329802663AF8C1EULL,
		0xA402E0953420DFBBULL,
		0x53B87E7C2D68B9EFULL,
		0xC6A08C63D53C6E2AULL,
		0x7FBA491ED4B0BF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EDD3A848E698B10ULL,
		0xE7321C28A3821686ULL,
		0x901924C8D426F961ULL,
		0x05DDBEFE8062DF43ULL,
		0xC519E8604DA98905ULL,
		0x973598D253D05FBDULL,
		0x42949058A9E1A6EAULL,
		0xD7375F1C41BBB2C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A1A54580BF12FC5ULL,
		0x0AF4BA6B86642448ULL,
		0x6EA9EC1FBC07C0AEULL,
		0x6D4BC127E34CACDBULL,
		0xDEE8F834E67756B6ULL,
		0xBC82E5A9D9985A31ULL,
		0x840BFC0B2B5AC73FULL,
		0xA882EA0292F50C87ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1E367E3FB276646ULL,
		0x10B20794EC49F135ULL,
		0xB92944AA989838E1ULL,
		0xE1B91F3B92B47E35ULL,
		0x6C184B1229E12E36ULL,
		0xB5714B2B859B9BE7ULL,
		0xDCFC3E04B3387746ULL,
		0x33F885B922C2A004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A7F4B842D55EE63ULL,
		0x2D79A5E766F15431ULL,
		0x311D20D59EBE3B0BULL,
		0x333B641D8E2B70A4ULL,
		0x98992259DFC90B45ULL,
		0xA57B85860F750E61ULL,
		0x51B594B31590F670ULL,
		0xA84DBB62B2D6EB45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7641C5FCDD177E3ULL,
		0xE33861AD85589D04ULL,
		0x880C23D4F9D9FDD5ULL,
		0xAE7DBB1E04890D91ULL,
		0xD37F28B84A1822F1ULL,
		0x0FF5C5A576268D85ULL,
		0x8B46A9519DA780D6ULL,
		0x8BAACA566FEBB4BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02ECB16FD691E41DULL,
		0x4A53682DB6E4F535ULL,
		0xDC9E61A3E2EBF421ULL,
		0x9465D6B0E73BA7EAULL,
		0x933B1A96515C4003ULL,
		0xD6D1355E6D64E702ULL,
		0xB439947FF3C438E6ULL,
		0xE7053DF36CBFC59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DCDDEE245E0DB4ULL,
		0xA1BB4A3E7BE9E03BULL,
		0xCA2DC69DB9535F6AULL,
		0xF632186CDEE1BF01ULL,
		0x916DA67EB8C02F4AULL,
		0x4EE8185F4E8506B1ULL,
		0xF38CC0568227A97EULL,
		0x9FBEEE705939C142ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC0FD381B233D669ULL,
		0xA8981DEF3AFB14F9ULL,
		0x12709B06299894B6ULL,
		0x9E33BE440859E8E9ULL,
		0x01CD7417989C10B8ULL,
		0x87E91CFF1EDFE051ULL,
		0xC0ACD429719C8F68ULL,
		0x47464F8313860457ULL
	}};
	sign = 0;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA401C40E975E6F21ULL,
		0xDEA9754498A08437ULL,
		0x92CCAD444D172D46ULL,
		0x3854FA3DF357BF59ULL,
		0xE52E9BB02071CA14ULL,
		0x524F6100DFB25A0CULL,
		0x7E52266D73C5F919ULL,
		0xFF363FF1AFA452CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3240C90BA704ED10ULL,
		0x90B8326968BB0DAAULL,
		0x17066E9DA2D75A69ULL,
		0x350D3AA77DB07539ULL,
		0x9DA0B9F176D2CDC9ULL,
		0x1D6EA6D609244DA0ULL,
		0xD95966AB8F6AE7D3ULL,
		0x01E587DB8906995FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71C0FB02F0598211ULL,
		0x4DF142DB2FE5768DULL,
		0x7BC63EA6AA3FD2DDULL,
		0x0347BF9675A74A20ULL,
		0x478DE1BEA99EFC4BULL,
		0x34E0BA2AD68E0C6CULL,
		0xA4F8BFC1E45B1146ULL,
		0xFD50B816269DB96FULL
	}};
	sign = 0;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15279DF77D8AF310ULL,
		0x4B339A09D4470B31ULL,
		0x3159FED304335C2AULL,
		0x1D594642CF0A3BF7ULL,
		0xD42A3EB6F29E48DFULL,
		0xF0D08F39D4D01AD2ULL,
		0xA20ED1344FA72B47ULL,
		0x4FEC188A776A03E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85779BAF442D1E76ULL,
		0x32AD6E9FF8E57277ULL,
		0x26165918BB1FA75FULL,
		0x2FB94CF047B55B17ULL,
		0x5A380030937F3D34ULL,
		0x7BDB8190FCE01AD1ULL,
		0xC2214FB2ECC46BE2ULL,
		0x1CD97FDEAAC46533ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FB00248395DD49AULL,
		0x18862B69DB6198B9ULL,
		0x0B43A5BA4913B4CBULL,
		0xED9FF9528754E0E0ULL,
		0x79F23E865F1F0BAAULL,
		0x74F50DA8D7F00001ULL,
		0xDFED818162E2BF65ULL,
		0x331298ABCCA59EB4ULL
	}};
	sign = 0;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x753E6E429ACE9226ULL,
		0xD4A27915D3406CD1ULL,
		0x6F083F6697CBA252ULL,
		0x3DBA2F00D22AF6C7ULL,
		0xB1B411BF4E0AFB3AULL,
		0x0F99223E855CE7CBULL,
		0x45AB35BD135CDA95ULL,
		0x6387C4A98515D2F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40BCB01BF72804A3ULL,
		0x58A7D1666D3B4FF9ULL,
		0x50CB411E86B03446ULL,
		0xDEB1D4BB48DE6651ULL,
		0x03BD12C7F66E571DULL,
		0x76BD166B3EFD75A2ULL,
		0xD039FDD5D4C557DEULL,
		0x285202739EEF6022ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3481BE26A3A68D83ULL,
		0x7BFAA7AF66051CD8ULL,
		0x1E3CFE48111B6E0CULL,
		0x5F085A45894C9076ULL,
		0xADF6FEF7579CA41CULL,
		0x98DC0BD3465F7229ULL,
		0x757137E73E9782B6ULL,
		0x3B35C235E62672CEULL
	}};
	sign = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6A3E4B798A350D6ULL,
		0x1D0984A4CD8AC32DULL,
		0x18C214726AEADCE7ULL,
		0xFFF7C9EBC9CA3244ULL,
		0xDAD44F3DFCF229D6ULL,
		0xF16273466B7BC2F8ULL,
		0x438ED6B753A996BEULL,
		0x8E1EC0149C23A247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68569BEC4953CB16ULL,
		0xF57FE8449593A639ULL,
		0xB747F74FDE90B0E7ULL,
		0x86B7E306E445A75FULL,
		0x980D4C51CDF31540ULL,
		0x17312768B72B6162ULL,
		0xE729D99C7A11C0C7ULL,
		0xDE5B719427CC3794ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E4D48CB4F4F85C0ULL,
		0x27899C6037F71CF4ULL,
		0x617A1D228C5A2BFFULL,
		0x793FE6E4E5848AE4ULL,
		0x42C702EC2EFF1496ULL,
		0xDA314BDDB4506196ULL,
		0x5C64FD1AD997D5F7ULL,
		0xAFC34E8074576AB2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23119A6D20A0101BULL,
		0x346B6EB2F0050994ULL,
		0xFB81CB54B86FA818ULL,
		0x8C32A6CE71E802A9ULL,
		0x7C15E81B1460D609ULL,
		0xB9CAE90AAA252AC3ULL,
		0x2A9A58188750FB88ULL,
		0x500525C1D50A7FBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCBCBA80EFB71957ULL,
		0xB54E7CB16FD687CAULL,
		0x73517F95730EE0B5ULL,
		0x58C96664A1F9ED7AULL,
		0x950D1ACDD05388A9ULL,
		0x622BA9AA99335921ULL,
		0xD1F590D42A97CBCEULL,
		0xDB2003A536412935ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2654DFEC30E8F6C4ULL,
		0x7F1CF201802E81C9ULL,
		0x88304BBF4560C762ULL,
		0x33694069CFEE152FULL,
		0xE708CD4D440D4D60ULL,
		0x579F3F6010F1D1A1ULL,
		0x58A4C7445CB92FBAULL,
		0x74E5221C9EC95686ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF03A3D687F4FE6CFULL,
		0x816A3BC8DE9000F8ULL,
		0x00D83FFD62308085ULL,
		0x7CCE05B33608C4F1ULL,
		0xDCD7D4FACC3E8DA7ULL,
		0x8B8CBB5EB02FA0DEULL,
		0xAE53B1EAFC9E27D9ULL,
		0x2F2ECD262A04136FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB20284B24582D23ULL,
		0x39826623BEAECC54ULL,
		0x443222FBD649307EULL,
		0x851D9355FC001A6DULL,
		0x5146F15B322FEFAFULL,
		0xED8277715F3073F8ULL,
		0x854058F57D21A08AULL,
		0xB9C1E6BCAF2FEBB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x151A151D5AF7B9ACULL,
		0x47E7D5A51FE134A4ULL,
		0xBCA61D018BE75007ULL,
		0xF7B0725D3A08AA83ULL,
		0x8B90E39F9A0E9DF7ULL,
		0x9E0A43ED50FF2CE6ULL,
		0x291358F57F7C874EULL,
		0x756CE6697AD427BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9A51920CC15D23CULL,
		0xB48BE27C02A08438ULL,
		0x22612E4416375DDFULL,
		0xCF1A0176D4388E27ULL,
		0x2C94265BDC231840ULL,
		0x898D68E67C33B13EULL,
		0x27FCF2C41693C035ULL,
		0xCEE95A25819E0BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x136894624742B0E9ULL,
		0x24338D844E34D9FEULL,
		0x73818901221F28C8ULL,
		0xDD4F971EEC9BD3FEULL,
		0x2FD5BF95F66A11C9ULL,
		0xE1412F2C24ED143DULL,
		0xB85ED79FF6C29435ULL,
		0xFA6D8412C8BF6D02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE63C84BE84D32153ULL,
		0x905854F7B46BAA3AULL,
		0xAEDFA542F4183517ULL,
		0xF1CA6A57E79CBA28ULL,
		0xFCBE66C5E5B90676ULL,
		0xA84C39BA57469D00ULL,
		0x6F9E1B241FD12BFFULL,
		0xD47BD612B8DE9EBEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59EC7ACC5602A3E8ULL,
		0x002CEA08BC8EB930ULL,
		0x1F23D06D3052CF09ULL,
		0x34BC8D086CFC3006ULL,
		0xEB3EF055B6899983ULL,
		0xA59F6D7E3A0BC9D6ULL,
		0x85E774DAD1553706ULL,
		0x866A631C0951F305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB3FB9DE08C7783ULL,
		0x0924F3A0D0D4CF25ULL,
		0xA4F69677B65908A6ULL,
		0x3B7727D2D7C24A63ULL,
		0x88EAC1FC3B018D02ULL,
		0x577601BBC4490837ULL,
		0x6F70C7BF51FA0270ULL,
		0x6DB3692755665692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B387F2E75762C65ULL,
		0xF707F667EBB9EA0AULL,
		0x7A2D39F579F9C662ULL,
		0xF94565359539E5A2ULL,
		0x62542E597B880C80ULL,
		0x4E296BC275C2C19FULL,
		0x1676AD1B7F5B3496ULL,
		0x18B6F9F4B3EB9C73ULL
	}};
	sign = 0;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE615A3C9B0B13F4ULL,
		0xAA01D2C5D6981992ULL,
		0x4A4CE30BF7D3F1C0ULL,
		0x93AA950012CB4837ULL,
		0x3CB0799BE3E82962ULL,
		0x8E15A352C5C3C88AULL,
		0x7EE94D020444E364ULL,
		0x5E44A4FDEC4A0812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D913E69D89953B7ULL,
		0xBBE1BAC007860831ULL,
		0x9CAE51FACE278104ULL,
		0x2F9DE42C1D59E179ULL,
		0x503B6054252E41D1ULL,
		0xD532BE65EFC9C032ULL,
		0x360C59925A3FF6A2ULL,
		0xE0690D3C691A8F5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90D01BD2C271C03DULL,
		0xEE201805CF121161ULL,
		0xAD9E911129AC70BBULL,
		0x640CB0D3F57166BDULL,
		0xEC751947BEB9E791ULL,
		0xB8E2E4ECD5FA0857ULL,
		0x48DCF36FAA04ECC1ULL,
		0x7DDB97C1832F78B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51E00A3991A775C5ULL,
		0xAC337D30081BDEE4ULL,
		0xE15004BA1579357CULL,
		0xA6FC83C52F4E67ABULL,
		0x67A87873C09E49B7ULL,
		0xBCD094B56F0EF19AULL,
		0x59744DD8C18B9392ULL,
		0xE449B9400A5057A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x877DFF682875DE51ULL,
		0x48C7664512164D06ULL,
		0x8ACCFD7DFA4879DFULL,
		0xFBB7505F6FA6E994ULL,
		0xD14F31FA1E486D2FULL,
		0x4747FD036A0C18E5ULL,
		0x75065C526A596B48ULL,
		0x2975B55E2D9F8007ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA620AD169319774ULL,
		0x636C16EAF60591DDULL,
		0x5683073C1B30BB9DULL,
		0xAB453365BFA77E17ULL,
		0x96594679A255DC87ULL,
		0x758897B20502D8B4ULL,
		0xE46DF1865732284AULL,
		0xBAD403E1DCB0D79AULL
	}};
	sign = 0;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10BB1221BFBF3331ULL,
		0xA2BA90762AB66B0FULL,
		0x4E62B8C98C64D8CFULL,
		0x22A5BCF6E739B5D4ULL,
		0x93A4E10691499814ULL,
		0xB6C8C71D4C2881FBULL,
		0x8B11FB234042D7CEULL,
		0xE4A658DED9BEF3E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A29A5515B6811DULL,
		0x042B3C2F3900A958ULL,
		0xA01A8487A3CCE3E5ULL,
		0x093D75F33C8F2B97ULL,
		0x3268520E29769172ULL,
		0x88869D2960A8CE26ULL,
		0xF811FFF9E9FBE752ULL,
		0x32D37BEA22D8A0B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x171877CCAA08B214ULL,
		0x9E8F5446F1B5C1B6ULL,
		0xAE483441E897F4EAULL,
		0x19684703AAAA8A3CULL,
		0x613C8EF867D306A2ULL,
		0x2E4229F3EB7FB3D5ULL,
		0x92FFFB295646F07CULL,
		0xB1D2DCF4B6E6532CULL
	}};
	sign = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F4E3712F5165CD3ULL,
		0x7C0B1B825368C274ULL,
		0xFA5401DB727077B6ULL,
		0xB1F8E3E9AE48B755ULL,
		0xAE96074E3FF56889ULL,
		0x3A38AD9D0D33EDDFULL,
		0x0096C88E134C4448ULL,
		0x9DB51E0427F5B4ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4B3C01B5DBEA096ULL,
		0x3D2367E2F3911720ULL,
		0x57B2805AD84E1707ULL,
		0x0B432AD0056CC9C7ULL,
		0xDDC00784108CDDCEULL,
		0xF846CD9D405FEDC9ULL,
		0xE251311BBA8C721CULL,
		0xD9DC71ABD7BB7313ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A9A76F79757BC3DULL,
		0x3EE7B39F5FD7AB53ULL,
		0xA2A181809A2260AFULL,
		0xA6B5B919A8DBED8EULL,
		0xD0D5FFCA2F688ABBULL,
		0x41F1DFFFCCD40015ULL,
		0x1E45977258BFD22BULL,
		0xC3D8AC58503A4197ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD143F89B4F4AD6AULL,
		0xB3CBD2F27C806E0AULL,
		0x80CFDC9E4704483BULL,
		0x019EC6A96212450AULL,
		0x56E4F59072911953ULL,
		0x45B75BA160E249E8ULL,
		0x6A7C39D945C117D9ULL,
		0x7E2C7E9C2DEB39F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4EBD1BB5118FA1ULL,
		0x8E128961ED6F1D2BULL,
		0x080BFCDE57757BA2ULL,
		0x3E41358F6148737DULL,
		0xA44E9AC851A461E1ULL,
		0x928CBDC6B92AB3CDULL,
		0x87DF43FEF65BECFAULL,
		0xBCBA5D48CED605C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEC5826DFFE31DC9ULL,
		0x25B949908F1150DFULL,
		0x78C3DFBFEF8ECC99ULL,
		0xC35D911A00C9D18DULL,
		0xB2965AC820ECB771ULL,
		0xB32A9DDAA7B7961AULL,
		0xE29CF5DA4F652ADEULL,
		0xC17221535F153429ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB24BF100C9AF03AULL,
		0x9FA1311460E0888FULL,
		0x4A6BFB377519CE18ULL,
		0x50C8757B53DC1514ULL,
		0xC470A81F9A022932ULL,
		0x2AE00B069979CA7FULL,
		0xAD651279631D750EULL,
		0xFE1D9125B11825FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC008FF7029886690ULL,
		0x14CB9B2AFAFC4F2BULL,
		0x8C819E26F80201ECULL,
		0xE909102110544258ULL,
		0xFF3E0A6DDAC3275AULL,
		0x84F60EF36D2E553DULL,
		0x7A386B4622AD9181ULL,
		0x1DD2B6C8B2B3AE2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB1BBF9FE31289AAULL,
		0x8AD595E965E43963ULL,
		0xBDEA5D107D17CC2CULL,
		0x67BF655A4387D2BBULL,
		0xC5329DB1BF3F01D7ULL,
		0xA5E9FC132C4B7541ULL,
		0x332CA733406FE38CULL,
		0xE04ADA5CFE6477CEULL
	}};
	sign = 0;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D8BD68E3FBE3209ULL,
		0x55596C89658EDEF4ULL,
		0x41FD31FF8E8ADE7AULL,
		0xCFEF2C357BD43E47ULL,
		0x9A928F664709CDF4ULL,
		0xF19B7CE9BDFA294DULL,
		0x1FD14B3602F5801CULL,
		0x740DB2C015050B31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA05BF5A540BA5493ULL,
		0x6843CBFB061D0767ULL,
		0x614A85AD8D70A9CCULL,
		0xFD95336E4EC1848AULL,
		0x7F0183C871EF0D10ULL,
		0xC169A0CA309571BEULL,
		0x19BCBCB181E56A43ULL,
		0xAB6DD8512CB8236CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD2FE0E8FF03DD76ULL,
		0xED15A08E5F71D78CULL,
		0xE0B2AC52011A34ADULL,
		0xD259F8C72D12B9BCULL,
		0x1B910B9DD51AC0E3ULL,
		0x3031DC1F8D64B78FULL,
		0x06148E84811015D9ULL,
		0xC89FDA6EE84CE7C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC684DE34EA3CCECEULL,
		0x0C2960ECDFCAC5EEULL,
		0x001FA3725BF9DD2AULL,
		0x4F321D3527B0CBD3ULL,
		0xA721D0513E935C1CULL,
		0xEE698E4D2D8AE322ULL,
		0xCDA6AD3B773D069FULL,
		0xDA54345B93E29B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BC313C7216E62BAULL,
		0x2856159D83170DB8ULL,
		0x47BAB9340F592EBBULL,
		0xFD155E29A11A192EULL,
		0x36D2D868FD18695DULL,
		0xE3AA7ADD9C418EDAULL,
		0xBA04EE7BA6B3203FULL,
		0xA5FFD8F88AB54B51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAC1CA6DC8CE6C14ULL,
		0xE3D34B4F5CB3B836ULL,
		0xB864EA3E4CA0AE6EULL,
		0x521CBF0B8696B2A4ULL,
		0x704EF7E8417AF2BEULL,
		0x0ABF136F91495448ULL,
		0x13A1BEBFD089E660ULL,
		0x34545B63092D4FF9ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92AF47F5816E9DC9ULL,
		0x91AF6D643E490BE8ULL,
		0x0130AED39CC2A7A5ULL,
		0x4D4F012773C91ED1ULL,
		0xCC5926D13E821ED3ULL,
		0xFE168C7C7A7D26C5ULL,
		0xD456AB893BBC4BE1ULL,
		0xEFCB33AAD0FC113EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD9BE12B58DB2D6ULL,
		0x5E56589202FDD0A3ULL,
		0x7E4481284A920FBFULL,
		0xA60C0B57AB48A9D0ULL,
		0x4B8861CC05CD2A7EULL,
		0x8AD51CFA1F0D78B8ULL,
		0x8F675DCD3ACAD077ULL,
		0x1DA857384AA93C49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2D589E2CBE0EAF3ULL,
		0x335914D23B4B3B44ULL,
		0x82EC2DAB523097E6ULL,
		0xA742F5CFC8807500ULL,
		0x80D0C50538B4F454ULL,
		0x73416F825B6FAE0DULL,
		0x44EF4DBC00F17B6AULL,
		0xD222DC728652D4F5ULL
	}};
	sign = 0;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8702795A56A979A9ULL,
		0x7489AA8196CA240AULL,
		0xB4FE92B939597CF7ULL,
		0x20CB0713095E250BULL,
		0x98442AA6650AC249ULL,
		0xBC70A4DAC0403F00ULL,
		0x8FFB9C10EEEBA36BULL,
		0x00B5BF3D617A8690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9066F809EC83DA83ULL,
		0xFA06711BA7DCF095ULL,
		0xB17C820BE4141048ULL,
		0x58E28BC0AE75251BULL,
		0x595F3AAA4403908BULL,
		0xD0C8E2D917C8FCB5ULL,
		0x46C96BAD95D7C6F5ULL,
		0x68B3AD52549E4A05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF69B81506A259F26ULL,
		0x7A833965EEED3374ULL,
		0x038210AD55456CAEULL,
		0xC7E87B525AE8FFF0ULL,
		0x3EE4EFFC210731BDULL,
		0xEBA7C201A877424BULL,
		0x493230635913DC75ULL,
		0x980211EB0CDC3C8BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE19377ECC9E237C8ULL,
		0xACFA6DFAEE6997D8ULL,
		0xA7A41F508BB6A4E5ULL,
		0xD4F3CD8D9AFF57DFULL,
		0xF2529EC443D2450CULL,
		0x890879BC5944EEE3ULL,
		0xE9DCCB1CE28E34EEULL,
		0xDF10D3C317221223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951B001F26F5ECFCULL,
		0xFC1D6A73E22AB0FFULL,
		0x793826D1C1C21A4CULL,
		0x416ADB2DB1962012ULL,
		0x0C275431663ED25CULL,
		0xBE33D1AAAB53BA21ULL,
		0x4C00D98DE6EAA9B6ULL,
		0x13D487928A885FB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C7877CDA2EC4ACCULL,
		0xB0DD03870C3EE6D9ULL,
		0x2E6BF87EC9F48A98ULL,
		0x9388F25FE96937CDULL,
		0xE62B4A92DD9372B0ULL,
		0xCAD4A811ADF134C2ULL,
		0x9DDBF18EFBA38B37ULL,
		0xCB3C4C308C99B26CULL
	}};
	sign = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF5D860AD886B28BULL,
		0x7917BE44599DF493ULL,
		0xD3FE8DC9437FEF98ULL,
		0x9CBFF7A1C0FD7186ULL,
		0x64548A131D4813ADULL,
		0x71D255F14FC1898CULL,
		0x7947E50719A24012ULL,
		0x2A16C19E1528BBC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1451961BBE906EACULL,
		0xD9402B74A6860508ULL,
		0x34558BA3396FADE8ULL,
		0xF8EA6408E097359DULL,
		0xED331E93AC509875ULL,
		0x1E4EF8EF560504DEULL,
		0x2C3436D0B9C1DD17ULL,
		0xEECD9CF76D9A8F1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB0BEFEF19F643DFULL,
		0x9FD792CFB317EF8BULL,
		0x9FA902260A1041AFULL,
		0xA3D59398E0663BE9ULL,
		0x77216B7F70F77B37ULL,
		0x53835D01F9BC84ADULL,
		0x4D13AE365FE062FBULL,
		0x3B4924A6A78E2CA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4AD34DC533C8582ULL,
		0x8D5C5C2546288C46ULL,
		0xC93FA292A9A70A57ULL,
		0xC1D5B65548813367ULL,
		0x42E3BBA62E227C60ULL,
		0x5E175A738E69861CULL,
		0x4E8A32C58F76DAA9ULL,
		0xF0B9EE178D4289BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B1AF46F021E4F7ULL,
		0x24DD579FFC9091EDULL,
		0x5AEE4E75BA22CCB1ULL,
		0x11D91DA600EDAEE0ULL,
		0xE7D8C4819023F1D0ULL,
		0x64E3BD052A581833ULL,
		0x835D6D38B879FFEEULL,
		0x6BA4793DA789AA9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CFB8595631AA08BULL,
		0x687F04854997FA59ULL,
		0x6E51541CEF843DA6ULL,
		0xAFFC98AF47938487ULL,
		0x5B0AF7249DFE8A90ULL,
		0xF9339D6E64116DE8ULL,
		0xCB2CC58CD6FCDABAULL,
		0x851574D9E5B8DF21ULL
	}};
	sign = 0;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x879214C100CA414AULL,
		0x17AF98C11B990B40ULL,
		0x8F3A7DA4CE35DF6FULL,
		0xE8D713D8F7D8A226ULL,
		0x1813B94B0703D3D6ULL,
		0xD6880074CDE1BA85ULL,
		0x22659CA27B4B9144ULL,
		0xBA88244053420562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4130C735A758E89BULL,
		0xEFCFD49ECED39729ULL,
		0x4A3E9140B1791FF6ULL,
		0xE4FBEBF2775FC58BULL,
		0x5C6AC66E8DE6D4EFULL,
		0x703372C6F5F200D2ULL,
		0x278D35EB8D3938EDULL,
		0x586338D6958F9E9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46614D8B597158AFULL,
		0x27DFC4224CC57417ULL,
		0x44FBEC641CBCBF78ULL,
		0x03DB27E68078DC9BULL,
		0xBBA8F2DC791CFEE7ULL,
		0x66548DADD7EFB9B2ULL,
		0xFAD866B6EE125857ULL,
		0x6224EB69BDB266C3ULL
	}};
	sign = 0;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AD8A96FB2C7CB75ULL,
		0x2E8B58DF814895F6ULL,
		0xC6E3355EB7E7F4B3ULL,
		0x04B20B72A78B0B06ULL,
		0xCD56BC6DC3C91293ULL,
		0x781730434E5FE98CULL,
		0x2CDED1B219FC9A82ULL,
		0x461E59611B045BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A59358A4218079BULL,
		0x19B63AE2D6165A71ULL,
		0x4FA0E64737FDD420ULL,
		0x38D810AEA0C71C7BULL,
		0x175CD12C6F6D3A8CULL,
		0xD8E1B409637B1BBDULL,
		0x8536EEA90EA0A05EULL,
		0x29E8BFC8C9714562ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x407F73E570AFC3DAULL,
		0x14D51DFCAB323B85ULL,
		0x77424F177FEA2093ULL,
		0xCBD9FAC406C3EE8BULL,
		0xB5F9EB41545BD806ULL,
		0x9F357C39EAE4CDCFULL,
		0xA7A7E3090B5BFA23ULL,
		0x1C35999851931649ULL
	}};
	sign = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51561C0E9C3C2E00ULL,
		0x78C1458AFDA440A3ULL,
		0x5708CF1FA65C574FULL,
		0x9921ED8AD4249593ULL,
		0xE8F6B64AA7F7F382ULL,
		0x58E8D8A8E67946F1ULL,
		0x055FCAB7AFB0DB80ULL,
		0x2CBA6EF9A974EF6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D3CEFF14D65ABDULL,
		0xBE4253E44856C399ULL,
		0xB16FE7EE8283F7D7ULL,
		0x648E09F09E088FADULL,
		0x32121F2378333EBAULL,
		0x0E5250B76BCAD2D3ULL,
		0x7B6F795F21BFAAD7ULL,
		0xEF7A8D8F6F781838ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F824D0F8765D343ULL,
		0xBA7EF1A6B54D7D09ULL,
		0xA598E73123D85F77ULL,
		0x3493E39A361C05E5ULL,
		0xB6E497272FC4B4C8ULL,
		0x4A9687F17AAE741EULL,
		0x89F051588DF130A9ULL,
		0x3D3FE16A39FCD733ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x902ABC7FC170455FULL,
		0xC546EBA0F8EF3E18ULL,
		0x5E9860D51EA29ED2ULL,
		0xDFFF96406427D648ULL,
		0xB544CCFBC30B7103ULL,
		0xF036AA3A7F76806CULL,
		0xAFD66ABE842922E0ULL,
		0x7EFB3EE1CE660EE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3FFBAF9F2FC116ULL,
		0x5FA99A0D1969054AULL,
		0x47B6D0F634689E2FULL,
		0xD999687FBA449902ULL,
		0xD47A3DFB5159CF6CULL,
		0x27BBB99A92BC6D80ULL,
		0x7FB993DED091C866ULL,
		0x9DEEFBA18FC68F2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0EAC0D022408449ULL,
		0x659D5193DF8638CDULL,
		0x16E18FDEEA3A00A3ULL,
		0x06662DC0A9E33D46ULL,
		0xE0CA8F0071B1A197ULL,
		0xC87AF09FECBA12EBULL,
		0x301CD6DFB3975A7AULL,
		0xE10C43403E9F7FB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA91C595AC6AC917CULL,
		0x0BFFFCB9E5B88AF1ULL,
		0x4DEF0186B56726EAULL,
		0x6F18255CE518A20BULL,
		0x297A44245968C7AFULL,
		0xCE18C91FF5BCC796ULL,
		0xAAA8DBAC0DC9D4B0ULL,
		0x463F5457B37C770EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF19A56CB81F526ULL,
		0xCFA7BB48C73DB2AEULL,
		0xA2049520431E93F0ULL,
		0x71CE24A239BBBB0BULL,
		0x7CF61D9AB0A28AC1ULL,
		0xCBEB5FA13908B47EULL,
		0x936FC87D4C208024ULL,
		0xBCFF83EFA1382767ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE2ABF03FB2A9C56ULL,
		0x3C5841711E7AD842ULL,
		0xABEA6C66724892F9ULL,
		0xFD4A00BAAB5CE6FFULL,
		0xAC842689A8C63CEDULL,
		0x022D697EBCB41317ULL,
		0x1739132EC1A9548CULL,
		0x893FD06812444FA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71F43891C4A89FFBULL,
		0xF1CFCC77EAC28EDAULL,
		0xAB56084DBE9514C8ULL,
		0x530B1C2545095025ULL,
		0xA2C8A6086FABB5A5ULL,
		0xCFA232952985D918ULL,
		0x98157AAF7B6E4450ULL,
		0xF303398EC5EEA5FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF204388B4BCED23EULL,
		0xC51C7481706A82C0ULL,
		0x117184603F513E49ULL,
		0xD68CB109F8F89F80ULL,
		0x85279A5B000CC778ULL,
		0xFFAE79E34436183AULL,
		0x3281911764A70BAEULL,
		0x2DA5B7DE8F9ADC59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FF0000678D9CDBDULL,
		0x2CB357F67A580C19ULL,
		0x99E483ED7F43D67FULL,
		0x7C7E6B1B4C10B0A5ULL,
		0x1DA10BAD6F9EEE2CULL,
		0xCFF3B8B1E54FC0DEULL,
		0x6593E99816C738A1ULL,
		0xC55D81B03653C9A1ULL
	}};
	sign = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29C6A782D2C3C335ULL,
		0x8C83B9BCCA4FB563ULL,
		0x903FC2CAD134329FULL,
		0xB6E869AC97AB7A96ULL,
		0x6F211A14BB8BBE5CULL,
		0x2D81A34649385294ULL,
		0xA2BD294582A6080FULL,
		0xEA3614E20199113CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x939E405B200623FDULL,
		0xCE7F007AB29A33FDULL,
		0xA24E21581C938542ULL,
		0x6CEA95CFA4478285ULL,
		0x2A55F17A4ACB7CE7ULL,
		0x53248D6B499EDE1CULL,
		0x5E6A89F60D887B49ULL,
		0x7C09387AC577409FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96286727B2BD9F38ULL,
		0xBE04B94217B58165ULL,
		0xEDF1A172B4A0AD5CULL,
		0x49FDD3DCF363F810ULL,
		0x44CB289A70C04175ULL,
		0xDA5D15DAFF997478ULL,
		0x44529F4F751D8CC5ULL,
		0x6E2CDC673C21D09DULL
	}};
	sign = 0;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAF4C52AC9868848ULL,
		0xBD50B62ADBEF467AULL,
		0x1C54D064CA792893ULL,
		0x194CEA7C99A4C92FULL,
		0xCFA1F491F4FBCDF9ULL,
		0x0C2ADD0364FC1D06ULL,
		0x240F7BFAAA8E4EEDULL,
		0xA9AEB162626A2B16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x188DC1602B1874D4ULL,
		0x493396D97F0CB33FULL,
		0x1AE288198F7C0618ULL,
		0x3B9865866BDFBC27ULL,
		0x11769D6DD4DEC274ULL,
		0xA120A76F9591EA28ULL,
		0xE818B5FA82E39D4EULL,
		0x2DA53EA5A0EC4711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC26703CA9E6E1374ULL,
		0x741D1F515CE2933BULL,
		0x0172484B3AFD227BULL,
		0xDDB484F62DC50D08ULL,
		0xBE2B5724201D0B84ULL,
		0x6B0A3593CF6A32DEULL,
		0x3BF6C60027AAB19EULL,
		0x7C0972BCC17DE404ULL
	}};
	sign = 0;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02E10A0DF46CE388ULL,
		0x64E2AC1A050A5DFFULL,
		0x9AA90239986A62EDULL,
		0xE2F4D9E9DBB6FE49ULL,
		0x9FCC1DA474730627ULL,
		0xC180DF6E0F401E2EULL,
		0x4AA5A04BBA863099ULL,
		0x1DD420676C485F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB28E6BF5FCDB2F8ULL,
		0x0EFAC98101D520FFULL,
		0x5F736FECF449EAAFULL,
		0x6E320DF072061AA8ULL,
		0xDAD757C7EC2BF592ULL,
		0xB4891A1A7FE77DF6ULL,
		0x97FBF191C51885C7ULL,
		0x4DD7EEBB8F4FCCD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27B8234E949F3090ULL,
		0x55E7E29903353CFFULL,
		0x3B35924CA420783EULL,
		0x74C2CBF969B0E3A1ULL,
		0xC4F4C5DC88471095ULL,
		0x0CF7C5538F58A037ULL,
		0xB2A9AEB9F56DAAD2ULL,
		0xCFFC31ABDCF89282ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EDD7F05CACD5740ULL,
		0xE9A5136DC06E727BULL,
		0xC6C12469A446A203ULL,
		0x798391A6AAED7296ULL,
		0xF541F7CC238C0D3DULL,
		0x35B970874C57121AULL,
		0xAD7E01B779EB2FB3ULL,
		0x4041607E9AC3D344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x138983047DC70BF8ULL,
		0x87BC0372FA902C7AULL,
		0x9239AAA11FB2B340ULL,
		0x86F3CD3897E97B85ULL,
		0x2DD88599CF59239FULL,
		0x5F76C6AF2B71FA0FULL,
		0xC85F711D0B1CA8BCULL,
		0x7BECBBFF2592BEB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B53FC014D064B48ULL,
		0x61E90FFAC5DE4601ULL,
		0x348779C88493EEC3ULL,
		0xF28FC46E1303F711ULL,
		0xC76972325432E99DULL,
		0xD642A9D820E5180BULL,
		0xE51E909A6ECE86F6ULL,
		0xC454A47F75311490ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2383EFE4154420C7ULL,
		0x6A4DEF537F013544ULL,
		0xD1C1A05433B1668BULL,
		0x0760785D9D6569A8ULL,
		0x09509333B6457F98ULL,
		0xA5AD9E7C9D5D9E2EULL,
		0x5F16364AE0071CACULL,
		0x05267748E4FDF9E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89766F31F3F29998ULL,
		0x53CBA252AAACF4F4ULL,
		0x0A834EF734CB2A44ULL,
		0xF145705F2B300085ULL,
		0x3699E6DDE2ECA1F4ULL,
		0x0A0E87E4F2E1F6C7ULL,
		0xB37629BF689287ABULL,
		0x5C102374DB7F06A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A0D80B22151872FULL,
		0x16824D00D454404FULL,
		0xC73E515CFEE63C47ULL,
		0x161B07FE72356923ULL,
		0xD2B6AC55D358DDA3ULL,
		0x9B9F1697AA7BA766ULL,
		0xABA00C8B77749501ULL,
		0xA91653D4097EF33CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1462F3B4C39B14DBULL,
		0xD6CECAD2B7F3685DULL,
		0x83C81A736F96A296ULL,
		0x890AA67CF217AF45ULL,
		0xF2D17DB34393DA7DULL,
		0x7363A9D2486D1973ULL,
		0x7EC5363F6415C63BULL,
		0x3431E640C69CEB8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD6F4F6C336DF67ULL,
		0x4E706875284D2CFCULL,
		0xFD243150275710A9ULL,
		0xFFE1D79680C3E875ULL,
		0x46BAAFD20DD947DFULL,
		0x5889832601CB55FCULL,
		0x53FAC69F1246D2A6ULL,
		0x9F8ABE37ACB7B9A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x148BFEBE00643574ULL,
		0x885E625D8FA63B60ULL,
		0x86A3E923483F91EDULL,
		0x8928CEE67153C6CFULL,
		0xAC16CDE135BA929DULL,
		0x1ADA26AC46A1C377ULL,
		0x2ACA6FA051CEF395ULL,
		0x94A7280919E531E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA76B7B39B6822F76ULL,
		0x081ACA21E0345FD1ULL,
		0xAEE18DB4E6405736ULL,
		0xFA0CF59B80117DF1ULL,
		0x57D6BB6095A6A0E9ULL,
		0x6300E7D30E1CB84EULL,
		0x9E9BC0570463100FULL,
		0x124A396AEADE0E14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56FCA73561CE0866ULL,
		0xAA0DE0A22FD8E797ULL,
		0xC4F4933EB9C2DABAULL,
		0x333D0B8031876289ULL,
		0xF0D1B25369EABE27ULL,
		0x78E1C41AA9B80F43ULL,
		0x782D594D6932E2F6ULL,
		0xC34F0D4A8D7D373FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x506ED40454B42710ULL,
		0x5E0CE97FB05B783AULL,
		0xE9ECFA762C7D7C7BULL,
		0xC6CFEA1B4E8A1B67ULL,
		0x6705090D2BBBE2C2ULL,
		0xEA1F23B86464A90AULL,
		0x266E67099B302D18ULL,
		0x4EFB2C205D60D6D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B3B8B4853722B72ULL,
		0x2DF248F81AC3DF7BULL,
		0x20D4DD91F5A483A5ULL,
		0x5713E3637713219DULL,
		0x9C0057385702E848ULL,
		0xBA2717AA94488D4CULL,
		0xE6B1A89EF4A85419ULL,
		0x5C0FA08CE07F49FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B56BEC89577C374ULL,
		0xCE625DC7B6DC1EE2ULL,
		0x4EB895630ABB1FA1ULL,
		0xDAE9A449CBD7CF65ULL,
		0x9BA73C14E7575DDBULL,
		0x25C46BC5430CC454ULL,
		0x11262E22BEFF5AB0ULL,
		0xC985677A7277B5D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE4CC7FBDFA67FEULL,
		0x5F8FEB3063E7C099ULL,
		0xD21C482EEAE96403ULL,
		0x7C2A3F19AB3B5237ULL,
		0x00591B236FAB8A6CULL,
		0x9462ABE5513BC8F8ULL,
		0xD58B7A7C35A8F969ULL,
		0x928A39126E079424ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA56BB36661566162ULL,
		0xC0AEB0BDF10FA1B6ULL,
		0x68E22A0DADFFB805ULL,
		0x9D2EE7C231CB7CBAULL,
		0x09499C387AB0D633ULL,
		0x2AD3EF3344C3248DULL,
		0x4489DCE5E07076D1ULL,
		0x3E7084D2D99B8425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C9D5F5F9D85B1B7ULL,
		0x996BC80B92BA7AE0ULL,
		0xD2B83183BCCD6FB6ULL,
		0x007E84E88C86E6C7ULL,
		0xC5AF1F16EA38BA45ULL,
		0x3F599B92721F725BULL,
		0x02FFBD33445D3720ULL,
		0x16BDEF8A8A4B3D99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08CE5406C3D0AFABULL,
		0x2742E8B25E5526D6ULL,
		0x9629F889F132484FULL,
		0x9CB062D9A54495F2ULL,
		0x439A7D2190781BEEULL,
		0xEB7A53A0D2A3B231ULL,
		0x418A1FB29C133FB0ULL,
		0x27B295484F50468CULL
	}};
	sign = 0;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D30502155ED2975ULL,
		0x31F3B8A2D8D290F2ULL,
		0x1C598FE37AC55718ULL,
		0xDB0853BAD84E7212ULL,
		0xE17E3386843C758BULL,
		0x748D783A8E5AB96CULL,
		0x81E9677C94E8A567ULL,
		0x8A98AA5FD108E7E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x049129B609C2B85FULL,
		0xE7C6F8A3D9D88275ULL,
		0x4B60A1B5D3130FBBULL,
		0x362ED7739192D4C2ULL,
		0xE1207DE9133E7764ULL,
		0xD0D8228623C6FFA7ULL,
		0x391EC7E6016E1217ULL,
		0x19890AF2A26A5163ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x189F266B4C2A7116ULL,
		0x4A2CBFFEFEFA0E7DULL,
		0xD0F8EE2DA7B2475CULL,
		0xA4D97C4746BB9D4FULL,
		0x005DB59D70FDFE27ULL,
		0xA3B555B46A93B9C5ULL,
		0x48CA9F96937A934FULL,
		0x710F9F6D2E9E9682ULL
	}};
	sign = 0;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32D3D78FDB7688BAULL,
		0x1DD40760D73A8B4DULL,
		0xE9B00B86764C3F0BULL,
		0x338F07F411DDCAC6ULL,
		0x7EF59FBA2DC19597ULL,
		0xD4E7A12730202532ULL,
		0xEA5589C222FD8FA5ULL,
		0x7DA64078E60DC255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA951DF0BD15C269ULL,
		0xF8BC69A2CC9D512BULL,
		0x2EE02C9F1A7F9665ULL,
		0xC5F7D32D325BDE13ULL,
		0x1B92DD0B43230E86ULL,
		0xF1851B4E6A18A67DULL,
		0x990885A47B56904FULL,
		0x394E26C856004278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x783EB99F1E60C651ULL,
		0x25179DBE0A9D3A21ULL,
		0xBACFDEE75BCCA8A5ULL,
		0x6D9734C6DF81ECB3ULL,
		0x6362C2AEEA9E8710ULL,
		0xE36285D8C6077EB5ULL,
		0x514D041DA7A6FF55ULL,
		0x445819B0900D7FDDULL
	}};
	sign = 0;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F38E96319D176DBULL,
		0x692A27C278F74C83ULL,
		0xEB1D2BB83FEF2439ULL,
		0xD6EFBBBC9B881E10ULL,
		0xF8DE70B5A54E5AEBULL,
		0xAA06E4C7FB15649AULL,
		0x2316EA7615DC255FULL,
		0x600B8333973EAAABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A9E58021B7A84CULL,
		0x0C31FD420A8A51AAULL,
		0x0271E716586E4A6CULL,
		0xC99DD7E7E3C292DEULL,
		0x52F7CECA755F8C4AULL,
		0xB3E98A08FC171689ULL,
		0x2427BCB32AC549E1ULL,
		0xC2C2CDBB2CE38F12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD8F03E2F819CE8FULL,
		0x5CF82A806E6CFAD8ULL,
		0xE8AB44A1E780D9CDULL,
		0x0D51E3D4B7C58B32ULL,
		0xA5E6A1EB2FEECEA1ULL,
		0xF61D5ABEFEFE4E11ULL,
		0xFEEF2DC2EB16DB7DULL,
		0x9D48B5786A5B1B98ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED09C0690A2FAFAEULL,
		0x8A7F4EF241BB638CULL,
		0xB20E83FE4F150BB2ULL,
		0x098E9AE02F6DD523ULL,
		0x0BDFB91142B4ED03ULL,
		0xFB1A742CA79A8F66ULL,
		0xC9CB9AAE6B73C53CULL,
		0x9B2D155A49BBF08FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D9BE2AA406B35E6ULL,
		0xDB2844FFD6C1BDC5ULL,
		0x56CB0777C1CC265EULL,
		0x6B79951F472D747BULL,
		0x69A6616F26BA97B8ULL,
		0xE8D55F26FC0D0C16ULL,
		0x05A918533BB10CAAULL,
		0x5A96E4648B66A7C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF6DDDBEC9C479C8ULL,
		0xAF5709F26AF9A5C7ULL,
		0x5B437C868D48E553ULL,
		0x9E1505C0E84060A8ULL,
		0xA23957A21BFA554AULL,
		0x12451505AB8D834FULL,
		0xC422825B2FC2B892ULL,
		0x409630F5BE5548C7ULL
	}};
	sign = 0;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC623FFF60782DAAULL,
		0x4CA099EBA451E2DCULL,
		0x210CAC32A960B015ULL,
		0x7D4A3A519557C0D3ULL,
		0x298382CE86F55183ULL,
		0xB1963D1D11C83034ULL,
		0x8832F0F3AB0B7B60ULL,
		0x1505BDA3CB685C6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1669DE6A0B5443BFULL,
		0x4496CFC140E87E9EULL,
		0xC5BD33AF31245C3FULL,
		0x6EBE03EEBDC528E6ULL,
		0xFB70C98A6E0E17E7ULL,
		0xCF07E09E5493A849ULL,
		0xE2E579CDF797555FULL,
		0x55B7FC31F8D7D9E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5F861955523E9EBULL,
		0x0809CA2A6369643EULL,
		0x5B4F7883783C53D6ULL,
		0x0E8C3662D79297ECULL,
		0x2E12B94418E7399CULL,
		0xE28E5C7EBD3487EAULL,
		0xA54D7725B3742600ULL,
		0xBF4DC171D2908283ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F0E11E45D0E92B0ULL,
		0x24F6C7476F947DC3ULL,
		0xAED30B51F0EDBD9AULL,
		0x0A9AA22142068B63ULL,
		0x1F8699A698CB1365ULL,
		0x9C63CAC82BE87BB8ULL,
		0x1597F8CC385B3563ULL,
		0x984ACDC3A87A6093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCACA708387D3A36AULL,
		0xE57663510C50B52CULL,
		0x8F376DA376D61E5BULL,
		0xBB4F9AAC3C63A4A1ULL,
		0x5D89E6765DB59A3CULL,
		0xE6AE0E9B9CB6E634ULL,
		0xB785AE80995350ABULL,
		0xC271FE148A285DCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5443A160D53AEF46ULL,
		0x3F8063F66343C896ULL,
		0x1F9B9DAE7A179F3EULL,
		0x4F4B077505A2E6C2ULL,
		0xC1FCB3303B157928ULL,
		0xB5B5BC2C8F319583ULL,
		0x5E124A4B9F07E4B7ULL,
		0xD5D8CFAF1E5202C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39DBEDC9BF98044AULL,
		0x41FFD067A42AB6DFULL,
		0x493BD0576BEAB3D1ULL,
		0xAB145CD4E063468BULL,
		0x38AE8792C18FA3A2ULL,
		0xF3220D65E1621589ULL,
		0xB1B13A87A159A8CEULL,
		0x093529C7D27BE740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x402BED2C09632A3BULL,
		0x63125037CEE9ACE0ULL,
		0x1C63F8D24791C4FBULL,
		0x9E4662A2B8B1551CULL,
		0xE36EEE0380AB8BB5ULL,
		0xA8D9CBCB47D30383ULL,
		0xC38150E4811D4683ULL,
		0x83039C7A89F9D111ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9B0009DB634DA0FULL,
		0xDEED802FD54109FEULL,
		0x2CD7D7852458EED5ULL,
		0x0CCDFA3227B1F16FULL,
		0x553F998F40E417EDULL,
		0x4A48419A998F1205ULL,
		0xEE2FE9A3203C624BULL,
		0x86318D4D4882162EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8E920F7F4C47D38ULL,
		0x94DE5A0B0A0BCB9DULL,
		0xDBADEDFA3718F231ULL,
		0xA4B608169C588F61ULL,
		0x5296C9BDF1B1F48AULL,
		0xB4E851ABF8E11A11ULL,
		0xD597D7ECA368F1C1ULL,
		0x1E18DD9A95842F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78AF655D8043166CULL,
		0xD2EA4BE172A5E568ULL,
		0xD3691739A10692E3ULL,
		0xDC2EFCD49863AF1CULL,
		0x0CA7F0176F8AB0DAULL,
		0x96C57A26335F65BDULL,
		0x09F4429E9E0B3246ULL,
		0x0A6CF6F91A70F543ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6039BB9A748166CCULL,
		0xC1F40E299765E635ULL,
		0x0844D6C096125F4DULL,
		0xC8870B4203F4E045ULL,
		0x45EED9A6822743AFULL,
		0x1E22D785C581B454ULL,
		0xCBA3954E055DBF7BULL,
		0x13ABE6A17B1339CDULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24456029713125DDULL,
		0x317F96E275895B88ULL,
		0x1DC373B3DD7B3D61ULL,
		0x3E9E8C22E31EB39EULL,
		0x69C899948E2E0F53ULL,
		0x2864AF16E4FFF712ULL,
		0x344C6707F898A170ULL,
		0x54EED78A3B491568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9CFC3EBA411440ULL,
		0x034024E53CAABE98ULL,
		0x122A5A606E5069B6ULL,
		0x74496D1BD54E5913ULL,
		0xB30C4A33308310BAULL,
		0xB98FAB4CD27A7A8BULL,
		0xCD98F63572B7FE41ULL,
		0x4C48DAA280A104A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4A863EAB6F0119DULL,
		0x2E3F71FD38DE9CEFULL,
		0x0B9919536F2AD3ABULL,
		0xCA551F070DD05A8BULL,
		0xB6BC4F615DAAFE98ULL,
		0x6ED503CA12857C86ULL,
		0x66B370D285E0A32EULL,
		0x08A5FCE7BAA810C5ULL
	}};
	sign = 0;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x663922CFA72060DBULL,
		0x613C91F2B6881C60ULL,
		0x380C2A0648AF1F5FULL,
		0x343E6DF9D3630178ULL,
		0xB5B490C86C10D7A1ULL,
		0x267F7AB1A94BB371ULL,
		0x0F9B366D573D51D7ULL,
		0x1C19B14F4A70EBFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9202AD01DD5CEB0ULL,
		0x1FEE432CEBCA8D88ULL,
		0x2ED05486EEBED709ULL,
		0x2948B0C242C8A606ULL,
		0x73BBF675AFDC72E9ULL,
		0x5D12ABDCF9467366ULL,
		0x25FFBFBADF976B47ULL,
		0x2B24EDF6A3A95D3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D18F7FF894A922BULL,
		0x414E4EC5CABD8ED7ULL,
		0x093BD57F59F04856ULL,
		0x0AF5BD37909A5B72ULL,
		0x41F89A52BC3464B8ULL,
		0xC96CCED4B005400BULL,
		0xE99B76B277A5E68FULL,
		0xF0F4C358A6C78EBBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA49F03A95D65A066ULL,
		0xC23D956D31B2774DULL,
		0x96926B198E03C0FCULL,
		0x4FE0C1BB4FF6C00CULL,
		0x6DA9ACC9E6E4DA84ULL,
		0x23067DECA4C992B5ULL,
		0x76175C531B4FEB67ULL,
		0x861C91AC0D104F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83087DDBBDEE8D9EULL,
		0x4D12D418C9F3E9A3ULL,
		0x1B1CA945961D2269ULL,
		0xF3431A6BBE9EAF50ULL,
		0xD4429104A4F91B5CULL,
		0xF9129D810C45840AULL,
		0x9785CAD93E1759BFULL,
		0x1A056C39DA157D61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x219685CD9F7712C8ULL,
		0x752AC15467BE8DAAULL,
		0x7B75C1D3F7E69E93ULL,
		0x5C9DA74F915810BCULL,
		0x99671BC541EBBF27ULL,
		0x29F3E06B98840EAAULL,
		0xDE919179DD3891A7ULL,
		0x6C17257232FAD21AULL
	}};
	sign = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CF5F141B854FD3BULL,
		0x64D8F4312497EE1FULL,
		0x2672A7D7C6A7656BULL,
		0x7715D0ABB552FDADULL,
		0xEA7685E64575111BULL,
		0xDE7B5375E4823872ULL,
		0x8493DD035815C89DULL,
		0x0272246A689EC4E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B80297668A221FULL,
		0xC4E4095CB1C285ADULL,
		0xC6DEAC79B36FE0D3ULL,
		0xA51745D9BBCC7A89ULL,
		0x19AF2FA061DE5002ULL,
		0x6D9834A578094907ULL,
		0x8C1FE6AC6DCB4918ULL,
		0x07D2878E3E6AF101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x373DEEAA51CADB1CULL,
		0x9FF4EAD472D56872ULL,
		0x5F93FB5E13378497ULL,
		0xD1FE8AD1F9868323ULL,
		0xD0C75645E396C118ULL,
		0x70E31ED06C78EF6BULL,
		0xF873F656EA4A7F85ULL,
		0xFA9F9CDC2A33D3E1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x504E98BEEB543D89ULL,
		0x03461348A3AB06BCULL,
		0x9BE7A7B7D1F56D4AULL,
		0xFF62B51872B76A2EULL,
		0xCA62CA9554C6354CULL,
		0x00F2435979719088ULL,
		0xD2CC3AE41195A0DCULL,
		0xD43365F00217D3FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90DF98ED55C860C1ULL,
		0xAB84428D28442698ULL,
		0xA708D2A8DBFAE246ULL,
		0x40A627D309A6A886ULL,
		0x6B2317472811B9C8ULL,
		0x3DEF547F5D634069ULL,
		0x5B5C3120171CC06BULL,
		0xCCCDF789E9978F15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF6EFFD1958BDCC8ULL,
		0x57C1D0BB7B66E023ULL,
		0xF4DED50EF5FA8B03ULL,
		0xBEBC8D456910C1A7ULL,
		0x5F3FB34E2CB47B84ULL,
		0xC302EEDA1C0E501FULL,
		0x777009C3FA78E070ULL,
		0x07656E66188044E5ULL
	}};
	sign = 0;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86B2EE2E7CAB1C78ULL,
		0x4A364AF6B9747D43ULL,
		0xA12649815DF444DAULL,
		0x59717C3B7D6BC97CULL,
		0x5759FB82FB13C5ADULL,
		0x3F03C6011C5CA69AULL,
		0x4D3F899B78BA4460ULL,
		0x0DD4B89D9C9D4CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC14B0FF555BB9F5CULL,
		0xADAE02016F73309DULL,
		0x6603D6C5B0F0DAFFULL,
		0x54BD6216E600C710ULL,
		0xAE4BB1E50E5BE95BULL,
		0xA7699FA8D83F40C1ULL,
		0x3C3F9A82CAF41C58ULL,
		0x07C13879B337B9CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC567DE3926EF7D1CULL,
		0x9C8848F54A014CA5ULL,
		0x3B2272BBAD0369DAULL,
		0x04B41A24976B026CULL,
		0xA90E499DECB7DC52ULL,
		0x979A2658441D65D8ULL,
		0x10FFEF18ADC62807ULL,
		0x06138023E96592D6ULL
	}};
	sign = 0;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x575B0F1F8C8B2C1CULL,
		0x1C1BE110DCF89F8AULL,
		0x37278360518EEC79ULL,
		0xCDAC74F874B3601BULL,
		0xE323A95F8102A5E6ULL,
		0x7341BDCB5A6ED6D0ULL,
		0x5AE53CBB6AFEF3EBULL,
		0x82B78EFDCCA08972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB73793FEB8E77E32ULL,
		0x8AD898395E3E4773ULL,
		0xA0216AF1FAF95393ULL,
		0x7C2C2CEDEA613841ULL,
		0x196CFAEA2FB8197EULL,
		0xC52801641B12A619ULL,
		0xE3AA70E59FCD85CAULL,
		0x2BC4C1CE75418CCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0237B20D3A3ADEAULL,
		0x914348D77EBA5816ULL,
		0x9706186E569598E5ULL,
		0x5180480A8A5227D9ULL,
		0xC9B6AE75514A8C68ULL,
		0xAE19BC673F5C30B7ULL,
		0x773ACBD5CB316E20ULL,
		0x56F2CD2F575EFCA3ULL
	}};
	sign = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90498D22A2DC17E2ULL,
		0x630E3A20A9192D74ULL,
		0xAC0B588C7ECBE561ULL,
		0x2BE9E8EB488E2F19ULL,
		0x689E9CC8F0E1C186ULL,
		0xF633CB1AE8FF5780ULL,
		0xA21AB659352C01D5ULL,
		0x6C57EE54C468922DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9F3F44E3F400BFULL,
		0xEF7C217623BC18E7ULL,
		0xC4AEEC30E35AC20FULL,
		0xF3987A8180204BA2ULL,
		0xC87283E84F0B8C6BULL,
		0xCB6959164C8F2C66ULL,
		0x98D1D8FD5F8A511CULL,
		0xB8EED382A933DE8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23AA4DDDBEE81723ULL,
		0x739218AA855D148DULL,
		0xE75C6C5B9B712351ULL,
		0x38516E69C86DE376ULL,
		0xA02C18E0A1D6351AULL,
		0x2ACA72049C702B19ULL,
		0x0948DD5BD5A1B0B9ULL,
		0xB3691AD21B34B3A1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A7171E82C061E5AULL,
		0x0F049B6C9F4A8BD6ULL,
		0x45D5209CDFB52FE0ULL,
		0x65E46B5018B76227ULL,
		0x666FE77CE5618A2AULL,
		0x66DE93C9785BF562ULL,
		0xD75F9078D2E9D86FULL,
		0x281EAFBD6CAAA4E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D05374B8417F63ULL,
		0x4B01109F49FFE9E5ULL,
		0x7E6A8E13BDE630AEULL,
		0x2F6210F72941BA42ULL,
		0x0E536DCD4BBC1FD7ULL,
		0xD930821965AEB8B2ULL,
		0xBD56A5BADE6272BBULL,
		0xBCE55ED10A1609A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43A11E7373C49EF7ULL,
		0xC4038ACD554AA1F0ULL,
		0xC76A928921CEFF31ULL,
		0x36825A58EF75A7E4ULL,
		0x581C79AF99A56A53ULL,
		0x8DAE11B012AD3CB0ULL,
		0x1A08EABDF48765B3ULL,
		0x6B3950EC62949B3FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FF8ED12C6D9FEB6ULL,
		0x124CF949AA0000EFULL,
		0x6EDBEFE3DB956DAAULL,
		0x2F438FC2CF65B115ULL,
		0x8CAC5E454B1677C2ULL,
		0x5CB3A4CC72EA2B68ULL,
		0xC3E0CC062EE64E39ULL,
		0xE09A768CAD0784E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AA3EEB54DCC2EAFULL,
		0x9427E98AA044D8F8ULL,
		0x72E46D0AA26B7651ULL,
		0x531E0DED6A422F5FULL,
		0x60DDD96F0E08981CULL,
		0xE1E352438682F34AULL,
		0x311DBE2445763150ULL,
		0x7E0C92ED6BD42337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9554FE5D790DD007ULL,
		0x7E250FBF09BB27F6ULL,
		0xFBF782D93929F758ULL,
		0xDC2581D5652381B5ULL,
		0x2BCE84D63D0DDFA5ULL,
		0x7AD05288EC67381EULL,
		0x92C30DE1E9701CE8ULL,
		0x628DE39F413361A9ULL
	}};
	sign = 0;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}