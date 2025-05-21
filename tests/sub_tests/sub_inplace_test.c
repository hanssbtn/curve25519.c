#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9B07801E8F029E80ULL,
		0xF0565C3F229084FDULL,
		0x4309B370F16C6794ULL,
		0x41DE5816F767DE28ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xAFD10601F02F5E1DULL,
		0x8EE68320A025243DULL,
		0xC2C45913686B56E4ULL,
		0x087B0AD77D19927FULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xEB367A1C9ED34063ULL,
		0x616FD91E826B60BFULL,
		0x80455A5D890110B0ULL,
		0x39634D3F7A4E4BA8ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4CD4F5AF0C372E1ULL,
		0x78F389FAACC7C6F9ULL,
		0x27833910BA8DF349ULL,
		0x698E55666A47B263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6119C84595B7EE6ULL,
		0xB23459FBACA85109ULL,
		0x5182DAD8122DD025ULL,
		0x04340604059CA9A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEBBB2D69767F3FBULL,
		0xC6BF2FFF001F75EFULL,
		0xD6005E38A8602323ULL,
		0x655A4F6264AB08BAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x028683787F834F9BULL,
		0x448BBEB732302784ULL,
		0xF0FDBE3EE11E204CULL,
		0x0C24E472373E79A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x417B7308DE1DDB64ULL,
		0x16CF43F1CA38BD2DULL,
		0x3109A7C80FB9040DULL,
		0x5097554044710344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC10B106FA1657424ULL,
		0x2DBC7AC567F76A56ULL,
		0xBFF41676D1651C3FULL,
		0x3B8D8F31F2CD7662ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x229BC8ABBF224BECULL,
		0xD50D1939F9C80434ULL,
		0x3F708C09635E1D71ULL,
		0x4B992C49FF0225C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC29A5BF3F29F67ULL,
		0xD1E5E11B72059860ULL,
		0xDC68E61C5B84A850ULL,
		0x558C71BD56996650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23D92E4FCB2FAC72ULL,
		0x0327381E87C26BD3ULL,
		0x6307A5ED07D97521ULL,
		0x760CBA8CA868BF73ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43BC0F30623562E7ULL,
		0xC41083754F7560EDULL,
		0x1C06F44543A4FD05ULL,
		0x77FD0E0A026BE194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C8B30330B61BD65ULL,
		0x0974A60D3348D5EBULL,
		0xC4999F9651AD0A87ULL,
		0x1AA7FAAC0E58F784ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE730DEFD56D3A582ULL,
		0xBA9BDD681C2C8B01ULL,
		0x576D54AEF1F7F27EULL,
		0x5D55135DF412EA0FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBDC63BB2C09ADF5ULL,
		0x9A0CA1E3DDCB9A06ULL,
		0xF7F0D783B6EDB150ULL,
		0x2F6DD9105D2C94E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8FAAD9F323812DBULL,
		0x34FEC2F6A23C9620ULL,
		0x922AC2732367F2F5ULL,
		0x15A170D21CC69CD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12E1B61BF9D19B1AULL,
		0x650DDEED3B8F03E6ULL,
		0x65C615109385BE5BULL,
		0x19CC683E4065F810ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E98D299FFAE15C9ULL,
		0x5D66CE092885FACEULL,
		0x26BBB5489633C212ULL,
		0x6740A5A34F418823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D801727255509B3ULL,
		0xB426811470ED2F83ULL,
		0x7D5DCABD9A7F2AD1ULL,
		0x24042579DE1424AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB118BB72DA590C16ULL,
		0xA9404CF4B798CB4AULL,
		0xA95DEA8AFBB49740ULL,
		0x433C8029712D6378ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA948060A8267B8AULL,
		0xC62B146FE956103EULL,
		0x26DE8066C5AFB447ULL,
		0x01AA34822768FF68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1254243F990DA151ULL,
		0xA73067E63FB5F894ULL,
		0xAA351F861537CD16ULL,
		0x5898EA28A03BB9DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8405C210F18DA26ULL,
		0x1EFAAC89A9A017AAULL,
		0x7CA960E0B077E731ULL,
		0x29114A59872D4588ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2707EBBE691B7FA3ULL,
		0xCA9443DEC1186CA8ULL,
		0x874DD16414AA8FB4ULL,
		0x5D167140801F11B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA59214B238CD9C75ULL,
		0xE6C2C921C53C99A5ULL,
		0x59E97BD9374EBCF7ULL,
		0x6FF59F02A256FAE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8175D70C304DE31BULL,
		0xE3D17ABCFBDBD302ULL,
		0x2D64558ADD5BD2BCULL,
		0x6D20D23DDDC816D0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C8B33E7BB37906DULL,
		0xA45E4D13401EFBC6ULL,
		0x1E03E895492F58D3ULL,
		0x6EE689FC09702EA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEA00C1D5F8A2CFCULL,
		0x59752E76441E71F9ULL,
		0x3CD7C34C954A30DBULL,
		0x1F88A119B013671EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADEB27CA5BAD6371ULL,
		0x4AE91E9CFC0089CCULL,
		0xE12C2548B3E527F8ULL,
		0x4F5DE8E2595CC782ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2056F65988AD2F67ULL,
		0x0A6BD0E608AB5FD8ULL,
		0xE3F2654CCD72DFC7ULL,
		0x12C02761A96A22E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C4115B5F250D41ULL,
		0xB34B23F0E47A34C9ULL,
		0x2EAE9816CDDC10B2ULL,
		0x4F965528A5BD3644ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D92E4FE29882213ULL,
		0x5720ACF524312B0EULL,
		0xB543CD35FF96CF14ULL,
		0x4329D23903ACEC9FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D1E4620DAA6C6EAULL,
		0xE0FBD4E8766B66A6ULL,
		0x695EE352F967A817ULL,
		0x154FAE02E3588AA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C865283D685B3BCULL,
		0x6B663D59D76E77F6ULL,
		0xA50B666D9372D112ULL,
		0x3E64E8DD7B32F827ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB097F39D0421131BULL,
		0x7595978E9EFCEEAFULL,
		0xC4537CE565F4D705ULL,
		0x56EAC52568259280ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B153956BD6D66E8ULL,
		0x92C1F1EA05B8050EULL,
		0x5E7247E70BECA2F5ULL,
		0x3A4DADFD97B75C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679385FE95018175ULL,
		0x5AB3B4C33D960357ULL,
		0x78D35E3E0478E949ULL,
		0x64CE5D0B5C82DADFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD381B358286BE560ULL,
		0x380E3D26C82201B6ULL,
		0xE59EE9A90773B9ACULL,
		0x557F50F23B348142ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x848C039AC4266C87ULL,
		0x4038B2630D900380ULL,
		0x75A1AB36CC85680BULL,
		0x2EC5AA9EDB95A91CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66B10033593556FAULL,
		0x54297321B8B6A564ULL,
		0xE745F57E0A6BD531ULL,
		0x2B1B904951949A42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DDB03676AF1158DULL,
		0xEC0F3F4154D95E1CULL,
		0x8E5BB5B8C21992D9ULL,
		0x03AA1A558A010ED9ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2891DDA1C95A7723ULL,
		0xC96C4C1BD64FE490ULL,
		0xE782CFAE4CE6C2C2ULL,
		0x0AB31A86CA37F13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF3200C9FF66BADBULL,
		0x53184188FD5EC816ULL,
		0x7BF2BF09096B818CULL,
		0x3E8A22F69DA974EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x695FDCD7C9F3BC35ULL,
		0x76540A92D8F11C79ULL,
		0x6B9010A5437B4136ULL,
		0x4C28F7902C8E7C51ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99A5895C5DBDFAA8ULL,
		0x99E792932FC28A09ULL,
		0x6F46ADB82ABE224AULL,
		0x0687C70AE606F52DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E352E07CF9D2FB6ULL,
		0x1D58D36100E55499ULL,
		0xCBEAD43965BB8B33ULL,
		0x72E05582DB24E681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B705B548E20CADFULL,
		0x7C8EBF322EDD3570ULL,
		0xA35BD97EC5029717ULL,
		0x13A771880AE20EABULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF9B7C0FFF847E63ULL,
		0x1A6A74283275474FULL,
		0xF27B59FF6BC5B964ULL,
		0x533B55A0634C8614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E2D67699BF38C3ULL,
		0x01F5D5CDA38277DAULL,
		0xED6293F1B4F9E1F2ULL,
		0x2264DD73819C3EFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADB8A59965C545A0ULL,
		0x18749E5A8EF2CF75ULL,
		0x0518C60DB6CBD772ULL,
		0x30D6782CE1B04717ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAFAE9736DC518EAULL,
		0x1A1C482B5E8091F8ULL,
		0x139225A46A97D7BAULL,
		0x0307ACAB038BA4B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B76B0A9C696D0A2ULL,
		0xB502FF521D5BE053ULL,
		0x7F6B0D610B8F43B6ULL,
		0x26326C9DAC88CDAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F8438C9A72E4835ULL,
		0x651948D94124B1A5ULL,
		0x942718435F089403ULL,
		0x5CD5400D5702D706ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x298353D9B802F780ULL,
		0x47B7E4D1B168146CULL,
		0xBE127E7AC5152D15ULL,
		0x142534C2526E9ECBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6208A9FCABA9721ULL,
		0x911BC8F95779A839ULL,
		0x3CB7BB07CF3F21CBULL,
		0x19318DF956C5502DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8362C939ED48604CULL,
		0xB69C1BD859EE6C32ULL,
		0x815AC372F5D60B49ULL,
		0x7AF3A6C8FBA94E9EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6BF425B110AB7E7ULL,
		0x1DECE4C10A8CF689ULL,
		0x179BD20A88BF0B7BULL,
		0x27ED39109BE85F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5BB8B01B7879554ULL,
		0xAB9A5885B87AC3E1ULL,
		0xE551432A964298E9ULL,
		0x23D8437F1B36D353ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE103B75959832293ULL,
		0x72528C3B521232A7ULL,
		0x324A8EDFF27C7291ULL,
		0x0414F59180B18C0DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34C5DE44B7C9C5A6ULL,
		0x87B1D17A60CAEE47ULL,
		0x632E367502613428ULL,
		0x5697188B39BF1F79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA2D69B16A5899AULL,
		0xAA115406827C64C1ULL,
		0x539642253FF6C4EEULL,
		0x52A81BE55439FA9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC72307A9A1243C0CULL,
		0xDDA07D73DE4E8985ULL,
		0x0F97F44FC26A6F39ULL,
		0x03EEFCA5E58524DAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF70E8EF0E528B1CFULL,
		0x2F39DD5A2264425EULL,
		0x1C5334C3F4692D15ULL,
		0x522E20813FCB3442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE270B5154F3F72CBULL,
		0xF2FAA424765DF00EULL,
		0x6E5C16EA6DB5DA30ULL,
		0x265B0DF921EEF926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x149DD9DB95E93F04ULL,
		0x3C3F3935AC065250ULL,
		0xADF71DD986B352E4ULL,
		0x2BD312881DDC3B1BULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07A4449223FA5336ULL,
		0x0E00595674E85F95ULL,
		0x17E3C771A2C7DB7CULL,
		0x6765BF3500F405B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3155CEA0422723BFULL,
		0x12D19834BAD08FD9ULL,
		0x4D017D211C0ADCF5ULL,
		0x6CB1C74CAC7E2A1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD64E75F1E1D32F64ULL,
		0xFB2EC121BA17CFBBULL,
		0xCAE24A5086BCFE86ULL,
		0x7AB3F7E85475DB91ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5A71C379488EBEEULL,
		0xAC2D3AAC663A7FDFULL,
		0xDE51B29DFCF71126ULL,
		0x6C0EB616C3BAB716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11BAC5AA4B1AE959ULL,
		0x1DC722F44ABFC14AULL,
		0x1CD251A84D137BCFULL,
		0x11F36AE6F528DC5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3EC568D496E0295ULL,
		0x8E6617B81B7ABE95ULL,
		0xC17F60F5AFE39557ULL,
		0x5A1B4B2FCE91DAB8ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEF96CB1CED07EADULL,
		0xDCCE58234D1CA749ULL,
		0xF088B2F2CF2C4EF6ULL,
		0x6A549D6273AF36A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21509E3A4F28C4E5ULL,
		0xB172A75C18EB9143ULL,
		0x1D6B83CEEA0435FEULL,
		0x4272C71B8343B6F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADA8CE777FA7B9C8ULL,
		0x2B5BB0C734311606ULL,
		0xD31D2F23E52818F8ULL,
		0x27E1D646F06B7FB6ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEE6F227D5718075ULL,
		0xF695FA130EE744A3ULL,
		0x2EB8379CF559DB2EULL,
		0x6E44708FCB969800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09176704BDF09EC8ULL,
		0x86923F57D7675127ULL,
		0x6DB3166C7375165DULL,
		0x075C994E92F9303FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5CF8B231780E1ADULL,
		0x7003BABB377FF37CULL,
		0xC105213081E4C4D1ULL,
		0x66E7D741389D67C0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FDB0B4A55CB1DAEULL,
		0x6BFA16976BC65B26ULL,
		0x8A439664DBFFBDE9ULL,
		0x26EAC2ECF8599DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x850782EC01621F88ULL,
		0x2CA06C6A3A19DCDBULL,
		0xF72D0C8AD1E8C51DULL,
		0x2CB010D0DEA57717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AD3885E5468FE13ULL,
		0x3F59AA2D31AC7E4AULL,
		0x931689DA0A16F8CCULL,
		0x7A3AB21C19B426D2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EE3C05C1B388D3BULL,
		0x1E2472690B90DDDEULL,
		0x6A193AD33D296DE9ULL,
		0x3D8405761C806CBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D27E63402016266ULL,
		0xA7B96D662DE53AFDULL,
		0x46D495816B1CCEB8ULL,
		0x08BFD2C9523ABEDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81BBDA2819372AD5ULL,
		0x766B0502DDABA2E1ULL,
		0x2344A551D20C9F30ULL,
		0x34C432ACCA45ADE0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04D10083ECE95541ULL,
		0x1107A5F190CB2AC0ULL,
		0x5247A22E762C490BULL,
		0x5B2C2617256A27AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26FCE59A1339A71ULL,
		0xFBC91B77FC06C021ULL,
		0xB4E41E78F211F09CULL,
		0x1F51D7FF6998894AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3261322A4BB5BAD0ULL,
		0x153E8A7994C46A9EULL,
		0x9D6383B5841A586EULL,
		0x3BDA4E17BBD19E5FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0132F31D4A970307ULL,
		0xF9FC9519CD897012ULL,
		0xA4D08B003C1E02ECULL,
		0x3DF618D131C75A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x542763D7F1CFAA10ULL,
		0x16657ADDCC987F6CULL,
		0xD3B94F0726847283ULL,
		0x253C0231058DB7B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD0B8F4558C758F7ULL,
		0xE3971A3C00F0F0A5ULL,
		0xD1173BF915999069ULL,
		0x18BA16A02C39A2A7ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33665910E47362D2ULL,
		0xD8157122D25D5679ULL,
		0x0A0B5D7B0165A010ULL,
		0x1FE7698D3163B2C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BDD65C7AA8B8FA3ULL,
		0x12FF98EE3860E02FULL,
		0x1F20B2FDA085A456ULL,
		0x0D6F333E4A4D41F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC788F34939E7D32FULL,
		0xC515D83499FC7649ULL,
		0xEAEAAA7D60DFFBBAULL,
		0x1278364EE71670D3ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82BB858A1AACABAEULL,
		0x297B7E57B1EC9D6EULL,
		0xC0D6A8975937C202ULL,
		0x6C78DC07BEDFC03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4DCAE1C96F8A0FEULL,
		0x63C8475EFA1AB37EULL,
		0xB78349890A10AC05ULL,
		0x3D7E6BDBC4F197E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDDED76D83B40AB0ULL,
		0xC5B336F8B7D1E9EFULL,
		0x09535F0E4F2715FCULL,
		0x2EFA702BF9EE2854ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC903444FF07CEFD9ULL,
		0xD0D1C925EECC3C71ULL,
		0x9D24C2104D9C980BULL,
		0x1380FFEE125C5461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x653F3799C0428977ULL,
		0x0A843B1D2AD19B1DULL,
		0x318534D15D9446FFULL,
		0x7BE91599F74BDDC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63C40CB6303A664FULL,
		0xC64D8E08C3FAA154ULL,
		0x6B9F8D3EF008510CULL,
		0x1797EA541B10769AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02365D0BC5B43242ULL,
		0x006B4DF93C514720ULL,
		0x46EDB3B4D108B6CBULL,
		0x5C2D01FD8EECE840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B46247E9A3A761EULL,
		0x22C4DFD2FB6C4A3AULL,
		0xFAA7EE6385E3E10EULL,
		0x1A381750932C7DBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6F0388D2B79BC24ULL,
		0xDDA66E2640E4FCE5ULL,
		0x4C45C5514B24D5BCULL,
		0x41F4EAACFBC06A80ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE739D845827729FULL,
		0x6465772F55334C08ULL,
		0x92B41FEB278B298BULL,
		0x7D0AD9595E07D7F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD00A0BEE670397ULL,
		0x9AEF29FFACECA163ULL,
		0x3575B66994E86510ULL,
		0x6A8803FA3BFE7E24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A3937869C06F08ULL,
		0xC9764D2FA846AAA5ULL,
		0x5D3E698192A2C47AULL,
		0x1282D55F220959CEULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B8B85067795493CULL,
		0x32F4E421B8970FE1ULL,
		0xE18E7F43953FA252ULL,
		0x528DD6A877D9DA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4766B57FB2366AAULL,
		0x93D45C7AC94A5758ULL,
		0x34C09429674CA63DULL,
		0x77004A3D43621E36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x671519AE7C71E27FULL,
		0x9F2087A6EF4CB888ULL,
		0xACCDEB1A2DF2FC14ULL,
		0x5B8D8C6B3477BC13ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70F018AA67472B5FULL,
		0x11746BFDE6CB6C60ULL,
		0xDF37A262AC5BAAABULL,
		0x3A11190DE9FD55E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE8F6C1B2FA451DULL,
		0x25105887452F2F63ULL,
		0xFD6F52BC182B236EULL,
		0x1B2AC67A14662575ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x410721E8B44CE642ULL,
		0xEC641376A19C3CFDULL,
		0xE1C84FA69430873CULL,
		0x1EE65293D5973072ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A22E7A2E2A29C9EULL,
		0x45E9BCBA04188EBEULL,
		0xE8CE87A8DD8F6CB1ULL,
		0x09BE654ADE80B414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB11BA8A9B0795986ULL,
		0x5D09086BBE741215ULL,
		0x8DCBBBA730F0448CULL,
		0x32F91562A87957EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9073EF932294305ULL,
		0xE8E0B44E45A47CA8ULL,
		0x5B02CC01AC9F2824ULL,
		0x56C54FE836075C25ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F40AAC0E7011587ULL,
		0x796D46CEBFCC84C3ULL,
		0x040E3E30288C7958ULL,
		0x2E93FC7756861936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF97E69E122703A0ULL,
		0x071403DE3746A3E6ULL,
		0x41A5A9DC4BB2A68EULL,
		0x70B8E8B868FEAC1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FA8C422D4DA11D4ULL,
		0x725942F08885E0DCULL,
		0xC2689453DCD9D2CAULL,
		0x3DDB13BEED876D16ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x983DC240062D43C3ULL,
		0x54B4DC348A1638DEULL,
		0xFE5F007C9BA19366ULL,
		0x109B76D5E0673696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x651CEDF19877D195ULL,
		0xADBDD46D5924DC12ULL,
		0x4BD5DCD72888E67BULL,
		0x6D6C5E6D480D98D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3320D44E6DB5721BULL,
		0xA6F707C730F15CCCULL,
		0xB28923A57318ACEAULL,
		0x232F186898599DC2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B8755CDFBDDB896ULL,
		0x27CF976F95FC0785ULL,
		0xA0A4544EB0395583ULL,
		0x68E1042CE1BE62C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1478A7C3EF6F880ULL,
		0x30A2059B08AD8E46ULL,
		0x110346F3AD48C3A3ULL,
		0x4B72A20F7835DFC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A3FCB51BCE6C016ULL,
		0xF72D91D48D4E793EULL,
		0x8FA10D5B02F091DFULL,
		0x1D6E621D69888302ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9528E53988E206E8ULL,
		0xAE6D8CB8CDE54F46ULL,
		0x3C180701B5AD2BCFULL,
		0x126885D256C5BA65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6419C5594EE340CULL,
		0x39BDB7B887AC6D14ULL,
		0xEC4642F03FF95BC6ULL,
		0x149E125906EC5988ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEE748E3F3F3D2C9ULL,
		0x74AFD5004638E231ULL,
		0x4FD1C41175B3D009ULL,
		0x7DCA73794FD960DCULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB9D88173AAF9EA3ULL,
		0xB8B72B6A1FE888E8ULL,
		0x925EF32E8FFBE3AAULL,
		0x5E86A3655C3FE561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4760E518347964DDULL,
		0x28603E74A0395FAAULL,
		0x49B8FC7CA2BD2E27ULL,
		0x120541F56BFDEDDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x743CA2FF063639C6ULL,
		0x9056ECF57FAF293EULL,
		0x48A5F6B1ED3EB583ULL,
		0x4C81616FF041F785ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FA9B417D4C2892AULL,
		0xCC4E2D4781FA4064ULL,
		0x99D2014A3880D5D3ULL,
		0x6D635CBF19B8BCFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D28F095C9E9792ULL,
		0xC222109D14F781F0ULL,
		0x7B57F95FAD7DA6D9ULL,
		0x1A0F43984995A263ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECD7250E7823F198ULL,
		0x0A2C1CAA6D02BE73ULL,
		0x1E7A07EA8B032EFAULL,
		0x53541926D0231A98ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CC71A5924D9DE43ULL,
		0xB047A16A4112008AULL,
		0xC8CB5948F266F4E6ULL,
		0x136EBEF8E16C4390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A13D2A4869913AULL,
		0x728B4DB57A024750ULL,
		0xDEC9CCB4A5543959ULL,
		0x6D0F5FEC09D49D30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B25DD2EDC704CF6ULL,
		0x3DBC53B4C70FB93AULL,
		0xEA018C944D12BB8DULL,
		0x265F5F0CD797A65FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE5E8543F5965059ULL,
		0x80E7CE3A8B6A2A17ULL,
		0x390A2E6E863D6358ULL,
		0x44EC5C87B332EF75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE9D31F1F2D858D1ULL,
		0x840C33F1F9DC8A20ULL,
		0x0BDE3A1174320C52ULL,
		0x3DF3E9FC4E5B934FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FC1535202BDF788ULL,
		0xFCDB9A48918D9FF7ULL,
		0x2D2BF45D120B5705ULL,
		0x06F8728B64D75C26ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD1F692EC05DC728ULL,
		0x320254CFEAC2B586ULL,
		0xA53C7954B2EA4A1DULL,
		0x55B0D5B7392B0466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8135220E5E7ECA26ULL,
		0x513F7DD628DD2BE5ULL,
		0xC4403C11A0E229E2ULL,
		0x0DA099408C24A07BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BEA472061DEFD02ULL,
		0xE0C2D6F9C1E589A1ULL,
		0xE0FC3D431208203AULL,
		0x48103C76AD0663EAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99A4D18B0C74222EULL,
		0x9F364440D6788FC9ULL,
		0xC5BAAD43E65244C0ULL,
		0x165A5A770DF68995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9288944E5DBF012ULL,
		0xC4ABA56109479DE6ULL,
		0xE1EB19E3BEC0FF0EULL,
		0x40EA271C6BECD76EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE07C484626983209ULL,
		0xDA8A9EDFCD30F1E2ULL,
		0xE3CF9360279145B1ULL,
		0x5570335AA209B226ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF2E9256E04B71FAULL,
		0xF91EDB8E7911E9D1ULL,
		0x55A44713CADD1265ULL,
		0x60944509CCAF257FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07A28DB3C5CB195ULL,
		0x3FFDA82F727D9B18ULL,
		0xB8A4903552823F6AULL,
		0x3FE994AF8E677360ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EB4697BA3EEC065ULL,
		0xB921335F06944EB9ULL,
		0x9CFFB6DE785AD2FBULL,
		0x20AAB05A3E47B21EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1645A733E6E5ECABULL,
		0x4FFA35BFDC9F2F08ULL,
		0x6A84337903431CA5ULL,
		0x6D97313C2B2F62B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC03BF9404942683ULL,
		0xC47BFCAA7EEA32A0ULL,
		0x78CE9C6C73AC463FULL,
		0x58EAEC6BBCAE6582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A41E79FE251C628ULL,
		0x8B7E39155DB4FC67ULL,
		0xF1B5970C8F96D665ULL,
		0x14AC44D06E80FD33ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0C0CA40B9193B78ULL,
		0x7F822293E8255B56ULL,
		0x7895DA01966BE987ULL,
		0x7FB38D5619FA0D7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06CB66734B9ECB19ULL,
		0xCC8251F3661A5DCFULL,
		0xFB666B44C9AE0107ULL,
		0x0B6937B02184AE49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9F563CD6D7A705FULL,
		0xB2FFD0A0820AFD87ULL,
		0x7D2F6EBCCCBDE87FULL,
		0x744A55A5F8755F35ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDABA0CF29D81958EULL,
		0x03AA201241A19BBCULL,
		0x52AFA37DAED7FA62ULL,
		0x65A568A89E31C732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E1243E0E17E9A13ULL,
		0xC9B5D3A21D895DF9ULL,
		0xC275E363F63DCCACULL,
		0x6D6420179365C0A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CA7C911BC02FB68ULL,
		0x39F44C7024183DC3ULL,
		0x9039C019B89A2DB5ULL,
		0x784148910ACC068CULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCE17A24FD5A9B0B6ULL,
		0x4E8E0F4BE94BBEB1ULL,
		0x1397E92060F56B82ULL,
		0x0163FEB81C76F6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE76700AAFDAE1C1EULL,
		0x1A5D77CFE350A19BULL,
		0x1DF7C7991F6E2137ULL,
		0x7F510DDC7CCD04E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6B0A1A4D7FB9485ULL,
		0x3430977C05FB1D15ULL,
		0xF5A0218741874A4BULL,
		0x0212F0DB9FA9F1F8ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x623926EF33F41FCAULL,
		0x201DAB481414FEB3ULL,
		0x70565E5EF805B0E9ULL,
		0x57A686AFE7B8B12BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB682BB5885D6B51ULL,
		0xF01F7FE4004629C5ULL,
		0x0946D58142FF3CFAULL,
		0x25104F6025E8709BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6D0FB39AB96B479ULL,
		0x2FFE2B6413CED4EDULL,
		0x670F88DDB50673EEULL,
		0x3296374FC1D04090ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC8F7711F2F307F47ULL,
		0x84BE7F202547AE92ULL,
		0xE17C55F3EC941F7DULL,
		0x59E9F59FAE5C4E9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74ECC5C09EC4AD93ULL,
		0xBD01F15AA6205047ULL,
		0xBF0FDB8AFCF53FF8ULL,
		0x37BE8986AD844ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x540AAB5E906BD1B4ULL,
		0xC7BC8DC57F275E4BULL,
		0x226C7A68EF9EDF84ULL,
		0x222B6C1900D803CFULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x21F6CD92ED768A5AULL,
		0x289A6F085AABB3A0ULL,
		0x34002F9C4C9519A6ULL,
		0x2AC9AA403229429EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F451A51418FA7BDULL,
		0x2E0E189B65963EF5ULL,
		0x541472374E7AFE4FULL,
		0x6E6A87F150C7BF93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12B1B341ABE6E28AULL,
		0xFA8C566CF51574ABULL,
		0xDFEBBD64FE1A1B56ULL,
		0x3C5F224EE161830AULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x268006BFBC3DB314ULL,
		0x780B0D76D8BB2F06ULL,
		0xA04795A1D6D4D3E5ULL,
		0x6FC63FAF88412CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC334FA0FF42A253ULL,
		0x36AC64CB10FBFD73ULL,
		0x47EBE151C3A694FDULL,
		0x59361C053F62B835ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A4CB71EBCFB10C1ULL,
		0x415EA8ABC7BF3192ULL,
		0x585BB450132E3EE8ULL,
		0x169023AA48DE7476ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAE06CD394150CB93ULL,
		0xC4D1C2720B6BF030ULL,
		0xF4630C2A11D237BFULL,
		0x6614D171B03CFA7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x954F18F51E28C1C9ULL,
		0xFE88371595A66C58ULL,
		0xCDB0706F60614930ULL,
		0x1B71BBC8C52A4C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18B7B444232809CAULL,
		0xC6498B5C75C583D8ULL,
		0x26B29BBAB170EE8EULL,
		0x4AA315A8EB12ADF2ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16A3C73B8AAF0DEEULL,
		0xBE9EEC422AB552EBULL,
		0xB290446702147A52ULL,
		0x353F11609B4EFE54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F864315ACEDA4C9ULL,
		0x0B61764D2AF44426ULL,
		0xE9CBB9A4F15EA1AAULL,
		0x3B87DFC7995D02C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC71D8425DDC16912ULL,
		0xB33D75F4FFC10EC4ULL,
		0xC8C48AC210B5D8A8ULL,
		0x79B7319901F1FB8FULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFD1CE6782F866430ULL,
		0xBE92F4DF9C056B2CULL,
		0xF470F8DAB43EA504ULL,
		0x7093642D36F0F9E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4CE106CDC9AF87AULL,
		0x7152AC5C9E86D5DCULL,
		0x8041F286B261F8E7ULL,
		0x6B329BD90B0B7657ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x384ED60B52EB6BB6ULL,
		0x4D404882FD7E9550ULL,
		0x742F065401DCAC1DULL,
		0x0560C8542BE5838AULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x471AA5BCA73AF14BULL,
		0x2F30550996FDF83CULL,
		0x660EB2240944455AULL,
		0x5827489C97D5673FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B1BB666B00E7A9CULL,
		0x681E872C5484487EULL,
		0x5A873A9DB79B8112ULL,
		0x0BA87B9E53C3D69EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BFEEF55F72C76AFULL,
		0xC711CDDD4279AFBEULL,
		0x0B87778651A8C447ULL,
		0x4C7ECCFE441190A1ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x99BE58C301498667ULL,
		0x151159AD83C78232ULL,
		0x0CBC2FB7795ADDF9ULL,
		0x6C84B26E2295915EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A7AAF7FE928B0DULL,
		0x789E323126BF4D47ULL,
		0xE8E0C54F08A22A56ULL,
		0x7E87B979D55E8265ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7216ADCB02B6FB47ULL,
		0x9C73277C5D0834EBULL,
		0x23DB6A6870B8B3A2ULL,
		0x6DFCF8F44D370EF8ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x72E2030CDBF5DA5EULL,
		0x3F7120B0A595DF50ULL,
		0x19CF1B53B1362714ULL,
		0x3B18E35267A6CFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4269B67C8D67B59BULL,
		0x28B0D575794945B5ULL,
		0xB0D49E381FB61166ULL,
		0x2D739713D775D489ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30784C904E8E24C3ULL,
		0x16C04B3B2C4C999BULL,
		0x68FA7D1B918015AEULL,
		0x0DA54C3E9030FB60ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA080235EC5049453ULL,
		0x3C7C89D3BD18E79BULL,
		0x59155E82F31FED0DULL,
		0x17E336012902E773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEED93A9DD28965ULL,
		0x98C97B1880840FF8ULL,
		0xAFB3E527262B7A54ULL,
		0x58EE2EB965043BBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85914A2427320ADBULL,
		0xA3B30EBB3C94D7A3ULL,
		0xA961795BCCF472B8ULL,
		0x3EF50747C3FEABB3ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE79E410AACE57760ULL,
		0xBA1E01D1BC7AAE5DULL,
		0xA1FAD05A344534B1ULL,
		0x668EE0642BF75781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A48D57B301FF4DULL,
		0x0C81AAD7DD8B4328ULL,
		0x95D93E76EF074FC9ULL,
		0x6FE9B4A2482238D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0F9B3B2F9E37800ULL,
		0xAD9C56F9DEEF6B35ULL,
		0x0C2191E3453DE4E8ULL,
		0x76A52BC1E3D51EAAULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x550D130980A309B5ULL,
		0x409922C31899D871ULL,
		0x9A90018E9906FB67ULL,
		0x64625B50B1202C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2287E1382EA524FCULL,
		0x2FE3A8D483AD320BULL,
		0xC82930071A0B674FULL,
		0x06F2ECEC29D28B45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x328531D151FDE4B9ULL,
		0x10B579EE94ECA666ULL,
		0xD266D1877EFB9418ULL,
		0x5D6F6E64874DA155ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1A4414B9FB8D6802ULL,
		0x834D1C8B39C98285ULL,
		0xB3A30DCC0199E18FULL,
		0x5D031945DA131AA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B5316DD33681BFULL,
		0xEEDA9A756F08922FULL,
		0x8FBBDB48ABB789CDULL,
		0x240D9DE5AB5C5F35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x348EE34C2856E643ULL,
		0x94728215CAC0F055ULL,
		0x23E7328355E257C1ULL,
		0x38F57B602EB6BB72ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC5C94417056DD9EDULL,
		0xB35DE0E970D167ADULL,
		0xFB803B67FB400367ULL,
		0x1DBEA890A9296122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9E6DFBF73C673FULL,
		0x1DF479113AF49B30ULL,
		0x97A30CAA9202480FULL,
		0x6CD322697EDF9C81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA62AD61B0E31729BULL,
		0x956967D835DCCC7DULL,
		0x63DD2EBD693DBB58ULL,
		0x30EB86272A49C4A1ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x39308A1543EC1F9DULL,
		0xF642C2142D856176ULL,
		0xC3ABE174F825F478ULL,
		0x0F8BF44B3EF43364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8DDBCD2B11D1A4DULL,
		0x8F4B09A870C03177ULL,
		0x8D2560260195E863ULL,
		0x0AB80B45BE4F7CFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5052CD4292CF0550ULL,
		0x66F7B86BBCC52FFEULL,
		0x3686814EF6900C15ULL,
		0x04D3E90580A4B665ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD0C3DD69A6937200ULL,
		0xBDFC7E1C9262BFEBULL,
		0x3412870932DAEFACULL,
		0x0DFF6E7523F6C7E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E9E7FC2DF0DA8BULL,
		0x19B24A5E07978E36ULL,
		0xAFF0DD1D1477FE0EULL,
		0x6D1FE1547F20ADA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36D9F56D78A29762ULL,
		0xA44A33BE8ACB31B5ULL,
		0x8421A9EC1E62F19EULL,
		0x20DF8D20A4D61A46ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF704ABA97DE8E3DAULL,
		0xF0D8AE96F35F1AF8ULL,
		0xC2896B867CAEA1ACULL,
		0x2195D9DFEB1B2E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BDA36B18E59B773ULL,
		0x5DD708BF929EB366ULL,
		0x8E19C9A8CAE50D28ULL,
		0x3F1B4337BBB244CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB2A74F7EF8F2C54ULL,
		0x9301A5D760C06792ULL,
		0x346FA1DDB1C99484ULL,
		0x627A96A82F68E9B0ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2374CC514634AEA8ULL,
		0x30221E3066E75C70ULL,
		0x1B28E1DBA8271F14ULL,
		0x025432E445FD1B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC3BC1C56038659ULL,
		0xAE1174BC1C69BE30ULL,
		0x62A684D297BBA810ULL,
		0x6FF31BF58CB913A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24B11034F031283CULL,
		0x8210A9744A7D9E3FULL,
		0xB8825D09106B7703ULL,
		0x126116EEB94407D5ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1E15D359AA4026E3ULL,
		0xB523433CE6B65A88ULL,
		0xD69D54DC2FAC39BFULL,
		0x733A9F183B62BE8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F573C2BA8D85C62ULL,
		0x5C7EB0608D350C13ULL,
		0xA1E2C21086827CF8ULL,
		0x54F43BC2839FFC54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEBE972E0167CA81ULL,
		0x58A492DC59814E74ULL,
		0x34BA92CBA929BCC7ULL,
		0x1E466355B7C2C23BULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x36C001C815C18EF6ULL,
		0xC74C2312C1E27BC5ULL,
		0x547D5082689A5A73ULL,
		0x2405CD0D676C4024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA8BA1B966A3ABDULL,
		0x6D2929CA836FAE70ULL,
		0x6F12105D6453A8D1ULL,
		0x7D1DA5171C872ACCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB91747AC7F575426ULL,
		0x5A22F9483E72CD54ULL,
		0xE56B40250446B1A2ULL,
		0x26E827F64AE51557ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDC66772720176674ULL,
		0xF78F969293D821E4ULL,
		0xA4D38FE1424DCF79ULL,
		0x2C12F5E0268153E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x263FEC0907E7960EULL,
		0x9A6483388AB661BFULL,
		0x855197B5ABD26FD1ULL,
		0x360AC831F4A3C6BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6268B1E182FD053ULL,
		0x5D2B135A0921C025ULL,
		0x1F81F82B967B5FA8ULL,
		0x76082DAE31DD8D2CULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDA422A97208A03D5ULL,
		0x8E76FD7F07A7F204ULL,
		0x8F467319C6ECCC00ULL,
		0x611F577B33318BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF517E6E389B1C9E0ULL,
		0x560E6B6F5074C573ULL,
		0x809AB8B1ADEB6757ULL,
		0x751E6AA281188541ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE52A43B396D839E2ULL,
		0x3868920FB7332C90ULL,
		0x0EABBA68190164A9ULL,
		0x6C00ECD8B2190660ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x654C85BD1E09D2F3ULL,
		0x1BDC332885F6D40CULL,
		0x445F1EB129430FE9ULL,
		0x4A0BFA2D3CB8AFD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3146C29C83E1CAULL,
		0x3AA64569338E26A3ULL,
		0xDC438E4F0B037D0CULL,
		0x35018091A96CC9A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x781B3EFA8185F129ULL,
		0xE135EDBF5268AD68ULL,
		0x681B90621E3F92DCULL,
		0x150A799B934BE633ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x36BDF563A2528024ULL,
		0x5B9923C003F215B9ULL,
		0x7A2B0095CA514AB3ULL,
		0x1B8D35ABC3E1091DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0C976933B38DE74ULL,
		0x3CE3E3AF68AAD957ULL,
		0x11CCADF33EAC94F9ULL,
		0x0DEE28315C47D0B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65F47ED06719A1B0ULL,
		0x1EB540109B473C61ULL,
		0x685E52A28BA4B5BAULL,
		0x0D9F0D7A67993864ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x29D911650B5BDAB3ULL,
		0xA4FB1B69859A3928ULL,
		0x49A215AC3F5BB00EULL,
		0x42F6B2D93AAF9444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C030B9160AE62B0ULL,
		0x376B9C3B76BD8E20ULL,
		0x9F5D567F41347B22ULL,
		0x775342AFA7FD3A5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DD605D3AAAD77F0ULL,
		0x6D8F7F2E0EDCAB08ULL,
		0xAA44BF2CFE2734ECULL,
		0x4BA3702992B259E9ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x04A0060A868BD047ULL,
		0xCE1332C1810EB01CULL,
		0x51233AC3151C04FEULL,
		0x2CD8E0CE2DE6A396ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF845C1B43A82DBDCULL,
		0x6B175DBDB34AD3CAULL,
		0x57E6B63EEEF27FBCULL,
		0x634CA761F40107CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C5A44564C08F458ULL,
		0x62FBD503CDC3DC51ULL,
		0xF93C848426298542ULL,
		0x498C396C39E59BC9ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBEF8E8196646922CULL,
		0x0AFD24A8E8B44C2CULL,
		0x4E23E8DCC71B062DULL,
		0x7E3B9B3C87C6C844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE825F8DC741D60C8ULL,
		0x3341CAF78D055126ULL,
		0x16AF59D6672C757BULL,
		0x488B80964C58E4EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6D2EF3CF2293164ULL,
		0xD7BB59B15BAEFB05ULL,
		0x37748F065FEE90B1ULL,
		0x35B01AA63B6DE35AULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x95CE53983BFECC7BULL,
		0x30BAF4FB2F10B908ULL,
		0x4C3F8821C6E5B609ULL,
		0x5206ED177D107D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D8357938A386D7CULL,
		0x0AC52E5FE6184006ULL,
		0x646A1FC618A3CAF4ULL,
		0x5F07F9D4ADEBAAACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x284AFC04B1C65EECULL,
		0x25F5C69B48F87902ULL,
		0xE7D5685BAE41EB15ULL,
		0x72FEF342CF24D2A4ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0D6161AAA97287B3ULL,
		0x8A65C998147B0669ULL,
		0x04C1E664368302AFULL,
		0x41EFB7108C95E3DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42992A1085D82952ULL,
		0x7F6F5BDB9A90110EULL,
		0x9B6BD21E2DBE1ECFULL,
		0x0917B509C8170B7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAC8379A239A5E61ULL,
		0x0AF66DBC79EAF55AULL,
		0x6956144608C4E3E0ULL,
		0x38D80206C47ED85FULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3BA0B12AB6CCA87BULL,
		0xACD0FC26D1FA52A1ULL,
		0x97A6D3BF567015F8ULL,
		0x1C5998D51826E7F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33599B2A291F9B22ULL,
		0x13CC09B878E86B32ULL,
		0xC3D1548C9BFE5B7AULL,
		0x147EA05DAFCCCC56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x084716008DAD0D59ULL,
		0x9904F26E5911E76FULL,
		0xD3D57F32BA71BA7EULL,
		0x07DAF877685A1B9BULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF0369B41474A8B6CULL,
		0x378345EB5B11CE5FULL,
		0x8B5A2965E200B7FEULL,
		0x344574DB131618F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0804B73251F1F94ULL,
		0x9D85EEAB84781014ULL,
		0x46A8870E7251D869ULL,
		0x3D247E9017A6D963ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FB64FCE222B6BC5ULL,
		0x99FD573FD699BE4BULL,
		0x44B1A2576FAEDF94ULL,
		0x7720F64AFB6F3F8FULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFF3C5FF6BF14529FULL,
		0xBD2F7FB4BCD97E20ULL,
		0xC46E2D8DDD392A46ULL,
		0x480CFD915DAE61FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E7E358AC75A8B7ULL,
		0xA98ECDD77DE208CCULL,
		0x7317B8D6976E15FEULL,
		0x165F2C235E74C8F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA547C9E129EA9E8ULL,
		0x13A0B1DD3EF77554ULL,
		0x515674B745CB1448ULL,
		0x31ADD16DFF399906ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0A6D8FB675AB5729ULL,
		0xF8F659D788D152BBULL,
		0x9540EE48FE738C16ULL,
		0x30F283DA49B41BA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD0E050FA5685A39ULL,
		0xE4F50AB6260885F8ULL,
		0x08D40EE16899341DULL,
		0x749269C1385D2E32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D5F8AA6D042FCDDULL,
		0x14014F2162C8CCC2ULL,
		0x8C6CDF6795DA57F9ULL,
		0x3C601A191156ED77ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD70A57FB95650BF6ULL,
		0xB5DB020C4EEB1FE1ULL,
		0x2838DF9902463954ULL,
		0x38B314737C82BF3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03840E5479EB46D8ULL,
		0xCBD948A39AE7655DULL,
		0x647FF6C1924A0EA4ULL,
		0x0CCAE9B7BF7560FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD38649A71B79C51EULL,
		0xEA01B968B403BA84ULL,
		0xC3B8E8D76FFC2AAFULL,
		0x2BE82ABBBD0D5E3FULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x751B957CAB68D8A5ULL,
		0xC4BE39784C70AA2CULL,
		0x51C0981C5A1A3654ULL,
		0x1D8D4B2A02DA0AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53221089CD0BBF5ULL,
		0x301E806FC337B0BAULL,
		0xAFC490BE42AD81C2ULL,
		0x6F9949DB83200948ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFE974740E981C9DULL,
		0x949FB9088938F971ULL,
		0xA1FC075E176CB492ULL,
		0x2DF4014E7FBA0162ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC863D9AB6E07CE58ULL,
		0x958F38936A1D9D4DULL,
		0x425753F1B139DB5BULL,
		0x0EE4EF7D50E4EA4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252B490AC00C5635ULL,
		0xCBEF99C185A24BFDULL,
		0xCE9EB9DD428E71C2ULL,
		0x0CED5AA8DA655F09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA33890A0ADFB7823ULL,
		0xC99F9ED1E47B5150ULL,
		0x73B89A146EAB6998ULL,
		0x01F794D4767F8B45ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5ADF035A95D76085ULL,
		0x0E20BE889DE0A9A8ULL,
		0x3D3CF2A8C151D798ULL,
		0x0D0962140E3EDEF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A95FE96DC5ADADEULL,
		0xA662AA174A807B28ULL,
		0x00961012B24EC562ULL,
		0x5EDFDADFB7573A32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD04904C3B97C8594ULL,
		0x67BE147153602E7FULL,
		0x3CA6E2960F031235ULL,
		0x2E29873456E7A4BEULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6B96F6E33F0FDBB0ULL,
		0xD2C2BD6309FC99DAULL,
		0xBA0933A6E572B37BULL,
		0x6D8CDAF7B83D1910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A5DD6285D90A59ULL,
		0x743EE7C3CA281827ULL,
		0xB8E335EF81B3BBBFULL,
		0x5003EB096EDCAB6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38F11980B936D157ULL,
		0x5E83D59F3FD481B3ULL,
		0x0125FDB763BEF7BCULL,
		0x1D88EFEE49606DA3ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF802E9F323C20613ULL,
		0xA84B0D0305065F25ULL,
		0x57DA8DD3DD3A3DB8ULL,
		0x20E08E7D60C13244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AC06E7ED4F47F3ULL,
		0xE9D532E897097E97ULL,
		0x1373F3E361240B30ULL,
		0x2B1F929D7FF2B40FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5556E30B3672BE0DULL,
		0xBE75DA1A6DFCE08EULL,
		0x446699F07C163287ULL,
		0x75C0FBDFE0CE7E35ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2A014F4DE669747DULL,
		0x36C5FA0B64CF688FULL,
		0xFC28FD91B7A2A055ULL,
		0x48147E2DA06144A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE21A2807760343C9ULL,
		0x37469CC69CB9D212ULL,
		0xF17E4F598DF5C3F5ULL,
		0x63B045AF46E7F9FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47E72746706630A1ULL,
		0xFF7F5D44C815967CULL,
		0x0AAAAE3829ACDC5FULL,
		0x6464387E59794AAAULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x76B4B56403534D80ULL,
		0xEEF9E0CBCAD8F613ULL,
		0xDA2837C8C15216F4ULL,
		0x535C889899C5EC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742E563F5524D7A7ULL,
		0xE6B666CA0FB0CAD2ULL,
		0xF52B27353F73B210ULL,
		0x42CE46CD28117F9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02865F24AE2E75D9ULL,
		0x08437A01BB282B41ULL,
		0xE4FD109381DE64E4ULL,
		0x108E41CB71B46CFFULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7C18F927E3B006DEULL,
		0xED3F4BB95C03510EULL,
		0xAF56128411EC1501ULL,
		0x5E8E9E12A70313F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF59016CA710FF08ULL,
		0xA04630FCC7D5519AULL,
		0x66BFB7D0EB3153E3ULL,
		0x4358C0295543F9D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CBFF7BB3C9F07D6ULL,
		0x4CF91ABC942DFF73ULL,
		0x48965AB326BAC11EULL,
		0x1B35DDE951BF1A20ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBB9E6EC441729CA8ULL,
		0xF8EC0FABE1818B1FULL,
		0x2BDE8BB1770B7E60ULL,
		0x6AAA5BBBB1609E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72C094961A02C3CEULL,
		0x2A67370D53534F6DULL,
		0x5DE66FB0EA96941BULL,
		0x30F0076D83F0EF76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48DDDA2E276FD8DAULL,
		0xCE84D89E8E2E3BB2ULL,
		0xCDF81C008C74EA45ULL,
		0x39BA544E2D6FAEACULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3D815EF4D6E624F4ULL,
		0x492E6A723BC9A10CULL,
		0x0886097D590D5869ULL,
		0x670D9F217D9C7FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E2AD5FCC55F0745ULL,
		0xF83FBCD4FF43EA50ULL,
		0x47B527256F69384DULL,
		0x6D9A0C1DB3F690A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF5688F811871D9CULL,
		0x50EEAD9D3C85B6BBULL,
		0xC0D0E257E9A4201BULL,
		0x79739303C9A5EEFCULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB6CD45404C30763EULL,
		0x9AAFD8E575D1A94BULL,
		0xC54CA6A6F24F88BCULL,
		0x4E655B009D48E31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x306781199DE849B9ULL,
		0xF742FCE9E9D3EEF3ULL,
		0xCB40BCD054EDA2A3ULL,
		0x2803BF06F0360544ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8665C426AE482C85ULL,
		0xA36CDBFB8BFDBA58ULL,
		0xFA0BE9D69D61E618ULL,
		0x26619BF9AD12DDD8ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6C8A69A9E0C9E82BULL,
		0x5FFE29E0DB108C76ULL,
		0x2B5BCA258A6F8BF8ULL,
		0x03C33377A31C177BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EAB2E508271C86DULL,
		0xA02740CA1BF1CF3BULL,
		0x25653313EABC9A99ULL,
		0x41FFEE0023DA5BB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DDF3B595E581FABULL,
		0xBFD6E916BF1EBD3BULL,
		0x05F697119FB2F15EULL,
		0x41C345777F41BBCAULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA0C8E3BFF46B8F72ULL,
		0x8240978DEA7A5057ULL,
		0x9C4212EB950D9A22ULL,
		0x20D794902FCF497EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD44DCC2C7E5408ULL,
		0x5B61B9527AE5579DULL,
		0x8BD46CDF348EE85DULL,
		0x67BB3947FFB52E43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73F495F3C7ED3B57ULL,
		0x26DEDE3B6F94F8BAULL,
		0x106DA60C607EB1C5ULL,
		0x391C5B48301A1B3BULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCB2D11FDEC8D8077ULL,
		0x266856D959298C19ULL,
		0x504F86C0A9678EF0ULL,
		0x73E60F5D49503EE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB5D6AFA8D551C31ULL,
		0xA4D07A0E90C52582ULL,
		0x68FF2938C1D74686ULL,
		0x5FAC2BD4F5047DBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFCFA7035F386446ULL,
		0x8197DCCAC8646696ULL,
		0xE7505D87E7904869ULL,
		0x1439E388544BC129ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9779CE9A22E76A24ULL,
		0x04B0BE48DCED8FD8ULL,
		0x2117AB2C6B7DF20FULL,
		0x4F104D8556740D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F218F30A82D89E7ULL,
		0x92BFA15F77BB97B2ULL,
		0xDB5F4F1680A60A81ULL,
		0x634EC69F26047C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48583F697AB9E02AULL,
		0x71F11CE96531F826ULL,
		0x45B85C15EAD7E78DULL,
		0x6BC186E6306F90DDULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x27ED101AE527728CULL,
		0xE280CCE02CCEEE6CULL,
		0x10717068932DBA6AULL,
		0x4FA06C7BF884DBBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BF14E2F73C7F536ULL,
		0x2D17D760037CB069ULL,
		0x49C3AD035EC59A71ULL,
		0x7A25ABADCC351B9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBFBC1EB715F7D43ULL,
		0xB568F58029523E02ULL,
		0xC6ADC36534681FF9ULL,
		0x557AC0CE2C4FC01FULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCD4E80286E580249ULL,
		0x973892643A88F703ULL,
		0x9F14BDBC78DF50CFULL,
		0x0C96F600471658A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E4FB2D5B976B67FULL,
		0x72E610C21FCE2B7AULL,
		0xEADD7FE7D70F9CFFULL,
		0x000CD13D0EADB28CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EFECD52B4E14BCAULL,
		0x245281A21ABACB89ULL,
		0xB4373DD4A1CFB3D0ULL,
		0x0C8A24C33868A61BULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA4F4E561632BDCA0ULL,
		0x1ED37B73CC775459ULL,
		0xAB2F0FBF98C613A5ULL,
		0x6F0D97DD71D023E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0925FDA97646520FULL,
		0xFBA28C5786BE3553ULL,
		0xACE643E5BAB32AB4ULL,
		0x2DDDA436C7FEED89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BCEE7B7ECE58A91ULL,
		0x2330EF1C45B91F06ULL,
		0xFE48CBD9DE12E8F0ULL,
		0x412FF3A6A9D1365BULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2E8A42F4B806F637ULL,
		0xB50570AA8EDA3720ULL,
		0xD71F435E35A39998ULL,
		0x1249CE9CEFCCC394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2525FDF27B1563BAULL,
		0x52228AF5EB01BAB3ULL,
		0xA1142A42722823AEULL,
		0x00539DDC59BC3255ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x096445023CF1927DULL,
		0x62E2E5B4A3D87C6DULL,
		0x360B191BC37B75EAULL,
		0x11F630C09610913FULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF77706E57E404B8AULL,
		0x8255B41D55226699ULL,
		0x3E9374345686086AULL,
		0x236C1EE3D2986088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C5CA657BD0D314ULL,
		0x10257AF5D97FF3CAULL,
		0xD398E425A45E34A8ULL,
		0x7F173B9F34E71552ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3B13C80026F7863ULL,
		0x723039277BA272CFULL,
		0x6AFA900EB227D3C2ULL,
		0x2454E3449DB14B35ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCEB73FD8852607FDULL,
		0xCD559EA8960608B3ULL,
		0xBD9CC9486806D68EULL,
		0x4F04E9AA87D40C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E5FAB19249D8926ULL,
		0x4D6E9D8634C44EAEULL,
		0xF140B4DBC959CF1BULL,
		0x201A36D306D7971BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x305794BF60887ED7ULL,
		0x7FE701226141BA05ULL,
		0xCC5C146C9EAD0773ULL,
		0x2EEAB2D780FC7569ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x096FCD17828969E9ULL,
		0xBFB39A14FCB22802ULL,
		0x42AD25B090D0F3CEULL,
		0x225E1F96652638ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57CC3460FA622C2AULL,
		0xEE443728A1088BDFULL,
		0x3B4186670EB110C8ULL,
		0x201857FB8AE25524ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1A398B688273DBFULL,
		0xD16F62EC5BA99C22ULL,
		0x076B9F49821FE305ULL,
		0x0245C79ADA43E387ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6017D36BE704D4F8ULL,
		0x436BB6945CCDE2D0ULL,
		0x9475136670B19E8EULL,
		0x658EE76D2EDA1F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x813E0621B32E056EULL,
		0x2F0875F335235A8CULL,
		0xCC66F1278C65D9C2ULL,
		0x26B491330C0E9ED3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDED9CD4A33D6CF8AULL,
		0x146340A127AA8843ULL,
		0xC80E223EE44BC4CCULL,
		0x3EDA563A22CB808AULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF1B57E7C20767B06ULL,
		0xC6352CEA01697478ULL,
		0xB28DEEB65A1C5E27ULL,
		0x71EB89337EF996A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6DE5E14F445097BULL,
		0xC417A885BFCF876EULL,
		0xC4CDD363C8619D5AULL,
		0x02C7A22FD72ABDAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AD720672C31718BULL,
		0x021D84644199ED0AULL,
		0xEDC01B5291BAC0CDULL,
		0x6F23E703A7CED8F6ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA3B8FC2804DB2DC2ULL,
		0xDA67939DF98BC570ULL,
		0x7B10DBC412515EA0ULL,
		0x0CFCF488D49C386FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x193D0D95E3335488ULL,
		0x73DF2EC01E5E0307ULL,
		0xAEACE5D38BDF3B32ULL,
		0x6CEAD7D93975C305ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A7BEE9221A7D927ULL,
		0x668864DDDB2DC269ULL,
		0xCC63F5F08672236EULL,
		0x20121CAF9B267569ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7301B6C91B39702BULL,
		0x04329329F17200A2ULL,
		0x565A324046F17054ULL,
		0x20E39E93C4745970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5936FD1ED1ABDBFULL,
		0xF5119E509F6EDB85ULL,
		0xB2A088AC369C3624ULL,
		0x3F8122A451F642A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D6E46F72E1EB259ULL,
		0x0F20F4D95203251CULL,
		0xA3B9A99410553A2FULL,
		0x61627BEF727E16C8ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8490D2D5A500E980ULL,
		0xAA43AAC8E49165E3ULL,
		0xA64C2CE5FDCBEC9BULL,
		0x39DE25D0BFC7A73BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x511BB2B586029028ULL,
		0x409F152FCC7B89CDULL,
		0xEE87948F81C9FA49ULL,
		0x41F24733825FEDAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x337520201EFE5945ULL,
		0x69A495991815DC16ULL,
		0xB7C498567C01F252ULL,
		0x77EBDE9D3D67B98BULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDEEA20EC0CBEEFBBULL,
		0x6717B95772A7A666ULL,
		0xD530E2A4B76E35F7ULL,
		0x61FB5A5C7D2178D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA882D6F948B45FB9ULL,
		0xEE77CA1F821F46C3ULL,
		0x323E01431F1C2FCCULL,
		0x197525ACB7C1292BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x366749F2C40A9002ULL,
		0x789FEF37F0885FA3ULL,
		0xA2F2E1619852062AULL,
		0x488634AFC5604FAAULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCA64098076A2E3C9ULL,
		0xF4131F36DC29D826ULL,
		0x98365B5CACB36AA7ULL,
		0x093A7B0AE1765E9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE313E9D1E3D4E7D8ULL,
		0xA38A476E4ABE9F65ULL,
		0x6F181A4ED34A49A3ULL,
		0x7037169E6782D935ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7501FAE92CDFBDEULL,
		0x5088D7C8916B38C0ULL,
		0x291E410DD9692104ULL,
		0x1903646C79F38568ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x969598AB467A5472ULL,
		0xA28B1D3727E67B5EULL,
		0x10CDE092451AAF0CULL,
		0x6F95B59FAECD4288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7934079F7491EE7ULL,
		0xA4168CA004021B6AULL,
		0xC9349720DA77B29AULL,
		0x0DD2C6B64EE7D9A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF0258314F31358BULL,
		0xFE74909723E45FF3ULL,
		0x479949716AA2FC71ULL,
		0x61C2EEE95FE568DFULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7CD89F06E9DBCE14ULL,
		0x56FA40FDCB2A8345ULL,
		0x2FB8BFF807AAF05DULL,
		0x5A2B6FCC05CD7A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF40D4FE2DF2D1B20ULL,
		0xF0085369C5893BFBULL,
		0xF7F5BD125AE27A94ULL,
		0x45A3B0CA9189CE09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88CB4F240AAEB2F4ULL,
		0x66F1ED9405A14749ULL,
		0x37C302E5ACC875C8ULL,
		0x1487BF017443AC62ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1B6079F6FF6785D3ULL,
		0xF74E3A8CD82751FCULL,
		0x730B421CC8C5838EULL,
		0x3D2400B3098D4534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58847C0A5428C467ULL,
		0x4FF645C8F4C47BFCULL,
		0xD19726671FF56B63ULL,
		0x480E87D975E59ED5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2DBFDECAB3EC159ULL,
		0xA757F4C3E362D5FFULL,
		0xA1741BB5A8D0182BULL,
		0x751578D993A7A65EULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x39F06F254E6E8DBBULL,
		0xFA6849670C803002ULL,
		0xD0C0E1A5D5E92D72ULL,
		0x235B375C7CC14B90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EAA9DD12BF1DC6ULL,
		0xB9CB807EEACFAA03ULL,
		0xD5210050DEA5F57CULL,
		0x3C99CEB56B0E46F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0405C5483BAF6FE2ULL,
		0x409CC8E821B085FFULL,
		0xFB9FE154F74337F6ULL,
		0x66C168A711B3049BULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x695CC216F7C0B221ULL,
		0x41DAA22B97D4D8B4ULL,
		0x21BA73096DB553B6ULL,
		0x74E7C1DF9E520869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5837E43F46A8DAE1ULL,
		0xE020427125D46804ULL,
		0x2024D9EA0AF1174AULL,
		0x6DE3C5A3FE0FDBD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1124DDD7B117D740ULL,
		0x61BA5FBA720070B0ULL,
		0x0195991F62C43C6BULL,
		0x0703FC3BA0422C90ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7778F653B91AD1F7ULL,
		0x4A80F8787394C2FFULL,
		0x7EC91EBD949947F8ULL,
		0x29A7825D62333A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC2FB9B6492542ABULL,
		0x55D1EAF7072F788CULL,
		0x24A4A56D0034F7F6ULL,
		0x2A3E9A478E267A3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B493C9D6FF58F39ULL,
		0xF4AF0D816C654A72ULL,
		0x5A24795094645001ULL,
		0x7F68E815D40CC014ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x159EAE0D2DFA8166ULL,
		0xA179AE636F11A1D4ULL,
		0xF7E6090C6F2C9D9EULL,
		0x2131901C646CA5CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4CD859D17AB79ABULL,
		0xA4C011F505DE8213ULL,
		0x2919E71E1C1E918FULL,
		0x5EF29BBCD8E2462DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70D12870164F07A8ULL,
		0xFCB99C6E69331FC0ULL,
		0xCECC21EE530E0C0EULL,
		0x423EF45F8B8A5FA2ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8C446CCF644458C6ULL,
		0x970DD337327AE6DCULL,
		0xBDAFE4827E402A7CULL,
		0x3C18F571CB2B87CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2964E97763B31CCULL,
		0x63080000245B3C8BULL,
		0x0CA5975689D6279BULL,
		0x6D7274663C074DA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99AE1E37EE0926E7ULL,
		0x3405D3370E1FAA50ULL,
		0xB10A4D2BF46A02E1ULL,
		0x4EA6810B8F243A2AULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2980FB7EC2F4881CULL,
		0x309FC78CEC27C8E2ULL,
		0xD98837A2DD2B54D7ULL,
		0x572AEC9D8B00D49DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD90430AE988BEC24ULL,
		0x4A5F9D205366ADDCULL,
		0x3AF01F73521C8507ULL,
		0x4DB802BB76E7B70BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x507CCAD02A689BF8ULL,
		0xE6402A6C98C11B05ULL,
		0x9E98182F8B0ECFCFULL,
		0x0972E9E214191D92ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD61EDA474A5B38D3ULL,
		0xE35B59806AEC7318ULL,
		0x882F8C9691F9DFB3ULL,
		0x7A53E53F8EE93E51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x664ECC29146A1F5CULL,
		0x31D178ABD4889FB6ULL,
		0x993138C4245A55EAULL,
		0x65CC9CDB66294FBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FD00E1E35F11977ULL,
		0xB189E0D49663D362ULL,
		0xEEFE53D26D9F89C9ULL,
		0x1487486428BFEE91ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x646BC4DAEC50E8CBULL,
		0x985FA161426AED92ULL,
		0x9A17EF7C01CAF54DULL,
		0x7B51F19E99FE323EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD285747EB3D7CB5BULL,
		0x9CEBC47E0BD93F20ULL,
		0x27C4816F4B95B17EULL,
		0x2D03AE6F654FFB50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91E6505C38791D70ULL,
		0xFB73DCE33691AE71ULL,
		0x72536E0CB63543CEULL,
		0x4E4E432F34AE36EEULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE03F08F96B4F07E1ULL,
		0x3D2E840849F0CDC0ULL,
		0xCA9C0CDBF0B5E227ULL,
		0x7A5A2366C7A5239AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x083E6F866A41AFD9ULL,
		0x2C5A270723C7BA4BULL,
		0xA1F8972CC7251BCEULL,
		0x768639623C97F224ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8009973010D5808ULL,
		0x10D45D0126291375ULL,
		0x28A375AF2990C659ULL,
		0x03D3EA048B0D3176ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB92E455257D6BC24ULL,
		0x59177837D757A953ULL,
		0x485FBBA75CB0F200ULL,
		0x69DC21F595C660C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF04B0F4BC21425B4ULL,
		0x670D7CEF2D9C9C0BULL,
		0x0AC2638E518B1829ULL,
		0x63E8334120AA571CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8E3360695C29670ULL,
		0xF209FB48A9BB0D47ULL,
		0x3D9D58190B25D9D6ULL,
		0x05F3EEB4751C09ACULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x553C1506A1998773ULL,
		0xA9776DA65FDA242EULL,
		0x10F5C0178EF40A7FULL,
		0x289B42B39D47D5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66DEB6282B34CFCCULL,
		0xA45CBA4772AE2989ULL,
		0xBB84CFC6D6853C9FULL,
		0x718AAF22F529CD02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE5D5EDE7664B794ULL,
		0x051AB35EED2BFAA4ULL,
		0x5570F050B86ECDE0ULL,
		0x37109390A81E08DDULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x430D336D3DCD39C2ULL,
		0x731861FC9C8EFA78ULL,
		0x8289DA3F945C2802ULL,
		0x6B4B1601E2C26F47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4E9642780F29CDULL,
		0x175886565C501860ULL,
		0x5E3504DED5CFCEB1ULL,
		0x68F2918A48E8AA7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4BE9D2AC5BE0FF5ULL,
		0x5BBFDBA6403EE217ULL,
		0x2454D560BE8C5951ULL,
		0x0258847799D9C4CCULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x04251EC635055B9DULL,
		0x381A24B32CF459A2ULL,
		0x7DEAE0634398F55BULL,
		0x51E3B21D5B75B8C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72A4D0280E15BFA6ULL,
		0xC1DFCCD8B07D7812ULL,
		0x98C63C835BFCC954ULL,
		0x2BF5AC4DB6920CAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91804E9E26EF9BF7ULL,
		0x763A57DA7C76E18FULL,
		0xE524A3DFE79C2C06ULL,
		0x25EE05CFA4E3AC14ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDE6363A8E73A284CULL,
		0xD176B507E16FDC4AULL,
		0xB511430F983C0900ULL,
		0x2842CF81F10C81B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BD9B2EC11CD35DULL,
		0xD79D9E1632BC5526ULL,
		0x0DB8BBAE2EC6D165ULL,
		0x5BFC9CB1D0D391F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DA5C87A261D54DCULL,
		0xF9D916F1AEB38724ULL,
		0xA75887616975379AULL,
		0x4C4632D02038EFBBULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCE3D12A4CD24AF52ULL,
		0xC44B2E4641E3F510ULL,
		0x10DF86CCA052F4ECULL,
		0x4ED2D92D5D3EBD63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1962DB0F918D9575ULL,
		0x1D64C3673AD32408ULL,
		0x9DBC415E414A5E0AULL,
		0x3296B85433AD1211ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4DA37953B9719DDULL,
		0xA6E66ADF0710D108ULL,
		0x7323456E5F0896E2ULL,
		0x1C3C20D92991AB51ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x02242D8827B1E16CULL,
		0x1A32856A6BD3A7AFULL,
		0xD818AEBA3DCD1358ULL,
		0x59456DADF69C0E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8545EF300BB1342BULL,
		0x2A34BB1973F4CE98ULL,
		0xEEF188C1E57EE749ULL,
		0x5B135AD47DD9C1AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CDE3E581C00AD2EULL,
		0xEFFDCA50F7DED916ULL,
		0xE92725F8584E2C0EULL,
		0x7E3212D978C24CCCULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBF2BB4A66056D175ULL,
		0xBA51ABEAD4FAFBB9ULL,
		0x8A6BDDA2E62B57E0ULL,
		0x25A7C9C5DEC9F3D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB1A92DACB214F8FULL,
		0xE86B6B894D7C6EC6ULL,
		0xCF7A00B56752E544ULL,
		0x62FA415FFC5F72A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD41121CB953581D3ULL,
		0xD1E64061877E8CF2ULL,
		0xBAF1DCED7ED8729BULL,
		0x42AD8865E26A8131ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEFBB9584ADB42FA3ULL,
		0x0E2C7A7148059927ULL,
		0x6EDCF240E4AA51B3ULL,
		0x0F6072AA197D306EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CB9C2C9F7795A8ULL,
		0x93C9E74CFF348B41ULL,
		0xDA57D9159447CEBFULL,
		0x6F5E41135220A74EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76EFF9580E3C99E8ULL,
		0x7A62932448D10DE6ULL,
		0x9485192B506282F3ULL,
		0x20023196C75C891FULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6E3C1A4396A4F187ULL,
		0xEF16035F504D5795ULL,
		0xDAC3AE2C79AA7844ULL,
		0x10A4016F869ADA18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB882EC6080C23AAULL,
		0x080073D9D2669F06ULL,
		0xD97F5BA1B766D24EULL,
		0x6752D45870870355ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2B3EB7D8E98CDCAULL,
		0xE7158F857DE6B88EULL,
		0x0144528AC243A5F6ULL,
		0x29512D171613D6C3ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5B807166EED28B60ULL,
		0x6A4005C1956F74AFULL,
		0xD3EEB25FFEDA5DDCULL,
		0x134CD84CA87736A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94693ED5ED41D0F8ULL,
		0x7039F902E85FA14CULL,
		0xA252A58FDFB41E97ULL,
		0x40290DE920221FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC71732910190BA55ULL,
		0xFA060CBEAD0FD362ULL,
		0x319C0CD01F263F44ULL,
		0x5323CA63885516F9ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5105471A7423D0EFULL,
		0xAAFF0FA74959A9ABULL,
		0x7DED99C9CF62D4F8ULL,
		0x235815A937111C40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D7803E537882029ULL,
		0x99E24EDBB1F86781ULL,
		0xE27EAEB66FE03601ULL,
		0x6F89DE4A935863D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x338D43353C9BB0B3ULL,
		0x111CC0CB9761422AULL,
		0x9B6EEB135F829EF7ULL,
		0x33CE375EA3B8B869ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4A1D8003B1B69647ULL,
		0xF777FB503C287959ULL,
		0x13B5087D6CCFBA4EULL,
		0x5B5A9E56A8D5A223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x901B3520E3910361ULL,
		0x6C3EC1E6B30D8838ULL,
		0xC3649AB6CB989E99ULL,
		0x770F8289A4FFB45DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA024AE2CE2592D3ULL,
		0x8B393969891AF120ULL,
		0x50506DC6A1371BB5ULL,
		0x644B1BCD03D5EDC5ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD3C5D19D9E187BA8ULL,
		0x8E442CD58A73CD93ULL,
		0x256115E0508D56A6ULL,
		0x050F8A69851F1444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4655791D8F5312ULL,
		0xD7AEE3143872D4BEULL,
		0xDBAA359BE1BE23D6ULL,
		0x1A6E55B3B4698299ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x087F7C2480892883ULL,
		0xB69549C15200F8D5ULL,
		0x49B6E0446ECF32CFULL,
		0x6AA134B5D0B591AAULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x705E00CF77AB87D8ULL,
		0x8A88C54638DDECE8ULL,
		0x0B5FC3A779920401ULL,
		0x50E19585586ABEF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x558346DDEF931F8AULL,
		0xB8AB77CC37E6D9CFULL,
		0xBB24DDBF16AE1513ULL,
		0x7DEEC985D77675EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1ADAB9F18818683BULL,
		0xD1DD4D7A00F71319ULL,
		0x503AE5E862E3EEEDULL,
		0x52F2CBFF80F44904ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1D976FB8578707F1ULL,
		0x4447C1DD7F7A9BC6ULL,
		0x8A144AD56726D63AULL,
		0x00CBE3CFA509787FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C3A1F88F4657ED6ULL,
		0xB5E96E024A872EABULL,
		0x19AE40F2DD954CDDULL,
		0x5A2D7AE7B617DC7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE15D502F63218908ULL,
		0x8E5E53DB34F36D1AULL,
		0x706609E28991895CULL,
		0x269E68E7EEF19C03ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF4B9E2ADAF896EA7ULL,
		0xC71F2447B8ED9E07ULL,
		0x13944904E23EA42DULL,
		0x231B36AB744F94AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A9462D5E471B91ULL,
		0x548FA1360CED7D96ULL,
		0xFACA2F5BF102781BULL,
		0x5124144FCB7CCAF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13109C8051425303ULL,
		0x728F8311AC002071ULL,
		0x18CA19A8F13C2C12ULL,
		0x51F7225BA8D2C9BBULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x82C5F5581E08C560ULL,
		0x5F3BCA696FC07A02ULL,
		0xD6E144B032C2CAB7ULL,
		0x3BED00FFC33FC82FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CC0C3ED3E90EFBEULL,
		0xF9DDC17EDEDE33ACULL,
		0x894B17E3973091ECULL,
		0x028FC49938907426ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0605316ADF77D5A2ULL,
		0x655E08EA90E24656ULL,
		0x4D962CCC9B9238CAULL,
		0x395D3C668AAF5409ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEFC895A8F30A9D0AULL,
		0xAC7D8853E850371AULL,
		0xD68B9B0B2253D33AULL,
		0x77D507F36F9ECF48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA78C255443724C2CULL,
		0x7B0CA7618772B663ULL,
		0x7506A61FB85FD193ULL,
		0x11C82AC3AEA05F3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x483C7054AF9850DEULL,
		0x3170E0F260DD80B7ULL,
		0x6184F4EB69F401A7ULL,
		0x660CDD2FC0FE700EULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0F43E404E6B437DEULL,
		0x7A0895E4CD2EEAB0ULL,
		0x7E1747D57FA815C5ULL,
		0x1F9FDEC664F46DA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0BF928D2CC2088BULL,
		0xBAD44F0678DEDEB2ULL,
		0x420764F3018514ADULL,
		0x4FE6477DDFC8543BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E845177B9F22F40ULL,
		0xBF3446DE54500BFDULL,
		0x3C0FE2E27E230117ULL,
		0x4FB99748852C196EULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x100C6D812CD3047BULL,
		0xF326E8D17E5D9C88ULL,
		0xB30EA3ECDA4ABC6EULL,
		0x18EC6AD80B912ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB83B12791C4E952BULL,
		0x58D5C96C17C76D55ULL,
		0x4B6DFA561D1C70F0ULL,
		0x65A4E7886439D155ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57D15B0810846F3DULL,
		0x9A511F6566962F32ULL,
		0x67A0A996BD2E4B7EULL,
		0x3347834FA7575977ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4DA2AA683FB0ECA3ULL,
		0x8D72E66C10529F77ULL,
		0xE16F83D809DF8818ULL,
		0x76D60423B714025FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A10746DC636E78ULL,
		0x5E7BED0BB53E4123ULL,
		0x51D5E19736D795C8ULL,
		0x581F94A423D5ADA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0501A321634D7E2BULL,
		0x2EF6F9605B145E54ULL,
		0x8F99A240D307F250ULL,
		0x1EB66F7F933E54B6ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x85F3008BE87087DDULL,
		0xE7839D070CFF3C15ULL,
		0x77DE153CA203A46AULL,
		0x7E37057F8F90B94CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E625805B340E6AULL,
		0x323B63592B52EF7DULL,
		0x08B8040ECA341EE6ULL,
		0x61298846BC669216ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE0CDB0B8D3C7973ULL,
		0xB54839ADE1AC4C97ULL,
		0x6F26112DD7CF8584ULL,
		0x1D0D7D38D32A2736ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x56F950CE2FE5113DULL,
		0x02F41C949369CB05ULL,
		0x4FE3884125EC6EDCULL,
		0x50A32D3A4C382D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AD2B2A5492AFF85ULL,
		0x15BFACB34409A0CEULL,
		0xE6718DEE6EF94898ULL,
		0x17797F60485C7125ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC269E28E6BA11B8ULL,
		0xED346FE14F602A36ULL,
		0x6971FA52B6F32643ULL,
		0x3929ADDA03DBBC22ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF3234956FD2B770CULL,
		0x9130F0481740E939ULL,
		0x3DC97F2A4D7CFEABULL,
		0x3ED488425A4455D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D84C671ADAF6276ULL,
		0x5754EAF4D1830A7BULL,
		0x4EC62276365E5D06ULL,
		0x51646E69BF0990A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA59E82E54F7C1483ULL,
		0x39DC055345BDDEBEULL,
		0xEF035CB4171EA1A5ULL,
		0x6D7019D89B3AC529ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x342D034649751437ULL,
		0xBC1FE7C552E108DBULL,
		0x58FC5B4C2C029EE6ULL,
		0x4D1797AFA04571D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x618FABC5D3AD0D4FULL,
		0xF35C25D9AFAB8ED4ULL,
		0x1BE30EE37BDC6DAAULL,
		0x05134BCD4EE363EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD29D578075C806E8ULL,
		0xC8C3C1EBA3357A06ULL,
		0x3D194C68B026313BULL,
		0x48044BE251620DE7ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3FE0232780C51A9DULL,
		0x42174AAA994C7E62ULL,
		0x1D3B727D3280D4CCULL,
		0x3B138C2138EE705DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7658A3E56C0E4F23ULL,
		0xD12D987F2034D64BULL,
		0x4A59C347AA308E27ULL,
		0x288A21B43454933CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9877F4214B6CB7AULL,
		0x70E9B22B7917A816ULL,
		0xD2E1AF35885046A4ULL,
		0x12896A6D0499DD20ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x906A5CA29DD2C755ULL,
		0x46E0D77A1CE747F9ULL,
		0xC8C4D02AB82CE43EULL,
		0x113CBA100A7F032FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB143D9AFEA8000DFULL,
		0x254DBF0CAC85BB99ULL,
		0xE330F66F337A95C9ULL,
		0x6D3C370EAD8FEFFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF2682F2B352C663ULL,
		0x2193186D70618C5FULL,
		0xE593D9BB84B24E75ULL,
		0x240083015CEF1331ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2835BC890D759990ULL,
		0x98A3891C1DDB2E3FULL,
		0x2FE3E421A9E7692AULL,
		0x3DF96EE7ACD9F4B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9017D8A936616DD8ULL,
		0xCC79289B5CAFF9E3ULL,
		0x6B480311DEAF68E8ULL,
		0x32F7C1809E3D1371ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x981DE3DFD7142BB8ULL,
		0xCC2A6080C12B345BULL,
		0xC49BE10FCB380041ULL,
		0x0B01AD670E9CE146ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5ED8B93F5ACF93E5ULL,
		0x233F5A89BE9CAF36ULL,
		0xB866A9232EF5F98FULL,
		0x724FCE4FE7A39259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39CDB821F91C4BC2ULL,
		0xDA6F33C764BDFC88ULL,
		0xD26CA0479731BCCBULL,
		0x6C0027A85DA5AF35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x250B011D61B34823ULL,
		0x48D026C259DEB2AEULL,
		0xE5FA08DB97C43CC3ULL,
		0x064FA6A789FDE323ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDC1F97EF22520AF4ULL,
		0x957FEC1EECB3C4B7ULL,
		0x56A527C5565330D4ULL,
		0x04F3496A84D71EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44BC7CCA7F37DD09ULL,
		0x3A00F6AAA15DC03CULL,
		0x6DAD661D263DA944ULL,
		0x5C2A9C676A970AB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97631B24A31A2DD8ULL,
		0x5B7EF5744B56047BULL,
		0xE8F7C1A830158790ULL,
		0x28C8AD031A4013FFULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5823358C3CD99809ULL,
		0x9D338067627474F5ULL,
		0x44463A5DA5D3B8EEULL,
		0x2FFCF89D4F14DCD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D9992E65069DE3ULL,
		0xD59D2206D9FB1906ULL,
		0x352DEFFD4182FC8CULL,
		0x24778A6CD3F23058ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3499C5DD7D2FA26ULL,
		0xC7965E6088795BEEULL,
		0x0F184A606450BC61ULL,
		0x0B856E307B22AC80ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAAB3EE6A8CE4220EULL,
		0x82B4D0C3A1C9AD24ULL,
		0xF4634131A3FD67E2ULL,
		0x0BFD65790E9EACB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CA2FFEB2114E33ULL,
		0xA53452B5A26F8D9CULL,
		0x9841057C0B629C04ULL,
		0x448657BAC414358AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1E9BE6BDAD2D3C8ULL,
		0xDD807E0DFF5A1F87ULL,
		0x5C223BB5989ACBDDULL,
		0x47770DBE4A8A772EULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEE91437720BC6B0DULL,
		0xE68094E59641C57FULL,
		0x0798663E898217C7ULL,
		0x1F347A129529B34DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE12581269FBD5521ULL,
		0xCCCA8E840ED4F7B6ULL,
		0x582ACBC5AA9AE3E1ULL,
		0x04C75DAC480F25B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D6BC25080FF15ECULL,
		0x19B60661876CCDC9ULL,
		0xAF6D9A78DEE733E6ULL,
		0x1A6D1C664D1A8D9CULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8107262985DDD236ULL,
		0xF6CA510B7BF2594BULL,
		0x8DA6CE7C5DDE1608ULL,
		0x1802FF14304D88F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8631CE91919EE5ULL,
		0xF25CD5EBF01A6C04ULL,
		0x34BB39120E8B1D63ULL,
		0x706C1FBC02B2A4E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3480F45AF44C333EULL,
		0x046D7B1F8BD7ED47ULL,
		0x58EB956A4F52F8A5ULL,
		0x2796DF582D9AE408ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB6F244D2A2D8FD47ULL,
		0x3C9018D6E2A69E14ULL,
		0x7A681EDEA5C135D9ULL,
		0x1674662B1100C81BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE83F0B1D38C95D7ULL,
		0xBAEA8A53F1368FC0ULL,
		0x7C045FFD8427B809ULL,
		0x7AFEF7E98A8A959DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD86E5420CF4C675DULL,
		0x81A58E82F1700E53ULL,
		0xFE63BEE121997DCFULL,
		0x1B756E418676327DULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEED1E2F9DC58C527ULL,
		0x5097054273F0AE3DULL,
		0x21E1E167E6FC1F0FULL,
		0x097F4215A278396CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CCBF5D0F435339BULL,
		0x6F21C56589354259ULL,
		0x36DCBB0D094CBD6EULL,
		0x4D153FF8E8CD6F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7205ED28E8239179ULL,
		0xE1753FDCEABB6BE4ULL,
		0xEB05265ADDAF61A0ULL,
		0x3C6A021CB9AACA3BULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x31E18FF3F9907400ULL,
		0xC2ED3D20AC74D063ULL,
		0xC606E43E88F30AB9ULL,
		0x3E0D23F31326AFC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x143C056B28DC2434ULL,
		0xD6AC4D6982F86C47ULL,
		0xBD464F5C20F82CA9ULL,
		0x125649341E50D056ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DA58A88D0B44FCCULL,
		0xEC40EFB7297C641CULL,
		0x08C094E267FADE0FULL,
		0x2BB6DABEF4D5DF6FULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA03C9CAA7D04DB81ULL,
		0xA89458AFE31C7718ULL,
		0x41599C0FEDF59994ULL,
		0x76A6AA3FFF3C4C7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4173A6C3E8F3E9A9ULL,
		0x8666DC47CBF85208ULL,
		0xF16A9C81AE16F5BCULL,
		0x3F3B5FF7F5F7D0FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EC8F5E69410F1D8ULL,
		0x222D7C6817242510ULL,
		0x4FEEFF8E3FDEA3D8ULL,
		0x376B4A4809447B7CULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2CEE8EDAEBDF5B0FULL,
		0x5C1C2AE893AE202BULL,
		0x9629823C440372DCULL,
		0x508312571A14664FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CA26C5ED74D955FULL,
		0xF1BAB35C42884FDEULL,
		0xF0B62E4173AC071BULL,
		0x7AE40EAE28CE4A20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x904C227C1491C59DULL,
		0x6A61778C5125D04CULL,
		0xA57353FAD0576BC0ULL,
		0x559F03A8F1461C2EULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x02B21D1285FACC5BULL,
		0x9952ADD053CB540FULL,
		0xF6E445D94F7D00DCULL,
		0x1A2FC15DA57A1732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE7117EB039367EBULL,
		0xD8947E60A8866025ULL,
		0x0B983484EA6448F0ULL,
		0x0365C6230540B4C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1441052782676470ULL,
		0xC0BE2F6FAB44F3E9ULL,
		0xEB4C11546518B7EBULL,
		0x16C9FB3AA039626EULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x01F58439AD39D794ULL,
		0x1D7451FF57C7B933ULL,
		0xEDE4D8CB25A65C96ULL,
		0x4E4DC688BEAB7BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19505D5E1AF83D57ULL,
		0xCA3250DBB880B1BFULL,
		0x675C3046CD92EEBBULL,
		0x23880A50CE7C78D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8A526DB92419A3DULL,
		0x534201239F470773ULL,
		0x8688A88458136DDAULL,
		0x2AC5BC37F02F02EFULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x911F191F24D6CD0BULL,
		0xC7AC94559401C412ULL,
		0xAF06D007C6F149BDULL,
		0x18156B946EE34EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0EE68F3E834669DULL,
		0x68C55D6402CDB6BDULL,
		0x2A26B444E01D303BULL,
		0x275DEB9C9C97D3F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA030B02B3CA2665BULL,
		0x5EE736F191340D54ULL,
		0x84E01BC2E6D41982ULL,
		0x70B77FF7D24B7B06ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA32ECA7D3C7A658CULL,
		0x3D8AFC445A371AD4ULL,
		0xCC836440D0121D68ULL,
		0x0ECD340EFF159E42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5502B28D40A0FF8ULL,
		0x8C67DBBFD1189A6BULL,
		0x928B966D6E0BC1B0ULL,
		0x30D5FFFFA0F269C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDDE9F5468705581ULL,
		0xB1232084891E8068ULL,
		0x39F7CDD362065BB7ULL,
		0x5DF7340F5E23347BULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE073FFBDE7BD8042ULL,
		0x9662A0D8F5A2DB6AULL,
		0x75186B82E02B9016ULL,
		0x4D327B85A080806DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF9E697C4D64EF2AULL,
		0x530CE4D470A3CEA8ULL,
		0xA5FD72E96BF9BD0AULL,
		0x7CEF4BB0F8C79023ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0D596419A589105ULL,
		0x4355BC0484FF0CC1ULL,
		0xCF1AF8997431D30CULL,
		0x50432FD4A7B8F049ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x551F7A7F44A51AB2ULL,
		0x4FF2F8A0D175720AULL,
		0x9198F1A9E0387AD4ULL,
		0x08A1C081FC218D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC7809E76513CF4ULL,
		0x954ECB493D6C34BAULL,
		0xC78E10BEB0943CC3ULL,
		0x5B13E69899155665ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD557F9E0CE53DDABULL,
		0xBAA42D5794093D4FULL,
		0xCA0AE0EB2FA43E10ULL,
		0x2D8DD9E9630C372EULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6A5C78B07E84BCE8ULL,
		0xD1B44FA6BEA5C6AEULL,
		0x3C0AA52D43386794ULL,
		0x694286972871E66DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9716F056B7D6D59BULL,
		0xA2A9C51C73AB422CULL,
		0x6AB754B1C8AF4A92ULL,
		0x05958087A3F337B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3458859C6ADE74DULL,
		0x2F0A8A8A4AFA8481ULL,
		0xD153507B7A891D02ULL,
		0x63AD060F847EAEB8ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB8E273EDD5E10CE8ULL,
		0x64C09F57A2F62E5BULL,
		0x07E3564FEBA86B02ULL,
		0x5184C5BCF5FB314BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA350A85948F533DULL,
		0x54C22EE02195F9E5ULL,
		0xEB0A33EB8E1BD860ULL,
		0x29DDBC1E9D5153C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEAD69684151B9ABULL,
		0x0FFE707781603475ULL,
		0x1CD922645D8C92A2ULL,
		0x27A7099E58A9DD81ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD348C322AF9A5286ULL,
		0x60D9D1F56AB27EFCULL,
		0xD47062F492661EF6ULL,
		0x1A7AA762DFD1186EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B9A942D463D132ULL,
		0xB6F5AD00BD3E9AF7ULL,
		0x9C4170E129413689ULL,
		0x40F9BF8A07E92A09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC8F19DFDB368141ULL,
		0xA9E424F4AD73E404ULL,
		0x382EF2136924E86CULL,
		0x5980E7D8D7E7EE65ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x35A07CD64B8DA1D5ULL,
		0x26FA20C042CD9DB5ULL,
		0xF13B18EFDA943599ULL,
		0x2E7EAFACEE6957E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x204EA86CDC37EB6EULL,
		0xA78F15A3D551C564ULL,
		0xD5C7C5ED83CB10E7ULL,
		0x51B91E8493039351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1551D4696F55B654ULL,
		0x7F6B0B1C6D7BD851ULL,
		0x1B73530256C924B1ULL,
		0x5CC591285B65C496ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0E21340992556C4DULL,
		0xEFCE27286D92F1F7ULL,
		0xA4DEA77D137B324AULL,
		0x71C5A9AD4BF3B5ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40FB79F316AE3760ULL,
		0xA7EB6DD01E7C5B44ULL,
		0x1C1ED1DA9B44AF67ULL,
		0x62EA275B877AA0EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD25BA167BA734EDULL,
		0x47E2B9584F1696B2ULL,
		0x88BFD5A2783682E3ULL,
		0x0EDB8251C47914BFULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDA02B923B85CA5A6ULL,
		0xBD42CF279CA03CDAULL,
		0x6E7121692E052A42ULL,
		0x388F2F6D564DA901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E47388ECC22F9CULL,
		0x8F676630BD1F834AULL,
		0xEA6DE053986A9FC0ULL,
		0x4730C785BE561D3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x811E459ACB9A75F7ULL,
		0x2DDB68F6DF80B990ULL,
		0x84034115959A8A82ULL,
		0x715E67E797F78BC5ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x891DB68B8C0A3E03ULL,
		0xD673515E6D77205EULL,
		0x76DC7D60CE25F039ULL,
		0x7F0087AEB166068FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8850C139DA52E119ULL,
		0xD715728555ACD442ULL,
		0x3E8EF854BCA53107ULL,
		0x13303E221B5E5FD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00CCF551B1B75CEAULL,
		0xFF5DDED917CA4C1CULL,
		0x384D850C1180BF31ULL,
		0x6BD0498C9607A6BBULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8753FDB27C6450FAULL,
		0x9E8D73DA20E187BAULL,
		0x7B115630BC6AC30AULL,
		0x6D2ECE1E27F67CC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB885FC39DF5574FDULL,
		0x32315D06E73DCACBULL,
		0x68FF499AF24553DCULL,
		0x5DE381801B80CF2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCECE01789D0EDBFDULL,
		0x6C5C16D339A3BCEEULL,
		0x12120C95CA256F2EULL,
		0x0F4B4C9E0C75AD98ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7840CD46435576DEULL,
		0xA4282A4C864EC8E2ULL,
		0x0ED553DF2B31E213ULL,
		0x0B23C4A6103DF67CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB56458F942979462ULL,
		0x4277A67D1158CB75ULL,
		0x9511CBFCE61A32FDULL,
		0x3D3E5B8D960607BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2DC744D00BDE269ULL,
		0x61B083CF74F5FD6CULL,
		0x79C387E24517AF16ULL,
		0x4DE569187A37EEC0ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7B8CAB202A0946BBULL,
		0x0AF498A3EBC5E382ULL,
		0x4A6737C5DC921899ULL,
		0x1E0FF47C0A62F24CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7E6CB8488734F60ULL,
		0x872AD9949120FB50ULL,
		0x688A05A2B10AF2B5ULL,
		0x49C79F0927E96A2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3A5DF9BA195F748ULL,
		0x83C9BF0F5AA4E831ULL,
		0xE1DD32232B8725E3ULL,
		0x54485572E279881DULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x49F8154AE4B97742ULL,
		0x395E8959515944BEULL,
		0xF31419A7EBE82A6FULL,
		0x06CD0D3F045932AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955056DF8D79A3B6ULL,
		0xEF843561B3462BCDULL,
		0xFF40611666704E85ULL,
		0x109FF9B6FB7E9717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4A7BE6B573FD379ULL,
		0x49DA53F79E1318F0ULL,
		0xF3D3B8918577DBE9ULL,
		0x762D138808DA9B92ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDCF484E74DACEE1EULL,
		0x2707324D3DDDB8D3ULL,
		0x6F217406AA76C276ULL,
		0x6E102DCA102B7BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65FE6BAEF7B5B45FULL,
		0x8E3952FFCD1130A8ULL,
		0x34BB688344A3DE32ULL,
		0x6D850AA943A5E357ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76F6193855F739BFULL,
		0x98CDDF4D70CC882BULL,
		0x3A660B8365D2E443ULL,
		0x008B2320CC859858ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x952481C6A7A71DDFULL,
		0xD832A31B9A2D1C3BULL,
		0xDAFDCFF73D71A59CULL,
		0x2D391B06A30F3953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E9007C339D8DF2ULL,
		0xA900B82197BBC477ULL,
		0x16E063D55D49E370ULL,
		0x3FDC8B2D275EF282ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x233B814A74098FDAULL,
		0x2F31EAFA027157C4ULL,
		0xC41D6C21E027C22CULL,
		0x6D5C8FD97BB046D1ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB39426B887912E33ULL,
		0x5D88B1E315C81FF5ULL,
		0xA02827006D635A37ULL,
		0x7EEF34A4D7FEF012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7FECF78485A6435ULL,
		0x51AA4304B37A80D2ULL,
		0x1716EEC9416A7A33ULL,
		0x5A710AC495196925ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB9557403F36C9FEULL,
		0x0BDE6EDE624D9F22ULL,
		0x891138372BF8E004ULL,
		0x247E29E042E586EDULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD259A48EF06AD4A1ULL,
		0x990FACB403812B6DULL,
		0xDE51ADDEF221C3AEULL,
		0x409BB3CCFCB7E8E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E200763113755CULL,
		0x8995FE3C9DE043B5ULL,
		0x6AF3169D0EBC544DULL,
		0x1F9D71FE1B6622FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7877A418BF575F45ULL,
		0x0F79AE7765A0E7B8ULL,
		0x735E9741E3656F61ULL,
		0x20FE41CEE151C5E6ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9A46EECCB2347AE3ULL,
		0x5A32D1E9209D4276ULL,
		0x35246EFBCCE77A49ULL,
		0x17447CF4452D26D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE555DABD72847F6AULL,
		0xB2C7745AD7F1D343ULL,
		0x3ACA153C0A693182ULL,
		0x2D4D999EE977D88BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4F1140F3FAFFB66ULL,
		0xA76B5D8E48AB6F32ULL,
		0xFA5A59BFC27E48C6ULL,
		0x69F6E3555BB54E49ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x24BADF9C54FD37FAULL,
		0x7A8AC898872A64BEULL,
		0xB3729366D63743E1ULL,
		0x6EB7F3AC5FD1D377ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF25B6FA385A51ADCULL,
		0x7FD1CEA9613A185CULL,
		0x4CD30EDC29728D40ULL,
		0x369871955BB9D3C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x325F6FF8CF581D1EULL,
		0xFAB8F9EF25F04C61ULL,
		0x669F848AACC4B6A0ULL,
		0x381F82170417FFB2ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5A53535372AA4170ULL,
		0xE1A355ED9A50C222ULL,
		0x3C20266696CF2D68ULL,
		0x39CCEC812E4AE99EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE76E42D26CD039AULL,
		0x2E332EAE93614272ULL,
		0xACAF7C6E1E5B3B83ULL,
		0x7F6D90B281232D10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BDC6F264BDD3DC3ULL,
		0xB370273F06EF7FAFULL,
		0x8F70A9F87873F1E5ULL,
		0x3A5F5BCEAD27BC8DULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x59B6C244C4C277DDULL,
		0x821A8E64C574EF56ULL,
		0xF905DD7B728EA412ULL,
		0x36550763610A3B25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73CB24BC115FEF1AULL,
		0x494D6C763928F691ULL,
		0xC34E15E8A14B341BULL,
		0x6C82D389974701B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5EB9D88B36288B0ULL,
		0x38CD21EE8C4BF8C4ULL,
		0x35B7C792D1436FF7ULL,
		0x49D233D9C9C3396FULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x714D48728181F525ULL,
		0x47B03A2296229EBEULL,
		0x460C2CC216C48902ULL,
		0x3551D7173E4A37D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6BB2ED6FEB4B3E8ULL,
		0xE29A769FA0A10735ULL,
		0x8C903D34394B0202ULL,
		0x1C23E682EEDD1E15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A92199B82CD413DULL,
		0x6515C382F5819788ULL,
		0xB97BEF8DDD7986FFULL,
		0x192DF0944F6D19C1ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6985B8AFC4692EDAULL,
		0x463B472678089BAAULL,
		0x0FFCD424E31BF9C7ULL,
		0x3D3ACC01D99A384BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BAF092827371B7FULL,
		0x8A87092EBFDB7977ULL,
		0x3D39DCE1000D59F6ULL,
		0x2E3DF0B1239169C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DD6AF879D32135BULL,
		0xBBB43DF7B82D2233ULL,
		0xD2C2F743E30E9FD0ULL,
		0x0EFCDB50B608CE86ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x59BE7EC1CF1AEB4DULL,
		0xC353AA434C59662BULL,
		0xB859FA9A26347647ULL,
		0x59D5AF0C0BDA674AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E23A1D4FA99A104ULL,
		0x08C09E796E392259ULL,
		0x82C9A100204B862BULL,
		0x669ACC1BF07A3303ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B9ADCECD4814A36ULL,
		0xBA930BC9DE2043D2ULL,
		0x3590599A05E8F01CULL,
		0x733AE2F01B603447ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD5CAB8B7499116C5ULL,
		0x21CC4EA8D5AD1B30ULL,
		0x7686B801AA082380ULL,
		0x7E868CFC0F82CCC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B324BAC7FC85578ULL,
		0x2A7C2336A006EC88ULL,
		0x043AD24A16470F5FULL,
		0x6FAE2CEAAC45ABA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA986D0AC9C8C14DULL,
		0xF7502B7235A62EA8ULL,
		0x724BE5B793C11420ULL,
		0x0ED86011633D2123ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x721E50F9D111E7C1ULL,
		0x0F3F580CA3B41D86ULL,
		0xBC82DDDC10DF31C2ULL,
		0x697A6DF70F5A3863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE131D124B69DB200ULL,
		0x4D2DBEBFA5EA5B59ULL,
		0x24EE5B2D5BF8C2F1ULL,
		0x1CEBF0E4C98CE6CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90EC7FD51A7435C1ULL,
		0xC211994CFDC9C22CULL,
		0x979482AEB4E66ED0ULL,
		0x4C8E7D1245CD5198ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x11C9499286BD1BB7ULL,
		0x538CF6C25239D7EAULL,
		0x85F4735B5E585404ULL,
		0x0EE775243F476CA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A22EE88CCC31D2AULL,
		0x2F3BC450798C3456ULL,
		0x9C0E0B4DFA14449CULL,
		0x55570F170803A178ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7A65B09B9F9FE7AULL,
		0x24513271D8ADA393ULL,
		0xE9E6680D64440F68ULL,
		0x3990660D3743CB2EULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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