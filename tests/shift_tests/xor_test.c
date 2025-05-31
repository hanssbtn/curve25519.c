#include "../tests.h"

int32_t curve25519_key_xor_test(void) {
	printf("Key XOR Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6467DBCB5FF79C59ULL,
		0xAB8C038FB7CEE37EULL,
		0xF15E8DD103A91C5CULL,
		0x7BE951F67A27EBF0ULL,
		0xE66D920EE669A5C8ULL,
		0x134D290E22CBFF3EULL,
		0x7EEE96478512E866ULL,
		0xBBD643143B7E924BULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x68541CD42200B567ULL,
		0x0BC53889534A3366ULL,
		0x95F848302AAAAB9FULL,
		0x024BB7241E076959ULL,
		0x539777FC31B42673ULL,
		0xB70078CB0B401A53ULL,
		0xA7697BB388CBEFC4ULL,
		0xBCC507E5F0BE0B93ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x0C33C71F7DF7293EULL,
		0xA0493B06E484D018ULL,
		0x64A6C5E12903B7C3ULL,
		0x79A2E6D2642082A9ULL,
		0xB5FAE5F2D7DD83BBULL,
		0xA44D51C5298BE56DULL,
		0xD987EDF40DD907A2ULL,
		0x071344F1CBC099D8ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF497F7E841261A7ULL,
		0x21721EFD994693FEULL,
		0x392C22B5042B5566ULL,
		0xBD26A40781486325ULL,
		0xAE36C5C0318C6554ULL,
		0x0B5AEB0C6C9EB239ULL,
		0x873D232EF165F864ULL,
		0x1DEA86034512DA82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C47F8F28C605E0ULL,
		0x040CF4F66DB701DFULL,
		0x0DEE86B3A0CB4A31ULL,
		0x9BD911948BC76ADCULL,
		0x61746B6601CEE524ULL,
		0x4C4602750828B3CFULL,
		0xBD0842DE803B7315ULL,
		0x190F31A74EE08C04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B8D00F1ACD46447ULL,
		0x257EEA0BF4F19221ULL,
		0x34C2A406A4E01F57ULL,
		0x26FFB5930A8F09F9ULL,
		0xCF42AEA630428070ULL,
		0x471CE97964B601F6ULL,
		0x3A3561F0715E8B71ULL,
		0x04E5B7A40BF25686ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13335252BCCFB4A6ULL,
		0xAA80BDAF21D3DE1CULL,
		0x247F3EED730DBBF4ULL,
		0x145A7678C10F9F5AULL,
		0x86865999B7DB9171ULL,
		0x60721675B0F67B0FULL,
		0x4543C8DF2CB7EEB1ULL,
		0x6A227136E42F9141ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC985ED4D5E15744ULL,
		0x57719277D8C74B22ULL,
		0xC1E3B2D3F73D54B6ULL,
		0xBECAFEE7887C75DEULL,
		0x343C11CC37CAA93FULL,
		0x53499E1ECEE68AB3ULL,
		0x9B6ED59329B99E6CULL,
		0x0F3CB91E34E1F69CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFAB0C86692EE3E2ULL,
		0xFDF12FD8F914953EULL,
		0xE59C8C3E8430EF42ULL,
		0xAA90889F4973EA84ULL,
		0xB2BA48558011384EULL,
		0x333B886B7E10F1BCULL,
		0xDE2D1D4C050E70DDULL,
		0x651EC828D0CE67DDULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7D2834A206B57FFULL,
		0x5F1AFBE2F74FDFE0ULL,
		0xFB9A57C7F14AA919ULL,
		0x982F3D39D0B020B5ULL,
		0xA282D403309ECE02ULL,
		0x1677C3C805210668ULL,
		0xF5C5338E9AA03A15ULL,
		0xAD63CD1B851EA986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x637226BD8165CEEBULL,
		0x0EE270F1E7F6DD7CULL,
		0x6B44CCA2142C6A44ULL,
		0x6EE05B2935521800ULL,
		0x63EFA59EA2AA67D6ULL,
		0x72BFC1E9A9BC7986ULL,
		0x98905FBE260C5B7CULL,
		0x6C1F4356221EE220ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84A0A5F7A10E9914ULL,
		0x51F88B1310B9029CULL,
		0x90DE9B65E566C35DULL,
		0xF6CF6610E5E238B5ULL,
		0xC16D719D9234A9D4ULL,
		0x64C80221AC9D7FEEULL,
		0x6D556C30BCAC6169ULL,
		0xC17C8E4DA7004BA6ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52898A7791B8E471ULL,
		0x996DE917ECD400FAULL,
		0x302B4E1081B9A0CAULL,
		0x469C68B70C4E81F3ULL,
		0x012D4A7558C1A013ULL,
		0xC3D3FD5122061334ULL,
		0xEFCC072951CF7741ULL,
		0xFAB03E85D0EC2C26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B12F184346A61D1ULL,
		0x6C333F9A8AE68DBBULL,
		0xC7598101AC6BB4DFULL,
		0x7F06E454B623C1DEULL,
		0x8BD7576EC053C9A5ULL,
		0x335E221E6234B12BULL,
		0x2C044EEB2971E36FULL,
		0xBF59B8443A5EA406ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x799B7BF3A5D285A0ULL,
		0xF55ED68D66328D41ULL,
		0xF772CF112DD21415ULL,
		0x399A8CE3BA6D402DULL,
		0x8AFA1D1B989269B6ULL,
		0xF08DDF4F4032A21FULL,
		0xC3C849C278BE942EULL,
		0x45E986C1EAB28820ULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8128A1D1C5933257ULL,
		0x141780DD03DC2653ULL,
		0x5FD814EB5D35DEC2ULL,
		0x421FDB2DBB44F75EULL,
		0x62501EED5F1C83E5ULL,
		0x7687EA0A16959563ULL,
		0xD656A15D0E2EA3FBULL,
		0xC735558DA0209F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x103080DFD87AF9B7ULL,
		0x4FBB9CEFEFE5768AULL,
		0x5280860FBED5CEB9ULL,
		0x3FC9CAF042498BC9ULL,
		0x739B4932A458066AULL,
		0x859B92C4EDB35794ULL,
		0xE8455A52EF608213ULL,
		0x5FF730A104A40D3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9118210E1DE9CBE0ULL,
		0x5BAC1C32EC3950D9ULL,
		0x0D5892E4E3E0107BULL,
		0x7DD611DDF90D7C97ULL,
		0x11CB57DFFB44858FULL,
		0xF31C78CEFB26C2F7ULL,
		0x3E13FB0FE14E21E8ULL,
		0x98C2652CA4849224ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09D88C6F252C839FULL,
		0x9454744EA77040A6ULL,
		0x6DBB46373C78D604ULL,
		0x98A93016E77BB6BBULL,
		0xCB151B4C85C100E2ULL,
		0xDEC60A0111733140ULL,
		0x7FB6572510412AE6ULL,
		0x8A207FAB4258F028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D617FAD6FD313FULL,
		0x4BA48C7262E4795BULL,
		0x4D4081F09B096057ULL,
		0x46B8F14B58AC73E0ULL,
		0x77737CC3CBB91A72ULL,
		0xF952A22292B7F1CEULL,
		0x0A1AE629B3167304ULL,
		0x3DC49C6907C57375ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B0E9B95F3D1B2A0ULL,
		0xDFF0F83CC59439FDULL,
		0x20FBC7C7A771B653ULL,
		0xDE11C15DBFD7C55BULL,
		0xBC66678F4E781A90ULL,
		0x2794A82383C4C08EULL,
		0x75ACB10CA35759E2ULL,
		0xB7E4E3C2459D835DULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC9BA54ED4057A7FULL,
		0x8CEF562C128D1136ULL,
		0xA91F77D2C1EE5FB7ULL,
		0x014B58D4A88B11CCULL,
		0x4528DF79B317DB97ULL,
		0xB7A179F0DC849B44ULL,
		0x31CCEADFA8F5E2A7ULL,
		0xB424D5105F22FF47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415528C2A49B2F3BULL,
		0x5B2D1FBF446ED7B2ULL,
		0x5763CA11D57C4C56ULL,
		0x777E406E41CECED9ULL,
		0x67FF0CD065B9393EULL,
		0x49201ABC33859BB6ULL,
		0x15B6798C55E8F94BULL,
		0xD1AB4450F52F8D8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DCE8D8C709E5544ULL,
		0xD7C2499356E3C684ULL,
		0xFE7CBDC3149213E1ULL,
		0x763518BAE945DF15ULL,
		0x22D7D3A9D6AEE2A9ULL,
		0xFE81634CEF0100F2ULL,
		0x247A9353FD1D1BECULL,
		0x658F9140AA0D72CDULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5C0921D8E36644CULL,
		0xD815441C3E1D04C9ULL,
		0x7AEA27B21DAB52F9ULL,
		0x679EA86213972CA0ULL,
		0x0159B1E2BA858E30ULL,
		0x777A10CC0BE6386FULL,
		0x1866A15EFAEDF25EULL,
		0xDF17D62D190409EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B1901EE817DD92ULL,
		0xD244709C2E76FE8EULL,
		0x2D2A48211DC9954FULL,
		0x1C2AD2D1F860B9A7ULL,
		0x9C8D6BA238E4F086ULL,
		0xC0530761E92D839DULL,
		0xD5454BC8CDA6A87DULL,
		0xCC74AD33A139739BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x277102036621B9DEULL,
		0x0A513480106BFA47ULL,
		0x57C06F930062C7B6ULL,
		0x7BB47AB3EBF79507ULL,
		0x9DD4DA4082617EB6ULL,
		0xB72917ADE2CBBBF2ULL,
		0xCD23EA96374B5A23ULL,
		0x13637B1EB83D7A71ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3751D2C0D6787CD0ULL,
		0x79EFBEA94B6AA427ULL,
		0x6A74C6225E90DFCCULL,
		0xC5768FD26A6351C4ULL,
		0x45A0B818A22FFBCAULL,
		0x2F339BC9CCB11579ULL,
		0xA6F9E2ADA7C1CD7AULL,
		0x26F54CC1D382947AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x596C3015AE8CDF13ULL,
		0x03F74FE6A78FD58AULL,
		0x07F6BC8D88C7722CULL,
		0xF9D29A40040B1F61ULL,
		0xB85A1DE47CE350C2ULL,
		0x578E370E96161FE1ULL,
		0x50F3668D73AE0CE4ULL,
		0x55E8C23961698AA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E3DE2D578F4A3C3ULL,
		0x7A18F14FECE571ADULL,
		0x6D827AAFD657ADE0ULL,
		0x3CA415926E684EA5ULL,
		0xFDFAA5FCDECCAB08ULL,
		0x78BDACC75AA70A98ULL,
		0xF60A8420D46FC19EULL,
		0x731D8EF8B2EB1ED8ULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93DF5FDD0DDFEB11ULL,
		0x98149C9286691A06ULL,
		0xD03AE321646E786EULL,
		0xD5471D8FD5AF9A23ULL,
		0x7AF63D1EC09F2295ULL,
		0xD8CF7C161C4C96D6ULL,
		0xF09D788E10E643D5ULL,
		0x563058838C00B583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D8144AAE5F471AFULL,
		0xC96FFEDD4C55EE40ULL,
		0xAB767680A93D97DFULL,
		0x94F8FCA98A88213DULL,
		0x5453EB20B40F4860ULL,
		0xFB63726ADC25C6C2ULL,
		0xC6BDA5C491977B08ULL,
		0xFDD9FFEBB7FD5C90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E5E1B77E82B9ABEULL,
		0x517B624FCA3CF446ULL,
		0x7B4C95A1CD53EFB1ULL,
		0x41BFE1265F27BB1EULL,
		0x2EA5D63E74906AF5ULL,
		0x23AC0E7CC0695014ULL,
		0x3620DD4A817138DDULL,
		0xABE9A7683BFDE913ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76B13DD0921D845CULL,
		0xD91B4A2866B6D154ULL,
		0x643741E9144AF6A6ULL,
		0x8FB87514EE49490BULL,
		0x71F427253CE3CEFBULL,
		0x673B6A4C8F5B174DULL,
		0xA874B1CDA7373D26ULL,
		0x1E712472EC1D855DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBB97C1DEB36133ULL,
		0xCF8962AD2C7996A8ULL,
		0x3C2A8900C7E843B7ULL,
		0x45BD5C46B598A1FBULL,
		0xA42D2877E78C9C49ULL,
		0x13AA95254127766DULL,
		0x94DB9883D8200565ULL,
		0x9C58C812B471C7B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B0AAA114CAEE56FULL,
		0x169228854ACF47FCULL,
		0x581DC8E9D3A2B511ULL,
		0xCA0529525BD1E8F0ULL,
		0xD5D90F52DB6F52B2ULL,
		0x7491FF69CE7C6120ULL,
		0x3CAF294E7F173843ULL,
		0x8229EC60586C42EEULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6427636826489E8CULL,
		0x84F305876A8EF206ULL,
		0x96785933BAD390F4ULL,
		0x22F8BFF50F63204AULL,
		0x063A9A3A967CD18EULL,
		0x880534FD597CB34EULL,
		0x863DC514D1E4FD3AULL,
		0x5D08B8470E5733A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B3186BDAF1339A7ULL,
		0x134C78569CB81C03ULL,
		0x45866C0A07979428ULL,
		0x8809A2E435113C05ULL,
		0x568D566145A7944FULL,
		0x004D5BEAAA678524ULL,
		0x3185CB1253B434A6ULL,
		0xAB2DCA6C9CE83EDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F16E5D5895BA72BULL,
		0x97BF7DD1F636EE05ULL,
		0xD3FE3539BD4404DCULL,
		0xAAF11D113A721C4FULL,
		0x50B7CC5BD3DB45C1ULL,
		0x88486F17F31B366AULL,
		0xB7B80E068250C99CULL,
		0xF625722B92BF0D78ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE021D9FE2A931A9DULL,
		0x07757B891EFFFB19ULL,
		0xEA95D838C5B8C230ULL,
		0xC3DFB561A6C87C9DULL,
		0x2DFD5796EAAB23E3ULL,
		0x3999951BBAE0ACDDULL,
		0x4DA2FC801D40DEE2ULL,
		0x9B72C5E706D584B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1125C0A91E78CF79ULL,
		0xA043361DA45B141AULL,
		0xF1A529E7627DBA1EULL,
		0x17B355534A72C874ULL,
		0x439A7C8EA19D66EAULL,
		0xF0168D372047553DULL,
		0x760B021EFAA4FAA5ULL,
		0x34ECE20A48BCAFB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF104195734EBD5E4ULL,
		0xA7364D94BAA4EF03ULL,
		0x1B30F1DFA7C5782EULL,
		0xD46CE032ECBAB4E9ULL,
		0x6E672B184B364509ULL,
		0xC98F182C9AA7F9E0ULL,
		0x3BA9FE9EE7E42447ULL,
		0xAF9E27ED4E692B01ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x721B228F37102A79ULL,
		0x5EC1361F1CDC0F6CULL,
		0x92914EB859CAC181ULL,
		0xBB5B993D8E50E9D3ULL,
		0x0F728732721133F7ULL,
		0xF07BA9771EB24D5EULL,
		0x618B8382E13B593FULL,
		0x861F5BDCDAF85AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57791BFD85377F86ULL,
		0x2B12F34F855A2B3EULL,
		0x2EEA3078927D958BULL,
		0x8595125E8C271F22ULL,
		0x4C407DEC6C92DDE4ULL,
		0x53E2CDB40200A63FULL,
		0x06A113079253EF78ULL,
		0xBC060F75DDE6A6DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25623972B22755FFULL,
		0x75D3C55099862452ULL,
		0xBC7B7EC0CBB7540AULL,
		0x3ECE8B630277F6F1ULL,
		0x4332FADE1E83EE13ULL,
		0xA39964C31CB2EB61ULL,
		0x672A90857368B647ULL,
		0x3A1954A9071EFC7CULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CFFB28619AA0D2FULL,
		0x752E71BD5B5F951BULL,
		0x24F07D2B7C554B86ULL,
		0xD7B1324C211973EEULL,
		0x194555CB98880BAEULL,
		0xA3178A9467033D95ULL,
		0xB6541CFE9FA25F24ULL,
		0xCF1687CE4B836BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35F3868E29333124ULL,
		0x74D1A5EB3F78ADDCULL,
		0x6E820E1CC9282AEAULL,
		0xABAA96AC8DBDA25DULL,
		0x5EFA1B9C92A2E95CULL,
		0x37593EC150AF4695ULL,
		0x5C5FD9FFE0A85DE0ULL,
		0xE29D33A332138AC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x790C340830993C0BULL,
		0x01FFD456642738C7ULL,
		0x4A727337B57D616CULL,
		0x7C1BA4E0ACA4D1B3ULL,
		0x47BF4E570A2AE2F2ULL,
		0x944EB45537AC7B00ULL,
		0xEA0BC5017F0A02C4ULL,
		0x2D8BB46D7990E13AULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3904C784D9D2F1FULL,
		0x4580635A2D985958ULL,
		0xFB7446740809BF4DULL,
		0x8B6E0F9BE5C0E2EAULL,
		0x204C156870BD88F3ULL,
		0x1500DF1194249853ULL,
		0x8365F675C42F4599ULL,
		0x018C9FDBFFF0B376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A3B5FB1EF00BAEULL,
		0x393E85ACF5EA7798ULL,
		0x4964452C07274F83ULL,
		0x8937C7AB631FE565ULL,
		0x1FDB0D1DCC0272B7ULL,
		0x17DB6C0634B4C9D5ULL,
		0xE14A44233A0F6D27ULL,
		0x700C62AAE17EA518ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A33F983536D24B1ULL,
		0x7CBEE6F6D8722EC0ULL,
		0xB21003580F2EF0CEULL,
		0x0259C83086DF078FULL,
		0x3F971875BCBFFA44ULL,
		0x02DBB317A0905186ULL,
		0x622FB256FE2028BEULL,
		0x7180FD711E8E166EULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1275DB5E1F32E98EULL,
		0x31A36303CFD59A5FULL,
		0x7BD9BAC72C63F141ULL,
		0x5A86076D2340AC34ULL,
		0x2ADF970AAB13688EULL,
		0xCEDA9CF1898C21B7ULL,
		0x07E3E1EE7D3E21ECULL,
		0x9F14D3B6B359D147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D798339AC3B1851ULL,
		0xC953BCF99B8C5833ULL,
		0x1B0D7330EC291156ULL,
		0x5AD3B5CC19A18B29ULL,
		0x5E7929875EFA1334ULL,
		0x61BA151795F7BFABULL,
		0xAA2F196E9DBAE2E3ULL,
		0x4896A8D8BA2FBE70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F0C5867B309F1DFULL,
		0xF8F0DFFA5459C26CULL,
		0x60D4C9F7C04AE017ULL,
		0x0055B2A13AE1271DULL,
		0x74A6BE8DF5E97BBAULL,
		0xAF6089E61C7B9E1CULL,
		0xADCCF880E084C30FULL,
		0xD7827B6E09766F37ULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80C85DD53F31B48DULL,
		0xE4D2509F3CC42D8BULL,
		0x23E362E358FD758EULL,
		0x8E7BBA74088B0221ULL,
		0x7949169A0EAE276CULL,
		0x54ED21211A39B38DULL,
		0x15BD8B6704E21DEBULL,
		0xD55939C8B5FB1CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C54B2D73A520853ULL,
		0x672DD9CC448080ADULL,
		0x0701AA1506611A55ULL,
		0xB2C874E9F7EB426BULL,
		0xC1F9AA3F820924C6ULL,
		0xEF3E8A6F3A3E2F63ULL,
		0x49A7B7FF2916E806ULL,
		0x1633704FDAACE9A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C9CEF020563BCDEULL,
		0x83FF89537844AD26ULL,
		0x24E2C8F65E9C6FDBULL,
		0x3CB3CE9DFF60404AULL,
		0xB8B0BCA58CA703AAULL,
		0xBBD3AB4E20079CEEULL,
		0x5C1A3C982DF4F5EDULL,
		0xC36A49876F57F567ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89D0BDCCCF999490ULL,
		0x9A2C67A0A36A4246ULL,
		0xCD1A195A3C83A337ULL,
		0xC5F66C2828E11833ULL,
		0xCFD03D4595B8E729ULL,
		0x8ED2B8A68D0E8BF9ULL,
		0xABD3B2D1DC973A96ULL,
		0xA61B995E5EE59778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462347BC2FCA3A80ULL,
		0x3BB0BF54D352032EULL,
		0xA99042FC3E4FAAA1ULL,
		0x6FC55495CCABA929ULL,
		0x5DFDBCF81EBFEA4EULL,
		0x4E4B6FEC64885A6AULL,
		0x4FD0024A7CF2B049ULL,
		0x4968E06BEB1C0F8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFF3FA70E053AE10ULL,
		0xA19CD8F470384168ULL,
		0x648A5BA602CC0996ULL,
		0xAA3338BDE44AB11AULL,
		0x922D81BD8B070D67ULL,
		0xC099D74AE986D193ULL,
		0xE403B09BA0658ADFULL,
		0xEF737935B5F998F6ULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFF850C132180D9CULL,
		0x2BE4F2537DC97EE9ULL,
		0x92525B5ECC8EB5F2ULL,
		0xACB21DB42E85C7AEULL,
		0x240250AE034DE2CBULL,
		0xEF9E6C9C51800EFAULL,
		0xC09511D7F149F1CFULL,
		0xDDB1C64F1F5BE888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58285550AF274F77ULL,
		0x83FC5B2E75F4281FULL,
		0x0ABA63D95EC4F8AEULL,
		0x80FCDBE56DACC408ULL,
		0xAB45347FF7156E2DULL,
		0xDD0AB691DC47B28AULL,
		0x2B0D438C9D24D211ULL,
		0xC461A6BC41579D9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87D005919D3F42EBULL,
		0xA818A97D083D56F6ULL,
		0x98E83887924A4D5CULL,
		0x2C4EC651432903A6ULL,
		0x8F4764D1F4588CE6ULL,
		0x3294DA0D8DC7BC70ULL,
		0xEB98525B6C6D23DEULL,
		0x19D060F35E0C7513ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC992760FE0424C2ULL,
		0xA9B59C1117FFCD74ULL,
		0x2423594C5E7C1B72ULL,
		0xFCC8EFAA9FFA1029ULL,
		0x3E45CC74C86F0D5AULL,
		0x7F5F28A01A663589ULL,
		0x254AB4373DD1D854ULL,
		0xDDDBDE8DF1DA9EA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D3E452A9760E5BEULL,
		0xE9530F8DCAB1B7F9ULL,
		0x8C639ABC24B2E076ULL,
		0x805B4E81B87162E9ULL,
		0x49179C3E88A8FCBDULL,
		0x6ADB9EF111A1DD6EULL,
		0x0962B50B583AD5F5ULL,
		0xCB2990718A1CA394ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1A7624A6964C17CULL,
		0x40E6939CDD4E7A8DULL,
		0xA840C3F07ACEFB04ULL,
		0x7C93A12B278B72C0ULL,
		0x7752504A40C7F1E7ULL,
		0x1584B6510BC7E8E7ULL,
		0x2C28013C65EB0DA1ULL,
		0x16F24EFC7BC63D30ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27DC9754A016A39AULL,
		0x953AE6F74E696DB2ULL,
		0x5CCE3A161559B833ULL,
		0xDAAEF457C4E64025ULL,
		0x3D8068CD1C13B8FBULL,
		0x4C34F4004A91342BULL,
		0x7AE77B77CADD9DC0ULL,
		0x702492778C181D36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC8BB33F1FDA882ULL,
		0x68661B1443B70EBDULL,
		0xC6049D8F75B4CA4FULL,
		0x3E598A2D269FA528ULL,
		0x6D2551EB4886A445ULL,
		0xF7422673AF3C41E3ULL,
		0x7635CE5A2D779DC0ULL,
		0x86CB4AE82100F8B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58142C6751EB0B18ULL,
		0xFD5CFDE30DDE630FULL,
		0x9ACAA79960ED727CULL,
		0xE4F77E7AE279E50DULL,
		0x50A5392654951CBEULL,
		0xBB76D273E5AD75C8ULL,
		0x0CD2B52DE7AA0000ULL,
		0xF6EFD89FAD18E580ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26E728B602E33C69ULL,
		0x74C0672F826C627BULL,
		0x752BC597F9561530ULL,
		0xD95C24EF5A5B95EDULL,
		0xDB269CE742AF1AB9ULL,
		0x2BC6AA9274555A3FULL,
		0xB76739590062452EULL,
		0xA709CDD6BD816D59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF1CA11CFB1EA23ULL,
		0x70A22C212609209CULL,
		0x3A553D07946A2304ULL,
		0xF73F80545EF9319CULL,
		0x3E2467F8603232AFULL,
		0xB1A6458E9F4D6DA7ULL,
		0x714224AFD5D4C03AULL,
		0x72C059B1570C812EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C16E2A7CD52D64AULL,
		0x04624B0EA46542E7ULL,
		0x4F7EF8906D3C3634ULL,
		0x2E63A4BB04A2A471ULL,
		0xE502FB1F229D2816ULL,
		0x9A60EF1CEB183798ULL,
		0xC6251DF6D5B68514ULL,
		0xD5C99467EA8DEC77ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CE78D7F79EE9AE3ULL,
		0xA08458C1227F14B4ULL,
		0x79AC8123C90BF563ULL,
		0xF7DC7736582894A2ULL,
		0x280993B53C518061ULL,
		0x685A154C808336C8ULL,
		0x9C2D75D76C2A098BULL,
		0x41BC16DCB3222CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B86C922723BF895ULL,
		0x996D654A55148293ULL,
		0xF57D6E886380F049ULL,
		0x84C749FCCD9E309FULL,
		0xF3259D2277315743ULL,
		0x1E414F228940323DULL,
		0x2D8B8EBDBBCA6A8FULL,
		0xC515DB5C1730AA95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2761445D0BD56276ULL,
		0x39E93D8B776B9627ULL,
		0x8CD1EFABAA8B052AULL,
		0x731B3ECA95B6A43DULL,
		0xDB2C0E974B60D722ULL,
		0x761B5A6E09C304F5ULL,
		0xB1A6FB6AD7E06304ULL,
		0x84A9CD80A4128653ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B04990A7C7B7A52ULL,
		0xB2FDF331C8F12F01ULL,
		0x190148DEF8C10340ULL,
		0x78D6373A67D10717ULL,
		0x7AFC94C0CA14523DULL,
		0xDF5C1F3588F1DFCEULL,
		0x1E3491450C238B21ULL,
		0xCE635F21B70C0A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021D590A3BF836F3ULL,
		0x42103E4EF33F6C3CULL,
		0xB011D632D4077A2FULL,
		0x6AF5F5392E7C4D86ULL,
		0xBC405A466536B355ULL,
		0x35C97684CD82CCAAULL,
		0x00577C26B388A2C7ULL,
		0x055041579F6CD02AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1919C00047834CA1ULL,
		0xF0EDCD7F3BCE433DULL,
		0xA9109EEC2CC6796FULL,
		0x1223C20349AD4A91ULL,
		0xC6BCCE86AF22E168ULL,
		0xEA9569B145731364ULL,
		0x1E63ED63BFAB29E6ULL,
		0xCB331E762860DA14ULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18BE915CBB802858ULL,
		0x062000F4DC30DC0BULL,
		0x2D4403E8EF68C532ULL,
		0x05681C03B9610641ULL,
		0x26C55C821D6EF808ULL,
		0xD8165EAB22B00642ULL,
		0xD5C50589C70444E7ULL,
		0x75553F905E835477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA486666A4A3E5B9EULL,
		0x4609B35F4BA17D7BULL,
		0xF1ECEFF60E8C6B54ULL,
		0xD2303E97D069DD28ULL,
		0xE4D2CC45586A355BULL,
		0xE31CC0A22109E92AULL,
		0x7D55FCD35D1AE697ULL,
		0x11BDD81D0D77276FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC38F736F1BE73C6ULL,
		0x4029B3AB9791A170ULL,
		0xDCA8EC1EE1E4AE66ULL,
		0xD75822946908DB69ULL,
		0xC21790C74504CD53ULL,
		0x3B0A9E0903B9EF68ULL,
		0xA890F95A9A1EA270ULL,
		0x64E8E78D53F47318ULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x672492DDE715B1F0ULL,
		0x8B33AA5BF066C2DBULL,
		0xB073DF1B0EDBDB2DULL,
		0xBE5E2D6EE0E5A20BULL,
		0x20A5AF04D77CA942ULL,
		0x5C087A0B15150AA7ULL,
		0xBA9FFC1D90FC8EE8ULL,
		0x5BEAA8C71A97E543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9189CA5254D1C779ULL,
		0x8306AA761720BCEEULL,
		0xF8ACAE2B1DD718ABULL,
		0xDC820C370DB2613FULL,
		0x5A3F246EE203EC2DULL,
		0x1278A8440A87BB72ULL,
		0xDD382889568F296EULL,
		0x46FA52ED6A9EC6C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6AD588FB3C47689ULL,
		0x0835002DE7467E35ULL,
		0x48DF7130130CC386ULL,
		0x62DC2159ED57C334ULL,
		0x7A9A8B6A357F456FULL,
		0x4E70D24F1F92B1D5ULL,
		0x67A7D494C673A786ULL,
		0x1D10FA2A7009238AULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB88AD65C6965B7AULL,
		0x25D5F668294A9EB0ULL,
		0xB01D3FDABD53BF2EULL,
		0x19597824CC74BB4CULL,
		0x593388F016C026BDULL,
		0x708CFEA12E743DFFULL,
		0x1B52182789D15A9DULL,
		0x78B6BC2A0C0672E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F753A78DFD5201AULL,
		0x9C854E3A24F8042CULL,
		0x511F61BC9B5B0F2CULL,
		0xF69A9855442B7A54ULL,
		0x66AB267C71027815ULL,
		0xC6083DD0ABE47865ULL,
		0x9D2B5FC8059ADB1DULL,
		0xB8EF6ED12F2BA57AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4FD971D19437B60ULL,
		0xB950B8520DB29A9CULL,
		0xE1025E662608B002ULL,
		0xEFC3E071885FC118ULL,
		0x3F98AE8C67C25EA8ULL,
		0xB684C3718590459AULL,
		0x867947EF8C4B8180ULL,
		0xC059D2FB232DD79BULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A7945F9890A42FFULL,
		0xE4F03FEDD783815FULL,
		0x07B6C8349289B8B9ULL,
		0xAD5198058FE16A12ULL,
		0xF1F99C19A41F615BULL,
		0x5F8A549365C0D3BAULL,
		0x7731CE3F75D21A88ULL,
		0x88C960F68AA8DEC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F8C045418DA96EDULL,
		0xA04FF1141EFE0403ULL,
		0xF05570A81EA37477ULL,
		0x3A90A916BFAD5A40ULL,
		0x7B277EAD2A002AD6ULL,
		0xBE54C307E82AE6AAULL,
		0x3B7C2F72D553D5E2ULL,
		0xBF747CE0681146E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55F541AD91D0D412ULL,
		0x44BFCEF9C97D855CULL,
		0xF7E3B89C8C2ACCCEULL,
		0x97C13113304C3052ULL,
		0x8ADEE2B48E1F4B8DULL,
		0xE1DE97948DEA3510ULL,
		0x4C4DE14DA081CF6AULL,
		0x37BD1C16E2B99826ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x999288316F0ADE39ULL,
		0xAC63AD018A205B58ULL,
		0xB2452A7E8044CF39ULL,
		0x6C062F5C89E3716CULL,
		0x16112EDAD4B51FEAULL,
		0xB7E7F11DCF9C7ECFULL,
		0x09E28425489F9FB5ULL,
		0xD920B7D33AA89E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79D3F138C932ABF2ULL,
		0xB919E353E3C8AE18ULL,
		0x74865C7A144950CDULL,
		0xC8545163C48DC39EULL,
		0x6C2F76ED33A176D6ULL,
		0xAF4993C452DDA524ULL,
		0x90B270BCFC9FBBF7ULL,
		0xFB78651E99E7A7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0417909A63875CBULL,
		0x157A4E5269E8F540ULL,
		0xC6C37604940D9FF4ULL,
		0xA4527E3F4D6EB2F2ULL,
		0x7A3E5837E714693CULL,
		0x18AE62D99D41DBEBULL,
		0x9950F499B4002442ULL,
		0x2258D2CDA34F3967ULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EF8C54125C33B51ULL,
		0x5B139A3AD2D27D9BULL,
		0xD22BBEE60112C987ULL,
		0x3802263D3350B2E0ULL,
		0xE722017281B7629BULL,
		0x0BCF383907C85214ULL,
		0x44E0FB478BE328D5ULL,
		0x76F4D47A49452B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB061844D7EBCC803ULL,
		0xF8F01507F4B6704AULL,
		0x38596C89AE81DB75ULL,
		0x2392BE05BD61472CULL,
		0x181C333703F773F0ULL,
		0x8936A9EA646F12E1ULL,
		0x2F305A71B867797FULL,
		0x5E0437441FF6798DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E99410C5B7FF352ULL,
		0xA3E38F3D26640DD1ULL,
		0xEA72D26FAF9312F2ULL,
		0x1B9098388E31F5CCULL,
		0xFF3E32458240116BULL,
		0x82F991D363A740F5ULL,
		0x6BD0A136338451AAULL,
		0x28F0E33E56B35204ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB37FF750132D736CULL,
		0x0531FFA61080D13BULL,
		0x4EF633290C0DDABDULL,
		0x79FBA81D9037D739ULL,
		0x1B6582A427B0435AULL,
		0x9909B35641CEC8C0ULL,
		0x6DAEB32B21CDC83CULL,
		0xA069D1268793F095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582F336C30F6C2C7ULL,
		0xAA593EB4C9CEF6E0ULL,
		0x471A02627D4AB2D1ULL,
		0xC9C081BA06228809ULL,
		0x293534263DD54377ULL,
		0xA64F569BDE0668FBULL,
		0x85568854FC1B45A4ULL,
		0xA5EFDAED159C63CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB50C43C23DBB1ABULL,
		0xAF68C112D94E27DBULL,
		0x09EC314B7147686CULL,
		0xB03B29A796155F30ULL,
		0x3250B6821A65002DULL,
		0x3F46E5CD9FC8A03BULL,
		0xE8F83B7FDDD68D98ULL,
		0x05860BCB920F9359ULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75CA35057D5A6C5CULL,
		0xFB293C3B3D7D3453ULL,
		0x1B1C6DFDAC8A825FULL,
		0x460A9C25CA0C9660ULL,
		0x48D9DDB9228CFB67ULL,
		0xB00DB056D6873CE1ULL,
		0xC73EF1676F77A420ULL,
		0x21A123D0D2D99289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3249ABA645296A8ULL,
		0xA0908345CBCB1C69ULL,
		0xBF75C1E44D4E395FULL,
		0x16D2863A02FBF41FULL,
		0x96DED57CFD8C9719ULL,
		0x24E433C991B59C82ULL,
		0x0063D37C2B854A60ULL,
		0xEEECA086F7D54C7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86EEAFBF1908FAF4ULL,
		0x5BB9BF7EF6B6283AULL,
		0xA469AC19E1C4BB00ULL,
		0x50D81A1FC8F7627FULL,
		0xDE0708C5DF006C7EULL,
		0x94E9839F4732A063ULL,
		0xC75D221B44F2EE40ULL,
		0xCF4D8356250CDEF4ULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7500CD2BD2CB655ULL,
		0x6F99DB10D0790120ULL,
		0xBFA767FEEB3409F1ULL,
		0xCE856D135D3ABFCDULL,
		0x7CA8DB877CEB330AULL,
		0x9E41F2B23914311AULL,
		0x20B1D29636942A1FULL,
		0xF3B2E2D9078661D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A165688CFBB851ULL,
		0x0518A8CBA7929C22ULL,
		0x29866693CBBCC314ULL,
		0x2BA862F26471AD32ULL,
		0xC63121FC80627D55ULL,
		0x2B71D317742A163CULL,
		0xE94FAE45F1456EC5ULL,
		0x1C032B30019C0331ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EF169BA31D70E04ULL,
		0x6A8173DB77EB9D02ULL,
		0x9621016D2088CAE5ULL,
		0xE52D0FE1394B12FFULL,
		0xBA99FA7BFC894E5FULL,
		0xB53021A54D3E2726ULL,
		0xC9FE7CD3C7D144DAULL,
		0xEFB1C9E9061A62E3ULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11DD5CD1D48046D7ULL,
		0xF53073C3BCDDA5CBULL,
		0x4CF80BC505EB206AULL,
		0x9D8DACE38B74472AULL,
		0x1A59DF514AA20FE4ULL,
		0x7F63ABF978A89C13ULL,
		0x3B94EA249409B183ULL,
		0x94860ABDDD56C41CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9F6698B6BD2812ULL,
		0xBBAA9662012297D2ULL,
		0xDCC1E6268FF5264CULL,
		0x438F133E6BB83555ULL,
		0x15C8B14802F8D271ULL,
		0xE266174CA134D4D6ULL,
		0x2ED1EAA4F318C146ULL,
		0x19A4DE9B73D83378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE423A49623D6EC5ULL,
		0x4E9AE5A1BDFF3219ULL,
		0x9039EDE38A1E0626ULL,
		0xDE02BFDDE0CC727FULL,
		0x0F916E19485ADD95ULL,
		0x9D05BCB5D99C48C5ULL,
		0x15450080671170C5ULL,
		0x8D22D426AE8EF764ULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76AB7BA24B36FF46ULL,
		0xE9D43824E22DB019ULL,
		0x48C630DF05C610ECULL,
		0xD07DC51FB93576A6ULL,
		0xE728FB1500B15440ULL,
		0xEE2E7E4C2B8DA403ULL,
		0x571335243E4D78C5ULL,
		0x5526A05D1229A5A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB887BB5140517CC6ULL,
		0x34DA81C8A2DAA507ULL,
		0x89474A9F7854F3FAULL,
		0x56F2D7C6C92A47E2ULL,
		0xB8C1FA38C0BDFF0CULL,
		0xF0EADEB4D09160BCULL,
		0x8E90458C08B4428BULL,
		0x5A0CCF131C2D7829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE2CC0F30B678380ULL,
		0xDD0EB9EC40F7151EULL,
		0xC1817A407D92E316ULL,
		0x868F12D9701F3144ULL,
		0x5FE9012DC00CAB4CULL,
		0x1EC4A0F8FB1CC4BFULL,
		0xD98370A836F93A4EULL,
		0x0F2A6F4E0E04DD8FULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27F95E72C6243A9EULL,
		0x6786897D19569B7EULL,
		0x6FC2D4C0F1687436ULL,
		0x6CC9D6DF0E39DD62ULL,
		0x355873E07DF87794ULL,
		0x79F9173F724D5232ULL,
		0xCE4FAA06F0A7D7C5ULL,
		0xF43D1D7D3AB4473EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CBEA6D67AF5FFD3ULL,
		0x64E7A85611BBF9E0ULL,
		0xDBCAD590DC7B9CD6ULL,
		0x44FF47432A69A6B3ULL,
		0x5B768B68FC871F57ULL,
		0x78367E9A86F9090CULL,
		0xE0947D6E1B44797AULL,
		0x13C847C83B05C051ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B47F8A4BCD1C54DULL,
		0x0361212B08ED629EULL,
		0xB40801502D13E8E0ULL,
		0x2836919C24507BD1ULL,
		0x6E2EF888817F68C3ULL,
		0x01CF69A5F4B45B3EULL,
		0x2EDBD768EBE3AEBFULL,
		0xE7F55AB501B1876FULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48A69A3F75C87383ULL,
		0x0CD0EDB32518460CULL,
		0x1691B70354E8A226ULL,
		0x8A17786476A65CF3ULL,
		0x64611B93117AA61BULL,
		0xBA43F8CECA9AFF02ULL,
		0xE47B90B082B37A14ULL,
		0x4E4A9784E22EE860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EC8E36D58890AC8ULL,
		0xEB021EA771354896ULL,
		0xF79ED94520F4652FULL,
		0xC0AB45558C1B869EULL,
		0x643809A71E9F6E20ULL,
		0xE7CD55AE551DAAAFULL,
		0x3C8A01B166D11C9FULL,
		0x21D1CE627730AF4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x366E79522D41794BULL,
		0xE7D2F314542D0E9AULL,
		0xE10F6E46741CC709ULL,
		0x4ABC3D31FABDDA6DULL,
		0x005912340FE5C83BULL,
		0x5D8EAD609F8755ADULL,
		0xD8F19101E462668BULL,
		0x6F9B59E6951E472EULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91A33D655AB4E10AULL,
		0x49792EA9065FC0C7ULL,
		0xF7270513AD99E0A5ULL,
		0x195FA410DCC03768ULL,
		0x9D6BA5CA8A439607ULL,
		0x12E1B1BD5A01035CULL,
		0xAACF4DAD5FF0F6DEULL,
		0x9985A223B191EC28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E9CFF92ED1FCD58ULL,
		0x4F358A1FD24E4C33ULL,
		0x4BE711AD5D7BA815ULL,
		0x0A478F575F23E9EFULL,
		0x3E94AFE935F05B8FULL,
		0x7566F2D5BC5C1EE9ULL,
		0xB55CD002829427FEULL,
		0x19F236484A68288AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF3FC2F7B7AB2C52ULL,
		0x064CA4B6D4118CF4ULL,
		0xBCC014BEF0E248B0ULL,
		0x13182B4783E3DE87ULL,
		0xA3FF0A23BFB3CD88ULL,
		0x67874368E65D1DB5ULL,
		0x1F939DAFDD64D120ULL,
		0x8077946BFBF9C4A2ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24B9F8FDD016E829ULL,
		0x43C8A4FE562F8FB5ULL,
		0xB5C9010F38CDBE76ULL,
		0x85B78CAD368ED376ULL,
		0x387CF9B8315214F0ULL,
		0xD82AEB62904BBD9CULL,
		0xA56042362214126DULL,
		0xFA27FC15F62C030CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF4700742AE9AE9ULL,
		0x864FB1193356E153ULL,
		0x584CA3EAFBA421B8ULL,
		0xA37C387ACDF0D451ULL,
		0x8CDB5F5625D98AB4ULL,
		0xB9C3F0D358A873DFULL,
		0x6D8CC6658D572125ULL,
		0xD4DBD94DFCD7ADF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE4D88FA92B872C0ULL,
		0xC58715E765796EE6ULL,
		0xED85A2E5C3699FCEULL,
		0x26CBB4D7FB7E0727ULL,
		0xB4A7A6EE148B9E44ULL,
		0x61E91BB1C8E3CE43ULL,
		0xC8EC8453AF433348ULL,
		0x2EFC25580AFBAEF4ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC22723A24677DE8BULL,
		0xE71455BF01768085ULL,
		0x957EAB5B06655804ULL,
		0x52A09856F64B4FEFULL,
		0x5C06C7C892D2975EULL,
		0xBB2A3FC7E1199517ULL,
		0x23F9C6A14CEDF8FFULL,
		0xEBCFC80F2091009BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA8CC8D351D906CULL,
		0x0BF3EB285EBBE407ULL,
		0x57E308F9F1C2C5EBULL,
		0xCDED95F61C5527AFULL,
		0xD85010BD1C771179ULL,
		0xADE409068F048C56ULL,
		0x45B7DC0A8FA3F0FFULL,
		0x7B294E29E0936E19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC8FEF2F736A4EE7ULL,
		0xECE7BE975FCD6482ULL,
		0xC29DA3A2F7A79DEFULL,
		0x9F4D0DA0EA1E6840ULL,
		0x8456D7758EA58627ULL,
		0x16CE36C16E1D1941ULL,
		0x664E1AABC34E0800ULL,
		0x90E68626C0026E82ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x525E59A02E3C08F0ULL,
		0x5B2A462C18A14BDEULL,
		0x0EC68B834523CB20ULL,
		0xE4015A2233CF1928ULL,
		0x3B6E82737C088A28ULL,
		0x66031F8B83CEEE62ULL,
		0x54FA07B5081667E9ULL,
		0x54D60B9C1CD8523AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0548EB6BD436208BULL,
		0x4612AD82D83ED415ULL,
		0x57F33F1B05027858ULL,
		0x50F3454DD330A918ULL,
		0x0D5D12B0C02E68C3ULL,
		0x588B7EBF41947B49ULL,
		0x1467A197CDCB2D08ULL,
		0x400485EF29DFD2A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5716B2CBFA0A287BULL,
		0x1D38EBAEC09F9FCBULL,
		0x5935B4984021B378ULL,
		0xB4F21F6FE0FFB030ULL,
		0x363390C3BC26E2EBULL,
		0x3E886134C25A952BULL,
		0x409DA622C5DD4AE1ULL,
		0x14D28E7335078092ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6041649922FF9C4ULL,
		0x6A5924DB50F221C3ULL,
		0x6F8EDDA982FDBBFEULL,
		0x54A2CC6DD71278D1ULL,
		0xFC8CDFF2C3DA1A60ULL,
		0x0C3A5C0554CA5C48ULL,
		0xDA02CB569966E539ULL,
		0x022E1191F74E3AD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A53D8240183F423ULL,
		0xAEE319F3BAD34E99ULL,
		0x614129FC97EC7A66ULL,
		0xA5DCAB2BD5068C9FULL,
		0x6A4C0906D29B083AULL,
		0x6608DFA15A1987D1ULL,
		0x48C1472F8265BDB6ULL,
		0x16D246964750FCC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC57CE6D93AC0DE7ULL,
		0xC4BA3D28EA216F5AULL,
		0x0ECFF4551511C198ULL,
		0xF17E67460214F44EULL,
		0x96C0D6F41141125AULL,
		0x6A3283A40ED3DB99ULL,
		0x92C38C791B03588FULL,
		0x14FC5707B01EC617ULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB165B8593E8B5AABULL,
		0x8361829273B600B5ULL,
		0x3BB23B7258A568C7ULL,
		0x741424A7345E38ADULL,
		0xD788DA78A4106E01ULL,
		0x2B907D700818927BULL,
		0x5BEB7BB7DA58DF0FULL,
		0xD79CE8E4005DD81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92445B954210437DULL,
		0xB19B0FB0A69F52DBULL,
		0x6B3970F1625937A0ULL,
		0x8FC2412DDBC82793ULL,
		0x27C8F2EB435C5E03ULL,
		0x3C24C32B11BCABABULL,
		0x6F5A7DDAB4E31EA0ULL,
		0xA43CBEAB87B1FB67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2321E3CC7C9B19D6ULL,
		0x32FA8D22D529526EULL,
		0x508B4B833AFC5F67ULL,
		0xFBD6658AEF961F3EULL,
		0xF0402893E74C3002ULL,
		0x17B4BE5B19A439D0ULL,
		0x34B1066D6EBBC1AFULL,
		0x73A0564F87EC237DULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F6E69F27E3E620BULL,
		0x168F500C26B26D73ULL,
		0x362A458C354EA097ULL,
		0x534A278B7F36B2C1ULL,
		0x72AD529492732C59ULL,
		0x8D8DEF749B0B6911ULL,
		0x0AAF3DFED413701FULL,
		0x34D0AD99F8ABE8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7155D8FD7F4F544DULL,
		0xC7A0BF3F205FD1BFULL,
		0x890C139D2D4CFF90ULL,
		0xB23A9FBCED37B08FULL,
		0x47388AA1C3B81215ULL,
		0xC0442A85E7435178ULL,
		0xD4A17EEB48E6A6ECULL,
		0x77405833E2D90180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E3BB10F01713646ULL,
		0xD12FEF3306EDBCCCULL,
		0xBF26561118025F07ULL,
		0xE170B8379201024EULL,
		0x3595D83551CB3E4CULL,
		0x4DC9C5F17C483869ULL,
		0xDE0E43159CF5D6F3ULL,
		0x4390F5AA1A72E935ULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8709B500570B4C34ULL,
		0xE51A321313D806CEULL,
		0x4115690CA3DBCC34ULL,
		0x3334A6EEE23725B7ULL,
		0xB97C86B3E3E206DAULL,
		0x425A88A93AF2E989ULL,
		0xFBE960F65A880471ULL,
		0x284D026B7CD68DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25FF539B41E5A2A4ULL,
		0xFCAC21B9F14CACD3ULL,
		0xF45A842F48447A67ULL,
		0xB5C2D935E02969ADULL,
		0xEBDB3BA08B1B4E0DULL,
		0xB9C9382ADA41ED92ULL,
		0xA84946D6DD8087B8ULL,
		0x67D5C6C8BABB6635ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2F6E69B16EEEE90ULL,
		0x19B613AAE294AA1DULL,
		0xB54FED23EB9FB653ULL,
		0x86F67FDB021E4C1AULL,
		0x52A7BD1368F948D7ULL,
		0xFB93B083E0B3041BULL,
		0x53A02620870883C9ULL,
		0x4F98C4A3C66DEBF5ULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9204DECBD839E50AULL,
		0x899DD16D7629B06CULL,
		0x7CAD55B559CFAFA0ULL,
		0x4C5D4044005ECC50ULL,
		0xF99CBDD2CB769F90ULL,
		0xB1216E83724206F4ULL,
		0x44602A68951C598AULL,
		0x7C37F003D393BCE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC597760A8E54954ULL,
		0x7D7494EB7F7592C6ULL,
		0xF5C575D628DF9423ULL,
		0x8DD54CE20FBD30DCULL,
		0x71152D90A64A7E35ULL,
		0x350B2AB42EE59F94ULL,
		0x4594E1294E947C7CULL,
		0xF04B391C32F67794ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E5DA9AB70DCAC5EULL,
		0xF4E94586095C22AAULL,
		0x8968206371103B83ULL,
		0xC1880CA60FE3FC8CULL,
		0x888990426D3CE1A5ULL,
		0x842A44375CA79960ULL,
		0x01F4CB41DB8825F6ULL,
		0x8C7CC91FE165CB71ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BE5D63DA988F3BFULL,
		0xD3B3C6CEA1D71443ULL,
		0xE9238FF68A5CD781ULL,
		0x56F69E036A9578E6ULL,
		0xF39C42D491DC4018ULL,
		0x4CF9F129827D6B81ULL,
		0x29125C4DDF717BD4ULL,
		0x03DDD62D7FB59615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149DDA07CE8C278FULL,
		0x7E2F686DE90C0ADEULL,
		0x5DB6EDF8B8721CDEULL,
		0x44CD8CCF296F4E67ULL,
		0xC860920EBB66DA2BULL,
		0xCF235B52263327B0ULL,
		0xA6F43455099491F5ULL,
		0xF295665673A1AEF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F780C3A6704D430ULL,
		0xAD9CAEA348DB1E9DULL,
		0xB495620E322ECB5FULL,
		0x123B12CC43FA3681ULL,
		0x3BFCD0DA2ABA9A33ULL,
		0x83DAAA7BA44E4C31ULL,
		0x8FE66818D6E5EA21ULL,
		0xF148B07B0C1438E0ULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x095938B51F148EB9ULL,
		0xC090DF74B17224B5ULL,
		0x290FB5A03B4BE8FBULL,
		0x126EDB58C4A98BDCULL,
		0x0058539DA0C40931ULL,
		0x4A6C5A6A1BFAE25CULL,
		0xFAE5675AB0662C6EULL,
		0x90477FC05FBC553AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E623DDDF844700ULL,
		0x7B2E34D9555BECB3ULL,
		0x42CDCB6A2C9CAEE0ULL,
		0x01A4289B0E1B45A7ULL,
		0x7B7338D5C42B0E8BULL,
		0xD0BFCEAEED1C680DULL,
		0x5EE93D849219430FULL,
		0xDF8508C403576C45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1BF1B68C090C9B9ULL,
		0xBBBEEBADE429C806ULL,
		0x6BC27ECA17D7461BULL,
		0x13CAF3C3CAB2CE7BULL,
		0x7B2B6B4864EF07BAULL,
		0x9AD394C4F6E68A51ULL,
		0xA40C5ADE227F6F61ULL,
		0x4FC277045CEB397FULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x576BBEF0CC3D3127ULL,
		0x1DE9F05369A70C4DULL,
		0xFAA1FF498C1C89EBULL,
		0x7FEDE16C11B18353ULL,
		0xABA72EBCB97A2767ULL,
		0x5E9E1E105C6117D6ULL,
		0xBBADC3594EEE286BULL,
		0x131776F5723BCB2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC673AE8538BC4A0FULL,
		0x564F00B83778E73BULL,
		0x7C542D22357AD691ULL,
		0x24451F3EFA753588ULL,
		0xA883C38D48261378ULL,
		0xFF6E7A585B5EEC27ULL,
		0xE11294B632C48292ULL,
		0xA1A562D96129EB4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91181075F4817B28ULL,
		0x4BA6F0EB5EDFEB76ULL,
		0x86F5D26BB9665F7AULL,
		0x5BA8FE52EBC4B6DBULL,
		0x0324ED31F15C341FULL,
		0xA1F06448073FFBF1ULL,
		0x5ABF57EF7C2AAAF9ULL,
		0xB2B2142C13122066ULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83C8929679517F68ULL,
		0x6DDEA354AC6BC42CULL,
		0xEC118E66CAA3C76EULL,
		0xF3D79ADD0228E1F0ULL,
		0x13001D4EDEB854A8ULL,
		0xEB655AA6F8DBDECEULL,
		0x85759218A32DA2CFULL,
		0x78BF05A555BB63D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47EE12F2B387EDABULL,
		0xE559EBF015461FA7ULL,
		0xD531FAAA3E8245EEULL,
		0x70EE3BD69F96E7C2ULL,
		0x2BF17B04FABEABEEULL,
		0x9DD3B847E163D50FULL,
		0x9246CAE4292A603AULL,
		0x0BC1BFDCC4274CB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4268064CAD692C3ULL,
		0x888748A4B92DDB8BULL,
		0x392074CCF4218280ULL,
		0x8339A10B9DBE0632ULL,
		0x38F1664A2406FF46ULL,
		0x76B6E2E119B80BC1ULL,
		0x173358FC8A07C2F5ULL,
		0x737EBA79919C2F6DULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C156A4E5C0B4F34ULL,
		0x6B5171515DCFD70FULL,
		0xEEBE8EB924C5C683ULL,
		0xAFFE20BA51376887ULL,
		0x51741F25E3E2D70BULL,
		0x639485F1EDFFF7A2ULL,
		0x59B5622B3223A33EULL,
		0xB9F9C729E4B76971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B161CDC9902E5A7ULL,
		0x4BBD708FD760084DULL,
		0x1419961F791A76BAULL,
		0xE394118D6BF94E73ULL,
		0x10618E33DB3BA117ULL,
		0xD38C94A6A00B605AULL,
		0x555A8321DEB031DEULL,
		0x60CF5371A8A2C960ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57037692C509AA93ULL,
		0x20EC01DE8AAFDF42ULL,
		0xFAA718A65DDFB039ULL,
		0x4C6A31373ACE26F4ULL,
		0x4115911638D9761CULL,
		0xB01811574DF497F8ULL,
		0x0CEFE10AEC9392E0ULL,
		0xD93694584C15A011ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FD2B94F56D8E4C5ULL,
		0x6A275779043A691DULL,
		0x32AA29CB2B0A9015ULL,
		0x20EC710D4BAA39F8ULL,
		0xC1313D88A435EDA8ULL,
		0x731882E4DDE7696BULL,
		0xFF38003F2B6BC7CDULL,
		0x59EED8EEFE8C520BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9730B56FAB0A29CDULL,
		0x1E7AE1DDEF533B1EULL,
		0xFE842EE9ECE3E017ULL,
		0x6DB7E9039980BB2BULL,
		0x9DFC1CB7CB17E0EAULL,
		0x56B2D373640D9A1EULL,
		0x3AD91C24F9CDFEF8ULL,
		0x1B99D70093BF70EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8E20C20FDD2CD08ULL,
		0x745DB6A4EB695203ULL,
		0xCC2E0722C7E97002ULL,
		0x4D5B980ED22A82D3ULL,
		0x5CCD213F6F220D42ULL,
		0x25AA5197B9EAF375ULL,
		0xC5E11C1BD2A63935ULL,
		0x42770FEE6D3322E6ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x653CAFFEB281A9E4ULL,
		0x59BBE15721C51783ULL,
		0xE7EF92C38229D039ULL,
		0x4DEA2006FEC829FDULL,
		0xE71368D1D5B9EBC8ULL,
		0x26F928B9E7BFD699ULL,
		0x9BC968BDA049B165ULL,
		0x1D291FBC48311F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8758B2B247A62F4ULL,
		0xA80348ACB84B32D2ULL,
		0x352D3A22824B7C59ULL,
		0xD99A229D45A83F1CULL,
		0xCE42B8B681BAD5EAULL,
		0x384693B62EDC9670ULL,
		0xE6EEA47269CF4986ULL,
		0xA7E789BE84F77405ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD4924D596FBCB10ULL,
		0xF1B8A9FB998E2551ULL,
		0xD2C2A8E10062AC60ULL,
		0x9470029BBB6016E1ULL,
		0x2951D06754033E22ULL,
		0x1EBFBB0FC96340E9ULL,
		0x7D27CCCFC986F8E3ULL,
		0xBACE9602CCC66B93ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD24AE64A009DA78ULL,
		0x75C1DF7CB504540BULL,
		0x10FAB65C6B67B25FULL,
		0x28EE52C30ED9253AULL,
		0x49CEDFF484341767ULL,
		0x815A5AF9456AD84EULL,
		0xAF7DC3CFF45722E7ULL,
		0xE9AF952F0E6DB175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAFD5F8ECDD7D678ULL,
		0x525D987C282BE9B8ULL,
		0x067350FD7607EA56ULL,
		0xE53BB8BA85B63B42ULL,
		0x6CBBB062677797E7ULL,
		0xF98AF1F2182BE8D5ULL,
		0x0606B62B0BC6DFDEULL,
		0x4445D52148156515ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67D9F1EA6DDE0C00ULL,
		0x279C47009D2FBDB3ULL,
		0x1689E6A11D605809ULL,
		0xCDD5EA798B6F1E78ULL,
		0x25756F96E3438080ULL,
		0x78D0AB0B5D41309BULL,
		0xA97B75E4FF91FD39ULL,
		0xADEA400E4678D460ULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x814298D59513AE14ULL,
		0x106DA25098B8D26BULL,
		0x04D88E42E28652ECULL,
		0xEB7F53A75C825084ULL,
		0xD352D5274CC0939EULL,
		0xD960CBC231D28370ULL,
		0x1521C3B25C007F9FULL,
		0xB52B4D76C56C7162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x987297D55C308429ULL,
		0x2B23471FC98ED1B5ULL,
		0xDC4418822AB13CD0ULL,
		0xFC95435E755188F0ULL,
		0x2707E0F0FB9922ADULL,
		0x9FFB9489B8DD276CULL,
		0xACA7CD23FADB9135ULL,
		0x378D1614ADED5D43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19300F00C9232A3DULL,
		0x3B4EE54F513603DEULL,
		0xD89C96C0C8376E3CULL,
		0x17EA10F929D3D874ULL,
		0xF45535D7B759B133ULL,
		0x469B5F4B890FA41CULL,
		0xB9860E91A6DBEEAAULL,
		0x82A65B6268812C21ULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA749DA0585A7D4A2ULL,
		0xBA055C049D07B913ULL,
		0xDA360BB4A0E17F6AULL,
		0xF7921AB3499C8639ULL,
		0x672CF364F595FF1EULL,
		0x89A25C44480BD91EULL,
		0x43E5D37FD932B535ULL,
		0xE33428254AB1A34FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24727CD2638E6193ULL,
		0xD772BA3B0C2407BAULL,
		0x76FF8377957A6AD4ULL,
		0x2F7EB072A5695C08ULL,
		0xFEB33B6BF1935A9FULL,
		0x4BD192D9CE060E48ULL,
		0x6499936308F2838FULL,
		0xC4FA09E83639DACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x833BA6D7E629B531ULL,
		0x6D77E63F9123BEA9ULL,
		0xACC988C3359B15BEULL,
		0xD8ECAAC1ECF5DA31ULL,
		0x999FC80F0406A581ULL,
		0xC273CE9D860DD756ULL,
		0x277C401CD1C036BAULL,
		0x27CE21CD7C887980ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5CF78DE0C29C457ULL,
		0xC37523E86C6AAF10ULL,
		0x6D6D97E8CF500E28ULL,
		0xD588E0EE02D9AAA3ULL,
		0xDBB470638D25963FULL,
		0x9E88AEF1BBA1DEE7ULL,
		0xA78C6593A63CE6C1ULL,
		0x232EB0DC476F4266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85BF3638EB3F644CULL,
		0x7486BC031D649F68ULL,
		0xDABDED3C2D83A084ULL,
		0xC9F172F0FA0F0CC6ULL,
		0xF13CD6CF1F182D68ULL,
		0x81A1587183A7BCC6ULL,
		0x64920555E8DC6889ULL,
		0x7FD77E035C795A8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50704EE6E716A01BULL,
		0xB7F39FEB710E3078ULL,
		0xB7D07AD4E2D3AEACULL,
		0x1C79921EF8D6A665ULL,
		0x2A88A6AC923DBB57ULL,
		0x1F29F68038066221ULL,
		0xC31E60C64EE08E48ULL,
		0x5CF9CEDF1B1618EAULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4935AEE86ABA74C8ULL,
		0xFCDB1D2CD40D3046ULL,
		0x6FB50D4228FC6297ULL,
		0x1AD62BF7B83627A2ULL,
		0xAF6C326EF5D5C945ULL,
		0x366B404DD251FC5EULL,
		0x13C5D124936AF101ULL,
		0x310C11AACF776E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D869BC69B5C202ULL,
		0x545D3F92FFA358F0ULL,
		0x3C2F9DFDE97A4E70ULL,
		0x9E9FBF407DF4DBFDULL,
		0xFD9813E58DE1573BULL,
		0x530BB66F0FA4C97CULL,
		0xF9E9BDE8E082DE3CULL,
		0x4F9A957C928D95E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9EDC754030FB6CAULL,
		0xA88622BE2BAE68B6ULL,
		0x539A90BFC1862CE7ULL,
		0x844994B7C5C2FC5FULL,
		0x52F4218B78349E7EULL,
		0x6560F622DDF53522ULL,
		0xEA2C6CCC73E82F3DULL,
		0x7E9684D65DFAFB7BULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x735D3D95E444A2BBULL,
		0x031C8A5C6338BB49ULL,
		0x0DEB71BF7D676617ULL,
		0x13B62F5B8627B822ULL,
		0x01C344D8335D8F86ULL,
		0xC18DBCB729DF94D0ULL,
		0x539247997D1BE8C8ULL,
		0x2EAF64B7A10CA9D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74A304EC446C1AF6ULL,
		0xD90FDCC281AD110AULL,
		0x51FB90CA0B24D468ULL,
		0x8052DA4EEB7DA763ULL,
		0x08323DAF1A176FE9ULL,
		0xE5F5BAF96B2C542AULL,
		0x5EB5C866FEF803D0ULL,
		0x043167D2B7D82F57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07FE3979A028B84DULL,
		0xDA13569EE295AA43ULL,
		0x5C10E1757643B27FULL,
		0x93E4F5156D5A1F41ULL,
		0x09F17977294AE06FULL,
		0x2478064E42F3C0FAULL,
		0x0D278FFF83E3EB18ULL,
		0x2A9E036516D48682ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD772D04A457BD4D6ULL,
		0x36B6B0E457709099ULL,
		0x2393ABCB03C88DCAULL,
		0xEB0C8D0B8BD3D282ULL,
		0xBD92FE69BA784BFBULL,
		0xDC1AB0A2CF452C52ULL,
		0xFAEC82DA3B2BC0ACULL,
		0x679529A49115B5F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2906DCA06AB6CAF0ULL,
		0x60C653A644C2CD7CULL,
		0xF5DF2AD3AFF8C651ULL,
		0x5F274917A45BB2ABULL,
		0xD4D97848539F9893ULL,
		0x99874D5AD1D45602ULL,
		0xFB3E1DC79B487138ULL,
		0x0ABAEF5153878E52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE740CEA2FCD1E26ULL,
		0x5670E34213B25DE5ULL,
		0xD64C8118AC304B9BULL,
		0xB42BC41C2F886029ULL,
		0x694B8621E9E7D368ULL,
		0x459DFDF81E917A50ULL,
		0x01D29F1DA063B194ULL,
		0x6D2FC6F5C2923BA1ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x341C2DB250FB05E2ULL,
		0xE481669F359A27EBULL,
		0x658B5BC2553E18D1ULL,
		0xC2D28456F7342B39ULL,
		0x2F9F84B403AAB6F2ULL,
		0xBE178A52F283001FULL,
		0x4E5A232DCB240C89ULL,
		0xC0ABB0BF67968574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6E3F43254584A5ULL,
		0x8A0CAF27F607E9EAULL,
		0x742DBD7337CA1766ULL,
		0x248A1B7743AF81E2ULL,
		0x4105725379292B03ULL,
		0x3AE36C7B97ECEB4AULL,
		0x505D988B647DB938ULL,
		0xE778FB599A59A50BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B7212F175BE8147ULL,
		0x6E8DC9B8C39DCE01ULL,
		0x11A6E6B162F40FB7ULL,
		0xE6589F21B49BAADBULL,
		0x6E9AF6E77A839DF1ULL,
		0x84F4E629656FEB55ULL,
		0x1E07BBA6AF59B5B1ULL,
		0x27D34BE6FDCF207FULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEFDD9F905AB7398ULL,
		0x2DD2EAAA00EC6DEEULL,
		0xC7ECECD158D35F67ULL,
		0x9174F55E64313E20ULL,
		0xE56C16DDEC4C2DA4ULL,
		0x0616F3353684FA41ULL,
		0x478258E6D27F1A23ULL,
		0x4C5264060A4E4351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFAEBCB7242CD0B8ULL,
		0x310119929B645209ULL,
		0xBF5DBA5C02C11B7FULL,
		0xF2279D7E695B23D0ULL,
		0x42FF252C9FCE1B2DULL,
		0x2EAB276DFFE7C801ULL,
		0x87473085D2E6CF27ULL,
		0x70EFC60484579C23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1153654E2187A320ULL,
		0x1CD3F3389B883FE7ULL,
		0x78B1568D5A124418ULL,
		0x635368200D6A1DF0ULL,
		0xA79333F173823689ULL,
		0x28BDD458C9633240ULL,
		0xC0C568630099D504ULL,
		0x3CBDA2028E19DF72ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5AA7EA54F9E8B6FULL,
		0x4FCC3C23E522139DULL,
		0x0EF3ED1E8892492CULL,
		0xA7FFB98ED4C6B6D3ULL,
		0x7751AF68D963C7E4ULL,
		0x06583E21C56DADD4ULL,
		0x7716EE15A58F2483ULL,
		0x8A8EFE1856329C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1D91CB914727CAULL,
		0x652592928A8AD15DULL,
		0xE08BFE5E162B808EULL,
		0x11E8DED28D4BC159ULL,
		0xFF8D6CD19CE6332EULL,
		0x52C1614F3DD77713ULL,
		0x358EDE25DD73D971ULL,
		0x78258ABC6027147BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBB7EF6EDED9ACA5ULL,
		0x2AE9AEB16FA8C2C0ULL,
		0xEE7813409EB9C9A2ULL,
		0xB617675C598D778AULL,
		0x88DCC3B94585F4CAULL,
		0x54995F6EF8BADAC7ULL,
		0x4298303078FCFDF2ULL,
		0xF2AB74A436158840ULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F038D1CCE3B739FULL,
		0x714864E782FA9F8AULL,
		0xE22339E3DDA3C2E3ULL,
		0x39E03E39B6842B8DULL,
		0xD54DD65B2082B0E4ULL,
		0x92440B848F020B4FULL,
		0xB7820CF462097E64ULL,
		0x2456172025CF2F58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6318932E06C76269ULL,
		0x6C1287663C3CC7F2ULL,
		0x3126832CD63FEE3CULL,
		0x81B89C1BA76EF528ULL,
		0x8BDB0E69B9874DCDULL,
		0xAC301C0BC6B4C5B7ULL,
		0x0CDE1E6B4CDB57B0ULL,
		0xB2BC67768A81C285ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C1B1E32C8FC11F6ULL,
		0x1D5AE381BEC65878ULL,
		0xD305BACF0B9C2CDFULL,
		0xB858A22211EADEA5ULL,
		0x5E96D8329905FD29ULL,
		0x3E74178F49B6CEF8ULL,
		0xBB5C129F2ED229D4ULL,
		0x96EA7056AF4EEDDDULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21C72DA3D25169DEULL,
		0xCECF746ED3F77EC2ULL,
		0x0660E5CE7539447EULL,
		0x111C1F03209B615EULL,
		0x3664A937580200CDULL,
		0x349E403267A97ECDULL,
		0x316DB15512FC4F21ULL,
		0x4F476E8858390C4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0138F27A772A70F3ULL,
		0xA39478A34DBAB782ULL,
		0xCFF0D64E0FE9C6BFULL,
		0x03ED867A1937F1A1ULL,
		0xDD5EE7E5B7E4B395ULL,
		0x7CCB911E8B770B9FULL,
		0x23D72620A8A64712ULL,
		0x12F92A546A7CDB7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20FFDFD9A57B192DULL,
		0x6D5B0CCD9E4DC940ULL,
		0xC99033807AD082C1ULL,
		0x12F1997939AC90FFULL,
		0xEB3A4ED2EFE6B358ULL,
		0x4855D12CECDE7552ULL,
		0x12BA9775BA5A0833ULL,
		0x5DBE44DC3245D732ULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64DEDF71849A190FULL,
		0x668448012FE87072ULL,
		0x73259F5E9FCCAB22ULL,
		0xE22CF69F3F897772ULL,
		0x016C7AA6C0448F7EULL,
		0x89BE17DB055111D0ULL,
		0xE3B926D4F53810C0ULL,
		0x3957153CF4FEA7A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F2819C745619B47ULL,
		0x50A0F5871B8E986EULL,
		0xDF30520545706A8EULL,
		0x4783CCB6AD3C3CD8ULL,
		0xCF1C4E74347B9A73ULL,
		0x35BDC2076A4B3403ULL,
		0xEDE8CD67B1ACCDC5ULL,
		0x1BB73995BA5772FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BF6C6B6C1FB8248ULL,
		0x3624BD863466E81CULL,
		0xAC15CD5BDABCC1ACULL,
		0xA5AF3A2992B54BAAULL,
		0xCE7034D2F43F150DULL,
		0xBC03D5DC6F1A25D3ULL,
		0x0E51EBB34494DD05ULL,
		0x22E02CA94EA9D559ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D7B18F15C5EBA05ULL,
		0xDFB2DB85E6504870ULL,
		0x7BC5E1E34BA95A3FULL,
		0x8DBFE8AE8750FA2AULL,
		0x2AD2B59527512A39ULL,
		0x713181A886730699ULL,
		0x053737C979456CE1ULL,
		0xA3192A57D1B9D73AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x470E9C41BD221698ULL,
		0xBABB25A74E7CD53FULL,
		0xB3C91045B5DCA9EEULL,
		0x7C0D7765D12340FEULL,
		0x7166DD357A14B56DULL,
		0x5271A513E4275FEFULL,
		0xF3376A9051D1AD3BULL,
		0x31B27BB62D1A99D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A7584B0E17CAC9DULL,
		0x6509FE22A82C9D4FULL,
		0xC80CF1A6FE75F3D1ULL,
		0xF1B29FCB5673BAD4ULL,
		0x5BB468A05D459F54ULL,
		0x234024BB62545976ULL,
		0xF6005D592894C1DAULL,
		0x92AB51E1FCA34EEFULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AB92DAF9161A5EBULL,
		0x35FC1F80C57C1860ULL,
		0x1C8873B6AA64B380ULL,
		0xB41E2A50B02D5B4DULL,
		0xFDE250A981AAD18EULL,
		0x65965CF99888BA89ULL,
		0x97115E7A1EA41065ULL,
		0xE93A8D1A3DCE5C76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92CC3A305D0DBAEDULL,
		0xF650DC1661770B1CULL,
		0x653DB632E826A221ULL,
		0x677EBEDE6FA56CC6ULL,
		0xE0E618D794FCE764ULL,
		0x8277A97543B59EEAULL,
		0xF6A6A5003695F5EEULL,
		0xED33B17B28FCDDE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD875179FCC6C1F06ULL,
		0xC3ACC396A40B137CULL,
		0x79B5C584424211A1ULL,
		0xD360948EDF88378BULL,
		0x1D04487E155636EAULL,
		0xE7E1F58CDB3D2463ULL,
		0x61B7FB7A2831E58BULL,
		0x04093C6115328192ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90F6CB927D45ED48ULL,
		0x27C547247E873F73ULL,
		0xB15674037F8AC57FULL,
		0x6FC3FB126FA958E3ULL,
		0xA78F9AFE07A9B41FULL,
		0x5DCBBB5DA3A44EA2ULL,
		0x3E2841EA803B6571ULL,
		0xF955383E16EA7E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78CC63AEAD0E6C9ULL,
		0x9D23A0D15ED8C13CULL,
		0x2D0C53AE1DCE0A1EULL,
		0x57C47E3D2CDD10B8ULL,
		0x86B2D456C0A6C8E5ULL,
		0x36E4202CC7D01DFCULL,
		0xA7409DBAF37CA1AEULL,
		0xF7DD764CA306E943ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x677A0DA897950B81ULL,
		0xBAE6E7F5205FFE4FULL,
		0x9C5A27AD6244CF61ULL,
		0x3807852F4374485BULL,
		0x213D4EA8C70F7CFAULL,
		0x6B2F9B716474535EULL,
		0x9968DC507347C4DFULL,
		0x0E884E72B5EC9711ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A9C56239228541AULL,
		0x769B64C0900A3EEEULL,
		0xC79787AAF071E1A0ULL,
		0xA6E2AD19298DBA4CULL,
		0xFD07EA81EC271157ULL,
		0xE4FF34F26077FE7CULL,
		0x08D14D65C0421D9FULL,
		0x60CA6100FB9B96C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CFF82FF405627A0ULL,
		0x89F47FF6C61D19BEULL,
		0xA1FB556406A788EEULL,
		0xD60C9BBE76DE37C7ULL,
		0x662B08AFF537A28DULL,
		0xF82890463A9A0ACDULL,
		0x1311C18C8406D990ULL,
		0xFB2BE8D451C535ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB663D4DCD27E73BAULL,
		0xFF6F1B3656172750ULL,
		0x666CD2CEF6D6694EULL,
		0x70EE36A75F538D8BULL,
		0x9B2CE22E1910B3DAULL,
		0x1CD7A4B45AEDF4B1ULL,
		0x1BC08CE94444C40FULL,
		0x9BE189D4AA5EA36BULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2B87F565B93E4EEULL,
		0xB4196469C8E30FBDULL,
		0x9CA8E651FCA4C170ULL,
		0x0FB269CB5D17F60DULL,
		0x8488426B06FE3848ULL,
		0x4796B698AD88AF08ULL,
		0x2EE3029363158D36ULL,
		0xA90148DF08F1D808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1C096598AD5EA2ULL,
		0x7612F3BEB9EBEAB7ULL,
		0x8EB06F11244A3D43ULL,
		0xC334006C903BC977ULL,
		0xCD43442A2C8573A6ULL,
		0x3342397E05C92FDFULL,
		0x94D88FF87BF6A493ULL,
		0x0010F18C5458401BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CA47633C33EBA4CULL,
		0xC20B97D77108E50AULL,
		0x12188940D8EEFC33ULL,
		0xCC8669A7CD2C3F7AULL,
		0x49CB06412A7B4BEEULL,
		0x74D48FE6A84180D7ULL,
		0xBA3B8D6B18E329A5ULL,
		0xA911B9535CA99813ULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4D86DF6D70E680EULL,
		0x7A5C12C33F6907E2ULL,
		0x314D7809F4854057ULL,
		0x3ECC431DA8E58D53ULL,
		0x4C3F0BF0D33B6835ULL,
		0x882301097190718FULL,
		0xBFA6E24FAD74223AULL,
		0xA39DF0DBAD8C224CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C322B7CDAF7DCABULL,
		0xBA62B738A4A916E6ULL,
		0xAB8FB4E8496979F2ULL,
		0x667E1A090A73C32DULL,
		0xE688B13CB26BD1ABULL,
		0xA028D2546AC86D70ULL,
		0x1D19CC49A46EBA07ULL,
		0xB4EED83CEF28041DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8EA468A0DF9B4A5ULL,
		0xC03EA5FB9BC01104ULL,
		0x9AC2CCE1BDEC39A5ULL,
		0x58B25914A2964E7EULL,
		0xAAB7BACC6150B99EULL,
		0x280BD35D1B581CFFULL,
		0xA2BF2E06091A983DULL,
		0x177328E742A42651ULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x817C8A95B81F4A80ULL,
		0x1D4D81DFF7C65E04ULL,
		0xB4E4894326C7F94AULL,
		0x8D07611B17AD42F6ULL,
		0x84AC4698E3E7B77DULL,
		0x7389827E1EC4CEB6ULL,
		0x9B210599DF9153BDULL,
		0xF040F4230BB4D6BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67B93A18E58DDBC6ULL,
		0x469EBB323C112122ULL,
		0xD3D3183F4F2A953FULL,
		0x872A59AD67E63D63ULL,
		0xEE3E0D924D0C5189ULL,
		0xDA3987D319D5EFB4ULL,
		0x6B24D4AF1494889EULL,
		0x7BE66C91595E8AD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6C5B08D5D929146ULL,
		0x5BD33AEDCBD77F26ULL,
		0x6737917C69ED6C75ULL,
		0x0A2D38B6704B7F95ULL,
		0x6A924B0AAEEBE6F4ULL,
		0xA9B005AD07112102ULL,
		0xF005D136CB05DB23ULL,
		0x8BA698B252EA5C6EULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA113AFD9407DE8DULL,
		0x4288139B3FDBEE3BULL,
		0xE5506C6772C2D3EFULL,
		0xE9FCB9372D2D8F91ULL,
		0xB50DC15BD1A49A94ULL,
		0xFDCECE8090FCEC36ULL,
		0x5B65CE542F9652D8ULL,
		0x26FD3FEE6CB8BD9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x335B71A94A157903ULL,
		0x1DEA3ACC7957FF21ULL,
		0x3C03563B7A4589A9ULL,
		0x10E5E977AC92C891ULL,
		0x3C617D2C102BC1CDULL,
		0x24F446131664A2FBULL,
		0x849D4B9D0825C9D1ULL,
		0x6167548D1371084DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x894A4B54DE12A78EULL,
		0x5F622957468C111AULL,
		0xD9533A5C08875A46ULL,
		0xF919504081BF4700ULL,
		0x896CBC77C18F5B59ULL,
		0xD93A889386984ECDULL,
		0xDFF885C927B39B09ULL,
		0x479A6B637FC9B5D6ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD28F7712A211A334ULL,
		0x473C1642F54B6CEAULL,
		0x9FCDAD1E8AFD4EB7ULL,
		0xDBF2110098F0B63EULL,
		0x6F8A498033A5E0A5ULL,
		0x570D73264F1EB0EBULL,
		0xBCF5D1C3B349B086ULL,
		0x7EAFA242FCA07FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC53C6CAA0C7701C1ULL,
		0x5FB69023FB093194ULL,
		0x4FDC5F195441794FULL,
		0x34179D9915DB57D6ULL,
		0x8188228AA16F2EF8ULL,
		0xAF4E013D05AB4534ULL,
		0x96AD2B9DB0558CB8ULL,
		0xCD5B7EEC95424985ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17B31BB8AE66A2F5ULL,
		0x188A86610E425D7EULL,
		0xD011F207DEBC37F8ULL,
		0xEFE58C998D2BE1E8ULL,
		0xEE026B0A92CACE5DULL,
		0xF843721B4AB5F5DFULL,
		0x2A58FA5E031C3C3EULL,
		0xB3F4DCAE69E23643ULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB8AF7A05776C613ULL,
		0xFF855FF4ED41AF54ULL,
		0x30F8178C9884E3A3ULL,
		0x06B7748DDBF96CBDULL,
		0x0597D98192E6EF4CULL,
		0x19836AC519120FF0ULL,
		0x7A0736631EF040C3ULL,
		0x419D16BF86D67138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A0D5CCA17C89A9ULL,
		0xD5D05FBEEFFAD94FULL,
		0xFC14CC8C4374219DULL,
		0x383984582871530AULL,
		0x94F3323D7E2090EBULL,
		0xD65C2E35F5FE66DAULL,
		0xEA4D274C31FD16F4ULL,
		0xB886C998ED8C6F3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C2A226CF60A4FBAULL,
		0x2A55004A02BB761BULL,
		0xCCECDB00DBF0C23EULL,
		0x3E8EF0D5F3883FB7ULL,
		0x9164EBBCECC67FA7ULL,
		0xCFDF44F0ECEC692AULL,
		0x904A112F2F0D5637ULL,
		0xF91BDF276B5A1E05ULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x411D64D4F4D5A27DULL,
		0xB372F0BE22765B37ULL,
		0xD20353474B033604ULL,
		0xE78ED888C74AC9F2ULL,
		0x2DAD5C93B503CE4FULL,
		0x0C2C2D8ABE3C3362ULL,
		0x01BAF10F80D8C78EULL,
		0x1A5BD0E36AF1DA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x041B8F8CCED77EBFULL,
		0xB795D34D3DF4368BULL,
		0x177AB5B96F443886ULL,
		0x4DE6B96F745506BFULL,
		0x3D2B2496D26A081AULL,
		0xF9C14AD4B0C67127ULL,
		0xC9753C1C284B71D4ULL,
		0x2DBF2609E11B15F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4506EB583A02DCC2ULL,
		0x04E723F31F826DBCULL,
		0xC579E6FE24470E82ULL,
		0xAA6861E7B31FCF4DULL,
		0x108678056769C655ULL,
		0xF5ED675E0EFA4245ULL,
		0xC8CFCD13A893B65AULL,
		0x37E4F6EA8BEACFFDULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD588E333F81DB90AULL,
		0x5A68024E5B2E54D7ULL,
		0x631167011FED71B1ULL,
		0x3C147BBDDF0A7E57ULL,
		0xA24D7C9883912257ULL,
		0xE90A75BBBBBE9CDEULL,
		0x45A61D22D828F00AULL,
		0xCEFA56510B10173DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072CCBFC1A921AE7ULL,
		0xC5C5A4DF8356D68EULL,
		0x71AD89FA52CF5F3AULL,
		0xC0D8B18F873EB7AEULL,
		0x02172B6F99F1E095ULL,
		0x015E37DEFFEDFC30ULL,
		0x5E85C90EE190CEA9ULL,
		0xF4E3DBE0E7152BACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2A428CFE28FA3EDULL,
		0x9FADA691D8788259ULL,
		0x12BCEEFB4D222E8BULL,
		0xFCCCCA325834C9F9ULL,
		0xA05A57F71A60C2C2ULL,
		0xE8544265445360EEULL,
		0x1B23D42C39B83EA3ULL,
		0x3A198DB1EC053C91ULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0143F4D1326360ULL,
		0x93841A3C589AC7E7ULL,
		0x11577AFA1AB0B936ULL,
		0xB08269A9FE835A59ULL,
		0x6FD656E6B221DA8AULL,
		0x3E0454CDE92FD627ULL,
		0x14C3B482F6A04F3BULL,
		0xBC49A4B177C16D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E05354CEADAE05BULL,
		0xAD35CBC71F74F105ULL,
		0xD92A39741C95564BULL,
		0xB4540D4F016B6757ULL,
		0x4FB31D5C78705C98ULL,
		0x0892D4EF0275FC90ULL,
		0x2F880C3273532773ULL,
		0xF70726FAAE6DACECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB30476B83BE8833BULL,
		0x3EB1D1FB47EE36E2ULL,
		0xC87D438E0625EF7DULL,
		0x04D664E6FFE83D0EULL,
		0x20654BBACA518612ULL,
		0x36968022EB5A2AB7ULL,
		0x3B4BB8B085F36848ULL,
		0x4B4E824BD9ACC1BBULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03F2400D0002B83FULL,
		0x53B84F7EB272B990ULL,
		0x8564C232182A4E12ULL,
		0xFB30C0443B3912ADULL,
		0xFE027466F4D76270ULL,
		0x9123F8B978028507ULL,
		0x9F56FA02D7B303DBULL,
		0x9851BFA3AE9C4B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB14D394B5E0229CBULL,
		0x7AED9F515AE0E9DDULL,
		0x6629D49F2B43753FULL,
		0xC15BE9AFE32FF0AFULL,
		0xFEDF5DFB68E2859AULL,
		0x900BBCA1EBECC5B7ULL,
		0x000776817A68E953ULL,
		0x90BEC727AAE95EEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2BF79465E0091F4ULL,
		0x2955D02FE892504DULL,
		0xE34D16AD33693B2DULL,
		0x3A6B29EBD816E202ULL,
		0x00DD299D9C35E7EAULL,
		0x0128441893EE40B0ULL,
		0x9F518C83ADDBEA88ULL,
		0x08EF7884047515A0ULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44228A371827FC23ULL,
		0xF2C23A3F8EFB7E04ULL,
		0xC02BAC4AC223E8CDULL,
		0x15D1F586E4CFD329ULL,
		0x70CDF3F19A86C61BULL,
		0x7AEB49941AE2F118ULL,
		0x0242995E22A3D2B7ULL,
		0x17380C4322B44C94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F9D321B66013B6ULL,
		0x3725636F43D923C8ULL,
		0x204E33F137DF569DULL,
		0xB399680C72382979ULL,
		0x68472F1D9E51DDA5ULL,
		0x8C3489DDA6FD44E0ULL,
		0x68A3ED2B10E4C647ULL,
		0xC0F20EB4909EC149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CDB5916AE47EF95ULL,
		0xC5E75950CD225DCCULL,
		0xE0659FBBF5FCBE50ULL,
		0xA6489D8A96F7FA50ULL,
		0x188ADCEC04D71BBEULL,
		0xF6DFC049BC1FB5F8ULL,
		0x6AE17475324714F0ULL,
		0xD7CA02F7B22A8DDDULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BE710007072B141ULL,
		0xCD1A64D17F047835ULL,
		0x12827D1213F61800ULL,
		0x78728CB28BE2A84EULL,
		0x5587029FABC9AB5FULL,
		0x1986272B21DB7D60ULL,
		0xF7D20DC36F33414DULL,
		0x8514D155D40A4671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63098D4FA9D9A4AFULL,
		0x4A3BB09FC3E83BB2ULL,
		0x3EBA3989A3187FBBULL,
		0x0375F95C55F566CBULL,
		0x762E80AC7F61A768ULL,
		0xCF1ACB959A54E412ULL,
		0x21EA90766110C20DULL,
		0xA08D98CAD148A968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28EE9D4FD9AB15EEULL,
		0x8721D44EBCEC4387ULL,
		0x2C38449BB0EE67BBULL,
		0x7B0775EEDE17CE85ULL,
		0x23A98233D4A80C37ULL,
		0xD69CECBEBB8F9972ULL,
		0xD6389DB50E238340ULL,
		0x2599499F0542EF19ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71D2549E1182D070ULL,
		0x7EC24FFC7E10165AULL,
		0x600C5DC2147A2262ULL,
		0x032AEA835BECE6F3ULL,
		0x81C9DF82BE62D133ULL,
		0x8C63E3F2263D4ED9ULL,
		0x9B50609026A1E96FULL,
		0x93F632837294B71AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0C7D94888429E4ULL,
		0xE47522EEE4060EC3ULL,
		0x32B9E40923FED1E7ULL,
		0x04A65D0B9B386464ULL,
		0x498C8BBB421D87C3ULL,
		0x35DADDAF719B31B3ULL,
		0xBBC1CE8061B75AE6ULL,
		0x0032DF6BA87FC6AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FDE290A9906F994ULL,
		0x9AB76D129A161899ULL,
		0x52B5B9CB3784F385ULL,
		0x078CB788C0D48297ULL,
		0xC8455439FC7F56F0ULL,
		0xB9B93E5D57A67F6AULL,
		0x2091AE104716B389ULL,
		0x93C4EDE8DAEB71B4ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x861AD9AF23DB28DDULL,
		0x0183EB783DFA6B3FULL,
		0xA91F0B54F73D77AEULL,
		0x83F609A6F69182BCULL,
		0xBC6CA9B69B09D28AULL,
		0x018F60AF65585737ULL,
		0x1FCA1704D44D3945ULL,
		0xC3A2297506DB8BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C52923476AD0AA3ULL,
		0x3BC2762BBF16DA57ULL,
		0x61B81C6D7FC9239AULL,
		0x98E41F48ED874C22ULL,
		0x015714E5C211FB34ULL,
		0x14E4ACBFE72ED017ULL,
		0x6F470EAE58FEA2E4ULL,
		0xE9581B4CC5735A5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA484B9B5576227EULL,
		0x3A419D5382ECB168ULL,
		0xC8A7173988F45434ULL,
		0x1B1216EE1B16CE9EULL,
		0xBD3BBD53591829BEULL,
		0x156BCC1082768720ULL,
		0x708D19AA8CB39BA1ULL,
		0x2AFA3239C3A8D18FULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECC8A8BC51DC6E2CULL,
		0x55C8019D67240D0CULL,
		0x49A307CB8A34EA85ULL,
		0xDD341731A6092B1FULL,
		0xEE73B628DC720C00ULL,
		0xAA0C726DD6D28F1AULL,
		0x894F7D1AF501EB61ULL,
		0x54FFE76B5A9B23E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E519AE006A7AA08ULL,
		0x1D724937A60FD9F5ULL,
		0x57BC7BFC4DFB5D42ULL,
		0xF90186F79E7B0573ULL,
		0x07A73ECAA4249CA6ULL,
		0x9D1E96E9C32513E3ULL,
		0xBCDB5079CD124E7AULL,
		0xEFC0F8BB5AF8018AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF299325C577BC424ULL,
		0x48BA48AAC12BD4F9ULL,
		0x1E1F7C37C7CFB7C7ULL,
		0x243591C638722E6CULL,
		0xE9D488E2785690A6ULL,
		0x3712E48415F79CF9ULL,
		0x35942D633813A51BULL,
		0xBB3F1FD000632269ULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41CE9955B29F0F07ULL,
		0x787BD51277E2C237ULL,
		0x7D61809283A122F8ULL,
		0xFF3C32A337255D76ULL,
		0x0600F771E430E0F3ULL,
		0xB8291416E9F9150AULL,
		0xC3199F97160716DCULL,
		0xE46959806ECE560AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C83C67BC9D5882ULL,
		0x38AEB0A50132C59BULL,
		0x980415EF2B998B22ULL,
		0xD28B7833BBE7AE9AULL,
		0x7EC38A7F8F6ECE7CULL,
		0x5BFEC123B1DFBBDFULL,
		0x9A947E0228066BBAULL,
		0xD87465528D32708FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7506A5320E025785ULL,
		0x40D565B776D007ACULL,
		0xE565957DA838A9DAULL,
		0x2DB74A908CC2F3ECULL,
		0x78C37D0E6B5E2E8FULL,
		0xE3D7D5355826AED5ULL,
		0x598DE1953E017D66ULL,
		0x3C1D3CD2E3FC2685ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x985BEA31FAD51F24ULL,
		0x647F3265CCC0CDCFULL,
		0xAE91FC3AD779E6B4ULL,
		0x96324060037A23B4ULL,
		0x70545FCC2DF104E8ULL,
		0xD4DB125D03DEB231ULL,
		0xF843E89E258309A1ULL,
		0x05D06E1316814375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E2FE84971807D1ULL,
		0x4491D2EAB05D7456ULL,
		0x77A708AF0BB3DDF7ULL,
		0xF38897B637A02F20ULL,
		0x83B67B556B66B464ULL,
		0x671E29CAEFA27096ULL,
		0x908293AE9F3095DFULL,
		0x69B552F302339685ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51B914B56DCD18F5ULL,
		0x20EEE08F7C9DB999ULL,
		0xD936F495DCCA3B43ULL,
		0x65BAD7D634DA0C94ULL,
		0xF3E224994697B08CULL,
		0xB3C53B97EC7CC2A7ULL,
		0x68C17B30BAB39C7EULL,
		0x6C653CE014B2D5F0ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61C295C74D0B6A43ULL,
		0x13096FB517D6F6BCULL,
		0xBBF77459118335A1ULL,
		0x8431ACA47ECD2AFCULL,
		0x416E1C82F2A9891DULL,
		0x12A628F681E7B936ULL,
		0x4E570E51E48347BFULL,
		0x5025135A4D8DAC96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB09C19BEF1EA9BA3ULL,
		0xF5A5BE00DEED8C1CULL,
		0x7D9238D74885EE95ULL,
		0x8006FCD1160CA3D4ULL,
		0x893DC11463AB4A8FULL,
		0x9F1ED7C0FB1850B2ULL,
		0x21BDF58D90DEFB42ULL,
		0x553C51066ECE0A96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD15E8C79BCE1F1E0ULL,
		0xE6ACD1B5C93B7AA0ULL,
		0xC6654C8E5906DB34ULL,
		0x0437507568C18928ULL,
		0xC853DD969102C392ULL,
		0x8DB8FF367AFFE984ULL,
		0x6FEAFBDC745DBCFDULL,
		0x0519425C2343A600ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEB295070AE4095FULL,
		0x7D911886FDE7867DULL,
		0x8C0188F368CDF8B5ULL,
		0x702E4D906944DC69ULL,
		0xB000B0B20C88A9A4ULL,
		0x14DE632BCD27F26DULL,
		0xEB079ADFADD8AB74ULL,
		0x169496259116EC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86B466A8AABF17DAULL,
		0x5971CE12B31DECADULL,
		0xE3C81724B8A4840AULL,
		0x2C5B098D6555241DULL,
		0x266EB15DD1264DC7ULL,
		0xF3A3D35F9EA1098FULL,
		0xEA23045F23DF9371ULL,
		0x50014D9A56A99DE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6806F3AFA05B1E85ULL,
		0x24E0D6944EFA6AD0ULL,
		0x6FC99FD7D0697CBFULL,
		0x5C75441D0C11F874ULL,
		0x966E01EFDDAEE463ULL,
		0xE77DB0745386FBE2ULL,
		0x01249E808E073805ULL,
		0x4695DBBFC7BF71F2ULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79503B32840D19EFULL,
		0xFE2A5EF91705DB2DULL,
		0x53F1141A4FF9A119ULL,
		0x14739D80DEF31DAEULL,
		0x75E602CD0B1F739DULL,
		0x8E607072838259C6ULL,
		0x166D522AF1717108ULL,
		0x50900D66A60B07E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4E5B6E59BFD29EULL,
		0x63F0585571B1D765ULL,
		0x7A3589EB35A3864BULL,
		0x846EB938386F093BULL,
		0x009C1838FD624352ULL,
		0x0CD30249FD4798C4ULL,
		0xB6DCE078D6B8956AULL,
		0x9E440C57AA274EDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC41E605CDDB2CB71ULL,
		0x9DDA06AC66B40C48ULL,
		0x29C49DF17A5A2752ULL,
		0x901D24B8E69C1495ULL,
		0x757A1AF5F67D30CFULL,
		0x82B3723B7EC5C102ULL,
		0xA0B1B25227C9E462ULL,
		0xCED401310C2C4938ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9584EFBF6D200D80ULL,
		0x276A07991D5A76E5ULL,
		0x4741FF6DBFEA2984ULL,
		0xD59317CFF939C546ULL,
		0xFC561E1B12FD17D8ULL,
		0x7711AD3BB3A676E5ULL,
		0x2E750E3ACEC404B2ULL,
		0x28EEAC8290108945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B6120A0398E06F5ULL,
		0x8427007362831217ULL,
		0xA793820A5C37F1C9ULL,
		0x203D53930F50A191ULL,
		0xCDA2FF57E0DF78C2ULL,
		0x90674793CEF22E44ULL,
		0x50B390A77C4F04F0ULL,
		0xBB726A8CEA82A771ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EE5CF1F54AE0B75ULL,
		0xA34D07EA7FD964F2ULL,
		0xE0D27D67E3DDD84DULL,
		0xF5AE445CF66964D7ULL,
		0x31F4E14CF2226F1AULL,
		0xE776EAA87D5458A1ULL,
		0x7EC69E9DB28B0042ULL,
		0x939CC60E7A922E34ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE314BD22F847FC1FULL,
		0xF3DD4E312F6CDB58ULL,
		0xAC16461178FD6274ULL,
		0xC038BF97C30A4066ULL,
		0xA70D603F2EB87FC2ULL,
		0x467FF344E1C8A5E8ULL,
		0xACBE0EE3129C0D54ULL,
		0x66FF7C1D1D9A44CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A5296227034F3E8ULL,
		0xBD8FB5365C400702ULL,
		0xE743DA216AD01C34ULL,
		0xA6041436C52DCA8DULL,
		0x4BE5E01EFA962FAFULL,
		0x227FEE1556DA474FULL,
		0xA10D81CB52B41B2FULL,
		0x72CD999F5AC73A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89462B0088730FF7ULL,
		0x4E52FB07732CDC5AULL,
		0x4B559C30122D7E40ULL,
		0x663CABA106278AEBULL,
		0xECE88021D42E506DULL,
		0x64001D51B712E2A7ULL,
		0x0DB38F284028167BULL,
		0x1432E582475D7E44ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF12460A743E55684ULL,
		0xCF874E7BEA977CADULL,
		0xCEEDDAB9A8CD25B0ULL,
		0x51D0D2C8EC25F5F6ULL,
		0x4BD5E6EABE745B50ULL,
		0xE1A33EC34B82672BULL,
		0x819C4192577E48D4ULL,
		0x378F82787BDDD096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2D265D2B9AC682ULL,
		0x118CB4E098A6FE26ULL,
		0x3167EA2AE42C4E07ULL,
		0xACDB3585CCEF4958ULL,
		0x0E2C12E5A1233CE3ULL,
		0x6F22B7B1E7278428ULL,
		0xDD86FED3406268D1ULL,
		0x616FADA31B9C7E53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D0946FA687F9006ULL,
		0xDE0BFA9B7231828BULL,
		0xFF8A30934CE16BB7ULL,
		0xFD0BE74D20CABCAEULL,
		0x45F9F40F1F5767B3ULL,
		0x8E818972ACA5E303ULL,
		0x5C1ABF41171C2005ULL,
		0x56E02FDB6041AEC5ULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AB3219C5D6959CBULL,
		0x0B4C719781E1D525ULL,
		0xF614FFE0709C105DULL,
		0x31B56C240D768F00ULL,
		0x81B7DD7FC02B86C7ULL,
		0x42E58EC1E713323FULL,
		0x0D48339C397CD45BULL,
		0xC595987CC058515EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD980B469F2B807B8ULL,
		0x9D74B34E906709F8ULL,
		0x10D2C1BD8F0F3309ULL,
		0x7DCDF2070CD5AE05ULL,
		0xF88E047D1EB2235BULL,
		0xA9E55FEE1D37062BULL,
		0xA004AFC13414410BULL,
		0xD3BE3292515477A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF33395F5AFD15E73ULL,
		0x9638C2D91186DCDDULL,
		0xE6C63E5DFF932354ULL,
		0x4C789E2301A32105ULL,
		0x7939D902DE99A59CULL,
		0xEB00D12FFA243414ULL,
		0xAD4C9C5D0D689550ULL,
		0x162BAAEE910C26FBULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68678B7266B00CD9ULL,
		0xDBF3195BC4209EB8ULL,
		0xCB9B40FF25D84E7FULL,
		0xFA435189A3087BB2ULL,
		0xE1C5BA911894B0BCULL,
		0x9A1D9F6FECF24F2AULL,
		0x18F9BC5B36E05EB3ULL,
		0x75F97B86BC7A1C55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9393855A90FFD093ULL,
		0xA677594CCA7D75CFULL,
		0x80CCD33C33018D49ULL,
		0xFD61FB560B667320ULL,
		0x2B3AC54333DAFE37ULL,
		0xC1963C7FF9E388F3ULL,
		0x905DB62CE2C4771BULL,
		0x673DEBC1D973A47EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBF40E28F64FDC4AULL,
		0x7D8440170E5DEB77ULL,
		0x4B5793C316D9C336ULL,
		0x0722AADFA86E0892ULL,
		0xCAFF7FD22B4E4E8BULL,
		0x5B8BA3101511C7D9ULL,
		0x88A40A77D42429A8ULL,
		0x12C490476509B82BULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD308638FE54B165ULL,
		0x26C19FBF9521B1ADULL,
		0x0888522DBEA8B885ULL,
		0x38AFD3DC5275169DULL,
		0x6100BAEAB0E06C0BULL,
		0x511C334447EDF078ULL,
		0xA1B4D6E62E414C0DULL,
		0x2C90148264014080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4CDA43144FD0FA8ULL,
		0x6518521886D7C484ULL,
		0xDF0283BACB4497F7ULL,
		0x6153F779E0C93D40ULL,
		0x5FF7E8CAE3A5158AULL,
		0x2A4E6CC14AF8D26CULL,
		0xFF9CDC1B6E8C76DCULL,
		0xE16E45D8B22B1547ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49FD2209BAA9BECDULL,
		0x43D9CDA713F67529ULL,
		0xD78AD19775EC2F72ULL,
		0x59FC24A5B2BC2BDDULL,
		0x3EF7522053457981ULL,
		0x7B525F850D152214ULL,
		0x5E280AFD40CD3AD1ULL,
		0xCDFE515AD62A55C7ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54B32954FAFCE7ADULL,
		0x84FA7DB906C18F7EULL,
		0xF2C2D240A4146D90ULL,
		0x11E15D96C2360175ULL,
		0x2647488839D3EE7CULL,
		0x90464C6130B207E2ULL,
		0x32367A7A77D9606BULL,
		0x51D92EAD82E36928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F011DAB5C12CA94ULL,
		0xA886903CF3991ACEULL,
		0x01147F8FD5627A8EULL,
		0xE00F3EB90D4180ECULL,
		0xD69B92972B531777ULL,
		0x43460FDB60CA2EE4ULL,
		0xC3E3C1D12B9D241DULL,
		0x10239A2DA0C09733ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BB234FFA6EE2D39ULL,
		0x2C7CED85F55895B0ULL,
		0xF3D6ADCF7176171EULL,
		0xF1EE632FCF778199ULL,
		0xF0DCDA1F1280F90BULL,
		0xD30043BA50782906ULL,
		0xF1D5BBAB5C444476ULL,
		0x41FAB4802223FE1BULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F683061E32DBDDFULL,
		0x33FDFFB3D8F7BEACULL,
		0x6FE2CC721A5E42C1ULL,
		0xD69D1DA4DA9DE131ULL,
		0x8600BEE435B80EA6ULL,
		0x65246008070BADA4ULL,
		0xF6A30399ECD829E6ULL,
		0x57C440641EEC7028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10C591D05E475A25ULL,
		0x088031FB0A9C7B79ULL,
		0xF87EDA141E31B363ULL,
		0x1B571B90F9DE7D89ULL,
		0x14E39D0288211EE6ULL,
		0x53F36980BEB3DDDFULL,
		0x53F46DDF291F7221ULL,
		0x93B94B3BAB01C45BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FADA1B1BD6AE7FAULL,
		0x3B7DCE48D26BC5D5ULL,
		0x979C1666046FF1A2ULL,
		0xCDCA063423439CB8ULL,
		0x92E323E6BD991040ULL,
		0x36D70988B9B8707BULL,
		0xA5576E46C5C75BC7ULL,
		0xC47D0B5FB5EDB473ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB13CFEF2E605E465ULL,
		0x4E5420AC1F3F4613ULL,
		0x8450235193D93E47ULL,
		0x90EC5832452CB269ULL,
		0xF78C47485E79D1D2ULL,
		0xFEF29FC3CFA1C7D4ULL,
		0x098B21833262E7C5ULL,
		0x586A6E361E22040EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD9DAE054F64DF64ULL,
		0x16281F2AA80D0669ULL,
		0x4A86B4420E888661ULL,
		0x04AF0C008E15E694ULL,
		0xDED7E03033A9B368ULL,
		0x61056AD95B9C0C21ULL,
		0x3F63809D7C99D6EAULL,
		0xBB670EBE891045D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CA150F7A9613B01ULL,
		0x587C3F86B732407AULL,
		0xCED697139D51B826ULL,
		0x94435432CB3954FDULL,
		0x295BA7786DD062BAULL,
		0x9FF7F51A943DCBF5ULL,
		0x36E8A11E4EFB312FULL,
		0xE30D6088973241DBULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6803E585B1309E01ULL,
		0x62BFB8E5A7E314A1ULL,
		0xFD2C5138771FC2E3ULL,
		0x47F9EC6557B4D8CBULL,
		0x3CE0EF61C984AE0CULL,
		0x0CCF89137488CA46ULL,
		0xDCBBCD0EBEE995ACULL,
		0x380073D7134433FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D1D4C1C57A70F4ULL,
		0xD128254CB5907531ULL,
		0x2737204FEF0509FEULL,
		0x1B34F8554D286730ULL,
		0x7D1676F605DCB52CULL,
		0x6095C44108E82BD7ULL,
		0x1CEE61CF5B49EF92ULL,
		0xC3115E9AA80A16B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ED23144744AEEF5ULL,
		0xB3979DA912736190ULL,
		0xDA1B7177981ACB1DULL,
		0x5CCD14301A9CBFFBULL,
		0x41F69997CC581B20ULL,
		0x6C5A4D527C60E191ULL,
		0xC055ACC1E5A07A3EULL,
		0xFB112D4DBB4E254AULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9AA5788D4977BD8ULL,
		0x2954B1F1B496060EULL,
		0x0898B04062F983B6ULL,
		0x0E0D0BE8E17704A5ULL,
		0x41D08A0F8629ED20ULL,
		0xBABB319561B9194FULL,
		0x1BA526253591BE7EULL,
		0x09652EFAD6B141D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA068D2E19A885E19ULL,
		0xB4E4051101EDC769ULL,
		0xAED6BBC6BF2FFD9BULL,
		0x45755D48E49CCDE3ULL,
		0x4C7A946C3E7BE921ULL,
		0x940E79BDD1C69920ULL,
		0x79618F0E5DBA18EBULL,
		0xE8FEA51DF65B3409ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19C285694E1F25C1ULL,
		0x9DB0B4E0B57BC167ULL,
		0xA64E0B86DDD67E2DULL,
		0x4B7856A005EBC946ULL,
		0x0DAA1E63B8520401ULL,
		0x2EB54828B07F806FULL,
		0x62C4A92B682BA695ULL,
		0xE19B8BE720EA75D0ULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AA214FC64891564ULL,
		0x70A68AEB0088265EULL,
		0x55BF6E84837C562EULL,
		0x2BE168E020539B33ULL,
		0x45ECF7C1D67F60D5ULL,
		0x7636F6708E200478ULL,
		0x34387B05E59BF680ULL,
		0x2E9536A6DC534EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD0D6D67406563C0ULL,
		0xD7D05AAF7B969472ULL,
		0x952CCF564CADC035ULL,
		0xF0EACA26F54808E7ULL,
		0xE525BE9BCFB99650ULL,
		0x24DB1A54649005DFULL,
		0x03717B0150143CE3ULL,
		0xE032F64D2C37C4E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37AF799B24EC76A4ULL,
		0xA776D0447B1EB22CULL,
		0xC093A1D2CFD1961BULL,
		0xDB0BA2C6D51B93D4ULL,
		0xA0C9495A19C6F685ULL,
		0x52EDEC24EAB001A7ULL,
		0x37490004B58FCA63ULL,
		0xCEA7C0EBF0648A29ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x661F358D0089439BULL,
		0x881584797B613DEFULL,
		0xE74271A957A08446ULL,
		0x3687002C8ED74662ULL,
		0x21881C8157587D35ULL,
		0x40CBF18447416542ULL,
		0x4D4C08C842438B4BULL,
		0x2274F7D5ACE61A49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x787445FDF81B94D9ULL,
		0xA361AB3F2878717DULL,
		0x2F2EA03FB70985C0ULL,
		0xD7F87AFCE9AAC410ULL,
		0xE5F8F6357BA235CDULL,
		0x95CC9BBBDDAA8C68ULL,
		0xD03E28EF9CE7EDF5ULL,
		0x35DAAB8D45AFEBFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E6B7070F892D742ULL,
		0x2B742F4653194C92ULL,
		0xC86CD196E0A90186ULL,
		0xE17F7AD0677D8272ULL,
		0xC470EAB42CFA48F8ULL,
		0xD5076A3F9AEBE92AULL,
		0x9D722027DEA466BEULL,
		0x17AE5C58E949F1B7ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAFBDC73D01FD16BULL,
		0x93127BE2A8797F30ULL,
		0xFD5DAFB11CA0CCD8ULL,
		0x201AC54B0001E936ULL,
		0x1426351FF5DD75DFULL,
		0xA9F751914957ABB1ULL,
		0x011E0B002B39BCA8ULL,
		0xA2EE89822739E0FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E584924A10B76F2ULL,
		0x32A560748ACBDE97ULL,
		0xF5B09F4A4F30DBB6ULL,
		0x87DC36AF0619B6A5ULL,
		0x5464373BAD2D2A12ULL,
		0x3B640563FA6A2DD7ULL,
		0x93892C9F4121BDD4ULL,
		0xACDB4D15901B026FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4A395577114A799ULL,
		0xA1B71B9622B2A1A7ULL,
		0x08ED30FB5390176EULL,
		0xA7C6F3E406185F93ULL,
		0x4042022458F05FCDULL,
		0x929354F2B33D8666ULL,
		0x9297279F6A18017CULL,
		0x0E35C497B722E295ULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x663A433677E47F6AULL,
		0x43473FDBEAC76E28ULL,
		0xE8FCEFD118F03E4EULL,
		0x34055A406AADED35ULL,
		0x15470BD280EB00E1ULL,
		0x5379B140185CCA0AULL,
		0x24ED368E8239A4C4ULL,
		0x32B032E5FFAC57CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC65F45E6AF0A89ULL,
		0x9D93EFD8094AF341ULL,
		0x177BD99F3EB8F063ULL,
		0x38E15EA1248AB006ULL,
		0xFA2DB7CFF96ABD69ULL,
		0x9520300177D34DF6ULL,
		0x3A6A967554512EC6ULL,
		0x58689CEE7CA3F699ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DFC1C73914B75E3ULL,
		0xDED4D003E38D9D69ULL,
		0xFF87364E2648CE2DULL,
		0x0CE404E14E275D33ULL,
		0xEF6ABC1D7981BD88ULL,
		0xC65981416F8F87FCULL,
		0x1E87A0FBD6688A02ULL,
		0x6AD8AE0B830FA156ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x414DC9E3FF852B29ULL,
		0x374FB49C5635049FULL,
		0x1934BF60B7D04A77ULL,
		0xECBD1E8D5C385376ULL,
		0x7B531E222A6F46B0ULL,
		0xE28E82F2C39E5200ULL,
		0x63C895EF442A9B7BULL,
		0x5EBBFD327C81E738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A156BBC3ED236CFULL,
		0x3137A48CDD9B8677ULL,
		0x66E7A9AFC507F725ULL,
		0xC1D88236840FA51CULL,
		0x4A2BBF78B2072A87ULL,
		0xFDC010D25B1AF098ULL,
		0xDAE99A567137010FULL,
		0xC5D7193BFA31D72EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B58A25FC1571DE6ULL,
		0x067810108BAE82E8ULL,
		0x7FD316CF72D7BD52ULL,
		0x2D659CBBD837F66AULL,
		0x3178A15A98686C37ULL,
		0x1F4E92209884A298ULL,
		0xB9210FB9351D9A74ULL,
		0x9B6CE40986B03016ULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27AB275279821F12ULL,
		0x000739018AF147F5ULL,
		0xD39CFD9338112AA2ULL,
		0x4F2396F284C35499ULL,
		0x262D69DBDB51197BULL,
		0xF0F708D04278010AULL,
		0x4CBEFA4635E7022EULL,
		0x21E66EAFBB722533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A07204A099DF35CULL,
		0x3B1B87CC02C3B51CULL,
		0x7AAFAD994516992BULL,
		0x2E14AEA12522B69AULL,
		0xCCB72F794A2E2925ULL,
		0x05FDDAE255B0C81BULL,
		0xE0BE46318E19609EULL,
		0xBCA7048C5D44E915ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DAC0718701FEC4EULL,
		0x3B1CBECD8832F2E9ULL,
		0xA933500A7D07B389ULL,
		0x61373853A1E1E203ULL,
		0xEA9A46A2917F305EULL,
		0xF50AD23217C8C911ULL,
		0xAC00BC77BBFE62B0ULL,
		0x9D416A23E636CC26ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD3F83EABA8416D9ULL,
		0xBEDAB211696418BAULL,
		0x8472B995BF87091AULL,
		0x7732C3FF21D1E9B8ULL,
		0xB573EED7C6F5D3FFULL,
		0xDC763C0466FC9D5EULL,
		0xE14F58A0B74431DBULL,
		0xA40F3323F0BAE438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E9DD4D48A9B83AULL,
		0x35A7A511774A1F49ULL,
		0x0BE47FBE6DB1BDE7ULL,
		0x6638BF1D2A0F4EA6ULL,
		0xF5BE60392588FBC8ULL,
		0x8068536D7910B116ULL,
		0x87A2DD52B71C7F3AULL,
		0x6872F663D6CB9585ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FD65EA7F22DAEE3ULL,
		0x8B7D17001E2E07F3ULL,
		0x8F96C62BD236B4FDULL,
		0x110A7CE20BDEA71EULL,
		0x40CD8EEEE37D2837ULL,
		0x5C1E6F691FEC2C48ULL,
		0x66ED85F200584EE1ULL,
		0xCC7DC540267171BDULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73A5EDC331A50AB4ULL,
		0x32A97D3D4E357108ULL,
		0xC128D892E4AEB85DULL,
		0xC40C1AB55DF0D17AULL,
		0xE05815E238C4CD70ULL,
		0xDDDC1B3781782D14ULL,
		0xD181127C9F859EB9ULL,
		0x70A676B97E503C24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AD2A91E8446C960ULL,
		0xDF4751F2D9DB9245ULL,
		0x4B2909D4DE8CCC74ULL,
		0x7BFE21CC67E14AA4ULL,
		0xB7C5B81EB3F77173ULL,
		0x9C1671114ABAB5C7ULL,
		0x3606BF0865B0AC6FULL,
		0x3757DB0B9D4EBD59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x697744DDB5E3C3D4ULL,
		0xEDEE2CCF97EEE34DULL,
		0x8A01D1463A227429ULL,
		0xBFF23B793A119BDEULL,
		0x579DADFC8B33BC03ULL,
		0x41CA6A26CBC298D3ULL,
		0xE787AD74FA3532D6ULL,
		0x47F1ADB2E31E817DULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60C55219D55359D7ULL,
		0xB9A2C080F86D0D07ULL,
		0xAC4116FEB26C92A2ULL,
		0x67C3B6DBA64F3E77ULL,
		0xE1661E4D245B68A0ULL,
		0xD482E9E84973E22FULL,
		0x018FD35A81B503A9ULL,
		0x557C60A9950D75DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE020A828CCC97846ULL,
		0x46BC7086508C09C3ULL,
		0x9249373CC3C3910EULL,
		0x8126783852480EE0ULL,
		0xDD7D306A975B0A6CULL,
		0x23905880FB3DB472ULL,
		0x709081C6EB34EBDCULL,
		0x94DFCE3035A839F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80E5FA31199A2191ULL,
		0xFF1EB006A8E104C4ULL,
		0x3E0821C271AF03ACULL,
		0xE6E5CEE3F4073097ULL,
		0x3C1B2E27B30062CCULL,
		0xF712B168B24E565DULL,
		0x711F529C6A81E875ULL,
		0xC1A3AE99A0A54C28ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F9EB0A0B2157810ULL,
		0x8512D303D70D5F05ULL,
		0xBBE01BB45FE94940ULL,
		0xC9E591FA202B9FE2ULL,
		0x775953554F6BC8E3ULL,
		0x211095DDD0C12838ULL,
		0x3B0778C429B7F8FEULL,
		0xE97CB9F7C445A99CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F48532ECFD52381ULL,
		0xE2A83DB68A690B40ULL,
		0x9F781FE07C5BEB67ULL,
		0xCB7DD9935C28AD12ULL,
		0x6A3C52A8CD19489EULL,
		0xA09AA40F0EA02414ULL,
		0x951E5E9C0A1D960AULL,
		0xA1B77E0AF5F3EC97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40D6E38E7DC05B91ULL,
		0x67BAEEB55D645445ULL,
		0x2498045423B2A227ULL,
		0x029848697C0332F0ULL,
		0x1D6501FD8272807DULL,
		0x818A31D2DE610C2CULL,
		0xAE19265823AA6EF4ULL,
		0x48CBC7FD31B6450BULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50E8EB935DE0A197ULL,
		0x46B4507EF8ABA063ULL,
		0x681AC2FC9F9005ADULL,
		0x077B71A954B5BC75ULL,
		0xA2E33F5366C0F9A4ULL,
		0xD9C371EAFBFABA7AULL,
		0x28F05DBE3EDBB5F1ULL,
		0x6FCE01C724A1F269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E7FDCBF15142D07ULL,
		0x14A3F10BFC9DDB23ULL,
		0x8C98FDC3D2C2C905ULL,
		0x092403EBA476AFFFULL,
		0xE6BBEAAFFEF43C33ULL,
		0xC9882A5D5BD8CDFAULL,
		0xB888741959D6F28BULL,
		0xA6B0B805C5BE7262ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E97372C48F48C90ULL,
		0x5217A17504367B40ULL,
		0xE4823F3F4D52CCA8ULL,
		0x0E5F7242F0C3138AULL,
		0x4458D5FC9834C597ULL,
		0x104B5BB7A0227780ULL,
		0x907829A7670D477AULL,
		0xC97EB9C2E11F800BULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x671BBDB05CAC93A6ULL,
		0xB58A432C09E6D00CULL,
		0x481F53AD581A004FULL,
		0xF2A1D9BE64C423E7ULL,
		0x21BE1FEE346BE500ULL,
		0x9CEC47345F92583AULL,
		0x86775220B15624FAULL,
		0xFBA81793B2AD3006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x595461A3A588A8AEULL,
		0x3345FA5E809B7751ULL,
		0xFE0028B6F4A1D12AULL,
		0x30930066C37ACD32ULL,
		0x31FF8414A45DF641ULL,
		0x2A8260A4FB845F9DULL,
		0xA2B17B1F89FEA66AULL,
		0xDDB3A76CF434A263ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E4FDC13F9243B08ULL,
		0x86CFB972897DA75DULL,
		0xB61F7B1BACBBD165ULL,
		0xC232D9D8A7BEEED5ULL,
		0x10419BFA90361341ULL,
		0xB66E2790A41607A7ULL,
		0x24C6293F38A88290ULL,
		0x261BB0FF46999265ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4A81238498E0A82ULL,
		0xD8625AC61E114103ULL,
		0x30B5F3FCE4CDE046ULL,
		0x67AD32F618DE948DULL,
		0xE59995FC12831032ULL,
		0x2A97D7C4DC3B9876ULL,
		0x5FFE4B9335A08B91ULL,
		0x163DA86B2D22D492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247C3928C0756901ULL,
		0xB8719CE363F4A038ULL,
		0xEF53FBC0FED94978ULL,
		0xD558E234562B9A05ULL,
		0x61194D5641555A17ULL,
		0xF6164F6E900825D2ULL,
		0xBA559A87A9670736ULL,
		0x1CE79777A82D7EEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0D42B1089FB6383ULL,
		0x6013C6257DE5E13BULL,
		0xDFE6083C1A14A93EULL,
		0xB2F5D0C24EF50E88ULL,
		0x8480D8AA53D64A25ULL,
		0xDC8198AA4C33BDA4ULL,
		0xE5ABD1149CC78CA7ULL,
		0x0ADA3F1C850FAA78ULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFF9F75BEE352D85ULL,
		0x160CBD7F40B742E9ULL,
		0xE0F48B2B0138B0ACULL,
		0x4C6D89893F8CA48AULL,
		0xAC77C41D09E3693EULL,
		0x7A6A66C4EAA8335DULL,
		0x20329835ED211D1EULL,
		0x7AEFAC80F399CF78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22333AC82679499ULL,
		0x4E1B4E886016E8E2ULL,
		0x35EF5BA9F97B0B27ULL,
		0x3185A6333FB8C1E4ULL,
		0x0C3622609EA3F673ULL,
		0x3B02CFAD1B790645ULL,
		0x6832799ED0A9C3B0ULL,
		0xD30DECB5E75B2CF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DDAC4F76C52B91CULL,
		0x5817F3F720A1AA0BULL,
		0xD51BD082F843BB8BULL,
		0x7DE82FBA0034656EULL,
		0xA041E67D97409F4DULL,
		0x4168A969F1D13518ULL,
		0x4800E1AB3D88DEAEULL,
		0xA9E2403514C2E38AULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C0431EEABAE5250ULL,
		0x15F9CDF95C3E5E16ULL,
		0x3A8A67579BC89165ULL,
		0xF32653CE16343F85ULL,
		0xA4C0BBDF3EABA060ULL,
		0xBCC5A70FAE60F2CEULL,
		0x965130314304E482ULL,
		0x408D8172D1996627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFC13E107C9709BULL,
		0xD171FB27A3286DD9ULL,
		0x74E308BE4CA222B3ULL,
		0xB54AF3C8D14B524FULL,
		0x434337EB7E86C073ULL,
		0x762CBB8BB34B3BD9ULL,
		0x86FA9356E923891CULL,
		0x2A3FB544B694F21CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73F8220FAC6722CBULL,
		0xC48836DEFF1633CFULL,
		0x4E696FE9D76AB3D6ULL,
		0x466CA006C77F6DCAULL,
		0xE7838C34402D6013ULL,
		0xCAE91C841D2BC917ULL,
		0x10ABA367AA276D9EULL,
		0x6AB23436670D943BULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD822A7E97D42A89ULL,
		0xBE9AC4072AABA43AULL,
		0x1BD89934872D2486ULL,
		0x462F69A321C69C0DULL,
		0x10DF3D38D32F63B4ULL,
		0x26EBC3F1B5A2CD46ULL,
		0x1CFE1D44E9378C8DULL,
		0x5106B00F19203CD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF88F6A9855AC31ULL,
		0x36A4A43F96242D90ULL,
		0x24184FE460198363ULL,
		0x1CB8027DA7A8FC02ULL,
		0xAEB92B26C6F5E1E8ULL,
		0xEF0B291085B635FCULL,
		0x35A82D9729B2BE01ULL,
		0x4A2FDD0903D8EA51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD27AA5140F8186B8ULL,
		0x883E6038BC8F89AAULL,
		0x3FC0D6D0E734A7E5ULL,
		0x5A976BDE866E600FULL,
		0xBE66161E15DA825CULL,
		0xC9E0EAE13014F8BAULL,
		0x295630D3C085328CULL,
		0x1B296D061AF8D683ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x538969102B65D0C2ULL,
		0x2C4C9C31E1F39E56ULL,
		0xD10F02FA6949EFD0ULL,
		0x0B8AFBAF48B5CAC1ULL,
		0x9709A29A237FFD0EULL,
		0xF3A897298683619DULL,
		0x358037ACF6F1072EULL,
		0xB6B648CC336CA6A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDE8AF50E3842AFAULL,
		0x471780A97442EB64ULL,
		0xC19F00AC817944C0ULL,
		0x26C1DAAE994BE843ULL,
		0xE0CD75359553FDB6ULL,
		0xC8109C7B65F19FCFULL,
		0x4BDF8041DE59B601ULL,
		0xB8B8D1BDC63C88B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E61C640C8E1FA38ULL,
		0x6B5B1C9895B17532ULL,
		0x10900256E830AB10ULL,
		0x2D4B2101D1FE2282ULL,
		0x77C4D7AFB62C00B8ULL,
		0x3BB80B52E372FE52ULL,
		0x7E5FB7ED28A8B12FULL,
		0x0E0E9971F5502E11ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E20AD9FA72D1168ULL,
		0x24ECADF539997D51ULL,
		0x7212D14CE2638C80ULL,
		0xFB16A3CD2131A7CAULL,
		0x21089DF98A7785ACULL,
		0xF6874853C1420822ULL,
		0x154EF65F3E7E7BDFULL,
		0x1FE5009153A9FA83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3959CAB209FD3E36ULL,
		0xA2B773341C79DD8FULL,
		0xDBAB28B4B6A7ED70ULL,
		0xFF3BB50D4D015D6EULL,
		0xA0039C50D5CCAFFAULL,
		0xFEE7E4BCDFE9FB48ULL,
		0xEA2B93D1E9CBC92AULL,
		0x8E8B8F094A60B4C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA779672DAED02F5EULL,
		0x865BDEC125E0A0DEULL,
		0xA9B9F9F854C461F0ULL,
		0x042D16C06C30FAA4ULL,
		0x810B01A95FBB2A56ULL,
		0x0860ACEF1EABF36AULL,
		0xFF65658ED7B5B2F5ULL,
		0x916E8F9819C94E46ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42794AF97658031EULL,
		0x9BE4C3E26E65C333ULL,
		0xFA2ECA434C7A4329ULL,
		0xCC804B84F5160847ULL,
		0xC093474460F5F4C7ULL,
		0xF8F57A872447CE7CULL,
		0x9668599FBC6C36E0ULL,
		0xE83D5DD7D1AC2382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x473C70377D48289EULL,
		0x20DE047FFD8EF781ULL,
		0x09092200DB710199ULL,
		0xF7FF1F28FD19753CULL,
		0x6921DA3D3E09BC00ULL,
		0xD3F176A7C918DD59ULL,
		0xB8461D5ED283C8E4ULL,
		0xF25B5D57A452DD81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05453ACE0B102B80ULL,
		0xBB3AC79D93EB34B2ULL,
		0xF327E843970B42B0ULL,
		0x3B7F54AC080F7D7BULL,
		0xA9B29D795EFC48C7ULL,
		0x2B040C20ED5F1325ULL,
		0x2E2E44C16EEFFE04ULL,
		0x1A66008075FEFE03ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF29D6E4E2D30ABAULL,
		0x4DADF6A298CBAA26ULL,
		0xD3C1EC5C983F75E4ULL,
		0x1EB2F50F42402A4DULL,
		0xF81C5B1CD6FB001FULL,
		0x35628A01A84D02D1ULL,
		0x43F97E89DBD3D20CULL,
		0xF638F99D2C02D170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A6BDB7E5A2244CEULL,
		0x2E68A0F7CB293186ULL,
		0x072C195D53C614BAULL,
		0x83A1794A9C02F5BAULL,
		0x9B9013DA17E19A31ULL,
		0xDA53E2A5B14306C5ULL,
		0x7411007318D29DA8ULL,
		0x43F605778F0EAF69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5420D9AB8F14E74ULL,
		0x63C5565553E29BA0ULL,
		0xD4EDF501CBF9615EULL,
		0x9D138C45DE42DFF7ULL,
		0x638C48C6C11A9A2EULL,
		0xEF3168A4190E0414ULL,
		0x37E87EFAC3014FA4ULL,
		0xB5CEFCEAA30C7E19ULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDBEEE4C75CA0172ULL,
		0x7A16A482EFDE3D9DULL,
		0xACA1FB3F784892F9ULL,
		0x272ED33F1F5B146DULL,
		0x6D3577D0D7A5E4DFULL,
		0xF7927B515A5F887DULL,
		0x133093CD99F821D0ULL,
		0xCE59F85C57D93AC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB27423582660DA6DULL,
		0x627158823AC872B7ULL,
		0xAE1FE902279BCFF7ULL,
		0x07AD1823DE647858ULL,
		0x007C50DCFB4B7AB1ULL,
		0x97446D276B252DC0ULL,
		0x4411806E4DFE7B1FULL,
		0x02FCE2C30D0AED8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FCACD1453AADB1FULL,
		0x1867FC00D5164F2AULL,
		0x02BE123D5FD35D0EULL,
		0x2083CB1CC13F6C35ULL,
		0x6D49270C2CEE9E6EULL,
		0x60D61676317AA5BDULL,
		0x572113A3D4065ACFULL,
		0xCCA51A9F5AD3D743ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ABA9FB2D6BDD684ULL,
		0xC5D74806126B9196ULL,
		0x8282DF4DD9042054ULL,
		0x4D8AD827195FA9D1ULL,
		0x2B94F8A5588BBDFBULL,
		0xD7CC9B168245F5BBULL,
		0x3CB7FB38D6659106ULL,
		0xDBBA691B1F731516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C636307A02A00C0ULL,
		0x649F71B6C240129BULL,
		0xA0C00171FA0BCF6FULL,
		0xD9F15EFA7BDFC66AULL,
		0x6FEC0D5D333504C0ULL,
		0xAD73363D2A8DC586ULL,
		0x25777285691F491FULL,
		0xB8081E0E1DEF9DA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76D9FCB57697D644ULL,
		0xA14839B0D02B830DULL,
		0x2242DE3C230FEF3BULL,
		0x947B86DD62806FBBULL,
		0x4478F5F86BBEB93BULL,
		0x7ABFAD2BA8C8303DULL,
		0x19C089BDBF7AD819ULL,
		0x63B27715029C88B1ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46C5CC1365B2AE5DULL,
		0xD6A597210EC5CA1DULL,
		0xB948E6DA5D3B4EC3ULL,
		0x473835267DEF7E3FULL,
		0xE16AD4C090357717ULL,
		0x8DA8C7DB007CC423ULL,
		0x06A09FBB130484B0ULL,
		0xB72E7BCB7C4E4E89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x066840452B4511F6ULL,
		0x8363AA45CD674012ULL,
		0xB3A06FF775C79E92ULL,
		0x5B1FDC466D39BC71ULL,
		0x503E57E02A51CBF7ULL,
		0xC88130D09C59950AULL,
		0x18ECFAF1D4E8E728ULL,
		0x31256935B44910A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40AD8C564EF7BFABULL,
		0x55C63D64C3A28A0FULL,
		0x0AE8892D28FCD051ULL,
		0x1C27E96010D6C24EULL,
		0xB1548320BA64BCE0ULL,
		0x4529F70B9C255129ULL,
		0x1E4C654AC7EC6398ULL,
		0x860B12FEC8075E2DULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE999CC885673A9F2ULL,
		0x2EBD2A5B046907C6ULL,
		0x66827F516B096C19ULL,
		0xA700F11B9B97C882ULL,
		0x8F1B86E27CA5697BULL,
		0x96BEEC5E109552C5ULL,
		0xABDB071A04FFD3D0ULL,
		0x699C4FD8AE1C2D77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD3A593DDBBF59B2ULL,
		0x3A8BBAF1E67524D2ULL,
		0xC54AF91A3841A3ECULL,
		0xAF1B14C472A6A2DDULL,
		0x3975E8FF30C38100ULL,
		0x7CF8BEA45538AF38ULL,
		0xF91095B29F899C63ULL,
		0x0D7137FF6BCA64C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14A395B58DCCF040ULL,
		0x143690AAE21C2314ULL,
		0xA3C8864B5348CFF5ULL,
		0x081BE5DFE9316A5FULL,
		0xB66E6E1D4C66E87BULL,
		0xEA4652FA45ADFDFDULL,
		0x52CB92A89B764FB3ULL,
		0x64ED7827C5D649B4ULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8D2FE8A1C4E9C30ULL,
		0x1E17C5148A36CC77ULL,
		0x41F451CC8E21A15DULL,
		0xFAA10833EEB7030AULL,
		0x1D41CE79E4D15E85ULL,
		0x66B9B5F790131314ULL,
		0x5718B1E576F0B238ULL,
		0xEA7312E581AFD03EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D9217BD8257E59ULL,
		0xB51B7F950BFB0C5FULL,
		0xDD37CA01D43F1D18ULL,
		0x3564139720C2DDB4ULL,
		0x0E08206659A1AC1EULL,
		0xCF778E76B976F2E1ULL,
		0x2CB39BA973F6A459ULL,
		0x6FFEA9B339F1D392ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F0BDFF1C46BE269ULL,
		0xAB0CBA8181CDC028ULL,
		0x9CC39BCD5A1EBC45ULL,
		0xCFC51BA4CE75DEBEULL,
		0x1349EE1FBD70F29BULL,
		0xA9CE3B812965E1F5ULL,
		0x7BAB2A4C05061661ULL,
		0x858DBB56B85E03ACULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66980C2DFE5DCC20ULL,
		0xE5A7AF1F4F73EE3BULL,
		0x0D2AF08952C2DBCEULL,
		0x969601C563C7E678ULL,
		0xE0A91E53AE6D9130ULL,
		0x92E52DCF3D69DF70ULL,
		0x0CD6AA7AD18CACC5ULL,
		0x98B7EAA3269A44C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E1CF2962EB6CE4ULL,
		0xF66785E8D49B55EDULL,
		0x18674F1D838F0D1FULL,
		0x87E42254CCA17CB9ULL,
		0x79F8DB7D5CF74333ULL,
		0x72E1A1BF90CDB261ULL,
		0x182D55D670EDA5BEULL,
		0x416EE85EBDEB3D78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3679C3049CB6A0C4ULL,
		0x13C02AF79BE8BBD6ULL,
		0x154DBF94D14DD6D1ULL,
		0x11722391AF669AC1ULL,
		0x9951C52EF29AD203ULL,
		0xE0048C70ADA46D11ULL,
		0x14FBFFACA161097BULL,
		0xD9D902FD9B7179BFULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20842C70E265A2EDULL,
		0x4D43F2DB93B15858ULL,
		0x22D2DABBF20F4B87ULL,
		0x3F2CD8BC26FDBBFFULL,
		0x2331E471AD5E5D99ULL,
		0x854820CDBEC39968ULL,
		0x19DDD36E710B2B84ULL,
		0x9924549F7B230727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46297BF88653FFF6ULL,
		0x43985F9BC119095EULL,
		0x1F3FB3494EF98236ULL,
		0x2684180AF211EFB2ULL,
		0x26FC8D20AAA08C8DULL,
		0x0392C2C83F455053ULL,
		0x62574FD8B85D8D27ULL,
		0x60C81E9F2CA6CE50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66AD578864365D1BULL,
		0x0EDBAD4052A85106ULL,
		0x3DED69F2BCF6C9B1ULL,
		0x19A8C0B6D4EC544DULL,
		0x05CD695107FED114ULL,
		0x86DAE2058186C93BULL,
		0x7B8A9CB6C956A6A3ULL,
		0xF9EC4A005785C977ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD1F4D342935FD26ULL,
		0xC644D0F3A795A7BEULL,
		0x4BAC3D6640F2CC59ULL,
		0xACC7BDD401A81C7DULL,
		0x6129F54CE19DAE0EULL,
		0xB59A1358B8B0DAD2ULL,
		0xC51AE22928B63FB4ULL,
		0xAEA39A87B0F4B467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F753D2464402305ULL,
		0xDCFF42DFD402B1BEULL,
		0x065E8F603AB03357ULL,
		0x4F53089E15F52F7FULL,
		0x7C319434BBB62F2BULL,
		0xF0374DC563665F75ULL,
		0x5D11784A4E8013F6ULL,
		0x848DB1F988972DA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x926A70104D75DE23ULL,
		0x1ABB922C73971600ULL,
		0x4DF2B2067A42FF0EULL,
		0xE394B54A145D3302ULL,
		0x1D1861785A2B8125ULL,
		0x45AD5E9DDBD685A7ULL,
		0x980B9A6366362C42ULL,
		0x2A2E2B7E386399CFULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF76AFE47429CC70ULL,
		0x16894BF6633D772EULL,
		0xA201AC3540E77572ULL,
		0x82C018B11BC26FFBULL,
		0xCD5181859B2937FDULL,
		0x22A27AF0045BFB61ULL,
		0x83BCEACBAE8EEF92ULL,
		0x4E5A18034DD7FC9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72968A8C8A1E21B8ULL,
		0x652F6715754DDF0CULL,
		0x135240620C0DF9F3ULL,
		0x478FB49B93BA0837ULL,
		0xC5B567F4CC16BDC5ULL,
		0xAA3ADF0A83E097BBULL,
		0x8BAC20C8D3796D73ULL,
		0xAB6F39F0FDDD0BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADE02568FE37EDC8ULL,
		0x73A62CE31670A822ULL,
		0xB153EC574CEA8C81ULL,
		0xC54FAC2A887867CCULL,
		0x08E4E671573F8A38ULL,
		0x8898A5FA87BB6CDAULL,
		0x0810CA037DF782E1ULL,
		0xE53521F3B00AF758ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0632AE74B7F6415BULL,
		0x1F33768528597D94ULL,
		0x946860F3513ED872ULL,
		0x5D918705D0203226ULL,
		0x7D1DD5949C1DE25CULL,
		0x453A895253C75E4DULL,
		0x39C2AF30B68C7D5DULL,
		0xC2222707BE258C82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CA1BDD6D0CE9DB4ULL,
		0x5F0AF8C83F002DE9ULL,
		0x3A84280FFEA32E8AULL,
		0xB6050E21001B0F60ULL,
		0x5255D0E8F5AE7808ULL,
		0x5E58EF5F00120DC8ULL,
		0xB92B11B6F22E3425ULL,
		0x24B70AD76BE11812ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A9313A26738DCEFULL,
		0x40398E4D1759507DULL,
		0xAEEC48FCAF9DF6F8ULL,
		0xEB948924D03B3D46ULL,
		0x2F48057C69B39A54ULL,
		0x1B62660D53D55385ULL,
		0x80E9BE8644A24978ULL,
		0xE6952DD0D5C49490ULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x913EEAFB13615582ULL,
		0x44859ED5DD0355A4ULL,
		0x59826B4D5E514201ULL,
		0x34021B9CA3C8B41EULL,
		0x9240E6719FE01D80ULL,
		0x8483188D4793E8E0ULL,
		0xFA54FDFAC311943DULL,
		0x78A88FC370E6D55CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA54A7BD89AB3C4FBULL,
		0x44BD905F1B1DA096ULL,
		0xAAFFCA52C3424BBFULL,
		0xAE8276D1FDAE3C33ULL,
		0x3380E0FBE03DBBC7ULL,
		0x2F8B8B452B24240CULL,
		0x25DAE15F3E6CC8EEULL,
		0xCCC36C1EA33AE1A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3474912389D29179ULL,
		0x00380E8AC61EF532ULL,
		0xF37DA11F9D1309BEULL,
		0x9A806D4D5E66882DULL,
		0xA1C0068A7FDDA647ULL,
		0xAB0893C86CB7CCECULL,
		0xDF8E1CA5FD7D5CD3ULL,
		0xB46BE3DDD3DC34F4ULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29D57776A2D7C538ULL,
		0x01F3B89774150668ULL,
		0x279F35A2259F9FC2ULL,
		0xF6780560B10BAD3BULL,
		0xA7687CC37E667794ULL,
		0x35930D9FC8ECE5EBULL,
		0x39FDFA11EE6517A9ULL,
		0x3202627DCEC857EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ADE4061D500C66AULL,
		0xB8F322DFEA3AC451ULL,
		0x83404BAC75024F2CULL,
		0xF31D6F50EFD299E9ULL,
		0xD2EEBFCA33AD036AULL,
		0xDE75D2D7DC8DBF1DULL,
		0xC721F6192A6C1E49ULL,
		0xB6D37C9E747A0F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x630B371777D70352ULL,
		0xB9009A489E2FC239ULL,
		0xA4DF7E0E509DD0EEULL,
		0x05656A305ED934D2ULL,
		0x7586C3094DCB74FEULL,
		0xEBE6DF4814615AF6ULL,
		0xFEDC0C08C40909E0ULL,
		0x84D11EE3BAB258ACULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E08834EE3D09DAAULL,
		0x10587D464A1CB13DULL,
		0xAC3A85A7691B3F8EULL,
		0x7A3A64519BE456F7ULL,
		0xA96875728BBA3FA5ULL,
		0xF392BC71E9653F8CULL,
		0xE64F5B891E702A25ULL,
		0xE4962A873CE80AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F72CB788316C51ULL,
		0xCAB8F34882A68D59ULL,
		0x2A6F47A467610B8BULL,
		0xE2ADF1746C909FD5ULL,
		0x3805CDE222EEF63FULL,
		0x2C22D9AD380E2401ULL,
		0x7CDBC06250C26026ULL,
		0x14E1B3F4536A5C00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDFFAFF96BE1F1FBULL,
		0xDAE08E0EC8BA3C64ULL,
		0x8655C2030E7A3405ULL,
		0x98979525F774C922ULL,
		0x916DB890A954C99AULL,
		0xDFB065DCD16B1B8DULL,
		0x9A949BEB4EB24A03ULL,
		0xF07799736F8256A2ULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC3140BD7028560CULL,
		0xEF4C475BEC2FF940ULL,
		0x6088D65A6197A3DDULL,
		0xD48AFE0BED70CE37ULL,
		0x14B2E6A8B8CF4083ULL,
		0xD0D108FE6793022CULL,
		0x0170A05F075B6D6BULL,
		0x93BDF6FD4A2637E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0B2610FA82B2CEDULL,
		0x9B6533F9008B9777ULL,
		0xBB96DFB00244D610ULL,
		0xE3760E3002C0198EULL,
		0x885EC80A3E893EDAULL,
		0x26DD303AE989E256ULL,
		0xF5162EEE77628F9CULL,
		0x18B965EAB27F8712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C8321B2D8037AE1ULL,
		0x742974A2ECA46E37ULL,
		0xDB1E09EA63D375CDULL,
		0x37FCF03BEFB0D7B9ULL,
		0x9CEC2EA286467E59ULL,
		0xF60C38C48E1AE07AULL,
		0xF4668EB17039E2F7ULL,
		0x8B049317F859B0F6ULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3E16A81AB7BAD55ULL,
		0xB28087C65A815E39ULL,
		0x02B518B8659F8057ULL,
		0xD777F2D130B073CAULL,
		0xEDD5CC2797D1F524ULL,
		0xF1A926A9DCF9F2DBULL,
		0x3E730DB761C49403ULL,
		0xDA5359B3ABD04EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7837751FF01EAA67ULL,
		0x3758116C22E3514EULL,
		0xA0DB2EFFB55CE186ULL,
		0x91751A901AED1206ULL,
		0x54D546A08D7585A4ULL,
		0x62222767EC5B20F0ULL,
		0x7788638355077ACDULL,
		0xD081F8645C55257AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BD61F9E5B650732ULL,
		0x85D896AA78620F77ULL,
		0xA26E3647D0C361D1ULL,
		0x4602E8412A5D61CCULL,
		0xB9008A871AA47080ULL,
		0x938B01CE30A2D22BULL,
		0x49FB6E3434C3EECEULL,
		0x0AD2A1D7F7856BDCULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x049B2EE760F81A7AULL,
		0xEB165F4DE58098F1ULL,
		0xE5769101FF8D6962ULL,
		0x2EB0B38D4E16FEF1ULL,
		0x0CB5642EDCF2C684ULL,
		0xB4DE8A3F512644E8ULL,
		0x1CE481DD04A0BEC7ULL,
		0xC4CDE986A577DC44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD859D7258B1E2A9AULL,
		0x02FA99C0518BC9AFULL,
		0xD81C212E02B50198ULL,
		0x50B9953FD44946AAULL,
		0xBBE95A3435FADE64ULL,
		0x8087C261378E78F3ULL,
		0x4930ECB20D4E79ACULL,
		0x98708735F87E5422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCC2F9C2EBE630E0ULL,
		0xE9ECC68DB40B515EULL,
		0x3D6AB02FFD3868FAULL,
		0x7E0926B29A5FB85BULL,
		0xB75C3E1AE90818E0ULL,
		0x3459485E66A83C1BULL,
		0x55D46D6F09EEC76BULL,
		0x5CBD6EB35D098866ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBDEA931F7327B7AULL,
		0xEE27C0E0204D8A8EULL,
		0x9FC54672F6151AD8ULL,
		0x3CCAC2B7D3B13CE3ULL,
		0x980B3AFCC255927FULL,
		0x6DE38E613DE6F5E7ULL,
		0x19AE7D88DD271941ULL,
		0x81EF315D0CAF7577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43B9B1775A5DCE2ULL,
		0x86C48373D60541E9ULL,
		0x12CB90D89D2A9F50ULL,
		0x422CBE713BBC3A28ULL,
		0xF77432029B4C0660ULL,
		0xD59E8F6DD43D059FULL,
		0x79E4DCC1CAD41B07ULL,
		0x9D5554D6913DD27BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FE532268297A798ULL,
		0x68E34393F648CB67ULL,
		0x8D0ED6AA6B3F8588ULL,
		0x7EE67CC6E80D06CBULL,
		0x6F7F08FE5919941FULL,
		0xB87D010CE9DBF078ULL,
		0x604AA14917F30246ULL,
		0x1CBA658B9D92A70CULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72C3F752FD8EDBEDULL,
		0x46AEB4DDAACD158CULL,
		0x53470DEB4CB3927EULL,
		0x35B515FCDA45B98DULL,
		0x65ED9A07492FA14EULL,
		0xF62E7F1657455AC6ULL,
		0xB596B20F87AB4366ULL,
		0x46984F52A5931B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C01D3F92ABC887AULL,
		0xB84BC99E1B3E816BULL,
		0x0E56FFC5E642F437ULL,
		0xDCE953E1ABDEBED5ULL,
		0x012C99E5BA262DD4ULL,
		0xD765E62C469CC20BULL,
		0xB9DA53070B2024D8ULL,
		0x61F1B5EF452E8349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EC224ABD7325397ULL,
		0xFEE57D43B1F394E7ULL,
		0x5D11F22EAAF16649ULL,
		0xE95C461D719B0758ULL,
		0x64C103E2F3098C9AULL,
		0x214B993A11D998CDULL,
		0x0C4CE1088C8B67BEULL,
		0x2769FABDE0BD985CULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x513F81D81EFF7623ULL,
		0x3D760832872E68C1ULL,
		0xEA584D0F2B11F766ULL,
		0x3C54F5B80576E854ULL,
		0xE9E0A94E35B5391BULL,
		0xFA0B6CE414C4A822ULL,
		0xB8C753A289921F1AULL,
		0xBA524F6AC0910536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x130AA391488D8C13ULL,
		0x37EF0FE4F6CCF1EAULL,
		0xCB35C43CC9AA70A3ULL,
		0x4A484727BB7253AEULL,
		0x0311D371B995C61DULL,
		0x8FC0E20DD61051FFULL,
		0xABAD06A4CACAE671ULL,
		0xDDAC1B1A0F92752EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x423522495672FA30ULL,
		0x0A9907D671E2992BULL,
		0x216D8933E2BB87C5ULL,
		0x761CB29FBE04BBFAULL,
		0xEAF17A3F8C20FF06ULL,
		0x75CB8EE9C2D4F9DDULL,
		0x136A55064358F96BULL,
		0x67FE5470CF037018ULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AEFDC446C954D06ULL,
		0xD2E3A1032F43A345ULL,
		0x39463D7F5FE9AEFDULL,
		0x48E9A856B4EA903BULL,
		0x8CE2C33C4EBFEA19ULL,
		0x19D3E6B895BF99E8ULL,
		0x7F3874CEB83F825CULL,
		0x35172EFC3491E7F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D58C032B7EF92F9ULL,
		0x7C5F0FFF576E7ABAULL,
		0x5270A9388F5D3B1FULL,
		0x3BC6B9B955A884F6ULL,
		0x30FAAA73AD55002DULL,
		0x4F6B87099DD1C0B1ULL,
		0xEDADCB76ED3A0624ULL,
		0xC778A43B0BD3907DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57B71C76DB7ADFFFULL,
		0xAEBCAEFC782DD9FFULL,
		0x6B369447D0B495E2ULL,
		0x732F11EFE14214CDULL,
		0xBC18694FE3EAEA34ULL,
		0x56B861B1086E5959ULL,
		0x9295BFB855058478ULL,
		0xF26F8AC73F427789ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79929CB5C9CABB84ULL,
		0x4DD64B72DC13F10EULL,
		0xBF279A221CA7949AULL,
		0x90F2057515A88506ULL,
		0x4865C9FF87510244ULL,
		0x5EA255287DD818EDULL,
		0xDD1B9EE35FD26445ULL,
		0x2AF22A1D6D0D9EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC82D49A95180B3EDULL,
		0x7B2BE32EED07FC63ULL,
		0x1C60F3473BFFA423ULL,
		0x24108B60C20B3140ULL,
		0x99054823796C862EULL,
		0x25693AE44C9B6BF9ULL,
		0xE9C85BA3F13FDC51ULL,
		0xB1859AC0DC28A974ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1BFD51C984A0869ULL,
		0x36FDA85C31140D6DULL,
		0xA3476965275830B9ULL,
		0xB4E28E15D7A3B446ULL,
		0xD16081DCFE3D846AULL,
		0x7BCB6FCC31437314ULL,
		0x34D3C540AEEDB814ULL,
		0x9B77B0DDB125378AULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E0F89CB34E2895CULL,
		0x71E73A441CDF01B2ULL,
		0xF0F19DAB2804EDD1ULL,
		0x391E3231B984C58DULL,
		0x91D5D541F232064AULL,
		0x59CA3B0E06C3E505ULL,
		0x6306F003F057D7E2ULL,
		0x873E4F2C20AC0BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x612E2486D7C464C2ULL,
		0x04AFAF84D3867FCBULL,
		0x811A4D5B8806D81EULL,
		0x8D120298FB63DD5FULL,
		0xA271867636378CC0ULL,
		0xF35C331F5DB557B8ULL,
		0x20985F8D16F33DE0ULL,
		0xCA616C0EAC2D3FE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F21AD4DE326ED9EULL,
		0x754895C0CF597E79ULL,
		0x71EBD0F0A00235CFULL,
		0xB40C30A942E718D2ULL,
		0x33A45337C4058A8AULL,
		0xAA9608115B76B2BDULL,
		0x439EAF8EE6A4EA02ULL,
		0x4D5F23228C81340AULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD82ECD01B756F3D2ULL,
		0x4B4C5CEF57BF19A5ULL,
		0x42F6DA3AD0998AE1ULL,
		0x00CDCEC37A9C4B66ULL,
		0x2188EC51A198F80DULL,
		0x4E6D5AE3AC5BFB06ULL,
		0xDCE2418B6F1EE768ULL,
		0x3B72768498516EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE7668EAD1F6A527ULL,
		0xF9EE998B1E31E78AULL,
		0x0AAB11942BACC4E0ULL,
		0xEDBB95F267BB2D74ULL,
		0xABBC1F6EB730A177ULL,
		0x97C3D3148BE74E19ULL,
		0x852BBE6B30204279ULL,
		0x511EAC56903CA150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7658A5EB66A056F5ULL,
		0xB2A2C564498EFE2FULL,
		0x485DCBAEFB354E01ULL,
		0xED765B311D276612ULL,
		0x8A34F33F16A8597AULL,
		0xD9AE89F727BCB51FULL,
		0x59C9FFE05F3EA511ULL,
		0x6A6CDAD2086DCFF2ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA8872B19FF603B3ULL,
		0x719A2467FD56A5DCULL,
		0xA1263DA717C1F612ULL,
		0xDFDA9A33AEF7DA9CULL,
		0xC2D5AD48583FAC5DULL,
		0xCA0CD8A06FE2E230ULL,
		0x7F12234B11DC30F2ULL,
		0x9B65F8C91DACD5AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC7A0EBF160A3BBEULL,
		0x6CB80E8F8D70D772ULL,
		0x872A15780B6A1912ULL,
		0xEDE9A9B1E6F004F3ULL,
		0x5B39FD81C0D6FDC2ULL,
		0xB3B0EFD4354641C7ULL,
		0x39D026C72A1FAAC0ULL,
		0x064F4D400AAEC594ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06F27C0E89FC380DULL,
		0x1D222AE8702672AEULL,
		0x260C28DF1CABEF00ULL,
		0x323333824807DE6FULL,
		0x99EC50C998E9519FULL,
		0x79BC37745AA4A3F7ULL,
		0x46C2058C3BC39A32ULL,
		0x9D2AB5891702103EULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x156A7C7EAC2B7EB4ULL,
		0xDB4663944924DC63ULL,
		0x4C2527F4557C8452ULL,
		0x1D9393C4ADF065A4ULL,
		0xAFEE32F09EED833AULL,
		0x06D012AAFFC4B175ULL,
		0x89692F7361355233ULL,
		0x3B4F0D0DEBE7E50BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7F1A8BEB7BAF881ULL,
		0x2B22B222BBAEA6A4ULL,
		0xB54F55F3CA4CC34BULL,
		0x3A3616BF3488E09EULL,
		0x4885B3DF47899787ULL,
		0x44B377A2ADD49695ULL,
		0xEC5BB64A8C234A88ULL,
		0x83177C335EF5038FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE29BD4C01B918635ULL,
		0xF064D1B6F28A7AC7ULL,
		0xF96A72079F304719ULL,
		0x27A5857B9978853AULL,
		0xE76B812FD96414BDULL,
		0x42636508521027E0ULL,
		0x65329939ED1618BBULL,
		0xB858713EB512E684ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA89318834A133374ULL,
		0x28879043B2EBB418ULL,
		0xFCDF40FC7D9F6F72ULL,
		0x3D248C25A23AB23EULL,
		0x68E3F9D134C478E9ULL,
		0xE5C8908644C08197ULL,
		0x6466E8C20BCB6D6AULL,
		0xA28FC5E76C80C14DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0666A7D1D50EBBF1ULL,
		0x481376B69FB4235FULL,
		0x8E05F3B1C182DFF4ULL,
		0x0FEC4BD56F83DACDULL,
		0x21879A7FA825F2AFULL,
		0xCF7EE48D1316C136ULL,
		0xE9F55E78A9D3770DULL,
		0x04112276FCA82775ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEF5BF529F1D8885ULL,
		0x6094E6F52D5F9747ULL,
		0x72DAB34DBC1DB086ULL,
		0x32C8C7F0CDB968F3ULL,
		0x496463AE9CE18A46ULL,
		0x2AB6740B57D640A1ULL,
		0x8D93B6BAA2181A67ULL,
		0xA69EE7919028E638ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF8F54ECA17078E3ULL,
		0xEAF9C45902677616ULL,
		0x603E14819636C9F8ULL,
		0x3E1F199B75C1C8DEULL,
		0x67BDBEE614EAA4D2ULL,
		0xD72284AF9A99F4DCULL,
		0x45D7664793401E32ULL,
		0xA252D2FB96091A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x282513342AEC310BULL,
		0xA0AA15134BD2CC35ULL,
		0x10E54093493A5AE5ULL,
		0xCB3C0C3A5D2200DBULL,
		0xF4223E22E300E72EULL,
		0xC1A2459C575B6548ULL,
		0xDCCD885B930147B3ULL,
		0xB892FE4D0F5CF31AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97AA47D88B9C49E8ULL,
		0x4A53D14A49B5BA23ULL,
		0x70DB5412DF0C931DULL,
		0xF52315A128E3C805ULL,
		0x939F80C4F7EA43FCULL,
		0x1680C133CDC29194ULL,
		0x991AEE1C00415981ULL,
		0x1AC02CB69955E90BULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A902ABB64A4B341ULL,
		0x5863089ADEAF60BEULL,
		0xCEA360237072C476ULL,
		0x461A261F54B5900FULL,
		0x12BACE141B8EEFDDULL,
		0xEA540CAEB0DE10D3ULL,
		0x72AF08FFA429D1A2ULL,
		0x1CBAC0A2BC2F442FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863E9ECB5B810A50ULL,
		0x553370A44636564FULL,
		0x72B35A820920B6F0ULL,
		0xE8A1A0E61BCE121EULL,
		0x7B5E0AA78453CD2AULL,
		0x071802A224DDA67FULL,
		0x99A3F080727FCBA6ULL,
		0xE87A6316E3E34BCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CAEB4703F25B911ULL,
		0x0D50783E989936F1ULL,
		0xBC103AA179527286ULL,
		0xAEBB86F94F7B8211ULL,
		0x69E4C4B39FDD22F7ULL,
		0xED4C0E0C9403B6ACULL,
		0xEB0CF87FD6561A04ULL,
		0xF4C0A3B45FCC0FE3ULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EEB412BAAA4FD65ULL,
		0x32E249A4AA52E3D3ULL,
		0x3B3BDF2E574B8041ULL,
		0x569D8517F48C95A2ULL,
		0x8E04E30C56171B1EULL,
		0xE9B5E53DBA1DDC7AULL,
		0xCF9F9501EBCC375FULL,
		0x4FD8329B3EA5C380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE8EBBED481F61EULL,
		0x28FC105201B07322ULL,
		0xBCD76E8868BD891FULL,
		0x80FB9905DCC8BCA4ULL,
		0xB9B090FC0D5D4AAAULL,
		0x9B8B671913BFB974ULL,
		0x504030C9F0AF4728ULL,
		0x1057294AA5A46CA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE203AA957E250B7BULL,
		0x1A1E59F6ABE290F1ULL,
		0x87ECB1A63FF6095EULL,
		0xD6661C1228442906ULL,
		0x37B473F05B4A51B4ULL,
		0x723E8224A9A2650EULL,
		0x9FDFA5C81B637077ULL,
		0x5F8F1BD19B01AF26ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x862AD9781297B9F1ULL,
		0xACC73527A58195BAULL,
		0x44E61609E18A2CF6ULL,
		0x69192BB955E977DFULL,
		0xC22612AEE3F12D05ULL,
		0x0974FFE1BFFB8D2AULL,
		0x52D37D518DAA25A7ULL,
		0x3565D8921E5566D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE6073456F22955ULL,
		0xB4748684612FDAE9ULL,
		0x3F514DED3A341A2CULL,
		0xF252F3A3CCCD6FC4ULL,
		0x415E4C062704B686ULL,
		0xC7BC73686DC6B532ULL,
		0x27A8ADB1F8F713CBULL,
		0x150B5A919497C375ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCCCDE4C446590A4ULL,
		0x18B3B3A3C4AE4F53ULL,
		0x7BB75BE4DBBE36DAULL,
		0x9B4BD81A9924181BULL,
		0x83785EA8C4F59B83ULL,
		0xCEC88C89D23D3818ULL,
		0x757BD0E0755D366CULL,
		0x206E82038AC2A5ACULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2611BEFA4266867DULL,
		0xA40B9C725C6433B0ULL,
		0x6B05D5E4B1F15010ULL,
		0xA750BE9BD95D5CAEULL,
		0x95D9073CE2887F81ULL,
		0xE82C9EA358D67263ULL,
		0x3D1B1EF4A2053C61ULL,
		0x3D248C4A0CB60F19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEBD15987F25284EULL,
		0x9344D8FF1F561D70ULL,
		0x84D6BCAEDB26A40AULL,
		0x4345CB16AD6CCA4CULL,
		0x79823CC7B79A5798ULL,
		0xEFE26C172ECC05C5ULL,
		0x532E5E31FB21E379ULL,
		0x7DE78E2B10993869ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8ACAB623D43AE33ULL,
		0x374F448D43322EC0ULL,
		0xEFD3694A6AD7F41AULL,
		0xE415758D743196E2ULL,
		0xEC5B3BFB55122819ULL,
		0x07CEF2B4761A77A6ULL,
		0x6E3540C55924DF18ULL,
		0x40C302611C2F3770ULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87F35925C75A058EULL,
		0xCF33564451DCC615ULL,
		0xE178823A30D51DAFULL,
		0x801FA3C3C1BD8921ULL,
		0xFA466C9FE573E110ULL,
		0x80AFBA43E84ED9DFULL,
		0x5E6DA473E66A9739ULL,
		0x5D278F5182F606FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE22046E09EBA37CULL,
		0x0A10E04654757E6BULL,
		0x0292642543F10FE3ULL,
		0x2743866D2A574F99ULL,
		0xD180DB3F47E90ECEULL,
		0x649FC5DE917A7966ULL,
		0x1294DF89CDE9F240ULL,
		0x9634DE633997DCF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49D15D4BCEB1A6F2ULL,
		0xC523B60205A9B87EULL,
		0xE3EAE61F7324124CULL,
		0xA75C25AEEBEAC6B8ULL,
		0x2BC6B7A0A29AEFDEULL,
		0xE4307F9D7934A0B9ULL,
		0x4CF97BFA2B836579ULL,
		0xCB135132BB61DA0CULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB38040453F7DC4DULL,
		0xA5FFB566749D8DEBULL,
		0x5CAFD1B164F4358CULL,
		0xCAF4C9A38A19DC82ULL,
		0xCA6068E0CB85F41BULL,
		0x2EE794A32BACE995ULL,
		0x8B0477C2BD39760DULL,
		0x1A1398D6A8A969B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE8D07B284A0E51ULL,
		0x1A5B39F872943AECULL,
		0x486C14DC528B1C9FULL,
		0x39D4AFF0D2FC5DD9ULL,
		0x62F02475564A0029ULL,
		0xF5375EF51B693558ULL,
		0xAA0351CC3D4FED8CULL,
		0x652FDE8115D43FAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1D0D47F7BBDD21CULL,
		0xBFA48C9E0609B707ULL,
		0x14C3C56D367F2913ULL,
		0xF320665358E5815BULL,
		0xA8904C959DCFF432ULL,
		0xDBD0CA5630C5DCCDULL,
		0x2107260E80769B81ULL,
		0x7F3C4657BD7D5616ULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8CF49CF28662A4DULL,
		0x0DD5ED83863C1524ULL,
		0x31483BC2A97689F1ULL,
		0x2C7E23D6617C31C7ULL,
		0x6AA5FB54D721BC41ULL,
		0x4B6D3E58445ADA8CULL,
		0x6C255DF5E9D6DC69ULL,
		0xDBAA5A4487C0853CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E06A2E772BFD84ULL,
		0x42127EE522EE2BAEULL,
		0x76E1850A2D60BB2FULL,
		0x9EDEB37415374FBBULL,
		0xF5D0441C7DEC21B1ULL,
		0x4B8C97B410157218ULL,
		0xFA70BDE2FCCB95CDULL,
		0xE4AE096879DF6099ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B2F23E15F4DD7C9ULL,
		0x4FC79366A4D23E8AULL,
		0x47A9BEC8841632DEULL,
		0xB2A090A2744B7E7CULL,
		0x9F75BF48AACD9DF0ULL,
		0x00E1A9EC544FA894ULL,
		0x9655E017151D49A4ULL,
		0x3F04532CFE1FE5A5ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F5DE328A49FB20FULL,
		0xA214F0C519DF218AULL,
		0xE96B3F18AFCA4580ULL,
		0x085BC00917FA955AULL,
		0xB3FC88E7EF635190ULL,
		0x98A619D1FD779BBAULL,
		0x4EA58FBA7A7CD355ULL,
		0xB4CB10F125B01D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0EB4396F9D738C8ULL,
		0x617FAFEF7B065EC0ULL,
		0xAB1593F4A72AD7A0ULL,
		0x98D58651CF51226CULL,
		0xB6ED194673365CEBULL,
		0x08D73D7532F950BDULL,
		0x5ECA26367A3D708DULL,
		0xBA6FC8CCF561DF26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFB6A0BE5D488AC7ULL,
		0xC36B5F2A62D97F4AULL,
		0x427EACEC08E09220ULL,
		0x908E4658D8ABB736ULL,
		0x051191A19C550D7BULL,
		0x907124A4CF8ECB07ULL,
		0x106FA98C0041A3D8ULL,
		0x0EA4D83DD0D1C21AULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD222E93DBE37C49ULL,
		0x307CE34055E05D4FULL,
		0xF95222CF5A62EA94ULL,
		0x50D579E2C41D059AULL,
		0x54D7C33CB3AE76ECULL,
		0x454F3F7787665049ULL,
		0x33323326A8DBA844ULL,
		0x6A27CCB7DEBDD02BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5011C96AB9A1BAEDULL,
		0xF301CC594969B6C3ULL,
		0x2C33DD85C0EDCDF7ULL,
		0x8BC75834850A1CADULL,
		0x25630F48282DF849ULL,
		0xD4D33E84C3B6271AULL,
		0x837D336AAD0A25AAULL,
		0xEE25E08F16225029ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D33E7F96242C6A4ULL,
		0xC37D2F191C89EB8CULL,
		0xD561FF4A9A8F2763ULL,
		0xDB1221D641171937ULL,
		0x71B4CC749B838EA5ULL,
		0x919C01F344D07753ULL,
		0xB04F004C05D18DEEULL,
		0x84022C38C89F8002ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDABED15455761181ULL,
		0x6C732B8C926D6825ULL,
		0x2936BD34EA30C582ULL,
		0xD9DFEB339E87524AULL,
		0xDA5C3D33D43B6011ULL,
		0x907A9CF734ABB419ULL,
		0xEE506F5AAED844CDULL,
		0xC733B18FC639E07AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF35566E6E70864ULL,
		0x9A4F8E5331DFD687ULL,
		0xFB227EE4108BD1B2ULL,
		0x8D855A4B001FF6DFULL,
		0xFBBF751A491D1989ULL,
		0x11EFFE3349F0F945ULL,
		0x430CCEB188E0BC15ULL,
		0xF4AC44F72DDF5B8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x964D8432B39119E5ULL,
		0xF63CA5DFA3B2BEA2ULL,
		0xD214C3D0FABB1430ULL,
		0x545AB1789E98A495ULL,
		0x21E348299D267998ULL,
		0x819562C47D5B4D5CULL,
		0xAD5CA1EB2638F8D8ULL,
		0x339FF578EBE6BBF0ULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16061C4A8521A066ULL,
		0x0694B852F6AFF0BEULL,
		0x60FCAB4EE184E537ULL,
		0xF8E0E3F3E19CFEF3ULL,
		0x2285B7C7DCC0DD42ULL,
		0xA91C7A6C0968F4E6ULL,
		0xBBA1033F5625A072ULL,
		0x53DFDDD977922B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66C8CE3A249B62BULL,
		0x07E7A02FD946CF25ULL,
		0x4AD0C99C3E3A837CULL,
		0x82B935D610758C25ULL,
		0xE3E73EEEBCDC63FEULL,
		0xAF03C7C8A4994252ULL,
		0xA2C0F8CF1917DEEBULL,
		0xA1DEE397432E0A5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD06A90A92768164DULL,
		0x0173187D2FE93F9BULL,
		0x2A2C62D2DFBE664BULL,
		0x7A59D625F1E972D6ULL,
		0xC1628929601CBEBCULL,
		0x061FBDA4ADF1B6B4ULL,
		0x1961FBF04F327E99ULL,
		0xF2013E4E34BC211EULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C4E9C7900C8B8E8ULL,
		0x2C370E71F6C5082CULL,
		0xEFB38BB7E575A6BCULL,
		0xC7B61D02E0B5EF76ULL,
		0x056663A3C2ED2E45ULL,
		0xE2594F32047D6A2CULL,
		0x96F018DC2CCBFEDBULL,
		0xFBF7C6C66C6FAB0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ED8E0FE43588AC8ULL,
		0xE1F3F170690DD10FULL,
		0x892DA2B454D7A78DULL,
		0xC861BC5CFC4719E5ULL,
		0x46D45E73B2CDEC79ULL,
		0x1F00FA1D3E2B4151ULL,
		0xC83CAE5FEF997470ULL,
		0x2AFC548482B821CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2967C8743903220ULL,
		0xCDC4FF019FC8D923ULL,
		0x669E2903B1A20131ULL,
		0x0FD7A15E1CF2F693ULL,
		0x43B23DD07020C23CULL,
		0xFD59B52F3A562B7DULL,
		0x5ECCB683C3528AABULL,
		0xD10B9242EED78AC0ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x083D4A20E90BDDDCULL,
		0x67F4B86022A34332ULL,
		0x57C37DBBD18CE832ULL,
		0x4358F5DBF02B7EFEULL,
		0x4A7F9B70D3639024ULL,
		0x65454CD79912D6BAULL,
		0x9352DBE79C04757EULL,
		0x0C94B65459C54F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x935884C129410A7BULL,
		0x91DDA52DC4A477F1ULL,
		0xF561422795BB799AULL,
		0xBB1FD332A3BA7764ULL,
		0xF7EBC6D86A825D5DULL,
		0xBD809A0AE8B24FA0ULL,
		0x1BEABAE68F6157CAULL,
		0x6C86EB785071BAFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B65CEE1C04AD7A7ULL,
		0xF6291D4DE60734C3ULL,
		0xA2A23F9C443791A8ULL,
		0xF84726E95391099AULL,
		0xBD945DA8B9E1CD79ULL,
		0xD8C5D6DD71A0991AULL,
		0x88B86101136522B4ULL,
		0x60125D2C09B4F56DULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14A794E3A07F8602ULL,
		0x0E9916D57B395EF6ULL,
		0x635E0954A79215F7ULL,
		0xF7603A47D5F483B9ULL,
		0xFF516AAA15074829ULL,
		0xB34B50D497BFF979ULL,
		0x9CB66B41D4E26524ULL,
		0x93914C83CAAFCD38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF091CFA3F81F7096ULL,
		0x7EB22D433BCCDC03ULL,
		0xDD2F18A8EF423144ULL,
		0xC38AAC7620CDB0A0ULL,
		0xB0544CB06FA1E389ULL,
		0x71188AB744B4CE50ULL,
		0xBB62086780911DADULL,
		0x706DF2BD327E7330ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4365B405860F694ULL,
		0x702B3B9640F582F5ULL,
		0xBE7111FC48D024B3ULL,
		0x34EA9631F5393319ULL,
		0x4F05261A7AA6ABA0ULL,
		0xC253DA63D30B3729ULL,
		0x27D4632654737889ULL,
		0xE3FCBE3EF8D1BE08ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD51F1E6A1D37165ULL,
		0xB973EDBBC5A50AF4ULL,
		0x22204A3FE75F9EE6ULL,
		0xA6FF236269B7728AULL,
		0xB215090B009E3FD9ULL,
		0x7495FE43A45049A6ULL,
		0xF5000A1044C0D63DULL,
		0x99AB702AD66E55E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B3A497265DF6D28ULL,
		0x3A4F13C4567A0243ULL,
		0x2B70307D454B0A7DULL,
		0x56116E524188A9E3ULL,
		0xA55F01AEDF220569ULL,
		0xF5F5DF8510F55CE5ULL,
		0x552115D938F7D810ULL,
		0x10BDA34951F80312ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA66BB894C40C1C4DULL,
		0x833CFE7F93DF08B7ULL,
		0x09507A42A214949BULL,
		0xF0EE4D30283FDB69ULL,
		0x174A08A5DFBC3AB0ULL,
		0x816021C6B4A51543ULL,
		0xA0211FC97C370E2DULL,
		0x8916D363879656F3ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2003B7DA03C45F0ULL,
		0xDD573A21A104E1EEULL,
		0x475E32643DB2D2A8ULL,
		0xAB2B49129A363B9CULL,
		0xE9D355D0D5A47372ULL,
		0x32B04DD30FBDAC4AULL,
		0x1D9294D271F06DA5ULL,
		0x497E46C3E77E6FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279CA3677CADF141ULL,
		0x42010574DB70DCA2ULL,
		0x37B239A546EC6AEBULL,
		0xD483D40CBB6FD9E0ULL,
		0x3AEEEAF9A25E6DA0ULL,
		0xD77D09D632AB2BBEULL,
		0x80784EC9FA9EF279ULL,
		0x501FDDB89957C6EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x859C981ADC91B4B1ULL,
		0x9F563F557A743D4CULL,
		0x70EC0BC17B5EB843ULL,
		0x7FA89D1E2159E27CULL,
		0xD33DBF2977FA1ED2ULL,
		0xE5CD44053D1687F4ULL,
		0x9DEADA1B8B6E9FDCULL,
		0x19619B7B7E29A95EULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE77CCAA0CEE2769DULL,
		0x82EE8CCA2A519302ULL,
		0xA9D1DCE4FB403ABBULL,
		0x7284D894ED500728ULL,
		0xEC5C987E32C93FACULL,
		0xBC5A4EA33533FD94ULL,
		0xB98E4C468BDA31CBULL,
		0xA3BF55820FA309A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4658F9CF761281ULL,
		0x7C680701C111EBE5ULL,
		0x479E0D323CCCCE57ULL,
		0xEE6AE9437E818079ULL,
		0x0571448F2798F0C6ULL,
		0x5A4770A9413FF023ULL,
		0x3C52A21DF1864C09ULL,
		0x16435D83A4BD2708ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x283A92590194641CULL,
		0xFE868BCBEB4078E7ULL,
		0xEE4FD1D6C78CF4ECULL,
		0x9CEE31D793D18751ULL,
		0xE92DDCF11551CF6AULL,
		0xE61D3E0A740C0DB7ULL,
		0x85DCEE5B7A5C7DC2ULL,
		0xB5FC0801AB1E2EA0ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFF31AE6F80BAF18ULL,
		0x16038842F5E72050ULL,
		0xC6ECE770689442F7ULL,
		0xB4EEDF56A3DE44D0ULL,
		0xADFB1E534E74D8DAULL,
		0x3773336EEDC7A134ULL,
		0x8BC9879EA80706C9ULL,
		0xBD0FA309A670EA4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97A222D1F7098086ULL,
		0x7D94C9DF35E9C4ACULL,
		0xD9C5AE5D89F97023ULL,
		0xD07CF601F75484B5ULL,
		0x08C31ED273A6BB3CULL,
		0xFB08748EA9D5C3BEULL,
		0x4AF22DBE9B97D996ULL,
		0x2546BA2632689279ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x685138370F022F9EULL,
		0x6B97419DC00EE4FCULL,
		0x1F29492DE16D32D4ULL,
		0x64922957548AC065ULL,
		0xA53800813DD263E6ULL,
		0xCC7B47E04412628AULL,
		0xC13BAA203390DF5FULL,
		0x9849192F94187835ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA717C8C5CFCC75E1ULL,
		0x8F8E89F337AC8D9BULL,
		0xC8325B0E08705D6EULL,
		0x312C56792E92234FULL,
		0x00E2E95AFF954331ULL,
		0x461508CEB56AEBD5ULL,
		0xB07E7EC37895EF9DULL,
		0x51991159841D9B9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC932ED9234F4EC1AULL,
		0x58E4C75D19D018FCULL,
		0x22A440B2B93CFEC0ULL,
		0xFF32A580F871791EULL,
		0x6C7FC8566E5CFDE5ULL,
		0xC4880150FD96451BULL,
		0xB4DE6DACB17C41C9ULL,
		0xAC4EC014305D6074ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E252557FB3899FBULL,
		0xD76A4EAE2E7C9567ULL,
		0xEA961BBCB14CA3AEULL,
		0xCE1EF3F9D6E35A51ULL,
		0x6C9D210C91C9BED4ULL,
		0x829D099E48FCAECEULL,
		0x04A0136FC9E9AE54ULL,
		0xFDD7D14DB440FBEEULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38CB70777F316242ULL,
		0xB7F333BE523F3868ULL,
		0x7CD61BA6D227F673ULL,
		0x4C4FD9356CDA6DD8ULL,
		0x4463CE23CE1A12D8ULL,
		0xD03888C23BB37952ULL,
		0x343A419F973B2B95ULL,
		0x53E3DEFA1A3BD635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB806C82DC45F9EDULL,
		0xDD8A43FCDDC0F889ULL,
		0x0D96CFAC93F16DEEULL,
		0xDD1C87E54D74CD8BULL,
		0xC7F19C4DBEF2191EULL,
		0x369C9E0ED461FF30ULL,
		0x34A9517D81314444ULL,
		0xB19FFA2DAECB4957ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x834B1CF5A3749BAFULL,
		0x6A7970428FFFC0E1ULL,
		0x7140D40A41D69B9DULL,
		0x91535ED021AEA053ULL,
		0x8392526E70E80BC6ULL,
		0xE6A416CCEFD28662ULL,
		0x009310E2160A6FD1ULL,
		0xE27C24D7B4F09F62ULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x241D21CEC6C95645ULL,
		0x85642C51DB28D92EULL,
		0x82E0A6FF3E2734D4ULL,
		0x6944DDDDA492C0B0ULL,
		0x34B03C4C3DE2DD8AULL,
		0x889CE893DCE56814ULL,
		0xF24CC1D600975366ULL,
		0x912EBBF827E4197BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F20D859A75CBF9ULL,
		0xCBE1272913EADE5AULL,
		0xA5177AFC3D1BB978ULL,
		0xA938761E3E7F0C61ULL,
		0x79DE42DA9E346968ULL,
		0x05EB4384F1F1CE09ULL,
		0x08CC131A78DD4128ULL,
		0x5FA4867F27E5F6FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECEF2C4B5CBC9DBCULL,
		0x4E850B78C8C20774ULL,
		0x27F7DC03033C8DACULL,
		0xC07CABC39AEDCCD1ULL,
		0x4D6E7E96A3D6B4E2ULL,
		0x8D77AB172D14A61DULL,
		0xFA80D2CC784A124EULL,
		0xCE8A3D870001EF85ULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85F736F5F2828214ULL,
		0xF0A9E0A3419F1FFEULL,
		0xB009E29D4918EC23ULL,
		0x5EC6493EFB67982AULL,
		0x25312EEFE7E60006ULL,
		0xC003D2BF80C6D6D1ULL,
		0x9AFB352BE78ECF08ULL,
		0x93B3BD0231F6D93DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F88EA9B7D35A5DULL,
		0x7D3091101F0FDB08ULL,
		0x5E206D0E925AE9FBULL,
		0xA500319AFFA6E781ULL,
		0x9EE87A513F25D8F2ULL,
		0x465E31109333998DULL,
		0xC5595D613B8DCBA8ULL,
		0x932CF4D2EB80B774ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x950FB85C4551D849ULL,
		0x8D9971B35E90C4F6ULL,
		0xEE298F93DB4205D8ULL,
		0xFBC678A404C17FABULL,
		0xBBD954BED8C3D8F4ULL,
		0x865DE3AF13F54F5CULL,
		0x5FA2684ADC0304A0ULL,
		0x009F49D0DA766E49ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A381D7AE86CA445ULL,
		0xA80645EE2189BE88ULL,
		0x9B155CD17CA48188ULL,
		0x8843D1B77B06CCA7ULL,
		0x46B0BE15D7E8D968ULL,
		0xF3B744C4CF8C70B8ULL,
		0x12424C1D01E4DC79ULL,
		0x595A15FDAD54444AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDFBA64FA9F73FF4ULL,
		0x6446504D3BDFDCD3ULL,
		0xA0E06B7AE43D1D5DULL,
		0xBD7FCA17EAD81525ULL,
		0xEA4E3F4A90814485ULL,
		0x54F3373286126FB5ULL,
		0x0AE8FBFD2A08DFD0ULL,
		0x3E6519441608CD83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7C3BB35419B9BB1ULL,
		0xCC4015A31A56625BULL,
		0x3BF537AB98999CD5ULL,
		0x353C1BA091DED982ULL,
		0xACFE815F47699DEDULL,
		0xA74473F6499E1F0DULL,
		0x18AAB7E02BEC03A9ULL,
		0x673F0CB9BB5C89C9ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x125FE03D96EC20FEULL,
		0xBCB933AAD0CE8A1BULL,
		0x9182A8BDC4D1C846ULL,
		0x8ECDD22E9D173717ULL,
		0x64713FDBCFF1DDFFULL,
		0xD6D87179821B43CDULL,
		0x392C51748A2D981FULL,
		0x856CE90381D208A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6AA9B12AEC1E1B9ULL,
		0xB360E1C993195E26ULL,
		0xFE33BC432CD9242CULL,
		0x04C63D73FD6942EAULL,
		0x782F813442F3F1A7ULL,
		0x9D6F81EADF08E566ULL,
		0x2B133C408857C632ULL,
		0x350539630BE57984ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4F57B2F382DC147ULL,
		0x0FD9D26343D7D43DULL,
		0x6FB114FEE808EC6AULL,
		0x8A0BEF5D607E75FDULL,
		0x1C5EBEEF8D022C58ULL,
		0x4BB7F0935D13A6ABULL,
		0x123F6D34027A5E2DULL,
		0xB069D0608A377125ULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ED0FDA8D12D2E78ULL,
		0x933B8AD22D94C7DEULL,
		0x3ECA2454720A0B98ULL,
		0xFA6FA4D321250F15ULL,
		0x8BFD2C44DC43E3B4ULL,
		0xF56B8F4971A8C972ULL,
		0x4A5691522B1DCE35ULL,
		0x6BED2B2259222C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB0D053EE2FB102ULL,
		0x495DB50B02D1B3FBULL,
		0x5341F64D03AE1556ULL,
		0x5AE04E517599F3D3ULL,
		0xD0F7A16272E3B5A8ULL,
		0x54786EAA76E954A9ULL,
		0x277AF015849EA2CDULL,
		0xD562F8CA817064F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90602DFB3F029F7AULL,
		0xDA663FD92F457425ULL,
		0x6D8BD21971A41ECEULL,
		0xA08FEA8254BCFCC6ULL,
		0x5B0A8D26AEA0561CULL,
		0xA113E1E307419DDBULL,
		0x6D2C6147AF836CF8ULL,
		0xBE8FD3E8D852487DULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5AD45A50E944387ULL,
		0x2416E6491AA873EAULL,
		0x3A89E3E132DF2A5DULL,
		0x7C2ED32DC4FA5FE5ULL,
		0xCF56E27FBF6848FCULL,
		0x0F784EEC598C44C4ULL,
		0xFAE6F19B59EFC6F6ULL,
		0x81BC01B4E0D56752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD96B9E52F4BCAB0DULL,
		0x0ADEDB46B9A334E5ULL,
		0xFACF85BE3FA2AFFEULL,
		0xDC39B64C8D71F61CULL,
		0x940DB60537E3E85DULL,
		0x2A954F9090EE28F6ULL,
		0x3F6F16C3A8DFB249ULL,
		0x59109A75A1BE07CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CC6DBF7FA28E88AULL,
		0x2EC83D0FA30B470FULL,
		0xC046665F0D7D85A3ULL,
		0xA0176561498BA9F9ULL,
		0x5B5B547A888BA0A1ULL,
		0x25ED017CC9626C32ULL,
		0xC589E758F13074BFULL,
		0xD8AC9BC1416B6098ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CBF3F8650DE910EULL,
		0xFFFC278A5EC5F3C6ULL,
		0x5443A10C3E724449ULL,
		0x933C1C998BC3B35AULL,
		0xC6420C79622478AEULL,
		0xB2B8C54F7A63369CULL,
		0x6E203F88FAA928E7ULL,
		0x9C417996D928772EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEED8F735567332ULL,
		0x0876E758664C7AF8ULL,
		0x54A4BB820B6247D2ULL,
		0xE0D2D402DC4A8743ULL,
		0x4E99D38AB6DB623AULL,
		0x0211F50AA6F1FAE2ULL,
		0x0EBDD7AFA4DD6E4FULL,
		0xC3E00FA70D135ECCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD251E7716588E23CULL,
		0xF78AC0D23889893EULL,
		0x00E71A8E3510039BULL,
		0x73EEC89B57893419ULL,
		0x88DBDFF3D4FF1A94ULL,
		0xB0A93045DC92CC7EULL,
		0x609DE8275E7446A8ULL,
		0x5FA17631D43B29E2ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3857B9F908E85DF2ULL,
		0xBD31FA47ECBC5ABDULL,
		0x5BB41DD5DBA1AEF9ULL,
		0xD06D26D5E0B0295FULL,
		0x423BA292E32CECFBULL,
		0xE03988345FA51FC5ULL,
		0xD9B750B6B36C6479ULL,
		0x38D0F46F9446294EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32CCC0A3DAAC468AULL,
		0xBDFFBD1D56E85D2FULL,
		0x2BC94F5CF0B50919ULL,
		0xB00796FCD5FCC385ULL,
		0x44604E2E8DDCBB8AULL,
		0xEE227D9D1714C787ULL,
		0x8F399630D0B50FF5ULL,
		0x360C999E660DBDE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A9B795AD2441B78ULL,
		0x00CE475ABA540792ULL,
		0x707D52892B14A7E0ULL,
		0x606AB029354CEADAULL,
		0x065BECBC6EF05771ULL,
		0x0E1BF5A948B1D842ULL,
		0x568EC68663D96B8CULL,
		0x0EDC6DF1F24B94ACULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34CAF170A2205BDFULL,
		0x1D68E341AB304756ULL,
		0x4F6E8E3C907ED893ULL,
		0x0C7614D927F17957ULL,
		0xE151C89C0EAB9F74ULL,
		0xEDD13DFF2B8668FFULL,
		0x6F678FA9BB3518BDULL,
		0x4388D1673FFD940AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51309F9A517828F6ULL,
		0xC22FAC6C293E2FE9ULL,
		0xB4B413D39C485F30ULL,
		0xF11DEB2CF96C0FA5ULL,
		0x4C057B30ADA2E875ULL,
		0xF090752B2BB75603ULL,
		0x26B5F45F32A14AA4ULL,
		0x16C4D81D97A820C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65FA6EEAF3587329ULL,
		0xDF474F2D820E68BFULL,
		0xFBDA9DEF0C3687A3ULL,
		0xFD6BFFF5DE9D76F2ULL,
		0xAD54B3ACA3097701ULL,
		0x1D4148D400313EFCULL,
		0x49D27BF689945219ULL,
		0x554C097AA855B4CFULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9576ACF8526B1A49ULL,
		0x3832CBD3260EE8B3ULL,
		0x99958AAAF0381EECULL,
		0xE75153126D0955F1ULL,
		0x8D473DA2B6EA7A5DULL,
		0x3D3450C0410E0EC0ULL,
		0x7B413DFCC1DF393EULL,
		0xE4156C126ACE2B74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2ACC47ED83CF7EEULL,
		0x1FD5FC1E96C0F269ULL,
		0xB08B6D05B8B992E7ULL,
		0x8B2B6F21E66C4EE2ULL,
		0xB3615515AF563BEDULL,
		0xC9D7D4ED052E319FULL,
		0x257B547FBE6E3C20ULL,
		0x7B220886DCE7B820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37DA68868A57EDA7ULL,
		0x27E737CDB0CE1ADAULL,
		0x291EE7AF48818C0BULL,
		0x6C7A3C338B651B13ULL,
		0x3E2668B719BC41B0ULL,
		0xF4E3842D44203F5FULL,
		0x5E3A69837FB1051EULL,
		0x9F376494B6299354ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x581CFFBC5CF0ECC7ULL,
		0x122F7B37DE4B8424ULL,
		0xCDD24540D305F5FFULL,
		0x4585DE3794E9EF02ULL,
		0x86D30C15B7AC07FDULL,
		0x86B90A7ABF61FD08ULL,
		0xB532674F7A746DA5ULL,
		0x76801A90C02ABC7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC0A191084E97B30ULL,
		0x347150A53FF2181AULL,
		0xA1B818AA5E18809AULL,
		0x3E4F473F3DCF189CULL,
		0x2B867B416C64952BULL,
		0xDD99A180CBC3DC60ULL,
		0x880CF9E64255C91AULL,
		0xBF94834D11EDA75EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB416E6ACD81997F7ULL,
		0x265E2B92E1B99C3EULL,
		0x6C6A5DEA8D1D7565ULL,
		0x7BCA9908A926F79EULL,
		0xAD557754DBC892D6ULL,
		0x5B20ABFA74A22168ULL,
		0x3D3E9EA93821A4BFULL,
		0xC91499DDD1C71B22ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ECF05219BD0EE9DULL,
		0x75DAF219614789F5ULL,
		0xD2025641F00B07A1ULL,
		0xB12CEBB4AA2052B6ULL,
		0x0C5962AE5B54BE19ULL,
		0x0EE01557EF6F5F74ULL,
		0xE67A403D9B52A70EULL,
		0x4CCA94C61FCC6374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E9DF02F9B0B28D2ULL,
		0x5CCFC7D2C885C33FULL,
		0xCAF6C8C16F04A592ULL,
		0x6B8AE02187D0956EULL,
		0xC4424F13DBBD4945ULL,
		0x5C337FAA1F2B9460ULL,
		0x2639B42DCC2F6044ULL,
		0xC76E1AE40B998AE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5052F50E00DBC64FULL,
		0x291535CBA9C24ACAULL,
		0x18F49E809F0FA233ULL,
		0xDAA60B952DF0C7D8ULL,
		0xC81B2DBD80E9F75CULL,
		0x52D36AFDF044CB14ULL,
		0xC043F410577DC74AULL,
		0x8BA48E221455E997ULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9399A26F32A380A8ULL,
		0x89EEF1235F779B2BULL,
		0xEF9F01E257C56A09ULL,
		0x6A2B42DEA799B059ULL,
		0xE59DD9332E8653F3ULL,
		0x0A1B0E60838EEEF0ULL,
		0xF2B6A13A980CACA7ULL,
		0x2EF8FC345308C0D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A5DF1ECB0FA8E30ULL,
		0x2EABA741103B06E5ULL,
		0x904054FF73BB29AEULL,
		0xB02CA7E06C9C5190ULL,
		0xC0612E9390ADBD50ULL,
		0xA2903546CC470DD0ULL,
		0xE5F85BF3BB5257ADULL,
		0x2AF1E4837416D5C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99C4538382590E98ULL,
		0xA74556624F4C9DCEULL,
		0x7FDF551D247E43A7ULL,
		0xDA07E53ECB05E1C9ULL,
		0x25FCF7A0BE2BEEA3ULL,
		0xA88B3B264FC9E320ULL,
		0x174EFAC9235EFB0AULL,
		0x040918B7271E1516ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x215C728AED7E9A44ULL,
		0x5A5F66ADF7A8B16CULL,
		0x44ED2DC578551CC4ULL,
		0xDC88B88789A65156ULL,
		0x96BEA6FB2DC75336ULL,
		0x66D1725E37B46283ULL,
		0x1CA7593A2C81FD1FULL,
		0xB159279A6852F86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF84A72B194CCCEEAULL,
		0xFD4DFEEC44B622D1ULL,
		0xEAFB212F1F83E037ULL,
		0xFED218C1D6A640C2ULL,
		0x920E880B0B408A75ULL,
		0xF192712E6DE15F7DULL,
		0x318526CBD01DBB83ULL,
		0x10F7CCAA525C5A39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD916003B79B254AEULL,
		0xA7129841B31E93BDULL,
		0xAE160CEA67D6FCF3ULL,
		0x225AA0465F001194ULL,
		0x04B02EF02687D943ULL,
		0x974303705A553DFEULL,
		0x2D227FF1FC9C469CULL,
		0xA1AEEB303A0EA256ULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF714EBAAE8127D93ULL,
		0xE20956541A8717DCULL,
		0x0FEDABA0E4CD9BCFULL,
		0xAC90A225B75630B5ULL,
		0x4B734E8A8EB5A0A9ULL,
		0x3BF6189BFA93E116ULL,
		0xB2C7A3623A8F38B7ULL,
		0x3E92F970CD0E094AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D00D341F39A0E83ULL,
		0x2FF6643EAAFC0B5EULL,
		0xBF6D0D8680186446ULL,
		0xF6B4DA1D33598E11ULL,
		0xD0BE890E5A1458B0ULL,
		0x3A8F2FBB6E85296AULL,
		0xD0A51114C6E39F9CULL,
		0x8106216518384F55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A1438EB1B887310ULL,
		0xCDFF326AB07B1C82ULL,
		0xB080A62664D5FF89ULL,
		0x5A247838840FBEA4ULL,
		0x9BCDC784D4A1F819ULL,
		0x017937209416C87CULL,
		0x6262B276FC6CA72BULL,
		0xBF94D815D536461FULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FCADF2C06EDC105ULL,
		0x2740132F17AEB345ULL,
		0x5E63ED5F161406EAULL,
		0xA29C9B700C985EABULL,
		0x1221A2A96F7631D2ULL,
		0x7A23D1B9844D5DDAULL,
		0xBFA991A8B012FE67ULL,
		0xFAC5431358966CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB515CAB23CBC9F20ULL,
		0x73881ABF2AD67401ULL,
		0x0D9125FC9DD473EBULL,
		0x40F66159D0DF32C3ULL,
		0xD8E61EE2F2AA2BA0ULL,
		0x5DDAB0B56F1A647EULL,
		0xDF7B2B59F3DC99DDULL,
		0x1D08D1A992CCAA4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFADF159E3A515E25ULL,
		0x54C809903D78C744ULL,
		0x53F2C8A38BC07501ULL,
		0xE26AFA29DC476C68ULL,
		0xCAC7BC4B9DDC1A72ULL,
		0x27F9610CEB5739A4ULL,
		0x60D2BAF143CE67BAULL,
		0xE7CD92BACA5AC6B2ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CA57EDF2E8C8BC5ULL,
		0x1BA3E4C0C4311124ULL,
		0xDBD7992012894364ULL,
		0xE259FBADEE0C5639ULL,
		0x192FA1CEDBC6B95EULL,
		0x5AB1617FFC713F8FULL,
		0x530BA4921543F82EULL,
		0x1A3683C98944205CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB38349405EB2112ULL,
		0xE410E00C16C6E6C7ULL,
		0x7573001F671D5BFEULL,
		0x49776FBE030BBB5FULL,
		0x30A3527A5DE7A588ULL,
		0xEEE78DE5A1FB0305ULL,
		0xAC120E38F933197EULL,
		0x9A566FC56225FDFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF79D4A4B2B67AAD7ULL,
		0xFFB304CCD2F7F7E3ULL,
		0xAEA4993F7594189AULL,
		0xAB2E9413ED07ED66ULL,
		0x298CF3B486211CD6ULL,
		0xB456EC9A5D8A3C8AULL,
		0xFF19AAAAEC70E150ULL,
		0x8060EC0CEB61DDA1ULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5CBFA4975A9FADEULL,
		0x9701425579339A96ULL,
		0x51CBA374E5D515D8ULL,
		0x9D53E0C040FBDE44ULL,
		0xF55153497AD60B39ULL,
		0x4881BB4FD88D181AULL,
		0xAD1FAE265C6865BAULL,
		0xA659A86EE7EF3654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D0C47A9B09DC41ULL,
		0x2B8F23D0C376B3ACULL,
		0xC4CEFF29CB56B18FULL,
		0xA1FD3409822E89E2ULL,
		0x0A3CA2AE023B1C7BULL,
		0x80B5EF8AB617994CULL,
		0xEC55D8C26D14768BULL,
		0xB746ED0D689FB6D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x951B3E33EEA0269FULL,
		0xBC8E6185BA45293AULL,
		0x95055C5D2E83A457ULL,
		0x3CAED4C9C2D557A6ULL,
		0xFF6DF1E778ED1742ULL,
		0xC83454C56E9A8156ULL,
		0x414A76E4317C1331ULL,
		0x111F45638F708083ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25A850424452D09EULL,
		0x471FB029C4487941ULL,
		0x47B0B600B8D3346BULL,
		0x7ECE9EE07E77799DULL,
		0x3DA382A04C9DE802ULL,
		0xC5121F8AD724F68FULL,
		0xC9940D723C5D9F6BULL,
		0x4AA94C3788B3F5C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A71854810B02CAULL,
		0x444317B4CCF12B69ULL,
		0x2901F9A9E98D122BULL,
		0xEDCCC00F7A1322F6ULL,
		0x4B73A55030B6A045ULL,
		0x1CFECB7817859044ULL,
		0x13EA73CD617E911DULL,
		0x419D4C1F3430802BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD0F4816C559D254ULL,
		0x035CA79D08B95228ULL,
		0x6EB14FA9515E2640ULL,
		0x93025EEF04645B6BULL,
		0x76D027F07C2B4847ULL,
		0xD9ECD4F2C0A166CBULL,
		0xDA7E7EBF5D230E76ULL,
		0x0B340028BC8375E2ULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD96F85E2A1A1AC7AULL,
		0xDC055B08D8D9D78FULL,
		0x9B152591265F2C73ULL,
		0xC04C7C3A02A77669ULL,
		0x8B9B564DE16998C7ULL,
		0xB706C79787657819ULL,
		0xBACD9DDBE086439EULL,
		0xF78A8C340A24F5CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9FFD02490DDEB9ULL,
		0x4E76597D9D48965CULL,
		0x69FD095E9754A44DULL,
		0xB38E4C5A6A08B4AFULL,
		0xD97A6F76EA180AD9ULL,
		0xD5B1A03F366DCE2AULL,
		0x58CD0033E3F3FCDCULL,
		0x545BC3DD245EC2A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46F078E0E8AC72C3ULL,
		0x92730275459141D3ULL,
		0xF2E82CCFB10B883EULL,
		0x73C2306068AFC2C6ULL,
		0x52E1393B0B71921EULL,
		0x62B767A8B108B633ULL,
		0xE2009DE80375BF42ULL,
		0xA3D14FE92E7A376FULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4F66DE2AF2F1ADAULL,
		0x7E1E6803D9B2D3B2ULL,
		0x426A60639563BA19ULL,
		0x03E3E9522B42958BULL,
		0x3773BA99AFB13004ULL,
		0xCC79745FC198233CULL,
		0x30BA284AE0C0DBB0ULL,
		0x0A5F86F286C1B258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A4D45778E4ABEEULL,
		0xA3638573B7881D63ULL,
		0x465638991A867DC4ULL,
		0xCF97950D81DDCF4FULL,
		0x834D16C80203C000ULL,
		0xFA57D585D30EEF29ULL,
		0xE43592E187499499ULL,
		0x88DB8B6F0090F819ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5752B9B5D7CBB134ULL,
		0xDD7DED706E3ACED1ULL,
		0x043C58FA8FE5C7DDULL,
		0xCC747C5FAA9F5AC4ULL,
		0xB43EAC51ADB2F004ULL,
		0x362EA1DA1296CC15ULL,
		0xD48FBAAB67894F29ULL,
		0x82840D9D86514A41ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E967EE7FCB6550CULL,
		0x730B91EA9ADF6947ULL,
		0xC279809E9767EF75ULL,
		0x77A4ED01ACF77D06ULL,
		0x197DB5DF7EEBC1D4ULL,
		0x1784C1C9FAC1737BULL,
		0x784CE26BD80724C5ULL,
		0x11D668CE1ADB89D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00D30B6E4E4CE10ULL,
		0xA35588E937F54057ULL,
		0x4E8642F3760284C2ULL,
		0x083DC1CFAD9121FDULL,
		0x124C06705AA4FA21ULL,
		0xDCDC1702D6ED465FULL,
		0xADF79EB00D249B6EULL,
		0x0A27B360495DAF13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E9B4E5118529B1CULL,
		0xD05E1903AD2A2910ULL,
		0x8CFFC26DE1656BB7ULL,
		0x7F992CCE01665CFBULL,
		0x0B31B3AF244F3BF5ULL,
		0xCB58D6CB2C2C3524ULL,
		0xD5BB7CDBD523BFABULL,
		0x1BF1DBAE538626C6ULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38F9723EE57969F2ULL,
		0xF5BF7B78DCBA47A4ULL,
		0x0BACE74C897D4AE9ULL,
		0xD4658F64A5D04466ULL,
		0x9E1F7152797F677DULL,
		0x400604276BB3ECF5ULL,
		0x58632E91CCA14D23ULL,
		0x447DB09E57AB91BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B53371D6A4E7E04ULL,
		0x3DA23F5EF5AAEF8AULL,
		0xED99D97BD9C457E1ULL,
		0x49D94460F46C5381ULL,
		0x188514F9855F5025ULL,
		0xADA3C4280E7C9415ULL,
		0x28547487F53F57CBULL,
		0xDE0182A7565AC279ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53AA45238F3717F6ULL,
		0xC81D44262910A82EULL,
		0xE6353E3750B91D08ULL,
		0x9DBCCB0451BC17E7ULL,
		0x869A65ABFC203758ULL,
		0xEDA5C00F65CF78E0ULL,
		0x70375A16399E1AE8ULL,
		0x9A7C323901F153C5ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18620D912AB06D77ULL,
		0xC0AE6340D9093728ULL,
		0xB93C09F6EE75DE4CULL,
		0x1C14D48E4B0AFE4BULL,
		0x391EF6E602370D07ULL,
		0x540C417F59FDDF15ULL,
		0x24131C20AC80E3AEULL,
		0x798342C78D7BC61CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE04785C811C91765ULL,
		0x9F2A48AFE19BBA65ULL,
		0x28593FCE9B399DAEULL,
		0x9DBDA6048085240DULL,
		0x8CE3B62937EB9B24ULL,
		0xBDB2962DE93EBA65ULL,
		0x245EFB0746D68A8DULL,
		0x63312FB3C7AA9E53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF82588593B797A12ULL,
		0x5F842BEF38928D4DULL,
		0x91653638754C43E2ULL,
		0x81A9728ACB8FDA46ULL,
		0xB5FD40CF35DC9623ULL,
		0xE9BED752B0C36570ULL,
		0x004DE727EA566923ULL,
		0x1AB26D744AD1584FULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5034591ECD8AE928ULL,
		0x44D3B11E744A07A5ULL,
		0xF27797140DE9E906ULL,
		0xA70A95E726435A31ULL,
		0x6056C36F81452838ULL,
		0x3ED6F605B0DF6E30ULL,
		0xCB1C17A8923E66B7ULL,
		0x887A782FEF6145B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAA353A774A21DAEULL,
		0x069E50D1FF764DCAULL,
		0xB1F58CA17EFE4990ULL,
		0x862C0D8B3BF49D14ULL,
		0x6999939CD3ADFAA4ULL,
		0xC4C2118AC117462AULL,
		0x50A1A3DB95B5AA5DULL,
		0xD02A1A55B007A78BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A970AB9B928F486ULL,
		0x424DE1CF8B3C4A6FULL,
		0x43821BB57317A096ULL,
		0x2126986C1DB7C725ULL,
		0x09CF50F352E8D29CULL,
		0xFA14E78F71C8281AULL,
		0x9BBDB473078BCCEAULL,
		0x5850627A5F66E23CULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD87AC3A11A4A3141ULL,
		0x916EB05A8AB7D2C9ULL,
		0x9657022F5FE3275FULL,
		0x232C7C4F476B2015ULL,
		0xF9AB4F4CACD704DAULL,
		0x05152BDF241E92C7ULL,
		0xC5C779EC559A5022ULL,
		0x6286A6012CAC4FBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26B411B3AEFE45F5ULL,
		0x65854B4393DF9E59ULL,
		0xE8C88232D5BC0155ULL,
		0x7941FA82B50DF705ULL,
		0x9AA18FD8EA828FFDULL,
		0x7E6CDCDCEF1D3942ULL,
		0x8308CCD5746BB896ULL,
		0x01895A9AFB22A905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFECED212B4B474B4ULL,
		0xF4EBFB1919684C90ULL,
		0x7E9F801D8A5F260AULL,
		0x5A6D86CDF266D710ULL,
		0x630AC09446558B27ULL,
		0x7B79F703CB03AB85ULL,
		0x46CFB53921F1E8B4ULL,
		0x630FFC9BD78EE6B8ULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE35EFC859B266558ULL,
		0xFB570D8BA007779BULL,
		0x204885C396E81CDFULL,
		0xF1060A2A659B0EF4ULL,
		0x863D3E29AD60C11AULL,
		0xE78CB38BD49A3701ULL,
		0xA34EBFD79DF5B9D6ULL,
		0xA64FD8819C36727DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF894DA106771003ULL,
		0xE5EB1DC8A4E5C7E3ULL,
		0x79DB0E48ADDC6D47ULL,
		0xB3F6CB7DEA39C889ULL,
		0xF846C863834DEFFCULL,
		0x995BCF918AF69699ULL,
		0x190E2354B355D250ULL,
		0xEF3A3AF77720143FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CD7B1249D51755BULL,
		0x1EBC104304E2B078ULL,
		0x59938B8B3B347198ULL,
		0x42F0C1578FA2C67DULL,
		0x7E7BF64A2E2D2EE6ULL,
		0x7ED77C1A5E6CA198ULL,
		0xBA409C832EA06B86ULL,
		0x4975E276EB166642ULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A15EC3D0595756DULL,
		0xB878C8952BD3D8C7ULL,
		0x2700ABE374738E94ULL,
		0x5E8AD9DD8F054132ULL,
		0xB9B8C09403051223ULL,
		0xF2DDCEB3D8E00C91ULL,
		0x4D393F2D7F2DDAB8ULL,
		0x7F0A6560EBDDC7B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD3FFEEA6B25500CULL,
		0x57C72A29898FF0CBULL,
		0xC39765B8CAD0D139ULL,
		0x0704814B0AE1D5F1ULL,
		0x4ACBC90565F6F815ULL,
		0x5895519DC688C186ULL,
		0xE4FF726F91C5111BULL,
		0xDB506082F982F4F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE72A12D76EB02561ULL,
		0xEFBFE2BCA25C280CULL,
		0xE497CE5BBEA35FADULL,
		0x598E589685E494C3ULL,
		0xF373099166F3EA36ULL,
		0xAA489F2E1E68CD17ULL,
		0xA9C64D42EEE8CBA3ULL,
		0xA45A05E2125F3343ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x176153FF37FA9679ULL,
		0xF9C060C04D90B8C7ULL,
		0x42143A0A23B34F51ULL,
		0x488C09080F7AC8CAULL,
		0xB0C7EDFDF8751645ULL,
		0xB2A250C0FFAF8A44ULL,
		0xEAD3C9612C693AE3ULL,
		0x78D49F581772136BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3268BF61107CF5F5ULL,
		0x36170614E2126310ULL,
		0x3C983C5C531B0A9DULL,
		0xE919047E7F01EE56ULL,
		0x2363D88902CBC259ULL,
		0x3B46C3F48B035ACFULL,
		0xBCF4C0B3AE7224A0ULL,
		0x4C2AB39D650C2374ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2509EC9E2786638CULL,
		0xCFD766D4AF82DBD7ULL,
		0x7E8C065670A845CCULL,
		0xA1950D76707B269CULL,
		0x93A43574FABED41CULL,
		0x89E4933474ACD08BULL,
		0x562709D2821B1E43ULL,
		0x34FE2CC5727E301FULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85BE76CE86212226ULL,
		0x93B06F2DF49F29FBULL,
		0xCB800596AAEA4AA0ULL,
		0x72CDA550E24F55F8ULL,
		0x4E6586A8242F010AULL,
		0xFC3BD678EA0257B1ULL,
		0x8CE9A3A655B75021ULL,
		0xD08F6B1576561314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x905B141BE1ACEDB6ULL,
		0x37B9C46664CD6A6CULL,
		0xF9E8058639B8C0F4ULL,
		0x34CAA960DF8860B6ULL,
		0x77D0AE0605523DD9ULL,
		0xECE6EA9E3BBAB812ULL,
		0x5B110FBCD7D622ECULL,
		0xF719FAC7F2E79C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15E562D5678DCF90ULL,
		0xA409AB4B90524397ULL,
		0x3268001093528A54ULL,
		0x46070C303DC7354EULL,
		0x39B528AE217D3CD3ULL,
		0x10DD3CE6D1B8EFA3ULL,
		0xD7F8AC1A826172CDULL,
		0x279691D284B18F75ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x215AADCAD69D5EBCULL,
		0xE29151F136075A3AULL,
		0x979823F26218EF24ULL,
		0x0C21AD40B4BD265BULL,
		0x4FFAF9763BC8ACD2ULL,
		0x1446A59CD21EC0B6ULL,
		0xE83A4BB66994033FULL,
		0xD1DD75C454DC3F1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C416380A31D4163ULL,
		0x28B11963191281DDULL,
		0x504B72C7CDF6AF84ULL,
		0x491F1908A9E97B20ULL,
		0x555C7FA55551FC50ULL,
		0x159EA7D4AD336DD9ULL,
		0x8336462DC42CD00BULL,
		0x3442C069314A8BE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD1BCE4A75801FDFULL,
		0xCA2048922F15DBE7ULL,
		0xC7D35135AFEE40A0ULL,
		0x453EB4481D545D7BULL,
		0x1AA686D36E995082ULL,
		0x01D802487F2DAD6FULL,
		0x6B0C0D9BADB8D334ULL,
		0xE59FB5AD6596B4F6ULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F9D15519E124850ULL,
		0xFA768F3E28591810ULL,
		0x7EFE7BC5F2F01191ULL,
		0x0B553FFC8A533A56ULL,
		0xE4991E9B21036941ULL,
		0x61041D06C2F0114AULL,
		0xB6208ACDB297B487ULL,
		0xF0526D651C2953ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x729A4C7B91D0C21FULL,
		0xD2F1228FD8AE84FFULL,
		0x666A3FDB61FFC132ULL,
		0xCFFC8830128339B5ULL,
		0xAAD5FA95160E4075ULL,
		0x0BB8A0F3DADAA545ULL,
		0xC069DCF7DE92601CULL,
		0x2CBE01D1EEFE0040ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D07592A0FC28A4FULL,
		0x2887ADB1F0F79CEFULL,
		0x1894441E930FD0A3ULL,
		0xC4A9B7CC98D003E3ULL,
		0x4E4CE40E370D2934ULL,
		0x6ABCBDF5182AB40FULL,
		0x7649563A6C05D49BULL,
		0xDCEC6CB4F2D753ECULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61F20A43B1E31EF6ULL,
		0xC717CCB6A92A1FE9ULL,
		0xC4193CB0FFBC3EAEULL,
		0x3AC38E6A4AAD4ED6ULL,
		0x67EAA715700DB43CULL,
		0x2967B0030B1E0032ULL,
		0x16D6CB96EAF1AED5ULL,
		0x9BD957FF269D2CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC42B125F06566126ULL,
		0x276727F2B9EAF10EULL,
		0x535E2F6FBF2A4162ULL,
		0x33037050C055B9ECULL,
		0xE31359FC4A32BE26ULL,
		0x5930A08706DCFD59ULL,
		0x1AD049CC843403B4ULL,
		0x0B1B86E6766CFF73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5D9181CB7B57FD0ULL,
		0xE070EB4410C0EEE7ULL,
		0x974713DF40967FCCULL,
		0x09C0FE3A8AF8F73AULL,
		0x84F9FEE93A3F0A1AULL,
		0x705710840DC2FD6BULL,
		0x0C06825A6EC5AD61ULL,
		0x90C2D11950F1D3D8ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x155B232CAADFE831ULL,
		0xF232D93673E53E57ULL,
		0xC10BF8E4F18D31B9ULL,
		0x944B5165F0A3618CULL,
		0x17629108B2D5D720ULL,
		0xB375605D4F8A86E5ULL,
		0xD248ED2BC58D9310ULL,
		0x4F01EB60B92845A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857F5498FA322E36ULL,
		0xF20CC163122C7772ULL,
		0x07C4B99BC7967202ULL,
		0x8FAFE559929124D6ULL,
		0x30B67D7315B5AEF8ULL,
		0xD58764444D5B332CULL,
		0x25EB801A0BE367A3ULL,
		0xB296271B7C006DE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902477B450EDC607ULL,
		0x003E185561C94925ULL,
		0xC6CF417F361B43BBULL,
		0x1BE4B43C6232455AULL,
		0x27D4EC7BA76079D8ULL,
		0x66F2041902D1B5C9ULL,
		0xF7A36D31CE6EF4B3ULL,
		0xFD97CC7BC528284DULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DE99B743739A7D0ULL,
		0xDF8971CA083B6416ULL,
		0xC2A1E77115BE4BB9ULL,
		0xCD7EAA8D50B93834ULL,
		0x6A2FF1DD21E59C8AULL,
		0x7BD7D2052B411023ULL,
		0xA8B240E84360D4B5ULL,
		0x2A1E022BD5DF8EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444C4BCB888488E4ULL,
		0xF4E1DAC366C573ACULL,
		0x556F7D3C01D52D73ULL,
		0xDE2F358835C43E82ULL,
		0xD9FD4F127A2865CEULL,
		0x5F887232CBBB39BCULL,
		0x11E3093BAEEAEAE5ULL,
		0xF575B4B9A3026C60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79A5D0BFBFBD2F34ULL,
		0x2B68AB096EFE17BAULL,
		0x97CE9A4D146B66CAULL,
		0x13519F05657D06B6ULL,
		0xB3D2BECF5BCDF944ULL,
		0x245FA037E0FA299FULL,
		0xB95149D3ED8A3E50ULL,
		0xDF6BB69276DDE281ULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CD11EB5DB28D3A1ULL,
		0x69758E15D5168034ULL,
		0xEA4A2F4B74022922ULL,
		0xBF2E237346BDFBE4ULL,
		0x9051BCDCA9810042ULL,
		0x476CF6DFFA3EF3CCULL,
		0xBDC7C1E2DA9178EBULL,
		0x324664DB33760300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A62903B2173E9BBULL,
		0x09C6F4B12ABD72D6ULL,
		0xFE723E5539043F10ULL,
		0x193B1602A05FAEDBULL,
		0xB9C28E268B868319ULL,
		0xEE955A71A43DF81EULL,
		0x5BB84EA74C420F69ULL,
		0x839072A51FFCD978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36B38E8EFA5B3A1AULL,
		0x60B37AA4FFABF2E2ULL,
		0x1438111E4D061632ULL,
		0xA6153571E6E2553FULL,
		0x299332FA2207835BULL,
		0xA9F9ACAE5E030BD2ULL,
		0xE67F8F4596D37782ULL,
		0xB1D6167E2C8ADA78ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7505DE04582CEC28ULL,
		0xDD3C6CF4F28765FBULL,
		0xB102755B7A426219ULL,
		0xF90A4E2983F18D0CULL,
		0xBAFB7FE1709845B0ULL,
		0x347ADA06AB848865ULL,
		0x6A25D802B5E1E7D7ULL,
		0xFFF93121DB86AF3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8C06C6B275F015ULL,
		0xD8657CD27132B5F0ULL,
		0x4A469A73BAC851F5ULL,
		0x2662ACC48F9D6CA5ULL,
		0x7CD0F33C73D0600FULL,
		0x3146218CB2F9259BULL,
		0x6DAE6380B670F1D7ULL,
		0xED9F04B610DE696CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA89D8C2EA591C3DULL,
		0x0559102683B5D00BULL,
		0xFB44EF28C08A33ECULL,
		0xDF68E2ED0C6CE1A9ULL,
		0xC62B8CDD034825BFULL,
		0x053CFB8A197DADFEULL,
		0x078BBB8203911600ULL,
		0x12663597CB58C653ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAE0B7980297B533ULL,
		0x734DB7AC88081D5AULL,
		0x56A26EE706C3C7A1ULL,
		0xC43D80DEAE28D164ULL,
		0x7936DF1DA5218245ULL,
		0x2C29EE4DD0B7E13FULL,
		0xB0CF327A741A86ECULL,
		0xFE7526829560D0BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC129DFC2726BDCFFULL,
		0x1D3C034DBC141288ULL,
		0x5126F599B61796AAULL,
		0x55931D4F6E223CAEULL,
		0xFF025EB97608CDB3ULL,
		0x2DC5E202FF651271ULL,
		0x41F3E45B59C906CBULL,
		0xA186AD6C4C6ACEEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BC9685A70FC69CCULL,
		0x6E71B4E1341C0FD2ULL,
		0x07849B7EB0D4510BULL,
		0x91AE9D91C00AEDCAULL,
		0x863481A4D3294FF6ULL,
		0x01EC0C4F2FD2F34EULL,
		0xF13CD6212DD38027ULL,
		0x5FF38BEED90A1E55ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70B2F7B408FAC6A0ULL,
		0x13413A6994DA421DULL,
		0x68015FF62E05B883ULL,
		0x179EB3B769AF8B76ULL,
		0x3490967470DEC28BULL,
		0xAB5E5FF73556B2D6ULL,
		0xFB933041C1A1418EULL,
		0x642B47A126436BA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5C60002C88CD5B3ULL,
		0xE34E354A075AC6E3ULL,
		0xA4C2C5CD54159172ULL,
		0x22D9D1BCC942FF7EULL,
		0x118C30DFAC5FBFC3ULL,
		0xB32DCC6BF8173028ULL,
		0x52375956BB04AA1CULL,
		0x35528011383F5430ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8574F7B6C0761313ULL,
		0xF00F0F23938084FEULL,
		0xCCC39A3B7A1029F1ULL,
		0x3547620BA0ED7408ULL,
		0x251CA6ABDC817D48ULL,
		0x1873939CCD4182FEULL,
		0xA9A469177AA5EB92ULL,
		0x5179C7B01E7C3F92ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3ACDF5AFFA2F27EULL,
		0x185D1055AFB8E929ULL,
		0x541D5EF22614FA6AULL,
		0x7372E53BD464F476ULL,
		0x1C1023A84A3E7BADULL,
		0x3DDB981002F0EB46ULL,
		0x5160CABD641BF9A0ULL,
		0x2C65B6F1A005BCB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1316F3EF2152FFD8ULL,
		0xC9C2386A77E0E37AULL,
		0xAA2A1BDA4E35C1ADULL,
		0x10C89F6EE6CB5E85ULL,
		0x8BDDF6233E569ECFULL,
		0x0652BCFEBF3F80BFULL,
		0xECA476337FC775FBULL,
		0x279CF13C41AE5DD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0BA2CB5DEF00DA6ULL,
		0xD19F283FD8580A53ULL,
		0xFE37452868213BC7ULL,
		0x63BA7A5532AFAAF3ULL,
		0x97CDD58B7468E562ULL,
		0x3B8924EEBDCF6BF9ULL,
		0xBDC4BC8E1BDC8C5BULL,
		0x0BF947CDE1ABE165ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB188D68A2BD8C718ULL,
		0x171F83B3F460272DULL,
		0x9C35BE3FCBF34100ULL,
		0x0A931A77F9FEE5F8ULL,
		0xF6E675689AF151D7ULL,
		0xC40160F0C3DEF508ULL,
		0xD5E5F120966B1DBCULL,
		0x255CB674F9310769ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF07E594D14DBBEAEULL,
		0x9C9D2E8268B9B953ULL,
		0x4293E48082FC5831ULL,
		0xF21889D6B749450FULL,
		0x938BD2B5666A1830ULL,
		0xDC90F19A96558933ULL,
		0x475B5B94CDA6200BULL,
		0x95B953E1849A4A9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41F68FC73F0379B6ULL,
		0x8B82AD319CD99E7EULL,
		0xDEA65ABF490F1931ULL,
		0xF88B93A14EB7A0F7ULL,
		0x656DA7DDFC9B49E7ULL,
		0x1891916A558B7C3BULL,
		0x92BEAAB45BCD3DB7ULL,
		0xB0E5E5957DAB4DF7ULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA074379B155FB66ULL,
		0xDD45542701860388ULL,
		0xF64A0FCF637EF0F8ULL,
		0x31E614EB4E001101ULL,
		0x48EEFED3BC78343FULL,
		0xA304D9E17C0DBB8BULL,
		0x3FC49AA064C2AC89ULL,
		0xA6FD6C844E445FD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F5442779DCCAB3ULL,
		0xACC2CD673F9354CAULL,
		0xDF732FC8ECC35AFBULL,
		0xD7B8ECF9F77BEF12ULL,
		0x632E213D51D5C238ULL,
		0x823AC40F7BED1F6BULL,
		0xA88BF6DB7B6EFBB2ULL,
		0x38AF2DB6EC211B11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62F2075EC88931D5ULL,
		0x718799403E155742ULL,
		0x293920078FBDAA03ULL,
		0xE65EF812B97BFE13ULL,
		0x2BC0DFEEEDADF607ULL,
		0x213E1DEE07E0A4E0ULL,
		0x974F6C7B1FAC573BULL,
		0x9E524132A26544C4ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADC8EBEBC0E8FBDDULL,
		0x88EE9398E161A427ULL,
		0xCCD140C159AF1AEDULL,
		0x6DE61E2BF15BD3DCULL,
		0x65DBD87840AB6DD6ULL,
		0x9DBD990F66D267E5ULL,
		0x50553E28E68A6FEAULL,
		0xACB5024F3A828FBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76BACA46555CBE40ULL,
		0xDFCAA5F41246E8E7ULL,
		0x3F3DD4FBDCD8E609ULL,
		0x8DE5F46D2194D7A0ULL,
		0xE1D3028D92F0842CULL,
		0x598DF25C2B202DBAULL,
		0x7AE7B8C04B427114ULL,
		0xB6F3DD8EE9302942ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB7221AD95B4459DULL,
		0x5724366CF3274CC0ULL,
		0xF3EC943A8577FCE4ULL,
		0xE003EA46D0CF047CULL,
		0x8408DAF5D25BE9FAULL,
		0xC4306B534DF24A5FULL,
		0x2AB286E8ADC81EFEULL,
		0x1A46DFC1D3B2A6FCULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5356FEDA0E1DD162ULL,
		0x0805A8DBF98E22D0ULL,
		0xF4C4EF7D861D0C2EULL,
		0x6A6298FE010536C6ULL,
		0x738EF98687C7D622ULL,
		0x205D501D04695D91ULL,
		0xC8485E43DDFFCE61ULL,
		0xF5415F131C28E324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE04CA156F079BCDCULL,
		0x72BE2819B8E72D3AULL,
		0xEC3CA66AFF3D876EULL,
		0x1FE7118380531D8DULL,
		0xD03BFB8F91939DBBULL,
		0x2C5B5AF1B9104E89ULL,
		0xFF95657E439042D2ULL,
		0x264F21520E6AFA56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB31A5F8CFE646DBEULL,
		0x7ABB80C241690FEAULL,
		0x18F8491779208B40ULL,
		0x7585897D81562B4BULL,
		0xA3B5020916544B99ULL,
		0x0C060AECBD791318ULL,
		0x37DD3B3D9E6F8CB3ULL,
		0xD30E7E4112421972ULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2A05938C7A14F0DULL,
		0x3F21B889170D4F29ULL,
		0xC765CA7C340F754DULL,
		0xB4763DEB80CE4805ULL,
		0xA4FD846F5830D53EULL,
		0xB54AD88E6BA097E4ULL,
		0x39667E0EA72A6FA3ULL,
		0x254408DB84E3E690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x018A14B3DBB0CAF3ULL,
		0x2BEC8E44E37A4B81ULL,
		0x80DF01D426FE196AULL,
		0x439F65FF7B14D4CCULL,
		0x80B73AEB532A0409ULL,
		0xA6548A06086FBBFDULL,
		0x56C1EA9ACE56F3E2ULL,
		0xC9640545C414AF26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA32A4D8B1C1185FEULL,
		0x14CD36CDF47704A8ULL,
		0x47BACBA812F16C27ULL,
		0xF7E95814FBDA9CC9ULL,
		0x244ABE840B1AD137ULL,
		0x131E528863CF2C19ULL,
		0x6FA79494697C9C41ULL,
		0xEC200D9E40F749B6ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30C1F05AED7913BFULL,
		0xEA60E89BC21C141BULL,
		0xE8B874EF59F4A1E5ULL,
		0xC06679BCB9A5D639ULL,
		0x0908135D3AE016BFULL,
		0xA57A442447C1B7C3ULL,
		0x7346B9F4EC7BF385ULL,
		0xAB8E3E8DA7BCCDB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13AEAD94B9578310ULL,
		0x0A7455B657DA523BULL,
		0xB9F4D3484CE43CE2ULL,
		0x47D7F0232182F345ULL,
		0x194936E615A70FC7ULL,
		0x23EF5BBA66A248DFULL,
		0x8D905BF1CB15D9B2ULL,
		0x18CA6FA0316985BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x236F5DCE542E90AFULL,
		0xE014BD2D95C64620ULL,
		0x514CA7A715109D07ULL,
		0x87B1899F9827257CULL,
		0x104125BB2F471978ULL,
		0x86951F9E2163FF1CULL,
		0xFED6E205276E2A37ULL,
		0xB344512D96D54809ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x039C4C7C8F2430BAULL,
		0x94C712F60D5330C8ULL,
		0x3C5AC05B701BBB61ULL,
		0x384EA6E2B82E2B89ULL,
		0x72215BBCD155CD50ULL,
		0xC98FA5434C044FC5ULL,
		0xBE98482E07DD8759ULL,
		0xF8C16492D74D1B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3086DAD916423E0ULL,
		0xFCF3617455960E41ULL,
		0xB51E7E7C347156AEULL,
		0x2C50BD8CFC686FFFULL,
		0x8299528570B86683ULL,
		0x8033FA669E089195ULL,
		0x6AAA1AF9681B6023ULL,
		0xB8F9255F3235A436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF09421D11E40135AULL,
		0x6834738258C53E89ULL,
		0x8944BE27446AEDCFULL,
		0x141E1B6E44464476ULL,
		0xF0B80939A1EDABD3ULL,
		0x49BC5F25D20CDE50ULL,
		0xD43252D76FC6E77AULL,
		0x403841CDE578BF16ULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D7E56FBB3A2C860ULL,
		0xCD361B6C575ED3A9ULL,
		0xDE38B65F5651E5DBULL,
		0xE52FB74A7E522C6CULL,
		0xC4839BB54C872A08ULL,
		0x9CC447263C6A0D5CULL,
		0x7CD99B006807A378ULL,
		0x2C553F309F6B9DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E24F6F41A14400FULL,
		0x20B75D2B74057433ULL,
		0xCEB3B05B7280B83CULL,
		0xA9C0D2D29B814A10ULL,
		0xF25FC75D22716D5EULL,
		0xEFED2BA4C54C777EULL,
		0x21967711E8E8B58EULL,
		0xB7D83EE15AC3E9F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235AA00FA9B6886FULL,
		0xED814647235BA79AULL,
		0x108B060424D15DE7ULL,
		0x4CEF6598E5D3667CULL,
		0x36DC5CE86EF64756ULL,
		0x73296C82F9267A22ULL,
		0x5D4FEC1180EF16F6ULL,
		0x9B8D01D1C5A87430ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x503C377D01BC9A59ULL,
		0x1606695F068B63ECULL,
		0xE8DC71DC950F0986ULL,
		0xC554F58E9F5802F5ULL,
		0xD14AAB14EF5FD5E2ULL,
		0xDBCE674CB471EF15ULL,
		0x82D4B4E695400AB6ULL,
		0xEE34B32AD9D492DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x502932691AABF06BULL,
		0xDFEA02FAFC88DAF0ULL,
		0x11E1446A4B7822FFULL,
		0x784EDB9833EE6E9DULL,
		0x3BFC86EB8B7D9C13ULL,
		0x839F050C60CDBD56ULL,
		0x846C278BA047F4A9ULL,
		0x21ADD2ACA435FADEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001505141B176A32ULL,
		0xC9EC6BA5FA03B91CULL,
		0xF93D35B6DE772B79ULL,
		0xBD1A2E16ACB66C68ULL,
		0xEAB62DFF642249F1ULL,
		0x58516240D4BC5243ULL,
		0x06B8936D3507FE1FULL,
		0xCF9961867DE16800ULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3802E276BD374AF2ULL,
		0x5C729F3685798607ULL,
		0x74B0FFF9CB9447CBULL,
		0x91AD37EB78F83C7DULL,
		0x078C5D5E156D53D7ULL,
		0x9FDC35C794DBD43EULL,
		0x19359C7058C2D2CBULL,
		0x30828B256E8EF34AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x877547DEA96537AAULL,
		0xF48F502CAEF2C334ULL,
		0x1888E7A7B97BFFBCULL,
		0xA3837586E767B9B2ULL,
		0x2FA8573EF8D5650CULL,
		0x75E3308C71D84F2DULL,
		0x184C3C75C2FD8BD3ULL,
		0x72EFA2ADB880F34FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF77A5A814527D58ULL,
		0xA8FDCF1A2B8B4533ULL,
		0x6C38185E72EFB877ULL,
		0x322E426D9F9F85CFULL,
		0x28240A60EDB836DBULL,
		0xEA3F054BE5039B13ULL,
		0x0179A0059A3F5918ULL,
		0x426D2988D60E0005ULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD235200FA6E30989ULL,
		0x67609901F76DE0C7ULL,
		0x7CB12AFB11519D38ULL,
		0x058E994807595F6BULL,
		0xD529A5C7729B125AULL,
		0xDEE9F0E9FB69E125ULL,
		0xC197B6BA4F222894ULL,
		0xB55196A0A84DBDACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22DAB1526C6406DAULL,
		0x898D083E5F2DB0D0ULL,
		0x48AB7881A3704A6DULL,
		0xEDAB8642B0913B0FULL,
		0x855671B7E5557AAEULL,
		0x36A5A5AEF8A38E78ULL,
		0x4BFA24A9D5850D4BULL,
		0xC8182BC5BAF62BA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0EF915DCA870F53ULL,
		0xEEED913FA8405017ULL,
		0x341A527AB221D755ULL,
		0xE8251F0AB7C86464ULL,
		0x507FD47097CE68F4ULL,
		0xE84C554703CA6F5DULL,
		0x8A6D92139AA725DFULL,
		0x7D49BD6512BB960EULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF377322096565ECULL,
		0x24623F525D6B9842ULL,
		0x73DBADD6030D5233ULL,
		0xEE7AC9E27D9CA401ULL,
		0x7BF8B6B8E9A8F496ULL,
		0x6E4A4A350600B071ULL,
		0xBD38E27D90D26652ULL,
		0xB02AD2A4B8EAE319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA96BF1C1E4A531AULL,
		0xB1E975CCB429AEF9ULL,
		0x5F23F7E950F9EBB4ULL,
		0xD187DD6B7D596F04ULL,
		0xE13EEE7CB5E14A2CULL,
		0x3B62EC6F86C29D05ULL,
		0xF128562AF3A9BCB4ULL,
		0x6E16322246B86AF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65A1CC3E172F36F6ULL,
		0x958B4A9EE94236BBULL,
		0x2CF85A3F53F4B987ULL,
		0x3FFD148900C5CB05ULL,
		0x9AC658C45C49BEBAULL,
		0x5528A65A80C22D74ULL,
		0x4C10B457637BDAE6ULL,
		0xDE3CE086FE5289E0ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3556A1CCAADEE43EULL,
		0x7E462824BF927264ULL,
		0xCB388EEECE4F6B6CULL,
		0xA237E1C03E4747DAULL,
		0xD71F5F29E0A58A74ULL,
		0x24D60C2E3BBE0CEFULL,
		0xA8FFC5782C7E61BCULL,
		0x6AD512ED2457AE7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD037688694B8DAFFULL,
		0x7CEF4013C1CCEF09ULL,
		0xCE20B39736E86916ULL,
		0x2D919C35C49CE1F7ULL,
		0xDC2932253AD18DE9ULL,
		0xCA8200BEB0D89EE9ULL,
		0xE1DBD17980733034ULL,
		0x1F6F1D388D6DA44AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE561C94A3E663EC1ULL,
		0x02A968377E5E9D6DULL,
		0x05183D79F8A7027AULL,
		0x8FA67DF5FADBA62DULL,
		0x0B366D0CDA74079DULL,
		0xEE540C908B669206ULL,
		0x49241401AC0D5188ULL,
		0x75BA0FD5A93A0A35ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC43DB4C844967EDULL,
		0x431E7B8747C67E93ULL,
		0x8C578C30D5143D6BULL,
		0x3A51EC30AE4B06C5ULL,
		0xB3D0708214DCA755ULL,
		0x776822B2D99B8A0CULL,
		0x4CB29AD3DD76ECD9ULL,
		0xAAB9A9C66533E633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCACCAB4C0B927BA2ULL,
		0x135C1185C61DC031ULL,
		0x0B135E24BF44C112ULL,
		0x51584C14CE0D80EBULL,
		0x22A6C9F58E6105C1ULL,
		0x9A21075373AAA543ULL,
		0x20AFD33E976B539BULL,
		0x06CDEAFD008FF71FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x168F70008FDB1C4FULL,
		0x50426A0281DBBEA2ULL,
		0x8744D2146A50FC79ULL,
		0x6B09A0246046862EULL,
		0x9176B9779ABDA294ULL,
		0xED4925E1AA312F4FULL,
		0x6C1D49ED4A1DBF42ULL,
		0xAC74433B65BC112CULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4CFD08FED3DF739ULL,
		0x8B03114BC9424345ULL,
		0x9447731FE99D3B79ULL,
		0xA4C960965F664B70ULL,
		0xC8D605ADEB5AABB8ULL,
		0xB21700C3545008B4ULL,
		0x15DCD8280B378B70ULL,
		0x8E6C45DEF2F23410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CCB4291BF9B6D50ULL,
		0x28D55E2E7850255CULL,
		0x84318DDB3A3A7416ULL,
		0x9395C8A1AC9E547DULL,
		0x1C7C7D8E721EB65DULL,
		0x9372D7F9DBD0299DULL,
		0xB3583855B26A24D9ULL,
		0x3417FECBF31C083DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD804921E52A69A69ULL,
		0xA3D64F65B1126619ULL,
		0x1076FEC4D3A74F6FULL,
		0x375CA837F3F81F0DULL,
		0xD4AA782399441DE5ULL,
		0x2165D73A8F802129ULL,
		0xA684E07DB95DAFA9ULL,
		0xBA7BBB1501EE3C2DULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E9B58929B65163CULL,
		0x82B5033AE0B3605BULL,
		0xD83DA627FC3A9991ULL,
		0x5ECFC2C31712F03CULL,
		0x00F57C9F5C4FCC1AULL,
		0x697F135F6BACCE93ULL,
		0x6BDCB67D24948A07ULL,
		0xE73C43F8FE91A232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63DE9138FBE8EF02ULL,
		0xFD30F7895B4B2A21ULL,
		0x26F993DDB86E4035ULL,
		0x90535D7ECA30D230ULL,
		0xC1A2F705A351B5A9ULL,
		0x43D642AEBF50109AULL,
		0xF4D9A13C8AB64B3CULL,
		0x50E0D38D700CAB47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD45C9AA608DF93EULL,
		0x7F85F4B3BBF84A7AULL,
		0xFEC435FA4454D9A4ULL,
		0xCE9C9FBDDD22220CULL,
		0xC1578B9AFF1E79B3ULL,
		0x2AA951F1D4FCDE09ULL,
		0x9F051741AE22C13BULL,
		0xB7DC90758E9D0975ULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE033D2013BB977ACULL,
		0xBF8FD17614ED6A59ULL,
		0x427A95AFAD646E97ULL,
		0xE00A6F9182797A53ULL,
		0xEE08215A86EAB56BULL,
		0xBAA0F3886AA14A86ULL,
		0x47E577D50C3EAE4EULL,
		0x9EC38949652A159BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x721B6A8A796782F4ULL,
		0x6CA8C19180CCDA00ULL,
		0xFFAD93945EEF3DDFULL,
		0x47D874D2E195D9C2ULL,
		0xBAC000D2DBAFE3C6ULL,
		0x7C0A714E7D611414ULL,
		0x31A7A84A90CA12CBULL,
		0x77697FC4C11121B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9228B88B42DEF558ULL,
		0xD32710E79421B059ULL,
		0xBDD7063BF38B5348ULL,
		0xA7D21B4363ECA391ULL,
		0x54C821885D4556ADULL,
		0xC6AA82C617C05E92ULL,
		0x7642DF9F9CF4BC85ULL,
		0xE9AAF68DA43B342DULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63364F6D96DA8814ULL,
		0x10139062FB398259ULL,
		0xEABDBDA0E3B5FDCEULL,
		0x04EE0946CB7B1ED2ULL,
		0xE9464F718C238F6AULL,
		0xE5CC66DACD9DF67CULL,
		0x9E4C3EDF39394D10ULL,
		0xDA9A4A35900C15DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE0EE12534083C3ULL,
		0xD406B1C3B2DF045FULL,
		0xF7D8E26A842892DCULL,
		0xB00FD9A505E6640CULL,
		0xC0F03816C552971EULL,
		0x9B73711DE90B20B3ULL,
		0x5DC1CFF011AB0FD3ULL,
		0xE250C23FFCD5E5EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8D6A17FC59A0BD7ULL,
		0xC41521A149E68606ULL,
		0x1D655FCA679D6F12ULL,
		0xB4E1D0E3CE9D7ADEULL,
		0x29B6776749711874ULL,
		0x7EBF17C72496D6CFULL,
		0xC38DF12F289242C3ULL,
		0x38CA880A6CD9F031ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBF63D38BD58AE31ULL,
		0xD48578265C114C4BULL,
		0x9B3186C34DC138A1ULL,
		0x9ABF8B35D174AE12ULL,
		0x820C35B399B7755AULL,
		0x2E2F92598473DE79ULL,
		0x4FD822D8038A8FC0ULL,
		0xC8CC731E37CFBEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE16F85DB85FADBD5ULL,
		0x29197EF99BD396B2ULL,
		0x7472879894309D46ULL,
		0xF7AB6B38398372E5ULL,
		0x76F8B1D8F085321FULL,
		0x75B276A28F1C8DB7ULL,
		0x7F0291E7949D8526ULL,
		0x1C819DB876DD8CBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A99B8E338A275E4ULL,
		0xFD9C06DFC7C2DAF9ULL,
		0xEF43015BD9F1A5E7ULL,
		0x6D14E00DE8F7DCF7ULL,
		0xF4F4846B69324745ULL,
		0x5B9DE4FB0B6F53CEULL,
		0x30DAB33F97170AE6ULL,
		0xD44DEEA641123242ULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC9DC6F840534961ULL,
		0x58F439A4D8311E26ULL,
		0xE632BA5702CFE082ULL,
		0x131F955C880D0D18ULL,
		0x3DE919C051DB773CULL,
		0xD294337D55F4DA05ULL,
		0x86409C45A884F78BULL,
		0x3F4EAF4E4ED9AB49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E75F80B23986BDULL,
		0x02E43B966EFFCDDDULL,
		0xC9E8C10346DC186CULL,
		0x5AD0B16D9ADF347FULL,
		0x253133EAABED9ACCULL,
		0xEE2F2D459F22B128ULL,
		0x25534E5938F7DD7EULL,
		0x9A1F5A2A98C1F636ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB7A9978F26ACFDCULL,
		0x5A100232B6CED3FBULL,
		0x2FDA7B544413F8EEULL,
		0x49CF243112D23967ULL,
		0x18D82A2AFA36EDF0ULL,
		0x3CBB1E38CAD66B2DULL,
		0xA313D21C90732AF5ULL,
		0xA551F564D6185D7FULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA493D78242A74AC6ULL,
		0x26C387C15B9514DDULL,
		0x4855DC59A5BB3620ULL,
		0x83D1408F5C3672E5ULL,
		0x91A523A46DE0AFFFULL,
		0xDBC7C5A2AFCB52C0ULL,
		0x7170F9EADBAFDF3CULL,
		0x66B0457174CD98DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B50801F38174F06ULL,
		0x0851F3C8DFD18DEEULL,
		0x7535EDFB267CBC0EULL,
		0x68FD446531C6E4A3ULL,
		0x9484B144C071F7C1ULL,
		0x6913FFC8B9EA46A8ULL,
		0x9C9BA9AD4470EEA8ULL,
		0xB2840182AB13C542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FC3579D7AB005C0ULL,
		0x2E92740984449933ULL,
		0x3D6031A283C78A2EULL,
		0xEB2C04EA6DF09646ULL,
		0x052192E0AD91583EULL,
		0xB2D43A6A16211468ULL,
		0xEDEB50479FDF3194ULL,
		0xD43444F3DFDE5D9EULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5502D3223616BC54ULL,
		0xD03BCD14D6499837ULL,
		0x6F76B2AE4AF1760AULL,
		0xCF5EE8AF97B01F2CULL,
		0xC7AC898A1527323CULL,
		0x7245870B2F4C3077ULL,
		0x93C358556A9A0A4BULL,
		0x92189108D6EDCD73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A236B2A8B34636ULL,
		0x41BFF51ADB4495CCULL,
		0xC0A8496E020978D2ULL,
		0xFAC887D49F7DF0A4ULL,
		0xE0EE99406FB2C375ULL,
		0xDCC3A6CEA5F6D740ULL,
		0x217C123957DE0271ULL,
		0xDA24DBC81DF5ED20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37A0E5909EA5FA62ULL,
		0x9184380E0D0D0DFBULL,
		0xAFDEFBC048F80ED8ULL,
		0x35966F7B08CDEF88ULL,
		0x274210CA7A95F149ULL,
		0xAE8621C58ABAE737ULL,
		0xB2BF4A6C3D44083AULL,
		0x483C4AC0CB182053ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEC060F19D1AF578ULL,
		0x546420A3718C7267ULL,
		0x20F5BBA10BA5080EULL,
		0x3F5EDD005BE54EADULL,
		0x62C6A2706E7A0A8AULL,
		0x8D4FB8B8D6FBEA58ULL,
		0xB87DB260ED32A892ULL,
		0x2C8B7832C6651949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C2F414D71033144ULL,
		0x7B5BC4F3F468A6C0ULL,
		0x44A8B75A29122EE4ULL,
		0xF4C6297FAC7F6E20ULL,
		0x58765824940061D8ULL,
		0xA6510DE6812FF5A4ULL,
		0xEC3D7FD6DA1F26CBULL,
		0xF8DAA7467D36CCF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2EF21BCEC19C43CULL,
		0x2F3FE45085E4D4A7ULL,
		0x645D0CFB22B726EAULL,
		0xCB98F47FF79A208DULL,
		0x3AB0FA54FA7A6B52ULL,
		0x2B1EB55E57D41FFCULL,
		0x5440CDB6372D8E59ULL,
		0xD451DF74BB53D5BEULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DAF716E825B5437ULL,
		0x20B270378AD50792ULL,
		0x7862ABF6BC16F2FAULL,
		0x2FFD1257D4278968ULL,
		0x1BC07D1BB36ADB22ULL,
		0xF1778C1736417E79ULL,
		0x23888063AA2B4C96ULL,
		0x104ADA28EB2D63CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3CEA9D7400EFFAEULL,
		0x8C2CC7485DFCC72FULL,
		0xCE74F0356DB2D9F2ULL,
		0x068306DD3966E119ULL,
		0x8AF111D459F538AAULL,
		0xAB2D31DBEEF05176ULL,
		0x4C9893BEA3B60B64ULL,
		0x657D74694AD01CBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E61D8B9C255AB99ULL,
		0xAC9EB77FD729C0BDULL,
		0xB6165BC3D1A42B08ULL,
		0x297E148AED416871ULL,
		0x91316CCFEA9FE388ULL,
		0x5A5ABDCCD8B12F0FULL,
		0x6F1013DD099D47F2ULL,
		0x7537AE41A1FD7F76ULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x576948476FCEA1F8ULL,
		0xF09759E45E45EF59ULL,
		0x1399FD357C2E55D3ULL,
		0x96C8F830CF485938ULL,
		0x170059F6B41D16EBULL,
		0x22E5F9200617C9B8ULL,
		0x6BE5B833EA54F8A0ULL,
		0x4EA7DCC707E4D597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93A0F7330256FF6CULL,
		0xD7A69D366DCA2E20ULL,
		0x04AC14A2CA191C05ULL,
		0x349C467B8286C9F1ULL,
		0x7E728530EA965D3FULL,
		0x63B95E29C46CAE80ULL,
		0x2AE8776586EA1242ULL,
		0x072478DBC47D7569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4C9BF746D985E94ULL,
		0x2731C4D2338FC179ULL,
		0x1735E997B63749D6ULL,
		0xA254BE4B4DCE90C9ULL,
		0x6972DCC65E8B4BD4ULL,
		0x415CA709C27B6738ULL,
		0x410DCF566CBEEAE2ULL,
		0x4983A41CC399A0FEULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x561668B1B3E9DD05ULL,
		0x7844DC5BC7228836ULL,
		0x357342C157B4D8BBULL,
		0x14E9823C04A3C944ULL,
		0xE67F23E21BA813BFULL,
		0xCC5AE85AE2C84CC8ULL,
		0x4B4A840EB36CD5A8ULL,
		0x15DB2A64613B049CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18DB49F4F1F7FA97ULL,
		0xE391BD759FD179B3ULL,
		0x0EAB04E4AF7E55F0ULL,
		0xEC2ECBCAB7B81169ULL,
		0x55A2768FBD7F5B41ULL,
		0x7332F825F4CCE871ULL,
		0xE2D41D7CBC0B05E9ULL,
		0x869C1B73E62F02DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ECD2145421E2792ULL,
		0x9BD5612E58F3F185ULL,
		0x3BD84625F8CA8D4BULL,
		0xF8C749F6B31BD82DULL,
		0xB3DD556DA6D748FEULL,
		0xBF68107F1604A4B9ULL,
		0xA99E99720F67D041ULL,
		0x9347311787140641ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC20A3053C7503BCDULL,
		0xD39A7983686A3FA6ULL,
		0x86A3EDF98C4142DBULL,
		0x0E3702E3C3C86027ULL,
		0xB3E3A861C3A9F7A9ULL,
		0x3A5DF98F756BAC3DULL,
		0x2F37C961FAF7C9A7ULL,
		0x864A7B350D6D2C3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD11C274E10CB297CULL,
		0x9E7044489347B81CULL,
		0x3262BF06A4F76FECULL,
		0xC90DCF4C76C9C1DDULL,
		0x20BCDF0D4AB9E494ULL,
		0x78500EDF9BF794EFULL,
		0xCF717CB5B3AF0C9FULL,
		0xCF02360FE1149DD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1316171DD79B12B1ULL,
		0x4DEA3DCBFB2D87BAULL,
		0xB4C152FF28B62D37ULL,
		0xC73ACDAFB501A1FAULL,
		0x935F776C8910133DULL,
		0x420DF750EE9C38D2ULL,
		0xE046B5D44958C538ULL,
		0x49484D3AEC79B1E3ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x600AE554A2FBBF04ULL,
		0x5E6DEFF3399599CBULL,
		0x537B9C9E3F0F6D5EULL,
		0xC0E3ED1795F62A94ULL,
		0x7A91711ABA2FB8EBULL,
		0x841C6A13EE72E608ULL,
		0x6418CF908D6E9365ULL,
		0xA5895567B676B285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0591D5E3E22A707ULL,
		0x1AA415C16E5C44A5ULL,
		0xEC25FB42D644EE6FULL,
		0xA1EB92F84E3841B6ULL,
		0x2ADE2321E07BD68BULL,
		0x133D78284B70FCD0ULL,
		0xA1D7CF7B8892C8A8ULL,
		0x8DB537F9B6DD50E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8053F80A9CD91803ULL,
		0x44C9FA3257C9DD6EULL,
		0xBF5E67DCE94B8331ULL,
		0x61087FEFDBCE6B22ULL,
		0x504F523B5A546E60ULL,
		0x9721123BA5021AD8ULL,
		0xC5CF00EB05FC5BCDULL,
		0x283C629E00ABE264ULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF840F47CA48C2A1ULL,
		0xCDB2B2ED9B6E8431ULL,
		0xB4F07D63A5399EECULL,
		0x30C353A924530742ULL,
		0xD2EFA58926A7E1D0ULL,
		0xA81D0A673A791FD3ULL,
		0x500A928F00A69F00ULL,
		0x9CF4C8CF105FB667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x256D567FA0A2EA7FULL,
		0x712003452ECBF2A9ULL,
		0xF168BEA69EEF6D8BULL,
		0x589EE43182C6F94DULL,
		0x86379B3BB8CEA120ULL,
		0xE0904B49DEB55E9AULL,
		0x6DB45C2D6F4B5AF7ULL,
		0xED0AFEFDDAA450DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAE959386AEA28DEULL,
		0xBC92B1A8B5A57698ULL,
		0x4598C3C53BD6F367ULL,
		0x685DB798A695FE0FULL,
		0x54D83EB29E6940F0ULL,
		0x488D412EE4CC4149ULL,
		0x3DBECEA26FEDC5F7ULL,
		0x71FE3632CAFBE6BBULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC9150742F868246ULL,
		0x7F675D961BA83CECULL,
		0x58C780C05C9579E6ULL,
		0xEE5E25E5C2E9277AULL,
		0x484D172AF80E96F5ULL,
		0x382F9BA91E87EBC5ULL,
		0xF6D8F527F8AB8058ULL,
		0xA6D70633EED77AD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE484E77888FDD5ULL,
		0xC58889D06EA0E9DDULL,
		0x23F3313826128CE9ULL,
		0x4EE88D64FE6E816BULL,
		0x6994ED65BF3D40B9ULL,
		0xA981F35FF3D6BFD2ULL,
		0x0FDB854FA278B008ULL,
		0x02474EFCA179799FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF275D493570E7F93ULL,
		0xBAEFD4467508D531ULL,
		0x7B34B1F87A87F50FULL,
		0xA0B6A8813C87A611ULL,
		0x21D9FA4F4733D64CULL,
		0x91AE68F6ED515417ULL,
		0xF90370685AD33050ULL,
		0xA49048CF4FAE034AULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC04381AEA45C9D75ULL,
		0xB148B0A27D03265EULL,
		0xC95A216DCB970C3CULL,
		0x0C5FF69CC2520B52ULL,
		0x68DA6A7FE3219DD7ULL,
		0x2E7DBDBB38DCE25CULL,
		0x1DE713DF68E84F3AULL,
		0x693B5781528E2D81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF136E6C1CEEA028CULL,
		0x7633B210EF243B1FULL,
		0x7BCE1FD91A1CD27AULL,
		0x57618D3884337438ULL,
		0x8C6AC8E2E0E3BE33ULL,
		0xA1DAEB5B79C0AD57ULL,
		0x29F0BBAE230B31F3ULL,
		0x393B27833DF342BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3175676F6AB69FF9ULL,
		0xC77B02B292271D41ULL,
		0xB2943EB4D18BDE46ULL,
		0x5B3E7BA446617F6AULL,
		0xE4B0A29D03C223E4ULL,
		0x8FA756E0411C4F0BULL,
		0x3417A8714BE37EC9ULL,
		0x500070026F7D6F3AULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A889992AB5FACD3ULL,
		0x416FE05C327175B8ULL,
		0x982AA722DCCF67B7ULL,
		0xFE5C46ACDF393343ULL,
		0xC7AE081B8C7D485CULL,
		0xC4ACDF68AD3B5F1EULL,
		0x520C94D5C011944BULL,
		0x68A1BF1955926CA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF87B54F3EC8FF74ULL,
		0xBC8E6165E0BE7492ULL,
		0xC5BC459147814162ULL,
		0xC4E1269C3F1E32FEULL,
		0x98D1CE64EAC8A3CCULL,
		0x245B531D54233819ULL,
		0x1E38C6697279D518ULL,
		0x9537E854CDD5E59EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x950F2CDD959753A7ULL,
		0xFDE18139D2CF012AULL,
		0x5D96E2B39B4E26D5ULL,
		0x3ABD6030E02701BDULL,
		0x5F7FC67F66B5EB90ULL,
		0xE0F78C75F9186707ULL,
		0x4C3452BCB2684153ULL,
		0xFD96574D98478939ULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09ED7530BB9E28F4ULL,
		0x75B4F7C41EC19936ULL,
		0x14F735E2C8ECFF89ULL,
		0x71E965C2382FA6E0ULL,
		0x211559CFC0A141ABULL,
		0x348E4D2BFC6DA492ULL,
		0x5142C7E202EE5AC8ULL,
		0x10AA96AF8D0F6DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00A4BE1A7D45C07ULL,
		0xE2A9269EB859B1EDULL,
		0x43B478885EDC33EEULL,
		0x0EEFE16CA4B874EDULL,
		0x670036BBD81402F0ULL,
		0x5BD8BB63E1908F11ULL,
		0x34B25A11F5A392F9ULL,
		0xB48EBFA2CB4E4F8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9E73ED11C4A74F3ULL,
		0x971DD15AA69828DBULL,
		0x57434D6A9630CC67ULL,
		0x7F0684AE9C97D20DULL,
		0x46156F7418B5435BULL,
		0x6F56F6481DFD2B83ULL,
		0x65F09DF3F74DC831ULL,
		0xA424290D46412230ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52F36FF8AEFD1F49ULL,
		0x88A84F920AE1B30CULL,
		0xE9449E594A218429ULL,
		0x986DE0BCB2645D5DULL,
		0x3A009F88694DE3ACULL,
		0x0C9C4F04F04BF951ULL,
		0x8991259D951B2915ULL,
		0x2881D3C85E4844ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x014172FB14488929ULL,
		0x8048C853FC2BBCA8ULL,
		0x6D4EA18AE371541BULL,
		0x9424A7A683A85BA5ULL,
		0x434C7F253ABDC2FDULL,
		0x4432BBE16E5AB473ULL,
		0xDEA27DA5FFA226ECULL,
		0xD0184DE0BC6F3DB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B21D03BAB59660ULL,
		0x08E087C1F6CA0FA4ULL,
		0x840A3FD3A950D032ULL,
		0x0C49471A31CC06F8ULL,
		0x794CE0AD53F02151ULL,
		0x48AEF4E59E114D22ULL,
		0x573358386AB90FF9ULL,
		0xF8999E28E227791FULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB3ED2F72CE6A841ULL,
		0xF140B2A65B2C9DC9ULL,
		0xA293016ECBC2D944ULL,
		0x17DE06873D03C543ULL,
		0x3A9BA3F24373A194ULL,
		0x0257775D25F3C481ULL,
		0x3D1721659DCA9704ULL,
		0x3B62EA9D024916A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DE0299BEC55CA50ULL,
		0x99F2D87CDFBE9FE1ULL,
		0x3CCE83B48A67C7C5ULL,
		0xE35EBBA426E07921ULL,
		0x27DA2DF28EA2A07BULL,
		0x9551C2D027D677F7ULL,
		0xC56F741CAAFDA0A5ULL,
		0x0862FC6878E47205ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76DEFB6CC0B36211ULL,
		0x68B26ADA84920228ULL,
		0x9E5D82DA41A51E81ULL,
		0xF480BD231BE3BC62ULL,
		0x1D418E00CDD101EFULL,
		0x9706B58D0225B376ULL,
		0xF8785579373737A1ULL,
		0x330016F57AAD64ADULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E96F84A3FF3FDD5ULL,
		0x1FACC94F84A995D5ULL,
		0x4DEC3986FD1D2359ULL,
		0xF039ED1B25496CE6ULL,
		0xCDB8731FD11FABA7ULL,
		0xB3DD614F1DE4450DULL,
		0x2356133A38E1518FULL,
		0x12B7A2EC4AEFC908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA7B73DF3CB05DE7ULL,
		0x8A79B3AE373BCD7FULL,
		0x33CC49CEF2E44D45ULL,
		0xAD81EA3167D969F2ULL,
		0xE2C740DA5C5AAC86ULL,
		0xDC6B9EE98A632357ULL,
		0x0B11AC92D143E1B9ULL,
		0x967BA3AD2B7FB28EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4ED8B950343A032ULL,
		0x95D57AE1B39258AAULL,
		0x7E2070480FF96E1CULL,
		0x5DB8072A42900514ULL,
		0x2F7F33C58D450721ULL,
		0x6FB6FFA69787665AULL,
		0x2847BFA8E9A2B036ULL,
		0x84CC014161907B86ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x283BE8EB0D20FE0EULL,
		0x907221892597780EULL,
		0xC43BB21B143885A1ULL,
		0xFD7C07030E05EF15ULL,
		0x045AC27016E59CF9ULL,
		0x4B506857B85FC30AULL,
		0xFEECF2EFA1F102DDULL,
		0xA08B7D48F059C872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29B6304987C7817ULL,
		0x80A59CC66637E5B8ULL,
		0x159E60147354E885ULL,
		0x9D76B9C862F74C38ULL,
		0x9653C860845FBF0AULL,
		0x1EFC9CE68B3CDB85ULL,
		0xB77A165E5FB1BD4AULL,
		0xBBAC9934F1A50A96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AA08BEF955C8619ULL,
		0x10D7BD4F43A09DB6ULL,
		0xD1A5D20F676C6D24ULL,
		0x600ABECB6CF2A32DULL,
		0x92090A1092BA23F3ULL,
		0x55ACF4B13363188FULL,
		0x4996E4B1FE40BF97ULL,
		0x1B27E47C01FCC2E4ULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07332930EAFE37BAULL,
		0xEE8A76E28B0BCB07ULL,
		0xDE754179F33752F4ULL,
		0x0641A9A5FC19E5ECULL,
		0x95E65ACEFB682174ULL,
		0xA7CD903945C1CA12ULL,
		0x5BE8033CEBAF53ABULL,
		0xCE3D5FFCC707F270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C5D4F4D8BF762BULL,
		0xCB24C257733A9642ULL,
		0xA27A81E60F48FDD0ULL,
		0xDB9DF30886BA3C7FULL,
		0xDD3631C25BC45143ULL,
		0xBE5B73C57EA83F23ULL,
		0x6011E6EC2E506432ULL,
		0xBF2C636F65B59396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1F6FDC432414191ULL,
		0x25AEB4B5F8315D45ULL,
		0x7C0FC09FFC7FAF24ULL,
		0xDDDC5AAD7AA3D993ULL,
		0x48D06B0CA0AC7037ULL,
		0x1996E3FC3B69F531ULL,
		0x3BF9E5D0C5FF3799ULL,
		0x71113C93A2B261E6ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x186C57368F4AF989ULL,
		0x1DBA188620CA9660ULL,
		0x5F94048AADB50156ULL,
		0x1B5509874AC1A817ULL,
		0x600E82FF3235C216ULL,
		0x339C42ADA0661545ULL,
		0x9CAA0E36FFDC68D4ULL,
		0x7520BDB4DEF230B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D5F1348DE1F1AFEULL,
		0x340B219CEBFDCC42ULL,
		0x4DE6AC89B352A357ULL,
		0x362B696487C5E3BAULL,
		0xFCDA39B31A34D5AEULL,
		0x5FC088DB2908BF43ULL,
		0x3700E16E7EF6FC47ULL,
		0xE41B095949EEC837ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9533447E5155E377ULL,
		0x29B1391ACB375A22ULL,
		0x1272A8031EE7A201ULL,
		0x2D7E60E3CD044BADULL,
		0x9CD4BB4C280117B8ULL,
		0x6C5CCA76896EAA06ULL,
		0xABAAEF58812A9493ULL,
		0x913BB4ED971CF884ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFC5C3E20F47574AULL,
		0x31965A5B138168E7ULL,
		0x1F1620270C3D71B8ULL,
		0xC46F0972814F181FULL,
		0x55B91BBCDB14B2C9ULL,
		0x773AF52CE4902F32ULL,
		0x8CEB8479923DB7C3ULL,
		0xFE7EF11BCCA5117EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C1CAD18AC827D3ULL,
		0xE755474960EAA48EULL,
		0x0E7D03D9891BA783ULL,
		0xD8FA9CAD660D8B4AULL,
		0x9A8B8B78374FB710ULL,
		0xAB8B6A7546E87E04ULL,
		0x4920EB4327FD39DFULL,
		0xA2F792241A284578ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB040933858F7099ULL,
		0xD6C31D12736BCC69ULL,
		0x116B23FE8526D63BULL,
		0x1C9595DFE7429355ULL,
		0xCF3290C4EC5B05D9ULL,
		0xDCB19F59A2785136ULL,
		0xC5CB6F3AB5C08E1CULL,
		0x5C89633FD68D5406ULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78C0BAE0C2CDF162ULL,
		0x6858E52141AB0F05ULL,
		0x3A532A805DBB6CB8ULL,
		0xEF9BCEA07780CBF5ULL,
		0xC5E0951C10A0061BULL,
		0x8AED1CD7FFF2BFD4ULL,
		0x8C0970029818A5C2ULL,
		0xFF9C3F1C3F8C3D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD867FAB4FDE04330ULL,
		0xA95539B544F5A591ULL,
		0x60C1B6F2FC93B0BFULL,
		0xF4E0624CCE59EA6BULL,
		0x40AACAFE8CAAFD83ULL,
		0x9051F970F6CFC318ULL,
		0x2EB9BD66131EDC23ULL,
		0x4BBA6C2E0AF0465FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0A740543F2DB252ULL,
		0xC10DDC94055EAA94ULL,
		0x5A929C72A128DC07ULL,
		0x1B7BACECB9D9219EULL,
		0x854A5FE29C0AFB98ULL,
		0x1ABCE5A7093D7CCCULL,
		0xA2B0CD648B0679E1ULL,
		0xB4265332357C7BCEULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF00C9BDFA2BB21ULL,
		0x0463DF01F9FD1D2AULL,
		0x38F61242C0EE60E8ULL,
		0x021A5677FB4FB516ULL,
		0x5AC85BA624180CB1ULL,
		0x496DC9501262B297ULL,
		0x52B9CC74B06E95FCULL,
		0xC6B2E5451B6777F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA0BC3F393EA8073ULL,
		0x4973AAE3FB24ACD1ULL,
		0xFA5B2FB2618FAA4EULL,
		0xF14841CDA7177E27ULL,
		0x88C111930F27C26EULL,
		0x3F79652B4A3B04C8ULL,
		0x7C451432D80434B3ULL,
		0xC168B88B7D80056CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71FBCF684C483B52ULL,
		0x4D1075E202D9B1FBULL,
		0xC2AD3DF0A161CAA6ULL,
		0xF35217BA5C58CB31ULL,
		0xD2094A352B3FCEDFULL,
		0x7614AC7B5859B65FULL,
		0x2EFCD846686AA14FULL,
		0x07DA5DCE66E7729DULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9611A59C773C3962ULL,
		0x8F5D3EE708F3ED57ULL,
		0x305B77B6BEE69F6EULL,
		0xC2AEEF904591112EULL,
		0xCF07E542DECEC35BULL,
		0x34910BE20DC28995ULL,
		0x7F248DA93392FAB9ULL,
		0x1DEB3F94761E4087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D40DD5469F5543ULL,
		0x33FBB843DA208804ULL,
		0x5D9A31A7679B67D0ULL,
		0x5EDD61B7C02A90A7ULL,
		0x7756592C8A56029DULL,
		0x14DA08A8B945F2ECULL,
		0xF170045ADE96DE87ULL,
		0xA64017A694B0EF42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22C5A84931A36C21ULL,
		0xBCA686A4D2D36553ULL,
		0x6DC14611D97DF8BEULL,
		0x9C738E2785BB8189ULL,
		0xB851BC6E5498C1C6ULL,
		0x204B034AB4877B79ULL,
		0x8E5489F3ED04243EULL,
		0xBBAB2832E2AEAFC5ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF42A2C3A37C8777FULL,
		0x82A34C68BD923EFFULL,
		0x1D9651AEB901C571ULL,
		0x7AAD1CAF44393F2CULL,
		0x138838DACED4A45DULL,
		0x3F96C721F47B1983ULL,
		0x77BA02FECD954106ULL,
		0x317B8E7357B19474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E6C1F0676F3F01ULL,
		0x6BC55595B9789994ULL,
		0x2F662F50A69E1B65ULL,
		0xDA69263C041466E2ULL,
		0xB053B1CF77DE8E56ULL,
		0xF450EF53CA8FC5F3ULL,
		0xBE20703C23F904EFULL,
		0xE904B35BB8CBDE15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46CCEDCA50A7487EULL,
		0xE96619FD04EAA76BULL,
		0x32F07EFE1F9FDE14ULL,
		0xA0C43A93402D59CEULL,
		0xA3DB8915B90A2A0BULL,
		0xCBC628723EF4DC70ULL,
		0xC99A72C2EE6C45E9ULL,
		0xD87F3D28EF7A4A61ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F13BE5B13F60250ULL,
		0x6E07544CFD271C70ULL,
		0x46610DBCF14D5E2BULL,
		0x960FC9BEB344C476ULL,
		0x3961DFBFDB48F129ULL,
		0xD9A94C38FDEC25EDULL,
		0x963D941F72ED0823ULL,
		0x3D991650A2963C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5249F65CB0EB9F2FULL,
		0xF38D9A8500F0C8A3ULL,
		0x914F86A02AC30D7BULL,
		0x121650240DA6A4BDULL,
		0x0C15ED20B64DE1DCULL,
		0x188B94A0910BDD0BULL,
		0x11CB9E12F3064420ULL,
		0x4C63A74B8970AD06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D5A4807A31D9D7FULL,
		0x9D8ACEC9FDD7D4D3ULL,
		0xD72E8B1CDB8E5350ULL,
		0x8419999ABEE260CBULL,
		0x3574329F6D0510F5ULL,
		0xC122D8986CE7F8E6ULL,
		0x87F60A0D81EB4C03ULL,
		0x71FAB11B2BE69129ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F89C6B3A909D682ULL,
		0x29A913AFBCE0E514ULL,
		0x58E242A030F08F36ULL,
		0x8348602FEE3D4C47ULL,
		0x23485D1D17B47EB1ULL,
		0x064D97F4E15C5D31ULL,
		0xCF2913F48BD32FE5ULL,
		0xF0F59F1B62ED7E9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x457A698FE1030574ULL,
		0x57D00DE1616EE755ULL,
		0x6EBB057051A0F61FULL,
		0x5279DD359DD1D2DDULL,
		0xCB8951DA6904B6F4ULL,
		0x3124B52EBFAE21C0ULL,
		0x653396F4D75F2E4DULL,
		0x805004C98F1E987FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AF3AF3C480AD3F6ULL,
		0x7E791E4EDD8E0241ULL,
		0x365947D061507929ULL,
		0xD131BD1A73EC9E9AULL,
		0xE8C10CC77EB0C845ULL,
		0x376922DA5EF27CF1ULL,
		0xAA1A85005C8C01A8ULL,
		0x70A59BD2EDF3E6E4ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BCE179981097061ULL,
		0xFC1709FF990E52F6ULL,
		0x5C1979BF7B21D294ULL,
		0x741D982D6C7BD267ULL,
		0x6BCF2A7FBC302BFFULL,
		0x0146096749B8E7EBULL,
		0x1498F1B7A69C2DC8ULL,
		0x66942DB42D52B091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA943E3F1866540ULL,
		0x1DF2B613127A2E2EULL,
		0x01BBE36E16DE1276ULL,
		0x5BAC401EDD501BD6ULL,
		0xDE247BC3DB52ECCDULL,
		0x978A1FF7D4742A4DULL,
		0xE87D5E2D5455234DULL,
		0x5EB0A742A44CF6C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1167547A708F1521ULL,
		0xE1E5BFEC8B747CD8ULL,
		0x5DA29AD16DFFC0E2ULL,
		0x2FB1D833B12BC9B1ULL,
		0xB5EB51BC6762C732ULL,
		0x96CC16909DCCCDA6ULL,
		0xFCE5AF9AF2C90E85ULL,
		0x38248AF6891E4657ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D5823BD7493F3C2ULL,
		0x683F1EE843A5FBC4ULL,
		0xF7AB0799AC2D8A77ULL,
		0xF419B4DA0FE0D447ULL,
		0xDE0B97913D5C8F41ULL,
		0x586A406F9EE9A006ULL,
		0x02CB6BB1C365F3F3ULL,
		0x3558DA4B679D5D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72EB473D77B0793FULL,
		0xABBB30BE6DCD1B08ULL,
		0x8D1B05414B5AC394ULL,
		0xFE66787EC58AC90EULL,
		0xEE7C1B84C6CDCE21ULL,
		0xA94BD32FA5E6FE3DULL,
		0x95DBCBACFF26A71BULL,
		0xE73D608990FA276AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FB3648003238AFDULL,
		0xC3842E562E68E0CCULL,
		0x7AB002D8E77749E3ULL,
		0x0A7FCCA4CA6A1D49ULL,
		0x30778C15FB914160ULL,
		0xF12193403B0F5E3BULL,
		0x9710A01D3C4354E8ULL,
		0xD265BAC2F7677AE2ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89EC2B9C5A1C46DDULL,
		0xD24B11435531054AULL,
		0xBD86C8831C515D0DULL,
		0x52E8B26973D1BE66ULL,
		0xE85A6888A532C5E8ULL,
		0xB334E0A839CCCD3DULL,
		0x50A27914D5020BF4ULL,
		0xEBF15B419C35D319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA16F90B9A978C665ULL,
		0xC745E7B071C0587EULL,
		0xF26055604373E7DCULL,
		0x0B57D903A29A83A0ULL,
		0x40787D876869E5E2ULL,
		0x880BF55520100283ULL,
		0xAC5710AA26B35A07ULL,
		0x06152F0CFA7E7760ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2883BB25F36480B8ULL,
		0x150EF6F324F15D34ULL,
		0x4FE69DE35F22BAD1ULL,
		0x59BF6B6AD14B3DC6ULL,
		0xA822150FCD5B200AULL,
		0x3B3F15FD19DCCFBEULL,
		0xFCF569BEF3B151F3ULL,
		0xEDE4744D664BA479ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA26AA3A5B7C5E7B4ULL,
		0xB513E756FEF2C7B4ULL,
		0x49C54B2B9AC49E02ULL,
		0xADB8A4CB98E194AEULL,
		0xCF831BF9FBA17EC8ULL,
		0x323244E664014764ULL,
		0x9FD180F8F1F9F0A8ULL,
		0x4C4B72B7C0AE7DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC766F774D03A0BULL,
		0x4865089876CE826CULL,
		0xA6652E3F61A55DD4ULL,
		0x43E10CC8B39BF717ULL,
		0xE3B103FDEC7715B8ULL,
		0xA4ADB6EA6C556A4EULL,
		0x44574CF0BC54C83FULL,
		0xBFB1469C702B33FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CADC552C315DDBFULL,
		0xFD76EFCE883C45D8ULL,
		0xEFA06514FB61C3D6ULL,
		0xEE59A8032B7A63B9ULL,
		0x2C32180417D66B70ULL,
		0x969FF20C08542D2AULL,
		0xDB86CC084DAD3897ULL,
		0xF3FA342BB0854E28ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06C02B7C8A6856DAULL,
		0xB2DB2105A3CEA40BULL,
		0x491EE44647929D88ULL,
		0xD8803ED49A966B5CULL,
		0x84A03F5957B29F92ULL,
		0xF2CF5B830FE1092AULL,
		0x5779C660672C099AULL,
		0x750C786BAF37F3E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679A6DECC2D22A3CULL,
		0x18A9A9B258254DE7ULL,
		0x45C525BD1B53E309ULL,
		0x7C7D3DF5033ACABEULL,
		0x041DC8C8780F5A72ULL,
		0xEC309E036A554DD2ULL,
		0xF9237070D030FC7CULL,
		0x6CD45EC7D6A38C7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x615A469048BA7CE6ULL,
		0xAA7288B7FBEBE9ECULL,
		0x0CDBC1FB5CC17E81ULL,
		0xA4FD032199ACA1E2ULL,
		0x80BDF7912FBDC5E0ULL,
		0x1EFFC58065B444F8ULL,
		0xAE5AB610B71CF5E6ULL,
		0x19D826AC79947F98ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5BC331F3038B76DULL,
		0x0CC15815D70F5F33ULL,
		0x0B3E532A933F5BE6ULL,
		0xF84E4D542846A70EULL,
		0xF2CB26DD0937FE41ULL,
		0x2BA89D1BBE7F9B2EULL,
		0xBDC913181E24EF5DULL,
		0x1061E200A094D0BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0321B0C768B6757ULL,
		0xD8445A14B2C69DDAULL,
		0x73B2CD8FA64893BAULL,
		0x60EBE7F049C0B183ULL,
		0x569A3FF61D32B8B3ULL,
		0x016308A7DAC14215ULL,
		0xE2A4AE979678CEE2ULL,
		0x93881A7A0457DB95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x258E281346B3D03AULL,
		0xD485020165C9C2E9ULL,
		0x788C9EA53577C85CULL,
		0x98A5AAA46186168DULL,
		0xA451192B140546F2ULL,
		0x2ACB95BC64BED93BULL,
		0x5F6DBD8F885C21BFULL,
		0x83E9F87AA4C30B2EULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x391A1221833EDB9EULL,
		0x967BFF3202AFE3ABULL,
		0xFD515E102858C635ULL,
		0x0BD786C5459C3940ULL,
		0x065F85EC4F3C2C2AULL,
		0xAC74168007AB529DULL,
		0x5DEBECBB3003CA58ULL,
		0x19D0AC9E8982FD07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0980D19A41C3DCECULL,
		0xD41BCB225E87EE5BULL,
		0x4B75A4311767FA45ULL,
		0x9451665CF0201BC7ULL,
		0xCB1C550F9493337EULL,
		0x2A5F14CB847DE665ULL,
		0xB5CF67073265B01DULL,
		0xF192986A4D6E3EC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x309AC3BBC2FD0772ULL,
		0x426034105C280DF0ULL,
		0xB624FA213F3F3C70ULL,
		0x9F86E099B5BC2287ULL,
		0xCD43D0E3DBAF1F54ULL,
		0x862B024B83D6B4F8ULL,
		0xE8248BBC02667A45ULL,
		0xE84234F4C4ECC3CFULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF44F871C274DBF9ULL,
		0x25C2FEF079C1AB84ULL,
		0xEC9903F4FAEF72FDULL,
		0x809ECB9B644C677EULL,
		0x3EDDC87C7547ECDAULL,
		0x9AFDBA87FE1823D3ULL,
		0x6FB8BA36D41D01CDULL,
		0xFAD4E22F8E216FCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18396D83C42668CDULL,
		0x9377B06FADF4B0DEULL,
		0x9911C9357B1AAFEAULL,
		0xFA5874BAD3060D5FULL,
		0x77368AF1C3CE8510ULL,
		0x7BC5541AAC27B618ULL,
		0x7E83522470B21A3FULL,
		0xC1568FEF8E9A5AD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE77D95F20652B334ULL,
		0xB6B54E9FD4351B5AULL,
		0x7588CAC181F5DD17ULL,
		0x7AC6BF21B74A6A21ULL,
		0x49EB428DB68969CAULL,
		0xE138EE9D523F95CBULL,
		0x113BE812A4AF1BF2ULL,
		0x3B826DC000BB351CULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAE771A229EF71F8ULL,
		0xED8AA76359F3D992ULL,
		0x377E0FB791FC4317ULL,
		0x95B0913966642007ULL,
		0xD6D1DD8A4058EC2EULL,
		0xB9446FCAC6B82AB0ULL,
		0xEF848743577D66AFULL,
		0x913436331FED32B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70849FF1D2C4ACCCULL,
		0xB0E6162CFE8DA6ECULL,
		0x4144CFF0D73A6677ULL,
		0x5D4771E3DF157516ULL,
		0xBCF23E230F5CECE1ULL,
		0xEDCA26FB2E3953FCULL,
		0xF04F4A4E163C71A3ULL,
		0xAA0E8BF4DF3FF89BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA63EE53FB2BDD34ULL,
		0x5D6CB14FA77E7F7EULL,
		0x763AC04746C62560ULL,
		0xC8F7E0DAB9715511ULL,
		0x6A23E3A94F0400CFULL,
		0x548E4931E881794CULL,
		0x1FCBCD0D4141170CULL,
		0x3B3ABDC7C0D2CA2DULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DF3CC30DFF3D28FULL,
		0x554300F4ACBA23B9ULL,
		0xD45B495B360F4BBAULL,
		0x237DBE470038647EULL,
		0x259EAF9B33B0BAB2ULL,
		0x4A9C99FE9F1B092CULL,
		0x8452DF7BD02A7176ULL,
		0x1E7EC3412AF52901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80A9C10200268507ULL,
		0x7625B825FFFACC80ULL,
		0xF8C5A9755D50DE35ULL,
		0xF22357286EFCC4F0ULL,
		0xED85D6E0622B9C08ULL,
		0x37BB6F06B585CB36ULL,
		0xA49A15DAD7396BFDULL,
		0xEF97474AA79E0C85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D5A0D32DFD55788ULL,
		0x2366B8D15340EF39ULL,
		0x2C9EE02E6B5F958FULL,
		0xD15EE96F6EC4A08EULL,
		0xC81B797B519B26BAULL,
		0x7D27F6F82A9EC21AULL,
		0x20C8CAA107131A8BULL,
		0xF1E9840B8D6B2584ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93C2BE5550F8E0D0ULL,
		0x31C47D55ED9B0711ULL,
		0x66A79FEA25F61972ULL,
		0xF5CBBAC67B2F9ED3ULL,
		0xD2927F5E8DFC2496ULL,
		0xCF2A8F39E36F5BDBULL,
		0x0EB6DB7603138054ULL,
		0x0C8A7D7FD9A1702DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2F0A190CFF0D4DULL,
		0x94CD99507A03DCCCULL,
		0x02884A8860DCCB03ULL,
		0x04F5F79EACE51DABULL,
		0xBC0941C216617025ULL,
		0x11A51B250FCA66EEULL,
		0x2E4AD751663459FFULL,
		0xC39A76CE91F53145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FEDB44C5C07ED9DULL,
		0xA509E4059798DBDDULL,
		0x642FD562452AD271ULL,
		0xF13E4D58D7CA8378ULL,
		0x6E9B3E9C9B9D54B3ULL,
		0xDE8F941CECA53D35ULL,
		0x20FC0C276527D9ABULL,
		0xCF100BB148544168ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F2D6C7D8214FE82ULL,
		0xC0BE3BEE68F1FBCAULL,
		0xE5A23A7121532A24ULL,
		0x5F14D4F07344AA55ULL,
		0x7AE24345F36CC85DULL,
		0x456E103FF6F47AE9ULL,
		0x9AE2209E70A2C52DULL,
		0xD0F0A8C9297A623CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0BCBBADF946AC39ULL,
		0xDD5E9402416B0286ULL,
		0x700E937E9E9EF693ULL,
		0xFB80EDF92F457760ULL,
		0xE286B97F6C5D5FA5ULL,
		0x64A91E0AC47EF119ULL,
		0x30F5393D9C506A1CULL,
		0x1CA925A6BD2A3272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F91D7D07B5252BBULL,
		0x1DE0AFEC299AF94CULL,
		0x95ACA90FBFCDDCB7ULL,
		0xA49439095C01DD35ULL,
		0x9864FA3A9F3197F8ULL,
		0x21C70E35328A8BF0ULL,
		0xAA1719A3ECF2AF31ULL,
		0xCC598D6F9450504EULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81D7BAF4E551CAA3ULL,
		0xCC5B8F74EE2ECDB6ULL,
		0x5885AD340F4EFB12ULL,
		0x95D28E45A8A22FB3ULL,
		0x6E65590F0D6D85F5ULL,
		0x0280F1D15943970BULL,
		0x933BEC5967005C78ULL,
		0x33EC9FEBA4EFC66CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x301F635A1347E472ULL,
		0xB9E0E016DA77F61AULL,
		0xA3EA14B7D6D6A48DULL,
		0x4BE3EBD6937E39E7ULL,
		0x3BCDA38BC018528CULL,
		0x7C0D385A1AB4B596ULL,
		0xC1593551221781B4ULL,
		0xAB04BB4DD248AF66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1C8D9AEF6162ED1ULL,
		0x75BB6F6234593BACULL,
		0xFB6FB983D9985F9FULL,
		0xDE3165933BDC1654ULL,
		0x55A8FA84CD75D779ULL,
		0x7E8DC98B43F7229DULL,
		0x5262D9084517DDCCULL,
		0x98E824A676A7690AULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x472A6D59344BF7D5ULL,
		0x3D3267BF8392517BULL,
		0xE9A9004EDFFA6F73ULL,
		0x373D0C4D37C086D5ULL,
		0x6218BFB704C2C219ULL,
		0x395574E9DAEF1700ULL,
		0x1A4CDDD41CAD9F15ULL,
		0x16E6A200B089C8B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x438C39F3E397A54CULL,
		0x08F906C9BA0C437BULL,
		0x4BF57004F0B3AD95ULL,
		0xA5F42E71D32F61CCULL,
		0x66EEA329C13B18D9ULL,
		0xD811C5F50224C5F7ULL,
		0x5AFFD47CFD08B10AULL,
		0x8E8FB1038BF5201CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A654AAD7DC5299ULL,
		0x35CB6176399E1200ULL,
		0xA25C704A2F49C2E6ULL,
		0x92C9223CE4EFE719ULL,
		0x04F61C9EC5F9DAC0ULL,
		0xE144B11CD8CBD2F7ULL,
		0x40B309A8E1A52E1FULL,
		0x986913033B7CE8AFULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x230DD6064E6FB6F9ULL,
		0x706CA13B880877FCULL,
		0x26F20DF6F0E9C932ULL,
		0x44BFEF3470A59913ULL,
		0xC4F9B8C6874B416AULL,
		0xB24B886BE18D646DULL,
		0x1B87F54CC206C967ULL,
		0xDDD980D13A829DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47CAB95DA811A12FULL,
		0xC53A816A06D4C32AULL,
		0x7AD011B56502947BULL,
		0x5B7BE8E91ECEA439ULL,
		0x81CE632A556299A3ULL,
		0xBD329F9C011B1266ULL,
		0x739BA42AD42C7ADAULL,
		0x0850834A91041C9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64C76F5BE67E17D6ULL,
		0xB55620518EDCB4D6ULL,
		0x5C221C4395EB5D49ULL,
		0x1FC407DD6E6B3D2AULL,
		0x4537DBECD229D8C9ULL,
		0x0F7917F7E096760BULL,
		0x681C5166162AB3BDULL,
		0xD589039BAB868166ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x732C28B019BD185AULL,
		0xAD0E75DFEF2855EFULL,
		0x5D07DE97CBD47935ULL,
		0x35B6C316AF51CCDAULL,
		0x4FB0B0D1A5E92F4AULL,
		0x87B92546DD332B23ULL,
		0x80E4E2686036C82BULL,
		0xF0CA5454D4FE248CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E14E8927A87144ULL,
		0xF2ED3C24A29CF841ULL,
		0xD10D3DA92994892CULL,
		0x2ADD1B7A205F315FULL,
		0x927F3A7EA11F1C67ULL,
		0xBDA75B78E5E13860ULL,
		0x5F3BF4750E4043BFULL,
		0x824D1A841F5B6AE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4CD66393E15691EULL,
		0x5FE349FB4DB4ADAEULL,
		0x8C0AE33EE240F019ULL,
		0x1F6BD86C8F0EFD85ULL,
		0xDDCF8AAF04F6332DULL,
		0x3A1E7E3E38D21343ULL,
		0xDFDF161D6E768B94ULL,
		0x72874ED0CBA54E6DULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2834BB1FAD1D756AULL,
		0x4B7E907E44E1B218ULL,
		0xD12665C8F196D009ULL,
		0xD53BB63A89AA5987ULL,
		0x4B8D958D8DD3B44CULL,
		0xDC96682377701D42ULL,
		0xB5A7AA7D82659BE6ULL,
		0x93F55D8786F3B87EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D04FC55ECBAD45ULL,
		0x258015B69E85651FULL,
		0xAA33932A809AFAABULL,
		0x1222FE1D0C7A26B0ULL,
		0x27F394F4079051F5ULL,
		0xAB36FAF76163269AULL,
		0xD7D6A2278F415090ULL,
		0x607AE1C07EBF9511ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E4F4DAF3D6D82FULL,
		0x6EFE85C8DA64D707ULL,
		0x7B15F6E2710C2AA2ULL,
		0xC719482785D07F37ULL,
		0x6C7E01798A43E5B9ULL,
		0x77A092D416133BD8ULL,
		0x6271085A0D24CB76ULL,
		0xF38FBC47F84C2D6FULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E72099BE2D4D7E4ULL,
		0xA8D02272706E9E06ULL,
		0xC8E8647EB6467079ULL,
		0x870EE5155E89C755ULL,
		0xE9DC15C7564809FCULL,
		0x77896D0A418ACF35ULL,
		0xF5EB8FA96EAD128BULL,
		0xF2DE637826596021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF131529CAD67B5C4ULL,
		0x8CD25533E8A5679BULL,
		0x79F2A1A32A1CB087ULL,
		0x88B31B6C846D4626ULL,
		0xAAFBE1AE5CFE396FULL,
		0x692BC1BB85E8AB39ULL,
		0x72E68629F6943AE4ULL,
		0x44FCED8710B10F32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF435B074FB36220ULL,
		0x2402774198CBF99DULL,
		0xB11AC5DD9C5AC0FEULL,
		0x0FBDFE79DAE48173ULL,
		0x4327F4690AB63093ULL,
		0x1EA2ACB1C462640CULL,
		0x870D09809839286FULL,
		0xB6228EFF36E86F13ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43DA64411427192DULL,
		0xC002E86B7F359356ULL,
		0x67200B9DEED168F2ULL,
		0x4F81333E480D3BD2ULL,
		0xCF6309B8FD83E22BULL,
		0x70C219CF791EE1FAULL,
		0x4C224771E9ADB2A6ULL,
		0xA1243F2C77ABF267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5312938D79D7260ULL,
		0x6EC95D968390B4FAULL,
		0xA8CA26439D69AA94ULL,
		0x1ACC6A607D585474ULL,
		0xC02DF2C062443982ULL,
		0x20BD7B1C67D7381FULL,
		0x4687BFFE8A5F3ED6ULL,
		0xB9C165AB5D2D5D31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6EB4D79C3BA6B4DULL,
		0xAECBB5FDFCA527ACULL,
		0xCFEA2DDE73B8C266ULL,
		0x554D595E35556FA6ULL,
		0x0F4EFB789FC7DBA9ULL,
		0x507F62D31EC9D9E5ULL,
		0x0AA5F88F63F28C70ULL,
		0x18E55A872A86AF56ULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24662A26C5FE2C57ULL,
		0xA3734299D8C1E8BFULL,
		0xE741A830A8750A73ULL,
		0x9D5C51C55135043AULL,
		0x32A726E7825D661EULL,
		0xBFAB9540293B840CULL,
		0x6352A8536C62F252ULL,
		0xCB5B22F6FF121CD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D5D138B0836BCBULL,
		0x0E7FC55BA58CC8C7ULL,
		0xFC7BB22C6AB21BA4ULL,
		0x14AA8AAB63865C9AULL,
		0x9FBB01541ABC83A4ULL,
		0xE598B5527B8FAED6ULL,
		0x2F96B47CBB9DFD97ULL,
		0xAA5EE776B8CCE26BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01B3FB1E757D479CULL,
		0xAD0C87C27D4D2078ULL,
		0x1B3A1A1CC2C711D7ULL,
		0x89F6DB6E32B358A0ULL,
		0xAD1C27B398E1E5BAULL,
		0x5A33201252B42ADAULL,
		0x4CC41C2FD7FF0FC5ULL,
		0x6105C58047DEFEB9ULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E546C702B9A004CULL,
		0x2C1B7F28940C95F8ULL,
		0xDAD7A4A2BD4FE240ULL,
		0x486AD69299D978BFULL,
		0xE1F4E8F02576D095ULL,
		0x447B8852B36F1513ULL,
		0xF6D626A467EDD51AULL,
		0xA5277F84BDC3E172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA7852D9E3173E7EULL,
		0x53AC04FCFB1002CEULL,
		0xB43EB3A17D879788ULL,
		0xC5E730028AE297A1ULL,
		0x7F46E408D69376DDULL,
		0xBC667BD2014C1125ULL,
		0x533C9F0FF6DE872DULL,
		0x84AC89CAA198D559ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC42C3EA9C88D3E32ULL,
		0x7FB77BD46F1C9736ULL,
		0x6EE91703C0C875C8ULL,
		0x8D8DE690133BEF1EULL,
		0x9EB20CF8F3E5A648ULL,
		0xF81DF380B2230436ULL,
		0xA5EAB9AB91335237ULL,
		0x218BF64E1C5B342BULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34786CDD6711B5CULL,
		0xF9AD76612A4BD453ULL,
		0x42E1F53911CEBD3CULL,
		0x535EAFDF8E3931D4ULL,
		0x7770770DC99002E3ULL,
		0xE00E20528A228824ULL,
		0x6BEAC717204D974FULL,
		0x755CD81C07118D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x925B3E4DB71A8358ULL,
		0x5CA0C006AAC78EF7ULL,
		0xF1680B0C80565682ULL,
		0xBC18FD6F52953661ULL,
		0x52C652555D181488ULL,
		0xA05C96B69CC28675ULL,
		0x5234F9A7AF9FC669ULL,
		0xB069EC5F4F688BDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x711CB880616B9804ULL,
		0xA50DB667808C5AA4ULL,
		0xB389FE359198EBBEULL,
		0xEF4652B0DCAC07B5ULL,
		0x25B625589488166BULL,
		0x4052B6E416E00E51ULL,
		0x39DE3EB08FD25126ULL,
		0xC53534434879068AULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5622DB995B619FACULL,
		0x2C2B7BF666D24B9AULL,
		0xEF1194AB04ADA8E5ULL,
		0xB1713129AAFD3901ULL,
		0xD0AD02EFC5058A1BULL,
		0x9340C3F531C9892BULL,
		0x1FFB62AE76746EBFULL,
		0xC968E35767065F24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE13D55F89DB91829ULL,
		0xE4841116C32A6C6CULL,
		0x66B135818E5DB4CBULL,
		0xC65C1ACE2FA5D0ADULL,
		0xB5D37747F85A87B0ULL,
		0x7A3B2C0C9381DCD1ULL,
		0x509FBACA9E217EA6ULL,
		0x4D7D2D2F1DA45FA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB71F8E61C6D88785ULL,
		0xC8AF6AE0A5F827F6ULL,
		0x89A0A12A8AF01C2EULL,
		0x772D2BE78558E9ACULL,
		0x657E75A83D5F0DABULL,
		0xE97BEFF9A24855FAULL,
		0x4F64D864E8551019ULL,
		0x8415CE787AA20087ULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BF375E4651ED696ULL,
		0xFDF28ECFA0559F02ULL,
		0xCA25F558987F7D5EULL,
		0x0D0E713D79801ED9ULL,
		0xDBC481714DE8BB33ULL,
		0x871E58A381F8E9E3ULL,
		0x78DBF550911D549BULL,
		0x39DE4A6188C740C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE21D0E700C637523ULL,
		0xCD3603C52D7EB83CULL,
		0x84E7CC720260E120ULL,
		0xD933613794F70091ULL,
		0x3A634F9627758303ULL,
		0x458DA8537E46CFD5ULL,
		0x231AF2D13D021617ULL,
		0x120D8FCE29A0A0C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9EE7B94697DA3B5ULL,
		0x30C48D0A8D2B273EULL,
		0x4EC2392A9A1F9C7EULL,
		0xD43D100AED771E48ULL,
		0xE1A7CEE76A9D3830ULL,
		0xC293F0F0FFBE2636ULL,
		0x5BC10781AC1F428CULL,
		0x2BD3C5AFA167E000ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBC6703839CBA325ULL,
		0x6277852BD0387E1CULL,
		0xD0D21A587AA1BBC9ULL,
		0x2B521C0D969E8414ULL,
		0x84EA2BAEDF2201E2ULL,
		0x99F9976122F02A64ULL,
		0xDF0C41FF3F4C5E36ULL,
		0x55C33921FC8711B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B70E213FFA4434BULL,
		0x1B724F95AF2A659EULL,
		0xFDE684CD1B1F19A5ULL,
		0x0BAB92A5913C1A2BULL,
		0xE8495E7E64DBC757ULL,
		0x55EB7A40E56B17A2ULL,
		0x58E5C5B522554530ULL,
		0xF6F94F8C54B0EC98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0B6922BC66FE06EULL,
		0x7905CABE7F121B82ULL,
		0x2D349E9561BEA26CULL,
		0x20F98EA807A29E3FULL,
		0x6CA375D0BBF9C6B5ULL,
		0xCC12ED21C79B3DC6ULL,
		0x87E9844A1D191B06ULL,
		0xA33A76ADA837FD28ULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7922352389EA3A23ULL,
		0x99296F7A9E421923ULL,
		0x810E74A8B8749F92ULL,
		0xEC18BF367A229CCFULL,
		0x43CB5F78B374EAE9ULL,
		0xD488C0D747DFA896ULL,
		0x1720E27C385472EAULL,
		0x9E94A6802338367DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D444D5CDB745557ULL,
		0xFC4CE30CC20D36F9ULL,
		0x2D05A28C951715DAULL,
		0xB24B32A744194C73ULL,
		0x78D754253119FECAULL,
		0x25F9DF4161D12F29ULL,
		0xDAFD01265B4A79B9ULL,
		0x86AE2BED9090EFABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3466787F529E6F74ULL,
		0x65658C765C4F2FDAULL,
		0xAC0BD6242D638A48ULL,
		0x5E538D913E3BD0BCULL,
		0x3B1C0B5D826D1423ULL,
		0xF1711F96260E87BFULL,
		0xCDDDE35A631E0B53ULL,
		0x183A8D6DB3A8D9D6ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A0CF6F93944A8EULL,
		0x095550FAB6E8453AULL,
		0xD5B0A9C481CDE13AULL,
		0xAFF0943F7EDC511FULL,
		0x03E87AF91A7801D3ULL,
		0xAFE3477A97FCC943ULL,
		0x2762D59366D78BC1ULL,
		0x6F6BDE220E8BEA8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5EFBD972BF0B1ABULL,
		0x832FD083A332232CULL,
		0x6E36291640E7609DULL,
		0x5056785121BFD675ULL,
		0xD79D4AF623DAE3A8ULL,
		0x1E5DFD304CF25EA1ULL,
		0xE59C1E30E3E4EFE6ULL,
		0xF32DB25977230E78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF04F72F8B864FB25ULL,
		0x8A7A807915DA6616ULL,
		0xBB8680D2C12A81A7ULL,
		0xFFA6EC6E5F63876AULL,
		0xD475300F39A2E27BULL,
		0xB1BEBA4ADB0E97E2ULL,
		0xC2FECBA385336427ULL,
		0x9C466C7B79A8E4F7ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA74FBD47726839FULL,
		0xBDB6345120392336ULL,
		0x0470C8A8D3FAC8E3ULL,
		0x85F73B16112C5C73ULL,
		0xEB74CEDC83E1B471ULL,
		0xA5640211EAFA4383ULL,
		0x41ED68C8BB1E3988ULL,
		0x8BE01318F191433CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9566A065F4F43828ULL,
		0xF166841FD2500C19ULL,
		0x5FCA87FE13D0B0CEULL,
		0x959DDF92E7DE93C3ULL,
		0x356E2504D72152F9ULL,
		0xE2AE4B2351AEA454ULL,
		0xFAABC43A10D6893DULL,
		0x3E1C112A7EB15FD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F125BB183D2BBB7ULL,
		0x4CD0B04EF2692F2FULL,
		0x5BBA4F56C02A782DULL,
		0x106AE484F6F2CFB0ULL,
		0xDE1AEBD854C0E688ULL,
		0x47CA4932BB54E7D7ULL,
		0xBB46ACF2ABC8B0B5ULL,
		0xB5FC02328F201CE4ULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7AD6DB3AAF541DCULL,
		0xD8587D4A3EDF4A55ULL,
		0xCEB558C577F78471ULL,
		0xBC17AC518AE2F56BULL,
		0xFAE449132D4D839DULL,
		0x1C9704B40519F4CAULL,
		0x6795D4AACDDAD7C9ULL,
		0xAF503AF1A86BCA79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3466DC8DA85821ULL,
		0x8006D48AFF441948ULL,
		0x3CC7854FC262706CULL,
		0x58E32E00030A28A0ULL,
		0x8DEAAE4BCFA5BF88ULL,
		0x8A985ED67060FF9DULL,
		0xE18D65F86E9BCEFCULL,
		0x0F6DED52F3AED5A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D990B6F275D19FDULL,
		0x585EA9C0C19B531DULL,
		0xF272DD8AB595F41DULL,
		0xE4F4825189E8DDCBULL,
		0x770EE758E2E83C15ULL,
		0x960F5A6275790B57ULL,
		0x8618B152A3411935ULL,
		0xA03DD7A35BC51FDCULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FF7628C2F585E68ULL,
		0xA07468D0CFFD9D25ULL,
		0x06589896ABFEAB05ULL,
		0x19FF98397A90B388ULL,
		0x5DC5176DCB56FE73ULL,
		0xBBDF1674559B542EULL,
		0xC7CEFE9B5257012FULL,
		0x0941328557E79002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD414D01BD39915A4ULL,
		0x999B30E6C60C4455ULL,
		0xFE19A72CA509625DULL,
		0xDE1C2E267CFC99D2ULL,
		0xCB1DCD4A231E7D97ULL,
		0x15D08DD3CA908E0DULL,
		0x59C7A96B05C9F6A5ULL,
		0x8698E331AEF11350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBE3B297FCC14BCCULL,
		0x39EF583609F1D970ULL,
		0xF8413FBA0EF7C958ULL,
		0xC7E3B61F066C2A5AULL,
		0x96D8DA27E84883E4ULL,
		0xAE0F9BA79F0BDA23ULL,
		0x9E0957F0579EF78AULL,
		0x8FD9D1B4F9168352ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD1C87ABAAD18B19ULL,
		0x0ED23DB66FF61635ULL,
		0x3F5B0708647A96DAULL,
		0x92E55D2F984FB178ULL,
		0xE96F982513034471ULL,
		0xE3A6AC19D4404C81ULL,
		0xC191EA2C513BDD6FULL,
		0x067C3F80774B4FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CFAECB2512A3777ULL,
		0x72D932FC59BCD290ULL,
		0x9BCDEFD28DCFA501ULL,
		0xE29F82DC690EF358ULL,
		0xFE07B9CEC329AE3FULL,
		0x688F9D3F7892C5A4ULL,
		0xEF21C73DDF44A905ULL,
		0x639685CF62F2F2B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1E66B19FBFBBC6EULL,
		0x7C0B0F4A364AC4A5ULL,
		0xA496E8DAE9B533DBULL,
		0x707ADFF3F1414220ULL,
		0x176821EBD02AEA4EULL,
		0x8B293126ACD28925ULL,
		0x2EB02D118E7F746AULL,
		0x65EABA4F15B9BD14ULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46A8076ADE8339BFULL,
		0xC331B8014D1FBCE0ULL,
		0xDDACCF616C767F2AULL,
		0xDBEB1D42140C4030ULL,
		0x09C71708E5D3F73EULL,
		0x75104DEAB90EF30AULL,
		0xA6749C90D90F331EULL,
		0x452E31DCF203E890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA2B6EE5D65AC65ULL,
		0xAC913BA6200CE2E3ULL,
		0xCC973B7CCB056AC4ULL,
		0x59F8E3CB52B2B174ULL,
		0x06698B939DB91811ULL,
		0x88E067CC06584068ULL,
		0xA96453839E94770BULL,
		0x8EB143D145A6A692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B0AB18483E695DAULL,
		0x6FA083A76D135E03ULL,
		0x113BF41DA77315EEULL,
		0x8213FE8946BEF144ULL,
		0x0FAE9C9B786AEF2FULL,
		0xFDF02A26BF56B362ULL,
		0x0F10CF13479B4415ULL,
		0xCB9F720DB7A54E02ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56CDD8CDF56D2C39ULL,
		0x6AB2D320E47A359BULL,
		0x267375B386DBF0F2ULL,
		0x6D876E62142BF92DULL,
		0x239B6AB5EBC6E4A6ULL,
		0xC6C95F5E889D94B2ULL,
		0xB973728E1136A884ULL,
		0x37A29DB44D8C1A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0C617F41DC1803ULL,
		0x643A5782FB64420CULL,
		0x5049EBF34C040C57ULL,
		0x30D6357EAE3DC298ULL,
		0xB9157A64C8AA7176ULL,
		0x04BFE775CB5169F6ULL,
		0xB189ED37A305ABFBULL,
		0x619424D37C9103CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDC1B9B2B4B1343AULL,
		0x0E8884A21F1E7797ULL,
		0x763A9E40CADFFCA5ULL,
		0x5D515B1CBA163BB5ULL,
		0x9A8E10D1236C95D0ULL,
		0xC276B82B43CCFD44ULL,
		0x08FA9FB9B233037FULL,
		0x5636B967311D19D7ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAB8BBDDA9AA9832ULL,
		0x5841FCE776285D3EULL,
		0x502962805AF1A4CEULL,
		0x022085039131E12CULL,
		0xC7B3407B56862589ULL,
		0x10498132A5E43302ULL,
		0xE7B9992BCBD06C1FULL,
		0x4A9FDFAB01A358F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD97D5D440060F738ULL,
		0x042BD590E977E935ULL,
		0x3F048A3C95C96672ULL,
		0x58E6FAC1BA9E0522ULL,
		0xBEBD8B7BDCCB681CULL,
		0xE612D7A974606A29ULL,
		0x3C1F5F3676C7D236ULL,
		0xD19E4E2DA46794E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C5E699A9CA6F0AULL,
		0x5C6A29779F5FB40BULL,
		0x6F2DE8BCCF38C2BCULL,
		0x5AC67FC22BAFE40EULL,
		0x790ECB008A4D4D95ULL,
		0xF65B569BD184592BULL,
		0xDBA6C61DBD17BE29ULL,
		0x9B019186A5C4CC17ULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC8395560AB2786CULL,
		0x6151AC5FDF19E846ULL,
		0x418E0A1E3C9174E4ULL,
		0xB1858AC1277B1570ULL,
		0xD721ECE0AC13B75CULL,
		0xBB5E1CBFF16D9F11ULL,
		0x898887B9022219EFULL,
		0xB7DF98E2A4BEC201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F0666CB86B8AAA9ULL,
		0xD7ABB0561AC83D1CULL,
		0xD61E6A44952A311DULL,
		0x6DBFF504B65BCE2DULL,
		0x45940CA6AFB05277ULL,
		0xB6C32B127DE69A91ULL,
		0x20A229473E3872B9ULL,
		0x49618A87DB1868FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC385F39D8C0AD2C5ULL,
		0xB6FA1C09C5D1D55AULL,
		0x9790605AA9BB45F9ULL,
		0xDC3A7FC59120DB5DULL,
		0x92B5E04603A3E52BULL,
		0x0D9D37AD8C8B0580ULL,
		0xA92AAEFE3C1A6B56ULL,
		0xFEBE12657FA6AAFCULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E29E34462C2FC91ULL,
		0x2C9084E8BD90610FULL,
		0x9B72AF9AE65185B9ULL,
		0x28F001A05B805153ULL,
		0x3189CA740928FE12ULL,
		0x29248B5041D7D820ULL,
		0x9BECDD65FEADF51CULL,
		0x885F40FEB979404DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA4AE131EEBD6FCULL,
		0x9847E72575F09000ULL,
		0x63BD8F89751F2D96ULL,
		0x49B0004D8036483CULL,
		0x3BC7035CB1683C13ULL,
		0x477FE8883AEC8DC9ULL,
		0xE254B238749C169CULL,
		0xC03925EF243C9542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x948D4D577C292A6DULL,
		0xB4D763CDC860F10FULL,
		0xF8CF2013934EA82FULL,
		0x614001EDDBB6196FULL,
		0x0A4EC928B840C201ULL,
		0x6E5B63D87B3B55E9ULL,
		0x79B86F5D8A31E380ULL,
		0x486665119D45D50FULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0216B05D58533017ULL,
		0xD111D8B504DAD454ULL,
		0x6439CC83C735EDEFULL,
		0x86A57952DA65DB17ULL,
		0xB344FB55A7033E44ULL,
		0x9471D5531E98FD7DULL,
		0xBD1386D3DFFA088BULL,
		0xBF84ECFA47BAF54BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F65EE6C23BB340CULL,
		0x8B8F801CC062156EULL,
		0xE115B82802EE0ACEULL,
		0x146659B16D4E8F71ULL,
		0xA3D6B473DA5E00ACULL,
		0x0AD56E3CDC677B85ULL,
		0xE2CB7D008DB3C401ULL,
		0xD2FD0966154CF3D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D735E317BE8041BULL,
		0x5A9E58A9C4B8C13AULL,
		0x852C74ABC5DBE721ULL,
		0x92C320E3B72B5466ULL,
		0x10924F267D5D3EE8ULL,
		0x9EA4BB6FC2FF86F8ULL,
		0x5FD8FBD35249CC8AULL,
		0x6D79E59C52F60698ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CC5E584A27114EEULL,
		0xCD6A1ABE0A38DADAULL,
		0x03CDD3E56522BB8BULL,
		0x1E838B4C139E230CULL,
		0x7B5629164B90BBB2ULL,
		0xFFCED9EBF1792139ULL,
		0xC4C05DE72E1D15F8ULL,
		0x65348237E6492A77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1086DF64216281FULL,
		0xF28432F6BA9F444DULL,
		0xB303FDDECDE035D7ULL,
		0x8DE43B6EB8F370D0ULL,
		0x42811E6CEDFE776EULL,
		0xD26BAA00898C126EULL,
		0x974B9D9D3D0D4A39ULL,
		0x13F3782BEF931B43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDCD8872E0673CF1ULL,
		0x3FEE2848B0A79E97ULL,
		0xB0CE2E3BA8C28E5CULL,
		0x9367B022AB6D53DCULL,
		0x39D7377AA66ECCDCULL,
		0x2DA573EB78F53357ULL,
		0x538BC07A13105FC1ULL,
		0x76C7FA1C09DA3134ULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6579C10FDB45CA2ULL,
		0x00FB6C0F2E74E9ECULL,
		0x56E1D70EB3CCD502ULL,
		0xE60829FCDE299DEEULL,
		0x011FAD01B3E22557ULL,
		0xC2F195DF0C6628B1ULL,
		0x3251BD292D73FCCAULL,
		0xC87A71D7578EB460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8380899C89AFB74ULL,
		0x6589FEA06B8B6B5EULL,
		0x79549407F21221F2ULL,
		0x268C27EB7953111FULL,
		0xF35A9BE6AE907213ULL,
		0x4B7209861CFF075FULL,
		0xD31C2132039E0624ULL,
		0xE92591D2415200F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E6F9489352EA7D6ULL,
		0x657292AF45FF82B2ULL,
		0x2FB5430941DEF4F0ULL,
		0xC0840E17A77A8CF1ULL,
		0xF24536E71D725744ULL,
		0x89839C5910992FEEULL,
		0xE14D9C1B2EEDFAEEULL,
		0x215FE00516DCB499ULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44FE6A5F8A325379ULL,
		0xE5BC68899607979EULL,
		0xF3E2FBC95F1650A2ULL,
		0x57623390ADF23039ULL,
		0x5ECECB870CCD1588ULL,
		0x4F347822A2F3C3ECULL,
		0x5DCDD3CA7741B146ULL,
		0x1401841C2B7C5A83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57CE583481FFCB56ULL,
		0x85027E34BE760C56ULL,
		0x6BB2D91D739AB391ULL,
		0x5FA2C11357871929ULL,
		0x6CAFCB91083D41A1ULL,
		0xE34685BD6E40BF7DULL,
		0xD44289B34877FABDULL,
		0x42621C3F98957A59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1330326B0BCD982FULL,
		0x60BE16BD28719BC8ULL,
		0x985022D42C8CE333ULL,
		0x08C0F283FA752910ULL,
		0x3261001604F05429ULL,
		0xAC72FD9FCCB37C91ULL,
		0x898F5A793F364BFBULL,
		0x56639823B3E920DAULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5C4FA571F611E27ULL,
		0xB27497B8B580E954ULL,
		0xCAE54CC1237CEF7BULL,
		0xF2AB866D86663713ULL,
		0x964D60815A1C49A1ULL,
		0x9CA8BB86F874547AULL,
		0x8D4F2A771037407AULL,
		0x1F452B13B8823279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91C95FCCBBD4824ULL,
		0x87EB2EF49B8C9A23ULL,
		0x652F578E3E820372ULL,
		0x6B684059542EDC15ULL,
		0x21145F96D38A9037ULL,
		0xB3C2E970E277EC0DULL,
		0x9E31477DF5DBAE14ULL,
		0x3595B02D72D4E0FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CD86FABD4DC5603ULL,
		0x359FB94C2E0C7377ULL,
		0xAFCA1B4F1DFEEC09ULL,
		0x99C3C634D248EB06ULL,
		0xB7593F178996D996ULL,
		0x2F6A52F61A03B877ULL,
		0x137E6D0AE5ECEE6EULL,
		0x2AD09B3ECA56D284ULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E7AAC893BDCC76BULL,
		0x6DF38A7ECABF6AF2ULL,
		0x5DF5BDD628ED332FULL,
		0x53F3CA12DAE2068EULL,
		0x59A32B24374C0DDCULL,
		0xD41F3E186BA9EB5AULL,
		0x393D158F7BDE2C83ULL,
		0x12B584706D43F85AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE89924D67537FBDEULL,
		0x33BD228F5AF0F39EULL,
		0x2FCBD403CAFDFDC2ULL,
		0x285142274E93B0ABULL,
		0x578B40B551E63491ULL,
		0xC34DED10CA36C634ULL,
		0x05DCBEAD14622B3AULL,
		0x11BF973B375E02B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6E3885F4EEB3CB5ULL,
		0x5E4EA8F1904F996CULL,
		0x723E69D5E210CEEDULL,
		0x7BA288359471B625ULL,
		0x0E286B9166AA394DULL,
		0x1752D308A19F2D6EULL,
		0x3CE1AB226FBC07B9ULL,
		0x030A134B5A1DFAE9ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD6E66B3C4DC3E0AULL,
		0x615EB791F77C9CDBULL,
		0x2EE62C39636A6342ULL,
		0x0F385FF940372B64ULL,
		0xCD6EA4B0F8CAE3E4ULL,
		0xCCFCFF39F3825BF4ULL,
		0x406FC4AB76D2C0DDULL,
		0x5A233ADE9B9424C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02EE453CD16E21EULL,
		0x40C9C9DDE2F59B04ULL,
		0x1C14866540AA0B38ULL,
		0xBB4EAF2FCE15D60EULL,
		0x70DD55882547A5F7ULL,
		0x855C6939463BB354ULL,
		0x91EDDEFB6251B90AULL,
		0x7D61833E64D212A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D4082E009CADC14ULL,
		0x21977E4C158907DFULL,
		0x32F2AA5C23C0687AULL,
		0xB476F0D68E22FD6AULL,
		0xBDB3F138DD8D4613ULL,
		0x49A09600B5B9E8A0ULL,
		0xD1821A50148379D7ULL,
		0x2742B9E0FF463665ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81739D60423F1C99ULL,
		0xA06712C6C28DC84FULL,
		0xA41007B09B10C530ULL,
		0x2547F0D578D3F0F1ULL,
		0xD46874FF6246F952ULL,
		0x945D4BF836DA109CULL,
		0x901BA20A7D2E9004ULL,
		0x887F6B48B6446938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8067307C3B429863ULL,
		0xC64472CA12F7B1B4ULL,
		0xF4E10457C58FDEE0ULL,
		0xE4BF20CFED1D53DDULL,
		0xFB028F8E1C40727EULL,
		0x045E93D7A7EFC81CULL,
		0x461D1B5A104DAE8BULL,
		0xFA03CF3C893539E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0114AD1C797D84FAULL,
		0x6623600CD07A79FBULL,
		0x50F103E75E9F1BD0ULL,
		0xC1F8D01A95CEA32CULL,
		0x2F6AFB717E068B2CULL,
		0x9003D82F9135D880ULL,
		0xD606B9506D633E8FULL,
		0x727CA4743F7150DDULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1D1299708BDF373ULL,
		0xBFAB11E04D59AF22ULL,
		0xBE3224A396363AABULL,
		0xE2729866FFD93ABCULL,
		0xD9026F9ECC679E70ULL,
		0xAC896DE61EA07059ULL,
		0x342E01B6A12D974EULL,
		0x0EE9F0E0B679AB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x268609DD1E8B0600ULL,
		0x4EFAE76AA0218EA3ULL,
		0xB1E8E33AAB775DDCULL,
		0xEBF0870002AC40E4ULL,
		0x17392A9B9E93E4B6ULL,
		0xE2A35706C7B50E40ULL,
		0x3FE1F9255B8BD3BDULL,
		0xACD73F0A04876320ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC757204A1636F573ULL,
		0xF151F68AED782181ULL,
		0x0FDAC7993D416777ULL,
		0x09821F66FD757A58ULL,
		0xCE3B450552F47AC6ULL,
		0x4E2A3AE0D9157E19ULL,
		0x0BCFF893FAA644F3ULL,
		0xA23ECFEAB2FEC876ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0D18F2E0C7D605FULL,
		0xABDAD4B6942DC75AULL,
		0x35773CD6BF49DAB8ULL,
		0xD8D6C2CBB6D63697ULL,
		0xDBD4727FAC1448BBULL,
		0xC012A397B191FAC5ULL,
		0x1AEADC5CF8DA99B5ULL,
		0x37FBF59DF1FA58F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69477ADBE9E2CF06ULL,
		0xA6547023A23E1E98ULL,
		0xBB58857732FA507DULL,
		0x00376F9D113BECADULL,
		0x173D84930F7D4105ULL,
		0xBCC977F652087942ULL,
		0xE319A570949E09BBULL,
		0x998EDD82C343B576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA996F5F5E59FAF59ULL,
		0x0D8EA4953613D9C2ULL,
		0x8E2FB9A18DB38AC5ULL,
		0xD8E1AD56A7EDDA3AULL,
		0xCCE9F6ECA36909BEULL,
		0x7CDBD461E3998387ULL,
		0xF9F3792C6C44900EULL,
		0xAE75281F32B9ED81ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B7167816D7AF5DDULL,
		0xF3E0DC5FB80A6DBDULL,
		0x2BB986352F016D2DULL,
		0xEE045CC94D0C6587ULL,
		0x393C7684A2223471ULL,
		0xD9522EA0021FD25CULL,
		0x1141DF91B3CA43E4ULL,
		0xBAA20DDC26F4819BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFF167752B4A0FC6ULL,
		0x18326322D7C2213BULL,
		0x1D61D1C61A6E97CFULL,
		0x8FFD93C5E4BC06E7ULL,
		0x34EA856511289DFBULL,
		0x83F4CC7D3C1A9C59ULL,
		0x58018C08542F7528ULL,
		0x41189F2C428ECD3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC48000F44630FA1BULL,
		0xEBD2BF7D6FC84C86ULL,
		0x36D857F3356FFAE2ULL,
		0x61F9CF0CA9B06360ULL,
		0x0DD6F3E1B30AA98AULL,
		0x5AA6E2DD3E054E05ULL,
		0x49405399E7E536CCULL,
		0xFBBA92F0647A4CA4ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB966F9F94C34344ULL,
		0xF37AA6F5683A5B0AULL,
		0x58C08A1EB517662CULL,
		0xCE7FDEAAC232BEDAULL,
		0x1CDBB12A3B12841AULL,
		0x23D5515755C3233AULL,
		0x9B39F193A49EB57DULL,
		0x19D85AB8EA127577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E05C1A90E8DBEABULL,
		0xA94A28169F767BB1ULL,
		0x98BE708FE3C3A7B6ULL,
		0x5DE03B04B245B735ULL,
		0xC534B6DC203D159FULL,
		0xD0253A0AD687AAAAULL,
		0x72AA00CBEFB5FB59ULL,
		0x8345FED6D07B904CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA593AE369A4EFDEFULL,
		0x5A308EE3F74C20BBULL,
		0xC07EFA9156D4C19AULL,
		0x939FE5AE707709EFULL,
		0xD9EF07F61B2F9185ULL,
		0xF3F06B5D83448990ULL,
		0xE993F1584B2B4E24ULL,
		0x9A9DA46E3A69E53BULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9CD007E7B2D6652ULL,
		0x8240F4767B46D91CULL,
		0x30678DBC19F675D5ULL,
		0x4505D6259F0C26DDULL,
		0xE054EDE8D22161B2ULL,
		0xBFFD91DDB93E07D0ULL,
		0x5B1A1718708C1E2BULL,
		0x9D1F526C8CBBDF35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17CF9F1B0D72A44ULL,
		0x4A14C86B64297DB8ULL,
		0x330C233E1E9F15D7ULL,
		0x430A4525A7A1D92BULL,
		0xDFCE645829B385DAULL,
		0x9E39E13B395CDAE5ULL,
		0xF79E822AD9DE5C94ULL,
		0x9FE6C9FAB957ABF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48B1F98FCBFA4C16ULL,
		0xC8543C1D1F6FA4A4ULL,
		0x036BAE8207696002ULL,
		0x060F930038ADFFF6ULL,
		0x3F9A89B0FB92E468ULL,
		0x21C470E68062DD35ULL,
		0xAC849532A95242BFULL,
		0x02F99B9635EC74C0ULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49A2872E51A39CBDULL,
		0x661FD6F5B75DC08AULL,
		0x3B94209E5038A933ULL,
		0x8571346C02ED3EA4ULL,
		0xC7E289CC18EC4A74ULL,
		0x76E4BB0DC69B2002ULL,
		0x5A5E01BC98632AFEULL,
		0xB224BD3F8FE58B74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF428E5C8BFA9B38ULL,
		0xAE271979C6800277ULL,
		0x902234C4BDEB9B84ULL,
		0x4D9FA46DCB4BE73FULL,
		0xD903AB43C4D1A9A2ULL,
		0xB8780E68AB9E082AULL,
		0xCF9DF14CB0B84DFCULL,
		0x9BCE2EFAE3AA9F02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6E00972DA590785ULL,
		0xC838CF8C71DDC2FDULL,
		0xABB6145AEDD332B7ULL,
		0xC8EE9001C9A6D99BULL,
		0x1EE1228FDC3DE3D6ULL,
		0xCE9CB5656D052828ULL,
		0x95C3F0F028DB6702ULL,
		0x29EA93C56C4F1476ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x025174BED7840CEEULL,
		0xE1A33E8E16471E52ULL,
		0x0BECEA5AD620D12DULL,
		0x9D1CC3C0D4D6EE17ULL,
		0xA310CBC16D751247ULL,
		0x3B644039F1A54363ULL,
		0x0F596B79DA70410AULL,
		0x14B028ACFEE3820BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2973B5615E86D5FULL,
		0x80B4A9454B7B5BE6ULL,
		0x51223A51495CABFEULL,
		0xFF9427C37F90702AULL,
		0x88385470CE96FC36ULL,
		0x22CD5F7AE1C9F50CULL,
		0x4A521D7B16098F0AULL,
		0x85D81B707F249882ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0C64FE8C26C61B1ULL,
		0x611797CB5D3C45B4ULL,
		0x5ACED00B9F7C7AD3ULL,
		0x6288E403AB469E3DULL,
		0x2B289FB1A3E3EE71ULL,
		0x19A91F43106CB66FULL,
		0x450B7602CC79CE00ULL,
		0x916833DC81C71A89ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD396196CD1F0ED9ULL,
		0x7F3C63D104A48D1DULL,
		0x690B55930804A38EULL,
		0xF8BDC37615D5D9ACULL,
		0xC79869D3D5AB0E48ULL,
		0x39DB77819E2FD88BULL,
		0x0EB773610249C468ULL,
		0x5A4CACEE404B0EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03EF8131B4379A8FULL,
		0x0BC06FB9DF3BC152ULL,
		0x35DF7C0F83EB6218ULL,
		0x28E4F29ABD66D485ULL,
		0x5DEF893E4A768D7DULL,
		0x79154E3AE228DE49ULL,
		0x34AABFF3ACF14BC9ULL,
		0xA16AF43F30D73EB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDED6E0A779289456ULL,
		0x74FC0C68DB9F4C4FULL,
		0x5CD4299C8BEFC196ULL,
		0xD05931ECA8B30D29ULL,
		0x9A77E0ED9FDD8335ULL,
		0x40CE39BB7C0706C2ULL,
		0x3A1DCC92AEB88FA1ULL,
		0xFB2658D1709C3054ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD02626BE2D557FFULL,
		0xB8A7C20B5C690563ULL,
		0xFF544CCF1FEF1F51ULL,
		0xE681B864BEFC68D3ULL,
		0x3224F2BA0662670AULL,
		0x1DFAE9DD8E7D30CCULL,
		0x57A375BCC5A23541ULL,
		0x6FA3F147AAAF8AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x725CA00D7B5D2D01ULL,
		0xA869CF948E843379ULL,
		0x509E988076AC33ADULL,
		0x11394899D20C6F30ULL,
		0xA20824D5307C5AB5ULL,
		0x76E768D642A420E0ULL,
		0x68B00A2832E04CC6ULL,
		0x8601EBC554A23F23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF5EC26699887AFEULL,
		0x10CE0D9FD2ED361AULL,
		0xAFCAD44F69432CFCULL,
		0xF7B8F0FD6CF007E3ULL,
		0x902CD66F361E3DBFULL,
		0x6B1D810BCCD9102CULL,
		0x3F137F94F7427987ULL,
		0xE9A21A82FE0DB5C0ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1D7D92E1C769EAFULL,
		0xFB19E48C62C0F8D5ULL,
		0xE179FA2A88F650DEULL,
		0xA7B7A917308273B2ULL,
		0x993007505B6DA823ULL,
		0xE992809E87AE18F5ULL,
		0xF7A36C8D0C202AD2ULL,
		0xB5394F389ED0C7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C720CFA7FE50883ULL,
		0x5628DD7E5172CDEDULL,
		0x7C1B7953C2A15C5FULL,
		0xBE5EB1A6217F4368ULL,
		0x14FD6E9B7C54B856ULL,
		0xBDEAC3B87A4D7AD4ULL,
		0xED29414B8162AE2AULL,
		0x34004960E7AE6AA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA5D5D46393962CULL,
		0xAD3139F233B23538ULL,
		0x9D6283794A570C81ULL,
		0x19E918B111FD30DAULL,
		0x8DCD69CB27391075ULL,
		0x54784326FDE36221ULL,
		0x1A8A2DC68D4284F8ULL,
		0x81390658797EAD0DULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F065B432B52E0D9ULL,
		0xAE1CA751E7C7CC0CULL,
		0xB65404C5C2F4DBAFULL,
		0xF426DB24904F71CDULL,
		0x965991343AF719FBULL,
		0x9D49FED713EE421FULL,
		0x68012F9791CC2E51ULL,
		0x5B57D0DF8F22A3C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A985AA0E1FBE98DULL,
		0x1B0199D7738B76CAULL,
		0x96C216C5EE57E89EULL,
		0x8FF603DEE1928FA7ULL,
		0x269E96209407952AULL,
		0xE3A318AA91D9F98FULL,
		0xFDE2E6F30D1A49D1ULL,
		0xF2AE9075FE254DF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB59E01E3CAA90954ULL,
		0xB51D3E86944CBAC6ULL,
		0x209612002CA33331ULL,
		0x7BD0D8FA71DDFE6AULL,
		0xB0C70714AEF08CD1ULL,
		0x7EEAE67D8237BB90ULL,
		0x95E3C9649CD66780ULL,
		0xA9F940AA7107EE32ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6A48A452EAE6D17ULL,
		0x9606D1301444A3C5ULL,
		0xE7D3E661637AB4E0ULL,
		0x18524DD85C1F37F8ULL,
		0xC781F88E4A275CBAULL,
		0x2596C00B3ECA94F4ULL,
		0xE2136E7D967DBC74ULL,
		0x0075B1D425C965E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EB11CCFF41A85FDULL,
		0x79A82BC3CE1E79DDULL,
		0x4ACF340FA67957B6ULL,
		0x81380DB53CAFB031ULL,
		0xD02C782C99AF0354ULL,
		0x8D461B54CA5BAE96ULL,
		0x5618BA26041F16EEULL,
		0x5FF9DBEC8D0835F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC815968ADAB4E8EAULL,
		0xEFAEFAF3DA5ADA18ULL,
		0xAD1CD26EC503E356ULL,
		0x996A406D60B087C9ULL,
		0x17AD80A2D3885FEEULL,
		0xA8D0DB5FF4913A62ULL,
		0xB40BD45B9262AA9AULL,
		0x5F8C6A38A8C15013ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933C3B1D2BA6DDF7ULL,
		0x34DC68D108E42085ULL,
		0x688D60A60D86BA18ULL,
		0xA1CBA29283113CABULL,
		0x01EE68639233B07DULL,
		0x53030730DD29947EULL,
		0x113D4EAB046B7777ULL,
		0xDE15B9DA3CB46335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F590F38BE2BC8BBULL,
		0x2DABF30D0BB52BE0ULL,
		0x7FAF6709674EC11DULL,
		0x01D360E8BFF5E27BULL,
		0x363BFA59F4FEB39BULL,
		0x1A802CC90453145BULL,
		0x080C2535AC1495ADULL,
		0x8C457A0E5B13F2C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC653425958D154CULL,
		0x19779BDC03510B65ULL,
		0x172207AF6AC87B05ULL,
		0xA018C27A3CE4DED0ULL,
		0x37D5923A66CD03E6ULL,
		0x49832BF9D97A8025ULL,
		0x19316B9EA87FE2DAULL,
		0x5250C3D467A791F3ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF0715DC47AB49D2ULL,
		0x4C8AF5F32CD331D6ULL,
		0x680A42FEEE2DE2AEULL,
		0x5ECE2417C991C800ULL,
		0xE69E0E8AB29F7260ULL,
		0x8DA7D44ECC60E91BULL,
		0x5885F0B882D1FB1FULL,
		0x44D30685276AEC91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68FDEAF4AB6C04BFULL,
		0xB8106699E1DC5AE6ULL,
		0x9BDB76B5A9AAE942ULL,
		0xF64EC92DBEF5B36AULL,
		0x288ECD704DD16F07ULL,
		0x24EA58E2A8949872ULL,
		0xF1C6E10E44822789ULL,
		0x312D63A347DFE2D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97FAFF28ECC74D6DULL,
		0xF49A936ACD0F6B30ULL,
		0xF3D1344B47870BECULL,
		0xA880ED3A77647B6AULL,
		0xCE10C3FAFF4E1D67ULL,
		0xA94D8CAC64F47169ULL,
		0xA94311B6C653DC96ULL,
		0x75FE652660B50E42ULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DD380A80FBEC1C2ULL,
		0x6546A2BDAFCB47DCULL,
		0xBE48818ABFFD288EULL,
		0x82A4357495EF8B08ULL,
		0x38BD9F8F109D8127ULL,
		0x0F842B62E1CA9C06ULL,
		0x05B02A3313330B43ULL,
		0xA5E58839CC980E95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792A293FCE5A26EAULL,
		0x1EE23F007964201EULL,
		0x08CE5D049EBAA9BCULL,
		0xFB762EEB0F6EB8FFULL,
		0xCFA1699C1E0F15E1ULL,
		0x041EB865D29A757BULL,
		0x03140E611F82A2F0ULL,
		0xBB3B06A69030F1FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64F9A997C1E4E728ULL,
		0x7BA49DBDD6AF67C2ULL,
		0xB686DC8E21478132ULL,
		0x79D21B9F9A8133F7ULL,
		0xF71CF6130E9294C6ULL,
		0x0B9A93073350E97DULL,
		0x06A424520CB1A9B3ULL,
		0x1EDE8E9F5CA8FF68ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1938A8865BEDC95ULL,
		0xB8EF6B0AA2EB532CULL,
		0xEE189F9BB0475882ULL,
		0x410715F558A28DB7ULL,
		0xF44AE401B7584F58ULL,
		0x02446F1AA681AFD2ULL,
		0x27BF7CCB15CFADD1ULL,
		0xA07DFD097F20FEF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA052E746D2AFA3A5ULL,
		0x97EA0CFEF4353639ULL,
		0x4F4728CC50300BAAULL,
		0x576E8887FE60C3FCULL,
		0x92E2A6B1C47B8EF9ULL,
		0x1F3D1BD74D7638DCULL,
		0x127B0EBB902CE5CEULL,
		0x28D332A6C7A8372DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11C16DCEB7117F30ULL,
		0x2F0567F456DE6515ULL,
		0xA15FB757E0775328ULL,
		0x16699D72A6C24E4BULL,
		0x66A842B07323C1A1ULL,
		0x1D7974CDEBF7970EULL,
		0x35C4727085E3481FULL,
		0x88AECFAFB888C9D5ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D764736F67A3287ULL,
		0x9CC98C69F737318FULL,
		0xC3BF24CCA764ABE9ULL,
		0xB1BE19A65FDFE03CULL,
		0xD43584D75887AB7CULL,
		0x21F7F2FD4ED6918FULL,
		0xBDFE7845161C88A3ULL,
		0xDE5ECACAEEE5DAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24007076BBFE9A98ULL,
		0xD594FB958BBF1DD1ULL,
		0x5C590E7549CAC801ULL,
		0x8F5E6EE79D85EC2BULL,
		0x06300B2A4CD66F8FULL,
		0x6EA96D9AF18E421DULL,
		0x1F8B07E974598B52ULL,
		0xF02545F2EEB50241ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x297637404D84A81FULL,
		0x495D77FC7C882C5EULL,
		0x9FE62AB9EEAE63E8ULL,
		0x3EE07741C25A0C17ULL,
		0xD2058FFD1451C4F3ULL,
		0x4F5E9F67BF58D392ULL,
		0xA2757FAC624503F1ULL,
		0x2E7B8F380050D8EFULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E31AB9E005BC96FULL,
		0x5B94B35F934B3ACBULL,
		0xD7E0A50B7575D267ULL,
		0x28B7C94B05EDD03DULL,
		0x3BC82D3019C32502ULL,
		0x6B041216A9DA727AULL,
		0x34C21566C97E78D9ULL,
		0x3A22BB3DFA3B7BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3122488E5783A1CAULL,
		0x107F596973BC29CFULL,
		0xB202A35CD05B17D0ULL,
		0x936A39F3CDD2AFB8ULL,
		0xE6C6F8F8242AFC03ULL,
		0xF9534DC2EFF37C5CULL,
		0xE19C198717255C16ULL,
		0x2DE288CB33EA7A5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F13E31057D868A5ULL,
		0x4BEBEA36E0F71304ULL,
		0x65E20657A52EC5B7ULL,
		0xBBDDF0B8C83F7F85ULL,
		0xDD0ED5C83DE9D901ULL,
		0x92575FD446290E26ULL,
		0xD55E0CE1DE5B24CFULL,
		0x17C033F6C9D101FBULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9CC0CD80B49A775ULL,
		0x53AAEE16689103CDULL,
		0x5B160214F78E9ABFULL,
		0x419596C12534C002ULL,
		0xD441254B28CA3CB8ULL,
		0x545AEE6AD7AF4390ULL,
		0x2B0CD10F69EADB1DULL,
		0x4932DD6506451F4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0384A9055C05D266ULL,
		0x6700788811A93D0CULL,
		0x67E4B581158E245AULL,
		0x5C1D9C47EF1746E7ULL,
		0x9508DC4D665593D2ULL,
		0x0CCB106A9A65A5D5ULL,
		0x79DE7D2A1F8889C3ULL,
		0x65E59C405B212AEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA48A5DD574C7513ULL,
		0x34AA969E79383EC1ULL,
		0x3CF2B795E200BEE5ULL,
		0x1D880A86CA2386E5ULL,
		0x4149F9064E9FAF6AULL,
		0x5891FE004DCAE645ULL,
		0x52D2AC25766252DEULL,
		0x2CD741255D6435A3ULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ECBB3C74FB20D3EULL,
		0x9924931FD69FACD8ULL,
		0x3704BFB0E380170CULL,
		0x9868291DB831BF1AULL,
		0x9FA047FDB2ED5F19ULL,
		0x2D9CBB936E7CE81FULL,
		0xE8897CC281580D29ULL,
		0xF208E7417F184CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F37ACEFB72A6256ULL,
		0x2B6C7EB0B79DE974ULL,
		0xB586030096934D1DULL,
		0xCC5890655D4683CBULL,
		0x92918E9A3FC12E7DULL,
		0x885B1270E7291E7DULL,
		0x5077F236011429C5ULL,
		0x293689FD44174308ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71FC1F28F8986F68ULL,
		0xB248EDAF610245ACULL,
		0x8282BCB075135A11ULL,
		0x5430B978E5773CD1ULL,
		0x0D31C9678D2C7164ULL,
		0xA5C7A9E38955F662ULL,
		0xB8FE8EF4804C24ECULL,
		0xDB3E6EBC3B0F0FA9ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90431B8797CA1FFAULL,
		0xBD90AC9CFDBD291AULL,
		0x8953DC180CC11E8DULL,
		0xD79849CA61FA0818ULL,
		0xEDFFC2C482899AB4ULL,
		0x5C200BE94174FDAEULL,
		0xED34A547D6E439F3ULL,
		0x1960E91A091152BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2C7C5DB848B5CB6ULL,
		0x292F5353948C5DB2ULL,
		0x8E75041D2639F409ULL,
		0xAD5A616842B61FCFULL,
		0x622D674CE2596A10ULL,
		0xE5E38343628BE115ULL,
		0x3546584B04AF47C2ULL,
		0x6D11DF9BC66A71FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5284DE5C1341434CULL,
		0x94BFFFCF693174A8ULL,
		0x0726D8052AF8EA84ULL,
		0x7AC228A2234C17D7ULL,
		0x8FD2A58860D0F0A4ULL,
		0xB9C388AA23FF1CBBULL,
		0xD872FD0CD24B7E31ULL,
		0x74713681CF7B2346ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE782214619854BDBULL,
		0x8B39DE42EAF7C147ULL,
		0xDC1B62D0ED75A111ULL,
		0x20279A954FF37BD8ULL,
		0xDBC9DE619DF31CCAULL,
		0xC36D8695BF7C7229ULL,
		0xA2B2278BB86E1CE0ULL,
		0x3A5C76991F46DFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3607D744C902EDCULL,
		0x5AEBA9F078D313AEULL,
		0xA454C879CA270218ULL,
		0xEF9A72815DF04C60ULL,
		0x04B547A4EFB59D36ULL,
		0x2A3D6AE662F7ECB8ULL,
		0x978329AEFC13D8D0ULL,
		0xC03D07DCF9CACBAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54E25C3255156507ULL,
		0xD1D277B29224D2E9ULL,
		0x784FAAA92752A309ULL,
		0xCFBDE814120337B8ULL,
		0xDF7C99C5724681FCULL,
		0xE950EC73DD8B9E91ULL,
		0x35310E25447DC430ULL,
		0xFA617145E68C1401ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EA639B426DEA917ULL,
		0x2DBB06774CF34043ULL,
		0x218F1C11EE6653BAULL,
		0x3342AD9299E2629DULL,
		0x97C557485605153AULL,
		0xBE100092E268BE27ULL,
		0xA441A4AC64FFD861ULL,
		0x21ACDBBA703DB9F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA48FDB46A018B1ULL,
		0x33AE461171A579E3ULL,
		0x645495C3D851BED1ULL,
		0xD76E5A9220ED6FACULL,
		0x79DEBCFF6410295EULL,
		0x234538D24C719F58ULL,
		0x6B1E9F369EC4EE1FULL,
		0x04DF8B3FB12DFAFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB302B66F607EB1A6ULL,
		0x1E1540663D5639A0ULL,
		0x45DB89D23637ED6BULL,
		0xE42CF700B90F0D31ULL,
		0xEE1BEBB732153C64ULL,
		0x9D553840AE19217FULL,
		0xCF5F3B9AFA3B367EULL,
		0x25735085C1104305ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC58000910F41E2E1ULL,
		0xF870AF26DC68CAE3ULL,
		0x309971FFFC16AD77ULL,
		0x414478A9A63689E8ULL,
		0xD3666C5712211723ULL,
		0x90C7817F5DF68575ULL,
		0x8890B3FE66FA9E14ULL,
		0x5A2BF6EB5CA1F622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514812AA229C3492ULL,
		0x0FA5E65A433FBE61ULL,
		0xE47C432EE5251CE4ULL,
		0x178E398DCC2F4749ULL,
		0x46625E94ACF1D0A8ULL,
		0x72986118CECAA913ULL,
		0xED3D9FFC2CDFA1B7ULL,
		0x31A62555A4715830ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94C8123B2DDDD673ULL,
		0xF7D5497C9F577482ULL,
		0xD4E532D11933B193ULL,
		0x56CA41246A19CEA1ULL,
		0x950432C3BED0C78BULL,
		0xE25FE067933C2C66ULL,
		0x65AD2C024A253FA3ULL,
		0x6B8DD3BEF8D0AE12ULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC5A596A357C0E03ULL,
		0x46984DE79C640A15ULL,
		0x02C3F6084E0F3066ULL,
		0xD47B507F14E0D3B1ULL,
		0x880FB59C746839B5ULL,
		0xA1D626B6A5B60411ULL,
		0x96E9D766CB13CAE9ULL,
		0x44BF5FCA128A8EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA253D01BEFA2CCBULL,
		0x13A0831C0D44D894ULL,
		0x530A4E646DBE7454ULL,
		0x69F9FB165A545832ULL,
		0xE6B991F94A54CC53ULL,
		0x197F99EC25056A32ULL,
		0xA10ABAE47D39BD52ULL,
		0x4D94B290298389E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x167F646B8B8622C8ULL,
		0x5538CEFB9120D281ULL,
		0x51C9B86C23B14432ULL,
		0xBD82AB694EB48B83ULL,
		0x6EB624653E3CF5E6ULL,
		0xB8A9BF5A80B36E23ULL,
		0x37E36D82B62A77BBULL,
		0x092BED5A3B090719ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24CF33B857A405CFULL,
		0xD4697742D7D2C676ULL,
		0x8C325C1A74FBCBBAULL,
		0xEE2EA05559857798ULL,
		0xA65AE0FF506DAE8BULL,
		0xEA659D33717B4208ULL,
		0xAD75A39B73D7E53BULL,
		0x2973B67CB0B0265DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2784CA1DD9EB8A6AULL,
		0xF90C80361D8DA7F0ULL,
		0xDF302BBB9E60F26CULL,
		0x147AE42A22D71A7EULL,
		0xD20863ECB0D245C7ULL,
		0xF708E9CEA11A693FULL,
		0x0ADA13E38EDF672FULL,
		0x66E05F82FBA15B70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x034BF9A58E4F8FA5ULL,
		0x2D65F774CA5F6186ULL,
		0x530277A1EA9B39D6ULL,
		0xFA54447F7B526DE6ULL,
		0x74528313E0BFEB4CULL,
		0x1D6D74FDD0612B37ULL,
		0xA7AFB078FD088214ULL,
		0x4F93E9FE4B117D2DULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C02D3BB52E47994ULL,
		0x04160B43F40A71C6ULL,
		0x093CDD571CC49808ULL,
		0xD88AEF8E1C3A6282ULL,
		0xA2AA028366458D5FULL,
		0x6BFB8C180FA92200ULL,
		0xC301256C90621A3AULL,
		0x5820C038B63B81F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83F2EDC8B7AE212EULL,
		0x0F695D41EC560E10ULL,
		0x646127A7E89BB3E5ULL,
		0xA91342A5E41CC780ULL,
		0x1074FA4EC34D1FE8ULL,
		0x65A9E61AA54A6B1AULL,
		0xCAEA86B4E9F4CC6CULL,
		0x9E4060180ADD87E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FF03E73E54A58BAULL,
		0x0B7F5602185C7FD6ULL,
		0x6D5DFAF0F45F2BEDULL,
		0x7199AD2BF826A502ULL,
		0xB2DEF8CDA50892B7ULL,
		0x0E526A02AAE3491AULL,
		0x09EBA3D87996D656ULL,
		0xC660A020BCE6061FULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A987FAC3F585998ULL,
		0x8ADF814EF6432D8DULL,
		0x6C16D0D7D0A73A4BULL,
		0x7BFFE1FBF1B0CB05ULL,
		0x16BE76688588F405ULL,
		0xFE5BFDF3CFC80F68ULL,
		0x96AF7118202EBC9CULL,
		0x82DCCBD879A980B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E39EA0A0D77D102ULL,
		0x7219108EA156ECCFULL,
		0x9974F133EBA667C7ULL,
		0xFBECD4B5DCE90A89ULL,
		0xFEDCCDBC8D015719ULL,
		0x798FB3F8FE7D0A30ULL,
		0x317C35CCDF69ED37ULL,
		0x1E74AD1FA27EBB7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4A195A6322F889AULL,
		0xF8C691C05715C142ULL,
		0xF56221E43B015D8CULL,
		0x8013354E2D59C18CULL,
		0xE862BBD40889A31CULL,
		0x87D44E0B31B50558ULL,
		0xA7D344D4FF4751ABULL,
		0x9CA866C7DBD73BCAULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA38381A5F9A1C4F6ULL,
		0x12078AF1426C4703ULL,
		0x991069EEA599AB1AULL,
		0x232B9153304D967DULL,
		0x122E91820040662DULL,
		0x3741DE907B954F0EULL,
		0x59FF7E4C2D90EAF5ULL,
		0xEA1CFD6C994E447FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C079A0934BD8665ULL,
		0x278CC0E3653D49ADULL,
		0x0D74558EF37E4400ULL,
		0x581010A0EB73AC22ULL,
		0x4F77C48743C1A412ULL,
		0xDBDBF0404D8D3BF9ULL,
		0x5834434D397A4C6CULL,
		0x0332E56CA6FCE56DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F841BACCD1C4293ULL,
		0x358B4A1227510EAEULL,
		0x94643C6056E7EF1AULL,
		0x7B3B81F3DB3E3A5FULL,
		0x5D5955054381C23FULL,
		0xEC9A2ED0361874F7ULL,
		0x01CB3D0114EAA699ULL,
		0xE92E18003FB2A112ULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22EDDDFB6F4B6DEFULL,
		0x7C66C14BE02656A0ULL,
		0xC0147E68DAB97F90ULL,
		0x2134430F18B5BD25ULL,
		0x2385CFE7694D07BAULL,
		0x0F5A58D4C4E203D2ULL,
		0xE96FC5C3F85BD1EFULL,
		0x076A418B3A001BA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD4F5F525209A35ULL,
		0xCDA40B79EAFD9A85ULL,
		0xC76F8B3E9088E438ULL,
		0x407C97B06983DF85ULL,
		0x34BB70CB2120764FULL,
		0x7CBC22E428D9C8FDULL,
		0x34C6357A71BB61EDULL,
		0xAC7A83C030890AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA939280E4A6BF7DAULL,
		0xB1C2CA320ADBCC25ULL,
		0x077BF5564A319BA8ULL,
		0x6148D4BF713662A0ULL,
		0x173EBF2C486D71F5ULL,
		0x73E67A30EC3BCB2FULL,
		0xDDA9F0B989E0B002ULL,
		0xAB10C24B0A89114BULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EEDA5506A0BB6F0ULL,
		0x5A8A7ED6E8281A49ULL,
		0xDE69C142787C4B14ULL,
		0x847A96F0E45B90FDULL,
		0x12CC166AAD828DF3ULL,
		0xEBCCDC9A7455F54CULL,
		0x70B12A9B5B4D6258ULL,
		0xC1977CD8BC47E9B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1196830556D9A29AULL,
		0x09C665DBDEB4A1D4ULL,
		0x3FD52CE4573EB9BDULL,
		0x54F0BB4885B84572ULL,
		0x6EA173C90350129BULL,
		0x0C856C808421F518ULL,
		0xFBD7E3D4B8DFD607ULL,
		0x38833154EA351ADEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F7B26553CD2146AULL,
		0x534C1B0D369CBB9DULL,
		0xE1BCEDA62F42F2A9ULL,
		0xD08A2DB861E3D58FULL,
		0x7C6D65A3AED29F68ULL,
		0xE749B01AF0740054ULL,
		0x8B66C94FE392B45FULL,
		0xF9144D8C5672F36EULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60378DC50F37520FULL,
		0x285ABE5EF25A473EULL,
		0x134267988388ECC0ULL,
		0x569A1C554AF5D188ULL,
		0xE46721907A9EE7CCULL,
		0x0CCFF42872DC91DDULL,
		0x771637A1DE199FC9ULL,
		0xEE35EDAF8B54CE9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDECD81B2A109A1F7ULL,
		0x5B8F356A6FB01E7AULL,
		0x84974D17BCC755F2ULL,
		0xFA23878B3448A2DFULL,
		0x9EE5F5849E6B4D30ULL,
		0x8FE87F4A8453E0CDULL,
		0x5ED6938322043CA4ULL,
		0x6217F008FD02521CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEFA0C77AE3EF3F8ULL,
		0x73D58B349DEA5944ULL,
		0x97D52A8F3F4FB932ULL,
		0xACB99BDE7EBD7357ULL,
		0x7A82D414E4F5AAFCULL,
		0x83278B62F68F7110ULL,
		0x29C0A422FC1DA36DULL,
		0x8C221DA776569C83ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x054277127FDF36A6ULL,
		0x075F995F48A2762EULL,
		0x82F481351DF2B906ULL,
		0x348060BF8F2DF4DDULL,
		0xA475B383F5F2EC41ULL,
		0x9F75EA192574BFF7ULL,
		0x80028CD78D11B436ULL,
		0xBA03A21BB3979749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99BC5CA61D613FD0ULL,
		0x9CD61EF74BA2C9E0ULL,
		0x16E194505B2EC449ULL,
		0x714BA24C39D2C0D3ULL,
		0xF912B4077879A5F6ULL,
		0x41E0DC9E11D7A25BULL,
		0x1147474D705EBC75ULL,
		0x4B6A5870495AD48BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CFE2BB462BE0976ULL,
		0x9B8987A80300BFCEULL,
		0x9415156546DC7D4FULL,
		0x45CBC2F3B6FF340EULL,
		0x5D6707848D8B49B7ULL,
		0xDE95368734A31DACULL,
		0x9145CB9AFD4F0843ULL,
		0xF169FA6BFACD43C2ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CE49EE0946309A1ULL,
		0xF38178594240A2EDULL,
		0x273F9EA0592F5A11ULL,
		0x47FDD97663FC4566ULL,
		0x7392C0CADA082BBAULL,
		0x1DA480B3315B8916ULL,
		0x39604A69CB39DED1ULL,
		0xB9838D5DD6476C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0538A12275ABDFULL,
		0xD744C6ECF5871AEEULL,
		0x4AC0190584F8BF06ULL,
		0x07FD0ABCF2163DB0ULL,
		0xF8CB5AC6B1B86748ULL,
		0x04A03D5DCC249A20ULL,
		0x80FFE527F0F3A200ULL,
		0x4DCB6794B8E484A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1E1A641B616A27EULL,
		0x24C5BEB5B7C7B803ULL,
		0x6DFF87A5DDD7E517ULL,
		0x4000D3CA91EA78D6ULL,
		0x8B599A0C6BB04CF2ULL,
		0x1904BDEEFD7F1336ULL,
		0xB99FAF4E3BCA7CD1ULL,
		0xF448EAC96EA3E823ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEAB4951E87D3DA2ULL,
		0x0F74C3532118AADBULL,
		0x0B57065A84AFEF33ULL,
		0x9468BAC9DE3644A6ULL,
		0x31488E95AA468430ULL,
		0x64EDDAD4618D361FULL,
		0x29C40053850F7CD6ULL,
		0xC2A24F0B1DD39C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69AC89B3A7684256ULL,
		0xF23F8510B92F0BFCULL,
		0x475F080B3A974926ULL,
		0xEB6377311DB031F7ULL,
		0x87C5C3FBFE2035E6ULL,
		0xF5AB60AB83B4BDA6ULL,
		0x79D91741D692343DULL,
		0xD6DF655DB453FACDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB707C0E24F157FF4ULL,
		0xFD4B46439837A127ULL,
		0x4C080E51BE38A615ULL,
		0x7F0BCDF8C3867551ULL,
		0xB68D4D6E5466B1D6ULL,
		0x9146BA7FE2398BB9ULL,
		0x501D1712539D48EBULL,
		0x147D2A56A98066A1ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6FCBF894AA31812ULL,
		0xE4CAA5FFAE0AD482ULL,
		0xBC6F1FB18720A50AULL,
		0x206F0C54061F9459ULL,
		0xFE5CF079C1D11E9AULL,
		0xA3477F4ED52CF397ULL,
		0xC22073C03017E017ULL,
		0x5CA4403D1441BBD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948004E4158C77A5ULL,
		0x0CBC10346E99A869ULL,
		0x449D3FA97097FAB5ULL,
		0x7E82CC910BF38158ULL,
		0x266B07B0EDAD149CULL,
		0x16736BA56CF61590ULL,
		0x159AB8B7CFC356FEULL,
		0x77743C1C69CC0262ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x527CBB6D5F2F6FB7ULL,
		0xE876B5CBC0937CEBULL,
		0xF8F22018F7B75FBFULL,
		0x5EEDC0C50DEC1501ULL,
		0xD837F7C92C7C0A06ULL,
		0xB53414EBB9DAE607ULL,
		0xD7BACB77FFD4B6E9ULL,
		0x2BD07C217D8DB9B2ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7473D69807F4E0CFULL,
		0x78DFECBAA1F696A5ULL,
		0x2D090587CD04C739ULL,
		0x5DAB99C0D957829FULL,
		0x4F325F32907746A3ULL,
		0xF1DF2EF50E74FFC7ULL,
		0xC683E6BCD10786CBULL,
		0xE847985DEAA954DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA47CCA7586ED39ULL,
		0xBAEC16DBA86B815FULL,
		0xFBE5F2A994FF73CFULL,
		0x9632FDE6E206B8A2ULL,
		0x7DFDF79C78F3C5B8ULL,
		0xEDE394F5910E670EULL,
		0x9E92FB717315788BULL,
		0x939A8BF05F203D99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BD7AA5272720DF6ULL,
		0xC233FA61099D17FAULL,
		0xD6ECF72E59FBB4F6ULL,
		0xCB9964263B513A3DULL,
		0x32CFA8AEE884831BULL,
		0x1C3CBA009F7A98C9ULL,
		0x58111DCDA212FE40ULL,
		0x7BDD13ADB5896945ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x665F4DC81A21F869ULL,
		0x60DF5426089259C1ULL,
		0xBAC5A4DD09738E59ULL,
		0xED56A1D31F32DC25ULL,
		0x210A6A7981A2C654ULL,
		0x35F8878B84364AA8ULL,
		0xF700C6C9ADA58409ULL,
		0x0C3739DCE76E07E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ABAD5F2133D27EDULL,
		0x49BBA3EC28C506F2ULL,
		0x754D9E4DE1B1A124ULL,
		0x4AA3851F808A7893ULL,
		0x803C16A74CA18CD4ULL,
		0x5B441DED1A628852ULL,
		0x0E244DB71224700EULL,
		0x5323A2C25EBE77DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CE5983A091CDF84ULL,
		0x2964F7CA20575F33ULL,
		0xCF883A90E8C22F7DULL,
		0xA7F524CC9FB8A4B6ULL,
		0xA1367CDECD034A80ULL,
		0x6EBC9A669E54C2FAULL,
		0xF9248B7EBF81F407ULL,
		0x5F149B1EB9D07038ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF350FE4CC0EC3D0ULL,
		0x11F3FC2BFA1B6156ULL,
		0x8394781542E3CF4CULL,
		0x124EE91B92E1D019ULL,
		0x8579A784E1AD4664ULL,
		0x34609B2351E4156FULL,
		0x961F1F3EF8056266ULL,
		0x643E8AA98E017A47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E45F4CA15B3C01ULL,
		0x62FAFFFDC7C2E8F9ULL,
		0x97C5AD6CBCE42909ULL,
		0x1AD9AD24DA7FA61CULL,
		0xFA7E88922FDDA7C6ULL,
		0x5207C01DC36F39EBULL,
		0x3B094A21D816AA01ULL,
		0x1D3E71A4A5219D90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6D150A86D55FFD1ULL,
		0x730903D63DD989AFULL,
		0x1451D579FE07E645ULL,
		0x0897443F489E7605ULL,
		0x7F072F16CE70E1A2ULL,
		0x66675B3E928B2C84ULL,
		0xAD16551F2013C867ULL,
		0x7900FB0D2B20E7D7ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA390A3310D38CD20ULL,
		0x86BF65AB31E9E602ULL,
		0x66D5137E5D134E76ULL,
		0x91A49EDC170FB032ULL,
		0x46DC18BA7D4CB30DULL,
		0xC94A97AFDCFB0E5BULL,
		0xEF61D07D82A661E2ULL,
		0xDA76BCEBC4E5046CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ECBC72D65C46FADULL,
		0x392EF55D27486DFCULL,
		0x9F0138325FAE8304ULL,
		0xAB9AF5A69796FE78ULL,
		0xA93ECED1DDC01685ULL,
		0x4E41BEDD78E6635EULL,
		0xE0E4DF22F27D2C10ULL,
		0x99B45DC5EC2AD0CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD5B641C68FCA28DULL,
		0xBF9190F616A18BFEULL,
		0xF9D42B4C02BDCD72ULL,
		0x3A3E6B7A80994E4AULL,
		0xEFE2D66BA08CA588ULL,
		0x870B2972A41D6D05ULL,
		0x0F850F5F70DB4DF2ULL,
		0x43C2E12E28CFD4A1ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7B516712E433FF0ULL,
		0xD4BB73DD12FC73D0ULL,
		0x774625D406EE77A2ULL,
		0x7C6ADB83E7F355DAULL,
		0x01F139B70CCDAF36ULL,
		0xD4EF93371565E944ULL,
		0xE0695023F37A5BB4ULL,
		0x66953FE764716969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6517BF9F524636ULL,
		0xCBE44D9D7414617EULL,
		0x1DE59DE4D3722D1EULL,
		0x1B69BDF06955D06FULL,
		0xEF58BCD1BA72D5A0ULL,
		0x97F4BE2F48B50680ULL,
		0xCC71EA888A492835ULL,
		0x248DF5E314DD04C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DD001CEB11179C6ULL,
		0x1F5F3E4066E812AEULL,
		0x6AA3B830D59C5ABCULL,
		0x670366738EA685B5ULL,
		0xEEA98566B6BF7A96ULL,
		0x431B2D185DD0EFC4ULL,
		0x2C18BAAB79337381ULL,
		0x4218CA0470AC6DACULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CE48AA4A866AED7ULL,
		0xD4C2AE85945CDED4ULL,
		0xABFFE0ECD027B60DULL,
		0xE13931FBC172ADA1ULL,
		0xA0EC8052C93D95C4ULL,
		0xC855CF17EBE9F814ULL,
		0x2EE42B29CCDDF31EULL,
		0xDBF8133BF79F3121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x546F5A7CEB0818AEULL,
		0x240EAB17B0E1B157ULL,
		0x91F0EFB030A70948ULL,
		0xC1F9FB6025E1658FULL,
		0x511EB98B281E738EULL,
		0x1A3D6C87E1B3F2C7ULL,
		0x88EF304B4F658F44ULL,
		0x57D474A0CE6953F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x088BD0D8436EB679ULL,
		0xF0CC059224BD6F83ULL,
		0x3A0F0F5CE080BF45ULL,
		0x20C0CA9BE493C82EULL,
		0xF1F239D9E123E64AULL,
		0xD268A3900A5A0AD3ULL,
		0xA60B1B6283B87C5AULL,
		0x8C2C679B39F662D2ULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE76E74888C09297ULL,
		0xEF88E47AC4E6782EULL,
		0x7996C22740163891ULL,
		0xB464A576D6683BFAULL,
		0x3D0C4DBF0E10426AULL,
		0x0767F729EA95862BULL,
		0x7260C9D67457CC43ULL,
		0x9F93572E328A9E39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A63BEE4D6CC3243ULL,
		0xE4631E67E96FBC1BULL,
		0x44AC1EDFD0652A38ULL,
		0xC8EF15BE87A7EFC7ULL,
		0x4D370CA4005AF616ULL,
		0x7B001A623C978A7AULL,
		0x7BDEA05FE1E8DF74ULL,
		0x569A43F2D5514654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x541559AC5E0CA0D4ULL,
		0x0BEBFA1D2D89C435ULL,
		0x3D3ADCF8907312A9ULL,
		0x7C8BB0C851CFD43DULL,
		0x703B411B0E4AB47CULL,
		0x7C67ED4BD6020C51ULL,
		0x09BE698995BF1337ULL,
		0xC90914DCE7DBD86DULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1180E2A6F602BF2DULL,
		0x4B4F287759F289A4ULL,
		0xD23120F5B4D422A0ULL,
		0x98EC9FC0CA4412E2ULL,
		0xB9B0DFB62AA362EBULL,
		0xF2157E328888FFD7ULL,
		0x4FC2CB75E6E0ABDFULL,
		0xCD2B00277A1480D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD900E946FAC3D80ULL,
		0xA7281120D20988AEULL,
		0x8F9C36EF85419D2FULL,
		0x1D359F63B459DF86ULL,
		0xEFCD25274D275116ULL,
		0x85D92FA48E3BEC45ULL,
		0x14B4368F618C3CEEULL,
		0xD2FD2C0BB990EA92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC10EC3299AE82ADULL,
		0xEC6739578BFB010AULL,
		0x5DAD161A3195BF8FULL,
		0x85D900A37E1DCD64ULL,
		0x567DFA91678433FDULL,
		0x77CC519606B31392ULL,
		0x5B76FDFA876C9731ULL,
		0x1FD62C2CC3846A42ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3913E178B2FC293ULL,
		0x5330B17098C86297ULL,
		0xB3CB59848C317380ULL,
		0x488D158CCF8C020FULL,
		0xC66BF243CCEE58BCULL,
		0x76132FB6C12729D6ULL,
		0x5EF10992DDC1E0D1ULL,
		0x83368E3EE237BFC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2470BE928856CADULL,
		0xBDC9C61295887FD6ULL,
		0x603BF8710BEB6AE4ULL,
		0x7D0EAA0AC57BB8B3ULL,
		0x77E8FFE0B45567B6ULL,
		0x3C1EC8D551C93890ULL,
		0x0F2CB479A0423E12ULL,
		0x2177A6D2165FD8BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11D635FEA3AAAE3EULL,
		0xEEF977620D401D41ULL,
		0xD3F0A1F587DA1964ULL,
		0x3583BF860AF7BABCULL,
		0xB1830DA378BB3F0AULL,
		0x4A0DE76390EE1146ULL,
		0x51DDBDEB7D83DEC3ULL,
		0xA24128ECF4686779ULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D3CA7B3CB7CB556ULL,
		0x7D3BF8676B9ACE96ULL,
		0x1F0714FD5BF2152EULL,
		0xEF748C108FEC337FULL,
		0x837F5DCB11C92EB5ULL,
		0x7666E5DAF8FBB8B0ULL,
		0xFD873DF27E89E492ULL,
		0xC0EBE6C2BCD343DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA7514CDFCA6BD6ULL,
		0xA698CB64D0616654ULL,
		0x9CE178BE04D3A2C4ULL,
		0x019FFDB06C34F998ULL,
		0x924C892C8E029649ULL,
		0x7A26A52965FD401EULL,
		0x9F8DC5289450A586ULL,
		0x63FD4690EC2B888EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x329BF6FF14B6DE80ULL,
		0xDBA33303BBFBA8C2ULL,
		0x83E66C435F21B7EAULL,
		0xEEEB71A0E3D8CAE7ULL,
		0x1133D4E79FCBB8FCULL,
		0x0C4040F39D06F8AEULL,
		0x620AF8DAEAD94114ULL,
		0xA316A05250F8CB55ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C9BC43C1F4768A8ULL,
		0x7C20900E08FCDF59ULL,
		0xB52B6CF89FCF3EB9ULL,
		0xFD7C4879EF1306B9ULL,
		0x34A55CB5141E916CULL,
		0x809AD330ACD1E770ULL,
		0xE0A1B7A5C4D7B6F6ULL,
		0xEEC49514B342CAE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A59828DECE869D3ULL,
		0xFDC203544702C343ULL,
		0x5027A69AE206F177ULL,
		0xDD9C65B22C6A4E8EULL,
		0x0093343D75A76AB8ULL,
		0x12127AFA5C1E1035ULL,
		0xDE64B11363955AE2ULL,
		0xFC23F368D4D34147ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46C246B1F3AF017BULL,
		0x81E2935A4FFE1C1AULL,
		0xE50CCA627DC9CFCEULL,
		0x20E02DCBC3794837ULL,
		0x3436688861B9FBD4ULL,
		0x9288A9CAF0CFF745ULL,
		0x3EC506B6A742EC14ULL,
		0x12E7667C67918BAEULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA4D9799AF6E8A4BULL,
		0x94DCA3095C2D3FEEULL,
		0xD1E6910F29E9C698ULL,
		0x2BFD27C3EA3618D9ULL,
		0xCC3B5976844840D2ULL,
		0x3D6A576987F4A220ULL,
		0x11442DB773217D0AULL,
		0x47E5AE5CA9102CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x376332615013D9DFULL,
		0x02BBBD721DA72F5AULL,
		0xF3519418808F6250ULL,
		0x9A57210916602739ULL,
		0xFCE705364EDD76A7ULL,
		0xC6A6FE1D1066D3DAULL,
		0xF61CC475B3FEE668ULL,
		0x05E24BB3CAA2924FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD2EA5F8FF7D5394ULL,
		0x96671E7B418A10B4ULL,
		0x22B70517A966A4C8ULL,
		0xB1AA06CAFC563FE0ULL,
		0x30DC5C40CA953675ULL,
		0xFBCCA974979271FAULL,
		0xE758E9C2C0DF9B62ULL,
		0x4207E5EF63B2BE8FULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97B461A738D25F24ULL,
		0x462EBCEA7FE612F0ULL,
		0xEE3036B03DBD7812ULL,
		0xB59F4D92106C60B5ULL,
		0xBECA02829A2786FEULL,
		0xA9CB75299A11E1EAULL,
		0x1A4E43DD73EECE32ULL,
		0xB2FD7AC8DDDB05EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A1FB33E8357574ULL,
		0x4A9C0C9DA9357421ULL,
		0x6D0ECEE12B665BC8ULL,
		0xEB23E91DF2513EE8ULL,
		0x86606C9A7143759FULL,
		0x26A5DB9CA7868FFEULL,
		0x18F28F84E4B8DA67ULL,
		0x085F7F3D55046B21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1159A94D0E72A50ULL,
		0x0CB2B077D6D366D1ULL,
		0x833EF85116DB23DAULL,
		0x5EBCA48FE23D5E5DULL,
		0x38AA6E18EB64F361ULL,
		0x8F6EAEB53D976E14ULL,
		0x02BCCC5997561455ULL,
		0xBAA205F588DF6ECCULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FE44E4410A2E891ULL,
		0x95F8F154879F8DF3ULL,
		0x1EB6F5087F420B37ULL,
		0x4FC525A61560059EULL,
		0x23CB227E3AE7E000ULL,
		0xA5A843CCC5C72272ULL,
		0xE9B014450A22B9D8ULL,
		0x3C23C1AEAF126992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE5958A5025C126CULL,
		0x4AB25F199FD6AB4CULL,
		0x7F881597F2536F84ULL,
		0xDC687EB2058F046BULL,
		0x4034CB063D71C8CDULL,
		0xCF1BAA0AB92142B9ULL,
		0xCFBB88E82F0A82B0ULL,
		0x8B3A821F64E363CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61BD16E112FEFAFDULL,
		0xDF4AAE4D184926BFULL,
		0x613EE09F8D1164B3ULL,
		0x93AD5B1410EF01F5ULL,
		0x63FFE978079628CDULL,
		0x6AB3E9C67CE660CBULL,
		0x260B9CAD25283B68ULL,
		0xB71943B1CBF10A5FULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EA0C29D1CB5A235ULL,
		0xE1EC252668991727ULL,
		0x0233A85AF17E2F51ULL,
		0xAA251DFB30107C9AULL,
		0x5C68D961726B8493ULL,
		0xFE7AA7C58E03B0A2ULL,
		0x80598C43DA6694DAULL,
		0x7004834EF74C6897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x870C3F0BBFD698DDULL,
		0xC185ADD27639B18EULL,
		0xD25604630F368ED0ULL,
		0xCFE48BF30D14B6DFULL,
		0xF45DD1B23E0D968FULL,
		0x6050BFAC75B61A0EULL,
		0x8AEB8BD4E852FDBBULL,
		0x3C90777AE3BBD5ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9ACFD96A3633AE8ULL,
		0x206988F41EA0A6A9ULL,
		0xD065AC39FE48A181ULL,
		0x65C196083D04CA45ULL,
		0xA83508D34C66121CULL,
		0x9E2A1869FBB5AAACULL,
		0x0AB2079732346961ULL,
		0x4C94F43414F7BD3AULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86A2575C66E2D15AULL,
		0x47B65C148592E854ULL,
		0xE4EF7B38079B78C5ULL,
		0x6571014C01D31989ULL,
		0xCCAE6322FA9C8F8FULL,
		0xAA6AA706E0C0E88EULL,
		0xB3AE8393467A4895ULL,
		0x2C27E909741C0F7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB7B261E01FD8C1ULL,
		0x709239153B94991BULL,
		0x216BFCE55B250175ULL,
		0x52BF796F336143FEULL,
		0x5B99ECDE4DC1CE89ULL,
		0x5CB9CAB47420EAEAULL,
		0xF191A4501EB97356ULL,
		0x5E57689A0946D247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C15E53D86FD099BULL,
		0x37246501BE06714FULL,
		0xC58487DD5CBE79B0ULL,
		0x37CE782332B25A77ULL,
		0x97378FFCB75D4106ULL,
		0xF6D36DB294E00264ULL,
		0x423F27C358C33BC3ULL,
		0x727081937D5ADD3DULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFAB0A0BF85771CAULL,
		0x1DB41C6C37791A79ULL,
		0xA4A893C9EB5C3EDFULL,
		0xBB4B5DBD9B791B78ULL,
		0xA3713786AA7C4C42ULL,
		0x4691A69B6A5827E1ULL,
		0xFF5C1A3E57DE5924ULL,
		0x78167F29BDAE0FB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ACE2A22DB6EF7ADULL,
		0x141C3EC7B81756E1ULL,
		0x92A91C6ABC5E068CULL,
		0xF74E09F6127C0259ULL,
		0xB0AE89570F4CEE8BULL,
		0x73F17AFA0F861C12ULL,
		0x6E08AAEA0EF0A05BULL,
		0x8A95F65FB1C5FE46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3565202923398667ULL,
		0x09A822AB8F6E4C98ULL,
		0x36018FA357023853ULL,
		0x4C05544B89051921ULL,
		0x13DFBED1A530A2C9ULL,
		0x3560DC6165DE3BF3ULL,
		0x9154B0D4592EF97FULL,
		0xF28389760C6BF1F2ULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E016A030AA8C4D8ULL,
		0x891D0E226672532DULL,
		0x6EFD7E4A2CDC8CB7ULL,
		0x88DF82273B1BA1E8ULL,
		0xE23339255FE3D930ULL,
		0xBAC078C5B8337A50ULL,
		0xFFA5A2A1EAF918E7ULL,
		0x685B860270966CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ECBBD85F59DC41EULL,
		0x419E74CBBD37C02FULL,
		0xAE4E7D0CD184FAB4ULL,
		0x7DA7898F18B82123ULL,
		0xE13C22AC7C55286CULL,
		0x2B0043D2E92405E2ULL,
		0xA251A62A463B2806ULL,
		0xF095FFAD6426C52FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10CAD786FF3500C6ULL,
		0xC8837AE9DB459302ULL,
		0xC0B30346FD587603ULL,
		0xF5780BA823A380CBULL,
		0x030F1B8923B6F15CULL,
		0x91C03B1751177FB2ULL,
		0x5DF4048BACC230E1ULL,
		0x98CE79AF14B0A9EFULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33A1A7802E3165A3ULL,
		0x57DD5766846CA13DULL,
		0xCB99058E98CAA79FULL,
		0xE2253D955FDF6F7DULL,
		0xC09E2C16A0E3A982ULL,
		0x9CA50265860D2756ULL,
		0x5ED6FE8DFD1F692DULL,
		0x4286D8BE4CEDDBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB938C203E45D5A6AULL,
		0xF14C5620BD03CFC3ULL,
		0xDAEA74AFE3A4B785ULL,
		0x588B2FEF885D2C2CULL,
		0x8E6C821DCFAB5018ULL,
		0xF2BF7E7F05963DBFULL,
		0x27CBE41864E75292ULL,
		0xC2CE278ED9E19746ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A996583CA6C3FC9ULL,
		0xA6910146396F6EFEULL,
		0x117371217B6E101AULL,
		0xBAAE127AD7824351ULL,
		0x4EF2AE0B6F48F99AULL,
		0x6E1A7C1A839B1AE9ULL,
		0x791D1A9599F83BBFULL,
		0x8048FF30950C4CBBULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88AF0AEBF6FA70E7ULL,
		0xF5826E719F7FD510ULL,
		0xDC8E92F8AE81D92DULL,
		0x879B49E9F55440A5ULL,
		0xE1B452D569C798D8ULL,
		0x6A889C9BCCBF1DCFULL,
		0x467E2BF03D16FD94ULL,
		0x63FF23668DCEE9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32298034EB6B2E1FULL,
		0x588B3F67289C711FULL,
		0xC7468558C5919494ULL,
		0x7BB8D320309BFDC9ULL,
		0xB01D44D60670CFC1ULL,
		0x3D8F4A2016347F99ULL,
		0xFF12E6299494C6A9ULL,
		0x0ACF8DD6B8B0E976ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA868ADF1D915EF8ULL,
		0xAD095116B7E3A40FULL,
		0x1BC817A06B104DB9ULL,
		0xFC239AC9C5CFBD6CULL,
		0x51A916036FB75719ULL,
		0x5707D6BBDA8B6256ULL,
		0xB96CCDD9A9823B3DULL,
		0x6930AEB0357E00B7ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8153DCE896AF6B3ULL,
		0x03717B1DC32349D2ULL,
		0x0BF31370EC28A09FULL,
		0xCE2F7EE77C846AF7ULL,
		0xDDF9B21774120310ULL,
		0xD73C78D1D5B795BCULL,
		0x2D41393B9B82A20FULL,
		0xF8B7B7047F15B221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x387FEDB2945294D2ULL,
		0x29C12A80F655A432ULL,
		0x46427DD4BC189403ULL,
		0x2F3F26C1C05DC428ULL,
		0x93B0883F4E56D174ULL,
		0x771680AD4D9B02F4ULL,
		0xAD97A181C596F7AAULL,
		0x8BDC7294E331FD61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF06AD07C1D386261ULL,
		0x2AB0519D3576EDE0ULL,
		0x4DB16EA45030349CULL,
		0xE1105826BCD9AEDFULL,
		0x4E493A283A44D264ULL,
		0xA02AF87C982C9748ULL,
		0x80D698BA5E1455A5ULL,
		0x736BC5909C244F40ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8E3D26C9353A97CULL,
		0xF8D8D2C3E9A8F7B3ULL,
		0x13FDFCAF3EFC8FCCULL,
		0xAD318ABCB278B7D8ULL,
		0x4B64C0EB268A4769ULL,
		0xB0008F8AB688524EULL,
		0xC846790074B22C81ULL,
		0x7FBDD1051C0344DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EF97D78944EB19ULL,
		0x1FB7F776C785B20CULL,
		0xDDC6BC2808E00C88ULL,
		0x26AB1A7089B77C53ULL,
		0x68343FD55DB6D076ULL,
		0x1E4C096C46A8CE7DULL,
		0xE35A17DF1863AEE8ULL,
		0x622A60CEDB096460ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D0C45BB1A174265ULL,
		0xE76F25B52E2D45BFULL,
		0xCE3B4087361C8344ULL,
		0x8B9A90CC3BCFCB8BULL,
		0x2350FF3E7B3C971FULL,
		0xAE4C86E6F0209C33ULL,
		0x2B1C6EDF6CD18269ULL,
		0x1D97B1CBC70A20BEULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x186732D712813B5DULL,
		0x13031673EB0D41FCULL,
		0x13F2D004CE47846BULL,
		0xB0DC7A05191B2FBFULL,
		0x56E2C4DDC169081FULL,
		0xEAA311CBF6683F8DULL,
		0xD9D3DDEFD952DCECULL,
		0xE202CA75E20D96AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EDEF0F623FE6264ULL,
		0xC3DFE56138E14F3AULL,
		0xC1972123A4B70844ULL,
		0x74EC49285CD0B756ULL,
		0xD0184B9BCB8976D2ULL,
		0x8AC57A642F00BCF7ULL,
		0x674F01DB173A4364ULL,
		0x387E7489A96DAF7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36B9C221317F5939ULL,
		0xD0DCF312D3EC0EC6ULL,
		0xD265F1276AF08C2FULL,
		0xC430332D45CB98E9ULL,
		0x86FA8F460AE07ECDULL,
		0x60666BAFD968837AULL,
		0xBE9CDC34CE689F88ULL,
		0xDA7CBEFC4B6039D0ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D2435815C2366B3ULL,
		0xCD492F3A86A8B3E7ULL,
		0x67BAF38E8B55F44DULL,
		0x9B0EBA380B54F33DULL,
		0xFD5690C9826518FCULL,
		0x29BC307C92C72571ULL,
		0x8101EC5D7D67174EULL,
		0x2EE810106369FA31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5691770CBBB1FBCBULL,
		0x5295CA9F1CBFD9BAULL,
		0x8435E67AD169D4C0ULL,
		0x5A9C1D37852AA9CFULL,
		0xA97E2A9EF03BC8EBULL,
		0x29B65949B9071D2BULL,
		0xFBB3A4653003E469ULL,
		0x33B9E77801F3E5DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BB5428DE7929D78ULL,
		0x9FDCE5A59A176A5DULL,
		0xE38F15F45A3C208DULL,
		0xC192A70F8E7E5AF2ULL,
		0x5428BA57725ED017ULL,
		0x000A69352BC0385AULL,
		0x7AB248384D64F327ULL,
		0x1D51F768629A1FEAULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C81D7EAE9714427ULL,
		0xF27C53C50B7CB097ULL,
		0x13A6A7C5A5FC80F2ULL,
		0xDB5281CA3AC3B7C0ULL,
		0x4B603EE0EB207D7EULL,
		0x5BAC54B0D1EC784BULL,
		0x9D298F6FCF936ECEULL,
		0x361B5C38288C9236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEA5E7EB0D0BAF2ULL,
		0x98271F7265BD85E1ULL,
		0x7701E11CD54593E6ULL,
		0x0F525E0478B26653ULL,
		0x300DF3F9519DFBC5ULL,
		0x1E1BF8ABF7FF1518ULL,
		0x8C10AB4C7D7231F7ULL,
		0x32BE3D111A42D969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x126B899459A1FED5ULL,
		0x6A5B4CB76EC13576ULL,
		0x64A746D970B91314ULL,
		0xD400DFCE4271D193ULL,
		0x7B6DCD19BABD86BBULL,
		0x45B7AC1B26136D53ULL,
		0x11392423B2E15F39ULL,
		0x04A5612932CE4B5FULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFABA80B69A32A308ULL,
		0xE36D794DAB3FBD4DULL,
		0xC7EB1A677DCD75B4ULL,
		0x9BE80E9AD756D74BULL,
		0x17434586108D14ADULL,
		0x425E5A238EBE46FEULL,
		0x643197ADA3F274BCULL,
		0x8BA1F058944245B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CE607712E745E2ULL,
		0x9AE1748F1744C602ULL,
		0x8B35DD7E61965FC0ULL,
		0x31520F068A9AE06BULL,
		0x264CF86FF4DEB615ULL,
		0x66EA122AC8BCCC9AULL,
		0x4B1F6390A2BA6746ULL,
		0x60B52C7E40090F7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0874E0C188D5E6EAULL,
		0x798C0DC2BC7B7B4FULL,
		0x4CDEC7191C5B2A74ULL,
		0xAABA019C5DCC3720ULL,
		0x310FBDE9E453A2B8ULL,
		0x24B4480946028A64ULL,
		0x2F2EF43D014813FAULL,
		0xEB14DC26D44B4AC8ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C69B44D7C5D21C3ULL,
		0xB44D12534522E80AULL,
		0x35C8C463D0C6660BULL,
		0x1C8B5BE6C0C364EAULL,
		0xFB75210B7920B96EULL,
		0xC8D557D212FC9328ULL,
		0x36900F8DA95EE2F2ULL,
		0xD59E8FA05F58AFC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373629DAB46880DFULL,
		0x932672863674571FULL,
		0x9CEA70FBEEBAD425ULL,
		0xC502105131B32514ULL,
		0xE75F2ECB04456CBCULL,
		0x2D79B5F007C760A4ULL,
		0xE70139BE446F14C8ULL,
		0x598D0B5382145079ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B5F9D97C835A11CULL,
		0x276B60D57356BF15ULL,
		0xA922B4983E7CB22EULL,
		0xD9894BB7F17041FEULL,
		0x1C2A0FC07D65D5D2ULL,
		0xE5ACE222153BF38CULL,
		0xD1913633ED31F63AULL,
		0x8C1384F3DD4CFFBCULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA500EC45E6E480ACULL,
		0x2322EA97CB29995AULL,
		0x870B8590EFDB7EB9ULL,
		0x2EE9D189761F7698ULL,
		0x2BD41D4F48B56C82ULL,
		0x5EFD1AADFB221504ULL,
		0x7BAD348810442560ULL,
		0x8AA1426B04E23835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D775CA62EDBD69ULL,
		0xABF4C73492A54717ULL,
		0x593D3B57FBD0EF2BULL,
		0xE49CF62139E6E49EULL,
		0x6BB6F294E274343CULL,
		0x2E39BFB61AFABE29ULL,
		0xAAE65C056C833164ULL,
		0x6362991858DC15AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CD7998F84093DC5ULL,
		0x88D62DA3598CDE4DULL,
		0xDE36BEC7140B9192ULL,
		0xCA7527A84FF99206ULL,
		0x4062EFDBAAC158BEULL,
		0x70C4A51BE1D8AB2DULL,
		0xD14B688D7CC71404ULL,
		0xE9C3DB735C3E2D9AULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CD2DEC3FAA7AEB8ULL,
		0x1A713ABBF40AC1D1ULL,
		0xE796698A658CED81ULL,
		0x76AC30495C780446ULL,
		0xA171C8A21BEA5E6EULL,
		0xDEF4A7BE646D7ACBULL,
		0xDE1CEFFDCB3102EEULL,
		0xCD9BD40629707F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB57A18B8405AE930ULL,
		0x8A419EB1C21FB0F0ULL,
		0x81428AFFCCE97908ULL,
		0xC36FBAC8309B2352ULL,
		0x361BB17FB2EE5C68ULL,
		0x2553AA9EA1E5A20BULL,
		0xCA3242EC811B8017ULL,
		0x301583E763BDC16CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9A8C67BBAFD4788ULL,
		0x9030A40A36157121ULL,
		0x66D4E375A9659489ULL,
		0xB5C38A816CE32714ULL,
		0x976A79DDA9040206ULL,
		0xFBA70D20C588D8C0ULL,
		0x142EAD114A2A82F9ULL,
		0xFD8E57E14ACDBE3DULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82B71F6060A54C7BULL,
		0xF07CAE1A0DB9EF82ULL,
		0x560A1AB7DFEB183EULL,
		0x7ACEA3ED0F846F30ULL,
		0xBB70069CB59BE281ULL,
		0xCD1D6FCBB1554FB7ULL,
		0x427B7F02DF74071DULL,
		0xCDE8C777AE81437DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800BB1A45F78CA2ULL,
		0x55DBA3C847EE3044ULL,
		0x6DFFB9832C38E95FULL,
		0x5AD7906068A768E5ULL,
		0x078356A0817F299EULL,
		0x7EB51DF50A546A8DULL,
		0xBB0DC6A86EDC37E5ULL,
		0x84E183EF37A40B2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AB7A47A2552C0D9ULL,
		0xA5A70DD24A57DFC6ULL,
		0x3BF5A334F3D3F161ULL,
		0x2019338D672307D5ULL,
		0xBCF3503C34E4CB1FULL,
		0xB3A8723EBB01253AULL,
		0xF976B9AAB1A830F8ULL,
		0x4909449899254853ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC83CDEAF7A8A3B2EULL,
		0xC5EF59BBDF1C5A43ULL,
		0x6430CC8B9CFBC47FULL,
		0xD03A0D3E68B23A6EULL,
		0x029FBE56D0F8B55BULL,
		0x58717BF37E47749CULL,
		0xFA6AB9A3D234F8D4ULL,
		0x034C3C0CF6882CC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67C3A3608B4578C9ULL,
		0xC898ECB9C87CB263ULL,
		0xAA29F0353518B59CULL,
		0xA1658823BC6C2ABFULL,
		0x52425DF2CE298888ULL,
		0xD754D4183F78D1DEULL,
		0x4329D4ABF93086B7ULL,
		0x8C4BAC1FE64FFC25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFFF7DCFF1CF43E7ULL,
		0x0D77B5021760E820ULL,
		0xCE193CBEA9E371E3ULL,
		0x715F851DD4DE10D1ULL,
		0x50DDE3A41ED13DD3ULL,
		0x8F25AFEB413FA542ULL,
		0xB9436D082B047E63ULL,
		0x8F07901310C7D0EDULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7F66C830EAC4ABEULL,
		0x8C6D15D0007B4066ULL,
		0x74FB632F9BA5C60CULL,
		0x55199F0ADDE2BEECULL,
		0xB3BF7BF7C899F884ULL,
		0x66003EBDDC868AE5ULL,
		0x22740D1E94200949ULL,
		0xCDF9D79581AF5795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x587A3D86CAABA82AULL,
		0x609C9D56B5BE5221ULL,
		0x75EA9A236362DBCBULL,
		0xA734B7C88555B514ULL,
		0x8ACBE0FAD7EA93BEULL,
		0xCE6D70548BEE710FULL,
		0xE8615A3BAD6472CDULL,
		0xB066D94E8E284A5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F8C5105C407E294ULL,
		0xECF18886B5C51247ULL,
		0x0111F90CF8C71DC7ULL,
		0xF22D28C258B70BF8ULL,
		0x39749B0D1F736B3AULL,
		0xA86D4EE95768FBEAULL,
		0xCA15572539447B84ULL,
		0x7D9F0EDB0F871DC9ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA95496D3B81451C0ULL,
		0xEA0DF3CFAC21CC62ULL,
		0x3185D294156A6C5AULL,
		0x359782853E69F2A6ULL,
		0x70FF5D27E18175FCULL,
		0xAB66EEFA61082131ULL,
		0x8AB9B5864533AC8FULL,
		0x5DA2E47D29ABB6CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61B57E8816FCF280ULL,
		0xDB38B16FBCB24A40ULL,
		0xD18DC653300C20D5ULL,
		0xA57395E56C5EE7CBULL,
		0x1BA92D66EEFCA503ULL,
		0x2EF65C7EEAE52538ULL,
		0x05E0CB669886E889ULL,
		0xD56FBA47FB30FB8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8E1E85BAEE8A340ULL,
		0x313542A010938622ULL,
		0xE00814C725664C8FULL,
		0x90E417605237156DULL,
		0x6B5670410F7DD0FFULL,
		0x8590B2848BED0409ULL,
		0x8F597EE0DDB54406ULL,
		0x88CD5E3AD29B4D44ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A6477F95A7FB891ULL,
		0xDB7730C8DAC4BC31ULL,
		0x6565229F78B28101ULL,
		0x82FD004410CCA2EEULL,
		0xA7FA025566B0DDF8ULL,
		0xFBDC54A18395C1C7ULL,
		0x77322A61CBD46469ULL,
		0x0D285D63D9CC17BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8066CD29972F4E6ULL,
		0x0281302B60E80C5AULL,
		0x19869465A5F0EC80ULL,
		0x3DA2D9EEA178B928ULL,
		0x165AADFFC627E8FCULL,
		0x3C86036D1E5E8B22ULL,
		0x2BE7C54708DB2309ULL,
		0x19BBC5607A009E49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42621B2BC30D4C77ULL,
		0xD9F600E3BA2CB06BULL,
		0x7CE3B6FADD426D81ULL,
		0xBF5FD9AAB1B41BC6ULL,
		0xB1A0AFAAA0973504ULL,
		0xC75A57CC9DCB4AE5ULL,
		0x5CD5EF26C30F4760ULL,
		0x14939803A3CC89F5ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CB56098F9BD0175ULL,
		0x82C8BA69319E4607ULL,
		0xCB68724E4BD6F20BULL,
		0x6F69065ADBB28836ULL,
		0xDD83F247E536620DULL,
		0x71D29D85F3DDD918ULL,
		0x3915A3E8DA4AAC1FULL,
		0x826088512A75FB69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4902D69CC4CEC863ULL,
		0x1AE2773BBE53E0A2ULL,
		0xFCEB8D3A2C68D964ULL,
		0x6CBEDA64C84A57D3ULL,
		0x9EC388885575E548ULL,
		0x5F1C826A2BA13369ULL,
		0x52764D3D6F502D58ULL,
		0xA5DA1798E59A7C5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05B7B6043D73C916ULL,
		0x982ACD528FCDA6A5ULL,
		0x3783FF7467BE2B6FULL,
		0x03D7DC3E13F8DFE5ULL,
		0x43407ACFB0438745ULL,
		0x2ECE1FEFD87CEA71ULL,
		0x6B63EED5B51A8147ULL,
		0x27BA9FC9CFEF8737ULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45D4F1DB0FBB4B7DULL,
		0x9B9F8561C9201819ULL,
		0x0AE9107A5F2DF0EAULL,
		0xBD7A6900D184CEA6ULL,
		0x7CB7DA4DECFB4F04ULL,
		0xEF0D3062FAB69902ULL,
		0x9BA4FDFBE401CDADULL,
		0x08E5C034208B932FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A3A68D971690E90ULL,
		0x99630833E153B2F4ULL,
		0xDE4F95FE4EF3B6A2ULL,
		0xB3759588702D605DULL,
		0x4A778BDBACB45AAFULL,
		0x45FF5305B1CDC576ULL,
		0xAFDFA42AD30A17C6ULL,
		0xFDCE775027C1D3ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FEE99027ED245EDULL,
		0x02FC8D522873AAEDULL,
		0xD4A6858411DE4648ULL,
		0x0E0FFC88A1A9AEFBULL,
		0x36C05196404F15ABULL,
		0xAAF263674B7B5C74ULL,
		0x347B59D1370BDA6BULL,
		0xF52BB764074A4083ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B1D5236CFF34394ULL,
		0x936C20840E29E188ULL,
		0x8FF6FDF25AD9851BULL,
		0xFD7B3236D4429447ULL,
		0x0836E8ACA8F02AB7ULL,
		0x6A3D081231F0D6E8ULL,
		0x6ADABD8F2B5C2223ULL,
		0xC05C7F6E3C8C501BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC0672C4FD03A0DDULL,
		0xF481833F8D7D7820ULL,
		0xCC1759E4F2DC9F5EULL,
		0x61D4F809368FBA5CULL,
		0xE923F7AA2F4E61BBULL,
		0x251FA5EACDBAA3C1ULL,
		0x73AE55C1EDE427D4ULL,
		0x613CB4E19D37EE1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF71B20F232F0E349ULL,
		0x67EDA3BB835499A8ULL,
		0x43E1A416A8051A45ULL,
		0x9CAFCA3FE2CD2E1BULL,
		0xE1151F0687BE4B0CULL,
		0x4F22ADF8FC4A7529ULL,
		0x1974E84EC6B805F7ULL,
		0xA160CB8FA1BBBE04ULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA55A55E93C9D1397ULL,
		0xE2C0BA5F9610494CULL,
		0x06CECBB833791BB8ULL,
		0x10C5008CDC727866ULL,
		0x5FDDB5E9B053396BULL,
		0xCF574E74C87BBE6EULL,
		0x2630D05B29778B3AULL,
		0x5B674457FAA407CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB40BB60BB07F105ULL,
		0x1C3681CA03094C5CULL,
		0x44E6D8C9610F6167ULL,
		0x80BD34A85B8F0FF2ULL,
		0x664F8A1DCAF8CA59ULL,
		0xEE76332ACB365111ULL,
		0x79D2C0DE109775DBULL,
		0x2D137F4165F0B97EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E1AEE89879AE292ULL,
		0xFEF63B9595190510ULL,
		0x4228137152767ADFULL,
		0x9078342487FD7794ULL,
		0x39923FF47AABF332ULL,
		0x21217D5E034DEF7FULL,
		0x5FE2108539E0FEE1ULL,
		0x76743B169F54BEB5ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x741E283049969162ULL,
		0x2AC2885A483C41B2ULL,
		0x299C348B6A0643B5ULL,
		0x640BE1D76E1435A1ULL,
		0xCED790CC1C9C4875ULL,
		0x091025F3DB75FCB0ULL,
		0xB784D873EA0736A5ULL,
		0xF94C95B773F25D1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4567305F0919DC7ULL,
		0x96F2473AB92B5220ULL,
		0xC7ADD91446F13C09ULL,
		0x2B9ED5A9BD923FD2ULL,
		0xB3B817DF4C168D00ULL,
		0x08FDC9536FDB3FE6ULL,
		0xA150E73080B813D8ULL,
		0x2AEF1D44943CBF4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90485B35B9070CA5ULL,
		0xBC30CF60F1171392ULL,
		0xEE31ED9F2CF77FBCULL,
		0x4F95347ED3860A73ULL,
		0x7D6F8713508AC575ULL,
		0x01EDECA0B4AEC356ULL,
		0x16D43F436ABF257DULL,
		0xD3A388F3E7CEE253ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DE7DA7A632A9336ULL,
		0xD0573061BFB83F5BULL,
		0x93B562B0BEE81C71ULL,
		0x62E2F69F399AD04DULL,
		0xD3FB248197228E5CULL,
		0xFD55B746AA0FA24BULL,
		0xC6243FD7597AB7B9ULL,
		0xA489339C2C25A491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7BA37BE946AF15ULL,
		0x2D7821A2AB28347FULL,
		0x5902E90EC3F5BFDEULL,
		0x711DEFD23B23A396ULL,
		0xD1010CB442415854ULL,
		0xB8F4EB36C5253BB6ULL,
		0x6374A8AE5C599D6FULL,
		0xF076DBD6B51FD650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x979C79018A6C3C23ULL,
		0xFD2F11C314900B24ULL,
		0xCAB78BBE7D1DA3AFULL,
		0x13FF194D02B973DBULL,
		0x02FA2835D563D608ULL,
		0x45A15C706F2A99FDULL,
		0xA550977905232AD6ULL,
		0x54FFE84A993A72C1ULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0516844DFD99037ULL,
		0xE940A89CC1BB130AULL,
		0xB28F71FCECD64977ULL,
		0xBE9E1CF31DBC0334ULL,
		0x3E6A904781648C7FULL,
		0xC8A284DBAE4BC894ULL,
		0x551C5FF3ABAAFD33ULL,
		0xDA781B9F717266FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB99E8CC88FCF6B8ULL,
		0x1978A81D265B3C85ULL,
		0x44BF196C03C6B60AULL,
		0x86D806A6DE927E9EULL,
		0x181FD18745D733A1ULL,
		0xC1D7B896A6651B13ULL,
		0xC125BDDA6A602670ULL,
		0x61430DCB4A12C13DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BC880885725668FULL,
		0xF0380081E7E02F8FULL,
		0xF6306890EF10FF7DULL,
		0x38461A55C32E7DAAULL,
		0x267541C0C4B3BFDEULL,
		0x09753C4D082ED387ULL,
		0x9439E229C1CADB43ULL,
		0xBB3B16543B60A7C6ULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67C3018F261CFD26ULL,
		0xC66CF0901EBC382CULL,
		0x1C053AB7637F8FCFULL,
		0xE97E08A510F6B6C2ULL,
		0xAD267AF1F7D1CEC5ULL,
		0xD20E52F2EF283CF5ULL,
		0xE6AE88DCA8234DA2ULL,
		0xDFBABA942FCB7268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22BC2904B7DF2BBDULL,
		0x05315F61990D0B13ULL,
		0xBEEFFD78DF7FA57FULL,
		0x2350A2813D478C02ULL,
		0xE72378C27B3BBD3CULL,
		0x1BC57AF17A3D32B5ULL,
		0x179DC3324CFC0D0AULL,
		0x63591FD7AC88DAB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x457F288B91C3D69BULL,
		0xC35DAFF187B1333FULL,
		0xA2EAC7CFBC002AB0ULL,
		0xCA2EAA242DB13AC0ULL,
		0x4A0502338CEA73F9ULL,
		0xC9CB280395150E40ULL,
		0xF1334BEEE4DF40A8ULL,
		0xBCE3A5438343A8DDULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x632568B9DF2CB6C2ULL,
		0x45EF6455B7F09C59ULL,
		0x4BBFA5464EDE2A3AULL,
		0x28F5430422ADA5E4ULL,
		0xD6EE2C6EB64D9094ULL,
		0xDC119DA2A02FD77FULL,
		0x5B301BB35E925EC0ULL,
		0x61E418C9574AD3F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD071023E1E0CF3F5ULL,
		0x60CFC5B5B0437829ULL,
		0x10F18E68F6C2E79EULL,
		0xA54DFC76B7B58472ULL,
		0x50FE9889F5EC7891ULL,
		0x3E470A91E9FDBAE3ULL,
		0xAFBEFE1618D05C3CULL,
		0x802C55154A6EE0FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3546A87C1204537ULL,
		0x2520A1E007B3E470ULL,
		0x5B4E2B2EB81CCDA4ULL,
		0x8DB8BF7295182196ULL,
		0x8610B4E743A1E805ULL,
		0xE256973349D26D9CULL,
		0xF48EE5A5464202FCULL,
		0xE1C84DDC1D24330CULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x159EE078B528EE8AULL,
		0xBA038A257D6561AEULL,
		0xE1A84A23FEFD287CULL,
		0xE055488A0A1C6710ULL,
		0x6C097B60EA7621FBULL,
		0x665BD56998394BF4ULL,
		0x754FA99D9DF2D590ULL,
		0x273D778F1AAE847DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1385C7B4D5459FC4ULL,
		0x40FE9A24D83C1A5BULL,
		0xE7B2E22B2F74528EULL,
		0xD9B60E961A5A73CFULL,
		0xDC67AAFEF1A14C95ULL,
		0x02C259842AD12A6CULL,
		0x5FC3EE152A8C3A13ULL,
		0xBFDD49B96560A5E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x061B27CC606D714EULL,
		0xFAFD1001A5597BF5ULL,
		0x061AA808D1897AF2ULL,
		0x39E3461C104614DFULL,
		0xB06ED19E1BD76D6EULL,
		0x64998CEDB2E86198ULL,
		0x2A8C4788B77EEF83ULL,
		0x98E03E367FCE219EULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAB21839F7E7FE78ULL,
		0xE5E52E1BCAF17E6FULL,
		0xF88E53141ED5B064ULL,
		0xF3F5B4CAA25825D8ULL,
		0x276ECB12BF8E6695ULL,
		0x84082BE8256B9B31ULL,
		0x3FC4B03DEF6018ABULL,
		0xEE604C749462F8AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA07C6F752F545C47ULL,
		0x579A6E815FBC802AULL,
		0xB66735C8101A5938ULL,
		0x47AF1441C0C0BAC7ULL,
		0x13CB8E427B05B7D3ULL,
		0x1093C2E3CDAAFAFEULL,
		0xDBF64CF239CA87A5ULL,
		0x7320B95B973D3D69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ACE774CD8B3A23FULL,
		0xB27F409A954DFE45ULL,
		0x4EE966DC0ECFE95CULL,
		0xB45AA08B62989F1FULL,
		0x34A54550C48BD146ULL,
		0x949BE90BE8C161CFULL,
		0xE432FCCFD6AA9F0EULL,
		0x9D40F52F035FC5C6ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F995B84A2893C23ULL,
		0xDEECDE2E6626E957ULL,
		0xC6E01223E14D6B34ULL,
		0xA48B7D0772301E06ULL,
		0xF8C2B7474EB728BFULL,
		0xA56B39FCCC577F41ULL,
		0x6DE9D6E0A20A93D9ULL,
		0x2881792746814DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5806AE8AA1CD7B8AULL,
		0xE0B1691B1768619EULL,
		0x80AEC2AC610387D1ULL,
		0x140832A41114F9A1ULL,
		0xAD36E0B9ACF7ECE0ULL,
		0x0822F11F8212C1B0ULL,
		0x659E90F7D57FF273ULL,
		0xFD8F0B378C6E719DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x379FF50E034447A9ULL,
		0x3E5DB735714E88C9ULL,
		0x464ED08F804EECE5ULL,
		0xB0834FA36324E7A7ULL,
		0x55F457FEE240C45FULL,
		0xAD49C8E34E45BEF1ULL,
		0x08774617777561AAULL,
		0xD50E7210CAEF3C2AULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3F36A374B893F04ULL,
		0x403A79BE872AF99BULL,
		0xFD78321ED5B55687ULL,
		0x87F9EDA3E6DD9C42ULL,
		0xD9F42DBC2C085698ULL,
		0x2266A06DC492FC9DULL,
		0x53BF4C10AD3EA68FULL,
		0xACA0664CCB02AD02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A733791E1ADF53ULL,
		0xB1626A7BD862BD00ULL,
		0x69E8D4804D1A440AULL,
		0x504BF8EF01FD3E13ULL,
		0xB201E5382E9493B6ULL,
		0x3B772AE16E252A15ULL,
		0x4750B3A42C859E24ULL,
		0x087B2E0E7DDC7ADDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1754594E5593E057ULL,
		0xF15813C55F48449BULL,
		0x9490E69E98AF128DULL,
		0xD7B2154CE720A251ULL,
		0x6BF5C884029CC52EULL,
		0x19118A8CAAB7D688ULL,
		0x14EFFFB481BB38ABULL,
		0xA4DB4842B6DED7DFULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EB7F9ACA3F5A9D8ULL,
		0x21FB47D9D496F44AULL,
		0xCB937D33DF5E7042ULL,
		0x9BCE5AA113E2657EULL,
		0x9B0E7B13D6F2209FULL,
		0x4C31EE41E0A6DD61ULL,
		0xA619AF4C35B484EEULL,
		0x2DD2E5AC958BA371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB63EE8C8653FB989ULL,
		0xC7ED72C4F48C72B8ULL,
		0xC9FC8F89AE0C2917ULL,
		0x670B733A525CD4A5ULL,
		0x9D88ABB0C542F4ECULL,
		0xEC0789443EDA4067ULL,
		0xDDDC5E3B14F07748ULL,
		0x21BE019497AA06B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98891164C6CA1051ULL,
		0xE616351D201A86F2ULL,
		0x026FF2BA71525955ULL,
		0xFCC5299B41BEB1DBULL,
		0x0686D0A313B0D473ULL,
		0xA0366705DE7C9D06ULL,
		0x7BC5F1772144F3A6ULL,
		0x0C6CE4380221A5C8ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A7FED947D61F1B8ULL,
		0x43364DF5C7CE0771ULL,
		0x5BE1368829A94E82ULL,
		0xD36B5A2A4DB2E6E7ULL,
		0x5C627C5E2D112187ULL,
		0xC977F04D1A0F951CULL,
		0xC0334E7B9CA756A1ULL,
		0x452DC8483456D415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D1CBDAB2AC9A02AULL,
		0x410E25A236B5E895ULL,
		0x2266D2A82A2641F8ULL,
		0xD6F6CC674FB146EEULL,
		0x52855E83325DDA74ULL,
		0xD7B9BE7C44FD342CULL,
		0xD5DD6D2A40265684ULL,
		0xC3C8B5E874183A40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7763503F57A85192ULL,
		0x02386857F17BEFE4ULL,
		0x7987E420038F0F7AULL,
		0x059D964D0203A009ULL,
		0x0EE722DD1F4CFBF3ULL,
		0x1ECE4E315EF2A130ULL,
		0x15EE2351DC810025ULL,
		0x86E57DA0404EEE55ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F055E00C96429C8ULL,
		0x678B08CAC469C0C4ULL,
		0x7B95F26F534788DFULL,
		0xA4C3C41DDD964128ULL,
		0xAC99B665B2EE60B2ULL,
		0x916D9BF5DDABEB7FULL,
		0x629CF5701A0AD3A2ULL,
		0xA6F9C655A6B392E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92EFB55AF72C6EE4ULL,
		0xF2D949202B265B50ULL,
		0x44D245ACC4302C2DULL,
		0x628FFB7F5FC34FA7ULL,
		0xDB829EF03FAF93CEULL,
		0xC3D82770FF0E05D1ULL,
		0x3DF9DFD79A7F85F5ULL,
		0xDC64C41DF886308EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DEAEB5A3E48472CULL,
		0x955241EAEF4F9B94ULL,
		0x3F47B7C39777A4F2ULL,
		0xC64C3F6282550E8FULL,
		0x771B28958D41F37CULL,
		0x52B5BC8522A5EEAEULL,
		0x5F652AA780755657ULL,
		0x7A9D02485E35A266ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EE279A92B56F32DULL,
		0xFDFA94535CA8DDF2ULL,
		0x466204BDFE42EF59ULL,
		0x8E147C0E0442BC41ULL,
		0x509A1EB1A75B27AEULL,
		0x7A3F901D0179842EULL,
		0xDCDBD597EF2A5491ULL,
		0xEAA3898E6852A564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B90E1473D6BC8ABULL,
		0xDB8675461BFC2653ULL,
		0x6FC5C32698E9AB6EULL,
		0x4A72861E5EC69CC5ULL,
		0xC6826B1B4CF92775ULL,
		0x7EA34935FD34AC21ULL,
		0x307C3FF156A21F07ULL,
		0x1A43DB600BF96436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x257298EE163D3B86ULL,
		0x267CE1154754FBA1ULL,
		0x29A7C79B66AB4437ULL,
		0xC466FA105A842084ULL,
		0x961875AAEBA200DBULL,
		0x049CD928FC4D280FULL,
		0xECA7EA66B9884B96ULL,
		0xF0E052EE63ABC152ULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34FB0AEB25D75415ULL,
		0xE0BAFEE69A38AB71ULL,
		0x536BA269B9F33F05ULL,
		0xDD1617FF30447531ULL,
		0x1E025E340CC44A6BULL,
		0xE384ED14142DA852ULL,
		0x0310D3C4191E5C5FULL,
		0x6FC6836939DE0BF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x350A7BC09FA232AEULL,
		0xCA73118E1EC210B3ULL,
		0xACB70F76083E6216ULL,
		0x42FD8E4F33C3C867ULL,
		0xD112DECA901B0D92ULL,
		0x94C1D74A95FC6A04ULL,
		0x3862C4D531B70549ULL,
		0x9ED9B83EBC702058ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01F1712BBA7566BBULL,
		0x2AC9EF6884FABBC2ULL,
		0xFFDCAD1FB1CD5D13ULL,
		0x9FEB99B00387BD56ULL,
		0xCF1080FE9CDF47F9ULL,
		0x77453A5E81D1C256ULL,
		0x3B72171128A95916ULL,
		0xF11F3B5785AE2BAEULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AF57DADAC15FB38ULL,
		0xEAF00DD62ABCA4ACULL,
		0x3D1161BD5E6BA2E0ULL,
		0xA9BBCE1E82DB1B3FULL,
		0x2168C550F507EA1CULL,
		0x417E6419B29FD6EAULL,
		0x733097B03845E7E9ULL,
		0xD4DE58EB7E7B8DB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516EF845BF5445B6ULL,
		0x3D2F7A6456AFC0E6ULL,
		0xE194CF4632508D35ULL,
		0xCC66DBA2D9343E8EULL,
		0xEBAE7F1EFBB1817EULL,
		0x1938CFDD6DB10C61ULL,
		0xF60248DAAB06B3A3ULL,
		0x4E029171DCBCC36CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B9B85E81341BE8EULL,
		0xD7DF77B27C13644AULL,
		0xDC85AEFB6C3B2FD5ULL,
		0x65DD15BC5BEF25B1ULL,
		0xCAC6BA4E0EB66B62ULL,
		0x5846ABC4DF2EDA8BULL,
		0x8532DF6A9343544AULL,
		0x9ADCC99AA2C74EDAULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9885B3DEB3F44B8DULL,
		0x24743B0523AFA43AULL,
		0xD16C2C78E89930EFULL,
		0x0801F01066B5EF97ULL,
		0xAB7DC4301870B261ULL,
		0x53B0B429EEAE3599ULL,
		0x249A94BB07574502ULL,
		0xC031B38859421EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1C84BC99ED08BD1ULL,
		0xAB34BFE7638A0C2BULL,
		0x216DE8AEC1362B57ULL,
		0x3B84F14419737BF6ULL,
		0x76D55DA74B578235ULL,
		0x8332F4D93AB12BA0ULL,
		0x481AA6602B1F89A0ULL,
		0xE85487B8BE454F89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x694DF8172D24C05CULL,
		0x8F4084E24025A811ULL,
		0xF001C4D629AF1BB8ULL,
		0x338501547FC69461ULL,
		0xDDA8999753273054ULL,
		0xD08240F0D41F1E39ULL,
		0x6C8032DB2C48CCA2ULL,
		0x28653430E707512AULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4702DE7112CB24E5ULL,
		0x822B00598165A101ULL,
		0x3C9C79A136FDF3F7ULL,
		0x7CC985ED57DB9F7DULL,
		0x038F68AC7C54CB5EULL,
		0x6E6B34FF02417F54ULL,
		0xA5FFA2AB3800C249ULL,
		0xCD08CF0166B0175FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB60D8AF85EB2C8B1ULL,
		0xCD1EDD18615B9384ULL,
		0xA082DE513F7273FBULL,
		0x6B3A7B8EAA1A8A5FULL,
		0x51CECE56CC1F3441ULL,
		0xBE53193E5A3864AFULL,
		0x0A24E19E9EBB573CULL,
		0x2534C2DC2C5C7914ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF10F54894C79EC54ULL,
		0x4F35DD41E03E3285ULL,
		0x9C1EA7F0098F800CULL,
		0x17F3FE63FDC11522ULL,
		0x5241A6FAB04BFF1FULL,
		0xD0382DC158791BFBULL,
		0xAFDB4335A6BB9575ULL,
		0xE83C0DDD4AEC6E4BULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE062CCBE69B8148ULL,
		0x9F628B7EC5424217ULL,
		0x17184DA6E1E12B05ULL,
		0xEE04F261D4241492ULL,
		0x05E0B478C4398C5DULL,
		0xAA1550C4C1D73671ULL,
		0x41D87BC76602E068ULL,
		0x445915E389CD39FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE93A12CF6F1C02C1ULL,
		0xDE33C8CBD0C6DADDULL,
		0x6E69DBC997930886ULL,
		0xC5A1AFD54739FA9BULL,
		0x3CD1C735127876F6ULL,
		0x9B530C04F1CD49A7ULL,
		0x1532968AD85443EBULL,
		0x70B70567E20E3DA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x373C3E0489878389ULL,
		0x415143B5158498CAULL,
		0x7971966F76722383ULL,
		0x2BA55DB4931DEE09ULL,
		0x3931734DD641FAABULL,
		0x31465CC0301A7FD6ULL,
		0x54EAED4DBE56A383ULL,
		0x34EE10846BC3045FULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21762A2DDE671E66ULL,
		0xAA95EDC9F5FF42AAULL,
		0xABE35D19812321F0ULL,
		0x4572A0662DCBA22DULL,
		0xEC8A0CF864CE6BC8ULL,
		0x85376A529550C226ULL,
		0xD7518CA11A03229FULL,
		0xD47A4266BCA8EF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9999746A8C6F479ULL,
		0xAA4E7EC6264F6B86ULL,
		0x2DC121D46CFD1A52ULL,
		0x23CCE2AD04012EC1ULL,
		0x20508A7BCDC6662FULL,
		0x54E5306FFD962A29ULL,
		0xD8819D4A1B5242A6ULL,
		0xA97717D57C8A8063ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88EFBD6B76A1EA1FULL,
		0x00DB930FD3B0292CULL,
		0x86227CCDEDDE3BA2ULL,
		0x66BE42CB29CA8CECULL,
		0xCCDA8683A9080DE7ULL,
		0xD1D25A3D68C6E80FULL,
		0x0FD011EB01516039ULL,
		0x7D0D55B3C0226F30ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D6D823BCBD81DCEULL,
		0xDFD5EED60BBEA348ULL,
		0x53F936EE6A88AD02ULL,
		0x886D9761ECC51B9FULL,
		0x79EB328C95949807ULL,
		0x776A03947DC84962ULL,
		0x957E24E7C626A982ULL,
		0x14879F700CA0C3B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE879E1F0B59E6DD4ULL,
		0x40686338F012F6D7ULL,
		0x1862EDEF2C6DC6CEULL,
		0x90660F2D50836BE4ULL,
		0xC6C0B3FB781A6B2DULL,
		0x85E64F693297C63CULL,
		0x04AA3F3E0A9B931DULL,
		0x18A284B61889A904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD51463CB7E46701AULL,
		0x9FBD8DEEFBAC559FULL,
		0x4B9BDB0146E56BCCULL,
		0x180B984CBC46707BULL,
		0xBF2B8177ED8EF32AULL,
		0xF28C4CFD4F5F8F5EULL,
		0x91D41BD9CCBD3A9FULL,
		0x0C251BC614296AB5ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB292BFE84C933D4ULL,
		0xEB80BC1A89D3EF47ULL,
		0x6C936649AEE5109AULL,
		0x1943796B32112122ULL,
		0x61B2220DA7A9EE81ULL,
		0x0672F9F4745B811AULL,
		0x1641D52865917E62ULL,
		0x961C47616481CFA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72271C12B79EADEFULL,
		0xDF29BEE020F7DAD6ULL,
		0x54ED45ED1C4A32B7ULL,
		0xF8306EDF4A7EBA17ULL,
		0x3D563FA6189F9783ULL,
		0x26F8FC5090B68F5DULL,
		0x3CF8F389C7D01C9CULL,
		0x4022D7C752F24619ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x890E37EC33579E3BULL,
		0x34A902FAA9243591ULL,
		0x387E23A4B2AF222DULL,
		0xE17317B4786F9B35ULL,
		0x5CE41DABBF367902ULL,
		0x208A05A4E4ED0E47ULL,
		0x2AB926A1A24162FEULL,
		0xD63E90A6367389BAULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC254E8820D498D64ULL,
		0x4102BA65F4C55F8EULL,
		0xAB55D2B05A189EF8ULL,
		0xD8FFC36E396385B8ULL,
		0x87B15793C2AEFF28ULL,
		0x3F82F48855A1F35DULL,
		0x96F747BB83A6891AULL,
		0xCF3E8CDEB302AEEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2F5411D79BDFFBULL,
		0xF078AA956B6F0F61ULL,
		0x2ABA3C4777E62A88ULL,
		0x2881D412C5E508FCULL,
		0x9A7F4B169426C884ULL,
		0x01F88040BEFB80BCULL,
		0x0CFB20A0430F5D6CULL,
		0x04B62685F581577AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF87BBC93DAD2529FULL,
		0xB17A10F09FAA50EFULL,
		0x81EFEEF72DFEB470ULL,
		0xF07E177CFC868D44ULL,
		0x1DCE1C85568837ACULL,
		0x3E7A74C8EB5A73E1ULL,
		0x9A0C671BC0A9D476ULL,
		0xCB88AA5B4683F990ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x354D0759BEBEB160ULL,
		0xCE44C6152F533B8DULL,
		0xC6A7202C34002C1EULL,
		0x8DC78DD2E18388B9ULL,
		0xFFFF700002744637ULL,
		0xD7ED72BBA2200629ULL,
		0xA83B01A083369962ULL,
		0x5F492115F86A859BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E9A781373BF4E5ULL,
		0xE654CF3101678398ULL,
		0x97A3A0D781B5A48DULL,
		0x14F28BFE5F7FA708ULL,
		0x332DCA776BC56B91ULL,
		0x8A31BC707F903A70ULL,
		0xE92D12431AE0B698ULL,
		0x54A7D0A2BC9E3446ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1A4A0D889854585ULL,
		0x281009242E34B815ULL,
		0x510480FBB5B58893ULL,
		0x9935062CBEFC2FB1ULL,
		0xCCD2BA7769B12DA6ULL,
		0x5DDCCECBDDB03C59ULL,
		0x411613E399D62FFAULL,
		0x0BEEF1B744F4B1DDULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8525DEDA124C43AULL,
		0x7EECDEBCFAC7054AULL,
		0x64322D3DBB3ACD97ULL,
		0xC723B7B07A238B78ULL,
		0xDF14F29A7EDD8934ULL,
		0xB0AA0F727F393B11ULL,
		0xBE586D59C154AE30ULL,
		0x0F393A0A29DFC6D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABDEE0DF43713F30ULL,
		0xD076B686BBB9F4F3ULL,
		0x937608686D5A2FB9ULL,
		0x62B80E8346FDE275ULL,
		0xF025EB236152B78FULL,
		0xA2528729DE61AA0BULL,
		0xF17505ADD001955AULL,
		0x44C00619CB952817ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x038CBD32E255FB0AULL,
		0xAE9A683A417EF1B9ULL,
		0xF7442555D660E22EULL,
		0xA59BB9333CDE690DULL,
		0x2F3119B91F8F3EBBULL,
		0x12F8885BA158911AULL,
		0x4F2D68F411553B6AULL,
		0x4BF93C13E24AEEC5ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33F9F8A140C3B5FFULL,
		0x1D01DB395B07875AULL,
		0x1F4830D30951C934ULL,
		0x677750D5EAE515CDULL,
		0x20CFCCE64727E73BULL,
		0xCE4BA3C5FE30E1A5ULL,
		0xDD8E849DFEABBC16ULL,
		0xAC091643D456305BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA50890714D6DBAECULL,
		0xC39D278907D1DE13ULL,
		0x3CB596CA7671E930ULL,
		0x5A636FC988F3B5BDULL,
		0xE9431B78083D6AEDULL,
		0x4908205CAC534E16ULL,
		0x9FD0F38282A7034FULL,
		0x78F9BBCA66404929ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96F168D00DAE0F13ULL,
		0xDE9CFCB05CD65949ULL,
		0x23FDA6197F202004ULL,
		0x3D143F1C6216A070ULL,
		0xC98CD79E4F1A8DD6ULL,
		0x874383995263AFB3ULL,
		0x425E771F7C0CBF59ULL,
		0xD4F0AD89B2167972ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3088DF66DD4AE537ULL,
		0x9B04821E3FA9A224ULL,
		0x1B5E37EE07EBCAE0ULL,
		0x3AC6AA37AF373955ULL,
		0xFF9732D66913FA96ULL,
		0x12239762A78CF943ULL,
		0x2DA6BE8636F09FD4ULL,
		0xEEF76B6BE6170574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A64279B4AD8254ULL,
		0x38378AA4E55F4857ULL,
		0xC92807782F19EDBDULL,
		0x337AA1C139546692ULL,
		0x8D4CFD67DE79B957ULL,
		0x4A222AAF3DBAD8C5ULL,
		0x0070364B223E714FULL,
		0x7994155E96FC421FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF22E9D1F69E76763ULL,
		0xA33308BADAF6EA73ULL,
		0xD276309628F2275DULL,
		0x09BC0BF696635FC7ULL,
		0x72DBCFB1B76A43C1ULL,
		0x5801BDCD9A362186ULL,
		0x2DD688CD14CEEE9BULL,
		0x97637E3570EB476BULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE5DBE749A782388ULL,
		0x8995BB0B717965A5ULL,
		0xE699C0BA8457C154ULL,
		0x07FBF31EB665CBA6ULL,
		0xEB971B81E31D26C6ULL,
		0xA4BE856648F555E4ULL,
		0x642DEAC8614CFD2BULL,
		0xC34A22D970BE1468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E948457EE2A6B1ULL,
		0x6E718B5C03EEAB20ULL,
		0xA2E516E6DAFA6D14ULL,
		0x9967E7CC3E332AB5ULL,
		0xF837F2E3A7632E1DULL,
		0x0BE15EBEC02ABAEDULL,
		0xC0907176BAEDFBF4ULL,
		0xDCD6867B91704746ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFB4F631E49A8539ULL,
		0xE7E430577297CE85ULL,
		0x447CD65C5EADAC40ULL,
		0x9E9C14D28856E113ULL,
		0x13A0E962447E08DBULL,
		0xAF5FDBD888DFEF09ULL,
		0xA4BD9BBEDBA106DFULL,
		0x1F9CA4A2E1CE532EULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BBB53A349FCA5A7ULL,
		0x7F5153F324209B84ULL,
		0xA552E395F0A7599EULL,
		0xB89476E1216A29BAULL,
		0xCFA523D5168F6034ULL,
		0xD3388C7A9B2890F3ULL,
		0x638D8C2CE3EB2253ULL,
		0xF52EB53EFF30488EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB281C7E0DF8C63ULL,
		0x41B38C5859AF2C55ULL,
		0x0E0B8B9AF7996BDDULL,
		0xA82855E2AE6DA496ULL,
		0xF63E6AD2563D18F9ULL,
		0x309AAB62930BC822ULL,
		0x0EE597A863E14CFDULL,
		0xBDDDAE7CF12C635EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1709D264A92329C4ULL,
		0x3EE2DFAB7D8FB7D1ULL,
		0xAB59680F073E3243ULL,
		0x10BC23038F078D2CULL,
		0x399B490740B278CDULL,
		0xE3A22718082358D1ULL,
		0x6D681B84800A6EAEULL,
		0x48F31B420E1C2BD0ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC86D613290BA96F8ULL,
		0x9255D0051A5BCA88ULL,
		0xA330CC459671733FULL,
		0x892CC2FCBBB06FF7ULL,
		0x88DB81515653652DULL,
		0x494AA35A675EA6D1ULL,
		0xD32F88ABCEA2DDA6ULL,
		0xE56D397A263960EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x193F485B209B6629ULL,
		0x7716441B6A304B8EULL,
		0xDE7F7366CE8E4E5BULL,
		0xAC477E313F41B3F2ULL,
		0x81063B6089934E65ULL,
		0x44212DCD7CB24EF8ULL,
		0x4A5D8F156CB45008ULL,
		0x98D65F30BB0838D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1522969B021F0D1ULL,
		0xE543941E706B8106ULL,
		0x7D4FBF2358FF3D64ULL,
		0x256BBCCD84F1DC05ULL,
		0x09DDBA31DFC02B48ULL,
		0x0D6B8E971BECE829ULL,
		0x997207BEA2168DAEULL,
		0x7DBB664A9D315837ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD42EE955D69AD012ULL,
		0x061A6E4A450DFAB4ULL,
		0x3B96876C8B7BDEE6ULL,
		0xA3240609BB6F5223ULL,
		0x4758D2A751357721ULL,
		0x348EBAFA02E29330ULL,
		0x33B6926C760237D9ULL,
		0x901387928643EBA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167D85DF5279773CULL,
		0x1058B20037D38CE6ULL,
		0x0C66BADD9382FF2AULL,
		0x78C0CA38E2D09021ULL,
		0xE4B505F5D849D70EULL,
		0x31A970870962BCDBULL,
		0x870928D684FB6579ULL,
		0x390D9A669CCD358EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2536C8A84E3A72EULL,
		0x1642DC4A72DE7652ULL,
		0x37F03DB118F921CCULL,
		0xDBE4CC3159BFC202ULL,
		0xA3EDD752897CA02FULL,
		0x0527CA7D0B802FEBULL,
		0xB4BFBABAF2F952A0ULL,
		0xA91E1DF41A8EDE2AULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BF8830313259BFEULL,
		0x88B197A7078086DBULL,
		0xAF4FFA294150F3BCULL,
		0x03D3C5559ACE3A90ULL,
		0xA5094AFB65B55584ULL,
		0xDA77821859A13159ULL,
		0x677C7F238462A860ULL,
		0xC1C8E79F5EBDE7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A66FE3ED77407BULL,
		0x7D39FF251B7CFF8FULL,
		0xFD643A6BDF5E2B3AULL,
		0x0938E5AC9623ED8CULL,
		0xBF8717616C4889C6ULL,
		0x9AE7ABF2BBC25BC3ULL,
		0x9004E079DFA316A0ULL,
		0x67492D96857421D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235EECE0FE52DB85ULL,
		0xF58868821CFC7954ULL,
		0x522BC0429E0ED886ULL,
		0x0AEB20F90CEDD71CULL,
		0x1A8E5D9A09FDDC42ULL,
		0x409029EAE2636A9AULL,
		0xF7789F5A5BC1BEC0ULL,
		0xA681CA09DBC9C666ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBABA58D06D1D674EULL,
		0x87C9E2ED83C9E890ULL,
		0x07BEDCD64034EA1EULL,
		0x5035383F325C8149ULL,
		0x6533FAF8C3B882AEULL,
		0xC0679A97E6EA1AF1ULL,
		0xAB072F3697B4D465ULL,
		0x66114F8DB1DF51EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF60C69A12DE67486ULL,
		0xD343300A10D8D0E8ULL,
		0xCED113F2B2A8F64BULL,
		0xBF5240445D7ABA7CULL,
		0xECF4A7CDBB8862C7ULL,
		0xCB6E1954B3A2B670ULL,
		0xAFD44D4FE5213439ULL,
		0x58195F1194B88723ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CB6317140FB13C8ULL,
		0x548AD2E793113878ULL,
		0xC96FCF24F29C1C55ULL,
		0xEF67787B6F263B35ULL,
		0x89C75D357830E069ULL,
		0x0B0983C35548AC81ULL,
		0x04D362797295E05CULL,
		0x3E08109C2567D6C8ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6787700EDBD50ADBULL,
		0xE8197BC9F6C3F057ULL,
		0xEC6D8E6F1F3D2D20ULL,
		0xB0CF4DCC7CEDD125ULL,
		0x79841C4F807EE5F2ULL,
		0x2E3E328344221B80ULL,
		0xF5506E9005D86C32ULL,
		0x4C8177F85A1BC2DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABDBD87165E1AF74ULL,
		0x13C85F712FB5DD16ULL,
		0xD16731C9D9484652ULL,
		0x462587DF70DF710AULL,
		0xD674FFB6618E6C8BULL,
		0xFFF74D71EDADA1CEULL,
		0xFC627F7A7AFCE90BULL,
		0x072E232882C0A592ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC5CA87FBE34A5AFULL,
		0xFBD124B8D9762D41ULL,
		0x3D0ABFA6C6756B72ULL,
		0xF6EACA130C32A02FULL,
		0xAFF0E3F9E1F08979ULL,
		0xD1C97FF2A98FBA4EULL,
		0x093211EA7F248539ULL,
		0x4BAF54D0D8DB674FULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F451730E882C2FFULL,
		0xFC74FB0ED8F63D46ULL,
		0x80D26B0D044DF754ULL,
		0xF5E52CF21A6AB9C5ULL,
		0xAD4A4359C2D39D6FULL,
		0x27DA0F2CF470FF08ULL,
		0x2FCE1A88EB3D6F8DULL,
		0x1FF4F2927557CB91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B9265622AD4D1B7ULL,
		0x5AACFCD679E59A0EULL,
		0x2E217DD761C03E3AULL,
		0xE64B299F2C1075FCULL,
		0xB6D7C4EA142B1D50ULL,
		0x70D8464686961EDAULL,
		0x16209B32531F15DEULL,
		0x9D9A2A912EB6C14CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04D77252C2561348ULL,
		0xA6D807D8A113A748ULL,
		0xAEF316DA658DC96EULL,
		0x13AE056D367ACC39ULL,
		0x1B9D87B3D6F8803FULL,
		0x5702496A72E6E1D2ULL,
		0x39EE81BAB8227A53ULL,
		0x826ED8035BE10ADDULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1132B121D83AABULL,
		0x08436811861796D5ULL,
		0xAA4779F55C868874ULL,
		0xB421F3F6C4BC0595ULL,
		0x8A343CE2BF309AB7ULL,
		0x917980B16FC1B674ULL,
		0xDE811E3101707E4DULL,
		0x2592A93CACB5CEA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80FE401C518A1792ULL,
		0x3026F830418F5053ULL,
		0x3489C081B8C95141ULL,
		0xE8940B601D8F665FULL,
		0xA16B79878EEE4514ULL,
		0xF0F453A9D5F10BB6ULL,
		0x324CF8CAA863A382ULL,
		0x0525EF771E04D54EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCEF72AD70522D39ULL,
		0x38659021C798C686ULL,
		0x9ECEB974E44FD935ULL,
		0x5CB5F896D93363CAULL,
		0x2B5F456531DEDFA3ULL,
		0x618DD318BA30BDC2ULL,
		0xECCDE6FBA913DDCFULL,
		0x20B7464BB2B11BEFULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D41426171E22A3DULL,
		0xEF70154E8C27A017ULL,
		0xD49FFA25F559560CULL,
		0xBE4A89419D1B300DULL,
		0x0BE99067E599AC2FULL,
		0x54B208AF66876315ULL,
		0x4CF7CD7E6E37FB59ULL,
		0x13124F21506BB284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE238100BEBAF785AULL,
		0x3ED78E9EF494B9ADULL,
		0x031F9440F08FBDBDULL,
		0x3ECC28AE873DA0BEULL,
		0x37D5AA7C0C73C202ULL,
		0x0DB1390954767B86ULL,
		0xA813B52005F97FFCULL,
		0x77425C3BB7C75FD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF79526A9A4D5267ULL,
		0xD1A79BD078B319BAULL,
		0xD7806E6505D6EBB1ULL,
		0x8086A1EF1A2690B3ULL,
		0x3C3C3A1BE9EA6E2DULL,
		0x590331A632F11893ULL,
		0xE4E4785E6BCE84A5ULL,
		0x6450131AE7ACED51ULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8EC440089B0C5DAULL,
		0x7A7F39B12BBE3105ULL,
		0x0584AEBA6C54557AULL,
		0x42BD3EB4011F0F2BULL,
		0xF2E48458AF4D3341ULL,
		0xEE1B116A35FD906AULL,
		0x198C8C2AC3B8329DULL,
		0x9394EB4BBE9D6CBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC62BB3DDCDE82597ULL,
		0x9994B1392AE603B5ULL,
		0x67ADCCF43E7466A4ULL,
		0x16E87419C95898B0ULL,
		0xA925D5974E216585ULL,
		0x8FC2C618BBC8779AULL,
		0x9221A286BF6F6A9BULL,
		0x6DA1C765A3371E53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EC7F7DD4458E04DULL,
		0xE3EB8888015832B0ULL,
		0x6229624E522033DEULL,
		0x54554AADC847979BULL,
		0x5BC151CFE16C56C4ULL,
		0x61D9D7728E35E7F0ULL,
		0x8BAD2EAC7CD75806ULL,
		0xFE352C2E1DAA72ECULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99BAAFECD2A1FCF5ULL,
		0x45B9952161F7023BULL,
		0x113B039F60A0693CULL,
		0x71E30BED06F9A362ULL,
		0x950DF68A4E92D357ULL,
		0x3BFA0568B75B9C56ULL,
		0xB7E8B4D16BD69466ULL,
		0x4EBE53E8B3719135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F52E0B18D4B8B8ULL,
		0xE6C57B022AB367F7ULL,
		0xC7F9BC88A3705FEFULL,
		0x8752CDCD1EFB2681ULL,
		0x866013EC0242BF86ULL,
		0xD00BC4503C6C28B6ULL,
		0x402DEC0D598F5A50ULL,
		0x80727E702BD1354AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B4F81E7CA75444DULL,
		0xA37CEE234B4465CCULL,
		0xD6C2BF17C3D036D3ULL,
		0xF6B1C620180285E3ULL,
		0x136DE5664CD06CD1ULL,
		0xEBF1C1388B37B4E0ULL,
		0xF7C558DC3259CE36ULL,
		0xCECC2D9898A0A47FULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BD69237D575B2FCULL,
		0xE37ABD217DE33456ULL,
		0x8E74F9169DF63818ULL,
		0x749D4D5293588766ULL,
		0xA616FFFD88E787F7ULL,
		0xBC5276A4F79D03B7ULL,
		0xB51531EED5868EA9ULL,
		0x885E880341F1917FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC167FF0D9B9821ULL,
		0x982DBF6D130E03D2ULL,
		0xA8C34739B96B3A39ULL,
		0xE29F313E998671CFULL,
		0x1F1D50A4CB4C6C27ULL,
		0x9B69063A9C24563EULL,
		0xF2EEC22F44F7E111ULL,
		0x381A2FEE0D93D183ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1617F5C8D8EE2ADDULL,
		0x7B57024C6EED3784ULL,
		0x26B7BE2F249D0221ULL,
		0x96027C6C0ADEF6A9ULL,
		0xB90BAF5943ABEBD0ULL,
		0x273B709E6BB95589ULL,
		0x47FBF3C191716FB8ULL,
		0xB044A7ED4C6240FCULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDF83193DF341049ULL,
		0xF1FCB3FBE8E2D777ULL,
		0x79211D4D5A61574CULL,
		0xE667946ADCA52E7CULL,
		0xDCAFCD701275C00CULL,
		0xF0F77DCDFCAA6DDDULL,
		0x9B9A67340AC1CFDDULL,
		0x8DC5FEC68F2DAB41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC583BA2B2CC19F6EULL,
		0x305E9A039E8AE9CEULL,
		0x8DCE0ADB29193F37ULL,
		0x496B2C668F307E5BULL,
		0xDA5194AF602C38EBULL,
		0x6F179D2E01A6F20BULL,
		0x59B567490E580DE1ULL,
		0x2393BF540B0FADF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x187B8BB8F3F58F27ULL,
		0xC1A229F876683EB9ULL,
		0xF4EF17967378687BULL,
		0xAF0CB80C53955027ULL,
		0x06FE59DF7259F8E7ULL,
		0x9FE0E0E3FD0C9FD6ULL,
		0xC22F007D0499C23CULL,
		0xAE564192842206B4ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4F48CE3D39DF008ULL,
		0xF29142A0724F672CULL,
		0x0CCCA9459E56B69FULL,
		0xC104B29D8818DABCULL,
		0x4C0070AEA30AB20BULL,
		0x9339C7A111D01688ULL,
		0xF72F0A84AA613108ULL,
		0xFEF6A064EE1A0F7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DDFA465F014B1FCULL,
		0xF3206B3C30CE850EULL,
		0x7451F1DA808C4F9EULL,
		0x5CD2C336117760C8ULL,
		0xE0724DF7442334E1ULL,
		0x9FA1E2C237AFED1BULL,
		0xDCFF41D5CAE2BE2DULL,
		0xA07DF948FDF95EC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD92B2886238941F4ULL,
		0x01B1299C4281E222ULL,
		0x789D589F1EDAF901ULL,
		0x9DD671AB996FBA74ULL,
		0xAC723D59E72986EAULL,
		0x0C982563267FFB93ULL,
		0x2BD04B5160838F25ULL,
		0x5E8B592C13E351BDULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFF503414CD90441ULL,
		0xA9BF7F4A9E79B4A5ULL,
		0x4ECE7961BAEC003AULL,
		0x05917CFE35E251A9ULL,
		0x6423BAB31CC2A2D0ULL,
		0x05D38E51DD2F7163ULL,
		0xF1C8F532E5B4D34DULL,
		0xF97BCBA1530D1EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA806340936D88CFULL,
		0xE4CF6FCCFDB184F6ULL,
		0xA0C2A42C1404ACA0ULL,
		0xEF934F427C0734A9ULL,
		0xED22902D30893BBEULL,
		0xCC2995FB56E50215ULL,
		0x004E2359CD859EEBULL,
		0xC91C2F88A5A61917ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15756001DFB48C8EULL,
		0x4D70108663C83053ULL,
		0xEE0CDD4DAEE8AC9AULL,
		0xEA0233BC49E56500ULL,
		0x89012A9E2C4B996EULL,
		0xC9FA1BAA8BCA7376ULL,
		0xF186D66B28314DA6ULL,
		0x3067E429F6AB07A6ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA8854CC1EBDCF7ULL,
		0x10BF1D53AF0E97AFULL,
		0xDACAAD4ECDF20C5BULL,
		0xDB34686E124C88A9ULL,
		0xE6798C56F59BE973ULL,
		0x8A56328565454DFCULL,
		0x965A2AD28EEAF06AULL,
		0xEACB909F5A39A908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEE741895FD49C9ULL,
		0x7D018D540B0D4865ULL,
		0x8D8EC45A2422C29CULL,
		0x343E9259D4EA6B2DULL,
		0x29CC0CAD6C6F4DBAULL,
		0x8A7540B8C7155374ULL,
		0xD002B589C9177022ULL,
		0x78E55B047F1EC840ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0346F1545416953EULL,
		0x6DBE9007A403DFCAULL,
		0x57446914E9D0CEC7ULL,
		0xEF0AFA37C6A6E384ULL,
		0xCFB580FB99F4A4C9ULL,
		0x0023723DA2501E88ULL,
		0x46589F5B47FD8048ULL,
		0x922ECB9B25276148ULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC348567B84EDC23ULL,
		0x866310D0632AC9E5ULL,
		0xF8888CAD99F04F5DULL,
		0x7A3B53CC32A5DC98ULL,
		0x0B6187BD89E62EB7ULL,
		0xE421A5B77F1B2B43ULL,
		0x8A490E7E56FF98EFULL,
		0xBC877B3C7D635660ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DAE7E3831D6561ULL,
		0xA27A83C3073A1C1CULL,
		0xEB9BF950B59FD4F0ULL,
		0x60B463A4CFB54035ULL,
		0xA66AC42854C0E24CULL,
		0x7C7E1085EB38B686ULL,
		0x97B5FAEB0DA80D82ULL,
		0x739EC0BC3CD4043DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FEE62843B53B942ULL,
		0x241993136410D5F9ULL,
		0x131375FD2C6F9BADULL,
		0x1A8F3068FD109CADULL,
		0xAD0B4395DD26CCFBULL,
		0x985FB53294239DC5ULL,
		0x1DFCF4955B57956DULL,
		0xCF19BB8041B7525DULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D8C97CEE9D38C23ULL,
		0x7098072DA62627B3ULL,
		0xF9997AE98534E8B5ULL,
		0x24DCF4D2F791A40AULL,
		0x8297A531608D122FULL,
		0x06AFFC629E2A2C90ULL,
		0xA9D06AA1AA075BBAULL,
		0x4FDACD17619BBC0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AF60C335395B56CULL,
		0x3FDF1077917123B4ULL,
		0x9703309EE3C6569BULL,
		0xAFAA4D79B6771CEDULL,
		0x74AAA90C58EC7114ULL,
		0x3A8D35C8090C8A66ULL,
		0x675E690B647A285DULL,
		0x24A6EF657A9D731EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x077A9BFDBA46394FULL,
		0x4F47175A37570407ULL,
		0x6E9A4A7766F2BE2EULL,
		0x8B76B9AB41E6B8E7ULL,
		0xF63D0C3D3861633BULL,
		0x3C22C9AA9726A6F6ULL,
		0xCE8E03AACE7D73E7ULL,
		0x6B7C22721B06CF14ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A7900E99A4D02B4ULL,
		0x6F0A86D7CAE9A6C2ULL,
		0xF13232C1D706F71AULL,
		0xB8C8E67338A76DD0ULL,
		0xAE5DAB32C8ED8AAAULL,
		0xBD5AC678985F43B1ULL,
		0xC1CB55F2F27BC40DULL,
		0x96680C10A5CE199EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D33627211EC57A8ULL,
		0xCA1069A39F60CDB2ULL,
		0x8059F9D8FA2536C1ULL,
		0xC8F7891ECD586B40ULL,
		0xFD574A1E7E89BB19ULL,
		0xA7498CD3F37A5323ULL,
		0xAEA86F7E085BFC54ULL,
		0xBBA33749AB1C23E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x474A629B8BA1551CULL,
		0xA51AEF7455896B70ULL,
		0x716BCB192D23C1DBULL,
		0x703F6F6DF5FF0690ULL,
		0x530AE12CB66431B3ULL,
		0x1A134AAB6B251092ULL,
		0x6F633A8CFA203859ULL,
		0x2DCB3B590ED23A7CULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DAAC8A0A8CA8030ULL,
		0x7A3CA9178532F8C4ULL,
		0xE4F0FFE6A74A5099ULL,
		0x9BEE60C47445E256ULL,
		0x1FE497568AF9FE4CULL,
		0xA762762E2CCC1963ULL,
		0x61D9EAC586B3AFDEULL,
		0xC82BD08B52E28926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0BB09AB76C48185ULL,
		0xBD67441C8FB1A4C1ULL,
		0x2A87AC3D4EB8EDC5ULL,
		0x4FABD190A637A2FBULL,
		0x7507E2C3A81186B2ULL,
		0x577BB02A3DE8401CULL,
		0x4C668A5A73D66569ULL,
		0x130D10D71F3FF85EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D11C10BDE0E01B5ULL,
		0xC75BED0B0A835C05ULL,
		0xCE7753DBE9F2BD5CULL,
		0xD445B154D27240ADULL,
		0x6AE3759522E878FEULL,
		0xF019C6041124597FULL,
		0x2DBF609FF565CAB7ULL,
		0xDB26C05C4DDD7178ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9088CEC2A7B9D236ULL,
		0x4382869B7E72BE7FULL,
		0x68DD12070DC0B7EBULL,
		0xA598B61E40AF29DBULL,
		0x441727CFF3C11D21ULL,
		0x10FB15B57FE89F84ULL,
		0x5F494FE45A469B77ULL,
		0x0A7EA0ADFBAF7DC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C0EF82B111DADFULL,
		0x55C3EE51EAD87B27ULL,
		0x60C500083157C143ULL,
		0x4E861D497CE33557ULL,
		0x5E3B6D1800CD448EULL,
		0x851EA7603F48161DULL,
		0x2B36D3C4F1D85AE4ULL,
		0x446C0B49B807437BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7348214016A808E9ULL,
		0x164168CA94AAC558ULL,
		0x0818120F3C9776A8ULL,
		0xEB1EAB573C4C1C8CULL,
		0x1A2C4AD7F30C59AFULL,
		0x95E5B2D540A08999ULL,
		0x747F9C20AB9EC193ULL,
		0x4E12ABE443A83EBAULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EB90617FA683F33ULL,
		0x8A387705361985BEULL,
		0x98BB6384B4E16AF1ULL,
		0xA3A7902820936AD8ULL,
		0xDD89E310EADF35B5ULL,
		0x9C9BCE148A3D057EULL,
		0x7D68A3F6DBC0EE43ULL,
		0x5EE3370B9DA420C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D4B7C52FEBF5809ULL,
		0x1E665991DCD5842CULL,
		0xCB3FDE60785E863AULL,
		0x8E8F62B4E16F49C4ULL,
		0x5EE615D52D4A9AB6ULL,
		0x091614B5C7584ADCULL,
		0xD073CBAA9CE41615ULL,
		0x5CD963ED006AC7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13F27A4504D7673AULL,
		0x945E2E94EACC0192ULL,
		0x5384BDE4CCBFECCBULL,
		0x2D28F29CC1FC231CULL,
		0x836FF6C5C795AF03ULL,
		0x958DDAA14D654FA2ULL,
		0xAD1B685C4724F856ULL,
		0x023A54E69DCEE72EULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x723C7DB12ACF2C90ULL,
		0xE2E8C95261C28E7DULL,
		0x9569C83C97974B68ULL,
		0xF274637D5178B26FULL,
		0x193FD5F47DA62EF9ULL,
		0x792F59BD3B4C220FULL,
		0x5191119E7A6DBF90ULL,
		0x250778CA2B7E2CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6127416C634E43EULL,
		0x825D45D515DB355EULL,
		0x6E2FA2B5258DFABDULL,
		0x6355B83C70E7F1F4ULL,
		0xEEB94F28F03626A8ULL,
		0xD2F87AA3E813AB19ULL,
		0xF67EA22088572AB5ULL,
		0x937792A96B179F1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB42E09A7ECFBC8AEULL,
		0x60B58C877419BB23ULL,
		0xFB466A89B21AB1D5ULL,
		0x9121DB41219F439BULL,
		0xF7869ADC8D900851ULL,
		0xABD7231ED35F8916ULL,
		0xA7EFB3BEF23A9525ULL,
		0xB670EA634069B3CBULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD496CA0A9A26222CULL,
		0x9842C316A98E72E2ULL,
		0x471FF0A38955036FULL,
		0x25C11C3BD820D978ULL,
		0x8580A708BDF121B3ULL,
		0x83B7EC87302D2265ULL,
		0x39991AA79B5FDD8EULL,
		0xFD732C48FD13FD90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5FD98F682C92AE1ULL,
		0xFB6922B59E06F7D3ULL,
		0x4DDCE88351ABD9A3ULL,
		0x546BA5ADF8B9DAA3ULL,
		0x8F18317B0B1888E3ULL,
		0x4F8D2912B7CB77F5ULL,
		0xB6EFAF74CA040008ULL,
		0xACA447FEA6E9782DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x616B52FC18EF08CDULL,
		0x632BE1A337888531ULL,
		0x0AC31820D8FEDACCULL,
		0x71AAB996209903DBULL,
		0x0A989673B6E9A950ULL,
		0xCC3AC59587E65590ULL,
		0x8F76B5D3515BDD86ULL,
		0x51D76BB65BFA85BDULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FFD4F18BFEBD26DULL,
		0x8102366ED5C35FC6ULL,
		0xF1792C75D032E04BULL,
		0x09FBC4D42A089708ULL,
		0xBADEDE15FF62DC66ULL,
		0xFF0BCF36AE888240ULL,
		0xA1D88663C911A80DULL,
		0x5AA6F0059FEC1B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25291215837F5874ULL,
		0xB3FFD48894AF0AEDULL,
		0xAE70CEFBE37270A1ULL,
		0xA5F7A9E8EBDA1D00ULL,
		0x40DC04036D8006A9ULL,
		0x791B1ECBEFA9D5B6ULL,
		0x017283DDF423D1CCULL,
		0xB73C13C3257E6111ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AD45D0D3C948A19ULL,
		0x32FDE2E6416C552BULL,
		0x5F09E28E334090EAULL,
		0xAC0C6D3CC1D28A08ULL,
		0xFA02DA1692E2DACFULL,
		0x8610D1FD412157F6ULL,
		0xA0AA05BE3D3279C1ULL,
		0xED9AE3C6BA927A68ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x271B93C254FD4829ULL,
		0x4066D977D838BD43ULL,
		0xE796A30A017EF4E0ULL,
		0x5BF6031BC57D72E1ULL,
		0x22ED7A19A3FDBEEEULL,
		0x489EBC6C19925663ULL,
		0x55C0AF8EE02B5557ULL,
		0x78725A69EB25DA56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEFCAF66FC43C4A0ULL,
		0x12A39D986B36758EULL,
		0x1E3D12C3174BF879ULL,
		0x798294052C154D6EULL,
		0xCBC2DBA5A2A130EAULL,
		0x7247420B12EE8875ULL,
		0x1658B009926C25ADULL,
		0xBB4BFD9148D2B442ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9E73CA4A8BE8C89ULL,
		0x52C544EFB30EC8CDULL,
		0xF9ABB1C916350C99ULL,
		0x2274971EE9683F8FULL,
		0xE92FA1BC015C8E04ULL,
		0x3AD9FE670B7CDE16ULL,
		0x43981F87724770FAULL,
		0xC339A7F8A3F76E14ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE93C57AF48227B7ULL,
		0xF7F54113C5D260ABULL,
		0x5514CFB151689C36ULL,
		0x990E12ECDC8029FEULL,
		0x50D1890CE2E3AA44ULL,
		0x7D75F22AAA9C5DA0ULL,
		0x8F9A99CF42A2E3DAULL,
		0xEFED6CEEE8DFEBB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0453E279861DA78ULL,
		0xB0308AD2FF1F9D4FULL,
		0x8F044778B69E3DD9ULL,
		0x88CB2F6DAD3892F4ULL,
		0xC65BD86BA6C6B9DAULL,
		0xDF30557BB8C1F2B4ULL,
		0xB92427A05FFEEDBCULL,
		0x1F38D6E38216C15DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ED6FB5D6CE3FDCFULL,
		0x47C5CBC13ACDFDE4ULL,
		0xDA1088C9E7F6A1EFULL,
		0x11C53D8171B8BB0AULL,
		0x968A51674425139EULL,
		0xA245A751125DAF14ULL,
		0x36BEBE6F1D5C0E66ULL,
		0xF0D5BA0D6AC92AEEULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC64689085D9A0E4ULL,
		0xE004D5E9AB25BDC8ULL,
		0x4A204EF5D109A5FAULL,
		0xE8D961732A462041ULL,
		0x12B247F0F9421E87ULL,
		0xBBB17A395D520FAFULL,
		0x7ABBE6771B157E63ULL,
		0xF02E9B8FB181123DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B51E1F1B5EDBB95ULL,
		0xAFEB3C4C882F66B9ULL,
		0x771A727B45EAB440ULL,
		0x543CB7B474BD74EEULL,
		0x810F9A769CAB2654ULL,
		0x4ACC462DADA2BEC8ULL,
		0x9AA8C9AA8C355333ULL,
		0x87B3EA66DDB318B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7735896130341B71ULL,
		0x4FEFE9A5230ADB71ULL,
		0x3D3A3C8E94E311BAULL,
		0xBCE5D6C75EFB54AFULL,
		0x93BDDD8665E938D3ULL,
		0xF17D3C14F0F0B167ULL,
		0xE0132FDD97202D50ULL,
		0x779D71E96C320A8DULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8C2E047BB9E37A5ULL,
		0x4C6D62B469FFA878ULL,
		0x202CE9826EF7D987ULL,
		0x2BB23D63694B3917ULL,
		0x555E442655CE1614ULL,
		0xCBD6777F606404AAULL,
		0xE6D87B1C92B4A304ULL,
		0x0DC210D1665D5DD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB894C395D52BE25ULL,
		0x3941A248A58A068FULL,
		0xCB468A376250B9F0ULL,
		0x5711F069326EE15EULL,
		0x373102D03647A50EULL,
		0x3C5576412D39E62FULL,
		0x2C0A95841D1A704EULL,
		0x4BA6E4BAE3972042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x534BAC7EE6CC8980ULL,
		0x752CC0FCCC75AEF7ULL,
		0xEB6A63B50CA76077ULL,
		0x7CA3CD0A5B25D849ULL,
		0x626F46F66389B31AULL,
		0xF783013E4D5DE285ULL,
		0xCAD2EE988FAED34AULL,
		0x4664F46B85CA7D9BULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE092BA51C10CEE57ULL,
		0x666CB22D78367478ULL,
		0x7AAA311D4910297CULL,
		0x911105C6A9737EECULL,
		0xA686FB24A0B44F24ULL,
		0x331E1ABE46154491ULL,
		0x8CBD6475D14E256FULL,
		0x491A622319D48EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0146BAF9AE9E0A1CULL,
		0x0E79ABA7F23D6BAAULL,
		0x53B2C0AAF223AEB2ULL,
		0x4E109CE3E49E47A6ULL,
		0x03D255F948B112B6ULL,
		0x431349E821C81D99ULL,
		0x91A933C3F9A0BBF2ULL,
		0x8F36756BD4F9BF89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1D400A86F92E44BULL,
		0x6815198A8A0B1FD2ULL,
		0x2918F1B7BB3387CEULL,
		0xDF0199254DED394AULL,
		0xA554AEDDE8055D92ULL,
		0x700D535667DD5908ULL,
		0x1D1457B628EE9E9DULL,
		0xC62C1748CD2D314CULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C80649767E4F3D4ULL,
		0xE5D26A888FFEED5BULL,
		0x5D26B2974C057715ULL,
		0xF19B0757AFD249F7ULL,
		0x50A07487ECB50B3AULL,
		0x87F0A5EADB30CF2EULL,
		0x352D04334772BD7EULL,
		0xA8728F9C0F1DF99BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB921308BBFA241C8ULL,
		0xCA3E9B675994CF07ULL,
		0x3DBEE2E5659DC16BULL,
		0xB50143EEA6BD75F3ULL,
		0x3BE6B415C46BBDD2ULL,
		0x92418351037325FAULL,
		0xA34BD294BA6F6FFAULL,
		0xA132A6A6530D7E38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35A1541CD846B21CULL,
		0x2FECF1EFD66A225CULL,
		0x609850722998B67EULL,
		0x449A44B9096F3C04ULL,
		0x6B46C09228DEB6E8ULL,
		0x15B126BBD843EAD4ULL,
		0x9666D6A7FD1DD284ULL,
		0x0940293A5C1087A3ULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB06DCF0D57E1F1F9ULL,
		0xB9866107F04610BCULL,
		0xC376CD75E9896D08ULL,
		0xD32C27BF7F7C1C34ULL,
		0x21C815EA7B2808D9ULL,
		0x2F37CC2CC47F5FC5ULL,
		0xE098617723B9774FULL,
		0xE52D0489E8297743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1E9D2D67C927E4EULL,
		0xD46A985BFAD42B92ULL,
		0x56E2C394073F2F1BULL,
		0x07CB7ACE24027B4EULL,
		0xD97A251317C1297AULL,
		0x3C5C586164204565ULL,
		0x7B6D14429F6AB2CEULL,
		0x45B1F74E4DA6B0FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41841DDB2B738FB7ULL,
		0x6DECF95C0A923B2EULL,
		0x95940EE1EEB64213ULL,
		0xD4E75D715B7E677AULL,
		0xF8B230F96CE921A3ULL,
		0x136B944DA05F1AA0ULL,
		0x9BF57535BCD3C581ULL,
		0xA09CF3C7A58FC7BCULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C17E034CF490536ULL,
		0x1EF2691BC62994C5ULL,
		0xC040051F76D92E2FULL,
		0x9ECF2E35F85C6567ULL,
		0x1056261A13CA63C0ULL,
		0xC51148E7F6B5F3FEULL,
		0xCC6D2C4EF726BEF9ULL,
		0x05B497871D54CB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FFD1B7FEDE7A4E8ULL,
		0x3F1F293B64B63613ULL,
		0x677C26415EF5C3DFULL,
		0xE0DB4DF012AB3CBDULL,
		0xAFC059E569C38222ULL,
		0xE8301ECFBBE0F9A3ULL,
		0x344686E12A13DCFFULL,
		0xA9F7E4BEA4BA6C18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3EAFB4B22AEA1DEULL,
		0x21ED4020A29FA2D6ULL,
		0xA73C235E282CEDF0ULL,
		0x7E1463C5EAF759DAULL,
		0xBF967FFF7A09E1E2ULL,
		0x2D2156284D550A5DULL,
		0xF82BAAAFDD356206ULL,
		0xAC437339B9EEA797ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99957C841E512902ULL,
		0x2164BD19D269646AULL,
		0xE843098C1E6FE3EBULL,
		0x40D952EE21F3CB5AULL,
		0x7A44197EAE424618ULL,
		0x8415F0F3A1AEB6D1ULL,
		0xEF44900A6C4E05DEULL,
		0x589B132FC62E4197ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169F717EE7C0EDCEULL,
		0xCB35D9ADB2246D07ULL,
		0xFC58A7B6795BD8C0ULL,
		0x9A6F1C155A966A36ULL,
		0x973F376100D9F992ULL,
		0x34B1351EC3064605ULL,
		0xA59EB9139185F93CULL,
		0xCA6F1BD2A8C73AF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F0A0DFAF991C4CCULL,
		0xEA5164B4604D096DULL,
		0x141BAE3A67343B2BULL,
		0xDAB64EFB7B65A16CULL,
		0xED7B2E1FAE9BBF8AULL,
		0xB0A4C5ED62A8F0D4ULL,
		0x4ADA2919FDCBFCE2ULL,
		0x92F408FD6EE97B67ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x809878B3074E54CAULL,
		0x0B4E4A980B35B016ULL,
		0x2A9C60726AAA0A2DULL,
		0x0CE7B90625B3A21EULL,
		0xA505E1471B0A764DULL,
		0x66DA8F2458C1824DULL,
		0x494C0F171AC2D180ULL,
		0xA17BA7FE5CC3C98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B32AAEE1A0EBCC9ULL,
		0x905811E26F69B8A9ULL,
		0x966F2BB4A03C0A9DULL,
		0x1315BBFC7C9CFA49ULL,
		0xE8B125B26136DD14ULL,
		0xA55235C2FA0C4579ULL,
		0x7DED3498F5A9D1FDULL,
		0x623B26221D857AE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BAAD25D1D40E803ULL,
		0x9B165B7A645C08BFULL,
		0xBCF34BC6CA9600B0ULL,
		0x1FF202FA592F5857ULL,
		0x4DB4C4F57A3CAB59ULL,
		0xC388BAE6A2CDC734ULL,
		0x34A13B8FEF6B007DULL,
		0xC34081DC4146B36BULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C56841AFEB07EF4ULL,
		0x8E003A08791619C5ULL,
		0x3EDA62336A360A6FULL,
		0xB1E7981A060ABF4FULL,
		0xC3F5AEA07CBFC849ULL,
		0xD0137AD96181B7BDULL,
		0x7E3A293ECCDF62C2ULL,
		0xF9B0199493A1AEBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB696FD6737CB9BULL,
		0xC43F11E7C3EC3EB7ULL,
		0xD56B0BA61A8C3CFFULL,
		0x11C747BB45119E34ULL,
		0x1142729734CF0E27ULL,
		0xA1961252C9D9C10DULL,
		0xB71E283A0CB1760FULL,
		0x076268CA480C3150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86E012E79987B56FULL,
		0x4A3F2BEFBAFA2772ULL,
		0xEBB1699570BA3690ULL,
		0xA020DFA1431B217BULL,
		0xD2B7DC374870C66EULL,
		0x7185688BA85876B0ULL,
		0xC9240104C06E14CDULL,
		0xFED2715EDBAD9FECULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FF46533E6DF70B2ULL,
		0x4B83A0B614B306D8ULL,
		0x415762858905F926ULL,
		0xFED2F77B8793229FULL,
		0x685ACDCB28C6EA96ULL,
		0x3A5256E9704F8B95ULL,
		0x297D1ACFA5B080A3ULL,
		0x355AF281D53F79DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x759E4B03367A03D2ULL,
		0xC50A080511041961ULL,
		0xB5A6CF3B7EFB0691ULL,
		0xBFF1EC892E04840AULL,
		0x31D2E6B19BF38039ULL,
		0xD9E137F61642F11AULL,
		0x90A4FAF43398B988ULL,
		0x6C6A0E04FF6411C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A6A2E30D0A57360ULL,
		0x8E89A8B305B71FB9ULL,
		0xF4F1ADBEF7FEFFB7ULL,
		0x41231BF2A997A695ULL,
		0x59882B7AB3356AAFULL,
		0xE3B3611F660D7A8FULL,
		0xB9D9E03B9628392BULL,
		0x5930FC852A5B681EULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77796C9DC5BEDF48ULL,
		0xD1DDF1EF8EFC4F90ULL,
		0x5DDEC822EACCA22BULL,
		0x4C3A2D4D3EF36BC9ULL,
		0x2F670488E99ACC2BULL,
		0x6A5842E00B87DCA5ULL,
		0x37D7DBC2B1A241A9ULL,
		0xD70D22B2451AF776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDD2CA5D0C44BE92ULL,
		0xDAFD2D32B848A058ULL,
		0xE17B0C80EB84F76DULL,
		0x4FED13FF63EF303AULL,
		0x137383D3950ED492ULL,
		0xA2805CE18757726CULL,
		0xE9AACB3325A36144ULL,
		0x3372E5DDC99034A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAABA6C0C9FA61DAULL,
		0x0B20DCDD36B4EFC8ULL,
		0xBCA5C4A201485546ULL,
		0x03D73EB25D1C5BF3ULL,
		0x3C14875B7C9418B9ULL,
		0xC8D81E018CD0AEC9ULL,
		0xDE7D10F1940120EDULL,
		0xE47FC76F8C8AC3DFULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDECF30FDD80F315AULL,
		0x196EA337F179F6E7ULL,
		0x15BD0049B29D879FULL,
		0x8D89AA95DB981998ULL,
		0x74767448DB1D010AULL,
		0x7EFFE60DFAB09F18ULL,
		0xF1EA3F720426DEB2ULL,
		0xA83E002FFDDBE94EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08324381C11AA53BULL,
		0xF16AC41C5CB8C069ULL,
		0x5802580D1CDDBE76ULL,
		0xE59A10029F588448ULL,
		0xD3FF8ED0A3C66A03ULL,
		0x63E13A82950AD94CULL,
		0xD71997AD4F552048ULL,
		0x3627DB87D2D192C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6FD737C19159461ULL,
		0xE804672BADC1368EULL,
		0x4DBF5844AE4039E9ULL,
		0x6813BA9744C09DD0ULL,
		0xA789FA9878DB6B09ULL,
		0x1D1EDC8F6FBA4654ULL,
		0x26F3A8DF4B73FEFAULL,
		0x9E19DBA82F0A7B8CULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57D0C9FDFF91EEFFULL,
		0xFA774F8C8116D7CCULL,
		0xC34AD8EF7956FE63ULL,
		0x3B86C6A322DB9BACULL,
		0xCFF316BFD4019F4EULL,
		0x6911F1F197E78385ULL,
		0xA92B8AD83200C7A7ULL,
		0x42FC1A630B9AF44FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE3A2E2CC123626DULL,
		0xDCDC23621516311BULL,
		0xF457F2D30D959BFDULL,
		0x3BAECB687B6AFED3ULL,
		0x88A592C8A9186B74ULL,
		0x94A45741F7D1557EULL,
		0xB2E712F7C13BE3C0ULL,
		0xFBC71707487CBE0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9EAE7D13EB28C92ULL,
		0x26AB6CEE9400E6D7ULL,
		0x371D2A3C74C3659EULL,
		0x00280DCB59B1657FULL,
		0x475684777D19F43AULL,
		0xFDB5A6B06036D6FBULL,
		0x1BCC982FF33B2467ULL,
		0xB93B0D6443E64A43ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F75D32AD14D5DD3ULL,
		0xE40DB49ED423BB52ULL,
		0x005C2959047E2EEBULL,
		0xB6ABB38D9995AC51ULL,
		0x16349B8C0CB1A87BULL,
		0x4EC269F13D38F20CULL,
		0x32ECAD7518750D36ULL,
		0x4ACD91A3FC65F746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA593442DB8A99824ULL,
		0xBA17DC563CF76031ULL,
		0x5D5F0FEEC1B55BA8ULL,
		0xBEF62E2A76FBEFB7ULL,
		0x68A4A9020AE06CA1ULL,
		0xFE67A6A4D54B628CULL,
		0x0532C8965907A6F0ULL,
		0x39ACDC2CA9BB5B8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AE6970769E4C5F7ULL,
		0x5E1A68C8E8D4DB63ULL,
		0x5D0326B7C5CB7543ULL,
		0x085D9DA7EF6E43E6ULL,
		0x7E90328E0651C4DAULL,
		0xB0A5CF55E8739080ULL,
		0x37DE65E34172ABC6ULL,
		0x73614D8F55DEACCAULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA9993AB613CA6F2ULL,
		0xD245D19702C606FCULL,
		0xFFE8A567124376DBULL,
		0x569634D04753499DULL,
		0xEE45EDE625F9AED4ULL,
		0x13EEF0ABA94F725DULL,
		0xDCBF4922886CAD0FULL,
		0x927D487E6155F523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB9B9A1B0E0F63D8ULL,
		0xE2E1E1BD230F8797ULL,
		0xD9E9EA5174FD1E2EULL,
		0xD9C4BD626BD7ADB8ULL,
		0x1E9214ED7E24B4BBULL,
		0xE6784C823AF8BAB5ULL,
		0x716354678792154EULL,
		0xB1E7E6F71D29E3D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x410209B06F33C52AULL,
		0x30A4302A21C9816BULL,
		0x26014F3666BE68F5ULL,
		0x8F5289B22C84E425ULL,
		0xF0D7F90B5BDD1A6FULL,
		0xF596BC2993B7C8E8ULL,
		0xADDC1D450FFEB841ULL,
		0x239AAE897C7C16FAULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x327F3443469FA944ULL,
		0xF0AC2455BAD22770ULL,
		0xF0FE9C19BC31C855ULL,
		0xB819EFBFC33D343AULL,
		0xE929FC003B702DD3ULL,
		0x00B1AE53E2035BE4ULL,
		0x5441D9E99905BA03ULL,
		0xD2656E7E349A5088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4B4C4FAD920B83ULL,
		0xA146F353E3FFF94DULL,
		0xA455D9A888881BC0ULL,
		0x481FBEFC2D8FD1EEULL,
		0xA6DBFD38188B63EAULL,
		0xA05177A57571756AULL,
		0x4342E28891A6C88EULL,
		0x2E1C1A04113D27BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF34780CEB0DA2C7ULL,
		0x51EAD706592DDE3DULL,
		0x54AB45B134B9D395ULL,
		0xF0065143EEB2E5D4ULL,
		0x4FF2013823FB4E39ULL,
		0xA0E0D9F697722E8EULL,
		0x17033B6108A3728DULL,
		0xFC79747A25A77733ULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AF35946FB7F74EFULL,
		0x5E073D691A120D28ULL,
		0x23F6F80F3382BB9DULL,
		0xC9BA855B93EC967FULL,
		0xA322723917F67333ULL,
		0xD3E4CD5AF7A5A157ULL,
		0xAFD984324373C2EFULL,
		0xC59223A094E08BA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18AE072D7F6569B3ULL,
		0x3A158E63B412D044ULL,
		0x705A2F735A72E02DULL,
		0xF88F3B539437D79FULL,
		0x881281FEF3098E41ULL,
		0xB14177F1FA6EEDDDULL,
		0xEF5924D4C6967C63ULL,
		0x29D50B8E00A48EB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x025D5E6B841A1D5CULL,
		0x6412B30AAE00DD6CULL,
		0x53ACD77C69F05BB0ULL,
		0x3135BE0807DB41E0ULL,
		0x2B30F3C7E4FFFD72ULL,
		0x62A5BAAB0DCB4C8AULL,
		0x4080A0E685E5BE8CULL,
		0xEC47282E9444051FULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03C0C88F68673CABULL,
		0xC21F12970FED0257ULL,
		0x99E4242DC6284BBAULL,
		0xD8B9255B3E34DA56ULL,
		0x678F4AF1D622388EULL,
		0x120035AF671EA682ULL,
		0x5AE3ED5B75C1C6E8ULL,
		0xF98BB8A8425283ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8335F21B1F66C8A5ULL,
		0x6AB905FB9CC50D77ULL,
		0x2C934931DD4D4F84ULL,
		0xED4619959AF74E43ULL,
		0x8778D5952F65AED6ULL,
		0x5594275A2C506CF5ULL,
		0xBC908912455323EDULL,
		0x1A9B2A1B123C6FB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80F53A947701F40EULL,
		0xA8A6176C93280F20ULL,
		0xB5776D1C1B65043EULL,
		0x35FF3CCEA4C39415ULL,
		0xE0F79F64F9479658ULL,
		0x479412F54B4ECA77ULL,
		0xE67364493092E505ULL,
		0xE31092B3506EEC19ULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CC1429CC1DA9B03ULL,
		0x2978BB12E71A8516ULL,
		0xC7A4B5EC7DD8C39EULL,
		0x9618C7562A1CD399ULL,
		0x27AB843A6D64CADCULL,
		0x5FF1B8639FD3F087ULL,
		0xF4A3076E2E88A8B1ULL,
		0x951F273E4BBA723DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5869486DF103D2ULL,
		0x758DD528B8385690ULL,
		0x2A8FE70BA8B73BDAULL,
		0xE63174B3270CE212ULL,
		0x8DC80FE6C64CFD02ULL,
		0xF0635BD301D87720ULL,
		0xD0E441F5DA88F9D9ULL,
		0xC257E538B31AC076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50992BD4AC2B98D1ULL,
		0x5CF56E3A5F22D386ULL,
		0xED2B52E7D56FF844ULL,
		0x7029B3E50D10318BULL,
		0xAA638BDCAB2837DEULL,
		0xAF92E3B09E0B87A7ULL,
		0x2447469BF4005168ULL,
		0x5748C206F8A0B24BULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D59912DE6E9CA03ULL,
		0x281BCEA283F54555ULL,
		0xABD4ED211866E40CULL,
		0x76C58D72F8526923ULL,
		0x9727ACD816F8443DULL,
		0x018B32845C6BE3C3ULL,
		0x4AF7656456DCB909ULL,
		0x54B07A42AF3B14E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83AFA8CB17B619B2ULL,
		0x22242B39D1FC3057ULL,
		0xB814EE7A052D0397ULL,
		0xCD4E7B29FF242237ULL,
		0x9F2DD77F4293ABCCULL,
		0xECF1EFDDEE434139ULL,
		0xAB06E8254DF99EFAULL,
		0x9194051CADB5BE8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEF639E6F15FD3B1ULL,
		0x0A3FE59B52097502ULL,
		0x13C0035B1D4BE79BULL,
		0xBB8BF65B07764B14ULL,
		0x080A7BA7546BEFF1ULL,
		0xED7ADD59B228A2FAULL,
		0xE1F18D411B2527F3ULL,
		0xC5247F5E028EAA6AULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB518DAC5196EB2C7ULL,
		0x32C3AE64CCCFFC9EULL,
		0x76D8A20574D04614ULL,
		0x21E6FAB2905FF417ULL,
		0x414B6DFF4C64CA0DULL,
		0x94F63BF541A88182ULL,
		0xE15E27FB9AC55A79ULL,
		0x93EFA6B829D1F570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956B15C6B3F50881ULL,
		0x31B982B4281DAD49ULL,
		0x7EC3905EDB956B28ULL,
		0xD6832616D02F9CDFULL,
		0xC0AFC0BBDA747ADCULL,
		0x71B279E12FF5482FULL,
		0xD2A30598CEA88954ULL,
		0x788F5323A6B9244AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2073CF03AA9BBA46ULL,
		0x037A2CD0E4D251D7ULL,
		0x081B325BAF452D3CULL,
		0xF765DCA4407068C8ULL,
		0x81E4AD449610B0D1ULL,
		0xE54442146E5DC9ADULL,
		0x33FD2263546DD32DULL,
		0xEB60F59B8F68D13AULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF54AD74FD98A5A15ULL,
		0x9CA2456EBB2A2E81ULL,
		0x296A2BB5E17E25E8ULL,
		0x82AF836F12DC5A27ULL,
		0xA4E5FF80BCE8A260ULL,
		0x16E4D997A8A3E2F7ULL,
		0xF2F034682993B2D0ULL,
		0x00423047194668A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC9F67E1ED4D08BULL,
		0xFA1EDA09358B8C91ULL,
		0x251A004A43BE2B40ULL,
		0x66309C10688EE62EULL,
		0xB9C876B5493BA667ULL,
		0xD8990DC3B64044B6ULL,
		0x8C932A3EE490DD40ULL,
		0xEA3952396AEBBB9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8832131C75E8A9EULL,
		0x66BC9F678EA1A210ULL,
		0x0C702BFFA2C00EA8ULL,
		0xE49F1F7F7A52BC09ULL,
		0x1D2D8935F5D30407ULL,
		0xCE7DD4541EE3A641ULL,
		0x7E631E56CD036F90ULL,
		0xEA7B627E73ADD33CULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69A9E96206C5E993ULL,
		0x7C626266927AC305ULL,
		0x3EB0EC21055F4228ULL,
		0x31829ABD3CDF293AULL,
		0xC22EB3029296CF45ULL,
		0x4A63C293D79CC481ULL,
		0x0F38A83116DD0069ULL,
		0x1B4B138FF85447F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9971E0E93674AF7FULL,
		0x9485B2CC9F2929D3ULL,
		0xB8D6FE469B9AA7DDULL,
		0xC9186326701D36DDULL,
		0xE155E6A9437CD9F5ULL,
		0x0E77CDCD231D36FEULL,
		0xDF5762842DDCD20CULL,
		0xEF7A3D609CF04A4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0D8098B30B146ECULL,
		0xE8E7D0AA0D53EAD6ULL,
		0x866612679EC5E5F5ULL,
		0xF89AF99B4CC21FE7ULL,
		0x237B55ABD1EA16B0ULL,
		0x44140F5EF481F27FULL,
		0xD06FCAB53B01D265ULL,
		0xF4312EEF64A40DBDULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB1AFC4A7A27A639ULL,
		0xE21D4AF87A9123D3ULL,
		0x28C46FFA6BEE5344ULL,
		0xE5B2AD3C4AECA684ULL,
		0x120BB85C0101418DULL,
		0x2741A7EE5A0DF75FULL,
		0xE3C2D8BA3774BB8FULL,
		0x20AB085999A7A03FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2760B851A005E687ULL,
		0xF0F9B961D9158FFBULL,
		0x9D5356687E00DD1BULL,
		0x9B252AF83E86DBFDULL,
		0x5D79B368381782E5ULL,
		0x77708D860084BEE1ULL,
		0x707019BEC358CBC4ULL,
		0x0F07263277A5A829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC7A441BDA2240BEULL,
		0x12E4F399A384AC28ULL,
		0xB597399215EE8E5FULL,
		0x7E9787C4746A7D79ULL,
		0x4F720B343916C368ULL,
		0x50312A685A8949BEULL,
		0x93B2C104F42C704BULL,
		0x2FAC2E6BEE020816ULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC97DEE735311951ULL,
		0x3F4F8B0BCECDC1E1ULL,
		0x4E353A8693975BC5ULL,
		0x3F2D16776D65C9D7ULL,
		0x5027D6A488C05882ULL,
		0x15A5D2AC515DA450ULL,
		0xC08F6E649F17F5DBULL,
		0xD45C4CFDEAA8F014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A0FB3F13D3A786ULL,
		0x75B9DAD7A909921BULL,
		0x8CFD78C1984C8F82ULL,
		0x80EBF2BD79BA3131ULL,
		0xBBCB95E57C616DCAULL,
		0x755AB5C11C230494ULL,
		0x4323F08D25CED29BULL,
		0x172EBCFA718188E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB43725D826E2BED7ULL,
		0x4AF651DC67C453FAULL,
		0xC2C842470BDBD447ULL,
		0xBFC6E4CA14DFF8E6ULL,
		0xEBEC4341F4A13548ULL,
		0x60FF676D4D7EA0C4ULL,
		0x83AC9EE9BAD92740ULL,
		0xC372F0079B2978F7ULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7737F9A02E5605E3ULL,
		0x1D478BDCED3E6CC5ULL,
		0x65901C7F2A97E40FULL,
		0x94D72174ADF45152ULL,
		0x1A80C0D39C41BF5FULL,
		0x191ED5767268FCEBULL,
		0x3F53B7BC2B816B81ULL,
		0x5448D18353D84CC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEAADB010EC4598EULL,
		0x1FE52426CC1AEE96ULL,
		0x70A719ED05CC83E3ULL,
		0xF9ABAC1048CD4F14ULL,
		0x220D808F475B7300ULL,
		0x39C8DCC5F1E13175ULL,
		0xF852744C59243BF0ULL,
		0x9482588D0521510EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC99D22A120925C6DULL,
		0x02A2AFFA21248253ULL,
		0x153705922F5B67ECULL,
		0x6D7C8D64E5391E46ULL,
		0x388D405CDB1ACC5FULL,
		0x20D609B38389CD9EULL,
		0xC701C3F072A55071ULL,
		0xC0CA890E56F91DC6ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74FE65815D1FCCA7ULL,
		0x0E8936D0EF60968CULL,
		0x98D7AC5DCAF001DEULL,
		0x5D9EB5E95240B9BAULL,
		0x20E78025882D9041ULL,
		0x2315D2A89D44F242ULL,
		0x7937A7FD884DFE38ULL,
		0xB3F7CE8FE9B13927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EE5ED3E371B865CULL,
		0xB202395CE04A96D0ULL,
		0xD85C6E4F68496751ULL,
		0x85591A0D853F2769ULL,
		0x8C71C99CC07AC0ABULL,
		0x17D14C4D7CF7388EULL,
		0x92FCBD8B83888FF4ULL,
		0xFB8B2B8A2749A7AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A1B88BF6A044AFBULL,
		0xBC8B0F8C0F2A005CULL,
		0x408BC212A2B9668FULL,
		0xD8C7AFE4D77F9ED3ULL,
		0xAC9649B9485750EAULL,
		0x34C49EE5E1B3CACCULL,
		0xEBCB1A760BC571CCULL,
		0x487CE505CEF89E8DULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68752287D7E27CC4ULL,
		0xEE9B6FBAF98D78E0ULL,
		0x86F8C52411638845ULL,
		0xC470A99914771415ULL,
		0x0837937032F75941ULL,
		0xC178CF884C2F1F42ULL,
		0x1FCFBDD21FDFB76BULL,
		0x1A810EC4FB50964AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE757E1093840B0AULL,
		0x2589C8A666DDF730ULL,
		0xC10C0C62F5B57A73ULL,
		0x1A3BE97038BA6205ULL,
		0x287FF52C7C91BFEDULL,
		0x3B31627ECEA24779ULL,
		0x979D63569D9935E7ULL,
		0x64C65F6446C1CE88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6005C97446677CEULL,
		0xCB12A71C9F508FD0ULL,
		0x47F4C946E4D6F236ULL,
		0xDE4B40E92CCD7610ULL,
		0x2048665C4E66E6ACULL,
		0xFA49ADF6828D583BULL,
		0x8852DE848246828CULL,
		0x7E4751A0BD9158C2ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58440DD3965C488FULL,
		0x6D5CAA4774B72D10ULL,
		0x8E1B6D3CE5D7A45FULL,
		0x740B117628A9B909ULL,
		0x535CCF3A4DA5CD6CULL,
		0xF86FB45998B3B533ULL,
		0x57666D26C5C7B876ULL,
		0x06E8A9857A83B287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD535720EE96B3269ULL,
		0xA6356AC0E166C4A5ULL,
		0xA1098185F8C65655ULL,
		0xF29BABD31DA49640ULL,
		0xF5706B12503DF6E4ULL,
		0x1137600A0B094369ULL,
		0x5870FC70AA4ADE1DULL,
		0xE126CA0B35E31CB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D717FDD7F377AE6ULL,
		0xCB69C08795D1E9B5ULL,
		0x2F12ECB91D11F20AULL,
		0x8690BAA5350D2F49ULL,
		0xA62CA4281D983B88ULL,
		0xE958D45393BAF65AULL,
		0x0F1691566F8D666BULL,
		0xE7CE638E4F60AE31ULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CF43DC36DC52059ULL,
		0x35F4D541AD6F2E8FULL,
		0x4EA5267EA48EBF82ULL,
		0xF2B068B84FBFF26BULL,
		0xA83E56C737C28A5FULL,
		0x2C33E3DBB80B5998ULL,
		0x3729EEA239F42293ULL,
		0xACE170353104460CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF6904690C447AFULL,
		0x3E931043C7A9A27BULL,
		0xC0D5B156A7A620FFULL,
		0xC4612F0CF74A85DEULL,
		0xD5F234CDEF6CCD09ULL,
		0xC4804BE3B1634C83ULL,
		0x5F2C56EAFD5B2771ULL,
		0x81B4E717F27AD07FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB002AD85FD0167F6ULL,
		0x0B67C5026AC68CF4ULL,
		0x8E70972803289F7DULL,
		0x36D147B4B8F577B5ULL,
		0x7DCC620AD8AE4756ULL,
		0xE8B3A8380968151BULL,
		0x6805B848C4AF05E2ULL,
		0x2D559722C37E9673ULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EBE2D7BAF8BBF2EULL,
		0xEAEE85CDA327E2F1ULL,
		0x49CCAB24485A7F75ULL,
		0x82F545AA287D2C2BULL,
		0x8164A4B3108CC3AFULL,
		0xF7D41467586D5D62ULL,
		0x23ECFB016FED7E80ULL,
		0x8D70B7ABE9C555C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB305438B4CFBF41AULL,
		0xE8F2B86F622AC606ULL,
		0xE8091CCA08FF78A5ULL,
		0xA7AF21D6F7EDF4D6ULL,
		0xC1540C9A3F78EA41ULL,
		0xE3454265260340A1ULL,
		0x8142ACC5289B3ADDULL,
		0xF4FF249A51724C5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDBB6EF0E3704B34ULL,
		0x021C3DA2C10D24F7ULL,
		0xA1C5B7EE40A507D0ULL,
		0x255A647CDF90D8FDULL,
		0x4030A8292FF429EEULL,
		0x149156027E6E1DC3ULL,
		0xA2AE57C44776445DULL,
		0x798F9331B8B71999ULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F0F5D2955D87152ULL,
		0xB1FA41CA364945C2ULL,
		0xAC34ED103015E781ULL,
		0x9F90453DD69E2984ULL,
		0x018C782346A6193CULL,
		0x7DD86C03210E490BULL,
		0x52CFBF464044EE00ULL,
		0xAB24A1D35C472A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84B3D01657D2D0BEULL,
		0x9C122CA484E3841AULL,
		0x311FEC5A6D35724DULL,
		0x8CB09B53CA1754D4ULL,
		0xD87302345BDCAF68ULL,
		0x52026A01A7EB96AEULL,
		0x927E54178915B8D2ULL,
		0xAF49A521E78C7453ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BBC8D3F020AA1ECULL,
		0x2DE86D6EB2AAC1D8ULL,
		0x9D2B014A5D2095CCULL,
		0x1320DE6E1C897D50ULL,
		0xD9FF7A171D7AB654ULL,
		0x2FDA060286E5DFA5ULL,
		0xC0B1EB51C95156D2ULL,
		0x046D04F2BBCB5E00ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFCFA4DFB459784BULL,
		0x798AF858665D9FCCULL,
		0x9F2B20044F40B497ULL,
		0x084F80A0A340865CULL,
		0xB4E9169934CAC819ULL,
		0x238ACDA3CE9516D0ULL,
		0x74B75ADC54305DD8ULL,
		0xC79A510E3A9DE1A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB86DB45D2B9DD0ULL,
		0x14D3E0B8EDD6A923ULL,
		0xBA60EE5B4DCFA2FFULL,
		0xA0EB0AC10343C5DCULL,
		0x59BCB020398F64E7ULL,
		0xC2A46A6367DF53A4ULL,
		0xBA2327231D2AAE21ULL,
		0x0C19F438571597B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3277C96BE972E59BULL,
		0x6D5918E08B8B36EFULL,
		0x254BCE5F028F1668ULL,
		0xA8A48A61A0034380ULL,
		0xED55A6B90D45ACFEULL,
		0xE12EA7C0A94A4574ULL,
		0xCE947DFF491AF3F9ULL,
		0xCB83A5366D887617ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2C19A709A11AA38ULL,
		0x6761F3D3C855A211ULL,
		0xDDB5437DDFF7CF5FULL,
		0x7B19EBA10C80A610ULL,
		0xC70842873E6A61EEULL,
		0x7F2A79986B8DCCFAULL,
		0x91E6E452CCB0AB5DULL,
		0x1B4B5DAE5C3D40C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0431D3DEE4035E6ULL,
		0x3DF20D03CD3BB776ULL,
		0x73FEFB10071EBB4EULL,
		0x93E5E2EF864B8CFDULL,
		0xD4439EB1641397A7ULL,
		0xF063CE27B58DAD59ULL,
		0x682296803BA57A2FULL,
		0x2AD4F4070EDDE43EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4282874D74519FDEULL,
		0x5A93FED0056E1567ULL,
		0xAE4BB86DD8E97411ULL,
		0xE8FC094E8ACB2AEDULL,
		0x134BDC365A79F649ULL,
		0x8F49B7BFDE0061A3ULL,
		0xF9C472D2F715D172ULL,
		0x319FA9A952E0A4F6ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0FED1A4DEB469A7ULL,
		0xD8809AD4174F4830ULL,
		0xFEDFD3D2787C3519ULL,
		0x3C884F6F4E98B3BAULL,
		0x10736FD118BE4E18ULL,
		0x5659A7F6A2C61AF3ULL,
		0x8AE7D879CEDEFE5CULL,
		0x94CD845776DFF3EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11D34723FD0C9F2ULL,
		0x842F5C45150FC9D1ULL,
		0xDC6E46A64574D40AULL,
		0xD55C020E5E917AFCULL,
		0xFB2ABA536AE0D53CULL,
		0x04E6AA181E1C0286ULL,
		0x36043E079E49229DULL,
		0x9DB93C5C4E70CB9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11E3E5D6E164A055ULL,
		0x5CAFC691024081E1ULL,
		0x22B195743D08E113ULL,
		0xE9D44D611009C946ULL,
		0xEB59D582725E9B24ULL,
		0x52BF0DEEBCDA1875ULL,
		0xBCE3E67E5097DCC1ULL,
		0x0974B80B38AF3872ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00FA535FC2B5AAD2ULL,
		0xA16A2133D6975EF1ULL,
		0x9D742E2F2AE4312CULL,
		0x74AD97ACA40287E4ULL,
		0xDB463C69CCB7B650ULL,
		0x79327AB3D315DB29ULL,
		0xDD8F9DCF89DE41FFULL,
		0xBAE60EA65E01D5C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8139E0BF1A6E7850ULL,
		0x6D88E0E63E510ADFULL,
		0xE189BCDCD302377AULL,
		0xA5DC4BF4D4CA95ECULL,
		0xF1214EBE41B95DD8ULL,
		0x37602AEA6733BAA8ULL,
		0x4B3601E9FB181B23ULL,
		0x6F3799BE97D8AC9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81C3B3E0D8DBD282ULL,
		0xCCE2C1D5E8C6542EULL,
		0x7CFD92F3F9E60656ULL,
		0xD171DC5870C81208ULL,
		0x2A6772D78D0EEB88ULL,
		0x4E525059B4266181ULL,
		0x96B99C2672C65ADCULL,
		0xD5D19718C9D97959ULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2C7D29633EEA794ULL,
		0x20F791445DEAC982ULL,
		0xD427385D36485F9EULL,
		0x014A4F72623F1E0BULL,
		0x61E6149705EFCC98ULL,
		0x3862DED49F22964CULL,
		0xD0C0D5EBAAD8997FULL,
		0x4433823BEE22DA2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56CBB62980314FD2ULL,
		0xD059B3D9806AEE1FULL,
		0xF0E79185E5964B7DULL,
		0x57EB8EA6004D3E47ULL,
		0xE47EAFF1C4CE5D59ULL,
		0x1B1DAC901AA7BCA3ULL,
		0xE3F67DFACD5997D6ULL,
		0x9B57044C590A4A2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB40C64BFB3DFE846ULL,
		0xF0AE229DDD80279DULL,
		0x24C0A9D8D3DE14E3ULL,
		0x56A1C1D46272204CULL,
		0x8598BB66C12191C1ULL,
		0x237F724485852AEFULL,
		0x3336A81167810EA9ULL,
		0xDF648677B7289006ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x685B7254ED6C73D8ULL,
		0x175A38B15BF72B6DULL,
		0x8524B7C7E4E552EEULL,
		0xE791E7C0D9FCA96BULL,
		0x72F284710F10F076ULL,
		0x4716961C98F5A2BCULL,
		0xAE3D39AB9749FFA3ULL,
		0xC628A9421AA1616DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DDE16A896A51F85ULL,
		0x168A61BB927A6C86ULL,
		0xFAC41C7BAF71F29DULL,
		0x73CB9AA3D96D2429ULL,
		0x56E04BEC064295B0ULL,
		0x7ADF1B28261093B6ULL,
		0x472A7C42065964B3ULL,
		0x64875944DDC125F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x258564FC7BC96C5DULL,
		0x01D0590AC98D47EBULL,
		0x7FE0ABBC4B94A073ULL,
		0x945A7D6300918D42ULL,
		0x2412CF9D095265C6ULL,
		0x3DC98D34BEE5310AULL,
		0xE91745E991109B10ULL,
		0xA2AFF006C760449CULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC701700CE9399C74ULL,
		0x3E66BE86955BE816ULL,
		0x7B46A26067C2FDCEULL,
		0x4325994572ADBA40ULL,
		0x4AB8B5EF1D782740ULL,
		0x558406896CC64F84ULL,
		0xB30537D11BD73553ULL,
		0x74B383E892FD2115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6395FF736B174CCDULL,
		0x104C9513C53FA44EULL,
		0x1E0FE4FA6E54FC45ULL,
		0x6EA6C7E196AF23E3ULL,
		0x49294F7E583A56DBULL,
		0x417A07572013C5C1ULL,
		0xE02B8502B3232205ULL,
		0x8F1182BCF49EF8D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4948F7F822ED0B9ULL,
		0x2E2A2B9550644C58ULL,
		0x6549469A0996018BULL,
		0x2D835EA4E40299A3ULL,
		0x0391FA914542719BULL,
		0x14FE01DE4CD58A45ULL,
		0x532EB2D3A8F41756ULL,
		0xFBA201546663D9CDULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5E5BB946D9472B4ULL,
		0xD4650163F9F8181CULL,
		0xE2B0CD88813733D7ULL,
		0xB434DAB790FBFAB9ULL,
		0xC8DB29AE672F1E16ULL,
		0x8BBA954E1CB0A2E6ULL,
		0x650FAE07907C9287ULL,
		0xD612021EB5C35184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9696BCF86635D68ULL,
		0x4659FE9C586E9299ULL,
		0x9ADE89A89B9A6B25ULL,
		0x8BCABAF4286F537BULL,
		0xE618193720763F48ULL,
		0xDD5806FF1FB5CF3BULL,
		0x5C04E3D0343F18DFULL,
		0x6A42E98C94AB8E01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C8CD05BEBF72FDCULL,
		0x923CFFFFA1968A85ULL,
		0x786E44201AAD58F2ULL,
		0x3FFE6043B894A9C2ULL,
		0x2EC330994759215EULL,
		0x56E293B103056DDDULL,
		0x390B4DD7A4438A58ULL,
		0xBC50EB922168DF85ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6172180DFF238B2DULL,
		0xE6779FCE8C9327F7ULL,
		0xB0DD5D595DE4DA87ULL,
		0x44582A9D404ACB0BULL,
		0xA01E585E88F95F2FULL,
		0x4D611DD3AA79AC7FULL,
		0xC5E21893C0D597E8ULL,
		0x77BA8E648B607743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4EF8F5059735370ULL,
		0x7A1853EB41CB6BADULL,
		0x68E440007B80B3B3ULL,
		0xE10C90E771AB6BBEULL,
		0x6252911D090FD7F9ULL,
		0x6B4D652A19ECA7FAULL,
		0x571F4BCC189B49A4ULL,
		0x6C2D9C9BA497F6F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x959D975DA650D85DULL,
		0x9C6FCC25CD584C5AULL,
		0xD8391D5926646934ULL,
		0xA554BA7A31E1A0B5ULL,
		0xC24CC94381F688D6ULL,
		0x262C78F9B3950B85ULL,
		0x92FD535FD84EDE4CULL,
		0x1B9712FF2FF781B2ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAADC5107DF60DD9FULL,
		0xFA1FE1D3A38550DDULL,
		0xFEAB2D0F2A6F73CFULL,
		0xADCE2768A21276F7ULL,
		0x3EEBD2B53B48DF14ULL,
		0x3CCF2C36197857E8ULL,
		0x2B4A81C30E637D11ULL,
		0x43C6218B92ADFA19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A91236870B6286ULL,
		0x57B20F95482BD051ULL,
		0xD1F94AAA83541866ULL,
		0x6EBDD308056B223AULL,
		0x02264CE28FF953C7ULL,
		0x89FB1A95F785C27DULL,
		0xD2055432306655F6ULL,
		0x06236D7672D6487AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2754331586BBF19ULL,
		0xADADEE46EBAE808CULL,
		0x2F5267A5A93B6BA9ULL,
		0xC373F460A77954CDULL,
		0x3CCD9E57B4B18CD3ULL,
		0xB53436A3EEFD9595ULL,
		0xF94FD5F13E0528E7ULL,
		0x45E54CFDE07BB263ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45FA6A33D03E3CDAULL,
		0x121367EFEBFAB37AULL,
		0xBFE7E540D77D3247ULL,
		0xAA203D08BBF65724ULL,
		0xB892339C4C4E1D56ULL,
		0x49A85223F92047E7ULL,
		0x82FC50E25961C208ULL,
		0xAE5BB846097A487EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC01E113F991C19E4ULL,
		0x9C6630CD213279E5ULL,
		0x835252409FBC5072ULL,
		0x7AB3ECB017F5A051ULL,
		0x235EF8AEFA5351C5ULL,
		0xB5F8FA286A13A298ULL,
		0xE40D4CCC3BA7C9F3ULL,
		0xAB59C9F017764B5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85E47B0C4922253EULL,
		0x8E755722CAC8CA9FULL,
		0x3CB5B70048C16235ULL,
		0xD093D1B8AC03F775ULL,
		0x9BCCCB32B61D4C93ULL,
		0xFC50A80B9333E57FULL,
		0x66F11C2E62C60BFBULL,
		0x050271B61E0C0321ULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x000538320911DCADULL,
		0xCFBAFD0C2A363F91ULL,
		0x1E14A6533D64C5A9ULL,
		0x30D9A04A6D7B287FULL,
		0xB06745FD5E69101CULL,
		0xCF3DC7251D01C184ULL,
		0x297FC472BBA64856ULL,
		0x4FC2DA3ECE052D74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4AFF468D641522AULL,
		0xCBF77FFAD300519BULL,
		0x20910EE6D88B61FCULL,
		0x4407A789BEF049ADULL,
		0xF592FAF39E656233ULL,
		0x1BB0860972203D76ULL,
		0x69B4E8B818F20E31ULL,
		0x0AC3FE40B8CE1558ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4AACC5ADF508E87ULL,
		0x044D82F6F9366E0AULL,
		0x3E85A8B5E5EFA455ULL,
		0x74DE07C3D38B61D2ULL,
		0x45F5BF0EC00C722FULL,
		0xD48D412C6F21FCF2ULL,
		0x40CB2CCAA3544667ULL,
		0x4501247E76CB382CULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FB0A7EF1F5480D0ULL,
		0x89447A5A069F8CA2ULL,
		0xC7F56E0229DD6703ULL,
		0xCEB1D592BD612FF5ULL,
		0x5ACFB8209DA9DCE6ULL,
		0x1CE23437D0FBBB91ULL,
		0x7275529D395582B3ULL,
		0x98ADE6E1603FAF0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF249C55B7990127FULL,
		0x482CF7F209085D8CULL,
		0xB354A55362D5AE6EULL,
		0xC5B5C0824179C627ULL,
		0x227D56955577BD27ULL,
		0x5F159E5C307F5ADFULL,
		0x4FA3A84519EB9C1AULL,
		0xF8EB8E893E78B940ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDF962B466C492AFULL,
		0xC1688DA80F97D12EULL,
		0x74A1CB514B08C96DULL,
		0x0B041510FC18E9D2ULL,
		0x78B2EEB5C8DE61C1ULL,
		0x43F7AA6BE084E14EULL,
		0x3DD6FAD820BE1EA9ULL,
		0x604668685E47164EULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD84A2E5BD7A72AF4ULL,
		0xEACBF9C0F78F6CE0ULL,
		0x6DE1C422FC7C5878ULL,
		0xD48255F5CB5F5675ULL,
		0xC4D9A55293FC8801ULL,
		0x3253A35F310B341CULL,
		0xF407D017BC07B96CULL,
		0x9FD281A24DE9A24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x126A029A6A02C506ULL,
		0x40B8D25E57BB4D13ULL,
		0xD275BF89B05C16B5ULL,
		0x2E2225FDDACD023DULL,
		0x7D6117591DDB2501ULL,
		0x65E94A33220F00BDULL,
		0xC704D8288F24CE25ULL,
		0x9C70889CE7E21601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA202CC1BDA5EFF2ULL,
		0xAA732B9EA03421F3ULL,
		0xBF947BAB4C204ECDULL,
		0xFAA0700811925448ULL,
		0xB9B8B20B8E27AD00ULL,
		0x57BAE96C130434A1ULL,
		0x3303083F33237749ULL,
		0x03A2093EAA0BB44CULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79F6692A7E9F8F65ULL,
		0x066D736211320F93ULL,
		0x7AAEB25AC2DD9A76ULL,
		0x4708A20B5A001EDEULL,
		0x7DFBCBA90315F5E8ULL,
		0x3113CCDB0FE21CDEULL,
		0x5D3279BAF5822762ULL,
		0x1F1AD8C01DF76269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E7DDCEAE2D4E275ULL,
		0xA2F2624BB2CAB426ULL,
		0x1A4A9FDDB7513A8CULL,
		0xF84CA42EE7629BD0ULL,
		0x01E2EF7C4EE7DC11ULL,
		0xE504F35A66AE5E8FULL,
		0xD2DD58E749D212DCULL,
		0xF008B3AE258470B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x778BB5C09C4B6D10ULL,
		0xA49F1129A3F8BBB5ULL,
		0x60E42D87758CA0FAULL,
		0xBF440625BD62850EULL,
		0x7C1924D54DF229F9ULL,
		0xD4173F81694C4251ULL,
		0x8FEF215DBC5035BEULL,
		0xEF126B6E387312DAULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D9E52CF420D01D4ULL,
		0xF7AC6F012C10BCB3ULL,
		0x880C38058BE614F8ULL,
		0x36AC0071C9AD1E47ULL,
		0xA3AFDDDA769B2AD8ULL,
		0xD615C19414AEA479ULL,
		0xEF2F1EB6ECE4E478ULL,
		0xA2E5FDE8F08F24C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x413125C07D259E8AULL,
		0x5A72D5A5C4AF6B60ULL,
		0xC5702E9B350434F7ULL,
		0x4B7971CF75051E5FULL,
		0xA29026767A51701BULL,
		0xA1808DD043D16DF1ULL,
		0x2B5654879E1E8FB1ULL,
		0x4167224BC8D1E15BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CAF770F3F289F5EULL,
		0xADDEBAA4E8BFD7D3ULL,
		0x4D7C169EBEE2200FULL,
		0x7DD571BEBCA80018ULL,
		0x013FFBAC0CCA5AC3ULL,
		0x77954C44577FC988ULL,
		0xC4794A3172FA6BC9ULL,
		0xE382DFA3385EC599ULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD3C76AC7A5246B7ULL,
		0xE190FF11F9A1BC57ULL,
		0x73F8915FF38C1739ULL,
		0x022190691170B8BBULL,
		0x42E6A6DF31D5F13EULL,
		0xCD2B4C428A0B7833ULL,
		0x6878B2CFD0E08501ULL,
		0x4183BB7D9FA46D4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69A73331F745923FULL,
		0x86C421E59A0376E4ULL,
		0x7AEA986AEA9EF990ULL,
		0x41E3F795FEFF0ACCULL,
		0x8C150A61C44C41A3ULL,
		0x2EE7813EC1E4CC3CULL,
		0x3604E67BE882DFFFULL,
		0x86612C38C71710A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x949B459D8D17D488ULL,
		0x6754DEF463A2CAB3ULL,
		0x091209351912EEA9ULL,
		0x43C267FCEF8FB277ULL,
		0xCEF3ACBEF599B09DULL,
		0xE3CCCD7C4BEFB40FULL,
		0x5E7C54B438625AFEULL,
		0xC7E2974558B37DECULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE70EE08422824D6EULL,
		0x9FBDBB789A1E4903ULL,
		0x48F4C6BF1AE0C584ULL,
		0xF78F75926124F128ULL,
		0xCA243AB48F2D70A3ULL,
		0xDFAF4934758DF20BULL,
		0x118F13FC9C93A705ULL,
		0xA9A2D017F10E4337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C84A877F1C47F0ULL,
		0x6264BC02EBCBAB19ULL,
		0x909E1EDDEC18E61CULL,
		0x0F64A3CB3651CD0BULL,
		0xAA52838D0DB00B0DULL,
		0xABE98BD615B05270ULL,
		0x26864BA686E4D4BDULL,
		0x4BFCBA3E03925540ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14C6AA035D9E0A9EULL,
		0xFDD9077A71D5E21AULL,
		0xD86AD862F6F82398ULL,
		0xF8EBD65957753C23ULL,
		0x6076B939829D7BAEULL,
		0x7446C2E2603DA07BULL,
		0x3709585A1A7773B8ULL,
		0xE25E6A29F29C1677ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22E8087E72425B33ULL,
		0x6817886845D487BAULL,
		0xCE7C5E1C59AE5875ULL,
		0x211A20F01FF26040ULL,
		0x4DF0EC8D39DDA006ULL,
		0xDBC0B5CBA5CBC01DULL,
		0x48ED0D773341263EULL,
		0x63C4901593E11580ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C37B9D0651A529EULL,
		0x2248FBEA520F53DEULL,
		0x3A954D2F0E0749C5ULL,
		0xD3E0B765430B78E9ULL,
		0x50EF028ECAD2CD1FULL,
		0x88FEE994DAEEC4C9ULL,
		0x2EC9E46D7E7250B1ULL,
		0x2074E77C57DB4157ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EDFB1AE175809ADULL,
		0x4A5F738217DBD464ULL,
		0xF4E9133357A911B0ULL,
		0xF2FA97955CF918A9ULL,
		0x1D1FEE03F30F6D19ULL,
		0x533E5C5F7F2504D4ULL,
		0x6624E91A4D33768FULL,
		0x43B07769C43A54D7ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AC06A83901962CEULL,
		0xEB4B9C1EF378ADFEULL,
		0x0E8FDC87F1058845ULL,
		0x2F7C7FA409633BACULL,
		0x9933AC4B4CDB0B94ULL,
		0xB3FBCAB0929D28D0ULL,
		0xC51BF4310F50B503ULL,
		0x4C7440154400F9B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B654235FE39F518ULL,
		0xAE4905EABF9C90B0ULL,
		0x6E24E7483CB2D1CBULL,
		0x1D50BBDA7150E17DULL,
		0x3DB9E3A4864A7D05ULL,
		0xF0408500D44F0355ULL,
		0x1353C5553592ACD6ULL,
		0xA3A0534583EF745FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71A528B66E2097D6ULL,
		0x450299F44CE43D4EULL,
		0x60AB3BCFCDB7598EULL,
		0x322CC47E7833DAD1ULL,
		0xA48A4FEFCA917691ULL,
		0x43BB4FB046D22B85ULL,
		0xD64831643AC219D5ULL,
		0xEFD41350C7EF8DE9ULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFE114C4E7119984ULL,
		0xDDD191AF4B0B31B7ULL,
		0x2D002C8CA7B5944CULL,
		0xAE18D8A3C3C5AB77ULL,
		0x0AE922B8FDD15780ULL,
		0x39938EEF7EB2629CULL,
		0x13ECE01E55B59855ULL,
		0x251874754D2A0A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0475AC61CD7F3D29ULL,
		0xA3ACF6F5DA9F907DULL,
		0xB9DF6812E1A48061ULL,
		0xE8F62AA571C2883AULL,
		0x47B03F677B670866ULL,
		0x74B54F22C16B3986ULL,
		0x2560FB45B3726C08ULL,
		0x6543EE07C4DB92C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB94B8A52A6EA4ADULL,
		0x7E7D675A9194A1CAULL,
		0x94DF449E4611142DULL,
		0x46EEF206B207234DULL,
		0x4D591DDF86B65FE6ULL,
		0x4D26C1CDBFD95B1AULL,
		0x368C1B5BE6C7F45DULL,
		0x405B9A7289F1985FULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86DBC053E6B42192ULL,
		0x9E053F0E9F5CB4A8ULL,
		0x987B57FFCE4FBBBAULL,
		0x1981B67936754CA6ULL,
		0x02AAC469FB0D0FA2ULL,
		0x6339B34970D47B23ULL,
		0xC80B4BE91978B4CDULL,
		0x7315FC0BC0A87625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEAAA08FD4936BDFULL,
		0x64A197EB624DACEFULL,
		0x98A3EBB28B2EE785ULL,
		0xE9C124F39920A890ULL,
		0x1F56793562C8655BULL,
		0xD45AC48BBFD7A1B1ULL,
		0x98778215A88CDD0EULL,
		0x68DCAD55A4DCBFD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x687160DC32274A4DULL,
		0xFAA4A8E5FD111847ULL,
		0x00D8BC4D45615C3FULL,
		0xF040928AAF55E436ULL,
		0x1DFCBD5C99C56AF9ULL,
		0xB76377C2CF03DA92ULL,
		0x507CC9FCB1F469C3ULL,
		0x1BC9515E6474C9F2ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BCDA1E8684CDF19ULL,
		0x4BD214C8B95B9B94ULL,
		0xCFD1B3A6D58BC81DULL,
		0xB50AC8C82F1E36C1ULL,
		0x5F2C8C6E2015540FULL,
		0x8EE6F78074F2F87FULL,
		0x4E232BD3394B5669ULL,
		0x82C90F0C4318F087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C419F341D264F9ULL,
		0x0470D855B05550F9ULL,
		0x4135247473CD7146ULL,
		0x4575425C48F8C0CDULL,
		0xBF8CA20B13F2E72EULL,
		0x801E1F4CB21D6029ULL,
		0x4A266B24D1CCC6F7ULL,
		0x46DB9625222698F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB809B81B299EBBE0ULL,
		0x4FA2CC9D090ECB6DULL,
		0x8EE497D2A646B95BULL,
		0xF07F8A9467E6F60CULL,
		0xE0A02E6533E7B321ULL,
		0x0EF8E8CCC6EF9856ULL,
		0x040540F7E887909EULL,
		0xC4129929613E6871ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEA91AA061D6BA1FULL,
		0xDCB8D7199EA8097AULL,
		0xD611D254643A6A7BULL,
		0xF437DD8C56913619ULL,
		0x844015453392D0F7ULL,
		0xBC7899E79F423D61ULL,
		0xB9CC697486F4D749ULL,
		0x827B68990DDB54CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1340C8416D6FBA10ULL,
		0x13E7565814D1CB9CULL,
		0x063A26E157A43A52ULL,
		0xD4BB4828A7FB463AULL,
		0xF168E5A27B7D72B1ULL,
		0x8EBF8FF24653AF1FULL,
		0x9C25E35D6DB6C36DULL,
		0x8AF5050D949CDEB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDE9D2E10CB9000FULL,
		0xCF5F81418A79C2E6ULL,
		0xD02BF4B5339E5029ULL,
		0x208C95A4F16A7023ULL,
		0x7528F0E748EFA246ULL,
		0x32C71615D911927EULL,
		0x25E98A29EB421424ULL,
		0x088E6D9499478A7CULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE1E8DE88E328832ULL,
		0x88D55AF73B9B4428ULL,
		0xCC3FD6A1CC7584CDULL,
		0x7955F3DC0EEF0782ULL,
		0xDD02D6EDF41A9B73ULL,
		0x6791B8CCFE769707ULL,
		0xC3C3C86F9E166CFBULL,
		0xFC5F9BB7263F3715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED46340E6788AA0ULL,
		0xFB1986DA2B434295ULL,
		0xF512A6251D9CCE9CULL,
		0xFF4322DA7E008840ULL,
		0x05BCD6B923646F05ULL,
		0x71AD103B92639326ULL,
		0xFCD18A8AFA4D1798ULL,
		0x7A22AAD350EFC973ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30CAEEA8684A0292ULL,
		0x73CCDC2D10D806BDULL,
		0x392D7084D1E94A51ULL,
		0x8616D10670EF8FC2ULL,
		0xD8BE0054D77EF476ULL,
		0x163CA8F76C150421ULL,
		0x3F1242E5645B7B63ULL,
		0x867D316476D0FE66ULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E3166245213D4E5ULL,
		0x304F021923AA632EULL,
		0xCAB1E493DBFA17DFULL,
		0x34B0D46B89464754ULL,
		0x7103EF2C28135DADULL,
		0x92F0511FC2070A71ULL,
		0x379CB8C1C4CF9806ULL,
		0x8CB9D65D4C9DDC27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2FEBB67FCDB24D5ULL,
		0xA199C968C40A84A9ULL,
		0x3F11832CAB12D601ULL,
		0x2369825876C14B0EULL,
		0x58428C68C76E84F8ULL,
		0x2EC8044A3B8529C1ULL,
		0xB7E035DF13F40E89ULL,
		0x9969C27369342F84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCCFDD43AEC8F030ULL,
		0x91D6CB71E7A0E787ULL,
		0xF5A067BF70E8C1DEULL,
		0x17D95633FF870C5AULL,
		0x29416344EF7DD955ULL,
		0xBC385555F98223B0ULL,
		0x807C8D1ED73B968FULL,
		0x15D0142E25A9F3A3ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA6311B00AD9AE6BULL,
		0x9037652DE7E50B51ULL,
		0x76A71FADBDFC03F9ULL,
		0x91A5A547BD3522ECULL,
		0x4E6E4884A593C093ULL,
		0xB77676107E51002BULL,
		0x460722C93B13CF0EULL,
		0xA5332A7A115F6EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x522322C6A57FE957ULL,
		0xF4C9CFA00A950259ULL,
		0x623A495AC20C43FDULL,
		0x738814ABA080C44CULL,
		0x30C706341260C4DCULL,
		0x046822C158824C37ULL,
		0xA7964990EA9F5CCFULL,
		0x5F9AE165DC22241CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8403376AFA6473CULL,
		0x64FEAA8DED700908ULL,
		0x149D56F77FF04004ULL,
		0xE22DB1EC1DB5E6A0ULL,
		0x7EA94EB0B7F3044FULL,
		0xB31E54D126D34C1CULL,
		0xE1916B59D18C93C1ULL,
		0xFAA9CB1FCD7D4AB9ULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8001C654D4DE211ULL,
		0xBBB12DC4AEFEE717ULL,
		0xB1AEFBAE21EED041ULL,
		0x021BD3CD49D7F92DULL,
		0xC6587BFBC0200BDCULL,
		0x62ED5BEE150373B8ULL,
		0x981DE662A5F76757ULL,
		0x7EAD51A15F907EA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x158F8A1EFDC9EFFFULL,
		0x205DC85781D7BAAFULL,
		0xE28342FF00DD9935ULL,
		0xB4499A9BADE2A863ULL,
		0xD261AEABC5CBAE32ULL,
		0x839F65BF4E248494ULL,
		0x4F30A154C7A35356ULL,
		0xC2C54EBA84278F0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD8F967BB0840DEEULL,
		0x9BECE5932F295DB8ULL,
		0x532DB95121334974ULL,
		0xB6524956E435514EULL,
		0x1439D55005EBA5EEULL,
		0xE1723E515B27F72CULL,
		0xD72D473662543401ULL,
		0xBC681F1BDBB7F1A2ULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92C96F6AC9EF2193ULL,
		0xB80A1454A44C81B2ULL,
		0xFBB3B6300B38373EULL,
		0x109BDF1B7298797BULL,
		0xAF1CAF35C9D04711ULL,
		0xD4A2C308191955E3ULL,
		0x8E10DE78BCEF643DULL,
		0xC93411741EA4DEAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E23E609FDCDA8DULL,
		0x633BAF9FCE32BCA1ULL,
		0xAC828CA5475E0AE0ULL,
		0xEAC3E69DDD074E06ULL,
		0x65F1D2FF1DAA90FEULL,
		0xBB4BEC3F8C3FCD4EULL,
		0xB2C7612C85D2AB15ULL,
		0x519813E979EA7E93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE22B510A5633FB1EULL,
		0xDB31BBCB6A7E3D13ULL,
		0x57313A954C663DDEULL,
		0xFA583986AF9F377DULL,
		0xCAED7DCAD47AD7EFULL,
		0x6FE92F37952698ADULL,
		0x3CD7BF54393DCF28ULL,
		0x98AC029D674EA03CULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3B2BEA81AB3F4E3ULL,
		0xA380FD730D93857AULL,
		0xF5F99445EA81DE98ULL,
		0x1B736FFFC6480F74ULL,
		0xBDD388BC11009AE7ULL,
		0x05D5284833156DFAULL,
		0xA9FF21D2BB5209E8ULL,
		0xB764B181CD106C82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BE11A32F6CA9C46ULL,
		0x4E5080D506973227ULL,
		0xDC1023449DA9E374ULL,
		0x35E683E799CF41B3ULL,
		0x228C7A0E2FC25D15ULL,
		0x4DE9DBC9C436A721ULL,
		0x373A6C70BCFFAFB9ULL,
		0x99B756B1B9AFACC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8853A49AEC7968A5ULL,
		0xEDD07DA60B04B75DULL,
		0x29E9B70177283DECULL,
		0x2E95EC185F874EC7ULL,
		0x9F5FF2B23EC2C7F2ULL,
		0x483CF381F723CADBULL,
		0x9EC54DA207ADA651ULL,
		0x2ED3E73074BFC04AULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F07C72A80AD051AULL,
		0xC435EDE9E15DC12EULL,
		0x3B4B9BD473A521A9ULL,
		0x440A74D67C54032CULL,
		0x51A83B90C3129368ULL,
		0xDCB54C337E21146BULL,
		0xBA8CE69AD237EBFFULL,
		0xF0F9E8B77B3AC56DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74451527B790DA3AULL,
		0x914C092928641DEFULL,
		0x98FC1947D58809D1ULL,
		0x9EE9EA425DA48EF6ULL,
		0x1FED6F14D23D0B5BULL,
		0x2A5358654FF27946ULL,
		0x05E9F8829EE3E55FULL,
		0x7BFA19A3EB0256B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB42D20D373DDF20ULL,
		0x5579E4C0C939DCC1ULL,
		0xA3B78293A62D2878ULL,
		0xDAE39E9421F08DDAULL,
		0x4E455484112F9833ULL,
		0xF6E6145631D36D2DULL,
		0xBF651E184CD40EA0ULL,
		0x8B03F114903893DEULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34CF65823E905791ULL,
		0xF7059D59355238EEULL,
		0x2EEF563D8CB9F7E9ULL,
		0xF12F41CE0AD1547BULL,
		0xBC15930A502BD7AFULL,
		0x166753E32E84BF1AULL,
		0xEB5C22716CCD96B4ULL,
		0x2485609D0FE1B5E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C398A850F4432AULL,
		0x90817CA441206D64ULL,
		0x484D06095259B65CULL,
		0xFF4B6AEF013C46CCULL,
		0xF2BE257850BB5CC6ULL,
		0xCF0A7EA48AEB47F7ULL,
		0x315BD561389C7EF1ULL,
		0x40DB1BF08D242AB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x330CFD2A6E6414BBULL,
		0x6784E1FD7472558AULL,
		0x66A25034DEE041B5ULL,
		0x0E642B210BED12B7ULL,
		0x4EABB67200908B69ULL,
		0xD96D2D47A46FF8EDULL,
		0xDA07F7105451E845ULL,
		0x645E7B6D82C59F54ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78009D2F71E70563ULL,
		0xDDA2EDEDBC20B5EFULL,
		0x8E329F348D57A6F7ULL,
		0x20A7E1B5B2C4838CULL,
		0xCCD1CD51DED54E0FULL,
		0xFB44BC4852A3982AULL,
		0x1A6E528450C6A682ULL,
		0xCA83715B98D65246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF80DEC0B7DBC4364ULL,
		0xE3A4697929BF976CULL,
		0x7845316B6C7827EBULL,
		0x9B2464BA8D6DE77FULL,
		0x96142FDDFDCBB5E1ULL,
		0xAB4BB8CEDE823A07ULL,
		0xE504AB3A2221F4B2ULL,
		0x4536157A8D5BBF4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800D71240C5B4607ULL,
		0x3E068494959F2283ULL,
		0xF677AE5FE12F811CULL,
		0xBB83850F3FA964F3ULL,
		0x5AC5E28C231EFBEEULL,
		0x500F04868C21A22DULL,
		0xFF6AF9BE72E75230ULL,
		0x8FB56421158DED0AULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70C94D8C96CAEBDCULL,
		0xA61265C1A309B1D3ULL,
		0x06F288D3B17E87FDULL,
		0xA5CCA90EC2B95BF4ULL,
		0x916A752DA39A5BEBULL,
		0x450AF7438A517A5EULL,
		0xE90E6E407069BEF8ULL,
		0xA31BC4A4EEC382F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB6D8F9DB314BEFULL,
		0x421315AC8CAE5068ULL,
		0x9345E0CB476DB8E4ULL,
		0xC53004AD224DF3A5ULL,
		0x92B28ED33C8D7415ULL,
		0x55F40DF128D4E7F3ULL,
		0x437368089BB12612ULL,
		0xBF60C199C481E9B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD7F95754DFBA033ULL,
		0xE401706D2FA7E1BBULL,
		0x95B76818F6133F19ULL,
		0x60FCADA3E0F4A851ULL,
		0x03D8FBFE9F172FFEULL,
		0x10FEFAB2A2859DADULL,
		0xAA7D0648EBD898EAULL,
		0x1C7B053D2A426B45ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8479106B6100A42ULL,
		0xD176CFFA971CEBFFULL,
		0x7A705679E341E69BULL,
		0x4F889145E83F8C30ULL,
		0x4B19930C5CECF67CULL,
		0x27711A5C63FF8A79ULL,
		0x23A73678AF28C38FULL,
		0x553B73462EFA663DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D562A2A170AEEDULL,
		0x27AAE227318486D7ULL,
		0x5295C4206B554C62ULL,
		0x5E5D48AA027DB2B2ULL,
		0x025187A6F06F05D5ULL,
		0xA70C7C2A7CF0A3B4ULL,
		0x1656D3F179F4BEF9ULL,
		0x8071D283BFC1F440ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F92F3A41760A4AFULL,
		0xF6DC2DDDA6986D28ULL,
		0x28E592598814AAF9ULL,
		0x11D5D9EFEA423E82ULL,
		0x494814AAAC83F3A9ULL,
		0x807D66761F0F29CDULL,
		0x35F1E589D6DC7D76ULL,
		0xD54AA1C5913B927DULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BBA3D08EE0EA794ULL,
		0x6D1279F7CA584141ULL,
		0x7C8B738C9B12333FULL,
		0xAE6BA8ED71B2F3F2ULL,
		0x42E47FEFB5859654ULL,
		0xB2AFD51C06D8311AULL,
		0x9418E6D47261A3C3ULL,
		0x7E9B8538D34A8A32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D9EE7F726635D1CULL,
		0x136C98CC7F46F75BULL,
		0x87C9E96C2C1C27CFULL,
		0x0641418BBA2349E9ULL,
		0x272B04DC628728DEULL,
		0x4AE6B1F14E53E574ULL,
		0x85CEC36014CB8E99ULL,
		0xE7BCC8B0F53D4F6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2624DAFFC86DFA88ULL,
		0x7E7EE13BB51EB61AULL,
		0xFB429AE0B70E14F0ULL,
		0xA82AE966CB91BA1BULL,
		0x65CF7B33D702BE8AULL,
		0xF84964ED488BD46EULL,
		0x11D625B466AA2D5AULL,
		0x99274D882677C55EULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC72EAC7DB0D6EBBULL,
		0x668E32FEB768EA36ULL,
		0xC33850A91653E4B8ULL,
		0x958BD502CA7F98F3ULL,
		0x5A06B24CAB6F9B1BULL,
		0x8294992D88CB8F92ULL,
		0xB7178548439FBE52ULL,
		0x7D65BE4BDB482476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB433A9229B1E68ULL,
		0x20185025946AA780ULL,
		0x04273E7B9CDB7D3DULL,
		0x642F2CA16F1910FFULL,
		0xACAC3616FC15021BULL,
		0x1DA46C95E351C9ACULL,
		0xF6B91C7198AE9A89ULL,
		0xD33EB5920FD78BB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06C6D96EF99670D3ULL,
		0x469662DB23024DB6ULL,
		0xC71F6ED28A889985ULL,
		0xF1A4F9A3A566880CULL,
		0xF6AA845A577A9900ULL,
		0x9F30F5B86B9A463EULL,
		0x41AE9939DB3124DBULL,
		0xAE5B0BD9D49FAFCFULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D1DC0988AD34570ULL,
		0xFE48E5E75C5EE40FULL,
		0x13BFCD5042B6D1BBULL,
		0x3A6F0FABA27475B9ULL,
		0x43916253AE435B13ULL,
		0x95CE681496480C99ULL,
		0xE5DEA40F29B5F01DULL,
		0xE77958F43B4131EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED066F0CA5C1D02BULL,
		0xF4073D1932DCFD01ULL,
		0x5E385EA66D096575ULL,
		0xA1CF2AF19A36322CULL,
		0xD135F5EC4D120F84ULL,
		0x37794BB4467DF13AULL,
		0x0F9978A94690A7EDULL,
		0x00C0933BAF3DD105ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF01BAF942F12955BULL,
		0x0A4FD8FE6E82190EULL,
		0x4D8793F62FBFB4CEULL,
		0x9BA0255A38424795ULL,
		0x92A497BFE3515497ULL,
		0xA2B723A0D035FDA3ULL,
		0xEA47DCA66F2557F0ULL,
		0xE7B9CBCF947CE0EBULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44177ED142E2FE27ULL,
		0x5B9F2FB9357DFAF7ULL,
		0x4C15BA6A37727161ULL,
		0x1102E792476F6084ULL,
		0xD8C5D00E79A210BDULL,
		0xF70665FB008250B0ULL,
		0x6D4ED8B11B2E18EBULL,
		0x1176CFF71EE08B7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EEA7C7A9C782961ULL,
		0x235F84C252B99F74ULL,
		0xDCB97EB188A0C8ABULL,
		0x0959D104877B7FA7ULL,
		0xC22DCDF30527F190ULL,
		0x2DC1D87A1FD06527ULL,
		0x65A425FF904177F5ULL,
		0x02CFB0AE75B7ECC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AFD02ABDE9AD746ULL,
		0x78C0AB7B67C46583ULL,
		0x90ACC4DBBFD2B9CAULL,
		0x185B3696C0141F23ULL,
		0x1AE81DFD7C85E12DULL,
		0xDAC7BD811F523597ULL,
		0x08EAFD4E8B6F6F1EULL,
		0x13B97F596B5767BDULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x749D3EB06EC05BF1ULL,
		0x5CFAADDE05F98184ULL,
		0xD23D6DF5F79705A3ULL,
		0x998D884A63CE68F8ULL,
		0xB3B5DC3A16AC7FF6ULL,
		0xC25FA03D61A9E97EULL,
		0x44F51EED4F779871ULL,
		0xA76E5B487C303C4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5597496B391AA65ULL,
		0xE8F325EE9DB87671ULL,
		0xD499D12F61237DEFULL,
		0x3D206F8E7416890EULL,
		0xB33D4F3A5DE67DCBULL,
		0x88A8F76C162D877DULL,
		0xC7A845A7F46C8938ULL,
		0x9E5141154489D167ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C44A26DD51F194ULL,
		0xB40988309841F7F5ULL,
		0x06A4BCDA96B4784CULL,
		0xA4ADE7C417D8E1F6ULL,
		0x008893004B4A023DULL,
		0x4AF7575177846E03ULL,
		0x835D5B4ABB1B1149ULL,
		0x393F1A5D38B9ED2DULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E5F8D2992113D41ULL,
		0x53A553CA3900B5B1ULL,
		0x7E9F095AA1A7E3A5ULL,
		0x30B7F45912DD64BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702453F487DF6A54ULL,
		0x648E7F44F340E123ULL,
		0x70661DA10EFF0E86ULL,
		0x006C8326D7465DBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x702453F487DF6A54ULL,
		0x648E7F44F340E123ULL,
		0x70661DA10EFF0E86ULL,
		0x006C8326D7465DBBULL,
		0x8E5F8D2992113D41ULL,
		0x53A553CA3900B5B1ULL,
		0x7E9F095AA1A7E3A5ULL,
		0x30B7F45912DD64BEULL
	}};
	printf("Test Case 501\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD18BA7DE06D10E3ULL,
		0x173341F205E5B5D5ULL,
		0x33D0B3EA99A4FC04ULL,
		0x676C855DBD700371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE57A8D58C0A08BULL,
		0xC4EAC2CC717068F7ULL,
		0xA556131DAAD2B1B7ULL,
		0x4591776E92A0288AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BE57A8D58C0A08BULL,
		0xC4EAC2CC717068F7ULL,
		0xA556131DAAD2B1B7ULL,
		0x4591776E92A0288AULL,
		0xDD18BA7DE06D10E3ULL,
		0x173341F205E5B5D5ULL,
		0x33D0B3EA99A4FC04ULL,
		0x676C855DBD700371ULL
	}};
	printf("Test Case 502\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 502 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF1DFD21D39568E3ULL,
		0x897636BCAAE5C610ULL,
		0x419AAD3292D809ECULL,
		0xE41F81F862FC6C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB7F5AC21BEE9C27ULL,
		0xC81414DDA4A74349ULL,
		0xBA89CF54A11DAEC0ULL,
		0x83E13FF15EE8D242ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB7F5AC21BEE9C27ULL,
		0xC81414DDA4A74349ULL,
		0xBA89CF54A11DAEC0ULL,
		0x83E13FF15EE8D242ULL,
		0xDF1DFD21D39568E3ULL,
		0x897636BCAAE5C610ULL,
		0x419AAD3292D809ECULL,
		0xE41F81F862FC6C99ULL
	}};
	printf("Test Case 503\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 503 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1687C24317A0577DULL,
		0x7B521B1A9BC09BAFULL,
		0xB0572CE934CE7384ULL,
		0x169A28DDA87006DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58ECA677F5973C3BULL,
		0xD29358FE9B823F81ULL,
		0x35CB24D3219627BAULL,
		0x383B40C5F288465DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58ECA677F5973C3BULL,
		0xD29358FE9B823F81ULL,
		0x35CB24D3219627BAULL,
		0x383B40C5F288465DULL,
		0x1687C24317A0577DULL,
		0x7B521B1A9BC09BAFULL,
		0xB0572CE934CE7384ULL,
		0x169A28DDA87006DDULL
	}};
	printf("Test Case 504\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 504 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x085F8B9843F69098ULL,
		0x2DDF6CFA12F43F8FULL,
		0x08EFD11C6FA34B1BULL,
		0xE027289B6CA8B059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9D74A3C1A5754CFULL,
		0x4062F36FCFBEDFFDULL,
		0x67A989F034DBC2BFULL,
		0x6AF5391A8B998911ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9D74A3C1A5754CFULL,
		0x4062F36FCFBEDFFDULL,
		0x67A989F034DBC2BFULL,
		0x6AF5391A8B998911ULL,
		0x085F8B9843F69098ULL,
		0x2DDF6CFA12F43F8FULL,
		0x08EFD11C6FA34B1BULL,
		0xE027289B6CA8B059ULL
	}};
	printf("Test Case 505\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 505 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD20AEC00C0C10D4ULL,
		0xDA6CF3AC303D1E03ULL,
		0x69232E5CEA0D88B2ULL,
		0xE03B5E0FA0EF442CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2244AF095F4C289ULL,
		0xF2F84ABB63E6CA97ULL,
		0x3D1A3E7A5C845874ULL,
		0xD48C1EED768FEE61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2244AF095F4C289ULL,
		0xF2F84ABB63E6CA97ULL,
		0x3D1A3E7A5C845874ULL,
		0xD48C1EED768FEE61ULL,
		0xCD20AEC00C0C10D4ULL,
		0xDA6CF3AC303D1E03ULL,
		0x69232E5CEA0D88B2ULL,
		0xE03B5E0FA0EF442CULL
	}};
	printf("Test Case 506\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 506 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93C84CCCDF78B7C5ULL,
		0x3326DAE54568945CULL,
		0x6DA1CF2F302962EFULL,
		0xEABE74344B9F13F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27947C0C7D15BA97ULL,
		0xF19134ED976336D6ULL,
		0x960D65E00B29512DULL,
		0xBC51B9FEAAD26CE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27947C0C7D15BA97ULL,
		0xF19134ED976336D6ULL,
		0x960D65E00B29512DULL,
		0xBC51B9FEAAD26CE4ULL,
		0x93C84CCCDF78B7C5ULL,
		0x3326DAE54568945CULL,
		0x6DA1CF2F302962EFULL,
		0xEABE74344B9F13F0ULL
	}};
	printf("Test Case 507\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 507 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x086E8458F076212EULL,
		0xE1B5814B91FADCC4ULL,
		0x45893DA49AFD61A5ULL,
		0xDEFCD687E5A8D7CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56B87E7053F07ABULL,
		0xB05EBC7FB8CF830DULL,
		0x6BB05059519AF0D4ULL,
		0x286877EE2E139A28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA56B87E7053F07ABULL,
		0xB05EBC7FB8CF830DULL,
		0x6BB05059519AF0D4ULL,
		0x286877EE2E139A28ULL,
		0x086E8458F076212EULL,
		0xE1B5814B91FADCC4ULL,
		0x45893DA49AFD61A5ULL,
		0xDEFCD687E5A8D7CDULL
	}};
	printf("Test Case 508\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 508 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D62C33F7479DCB2ULL,
		0x51D49EC55A0A9B98ULL,
		0xA3D13545CE2EC1A4ULL,
		0xE521BEB0772309B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8498CA5D84B323B1ULL,
		0x96A8742570205A59ULL,
		0x9385B34E16ACC043ULL,
		0xE483CE69D3BCC22CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8498CA5D84B323B1ULL,
		0x96A8742570205A59ULL,
		0x9385B34E16ACC043ULL,
		0xE483CE69D3BCC22CULL,
		0x2D62C33F7479DCB2ULL,
		0x51D49EC55A0A9B98ULL,
		0xA3D13545CE2EC1A4ULL,
		0xE521BEB0772309B8ULL
	}};
	printf("Test Case 509\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 509 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD37489155718FB9ULL,
		0xF4A4BCA2A894CC8AULL,
		0x9FF68589A5A46EB2ULL,
		0x5CB08A8F51340936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9839FB95300FD5EULL,
		0xAB555A866E50BE4EULL,
		0x6C9689496592CBD6ULL,
		0x971F46BF3BDE1BADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9839FB95300FD5EULL,
		0xAB555A866E50BE4EULL,
		0x6C9689496592CBD6ULL,
		0x971F46BF3BDE1BADULL,
		0xCD37489155718FB9ULL,
		0xF4A4BCA2A894CC8AULL,
		0x9FF68589A5A46EB2ULL,
		0x5CB08A8F51340936ULL
	}};
	printf("Test Case 510\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 510 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}