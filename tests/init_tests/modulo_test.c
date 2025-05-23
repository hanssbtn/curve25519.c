#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xF069C18D1A1F8F06ULL,
		0x70AF42BFD0BEE838ULL,
		0xB2EBD2C4D26C69C4ULL,
		0xC0828DF75A4BEE0FULL,
		0x41FE8E7F2B3A390DULL,
		0x507C9517AB9BB117ULL,
		0x300126A9AF1E6FAFULL,
		0xE402558DD460060CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xBC32E86D84C40C13ULL,
		0x632D644349DB31ACULL,
		0xD3178FF4D0F0FDCAULL,
		0x18DB4104E08CD3DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68DE20C7C298B20EULL,
		0x1F94790411A744B8ULL,
		0xE2804008D296D793ULL,
		0x67D2A2CA972DD8A2ULL,
		0x0AD0F395341BADCDULL,
		0xB6D8017BA2B98656ULL,
		0xF7E44ED13F2C3F38ULL,
		0x8BAC168C8CDD7BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E248ED7EB4819AULL,
		0x43A4B15E3931357EULL,
		0xAE63F318332839FEULL,
		0x235DFBA7800E376DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9D1B3E554ABAC93ULL,
		0x55DA071785F21DE7ULL,
		0xBA83DB77F36370D5ULL,
		0xC9461AB702630AB9ULL,
		0x7CC53E05890061BFULL,
		0x4EF22D46EAACEB16ULL,
		0x94BBD993F8D51DF5ULL,
		0xA18DD19B505C0505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F18E8B7AABA3290ULL,
		0x0DCCBF9E5B9D033EULL,
		0xCE66276EE305E33FULL,
		0x445337C4F00BC98DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66AC1D44055A4B41ULL,
		0x82F2ED8011B3E842ULL,
		0xB7A419E25F9AF60DULL,
		0x085F251192C60860ULL,
		0x07454419D393406BULL,
		0x4A0CA3970860D5BAULL,
		0x2D3E0F381FFA63D1ULL,
		0x15004FE2FD64DAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AF439196D35DB95ULL,
		0x80D335EB5013A1DFULL,
		0x6EDA5C371EC5C71EULL,
		0x266B00C32FBE882DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BD62866DE021006ULL,
		0xA3F6CD02F3889C11ULL,
		0x34160754D60D4E71ULL,
		0x00DCBFF9DAA19232ULL,
		0x9C174688322B9E6DULL,
		0x544432B17A7DFC0EULL,
		0x9C948B71ACF2A803ULL,
		0x4ECD21CE46777EABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x774AA09E507B95E9ULL,
		0x2616535B223C063CULL,
		0x7222BA3482123EF0ULL,
		0x334FC498505E5FABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E94076D7C328645ULL,
		0x3867F79461296282ULL,
		0xBC19E2F894C676AFULL,
		0x088902FC9C27EA50ULL,
		0x43455D682D6BA115ULL,
		0x638906C121724FD1ULL,
		0x3DCD780FE140C6CBULL,
		0x87C28CE6829F21B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ADFE4E43A2C725BULL,
		0xFEBEF83F58213B92ULL,
		0xE899B5540463F8DFULL,
		0x2F69ED33FFC6EB37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F590CC6C96C64BEULL,
		0xD8DC41D65740F9F7ULL,
		0x526076958F2A60DEULL,
		0x22B94A3350AACEFBULL,
		0x2C7A86BD76C492B1ULL,
		0xF3371FC5866F1FEDULL,
		0xEC849B6A58A95C8BULL,
		0x5E4BA83CE00C4BCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19890CE66A9A2D18ULL,
		0xF30AF9284BBFB72CULL,
		0x6E0F885EB84E1DA4ULL,
		0x21F4433C927E0F40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7A45A8FDBC0FAECULL,
		0xBD1B60B6FD554230ULL,
		0xC91729A6E7CCC3FFULL,
		0xEF55AED36198F366ULL,
		0x80BD406296A5C150ULL,
		0xC836B0917FAFA294ULL,
		0x2886005E778F1524ULL,
		0x9A4B9C8CD5CB47A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3BBE932385BB049ULL,
		0x7539964FF167643BULL,
		0xCCFB37ACA709E775ULL,
		0x568EEBBB1DC59578ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BDA00091C0466EAULL,
		0x24699B8337EAFF46ULL,
		0x7879ECE1947528B3ULL,
		0xA89FCDEC20B370A2ULL,
		0xB4D9ACE82B453599ULL,
		0x8FB1C0BC5E20DB91ULL,
		0x35E1B0AAE7165186ULL,
		0xDD4703A465A59A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3429AA7F884A6099ULL,
		0x78CC377930CB96E7ULL,
		0x77FA263FE1C542ACULL,
		0x012A5853374862EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D98EE9AF69349AAULL,
		0x2A197B5DC8E1387EULL,
		0x9E3252245EC0ED93ULL,
		0x30E98FB8A97DC2C2ULL,
		0x1D158FEBAAC86A6FULL,
		0xA8D93C6A86560C47ULL,
		0x720987C9848BBA17ULL,
		0x35BA372776144CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAECC4B9650531754ULL,
		0x3A58732DB9A70B0CULL,
		0x8B9C7A0E0B7E8D16ULL,
		0x2A8DBF9430812707ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD2F2CFD08DFE252ULL,
		0x6076660279CCBBD9ULL,
		0xA009ED07D5147068ULL,
		0xB42839DBA262400AULL,
		0x53292B48B74EF10AULL,
		0x8322596BBD9BA60CULL,
		0xCAFC8C6CC8663CD4ULL,
		0xEEBC74E85F61BE02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x554B99C83E97AF26ULL,
		0xD78FAC009EE761AEULL,
		0xC186C52D944177F3ULL,
		0x24219459CAE47474ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9241179A6E80405ULL,
		0x2EA7DDE37D5869BCULL,
		0xFF040B6AEC1BDF17ULL,
		0x12F72FD110465CBAULL,
		0x4578FF04799A9ADFULL,
		0x9678911662DB6ADBULL,
		0x225584D67F05B75EULL,
		0xF6D2754F75167938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1919EC23B3DB068AULL,
		0x848D673629EA4649ULL,
		0x17B5C341C6F51721ULL,
		0x3634999C719C5B10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC5ABBD0EF6E4BF4ULL,
		0x3BB6F65012A1E818ULL,
		0x3168743363665F88ULL,
		0xAF65FF14A8B5FEB7ULL,
		0x7E40D4453E482135ULL,
		0x70824B3A0E6C74C5ULL,
		0xB1F33D85ADF1EDA2ULL,
		0xA50A33BA713D3CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FA3E182E233D88ULL,
		0xEF0E20EE36BB3D69ULL,
		0x9B83960B354FA5A4ULL,
		0x2EE9ACC177CD09B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93BFF6C5A56D11B8ULL,
		0xC0187B55E3810BEFULL,
		0xDD017EE148ADBC9EULL,
		0x58FC9D1FC8CC5EC6ULL,
		0x6508079C55704F88ULL,
		0xEACC94ADC58C00A5ULL,
		0x131A14761F86B44CULL,
		0x5E26158585DCFD10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F117FA5418E1FCULL,
		0x9A768D213649247CULL,
		0xB2E08869F6AC8009ULL,
		0x52A3CEF1A799EF29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x907EB4477C2E0C5EULL,
		0xB764CF4C0BCEA0CBULL,
		0xCFF3FEBFBCDEDD04ULL,
		0xDC5F4614DB898D5EULL,
		0x32FB63DD986567C8ULL,
		0xDEDE2C710D12D6FBULL,
		0xDB883802ECA051F1ULL,
		0xBE1AAC27C0D08C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21CF872C1B3B785CULL,
		0xCC5F6813FC9A8A15ULL,
		0x662C4F2EDCAB06EBULL,
		0x1454D3FB7A7E5D11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x651B05E475447319ULL,
		0x618AB7A0D8FBF91FULL,
		0x3B6FB50B41B99559ULL,
		0x78A4E42EDA038806ULL,
		0x2D6C919858D3C829ULL,
		0x08570602198558C0ULL,
		0xAB4BBD3B7AC42CE2ULL,
		0xAAF1D3B5DDC03894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2338A281A4B42CF8ULL,
		0x9E759BF0A2C725A6ULL,
		0xA8ADCBDF7AD83EE6ULL,
		0x588A512DC48BEE17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91F3B82EDD757A04ULL,
		0x6B5209C72A5DADBAULL,
		0x4410E4DD5D65BA32ULL,
		0x6BA6A1C1286A9238ULL,
		0xDB5C442B86B5A013ULL,
		0xA01430A0AB517B6EULL,
		0x66C1D57A29EB1382ULL,
		0xC15D00C1F7EEC9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A5D6A4DC6B4124ULL,
		0x2E5141A09876002FULL,
		0x84D694FF964A9F96ULL,
		0x1F74BE8BF5DC8CF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A1D0E38981461F3ULL,
		0x1B3479B41567B67BULL,
		0x0DCCC66D1B32C23FULL,
		0x386D93631610012FULL,
		0xE24FDFEA5427D13FULL,
		0xC0ADAA2282F2D3C9ULL,
		0xF5DB537DB3AEABD3ULL,
		0xAE3A736DBC416BEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F84B0115FD7529ULL,
		0xB4FBBAD385732672ULL,
		0x8C5B2B15C72043ADULL,
		0x151AB5AD07C606CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2668499ACCE6F18EULL,
		0x98BB14A9E1CE8355ULL,
		0x111CF6D4D07ED4C2ULL,
		0x8D2A7465A2C051B4ULL,
		0x111F0BB280ACFD61ULL,
		0x1D8678696BC79E95ULL,
		0xFBABF41904D6A02BULL,
		0x6C702F64CBEA3323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1040619E6949067ULL,
		0xFAB0F44FE1700D75ULL,
		0x6CA3328B885A9B28ULL,
		0x25D17D5BE783E90BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDDBE354718E6C2EULL,
		0x68A56783E62C4530ULL,
		0x4911B6A06D549FB5ULL,
		0x1BE82113FB1B11D2ULL,
		0x587F1206BBDB229BULL,
		0x35A8C86871ACDD7EULL,
		0xDD513845218C4079ULL,
		0xC5AABF541F444B74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B890545415937EULL,
		0x5FB32704C5D525F2ULL,
		0x232010E3682631B3ULL,
		0x734087909F3E452BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4C8AD4B7ACC3A30ULL,
		0xB0DFB849C0DF5288ULL,
		0xB136BB6346156662ULL,
		0x75A9AF927C650C7CULL,
		0xA060BDB6F5DF233AULL,
		0x8FCB8D5195C79819ULL,
		0x41877D99F99F5C7AULL,
		0x657177923271A4F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA324D673F9EB7719ULL,
		0x0916B265FC7FE656ULL,
		0x6B53603E53BD2094ULL,
		0x04816F45F9438898ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x104B44A5C11DFBB4ULL,
		0x33AA78CE3B18CA0FULL,
		0xA7BA5D0D715B1857ULL,
		0xCE8E40E7B6EC3D6AULL,
		0x21B0CF6ECC52A363ULL,
		0x9D1CC3E83FEA0860ULL,
		0x7D21369D33D85154ULL,
		0xE276EDFBFF8F361EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108A0F1815624172ULL,
		0x85EF8D47B7D60854ULL,
		0x3AA8786323772AE6ULL,
		0x6C35944FA62E45F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A0729E45028893FULL,
		0x0A701CBBBAB42C96ULL,
		0x269B74358225BF16ULL,
		0x6A1CE4FF57D4F39EULL,
		0xCCB0D1F73D0DB1ADULL,
		0x7E295D972E1D24C0ULL,
		0x38671BF1B2BE4BDCULL,
		0x813551791E60061CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC4654976030EBD2ULL,
		0xC494012C9307A134ULL,
		0x85E99A160A6501D0ULL,
		0x1806FCF9DA15DBCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9A8A9C345C3CE21ULL,
		0xC4D6E2E7E6EC60B8ULL,
		0x708F88414D68DBFDULL,
		0x1A69B107D6F5CABFULL,
		0xD15A9F565EB1D038ULL,
		0x278DCA2CF50CD76CULL,
		0x2765D1A172C2AEB5ULL,
		0xFC76334784988A4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1C50955428BC02ULL,
		0xA3E2E59446D45AE0ULL,
		0x49ACA638564ECAE1ULL,
		0x13F54DA5859A51C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA15A32A331FD9AF3ULL,
		0x621452B2E40AA882ULL,
		0x7B916585D302FB7BULL,
		0xC3F1154DD52D8816ULL,
		0xF3879183462FEE48ULL,
		0x0073E357A34E0446ULL,
		0xE6D09017471FF6ABULL,
		0xEC6541528FF6F652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC779CC1F9D1AFEE8ULL,
		0x734811B5219F4B0AULL,
		0xBE86C8FA61C198DDULL,
		0x5AF8C78F33D61864ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB98EF4E1DB04A56ULL,
		0x763831D6B55A4DFAULL,
		0xEA87F154442C652DULL,
		0xF9B95B0C3857DC69ULL,
		0x83D3EA60E5745368ULL,
		0x5D99BE1B1B5FD1A5ULL,
		0x399B36FB29E515A9ULL,
		0x8DEFCBB220FCA9CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D0DB9B02CF4AF0AULL,
		0x5B0A69DCC5936C8CULL,
		0x77921A9C7C2D9C51ULL,
		0x0B51977D1DD910BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FF8F301E05E89EDULL,
		0x41A25DF7FB5C38F8ULL,
		0xC5BE21875D4D7405ULL,
		0xCACEAEAE4B3AF188ULL,
		0x6E5A9FB51AE4629BULL,
		0xC7AEFBD588D5EEB6ULL,
		0xB5278B6455A266B3ULL,
		0x4FD7740936079279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x816CA7E3DE452ECAULL,
		0xE59BBFAA4B1DA80CULL,
		0xA99CD26C1368B2B4ULL,
		0x24C9E80C505AAF99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x351986189968BA06ULL,
		0xE363F4A51AD77F5EULL,
		0x81F843C188808D7CULL,
		0x40A92CAA3A42A7D3ULL,
		0xB1959FFCAE9672DBULL,
		0xD9B5B7DD41BEE7B7ULL,
		0x82E00E8016384ABEULL,
		0x87A4A4D01FC185B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x914F459A83BDC980ULL,
		0x345D3F7CDD2DE4A2ULL,
		0xEF3A6AC4D4DBA5D1ULL,
		0x6319A38EF0FC80C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCC2F9C9070E3DB9ULL,
		0x52D75A0D9AED52ABULL,
		0x39E822DE9648BD63ULL,
		0x02F96DFE4FEAB610ULL,
		0xCF34EB572F7928B0ULL,
		0x839CFC9AEFFF82C2ULL,
		0x40699B4E9C2BF97EULL,
		0x0858B7EC29F55709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9DE8BA130A47FFULL,
		0xDC24D90D3ADABB96ULL,
		0xC9953089C4CFC62AULL,
		0x4024BB0C8A55A16FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF53C974213EAC920ULL,
		0xADF456277818A9A1ULL,
		0xDF0B11D432078E79ULL,
		0xD29E007DCE4FDCD1ULL,
		0x2A081D043BE95D89ULL,
		0x5F7B5758479E0FC4ULL,
		0xD150BAC10D9B092CULL,
		0x0A7EBE37CCEA127FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3270E5E2F88EABC2ULL,
		0xDA434D42198F00C0ULL,
		0xF106CA7C370AEB0FULL,
		0x616E3CC6390E9BCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32EFD8E8B4C60BAEULL,
		0x472D0D001D94D2A7ULL,
		0xCF26C517553AA412ULL,
		0xC7979234D99DFEFDULL,
		0x965B1F0C3E655DC3ULL,
		0x5245894B861F87C8ULL,
		0x8002EDEC9BF6E480ULL,
		0x798CAAC8E28ED905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x847674B9F7D1F95FULL,
		0x7D7F6E360642FA6DULL,
		0xCF9616367BE08F1EULL,
		0x5278EC067AD235CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A769991C79991DBULL,
		0x7BDC4913C32CABC5ULL,
		0x902F4E3979071C59ULL,
		0x1788790A94386003ULL,
		0x76DDDD0DC05F1B98ULL,
		0x3B242EAB28BE58DAULL,
		0x140CB7649D134EC0ULL,
		0x05333DE9A4C0DB9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF65699C55B7AA7EULL,
		0x433B367BCF6DDC32ULL,
		0x8A128728C9E4CCE2ULL,
		0x5D23A9B908D8F97AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x009DCF6732ACE74AULL,
		0x97B79F616C1B5523ULL,
		0xCA2C168BF8423E73ULL,
		0x70A24D7F75F12F10ULL,
		0x230DFF3876596DEBULL,
		0x3D7363C4E39A9417ULL,
		0xA1DC02FC0F4C1AB7ULL,
		0xADA29049D6C33F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B1B1C8C3F33C08ULL,
		0xB6D86E9B350D5092ULL,
		0xD0D487F63D8E35A6ULL,
		0x36C3B87556EC8928ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D22B34286956E4BULL,
		0x1CC2682512ACB2C5ULL,
		0xD072D6AFDBC81E0BULL,
		0xFB518A9BFB123621ULL,
		0xCC292C45C3C48E2DULL,
		0xD7FC518F150DFB8CULL,
		0xAEDCC2962C9AA328ULL,
		0x9318F708BC1D70D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB3F459D95C28C50ULL,
		0x2C36836232C009ABULL,
		0xC537B8FA7ABC561BULL,
		0x510635E7E770F541ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0757CC7272E93F4ULL,
		0x8B992278FEDD0A23ULL,
		0xE351F4587F257DA8ULL,
		0x7D449E5064CAFAE9ULL,
		0xADAB8FD2679C17E8ULL,
		0x5E1BA2FEB2E89B6CULL,
		0x05CDF4E285C9022BULL,
		0x6B938E91228B93E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7ECD602885A22C4ULL,
		0x83B354478D641C45ULL,
		0xBFE44DF85AFBD018ULL,
		0x752BC7DB8582EE9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B8FCC6D65CE086EULL,
		0xFBC4B8CA1AD1F933ULL,
		0x9A1990021B819162ULL,
		0x4E39EB65AEDC8523ULL,
		0x31C26A1B008C0F7EULL,
		0xA504847B85983656ULL,
		0x4CF71021841B8805ULL,
		0xB153C154C28DAA68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E6B8C6F7A985911ULL,
		0x7A70631FEF6A09FEULL,
		0x06C5F4FBB797C239ULL,
		0x20A89DFA8FE3D09FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F6E7E2027C65C6FULL,
		0x0166E5B81D17B57AULL,
		0xEC9F63AEC6EDD5A0ULL,
		0x59B9E398DD3D0EF2ULL,
		0x55E595ABF23C0911ULL,
		0xD818FF1B0F0E2BBDULL,
		0xD8FA50DA831D3013ULL,
		0x95A95CE06618C83CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF82B5A61CAFB84CULL,
		0x151CC3BC59323394ULL,
		0x21C7641E3D42F892ULL,
		0x10DDACE804EAC7FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40D09B0D8DDBF62AULL,
		0xCD96EC9B810A882DULL,
		0x1D06D6FFEB92F3B9ULL,
		0x462136857A30481FULL,
		0xDE89416E9C701CE3ULL,
		0xA8757C9D7F11CFDAULL,
		0xD3F50CD75E6F9C16ULL,
		0xD9B93722FF3047E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49305178C68044AFULL,
		0xCF076BFC5DAF62AAULL,
		0x9366BEF7F0241F16ULL,
		0x179F65B75B5AF3A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63553DC5E92C28A9ULL,
		0x0321D3F924242D1CULL,
		0xE0AFF9B52D2122EBULL,
		0xA2E34CB784D30577ULL,
		0x84D854C5E29B4B65ULL,
		0x31B9672FF8972251ULL,
		0xBB683D145C4FB817ULL,
		0x820D96260D7C0435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B71D3258C395C8CULL,
		0x64A725180A934536ULL,
		0xB2290ABAE0F6765CULL,
		0x70E7965D853BA571ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x754E8337A1B33AC4ULL,
		0x6156DB49529DE4A6ULL,
		0x02E0991AE21A1B91ULL,
		0x215935515921E472ULL,
		0xEE8BAD2F9ADAA243ULL,
		0x6A634A995938A6E1ULL,
		0x73FD424E7F669D10ULL,
		0x2726AA0459B45D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0A38489E275187ULL,
		0x2C13EE0C9106AA2FULL,
		0x3A7870C1CB556C01ULL,
		0x711671F6A9E7C09DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7932C3F77DDD15BULL,
		0x74E890DB3C801590ULL,
		0xC7E0B123A69AC90DULL,
		0x948886D188AC7FABULL,
		0x08700A266CFE1B07ULL,
		0x9416459E17819EDBULL,
		0xEC4BB32347273137ULL,
		0x39E63877FBB60269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2834ADF3A595D5BBULL,
		0x7036E652B9BDAA14ULL,
		0xDB1D4860366C174DULL,
		0x2CB4E8A0E5B0DB64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C109A714CC13F95ULL,
		0x5ECDD9E0BBAA7866ULL,
		0xB6EB2C480C8D2756ULL,
		0x2175DB3E7BA42A2EULL,
		0x2B01861DBC00446CULL,
		0xF7CC856D1FB9CDDAULL,
		0xA4434788CDC8A6BCULL,
		0xAFCDB141A8752B51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4A82DB34CB6B79ULL,
		0x2729A813713F06C8ULL,
		0x18E7CA969855E763ULL,
		0x39FE2AFD7D08984DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x737CB44429DF3FF8ULL,
		0x4913060BA662873FULL,
		0x1120727023DF2D82ULL,
		0xF0701F6A53A65D1BULL,
		0xFB92985F0662FFD8ULL,
		0x6D4D23EA4CD263FEULL,
		0x2B4DA93AE8E90812ULL,
		0x7544642F8E7EF233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB3F525F1C913CB4ULL,
		0x82865AD30D9D5F18ULL,
		0x7EA7912EB676603EULL,
		0x5896FE797A7E50B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC275215069648884ULL,
		0xD88A3A81D3E97B76ULL,
		0xF083A80321A9930FULL,
		0xF5D36F3F72569AE1ULL,
		0xD4FAFA3DB9B9F9FEULL,
		0x5C6D6837538C5BE9ULL,
		0x087AE626D8FAB7DBULL,
		0xD93000E22808EEFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FB64679FAFFA91EULL,
		0x90C7B2B83ABF202CULL,
		0x32C1D1C756E0DD9FULL,
		0x32F390D163AA13FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC54933478B56795ULL,
		0xCA4858422DD60A5BULL,
		0x28214D2646AC5E87ULL,
		0xEBEBBA082083744DULL,
		0x86025ED5DFBA2BACULL,
		0xD69B1C71B5092942ULL,
		0xE29C5AE1563F1CE2ULL,
		0x5EE632BF2E438541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0AEA6F3AE57E557ULL,
		0xA54E91230D322A3BULL,
		0xCB56CA99140AA833ULL,
		0x02174268FE893C14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCDA540AB735F8E0ULL,
		0x7491D9931C4D0541ULL,
		0x9E7810F15E4790DBULL,
		0x324709092FBDF805ULL,
		0x83C0E746E3D05CD7ULL,
		0x13A6573F069BACCAULL,
		0x820FEEDBBA785B88ULL,
		0x36CC0739844D626FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7CA8908823C1FAULL,
		0x5F42CCEE1768AB51ULL,
		0xECD5858F0C25270EULL,
		0x54901B92D33A9492ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00F6E028FE8FEFF7ULL,
		0x4C7984F97010FB59ULL,
		0xDD7299B0226BC7A2ULL,
		0xB70CC39CADEBCFBCULL,
		0x6BD18BE7E2E44896ULL,
		0x69EA2AEDB8BBCE7EULL,
		0x5BD3376D3E91C0A0ULL,
		0x633E699EAAB99EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0211A494AC72B875ULL,
		0x053BE442DBF1A21DULL,
		0x7ECCD3E76C0E5F72ULL,
		0x7250712A05795F40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50BB4AC07F43F6ADULL,
		0x114371A00205A3E5ULL,
		0x081E29AE3AD49749ULL,
		0xB968C9072E5DC7A7ULL,
		0x822C6A22634B4F0EULL,
		0xE48D831E0EB5124AULL,
		0xDB9A54168D184329ULL,
		0x08021189C46D0718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3530BDB3C71B2FAULL,
		0xFE44E81630E65AF4ULL,
		0xA106A5072C6E8F80ULL,
		0x69B7637A568CD557ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x412EDB3E241FE1D8ULL,
		0x3BB3144B616027BBULL,
		0x337CC845E85BFD51ULL,
		0x8DE3A17EF1BD9DB0ULL,
		0x7F804B1B3E802EFBULL,
		0x0466AFCCCCBAF948ULL,
		0xC131168E38D517E8ULL,
		0x840FCB28C054A809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E3A01496B26DE12ULL,
		0xE2F12CB1C521287EULL,
		0xE0C6216257FD89C1ULL,
		0x283BC98B7E4E8F22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB63D8C9BF430F98FULL,
		0xC7D2BE766CF040CFULL,
		0xAA9110A3E73DADCAULL,
		0xDBB0DB427FFC87ECULL,
		0xE66CDE738AF76B78ULL,
		0xE914233E98CD7F80ULL,
		0xB6E14FAC16F2287EULL,
		0x7D08ED5E2C11F05DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA6691C294EAF031ULL,
		0x60CFF9C11B712DF1ULL,
		0xD002E42F4F2FB0A1ULL,
		0x6B04173D0AA635D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F4192EE41614EDCULL,
		0xF7F06B6378F8089BULL,
		0x84CEB799788C754DULL,
		0xEDA4916EBB9E07B0ULL,
		0x2BD9B33D4E5D28B3ULL,
		0x28663B415F959857ULL,
		0x1F9FF5AEA22A8BF0ULL,
		0x3A630F9BBB8FDF43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1922E07E3355AD7ULL,
		0xF71D3717A92CA58BULL,
		0x368D2F858ADD3AF3ULL,
		0x1858E28C92F92BA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62461373C20E2F84ULL,
		0x57EC974FB97AF383ULL,
		0xEF8B8809E0F9623AULL,
		0x79DDC9B9FEA2CE39ULL,
		0x21CCE5861931E758ULL,
		0xD5C5D8614FB45BEDULL,
		0x6029A40F934B53EBULL,
		0x0EBB0C92624E7F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66B0255B7F7686F3ULL,
		0x134AB5C18E4098B6ULL,
		0x35B9E259BE27D73CULL,
		0x29A1A7749649B8C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B3E53ECCCDAEA89ULL,
		0x69EA07CB84FB711BULL,
		0x52751BB2947039D5ULL,
		0x2029EC8A1F75D97CULL,
		0xA9FBB217885CD966ULL,
		0x15D966234EEA253AULL,
		0x0E859D6F67769D3FULL,
		0xF75A3B71DE2B5CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x569AC36B0AA33518ULL,
		0xA82F31093BBCF7D0ULL,
		0x7A4A7A3BF00B9132ULL,
		0x578EBF7119E59FECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECA8B415936CBE70ULL,
		0x36384AFF383D19E9ULL,
		0x074E410C01CADD3EULL,
		0x2F830916E6B122F1ULL,
		0xB87DFB3A04C882A8ULL,
		0x502364981C5A933BULL,
		0xD8B42C08DA759F60ULL,
		0x80D685D845E648E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F5BFEB249302632ULL,
		0x1B7939936DAEF4C7ULL,
		0x320CCA5C6F40858AULL,
		0x4F5AE73146DFF581ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAF43B16128AFCC2ULL,
		0x8FE3954620318CA0ULL,
		0x4E52F7E7222561F3ULL,
		0xB4C3D29C96D9F494ULL,
		0xBAC30169D914EB3FULL,
		0x80C00DE1037604E5ULL,
		0xACCD1BB34CC25DF7ULL,
		0x7804395A95D30C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E670CC4BA5EADBULL,
		0xAC65A4ACA3B646BAULL,
		0xF4C5148486FF54B0ULL,
		0x0564560ED42DCB39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16A983F8F95C6CCFULL,
		0x2F965C7C7C9B4461ULL,
		0x3C751D00FF049418ULL,
		0xC5156D26F8233086ULL,
		0x9D60D7C2CB603754ULL,
		0xBEDC616E1FC304C8ULL,
		0x966841E1FEB4B0DCULL,
		0x16381B721C1F0252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73098AE329A4A3DFULL,
		0x844CD2D5338DFA28ULL,
		0x8FEEE48CCDD6D4DCULL,
		0x1169801724BD88C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1B96D7ACCB50363ULL,
		0xA89261129559FC18ULL,
		0xBA0A8AB0AB787003ULL,
		0x9C39EDE0AC0BADF1ULL,
		0xF472701482A3D96CULL,
		0xFD19CE9A951CEB75ULL,
		0xB1103678712AF87DULL,
		0x25D8828CCF3DEA8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB6108631074A4FULL,
		0x3A670C04B7A4EF9AULL,
		0x0272A09177D952B7ULL,
		0x3A5D4EC76F3C7F20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x847AE4A144FE479FULL,
		0xEF51196E61F0F981ULL,
		0xE992086A85AF4D2FULL,
		0x261A798F9341BF6DULL,
		0xA28BA0ADB83CB5DFULL,
		0x3BA0193E3A15F603ULL,
		0xE14AF6BD5C66F4EAULL,
		0x0A2B5F4047C6BDA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA534BE6A9E0146F2ULL,
		0xC914D8AB01337E0BULL,
		0x5AB2A8863CF7A7F4ULL,
		0x288A9D1A3AC1E67FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECFF3813356D0FF2ULL,
		0x810F238B4008F0F9ULL,
		0xC34B363F30529E0EULL,
		0xFD4D1A401C03F32DULL,
		0x57E7B9171082E542ULL,
		0x60BDF1A94747B322ULL,
		0x2C982034E123719CULL,
		0xDAAEF80E8836940CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF964B17FA8DB1CA4ULL,
		0xDD4102ABD4AD8812ULL,
		0x61DFFE189B957B44ULL,
		0x7345EC68541DECFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE46DC962E51CCE7ULL,
		0x754E2A4D20F32FCCULL,
		0x9F6ED57B00A06903ULL,
		0x07A4ED8CA5CEDDF1ULL,
		0x50F46163AB193EFEULL,
		0x3D0D2A67FC60E511ULL,
		0xF347A903C2A53DE3ULL,
		0x0A371BEB8FE22380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF28D5161941126D4ULL,
		0x854275BC9755305EULL,
		0xBC11EC09E52798BEULL,
		0x0BD3128401602315ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2D105EC2640BF1AULL,
		0xD4B24738718025F8ULL,
		0x5ED53989D5D3F7D0ULL,
		0x1EBFBD6C9EAFD8EEULL,
		0x17E2867339D28399ULL,
		0x72FDFF88F5DBA8BEULL,
		0xC64CDD3418F983CEULL,
		0x73B2F032CBB7E400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E70FB06BB804A56ULL,
		0xE666358CF01B3230ULL,
		0xCE3E0F458ADD8875ULL,
		0x4B4F64F6DBFBB10BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89286EC97843C17BULL,
		0x7181AA5B0DC281BBULL,
		0x2F87E370569F6409ULL,
		0x370172CBCBECF17EULL,
		0xDF001D932D1A4542ULL,
		0x734FD13F69EEAC21ULL,
		0x25BC794AB6A795F4ULL,
		0x38C820FC5F025867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32CD2A22A2A0A8AULL,
		0x8F5AB9C4C7300EC2ULL,
		0xC981E487737FA652ULL,
		0x24B65841E64610CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9CE957854467475ULL,
		0xD3F0B1B0D3AD3A0BULL,
		0x246889F836891466ULL,
		0x9B91B220631D49A7ULL,
		0x5650E89CE473E806ULL,
		0x99507F4DF4740F3CULL,
		0x90423789E70C9D04ULL,
		0x603AEB956593A51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D11CC23D7AE780ULL,
		0x95E397431CE77D00ULL,
		0x8E3CC87082686315ULL,
		0x6450AA4D7707CBE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF85E5B82D83300F4ULL,
		0x87F01B2BA142CAA0ULL,
		0x6151E8497AF77A59ULL,
		0x9A67C8F470999875ULL,
		0x66F492A4CF2752B6ULL,
		0x9DC1C4033E696351ULL,
		0x1178ABB33A4EF56AULL,
		0x12EB962C66F3586BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40AC1FF99809486AULL,
		0xF2B333A6E4E788B6ULL,
		0xF93B64E422AFE82CULL,
		0x6960138BB8B8B859ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B15E8CAB4B292A5ULL,
		0x7826731EB88D0B5AULL,
		0x90F913EC4802E6CDULL,
		0x7CA6B9543B7CB271ULL,
		0xA5526273A837A9A4ULL,
		0x0C0E1686215F0BAEULL,
		0x9630734ED724C045ULL,
		0x36D98AB1FD0BEA3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB55085F5ACF5C240ULL,
		0x423DCB07ACA8C746ULL,
		0xDC2A31A03777710DULL,
		0x20F14FBFCB4177BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1270DFEB7BA95E55ULL,
		0xB76A03BF42DAA7F3ULL,
		0x6A16E77B24B6E7F2ULL,
		0x584CA3CF9BA31A5BULL,
		0x6E920CB4485ECB2DULL,
		0xD21CB8BE376267C0ULL,
		0xAF29D0364F79D134ULL,
		0xC5D81D61C683124EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1EC2AE39BB8B64ULL,
		0xE7AD6FFB7B760E83ULL,
		0x6A4BCF8AF0CBF5C9ULL,
		0x366100531317D209ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ADF857E285DF374ULL,
		0x54221B5089322347ULL,
		0x52BFB5A21E20FBFDULL,
		0x827B9821D08497D0ULL,
		0xE7B93DEA76BB8F0DULL,
		0x0AC14710C770ACCDULL,
		0x193BC0ACF08DBF56ULL,
		0x1FA854FCCCA8ABEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805EB64BC8353020ULL,
		0xECD2A7CE23EBC9D7ULL,
		0x119E4F4DD32B62C2ULL,
		0x357835A8318E1C90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22DE08B1B07ACBECULL,
		0x554EDFC0F10864F0ULL,
		0xBA10131747F874DAULL,
		0xD9A0F65A5056B5C4ULL,
		0xD66E4A51A1922076ULL,
		0x69FDBE96F36A6D52ULL,
		0x26B76E3A216E4DD4ULL,
		0x95D14BADB55B7BBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73D10CFAC2BA0DAULL,
		0x10F92A2912D49F3BULL,
		0x794A6FB83E580262ULL,
		0x16B232233BEB138CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47A35A6A69117427ULL,
		0xAD82FB353772C21CULL,
		0xE5EC1AF689B4A54DULL,
		0xD79D89E4CAC77FABULL,
		0x37CCFB0051B84F17ULL,
		0xEB8CA7750D977D0AULL,
		0x1392613E916C4988ULL,
		0x66D394B5B4F2A3F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90109C768A6D33F1ULL,
		0xA463D6953BEF51A0ULL,
		0xCDA68A401FC78FA0ULL,
		0x1B059CDDA6CBD54EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAC6D48F7E5EF1FEULL,
		0xF464622FB86F42ACULL,
		0x51138FCE8F603E2CULL,
		0x92FDE7823FD1DDC5ULL,
		0x434A29F283315E55ULL,
		0x0A3E5B7D3BF63DBAULL,
		0x3DDAC05473E2F394ULL,
		0x28DAAD505C520B58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C90E8EF7B2F393ULL,
		0x79A5F6C69EFC6C52ULL,
		0x7F8C1C57C3106626ULL,
		0x2373A16FF3FF8CDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA675F586436DAB6FULL,
		0x76BAA8EC90FF6831ULL,
		0x52D35B7589E70BBDULL,
		0xA0BCA6F5A174651FULL,
		0xF5E18FB117206D27ULL,
		0xA581056646E3D3E7ULL,
		0x1E3D996AC392C856ULL,
		0x36F9117098B495AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F149CFB23DE07CULL,
		0x07E1761B16D0DCA0ULL,
		0xCFF8214E91B0C89AULL,
		0x49B53DAC4C429C5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CB35C3FF1F344A9ULL,
		0xE60F57D2F5984ADAULL,
		0x349EB9A5AE6CFC24ULL,
		0xFB8ED7D91152AECCULL,
		0x8B9526299840B323ULL,
		0xC591FF06DC9A002AULL,
		0xEE5DBF00BD07B2CBULL,
		0xB04F119780CB0234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D7066C8B8DDFDDULL,
		0x39BB32D7B474512AULL,
		0x968913C1BD918664ULL,
		0x274B74562F7502A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8F9DCD0A1A6674AULL,
		0xDAAF3C3E555ACF1FULL,
		0x58BD3EAFA285835DULL,
		0x6E3836B36FDEF3D8ULL,
		0xA949E5918D0CDBC9ULL,
		0xF2B35D002F38D5ACULL,
		0x77266551163C60F8ULL,
		0x774334DBBEE70B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9F1F06B918F09CCULL,
		0xE14F0A4557CA86C0ULL,
		0x087048B8EF7BE851ULL,
		0x22320F51C62A9870ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x586D5FD04EC6AC4EULL,
		0x3C54945F3488B301ULL,
		0x5DDDC0E3B572D854ULL,
		0xF03D73E37ED4086BULL,
		0x1AEFDC526CB8C29BULL,
		0xD8E1C7EC890D489AULL,
		0x809F47CE57990B79ULL,
		0xC6DF5133FCEE382CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5808140C723393C4ULL,
		0x6DD8417B8C8179E1ULL,
		0x75826984B62A8C6AULL,
		0x7563819B0A305F06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39D1B00F92D6A4E9ULL,
		0xE747F15363A16E53ULL,
		0x146E9B80BD5B3105ULL,
		0xB88A9E688B636130ULL,
		0x7867A6C445F434B4ULL,
		0xD42D0CA71BCC7364ULL,
		0xF740A0F4F983AC2CULL,
		0x3FF7C54247E6444EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19347131F516791DULL,
		0x65F7D22183FA8F3DULL,
		0xC8067FDDC6E6BFADULL,
		0x3751E63F379184E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x715EEB2CB80DA299ULL,
		0x13590D70FE062CA6ULL,
		0x64EC9F27844A14DCULL,
		0x6F63C070C38FD4EAULL,
		0xB13B333D4E210FF0ULL,
		0x8936046AEF22450DULL,
		0x0131670267D439D4ULL,
		0xE568EBE015F914D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC028864650F60545ULL,
		0x715DB5507D1C6CAEULL,
		0x9241E982EDCAAA68ULL,
		0x7CF6C3B40688ECD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F74258D8F75AF6DULL,
		0x9F205742B5CC11C2ULL,
		0xAEC10AD93B1771D8ULL,
		0xDEDE6E4CA76E8B18ULL,
		0x09E8BE95709AC3EBULL,
		0x6CCF4EAF1C8B18A6ULL,
		0x97E7028EA6E84027ULL,
		0x36754DE21A858E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98006FBC466EC592ULL,
		0xC5E60540F271BA67ULL,
		0x3B0B6C060190F7B2ULL,
		0x7447FDDC9741A3A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86037FFB607B0846ULL,
		0x0B563D752919A94CULL,
		0xF7FB7DEF565B2005ULL,
		0x2B4287159B408FC0ULL,
		0x38CACC122DDE481AULL,
		0x5FA3E015F5B916E3ULL,
		0x7A00FC375231E7F2ULL,
		0x05B88E8A43CE2192ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF41DCAAE2F79BC48ULL,
		0x3DA980B7A2930F06ULL,
		0x1420EE2589C38DFFULL,
		0x04A7AF9BABD98B7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C0A57DCF174C582ULL,
		0xD3F52A76BA6A4DCBULL,
		0xCF69E33E71A00F7FULL,
		0xF57D43E1AF466CCCULL,
		0xCCA1DE11B63DD05BULL,
		0x659B1EA20B172CF8ULL,
		0x834C9F7A889ACA19ULL,
		0xC356DF46AF143EE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC114E7DFEA1B765ULL,
		0xE8FBB6845FDAFAB9ULL,
		0x4CC98F6EB89A0F44ULL,
		0x7462685FAC47C304ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF075C83918158EEAULL,
		0x653C2165E5A7A0DEULL,
		0xE2A6C12C44534B87ULL,
		0x7ED2283ECF6A1086ULL,
		0x721D81693E60FAFBULL,
		0x41A7B1E59CB3A67DULL,
		0x540A4058759E3766ULL,
		0x26325474AAB1695BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0D6FDD85A7AD110ULL,
		0x2420897B2852577DULL,
		0x5C2C4E4DB9CF84B5ULL,
		0x2A4AB19025BFB415ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6460E5F9478B00ADULL,
		0x9791A6B418472CA6ULL,
		0x638112486B566565ULL,
		0x08AC47A12DF09455ULL,
		0x32F0921E23AFAF81ULL,
		0x390EA787485D062EULL,
		0xD1D4AD8B15A9476BULL,
		0xF21CB1BC63EE69CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4169672939F1318ULL,
		0x0FBE84C8D6161781ULL,
		0x8912D4EDA276FF50ULL,
		0x78EEA99803544896ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x945AE345ADC3BD1FULL,
		0xD6083D8A0E673E21ULL,
		0xF43D3DC4B5521A4EULL,
		0x837B2ADA23A45B08ULL,
		0xE1DF91431A15648BULL,
		0x30714053E62069A6ULL,
		0x02D450EB99570562ULL,
		0x6746D539B008E9D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B8A733B8CF0AC0EULL,
		0x06D7C9FE3736ECE7ULL,
		0x5FC140BD783CE6E2ULL,
		0x57FED16A44F71081ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD01B7164D33B5FB6ULL,
		0x96F6FF2C16E9B0BBULL,
		0xAD6B6FE9C18D4C79ULL,
		0xCDF3EEDD1CAB4E9AULL,
		0x6ACCE5E516ECF43EULL,
		0xEFD3AC7692B86E3BULL,
		0x2400EC5A82DA7D10ULL,
		0xC6108C8B24FA7336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8591663A67A55EULL,
		0x306298C5DE4A0D8DULL,
		0x058E85592DFBDCFDULL,
		0x3468CB8499D868A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A4F18010D15CD86ULL,
		0x168C501568464331ULL,
		0x3CA5E4E8AD8F274AULL,
		0xD3E0E2E4CB4D911CULL,
		0xE35D68E62795D885ULL,
		0x41B59302F2C0EBEFULL,
		0xA751C9BB215D11D4ULL,
		0x62CEA140A61BF63EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2CAA2AED53F37EULL,
		0xD780228570E948CCULL,
		0x12C9D6AFA15FCCCBULL,
		0x7E8CD27D73741E69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5A761C52D28BCF6ULL,
		0x6E31E65456C75D4CULL,
		0xDFFE2FCD5E10A9E8ULL,
		0xB6471E84C92561C7ULL,
		0x3C0D18BEE7767847ULL,
		0x5ED6D518BA15297DULL,
		0x5447FEB9D3C7A05DULL,
		0x63681D42C70AED48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF990E1B88BE99BAULL,
		0x821587FFF5EB85E3ULL,
		0x62ADFF62CDB277C4ULL,
		0x77BB766E54C49A84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D067B6115EBCED5ULL,
		0x4670C2D5841B7AB2ULL,
		0x71A4A8363A06E2ADULL,
		0x9357E2BD28EE2685ULL,
		0xD9BB78DEF102248BULL,
		0xC8ACD4D37B013F38ULL,
		0xBD2C32C5734719D8ULL,
		0x989EE71A7D1D4884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEDA6C78DC3D3EE1ULL,
		0x10185A39C64ADD22ULL,
		0x863431855694B8DBULL,
		0x3AEE30ABBB46EA39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2E8920E08E31058ULL,
		0x2D4CA0C78E42D8ECULL,
		0x004A3043CBC354C3ULL,
		0xEC8D4E31A33E24B4ULL,
		0x15E53C656606C95CULL,
		0xE4561D219141F933ULL,
		0xD05E51B438B719DFULL,
		0xBF737E4D011A286EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22EF891B2DE4F84EULL,
		0x1214F3C31E0DD682ULL,
		0xEE4A510436F12BFFULL,
		0x57B20D9FCD202526ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B3D69562D1E6B25ULL,
		0xD00A199E45E669A8ULL,
		0xB813150811970B63ULL,
		0xF7F979D294D3ABB4ULL,
		0xFFE581DD6961FB71ULL,
		0xDDFD3764748910E4ULL,
		0x38002DD71498A967ULL,
		0xE9D94668070C2DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x274EB033D1A9C330ULL,
		0xC3A05287923EEBA6ULL,
		0x0819E2F5204030CEULL,
		0x2E39ED43A0A27689ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5E05B56B2ACDEC8ULL,
		0x9EEE99ECFE7BAD12ULL,
		0x34B6C61667C21B48ULL,
		0x049BEAD724D4DEE0ULL,
		0xF3739F2D135091BBULL,
		0x15E8939BA356E8E2ULL,
		0x7DEAE3019395FD7BULL,
		0x308FC564759C58C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD909FC0790A28194ULL,
		0xDF7483073D623EC2ULL,
		0xE59478525005BB8DULL,
		0x39F337C09A0A0C30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC724B325928F3898ULL,
		0xCF8706056BED2B82ULL,
		0x071E738B71E188D6ULL,
		0xD967D705ADF05619ULL,
		0x9C1B6856D5423F69ULL,
		0x38D81F73754B5F1FULL,
		0x63FA23A254C3166EULL,
		0x660057E2E4D7FF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF33630093A64A47BULL,
		0x3F9BB128D51D4A33ULL,
		0xDE3FBDA406D6DD33ULL,
		0x7D74E2B3A6003C79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3D306F3E077F76BULL,
		0x3A122E36CD838D80ULL,
		0xE60939BB5B71B5B9ULL,
		0xC9BAF8F9DB8FDC0EULL,
		0xEA396904CC3039DFULL,
		0xD4B33D3D5E02FCF3ULL,
		0x1F0956B834CF4E9EULL,
		0xB05A6494B78A67A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78589DAA2FA09274ULL,
		0xCCAD4552C1F519B5ULL,
		0x816C19133237614CULL,
		0x7725E70D1A1B3F29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E791E73972795A6ULL,
		0xE469376627260B2EULL,
		0x32B148B6E6FD5CDAULL,
		0xCCC4D2136FDD235EULL,
		0x348D9F73C32351E4ULL,
		0x91B51DF1C1A37947ULL,
		0x6967F5B7E0D304F3ULL,
		0x9CC591DADE781FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7EC9A28E65C10EULL,
		0x854BA948E56A0BC0ULL,
		0xD81FC20246501902ULL,
		0x1218789075B1D8E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E3631D62A23C260ULL,
		0x1922C0319E3722D8ULL,
		0xA52DB2F449CFBE4BULL,
		0x129032FEE25E4FAEULL,
		0x72D238FFF4766E2BULL,
		0xFA004AEAEB570D6AULL,
		0xDD5A71E324E8C051ULL,
		0x28F2537A39E6D742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA96AA7D473B81DA6ULL,
		0x352DDF108D2320A5ULL,
		0x809A9AABC45C4A76ULL,
		0x268897237AA2439BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52823F9C8CC109C5ULL,
		0x06C6B42A8B7A3B92ULL,
		0xB224C06613B0BE31ULL,
		0x6D30A6AB794965E7ULL,
		0xA4C2D1391D693D73ULL,
		0xC1F2F3BCD9944347ULL,
		0xE99D6A3D694B3FFCULL,
		0x1B142188616E0BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76D4E16EA60296FULL,
		0xD0D6E232D77C3834ULL,
		0x5F828583B4DC3DB5ULL,
		0x722DA0E9EF9F2C1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED3FA4DB5332963FULL,
		0x7590D8CE95451725ULL,
		0xB4A5A159EA4F6A3CULL,
		0xAFD7378329591FF7ULL,
		0xA902ADBC30755A78ULL,
		0x30C390A20EF4751BULL,
		0x115032CE3A809EFFULL,
		0xF5B2F6CAEA2DA131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A56ECA849E098DULL,
		0xB29850DCCD8E7941ULL,
		0x468D2BF69967041DULL,
		0x2867D9A1EC1F0D40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8131EC5BF5154331ULL,
		0xA24886D32D153B2CULL,
		0x46A6F3A807B39926ULL,
		0x5788AF1A1457D1EAULL,
		0x45C3FC41EE965DEAULL,
		0x46F2F920E4656BBAULL,
		0x3D94C3ABC5CF4D10ULL,
		0xAC880B45B6548DEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC495E255F6737B6ULL,
		0x2A5981B5142338D2ULL,
		0x6ABBFF2764790991ULL,
		0x73BA5B7324E4E347ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F721EFD4DA3B960ULL,
		0xF9E827699D925651ULL,
		0x394E3BCCAF1B7623ULL,
		0xA38D6D1122E41F25ULL,
		0x4BEA86897EDDBEC3ULL,
		0x379C041292C95231ULL,
		0x987ADBAEC2B2B14DULL,
		0x26D3084F0224496EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4421766228E0B36ULL,
		0x3B10C22B677489A2ULL,
		0xDB8AD7BD95A1C79AULL,
		0x66E0A8CB7447058FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47AA075FD869CE9FULL,
		0x3E475996C6B8A80CULL,
		0x41714F63B8DC73DAULL,
		0x533630D5917687A2ULL,
		0x53B5AFD2EA12EBFBULL,
		0x78AB1EA009F54122ULL,
		0x43F469AB62C8CCC3ULL,
		0x5A11907ED2EE0C8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A220AE9738D7E2ULL,
		0x27ADE55841205324ULL,
		0x57B8FED462AAD8DEULL,
		0x31D1A3A8E0CC64E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6D605F5B99BDC4AULL,
		0x1332EF25583B24BBULL,
		0x59E00444E598349AULL,
		0x0A903AD4BFC09D5AULL,
		0x4FA8D869694EB807ULL,
		0x15F94788C1C0D8F7ULL,
		0x5AFFD832EC7A92CAULL,
		0x8BBFCD860999C0B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E6259B5B4B305FULL,
		0x56338D721ADB5971ULL,
		0xDBDA1BD3FFC9FE99ULL,
		0x4908BCBA2C9337ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3FC94B936BCFFE2ULL,
		0x6983199D15A43CFBULL,
		0xBBE7FBAF9B6BDCE4ULL,
		0xC86CC181A772E27DULL,
		0x3F9B99BCE5025953ULL,
		0x536AB2E9C14C6A60ULL,
		0x124BD75C22CE3990ULL,
		0x9D136071F7B298FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x351566C3351645C4ULL,
		0xCB59A84FC6FC0745ULL,
		0x7329F35CC6086850ULL,
		0x194D126C6BF597C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08A3D1078055CE53ULL,
		0x73D20A8AD1B5D7C4ULL,
		0x223A063901228FBDULL,
		0xF442A868488E66F2ULL,
		0x3BB29873A89C3B9FULL,
		0xBCEA168912363B20ULL,
		0x67A47FD066A5E4AEULL,
		0xCB9A99EF04DED6ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52672328786AC87ULL,
		0x7E9162E385C29E8CULL,
		0x84A4FF283DC281ADULL,
		0x2D3581E301A244AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74FE8A6721D48FDAULL,
		0x0B619F58D535A233ULL,
		0x8B78AABF3559163EULL,
		0x38C57873F9443DE6ULL,
		0xB3F1932CFD093ACAULL,
		0xCDA691E325C0D0D9ULL,
		0xBE79352DE8F71CDCULL,
		0x91AAFA1E02343D9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ADA6314B1334D07ULL,
		0x921B47106FD4A284ULL,
		0xD1768F8FCA075F04ULL,
		0x582698E84D056304ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC72950B3470D90D7ULL,
		0xDC764E0CEB4E4E66ULL,
		0xB0D49D190C65A879ULL,
		0x0A0B180C6AE1BFD0ULL,
		0x299A7B160A6D3D25ULL,
		0x3BE9BA292A1F6C0FULL,
		0xD44DD546DBCC9BB4ULL,
		0x49D901259A405CBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF41795F8D344A5F7ULL,
		0xC127F0292BF858A6ULL,
		0x3462459DACC4C53AULL,
		0x004143A1506F838CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x715162438A96DB50ULL,
		0x35177A58B653B798ULL,
		0x43978302292C67CEULL,
		0xD77228E68FF6AD2EULL,
		0xE9644FC9C8EBD96CULL,
		0xAE46EF276EC1B16EULL,
		0xB273D96F27FC8807ULL,
		0x6E62B55991C59777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16353A375D9923DEULL,
		0x139EFA3327140E0FULL,
		0xC0C9C98218A898F2ULL,
		0x3A191432334B28F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF10BD0C6FF3AC1A0ULL,
		0xCF644B49D6B980F7ULL,
		0xE12BC17AE51F103FULL,
		0x9AA8A5D230210354ULL,
		0xCEA8E84B35CC42C2ULL,
		0x76CCCE95A782892BULL,
		0x342DDB46D9A2E51CULL,
		0xF81C2C925197FAF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E1E4BF0FB8CAFEAULL,
		0x71CAF580B419DD78ULL,
		0x9FFA4DFF334D1279ULL,
		0x6ED7438A4CB043E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC54D452C671240BULL,
		0x0B10F1D12A528473ULL,
		0x7E6010C7230865A0ULL,
		0x8F68872E299BD585ULL,
		0x83C4E7D98764E6C1ULL,
		0xAECF232CBB8C0511ULL,
		0xFAED0BF48A47BE79ULL,
		0x8E221036EC346E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B8F3E9CDF6B67E2ULL,
		0xFDD02A75011B450DULL,
		0xBD8FD713A9AEABAFULL,
		0x2876EF5539644086ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE39A101851562F71ULL,
		0x1F5961E522BCDFCDULL,
		0xAB07FE7540CF8928ULL,
		0x205F71EF658EB383ULL,
		0xAA4B156F816721CAULL,
		0xACAFCE5358F93F19ULL,
		0xD0DC64F74E7CC1DFULL,
		0xC322765222D6DFF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ABF3EA586A537BBULL,
		0xC172024457BC3D9DULL,
		0xABBEFB2AE754505BULL,
		0x177D02209173F1B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x614203C2DB61B52CULL,
		0x2B332BA99C09F667ULL,
		0x49C7E93070C2B2C3ULL,
		0x4362FBF925724206ULL,
		0xAE41D6D242094E9DULL,
		0xE1A9606AAAA1BC04ULL,
		0xB5E9FB77F0705731ULL,
		0x2D59B4C5FDBE8F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F07E6F8A8C36171ULL,
		0xAA577B7EF00BDF19ULL,
		0x4A833CFE216FA42AULL,
		0x7EB3D15CCFBB81C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3A680DA3E94F429ULL,
		0x4522350803794588ULL,
		0x4881E50C736C2E0AULL,
		0x5D7E29B55EC35EC4ULL,
		0x877B5C1CAA8AF242ULL,
		0x6B37621E82266C86ULL,
		0xFE56561596158D68ULL,
		0xCDB6C6A16AD8595EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFF62D1B8F34EE7CULL,
		0x2F5AC58F552D6180ULL,
		0x0952AC40BA9F2B8AULL,
		0x669FA5AB3AE0A2DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2181345DBD9B0678ULL,
		0x2FCA452D6A0FDB04ULL,
		0xD1F5723511EA3FCDULL,
		0xF4CF5D072B40D77CULL,
		0xFCC33F20C1C9CE1EULL,
		0xC49907B0F294C497ULL,
		0x13764E7D2A49E4D8ULL,
		0xA881FF692F6289EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA67C933A818FA2B5ULL,
		0x5E8169716C250993ULL,
		0xB58518C958E237FAULL,
		0x781B46A433E1503BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B2A2526E59EEFA9ULL,
		0x145F5C494F01B0CFULL,
		0xA132FD7C32729E35ULL,
		0x554F6EEF4546E516ULL,
		0xA52064525E2A443AULL,
		0x138C0BD2A0A04722ULL,
		0x76F22EF5471E9776ULL,
		0xE4A3F7987D9F3C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF90960DFE51551ULL,
		0xFB291D8D26CC3FF3ULL,
		0x4925F5E4C0FD19BBULL,
		0x45A62F91EAE9D0DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AB4D76716DAE3B8ULL,
		0xF83C6E7465B44DD5ULL,
		0xC22B21B635C6AF84ULL,
		0xF3183DEEE7441408ULL,
		0x670F18C4AE87C3BFULL,
		0xACDE607A7B513653ULL,
		0xDC36CE062580AA13ULL,
		0x2264DED7854700D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6F28498FF01F2F6ULL,
		0xA13EC0A2B3C25E36ULL,
		0x724DB69FC6DFEE70ULL,
		0x0E1151ECAFCE3413ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07D04E1154B0985FULL,
		0x360D10623F599409ULL,
		0xCF247F13CF358D47ULL,
		0x8C4CDA3C460F249CULL,
		0x40E7D6F64B05F5C9ULL,
		0x2A7AF70CD2E58123ULL,
		0x4E629D542B5F2AE0ULL,
		0x852B08F9ED3FE8FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3A36A07793172DULL,
		0x844DBC498D6ABF44ULL,
		0x71C7D9923F55EA8DULL,
		0x50B02F557D8BB9EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x373578872EFEF386ULL,
		0x8958BEBB5241EA71ULL,
		0x6BBDFA898E05CC4AULL,
		0xE326551AB0266751ULL,
		0xAB764B3E865B3DEEULL,
		0xD66A8DAF1949001EULL,
		0x6BDDF296B510BC8CULL,
		0xAB96F90BD94678FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC4A3CF208A28B6ULL,
		0x5D29C6B91317EEFEULL,
		0x6EAFFCE86E81C932ULL,
		0x5B8F4CDCF09C5CEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7FF25F20A00D633ULL,
		0x63899DC30B537DFBULL,
		0xD44DD1B7906F6473ULL,
		0x92ABEC2ACE76757EULL,
		0xC233BF361771F812ULL,
		0x446E38F3C1974A87ULL,
		0x817D0A2F0E7B7726ULL,
		0x9B9EE4F19F125BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABAD87F984EBAC5CULL,
		0x8BE611F1C7C88E22ULL,
		0x0CDD54B3B6C31421ULL,
		0x2C41E8086B3010CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9216E107418DA63BULL,
		0x41D84D17B1F54AF8ULL,
		0x3BDD0D61D08E4B8FULL,
		0x5F18E74119F8EBC3ULL,
		0x06B2ECD9CDCFFCA5ULL,
		0x924A5094F80F878FULL,
		0x8352E5ABCDDF62DCULL,
		0xFDD950F29AD919C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A6095BCE6D2C5DULL,
		0xF8E0433484436A33ULL,
		0xBA2B24E25FB6F84CULL,
		0x0D5AEB441632BEC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79D8B26563BE91A1ULL,
		0x3C538540862C5D66ULL,
		0x5DC0734DBC50CA25ULL,
		0x7203EF16E45C57A4ULL,
		0x5089B085D69638D0ULL,
		0x14089E830247BCA1ULL,
		0x3C6009605CCF1AD8ULL,
		0x122980E2002E8A2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E48E6433E0B00F3ULL,
		0x359B0CB2DCD25D58ULL,
		0x5401D79B830EC638ULL,
		0x242D10A2EB44D9E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3F1173E2EA7F813ULL,
		0xE88C7AD467498504ULL,
		0x877DFD1D4CECBC5EULL,
		0x903DC260EC510B9FULL,
		0xC3EA0477DDE13E43ULL,
		0x9249961BA19912F7ULL,
		0xE684246787C843F6ULL,
		0x0A228B8E3533FAF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8ADC1091E173651ULL,
		0x9F78C2EE640255CBULL,
		0xBF1B647B74A6D2F8ULL,
		0x115E797CD2084BD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B46FD853DEFDCD3ULL,
		0x4CE544DEED215455ULL,
		0xFE161B3BD454315AULL,
		0xDE471C981FFD042AULL,
		0x2E5365692776479AULL,
		0x81915A95787DF9E8ULL,
		0x9AA77A599F798212ULL,
		0xA929D510CF7BB204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA80B21197E8178ULL,
		0x8878B70ECFD46CCCULL,
		0xF2F24489805D8019ULL,
		0x7A7CBD16EC5970D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x115B725E930794BCULL,
		0xB7EBBEFC19F08141ULL,
		0x320770FB0BA650FAULL,
		0xD637D3DA53B170F5ULL,
		0x99A15FD798D59BF2ULL,
		0x61278B58E174B94BULL,
		0x1D788D7DBAEE0DA5ULL,
		0x055F6F48B4BF0FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4FAC5F42BCBAE1ULL,
		0x23CA6E2D91440279ULL,
		0x91EC71A4CAFC5787ULL,
		0x226258A5280DCE27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE265D8BFC2C5DADULL,
		0xC8AC834BDDBBD59DULL,
		0x9E5E814583E498A2ULL,
		0x11942DF9CD67D168ULL,
		0x07C78A86A547647FULL,
		0xF011C1CC8EB318FAULL,
		0xD227DF8C59EBC161ULL,
		0xEBE0D44DFE1951C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C4ED8884C54DB9ULL,
		0x6B4F47A90C518ABAULL,
		0xD049B01ADCE34D2CULL,
		0x14F3B18D8529F479ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x119A69E0C4019BF1ULL,
		0x9E6ECBAB98CF09A1ULL,
		0x75FA04C39B9C46A5ULL,
		0xB8326C34785899E3ULL,
		0xD7868BF89AD6F7DFULL,
		0xCA10FE81D65B75F6ULL,
		0x3046A7B94B35C9A2ULL,
		0xC43778C868DA7D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F9330C7BFEA6B6CULL,
		0x9CF492F16A628C45ULL,
		0xA076EA44C59834CFULL,
		0x586E59F408C738B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D0FDF9AA33A530AULL,
		0x29C95FAA3DED22FAULL,
		0xBE093FBA2379D004ULL,
		0x9D96A50457788AD9ULL,
		0x8EC674AAB8235D7CULL,
		0xDA462270294A5986ULL,
		0x75ADD2B8D3BA80DBULL,
		0x030B4BB87A96664FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E8530F1F87A3398ULL,
		0x90327C505EF66CF3ULL,
		0x35D687299128F0A6ULL,
		0x1143E26689CBBAA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC0CCDD54126FE9FULL,
		0xAC279168DAA04988ULL,
		0x126BD8131EB03B08ULL,
		0x50B56BD78D749148ULL,
		0xF4E9CA23FBD6BE23ULL,
		0xECBB2614F3A2E183ULL,
		0x11D3B28397FD6D72ULL,
		0x146F47469419755CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C0CF2CA3073843ULL,
		0xCFEF388504CDC31FULL,
		0xB7D8579BAE4E7A17ULL,
		0x593A0051893BFCF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CC051D8FE654D29ULL,
		0x5DB96BFF6099D48BULL,
		0x2A1E471EDD12AE0EULL,
		0x2E8650E429DB7D55ULL,
		0x3765C02B8A497CFAULL,
		0x931195B00982E3E9ULL,
		0x375E99FCCAC510ECULL,
		0x2178CA9697F1F25AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85DAD84F854DDB03ULL,
		0x3255A420CA07A929ULL,
		0x622922A4F653312CULL,
		0x2674633EB7C576B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x980925C2F60EA3D9ULL,
		0xBFF7562AA0850312ULL,
		0xBBFD40BA880DCFA1ULL,
		0x8E50FC4F712EB239ULL,
		0xBC1141E535DEC5C5ULL,
		0x73BFD6C1E229F3F1ULL,
		0x09C1E3AAC8479C4EULL,
		0xA6D7A2773D447DDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8298EDC8F52002CDULL,
		0xEE7136F232BF38F4ULL,
		0x2EC50C1442AF0346ULL,
		0x52531A0289596109ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7302156E259C05E0ULL,
		0x022F9EB2B6D68835ULL,
		0xCE3D9A59CFC575DBULL,
		0x94AD037536776E23ULL,
		0x4330D2B028F590F5ULL,
		0x867BA0F6F6EE6059ULL,
		0xDF71B406EE8AB946ULL,
		0x5BF6A27210C1422DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C415B943A0F8C52ULL,
		0xF889835B5E38D575ULL,
		0xF91E5361385CF652ULL,
		0x3B492063B32740F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x179B3E14A75C40C5ULL,
		0x1CA3D24D223C9E9EULL,
		0x87A934E8DC804B37ULL,
		0x7ED4C3099614C599ULL,
		0x60601E9BCC178B92ULL,
		0xEED6AE829945CDFBULL,
		0x7C78864A6FFAEDA9ULL,
		0x39813D75F4CE1065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65DFC934F2DAF9C7ULL,
		0x9081B9AFE29931EEULL,
		0x018D23F57BBF9270ULL,
		0x0803E28BECAB34AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18ACAC7BECC17E6EULL,
		0x37A13A8C0373E589ULL,
		0xC23FDD1B00E13813ULL,
		0x94C7994C9310D102ULL,
		0xBB5AF8535D41D515ULL,
		0xFC4AC3BA76D6ACD7ULL,
		0xC69264BC4141D744ULL,
		0x92B7EA2ED6ABF6BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE82D88DBC48722D0ULL,
		0xAABA4839A7518D8EULL,
		0x3BFAD10CB0A72C50ULL,
		0x5C145C40709770BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE841A10EFBD0750EULL,
		0x5E04092B24FC22B9ULL,
		0xA73E763598919AB3ULL,
		0x576FAE979E4DCF30ULL,
		0x471FF503153E1AD5ULL,
		0x1986F468B2DF7C78ULL,
		0xF908922BF4622450ULL,
		0xF82A5B1FE7129C4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76FFFF842308762AULL,
		0x280C50B5B2289C94ULL,
		0x9E8428BBDF22FE97ULL,
		0x2DB93553EB110251ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16AB226C844539D8ULL,
		0xB1C16ECC91EAD1C0ULL,
		0x3AE0E64173D4166BULL,
		0x22581431CFD654F9ULL,
		0xB6468E7548AAAB3FULL,
		0x25148B93C7EE3BA3ULL,
		0x8ABF7605696EE5C2ULL,
		0x4354C14A24BD8452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252447D54D9AA6AEULL,
		0x32CE26BC3F47AC0DULL,
		0xD34C6B0F1A4A313DULL,
		0x20ECC53343F7F939ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE3F9F0D4130FC90ULL,
		0x15EE2CDDF983303DULL,
		0xBAEAE5B0FAB75439ULL,
		0xEB9D24D0A0886778ULL,
		0x0D8830BF2BC4F4D6ULL,
		0x5968D65DBC6DEBC1ULL,
		0xA013C781816DEF85ULL,
		0x4487FB1FADE3E4D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE076DB6DC06D55F6ULL,
		0x5B7DFEC7F1D42EE5ULL,
		0x7DDA82EA3108E204ULL,
		0x17CC6B84705C5EBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC05991899D5B664ULL,
		0x9AAF68645B125486ULL,
		0x2CBA94A94F904E4EULL,
		0x7E657BCBB1A1A9F5ULL,
		0x8E6F525FDC429AA3ULL,
		0xFE2A8A9A463E2B66ULL,
		0xAE7AADBD44C1C360ULL,
		0xEA24C2FC9295E9FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF08BD3534BB8AFC8ULL,
		0x54FFFB4AC84CC5BFULL,
		0x12F05EC184534EB4ULL,
		0x3FDA6D4973E26551ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE84BEABB1AA7F093ULL,
		0xCA4EF6308A3602CBULL,
		0x15EB959E39B87717ULL,
		0x1E9DC7C6FACF3E0EULL,
		0x8DAA55A025849EACULL,
		0x767F08FE7117C592ULL,
		0x253C29045C7D516DULL,
		0x68EC4E563C3D904DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF94A080AC578068ULL,
		0x612A4BF553BD568CULL,
		0x9CD9AC43F4528D57ULL,
		0x31B16893EBF2A981ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18BA51D10A8F4B4BULL,
		0xA12FB608F9D6E243ULL,
		0xF3DAFCF33E42F99BULL,
		0x5AF17949337EDCC3ULL,
		0x14B293C52B8EE3A0ULL,
		0x3FFD116912FDA924ULL,
		0x05ED56D0104ED883ULL,
		0x4907C517D8933756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B3C411581C516ADULL,
		0x20C04BA1CB7DFD9EULL,
		0xD515DFD5A9F71D17ULL,
		0x3218BAD359591388ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74C2F3E6929B6C3AULL,
		0x46A099A21AD55500ULL,
		0x6D805A3C1947E191ULL,
		0x694022E11A53E194ULL,
		0xD3DBDDCBCCFB5C7AULL,
		0x850FE8992744C71AULL,
		0x03A5E8F318A27FA0ULL,
		0xBA1208E90E02C6F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE765E026FFEB2A7EULL,
		0x06FD205DEF0AE2FBULL,
		0xF820EE51C166D365ULL,
		0x07ED75792EBD695AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8DC7D21433EBD7DULL,
		0x80672C6BDCDDF431ULL,
		0xEB04CE369567E696ULL,
		0x530A0C2ECED67061ULL,
		0xB9C76519BCA48F4EULL,
		0x856304548CA4D4C4ULL,
		0x98BA64E08F631DE8ULL,
		0x90CE601010853A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C757EF343AC0642ULL,
		0x4D19D0F8BD558965ULL,
		0x96AFC78BDE1E571AULL,
		0x51AC4E91429D1DB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A26EE79B3D93E4CULL,
		0x0DDD965FD6978622ULL,
		0x08180CF3D96E1DDAULL,
		0xC52D9C8C94FE4A2FULL,
		0x30C7CBA7687A36DFULL,
		0x16EB71CFC024D308ULL,
		0x3F3B260ECE0D229CULL,
		0x2615DC2718C694FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47CF295335FD644AULL,
		0x74D07B365C0ED959ULL,
		0x6ADFB3266F614105ULL,
		0x6C6C4A5A42786812ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6B511BE59DB366BULL,
		0x7B279CE61D0B99A1ULL,
		0x00BAE113C259181CULL,
		0x8FC07B3A43C3712CULL,
		0xF7A49E5ABA3FBCBBULL,
		0xE4F61704D9CF12EFULL,
		0xE6313A0783897577ULL,
		0x8A94E65B978A8F05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9249335FF513D4BULL,
		0x77AF079E71C86940ULL,
		0x2C097E3148C087E8ULL,
		0x21DAACD2C254AC0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1335A7EB879EF2BULL,
		0xB58F7CCAF9C33F4EULL,
		0xC77E34C4646CC509ULL,
		0x52E8488D00EDBA19ULL,
		0xBF01026DF3E91C30ULL,
		0xFCE768C879C391B2ULL,
		0xD282F0966D58BFA2ULL,
		0x0473701D7CC8E0D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B59B6D0ED141E5EULL,
		0x3FE90A8D0CCADFD7ULL,
		0x06EDEB189F99373BULL,
		0x7C0AECED86BF1A49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DB3FBDFB38507DEULL,
		0x453AC87D7AEAEEF1ULL,
		0xD18608B35113B4D3ULL,
		0xF8EE4F9C2382E831ULL,
		0x148D42090C44D466ULL,
		0xA5B1EDDD9039A6DCULL,
		0xE12CEBEB9D6264BDULL,
		0xEC293C64AD8E0D78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AABC93785BC945AULL,
		0xDDA41760E379B39CULL,
		0x3E310DACADAEA8F9ULL,
		0x070D468DE698E823ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x824484DFB57EB730ULL,
		0xD744D17323D431FBULL,
		0x9AFBEF524D4FEC7EULL,
		0xCE5668948D5D5AF5ULL,
		0xB32C8ADA63F06946ULL,
		0xA91560F89BF3E1A0ULL,
		0x5C37C932CB6BF133ULL,
		0x72B91E0AB4664547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AE1214A8B2E5A2DULL,
		0xF071365A4A07AFD6ULL,
		0x4B43CCDC7F55BA29ULL,
		0x55D0DE2B548BA38DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x394CEF03B700FB16ULL,
		0x68F3FDA9651021D6ULL,
		0xCA46846DC0AE0A48ULL,
		0x056B995AAED65ECCULL,
		0x1CB0C74C0BA9B1B6ULL,
		0xA0ABD693D621C62EULL,
		0x3BCAF2DAEA289F7FULL,
		0x92B850440EF9B836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B8A844D72315F4BULL,
		0x4275D79B2E138CAEULL,
		0xAA6690EC82B5B73AULL,
		0x4CC78374E7E7B6D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2454B1A0759C9F3DULL,
		0xD046621ED3BC376DULL,
		0xAC74077CDBFDC830ULL,
		0x3441DA1FB87C2D09ULL,
		0x984C8E15D1EF8B78ULL,
		0x03522BF4F1E7726FULL,
		0x6A556C9ABBBFC504ULL,
		0x89A82160B2A5D2AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB1C8DD9F2B5618ULL,
		0x4E78E87ABC1733FDULL,
		0x75222674BA7506C9ULL,
		0x2336CE7A3D197255ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDF8D44373DE6BB4ULL,
		0x1E0CA4327B18B250ULL,
		0x146292DA29538AB4ULL,
		0xECC5C36A346020DEULL,
		0x246E076EA3A53ECDULL,
		0x7A848489B0D0B11CULL,
		0x948940713B694659ULL,
		0x7D4EB458636F3B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x264DEEAFBE65C107ULL,
		0x4DB850A2BA12FC7EULL,
		0x20C223A8FAF3FBFCULL,
		0x06748888F6E2E6F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E9BBDEA2D8D7636ULL,
		0x283E9BD742B45EEBULL,
		0x1FDE64DA76A6A738ULL,
		0xE77742094AF02EAFULL,
		0xCB30558CCF683A6EULL,
		0x3B5D5C998F7E9354ULL,
		0x386025A87CC6348CULL,
		0xC4C04214418202E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C870D0F70626FEULL,
		0xF81A5AA28F7E3D81ULL,
		0x7E23FBDCFC127408ULL,
		0x1C01110B043C9C69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE351B3C58FD37071ULL,
		0xA47AF2B60D18D5C3ULL,
		0xE7750AB2F4DBCF86ULL,
		0xFCD3E8512A238CDEULL,
		0x8F77915F1CE8369CULL,
		0xF4E61915E53C2454ULL,
		0x46CE967795BA9EECULL,
		0x3488C3B443C83EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F1147E3DA4B8CDCULL,
		0xFEA2ABF614063A51ULL,
		0x6A1F60732E8F66B2ULL,
		0x4920F51339DCE3CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5EBDE46B75FD32DULL,
		0x5EAA39F18C35D958ULL,
		0x08C0DBCCB53A4F71ULL,
		0x677734D45D9C2178ULL,
		0xEE173CFF192B8D86ULL,
		0xC712BE76D56F88DAULL,
		0xFD53BF7730B4FB6EULL,
		0xD0E0760C48B2D9E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D5EEC2473D6D9ABULL,
		0xEB727F953AC429D8ULL,
		0xA32F477DF017A1E2ULL,
		0x68C8BAA728287929ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAEB14FB3BE39DEDULL,
		0x2F95121623F66E3FULL,
		0xA6E2271106C73023ULL,
		0x5C9507182A42FC80ULL,
		0x2ADD7F7BA1A8B92EULL,
		0x7CD011D2985F2260ULL,
		0xAF3F1E84F13472BDULL,
		0x50DF47096A024BBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07CC01553AEF1C89ULL,
		0xB677B758C2158886ULL,
		0xAA40AECCD4903843ULL,
		0x5DB9927DE69A3A5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68FD7E43075EEBC3ULL,
		0x34BDD1EE2CF72544ULL,
		0xFB9F26B156E7DDF7ULL,
		0xA8695D4BAF3FA652ULL,
		0x4CCE567F33D1FAECULL,
		0x7CF83F62469042CDULL,
		0x7B4E1C279F32A715ULL,
		0xE2A9E6ECB6D02F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9E5524B88A2FD7ULL,
		0xC1973A84A6610FBDULL,
		0x49375492F86CAB27ULL,
		0x4DA1A46ED226A869ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4063067C3C20223EULL,
		0xE6CF0D7224DFEEEEULL,
		0xCC51B2BE3C4C899BULL,
		0xA74CCEDA1CEB43DCULL,
		0xBE1DF9D0C5C5F18CULL,
		0x748F4574D479AC5DULL,
		0xE3F63E532C365C20ULL,
		0x084D065AA4BFA3CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D61B799781FD3FULL,
		0x34135CC9AEEF84D8ULL,
		0xA2DEF316CC5E366DULL,
		0x62BBC04E915D946CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2166AE2320693466ULL,
		0x8B11CFBB0F754407ULL,
		0x65D280F526D2F7A9ULL,
		0x80DCB8321E0F52B5ULL,
		0xD5D0E4294A253B92ULL,
		0xE600A89A91414697ULL,
		0x29A1B8FAE5FA5DC7ULL,
		0x2E439F9A15077C64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE688C4421F00D1CULL,
		0xAF2AD6AC9F25BE90ULL,
		0x93D3F63349FCE355ULL,
		0x5EE669113D2BC993ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64FC6CC112F1C759ULL,
		0x8114723428B288B8ULL,
		0x00193A00C612F024ULL,
		0x5DF2ADCA56DD20F8ULL,
		0xAEF90D0D9C6E7B5EULL,
		0x213877D7C3D5CC2CULL,
		0x9850D997F8F784B7ULL,
		0xC4D50239E36BD3DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DF45CC64B581BAEULL,
		0x6F763C3B3A6ED75AULL,
		0x9C19868FBAD0A353ULL,
		0x1591026218DE93DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x407FB9E61957AC98ULL,
		0x86418DD865FFA218ULL,
		0xFF9FD021E61C8CE7ULL,
		0x23088EFEBF58BA3FULL,
		0xE0C407E256B9BBE8ULL,
		0x6D70ADCA6BF2FF76ULL,
		0x9C065A3DE9B19EF9ULL,
		0xCFB2583464D52A4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D98E57EF8E9958FULL,
		0xC4FB59E46C118DBDULL,
		0x28913552967A25EDULL,
		0x7781A6C5B6FD0211ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC794A944C0D6230BULL,
		0x706161F1350AFFFAULL,
		0x4809D9D7012800B2ULL,
		0x71A4FBDC62EFB80BULL,
		0x661E4490E7700EF4ULL,
		0x66C4FB9A038D9F8EULL,
		0x96DD90D638C15665ULL,
		0xB9C9ADF91AE9C180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF012D6C71B785F6BULL,
		0xB19EBACDBC10AF1DULL,
		0xACED59A36DDAD3BFULL,
		0x0594CED661A27121ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933CF0ABFA294AAAULL,
		0x0372846BA9A7FD2DULL,
		0x8F842176E5A18278ULL,
		0x4E9B9771F81F93A7ULL,
		0x52D0BF0EAAFE38C0ULL,
		0x647DB6900FCF803BULL,
		0x5B5EBCDBCA875EC5ULL,
		0x0C6380E5E929AAC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE394CD95BE5B776ULL,
		0xEE1B9DCE027505FBULL,
		0x1F942A16F5B993C4ULL,
		0x2560B992944EECA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB60A6B7E942AC11DULL,
		0x5BDA3B9B8D821C7FULL,
		0xA2CF5DED982FCCF3ULL,
		0x60971F52CA13CAAFULL,
		0x1BA33FD058856E92ULL,
		0xB8CB78253FD89BBBULL,
		0x276D4C6295819A63ULL,
		0x025F24B6BEC60142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD045E46BB7F92ADCULL,
		0xCA0E112307A93A45ULL,
		0x7D08B48FC96CB7C0ULL,
		0x3AB692731B77FA81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x466E78DDD3433B1BULL,
		0x03EFB146772C4E5BULL,
		0x0FF8019FFD3D6D6CULL,
		0x3E1232E178686898ULL,
		0x09807A04EFE2BDA7ULL,
		0x3D4A13B7C9289134ULL,
		0xFB86C49A5FB12D92ULL,
		0x8E1EF85B1B2F538FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8095996EEB6503ULL,
		0x1CEE9E8E5331DC14ULL,
		0x65F9308A318A3121ULL,
		0x56AB1067816ECFF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F60F30591FF3C3DULL,
		0x9D568896D8236848ULL,
		0xF75BD245C9BABEA7ULL,
		0x07720E1F9C65970AULL,
		0x4D20EECC4C52A080ULL,
		0xF888A940877DA105ULL,
		0x87E0C878C13786A0ULL,
		0x368188B94B7BCF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02446558E643106DULL,
		0x819FA82AF4C94F12ULL,
		0x22B9943277F8BA8CULL,
		0x1EAC59A0D0C661BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB6EFCA2D04268C2ULL,
		0x079EC1163E30A437ULL,
		0xE9ABA9748460F8BDULL,
		0x87DE7471DFC3D7E6ULL,
		0x12F125CD5E5D1988ULL,
		0x8079A6E7797DEB6FULL,
		0x27713F351E80F422ULL,
		0xF1570B9993B20CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B3A991ED214384AULL,
		0x19AD877246E196B4ULL,
		0xC47B0B570B8535DCULL,
		0x5ACA2D3DCC31BB3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F841362DB464A22ULL,
		0x114577754549186EULL,
		0xA5AE341DF903F4CFULL,
		0x6FDF0C3B29FFFCCBULL,
		0xB701C6EF45085961ULL,
		0x4411B4D50CF0931BULL,
		0x7790429CC6596B89ULL,
		0x2184FF0104D105F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9C79AE71A838F46ULL,
		0x2BE64F1530FEEE8BULL,
		0x651817636A49EB2FULL,
		0x699CE661E106DEEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF31CC45E5ADD6F5FULL,
		0x8232D3D2DB4826A8ULL,
		0xEC653A461FEB6CDAULL,
		0xDBBEB06A654E9B31ULL,
		0x37946710EF67AD68ULL,
		0xC2DC19683963E428ULL,
		0xADCE9207C6085098ULL,
		0x92E8911202DEA371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x332410E1E4413026ULL,
		0x6EDE994B601C04A1ULL,
		0xB90EE76D85276387ULL,
		0x2A443916D25ADE11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE267518E5512DD8CULL,
		0xAD888F250249A7D6ULL,
		0xBC7135943744DD94ULL,
		0xB0F96847E0A1E2A6ULL,
		0xEF71DBB973B28D89ULL,
		0xBD6D1B19B0992B4FULL,
		0x8D0F9B991E6661A7ULL,
		0x1522DEE03E629510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4DEF158193E067ULL,
		0xCBBA94F5390615B4ULL,
		0xACC24E4EBA775C7AULL,
		0x54267D912344031BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4C24254D67F19A0ULL,
		0x79AA3D124BAA2E95ULL,
		0x12DAF99E62D3CB0DULL,
		0x5DD1680E9D75A77EULL,
		0x0266BD8026F45EDBULL,
		0x44AE435DC7CCC318ULL,
		0xBD21FE72C19117FDULL,
		0xD54C3B6E334C7DEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0002635A9EC532E2ULL,
		0xAB883CFDF40F2426ULL,
		0x25E6BEA71E5D5AA5ULL,
		0x07223A6A3AD0587CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8ACCD968B3ED0AA6ULL,
		0x9064977E4DAD2406ULL,
		0xA431502565095C0DULL,
		0x4EF208A49DB92882ULL,
		0x9399F97DEFFCC02CULL,
		0x8C8ED478F5F7E3AAULL,
		0x54FA943B8DB97154ULL,
		0xD20CB164B5A91515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A7E21A537195C8ULL,
		0x6D982172D078EF58ULL,
		0x416350FC6E902E9AULL,
		0x7CD45D9794D249ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5244ACB3688C71DAULL,
		0xFB447C71C8E4D52CULL,
		0xACABB0AF722F1B9AULL,
		0x872DF7FBC10A5B92ULL,
		0x2105DE4F5D77F2E2ULL,
		0x5B6E92FB04DED4CFULL,
		0xDE2CD302113C607FULL,
		0x1A0212307FA5003DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3923AC7B485A7FFEULL,
		0x8DAE4DB481F86BEBULL,
		0xA75302FE01256E82ULL,
		0x637CAB2EB38864C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDB2FC485792460FULL,
		0x61F6C0536224CA38ULL,
		0x7D8DE8F90360BF27ULL,
		0x0249CDF0D3E6F09FULL,
		0x9FAA5AB94AD6FE7BULL,
		0xED7629F359648BB4ULL,
		0x097DBDAD2FEA34E3ULL,
		0x5F5D8F3B6F7A4DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0FC73C9737C0E65ULL,
		0xA180FA72A7118708ULL,
		0xE63810AE202498FCULL,
		0x2A2D10C3600E7BB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4775DF02ABF614DULL,
		0xBFE2E4A93B0CFF7DULL,
		0x34A168654DE7294AULL,
		0x009D6525E102A23FULL,
		0x0F4C4342083C5282ULL,
		0xEABBE72BB9382B6FULL,
		0x30134C0672194DD9ULL,
		0x92A00C095A6E92C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C959BD63B3A3CAULL,
		0x97C73526B96371FAULL,
		0x577EB15A3DA8B7A3ULL,
		0x445F2E894D6C6B84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22479AE11C49F221ULL,
		0x2B46172DF1CA707FULL,
		0xE67637B43DE5C4A5ULL,
		0x784175A5AE75DAD2ULL,
		0x5DE6DB279290F95AULL,
		0x23CB637E1D506CECULL,
		0xF74A44B1DEA004CBULL,
		0x35C9C90318C36698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128C22C0DDCEF6ADULL,
		0x7B76DBE64BBA9B95ULL,
		0x9B7C6A1B49A67ACCULL,
		0x74354C1B5B771587ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BD8DB9111E68632ULL,
		0x7E239E2E340C02D6ULL,
		0x5C4A67995E5AABCEULL,
		0xAE43A94AD53DB66BULL,
		0xC26E8C17333E26AAULL,
		0xE5D710863DDB2A03ULL,
		0x36AE359D2FF8F7D8ULL,
		0xE810150E8B15750CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0841A702AD2048A0ULL,
		0x9C10121B62943F65ULL,
		0x7A265CEE7D4F7600ULL,
		0x20A6C9737A6D163BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B77343A2A935469ULL,
		0x23DE7CAAD0F01FDBULL,
		0x9F0FBEB8C98D519AULL,
		0xBF3146AEAE4BA424ULL,
		0x48693CDC57262C39ULL,
		0xDBEB096FCE427524ULL,
		0xE17CF60E5CA64DDAULL,
		0xCC57605E7DE864BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B163CEF1A3DE979ULL,
		0xC8C1E3436ECD833EULL,
		0x179C44DA8A3CE016ULL,
		0x142994B55ECA9808ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB9F2DB50A51B661ULL,
		0x90E96DA4FA6C7954ULL,
		0x58F1C2225F67A5D5ULL,
		0xBADA668C851EE31AULL,
		0xB24A8A6DF966F5DAULL,
		0x7B21B0F6ABAB0907ULL,
		0x8582E4788E453024ULL,
		0x8816EFE65A7F4B00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42AFBA080F9A37C8ULL,
		0xD7E9B24275CFD079ULL,
		0x2A5FAC077DACCB3FULL,
		0x6E4202BDF404052EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFFD6318A6A4E68FULL,
		0xBD2577F784764519ULL,
		0xDD76314A8F0C026CULL,
		0xA179BE31B5A78F93ULL,
		0x32AED0DA4AF92381ULL,
		0x53AFCD8FC3DDCDC4ULL,
		0xCB9EF855A77921F6ULL,
		0xEDDA516FC6F7B5A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65F0637FC7A030FAULL,
		0x293DFB4E9762D039ULL,
		0x170F0E016B070CFDULL,
		0x6FE1D4C93E6C86C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB56F936E2240972FULL,
		0x008307376AEC6043ULL,
		0x5FA5041570229333ULL,
		0xE745E4159FD90DBDULL,
		0xBBFB5CE5FE72FFB6ULL,
		0xBE63BE86E0C81236ULL,
		0xF9F0177558E00115ULL,
		0x936256141D0F3F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CBF5D91E7528F8AULL,
		0x43514F3CC89F1463ULL,
		0x79487F80A162BC6DULL,
		0x47DEAB11F01C7D68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x577A0C597440BC5BULL,
		0xA66DD688E8FA9C3EULL,
		0x5A477964125145B9ULL,
		0x7CE533146ACB798EULL,
		0x670798D0DC7B66FFULL,
		0xE7FB2D19849EA686ULL,
		0x4DCA48E4D732FB27ULL,
		0x59187600E41E63E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA29ABB5A2E920836ULL,
		0x15B6885298875431ULL,
		0xE64E4B5C03E28DA6ULL,
		0x3686B736474E4E2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73516D591034EA37ULL,
		0x9220380E79797387ULL,
		0x038E447345CB8E50ULL,
		0x3C5FD88D310CCA6BULL,
		0x0705A1151B1CFA2CULL,
		0x7758187F9E11A7CEULL,
		0x75365D578AB78DF6ULL,
		0x1A90C2638B7301D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E27567B16820D57ULL,
		0x4933DAFFF0185C1CULL,
		0x69A01F71DD0AA0E6ULL,
		0x2DDCB353E41F0FA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x925C1F52285BF91AULL,
		0xD30FA98BD8B9D45BULL,
		0x24A0DDE407DBA792ULL,
		0x04DBD75347CAE7DFULL,
		0x070C1FC413DF9834ULL,
		0x88768B7EFB09FDC1ULL,
		0xF62B4204C3563450ULL,
		0x2F1ED8B775B07E36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E28D66D1B8C91DCULL,
		0x14A85E651C357F02ULL,
		0xAF0CAA9906A76B87ULL,
		0x0370028EBFFDA407ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91B2BC1C740B1511ULL,
		0x87B66C5E14DFE301ULL,
		0x99E6DFE865A5BA9AULL,
		0xBE61383B1ABFEC7BULL,
		0x392F3926D444D520ULL,
		0x810D98AFCCA3A247ULL,
		0xE75552C4C4164D19ULL,
		0x3F80A5A3773EC50FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB537DFF642B94DULL,
		0xAFBB16767529F994ULL,
		0xF091291D80F52C63ULL,
		0x2B79CE7ECE112CD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4FF585176F1A256ULL,
		0x03AD4C3F6D33F5E5ULL,
		0x57B9F7121DAF9AFDULL,
		0xDF85D24BC6C85447ULL,
		0x361D6043FF054C37ULL,
		0xDF4DA37AF1A20581ULL,
		0xC34E3C38AA259889ULL,
		0xFD2C952E20372796ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5BA26951BAF824ULL,
		0x2933907F4B40C713ULL,
		0x5556E77B5F443F74ULL,
		0x7423F7248EF834A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC93442D766FF6623ULL,
		0x1AC8B8C0017F85E1ULL,
		0x9FB1A4D16E718957ULL,
		0x1F6016B20255E66FULL,
		0x6BDD518752BD643FULL,
		0xD3E07CBC11E13C50ULL,
		0xA05A1F6A88042096ULL,
		0xEEEFFE35003B5E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC0E5CEDAF1C4CC2ULL,
		0x8E1B3CAAA8EE79D1ULL,
		0x6D124EA19F0E5FBAULL,
		0x16FFD2900B25DE3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55045792F5F84F19ULL,
		0x640109742EE845DBULL,
		0xE07FEBB6B6D3A62FULL,
		0xCDF4D8DFDAC87615ULL,
		0x0F35A44CD3B06177ULL,
		0xAC64AB2A296BBA6FULL,
		0x4480AD62225EB71BULL,
		0x06B0B5173E8C6016ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96FABAFA6226C6FCULL,
		0xFAF271B654E5F257ULL,
		0x0B99A847D0E2D44AULL,
		0x4C2FBA53239EB964ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x048C6FF0CE787D8DULL,
		0x883A6C1D2B26F1E6ULL,
		0x8AEB95F8A3C12263ULL,
		0x6F16AD5868FD1D6EULL,
		0x58CCC95624C9144FULL,
		0x8B257DFEA2C16BE7ULL,
		0xA8C9479E9C131181ULL,
		0x04BB05DC1E100DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32F252BA4451816DULL,
		0x2FCB1FE953DCF63DULL,
		0x98CC3783CE95BB9EULL,
		0x22D98C04DF5F2795ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E572FC3A83E3B17ULL,
		0xE4E422AD7C4A3D74ULL,
		0xE226E5C61CF06E75ULL,
		0xD37F950B1207933AULL,
		0x545146D0343356A6ULL,
		0x5402B082426A26BFULL,
		0x1E68B3E3E2856E38ULL,
		0x068779A3445F3B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0267B2AB67DD17F4ULL,
		0x5D4A5603580BFDDBULL,
		0x65B19999BCBECAD2ULL,
		0x4B9BA347382A6CB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC103C67FF068335ULL,
		0x8BDF58CC81CBF99BULL,
		0xF5D880894F31F9CAULL,
		0x8E811DEAB3B0B0EEULL,
		0x39778BED6E7D8427ULL,
		0xB9F0A098A8B438AAULL,
		0x6FD4DF60C6F19E10ULL,
		0x0B3135009A15EF7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43CF01A665A8214BULL,
		0x25972F758C8C62E0ULL,
		0x8F71A8E6D70F7046ULL,
		0x37CEFC0192F23D1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC8B8701CBD711ACULL,
		0xB3D1FE78BC04E9AEULL,
		0x1241C0F7F8114435ULL,
		0x3391D38E1E5D6E69ULL,
		0x1FAB0590CA8FC878ULL,
		0x40E2715650511098ULL,
		0x3C63402DC7F0B3ABULL,
		0x136163E0EB05A08FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FEE5A7FDD2ED3EEULL,
		0x556ED148A80D6043ULL,
		0x08FD47C3A5CBEFA1ULL,
		0x1406A6F1013343ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7D0E1CDD758D8DULL,
		0xA8B84B83D67FB649ULL,
		0xE190A9008874DD38ULL,
		0xBF6AEC854629CAE6ULL,
		0x50DEBC27549238FBULL,
		0x0E69F558E4BFBF4AULL,
		0x28CECFDBBEB4BBB0ULL,
		0xBABB2BAF6022F4FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x808CFBF36B2A06F7ULL,
		0xCC72B6B5CAF61B51ULL,
		0xF043839ED748B95AULL,
		0x7733688D8B5A287AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C4AB6E70DC07CF6ULL,
		0x596B10EA279DE7E9ULL,
		0x1E72881EDB0DA693ULL,
		0xB90ABB0BC9934957ULL,
		0xF79A019C42B1C986ULL,
		0x1B54E9C23726B0FFULL,
		0xCB4FDB879EFF131FULL,
		0x0A3DA66D415D3060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D26F418F4246726ULL,
		0x6805C3BE575C2DE8ULL,
		0x4C4D1E4074EA7D31ULL,
		0x3E316F437D6877B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42EC974EB5EE9DE0ULL,
		0x48DF71C1BEE940D3ULL,
		0x4DEEC3C224B4B80CULL,
		0xCCDFA5AE164B7292ULL,
		0x4C2386B8FEEAE7A0ULL,
		0x4EC6C8E328C93C4CULL,
		0x1892BD34F62370BFULL,
		0xD3F053DB4846B259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x903296C48CCD0460ULL,
		0xFA614379CCC83426ULL,
		0xF3B6D99EADF77471ULL,
		0x428C183AD0C9EBCBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4756FFA75044E3FULL,
		0xD6C0615CFFB9664BULL,
		0x3075FCDA1EE552DCULL,
		0xFC12546C105534EEULL,
		0x0E1CE4066C2ED211ULL,
		0x886627D46D03E70AULL,
		0x1F86A181911D992CULL,
		0x1EF24705F14B035FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCBF48EE83F77D96ULL,
		0x15EA4AE52E4DB1C9ULL,
		0xDE71F615A94A0F79ULL,
		0x1408DF4DE177B50CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C7237170BE51E14ULL,
		0xCC02BE7E15403A7FULL,
		0xAFE5DDD37621C450ULL,
		0x01A3B73DEBAE35A9ULL,
		0x9CD588353972416EULL,
		0x07116AB058D75844ULL,
		0x1494789E700F9600ULL,
		0x8A840EC4AD669C94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4246EFD92DAD773ULL,
		0xD89894AB453754AEULL,
		0xBDEFC55818720851ULL,
		0x113DE86FA8E973A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6ADD9C88BF6F813ULL,
		0xC9024E4BAF7F6467ULL,
		0xA6632CF6473F268AULL,
		0xCD9F654EF9CD1B30ULL,
		0x21848BA6E76DF0F9ULL,
		0x80095794D6BFEFC7ULL,
		0xC9092493F5170BC2ULL,
		0x4EA07AD6B2209A27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB05A948EE648BED1ULL,
		0xCA654E638FFCFBF6ULL,
		0x7DBE9AECA8AAE569ULL,
		0x7971A12D6AA3FD18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDEBE123B03814FFULL,
		0xCB1DE74D8E0730C0ULL,
		0x8BE02FA9A26AF920ULL,
		0x198E6FBB5807FE20ULL,
		0x2A4B0A6A7E61ACD9ULL,
		0xDD72FFE1BE5C96F1ULL,
		0xE86AEA7F8E5D2BFBULL,
		0x8D3E9B75A7F99CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150F6CF272B7C053ULL,
		0xAA2FE2CFCFC5988DULL,
		0x0BBEFE98C43F8083ULL,
		0x10D9833247154711ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9A59B9364ECFA96ULL,
		0x66DFA4ED28826647ULL,
		0xA3080196DDF3D871ULL,
		0x4B0F9CBF9104268BULL,
		0x4AF9650E83BD893AULL,
		0xD5D8918AE568A23BULL,
		0x0F1B2A5B7D1ED454ULL,
		0x421C33D1DA3AE3CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAAA9BBAF30F5AAEULL,
		0x25053F8B360A7B14ULL,
		0xE1104B2B70875D09ULL,
		0x1B3F4DE5F5C1F6AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA1BCE68A11BF36ULL,
		0xC7C8A75B71265098ULL,
		0x3B9C7701BAB03BD5ULL,
		0xDE5623830B0F822BULL,
		0xECA06B24DA71FEEAULL,
		0x3D4533E2A6626127ULL,
		0x85766321178BEC62ULL,
		0xEB088A4552D308BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D71A45EF6FD9B37ULL,
		0xE00E5B0023C0BC85ULL,
		0x0B2F2DEB3975526AULL,
		0x419AA9CD5662CE27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB51CE6132FD48F1ULL,
		0x14993B80110C5B1FULL,
		0x6A75EA2C41A35630ULL,
		0x7B71A1B85B89D13DULL,
		0xF3B7CDAE9FD61848ULL,
		0x1AF7295D90895987ULL,
		0x48F76A0CB931DDCBULL,
		0x4A392F807D4FD697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD89A564CECC4E543ULL,
		0x15495F63856FA54DULL,
		0x3F2FA80FBF0A4256ULL,
		0x7FEEAECAF563ABB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x949A30DCEABF4DDAULL,
		0x41E99715A1512650ULL,
		0x56CD3A4989A176DDULL,
		0x3B62619BEF3B5EEFULL,
		0xAA2856BD5723A75FULL,
		0x817B8262B5BE1539ULL,
		0x3D4447BFC3D9D446ULL,
		0x5958F7F6139AE181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD69710F7DA0A27E2ULL,
		0x7A3EF1BC9B884CDFULL,
		0x6EEFE0C09BF6F954ULL,
		0x7E973022D838D81EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78358CB56D2D13C4ULL,
		0x3F774A5D175641F0ULL,
		0xDC1E0EA0E5BB3048ULL,
		0x34FC12999A7E5AF9ULL,
		0x91FEBFFBC9621F6CULL,
		0xE73B37924671A77AULL,
		0x366CC01C7E7C0DA6ULL,
		0x32B8C696F88A834EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24060C1551BDBEE9ULL,
		0x92418A138C351E22ULL,
		0xF04292DBAC25370EULL,
		0x3C698D027F0DD895ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x894362B0FA52228AULL,
		0x3BC6316828E6751AULL,
		0x928D01833E63AFF2ULL,
		0x0185D6AD258C2479ULL,
		0x7C5277FBBC4B8D2FULL,
		0x9A6F7B1558AD3B50ULL,
		0x055D41CE7D1A5B7FULL,
		0x4DA973663B1BF3A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD81320EED891939ULL,
		0x28527693529D430CULL,
		0x5E64C629D04D44E3ULL,
		0x08ACF7D9EBB24F44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3DC355C3B524474ULL,
		0x7CF419F643625B2CULL,
		0xA387CE8C9BBB1EC2ULL,
		0xFCF7328AC5D7A8BAULL,
		0x7540177FAF250356ULL,
		0xD11002970636D492ULL,
		0x6098C8C9F7AC69ECULL,
		0x78A5BEC79AF0AD34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5FB2503AD0C5F7ULL,
		0x85547C612F85E8EAULL,
		0xFA359C875F52D7E9ULL,
		0x6591842BC5915E80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BAE5D3B6CC14E84ULL,
		0x5FB09CF24C4551F2ULL,
		0x1B05534D3FFA984FULL,
		0xFFB2CC18B7E6B6B2ULL,
		0x94209FB7C47B3C2DULL,
		0x8F6653802F6E4E2CULL,
		0x5021D487AB972400ULL,
		0x9E6FA23BAB93FF96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38861282970C40D5ULL,
		0xA8E101F956A4EC90ULL,
		0x000ADF70B869F064ULL,
		0x0444E0F42FDEA702ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E55269420C1609DULL,
		0x6FAF99FD0A5F2BB9ULL,
		0x364D6F6544257193ULL,
		0x95ADA76A27354D7FULL,
		0x5494872EBF105D35ULL,
		0xDCE19A1FB90BFA24ULL,
		0x9198B93391DA19B6ULL,
		0x78FC7EFB7D38C28DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC6137847D2F393AULL,
		0x392C7AB282264D1DULL,
		0xD2F8ED0CEA8542B8ULL,
		0x0B2880BEBDA22E82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48CF65EFEE24D6DFULL,
		0xE165D1A0A0173A4DULL,
		0x08F2A192E479C6E6ULL,
		0x4B43474A9FA7DA63ULL,
		0x19885FDF787707D6ULL,
		0x43932328BDB6E61CULL,
		0xCBFDBC8CDD724A01ULL,
		0x385C2DB6E4DDE7B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x130DA11BCFD001E6ULL,
		0xE93D09ACC93D6279ULL,
		0x509C9E7BC370C316ULL,
		0x28F2107098983EC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D4498E62D68DCF8ULL,
		0x8D6E00F008A928B1ULL,
		0xE67388E843A2609BULL,
		0x1A51F48B5E76A04CULL,
		0x1B7C82D8726703DBULL,
		0xF3C2226683907F37ULL,
		0x662E441463F05B60ULL,
		0x5CFE0C3A0F48F908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81C0050728B3717BULL,
		0xBC3F1C27901C0ADFULL,
		0x1151A3EF194FF0FFULL,
		0x6807C529A34B978CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F131B76EDB6B420ULL,
		0xFCB725EEA7B14926ULL,
		0x63A7D9305668E945ULL,
		0xF789CD139FF5E30FULL,
		0x4D8AE68B7AE897D4ULL,
		0x2EF2E113CF975E94ULL,
		0x865CCE198419AFC4ULL,
		0x99E8108C93565492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B1542B2C3D4115ULL,
		0xF4C48EDF78295329ULL,
		0x556E70F9F2390064ULL,
		0x4FFC41F17EC670CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA631888BE5D4105FULL,
		0xEDE2D31760063D34ULL,
		0x6A5C14C76FECB653ULL,
		0x6BCE47E09FA0BCFBULL,
		0xC32E0374E490D6CDULL,
		0x74E7EA03CF17FAB5ULL,
		0x555235D6448AE0E1ULL,
		0xB32E6B79E123BCCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F060BE5D353F6CFULL,
		0x484F8FA81D95742FULL,
		0x149012959C8A17CBULL,
		0x04B23BF80AEEC3C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4426C2BE81611E1BULL,
		0x57C72F3F3BA80203ULL,
		0x129AB91DA7F6B1A0ULL,
		0x2C554801A343436BULL,
		0x1DBEF8F833F34BC4ULL,
		0x6D9D06A32FCC42FCULL,
		0xB4A26E8A743C6BC7ULL,
		0xBFE8EAE70358E854ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE7FB796377E616EULL,
		0x9D162B7853F9F36FULL,
		0xE2B721AAE8EEB13AULL,
		0x28E8264C2275BFFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68A56F1C59E2692BULL,
		0x62569FA847FE6D64ULL,
		0x12FC18275C6BA84FULL,
		0x19DCC07CDDC97829ULL,
		0x931799968B0DFAD6ULL,
		0x3F63AE2BE156CCE2ULL,
		0x2E2D120C8220F7B9ULL,
		0xDF566A9FB93D43EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E263B74FDF5A9D5ULL,
		0xCB227A2BBAE0D706ULL,
		0xEDACC602AD506DCEULL,
		0x40B094325CE18CEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAC331FAFF0B162EULL,
		0xD57BED4B8297A544ULL,
		0x4475D4AB13975176ULL,
		0x59B7106B46D77F86ULL,
		0x83162CB89A902CEDULL,
		0xEBE646B7CF872678ULL,
		0x31A3DC830A50C3A0ULL,
		0x8380B885E985D8AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x500DD561F071C441ULL,
		0xD9AA6C9450A75B28ULL,
		0xA2C8901E9B945B59ULL,
		0x5ED2744BF0B5A8C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E65B872FAF36DB3ULL,
		0xCF7E3DBDD857FA88ULL,
		0x9EB3F062A21B21FFULL,
		0xDCA75D030C64C852ULL,
		0xF7F115D9B84674AFULL,
		0x075149FAAD745C00ULL,
		0xFF33B9CD9AB8133FULL,
		0x185C9EFF7822B3A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C2EF6C45568C045ULL,
		0xE58F38F3979DA2ADULL,
		0x806184E7996DFD5AULL,
		0x7A66F6EEE18B72D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB25CA960583A33C5ULL,
		0xEC4DA1DA195B3436ULL,
		0x2B3C7BD9F6EB983DULL,
		0xD084006C17BCBBF8ULL,
		0x98B74D56CB1D6E97ULL,
		0x091154237D38AA87ULL,
		0xFE786A68E82FC01DULL,
		0xFE6BC9594D90683DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D9224427E98A3E6ULL,
		0x44E01F1EAFC48457ULL,
		0xF11C476C6E021C8DULL,
		0x1483E3AD9B2C352BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A4A489B08D244BAULL,
		0x26A00C681FDCF251ULL,
		0xF7E3F8FAAFA78397ULL,
		0x69DA365160C4752CULL,
		0x7A02AA503C61AD49ULL,
		0x57F2291B3B941E95ULL,
		0x58B94BC7A4839428ULL,
		0x21C2E113777DF8FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46AF9083FF51FE4EULL,
		0x34922672F7D97C81ULL,
		0x2365389D1B2F8194ULL,
		0x6CC79F351D776A7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89B7794A7C7CB462ULL,
		0xC5B57464AF456036ULL,
		0x587E5188742D7B20ULL,
		0x224A5DA7340BC06CULL,
		0xD69B5FAC13747385ULL,
		0x7FFD31D66C7EAD28ULL,
		0xD6E40A811B5327E2ULL,
		0xCA7D74B9DA9BAF2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C7ACD55FC5DE94ULL,
		0xC54ADA38CA131446ULL,
		0x3E57E0B2828566BFULL,
		0x30E9B13DA727C13AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61DC31233DC268FAULL,
		0x27B5681015A25666ULL,
		0x604323486CAC3F37ULL,
		0x5DE592894BC25E90ULL,
		0x2EB88663F1BE47CFULL,
		0xB64467D8A8BC7FDEULL,
		0xDE474A678F35886FULL,
		0xB8FC5A5D0B083C77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514023F9200115C9ULL,
		0x35DCD239219D5161ULL,
		0x5ED82EA7AE9E7FCCULL,
		0x535AFC58EEFB585BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AB20F6DEECEA65FULL,
		0x46E08DDABF6AC134ULL,
		0x682A713E6232A1E6ULL,
		0x15E8B732C04ED112ULL,
		0xC029A0D1F5A51964ULL,
		0xDBAF91243C39BA00ULL,
		0x128255A07FB53850ULL,
		0xC46C912A31B35D96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90DFEE9865506F85ULL,
		0xE2F0193BAFFC5D50ULL,
		0x278327115718FDE6ULL,
		0x3E06437620EEB559ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23193F18AC27C749ULL,
		0x75C6F2CD040CAB60ULL,
		0x86E9638050A1EA28ULL,
		0xF066EF7F074C0C88ULL,
		0xA555BD42D84564C4ULL,
		0x1DBDD6F371BE01B3ULL,
		0xBBECFFD3FCDB89B0ULL,
		0x56D145BB5DF0C9F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADD35704C674BE62ULL,
		0xDFF4DAEFE640EC0AULL,
		0x6C175CF7D9385A4CULL,
		0x5377494EF90A0774ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DD6CB85BC95FED2ULL,
		0x43FFE2D2464E3ABAULL,
		0xC853720AEF09C231ULL,
		0x215C290E2DA930E1ULL,
		0xEADC9335CB27BFA4ULL,
		0xA6EAE63A0715AD67ULL,
		0xF03A90524E7E9465ULL,
		0x62A9C53E6DA01D1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A94A581E47C7351ULL,
		0x0ADE0F6F5385F827ULL,
		0x7104DE4295D3C948ULL,
		0x468F7052736D832DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BD0D3A0B61D2685ULL,
		0x2AF6502665EE858AULL,
		0x8171CAAD99299D75ULL,
		0x24AC25000CA136DBULL,
		0xAF49F83DA2EAAE71ULL,
		0x336CFDDECDCC241AULL,
		0xB08D2F9078479E97ULL,
		0xC24501316D786029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0CBACC6E4F30F86ULL,
		0xCD23FF38F23BE180ULL,
		0xB666DA1F73CB27E6ULL,
		0x7AEA52564C7F7D0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89DCF2F0218AB8CAULL,
		0x55BE31699107AC2EULL,
		0xCC7FE926DD5526D0ULL,
		0xB010C1E947A24437ULL,
		0xE9116F4BDE8A3199ULL,
		0xE4D2695A20B8EF82ULL,
		0x1AF56D88A1CFC32FULL,
		0x325E8DD2D057B2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227378332A0E16B0ULL,
		0x4CF9D4CA6C7B399DULL,
		0xCCEE2B6EE22C1FECULL,
		0x2A19CF3434A6CDEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x753CC257543D3305ULL,
		0xA3330D0A85EA5435ULL,
		0x7168F6923643D500ULL,
		0x3309E86BA58D4470ULL,
		0x8F522CD3F1A4CB81ULL,
		0x33F7E79F4F257BF8ULL,
		0x1CCD4488DC11974CULL,
		0xF83FCF3F31517829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB6F69CD32B36DA9ULL,
		0x59FF6EB0457ABB1AULL,
		0xB7E122E2E0E04A50ULL,
		0x0C82ABCCF7A51A8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01CA4ECC74A40802ULL,
		0xF8CE817D0B23D040ULL,
		0xFC2ACF397C1EB86DULL,
		0xEB52CC84B5E8DFACULL,
		0xAF43B5316800343BULL,
		0xB5D081C32B1B250BULL,
		0x6022FED4060B65FDULL,
		0xACD18B7C7189573BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D73421E4ABCCB3ULL,
		0xF5C1C475712B4FFCULL,
		0x415CA2B261CFDC16ULL,
		0x126D80FD904BD27DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF28C71FCC058643ULL,
		0xCF6CCD01AE3BED5AULL,
		0x8A94A9D663AF33B6ULL,
		0xCC8FAAC14D50CA67ULL,
		0xA6ECB28BEE2EE4A8ULL,
		0x1FAD45FCEE013FD0ULL,
		0x2A48D77945CFA6BFULL,
		0x34BB9693D955FC16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64B47E526FB7876ULL,
		0x8325308D026B6653ULL,
		0xD164A5D6C081F415ULL,
		0x206804B3901435B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D46BB0E3A544FF0ULL,
		0x6BE6A2B8F384DC28ULL,
		0x3D500DA8D43B2D23ULL,
		0xAD6CBB9D5D596AA9ULL,
		0x397B523FD47C284BULL,
		0xABE68FBCF5F9DC70ULL,
		0x220A881FDD165D44ULL,
		0x234CAA9D08E017BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB594F087C4C24BE3ULL,
		0xF01FF8C5769B94D0ULL,
		0x4AE04263A58D0554ULL,
		0x6ACE0EECAE9CF0E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17F25383FD6C4B88ULL,
		0x3E8F7D66313ED0BEULL,
		0x7872494994CEBDE7ULL,
		0x4AAC6D4770EB48B4ULL,
		0xCB5FF11FE39441F3ULL,
		0x8BB213CD75D3DC65ULL,
		0x37B616C6AD99B100ULL,
		0xC9C7E20C4B6F655AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48301E3FC56E1A0EULL,
		0xFAFE6DE5AEB187DAULL,
		0xBD79AAC7599F03FBULL,
		0x3E57FB1AA3745418ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2071CF272919ABDFULL,
		0x7B3CAA5C12B55403ULL,
		0x9F8D09B531155241ULL,
		0x2AED93D87368E46FULL,
		0x7EA502F86B2DF660ULL,
		0xF290141F29BB825DULL,
		0xF94682769D96538DULL,
		0x3C14C932D32A4878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF0400711EC3F75ULL,
		0x7C9FA6FC448AADE3ULL,
		0xA00467509565B953ULL,
		0x16037163CBAFA664ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B72EDEED6316D12ULL,
		0xDA5CB38203068F94ULL,
		0xFC6CAB42F6A36E13ULL,
		0x8D9E1D7FD0F02593ULL,
		0x21BD4A49432A85C0ULL,
		0x5D990F307AAEF96DULL,
		0x3485A32256EDBB9FULL,
		0x279F3FE552A01FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D8BF4CECE814876ULL,
		0xBF14F4B438FF95C7ULL,
		0xC842E25BDDED47BBULL,
		0x6F41998A14B4DCFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0557C7BF4C8E8C39ULL,
		0x9ED650E04BC354CBULL,
		0x704A86AC9DC38E5FULL,
		0x1F9010934E17B921ULL,
		0xBFE024C459EA8619ULL,
		0x93B3E1E43B189CF1ULL,
		0xD38D3F0F5383DF40ULL,
		0x35FFA58D912C35DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x809D3CE4A55E751FULL,
		0x8B89D8C1116AA0ADULL,
		0xD741E2F30356B1F5ULL,
		0x2382A396DAA7B79CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B7A95E8E208CC49ULL,
		0xFC37BD1EDDF7BD20ULL,
		0x0C807EE72D28934BULL,
		0x512F58DAF9C145C8ULL,
		0xF074238BCE517B5DULL,
		0xBF689F211678B947ULL,
		0xE6A8F93675C85C7EULL,
		0x0FEADC6775FD0D65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CB7DCA982211C76ULL,
		0x65BF5C0833E33DCEULL,
		0x49957CFCA8E64E1CULL,
		0x2E0C10367D5142E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD70253229931868ULL,
		0x0CBD4D310EBD64BBULL,
		0x0BB3BDF63F463EFAULL,
		0x5B445AFF70E438A6ULL,
		0x1AA2DC45043C59BBULL,
		0x5A5194EC07ED355CULL,
		0x46988F270842D9FBULL,
		0xF7648D523BFD5065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA19CD770CA886FA8ULL,
		0x74D9683A3BF35067ULL,
		0x8658FDC179329A49ULL,
		0x14315534587E27AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9DFDC930AF6B231ULL,
		0x3F317B60F01D5240ULL,
		0x658E3168C20C2181ULL,
		0x29CE9F6A6F358FD2ULL,
		0xD936752730A9D990ULL,
		0x26B8BEBA3C6EE18EULL,
		0x3F1BCDF5BAFE1DFCULL,
		0x9E7C10A7DAECC855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7F54064442D010EULL,
		0xFE9DCB05E892CD74ULL,
		0xC3AEC3E283C494EEULL,
		0x30391854EE5B4C79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4776D1CC4D4DD5C3ULL,
		0x4004FE5D289A44ECULL,
		0x8DF8EA36EBB9F060ULL,
		0x78CD4BD18D278779ULL,
		0xE3DB230021D05849ULL,
		0x2A451D7FB5A20733ULL,
		0x8744DFE4147C33B5ULL,
		0xFDDB6DFD0B72712AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19FE03D1523AF63DULL,
		0x86475F521EA756A0ULL,
		0xA2322611F6299D44ULL,
		0x275F9F61402453C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBAC04365D6B666AULL,
		0xD6E43AE6DDF8B5E6ULL,
		0x974765705BA1441DULL,
		0x542107D7879F3B90ULL,
		0x25E439B9DBE06075ULL,
		0xFCCF24CE1E824295ULL,
		0xE0489D2AD5DDB7EAULL,
		0x4CB77E74068A7573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8C95CD00B9B97DULL,
		0x5DA3B17F654E980AULL,
		0xE20EB9CC1A8A90FFULL,
		0x375DCD10802CAAC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAFA5E3AE509928CULL,
		0x194FF57402C4BB3CULL,
		0x3F62631B43C85496ULL,
		0x161B40E081090B33ULL,
		0xB0BB9948952F28AAULL,
		0x10E3034ADDE1B5EBULL,
		0xCF9B1AE1ACAC7AE3ULL,
		0xD3917DE1A0993C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D31F010A09A062ULL,
		0x9B027290F245BC38ULL,
		0x1068609AE562924AULL,
		0x7DB3F05E57C80204ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CE56685447ECC6DULL,
		0xD8E6B386EC252C11ULL,
		0x266251EA0A9198CFULL,
		0x160C24A8234AF7D6ULL,
		0x26434D1C9021E7C6ULL,
		0x95E34650A7CD5FC3ULL,
		0xF0C6DA043FEBE98AULL,
		0xB5A1EBCE1A32B46DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE2D8C2A98737D3ULL,
		0x18A3237FD4A16308ULL,
		0xE3E6AE8B87964362ULL,
		0x0C15254006D1C027ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF85FE58D2BEF6313ULL,
		0x4BE9B0FDED087CA1ULL,
		0x8BBA464911736BB3ULL,
		0x5852E3E0305D35EBULL,
		0x2808DA0F0C86AE3AULL,
		0xDEC1A188BE04E368ULL,
		0x91A84B0CFF29E43AULL,
		0xBC4658DD8610877DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9B043C907ED43D7ULL,
		0x5CA7AB4A21C23E17ULL,
		0x2AB56A36F1AB4C70ULL,
		0x4AC414C216D1528FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x342AC051ED047EA9ULL,
		0x8EE031E0B55C3768ULL,
		0x9BB9EFA35DA7D588ULL,
		0xD0F3C3EA89884E90ULL,
		0xABD72F2446C78919ULL,
		0x95C6240A6D088BF7ULL,
		0x29BAD0049DB274E2ULL,
		0x1EADE0A94F094905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB61BBFB46EA2D91DULL,
		0xCA498B6CE4A0FE2BULL,
		0xCD74D052C6252F2AULL,
		0x5EC31D0C44E92554ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD177F54CFAD9D348ULL,
		0xD3DD6DC89AA07FD5ULL,
		0xB860E962833510C8ULL,
		0x4D0550F6ED743006ULL,
		0xFA38A182EFA3C09FULL,
		0x7B5E26DF6CE9CC9BULL,
		0xD1800791D01E4F65ULL,
		0xB0F84DB09A1B3F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5DFEEBC8D286ED1ULL,
		0x23D732F2C554DEFCULL,
		0xD162090767B4D9D9ULL,
		0x11E0D92DCD7FA069ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCECEA42DBC0337EDULL,
		0x0F2A6AE59309DD00ULL,
		0x702947BF73BC9000ULL,
		0xD15E50DDCED34E5EULL,
		0xBFEB910914A87FC8ULL,
		0x340AAF018CE746DBULL,
		0x9BFC611E6752AB59ULL,
		0x1905443E367F8DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BC62B86CD063048ULL,
		0xC8C065207D5E619FULL,
		0x979FB242CA01FF3DULL,
		0x08267219E5C257C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29EEF04988A7A65EULL,
		0x54D8F4F0854237C1ULL,
		0x5F95DA6CDD84EF65ULL,
		0x837F3A1DE5A846E2ULL,
		0xFA091C31C9E1E5B0ULL,
		0x7F2D2DEA9601B34AULL,
		0x3E4E772D81B84C88ULL,
		0xDDD38446E60C2D86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47491FAD802FC364ULL,
		0x358DC5C2C982D4E2ULL,
		0x9F3B8B2E1EE04BA8ULL,
		0x70E4DCA40B7708CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10E7147335AA39ECULL,
		0xD3DFBEB8CB3421BCULL,
		0x9998411FDA46E72CULL,
		0x1DDF6BDCB9977AC3ULL,
		0x4625AA54D6A42426ULL,
		0xB2DDF2C6CAA100DCULL,
		0x9193759BC8FC919EULL,
		0xDCBE241DB3369E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A7E5D0B12079C63ULL,
		0x60D1C83ADF1A426EULL,
		0x357BB63FAFC484BBULL,
		0x6218C84553B2F9FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA44ECE8A12AA5C0ULL,
		0x9A67F80791ADD6E2ULL,
		0xA7A23443091C4856ULL,
		0x007F8C0829A74935ULL,
		0xCC636A0FE6E71F8BULL,
		0xCE2A1840F00C416EULL,
		0x12417DCFDC1B07D0ULL,
		0x6C7126DE7CE4DB53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4106AB44E77956C2ULL,
		0x34A791AB337F8D55ULL,
		0x5D5AE11DB51F7155ULL,
		0x194B510EB39FD78AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BA79A5C0547C453ULL,
		0x9AAD84D5745B1D58ULL,
		0x7DE60B6130DAB757ULL,
		0xBEF96B9A2C7A4740ULL,
		0x5FB474AD5AE4DFA9ULL,
		0xFAF8E8D03DC87E4CULL,
		0x8AC285E3756B2C7CULL,
		0x9134661074F1211EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8070EC178340FAADULL,
		0xDBA013BEA01DDCAEULL,
		0x16C5EB249EC351E4ULL,
		0x4CC0920B884531C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x935870088FD03A3AULL,
		0xE019FBBA5B224509ULL,
		0x7E9DA25296737B01ULL,
		0xBCB7C1274CF081EDULL,
		0xA2C5A24ED174E884ULL,
		0x46E10DC2DDC584DDULL,
		0x6C90B327B0DD489CULL,
		0xD72AD8C7BE22147BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAE87BBA72AC2A5ULL,
		0x658206A74673FDEFULL,
		0x9C183A36D74C4234ULL,
		0x2D13EECD85FF8C3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57DA1EC074E72B61ULL,
		0xB795F6C6A942D233ULL,
		0xE2A38816A2986EEEULL,
		0x831B2CF380E9B0AEULL,
		0xBC7071FB20DB0289ULL,
		0xA9F70826A464C097ULL,
		0xF204DBF7DFC4B795ULL,
		0xB75E42812E319A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x508B0A0755698FCCULL,
		0xF2412C83103768B9ULL,
		0xCF5C2EE1D9CBAF25ULL,
		0x3B190C205C469B84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDED6B06BEE58980ULL,
		0xAD3E064250F1BBBAULL,
		0xC63C560C2A5ED9AEULL,
		0x817C102C6DBA6A32ULL,
		0x6C85D2E0148A9875ULL,
		0xE34D40CFD6DD0201ULL,
		0x51FAFDA605822A57ULL,
		0x390142422EA98654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19CAB849CB782C21ULL,
		0x6AB5A51C35C007F1ULL,
		0xF17DFCB0FBB122BAULL,
		0x77ABE5FF5AE45AB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB413958F868AFB8CULL,
		0x6DB8C679AB5401F0ULL,
		0xF0A747ACF4B0D0A5ULL,
		0x1D536F749D4C19CFULL,
		0x4DAD9912CDD09C97ULL,
		0xDF41BF701ED4EA88ULL,
		0x3AF3CA0127C2A528ULL,
		0x66750520021E1CB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD84E5A13823C30ULL,
		0x917B311E3EEED22CULL,
		0xB0D743D8DB9554B6ULL,
		0x52B23234EDC45C90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE8B61FE1188A3C9ULL,
		0x821CF4EA4D2150CFULL,
		0x3AF1B3155E259C08ULL,
		0x1469883497C19512ULL,
		0xD0E8BD99D617F32FULL,
		0x1884D95197F939E8ULL,
		0x53D3BCBC2959A77AULL,
		0x2792B5DA90925D73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC11786D3D916BD94ULL,
		0x25D53706DC1FE95EULL,
		0xAC5FB70381747828ULL,
		0x743086A60D7B7430ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A5A9863A1A50702ULL,
		0xEC41086B041C5401ULL,
		0xF91F67CF0F92ED03ULL,
		0xCBC39DFF75FC1A43ULL,
		0xF42D0C832A7E6993ULL,
		0x4BA329F520240685ULL,
		0x975FB242B34298E9ULL,
		0xA15306639D18311CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x990A73DBF068B677ULL,
		0x267942CDC9754BE3ULL,
		0x7153DDB5AB759FA5ULL,
		0x3E1690C8C7936482ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA186798E5AB665ADULL,
		0x507C850B0EDCDAA0ULL,
		0x7CCF98FC22509C20ULL,
		0xE420837100FFCAE4ULL,
		0x06EA76A811CE08CFULL,
		0x7BF6ED6E19A15E0BULL,
		0x7886ED1E69B6FC69ULL,
		0xE4D4A0E0236A3FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8541680FF4BB986ULL,
		0xB723C362DCD0D043ULL,
		0x60D6CB7FD37A13C8ULL,
		0x5BB064B642C54610ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2A2DA289D5C8243ULL,
		0x0627022BC76A9B32ULL,
		0x30F56CC91AE9B6EAULL,
		0xD8A09BA81E24EBFEULL,
		0x021466D3262409B9ULL,
		0xD2B081C632A5BCC5ULL,
		0x7BCEC7AA6C86498BULL,
		0x0C32524584BC1EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1AA1D8046B5F418ULL,
		0x4C5A45974C04A070ULL,
		0x91A7101536D8A1ABULL,
		0x2818D1F9D2117BF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFAE767F7B17C5EBULL,
		0xD27AC596CB5A727DULL,
		0x7B52C12EB0E99A63ULL,
		0x8B31F7A1C47C82BAULL,
		0x3FBA108DEF624783ULL,
		0x29DFBACD23174CC1ULL,
		0x04F9B84486C19D41ULL,
		0xA788AF3776CAFC82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754CEB9103AE6713ULL,
		0x09B0800A00CFD72DULL,
		0x38641B5AB1A6F210ULL,
		0x697BF9DD669DFE07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7C2D8D3A198DFC4ULL,
		0xE0C26E41DCB5412EULL,
		0xCB68A166A99B0EBAULL,
		0xA48D1F297E823155ULL,
		0x61191377FF2904B3ULL,
		0x5F5365640D2D0DDCULL,
		0x2BF73653AB97C78AULL,
		0x4453F0DC6EFAC667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x617BBCA381AF93E5ULL,
		0x07237B1BD1654FE5ULL,
		0x521AB1D22222AD45ULL,
		0x4902DFE1F7BBA4A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F7FEBFF5F15118EULL,
		0xF6FCAEC66AEAB57BULL,
		0x6B39326FA94119CEULL,
		0x4BF19F28973E7AF1ULL,
		0x1CC20E0008550D73ULL,
		0x30216691ABC0F01FULL,
		0xF4356C945D5223D5ULL,
		0x27DB87AF5A9CD37EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x544E00009BB51184ULL,
		0x1BF1E865E98E5A19ULL,
		0xAB27507583726B74ULL,
		0x3687C3300A85DFC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53E59B423C22F45FULL,
		0xDAC6D34BA7C9CC71ULL,
		0x04B3029DA5FA94E7ULL,
		0x561AA23436941B87ULL,
		0xCEE2FC19E2C88366ULL,
		0x1553CA4542C1FE3CULL,
		0x830B138279FCCD22ULL,
		0x30C29CF8CFD791DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09970719E5E676A0ULL,
		0x0536D99390958978ULL,
		0x7857E7FBC18107F7ULL,
		0x12FDEF231093C242ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB142F327C9FD58A6ULL,
		0xACD78CF6E14DE4F6ULL,
		0x15CA50DFD4FB9B93ULL,
		0x029C23D5353A36AAULL,
		0xAEC71303E47DCB7FULL,
		0x5053C8E55233C01CULL,
		0x3768EBBCCD3A9F84ULL,
		0x290C8FAEE20B9A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2CFC5BBB4A98E64ULL,
		0x99475F0114FC6938ULL,
		0x4F5D4EE64BAF4937ULL,
		0x1A7977CAC2F327ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CCE4BC45526326EULL,
		0x690AAA30872FCC5FULL,
		0xE07A301C96C4DDC2ULL,
		0x3AFA0A29FA1FF815ULL,
		0x35A2BFE75C45E201ULL,
		0x9707D3ACE491AF89ULL,
		0x471D7EC31D99F241ULL,
		0x76B83CC06CA3468CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F6C81C0785C12DULL,
		0xD43415DA74CFDABDULL,
		0x6EDB0112FB9ED37EULL,
		0x5A530EBA1A5C70E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E886DB899807BD0ULL,
		0x6B33B35D95B94EBEULL,
		0xAF16BE3D82F69D5BULL,
		0xF659E5E73B1DF3AEULL,
		0x9406C424A8FFF2B4ULL,
		0xA88E1739C820C5C0ULL,
		0xF0A11AB68DE7649FULL,
		0xC117F1F3CEF3DF16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07898B29AF7E86E9ULL,
		0x704B25F14A96A954ULL,
		0x6700B556934F8D0EULL,
		0x1FE7D017F3511116ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB952E85003B01425ULL,
		0x03F32A6F363CF301ULL,
		0xA76EAE974AD40D96ULL,
		0xF09680F933192D1AULL,
		0x432B4FC11FF5A94DULL,
		0x158BAF73463CF944ULL,
		0xF85DD4FE279A5A92ULL,
		0x3F921C054F610061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C0BEFAC227370FULL,
		0x36AF358BA349F323ULL,
		0x855C4C512BBD7F45ULL,
		0x6046A9C2FB7F3BA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0DF9CB853B38FDULL,
		0x4EDDA88F2CA15254ULL,
		0xBE71525329C4CE21ULL,
		0x4C1B1682BDAAF873ULL,
		0xD22EDD8F4ED1C73DULL,
		0x7BAA4399FE7DA2DDULL,
		0x8D709394EA00CB15ULL,
		0x211F946C62EED43FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC002DD11385ECCC9ULL,
		0xAA23B16AF3477F41ULL,
		0xBD273A6DE5E2F351ULL,
		0x36CB1E996D1E79E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x962FB478396F3815ULL,
		0x9C6DF600B48D6F06ULL,
		0x23ED6F35E87D0304ULL,
		0x48E6C46D263A6EF8ULL,
		0x44FD3C4C6A84B614ULL,
		0x278FFCB64AF42106ULL,
		0x1E163B5440A60977ULL,
		0xE2A81E53229E956AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C6A7D009224406ULL,
		0x7BCD790FD4CA55F4ULL,
		0x9B3A3DB781226AB4ULL,
		0x6DDB44C449C49CB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE31127D474E767E7ULL,
		0x81C06735EC1AB91FULL,
		0xB670BB0B53BF63CAULL,
		0x9FD0AB241A8966BEULL,
		0xEAC51C7BD9A98A5BULL,
		0x10616854B46DF1B7ULL,
		0x0DA61FD7BF969073ULL,
		0x1F7AF30088C9A895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC536236C411F227ULL,
		0xF035E3C8B46C9A6CULL,
		0xBD197511C418D4DEULL,
		0x4C10BD3868786CDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D400223158DC0C4ULL,
		0xCD2BB977FE4C3A84ULL,
		0x1ECFB18ACDCF81F8ULL,
		0x5BA3A3A533A64671ULL,
		0x1EE664CB50BF0E9EULL,
		0x9C7F5153EF89B70FULL,
		0x022D654474AD69ADULL,
		0xA41766DCF6FB934DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0372F85111E9EFDBULL,
		0x0811CBED8CBD66C3ULL,
		0x718CB9B41F8D31BEULL,
		0x371CE871DCFE23DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7786ACCA9363A5B2ULL,
		0xA0D9F7157FAD99FEULL,
		0xA7487B02753A124BULL,
		0xD15A0CA09609F260ULL,
		0x98B2683F63E00ED3ULL,
		0x76F610FB73F6031DULL,
		0x7F31696678E30C7FULL,
		0x403E628715B82383ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2202263366A5DA80ULL,
		0x49607C68B6321063ULL,
		0x889E203866EDED37ULL,
		0x5A9CACADCF5F37E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90C647AA8DDA5F14ULL,
		0x6D5AC509C60EF6DFULL,
		0xA7C9F20097B4808FULL,
		0xD8BAADA217BC6775ULL,
		0x8D0F27ED63B982F2ULL,
		0x92D0F3B9C3115090ULL,
		0x92D6860018D3C2F8ULL,
		0x03F1DB9963403628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810634E75B63CF26ULL,
		0x385EF29CBAA0EC54ULL,
		0x73A1D60447237175ULL,
		0x6EA14666D344717BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF88269B9F89D5A2ULL,
		0x27B237DF90295289ULL,
		0xFCDCEBC25FA42011ULL,
		0x309CB07B21AC3726ULL,
		0x207D6C90BEDD58DEULL,
		0x583FB446D02DAD84ULL,
		0xDA93FBDEA98AC2C0ULL,
		0x7DF77DC8F3D817CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82264417F4650955ULL,
		0x4126FA6276F11426ULL,
		0x6ED44ECF8A3D089EULL,
		0x63595C4F53BFBFB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96EF4B56589274ABULL,
		0x2B1D957B896EEA64ULL,
		0x612D921A75A74DDCULL,
		0x5F9643C8BBC0DBB3ULL,
		0x9DE4B81EE09FE305ULL,
		0xB16A9AF318EC92B5ULL,
		0x72975EBA31E4FBBEULL,
		0xDBCBB13879ED517BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E29FEBB04E2C3CULL,
		0x80F095913C8CB15AULL,
		0x63A5A1BDDDA4AC2AULL,
		0x7FD2922AD4FAF406ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE521C1B60A30E770ULL,
		0x4CBB7925472BC082ULL,
		0x92BB8FFA94D3777EULL,
		0x1253832E6442FD28ULL,
		0xDA04239389EBB5D9ULL,
		0x6F37A0642F9E17C7ULL,
		0x3DED8C50D004AD36ULL,
		0x0E12BF0305434147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BF099C832DE5F2ULL,
		0xCEFD480458A3482DULL,
		0xC3FE63F975852D92ULL,
		0x291BDDA12C3EADBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0D71B66B8C6611FULL,
		0x5B519DD6CE45CA0EULL,
		0x6F493C974045D1EEULL,
		0x27CBB531343FC762ULL,
		0x449C41DF3BE6AC37ULL,
		0x5A3B986F1C89B8E5ULL,
		0xB2CE9CBB06335464ULL,
		0xF61E979C1E364550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD008E2899D03F6B4ULL,
		0xC02A3E550AB73C16ULL,
		0xF9F4805A2BE458D3ULL,
		0x3056365DB04E115CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5920DAEC86DC129ULL,
		0x09BB20B618ECD0ECULL,
		0xEC3DDD2C4C57F8A7ULL,
		0xD374C964CE8CBAACULL,
		0xB79A6408C3891C7AULL,
		0xCCD2A835FFE50201ULL,
		0x1291438A5D31376EULL,
		0x3E906426D9FE685BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67CE6FBCEC7FCC1ULL,
		0x710018BA14EB1D2DULL,
		0xADCDE3B621A63319ULL,
		0x1CE3A7292A503831ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCA48AC1537FB6F1ULL,
		0x26B1EA4CE4A60BA3ULL,
		0xCC100088F4086551ULL,
		0x4521EC65AE044982ULL,
		0x6210FFFBC2F71D8DULL,
		0x9803E0C5C7A1C708ULL,
		0x57C5C72702B03530ULL,
		0x6127CCBF8285AA00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2A8A20442E1C06ULL,
		0xB74547A886A996E2ULL,
		0xD36B90535A304A87ULL,
		0x310A50D30DDB858FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47432938F17B863DULL,
		0xBE6DC611580A904AULL,
		0x5AA1CD83AC0C3840ULL,
		0x86A863039C4E122DULL,
		0xBA46496BBAD4932DULL,
		0xFC83F6ECA19120ABULL,
		0x09D9DB96A5990396ULL,
		0x4930F1CDB953D1A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB20F36AD09608DULL,
		0x3A046D31539569C7ULL,
		0xD0F865E040C2C0AAULL,
		0x63EC478D1EBF303AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA092D808BD751281ULL,
		0x14DAFF84A6517871ULL,
		0x51A6031F3719ED63ULL,
		0x867E35457027CDA9ULL,
		0xA13A195259DA1209ULL,
		0x9F1404D87EBCA903ULL,
		0xA0F6AEDDCF3D9987ULL,
		0x2D5B6A1B09486D81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F329A4213D3C0E1ULL,
		0xB1D3B7A776528EFBULL,
		0x3643F80BFA3EB784ULL,
		0x420FF548D0E80EE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7FFB6A4E0A24B5ULL,
		0x0809EE4409B3CBDBULL,
		0x50B773D395E2CF49ULL,
		0x36028CFE171413E1ULL,
		0x59CFA33BF8F9C0B7ULL,
		0x2D07E5B953ED3DA2ULL,
		0xE7ECE58967E0AEA6ULL,
		0x34CAE51ADDA47580ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2523651431CC10FULL,
		0xB73607C67EEAF1F4ULL,
		0xBDE18639013CBBF3ULL,
		0x0C208EFAFD7D8503ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC1288B1F806D2CDULL,
		0xC325E8B01A9A6A4EULL,
		0xB70B5B50DB039CA0ULL,
		0xC1C83B2406C9D753ULL,
		0x88BDEE24185FFDD6ULL,
		0xFC1E024A8E35E78CULL,
		0x5CF06BBB87E5B7F0ULL,
		0x26939F478B059D72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4843E20D96468175ULL,
		0x2F9A3FC1369AC92BULL,
		0x82BB5927071CEA66ULL,
		0x7BB1DFC2A99F364DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17F86DA538ED2087ULL,
		0x95A4A687824BCE0EULL,
		0x6FB0930C94EEAFCDULL,
		0x8FD165CC5D7CDE71ULL,
		0xB8080B04B6A8B8DCULL,
		0x4A0633BE2DEFFBD6ULL,
		0x6005AD47DE7DB1A9ULL,
		0x8E2AC22A644FC65EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x692A105855F89460ULL,
		0x929054C253EB2FEDULL,
		0xB0884BB79B970EEEULL,
		0x2A2A381741545073ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB9EF5BE82B1B8DAULL,
		0xA19981CAAD44CB99ULL,
		0x093FA37C2293FBA3ULL,
		0x0DF1318C4AD47493ULL,
		0x495D2E16796F73ADULL,
		0x34F5A7F47F86B6A8ULL,
		0x3F959EC9400A36C8ULL,
		0xC89806DF7B6239D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F73CD14893CE8E9ULL,
		0x7E1070159B43E894ULL,
		0x7975355BA4181D5BULL,
		0x548236B89B6909EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A3D241D079F4A67ULL,
		0x8D6128CC5F49055CULL,
		0x12B99187503A90F6ULL,
		0x380404F5D29EF941ULL,
		0xA79234773D739E35ULL,
		0x25579231FB38A2B0ULL,
		0xFD38C97D52E3F452ULL,
		0x4FD22B011CAE43DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9F0EDD026C8C80DULL,
		0x1860DC37A9B12B94ULL,
		0xA9277A219E10D528ULL,
		0x11366720147D0BE8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD22D7E4E3303FFFULL,
		0x8FBCE7C6DC1344EFULL,
		0x58F88EA664810976ULL,
		0x0C4C3D959A809057ULL,
		0xF97B726840A95641ULL,
		0x260E9C6C96A3DA3DULL,
		0x8F91BDBBB558ED6EULL,
		0x2468235CB84AB94FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB575D35E7C530E63ULL,
		0x35E81FE53865AA22ULL,
		0xA89AB8834FB447D0ULL,
		0x73C17D58F5981226ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13518A9DFAFAD1E7ULL,
		0xFEA03D3F4B72E817ULL,
		0xF7941DFCAADFBD7BULL,
		0x029F7E5834A78D8FULL,
		0x06F9BAC9545E9C05ULL,
		0x0D34B8FD9F4B9DBFULL,
		0xECF80F3B43498162ULL,
		0xCBCDFC1493A4C3B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C6344808105FF19ULL,
		0xF473B2E4F0AC5272ULL,
		0x246660C8A7C8F209ULL,
		0x4332E9661F1C9B29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB316FEFAA59DB361ULL,
		0x081261C3DB9C4BD4ULL,
		0xA728155BCB43CF61ULL,
		0x218712044542B86EULL,
		0xB4CD9F86D84CA040ULL,
		0x26F0AA3C4E7122D4ULL,
		0x56792EEC0A1C81C6ULL,
		0xEC20BB879EB7AA2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x899CACFEC0FD8213ULL,
		0xCFCBA6B780677767ULL,
		0x7D250C654B7F12CAULL,
		0x2E62E825D485FB03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE29E3349395C501BULL,
		0x5B700399D4F87E4BULL,
		0xD9C1D49735C12ECBULL,
		0x5F9F65256D490F02ULL,
		0x296C4E350C79C9EAULL,
		0x77088E3B5AC136F4ULL,
		0x88ACA89A6991281FULL,
		0x070030D947376B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08B1CF29137048FDULL,
		0x06B520694DA6A68AULL,
		0x2362DB82E14D2377ULL,
		0x69A6A565FF82FB09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4262292FEF24A70DULL,
		0xE740DCF06384FDF1ULL,
		0x1AA67757D10951E2ULL,
		0xF1E987A9A66F8055ULL,
		0xF2CC4608336CF321ULL,
		0x456FDC491AFD28C1ULL,
		0xCEE9180D7BAE3AD2ULL,
		0x96532A190F0D9AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CB48E679150C15DULL,
		0x35DB8FCA65190ABBULL,
		0xD14009582CE60D19ULL,
		0x4241C761E2747E4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E2CE1D6AECE2A8ULL,
		0xC231F09A5DBE3825ULL,
		0xDE850C3CB589293EULL,
		0x5ED574980FA18A6AULL,
		0xDF6A7EDBEB7EEA4FULL,
		0x4DDDB394115B5C02ULL,
		0xD1B498A27BE5792CULL,
		0x5E7FC8E1F3AAC5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB1A2C25FC3AC76ULL,
		0x511A9894F14DE092ULL,
		0xFF53B45B199925D2ULL,
		0x65CD46223AFAE509ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x624225BE246AD94AULL,
		0x62F4BF4FC79C2DA3ULL,
		0xE5EE665FF4C2FBD9ULL,
		0x55BA7656775BDACFULL,
		0x2C1F9F5F68DF4852ULL,
		0xEDE96E113F984BC5ULL,
		0x2EA2463704F433E7ULL,
		0x69919E26AB469FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEF3CDE7B58F97D6ULL,
		0xB39B15DF38376CE7ULL,
		0xD204D28AB102B046ULL,
		0x0157F013E3D7957EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13AB27D06D99C07CULL,
		0x99A67FC7649CC69AULL,
		0xE70C508CAB3C3BECULL,
		0x6DAE07197B564B4FULL,
		0x809CDB8E73413E87ULL,
		0x91342EF0D08D4F93ULL,
		0x6448330408355FA0ULL,
		0x101535E04C9659F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF3BEF5894908E5ULL,
		0x276577865996967FULL,
		0xC9C3E325E3286DC2ULL,
		0x50D40664D9A7A608ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BBA111BB49493A2ULL,
		0x9CF24A2928886F9CULL,
		0x29E9BB6ED5E853C2ULL,
		0x2445F7282E857E04ULL,
		0xEC94610E58980D41ULL,
		0x715D87BECE95C18EULL,
		0x073AFE099879D326ULL,
		0x7CBD5A123CA5AAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C0793CDB268E07ULL,
		0x70D4707BD2C32AD3ULL,
		0x3CAB70DB77FDAB77ULL,
		0x286155DD2F1CDB91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A171A558654FD4FULL,
		0xF487B1EC2C278F39ULL,
		0xFFD76D95405200E5ULL,
		0xD0DB7BC8EF8CB4ABULL,
		0x163535EFA8066072ULL,
		0x3EE4876CFF444661ULL,
		0xD22D027F8B7ACC55ULL,
		0x7123D2965AEE97D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5FD1BE8774750D4ULL,
		0x4A73CC1A104A01A2ULL,
		0x3285CC83F48C558DULL,
		0x1C2CBE1A6EF73DD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02329E67DBDE9BB2ULL,
		0x2F3B8058114634BAULL,
		0xC73BAC8B922BD451ULL,
		0xAECC7FC4B30395C5ULL,
		0x575B57C6A43DF5DDULL,
		0xF135B58E3F70ECCAULL,
		0xE3118607708C113EULL,
		0x4AF9467466733D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9C1A5E43D111C35ULL,
		0xFD3473757C095AC2ULL,
		0x7BD591A646F663A8ULL,
		0x4FCCF50BE81EB629ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16B50223F9BECEE1ULL,
		0x59222195A8EF80C0ULL,
		0x1D3EA2289EA7C288ULL,
		0x46F0975240EEA515ULL,
		0x00070819FDE79132ULL,
		0xBE946E4F87E965F7ULL,
		0x6B48643F50DEFC94ULL,
		0xA892DD4C0D00AFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C035FFAA1E6003ULL,
		0xA32A8163D594A36AULL,
		0x09FD838E9FC1409CULL,
		0x4CBD709C2F08BE51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE8D0932BB7DDA53ULL,
		0x4DF1646634300161ULL,
		0x9EE402AA86663CF4ULL,
		0x6F73377FE3BFD7FCULL,
		0x4EC6D695F930E80EULL,
		0x7909B18CD1CAF25FULL,
		0xD4C875AA3B47B2ADULL,
		0x0411E1D6FB3CC22CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6010E375B8C04C8DULL,
		0x4561BF4D584FFB87ULL,
		0x34A579EF530AC2B4ULL,
		0x0A1ABD692EC4AAA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30E765BAEA9CB1DAULL,
		0x7C7826B9B67D0E1EULL,
		0x8F38EE335E9411E9ULL,
		0xCFB856EA176F95CAULL,
		0x3EF09598412B6CBBULL,
		0x5B5B08C849018DECULL,
		0x72DBBA64450D6E4EULL,
		0xCFA6B5AFB2FE373FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889D9A54970EDA49ULL,
		0x0BFB74748CB81F2FULL,
		0x9BD699159E92718BULL,
		0x22774EFEA92BC935ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE5970C6F63D37ACULL,
		0x1AE5FDC5C8983F2FULL,
		0x18C4C28CFF0B8A37ULL,
		0x5EE8D9DFFFC49D7BULL,
		0xD73BF78EA31FF8C7ULL,
		0x9A3FAFADA0F572FEULL,
		0x93F9EDC7A355886FULL,
		0x9EAEEFF813C2B73AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1402FF32CFC28B3ULL,
		0x005A118BAD075103ULL,
		0x0FDE0E2F3DBDCAC8ULL,
		0x6CE078B2EEABD02DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F61EBCD8325358BULL,
		0xC681C475F9CF1A48ULL,
		0x1578FC04A5AC6ABAULL,
		0x423B7AE1D3EED47CULL,
		0x735B9F7F27770654ULL,
		0xC68DA45FD10F1C3DULL,
		0xA6186ABF27F47B2AULL,
		0x72812C3CDEC5F465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EFB98AD5ED02889ULL,
		0x3F882AAF020D4B67ULL,
		0xBD18D46493F6B314ULL,
		0x41680BEAE5511B92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1192C04A121DB7FULL,
		0x476355C842F98831ULL,
		0xB2B2356DB0D548D5ULL,
		0x00D2C9FCAA180478ULL,
		0x1640B7AF40224909ULL,
		0xE803CAB65638FDD3ULL,
		0x0A5A16D19597282AULL,
		0x71C1302B4A7FAAA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB470082638B548ULL,
		0xB7F36CD90F6F3586ULL,
		0x3C119889E5453F33ULL,
		0x637FF069B90B5990ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5AF3320CAE92273ULL,
		0x4ECFD84F1841C226ULL,
		0xD6A46C5C05690E35ULL,
		0x08404A6AB87FE998ULL,
		0x0A00D4C69CD19D54ULL,
		0x8643AD7EFE225A75ULL,
		0x8D3BC4D84A66753CULL,
		0x867F513C291DD089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CEC89C12067FD0ULL,
		0x3CDB9928D15B2F86ULL,
		0xCD83A477109E7531ULL,
		0x7F265958D2ECDE03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68CDA1556D29773FULL,
		0x741373FAB388583AULL,
		0x4D2870AE55EACF78ULL,
		0x10AC8D0EEFDDDBE6ULL,
		0x9BE85199919B9903ULL,
		0xCA7E171630F738AAULL,
		0x19D123966F7602E0ULL,
		0x21563648BEB6BAADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D49BE210A422E6FULL,
		0x82CAE145F83AC18DULL,
		0x2233B902E16F3CD6ULL,
		0x03789BDB3EFD9198ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD950F1B4EC66A7E5ULL,
		0x814B6A59DC44A915ULL,
		0x8B983D0BE2632C12ULL,
		0x48FA38732BE5A181ULL,
		0x51722C324BDAE62EULL,
		0x4426B5239DAEB50EULL,
		0x6F585357B25688A0ULL,
		0x36017F052EB4FAFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF043812C2EE4D3E9ULL,
		0x9F0A4DA344338935ULL,
		0x12B49C105B3B73DCULL,
		0x4D3313381AC2E346ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE57AE48396304407ULL,
		0x41236379843F6FEDULL,
		0x5072D2DDCF01E1C9ULL,
		0x3E2DF62F4CD7824CULL,
		0x740F443BC8D58DDAULL,
		0x75C2729FD5A9042BULL,
		0xE2FBEE9629BFF653ULL,
		0x761D70B3BE9C9C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FBF056365E354FCULL,
		0xBC0067333B560E61ULL,
		0x01D83D280180722CULL,
		0x468CB0DD9816AE24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE9EDFB11871DFBAULL,
		0xDC6EC10505C3097FULL,
		0x4554A0D3F034DD50ULL,
		0xBCE6B0498AF7D070ULL,
		0x4ED7C67B8DBB7511ULL,
		0x84428F21B75B6B07ULL,
		0x42DEA1E8E5A61DA1ULL,
		0x9D3E2744B74C2852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A65608224543D0ULL,
		0x7E5000063D54EC95ULL,
		0x3260A96606DD434AULL,
		0x1420847CC045CCA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01B0FABBCA510643ULL,
		0x185DBF0B7CFC7C38ULL,
		0x38D9DE861E5083A3ULL,
		0x300A98E2669BD392ULL,
		0xDD2750F31CF315CDULL,
		0x7B843FCD28665306ULL,
		0x4BBA2C563DB07698ULL,
		0xB7EE73D06925CE4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD586FED2166646B3ULL,
		0x6DFF377F7C2CCF3CULL,
		0x767C735346821E45ULL,
		0x7D6FC9D202387357ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6DEFF37B05B76E1ULL,
		0x92E4F4AF1C9FAA44ULL,
		0x765298E8E9CCC9FFULL,
		0x4634552D0070F27EULL,
		0xFADCBB806FE7F1E9ULL,
		0x61A61C90E4E209A9ULL,
		0x03F7B2F4F55AEE13ULL,
		0x03BCA318B9CE8043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A2D4484CC95F8AULL,
		0x118D3231162D1980ULL,
		0x0D172945554C20E0ULL,
		0x54348AD89517FC71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A9AA4CF3B81DD08ULL,
		0x06D8CA317CB283EAULL,
		0xCA9544768FBAA06DULL,
		0xB68BFEACB8F65119ULL,
		0x98DD3D8BDCACA9A7ULL,
		0xC29D5496E97C390BULL,
		0x6085F101DF343341ULL,
		0x75B336C0E31D7D09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B71C791FD230E7EULL,
		0xEA3358982522FBA3ULL,
		0x1E770ABDB17A3C2FULL,
		0x2F261F4E6F56E07EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39C91C3BEF192541ULL,
		0xD50CCFFC0824D965ULL,
		0xD5CA5F0D0680421EULL,
		0x13CBFC9445EC0A60ULL,
		0x77730DD835D7D68CULL,
		0x680F672EE8B1B604ULL,
		0x4CE0A9003E7E8ED4ULL,
		0x8F22224B2CD80B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4DD2A53ED230127ULL,
		0x475620F29285DE0EULL,
		0x3F2375164D4975A6ULL,
		0x52DD13BCEDFDBBB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC964254A529A10B7ULL,
		0x180C403A7495D994ULL,
		0x01F562F673619C3AULL,
		0xBF00F159E807D37CULL,
		0xC07587406E3C5852ULL,
		0x203F829C3F43175EULL,
		0xE8EF500221EEA22BULL,
		0x5EF79B46A4D8EFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD638DAAF8F2F0AULL,
		0xE179A36BD88B51A5ULL,
		0x957B43477CCDAEA0ULL,
		0x57C1FDD6603B6700ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42F370C9CA04DC2FULL,
		0x97FA0B99E4887B2EULL,
		0xCDFD1A9F4C4F8BF8ULL,
		0x22B67EB9BDADC0D3ULL,
		0x1F40FC06432E3E0CULL,
		0x901FA79C621AFBDFULL,
		0x93ED5CD76FE1D05AULL,
		0x5B8FB359DD6E9A20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE698D9B7C2E213F8ULL,
		0xFCACECD07489DE4CULL,
		0xC338E299E7D47969ULL,
		0x3A0B1E109C18A1A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECD39810C20C57AEULL,
		0x8D1B458973310F4FULL,
		0x4992B438DC3421BEULL,
		0x23A9EB47B61879A7ULL,
		0xD41644D654829F94ULL,
		0x2D6AFA01EA6EB423ULL,
		0xA499F62EB9B54578ULL,
		0x18E5C894786A1DF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6821CFE14D70082BULL,
		0x4AFC61D23F9FCCA1ULL,
		0xB86D3F286D1C7195ULL,
		0x55C5B15195D8EBABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49B718A8724E38C3ULL,
		0xE5CD444702644DCBULL,
		0xBE73D7D1AADC3840ULL,
		0x7C8E3C1510A63F5DULL,
		0x567EAE72C585090EULL,
		0x735114E00C33631AULL,
		0x50A9087A8C032DE4ULL,
		0xD029268DB47CC92EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2084FDB1C40D9571ULL,
		0x03D65D88D20503B4ULL,
		0xB78B1A027355082AULL,
		0x62A9F51DDB2C1C3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x737974E81BBEB27AULL,
		0x815B9F71597756E4ULL,
		0x02C4BD79E4F837E4ULL,
		0xCD27E5E551C762FDULL,
		0x084B1B59419454D3ULL,
		0x64FAD8AE2B9E3BA6ULL,
		0xBC54E15AEC51633CULL,
		0xDE5637041E21A27FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE9F8427D7C34EC5ULL,
		0x7E97C94BD2F43189ULL,
		0xF75E30F8F90CF2DBULL,
		0x4DF41081CAC581F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C4343AA3E87EC5BULL,
		0xEFA333C83E0E7F61ULL,
		0x2C940B9B96099646ULL,
		0x989CF3D0147C5935ULL,
		0x2130D9F2E85EB8D4ULL,
		0x9A23366FC8D8886EULL,
		0xD3FD495B3CAF0586ULL,
		0x5FBE40F2C38ABEBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49839DB8BC975DFAULL,
		0xD0DD48600E32BFBAULL,
		0xA42CEF2698046841ULL,
		0x4EDA97D91B14A988ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AB09B4654B78386ULL,
		0xACE8EB679C94168AULL,
		0xFBFDC871B1FF124CULL,
		0x9B011347B67F6A75ULL,
		0x9DE98785A4E705A0ULL,
		0xD4692107466E0D58ULL,
		0x25066AE41E91317EULL,
		0xEE641C03C6FE25B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB5AB91CCF025E8BULL,
		0x3483D27C10EA11B1ULL,
		0x7AF1A64E3B8C6B20ULL,
		0x7DDD3BD74039037FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F38AA35102950FEULL,
		0xBFFB4A100C6AB997ULL,
		0xFF40F44D1A4E9748ULL,
		0x55533E21088076C6ULL,
		0x7435116AF4807F43ULL,
		0x51F9F0CB93FAAF34ULL,
		0x6C7CEA534A9151BAULL,
		0x431117E33102698CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF1940155B3C366CULL,
		0xEB15084803A0BB60ULL,
		0x19CBBCAA2BE0B8F0ULL,
		0x49DCC9DA4EDC219FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF525B0481BD75867ULL,
		0xEFF8D6649FE96795ULL,
		0x0EBC4F5FD75BF33DULL,
		0x2F6F26D6B3CF42FDULL,
		0x2EA0AF74B2AAB586ULL,
		0xB0D748BC6D202990ULL,
		0xF14334250F872860ULL,
		0xD4378E57A31D3B3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0FFBB9AA12E4EF8ULL,
		0x2FEDA25CD2AF92FCULL,
		0xDEB60CE0256BF198ULL,
		0x2FAE47D8EA260E08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3373B1162677C92FULL,
		0xCCCDF2ECC8A98F62ULL,
		0xE22816FCB1608ECEULL,
		0x08894EDF45CDB746ULL,
		0x225AED52D66042DBULL,
		0x98719B27277AF948ULL,
		0x76081D037FDCF5BAULL,
		0x087849C14FC36E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF2EB61F8C1B5D7ULL,
		0x6DAAFABCA4EA9017ULL,
		0x675C6581AC2D0881ULL,
		0x4A6441911CD01BF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5071169A77FB7905ULL,
		0x3066957C9322C9FDULL,
		0xB33962DEAD72ADFBULL,
		0xA961B954A436EA44ULL,
		0xD062DA730E948016ULL,
		0x1A3F0FAC47432D26ULL,
		0x0D7511ED8E4CCF0AULL,
		0x89105F42AE8EC716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1D83AEA2067F67ULL,
		0x15C2E90F271B7DC0ULL,
		0xB29A0C21CCD9697BULL,
		0x01CFDD3A8D68778AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F8F8F8129DB2D22ULL,
		0xA56C3EA65B39F533ULL,
		0x0C3341B5E7229258ULL,
		0x990BCBFCD62840E4ULL,
		0x1E09D1047C71E149ULL,
		0xA28D341F1D4486D5ULL,
		0x208B4BF6853F25EEULL,
		0xD03F228A90C626F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE504962BA2C2A2A5ULL,
		0xC661FB44B365F8D5ULL,
		0xE0E0884DAE8233C4ULL,
		0x026AEC8E53920920ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD71B33312902D8C9ULL,
		0xB29F547A1CA4915DULL,
		0x393E8DFA8A61E76CULL,
		0x68BB2959C2E5C344ULL,
		0xB79AD434D62DDC18ULL,
		0xE61D6FFE9883619CULL,
		0x5618DDE3C0B2A900ULL,
		0x746FA38722DB6DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1816B308F3D186F2ULL,
		0xDAFDF444C0250EA1ULL,
		0x00EF7DC924E6FD8EULL,
		0x314D6F68EF780D5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28ECAEC0BE9791D3ULL,
		0x151C866B98DA9287ULL,
		0x9721B81FE9349501ULL,
		0x05030C4261CE0946ULL,
		0x99B552B52AA8CB4EULL,
		0xD6D8571A7A05F5D0ULL,
		0x0B29B00CBCC4C5DAULL,
		0x593241A2E97043D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D6F5A513A5C155ULL,
		0xF9397459B5BD0F7DULL,
		0x3F51DA03EE69F37CULL,
		0x4278CA7108781A74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BBB7B1AA3EDB0EEULL,
		0x6F64A52EE2173D8DULL,
		0xC388C8C9C22DC69DULL,
		0xEDA0BB83E6230847ULL,
		0x8B86FAA3C96125E1ULL,
		0xAB8CCDE68784CEA0ULL,
		0x01A53F4FEE10B79BULL,
		0x4DD4A0EF998A5242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C4AF6A8859521CULL,
		0xE64B3566FFCDE962ULL,
		0x02102EA718A907B8ULL,
		0x7B309F14B0AB3E14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF150A890D916CDEAULL,
		0x5433493A7E0FF35BULL,
		0xFECE64A0B4DE8203ULL,
		0xBF15C8C78BAAB8FFULL,
		0x9302D695E40111B3ULL,
		0x5387DE8FD9D671A1ULL,
		0x675CA947853A1BA1ULL,
		0x7E54EA117346DECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3BC82D0B13F714EULL,
		0xBA5E5294D3E4D157ULL,
		0x568F853E7B7E9BF5ULL,
		0x7FB0875EA82FCB7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA28A086A5B59128DULL,
		0x4F1F7CBE882EFC53ULL,
		0x250E51A1A8FDB4E1ULL,
		0xFF9024641DAB3D0DULL,
		0x35E60D33EBEA7258ULL,
		0xDD89CD62A529DF5BULL,
		0x061613FA7CD9F2B4ULL,
		0x5434017A39615686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AFFE1F60260D8BULL,
		0x3193F9630C6623DDULL,
		0x0C5548D03157BBBAULL,
		0x7F485C88A21E14F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x769C28C76E4F9580ULL,
		0x4C7D38D6BFE20E8CULL,
		0x0C1F3E7B58968CD6ULL,
		0x78B3DAEFBE77DB80ULL,
		0xCE9F826C1A6BCF4AULL,
		0xCC51E06E7ECF9E8CULL,
		0x69CEDF361E65646FULL,
		0x8984A10558DBD884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224984D35A505D87ULL,
		0xA0A4893D92B39773ULL,
		0xC0D46083DBA3756EULL,
		0x6263C1BAEF19FF27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43F666A046F91D1CULL,
		0x0C7720A6E344CFDDULL,
		0xAFF5CF05DB835311ULL,
		0x82C36222C43056FDULL,
		0x56F5DA1BB0640058ULL,
		0x71CC6B265016DF51ULL,
		0x9226F494CB45B974ULL,
		0x8E4FD2DA623A6B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C74C6BC75D12D5DULL,
		0xF0CF0856C6A9F5F0ULL,
		0x61BE1D1C07DCDA59ULL,
		0x229CAE8D58DC3DF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F737C40F5B6A435ULL,
		0xA5E164FF8A700D74ULL,
		0xA00FDF2D88271021ULL,
		0xA9EF09CD7EEA6A06ULL,
		0xE56FBAE9703FC29DULL,
		0xAA5885B8012807C8ULL,
		0xE7C2B86EAE094C7AULL,
		0x828A564B668BDBE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E093AE79F2D8A7BULL,
		0xEF053E4FB6613546ULL,
		0x06F73F9B5D886A56ULL,
		0x0A77D8FEB7AD0E01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A44731AF1EC9CC2ULL,
		0x18EE2588768E0FE9ULL,
		0x55D36A964E75DF10ULL,
		0xDA02AC58686E1DB6ULL,
		0xF61FABB52A3E1CDCULL,
		0x3B591090BC23C7D8ULL,
		0xEAC3379A3682BDD4ULL,
		0xE40F8413294ADFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F7EFFF3724EA89ULL,
		0xE8269B0463DDBA1DULL,
		0x2ECDAB7A65DE0C90ULL,
		0x34504730898B5D67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07489FCDBFE3CBAEULL,
		0xE5F172D4F5059C58ULL,
		0xB21965993F76F6E5ULL,
		0x9951C3FC9C6044E3ULL,
		0x093D7235DC48F95AULL,
		0xAF1F0A7142FFAE7EULL,
		0x79E81795A8E4DD34ULL,
		0xAA62E622A33DD6EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666793CC72B8D2D3ULL,
		0xE48CFFA4E6F9830DULL,
		0xCA8CE5D0516FCCB7ULL,
		0x63FFED20D78E2C23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62B5B379305C9E7AULL,
		0x4FC58C125E4612D9ULL,
		0x3D9A8DE439C9E70AULL,
		0x1F9ED8F587E5C355ULL,
		0x88DCC9A880EEEC7AULL,
		0x69C5F4D83E1273A3ULL,
		0x8628DE2E2C1CDCE8ULL,
		0xAA4CF3B90281B6C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB37BA27C53D3BC4CULL,
		0x0327E42B95033D1FULL,
		0x27AB88BEC612B18AULL,
		0x670B066BE726E4CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1C1F277920FAE0AULL,
		0x2CBE27303675168CULL,
		0x7A931E2E395D0C7FULL,
		0x6938623112E6D29DULL,
		0x8A9765D2778643D6ULL,
		0x8F313741F6C63024ULL,
		0xA8358461FA07C1ADULL,
		0xF1555A96A46D0EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643B0FB54FFDC526ULL,
		0x6E0C5AFAD7E03BF9ULL,
		0x7284C4B95683CC42ULL,
		0x3BE3D48D7B1703F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD872822177BC2A60ULL,
		0x7D9F340595442020ULL,
		0xB72306A34580EDDCULL,
		0x38E4BA329C4FC481ULL,
		0x64C3593FCA2329DDULL,
		0xFA21C1AAE2D42685ULL,
		0x9A9D689833FDC4A2ULL,
		0x0FF334237BCE3464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD71C19978F4618DULL,
		0x9EA1F36340C1D7EDULL,
		0xAA808D3AFD2C1E0DULL,
		0x16FE7776FCEB8B70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA85ED62C717B67DULL,
		0xA9ECAF90F823694AULL,
		0xD20844361BA1E4C3ULL,
		0x01CAD0431D3F8E23ULL,
		0x7F6420E1B67E91FDULL,
		0x367D30F493DC6F2EULL,
		0x9C1F157B2141DA9AULL,
		0xDF460B8E18560B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE362CEE3DDE166F1ULL,
		0xC081F3DEEADBEA31ULL,
		0xFEA5747D0B6857A7ULL,
		0x2630875ABA053190ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A4F209F840A96D7ULL,
		0xCA41F23F016843CCULL,
		0x04A77B15840FC903ULL,
		0x51DDA6F26F5A1089ULL,
		0x927671B6776DDA7CULL,
		0xC9A8053F13D9BD0EULL,
		0x1FD9F8C34A230CB3ULL,
		0x7FFE2B02882F26D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E401B53E590811ULL,
		0xB932B99BF3BA53F6ULL,
		0xBF0268128543ABB3ULL,
		0x51980952A659D393ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4853AEE27B7E169ULL,
		0xB59F14AB5E2209AAULL,
		0x6F60DEAC8E0C3D2FULL,
		0xA90B6D0E0DD40B62ULL,
		0x6BC6B665E2045476ULL,
		0xB75E10EED26960C0ULL,
		0x103CC63BC8F81B73ULL,
		0xD21E044D8561131DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4044E0DB45C6F9AULL,
		0xED95981E99C6663AULL,
		0xD8664B8C62E0505CULL,
		0x5980108FDA3CE1B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF43F48334B462A1ULL,
		0xD80FDBBE9E67DFDDULL,
		0xEAA69B6B33794907ULL,
		0x30343D9F9AB214ACULL,
		0x73F471C46132BCBAULL,
		0x7571F3078C64C145ULL,
		0xD3E34F5395116593ULL,
		0xFA72F3913566825BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058CD7A9A23C6BBBULL,
		0x46F9EEDD755C902DULL,
		0x5E6461D3540E5CEBULL,
		0x5D44652D87E96E4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCBD96881369AB5DULL,
		0x525C6548566ED540ULL,
		0xF974F87A2D3C1662ULL,
		0x674DFA27524F8908ULL,
		0xB491F65FAE9B046AULL,
		0x0311DF107F46F841ULL,
		0x240E9F4CCAF6FB0BULL,
		0x97F9527C03A6BD23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A6828BBFE6C5670ULL,
		0xC70381BB3AF7AF01ULL,
		0x53A09DE04DE55A04ULL,
		0x7650388FDD0F9C40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x818CD8AD30510361ULL,
		0xDB2919AF5823AE3BULL,
		0x9D5F8E4559789265ULL,
		0xF7B766030361571CULL,
		0x030F551AFE771DDCULL,
		0x0BFFE58608FD3301ULL,
		0x78E434CF61295B02ULL,
		0x5D4271A87BD1812CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5D37AAEF5FF7430ULL,
		0xA3252B94ADB94061ULL,
		0x8F3F650DC59C14B3ULL,
		0x4F944505647A83B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9916A5BE841BB74AULL,
		0xC140D3C2AAD2B43CULL,
		0x0120F5744AB6BA76ULL,
		0xF7E000F9A0182E1DULL,
		0xD1768A8267A367E5ULL,
		0x60D865714DBB5060ULL,
		0xC234BB32600743BBULL,
		0x5D5ED296BBF21281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0AF3519E65D256FULL,
		0x215FE29434A0A29BULL,
		0xD4F4BEEE8BCAC847ULL,
		0x53F343598606ED5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24DA8986BB66F06CULL,
		0xF4389B69F574EEB5ULL,
		0x07907F544286E503ULL,
		0x29EA21E78406F395ULL,
		0x7BC1DC3A978FC4ACULL,
		0xF4F26E27EE382389ULL,
		0x4CBF015BB26BC73CULL,
		0x2925F1E924FDC668ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A13A393ABE22D8ULL,
		0x5034F55751CA351DULL,
		0x6BEAB2F0BE867810ULL,
		0x458C0A8301B26710ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CC7E76F5E04FC32ULL,
		0xFF81BAB5AEC5DA69ULL,
		0x52AF8FBF814DE9A6ULL,
		0xC906865ED4FCED6AULL,
		0xCEB97BBB9109E6B9ULL,
		0x47C8E93761FD55FEULL,
		0xD8A4D0BDED358EA2ULL,
		0xA9E51D9BD5D6B488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC504546E57D3F84ULL,
		0xA75458EE3A609E3BULL,
		0x7B268BF0B74115BDULL,
		0x0108EB8092DBB9BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E269141AAED0FE7ULL,
		0x854C514DD8D7EB1AULL,
		0x5BF339D9A3B76825ULL,
		0x2FF284C7783B2E05ULL,
		0x15E060B40C71E799ULL,
		0xB6C2CCCE7B0A2A0BULL,
		0x7A3261952185B33CULL,
		0x6D50F1C24D89F8A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD74EBFB83D572FDULL,
		0xA636B7F41C5A28BFULL,
		0x7F6DB5FC9D900328ULL,
		0x69F6679EFAB61707ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF875BBF1D5D385BCULL,
		0x20B683A0130E205DULL,
		0xAB60B6920F20598FULL,
		0x413CA90619FBEAEFULL,
		0x130BFB3F4EF150B7ULL,
		0x65BF96DD8A9A9E98ULL,
		0x651C4C05B4566E33ULL,
		0xE9367DFB89B5D147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC3D07578DA58605ULL,
		0x3B26E882A601AAF0ULL,
		0xAD93FF6AD3F4B530ULL,
		0x5F535C5C8AF8FB88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D80733311074CEEULL,
		0xBCB3A5875CF26344ULL,
		0xA09999969AAE4788ULL,
		0x44840951D16074A2ULL,
		0xC3AF1B06B7818039ULL,
		0x96EAF11933E9CDD4ULL,
		0x3C5B28299797373EULL,
		0x624B8BC05B5EF445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997E76324E40578BULL,
		0x23936F4511A6F0D9ULL,
		0x96218FC31B207AD3ULL,
		0x5BBAC7DF6178B6E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA70BE04716424E09ULL,
		0xA712A24C9A73DBB5ULL,
		0xC29D5D24B1FF45D1ULL,
		0x46187DE8C202B498ULL,
		0x61CA4FB529553F48ULL,
		0x32B2A494E9ED0915ULL,
		0x97B62E567A783030ULL,
		0xA27F8C79CF5BDB8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B13B52B38E9B649ULL,
		0x2D97106753A334E2ULL,
		0x47A83DFADFD66CF9ULL,
		0x650757FD89A54B9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7D3EFD5ADC13C78ULL,
		0xAF0E855AA81BE913ULL,
		0x3E7BB6EB0EC76A3AULL,
		0xA0FD653FB381E231ULL,
		0x90A2DCE7A08C5F03ULL,
		0xAFEC00CBF7605E05ULL,
		0xA8A400711C9D1634ULL,
		0x24B33270C9588D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000BA37829757CEULL,
		0xCC16A3A16069DDE7ULL,
		0x46D3C7B54E18B60CULL,
		0x1396E1FD96A6E1A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC490F5AB4F7B32A8ULL,
		0x74FF62762B66E713ULL,
		0xFD87E1DD5898A129ULL,
		0x408286A54CE52897ULL,
		0x3EFAFE5C820FFED9ULL,
		0x7627E0C33B8CCA12ULL,
		0x6A3AE2103E027CADULL,
		0x8F00AFDD90C8C3E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD2B7669DDB09FCULL,
		0xFEEABF71024CE5C9ULL,
		0xC24570468CF722E8ULL,
		0x7A9CA188CAB23C7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF903135A39EBB17CULL,
		0x29E769197FF7D818ULL,
		0xB4B8F56422143730ULL,
		0x0DEC3891C68FCF06ULL,
		0xD564EEA3C0D7972BULL,
		0x4D408CEFA9161DCDULL,
		0xF00F7ACF9093C419ULL,
		0x69BB8BCAA4247548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5FE7FA8D9EC242BULL,
		0xA17C54AC994044A6ULL,
		0x57053033980352F1ULL,
		0x3FC2F8A623F937DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03D7CD2EE98E888DULL,
		0x9EC9C8AFFE82A9FAULL,
		0xA9B1E35743E15519ULL,
		0xB5D25B828D5AA20CULL,
		0x45EAA778A09F817AULL,
		0x00D9BC0B585A5D37ULL,
		0x07E42C57372FDB92ULL,
		0xDEC4CD9DE837E922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64ACA916C13BC5A2ULL,
		0xBF1BB25F1BEC802EULL,
		0xD590784974FBECC5ULL,
		0x4708E0F305A73D19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA0D7AEFD2D3B7EBULL,
		0xD6209BF68CE7E069ULL,
		0x4A247F3EA84EF56FULL,
		0x90E8C414898593C7ULL,
		0x8676A616621ABDF2ULL,
		0xF88024A41C9BBFAEULL,
		0x5976AA592E3129D4ULL,
		0x874B3E0FC90C549BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFAA224262CBECE2ULL,
		0xB9260C52CC065451ULL,
		0x91C1C87B839B2B0CULL,
		0x2613FA6C615A22D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73FEEAA8E500FB70ULL,
		0x57F45CDEBFBB81F9ULL,
		0xA02C729660525A1EULL,
		0xF604FA3E0AD16474ULL,
		0x988F0611FB14D1CEULL,
		0x98A9ADF2E1BCDF53ULL,
		0xC01358AF59474E84ULL,
		0x4BE6837BD1093AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1939D1542A1821CCULL,
		0x01242EEC41C4A862ULL,
		0x230B9C9DA0E801CDULL,
		0x3A3C7E9F1230207BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1D6500719C316E2ULL,
		0xB5DB5FA85D353996ULL,
		0x9147BAF7F92C3E13ULL,
		0x1C0807D1FA3226D2ULL,
		0x352313A0901D5D03ULL,
		0x4B1469DB2647C3CCULL,
		0xDB0080992A4D5DD1ULL,
		0x1BBA8633AC3A57F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC50B39DC7E1EE5ECULL,
		0xDAE316300BDC49E6ULL,
		0x135AD1B440A82B24ULL,
		0x39B7F37D8ADB3493ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9F2FCB3A7E63F7AULL,
		0x3AA5FE75C2130312ULL,
		0x090547BC3CA15614ULL,
		0x17633F0F36A9353BULL,
		0x0FC51B4B7206F14BULL,
		0x8308246BCEC1A1FFULL,
		0xFE5456DFEC4CFD5EULL,
		0xDAA12F217D96156FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213509E694EE156FULL,
		0xADDB667672D10EEFULL,
		0xC98A2CF9500EF21BULL,
		0x0B503E07DAF063DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF54C5D2844EC9EB9ULL,
		0x22121F55774A1364ULL,
		0x0FC206A26D65BB67ULL,
		0xDC190E1C15999EB2ULL,
		0x59BE24D773D9DDB5ULL,
		0x81922524A59428ABULL,
		0xE987B4C953512AF1ULL,
		0x91F1915A89B44E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4785D52377438AEEULL,
		0x5DC3A2C60B481CD4ULL,
		0xB9E6DC84CB721B40ULL,
		0x05F4A18C865D42DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22405E3092179031ULL,
		0x52E6D1F6D8000AA4ULL,
		0xFCF9786161B7EE4BULL,
		0xC42428236D3ABC94ULL,
		0x49CF32036875332EULL,
		0x54FFD70D734ACF80ULL,
		0xC81FAABB51103062ULL,
		0xABCA53C472AAB80BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1701CAB2137D2CE1ULL,
		0xF0E0BDF5F51AD7AFULL,
		0xB1ACD02F6A1F1CE3ULL,
		0x442C974C72920E54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB37F0DDD958ABEEULL,
		0x7C084E958D4974D6ULL,
		0xE1041B34C2E25D82ULL,
		0xAACF211A31A81203ULL,
		0xF5435090785732D2ULL,
		0xCA2B4720672BF1E5ULL,
		0x5DDE2837F8CC5BFFULL,
		0x371BCD6F4E8182F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1335E64FB64A385DULL,
		0x7E74DD64DDCF5CF9ULL,
		0xCFFE1383B138057AULL,
		0x58EF9F9FD8E181D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DBFFF7FD27BEB44ULL,
		0xBF3400DFB74727FCULL,
		0x432AF0F90A60F135ULL,
		0xFD2E681579B0C82EULL,
		0xC73AABED3B2C083DULL,
		0x54C1243728F15F24ULL,
		0x2DD5191812855E04ULL,
		0xEEA16B6DE4FB1CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07584B69B0529AAULL,
		0x53DF610FCB1B4771ULL,
		0x10CCAA8BCA2CE5DAULL,
		0x69245A6576F70D99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x873C7E5BDD3BB0BDULL,
		0x19087F252932CE0DULL,
		0x84B736624A25EFC6ULL,
		0x5B2E68CB5AF10748ULL,
		0x3ADB6F8ED14B9A68ULL,
		0xA4B60EE484FD9A11ULL,
		0xCCBC376A45D83B38ULL,
		0x40866BFE6B5C4476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43CF0D8EEE749D96ULL,
		0x8C0EB510E6D7AC9CULL,
		0xE8A77028A83EBA2EULL,
		0x6F22708F4AA330EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A29A2220D3BBACAULL,
		0xEB7FEEBC462CFEBEULL,
		0x338B803CC819F719ULL,
		0x8C202FE60905B8FBULL,
		0x9571BAD3FE965A4FULL,
		0x9338C10C97850BBAULL,
		0x5740F4FB17E50F4CULL,
		0xD9430F0C3D8D885CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x890B5D99D78D2757ULL,
		0xC5EC969AC3ECBC70ULL,
		0x272FDD82541A3C77ULL,
		0x4C146BB72C07F6B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x312D6741BF13BF8BULL,
		0x02EFC45C08D8AE46ULL,
		0xA9618C97AB93A2A7ULL,
		0x8905877172DAA167ULL,
		0x38A541104C1AF156ULL,
		0xEDBC21FA92B071FAULL,
		0x832CCB183BF8CB9BULL,
		0xA1CB0562940B890CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B50FAD0B1395F2ULL,
		0x4CDCCF8DCF09996AULL,
		0x2207B2309281DBCCULL,
		0x0D2854136C90F943ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CDB7A91E2D6D917ULL,
		0xF118E3BBD54E4CB4ULL,
		0xEB9E1E0A7B3E8E95ULL,
		0x659BBCBC5D6F30A7ULL,
		0x3F0D338D1829715EULL,
		0x3770B04954F24432ULL,
		0x2DD9FD97ACF4D985ULL,
		0xC5CDA3003C99CF21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D1218378FDB16CULL,
		0x2BD30E9E71446C29ULL,
		0xB9F9C28E2796D85CULL,
		0x4221EEC55C43EF94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A492F28188385DCULL,
		0xD92393D48851D8DBULL,
		0xB99581CA1E3DB695ULL,
		0xB3ED5E9E0B1DD2A6ULL,
		0x11C1AC3FD70B74ABULL,
		0x6A366C6D454B0346ULL,
		0xA89FACE82DD6ACC7ULL,
		0xA0637EC8CD6BB727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD08C0A20436DAE1ULL,
		0x9D37AC0CD1745541ULL,
		0xC1492C40EC1B5C2FULL,
		0x02B2306C891B0289ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x411AE2620C65B0F8ULL,
		0x48308F44FDB26534ULL,
		0xB3841E489FB2FEC6ULL,
		0xDD61AB2152339651ULL,
		0xBB75A586911D2890ULL,
		0x9F26CD9C3CBB5191ULL,
		0x221A0F0176A34A1CULL,
		0x6E69FB439B01784FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1491745B96B9B8DEULL,
		0xE7F31476018080D6ULL,
		0xC36258803BEFFF05ULL,
		0x411CF72A546B7210ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDDC64AB5FAA78F4ULL,
		0x9EC9201D9BD0197CULL,
		0x9F793BC0F3126A5FULL,
		0x226A9247A2A97475ULL,
		0x00171CFC19ABE3F8ULL,
		0x58457F1E67239992ULL,
		0xD9A7907159308225ULL,
		0xB2A07568176B07ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC14AB2172F2E53B3ULL,
		0xB919FEA0EB18E528ULL,
		0xEE58AC943045BBEAULL,
		0x263BFFBB1C8CA19DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC00A2173C08BD68ULL,
		0x6875369597033249ULL,
		0x7D97DECA3400352BULL,
		0x12E5B59A0471CDF6ULL,
		0xA6FAAA9DC3823167ULL,
		0xF8B55DB4ADEFA22EULL,
		0x3F5898FDBFAE97DEULL,
		0x74AD881BBF262CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7535F582415C1538ULL,
		0x53611F6768954536ULL,
		0xE4BE9474A7EAC044ULL,
		0x64A7E9B8641C7A5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4894A60D239267C8ULL,
		0xD158B5D028657C98ULL,
		0x1BE57FFC0B20D8ADULL,
		0x87FDEA6ECED1BD31ULL,
		0xF24992C4042432F6ULL,
		0x5EA27419B1473295ULL,
		0xCFF30902E11F03E0ULL,
		0xA628F79DC9E16A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F806F25C0F1FC02ULL,
		0xDD75F1A078F6FEDAULL,
		0xF9F8D66975BB6BFBULL,
		0x3212ABDAC647857BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FBD42B47558D70AULL,
		0x51CFE5F646B61920ULL,
		0xA81A864F6866C6EEULL,
		0x18F5B5A14F329A7CULL,
		0xEF3EC336F7EEBF9FULL,
		0xEFEA930A97848195ULL,
		0xD32250D9C86EE4B4ULL,
		0x0FD7F75A65365225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230E3CDD42C948F0ULL,
		0xEEA1B988C4615562ULL,
		0xFF3286A328DCB9C9ULL,
		0x73046D0C5542CC19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93BF4F60D110E288ULL,
		0x74E9A22424E4082DULL,
		0xF6998B64980F8737ULL,
		0x8D7BF444D5BAB86BULL,
		0xF06468ED5F00B62FULL,
		0x0D82D8E58AFC33B7ULL,
		0x14E7262F8D214CC7ULL,
		0xD54E7B00FEF2A568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A6E29CEB2BF242ULL,
		0x7655D436C653B57BULL,
		0x10E936738B00ECC3ULL,
		0x3722366AADBF45DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA080C3CCAECA05F0ULL,
		0xACC537399A510483ULL,
		0xC5FBD58C54C2F718ULL,
		0xD1FD417051482F5DULL,
		0x2BF0BAF545C06620ULL,
		0x14221E0C2BD4ECCBULL,
		0xF6632C79E1D80ED4ULL,
		0xB10A1829A6ABCF8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x263C8435095932B2ULL,
		0xA9D5AD081BEC2AACULL,
		0x58B46FA3DAD52A93ULL,
		0x197CD79F0EC8FE70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x231990E6A496735AULL,
		0x6B69DB3F344A47EBULL,
		0x7B14FE1A7D11B0D8ULL,
		0xEFE6541898D3765CULL,
		0x686C47F863153082ULL,
		0xC2707F843A7E8E30ULL,
		0x15600B181CED7184ULL,
		0x7F732017DD6E3419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32C3FC559BBA98BULL,
		0x481CC8DFE313631AULL,
		0xA756A3AEC8508A8DULL,
		0x5AFD17A3772F3215ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD3FC0E6AE5A6388ULL,
		0xFEB4B3291389DC33ULL,
		0x04A49E4D44FC0C5AULL,
		0xC2EE3BFC393E5B98ULL,
		0x1AD4D3EF708A7DD6ULL,
		0xD562378947DB24F0ULL,
		0x9DF962ED593B06B2ULL,
		0x7B0D3EF3C84A1873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8D7367162E9141EULL,
		0xAB48F189BE1157D7ULL,
		0x77A94D8883BF0AE6ULL,
		0x06E5942BF43DFCC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE632E755BBC785BDULL,
		0xF51CB628A880B599ULL,
		0xB499A198188A99A5ULL,
		0xC7F08A029D491A6DULL,
		0xEE215BD0840B65D1ULL,
		0xDAAB417589DD6F4BULL,
		0x7F59E7763059E910ULL,
		0xF55019B0645DC078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2688495578A841ULL,
		0x6A886D9B1F5F3ADFULL,
		0x9BF1FD2345E33226ULL,
		0x31D45A318333AC50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B8D3C096985496BULL,
		0x6B1182098C606419ULL,
		0x37C147E3BD7AFEA1ULL,
		0xF869845FF40FE42BULL,
		0x1A60C9979E70E917ULL,
		0x1959C061747EAA52ULL,
		0x31F94181CD2DEB57ULL,
		0x88BDFDD816FD320AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85EB288AEE47E5F3ULL,
		0x2E641080D72DAC49ULL,
		0xA2C10128324BED8FULL,
		0x449D32735DA551AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69C94F959D631654ULL,
		0x6F26ADD0B63FF935ULL,
		0x62F2404E103785F4ULL,
		0xE0794EAFEDFB0D3FULL,
		0xAA25FCBC6C821BECULL,
		0x60E24AC7D5AB37CFULL,
		0x4611ECB0A78E0AC0ULL,
		0x088991816ED4FC8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB6CD38DB8B33BA8ULL,
		0xD0BDC77A6DAA4208ULL,
		0xC99B6286EF4D1E82ULL,
		0x24E4E7E661988A11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D8B464E4A616E22ULL,
		0x7CC9DD759CC464F6ULL,
		0xD6975542E6C7B13EULL,
		0x25E523916AE16C45ULL,
		0x67F78F6641FDBB07ULL,
		0x9CDCE5C823DABB88ULL,
		0x3EA359A76E0ED2D8ULL,
		0x0A03663B947D4A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C4A8F7C160B3165ULL,
		0xC593F92AEF3C3B35ULL,
		0x22D6A41D3CFAFD65ULL,
		0x22665069757A690DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1ED4D983753BB6FULL,
		0x6D06FF6B60093217ULL,
		0x42B0606E11926B0DULL,
		0x7FC3480C9D880E04ULL,
		0xCF32F4659DBB19BCULL,
		0xBC28B2711F6AEF55ULL,
		0xB34A10A335A00A89ULL,
		0xB276A49C19A2ABC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x737D94ADA1199146ULL,
		0x5B117C3609E8B8D4ULL,
		0xDFAED8A80753FB7FULL,
		0x7D5FB7386BAD8DF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A8C6E076912D16CULL,
		0xF7ADE0D76CE4A31BULL,
		0x06238132F3535EF9ULL,
		0xF111440E9E086EBDULL,
		0x109F86AC5CBFDB2AULL,
		0xDE91CAD73E321C09ULL,
		0x93DA14ECB9E75890ULL,
		0xFD0FB2D1E42BDC23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE23A6B9D2D8D5F5FULL,
		0x0151FCCAA854CC73ULL,
		0xF8829C568BAA847BULL,
		0x0165CF367C8B1C04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF665D91BD65D2F2DULL,
		0xD7A8CF103485F8B1ULL,
		0xF41FF00BC6794DDCULL,
		0x9E40EF4D60B4B40BULL,
		0xB7A59131760D4B32ULL,
		0x8E4E075C8DDA2381ULL,
		0xD6DA43DBAADDEB18ULL,
		0x561CE3F4B3EDA21DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F966735C565A87ULL,
		0xF73DE6CD42E73DF3ULL,
		0xD88602A7236A3381ULL,
		0x668AC5A015FAC479ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51D107B60D5EC917ULL,
		0x0E1476F73252EAEEULL,
		0x6A12940EE4EEA374ULL,
		0x37B161E9542F690DULL,
		0x7636FCA4D9372607ULL,
		0x99EB6EE78D50DF3AULL,
		0x2D69C52D89283553ULL,
		0x826574FCC02DC642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDFA882E4B8E7106ULL,
		0xE706ED562C540D9BULL,
		0x27C5D8D140E68DDCULL,
		0x12C0BF6DDAFAD6E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C4088C0AAC45E35ULL,
		0xDD23E1DE5FCFE060ULL,
		0x76ABE7087DF3F697ULL,
		0x4CF034E483B10BECULL,
		0x48157A0069B6E222ULL,
		0x46F7A175B5028BF3ULL,
		0x0DB6D55E2F8926B7ULL,
		0xFEFB16FEAF28AB0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF70A4D05BE9F4E5ULL,
		0x65E5D9573E30A67CULL,
		0x7FCF93038C4FB5CCULL,
		0x26359EB283BA6F6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAF6248964EF9FE8ULL,
		0x96BCAADED44C03C2ULL,
		0x09EC677A37404310ULL,
		0x8CD8D98A085F0D86ULL,
		0xE31FBB5393C3CB5FULL,
		0x421B3A0C5CF65CD7ULL,
		0xD70214D16AA9B99FULL,
		0x6517278EFC9A1254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71ABF2F153FFD24FULL,
		0x66C748B4A0DDCBCEULL,
		0xF43B7E900C71D0B4ULL,
		0x0E48B8C3873DC61DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCADB9B588501FEA7ULL,
		0x8DC3E95F90980146ULL,
		0x758FEE7FD8650333ULL,
		0x1A3F66FE354D9EA9ULL,
		0x628F1370611CD972ULL,
		0x9C6D3BAE8D7A5F1DULL,
		0xB6568D887FB23139ULL,
		0x78CE09626663590FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C187E06EF4A483FULL,
		0xC5FAC54890C21FA3ULL,
		0x8668F0C2CCD851C0ULL,
		0x08D4CB99680CD6FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D8862C3F4F4D78BULL,
		0x60C2BB6AA74A7F5DULL,
		0xAF85150B324786ECULL,
		0xC79384297E16C6FCULL,
		0xD7527285AB18D7CBULL,
		0x12E7EE44F6C7FF66ULL,
		0x1BBFB5188E086DD4ULL,
		0x9C47703FE1746B39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23C5629B5AA4E32AULL,
		0x2F3019A748FA68A1ULL,
		0xCDF9F6B04787D467ULL,
		0x7A2E2DA4F55EB176ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9AF9BD1FCEA5E10ULL,
		0x3B1D5CA6D6192429ULL,
		0x96EF294ED2B28FC4ULL,
		0x51A6443B26A132B3ULL,
		0xA0F36D2A499F5DD2ULL,
		0x68CDD9EA4486F395ULL,
		0xA3AABDE1A8C6EB86ULL,
		0x079A69949696814EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDD1D018EA924B62ULL,
		0xC9ABB56D02214C5FULL,
		0xE24758CDE03985B7ULL,
		0x7291F04980F8645FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07515315C421F418ULL,
		0xD0C3882B4BE5AB77ULL,
		0xFBC0C040AD22B052ULL,
		0xEBA2541D0CD86932ULL,
		0x8B2CC6FBF4B11AA6ULL,
		0xA30770356F1E4918ULL,
		0x2692DEBAB7172CFAULL,
		0x76DC15391D2B187CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFF6DC7C166BEB7BULL,
		0x03DE3019CA64851BULL,
		0xB58DCFF7DA935D87ULL,
		0x104D7A97613E0BA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92A4DDE4BEE009ACULL,
		0x046D4559DA670C04ULL,
		0x991698E21F761B5AULL,
		0x78E4AF5A07DCC09AULL,
		0xCF9B70E19924AA86ULL,
		0xDC1CF64BB586EDF3ULL,
		0xB5FC662815FB3CE9ULL,
		0x95475E541F1C1356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B79F617A515CE7ULL,
		0xB0B9D496CC6E5E35ULL,
		0x9C8DC2D562C12610ULL,
		0x217CAFD6A6079F79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEA8813E9389DB06ULL,
		0x3837DAD4BCA43734ULL,
		0x5F2B7390633CABC9ULL,
		0x9D63B5E1F00214F1ULL,
		0x60A36F8D9CA2A90FULL,
		0x710BDADEFC86877BULL,
		0xBC6E863612598CB6ULL,
		0x15AC68C9E18A8ACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36EB1043D3AEF3C5ULL,
		0xFFFA57EE389C5385ULL,
		0x57935F971C878EDDULL,
		0x54FB43D96A92AFA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE058500E8BC4DD23ULL,
		0x3C3411F8D569AD2AULL,
		0xB7E138260D7FDEE5ULL,
		0x25CF2964A322982AULL,
		0xDECB996AA270FEA6ULL,
		0x53261E2042BD4009ULL,
		0x6FCE4C48F83B4225ULL,
		0x35129A0802BB2647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF29115E2A88AAAF7ULL,
		0x93DC8AC2BD812EA1ULL,
		0x50808AFAE64BB06FULL,
		0x069206950AEA46C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x398C89BB6F065FC3ULL,
		0xB7F963FA5D691B0FULL,
		0xDFC0102D6E79F4E0ULL,
		0xF167BB6C07536F4DULL,
		0xF83EB4B68FF39557ULL,
		0xD1E11A2C8E9E250DULL,
		0x39E76F22D5EFFCE2ULL,
		0x4CB2B76FB1D63424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12DB5CD4CD2E8C75ULL,
		0xDF63469788E29B22ULL,
		0x781A8F5930197E8BULL,
		0x53EEF6006D1F2CAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC25FAD4640B908CAULL,
		0x3C354D7A7D24E2EAULL,
		0x7141B525D853AAB0ULL,
		0x55726D70F659F7A3ULL,
		0xD7632220C13BDC15ULL,
		0xADA7AC910F89E5F2ULL,
		0xD85E89DBDB5E98A2ULL,
		0xFDBD9447FE038ABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB16BE22EF9BB979ULL,
		0x0318EB02CB9D04F6ULL,
		0x8F4A2BC8685E52D6ULL,
		0x7F967020AAE08F5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AC1EDF5477F0517ULL,
		0x5D80C864BF7E2B31ULL,
		0x23A57C2D586B5124ULL,
		0xF9D97490A5C5E0E4ULL,
		0xB81B621E040836CCULL,
		0x9A56C4F8175BD0DAULL,
		0xECC02B4AC6BC0901ULL,
		0x936B8CFB0AC9AAEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED27E69E0B72AB6ULL,
		0x46620538371F2BA8ULL,
		0x482BE946D854A761ULL,
		0x5BD061D43FB54081ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8348ECF92BF84C43ULL,
		0xC08D1E4E1ACF9306ULL,
		0x4A68AA4B9ADA3D8AULL,
		0x1EB07D8B5DF6652CULL,
		0x1CA553E88E149B1DULL,
		0x4E0217578AE4E070ULL,
		0x8C44F32A69D5C288ULL,
		0xD06607BEEBA307EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3D3617E4307572BULL,
		0x54DC954CB8C8E3AAULL,
		0x1CA4C29750951DC6ULL,
		0x0DD5A3E2582991FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71286D3EAE38511EULL,
		0x1D1EC5D1FFB19637ULL,
		0xC3896E72566B8538ULL,
		0x376207F6B4C15506ULL,
		0x4003C82820EE66A4ULL,
		0x971B56975FF8295BULL,
		0x5588FF4C116F0A26ULL,
		0x21293D4013ED0A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B82333919B8E34ULL,
		0x8B2DA04A3E87B9C2ULL,
		0x75DF53BCECE706F2ULL,
		0x23811F79A9F0D9FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB51EEC5C2C61C63FULL,
		0x43EE96EC83F767FFULL,
		0xA2112D330F715A63ULL,
		0x8B00E63B64E45EF3ULL,
		0x2E77C8FD3B57AD06ULL,
		0x0B7FE1031FEC18F3ULL,
		0x14D7F996398D8738ULL,
		0x59A4CCA9BAC5EF62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AE6C1F2FB657724ULL,
		0xF8E9FD6341031C18ULL,
		0xBA20397F9A736CB4ULL,
		0x5977476D1E45E782ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99AD6C69B204C6F3ULL,
		0xAD48D79C228A4CE9ULL,
		0x428A1107D1FE87F8ULL,
		0xCF88FA81E6797B7BULL,
		0xE721EB8EF87848B6ULL,
		0xD9849A28BCBAD28EULL,
		0x2D15290EF972F268ULL,
		0x03CDEDE25C06D59FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B663A293DF921DULL,
		0xF6F7B9A826458E1FULL,
		0xF3AE2940D90E8388ULL,
		0x601A4A1B8F7D311BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A3576E01669D883ULL,
		0x07B73BD5AA5C921CULL,
		0x3630534D0B3522B3ULL,
		0xE411E79C0D89B762ULL,
		0x3ABEA69015E893B7ULL,
		0xD6F285D28E0EBAB1ULL,
		0xDCB3A593EC7C80BAULL,
		0x6FEBAA16A10C8DD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4282304356EFC846ULL,
		0xEFB71916C08C486BULL,
		0xF8DAE74225B03E6EULL,
		0x010D26F7F566C4FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94CDE28D53E7FE2EULL,
		0x228D6D72C30162E2ULL,
		0xA00F8B763F9D4968ULL,
		0x040C50E32F5042C7ULL,
		0x83036DAE67EB0EC5ULL,
		0x5BBFEF45E168CE33ULL,
		0xD55BD0914082B15AULL,
		0xB506DED5E9C46DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07502A70C0CC335BULL,
		0xC10AF1D2388FFE88ULL,
		0x4BB08105D3039CD1ULL,
		0x631164A3E27893A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x384547AF932CB021ULL,
		0x531C27EB66189C59ULL,
		0x89CDC201FCB56978ULL,
		0xB58609356776744BULL,
		0x2A35927BFA1CBC75ULL,
		0x064AC63D84E5A643ULL,
		0x86AAB8082033554FULL,
		0xC229DD9330EB064DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C390616B370ADE0ULL,
		0x4235950D202F4A51ULL,
		0x87251336C4541333ULL,
		0x07BCED0EAA5963CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41DCFEA47EF1AAFBULL,
		0xDC1206F5A1A36EE0ULL,
		0x91069767A8376F22ULL,
		0x5F9BE9D4796D3CD8ULL,
		0xBDD53A5A129431C9ULL,
		0x456C2D23B1CC9FC5ULL,
		0x156F554AD07B244EULL,
		0xB9B43703CA6CB8E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F83A80340F112E6ULL,
		0x2A20BA420603263AULL,
		0xBF8D40829A7ED2C1ULL,
		0x705C14648590AF25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x457F6B5AD30C14CEULL,
		0x899B58DF9CD0C84DULL,
		0x1665D1FAB3C2DE8BULL,
		0x217FFA72F9EB091CULL,
		0xB4EB5019F94CDA1AULL,
		0x9152FDC7CA53987DULL,
		0xC334E4D5F5F04802ULL,
		0x9AB8768EA38E1C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206D4F35D4747814ULL,
		0x1BED0487A5396AF6ULL,
		0x103FC9BD356D8EEDULL,
		0x18E1939F41033DFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D67DB6FCBAC87E1ULL,
		0x36FB6E57B8D437B7ULL,
		0xDC952A0103BEFD25ULL,
		0x8FA69D5262C04C1BULL,
		0x3EB57E1F7D2F4BBFULL,
		0xA39D9999974F6153ULL,
		0x45865645EE2D9E89ULL,
		0x8FF4FF247D964691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC58941C60B1C96CULL,
		0x80603B242E9CAA12ULL,
		0x2E85F8625E848593ULL,
		0x6E047CBD070EC5ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB952709D825AF9A9ULL,
		0x4A701C126501BF0FULL,
		0x63FD54A125B27060ULL,
		0xE709A29A362D344BULL,
		0x871FE6F3AFBA5A14ULL,
		0x451BD4EFBCFB4F43ULL,
		0x33D9279EF92FD290ULL,
		0x55AECE060B99396AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC80EB8C998045AA2ULL,
		0x8C91B7A8724F8315ULL,
		0x1639363A22CBB1CAULL,
		0x1EFC377FEEEBBA0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFF6BB993690DFB8ULL,
		0xD77B5E5165889170ULL,
		0x7CD57D86E477354AULL,
		0xB4F781436C4B0D38ULL,
		0x7B2EA4FF3AF26E14ULL,
		0xD4C424A78E91A49FULL,
		0xED796426DE416A25ULL,
		0x8C83AB0C23937A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E3397BF68D39E1ULL,
		0x6C98CF308F27011DULL,
		0xBCDA5B4BE22CF6E8ULL,
		0x1082E510B42F353BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DFFC0AAC8987236ULL,
		0x12EB288B0F25C487ULL,
		0x5BC1E0EF9A451257ULL,
		0x0D7BDEF9883FD029ULL,
		0x268EA73552C49495ULL,
		0x165B989743149D65ULL,
		0xB09786ABFFBF0B42ULL,
		0x4E93160E32D50DD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072C929511C68209ULL,
		0x6483CEFF0435218BULL,
		0x923FDE7790A0BE26ULL,
		0x3751251513DFDDE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF9EE894703CF1D7ULL,
		0x1FCC4749734896B9ULL,
		0x1D1DC5AB83AFD325ULL,
		0xEC143804AE685516ULL,
		0x894280EECBEE8494ULL,
		0xB4FB1BAAFA3409F3ULL,
		0x73F16D65A78A104CULL,
		0x342745895A25BE2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F7E0C06B5A4A112ULL,
		0xFD1262AA970210E0ULL,
		0x52F402C2622E3E87ULL,
		0x29E88A6810029021ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02AE78B92DC5082FULL,
		0x811C15413C82CBCAULL,
		0x08C0BF5D95FF8F30ULL,
		0x821BB6C120E29A9BULL,
		0x931919ADC6FE3C1BULL,
		0x866D2EDD904CE305ULL,
		0xB97A446A55278289ULL,
		0xB4CB7AE0AFAF09E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8684884B781F833ULL,
		0x75510A24A7EC7E9DULL,
		0x90E6E72639DCEF9AULL,
		0x584FF41B34DE1242ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB04B81D390F7D548ULL,
		0x899AC56CD07D9DB7ULL,
		0x32D782ACE0A377F4ULL,
		0x0AAA9B3F82C89860ULL,
		0xFB20DB33E49E70CDULL,
		0xB49A60F7A8AFD9CEULL,
		0x178196668B22FBA2ULL,
		0x91C82DAE4BEDA70AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF72C0B87807C96E7ULL,
		0x58852A2FDA97F270ULL,
		0xB013D5E587D4D21BULL,
		0x2E61631EC80F63DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0090BA28A3C3CE28ULL,
		0x772F7CB1E449821CULL,
		0xE997D469C12F3FA9ULL,
		0x731AFF9847514C84ULL,
		0x43E4FCE528D977C5ULL,
		0xC5C3A1721C055A31ULL,
		0xEEC72B23C771F745ULL,
		0x700985A6AAB53ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x148E442CB40B97ECULL,
		0xD23973A20D14E56CULL,
		0x5B283BB95C19F404ULL,
		0x1484D6559E389F16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E56F77A3CEEE2C1ULL,
		0xB29B741AEA9E8C9CULL,
		0x19EC274DA67A0633ULL,
		0xA4273F6D6809897CULL,
		0x8110FE7F8CC654A5ULL,
		0x50EC0145CCA699C6ULL,
		0xD75A4C1E309BC940ULL,
		0x6A80F71B04D76259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66DCBE69225F759FULL,
		0xB5A3A4774B596013ULL,
		0x115373C8DD99E5BFULL,
		0x734BED70200222D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x244BE6EDE08770B7ULL,
		0xF09B4384AC84A172ULL,
		0x193EC1EF1EDB9020ULL,
		0xEB4A821F268C92B1ULL,
		0xA83A9044EDB98ECBULL,
		0x9A57D06FBA93305DULL,
		0x812641423EA994D5ULL,
		0x00343F0E6070346AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CFD51292A12A2ECULL,
		0xD9A4341A5E5DCF59ULL,
		0x44EC71C46C07A7D5ULL,
		0x730BDE4177345A80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9D55D379DA31BB2ULL,
		0x14FE34A2F816B39EULL,
		0x0B6576ED98D60A54ULL,
		0x7164EC7FD9BDA688ULL,
		0x4CA9B1A7000B075BULL,
		0xAF215ABD4EACAC64ULL,
		0xC2B286FB9D326B3BULL,
		0x461059FB6326CA11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B05BC019F4634C3ULL,
		0x13F1ACBCA5B84A82ULL,
		0xF1E58046EE51F530ULL,
		0x57D247D0917FA52AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FF407A643E740CBULL,
		0x0ADB762A2012F3FFULL,
		0x153AF14C1A7C1BA1ULL,
		0xE3DF0927048C0B24ULL,
		0xE9F87D0EDA0905FEULL,
		0xF12A82FFBB47C45EULL,
		0xDC21B3A148B671E4ULL,
		0xAF947A69D4DC95EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD697DAA13E286EULL,
		0xD72AE81FECBA1A16ULL,
		0xC23B9B3CE591039CULL,
		0x73E934DC9D4A4C00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51A70D8A72A8A372ULL,
		0xCE661A62C39177F8ULL,
		0x87C6CC1995DC0E14ULL,
		0x3D58AE568E857001ULL,
		0x0719AB57ADA68B5CULL,
		0x9614BCF18A803D64ULL,
		0xAE8287CA9F755421ULL,
		0x51BA43AA7360A1B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F767C8E396154E2ULL,
		0x157A263D529A94D1ULL,
		0x6F26F42D41468B11ULL,
		0x5EFEB9A3AEDD7061ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87E00EEE2A33B30BULL,
		0x65A4FCE30DB1CAE1ULL,
		0x8402BD0EA9CDF9C5ULL,
		0xA41252C362C41A35ULL,
		0xA37CCECF5FC5D956ULL,
		0xB7ADD9CF4BDB492DULL,
		0x2D3B52AA42E43214ULL,
		0xDF02406A1DA76067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC66C1B66191FAC8ULL,
		0xA97351A8503EA7A7ULL,
		0x3AD1025497AD68D8ULL,
		0x3E67E283C99C6986ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A95825A5425FC69ULL,
		0xF1E7C687F6CB1707ULL,
		0xE9C4BB8994C800ACULL,
		0x1E9D518436BFB8B8ULL,
		0xF3A61DC518943095ULL,
		0x9DD728317DC493B7ULL,
		0x1E8B88FB48119487ULL,
		0x9689787D54831557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x453DED9BFA2535CBULL,
		0x5FD7BDE0A1F90455ULL,
		0x727B10D647640CCEULL,
		0x7705341EC234E3A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13860984417E9160ULL,
		0x747A5C77BF8285EEULL,
		0x5C42F8001100631DULL,
		0x994E981DDA3D41EDULL,
		0xDB9547A7F972B387ULL,
		0x1D6E00DCFB2727E8ULL,
		0x4DD13C942BA9041AULL,
		0xEDE8A3354F427430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABAEAC7348853CAFULL,
		0xD2CE7D450752727EULL,
		0xE951F5FE8C16FEFDULL,
		0x69D6D2079E1A8118ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0248709F15ABFCC3ULL,
		0x10FE7882BA34B41DULL,
		0xA1262A81E8DDC49CULL,
		0x9A458DDE86443B30ULL,
		0xDEDCE96F3211845BULL,
		0xE55A25A04BA66879ULL,
		0xA1AB84EB13C2BCB2ULL,
		0x125C2C025431962AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171317208445A2B7ULL,
		0x1C600E4DF4E83634ULL,
		0xA09BE566D7C5C72AULL,
		0x53F4163705A08584ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05D9C936EFE19DE1ULL,
		0x1D8BEEDCBCD5C120ULL,
		0x0776AC59E8248E19ULL,
		0x3816A26690389F7DULL,
		0xCAECA72AA4ED12B9ULL,
		0x4BD32855113978E7ULL,
		0x49B581E0C5C29054ULL,
		0x35FC22909A6828E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24FA998B6B126687ULL,
		0x5EE3EB7D4B5DB388ULL,
		0xF867F3B74305FA9CULL,
		0x3B83C3DD7BAEB21DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C717C3CEF3E77E0ULL,
		0xBC176EE85E5009BCULL,
		0x210582E3FB013062ULL,
		0xE49F870E9E8000F6ULL,
		0xA8250B1CA5147EEBULL,
		0x393D5BCA8DF7C818ULL,
		0xCD2FA11C26EA3994ULL,
		0x62AE23E5FC04CD35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51F1227D7049510FULL,
		0x3B330EF97117BD65ULL,
		0x96176D11C1C5BC63ULL,
		0x0A78DB32073676F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DB871A9BE055602ULL,
		0xD1D0F503114F772BULL,
		0x180B0160A9580084ULL,
		0xA6CD3DEBA5E8996BULL,
		0x4FEC0964364DC17DULL,
		0x23006CF7FDE41CFBULL,
		0x335054B22C9397CEULL,
		0xC06BC4A0199B53CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAC1D689CD9012DEULL,
		0x03E121D2C12BC478ULL,
		0xB5F793D34740891EULL,
		0x36CC6DAF72F709BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07E36941C253229EULL,
		0xBE1AD9AF4E565DD9ULL,
		0xE68F2576F4392C41ULL,
		0x999FB1286996A45EULL,
		0x3B286DB081E9AA03ULL,
		0x7277821400BB1AA1ULL,
		0xF7FCBED87EBE8F1AULL,
		0xD788611AF7610FE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFE3B1750B0263E3ULL,
		0xBBD828A76A1C51C7ULL,
		0xB6137999C4826A2EULL,
		0x17DE1B2921FEFFE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF72E77F492E81EE5ULL,
		0x99C0ED9FA8DAF38EULL,
		0xE0EC93C942280D73ULL,
		0x2C881B06676FF307ULL,
		0x5D786BEC2CB2B2C8ULL,
		0x4C158914EBFE319FULL,
		0x3B31F607FBF656DAULL,
		0xEE435055D5AE9237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD70E7D03356EADDAULL,
		0xE4F346BAB0965136ULL,
		0xAA5718F8A8B8F1DAULL,
		0x0A8607C41F59A73AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2D0E9C3525B6F10ULL,
		0x8F8A1EE50C10DE99ULL,
		0x11904B123F8E6C36ULL,
		0x9E9D37D9039C64F2ULL,
		0xBD58353B51DF0703ULL,
		0x57EF9A3D52CA6233ULL,
		0x152DE5118FA202DFULL,
		0xE0BF5BC1BA68C614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DE8D09179767E7BULL,
		0x9D1B03FF561B7248ULL,
		0x36604BAD919AD95DULL,
		0x7B04D69AAF29CBEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4E93658F45D28B6ULL,
		0xEC6FAFC9A488EB1DULL,
		0x65FBA72FFC3A56E0ULL,
		0x636CA9413A6A8E4BULL,
		0x9BF68140479CA85FULL,
		0xAC70A6AF306625AEULL,
		0xEF56327ECA86A6E4ULL,
		0x0543596C1CDD0143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B8065E3959E26F6ULL,
		0x85286DCAD3B28309ULL,
		0xECC726020C371CD2ULL,
		0x2B6BEF4D8338BE60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80E49441FF575338ULL,
		0xD0FB076777C5451AULL,
		0x93D1B0999702D558ULL,
		0x7798B3691DF41691ULL,
		0xBA252FEE64F67803ULL,
		0x6119C614A153E9D4ULL,
		0x560EA4440087278EULL,
		0x77F5D7787596659BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2269B1A4FBED2656ULL,
		0x3ACE6E776A39FAAEULL,
		0x59FE12B1AB12B47BULL,
		0x4616AF4A92472BA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB86BD58CC96C2F0FULL,
		0x5F185FF7129FB2F4ULL,
		0x37222B42F1BD8E99ULL,
		0xD7D6461839716A95ULL,
		0x45B6868EC9D234E4ULL,
		0x4607EEEDE0401AC7ULL,
		0x2A8C453374E3B2D7ULL,
		0xC38D8D0A1796E501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1183CEBEBEA00D48ULL,
		0xC445D7465C23AC89ULL,
		0x87F470E64B8A1A8DULL,
		0x5ED93597B9D768C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34E4836A4139DA1ULL,
		0xFB4ED61F153693B2ULL,
		0x3C47FDB5E72ADF46ULL,
		0x7D0786F6C154AC65ULL,
		0x162D02B196AAFE67ULL,
		0x8F71153CF1F65500ULL,
		0x1E75936D3A9D1662ULL,
		0x39265F3463349B1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DFCAE930175622EULL,
		0x4617FD2AFFC731B6ULL,
		0xC1BBDFEC9A7C31E8ULL,
		0x78B9A8BD7B23B303ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE5CE4DDF4C773FEULL,
		0xBB703D64C955C393ULL,
		0xD4A64FA8B1B2909DULL,
		0x9963F332A8A26178ULL,
		0x4FECEFE3910C2418ULL,
		0xC0AC5E009FEDDE16ULL,
		0x7531ABB6594B342FULL,
		0xF983A9BF2F9B486AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB8880A57C94D51FULL,
		0x5506317C86A4BAE3ULL,
		0x3A05CCB9F2DC4FB4ULL,
		0x22EF2593B9AF2146ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31F88828E29AFBEAULL,
		0x0700DABBA2CA16AAULL,
		0x305F3BB12D95F329ULL,
		0xA0B3CF5FD3CDFB1BULL,
		0x2947484E29C97C76ULL,
		0x9D13AEC7CA4D0E05ULL,
		0xA9213093C48DEBA0ULL,
		0xA716152274BC5AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528D43C316837924ULL,
		0x57ECCC63AA3A2B6EULL,
		0x4B4C71A05AA6ED00ULL,
		0x6DFAF27D27C37238ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03C53B71EE57ED67ULL,
		0x3001B66971E5BA6DULL,
		0x1B7F0D5B3BE25DB6ULL,
		0x98E2FE4B6F6A1309ULL,
		0x0ABE0B02EA46A2C4ULL,
		0xC557895912CCF28BULL,
		0x14E3283E082EB2BDULL,
		0x53FFE158B7F60363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFADDE0B4D4186DULL,
		0x7B0019A23C51BB10ULL,
		0x3537069072D0E5E1ULL,
		0x10DE7176BDEE93BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD3F027CF28888DEULL,
		0xAC419227CCBD0516ULL,
		0x114B93AAA4721139ULL,
		0x72C19A5746E579D7ULL,
		0xA1B996A22444B1F9ULL,
		0xDDE44E98A7A1950CULL,
		0x2F227A109E9ABDA3ULL,
		0x8FF082F61E179E29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDECB5E8E54BAF705ULL,
		0x9C253CD0AEB924F6ULL,
		0x1069B2222F6A378CULL,
		0x50750ADFBE66F3F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6338CE8C2D22C273ULL,
		0x82046649A78990F5ULL,
		0x6DE244F6673B5AC6ULL,
		0x65A49FF6D4F1D015ULL,
		0x34E7A058495A8E8FULL,
		0xCD5A67E3FF808B22ULL,
		0x96A4CFA3C2C40CFEULL,
		0x4A06E9BFB20FCC27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D9A9BA71093ED4FULL,
		0xFD6FD221949E3809ULL,
		0xCA59174550554898ULL,
		0x62AB526B434A1DF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4D4090E194144D9ULL,
		0x9AF98B8E41F65959ULL,
		0x9442685DF91C9A7CULL,
		0x7BF1403EF0CB0362ULL,
		0xE47C51CDA311CE9FULL,
		0x94ACC2E815A53FAEULL,
		0x9556AF50FE94E821ULL,
		0x5501999E1FED0F1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF482D944DE5F261ULL,
		0xAC9E7A01787DCD4FULL,
		0xBF206E63C3370F78ULL,
		0x1A2E0DB7ADFB41ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C1E169F6D3CF9D0ULL,
		0x01A4B4A0DAD69755ULL,
		0x80D53E36DC540C40ULL,
		0x0A4C3B154B76CFDBULL,
		0xD03792CC75E2E2B9ULL,
		0x8F4384240B3570F1ULL,
		0x6FB5A9E9E3A156DBULL,
		0xBF1EECA8F0571FA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745DE0F8ECEAA56EULL,
		0x45AA51FA84C55B3AULL,
		0x15CC76EEA646F0D7ULL,
		0x68E35C28F865821EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5FF385054DC0B6EULL,
		0x878CBE5636A1BD47ULL,
		0xC4B2A560A95EA887ULL,
		0x495B8C76481C2F62ULL,
		0xB4E0465330276903ULL,
		0x59DC889CDD9034D5ULL,
		0x697017D802B4A748ULL,
		0x819A5078E61306FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F49A8A97AB5A4C5ULL,
		0xDE49059F1A099500ULL,
		0x6B562F71102F7D44ULL,
		0x06437E686EEF38B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02B19304CFD73E8DULL,
		0x0B5F9A0FA3FA9AAEULL,
		0xA2A364107A0B2D0EULL,
		0x0000FBA60E794DC8ULL,
		0x90F38D94212989C6ULL,
		0xE91F8F9E2E9D8FD6ULL,
		0xD1FF855B3B9B043EULL,
		0x56AFDA30C18C63F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D89701BC01B3CCULL,
		0xA60EEB8A8F5DF487ULL,
		0xCE912F9B530DCE64ULL,
		0x5E1B5EE2C95023ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BEFA6882CE3EFE5ULL,
		0x8F9B1343A9C41122ULL,
		0xBBD3756B4BD5FE72ULL,
		0x6343D3B552CC2E9EULL,
		0x07152FA45ADDA83AULL,
		0x7E0CD29616FEEA9FULL,
		0xEBFF21CC89DF1C4BULL,
		0x42A39AFC0ED51EBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6914B8EDA9CAE9FDULL,
		0x4582558B139AE4BDULL,
		0xC3B279C7C2F431A7ULL,
		0x478CD51F866EBF1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1186BAE2A59DAA94ULL,
		0xE81031BB3C122852ULL,
		0x6DC19D87D58B2E13ULL,
		0x55713F04A4C39B32ULL,
		0x8FD1977E4B484FD4ULL,
		0x0BB2F235D0DC8791ULL,
		0x4A77631412C52F44ULL,
		0x578E65A9A37E2512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA337A1D25985FAULL,
		0xA4A025B83CCE47EDULL,
		0x7B7A52829ED0322DULL,
		0x54945632E97D1BE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C04DBC03BF54E5DULL,
		0xA552004437AF3182ULL,
		0x07664E48C2BE5626ULL,
		0x6D84A99D8AE5C1B6ULL,
		0x3A5FD24F1CF19049ULL,
		0xC7C4E2B9CAEFB43DULL,
		0xAD39FDD4CF835C8BULL,
		0x49312FE6FE5DC1D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB63E137E87D0BAD5ULL,
		0x4C8BA7D85743F298ULL,
		0xBE01FBDF903E12E6ULL,
		0x4AD1C5E74CD0876DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF519FCB01A4A46CEULL,
		0x2D71186DA7A7DF91ULL,
		0x8C10628B08BDEB62ULL,
		0xFC18CFC33992C081ULL,
		0xA57ECFD63D8B28F8ULL,
		0x95ACB1FAA275DE4FULL,
		0xF4244E24D0E4C948ULL,
		0x2BB671141CE38278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85ECD67D3CF25CA8ULL,
		0x651383A1C526DF64ULL,
		0xC973FC020AB3CC28ULL,
		0x792D98BF83581E75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AF8F1F4689F6A93ULL,
		0x76CE01D998516873ULL,
		0xBE1A55995BE7D5B3ULL,
		0x2F847C5998738235ULL,
		0x98A437670C755F23ULL,
		0x517CF8763E123CA7ULL,
		0xC809A7B9FFC3F57EULL,
		0x30E078F39A050497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43592B40420B8ACFULL,
		0x8F5AE366CF066954ULL,
		0x6F893B3552FE4673ULL,
		0x70D67082753230BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA093C902F2DC009ULL,
		0xE2BC10C2AC688E60ULL,
		0x522FB39163DDAB6DULL,
		0xB76B897F30ECD43CULL,
		0x30013D44DF01C812ULL,
		0x4D13F085567CADBEULL,
		0xBA16967BD14E3BF7ULL,
		0x691B1C333AD178C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA3854C949717515ULL,
		0x53B1C48D82EA589BULL,
		0xF18A09F2757A9223ULL,
		0x5171B919EC04C0D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9470D4B796CCFAAAULL,
		0x28C9629DD1FFCCB1ULL,
		0xFD24F1C2917D7EC6ULL,
		0xE9495E45B26650F1ULL,
		0x8455C02D7BC75B9CULL,
		0x4CB7F63FE0B3A4D6ULL,
		0x92B015C328D7BCEDULL,
		0x5D9DCF08F7358B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x392B5B77F66495F9ULL,
		0x8C17F0192CAA4489ULL,
		0xC3482CBAA18389FFULL,
		0x4EB6199A6458FF33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FFDE4DAB2082720ULL,
		0xB5D6A6A93A9C3E9DULL,
		0x04656C023FDD3948ULL,
		0x0CE432809D842981ULL,
		0xB43D63E3520363DBULL,
		0x0370EDDE08226431ULL,
		0x6185138A34ED2D53ULL,
		0x1A1EB7571FE63BB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11AB898DE88FA27ULL,
		0x3899F59E6FB71DFDULL,
		0x7E2652861B11F39BULL,
		0x6D73696F59B1066DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18E0A71AF5F5FDBBULL,
		0x111381963A38A02AULL,
		0xE2939A4517FBC272ULL,
		0x1D2985F41F229155ULL,
		0xD121AF643E9D7E2AULL,
		0x8BD0F4B5CFBC632BULL,
		0x4479C9F7B693AB72ULL,
		0xF14C23ACF96D98D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23E0AFFC4156BD3CULL,
		0xD217D493102F58ABULL,
		0x0CA7950A31E73572ULL,
		0x6E76D1A1256740B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1ACC85A5085E359ULL,
		0xF3DC2722B0C5BE3EULL,
		0x9B24227E1772E59BULL,
		0xF89621588E49B999ULL,
		0xA3376D56752E6CF8ULL,
		0x8AA65F0CECC01A4EULL,
		0x41EDF748F7E9ED91ULL,
		0x40A9EB099716D5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE7032FB56A11B8ULL,
		0x888E430DD549A5EBULL,
		0x6476D752E42C2936ULL,
		0x11CF04C4FBAD778DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x784062B3A6584AD3ULL,
		0x0524BCB1034517D2ULL,
		0x0B48B15E933B3FBAULL,
		0x1C06410312898DBDULL,
		0xF24034117A8720E2ULL,
		0x2D2ADF54316F4F51ULL,
		0x09F7AA8A96E3E1A3ULL,
		0x2DB203DC5BBB54FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DC81D4BD6672D56ULL,
		0xB981E33059CADDFCULL,
		0x860C01F0F90EBDF2ULL,
		0x6472D3B8B0582B98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CC1BD415BAEF959ULL,
		0x52AAA8A3CCE33EB8ULL,
		0x07BF3430C1328D86ULL,
		0x27926C7B9E360176ULL,
		0xC07174E412335952ULL,
		0xD15E70A5E4E082C8ULL,
		0xD5587A9575A72205ULL,
		0x9105CBB968CA5292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED99171C0F4E3EB6ULL,
		0x66AF6143C636A884ULL,
		0xB2E1666038019A63ULL,
		0x2E6EAA012C3E4341ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC6369478B4F3AE8ULL,
		0x3964BE4BE8B92E10ULL,
		0x391662EA167FD229ULL,
		0xE18B292076AACF39ULL,
		0x316C774BAADA2616ULL,
		0x470CC4B692BC7D72ULL,
		0xB8E72633B22CC2ECULL,
		0x18930B2CB39CCD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427D1E82E7B0E2D7ULL,
		0xC549F165B0B3CD04ULL,
		0xAB660E968924C13BULL,
		0x075ED1C31FF148C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1749EDE9E8550BF9ULL,
		0x2BB1FCAD5FDFEF2EULL,
		0x146D66F83281FD5BULL,
		0xE9052B6840032C02ULL,
		0x22FB9D861FFE9B41ULL,
		0xB277B6EA9F0ACCD7ULL,
		0xED1537114FC001FAULL,
		0xE32B43C2965089B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A34FD2A8201CBEULL,
		0xA9772380FB7A571DULL,
		0x4593938A09024891ULL,
		0x21713A4A8FF79C91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDC49497AE51A45DULL,
		0xD49A92E40C6753CCULL,
		0x29D115E40D82C992ULL,
		0x03DC28CEDDC8EB3FULL,
		0xD2BCFA05DBA4C787ULL,
		0x9A36F9A43CC64307ULL,
		0x420A6FC5FE05DBF4ULL,
		0xC2952575B1787DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15D1B17648C746A2ULL,
		0xB8C3A14511D546F6ULL,
		0xF75DAD47C2616FE1ULL,
		0x65FFB84735AB9660ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C08DC8681593A1DULL,
		0x61B623A60476C374ULL,
		0x60E72BF61B7863E0ULL,
		0x747AAE7C7203D2F6ULL,
		0x5AB0DA4C4DDC91C1ULL,
		0x36D7944DCAC3DC1BULL,
		0x27C949E9A4E5064FULL,
		0x0688621D31517326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124943DA1016DCE9ULL,
		0x85B627321D896F84ULL,
		0x48C824A4957753A2ULL,
		0x6CB93ED1C41AEAA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF2A52C8B6C00E32ULL,
		0x9A56E26E7383ABA6ULL,
		0x43F40CD632714E93ULL,
		0x3B0F86D96A378AF7ULL,
		0x91F63E5FE57BD48EULL,
		0xCD3D6965A96B6BB4ULL,
		0x38ED7ABA436119F2ULL,
		0x69340CDFFF326A98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69B79504C7219D93ULL,
		0x117487859975A874ULL,
		0xB734447C32DB289EULL,
		0x58C970194BB35D8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E9F65FF383E072AULL,
		0x395339479C920F38ULL,
		0x2D9A971CEDEFC671ULL,
		0x61541309CFE07651ULL,
		0xF1B450225F420FC9ULL,
		0xC9C3D66B0A7024FBULL,
		0x7A7680FD468544C4ULL,
		0x86AEF185CA088875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF634B195C0C61F8ULL,
		0x2C650D2B29378C9DULL,
		0x5B31BCB565B7FBA7ULL,
		0x5F4BECE5CD24B7C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x355E09D993742802ULL,
		0xED85D872FC0B1C0FULL,
		0xC61F9CD1DB6FD219ULL,
		0x0D98D201AB82782DULL,
		0x857A61A720889A1CULL,
		0x429FF7E17C45FFE3ULL,
		0xEF1B4315E7E1120FULL,
		0xA51B8215416C54DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058888A867BB0BCDULL,
		0xD144A3EB6E6F17D5ULL,
		0x442B921246D8805DULL,
		0x0FAE2129619710F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53015F9E8024ACF4ULL,
		0xC0110C53A5206E9DULL,
		0x2B68AAB098B5D412ULL,
		0xDE0580FD6072415FULL,
		0x1999C72998D00F0BULL,
		0xC50A8231B2AE6EBCULL,
		0x9E0D17B185C9137FULL,
		0xF98AC68A0C12F1CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD4EFCB2F06EE27ULL,
		0xFFA05FB42B04DE89ULL,
		0xA15A2F0A748EB909ULL,
		0x689EF97B2B422630ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90035577F3C8702CULL,
		0x2FFA8AEF09119D6EULL,
		0xB895F79201C71351ULL,
		0x55E667E836300BD2ULL,
		0xCE5F2CA245C1043AULL,
		0x9918AFF0810AD145ULL,
		0x0C46715B528E7D1DULL,
		0x4E83AAAF772AB6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3223F58E4E6F127DULL,
		0xE9A4A8A230ACADCBULL,
		0x8B0ACB2042EDA5B5ULL,
		0x7D71BDF3E687334EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC817838ED392F81BULL,
		0xD8FA924D692F3B92ULL,
		0xD79143F56D2519BDULL,
		0xF7A19C498C2B5F82ULL,
		0x474B468901F54DE5ULL,
		0x6420AA8D7543C76BULL,
		0xAD15396627C86EBCULL,
		0x7B0A17E22D7B7F32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D43FBE51DFC8AEBULL,
		0xB5D3E34CD13ED57FULL,
		0x88B7C91F54E589B4ULL,
		0x3B2127DC4C804108ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49421EE9E3281B82ULL,
		0x5EB023CA9A9B8A0DULL,
		0x76F8CF523825741AULL,
		0x2F09C6F0A6E6E70EULL,
		0x48A8F5F6C20A9AECULL,
		0x74069A792A7B42B2ULL,
		0x5E0E505BC5DA9FE9ULL,
		0x7EE5C5A3B6292D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1256A18AB0BB1D5CULL,
		0x97AB11C6E8E77084ULL,
		0x6D18BCF1969930C1ULL,
		0x05251D3DB1039860ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97D5B55B1F3E673AULL,
		0x3D5FD401CF7EAA3DULL,
		0x8FF8C22C32D3B2E6ULL,
		0xB727E1BBAD7D5FA4ULL,
		0x2060CBDD31EC65F1ULL,
		0x9BFC12560627D1F0ULL,
		0x086C9639ADB846A6ULL,
		0x165D285A52D1AA24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6633F83088558998ULL,
		0x64CA8CC6B967D3E2ULL,
		0xD0170EBBFC2E2FA1ULL,
		0x08FBDF23F89CA0FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D6206DFADBDC483ULL,
		0x45FDF5CFF21AFB92ULL,
		0x1BE204DC90FFA4ACULL,
		0xF4F103BAD56189B2ULL,
		0x5FFCC3504205649DULL,
		0x3720FB117A3AB1C4ULL,
		0xBF1D6A63D31505A8ULL,
		0xFCBAF23FABB01A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE704C97A8AB975ULL,
		0x74E33A6816D15EB8ULL,
		0x7A3FCFADE61E7BA4ULL,
		0x78B0F92E518571AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x873B9D189EFA9832ULL,
		0xE5D4B26D47A4661AULL,
		0xEEBFF42C93C121F3ULL,
		0x2ACFB68A15A92CDCULL,
		0xD17CFCED3D9FDB87ULL,
		0x03A0F5249C2921BFULL,
		0x1D083C3C9A9B86F3ULL,
		0x12362C387F774611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC9284FC4B52E9BULL,
		0x6FB915DC75BF6893ULL,
		0x3DF8E52B86D72A06ULL,
		0x5EDA46ED015D9367ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x537CC5E99666B76BULL,
		0xD1B96122ACE63A28ULL,
		0x079794BA37BF6191ULL,
		0xC8AFD541E28EB4FCULL,
		0x067E8A17A6F78EC5ULL,
		0x3ABFAC2456FD0EE4ULL,
		0x7D400DFE61252F4CULL,
		0xDE3476DC473265A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A45456C5F25EDA2ULL,
		0x8A2CEE8796767001ULL,
		0x9F19A87CA34466E2ULL,
		0x447979F47409CBD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1104515E902EBF74ULL,
		0x10C7BCD8C372D038ULL,
		0xFD14B66A87983AABULL,
		0x96B87C0370A969A5ULL,
		0xE42285CA9CB168F5ULL,
		0xA55C6FFEF86001D1ULL,
		0xA626C363B835B216ULL,
		0x55795CFE9D965910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE242D71D28455C0ULL,
		0x9C805CB1A1B3155FULL,
		0xA6D5B737DF90AA07ULL,
		0x46BC49CED4FAA21EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE274AE1B34784C48ULL,
		0xFD45812A1BA175B8ULL,
		0x7B783966F13A7D24ULL,
		0x6FD7F64FB1573E68ULL,
		0xD11239EB32C20011ULL,
		0x071E7E9EEFFB6038ULL,
		0x0E13D389E3D4B597ULL,
		0x748D2A44726D904FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB294704BD445167ULL,
		0x0BCC4CC1BAF1BE27ULL,
		0x92699FDEC2CD7190ULL,
		0x3CCC3C78AD9AAA24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25260E6C1A838D9CULL,
		0x43DA8DB2922EA174ULL,
		0xB2FAACCF9BAA0D3CULL,
		0x46299D5BD7655A40ULL,
		0x91E076B90DB5FFBFULL,
		0xF626F75437FA1DECULL,
		0xFA92302F1E963D3DULL,
		0x0775980CEE5E22D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC77ADE42387841CULL,
		0xCDA34432E14F1291ULL,
		0xE4ADD3CE25F7246EULL,
		0x619E2F47395E8675ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6B2CFBDF59D4059ULL,
		0x0700B533B80C2860ULL,
		0x62D30B13A154BD1EULL,
		0xCC3490A64188B3E5ULL,
		0x56D220786B347CEAULL,
		0x9A4B673C8613B64BULL,
		0xE3906C85C2A5183FULL,
		0xC99D0BEB4C31D709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E3A19DDF67CF9CULL,
		0xEE32082F9EF9378FULL,
		0x2A4326EE85D6568EULL,
		0x3984559390EE9F5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70D1526CC6E3C7DBULL,
		0x0750309E90DA23D9ULL,
		0x36E16F19BD41BB5BULL,
		0x4F8581A0A37145FFULL,
		0x9E2E0CA07FF40748ULL,
		0xC7C9112324805334ULL,
		0x941264EF07DD215CULL,
		0xAE6AA906743C2BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA7323FC51CE067ULL,
		0xAF28BBD5FBE67DA8ULL,
		0x319C6A94E814AF20ULL,
		0x335A9895E45FCB69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1348BD666B31AC25ULL,
		0xDBC39741DA9403FFULL,
		0x8650123020CD3D36ULL,
		0x8C646BF890854282ULL,
		0x5447E589CC7C0696ULL,
		0x83DD125B34980147ULL,
		0xD2D633C172C88B48ULL,
		0x5B887A2BAE26AA95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F4CFDAC59AA87DULL,
		0x6E9450CBA9243495ULL,
		0xD21BC0E72A91E9FAULL,
		0x22A68E746A4294BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B132FE52CF4F70ULL,
		0x311160A2F2D3F3F5ULL,
		0xC109DA207238E02CULL,
		0x35124E46CDAF00C6ULL,
		0xE2B1869D6FA755E5ULL,
		0x162E40F6C4CDE2FFULL,
		0x4C3EF4CED1336CA6ULL,
		0x27BE33BFC105467EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF80B2E5CE5A61052ULL,
		0x7BEF05442963A5F0ULL,
		0x126230D37FDB00D3ULL,
		0x1B4DFCBD74777786ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74A956AAB7E1666BULL,
		0xB3C581AB0E3F3D4AULL,
		0xCC4136EEEA86D0D8ULL,
		0x6BE453F50B65C547ULL,
		0xE53F80B92ACBA8BCULL,
		0x096FEDBF19698698ULL,
		0xAB13D7D8A2E09741ULL,
		0xB1893191F97B52BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C167227121C7642ULL,
		0x1A62CC08D3E937FCULL,
		0x3133411717DD4480ULL,
		0x4641AFA013B40D95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3142CAE78FE5B427ULL,
		0x9FF7409678D93DA1ULL,
		0x66CCF3C2902A172EULL,
		0x955E350744FFFFE4ULL,
		0xEE0D1EE10F5EA066ULL,
		0x67218BDB5EAF952BULL,
		0x76965AACE3C4DEA1ULL,
		0xD90B258354F75557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8735604FD7F1881EULL,
		0xEEF2032686E96226ULL,
		0x011E696C5F632323ULL,
		0x4D05C685E1B6AAE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2788557E2B39B368ULL,
		0xC38AAE09EDD87872ULL,
		0xDDD3B4DC25ED7F4AULL,
		0x714E49E0CD7AAF32ULL,
		0xFD6145F14B630314ULL,
		0xAE941A124C3570C5ULL,
		0x7BA5AA9E345B32C8ULL,
		0xCA35723769FF5039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F8B74F5BEC2CD4ULL,
		0xAD868CC13DC735D5ULL,
		0x386B0857EB770914ULL,
		0x753D3E1A896097BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC38EE25B7B5522BULL,
		0x8205351C37B30025ULL,
		0x8D6BDD4A3A25C501ULL,
		0x521858D10A581ED0ULL,
		0xB39915854D556ABBULL,
		0x87BF42D750838FE7ULL,
		0x57F927F8CB7C4391ULL,
		0x77D5AA81C4E4381FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F21FEF32632C99ULL,
		0xA86921122B3A5C8AULL,
		0x9C67CC386E97CC9BULL,
		0x1BCFA81444387377ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF170D3402B3E013ULL,
		0xD39EF684A2FB2856ULL,
		0x7C716AA35C9DB8FCULL,
		0x89E5D665ACBEDBCCULL,
		0x338C9B3843967B5CULL,
		0x077EC4AFF6FA8D94ULL,
		0xC70F0689F235ACF9ULL,
		0xA86E291143369050ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F6178E0B0A3384ULL,
		0xF07028A34C2C2C56ULL,
		0x08AC631D509565F3ULL,
		0x0A3FEEF5A6D847CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x319B80FA87168098ULL,
		0x234B40DD65DE4574ULL,
		0x8F4EB53F2E2D5F52ULL,
		0x37A4D6ECC149F2F1ULL,
		0xF6642BBFEB2F5A38ULL,
		0xA0F76EC3A1E6978AULL,
		0xA801E2B06ACAE610ULL,
		0xF71100A853C9E45DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC479FF77701DEA53ULL,
		0x0805B1E76E18C414ULL,
		0x7F965B6F084B85CAULL,
		0x642AEFE93141D8D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83B33F0BF59E8CD1ULL,
		0x113567472CCEBED0ULL,
		0x9AF83B679346FE15ULL,
		0xF7403EADAD07FF21ULL,
		0x25B9B5624F2F7C51ULL,
		0xCFB25C2E88E2A97EULL,
		0x6CE157C5E3629E9DULL,
		0xABFF95AA01A08A46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D442BA3B6AB04B3ULL,
		0xE5AF162F7E73E78AULL,
		0xC46B42C753EA8981ULL,
		0x7F3075E9EADC8595ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F77F5C28FC79836ULL,
		0x7BC9B68937131C1DULL,
		0xEA614A3BE0010E97ULL,
		0xB7D580424A871B7FULL,
		0x120793CD8122A642ULL,
		0x0DBA83C2A1FD9D3FULL,
		0x833CF0A78B65849FULL,
		0xC2124CF839B6BE91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C97E643BAEC4A63ULL,
		0x8579456D42B8737AULL,
		0x656D031A9112BE33ULL,
		0x068CED1ADBA76519ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CF18E758C7881C6ULL,
		0x8705E57175D5B10DULL,
		0x766CC5B0450DE6C2ULL,
		0x6894794B4350C78DULL,
		0xF529E09E8DC8A287ULL,
		0x4601CA90B20D8F31ULL,
		0x23B514C2E99EB257ULL,
		0x24A1C459CFE4F855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC128E5FE9840A2A1ULL,
		0xEB49F6EBE3D8F277ULL,
		0xC34DDA9EF29C5FB6ULL,
		0x58979EA01F4DA430ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF91F48A90801A41ULL,
		0xE51FD617D42014DAULL,
		0xC5A74EC2A0E437D3ULL,
		0xDAC7BEF8C0AB2FFBULL,
		0x1A23CD0914E9DC6CULL,
		0x5808FB5E19220184ULL,
		0x71B598F440A0C4F4ULL,
		0xE74A962B83B915DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0E263E3AB36D77BULL,
		0xF675260F8F2C4E76ULL,
		0xA69C030438C17418ULL,
		0x2FDA096E4E246F26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF191FE5FEDD2BA76ULL,
		0x2A27CAFA7738A969ULL,
		0x9E8EB94A674978CEULL,
		0xAB9234C6EEAB8102ULL,
		0x0A1B001898DAFC33ULL,
		0x1DBFDAD30A250082ULL,
		0xE3F1DC409C067332ULL,
		0x507AE20DDEC41D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719402069E542BE3ULL,
		0x94A2464DF8B6BCB7ULL,
		0x74756AE1903E923EULL,
		0x1DCFC2D5FFC7D5ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B92FE4F2E6FBAA6ULL,
		0x9D6B7835458A9579ULL,
		0x487B33C5358EF1F7ULL,
		0xEE2374757BB9B86FULL,
		0xC9F6ADA3A66022ECULL,
		0x2F0BFC1B562A31C2ULL,
		0xC35FB44C08B09D39ULL,
		0xEFA376127664E8BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8630C499E0B4EF19ULL,
		0x9932E4440FCDF863ULL,
		0x48AFF70E7FC64874ULL,
		0x0066FB330EB444E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE53E1B3391502E24ULL,
		0x022DF5B465897E59ULL,
		0x0A6408B300ABBE9AULL,
		0x029F2F8649023224ULL,
		0x778FB1559565888BULL,
		0x3C9567D1A0AE56CBULL,
		0x68E0197FA570D1B8ULL,
		0xD57B734703D9CBFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4926DE7BE627773ULL,
		0x005B5ED23F6A608DULL,
		0x9BA7D1A58F6ADFF3ULL,
		0x32F24C10DB567975ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E21F4C61E59CDBAULL,
		0x6AB3C3A9D34A3B3BULL,
		0xECC7BA7E7278F33CULL,
		0x054F0477164750E1ULL,
		0x5DC7E8F7F7258674ULL,
		0x90AC49857ADA06D4ULL,
		0x766B3D12DE9F7DA2ULL,
		0x0F4DFC8503EF17B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19CE8994CDEBC33EULL,
		0xE446AD7A0FA73EC1ULL,
		0x80B2CB4B7E25995DULL,
		0x4AE28035ABC4D669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B169C3D9F534104ULL,
		0x38B9045E34776FE7ULL,
		0x67FE1FB6AC5E6F0CULL,
		0x7DED811B6411C6A0ULL,
		0x76DF425F3F2EEC38ULL,
		0x9E5F556CB893C5F3ULL,
		0x4B1EEE8C6AA53C06ULL,
		0x97CDDAE812597E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB03A7661004A54BEULL,
		0xBADFB2819A66D20AULL,
		0x8E95888E80E55807ULL,
		0x067BFF8E1D5A7FDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F81A4414E41D81DULL,
		0xD160A67544052E0EULL,
		0x55E297A019F7F80CULL,
		0x6BBB862B802464E3ULL,
		0x0407DB969ECEC9C2ULL,
		0x87CB448E14367AD2ULL,
		0xDD61E5D9EA31D655ULL,
		0x64D5E43CE44E8358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28AC3C9CE0F3CD23ULL,
		0xF98CD38C441B693BULL,
		0x326AB5F8DD5DC8BEULL,
		0x637B673563CBE414ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9AB4989B75756EDULL,
		0x797A899D38E463BCULL,
		0x7227503012B2971FULL,
		0x0413AC5ABBBEC70BULL,
		0x2683617D64C704E5ULL,
		0x2AAC0898420D5BC9ULL,
		0x5365AE082CBF06A7ULL,
		0x9ABD6CE50710BB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12BC226ACE21442ULL,
		0xCF03D03706E00398ULL,
		0xD33F2566B70D93EFULL,
		0x7C31D659C83A9E51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58E6DBE00059288EULL,
		0x8D47DACC717CD525ULL,
		0x4A3A72CED5D71E80ULL,
		0x546D258A5A00DB3CULL,
		0xD6A68508BFC3A868ULL,
		0xC4200615322C826FULL,
		0x5F9A413D3E28B26CULL,
		0x1F67976115E3758DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x359E9B2C776428A9ULL,
		0xAA08C1F1E41831BFULL,
		0x7B2021E60FE19AA5ULL,
		0x7DCD9DF399C44E38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC9DCE2D28AC35B9ULL,
		0xBCAF6BA98EB28AF1ULL,
		0x37A746C96AC60038ULL,
		0xE82223457993E99AULL,
		0x1E9CE78E22372EE7ULL,
		0x4DA9A41FF0BEED81ULL,
		0x62B9F717B196FDDDULL,
		0xCD1F3497B4EEC086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E82D463CDD309DULL,
		0x43DDC8674B09CC1CULL,
		0xDF41F44DC72FAF12ULL,
		0x5AC3F1CA55047D8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE62FD17582BC3D96ULL,
		0x4C11EBA00E6CF6B9ULL,
		0xFD8EE94F7AD2ACA9ULL,
		0x7786680F032CA5D1ULL,
		0x5BFDFFC7E75AE0EFULL,
		0xBF9755258B15FE14ULL,
		0xCE36C033A6AA71EFULL,
		0xCCA3A726061E6CD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DE3C921DA39A597ULL,
		0xBC888F32B3B0ADBFULL,
		0x99AF70FA381F963FULL,
		0x57D137B3EBB0CE00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B5A8F0D0B06D6B3ULL,
		0xEDE020988EBF86AFULL,
		0xB6AFB7BA2FBE0966ULL,
		0x36F5BBA26377AFAFULL,
		0x56BC3E5AFCAA7C83ULL,
		0x2912AFE57D2A7982ULL,
		0x731C74B8F7190507ULL,
		0x507AC31AA7833A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B4BD08E8C5553EDULL,
		0x06A63CA9230D9008ULL,
		0xCCE90B2EDD74C877ULL,
		0x292EB19740F254CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A8806AF3031EBB9ULL,
		0xD3B60FED809F3486ULL,
		0x08E4C75D154824D1ULL,
		0x19AD675DDD378AF2ULL,
		0x27DBD95F765868A4ULL,
		0x56D05FAB7C86C24AULL,
		0xE2F9F2542DD6F370ULL,
		0xB3E9E76E56C36F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x052A4ADAC1517800ULL,
		0xB6A44361FCA00B88ULL,
		0xB9FEBFDBE330477EULL,
		0x4E65C1BEBE3A1C3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83E7544250E7637DULL,
		0xD3752800E26FBBAEULL,
		0x9B823545B84D30AEULL,
		0xC0A53AAD08A09636ULL,
		0x9439D8A45BF5C931ULL,
		0xAD1CAC090799B445ULL,
		0x78D9287654B09FC8ULL,
		0x2B43914F93A79E6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x847D7CA7F76341CDULL,
		0x85B6B15803407E02ULL,
		0x8BBE36D64A84E878ULL,
		0x2CACCC7CF3821A9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24EFE718FBEB0112ULL,
		0x6EFFE73FD390B995ULL,
		0x4E580A6272E68DB5ULL,
		0x35C55604E72D12A1ULL,
		0xEBC5E9D9A231BE52ULL,
		0x467E00F2CC791974ULL,
		0xD472C41AD4CF8352ULL,
		0xE72A6361AF7367E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24509D670F4D465DULL,
		0xE5B40B4A2D8A80F0ULL,
		0xD761265E09B40BEBULL,
		0x06101684F24E7F56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB1C6D5CDCF596C2ULL,
		0x857AA1CA82152497ULL,
		0x5254291A8BD27D33ULL,
		0x29E9C770A7006F0DULL,
		0xDCA65C0393BCFE28ULL,
		0x472F7388D37CDACDULL,
		0x8FF448538C59B511ULL,
		0x8312B251A3F8B136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BCE15E4CB035397ULL,
		0x1685C819E69D9F26ULL,
		0xB096E58161235DC4ULL,
		0x1EB03F8EFDEABD26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4B149ED27A2FD66ULL,
		0x259BAC82333BDE15ULL,
		0x91DFB6C38B108A3DULL,
		0x56B1E654D4BB8200ULL,
		0xF94A54D9E15C2E1FULL,
		0x64C04B1B51F072DAULL,
		0xC004289BB39A4FD4ULL,
		0x9731142FE6B97330ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B9E2449B51D957ULL,
		0x1A26D2905CECEA96ULL,
		0x127DBDE033F863C4ULL,
		0x47FAE57114429B3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF25F0D1D19941AFBULL,
		0x8460425B912A0749ULL,
		0x2F3EF2B0686D7266ULL,
		0x49E8BB4F87F54C52ULL,
		0x4BD22604C205E5C6ULL,
		0xDF472D6D8A861502ULL,
		0x8F1D2B589ECAFF9CULL,
		0x33E4B5B9DA05C7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3390B1D1E674377CULL,
		0xA8F1009E211125A1ULL,
		0x6D9361D7FA8F63AFULL,
		0x7DDBB4E5E4D0EFEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28C1CAE10CEF0A60ULL,
		0x1E0D54663E6A4A30ULL,
		0xD4EE50490A5CADAFULL,
		0x29017C1CF4D69B60ULL,
		0xC3E1C89E1709572AULL,
		0x590FFF7157E00F60ULL,
		0xCA645AFC60FB651DULL,
		0x52B573922AA08E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C4592587851FC64ULL,
		0x566D3F3949AC928DULL,
		0xDFD3D1BF6FADB00AULL,
		0x6FF0A3CF48ABC420ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF01DCA7D7DD8DE29ULL,
		0x17D4A88C3B1549B8ULL,
		0x0C2A1204F8AEA4BAULL,
		0x755DD840454334D0ULL,
		0xC731EF5D7540FEF2ULL,
		0x8BD887E180AC7916ULL,
		0x2672CC4A1B1ECEF7ULL,
		0x1D78AF07765AA8CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8187525CE57EB6C0ULL,
		0xD9F8D40554AF431AULL,
		0xC1346504FF415D78ULL,
		0x5547D35BD6B842F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BE15AC75FD96DF7ULL,
		0x7D65C5146A3F3BCCULL,
		0x507018AFAE6E7161ULL,
		0xE0E879451AFCFF18ULL,
		0xE144AED712DA30B0ULL,
		0x2DCAD1BC7137EFA4ULL,
		0xE44CA6DB003FC403ULL,
		0x33400B86CC3854BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C134EB42C3CA947ULL,
		0x4980E70D388CCE45ULL,
		0x33D0DD31B7E589DAULL,
		0x7C6A2F476B5992D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4E8F448892B1B20ULL,
		0x8EE7BAC06111E4C1ULL,
		0xC947A68F86B92005ULL,
		0xB962BAD20B3CB219ULL,
		0xE38F5F1DF640ECB9ULL,
		0x57A0381F585D65E6ULL,
		0x3C8A4CC776D7E01EULL,
		0x2C507365418FDE03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C3112BB16CE3FA0ULL,
		0x90B00F677EEF0507ULL,
		0xC5CF0C2B2AC46486ULL,
		0x4D53DBD9C697A694ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0F7FEBEE53173CFULL,
		0xB2CE7ADDCB708330ULL,
		0x4DC4A9E4CD4F94ACULL,
		0xCC97422599E074D0ULL,
		0x74BFFCB79400B5CDULL,
		0x5ED7BFA617F2E4E8ULL,
		0x3EE256E0697F8A29ULL,
		0x5FC09A69AAA19C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF57781FEDD4C7277ULL,
		0xC6D4ED85597E7DB1ULL,
		0xA35D8F34763E16D0ULL,
		0x032E2DD4EDDD9FD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2D3113399CAEAAFULL,
		0x037343A8D28E602FULL,
		0x9B9774BF216CC406ULL,
		0x743721616F57EF88ULL,
		0xE78981B852643158ULL,
		0xBB53E2739423C218ULL,
		0x28FAD9EA0E4DAE4FULL,
		0xF9604F82A8A884C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013C528FD4AA433DULL,
		0xD1E6E0D0CFDD2FE2ULL,
		0xB0D3CD7D40F4A3DBULL,
		0x7882EEC6785BA4F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0922025D90D2A14EULL,
		0x03F965F29E5C16F3ULL,
		0x40524168B0A7BB0BULL,
		0xA41195097CABA89AULL,
		0x33A5A0D9D97B7A2CULL,
		0xACDAEC3EC38F0EE1ULL,
		0xC0ABCAD875CAE845ULL,
		0xF5D338E618174BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B7E2B3D926C954ULL,
		0xAC787743A5984C60ULL,
		0xD9D25D8A2CC63562ULL,
		0x216C07311020F090ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35C47F1185A36D4DULL,
		0xF72C89D294EDAE97ULL,
		0xDE336100D89BE385ULL,
		0xAD22E3286D6D07DAULL,
		0xD0D15A865EF061C4ULL,
		0xEA5F407278E60D41ULL,
		0x4D41DDB60188F95BULL,
		0x4E1F0D1086A61CA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34D7EF039D51F22DULL,
		0xC1501AD08713A65CULL,
		0x55FA4A0512F0E72AULL,
		0x45BED39C6A1547A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}