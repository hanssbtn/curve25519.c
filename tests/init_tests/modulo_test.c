#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xEE485F0211A89C8AULL,
		0x9869F0D0EE5A915CULL,
		0x63476C20ABF16525ULL,
		0x33492E658679EF69ULL,
		0xF4FA32FD8A682B79ULL,
		0xC9082445B136DDCBULL,
		0xAE4F0E7D73248B09ULL,
		0xF2574977E4697CE5ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x4B6BF0A49D1F15D8ULL,
		0x6F9F53293C7F7DA3ULL,
		0x430392BFC35E0899ULL,
		0x2C3E16316E227981ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x50DADABB3D062210ULL,
		0x0F7EBE0B0B1F09FDULL,
		0xFCE5A99B2B23233EULL,
		0xE37484137C2DE82EULL,
		0x46C3462295451D0CULL,
		0xCD3D6AFE1AEE2DA3ULL,
		0x6E68C9551BD93A9BULL,
		0x560DCC3825D2B9DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D743DD654873D9ULL,
		0x869C9FC30A79D039ULL,
		0x60738C3D4D61D65EULL,
		0x2980D46919757E9BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC171D9DD18B78575ULL,
		0x0D3C79023A918182ULL,
		0x333D1C48F5836DF5ULL,
		0xA484229613FAEC5BULL,
		0x31A6162B52BB28EAULL,
		0xFDFCA0C4BBF69865ULL,
		0xA37BF6299005E054ULL,
		0x6AB24B9F5022BB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2019244B607F9A91ULL,
		0xC0BC5636212C2088ULL,
		0x77A3A6745662BA92ULL,
		0x7AFB5C3BF922C5C1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x09C64148E189FFFAULL,
		0x3D3EEFC500CA000FULL,
		0xC5CEE56BD44C64FAULL,
		0x40181838E1519693ULL,
		0x454DA583B897CA66ULL,
		0x25B369A5D01A8448ULL,
		0xE1AACCCAD27FE451ULL,
		0xA9F8FB248C782103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x534CD2D648120ED4ULL,
		0xD5E09E61E4B9A2C9ULL,
		0x45294B8713484905ULL,
		0x7B0D5FA5BB267D27ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD73CD485A81707CBULL,
		0x83EB38932F390856ULL,
		0xE95541BAEA2F818EULL,
		0xEFF24C9BA7CBB180ULL,
		0xF239418BAE352A32ULL,
		0x2AAB4E567695D3F3ULL,
		0xF67C8D091C44FD76ULL,
		0x04AB2EC8625587A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBC8F4183FB4B70ULL,
		0xD958D968C9767E8CULL,
		0x7FD231151C6D2118ULL,
		0x215B3E5A407DD3B1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDE2C17E86BE874F9ULL,
		0x2BBFB9254817FA52ULL,
		0x98E4DAD896366A16ULL,
		0xA6E2C4DA7A3AFBBDULL,
		0x9AF79B092C4B5581ULL,
		0xC4B817DAEE55E7F9ULL,
		0xCD9840A86F77E91EULL,
		0x0DC267E1D071F518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEED1B44FF17267EULL,
		0x5F1343A4A8D8695FULL,
		0x1D7E73D9220304A7ULL,
		0x31BE305F6B255D6CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB59FCD587C643FDAULL,
		0x5B237ECAEDB0F460ULL,
		0x3A007B05A798CB85ULL,
		0x0599B324565F60B1ULL,
		0xC9E99180FA17F7BEULL,
		0xD014688395077300ULL,
		0x3E236E4A833BB7C3ULL,
		0xFB6EEDE081590523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE4B667D9BF30B8CULL,
		0x3E2B02530CCC067EULL,
		0x7342DA1522761296ULL,
		0x58110277899623ECULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4417C5708AF489DDULL,
		0xA0C88FBD76ED004BULL,
		0xB76376DAC2480A25ULL,
		0xFBF4E2E1256E23BDULL,
		0x51C6A4C5F19188E4ULL,
		0x2ED7A3B6EC9EDB25ULL,
		0x259C5A0051A176A3ULL,
		0xC0DA1B8DA448EA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67943AD2668EE016ULL,
		0x94CADCE4968187D5ULL,
		0x4C98D2E6E03FA65EULL,
		0x1C54F9E78840E437ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4630294B208BC4BEULL,
		0x5A73D0DF6CB0130BULL,
		0x7526046F6CFE63E9ULL,
		0xF356FDD6E11D4CBCULL,
		0xCBBF9C53E1DE330AULL,
		0xA040C959686CFC54ULL,
		0x82BC7FA4433B3CB0ULL,
		0x8D718C72ED698674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A15DBEA7875B6BULL,
		0x2411B424ECDD87A1ULL,
		0xDD20F6D167C96621ULL,
		0x7231D6E61EC74207ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2B461C3D0DBAB75DULL,
		0x744216227CCC65B2ULL,
		0x8DEEE14A39CA49B6ULL,
		0x2D3E7D6CDF7F2223ULL,
		0x04CEC8D0624695D7ULL,
		0x8B7BA06FCAACAB2BULL,
		0x998B2C96A3D4AA5DULL,
		0x6A551150090FD1B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1F7EB2BA434F794ULL,
		0x289BE6BA926DCE14ULL,
		0x58977FA68B5B9399ULL,
		0x75DF0F4E37D843B0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBE6AED0A4F37465BULL,
		0x69084AC74A876C66ULL,
		0x359FC1BE17E70C10ULL,
		0x53C01B9AC4F33CA4ULL,
		0x96D4C3C363DE19BDULL,
		0x3A257970DBE42FAFULL,
		0xE4D6B87E050F87F7ULL,
		0x3D664AE7AF7AA1F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21FFFC0B222F19BFULL,
		0x0A985187EE668077ULL,
		0x2D7F2472D8353AC3ULL,
		0x70EF39FED1274770ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E49091A1A502DA1ULL,
		0x1B7E023655A623A8ULL,
		0x2CA4415A5C223419ULL,
		0xC7B683DF584480C0ULL,
		0x01B5ABFAA2528432ULL,
		0xD6528D943D6F69EDULL,
		0xB7B34DCCD6441399ULL,
		0xB9FB2C3DF3735B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF40904E328FD135ULL,
		0xEBBF0637742FDCD6ULL,
		0x7141CDC22A3D1CEEULL,
		0x62FF15117B640F79ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0DD814618281B69CULL,
		0xF84A4E1A33A0C1B1ULL,
		0xC88A6C48FF8F7A83ULL,
		0x6CD091530AC0A18DULL,
		0x47E45D2559312D50ULL,
		0xB0F51EB2B5CA4545ULL,
		0x4813954C31E7FD46ULL,
		0xFE4BBCC0E6BA396DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9BDE7ECBFCE7620ULL,
		0x3CACDCA12FA709F9ULL,
		0x7B72959867FF1302ULL,
		0x2C0E95F54A6527C6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x90DD83C2341C557DULL,
		0x886BF881EDD6F842ULL,
		0xF9F5E02306BB0F3EULL,
		0x790607C2AA39B2B6ULL,
		0x73F411F1DCF531B6ULL,
		0x28C5903D7A2D54C2ULL,
		0x4AB9FED8FAA69854ULL,
		0x19D0DF9676638E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7182DA90081B719ULL,
		0x95BF61A210918D1FULL,
		0x1191B4583B75ABBCULL,
		0x4E0738183D00CD96ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA6B6C29FCD81055EULL,
		0xCA65D3A4B685FFF8ULL,
		0x1579681F4261D617ULL,
		0x9856E25FD6E53F69ULL,
		0xC44C245DDDD91EB2ULL,
		0x8DEEE96E261D7F3DULL,
		0xEA5DD39F5453F543ULL,
		0x5114B8C9D0A40EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA04288EBBBB95A5ULL,
		0xDBDC79FE5EE6E323ULL,
		0xDF66D1C5C6D83E1EULL,
		0x216A5054CF3F70C9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDD5DB65403DF5E57ULL,
		0x3AE95095EBEB5B32ULL,
		0x1981C95C90B9F856ULL,
		0x02ADA33C95B871DCULL,
		0xACDEC918E68D71F0ULL,
		0x9D861364A0FAB2A9ULL,
		0x9183AE34109ABA29ULL,
		0x8677716E1167EAA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x866F90063CDE4ADCULL,
		0x9CD03185D121E062ULL,
		0xB30DA51707B19A83ULL,
		0x786879932B254649ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0F856162876A0019ULL,
		0xC9AC6436D16A2ACEULL,
		0xF9231A6FEDC44A47ULL,
		0xCEF238AD52AE6A29ULL,
		0xFBD2886E243BD178ULL,
		0x1B96099C6EE28319ULL,
		0xFAA0F6F077D635CEULL,
		0x2D6EE84897E4E633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C5A1BBE84B1906ULL,
		0xE1F1D16F4709A0A9ULL,
		0x2D07C221B79046DFULL,
		0x0D68B373DEA895E1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFD7DF8CF5BB8FB93ULL,
		0xD43A8C2A4DD4767FULL,
		0x0FA7453B0C4C2983ULL,
		0xF27CCD6123674D2FULL,
		0xE3200426C78781EEULL,
		0x9B3414A4CFBCBBB6ULL,
		0x22A7AFD877A4C7CCULL,
		0x749A83F08F376F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB43E9690F9D64793ULL,
		0xDDF59CA123D853A5ULL,
		0x348B5F5CCEC1D1E2ULL,
		0x416C631665A1DACCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x94C6D218CED0FC34ULL,
		0xB3C105855E12560CULL,
		0x845F0AF420FE5A67ULL,
		0xC3FC4254012BD5F2ULL,
		0x692F53C720F46595ULL,
		0x5A49E1E997DEF563ULL,
		0xDDE779ACBDEF1CD6ULL,
		0xAFDE037439DD9020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CD41A7B3181441ULL,
		0x1AB88E31E92AC2CEULL,
		0x74BB1A98527CA239ULL,
		0x5EF0C594980F3AD3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDC3204C98FE38AA3ULL,
		0x0C20CE11CA3270C0ULL,
		0xDF1BC15A216503ADULL,
		0x580A4F82C5E5A112ULL,
		0x097BD4D99753356EULL,
		0xFD2CCD94FE3EDFBCULL,
		0x409E80A31F1334F5ULL,
		0x542231EAE71B4A7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44939D16063D7AD2ULL,
		0xA0C7522F8787A6AAULL,
		0x76A2D990BE3EE030ULL,
		0x551DB86113F2AFAAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC2C43D576AB685D8ULL,
		0xF1207758C1911047ULL,
		0x5EE3D69B2DA8C5EAULL,
		0x27C3E736991BEC97ULL,
		0x17A1192C6235F0F7ULL,
		0xD83FAF210275A3DBULL,
		0xFDA7AA5FF126B87AULL,
		0x2E806378C5CA8B1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44ADF9EDFEB84B8CULL,
		0x0A94763F1F0762CDULL,
		0x05C720D8F9682827ULL,
		0x0ED2AB23F52C930BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4B513FD88AC5D54FULL,
		0x9F9A45FA5FADD667ULL,
		0x94272D5D94D2F602ULL,
		0x9EB7DF7B354A3575ULL,
		0x3B4664B376118833ULL,
		0x7C6F7F208976B00FULL,
		0x4049830A5B9BABAAULL,
		0xCA087157C965B659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C4327C11601168ULL,
		0x182724CEC74BF8AAULL,
		0x1F10A0E72DEE7151ULL,
		0x1BF8B2831A6346B5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFA4DFD3EB37C5A2CULL,
		0xFEBB944229F13985ULL,
		0x3948B4788AC4FD97ULL,
		0xC22EB762AD715E91ULL,
		0x47726625662D007BULL,
		0x9E3F15183EA6F26DULL,
		0x628A2048335A2D31ULL,
		0xD3C70BE0D2241E3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x954926CBDE2A712EULL,
		0x7C18B5DB76B935BEULL,
		0xD9C97F302A27B2F5ULL,
		0x31BA7AC1DECDDB87ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x199923D09915BF5EULL,
		0x7B66A470F1C5C1FDULL,
		0xEA2685184F544651ULL,
		0x966D9C9637CB34F0ULL,
		0x98C44E73982BB6DBULL,
		0x29191B499C82C115ULL,
		0x47A86FCE6D0CECD8ULL,
		0x0C4959BB01EF4BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BCC8F92F92E42CULL,
		0x9520B15E2D2E6B31ULL,
		0x8D271DBC7F3F6E67ULL,
		0x6950EE58815078ADULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2E8396D632369F69ULL,
		0xC6B11DE748DC66F9ULL,
		0x0ACD3D46C62F7DBAULL,
		0xB7DCC10DD98032B1ULL,
		0x7B9DFA254E817952ULL,
		0xE9D6349FAEB2129EULL,
		0xEDFC6395052438FFULL,
		0xDF494FB2E43E2D5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87F6B85FD96EA68EULL,
		0x7C7CED9B374B2A7FULL,
		0x5E440565898FF3B7ULL,
		0x5CBE959BBABAEEA2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7828EF7243C4D956ULL,
		0xB4F328CE19CB630EULL,
		0xAA1A39CE3C97C418ULL,
		0x8DF5FFDA6C652502ULL,
		0x6B30BD11128B21C4ULL,
		0x6B350CF973291469ULL,
		0x6E6D5F0561299CDBULL,
		0xFF4048D41ECA96B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6164FFFB046BE212ULL,
		0x9ED315D531E46AB4ULL,
		0x0E56549AA8C50CAAULL,
		0x7180CF56FE778417ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC1B68BB305AF3D0DULL,
		0x2BC1DBCF00EB48BCULL,
		0x56074D93A9A75E80ULL,
		0x5B3F75A86F4EA119ULL,
		0x14D786ABECC76547ULL,
		0x190D0DF617A31924ULL,
		0xD1305352D0C4E7A8ULL,
		0xF1E39A10522A4C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9B489382B484AEFULL,
		0xE3B1EE5683210417ULL,
		0x6333ABDEA6E1C173ULL,
		0x43085414A195FA24ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE299ABF1DC6958DDULL,
		0x8F39E33A418D472AULL,
		0xEFEEEB28EB63E2DCULL,
		0x6AFE3ECD82A42CE3ULL,
		0xD1B41B50DDD0B665ULL,
		0xE7DE1D25A5611939ULL,
		0xD48C23AC4582DB34ULL,
		0x8ED1CB0A517DBD07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0355B9F2C9646F0CULL,
		0xFA3236D0CDF705C0ULL,
		0x7CBC36BB3CD06CB6ULL,
		0x1E2262559B4E3C0DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6B0ED0B454BE7BF3ULL,
		0xED085FB4F6E4F3BEULL,
		0x09E4924B68A7E3FDULL,
		0xC81B0F28F7C2B2D6ULL,
		0xCCD882AEBABE62BAULL,
		0xEDBA8EDDA1990852ULL,
		0x9A1F4E5E1BF02AC0ULL,
		0x4F5A7A4C567DEE2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33236A40D01256AULL,
		0x36B9949AF39C3008ULL,
		0xEA8A34438E4E3CA1ULL,
		0x0F89367DCE740DE6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x89AEAE3BC9CB4CE7ULL,
		0x13A32E1E1A60E08BULL,
		0xFC1B96BAEB6877D9ULL,
		0x4A1C217359C5E28AULL,
		0x24AFE3A472C1FB9EULL,
		0x7457D4B52FA54551ULL,
		0x8ECB088DDB3F845FULL,
		0xC120FE4B1F92147FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBCA78A4D296AA96ULL,
		0x58ACC1032CE92A96ULL,
		0x2E3EDBC976D61E04ULL,
		0x7501E09A0974ED7AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E7269F91644F243ULL,
		0x86F0CAC893A57D71ULL,
		0xE062912027C5547CULL,
		0xE5C5D77E5847C21BULL,
		0x637D5116E0D252A6ULL,
		0x5EB68BD766EC8074ULL,
		0x03BE3E997D647E19ULL,
		0xF05A8ED7B286D841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330C735E757D3C52ULL,
		0x96098CC1DAC08EB8ULL,
		0x6E9FDBE8C4B00C40ULL,
		0x13370B82D84BDBC2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB46B03A2949D7308ULL,
		0x310C1726C2DF8343ULL,
		0x26BA9C0AC641D862ULL,
		0x926BA8070CF58160ULL,
		0x85207164D28DD413ULL,
		0xC61395FFD0228100ULL,
		0xCF9F18648B8D5712ULL,
		0x4CAC24EC35EA9929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x773BD899D5AAEF8FULL,
		0x97F45B1FA7FEA957ULL,
		0xF8583AF77D3CC52BULL,
		0x73F923170DC83D94ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBF6CBBBFDE6F5A23ULL,
		0xB9FE4495B91384E5ULL,
		0xB5CF1415C007A18AULL,
		0xBF8C335EE83C2A4EULL,
		0x165A391525354787ULL,
		0x2DE616300D523526ULL,
		0x9A7D3E1AD82549DEULL,
		0xB9295AA29C0DDD6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10D134E36457FC55ULL,
		0x8A258FB7B347688DULL,
		0xA4664C11D5909885ULL,
		0x3BAFA782124B08B9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7C0C82721FCE2B7DULL,
		0xFCCA099B67626331ULL,
		0x4BCB1886AA799973ULL,
		0xADA188544D00C602ULL,
		0x0CDD71952C4837D7ULL,
		0xF2C3EF7A11BE81BCULL,
		0xA0895A1F72E11D05ULL,
		0x665A5F5CB4BC125DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64EB5E96B28677B4ULL,
		0x05DF95BA09A9A51BULL,
		0x202E7931B7E3E856ULL,
		0x5F0BB01720EB7FE8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE5734D916F347CB2ULL,
		0x220FA4BE51C26C5AULL,
		0x3A60FBB69A41DB55ULL,
		0x06D9C6B8424ED1F0ULL,
		0x5811928D773963F2ULL,
		0x93291828EE459B57ULL,
		0x87D76D82F9F830A3ULL,
		0x1F84672C2C60F441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF80F0E9121B95349ULL,
		0xFA293AD1B0177B51ULL,
		0x645B3D27B519139CULL,
		0x34811746D8B313AAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6A3A9C058B4476CBULL,
		0x6D822A560437CFA5ULL,
		0xB1176EC017455F69ULL,
		0x6954C33CBE6C24D6ULL,
		0xC49B53EC27610271ULL,
		0x5C8F0E61ED2378F4ULL,
		0x33B43AB7D69CD9C2ULL,
		0x08EDC0E490FBFC24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9949111363AAD3CAULL,
		0x2ABE4CDF377BC3FAULL,
		0x5DD82609F28DB243ULL,
		0x3C9F652A43D39236ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA8E42999440512F1ULL,
		0xF53D4EAD95C43B2DULL,
		0xDBF41852376C9D97ULL,
		0x5475BD58118C21F2ULL,
		0x2052F07E0A58E784ULL,
		0xBADB13A7BCA657F1ULL,
		0xA2E2208CE71E4908ULL,
		0x116DBF4D456E5168ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7533DC4ECD3770E8ULL,
		0xB1C23993967548F8ULL,
		0x0984ED3C85EB74E3ULL,
		0x6AC022D05FEC377BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEF536E68CC6899ADULL,
		0x6DCEE09249F73F74ULL,
		0xBAAFF4D67C5FA1E8ULL,
		0x3F783D3862C55A15ULL,
		0x4BCDBF594A2E8BFAULL,
		0x031067A232CAC3D5ULL,
		0x3FE480D128D566B2ULL,
		0x2C4966E7D4FC45AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FDDD5A9CF5161C0ULL,
		0xE23E42A5D410511EULL,
		0x369B13E28C0CE054ULL,
		0x525D83A20037B1F3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x66EF3E535E55FEA3ULL,
		0xDF07EBE7842F5898ULL,
		0xF9B17B4BAD343B78ULL,
		0xE305B6508761B528ULL,
		0x332EF0B5937A90C6ULL,
		0x51A2D0CF9536C0DAULL,
		0x0D45547E11EA43A2ULL,
		0x16EA487C51C231B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFE6F94742877C9FULL,
		0xFD32EAB7AA4FF8FBULL,
		0xF1FC060255FA4590ULL,
		0x49CC78C4AA3516A0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6F5EBF2982F46E1FULL,
		0x6802200B4A3DB10AULL,
		0x81A8BFAD64A89B23ULL,
		0x90C9B33E1DAD4B4BULL,
		0xE5A8CB7BFB857A88ULL,
		0xEE9EF06857B736C0ULL,
		0xC4F713E818EE4A91ULL,
		0x193CE036E7F6EDB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x866CF390D8C49EE7ULL,
		0xD399CF884F6FD1ACULL,
		0xBE55B4211807ACCCULL,
		0x4FD2FB648C5494B8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC61CBCD7D09B16BEULL,
		0xA1C9FD6F20FF8198ULL,
		0xFF4330CD3E9C57A8ULL,
		0xC8853AEF27B7627CULL,
		0x1FBFECA9818AB739ULL,
		0x89A70E20E3086E74ULL,
		0x0C9B6E3D802D0E7BULL,
		0x763B5BBB69CA6493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C99DE010B324BE0ULL,
		0x10961650D43FE6D5ULL,
		0xDE558DEE454C7DFFULL,
		0x5554D8C0DBC25050ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x16960607C892E1BAULL,
		0xE61DFB4A2676A393ULL,
		0x95EB0F21EA66204DULL,
		0x3D228D27978B7844ULL,
		0x53CB67F4C36828E1ULL,
		0x30608F2AF54E1A3CULL,
		0xCC60C4BAD9D6EBF3ULL,
		0x2EDD93665AD4A377ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C7745CCA08F42AULL,
		0x14733BAA900E8887ULL,
		0xEC4842DE404D2667ULL,
		0x32066E59131BBC0CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x028584A770E3476BULL,
		0xBA37E5ACE4115436ULL,
		0xC7073965F5CA4C40ULL,
		0x9B93C898F5D48555ULL,
		0xDA2EF00AAC56554FULL,
		0x0F4896205B7A8BD4ULL,
		0x76B019D6081A3487ULL,
		0xFE00F4DB68AD46FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657D263D05B3F6C9ULL,
		0xFEFE2E7A784215CEULL,
		0x652B0F2B29AE184CULL,
		0x4FB8212A7F8D0ECFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4A4AD9A703F94802ULL,
		0x106FC64CAAA2220FULL,
		0x106B32B0087F6A78ULL,
		0xC817B219049B69A3ULL,
		0x066FD2827C0C697DULL,
		0x42176611AE7B525DULL,
		0x12673D3314CC9277ULL,
		0x5F1E67DF43F8362FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EE419056DD0F2B7ULL,
		0xDFE8ECEC90F05BDEULL,
		0xCBBE48451EDD282BULL,
		0x669B1D3D1B73749FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2976D82DDE1AE101ULL,
		0x4436509B1EB8B581ULL,
		0xAEC3B938B61A39D3ULL,
		0x661EEF837673D8D9ULL,
		0xA6560AA93919C1EDULL,
		0x3E2E59F16F330EF0ULL,
		0x547AF81A1A4FD274ULL,
		0xBCA99B82F8744126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3C6D4C57EDAE57ULL,
		0x7F17AA71A04CED39ULL,
		0x39048D189DF37714ULL,
		0x674C04F457B5848AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0EF20493BD0319A0ULL,
		0xADAEE1FC7E8ECCAAULL,
		0x38BE9B81435245EEULL,
		0xCEAC520433A8DE2EULL,
		0xA769E5AE211A309FULL,
		0x4C368C32FC0ABC5CULL,
		0xA6937356044E4417ULL,
		0x38DD7676DF4096F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8AA1C6CA6E65290ULL,
		0xFDC7B18DE826C26AULL,
		0xF2A1BA45E6F06163ULL,
		0x3F8BE7A9573F46CAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDC3D84EDC8AE1B9BULL,
		0xB22451AAC916C2CCULL,
		0x15C0566B870F58A6ULL,
		0x9C409992013B01AAULL,
		0x018360A0D2B17890ULL,
		0x4895FD4A0E8A3E97ULL,
		0x02D0C3090542B8E9ULL,
		0x48E7AEA0E3657C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15BDDCCD0F06029DULL,
		0x7867EAA8F19C0D37ULL,
		0x80BD49C24EF6CB47ULL,
		0x6EA48573C24B7E98ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6D06CCFF1499C549ULL,
		0x81C1D05C1CF0A035ULL,
		0xD390E8B098C32B1BULL,
		0x1B9618BFA4811FC8ULL,
		0x7B5F89727583ED4AULL,
		0xF1855E5298A185F0ULL,
		0x5961049C3CC132D7ULL,
		0xC25F92BA8E186E5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD3533FC862F0280ULL,
		0x5B8DD09EC4EA81E7ULL,
		0x17F797E19D70B729ULL,
		0x75C5E070BC218158ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x96E827C8B99B6E2DULL,
		0xC97007C1ADB524BEULL,
		0x16C08A646420209DULL,
		0xD789DF0495CF4FD6ULL,
		0x970AC86180DDE928ULL,
		0xA0C33F58FB77E182ULL,
		0xF891DED64F6B2F29ULL,
		0x05191599CA28DACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0281E641DA8C0A56ULL,
		0xA66B6EF701809E21ULL,
		0xFC679E342E0920CBULL,
		0x194313D897DFC9F6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF147B8E28C6E2A24ULL,
		0xEB1DB269AB316303ULL,
		0xFA6FC7B687F48013ULL,
		0xE2FDE76B3E286189ULL,
		0xEBD96890C59FC810ULL,
		0x08EC328156722B49ULL,
		0x10BBFF8F0A08502DULL,
		0x5C3456FBF2D16AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38D3E5FE225DEABULL,
		0x3E2D319C8023CFFCULL,
		0x7657B6F2053066C3ULL,
		0x12C2D0D1493E36A2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAD88F858C5A0AE76ULL,
		0x3E1FACF6336D0179ULL,
		0x8E75B7A0A6F833E7ULL,
		0xD3010E169D02013BULL,
		0xD4DE8E7D9BFE4D12ULL,
		0xC7E512A620FEFC7AULL,
		0x86387F9B6513593EULL,
		0x6573AF8D3CF683CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46921EFDED60216FULL,
		0xEA20719F19467BB5ULL,
		0x7AD8A8B1A7D77338ULL,
		0x622D1D0DA99991BDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x26985B79925342EBULL,
		0x0E3F53881E4F51C8ULL,
		0x35A21CBF2F5BBC96ULL,
		0x465FA2AF3A425CCBULL,
		0x8978AC68FCED2361ULL,
		0x3C30032213FC7BD7ULL,
		0x5F7FC819026C3E95ULL,
		0xD11ABD35BA460997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E81F30F1D8687EBULL,
		0xFD5FCA9715C9B3C6ULL,
		0x6299D0758B6D06BCULL,
		0x5057B8A8E0A7C943ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC3FA4C34AE10FF5FULL,
		0x88B66853BEA2ABD0ULL,
		0xEF8A57245362C99FULL,
		0xB9B16895AFF16E92ULL,
		0x617519C935400FF1ULL,
		0xFEACC58D204C4A84ULL,
		0x48D253F83F9ACD6AULL,
		0x3867DF5E9A97233AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5C201295935E7BULL,
		0x565BBB4689F5BB77ULL,
		0xBEC2CDFDC45D4781ULL,
		0x191C90A0A260A939ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2C3326E09C779C62ULL,
		0xCC024A6C1FF5D7E5ULL,
		0x51E6D3DD3C77B84AULL,
		0x57E8A758D646A876ULL,
		0xBC5821A2655808FFULL,
		0xD341B5526C06190EULL,
		0xEED63CEE7FB45978ULL,
		0x313412FE9B079A48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x214824FBA788F359ULL,
		0x27C334A828DD9015ULL,
		0xC5B3DF44313D003AULL,
		0x25A37923D9678F49ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE5A32DC99D21A5DCULL,
		0xBE6E2A763894BBC2ULL,
		0x50D04E03407CE298ULL,
		0x9194EC83DDDA7660ULL,
		0x340D2E19E5C56EBBULL,
		0x0534E8D1B348CA17ULL,
		0x3A2CB203E646D7B4ULL,
		0x1FE7BCE16BFF5746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9805A1B870165CULL,
		0x8448B996D562BB34ULL,
		0xF372BA976F00E751ULL,
		0x4DFAF5F9E5C16ACCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7C5F9EF58221FC12ULL,
		0xABB25920F277B18FULL,
		0xC3C3853F5A497BAAULL,
		0x1B1B38E0086D7457ULL,
		0xA17031EA65D64CE3ULL,
		0x5FC2E25FDD7FCECCULL,
		0x06FC37B50E32D5EFULL,
		0x062DD7F3CF3BA5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730707C09FF165EAULL,
		0xE29FF35BD37063EFULL,
		0xCD33CA1F75D53D32ULL,
		0x05E94710CB480D36ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2EF9193003DA709CULL,
		0xC06C8F4995FC7D75ULL,
		0x88479058742DDBADULL,
		0xE66F6427B744E38FULL,
		0x1F34CF8122EC27E8ULL,
		0xC3A70AE1E88E2062ULL,
		0xC16B3B3490569825ULL,
		0xA4EFCD33AADAC5AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0CFE65B32E860C2ULL,
		0xCB382CD21B154C05ULL,
		0x3E325A25E1087148ULL,
		0x6207D9D313BE3BA6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD893FF7E547302B2ULL,
		0x6785B9782860FDF0ULL,
		0x352C5679AC8F2D27ULL,
		0x1DB0E496117E22D4ULL,
		0x9CF102F3475FE2BBULL,
		0xF2C54F10805F2776ULL,
		0x167553FCF22B5DB9ULL,
		0xDB5CD4B75B1A74D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x245A6F9AECAEAF47ULL,
		0x70CF75EB3680D98CULL,
		0x8A96CE059EFF16C1ULL,
		0x2D7877CD976B7A29ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFF70292B0ED772BDULL,
		0xDC08CC36EB28481EULL,
		0x64325BD6B3E1F58FULL,
		0xBE4F9F1B89912F32ULL,
		0xEC1F77D280308D4EULL,
		0xA69BC69CDAD5AC1EULL,
		0x354AED73691F8570ULL,
		0x41A3F675BC5086D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C1BF26A160C6DCDULL,
		0x9728477F66DFD4B6ULL,
		0x4D519AF84E8FC448ULL,
		0x7CA634957D8532FEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6C7B09BD61F45F43ULL,
		0x6CDD6A9709B80207ULL,
		0x410AE72A47639EA6ULL,
		0x19A16EA65113CD79ULL,
		0xFD6CB8F5A85D00DBULL,
		0xE6E2BAF13FCF3E02ULL,
		0x76832F403E5F44F8ULL,
		0xF761FEA39D50B807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9E7E345FC28530ULL,
		0xB2852A66827B3679ULL,
		0xD883EAB38987DB98ULL,
		0x522D3AEFAB0F1E94ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2C00FEA97F3892BAULL,
		0x5EADCF49EE8D77ECULL,
		0x36F71DAE623EEF0EULL,
		0x4A42ECEE39B8BAA6ULL,
		0x26FB80BA0AB17C06ULL,
		0x61400E836CBB3971ULL,
		0x01872A1DAC141300ULL,
		0xB717668C05A49AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5561A471590FFA0ULL,
		0xCE2FF6CC1257FEB7ULL,
		0x71075E15ED39C11CULL,
		0x77BC25B71027B02EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6A2E4E2AF178823CULL,
		0xF588DB1EC32120A7ULL,
		0x87E6B81F2BC088DBULL,
		0x17E3F82B185EED8FULL,
		0xDD510E5EF90250E1ULL,
		0x765071C4CB6CB00AULL,
		0x130B6A491CE0B468ULL,
		0x113D91E59E6F6B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44367043E7D08401ULL,
		0x8579BE54F5434244ULL,
		0x5B987EF9751B505DULL,
		0x2707A0409CE8D5A8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x776E1A8995471D87ULL,
		0x691811CFF66ECAA2ULL,
		0x8F9AF034E1EAF4C9ULL,
		0xF2B1D91105EA5C68ULL,
		0xBDBCCED95AF8BDCBULL,
		0x580FE011D8CBE0DAULL,
		0xB0B9E7F4D15A3AAEULL,
		0x117EDD17F0D58E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA174CECD16334A2EULL,
		0x7B73547624B22B1AULL,
		0xCB335E8BF54FAAAAULL,
		0x0B86AA9EC59D7B58ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBE2FCC2C3EA0A928ULL,
		0x7DF79C1A2213BABEULL,
		0x59DD4990500E520AULL,
		0x65DA3161192A1150ULL,
		0xF828D5597A7EF01AULL,
		0x7972967027733CB4ULL,
		0x6FA93B963CD29CEEULL,
		0x59B169D0E45AAD9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x943F77746D784F05ULL,
		0x84F9F0BFFD2EBD9BULL,
		0xECFC21DD57519D70ULL,
		0x362FE662FE9FD688ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE73E55251993D979ULL,
		0xEA442D512EB1B423ULL,
		0x669E7A81950DAFDDULL,
		0xCF7CE2B56CB65FCFULL,
		0xCB6B4D7948E080ABULL,
		0x7B6EB33E219EB4ABULL,
		0x61AD30E5338D3066ULL,
		0x5F980566ACCBA7A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x192BD525EAE6F515ULL,
		0x3CB2C88A2C4085A4ULL,
		0xE653BC873C02DF14ULL,
		0x000DAFF312F14281ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD1F7E807933452B7ULL,
		0x8630E5C757F62673ULL,
		0xD2ADDA5CA3DA07E9ULL,
		0x97EF200068FE5702ULL,
		0x6B20F7F51914B3DDULL,
		0x1A0CE21C4269BE71ULL,
		0x324763C59ABDDE96ULL,
		0x1B2BDEE7EDFE292CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8DCB6694C470630ULL,
		0x641A75F933A86B49ULL,
		0x4946A9B19C091231ULL,
		0x2072366DBCB87392ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x981F0FACFAD18850ULL,
		0x5C1A2EDF221C89C7ULL,
		0x0825459D514EC179ULL,
		0x0BB6FB629492B4AAULL,
		0xED51DE4AEA4F2C8BULL,
		0xB6A98A684BA272F8ULL,
		0x3DD4CD4E5F5A1CC5ULL,
		0xD46AF5F85F14E175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2460ECBC292299FULL,
		0x7944BA5A5C399ABAULL,
		0x35BBBF3F78AF06D2ULL,
		0x13977E40B1AC2C11ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDB19A0D3A7BA30D9ULL,
		0x88AB10BFB6192673ULL,
		0x53F7CAF681329C70ULL,
		0x35A7B974BC5B5424ULL,
		0x4C8F13DE1C96FC4DULL,
		0xB0A7269E59F1B2C7ULL,
		0x01A946F40A76794CULL,
		0x80EEDCA432950823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385693CBE623A719ULL,
		0xC17ACC410FF9B009ULL,
		0x931853300EC89DD2ULL,
		0x591C79D43E7A8956ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDC5BDC5618388634ULL,
		0x31481DCEAD1A9D0EULL,
		0x3CBD893CA5318433ULL,
		0x6CFA86E750CAA06CULL,
		0x8B26E883B3C35709ULL,
		0x6959659DE7A2A897ULL,
		0xCD659891732012C4ULL,
		0x9C28C646F4C6936CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84225FE2C7377507ULL,
		0xD48D333F0F3FA38DULL,
		0xB9D22ED3BBF44D5AULL,
		0x1B07F56FA6448292ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC30BB5B7C99C8E9DULL,
		0x22F03BA079A08DCAULL,
		0x6233AA52B4C8B44CULL,
		0x4F59BA6E2AA47AEBULL,
		0x16506EFF4D47523AULL,
		0xC4EBD1450531B89EULL,
		0xBF2341621EFFC9FBULL,
		0xE8A2BBD51DF86EB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FC2F9D4232C858ULL,
		0x5DF14BDF3F01F542ULL,
		0xC16F5EE34EC0AFABULL,
		0x57819C109D84EA57ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0FC13171ACE07327ULL,
		0x6F2B3690F0B89EA4ULL,
		0x4DBBBF0AF5A2D97DULL,
		0x6CF0D48BCDD64F29ULL,
		0xF0F5E8E71BCE95ACULL,
		0x0216C96EFA055889ULL,
		0xAC874F89FC86F725ULL,
		0xBA509D31D498450DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD441C3BFCD8AAED7ULL,
		0xBE8D1D0A0D83C31DULL,
		0xE9D18D8671AB88FBULL,
		0x14E829F15C708F30ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD74ED293FF6BB2CFULL,
		0x82B8BF059765196DULL,
		0xABF9303FF4BF3146ULL,
		0x37779C3C53F36232ULL,
		0xBF8CDB98F7EB7849ULL,
		0xF5A5F1678A4E6AC4ULL,
		0x1D7AC449D5E49DB4ULL,
		0x48A09195D3E61065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46376B48CC5F8F34ULL,
		0xF95A94641F08F2A2ULL,
		0x0C325335B4AE9A22ULL,
		0x7F4D3879C819D135ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x78195927C04D548AULL,
		0xC67D15685406313CULL,
		0x37D84503011A8E8BULL,
		0xE4EEEF6E67F57E57ULL,
		0xB88A355D793CCD44ULL,
		0x22F2BD29FCEE16D6ULL,
		0x9A522A4FDFC13A32ULL,
		0x105700140E56FF4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC9D4507BF53CD14ULL,
		0xF68529A3DF5D951BULL,
		0x200A8CDE37C931FCULL,
		0x51D8F26888DF636AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5C638A4F6ADD84F9ULL,
		0xDFCFDF6F1B131B87ULL,
		0x457F094762A5EC54ULL,
		0x1A7FEEB632570A7BULL,
		0x67682104B80A1B6EULL,
		0xD88E0EC1074FCFECULL,
		0x3746E28548DFDB2BULL,
		0xC53E81E4AD11892BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D87102BC5D9B9BULL,
		0x04E6101630EBF89EULL,
		0x7A04A91033E074D7ULL,
		0x61C736A7E2F166E5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDCC16737D05E4572ULL,
		0x1D2BDE2BAF6DBDBBULL,
		0x3037E1ED313259E7ULL,
		0xD7AC0FFEF9B22733ULL,
		0x941B88596DCD5FCCULL,
		0xB5D41CAD7250EB82ULL,
		0xA238E25C3F6D8972ULL,
		0x49BD02DB03F437C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D7A47E1CDA7F6FULL,
		0x1AA81FEAA770B31DULL,
		0x44A97B9E9B74C0EEULL,
		0x49BA7C818FF26EFBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1641847B32C54F1DULL,
		0x0C78311314765A6CULL,
		0x76C35B57C8BF7819ULL,
		0xF8075F6AB516FB12ULL,
		0xC3ABD31E173DF89CULL,
		0x0E7C44990B8FD0B1ULL,
		0x2A17848D5DAF277BULL,
		0xB193C7AF8489D579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C2DAF2A5F83A47ULL,
		0x32EA5FCACBCF54CFULL,
		0xB6410853B0BF545DULL,
		0x53F70378618CAB0EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7D9970591307AD94ULL,
		0x2AAFF0C2D140844AULL,
		0xD02D4B60B396FBC9ULL,
		0xA84BD65930DD274DULL,
		0xCBF3A4D47DB9A7A0ULL,
		0x52E1084E05608ED6ULL,
		0x13163B6C956CCB79ULL,
		0x920F93607D1C02EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3C3E7E3BC969298ULL,
		0x78172C579D95B82CULL,
		0xA57A1D7EE1BD2FCBULL,
		0x569BB6ABC30596CAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA6ABB696637E38F1ULL,
		0x11B852FDD499DEB4ULL,
		0x6BBF5EAD4E29EE37ULL,
		0x3880C36CA4ECBC1DULL,
		0xFC641F08EB22D3D9ULL,
		0x0B2FBBA2CFD27070ULL,
		0xD0AD96AEDEC31EB4ULL,
		0xD55D7C15B77327DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8851E94AA9AFD4ULL,
		0xBACE2D28ADD68F7AULL,
		0x6583BCA25F207CF0ULL,
		0x64612EA5E004A698ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFA4D3A9B5AD35937ULL,
		0xD2685F8AA3626AA1ULL,
		0x0AE2C66E6436BE8DULL,
		0x0C50C6B76D96536AULL,
		0x17636CA5F0F1D71BULL,
		0xABEA63F5E97F0A5BULL,
		0x5DCCF0DD142A2BCAULL,
		0x3CEB53BA1F4B3002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730F5B3D1EB9488FULL,
		0x5733360B4C3DF427ULL,
		0xF74E873F62793EA3ULL,
		0x173F345812BF73C3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9877279A901ACB69ULL,
		0x99315DF16851875AULL,
		0xD004234E265EE26AULL,
		0x3274C9A67F096E6EULL,
		0x6780874FD516AAD8ULL,
		0x2593E28DD2A69736ULL,
		0x653E909451AB2B1AULL,
		0x61A63956CD0B8CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF58B3D74317829A0ULL,
		0x2D24FEFEAD0BF96DULL,
		0xD74D995245C7484CULL,
		0x31214C88EEC05511ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x63265E1DF06BEF56ULL,
		0xB9C275B7263C2184ULL,
		0x0E3A459DB8AB7325ULL,
		0x1A3B2630F7E5A99EULL,
		0x5AECED423386663FULL,
		0xCEF8FFAC99750782ULL,
		0x45905B157729EB85ULL,
		0x307A0B2D6FC96418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE25195F1965F1DBAULL,
		0x72B86955ED9B3EDDULL,
		0x61A7CACD68E46902ULL,
		0x4C58CEEF8FCA8538ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6ED5C255B9FF2FC7ULL,
		0xCB1C8AA0BFD362C6ULL,
		0xD4D16AD16E2920CDULL,
		0x92CFB3222F4A0630ULL,
		0x650C6C74BD709257ULL,
		0x443BF1661A5F84F3ULL,
		0xD947FC087A9300E4ULL,
		0xAF321C2A35C116AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EADDBA9D8B4ECA0ULL,
		0xEC025FC8AA011EE7ULL,
		0x1580D4139FFB42AFULL,
		0x143FE16629F3638DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0EB0DFF03DBC9462ULL,
		0xA253F01485340939ULL,
		0x5A7BC09DDB966E70ULL,
		0x8F6AA81A13EED069ULL,
		0x760D45FC59261D96ULL,
		0x7E13AB96BEC3F96AULL,
		0x38E54D271178EF08ULL,
		0x5CFC73B05C4A54D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94A943657964FABAULL,
		0x593F6874D64B0F06ULL,
		0xCC85346A7389E9B3ULL,
		0x5CE3D447C6F7680FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4E7C185CACF52084ULL,
		0x229B5E7F6341699EULL,
		0x2E300BCCD3F258CDULL,
		0xF281DF8248465B0FULL,
		0x7AB8A972770A26CBULL,
		0xE52E5EDACC9AAD23ULL,
		0x68D225F2D3DE681EULL,
		0xAE5993EBFB30F9AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E53F5A5876E695ULL,
		0x277D72F9C2371CE2ULL,
		0xBD61ADD846F5CD63ULL,
		0x53CDD489918B6AF2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA8809F6BCF8B371FULL,
		0x9002CF4B043D3530ULL,
		0x1BF2295D5BD8D269ULL,
		0x89161B35200C5C4EULL,
		0xDA365EFE91387310ULL,
		0x00E725ADE914D7ADULL,
		0x1153AE06AC5A6E35ULL,
		0x2267B845E0E5A8FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C92B9355DEC4C50ULL,
		0xB252671B9D5538FFULL,
		0xAE5DFE5AF1452E47ULL,
		0x247B759482237192ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3A8B068D0F5E1347ULL,
		0x4A675A7EDF08D236ULL,
		0x15DE1578B8E28435ULL,
		0xF36F4EE5F9550B76ULL,
		0x3D210A5CD5077AA9ULL,
		0x1FCC52DC605E0781ULL,
		0x8E7E09AB756610F5ULL,
		0xFC5E9B6498583014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D729054AE7A4E01ULL,
		0x02BBA7352CFDEF65ULL,
		0x3C9384EC26090898ULL,
		0x697A5FD4966C2E83ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x60AE0F7373AB0CEBULL,
		0x40614F9D3FE6A81BULL,
		0x2DE9597A7671F4DEULL,
		0xA62357D0FCE7D52AULL,
		0xA62E3E84D3612BF6ULL,
		0x023714B53BFF903AULL,
		0xAD42A45A5E0BB49FULL,
		0xA25360FADB6C7B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B8B572AD4179712ULL,
		0x948E628427D610D0ULL,
		0xE5CDBEE46C2EC478ULL,
		0x3E83BD0D8F021AD3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1C7DFDA0F1F5F856ULL,
		0x5F750550E75DB711ULL,
		0x4D4FB202468B6B56ULL,
		0x3D3BAFB5B548093DULL,
		0xDC947EED5DB7E42DULL,
		0x5E59A0438909CC96ULL,
		0x4BFE6DA9A5F30812ULL,
		0xC7A844E0C1679714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA88D4DCDB41DB65ULL,
		0x60C2CF573ED21575ULL,
		0x9513F930E89E9E10ULL,
		0x6035E9126AA87640ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2E6D899AF0BEC8ABULL,
		0xF1F5646FA5E37404ULL,
		0xAF3BAA6FB4C23DA8ULL,
		0x631ACC166CCD8DF1ULL,
		0x932437BCF51DB55DULL,
		0x6FB87FC69BAE2823ULL,
		0xCE354AD58943EFD6ULL,
		0x8745783ECC348AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CDCFA75327B771ULL,
		0x87585BEAC1BD694CULL,
		0x4B24C62214D7D77DULL,
		0x776AA568BC9A2C5AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC4AF3D068580CEAFULL,
		0x0130AFC5CB915AE1ULL,
		0xA5B48CA8C3465664ULL,
		0x30FB2ABE708F86C5ULL,
		0x60C88507AD466093ULL,
		0xB8606FF6ADA0AE6CULL,
		0xA7F5549E13B0ED52ULL,
		0x1543BBBFC6D66CD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2272FC2A3DF324F3ULL,
		0x5F814E63916B3EF8ULL,
		0x941F1C1FAF8990ABULL,
		0x59090935F463AE0AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x45627AEE7626AF2EULL,
		0x4E9DE41BD9DA8137ULL,
		0x81AD8D9C5BA524FDULL,
		0x12AE492A8FB39950ULL,
		0x16395960C3F6050DULL,
		0xA1CC8E3A4A8F3436ULL,
		0x9B152E016610C486ULL,
		0xCB30A243D19210EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E5BF4B8CAB7390ULL,
		0x52FB00C2EB1C413EULL,
		0x86D261D1822250F9ULL,
		0x3BE65F3BAB621C49ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xABE1696C1C96E320ULL,
		0x9BB3CCE875144750ULL,
		0xD2A7F145D68DAD7CULL,
		0xAC3E0AEBC054D9BAULL,
		0x9F20432CBC388E86ULL,
		0xCDF14F62E332545AULL,
		0xB07CA894E1AC499CULL,
		0x19905A5678F53E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AAB62100CFC0B9CULL,
		0x2D8595962E8CCCC4ULL,
		0x0528F75F56209AC3ULL,
		0x77AB73C1B4BC15FFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC22203CB700F5170ULL,
		0xF11DDDAF3D58F6EBULL,
		0xA08A7D68653F1795ULL,
		0x8B25109433CC1632ULL,
		0xE5D384F5AD6E109EULL,
		0x0C1ECE2A85A0448AULL,
		0x85E91A33DADC28A7ULL,
		0x3230134FDB81A93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF87C0432E65CA01ULL,
		0xBDB077FF13232389ULL,
		0x8124611AE1ED2061ULL,
		0x7E47EE6EC90B35A0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x324038737FB57A53ULL,
		0x93E2665DB1EAFE05ULL,
		0x98FE0B33C9CFE666ULL,
		0xAAD41A2D1BB020A2ULL,
		0x0A23C44FA24EEAD1ULL,
		0x160911049BE1F20DULL,
		0x14E74C3A638CF808ULL,
		0x10FDF18217C67794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB38F5C45976C55CBULL,
		0xD93AED0CD574EBF4ULL,
		0xB3535BDE90BCB799ULL,
		0x3085F37CA325E09DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x02DE3D32B6C11C1AULL,
		0xF35115046941A6C0ULL,
		0xDC8460459F993F5CULL,
		0x7BA50CAD45130959ULL,
		0x678C358D0762F3D9ULL,
		0x12E0E8DEF29CFA47ULL,
		0xCD8B3009BB451BE4ULL,
		0x8F8B2051D5D20E5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61AE3021CF715181ULL,
		0xC0B3A61C6C8ECD59ULL,
		0x5F2D81B76BDB6337ULL,
		0x4A4BD8D302412AD4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x206D5B741795E753ULL,
		0x3C37112FA2222492ULL,
		0x2F06345CFC460F95ULL,
		0xB59EA000731BB236ULL,
		0x9797156778E7E1B3ULL,
		0xEFFDD4EC4601CE5CULL,
		0x5D0353A1397AA75EULL,
		0xF153C043A263EFBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0DA88D00A016D50ULL,
		0xDBE4AC420666C650ULL,
		0xFD849E4B847AE7ACULL,
		0x080D2A0A8DF14851ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD4F92D10F5679264ULL,
		0xEC72221302F4E357ULL,
		0x7DFCF1C79AEF4EB7ULL,
		0xE41F146D33580C62ULL,
		0x2A5925F48BFDE292ULL,
		0xA0682AD5B1AF8372ULL,
		0xF5542A8C743FD600ULL,
		0xC614F71E2C1A036DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E34CF5DBD173884ULL,
		0xBBE87DCB6302664AULL,
		0xE87B42A0DC6912CFULL,
		0x4B3BC2E7BF348EB4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9564BFBD77AF9D07ULL,
		0x60FD57B435588C0AULL,
		0xF2594BBA0916C922ULL,
		0xCC178C5C712CB2D6ULL,
		0xA466A5926A177CA6ULL,
		0xA37AB18CA5ADA41DULL,
		0x09776D70A8BDC5A3ULL,
		0x79E6F9C6A0C54CA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCA15379372C206AULL,
		0xA533B294CD1EE870ULL,
		0x5A138A7315421F6CULL,
		0x64609FD84E7613A2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4C6B3945269862B8ULL,
		0xD0DDAAF5A71F416AULL,
		0x1E1BB267FFBDA910ULL,
		0x3652B82458B17880ULL,
		0xA0D86D8A011505B3ULL,
		0xD94B6832C3D73861ULL,
		0xE05D3BDF4F500F9EULL,
		0xC276BB4D923B9C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8B7BC14FB73F98ULL,
		0x120F227EB9119FE8ULL,
		0x6BF2958DC59FFAA5ULL,
		0x13F285A80D8AAFEBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x08E8051FAA4BB254ULL,
		0xD3D11FE4837344F1ULL,
		0xA85370CD7024B8EFULL,
		0xB5D810AE29B92036ULL,
		0x344A4997F108A9CFULL,
		0x491660EFB53C9591ULL,
		0x6618CFFB82F278DFULL,
		0x9AB06CB13DC58FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBEEF1AD7194EA8BULL,
		0xAD2383796A71787EULL,
		0xD0025022E022AA14ULL,
		0x2C0832FD550C75E1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4E06613D7CD91712ULL,
		0xF13B459AD1A7FE24ULL,
		0x74D07E533119FB24ULL,
		0xFFD53CEEBE46DA3DULL,
		0xEEC251C27D039145ULL,
		0x17A2C227DA1D6AF7ULL,
		0x18B1C779DFCE4230ULL,
		0xEEC8E40D466672BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEDE841C0B60ACA8ULL,
		0x736417853205DEF1ULL,
		0x1F341A6A69B7CE48ULL,
		0x71A716E7317BE24FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0CF7592291A62903ULL,
		0xD2DE9A051E62DF3BULL,
		0xC67ED5508BEB1065ULL,
		0xE657BED28F388EDDULL,
		0x82A5D7B2064368D3ULL,
		0xC1332D394EC84CC0ULL,
		0xDDD1C8D7A886F284ULL,
		0x5824916EFF54B4A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71955D8F7FA7BA56ULL,
		0x80775086D01E43CEULL,
		0xB3A2A5538FF3101AULL,
		0x7BC5554C75CB5F56ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDF824530F930F909ULL,
		0x70A63EA0C6A2FCD1ULL,
		0x8EBA31DF7CF06B0EULL,
		0xD36652436450A584ULL,
		0x70639D27E649B95AULL,
		0x06A8B4DD09009B86ULL,
		0xEC5B5F1BE7F5A7B6ULL,
		0x71255B012D4FBDA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E4B991D28227EFEULL,
		0x6DB117701CBA12C6ULL,
		0xA44A5003EB675013ULL,
		0x1EF1D4701E26CC25ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9FB0D548384079BDULL,
		0x5A591996DD5F1558ULL,
		0x4CBDB4920A3976B0ULL,
		0x1DEDF90E3261466DULL,
		0xB1DBD9F63FFB5D2AULL,
		0xD23C350669C73343ULL,
		0xC0CD8334CB651A2BULL,
		0x087ECC1CF90B83A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06532FD5B7904E1FULL,
		0x8F48F88A90F0B165ULL,
		0xEB3F2E683B3B5931ULL,
		0x60C0455B2A16D107ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x47D434D584F0AEE2ULL,
		0xE1832DC1F5A4042AULL,
		0xB4B504FB10F45079ULL,
		0x15ACDCFA5519E98EULL,
		0xEACD4FBA4C1AA52FULL,
		0x578EF04F93FD1EF1ULL,
		0xE7A422956D85A525ULL,
		0x9F6118A87AFA7DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224E0A7CD0E53759ULL,
		0xE0BAD991ED369C13ULL,
		0x1712272952CAD404ULL,
		0x3E1685FC96488F97ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2FB43FC2906F2583ULL,
		0xA85E394EAD0C2629ULL,
		0xF21B9A9D36495D85ULL,
		0x8BB1E0768B242083ULL,
		0xFF19E26171E5BBD3ULL,
		0x1CD412BD3FAD5827ULL,
		0x3D23E1CFC1A61950ULL,
		0x57A605457B043A2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D8BDA39788908D6ULL,
		0xEFD9016620C73C19ULL,
		0x056F1F73F4F11F69ULL,
		0x0E56A8C6CDC4C361ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA6410469A55A96DEULL,
		0x44A6DA0D4360D0E0ULL,
		0xCEAB3B0ED6AC1C64ULL,
		0x2059F631DDE4FC96ULL,
		0x68E70B2CDC60FF6CULL,
		0xDCE365553D0E60CCULL,
		0xB30C3FAB5AF5F8BAULL,
		0x95AC77E693BE924DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388CAD125BC0842AULL,
		0x0E67E4B453832F38ULL,
		0x627CAE7E572F0821ULL,
		0x57F3C26BCC2EB41FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCCA4E7D2487E8CF6ULL,
		0x0952CC9589A15065ULL,
		0xF4F575A413FD029CULL,
		0xE6900C0D8B117ACDULL,
		0x7903D8383E008260ULL,
		0xA54A385F6A0AC53FULL,
		0xCCAA50F8F7148BAFULL,
		0xD21CB691AB241FE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC337002B7C91EBF6ULL,
		0x92572ABF473A97D1ULL,
		0x563D7A98C109BEAEULL,
		0x16D325ACF26E3782ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA5D9AF0BA1480BE2ULL,
		0x10C224A5C61F4DFDULL,
		0xEF4BAFE31C8D0300ULL,
		0x53F2D433C4747558ULL,
		0x72DDACC3CF71FC84ULL,
		0x42AE14881E3DD834ULL,
		0xF5946BAFB2FF9F04ULL,
		0x97EDCC481F3CF617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2C1541C6C338AD1ULL,
		0xF69930DA434D65C6ULL,
		0x6353ABF7AE7E9DA1ULL,
		0x613F26E86780FCE7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4C498CB0FADC7195ULL,
		0x0D7663E8A24F3C44ULL,
		0x055626613D8C4677ULL,
		0x4B541E3E3F183BFFULL,
		0x12091976CF38D2BEULL,
		0xE88075E125D06D6FULL,
		0xCD92292471EB63E5ULL,
		0xC9EFEDF8604B32DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A35453BD4BBE3DULL,
		0x9087E3543F3F7AC0ULL,
		0x890841CA267D1A97ULL,
		0x44F1711C8A41C879ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x997987686F83A9E8ULL,
		0x86A230E138DA207DULL,
		0x7CEC76364C2F9605ULL,
		0xED71680024DE55C1ULL,
		0x4427D51F88C15F3CULL,
		0x240C8C48352112ECULL,
		0x92E1BCEF40093B2BULL,
		0x72B2B4E6313D021EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7632A16BC37CF69ULL,
		0xE07F03991BC2EF8FULL,
		0x4A6E81B9CD8E5E6CULL,
		0x73F8422B73ECA64BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7413FF78C3CF39B3ULL,
		0x573E164CD8D8AA5FULL,
		0x7CC2453991BF87B1ULL,
		0xFB7F29B49D2736A8ULL,
		0x6EF8F895C2CB37E1ULL,
		0xD61A708D4F7C6645ULL,
		0xB359CA0F67A187CEULL,
		0x40B82105FAC105A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED08E5B3ADF986A8ULL,
		0x1F2ACB46A54FD8ADULL,
		0x1C164382F3B9B065ULL,
		0x16D41097D5CE0CCFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x069E9B5060261906ULL,
		0x95DFA9573119EFFEULL,
		0xB4CDFF69B95A8C05ULL,
		0x4039C5476EDF8C68ULL,
		0xE66E48A1954F6C14ULL,
		0x40C5B449C8E7A378ULL,
		0xE8B90F04DDCC5065ULL,
		0x00F65D85251C07B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AFD634C89F023FEULL,
		0x33386C4B037C33F0ULL,
		0x40463A22A5AE7B0DULL,
		0x64CBA70AF108B0F7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6032A69C4C7C9914ULL,
		0xD32ACE19374912F2ULL,
		0x977D389D7679944BULL,
		0xEA28E4BAF2182FDCULL,
		0x467BD08406A9F81CULL,
		0x50219FD88F0E72F7ULL,
		0x0FD3CDF0E8182F6AULL,
		0xADB1BBD9066A0323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6939A3549B7712BULL,
		0xB828883E736E23A6ULL,
		0xF0EDCA5FEA109E13ULL,
		0x328AC6F1E5D4A710ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA3E72E833CEF943AULL,
		0xF4CE48C50595733EULL,
		0xA8566BFA91093904ULL,
		0x0CE17E33856745B1ULL,
		0xE07530184D1F2993ULL,
		0x9C503519A52D9D1AULL,
		0xB1AA6BBE84FC5900ULL,
		0x70FAC817152EB2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF54C521EAF8FC27FULL,
		0x28B62A938A5AC53BULL,
		0x07A26A424E7E6F1CULL,
		0x521B31A0AA55D43CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x893DC8AF58320D06ULL,
		0xFCDC10CBA83D30C4ULL,
		0x354A1CCC93ABB980ULL,
		0x256CD6237C8EAA3DULL,
		0x134C5ACE88B0D0BEULL,
		0x848737F3BACFCF46ULL,
		0x8774187B881357C2ULL,
		0xFF6F2BA07BF480B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66934357A2710EDEULL,
		0xA8EE5EF96315F52BULL,
		0x5085BF22C68AC060ULL,
		0x0FED4FF5E2D9C5C7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFC56252D14B4AD59ULL,
		0xCCAC92B996848D4FULL,
		0x592A0D693585CD10ULL,
		0x32CF6849AE4AEBF4ULL,
		0xB318D094EB941CDCULL,
		0x74AB4860F14BFE3CULL,
		0xC37A2D9B833C71F2ULL,
		0x7B6E6791425C51C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92051B480CB0F8C0ULL,
		0x1E19511D67CC4A52ULL,
		0x5D4CD27EB07EB70EULL,
		0x0532C7D987FF0EB7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x317AA7D439E23D38ULL,
		0xCD54A271F10F0A83ULL,
		0xFE5F185F8004854EULL,
		0x23BD35CB50BEE477ULL,
		0xA5C82FCC5D14AC4FULL,
		0x26547C2110446A6AULL,
		0xC0D6F6EFA77CC608ULL,
		0x77833B65637C425FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD31C02A0AF3D38BULL,
		0x7DDF0F5A5B36D657ULL,
		0x9E47BFF25C89EA84ULL,
		0x613806D81530BEAEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB7400F105380B3ADULL,
		0x6040BF701046EFC5ULL,
		0x1B9E3B3BFB10B4CAULL,
		0x716797DA98D53DC9ULL,
		0x828FC864ADA19160ULL,
		0xFFD69F2D1F68A6B6ULL,
		0x4DE397B09F0397ADULL,
		0x8296F30EB11F61FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1897CE02197C4AD2ULL,
		0x5A1C6022B9CFAEDDULL,
		0xAB66BF739599389EULL,
		0x53CFAC08E37DC962ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE2BE6F75670DC19CULL,
		0x38F1C0E3BC7B6C4DULL,
		0x4B8FEC7A46FAF711ULL,
		0xE86D6AE380215BC7ULL,
		0xDF6C25F76E7B9C39ULL,
		0x2187B065A9B38A7FULL,
		0x84BC64DFC0D7F4EAULL,
		0x3BEDCB1E7635675CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CCC122FCD66F37BULL,
		0x3315EFFAED21FB49ULL,
		0xFF86E5B0E70951D2ULL,
		0x4DB991690C0EB382ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC533FFBA0CD4AC0BULL,
		0xB3157F2E705B6949ULL,
		0x07A06AE8B512F60FULL,
		0x8CF9E1FD50D285D1ULL,
		0xF3FDFA6B3FF7854BULL,
		0xD034B610D7FC23ECULL,
		0xF10F7FE83175196DULL,
		0xA518EB874114F512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCE72BA58B9278E3ULL,
		0x9AE885AE7FC8BE75ULL,
		0xCFED67600C74BC5CULL,
		0x0EACD810F9EEE6A0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xABBC403E92F499B2ULL,
		0x5F9D754D699051E0ULL,
		0x579A292225711666ULL,
		0xFA1EBD82DBE21890ULL,
		0x4DB4948992B4FDCBULL,
		0x93CB89391175EF7DULL,
		0xC0494AC539B3F952ULL,
		0xC4484EE42FDAFC35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348A4CAA59D24A48ULL,
		0x4FD3D3C60111DE7AULL,
		0xE27B4268B62818A8ULL,
		0x1CDA7361F663888AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x474A189C01F6368EULL,
		0xBBA8C24B48E52F03ULL,
		0xC1EB2D0F7EC989EFULL,
		0x4F926A03D3F2AD78ULL,
		0x638A32E5DB955973ULL,
		0x7D24E62548D9A571ULL,
		0x5DD5F3FF5BD81DA8ULL,
		0x8A9F0E22BF2A1FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DCDA6BA9A2180ABULL,
		0x4F22EBD41933BDD8ULL,
		0xAFAD64F720DDF0F2ULL,
		0x632E832C3433687AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEBE0A9B6FC3B96E8ULL,
		0xFCFAC2DA2B0EE615ULL,
		0x14DFDFCFEA12FAB6ULL,
		0x4A4D25A811E4F13DULL,
		0xAC9811EB3C8320EDULL,
		0xB9DD8556A492D205ULL,
		0x5EF28B46C94EEE0EULL,
		0x31F85FA93D26ADE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A7352A1F7B27B33ULL,
		0x93DC8DB698DA12EDULL,
		0x2CE08C51CBCA50E6ULL,
		0x352B58C725A2C16FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5755E5AE100CB394ULL,
		0xD1D62772722F7EBBULL,
		0xB928F250874FA922ULL,
		0x0D0659BBC95742CAULL,
		0x0891E1D04079BE99ULL,
		0xEF5EFC4400DE103CULL,
		0x57DAD49A999FFA6BULL,
		0xC3D366D40DDFE8C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CFD6A97A21F0298ULL,
		0x59EF998A9325E7A4ULL,
		0xC3A48143550ED528ULL,
		0x1E679D35D893D015ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8D1E0667CC3AF4F5ULL,
		0x598DBB0261B15EA4ULL,
		0x96DABD5F9C60B92DULL,
		0x484477D86A26676FULL,
		0xCC53FCD7F59BD861ULL,
		0xFAE4586D78E88F4DULL,
		0x58B8159548BBF600ULL,
		0x9D3373BF09E0FAC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1958E76415D16D8ULL,
		0x9772DB425436A430ULL,
		0xC22DF18868473D52ULL,
		0x1DE7A633E18BA094ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBDAB37D220381E48ULL,
		0x86CCA0C697BC498BULL,
		0x7EE4D7F6D58D0B7CULL,
		0x203103FF1C8E47BEULL,
		0x6B544F60B7ADAB55ULL,
		0x4EE84683338F8249ULL,
		0x18ED359CA5463240ULL,
		0x9685CCBC5A49C8EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2F002D63FF902AULL,
		0x3D4718403F09A071ULL,
		0x321ACD375DF88108ULL,
		0x780D67F483821B3CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDD72CA1768B7CE47ULL,
		0x93A182AF385AFB27ULL,
		0xC87FD6DE032F36CBULL,
		0xF70EA1D296B4545FULL,
		0x647D3D210B65BE28ULL,
		0x4D5CB8EBC4E4D51DULL,
		0x984653502AE0F647ULL,
		0x3414EB076AF86459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC809DCFF19D2097AULL,
		0x0F64F5AE72529D84ULL,
		0x62F034C46093C561ULL,
		0x322984EC779339ACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7AA98951E8175B57ULL,
		0xFA6E4EC9EBB46895ULL,
		0x27098F6AC03435D5ULL,
		0x85D7BC1BA203EE36ULL,
		0xF3965B8F579AA29AULL,
		0x688839A9EBB81E92ULL,
		0x1412336F6D5A006BULL,
		0x62263025123AD034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2FB2098E90B806DULL,
		0x7EA6DE02E908F265ULL,
		0x21BD31F4FB9045C7ULL,
		0x1782E19C56BED5F1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x097B9E1D146BCFDCULL,
		0x78E59939412687F7ULL,
		0x717BF6CB0133B4DEULL,
		0x55ECEEE9ADA6B75CULL,
		0x0064230DB43DAB66ULL,
		0x3255054FA3BA94F2ULL,
		0x0BEFF08946F5FAC2ULL,
		0xA56EDA96B65672C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1858D225D59344A3ULL,
		0xF184630B8ED8A3E3ULL,
		0x3719AB2B89B6EDB1ULL,
		0x64616148BE7BBFDEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9179B250E4A9C446ULL,
		0x9E2A831891921154ULL,
		0x09F59784011B54C1ULL,
		0xAE160E791595184CULL,
		0xD034E7A06E04DE99ULL,
		0x7A375D8F5C68C86FULL,
		0x2BEE8D5997F14E62ULL,
		0x81F5AB3951A2B6F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x795414213962D1E1ULL,
		0xC2626660491FD1EDULL,
		0x8F5E92D08EECF75FULL,
		0x788D78FB33BC403EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA4E759F13A2CAFE6ULL,
		0x1683850DDD7713AAULL,
		0x60CB33D218EFD794ULL,
		0xF618D46B7244F492ULL,
		0x0A916DC4E3348185ULL,
		0x627CA89D901116F6ULL,
		0x3F5C2ECA29B1347FULL,
		0xCA5CD756BAB9D172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x367DA52AF3F7EE2BULL,
		0xB5048C7140007C30ULL,
		0xC87A25D4493DA27CULL,
		0x7FE0CB4B29DA0B87ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x726412E6670108E2ULL,
		0xF4C255375654CE4BULL,
		0xDCD7DE4640B4656BULL,
		0x5F503932BD16B469ULL,
		0xB5A714E61256CBEAULL,
		0x1C37D5B05485E028ULL,
		0x9102855ED2A1CD67ULL,
		0x691B5A7E7522DF47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69312D0D1FE34FEBULL,
		0x250C0D63E2341456ULL,
		0x6337AA5984B8E2BAULL,
		0x795FA7F82043D909ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB2364E366427C243ULL,
		0xFCB747AFA29FCEADULL,
		0x9A6DCC86B1ED0913ULL,
		0x4BEBAD154E224575ULL,
		0x4AF8E748479D3580ULL,
		0xC8CC424E626E27D0ULL,
		0xFF91CBE0EEE605A9ULL,
		0x3CCFC27E10A67134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD328A2F1057DB499ULL,
		0xCB091F523EF9B798ULL,
		0x8A120FEA2811E047ULL,
		0x52C28BCBC6D71353ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5F7DBACA7EC38A37ULL,
		0x794E882F9BABB1D7ULL,
		0x9E48B9B551805551ULL,
		0x0834934A05296DD2ULL,
		0x9FDD2CFCED0C3DCBULL,
		0x98E0B80E69F69EBEULL,
		0xE06CA4DA97C45955ULL,
		0x4CE6699E9FE5AB66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A526855AE94B7FBULL,
		0x2AA9DA5356474223ULL,
		0xEE693227D8A59806ULL,
		0x726840D5C140DF17ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB626C1AB0938C472ULL,
		0x10100C0D1F657D16ULL,
		0x76097B5CF4DBD9F2ULL,
		0x28A6CC65F2C74567ULL,
		0xAE83B60437FCFE0AULL,
		0x9F407AF1DFDC711CULL,
		0xCBAAE53F25A50468ULL,
		0x2062D319F69DF7E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DB3C64B58C67A99ULL,
		0xB3A24BF45A1E4758ULL,
		0xB16782BC8B5A8179ULL,
		0x775222408E3A10EBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x72C42B95B87FF5F3ULL,
		0x3B9E246707449922ULL,
		0x93E39E856FE8356BULL,
		0x6E95C360B8156948ULL,
		0x51D4C38396127E74ULL,
		0xE0C8C16261C179BEULL,
		0x43D6307972253D11ULL,
		0x8E5C8D8F479503DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9859311DFF3EBE5CULL,
		0x996AD90189FCAB62ULL,
		0xA5AED08C616F4612ULL,
		0x1052C6A55833FC6CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9B817EABD5A8A446ULL,
		0x5FA068B1D4343320ULL,
		0x4D7561DD566D0465ULL,
		0x297AE05E094FC96FULL,
		0x0827834E779E88C1ULL,
		0x41692132697A9A55ULL,
		0x4592FB38B686E688ULL,
		0xAF27DF3E0CE74CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15EFC519730F4C8ULL,
		0x153B562D7C671BBFULL,
		0xA146AC486E733C9FULL,
		0x29660393F3A52CEFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x771E243E6E97ED8DULL,
		0xC5D8385BA716AB9AULL,
		0xDC62014DDFC27EA7ULL,
		0x8AC2A1C7D39B9844ULL,
		0x449E08578B230899ULL,
		0xF65D52A81BF2989AULL,
		0xA8EB3FDD582F76C8ULL,
		0x36F85CA0F409FADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA693613D15CB3586ULL,
		0x57B27D4FCD195280ULL,
		0xEF4D7C28F6CE207CULL,
		0x33A061AC0D16D577ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x38A731FD04EB0141ULL,
		0x62CE7C799CE9B8F0ULL,
		0x4613449A5537781EULL,
		0x675A61A1D03B7C22ULL,
		0xA1A132FFE4658849ULL,
		0x911B7E296A444D7FULL,
		0x0EDD3F1B80B1AF4CULL,
		0xD13D5B1D39D74ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3694C3F8EBFD40B1ULL,
		0xECE3369F630D39E2ULL,
		0x7AEAA2AF6F977D7BULL,
		0x7675E7F866309458ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x170B99EFA59B775BULL,
		0x54BF4AAF8415DB66ULL,
		0xFD56617876D2B3E2ULL,
		0x0DF92C49C81E0111ULL,
		0x56BC260BFD45BD1AULL,
		0x19EA309FAF3FD3C6ULL,
		0x4A8C70B8FCEEDD9FULL,
		0x5F68CB60F71487C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6F93FB73DF58B4BULL,
		0x2D828263878F4AD6ULL,
		0x0E2F1CEE02479980ULL,
		0x37875CAE752A2881ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC5BEF5EEC917D9C3ULL,
		0x26043E3B367EF586ULL,
		0x39F3544C2C241673ULL,
		0xFB1BF8A220FEB9B5ULL,
		0x6D6F57CA81B369F2ULL,
		0xD972A001AAB8448DULL,
		0x1396063A99D9910EULL,
		0xB1667779CDDE6B6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0445FDFE09B997B1ULL,
		0x6D07FE7A8DD92285ULL,
		0x223840FF026F9EA7ULL,
		0x5051B4B6B002AC32ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1E8EC9836500E91AULL,
		0x3056DAD86A3A3B0CULL,
		0xEFB3D1AE26F200D9ULL,
		0x016499EB0A2865EBULL,
		0x6E26052603641CB1ULL,
		0x08C1C8FC5EE9CA50ULL,
		0xDA69409C6E81C489ULL,
		0xBFEAD3E1D4CA8431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78338D27E5DD2F88ULL,
		0x7D1AB04E80EE42FCULL,
		0x5B5368E68E352D30ULL,
		0x7E400D70A0380552ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4EBAAB75B667942BULL,
		0xED9F1FCA2647E3ADULL,
		0xEFA86230A15E557FULL,
		0x92193609AABA506FULL,
		0xF91B3EF42C153B54ULL,
		0x7A4B8390EC350E00ULL,
		0x3302E493E2269E6AULL,
		0xAA7E252C0EE3C9DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C603B4418E666CULL,
		0x14D4A74D3627F7D2ULL,
		0x821650243319D94EULL,
		0x60D2BA93E08A46D3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF305E8E82AF31E50ULL,
		0xF9C04ED70FDD8DD6ULL,
		0x184822879F1F934DULL,
		0xD3B9DB3CE2298C9CULL,
		0x1CF515BB6BB5FD4EULL,
		0xE7418414024C4FABULL,
		0xB38BF820B9E9DE1DULL,
		0x175984C53FCAB8EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6722BA27F6B87CULL,
		0x4D79E9CF6731613DULL,
		0xBF0EF76337D68BBEULL,
		0x4B0390845A410030ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0FB918215CE05A26ULL,
		0x988E17202B82787FULL,
		0x4CD60BF55601C81AULL,
		0xFFE0976DB35BAFE1ULL,
		0x7DA754242125CE63ULL,
		0xB8B294EE91E05DE3ULL,
		0xBC89BB48FD170191ULL,
		0x020C69A4E89BA222ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB68F957E487CFCFEULL,
		0x03103289D2D06843ULL,
		0x4947D8CAE76C03BCULL,
		0x4DB845E83A75C109ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDBF7842E93527374ULL,
		0x73AFB6389767B738ULL,
		0x85D676EF5F20B9BBULL,
		0x24AE429DBAA2143BULL,
		0x561B797DBDE23937ULL,
		0x29BC86A5386C493BULL,
		0x2817AD9C8D898ACDULL,
		0xAC39AF1930549A23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA40B8CD8C2E6F567ULL,
		0xA5ABB2BEF77A9607ULL,
		0x795A3C2C618B542FULL,
		0x353E405AE730F573ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3D64BAA29CDB7856ULL,
		0x55AEB1B9D148B429ULL,
		0x89A4D701152F81A8ULL,
		0xB86BB8DEB600F1ECULL,
		0xDAFD161608B9F840ULL,
		0x88B1461F15F3450BULL,
		0x716BFAB400CD3B69ULL,
		0xB3D27DF57D64D73DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEF601E7E87655D8ULL,
		0x9FFF1A571364F3EBULL,
		0x5FAC0DB933A65352ULL,
		0x69AA6B4F52F8E50BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB4F312C3C070B600ULL,
		0x6A8D3BE7DD56124BULL,
		0x73A468C11ECC2175ULL,
		0x84284C8313868C28ULL,
		0x98855C746A7B7743ULL,
		0x2B0EF6442FD93858ULL,
		0x61F6EC938809E160ULL,
		0xAFA58E498CC51206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58BECC0B8EC46DE1ULL,
		0xCEC5CA06F7946F72ULL,
		0xFE4B86A7504395BBULL,
		0x16BB6B6DF8C7391AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6FC565C2EC2AEF99ULL,
		0xC9C6774A9AB0F1A6ULL,
		0x2B72B6A19DCC4BDEULL,
		0xDAA02DEA35222CA6ULL,
		0xD96CA95FC7EFB0AEULL,
		0x7BE210D96E473AF1ULL,
		0x4F54E656041BB000ULL,
		0x3AC8D7131864CAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E689FA99BF2AD6ULL,
		0x2D54F790F943B18CULL,
		0xF20CE76639E86BF1ULL,
		0x14701ABFD4184829ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBE5C46ECA41E12ECULL,
		0x7AE2B472781D8407ULL,
		0xF477755E30B0E305ULL,
		0xF251E56CFCF9E6CBULL,
		0xE5C720710DFFA057ULL,
		0x9E366FA74CC75CF8ULL,
		0xA1E790BEE7F3DC6FULL,
		0x9C70B28A55534918ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9EB17B4B80FE366ULL,
		0xF6F74747DDB550F9ULL,
		0xFCD6F1B49EE39B96ULL,
		0x2B0C65F5A756C073ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8E82790F26C1ACCEULL,
		0x59F9E2BB9419450EULL,
		0x3301418B310C7CECULL,
		0x889E33F37C032FF4ULL,
		0xD284477DE801E9D4ULL,
		0xCABA04CA63A3E99DULL,
		0x9F4C68ABD333679EULL,
		0x3D5D74F2C82394F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE2515BF970A63AFULL,
		0x719698C65E6DF27BULL,
		0xD858CB0C8AADDE7EULL,
		0x247D8FFD314B4C69ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x64499102281D9B13ULL,
		0x3CAC68A93FF347EBULL,
		0x7156C32700EAE7E2ULL,
		0xB1D9F47A1B6DB9A7ULL,
		0x6189D15A603C5F1EULL,
		0x902E5DECD9C404EEULL,
		0xA5FC6F4C06CCFEC1ULL,
		0x4C750B573680A785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEBEA46C7113BB4FULL,
		0xA38E59D1930C034DULL,
		0x14CF48700358B89DULL,
		0x0B39A36C3286977EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1818997FDB4B69C1ULL,
		0xDFB33DFDF9722839ULL,
		0x8CFA3680E8E2A992ULL,
		0x6107DD78746B72DCULL,
		0xBF065CCC18AD233EULL,
		0xD1CB41B4BA637EA9ULL,
		0x1F1B4339EB4EA3E7ULL,
		0xB4F53A11EEC6238AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730A5FCB84FEA8F7ULL,
		0x03DEFED1A436F56BULL,
		0x2B063119D68EFDFCULL,
		0x3D6E7C21E5D4B95DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8E342FAA4E49E24EULL,
		0xF833234D76FBCD5BULL,
		0x54B7F0412A53FBF6ULL,
		0x845107C2EB3F56F3ULL,
		0x987B6DFB8D68A270ULL,
		0xE532A52DA8D96FA1ULL,
		0x48E6B41283E2B346ULL,
		0x88045CD6BE81AFB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x308683014BD201F9ULL,
		0xFDB7A81487425F58ULL,
		0x26F6AB00BDFA987CULL,
		0x34F6CFA3327F6C4EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAF05FC35A3214BCFULL,
		0x346EEFACBAFD1305ULL,
		0x133D502C4AF1B36CULL,
		0xEF6DCCB4AD879226ULL,
		0xAB3DB6BB899EC7B7ULL,
		0x4EB7CAA4B89E1266ULL,
		0x585CD856CFDED5CDULL,
		0xCD3F18DE8117DA3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A2F1C0C10B2F593ULL,
		0xE3B704202273CE43ULL,
		0x31056D0F26056FE5ULL,
		0x66CB7DBBD711F741ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1A7620AC1F66E50AULL,
		0xFFE4398D9C7AA8E5ULL,
		0xD4D1789AC3191D02ULL,
		0x998DE74A7114C853ULL,
		0x7DDBA6A3FA22FA15ULL,
		0xE48D0760ED63F530ULL,
		0x45EA149950815D62ULL,
		0x58EF3EBD6FA14326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC910DD0340980629ULL,
		0xECD351F0D9510E17ULL,
		0x3590875CB64CF9B0ULL,
		0x4D1137690304C002ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x50F1709C01F1571AULL,
		0x311324388775033FULL,
		0x7F85D06A74C2CE05ULL,
		0x033375A935EEACD7ULL,
		0x6EB0BD92D2A35D98ULL,
		0x58BA1240AB665C3AULL,
		0xD754CA85D67AC748ULL,
		0xCAC74DBD5BD8AAE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF2D94674631401EULL,
		0x5CB1D9D1F8A6B3EBULL,
		0x761BE0484AFC62C2ULL,
		0x1CC8FFC4D8180A5DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBC12300F162E67FCULL,
		0xAAC09182E859C70AULL,
		0x1321B387A7C3D39CULL,
		0x3274E74D91D2C0AFULL,
		0xC29BA530DF68C610ULL,
		0x6F9CDEA27746FA48ULL,
		0x43F723A44B108BF3ULL,
		0xC6E4DBC1FD39EC71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F2CB5503FBBD2BDULL,
		0x3C099DA09CE2EDD7ULL,
		0x29D0FDEACC3899BFULL,
		0x386D8619286BD97FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE022407A5CD5190CULL,
		0xFC8B6F59A6AB598CULL,
		0xD1FD821B4BE4A9FFULL,
		0x33BAECE63E3D1A64ULL,
		0xCBF19E02E42DE781ULL,
		0x7404C8FAEB582344ULL,
		0x3898A59FA5D88B2EULL,
		0xF589E9B8A426E2EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25FFB4E83BA57B9DULL,
		0x3541449895C095C3ULL,
		0x38A617CDEA0952E5ULL,
		0x26339E4E9C02C94FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3D70D39AD3F654F6ULL,
		0x37AC99565F3D3274ULL,
		0x681487D0A181B5D1ULL,
		0x949E6B2E13865BB9ULL,
		0x9C22A00B6682A181ULL,
		0x5ACEB6E38B89EF71ULL,
		0x65C6A039E148FC02ULL,
		0x3409765D80603BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A94954C0B5A4F4CULL,
		0xB25BBF1D15B6BD51ULL,
		0x8390506812571E2AULL,
		0x4E05FD0F21CF3F08ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAB686EF1F171CEE2ULL,
		0x7C82BE2E06682ED4ULL,
		0xE1BD409F5E9184ECULL,
		0x928A720A2D031FE8ULL,
		0xE61D4F8877B2DC47ULL,
		0x191AAC07895D446CULL,
		0x80EB7D476857E879ULL,
		0x4B0B84EB29C22C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C23D33B5FE8321ULL,
		0x3678474C6A4056FEULL,
		0x04B1D938DB9E06E6ULL,
		0x36402CF25FD5A92CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6C249086816D0BDBULL,
		0xA585C3E484B3A296ULL,
		0x4C02C8F599851DABULL,
		0x0EB1368533F7DAE4ULL,
		0xFC65A2000F5CAE90ULL,
		0x3BECED015E631288ULL,
		0x6B8B71DBC3B5ED0CULL,
		0xFF4AE2BB73184923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE33A9C88C92EFACCULL,
		0x8AB0F218876862EBULL,
		0x42B5AF94A6864D7CULL,
		0x73CEDE584992B626ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEE46B7BE8C30131FULL,
		0xE50335EBF49FF0C4ULL,
		0x1C79B8D21FB0C61BULL,
		0xB6BB978000A354EEULL,
		0xE59D304C75A0F8A6ULL,
		0xE00C8319E644D093ULL,
		0x2CF9664EE1A74B92ULL,
		0x4DD29D4F64046179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x039BE3180214FD8BULL,
		0x26DEABC422D6E6B9ULL,
		0xC97EE8879E85FDE9ULL,
		0x43FEF148D949CCEAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5F0B9D222453A607ULL,
		0x47869D19B63C5ADEULL,
		0x69E5C70AFFBB02A1ULL,
		0x0A0BABA1106F193CULL,
		0x78F0F2B2EF84C483ULL,
		0xB45B75A91C0ED891ULL,
		0x6CA7D0F7BEFF7BA2ULL,
		0xFFAEC0DBDE5BC905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52CFA3B1B208D70AULL,
		0x0D1A1433E0708076ULL,
		0x8ACECBD159A75CC8ULL,
		0x7DFC4C44120EF00AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3009AA356B84027AULL,
		0x43500F65E42B9166ULL,
		0xDEE372BE0604DB80ULL,
		0x06104ABDCA10CA31ULL,
		0xB016F3240B01FD58ULL,
		0xB4A3427D8AEE75B3ULL,
		0x3C37F94FCB044447ULL,
		0xFF909E03FAD7991FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5371C18F0DCFA31BULL,
		0x138BEE0883910A12ULL,
		0xCF32749628A6FE25ULL,
		0x7587BF55061184D4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB8A29E0D69808E34ULL,
		0xA40A23164A635E97ULL,
		0x2D52D273E9718525ULL,
		0x075E2437C59D3CADULL,
		0xC8B1230BE3B2AD48ULL,
		0xA3130C6AC2F70526ULL,
		0x7BC30ADC0A2A8152ULL,
		0x811B3B1D17540FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EDD1D1360649B6ULL,
		0xD8DDFAEF3B0E2259ULL,
		0x8C466F1D6BC0B769ULL,
		0x3168EA893C179151ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9946B948A1E4F977ULL,
		0xBBFAD248C801D3AAULL,
		0x1221097FE01B9962ULL,
		0xA28ABDB660BB8508ULL,
		0xC2B2505403E97E71ULL,
		0xA008B8802E2B9FB6ULL,
		0xCC25F0AC4E409621ULL,
		0x442F89953B6B464AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FBEA5C1368DBFCCULL,
		0x7D46354FA27B88CBULL,
		0x5FC2C3137DB1E260ULL,
		0x419929DD32A7F422ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC21FDBAAB8CB4165ULL,
		0xEC93E17887306029ULL,
		0xA2979B1AAF16D7E8ULL,
		0x06E2DEE7161CD4C6ULL,
		0x0EDAE1CD551771EAULL,
		0x75EAC1668C9220D6ULL,
		0x65E2D34C62EF63AEULL,
		0x791AFF073D836EEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF69D60255A462CCDULL,
		0x6D6C96B164E13FEFULL,
		0xC242F8715E9FA3CEULL,
		0x00E4B9FA379F4C29ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD8C4E0B1AFAC920EULL,
		0x635DD053A552F403ULL,
		0x5525CE27BB6CBADAULL,
		0x0BCF85AFED476351ULL,
		0x140B7BF69B3E52BAULL,
		0x469EF171A7AE3F85ULL,
		0xB504B1845B1AA1E3ULL,
		0x4866089CF66E7030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD279474CBAECDB39ULL,
		0xDEF5A732893061C4ULL,
		0x33D827CD4160C296ULL,
		0x4AF4CCFC81AC0A8CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD4D695BFD8877004ULL,
		0xDB57A05851FFF6F8ULL,
		0x97AD2B98713E02C7ULL,
		0xAF3EDFE61E64F912ULL,
		0xD5FF91D958146152ULL,
		0x23AC77BF8B446E30ULL,
		0x1230400A1E60CB83ULL,
		0xC349B9810824CBA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C63C02EB8DE691ULL,
		0x26F166C6FE285238ULL,
		0x4AD6AD18F39C383FULL,
		0x2C30690D53DB3347ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x835BB53E1F18ED93ULL,
		0x52F228F991DACC7AULL,
		0x02CAF38F24E330A8ULL,
		0xEE9927A52757DA13ULL,
		0x5B13F8E5A02AEFCFULL,
		0x633709930FB59296ULL,
		0x7E81FCCD09D4B144ULL,
		0xA10CB2F9BFAB8798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0852A753E57889F0ULL,
		0x0D1D94CDE6CE8ECCULL,
		0xCA1679FE9A7580CFULL,
		0x567BB8B79ACDFAB5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD4677A8B82B3E261ULL,
		0x44476C9B3A7EED52ULL,
		0xC4F5FA1F42940AA9ULL,
		0xFFC3BB26A9FE177AULL,
		0xABA0741FC21080B0ULL,
		0x749DF7E5921FCA29ULL,
		0x390F635D6362764CULL,
		0xA827ED7460C79FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E38B7425127004AULL,
		0x93BA38AEEB36EF82ULL,
		0x3D3EB9FC03319A02ULL,
		0x75B0FA6D079FD205ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2FC6AB592AE15F62ULL,
		0xBA8EB90B98714F13ULL,
		0x2819E86CC6E2FA50ULL,
		0x51C5597AA97F960EULL,
		0xFD91AD6797DEA39FULL,
		0xCD732FCD2CA5A9BAULL,
		0x63E5C2E433C5FE2FULL,
		0xF671F1DA4A84F3C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD36668B9B5EDAE67ULL,
		0x39A7D180390880D4ULL,
		0xFC34D64C7646B569ULL,
		0x66AF3FE1B93BC5F2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF8EF597E07EE019AULL,
		0x3B12ADADFD93CFFAULL,
		0x2C2E32923D868001ULL,
		0x31F5603FBF46C94AULL,
		0xDA8787054ECE29B4ULL,
		0x94427BF104A3DCB8ULL,
		0x502BF873976A9C73ULL,
		0x786B9BF517CA7D2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x690D6447BA8834FEULL,
		0x3CF11374ADE6936BULL,
		0x12B513BAB759B929ULL,
		0x11EE86A147555DB8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x098C49225B32285FULL,
		0x8BA3C35E737C52C0ULL,
		0x9CF40FDC8AB153B0ULL,
		0x7E36DD3DFF4CB6B6ULL,
		0xAC8AFEEDB612430FULL,
		0x0A0BE2ACC1D04E74ULL,
		0x2CD3E8920F4F449AULL,
		0xE1AACB904312E989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA62E206B61E82192ULL,
		0x096769033867F811ULL,
		0x4468958AD075828EULL,
		0x7D9114A7F41B6113ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBB5EF7B01769C442ULL,
		0xC62EEF7410DDD9F2ULL,
		0xA7A302CC15BE17A0ULL,
		0xC5AB09B37A828125ULL,
		0xD0B282F09F779802ULL,
		0x27B5A97EA79A0932ULL,
		0xD22D2312768C35DDULL,
		0x684634E42BA20EA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5DE6767C32A56EEULL,
		0xAB261840F1BB377DULL,
		0xDA563789AE8E1674ULL,
		0x4016E391F490AE5AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x10F9F07DDF35C901ULL,
		0xB2899893D722503EULL,
		0x0088331050EAB67FULL,
		0x5DB777F25C9727F5ULL,
		0x54B117592C273134ULL,
		0x9A4F63FC9C4D922BULL,
		0xB55572F9E19E3736ULL,
		0x780ED10522BA0BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA34367BA6D071965ULL,
		0x9A5270130AA602ACULL,
		0xEB374427CE66E89AULL,
		0x2FEA7EB58434EDFBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x78BD0C7BC015B79FULL,
		0x3C06627BAE5DA749ULL,
		0x702D13054DD7769AULL,
		0x063A65200B7B5A94ULL,
		0xDD24781952CD9402ULL,
		0xFA618B035C452AC5ULL,
		0xA28A90DC0A3A8C1FULL,
		0x78B5C86ED6045B5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C26E03E0A99B284ULL,
		0x668104FB60A200A8ULL,
		0x90BE93AED2884359ULL,
		0x71362593D020EAA0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8C33186E219124ECULL,
		0x03025AF0F5530DA4ULL,
		0xAFE1DF9F35B67845ULL,
		0x60D633D1C46401BAULL,
		0x842505F83413ED99ULL,
		0x28FFADF572DB80F4ULL,
		0x7B1E340EF7832245ULL,
		0xC34CD21631C6F4B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29B1FB45DC866DF0ULL,
		0x18F62D6001E831F0ULL,
		0xF65D99D7F32D8E89ULL,
		0x5E3D631D27EC53ECULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x54D13F9B1970921EULL,
		0x6A4B09B26C7918EDULL,
		0xF6CC49F963CD09CEULL,
		0x8F475DE7813ED069ULL,
		0x8983307B0B5379FBULL,
		0xA0EDEF6AB65A7618ULL,
		0x638605765B9F136FULL,
		0x2DDEE4025B3A57F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE4A71DEC7D4AE6AULL,
		0x4D9C93897DE6A091ULL,
		0xBCB1198AFD69EC60ULL,
		0x5E5D36410BE7DE18ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE22E97E55AA9B8DFULL,
		0xB7915451BD369B79ULL,
		0x478A6EF105FAAE8FULL,
		0xBCAB987A23890144ULL,
		0x8F1AFDDC8E46FDB8ULL,
		0x0483F87FC07EA424ULL,
		0xBCB68350D9483960ULL,
		0x853AC1EFCF8C2CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x203046A27933653AULL,
		0x632837485002F8E7ULL,
		0x4AA1ECF146B332D0ULL,
		0x03646212F257AB5EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA1FF98F147214F89ULL,
		0xC7FE283CAA412918ULL,
		0x6948A3DE1BA5B5A9ULL,
		0x029F85ABF0F66EE6ULL,
		0xB080D3EEF271F6B3ULL,
		0xF7C412EF8E2D72D5ULL,
		0xC019CE4540BDB2BDULL,
		0x7A27D6EA8633B689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51F0E69440BF0C7ULL,
		0x8F18F7CBC50034D0ULL,
		0xED1D4225B7CE3DDCULL,
		0x24896C7BDCA38758ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD0C86FA5B6D7F09CULL,
		0xC264A6F067141C5EULL,
		0x1E2B055626521D57ULL,
		0xE5E616696FC7501CULL,
		0x8B771141D82E45A6ULL,
		0x41A3A5EE61EBE58DULL,
		0x83F6085D3B997FBAULL,
		0x5335C0E7BD466BCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8474FF6BCDB6492EULL,
		0x80AF4852F0182F61ULL,
		0xB4B0432CFF1B12FDULL,
		0x3FE0B8CF883B50C3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6A526BB0702489A2ULL,
		0x97C9E99A136EB356ULL,
		0xFAAF7077C6987805ULL,
		0xF7DCC8EAEBA0FD6FULL,
		0x6AE29C3E90FDFEAAULL,
		0xF228E1B724B590E5ULL,
		0x003D54A504DB7725ULL,
		0xE761B6131AE924BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47F59CF9F5D85C10ULL,
		0x89DB6AC986623564ULL,
		0x03CA00F67F2C27A7ULL,
		0x505DCFC0EA3C717EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF080F1F384987D40ULL,
		0x35F68CD110CF9980ULL,
		0x6FFA3F32B154F6F0ULL,
		0xE1C33B0726427D8EULL,
		0x64EE742455A699A0ULL,
		0xE03AB795211562A3ULL,
		0xBA652C30319C75CAULL,
		0x2C234F89CFC1102CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE62F583B534C0AULL,
		0x7EADCCF3F9FC3DC1ULL,
		0x1AFECE5A0E8E730DULL,
		0x6F01097BFCEAE432ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCC73E7933CE03F21ULL,
		0xD1EC2C076490303EULL,
		0x43DA514420856507ULL,
		0x2E24207B94EBA2D2ULL,
		0xEFC29B0E9F3CA1B0ULL,
		0xB1385557D940F916ULL,
		0x66968A3942D484B5ULL,
		0xEEE8C6694BFCB0FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6356EBBEDFE04486ULL,
		0x2048D711A43529A6ULL,
		0x7E32D5C40C111800ULL,
		0x24B1941CDC6DE86FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4E3E162385998E47ULL,
		0xA6FE5E86FE683945ULL,
		0x32AFE4C90E04913DULL,
		0xC360189EE83F0E6AULL,
		0xD1EA787CB05C4617ULL,
		0xAFAA14B3B606CA40ULL,
		0x959A72AE19A3D79CULL,
		0x430C8C941B2E75C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770BF8A5B34BF740ULL,
		0xBA3D7134036A3EE4ULL,
		0x679CEAA0DC56927FULL,
		0x373CF69AF1248972ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x30A4C644E0D6A4B8ULL,
		0x54332A7BF25EBE8CULL,
		0x6E6C573B457EC02DULL,
		0xE3CC0279079F2AE6ULL,
		0x017AFB3C74B32A37ULL,
		0x642ABA0E61098E19ULL,
		0x5182BED678E240D4ULL,
		0xC8101BD17A3C64FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68E6113E336EED69ULL,
		0x328AC89E59C9D642ULL,
		0x87D4AB1137145FB4ULL,
		0x163023912C9628A6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD17954CE56DC64FAULL,
		0xF9481F15BB571B96ULL,
		0xF017C3A045E21B91ULL,
		0x8E711E5DF6129987ULL,
		0xA49557E45C95F344ULL,
		0x81A02DA3DC600C74ULL,
		0x65E2D85EFABA26C2ULL,
		0x17D518CA2466C67CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FA460B4151E81AAULL,
		0x370EE5687198F4E7ULL,
		0x0FC3E1B97D83DC71ULL,
		0x1812CC5F5D540FFFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x12064DC851F60605ULL,
		0xC59EC16867D0D465ULL,
		0x82FE8D49DA9C39A5ULL,
		0x732447A54743678CULL,
		0x0761CEEE5453A797ULL,
		0xCA32707AE67F0374ULL,
		0x1606EB6BB002E160ULL,
		0x81A7859D832874CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A8B0528D660E954ULL,
		0xC91B73A69EAB579EULL,
		0xC8057F45FB09AE03ULL,
		0x32021D06BF44BDB1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4D034383B527FAD8ULL,
		0xAAC4D39127E7A104ULL,
		0x6BB3FDA402ACC7D1ULL,
		0x2B6F3A1F6A5643A2ULL,
		0x068FF8B5FCE571DEULL,
		0x4B3F0BCB89C4F294ULL,
		0xCC3EFA65810B2DEEULL,
		0x916A350BE33FE105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46622E873F36E4FDULL,
		0xD62093C79B23A2FDULL,
		0xBD0D28B52A559930ULL,
		0x413319E325D1AA7EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC292018A556F790BULL,
		0x11B4A2A254417B5EULL,
		0xDD1CA8B39B3553C6ULL,
		0x920363EC82BE1640ULL,
		0x10CED8212FB8896FULL,
		0x97C5A4DA9E368840ULL,
		0x8267E8D99D5CD7B8ULL,
		0x5E1314FB6A8DB8E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x414616776AD3E1ACULL,
		0x990B1B15D059B4E1ULL,
		0x38893900F6FD592CULL,
		0x08D8813E53C7889EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC97778F923C39F5DULL,
		0xEADF63476F3E336CULL,
		0x21C456D654D985E2ULL,
		0xF8F59649075FFD0CULL,
		0x1EEA055BDA673E4CULL,
		0xD237F04F1FFD5A6BULL,
		0xAEBF73E1FAA6618DULL,
		0x20CD129CD61D6DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6034449B8F16DF76ULL,
		0x1F2D0F062ED99F53ULL,
		0x122F8A61898C00F0ULL,
		0x57665990CFBE4520ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFB59E1033D0E6639ULL,
		0x9E14172F3C394419ULL,
		0x1C49A98256378D93ULL,
		0xF819FC9AFB94AFB2ULL,
		0x9DEBF93C95EA5743ULL,
		0x5CD7C6CEDBBEC41DULL,
		0xDFF85805D510A576ULL,
		0xF9678B31C04BF382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C60E0017DD75FBCULL,
		0x661B99E3DA8A607FULL,
		0x5B26BA5FF6B01D25ULL,
		0x7D78A5FD86DAD51FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7FC945F1B7290F05ULL,
		0x881E6B9035B6296BULL,
		0xD0C1EF8F44BAA45EULL,
		0x7B7ED62035E82952ULL,
		0x5F82E1725EE0E101ULL,
		0x61C3E7310EB71B1CULL,
		0xB9C527AD3B905F86ULL,
		0x0F7E2B97DC98AEF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD36BCEBCC8A758AULL,
		0x0B32BCD864E42FA1ULL,
		0x6405D3461C28D251ULL,
		0x48394EAAF4922180ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4F46A5264EEE2596ULL,
		0x5FED4D6027ABB53CULL,
		0xDC2F0D5541F8D2BCULL,
		0xB5F5B3EC08710D64ULL,
		0x8E2A87A99775C2CEULL,
		0x4B819424A303B67BULL,
		0x8221DF54BF1CFBA1ULL,
		0x62F0639CBD34FED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6996C852CA691264ULL,
		0x95294AD05A38CB93ULL,
		0x2D3633E9A0462CADULL,
		0x65A47D301E4EE116ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x98200A83BCC2BE36ULL,
		0x618D217C9421FC72ULL,
		0x86BE97D0C4B61594ULL,
		0xFCA6238FD7C77739ULL,
		0x1467AC31B3245417ULL,
		0xDAD16442D396DD5EULL,
		0x508DB8C2DA10E8F4ULL,
		0x3E7200D5A3E7F443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F8399E454273B1CULL,
		0xDCA20367FC86D869ULL,
		0x7BC804BD2338A9ECULL,
		0x419243462C35B937ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x70CAE93EDAAEEBFBULL,
		0x2FBD82474A2B8714ULL,
		0x3210693CAB124C9BULL,
		0x31C48A17D1A48805ULL,
		0x83ED5A7CA197580FULL,
		0x69A25098638ADBC2ULL,
		0xD864B2A0F63777DEULL,
		0x65E87FACBD3FF9D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x060657BED726006FULL,
		0xDDD578E610C825F4ULL,
		0x5102ED21374E179EULL,
		0x52477DBBE9239DE9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4B1BEEDCBF59F1D6ULL,
		0x99C12DC768B2D2F9ULL,
		0x1E0D34D5421A13B6ULL,
		0xCFAF9D1E6C3B9DE6ULL,
		0xFC473C4FFF8CED27ULL,
		0x57A93A42639F8AF1ULL,
		0xF184F232E5A758D2ULL,
		0x966988E80C7944EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDAEE2BCAE45290AULL,
		0x9CDFD3A2326172E4ULL,
		0xF7C9286358F142EFULL,
		0x2359EF90463BD8C5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7EBE7A54EE9933DAULL,
		0xF888979F3B8B5B64ULL,
		0x9936784ABC8B7BD5ULL,
		0x78845B12E19EF606ULL,
		0x5E090FB7560A1BBEULL,
		0x5531A64CA51B67D4ULL,
		0x22B21D9FFDA79920ULL,
		0xD6CF813AE9927560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7416CF8BB41956CEULL,
		0x9DE746FFBD9CC4EAULL,
		0xBFA6DE0A636C36A2ULL,
		0x5B5189D18D5C624BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x42E6CAAF1F504506ULL,
		0xBE296DCECEAEEF33ULL,
		0x633FD15CBD37CF12ULL,
		0x014E60C536215D2CULL,
		0xCB1D1563033C9728ULL,
		0x070B083B68DA3F0DULL,
		0x21BB9C1DDEA9A270ULL,
		0xA9701228C432CDE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6937F7619A4EB8ACULL,
		0xC9CCA6A05F144B3FULL,
		0x6518FDCBCA65EBB3ULL,
		0x27F112D255ABEDA1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF32424B90BDDEFA1ULL,
		0xC35B91609DF0E0F7ULL,
		0x8679ED2FA41C98C5ULL,
		0xE4783E423F12316DULL,
		0xDCC728313DF8AF8BULL,
		0xA694FB83423BE640ULL,
		0xFE8A5C8CB0183DDCULL,
		0xAFA21304ACAA36BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8B41C083EC80232ULL,
		0x7D78E6DC72D50E98ULL,
		0x4F03AA11C7B5C786ULL,
		0x768710F3E056512FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xACB9CBFE679D4E21ULL,
		0x0DD29D5E76454E38ULL,
		0xBF2C2892B1720BFCULL,
		0xBCC5D7A0D5BFA879ULL,
		0x9EDB88FC6AB36787ULL,
		0x016F6B74C0ABAC74ULL,
		0x2893CAC1F901D0EEULL,
		0xA481EC88FC5ED40DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415021763E3EAFE1ULL,
		0x445C90B30FC0E788ULL,
		0xC51C415DA7B70F50ULL,
		0x280EF3F64BD3226DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE847ED0B8D0CC9F7ULL,
		0xC4DE6E0F115B5AF1ULL,
		0xB3504516E73946CDULL,
		0xF712A90A7698A475ULL,
		0x5C33DF9DEE5791B3ULL,
		0x40276D00DAFAAF38ULL,
		0x71C49DCF4E8A3735ULL,
		0xC8EFA071C7BB7A2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97FB1E7CEE0C6F10ULL,
		0x4AB89C2F92915D4FULL,
		0x967FB1DC8FBD78B5ULL,
		0x4AA479EE1C6CC6E8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x584D109CFC7175EDULL,
		0x8936836928BA7A99ULL,
		0xBE5B710E84D6A1ECULL,
		0xF9730FBD48DB81E6ULL,
		0x1D5655265125C71BULL,
		0x7AFBB0FCDB8868B8ULL,
		0x9825EA5F90788B57ULL,
		0x8D1FD2A5E164D830ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB31DB44D080D0720ULL,
		0xCA92C8F1BEFA05EDULL,
		0x53FC3B3DF6BB50E8ULL,
		0x6C2C545CBDD3991DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x56E0816E4BB42502ULL,
		0x01CBE5906FCF8C30ULL,
		0x7960224CC8720D40ULL,
		0x82BBEA206254B1D0ULL,
		0xD406C4F04376561CULL,
		0x96037CD02CC0F1D4ULL,
		0x28BAF0E2D1CD40F3ULL,
		0xDE61D055A6054165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFE1BD184F44F223ULL,
		0x46506C77147371C7ULL,
		0x851FE3F7ECE9B168ULL,
		0x0540D6D7071C66D4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0724DA3F1EC35326ULL,
		0x6DEBDB818E7A0D86ULL,
		0x678FFCE922F9D605ULL,
		0xF4A3166B3BD69823ULL,
		0x477D453421451B0BULL,
		0xBB002B9600B7C357ULL,
		0x96427C0A29AC6090ULL,
		0x21E487A6A28539CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BD1FFC0F055799ULL,
		0x2FF253C5A9C10C7AULL,
		0xB56E666B52902B81ULL,
		0x7C8F39275B9D2C35ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x93C4B2FB55D5067BULL,
		0x75801E5AB9FF24DBULL,
		0xC808D515D22F8A20ULL,
		0xF4BA770319C9753FULL,
		0xE28ABB42D3E31812ULL,
		0x68498FB0E0046A3FULL,
		0x117398BB67F54DD0ULL,
		0x9045EB387E4FC26AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x345C7EE6C98A9C6BULL,
		0xF06B729BFAA6EA57ULL,
		0x5F3180E74099170FULL,
		0x5F1B6165D9A050FEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x49F2F4263943116EULL,
		0x9A0C2B082CD2A113ULL,
		0x25D652F67E41FE6AULL,
		0xE362168ABFBEE165ULL,
		0x6A70008433EF2C97ULL,
		0xE9295B7722287F96ULL,
		0x69EF0E9F2C642B01ULL,
		0x65330844438E8A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169307C5EEC3B225ULL,
		0x362FBEB73ED59167ULL,
		0xDF527E97152060B3ULL,
		0x68F550ACC6E770C0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDECEDB6013F0BFD4ULL,
		0x4BB60941CB0BE0A1ULL,
		0x8FC10745E7869BC8ULL,
		0xFB7CCEBF6DFBEF24ULL,
		0x1F48699E2E0CEE8DULL,
		0xACA3F9E36CAB5894ULL,
		0x41A793223CDCF6ABULL,
		0x37D429B54A59F58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x838E88DAE9DC2A18ULL,
		0xEC0D2103EC7B069EULL,
		0x4EA0DE5AF0533943ULL,
		0x44FAFFA877566268ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE80D1E74606BF1C6ULL,
		0x601C504E81A65045ULL,
		0x82DA5347D820B792ULL,
		0xAF9B5A4510B1CAD8ULL,
		0x970BB9DDE28E692EULL,
		0x67ADA636C0AAE96DULL,
		0x892D70850FA88C84ULL,
		0xF6043D9C8CF03A7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53CAB564018F9418ULL,
		0xC3E2FC6F1B04F68AULL,
		0xDF9907082B259339ULL,
		0x343C7F81FC5A797AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBD0BF3F60DFED7CAULL,
		0x79CA0B9F2B32F318ULL,
		0xF2BD961075B601D4ULL,
		0xC2CAD890188A9C86ULL,
		0x9CBA4ECBB03F753FULL,
		0xE838868B56DB19D8ULL,
		0xF0F0D7A80DAF64EBULL,
		0xAC5859359FE19AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00B3A632376A4300ULL,
		0xF22E044E0FB8C940ULL,
		0xB67D99027DBEFCD8ULL,
		0x57E81685D407920CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x74ACC334039246BFULL,
		0x31AF1892E14EA238ULL,
		0x57527FC5583567D2ULL,
		0x0739EB744161BD4EULL,
		0x0FEC0FDB74484ADFULL,
		0x9AB3E0FCDC34AEC8ULL,
		0x7AC4A48BC6F4F89FULL,
		0xEF4794AA7CC27EE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B71DC7464D691EULL,
		0x28627E1B912093EAULL,
		0x9082EC84E0924F83ULL,
		0x0BD9FCC2C6409384ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4E1F83F58B48B961ULL,
		0xD2DCC145C1E2D518ULL,
		0x86899C9F36EE6470ULL,
		0xD5E7834278882F8EULL,
		0x0A6CF3FA66A27C88ULL,
		0xFF25E211E07884BAULL,
		0x32314FF836A98DCCULL,
		0x071723407AB77D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA4BBB20C76735CAULL,
		0xB27C4FED13C688B5ULL,
		0xF9DB7B77541970DEULL,
		0x6356BED4AFC4D44BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x99EFD6DD6F69CED3ULL,
		0x0D6E592E069812D9ULL,
		0x3AF309EF402BC3C7ULL,
		0xD3435EA0F4CD2212ULL,
		0x4BC6B276246C7BAFULL,
		0xC5AA7A7BC9D88669ULL,
		0x4F04D1D3D02FDC23ULL,
		0x72384732B38F2F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD96E5466D7842D66ULL,
		0x64BC878DFCBC067AULL,
		0xF5AA2F6027467116ULL,
		0x479DF0279C0E20DDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x71D17AA2A9AF74F9ULL,
		0x35198072029F1BC2ULL,
		0xD898888C9F2C6AA2ULL,
		0xFD903EF8A77D3DE6ULL,
		0x7787609D9AAB8328ULL,
		0x25A1DA75859EFD4CULL,
		0xBAE38CD849D11EEBULL,
		0xDCD154EA96F704D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE9D2079F24F1E2ULL,
		0xCB1FEDE3D838B51CULL,
		0x965F70A794370189ULL,
		0x44A2D9CB1027F508ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCC44082749D1ED70ULL,
		0x0D106AFC3AE88922ULL,
		0x7B2AF1C60D73F0C2ULL,
		0xA58F1792B9B97EDAULL,
		0x213DABFA953F84F7ULL,
		0x00BFEB45162EB65EULL,
		0xD6415E28F1EE07C7ULL,
		0x31F354965CCA72B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB6B8F59713FAB4AULL,
		0x298D573D85D79B1BULL,
		0x48DEEBD9F6C9184CULL,
		0x0FADA5E47FC685D8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x004B4F7035D7DDE8ULL,
		0xEF47A3F1480923FBULL,
		0xC49EAA583BDE1A1EULL,
		0xF6ADB7A66C99FDA5ULL,
		0x961742F72066EFE3ULL,
		0x1AAABF5785BD16C4ULL,
		0x148BF08488893ADEULL,
		0x22CDA3CC8C0FEB61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47BF401F051F7A7EULL,
		0xE4A00AEF221A8529ULL,
		0xD1645E04803CD716ULL,
		0x2134080336F6EE0EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x257C4AEAD5C72858ULL,
		0xF982914F71D59AE6ULL,
		0x73D41DD1DDE4CE1AULL,
		0x972BA40DC04A23ADULL,
		0x598A1CBCC5D9176AULL,
		0x30CDE8EC0429A703ULL,
		0x01C03335A2E5E488ULL,
		0x7E1B5AB570246DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFC8EF03400A4E6ULL,
		0x3813245810046565ULL,
		0xB65BB7C80C04BA52ULL,
		0x4F3B1AFC65B2767DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7052AB6736461AB9ULL,
		0x6ACF26E4077FD4EEULL,
		0x4B78684E8EEBEC25ULL,
		0xB06C815A393A6404ULL,
		0x569FDA3F56849771ULL,
		0x98942BFDF41D7EE6ULL,
		0x11DA65D80FE29977ULL,
		0xE95FD1B71C0E2643ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0D10CE0DF49AB1ULL,
		0x10CDAE9643E0AB1FULL,
		0xF1E38660EA8EB3E6ULL,
		0x54A5A288635411F8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x12158DA5309C0F2CULL,
		0xB039F138957C9EB3ULL,
		0xD46AF3E621043B38ULL,
		0xE73DFEEA4E0550FCULL,
		0x06956A5C598CFD0EULL,
		0xA6D01A6E3006754DULL,
		0xDF888B13B213B78EULL,
		0x2DFA32189CF9FE99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C43575A7B89A05DULL,
		0x731DDD93B6720822ULL,
		0x02AF98D28FF17A65ULL,
		0x3A616E919B211BD4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE36B6FBC4D5122C5ULL,
		0x3683D14658EEEA90ULL,
		0x75A7EB7BFFFBC8D3ULL,
		0xD081FA1D39F55ECFULL,
		0xDCE3E74E250E129AULL,
		0xB93AEF0AD025102EULL,
		0xD6CD954B535C7E2EULL,
		0xEBA76CD115A3725FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD3FC555CD67EAE6ULL,
		0xB5434CE13E6F5185ULL,
		0x582C14AA5FB683C2ULL,
		0x4B5C212670385909ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA1E63A4F765425A9ULL,
		0x01EAA61CD39B05FBULL,
		0xFD5BB7727D026B74ULL,
		0xE02031F80FC711B4ULL,
		0x96F657D3147E3C5FULL,
		0x7F46A0742A59271AULL,
		0x3505CA9E12994922ULL,
		0xCFECF119F6D3CBACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A7743A481112070ULL,
		0xE666775B1CD6D3EEULL,
		0xDC37CAE93FC34692ULL,
		0x3D4BFBD2B3374D44ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6B2702B10066F39DULL,
		0xDB41E9EA5D512F8AULL,
		0x6B68227FEE82F415ULL,
		0x2A402BD40782E637ULL,
		0xBB1A566FEAEE9808ULL,
		0x23664D080138266AULL,
		0x6876BD4D3EC53DA0ULL,
		0x3BB0CB3CBE0A5F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x310FD74DDFD18623ULL,
		0x1C71591A8BA6E362ULL,
		0xED083BF73FCA19DBULL,
		0x067E56D83D0D0B1CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xACC8496F4AD8AF33ULL,
		0xB4EDEEBD862D14F5ULL,
		0xE643F248FF0457EFULL,
		0xE35412F9C77810EEULL,
		0x1562FD8F30E61237ULL,
		0x2E53C5508D090A2DULL,
		0xC4A36CA7EE4A5E0AULL,
		0xA45619AB678F8C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD979ECB08CFF6713ULL,
		0x955D38B2758497A6ULL,
		0x168613365E0E4D72ULL,
		0x481BE26B26C6DC76ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC03EEAA86414F554ULL,
		0xA6764C3F09F755BCULL,
		0x262386670E31E6C0ULL,
		0x238A215B4D390300ULL,
		0xA6199082599B9B5AULL,
		0x2CFC12BC33898F2CULL,
		0x67DC6C1D4140F718ULL,
		0xBA4F061507C1C69EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x680A5E01B12E08C5ULL,
		0x53E1142EB062965DULL,
		0x90DB92BEBDD69457ULL,
		0x4B45087A73FC7E83ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB232F4123389BB00ULL,
		0x724EBBB82596993DULL,
		0x881B4DADA92F2F4DULL,
		0xB527769273ACE09EULL,
		0x040686B3B0156325ULL,
		0x6A0D8E715F85EDD9ULL,
		0x712C84F67EFA6B45ULL,
		0xC99BB2A2B70B7F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2AF2BE56B67705ULL,
		0x3051E08C5377E774ULL,
		0x54B70A44825B1B9BULL,
		0x2243FAB99F61CB75ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD6B9BE194A543CE7ULL,
		0x671B9F4165B2D774ULL,
		0xC88C70CB2418FAAFULL,
		0x35137BB6B6CE16E1ULL,
		0xA2B35DB6E86EFD4FULL,
		0x2FE3AEA7D7CA00A5ULL,
		0xE27F4F80A0FB2505ULL,
		0x3E414F83BD0FC48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD59A73FCACDD7F7ULL,
		0x82E78C2B6DAEF00AULL,
		0x67723DE309607974ULL,
		0x72C54944C72543F1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3A494F2E42B0073CULL,
		0x9EF260FD87AE8FE0ULL,
		0xDA335E9444D01FA0ULL,
		0x1E5DD892B778D654ULL,
		0x8018BA92983C8B47ULL,
		0xFD48A61F842882C8ULL,
		0x26DB62A0C70FDEB1ULL,
		0xEB287D6ACA7B033CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DF500F0DBACB8F8ULL,
		0x37BB09AB25B1F9A3ULL,
		0x9EC40271D12B2E0CULL,
		0x0660766CC5BB5142ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x21FBC283E375426EULL,
		0xD68D540CCF685CF6ULL,
		0x6FE4948EF1B8F91CULL,
		0xFF2DCC11E1171C13ULL,
		0x80199044DBBFE407ULL,
		0x6A9550F1821339D3ULL,
		0xDDC3773E56F581BDULL,
		0x63F8B64993888B17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C72CBC81F11DC5ULL,
		0xA8B757E61E42F25BULL,
		0x5AE847CFDA2A3B3AULL,
		0x5618DAFDC75BC19EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBC8CA8E87663EEEFULL,
		0x8094D02D84420069ULL,
		0x2D5E8E789AD52F79ULL,
		0xCCA781B77F888CECULL,
		0x3DB68C3675B398E9ULL,
		0xB35F39915C1581A1ULL,
		0x20417BE728BC5DBAULL,
		0x7F1173A778FCDC63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A578FDEF0CA46AULL,
		0x20B75BC12F733E58ULL,
		0xF716F2C8A6CB1930ULL,
		0x293EAC93751143A2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x89288E151EC63512ULL,
		0x91A6099E82A57DF2ULL,
		0xD878ED4A00D269C5ULL,
		0x9842A3D3471240DEULL,
		0x6BDFE2F739DC5971ULL,
		0x933970EFA8E1A79DULL,
		0x8736673BA60C261FULL,
		0x9B4F835BC9A70F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C643EC7B57B7F55ULL,
		0x6C2CCD3194245F50ULL,
		0xEA8C4024A6A01275ULL,
		0x2610237335DE7B64ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x235400FCD6387A82ULL,
		0x81AC21840F284D29ULL,
		0x9FF5494C58D97382ULL,
		0x5A9DFA98BE1491ADULL,
		0x16CE86BCB4D2D2B3ULL,
		0xE93558C8B903CEF3ULL,
		0x908007E1440070E3ULL,
		0xEE107712864192B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85FC00FFAD83C659ULL,
		0x1F974F4F85B9053EULL,
		0x12F674BC70EA3557ULL,
		0x310FA758ABD0582FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA3364ABF41F17BB1ULL,
		0x70B70DBDE474C86CULL,
		0x7A1C04EBEA6D2DF7ULL,
		0x00106DCE88A767C1ULL,
		0xD2580B8D52E2E4A8ULL,
		0xF314CE241DB0F084ULL,
		0x9FC1A8F21BD5EDCAULL,
		0x3204A4588CA12AD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC4801B98F9F6DABULL,
		0x85CDA71A4CB87C23ULL,
		0x30DB18DC0C2E7A17ULL,
		0x6CC0D2F36893C351ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5C04DDAA8B2BD096ULL,
		0x4E28416011D74618ULL,
		0x294A6A028552F592ULL,
		0x41D2B4446AC50C8FULL,
		0x73DD495EA1104120ULL,
		0xDD7BAF80A073C812ULL,
		0xF00F9CCAA382C9F7ULL,
		0x20044F413EBA49E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EDDC1B673957C14ULL,
		0x2E844E77E306F8D5ULL,
		0xCB9BB016CABCF05DULL,
		0x027677F3BA6C048AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5200A853F5654264ULL,
		0x37AE2266F26BFCB3ULL,
		0x2FA566261A5EE247ULL,
		0xA706D703DC23CC3DULL,
		0xC77F8C39C4365B8BULL,
		0xE9A787C1E7846327ULL,
		0xAC8F1890DA30FD83ULL,
		0x3A2A8B92E0065BE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEEF78E71576DA5CULL,
		0xE68C492F5012B49AULL,
		0xCCE30BA67DA483DBULL,
		0x49578ED11D1570C6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB9FC234EB9866056ULL,
		0x8A8FC9394D63E9B4ULL,
		0x04FDA25D2F5D9274ULL,
		0xFD19EBC7B8FE07A3ULL,
		0x4AB22979A0DE1C90ULL,
		0x31ABA4C3195716DDULL,
		0x3652CF14C45FD82CULL,
		0x080FA0871DDFBE39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06E4B5C9A7E9E02ULL,
		0xEA0A3E2F10514E8DULL,
		0x15485F725597A903ULL,
		0x2F6BBFD628344421ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x73824E9B30E9E421ULL,
		0x43E7AEE522630261ULL,
		0x884B34F10364D48AULL,
		0x26D24B2A1086C468ULL,
		0xB5A80636D5110C87ULL,
		0x70C9429C3DAED1FBULL,
		0x3921F6961DB62C2DULL,
		0xBD1151221B34C925ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A733ABED171C453ULL,
		0x01C792164A562DBEULL,
		0x0355CF396C6F6349ULL,
		0x3764563A1A5C9FEFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x79B170ADB1D5E518ULL,
		0x98682C24476C18DCULL,
		0xEE48519C36986138ULL,
		0x2819BD7FC37C6849ULL,
		0x901B86FFC8585894ULL,
		0xF01A1425E3E48B55ULL,
		0xB6C4B7151C784CD9ULL,
		0x3F8E7F92732BDD43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDC77AA56EF30C79ULL,
		0x3C4729C41B58C78FULL,
		0x0F7B7EBE7073C992ULL,
		0x1740AD3CDBFF4057ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8756FE6D612F2D4FULL,
		0xD2FDC848E153B8C8ULL,
		0xEC5938CC2FE0A41FULL,
		0xF0EECB44BB345EA4ULL,
		0x06886FB14003B074ULL,
		0xB704CBD9E03E1C43ULL,
		0xD41BF1BA00AF9A9FULL,
		0xE4D17D57EF4B236BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F9792BCE1BB63A6ULL,
		0xFDB40AA02A8BEABBULL,
		0x687F1A6849F197D4ULL,
		0x68076652405BA0A6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x42F6219F6AD7AA2EULL,
		0xAE486158353F9892ULL,
		0x5C2A450FA2101A02ULL,
		0x8B41BFA5C7E01534ULL,
		0xEDEFD8A0D4FA9515ULL,
		0x2DFAED7AB714168DULL,
		0x7A668E69C292CF01ULL,
		0x5AC26D61E9678BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9490497F0809CD60ULL,
		0x8187A18F623AF1A3ULL,
		0x876368C283DAD42FULL,
		0x041DFC2E6D3ED814ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x868E47CDD9EBBFE6ULL,
		0x385D5BB5DF98F0B7ULL,
		0x131D949D1BA42FFBULL,
		0xED8B1E9E656F67D4ULL,
		0xA2EB1D0E350BC88FULL,
		0xDAA52F2AA2F05750ULL,
		0x001B045CB86BA232ULL,
		0x28725F7D603CE2CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB57497E9B9AB8617ULL,
		0xACE25C0A0F45E6AFULL,
		0x17203A607B9E4387ULL,
		0x6E854B3AAE791242ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x665954CB483F1F54ULL,
		0x4C6EDBCA79B83DE1ULL,
		0xF13B4F256C1CCB93ULL,
		0xA918F841403DF9E0ULL,
		0xC14933D28D237E11ULL,
		0xA794932601CC01B2ULL,
		0xB2D1AE9D1CAFB0E0ULL,
		0xA0097E48FF48AA73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1737060C3B83D96AULL,
		0x2C7CB36EBE007E6AULL,
		0x7C5B3A77AE310CECULL,
		0x6A81B7172507470DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x96D3218DF60B015AULL,
		0x950DDE95C01A6E34ULL,
		0x0599D3A212E79041ULL,
		0xA456514EB4035956ULL,
		0x6812D0B6AE8BB12CULL,
		0xDB26168C51BA2015ULL,
		0xF0816D032CE39D98ULL,
		0xC34EE6E47545023DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x099E1CABDEC75243ULL,
		0x1CB53769E1BB3162ULL,
		0xB8D0021ABCB0F4F2ULL,
		0x220C97381C41AE87ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF730DC513EE6301CULL,
		0xA6DD906E13DD2031ULL,
		0x7FCCCE219933BA8DULL,
		0x9C49C8B7030A340DULL,
		0x027402A8E4C998A5ULL,
		0xC47D2EDA44AF8E54ULL,
		0x493C09996960D565ULL,
		0x7330C492D7E95753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5469416334D2DB33ULL,
		0xD17284D445EC40AAULL,
		0x5EB63AE73D9367A8ULL,
		0x3586F6830FAD2A6AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA74FF8834D9470E9ULL,
		0x1FE4D6C728A74FBEULL,
		0xD2931714441F0F5DULL,
		0x92AB453F4A2DDA1DULL,
		0xBFB5C3CA1F29BB62ULL,
		0x90EB8FC86F87C909ULL,
		0xAB648240AE8F4EA7ULL,
		0xC43823DCAC846D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4B0883EDC645D6ULL,
		0xA2DC2E87B6CF2731ULL,
		0x437E6CAE2D64BC3CULL,
		0x33009800E5D60F31ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2B744EAC662BC1B0ULL,
		0xDE727A4C84CBC9A7ULL,
		0xA6CDAFB6C5A2FA43ULL,
		0x49450C59AF722665ULL,
		0x58438CA768BF9827ULL,
		0x03297C1BC8E97C54ULL,
		0x7BB24CE397BC7153ULL,
		0xEE669865FCAA0732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x457B2F85F29C5CBFULL,
		0x569AE66C57743E2CULL,
		0x0345197F4B9BCC96ULL,
		0x2C7FAB7D30AF37E4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x314416E909129361ULL,
		0xCB9DD5576EE3C462ULL,
		0x3C61B9AC432F1FB8ULL,
		0xD9847D72D2C8268BULL,
		0x66A622CFDB2A25AAULL,
		0xA04B1947351E681AULL,
		0x36CD8F2B291E862EULL,
		0xEA0FC428620D22E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DED41C391542FE2ULL,
		0x96C395E95167384DULL,
		0x5EE4FA145DB70AA4ULL,
		0x17DB9B7160BB54B7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0D5B0E122078E5B5ULL,
		0x48C74C70E664F596ULL,
		0x9E495E1B695E9AAFULL,
		0x2C25ECC84E31F41FULL,
		0x81EA2F52E4F57F4BULL,
		0xFEEE9A589C537A81ULL,
		0xEC734CDE016131DDULL,
		0x5DAFA2DB2D0644F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x561E14601CE9CCEBULL,
		0x203235981AC924CFULL,
		0xB766C70F9DCC01A3ULL,
		0x14381950FD2030C6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x66F86EE23DC3D50BULL,
		0x10BE8A160B0851E6ULL,
		0xF734279ED9463A73ULL,
		0x8FA0AEBE0A93DD38ULL,
		0x8595C73326D78FB5ULL,
		0x951E84BFDD409675ULL,
		0x6479EA71B51FDD0FULL,
		0xB3C555AD6A2F5724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B34007A01C32DEBULL,
		0x33463E90E29EA758ULL,
		0xE14CF47FBC010AC3ULL,
		0x3EEB667BCD9ACC9FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x14106F07378DFD0AULL,
		0x2E6492FB17F90619ULL,
		0x52BD8A11217A08B9ULL,
		0x394BA220E218AF8DULL,
		0x8F5095FF918C3FFAULL,
		0x33363EE36A91446EULL,
		0xD94E59FB335AF280ULL,
		0xA4CD02AC6DC7A209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A06B2F6D25F7FC9ULL,
		0xC871E8BCE9892E82ULL,
		0x945EE55AC0FA07C0ULL,
		0x2FBA07B92DBABD03ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4C1D0AF55B6B9E95ULL,
		0xB8862B15487426A5ULL,
		0x39BC979DA93ABC34ULL,
		0xBAEE5507CE35544CULL,
		0x3E0007229FB73F1EULL,
		0x541100D6F13F89F9ULL,
		0x752A86B157A46F28ULL,
		0xFD54150C480B3298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801E1A19109F02ADULL,
		0x330C4AFD17E2A1A4ULL,
		0x9E0C95F0ABA33C31ULL,
		0x556974DA7FDED6EDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE7E209E917C22997ULL,
		0xD9589B1EE1334053ULL,
		0x7A86B339D6CAE8ADULL,
		0xFB5128DAAC67D6FAULL,
		0x02CCFA3E085E68E9ULL,
		0xDB6585E87A853334ULL,
		0x672A56FCF11E6204ULL,
		0x0EE4C2BA2E30B3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x524F2F1E55C5BC9FULL,
		0x6A6A7BA110F8DA0CULL,
		0xCACF9CC5A14D7566ULL,
		0x3146107D87A282B7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE7AD5954E1F2730BULL,
		0x28AB8788CB298788ULL,
		0x93B096E964F331EDULL,
		0xE4F38281FEC26A7FULL,
		0xC4A53E8FBAECA9ABULL,
		0x4F319AE527B5BF5AULL,
		0x8611D4E9F6763607ULL,
		0x529605D8EE379D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1834A2AAA113A45BULL,
		0xEA08858CB023EF02ULL,
		0x7A5631A3FA7F3702ULL,
		0x273860B55B03C3B5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0097EC6EFA967CF2ULL,
		0x1C4BE97D63E50249ULL,
		0x769D2E26F0E07ACFULL,
		0xEB0A6F4C9D22DD05ULL,
		0xD6C557A8AAE94E48ULL,
		0xB67D0E3BD22BF078ULL,
		0xB4710AAB1CA9F888ULL,
		0x8D416277F0FF1E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1E2EF7859381ED3ULL,
		0x32DC065E966AB438ULL,
		0x3F64C38D321B5F1AULL,
		0x62BF0D1A63015D98ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9507B309E603F96BULL,
		0xE69F2C7430642F14ULL,
		0xF9F6A93F3B3F8B6EULL,
		0x553855C984AB22F9ULL,
		0xD9FD445AFC8E33E3ULL,
		0x9ED447EFA6B9742EULL,
		0x8CF3FA9ACB720BFDULL,
		0x488AA64DE4216137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF09FD88B631FAEBFULL,
		0x7A21DA06EFEB6E08ULL,
		0xE62DDC396E2D5314ULL,
		0x19CD0559619F9138ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7114223B69E4E112ULL,
		0x25E7C35F0F7B92AFULL,
		0x85ACF16569E1675AULL,
		0x48E3CDD1340B2195ULL,
		0xBC8B15D80FEC9FA9ULL,
		0x5158F871EE553D65ULL,
		0x65AE31529B52634EULL,
		0xF941BA067F1AD833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB9604DC70499A6ULL,
		0x391CA4487022AFC9ULL,
		0x9D8843A8781C24FAULL,
		0x48A56AC812073936ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBA71A9FDEDC5008BULL,
		0x460CFC6372337491ULL,
		0x3B4DC1B766AF8149ULL,
		0xD791E25B605172E1ULL,
		0x83B872B575A3FF43ULL,
		0x054884CD12FA4E03ULL,
		0x0A9C5264DEE395E8ULL,
		0x7DD71F08EC78004BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D2B0ED641CE762ULL,
		0x0ED0B2D4435B0917ULL,
		0xCE81FCB07C77C1BAULL,
		0x05807DAE7A217E04ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9756BC61FE5449CFULL,
		0x09449FFB1A61AE0DULL,
		0x6705CDEBF33D1153ULL,
		0x97F2191CB24666E1ULL,
		0x1434C872F5056F5FULL,
		0x25F3E46C6B358784ULL,
		0xA920F597337857BCULL,
		0xEDE9404BBACF69CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x972C7D725D22D72EULL,
		0xAB7888130453CBA8ULL,
		0x81EA425D971A1740ULL,
		0x6891A45A6D101BB4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC0D3A3221883442FULL,
		0xC195E35CE4C4973DULL,
		0x893F6E6F12FF8B91ULL,
		0x9DF235D067CC9756ULL,
		0x9F2257B18E783CDBULL,
		0x9A55C27120BF04D7ULL,
		0x92A053537BE865ACULL,
		0x5A947A60F1DDD2B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FECA77D3E5C4EC5ULL,
		0xAA50C027C11F4F3FULL,
		0x4D0BCCD3777EA330ULL,
		0x0FFC60344EB9DE70ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9B2116530A978D46ULL,
		0x72775671D2BAF18FULL,
		0xCF555F99485BA9EEULL,
		0x961C6249A215AF0BULL,
		0x32A66F8A7CD6B9C2ULL,
		0xD62F9EBF2B612572ULL,
		0xC66A7CE6B5395B85ULL,
		0xF3997944A06EF3D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD5A4E19277257DULL,
		0x3D88E6D243268083ULL,
		0x4323E9D82EDF3FCCULL,
		0x3EE46279728DE0EDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x806D3084C213B359ULL,
		0xAD068D7EC0E50C3FULL,
		0xF2915B1C1A4AD138ULL,
		0xB99A6DB586BBBEE6ULL,
		0xD3480464095C411DULL,
		0x3145D8F3CAAC6F2AULL,
		0x395C414F167188D5ULL,
		0x52A480021EF56F19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD1DD75E25C55F82ULL,
		0xFD64C1AED67D8C9AULL,
		0x76430CD96F2520DDULL,
		0x7E056E061F2A3CA5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x324D4A50F24FFB7EULL,
		0xCC392176E5D164C2ULL,
		0xC778DBFA37C415A7ULL,
		0xED7233749771EF76ULL,
		0x02A4FD2833E9942EULL,
		0x228BF39C3CBD4B0FULL,
		0x82AE559B78EAC3F3ULL,
		0xCD061D4633AD6AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96CADE48A6FBFEECULL,
		0xECFF4AA7E9EA88FCULL,
		0x2D59910E2A9D2BBEULL,
		0x5C5A8BE0432FC4A0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8A5DAA1F3B1A7D6AULL,
		0xE7850B44F09009D7ULL,
		0x682FC0FE95C01689ULL,
		0x56FE171A3E1F9DA8ULL,
		0xAC4419FAAC5A58EEULL,
		0xA85EFADB3F9D819AULL,
		0x6D85D8F7BBA0F2F0ULL,
		0x5133A66C8DC0B757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C798554D083B286ULL,
		0xE59E47D061F146CDULL,
		0xAA0DF5C46FA42642ULL,
		0x64A8CB3748BAD4A2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEBF359BABC226DBDULL,
		0xC1AC63241F1624C8ULL,
		0xFC2CA54B875500A8ULL,
		0x15875B51BB903A53ULL,
		0x3A12FCA1D205E2F4ULL,
		0xEE83D6D40F57E3A6ULL,
		0x3C9F3E938EDED7E9ULL,
		0xA659A1F81A7D543BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AC4D9BFE9022198ULL,
		0x293E469E6621EF75ULL,
		0xFBCFEF32BC690D62ULL,
		0x46D56625AA2ABB1EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB3A0C9BC00902643ULL,
		0xA83561412112188EULL,
		0xE58D4EA19E751433ULL,
		0xF9B592CEB17C050FULL,
		0xC4567281B4F44EDFULL,
		0x8BA1C9EF6C2B4306ULL,
		0xAA463ABE290E96B6ULL,
		0x26C078C894DA14CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD875C8FCDCD3DC54ULL,
		0x62395ACB2F7E0B8FULL,
		0x2BFA06DBB69F734CULL,
		0x3A478094C9DB1BE3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x92FBB26193AEE242ULL,
		0x6AD60746DC18DFDCULL,
		0xCC920212751BE16AULL,
		0xB5DF138B3FA2F010ULL,
		0xF157AEDD960B7617ULL,
		0x946A70F09F5D96B6ULL,
		0x43C1B902193E228DULL,
		0x5EE5F37B0209377AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65FFA745D9626BD3ULL,
		0x72A2CAFE83FD3F04ULL,
		0xDB5378623455026EULL,
		0x4C0137CD8D012C36ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA61DE663492390A0ULL,
		0x7A32A2F8AD15B9A6ULL,
		0xD64848DC6AB51F57ULL,
		0x7550E6687931C865ULL,
		0x7411BCE340ABCA65ULL,
		0xD102CD2098FB752CULL,
		0x68785CF87A1FE12AULL,
		0x5DBAAD6DE0122FB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0BFF01EE2A39DB2ULL,
		0x809D15CF62691E3FULL,
		0x582615BE8B708BB2ULL,
		0x5F06A4B7BBE4DD2DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2190D034CC733E4FULL,
		0x3836726311A1EC02ULL,
		0xD0A3A933718D1F1AULL,
		0x692058827B0EA888ULL,
		0x75FC1E5972F1E79CULL,
		0x6C2460B27EC82F5FULL,
		0xD67F2E9E0F62052FULL,
		0x857D5A860CC67A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4FD517BDC5BA26FULL,
		0x459CCCE1E358F42DULL,
		0xA78494A9BA19E424ULL,
		0x39BBC8686084C6BCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x47425F471077308FULL,
		0x3CCDEF77933B1DEDULL,
		0x6EC130BA7759A0C9ULL,
		0xB56F2B78268635F4ULL,
		0x41272481B7465AB7ULL,
		0x8FED41B18BC16C1DULL,
		0xA86DD6FCC53F7218ULL,
		0x376EF022F616D32EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF311CA8844E8A8FCULL,
		0x9A05AFD251F12A44ULL,
		0x6F0F1A3FBEC4906EULL,
		0x6FE6D0A8ADE98EE1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD83DB45D8C10994DULL,
		0xD83BA5DD0A212895ULL,
		0x592EEB37B61F2B53ULL,
		0xAEC1E9D8FF9132AAULL,
		0x0778A2DBB8F90230ULL,
		0xEDDDC5EBA9E8A28AULL,
		0x15D310F80C62F250ULL,
		0xF8C2C865B667737AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF425E0FB0106F1FEULL,
		0x272706D842A94912ULL,
		0x968370098CCF2357ULL,
		0x1BABA8F212EC56C9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCF631ED55D81C644ULL,
		0xFB8CDAC341FECD1EULL,
		0x9E84CDE1E9B50614ULL,
		0xC71D9726B42D1B34ULL,
		0xF404AB6D86D3CE97ULL,
		0x35D3876E2E3A6C33ULL,
		0x172D0B2EBBD03D0FULL,
		0x0E20457EF52FBB1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0814911760F2710DULL,
		0xF8F2F51E1EAADCD5ULL,
		0x0F3476D1CA9E1656ULL,
		0x5FE7E7FF1942E1D2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFD6600F40EDB7ECCULL,
		0xCBF443580EA73A55ULL,
		0x8A0D85AB5BCC4E38ULL,
		0x286F8EC6ED2EE084ULL,
		0xE701A50DCEE84994ULL,
		0x2F1F14CF2F68560AULL,
		0x955A41E16AB650D3ULL,
		0xE5508E1815607D2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A48100C5566FD0ULL,
		0xCA915A191823FFF4ULL,
		0xB5734D2132DC4D91ULL,
		0x3264A65A19817548ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBCA5F0237AEF79B8ULL,
		0xC4E328D4FB0A814FULL,
		0xFD7CC285AA7D48E8ULL,
		0x4FF32429474F49BBULL,
		0xC09B9A4D7C7E64E2ULL,
		0x9FCBF8B503073ECBULL,
		0xE03A075371A5AC34ULL,
		0x90C258F1374F9A97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53BED7A3F5B27675ULL,
		0x7D2A13B36E1DD38EULL,
		0x4619D8E88914D8B8ULL,
		0x4CCC57F77D203C47ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x894004C51071EC07ULL,
		0x923CED04C077DF17ULL,
		0xC304653AD31F3632ULL,
		0x62ABB791A7362CC0ULL,
		0xDFBCAC8270AE025DULL,
		0x65A5BBD9DF55C6CFULL,
		0xB9D2686A9D05917BULL,
		0x7D3D635F2A9EA71FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF41A021CA464894ULL,
		0xA8D6CF5BE73361F2ULL,
		0x583FE50E21F2CE83ULL,
		0x79C877B1FAC2FB76ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x28CBC0C0D61DC76AULL,
		0x33FF0B33DB18E229ULL,
		0x0FBA9B6F09EC4E9CULL,
		0x3B5B1FA6139A48D9ULL,
		0x08A03524D8F0CC67ULL,
		0x7A0A10DCC3527A5AULL,
		0xB5A8FDCC9CE956CCULL,
		0xBCF4A7F0904CD5BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7093A43909DC22DCULL,
		0x517D8BF8D9570B86ULL,
		0x06D047CE548F30F6ULL,
		0x47AC0D5B7F020290ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0362F140A1CEA7DFULL,
		0xBA99B7A26AF8541BULL,
		0x8FADFB70C21730BEULL,
		0xD0B135120CB5159AULL,
		0x8F28A228C73C4E0CULL,
		0x232F00F63DE254CEULL,
		0x5A2D4D5F9E7B13F0ULL,
		0x35BC981993C7AC35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x436B034E34C23EEAULL,
		0xF393DC2F9A90EAC4ULL,
		0xF26777A2485C2663ULL,
		0x4AAFC8DDFC58A585ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x98D7F07D85D3262DULL,
		0xE8395A6D537D3247ULL,
		0x7DDEF606F72281C7ULL,
		0x5411E675AC2A6B1AULL,
		0x23F4AA04B7AE3A22ULL,
		0x1915019EE32906BEULL,
		0x2598279F49AA919AULL,
		0x62BE1F35188A07DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF292D30C9AFC960ULL,
		0xA15798030B943280ULL,
		0x1274D7ABE6741EA7ULL,
		0x7C4A885750A7963AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFAF44FD4273F1CCCULL,
		0x4C995FA0EC126A9FULL,
		0x2C1BFD36F4ABAB01ULL,
		0xE7F1D5BB5D36427DULL,
		0x490605D0A626A000ULL,
		0xC2CD069C54393C32ULL,
		0x7C547F7A290DE271ULL,
		0x0DEEFEE112AB732FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D92CCCD0FADD2BULL,
		0x37085AD56C915A16ULL,
		0xA0A6E9590CBB47E4ULL,
		0x796BAB2422A95B89ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBE6FE291DAB38240ULL,
		0xF17EF7B2D5887DA0ULL,
		0xC3DB035A33A334B7ULL,
		0x29F04107E83D17F0ULL,
		0xB76B9C67D93931E8ULL,
		0x46B19195DF6E3C33ULL,
		0x7301FD0EF2F90B52ULL,
		0x9FF3CF8ED376B672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF86919FC1930EE2DULL,
		0x6FDA93F1FFE56D4DULL,
		0xD6269392449AE2EEULL,
		0x6821103B4BDC2CEDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x79ADED33F9D004ECULL,
		0x8AA561408D8E904AULL,
		0x335C5A8A15194F34ULL,
		0xC0077F8B1539220AULL,
		0x606E745CB15AEABAULL,
		0xDA94AB24D07013A8ULL,
		0xAB01D640FC963B00ULL,
		0x10FFD290ECD33C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA1332F64D4EDCFAULL,
		0xFCB6C8B77E317B48ULL,
		0x95A2282F93661154ULL,
		0x4600C10E3C9410F7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x81B44792667DB6CAULL,
		0x42BF0A44A044BCFBULL,
		0xD2CFDE2ED7DFEE2FULL,
		0x14A2DA3E004821ECULL,
		0xA86879DA94DCB9B9ULL,
		0x7E344EE74A477145ULL,
		0x3BC08A3BFA497621ULL,
		0xD3A461281C5E45D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81365E047F414CDAULL,
		0xFE82C099A6DF8D52ULL,
		0xB1646315FEC77727ULL,
		0x7F09463236467F21ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6B5EFBB7F685D51BULL,
		0x4F9CE8C8F5730F34ULL,
		0xDB7D711E15CAD009ULL,
		0xB213C33A5544B49BULL,
		0xA8986FD92564DD9BULL,
		0x241811763BBDB80EULL,
		0x3969E801836336E6ULL,
		0x7CBA4F4B4C6E2E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71FF95F3837EBCEFULL,
		0xAB2F8055D39C6161ULL,
		0x6135E1579684F632ULL,
		0x35BB8867AD9F9AE6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8651FB4886FA0F31ULL,
		0xB9FB11853115FF30ULL,
		0xC3570251C7E86304ULL,
		0x57EFE8A60BFA5C28ULL,
		0xE926B4633EE608E9ULL,
		0x5D4EBFA2FF72E75DULL,
		0xC79213549FCE6B50ULL,
		0xB143EA885095DA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2210C203DD1F65B6ULL,
		0x93AB83B71C245721ULL,
		0x6305E0E1808C50F2ULL,
		0x2804B8E20238CC9CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x05B808CE6AE18FBEULL,
		0x1F46F37CA47624B2ULL,
		0x6F70F00A3757A716ULL,
		0xE791C96439D3682DULL,
		0x7A4517E2989F0488ULL,
		0xD427EA85BFFD91A7ULL,
		0xABF3808B99C4D578ULL,
		0x9516E1D96F2A0DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF99471127C3F58ULL,
		0x9D33C3572419C38EULL,
		0xF59604C30A8F5705ULL,
		0x08F74FAABA117ACAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA995858C096509ADULL,
		0xC9B2EE1D92CA5546ULL,
		0xF6E9AA470F34CC82ULL,
		0x5F4AEAAF4C2C782FULL,
		0xDC0ABF8AB16A0681ULL,
		0xF3B701D97B20C748ULL,
		0x6476B3E5E08373C2ULL,
		0x6177FF3DA67D8F7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532DF4225F2202FAULL,
		0xF6DD3465D9A7EA17ULL,
		0xE0885E6662B7FB72ULL,
		0x571ACDD602CFC480ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC007F871B226D679ULL,
		0xC19AB665FE7D33F8ULL,
		0xF6DF2117A943E3A7ULL,
		0x1CD10E4FD17804B2ULL,
		0xF9BB7706E70A0F90ULL,
		0xD7D531AF0EDF6A80ULL,
		0x5C7DEEBD3C73769DULL,
		0xC6D045DF6F5D2603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DBA377FDA52A3AULL,
		0xCB40166233A7031DULL,
		0xB190912EA2677F15ULL,
		0x1FBB6D7A594BA932ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x59A6FC926874A908ULL,
		0x84DC3A48712EE12EULL,
		0xB64E25174BBB3160ULL,
		0x2BC5037433E9B6B6ULL,
		0xB8D19DD6C90B800CULL,
		0x6C786C282BDBE25BULL,
		0x4FE492A1C042511AULL,
		0x1B3DB226361FB151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8C46A744029AB68ULL,
		0x9EBC483EF3D27ACBULL,
		0x923BE919D5933B4CULL,
		0x36ED75203C9E08C8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x00D2F7E28ECCA709ULL,
		0x2E18ED0CDB232155ULL,
		0xE1B15DA87A8C01DFULL,
		0xAF433F6CC4143EECULL,
		0x77AF2134D2B387FCULL,
		0xFE91C9F6602F4E85ULL,
		0x3126C70D0EE118A2ULL,
		0x40DB463859505D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D1E5B9D572D7EDULL,
		0xF7BCE79F2228C924ULL,
		0x2D72E998AFF5AA10ULL,
		0x4FCFABCA060217F0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF79C9D25AE987879ULL,
		0x30DE3220D66D5DBAULL,
		0x71FB369D94C20D1DULL,
		0x8C9BF3047CBCD25AULL,
		0x28B8D9F4556AFE0EULL,
		0xC2A2A058AE092A65ULL,
		0x0617CBB7E73A845FULL,
		0x95387416C50BEF13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x030CF76A5C7A31E4ULL,
		0x1501FF4AABC9A8BFULL,
		0x598373E9E771B354ULL,
		0x32FD2E65BC824F2DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7E42D865EBD81A29ULL,
		0xFCBFE73E013AC719ULL,
		0x6CDAB63327E2C819ULL,
		0x6DBD5EA4A0DE34A4ULL,
		0x3368787F07DFF5BDULL,
		0xD44BB2B8BC5A0508ULL,
		0x7A842493F3E4796FULL,
		0x3CD6C1E1F404C119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FC4BB411716958DULL,
		0x7FFC6EA9F6978651ULL,
		0x9C7824295BCCCEB3ULL,
		0x759E262ED992DE6CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBB913FEF31406BCCULL,
		0x76CEC4ECEF32A81EULL,
		0x71949CCC5E0AF306ULL,
		0x5A757724B84711BCULL,
		0x95D063A721AB9D1DULL,
		0x97E32DD0869F670EULL,
		0x790B5466D9212BE3ULL,
		0xAE0B2540BF07285BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8800ABE30B9C1F6ULL,
		0x028791E0EADBF448ULL,
		0x6943241098F776CFULL,
		0x301CFEC113570F50ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x597E9D831C3B9468ULL,
		0xD6E8A0914731B807ULL,
		0x121DFB720782DD82ULL,
		0x62665C73506FC803ULL,
		0x91A1A7C3783A066DULL,
		0x44742C90265B4905ULL,
		0x8C6C3D8D01B04142ULL,
		0x711435D5FF8CA97BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77D8486F4D88B1CULL,
		0x00273DF6F8BE8EDAULL,
		0xEA2F1E6047AC8D59ULL,
		0x2B665A373F50F059ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1FF004682DF5ADF7ULL,
		0x04295E147DBFF94BULL,
		0xCDBA37CA38011A8AULL,
		0x70BBAA885F854202ULL,
		0xB17B0A1126BDAF4FULL,
		0x38279EFE1BFFB556ULL,
		0x33C9AEEF3FA9B505ULL,
		0x8A20EDD1A65060FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783382F3EE1DB6BCULL,
		0x5A0AF7CCA5B4E429ULL,
		0x7DAA2F4DAB31F950ULL,
		0x719EF7A70F73A7BEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3755FFBC73222622ULL,
		0x51CFA47B5350228FULL,
		0x773F7BCFC4290C3AULL,
		0x31EC706922486AF8ULL,
		0x234FE157D4A3F327ULL,
		0x17EE628EB7AE9385ULL,
		0x302FAA60A94B160FULL,
		0x1399D0FFC3B71BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x753172C603783E5EULL,
		0xDF3245AA973A0852ULL,
		0x9E52C628E54E5277ULL,
		0x1AC176602F768C2BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD7DA86146E5B30E0ULL,
		0xFBDF67B304FF3B03ULL,
		0xDD39E566171B0BBEULL,
		0x8A4FA3E25A5CBBC8ULL,
		0x7E5E81115C7C5C7FULL,
		0x2E99D1658BFA7772ULL,
		0x5B5F4BB951297FD6ULL,
		0x554269D7E6666A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E1AEA828D0EDA8ULL,
		0xE6B47CC5CC2CF602ULL,
		0x6D5F22E823440589ULL,
		0x322B59EE8D907A5CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBFC8FC795CC0280BULL,
		0x9B003A8B90A07F19ULL,
		0x146C9F499ACB7960ULL,
		0x4A6CCB7CC3016DF0ULL,
		0x8A8EAB77BB7AA1BBULL,
		0xA62EED282B6D3723ULL,
		0x44011A4224A67477ULL,
		0x4282FC7A026EA595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F6703F30F42B49ULL,
		0x45F76E8202D6AE60ULL,
		0x2C96851B0B80C323ULL,
		0x29DE45991F6E0218ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0A51EEFE6AC20878ULL,
		0x0253DDD527D5AA8CULL,
		0x20A8C267E1A30021ULL,
		0x6D3FE53E892FEE89ULL,
		0x115AE464B42A04F1ULL,
		0xCC0041612AA0457DULL,
		0x761FEEF12B766B91ULL,
		0x3CD9161BBC2B836AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DCFD5F128FEC594ULL,
		0x4A5D92417B9FFB1CULL,
		0xA9663A345536F7C5ULL,
		0x75792D5C77A57056ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3BDC965D6D816092ULL,
		0x167D1E8E5D328101ULL,
		0x179B465BAB225831ULL,
		0x37EF0C93540EC1F8ULL,
		0x3232D0A9C9FA089DULL,
		0xC6347B0939BA359CULL,
		0x55094C3A10616A56ULL,
		0xDCDA8E4783C90D15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF678F91689EACC6ULL,
		0x824761ECEED67630ULL,
		0xB6FC96FA19982112ULL,
		0x00602B30E3E6B322ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4848DBB73F0F3939ULL,
		0x334973938D19AEE5ULL,
		0x8D0625BB0B2C0A04ULL,
		0x0A05563C92427FCFULL,
		0xCD7972666AED015EULL,
		0x2E868ADF2465B9B7ULL,
		0x168CE085D5A0C65EULL,
		0x7A0FC1CF5484370DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC84FD6EB1E3D6FD9ULL,
		0x1B4210B2F433402DULL,
		0xE5EF7998C1097BFFULL,
		0x285C1B031DE2ABC0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9C441E7618B2F412ULL,
		0x4CCBEA97459E5D91ULL,
		0xAF1D6D4D6EFCD95AULL,
		0x792A73D175A3EE42ULL,
		0x6A8B9187D70E1CB8ULL,
		0x6E9F4E58953BEEE4ULL,
		0xA119096A000B2AE6ULL,
		0x835A36A8EAC77C7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CFBB8A004CB3A47ULL,
		0xB8718BBD6C83D379ULL,
		0x98D4D30970A5378EULL,
		0x788E90E44F40690EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD4451ED7A4B4B667ULL,
		0x2FD9A148A9C0CB27ULL,
		0x5243F16977218B21ULL,
		0xA7CF265E20EF1F50ULL,
		0xFCAF2F772799EAABULL,
		0xC9E4BE937CE073EBULL,
		0x655D525B4012D57EULL,
		0xC8F9D6AB8220617DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56462A87858D903DULL,
		0x27CDEB2D3312002FULL,
		0x5E1E2AF4F9ED3BF3ULL,
		0x7CE503D371BD97EDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBC33D5E3774FAD86ULL,
		0x1D97132A35D6298EULL,
		0xFC4A1D11C2CDE216ULL,
		0x990D7CC37A592547ULL,
		0x14EDF0AC4964A361ULL,
		0x65CA1567A7E56423ULL,
		0x76B628F05CBF7AF2ULL,
		0x144532115EA830E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7858F765C3FEE71ULL,
		0x3996408D21E306C3ULL,
		0x9B5430BF873A2211ULL,
		0x1B52EB57875067C9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x00D5EEA41A91F88AULL,
		0xD92F886A26DBD296ULL,
		0x59C879C83F3F2764ULL,
		0x9C720C02D6147DC3ULL,
		0x7EFB1E320AC4AD49ULL,
		0xAA677B2B74FAB3EFULL,
		0xB416ACB0F5DDCE3EULL,
		0x5BB454C6CDED7E3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1C6A11B3C3B374ULL,
		0x248BD0DD84128822ULL,
		0x15261C0CBE2BC4B2ULL,
		0x3936A18567553AC6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF4ED0EC6A9F2C7E4ULL,
		0x889BF2AE86A6511EULL,
		0x298A8D9D537BCD03ULL,
		0x4EF89B2EE4B0EAE5ULL,
		0x3CC76BED7D54F69AULL,
		0x31487E6B5106C5C9ULL,
		0xA90491AAF29A69D4ULL,
		0x7EA3312A9EA011F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA871407448F6592ULL,
		0xD95EB69C8DA7ACFDULL,
		0x40382CFD56678282ULL,
		0x1B31E782707395A8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9A469A64C2A3017CULL,
		0x6FE95E39E75BA53BULL,
		0x166D95B5B71D69D7ULL,
		0xB3B224E21301AAA8ULL,
		0x00D19F69CBAF5B06ULL,
		0xC05B52C92BA83926ULL,
		0x0C307710AFF9101DULL,
		0x98BF17B9EDD1F1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9644418FEAA87CAULL,
		0xFD77A816625420DFULL,
		0xE59F422FD615CE41ULL,
		0x600FAA7B602B8CB7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF4CDEB188606F557ULL,
		0xAF8A93B06A2A823BULL,
		0x5416AAD39609C179ULL,
		0x3B3C0E4A027FA52AULL,
		0x4051F44CDE5C4151ULL,
		0x90315FB005C2B463ULL,
		0xDA79C49CB9FCB727ULL,
		0xE2C85EBCA3536898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F82E8187B8AC56ULL,
		0x16DEC7D1451148F7ULL,
		0xC229DA17318CF159ULL,
		0x64FA1E4A40E12BDAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1BB9A98A3B05BD36ULL,
		0x81B8AE510643DAFEULL,
		0x7E57471D1757AC0CULL,
		0xEC439A0A8346BB63ULL,
		0xD95FB7CBB89AB7D8ULL,
		0x977648CFD7402722ULL,
		0xCCC4048E14411BD6ULL,
		0x7E6E1BBD49A76B32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FEEF1C7A1FD0A2BULL,
		0xFD477D2AF9C9AA2AULL,
		0xE36FF4341901CDE6ULL,
		0x309BB8237220A4EDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC0178D3E039F8071ULL,
		0x486E46F7A9E8D148ULL,
		0x408C0D12BC770871ULL,
		0x44C49B7B1AA01D71ULL,
		0xB99BF23ABB8337CDULL,
		0x716EDB764EDD1B49ULL,
		0xBDE83BC8652A177DULL,
		0xAD797A67FDCF7ABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3D81F5D919CCBBULL,
		0x1EE2DA875EBADE3AULL,
		0x7104ECD1C0B68510ULL,
		0x04CCC6EAC76C5529ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCCB8A85F515D6795ULL,
		0xD67E7DCA81486962ULL,
		0x69EB2228F065790CULL,
		0x112C9DB4D910437DULL,
		0xFB213EA6A4BCCBC5ULL,
		0x4762A7551D31893AULL,
		0x4C3BF133D30E4183ULL,
		0x8FD0E9FA9255B03CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A7F51BC563A9F1ULL,
		0x6F23546CD6A2C824ULL,
		0xBAD0EFDA44833289ULL,
		0x6A2F58E691C86C70ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x52A48498BAE25159ULL,
		0xAB0CB78475BC1BF8ULL,
		0x387C36B89A2F4569ULL,
		0x88DF37FDED86EC1AULL,
		0xBBA10D462647C1F5ULL,
		0xF36933CBC66B29F0ULL,
		0xD85FDDC5E7A4FB46ULL,
		0xC715AEA6D3CC3BE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8C7D026989202BULL,
		0xCCAA67C3E9A455B4ULL,
		0x56B72218FCAC91F1ULL,
		0x161724C15DD7CFC6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB2826850D3116910ULL,
		0x9E5609F8E4D67134ULL,
		0x86066B96237F7F21ULL,
		0x888C2EFD6076C73BULL,
		0x5F2254AB73B4DCCFULL,
		0xE639FD8321ADECD7ULL,
		0x59888D843F950505ULL,
		0xF9C18C7D3316A14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD19AF9C3FFEA355BULL,
		0xCAF1AB6FE4A7992CULL,
		0xD04B6D37939E3E01ULL,
		0x1B470992F5D2B86AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x07B2664325A88050ULL,
		0x3FF2F8F5C8840BB3ULL,
		0x350F2F3A48BB55A0ULL,
		0xE0A22A6FEFBE3B1DULL,
		0x60D08603B7248381ULL,
		0xCB8A3026AF7E619DULL,
		0xA1235C51E4B88FE5ULL,
		0xA8A841E099E742DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A64AD05514093FULL,
		0x76761EB3D546890FULL,
		0x204EE3623C20B1BCULL,
		0x699BF1C6C8122803ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCA08A860E11BA27DULL,
		0x8D2D898B8C096B3FULL,
		0x40842B0D47BEAE77ULL,
		0x012BCF77E8EAFE26ULL,
		0xAF0B19D9C9E30074ULL,
		0xEE0BF7FADB5C4A7BULL,
		0xCEB4B9DFA8DA98C8ULL,
		0xB8B73D2D7099F219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5AE7EB4D8CDB7B7ULL,
		0xE2F458C81BBC799BULL,
		0xEF57C24058315C4AULL,
		0x6C5EE4369FC4EDFAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB6597C0D27B0E07AULL,
		0x443FDC8249413FFAULL,
		0x5E9C508E748CBD0DULL,
		0xF875605C9375DC89ULL,
		0x3E762D3980443C1DULL,
		0x6D17F745F27F96E2ULL,
		0x1D92291348890D9DULL,
		0x4FE0C283BDEE2FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE4329631D1CEA3ULL,
		0x75CE90E44831A58FULL,
		0xC24E696B38E4C26BULL,
		0x53D23FEAC4D0EE99ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4A887A7FDD2C0AABULL,
		0x7FFCF92105AA4FDFULL,
		0xB8FF49F3AE523D96ULL,
		0xCA521E15A2C44F10ULL,
		0xF76EBFA253181C07ULL,
		0x81FA95CD71CFBA80ULL,
		0x03074C39BF96E753ULL,
		0x3D673DCFBA57B544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F8EC9832C0351EULL,
		0xCB2F359FEA7FFF04ULL,
		0x2C149A861EB893FBULL,
		0x67A54AEB4BC93729ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE7AACF5399194327ULL,
		0x4625DE1B1232BDA1ULL,
		0xB3572C26DAE511E7ULL,
		0x61BA916FBF246B37ULL,
		0x745D71B5972B9FBCULL,
		0x6DB242E52FE38655ULL,
		0x940535652A902146ULL,
		0x546F47CE1AF6B8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D89B0480992FAEAULL,
		0x8E9BCC202DF8AE51ULL,
		0xAC1D192B2C4A025BULL,
		0x6A3F3A07BFC3D4D5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8D5D6818AFC45E58ULL,
		0x99A3EEDA716AAC99ULL,
		0x7BDCA34F4E6C0A12ULL,
		0xE339C1A8D52B99C1ULL,
		0xA8986EB748E7320BULL,
		0xBEABAD82634D811AULL,
		0x511E4014C29038DFULL,
		0x738AD99469C984C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93FDD74D8215CEA6ULL,
		0xE71FB0352EEBD68EULL,
		0x865A26642FD47B48ULL,
		0x09D60DB089154EE5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA84373B64CDB3486ULL,
		0x34F4494A5A906839ULL,
		0x3F4861133AB9CD85ULL,
		0xF109DA850ABA5E12ULL,
		0x5C2A6C7E6125DF61ULL,
		0xE71932FF520BA507ULL,
		0x40EB5C6C9E911756ULL,
		0x3CD3B6433F479551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x568F8E78B87A5E55ULL,
		0x82B1DB30884AE751ULL,
		0xE2381932C443446BULL,
		0x7876E8806F5A8821ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8C40F1D2A7EE3FBCULL,
		0x29EE575F91C9F344ULL,
		0xCBC66CBE49EDB0E0ULL,
		0x363913E82E088904ULL,
		0x130CD4711E0E4507ULL,
		0xCCE2A4CE126DD75CULL,
		0xD49A14AE1E5B468BULL,
		0x966769D9E0626D19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60287A9D1E0C821DULL,
		0x9392CDF64E17EAEFULL,
		0x5AA57E96CB7A29A0ULL,
		0x0992CA3F7CA4BADAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x75ABA5566C9F0104ULL,
		0x68F8824D5895674FULL,
		0x8D73D69244353728ULL,
		0x27AB579FAABB6DBEULL,
		0xD4F154637802F836ULL,
		0x340ED35CB8765EADULL,
		0xAECB7BCAAE6E482FULL,
		0x4FF05279D6DB34AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117E2C1A3D0FDAD0ULL,
		0x232BE210BA27751DULL,
		0x7FA836A82893EE2AULL,
		0x055795B58F453F14ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB6FD398E34F902C5ULL,
		0x580CB389BA6D5CC2ULL,
		0x08B1F927B3A0A565ULL,
		0xDEA5C491B47E397FULL,
		0xCD986BE4016627EEULL,
		0x1079CE3649D6761EULL,
		0x87FD75BD008F4652ULL,
		0x1DD70F340D35AA64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9D3D666A22F0D7ULL,
		0xCA214F98B042E555ULL,
		0x38517335C8E51593ULL,
		0x4C92064BAA75846BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x58973ECD697C20C7ULL,
		0x79068A280275C786ULL,
		0x496526C92A050FF8ULL,
		0xE6179C08FEA135E3ULL,
		0x32837B798D6AA4B7ULL,
		0x249E3E9BA8E5E84BULL,
		0x259CCFCF3C713B51ULL,
		0x18A45654724B0CD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD81B92D86750949CULL,
		0xE883D543149642AFULL,
		0xDEABFF8C22D3DE03ULL,
		0x0E7C6C91F5C51D3AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x081708DB8E0E5BE1ULL,
		0x4E34A5EE00D4F753ULL,
		0x9A25E8D532D042E7ULL,
		0xE0C3E5B2D5217014ULL,
		0xD1C88A67160810E0ULL,
		0xC276CBB3DCB42014ULL,
		0x2F2183A081B81DB2ULL,
		0xC51C69B431FB28F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BDB9428D340E195ULL,
		0x2BD6E2A0C391BA6AULL,
		0x991F72A87424AB70ULL,
		0x22FB967240698453ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2B95DBB6516CAC9BULL,
		0x441B7880F4AFA55DULL,
		0x1126AB053E4ADC54ULL,
		0x467C73D05A995D56ULL,
		0x771CC67C84EB7DD9ULL,
		0xBDEC3A6E611C0B5EULL,
		0x104CF60BF293A33FULL,
		0xFC31BCDB5AFD6757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9DB52320C616062ULL,
		0x752C24E35ED95562ULL,
		0x7C9330CB403517CAULL,
		0x35DE7C5FDC36B442ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8E3646269A7DE03CULL,
		0xBE6FCB745FB73E06ULL,
		0x0B536BA3F1C80B9BULL,
		0xD63E4DD852FF17E6ULL,
		0x7349CFE6B8DE4DDDULL,
		0xD23F082D47B55ED7ULL,
		0x4AABC8B5F5C93F09ULL,
		0xF69A0B8C8019E6FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB2B22660B7D7488ULL,
		0xF3CB022D04A35201ULL,
		0x20D336A66DA76710ULL,
		0x711C04B356D761A5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFD2A95360A1A2594ULL,
		0x451BBD72F86F2920ULL,
		0xC553C4E020B19F88ULL,
		0x69DF955E4E3B2105ULL,
		0x62C0E55449379145ULL,
		0xC04A3B160454B000ULL,
		0xA6AE880207995E34ULL,
		0xE182E076D414F5F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5CC9FB8E859BACBULL,
		0xD02082B79D01492FULL,
		0x833BF52D41759B5CULL,
		0x634CE701C957A37CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x81DB8A5C51876E13ULL,
		0xCBC52F3D4E73FEDAULL,
		0xEFB6F92D646E9552ULL,
		0x4A4320A0D9313BD2ULL,
		0xE68BA230D62B5040ULL,
		0x7ADDE5B66A173A11ULL,
		0x51AB08C971BCCF9FULL,
		0x90EBEAEBB5289EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA959D9C1BF55AC4ULL,
		0x08B548510DE69D82ULL,
		0x0F1A4714467566FFULL,
		0x4D47FF9DBD38D547ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6932BD6ADCBD08F5ULL,
		0x8DDD22FEC098CCA4ULL,
		0x4D30251C0F46DFFBULL,
		0x3B8E8E67D482183CULL,
		0xB8100F639B1BA9CBULL,
		0xF2C8EF7F7D2FE03BULL,
		0xCB5C43C2D71C2BB3ULL,
		0x8697EEFC18979689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB950633E2D8400FULL,
		0x97B0AFEB55B41581ULL,
		0x7CE23407FD755CB1ULL,
		0x361C07D37B0270B0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBF09EC39A0B1EDA8ULL,
		0x4AD2C2ADA71130F7ULL,
		0x172341F439C98424ULL,
		0x97DA0C18A3523C2FULL,
		0xA4265E2785EDA0ECULL,
		0xDD8778EB85A7A6BDULL,
		0x6C6412AFFAF57814ULL,
		0xDC1BA97EBB811C70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBBE61781F7D596ULL,
		0x2CEEB5A37DF3F11EULL,
		0x2DFE08137A39573DULL,
		0x43F534E8787C74DFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0F85701043086136ULL,
		0x4202F3EA5370EA6CULL,
		0xA3BA4755CD688DF7ULL,
		0x9C5A627A29B4EC2AULL,
		0x3CD3E0DED954D446ULL,
		0xB546847B3CC90A27ULL,
		0x7C03A0A9A3DC3D0EULL,
		0x4A6CA94AE54DD73BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F8D124859FE54FULL,
		0x2A7A9E3559486C3FULL,
		0x0C44208420199E26ULL,
		0x287B83983342DEFFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x37B3E2916FBAEE2DULL,
		0x8B68F48B4C636398ULL,
		0x5EE34D779AD31A08ULL,
		0xBDA302103278DED9ULL,
		0x6865C752404424BCULL,
		0xBB6667FCEE209D68ULL,
		0xF0081FCE5646AE82ULL,
		0x5C32ECB2FC1FCDE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6CF78C6F9D86429ULL,
		0x5C9C6416A53AC117ULL,
		0x0018061869510170ULL,
		0x6D3224A19F316F47ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCAAF560F3CD33FADULL,
		0x3D3C5773BD5ED567ULL,
		0x18228AA4A0B08F91ULL,
		0x8268DD882CE768D4ULL,
		0x975A3DB7F42CF12DULL,
		0x9225F25FB6D71EC9ULL,
		0xEB79F76E1CF38806ULL,
		0xB7F238FB9C273FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42147F5D7B7F1070ULL,
		0xEEDE51A8E14D6754ULL,
		0x0C3D44FCECD6C08AULL,
		0x505D52E15ABAE39FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x43BBA583DF69BAF8ULL,
		0xD26B250C3603B9BAULL,
		0xFF2A14006C477AD3ULL,
		0x0CCAB627FB46597CULL,
		0xC8AB23529A753859ULL,
		0x22AB34095E4B470EULL,
		0x9A610D00F174D253ULL,
		0xDEB9BE88689D96D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D22E3C6CCD01D14ULL,
		0xF7D4DE70353045ECULL,
		0xE9920224439EB32AULL,
		0x1C5CFE6782AABD0BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBF92EAFBD9AF3692ULL,
		0x130B50944713A026ULL,
		0x3E5B88DA0C075A29ULL,
		0x06195A13526B3011ULL,
		0xDAEF3A6D0C184D42ULL,
		0xB8B918D607227755ULL,
		0xBDED160F968DB3CBULL,
		0x80C7E591C554D089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F15972BA54AB130ULL,
		0x7E850059563156E5ULL,
		0x6F8CCF2A65100A66ULL,
		0x23C56DB69D022483ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAD856BA5BEE8838EULL,
		0x3CED0EE048226D68ULL,
		0x526C5113A2A56531ULL,
		0x2D39697803699063ULL,
		0x7E693C4FF561F7B9ULL,
		0x5C7D8ECE48628BB1ULL,
		0x8C9F8102784D46F9ULL,
		0x7A566180B7FEA53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71245F842B734BB0ULL,
		0xF790417F06C329C1ULL,
		0x321977717E1DEE34ULL,
		0x560BE29353361714ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAAE32E6DC0A78ADEULL,
		0x9B37B0314DC35098ULL,
		0x4C2002F2D2E04836ULL,
		0x786986171B3751DCULL,
		0xBE51823C31A39128ULL,
		0xC2D703B72A887B16ULL,
		0x09C5DB7AB879FDFCULL,
		0x69D7EF41767E1ABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAFC835D1EEF192EULL,
		0x87223D619E0595F8ULL,
		0xBF7E972A34FBFBBBULL,
		0x2E7709CEB1EF49C5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6DFCA41101B77759ULL,
		0x9C237A561F1B6B3AULL,
		0x6607985AE067DE59ULL,
		0xD5CF7E9197D49E6BULL,
		0x780A3A27969FACA9ULL,
		0x1E63B45D83FAF93EULL,
		0x383BD6043DC59491ULL,
		0xB454627DA7322753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8145F15D6B1C84ULL,
		0x1EF04037B65C6A80ULL,
		0xBEE95CFC0BBBEBE4ULL,
		0x1A561D38694674C5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7CA260FABA1E8B7DULL,
		0xF506456F03254293ULL,
		0xABDE3FA7CF75083AULL,
		0x61171F31872CEF53ULL,
		0xC0FA8A19EE19AD1FULL,
		0x10466CE9FDDA4006ULL,
		0x815F2B58C52BD1E2ULL,
		0xE53FD24B07CF7F09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D2E0D411EE4323ULL,
		0x5F7A702AB18AC394ULL,
		0xDFFEAED513F62FC9ULL,
		0x68905654AFF9CABCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF2DD56A410AA4608ULL,
		0x0A8D697BE5CF0F36ULL,
		0x989EBED9254F3A74ULL,
		0xF99961F25493568FULL,
		0xB8A8A0269FADE24EULL,
		0xA968E5C2CD84BC09ULL,
		0xD0B81CFA8ECC2911ULL,
		0xF66EF58C70C0E364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BE51C5FC479E32DULL,
		0x301F84666782F8A8ULL,
		0x93F30C0A579D5313ULL,
		0x0E11D4CB11351786ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x329CCF347E65F4ACULL,
		0x6882EE0615B61ED1ULL,
		0x92C0C0FE9B08F74BULL,
		0xBEC3EDBB77577F77ULL,
		0xE33528EFB18144FAULL,
		0x50C2A9053CE82BAFULL,
		0x2971C6F3F77524BFULL,
		0xAB8B985A46B438EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC80E2C8D79635A4ULL,
		0x656804CD202C9AECULL,
		0xB9A44935566C6BB1ULL,
		0x357C8B21F617F239ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x708C072706F391EBULL,
		0xD9677970DB0F807BULL,
		0xD47911F0212E93A0ULL,
		0x846F6C878761B154ULL,
		0x4B3A18742402A182ULL,
		0xA75C7AFA57A6D1DAULL,
		0x63037B7547D230C1ULL,
		0x5A10E6AA3168F992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B2BA8645F578D38ULL,
		0xB121BA99DDD2A6E2ULL,
		0x86FD6558CA61D05FULL,
		0x62F1A9CADCF6BD0FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC5FF2759CFD7DC5EULL,
		0x205F7E11B2C61530ULL,
		0x0D561F3D4127397BULL,
		0xD5A517F6B92B7FCCULL,
		0xAB7944EAD1FCE3E9ULL,
		0x85D5279C5D515389ULL,
		0x8B05DF9B93960818ULL,
		0x03F4D90CB7C522A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39FF6234FB61B11AULL,
		0xFE035F478CD87BA0ULL,
		0xB0355055296C6D1EULL,
		0x6BFD4FDA006EA3A0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9031813BAF984B04ULL,
		0x379371CEFDCDED27ULL,
		0xBE590F011409D8C6ULL,
		0xB63882FF122F6193ULL,
		0x93CEED85DFE5F4ABULL,
		0x0074F7B382721C2EULL,
		0xB53D513D7F71B88EULL,
		0x91865A6B7B2CE680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E8C31AEBBA9FAAULL,
		0x48F036745ABE1C11ULL,
		0xA5731E21FEEB3DDAULL,
		0x5029EEF35AD998AEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x86AFC40D63C0527CULL,
		0x0D9AD49A2B00B3D0ULL,
		0xE645DD5CE84D5D3CULL,
		0xF79BBBB461872BC5ULL,
		0xB3CE771B65721940ULL,
		0x6DCA3C50531D204DULL,
		0x163BF5BF27DED913ULL,
		0x53858BBA3C738E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3755721E72B013EAULL,
		0x599FC88681537F59ULL,
		0x332C57BCD361961EULL,
		0x5D6E79595AAE4781ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7B4965EBC0054C7DULL,
		0x67EA0284E0D01E05ULL,
		0x9C461D42A96FEF4DULL,
		0x209C3E78C1DFE724ULL,
		0x4C6DFF1503606972ULL,
		0x679C35E65B94EB43ULL,
		0x888FE0AC77BEEC6CULL,
		0x78812108BFCC8118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD39D430A4054F615ULL,
		0xC91A02B678EB0A02ULL,
		0xE1A176DC6FC70764ULL,
		0x03C725C53A3B10C8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x13CD4224E66841ADULL,
		0x50FEA40A5A9987C7ULL,
		0x64BC170F1CB93A87ULL,
		0xC02AA6C80A6E1BE3ULL,
		0xC933645814182C64ULL,
		0x0BE8A576630D97D8ULL,
		0x23CAF3E321C29347ULL,
		0x327EB327024C089FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF16E2737E1FED9B5ULL,
		0x1587339D0E9E11F4ULL,
		0xB4DC4AC61F9B1713ULL,
		0x3EF93E9261B76382ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE5AD10A7A08457CCULL,
		0xCD44A18C496C142AULL,
		0x79EA26A583E3F74DULL,
		0xD515B151A96B6E69ULL,
		0x29C0016B87C7245CULL,
		0x2F373FD290DC9BF4ULL,
		0xE48B4E53522B232BULL,
		0xE8B21D43551BED39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182D469DC813C2A6ULL,
		0xCF781ACDCA2B3A69ULL,
		0x6697C703B64B2FB6ULL,
		0x5F8609504B90A501ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4F2FF7A0D5032F20ULL,
		0xC298F795879E6CE2ULL,
		0x6E0829F518A94B9CULL,
		0xE486FCB5584D8633ULL,
		0xEF0310B94C8A0DD9ULL,
		0x900F00E7D0B6E0F7ULL,
		0xB49F4CE719C003B1ULL,
		0x3A4EFF4BBF227DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A4732231813EBFULL,
		0x24D319FE82C3D1AFULL,
		0x3DAD9442EB29D7F8ULL,
		0x0C40E1F3B76C2F78ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEAE7DDEEA914A220ULL,
		0x6C88AB2E7D32E58FULL,
		0xFA9A83F23BD85BA1ULL,
		0x3F35BF67547AEEA0ULL,
		0x3E9E0BAB8E524B02ULL,
		0xC0E2924EDF046376ULL,
		0xAB0D05EB5C1F60F2ULL,
		0xB8E2AD38578D3B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x365D9965C94BC881ULL,
		0x0E2A62E397D9A91DULL,
		0x5E8964E1E880BFAAULL,
		0x30DB75C45371BAACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFB80672CE7ED50EFULL,
		0xA1FD54F79C71A336ULL,
		0xDD0352BB7F2F1BD5ULL,
		0x78420A0FC20E9590ULL,
		0xFB7B63D8E3E6A53BULL,
		0xB05B0C2626C387B2ULL,
		0x4AD854456DC682AAULL,
		0x325C0221650ED207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FD1395EBC29D8CEULL,
		0xCF8122A15D77C7C8ULL,
		0xF91FD509CAA6812BULL,
		0x71EA5B04C241C2A5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E4A64F861EDBB67ULL,
		0x7C947F1F9D86C991ULL,
		0xCDAFB6274F70D487ULL,
		0x0040743D1C3CB7FBULL,
		0x8AB9AC91FB8708A8ULL,
		0x7183DECB90248AC0ULL,
		0x54A857B8CF805CC0ULL,
		0xCDB649506C55EDB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05DA02A3B7F908DEULL,
		0x5627915702F36226ULL,
		0x5EACBB961C7E9918ULL,
		0x094F562D30FE00E6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x73399B0FC6659C62ULL,
		0x265797A3A4D0833CULL,
		0x4C7AE3034B74ECD0ULL,
		0x0A92740C4334E23DULL,
		0x8B3E2E480D187E92ULL,
		0xBBA1DC8E3633258DULL,
		0x9FF1825395511383ULL,
		0xFDBCCE8CAB958B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E7479C1B8086B9FULL,
		0x005E54BFB068163FULL,
		0x0A543B6B757DD25EULL,
		0x34991CEDBB679BA3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x33825906979017AFULL,
		0xE6852214DE2CAE40ULL,
		0xE842E57F5704E14FULL,
		0x726620B8062A207BULL,
		0x04847FBD0C14A3A9ULL,
		0x7119CEB5293F7692ULL,
		0xA148665F77B6B91AULL,
		0x526878C861FCC39AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF2D4F1662A064A0ULL,
		0xB059D0F8FD9847ECULL,
		0xD90217AB1C245B3CULL,
		0x2DE80E7691AF296FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4F3D13C80F5CDF64ULL,
		0x451B24BB5DD5998DULL,
		0x817395399C4A2667ULL,
		0xD339242EC401D326ULL,
		0xF6EB45E8F3CBA5C0ULL,
		0x6E853AE0686D1B40ULL,
		0x0D4DBE6E2B188098ULL,
		0xB1662A820384011FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF629745C3F977DE6ULL,
		0xACE1E20ADE07A531ULL,
		0x7AFDD99401ED3D07ULL,
		0x2863737B4999FDC2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE3162454D3308F7FULL,
		0x275B8AE7EADF0B46ULL,
		0xB2675097DA546461ULL,
		0x11C38A690E006869ULL,
		0xB21B339CC8A25D5EULL,
		0x8238E57DEE93CFF5ULL,
		0x78FC740DCC39A886ULL,
		0x929FA24F2849305CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x531FCD9A9B4A6EA4ULL,
		0x7BCD9B9954CFE9BFULL,
		0xA7E08AA42AE36858ULL,
		0x5575A22908DD9623ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x338A64C274717F87ULL,
		0x49C3B15F93071C36ULL,
		0x7806244C2F90FA57ULL,
		0x460F7161982F2077ULL,
		0x2587C4439D261D29ULL,
		0x78EAF1518F50C85FULL,
		0xD27547D222ADAD3FULL,
		0x9B47F5F486ED1869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B186CBC819D707ULL,
		0x3CA3837AD904DA55ULL,
		0xB56ECD7D5558B1C3ULL,
		0x52BDF3AD9F60C02CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEC25DB1F5058F956ULL,
		0xFD3B03B010C3C23AULL,
		0xFC37EE079CAFA53CULL,
		0x92AB52FA49468CD8ULL,
		0x83A3DC721B4493B5ULL,
		0xF8468CF327AA4F47ULL,
		0x65DC1DCC7E646544ULL,
		0x355790E4937DA743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7678940F5C86E764ULL,
		0xD7B3EFC7F40B86D8ULL,
		0x1AE45A625F96AD79ULL,
		0x7DAAD4E82DED60DAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xED22B051ED551EC6ULL,
		0xB1ED663363E20160ULL,
		0x94CA29A816182B8EULL,
		0xDA7C84BB235A9CD0ULL,
		0xAF777513D4104059ULL,
		0x8FD2E6263B37BEE4ULL,
		0x41AC6E2198A4D84CULL,
		0x974350E5AA63BB9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8DE114367BEAF66ULL,
		0x0B3B8FE02E285752ULL,
		0x546282A4BE9046ECULL,
		0x4E7A86D26E2875B6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x60697907DADEC2D1ULL,
		0x57990681C0100AEFULL,
		0x4111D1FDCE39C3D0ULL,
		0x4993A9E92DB08268ULL,
		0x0640C29B1573FA60ULL,
		0xEFF20E8CA57445EDULL,
		0x3BE3E399EC03B67BULL,
		0x83A40A578EC2BB7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E065C0D0A15EFF6ULL,
		0xF5872F624F526C1EULL,
		0x24E59AD6D6C6DA35ULL,
		0x53ED32E85E98568DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x64FE3AB8C6E5556EULL,
		0x3524A5B15440CD34ULL,
		0xA1B17E7429F7D1EFULL,
		0x0B78B425859824CFULL,
		0x284D199E43121225ULL,
		0xB1444F028C2458DFULL,
		0x4EA520663D0A36BEULL,
		0xA4DD5E05270ECF66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60700836BB940A8FULL,
		0x8548601221A5FE54ULL,
		0x4E344DA1397BF23DULL,
		0x0454A8E951CAEDFFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x61129705D83B616BULL,
		0x230D5C9BFCDA27B3ULL,
		0xBA669D0D4C2B848EULL,
		0xD2482CD8C2CE31E8ULL,
		0x4EFA7F7DC117E736ULL,
		0x8EEE8D70C57016DFULL,
		0xF1693BF941998560ULL,
		0xF969F80347FFE5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A4183B081C7B900ULL,
		0x5A765B594B7D8CD9ULL,
		0x9005840D08F550E3ULL,
		0x5802FD5572CA4FF6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8E9F2CA2BB77E943ULL,
		0x79BAC2AE304F9DC4ULL,
		0xD61B8F2D2395CBE9ULL,
		0x79E501FE7BA482D2ULL,
		0x2E942910A344B5A5ULL,
		0x7A616B8D6846EB92ULL,
		0x87BB47F18C2E010FULL,
		0xCBF38E140468C00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789D451AF7AAE448ULL,
		0xA430B9ABAAD69577ULL,
		0xFBE83D07F269F435ULL,
		0x400C18F7233104FAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x37055B4CE2AE104BULL,
		0x4EF083BA77A03973ULL,
		0xBF580CEDF9400AE8ULL,
		0x6257FB734DFFA394ULL,
		0xB8776D26DEDD7EB7ULL,
		0xFD42098216DEDAD7ULL,
		0x44528557C61B9DCFULL,
		0xFEEE769640B72670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BF8F11F78EE519ULL,
		0xE6BDED09DCB4B578ULL,
		0xE397D7F5615977C7ULL,
		0x39BD95C0E92F583EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF5230A9446E64484ULL,
		0x82BEDF464993AF9AULL,
		0xC99243A2A1796DA0ULL,
		0x97A86881582D6368ULL,
		0x6E1D80C03A0D1AABULL,
		0xC25E10A8CFA79127ULL,
		0x135480E20CC996FBULL,
		0x840FEFD144DE2292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D84271CE4D83CDEULL,
		0x5CB558551C733B75ULL,
		0xA81D65308765D6FFULL,
		0x3206019191268517ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x69E53660887DF99BULL,
		0xFF3BEB4921E9089FULL,
		0xA3735FA9F26ED42BULL,
		0x8B4B640D87563B72ULL,
		0xE72BB4F4B35B7B21ULL,
		0x9725C8E957EE2554ULL,
		0x4DB53495E16EAEF0ULL,
		0xCF0A2812EA2A44E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA6212B32812451BULL,
		0x6ED7BDEC2F429339ULL,
		0x2C592DE968DCCBE2ULL,
		0x46CD56DC499C7530ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6A974B268CA7BC2EULL,
		0x157F0B89B9F87EECULL,
		0xFA3F77C8F7FD3E17ULL,
		0x3D1EE666A765F7BEULL,
		0x571D873448E14B6CULL,
		0xE65584F065492773ULL,
		0x2A65C38A0E965CFAULL,
		0x4C79CEA4EA423BDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F95CE95E18EFEBULL,
		0x4630C738C2D45A0BULL,
		0x455A7E47224F0B55ULL,
		0x173392E16D3ADAB9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x069BFE1F4189AFDEULL,
		0x51C940AC27E5EDD7ULL,
		0xA47D361395167F8BULL,
		0x7C324D44D6449A2FULL,
		0xB2947BA5AC844874ULL,
		0x1102639F888CF3EDULL,
		0xCF727B1E0E2F20DDULL,
		0xFD70CD20CDFC7260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A658B6DD2C76BAULL,
		0xD8240A5A6CD2231FULL,
		0x6F7B7C89B015605BULL,
		0x1AF0C02369BD948EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x912A1FF61590F654ULL,
		0x8ED72FAD36A52DB7ULL,
		0x3907434D1139AB57ULL,
		0x816E716C509299E7ULL,
		0xC3D0B1712FB9CC9CULL,
		0x2616EEEA9810F1A1ULL,
		0x170E6C99DA39F2CEULL,
		0xD0262EE4F2B91B9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22476C32B255A16ULL,
		0x363EA67FC9290BBAULL,
		0xA52B622375D3B5F1ULL,
		0x67196768580CB2C6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8FADA404E9BB62EBULL,
		0xFB8FD346A79F0609ULL,
		0x15F3A327A2A29A6DULL,
		0xBD9228593A702352ULL,
		0x2479853D64533F26ULL,
		0x4FF7FF7EB082BE2CULL,
		0x5D070C240A0F5F44ULL,
		0x1F34B6640108CC19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9B76B21CE16C34DULL,
		0xDA5FC014DB074096ULL,
		0xE4FF708120EABE91ULL,
		0x5F653B3161BE6F15ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x90D886381382E42CULL,
		0x8D3827C29907FFC1ULL,
		0x825A4082C608E505ULL,
		0xF90409ADCD0B8F98ULL,
		0x03B8B8AB19C17711ULL,
		0x706CCA7B03A8F893ULL,
		0xCC48CCA054256D84ULL,
		0x4FF7FF2C7C34E039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E43EF9DE63A928DULL,
		0x3D5E3605241CE594ULL,
		0xD528A04F439726AEULL,
		0x57D3EA483CE4D82CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x14FC4DF5441C2C53ULL,
		0x7905ED9FEE591CE4ULL,
		0x8E9ED85232AF83EBULL,
		0x08553AD8D3793229ULL,
		0x1A3789F312973496ULL,
		0x65D3070DE86347EAULL,
		0xCB81382E7F8EBCE8ULL,
		0x20BAFCE2D16EEDFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF93AC80A068DFB42ULL,
		0x9658F9B06D15C9A3ULL,
		0xC3CD2F3921DF8E6AULL,
		0x6416C483E9F08563ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x479044E59927544DULL,
		0x2A9EEF55FE974F5FULL,
		0x9A6790DEE04DD66FULL,
		0x2F864EC2493D67CDULL,
		0x9FDA3EBE5913CE62ULL,
		0xE5D13AAEAE5CDA6BULL,
		0x6FA8A433B2E656F2ULL,
		0x2EDF69EE7B7A8356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F59526D217F7E3ULL,
		0x47ADA543E05FBB59ULL,
		0x2D6FF08B6E7EBE7DULL,
		0x24B008289D6CE6A2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x07ADE5D193178889ULL,
		0xD7D8F04D801BEA98ULL,
		0xDC5A4A31FA72186EULL,
		0x69B9095BCD3D1DEBULL,
		0x279CBEEDDA06919AULL,
		0x1015280D7A6CD723ULL,
		0x31DB6528A8B1289DULL,
		0x2850DC75D81189A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F23D1FF0112649ULL,
		0x3AFCE24DAC43D9CFULL,
		0x42EB4E3B04BE1FBFULL,
		0x65B9C2D9DFD78C4BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x61DE32441A97AFEFULL,
		0xF0999A3D0F292810ULL,
		0x6E67D2E87FE87EB9ULL,
		0x4C5535B7FDE52B1AULL,
		0x452B1077043746F6ULL,
		0x9EC164ED0F402D83ULL,
		0x595038A0DD2C09DDULL,
		0xF501114E5E7FFB4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA642A3EEBACC3DDEULL,
		0x814E956D52AFE98CULL,
		0xB0503AC95471F59FULL,
		0x2A7DC75A04E478E1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFE4F20C2ABEE5B57ULL,
		0x95B7B88609445654ULL,
		0xFE523D9086E10FCDULL,
		0xC5C7ED1C319D6030ULL,
		0x0138818671CBC47BULL,
		0xA7636FDA3274189FULL,
		0x4B9F5E3593E51136ULL,
		0xBAD74D29AB2FE6D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CB25AB7902D89D4ULL,
		0x6E7A52E9867FFDEFULL,
		0x37FA39847AE19DEAULL,
		0x01BD614B9AB9A38EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4AD56DE3B0FC2DABULL,
		0x346BFCEDF138D471ULL,
		0xEC6D47CAC758AAFEULL,
		0x71A68F2B5520C1B0ULL,
		0xB9447BC3981072B4ULL,
		0x2B2BF7072EC249DCULL,
		0x93A702AC58E40D40ULL,
		0xD96AEF6A8B512875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAFFCCEC436D3936ULL,
		0x9CF2A7FEE20FCB34ULL,
		0xD737AD5FF932A284ULL,
		0x378618FC032CC324ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDBA6425098040B77ULL,
		0xA577C58E563449BBULL,
		0x35306A9B27F9D492ULL,
		0xDD48CCE6D3FE7A43ULL,
		0x568CC6F03A418C31ULL,
		0x8B5F66CA05453F82ULL,
		0x3E408644359C7F52ULL,
		0x5A9E937F4BF145E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB48BC9F93DBEDCD1ULL,
		0x55A1078B1E7BB714ULL,
		0x72C458BB1D34BAD3ULL,
		0x50D2B1CC19CEDA4AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE7C1A5CF4FEDC338ULL,
		0x2F90AE8A1A868E60ULL,
		0xC42A65E1A4BB6F0DULL,
		0x0FB6ED819D551276ULL,
		0x6F5AA4482D7AE9D7ULL,
		0x0386EC518D8DB88DULL,
		0xD6F8BDDAD77E8FF2ULL,
		0xE143E00A83119479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F360886102C7E08ULL,
		0xB597C2A51D8FF35FULL,
		0xAD16945DA184CCF9ULL,
		0x7FCA2F1111F11C8CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3DBA5C15EB4E9BEDULL,
		0x24E9FA3A2CB7B66CULL,
		0x45AA885E1F6B9D2DULL,
		0xA4C8514FA1BA3D2CULL,
		0x2F98D30217A9F20EULL,
		0x70AB9FECA60A89CEULL,
		0x14EF50F7E5C05BD9ULL,
		0x7AE275F861EBD54FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E69AE656E888CC0ULL,
		0xDE63B75AD2482B07ULL,
		0x61308D2A39F93F73ULL,
		0x6265D42E2ABBE6E9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE1AE64176F6FA5E8ULL,
		0x9D6578223AAC0FE6ULL,
		0xBD51968045D2EB00ULL,
		0x782E692218781E4FULL,
		0xA3CD6D04895442CFULL,
		0xD39D106908B1ABDBULL,
		0x8CF517F8CA215CE1ULL,
		0x96A7C5E39624E97BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x322C92C3D1F193F9ULL,
		0x06B5E7B9850B9281ULL,
		0xA9B3256E46C6B486ULL,
		0x5515C8EA61F2C6A6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD98B6BAC65C487B8ULL,
		0x774BAF3E6B18A8B6ULL,
		0xA10ED06759BAFFE3ULL,
		0xCAA5662CE176F80CULL,
		0x1D4ECA8A7AD6BBA3ULL,
		0x4E77AEBF0A671EACULL,
		0x53E7E3963CF72759ULL,
		0x2714F72BAAE67DDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x333D7C3AA1A462E1ULL,
		0x1D0F9F99F6673643ULL,
		0x157A98B4666AD725ULL,
		0x17C216A83FADA70DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x86B849D2518836B2ULL,
		0x329F607584F4B09DULL,
		0x8326F65B3CF47443ULL,
		0x2B28C5B3B2F50B5DULL,
		0x20C262639E1753B2ULL,
		0x98F2B32EBD1D6C27ULL,
		0x74EC867BB387DA94ULL,
		0x016515168F902E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6392E49BC8FEA31EULL,
		0xE6A5F9659752BE6CULL,
		0xDE42ECB7E31EE651ULL,
		0x6029E70D025BE9F8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB488C7D7C30F1783ULL,
		0xB1D4AEA7C1F1E926ULL,
		0x54721F6996099402ULL,
		0x3D096DC048A62825ULL,
		0xB5116F06892904ACULL,
		0xA83D5D4F4D209A2DULL,
		0xA78CE632C957BF67ULL,
		0xC3851B510B4B553CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951F42D01F25CD59ULL,
		0xAAF0886D34C8CBEFULL,
		0x335C4AF3790FFD65ULL,
		0x42CB7BC7F5D4CF26ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE974C95E323A137EULL,
		0x1C5F95999006C597ULL,
		0x920C626AB0B27282ULL,
		0x834D7D4825B4F647ULL,
		0x4C8AB8ABAB1FBD54ULL,
		0x4FCE5A93C4D8309AULL,
		0x5904A18D4126488BULL,
		0x94C9992D1AB9D213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x460C32D998F0314DULL,
		0xF5010788C81DFC7FULL,
		0xC8BC5D625C61372FULL,
		0x193A39FA1D4A2526ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x45D78BF8E24CA4C3ULL,
		0x4EF52D343E3D9604ULL,
		0x96E852741C37959EULL,
		0xA7763FE5FF5762A3ULL,
		0x8781845A7A924B5BULL,
		0x8F1EE6E6E6B833A5ULL,
		0xBA465665DAE37547ULL,
		0xB0683CEE6BEDE217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631131671403D834ULL,
		0x8D8B737A7D954096ULL,
		0x3D59259299FAFE3DULL,
		0x56EF4B4A04A6F229ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6ACCFC6A4E64FCB1ULL,
		0x10D405E2708A6189ULL,
		0xE8EEC4187D8243CEULL,
		0x7F90EF4743313234ULL,
		0xE11942E5064E03D0ULL,
		0x8AA6291F8E570C30ULL,
		0xD03E040C638C131AULL,
		0xAF7A11EC88C69ED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD48CEA693DF99180ULL,
		0xA57E2091917630CAULL,
		0xD2235DEF444D19BEULL,
		0x0BAF986390ACC5F1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0E3ED9C52240A8F5ULL,
		0xF824591EC7608991ULL,
		0x0182DFA7CA632710ULL,
		0x7A4EFE95F889291AULL,
		0x573DB0CF8B4DB608ULL,
		0x845901E44A907FAAULL,
		0x44AF192560ECBA98ULL,
		0x720863417FBE3F0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01671893CFC9B0ABULL,
		0x9D5AA101D8D37CDAULL,
		0x33809B342D86D9B4ULL,
		0x678DBA4EEEC684C6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDBC531B92745E6E4ULL,
		0xE936CC6CD73DBAA8ULL,
		0xA74CC71F85A3D5B8ULL,
		0x19B1A3AD89C4A1F6ULL,
		0x511A27BE37A1C79FULL,
		0xCF8592A0C2568FC5ULL,
		0x7CB48E2EC3303B2CULL,
		0xC2CDFFAF8C87B4B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A717F569498CCCULL,
		0xB70A9049B01711F2ULL,
		0x2A19E2107ECC9E5FULL,
		0x044597BC65E974E7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3DB8FC624ABB61BCULL,
		0x90B4D20EC64A5691ULL,
		0x7F28A8CFB532DC20ULL,
		0xE75FFC8A3843BC34ULL,
		0xB31E8711E23CD588ULL,
		0xAAE6EA9DBDF1BA40ULL,
		0x80DFD5DEC0BF5B17ULL,
		0xA5A95D62C6AD883BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4410909DFC317A2ULL,
		0xEEFBA578F82BFC2BULL,
		0xA06267E0519A61A3ULL,
		0x7E83D933B605F509ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA162AF38DA601D7FULL,
		0xBC2039F198C17931ULL,
		0xD4AC6D2782ABCC5AULL,
		0x8694C4A07942FCF1ULL,
		0x32AF4A3E6B4E8CDDULL,
		0x7A55E0FC8EB7597AULL,
		0x81E8B1462DE38E6AULL,
		0x5A9087E01677E80EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2767B47CC809084EULL,
		0xE4DF9F6EC7F8C155ULL,
		0x1D36BD925272F028ULL,
		0x7808EFE3CF0F6F19ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC51B6EE3D43380E9ULL,
		0xCC0A957B9CA63C82ULL,
		0x0E35CF8AB23E0578ULL,
		0x025A9610D3011E0EULL,
		0x817DDAA3DCDB822BULL,
		0xCE13EAC790E93F3DULL,
		0xF0AB8E450CA29E25ULL,
		0x47939F7DD6D15198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC9E3369CC8D4DAULL,
		0x62FF6F1B1F459FA3ULL,
		0xC7ACEDCA92617F15ULL,
		0x224442BEB6133AC1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x633286B9B5F72293ULL,
		0x10B15A61A564B952ULL,
		0x2B37CEB481947F64ULL,
		0x823FCAB334AE4B5CULL,
		0xB4E2667C8B4F6C76ULL,
		0x436CBDE97F66040CULL,
		0x0768AE86C7625D49ULL,
		0xC08EE8976FE4D5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CCDBD3663C14065ULL,
		0x12D58B0A8E895335ULL,
		0x44C1B6B61A2E5844ULL,
		0x1776512DD0A60A9DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDE7AAD160CA0FFC6ULL,
		0xDFF6EB39726B037EULL,
		0x94C660E389BAD2E7ULL,
		0x17601F3629DA9C4FULL,
		0xADD8CA5939093FDFULL,
		0xB4D55F37CC057ED5ULL,
		0x21220032EA9684D6ULL,
		0x8989849B9C6B6638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA8B65484007DEBULL,
		0xB7A30D81BB3BD736ULL,
		0x7FD268725C128AC6ULL,
		0x01C9CE4F61CBC8A4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8FBFFF2B0B558858ULL,
		0x5968BC135BF3D064ULL,
		0x6109A1F2F74EDE28ULL,
		0x2ACB4FB47DAD7615ULL,
		0x05020230B80D8993ULL,
		0x9F5AEA8817664CC9ULL,
		0x8CDE0667D1ED4815ULL,
		0x55F21BD1BCDD2584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E0C52665D57F605ULL,
		0x00E78C46D523363BULL,
		0x49FE955C2087915EULL,
		0x6CBB70D6868107C2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB3D7B4F5763DC013ULL,
		0x9C508DC48DBF7B72ULL,
		0xE98A162CA613582CULL,
		0x2D3432B9AB3BC59AULL,
		0x1E84F2F53FA08C94ULL,
		0x6C0ADC9768A59490ULL,
		0x15F8246B563D1031ULL,
		0xB7E1233CA675146DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B93C55CE812A20DULL,
		0xA5ED4C3E165388D7ULL,
		0x2C5F7E1B7323BF82ULL,
		0x789F6DBA609CCDCCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5DE076D3BA802C44ULL,
		0xA0BD3B7D8D767E4CULL,
		0xE3D5E6510A53C2EDULL,
		0x72E0A13DAD5EE8ADULL,
		0xA49124D24A391ED1ULL,
		0xF412611D96DB8B3EULL,
		0x94B6C2836ED7AA32ULL,
		0xD0D6C100A4DF3EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6BEE0ABEFAC3E4ULL,
		0xDB77A5E1F20D2998ULL,
		0xF6F6C5D37E57067DULL,
		0x72C14756268238D1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6040A836A4C393BCULL,
		0x3896EB285281B4CBULL,
		0x3A22491804841C50ULL,
		0x379326C33D5408DCULL,
		0xE31A27D7E6BD7874ULL,
		0xD15054C0C02444E2ULL,
		0xD06EE036BE02972EULL,
		0x5D562C9D8D1183DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16229242E4E37708ULL,
		0x4A837FC4D7E3EE79ULL,
		0x2A97913838E68D43ULL,
		0x125DC6262DED9BEFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC1BEB77D3ABD14B0ULL,
		0x4253E2CB788F10A9ULL,
		0xD96A0707E8E065A7ULL,
		0x14B4E91DB882F561ULL,
		0x11BF3454704C5BBFULL,
		0xB1E80194F8A7F043ULL,
		0x73F4B4FD0846F221ULL,
		0x4BB638CD53636567ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64207C05E612B4ACULL,
		0xAAC41EE8617CBA9EULL,
		0x0FBCE497236856A7ULL,
		0x51C15798194402BDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF5AA8CC5FE050D07ULL,
		0xBCEEEF6BDB45E2B2ULL,
		0x89D1F16B841B1487ULL,
		0x27168266B0928059ULL,
		0x192A1357DC785D1FULL,
		0x10A8302BDC986477ULL,
		0xB4A64D3092BA4933ULL,
		0xB6E869FE8AB3C5DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1E96BD0B7E2E3A3ULL,
		0x35E615EE99E4CC60ULL,
		0x5A8166A14BC1F21CULL,
		0x4D963E2F4741DF42ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1423F0E6E37D77CBULL,
		0x6677893EBFF28124ULL,
		0x69391388DE62ED8BULL,
		0x9C7A3980A5BA341CULL,
		0x7776B96D1C69DF98ULL,
		0x06E388F8BB2D99CDULL,
		0x998F2E9B8752452FULL,
		0x0CF28E8A3B3ED215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC377191B34A8BAULL,
		0x6C3DDE2A88B755A3ULL,
		0x3479FE9EF4993286ULL,
		0x087B6205710D6351ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x45B3E5EAB1EAFABBULL,
		0x43BB100DDE2D53D9ULL,
		0xF9CCE4E7856EFBCDULL,
		0x61EE1E49E2BD91BBULL,
		0x8DEDD90B4FEDD026ULL,
		0x86D3A56DEB7B0512ULL,
		0x120E994EF3BADA68ULL,
		0x45019F93DFA52426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57021D988F37E1EEULL,
		0x47259E5ED270149AULL,
		0xA7F7A69FB32B6751ULL,
		0x202BCE3D1540EF62ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5B0A20AB9D1C854FULL,
		0xD0D1ED5DF986DD68ULL,
		0x899DB8FC7F3D65DAULL,
		0x48DF02676BDC64A5ULL,
		0x2C19BF315FB3347DULL,
		0xD21E189427EC83D3ULL,
		0x980FE27429C34369ULL,
		0x82CE6C8DAFEE1225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6DC81FFD1B652C2ULL,
		0x0149935BE6A26EC0ULL,
		0x1BF9563AB2396790ULL,
		0x33831F6F8933163AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5E91234F490FB8E7ULL,
		0x616AB4379E971A44ULL,
		0xE78B49D9C50F5E65ULL,
		0xEA3C49F7E32A909CULL,
		0x75D69AFF60551373ULL,
		0xB3CF8E195CA5EFABULL,
		0x4AA8024D6BC9DEFFULL,
		0xCA150036A42F3AC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC6C253795B0A080ULL,
		0x1239CBFB5F38ADB7ULL,
		0xFC7BA157C506785AULL,
		0x695A5214422D4A0BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE0E7CDD291A4B685ULL,
		0x4746B7279AE5B932ULL,
		0x1B815D72D656740FULL,
		0x1964C9DB5AEF63A4ULL,
		0x62CB3ECD7B41188AULL,
		0xE7A6393B4DAB9DB6ULL,
		0x6D2866E91AD67A95ULL,
		0xCD4B1803226E8F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B132052DD4E5F88ULL,
		0xA9F335F5225F2245ULL,
		0x4F80A40CD22CA64FULL,
		0x128A5A527758A190ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x18EFE761935B5DEBULL,
		0x47F55DEC6247EE77ULL,
		0xB9E8366B02C78A77ULL,
		0x7F59CF8B2A27B020ULL,
		0x802868DDFCF72683ULL,
		0xA257C7E77BDCFACAULL,
		0xA29EB7CEC8BE9DD3ULL,
		0x14712ACFA2FEA6E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EEF7855200B15E2ULL,
		0x60FD0A48C5152886ULL,
		0xDD777F1CCF12F7E1ULL,
		0x08262A5D5BF476A8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB5CD6781E5E7EDC3ULL,
		0xF49F2E2E74120C72ULL,
		0xD986497C440741F2ULL,
		0xDE44F933F1305B25ULL,
		0x663E93D64565BEA0ULL,
		0x6D9591EB29438643ULL,
		0xB9DD70ED702696E5ULL,
		0xF39665EC40760C58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE317595033023F01ULL,
		0x38D2D7169417FA73ULL,
		0x70650CBAE9C1A801ULL,
		0x06981A4582B63051ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7AF3452A374AD250ULL,
		0xAC026422106B5EA2ULL,
		0x997FFAD389F58A3AULL,
		0xE41A76B6BE8CB63CULL,
		0x41C3A4DB2BB89BF7ULL,
		0x0A2DC1368C15E6D5ULL,
		0x1B54959B69164E0EULL,
		0x6567DF617FF2AC81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DFDBDB2B4B1FB47ULL,
		0x2ECD123ADBABA24AULL,
		0xA80E2FE523452050ULL,
		0x71859F2FBC925166ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBE5780C09AB5B4E0ULL,
		0xCC85F18E224AC4B0ULL,
		0x1C2F73BDD6BA0E87ULL,
		0x273CA0E45CA306F6ULL,
		0x224529E918D0841CULL,
		0x6B6E9721D1E287FFULL,
		0xCF84281C0712F646ULL,
		0xE732D18D6CC8C6F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD49BB95A49A95614ULL,
		0xBEF0609349EAF48FULL,
		0xE9CD67E6E38A9CFBULL,
		0x78C7BBE282708FE4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x16D483C6A14C88CDULL,
		0x91609247BAC0D612ULL,
		0xBDEC9D8BC0F8487DULL,
		0xCEFB82E66A7C07F0ULL,
		0x3AC9A19AE96D7B77ULL,
		0x6416F23624A596A4ULL,
		0x96174CEF7B792D9AULL,
		0xE8ABA1779D6702E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0C280C5478CE1A9ULL,
		0x6CC886512B553272ULL,
		0x0562091814F50D68ULL,
		0x58757AA7C7C675DFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1D8A20E2BE7BCF27ULL,
		0xB3EA6CF7D1B1638EULL,
		0x903032EF44AF8573ULL,
		0xB2538D7D23B49699ULL,
		0x141ED1CD7DBE8EBDULL,
		0xA599C135A400F2B0ULL,
		0x48FE982799229F59ULL,
		0x39DD07F2DF59F5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A1D456368C5008BULL,
		0x48BD1AEE29D569B1ULL,
		0x65FAC8CFFFD32CC2ULL,
		0x4922BB8A4B0F15E4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x63EF5EC57FE167DFULL,
		0x97D27546DCC21935ULL,
		0x25E8A6193A825465ULL,
		0x83690D7166026395ULL,
		0x5A7F14E809451965ULL,
		0x069B98D16E0FC5C9ULL,
		0xA39CA7815C5FD6E3ULL,
		0x48B5B8EC82BBC556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2CC7936E0232E7FULL,
		0x92EB245D33197518ULL,
		0x6F29834CF0BC3A18ULL,
		0x4E62808CCDE1AE71ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC9D35221C9CC18C3ULL,
		0x8770143AFB71FE40ULL,
		0x422AA052FECF3ABBULL,
		0x958098FB2805C9CDULL,
		0xCC2535DDA6C403E9ULL,
		0x7030D6B82F2BA4B7ULL,
		0x2DBD72D52D85DA75ULL,
		0xDE7896C269E064E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x175951088AE4B252ULL,
		0x2EAFF391FBEC7189ULL,
		0x0C49ABF7C0ADA82AULL,
		0x1B66F9D6DF54C3F8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE489A9F0275A4D46ULL,
		0x23B97A09041109A0ULL,
		0x3CEF69A914A0F936ULL,
		0xEEFCF10311B47FECULL,
		0x5AFB4C63764EF61BULL,
		0xE8916AEE43734F91ULL,
		0x99B6621DCA22D8A6ULL,
		0x39E432329CF451F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D700B3B712D6B1ULL,
		0xA94F5967072ED934ULL,
		0x0E01FA1515CD21FCULL,
		0x06DC64865DF8A9EFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8D10CF778F806D58ULL,
		0xCB8502C63F6608E1ULL,
		0xF37B11ED451C31E2ULL,
		0x98B2E53237A09F74ULL,
		0x155FC7EDEC22D763ULL,
		0x4D6DD5B7B5844537ULL,
		0xC593B1279E5711CCULL,
		0x7A111FB5E52D64C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9487CC89CAC68C9ULL,
		0x49D2BC0B31084F0EULL,
		0x47675DCEC608D636ULL,
		0x373D9A323C5D94D0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDDCDB27658B2F4FFULL,
		0x6464CA4CDC8DCAE7ULL,
		0x8126C72EE5B367C2ULL,
		0xB1D525F290883DE0ULL,
		0x80D2645F100290DDULL,
		0xA6164EEDAE7F5742ULL,
		0x29F1B8A07F389295ULL,
		0x616860AE0BD8A6B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD089892B9147807ULL,
		0x0BB48194C374BEC6ULL,
		0xBB082F01C81929F9ULL,
		0x27537FC852B0FD10ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDC7FD202B569868BULL,
		0x64DB0C88416C7C21ULL,
		0x7949224C23EF58B9ULL,
		0x5A8A70EEF9E52283ULL,
		0xE910CFBFE3206A73ULL,
		0x66E7FB3B4DF58463ULL,
		0x23104D20A6B9793AULL,
		0x6DFA7F8FF952F1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74FEA87E6C395610ULL,
		0xAB4A5755D3DE22F6ULL,
		0xADB49524E3775764ULL,
		0x2DB9604DFC350A14ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x40B0A89B830FD222ULL,
		0xF105C87D76675A90ULL,
		0x696DD5EB73741A83ULL,
		0xB2B5E7C6CB9525F7ULL,
		0x1EB71B8C40668F24ULL,
		0x2ECEA1CA237921FEULL,
		0x82200F140781DB58ULL,
		0x1E140BDE4B9848A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFDEBF6D12491238ULL,
		0xE3B1CC7EBA626648ULL,
		0xBA3012E490BAA99AULL,
		0x29AFAAC6042FEDF0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x94C6981C132E9418ULL,
		0x57DE57A04ECE4DC9ULL,
		0xE2F8FD1459023778ULL,
		0xC51C27666BB2682DULL,
		0xCE4B07AB034E0E33ULL,
		0xAC06C106E17F92F7ULL,
		0x2066D856D01DC99EULL,
		0x0F085972FB4D5BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33E9BB7E90C4B01CULL,
		0xE0DEFEA5C7BE1E92ULL,
		0xB23D19F73D6E2505ULL,
		0x00596E77B92E0218ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEFB618C33EFF946BULL,
		0xB60D3484962008EDULL,
		0x8BFA393919CF9B8AULL,
		0x1C01990BBBFDE473ULL,
		0x25A7EFB2A9EC1818ULL,
		0x8BE5B4337279AA4DULL,
		0x3C88B1E67BEC0847ULL,
		0x3556FD8DB9FC21A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A3AD48780B292BULL,
		0x7A25F427942F5061ULL,
		0x8844A16F7ED8D629ULL,
		0x06EB3C15576AE36CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5756DEBA62B058A2ULL,
		0x5D362338EC45F4B4ULL,
		0xCB0577DF016EEAF2ULL,
		0xF81EACB652FCACB4ULL,
		0x580B0778EEB7761CULL,
		0x099D20AC419D48D4ULL,
		0x55F9CB1E6B2412E7ULL,
		0xF241465DFF5CF3AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F9FAADD1EBE635ULL,
		0xCA88FCCAA99EC439ULL,
		0x8E199E62E8C9B93DULL,
		0x6DCF1EAA3AC8D895ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x631424505209B66FULL,
		0x8E6F9C266E3FC06FULL,
		0x6A21ABC00433C01AULL,
		0x27A4E33CC3B86430ULL,
		0xDD12576BF447353DULL,
		0x9B41A4FA26109D74ULL,
		0x06205F00479FB8ECULL,
		0xEB19AD2D74C625EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CD1E56949BA2AFULL,
		0x9A2E194814B71FC8ULL,
		0x52EFC5CAA5E93339ULL,
		0x0D7497FC19220513ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x777C168F3898201BULL,
		0xD336CB0936D9BE67ULL,
		0xB30529AC73665EBFULL,
		0x38C04AA326FE8F98ULL,
		0xD500196C1AFFC3A8ULL,
		0x0C950B14C6327307ULL,
		0xEBA65B19E30AFF5BULL,
		0xA3B9AC94F29A4884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x157FDC9B3A8F2EAEULL,
		0xB156701EA256D191ULL,
		0xADB6AF8427084643ULL,
		0x064FE8BF29E55353ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF19121ACD45E37ABULL,
		0x3DF6A934EDC43BF7ULL,
		0xEBF7200313E2B9BFULL,
		0x66B3EEE6E7B865FCULL,
		0xED214FF19BBC54D2ULL,
		0x431C4D0AC58EFC8BULL,
		0xA8E452AADECD6734ULL,
		0x10796D72CE92F611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2482FF89F252CF36ULL,
		0x342A18CE40FDB8BDULL,
		0xFDDB656026600B81ULL,
		0x58BA2DF19188EC9BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCDAC4F9AB77F88B3ULL,
		0x65AC345BC0F33465ULL,
		0xC0CD94EAE7975402ULL,
		0x5613F6E38C4AB14AULL,
		0xD6B28E1D143378FBULL,
		0x13ADBC4FFAE340C8ULL,
		0x786AD595210508B8ULL,
		0x9522A3CD7590C04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2D67EBB7238139ULL,
		0x5176283AFEAED235ULL,
		0xA0A9490DCE569F55ULL,
		0x79384762FFC73CCAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x77717CB6D3130CB9ULL,
		0x85C35E80244580F6ULL,
		0x96F1738CE7E5FD5FULL,
		0x667D72BB64423933ULL,
		0x0B8AA665A489E699ULL,
		0x7932898D76C55841ULL,
		0x1468696B052FEEB4ULL,
		0x5F4EBF5548E09AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E062FCD3F8B4996ULL,
		0x8343C97FC5909A9EULL,
		0x9E71196FAD036C29ULL,
		0x0C2DD964359934FAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCDA66FBC07EE2671ULL,
		0x4F4DD3A7B575049EULL,
		0x26390E8ED85EBD28ULL,
		0x4BB21C008B31B3E0ULL,
		0x4F897260469433FDULL,
		0x6165BED995D83414ULL,
		0x3BDA5DB0132652D3ULL,
		0x689784A2D6D9456AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C0D6A0681EDE04CULL,
		0xC46827F3F38CBFA2ULL,
		0x08A2F6B1B00F0888ULL,
		0x522FCC2C6F7201A5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAA05EA6C86C85EE5ULL,
		0x9B9079554DD43430ULL,
		0x5F25CA279AB32551ULL,
		0x52173060DF69C79DULL,
		0xC03140255B41C0F7ULL,
		0xA8E4BC4196919AB1ULL,
		0x4E3A3740FD4E9886ULL,
		0x91AB334D6CC8E976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31556FF8128B06C0ULL,
		0xAD846B11A7712A93ULL,
		0xFBC9FDCD345DC94EULL,
		0x7180CDDF053C6F2CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x551930C87E536362ULL,
		0xA0A047261649BF41ULL,
		0xC571333FE0223BB0ULL,
		0x8A61157E948782E8ULL,
		0xE4E2F9735E231AD0ULL,
		0x897CE2E1F0EF437EULL,
		0x28C4DAAF9937930AULL,
		0xD40C4F6982A95C42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ECA37E877896302ULL,
		0x0929F4AFD9CDC417ULL,
		0xD2A9A9509E620F41ULL,
		0x0434DF27F9AB34BAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF0D07B33511D5AFDULL,
		0x9A610E33BF2D39C6ULL,
		0x842B7097DC174A4FULL,
		0x3E62CEF864980CF8ULL,
		0xADB34F4CD9C4771CULL,
		0x8E88E43F734A0768ULL,
		0x1B92C8308B94B659ULL,
		0xE5A03781A5775797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96E409BA4470E31ULL,
		0xC2B2EF9EDC2A5350ULL,
		0x9BF527CC942A5B9AULL,
		0x542B0C36F44F0D66ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4AF626A012588591ULL,
		0xA40E1EA0FE46FD50ULL,
		0x3C9FC7BA4F0E311DULL,
		0xB237C30125277634ULL,
		0xBA5D0B6756673CB0ULL,
		0x03CA7D8F0269FAB7ULL,
		0x1713FC856C23DB4DULL,
		0xAD2650E32D37FF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4C5D7F6E5AB8B8DULL,
		0x341CC1DB5A023495ULL,
		0xA99743885C60BE8CULL,
		0x65E7C4B9DB7764B3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF99099171D3E30D1ULL,
		0x71C7A1503BA9F47DULL,
		0x4D629FE33718BE44ULL,
		0x6668B1D69132FD27ULL,
		0x5C8158985A8FADB1ULL,
		0xB869832FA965FB2BULL,
		0xAD329469ED2C25C4ULL,
		0x459A8C290E06E8A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C3BFB48E91FAA6ULL,
		0xD1711A6360CD3CEDULL,
		0x02E4A79C6BA65977ULL,
		0x3B597FEEA639854DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA781501C13189357ULL,
		0x9A63CE4FD5FBB30EULL,
		0x4B9F2BC1E149D316ULL,
		0xFEABC31CEE8A984BULL,
		0x6797B8CE197DDAA2ULL,
		0xF0FB51272AB97047ULL,
		0xF105ABB1E883C3EDULL,
		0x94B41CB23BC62BCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0806BEB3DBC70ACDULL,
		0x5FB1DA202D825DA8ULL,
		0x1276A82A64D8E868ULL,
		0x11680591CDF5186BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4138B2706B3215E1ULL,
		0xCD1350E4CF11D959ULL,
		0xA536385EA22CBB7DULL,
		0x4242EFE87F2E3086ULL,
		0xD6D09FB065FF5F00ULL,
		0xC641A4443B5BA3F2ULL,
		0x2E7934D4ECD34E0EULL,
		0xA3F5B58F63B78031ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2430669F8F1A3384ULL,
		0x3AD1B3059EAC2F65ULL,
		0x8B340FF9C98A51AFULL,
		0x18BBE3314C6B37D3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE8ACBCB277C16F34ULL,
		0xE68E7C3082FF6446ULL,
		0x76F0A5FA5BC70F70ULL,
		0x3793FBF3FD936AEBULL,
		0x0937A413357A67EAULL,
		0x894355F76A86AE9AULL,
		0xCA0E5D81EAEA5E0AULL,
		0xD6C2D0A521C14990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46EF178C67ECE0B0ULL,
		0x468D3EEA52FD4F24ULL,
		0x751287433A910501ULL,
		0x187EF47700445669ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x67F64A05FAE64D85ULL,
		0x5E8C6932C95B95B2ULL,
		0x825CE60A7C623096ULL,
		0xAD7059A5181CA638ULL,
		0xB8D058E701164A76ULL,
		0xD27A70F80D2BE3D3ULL,
		0x548F6A96C31F9FF6ULL,
		0xA1F2A878188F93D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E37C5024355EACULL,
		0x9CB92E04BDDF671FULL,
		0x0FA6B86B7313EF39ULL,
		0x37755B78BD6C9797ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x24690C7C14FEDF6DULL,
		0x94CC79F6F5646C3DULL,
		0x76C438AD365E9446ULL,
		0xEC448D5A232C0B5CULL,
		0x869C8535211E66E2ULL,
		0xD9258689CA456348ULL,
		0x25716A533B96619FULL,
		0xFD0350163F13BF58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA4D25EFF822A9DULL,
		0xD05E726AFBB12901ULL,
		0x059A01080EB11200ULL,
		0x7AC270A7801A7272ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9927F5AEAE954D5CULL,
		0xD4515DA707754948ULL,
		0x4E2F0EEDAAB15A8AULL,
		0x1FE5F068110D0D5BULL,
		0x3E86794FD56B4E30ULL,
		0xAEB4F8C1A0A3655CULL,
		0xA95DC7E90CF12385ULL,
		0x00293D0792D2B120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE11DF7885C82E87CULL,
		0xC32E4A64DFB654F9ULL,
		0x721ABB85967CA062ULL,
		0x2604FF87DC535834ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAA583DD2ADF842FAULL,
		0xC9D24D983D25C744ULL,
		0x1C0568266821EAB6ULL,
		0x783EB3E1FE72CAF4ULL,
		0x229D125E95523B0AULL,
		0xCF4EE8E328C8065CULL,
		0xF58119A1ECF24188ULL,
		0xF4A4DF5A7C5F41D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDA8F7DCD82D0BE1ULL,
		0x8F88DF504AD6B8F1ULL,
		0x8D2F362F9417A505ULL,
		0x48B7DB5074969128ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x52687F96292597F8ULL,
		0x075BA52B1D4E940EULL,
		0xA5C927E5F89EAA2EULL,
		0x420CCDADB396AC93ULL,
		0x94B59F0D64DE315FULL,
		0xC843065F58A6E9ADULL,
		0xE09C273A9CF33BC7ULL,
		0xFBDD7F61240B60D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x655E1B932220F1A3ULL,
		0xC14E9752461543D2ULL,
		0xFCF6FA9944B989D5ULL,
		0x24EDB6190D470BBAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x36AA23ED02EF6240ULL,
		0xA909904A267B39A9ULL,
		0x169B68A6D9D8F7A0ULL,
		0x3D22E590D6E92F1EULL,
		0x20A0A2AB64F1FF04ULL,
		0xCB17971779C013F9ULL,
		0xC463F85DC5929A09ULL,
		0x578012FE2634A9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E82495DFEDB3EC6ULL,
		0xCE89FDC638FE30A4ULL,
		0x3D7246922D9BD514ULL,
		0x3A25B74A82BA6869ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE82D8E5A2F50AEAFULL,
		0xE359DFCBD24AEBA8ULL,
		0x7A641275031ADCEFULL,
		0xCFC6E5849AEC306BULL,
		0x59BDAB3CFBC3C18CULL,
		0x57B9D64CF3C62ADDULL,
		0xDC0E3430A94C50C8ULL,
		0xC5526AD3AA5C9770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A54F9678E5F6DEBULL,
		0xE8EFAF3801B54884ULL,
		0x247FD1AE246EDAACULL,
		0x1A02C0EFE4AAAB2CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x29BEEBD2741ABB7DULL,
		0x1A9051088B328FD4ULL,
		0x58A43818C587557BULL,
		0x2A43D51B21A202DAULL,
		0xB09F572F9F4A06F4ULL,
		0xE8E6F427975EFBC4ULL,
		0xDA5991759FD7F60DULL,
		0xB76B3DA2331A59E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6165DCE41917C7B7ULL,
		0xACD88EE9034BEF06ULL,
		0xC1EFCF8E7F95DB8BULL,
		0x642EFB2EB78B5A60ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAC99D8CB96F0825EULL,
		0x48D218C3B67A390FULL,
		0xB897E767187E8851ULL,
		0x406C2FB59C0EDDA0ULL,
		0x9ED2C004A69BD6C4ULL,
		0x18357170A8D20AF4ULL,
		0x7B62D3AB8ACAE5CAULL,
		0xD021A423A32CDBF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FE2597C52126810ULL,
		0xE0C0EF7CC5A7D95FULL,
		0x094352DDB29CA450ULL,
		0x256A8CFFD4B7845DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC19D8C5E4D86ACD1ULL,
		0x257FA9F27ACB475AULL,
		0x4C40D18CBB83E7FCULL,
		0xAC1D3DCF9087CEECULL,
		0x96E4059A4B6B3EA5ULL,
		0xC5A732BE47E2554DULL,
		0xB17E71D000A8122EULL,
		0x0814049DEA9C84F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x277661457F71F988ULL,
		0x7C5132312663F0DFULL,
		0xA505B66CD4769AEDULL,
		0x5F15ED4063C38B18ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x39FBAF82AD049EB0ULL,
		0xF0C9BF15896E657CULL,
		0x0AAE668168D4E788ULL,
		0xF4AC0515F2381B37ULL,
		0x2CFAE5D533C3F127ULL,
		0x7907D925C5F97DF5ULL,
		0xED5A000F29961B59ULL,
		0xF9DCFAF0B628CC7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE739CD285C1A701EULL,
		0xE7F3FAB0EC7717E0ULL,
		0x460A68C1951CF6D0ULL,
		0x0B7944D0FC46759CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x280AB534DB3394EBULL,
		0x7D06B87ADADE11A0ULL,
		0x43654AEF802243FBULL,
		0xE936288C8BC081FFULL,
		0xB91BCE0E982118F2ULL,
		0x8DA9303B99A07640ULL,
		0xE6F567AAAAC346F5ULL,
		0x517FC0BD786B4956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22B4B5F701D4AC5ULL,
		0x8423E153A8AF9F3BULL,
		0x8BD2AE44D91ECC6EULL,
		0x022CC4AC6BAD64E5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEF11706E660EF9D0ULL,
		0x6AFD604630AFDD23ULL,
		0x2622CB333C55EFB9ULL,
		0x07F30E5733F75308ULL,
		0xC381D2E7FE8F3745ULL,
		0x362185FF62BC08E3ULL,
		0x4BEA74F274AA32D9ULL,
		0x34280DFFE07AE9AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF456BEDE2F512F2BULL,
		0x73F7442ED8992EF2ULL,
		0x6AF027308D997BF7ULL,
		0x45E522528636024FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5D0A0E0678675EAAULL,
		0xAC688076F630DE31ULL,
		0xB605CB46B346CF30ULL,
		0x31FF29210CC81F44ULL,
		0x665D17D717BE223DULL,
		0x865856C9FD7ED011ULL,
		0x360FB36F8F79BCFCULL,
		0x14DC48D297A1EAA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EDB97F3FEA0742AULL,
		0x9D8562729703C0C6ULL,
		0xBC5A6DD5FF58DCACULL,
		0x4AB1F8638ED0F332ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5FE6502140E4D9B2ULL,
		0x921589954CB6F77EULL,
		0xAC390B99F38E7CAAULL,
		0x43F6D6539EBA04C2ULL,
		0x6912BBA37A0C57B2ULL,
		0xE4394BF5EADA88A6ULL,
		0x9E6DFED04901259FULL,
		0x0F33EC676CB79AC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8AE2A655EB9DE7DULL,
		0x7296D01629274031ULL,
		0x308CDE84C9BA1266ULL,
		0x05ABEDADC1FAFEB0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x15EA73819D3A232DULL,
		0x3C9B3C1FB8F7AAE0ULL,
		0x5BE25FD63978F100ULL,
		0x80F37977B912AC94ULL,
		0x374624AA842EB8ECULL,
		0x30B4FF7242FE178FULL,
		0xD60B3FEE81AE4F83ULL,
		0xEBD1B99F17EAA553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A53E4D13C299B7AULL,
		0x77792715AAAF2A22ULL,
		0x218DDD3D7958BE79ULL,
		0x0215071545E73706ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x15A670BB0315E6A0ULL,
		0xDDE5464D5ECA1B97ULL,
		0x45E11C4215396F8CULL,
		0x2ADD7BBDDC4090E7ULL,
		0x642FBAEDCD9F4D22ULL,
		0x3694DB45E6F28677ULL,
		0x76A39F5A013EA6FCULL,
		0x8FF8050F0A3A0105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4BC300788BB5CDDULL,
		0xF7FDD2ADA6CA114FULL,
		0xE22AC39E448638FCULL,
		0x09AE3BF960DCB7B6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x47E9293C3FDACBE8ULL,
		0x4548D610578C885DULL,
		0xA55A4992ADC3ABFDULL,
		0xD21304B71334E636ULL,
		0x4FD7ED32EBCFEDFAULL,
		0xD02F838BBD89CF20ULL,
		0x8A5CD11737DA2937ULL,
		0xAF145A2DFE711F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21F65ECB40B822F3ULL,
		0x2C565CCE7A014729ULL,
		0x2F215304F825CA46ULL,
		0x4F18678AD7FF804BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2DF7CF672A6F7483ULL,
		0x9682A10326A08F41ULL,
		0xED14111F6A9C5EBBULL,
		0xD865ECE57CFF9FCDULL,
		0xC19444F179A2DD22ULL,
		0xBB69A9DE7CB31874ULL,
		0x0B533217801BBF8EULL,
		0x767E64CDEBC0372EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9FA0B3F389C4A3BULL,
		0x6831D809A9363095ULL,
		0x9B6D809C6EBACDEBULL,
		0x6F28E3767B87D0A3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E4EFDA2BD4B938DULL,
		0xF4D5D91924C2544CULL,
		0x574D59857B4FEFAEULL,
		0x485C8CEF15887A69ULL,
		0x92699510193271B9ULL,
		0x331BD8939CB9A642ULL,
		0x6A1C756EB14D6ABEULL,
		0xBE28054FD41344E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FB1E067AC8793EULL,
		0x8AF7FF026851022EULL,
		0x1786C7F3CCCDC7EAULL,
		0x024D56C89064B477ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x85D4ABA802F15E37ULL,
		0xC9E0FAEBC018D047ULL,
		0x9F599F58CEC61C6FULL,
		0xF5FEC4CB9D85E25AULL,
		0x32E4412FADB801BFULL,
		0x142DA274A1752FE9ULL,
		0x8037E9335C8B24CAULL,
		0xEB5BA17DCD670B8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B658BBCC41A5D6ULL,
		0xC8A7183BB77DECE5ULL,
		0xA7A63CF88B6D926EULL,
		0x6598BD781AD198E9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x31EF7258DD8EB082ULL,
		0x2D7A6EC3E7E59560ULL,
		0x8BB440FC5599AA4AULL,
		0xEC94A8A8F8A0F4F1ULL,
		0xCD14E567D765BDB8ULL,
		0x5E84F7DBD40D56BDULL,
		0xEBD1F8044BB01B2AULL,
		0x8D84AE30A8B2D6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3097FC2D6A8DD03ULL,
		0x3537396561E0758CULL,
		0x8CDF119F91BDB294ULL,
		0x6E4683E2032CDA2EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDDA351F2971E60BBULL,
		0x17FDFE81154101C3ULL,
		0xC11B0DF7ACADD293ULL,
		0x2BFC6E8853DBE818ULL,
		0xDFBCE551022E7F95ULL,
		0x9B1CB6600A8C69CEULL,
		0x08B7199D84009F57ULL,
		0x81B58AB6DE9F4182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13AD5BF8EA0553ABULL,
		0x1E4110C2A618B679ULL,
		0x0C48DB5944C57994ULL,
		0x6CEF05AD5F7FA166ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x4B2F8E05E678ACFAULL,
		0x6CE73635AF7C56B7ULL,
		0x8AA16A4F2D83EB7AULL,
		0xBC25C7E4AD056429ULL,
		0x1560F57558473320ULL,
		0xF6A03789E3BFD5C2ULL,
		0x737B0A40DDB3792DULL,
		0x24A93AA94F805C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7793FD71010A449EULL,
		0x08AF74AD7DF61186ULL,
		0xAEE4EFF01627E84DULL,
		0x2D447D067A1319BCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAAAD3A6D8FA9B75BULL,
		0x7029D4EF5B8DE248ULL,
		0xC7FDDF54AA246C7AULL,
		0x05AEC3075D4AD16DULL,
		0x6817486C8F6793CEULL,
		0xBB8D0BEAA602901BULL,
		0x4FEED045CD3C2A94ULL,
		0x5193CD6E121C6FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E21FA8AD909A9B7ULL,
		0x471999C3FFEF465AULL,
		0xA570C9B12112BE8EULL,
		0x219F415E0D8368B7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEBBD4EEEFE60CA82ULL,
		0xEBDF3DDBD36462C0ULL,
		0xCEF0DE0DBE32181EULL,
		0xA98AC487D25C26CFULL,
		0x784B1E2C8CB2B584ULL,
		0xD41CBFB8CD613D45ULL,
		0x9CAA8AA6F829D106ULL,
		0xB890783F836DA0BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6E3C98BE0E7C042ULL,
		0x6823B34A4FD37B10ULL,
		0x104172D694671F22ULL,
		0x0EFC9DF554A20341ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7F9C104A654D16ECULL,
		0x6AF317155E67CD99ULL,
		0x3229B751E6155C90ULL,
		0x54C772D65E769EA4ULL,
		0x511E6A37BC3E27EBULL,
		0x2A9625CF05AFA698ULL,
		0x81210295296171EEULL,
		0x1C3804A36C914DEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A1FD49056870479ULL,
		0xBD3CB3D0367A8835ULL,
		0x5D1019760A8C45EAULL,
		0x051823187C08300BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x17E9F58D8D18BBAAULL,
		0xFCFA85A77A6B7D0BULL,
		0x282D16761D997B94ULL,
		0x180A24F468C11A79ULL,
		0x438D12614BA14233ULL,
		0x93367FD503DD8F46ULL,
		0xBEA2EF7C2A513C5DULL,
		0x1AF0C7612E779174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EDAAFFEC7088FD4ULL,
		0xD7117F460D4EC179ULL,
		0x745CA2E465A87178ULL,
		0x17C7BD614E80B1CDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE84443342E784203ULL,
		0xAB43D9213693CF90ULL,
		0x2BA866DC051355F9ULL,
		0xE4F74F06F56ACD70ULL,
		0x205D88430679E5D8ULL,
		0x72A2C9A5103337F0ULL,
		0x2430BDC863FC9D1FULL,
		0xE617AF243E293F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6267D2724906545ULL,
		0xAF6DC7A19E2E1D35ULL,
		0x8AE4929ADC92A8A4ULL,
		0x0C7B4E682F8A3887ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x90D638E2F812DA33ULL,
		0x3D81C0D080E3D922ULL,
		0x540EA90FA2192C2CULL,
		0x73FD9DF523BEC744ULL,
		0xBF5473FD04EE1B96ULL,
		0xDFF1D16DC6EA7351ULL,
		0x1242AB1E00E3F672ULL,
		0x68A106852B5F5902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75F7071B36AF4C4ULL,
		0x7B66D71C07B0F744ULL,
		0x09F40F83C3EFC139ULL,
		0x7BE495B993E5FD93ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x69327EC4C2F0D4B3ULL,
		0xA25233E73DD5A46DULL,
		0x3E73822F64BAAF7CULL,
		0xB07743F3E68F76E1ULL,
		0x167B271132D20486ULL,
		0x14D854FED77FB795ULL,
		0x9ABB140B6B8C146FULL,
		0x5B8A2F736A83D78AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF7A4B524E1D82ABULL,
		0xBA6ED1BB3ACAE48EULL,
		0x36387BE15B85B7F9ULL,
		0x46FA4F15B6217574ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5DC9761B6DB060A8ULL,
		0x8F263B691B9196C4ULL,
		0x7C594B4BC5389EFFULL,
		0x000A425C3FE24388ULL,
		0xF143646126DD2C6EULL,
		0x8E7A2774A6D29BF2ULL,
		0xF5436079C1AC3802ULL,
		0xA5835B13C0BCB0B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DCA5C873284FC9FULL,
		0xB54816B9DED4BCD4ULL,
		0xE4599D5E84C8EF60ULL,
		0x1189C74ADBE47E8AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7213F5B1653ECCC1ULL,
		0x115DC2DA7D80CDC6ULL,
		0x5C6B1257151778AEULL,
		0x519C579E77CB7B22ULL,
		0x5E9C8CFE56856F1EULL,
		0x2857B7750A9E9584ULL,
		0x7FC59EDD05B33837ULL,
		0x6BFB0EAB78A269D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D50E3723D0D4D95ULL,
		0x0E62FE3A110AFF6CULL,
		0x53C0A725EDB1D0DEULL,
		0x58E085125FE73015ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8AD05065537A665EULL,
		0x1A058132F12CD98CULL,
		0xD764C2834BE61946ULL,
		0xB9AC86E07BC31725ULL,
		0xF244F78E5B04E087ULL,
		0x347AC8FCAE0D93F5ULL,
		0x2777D21DD02FD7EBULL,
		0xCA10552A217E1677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810D0F86D633BEEFULL,
		0xE43F56B4C730D00EULL,
		0xB32DF2F03300262FULL,
		0x38192B21747A6CD5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x083FD78713F2545BULL,
		0x0F14ACE8D3C74D25ULL,
		0x65043BFE2093B6BEULL,
		0x20F00E7FF9706009ULL,
		0x2805CE25E54B6F24ULL,
		0x7D9F319D6E037483ULL,
		0x303FE0180AC7C3C7ULL,
		0x167E9D71AF54D9FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF91C71271D24D425ULL,
		0xB4B60A47284A989CULL,
		0x8E7F7F8FBA3AC65AULL,
		0x77BB6D600008BBEAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x21731D4DE21C0B89ULL,
		0xC4C55AD8559DED55ULL,
		0x5796AD0913983058ULL,
		0xACA7D8454C6533A2ULL,
		0x79F9B5D705DAA8BBULL,
		0x4A0F412C3108F15CULL,
		0xA9EC5494723EFC7FULL,
		0x34300B42D0B2EB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C841B38C091187BULL,
		0xC30907679CF1C10FULL,
		0x90AB3B1208F1AB3DULL,
		0x6BC9843046F41D01ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2674FF1F9E3E2481ULL,
		0x4089F1FC17626922ULL,
		0x138409C6AC384DCEULL,
		0xF90C34C5216F20FEULL,
		0x3A22821B22BF5802ULL,
		0xEE6B3C6B81904396ULL,
		0xABB33FDCE6BD89A0ULL,
		0x970AF543D6BE294EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7944F26C6A53837ULL,
		0xA474E9F152CC716EULL,
		0x901F8490EC5ABBB1ULL,
		0x64AC9CD701A942ABULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0D9F5005A34E6FFCULL,
		0x74AC697DF7039B82ULL,
		0xF778265046F73473ULL,
		0xD5B14B89EB78346EULL,
		0x890BF2B8F8E222DDULL,
		0xBF6529BC73184BC1ULL,
		0x0BF316BF361E328FULL,
		0xF072FA3F9D34BF55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6565577A94DFA235ULL,
		0xDDB09B770C9EDA3CULL,
		0xBD8D86B24F72B5C9ULL,
		0x06C270FB414C9B0EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6AD43E7BD7296458ULL,
		0xC4E06909F212690EULL,
		0xC6B52E01C2BE6DCAULL,
		0x15A98E8A8D9AE001ULL,
		0x586273B305832964ULL,
		0x24BEA7604769F4ECULL,
		0x8CCA42590D55F374ULL,
		0xE44D811FBE491D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89716B0EA8A18E29ULL,
		0x392D41548BCCC423ULL,
		0xACBB0739BD809108ULL,
		0x792AB940CC753A1CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9620E43846B987ECULL,
		0xD63D639B8E7414D6ULL,
		0xEF80C56FC411F642ULL,
		0x6A7F24D454CCE26AULL,
		0x195DE003F87B294FULL,
		0x03832D9032F10CA3ULL,
		0x42257D25042C26E6ULL,
		0x78A0888D2AD31440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1024CF2901AC52ULL,
		0x5BB627031E3BF50CULL,
		0xC11158EE629FBC67ULL,
		0x525369C8B021E3F4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEE511F0B0C48A0E4ULL,
		0x50EC032CEECD528AULL,
		0x3E9491AE40649D73ULL,
		0x84B6AF638AA144E4ULL,
		0x39FFAEA3D2A42CF2ULL,
		0xAABC9C3FD1D26EBAULL,
		0x3D2C80BFEEE7958EULL,
		0x7E1FCB0D195F1E5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A450B5C50A74FA2ULL,
		0xA8EB34A61409C22FULL,
		0x532FAE2BB6C4D0A0ULL,
		0x3D6ED3554EBFC707ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3914F985A46BBBF4ULL,
		0xC011197B2F66B0EDULL,
		0xA9745C09E0AACA27ULL,
		0x91F6BDBA708BCC7AULL,
		0x3F98215C8D10E887ULL,
		0xBE62361637691F9AULL,
		0x2E29ABF192F36828ULL,
		0x7D19A904BF318B12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9A9ED4294EE42D0ULL,
		0x02A520C7690161D2ULL,
		0x83A3E1E5B0CC4034ULL,
		0x23C5D46ED1E6712DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA1C677DEAD186479ULL,
		0x6FBA52E534255F6BULL,
		0x168D306A9C058077ULL,
		0x93756ACF2287D427ULL,
		0xF945D1CC5D5F3F14ULL,
		0xD138151BA3EE7F58ULL,
		0xB3E7A1A2CEBD31DBULL,
		0x7FFFCDCEA30B657FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2239C34893BC456ULL,
		0x7E0D74FF898C46A0ULL,
		0xCAEF2E954C1AE718ULL,
		0x136DF77B5638E51BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0A3B0E99271FC985ULL,
		0x3A7A55A45CA09BFEULL,
		0x50C5B090C75DAF8BULL,
		0x45FC19E1516B29B4ULL,
		0xE566E830ACE9976FULL,
		0x4079980EC00D1AEEULL,
		0x8F8E5468EC0D0DE5ULL,
		0xADF7A5C3937A0704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x178185D2D1CC47DBULL,
		0xCC86E7D4DE929B74ULL,
		0x9FE63823D14DBF92ULL,
		0x18BEB4E935883461ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA4BFCF214ACC9BDEULL,
		0x5251E5F08E903744ULL,
		0xAF05F1C2237A4F9FULL,
		0x2161945F3A45548EULL,
		0x3A4D0755CDF63E06ULL,
		0x32A8286EDCBF2BE1ULL,
		0x434DDAA9E7765BF9ULL,
		0x095822A7985531D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C2EE5DDDD59D0FBULL,
		0xD747E66552F0BAB3ULL,
		0xAC9466FA7F0BF69CULL,
		0x0476B93FD6EAB9C4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE358D6E1D70E3C47ULL,
		0xBE971235C30B9F9DULL,
		0x59DBB93E15578E03ULL,
		0xDA6E3B94A3686600ULL,
		0xE81FA128B2F9D28AULL,
		0x6905061571010206ULL,
		0x51BFA11AC607D1A0ULL,
		0x46C2A36D9B284E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x580AC2EC68237E65ULL,
		0x5555F9648931ECA4ULL,
		0x7C4DA3377A80ABD3ULL,
		0x5B527DD9AB63FF3EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD11C7318CB095275ULL,
		0x1D21644BB775C831ULL,
		0xB8A7D556D657E7F8ULL,
		0x1CE4F688B6AE4423ULL,
		0x0015F85543293D4AULL,
		0x27EAE7B9E61818F0ULL,
		0x9B4527E8ED67FE78ULL,
		0x2893180ED4F9C92BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45F4FC0C3286C55ULL,
		0x09FFC9E3DF097BD1ULL,
		0xC4EBC1EA13C7ADCEULL,
		0x22BA88BC53C2209CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1FACAB528E90023EULL,
		0x84A6050E467D1D71ULL,
		0xCF6676C6D0FE2786ULL,
		0x51C66DB6AFD70F58ULL,
		0xAB1A03736089F0A0ULL,
		0x4F420F633924B575ULL,
		0x83A6AC01D88C320CULL,
		0xCC7AE326A78DD99DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85892E72E309BE85ULL,
		0x48744DC8C1F00CE8ULL,
		0x5A23FF0CF5CD955AULL,
		0x2C0425738EE55CBAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD826299C8A870B3DULL,
		0x061B25E66AB1715DULL,
		0x6080509BF912AF82ULL,
		0xE966FA757FBDDEEFULL,
		0x70A3B82EF5262727ULL,
		0x651E47333DCEDD1BULL,
		0x23FDF89F81498B71ULL,
		0xEF41FC1E5536C9B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90738094EE30E05FULL,
		0x0899B78197664370ULL,
		0xB833384929FD6257ULL,
		0x6D3266F625DFCF60ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0A2ABAF34B5F533EULL,
		0xED613BC89E631725ULL,
		0x17A5A247F8FC11BBULL,
		0x7BA6817C8D4B8C6DULL,
		0xB8E3A8065531C215ULL,
		0x7794F1B62F95423BULL,
		0x8808F3A4475506D9ULL,
		0x2BC1C79ADB27D3ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BF5ABE3F0C22353ULL,
		0xAD7D1CD3AE8AEC02ULL,
		0x48F9CCAA8F9B1603ULL,
		0x7A6A22791534F809ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x80088954EA99831BULL,
		0x7AD37083DCD0DB6EULL,
		0x2BFB56430599577FULL,
		0x725ED9AAEFB2C312ULL,
		0x38AF069A98B9CB2DULL,
		0x88C220B66B5B38F1ULL,
		0xAAA366B53788DEF3ULL,
		0x7AC13F1F9D1CF247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA038447962DAE88ULL,
		0xC7A44B97CC5B4F3CULL,
		0x803C952943EA6FA5ULL,
		0x2B0E385C41FEB9B5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3E59BBF33E51D7F1ULL,
		0x636D86A2774A6C6FULL,
		0x944771E91B5A3829ULL,
		0xA543B16DD5BF8E2CULL,
		0x9227331F744E0317ULL,
		0x0BCE8066C7DEB6E9ULL,
		0x37A05F35DDF901C9ULL,
		0x65465F897B54058AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF02B529E81E64FA8ULL,
		0x241495E42259931AULL,
		0xD61593E80E507C01ULL,
		0x2DB5DFD6243860B0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCB31964AF66AA132ULL,
		0x438DBD88126DCE0EULL,
		0xED397D7FB08FEA4EULL,
		0x8202CFC5964D6FC4ULL,
		0x14D6E075EB91B268ULL,
		0x3155A340F5C8F8FDULL,
		0x349B7FF414FE86E2ULL,
		0x587DC23B16EBD447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE316E7CBEE0B1EA3ULL,
		0x9643F92C8E42C39FULL,
		0xBC4E7BBACE57EFE1ULL,
		0x24ADA48AFD4EF256ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3569AC391D9531E2ULL,
		0x9F6174B73DF6F0B0ULL,
		0x60A867D71851522FULL,
		0x4F119C5AE1072482ULL,
		0xC59A4E7EE9C8CDCEULL,
		0xE99EE3195D1F8CB1ULL,
		0x81A44CCD019EAF1FULL,
		0xFCFEF76A505F533BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A51530FD163C407ULL,
		0x4CF72A7B10A5D313ULL,
		0x9F0BCE4555DF50ECULL,
		0x5CEA5622CF2D7F57ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x46B20D3FE3BBA7B6ULL,
		0x728B957B71EEAA4BULL,
		0xD24FFD8B257340D4ULL,
		0xC2277D9940C80E09ULL,
		0xE2CDC42EAA7609A2ULL,
		0xF7D96A59D21663EDULL,
		0x6D30CCDF24E6E09AULL,
		0xC6D380B8602417ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13D2C2D31411A36ULL,
		0x3CD15ED0A1417F9AULL,
		0x078E66AA9FB897D5ULL,
		0x458C98F786239B22ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDD3ED55CE8842EF5ULL,
		0xE9952D6A4167E400ULL,
		0xDF9457A3ABAA1737ULL,
		0x52E668D683B024DFULL,
		0xE530E631102D0F65ULL,
		0xD243A0CA392B11B4ULL,
		0x459C4222E68A3FA8ULL,
		0x327CF2CD452DD2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE28100A54F347910ULL,
		0x1F9F0B6EBDCC84DAULL,
		0x34C628D1E42F8A47ULL,
		0x5172734EC87D6BA2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x65A89EEBF231E45DULL,
		0x00E75B490B5A52FCULL,
		0xB9E311A7E5CA67BFULL,
		0x09422EE2F2F01427ULL,
		0x2E3B37A923BDD385ULL,
		0x3A8DF18978653E82ULL,
		0xD3E3D6154563E705ULL,
		0x141CBC7FD80582E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4272E207405F4A8DULL,
		0xB1F935B0EA619A4FULL,
		0x2DB4D8D0329EB285ULL,
		0x058629DD03C182DDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEF5B2D5F597FA8C0ULL,
		0x864CC6DFA676B13DULL,
		0xE9034A6F8168F8A9ULL,
		0x4674BEE437D853FBULL,
		0x44B6FB6FC7B55F4FULL,
		0x987E358E14FE5A6AULL,
		0xE10DB48858B89AAFULL,
		0x7067E1501998E65FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22847FF6FE6BD0EDULL,
		0x2908B9F6C4381D04ULL,
		0x510C16ACACCFEEBAULL,
		0x75E030C8048A8637ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2F8C5B87730D3410ULL,
		0xD7CE3960233BA82FULL,
		0x781655A043464574ULL,
		0xCD5612AE01F6572CULL,
		0xDD30F4E54F69719CULL,
		0x73FE7EFBD8D6A011ULL,
		0x520EE8FD94EE9600ULL,
		0xF074F1BC8000D5AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04D0B5913CB41690ULL,
		0x0F9512C253176AD6ULL,
		0xA64CEB445EB08986ULL,
		0x7EB1F4A902160F32ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x50EE96D5CAA0A8FCULL,
		0x2D05B5E37AF65EC5ULL,
		0xC332C4875A38D037ULL,
		0xE83A65390278F99DULL,
		0x96E785B94C592A5CULL,
		0xD593FFED0892741DULL,
		0x975CB338276CEEA2ULL,
		0x9148DFC33E6296D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB74C70571FDCF5E8ULL,
		0xE0FDB312C0B39B29ULL,
		0x3AF55EDD34643C62ULL,
		0x790B9C34451B5DEAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE7DC8312F915C9A8ULL,
		0x35712E34575505CFULL,
		0x3BAC4F62B555AA0BULL,
		0x9D40DC049D624CDDULL,
		0xC85A52884B5D8A39ULL,
		0x5F824F03A7DAB4FAULL,
		0x0B089444E9F91F56ULL,
		0xD87D8C808B1EFE6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA544C34E28F852F1ULL,
		0x62C8E8BF41CBE309ULL,
		0xDEF2519D705050DDULL,
		0x3FE3B71943FC10E6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA6A2867D04E74284ULL,
		0xF5C88C344612A391ULL,
		0xC7CC2FA3BC18846EULL,
		0x10A9B8D516152E59ULL,
		0x9F9A4FBD5E62C311ULL,
		0x23F68A944F012B94ULL,
		0xF775C1FA19F7CE10ULL,
		0xAB06E815A64921C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x578A5C9907903AC0ULL,
		0x4C611E38003F1BA1ULL,
		0x8346FAC396E11AD4ULL,
		0x73B02C0BC4F031BCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9729B300FFE24CF7ULL,
		0x07BADCFF078A065CULL,
		0x39BE4F632C927C4BULL,
		0xECA55437258D157CULL,
		0x37C15326E719202BULL,
		0x8675AC93112CE937ULL,
		0x84E74D054AEB1873ULL,
		0xD691589F0F2284BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDDC0AC74D9D182CULL,
		0xFD327AD39434A48EULL,
		0xF413BE2C4B781D70ULL,
		0x46387BD364ACC99DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x72A032C2D14DA899ULL,
		0x53396A9EE4D1D681ULL,
		0x372373AA748E5ACFULL,
		0x22BADAE1F3074467ULL,
		0x1C1B657D41B9F3FDULL,
		0xF25666A8F6E785A1ULL,
		0x6E5EE22129D18015ULL,
		0xEF8EC7AB133891D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB1435A92E7E56CULL,
		0x4C0CA7B38B2FAC6BULL,
		0x99390496A9A75E11ULL,
		0x31EC7E46CD6CE97DULL,
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
	curve25519_key_compute_modulo(&k1);
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