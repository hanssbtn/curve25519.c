#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x7089F83A70DC561DULL,
		0x0C6AA0105817F516ULL,
		0x47CEEC8154F95918ULL,
		0x1D848AEC15E73548ULL,
		0xE9E1E5E60F4025EBULL,
		0x96C42FD29120E9DFULL,
		0x20C3687A4ADFDF67ULL,
		0x83061CE35A523A5FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE5839F27C348843FULL,
		0x1B240AE5C1300561ULL,
		0x9B3E2773C502FE0FULL,
		0xFB0EA712A0835861ULL,
		0x29883B150D4380E9ULL,
		0x5945760CCBB949D0ULL,
		0x3CFC024549B7D8EBULL,
		0x619AC36DC21950C3ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
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
		0x28E699AB4978D6DFULL,
		0x8204F70A1495E052ULL,
		0xC24EF6A87F2E23A2ULL,
		0x6FE1E196CD7E197FULL,
		0x6BD29A340E237B7EULL,
		0x25E58A1C80A758EFULL,
		0x1D78C99CDB63D4EAULL,
		0xCAB8AC2D125968E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A7A2C3A67A888F3ULL,
		0xD3DB401B0CF86D9CULL,
		0x0EB866E2AB56C202ULL,
		0x5982A3065EBF92E8ULL,
		0x075E2899918FB9AAULL,
		0xC97D02468AB8625CULL,
		0xB562745C2F18CB76ULL,
		0xED01612CF8BCC024ULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEE1874FD2E2E8C04ULL,
		0x20333607411351C6ULL,
		0x6E7F125FCAD7F077ULL,
		0xAAB3B2571C1D628DULL,
		0x4695AE77CE7531D6ULL,
		0x103C2F6148C093BBULL,
		0x71A2A63CC9B5BADBULL,
		0xB35AEB83B260F66DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F91A4BCEB65997AULL,
		0x5184AEA185A421EAULL,
		0xE29EA15AD60B1213ULL,
		0x27FBB3E8D74FC066ULL,
		0x27D79DA31FF8FBBBULL,
		0xC9DDA78E2D2FE424ULL,
		0xE75C74C7110D8E73ULL,
		0xC25379AF81940390ULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD25E2E0E060F836EULL,
		0xA572C2B896FCB9E8ULL,
		0x28E4078EA66906BFULL,
		0x41B72B81C2888125ULL,
		0x6D9BFA13FD35E20AULL,
		0x0F645DCA526E868EULL,
		0x2EA93270C4A66808ULL,
		0x87F9484FA79ECE6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD22132CB43FB4B9ULL,
		0x6CCF9518B1AE213CULL,
		0x2909ACC9D3236A31ULL,
		0xD41D2C21111AE178ULL,
		0x0992BF6491C33B00ULL,
		0x5A200E6B4D7ACC1EULL,
		0xE5F8F064171DA3BFULL,
		0x13A312E7C91C2E97ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x076F136CA82C66ADULL,
		0x5FB9101C147B7E12ULL,
		0x8C99D9BB4F5C8E29ULL,
		0xD1A98A49C44B73A4ULL,
		0x6B256BCA88CFED80ULL,
		0x02B8691D75FB8378ULL,
		0x5F1897ADF980EDB6ULL,
		0x086E044F2F3E867DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x076F136CA82C66ADULL,
		0x5FB9101C147B7E12ULL,
		0x8C99D9BB4F5C8E29ULL,
		0xD1A98A49C44B73A4ULL,
		0x6B256BCA88CFED80ULL,
		0x02B8691D75FB8378ULL,
		0x5F1897ADF980EDB6ULL,
		0x086E044F2F3E867DULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8550B8A76718437FULL,
		0xFDC6EDB748DCDF68ULL,
		0x55CDEC50BDCE4C30ULL,
		0x9E7B4789FFBDA900ULL,
		0xD1228332064E7439ULL,
		0xF6CE605BB5D9C3F0ULL,
		0xA9A15DF4C5E551C7ULL,
		0xCB5AD597BB7A9C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647E16D9CBB64A2FULL,
		0x76BF51627A192630ULL,
		0x7E30BD787394AD1DULL,
		0x0152488F3F31725FULL,
		0xB2FD57519B7DBE82ULL,
		0xCC6989C612E0589FULL,
		0x6A3A249FEBB64EEAULL,
		0xE0B45D6E03598568ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB25E8D56DA09113BULL,
		0x1DD81CDD14B419E8ULL,
		0x6DAF9FEC88CCDA98ULL,
		0xA579AA2CD5AD4B84ULL,
		0x62B1B83821BC0360ULL,
		0x17C650436AAE9DA1ULL,
		0x3BF3D9E1C010D6B1ULL,
		0xF75D923DCB60C22CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD349C59A72245DDDULL,
		0x6482E09FF01FCE2BULL,
		0x5AD1F50A2E2022D5ULL,
		0x0C619FEA62B448CCULL,
		0x69016BD740E36EA6ULL,
		0xB7B1F043474C7B09ULL,
		0x9F9F9665558005F3ULL,
		0xFBC9F3584F24E34FULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x63216F3C345FC851ULL,
		0xD92F580F6994D7D9ULL,
		0xBFF4925FDF442A66ULL,
		0x8F7B9C42D304EF07ULL,
		0x50DAF6557E8FD4A9ULL,
		0xF5B96611F6CF6D30ULL,
		0x0BC9F5AE45C40398ULL,
		0xE40C65E9F5C5B26CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2D9E476A037295ULL,
		0x5495E89052BA079DULL,
		0xC6879B444EEA4125ULL,
		0x88CAED7BFBA6B393ULL,
		0x7A120DCA754699C8ULL,
		0x5582B92D0E5E6193ULL,
		0xF67AD5E4408B0EB3ULL,
		0xBBF3458411FAAD82ULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB67F793C497F72ABULL,
		0x5DA917CE437AE1A4ULL,
		0x36793AE8692C8200ULL,
		0x9C3F8F04A1770764ULL,
		0xEEF68D4C89797110ULL,
		0x083D4FB1C19407CEULL,
		0x60F9EB8037958E37ULL,
		0x7D6E558CF6F13812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67F793C497F72ABULL,
		0x5DA917CE437AE1A4ULL,
		0x36793AE8692C8200ULL,
		0x9C3F8F04A1770764ULL,
		0xEEF68D4C89797110ULL,
		0x083D4FB1C19407CEULL,
		0x60F9EB8037958E37ULL,
		0x7D6E558CF6F13812ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4956B258F484BCDULL,
		0xCEC4C0B1BCEAB781ULL,
		0x9B0C142E3524ABADULL,
		0x9EC832F9D7689464ULL,
		0x58FF3BBB5DDFC901ULL,
		0x79E0C3B9CE5848DFULL,
		0xC3F0B3BEFDEEE490ULL,
		0x0B994D446632F689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ECFB7D82AD225A5ULL,
		0x998260BB2CB9410DULL,
		0x41BC963AD6F36690ULL,
		0xCB1BF4D54A7CEC4CULL,
		0x77ADF4F96B8D95D4ULL,
		0x0ACF4CBCB3067065ULL,
		0x37329F16E706EC15ULL,
		0xC7B0D48BADC7D5F6ULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBBC4F0A493820537ULL,
		0xCA84089619CC6369ULL,
		0x2BE43A8CDA76B9F7ULL,
		0x6122125100BA390BULL,
		0xA21314D811221AACULL,
		0x657B584B3FEA74C8ULL,
		0xB5EDFD4F1E9AB39DULL,
		0x7B5F451E376C977BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4F5C137AB309218ULL,
		0x84DAE3C8272EA5FAULL,
		0x7555C4F34C4DEE0DULL,
		0x4C1FB89BF84CE78BULL,
		0x51E10A6F0548B617ULL,
		0x37343C1097FFD4C2ULL,
		0xFB8BB66E8AE3A0D6ULL,
		0xCE188458584367DEULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF158CA613EF8A161ULL,
		0xB9DD39FC9B46FCA6ULL,
		0x8D8DAAE66D970AFAULL,
		0x23D6443830AF9024ULL,
		0xED6810583FAEFA2AULL,
		0xAB4AE8198AA5F61AULL,
		0x8F57833E7F686CB2ULL,
		0x7C1708018C111D8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D1A98229E331719ULL,
		0xB57399A4633DD5D9ULL,
		0x057DE4619F51A863ULL,
		0x69C86EDC016B671CULL,
		0x0EE87876E9F135DAULL,
		0x189D9956BAA1D445ULL,
		0x1FADF3783A55FB3EULL,
		0xC3475806C291CDB7ULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x777CC3D762776E5BULL,
		0x94A8E34816D544EBULL,
		0x9BB82A5DD20692F4ULL,
		0xF2488E2BACDA80EEULL,
		0x078B7CEA9CF2FEB2ULL,
		0x787904905FC3E4DBULL,
		0x933B0262D54F915CULL,
		0xD00825164E7500A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777CC3D762776E5BULL,
		0x94A8E34816D544EBULL,
		0x9BB82A5DD20692F4ULL,
		0xF2488E2BACDA80EEULL,
		0x078B7CEA9CF2FEB2ULL,
		0x787904905FC3E4DBULL,
		0x933B0262D54F915CULL,
		0xD00825164E7500A4ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x79FFE42CA32A2BD2ULL,
		0x49F979B779063AEFULL,
		0x577EE3586E3FAB77ULL,
		0xE0798BC695E15CC7ULL,
		0xED4D7EE4CF48AFA4ULL,
		0xC62DCF66A0B2CE4AULL,
		0x687AFD5F98E8B57CULL,
		0x9EE5FF545B03811FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238703BF948C0B17ULL,
		0xB5A8E2EE74BEE72AULL,
		0x1EE9F781735C33EAULL,
		0x049F38188AEB0FC5ULL,
		0xC480D5321363DDF6ULL,
		0x79AB9F1FF28CB1BDULL,
		0x548D9B94442E8054ULL,
		0xEED0C941F2B5BDB8ULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1FEF98C953B203FFULL,
		0x0EEB611883231D86ULL,
		0x965F105D4FD0A65DULL,
		0x7461AB3BA15DDE25ULL,
		0x44D238C4935A2962ULL,
		0x96F3660A2588401FULL,
		0xF4FC58376C7F5062ULL,
		0x2D1A1153996D2553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x903D245B4C2D4668ULL,
		0xD04C3B6B6E99BC61ULL,
		0x5947E1D844D636B0ULL,
		0x30B748F5F2E0C010ULL,
		0x66BAEFF92E116DDBULL,
		0xA8FC278820BB1090ULL,
		0x978CBFDB75031DCEULL,
		0x00016C1D3AFAFEAEULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE68DA55ECDBC76E1ULL,
		0x709928F791E25BD1ULL,
		0x4FA407BD5889C6DBULL,
		0x8BC8D4E0499251E3ULL,
		0x7614FDC6CD28C3BFULL,
		0x74A1F75ED3B3D1A1ULL,
		0xDB379033664B3A09ULL,
		0x27BB46A1CF5868E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77DB15D529653053ULL,
		0x765813B31D96CDD8ULL,
		0x6F5172D38CF4E137ULL,
		0x98AC5536DC8F72B3ULL,
		0x688A1AE5AEEBEC62ULL,
		0x9658864F4B40AD74ULL,
		0x501803E0682E60B1ULL,
		0xFC63877A2CC3C14BULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE8E7981DEDA431DBULL,
		0x81DD29F44A1F5AA2ULL,
		0xFE48020318C0D305ULL,
		0xA084A63749A97CE9ULL,
		0xF25398F49AA43184ULL,
		0x4F2BA5035243003CULL,
		0xF771AAD512DCA00EULL,
		0x0A546295483B30CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E7981DEDA431DBULL,
		0x81DD29F44A1F5AA2ULL,
		0xFE48020318C0D305ULL,
		0xA084A63749A97CE9ULL,
		0xF25398F49AA43184ULL,
		0x4F2BA5035243003CULL,
		0xF771AAD512DCA00EULL,
		0x0A546295483B30CBULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB555E1928AD68D86ULL,
		0x0F8C1F82F1CF7759ULL,
		0xDCBC2A21154205B7ULL,
		0x8967CB04FB39D60AULL,
		0x58FD0E081A916FB4ULL,
		0xB4D1C95D41ABF28DULL,
		0x3C03A799CB3B5C86ULL,
		0xC2D107A6F4DDF4E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F61CE4FE55A8B83ULL,
		0xE9A3E92D41D0A8BBULL,
		0x6F9381F24E72A109ULL,
		0xA350EEC7C5CE811FULL,
		0x803E49C36E1D45DAULL,
		0xCF5E59345614FE3FULL,
		0x983983C63F1FFADFULL,
		0x1296A8269B892634ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x160559A5DFACAA41ULL,
		0x101BB8AD6933D901ULL,
		0xE3C6AA340D5BA0B0ULL,
		0xA70EBC04D1F6233EULL,
		0x527F47B5C3A54AECULL,
		0xC889B96F618F1FC9ULL,
		0x33D1B2F578E1FEB4ULL,
		0x98870E5EB2011EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE109C761AEE99AULL,
		0x7EEFF80008528296ULL,
		0xF133CBEED45F04F1ULL,
		0xB940D2CB12204AF6ULL,
		0xA69DD64166801D2DULL,
		0x49BACDEC8C3A9617ULL,
		0xDCE40CC17DFC68D3ULL,
		0xAA63D5F4CD8603E5ULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x761FF56A1E4DA8D3ULL,
		0xAA46B137912CE172ULL,
		0xEF60523AB5DFFCBBULL,
		0xA4F0CBF04B7B6599ULL,
		0x1012804D6724D8A7ULL,
		0x1CD1D86B188C3600ULL,
		0x503BC517A485F0A5ULL,
		0xDEBBDA4CB206501BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C17E953A6DDB931ULL,
		0x0D58DA031C1F08AFULL,
		0xC7B2C4EAF065C028ULL,
		0xC8FAAB9611F610D0ULL,
		0x398A53F825905AD1ULL,
		0xBF8CB1CCDDE76D78ULL,
		0xF608C80C28A502CDULL,
		0xCD75012D4BA7CBBFULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDAB3FB4199D5EC7DULL,
		0x2C810360BDB7DC85ULL,
		0x8A83C5B5804C6490ULL,
		0xB7AA832CC6231ABBULL,
		0xC8539288679899BDULL,
		0x88B1D3D2E95CBB9AULL,
		0xB8B6090BEBE15C42ULL,
		0x2E51634EF72A2677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAB3FB4199D5EC7DULL,
		0x2C810360BDB7DC85ULL,
		0x8A83C5B5804C6490ULL,
		0xB7AA832CC6231ABBULL,
		0xC8539288679899BDULL,
		0x88B1D3D2E95CBB9AULL,
		0xB8B6090BEBE15C42ULL,
		0x2E51634EF72A2677ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD7347E400D09B7A7ULL,
		0x90CE528B2E138F0EULL,
		0x791A4522AFA2D77CULL,
		0x840ADF46C6C35021ULL,
		0x94F21AFE22337861ULL,
		0xBC45BBB44AC318DFULL,
		0x80BC369739F84A0CULL,
		0x09A94B1086FF0376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA39B3EE6B9BE101AULL,
		0x748E99A137D9A826ULL,
		0x7060BCD333272D34ULL,
		0xFBBCA88F254403DDULL,
		0x09572BB14E5B4F76ULL,
		0xDE9CB8236375C57BULL,
		0x22946021A1534360ULL,
		0x1566498FD9F42D20ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6D40EBC118F5CAE0ULL,
		0x1E1595833AD90FCBULL,
		0x794F032990DA7C3CULL,
		0x6CC151E2F88BD278ULL,
		0xAEE6E649FB3D2079ULL,
		0x3D1FE3E3FDB58A8AULL,
		0x6654B06221A48AA2ULL,
		0xFDC5C4DCCBD1C596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CECCA5F5B6929FULL,
		0x7DD50EE4F816A8F1ULL,
		0x4093C39A43C653C9ULL,
		0x8C057E682730E31FULL,
		0x6205315BD1A605DDULL,
		0x383A8D0625C7A4ECULL,
		0x321681A789A8CAC0ULL,
		0x42EECB5A2A9A51E7ULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9CC39E20BD95E8F8ULL,
		0x790C4EE365699BA4ULL,
		0x52DB7B5A76254653ULL,
		0xE53D7D477B491EBCULL,
		0x2C227B020DA0F8E1ULL,
		0x143B078B468160CFULL,
		0x3EFDA8FAD49BDFD8ULL,
		0x3BF16B8FA1542A9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96743184777C234CULL,
		0x3B34FCEF0231D10CULL,
		0x7B9F8666332588D5ULL,
		0x670FD63B783D73ADULL,
		0x5EC60BA831BA17F8ULL,
		0xD6292F5DF2854846ULL,
		0x3D60A36E29C09777ULL,
		0x46A1BAC265CAC3FAULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x034B0F2411EDBCDBULL,
		0x1C7DF4ABA7F3460DULL,
		0xA4474369A57AA1D1ULL,
		0xF7B5DD2D6A5B5C18ULL,
		0x7EF6AC5B24E69412ULL,
		0x9082E7A29D0A62ECULL,
		0x1C5D8140075C639CULL,
		0x1C26FEF0485B7B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034B0F2411EDBCDBULL,
		0x1C7DF4ABA7F3460DULL,
		0xA4474369A57AA1D1ULL,
		0xF7B5DD2D6A5B5C18ULL,
		0x7EF6AC5B24E69412ULL,
		0x9082E7A29D0A62ECULL,
		0x1C5D8140075C639CULL,
		0x1C26FEF0485B7B15ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBFF29EF1BE62297AULL,
		0xEEED57A498E5E8D5ULL,
		0xE142D45D879FC4F0ULL,
		0xA545A6908A44AE97ULL,
		0xA75AEC0F73449F2AULL,
		0x1320B047F9BA968EULL,
		0x837E882AECFC535DULL,
		0x6AC925A2F70C21A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E7EE3DB3E94712ULL,
		0x7E9A9AC2F401506AULL,
		0x9F60D4A45FFFE203ULL,
		0x63DA4D57A8A885E1ULL,
		0x85976C1E20E9DF9BULL,
		0x4E9D69300547BB93ULL,
		0xFF87CF829AC15798ULL,
		0x7BF31CFAADD18ECAULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEB30FA5EAAEF6CAEULL,
		0x2F4AC57C0C621822ULL,
		0x87E921FA663A6D3CULL,
		0xF7DEA3BD99BF9A79ULL,
		0x432CB3283795990CULL,
		0x5988DB85A5ECB9E9ULL,
		0xCAC08E19DC9ADE67ULL,
		0xEBCC851DAFE8AFB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3CB5FB63D19CDECULL,
		0x2B10D959DE20A901ULL,
		0x1FDE143C85282804ULL,
		0x464F9DEE9EED9169ULL,
		0x81FE491A2F3FB738ULL,
		0xB1CDBBBB4E615A4FULL,
		0x6EAD362D21C42E0CULL,
		0x862BB82442E89860ULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB8B947686E8D116BULL,
		0x9583CDA077B7494EULL,
		0xCEA43796F2349050ULL,
		0xFAF2EF3DAD10FC96ULL,
		0xC24E73F0D3901544ULL,
		0xD4042DF5DDFFB834ULL,
		0x9A2BEC8B4F362799ULL,
		0x88CE8E62D2378584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0DD9E7CD71C5E7EULL,
		0xB75E34436499D8FEULL,
		0x8041CE123CE28E7BULL,
		0x2D0EF064642A6D1EULL,
		0xF5DD0572C46CCADAULL,
		0x77BACB76E8E8EE20ULL,
		0x64A4D0C85A994B2EULL,
		0xDCFBDCFE3ACACC6BULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5844744583E69741ULL,
		0x4EAA92E47B64BB6AULL,
		0x37389541FC3C2939ULL,
		0x913FF70902BAFE49ULL,
		0x18FD941E0833804CULL,
		0x8B764B087856B6D5ULL,
		0x29C7C1156A50F718ULL,
		0xB53BE0FBFE327F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5844744583E69741ULL,
		0x4EAA92E47B64BB6AULL,
		0x37389541FC3C2939ULL,
		0x913FF70902BAFE49ULL,
		0x18FD941E0833804CULL,
		0x8B764B087856B6D5ULL,
		0x29C7C1156A50F718ULL,
		0xB53BE0FBFE327F59ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9AEAB036B69E7C9FULL,
		0x2C82F22212537FEFULL,
		0x4DB979BAFA3C6D3DULL,
		0x0763F38955EB95FCULL,
		0xE5ABD26244706926ULL,
		0x1FACD3FED4F22C60ULL,
		0x75855605563470D9ULL,
		0xDE80F04052312612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F4715B0D062595ULL,
		0x276FB91C96D8EEC0ULL,
		0xD7D0D6D2A229F866ULL,
		0x92EC51F1CBDA022BULL,
		0x11139F8EEF82B639ULL,
		0xA988B8429A35BE2EULL,
		0x46F40C390759185FULL,
		0x8927A3897C2761A5ULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB7B30CF5A51E52E0ULL,
		0xF0CC40A15F4690CFULL,
		0xD4DE6A4CA8B5C327ULL,
		0x40B061146294F8CBULL,
		0x9813B3B491E33416ULL,
		0x2DAFFD1C8A822B06ULL,
		0x5949AE5A8374B591ULL,
		0x0FA0ABB93EFDF61CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD88FB1590A3CF311ULL,
		0x3152FFC87DE06447ULL,
		0xDF9D09A09C2663DBULL,
		0xC9629CE4736CD9DFULL,
		0x7E3394B77269D11AULL,
		0x5781BA8B97ED4EEFULL,
		0x50712B35E13239A9ULL,
		0xFE743F900BA3D2BDULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5EBCBB65AF4C9D57ULL,
		0x255B45965F8C5AF5ULL,
		0xFD98423CBCC19B25ULL,
		0x2E85D13BD5356F9FULL,
		0x0BF6D8320CC75D6FULL,
		0x771C6A9D878B39E4ULL,
		0xC5FCEF3B14ADDDE5ULL,
		0x9FA345A487D7206CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD355D6E58EF5E74ULL,
		0xA69678C132F238FFULL,
		0x3048392A6FDC96F4ULL,
		0x287BC4338C8C58F8ULL,
		0xA60C90B3D5602A74ULL,
		0x5657800CC6555D41ULL,
		0xBD56AA508BDBD79CULL,
		0x658EF1CB5BB09CD5ULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAFE9D90183F894ABULL,
		0x6AF540607C0FC5B7ULL,
		0x008E9C56941672CBULL,
		0xA53C8F0829B222E4ULL,
		0x2E08CEFA642CD025ULL,
		0x6E6301537940788EULL,
		0x550B31AFD70A7B59ULL,
		0x201FB67C5CFC989EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE9D90183F894ABULL,
		0x6AF540607C0FC5B7ULL,
		0x008E9C56941672CBULL,
		0xA53C8F0829B222E4ULL,
		0x2E08CEFA642CD025ULL,
		0x6E6301537940788EULL,
		0x550B31AFD70A7B59ULL,
		0x201FB67C5CFC989EULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCF25CA35BB14DBC0ULL,
		0xD6C1DC32062C054FULL,
		0xC557145969280E05ULL,
		0xCF70E27944D22EC5ULL,
		0xBB0144903BDD787EULL,
		0xC1E04CB75B29E033ULL,
		0x4114F054C5B28D5DULL,
		0xEB006981C66A4D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362D93A675D922C6ULL,
		0x896E272CF0511A2BULL,
		0xB16D8022081C9F26ULL,
		0x55A5A2B4CD58131AULL,
		0x7626F2A56296B6DFULL,
		0xCC188246BDDB6F50ULL,
		0x8A487F88EB07F469ULL,
		0x020D21C6A4D796B7ULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC7ED3B02EFB68341ULL,
		0x1FD08AF75503D752ULL,
		0xA852FDAA541D128CULL,
		0xCCEECC407DE3B49DULL,
		0xA9BA5C6351838BFDULL,
		0x467744B38CE3B9A2ULL,
		0x74A93B20B631FABAULL,
		0xB1168E1FCA03B93AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA274EE00CAFDFEC9ULL,
		0xF64CA21666A63BD0ULL,
		0x60A1B9F35A02BBE1ULL,
		0xDE6BD3E34259A3C2ULL,
		0xC6C5130A90BC5F85ULL,
		0x2032F3897CB6D9F8ULL,
		0xEA538E1436040E32ULL,
		0x5561D5551AAC0654ULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8B095D4CB40C9D7AULL,
		0x767BF9AC8C5333CFULL,
		0xDF5F3097ED88D1A1ULL,
		0x2C2BC41978215F8FULL,
		0x670F7825D3058F7DULL,
		0xCE83EB68EC673A06ULL,
		0x83631977F28BA91CULL,
		0x5EB8B21993E9F086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x002C10BCCCDEF6A9ULL,
		0x0A5792F58EC0265EULL,
		0x4F947903FBF581C0ULL,
		0x8C7D4AFC5D461EDDULL,
		0xC93CBE3703FDB480ULL,
		0x34EEB65A3C093367ULL,
		0xE2782EC5F86E571EULL,
		0x4CFCD76AE1544D02ULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8B0CFD487374A01AULL,
		0xB7D1C7DA9754D445ULL,
		0xE84F34072076C675ULL,
		0xEAE8CF97BAECCADBULL,
		0xABDEF2999566B2EDULL,
		0xE21AC7320BA4BDD7ULL,
		0x26CAD4B06F03854FULL,
		0x89EEA2910A339AECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0CFD487374A01AULL,
		0xB7D1C7DA9754D445ULL,
		0xE84F34072076C675ULL,
		0xEAE8CF97BAECCADBULL,
		0xABDEF2999566B2EDULL,
		0xE21AC7320BA4BDD7ULL,
		0x26CAD4B06F03854FULL,
		0x89EEA2910A339AECULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9A8C15A87A13A20BULL,
		0xF035CEE939C0C21BULL,
		0xD1972704FF0A0319ULL,
		0x04BC724BE7080299ULL,
		0xA4D0D007B76A3747ULL,
		0x70D8B2D437ED5172ULL,
		0x21A4616DDD88D57FULL,
		0xDFF884E746B16413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x895A9E5A78CFD460ULL,
		0x6C4042FDE3F89373ULL,
		0x2AC30AEEDC7A3D0FULL,
		0xE3F7E06D1B14EE7AULL,
		0x8DC4D8692EE501A2ULL,
		0x9710390207151B9FULL,
		0x712B02E0C67E90ADULL,
		0x747938431E1D0113ULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8B529240B85CB7C1ULL,
		0xA6927E5381484A0BULL,
		0x7054BEF5F072D6CEULL,
		0x1AA8B1B9A1A51E24ULL,
		0x0603B0D74C95E80CULL,
		0x4C101F8C2F92DE3FULL,
		0x4466E514B8254073ULL,
		0x2DA95404029ED14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83FAFAF2C1F7D646ULL,
		0x3E89DE0BD0C4A767ULL,
		0x738EE2C39770CAC7ULL,
		0x2637BDB965E7087BULL,
		0x350D9300CB6EA0CEULL,
		0x65218BA6B4EBAC31ULL,
		0x56B863B7C72AD17FULL,
		0x99E43AD098C83DDAULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x24056CEC533DA428ULL,
		0x2E5AE5D4729A38ADULL,
		0xFCC76B26CED341D2ULL,
		0xEB2A308D543B5942ULL,
		0xF6B489EEAEA25BACULL,
		0x6EEB61089D077C8FULL,
		0x8026BA24E09FEB7AULL,
		0x4166F39C4C3B3343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C0F8509AF8D8D1ULL,
		0xA1748C6AB91074D5ULL,
		0xE607ED68703293F4ULL,
		0x320CA01E2A148D0EULL,
		0x41240E1A04C22B71ULL,
		0x3BFFFDDDC7A3B6B5ULL,
		0xED569916413A6819ULL,
		0x9AD28D2BBFD386F8ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFE247491F1226D96ULL,
		0x2F8F6F19FBC37AEDULL,
		0x5313133ACBA40D3FULL,
		0xD8B40A3AA04F960FULL,
		0x8C756AEF26791FCFULL,
		0x4EA95620F4199C80ULL,
		0x029B14ED58D30B0DULL,
		0x774FF101480D8E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE247491F1226D96ULL,
		0x2F8F6F19FBC37AEDULL,
		0x5313133ACBA40D3FULL,
		0xD8B40A3AA04F960FULL,
		0x8C756AEF26791FCFULL,
		0x4EA95620F4199C80ULL,
		0x029B14ED58D30B0DULL,
		0x774FF101480D8E37ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9B2F3FA11B05D0DBULL,
		0x468064B2D105A28CULL,
		0x3C0D3C1E00029F15ULL,
		0x160D41316D2EC578ULL,
		0x4285E95E34D5E230ULL,
		0x68BD7D2811B3DDD5ULL,
		0xA3911FD9B4D34E7BULL,
		0xA5540D4D2CBC98A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC724D58A08AA769ULL,
		0x064AE161F9755484ULL,
		0xB48A38BFE71D2D67ULL,
		0xB7E3224221D5D350ULL,
		0x09CA321571CB7218ULL,
		0x982E0C040C6F3830ULL,
		0x87B99143D5A81EEAULL,
		0x7C0937C8E7C376E3ULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x03ADA32767F1B237ULL,
		0x4BE41A55F438E4C2ULL,
		0xE2029CBB761A331EULL,
		0x04714B4C8D7B1198ULL,
		0xC545E358192BE167ULL,
		0xDB9BD18F9396EA72ULL,
		0x84A07DD72279B220ULL,
		0x8A5C11A7D166D921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A00220334ACAC0CULL,
		0x5AA20A5B9F81574EULL,
		0x14BA4C3EA37D23D7ULL,
		0x6DA04C98AAD918D2ULL,
		0xB1D031C6C65563F6ULL,
		0x6B77665DD4C1DCD1ULL,
		0x64931425657B37C4ULL,
		0xC9BE40E30952774CULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBCDB07E8FD5E0740ULL,
		0x233509FC881697C1ULL,
		0x07C3D6159C64F3D7ULL,
		0xE5CA9D3D44D2DC2AULL,
		0x3C0BC2710700E776ULL,
		0xC5ABBECD2704A00EULL,
		0xED8E9A1B7AA466E2ULL,
		0x84A11649C2209B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC26B74D8B666446ULL,
		0x622BE1C47D6DD1DDULL,
		0x6ECFF3FBA61B49B5ULL,
		0x7AD88C14DE60A080ULL,
		0x3780EAC69B1E5F79ULL,
		0xA9E9A7CB1E452E25ULL,
		0xA68510D311FB4086ULL,
		0xD7788A4806AA9650ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEB574455C1EC60B9ULL,
		0xBC7AA74FDB5EC348ULL,
		0x76B9F1A08BCF1CF0ULL,
		0xB70BEFA796E0EBF5ULL,
		0xF253B85B7A65FD22ULL,
		0x18C9209835268E5EULL,
		0xB688008A4EFCA19DULL,
		0xD5378CC29D72E012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB574455C1EC60B9ULL,
		0xBC7AA74FDB5EC348ULL,
		0x76B9F1A08BCF1CF0ULL,
		0xB70BEFA796E0EBF5ULL,
		0xF253B85B7A65FD22ULL,
		0x18C9209835268E5EULL,
		0xB688008A4EFCA19DULL,
		0xD5378CC29D72E012ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x68D827DE13EBE752ULL,
		0xE32E26E36795270AULL,
		0xD9C18E455D485631ULL,
		0xE881A62BDF58D7F8ULL,
		0x9F4B29370F597B4BULL,
		0x1672DB688D06F990ULL,
		0x54277F8D92BF8040ULL,
		0xACD7C3055BB74FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB269BC6B492577C4ULL,
		0x8499048DD058F0E6ULL,
		0xA863B78CEC99B463ULL,
		0xD0BA0901D88CB82FULL,
		0x744560DAE750CEC5ULL,
		0x56898357D9376803ULL,
		0xFD67CCB3186FCE4CULL,
		0x6679E5B7090B6392ULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5B4D97769D5B6EA4ULL,
		0x457D21D6A9711A7BULL,
		0x7EB0D44EBD9DC6E6ULL,
		0x371C6953EC5DFB62ULL,
		0x087CBF782624C525ULL,
		0xAE5575EF1BDCB754ULL,
		0xCAB2CCC67F915CE4ULL,
		0x0CEB65039B2DF92EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF210BE5895BE8F28ULL,
		0xCE7A5B96CE25142CULL,
		0xFD43AFE10D5015A2ULL,
		0x1955243414025CFEULL,
		0xC18ED5C4EEE8B622ULL,
		0x26DC2CDCC231AD6BULL,
		0x7E9FF5775B9BCDF5ULL,
		0x3F15DB4795B9616DULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5A0CFE2AE54072F6ULL,
		0x4ADF6CC499553149ULL,
		0x2D4ACB4AD56A19C7ULL,
		0x1C7290C3BEB93930ULL,
		0x97581173108991B4ULL,
		0xE38526676BC9351CULL,
		0x68943BD3863D3368ULL,
		0x950D00FF3429B4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7584AE2A5F6C11D1ULL,
		0x2CBC6B4EAB73B1DFULL,
		0x00746D374A8BA975ULL,
		0xEF29D09F6CA76BAEULL,
		0x0E2643D8541AAABAULL,
		0x441F97D8DF0C12F2ULL,
		0x157E775E3233ACABULL,
		0xF7BC170A4D65FEE0ULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB9C4A9C9AF7576A6ULL,
		0x826F3FC0B678E0CEULL,
		0x9151AF4E0B81F4CEULL,
		0xCB7B16E345573CCEULL,
		0x732B9E41867A54CEULL,
		0xEDC432B1918FB1DAULL,
		0x869573087784047DULL,
		0xBE01F72323F1EC4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C4A9C9AF7576A6ULL,
		0x826F3FC0B678E0CEULL,
		0x9151AF4E0B81F4CEULL,
		0xCB7B16E345573CCEULL,
		0x732B9E41867A54CEULL,
		0xEDC432B1918FB1DAULL,
		0x869573087784047DULL,
		0xBE01F72323F1EC4AULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x83D857DE728D5AD4ULL,
		0xC37B9F2A14E8311AULL,
		0xACEF2A90BCA361BEULL,
		0x45CAF80F985591D5ULL,
		0xAAB409B354510C4AULL,
		0xBEAD0402129D0FE7ULL,
		0x242651C8BE934726ULL,
		0xE49222C0D80FB4C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32B732934E7A6EE4ULL,
		0xE313F8AFD2CBC802ULL,
		0xF8B22735D7369B7AULL,
		0x0CD24CC201EE6814ULL,
		0x586B492DD0B00EADULL,
		0xC359AC5A100D4041ULL,
		0x31ED518B8156E1E3ULL,
		0xF4BFDBB3AF99370EULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6372E8D262388AB2ULL,
		0x063EFA38AC924566ULL,
		0xA80E690C574693ECULL,
		0x68C59D767184B247ULL,
		0x673B245A1C2C79B3ULL,
		0x4D30AC48E8703126ULL,
		0x04E7A0D516BEEA41ULL,
		0xE41B3B0FEA809441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3263598D18AF3FFULL,
		0x8D3B9A9B37317984ULL,
		0x1F91508B8A2B05AAULL,
		0x69AFC0F7B42F1D88ULL,
		0xE6F9F66CF0E7A8D6ULL,
		0x580BB25B3702F04FULL,
		0x819D18161D4D9E57ULL,
		0x8CD0276277A1307FULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x89039F5BD7C84A18ULL,
		0x090C037B39A2C04CULL,
		0xE1729008B3C3DCFDULL,
		0x5382C841006CE20CULL,
		0xBFEA9E141ABB8DD3ULL,
		0x17B74183172C91C9ULL,
		0xFF4CF1E359E990FDULL,
		0xFD1A65BECDC9745EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F6B11E938785B24ULL,
		0xB9B4DC811DEA543EULL,
		0xAD81B85AC109E3A6ULL,
		0x4995EACFB639DF13ULL,
		0xAFDCFA143252CFBAULL,
		0x6159CA474F13E4BFULL,
		0x86953F702991307CULL,
		0x9D3DFA07A95B36C2ULL
	}};
	t = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x390FB12A50B2FF56ULL,
		0x8A77A9BEC4629820ULL,
		0x9197A32D92D4B28BULL,
		0x17D8E4FE6DAFCA1BULL,
		0xB40C4433DC62DEEDULL,
		0x8A37A7C4A2313A04ULL,
		0x5F3A8783F174C097ULL,
		0x712AF28C679E03BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390FB12A50B2FF56ULL,
		0x8A77A9BEC4629820ULL,
		0x9197A32D92D4B28BULL,
		0x17D8E4FE6DAFCA1BULL,
		0xB40C4433DC62DEEDULL,
		0x8A37A7C4A2313A04ULL,
		0x5F3A8783F174C097ULL,
		0x712AF28C679E03BBULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2876D51261420DECULL,
		0x3F6760FBDD1BB414ULL,
		0xA243CCD86E5AA506ULL,
		0xF7AF4A9E5BAAA8CDULL,
		0x08F6BE928087001CULL,
		0x942526F17138707AULL,
		0xD9F2EDD76F0ECCA9ULL,
		0xD5D1032232DD6666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x635822BA26626ECEULL,
		0x09D86B34C8EEA70AULL,
		0x93578FC251FC90FCULL,
		0x6B8153D17374A2E1ULL,
		0x683A7F74CE806C1EULL,
		0x478D3A60A4203D37ULL,
		0x93E6104330927A06ULL,
		0xB49A0D8EBCBB4FE8ULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x18E9BA0C4327495EULL,
		0x2FFB6EA8A038F20EULL,
		0x74C353CF59107AC0ULL,
		0xB656545DE246889EULL,
		0x4B77726938DB86FAULL,
		0xFEEFE7349967584DULL,
		0x38FA3C6F28E9C4DFULL,
		0x2690AA764814CDC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4573E145C57BCEEFULL,
		0x906D92F9DA5338F8ULL,
		0x331A76C61F3CB26DULL,
		0x5C161C0C4F47F0F9ULL,
		0x28419FD86C856A31ULL,
		0xA215E52F86E21689ULL,
		0xA1522F12E774AC9BULL,
		0xE4999E4ED106AD85ULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA17CBE91C00D4799ULL,
		0x6B69986551A03BF4ULL,
		0x0E744EE7C3CD6B64ULL,
		0xFBE458A2121A3836ULL,
		0x2AF960FD3C3BA54CULL,
		0xCF68611C9AE99836ULL,
		0xF0EE5648456041AFULL,
		0x6BEAC4212C3271ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x944CD51D1B8C183AULL,
		0x09363834EB85AEC3ULL,
		0x374AC7E2BD97E8C4ULL,
		0xAB6F2F63BDBA6B63ULL,
		0x97E4BCD109586CA4ULL,
		0x67DD2888DB4F47D0ULL,
		0x040659169DEFB4CFULL,
		0xCC7565227767D5F2ULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB01225783BA7FA24ULL,
		0x198EA4FDA31E2618ULL,
		0x03119519497B08D9ULL,
		0x4A2CB432125CA44EULL,
		0x0F22C5A37B23C2C1ULL,
		0xDDC68CF74B7BE790ULL,
		0xDC2884570E35FC71ULL,
		0xCB40F7C65391B5A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB01225783BA7FA24ULL,
		0x198EA4FDA31E2618ULL,
		0x03119519497B08D9ULL,
		0x4A2CB432125CA44EULL,
		0x0F22C5A37B23C2C1ULL,
		0xDDC68CF74B7BE790ULL,
		0xDC2884570E35FC71ULL,
		0xCB40F7C65391B5A4ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB46E2575E9E3388EULL,
		0x63047EFC7AA48D83ULL,
		0x16D8C7221341B438ULL,
		0x6DF5E9C499D4C0C3ULL,
		0x05DFE3B583DA5A75ULL,
		0xBA609970B83E96ABULL,
		0xCCD44B0C095C9816ULL,
		0x5E5014584219486CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10B57EE989D3FED2ULL,
		0x80E273059DAF5359ULL,
		0xDB6D3DBCDC144324ULL,
		0x954397A4148456F4ULL,
		0x4E3A1D2006F22EF1ULL,
		0xC334DAD6DF95CB3DULL,
		0x665B20A60A6B960EULL,
		0x75525B8DCE1BB4A1ULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5831F2F940D34443ULL,
		0x4889ABCC3484A9E3ULL,
		0x4606C2ED90E93B78ULL,
		0x45C18D3715BAD34CULL,
		0xA9E9682873864B54ULL,
		0xB7B3DB8B06DCF8A8ULL,
		0x8FE51746752566A2ULL,
		0x23364FF99E6765E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C381D0CF7F1659ULL,
		0x215728952DC53628ULL,
		0x17FB34D5D4C5B0C9ULL,
		0x0CC1E9D647F2D7F3ULL,
		0x97510B2E2B34265FULL,
		0xC62FBB02D9918A5EULL,
		0xD008B756EE748E28ULL,
		0x5819BFA0CAEC1541ULL
	}};
	t = -1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4E7AF34B6DC76B94ULL,
		0x8E3805AED0FA96ADULL,
		0xD83834AA1C69F23AULL,
		0xCD4C8DE83700E701ULL,
		0xBAADE48E4332218EULL,
		0x82A3AFCAAC22F66DULL,
		0x361899AE17C682D1ULL,
		0x5292B2FEFD1BA110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0898042627C22176ULL,
		0x38FD50F3375722DEULL,
		0xAD2CE8CA85E5259EULL,
		0x53C6AF27CC343A1BULL,
		0xFC8D3F13E9198501ULL,
		0xA06CBC46794B5EF0ULL,
		0x5973E8A19D173662ULL,
		0x5A9F624BDC6A6D12ULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4456A1E20138DA99ULL,
		0x83DC6D6B8AC56AEEULL,
		0xAA9FFC4F29D4199EULL,
		0x9D2AE042FB2D0C19ULL,
		0x67A4D2006FD5C494ULL,
		0xF520A2919A0168BBULL,
		0xB8F0C78C28784CF3ULL,
		0x0E2D42CC31BCE4A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4456A1E20138DA99ULL,
		0x83DC6D6B8AC56AEEULL,
		0xAA9FFC4F29D4199EULL,
		0x9D2AE042FB2D0C19ULL,
		0x67A4D2006FD5C494ULL,
		0xF520A2919A0168BBULL,
		0xB8F0C78C28784CF3ULL,
		0x0E2D42CC31BCE4A9ULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD33FF5259DD9ECA7ULL,
		0x990E08CD5BFC8FA7ULL,
		0xEE6EB000F109CFFAULL,
		0x6127DB782A6351DAULL,
		0xA53CB95C62F777B1ULL,
		0x2D3DF643F592706BULL,
		0xB3DF44E353AAA548ULL,
		0xBB5B6516D29148CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA0BF4A4F1AA7B94ULL,
		0x66C8D54FFAC6657CULL,
		0x9C17818A07195A4BULL,
		0x149FFF1AD943319AULL,
		0xBEC47B5B1790B6A0ULL,
		0x8F71775A3AE45B0DULL,
		0x8FE73E749EF95480ULL,
		0xAAC453EDA0A86551ULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6D38C61497A7E367ULL,
		0x66B9ABB0ACB14BB4ULL,
		0xA85A50F1E0281B05ULL,
		0x29AFC00D0D0A034CULL,
		0x4F6083D80B75F8B7ULL,
		0xFCE7F3FFEE6A16C8ULL,
		0x494B071B792292CBULL,
		0xDB8F8A96198199A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x613F9C0450EB0AEFULL,
		0x0FFF46C125FBEE34ULL,
		0x2F13BCE911A3939DULL,
		0xC8C57E02A82A7394ULL,
		0x61E48C1A12A154E1ULL,
		0xA7404BC782EE7E59ULL,
		0x1529450003879575ULL,
		0x343E6D7D7B0A1904ULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA10DF3E2AE21FBF4ULL,
		0xAB88CB93F7041390ULL,
		0x0F19FD37E58A2538ULL,
		0x871885BB96387D1CULL,
		0xC4ACA19A1380B5AAULL,
		0x65A2F308E277DA49ULL,
		0x5D560EC687E4441FULL,
		0x1E9CFFA0B5F8C0ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80772010C6AF767EULL,
		0x9E403386DBCEE83BULL,
		0x16ACFC9B1EBF0085ULL,
		0xA1A5EFE73A4C4F67ULL,
		0x1AACACC40CD93509ULL,
		0xFA54117062FF3AF3ULL,
		0x43C678BDF2CDC111ULL,
		0x37A3EAF5DB76CDE4ULL
	}};
	t = -1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5A2F1D9FA015E381ULL,
		0x8F3FA71816D2D425ULL,
		0x45E5C99559F548AAULL,
		0x858FEC4C32D8B14EULL,
		0x6406E6B5DD63A20DULL,
		0x1F6CE3217B622B1FULL,
		0x7203C9302C8291CCULL,
		0x06C066A259E1047BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2F1D9FA015E381ULL,
		0x8F3FA71816D2D425ULL,
		0x45E5C99559F548AAULL,
		0x858FEC4C32D8B14EULL,
		0x6406E6B5DD63A20DULL,
		0x1F6CE3217B622B1FULL,
		0x7203C9302C8291CCULL,
		0x06C066A259E1047BULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7C3BC65109F43A3CULL,
		0x1DACE5FECE7EAF53ULL,
		0xE17E0FD253008EB6ULL,
		0xCB6D32518E0FED3AULL,
		0x586DABD7CF5E0E9EULL,
		0x89C17167B68867DFULL,
		0x5C62FFA62392CBC3ULL,
		0x3EF179677432E876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128EF70A3DDD6713ULL,
		0x41345402B73727B4ULL,
		0x94CEC51055D9A8A7ULL,
		0x44DCDB99096BE099ULL,
		0x5BC315A79B29E5DBULL,
		0xA4ECE42914BD5C74ULL,
		0x8483FEE19865BA1FULL,
		0xA650F8C2CFD62620ULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x56DFE8DF4C823153ULL,
		0x61125E5A75BE80CDULL,
		0xF41CCEEB0CC0F2B4ULL,
		0xB59C2FC2D182BB30ULL,
		0x11C4ACCA112E3DFCULL,
		0x1D19BF4DAE72FF52ULL,
		0xCA29B867C1643B14ULL,
		0x6C92051E64F689D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B2B9B5B68932751ULL,
		0xC1D00BFC0DA4F383ULL,
		0x05E955F7611EAF02ULL,
		0x456B6FBF659E8CCDULL,
		0xA7341BE5D2363157ULL,
		0xF16E13AFB47F380AULL,
		0x2DCF1F26872599CBULL,
		0x5E76D0762A40B45AULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x40BE322FBF5E2D06ULL,
		0x05B47887E3569100ULL,
		0x6734153CB292CFA3ULL,
		0x5007D2E6B65CD2AAULL,
		0xE56FC623F493A559ULL,
		0x0BF7C71FDDB8E039ULL,
		0x92A8FE4FA257EBF8ULL,
		0xECD552A2B185E2B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB59C8FEF3EE653ULL,
		0xB19E5F624DD496DBULL,
		0xE907AD8FC71A2B23ULL,
		0xB1D0E7F9760ADA44ULL,
		0x26A9EDF43FDE7F5BULL,
		0x3BBE02686C7BFF1AULL,
		0xF2AE0B7AE7EAD5D3ULL,
		0xEE137A5DE4CCF1C3ULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFC72842F23BCC626ULL,
		0x2814CF3003EE3488ULL,
		0x55F4E550960BFAF8ULL,
		0x917EA6FDDC15274FULL,
		0x80902707A708DB42ULL,
		0x013327C90C7CF1FFULL,
		0x77EC6C6698F29BBFULL,
		0x19121747808B0056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC72842F23BCC626ULL,
		0x2814CF3003EE3488ULL,
		0x55F4E550960BFAF8ULL,
		0x917EA6FDDC15274FULL,
		0x80902707A708DB42ULL,
		0x013327C90C7CF1FFULL,
		0x77EC6C6698F29BBFULL,
		0x19121747808B0056ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAEDC61DD63EC42A0ULL,
		0x5A6C5FC77E326B6CULL,
		0x5312ACE2B5FF98E9ULL,
		0x69C5F13763A025C4ULL,
		0xDA54843A9F3F4A3AULL,
		0x3E1BF8B7728FECCAULL,
		0xA39CB3C1552782F8ULL,
		0x0913CAD9B0A2E3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA08545000994BBE2ULL,
		0x2BF57A76CAD86B91ULL,
		0xE9CD56E3B96E3F1EULL,
		0xD29BB00F02ECF7E6ULL,
		0xA8543A9623394429ULL,
		0x7C3541333FE98802ULL,
		0x1A3BC215450E2CD6ULL,
		0x8EDF90ADA84A3C08ULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7782B002EC2C01A9ULL,
		0x03B40B01BBB3127DULL,
		0x30F3BAECAD13F7DBULL,
		0xABA7304D9CD80E09ULL,
		0x19F5B4A1BFBC973EULL,
		0xE90D068B503E8357ULL,
		0x9C5FC381C07C00D6ULL,
		0x60F5EFE7C3101846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00D66CA7521BE96ULL,
		0x54E78BAA3816BA9EULL,
		0x52959EA6E76978FDULL,
		0xFD558081CC84946EULL,
		0x34B20659AE80F3E7ULL,
		0x9CFB06CBB0A75010ULL,
		0x9F9D3A742734C8BAULL,
		0xB53263BA0C773D84ULL
	}};
	t = -1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x03855633DD322390ULL,
		0xFDAC838451E7665BULL,
		0xE25DA4AECBD0FCEFULL,
		0xAB91FD1AA7C1955BULL,
		0x304D35211149F12FULL,
		0x7AF696825A38037AULL,
		0x816C17343FD75722ULL,
		0x94E6B7C88868B7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532976B55A02DA89ULL,
		0x576FDD96F70D2995ULL,
		0x40B820B768361C8CULL,
		0x7E9E573DF5D1887DULL,
		0x7B88CA4DB8BB15E2ULL,
		0x7803C835C1E30E3BULL,
		0x9431EE0FCF1FD693ULL,
		0x0ABA6436712581C8ULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF25B5CC5552D26FBULL,
		0x7FF9D99B8B90AB2EULL,
		0xD11148EE3888CAE6ULL,
		0xE790EC22F1F96B82ULL,
		0xD07F388F1D7EB0EBULL,
		0x525EE4B3C865D002ULL,
		0xDDEDCF0887E007BAULL,
		0x171E2AA324D69FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF25B5CC5552D26FBULL,
		0x7FF9D99B8B90AB2EULL,
		0xD11148EE3888CAE6ULL,
		0xE790EC22F1F96B82ULL,
		0xD07F388F1D7EB0EBULL,
		0x525EE4B3C865D002ULL,
		0xDDEDCF0887E007BAULL,
		0x171E2AA324D69FC5ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9A1D158AE324E33EULL,
		0x59ABA3D185EE940CULL,
		0xD723FA741F149FAFULL,
		0x89EF91A0E5DCB7B1ULL,
		0x7E586250B7DDB026ULL,
		0x51B71E4B96AF2746ULL,
		0x4859927292C3BAD6ULL,
		0xFE9708AA647B4C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B4F0E709B327FBAULL,
		0x4D30397BE5251511ULL,
		0xA276A1B09DBD1841ULL,
		0xCD7FA43553CEB6D6ULL,
		0xA1B207CCB9F7E7AAULL,
		0x9F59DC3EABCFB991ULL,
		0x3E7F056A6DDD0437ULL,
		0x98062D9BEEEDE46FULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x19EA268686DAE9AFULL,
		0x310FE98AD118105CULL,
		0x10D2C13CFE3EF5C6ULL,
		0xF9C421FE8A2D3EA5ULL,
		0x4BB19A09D8048014ULL,
		0x86D777A262475023ULL,
		0x8BA0C85DF39044F6ULL,
		0xD6AAFCC3D89B7870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76295C5CE4F9391ULL,
		0xB8A71BBE24BB796FULL,
		0xDD6F80ADC3D1FD2BULL,
		0xA47A2313CE204760ULL,
		0x4DF2FFB585AEE60DULL,
		0x7D8C8F3D8E05F0EFULL,
		0xBBC0CF84628F204DULL,
		0x4B9530A99095530FULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x90662E788E66B886ULL,
		0x795D73AB2D166BE0ULL,
		0x7990A7081FA5B49FULL,
		0xC4A4AF7EB663FA02ULL,
		0xE7417041A86165D9ULL,
		0xAB51C410A98C8745ULL,
		0x07AE7AEF44E4C52CULL,
		0x4EAA6F9F4C759300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B8DFE0137F77B4ULL,
		0x80EB09AB7FE28989ULL,
		0xB90C99E84F5C1908ULL,
		0x5A7CA3A20B56B78FULL,
		0x6BE63EA06C2A76ECULL,
		0x29CE1BBC9B1B5465ULL,
		0xECA8B564B6DA83C9ULL,
		0xC7B8674B08D6D0DFULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6990D4B0A060AE89ULL,
		0x812479BA1A0B0508ULL,
		0xDB7F3123BBEC0790ULL,
		0xE5711598B98C7EBDULL,
		0x0460831738EAA34BULL,
		0xC132D482AEBB8CF3ULL,
		0x9087372C7BAFCB7DULL,
		0x6EBB34A13E242151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6990D4B0A060AE89ULL,
		0x812479BA1A0B0508ULL,
		0xDB7F3123BBEC0790ULL,
		0xE5711598B98C7EBDULL,
		0x0460831738EAA34BULL,
		0xC132D482AEBB8CF3ULL,
		0x9087372C7BAFCB7DULL,
		0x6EBB34A13E242151ULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBF498F51904A6CEBULL,
		0xA5B1D4D7A92BDD8EULL,
		0x5CCC570898F0A2E4ULL,
		0x646E762B4F88FC74ULL,
		0xB21CCFD4431D88C0ULL,
		0xB81C799C51535F3DULL,
		0xE95DD215135E6693ULL,
		0x6ED0BC867687C30CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB69DB28DB05227B8ULL,
		0x801F5CF8B2EA7E17ULL,
		0x643BCE041FBF6190ULL,
		0xBD1708F893E390C1ULL,
		0x1E1A6CCFF0A2D6CBULL,
		0x0BF7EAC608FAAA50ULL,
		0x0DD717B847B2584FULL,
		0x6F7A29EAB8F56152ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x151C047B17ECE038ULL,
		0x5F4CBDF36029F69CULL,
		0x37F73D1873A8BA6DULL,
		0x8434DDDFD61890D3ULL,
		0xBFF894811714E748ULL,
		0x77E92A54619BDFD5ULL,
		0x1D3A7DC7B4640081ULL,
		0xA21A042AABA11F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD24621E7C85BB51AULL,
		0x4091BBF4DBFABF1FULL,
		0xD70891FD55938A00ULL,
		0x2F6F457BF88FA5F3ULL,
		0x5A6BB46109CDFEB8ULL,
		0xFE67DA8C2AB2084EULL,
		0xCA1E032623AC9E50ULL,
		0xAF9A2E38D2A6A531ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x29CBB5FF527DDC9CULL,
		0xFE320332B57800E9ULL,
		0xB55CA61FF6F016A3ULL,
		0x0DAFE7F31BCF5046ULL,
		0xEFA2B4617857BA79ULL,
		0xEA3494CB46A5DD0BULL,
		0x76F6579E489642AFULL,
		0x73AD6A050B40F20AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E3034418B40AFC3ULL,
		0xB2D41C10180248D2ULL,
		0x810A4EF5DB1A7A72ULL,
		0x636521E841F4AAE4ULL,
		0x5FE499309F1DCA72ULL,
		0xE360862DF3530AC6ULL,
		0x2997A31B3173043FULL,
		0xB2BCA70F6841EF87ULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF6AB7010F391F1BCULL,
		0x742504EA29EB0BB2ULL,
		0xDBC6E78889B60BC3ULL,
		0xC55DF8FF32987E00ULL,
		0xD9C4D3134D0B23EFULL,
		0x146529D65845EBB4ULL,
		0x6C42FB8E74CA8398ULL,
		0x447A856803C9FBB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6AB7010F391F1BCULL,
		0x742504EA29EB0BB2ULL,
		0xDBC6E78889B60BC3ULL,
		0xC55DF8FF32987E00ULL,
		0xD9C4D3134D0B23EFULL,
		0x146529D65845EBB4ULL,
		0x6C42FB8E74CA8398ULL,
		0x447A856803C9FBB3ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2C35A87F878BC384ULL,
		0x5FFAE628317D7CFBULL,
		0xD449E26DCB20C0B3ULL,
		0xD3D7F61E22E73D2EULL,
		0x607A43EA53D0C309ULL,
		0x44B2866F68158E49ULL,
		0x8C5531DA2BE94D99ULL,
		0x46157E19F6A20211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F70008FFDD53AA4ULL,
		0xEB953FE9AA933F42ULL,
		0x25F778BBE0BCA081ULL,
		0x431138AE4E140FE8ULL,
		0x0CD335F5D6681F25ULL,
		0x566A4134BC5D27B0ULL,
		0xC650A81714CF131EULL,
		0xC555939154F46619ULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5B0F17853B30C814ULL,
		0x7C3A12ABD4282D10ULL,
		0x5BE43F1354C178CEULL,
		0x376AF38123E63A95ULL,
		0x976130FA9412EE99ULL,
		0x26A03CEA9941ACCCULL,
		0x506F1E17B685D495ULL,
		0x4CC1321B229ACADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E1BF0DCBA53934ULL,
		0xD1E388F757DDB073ULL,
		0xB798B35ECCBDD690ULL,
		0xA5F42B87BACDBD15ULL,
		0xA9E05B48CE5EC024ULL,
		0x98B100B941801D24ULL,
		0xC63E842CA1A34438ULL,
		0xBC3877DB3AE342B4ULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4224484EF80A110AULL,
		0x566A23E5A64AA5F5ULL,
		0x919CC9183B830CA3ULL,
		0x0D606043CCBEB2F9ULL,
		0x781F5D2801AA8918ULL,
		0x8847579385C51411ULL,
		0x2FE8CD23390B6826ULL,
		0x4711A62FA5C985FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x113A1CE6E6022D4AULL,
		0x23AE66630E5C8162ULL,
		0x111826867835F99BULL,
		0xAB4BFD0417771D70ULL,
		0x03EBAD92BDCF1B1CULL,
		0x4526ED773BA13C88ULL,
		0x6CAB2A24546D9D38ULL,
		0x8BA673BD698B3A26ULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE6BC4D2DEDA74A44ULL,
		0x28228456A91BF97EULL,
		0xC8E45EC1901C34E2ULL,
		0x371DD01563D1C4CEULL,
		0x92A888ED93898947ULL,
		0xED150CBC19B2ED9AULL,
		0x01178E16D273D343ULL,
		0x994FC2C2FF6CAD04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6BC4D2DEDA74A44ULL,
		0x28228456A91BF97EULL,
		0xC8E45EC1901C34E2ULL,
		0x371DD01563D1C4CEULL,
		0x92A888ED93898947ULL,
		0xED150CBC19B2ED9AULL,
		0x01178E16D273D343ULL,
		0x994FC2C2FF6CAD04ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEAF0CCAF6E003ED9ULL,
		0xDE0E58E8ED3ECFD5ULL,
		0x48D3C84A92937D49ULL,
		0x708FEA2516F63603ULL,
		0xE70044F8E4CBFDBCULL,
		0x09452F5F7634C356ULL,
		0x914269006CB4CABBULL,
		0xE86EEF33B223F344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7AC3AD6D1EFE846ULL,
		0x703A82C001460A72ULL,
		0x62025780F0D6FCFCULL,
		0x9B743DEBCF7E901DULL,
		0xB477ED2A92A4D80BULL,
		0x6EFB46DA2D91B901ULL,
		0x90115613DDEB9CFEULL,
		0xF472485D74772EDCULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6EAB1F8E470FA6EAULL,
		0x79D429DD1BDFABA4ULL,
		0x0BF8D8558091E1E6ULL,
		0xDF80BFDB0F349941ULL,
		0xB66D94E42EC691EDULL,
		0x0F38AE6A69384165ULL,
		0xAB405CDE66D82955ULL,
		0xA00AB8E9C140706AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9864D769DD216C6BULL,
		0x907F6C065015269EULL,
		0x10948D604B13CE78ULL,
		0xAFE49633110ECE55ULL,
		0xEFD24A4FD20BF989ULL,
		0x20977D669D568415ULL,
		0x9B583624E734167FULL,
		0x61631BF52B7D4521ULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x68FAC4FE3482D266ULL,
		0x402DB9F169651C72ULL,
		0xF21B424FE4A18450ULL,
		0x3A0B2AE48DC2587DULL,
		0x6295A8D113B22E94ULL,
		0xF0B490710FE80BE3ULL,
		0x2719F9C972695629ULL,
		0x5B03DCA118F2803EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE90B2E764E85F551ULL,
		0xC78F904130CA6EDFULL,
		0xBD7FC73682FCBDEFULL,
		0x65EB45125AB89F21ULL,
		0x69047DAB1891CC32ULL,
		0xA7B1A00353333BCCULL,
		0x9B2D5D4D62D1D4F5ULL,
		0xD49909E1D1DFB4F9ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB78CC56316692AE0ULL,
		0x4CF7A9A702341EBFULL,
		0x8DD7B44C258586E8ULL,
		0x7303BA9D3F0CAEECULL,
		0x9B642F89BA03DA98ULL,
		0xCF779EFA5A2F7C70ULL,
		0x7701F78EC5E9D6E1ULL,
		0x54D9CB51AAEB4A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB78CC56316692AE0ULL,
		0x4CF7A9A702341EBFULL,
		0x8DD7B44C258586E8ULL,
		0x7303BA9D3F0CAEECULL,
		0x9B642F89BA03DA98ULL,
		0xCF779EFA5A2F7C70ULL,
		0x7701F78EC5E9D6E1ULL,
		0x54D9CB51AAEB4A53ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA84CC92D28184D55ULL,
		0x1E16B8BFF440F218ULL,
		0x337B1A2A4D585511ULL,
		0x36B90AAA84FFE68EULL,
		0x13068951F239C8ACULL,
		0xB2AD69F5E0B0B1A1ULL,
		0x643F49571FA0F447ULL,
		0x9EE9EB5FE1BC4569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x187A8B22DC741360ULL,
		0xA36C1DC076204055ULL,
		0x5D711ECE6904565CULL,
		0xBFFA572010831CFDULL,
		0xB876A2177B7F6C09ULL,
		0x50DF3AE94440BD8EULL,
		0xF97207D93A0AA879ULL,
		0x96F938C85887BFD9ULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7E240D082A000407ULL,
		0xEBF7DCA6968DB6FFULL,
		0x5AEE6DF2AB1C97C1ULL,
		0x73A8434AB648644EULL,
		0xCB632152A25ABD13ULL,
		0xD1C27530DF2F4C23ULL,
		0x8A508CF8FF2863A5ULL,
		0x34B8816D5F3978B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA7DF6CB9DD1AB0DULL,
		0x7F1B9D8894130011ULL,
		0x55FE411FCFBD1C52ULL,
		0x55BC750767B43453ULL,
		0x38C9B42C3570FF85ULL,
		0x7AD39370B9584516ULL,
		0x1BC013CB3504C25EULL,
		0xA9CEE4143A4E72DCULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x994899BDA8ED4283ULL,
		0x863B244095257432ULL,
		0xB5396F2EC436FA18ULL,
		0x96C169EADE66C506ULL,
		0xDF293F8ED05B57F0ULL,
		0xD27AC1D55ECF3F92ULL,
		0x4D9B6962D53DC1F2ULL,
		0xC200A8607BA9309EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x312563DE8DABC14DULL,
		0xDBF17E6C275482B3ULL,
		0xEAF7EB60BCAA07DBULL,
		0xB1CBE4B9E6734A6DULL,
		0x45B81707153EC8A4ULL,
		0xC49919FBCE0C2463ULL,
		0x87D7E8B042FCEEBCULL,
		0x7F46D89FA7D65030ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0529F9FD0AC2626FULL,
		0xED9066A5BD7F6C6AULL,
		0xC76C9852ACB2B2CFULL,
		0xC13E6A2E6C9EDD8DULL,
		0x58882DD652D2C19EULL,
		0x86260B984BFB5012ULL,
		0x07E689DEF6E5F1F5ULL,
		0xD53A3AB885FE5315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0529F9FD0AC2626FULL,
		0xED9066A5BD7F6C6AULL,
		0xC76C9852ACB2B2CFULL,
		0xC13E6A2E6C9EDD8DULL,
		0x58882DD652D2C19EULL,
		0x86260B984BFB5012ULL,
		0x07E689DEF6E5F1F5ULL,
		0xD53A3AB885FE5315ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7F747B79D15CDAD1ULL,
		0x980D92741FB54A77ULL,
		0xEB89EFE376B4E116ULL,
		0xA6BD5946DB144711ULL,
		0x9FACF91F6093BD5FULL,
		0xE4227CF49CB9FFA8ULL,
		0x5ADE023F23FD29BAULL,
		0xDF8C9205B4C5E1D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24885F95A4007270ULL,
		0xB99C2020DE1D05C8ULL,
		0x2CD76B700F2A0577ULL,
		0x94B35293CBF634E3ULL,
		0xCE54A413D4D8B408ULL,
		0xC80212CBE9420951ULL,
		0x9253E036198ADA8AULL,
		0x616432237368756DULL
	}};
	t = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x173F17182AC9B447ULL,
		0xEF3D57A684DDFD91ULL,
		0xB1C2FD66A390505FULL,
		0x5F8F90A8FA1C6672ULL,
		0xF6B1F696807038F1ULL,
		0xF106B3CE8EA85A63ULL,
		0xBBFAD5F2E5DF71F0ULL,
		0x3A3AB93BD17F1825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41C0AF604B270AFFULL,
		0x62327A47AE15FF53ULL,
		0xDA3FDB2F8F7FE714ULL,
		0x2FFE610FE9A2E121ULL,
		0xDC8274F53DE9079BULL,
		0x7BC69BAD1FDF48B4ULL,
		0xA73CE38168D7D414ULL,
		0x0DA60E5D9D6BBDEFULL
	}};
	t = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7492EAD2D4A78381ULL,
		0x79D30A557D42F31FULL,
		0x9012B1853124C2E4ULL,
		0x5D10AA135FECA437ULL,
		0x95E80CECF258F2FBULL,
		0x7FC3C92128A2F834ULL,
		0xB7446C4DF171CB55ULL,
		0x60AA4D2C9586CE8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x943ED6464EAB1D95ULL,
		0xE7408D485F881600ULL,
		0xD394E4BE7AD245B6ULL,
		0xD30B84864D6835E0ULL,
		0x13AB60AA93259798ULL,
		0x686C8B87967C9487ULL,
		0x07D3957608F87603ULL,
		0xA94A5F88E7BF84A4ULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAF3F09624B4C4743ULL,
		0x1B1854D798F08D8DULL,
		0xFCA370BE74509CF5ULL,
		0x0CF1A2E2FBCD7070ULL,
		0x283F1A6F4F8CCA51ULL,
		0x0FDE844A018017B3ULL,
		0x800FBFC2CAAA5A01ULL,
		0xBE0F30E7A144CCDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3F09624B4C4743ULL,
		0x1B1854D798F08D8DULL,
		0xFCA370BE74509CF5ULL,
		0x0CF1A2E2FBCD7070ULL,
		0x283F1A6F4F8CCA51ULL,
		0x0FDE844A018017B3ULL,
		0x800FBFC2CAAA5A01ULL,
		0xBE0F30E7A144CCDFULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6CDC47907FC17429ULL,
		0x898D7752AD9E40E7ULL,
		0x04C864327DC9A6F6ULL,
		0xEE083E7C09D13AB1ULL,
		0xA6DE2DDC23613675ULL,
		0x1CEE2BE6C122627CULL,
		0x52816476F9BE638AULL,
		0x3D19A4418465A10AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x226AB52862D3FB46ULL,
		0x3A44D06BC33CE19CULL,
		0xE1B5EFDB9EB0BB83ULL,
		0x8C2E7CB0F947F6F6ULL,
		0x31AD8ECCC4E2906EULL,
		0x7EE34AE48131B273ULL,
		0x0D89AB940079524DULL,
		0x5C1F8FD7736DAE49ULL
	}};
	t = -1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7A317E73B3B1BBA5ULL,
		0x95180E05BE90402BULL,
		0x17FCED6C832635B0ULL,
		0x118A21D2BBB97139ULL,
		0x6F5005F3255F53C3ULL,
		0xD5C91109C25FEB07ULL,
		0xB99FFFC3C58E69B7ULL,
		0xC4FED40A02D557D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E7A76F1F1F5D8FFULL,
		0x321B4BA7A3E683C6ULL,
		0xC191C85150A96E19ULL,
		0xE8BF0CA12B3D415AULL,
		0x876B9CFAD73B36DEULL,
		0x0D021327BA2D75AAULL,
		0x5EE84CB7C29EEE56ULL,
		0x8ABD2BAC81B95F0DULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE4395322B7E6BC1AULL,
		0x12DC055795922671ULL,
		0x076E6634731B55AEULL,
		0x51141A50B3E1AA1BULL,
		0xE2EAD33BCE1746C5ULL,
		0xE731FD0B870E0CCEULL,
		0xDE6C0F84F31386C1ULL,
		0x64E890FBA0A0179EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB13C9E8B561F15C6ULL,
		0xD4FB5630E19B36CEULL,
		0xB55ADDF55AA0887DULL,
		0x231CF2C4EF6F9FB3ULL,
		0xDBB68358426E0A16ULL,
		0x7EE0F2309DF0EDCAULL,
		0x77CBD918C9486BA1ULL,
		0x0B8CA94AC2C9FCC4ULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x775A406D29A893DBULL,
		0xA86BE1DE02BCA822ULL,
		0x5C1C2F0A27C1C938ULL,
		0x2740EC9A70303EB7ULL,
		0xF1D5E14D9FDAC200ULL,
		0xA9647016628D8134ULL,
		0x9622905CB880F448ULL,
		0x72D3C3BD4027E20CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775A406D29A893DBULL,
		0xA86BE1DE02BCA822ULL,
		0x5C1C2F0A27C1C938ULL,
		0x2740EC9A70303EB7ULL,
		0xF1D5E14D9FDAC200ULL,
		0xA9647016628D8134ULL,
		0x9622905CB880F448ULL,
		0x72D3C3BD4027E20CULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE447769C0C22618AULL,
		0x8DC4F853B4AFC4D7ULL,
		0x2ACCE163762DC63FULL,
		0x82C34094B260190DULL,
		0x6051CD724B949D9AULL,
		0x5C86AD9A27538D48ULL,
		0xB354F0C772D3DB8FULL,
		0x49DCD8D516BD6A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B2F1527DBC3540ULL,
		0xEBBF3CEF0B1B2FA8ULL,
		0x91F025D531D70A59ULL,
		0x1D7E365301F6FC12ULL,
		0x9982C82E5F50ED2CULL,
		0xA20B44B05AEE366AULL,
		0x6BA8DC9EE33EFF1CULL,
		0x88B5E9EB62FE65B6ULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x59943F122FF96D4AULL,
		0xDCA43E9EAF9CF954ULL,
		0x437D5CC33B489A78ULL,
		0x95400BAD63553109ULL,
		0xA8B81B0910613048ULL,
		0x4F80AAEC0B652984ULL,
		0x71484948093F39C8ULL,
		0x1D61729C50772EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C7482522B2A1DAULL,
		0xA12542DE1E427469ULL,
		0xFE95DE65AF97D3D3ULL,
		0x2B769CAF8EB4C278ULL,
		0x401D214465CDD436ULL,
		0x1B391FADECC05135ULL,
		0x30149F12A7D4EFD0ULL,
		0x1A969D343AA41C00ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1103307899FC96A9ULL,
		0xA506D267373F6F51ULL,
		0x0EBAFDAFCAA29264ULL,
		0x2770B7EB11436454ULL,
		0x4ED25F952D238252ULL,
		0x24E146939FF738DDULL,
		0x1F321744171C68D6ULL,
		0xF56D6AEAEEFAE834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0CF9F31339BA9CBULL,
		0x74556092A43FDA7CULL,
		0x4B00EC4EA1C036A5ULL,
		0xD2DF512FE22C3B83ULL,
		0x552E1A6E3D2D8523ULL,
		0xC940564AB42793E6ULL,
		0xF28F855D2442C024ULL,
		0x3E6763AD3C793C55ULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x42A91B3D6F9534FAULL,
		0x3DB6CC60E7D4DD87ULL,
		0x62B2BDA048F45F30ULL,
		0x7F14402D9FF20385ULL,
		0x31946A2612BC74CCULL,
		0xED6A420EB1C7A4CDULL,
		0xB2A32071529AE4A9ULL,
		0x17B641A9D6FB973FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A91B3D6F9534FAULL,
		0x3DB6CC60E7D4DD87ULL,
		0x62B2BDA048F45F30ULL,
		0x7F14402D9FF20385ULL,
		0x31946A2612BC74CCULL,
		0xED6A420EB1C7A4CDULL,
		0xB2A32071529AE4A9ULL,
		0x17B641A9D6FB973FULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1F834DEA80D53954ULL,
		0xA9D51851BCD1C903ULL,
		0xBAF760530435D33BULL,
		0x82366325AEE540E1ULL,
		0x97DF4F1B0C2A2642ULL,
		0xDAAE0DB44D6CC159ULL,
		0xE153FF2D418247C5ULL,
		0xF62603C089704CC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41533019CE436926ULL,
		0x676AB870102492E8ULL,
		0xB367EBA09DD4378FULL,
		0xDA651484DDA51895ULL,
		0x6DEB15BA114F8850ULL,
		0x9CA8F1C252381DD2ULL,
		0x614EBAA6E7056B2FULL,
		0x994C3DF382C76063ULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB5D7CF9B8F798922ULL,
		0x90E07685B99B7260ULL,
		0x377DBB0840484FDCULL,
		0xACF4E410D8E3CCF4ULL,
		0xB67D7F95B1ECEAC0ULL,
		0xC5FB3F67CC00223DULL,
		0x934006EB273AD6B6ULL,
		0xEC366A624ABECBB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464A85F1490CA075ULL,
		0x38FE598B73A03D54ULL,
		0x376E8AFCB61CE52EULL,
		0xE96078F8CD37DBF0ULL,
		0x821271E987351454ULL,
		0xAC2C981FA2F644D9ULL,
		0x3BF652836BCCA3C8ULL,
		0x559156A60CC333C8ULL
	}};
	t = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x71822D6983C36300ULL,
		0xA5057193EF0CFD72ULL,
		0xC85DECD75B318D7FULL,
		0x199343FE92130161ULL,
		0x0BBAEDCD9A7A30A2ULL,
		0x1C512E44D89C13F4ULL,
		0xC7DA277FAED031B1ULL,
		0x14AB789F670354CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB233D5B0A50C7EF9ULL,
		0x1BFD3A15BCC1F506ULL,
		0x29854F2F8163A9A3ULL,
		0xDDF26F8ED0338938ULL,
		0x5953849B2F1E4530ULL,
		0x153A20A8FF659624ULL,
		0x817649669AFC2ABCULL,
		0xC5FA202B7048527EULL
	}};
	t = -1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC8A77A40B79818A2ULL,
		0x55592D9A17AE091DULL,
		0xC46F66A416BA426AULL,
		0x12BBF01316EAC138ULL,
		0x7F3A336E2AE529D8ULL,
		0x3DD9C599F875F83EULL,
		0xA8F4A0A635015F22ULL,
		0x9D11CFE9306C9F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A77A40B79818A2ULL,
		0x55592D9A17AE091DULL,
		0xC46F66A416BA426AULL,
		0x12BBF01316EAC138ULL,
		0x7F3A336E2AE529D8ULL,
		0x3DD9C599F875F83EULL,
		0xA8F4A0A635015F22ULL,
		0x9D11CFE9306C9F1BULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0B46D13FD132F9A6ULL,
		0x087C67E5E7578C5EULL,
		0x05E59FADEACD26C4ULL,
		0xD1122C05EB29EFDBULL,
		0xB1B5A3370AAC0832ULL,
		0x9AA85D47C64F68C8ULL,
		0xD2B8B70FBFAA434FULL,
		0x37C3E5BDBDB3455BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x751CBB5BD9726A46ULL,
		0x21C06B4CEE7E89B6ULL,
		0xC3D6C7AB93A5FD10ULL,
		0x64A43FD4BFD302B3ULL,
		0x86890583F8D436B0ULL,
		0x841AFBB4159036FFULL,
		0xF5529CAD931E5BB2ULL,
		0x8F95CAF5CE1F5C05ULL
	}};
	t = -1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x60AF2801051D637AULL,
		0xFF9A80E7EAF2718AULL,
		0xB99A37A78EF3F0FDULL,
		0x7B99064F9FC8F4E0ULL,
		0x6EF51E19CCB915A0ULL,
		0x44C69A64CD1DEFDBULL,
		0x3984CBEF34662765ULL,
		0xE6DB19B2467AD58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60B3CA9235DD1BC8ULL,
		0x2327AD2E371E7C58ULL,
		0xED4661E4F64337A2ULL,
		0xF90CE8E53563C272ULL,
		0x6F4671C095089BA7ULL,
		0x5BAE6B9D5A0A797FULL,
		0xF463DC84D0E75257ULL,
		0xC4E1F596715A0C3CULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x15B82A167EF58101ULL,
		0x37CA80CA7E2E26BEULL,
		0x257CA12C33042534ULL,
		0xFEC5575F6ED195FAULL,
		0x1EE46E58CF5354F4ULL,
		0x19648E327F6DB8E3ULL,
		0xCBF69D1D75186D53ULL,
		0xCFB138FA6ADFB012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE976E73987E585F6ULL,
		0x72EAE70FDE2B01BAULL,
		0x41FB01A5DBCC601FULL,
		0x6A7629A67825075FULL,
		0x0FA3EEB6561D2A3BULL,
		0x0091E40358348C1FULL,
		0xA0BE33E009BFF83DULL,
		0x3A910E4D6E2041AEULL
	}};
	t = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE5CC95A541C0CC5BULL,
		0x40D8ED5445C21D8BULL,
		0xA21426C7FE28404EULL,
		0x36F66673F6043C1FULL,
		0x16B2E79330B6992EULL,
		0x33A8610BFB46967BULL,
		0xD340C3B880340489ULL,
		0x708CEA3CFCA817F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5CC95A541C0CC5BULL,
		0x40D8ED5445C21D8BULL,
		0xA21426C7FE28404EULL,
		0x36F66673F6043C1FULL,
		0x16B2E79330B6992EULL,
		0x33A8610BFB46967BULL,
		0xD340C3B880340489ULL,
		0x708CEA3CFCA817F8ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x130739BD777F99B1ULL,
		0x9F4983308FD10EB7ULL,
		0x303283CCE63D5A03ULL,
		0x67DE9E6F3544A9F3ULL,
		0x12D287B8B70EB157ULL,
		0xB3ABBC25191DC9CFULL,
		0x8EC34B966D9C83BCULL,
		0xF3592194E0073FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA004E383033ABE5EULL,
		0x6C254CEBCEA2ECB3ULL,
		0xBC0EEACC80C94C13ULL,
		0x3A07D31E035E314FULL,
		0xD4CE646302DFFBC4ULL,
		0xA729B9D0DEB7A643ULL,
		0x998FC0BA7754703EULL,
		0x3207E16889B487E3ULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2813305EA2386F78ULL,
		0xA03B4C1221786A39ULL,
		0x2577D208B41F82DEULL,
		0x4CEF14B85ECB9351ULL,
		0x89A905A7CCA99940ULL,
		0x562419ACE44ABE6FULL,
		0x93AEC122B9C860BFULL,
		0x628424B9449AA6A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67DEC654A1C1EDCBULL,
		0x041AEDE33CD2D0D1ULL,
		0xB726DF19CCB2C090ULL,
		0xCEF3317850020381ULL,
		0x9DDFE64D3499EC6AULL,
		0xFC8EEA1080185295ULL,
		0x926D811174DCCA36ULL,
		0xFB7E9803D1B67A88ULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5D6BF40EC15E85C1ULL,
		0x19558AC0BB4E41CAULL,
		0x8A29EEDAF2DD91C6ULL,
		0x8629B17ABC51D679ULL,
		0x02E22178E28A9F60ULL,
		0x9001882624B3015AULL,
		0xF3399895A32F8B6BULL,
		0x8BFD936509E2A12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E80C6EA6674534EULL,
		0xD216AA680BF68111ULL,
		0xCD8D3D5DA0E80A04ULL,
		0xC0F0B568AB083375ULL,
		0xE089DCF588422A24ULL,
		0xB0BDF281CD504DB0ULL,
		0x7EC7B117C7E18521ULL,
		0x6383044A6401A7AFULL
	}};
	t = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x45DE2E80B2A5889BULL,
		0xB01A18973C9EF4FBULL,
		0x2DB5346667FF182AULL,
		0x4E3E5C60132ECDC1ULL,
		0x8DDF2A2A4C69DEB1ULL,
		0x942F8F75AF740E0EULL,
		0x44D6C667113378CFULL,
		0xD2B3C6A071ED728AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45DE2E80B2A5889BULL,
		0xB01A18973C9EF4FBULL,
		0x2DB5346667FF182AULL,
		0x4E3E5C60132ECDC1ULL,
		0x8DDF2A2A4C69DEB1ULL,
		0x942F8F75AF740E0EULL,
		0x44D6C667113378CFULL,
		0xD2B3C6A071ED728AULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEE7A9D3CF72E7B22ULL,
		0xCA3E3765776E727FULL,
		0xC0829685CDAF5053ULL,
		0x20F80B1D62EC11EEULL,
		0xA2BACA2A3005DD53ULL,
		0xC2C98BD593EA16B4ULL,
		0x7FF73EA8BB66C286ULL,
		0xB8196AD7F4574E28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD665AA41E17849ULL,
		0x244DBC198F0D66A6ULL,
		0x7F224135B3138EF3ULL,
		0x4CD44404AFC12586ULL,
		0xDC55A4BEF12A9565ULL,
		0xF96099D700BC7874ULL,
		0xF76180D3EE97052FULL,
		0x7155A8FA967C4733ULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x27C9F48E909F86CCULL,
		0x4FE71C9C97FBFFC9ULL,
		0xF51031B2EA5FC4B5ULL,
		0x381DE27A21F3EACAULL,
		0x81CD6BED9D6B19B9ULL,
		0xDC1DF6564A029ED4ULL,
		0x88FB4277AB0CDAADULL,
		0xB9B49B00FE6853B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB81C35219F6EE164ULL,
		0x386583EB2FE7781FULL,
		0x770C250B64A77B33ULL,
		0x4F5FAF9B5C7FCEE0ULL,
		0x14316B9C0B14269EULL,
		0xA42FEAF591BFE4F7ULL,
		0x7313F48DC55D308FULL,
		0x97B7BA965DEFE7FCULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0E57F6E7D7AE930FULL,
		0x893F8527C5A214CFULL,
		0x2D5BFB869523EECBULL,
		0x33A35E605C3D92D7ULL,
		0x72E0A67E26976694ULL,
		0x7E5641B88BDEC410ULL,
		0x65A89031B09C05FCULL,
		0x87A99B68BC3835BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C60ADB07C71281ULL,
		0xAE415B9789513E9AULL,
		0x3E9F0D2944F6ACA2ULL,
		0x74744BA535BC5AD2ULL,
		0x5810E8F478FBE2DFULL,
		0x277F60C85F46AE2CULL,
		0x5592CA8000B78BC5ULL,
		0x1F71F6890E102257ULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD9D7B82F495B9CF6ULL,
		0x1C2B3940D5C10D23ULL,
		0xC5206490BBFB31DDULL,
		0x0C7C55415D4A2CEBULL,
		0x5362C20E5AC8B507ULL,
		0xDA5A42B8751D440CULL,
		0xCA4D9882891A199FULL,
		0xC0D9610A2D1A03C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D7B82F495B9CF6ULL,
		0x1C2B3940D5C10D23ULL,
		0xC5206490BBFB31DDULL,
		0x0C7C55415D4A2CEBULL,
		0x5362C20E5AC8B507ULL,
		0xDA5A42B8751D440CULL,
		0xCA4D9882891A199FULL,
		0xC0D9610A2D1A03C4ULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x526DAB6B890C048CULL,
		0xD2C52C18C0505EFDULL,
		0x5EF7E764BD5488D2ULL,
		0xB7261625289AE2F5ULL,
		0xCC8766A343D2784FULL,
		0x10EA99793CA3677BULL,
		0xC2283C7A26405067ULL,
		0x7019CC91FE35A7CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD208E6981B3B8A7CULL,
		0xBF3D88A1422EB0C1ULL,
		0xD0D0DF76C7774D70ULL,
		0xEE1193594E9DF57CULL,
		0xD8381428B7BC7B25ULL,
		0xB272C49A3D8FC568ULL,
		0xD84A2011B8B85450ULL,
		0x7AF515CEC0172ED4ULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x17BCFBFF158C800AULL,
		0xB6FDBCFBDB0CF5DDULL,
		0x9F096D7139B6B890ULL,
		0x148FEAF969951400ULL,
		0xBDAD170D75E8EC02ULL,
		0x7641F00020EF6CBAULL,
		0xA9C92310450AC980ULL,
		0x2884C46A17537533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6407FBD1F4340F4AULL,
		0x6C2BE5F61B125604ULL,
		0xB559CAF1447FAF15ULL,
		0xEA084DF8A44E106CULL,
		0x1071DA3BD3F1E1DBULL,
		0xBFCA750E60FA727FULL,
		0xCFE54458463F0855ULL,
		0x4D02C906C5A0DD17ULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7D65F1C661DFFA99ULL,
		0x3E0D072423D2EB5DULL,
		0x2B107BECBAD9FAE9ULL,
		0x3FDB162EEE46ED4EULL,
		0xD81EE56C06C77D69ULL,
		0xADE40C077826E1E3ULL,
		0x618B32919F150C82ULL,
		0x13E70C678A307AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C1F9AE15513E88ULL,
		0x6A61CEAAB5F585C1ULL,
		0xEF8273906AED0482ULL,
		0xD1FB795340207DBFULL,
		0x5B81AE4B7723971CULL,
		0x8A6BA1391FDEEB74ULL,
		0x6CFD896B4EADD6D6ULL,
		0x89AEACA7731884D1ULL
	}};
	t = -1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA6528472DE736605ULL,
		0xD48EB9898B652353ULL,
		0x3B61AA11F7D91117ULL,
		0xD68ED530BD6106CFULL,
		0x7690AF1A1BF9013CULL,
		0x755AD6EBCA5C1DE9ULL,
		0xDE7A7C4885502D03ULL,
		0xA0C6432901E98891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6528472DE736605ULL,
		0xD48EB9898B652353ULL,
		0x3B61AA11F7D91117ULL,
		0xD68ED530BD6106CFULL,
		0x7690AF1A1BF9013CULL,
		0x755AD6EBCA5C1DE9ULL,
		0xDE7A7C4885502D03ULL,
		0xA0C6432901E98891ULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x07663045C2592CFBULL,
		0x9001B2162B308636ULL,
		0x8C1613CCD6D65735ULL,
		0x4A95DF0F7CC0A41BULL,
		0xDA7750CC32C8626DULL,
		0x18177D5803D66AB5ULL,
		0x148D1D9E0C78D1F3ULL,
		0x5438D857481E63CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E9249A80D1888AULL,
		0x3DB642FC98666223ULL,
		0xAB8240299E78275AULL,
		0x5492CDEAB7AB7B87ULL,
		0x67F5709512F540B9ULL,
		0x1AA8C404C7ABFBA3ULL,
		0x39C1332DC0CD637EULL,
		0x2CB65E6E106243D8ULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE39D60F78EC6B909ULL,
		0xF72522703A65D738ULL,
		0x54391CFE6419C627ULL,
		0xAE953EAAEBAF94D3ULL,
		0x0BDDA81D2F447FBEULL,
		0x10988E03CE987DA4ULL,
		0x0E0B411920CC814AULL,
		0x8DD9D755C6616B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A257834C6E37CDULL,
		0x638E5FC39D4D0538ULL,
		0xB2F9FBC2A27D105CULL,
		0xE6D1577C3BF36DFFULL,
		0xE89E2BB382A03D77ULL,
		0xC217356F49528444ULL,
		0x1C44792A40C2308DULL,
		0x08C21BCC3A0A4146ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD707F48908ABB919ULL,
		0xF4643051AB62A831ULL,
		0xDC84C64674F94684ULL,
		0x13FDEB37B217BD3FULL,
		0x0DB3D95C775220E4ULL,
		0x4A5DCC43DFEEE536ULL,
		0x76876DA1DF38423AULL,
		0x6DB3770951835563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4289B72F7B700E3CULL,
		0x3279C256A711DC70ULL,
		0x21463009EAC04E9BULL,
		0xE16D26C4E2C0AD6FULL,
		0x5410F36BAAA92382ULL,
		0x50C1B088A1CBE471ULL,
		0x1E286201866F86B4ULL,
		0x36D77DCEE087DF0BULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD9C1E17A3F421357ULL,
		0x0895E825C24BAE78ULL,
		0xFF01C40B2272F5A5ULL,
		0xED90938C5C268C07ULL,
		0xFCE3D4C799F38B5AULL,
		0x1F4DBB427BE907D8ULL,
		0x7E994D7645643AEFULL,
		0x90DF74C497AFDDC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C1E17A3F421357ULL,
		0x0895E825C24BAE78ULL,
		0xFF01C40B2272F5A5ULL,
		0xED90938C5C268C07ULL,
		0xFCE3D4C799F38B5AULL,
		0x1F4DBB427BE907D8ULL,
		0x7E994D7645643AEFULL,
		0x90DF74C497AFDDC2ULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA99045E1AAE96AB7ULL,
		0x4DDFF3EB799FBCC3ULL,
		0x0BA9F3DEA83D2F79ULL,
		0x85FF9280D48AAA58ULL,
		0x5A3145E42EC22E1AULL,
		0x08E8B1B8974C8BD0ULL,
		0xA90299809C1FC694ULL,
		0x23169910712A941BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FD390357568C22ULL,
		0x99ED8DDCBEF3DE37ULL,
		0x0815AA853BF765C4ULL,
		0xC7CDE8773D5AA0F7ULL,
		0xC1C7C24065121531ULL,
		0x9C4DFA0A084390C9ULL,
		0xC76B1DD3966D2DB2ULL,
		0xE6237384ECB1259BULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x70DA8D4646EE778CULL,
		0x0F3868B96F504AA1ULL,
		0x1B994A5A5979D8DBULL,
		0x59C15154FB5DA1EAULL,
		0x5B6B7FF2ECA28E01ULL,
		0x56FA1698984489BBULL,
		0x21DC3261DDAA71CFULL,
		0xD9EF2A2BDCDDDB9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19B82FEB77C6A9F7ULL,
		0xC66B96B5BEA42DABULL,
		0x1AFE78A41E9E7B89ULL,
		0x1D4B37B2BCFFA3B3ULL,
		0xFB2519AB12C22070ULL,
		0x6D3D59987CACFBBAULL,
		0xE63A091F26774B8FULL,
		0xD12E02F1346B9BFBULL
	}};
	t = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x90812B2FF4F598DBULL,
		0x19B5D60B094CBC05ULL,
		0x6C9430C4CC62EF7DULL,
		0x60BB5FD4032FA1F0ULL,
		0x4A7DDC4126B23E12ULL,
		0x9F216B254990AA7EULL,
		0xAD0EB010122CB8A7ULL,
		0x7B6CDAB6B856EBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x127D324CC3BD504CULL,
		0xD007EB5FEFD4EB16ULL,
		0x8E1BB1EFC4442862ULL,
		0xB48BC6804E57550AULL,
		0x6083658E2F401F0EULL,
		0x373FABFFB8DDEB5AULL,
		0x78349D888B07BE80ULL,
		0x9F45B81A52CF9CD9ULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC43373EC84162F4FULL,
		0x6379B5EF5FC43059ULL,
		0x09943C8EE8621B18ULL,
		0xD3605F56EECD51EEULL,
		0x1827D7A0E9D58573ULL,
		0x81EAE99AD4863448ULL,
		0xFA86CB73EB47EE2AULL,
		0x1ACE2EB61A461A1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC43373EC84162F4FULL,
		0x6379B5EF5FC43059ULL,
		0x09943C8EE8621B18ULL,
		0xD3605F56EECD51EEULL,
		0x1827D7A0E9D58573ULL,
		0x81EAE99AD4863448ULL,
		0xFA86CB73EB47EE2AULL,
		0x1ACE2EB61A461A1EULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x83DD6C7A4D892B7EULL,
		0xBD3FFEEE4D5B402DULL,
		0x557EB03253437FE7ULL,
		0xBF0FA4D2716E7DA4ULL,
		0xC6B2FBAA6F55BBC4ULL,
		0x639402BF7A6DC719ULL,
		0x4C8CBB2F07864C27ULL,
		0x652A1B01549EE4FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12945653645B0769ULL,
		0xD978446D00514339ULL,
		0xC4771C8E08213A00ULL,
		0x7ED43F8ADC866649ULL,
		0xF26B61678504349BULL,
		0xC07F1BE64FD8526CULL,
		0x17DF88E647D922C6ULL,
		0x5FE94C1304CCCB9CULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD9F04F0AD9796F74ULL,
		0xFFE8455E35CBAEF5ULL,
		0xB1C3E519338F558AULL,
		0xD984CC7D1FA4BAC3ULL,
		0xB867822ACA08BAB1ULL,
		0xE8140CF5E6C9056AULL,
		0x831919702AD562C0ULL,
		0x10424EAF377FB565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F35D04BC2103167ULL,
		0x8EBF4CFE2716A6AAULL,
		0xA78D8CE8E03CB8E3ULL,
		0x93C2A6F357E6FA00ULL,
		0x03C9D9DF408F489BULL,
		0x78317BBD18911261ULL,
		0x2D4816339267F152ULL,
		0x6F238D4EBB6B362FULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0FE5DC25E0107DAAULL,
		0x043AFEBDFCC8CC36ULL,
		0x0AADBFEAA72C4564ULL,
		0x2F968E59B6A54E2EULL,
		0x5F192B4A29FCC1FCULL,
		0x64B3CCC0442B99AAULL,
		0xA545EDD41CEF0FA3ULL,
		0xB768E49AA43956D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4CF6C307339C918ULL,
		0xCE88BBFE421E2685ULL,
		0xDA659830D0F3BFFAULL,
		0x9A67309B6F7C7648ULL,
		0xEE9C24E2EB7EDD41ULL,
		0x63FC1BC08CE45E7AULL,
		0xB07459FD8882E991ULL,
		0x115AF179C9D27D68ULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCCA930E016EFCDAAULL,
		0x8B1546AE446E2FF2ULL,
		0x4D0D466B7D3D5DA1ULL,
		0x1A81D1B0FDC1FD86ULL,
		0x5FF965B1295E27DCULL,
		0x85D9BBA52B4DA26DULL,
		0x58ED503C0DA114B3ULL,
		0x050444790C7D682EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA930E016EFCDAAULL,
		0x8B1546AE446E2FF2ULL,
		0x4D0D466B7D3D5DA1ULL,
		0x1A81D1B0FDC1FD86ULL,
		0x5FF965B1295E27DCULL,
		0x85D9BBA52B4DA26DULL,
		0x58ED503C0DA114B3ULL,
		0x050444790C7D682EULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE8A12A24E04D5275ULL,
		0x290545E4F6F238FCULL,
		0xA1FFE3B1BF6B59DDULL,
		0x091FF195CE561F3AULL,
		0xAC45BCC1AB6C323BULL,
		0x00130AE8B2AFACC1ULL,
		0xCF538428E03E3A2BULL,
		0x45259E599C8E22DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA858D32DD20FAD2BULL,
		0xC81B71917A10296FULL,
		0xB290F27D3A4F1CEDULL,
		0x53C9EF6DC9425E01ULL,
		0x28C600DE55E87E67ULL,
		0x1535403AB4F65C7CULL,
		0x0FC2D9F47CD0B832ULL,
		0x8182D9A4EB498EBAULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9671730EE2E09973ULL,
		0x5C7A07759FDD7E7DULL,
		0x1AA409C07A3D3DE4ULL,
		0x312B238B2BB915AEULL,
		0x35E3BD46E9AA82C3ULL,
		0x2C28C858E6F63771ULL,
		0x8421B5D8635E126DULL,
		0x92F527AA7F04E051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x246E97E0F746D5F2ULL,
		0x966935711F53480DULL,
		0x87499294965CDF2CULL,
		0x2F89C94930E98F69ULL,
		0xA4FED05A0EAF2868ULL,
		0xB8F7AF8730B43490ULL,
		0x093813F33A21434BULL,
		0x09F79ECDEDB1609DULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA68BCB66C8A79059ULL,
		0x9DE8C101C6243781ULL,
		0x1D332CFB58CFF1EBULL,
		0x8B5E3793B47078CFULL,
		0x0822048E73DE6373ULL,
		0x5FF4135612059D0BULL,
		0x7D882D18336C089EULL,
		0x705BEE09FAE93B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F796B52C4A10B5ULL,
		0x1BDF0420BFA2597EULL,
		0x4E39A9285B832CA6ULL,
		0xEE1E5929541BC6C5ULL,
		0x8451B49B46E4BE6BULL,
		0xF8467400B537C0F7ULL,
		0x970BD10A366BBDB2ULL,
		0x74EFF3D958461051ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE28CE64FFF33E171ULL,
		0xAD2FF27E896AA405ULL,
		0x6F5DED1A93E44F6AULL,
		0x713E1CDA37501B11ULL,
		0x5511C4C57B4B2C49ULL,
		0xE9535EB5B5CCE664ULL,
		0x8436687D8C494497ULL,
		0x999AFF8F7E2ED9F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE28CE64FFF33E171ULL,
		0xAD2FF27E896AA405ULL,
		0x6F5DED1A93E44F6AULL,
		0x713E1CDA37501B11ULL,
		0x5511C4C57B4B2C49ULL,
		0xE9535EB5B5CCE664ULL,
		0x8436687D8C494497ULL,
		0x999AFF8F7E2ED9F9ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x233B82C4E9A7DAF5ULL,
		0xE779D7E2E41EE8D9ULL,
		0x52D9509C94EA796DULL,
		0x9EA6B06C607076DFULL,
		0x96895D4D5196C59FULL,
		0xFC9C42E24D4E9CCCULL,
		0x24FB7B87C492B6D6ULL,
		0x76BC9A67D7AF2F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A8C961628669DEEULL,
		0x0C4E44CE88822474ULL,
		0x5DCF066E6950A102ULL,
		0x41636141E13ED473ULL,
		0xE2BEB01FC58FC492ULL,
		0xAFC02FA92973CFDEULL,
		0x7D5E7FE86E671E85ULL,
		0x95B30D0DF1190E12ULL
	}};
	t = -1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x06DDD46B625015D4ULL,
		0x9FCDBDD89DB97396ULL,
		0x65A75E5BD7878567ULL,
		0x6AB5F551406A8894ULL,
		0xBFCD9C5DBD698181ULL,
		0x351D3EA9564B5519ULL,
		0x769CDEF8FB442484ULL,
		0x7CC1DF5FE35E44D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70D78F3784A01722ULL,
		0xA13822774692803EULL,
		0xD777A8391C5F2680ULL,
		0xB8A1FACB414CB5AAULL,
		0x32AD6649B2154610ULL,
		0x80A723D4464F9CE7ULL,
		0x91BB40C2B3286F7FULL,
		0x9C82D136576F6262ULL
	}};
	t = -1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4A84A217759ED79ULL,
		0x22666E679881E0DFULL,
		0x658EF9CA7EAF021DULL,
		0xF01E5CADFCCD6542ULL,
		0x28993745B2707EA8ULL,
		0xEDA2A44CA539DE75ULL,
		0x4C6BD4D84D071638ULL,
		0x622F11C2487A2A1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE58F65AA45626EEULL,
		0x6307C3429FBA5BB3ULL,
		0x58F4045BA913282BULL,
		0x46E01F597A8DD4C1ULL,
		0x5B9EE115484E8D1AULL,
		0x78A0EC5A48359EF3ULL,
		0x4ABB4F72CB7FAF1AULL,
		0xEDBB1570D05231B4ULL
	}};
	t = -1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD5404A55245DC325ULL,
		0xE4C4B1D9494853C9ULL,
		0x8295F75278F3EF23ULL,
		0xF75C0D06CA13FF46ULL,
		0xCC3B7A7F5C274EB8ULL,
		0x3252C2F66A4529E0ULL,
		0xCACEDE5F09305CF4ULL,
		0x4A78990EC307675AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5404A55245DC325ULL,
		0xE4C4B1D9494853C9ULL,
		0x8295F75278F3EF23ULL,
		0xF75C0D06CA13FF46ULL,
		0xCC3B7A7F5C274EB8ULL,
		0x3252C2F66A4529E0ULL,
		0xCACEDE5F09305CF4ULL,
		0x4A78990EC307675AULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1D3948F2A10E4137ULL,
		0xE7EDA95243785EDBULL,
		0x251E17F27D9DB998ULL,
		0x4CC146107CF052B0ULL,
		0x56C6DF95CE44D04CULL,
		0x21CD683C83A192B7ULL,
		0x926F79B7A383A679ULL,
		0xDD3C89E0FB2C72B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6246E89D96EDFCAULL,
		0x3268636964DE0CF5ULL,
		0x5BBD5763754C7B50ULL,
		0x41BFE923DDE5199CULL,
		0xBE685E01BD62A4A2ULL,
		0xDF68F1ACA2F68644ULL,
		0xEA185B30E6076569ULL,
		0xD9E35C50747B4E75ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB74FDFD720916B8CULL,
		0x5DFB39AF89A8D54AULL,
		0xB315FB8CAC55AA26ULL,
		0x5B677F670435B55BULL,
		0x3EEAC028E056AB21ULL,
		0xE48D8EF0EA3200F4ULL,
		0x64A3D64073D1DCE6ULL,
		0xDECF82AFCFBD93F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4F8ED06AB39872ULL,
		0xD8CF3980F7639963ULL,
		0x2AE20D3A724B5BE0ULL,
		0x9BAC4E35DFBC6795ULL,
		0x19E278D461C19687ULL,
		0x73C22191AFA04665ULL,
		0x97A9DD58A08205AFULL,
		0x83EBA0A25D1CD224ULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1F5C43040D46651FULL,
		0xB5A319C2C946DE9EULL,
		0x8C349B821A4A6F91ULL,
		0xF93FE0BA6EE89B31ULL,
		0xA65B005908AE9F72ULL,
		0x5BC457204FC94F4AULL,
		0x29DFDCAD52C6DB2EULL,
		0x047D18233E4EB79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D73BF898046BF7ULL,
		0x377CBCB153640743ULL,
		0xB0A0C525757C5DA7ULL,
		0x3D9E03F0BC73ECD2ULL,
		0x6A6B4E7B046E739EULL,
		0xCDDC7F627BD6E72CULL,
		0x028D017347CF6BF6ULL,
		0xD00B5C0461256AA0ULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4C6624C2A397F997ULL,
		0x57355D014CD641B3ULL,
		0x30B6CC0D13652DF6ULL,
		0xD5C1F473D0E32293ULL,
		0x0A7D4C2BC9CFD2DAULL,
		0x625C596F2D4F430BULL,
		0x985093FEFE384B97ULL,
		0xAB0B3EE503C61902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C6624C2A397F997ULL,
		0x57355D014CD641B3ULL,
		0x30B6CC0D13652DF6ULL,
		0xD5C1F473D0E32293ULL,
		0x0A7D4C2BC9CFD2DAULL,
		0x625C596F2D4F430BULL,
		0x985093FEFE384B97ULL,
		0xAB0B3EE503C61902ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6F2744D1890826CAULL,
		0xA8BA2BFB350EB931ULL,
		0xEE9E70CF5EC5362DULL,
		0x6C9190D876B7DF0DULL,
		0x33589C3DCAE8A0D0ULL,
		0x9DDAF0B03D2ABF33ULL,
		0xC9E32521B875FEBEULL,
		0x97FE21712C0049A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEFB06424CC2119EULL,
		0xBF07FFC9481A9A12ULL,
		0x309CEA2ABF343791ULL,
		0xF921F842515621B7ULL,
		0x58AB59CF925045E4ULL,
		0x5871569BDD827ED9ULL,
		0xF1334F2CF80C4C6AULL,
		0x69BDD710F6D6A460ULL
	}};
	t = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC97D44679CD3C353ULL,
		0xDD522525C6467DD0ULL,
		0xBBFADA0EDC8E9AACULL,
		0xB776120BEE73FD12ULL,
		0x4B873E987B5C354FULL,
		0x180024F40FF5D7FCULL,
		0x0B13F38645203023ULL,
		0x142CAB0163566565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ABB640160703999ULL,
		0xB153A194F384C41BULL,
		0x4E4606D850AF411EULL,
		0x3B20AFB18229F13DULL,
		0xE8BC7D891A1A1346ULL,
		0x34EC106D3DDC6BE9ULL,
		0x6A9E8CADA3E7E662ULL,
		0x23D12DA0C9379B49ULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x847F8147BA7629A1ULL,
		0x706B0517C6D070CCULL,
		0xF5D0655F5B9DB9AEULL,
		0x90531C9A6D0C6244ULL,
		0x3BD1AE2EDB8F35FFULL,
		0xF044A8294CD4494BULL,
		0x35A80A93D524535BULL,
		0x0B1D338F2CEC6A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7093FCD9E890EF19ULL,
		0x84304F8423C79524ULL,
		0x4BC31CF7038089D2ULL,
		0x8F9E7B97D73C46AAULL,
		0x6D29D961EB6FE9B7ULL,
		0x8F0E1B248F6EB729ULL,
		0xEBC8E52EAF774FB8ULL,
		0xBC6EB34FA9EC2ED0ULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3045951604BAFB04ULL,
		0xE79FDD6424331733ULL,
		0xD40398B4082272FEULL,
		0xDDD2A53F0D59CD6DULL,
		0xEA0E4D6E1780F5A6ULL,
		0x924AF80B43AC2543ULL,
		0x94A25274AD92DAB0ULL,
		0xB26217C6D8BA14F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3045951604BAFB04ULL,
		0xE79FDD6424331733ULL,
		0xD40398B4082272FEULL,
		0xDDD2A53F0D59CD6DULL,
		0xEA0E4D6E1780F5A6ULL,
		0x924AF80B43AC2543ULL,
		0x94A25274AD92DAB0ULL,
		0xB26217C6D8BA14F4ULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x975ABE6B12A0A4ACULL,
		0xD01C1EE2B91351B5ULL,
		0x5F739048BF9A0FEBULL,
		0xAC3C01187AC40DBFULL,
		0x96B5D5B6F6971952ULL,
		0xC529A2AFD8FE963DULL,
		0x390F58AC7B24A6DAULL,
		0x793F3A4831434E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0106E517AF048592ULL,
		0x08FE5415448F6524ULL,
		0x2F446C365293D45AULL,
		0xD4311AA7D7AD971FULL,
		0x14792A41D4B81D3CULL,
		0xCE33E148C60DAB6CULL,
		0x035E48CE651196B3ULL,
		0x7FEA6A442F141E3BULL
	}};
	t = -1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x696CF14FE3ED9743ULL,
		0x5FDEDD86743A5EBEULL,
		0x172BC2B99C7D04C0ULL,
		0xFFABD6B5E8BA6F45ULL,
		0x922ECA2B116CEC4BULL,
		0x45DAE3432D132B29ULL,
		0xDFDBFA74B17AA628ULL,
		0xFF306E4D80135E5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528C416129BD9312ULL,
		0xFC7698359121DB24ULL,
		0x6547FAC8F4BB9C43ULL,
		0x17D8600FEEBD7056ULL,
		0x0FFC2C61431F468CULL,
		0x71301BCC18D94C1EULL,
		0xF522FBF7D74F5779ULL,
		0x6E892B857D5A67E3ULL
	}};
	t = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8DEA4A12992AEFDBULL,
		0x4A0C449501FFEC1EULL,
		0xF0B4B6864D762887ULL,
		0x4D04F7688CCB5AF3ULL,
		0x990C3F23CC2C4579ULL,
		0x47370109245BA60DULL,
		0x1D70281F03DCE8D5ULL,
		0xFE5A9FEDC2805F1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x615D3FDF234E6FF2ULL,
		0x6D1C671C610BD248ULL,
		0x7A6A116D0CF4E512ULL,
		0x3D0DDD2C817510A9ULL,
		0xC79D5008CF117169ULL,
		0xECE2925CD8171DFEULL,
		0x536818402C78FEBEULL,
		0x0F7662C5EE00CBA2ULL
	}};
	t = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1566C0113ABA90F1ULL,
		0x1BBE9E821BD839A3ULL,
		0x64D28EB72B506206ULL,
		0xDA27CFECE2DBB09EULL,
		0x44E1FC6FCBA26B0DULL,
		0xA7CE4091E3934298ULL,
		0x13E6E6F5189FEF3CULL,
		0xE699EF1B625A0ED0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1566C0113ABA90F1ULL,
		0x1BBE9E821BD839A3ULL,
		0x64D28EB72B506206ULL,
		0xDA27CFECE2DBB09EULL,
		0x44E1FC6FCBA26B0DULL,
		0xA7CE4091E3934298ULL,
		0x13E6E6F5189FEF3CULL,
		0xE699EF1B625A0ED0ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBEB6F54D77E6AB8DULL,
		0xE7AE9C7A6D453225ULL,
		0x1BF69D9D26B4D1F0ULL,
		0xA4EA0132CAE198C6ULL,
		0x13888A8CE07AD059ULL,
		0xC7C2DD223A363B69ULL,
		0x97E6E685CFD5738EULL,
		0x2F87FFE67F4230C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x234D6C6F104F7A98ULL,
		0x03A91D53E5C1A78FULL,
		0x31CDFE607CF31267ULL,
		0x006FD47360F38715ULL,
		0x46762305B1C539EEULL,
		0x92D4CDE111489002ULL,
		0x2A5075C288274E8EULL,
		0x6C315C0F4EC3EAADULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3C2855A23167C9EEULL,
		0x2C067DA0191266ECULL,
		0xE2D8CCA70D2DFE79ULL,
		0x90B79B0CA6F7D925ULL,
		0x54EEA86B7F939774ULL,
		0x117A242A28FC9EECULL,
		0xEBAD4464CE60D6DCULL,
		0x70D3B71E48B6B104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF6709E1EFB156CULL,
		0xF47B6FCF868D5F16ULL,
		0x3F1C3972BD72C2F3ULL,
		0xFC533DAD0281E0C3ULL,
		0x6D6CC47B25BCF0E2ULL,
		0x2DC0EB7E18938188ULL,
		0xBFC0A15456A1D23EULL,
		0x9AB906D8B8C6CA19ULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x444FDE3A200C9B32ULL,
		0xCC75CA22C6F3EC0AULL,
		0x78B0430CFA9AE63AULL,
		0x89BD490FD25915B5ULL,
		0x3BFC850514784072ULL,
		0x7797A699732EF036ULL,
		0xC01D6AF7322EF397ULL,
		0x4F5D79650B8ED872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395DAF274A17760AULL,
		0x41EE148CC2D3A321ULL,
		0x0A926531A3177C38ULL,
		0x17E4694C1F47DE69ULL,
		0xCB989BFA358C9A9AULL,
		0x2F712D59D386D099ULL,
		0x253E28E106697816ULL,
		0x6E03DD03E96FEC7BULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD316BE84D0EF7218ULL,
		0x902144F9C4BCEF36ULL,
		0xA5CD7AD5D3ADAE61ULL,
		0x2A0B0B4878245281ULL,
		0x14C5A5CA98E43120ULL,
		0x30BACE0C34D39874ULL,
		0xF5681AD5652F5641ULL,
		0x6070549971EA2813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD316BE84D0EF7218ULL,
		0x902144F9C4BCEF36ULL,
		0xA5CD7AD5D3ADAE61ULL,
		0x2A0B0B4878245281ULL,
		0x14C5A5CA98E43120ULL,
		0x30BACE0C34D39874ULL,
		0xF5681AD5652F5641ULL,
		0x6070549971EA2813ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE5D83AA23C88D168ULL,
		0x262AAE193BE7D8A0ULL,
		0x258DE48471161A9FULL,
		0x9F2EA2AC92EB3207ULL,
		0x88CBF51830E2A313ULL,
		0xAE45D146B757F2E6ULL,
		0x979289A30CEB054CULL,
		0xB950F282CC916D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB974133326B05BC0ULL,
		0x2338BD399D3B4653ULL,
		0x4F5054365183AEBBULL,
		0x6E497952282B27DCULL,
		0x2CF7350810F057F2ULL,
		0x983D9D6705B851A9ULL,
		0x21AD7DC0F240D228ULL,
		0x5E576EBA8031FE7BULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD150B5E5C436ABFAULL,
		0x407FD9CC3803177BULL,
		0x39C239E4745516C6ULL,
		0xE0D466ACDE049326ULL,
		0xD543D72B2D880C38ULL,
		0xB785370971F224EBULL,
		0x49CF9FBDA6E77EC6ULL,
		0x9DB6EB91D18B5A2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8395B1E58EF388F3ULL,
		0x28EE8E41FF8C9167ULL,
		0xE9F4B4469B0A795EULL,
		0xE9462D2D6364A91EULL,
		0xD41A47E6C97CDBD9ULL,
		0x3B9167FC54E0148CULL,
		0xA1A91E93DB68C454ULL,
		0x17BDAB72B6677019ULL
	}};
	t = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF352C79864D8D703ULL,
		0x9A24DAF1A2B031FCULL,
		0x1DF5641E2DFFD042ULL,
		0x10BB432FE9326C4AULL,
		0xAC837E82A13F92F6ULL,
		0x8D177F684FA401C9ULL,
		0x2BA2326DD92B0392ULL,
		0xB9144F3331D106F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EBC870A6B6AEBC1ULL,
		0x6CFE2BD913B49F56ULL,
		0x4F0BAD48B207E665ULL,
		0xF3FCF50136BFDBB8ULL,
		0x81E1C1BFBFF6FA7FULL,
		0x6F49A28794C466BCULL,
		0x9CF238F04B059170ULL,
		0x08CF02B1D7569D33ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2762F5C5FF5D3675ULL,
		0x3CC4BF0564E6F863ULL,
		0x110508315BF2A513ULL,
		0xD75BC96A7F4E35B3ULL,
		0x9EC9813DDC1DA906ULL,
		0xCC1530DF92C0713FULL,
		0xCD1F48E36CDACE38ULL,
		0x18065A0E5D967DEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2762F5C5FF5D3675ULL,
		0x3CC4BF0564E6F863ULL,
		0x110508315BF2A513ULL,
		0xD75BC96A7F4E35B3ULL,
		0x9EC9813DDC1DA906ULL,
		0xCC1530DF92C0713FULL,
		0xCD1F48E36CDACE38ULL,
		0x18065A0E5D967DEFULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5154972909CFC5ECULL,
		0xC481E756027B2CA4ULL,
		0x31CBE2E889486C75ULL,
		0x41DD0171C7FD3FB1ULL,
		0x7202A724BC0F7256ULL,
		0x853A3FAA8BE93629ULL,
		0xF9097BE4F5100806ULL,
		0x0B9FEB3EB311B1A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF652AD2DC724620DULL,
		0x7DA5A1E25B883EE0ULL,
		0xC5FA8060D6CB197CULL,
		0x446B2D66DAB0686BULL,
		0xCB8906F46F38FB7BULL,
		0x64BFD1627D5992C6ULL,
		0x33685E78DB108319ULL,
		0x46BAF79E869D8B6EULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB02CC3F73482E2ACULL,
		0x0D62BA19D038DF61ULL,
		0x7579F455B5C68119ULL,
		0xC33532EAC4C4C9E1ULL,
		0x972DA627167D9BA0ULL,
		0x464DD6B1BF59F70FULL,
		0x5E573450BD66747AULL,
		0x4AC31A4295599F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAFE83892C58B206ULL,
		0x9667C01EF6E33096ULL,
		0x887024451E932E1AULL,
		0x88FE4C2E4F713058ULL,
		0x9212AA29BF5C8D65ULL,
		0x6F38AE387BADD3BFULL,
		0x2F844694C1BB469FULL,
		0x260C2B749C40C00BULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x60A9A347EC76DC35ULL,
		0x0E7D3EC9BD433DADULL,
		0xF3A2160BE1897991ULL,
		0x6F6B5243D19333ABULL,
		0xB5532A17831FF724ULL,
		0x4210769BAF3A9504ULL,
		0x0410F55E7837F9A0ULL,
		0x8736AAB9BD5C4CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C202B11D739B00ULL,
		0x0FB6F03439B590F4ULL,
		0x88C52D0CA307D781ULL,
		0x8BAEBE62377F88C5ULL,
		0xC48FDF442CE3EC3EULL,
		0xF0AA02D4575CC720ULL,
		0x9C00911A0C398B99ULL,
		0x4F18E8F51C7C6B67ULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD3FA2C02AF00B942ULL,
		0x27E7AE5B91A0AD14ULL,
		0x5F776AD9493687DEULL,
		0x51082A65A9672750ULL,
		0x099D9E842323CAD6ULL,
		0xE3055ED7DC6D4FB8ULL,
		0x55886CB5759ADCBFULL,
		0xD7D8F399D53BADE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3FA2C02AF00B942ULL,
		0x27E7AE5B91A0AD14ULL,
		0x5F776AD9493687DEULL,
		0x51082A65A9672750ULL,
		0x099D9E842323CAD6ULL,
		0xE3055ED7DC6D4FB8ULL,
		0x55886CB5759ADCBFULL,
		0xD7D8F399D53BADE1ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5B0C5CF762F051A0ULL,
		0x28345C9D136495F2ULL,
		0x3550765E69A81CD4ULL,
		0x23FEBADDAD9F0131ULL,
		0xAEEC32C942BB0CC1ULL,
		0xF911ED23A60203D3ULL,
		0xA21E09BA1D4A0499ULL,
		0x2A6F9617BC3CAE98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84BD8C495FFAF865ULL,
		0xE1E051792D8BF2E6ULL,
		0xD9745A1E4AE4C5C1ULL,
		0xB505D658AD3D1017ULL,
		0x63B6636A0DA1272FULL,
		0x362B59308FECCDB4ULL,
		0x617A9E7BE36BE21BULL,
		0xFDEE493E4072FBC8ULL
	}};
	t = -1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x08EB1F47070587AFULL,
		0x4395CC439811EB30ULL,
		0x87F19DB72EE18A10ULL,
		0x26D57D219C1F22CAULL,
		0xABB96B27B25DD0EEULL,
		0x231A51F23482110AULL,
		0xF90B6CA95D24096EULL,
		0x4A0ABC8DD0657AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013AA33A03AE290BULL,
		0x659E4F984F254A30ULL,
		0x9D79E1A61A89779BULL,
		0x7F4511BBD0BB6C46ULL,
		0x9F82C14891BF7E08ULL,
		0x4E38F185A7657372ULL,
		0x23F302026019A67DULL,
		0xB6FF7C99CEC74240ULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEA3A09C2E52ECBB9ULL,
		0xB2E3986F82FD3779ULL,
		0xC376DAE647B0C564ULL,
		0x7538146A83B4EEA7ULL,
		0x2FD001FD3CEDACB2ULL,
		0x925FEC7D3B7533ABULL,
		0x5C309F6979AB9E4BULL,
		0xED1DBF75E25C88A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF69F9C9B3EB84BDULL,
		0xD06FF6500C4251CFULL,
		0x94D7057C9CFC4B7AULL,
		0x9302607F30719D56ULL,
		0xD64B00B771E49918ULL,
		0x09640093B23A4D2FULL,
		0xFB3A3A6382F8F994ULL,
		0x0EEA76688C3BF43BULL
	}};
	t = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x76B1B63D162340B0ULL,
		0xE9EF8DB0092D32E9ULL,
		0xEE348EC1BF7619AEULL,
		0xFC659C6CE7ECB7BBULL,
		0x93B0FFE3E85B828CULL,
		0x9AD4BEC99CF68BF3ULL,
		0x6B390FAD59FF90DEULL,
		0xCAE4E48D2966A49EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B1B63D162340B0ULL,
		0xE9EF8DB0092D32E9ULL,
		0xEE348EC1BF7619AEULL,
		0xFC659C6CE7ECB7BBULL,
		0x93B0FFE3E85B828CULL,
		0x9AD4BEC99CF68BF3ULL,
		0x6B390FAD59FF90DEULL,
		0xCAE4E48D2966A49EULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC384D4A2C016458CULL,
		0x2A91ED9EFE8A2F4EULL,
		0x1264D6C5AE607B1EULL,
		0x284363B86787AAFCULL,
		0x021EF9A9B18DF24EULL,
		0xE32DE986D4323A00ULL,
		0xE83140E369934C8DULL,
		0x591123F2405D806AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB37F0E57C6D622FAULL,
		0x7894B6539115A086ULL,
		0x03E98AE8F118CB40ULL,
		0x5E1B4E305D5573BDULL,
		0xA4FE76844DED4A72ULL,
		0xBC0ED50AA6BE13E4ULL,
		0x2B6A4C63F4A2E08DULL,
		0x3C5AC819F290E1D2ULL
	}};
	t = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1A749279953DE712ULL,
		0x090D99D49808CA28ULL,
		0x9FB419E55601CE28ULL,
		0xA25927C98C3AA5ADULL,
		0xDDE59DA2A7BCA40AULL,
		0xF05872201954F945ULL,
		0xCC28BCDA4A177B59ULL,
		0x2FAB1986819222E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x479E6928E67FA171ULL,
		0x60A93852756DB8A4ULL,
		0xCA6240A15145BF0CULL,
		0x5445CDE8098B7EA6ULL,
		0xA733CAD254D69BF1ULL,
		0xA57FB2C8C91BC2E4ULL,
		0x20FC759EC1F26C33ULL,
		0xB41EFE409C73751FULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x44944D910696447BULL,
		0x413BF772EED0CA6AULL,
		0xC1464CC856B2733DULL,
		0x4E82D072CA86C14BULL,
		0x4FD02852EF565267ULL,
		0xE037982936242BBCULL,
		0xBF5486DFDE8766B4ULL,
		0x969F699B79D5DB9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3553E014A690380DULL,
		0x0ECB2EF6A22BB0EAULL,
		0xF06302434C066AB0ULL,
		0x2EFA3E2AFA13E6AAULL,
		0x3BE44AD3FD68B8C5ULL,
		0x010B9601DB7E8AD2ULL,
		0x3AA17E262B457046ULL,
		0x6638A2B8C484B876ULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3E914789B5CF593EULL,
		0x1587B394E034B209ULL,
		0x189C371CF5E485AFULL,
		0x83AD6739691F6742ULL,
		0x3F008223E244DF2CULL,
		0xA60F9139FFB55354ULL,
		0xCF8A8FA67A678CE9ULL,
		0xB6BE48EB84967B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E914789B5CF593EULL,
		0x1587B394E034B209ULL,
		0x189C371CF5E485AFULL,
		0x83AD6739691F6742ULL,
		0x3F008223E244DF2CULL,
		0xA60F9139FFB55354ULL,
		0xCF8A8FA67A678CE9ULL,
		0xB6BE48EB84967B15ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7CD5265EEEF122C7ULL,
		0xBD3D8E0532836D30ULL,
		0x624DA73A5F69D76EULL,
		0xA8F1B1D2B78DD638ULL,
		0xF400B3ACAC76AA1AULL,
		0x8022BEBB4988475CULL,
		0x01D350D91FCE2C11ULL,
		0x4ED577C05FDD58CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9DBB9A5E5356EF2ULL,
		0x07D14F4451B18973ULL,
		0x44D294813E72F2A0ULL,
		0x72DE8DC64577F072ULL,
		0xF51EEECFC5A0FD38ULL,
		0xAC2987869BEAF0E3ULL,
		0x971993F099B0AB0AULL,
		0x65901AF68CB35C32ULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBB21386A41C0137FULL,
		0x454CDCB6A8E1137FULL,
		0xEB4230AE6C913E72ULL,
		0x02E23CFFF3F1D07EULL,
		0x86FB906B53F2D957ULL,
		0x0F67F3521436A8E7ULL,
		0xD739A7E50DBCB27DULL,
		0xF20E4C33DD467200ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C7DE53CA522FBB0ULL,
		0x4C21F201DED7F791ULL,
		0xD9369CC3FCBC46E5ULL,
		0x414ED2E95E3CED3DULL,
		0xF4E612049CE0EB45ULL,
		0xEDDB51D0F1F12D34ULL,
		0x0BFCDF1FFA639AC5ULL,
		0xAF0A416F4E335DD6ULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB748A3242A2757D5ULL,
		0xC6E785291F6FB8FBULL,
		0x26A3F2B3E6AC8774ULL,
		0x20082718266125AFULL,
		0xC8EFF394CF52C5BDULL,
		0xA7FDAD5CF5FF5DB0ULL,
		0x53F659AEF6753850ULL,
		0x18EEDE6DC30D56B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E1CBB84EA7F084ULL,
		0xF5CE1EA28A499A5DULL,
		0x58CABDEE79789C4BULL,
		0x8D0CC7BA03739333ULL,
		0x0468FC6D4E7B119DULL,
		0x6CEE75D4246666F2ULL,
		0x2789CD69F0779146ULL,
		0x34480062DD0D7635ULL
	}};
	t = -1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x950A6A5336E003BDULL,
		0x1E36F666F2C81E0DULL,
		0x6352CF407B75462FULL,
		0x2904175BE06D7E57ULL,
		0x5A8724599EEBDBF4ULL,
		0x6BCA08095D6EA646ULL,
		0xDBF592D4AECC13EBULL,
		0xBEE3C22B437E6474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x950A6A5336E003BDULL,
		0x1E36F666F2C81E0DULL,
		0x6352CF407B75462FULL,
		0x2904175BE06D7E57ULL,
		0x5A8724599EEBDBF4ULL,
		0x6BCA08095D6EA646ULL,
		0xDBF592D4AECC13EBULL,
		0xBEE3C22B437E6474ULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3B17D3340693002AULL,
		0x93A5FA50DD83F754ULL,
		0x79EA113B03BCCF7AULL,
		0xE518BA89A80930F5ULL,
		0x0697BEA5A9C7736AULL,
		0x380D0DF333F2535EULL,
		0x462B3C61234B501CULL,
		0xCC54DF3BC8277C21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7345EE293E135985ULL,
		0xB633644BF7429F95ULL,
		0xC526CF25F3C23AF5ULL,
		0xEEC5C7C1C1F53B09ULL,
		0x789D7B682127B78DULL,
		0x2D6853E1D6BD5822ULL,
		0x33157A80D298B596ULL,
		0xCCEF1E5A2623C961ULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7DA63B288216D5A4ULL,
		0x69B4157D441249B7ULL,
		0x46B43C195B8FF4C3ULL,
		0x76D0BB2F318268ABULL,
		0x04C39F00D3749C7DULL,
		0xDBAB079F13CBE2E5ULL,
		0x252A34F68A289E10ULL,
		0x155BCB508879857DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F1C57CD204E8DBFULL,
		0x6B5F5EE93224F7C0ULL,
		0x4463A3FB1CE12309ULL,
		0x3F807204CA81096DULL,
		0x1CC9DE0C3C552656ULL,
		0x18DEBA0DF9FA8CBCULL,
		0xC2B409A04F019FA1ULL,
		0x71147A9FE8DCC14FULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x848F7C2028F623A1ULL,
		0x1E9C45EF57BE8F2AULL,
		0xA399807D2A00D249ULL,
		0x1D01997DA687792BULL,
		0xF5485BFF38952770ULL,
		0x1A5EA627E551E3B2ULL,
		0x432C7662AA0BDE0CULL,
		0xD8AFFF15348521C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBCA9102DE9B411EULL,
		0x877E227678FB2292ULL,
		0xD14B3C2EC4ED43DCULL,
		0x20FA7524B44F8C20ULL,
		0x17339F55748B3F13ULL,
		0xD0256DDCE33EBB19ULL,
		0xE54B384BFEB2477BULL,
		0x5B24BDA1EBBB0959ULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC426E4A82BCB93A8ULL,
		0x1A458AB432E09E76ULL,
		0xAD0420F95767908EULL,
		0x9EFA016868E948C0ULL,
		0xB47087D3C4408077ULL,
		0x1968802BAFF08CFFULL,
		0x15DF9097536CD949ULL,
		0x2B9C0A2A76EFC4D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC426E4A82BCB93A8ULL,
		0x1A458AB432E09E76ULL,
		0xAD0420F95767908EULL,
		0x9EFA016868E948C0ULL,
		0xB47087D3C4408077ULL,
		0x1968802BAFF08CFFULL,
		0x15DF9097536CD949ULL,
		0x2B9C0A2A76EFC4D2ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD0A28AFE5523322BULL,
		0x92C155113E9F06F9ULL,
		0xF455EFB85CA6C9CDULL,
		0x11185C0AF3F67226ULL,
		0xD2DCAFB404CB94C7ULL,
		0x8F77E1D86F16F2E4ULL,
		0x3EEDB23C4D27A34DULL,
		0xBB7E890BF68EB230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0131496AA820B2DDULL,
		0xAC63B7D4FD9AB67FULL,
		0x1624588CE6349EA2ULL,
		0x9C626944947DB98CULL,
		0xDB86347F1026C338ULL,
		0xD8066A64BD879383ULL,
		0x5FF42AB0C4F30BEAULL,
		0xD761890D7BDB19E0ULL
	}};
	t = -1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x478990AF0E64CD62ULL,
		0xDD9993652377043AULL,
		0x50EE5BD96C6CA281ULL,
		0x365ECE9130897EB3ULL,
		0x191F4C9383B640A9ULL,
		0xAF3B7A9F1956DB7DULL,
		0x50B363AE2722939DULL,
		0x1469EE0AA396A0FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28962D25C599D8C3ULL,
		0x141F1A13ED9F281AULL,
		0x5B617C3045453669ULL,
		0xD72704EDB6C5EEECULL,
		0xC03CCC057AB34611ULL,
		0x9CF99FABC9DE1508ULL,
		0x8DA500F9971CB61DULL,
		0x62616EED394DAD4FULL
	}};
	t = -1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAE4674A255DF5D35ULL,
		0x17AE1F01530F341FULL,
		0x970C0C8B53F4CEE1ULL,
		0x661C5ADD12500795ULL,
		0x329F6F43F516E51EULL,
		0x8F19FCACFAA4231CULL,
		0x2DCE21763ABDADD6ULL,
		0xA511845894BDD817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C10457AEF8EF507ULL,
		0xC252FA73506B537CULL,
		0x4EFA83219BE07DA2ULL,
		0xD77A5C1FAF268E21ULL,
		0x53B2AFE497AC703EULL,
		0xE7449FB928F479F9ULL,
		0x151AC33D4240256DULL,
		0x958BA1B21C461197ULL
	}};
	t = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x35E56304C32DE073ULL,
		0xA325855EE7FD0FD0ULL,
		0x5FD5E05207BF8E12ULL,
		0xDC4C86E142BBDDB1ULL,
		0x912A0ED72E16A5D0ULL,
		0x3AF5351590BB9D64ULL,
		0x3DEE67FD7998D3BEULL,
		0x05BBB35383534260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35E56304C32DE073ULL,
		0xA325855EE7FD0FD0ULL,
		0x5FD5E05207BF8E12ULL,
		0xDC4C86E142BBDDB1ULL,
		0x912A0ED72E16A5D0ULL,
		0x3AF5351590BB9D64ULL,
		0x3DEE67FD7998D3BEULL,
		0x05BBB35383534260ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1D655A72EBB716D2ULL,
		0x73CF0B272B82A608ULL,
		0xCF1577936BC9ED1BULL,
		0xE799AD6C0A18945AULL,
		0x4B88E587670B9D3CULL,
		0xBF5B7A5656B6E0A2ULL,
		0xFAE20D0CE4C7CD53ULL,
		0x03C366DD24D53222ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FD1CA44275712DEULL,
		0x902E0973B0D225E1ULL,
		0x8282084F900957A4ULL,
		0xBE761C99A118F332ULL,
		0x6A95F2B4BE876DE6ULL,
		0x56941A35250DC074ULL,
		0x3234FDE1AFBC4364ULL,
		0x3E64EF083328C637ULL
	}};
	t = -1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDEEFE936E4840C96ULL,
		0x22212081CF2E63AEULL,
		0x5BEEED43113F8630ULL,
		0x3814423F3E7CD262ULL,
		0x6047ED0EDD4711D7ULL,
		0x88EFE8935BEA0C4BULL,
		0x0B19E9D1D2D93FADULL,
		0xE3C75CCF5C6F83F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC8AE1A2D7B81BE1ULL,
		0x04DCE8827F84CC3DULL,
		0x9ACCB8F32D003824ULL,
		0x4E0425ABA27EB3EDULL,
		0x5BB274E4A826D278ULL,
		0x327913B6CA804606ULL,
		0x0F2CF445F618DA6DULL,
		0x8A2B6AF761CF8F3FULL
	}};
	t = 1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0EF0D9EDB9063BD8ULL,
		0x98E1C650FDFB45F3ULL,
		0x54A9BD517475162DULL,
		0xC50C7DA99422C692ULL,
		0x412DCF860C129C76ULL,
		0xBFF9B38CFD972174ULL,
		0x0637E9D49F3F694CULL,
		0x35B9BF4774EC2C1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77B17A5FD9BDF2B7ULL,
		0x5DCA6EB2F137D376ULL,
		0x29F95EF0785F2E28ULL,
		0x917E6E1E7A046066ULL,
		0x48083DFDF29BE27EULL,
		0x7EC0519BCBC12B5DULL,
		0xF97977B113FE61CBULL,
		0xADE908745BDFE7EFULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xACE54095F0D0161BULL,
		0xAD71BA4A97423D19ULL,
		0xDC7BD780FEA1DFE9ULL,
		0xADD94A0FFC77AA4CULL,
		0xE0703740124FB9C8ULL,
		0x695F6E522B420823ULL,
		0x419C59FBD572463CULL,
		0x194144E1706C626CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACE54095F0D0161BULL,
		0xAD71BA4A97423D19ULL,
		0xDC7BD780FEA1DFE9ULL,
		0xADD94A0FFC77AA4CULL,
		0xE0703740124FB9C8ULL,
		0x695F6E522B420823ULL,
		0x419C59FBD572463CULL,
		0x194144E1706C626CULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEA11EF3308FB8E37ULL,
		0x4A99E65ED1D31453ULL,
		0x9FFDA16C93136400ULL,
		0x91078456137B6186ULL,
		0x620C47F7736F3024ULL,
		0xA2E3BA27F1F3A23EULL,
		0x25F632272589B9E3ULL,
		0x4B0E89B116FF56A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7F009B909820D6ULL,
		0x0A9B6ED75837A05FULL,
		0xBF42773CD6D9D8FBULL,
		0x1007E9C247FB29CCULL,
		0x1251FC4172D5B7F0ULL,
		0xFC17A656EC5420AAULL,
		0xDDBE10121B36C92FULL,
		0xD16F873F04AD2988ULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDB21CFA2D50EEE3DULL,
		0x34DD30D25539EF07ULL,
		0xD2699B2480F36A53ULL,
		0x4F9B6AD16692F372ULL,
		0x068207393B60939FULL,
		0xA1BB3A9B1664CEC8ULL,
		0x365D99E39CDB3242ULL,
		0xED841A3E526006D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD690C5F30DAB2A35ULL,
		0x0A63FB747E390C0CULL,
		0xEF77A88721057033ULL,
		0x6A3ACCC475481795ULL,
		0x83B66E16FAFE0F3AULL,
		0xB7FD60A9A8C89AE1ULL,
		0x14D9198EF5729251ULL,
		0xE0204D61450BC97DULL
	}};
	t = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFC6628E62E096B59ULL,
		0xF20AD94DA1656B2BULL,
		0x11AD6277CF66F521ULL,
		0x9F51D6E12E0C7BCEULL,
		0x3EE94DDFA70825A7ULL,
		0x5424A13B373A087CULL,
		0x83FA24D170EBFED2ULL,
		0x2AC89F049E728F79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F9B03CFF8E7750ULL,
		0x76159A03CF6BE9C4ULL,
		0x804F270D7E7BB2BCULL,
		0x3AD1DFDD3BBA411BULL,
		0xB7AFFE74DDEF5245ULL,
		0x0CB95E25DCB01D06ULL,
		0x860FFE35A8196B4EULL,
		0xA7FE6F41F03F36B2ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEDA701FF4B4D105BULL,
		0x1EE6D1E87B3DF8C7ULL,
		0xB6DD580655F55B59ULL,
		0xB3CB7E17969269E2ULL,
		0xF481814BEE917D1DULL,
		0x2B0DF0BC533EB11BULL,
		0xEDF418D48552BD1AULL,
		0xFF5BB142B4F3ADD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDA701FF4B4D105BULL,
		0x1EE6D1E87B3DF8C7ULL,
		0xB6DD580655F55B59ULL,
		0xB3CB7E17969269E2ULL,
		0xF481814BEE917D1DULL,
		0x2B0DF0BC533EB11BULL,
		0xEDF418D48552BD1AULL,
		0xFF5BB142B4F3ADD6ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3B876F53508AA52EULL,
		0x910A226BD63D8B0FULL,
		0x837CE9EDA6942DFBULL,
		0x1246218F22F2144DULL,
		0xB02DBEBA3F7628E8ULL,
		0x406BFCE67013A778ULL,
		0x1BFB3309E7A61A6DULL,
		0x47607A8432CC761BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41DBBCB6F866A396ULL,
		0x83BDC9CBB97A75D2ULL,
		0xA1A1F83C71E4D246ULL,
		0xB22B31FBACE93825ULL,
		0x9BB793EA85ABE7C9ULL,
		0xC594D51DADF83098ULL,
		0xCBAF10A50DC155E4ULL,
		0x959A42B8BC4DF12AULL
	}};
	t = -1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7782B6F7C47A1D41ULL,
		0xE63260702F8C0613ULL,
		0x1EAB2CFE7BB0B07AULL,
		0xCCBDB6286E82B615ULL,
		0x2D45E5262DD20C98ULL,
		0x629E60BB14950055ULL,
		0xBECF5746804E3C67ULL,
		0x4D2C732F9A5053B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85F187CC285B4DFDULL,
		0xC7336AF2DB5E7AB6ULL,
		0x85C7A0D85C0EE9FDULL,
		0x9E5654DE1F1FF843ULL,
		0xE89D302E87C80922ULL,
		0x9F17FFF279574BCCULL,
		0xC79573FA71AAB4B5ULL,
		0x3493258F3C483892ULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1AB83A11DC142443ULL,
		0x839F958C8C3D90E0ULL,
		0xD7D32E2B61FB5128ULL,
		0x347419AC5DDE79D1ULL,
		0x7C07AD6F8A8FAAEFULL,
		0x7EB4B663FF4EE204ULL,
		0x968ED1EA92553A65ULL,
		0x345874A53601DC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D87B66DDB9AAE9ULL,
		0x2959B671AFE96915ULL,
		0xF659149DC013ADB5ULL,
		0xE05680C9BD272433ULL,
		0x7894A7282F03FD6DULL,
		0xA4F7B35690CB5E72ULL,
		0xE62BA4D76E59DE76ULL,
		0xE58EB908DE651CDEULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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