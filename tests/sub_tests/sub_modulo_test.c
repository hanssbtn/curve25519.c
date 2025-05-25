#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x8930840208B90930ULL,
		0x5C039A6AE3753B18ULL,
		0xC498F83676F9692EULL,
		0x9B4266E67F8FFCEFULL,
		0x48E05265138EE6DFULL,
		0x74A28B0018908423ULL,
		0xE0DE696AD5E45313ULL,
		0x65D1AB75C23424A3ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE095AA7A51D8A9B6ULL,
		0x19FBBC9A76F93AA3ULL,
		0x7D341AC7E303E53EULL,
		0xD1548698DB88AB90ULL,
		0xD1548B2940CE73B8ULL,
		0x136405D669DB32B9ULL,
		0xFB29B7DD274521A6ULL,
		0xC20CFB8E19CEEA40ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x675A6C68FF717530ULL,
		0xB14FA2005B66161CULL,
		0x603738767F96DA2CULL,
		0x191FFCB0A30DFC0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x764469760DC591EFULL,
		0x2AFBA05B09965908ULL,
		0x23546F6FA986A883ULL,
		0x1F38158A423DD1B7ULL,
		0x9166B20684E72DCFULL,
		0x4C87CA86BC3D7DB1ULL,
		0x77E3B874BCBE83A4ULL,
		0xA765EC2DE24D6EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B79D461D6B72D40ULL,
		0x019033FACFC5E4F8ULL,
		0x1FC454B9357AF05DULL,
		0x4503FF5E5F0ED240ULL,
		0x4C0BDB3CD270F17FULL,
		0x862DDB064BDBC75EULL,
		0xE7F8A53673A0F8CBULL,
		0x2ED955760EDD426EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66467704B49B5B28ULL,
		0x9AC4F970E851846CULL,
		0x6074F5F54E6E5453ULL,
		0x3F12757545D590E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA85E4E11D2602564ULL,
		0x3C48F8028E20D24FULL,
		0x5907EFCB871E7A9DULL,
		0x5A5B0B2940B0C820ULL,
		0xF4A3E9EE12704C80ULL,
		0x7EEF0E8B95B12DE3ULL,
		0xC3243DF06029A8DBULL,
		0x14D34C7401EE441BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E9E2AA5E6473C1ULL,
		0x324A68137C2C12FAULL,
		0x531F859FE9D8FB1BULL,
		0xF695B92376C21EA8ULL,
		0xFB0CEEBF5D46B2C3ULL,
		0xFC56CB56EED3FC1FULL,
		0x5ACA6EFE8EB375B1ULL,
		0xF7201C26ED3E9267ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEDDB45658287E92ULL,
		0x6C9889BFD6CA226BULL,
		0x833D2210B4D117ABULL,
		0x4C5E7D76DC030A3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCC7087D966F7C99EULL,
		0x9E63ED9016A32441ULL,
		0xBDB873CF1655826EULL,
		0xDD02EB3BA3F93913ULL,
		0x06606071CA07FC81ULL,
		0xA7C0A18D5AB56D0CULL,
		0x9C6BE45E2FC09ACCULL,
		0x41BE6ECDBCD3E494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D30037C8CEC364CULL,
		0x6383182DD6F42843ULL,
		0x8709A3D256CC090BULL,
		0x5B028EC8FC6DA4CBULL,
		0x6A8E1B34F1564352ULL,
		0x5922CDE589066488ULL,
		0xC380382460F27921ULL,
		0xF876D38D8450C361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5076CB65046D0C4AULL,
		0xE64E404B5FAA3F87ULL,
		0x69AA6091722278D0ULL,
		0x62A167FB0B0281D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEC76E7DC74F61296ULL,
		0xD1559C2315F7B2ACULL,
		0x3CCDB0522FB51830ULL,
		0x4B107C4D39DE31BCULL,
		0x0EE9F2A3AFA45008ULL,
		0x7CD10287FDCC19C1ULL,
		0x3A3FD1EF01002F05ULL,
		0xEA6233EDE999B0A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D07A0176FA31E8BULL,
		0xB845DAB3561533B9ULL,
		0x952CDBD6E2F02499ULL,
		0xDEB55FADF1C54FE0ULL,
		0x1D87FDA198A22E82ULL,
		0x998C2D395D8B6680ULL,
		0x247807C5FA371473ULL,
		0xFB08356972FD0B6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83F9A6146FA3ED6AULL,
		0xD5476B1B897D1A97ULL,
		0xE348D6924E9EE53EULL,
		0x73B6E448E35968A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x025E8302BC51688CULL,
		0xB1BD84BC304BC21CULL,
		0x150A147E9267E6D4ULL,
		0x8145259C3A7E379AULL,
		0x070F0B66001CE0D5ULL,
		0xD8501B5DFDF67F80ULL,
		0x180DD6E403256926ULL,
		0x1D420449F6E39259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF58FB9C87AE99381ULL,
		0xE9C08B49A15738FAULL,
		0x699CEB09BACDB490ULL,
		0x6AEE0AC4F6DF7C76ULL,
		0x026734ED4985639EULL,
		0xF1429CC7333471E2ULL,
		0xD7161D8E443AF5ABULL,
		0x7823CDB25585DE01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDB89F255BE46934ULL,
		0x13FDC3D4A7C28E95ULL,
		0x5032AC2F2E675682ULL,
		0x18D3355937878017ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x92E77B2D55FD85DBULL,
		0x3067C340EC6B5560ULL,
		0xD1A2DE28B31BE30FULL,
		0x2DE565718BF7120FULL,
		0x2B3F195BB19D7872ULL,
		0x8004AF49C36CF9CAULL,
		0xA7EFA1D0E4690084ULL,
		0xA4B704763851A818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8642570CA3383C3CULL,
		0x13375EDEA227D7A1ULL,
		0xBF0A026F25AF1D49ULL,
		0x1F0CCA7C1E91DA6BULL,
		0x53F9ED5AC11AAA80ULL,
		0x8DA3AF6657FB4FECULL,
		0xF4F47BC17D14260DULL,
		0x759F87DD3ED8B411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00E9AC44662FDC95ULL,
		0x179660243D22B4ADULL,
		0xA3E08202E405336EULL,
		0x0C5519AA755970A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7F9172B264717FC0ULL,
		0xB0FEB137765877F9ULL,
		0xC5FEA694BF5C33B4ULL,
		0xEEFCF1BE160A90B5ULL,
		0x532958CDC92B8C78ULL,
		0x10C0617AF2449C32ULL,
		0x815C2ABBB3ACC747ULL,
		0x0CE5966128BD1148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0469D9105F054578ULL,
		0x8FB69C8E69737144ULL,
		0x90464A6DBB1DBA95ULL,
		0xE4A1724706A6E267ULL,
		0xCC687C1FB951F774ULL,
		0xAD5535E67AF996B9ULL,
		0x2D170AF703A89075ULL,
		0x0DC36ED579C8BDA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BC85B785FB858CDULL,
		0xE3308CB2C207D699ULL,
		0xB7FB135924DE9C33ULL,
		0x696D5E3307A8194AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC19100108C43DD92ULL,
		0xFDCE7499A4562CCAULL,
		0xBA84BB8A4276DCA6ULL,
		0xB978D18723ABF666ULL,
		0x5D254849F22FFCFFULL,
		0x43D856B18C337F74ULL,
		0xE42BD4544C977933ULL,
		0xA2AED557A80C01AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA9478E05DE2B07ULL,
		0x881F3ED7669A855FULL,
		0x18E668CDFD0AE1E8ULL,
		0x144754DB10303129ULL,
		0x9DBF62B1197115B3ULL,
		0xACD2A684CDF7F283ULL,
		0x615AE43BAEFCB47CULL,
		0x732CE1655D73B6C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD07CD32B2BC08F0ULL,
		0xE0875C667A929327ULL,
		0x0CA1F663AA652DD8ULL,
		0x327BB2A32616E3E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x69E976B44E6999DBULL,
		0xCE42CAA032302A77ULL,
		0xDCB2FF73E2037FEDULL,
		0x22B7DD4C83D4AC65ULL,
		0x5132AE12DF8AC70FULL,
		0x46D7243399B36BA0ULL,
		0x7BD3FC1653938D6CULL,
		0x3A570D1032FA6E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4685F1844A208DDULL,
		0x1301C7D6A25ED86FULL,
		0x960B84227F499921ULL,
		0x2BCB8324B381A8FBULL,
		0x8DEBD86BC4A9CEAEULL,
		0xB9DC705C48C884B2ULL,
		0xEB146E09EB5D7552ULL,
		0xAE6A84FC791C81A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9204CE6A072C6CCBULL,
		0xA877B4BF92AF9952ULL,
		0xC3169128DAC17A97ULL,
		0x3C088D1567442E15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA864297314F4CEEDULL,
		0xCCD225EBF9855EEEULL,
		0x29794ADDB4FE561EULL,
		0xFDDE1055553BF027ULL,
		0x34A13FB65CD9950DULL,
		0xE60D14ACAB1902ACULL,
		0x73101EC1B730FA1BULL,
		0x1AD4B1FE9222AA02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C02ED0045271ABULL,
		0x913EE0756CCBC3B4ULL,
		0x317A9F7CA677CB01ULL,
		0x28DEEB18F526F096ULL,
		0x62DB872978032B5CULL,
		0xDAAC23C27EB62A7CULL,
		0x108CD0C473502F83ULL,
		0x50E8C47D15FCD787ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71FD5F8D08760C6BULL,
		0xEBF708392365B253ULL,
		0x977C3EF921E49DAEULL,
		0x4E046674CDB23DE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB0914D3CF6851E53ULL,
		0x8E551358CB283248ULL,
		0x00CD0EFB5E21C49CULL,
		0x0C40B9B573FF8B40ULL,
		0xB17E2E399A6C8C96ULL,
		0x5358D622F412FB92ULL,
		0x0DD87D441B98BD8FULL,
		0x596B68F7BCA482F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309CBF1A99BA4B23ULL,
		0x9AF6CCCE181A1BF8ULL,
		0x8BB73AA5A5F91D33ULL,
		0x5EBD9D67278DDCD1ULL,
		0xC750AA6FC56BD3D8ULL,
		0x5D0A16DEA3263849ULL,
		0xAAD6C50595CC4A67ULL,
		0x5163D5DFE910A3BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42B61E17FAE63F77ULL,
		0x830EAAAEB6331323ULL,
		0x27572D9D9481BF57ULL,
		0x5EA2F1D7B464D05BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6FAB59F874B4AF2DULL,
		0x2A8DE48BB6E30B32ULL,
		0xC1091EBB63F56CEDULL,
		0x0398611A6879167DULL,
		0x728B269B8EA3342FULL,
		0x8AF71119325146A8ULL,
		0xBAE3714803F28812ULL,
		0xB11690FC7F723725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB9BFD54CF5DCC0ULL,
		0x640EEEE641A8DBAEULL,
		0xBBA3A506DCFC609DULL,
		0x64D7C7034BA369C0ULL,
		0x0A7CF39E2DB429B4ULL,
		0x7DF1EFA16FB9A905ULL,
		0x067DEE186B977AE6ULL,
		0x0CFC101C85214398ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x640D2BBF8B3A642CULL,
		0xB541ED6C57BB95C5ULL,
		0xCC76F2C5247D00D9ULL,
		0x7AAFBB5644D9D3C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9E16F2F74C4575FDULL,
		0x3F86130A11FEA775ULL,
		0x2F3930BC7EA604D7ULL,
		0x91CF8699DF0E7F97ULL,
		0x792C954047820D12ULL,
		0x0BC1B5CCDD1FCC19ULL,
		0x554E509E9C58A7E9ULL,
		0xD70EAE7FD1BEA022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C8D146DDD79B545ULL,
		0x70874D562BA9C9B1ULL,
		0xF2039350701ACA1BULL,
		0xCF316B6316B1C87DULL,
		0xF13C7620CBD1BF2FULL,
		0x77E5513083B92F3BULL,
		0x025F94DAB1F8BF6DULL,
		0x85CA57FB57AFEEBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F2E7D35CAF7521FULL,
		0xC1B5B4E92B9026A6ULL,
		0x8CA57C80D8C7BD13ULL,
		0x52C2F2E0E68B0C95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x95CAA32C04736ABCULL,
		0x27B904B79271C951ULL,
		0x864A5E10D334D9F8ULL,
		0x5B421B5327D64F14ULL,
		0xC993D1BBE80A275DULL,
		0x9B9D1714C92AF8F4ULL,
		0x6236305F4E43085AULL,
		0x26A109360F7F1DE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC239ECD63B9D729ULL,
		0x1EA16A128620F560ULL,
		0xF6990E7DC50485FAULL,
		0x43F906C4D36E71E3ULL,
		0xC433647F69FE0C74ULL,
		0x9DBBB9876AC221C7ULL,
		0x6470D40F014C3ED1ULL,
		0xF89B39CB9C5A5965ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5F73B5956858D7CULL,
		0xB88B7DA10FE0C49FULL,
		0x3AFD037E7AD23E53ULL,
		0x6C25DE5B6BDD087CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x45F41F7BD6E86D2CULL,
		0xDAEF1C502956EF49ULL,
		0xC9AF1F5E31D9A824ULL,
		0x7D7AAF7F9A51F2EAULL,
		0xDBD87CA0A58F0FDDULL,
		0x52A36DBBBFA1A294ULL,
		0xEED3B4DB9D93BC92ULL,
		0x11C134650AA28918ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E90EF63F3032CDULL,
		0x601CED5A42847206ULL,
		0x8D2F00F7FA2D3D97ULL,
		0x3111AB0AAF804C3AULL,
		0xF0FDE60F8CF80FFBULL,
		0xB8471C452B814E7EULL,
		0xCEE72C32858067D9ULL,
		0xFEAE66489C5A3C23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A7D6A0F3E2230B9ULL,
		0x6486468FE39EF883ULL,
		0xF99C677FCA8AFDF4ULL,
		0x21339CAD498D1312ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAAAC3B14C1137BDAULL,
		0xF164FCA0F2657530ULL,
		0xAC4372D8F915CCD7ULL,
		0x4E9E6C9BF207F1BBULL,
		0x1C46B55DB5CAAFBAULL,
		0xC1AD92C9C63DBE30ULL,
		0x57755AA73B98CE69ULL,
		0x205D40AA7D259052ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71415A776ACD2348ULL,
		0x9B35B32D09EB8AEEULL,
		0xC1BCA76EEB1E2C39ULL,
		0x943EF21319F3BDE3ULL,
		0x2D2B8C5FD49CA372ULL,
		0x40FFFD047E9C7B29ULL,
		0xEF5D2C840165AC89ULL,
		0xCD05C37A18702CE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB772F64CC31C2766ULL,
		0x6FF384BC8A69DD49ULL,
		0x5E1DA4A4B18EA7F1ULL,
		0x195C0FB7CB00F57DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA84024B06FD2568DULL,
		0x972ABBDCA12EAFADULL,
		0x6355CEA597514CCBULL,
		0x291D3202200E9084ULL,
		0x220657012CDCD99AULL,
		0x8C10DBA098935380ULL,
		0xE70678616A5772B8ULL,
		0x0F49D7F376D8583FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7226212FE7894625ULL,
		0x95ECAB4DA6378B1EULL,
		0x26B189CD7D6E97E1ULL,
		0xAF8FB63CBDF9FCCEULL,
		0x716C87BB7F52197BULL,
		0x65E24379A1DB9FBAULL,
		0x5A3AC0BC539816BCULL,
		0xF7994100A26F8A7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CEEC7D84AE18FBDULL,
		0xAC28A6579A3BD3E7ULL,
		0x22E187597A4A5C57ULL,
		0x7DC3E3D0E9A31E97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC2E297506E746EEBULL,
		0xE7937AB0DC253092ULL,
		0xD1089750B22965B8ULL,
		0x6FEB38C016CF8EE6ULL,
		0x4DA4C695105C88CCULL,
		0x35AD2AF6AC73A3D4ULL,
		0x573749C7C85766A5ULL,
		0x67B4C813D6CD5F3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE8F0E5137A92F03ULL,
		0x4911A204B37E8E60ULL,
		0x3DC2B4643109DF0CULL,
		0xF84C8E1F262E61E1ULL,
		0x0EC079805BC0A585ULL,
		0x6930EFF8C980F595ULL,
		0x0F7B4CC868A72EC3ULL,
		0x20B383BABF5797AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A36FA1205EEFDEEULL,
		0xF8F29A5BD8AC7F95ULL,
		0x392D70D4B547D230ULL,
		0x01CECFDA6C1CCC96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3E57AA718E7ABF30ULL,
		0x80018E469B87D918ULL,
		0xA68845C1985D664FULL,
		0x66C8716474F8BC97ULL,
		0x2758F6BBCCE7B88DULL,
		0xD724D47973D27A53ULL,
		0xCF76534E26158D03ULL,
		0x1D769AF5E973147EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD761A4FFB1A2391ULL,
		0x29AD5BDE4B6AE51FULL,
		0xC4D64A77D054616FULL,
		0x4B86395D57E51ACEULL,
		0x7D05D1E310DE9AB7ULL,
		0x7B81C2C55B268BEBULL,
		0x8EEA92C65096B8CAULL,
		0x5CF68C9711290DD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA939084D7CBB07FAULL,
		0xF088D323F9A2575BULL,
		0x76708F7378DC8563ULL,
		0x2E445A1B38109E9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x434884CC44DDD716ULL,
		0x5303E153F90D1C5BULL,
		0xABC34E8AAE6B49E4ULL,
		0x1AAEB9996BB29B68ULL,
		0xA908E7B130BC35E3ULL,
		0xFAE05EF8A82CE9A6ULL,
		0x21817CAE61C73231ULL,
		0x1EE76B891DECB481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACFEEB84018AB355ULL,
		0xA8FD049C07F85670ULL,
		0xF88B51E5414B4041ULL,
		0x0401B9AF371A4493ULL,
		0x765581D2664DC8ACULL,
		0x74DB1321773E353AULL,
		0x769A942DA354D17CULL,
		0xB997FD099952F567ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CEAB85A4FB75681ULL,
		0x8ED01EA934838DFAULL,
		0x117E7FC1B21A6494ULL,
		0x207766D7E36AB4A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x126D740E86218C13ULL,
		0x8DBB83C6C6E0EE37ULL,
		0x1E26C845CEAF1918ULL,
		0x7ACB1CFF255823C9ULL,
		0xB5BBE95B482F515FULL,
		0x352D9F8CABD00E38ULL,
		0xCCEFD86048E25ACAULL,
		0x48467C256F4C6009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E3E2C94075FCFCFULL,
		0xE17F5BFC6826F056ULL,
		0x8ADC4E106F623258ULL,
		0x8E2BB63F176BAB7FULL,
		0xF7422826BC961254ULL,
		0x0FEED9D8F79D3A0CULL,
		0x9932F24284BF1E80ULL,
		0xD2F5F95A7E4075D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA41F547378114C8ULL,
		0x338D80771E457C5EULL,
		0x4154A2A07C87D9C1ULL,
		0x5692D0DFD5B13B71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE2FDC93D791595F7ULL,
		0x0F2542A98199C0C2ULL,
		0x9B2C531246DF831DULL,
		0x70AE8E30CA6B2EFBULL,
		0xE077923FEC14630EULL,
		0x09CC7FCA40B9EAEEULL,
		0xDE0B7323322E6BFBULL,
		0xAF0070E7E0DDFD1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x765B5E9234751C19ULL,
		0xA6C95EC75E42C281ULL,
		0xC2CE56EBF090E471ULL,
		0xB5031C155473B2BCULL,
		0x9077631EC7B0AFADULL,
		0x16A2F9BAC4593A6FULL,
		0x78F5023A6EE6A462ULL,
		0xFAAB0F68927A011BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CA96996AB6D188FULL,
		0x8085CA2E99B13127ULL,
		0xD9B2BEB352F63F5FULL,
		0x0057EB0118CEE427ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE6C084B34C73128FULL,
		0x11D4B8FE16CECD76ULL,
		0x5CDA323E690CCEF4ULL,
		0x91EA5DE264D84082ULL,
		0xFE34C1936CE907F9ULL,
		0xAE3EFC89B80BA0E1ULL,
		0x0038C3CB20BD8F01ULL,
		0x2601861A7D877A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8C5EFCB7BDC2FADULL,
		0x0532E419DC98B620ULL,
		0x30E6CB88678A2D7CULL,
		0xA2698E9D0C1874ABULL,
		0xE869BE5C6DE410B4ULL,
		0xB507DDF60D301649ULL,
		0x2E846EC17011F9E8ULL,
		0x66F39A5476CE5C3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A1D0F11AB5395A4ULL,
		0x0AD05ECF96CCA9E9ULL,
		0x4CB806263AFAC32DULL,
		0x4B91CEAA583A40DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBF779B37ADA66B58ULL,
		0x352EB229486730F3ULL,
		0x1E67A8BE575EB430ULL,
		0x0DF246B69EFDD8E0ULL,
		0x12BC8910AF1C30D7ULL,
		0x84385B5CB20A90A3ULL,
		0x70566350F85C723AULL,
		0xC75B9E37FF695F22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE806990FF93BAE2DULL,
		0x661BB627BD46EE90ULL,
		0xB90C245B1D267F71ULL,
		0x82BB39B403F88827ULL,
		0x2528328D0B0ADBF8ULL,
		0xA72C171AC9221C3AULL,
		0x7D202734F63357DFULL,
		0xA60D54CDDCDF08FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B75D9B20EFD56DDULL,
		0x9EE51DCA1DA189F6ULL,
		0x7F68708B8C521E3BULL,
		0x7CD5F2C3BB8E1AA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0CBAF516703500AAULL,
		0x5FFF5211B84D6629ULL,
		0x66653BEB045D87C8ULL,
		0x749EB12A0A397425ULL,
		0xF616E1873921FF29ULL,
		0xBED8D87FA3108B3CULL,
		0x4614F1B463FDE9E6ULL,
		0x65B8AC8C50EF63B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22EF9BE90746794ULL,
		0x7A215E8CEEBEACF4ULL,
		0xF1793A18FD7BBEC5ULL,
		0xC05DB95A92F123F8ULL,
		0x1D21BAA321778ACAULL,
		0x79148136AFFB591FULL,
		0x761EDD3DF25A7F3AULL,
		0xDFD0E0AE58B501F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EEFC133630DDC71ULL,
		0x4102E858DEB429A2ULL,
		0x53730B66E5239E95ULL,
		0x14A93AC24FF2D259ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAD69F1F815F75425ULL,
		0xDF6529E679EE1C24ULL,
		0x800BB595A7E606C2ULL,
		0xA50B15F9D6476581ULL,
		0x58DB1E164EE83F42ULL,
		0x6FF009A55A656C81ULL,
		0x07FD734B4107F152ULL,
		0x4308122A383D0E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C8BECBEBD7679ACULL,
		0x0471FFF334AB9E06ULL,
		0x9A0D23542FDEE099ULL,
		0x43B043466266D925ULL,
		0x5F1895297E01E301ULL,
		0x24038B5658218AD8ULL,
		0xA52340190E0F241EULL,
		0xF92037BB3B409910ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53BE58605AB2881DULL,
		0x200DE9AD9B55FD33ULL,
		0x92622BB508F59BEDULL,
		0x59C53F2D0159F670ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8B06DAD08CAC7ED2ULL,
		0x163F1D07FFD7832EULL,
		0xA008DF348AFC9C9FULL,
		0xD3F9F210DB181F22ULL,
		0xBF229EC61063F3E9ULL,
		0x222D7CC8CA620E33ULL,
		0xF09CDAE3B0E8D8D9ULL,
		0xC2BB106603BA9F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FBD2673C744C025ULL,
		0x5FC83B51277DEDD3ULL,
		0x1EA68E612B5B3D71ULL,
		0xE3E195D1465F1498ULL,
		0xD1021A60DE9462ABULL,
		0xA0469CECEFAC91A7ULL,
		0xDA0B62A14A28F8ABULL,
		0x7735ED5C00030DE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x841D5B622A374F83ULL,
		0xFEBC1C594F4A1220ULL,
		0xDAFA2AAEA01CA5EEULL,
		0x25DB8FBC21F89CDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x880E7645C76D2D22ULL,
		0xFA6ED4D5A72E40CFULL,
		0x5C766E09702EB3ADULL,
		0xD1E11BB539707691ULL,
		0x3F66B8390283CD4AULL,
		0x771341B1F3ABC136ULL,
		0x2EB59B2CF9226842ULL,
		0x4A737A47E7F8BC6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23387CA950EFADCEULL,
		0xB340ED7704D15F98ULL,
		0xD145690F1A806054ULL,
		0xC73E79791DB4D67EULL,
		0xF71944855C3DE64EULL,
		0xA7CDB84686B94F58ULL,
		0xE02C2239D86BEA1DULL,
		0x67DEA2AB0DF3CC94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2055264724DDC811ULL,
		0x0B804D50CE59C810ULL,
		0x3398F91130C50CD0ULL,
		0x2CBAA38478773A54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7BE330CDB85CCF98ULL,
		0xF26ABDD8A90043ACULL,
		0x65BACA4E2BF796E6ULL,
		0x0D800F0849883720ULL,
		0x2E1F7CA68CE81A62ULL,
		0x6B89A46B559555E2ULL,
		0x0224CCBBE14B5C5FULL,
		0xF8CD9DE26F1A684CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146671B34EE6DB64ULL,
		0x7A1F8F1AFE1BAF47ULL,
		0xFBE8B4568A08144EULL,
		0x898817EAE0E4105DULL,
		0x3B22F094FB7C3101ULL,
		0x3075AC772B5EC4D5ULL,
		0x1D9A6BDA5371A6D4ULL,
		0xC9AD6D6669B0CD1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78F989B5FF7A9991ULL,
		0x3D41FCFBEEFE1C51ULL,
		0x565C7772B0407543ULL,
		0x02BF298636513004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4B4B2FDDA3B0D5F2ULL,
		0xC5C5E4ACA4C0766FULL,
		0x3D1521E6F60A54D9ULL,
		0xB088373B2952AF88ULL,
		0xEE272C954B78BDD9ULL,
		0x251C79EF2C3BD52BULL,
		0xEAF9E121B923A3E5ULL,
		0x5014AB1B0A238C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F49D9627643E90ULL,
		0x64F984EE999DF592ULL,
		0x7B3DCC9F990E9194ULL,
		0x8B18B757CA1183C3ULL,
		0x0E4BE7BD8B0F2888ULL,
		0x821A0EBF91C8DE0FULL,
		0x5AB3D4CD63DBAF29ULL,
		0x8A4F809907094763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50E2CA4E0BF8C025ULL,
		0x932848CEF8332F26ULL,
		0x2C3D29CC05AA171FULL,
		0x00B3CF2FD5276B56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC634037A64609DEFULL,
		0xAA4BC1C595F93A26ULL,
		0x2ED58F460FB9FE69ULL,
		0xAB2B5AECC1627A5EULL,
		0x22490AC4DB8998D8ULL,
		0xC9ED5BE1AC55DE58ULL,
		0xFC9CB3FA41C6535FULL,
		0xCD26266422CF06ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE0D845535FCE1BULL,
		0x7F4AE4F071B099D0ULL,
		0xAEB781D4E03BC575ULL,
		0x6C9EA91CFA65098FULL,
		0x1EC727768CD79871ULL,
		0x3AB77F292A79E356ULL,
		0xF2351AC37D60222EULL,
		0xED5EEBBA5AB6AF29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D9AE8D4BF6CDE60ULL,
		0x6CFFA0386AEFE2A3ULL,
		0x0B7ECB9256A9864FULL,
		0x761F67037A9A6E1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x53003FEF58B8F2CFULL,
		0xAD2374BE73934318ULL,
		0x1F916F03EFB871A1ULL,
		0x00AB83D9AB638DADULL,
		0xEEA58CB7CA73082EULL,
		0xEBB58E0425EC9D11ULL,
		0x5933E5954F7379DDULL,
		0x53F66F928BFEB467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1867B5DCB2E3FAB0ULL,
		0xFA7FF8605D06615FULL,
		0xE3314BF4AE6BFEDFULL,
		0x0544B233B2168574ULL,
		0x31167667EE9D18A4ULL,
		0x5E891DC3C407FB9BULL,
		0xB50AF18C77A806EEULL,
		0xC99A9407E30C876EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DD5D9ED47968402ULL,
		0xA73C25EC9E7CD959ULL,
		0x9A745C5F497F8250ULL,
		0x0509683B0D3FB520ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0A925559D184F7B5ULL,
		0x00C8CA6D26C1DED8ULL,
		0xE33F5D7123FE71B5ULL,
		0xEC40860606116F65ULL,
		0xD42362FB61DE9117ULL,
		0x606819AB83C3AA6FULL,
		0x4714E2354145E317ULL,
		0x460BF8088A3ADE9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x811E878C2A6AFBC8ULL,
		0x2CCB46197CCAEF36ULL,
		0x06677CCC68D367A0ULL,
		0xB504BD40CC3A8BE0ULL,
		0x443C986C991187BCULL,
		0x8D45F7FCFB12A957ULL,
		0xCE102C483CFDAD39ULL,
		0x2A174E729AB1D47CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5B5DEFF75896007ULL,
		0x2B0E843BF43D1946ULL,
		0xD38AE1D35DE30902ULL,
		0x5D8CF506C82E63E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCFCF230E41BBF29DULL,
		0x746A167EDA1EE529ULL,
		0xCE633496472E24F7ULL,
		0xEED3AE51DC107D58ULL,
		0xE731A51A4242E496ULL,
		0x222015F13D31CBDFULL,
		0x3B1EE4DCD0EB5234ULL,
		0x326424F8A3C18605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x033B7DDBC62DD1CCULL,
		0xF153DE40EE2E96F6ULL,
		0x5BB7D01791FDEE39ULL,
		0x19F65A4CBBC57202ULL,
		0x4B3F59373A1DB7E4ULL,
		0xAF8ACE97B37E59BFULL,
		0x9B63A54C62075D9FULL,
		0x3EAA9B4B74B3149BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF28AE8E5B112C317ULL,
		0x853ECF885C933F0AULL,
		0x2876D3EF2B0684C6ULL,
		0x0267C3BA1C6FE104ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6A302FF6EBF4BA58ULL,
		0xDE76EFEA8F8909D4ULL,
		0x691DE1670EB37E7DULL,
		0x7579B5DAC7875988ULL,
		0x51423E1B24369101ULL,
		0xC577D3AB22D87E18ULL,
		0x368645EEBFFF571AULL,
		0xBB4CB8969821DB05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F8637A0F86D67FULL,
		0xDBBE879A9042E5BEULL,
		0x76B33C5435247083ULL,
		0xCFFD246F170763B1ULL,
		0x737292993750CDE5ULL,
		0x42A0806E44277527ULL,
		0x1B5DCB6CB5FDAF01ULL,
		0x0C6B1F2024DC319CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D0B41C60688DDCAULL,
		0x6EAEC3590D8D77D7ULL,
		0xFA6CD46055CE01C3ULL,
		0x1AF95900CCD71B70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB606D66ADAC5A650ULL,
		0x2FB109D5EDCBE797ULL,
		0x8D36D2AE449AC19AULL,
		0xF0130B3C0EC8AC7EULL,
		0x4238F3422D0DABE0ULL,
		0xB0D3224DF88E7D5FULL,
		0x2205B53562E590F1ULL,
		0xC0BBDB96E9F88563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C392806FA12DC3ULL,
		0x959EE9BC4E282F99ULL,
		0x4440191B906772C2ULL,
		0xB0E8AFA9AA82165FULL,
		0xFE93115B4849D77EULL,
		0xFB437911028B6078ULL,
		0x999D5FA8919647A0ULL,
		0x7B5197B671F17E46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87E2CC30603600A8ULL,
		0x8D653F26241A022CULL,
		0x88736C79C5F830D2ULL,
		0x0CF06EE43551A45BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x21670AA75C7A0CF1ULL,
		0xE446799BD53C20D9ULL,
		0x8A30F80B6CBC0B19ULL,
		0x74DDABB2535A8F6DULL,
		0xD8263933D526FB53ULL,
		0xAFF89154FB64FDC9ULL,
		0xFCDD09E157CE6576ULL,
		0xD3DB0B299DB3D037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96556C7D2C10FB6FULL,
		0x37B107F5DD407CE4ULL,
		0xD0D28262301489A7ULL,
		0x1866E363D257A111ULL,
		0xEE25ABE38D7D33B8ULL,
		0xFC88B331ADEB6865ULL,
		0xDF138DB448958DC6ULL,
		0xA92F14A0251AE749ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47269814D39CB37BULL,
		0x4F306AE37807D0C9ULL,
		0x2546E4597F178587ULL,
		0x31FD60B667B581B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2EECC4CCAE9FD8F6ULL,
		0x85951DB5A8E74013ULL,
		0x69ABFCCEE17A1223ULL,
		0x106CDD66B4DB4A2EULL,
		0x8DBF57D3E6AB8C41ULL,
		0x45B5C8EB4F29A17FULL,
		0xDA96F75E402BF057ULL,
		0xBAB7DF1DEE6BF24BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7605656CC42E1624ULL,
		0xE9F281D536D20B73ULL,
		0xDC5B7F772FE6D635ULL,
		0x1C4887FAA7DE0677ULL,
		0x67EAC136A5A750AFULL,
		0xB01BA1C814977E8FULL,
		0x010A761BD81FF700ULL,
		0x6B3A5CD3AB01A8D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5675BAB791129C33ULL,
		0xD0846B1B23C66445ULL,
		0xD82BAD33235A3EC7ULL,
		0x40C5AC720EC42AC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF5057B2EE2484CD5ULL,
		0x60515F8118B5335AULL,
		0x16A9654493B162E2ULL,
		0x19D2F632355F2A7FULL,
		0x988D520EE3599FE0ULL,
		0xCF6C9397EC407FB1ULL,
		0x63C8985FA6E24E51ULL,
		0xA83D8B5EDA837255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF743C4915656C46ULL,
		0xDC9C98D996A3E0CEULL,
		0x22D18A2172C5D480ULL,
		0x0306B862E15938F9ULL,
		0x061980E1E27CA4D7ULL,
		0x4AFCB49C06BB47A5ULL,
		0xAAA5C54E98200284ULL,
		0xA507D3579D649720ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C24B93EDB023F8ULL,
		0x2C4FE00B93D7A469ULL,
		0x6F032FAB51C2CEE3ULL,
		0x10C58EE2669A7B59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5599E08CCB3657D7ULL,
		0x73E553E4518E2D93ULL,
		0xC4CBB7B06BBB7E79ULL,
		0x74BDE13A641CD386ULL,
		0x51BEA6FDFCF17028ULL,
		0xCD6E8EAFBD65E5CDULL,
		0x6D8694A727338F73ULL,
		0xC68C85A10012B103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F11D5D7EB88A151ULL,
		0xAD4496D327D1CD63ULL,
		0xA609C909A38699CCULL,
		0x3551846A8E37DEC0ULL,
		0x18EB9DB230806B66ULL,
		0xDA195ACE32DB4414ULL,
		0x814D2BE4393AD309ULL,
		0xBAEC6FB121F1E6CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5DB6BF538746B8BULL,
		0xE546708BBA5061AEULL,
		0x2F477B961B20DC66ULL,
		0x792F9E6ACEC2F913ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB9459C6EAD449E99ULL,
		0xE52F7A3159C77EDEULL,
		0x98282BB656DA3AD8ULL,
		0x7FFB483A43F29C02ULL,
		0x9BBEB786DB3746B8ULL,
		0x0161F7001559002BULL,
		0x78840A9F3C51F845ULL,
		0xD837F95AB5098F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9193868AB7205F92ULL,
		0xA79A2874CAE6E268ULL,
		0xEE16F5C16899099FULL,
		0xB0BDEAACF16F66CBULL,
		0xDA93A737F16E2730ULL,
		0xD09EE2FCA42607A4ULL,
		0xA731D77AA482C8C8ULL,
		0x75AB44BFC9419376ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD416819AA9FEEF4BULL,
		0x7A8A4A3F5C718076ULL,
		0xBC44CD6377023DA8ULL,
		0x70202C8C52328CDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFF3E38B0BC48994DULL,
		0x4A9BCB698DCB7169ULL,
		0x8B28B32C3154CB4AULL,
		0x66591B271AFDE66BULL,
		0x61225C9444EE295AULL,
		0xF683AE8159411114ULL,
		0xFBD3CE91C1FC60BEULL,
		0xC1BD59CA364DD24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DDD9B58C4039247ULL,
		0x7A5DAC923CE4C7F9ULL,
		0xA99E7F5AC682DF69ULL,
		0x8A32C1E7D772092CULL,
		0xEC5F579F6E4195AEULL,
		0x47675BFFE91307D7ULL,
		0xFFB354DA9D7799BAULL,
		0xC0C02B2A67FE2A74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x065359AFD5E2F28EULL,
		0xCE725E0DF7BC086AULL,
		0x4E5C4500D6877692ULL,
		0x01BB44F7E35EC774ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA8F1139495737E9AULL,
		0x4C6A697D46C0DF29ULL,
		0xC4FE9F4C217E0965ULL,
		0xDF43B3CAE4FCC9C5ULL,
		0x90DE35705DF4E074ULL,
		0xC893CC38A145EAF2ULL,
		0xF5413EE8626291E4ULL,
		0x5F254690AC3A9C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3B1526BD6E701AULL,
		0x5F50FD8542512954ULL,
		0x5CAE741EF394CB4FULL,
		0xDF70FDC6AA87B41FULL,
		0x783554A244CEC76EULL,
		0x8FF33C8F5F3D68BCULL,
		0xAA13C6229EAC92FFULL,
		0xD96470247D64D728ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42C75D0593ACC2A5ULL,
		0x54EEBF17D1B309DDULL,
		0x911018883AED141CULL,
		0x5A728A132E306133ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x2C5D8CC485774895ULL,
		0x77E8E3400B41C16BULL,
		0x1CC6428BC678E725ULL,
		0xE750DCB6394A539CULL,
		0xC89A776DD3507739ULL,
		0xF9F9718D8FFA4B1AULL,
		0x30A8019C9E2EFCC6ULL,
		0x81280215F332BC08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C36E76E73C7805ULL,
		0x9CE4D4B480C5C499ULL,
		0x9724DDE8CAB423B5ULL,
		0xA63BF99586455CCEULL,
		0x8C5C4E2687BC2C71ULL,
		0x56AF99808C8D38B4ULL,
		0x07BB6C3CAE9432DEULL,
		0xCA0019AEC69B4A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56D43EE2D63DE89EULL,
		0x17FA207A0CACB7FEULL,
		0x98BF90E08CBEBBF8ULL,
		0x71016271517FCF15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x062605A2A33E4A2CULL,
		0x8F7181C98026BFE0ULL,
		0xE3015501B68EA53EULL,
		0x0C93389BA417757AULL,
		0x0F0110A129EEBFA3ULL,
		0x6A27E7B4C698DBA2ULL,
		0xDF5F5ACE4AEBFF92ULL,
		0x1CD3CE8CB9B61D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA49CFAC21FFD91CULL,
		0xD09CBD1CB8CDA815ULL,
		0xA6FA563884C5D6D7ULL,
		0xF03B1EF71D06FB3CULL,
		0x43F2867025B4CD1CULL,
		0x845719D3B2A4912DULL,
		0x3A0F19167D3153DAULL,
		0x27872A97F2385D7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6004B93D21D870BBULL,
		0xDBD35415BD9C2520ULL,
		0xC5F0C011BB7E4BB2ULL,
		0x05B86FFA23BAFD02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD6F537322255354BULL,
		0x14545D653951AEFEULL,
		0xD90B0EEB056E901FULL,
		0x1D346A0A1A7ED516ULL,
		0x8059FD5664642140ULL,
		0x9CF35684053E25A2ULL,
		0xDBF049BD7992AAA1ULL,
		0xF71DFDDB300D213FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60AE96733EE5D75CULL,
		0x0E313D83F29031B1ULL,
		0xCE149B11D705004EULL,
		0xB2FF967F68216F01ULL,
		0x4882041AD2A1AF3AULL,
		0xD2C71F01B9C7C97AULL,
		0xFCB0424E83C936BEULL,
		0xCC8F1255868EF2ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0559F96864C4BA4ULL,
		0x08B35D387A532B45ULL,
		0x2E778E51AA50C37BULL,
		0x3B6BC961DB184FBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFA74A8AB41D1D714ULL,
		0x0EE561F9C789D565ULL,
		0x4070CAAB2358C9D8ULL,
		0xB2A8233A82B8042EULL,
		0xAE7670731D574B8EULL,
		0x04CF1377188C6841ULL,
		0x7959DF3F14ECE031ULL,
		0x4DAB07E93FE84E06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1381152CB0509871ULL,
		0x6B4CBF337840CEB5ULL,
		0xA952C3E55DBDBCF6ULL,
		0x080D2D5BE1974341ULL,
		0x956D53F8182AC571ULL,
		0x1FC14B3315571F11ULL,
		0x653B7724D8B965A6ULL,
		0x71CA408FADDEE792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E4DCDC1561D2633ULL,
		0xA3A45CDEC931E3D4ULL,
		0x93A17AAAB53F3D7FULL,
		0x4DF88D2A4E85F627ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8D259EE1BC07F20CULL,
		0x9EB649562B8AB7B2ULL,
		0x9CE69696F8B0773CULL,
		0xF3734E1B045F4BB6ULL,
		0xC3C936F712EEC566ULL,
		0xC87658E2F78F3AF4ULL,
		0x93B56B2D517951E7ULL,
		0x64B10A338121DFBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A2FE54E2754330ULL,
		0x89B26FB2617D1260ULL,
		0x0C6A91EA55FE9601ULL,
		0x1CE35C2D91CFEE9CULL,
		0x5AD4EDA6B806E6DCULL,
		0x4A429ABD63E4D437ULL,
		0x40DCB29675683319ULL,
		0x5C6E87DD33638AE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9C5827A57FDB7A4ULL,
		0xD0B21337B558E56FULL,
		0xDCA76B114D3C73E1ULL,
		0x106F4ABCFCCFF5CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEECC42B5B5E2C11BULL,
		0x96E26CC8FA21EAD3ULL,
		0x2BB255C57C46A171ULL,
		0x5B0A76FB09F0743EULL,
		0x89A8A53F789130A5ULL,
		0x08E93616969C3AEAULL,
		0xED6BFF2CA14077D2ULL,
		0xD6CC8B34E3566532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6F56D451C32DD67ULL,
		0xCFC8D0D821D50B37ULL,
		0xCBD0DDDA77A2DF1FULL,
		0xA2DA25750407DAC8ULL,
		0x52C4EE13BE08B431ULL,
		0x3AC4DA506C0B3D74ULL,
		0x4D1625ADEF7CFF58ULL,
		0xBCDDFA34B895AB45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DA405EE49F25D71ULL,
		0x607F3B5B29D27F28ULL,
		0x2C9FC0B967A7A466ULL,
		0x1199D78C5E8432BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x822DA7BA1F1EF92DULL,
		0x6A394F63A73D5D74ULL,
		0xBF269D7A0E5BC716ULL,
		0x6B23AE173FEA7B15ULL,
		0xD2A85167CE324628ULL,
		0xB143803F54D8AA70ULL,
		0xA6F1400F5DB00A12ULL,
		0xA6882A2C2DC3F1A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C86A138136274EULL,
		0xED7E0E5451701027ULL,
		0x2333158FEB8227F8ULL,
		0x2AA1F3D6D41C6EC5ULL,
		0x9E8432F9EF501903ULL,
		0xF863551B3C7FC001ULL,
		0x9BD4DA8AA1EBE4B2ULL,
		0x941F997CB76E8437ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26C1C1F5B37B85BCULL,
		0xEE01A86AF30019CFULL,
		0x422A999E01F72B52ULL,
		0x7C07344BFC7C49E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCA36006B5BC6FE89ULL,
		0x8184CBD4CD334020ULL,
		0x31A9C4933AB06003ULL,
		0xB6B077B533CC52DDULL,
		0x60EB14596CDB0A66ULL,
		0x9EA7277FAF35C224ULL,
		0x183A532831C9CB9EULL,
		0x366ABCE72F50E058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE45C6B2D337B7D3FULL,
		0xCAA367853C56FF31ULL,
		0xA5C1632274EF3A07ULL,
		0x1AEC7333667D772BULL,
		0xF04CC6B0481B7428ULL,
		0x5310595387E933D5ULL,
		0x0BE676224159D0CBULL,
		0x8AC2058624081417ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D591C599CBBCCB6ULL,
		0xEF43FEDD66396093ULL,
		0x605B305276606158ULL,
		0x16CF3CE97A1D2D59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x70C559959696159CULL,
		0x98A2DF2953751405ULL,
		0x533456D5C8A2C39FULL,
		0x90078894462C67E6ULL,
		0x01DA9DC4D9C7BB68ULL,
		0xC9A61E7AEEC5BD7EULL,
		0xB682047BD94F7AD5ULL,
		0x37BB2165B4C56E35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D794A41F1AB27CDULL,
		0x11DAB9306A47568FULL,
		0x4660EDC76FA4ECC1ULL,
		0x0888E974DFD3A5C4ULL,
		0xDE200B7AE21FB038ULL,
		0x18F8BF2518BCBD07ULL,
		0x5699066139E34845ULL,
		0xB06799EF89908EE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40FDC64E67DC9456ULL,
		0xC0844CB6AE83CEFFULL,
		0x49692102030D5858ULL,
		0x1DE4BAA9D031E7C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3A73C3244C4007A0ULL,
		0x150C361EABB71287ULL,
		0x4997D7380BDE1EDBULL,
		0x8665C968B779C8A7ULL,
		0x9733F94C936F2003ULL,
		0x5BEC2B68B110775CULL,
		0x76FD21735D62B4FEULL,
		0xDB9B6F9A840DEF00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x015CF875CA2D0DBDULL,
		0x71FF9304F4A3A186ULL,
		0xF818D67488C9BB24ULL,
		0x024A9BD7EF464325ULL,
		0xB4EDBEBB24DB5A49ULL,
		0xCB92CEB88DF9EB42ULL,
		0x2D28267B0CE344CFULL,
		0x092900ACE770EB55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF837C44EC02582CULL,
		0x1050653EEC6C3CD8ULL,
		0x471C419F75FF0AA0ULL,
		0x4117A4D6078210EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x922EDC7BC2AA9602ULL,
		0x8754121604040134ULL,
		0x8015763BA1F4B4FFULL,
		0xDC245276BE079AD0ULL,
		0xC600A2F94E4110DBULL,
		0x5A89BD76295FDF74ULL,
		0xADAD595B055AFE72ULL,
		0x98805F71C51A7132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DFC2F512F058C95ULL,
		0xEC28B08E52E08489ULL,
		0x48014ED1A3AA59FFULL,
		0xF69A0E7060749DF6ULL,
		0x2B9A6315EBB623F0ULL,
		0xD56653107F7BFC7DULL,
		0x67649C5B53E577BDULL,
		0x052088C6DF5E0176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF6028EB34443780ULL,
		0x5E6D2C9EE8F72D6BULL,
		0xA6E0355E55BC59CBULL,
		0x45C42164778B92CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9636E03F9ED43C5DULL,
		0x01F793154337BC83ULL,
		0xF5952F0D795F9A4AULL,
		0x63341D85DA7CB7ACULL,
		0xFC9DCE1106731318ULL,
		0x68E2D21376E5C3D4ULL,
		0xEA8B2920FD399356ULL,
		0x4F8C53239A85CEC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x285702D157F3AA40ULL,
		0x7F22F47208EA6930ULL,
		0x7E9DE637E0E9F7B7ULL,
		0x1E305C63DE37ADCFULL,
		0x931D9296F0E87B65ULL,
		0x545E09EEA68B1C82ULL,
		0x93B007A5F1C174B9ULL,
		0xF57F7580849130D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16E8B18D7973130CULL,
		0x8E8A541A27C2298FULL,
		0x5B7E41194C4A2DE3ULL,
		0x22ECA7573E947B3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1F29BB39A1B4BDDDULL,
		0x5FBA9169A5E81E58ULL,
		0x0310026922298000ULL,
		0xCBC4E26E144D9C23ULL,
		0xF3C61B17BA8B2E7DULL,
		0x11E34A5B64845FF1ULL,
		0x19A771F0DE82889BULL,
		0xA59622D08E2B8B97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x442AF6EFF12D44C2ULL,
		0xAB21F5383007B243ULL,
		0x6CBE19704E29FAB8ULL,
		0xF45849250238ECEFULL,
		0x2416220D389A7F5CULL,
		0xB2C15B4885EB8C25ULL,
		0xE9A1463A6BDF4EBEULL,
		0x128B559935CE13BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF1DBBD8FA417B32ULL,
		0xD3A218FE808FDC7BULL,
		0xB73C660DD83A1BFDULL,
		0x2B070F802FF47970ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDD852F9247892EB7ULL,
		0x0ADB0344611B6C09ULL,
		0xED87E418C43E2DDCULL,
		0x7D1B9F3CB8698083ULL,
		0x48DAA29644547313ULL,
		0xACA51CF5D019E210ULL,
		0x98B6CFAC401061B8ULL,
		0x83CC652C08A1FCBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66A7ADFE1779EDCULL,
		0x1983FC547074B5FBULL,
		0x981E00B95E0374BAULL,
		0x6F1F84EAB2F0DD00ULL,
		0xEB8DB53B57D64AA1ULL,
		0x207F3AEFEE304FB1ULL,
		0x76D46203DB131FA1ULL,
		0x95BA46B83423279AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC085F03180CB9055ULL,
		0xBEF693CF7952700FULL,
		0x5D062A5E63D288A0ULL,
		0x64AC9F83904C466EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5E7979981B7A8ADEULL,
		0x8D29019D4864BBF6ULL,
		0xCEF9E25B970E5E1CULL,
		0x4E80B06C82B0B36DULL,
		0x946DAE60244849C4ULL,
		0xCDA276321066E967ULL,
		0xC31EE92B897DF419ULL,
		0x80A4EC264428C2DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC8E60C86663B01ULL,
		0xABF2F99A8EE8A104ULL,
		0xA4E6D7C010FE0ABBULL,
		0x05B96D003E2CE64CULL,
		0x78FA8FD349191E0BULL,
		0x5245CC4291E4C59EULL,
		0xE61D94927E367971ULL,
		0x5A3BD215D8A50A1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72C71C741E14CE24ULL,
		0x30F7418F80CD6ACBULL,
		0xF845995332AC8863ULL,
		0x7C6121DC3A113903ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x51A8B24C536104C9ULL,
		0xD545187997DB28BFULL,
		0x1C275B0F9D3F73A8ULL,
		0xE4B696BE7B7C6606ULL,
		0x6C2E3BEA86D60F97ULL,
		0x7671768AE801ED44ULL,
		0xF64BDF210C44E5D9ULL,
		0x42002A0B7D4D1E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28BC29D3C1994E81ULL,
		0x8C8B8F0E13D93FFAULL,
		0xA0C4D4661DCCB1ADULL,
		0x32CB191035A36B64ULL,
		0xADF1AC4F0FFC5720ULL,
		0xA04B6E32303F11EAULL,
		0xCCDB641414380F9FULL,
		0x07F6939036DEEE2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65E9D98C36191948ULL,
		0x125EC696CAEE7817ULL,
		0xA214CA96515A8E91ULL,
		0x4F57D3FABA342745ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF6BAA3EF37E206BFULL,
		0x0FADF3C4B600737EULL,
		0xDF07804DE22F05B6ULL,
		0x67CF67FCFFCB85B0ULL,
		0x4169ACBB5FEFAA2BULL,
		0x3219173D07E49A65ULL,
		0xB8BF8FAC31F218E7ULL,
		0xADD0A2361E558F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB31D5F53B02AE419ULL,
		0x958B546313D0A0B5ULL,
		0x23123ADC7F778C21ULL,
		0xCC48FA3776A34831ULL,
		0xDAFFB1B565E014B7ULL,
		0x9ED7FB225D51F6F4ULL,
		0x901D2D9E64457807ULL,
		0xC62F5BD11966686EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7758877EA6075133ULL,
		0x55CCCB56F3F41578ULL,
		0xC40FD37DEA575AC4ULL,
		0x7D76E0C444A8022DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x250072A8C8A722A6ULL,
		0xC7CA52C6D08F87C5ULL,
		0x148A591643014B5BULL,
		0x9C0E1BBD1C5AD754ULL,
		0x89205C46D990EC53ULL,
		0x4117CEB3FAB7247FULL,
		0x49098B3B1EDF4615ULL,
		0x0C0B92C9F57CBA68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403BDDB70270D99AULL,
		0x55CA9469EB892BDDULL,
		0x4A9B47FD08AEEA3FULL,
		0xEDD8BB5AE7B7EA38ULL,
		0x8E4AA1924DA28D9EULL,
		0x2CEFFF4F57FC52B0ULL,
		0x218DA4E6D6D29D35ULL,
		0xEB822C8EA31C6655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x207E4BBE8B9852F1ULL,
		0x6FE8874D0CC180A1ULL,
		0xA653419BEC33725FULL,
		0x029A8D306EEF67F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x63B1AF642A6EB787ULL,
		0x83988963653F6883ULL,
		0x15AF5E148CE3741DULL,
		0xDA1878048D916C30ULL,
		0x2D848512268758C4ULL,
		0x880BF635825C894CULL,
		0x976D77FAC00CEC67ULL,
		0x72F4B98F3CCC8E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFBA0906C5E2908ULL,
		0x4B17342DD0E5A543ULL,
		0x6ED83441E6498FE6ULL,
		0x643BCD4739F8F600ULL,
		0x235AAE4C4B2B9239ULL,
		0x397650BC185972BEULL,
		0x091F2DE1CC8968AFULL,
		0x3963CC387D5F0A0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35EBF0324DB00877ULL,
		0xE2B7E53B50CF1C55ULL,
		0xC6762986CC1F7192ULL,
		0x015FE59DBDDA0FC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBC1C075FB50A6836ULL,
		0x4EA94006E366E427ULL,
		0xA77CFC22B0641979ULL,
		0xCAEBE45EB274CB97ULL,
		0x0F9D59AE46EE6AC8ULL,
		0x52F81BCB8D7CD5F0ULL,
		0xAC8FE0C2A904D274ULL,
		0xD3049A57755C4D0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8440F159185A33EFULL,
		0x39D2C42938B3830DULL,
		0x2AD63ED97AA5B711ULL,
		0xA6276D44046E2193ULL,
		0x6EF92FE48DA4A61AULL,
		0x8E2E4E1737D282FEULL,
		0x9E7C2EEB0F3D439CULL,
		0x0CB6D248CD9FB539ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x103949F81DA36A7CULL,
		0x4ACB04A261FBB0F8ULL,
		0x9393234A095D966FULL,
		0x145029479405330CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAFACEF714BBC6597ULL,
		0x82D7536C5C7FABEBULL,
		0x79E974130E354F2EULL,
		0x36977239F4B5255BULL,
		0xF6D78E6EFB306E24ULL,
		0xF8402C6B93BE4A40ULL,
		0xC9963126EAE94873ULL,
		0x107F5C125D71A9DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BA71E87E7EA2FE7ULL,
		0xD520078E9E499607ULL,
		0xF9B00475184772BDULL,
		0x686857CC9FB2D88EULL,
		0x34105DF389112043ULL,
		0xDA11D74465A3159BULL,
		0xB984EE64D33BBC93ULL,
		0x2004B11524076664ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D97033C5477C4B7ULL,
		0x2897EFAE963FE67FULL,
		0xE2C9586D79B09FB5ULL,
		0x00647C03DAC850EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC7BB04A6FF8FF34AULL,
		0x285904659E8A6C29ULL,
		0xD540DFC18A78C792ULL,
		0xE26FC8752690A64FULL,
		0x21F9A47DA8999185ULL,
		0x5DBFD472F0C7E757ULL,
		0x8B0EA384BEC76A40ULL,
		0xC3B7D88D7BAC978AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17D82EF256929986ULL,
		0x47EFC7888498DD11ULL,
		0x4DD06D07B678B57DULL,
		0xCD45C0F09523B14DULL,
		0xAC12C9F54DF85327ULL,
		0xA7596EB9B46C95A9ULL,
		0x5C72F82CC89F3963ULL,
		0x3D579C9B39FE33A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302745F21CEC9EB0ULL,
		0xF39C565C0F7FAED8ULL,
		0x728BE1C85DF752D7ULL,
		0x0772ED7A514FC979ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x42FA4F42217B232EULL,
		0xC682FAB693705E80ULL,
		0xA25C2A536CBDCC43ULL,
		0x4131EDE2363F188EULL,
		0x0B7FE9437BAA4571ULL,
		0xA4AC48661BF485FFULL,
		0x1FBFF8AC59BB85F7ULL,
		0x3803863137FBABD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D8C664E28349C1ULL,
		0x0DD389DD7AFD505DULL,
		0xF222E08D9FD36493ULL,
		0x4C991755E0E1F7DCULL,
		0x5720893CB0835149ULL,
		0x5165A7CAD3B26C25ULL,
		0x10EE4420FC7D20D8ULL,
		0x5C217EEBD276F83CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3849C9DF66C0168CULL,
		0x152B47E5D242E473ULL,
		0xE35A1675A42D6A57ULL,
		0x1825EAD9670FC91DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x20785FDF44B56AA0ULL,
		0xDEA5782B5748AD4FULL,
		0x40CF6F161F8DA13AULL,
		0xAF49DEDB1432E3C6ULL,
		0xABEB0C9AF45EEC43ULL,
		0xE80C9B5E7555D5FBULL,
		0x8D98C7C89DB1E171ULL,
		0x985ABD4B92430C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12A15396473F0698ULL,
		0x01F37DAEDDEA40CCULL,
		0x854D28022F30BC06ULL,
		0x30027F1BC4543DFEULL,
		0x962E4310D4EFA561ULL,
		0x44FF2725FD8CDEF9ULL,
		0x3E866C7ABB077E2BULL,
		0x6C4C8E93F34DD942ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47DCF6C9A7FAEA9EULL,
		0x10B13ADE413316D2ULL,
		0x783BD4A395A7A1B1ULL,
		0x09624F00E8443125ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x001813A79F433497ULL,
		0x222AD17368112331ULL,
		0x85BB6E3FAFA12578ULL,
		0xAE0AD47E56AB6B1DULL,
		0x0E7451712F199BF2ULL,
		0x8EE90B25D10BB0E3ULL,
		0x8C7D23195ED9E5E1ULL,
		0xF95BE44C66F1BEA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9F9774123CE0F5ULL,
		0x28F994082AECE3C8ULL,
		0xD7B6DA3AE568B337ULL,
		0x135BAE8B99546E5BULL,
		0x41E2BD4B98ED90C3ULL,
		0x14FF01C10C3AC57DULL,
		0x1EAC37D7C89D9AD5ULL,
		0x0021FD7C8BCA8805ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE1479C7D790022DULL,
		0x11EEA26074273084ULL,
		0xFB077FC1172B961BULL,
		0x194768CD45291929ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x302946F0C4D309CDULL,
		0xD962F7FFDF89CDD0ULL,
		0x763104ADE822B397ULL,
		0xD836B5787D1FE0E3ULL,
		0x3951CFBB5A18CD61ULL,
		0x78F7F99224FDE0C4ULL,
		0x353E3E24A1205006ULL,
		0x4C418881770543B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x232E3F704FD83B46ULL,
		0xB9F3DE23ECD16DB0ULL,
		0x22766F19AFA4F51EULL,
		0x176635366B43F397ULL,
		0x22FFFEE2A0BD647EULL,
		0xF12B3ACF50FEFAC8ULL,
		0x21A160E1CD5C6DD4ULL,
		0x575DF852E3DCD318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D2007ABF88C6013ULL,
		0x47D36AC76A8E838BULL,
		0x3D036D7FA79151D3ULL,
		0x1A97E72BE9DCA4E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCCBB188F76E6F906ULL,
		0x9EDAFD077704A5E4ULL,
		0xA502A8DF0657D7ACULL,
		0x7B36FA4FD311131EULL,
		0x09B447688432AA5DULL,
		0xF20E44DDE187EE8DULL,
		0x89CF2C637F87D31EULL,
		0xC551A15D1901EBC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x265CB97CE2FA06E5ULL,
		0x75EEC35C814E6316ULL,
		0xA20E83352C15F639ULL,
		0x48DBB26FF684FEB0ULL,
		0x0E715AE9B9E671ADULL,
		0xE8412595C81E1668ULL,
		0xE2EE763ED4356244ULL,
		0x9AA7530364AE5149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF24D79E49B3D5D38ULL,
		0x9D5EDE5EBB6C584BULL,
		0xC84F2F1B487EA1D0ULL,
		0x07A2E930A0F5033AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x209A2A231299FD06ULL,
		0x71D160DBA2F1EF46ULL,
		0x4BF1E11BF61A48B5ULL,
		0xF7E1CBCCF38115FDULL,
		0xA41891A75F95081DULL,
		0xF0165CAA06F7C863ULL,
		0xA6A52CCCD9477E6EULL,
		0x11A997B67B7387F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEFF255186D5E924ULL,
		0xE96E195DA7846D2CULL,
		0xD5C153DA7421046AULL,
		0xB9852D48F93B0ACBULL,
		0x9E06DF0D221CC58EULL,
		0xC9C262FD426D6F84ULL,
		0x60472129A720EC5BULL,
		0x269290A3E1B99A62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x483B87B6AB9DF4AAULL,
		0x38DA572327F6B334ULL,
		0xE826477AF3B2F322ULL,
		0x23C7AB46CBDF4F0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x12F3C856E0753757ULL,
		0xB06DD326D9028077ULL,
		0x59504D8E9E7B8C70ULL,
		0x9227DD5327FDF2EEULL,
		0xBB7341EAE926F221ULL,
		0x75E528846EF20656ULL,
		0xD7DA6D5832D47895ULL,
		0x1ED3641DA2514CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52AEDD79C26F9DBULL,
		0x04FE8A0B91B375ABULL,
		0xFC004DCB73297569ULL,
		0x777B3351D4CB0B79ULL,
		0x4722390885CB9141ULL,
		0x09987A6C8ADD8B1FULL,
		0x60006773A8C0B2EEULL,
		0xBB5922C0C89451BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81D02C1A03DE9B3FULL,
		0xBED120A722595506ULL,
		0x27ACDFAFAA416DE1ULL,
		0x5ED25DC9A5403164ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9374FED756AE8E0AULL,
		0xD27096E784C9DCC8ULL,
		0x88E38C57D71FD7CBULL,
		0x571D16D4848B039FULL,
		0xB2FCD0A0DD329C48ULL,
		0x7FB96F078AD0617DULL,
		0x05CB3E3DB6FDBCFBULL,
		0x1FE93A7EC6D63D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A734CA2562EAAB0ULL,
		0xCAB4F84426561DCCULL,
		0x7EDD2AF48687756CULL,
		0x41A3A26AAD133BDBULL,
		0x97A6685C80811C90ULL,
		0x599D5D9C50C2B0A9ULL,
		0xEFAA5E191CEA2ED6ULL,
		0x44D298596823E173ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57D52C5AC2D8D7D9ULL,
		0xAFE6348DFC7BFE78ULL,
		0x52E7A6D22F7F7BE2ULL,
		0x1AD585F5E5F1685BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x293AA2B7075B4E5AULL,
		0x5572E652DD2E7A6AULL,
		0x73AD6B0A37D13554ULL,
		0x8BC1EDE7A982DCC0ULL,
		0xA9C0A0E28C6BE14FULL,
		0x4222F4378572D731ULL,
		0x6FCD1504BD012B61ULL,
		0xC17E56FF5ACF92A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CA43942DDD008CAULL,
		0xAB25DAD09A96F905ULL,
		0x43A84B05646BDF10ULL,
		0xAAB035245869396CULL,
		0x8C922CF04276ACD7ULL,
		0x9CCAB02D3C06E586ULL,
		0xD823EE6A690440D2ULL,
		0x40F627401286F792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x717B9F6B23F1121FULL,
		0x35672509289D60CBULL,
		0xB320DAED4AF02770ULL,
		0x7548CF280BE0A8AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x19EA96EEDC8934D2ULL,
		0x992C938A7B1B921BULL,
		0xB7771C00D150BF3DULL,
		0xBA987659FFD64772ULL,
		0xAF6E87FC75966815ULL,
		0x0FCB27E2C983DFA0ULL,
		0xE96F6A421823E049ULL,
		0x43881124E9A9A35AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D22D7928301DFAULL,
		0xD57235E3804FB88AULL,
		0x14EC6CD039368AC8ULL,
		0x65C006B2A3D90E06ULL,
		0x9EA5AD86CDA4B6CDULL,
		0x1D5A82F3E6F7C978ULL,
		0xC39007D961854ADEULL,
		0x07A6C056C80CAB2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66E8D6ECA23968DEULL,
		0xC072D91C9B972383ULL,
		0x41B34ABBB3A46254ULL,
		0x384A6E40594A0FFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6FB4ABF2D8202CC6ULL,
		0xE6266C203EBF6123ULL,
		0x8FB797AFB0348751ULL,
		0x01B3EDCE6B0ACDBCULL,
		0x758A94E0772F8427ULL,
		0xE777785EF67A7917ULL,
		0x0D7601086248A69DULL,
		0x61FB8ADAFAE1C803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CDE0BEFBF05595AULL,
		0x89B6C53D27D86E1EULL,
		0x78EB9BB26E43BFD7ULL,
		0xBE4814AF089A2EC4ULL,
		0x553212808C8B34F6ULL,
		0xD507F9878F9E28AFULL,
		0x6367D8EE3CA118BCULL,
		0x0AF85A74B227886AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FF9FA3FED7E967AULL,
		0x18FC7ADC5B9AE27AULL,
		0x54E5EFDED8CFD6E3ULL,
		0x2DE5084E2E160FA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8722321D741D276CULL,
		0x643B00ACBAB4E67BULL,
		0x5171B9A7E4D6F902ULL,
		0x4123BCDBCAEE4EDCULL,
		0x8593C4A9E9D20807ULL,
		0x0E20652BAABD6B55ULL,
		0x24606E3D362ECF9CULL,
		0xA590A39B66A9F0D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA78D62169A0A2FBULL,
		0xF415BE3853A80048ULL,
		0x7E1E4562C1A6E479ULL,
		0xA25CC0409D200CC0ULL,
		0x1F40EFFE69D9DDF4ULL,
		0x4ABE629151D6C201ULL,
		0xC41628C2C4757D9EULL,
		0x2C2FA047BD78771CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCF4ED710952C5DCULL,
		0x70B1A55D994A08B9ULL,
		0x1E59C47204B24033ULL,
		0x232D7B064B2653A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x60873C9C53528E47ULL,
		0x26C2031B9D38B79EULL,
		0x212B3FDA65775864ULL,
		0xD885F47499C12021ULL,
		0xB6B5F8CAE2920FBCULL,
		0xDAB4F26246951F38ULL,
		0xDA7DB9933F2904A1ULL,
		0x20E3EC4F58D79017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3093B6A086107E72ULL,
		0x07BB7ACCC0097D4AULL,
		0x49047EA0DCA8470EULL,
		0xA9802C935F6CF29DULL,
		0xF302B2E7367E6305ULL,
		0xF436B360EDEAC858ULL,
		0xEB7844204160C004ULL,
		0x7E00A9E98837BA4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C8FE5C7582DB0EBULL,
		0x55C3E28206781F8BULL,
		0x52F6304B348940A0ULL,
		0x5CC1A2FE320DE9A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x905E5A9D78BB9EA1ULL,
		0xE8C65B9412EB97E2ULL,
		0x1E4203A1B8617C50ULL,
		0xFD677E510BF01F90ULL,
		0x3BDEF71DBBDCDA74ULL,
		0x08831E097C0D9880ULL,
		0x4D511BF34151493AULL,
		0x6E61CE92EAAF7F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77366B54613D3F81ULL,
		0x84A60C25F9FB5949ULL,
		0xFBB4A28B7EA7A8BBULL,
		0x00D71637C045F0ABULL,
		0x0CB1C0E05FB6A316ULL,
		0x62417367208E32F8ULL,
		0x8AB85AA9A4BD91EEULL,
		0x2133D05B261265AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19DDFC64C52A98DCULL,
		0x11DFA387ADD950D0ULL,
		0x053A120377A708D0ULL,
		0x716424607AFBF5A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x914425A9E83C4CFFULL,
		0x83880FBDF38B3D7DULL,
		0x1A2415FFCB71F5DAULL,
		0xCD8C8648AFE05118ULL,
		0xD42B8F67A9EBD259ULL,
		0xFADAB5F008A1EAB0ULL,
		0xF43BB1553543E48AULL,
		0xC04F28D0F3E738F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D7613833617663ULL,
		0x294F892C2C069F56ULL,
		0x5A14AF346F3EB3A2ULL,
		0x79200A5E194CFF65ULL,
		0xC8BE9B599E81F92DULL,
		0xBE06DB60ABE74A00ULL,
		0x5D099D80DF14CA8CULL,
		0x3AA90A45A658FA48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF98FE876691161CULL,
		0x61AAF7D98B387848ULL,
		0x317E585027311DF5ULL,
		0x2B15049819B09F51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC625FAE413BE1EC9ULL,
		0xE524D286DFC39AD0ULL,
		0x0760F0530924A194ULL,
		0xCADF78EC0C206C59ULL,
		0x683DBEC89CB7C485ULL,
		0xEA80ACF5E69CC4C3ULL,
		0xD49AC08219928EBDULL,
		0xD7912A4B3A22F880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB266B42CDF92579EULL,
		0x7F20E2A40126A622ULL,
		0x59DEEE343BB4E4F9ULL,
		0x7036DEBCC143C788ULL,
		0xFC01105B9D140753ULL,
		0x82D43E84C0CF3D29ULL,
		0x6D9E2DBA40249E8DULL,
		0x41FE7623224354DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24C12AE52679DFEEULL,
		0xC99C54AE7B1F1574ULL,
		0xF6FFCBC913C163CAULL,
		0x0E6F5822D60EEEC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBA079CC677355998ULL,
		0xC51721C64D525A14ULL,
		0xE398D58489E9F8D5ULL,
		0xAE097C520C06B9EDULL,
		0x6CD2F1E76F065DD1ULL,
		0x097E4EE0FA91516BULL,
		0xB736CAEA531246B0ULL,
		0xBC33B6F7235D00BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4200D60CF08640ULL,
		0x3B9D8EE8F9622A01ULL,
		0x0B927C3121EECBC1ULL,
		0x841031B1AA8EF86EULL,
		0x01A18146CE28C705ULL,
		0x4301C43E0D3CB33EULL,
		0x565CF83CDEEFD56DULL,
		0xB29BEDECAE87DCCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x261C53C84B2935D9ULL,
		0xFFF6270C8E7FAAD1ULL,
		0x385B9F12A517FCFDULL,
		0x1681222DB91B1708ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF7EF0A068A904DFDULL,
		0x1C64A50BEF7F7F47ULL,
		0xB2387246D4C95352ULL,
		0xE505792DF98CD8ECULL,
		0x8001F07B1118EBE0ULL,
		0x136ADC966F0BA5AEULL,
		0x1850943244B3C114ULL,
		0x738AC551221A8DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEADEFA3FE473A8CDULL,
		0x04F20C7FAAB380EDULL,
		0x6D52384EEAB76248ULL,
		0x206C6961BF5A1248ULL,
		0xF621FAB4DDDBEA9AULL,
		0x92584F2FD934388DULL,
		0x90E305F862B6BB49ULL,
		0x5CC12EEA222C9C42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x844E8B32412AD62CULL,
		0x403395C682C6312EULL,
		0x5F29568F75A0CD19ULL,
		0x2685631637849EFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6999F6469DE8B5B3ULL,
		0xA09F811A088EA743ULL,
		0xBA08142CF3E41660ULL,
		0x9E98921B93F7BB7DULL,
		0x1B4E3544850CB903ULL,
		0x0CF0C02136BCF495ULL,
		0x0A3D8D87B6E75C7FULL,
		0x76E4E4F34C92B944ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1817550E635940CULL,
		0x39325010D475D152ULL,
		0xC83DFCD1EFCEAA44ULL,
		0x503F804757E35732ULL,
		0xCDB8ACD50F077AACULL,
		0x3599E11542B1A9FCULL,
		0xC43ADB8A0BA90EEEULL,
		0x9241F3CB87406897ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C4AC1813C7A61F9ULL,
		0x5E524CCF6DC5E88CULL,
		0x563083026F54EF9CULL,
		0x3E88DDBB864C5DDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE653320DB4F16079ULL,
		0xC324FEEBC23C4C3AULL,
		0xAF87853A7BBEECE2ULL,
		0x4E8746F4C7E75F8BULL,
		0x313EAF8EF3BE6647ULL,
		0x12C93241666801B8ULL,
		0xFDCD7A40F13AD2B1ULL,
		0x9C12E5D7EECE471BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1578AB523D3807F5ULL,
		0xCA77DFDD4EC20285ULL,
		0x801952C76A8C9045ULL,
		0x7D1CD3274F60FFADULL,
		0x596927540BA32B8EULL,
		0xE927D95FF748AF8EULL,
		0xAFA6229D0C37024BULL,
		0xFE36FA6869897C57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA8CBF79EBC40DC0ULL,
		0x26A05084F2207BEBULL,
		0xC94534C70FC34BA1ULL,
		0x400F665B40BC7901ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x17BCD7167BF7D8E3ULL,
		0x99937E98BE6B54E7ULL,
		0xE707E122BEE41E71ULL,
		0x94AAB196FA413485ULL,
		0xD204C080EECD4CF8ULL,
		0xA98900C2020E09CBULL,
		0x87ACC878B765D0FEULL,
		0x36A77D08BB760B8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0C3F465BCAB0BCULL,
		0x7EF7FF5F25591B1DULL,
		0x0CBDF2B4034575D3ULL,
		0xD1AA6B9BFE228840ULL,
		0x933BFCEA845EE308ULL,
		0xF8D499C92E73ED39ULL,
		0xA40C86DAB9A3633AULL,
		0x16689679AA4CACC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA7DA023EC90E272ULL,
		0x5562C82901F2777EULL,
		0xA413ABE2667AF3AAULL,
		0x0C567F378842BE17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF40A077234BD9337ULL,
		0x76639544EEB3FC9BULL,
		0x1EC3189A116B2003ULL,
		0xC17DFEBD98DA816DULL,
		0x03F5BB19D9CF1288ULL,
		0x4217AD1A4FA0EC07ULL,
		0xB284A7F8E994E525ULL,
		0xC03321B529E4ABFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CF8EEE9C61FFC4CULL,
		0x338FD5100753FCE2ULL,
		0xF033CF891C84AD04ULL,
		0x389F63501AC58730ULL,
		0x65492A740507A886ULL,
		0xB3803E8632338915ULL,
		0x22A2DE9BA356D569ULL,
		0x847EB2EB005D1D7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14AE91260437548DULL,
		0x6D4E2A31459CAF97ULL,
		0x8A132CE9621CC8D6ULL,
		0x65A70D6FA83421E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xAFDF2519409F8D25ULL,
		0x07A6B2F07FBAD99AULL,
		0x123A8C2935BE3160ULL,
		0x814E64F282A1FE40ULL,
		0xEA4EDF72A0F036A7ULL,
		0xAAAF21FA0A5DF733ULL,
		0x24B6BCF2676EB822ULL,
		0xF95D36B22730E96AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x360FDF5BC6E05DE1ULL,
		0x23DBBCCA3366EF2CULL,
		0x912214F12C6C777EULL,
		0xC77C3AB1C41125DBULL,
		0xE46366FD40B88413ULL,
		0xE540E1A8080BAFEDULL,
		0x9F854D09FED1A4D3ULL,
		0x1269670FC5F2A6C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AC32729C203B648ULL,
		0x32288252A48A7ED3ULL,
		0x466F13B790A29793ULL,
		0x0202FC5B2DCEBCD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0202D68D80E541F9ULL,
		0x542FF6AC18E2AD8BULL,
		0x2387118B969DC522ULL,
		0x05B949A9B0D2E849ULL,
		0xB6AEFDFCB04A0F1EULL,
		0xDDD25EE50035D5DFULL,
		0xFE247C718EA7A837ULL,
		0xCE23CB2ADCC3CC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E478029256CB6BULL,
		0x897F607FA2C0D053ULL,
		0x5D01313D180E1C8AULL,
		0x8C49D14071591BD1ULL,
		0xA85BFFE484D6C96BULL,
		0x06A3DBD1D457D946ULL,
		0xADBE0DDA51C81654ULL,
		0xC3DB2C843691311EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D70162161AACF46ULL,
		0xBB980B04F9155BF0ULL,
		0xB5BA4AC187BF5069ULL,
		0x00370525EAFCCBFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x81A987E679A5663EULL,
		0x1D320EC2B4107FD4ULL,
		0x998EB27A583719ABULL,
		0x8A02CB43E9B57C13ULL,
		0xA3C530C06098425DULL,
		0x3B9DEFECF60EB36DULL,
		0x3B115950E7CDCF8AULL,
		0xE2F57C554C46CC41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2619CCBC135829ULL,
		0xD92D248A57197BE2ULL,
		0xF96C65D445E8A488ULL,
		0xFA4B958B0BA02CF8ULL,
		0xF97147E4DEC395F3ULL,
		0x0A2883F0569E4D4AULL,
		0x2EA874F7B4F5C4BAULL,
		0xB3CA6F1EDB0634DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBF7FEAF0323A6C8ULL,
		0x9B72F1B807A62D17ULL,
		0x77B431E39E601009ULL,
		0x101B2BCDADABC7A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF9DF9998B8F06642ULL,
		0x742D8EBAED2887DAULL,
		0xE8B2044ED81941F3ULL,
		0xD1C8182F60D28D94ULL,
		0xE719A9403A88694AULL,
		0xB4C8937B13574D27ULL,
		0xC9411B6CD4E3D633ULL,
		0x7B97B806F842D04EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14710CEE67199D72ULL,
		0xF74CE96CB9629085ULL,
		0xD73A9D001FD0D2E0ULL,
		0xFA78065411EFD24AULL,
		0x36F7EC4BFC530BD1ULL,
		0xA1EAB64EB277AA22ULL,
		0x6F5FDC7D8E216CADULL,
		0x4D7C44B2FBDFFE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A7098EB8DC2A9BDULL,
		0x49CF79E494F82A2EULL,
		0x68E6BED3392418F9ULL,
		0x2F633052C58DE5B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE160883C56A7436AULL,
		0xDA8052BDE699E667ULL,
		0x4614179CDB2B14F6ULL,
		0xE1AF3EBFB67A753BULL,
		0xD10433AE9DACADD0ULL,
		0xD516C34BA88E96BAULL,
		0xD291AC03B278CC26ULL,
		0x12783AB8DE2282F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA27B0302730D3475ULL,
		0xCC0ECBBE2056A73BULL,
		0x532A99E13D6D9AE9ULL,
		0xD3297FE7BE3AF2CEULL,
		0x0DAF4BF3A897D662ULL,
		0x9363415585F84D2AULL,
		0x98C4AFD615C00F50ULL,
		0xCED601AEB17FE5C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D7FEAFA44B20521ULL,
		0xCF16D188E8922AA9ULL,
		0x8756EC80E12981DAULL,
		0x189A365A9862D749ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE63E61D6CC4898F9ULL,
		0x320571B9EEE15620ULL,
		0xB907D8B35D822FF8ULL,
		0x619A9BF637A28C95ULL,
		0x2333819C36F46B8DULL,
		0x7E9CD0536985A2A9ULL,
		0x80F1A80947258BF1ULL,
		0x3CF4E1950FCCC1ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56B42DBBF205B2EULL,
		0x738FDBB48D78BEB1ULL,
		0x878FB5B1D5EACA4FULL,
		0x0DD5A21D62EFAF5BULL,
		0x3932FBF2A59C6C7CULL,
		0xA6519492B96E0E35ULL,
		0x2D67FE382EB24933ULL,
		0x47A3FBACC5C38DDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCE6F626A0381A18ULL,
		0xD9A0749F84E8A0A3ULL,
		0x97E7580B28B34DD6ULL,
		0x3DC71A53D21097A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x43859161A30CA2EFULL,
		0xFBEF962F654183B6ULL,
		0xF5C8307E453A8A40ULL,
		0xA7B243101501E258ULL,
		0x749D1BB6E735540DULL,
		0x13ACDCD038E5EE94ULL,
		0xC3900F1B0889983EULL,
		0x0773F62DD0F9EF5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6719A7DFCE4D92AULL,
		0x2A1A2FF07DAD0472ULL,
		0xE64BF9272979E76EULL,
		0x11D3C8E9DC230A0DULL,
		0x5F8E108205E85865ULL,
		0xE72986241D69296CULL,
		0x995EF61FD7728AB6ULL,
		0x77AC436512AAB2E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D4FA0BD17952242ULL,
		0x6D5443CAFC19C336ULL,
		0x52C5ECA0652CA4E3ULL,
		0x6D8303F278A1D247ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC7F4E49D0B52B501ULL,
		0xC98DEC6311BD4F4DULL,
		0x286A6316D4DB57EDULL,
		0xDEE2F52C60A30119ULL,
		0x9CD4C5B61E1363F4ULL,
		0x124FBE97D1FDAE05ULL,
		0x8968F2289A0C60F5ULL,
		0x910DB95D09A12426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C46A11A18E353AULL,
		0x874A986C6EFE71CEULL,
		0x3B16DB0FB63435F4ULL,
		0xAC60E28B48C0385DULL,
		0x920BC710183512F5ULL,
		0x17703A6F7BA020CEULL,
		0x90B8AB15F94D55DCULL,
		0xED271FA3D32C0C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE06473048C483A0ULL,
		0x7F70F1F374A1D3AAULL,
		0xD77E14CAFB02C7AEULL,
		0x06BCE41F2D444FF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA73EF58205565FD1ULL,
		0xE335BAEE250E4D7EULL,
		0x0D5D861519EF72B2ULL,
		0xD4FAFE18C9837450ULL,
		0x62085C120A30BC49ULL,
		0x60B800A1E3F1A7D8ULL,
		0xCAE62DDA06F01C30ULL,
		0xF3F31297FA539EA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FD6892341180F14ULL,
		0xA1D08A510BCC1E00ULL,
		0x7BE334A19C1AD000ULL,
		0xFE3300FC4CB756CDULL,
		0x30FC028CBA59AB4DULL,
		0xB0B355F08129E989ULL,
		0x6FAB8B4ED06ABB3AULL,
		0x86C9AE5476BB4A21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F3DB6289E2AD885ULL,
		0x621686F1C2E86F3FULL,
		0x1C2E721D95A1072AULL,
		0x0AECDF220568A9C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF3AAF7C825408733ULL,
		0x4CCA056DA77B4C3BULL,
		0xC2BA17BA8E826557ULL,
		0x9A93AA43584B7E37ULL,
		0xB07CC912DC5DDE99ULL,
		0x92D0D84E3380D0BCULL,
		0xA5E89B3541B28037ULL,
		0xCBAA8D1AB0B69CC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2514EE597FFED75ULL,
		0x6E24A078F77674A0ULL,
		0x81EDF937DE900760ULL,
		0xD925DC37D0DD27D5ULL,
		0x455A6801A1C035C5ULL,
		0x290D55751B48DE6CULL,
		0xD78A73D76364E7E7ULL,
		0x589AADDA9EB4692CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF874117140A7ABA9ULL,
		0x91AAD12E4852CF8AULL,
		0xE2C5F671AF76F9E6ULL,
		0x55C8F18E33C1FFA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFF871E1229728943ULL,
		0x08BD7B43315A6FE2ULL,
		0xDB787C24A1F874E8ULL,
		0xE0578964F881B228ULL,
		0x42406168D2C86403ULL,
		0x6D9AD4E964604B33ULL,
		0xD9F683EFB85D6927ULL,
		0xFB7F1C533067046DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3404ABBA6613FA34ULL,
		0x8EAECB72CEDA398EULL,
		0x4491F84FCFC4145BULL,
		0xE5F143A0D7F8D48CULL,
		0xDCA9621A03887910ULL,
		0x34A0CCDABAABB034ULL,
		0x25D06DCE973C49AAULL,
		0x7659659D4B3DF3B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFEC580A86DB7206ULL,
		0xEF2BE1FD934F3817ULL,
		0x548DCCBFBD1F0D22ULL,
		0x3DFF64C424A158BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6DE7058CD870CEBAULL,
		0xC018F9CC1C3BD22CULL,
		0xD6F726A1EE4E090DULL,
		0x26346D0C73B42638ULL,
		0x8F4CA79253D25742ULL,
		0x65678A8BA1F8C691ULL,
		0x2145AA1DCD132968ULL,
		0xFDDD0DFED0600BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120A74F5F607D9DAULL,
		0x4C5B4CEAF7EB61B3ULL,
		0x58136913C4244EAEULL,
		0x18E59213FE2F202AULL,
		0xB06421153B8C67BEULL,
		0xBA6787FA11AF5B65ULL,
		0xAC9AE4343F44B5A4ULL,
		0x920E9F3E3BA6F7C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x726087287CCA84D8ULL,
		0xD5BE0E7C8F3658FCULL,
		0xD03D1E3936CEE96AULL,
		0x0DF34B8E88FE0189ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD01E57381E9C63E6ULL,
		0x3E6CC906A08CA647ULL,
		0x4E384F0DCFA5AE61ULL,
		0x6E4618460ED07107ULL,
		0xCC72CB1441283ACAULL,
		0x2A546241FB01DF60ULL,
		0x01ECA4DC52ED680AULL,
		0x36AE4649FAA16AEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF876B6EDCC023F3ULL,
		0x0DB7732551AA0BACULL,
		0x7866C01EA314AE08ULL,
		0xCBAE8143A5B9AA9DULL,
		0x190D4358E0D86FC7ULL,
		0x894CE22D4A3F18C4ULL,
		0x7BCF4599476922FFULL,
		0x54A77B0B83658E81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91A911998DB461A7ULL,
		0x17D258F38BCC15DDULL,
		0xBE2DB2E2E2333FEDULL,
		0x2F99C2481BF97E13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7D3F1D5FF2D388CFULL,
		0x5E7638F27697051EULL,
		0x30641913551F0D6FULL,
		0xC4F5BFB80268C556ULL,
		0x04A0243D6996F404ULL,
		0xD7343E4F0A519E79ULL,
		0x99988C65D0FF3C80ULL,
		0x1289DC9D09512908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCAA933A3FD2AAAULL,
		0x2A4B0816F61842F6ULL,
		0x6A3D65E048584E8FULL,
		0xCD6EF963E9AD15BCULL,
		0xFF87318A07F4A0E1ULL,
		0xF6FC509A8693C6A6ULL,
		0x6B4A5DD98163E823ULL,
		0x52B86133FD69C5C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23287ACCCCEEB3DBULL,
		0x7C7879A70EACCB55ULL,
		0xA5C19C06DDD544A9ULL,
		0x709F17EBDD146C50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x338784C1BE9344E6ULL,
		0xED6181D096844FA1ULL,
		0x8C6B101E791D3444ULL,
		0x7A9607F95DA0CC72ULL,
		0xDD969F65CBD3D2EFULL,
		0xA0A988B18EB0E38EULL,
		0xB64F15DECEA8EF3CULL,
		0xE9423FCA30F2061DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEBA9BAC28A5C9ACULL,
		0xF1655F797ECC026DULL,
		0x58610EEE26F26038ULL,
		0x97FB23D46BD91A7EULL,
		0xC37109CEDEEDE3C5ULL,
		0xA9D0DA906D66AFECULL,
		0xC90102FAF4D54B7DULL,
		0xD96F1435B1FCE69CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26611D7CC00EFBC2ULL,
		0xA025FB4208BBF743ULL,
		0x6DA0CF02A7952264ULL,
		0x3BF35C2FCA2A5F17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x87CFFC39F35FF3A8ULL,
		0x46212F772C138CC6ULL,
		0xAAC3C08BD0C46838ULL,
		0x331E3AB12BC831A5ULL,
		0x79236F1887700A00ULL,
		0x766D5EE527E0BB42ULL,
		0xAEEFEEBBCAC196C0ULL,
		0xBF93BE05D43910A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB49D60998F1259ULL,
		0xF7CC33ADC80BA5B7ULL,
		0x5E3271F6CCA9AD2BULL,
		0x682964655799A05DULL,
		0x1400A5B4233EABD4ULL,
		0x52C358085B6E2D65ULL,
		0xDE5D662DA857766BULL,
		0x65EDD59228BB5FD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB4543C03924DDC5ULL,
		0x9992008FBD08F5EBULL,
		0x425193AE1FDB87AFULL,
		0x1995577748D6CFD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5CE88352FAE29BCDULL,
		0x49F54C4CB8584E97ULL,
		0xD56AC15A9EF33E71ULL,
		0x7C8A9C232C75C766ULL,
		0x26AA3C6EAABFDBEFULL,
		0xE01583C0133942D0ULL,
		0xE3FC6489DDE28637ULL,
		0x8C5EB1E7B2944F32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3006E77B06F5FD8ULL,
		0x8816678006D5049DULL,
		0x505BF6D2DCC357A5ULL,
		0xA4E51CA98E7592CFULL,
		0x30A31B5B2EF2D350ULL,
		0xE51D9B046ABAA220ULL,
		0x091A19E5DCF88030ULL,
		0xD50917A8A9D800E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEF6FDBFAAE281EDULL,
		0x02AB70A7B44F2417ULL,
		0x02A5DEDFE4ECCBD5ULL,
		0x0E5A64D4E9F3D38EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4B483989871D31F4ULL,
		0x446FEEF799133B18ULL,
		0x295AF7D1BBBBA63DULL,
		0xF97D7AB3509EC632ULL,
		0x629F1DC8F41A7BB2ULL,
		0xB91AAFD4AF392EB4ULL,
		0xF03E2537438BEDE9ULL,
		0x79C46A877918EA7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x314211931A34C623ULL,
		0x9B59AD82F9118DB6ULL,
		0x5E7A68A5F1CABB31ULL,
		0xD8EADAF5EBF16032ULL,
		0x43EA7065C82C5469ULL,
		0x0AC63959E807FD8DULL,
		0x1084FC5789B6921DULL,
		0x57A7EE6226437872ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8D7E4AEF2424165ULL,
		0x899FD7AE314EF930ULL,
		0x005CA0615F9C8B6DULL,
		0x30CD0D47B05C5377ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x40C148AD48EAACCBULL,
		0x4C1DC4E95AE2A642ULL,
		0x2E25200605EDA383ULL,
		0xEC844D707FE470C2ULL,
		0x808B35ACF2461FD6ULL,
		0x8E4A47443A4B44EDULL,
		0x536D7855D2D36610ULL,
		0xAEF42FD43A8C5909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D4B6F8564516F29ULL,
		0xEF2E79FCB2EC3A15ULL,
		0x8A7A59BAA9A99D08ULL,
		0x50B8307D0A3857CAULL,
		0x873BCD11C3653E75ULL,
		0x0BE3814CFEB6E5C1ULL,
		0xAC04454C46182D66ULL,
		0x490ECB5A69D2778BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x153F6030D9FAB455ULL,
		0xB830AD9F7FFC8CB4ULL,
		0x7D4859B6400E6FC9ULL,
		0x3BD907087143919EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x13F84EC9162C30FBULL,
		0xDAED2EA81D80D9ADULL,
		0xF279E7338696FA18ULL,
		0x0772CC3E94EC28DDULL,
		0xE44DCD2C7C4246C9ULL,
		0x919BC8717BC70D95ULL,
		0x842C171DB55047CCULL,
		0xECD71CCC05FE5D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC91C8BA567E640ULL,
		0x0FC428F5E75E9AB0ULL,
		0x18F0CE8EF9C6FA24ULL,
		0x77029080A637A69CULL,
		0x5F9E07C6064E206DULL,
		0x0B748CD9B66F6FDBULL,
		0xA979AC8FBB9B64D2ULL,
		0x9C88C32279C1433CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA467F72F301FE05ULL,
		0xB4FBDE398123A8ABULL,
		0x5004E9B79DA9B124ULL,
		0x7C118AE8BFC6615AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x95D472DE94DB7679ULL,
		0x1871605CE67055E9ULL,
		0x4DFA946AAA023C8CULL,
		0x8AE9888504837278ULL,
		0x4C318CBEBFE6CC41ULL,
		0xD51ABA1D52CC1F03ULL,
		0xF1BB7256CC489B73ULL,
		0xE5ADF1345CA23D69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE6097C71A72965ULL,
		0xE7A2CABF5547757DULL,
		0x23D428FBD95C98EAULL,
		0xD16BED0C5D737532ULL,
		0xBE644B6E1010F3C9ULL,
		0xB3702D8F1839BCBEULL,
		0x3CC2ADA5D62EB355ULL,
		0x0718168BDC278EFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5661B5C3CF273B7ULL,
		0x301F72BA42E37698ULL,
		0x07139DB3587E181AULL,
		0x43BC107BB945E169ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7D5B817D30E1CC27ULL,
		0x99A995652D000284ULL,
		0x32DE71FDA68DDAB4ULL,
		0x3889458E53A69681ULL,
		0x8BF2EE46A4828C5DULL,
		0xC9E10FB96761D1F8ULL,
		0x8B86501E14E4B323ULL,
		0x263D5CF2188A3400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9841E41073154307ULL,
		0xB6450047D3205415ULL,
		0x5643B6F11A561D92ULL,
		0x0EF07BC56F218980ULL,
		0x09057C3E210265A7ULL,
		0xA927394B8ECA6094ULL,
		0x63F397E1C04B1283ULL,
		0xEDCA4AA5C68A5B32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54588AB042D243C3ULL,
		0xBEFA696B805A835AULL,
		0xBC6214011B0594E6ULL,
		0x0AAD811D107F3B9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFDF49EC504810DF8ULL,
		0x71FFF579ACD99078ULL,
		0xDC5A76954E02A24DULL,
		0xAF5D963FFD2D6531ULL,
		0x35ABD64212CAEB1CULL,
		0x61598689996E0C10ULL,
		0x8CAE951E98701DA2ULL,
		0x1EE69A7692293F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B3418F885EB869ULL,
		0xD1BEE6EFF0812859ULL,
		0x9CF2925914B87D5BULL,
		0x4A52122871A0E411ULL,
		0xD84B8E9987707B2CULL,
		0xE0A70A7758E8D278ULL,
		0xE5B0607DCCAF4A01ULL,
		0xB7514BB9B8C0A939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x608C003A2B8EEFD8ULL,
		0xBABF793F501EF497ULL,
		0x0923B41A77E98EC4ULL,
		0x4535341FD112BCE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF48522F607847D6BULL,
		0xEFA0645E7489631DULL,
		0xF50B9A9BE5AEC8E4ULL,
		0xD8EC719D0E2CA416ULL,
		0xCF1CE46A3FD4768EULL,
		0x1EA4383BB9D8EF6DULL,
		0xFE1FB04EE5C587E0ULL,
		0x7D4115BE460D0DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x565D1CE9F9F2F671ULL,
		0x5277FB40808C70D4ULL,
		0xCA5B12AC3881AA92ULL,
		0x3FCCF3B2DBEB105CULL,
		0x7F2B21DD02B0B85FULL,
		0xE8C2BE80109F4B30ULL,
		0xA60F97B1F23F3B26ULL,
		0xBF092117736AA80AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C0AE70320DFC08BULL,
		0x9CA07AF9128B5363ULL,
		0x3D142F3BD31C81D0ULL,
		0x556DCEAD765CABC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4618250E4E0F2DA7ULL,
		0x38F7B857400696BCULL,
		0xC12BC6FFC62F3485ULL,
		0x391349741DF03446ULL,
		0x137DF5E0EA234743ULL,
		0xADF060D837E26FDBULL,
		0xC2199472C0BE2873ULL,
		0x05EDF145C6AD8DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAD1C10CD8A7377DULL,
		0xE843C2F2E5476A72ULL,
		0xF1E2673D90922B57ULL,
		0x593B7B5CA59752B0ULL,
		0xC82184A29AD21C6EULL,
		0xD60747B649A3E45DULL,
		0xAF84A8A228325680ULL,
		0xACD84DFC3521BCBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAFF33413B744E12ULL,
		0x5D4DB06DB807E0E2ULL,
		0x916460B8DA5E3339ULL,
		0x190E0B031319EFC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4EBC757AB98B2394ULL,
		0x7127652BA91292EDULL,
		0x8805310BCCEAB50EULL,
		0x59F027808640AB83ULL,
		0xCD05808467EEF062ULL,
		0x26EA0E7200CFE961ULL,
		0x6AA672C9B390BB9AULL,
		0x7CE9D4C1C2B76510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BE878EA7D28064DULL,
		0xDCB0985FA9031A0AULL,
		0x0350A1F621A42B38ULL,
		0xBA195F043858445FULL,
		0x36C474AA2518F56AULL,
		0xBB913D0FC800568EULL,
		0x43778A08AA035129ULL,
		0xF30657E84459E053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x607BBEF628265B6BULL,
		0x83A5E1606EDF444BULL,
		0x55AB1BBD16445685ULL,
		0x179B50C50FCA1B38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x741299370BAB325EULL,
		0xEDAEB4833EC69993ULL,
		0xD80A170D08DF7053ULL,
		0xD8B271970093FB39ULL,
		0x811FB73A8AB157B8ULL,
		0xA719772AC6B55A38ULL,
		0x333B558C9ACD7FE1ULL,
		0x2AEBBBC16B2EF81BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83ED448D7471CCF3ULL,
		0xA06197E5A2BC351FULL,
		0x30994F99E56766A6ULL,
		0x225362F9B23043C2ULL,
		0xD3AF6A47F155502FULL,
		0x90153B40A68E78E1ULL,
		0xF3F6FC1AEDC18AA1ULL,
		0x84C211E89E02F7C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAED0C0AC5AE281D3ULL,
		0xB7EE015E61CFD751ULL,
		0x0B960E52D33E7130ULL,
		0x608E44CBC2EBC491ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB6A7ACD4C1BBB5CFULL,
		0x04DF6204CD65334FULL,
		0xAA9CBFED9800BE87ULL,
		0xC6BB4497391F480EULL,
		0x4E87A32396ACE2BFULL,
		0x7C3308B3EA37C3ABULL,
		0xE420066DA6139D6BULL,
		0xA2D75BDF4BE6E21EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x223FF8D9FB872FBFULL,
		0xD7777FBCA9D8DEB1ULL,
		0x211AC772ABB75FC0ULL,
		0xB1D819A0AC24F44DULL,
		0x9DA0C394EC63C817ULL,
		0x0FCC4EB1CFC33268ULL,
		0xBCA568C79952E09BULL,
		0xE77B3160A6CC525CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6ACE3280D0E7971ULL,
		0x44A77E9810D9E484ULL,
		0x65B55F20D0E565B6ULL,
		0x649179C30EEBAA93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x95A78E24436907EDULL,
		0x8615DB99CDC15C6FULL,
		0x9A6C20E6ECA3D126ULL,
		0x2C72BB6FBFA98A14ULL,
		0x86F7C2BDA8CE5CE0ULL,
		0xBD1D85AA0477835FULL,
		0x3DCD2D54D029CCABULL,
		0x67A1054AD94160ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85112D9D793694EAULL,
		0x3CA96E53DB8D5D71ULL,
		0x48113AC29191B0EEULL,
		0x35AC56625E5030B8ULL,
		0x1041383F205CB8B0ULL,
		0x32B0C8EFEB49D51FULL,
		0x7997E9788A88343AULL,
		0x66E12AA57D642FA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFAEEF4F0B10D223ULL,
		0xD59070E5AEFBDC8FULL,
		0x7242F8D6B10EC112ULL,
		0x1340D999042EA083ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEA29DCAD10DF0C52ULL,
		0x836FD028964980B4ULL,
		0xEFCF71CC14311912ULL,
		0x39C5FC263685D951ULL,
		0x5E51D97863AFC54AULL,
		0x880FFFB2311B86FCULL,
		0x2C99D324B67C2DA4ULL,
		0xFB34213C7D83A141ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4296A58C6814BACULL,
		0x715A58AA1334A9FDULL,
		0xB67C2AAB74FE8E68ULL,
		0x177F8CFB122172F0ULL,
		0x42D8E91A4EF6E224ULL,
		0x86D5419464D3EAC6ULL,
		0x5C5C4A6F9D6CA199ULL,
		0x69B52BD653A996F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49F4204B5DCF7B7BULL,
		0x40CDAFEAD5B606BFULL,
		0x227592025781544CULL,
		0x3B1EDC555AC1EE14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC92BBC5F23FE0E73ULL,
		0x0A16055A0B07D1C9ULL,
		0x439697AAE0A7AB8BULL,
		0x0104B1B7F7E83F6BULL,
		0x45A65C3B6B435B91ULL,
		0xA4495F1B54679B8FULL,
		0x2E72663B0098C956ULL,
		0xEE290581175D73C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE8A09102431D63ULL,
		0x0020F4CA7307024AULL,
		0x17EE886F773C0D76ULL,
		0xA58DC18A0C5DDECAULL,
		0xDF4C7FC2D6CD67E9ULL,
		0x9E2DCE27E4AB7802ULL,
		0x1F8C065641373B35ULL,
		0xE14F2C5E249BC1DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F99D5B42B3D1C26ULL,
		0xF20C94B22DEE1656ULL,
		0x61DA4B2FD1E6B6FBULL,
		0x43CD2B5DF44AC9F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7E8AE05F81584ED6ULL,
		0xBAF9B3C09B142FA7ULL,
		0x772489ADD7D6DB36ULL,
		0xAEEE6F5B1A7AA728ULL,
		0x1E6B0FEEE81A8B35ULL,
		0x5D29DFB2EC4D051BULL,
		0x291D88BB8A5125EBULL,
		0x226FC7EEA3E7A68AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20573F312A4C2771ULL,
		0x886F8D8B30514F6DULL,
		0x86CC924056201DF8ULL,
		0xEF3401FECA124B04ULL,
		0x8C80156C5D613019ULL,
		0xAF9AA324E0A9811BULL,
		0xD0248D947F0127B0ULL,
		0x76AD8ECFE1B2172AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0714D08EEE8FAB9FULL,
		0xF5CD234B2508782AULL,
		0x254D3F392F9679F3ULL,
		0x3E8EE7ED245BA44BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE00FF7957D23E6C5ULL,
		0x740842D27C93D1CAULL,
		0x818205F00AF3FFE3ULL,
		0xBE250B4C94FFB8C0ULL,
		0xEC8504D78A50229AULL,
		0x7E4B06D96DB48267ULL,
		0x52533EEA9F30613CULL,
		0x1D0576C2A8FC472FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x508D144AD1B5D905ULL,
		0x2EB243F69E965760ULL,
		0x173E26632B05E39DULL,
		0x07CD6DD2FAC157C1ULL,
		0xB57BB021958A26C3ULL,
		0x0E88761125F91DBDULL,
		0x7AAFBA8B357A0184ULL,
		0xE6E0F67BE6B2EB98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAE5764D00D16B49ULL,
		0xDC377C9683CE6BAEULL,
		0x6C8985B6910051A6ULL,
		0x3FC2A7FA7121F963ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF0D47B81AD18B633ULL,
		0xBDB135D42492C24FULL,
		0xC4E8B07AB24F6ED7ULL,
		0xCF9F814408A7E4DDULL,
		0xBF2A67D62C1395FEULL,
		0xB87156BCB150E174ULL,
		0x18D061251372D0E4ULL,
		0x4EC17A8A2170293EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E9122396C565AAULL,
		0x06AD6585A8D6B343ULL,
		0x0685E05543C6794CULL,
		0x8B62A9EACA3A0194ULL,
		0x63181F196C67D9EFULL,
		0x554632E02F43B530ULL,
		0xD7F29CA7E7841F62ULL,
		0x58820773834859DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58A2356289D13A8AULL,
		0x6F6B2309C9B0A132ULL,
		0x5F4DFAB9F3F74EE6ULL,
		0x51A7ECB4B856AC05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF08C42478A4BB2F4ULL,
		0x95FE205569F7067CULL,
		0x3BB9AEBCAB77CF12ULL,
		0xC5948B14207D35F0ULL,
		0x3EB6CBB7326A41D9ULL,
		0xD0498D6B065A35DDULL,
		0xAE9BAF318BECF3EDULL,
		0x0ECCF86ABED265F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA0A127E0924C6DULL,
		0xEE70F1CFE93F1ED3ULL,
		0x75FC549AC12FCC89ULL,
		0x74A7DDA38F3D6F15ULL,
		0x7480B7B9E91F19DBULL,
		0x27B0E1921E241B29ULL,
		0x5CBFCCA293F8B7CBULL,
		0xD95966046C85C6D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14F298B88AE151C7ULL,
		0xAE36B0B7F8BFDE59ULL,
		0xEC60FB5AB888EFADULL,
		0x401468A0C89F65F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7244E1E474E3DB99ULL,
		0xA007D07601D21A65ULL,
		0x9B41DFD26B6A9E2AULL,
		0x6B5710DFE04244FBULL,
		0x857E21B7B2E682D7ULL,
		0x7332D9A02F22E4AEULL,
		0x7D9E6B995DBD3032ULL,
		0xDDEDE02052F94067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25CABAC03606A8DBULL,
		0xD8E461383BCA4441ULL,
		0xBE464BB75D83B4F0ULL,
		0xF17E00751AC39340ULL,
		0x8699A005D162A235ULL,
		0x3D549695093A00ACULL,
		0x997EBD99A9E025ECULL,
		0xD9D81C86F90B8F79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2265678BB8708ACAULL,
		0xC62162E56699AE70ULL,
		0xB9AF680FC0B66FA5ULL,
		0x1514192E1EC6F50AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF2911383CE62E21EULL,
		0xDE9C5F81835B7049ULL,
		0x9E88DBE4908D0266ULL,
		0x615C847678211033ULL,
		0xDF0B9EF563D570FAULL,
		0x8E253166B6A4EB56ULL,
		0xE990A05153A94A5EULL,
		0x8A3953250964A354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6312A80203FC6CD9ULL,
		0x7C0D60EF9417694BULL,
		0x964911A11D577F04ULL,
		0x36C145F455CDCAF9ULL,
		0x2AF9A2FB117D2D55ULL,
		0xD7D95A2A05B17948ULL,
		0xBBE55F1C65DE750EULL,
		0x6CA80176AD5A4C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A29D2AA0380806EULL,
		0x71D0F1943366F52DULL,
		0xCFAB781EBF512D37ULL,
		0x0E2D5E63CBDC26F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE7EACBD22B17099CULL,
		0x65E32C951936A75CULL,
		0x9E03BD26B44F2512ULL,
		0x15E1BD6BF4B85D56ULL,
		0x9DFD7261010167C9ULL,
		0xEC3C3E769B42279BULL,
		0x77A6530E650CE0E3ULL,
		0x216382101AD718F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F81C9DDE25F320ULL,
		0x06A9F12518F17F09ULL,
		0xDB24A656AA0695E4ULL,
		0xFFC64F2B59F9389DULL,
		0x2128982118CDB5A9ULL,
		0x6B05C8C9B64DC291ULL,
		0x611ACF7293062E5EULL,
		0x7C12A222D747E609ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x358B14B0C49D8515ULL,
		0x8D4EB319FC8C27E2ULL,
		0x1B949FF137470EFFULL,
		0x201CAB78A200B306ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xBF94C5CF634B6B85ULL,
		0x37ECE04AFF8AF27DULL,
		0x22117A44D42CBE64ULL,
		0xCBC8A72EA86644C7ULL,
		0x020D004A8AF1803EULL,
		0x9824B14A4B82FADAULL,
		0x2C5B5E211D6A0948ULL,
		0xA44B68D58E00E3B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A32374DD396820ULL,
		0x7007C43467D0AB01ULL,
		0xE8C3D3736F78886CULL,
		0xD4BF45F3CA835608ULL,
		0xB4E75142B8874A0DULL,
		0xE370DB987E16F67DULL,
		0x258597C7C5DB19B1ULL,
		0xF48B53D747C283C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19899D83C1D60CE3ULL,
		0x9A96D47B15C2ED30ULL,
		0x3D09181463EBC656ULL,
		0x0D8C7EF94B252BEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x63EC1FCE9141E1F8ULL,
		0x8E6D8D7C0944C5B7ULL,
		0x8D3E4E6907A653EFULL,
		0xAF29BBEA18BC9A16ULL,
		0x3ACFF725574AC55BULL,
		0xFA9543F82FB4692AULL,
		0x3F4F697FCEAA0E3DULL,
		0xBC9CB1B0AA3741C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4549A36525E88B5ULL,
		0xC735D6A32FB20C06ULL,
		0x694387393842DDBAULL,
		0x087AF69ECF265605ULL,
		0x8F0EF623C670B169ULL,
		0x5C0BAD9A41BE4F23ULL,
		0xCE3A022D65A7FA43ULL,
		0xE720EE94E5399D12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E3DABD3BF424E4BULL,
		0x4FA408CA2C1A96AEULL,
		0xED281D6B65B26D68ULL,
		0x570DBB6A873CB6B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7C1FA16C5F459B93ULL,
		0xCAB1F5C79F433131ULL,
		0xB76D9B4E07E08282ULL,
		0xDD565FB7BEF38C2FULL,
		0x59A501C5B03057BEULL,
		0xE146050D6C73DDD6ULL,
		0xADD447AF5159DD09ULL,
		0x8C6F32ECE873ED13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC377308E18760BULL,
		0x4471180551F31048ULL,
		0xCFA5F3ABFE545329ULL,
		0x4AAD81A1BECA874AULL,
		0x7AB0C1A6292D742BULL,
		0x40EE580948B057BEULL,
		0xE9C69500A0260B69ULL,
		0xB064D5FB44CA3434ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x059DAEE9DB9AEC9CULL,
		0x53448C5F9C560874ULL,
		0x01D02D90573D4D31ULL,
		0x3C32A9F44B5A75F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE9E5665F2575944FULL,
		0x8B240BA51F4820A3ULL,
		0xD547F074ED15ECD1ULL,
		0xE6926611AE17FB9AULL,
		0x7D5E9FE22C7C29B2ULL,
		0x607C151D36CF7EC3ULL,
		0x6CB13E2F87679244ULL,
		0x5792769E6ECE1AA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58D5D053F8758656ULL,
		0x741A60E95CC859E8ULL,
		0x74685D72BDEA0CFDULL,
		0x4A162559645BA0F8ULL,
		0xEEC787C7230431F9ULL,
		0xB1C7AAFB0E4C19B6ULL,
		0xE30AC9A645F518F7ULL,
		0x8A30E1064708E69BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB7D2A0E94CED265ULL,
		0x05D16BCDC600C698ULL,
		0xCF94DF61E629E136ULL,
		0x18F8754E3102147EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6546A796F303C535ULL,
		0xEFB8FC358E91EFFFULL,
		0x6F2C41A68884FCA6ULL,
		0x0D6B439B4493C40DULL,
		0xFCD9E4353FAE2A6CULL,
		0xD5FCBA4D1FC18155ULL,
		0x8272EC3EC2A8788AULL,
		0x15153CDDAB9B65FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FACA3885245AD5ULL,
		0x2C08975F09529754ULL,
		0xC0D96C0B6ACB2EACULL,
		0x5BB02048C5FB2C2CULL,
		0x274B986F7BD15844ULL,
		0x6F865684C25A77F5ULL,
		0x95E5704FBC83EC6EULL,
		0x6B2D85507718EDB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE76B1CB980A69A4FULL,
		0xF9433494628ABD0AULL,
		0xCB533B1607269A31ULL,
		0x6A20624849F671F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7438998ECD1771BCULL,
		0xF4E1C72E837CA881ULL,
		0xA65FC3DB36E76B4AULL,
		0xBC049CB43BCFFDFCULL,
		0xC4A1FD58EECA7D3FULL,
		0xAE6A880151A9E613ULL,
		0x0D8DABF4FE75907AULL,
		0x80BA3DC1B219790AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9EAC1692D337E74ULL,
		0x0622AEA97C3D7858ULL,
		0x5B34DAD78F1A651AULL,
		0x30234F3514109570ULL,
		0x00F4C666B39A8D8AULL,
		0xC03AD5632D85DABEULL,
		0xA598BAAD637F8AA9ULL,
		0x6600A053A7C566FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC604001A690188D1ULL,
		0x49D39BFE6498DEE3ULL,
		0xB986B9A4A851E334ULL,
		0x036EABD4B03A16AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3A39A8056589FD5BULL,
		0x4E886B8233D40711ULL,
		0xD1DDA8854A0F6900ULL,
		0x074FF576CA3F2022ULL,
		0xB0534F7FD9DC8A4DULL,
		0xD3B35C235FB8EE6FULL,
		0x37DF8906D9D08742ULL,
		0x823622562D300DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x684B850A95CD4DBEULL,
		0xD46A6AE053BDAFDFULL,
		0x3238C13B5BB2CD0AULL,
		0xA06FA7F28D6CB62AULL,
		0xFD68B1900AA71A94ULL,
		0xAE608E3D470312FEULL,
		0xB5AB25F6F87E570DULL,
		0x0CC164EC2B2761FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60C1949391AB4786ULL,
		0x046890C98B14E9ECULL,
		0xF36B9BA5608FC3D9ULL,
		0x56346B408A1BEB5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x000E5B7E88651F6CULL,
		0xAE12E872F734AB92ULL,
		0x5733187EFACB19C0ULL,
		0x260C20B37817FEBCULL,
		0x7B98B6B66EAAE46EULL,
		0x0DDD81282B604E31ULL,
		0xCD8F52BBEF39E32DULL,
		0x3A9560A49E2DED1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1C796BE839D4A9ULL,
		0x60583203AF0E55F0ULL,
		0x5B3E3CF4E4E0B82AULL,
		0xD23D58B77DA2A840ULL,
		0x7D715E37BE66A56DULL,
		0x1BBF9AEA0D18E5ECULL,
		0xF49A44FF2E375E9EULL,
		0xFC2573B0C7F176C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBC904E0CA4CA088ULL,
		0x3E2AE3A7C6BFCFDEULL,
		0x3054E58EBC4A0ECEULL,
		0x186BF42DC76EE760ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x66A2E9471DB9E33AULL,
		0x5C052096C6BCDDE4ULL,
		0x1E90732C98DDCD1DULL,
		0xFE5AC72DE350CF0CULL,
		0x322BE892A742C2A0ULL,
		0xFB39B7A6CD305D8EULL,
		0x3A4514F7267A5CF2ULL,
		0x9AF791BA79484F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15713DC363E0394ULL,
		0x7782190855375683ULL,
		0xD322750F9D728E5AULL,
		0xC221C5A8E37BDC25ULL,
		0xF8513B82AF479B30ULL,
		0x80B0636EC18602FEULL,
		0x4F03F8769C0D9411ULL,
		0xB4A9132F9327AA2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BC185C9B6C3B9AEULL,
		0x14E587E02CCEF8A3ULL,
		0x371839318791103BULL,
		0x6BDFCA2328AD78E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x5F1B0D704CD8CF3EULL,
		0x8880A8FD3C8E9046ULL,
		0x49FDEF7561BA59D6ULL,
		0x1A381DB3B0208408ULL,
		0xBEAE68F402272C2BULL,
		0x9BDFFAABF4EA23F9ULL,
		0x4C66B1E493093C50ULL,
		0xC0B01F28AA9B6B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E43C799C6BCF993ULL,
		0x1A2D72C86CC52781ULL,
		0x03E57EFB5DE07D86ULL,
		0x4758878AC0BC5DCFULL,
		0x9F8E8BF31FF9A375ULL,
		0xF4BC62163FBF859AULL,
		0x45F3361AB90F499AULL,
		0x74E9A780264CE770ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F9213F818DE2251ULL,
		0x3D9BDC6DB41CEAE3ULL,
		0x3B3CD0705EF3E347ULL,
		0x1255592C930BBDA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC56AC515CBF7DAE9ULL,
		0x407AB28023A3E8BFULL,
		0x71FEB4D1589EEFE2ULL,
		0x88ED7175A0F04C94ULL,
		0x6DA06DD13BA3A953ULL,
		0xC49BE98E5D35CF50ULL,
		0x4E01440D43A7DBDBULL,
		0x6D0CC0E56A11EB48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631C57863F53254DULL,
		0x4CBDF5A2B9667CD3ULL,
		0xF211716F56628E68ULL,
		0x90307452ED9D8A63ULL,
		0xEE086BB13BD445A2ULL,
		0xEE6E2E7ED018740BULL,
		0x393FE33A176E8065ULL,
		0x8631414948E41242ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52DEBE4F856D814AULL,
		0xBE86812C5C98F817ULL,
		0x94A1A2BA92BFF4F7ULL,
		0x3D51EE4FA020F917ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDC2B0F820542071DULL,
		0xB289E93C6D38C7BAULL,
		0x94954E4277EA38EEULL,
		0x6DFC2C3D10A44E60ULL,
		0xC036605DCEDCA945ULL,
		0xBE4079F68501F9D1ULL,
		0xF3397F673BE9A745ULL,
		0xD1E65E1FDB426DFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA8D1B46750373CULL,
		0xFA38310A2EF3640BULL,
		0x481D5746C75710FDULL,
		0x33E2E8062148643DULL,
		0xD3881E326243E3CDULL,
		0xFE3494CC84948CC5ULL,
		0xFD3E13EA0F89ED4CULL,
		0x164C14E414C0F790ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2160103FBC9F23D9ULL,
		0x3A15BC6E4E839374ULL,
		0xCFC9EB9046C8C2DDULL,
		0x1300231666937E9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x27E6A34B4C74E4B7ULL,
		0x66A55F4C17E205CBULL,
		0xBA4D1D63E1CF4A70ULL,
		0x6942144759A2D503ULL,
		0xF802259BB3601395ULL,
		0x91407E289E1909E5ULL,
		0xF7ECE3F5FC42BEFAULL,
		0xDB645B370E5C0B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB4EF627A8C07550ULL,
		0xD20A261B65A997BAULL,
		0xDFDD6DFB0F59BFF7ULL,
		0xE97C9D938CF5966CULL,
		0xBB3C21BF8F8E76C3ULL,
		0x4BE74DEA14B99E6FULL,
		0x1A1FF9E834F8E252ULL,
		0xACB402630535AB93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81FC3FD0F4D1B777ULL,
		0xDFD862791662619DULL,
		0xC6DA6D74676C4B72ULL,
		0x6DF2A62D285F73E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD2E9A64CB6ADB9BBULL,
		0x3D08260AF43EE25DULL,
		0x3D77587962846E5AULL,
		0xD4A7AD4AF3447528ULL,
		0xD35D96A29494B3F1ULL,
		0x9BCDCFB80F588392ULL,
		0x343567E6DFD9985AULL,
		0x3745D428C7C4C98CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B2FE07E3173E7FULL,
		0x4ECC2558171C5CF4ULL,
		0xF00D140CECA107B1ULL,
		0xF54432791E59DB4EULL,
		0x624B54AF7205334FULL,
		0xF384EEED5D07B184ULL,
		0xFF6B4E6C44861754ULL,
		0xDD0125AF8F927E40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01EC725BF4E38F92ULL,
		0xE90D5EC95521B38EULL,
		0x236A0C9F84488D7FULL,
		0x459560D02C61C703ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE7D57BE26F6A7E7BULL,
		0x504F5D81BFD9ADCEULL,
		0xD1CDBF9D0DB7F58FULL,
		0x44AE7FC91F698F35ULL,
		0x1814A9544BE6797DULL,
		0x827638FD0D345C64ULL,
		0x8E8C03508B675099ULL,
		0xD08ADF3B07FFB481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768ECA4180C00F32ULL,
		0xC010BBC8727BD3C3ULL,
		0xD44F501318DF9532ULL,
		0xEC3F49E01C57FC91ULL,
		0xC238A9366EA3C5D4ULL,
		0xCEFC0A1E6DB8364FULL,
		0x957F5E8DDF1D2164ULL,
		0xA319F91890814038ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FEEB60FC6911B43ULL,
		0x346196C4F9CB8110ULL,
		0xF55EE46F87DB622FULL,
		0x17315F06BFD6D578ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE9756C5FEA5D130BULL,
		0x85EDBCB16722EEE6ULL,
		0xCC65825FBA7286C0ULL,
		0xF32B0B1B285A3498ULL,
		0x8BF4E71C9271063BULL,
		0xCDE8CB8B03CA7298ULL,
		0x20861A6795BB3452ULL,
		0x4721405E85330104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1B60255EE87D2BCULL,
		0xEDCB43071A5F2ECCULL,
		0x22628C6138EFF11BULL,
		0x91120E6A577E704FULL,
		0x318EC27D1E8D20E9ULL,
		0x735B547524A489BCULL,
		0x2DF2F9CAFBD1FCE9ULL,
		0x05536D6B74C877DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2E8D9B52FA94BF7ULL,
		0x092226E96C6450CFULL,
		0xABD9CD3D5A20CF48ULL,
		0x26A64CC540AC2037ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x859ACD85FB928FF5ULL,
		0x2C8519C8B268963FULL,
		0x767E1017D9D65171ULL,
		0xD31F54F8C88CAD72ULL,
		0xEF08B592932C5D84ULL,
		0x3FEE0783E3089F09ULL,
		0x28E686830FF53D6DULL,
		0x417F369443B0A550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85739C976DFC6F31ULL,
		0x7D9DA923C254DE6AULL,
		0x0C161900BC91432CULL,
		0x537830977E44EE57ULL,
		0x5A49800889E2640EULL,
		0xEBA5ADC54578BCB4ULL,
		0xF360DDC8DF33496AULL,
		0x04E860CE7426DD5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1489236BEE91299EULL,
		0x31A4C2F0536F5089ULL,
		0x5C3F02BA5A0F469DULL,
		0x7E0ADFBE18BB6D0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6C5FDC6DBBCA3CCDULL,
		0xE13DB0DABF93DE9EULL,
		0x845E77B82F0F1156ULL,
		0xAD9EA0D46307ACCAULL,
		0xC202B890C2FA1001ULL,
		0xB6FB3D8602C2BA57ULL,
		0x36D3B4BDB353B347ULL,
		0x9657E7E415D621ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D699BFDC1A9ED8ULL,
		0x8A9B7F14E4860A5DULL,
		0x4120E91F03B4F546ULL,
		0x9054FF6B10BE51BBULL,
		0x3A9AC11D726BE82AULL,
		0xD727FCC48F4BE33BULL,
		0x6C936AEF5DF72714ULL,
		0x9ACB9C9F040AE4F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42F7FDCBD4C987B9ULL,
		0x8FFDCE7CFEB1C27DULL,
		0x48C88339D716EB9DULL,
		0x741CCDA9F6746823ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x21A36AFD60F049E3ULL,
		0x75F04610DB1490F6ULL,
		0x4C0395F8CF5BBD87ULL,
		0x041EF016A4F25980ULL,
		0x35F8276C2C45505DULL,
		0x4122558F08A822CFULL,
		0xA240B76C566A7131ULL,
		0xBA61A782FC84A420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F29A1231E3EB8CULL,
		0x557A4ABFF8294293ULL,
		0x43B35367467A13D3ULL,
		0x2AE7D815132926CEULL,
		0x113118469E29588DULL,
		0x3ECFE03E157F4A14ULL,
		0x2DFBCDB55C37D627ULL,
		0x668B1D18362773ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x143D107E473328FFULL,
		0x78B36554FAFB7A2AULL,
		0x4A8AF3BAAC64AD30ULL,
		0x4B0FA3DB039E5A7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0920F47B1135EC10ULL,
		0x7DCCCE2B5C41FFE0ULL,
		0xBE74A01F1E39E0B3ULL,
		0xC3FDFFB109AA4862ULL,
		0x68FE6E555F368181ULL,
		0x9793CF6FCEF0D4AFULL,
		0xC93681C23832330DULL,
		0x2B224749B83DB62DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD1D46FC9CB44A0ULL,
		0x6FA578FEFA8469D7ULL,
		0x1CE25E4EC2F1B061ULL,
		0x82796D7E58F33B4BULL,
		0x0F551B5044FBDB16ULL,
		0x94F57394B08965C6ULL,
		0x4384E6BA09D4CA5EULL,
		0x9EA8EBB8DDA44C10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC7172CD2C1F58CCULL,
		0x71A8F7B2E5180CABULL,
		0x79EF45073D25BA4CULL,
		0x1B8829B3237CCD79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCA4F093EB94B06B3ULL,
		0x614DA91A8210C890ULL,
		0xA040B85FFDFDFCA1ULL,
		0xA05EE5FAEF654AB6ULL,
		0xA9C16B759A552605ULL,
		0xF19A2F117FB97266ULL,
		0xBA4CCA0CD1C470D7ULL,
		0x60793D669CA8B112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC27CD07F2D63884ULL,
		0x731532FCB0303B46ULL,
		0x9E741CF2DD614569ULL,
		0x6C0B9AD69B70D027ULL,
		0x48FAEE45ED3A5F43ULL,
		0xD02895867901DA86ULL,
		0x7DDE7CD76145CE3AULL,
		0xBB4B6E3605124C8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B9DD14A786E4CFAULL,
		0xE51540C0D1211898ULL,
		0xFA2C115BD368DA8AULL,
		0x39200C5AD44766C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDD24C4D1943165EBULL,
		0x8283445448E2AAE0ULL,
		0x027C1408555934FCULL,
		0x9815589448F201EEULL,
		0x3CBA2C2E83556C82ULL,
		0xC3C5E260B43DBAA1ULL,
		0x7E8587A601E1FF38ULL,
		0xFCA79BC808D324FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A69ED9DF371FBDAULL,
		0x84CBC6443425A82CULL,
		0xBD51A0495CAACB8BULL,
		0x6BA1D8B482CE72C7ULL,
		0x77A63588723B4E11ULL,
		0x54F78F67291B3307ULL,
		0xBE6888FCFD237154ULL,
		0x7920636D1FB13E3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3B173DA2A9FF1BCULL,
		0x7057CF1ABBDD2387ULL,
		0xC97840D5ACF77959ULL,
		0x3285DD5E612BCEDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xD6620BD344B6E0BFULL,
		0xF2C7DB3A09A8E631ULL,
		0xC4467B0A13DFA254ULL,
		0x8261FABD40DB04F9ULL,
		0x14F9A8B07DD8547CULL,
		0x65EA726D51820B28ULL,
		0x65F1ED5C3136371DULL,
		0x336F97EE1B0F2F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC8B60925027A1DCULL,
		0x079FB3799F27EEA0ULL,
		0x672E29162CB4AAC7ULL,
		0x5C6F256407A2CE4EULL,
		0x971270A5E1D724DFULL,
		0x0B246C44576679F6ULL,
		0x6317FC1D1511EC52ULL,
		0x2E0EF0322D4E2ECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA28FCD41CBC5044ULL,
		0x648D11D58A9884E9ULL,
		0xC9722152148E11BDULL,
		0x724BBB3E83DE3FB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7C5DB35DB476F051ULL,
		0x3511391F233AD68FULL,
		0x1C01CD9B08210396ULL,
		0xD9CDD4A287A488A7ULL,
		0x272E678153FADACDULL,
		0x6A3B52CD8F24A033ULL,
		0x0D377E236834B5EFULL,
		0x2B7440BE6521C53CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E9E60F6DC86F538ULL,
		0xD57AFADA5BFF0719ULL,
		0x2F22B2AAEDE692C4ULL,
		0xD8AF09205B07C5ECULL,
		0x0D3AEDD3ED8F796EULL,
		0x83339FE3CBE81DAAULL,
		0x5AFC8D11762D1089ULL,
		0x748E3B4BDC1958E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37E362240BE06D91ULL,
		0xAABACCF7C2372FD0ULL,
		0x619EE39A075CFDF1ULL,
		0x27439A8283DCD773ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF8B021B193737206ULL,
		0x6BF542041CD31DAEULL,
		0xA2A003FBB6A3BCC5ULL,
		0x06C3947DAA43451EULL,
		0xEAE2D5C2C8E13440ULL,
		0xE54AA9CAE4DEED76ULL,
		0x2C33D454153ABF0CULL,
		0x196C24F40AB44CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0907777724400710ULL,
		0xE80AE92C215032AEULL,
		0x5188BF59D24259BCULL,
		0x9DFF259B6B9453CDULL,
		0x97D9605740D1C612ULL,
		0xEF124147103A1F34ULL,
		0xC9F1EC1A1E8CCCDAULL,
		0x74F2DBC9D70E7EB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43101830A17DC3A3ULL,
		0x1049DC698BF988D9ULL,
		0xE6DFBD3C82335673ULL,
		0x52C54B25E94B8A1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB1C6DAA3E3178F0EULL,
		0x9447B7E972689967ULL,
		0x1F39F4C7A1D8FD27ULL,
		0x733F9B28A2FB6A45ULL,
		0x1A65CB0AC215E190ULL,
		0x7E88451C2F3D2461ULL,
		0x3E10C8645E7424AAULL,
		0x45157EFB3DFB97D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C23ECAE414757CULL,
		0x8681EE1CB8A0466BULL,
		0x4B97EE6AD8DDAB29ULL,
		0xF7FA6D2EB3DB554CULL,
		0x6F70D011BC52A5EAULL,
		0xB23B93DB7D52BD16ULL,
		0xAE4597DD7BCD0988ULL,
		0xC1E254746530E36CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE061DCCFD9FDF151ULL,
		0x612819672293A811ULL,
		0x2BCB3A626DC95902ULL,
		0x74DD7DFE1D36DD16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4D4029E46F70569BULL,
		0xD527C967CECFB13DULL,
		0xA3CBF6FA4DB41B8DULL,
		0xD8F5705E00794EF2ULL,
		0x8FEEA5ECB405002FULL,
		0xCBD7D4B0C05B3183ULL,
		0x67EC26322694DC81ULL,
		0xF4883690A2DE04D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB14D1FD7B4B6CE5CULL,
		0xFCF5539F6E799F2DULL,
		0x4E1BB8EC71B608AFULL,
		0xD027BA362C3AE5C8ULL,
		0xECE4F9331E97CBB2ULL,
		0x46AAFA7A18EABF35ULL,
		0x015F7C7173A115C8ULL,
		0x8E04C070D1B5F584ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF62AD98E8EF5507ULL,
		0x9CDAD9E53B070995ULL,
		0x8E9170A86C2D9267ULL,
		0x40513EE0E030AECDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x12E56C1928343B69ULL,
		0x43C0E951C90C1B52ULL,
		0xD169CFDAA80E2873ULL,
		0x90CE4ADEADD2F568ULL,
		0x9A36D97EF1B87454ULL,
		0x821D3B17ED3219E3ULL,
		0x3945AC05CFA5CF09ULL,
		0x8B2D8147F4295128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA894FAF848CC971BULL,
		0xD3C28DD47716E6B6ULL,
		0xB49C358102D82DB5ULL,
		0xEB7E615614EE5B9FULL,
		0x388AFF385EDDDAD4ULL,
		0x6B09D8300322C8E1ULL,
		0x21A188760D936BACULL,
		0xBF84DA47E6AA2265ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9D2D79AABDA6C0BULL,
		0xDCDF09EA103B3AF5ULL,
		0x9F2AE1B073F0BA8EULL,
		0x6058B38A99C58ABEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF9FF769F82D79E91ULL,
		0xA3637D3CA5A586B0ULL,
		0x501497295C4495AAULL,
		0xF9E50AAADFABE18EULL,
		0x30DC036A5829E5D6ULL,
		0xE237E9D3E41536B5ULL,
		0xA7354011B6F496E6ULL,
		0xA7BFB8AB908A48F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8272E3580F718E1ULL,
		0xDE976936DC77169BULL,
		0xDF80138CB7ED60F9ULL,
		0x834342A0E9C8BDDAULL,
		0xB55160816454152EULL,
		0xE8C9C0646DF9220CULL,
		0xE9210625EB8F8BF5ULL,
		0x73D5EEBEE333215DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x586C76FE339D7FD0ULL,
		0xCB263A9151598117ULL,
		0xA7951C9CD556D475ULL,
		0x2B55C12BB0D303A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1D72599ED2E95B98ULL,
		0x40BE3C0B9BE90477ULL,
		0xCDDC99DCDDCAB6B8ULL,
		0xEDF49A12F4D951DAULL,
		0xD1B3D8D9B9B0E336ULL,
		0x05EBADDC49318BB5ULL,
		0x16FE75467E5EAD63ULL,
		0xDA7AFCC4A95F65D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A430C282A59F6EULL,
		0xE66C74A51E87E85BULL,
		0x5077C7207330FBE2ULL,
		0xCCA90DDD51278BB9ULL,
		0xFC1739EDDEC23071ULL,
		0x0E6D6361F8A0C803ULL,
		0xBBF81E7E572BAA2DULL,
		0x041E791D9FE94D24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC0DBFDECFB24A15ULL,
		0x1710D58E72DE2881ULL,
		0x0055B4723C2C34D8ULL,
		0x730717010B397029ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA31D049C689BA91EULL,
		0x0A4E3B6E46411827ULL,
		0xFCDD78F4D5B0B25AULL,
		0xC513B5F8A45C20E3ULL,
		0x86365CCC01D61B7EULL,
		0x3E98EECA3BC46ADBULL,
		0xB70292C78916C7F5ULL,
		0xB70CB0472D12E225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB289A2FF90FECEULL,
		0x6169588029EA121FULL,
		0x4EA7172BA6978287ULL,
		0xB849231FE8536BF8ULL,
		0xE20ED6EF96ADA0E1ULL,
		0xDE34EC9FF549E5A3ULL,
		0xB815904B959E226EULL,
		0xF920C977ED1BA8DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE64859B1510CDC22ULL,
		0xF7BD35349286CC4AULL,
		0x8564C02F5301C1C4ULL,
		0x3DCED59C3ABB360DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF297A95E877A39F6ULL,
		0x74CF4634FEA97F00ULL,
		0xB2A3EC8CDD212F7CULL,
		0xDDB2FBA663C10FF6ULL,
		0x5E1356FA1E520DAFULL,
		0x036ED874DDEB8757ULL,
		0xF6BEB8BEB64108B1ULL,
		0xCF489AC59339C12DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519976C38D8950AAULL,
		0x9D6FB09AE107A0DCULL,
		0x0CF6F5FBB11DBC89ULL,
		0x877EF75CF5E319D4ULL,
		0x61C2FEA927F03E83ULL,
		0x9528CB19DB49050AULL,
		0x1A3B0C9A2D5C2071ULL,
		0xE3F68434CB5CD26AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14EB4E9F8C75A962ULL,
		0x35C5911C81C13592ULL,
		0x613883FD7DFDEC5DULL,
		0x44635DC718A96735ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x38C4B62A3E4657C4ULL,
		0x011E94950E53C86DULL,
		0xC1261B5CDB336C18ULL,
		0x1587B2A082E090A6ULL,
		0x859DDE7C92365975ULL,
		0xFC52C0B7489D8BC0ULL,
		0xFEF8F0FF608153C4ULL,
		0x0606FCBE370EC713ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78D47245B3125D7ULL,
		0x932A4F0EC70CCF90ULL,
		0x783C0EF0747F187EULL,
		0x75152B7864282247ULL,
		0x14C9F8E375040DB4ULL,
		0xC132D12DE3E93906ULL,
		0xA3001EB5888F9112ULL,
		0x642D74E412870B48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30AB83C0388C6E6CULL,
		0x34B1D3EB3A0B4089ULL,
		0xEFD9436274973A0EULL,
		0x26BCB1898ADE4E8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x9AF89CC77E7EF726ULL,
		0x3B910CE65E7BA56EULL,
		0x257284F7BA15A1F6ULL,
		0xC5CDDFF41887B59BULL,
		0xBF73A3126AFE9AA0ULL,
		0xE14CFE4EB70E03A6ULL,
		0xA6396FC90CB65061ULL,
		0x17067F3C3C3E79FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0890012134BBFD0ULL,
		0x0932F785D2DE2A05ULL,
		0x6D8E42678E677923ULL,
		0x127991D79E4044C3ULL,
		0xDBAA9FF8E427B18BULL,
		0xA22398F6CD9EA968ULL,
		0xD567DE203CCEC180ULL,
		0x8E837D81D249CE8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A46127F6F19CDDBULL,
		0x9283206D3224E098ULL,
		0xB6FFE19F080D5E42ULL,
		0x76C68FC83498E34AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7EB899E06B4FA0CDULL,
		0x11E29DDE1217D392ULL,
		0x07336156A9C56518ULL,
		0x7B773BDA372E54DDULL,
		0x7614BD49406BCB46ULL,
		0xCD5EF8FC599A2C1BULL,
		0x7A668A3A98F8C5EDULL,
		0x692BC22D06435226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4160A57430C190ULL,
		0x875AE5D09A16EE25ULL,
		0x555705A8C358BC61ULL,
		0xFF165F1C58FB60B2ULL,
		0xE84C904B70E1EB67ULL,
		0x358D059E9C9C1C96ULL,
		0x843B69036308F17BULL,
		0x8577D85BD263EE68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902DE6E7C5961999ULL,
		0x13B1D7F785B73319ULL,
		0x3C4349DFE80631B9ULL,
		0x491591CB915BC25DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x44CC7F5842635CD3ULL,
		0xB01A25B23671AC09ULL,
		0x73BEE5FEDBDDF562ULL,
		0x75425CCE5FBE8BD5ULL,
		0x5AF485D327B33D06ULL,
		0x66E42E2BD5BAAD2CULL,
		0xB48DFB2D7CE044BEULL,
		0x591E449DD2C6AB79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B5096C1EB5D589ULL,
		0xFF1AA0D1A9D52A05ULL,
		0x160F1FEDDE3D943EULL,
		0xCF3033A9D34A22D7ULL,
		0xAB04AE4C5FB5B5E0ULL,
		0xD10F5679C73A4B82ULL,
		0x49A3C98D1A63F4D9ULL,
		0x23BF47177409B1B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BB173EDD34F980BULL,
		0xEE97894EB3AB0133ULL,
		0x3C7323DF9C143D11ULL,
		0x122BCB169C817BB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x534E67FD8952901CULL,
		0xEA2C36E4483A2A67ULL,
		0xD7821E0E1DE275F8ULL,
		0xEB7950E63A1A00C6ULL,
		0x88A0B5F8E7A47C8FULL,
		0x9FCA7C7B7C073CF8ULL,
		0x6897F6F6BCA8225EULL,
		0xB66EBBB0B5BACC32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8562CAE6F0B226A1ULL,
		0xBD1ACDC2C474EF04ULL,
		0x1F63C7AE08E5CC8CULL,
		0x273F2637FCFAAE50ULL,
		0xD185EF22C84F746FULL,
		0x66AD95633CC76093ULL,
		0x067034F2275B66B3ULL,
		0x4DF18DF448E2AFBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBE520DF3F3FA09BULL,
		0xA75BB6BAE73FF255ULL,
		0x4A05230E3E6084D6ULL,
		0x46CEF4A665338C55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xCF2F1DABEB710E59ULL,
		0x0519806BE0BD826CULL,
		0x132C97FF76EA388AULL,
		0x74014C6EA91B2384ULL,
		0x00FE24B6B9D197E3ULL,
		0xBBB595921B2B07B0ULL,
		0xE5D286EF178F9087ULL,
		0xBE8C627553D1D487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3736F2DAD6E2056ULL,
		0xBF1CC8CC61E7F14BULL,
		0x643E1434DFB092D7ULL,
		0x1BA6516D665D90CCULL,
		0x7C2647D7091D174CULL,
		0x9EF74D2B70296224ULL,
		0xAD31DE7DE3AE3130ULL,
		0x7DEA968931625747ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3C677B278CE05D6ULL,
		0x8A3B76DCE11423D6ULL,
		0x16C784984AADCCA0ULL,
		0x705F400E5F4A2A40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE5A6C5B08F283C1AULL,
		0x7FD637BBE827BA86ULL,
		0xBD34FFE5F6B64953ULL,
		0x2B7ECCA8B53DB61EULL,
		0xFC2B2A2086EEBA53ULL,
		0xC6B99380B94E541FULL,
		0x927312C3EDA95CF8ULL,
		0x69FCFE301948A569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1288FC70D6DD3236ULL,
		0xC32F0894650D59B1ULL,
		0x8DDF4BA7D46EA5B6ULL,
		0xD02FFEE317E2241EULL,
		0xBCFF1CDAC4CE3009ULL,
		0x50735DA33EF2F9F3ULL,
		0x3BAA2CEA3F90F13AULL,
		0x5F5DB318DF9C6A7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33A7C19A891F90F3ULL,
		0x4B132E07ACA9C367ULL,
		0x1127D28DF9E7A1E2ULL,
		0x6EF3F3382CEC5115ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4D4385D61385F578ULL,
		0xAEA4739B15F6B8B6ULL,
		0x2D6AFE915D6ADE7AULL,
		0x39F4B9BDC79FAE8CULL,
		0x3787600DC4AF973CULL,
		0x2F29EFAE755ADCCAULL,
		0x5549CD490EAC6614ULL,
		0xFD86F8B55CE75F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97A64B7A307C17C8ULL,
		0x998281144698447DULL,
		0x94F71A1908D40D15ULL,
		0xFE699EB33A9E5AD5ULL,
		0x31DEE1FE8CDDF20AULL,
		0x0A8719879B92B1EBULL,
		0x68995CC62B2D55DCULL,
		0x60788577FC9DC5B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C9FF09E2C286673ULL,
		0x854DBC4B2314D153ULL,
		0xBAA497E6197339BAULL,
		0x0BB03626D7EE227DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xE5D76DB9E1E2FE8AULL,
		0x5ACA6B5314B1D39FULL,
		0xFA083E865A061DC6ULL,
		0xAD9E621BCB965044ULL,
		0xD2D181A4FF7E25C0ULL,
		0x92347767EC5F311FULL,
		0x5D646E5B7C34CA13ULL,
		0x88DFC8C86048477DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2646C2461E30894EULL,
		0x549F5670E8751AD3ULL,
		0x1A5B654DA84DC4E1ULL,
		0xFF1523DD3799966EULL,
		0x0C98176BD95B3ED2ULL,
		0x03E527DB1C18AA0EULL,
		0x080E3AEBE2937C75ULL,
		0x5B90AF1DCFF049B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C166FEF6CE0BD74ULL,
		0x25F0E3C916B4C570ULL,
		0x8A787BC97FA9DE6EULL,
		0x68470D90010C6605ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x1DFD93F8C03A4334ULL,
		0xFC1F364090840172ULL,
		0x247A3F7AACB0DAE5ULL,
		0x532DF72D7F077249ULL,
		0xC631847A3A7A4274ULL,
		0x16F2A9A7C8EACE90ULL,
		0x1DB3207127D67643ULL,
		0xE9F010AFCCC5AF48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D6CCB497D1A7149ULL,
		0x4E80C1E4120FBAA8ULL,
		0xCD0DB50DA13BA2FFULL,
		0xDFE6DE4B79D6CB68ULL,
		0xA027D468CBE7400AULL,
		0x326B67245EB3F277ULL,
		0x182E2C57AC13A605ULL,
		0xFA9658B6661A64E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9600EB45ACF22D22ULL,
		0x99B253DE4298F285ULL,
		0x2928C6356A602116ULL,
		0x7A9867E7429DB121ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA2526E90B9D0ADA1ULL,
		0xD8FE8748A6FAF93EULL,
		0x566BBA5CE1FE5B3AULL,
		0x5053A41DCAF09FF7ULL,
		0xC55167F03E287122ULL,
		0x68D34A9C477CB30EULL,
		0x2BE0E5F517648592ULL,
		0xC9605678E7E2EABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF9C61619C916D9ULL,
		0x1747E7F33855276BULL,
		0x71F3CC6274741118ULL,
		0x8AB91F8F387FA169ULL,
		0xD61BCBB728D5E2B7ULL,
		0xD9FDBB03E5E7ADFDULL,
		0x5002483FE2DB8E45ULL,
		0x5C1B7542F0689698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x094DD8F3CA48BCF7ULL,
		0xF569EFF3EAC49257ULL,
		0x878356E039DEFF7FULL,
		0x7DD3F2914E997BBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xB60770484DFF5A3BULL,
		0xD6269E5F401E8C74ULL,
		0x6B8777179FA285BEULL,
		0x87330643EBA9C9C0ULL,
		0x2AE84752A717A56CULL,
		0x446F4735C213ECEBULL,
		0xB329C0C3381268CAULL,
		0x68FD88A6E50D69FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B2ACB4DA7F458BULL,
		0xF8C5400318AA203DULL,
		0x5321C9DF376C870CULL,
		0x4F0697016B6DB6B0ULL,
		0x833DEBC1CEECD8F0ULL,
		0xFDAFE1FF92066735ULL,
		0x1E15875001BDB5C9ULL,
		0xE479517B1CED462DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD39E5B1389DA6C59ULL,
		0x5DCA64674976452DULL,
		0x3966345278C890BCULL,
		0x63CC9FC23501642CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA0A3611EB926EC3CULL,
		0xE8C371234E05AD1EULL,
		0x98FA25A08D9D345AULL,
		0xE86C28F1025F39C8ULL,
		0xBF5FB241D2679874ULL,
		0x0DB9A305B6E5941FULL,
		0x4A624A9B2975D867ULL,
		0x94CC3B72E7C629FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F7F055BA8F5DA4FULL,
		0x17A6100C3E33B726ULL,
		0x95F1A4BABF5820AAULL,
		0x3108F1FAFF4A42EAULL,
		0xC8B045205B5AB9E4ULL,
		0x197A670E20855F7AULL,
		0x6D1FA0FAB7B1BB8BULL,
		0x48AA018DD112848DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF2E8EBABC1A1D15ULL,
		0x128047D76219C674ULL,
		0xDAEDAEB6B1615C57ULL,
		0x0477CEF761BF8578ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x7C7840E07A2CDE67ULL,
		0xD429A1D5DEA53484ULL,
		0x73B399773129DA5DULL,
		0x5ED7CEFD5A872287ULL,
		0xA5EB26C3B697C9ABULL,
		0x875C4D4211DC68EAULL,
		0x2C73D1097822C404ULL,
		0x8DC5C6C991466030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCFE6CC3C173E310ULL,
		0xAE35107C2003CE91ULL,
		0x87852A2C83DF3721ULL,
		0x1FB09D1F6015BBABULL,
		0xEDF50A58DBDD38ECULL,
		0x66BD3B07B46D2591ULL,
		0xC1993C12EA2B46CBULL,
		0x6AF83CD1194926B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E020BF9306A786FULL,
		0xFD9146039D25651EULL,
		0xC8A08BE3C00739B6ULL,
		0x69A9ACBFCA07EF2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x107342568A35F84FULL,
		0xCE392DBF05D2EE23ULL,
		0xC020CB20F43BF3F4ULL,
		0x40C61ADA0340B23DULL,
		0x0D867404A1F7697AULL,
		0xE4EA86F43B2FB8E3ULL,
		0x379874CEF9F3E403ULL,
		0xBBB70AE0C93FFB93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14773DB63C869E23ULL,
		0xEBFF3C106574EA19ULL,
		0xD4CE0AE67C87393BULL,
		0xD8C9C4C640569957ULL,
		0x53EE581EC5ADF83FULL,
		0xAF053C8C4D515BB5ULL,
		0x824BDC4544CEEDD9ULL,
		0x01F480B78F975D4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x889028BF00962CDDULL,
		0xE242FD1BEF5FD8D3ULL,
		0xD4B164AB5B3144FCULL,
		0x7ADCD83251F19764ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xF5F0C691F4C606FFULL,
		0x25436CAAB03AA4F5ULL,
		0x72FA191669EA6B65ULL,
		0xE395789A1ACF16D6ULL,
		0x98AD08DE1DB13B65ULL,
		0x791D803CACC16AFCULL,
		0xDD76B43B416460C6ULL,
		0x61F41B71DA20A378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F03164A07A631D2ULL,
		0x8AC134A6E1C7017CULL,
		0x9911F4B8EC65F858ULL,
		0xD9C38125539E0C50ULL,
		0xF5AD4D3B81BDE413ULL,
		0x8DC8D7D272F3BD8BULL,
		0xEB3460257C2DCAA8ULL,
		0x19C83E84FD9381E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8E38A6B133ECCE8ULL,
		0x891337C862FB6231ULL,
		0xCFC09F98C39EBB7DULL,
		0x4054C29D8424067BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8832A9017298A150ULL,
		0xBD96BA5E4ABAD597ULL,
		0x41701EDBF534A2FCULL,
		0xB153220907B570DBULL,
		0x3CB5A29C45E5D4B7ULL,
		0xE058E9F7A4362240ULL,
		0x7642FCFBF2B22E2CULL,
		0x23F88859E9785FA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348FD415B67FC02AULL,
		0xFC276163FFBBDF66ULL,
		0xC2DFD4A346C88C35ULL,
		0xBD0A42978E03D8B3ULL,
		0x99D7B69DD2D49CA8ULL,
		0x755D0BDEEE5FF8BFULL,
		0x78EE1CE101730D48ULL,
		0xE595EF0E57A00FFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8093DCB0D0A72F12ULL,
		0xA2D250A548C91F49ULL,
		0x19298E387DCAF8AEULL,
		0x36EBA0A91FCD6AA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x889FD434AE2665A0ULL,
		0x3B39B70C2AFF07B3ULL,
		0xF0FF5F47A8C4E8EBULL,
		0x9CA0C2845552F3D1ULL,
		0x955F0E808C4FE2E8ULL,
		0xDCE11AEA85011DB4ULL,
		0xE278CFE9149D6BC3ULL,
		0x8E8536764F95AE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5AD23333B30432CULL,
		0x17741B6D69E83FE4ULL,
		0x3ED38A792578EF9EULL,
		0x79DAAA7F1AC4DE84ULL,
		0xD15A74FC846ABFE4ULL,
		0xBF450CC2E0CC2CA4ULL,
		0x00CC9847A661E9EAULL,
		0x2E6B957C7660BF26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBA17A9A9EF95720ULL,
		0x88EFB58120F29025ULL,
		0x31BC16C4E0213F87ULL,
		0x6693FD1B78699E21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x45995BDF8727AEB8ULL,
		0xCEC932AE71C3EAD9ULL,
		0x09964FE0BE3305CDULL,
		0xBA9C1ED4428E89FAULL,
		0x88132116B1ACFAE2ULL,
		0x71DF2653A2C0F37FULL,
		0x799CBB8F8B1E74C1ULL,
		0x29256893B905BB79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5A6244834A6771DULL,
		0xCD7F1418CCCEB8A0ULL,
		0x259C303A0A52765EULL,
		0x960C53C0DAD61E62ULL,
		0x5A214BB585F50155ULL,
		0xEFDC2A6C9962C70FULL,
		0xFBCAD777E741015FULL,
		0xDCCE9E385DE32DEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71D8E403CFD03E87ULL,
		0x4DBB82E108EFCADFULL,
		0x9121FB2906BFAFE8ULL,
		0x7971D4A2EED96E26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x87767C8CFAE0067FULL,
		0xC366DE023DD929FAULL,
		0xFB4D3B1A31190F93ULL,
		0x2D307A0EC033C5D7ULL,
		0x88CFF6800510B0BFULL,
		0x3882FEDE779E4CE4ULL,
		0x77C90C03C95AFA83ULL,
		0x044E1F0AFFC8D1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98718FACB1E9D9FDULL,
		0x4CCB7B2A3508B8A3ULL,
		0x9CB11740317B7610ULL,
		0x11ED49FB6EED85FEULL,
		0xDBD00BB66C51019FULL,
		0xC43942CE36F3C715ULL,
		0x378C0BD06671AC39ULL,
		0x89EA9C19619E6A68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D01C6CCF56A284AULL,
		0xB98D4D41A2204E04ULL,
		0xE7AA2B7AAE3F386AULL,
		0x46089FF0CB919680ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA0FAD31ECFA022F6ULL,
		0x798B247EA2947FE0ULL,
		0x08A26DE3D80B7C43ULL,
		0x948EE60E5E29E042ULL,
		0x404ED9CB8EC10C83ULL,
		0xE5F3BDE33279086FULL,
		0x1DA26108CCE1CFB2ULL,
		0x5C8BB5326AAE4C40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEEF9EA20FAE6DCBULL,
		0xF00F5436104D602AULL,
		0x2803AC85CC8D7ECAULL,
		0x625D6A8E9688E8D0ULL,
		0x3F09821E2A7023FFULL,
		0xE31F4E7A6B3BC673ULL,
		0x5109CE789E375102ULL,
		0x9A64C7D91416D2DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2563839A3F4376DULL,
		0xF50459D6255EEB1DULL,
		0x3F4482C4F8CCCB98ULL,
		0x03F8B6C2A21CFC8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4E4FC5E525D19318ULL,
		0x2477874B09F10EB7ULL,
		0xECB69113ECB8C5AFULL,
		0x56FA3F85BA3D8A5AULL,
		0x647CC7357A8C20CBULL,
		0xA94600CFD232FBD8ULL,
		0x1C3C4929380425D1ULL,
		0x13B3061C36293514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F46810FC7AD1A64ULL,
		0x7DF984C16C0ACF15ULL,
		0x72A353AEA69D5088ULL,
		0x36059335EB95CF49ULL,
		0x2C0CA23F05428AAAULL,
		0x071A38F24BB4CD0CULL,
		0xFC9DB39D1182DF5DULL,
		0x7AD9A912C473F3A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FAEC16AC710BF4DULL,
		0xB8FDAD6B94A131F2ULL,
		0x2B9D7032FD4BEA76ULL,
		0x51387BB6AF8F71DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x841E13FEC2F39B78ULL,
		0x562565DCFE3F098FULL,
		0x45EE03C62B61B142ULL,
		0x70F7E34D1C7C46C9ULL,
		0xD638A13A13FA407AULL,
		0x3CBCDEF3DCEB3B32ULL,
		0x24E14CC58C3B88BDULL,
		0x120837B11555262DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x118AD15180C579EBULL,
		0xE5CA788A4A467847ULL,
		0xB5698383387A1F5CULL,
		0x94D391C9878D72BAULL,
		0x0A3E93D032951B27ULL,
		0xB63170FA83CDE8EFULL,
		0x0A9D493DBF9AB531ULL,
		0x66462C2095341949ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9B14064B731A9F1ULL,
		0x690D4055EE52C758ULL,
		0x769D066B52C6F89BULL,
		0x5AF208F699D6BDEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4EE2E449A0DB2BB7ULL,
		0xE28A18CC45B203D1ULL,
		0x7786F09AF669F769ULL,
		0x2848B0AC2A8873A2ULL,
		0x0A248AD0C0FB7DBFULL,
		0x4A7C1E310708B202ULL,
		0x006CF18BCB60FE92ULL,
		0x9B24A8245A291C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FF752770FAB47DFULL,
		0x262EFD7EDFB588BDULL,
		0xD3AB160BE9B58F2CULL,
		0xCE43D5240785E697ULL,
		0x40A426A6C4043FB4ULL,
		0x1D1021AAC65531C4ULL,
		0xC53FD7C911D5A37DULL,
		0x9116F01EFC924A78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7FA700E1DE3198DULL,
		0x7A62973B00A1843FULL,
		0x6C8DAD769763ED62ULL,
		0x580E2C540765BD87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4E23979EBC0FE0CFULL,
		0xBE438BA30B0E51A3ULL,
		0xD1FCFD0DF144E2B0ULL,
		0xB8E987979B1074FAULL,
		0xCF44DF4CE657C78CULL,
		0x44FECB7FB4E43EF1ULL,
		0x343DDAF39DB99AC7ULL,
		0x519334CB869C3678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB14F61FBFA93F0ULL,
		0x005EC626D7AF5CA3ULL,
		0xC29FE158891E3C85ULL,
		0xD0DF4BFCD025DB8EULL,
		0x38950A2DCE9B7126ULL,
		0xA404244D437F04A9ULL,
		0x0540C93ECB7D6978ULL,
		0x79DA6F8B08647261ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C8BEADA460A1F0CULL,
		0xA31996F908659BC6ULL,
		0x08EDBC8C9D15F7D7ULL,
		0x6D77832D8731B4DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xEA6D203CDB568650ULL,
		0x3F1C6BA2B51A75ACULL,
		0x050C92CE545835F2ULL,
		0xA47A3C535A24881EULL,
		0xDE5ECD103E625BF2ULL,
		0x070A522FD19F4196ULL,
		0x20294EC3DE30770FULL,
		0xB3B40103E0EC1A26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99DF72C8F446279CULL,
		0xB7878563830D47BEULL,
		0xBC661D6205A39954ULL,
		0xDC28A37DD7254C75ULL,
		0x87EA250B3C49F45AULL,
		0xA5DA0B5EBC3181D8ULL,
		0xEEB2E7A606CDF261ULL,
		0x55903B22D94B642EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25DE9E3236AFC145ULL,
		0xF4BF69486057A42FULL,
		0xA039C3DA47544E59ULL,
		0x41A0F83CA4DA3E59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xDE96448335C8AC1EULL,
		0x68C1B6A83A8E0E47ULL,
		0x94D96AC9EBA8329AULL,
		0x5B2D8C4A62FB2B11ULL,
		0x9CA3981478040E33ULL,
		0xDA97CDB131FE9422ULL,
		0x3F3E1481DF92F257ULL,
		0x6C8C6F7A2FFAEDEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F1C4D697B1DEDEULL,
		0x7EE6C6AE7FD5F43CULL,
		0xFD3D3DDB418B46BEULL,
		0x204E51DFB7216E30ULL,
		0x61CD83F8A4D1D6AEULL,
		0x857A44CA92408222ULL,
		0x28D58924098D22A5ULL,
		0x9020C986ABE09A9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x076B7BCDF78B0A2DULL,
		0x8C3D423570EEC614ULL,
		0xEB20DCDC6EF9C054ULL,
		0x72D9DC9047C21B35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x69A6164B4836F2FEULL,
		0x3DC851FC258EB9BAULL,
		0x620F797F160A2830ULL,
		0x3E48C00DFF8FBD2BULL,
		0x8A8E2A656FDF42B8ULL,
		0x6910FF3CCF91E193ULL,
		0xC638ED3546B5964CULL,
		0xE0D49B46956A4278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AA89D8F1E0C17EULL,
		0xCA7E28DCC25CF437ULL,
		0x3A3E53A685E28163ULL,
		0x9A7A96F127C0CD32ULL,
		0x732554BFC3D8DDB2ULL,
		0x20170E6939B0F849ULL,
		0xCFC36C737BE1EF25ULL,
		0xC87D3371B4A7B32BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008B4309DF4930D6ULL,
		0x4863E887A2946682ULL,
		0xBD42429CAB9276A1ULL,
		0x40C792B634B03565ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xA0555E2DB8FDC42EULL,
		0x1D2683957371FCBEULL,
		0xA22F89848C09C510ULL,
		0x3D3181C6E46CE808ULL,
		0xA4844E395D7C534EULL,
		0xC171B81CD2DF10D4ULL,
		0xB399CF15B7C1D7AEULL,
		0xE5C567BCC81FCD6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A08356ED146BA9ULL,
		0xF6E53E920367F74AULL,
		0xFA233C5B756558FCULL,
		0xDDDD85E48BB9E46BULL,
		0x6BB56CDD19713B68ULL,
		0x92D9285E5D1D2E77ULL,
		0x087FFACB33D7864EULL,
		0xF1CCF189348435BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB6A4E88E58EE44AULL,
		0x10E69B48EAD19F4AULL,
		0x0DE1D038AB6C805AULL,
		0x1635878A41CB87D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x428E25C811C0390AULL,
		0xFF77884803A0CF6EULL,
		0x22713152A8F9CA60ULL,
		0xE7F9F294FB8F83A6ULL,
		0x94F1C2C74157C498ULL,
		0x6049FA5669BAE808ULL,
		0x63A2A69E6537589EULL,
		0x80494A4260A40B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A86E92CBCE8045ULL,
		0xD3B32DD40F8215A8ULL,
		0xA5DBB08CE3FB9EE7ULL,
		0x2D4C0D455253AD28ULL,
		0x9FA0E4D083E00C73ULL,
		0xA55F4E30751A29EFULL,
		0xDED4E6C80972508CULL,
		0x0A89CDA9E20E8AACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95E6A9D565B710EFULL,
		0xEA99E81643FAF17AULL,
		0x331FFA97643D5E1AULL,
		0x351A63F2736CF441ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x3859FB2DD6E9B674ULL,
		0x706DED91DC8A2E4BULL,
		0xAF62B35E8D71EC6BULL,
		0x40D6DB4E88CCF48DULL,
		0xDFE2A5BAC52D0F68ULL,
		0xCBCD6D823F992EE6ULL,
		0xCAF121F4B4E2A6BEULL,
		0x870C182B36E8A136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D075500A42D8EDULL,
		0x869F213946E0BF3EULL,
		0x15190B035AD39C45ULL,
		0xD32B9AD65C5E31E5ULL,
		0x7A6F2E1A046AA846ULL,
		0xA37BF1C5D432A466ULL,
		0x74EEB874431AF00DULL,
		0x2DE885B195FD1BD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10AD47BA69822E6EULL,
		0xE5E72A5086E1FE1CULL,
		0x5EA5516C16436E71ULL,
		0x28F2FE860F648F41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC68DA77D9F70FBB6ULL,
		0xEFFEA498232A6F08ULL,
		0xD15D5C8BD6D43AE8ULL,
		0x8BCF2C3EFEC73CABULL,
		0x8D29E8E7598EAE5FULL,
		0x634F80D044B972C9ULL,
		0xA5500ADEDF430E67ULL,
		0x22183C1C4956902EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x824E388AEB24D167ULL,
		0x63BE86763CAB3B85ULL,
		0xDFC0629E1631314EULL,
		0xE7A6E81D7E10E840ULL,
		0x199B89FB4578BEA3ULL,
		0x66CA6BE629E4480EULL,
		0x5882DE19A0F1F5BCULL,
		0x66EC73ECC8E7D55CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B6185FDAF8DBE95ULL,
		0x080138E1E2238B56ULL,
		0x58119F3500ACB2FCULL,
		0x6CA7FB2E91260FA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x0FAF874622D3B1D1ULL,
		0x3EF5E5864BA030A7ULL,
		0x222922FC08C4A9F5ULL,
		0x861B1A7BCB96445CULL,
		0x08BD969C5A4DFF98ULL,
		0x13547705F6CC991FULL,
		0x2A9E37722BC9B5A2ULL,
		0x51B0D8D055BE0691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57380A4C98EDE7C4ULL,
		0x04280005C6EDC3FAULL,
		0xA387DC0F57CAC740ULL,
		0x46117A3FB75639F3ULL,
		0x82FC6A0DCC3DCAE8ULL,
		0xAC7C691843B1B791ULL,
		0xBF1A9B626AEB0348ULL,
		0xF75AA3EB1F34BB39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93241A22A04D988AULL,
		0x7EDFF6C91AAFE7AEULL,
		0x742A714352085BFAULL,
		0x28D57A422CA13962ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x8FD69681CE68B36EULL,
		0x1BDA59F10A33383BULL,
		0x4A4A7F685EE86573ULL,
		0x6987649542C038D8ULL,
		0xC52873695F3AA9E3ULL,
		0x9893B8764ADCE42BULL,
		0xFD2B0EE449F7E332ULL,
		0x14C21D623EBADE4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34633C2AC0404DB2ULL,
		0xA76209170A8ED5A2ULL,
		0x81E35ECE704C1CA4ULL,
		0x34B99AB1956FE1F9ULL,
		0x641E89EBF4E8A815ULL,
		0x2858F03A4C77B1FFULL,
		0x9F58108A3E8435F7ULL,
		0xF42E15CC6EAF1830ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2EC02F4D654A56AULL,
		0x1D3209C1C2A9D52FULL,
		0xB5B8E1F7A1C7FFA1ULL,
		0x0AC6EA208F0FBF3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xC0FC7DB7AB0C3D47ULL,
		0x38B1795253A1B698ULL,
		0xB94F8AABA5666FD1ULL,
		0x327C45CE81A9BA9EULL,
		0xC21D0E7F53434A1EULL,
		0xE4E5F3CA3944EE61ULL,
		0xFF7F8FF59C7CC472ULL,
		0xE5B207A321BA9DF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED26D19F48DBEA3BULL,
		0xAED88BFF83914DEAULL,
		0x50AA61F83E67D43FULL,
		0x41200E171D6E55AEULL,
		0xCC8926069ED025EEULL,
		0xC18835E02B824972ULL,
		0x9423309C98E0A334ULL,
		0xCC7123551E7B943DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47CA2E032B47B2B1ULL,
		0xC9C31E10DAF4E426ULL,
		0x585B4FE9F02B8ACAULL,
		0x30FE1B4BDF96D604ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x4148A6DF84B89AE8ULL,
		0xE3E74308A7C7735DULL,
		0x70CE2883DD4F405CULL,
		0xD2E22D9485720B6AULL,
		0x61E87432CFED3EDCULL,
		0x8032C60CE1D5E4AFULL,
		0xF78CE6C05C3C6563ULL,
		0x3FDAD6D3F275406FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4710CE2D33BF3FBULL,
		0xDF1FB1FA2765A400ULL,
		0x3FE00D70427B9DA3ULL,
		0x2BDEDC358E44479DULL,
		0xF4398F6DA6E064BAULL,
		0x8C0FE23E297E5D35ULL,
		0x1ECC71FC377C739AULL,
		0x567724BC3DFB9F4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4CD8F40C9650787ULL,
		0x41F561BDDD5FEB62ULL,
		0x5D7F70310F51868DULL,
		0x4BCFC0E3C13BAF1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFA4E03039C50AB92ULL,
		0x97EF17826C9AB420ULL,
		0x7B4F400C90C33318ULL,
		0x643B5D57BEDA2EC0ULL,
		0x5687D439E20AF138ULL,
		0xF6612ADFE7E8ACDDULL,
		0xC33CEB602072DA0AULL,
		0xE1AE76EC7074F8E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0250D44E869E9551ULL,
		0xC5E8D6212887CC10ULL,
		0x4325A1CA36DC5E7AULL,
		0xE197F7080C7DD4B8ULL,
		0x07EC1B3D8B937B35ULL,
		0xC98D909A1ED53683ULL,
		0x096C640D4AF1D7FFULL,
		0x7BC812D21B78BE92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA31AA429EB6D9CDAULL,
		0x796F27BD1CF67978ULL,
		0xCD1DB48E0B0D2246ULL,
		0x22D642384FCD0275ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0xFF87FA811D9B9A7EULL,
		0x565DD539F992077EULL,
		0x6958972CB42E9EDFULL,
		0xFD0457C011308F82ULL,
		0x01500C28162795DAULL,
		0xE4FE2EECA4281738ULL,
		0x4DFC4EA047ABD292ULL,
		0x5FCF278D6DBC67A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE90EB092109C6B3AULL,
		0x10C97B2F2BF223D3ULL,
		0x0C11956E6837D022ULL,
		0x8215C170A01AD928ULL,
		0x7365060CB7DCE6BBULL,
		0x503497D2F54F075DULL,
		0x6E940C534C2EDC37ULL,
		0xF9413BC84B129B7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x275C31FF0C152A87ULL,
		0x5B80C7DAC1D83E1CULL,
		0x86C0D92BA0836055ULL,
		0x33FF9592964A046BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x535C2B7500AFCBB4ULL,
		0x0DB9D5E1BC864389ULL,
		0x88A644403354F3E5ULL,
		0x70B95E2E4F2F5204ULL,
		0xD09B32574E42B892ULL,
		0x20452DAAE0D2AFBDULL,
		0xD928382F0B57FCFAULL,
		0xE1580C424C4D6A1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x588B261FF4F29117ULL,
		0x0B8D3DE79075732AULL,
		0x3D6E95D92F571421ULL,
		0x63F52802077EF767ULL,
		0xCE80596C30E46A87ULL,
		0x7842C0C702BD41EDULL,
		0x6AFCCB6630CC825FULL,
		0x3ECBBC7889ECAE2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ACD383B67BCD3CFULL,
		0xF288C1CD233F1D3FULL,
		0xA5A9D43774B212B8ULL,
		0x2D980E1F220C4099ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x6063FDCDC7339464ULL,
		0x7EBD0A6DCC1FE95CULL,
		0x1A720FF884FE24A4ULL,
		0x7C8E39627EBEE61DULL,
		0x8275BB303C8B6B75ULL,
		0x3FE3A0287AB839FAULL,
		0x205D6135EAB8548DULL,
		0x2954F80AFECCFEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41628C0DD5593D13ULL,
		0x2B625E47996DA7A0ULL,
		0x7666B1758D048EAFULL,
		0xD76BC978C459ED86ULL,
		0x5ED948E184B11067ULL,
		0x8A98D0CD09BA7B13ULL,
		0xBC1EBBCF9EBD462DULL,
		0x4F31E0674E9D84A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x683A696F3C43DA81ULL,
		0x3C7573B8F85C980BULL,
		0x8557EBB23F3DB82AULL,
		0x0657F235E1711C11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x991E04EFB8D12E5CULL,
		0xFB8B95EBD5DA3211ULL,
		0xC49EE4E0435E77A1ULL,
		0x021DCB76A4F0EB77ULL,
		0x89553C6AA9D1F460ULL,
		0x1ED0031E14B5CDC7ULL,
		0xA802E2B3074D7724ULL,
		0xC33415B48A0E4938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2207BCE696E0807ULL,
		0x8191F78FDC1EFDFEULL,
		0xC295208EF14080B4ULL,
		0xB09FFEED285EC64CULL,
		0x3D5E2C1674AF0408ULL,
		0x9AD4D272D17A4647ULL,
		0x0D1C186AC4CC5A05ULL,
		0x9CA61C3183A2B2F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA9F5A13292D423ULL,
		0x1142D7C7F491511DULL,
		0x004BCB0B31484975ULL,
		0x0A90D5FC708A7334ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
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
		0x34D8942F742656BAULL,
		0xC301F2132E95A37DULL,
		0x74F5F9D232E1727AULL,
		0xB58687DDF1ACA94FULL,
		0x32FE74B2BEF14793ULL,
		0x292D545B66E1D43AULL,
		0x4AB03E432B05DEE4ULL,
		0xE209AA44779065C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93252A5429DCBF61ULL,
		0x4FAA87E3613A7EA2ULL,
		0x30C2345571EB27FBULL,
		0x653BC1AAB01D2FF6ULL,
		0x6591CD95553CD28EULL,
		0xDD9C796D4BECC403ULL,
		0xAFBB70895D5B2885ULL,
		0x5B7B9EF6DA479303ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FD43838FB12F90FULL,
		0xAAD7E987CDBB8CFDULL,
		0x448A4F11484D5C7EULL,
		0x496073B89A5EC216ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x532852CB5695D321ULL,
		0x9ED2111A01304CF9ULL,
		0xA0927A2DDFFA425FULL,
		0x49E25B7FD0945DA3ULL,
		0xC5A3FA5021B3D4FAULL,
		0xF570BD99CC320C52ULL,
		0x1BDB1067C1C89D77ULL,
		0x146E63BEA22A4D5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC709492E98F60FEFULL,
		0x7759235A8F5EF345ULL,
		0x75AC197B6E543416ULL,
		0x15BC6ED2B9F30DD7ULL,
		0xC34FA876F5CC4F97ULL,
		0xCF2A086D710C301FULL,
		0x4075E739CF039D6BULL,
		0x98BB0278A4016342ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4A32FD941FD8CFFULL,
		0xD5F7D254F9700945ULL,
		0xBBEA7D847AE41016ULL,
		0x10C65D10D0B40F7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC890FCF74DDFA57DULL,
		0xB12DDF6440FD4624ULL,
		0xDE2D36B6C733856CULL,
		0x1871CE67E84BD631ULL,
		0x46E4A4A7057C4507ULL,
		0xAC5FA46087559A32ULL,
		0x6C34E184054EC741ULL,
		0x95F6618D58998AC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6397D0E6C82596ULL,
		0x622EDB4D6273A8C2ULL,
		0x325AEE3840D0FCD7ULL,
		0x76C64079319F76AAULL,
		0x7837B04EFB90FCE9ULL,
		0x81DA3A7A4B5AA09BULL,
		0xE7FE56E6CF606AA9ULL,
		0x4DE7C13DFAA505C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BD9AA37E00435D7ULL,
		0x9ECCBC43C5CAA9C5ULL,
		0x4BEADBD487C4472BULL,
		0x53D759B6A8F81D29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9AAB7CB718DD333ULL,
		0x01E6A2807C435C68ULL,
		0x474C4B83321D7CD8ULL,
		0x2F54EC080FC82C79ULL,
		0xD7D5FCC9B11A2338ULL,
		0x41E264383892E44AULL,
		0x5891D963C98B43A9ULL,
		0x5B1659F61731A2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDB57483EA9D6E6ULL,
		0xBA8168CF6FD7F5B0ULL,
		0x2C38BDE31B8984B5ULL,
		0x44413CC3BF6D2B20ULL,
		0xED692CCCFFEDD512ULL,
		0x1CBCECE22E219ACBULL,
		0x592C180BEC4992E3ULL,
		0x31A6CF53BE95C30DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7F640057F7796D5ULL,
		0xCAF4F076993C4F8EULL,
		0x042E40AAEE54358BULL,
		0x11A2435D777E3BDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x020E928B4C117624ULL,
		0xBA4EF15BFE50CECDULL,
		0xBC33927ADFBB2DB1ULL,
		0x4D4A41C6D14F406EULL,
		0x4620B22DFF6892C2ULL,
		0xBE6809F1014B8E0FULL,
		0x7F75E9238BA79F54ULL,
		0x1E052551F159CA07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x322C99BF4BBA6C98ULL,
		0xF4BF5C75E5B92A7FULL,
		0xB0767E742C90C126ULL,
		0x50190F6B0C86246CULL,
		0xBAA17437270FD496ULL,
		0xFBF9765908965F19ULL,
		0x6763FADBC243D332ULL,
		0x3AFDE48366971C57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84C52B701D834369ULL,
		0xA1F97D75037C9CC0ULL,
		0x9E6672AE97FAB98DULL,
		0x3044D1045DAEE425ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x431439305A6BFABFULL,
		0xD6CCDB3C1BC06938ULL,
		0x8034F2E3315F9881ULL,
		0x94476E8EA9AEB706ULL,
		0x3FCA89990BD68694ULL,
		0x11AB1497C69E402CULL,
		0xFB307969A123162DULL,
		0x4F7711471FB8BF79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E8792E5A8D398CEULL,
		0x21A27A74DD4C1E82ULL,
		0x42ADB57D285F8EF5ULL,
		0xADBF8EAFC0194696ULL,
		0x0363DDFAEDDAA279ULL,
		0x9CE38DC316DFD7A9ULL,
		0x9548F277830CC840ULL,
		0x893E7CCE8F8EFCF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBCA1FC324FC3C9DULL,
		0x0AC8645954B7CE30ULL,
		0x5DE54556804F9AA6ULL,
		0x52EDE9C44FC850AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EBBC2F1EDAFAB9AULL,
		0x61DC6CD2CC4B2811ULL,
		0x9E7A72187383789CULL,
		0x818960B6214FC2ADULL,
		0x1A9643F51FCCBEC6ULL,
		0x1FA3A11B989F77E0ULL,
		0xF69BEF841D46F66FULL,
		0xED8A49943C3007D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF516597C8A398CEULL,
		0xF716D810ADADAC35ULL,
		0xC944F4E1B3510F9CULL,
		0x1EFABD120F5B33F8ULL,
		0xD0E152922EC36C17ULL,
		0x6F30EA40890524ABULL,
		0x829FD5CB86C6AFC9ULL,
		0xC0F09F35F70D7722ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0463209EC6E59D0ULL,
		0x9BCCB9466F85D59EULL,
		0x0CA14E9D173CE597ULL,
		0x015DEDA2551609CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC152C809689B2954ULL,
		0x873254A4558CC72EULL,
		0xED50718E17250979ULL,
		0x455EBC0F1C3CCD1CULL,
		0x09B392995E33447BULL,
		0xE2DC99050E4FC212ULL,
		0x5B1B17039ED1439AULL,
		0x91A3B27014129420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97035BA273B8873DULL,
		0x064284600EA0DAADULL,
		0x384EC71D5AF9200DULL,
		0x754608BFD42C1C37ULL,
		0xD63156CE35794F4FULL,
		0xCC5300FC6DB9F6E1ULL,
		0xD3BBBEB8E930794FULL,
		0xB561665098AEC909ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFA44C8F007D05CEULL,
		0xD95C618C1D2815A8ULL,
		0xCD28C587B209F091ULL,
		0x01EFFFFB98E0D63DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1606BB37A466DEABULL,
		0xBADC1F7FAEBBB653ULL,
		0x3C192724178C26D6ULL,
		0x926847BE27A6EC85ULL,
		0xB1B957FC1E7E780AULL,
		0xB9A6EF97BE84ACD5ULL,
		0x8D5BB99680E4FEFFULL,
		0x81ED3D1982562715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66F50898EE93BB68ULL,
		0x45BE67AF5018EAE6ULL,
		0x9B75B090E9F4FA1BULL,
		0x8298B8F4404BE2AAULL,
		0x4C37E026BE2AA772ULL,
		0x30F98FD0A2CB45BEULL,
		0x5EF499EEE7A8ADA2ULL,
		0xBE1A041A3F9E50B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0497C4B0244187DULL,
		0xBED9EF5E7C2818E5ULL,
		0x83F22973EC8B409DULL,
		0x212A04ADCEA4DC47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4B5C4E5F0A11B37ULL,
		0x2938657CB59679B5ULL,
		0x692E63A9CD074BF0ULL,
		0xF5A988642E80FFC8ULL,
		0x6FB2E7FA5425597DULL,
		0x27292D3795BDB010ULL,
		0x42C13CC2CE6AA5E3ULL,
		0x0684B10630E9D4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117B0E956BB0CBC3ULL,
		0xC822898B226DAF51ULL,
		0xD143944A497DD330ULL,
		0x9B274E7D2C6A5EFAULL,
		0xB7BABF106E4A80E3ULL,
		0x7BDE0DE1A9044E01ULL,
		0xB305E37103E7DFFFULL,
		0xD5B970483135FDC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF210C908A36C71C9ULL,
		0xCE3C82B2B6AD5893ULL,
		0xEDBA118392F2D88AULL,
		0x18ADD61AF6C88FEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F11A73D0BD890EAULL,
		0x967A95665129584BULL,
		0x5BDD8A24C58C1EBCULL,
		0x32A6764863277A83ULL,
		0xD67F06EF05910CF3ULL,
		0xE8FF6EC8203B16B0ULL,
		0xBB484E4E6B3A9BAEULL,
		0xD7C63481C84493F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC92760C34FCF17A2ULL,
		0x644731F6339D4F40ULL,
		0x80A8F973511F218BULL,
		0x6352DB8FB7BC7E77ULL,
		0x4C1A6CABBD225F3CULL,
		0x9D2F460AFCC75F0AULL,
		0xC69C01D270169570ULL,
		0xE4F5F8BA3063AC8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D92C767C774213ULL,
		0x73196F8360B94BC3ULL,
		0x2CC7EB18BBC5EA70ULL,
		0x5A3C7A5936CD557AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58C333F807CA60F3ULL,
		0x33302C352E747CA9ULL,
		0x4AA5352AE993BED2ULL,
		0xE561537D8BAFD177ULL,
		0xEB3D354591B4458BULL,
		0x1D748F75DC3D6558ULL,
		0x98CECB14B9A32BD6ULL,
		0xE68EF9646BED8B87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53886CDB1A40864ULL,
		0x0F6981C1CCBC8AF5ULL,
		0x16DB1A931F700DDCULL,
		0x49BEAE3B02DBE396ULL,
		0xF7ED44F87C3D91FEULL,
		0x611D4C75EB212F45ULL,
		0x791B734B01527ED5ULL,
		0xE19E58DD285E5A19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA168589B85C4FFA3ULL,
		0x18BA9C712BE7F883ULL,
		0xE8692289261D5F12ULL,
		0x575A795690154439ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CE7D0423901EC13ULL,
		0x1FB7331A56322B5EULL,
		0x44B7B434269567C2ULL,
		0x7852A995BBDD4E77ULL,
		0x4C45678D523D625EULL,
		0xEA4C63104A582D1FULL,
		0x852595CF7DFC02F3ULL,
		0xBF0BAE2C87C0E1E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB244593E92F3F094ULL,
		0xEEC88A0C6472FDB9ULL,
		0x0487D88A24BC6A17ULL,
		0xA182E72C2A05FD3CULL,
		0x6F10C405769D1B0DULL,
		0x07CD900A839B7C9FULL,
		0xB18FF1F3D8ABEED4ULL,
		0x515DF4DB82465184ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5073BD2E3FD893E5ULL,
		0xCFC1FBE971C1609FULL,
		0xA8662E448BBBFA65ULL,
		0x1E9944706208BFE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC82CE7CE114AF8BULL,
		0xBCC0EEDB09623CBDULL,
		0x65D6E3058E9D65D8ULL,
		0x5D30B3D44D135D0EULL,
		0xA8FD70C1DA37A099ULL,
		0xDC0A58F8A9A2DDB4ULL,
		0x0BFD07601EA5787AULL,
		0xAA49F7CF26831737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40EF49F061A14505ULL,
		0x4AC56210AECFB8FDULL,
		0xF2DBA373FE825FBBULL,
		0xDA6B2FC82AE4AAFAULL,
		0x586029927FA2FF7CULL,
		0xD2CC7322465BD83AULL,
		0x5CCE4669594D75A8ULL,
		0x6361CD332DE12A6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82EC1593F1835650ULL,
		0xD12BAA9D171D53E8ULL,
		0x73EBE432DB2B714AULL,
		0x093BD7330A37D7B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3B9F8A3F1D22667ULL,
		0xC58E7C86575D81C9ULL,
		0x24203D0A1B9ADFFFULL,
		0x650773F00F152D4CULL,
		0x98C44A5E2FA3758AULL,
		0x3F19871A8F63D617ULL,
		0x3EC9DFE3C294AAB7ULL,
		0x6F3DCD6BF0776D7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x732B4EA43215A2C1ULL,
		0xB4C6A03F8EC810D6ULL,
		0x119F5510F55BF99BULL,
		0x4D3A2DA0D744F304ULL,
		0x55A11F078F1EBB4CULL,
		0xDF2ACC19F02FD386ULL,
		0xC18F93906A638884ULL,
		0x4135E1FC84E8E118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47C718DB937029D1ULL,
		0x4E379E5E6A4DD283ULL,
		0xA9283C583D89F9DEULL,
		0x6CFA38D92EF9117EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23D6FDC68FDFF74CULL,
		0x3DA6553476F951DBULL,
		0x254BE3F5227BDB20ULL,
		0x85642F8D31BCA351ULL,
		0xED1EDE79CD03F2C8ULL,
		0x576EF82FE0A29630ULL,
		0xE71BF7940AC58AC1ULL,
		0x521895859548EABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECCEB1F709202238ULL,
		0x398E770CBA8AFA17ULL,
		0xA0D3E2B3E8373115ULL,
		0x5584FCA7C999A5EFULL,
		0x21863C0987DAAC85ULL,
		0xA6431CD4619C0A55ULL,
		0xEFF0AD1C51BE9C6BULL,
		0xD6E9F33C714CCF4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FB06879CAE0400EULL,
		0x509A6DBC97671A63ULL,
		0x34E50F06B14C0AC3ULL,
		0x78CB49C0BF8F1026ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E23ECC50C62092AULL,
		0xD751DE1C62E63CA2ULL,
		0x9E6A425D7FDD258AULL,
		0xB9D262630D2FC1C3ULL,
		0x4DEC7B9418BBE7E6ULL,
		0x3F1ABC6567F6B8DCULL,
		0xFE6C76B25D124860ULL,
		0x1575E662B8BDEC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2100CEC6BB82A08AULL,
		0x5C24F5BE41094A62ULL,
		0xAB037C2DF93FEAB9ULL,
		0x57B6C183A26E3218ULL,
		0xC51CBA6A490DD868ULL,
		0x989DBEC8D9FE559FULL,
		0x98FE4A71D2359801ULL,
		0x9DFB53E4ABE0F3ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BF9CA3324B5B25CULL,
		0x31BA8D9B34BBAD3CULL,
		0x01C157C4235F68DEULL,
		0x1E4D5F95538E7080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A4231432842A5B7ULL,
		0x885B97B9C6E37F55ULL,
		0x8E1A38DB1FE31789ULL,
		0x859B10665F7AF7D0ULL,
		0xD929A42178BE869AULL,
		0x44DC4296D750359EULL,
		0x426CA904A782F375ULL,
		0x0DA4ED94924AD900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71A56466837B32A1ULL,
		0xD7CBA2E76B773485ULL,
		0x24045AFF7B9D11DFULL,
		0x65087E2CE307E60FULL,
		0x2AED1F89A09975E9ULL,
		0x95344AE861AAAD90ULL,
		0xD106B98734668EA5ULL,
		0x3B36E79349E83FD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85987B66BA47EC52ULL,
		0xC37EB8B7D1FE7CFDULL,
		0x3F376A7ABA7CFC7DULL,
		0x5CE7766A3B15CE34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC06D2E68505BF17ULL,
		0x761353F25E262CC8ULL,
		0x21C96047DEF4A84AULL,
		0x7604A41B39D82D17ULL,
		0xFBFD8C9D741135A5ULL,
		0x8B15462BCDDACDEFULL,
		0xE19D153E1335A46AULL,
		0x405458D697B41CD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D9D579F66E3CA1ULL,
		0x0D499C2DF1F1497FULL,
		0x93ACCCD45AAE9E0BULL,
		0x4EA7F3A31EE6E953ULL,
		0x07C33E25FBB1565FULL,
		0x5471E81F05AE97EAULL,
		0x3B47B70898ADE2F8ULL,
		0xD1F7839BDE04D806ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32D4A3286CD2A3A9ULL,
		0x8509ADAA22C4E82BULL,
		0x3EC88F63B46CC133ULL,
		0x0924572FAAF579D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3750F1AFFC52203AULL,
		0xFE256FE1480EC18CULL,
		0xB164952F7362B23FULL,
		0xFA10B4B275A72532ULL,
		0x5CE46AF5ED88FF9BULL,
		0xDA0C384918F60F56ULL,
		0x74AB9BA4ADD83B3CULL,
		0x5986B7BDF306E987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x479C319C53E85DF9ULL,
		0x267E871F10D77072ULL,
		0x7F8DF8D420F0436DULL,
		0xCB181960A994E385ULL,
		0x92A8801F2EEC1A1FULL,
		0x08A9129BD9958768ULL,
		0x6559517F62B41D92ULL,
		0x09BF10D3D4078952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4999BF3F3B3D471ULL,
		0xEC5E80799F8B7E65ULL,
		0x780D9DE479CED62DULL,
		0x069B621265FA898DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DED8D5191A5AEBEULL,
		0x304B465C09AF5DEAULL,
		0x6A40F9CD3FEF029CULL,
		0x0F13761B85D635ECULL,
		0x74E1040E990A2A0AULL,
		0xD37C69E21A3350D8ULL,
		0x6B555B4040E39EB5ULL,
		0x4A797A46E5159AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDBBD7AA8AF6F12BULL,
		0x0A7BF82AA8D9C5BCULL,
		0x6AE6DCB47DB19AAAULL,
		0x6B94B135B568CDF1ULL,
		0x16AD3A8EDE23D498ULL,
		0xDAEA34A5924DB9AAULL,
		0xF7F292F82DB66EA6ULL,
		0x4D57C58EBFDD873DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABE19E9CC4DF6C59ULL,
		0x0B83352D8CEA090FULL,
		0x2003D7CB9AF28A2BULL,
		0x367F983B56C04A3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D8262BE3961DA74ULL,
		0xEA9A77B42A69B47EULL,
		0x1ADB9EF4386BC05FULL,
		0xF25DE5FCDEF8D78CULL,
		0x8C03DBEEC70CC0D3ULL,
		0x687F6EA107E6EA12ULL,
		0x7AA68B8E6B501160ULL,
		0x4204845FB7812297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124DDA3C6F406D61ULL,
		0x778B94BF735D8F6DULL,
		0x49902A98C0B75AD4ULL,
		0xC16617F14A0F9239ULL,
		0xF0A57ECF34179634ULL,
		0x32DA26FD1B755701ULL,
		0xBDB6C318D63697AFULL,
		0x8A0CB78D8875C7B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B365B319A85BF0BULL,
		0x69978549CFE7F988ULL,
		0xDCE335CF997C75D9ULL,
		0x7FC0353E9098C2AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EA3FF6CC189DC7CULL,
		0x7CE5A53365742DC6ULL,
		0x911A114CA33A852AULL,
		0xB40D6BB203F0D10CULL,
		0xC1A0F7305DA21A2EULL,
		0xFF2A7BF391022692ULL,
		0x462CAEED89F841C5ULL,
		0x74A2F3B9C0B3F0B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF86AD901D0DB23BDULL,
		0xF8FC46E968F0034AULL,
		0x9704A671457EA2B3ULL,
		0xE0EABC5466A69321ULL,
		0x39B4201AAA064998ULL,
		0x42E775EFCD7225F3ULL,
		0xC025B8A970A5BE22ULL,
		0x8C46C3FA3B0670DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD36113A399CFAE6BULL,
		0x75DC42D903E44229ULL,
		0xDF1DF8F71FFB6CC4ULL,
		0x50D1C5CB750B37C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB89BEE159BCA098DULL,
		0xB7440641AE77A2A5ULL,
		0xC9AB5D856F36AEB6ULL,
		0xD139E307561F3C66ULL,
		0x4ED8BC16CEA3B824ULL,
		0x49917B14AE08967AULL,
		0x37B6729815EFAFFDULL,
		0xC50294F49735BB73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22B1C671BBC32EDDULL,
		0x1A8030250F472A43ULL,
		0xA12BE5342661996CULL,
		0xFEA5F9D32C2CE5F6ULL,
		0x80E31D9CB61A63F9ULL,
		0xC9CEBE8F19D2F9EFULL,
		0x237EA45768E357EAULL,
		0x1CA05C56BA34C643ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x285FADC384695CB5ULL,
		0x93ABD1F09F25B4FDULL,
		0x28C815EAF8AA2809ULL,
		0x512850A2F816BB93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41B7F1B920C563E5ULL,
		0x91EF3B145370846BULL,
		0xDEAECEE9CEF91519ULL,
		0x32CB87290E4442C8ULL,
		0x123152552DAA6DF1ULL,
		0x27570831ED14A7D6ULL,
		0xE77812A4827023B6ULL,
		0x798BCEEC1295AF1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51177B7AED561E39ULL,
		0x1409E896B991B61EULL,
		0x941B3CA80761FC69ULL,
		0xA5CE5C3BAA175D9FULL,
		0xACB88DE5A219008DULL,
		0x7593E6D93078FE4EULL,
		0x8BAE1BD3B14453F1ULL,
		0xE7D35FB5F07BF676ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008D9ECCEB057FFEULL,
		0xE0DC45A998F9F866ULL,
		0xEA8E3540D417EFE2ULL,
		0x2E5DACF673FE4D8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03686DDC7C79D033ULL,
		0xDCFA5399327AD9CEULL,
		0x4E9962E6C29AAB63ULL,
		0x267D6E66A9CB13ADULL,
		0x4ADD0810C182FE44ULL,
		0x015A893FBCBB5F09ULL,
		0x867C2146D778856EULL,
		0xF8664A8671AF82CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADC3F82A02F9E3DULL,
		0x9A32888891148ADDULL,
		0x000678B4C20D90CFULL,
		0x97E049CB7F37C091ULL,
		0x3F50181D217B96C9ULL,
		0x217080B995BA0ADDULL,
		0x848986C92E76D5D9ULL,
		0xAB2702E9D8CE1A82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF77CC839D638FDAULL,
		0x7F850EFA6B98CD79ULL,
		0x9895D8D916CD2AADULL,
		0x0601C5D9DC08CE18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4BF508712A72691ULL,
		0xEA65315A8DE9B336ULL,
		0x2AF59DEC82FE939CULL,
		0xA065A9A4855CD020ULL,
		0x15CA53954274323EULL,
		0x77458214181640BCULL,
		0x11D565676F1AC5BCULL,
		0x7951CB27BCD9C371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7E76B6EE322125ULL,
		0x4844F14AAF87E889ULL,
		0x4EAF262591CDC0ACULL,
		0xE11C872D71779071ULL,
		0x23B4B4C425D13B79ULL,
		0x504A6B68512203B7ULL,
		0xF73D8D50018C7574ULL,
		0x5AB1DFF345D4CEC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8766CDA64A5A742ULL,
		0x6B659D8F66A2D968ULL,
		0xCED08B413450BDA6ULL,
		0x4B060C40BEA190A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA074998C419D2AB6ULL,
		0x4A2ADA8DE60A15C6ULL,
		0x7221CFDEB239A7A3ULL,
		0x2557817AA21111BDULL,
		0x67C66F26F1003E3CULL,
		0x674D8193888AB609ULL,
		0xD001880C2E441745ULL,
		0x69148391EDD683CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3450E80D3E893CECULL,
		0x10BA7E2BF3273CF5ULL,
		0xCDB3F750306AA506ULL,
		0x0831FD4091C1731FULL,
		0x8307DCD05D5C0813ULL,
		0x3E8D6719E11D5BA1ULL,
		0x72D6E24C67050ECDULL,
		0x79F15F98645ECD39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x606D6A58ED73F781ULL,
		0x45F44A70CD1E443DULL,
		0x78C27306152A4473ULL,
		0x1C5CDB447814B87DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14D3EA8EB19962B0ULL,
		0x3C7D77C9D0B73CDFULL,
		0x97C04E48AA09BD3AULL,
		0x7DE0A941DE27F77BULL,
		0xE10E2FF73AB7D2F3ULL,
		0xB9F08548037861C2ULL,
		0xE2EF883943904EAAULL,
		0xC6CA19008BC52681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E71D3CA01F611BEULL,
		0x79EA0D9A53592E58ULL,
		0x7125EDC78030BAD2ULL,
		0x4825168324361B57ULL,
		0x963BC7029D29B174ULL,
		0xCE96DFE801D7A8E3ULL,
		0xE6D065C8C48BF97DULL,
		0x6C106D386CD160ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD19DAB1412BC4BCDULL,
		0xB1E1F66FBB397FABULL,
		0x93397D34047DA712ULL,
		0x2D4B127352213041ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB1B78087FE9662AULL,
		0x4956673CEF486694ULL,
		0x49E97411D771ECDCULL,
		0x13364D98FDD91C26ULL,
		0xC262C348ED8DAFDFULL,
		0x3AAAADEFC4B0EEDFULL,
		0x1D07481EF82C728BULL,
		0x65AEE397A1A78743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B2548163735AFDEULL,
		0x3DE58F947A03946DULL,
		0x09BBBABD9FC21A42ULL,
		0xCE4E963D1B828E4FULL,
		0xA24C00C473288F8BULL,
		0xB33B5767F7F7DB61ULL,
		0x8E081D5C39353574ULL,
		0xCED627D6EA17D622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83570F9C73B68051ULL,
		0x25F7AFD0D8BDB6E0ULL,
		0x7A0E123C9062E3F2ULL,
		0x291395F721AAD8ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03B196E298C1F21CULL,
		0xF9632F88FC865279ULL,
		0xA91A3BFB86E1F967ULL,
		0x2332988DED0905BFULL,
		0xE4B08C10BB82E2D0ULL,
		0xDA1F84F196B9E74EULL,
		0x82629CA0961C7A14ULL,
		0x788AE46470250133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD185090C7A6F830AULL,
		0xE54803ED4DBEBAE7ULL,
		0x1E8A67B73A83137CULL,
		0x3745011F1DA478F7ULL,
		0x27E0AEA7A3CF02C8ULL,
		0xE1A94C03E335B2A3ULL,
		0xEE9684C99EF8D000ULL,
		0xC6BF9A723158F109ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39076B6FA305AE7AULL,
		0xF5A79EE45467690FULL,
		0x7ADB5E2CFBAA24E1ULL,
		0x501A916421AEF2F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF34FB6E71AAA9E3ULL,
		0xFA7750498A609C2BULL,
		0xC43ACD60C3DEE2B8ULL,
		0x947E0DC98908A34EULL,
		0x8CFDA9E0F78DCDA9ULL,
		0x32B15537D71118C6ULL,
		0x077D6182903FA510ULL,
		0x720B0F0863EBD08AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC7ABB48A07A4750ULL,
		0x2C5FA08821BD5F5AULL,
		0x7B5F16EDA36F2461ULL,
		0x6D4349C9B8370D50ULL,
		0xA3190058EA14BC65ULL,
		0x074B9356609A016FULL,
		0x35F5BAE60BE48AB8ULL,
		0xC31A783B29509DD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAAB6A57D128F0E3ULL,
		0x3F327738FE50B3B7ULL,
		0x62FE71AEC5F5A76EULL,
		0x1EF1267683DB1C89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA24C4CA0946ABA7CULL,
		0x5433A7BDFDEA6C64ULL,
		0xCD6D50955E660BC3ULL,
		0x173BE097CA1FB5CFULL,
		0x7480B683AC94B08CULL,
		0xA110379F37082BCEULL,
		0x101D29EA309C9C48ULL,
		0x673C4651B3FD74D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BDB5BAEA1DC4B9ULL,
		0xC3BBCD6E23C99111ULL,
		0x55D0D9004A8172ADULL,
		0xEEB355EAD529384BULL,
		0x30F408C6738021E3ULL,
		0xF4C89DC5DF0B108CULL,
		0x6D836B1120540D9AULL,
		0x22A5011B24ECCF79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF47060FC235A242FULL,
		0x2318B092E9B2E728ULL,
		0x9A6ECBCD7EA9C6DDULL,
		0x56FCD0C6316F0860ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDD752AA19045D8FULL,
		0x8CB5C091EDEA7603ULL,
		0x4DEBE3D7F059DB1CULL,
		0x8935116DB89EFDCDULL,
		0xEC6592F1122839D7ULL,
		0xE231225B02A833D6ULL,
		0xB4BB9EDC2FEEF478ULL,
		0x38B22CD6813AD8F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF8DD9626A2AAEFEULL,
		0xD15926334DBA6CE6ULL,
		0x0BB883CB23264A21ULL,
		0xAD51BD730CE68C33ULL,
		0xFF80CDA2BB11C1F4ULL,
		0x3E62A155E68777A5ULL,
		0x3A5E3C10F2FC5CFEULL,
		0x22326EF01A4A6EF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x383EC2E89C2F7AB5ULL,
		0x0C03C120CD0BF860ULL,
		0x6C100A37D9360D2FULL,
		0x32D9842DF3682E44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA2E78CD51791476ULL,
		0x1E361B33B131E214ULL,
		0xA82AA52D6FE1AA5BULL,
		0x5EEB055BFA4CD063ULL,
		0x8B027836D2AA5B0BULL,
		0xEB0321FB938350AFULL,
		0x301925F5B4C5D6DFULL,
		0x03E82FFA6CC337E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53ECBCD6E06B1D4ULL,
		0xDA71818D6E409A2AULL,
		0x7A01D1EA7F260643ULL,
		0x09FCFEEEA2A0B58EULL,
		0x51A1C54245C1EA53ULL,
		0xC418F67AAB9E0B18ULL,
		0x6D65B381D7EBEF0BULL,
		0x639103D04B668F6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x694A3D4CCDF31BDEULL,
		0x0A870EC8AEF99C5CULL,
		0x14CBD075B9140D95ULL,
		0x21DE94AE4B6D1D5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7986AD55F4BD62FDULL,
		0xDC9B6D3512FD002CULL,
		0x4173932A51611F61ULL,
		0xEC8D43ABB6F45008ULL,
		0xEBADFF80C783586CULL,
		0xEA547680E2DF9065ULL,
		0xA375B1049AE6427DULL,
		0xD06763CE40C579C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24623BA558C0F91DULL,
		0x95904190A7F751E2ULL,
		0x2DD125F799225474ULL,
		0x9172EB2F1853C376ULL,
		0x28752097C2A8EC93ULL,
		0xBCAC0ACE6D680EC1ULL,
		0xF43A8D89F69046B5ULL,
		0xA93F68EC6C496B00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F95884754686CFAULL,
		0x0E0B2821DAC2ECBFULL,
		0x1669B1671D022AA4ULL,
		0x2B099602290ABDEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5D022F50C8EC8D5ULL,
		0x742C66698B572872ULL,
		0xFA956E62E723CD30ULL,
		0xE6952D703E7C0941ULL,
		0x648E73838A5C682AULL,
		0x5D8C74993AA44702ULL,
		0x46F002EC0DC6D706ULL,
		0x47CE43602BB33764ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD86D27070A55D7AAULL,
		0x62580EFD34D5B197ULL,
		0x24D82715D2B70A9CULL,
		0x498DBB8293A87C87ULL,
		0x57FD58BC94C8B95DULL,
		0x5FE939F8218F1914ULL,
		0xFF83167CE8350B55ULL,
		0xA155A7934A69D644ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAECF5767624E1ABULL,
		0xB80F0B560FA64830ULL,
		0x6FE85FCCA810FED9ULL,
		0x52EE92571BB7F75FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x482A7D816999B97FULL,
		0x3896C4DC97869F48ULL,
		0x86C6920E0549166AULL,
		0x4049E2A3FAB6454AULL,
		0x529FD96E77BF1F02ULL,
		0x812CC0A5F90405DBULL,
		0x60A170D630E88E65ULL,
		0x626E48EA8EE465A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A47EB32C2D4F49ULL,
		0xFF5AB07CE0C3AD84ULL,
		0x2142C828B0F95D40ULL,
		0xA53E7DCA67141B37ULL,
		0x21D70CE74E83674DULL,
		0xF114CFED0A3150FCULL,
		0x87F0DA4CB630683FULL,
		0x6D9C758D9DF967B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C545ADE5C49AEB5ULL,
		0x9CC9CFD32A09CAE5ULL,
		0x8FBA224D8BA562BCULL,
		0x7230C4A55683DC1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3E80FE4C28ECEC1ULL,
		0x4C67CAC006F3CD57ULL,
		0xA8460E1EB98DB71FULL,
		0xC9E78DE685DCBF26ULL,
		0xDA5FFC9BE6740F59ULL,
		0x76871B42EBBB5930ULL,
		0xEEDFF5FFF4D83F45ULL,
		0x1AD5C1BDBB9BD50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x273DE9B8E024CFE0ULL,
		0x9E00067DD50196FEULL,
		0x9AB0D97446AF90C6ULL,
		0x5EB7652BAAA71CE4ULL,
		0xB509A7239C99B5B3ULL,
		0x1B2F4DC71F3F62B3ULL,
		0x62E83AD0B40A3212ULL,
		0x3FC516B8E38A5AC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x077AD606D8D34CB4ULL,
		0x3D7044A28C58CCEDULL,
		0xD45AFDAE11741BF8ULL,
		0x6FA98B72EDCDC9C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2F234DC2EF04593ULL,
		0x558B0EA5E828C0FEULL,
		0xC7227E26D878193FULL,
		0x6A2967024CC4DDD3ULL,
		0xF27BD7591E3C3B5BULL,
		0x870C007C43437191ULL,
		0x59FDDA9AB8B1DC92ULL,
		0x5C9E82AA4FED7D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x290F68A58F89D19AULL,
		0x77AEC9EF35CAE64BULL,
		0xDB197460A2B0B4D7ULL,
		0xB6198EE6E1C72ADEULL,
		0x80A59302DCEF3A54ULL,
		0xD77ACEDB9895DEF4ULL,
		0xA54F73238CF41705ULL,
		0xD0E23DFCBF4DDA01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FB0F10450D49857ULL,
		0xED69A29008219E12ULL,
		0xBDEC6576B3F2B749ULL,
		0x720209DEE2AFECEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x745D9959FB485A88ULL,
		0xA51214A040881C83ULL,
		0x5099F483B8050D98ULL,
		0xA5F47BFF0B61C08CULL,
		0x7E11BBFBACAE2D54ULL,
		0x240B567A35951A8AULL,
		0x608B1AF2EA3F85E5ULL,
		0x8CF0EAE026D13987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED82F0E24895E2B8ULL,
		0x432BA79506B69417ULL,
		0x1625D3D1EB0210E0ULL,
		0xBB9C5087BD8A7C3BULL,
		0x3CC7AD0E4972568EULL,
		0x151957E505830098ULL,
		0x1418B1795DBD1337ULL,
		0x61FF9A6F39A20A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37D8DFB46D945A18ULL,
		0x99D237305C816261ULL,
		0x936FC8BCA860028EULL,
		0x4A2A1C3A82D851F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87B0ECD0E023EC18ULL,
		0x4A0B6EDFB548FAC0ULL,
		0x3C75F8D178D9750EULL,
		0x975435AE103D6365ULL,
		0x8BDB11E8E586FBFCULL,
		0xF2510AA4EFC3D9BDULL,
		0x97763ECE457E00D3ULL,
		0x32E9D1924E6403A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8AEC3EF4CBC9A3ULL,
		0x4A00972722F8FA3BULL,
		0x91BCB12DC073989BULL,
		0x46A38A48474309D9ULL,
		0x8A4A5F14A1E5D0BFULL,
		0xC0D663425B723158ULL,
		0xC812F6746E4319C0ULL,
		0x60F1DC810B4063EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96A08C13F5448C79ULL,
		0x583FB05A966EFF83ULL,
		0x737604F9AB24294CULL,
		0x7B7F0BF5C0440ED4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8059EC9F7CB4A0B8ULL,
		0xF09B4302771FDA51ULL,
		0x74347CDA3D8F44C6ULL,
		0xC079BBA28B90F609ULL,
		0xAB3B80A519F6AFF0ULL,
		0x0D364E4D10B44EC7ULL,
		0xE6D38B289DAD0E50ULL,
		0x5B43CD228438D0E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6258F9FDD74BB59BULL,
		0x733800D7DF6CC48DULL,
		0x06C560571ADB0F75ULL,
		0x4AE8C440BABB04F7ULL,
		0x7B49F94C9930E256ULL,
		0x781BE3B57A3BEC0CULL,
		0xB5ADDA2F4129783AULL,
		0x38E8DC7D982FE97DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BDB09C4C2C570CAULL,
		0x9F4F14AAED91BD8DULL,
		0xB9076186DE3C7C85ULL,
		0x0F10AFDCDA284AD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF837AF291E2B398ULL,
		0x51AB2AE67A5E4636ULL,
		0x20C1BDE0B12D49BCULL,
		0xA6E1C7BF1302801FULL,
		0x0E433E43E9C8482EULL,
		0x3B5C434AF77A873CULL,
		0x26F505F1003CC9A2ULL,
		0x1514C491131CC24BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAD993ECBF396C3DULL,
		0x1FD79D104E7D6232ULL,
		0x99F3CE323957E621ULL,
		0x8D9E2ADB1FF3909AULL,
		0xCBF3F55120FC9930ULL,
		0xDC27373AB5977D76ULL,
		0xEB1D66E6D60731FFULL,
		0x96808A0798721490ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C6EBB0FA0E53E2AULL,
		0x53B3583FF394574BULL,
		0x68CF8B30BBC9E5B5ULL,
		0x63444D4C2864B929ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA650E8BE2ECFF870ULL,
		0x153714CC86563D99ULL,
		0x7A515B3034D487E9ULL,
		0x9A178578F0764909ULL,
		0x1A29C50C03D2F0EEULL,
		0x6DA09B1CAA88BDC4ULL,
		0x4983D4CEC4517908ULL,
		0xD460ECD876457E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F29C0D8E463C6CULL,
		0x0E7C8E366E7DA534ULL,
		0xD6C96929EAF8A2C4ULL,
		0xFD14F56020C7BD6EULL,
		0x9D1F612F024F4478ULL,
		0xE9233AFDE7B684D5ULL,
		0x5AB257065052D1E3ULL,
		0x2BCA99DAEB4D23BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DE91F7EDA15592BULL,
		0xB156CB27030D0BCBULL,
		0x16A09DC781A8B490ULL,
		0x2352E1BB708BF624ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A65311DC983A40AULL,
		0xA5A9162ED3B1D94DULL,
		0xBA408D9C17CBC6BFULL,
		0x6EFF4848F0462A58ULL,
		0x4E78039F2651A376ULL,
		0xFFF4771B565CF73AULL,
		0x8D7A5A986D535A6DULL,
		0xB50FB22CD3097B78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDED1C033532A0E56ULL,
		0x9EA3E110C38D22CAULL,
		0x76CABB770F7B5C41ULL,
		0x566A582FD4A04C02ULL,
		0xA21831D7B43B352CULL,
		0xCD7D073E8F16CFE1ULL,
		0xB8A759FF6C20B029ULL,
		0x6D2ED4068DEBFE0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1CC948565ADF63FULL,
		0x84BFCFE3A48E8DABULL,
		0xDAC7E8DB35D5B09DULL,
		0x43F5E9C75E067BE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF9E929CE42D0C7ULL,
		0xCCD44FFC798B0246ULL,
		0x4338252C07C3339EULL,
		0x5581820738F0C787ULL,
		0x9FB8BF33DFCA0E48ULL,
		0xDB20801E66D20701ULL,
		0x52B6577293A812A2ULL,
		0x30CEA2EC943B95DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1F48CDADE5C32B3ULL,
		0xF2A66207AE60FBD6ULL,
		0x8ED438506C62C5D5ULL,
		0x17358588CC61DF82ULL,
		0x1CE5A20A0790B8A0ULL,
		0xB965CD155D9D6827ULL,
		0x61F0B0B15C19AE62ULL,
		0xF6F1C1A31FEFC514ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x745BB085086950A3ULL,
		0xDBE4814C28F99ADFULL,
		0x71BAAD89DA834F4DULL,
		0x55156D65AFCFE5FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46536958504358ACULL,
		0x9FDA5222813435CBULL,
		0x6529C79C83394B9EULL,
		0xEEA846916DA65D62ULL,
		0x2419D668CDBC0982ULL,
		0x3925C2B035DCC728ULL,
		0x7FDCBEC6D0E4F37AULL,
		0xFB941364E2DABE3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x927CAC55A8BB66EAULL,
		0xD21AB68EFA3EABF1ULL,
		0xDAF6AAB7E4DB7E21ULL,
		0x5531118AA6EFE9B8ULL,
		0x2FB4F8732D806EABULL,
		0x0876AD211A4B6068ULL,
		0xE3F2727504685BE4ULL,
		0x08318B3C831D9FF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFACFAF787060F317ULL,
		0x07BCCED19E8ACA57ULL,
		0xAEFA7108F8DC4DC8ULL,
		0x3A176B04FCC8F24AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6E2445D0FC2956DULL,
		0x386CA2E4F7B2CE0CULL,
		0x6B9FD0D8EBFCBBCDULL,
		0x7328B16D44F61AECULL,
		0xE0967BCD4276E25EULL,
		0xDB2C25B9A5BC7E72ULL,
		0x5712EB2C36A40D89ULL,
		0x773311E1DB4436FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD49B5A391F8D5B5EULL,
		0x3849560376C2826CULL,
		0xD687D7C58D364FA4ULL,
		0x183F9C9FFD14EB08ULL,
		0x70D2E24D8409B9A8ULL,
		0x5FD1E97203D06EBFULL,
		0x9ADC4B6F3F0EA02AULL,
		0x443A33DEB3863FE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x694FB31A34694630ULL,
		0x4F883F8389FAA042ULL,
		0x8533AF201EF4A855ULL,
		0x6BDA09452E13DD43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16556DD75BFD6420ULL,
		0x623C000A4A9DDA65ULL,
		0x528A4BEAE9DDEB1EULL,
		0x16B4A2A1BB656AAAULL,
		0xEAE6381A8BDAB783ULL,
		0x2A7252CD4DC1B811ULL,
		0xD1FB544E7E409F14ULL,
		0x2E6314FCB78D5212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77725BD060626003ULL,
		0x88645BFF8F4604CBULL,
		0x4758B5F70778A52BULL,
		0x6833AC9ED28E8593ULL,
		0x877807BE5FB86196ULL,
		0x0AD778EFE20A2AC3ULL,
		0x5FF0F22AE4D68CB7ULL,
		0xDA90D45CEB327E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x613E3FB588B3C16FULL,
		0x8AD3FAE8B896CF3CULL,
		0xF8BC273CA823FFC5ULL,
		0x1FB68DBB3E5249B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x056AFAE8F8742EAFULL,
		0xF01C50098623E350ULL,
		0x59EB149492D4B1A4ULL,
		0x418319033DED5359ULL,
		0xD36CB9FAC04CA3ACULL,
		0x1BF962FDFFAA86D0ULL,
		0x332E680FA63CC7A3ULL,
		0x4569C27313131CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1962934D963F4152ULL,
		0x56370E99801FB6F0ULL,
		0xA9D85A5DF0A8238EULL,
		0x92E9246BAB8044A7ULL,
		0xA7AEBDC512C23C51ULL,
		0xF289DDABCA270671ULL,
		0x8BD48ADE8C4861D1ULL,
		0x20E96A632A4536AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A3BD79324C0459DULL,
		0xC0730BA3F7893A80ULL,
		0x87698F807C73AB22ULL,
		0x19A706F420FD3504ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x473630D23F5AD315ULL,
		0x06198DD1E96005F0ULL,
		0x46473C3AC8317BBBULL,
		0xE0591CF348BD7BEBULL,
		0x6CA112D833A2F883ULL,
		0x2085591219234DF7ULL,
		0xA6FF609156089C40ULL,
		0x7187424E3C0D6300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5F2EFB453E1CC8FULL,
		0x78B31B7C60F514E5ULL,
		0xE5DA1479532D795DULL,
		0x732F546C0ED2DDB8ULL,
		0xF04A9B4B295C9E94ULL,
		0x2AE7EAECEB6D7E9AULL,
		0x479CFC415AA54A3EULL,
		0x02BCE28E7DD2558EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE619000D71EA6273ULL,
		0x02C4CBDA5167B8C4ULL,
		0x89080BA0C5C22EA8ULL,
		0x5F33FEFD76AE9D2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51E39927687447F4ULL,
		0x4B5DC0B2E39D350FULL,
		0x1E3F0CEE2DBA43D0ULL,
		0x4551AC587DBC53C1ULL,
		0xBC0AFB6C94C14DC8ULL,
		0xEC85078D2C41C015ULL,
		0x71CD583610A24518ULL,
		0x8AB23FF25AD0B60BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75EDDD7467FB505EULL,
		0x7AE16268E5C7EF89ULL,
		0x8B9DF4F21D22D490ULL,
		0xA0781C6FB3393BE6ULL,
		0xF0F901AA9D7DF827ULL,
		0x1F1E20E4C0823077ULL,
		0xF98A7713F60654E0ULL,
		0x5D98FB7DFE47F344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A0CE7DB477AE60ULL,
		0x4DC29B49FC4496F2ULL,
		0x6C8E830C03BD17AEULL,
		0x5699B92E86D00150ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8794A354EE79B748ULL,
		0x6FE63493DB9349DBULL,
		0x4E1A08A7518B336EULL,
		0xDDEA6BC58A05BC9BULL,
		0xE5B7839DEA8866E1ULL,
		0x25BC30B50A3BD3CFULL,
		0xD0EAF3B6B5E9786DULL,
		0x548B7E379FA4BF01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA802BCB513E5A6CCULL,
		0xFB737EA028228708ULL,
		0x7BDF508870128EF0ULL,
		0x561A619269EC00ACULL,
		0x28FEB80B44B21A32ULL,
		0x5226FCF304626000ULL,
		0x93DD2C9289189A05ULL,
		0xEDADE265839B942AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3001E6478636F1FULL,
		0xDC9864C091B7F3A8ULL,
		0xE246477D8879A7E6ULL,
		0x4CB52B63497617E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D9BCDD460383C4BULL,
		0x182A26F3A7FD6A28ULL,
		0xCB90F538FBB62C5DULL,
		0x722437C105320E90ULL,
		0xCE8438957C8161E3ULL,
		0xFBDFF522F7997E63ULL,
		0x482E2F44EB2AD081ULL,
		0x04D41D1F917DFD75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505FC15D28BABF85ULL,
		0x0E8273F14217B4CDULL,
		0x1B73E03870B7DD95ULL,
		0x2BB9983FAD763511ULL,
		0x69C9EFD12DD7D843ULL,
		0x35526BFD5883C4E5ULL,
		0x8A5EAD5697084EF0ULL,
		0xBCBCBE4E232F8C95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30E2D99AE4A7E671ULL,
		0x82AA0E98031F3E1EULL,
		0xDCEA5E61081D8A6BULL,
		0x79E2B297B7609AB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7BECA5A04F18AE2ULL,
		0x5CCEB5B0B8437D13ULL,
		0x2FF497653960F43CULL,
		0xDA86F5CFE3A45A26ULL,
		0x2BB99A7B8C4089A3ULL,
		0xC0309B071C5FE102ULL,
		0x67532709C64A2BF9ULL,
		0x5E240FD24A43A873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C049BBC24D8B25EULL,
		0x510F5BCB81E09C2DULL,
		0xA5818053A6A8FF16ULL,
		0xDF2F733CD62EF2B0ULL,
		0xB9A343792C62F42CULL,
		0x0907CD10EE023924ULL,
		0xACB3BBA3553963D6ULL,
		0x98490EA4D1553213ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B0B18F81AFD06D8ULL,
		0x3BCDEC701849CBC5ULL,
		0x3E1D08465B35AA73ULL,
		0x59D9AF5300DAF9ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB210659BE705A83ULL,
		0xF830FF8B2A461BB4ULL,
		0x1D4ADAE663FC9A25ULL,
		0x035D7300886F6367ULL,
		0x38E06A79EDA16708ULL,
		0x9BC47F286602290DULL,
		0xF5B841E02B90F989ULL,
		0x9D27C748A814117EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F53E878658BDB1EULL,
		0x6D5D71994129A35BULL,
		0xE871AC7C60439F4AULL,
		0xE40E05C00ACB5B05ULL,
		0xD37AFCA33F1AC80AULL,
		0x9AB1243B527B3EB2ULL,
		0x18FBE63E7347B34EULL,
		0x69901D47326C62B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88DB6BBF40E01A10ULL,
		0xB3B30D22CF2341C4ULL,
		0xF8CEC86B5E99679DULL,
		0x47D2A977F487F9BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79CEFDF0FDD90304ULL,
		0xFFCA1F36BF78373AULL,
		0xD64A1FFA22E05A7FULL,
		0xF4240B2E63325FC0ULL,
		0xA2E9C1A04AF4B69AULL,
		0xBF20D26EAF9EE619ULL,
		0xEA7613C3D10D7DF3ULL,
		0xEB1E6613EC5550E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB8D5612108EFC0ULL,
		0x994906789ACC4D36ULL,
		0xA6501142919082B6ULL,
		0x44A324EEDF03B6DBULL,
		0xC52F4E2A074495FCULL,
		0x72F219A4724287F0ULL,
		0xB5689C565B7375D6ULL,
		0x18426767254C9E97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94C34C1DE8F4EF65ULL,
		0xB57086C34061E414ULL,
		0x0FF9C8F7062D0C22ULL,
		0x7C28B3E50F792035ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x430F45EA35B8BDF7ULL,
		0x0A23B2F45ECC3854ULL,
		0x4435518A2E682169ULL,
		0x147880A35834D7D0ULL,
		0x31BF8A1511F1D4A7ULL,
		0xB4B64787E4C22C1AULL,
		0x8EB1A48B760AC88EULL,
		0x39A45C353AE27626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891E0E3E2A04559FULL,
		0x78586CF89C367048ULL,
		0x66429FF0DC88B39DULL,
		0x8E0C657F658DC2F7ULL,
		0x0FFB1D126F3C92E3ULL,
		0x40D685600EC41609ULL,
		0xA52F3E2584AF7940ULL,
		0x885D9BBCB429C6D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD196610329C2995ULL,
		0xC50217E5864D0E96ULL,
		0x874DE4BB256D3370ULL,
		0x56ECAD07F2111A43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x770E9BACEC6D8B07ULL,
		0x375A22C268DA9315ULL,
		0x2D0053768699F163ULL,
		0x448173A0B07177C9ULL,
		0x8B775312888A4D5FULL,
		0xB22087253DD87BF1ULL,
		0x00AB4546223B6DD8ULL,
		0x96C5976553D088F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11217FAEEF15796EULL,
		0x05DD9D5B2D8071CCULL,
		0x54D5E2AED5B00C71ULL,
		0x3F3F37A17F736ACDULL,
		0xD592F07B8F7FCF7CULL,
		0xF517B04134741F99ULL,
		0x4DB6A7E3E2976510ULL,
		0x1A5192FB19FEE5FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65D3BE66F4E6C3F7ULL,
		0x40CC6B40A03FD64EULL,
		0x6879CD5D23433298ULL,
		0x7E7AE3C3C61C3DC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB15713946E895792ULL,
		0x6EED5F34A167BF64ULL,
		0x8045D78BD4B248B1ULL,
		0x2BDE3B129EADFAB8ULL,
		0x8FEF94540C84E4DFULL,
		0x485AD879D116C96BULL,
		0xA3A5161410590C50ULL,
		0xD1448F4E3A702707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77448A70D9920F3FULL,
		0x059F5ACE6301F8BBULL,
		0x906C422EC0392C5DULL,
		0x444CE7E96E8D6F22ULL,
		0x9FA4FD583F6048E1ULL,
		0x06BC6377CBA104ADULL,
		0xCFCA82BDA90C2477ULL,
		0x577686DF6D6055B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE524F284086672A0ULL,
		0x26D362B30DE0FADAULL,
		0x624B743069E38694ULL,
		0x7C26939BA0799D95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3061159F7C2521E2ULL,
		0x4DC2E2B67AE4CCA4ULL,
		0x2C5131CE2C25FF9AULL,
		0x83902AFE06E994B3ULL,
		0x443A6C100DC14EA6ULL,
		0xEBBB044C7D8A6051ULL,
		0xDF342996B2315980ULL,
		0x13E821726025E98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A886429A10FDCFULL,
		0xEC59B7667D952094ULL,
		0x8ACEF5CD8938922FULL,
		0x51CFC04D7236114BULL,
		0xEA4E392A0A140994ULL,
		0x4857397EA72F08D3ULL,
		0x3D87FD10D33D3D22ULL,
		0xE71DA291DDAA15F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57C81D816DCC6012ULL,
		0xA23945DDCEDEA8ABULL,
		0xA110D7DFBB29A376ULL,
		0x57CF4003F314EC0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD17349601E1A8032ULL,
		0x26765662833E9BE2ULL,
		0xE580CB0F93B51E2BULL,
		0xE284A44860F6ED43ULL,
		0x6CEE757CEB1D3010ULL,
		0x055DD69531CAA84CULL,
		0x50289D6D445E2B20ULL,
		0xE22B1111102DF7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D687868846F2C5ULL,
		0x1F3B539DEE4A9D8FULL,
		0xD3A4DF13A8700849ULL,
		0xEFC6142A318B4060ULL,
		0x14DE72B4434E73C9ULL,
		0x73F01B1773B63B94ULL,
		0x9F12B26F37D2F7C3ULL,
		0xA4D1A29512170B77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DFD2BA27E83814DULL,
		0x9D84D76ECBFC21B0ULL,
		0x5B1CCDB1C7EEB59FULL,
		0x0E04F685E6D2C4DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76C53F28E1B12ACEULL,
		0xA26CB4BE5F29EB4EULL,
		0xE7C96FAD932BF1FCULL,
		0xC7FB9A638D408B09ULL,
		0xBDF73781F5BD9F04ULL,
		0xCE6FF04412050EC6ULL,
		0x258A01A95F64F5C8ULL,
		0xF3B8B3EBD550A7D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8BC0A52FF77BE0FULL,
		0x4E6974C1241C2186ULL,
		0x2A101356945A1168ULL,
		0xD2C91A2CD4DBD346ULL,
		0xF1EE77FF7DBBDC04ULL,
		0xDB2D50091AF36745ULL,
		0x5130EE278EEDF458ULL,
		0x1FCBFAD33514C67BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC755A233B27C6359ULL,
		0x6FE708BDE7ACA6E5ULL,
		0x42F2419BF07C1732ULL,
		0x6A55F9DE81482B65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E10BA339A84CC19ULL,
		0x50CB78FD4BAC1B5CULL,
		0x5BEEA17044D4583BULL,
		0x01A03D53136B684CULL,
		0x41D090AD805DB14BULL,
		0x64975770D4108E39ULL,
		0xA173309552CF60B5ULL,
		0xF82CA40E67FA3085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1400052FC47DE083ULL,
		0x814C573726564EAAULL,
		0xF87F6EFE54263609ULL,
		0xBB75B0B7E95C3B0FULL,
		0x16A329EC117C14C9ULL,
		0x94697DEB9FA5DA95ULL,
		0x3DA05F5548E6F572ULL,
		0xE05173508786928EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62CDF5BA4B842741ULL,
		0xB64D6B8BED2C7710ULL,
		0x34BA41F3692E0E1CULL,
		0x50B3C8CA7B389FF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C0DECDA9ECEF9F5ULL,
		0x44FA4BA82C007062ULL,
		0xF651B32FC474F35FULL,
		0x0928796152A9CF4CULL,
		0xFB9B5560BE2F17E4ULL,
		0x48DBFF3DE1D61FB8ULL,
		0xB1077FD8729681FDULL,
		0xF3C6ED967D8A632EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F332509D89A190AULL,
		0x42BB1A4E88FC5E47ULL,
		0xF010435C206D935AULL,
		0x250C28E8C07E25CBULL,
		0x1143DDDECD0E3944ULL,
		0x63E89AF2895EDF09ULL,
		0x68D236ADCC5559D6ULL,
		0xA41FEFB7997EF1A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5D6851A9115EE60ULL,
		0xFE601488C4B7AC37ULL,
		0xBE2A4C2851B355CAULL,
		0x36E5FF8E6BDE83E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12F743808D966398ULL,
		0x44C7DF0BB4ED9247ULL,
		0x2E3B85291C47D5CCULL,
		0x1CE50F178F6E28E4ULL,
		0xD0325530DA06D0EEULL,
		0xFB32014A069D16C8ULL,
		0x14615C613B843A08ULL,
		0x602A234BFFA09AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEAC15A64FBE0EACULL,
		0xE1004E0AEF8DC6DDULL,
		0xF10C906368F2BB31ULL,
		0xDEDADFD44EC7DDC0ULL,
		0x526DE42CC235A468ULL,
		0x0E6DFC5954240212ULL,
		0xC6C940F35148ED95ULL,
		0x3D69C58D4A681C57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF73F475C6E4F168ULL,
		0x88E04CBB4358DE7FULL,
		0xC1C30716782273CFULL,
		0x6698199227090F10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4804E6BA35451873ULL,
		0xFC21B57370FCC954ULL,
		0xF5F86A824BC663B5ULL,
		0x230A177AA2930A81ULL,
		0x046453F701453ECDULL,
		0x2848285AD24A1FE9ULL,
		0xBCE6614EAEA4B902ULL,
		0xACA2B829D3FBA340ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FBEDACD83677196ULL,
		0xE197D86ECE35C32DULL,
		0xAFD49A2691647B27ULL,
		0x0C4DA3A87FD78E06ULL,
		0xF4C9D234F418D78EULL,
		0xE73A76E7C09693E6ULL,
		0x4ED5F92E34AF90EEULL,
		0x99625E3B3FBEC261ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9354EBAA674FA96ULL,
		0xC2923419436DCE74ULL,
		0x9C93452DD4C5DB69ULL,
		0x7249CD3C23C4DDA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC00191495D487452ULL,
		0xC393F572B6C3E3B3ULL,
		0xE0D864048C9BD293ULL,
		0x3C7B1F58D34B2C5CULL,
		0xF9DC79D2EC0197EFULL,
		0x5D53807F89A423F9ULL,
		0xFC46FCAFC6EDDB00ULL,
		0x33250023A78DE760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF2916A9104CBEE9ULL,
		0x80DE6B888C42DED3ULL,
		0x296BAB521AE0267DULL,
		0xB060AB830B229C3EULL,
		0x9D7B522142C21B16ULL,
		0x7525771AF3E725E6ULL,
		0x26401E79B6B04744ULL,
		0x915DE03E22E5F560ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7445EFF6C683B78ULL,
		0xB98AEED8648EBBBFULL,
		0x7C71B4B8DADF99FAULL,
		0x0FA92FE779167C3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E528749BD302A72ULL,
		0x653C0488A9D32118ULL,
		0xC3DD9F42EAEF3DD7ULL,
		0xED7D26A5B02C5974ULL,
		0xE7F420AA08AB2E3CULL,
		0xB6A61D3FE6310CC8ULL,
		0x65487E49F15B557AULL,
		0x7B18002817864A16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE227CB4451C45906ULL,
		0xB410D3183FE9C4AFULL,
		0x72E61C3544D23730ULL,
		0x9284D7A2D4209D2AULL,
		0xD82FBF5D74BF0D4CULL,
		0x37F4C5B8EC7A8604ULL,
		0x8A6E4016B0778DB5ULL,
		0x3878530776649BA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13512D636078B688ULL,
		0x7F7E2F797B015D83ULL,
		0xCD5CBEA947ECADF7ULL,
		0x3EAC01DAC70BA0E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FDDFABE271EB3A6ULL,
		0xEADE4EC7D5D2A316ULL,
		0xDBA2CC8F29693816ULL,
		0x9BE8F7FC9DABFA2EULL,
		0x8470FA70B6F73875ULL,
		0x177E435CBF08C1D2ULL,
		0x26EF656AD9F0871CULL,
		0xD91BAAF69F176176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF34D0CCD5653BD59ULL,
		0xC4878CA17DCB639CULL,
		0xE269D5F9707DF677ULL,
		0xA2FC8B7DC0F3091CULL,
		0x022ADBAC657EF875ULL,
		0xA9E5DD720B583D58ULL,
		0xDAB7C1950742A743ULL,
		0x56EDC6EA762DFD9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2F97F14E8A4791FULL,
		0x6AF5E2FD043AE9A8ULL,
		0x497B4852FEBA7BBFULL,
		0x4BBC464CEF5DC307ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34C7A12A5BD464B3ULL,
		0x5F752E2E0D1E28CEULL,
		0x4A7E752E3CB91497ULL,
		0x23A5CE0F173011D9ULL,
		0x2DDDF581127794FAULL,
		0xD7E7DA67977EDD8EULL,
		0x8C8054A9CE55AC1FULL,
		0x9FCF25414676D3D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F0EDC4C8DE25D97ULL,
		0xD04FEC50D6AB7FDDULL,
		0x59E35E90378DF03CULL,
		0xB0F75208DDC7DF93ULL,
		0xA0C878E17D833C36ULL,
		0xEDB94760900C0D3FULL,
		0x011775EF2544B677ULL,
		0xB02ED2D90760D74FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6E9448DEA3733C2ULL,
		0x520F14E8517D9499ULL,
		0xA22C26531DAF9B47ULL,
		0x047AB77F96ABADA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABE14EEB8537B0B7ULL,
		0x874C3730329818C3ULL,
		0x1694BD535471EDC6ULL,
		0x63F46903C4D24DDAULL,
		0xC6AA0AEE5F8DB7DBULL,
		0xF7AE497415E8D049ULL,
		0xC06AE4FD7CD02C4AULL,
		0x326AB760FA71815AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A84B4B267C90773ULL,
		0x5BD6EB5F77F783AFULL,
		0x36076F3D7BA451FCULL,
		0x086387B8BCB10653ULL,
		0x075C59AA54558B35ULL,
		0xF1B7F92100A449EFULL,
		0x1B9E8FCD8AB7F9E5ULL,
		0x989AB0BF30225ECAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6E4EA52C7C547AEULL,
		0x0E053825E2CC868CULL,
		0x56E1F333C86516C9ULL,
		0x3071DD4F0FE068FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x565211A7EA565016ULL,
		0x159DE4A9EAA4946EULL,
		0x4A7CB548DE483F19ULL,
		0xE6467E0A315FFD67ULL,
		0x98548CEF997E29ABULL,
		0x9BF8AC709E9F927DULL,
		0xAC5602557B5817D1ULL,
		0xF31EFE058608664AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BBC8EA61D6285F8ULL,
		0xDF4EDA81BB931999ULL,
		0x57A39A38AEF6CA17ULL,
		0x2F57D0308387C646ULL,
		0x573A3B3D08D633C6ULL,
		0xE54AE8525FAA4F22ULL,
		0x3FE0BCF6D7A1AA38ULL,
		0x7ED5F467DD4DCE04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD47DA38345E24CB5ULL,
		0x541A26A587797A60ULL,
		0x0C41671C7C65B9ACULL,
		0x79C61B40B98AD195ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABCBE61B3C89110FULL,
		0x53055876D03B27F8ULL,
		0xBDC4E43C173C3B06ULL,
		0x844F210573F94BADULL,
		0xC443EB1785DB11D2ULL,
		0x0B08900EDC84C6C4ULL,
		0xCF30CF18EBC97FBCULL,
		0xF81CC98AE3B9FF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x691244BB62A46244ULL,
		0x1EE432C4F79A2A2FULL,
		0xBB96FEE237C54FD6ULL,
		0x9A0A20657225C4B5ULL,
		0xFC5D78AEEC0547D8ULL,
		0x337006E8042F94F5ULL,
		0xE07D5E6DC7CF54DBULL,
		0x14E19D4905767699ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEEE9CE6AFA0AEE0ULL,
		0x34C58175F546627AULL,
		0x70D09EC136994890ULL,
		0x250D9266FFD9CAD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90E65794CB47461DULL,
		0x3186FC76964F9A34ULL,
		0x95A7317EFFBF26FFULL,
		0x7515DE6AE3F142D1ULL,
		0x8C6CC68EC38FBE19ULL,
		0xF72EDB21425E9339ULL,
		0x02D046CEF84CB031ULL,
		0x3490B8D0209FF39EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4337BF9C0DF25CCAULL,
		0xA9E6E56EAF6C0632ULL,
		0x5C7FC22B8E94D055ULL,
		0x0BBD41530C9A71FBULL,
		0xA38AAF12F11B9F2EULL,
		0x98BCF83604B4FE1AULL,
		0x84BB594CEFCC514BULL,
		0xDFC8A1245C897878ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF3E1459FA917C6CULL,
		0x8C87C5F30E0FB698ULL,
		0xF042B0A0B4386CDBULL,
		0x7F0C2096F2AD1866ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6DAA0EECBF5668BULL,
		0x0C6A4440CE07A646ULL,
		0x1941EC27C8DD9493ULL,
		0x2074C8DEFD4EF97CULL,
		0x459AF80F9A500516ULL,
		0x5ECFA9AAB240B5E1ULL,
		0xF75537009BAE1AF5ULL,
		0x1EF1EC299EA1A926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB99E81AB5CE0946BULL,
		0xA4528989824C1F1FULL,
		0x7BE9B729D980C899ULL,
		0xBED1726379C407F7ULL,
		0xEC288857CFE48378ULL,
		0x7A1FC63C2457ED45ULL,
		0x94A085001EDBCFCFULL,
		0xF42C5AAB08DCD118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6438B48B7B0A0AC1ULL,
		0x5A337D205C494E36ULL,
		0x442AA1107693F399ULL,
		0x3AF6EF45BEC303A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0139F2F32A630AB2ULL,
		0x031D0806D7032505ULL,
		0x6730FEAA27152C2EULL,
		0xFAF26FA6C0E97A60ULL,
		0xDD20FFBC8BB71F7AULL,
		0x48092386EB8A7821ULL,
		0xC4BFE5DDDD7220FFULL,
		0xDC28DA667B9A151EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50121C844F7F6893ULL,
		0x860980F61FAF5E65ULL,
		0xFFCC76B3542E8496ULL,
		0x9B4EE55F5729729DULL,
		0x39C5A00DB4521FCAULL,
		0x2BC2C05C3345B2C6ULL,
		0x7051EF1C1D94A359ULL,
		0x19881FB7292AC16FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0B80A62D3E19A8DULL,
		0xAF863F6811891239ULL,
		0xEFB728B94DC74E3FULL,
		0x437F404DA64673C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x792871F4DDAEEA2FULL,
		0x62D5256CFDA8ECCCULL,
		0xDDDF943467D13B96ULL,
		0x949BE6402CC9F9F6ULL,
		0x726E6E52F9AF3AE5ULL,
		0xCBEA3668BA7BD792ULL,
		0x16AB899B958309A1ULL,
		0xD8D1A1F9F88B45A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D7634090169D86DULL,
		0xC2B7B760F9E56E41ULL,
		0x37A4BF341446264CULL,
		0x8547967044B08D66ULL,
		0x61CD1E5B543E6189ULL,
		0x5C43D36D6D73ACB6ULL,
		0x9008B7B41D0CAC26ULL,
		0xD4BE239CA7C6B995ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3A41CAE6B05557DULL,
		0x32D01F5972F9DB35ULL,
		0xA265FD5C351CF59CULL,
		0x2A3911A9E5463776ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9983E4A1ECEC8AE2ULL,
		0x47F0F9C8A5E310BCULL,
		0xE1A5F2C4C3483E85ULL,
		0x8F14258EE5877F7CULL,
		0x5DD943DA712F76BBULL,
		0xB2EEBA50434333E5ULL,
		0x6696DC548037B5C7ULL,
		0xE61D75A827F78E95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x587F0F07FA6B25DDULL,
		0x1FB0B7AA29FAC74AULL,
		0x4ECF07A8D2EA05E4ULL,
		0xE334ACEE130F6D92ULL,
		0xD756FEF4A1AE0D89ULL,
		0xC3323B4FDA323A92ULL,
		0xF3FA25353B3E01C5ULL,
		0x02A8B38F9EFD0FF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x385B0FB6BFB70757ULL,
		0xBE3B1C2E146D4BB2ULL,
		0x961A19C02D6EF0EAULL,
		0x6F34484527A6DD95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A5941E0BFA3701BULL,
		0x011CD02D83708698ULL,
		0xD4DA21F155610F31ULL,
		0xA0F46F6AE3F79ECEULL,
		0x6801941B39271DCFULL,
		0x3160DCFFDBA3A156ULL,
		0x4CD36D500E48800FULL,
		0x2ABF51543D34598BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB5F25515705F182ULL,
		0x822C5CA2E33EF36EULL,
		0xCDDFAECEC775C930ULL,
		0x6DE6FCF1E2570103ULL,
		0x848494DF75FE3CE9ULL,
		0xAAD7E0C085704D68ULL,
		0xBA673B5931F61963ULL,
		0x24C38B8587868225ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3387FF6E60AEE0E3ULL,
		0x7745E4F16BD00879ULL,
		0xC309DDC742268376ULL,
		0x166CCF27F96E96DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF36D46BDD811C33ULL,
		0xC0BA9B3AD3D7051FULL,
		0xD1D350E17CCE30ACULL,
		0xB428720B41806E01ULL,
		0x4CEA90E510D057ACULL,
		0x6BF922A5AD211362ULL,
		0x6BFDFE16F3BBF6D8ULL,
		0x6CC6A5ECA87EF5B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D9DF04049161D0FULL,
		0x7905C84F94D0A086ULL,
		0x9F8BC25D7424D648ULL,
		0xE4BB3EEBC83B840EULL,
		0x4BBA4004B1BD2FC2ULL,
		0x6C62825321E495FFULL,
		0xD0AEF568393A7484ULL,
		0x9A691ED880142F75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EC4E579B142EAD6ULL,
		0x38109F2BEA01014CULL,
		0x4002D873B7E2B2DCULL,
		0x094F401D791E56CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FE61A739C5012DFULL,
		0x0D6253FE3B27DD18ULL,
		0x63CFD49C5C7A6DCEULL,
		0x0C5BBA42E1838B5AULL,
		0x8429E1921CAFBD74ULL,
		0xA91E212FD9127B17ULL,
		0xF7A3453F322DEB0BULL,
		0x267BF324C2445BEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20814790D09057DULL,
		0x749AE58B090A05ADULL,
		0x016D9897FB960F5BULL,
		0x0EA5CCE56294473CULL,
		0x0DCBC54CF7AC8CE8ULL,
		0x118DF2436AC83868ULL,
		0xD6C3564FD53A7352ULL,
		0xBBA3F039465BE94DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FD6383E0DC03ED3ULL,
		0x182E658B9123BD76ULL,
		0x439FB38C2D0823FFULL,
		0x59C65C51E3704797ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA3A849D426F9ACEULL,
		0xAE8AAD2299B077D7ULL,
		0x5C41B8A63EACE29AULL,
		0x0BF01D6D13E62425ULL,
		0x3F14F01FE98A419EULL,
		0x18E943C0B01DBA6CULL,
		0xE7225DEF3D60A3C4ULL,
		0x5FEA72B80017FD85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x378F1F3F358DC3E4ULL,
		0x9FD9C1A2E067742BULL,
		0x6889632C8236410DULL,
		0x9D1C91590ED4D175ULL,
		0xBDF30624EE921312ULL,
		0x55C5CB3A1215CB38ULL,
		0xDFE36E9C723B33F7ULL,
		0x8EE0660FC2328475ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB4209F4DB8BE82ULL,
		0x05F4CF7B2E768551ULL,
		0x070FDBC3E40539F2ULL,
		0x76516D0D35214B11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F3282BCA766756FULL,
		0xA9F87BD4690CCA18ULL,
		0x6136896D182991CEULL,
		0xACDE231743C5CF85ULL,
		0x829B1C0BD77580D0ULL,
		0x8F2C1D39ADF0CA5EULL,
		0xB62F9A76AA62327BULL,
		0xDAE65FB9D53AF068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25F9317BAA55FF7ULL,
		0xDEAAE80E53252427ULL,
		0x19B8CB932B74C9C0ULL,
		0x8CE21752F8DFCA16ULL,
		0x3DF4FFC529EA9779ULL,
		0xDE20CAB36F569B55ULL,
		0x238C4C9B81F2638CULL,
		0x63C53712FBC8E52DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D7B2222AF5FBAFBULL,
		0x12FBD3B360CAA151ULL,
		0x0BBB4C61ED4D7F7CULL,
		0x4EE8148891D3B047ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE84AD30B44FCB35CULL,
		0x0F35B6202567ADFCULL,
		0x722AB0C60FA9D2B1ULL,
		0x038506400C3B66C2ULL,
		0x8B99FB0D1D22FC05ULL,
		0x8BF783D2C8D8651DULL,
		0xCE08DDF30CA963EFULL,
		0x9FFD360060F606BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97D2DCC17B555C3AULL,
		0xED40CA00BB4C5283ULL,
		0xB31AC1E8813F00C1ULL,
		0xD13B88AD5F8E1DB9ULL,
		0x1738BEBA2628C6C9ULL,
		0x1DD471C7C325F9ABULL,
		0xC7446927BB6C2D46ULL,
		0x9201F184CDCC9AEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96E6EA9A72CB3E30ULL,
		0x7B2999C242974E76ULL,
		0xC039450B9D80EF15ULL,
		0x4595A7EA84D349E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7E0C3CA4FD8654FULL,
		0xA524A956736E21CDULL,
		0xB4B91ADBD3B87D76ULL,
		0x3B5BD3B3296F8EDEULL,
		0x955ED94E2F51E1ABULL,
		0xE8D07DE742F74CDEULL,
		0xEC540E069EB5BBE1ULL,
		0x9142A6C2750D7B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1E9B967CCC8805EULL,
		0xC286970D907391CEULL,
		0x0CB5A3021BAE490DULL,
		0x21E85623FA83ED3AULL,
		0xF66BE8FFD09C30CBULL,
		0x66B47DDA5A8F56EDULL,
		0x961A8FC7BB752A4EULL,
		0x904CF27E8D4CD459ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE06B60492082631ULL,
		0x32C61433626911B6ULL,
		0x748C352F739FD04EULL,
		0x3DEC3FA395845EEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE701ECFFC48C581ULL,
		0x98460BDD141CB3AEULL,
		0x29C0ED4462688A8CULL,
		0x216F4776F7E1E446ULL,
		0x767CBA8D85C583B5ULL,
		0x216C513663E3107BULL,
		0xE3B7A814D03D4B99ULL,
		0xB06B0B4E068C00BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19204206F37C3716ULL,
		0x79DD4FAE932C2D32ULL,
		0xB4FF9E100A6D2B84ULL,
		0x19A9E4797A472E52ULL,
		0x2B2682DE7E9F3DC5ULL,
		0x8DDEFB7C36BF4972ULL,
		0x2A735460CA6A8B3BULL,
		0xC611902EEC374F8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE41C20C4187AEF86ULL,
		0x056375D1344011DDULL,
		0xF4E5BBED3543ECECULL,
		0x510DA99B662D0308ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF675B078473C3B37ULL,
		0x2A47F5A9135BEE7CULL,
		0x8D996077BEBC85C4ULL,
		0x00C396B585595806ULL,
		0x37334FAB7AA3BD42ULL,
		0xC9AA6C869CF4F9D5ULL,
		0x8D4DB1D58875273FULL,
		0x8866A730EF77D9F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x861C229F59CE62FDULL,
		0xFA7F3E2A98AC129CULL,
		0x02141701827C4922ULL,
		0x07298C495852E72EULL,
		0x592A6BE82AB14331ULL,
		0xA58BD759D882D967ULL,
		0xF8470CE5945A20B1ULL,
		0x8700D538CB959D59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65AB5CD6CB6BF6C0ULL,
		0x8C52DC23A3A0AC2FULL,
		0xAA81C514784335BAULL,
		0x2EB73541809B6F7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C5859C5072C682EULL,
		0x9827D48962C18FB5ULL,
		0xE4C26339922C0447ULL,
		0x57620AB005D79DDBULL,
		0xED509263D9A8BE67ULL,
		0xEE04390AE115013AULL,
		0x76553E19A1380D99ULL,
		0x23108A34E9B3AE81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED2FE36A7F81884ULL,
		0x362356D8681F13CCULL,
		0x40FB7D3A7E3A7F86ULL,
		0x4A5DD9CDE7883D05ULL,
		0xDAB9CF76EF6697A3ULL,
		0x55E37182287D339BULL,
		0xA4BFA46CCE025796ULL,
		0x3A908D9E2C9E1F5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFE64AB92506103DULL,
		0xF6E21BFC612B0185ULL,
		0xBFFBB5A66DEA8949ULL,
		0x1003AF422F829FDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50C2BE550FB728D4ULL,
		0x7B6379B9E77259CDULL,
		0x404B953900F3F517ULL,
		0x5E7C17F258A4B1C8ULL,
		0x00A68BFB10385AE2ULL,
		0x9A78DFA2B162A88CULL,
		0x2CB19D44A8FB6278ULL,
		0xE94C6B25D8BBEE3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AD6CA61C2044ABULL,
		0xA160F20AD23691F6ULL,
		0x957D936E539BACEBULL,
		0x52F484CEBFDDC619ULL,
		0xFD5A70B790B74A91ULL,
		0x507546A777BFECF7ULL,
		0x43007A12548347FCULL,
		0xA03121C25DD664E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86615DB3E0BF51BEULL,
		0xD68B3CF9A3639FCFULL,
		0x5B193B43372C369EULL,
		0x659477E7D6D94E49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32A820A8ACBD584CULL,
		0xE1681A8AD0B27833ULL,
		0x2BBAC30D33F6D8B0ULL,
		0x042552E6859337DDULL,
		0x5E534437D5B14DACULL,
		0xFDB49C733CCE6DDDULL,
		0x80827AC0506F2FAAULL,
		0xECB242FBD5F54066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCF01C21ED9B1A52ULL,
		0x7E44736B68B7B5D5ULL,
		0x5B30F49CFF4AE5A9ULL,
		0xCA9E2DA69D35BD96ULL,
		0x5247E6E965F14D6AULL,
		0x5E581BE3F9C03595ULL,
		0x0BAAF940798F4821ULL,
		0xF73CF13F1D5C0E58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF67DE2B55A24767ULL,
		0x0ADEBC635C171D0EULL,
		0x2887076A19E85175ULL,
		0x28F147434F1AE86CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CDD17415CB0209DULL,
		0xCF21D3610D73EFA3ULL,
		0xDB687B00857B8150ULL,
		0xF1A12A23299C155AULL,
		0xA00218AF821448FEULL,
		0xD954A5F583EF95FCULL,
		0xA4BEB2AC5D2317FFULL,
		0x61784D1A9036CA2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7893B731F5CCD5ULL,
		0x961363EEC9ED77AAULL,
		0xB4C030B1A93E0018ULL,
		0x9DA0A855D2007794ULL,
		0x5882675E00F151A6ULL,
		0xD6404AD9640B146FULL,
		0x15964AAAB199D3B2ULL,
		0x3745671CD10CC659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E58D5A355EB0BCFULL,
		0xAE13F59EFF71B2F1ULL,
		0x66A7BA8E529DA4A6ULL,
		0x178EA577B7D82F79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D07996B663DE654ULL,
		0x226366741950F179ULL,
		0x3D74C8D807A74433ULL,
		0xCEA8EB424A142628ULL,
		0x4A108A65B65DC492ULL,
		0x399F5FF053D13458ULL,
		0x34A10D694B582381ULL,
		0xC2EA0AA0DB63252BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB7A71AC612BD36DULL,
		0x6CE37239C220CCC8ULL,
		0xC7C35B4BF8BF6A9DULL,
		0x53F2EA482BFBFD90ULL,
		0x35D0FF5CD3E08D5DULL,
		0xB4B60FAFC7E2C28EULL,
		0x414FEFA554F48B32ULL,
		0x3583F88C76AB435BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32FBCB10A3A847E3ULL,
		0x7021DDCF1C9508AFULL,
		0x93BBD8A2A1B0753DULL,
		0x77DCB0011163AD75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F21AF66D2F3790BULL,
		0xE4E34B782D2BBAD9ULL,
		0x84AEA3D5BECD9E6AULL,
		0x6BC3F78389A21517ULL,
		0xB7B496651B45DB30ULL,
		0xF025B1106DD05C43ULL,
		0x96F967DF7B81C302ULL,
		0xE737CD3D8EB55FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67688ED66DE22E5EULL,
		0x14BA13260FD2AC22ULL,
		0x50485CF428B934E2ULL,
		0xF074EEFF0FA90F2DULL,
		0xFBB12678314B5DBEULL,
		0xD6DB58451C697BB5ULL,
		0x75F93D76DD855582ULL,
		0xC1EB1EC91F1C2D7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x903BBDBB203FEA57ULL,
		0x91326680329E63C0ULL,
		0x1A6C9269098CAA8CULL,
		0x04B0EDCD0AB682DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEAB0D9EE956C741ULL,
		0x5DE5ED308A9A540EULL,
		0x56ABD32EC760CEEEULL,
		0x67913A3BF323DA67ULL,
		0xB96C455098578FB5ULL,
		0x28F465C29FBBFA27ULL,
		0xF871D6905C232497ULL,
		0x9C4D40C36C1B3B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B555E1E31361A7ULL,
		0x30B982F259103109ULL,
		0x26E277D8B14432FBULL,
		0x272C1137498AB73FULL,
		0x04DB15BD94733E6CULL,
		0x9636A2D64D67B0DFULL,
		0x438919622CAFE6A3ULL,
		0xC05E00D9D5E47BC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF882C78F9A27759FULL,
		0xF55759526A0D03CFULL,
		0x0A5570312137CE1AULL,
		0x65E8A5B0F5B985B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD1F3374171311D6ULL,
		0x1365DB4920337CB3ULL,
		0x02C72FBED4EAFFC0ULL,
		0x84498C977A301727ULL,
		0xEEDF94788B748173ULL,
		0x66F49C85D12C1EF7ULL,
		0x071238ECEC20CA2BULL,
		0x1D5E7F5C87ADADF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9B0AE9BBD4F967ULL,
		0xC21ACBC94223D311ULL,
		0x403DA869CF3BF47FULL,
		0xF991502E9011C610ULL,
		0x9CB5126BA36C1CA5ULL,
		0x1BA83CC868F7FDECULL,
		0x6B065AB94FBDE987ULL,
		0x0C2E8BBBF553A351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2D37674CC7D0F4FULL,
		0x7EA1459D55CC9150ULL,
		0xEC4C82FE3C5C63A3ULL,
		0x17D6663EA37BE5F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86A2F8975D04BE42ULL,
		0x532D327C5BB1186CULL,
		0xC23C43BCC536EF88ULL,
		0x5F2FCE0FC04D57B4ULL,
		0x67EE919809864D74ULL,
		0x12DF054523899190ULL,
		0x9054AC13AD21CC57ULL,
		0xC00892AFD30C411CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB133A43A42C2A7ULL,
		0x47170E9EBD00B49AULL,
		0x545B780FDABAEA82ULL,
		0x032ACE4997DC4796ULL,
		0x4A5B46FE066D4BC7ULL,
		0x71432185F3FD8A45ULL,
		0x5D97CE3131B9A9D7ULL,
		0x6BCF5CBDE98B2737ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFCED7CF98783D24ULL,
		0x0939F23EAD7978F7ULL,
		0xF5E9BB4B3BF123F8ULL,
		0x5C8301AED19AE823ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDAF35AC293C2837ULL,
		0xD403228DB9EBB512ULL,
		0xC217F77679777E71ULL,
		0x2A9F10609A7BB79EULL,
		0x92FA917235C39ACEULL,
		0x3F0C5BF1E3A9B47BULL,
		0x0813E4915C95B594ULL,
		0xFA82DCF4C6079506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A284B3A04D3AAF4ULL,
		0xABFFEC69867D2152ULL,
		0x326EF064F1AE2629ULL,
		0x457B425D8B01A896ULL,
		0x0009660326F568BBULL,
		0xA1AD1351E3BEA112ULL,
		0xAE046E998C98EFE6ULL,
		0x03FE7F97BC1DACA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93535CEE5703F16DULL,
		0x8427FDE43053756CULL,
		0xEDF489DA674EB00DULL,
		0x7CC9A9D288328D55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA1E0812901B1720ULL,
		0x3C97A0F2BE85AAF2ULL,
		0x7072300BED6695E2ULL,
		0x5ACB098441544764ULL,
		0xFCDDF6CC6CFE8E7CULL,
		0xC6D6CB825B4590D2ULL,
		0x1BD33756F11D50CDULL,
		0x579B332108AE7410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB3857869EC54409ULL,
		0xF9C09EE57B8E3B12ULL,
		0x65EAA37267635A5BULL,
		0x78CB096FED2C2B4AULL,
		0x76932DA606BEFFE3ULL,
		0xD847B64CEFD60012ULL,
		0x8B6FE01CBB70F990ULL,
		0x71ECF407107E5F22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDFF8C3F1EC4FD22ULL,
		0xAC1427FB3586EC73ULL,
		0x79467F3D7D982E91ULL,
		0x79DD5DEF2B4B375DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A960466145D7BD2ULL,
		0x54940FC82D5177CDULL,
		0x3E13D4AB4E6E0B2DULL,
		0x54A525B82810772CULL,
		0x41BB1FD9B3F4194EULL,
		0xA0F45B7EA9F3FFA7ULL,
		0x5F1CC2C0FC935D25ULL,
		0x06C6D18FD5E47DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD278C71829F9146CULL,
		0xF2ABA582358FF2BAULL,
		0x33E2F7C897B900DFULL,
		0xC5FB2800C7F5173CULL,
		0xCFB6855F76E4B664ULL,
		0xC35DB4A00ECF80A3ULL,
		0x9A8906CAAAA1E7FDULL,
		0xE72A25A907526978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54CC2B72FAAD1116ULL,
		0x46452F50FF2C5F95ULL,
		0x381EC372E08C6E38ULL,
		0x3FEB81FA09CA6225ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC9F478F0277BA71ULL,
		0xD4CB6D651F7818B5ULL,
		0x05966BF62F39187FULL,
		0x12327DC32817AAE7ULL,
		0x019CCD1210044243ULL,
		0xC732E1C81D9F0338ULL,
		0x3F4BC6149E9C5907ULL,
		0x2C5E49992C5B0AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB2FF58C5F21358ULL,
		0x6AEEF3BCF16FC978ULL,
		0xD4F70FF6E5FBA4CCULL,
		0x2119DE65213897ECULL,
		0x1CEE5995EDCF6290ULL,
		0xBDC23815F3E666E6ULL,
		0xDC1D2295FB005AB6ULL,
		0x26CB10C763B7718AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3D16CA3505EDBBEULL,
		0xD095AA1A5F6F8364ULL,
		0xE98BA0CB926533BAULL,
		0x44F30E81CF27CE3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE270481347993F53ULL,
		0x94F7783F0BAA8C06ULL,
		0x2471C171ED91297FULL,
		0xEF5129EA1D139EE2ULL,
		0x073BC28C6D24E61BULL,
		0x635F9779F06FECD4ULL,
		0xAA401FF4D9676424ULL,
		0x1F3C1173062C4015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03BF44F5609A8363ULL,
		0x86636223E307E918ULL,
		0x925E26B40A55148BULL,
		0xA526771D506FD14FULL,
		0x656B9ABB5C2E6206ULL,
		0x3A43B3E7943CE38EULL,
		0x27E634BFD714EFD4ULL,
		0x8AADFCE9E58C0950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE396EC266B9654AEULL,
		0x28B7DDD4D8360344ULL,
		0xEB6C849C3B7958DAULL,
		0x5741BF27A46BEEE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE101DC6878647EBEULL,
		0x853FB0D4B1182FEBULL,
		0xB85103CBEF971798ULL,
		0x7A54EDB4538E95FCULL,
		0x6CB26D50AAB8C50DULL,
		0x14F74D6FDB5E91FEULL,
		0x23B1646C6CBD4152ULL,
		0x17E322492B6635B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53D0114269BAE4B7ULL,
		0x354EB56A7ACA26ECULL,
		0x8DF6525ECDA83E35ULL,
		0x1EB87BD940F7E762ULL,
		0x56061ACDE14CC26AULL,
		0xFFB71F22EE71762FULL,
		0xB293E066F7278E31ULL,
		0x26BA1EE91E414932ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAC60A8FF4B1FDEDULL,
		0x7777DAD5618029BCULL,
		0xF4BC4A3C96277026ULL,
		0x27B2F21D0611C9AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7227F632A82C02FAULL,
		0x6E93B66940F09E5EULL,
		0x2C7ED7CF1EF63075ULL,
		0x1EA62264FA0BCFC9ULL,
		0xB27E2B78C6C216DFULL,
		0xF1D32E994A59D90FULL,
		0x6032B9516C34AD52ULL,
		0xDA27B867415FDE94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A147ACB6406013ULL,
		0x7C6D9A0837932CFFULL,
		0xA22BA5FF3F989081ULL,
		0xA288F86851F58036ULL,
		0x50F8350A455A1D33ULL,
		0x8608CAFCFC2048DCULL,
		0xC16489627A71018CULL,
		0xACF5E37AEC4F06B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB6942ED275AB353ULL,
		0xF230E594A5E8D8FEULL,
		0x1CEE4F47C2691F67ULL,
		0x3182C51148965B5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6330AF107461C16ULL,
		0x89C5648783C49F5EULL,
		0x657546D14246F808ULL,
		0x5509620F11CB0007ULL,
		0xFB0CC6BB5233068CULL,
		0xF6C73BC8FF1132DAULL,
		0x2C40960F55A06416ULL,
		0xDCDA77D2843DDEBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857FDED3D7007185ULL,
		0xC921D944D4F267EEULL,
		0xAFDC3D717459961CULL,
		0x5CFE10CB27668DF4ULL,
		0xDC27FEE7C9F04186ULL,
		0x18136D6D35F0FC1FULL,
		0x4A202855CF7F2B97ULL,
		0xE74A20ED6FD04507ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06A8D5836A2EE929ULL,
		0xCF542CE2899A5737ULL,
		0x466952E9B6DBC4E6ULL,
		0x6B783744F2A9435EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0F019F781CDCAA5ULL,
		0xB12F411EA6BBB959ULL,
		0x1C97DA729CAA2921ULL,
		0x278E496758F277CEULL,
		0xB2CACA2425E6B69CULL,
		0x8CB7E5AE424BD516ULL,
		0x4B0C7A8CB46A8181ULL,
		0x906F311880D18875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA81205F52ABBC8ULL,
		0x070BFBB84494854DULL,
		0x8CA652CE797A8CC5ULL,
		0xE4989AC7F66B8690ULL,
		0xDD3FA3CFD92F4E03ULL,
		0x44CF35347DE1889AULL,
		0x365A867719CCE24DULL,
		0x69EC98938E68B024ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6EFB874EFDC963EULL,
		0x56AD777989EE8E6DULL,
		0xA25BC2D916953E1FULL,
		0x7A58525B5E170D46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5859C0DEDAA6C7C9ULL,
		0x96A37F6BC9A1F3F1ULL,
		0xE9051B305A18AC12ULL,
		0x74E98C3DFAB324C1ULL,
		0x3BFAC4F8E97780B9ULL,
		0xFD431E736D3FB252ULL,
		0x2EDF9165F4B275ACULL,
		0x48335971C63B2FD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1C4EDF8E2D693EULL,
		0xF7D54E12F8535DB6ULL,
		0x5035037C5A27F58EULL,
		0x27AF50E68AD4A4D6ULL,
		0xEE129F78482DA481ULL,
		0x3F01BB456B8515E9ULL,
		0xB39577220C495D63ULL,
		0x1AA7D03BF1DE92D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEB303173D700FE5ULL,
		0xDC82EA2D1301CDB6ULL,
		0xE5CFFDC87F8A5175ULL,
		0x0FF09954F59DCD65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16697AAD7D8B7A86ULL,
		0x3C76CC6FE3277CF9ULL,
		0x6632E7B39033EB2FULL,
		0xA6C10EC61E820CBFULL,
		0xB5BD8BEE06E93D78ULL,
		0x005FD80F5811BC96ULL,
		0x854A9FD33A02678FULL,
		0x47A6D7B279215D79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0A80B80419F969ULL,
		0x204ADE19515A5AD1ULL,
		0x8CC8E48FB0CE35CAULL,
		0x0B1CFA33F9D580C6ULL,
		0xB2E55264E1B7EEB4ULL,
		0xC9362C85867BF638ULL,
		0x5ABE9F860FFDAD97ULL,
		0xA327DDCB8AC19DE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3778450FEC33047ULL,
		0x4C5B64CBAE08941BULL,
		0x2A320E981C195017ULL,
		0x067D2CD986E2FC1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16C56DBAB821F892ULL,
		0x231C1676BED31A20ULL,
		0xE40FAC5C69969D68ULL,
		0x4BC44A571CA7EB06ULL,
		0x1F81B6CDAF2B6B4BULL,
		0x10F8CEE79444B9D2ULL,
		0xAAA4EC5A3F967AC6ULL,
		0xF72A966B9B73A46FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F194A106F05979EULL,
		0x0D0B0A52800DFD4FULL,
		0x7C55C57C566AFBD5ULL,
		0x48621270F54C479EULL,
		0xC24B82AC28DB397CULL,
		0x0380C04E84254EC3ULL,
		0x9108DF03BE137F51ULL,
		0xBF749CDD1D271A4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DB7E0A43903C6DEULL,
		0x15E336DCA36F00F2ULL,
		0x34E3E1B74C9CF4F3ULL,
		0x4865430CE6B8249EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2F4FFBAB53BDFEEULL,
		0xDD1AAAA797638233ULL,
		0x252A52D936831ED0ULL,
		0x2E6BBDB93331E9AEULL,
		0x16E5382AFF466DBEULL,
		0x37CBAB76400266FCULL,
		0x4851E874CE5C4402ULL,
		0xB33C628ABC9C9212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F019D98B308D84ULL,
		0x3AE0AB07676B1B03ULL,
		0x2BAFB5A9D140D89EULL,
		0xE45AB8299B2D6EC5ULL,
		0x0A79FD3668B85F55ULL,
		0x21DD23D6CE075BF9ULL,
		0x6CC788CF9BE53CC5ULL,
		0xEF6755BB5686890CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14EFA62F83217484ULL,
		0xE3A2214B1B3C09A4ULL,
		0x9004CFB4E2ED5943ULL,
		0x5BB0EC58BF49D1C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F84E2BF77F6A5F1ULL,
		0x65F8B53BB669E569ULL,
		0xE9BBB8E8CD83BCF3ULL,
		0xD2CC79B9EF46F9DCULL,
		0x2DC0A689FD76D3F8ULL,
		0xE7DDA5395402DEFEULL,
		0x4D3B68D99D6935E8ULL,
		0xF848DFD5C44B7987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933901B22B86E34EULL,
		0x51835D2D36A77B53ULL,
		0x024243555FECEB5BULL,
		0xAFD4BC6F3572E6E3ULL,
		0x69FB3576EFC3A712ULL,
		0x7B269F37EB32CBD6ULL,
		0xAAD102B108FAFB42ULL,
		0x348BDA66243A4C9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B9AA9E155087115ULL,
		0x37A03C440EA541FCULL,
		0x03449F9975F3864CULL,
		0x31068BDC7C60BDF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F1A3D843A755C1BULL,
		0x170E38EF3C247CFBULL,
		0xD8D1ED110F717A21ULL,
		0x37522900E72A55E2ULL,
		0xCB55C9563AE1340BULL,
		0x2DF89394E6BCD44FULL,
		0xC9E342EBE2AB63BCULL,
		0xFB7731C7F8569C4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1B4C50B11B689AEULL,
		0xC4A8764B21DF13ACULL,
		0x2DD14AB014430D57ULL,
		0xBBCBE5732077B765ULL,
		0x45BF2C14AD49BCADULL,
		0xDE01291167CCF30CULL,
		0xC832C31F74F8B1F9ULL,
		0xCA09A69963A86A0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1C0D0342D3A8B58ULL,
		0x311F9228F1E0D954ULL,
		0xEB339AB943B4CFA1ULL,
		0x51C8EC77D88E1365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA765CC4373D68C58ULL,
		0x02E9B9FC822E383DULL,
		0x6A28FD03EFEFAFADULL,
		0x9C593C8F3DC6E537ULL,
		0x27619958B1D8557CULL,
		0xA6702DF71ABAA2A2ULL,
		0x0A3FA17A9C3D96ABULL,
		0xE8E47DB9C960A264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C883F6A96CFB22BULL,
		0xF6D7E2D2DA195FECULL,
		0x1D07201F3EBD8336ULL,
		0x4CC2371B6993BF2EULL,
		0xA4C6DC60286E4638ULL,
		0x89ADCC527BB41FC0ULL,
		0x1533ECC91E4B0A62ULL,
		0x696B783E0A4735A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDD599BD42C52117ULL,
		0x50EC5599430C45CAULL,
		0xACDEAF3D6332FF50ULL,
		0x3B8DD5D231F94A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10C160AC0A5856B8ULL,
		0x9AC979B462319160ULL,
		0xAB81A99353890A90ULL,
		0x3D1C6425F7D136C6ULL,
		0xAAFC874585EAA941ULL,
		0xC4C52264AC725022ULL,
		0xFD8FAF22A499A66DULL,
		0x2CAE782196509F2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF249E4D0369AD227ULL,
		0x46EA69149B7C758FULL,
		0x8E1BBAB3AD5F7C04ULL,
		0x42099A1CB7709A14ULL,
		0xD704D84FD95EA12AULL,
		0x1FD16D7106AA3298ULL,
		0xA9C641F3F0BE98DCULL,
		0x040A8B02800B536FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x953B74537086B8DFULL,
		0xD00BECCA62697E45ULL,
		0x8D4C23CE58AD922AULL,
		0x0367FCA68EA9DB18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06D018B82FC378F8ULL,
		0x5ECC80CB1AEC2247ULL,
		0x9CC091A7C48A6925ULL,
		0x658C07F876DFEFBBULL,
		0x55E0AE24DB289739ULL,
		0x3F3CA5C9B9B9EB3CULL,
		0xE2DDB93D674B5B93ULL,
		0xB14FCBD56089E9DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2CDDC1D568ED0B2ULL,
		0x0E3D77548085B8FBULL,
		0x24B7DEF66D2D933FULL,
		0xDF2516674D6D52D2ULL,
		0x0A748470DC647683ULL,
		0x11501795F2D51F94ULL,
		0x3F54CFB32779F6DEULL,
		0x275BA8F7F4CCEA77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96106D52AA518642ULL,
		0x21AC2526205CA446ULL,
		0xBE5B5D36D071C8CBULL,
		0x00A41E6F27808625ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x884438C910878F66ULL,
		0x7D20664A76C9E4D7ULL,
		0x6CE6DAA74A2F6A7AULL,
		0x16F250473119601BULL,
		0xE5D7A7BBC91C6C3BULL,
		0xA55059A873C5848FULL,
		0x83C9873A729E91B6ULL,
		0x796E5F398471839DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7990C155F12D068ULL,
		0x3D92285045D9244CULL,
		0x23C5FAE759D4C3B3ULL,
		0xE02E948ECA1FA675ULL,
		0xF7790263ADC758A0ULL,
		0xBFB95FA22EF9F7AFULL,
		0x0BD602101E0AF03FULL,
		0x1C4AC955FE8DA71BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42B7B7C7C015A9EEULL,
		0x53F75AE86727A9C8ULL,
		0x1746A4087E449E6DULL,
		0x0A0BFB7E46CC7504ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FF92B9632C5E43DULL,
		0x744A5DED31214425ULL,
		0x1D8DA9F82AC8C630ULL,
		0x3CA2AC76E1CA175BULL,
		0x4693031B750821ACULL,
		0x1896CAD6F7654050ULL,
		0x9B58ABC0BE0E7EF3ULL,
		0x98C65C98F66AFCF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC33E313D67659AULL,
		0x438DD3F42A9C8E64ULL,
		0xE069670A592F95D7ULL,
		0x287C408E4DD3FF21ULL,
		0x45684E15434B8476ULL,
		0x5FF68F9EAE888C04ULL,
		0xB4CD96C8C4ED3899ULL,
		0x82894A378E216C03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118CCC50575DD519ULL,
		0x98855453D7477909ULL,
		0x75C95FBCCC89A1AAULL,
		0x6137265E0EE19B63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE506E18302FDD999ULL,
		0x39747EB9EF55937CULL,
		0x0211CD95136C823AULL,
		0x4937B994E38D5DE7ULL,
		0x9D892198CD20F7C7ULL,
		0x7430A7C951C35D2EULL,
		0x81CB979448D6D940ULL,
		0xBBADEC4A01B8FB14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEA380F85914EF9ULL,
		0x10FBB60CEA5B8C33ULL,
		0xB1091D60CE48F06CULL,
		0x546BD3DB0921891EULL,
		0x4DA81B140772FA24ULL,
		0x182F0C2CB8CF3C3BULL,
		0x493621C348EACD63ULL,
		0xBBB40A4D060A02DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7183A128D54030BFULL,
		0xD0B5E1EBB936EB67ULL,
		0xB7382D3A422D54A9ULL,
		0x73E371473664ACAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE5120B9BDC8BE9AULL,
		0xC3AB562478F94939ULL,
		0xB13DA2B4214D4B15ULL,
		0xE70AFB50D0FEF7FDULL,
		0x70223413ED5878F2ULL,
		0x72FFC9E305CCD0C9ULL,
		0x319B7411EBA4E480ULL,
		0xBCB6DA19D639C45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C015E376D5ADCEULL,
		0x4CE16A69B289E2C7ULL,
		0x775AA5D04A5E7BA6ULL,
		0x984AAD05B3DEF79EULL,
		0xF7C5E9ED00745E8BULL,
		0xB51FFEB188F9A0DEULL,
		0x2F82213425C7EA00ULL,
		0xB74A0A9CE1089605ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55440C9D70CEFC3CULL,
		0xA60215134DC88340ULL,
		0x89A549CF35BBFE65ULL,
		0x1CE71AD7826CE0FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA06E241A9947CF01ULL,
		0xA881911C6F61DE1EULL,
		0x5A635847D12AE048ULL,
		0xB39AB81E58DB7E4FULL,
		0xB19A96E12CB84E37ULL,
		0x5BA7FC09268AEDC0ULL,
		0x7D27735AAB25327DULL,
		0xE202B81B5A372417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x421122841047E2F9ULL,
		0x717F4E5F77D116D6ULL,
		0xA3557C071A2AD602ULL,
		0xABE795C14D058141ULL,
		0x511ED3AB67E6255DULL,
		0x290A5131FDEA7253ULL,
		0x8A2DCF7ABE379AF6ULL,
		0x9CACE780896BCCA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0BBFB91C031FDE0ULL,
		0xBA699EACFF631984ULL,
		0xC81C2F7DE2448857ULL,
		0x527019580A04F81DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1910A3233A782FA8ULL,
		0xA3E40BC70860A076ULL,
		0xC5FF9FC2F950D76DULL,
		0xDF94DDA6A6BA6030ULL,
		0xF172EAE8C88A62CFULL,
		0x6C37BC8DDF6C2E4BULL,
		0x6B62AC95CD19A5BCULL,
		0xE2E5F8A1D0A803CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F16E709295976D9ULL,
		0xFB9999E3400F8D08ULL,
		0xE026CE0AD0C5E44CULL,
		0x95248D7ADC981E5EULL,
		0x29019166B37E04CBULL,
		0xFF603CDBECEACABAULL,
		0xDF4694E588BA595BULL,
		0xA940B2413AED9729ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ACD056930F4AEAAULL,
		0xD047664DC785DB11ULL,
		0xB20455E24EB04970ULL,
		0x58F8C28203CE61F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D14E88438CDC33CULL,
		0x003328C28C589142ULL,
		0x65F95F615A2F2656ULL,
		0xE88BECAA6A5F628CULL,
		0xFFD1AEF8BC62D576ULL,
		0x2084E09AF5CD55DAULL,
		0x3CBC2BED34D8F949ULL,
		0x7A97B03E9887A6CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x892C9B224D6568C7ULL,
		0x20D2665B41147BCEULL,
		0xB72045149C8A10A3ULL,
		0xEFB459C1DE3F5284ULL,
		0x98725C41817BD1BBULL,
		0x3335DD291F8896E5ULL,
		0x56A471BD168E150EULL,
		0xEBA57B8C4C920A34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C0E9494A9B2E5B1ULL,
		0x191B454D19786DE1ULL,
		0xD65EBD713CC2F672ULL,
		0x30CB655FD2954F05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B66C832F6C1928DULL,
		0x1A0CFEAB5ED51381ULL,
		0xF2574B9F63775254ULL,
		0xC930CEA8E33B4237ULL,
		0x375F8B93D0F1764DULL,
		0x3A842068FDC8EB2EULL,
		0x9118E6A0755C5578ULL,
		0xCE3163EC6443C6C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6BE3EA49939978ULL,
		0xB6D981FE803B3383ULL,
		0xB7A345FE51BFBEBDULL,
		0x4D6CACEA4660750AULL,
		0x1F2532B7E98C470FULL,
		0x6537D13A6BF1F306ULL,
		0x54841E911A4AC988ULL,
		0x74588CAAC971BCE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78A414ED0632FE4AULL,
		0x0C873D968482B5F1ULL,
		0x38C9B7E896525930ULL,
		0x51F4157B98084450ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7407A4BD9CA5FB0EULL,
		0xC27AEE6193084CCCULL,
		0xC3AB826205539EC6ULL,
		0x2B612C6116D1C8E7ULL,
		0x4160A4D2356B2B12ULL,
		0x7D3EE829B74E73FBULL,
		0xABA08170A7C8DE59ULL,
		0xD74E3B807818D25FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECBD0CF794BA0F3ULL,
		0x47DA0B39C549D500ULL,
		0xFCEC0482A1C51B7FULL,
		0x36BE0733E697E51DULL,
		0x6E8BE1B1F24ED6F6ULL,
		0xDEC6C62ACF8BC60FULL,
		0x0098345899A08721ULL,
		0xC9FBFDF72D3A8A5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D0CAB8198ED67CULL,
		0x0075EEFE34A448CDULL,
		0x29FAEF717D8B7589ULL,
		0x6ED8478E4D3893E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38B45C4FF566CD2DULL,
		0x0EBB5F8DE0B53377ULL,
		0xEE5FF8687399EEE7ULL,
		0x40F8D3A2F8BE3031ULL,
		0xD915533007C95194ULL,
		0xF715656EF3B45AC0ULL,
		0x795D64B05621CE15ULL,
		0x62E0C66F0DD50DA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A280C4B49D9E3B5ULL,
		0xC9167A1D57BD14A4ULL,
		0x32CEF66FF8468ECFULL,
		0x3C38CA423E0A69BBULL,
		0x5E8D1F37B0A14BC1ULL,
		0x1589AC1757E830BAULL,
		0x170A26E37B651340ULL,
		0xDA305F5D65C0F916ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEC406E19B7DC41EULL,
		0xC0626871A9465BC8ULL,
		0x53EC2E60F3571BD6ULL,
		0x4EEF55FFADAED3E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8607B71B4ACB0BBULL,
		0xF82E3727125814C2ULL,
		0x7F2ED5C9CDFB5960ULL,
		0x22D7329EC5EF5E05ULL,
		0x0656712630A5BDDBULL,
		0x555CFC255EB466FCULL,
		0x23A5FD0C468D2408ULL,
		0xF34FC20A0E11AFACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F57025C4B7923EULL,
		0x40C6D800468A8C7EULL,
		0x03437AC39DC10692ULL,
		0xC4E96930C2ECE0A9ULL,
		0xECFE5198E954E6D0ULL,
		0xBB8F74355833654AULL,
		0xA133104350E3EC84ULL,
		0x9A71B8BEA989216AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD57FBA4485F50BFAULL,
		0x8BE98CC7C2F3C88DULL,
		0xD8FA80DAA7589057ULL,
		0x0EE32A9EEF479B15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23C97FE4AA98345EULL,
		0xF7229192034612E5ULL,
		0x757BA36999F708CDULL,
		0xD3F3CE724AD5644FULL,
		0xB28C56178268D472ULL,
		0x5D0514693613427EULL,
		0x56A7AE5A38BC9DC2ULL,
		0xCBD634FA6DAFEB0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA38A20C61C37371ULL,
		0x6FBC7256AF5A433DULL,
		0x9A474DFC6BEF7A24ULL,
		0xA2BB838E2CCD4241ULL,
		0x3A536D5D268B8E70ULL,
		0xC22C5968687E4D2BULL,
		0x4FE146405A318E60ULL,
		0x2E587B1A2EAAD27DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02036981EBAD28B6ULL,
		0x8391E159D8083A0BULL,
		0xDCA7C94436ABD726ULL,
		0x11E1E22D78C9C722ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3235C4F045D120F1ULL,
		0x8FB952648D69A834ULL,
		0xBECC5E44D2FE6A0FULL,
		0x85173750A2654ADDULL,
		0xD74EFE1E49BA16FDULL,
		0x9E56B84CA4B5FC0AULL,
		0x6F2B88F0B99FD407ULL,
		0xEAD2B6CA865C3C16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE374F0F117DDF236ULL,
		0x43B49BED19DA103FULL,
		0x95BF67B3A97384B6ULL,
		0x85E0510570876BBEULL,
		0x1CF870E778408C8CULL,
		0xABE285F4C54EE84CULL,
		0x5F08FE923107E8DEULL,
		0x7047948B43E0DB22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF799CA2245FDBE2DULL,
		0x49442F829CDC8643ULL,
		0x8E2D80997017CD6DULL,
		0x2FDDFBAF102E4359ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD4FCC2EB4388418ULL,
		0xAF847540F0D4B1E5ULL,
		0x27C597835483DADCULL,
		0x011D2CF6411DF5F4ULL,
		0xC9278D3727A64E20ULL,
		0x6BDE5DB354955F33ULL,
		0x5DC5901AC277AC71ULL,
		0x5E5AE7F07E893BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA69EC088B32D704ULL,
		0x78A0B00ED50F5821ULL,
		0x6AFCDB0586D8249FULL,
		0x6FE83C8CED17A6FBULL,
		0xC70487FD943C97DAULL,
		0xA3FF72D9FEC8AFDCULL,
		0x2DF9A9A3BD68B037ULL,
		0xC9A3F028B0A8EBACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8418A6B20AB6B905ULL,
		0xE1FAA174D82760AEULL,
		0xD50CF2288DE526D0ULL,
		0x245DB811E3523457ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C1C7A721177775BULL,
		0x70BD21BCA107A372ULL,
		0xFE874B5B14C481B2ULL,
		0x52F0D5011BDCD380ULL,
		0x6B391D4277F6286AULL,
		0xCA04F0EEF5F41C09ULL,
		0x3D9F49642BE138C3ULL,
		0x950C306ACFE5B281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0210F6768AFFFE2ULL,
		0xE60BE4DE1161E613ULL,
		0x33315F07A7F8E144ULL,
		0xB597F8A5FCEDF576ULL,
		0x00A67CC4014562FBULL,
		0xA34CF0660D4E964CULL,
		0x5C6B5FEAA8D8320AULL,
		0x5ACD31F715DD396AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDBF3DD04704C723ULL,
		0x4A0151311837977CULL,
		0x390A945CE0229FE9ULL,
		0x42B2A188BC30D770ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE51E79BFE1DFB89ULL,
		0x57C64ACF60125C5EULL,
		0xF1666C4873000097ULL,
		0x45FFAD55F1CCCDC1ULL,
		0x1EBCF6F18DDC467BULL,
		0x51A1139E14B0CBA3ULL,
		0x41EE29D9F78CE962ULL,
		0xED9B440E9FCA6A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBF972979F7046ACULL,
		0x48CC4D2C4DD59FF9ULL,
		0x90D92B396D1F9DA1ULL,
		0x37D3AF631ECE3A16ULL,
		0xF5CBEF3A231C8E7FULL,
		0x8E5BF4B190878F01ULL,
		0xE15DA955281999D5ULL,
		0x132666E814B337BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x461F9A3E37230905ULL,
		0x0B3C94BEB05BBC51ULL,
		0xB60054C5D0FE31DBULL,
		0x7B84D1AB787011FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x923B7CB2DCA6F92DULL,
		0x5C0B87DCA9386B7EULL,
		0xC720B92E967DA61FULL,
		0xB6EF9CCC20CCF190ULL,
		0x9C0741A0E95E1BD5ULL,
		0x7EFE087A8049BDCFULL,
		0x3ED6BCA3FF7F93AAULL,
		0x11D44BB72BFA69D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD835190550A3F882ULL,
		0xDF54CCF456F74649ULL,
		0x0DAD6683D424284CULL,
		0x8CF8EFE5A114A991ULL,
		0x38FE3B00E36E2A47ULL,
		0xFF313CBE3458F2AFULL,
		0x1EE2B2AFE817BE2BULL,
		0x929686F0D4D3DF81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D5D5F6E6DA0D8EDULL,
		0x751CF8DB97FF4C03ULL,
		0x77ACCCE63BC32E99ULL,
		0x0D21E2576F70CFE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4201C99A80460914ULL,
		0x44639BCD77273722ULL,
		0x077993AF042E964DULL,
		0x6399A9608197139CULL,
		0x20B3DBCD08E9C6D0ULL,
		0x2EA195EBF92FDF3CULL,
		0xDACD44B09BC33688ULL,
		0x7A67DDECDFEFA3F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x411A019834E06F93ULL,
		0x5AAAF3491F781704ULL,
		0x882476CCD6DE08DFULL,
		0xF35DA0A194855568ULL,
		0xBE028F8D8FF4A6DAULL,
		0x15626EB81F9EA307ULL,
		0x23D2DF26A1166FCBULL,
		0x14AB075F15002693ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA739196E3FC85A2CULL,
		0xA9187A36A33E0FE4ULL,
		0xA8802F5D62F60D7FULL,
		0x0A43E1CB0C9E5A68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5BC9E865165D0F7ULL,
		0xD3FBF56F9D7079E0ULL,
		0x3FEE362B857BF792ULL,
		0x49ED0A35C6717D09ULL,
		0x21442BB2B7B2849CULL,
		0xADFB912F85206FC4ULL,
		0xBB007485E012C2B8ULL,
		0xBA5291B4663D8AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E4F6A763C4EE84ULL,
		0x124562536603DD7AULL,
		0xE6137C20428207E0ULL,
		0xF03750EB308BBB5FULL,
		0x8865DD42049062E7ULL,
		0x1BA6105B09D9289CULL,
		0xBD67DD52E96DF9D7ULL,
		0x3A4D45FE2142F3F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFD74C9984B1E5FDULL,
		0x7A67B2A684012C46ULL,
		0xFE812B9BDF6FC12EULL,
		0x5A7EF658D3182B5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33B62DD7C0CEB65CULL,
		0x03F73D0B6F32C5EDULL,
		0x6370A67F08BA757EULL,
		0xCAA0285520C555A5ULL,
		0x601F83938F68DD52ULL,
		0x3734B6DE1D009DBCULL,
		0x4D7D29937D0A7875ULL,
		0x9D27694AB1430B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2484441B9CA85835ULL,
		0xCCEBB18A15872057ULL,
		0x55518073E7C2F493ULL,
		0x2A75430049AE3A1FULL,
		0x120AA2A292104DF6ULL,
		0xA1B9983A4065651AULL,
		0x75E1C02E3A0CDABEULL,
		0xC7980AE6801A2272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA64B4D81BF4BA4EBULL,
		0x675217D418B60DADULL,
		0x0F30CB13129CEA04ULL,
		0x5372E8342329ADCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26DFC1393EA028C1ULL,
		0xA3939A91C203E680ULL,
		0xF29092C45B47CC6EULL,
		0x0D4BF44FBB8FF209ULL,
		0xA3D8C244B05660F9ULL,
		0x0136711A0BD08763ULL,
		0xFACD94F9FDFA4C7BULL,
		0x388192C31487C1CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC129600E9A6E27FULL,
		0x73837AA0C11528D5ULL,
		0x63EFDF04E77EE189ULL,
		0xEE2F19554114BA4CULL,
		0xA997495F9E5062B1ULL,
		0xF2A7FAC4D1E2BCFEULL,
		0x529269B67FC7AAC6ULL,
		0x37293706362E62B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90851D3901DD04CCULL,
		0x5935B0979A3AC8A7ULL,
		0x87691FC42F4CEB9FULL,
		0x523A79037BBF551AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEA6BA8E49322491ULL,
		0xB7EA2F7B67978AA7ULL,
		0xFEDEA2A71F3EB532ULL,
		0x37F86A2F70BD00B4ULL,
		0x0E5639F80EEFFC6FULL,
		0xCF653F56DB6656DCULL,
		0x2C011838101982B7ULL,
		0x4CEC841338E0A914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x774540BD81D63A97ULL,
		0x928E4F135897027EULL,
		0x9FB63624D6079026ULL,
		0x84318A31CF89BA5BULL,
		0xBEDB14D4581E2F78ULL,
		0xF31693DCE213742FULL,
		0xC77B50B5A292F63AULL,
		0x3AB031577B8A2F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13A8FD1DEA8056F0ULL,
		0xD9095483114E2DBDULL,
		0x4B0409DE8B2FFF94ULL,
		0x68BB27DBBC095AB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0EE0F7D94B13546ULL,
		0xA67CF1EE30CB2BA6ULL,
		0x357A0C66D89D3A39ULL,
		0xF8A0F6CADDFC4E28ULL,
		0xC3BC9D10E36AA43DULL,
		0x7D98B4CF0D3B13B7ULL,
		0x44BF7E07FE4963C2ULL,
		0xC678D5EBE9DCD298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FFB678DE4237ADULL,
		0x9A10629E35382588ULL,
		0xDA62AB7582B67230ULL,
		0xEF92F5D0C112FFDBULL,
		0x686C23E3261E3645ULL,
		0x4BECC337DA8EFED3ULL,
		0x2309FB41FCC16C83ULL,
		0x850F566D6FBDFB52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96E055CECFC751D2ULL,
		0x6BF26BC1811E2003ULL,
		0x5C08CA5590157B6AULL,
		0x3EB6EDC03D7D42B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0D4D8D1D9F44ADFULL,
		0x699059F1AEC75431ULL,
		0x25EA88F7707D19A0ULL,
		0x78B7422F9F4E420FULL,
		0x6CA81BF9C2608239ULL,
		0x1E11ABFE7B3AEE8BULL,
		0xB3B6D7D3187940D5ULL,
		0x556A1987AC0DABA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE003C84CC2E470A6ULL,
		0x6CCE9D1851241E5CULL,
		0x42831E61EBFBA759ULL,
		0xC9E3BCB8A1927070ULL,
		0x66A9F2CFF634D1AFULL,
		0xA0CB9BF4A3A92941ULL,
		0xFF28A8F758ABB1DCULL,
		0xB2B463F799FC6180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD48B2CB9658C0C8EULL,
		0x95281E4F5D467ED1ULL,
		0xB0825F33FD04AB29ULL,
		0x55CC78D9AC4CD383ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C7120B8B1EA006DULL,
		0x764CA99BD126EA55ULL,
		0x5285F74A4ACF5540ULL,
		0x85F15421EE3E22C6ULL,
		0x617FB03B39E853B4ULL,
		0x4F99A4388ADAC249ULL,
		0xD5C2CBB1F9249259ULL,
		0x062599A320AFFEFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB221257F4AA39E91ULL,
		0xDAF19982A94F6070ULL,
		0xA8CA7BA7AC6AE0DAULL,
		0xBD2A2314A50A8940ULL,
		0xA39AE52E66180B19ULL,
		0xCEB3943F4641EB6FULL,
		0xFB2C2D11980AEC69ULL,
		0xE9C9C27B5CBB4D8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A461F20D83123BFULL,
		0xBD816F1956876E36ULL,
		0x1C170771083315F2ULL,
		0x7E6920F45F85F06CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54F598AB9647746CULL,
		0xF7222C1839C16B8EULL,
		0x2BA5C9A060D03555ULL,
		0x044BC6D4911F9D0FULL,
		0x488C4676309A64ACULL,
		0xC268D910C205498EULL,
		0xC49702A949D5F845ULL,
		0x6180B0D212F203ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CAB1928E707816DULL,
		0xDC7E4C44AAB0306BULL,
		0xE675B0E391557D84ULL,
		0x584865E599175E8AULL,
		0x535F1FBE544D0C78ULL,
		0x1F9923DA57B4D4DFULL,
		0xA5DC2F23BFDC2704ULL,
		0x8C2FED8107BC1199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CFE3ECD62BB09ADULL,
		0x4578C5E757028D1BULL,
		0xD4EB7E8F4A8FC78FULL,
		0x56005EF6A20A36DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6256E659ECBF14DULL,
		0xB623F0675670854FULL,
		0x0472D8316A093AD6ULL,
		0x840122AB6E3C1E6FULL,
		0xF1E79DE7D55956D2ULL,
		0x5686EA3F44A44F6FULL,
		0x24580E2BD4589988ULL,
		0x44C21990C7788676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B34136F914733CULL,
		0xFCA1E533F18CD33DULL,
		0x9A3B77CD09E0610EULL,
		0xC3BE60F4AD78EE9CULL,
		0xC2E8B2A9ABC8B8BEULL,
		0x97629434988ABDD2ULL,
		0x751427646850318EULL,
		0x86FDA0455AB116C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE491868D12EF37AULL,
		0x18E6D0C8F0AF4F66ULL,
		0x6E4BA1FE696848DAULL,
		0x6B6CC2E8E65DC39AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1A6E69BE5EA56B4ULL,
		0xC6A1F728CAD6CF91ULL,
		0xBF57EF1C1C4EAB5FULL,
		0xA20540C1292BABA7ULL,
		0xC0A6B1F75B4F7F8CULL,
		0x1D8568806337362BULL,
		0xAF2665C3B9A4AD03ULL,
		0xE7CB8D249A077208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9CF0A53FF512440ULL,
		0x744EBB054163FE04ULL,
		0x1F8C58533EC09AB9ULL,
		0x14DC8B0C95880977ULL,
		0x9929AB57CC0F8E39ULL,
		0x4873B1656749193FULL,
		0x31C0D69A46594360ULL,
		0x0CE8611DBF410F1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD466D7F72A1709ACULL,
		0xF2F46A24EECB1C9AULL,
		0x3CDED6EFFABFBED1ULL,
		0x0AE13EB90D165125ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E6957483052E7F8ULL,
		0x59062DD2D82F1060ULL,
		0x975274CAE9F6FEC6ULL,
		0x182D2DCD7D023D8FULL,
		0x70E1A315967D6146ULL,
		0xDD903D1D9AD8A823ULL,
		0xD7D0A4700F5F3E05ULL,
		0x978813209D028C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD6B9412290328C9ULL,
		0x9AAD3040D87B27E7ULL,
		0x5F90D47900283410ULL,
		0x612DD91603F76F83ULL,
		0x96CD63157CAE1451ULL,
		0xAD8E6FDB8056FAF4ULL,
		0x2A97D5A710069BD0ULL,
		0x08B1A1DA1F39D27CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFFF4339DC152E98ULL,
		0xDE9D7561EEF39D6CULL,
		0xEE305227D0F6DE9AULL,
		0x6AD4252E24D662DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x449305AD2FD2B8F6ULL,
		0xE84F47967F32C552ULL,
		0x0ADDEF36E4919F45ULL,
		0x67F5FE578759CA01ULL,
		0x3E9FE1190E03A3F2ULL,
		0xF9F66016555B744EULL,
		0x033DACCC1E3E06E9ULL,
		0x1609731A09211C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x446231943D8F30BFULL,
		0xF4688DA8617B64F4ULL,
		0xB418EFFF1005334EULL,
		0x532F37662C3E2F89ULL,
		0xE5DB6F4878226235ULL,
		0x3B30E31BE74ADFDFULL,
		0x2D3BC863DCA7AD63ULL,
		0x8FF9104DE1D50295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D59B90F31B34786ULL,
		0x4537471A742D68BFULL,
		0x1B0CE6B190DDB5F7ULL,
		0x7B35713F30676053ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3267D7CA3B78D6B8ULL,
		0xF16CA888DB55DCEAULL,
		0xF65AFBD62224A8EDULL,
		0x52CC7E0E4FBEFCFFULL,
		0xC18EBD9C4B66AFC7ULL,
		0x4E01A536AF97EF0CULL,
		0xB763CD5076EAA0AEULL,
		0x550B60F542437B7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4BC60D7B698FDDAULL,
		0x3C362103168A9E9BULL,
		0x662A9462B9D6F9ABULL,
		0xF9CFE1A0616B97FFULL,
		0x167D86F617EA1B61ULL,
		0x1063F88CC161770CULL,
		0x02C6E12AC1AB8F7FULL,
		0x3B5FA9A8D5F1A47DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD239939E295DE074ULL,
		0xDA9E28BF20E10E67ULL,
		0x5F7B750C4FAA3C45ULL,
		0x2879D1C602794ECFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAAB5DE0D76ECC27ULL,
		0xEE7F676E94C3C7BFULL,
		0xE9161C600C463D0AULL,
		0x5BC13323B024D0D8ULL,
		0xC1039ADA8083F726ULL,
		0x0CEBAB82BE0AE3A7ULL,
		0xC8CF3EAE31AB62D2ULL,
		0x8F7283074594BFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE705D7DD5F712C2ULL,
		0x49ED4853560680A7ULL,
		0x07F33EB422A5B12CULL,
		0x9853EB5DE778EDE3ULL,
		0x7CA6E9313CF66A0EULL,
		0x12FA26585B870113ULL,
		0x6145AC2EB5E365ADULL,
		0x5C6BA398A73DD5E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21FD5F83087AABFFULL,
		0xBE6BE365DE50E91AULL,
		0x3F8E9C9849501F5BULL,
		0x567272314992A2E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C663B08DA55DA5ULL,
		0x3EBB64EFD2AE1C6BULL,
		0xE97FA1AEAC10E7B5ULL,
		0x99ED675476D7091BULL,
		0x2AC06FFE6C7A62B2ULL,
		0xA6CCB6B62D19DA06ULL,
		0xE32C85E02CA9AA9EULL,
		0x04312F7EC70AEDCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A11FE759E9D90D5ULL,
		0x65C93B20CCE769D2ULL,
		0x216AAC840527D8F2ULL,
		0x2E3E21FAFC490B18ULL,
		0x9B952BE89F96F9EDULL,
		0xC6720AC8FCA9EB36ULL,
		0x6EBC542487C591EDULL,
		0xE352EF8A0CD293F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD020807758C95528ULL,
		0x2667AF0436642567ULL,
		0x10BC570520C4B904ULL,
		0x4CACC3AD1EEB5471ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE37E13D16D39039AULL,
		0xACBF970441835530ULL,
		0x93241745111753F4ULL,
		0xB31A40B8890D64DEULL,
		0xB0AEAD35EDD5B446ULL,
		0x0B4982E9532DB3F3ULL,
		0x842EA847D88186D9ULL,
		0x09AD83BFEAE73407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37051330DA596051ULL,
		0xC8A9E89B386509F9ULL,
		0x150FFD66F283124EULL,
		0xA561C06C1A532458ULL,
		0xD8106B35E6095F4EULL,
		0x21642FC8464ACC37ULL,
		0xB9C3FC753578D9C5ULL,
		0x3E9F8699816B262BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3F6CCA1BB343EE9ULL,
		0x9C200550F2CCB119ULL,
		0x89E99B2251DDF29AULL,
		0x31CC140017244F26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1761C459FCCA3A2DULL,
		0x9EC7D5EB75D0F269ULL,
		0x851CDD4C47462206ULL,
		0x468C243A497D9B76ULL,
		0x9971A8FE802012BEULL,
		0x9F2C4F8AE7B430B7ULL,
		0xC85972F7CFA2FF07ULL,
		0x14DB65DB7D7D6755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DA5E52E4FA6DBAULL,
		0x4F86339EAFF7FD34ULL,
		0x00C1FA3504F02954ULL,
		0xACA018EE0D5373D7ULL,
		0x251C969C62AF6A34ULL,
		0xF6D9EA8CBEEE8AB2ULL,
		0xAD98A920E9B31669ULL,
		0x5762FEDFF2BBAD2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A2820977688CF60ULL,
		0x4B7CA006D32F9A03ULL,
		0x7CF8D8FD63F28019ULL,
		0x39CB54A2D4EBCA05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x662F0B4998A1BFFFULL,
		0x2193CC32B156D174ULL,
		0xF9E34F81EEC9546EULL,
		0x54F36B9272BD26FEULL,
		0x2174624B9E985AD5ULL,
		0xBC3DF6FF7DE9B6EFULL,
		0x72E3FBAFCBB0D089ULL,
		0x0B208C513114CA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF8AE871F4CDD8E0ULL,
		0x812DA30218C71855ULL,
		0xB24F097BA1A8F6D1ULL,
		0x9B7762867427AE99ULL,
		0x6DDCEFA75A236E05ULL,
		0xAB391F87C9647CEFULL,
		0x7C6A9DAC8EDCAC53ULL,
		0x769D5CA3E391FE74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F1F2739CD2F0B8CULL,
		0x271E24F564565513ULL,
		0xDD983A81549DBDA3ULL,
		0x44F51CC57FFFB4A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FEF22B31518D889ULL,
		0x6BDBD61671AE7F04ULL,
		0x2E3231B158FA1D0AULL,
		0x17938FCB366502B1ULL,
		0x2563D113EE77A143ULL,
		0xFCE954DFF021069BULL,
		0x26A590AB0913D3B1ULL,
		0xDC1996EBC99FDD2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFC771456CDCCA70ULL,
		0x927101637FBFB95DULL,
		0xD71C8CD1DBEAE30EULL,
		0x8931CFF6036ADC62ULL,
		0xD9D34AC008D1717DULL,
		0xD4D0087C4B05CE8DULL,
		0x5C051B4805FDCE80ULL,
		0x23307E5AEBA64BC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE79BA1E1BEE7297FULL,
		0xCD2C2B7D73F9179FULL,
		0x6AE71191F253FF47ULL,
		0x00FB65562605BC28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x251D0F4A88D4493EULL,
		0xE395A6374674081FULL,
		0x7D88A8703D44EF20ULL,
		0x96A7AE9E14A54241ULL,
		0x6F764BF4DE7555D2ULL,
		0x459B3B761548F756ULL,
		0xD373B51C28A398BEULL,
		0x0C1175C7F456E290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE04384ECF9B5D751ULL,
		0x6DA41173F2F538CBULL,
		0xE28D00900762ED81ULL,
		0x39360462818393C9ULL,
		0x63D89115EB7F2B4FULL,
		0x6D64559CC613D276ULL,
		0xE3D81B1B10FE9B34ULL,
		0x3764F4B6B4E8C63EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE4347759FA8C068ULL,
		0x8E17B30515624894ULL,
		0x2C148409B85FA415ULL,
		0x6F0CD2CAFD79E2A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91ABBEDFF0C3F7A4ULL,
		0x5CAFB57763153C5BULL,
		0x97ACB4D3719469B4ULL,
		0x2A7E55A5108FD721ULL,
		0x4E2597E4B2DD54B6ULL,
		0x0634564D7F71C89FULL,
		0xADB627D155586609ULL,
		0xC9352602C2599191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3A7D121FDD86FF6ULL,
		0xE33670DA52E98253ULL,
		0xC8D4B990E28205D0ULL,
		0x838C136B8805BD5EULL,
		0x73E7B8BA016397DAULL,
		0x4229FEAB6FBFEFEFULL,
		0x3EB6EB9B65B4965AULL,
		0xC1F822E40CABA60DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13330E144AFD9069ULL,
		0x930246AB6491E422ULL,
		0x48BAEB44216337D4ULL,
		0x3A00B8C8805B0F6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4033333B7CCE1418ULL,
		0xEB398F3ABC8A76F8ULL,
		0x4E61E72B171FC755ULL,
		0xEAD94B771CBE8DE0ULL,
		0xB9A5E08628DACAD7ULL,
		0x1FC6EC4A0F148FC0ULL,
		0x6799D49C3947D034ULL,
		0xAA763594D6952269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B32B229D178AE0ULL,
		0x60E14FD52DD21435ULL,
		0x1EE28BA6FEEC4533ULL,
		0x3C381C8A8CC99FAEULL,
		0xE17BDE16115F2C19ULL,
		0xC9E2B4B2E5F78B2AULL,
		0x86BCFB0D3599C5CEULL,
		0x197E0A81B9E716D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5BC64BC5C101CB0ULL,
		0x4A387FD5A9071100ULL,
		0x9047A6BEA4090D2DULL,
		0x337793C2D1CAA625ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C6E3795A181AF20ULL,
		0xD47154634E0367FEULL,
		0x2C3B3B1A56C355C8ULL,
		0xFC36236EB1CAE1FFULL,
		0x1AB0F0BB7F3BD15FULL,
		0xE9C302182E7768DCULL,
		0x4C7B1A76DAA618F7ULL,
		0x6DB5A5BA40E63C64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6C4AA2E44136E52ULL,
		0x414B02ABEE6F6E06ULL,
		0x29C25254BACC3ACAULL,
		0x79EC6F3659F67E2DULL,
		0xFA610D167D201652ULL,
		0x3801A7D443B07E5FULL,
		0x9B84349BA914B2E8ULL,
		0x03FE34DC4BADE3A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118557E5AD8C071CULL,
		0xF5D9B7CC391AC864ULL,
		0x471F074EF78C4152ULL,
		0x3384752ABE318FD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F6B7A0F6B7A3F6DULL,
		0xEC08A50E1D7ED7B9ULL,
		0x1A85B469261290A1ULL,
		0x4E96410D34E847BEULL,
		0x4419E3F3EDBB0254ULL,
		0x91AE5C1290B12279ULL,
		0x60D040FCDF047116ULL,
		0xCCB26F760A8DFC96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA5ADA9D0E538FBULL,
		0x37640F9B715CF98BULL,
		0xD9D97C9DE67CC26EULL,
		0x7E8E60783C9473ABULL,
		0x966AC1256CCF3F40ULL,
		0x169DCD1014F9FE25ULL,
		0x5F5BDF6880469517ULL,
		0x570F149817C09DB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99C4F70CBD93FDF0ULL,
		0xF919CFD109514299ULL,
		0x77F2B3D14FC4761FULL,
		0x46475D8702CFEA36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B5CAAB05739C0C2ULL,
		0x5D47A2884D36DEC7ULL,
		0x8D9F290063951D91ULL,
		0x093402F0BD7A545BULL,
		0xBFDBB8D6167CC1D3ULL,
		0x2C13462749047509ULL,
		0x442A458198A8F53DULL,
		0x85B70090046B2AFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224AC47BB21551A9ULL,
		0x1009FB8799D5CC66ULL,
		0x63C5417B74610E44ULL,
		0xF20766631133FCCDULL,
		0x238C27589C7F165EULL,
		0x37F0139D6E86400EULL,
		0xCF2AB5E931671DDFULL,
		0xE9E3B0530D23252FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CE17ED4C0CBE017ULL,
		0x8A772777221CEFBAULL,
		0x87C9382442FA073FULL,
		0x388A859A60F7340DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D1CF59D1FD26C64ULL,
		0x432E4A1710022ED1ULL,
		0xCA6FADB7C99B7147ULL,
		0xC30D902FFC27D1C0ULL,
		0x92D1E389284DBCDCULL,
		0x8E60C274272F2B87ULL,
		0x3C3D9EEA41553B89ULL,
		0x76AE2ADC2072C59DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE2C638442AC737BULL,
		0x4CD0E80345883FC2ULL,
		0x6132C21A54D5FAB4ULL,
		0x01EA5FA0F184D670ULL,
		0x6B457E9FB30858E6ULL,
		0x40FAE436E73FAF53ULL,
		0x6608DE6CE0A82BBEULL,
		0xA0120DA7E83F169BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DC78CC04572CE9CULL,
		0x737C5F2B48065ECCULL,
		0x35117E39CE75CEC0ULL,
		0x1C4F864F624EF596ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x855408E0C2ED3080ULL,
		0xDFFC9C5DB62FC102ULL,
		0x9E196E85BD5A9198ULL,
		0x1D2DEBB5CF586BE2ULL,
		0x21DAAFA1C2CF9145ULL,
		0x4A9A2D1C0F3A1FF0ULL,
		0xC639B2D15603ED8DULL,
		0x67AAAB8BC3CA13EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D3368E65C9EEB0ULL,
		0xC4586393B1A3F30AULL,
		0xA14F75C8F72EC59AULL,
		0x91CDDCEF9540BD29ULL,
		0x9BCA481C6359EAC6ULL,
		0xC3ABD8621CDFCC14ULL,
		0xCF7152CF85BD8503ULL,
		0xBEE645E444F22720ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1F0301E8899F6A9ULL,
		0x2304CC63FDF4408DULL,
		0x9E883901B09F5068ULL,
		0x188725A30E24D571ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x044423FFB8D85D13ULL,
		0xC05F032B0402644BULL,
		0x92F278CC9FF62477ULL,
		0xDE7F63727E690CB4ULL,
		0x8A29DD91790EA7C6ULL,
		0x675D796FAABFEA8BULL,
		0x71EADE82BB5969D8ULL,
		0xFD776FF443E180FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB20F0BAF8FF3A9ULL,
		0x88D1F79E40606629ULL,
		0xA65010C43BAA37BDULL,
		0x7207F133925EA595ULL,
		0x0A9B7613DAFA0854ULL,
		0x998F176785080885ULL,
		0x6713DE1056DEDF2AULL,
		0xA030FDC7596D0163ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B571998058166AULL,
		0xC42F98C25CED8B18ULL,
		0x888C79034E7C8286ULL,
		0x44EC64E9B95557FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB856CA08826F95BULL,
		0x62F4AAE4ABC6F1A6ULL,
		0x547E5EA48B790CC1ULL,
		0xA14567AC22BD64DFULL,
		0xA965916EFF61AEA2ULL,
		0xCC1357E100F95009ULL,
		0x6C4D0E24CB3DC970ULL,
		0x43C65DBAF2EC6B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4D168DB784B962ULL,
		0x4493FBA777B114ECULL,
		0x4CCE85C4C91F2024ULL,
		0xCC135DAA5F6E315FULL,
		0xABA93885FEFB5386ULL,
		0x63ED29806A5733E8ULL,
		0x2E4C13C0DDA523EDULL,
		0xD591C04FF8DA5717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA2D88A8DFD3C2DDULL,
		0x940B91939026099FULL,
		0x3BD503B507027E1EULL,
		0x310167E2E1FE3AADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FE1CD7A7D4C8AA8ULL,
		0xC9D99FF204238E14ULL,
		0x49D05540178E7EB5ULL,
		0xA3BD2FC3F7FEE214ULL,
		0x35D08C86049092FEULL,
		0x40724A766DB3AAF3ULL,
		0x8E6914B4A48D5F88ULL,
		0x0E9BF44763FE3844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B6764CBEBE6967ULL,
		0xDAABF22803473246ULL,
		0xC107657BE6271650ULL,
		0x535963CABB2ED851ULL,
		0x959D0F3D97161E7EULL,
		0x26E63F831B324EFDULL,
		0xA1C37386B39836AAULL,
		0x203501A4D9226134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94CFEFEDFEBB6BE2ULL,
		0xB9F74DE840100243ULL,
		0xA95EDC95F5CB795CULL,
		0x33ABD019D971F61FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34A3FD91BC066996ULL,
		0xA42A123410C8A3A4ULL,
		0x395A348F57BE5CB4ULL,
		0x0D1C16169A2CF820ULL,
		0xAC5914A2C482093BULL,
		0x67A1EE33E062B1A5ULL,
		0x41F64538593F9EF2ULL,
		0x4C9299BB9B342786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D39B8E5531C780ULL,
		0xDE0A0579002EA3D3ULL,
		0x43AF551CB2D114F4ULL,
		0xE1990F2E3AD697A2ULL,
		0x053A5C058959B262ULL,
		0xCE114EC4F528802DULL,
		0x20F4B94BDD8E251DULL,
		0x693645A5EC2AB9B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D5FC95A2ED1857BULL,
		0x9197B731FB3D57B9ULL,
		0xDBE5A48D01455D4EULL,
		0x6B3782205ABCAD16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8308FB1E30DBF5CEULL,
		0x83F5CADF21677DDBULL,
		0x3E4724912A4CC3C8ULL,
		0x8503376A8C714E53ULL,
		0x817E091C843058BDULL,
		0x0D5ACFF60D6CF584ULL,
		0x874B36A32678C321ULL,
		0x8A67843D39144336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3910FFCF602B73ULL,
		0xA0261C178CDA892BULL,
		0xB82322DA2D4061D0ULL,
		0x6C35135E6258DF0DULL,
		0xC86830AF465A866AULL,
		0xD8AD1CE0F1C54501ULL,
		0x3D55B9CF61B5E792ULL,
		0x371E697FB580C41AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x220E0A558F390475ULL,
		0xB59843E9AF712817ULL,
		0x8094892631F8F913ULL,
		0x75A81C2DB1FD4D78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66D81E0D3BCF0965ULL,
		0xFBFC4B0084AC68CEULL,
		0x8534850E829BF888ULL,
		0x0088488E451FF0B2ULL,
		0x4C1DDE2D79693882ULL,
		0xA72F25CEAC2485E6ULL,
		0x3FE7857553F13285ULL,
		0x65F2E617A53266DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8955CA1A9D2586C0ULL,
		0xE7CEB4A7DD27B206ULL,
		0x631389058FA19CFCULL,
		0xA26D6D19B9C3C627ULL,
		0xBB228B8BDB6D1D40ULL,
		0xE573D624739E6E28ULL,
		0x5EEBF26A8E85C4E1ULL,
		0x9C213FCABE104A68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62D097F012158D1BULL,
		0xD5FB699D0B6C3CEBULL,
		0x8778CFA240ECA1DAULL,
		0x53398ADEDA6C6430ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6DD1630DE0ADD5CULL,
		0x132B4C3AC7FEB148ULL,
		0x04BEAAF87427FB18ULL,
		0xCEEDD32C05E0E977ULL,
		0xE3F842FAFCFE0930ULL,
		0xC389203E94A1E125ULL,
		0x79002021070541E9ULL,
		0x17F273972C77CE66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8273974C9FD04C9ULL,
		0x48405A830F75745CULL,
		0x8E395F3B01EA8138ULL,
		0x012F788568E781EBULL,
		0xBFF40F24EFE9D00FULL,
		0x318F96E0C8073116ULL,
		0xD13E45A2852679F2ULL,
		0xEB9719B0FA6A88E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47558E82050E4EDFULL,
		0x75F555A4177F5F2BULL,
		0x5D4BBA84B94F289FULL,
		0x634DB2D20AF1B916ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB7BBD77766590B2ULL,
		0xE30A3EB326D13309ULL,
		0x59F13CFBD52C704AULL,
		0xB910978355D70E33ULL,
		0x1700F9E07E2BA43CULL,
		0xDC5686D708C11E77ULL,
		0xE20F8144649A5471ULL,
		0x16F2FBD8859EAAB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B470C0BB9EB818ULL,
		0x84B81EFCE4D29F48ULL,
		0x00DBD009528E91CBULL,
		0x07A146AF3D1C241BULL,
		0x95E43BE79AEA1AE5ULL,
		0xA1B6D2BBE4DF3858ULL,
		0x4B1B4497D9B08236ULL,
		0x191CA330DADB6711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC0B7FA876813B84ULL,
		0x1206DBBD9586BC48ULL,
		0xC1566E8F2153134AULL,
		0x5F4079B771B6F51EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE67D751D828B7AFULL,
		0xA79C5C423BEDEF61ULL,
		0x675662E4EBA1BDFBULL,
		0x85C358409D7B2C9DULL,
		0x72035762CB783BBDULL,
		0x8C1609BBE44CF42FULL,
		0x5AD0F9FBB32D5FBEULL,
		0x048D9DD38A2C1A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18B4966C2D726BA2ULL,
		0xCB5D3F36B6C6581EULL,
		0xD8AA46B740A96EB1ULL,
		0xADEDD88A5DF9A371ULL,
		0x3965ADB93DBBA301ULL,
		0x296ECC9D518F7EADULL,
		0x1DB392942D22745EULL,
		0x3F791018C6A67CADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D1A7010B4B4F69FULL,
		0x81122F954D470898ULL,
		0xA109758B90973F98ULL,
		0x18E2896F4556EBD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B266585A4AFDC23ULL,
		0x2D369282C8183F9BULL,
		0x66E5FB6D6E35C804ULL,
		0xA82CEDD2D3672477ULL,
		0x5231F9A31E8F8EF3ULL,
		0xB9D20AEC073A74B6ULL,
		0x5AE8DBAEED75EA0CULL,
		0xAB0510083CBF944FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE968D9785A194D00ULL,
		0x876270B780AF2061ULL,
		0xF807A5FEA76C4ACFULL,
		0xD82D5BABD2AEB3B7ULL,
		0x2CD56C251BE26349ULL,
		0x5A70B01C6549FEB6ULL,
		0x9C881423C6018D91ULL,
		0x863548A1CFE79386ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D7A8CC1B04B0B1DULL,
		0xCE479C9D511AA33FULL,
		0xB13BF416A20F3784ULL,
		0x46D72B5B28C88E8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C2C33E1ED27B4BULL,
		0xD21BC4C5B4044005ULL,
		0x6DD0D463893C3802ULL,
		0x4A8B33B6275DA404ULL,
		0x10660520DCB8439FULL,
		0xD168E7FA83070A3DULL,
		0x293191F0D4B96641ULL,
		0x8577438E2FFE1DA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BD861AC216602DULL,
		0x0ECB99E45E62963EULL,
		0x281666496C559DB1ULL,
		0xF2AA294C1738DBE2ULL,
		0xE53FEC98256B4501ULL,
		0xE3451D5F6EDEC04DULL,
		0x1CCAC8B80E9507A6ULL,
		0x02810BBD5514E1B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07ACE16E9229E951ULL,
		0x1CA03DE6539CA347ULL,
		0x1CFC4C87864CA551ULL,
		0x486D536A8EC3AE36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2BE948D1EBA3882ULL,
		0x65A3F76A7FFC5A61ULL,
		0x0ECBE12578760983ULL,
		0x092402F66F2B6BB5ULL,
		0xCC577435379E60F4ULL,
		0xBD91ECEA5D614FD6ULL,
		0x3EA97DEA626687BEULL,
		0xB1C766C26E301CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CBE5C929436A2EULL,
		0xD0E660EAE3FB65B3ULL,
		0x78984F8F0A993BDEULL,
		0x063BEBE94B8A8EA7ULL,
		0x1A5A6C468B182E40ULL,
		0xFC49916C3DE94368ULL,
		0x797D49AD89419005ULL,
		0x5EC784991CDD865DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1781DC31916256D4ULL,
		0x457B2B3847D2CD1DULL,
		0xDAC3529EA9599311ULL,
		0x54E3A92F35E32D0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB208940357C8DF2ULL,
		0x444781A2B8159E79ULL,
		0x7DEDC70A9BC09192ULL,
		0xD49001C2A4BC7007ULL,
		0xB84597D41D92BF16ULL,
		0xFA7BE24A2A01740EULL,
		0x19639C35A64F7946ULL,
		0xE2884B582369D4E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB45A0003D82AA9D5ULL,
		0x00DBCF174F002885ULL,
		0x2098246862AFF478ULL,
		0xA052DE09132FEA82ULL,
		0xE813493274A7A2D7ULL,
		0x128C635734C0C61BULL,
		0x2CC3C8BC7C46910CULL,
		0xA049C71231278D9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE3E353B703816F3ULL,
		0xB0F88A9BD0AF47FEULL,
		0x7D0F069E766315D8ULL,
		0x0984C61B8763194EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26F36A2D0EB26298ULL,
		0xB65250BB3F7D16D6ULL,
		0xEE83017860BC3B3AULL,
		0x524E59C3504AF06FULL,
		0xAB8738EEE8BD7319ULL,
		0xEE5B27C2F6DB0271ULL,
		0x84928B33A5562CCAULL,
		0x362FF5BFA0011511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98D4BB23CB5325A7ULL,
		0x7D21397E28E40EE1ULL,
		0xA47EDF707BD43A58ULL,
		0x738830D9378B7898ULL,
		0xAB56D645632F4F80ULL,
		0x817EC891371A4C15ULL,
		0xE7EB154248D15D99ULL,
		0xCBB1208C6DB93B60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x954D543316788250ULL,
		0x61E7389F8D34199CULL,
		0x8ADFA3DBA09EC238ULL,
		0x2D99CE838F69C80EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D8E17B246A6BA43ULL,
		0x6AA65F8F184102BAULL,
		0x903530B7E6EDF99DULL,
		0x8E48E334F7B88614ULL,
		0x72D9EB1BD06B28F0ULL,
		0x20E57FDB9431EF2EULL,
		0xA316549D921C9D76ULL,
		0xD872E8EBE7896E86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF14A10330B54539CULL,
		0x67F4E6779987157AULL,
		0x0AAC8351012CFBECULL,
		0x5212A7ADB67124BFULL,
		0x4FA7F9556B794163ULL,
		0x4AE1F901A3C2EB83ULL,
		0xA9A4DD214F5BD1FCULL,
		0xF4F1B60439B4EB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75ADEAF2373AC4FDULL,
		0xC7377D712F3478A6ULL,
		0x8C6069D8CE5F31C6ULL,
		0x0163C9EB0ED2DA02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25C662112AA387BFULL,
		0xDD52808D0A8AE7A0ULL,
		0xD180F5D2BF15E61FULL,
		0x0DE8112D3B63329BULL,
		0x4F4AF6C175179E33ULL,
		0xB06EB5276ADCC26DULL,
		0xF1A358F2B185723EULL,
		0xD6EBCD9F56390DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F5A4E9604DA0DD3ULL,
		0xDFC072DC8C3D24B0ULL,
		0xC10694E53979A232ULL,
		0x642D62C41621DC74ULL,
		0xA52BFE663AB39A0BULL,
		0xDD44AD9534BCFEA2ULL,
		0x8CEE9BAFEDB851A3ULL,
		0x33B51053AD7E027DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC704F105D0A21B59ULL,
		0x55CF2D648704D304ULL,
		0x034E78D6960F1AE8ULL,
		0x63DAC7A43105070EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE05796BC3735244ULL,
		0x238FDC53431CCBE9ULL,
		0xD9312416FBB8C417ULL,
		0x0F8E7E930B10256FULL,
		0x09EA5ED088926A26ULL,
		0x5FDA50EC1BA2FDE3ULL,
		0x93F00DA411C4F5C8ULL,
		0x77D86721441614B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BE693DCB43783EAULL,
		0xC6D6B5891FB566C1ULL,
		0x4D069A80E77C660EULL,
		0xDCFCF24453D54884ULL,
		0x023CE437AFDDE6D1ULL,
		0x5F4CAB60B9E68D88ULL,
		0x469F3A704F305E59ULL,
		0x9C87B9EF280E613DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5DF183F3A074C01ULL,
		0x71BFB97AA56012ABULL,
		0x0629E344F64AD882ULL,
		0x408B41BEE05F815FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33FCA800513F597AULL,
		0x63706DC41DB5058AULL,
		0x8D98672B71DDC435ULL,
		0x7293EE09E3F25D4EULL,
		0x4F720F51F9E77F3AULL,
		0xA7FAB40CF6FEFE92ULL,
		0xB9D07B324D94ACC4ULL,
		0x5E69C0748DFCC843ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AC6D089356C0443ULL,
		0xE8C476002F47716CULL,
		0x9B7495167B290429ULL,
		0xC2A5A9E385C38719ULL,
		0xC22E6E818053C286ULL,
		0x18697FE6869B3DB6ULL,
		0x4B7DEFA50420456DULL,
		0x307898BC4358866AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE13FB66927C158E6ULL,
		0xCA39B5789D3C34B4ULL,
		0x5264890DDDFC170AULL,
		0x01BA298172909C7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAEAF11C91023744ULL,
		0xCCCABB9E7511D34BULL,
		0x5918029025470C91ULL,
		0xBFEB0B76E127586FULL,
		0xB4BE665745A78510ULL,
		0x0B68D64ADA7E996DULL,
		0xB1C1C7B4E88DB23DULL,
		0x954416AB9370BD43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x002A246594240ED3ULL,
		0x09A2D9B88CF48196ULL,
		0xC5484D05FE8D0F99ULL,
		0x882BB609D93FA963ULL,
		0xB24F6600362F8F40ULL,
		0x7EBACE6EDB80AFDAULL,
		0xA19910BAEAAC315DULL,
		0x0BED3BCF77B307ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x473AD9A348ACA85CULL,
		0xA4FD0C8DC1CDFD88ULL,
		0xF9DADEA5D6331E27ULL,
		0x1AA3D2192610A39DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8361C3CAFE68DC95ULL,
		0x5C45DFD4524D7AF0ULL,
		0x521401CC8C796A9BULL,
		0x9ACFB990693986FAULL,
		0xF0A63D19DA743552ULL,
		0x5B65659DFBC7DE53ULL,
		0x2F62BE1171B971E2ULL,
		0x1022040FDC183EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3F7198D93084D6ULL,
		0xB329D25000BD7202ULL,
		0xFDEA116132B51380ULL,
		0x9C3C0317CBCA9BACULL,
		0x97C922A91FE2B0FBULL,
		0x70C594814DD07935ULL,
		0x070123A90F622D92ULL,
		0xCCE494C84218022FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9F43EEDD6D1F86EULL,
		0x7CD517C624490B6EULL,
		0x52A6DBE9F2B87AF7ULL,
		0x79B23B197977F0B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B13B04A4A6609EFULL,
		0xB4B025731569680FULL,
		0xBF2DE38AC4D51A0CULL,
		0x31A4DDC0639FFF91ULL,
		0x5F3263DBE773B41EULL,
		0x12452DA977008912ULL,
		0x90FE092D4C1C42ABULL,
		0xA724C03615132335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE79AC9D5D8CFD00DULL,
		0xA8275AFCD769A082ULL,
		0x953B5EE74115E44EULL,
		0x059764BC50B4C8A5ULL,
		0xB7BADD4FF024AF74ULL,
		0xD17106419338A3C7ULL,
		0xB3053771AC2D30C0ULL,
		0x40531538B3C04712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F36DF3B2750ED58ULL,
		0xAC06A3E20DABD0A1ULL,
		0x1CE1A67D413BDE83ULL,
		0x6F2CDAA08537E419ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49F423BA6497657BULL,
		0x136ECB89DABD0407ULL,
		0x784728F938BB910DULL,
		0x570E6FF9864CFA62ULL,
		0x899BA52B74276C0DULL,
		0x531F76260FEA2721ULL,
		0xFB417D6B013E1A42ULL,
		0xBE69551F0DDA3388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA02FCBE1335C9CULL,
		0x4CDBFF1D6912A638ULL,
		0x59A212460B289578ULL,
		0x84A732AA96231094ULL,
		0xBD6DBB777C10A287ULL,
		0xB34FC4FBFEF9B922ULL,
		0x624612360D45EEB3ULL,
		0x64331D0BAF3C63C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB24A4A556C5F4B1ULL,
		0x7F6718AAF55AB1A0ULL,
		0xD3F7008F646972C0ULL,
		0x3673902EFB96C0B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F6DBF2DED4FFD2BULL,
		0x50818FD2A5F3B5CCULL,
		0x6346775773919199ULL,
		0x75E750F7E174A443ULL,
		0x237C3CC464978C73ULL,
		0x9A4F6C8A7EC0CF33ULL,
		0xFDD09110DEDBD797ULL,
		0x687B62CA69C19A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x760033A4246E999DULL,
		0x16C3593816A678DAULL,
		0x3CE6BA5A05516138ULL,
		0xD7EEA15A88C5CCBCULL,
		0x069FD1C544829217ULL,
		0xFB34B63D76A1C94AULL,
		0x2BE95C5B2A598658ULL,
		0xB6BE4A4D13550BD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22256D688BFE8B6EULL,
		0xD7B54609C3E81D8CULL,
		0x4EB18FF639983FACULL,
		0x000A52382CCC0742ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA76AF05DD5D36A1DULL,
		0x4D19FDFE0D541A56ULL,
		0x10172329802795D8ULL,
		0xD5A6DFC3F24B2386ULL,
		0x12F70465E36E74E4ULL,
		0xAE98771BE1037ED9ULL,
		0x05F442E6106A88C2ULL,
		0x47B8B5E206E31156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B45D52CB8731FAAULL,
		0xF6E0567BFC50B852ULL,
		0xC75142D658475EB4ULL,
		0x74CDE733C19737CCULL,
		0xF9A9D9FD41F42894ULL,
		0xAAB68F14754C4331ULL,
		0x592AEFC2F9052D01ULL,
		0xA8EA633A55E65398ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D9966B915879C2CULL,
		0xE9C2189C0E363CD2ULL,
		0xEEA83788A0EBD5C9ULL,
		0x73793D74763815E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C43ED29D7006426ULL,
		0xE42AB43600518155ULL,
		0xA35AD87570130A12ULL,
		0x3F65E1655F3CD23EULL,
		0xFD0EBA49911EB959ULL,
		0x14FD330AB3388E8FULL,
		0x62DF26EE9D8CC423ULL,
		0x358E5489CC4E65F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99066586134FCBC1ULL,
		0x584D2FD52D756EC5ULL,
		0x6A55CD9237B3787CULL,
		0xC6A18C2768AB5B4DULL,
		0x3A0D3314F69FF530ULL,
		0xBCB762C3D3A10AE0ULL,
		0x0D6BA90AA2D947B3ULL,
		0x32BAD84FF4E596F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5779972B281B668ULL,
		0xA63A6EE603599EA6ULL,
		0xE829BABA6F040A1DULL,
		0x6428C5D3F020303FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FA5EF7B3423E0DCULL,
		0x85627D9F7F3098C4ULL,
		0x9488FF8FE1E36B7EULL,
		0xE19FECAAEA947048ULL,
		0x1C194F871EEEE445ULL,
		0x73DD2B2EEDE4B449ULL,
		0x9CC8167F2F4FC643ULL,
		0x4747D9205E0A7FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9DD333A68C427F6ULL,
		0x4B0C3B18D77F9E5DULL,
		0xBCF00D198C2DD206ULL,
		0x1C230DF58D16D857ULL,
		0x78D19717FDAF7F3EULL,
		0xE3BD12304845EE35ULL,
		0xA15F2F100BD56F16ULL,
		0xC32F8DE6F483EF15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF26E1CBFBAC8B544ULL,
		0x9F19F8533D426150ULL,
		0x292B4CF599DE8A15ULL,
		0x6118093B077718E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5A619E7CF882089ULL,
		0xBAEA08DD78B30791ULL,
		0x307F0E5CB3DDA9B6ULL,
		0xC89AD3195931536EULL,
		0xD47098AA755DD97BULL,
		0xA58EDF78E855BDFEULL,
		0xA9C158A7BA884E24ULL,
		0xC766274937AC4F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC15FA9BAC9C8DB66ULL,
		0xBE310A9F15ACEF5DULL,
		0x549DBB290FACDC7FULL,
		0xB477826BA27D0E6FULL,
		0x2E66C86D11CF8931ULL,
		0x9468C17211CF080AULL,
		0x72C0469EA8927515ULL,
		0x4E686B6F3E07E103ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99BB5949CCDF32CBULL,
		0x886173423B051A84ULL,
		0x060A008C4EAF0573ULL,
		0x09CD3308C51C9A5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F439E0E65E20107ULL,
		0xCB8933207DC6D3E9ULL,
		0x147FFDAD9E9B74F7ULL,
		0x21E0DDE7F5BE321AULL,
		0x2D2115490E37304AULL,
		0x0ECFC0DC25B8902CULL,
		0x520BB40A5EAC299DULL,
		0xD4096D3CC721E2C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A19F148CD81D09ULL,
		0x35F499431FDB9D9BULL,
		0x72365CF4002074AAULL,
		0x276C54E801508039ULL,
		0x01ADF77DC7D0972CULL,
		0x66209B461E635A9EULL,
		0xF0DF7EEE80260386ULL,
		0xEF792DEA4F21D3ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DB86B264C449DC7ULL,
		0x9F942E2274912968ULL,
		0x0ED982DCA664A7AAULL,
		0x67DDEF3DC46FEEE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EC5D60D0EF0B525ULL,
		0x34221F9249DFC9EBULL,
		0xED38F2216A14164CULL,
		0xE29D4873CA1B8D25ULL,
		0xAD60744E07E59EE1ULL,
		0x25FED7399C700FC5ULL,
		0xA2BDBEBF0249E46AULL,
		0x6FD9BB7F1F4F4E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36E8EE28643108DULL,
		0x7031D15869AEA880ULL,
		0xC4502CBFD9D7F2BCULL,
		0x925EF6C4B4D1F6B3ULL,
		0x20225BA88ED1B8CDULL,
		0x638E398897FA0031ULL,
		0xB093EA41712EABEDULL,
		0x452230E9CF78839BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC28EEFBA81A1CC87ULL,
		0xA0A7B68089B77177ULL,
		0x1B1E50051A468614ULL,
		0x277CE3D8EF2BA4FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25ABD1C6C41DD7F8ULL,
		0x29736DE78E4B76E2ULL,
		0xE809A03CF636D40DULL,
		0x3C4B29BE90BD610DULL,
		0xA7D93F1A60A7556EULL,
		0x4AA17DB654CF2BFDULL,
		0x89C61F0DFBB7A67FULL,
		0x8345E34F58D974F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1471E7B2A5F409DULL,
		0xEDEB979AEB015FBCULL,
		0x214EF7099910DF62ULL,
		0xE7316FB8DF03BEC2ULL,
		0x18F140CFC041E9AFULL,
		0x2B008CC9CD52A625ULL,
		0xFFC2D47EE41049B8ULL,
		0xB56D748894E4DD29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AD4725F68CC9472ULL,
		0xED6B9968BFC5F54AULL,
		0x4337BA70DFFDBA38ULL,
		0x633A2B86C80829C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEBD11FE5708B019ULL,
		0xA0E09D036A3CA5C6ULL,
		0x6A64B0C598650DF1ULL,
		0x64C3EB45F42A7588ULL,
		0x427DCBBF895DBA50ULL,
		0x5FEB2C4D0C7D1AF2ULL,
		0x3253D8BF94CFF7E7ULL,
		0x8F2B2CCDC9C78E02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897875FF8ADEE8F4ULL,
		0x20B557D4D204B245ULL,
		0xE09FEFD74E62EDA7ULL,
		0xFB46243D66177FD9ULL,
		0xC7DB6ED1787D53C4ULL,
		0xFAA3F55B35D3A27AULL,
		0x601C0D7472ED520CULL,
		0x12E66F0F26A30588ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x895E67554D790286ULL,
		0x88BD6D14755FD53DULL,
		0xBE0CEE1551A6BEB5ULL,
		0x5BB1F154C57F37C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF60771CFBFA3109DULL,
		0xCCDD772423F2AA1CULL,
		0x282FF428D3379A60ULL,
		0xE2E4096C76D45C7AULL,
		0x809E475F054625D3ULL,
		0x418B6116572E31C8ULL,
		0x7FA1F0D57CD44D46ULL,
		0xB9AC5174F1A95E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5669864334C8D7E6ULL,
		0xD0582D7C6AF65287ULL,
		0xF2A6E8EC514952A4ULL,
		0x4003F060DCE3F844ULL,
		0xF7C0E25090747EB8ULL,
		0xC09A90D21A84B50DULL,
		0x3CEC26A79090388CULL,
		0xCA9C92C4D608E858ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF07AEBB1E1F9066DULL,
		0x204433C8BA24DB45ULL,
		0x1C850E0D94095B45ULL,
		0x1F36672FB3C1EE7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB07EEB3D544619C2ULL,
		0x7F35C5F9E9E2B400ULL,
		0xE105782D973D07B3ULL,
		0x2C6FFA621CE605B0ULL,
		0x680188F1DA541823ULL,
		0x49E54680F56B7224ULL,
		0x7035F31F3FF1C7BBULL,
		0xD083842A8CCBA36BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A3953720F921268ULL,
		0x4B188E828A3A6861ULL,
		0x78F7FAC1AE2283A9ULL,
		0xF0B3F173CEB568DEULL,
		0xD39801D7D17D6BF4ULL,
		0xB376FECE34819CF7ULL,
		0xB15B2ABA7167E5B1ULL,
		0x90A8BEB0DE8A392EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADEFA5A894919797ULL,
		0x887BDC00025DF03DULL,
		0xBC873C6291921176ULL,
		0x363558FE2BE661D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AC5FEE8D95A3A1AULL,
		0x82DCFD83B1F20FCAULL,
		0x92A2DB2821707E25ULL,
		0xC015BB68CD702FE6ULL,
		0x2E403A9B47C59CB3ULL,
		0x230E2279257978CFULL,
		0x11C8121E93A4E64AULL,
		0xAE016673085E653CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F4D60F5B37AB7BULL,
		0x4550C49A81EC5DF8ULL,
		0x9E26ECC2A5AEC312ULL,
		0x93F498D5E95C5697ULL,
		0x41800E482C7FC2CEULL,
		0x56504D271565695EULL,
		0x9C1AD9CD10E438A8ULL,
		0x03300719638E8E30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9657BD2F8A80EA66ULL,
		0xA1B9E31792FFFC94ULL,
		0x6C324A7EE45B8117ULL,
		0x073549E15AEDC502ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x648FDFA5E168994DULL,
		0x31B0F549FC478DE8ULL,
		0x6F3BEE4E5EDE775DULL,
		0xDF10840B31AFE934ULL,
		0x8CB33120FA2B1E66ULL,
		0x92FD2BA4F88E5220ULL,
		0x4057B6CD8FC31655ULL,
		0x680A877F44995BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x389CEF2CA672E4A4ULL,
		0x7C1CB15561B39AB7ULL,
		0x2B2FEB0E02BA6B82ULL,
		0x174EED4AE9559280ULL,
		0x51EF19B2B977786DULL,
		0xC6550DA20EF45F10ULL,
		0x7B2CF63AC80F8691ULL,
		0x0FE83F477C699DCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE50E6AD6D5A059A0ULL,
		0x1688B863476E0799ULL,
		0x8864990A00CB62EBULL,
		0x5CD84F07FF708B8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B5210AED8E01041ULL,
		0x066778369D178FAEULL,
		0x2CC841506B407977ULL,
		0x638CD7B91DD02C80ULL,
		0x785C99324C1478FCULL,
		0x4D957D12B8BBF7D1ULL,
		0x760569495B17E5D0ULL,
		0x385C7FA3AB53574DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB725955C0ADD0952ULL,
		0x8116A52D050DB2DBULL,
		0x534EFD2D82BA1B3AULL,
		0xB2DB19B73DFF75DAULL,
		0x87E2E73A28D0C403ULL,
		0x06B87B02A2F048ABULL,
		0xFFD3A0ACDFDC24FBULL,
		0x0369AC864F151A05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x763CE6280A0FE502ULL,
		0x0A1F216CD445DC74ULL,
		0x64DD0B5D3364FDE5ULL,
		0x0CBD145D910DCF41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEBB767D27443D2FULL,
		0x8D95BE32CC7B88E8ULL,
		0x1730178D01351908ULL,
		0x41A356FBAD61529EULL,
		0xD755A806198C1748ULL,
		0x5E97EC211BAB72DFULL,
		0x8588B2FA8AEE2135ULL,
		0x61A74B21DF31A635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8962D82DE8E29DB2ULL,
		0x1ECBB119617E7004ULL,
		0x261432A01615E180ULL,
		0x4C233A4F5D334BBAULL,
		0x04D580E1005CF04BULL,
		0xE01E2361A38599A5ULL,
		0x209BA5C9D4D7DDACULL,
		0x8FA013D8FF7D2BA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB45E6DD0FB616801ULL,
		0x34DDD985409B579FULL,
		0xEC4BDA27F26D3DCBULL,
		0x2292517D84F838EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58F05E32648A4AF9ULL,
		0x0B69E7F9BB9EA825ULL,
		0x7F654BE4CFD8C9CBULL,
		0x4280EE81D04FC844ULL,
		0x8A76355E203E589FULL,
		0x6FD34DC82647EF53ULL,
		0xACCC548046B568B0ULL,
		0xBAC7B4E7858F7805ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32C527F087A0F2FULL,
		0xB1CD14D05742A2C8ULL,
		0xB9461106051EBC44ULL,
		0x9C92FA2E34F9E181ULL,
		0x53618CB4FBC145F5ULL,
		0x33CB55EFACF67F99ULL,
		0x5C2CB10A90A72AA5ULL,
		0x0F892C38967D8B11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2D514CEC6A104BCULL,
		0x42CB9D4B66729B00ULL,
		0xBDD17E57D0D74331ULL,
		0x11363E4B17FF1306ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD006B4FD1B47ED1CULL,
		0x08A1A9C0BBB95CB0ULL,
		0x5251E5AB2D7399B0ULL,
		0xD2E04BB072A76732ULL,
		0x03E5946225F656D7ULL,
		0x4E674F600FA6FF95ULL,
		0xA32CB02B0665CF8FULL,
		0x288948167872BEF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x625220C42EF284C1ULL,
		0xC5CF0E254F9D99DAULL,
		0x0F75A8BDEFEC078FULL,
		0xAE8DE83B91524F26ULL,
		0xBEC8381F2B799203ULL,
		0xC68BBCC1F03FE184ULL,
		0xF1710280F9663E14ULL,
		0x5FCBA3DE72C548CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB010462A1ADA9E90ULL,
		0x6D6A5F14156A3940ULL,
		0xA4B8042B2B772A50ULL,
		0x7078C3C5B914A132ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6C8B577B934C79AULL,
		0xAC07C104DD4E4CFDULL,
		0x7CE8906D2CCA2A94ULL,
		0x623401B0FD2FF373ULL,
		0xC593E3C4D7BD82EEULL,
		0x0D2F2A58AA84E6C9ULL,
		0x03474EBB120EEA4FULL,
		0xA00DB07F70049209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DEF918194F2F5A0ULL,
		0xAA791787048480C4ULL,
		0x8C08C7D60F8D847FULL,
		0xCED6F8BC37DAB126ULL,
		0x53F6E42EB53C0331ULL,
		0xEFC5F0C5449F04E4ULL,
		0x8403CAE6A7214EF0ULL,
		0x2D6AD9647F2431ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7627143F437ACA7BULL,
		0x5F2D355EF8E95448ULL,
		0xD4E55A1EFC81B60DULL,
		0x1788F6F486A39007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x308D494A20ED8F47ULL,
		0xDD2F348B870E1E63ULL,
		0x5EA27A5A747DD99BULL,
		0x09C095BEE6A30230ULL,
		0x594BFC65C7E7BE69ULL,
		0x9626A0A771B02B4FULL,
		0x716CF5F285FCF1ACULL,
		0xCEA78FEC4A3126E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A7035F2CC48137ULL,
		0x609802C14F406D0AULL,
		0x7AD4528EC06F7B5DULL,
		0xA4243AF28996137FULL,
		0x91D29B50CBC59E15ULL,
		0x2D73EECBFFC32AE8ULL,
		0x127D4D6777C33B8CULL,
		0x9C4648A15457F1A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAEAAF086139DB7FULL,
		0x071D985D20FBC09AULL,
		0xFB612C6FD09F670EULL,
		0x600CEFECDB4AD6FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B370A6994AAD370ULL,
		0x2E3F5888D3283883ULL,
		0xDAD35BC3CB97FFF4ULL,
		0x250BA2E0C0030024ULL,
		0xCFC630E0D93BD591ULL,
		0xF45446C18B0D6D18ULL,
		0x381A66413F7B1141ULL,
		0x49470D819AAA5F3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB6957381F299FA0ULL,
		0x77856B273F1C23C3ULL,
		0x4466D84D8B4B40D3ULL,
		0xDD1CC3400D93BF38ULL,
		0xFEFA2AA360CDC73BULL,
		0xDEBAB9CEA57895C2ULL,
		0x8A8373743C244CF2ULL,
		0x9FE1FAA95B5876C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E16A05155D75280ULL,
		0xEB84D96FA8240B7CULL,
		0x5AD48DE4BF2DE2DDULL,
		0x6CEFABBA1897C2D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5FCF1D331B02FC6ULL,
		0xE7CE63F56CB47C9DULL,
		0x84667FF410D9283DULL,
		0xD363AE6D508FFAD5ULL,
		0x905F085B347FB7CCULL,
		0x6DFC5228860896A0ULL,
		0x81533EAAC107C13DULL,
		0xA3EBD9524DB5E322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6534DDDC906B7DD1ULL,
		0x3B428B9D90DE8EDFULL,
		0x4BA76BFB15AF6768ULL,
		0x4A5DF7956007C0BCULL,
		0x4AC2CF19108159B2ULL,
		0xD2EC5DA99B3FE599ULL,
		0x6878CBFE0DF375FAULL,
		0xAD18CD11EA45133BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5F893C7F906A9ABULL,
		0xB0EA232EB5A034D2ULL,
		0xE92C199B902CECB8ULL,
		0x2C598866B3471666ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3C3E25A156628BFULL,
		0x59DC8F9BCD6BFA27ULL,
		0x9E1857E48DD446EEULL,
		0x20ED154ABBC14EA7ULL,
		0x5D9D591003B9A4A4ULL,
		0x4E0EDB08E8746212ULL,
		0xD477AF51534A95C5ULL,
		0x77909A50AD78B45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32109D17D9092E9ULL,
		0x54263C084B829F7FULL,
		0x21F45E9E7C88408FULL,
		0x43EA2AB966E9A006ULL,
		0x7800F6DF3E7B36BEULL,
		0x7DA2CE945B4089CDULL,
		0xA0CC7E8D58B3E9DDULL,
		0x3D8644F1553B5A5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25D96BC5DF19E72AULL,
		0xF5C02CE0779B74E2ULL,
		0x278D365D43A98AC7ULL,
		0x7A8B96B86DF30A37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57E3D74A01E1DDB4ULL,
		0x6D604302BD6A2740ULL,
		0x4D9D999FCEBBF1E3ULL,
		0x8EDFED486CE5B454ULL,
		0x4D02A55A669B43D9ULL,
		0x24CE5A28B3380D98ULL,
		0x86B0B7C75D6DC1B0ULL,
		0xFF2BC53DB81E0A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B377C2FE0CD4E00ULL,
		0xA4CD19482385AD14ULL,
		0xD3AC6A8CD5E4FE92ULL,
		0xFCA48E550993C1E1ULL,
		0xF62DDAAC4AEF5CA5ULL,
		0xA277041979C7D99EULL,
		0x907578C1A814DB8FULL,
		0xC6AE70040CFEA21AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA04270F23C98E289ULL,
		0x2189EFFD208C312EULL,
		0x06BC89EBE4091C24ULL,
		0x74D60582C9FB6037ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D87C5E7C6DB6651ULL,
		0x5BEFB1B925F6B3C3ULL,
		0xBF53B1CA1067BCB7ULL,
		0xB0BEFEE0A480CFBFULL,
		0x5EB69B24A7DCA1D0ULL,
		0x126EB50048CE38DDULL,
		0x99DDCB18E89B5CDEULL,
		0x30666633404BFB3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC813863D99995008ULL,
		0x48242F94652D718CULL,
		0xD15D547BE1BDB1DEULL,
		0x2FE409D224F0FE7CULL,
		0xB1A70967B28D69D1ULL,
		0xC2C36CE71C394E12ULL,
		0xA698CC9E80CA4E7DULL,
		0x70B52DEA2084AA0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15C3E1B6970464BAULL,
		0xE73835E15EE41C4CULL,
		0x0A34237997B22D24ULL,
		0x75294FE93725DED3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58FBEF92FE5D94FDULL,
		0x18EDE5269010B328ULL,
		0xCB4CE605697A8155ULL,
		0x1ECFB03402D3608AULL,
		0x14C9A63F965EB63AULL,
		0xB472D9C553AFB2ABULL,
		0x794505F8BCA8D91DULL,
		0x80BF2A557F2417E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F631F07CAE3567ULL,
		0x5BA4CED485269C1DULL,
		0x94C4DE2E35899E08ULL,
		0xFB7F71603143CB0FULL,
		0xB2F359045D825CF4ULL,
		0xE8B2D38061584B28ULL,
		0x947F99D9DFFCE221ULL,
		0x0385804FEB098520ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AD5346CF264A293ULL,
		0xFBCA048E03E37465ULL,
		0x2BD6146BF5778CACULL,
		0x39DF7BA7CD815DF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54E51A6315763AA5ULL,
		0x520254649B6A6632ULL,
		0x5C9F51F1EF8DB7BFULL,
		0x1489A6CA104090C0ULL,
		0x8E49F7096101CBB9ULL,
		0xFF1DE050991E1427ULL,
		0xF29E07BF47079B93ULL,
		0x351F57D1CB08E4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7C650130996B55BULL,
		0xFE7B76F5FFDD7B36ULL,
		0x2F1837448F503D95ULL,
		0xF2BBFC64E86478DDULL,
		0x81881154093B247EULL,
		0x99E544E17A2073D0ULL,
		0xCB96D3D883A850C6ULL,
		0x8D7FF8ED6B08FA18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51E6E33B135C55F8ULL,
		0x59EDEFED3532B7E7ULL,
		0xF898CEEE606294A6ULL,
		0x0375C04B67D8ECB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF24099949D7611F9ULL,
		0x1E46D6A665F6102EULL,
		0x7E1BBFCCA9756CECULL,
		0x8C5E8AB328FC04D1ULL,
		0x1680A3EAD4FDCCD1ULL,
		0xA0E22CFDCE83253EULL,
		0xFC88199BF3B130C6ULL,
		0x5B28E6EA2C65285DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8478816C4CB602ULL,
		0x0CB88F849A9D1323ULL,
		0xC212F691A59D4153ULL,
		0x47D3A496A419E596ULL,
		0x5C90D0D6D8BB4D0CULL,
		0x49C825B3F88CED62ULL,
		0x5F752BA24D9645C6ULL,
		0x2AD9ECC8ED5D3178ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0055760AA308543FULL,
		0xFF6B5C178DE547A9ULL,
		0x0CD81C49ABD70DA5ULL,
		0x7044070BE010C550ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFCDB859D27F2997ULL,
		0x7ADCDD471219E2EEULL,
		0x984810EAB6A5C628ULL,
		0x86AEACBF0E4BEFAEULL,
		0x4C9ACB28EEF50FA0ULL,
		0x77CD67377D4C33EBULL,
		0xC444FE3BEDEAD638ULL,
		0x9BCFD1A24D3CA231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1991D9CF518678BEULL,
		0x45F4700B4CE7D4CCULL,
		0x2929A46307218577ULL,
		0x3FE555704F8E52D4ULL,
		0x891A2F4D8CABFFA8ULL,
		0x016381A08C4F160AULL,
		0x17B5F10BD2032BFCULL,
		0xF8E1C816B6AAA2FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB53011B17D10D95ULL,
		0xC8A081A38AC47D7FULL,
		0x0C5A61ABD3E785AAULL,
		0x761EC20718697EF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4C1B7B164637E21ULL,
		0xC6279BF9E8EBFA98ULL,
		0xACFD446C5497993EULL,
		0x089C959113537C07ULL,
		0x5DCBE12260A97B52ULL,
		0xE8B034FDCAF543BCULL,
		0xC23033DA7A58F3D1ULL,
		0x6F0C782E010D45DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE11D9F04830EAAEULL,
		0xF517BB97D4B23451ULL,
		0xF60E1472EDD4CDBDULL,
		0x77D37098FEE68E5BULL,
		0x7C39413A132F3D94ULL,
		0x0B5D2E0E17B2DA15ULL,
		0xD82BF52AFFF74DFCULL,
		0x27477B035A3B9D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2739A3C9C57BF23ULL,
		0xAB62E7F6B015750CULL,
		0x73907E059141693FULL,
		0x3806B94CD78BF4F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x619E7FE99E6B39C1ULL,
		0x33284FFD6BE8055FULL,
		0x3FACBD4F8F8E6F7AULL,
		0x56BAF3F1DFD1879EULL,
		0xE721733AFDE8671BULL,
		0xBAE1529342906668ULL,
		0xF27A07A544DC03AAULL,
		0x3DA8CB283A6FE038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4414A2005E86949ULL,
		0xA956D0586811D5A0ULL,
		0x53C1654831ACEFBFULL,
		0x8E2E07F25656A112ULL,
		0xDDF10EC6FDA0B437ULL,
		0xE6EB770EF8F5EC34ULL,
		0xA21E1B048ED6A2D2ULL,
		0xA2FB65BB01DEF476ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA8C1F01A3275C03ULL,
		0x00501547F0C45377ULL,
		0xD99077E262ADDFC4ULL,
		0x3E49FA35EEFDE563ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B87563A42D34CDFULL,
		0xDE701C2B9496EEE1ULL,
		0xBCEA44FDC17931A6ULL,
		0xCFAB6C51DD59037BULL,
		0x46856A1544142C8AULL,
		0x907AFD84A8E1B53EULL,
		0x753811E6CFA20517ULL,
		0x5EB56673086CDA4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x344F9A67EA9B11A5ULL,
		0x0E2D7299D1377DFDULL,
		0x7F7C808C6EC0B049ULL,
		0xBA3D311F871DA0ACULL,
		0xB2E7F2387D250720ULL,
		0x7C0F33E025953293ULL,
		0x70D60E7C18D5E444ULL,
		0xD38EE9F7462262AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30978697DFB7C65DULL,
		0xD84297FD40BAD636ULL,
		0xE3FA4648750560B2ULL,
		0x3D24B5912D492443ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC00EB2A9294B904ULL,
		0x7B24FCDF695C30F7ULL,
		0x8C0B67076A02F649ULL,
		0x87D30A570C3DB606ULL,
		0xBAB50C19911922CDULL,
		0x16028C25E699AEB8ULL,
		0xB9ACD782E08121C1ULL,
		0x7461DE644FCFB180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x791C061B325C00B4ULL,
		0x43213271254C16FBULL,
		0xD783DA92C2746619ULL,
		0x23B2E7B94765C1C3ULL,
		0x53C6C56FD514465CULL,
		0x885D6F5879C867C9ULL,
		0xB6FD12319044B6C5ULL,
		0x6873E55E7000C652ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA43624148F17162ULL,
		0x3E8610EC6B20A185ULL,
		0x1A9ED68690867187ULL,
		0x2973197CFD8EDD17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00146A4A4CCE6AF9ULL,
		0x162793AE477A0790ULL,
		0x6DCF9AB1E6E39740ULL,
		0x4E3DED82403B20E6ULL,
		0xC20983445FCA8780ULL,
		0xA04DD06A576BD0A0ULL,
		0xD1B8076D8B564B3FULL,
		0xFE6B9AB430CEC0BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8D6E5B457F9355BULL,
		0xBCD83552CFDF9C76ULL,
		0xEA9DC3D5BCF07B6FULL,
		0x76FBBF0A4C54BC1AULL,
		0x66793F2C620F0ED3ULL,
		0x27826653803E6A3EULL,
		0xD33FA31B46357F96ULL,
		0xAAE586273CEE3879ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEA7A0259EA92114ULL,
		0x47811DBF68579DB2ULL,
		0x4910BB126CD156F8ULL,
		0x3D293B64273A9E71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE90DB21C3294E1DBULL,
		0x639C5689E354F9D3ULL,
		0x65B2A42D96B75C9FULL,
		0x02E5D99ABFB3041BULL,
		0x33C917D7E52ACAE1ULL,
		0x3585694081299DB8ULL,
		0x5533F732D5C70897ULL,
		0x2266234C7571DAB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD110623250BC17F6ULL,
		0x82CD7040719D572CULL,
		0x81D10DDAB0939A6DULL,
		0x7594C04D6E9D3084ULL,
		0x4FDE9D74C1FE6C43ULL,
		0x7F3D04AA82130924ULL,
		0x68105DF997DF1A80ULL,
		0x543770EBC783FF85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECCB7AA11A6ED429ULL,
		0xEF8DD48D4F11B09AULL,
		0x172A54D216911990ULL,
		0x283F93A722645D00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6B3E627E2FC91F3ULL,
		0xBAC335B310EBE498ULL,
		0xF367494AE0DCC34FULL,
		0x8A21716E391E28D4ULL,
		0x7CA07AB6353F8E5DULL,
		0x1B08C2D366F515D3ULL,
		0x24286744168B87D2ULL,
		0x745B8D79FE115158ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71BC0BB96C67F1B4ULL,
		0x84D2C8FCF2135184ULL,
		0x1CB0DE7BE42E61FEULL,
		0x2A0D573D7D962943ULL,
		0xCD65B18F39652E18ULL,
		0x92F621F1F10E159DULL,
		0x0AC417D2230276D2ULL,
		0x5F3FB72284E7786AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77B1B637D8FEEB02ULL,
		0x68B44E2D9F229B0CULL,
		0x9B9A35B92306E73FULL,
		0x0235EB2CB7BE32E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE38721A4E04F73DULL,
		0x0A1E5BFFEE6D5924ULL,
		0xE8C0010DB2221D2BULL,
		0xF8E3BBA8040B503EULL,
		0xD0894FA3996E9C3EULL,
		0xBD41EA6E49619969ULL,
		0xB00F7E8C467241C5ULL,
		0xC66078799B02CB7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F8CEAD54831B96DULL,
		0x17100D10594ED84AULL,
		0x7E803299BC5C4C3CULL,
		0x305268C0B275D5CBULL,
		0x141502900D27317CULL,
		0xD662EE4CCB5EED87ULL,
		0x2C52BD1AB7B507A9ULL,
		0x6AAE871DCD04B382ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7EEF82BD86D18B0ULL,
		0x3827BBE849840482ULL,
		0xF844854F25DC7113ULL,
		0x64FB2687E54D09A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ECA7C5FB88CE52BULL,
		0x399A1307F76F8522ULL,
		0x82975639D00EDE3DULL,
		0x9035B1BA3EF51C0FULL,
		0x388BC504397E2B24ULL,
		0x9DC24E77D80D6E2DULL,
		0x0F3817F465392C9BULL,
		0x0086E6DE343A777AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1BC5BD2A4154F1CULL,
		0x7B7C0FBF33001CC0ULL,
		0xFFA7CF182DD59367ULL,
		0xC9D5BF28BB53B507ULL,
		0xE2B127564F177664ULL,
		0xB72CE0F22067DC29ULL,
		0xBB4A6E96578893EDULL,
		0xD52AF963855D6B94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B81885DDFB665CFULL,
		0xF84C4522070314E0ULL,
		0xF836AB17AA6FF4A5ULL,
		0x360532C778712B11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB895C396A435ED73ULL,
		0x4B973D0977467F51ULL,
		0xF27248798319FA3EULL,
		0x6637C7832226F3B3ULL,
		0x86F6CFB17A5ACCB1ULL,
		0x6E90D9B79876D13CULL,
		0x5168A52E2747FE16ULL,
		0x5B6E6BD339A56625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF15993D02FE908EFULL,
		0xC7ACD9AA710D4934ULL,
		0xDED087C8BAF8F3B3ULL,
		0x1132D93425944210ULL,
		0xA9020D33A2A1BA69ULL,
		0xDE10860D93C73076ULL,
		0x7E0B524FB343CEC5ULL,
		0x9ED4814719E7C5F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9910E7479C599B8ULL,
		0xF6F6CE9BB84B137BULL,
		0x737C0DB600C00C7FULL,
		0x53DDBF1BB2B8784AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB739F5F11C8DA20ULL,
		0xDC785E9C82363C63ULL,
		0xC15346F95EB31412ULL,
		0x776CCB29135AB3FDULL,
		0x78C7B0FD3D415DC7ULL,
		0x05EA5C8695206CA9ULL,
		0x2BB1B6A3F23A138FULL,
		0xB9285806DE1030B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C498F05C119B5B4ULL,
		0xE531B7A76C28C57CULL,
		0x49C49CCBCF2D35A5ULL,
		0x8F34D166AC7EB4F7ULL,
		0xD502C33EC3F4BA47ULL,
		0xC84ECB855328663CULL,
		0xA1B4FC171808D27FULL,
		0xAF25B8E13ADF6D59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE655A9F520F6992ULL,
		0x1C5E2D24E0DE6B07ULL,
		0xF3125B15F2D586B0ULL,
		0x649B9958A018FDDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F1A0FDF2EBC2719ULL,
		0x07EBE9706E4FBB7BULL,
		0x7F8B17CB4C9848C3ULL,
		0x73BF1D93DB5F2E7AULL,
		0xE60FA76C652FF747ULL,
		0x2DACE624525560E1ULL,
		0x8C4D062A95729E39ULL,
		0x1669C06C3C04B8D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x152F4353634F6286ULL,
		0x3B584DFF0D5F8AFAULL,
		0x21576D2F735EE560ULL,
		0x600985F852EECEC5ULL,
		0x6138A45075316318ULL,
		0x3039BFE016D52323ULL,
		0x8E12751B12B845AAULL,
		0xB2FABE800DF7FC1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01D542B16B36C010ULL,
		0x6BAB499235F95AC9ULL,
		0x1AE532E940E2889CULL,
		0x562FE0AA5E54640FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F8C8C9C22B1F970ULL,
		0x5914BFB3CEF5ACC5ULL,
		0x2A57FFC44E9FB6B8ULL,
		0x3F91BC9F935D0DF1ULL,
		0x0FD19C28B441B6C5ULL,
		0x793A772687C588DBULL,
		0xA5E6BD977DFD14AAULL,
		0x8310A718CDF3C4FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83F4ABA12487F1C3ULL,
		0x12BDA4321B04CDABULL,
		0x6A38D42E4C4C65D4ULL,
		0xB62F59679432524EULL,
		0x2773FA71F1588B03ULL,
		0x18AE7F5CABDE4613ULL,
		0xE1841F437E464D34ULL,
		0x238BE55A0A7FE269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x097DE21BECC6887AULL,
		0x9B1DE3785844C8C6ULL,
		0xE6C2AC0DF774EC76ULL,
		0x37172589025E5DDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E1203A768037C78ULL,
		0x40140A9696BE3489ULL,
		0xB117A87095AE1C18ULL,
		0xC4631EF07073FFB7ULL,
		0x1A1EDF93B7A7EC9CULL,
		0xC06FC5F825E29A29ULL,
		0x79A6D14E38A36D69ULL,
		0xD2EFFC64A365AD00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x746A734B1F15A452ULL,
		0x2E0CE4010ABDAA6DULL,
		0x0DCD15CC4864FCB3ULL,
		0x4FACDBE19C6A346DULL,
		0x0447721C37D58B2FULL,
		0x331C0A7ADEA6275AULL,
		0x6380223879D23A1EULL,
		0xDA20DF43D2230436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37A1D01942284E2EULL,
		0x0C74FB2E1EF994D9ULL,
		0xED088FDEA056BC9CULL,
		0x637495EDE3EED949ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2028DEE30BBD827DULL,
		0x5FACCE625D0D1353ULL,
		0x8E3DE1B22DA5580EULL,
		0xD682A68CD669695CULL,
		0x3CA6316BD028402DULL,
		0x5DB360051BFCE164ULL,
		0x36AFBF483F033A66ULL,
		0xA5795E7D3EEFA392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB94704260F9DCFULL,
		0xF746B62EE6E82633ULL,
		0x445BA98004CA228BULL,
		0x415ECBE643966096ULL,
		0x2D7E0BB77ECEA1C7ULL,
		0xC4595916AD3E86DFULL,
		0x7907880F83077D6AULL,
		0xE828B2F9418BF623ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x236530A2F8FB6669ULL,
		0x2BC31F97E6665CE0ULL,
		0x70DA6A9E103942DBULL,
		0x2F1D503E2F9EC736ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x837ED0F6F970AB47ULL,
		0x40C386E9C9042130ULL,
		0xBDB0697C20E2078AULL,
		0xB61C3980FC300BB8ULL,
		0x7A6139ED7685B83AULL,
		0x4547E7840604DA94ULL,
		0x78A0EA9A10F3F186ULL,
		0xAB75923D12F9A49AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59136EA6E3596C73ULL,
		0x9ECDB9A6A4DD5B06ULL,
		0x4123689E2F5F3B81ULL,
		0x7EEC5276A74D77F9ULL,
		0x15245DBA0AF2428BULL,
		0xB7B1CBDF3CE73901ULL,
		0xD8E7CE5DFB31E4A2ULL,
		0x90CB7352C22AB147ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x317411F20DFAB766ULL,
		0xA63DE7B8FE8CC20BULL,
		0x320731C92C50B5CFULL,
		0x2C707DD2539AB203ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9F6A25DA3BDD024ULL,
		0xD599602DEFDFB680ULL,
		0xC402C5EFA50F09F6ULL,
		0x8E7FB9AD45D7D486ULL,
		0x01485A1E10AFA612ULL,
		0xAFE1E6B03CE5CCE1ULL,
		0xDAA866FAF68DE905ULL,
		0xB4D56C47C39CCE6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB87B56C454534CULL,
		0x2F9F0E954651A0A7ULL,
		0xF1391751E864D63DULL,
		0xE16450E846678565ULL,
		0xAE9361E1303F87B7ULL,
		0x715B8A773674AFA7ULL,
		0x91F9B3CE415CBBE1ULL,
		0x5D6DE351827019DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF31B0010300E0035ULL,
		0xEDEC020F9E586C5BULL,
		0x9CB84740A1F6E71AULL,
		0x2679BD52AC131BF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3AE9403819DF492ULL,
		0xB3E5188273BCB321ULL,
		0x6F2517458585B223ULL,
		0x50AA888C10726832ULL,
		0xA6CB297C69D239C2ULL,
		0x27846A6021B24BD2ULL,
		0xDB77EE985B3E7094ULL,
		0x3138111D49041BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8AA883E10277E8DULL,
		0xFE00C02311EE776CULL,
		0x8BB2172410AC5099ULL,
		0xAC8F7D73351A6B36ULL,
		0x645DFD7903ECCDE4ULL,
		0x02F9D1D8A9731E9CULL,
		0x4E8C74BE3062E57AULL,
		0x2C8F38DF3BE2877EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7389446918478F9ULL,
		0x2276FC7B3B2EF1C2ULL,
		0xCE671683D170076BULL,
		0x552B244ECE53FC0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x703F516AC2FB04BDULL,
		0x1CFA47DB7923E3B5ULL,
		0xBD454DF19221AF92ULL,
		0x258072DD2A75B56FULL,
		0x64A6CD2D0718C3DFULL,
		0x421CDD1A09E49DECULL,
		0x0F3F0E25A07DC046ULL,
		0x0DCF7692412AC6F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603044E07C66403CULL,
		0x2E901138900BFC0CULL,
		0x40CD6280D83F576BULL,
		0xDC3971F7A63FBC65ULL,
		0x19E93311AD76F6E9ULL,
		0x64364178B15BE887ULL,
		0x942606A0A060BB13ULL,
		0x0713B626DA7A0A98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2833EC9994993105ULL,
		0xDEA550960D62D4B2ULL,
		0xC22F092EBE311DB3ULL,
		0x492590D6C271EE78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C8E8FB7D81F12C4ULL,
		0xF06C0258CBCA18BEULL,
		0xE0603F72972255E3ULL,
		0x4908799CD5D43187ULL,
		0xAFE6FC134C088016ULL,
		0x4D508F7692B42B2AULL,
		0x7526878B7FD59693ULL,
		0x2648DD9BB2AC621DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4624031684564FULL,
		0x4D3A09615E328C21ULL,
		0x035363178F5BBEAAULL,
		0x0B0499BA993975C1ULL,
		0x5A40B912F8F6CAFCULL,
		0x9580401FE7C68B7CULL,
		0x0F6489B16C2EBC8DULL,
		0x131C02B30F191207ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5F65DC1163B9EC3ULL,
		0xEC1DBFD4CCDD407DULL,
		0xF7D88AB9F28AF412ULL,
		0x16AC5E6A84789F19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF72C758A28B1CB34ULL,
		0x8CE10E24FC43F008ULL,
		0x8C151252D924B39BULL,
		0x7FE6CFE51D66F27CULL,
		0x6BAB1FB42083FB46ULL,
		0xC7DC69C2C4EB9CFEULL,
		0x85A6EE6886B35128ULL,
		0x13D70910C6284980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BACE251D174F6CULL,
		0x27F35D2E43A94127ULL,
		0x4EAAAE94CA32F9C6ULL,
		0xC30D1F50AA2B56AEULL,
		0xC09CFC7FF33BB388ULL,
		0x690945DFE001B396ULL,
		0x5F4BF8B0FB3BE9D7ULL,
		0xCAFFDB45F7B849F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x258AE123C4551DE7ULL,
		0x784504A4B3535445ULL,
		0xEEEADCFCC2AB0FE9ULL,
		0x0CCA7CAF17DB8AE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1288E26E6BEF0EFULL,
		0x0CF1520D7BB77E29ULL,
		0x8378AA04B2EC2E8EULL,
		0xB9024D4820B02A90ULL,
		0xE833AF8E3424EA20ULL,
		0x28B247780CC7CF0EULL,
		0x56B3A87754417253ULL,
		0x2C3F7D15D1DA5194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582FAEC0BA05F986ULL,
		0x298762D1A32607F1ULL,
		0x975D8908553F3946ULL,
		0xA33C8138CEFA8E15ULL,
		0x608DE65349367A01ULL,
		0x4AFAAA75053207F9ULL,
		0x637FCCE4C3D01E48ULL,
		0xDD909F8E31F17C5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B94BE250C1D9814ULL,
		0xCCAB3DAEF8CD036AULL,
		0x05CDB8BDCE7F6EE4ULL,
		0x43BAAE310E454315ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DB60DF46012CDB9ULL,
		0x2A1E9620106A70E0ULL,
		0xDC6549543C291103ULL,
		0x176ABE1C6FEB66EBULL,
		0x1885D2EE7651B484ULL,
		0x3FC3671322664766ULL,
		0x634346DFD89A2837ULL,
		0xD72413AAE4A8313CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90F26C017C45587FULL,
		0xE855DDDD8992EE0FULL,
		0xB06431A53708232BULL,
		0xB0BB9FFDB2CE6FB7ULL,
		0x7764CDFCFFD32E31ULL,
		0xB9076F8F3CF99A28ULL,
		0x4CFCC8FED07F9D11ULL,
		0x4CD232C29A2BA94EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7AA5DCA7A956871ULL,
		0x41AF75D694F939F6ULL,
		0x7A77C71639119569ULL,
		0x6ED68099CB99248BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8929111A91F9107DULL,
		0x51A6E6E0687FD063ULL,
		0xB6869912B95EC407ULL,
		0x4D16BB75F7EF6A5AULL,
		0x054DB4BD1D24FEE9ULL,
		0xD198EA355F858FFDULL,
		0xE70C56FB49D26336ULL,
		0xDF977A6FB8224C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x077730BE0FE1574FULL,
		0xCD2C6F2704A077C0ULL,
		0x0B6BC6D4F487FD78ULL,
		0x61FA75AAD5A2EE5CULL,
		0x78B9E1A65EF34189ULL,
		0xF8E12CBC0EF37E38ULL,
		0x7D81DB5E1080E26DULL,
		0xDC16D0E88918FA39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FA335BCBD79D56EULL,
		0xAFC097BB598DFBD0ULL,
		0x55A92B9446EFE45EULL,
		0x70356FDC1DAEADFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F15AD07F5008D70ULL,
		0x57A1DFF49C02C738ULL,
		0x927A685EB801FF98ULL,
		0x7B0E12A94605D9A0ULL,
		0x82E345CE566DA6CEULL,
		0x558EA518500226F6ULL,
		0xF09AE1F00A5669F8ULL,
		0x499C8A4A033645CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA340D576628E3109ULL,
		0xDB3569192332FE61ULL,
		0x054F6F36FDC1B384ULL,
		0xC9E957DDE18F96D8ULL,
		0xC4D8F53F1BD202A7ULL,
		0x376BF2FFD3DA2DBFULL,
		0xD20C6E3F5B391E1FULL,
		0x6018A4C8F165AD95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA15CCCD4458CB999ULL,
		0xF592E67DE6BEC6F6ULL,
		0x16502561B8998E4DULL,
		0x5AB8CBF4096CDAABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C6643FA3C595EB0ULL,
		0x679D13C94A02408CULL,
		0xA2372821E03B5F75ULL,
		0x7341B4D4699DA95FULL,
		0x14C646131C602239ULL,
		0x86BFD4843005834EULL,
		0x75865C867D9BB5DCULL,
		0xE620D4777571CEFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95972B0D20237FAEULL,
		0x693664D49DEB6A93ULL,
		0x9160EBDF5EE86016ULL,
		0x2344ECBCFD7E20F9ULL,
		0x0E0E09DEAF6FDB6EULL,
		0xA8972AA93B06DB39ULL,
		0x4C7C55A0A339EE4BULL,
		0x8DC04C6D05E2A8FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE62808B547E06312ULL,
		0xF86FE57509E3C917ULL,
		0x28534260EBD69EDFULL,
		0x6E50F9A3FB5F2C92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA47E36D06D1293CFULL,
		0x1C20C7B80F6F6594ULL,
		0x3CC037EF9BB1AB13ULL,
		0xDA88E6E9000DFD1FULL,
		0x98A443B4098FF1E2ULL,
		0x7AC06364826DCDAAULL,
		0x829E2200D3DC916CULL,
		0x2E4508E0F24E6987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25702E3C40801861ULL,
		0x77751E22E44E48EFULL,
		0x69A2645B1DA69DACULL,
		0x2BC026B753DFA810ULL,
		0x76283294FCBA7424ULL,
		0xD643DD3DCA4ED3BEULL,
		0x82C089E342B617A8ULL,
		0x6B0410B70D8A1AADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D7893301443245FULL,
		0x0F2793547FBA35B2ULL,
		0xCE0267F809C12071ULL,
		0x2A6D9669A152096AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD887B1E5C84A5428ULL,
		0x1AD79EF847AB26F4ULL,
		0x810E4670E4720B81ULL,
		0x6AB5FE6C426D3AEDULL,
		0xD677FB10B53ADA93ULL,
		0x81CD827E13C7194EULL,
		0xBF21D2AD58FC9CAFULL,
		0x5750959DC65C4AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC198730F5E54F87ULL,
		0xD478D0E120887337ULL,
		0xFFAF8B7F86C3A9FCULL,
		0xA4598C215CA4C4E0ULL,
		0xABE12602D98BF206ULL,
		0xB7826D0C5EB8B837ULL,
		0x51146AA08244EA54ULL,
		0x8DAAB676AD971A47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ED1CAC36E5B884CULL,
		0x4D83FCF807451D2DULL,
		0xD75C2CD93CF2DAFEULL,
		0x34FB9218930DB088ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68306610E2357838ULL,
		0xE43A38C7F6D651B6ULL,
		0x0BD0FB19B967740DULL,
		0x7ED7E710E9B30DFAULL,
		0xCDA822878C565AB2ULL,
		0x660E492495B24CB8ULL,
		0x541B6C98C598408FULL,
		0x5A2E8E77128D07A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7D949541C38D585ULL,
		0x33870A9A3E4F977FULL,
		0x3754C6B98F306D7CULL,
		0xEAFB5664B7F87E80ULL,
		0xEB6194A3D995ECBCULL,
		0x97DB32D0B8871756ULL,
		0x32647A43468B3F21ULL,
		0xA431E37A8ADFE4F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06D02C894E8CF382ULL,
		0x4C487EA08CF0A6BEULL,
		0xD5A42D1106253CDEULL,
		0x175DF228556DB4E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAA540BDCA1785B4ULL,
		0x23DA07C42864E693ULL,
		0xBAAF02AB4B64AC37ULL,
		0xF371FBF5A6AE52F9ULL,
		0xDF76140656A7D1D4ULL,
		0xE155450FC36A9398ULL,
		0x659A2250B7ACDBCBULL,
		0x5B08737A35F50A67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC4800F3AF30E3C2ULL,
		0x1C7679657CE5B852ULL,
		0x3BCFF1CD93750BBFULL,
		0x074A56F98AAF929AULL,
		0x69FBF083B30B0251ULL,
		0x2D546D50F4760879ULL,
		0xF7F4E671E0C707F3ULL,
		0xF438FF30F08257C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E7E852E642D6C20ULL,
		0xBF8394B163CBD4ECULL,
		0xC565F3F19E0D12A2ULL,
		0x2EF2E7DC6B0543E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FDF3BC16CA52F23ULL,
		0x7E26B13D5E9F3CADULL,
		0xAB4D02129202A944ULL,
		0xA3657E1D9A64A585ULL,
		0x64819F334BFAC0F2ULL,
		0xB2925733ED695F68ULL,
		0xB6037DEBCFEBF0A9ULL,
		0xC4FB7BA7222A574DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB9DB8FA8E1F64F3ULL,
		0x3C01FA4C7C37530BULL,
		0xAEACD8557828833DULL,
		0xE734DADB5E7E964DULL,
		0x810A8905D938F1BEULL,
		0x9B6E815544477BA2ULL,
		0x5A7291BDC48B3076ULL,
		0x1937BD2349989F99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47EECD85E74A8F9EULL,
		0xB17675FDFD6FB901ULL,
		0x94233892CA36AD9CULL,
		0x3B3EEAD4618753FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA346F64638A7BD0ULL,
		0x74789C3564BAB717ULL,
		0x78828EA7C5F5A4CBULL,
		0x6919B4BDDBF34E9DULL,
		0x821A5E6C561ED781ULL,
		0x2D20D99F2ADC73E3ULL,
		0x488D73EFC0177BFCULL,
		0x849412EF6389394FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6AD0615C23F0A1ULL,
		0xD7A37E4495419406ULL,
		0x56D73E0B13CF77BDULL,
		0x4AEE06E5D91E19A7ULL,
		0x190F34ED142704CBULL,
		0xCD0BE7BBFB71E286ULL,
		0x75646A585AFAA140ULL,
		0x8DB0EF4C37691158ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6671C7E6D22FD1FAULL,
		0xDFF105A9D94AB6EFULL,
		0x79C2BD15B46EA4DDULL,
		0x43E2F8108F9B2399ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD0256F0E8D17026ULL,
		0xF5919328314B6592ULL,
		0x32C3359D487001AFULL,
		0xEAAA733B80BC7C3EULL,
		0xD2465D92B68848D1ULL,
		0x4C6DC3614BD9FB89ULL,
		0xA2F76A09CB4C2AE0ULL,
		0x5C06128739F4618AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99EFB4CF075D64E1ULL,
		0xCE2A245568DB2B09ULL,
		0xE49D1892F63E09F4ULL,
		0x42012F9F972261ECULL,
		0x5333368294471655ULL,
		0xFD21DB54CA3CA19AULL,
		0xBA2FB896C0363403ULL,
		0xD7FE67711C3FF62CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFEA6E86F7218701ULL,
		0xECABE0AE05CB9415ULL,
		0xDBCA741DF7749C6EULL,
		0x41CCA8E452620A41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6EE78D88950B2CAULL,
		0x68FD1828F08C447FULL,
		0x3D8F1D575C625B01ULL,
		0x8A0F5891521B65FAULL,
		0x30BAE58B1062E401ULL,
		0x98310A71512BCA1FULL,
		0x8A16AF22395A42A7ULL,
		0xBDC9BB690D158FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C4C56D199277F7ULL,
		0x118C09185A1EEC3BULL,
		0xEC8600778ADC1CC0ULL,
		0xD56C6904BD9D2C0EULL,
		0x98EA78998BAC8630ULL,
		0x615575458E06197BULL,
		0xB21CE6B73EBFE100ULL,
		0x1D18DB652AB73151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0619DF4522D02B56ULL,
		0x7C09338F8E05908DULL,
		0x601CDCC10470BD13ULL,
		0x0EE430202E80476DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AD440FE7659CD19ULL,
		0xDF1CD928F9682C13ULL,
		0xCB33D4624BEAB9BCULL,
		0x8FBA53498AE69B6CULL,
		0x686402A75F094985ULL,
		0xAFDCEF76478B4123ULL,
		0xDB353D5B241D1D2DULL,
		0x9138809350003BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735DC708B43E803EULL,
		0x7AFDD2518022AA24ULL,
		0xBA32B78A74DD8209ULL,
		0xC3C52EB0B0B03759ULL,
		0x2B89D1E1768247CEULL,
		0xEA3668B4ADF8B52AULL,
		0xF57A9E9CE76AB6B0ULL,
		0xDF468B4F9CBD56FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFD9B75646258C3DULL,
		0xBAD70794450648EDULL,
		0x2AB4AD14D9886E38ULL,
		0x35DF8CA576246281ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2F588C7BC7FD50BULL,
		0xD8C02E67EA649086ULL,
		0xA222E31E094EF7A4ULL,
		0x7CD348BB64776F72ULL,
		0x17DB7035F5AB2177ULL,
		0x17225D9183FCD2CAULL,
		0x0B2E7AB9E168CC85ULL,
		0xEF8373E5BA6458C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5025472D3D7DA32ULL,
		0x11124BD537359A1DULL,
		0xDFE7C46510011315ULL,
		0xB3444A742456CEF7ULL,
		0x9786E373FFE3C8B2ULL,
		0x9B05EA829131FE32ULL,
		0xAACDB88B1C21955BULL,
		0x66AD32441E7239CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA80191F643F2B0FULL,
		0x33E6F6CABD4A84E5ULL,
		0x1097F1AA41E014B8ULL,
		0x195CBC44661139F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x178B77F43DAC4DADULL,
		0xB416E5261C3A1341ULL,
		0x05C21A841E6E85C0ULL,
		0xA0E53F0B4B5E25FDULL,
		0x9F6FD45D3465B57BULL,
		0x22C921DDD9641220ULL,
		0x7510F227779699E6ULL,
		0xFA773F87BD047DD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF701EA12A4A8E99ULL,
		0x829A718954A6D66CULL,
		0xBE0FB77F1EE19F1FULL,
		0x8B6171E1A3F03157ULL,
		0x41043966E35B760FULL,
		0xF4C7C106BDB009C7ULL,
		0x2BCF42613074EECBULL,
		0xE6779A1D9A963AC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C1459E31AE7298EULL,
		0x05B0D38AE44C7A18ULL,
		0x27727A738E8C4C84ULL,
		0x0D765AEAC3CBE8C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3B8034DEB0CB545ULL,
		0x1F00E05A18F5265BULL,
		0x128E009103219753ULL,
		0xCC0468C377FD0C63ULL,
		0xCC651A65238D1EDCULL,
		0xF039C23332FF3E01ULL,
		0xABD4BECD415515C1ULL,
		0x324675036AF7509DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BB399E329F833EULL,
		0x9FF634CD28A0ACCAULL,
		0xF1C40647CE1F20CAULL,
		0x501F19357A614E03ULL,
		0x7E8394F80F4E9B2FULL,
		0x32B7DE78D9BA23BFULL,
		0x214605FE7F6F48E9ULL,
		0xE0ACAAE454A6855EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x207697E0B9B4B9ECULL,
		0xA052793630965F69ULL,
		0xB1F968F9FD1EDEB4ULL,
		0x18B9502B4D99E9CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF19FCD264999C5ULL,
		0x3A0C84031E4894B2ULL,
		0x73EAD5FF69B92F57ULL,
		0xDF5674F0D5500B43ULL,
		0x655D4257832E5239ULL,
		0x755EF6144585AEE0ULL,
		0x5E2A715D32A92BD4ULL,
		0xBBF8E7A660EEBCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0EF11B057C0CE3FULL,
		0xB0E50E0C9667ECFBULL,
		0x32DF83182E855366ULL,
		0xD3E64B3D57401E13ULL,
		0x9AB89A04FDE407B2ULL,
		0x15AE999AB9247C86ULL,
		0x2440DF91F94E711CULL,
		0x834E12139B07B87CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF738A5C978FDCC0ULL,
		0xBD5530015E4E210AULL,
		0xD9B6F711BEAB934EULL,
		0x74CBDD7CDE5A9248ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1264C9C4770121E8ULL,
		0x97D3FC58E9F6D28AULL,
		0xD8AEB7EC76CC506BULL,
		0x99048A9B1B6D99EAULL,
		0x8741F08ECC26E82CULL,
		0x85D1A30D6BB0C94BULL,
		0xB4751CC20EDE3780ULL,
		0xEC2087B7CEEEFDFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6563D523476B470EULL,
		0x2A048C972471DF14ULL,
		0x8BC1001D84278B9FULL,
		0xD68EA1EBCFFB9C66ULL,
		0xA85B1C99B88DD8B9ULL,
		0xE72846859F77CCD1ULL,
		0x8BED582261423DDEULL,
		0x1D378F17DE610C36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3446B02184E2A60ULL,
		0xFAF32BEA15FA6D8CULL,
		0x5114E782B7CBD2C9ULL,
		0x790AD06D0083E0C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14DA0DB3A5857B50ULL,
		0x2A2C7A795CE3DB5FULL,
		0x44950B2267CB92C7ULL,
		0xF08B3351CF8237B7ULL,
		0xD544E4667E68AACBULL,
		0x24C4B3AD222B4D5FULL,
		0xF5E2DC23BEED692FULL,
		0x8A288F9274176C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF0DB6F523E0A57ULL,
		0x57F14835D9BD66ACULL,
		0x6DE408D26EB96C16ULL,
		0xD479C5F4B49551DAULL,
		0xC08E2DDC14D84168ULL,
		0x41C477CBC03DCAB3ULL,
		0x960B5509BDEA2EBDULL,
		0x6A43AB356D96C9F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18084ACFFEB71656ULL,
		0x844415B80C67DA3EULL,
		0x10AF102C1F8CD398ULL,
		0x580B532C1204FE63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x683DAF26B156FF89ULL,
		0x575C731CC17D7424ULL,
		0x70DF186BD43DA0EBULL,
		0xC07D6B3602523209ULL,
		0x1CDAB0F995D4F5AAULL,
		0x4841A340AE051783ULL,
		0x2DBD3F749937F82EULL,
		0xB3811F54D3469CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D13B7438D7C3E6ULL,
		0x6A3818FB286B3C1DULL,
		0xA6C6AC1CE0F3B8CCULL,
		0xB0D323826A0C2F47ULL,
		0x987C4755B8294CABULL,
		0x19597770CBDE8007ULL,
		0xA474638BE67CB912ULL,
		0x098EA2773C63A399ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC47022055FFA5533ULL,
		0xE39ADAFD2ACCB45CULL,
		0x2AE910D97B15464DULL,
		0x49A8D097FDF6FA78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6961E8547136E11ULL,
		0x094E223A5B6429A3ULL,
		0xAE05345573670E34ULL,
		0x2699F0BA325199EAULL,
		0xF6F91193D8B9BCEAULL,
		0xE277B187F22E6F2AULL,
		0xB57A69890DBF4B0CULL,
		0x35C4436F51BE214DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1ECBE1B29BEBFB5ULL,
		0x0BCE8D1C49C02371ULL,
		0x01EDA172618D23C8ULL,
		0x36910E6101A8C2AAULL,
		0xF424E6ACFB186E2DULL,
		0xC34D7AF140EE2D77ULL,
		0xA43F2F4C61817027ULL,
		0x373BED4F11240E4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7027BEAF03465E57ULL,
		0x9DC3AF7C612DC6C4ULL,
		0x3AE237E4A308686EULL,
		0x3845AB22C787A8F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x279DE18C9CAE5562ULL,
		0x63DC5B14E1BFF1FFULL,
		0xFBC3DF6CEB507E0CULL,
		0x339A08E78BD37C74ULL,
		0xCD130EE5D194B055ULL,
		0xD39B1BAB1AACB9DBULL,
		0x018F75E5F0D2202DULL,
		0x433AC0D5EE53384DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AB1342626C80130ULL,
		0xA9D9F7F87D072B1CULL,
		0xA58E26769378C68AULL,
		0x42E224F58840B8C3ULL,
		0x6793F1FD613CBAC1ULL,
		0xBB64F9BF9FC5C57CULL,
		0x337DBC7E928E16EFULL,
		0x38C190B313329DADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDCAF7E722F4C850ULL,
		0x520B6C10A3010D0BULL,
		0xECD73E4E55F116B9ULL,
		0x7EB5091E8A69B769ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC29E5EDD39B384E4ULL,
		0x2264A92C27C2709AULL,
		0xC96B1CE8EF0B575AULL,
		0x941C8475FD12F684ULL,
		0xD8158E34B7CA6B84ULL,
		0x6DA84834068D19FAULL,
		0xA454A24DE44C1031ULL,
		0xED10FF83D466A4C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C67453F8D1D81CEULL,
		0x8BD9B75BFE541FD9ULL,
		0x744A2E6C7B864BCEULL,
		0x3A3F6712BF7DE9EDULL,
		0x0F18E53AA2E0AED6ULL,
		0xAB554BF4133F4EE1ULL,
		0xADCC4BF86FB9E985ULL,
		0x7D004F685B6F3A78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBB82EBCC748075DULL,
		0x6EDC634E46FA7694ULL,
		0xED5DBF2BC136C90AULL,
		0x7C574177324ED3B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E976799E906076ULL,
		0xF21CFE062716754FULL,
		0x7C9B3F1C9212B7B6ULL,
		0x590C0329E98FFB95ULL,
		0xDCC8CA90BD7AD635ULL,
		0x54AB85DA653B2E64ULL,
		0x10395A87EF899B34ULL,
		0x6A75AC2FA726450DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21982E6EE5F6018DULL,
		0x58C8838B0B735295ULL,
		0x57C1B2554AE83E9EULL,
		0x87D2C0B3FE5E900EULL,
		0xC6CF75E114B0FD0DULL,
		0x46D9EA39A536C82AULL,
		0x5909FE4E0E16B7BCULL,
		0xD01C4F28BB904FEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8453DA1DC690988CULL,
		0xA67194579C4A4F59ULL,
		0x55E13D5EBE383CEAULL,
		0x3A7D117CE373CE3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9985FD227E6757E1ULL,
		0x9DC692326E0E2035ULL,
		0xC2DA1FF23D73D1D8ULL,
		0x00DCFDA3EDFF1079ULL,
		0x96EBA35DF16A3ADBULL,
		0x3673613228B65BE1ULL,
		0xEB0161098BC8068CULL,
		0x9BB0F80F02834F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F621F2DF3061B8ULL,
		0xC660AE0B846FB58BULL,
		0x57004B7384BF27C4ULL,
		0x7D279B711E4663A7ULL,
		0xE5F755FAB169E8B1ULL,
		0x2A72480708596618ULL,
		0x9F0AA8F906E8B0C7ULL,
		0xCDDD920615B00A47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16D357EB1F432735ULL,
		0x9F8FA08DB76AE674ULL,
		0xB27926F271DB6553ULL,
		0x11168785F714E6B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31226F2CC6194F8DULL,
		0x7E479886FEC14D9CULL,
		0x18A1F3EB8A0F0005ULL,
		0xD7BF45E8067DCE36ULL,
		0x6647DB03A3845D52ULL,
		0x6351D9A7DE74F4D1ULL,
		0x9D20B28C47623394ULL,
		0xCECAD83C81B4957FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D29AD8B677216C0ULL,
		0x061AA7740395FD59ULL,
		0xEB0E41023E03F2A5ULL,
		0x146907B1B00984D9ULL,
		0xD9EB0B6FB4116F19ULL,
		0x112C20A1608FC95AULL,
		0x6E7320A08464E5A9ULL,
		0xB6AE45E9F1442A95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89BF9196E9B695DBULL,
		0xA9C66809AB2FC3DBULL,
		0x1B575BE83DA49E4EULL,
		0x5793F677C724281FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03B5F24FB38FCEB9ULL,
		0xB7E0F57C05CBDA63ULL,
		0x4D4BF65F1CA48EB6ULL,
		0x0B7EBB5E4850237BULL,
		0x78CECDD5EF860109ULL,
		0x97E4B7EE43C65C82ULL,
		0xA18BC6875584AD43ULL,
		0xAD1797B73DB193CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A903D251F29C6DULL,
		0x26A977C711A27CC5ULL,
		0xB775A7BA209B626FULL,
		0x6D9A91A170A8958BULL,
		0x87C6C05D110E118AULL,
		0xFCC72E80652FFCD0ULL,
		0xD9FF96CB3DE1EB60ULL,
		0x5F002783A566D3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A3EEE6E676AC0C8ULL,
		0x9799E403FE7B9207ULL,
		0x34A564907E31F3EAULL,
		0x355ED16572C009BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4693AEE7972137AULL,
		0x38E3BEDC002B8322ULL,
		0xAD18352DB286B19EULL,
		0x0D9B574BED2B5876ULL,
		0x037403588C67D4F3ULL,
		0x30BFBCC3793AF510ULL,
		0x68CD04660097F587ULL,
		0xB1A5FE8F0F1EE642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA40E870852DF58ULL,
		0x592C9473564821D6ULL,
		0xC840D2D656601FD8ULL,
		0x7F5E9933815D35DAULL,
		0x03DFA9E70F4E905AULL,
		0xB001E9823CB8A1A9ULL,
		0xC69FA7810C729D05ULL,
		0x1D1391B9758EF64DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4CA734002DF6609ULL,
		0xFBE48617A53BC295ULL,
		0xF7932C5399B1B4FEULL,
		0x1BF8E5CD372BC0EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x417B689280C6C63CULL,
		0x81C571631E0A4CA5ULL,
		0xA754D42CAA1113D9ULL,
		0x9357AABC2F337C24ULL,
		0x7106FB589CB5E3D2ULL,
		0xDF5C664D54F4237BULL,
		0xFEB04EAA569A03D7ULL,
		0xBFCB4EF240746E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B85D2B58A5111BULL,
		0x6367B7004C76EB53ULL,
		0xEBE35F9C44317605ULL,
		0x6B869836B184EF1BULL,
		0xFF31CCB56269107AULL,
		0x161E8BFC9C276FEFULL,
		0xD7200ED35F6BEB6CULL,
		0xD70FBC1B31C96738ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9067F7A1CF8913ACULL,
		0xFD8C225E3FF60804ULL,
		0x9ADAEE7916B73DD3ULL,
		0x33A8DE71AB119592ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5360D5DB158B0717ULL,
		0x2A12BD62F5B36F39ULL,
		0x3FF71967BE956CC9ULL,
		0xE27F712FE3415383ULL,
		0xC8DC015A618A534EULL,
		0xBB624ED1BB05798FULL,
		0xA2DC4B660DA7E098ULL,
		0x977AAD7502D5E8B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81FEA00C557BCEDEULL,
		0x31D63EAC2964DDF1ULL,
		0x2C0C2107C70A737BULL,
		0xAC11E51B25A52905ULL,
		0x06619B9CCF3C81B9ULL,
		0xA98F599DEEEA73D3ULL,
		0x7BBA3EFBCFCE5955ULL,
		0x79D5C64C8E38F4A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF8D4FF2779C5502ULL,
		0x9D8CE46718516B4CULL,
		0xE2F8D02525D50D42ULL,
		0x1CE7DC160CE86471ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16D7DC49A0A6ACF8ULL,
		0xDFC4839725F80779ULL,
		0x7E1E481FAB8299B9ULL,
		0x552F9B923F4B371CULL,
		0x51332C39D4CB95AFULL,
		0x19A8FC8678A9FC4EULL,
		0x2E5379A63DFDC9DAULL,
		0x2A74C784EBBDA2D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2E8AC192D13DEF5ULL,
		0x77D6F2008B5630ACULL,
		0x97E3900F3ADAACA4ULL,
		0xCD7D4B37BD8ED61AULL,
		0x096477AAD8987958ULL,
		0x53A3D6F18FD569CCULL,
		0x32A207930F989DEEULL,
		0xEE2BF3BA8F413692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC9DFD69E328FE79ULL,
		0xCCB125B12A2F9622ULL,
		0x4291A6E953AC7214ULL,
		0x7A81C0643C347365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B1027932F411A1BULL,
		0x51C1ABBA378C0CB1ULL,
		0xE2472F9A35964B44ULL,
		0x6CE1831146A86A4FULL,
		0xBD0225BBDD553F80ULL,
		0x5D793A019E602884ULL,
		0xCA5283A6E7440367ULL,
		0x5B2A0E7AAB95009AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67276F26C8237224ULL,
		0x492E401C8BFA47E3ULL,
		0x259B945C52310B5DULL,
		0x727884960B4CACD3ULL,
		0x3533D15A1EDAAD93ULL,
		0x612F5E35C34603A0ULL,
		0xAEE9D043FA1AB24AULL,
		0x7641963537EB084FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C893EEEAD4F507AULL,
		0x7B8A0BE031733EBAULL,
		0xCE363BED17874A34ULL,
		0x74EAD8CA669698A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED95AD11DDF30068ULL,
		0x8D18DF52D3779F12ULL,
		0x098E00B5314FB77DULL,
		0xD702F6B8BF28C2F4ULL,
		0x4FAE8668BC075783ULL,
		0x68DB70B00EBFA3BDULL,
		0x371F2321FE22DC7BULL,
		0x17EADFBCFFB25019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556605CD6AA9949AULL,
		0x2C97F64BC1623774ULL,
		0xF56742128BF79077ULL,
		0xC24966F9351594F9ULL,
		0xF8D2C2B5AE8C6F0AULL,
		0x6D67E3A2077E1B18ULL,
		0x077F2B40723DD46AULL,
		0xB95C0C44B76E8C73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CCEB3D87387EA34ULL,
		0xB3A7D91C25CFB003ULL,
		0x25E58A1D6957598BULL,
		0x1DECF39A442238A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D5D77329BB3B280ULL,
		0x650DC09A2306D642ULL,
		0x2820CA6890C34A5CULL,
		0x3A32F97FCFEC0424ULL,
		0x64200D917FD36879ULL,
		0x137D16971E9E68C7ULL,
		0x1D3041944313D377ULL,
		0x7EA462216F4E90BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00E2723430935E4AULL,
		0x4631EC7021FEF85CULL,
		0x705AE2E773689291ULL,
		0x2EC3A5487F0873FFULL,
		0xC80695DC05031364ULL,
		0x55A2B729F6328F75ULL,
		0x045F3D0E0A24EC54ULL,
		0xFB34B81049A7129CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5842C9EEA60CF295ULL,
		0x4D45FE5E010A2003ULL,
		0x66CC936D90D106F3ULL,
		0x0E0292C2E7C0489CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08033D18935AE99CULL,
		0x7749D567571BB19BULL,
		0xB5B1EA5136F9FB34ULL,
		0x5F9539F6DA5743ADULL,
		0x6893628D67C97ACAULL,
		0x0710B2C54388425DULL,
		0xC76518F8BCEA793FULL,
		0x8742F2312E140AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB2A2D37B715398ULL,
		0x7C8E4D626BFE0A1DULL,
		0x4F83CA6A212733BEULL,
		0x7D64668F1144DB08ULL,
		0x10D7A5671F752EA5ULL,
		0x48D966751B6D5261ULL,
		0x4B591141BA8E14E6ULL,
		0x5A2CDE572F5B4354ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F2EADF3D46CE479ULL,
		0x36F0DBEADF1D46F2ULL,
		0xCFF745116F89ACA2ULL,
		0x1377C5C3987FFF55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D1956D032D39743ULL,
		0xB5C7E6D39FF321D0ULL,
		0x08D130D7A3DE40A0ULL,
		0xDABEABC575935326ULL,
		0x794A37124C24AA15ULL,
		0xB841D8BF079173A7ULL,
		0xCBCDA407C24E989DULL,
		0x5BC3FD6A734315EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E7BB13917CE381ULL,
		0x3BFA2A5970DF1877ULL,
		0xC51E268BF6719592ULL,
		0xFAD5890CEF45DCDAULL,
		0xD7DBBC45BD57A7B1ULL,
		0xDC70F1C34D5441AAULL,
		0x9206F29990D9F1E4ULL,
		0x4AD0D225A3D49622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB97D619D3C50EE6ULL,
		0x1AD005D7D42974D8ULL,
		0xD73160A704BD6A7FULL,
		0x64018EEF50B46E75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1408D2792B28369DULL,
		0xB62D471456682018ULL,
		0x77711AA82FCC44E7ULL,
		0xC7057E08CBD51EB8ULL,
		0x31AA5F9E28F96A71ULL,
		0x0C71CB1E0AB9CC6FULL,
		0x5B9E56FEF67BB0BAULL,
		0x84BA8182BB7D67B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66F99802FA569BE3ULL,
		0xEDA4674C928FFC97ULL,
		0xEE739AA59260B5C8ULL,
		0xD5BA7305EA026AB4ULL,
		0x30240C76B84E6C71ULL,
		0xD58EB0CEB7C51E92ULL,
		0x032F3F8206A983C8ULL,
		0xB2D6D8793B4FFBFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6FF9250EA334DB0ULL,
		0xEE3EC78E1429F24EULL,
		0xA97AFC8E369E3AECULL,
		0x1916226BE890B1D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5AFD00DBB7A017FULL,
		0xFC624B02EFB2A55EULL,
		0x540C7D81EA89BE21ULL,
		0x87179818382BE048ULL,
		0x9D43AB181D4D1F05ULL,
		0x499BC1BCD6F0F502ULL,
		0xC575F227C3F3A1A5ULL,
		0xC2A4A61D264AF69AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0B0AEA1279D7ED7ULL,
		0x13DEACD500911C8DULL,
		0x1CDDF7EC52F128DCULL,
		0x37D2810E20451C9DULL,
		0x842E2FD81E2CB727ULL,
		0x16CBCC86EC9FEE48ULL,
		0xFDC968E694715482ULL,
		0xF9399B2A840624DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE2F6CEC72ABEC6CULL,
		0x7362042EB7288870ULL,
		0xDACAE542A4F0087FULL,
		0x3528B70E2E1DE5B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAEF8758A0044BB3ULL,
		0x8BA631B7FBE9086EULL,
		0x902653ADB71588CEULL,
		0xCC3097CB68BD6510ULL,
		0xEFB19057C170A121ULL,
		0x17D6894AF06FFB6FULL,
		0xEC36581FFBF78C83ULL,
		0x876A07827E4E7617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x056FB5D9AEE3FD17ULL,
		0x67B33F7BD863D844ULL,
		0xBDE98320395A3ADEULL,
		0x7E19A8B1B0856EEBULL,
		0xEC9BDEEE34A84F7EULL,
		0x0EA37E7CDCEBF6D3ULL,
		0x7E4A65D9532EA359ULL,
		0xD8AF08CEFC4D58FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AB82729D6DC6B06ULL,
		0x81868CD3091DDF53ULL,
		0x2342C70A8B8DEA2DULL,
		0x3DD8BDBF046247EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB0781B7F30B13BBULL,
		0x2516C229B3DF4E61ULL,
		0xE9DF2F1366E05113ULL,
		0x21630A66CE11F082ULL,
		0xDB53BE92997F91E5ULL,
		0x37A7E124CF68D4F8ULL,
		0x1D0C7151356C4D5AULL,
		0x0283DCB061B927E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA14604990449A52DULL,
		0x6524D20687D5D3C7ULL,
		0xD9B87334FE5BD5E8ULL,
		0x7CB859C6BB73BF75ULL,
		0x6BB2E2C0E89F2F73ULL,
		0x3491D57CC094E643ULL,
		0x006948CCC0052E62ULL,
		0xEEA1086970DAC642ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBA21E3F30100635ULL,
		0x3537AB155F7EE988ULL,
		0x505EBF87D5D313FBULL,
		0x18563327D3A0AED1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE996E30DBFA35A47ULL,
		0x2E809F90D5700978ULL,
		0xD7456F7B139BC847ULL,
		0x66374754026C09E0ULL,
		0x1A187EFF4CBE2294ULL,
		0x9A50D4FADFC66D93ULL,
		0x6CD0A59E877053EDULL,
		0x635B07480278E2D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF1724649F9CADCAULL,
		0x1E1F43850CADD2DBULL,
		0x4922B862C286D763ULL,
		0xDE86F7F267F31309ULL,
		0xACEF91F7D5EEC853ULL,
		0xD36BD9FB219D4079ULL,
		0x5428A716DFBF9E38ULL,
		0x64A5067C994C1D96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E92EDC4C2CE11FDULL,
		0x965E9E0202DEE863ULL,
		0x37127F3B354FE9B9ULL,
		0x56B46D93371E3E5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x492E6899697D9183ULL,
		0x644C653A610CC490ULL,
		0x1E75FA69BE5B7244ULL,
		0x66A14AAC45A1F2BBULL,
		0x333B5CB99CD63044ULL,
		0xEE07509F55C9DC1BULL,
		0x67A37FA740B26DDCULL,
		0x70A1AF69D8324A8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2772508B6BF50FULL,
		0xC052EF1C41E20B4AULL,
		0xBCF52B3FFF66E836ULL,
		0x8A80F2A511EC5A03ULL,
		0xDD1C507269BF33BDULL,
		0x5119612FB0E529C0ULL,
		0x998A4EB57DD3AF8AULL,
		0xA200C3C172081B62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4A2C8DA737B1761ULL,
		0xEF4B00B0991D32AEULL,
		0xF93E130CAC04CA50ULL,
		0x080353065DF898EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAE7B254F02C5246ULL,
		0xC14E3DBA46568F96ULL,
		0x7DA62395BC66EBF9ULL,
		0x9358C37FBBF8C19BULL,
		0x1748324E36C7A465ULL,
		0x1207A921601C5DBDULL,
		0xE2C4D463CF4BFF5EULL,
		0x5DFD3D51D3D1E24FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB222D30A9C31B25ULL,
		0xBA99EC61E1DDB2EDULL,
		0xD1427822F26E0AECULL,
		0xF0B1451EF93C48DDULL,
		0xF6180998EAA7EE7DULL,
		0x2459B150F283AA28ULL,
		0x5E6C4206E162CBA6ULL,
		0xDE031763A6161883ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCEB900D931E34ACULL,
		0x4E871A48A92384A5ULL,
		0x5189653E1A968E5AULL,
		0x21C91FBB8C9C6D19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9E51CCA4DCAD66EULL,
		0x975F0692792F0D0FULL,
		0xC4C1173E6B7E827FULL,
		0x38BE156B51257FB5ULL,
		0x5438E579675D7D43ULL,
		0x1FD9C4AC983AD5C0ULL,
		0x14E64E7579826DDBULL,
		0xC0D6052D9F3CBB9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348D34112D3ED637ULL,
		0x89FB9C03F9A1B4A5ULL,
		0xDEBB3B993017CB1BULL,
		0x12EA43A32D5A99F0ULL,
		0x6E67C7025358BA15ULL,
		0x9470BD886AF71648ULL,
		0xACE92A1555093DD0ULL,
		0xF32C88936B933DB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2626E661940F7EEULL,
		0xBEFA79ED379BC436ULL,
		0x559941EAA563D8F4ULL,
		0x2CFC50ABCEF39644ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AEC15DBBE8D290DULL,
		0xE5C58D65F4A8C2EFULL,
		0x13DB709637CE1245ULL,
		0x91FA8F01825D9A91ULL,
		0xCDC1BBFCFE0CE082ULL,
		0x2F0C366B7F4D56CAULL,
		0x7A7AB1757038BB1BULL,
		0xF8B530B11C417832ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAA4B0FEAF758015ULL,
		0x03FC12458E721363ULL,
		0x32B5BF905EB82F02ULL,
		0x284740681B57E27DULL,
		0x99D9D71578322B1EULL,
		0x52837163AE163B06ULL,
		0x0121CB2E4A30F2F4ULL,
		0x954F164375F21546ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44B35F3AED8E980AULL,
		0x9E16BA497464CEABULL,
		0xE457DF957E3D9908ULL,
		0x2ADB3AE016CE672DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AC39CB2975DBB63ULL,
		0xC6A6C5C9D6772A49ULL,
		0x4D34303D054D1459ULL,
		0x808FD42F3A65411BULL,
		0x1EC1393ABDD37653ULL,
		0x1646DAB4AA4171EBULL,
		0xC3FCCDE9620F63A6ULL,
		0xB6C47A62E0CC4564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25923C619E334006ULL,
		0xAD6129B17506A312ULL,
		0x4D1A9C6D8C6B045EULL,
		0x1B2317340E8E39B4ULL,
		0xA73FA4B5BA4792B8ULL,
		0xE89FF9AB649EC2DBULL,
		0x176122E0835AFE65ULL,
		0x16F6072E4EF68C90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC26D6C0F7FEE47EFULL,
		0xE00B0378B7968382ULL,
		0x9F34F72087A91781ULL,
		0x1E11D6C8D19076F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46B0961E1C2894BDULL,
		0x71CCB66E5DF0AFEFULL,
		0x0416BA4A005996DAULL,
		0x56C707BEF68F7725ULL,
		0x9052511F54B5199FULL,
		0xF62CA97446330263ULL,
		0x070D9778BC395A12ULL,
		0xFE16309760E0095DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x800496190D058BA9ULL,
		0x7AFD99DF1A6B3BF8ULL,
		0x8AD52C197998055BULL,
		0x8CA04A234AFF8FEFULL,
		0x0D8E67AC03BCD07EULL,
		0x3F835DACC8E140EFULL,
		0xAC82CEC4FF5CA8D8ULL,
		0x2A972B605F95CA07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FC0A72313FDE894ULL,
		0x13F05C2BDDA82B42ULL,
		0xE9DB58DE8F83E036ULL,
		0x2F0183C5DC954DE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7560194797FA2E1FULL,
		0x099962E9801B5EDBULL,
		0x4B68303119F79EF6ULL,
		0xCE2323E41CBEE96DULL,
		0xBDE4A5C8EE04F1A3ULL,
		0xA4A6A69760E011E9ULL,
		0x6265ABA57ABEA445ULL,
		0x4BB2329B4F543785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCB68136E251DE11ULL,
		0xAA8B4961BC7A09C0ULL,
		0x000BC74FDFAB1EF7ULL,
		0xC089285F32996299ULL,
		0xE45FEC08F59A55C9ULL,
		0x8CA03C31434C9CCDULL,
		0x757693D3A9EEE9B4ULL,
		0x16A963641C89CFCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x025D2A8F957B7387ULL,
		0xF001E4B02784B73DULL,
		0x76D9F20639223187ULL,
		0x6CE8BDB67430EC93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC8C7941A8D87061ULL,
		0x4CFA9E6FB698B15FULL,
		0x05BAE080E0D97C1FULL,
		0xB8C21ADB8E420B12ULL,
		0x05517F746C5EB656ULL,
		0x103B15EDE258106FULL,
		0x6F773791B4FD0405ULL,
		0xFE7D2B5CF81EE5F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F1359FAE734D92ULL,
		0xAE3804EDABEE6E80ULL,
		0x6D9B14748228EA5EULL,
		0x41AF7E5B7D54DDCCULL,
		0xB63F89D02A8A6E56ULL,
		0xCEF8B7D4DEB9F7EFULL,
		0x077304AF83D9F722ULL,
		0x1C73EF6B5A6E2F67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7845BA03BFE7D7DBULL,
		0x4E9C91389421E5C5ULL,
		0x08BF599FA9E47B56ULL,
		0x0471825D79284669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96B221980289148CULL,
		0x90156754C0D80312ULL,
		0x96853294D87D6BB9ULL,
		0x9E95A7FEC129FF6CULL,
		0x3A9028FC29BDFA91ULL,
		0x77547D9B1DE5F1E6ULL,
		0xEAFFA9191C9FD0B8ULL,
		0xC49CAB83975C9D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE93E0BECB79348ULL,
		0x2721C03859E1AAACULL,
		0xC014C231881EAF7AULL,
		0x6F112DF4371FC965ULL,
		0x15599BF6BE44C299ULL,
		0x1BD7ED7A3A6E33DFULL,
		0xC722469B55724192ULL,
		0x9577703BECD254F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFE1D25A09CFD11EULL,
		0xFD710BFE2ABC8D75ULL,
		0x294D0F0EE121FBF0ULL,
		0x2F0B46ADDA90F5EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9213A325FCFD7B6ULL,
		0xB6DC686BD1773E04ULL,
		0x924637297E466B50ULL,
		0xC7F2062AB6FBAACFULL,
		0x29563DBCC998A718ULL,
		0x9E24D950BC5C2456ULL,
		0x1F45FB7769BF8345ULL,
		0x3FDD7120C1EDCE70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29B6C211E7A4CA87ULL,
		0x9EE224D9B4FB620AULL,
		0x03593BE0B376FEAAULL,
		0x9092721011268B29ULL,
		0x9465F531A24BE851ULL,
		0xD41A7E57F29E4D98ULL,
		0x3E6AAB908B353F06ULL,
		0x26898826E85B82DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB153CC84D8F5F3EULL,
		0x1583C4800EA9BC1EULL,
		0xEF7AD78DD3558DF8ULL,
		0x79D42930F18C57E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03EB7061DF8B947AULL,
		0x10240C4632E97140ULL,
		0xAF2C830EB65861A2ULL,
		0x5F87A14C4CDBEB26ULL,
		0x9462FAE6622A5228ULL,
		0x99928E037BB00B2CULL,
		0xB8827DEA6EAB329AULL,
		0x1CD3ABE27727ACF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9039DF0B079D7836ULL,
		0x88391DD11F99A739ULL,
		0xD506EBE80D0978B7ULL,
		0x8E5987FB51C13B76ULL,
		0x55E42558E0AA8116ULL,
		0x67F701D6B95625A6ULL,
		0x0AE7ADC996AD7A3BULL,
		0xC6D5CF9C948D3C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA85445810E72127ULL,
		0xE501BD19ECA7DBF3ULL,
		0x9F207C06B8F8470BULL,
		0x14DCCBB09E0769E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C5580F02E2FEDA7ULL,
		0x987E416EC8687374ULL,
		0x7BEAA0F0CD2DBF65ULL,
		0x563B2A90E8C25DA5ULL,
		0xB1397F6F2ECF56C3ULL,
		0x72416DCC65EA0DCBULL,
		0xDD6E54F4D0999A23ULL,
		0x6277B08E53B4FE01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0AF4DD2DCEA45EULL,
		0x54C1DC8C55CB2F44ULL,
		0x0E0A26B76BBA57DBULL,
		0x32A4042216A42079ULL,
		0x4BCC921DAA26ABAEULL,
		0xBB123FF430025191ULL,
		0x94141644DC14785AULL,
		0xC6C25FB4B8EFB373ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D75C62CB16AAC2DULL,
		0x74BD32FA730334DAULL,
		0x5145C857AD366B55ULL,
		0x408126BBCB674E4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95E9EA86E616F3F2ULL,
		0xC1790145D3E1B595ULL,
		0xFC7B9CD36B03FE4AULL,
		0x0659174858AC8203ULL,
		0xDE12383ED6908845ULL,
		0x6827A1DC4239B6A8ULL,
		0x3F458104377417D3ULL,
		0x1B6E45E251B3D6BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04F0F51D515AD3BULL,
		0x0B3951E396ADC3A3ULL,
		0x674B07651566E8D6ULL,
		0x1BF735155F692373ULL,
		0x6A46A35EC8B95DDFULL,
		0x9D48FD819F8FA261ULL,
		0xB9EA153B2AB947F8ULL,
		0x2FFF6B52BA2D983EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15D2F4771EF19156ULL,
		0xD34C14D66272F48DULL,
		0x60C295463957EFEEULL,
		0x5CD653837730A558ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x659AF475792CDAD0ULL,
		0x0B191C5573C7F11DULL,
		0x9B0096B870639442ULL,
		0xE34368E779D3E2D9ULL,
		0x456C79C44E786015ULL,
		0x37D0EBB42E0F910EULL,
		0xDE306FD506BA9A5DULL,
		0xC81818D7C0B7EEFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB35063FC13963AULL,
		0xC9EE005C5D0C6F2CULL,
		0x21F64C4B0221FA6BULL,
		0xAA09CF58D6A19517ULL,
		0x198634F6CB2CB126ULL,
		0x4B5E2FFF3B6F3178ULL,
		0x34E5BDB04CAC304EULL,
		0x9915F3E52518525BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C15DA92FA553D1AULL,
		0x5A32F8D51A89B23BULL,
		0x9A20BBE10C65580DULL,
		0x338B1591BCE38DE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81F1AFFDEFC88DC0ULL,
		0x8B8BAD32FD22975CULL,
		0xAD5A24EA9825DFC4ULL,
		0x0E766F8FE503F6C4ULL,
		0xCC02FA740D996A91ULL,
		0xDA7E05B733389BC3ULL,
		0x37F56FAF98EE3717ULL,
		0x22360A5C59D0B6D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF5A8E652288E6DAULL,
		0x1D8A03E6528365A5ULL,
		0xA1881E367DD32124ULL,
		0x551D5E741A1F0B09ULL,
		0xCD8DD393A77CA77EULL,
		0x201CE36102ED8A0AULL,
		0xD49AFCDA75E36822ULL,
		0x358800C46FAB339FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87FAE6E7F5849B33ULL,
		0x186CC217D5C3D32CULL,
		0xCB3F12574DED771AULL,
		0x5B2E7DA88C7665CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x790913ED1712AD69ULL,
		0x0D0ADE8D3AAAE18FULL,
		0x234C1EED9C379FE5ULL,
		0xB3159D9B1D978A88ULL,
		0x6B9B34B1BC55D096ULL,
		0xE68910ED00D38BF9ULL,
		0x1465945BDA9DFF1BULL,
		0xE880B22F3CB62405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735BC7BA564CFE4FULL,
		0x8BB348080DE67219ULL,
		0xEC91B5184C8522D1ULL,
		0x1CFF13E96BB28FFBULL,
		0x09228B35D21F1097ULL,
		0xE60968665E8F69B7ULL,
		0x81F122BCA500DF94ULL,
		0x7BA0BDBE570F4D5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA396749784E63167ULL,
		0x944A9A8142E18550ULL,
		0xF403477745052B1DULL,
		0x3F54D273C8A8D71FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x862F1D152C7B344BULL,
		0x27B54F98C47A38E9ULL,
		0xC76C90C41B843B7FULL,
		0x95D6F5ABDF74DDB5ULL,
		0xC4CAF07D3620D8D0ULL,
		0x7ACD56822F289586ULL,
		0xBA7D87792597F046ULL,
		0xAA463BAB829955CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76245DC8EAF0482BULL,
		0x2AC19ED2D2CB164AULL,
		0xF9E2A31336934243ULL,
		0x28F3EDB5ECBB7BECULL,
		0x3C3BEB9D72506BF6ULL,
		0xF3C2EDC5DEBE2A04ULL,
		0xCD8DC2D71DAAA24BULL,
		0x330A26D7B8B4B719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55457883527B1728ULL,
		0x087F3CB9E17B17FFULL,
		0xF9211DBE122A8C6CULL,
		0x1FCE1F65EAA8F07DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46D54B573505538AULL,
		0x8E96BA790FBD14E0ULL,
		0xDC5C0E41C9798068ULL,
		0x7011641A7DC2742DULL,
		0x21A99D870076FF75ULL,
		0x4EF6B31F79796319ULL,
		0xCF3819F111120316ULL,
		0xF1B0FEA099F1DD60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7250838597112E4ULL,
		0xA29F7DE3CF7C76F6ULL,
		0x0CE803E6A1C8D58CULL,
		0x2D6AC7F237D26BFDULL,
		0xE49AF878614C1359ULL,
		0xFD1486396E8E8DA1ULL,
		0xF1B1C95984362EA5ULL,
		0xCBF492B24997350FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FDCC34A7BF34D9FULL,
		0x1389E6BADF1C4D9CULL,
		0xB16400DA10523388ULL,
		0x5C9EA18833650431ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2840111E1616405ULL,
		0x97FD2B6C492CF805ULL,
		0x4EC607028DD5C2BDULL,
		0x56EF463FD19D9D2BULL,
		0x95F9305828171450ULL,
		0x829FCA26AAD238CFULL,
		0x54387185D2F5233EULL,
		0xE2B165BEF7398532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2407F4FFEA80B8F2ULL,
		0x1B0E92B7371BE3CDULL,
		0x153C924D8955B556ULL,
		0xB109356A54F3B2E5ULL,
		0x35951D04D3001189ULL,
		0x67928D9BC06A8D6FULL,
		0x0C91EAD84F6931A8ULL,
		0x92E107B156DF3B81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D56EA70984B163FULL,
		0x80E59553DD748487ULL,
		0xDC4172768B45E9AFULL,
		0x7ED406DB4A10DA96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D2AC7B307A22A70ULL,
		0x9C023B5F5E15DB00ULL,
		0x6DBF023881056761ULL,
		0x6A46C88F4F41A36BULL,
		0x27A2E90615009FA2ULL,
		0xF31FD54478D94371ULL,
		0xEEB4D1293B235D7CULL,
		0x50426BB9366A4CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F4784C9D34A071ULL,
		0xCB41A58E1CDD8713ULL,
		0xD22977ABF3E54908ULL,
		0x649983510A78B931ULL,
		0xE73844DA188C5826ULL,
		0x8F4E0EDA2DB41DC3ULL,
		0xFC34A4CFB6C9C3D3ULL,
		0xAB0E0C7639B7A817ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA70AADEDE3B02466ULL,
		0xA1E4099868BBEBA4ULL,
		0x9A9C1FD6326CED7DULL,
		0x0B73692FC74D574BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D1AECEA176A3D1EULL,
		0xC4D912D36D645470ULL,
		0xF627E359103FBED4ULL,
		0xB04A4421E2EFBA23ULL,
		0x7312EB9C301C37ECULL,
		0x374C9BA7C250771EULL,
		0xD1A4005DB6C1B1CDULL,
		0x29AF97FED3F2D75CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF947A6CAC8BDDDULL,
		0xB9A8DD24C1154420ULL,
		0x5F44B40500D75844ULL,
		0x454A9F1207C5DD0BULL,
		0xFA54053EC16F0AA3ULL,
		0x449580C75D904C6EULL,
		0xFF4C32A4843D8438ULL,
		0x2CD8C5B9B8EB8F85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC977D721BA563804ULL,
		0x125E32FDA0D5665BULL,
		0xCFEBB8D18F072AACULL,
		0x72E2DB51DE3E86FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA374514045F132BULL,
		0xC322A001CE081681ULL,
		0xF4475F85A08E9D1BULL,
		0x1A64F5777612B704ULL,
		0xF145CDD81D1B1775ULL,
		0x0EED6E33CD3192FDULL,
		0xCBFAFCF0EF964856ULL,
		0xA129CBA1E397837CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08CE7A3374F435BFULL,
		0xEF3264AD9E08C5B1ULL,
		0x9F3E9E343AE4E8C4ULL,
		0xD7509CCED3C9B99DULL,
		0x8D54F3F5A16E8EBDULL,
		0x7441E6AC491A3911ULL,
		0xC744C00AAE6DBFCDULL,
		0xA05DBAB88264403AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7729227EEB072896ULL,
		0xC9665971CB76A9E7ULL,
		0x0815CB7F11ADF89DULL,
		0x615EDB4D0FE4F934ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35EF2461580DDAAFULL,
		0xFDEC31D95F552D44ULL,
		0x2AD685431183A214ULL,
		0xB6D1D2FDA5FBB37DULL,
		0x60430EC7C5A9CDD9ULL,
		0xCFAF7CA182A52DF4ULL,
		0xE910822A8CB6E42DULL,
		0xEF3D8DED993B412DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x996EF698B319E834ULL,
		0x97CB793C39D08C38ULL,
		0x10ABA9C946B1BDB9ULL,
		0x07A93FDA4F2E8419ULL,
		0x4B859273F4F5830EULL,
		0x78A1D9BB304B6E10ULL,
		0xBDF5A67890D5A27DULL,
		0xAD37AD348964D1F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0A0A2399FB70E19ULL,
		0x5226E6CD5ED71CE6ULL,
		0x802777E52E41A488ULL,
		0x7C07EE9BB0A1B206ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x694C923998DC5C1CULL,
		0x19140C46BA22A803ULL,
		0x5759C6754FDF4EFEULL,
		0x4F51704340871A61ULL,
		0x9F97C50CEDE81A14ULL,
		0x860498E55C6F25E4ULL,
		0x8117B694C5BE995AULL,
		0x54B9DB1E71795CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F824528C36B87F4ULL,
		0xE681547B58A56523ULL,
		0x410C20B375B21095ULL,
		0xB7267234F23F53EBULL,
		0xED427FA60667F67EULL,
		0xF9D49DC5B9E41A6BULL,
		0x76089E0BB3B2F374ULL,
		0x05CCA25E2F437085ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62729A5732761E0EULL,
		0x01B1FE7D8220F6CAULL,
		0xBA8B4A1A87E7DE7BULL,
		0x4F616A982248D48DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2C9C26F8F427CEFULL,
		0x3B2647E9D0055269ULL,
		0xC2251F4D04AA749DULL,
		0xF37FADF4C62D88E0ULL,
		0x660262239ABA508CULL,
		0xD005A8F098480B83ULL,
		0xD526BB91AD8AB45AULL,
		0xAB432999FCF64F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE479C0422ABD885ULL,
		0x504CEACDEEFE5C74ULL,
		0x76D8DC5CD6D53C23ULL,
		0x5BEC41DC1F25FA4AULL,
		0xE92A8C746B014059ULL,
		0x0045F4958A39B999ULL,
		0xA2EFCF4BF3583A15ULL,
		0x99AED5B7DE4E18AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8BDE6C820F0C6EULL,
		0xC14E229FF7271E9DULL,
		0xBF735549D1535ED6ULL,
		0x3397DFA933FFACBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB368CD81799FB45EULL,
		0x7DB223EF753DF3F9ULL,
		0x96F5555B9A42643FULL,
		0x4F1F9E07ADEF71ADULL,
		0x9F0FF76D8AF815AAULL,
		0xE3C00CE296B7CE0FULL,
		0xAD52AF5EDFAEFC76ULL,
		0xB0A2661B627533BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF14F45E7DDD5C33ULL,
		0x65B957B96D04F7D4ULL,
		0xD52969A93E442E93ULL,
		0xD6B21A77F19E3925ULL,
		0x0BADF59A0BC0DCEAULL,
		0xF9857EDD168D36D4ULL,
		0x4A5B7C82801571B3ULL,
		0x1CC70208780172CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4E01E87DDF4C7C9ULL,
		0xDCA9E1070E8B6EFCULL,
		0x727D78688CC8CE9AULL,
		0x6AFE5E5E897FDC5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D172B9C1D3C9D7EULL,
		0xC4E0EB6EE55CFB7FULL,
		0x9D1E711D2C119052ULL,
		0x0DACAC953051A135ULL,
		0xFF80CCD4BD75B945ULL,
		0xC1B94FE2CC008AD2ULL,
		0x3E978E9626555AF5ULL,
		0x1A9F98B185B59F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBFF4A52BAAD3DFULL,
		0x2C50067CF11EA44FULL,
		0xA8994B8A887F9310ULL,
		0x0DEF85232C5F4BB5ULL,
		0xFD7A8CCD5D9BE357ULL,
		0x7DBC9977D66C7FDDULL,
		0xB975298A8108DA70ULL,
		0x12B68D02438F7202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E44B80F2BE78B19ULL,
		0xB013F8D26837F78EULL,
		0xB7A0254D2CED110AULL,
		0x2C54E375D59D0CA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 501\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}