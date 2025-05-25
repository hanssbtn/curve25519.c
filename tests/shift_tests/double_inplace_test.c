#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x8A7038CDEE7A6BD8ULL,
		0x024C0BB555EF55F6ULL,
		0x6119107EAFF02A59ULL,
		0x34AD822E8523ACC4ULL,
		0x8F789A3AA6916B1BULL,
		0xC259E9547CBE70CEULL,
		0x1ADB5868F8111CA7ULL,
		0x32AD109D8887873AULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x14E0719BDCF4D7B0ULL,
		0x0498176AABDEABEDULL,
		0xC23220FD5FE054B2ULL,
		0x695B045D0A475988ULL,
		0x1EF134754D22D636ULL,
		0x84B3D2A8F97CE19DULL,
		0x35B6B0D1F022394FULL,
		0x655A213B110F0E74ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7DE0B281F61399D0ULL,
		0x722A20D5C4DD418EULL,
		0x9FA213C2F8B0688BULL,
		0x4106CF4DF4B67318ULL,
		0x56CB4FF81DA02316ULL,
		0x892DC0D93588C239ULL,
		0xCB1A0F6FD5F40B10ULL,
		0x0B9EEC3C99D5B467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC16503EC2733A0ULL,
		0xE45441AB89BA831CULL,
		0x3F442785F160D116ULL,
		0x820D9E9BE96CE631ULL,
		0xAD969FF03B40462CULL,
		0x125B81B26B118472ULL,
		0x96341EDFABE81621ULL,
		0x173DD87933AB68CFULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE2FB4B0EB81631D5ULL,
		0xE50ED526834C44ACULL,
		0x34FD76DAC66FC4C3ULL,
		0x77E46CBC954A3629ULL,
		0x28475510AC61462FULL,
		0xBBA13F215772E7B2ULL,
		0x2A65B91B0632097CULL,
		0x19846A7021754F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F6961D702C63AAULL,
		0xCA1DAA4D06988959ULL,
		0x69FAEDB58CDF8987ULL,
		0xEFC8D9792A946C52ULL,
		0x508EAA2158C28C5EULL,
		0x77427E42AEE5CF64ULL,
		0x54CB72360C6412F9ULL,
		0x3308D4E042EA9E36ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD6667A3E802F52F4ULL,
		0x3E6554A7DE46F558ULL,
		0x2953A5ACAD813B42ULL,
		0x45D1D9C7330C4BF8ULL,
		0x0A45754B4FCB4028ULL,
		0xC7F206CAC4A2EEB1ULL,
		0x2251380CB71D68D6ULL,
		0x077DA388C38F931CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACCCF47D005EA5E8ULL,
		0x7CCAA94FBC8DEAB1ULL,
		0x52A74B595B027684ULL,
		0x8BA3B38E661897F0ULL,
		0x148AEA969F968050ULL,
		0x8FE40D958945DD62ULL,
		0x44A270196E3AD1ADULL,
		0x0EFB4711871F2638ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA289A463BFDD70B7ULL,
		0x40A3D924397BCD8CULL,
		0x0B6BE1C32805E413ULL,
		0xE549D98C23846904ULL,
		0xC9588CD14BC6E199ULL,
		0x1D9FA03C9601959BULL,
		0xA02B68C95A620F71ULL,
		0x05478AAC7403D907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x451348C77FBAE16EULL,
		0x8147B24872F79B19ULL,
		0x16D7C386500BC826ULL,
		0xCA93B3184708D208ULL,
		0x92B119A2978DC333ULL,
		0x3B3F40792C032B37ULL,
		0x4056D192B4C41EE2ULL,
		0x0A8F1558E807B20FULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x38515A5ABACECDD2ULL,
		0xFD76DD2627D43D67ULL,
		0x4B923BFB10FC5F3DULL,
		0x41FFA35740D6482EULL,
		0xEE2053E390F9A622ULL,
		0x0C0E561D2693B1F7ULL,
		0x7F53A31D7A0E3305ULL,
		0x17F64B05E1EFE07AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70A2B4B5759D9BA4ULL,
		0xFAEDBA4C4FA87ACEULL,
		0x972477F621F8BE7BULL,
		0x83FF46AE81AC905CULL,
		0xDC40A7C721F34C44ULL,
		0x181CAC3A4D2763EFULL,
		0xFEA7463AF41C660AULL,
		0x2FEC960BC3DFC0F4ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB4ABC5FBFF4B4C39ULL,
		0x86C75CBB3758766AULL,
		0xF8DE252E53753959ULL,
		0x8EE5EB498CD25413ULL,
		0x2535B5910858D71CULL,
		0x6EB1A5A6E3C14213ULL,
		0x889855A2F5A0ECF8ULL,
		0x143E4EC9AA0FD67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69578BF7FE969872ULL,
		0x0D8EB9766EB0ECD5ULL,
		0xF1BC4A5CA6EA72B3ULL,
		0x1DCBD69319A4A827ULL,
		0x4A6B6B2210B1AE39ULL,
		0xDD634B4DC7828426ULL,
		0x1130AB45EB41D9F0ULL,
		0x287C9D93541FACFBULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF21A02DA3911D257ULL,
		0xA507AB0F3C774D35ULL,
		0xBB2888600AE5E5D1ULL,
		0x640989284BA82C37ULL,
		0xCCBDE3B816F95A69ULL,
		0x2CFF744644BE5350ULL,
		0x69F7DB503758F649ULL,
		0x2F5F2664ACA28A87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43405B47223A4AEULL,
		0x4A0F561E78EE9A6BULL,
		0x765110C015CBCBA3ULL,
		0xC81312509750586FULL,
		0x997BC7702DF2B4D2ULL,
		0x59FEE88C897CA6A1ULL,
		0xD3EFB6A06EB1EC92ULL,
		0x5EBE4CC95945150EULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3C908A3427B013E1ULL,
		0xA7104A6CED1F8645ULL,
		0x016BFAF599101EA9ULL,
		0xEB6D39AA9219CD14ULL,
		0x1878B56FA4DBD121ULL,
		0x71E657D8120DE768ULL,
		0xCBCAF0943D96DF0EULL,
		0x17D92B471E349A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792114684F6027C2ULL,
		0x4E2094D9DA3F0C8AULL,
		0x02D7F5EB32203D53ULL,
		0xD6DA735524339A28ULL,
		0x30F16ADF49B7A243ULL,
		0xE3CCAFB0241BCED0ULL,
		0x9795E1287B2DBE1CULL,
		0x2FB2568E3C69349BULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCF78D1F1CCE71491ULL,
		0xAAE2BEEA7FAF2696ULL,
		0xCD44F40571613E0CULL,
		0xC0E7AE72450FBD6AULL,
		0xC2B089BE2ABC63FAULL,
		0x09F3A16FC2DC941DULL,
		0x27BBE9491EF14EE2ULL,
		0x3AB070C38DD3F868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EF1A3E399CE2922ULL,
		0x55C57DD4FF5E4D2DULL,
		0x9A89E80AE2C27C19ULL,
		0x81CF5CE48A1F7AD5ULL,
		0x8561137C5578C7F5ULL,
		0x13E742DF85B9283BULL,
		0x4F77D2923DE29DC4ULL,
		0x7560E1871BA7F0D0ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x14111071301D7A91ULL,
		0xE492CDFC196F3BDCULL,
		0x9E038B516868C0BAULL,
		0x4E1B9499B2262564ULL,
		0xAEC52135C4A4BC7CULL,
		0xBCD79F1BEFB87744ULL,
		0x7AB671BD10F635B0ULL,
		0x1EF42D4CAB485135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x282220E2603AF522ULL,
		0xC9259BF832DE77B8ULL,
		0x3C0716A2D0D18175ULL,
		0x9C372933644C4AC9ULL,
		0x5D8A426B894978F8ULL,
		0x79AF3E37DF70EE89ULL,
		0xF56CE37A21EC6B61ULL,
		0x3DE85A995690A26AULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4CCFCC3FB2966A08ULL,
		0x685E7A2AF7D807BFULL,
		0xB80FDC9A49C6046EULL,
		0x09BA8393C5BC15FCULL,
		0xB1C78CF724C4A998ULL,
		0x896977C272DCEA04ULL,
		0x050F73F4F60319CFULL,
		0x3B3FEC688A3E38DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x999F987F652CD410ULL,
		0xD0BCF455EFB00F7EULL,
		0x701FB934938C08DCULL,
		0x137507278B782BF9ULL,
		0x638F19EE49895330ULL,
		0x12D2EF84E5B9D409ULL,
		0x0A1EE7E9EC06339FULL,
		0x767FD8D1147C71B8ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA03F13EC3C88E847ULL,
		0x4589452A2BF822A0ULL,
		0xAA0BA7C9903DFA41ULL,
		0x0691E492BC4927ABULL,
		0xD90C0C830F3DF992ULL,
		0x458AC11F5D39C952ULL,
		0xDCED0C49156107DEULL,
		0x3E20C96C1564D699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407E27D87911D08EULL,
		0x8B128A5457F04541ULL,
		0x54174F93207BF482ULL,
		0x0D23C92578924F57ULL,
		0xB21819061E7BF324ULL,
		0x8B15823EBA7392A5ULL,
		0xB9DA18922AC20FBCULL,
		0x7C4192D82AC9AD33ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8AC7D6B2480776E6ULL,
		0x79744ECB133E1CF1ULL,
		0x9123D0C586C3A5D2ULL,
		0xD885D10BFAD889F5ULL,
		0x8728138F4A227A60ULL,
		0x78A55D66BEFDCA6FULL,
		0x892DCABB902EB37CULL,
		0x1F6A79F1C64D3995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x158FAD64900EEDCCULL,
		0xF2E89D96267C39E3ULL,
		0x2247A18B0D874BA4ULL,
		0xB10BA217F5B113EBULL,
		0x0E50271E9444F4C1ULL,
		0xF14ABACD7DFB94DFULL,
		0x125B9577205D66F8ULL,
		0x3ED4F3E38C9A732BULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3733AE0FC6351946ULL,
		0xB1832974C1F4761DULL,
		0xD914CCD9ED92909EULL,
		0xBEBD4EE82404C593ULL,
		0x6DBF24E1675067E1ULL,
		0xB70095A359422E5AULL,
		0x38390E0EE5E8D7AEULL,
		0x1BE7CC3AEEBA75F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E675C1F8C6A328CULL,
		0x630652E983E8EC3AULL,
		0xB22999B3DB25213DULL,
		0x7D7A9DD048098B27ULL,
		0xDB7E49C2CEA0CFC3ULL,
		0x6E012B46B2845CB4ULL,
		0x70721C1DCBD1AF5DULL,
		0x37CF9875DD74EBECULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x98A2FDDD6FDE977AULL,
		0x07A8540E66BB81BBULL,
		0x15145151C77BCF16ULL,
		0x509EF57BB5F224ABULL,
		0x049FC595C14FCDCDULL,
		0xBD75C0F77A4A02A6ULL,
		0x09EA28353F10A474ULL,
		0x3E519FCB4511E3C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3145FBBADFBD2EF4ULL,
		0x0F50A81CCD770377ULL,
		0x2A28A2A38EF79E2CULL,
		0xA13DEAF76BE44956ULL,
		0x093F8B2B829F9B9AULL,
		0x7AEB81EEF494054CULL,
		0x13D4506A7E2148E9ULL,
		0x7CA33F968A23C780ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4D55191CD68FD262ULL,
		0x05F1F6E8C72FA3DAULL,
		0xBDCBEB087787F4BCULL,
		0x9365DD8CC4CA3B1DULL,
		0x14360F1152B55C56ULL,
		0xA21394EDE78C379FULL,
		0x2B94DAF10ECF02B3ULL,
		0x3C9A0717F9D70D59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AAA3239AD1FA4C4ULL,
		0x0BE3EDD18E5F47B4ULL,
		0x7B97D610EF0FE978ULL,
		0x26CBBB198994763BULL,
		0x286C1E22A56AB8ADULL,
		0x442729DBCF186F3EULL,
		0x5729B5E21D9E0567ULL,
		0x79340E2FF3AE1AB2ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9D0DA0899A871690ULL,
		0xABE00016646C3DD6ULL,
		0xF9CA2999F6E88BF5ULL,
		0x3C434999B468678CULL,
		0xCBDB35C1AC4EC019ULL,
		0x0FC2C94079B5B601ULL,
		0x0E72A1A29FAAEA6EULL,
		0x16CEA5C4EF747A30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1B4113350E2D20ULL,
		0x57C0002CC8D87BADULL,
		0xF3945333EDD117EBULL,
		0x7886933368D0CF19ULL,
		0x97B66B83589D8032ULL,
		0x1F859280F36B6C03ULL,
		0x1CE543453F55D4DCULL,
		0x2D9D4B89DEE8F460ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4688E58DEBE0CD35ULL,
		0x175DCF6D6442B7A6ULL,
		0x37422D8D868DECF1ULL,
		0x59F93BD19B42853AULL,
		0x7314FF1C88DCDEB7ULL,
		0x6C620BF4020A356DULL,
		0x95E7614249DBE4FBULL,
		0x116C3604D889D07FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D11CB1BD7C19A6AULL,
		0x2EBB9EDAC8856F4CULL,
		0x6E845B1B0D1BD9E2ULL,
		0xB3F277A336850A74ULL,
		0xE629FE3911B9BD6EULL,
		0xD8C417E804146ADAULL,
		0x2BCEC28493B7C9F6ULL,
		0x22D86C09B113A0FFULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D5F474E681CB57DULL,
		0x6FA3FF8E96036539ULL,
		0xEF4DCCC7BF606E95ULL,
		0x2FB0ADC8E9FC2CC8ULL,
		0x1F8B1D9FA9874191ULL,
		0x8305B30CC8665B76ULL,
		0xEA9119442028FC69ULL,
		0x017AD68D57EBD867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ABE8E9CD0396AFAULL,
		0xDF47FF1D2C06CA72ULL,
		0xDE9B998F7EC0DD2AULL,
		0x5F615B91D3F85991ULL,
		0x3F163B3F530E8322ULL,
		0x060B661990CCB6ECULL,
		0xD52232884051F8D3ULL,
		0x02F5AD1AAFD7B0CFULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x87F89135613E387BULL,
		0x0FC08162C292E30FULL,
		0xC739AE90483F0DE3ULL,
		0x828B34A009CE74A3ULL,
		0x92473C49A24BB938ULL,
		0x41FE5AF1EA915A91ULL,
		0xE1B0B4FE7D63E08AULL,
		0x1F820B1C081A3273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF1226AC27C70F6ULL,
		0x1F8102C58525C61FULL,
		0x8E735D20907E1BC6ULL,
		0x05166940139CE947ULL,
		0x248E789344977271ULL,
		0x83FCB5E3D522B523ULL,
		0xC36169FCFAC7C114ULL,
		0x3F041638103464E7ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x804593B680FF5515ULL,
		0x1CC827C41C14220FULL,
		0x6971B9834DC41939ULL,
		0xA5121A3000C5D256ULL,
		0xE16F16207AE7E1A9ULL,
		0x9D2B198359312B94ULL,
		0x94BADDF8BB5C9B7CULL,
		0x1742BC6B0CEA9332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x008B276D01FEAA2AULL,
		0x39904F883828441FULL,
		0xD2E373069B883272ULL,
		0x4A243460018BA4ACULL,
		0xC2DE2C40F5CFC353ULL,
		0x3A563306B2625729ULL,
		0x2975BBF176B936F9ULL,
		0x2E8578D619D52665ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x27051C699106DDBBULL,
		0x54EEE4ED802A5332ULL,
		0x7BE6D7E45210F2FDULL,
		0xE1A42D8D297F7C18ULL,
		0x6F8A05ABF93E5644ULL,
		0xA41FA6C39E96D1CAULL,
		0xC99075D9A74ECF92ULL,
		0x2F56AEF7B71C2CE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E0A38D3220DBB76ULL,
		0xA9DDC9DB0054A664ULL,
		0xF7CDAFC8A421E5FAULL,
		0xC3485B1A52FEF830ULL,
		0xDF140B57F27CAC89ULL,
		0x483F4D873D2DA394ULL,
		0x9320EBB34E9D9F25ULL,
		0x5EAD5DEF6E3859CDULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x68C8F146C417578AULL,
		0x5D6D2DD9B0A1B5B4ULL,
		0x6638362CA0E6DCB2ULL,
		0x54573DB76BFC848BULL,
		0xE307DC63E9180C2AULL,
		0xE12F8E555ECB2132ULL,
		0x6325B14554F1EA63ULL,
		0x169044A86E7A40CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD191E28D882EAF14ULL,
		0xBADA5BB361436B68ULL,
		0xCC706C5941CDB964ULL,
		0xA8AE7B6ED7F90916ULL,
		0xC60FB8C7D2301854ULL,
		0xC25F1CAABD964265ULL,
		0xC64B628AA9E3D4C7ULL,
		0x2D208950DCF48196ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4BE463E4085880F0ULL,
		0x67CBB26F8E2A3A11ULL,
		0x40E7DF7E4A997BFEULL,
		0x37BDF6B1641BB13CULL,
		0x8CDA7CFF000EAD1CULL,
		0x2B647B9582434D0FULL,
		0xFE193D3D1D4F3F64ULL,
		0x393382414A26BE47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C8C7C810B101E0ULL,
		0xCF9764DF1C547422ULL,
		0x81CFBEFC9532F7FCULL,
		0x6F7BED62C8376278ULL,
		0x19B4F9FE001D5A38ULL,
		0x56C8F72B04869A1FULL,
		0xFC327A7A3A9E7EC8ULL,
		0x72670482944D7C8FULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF4018F6A10D8758DULL,
		0xACA9CD64A65D3062ULL,
		0x9CB5F27CACA2B6A1ULL,
		0x999A8D398EE7F7F0ULL,
		0x6B98C36EF4C394B6ULL,
		0xA95F1CAA330436F2ULL,
		0x6D05DF2225FD8217ULL,
		0x042A26799C920867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8031ED421B0EB1AULL,
		0x59539AC94CBA60C5ULL,
		0x396BE4F959456D43ULL,
		0x33351A731DCFEFE1ULL,
		0xD73186DDE987296DULL,
		0x52BE395466086DE4ULL,
		0xDA0BBE444BFB042FULL,
		0x08544CF3392410CEULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x30B98AC935DA8F3FULL,
		0xF664FD32353DA296ULL,
		0x1F83599BB5BED6F8ULL,
		0xC8392FA293D0340BULL,
		0x3BDC3F42BD05BC8AULL,
		0x6D8FA87239C32134ULL,
		0xBABB68A5E69A187DULL,
		0x222E2A6CC4AF2BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x617315926BB51E7EULL,
		0xECC9FA646A7B452CULL,
		0x3F06B3376B7DADF1ULL,
		0x90725F4527A06816ULL,
		0x77B87E857A0B7915ULL,
		0xDB1F50E473864268ULL,
		0x7576D14BCD3430FAULL,
		0x445C54D9895E5763ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEDC6B58C974309A4ULL,
		0xAE826CECA96B383AULL,
		0xB03274160C8F22E7ULL,
		0xD20E3C5FE8E159FFULL,
		0x3FF197110D508916ULL,
		0xBB91D4C9D463DAD3ULL,
		0xAC3E80EC4B2377F6ULL,
		0x242F8A59CDC2145EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB8D6B192E861348ULL,
		0x5D04D9D952D67075ULL,
		0x6064E82C191E45CFULL,
		0xA41C78BFD1C2B3FFULL,
		0x7FE32E221AA1122DULL,
		0x7723A993A8C7B5A6ULL,
		0x587D01D89646EFEDULL,
		0x485F14B39B8428BDULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1B4351A30C237F0CULL,
		0x71DC1EE312644B27ULL,
		0xD30373670701A8F2ULL,
		0x4418078973B3F47CULL,
		0xCDF24B52BFBAD3F2ULL,
		0x8CC0F75AF4295388ULL,
		0x69F887E1C680735FULL,
		0x10F9B19275F4B633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3686A3461846FE18ULL,
		0xE3B83DC624C8964EULL,
		0xA606E6CE0E0351E4ULL,
		0x88300F12E767E8F9ULL,
		0x9BE496A57F75A7E4ULL,
		0x1981EEB5E852A711ULL,
		0xD3F10FC38D00E6BFULL,
		0x21F36324EBE96C66ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5063E4EC3C8DFBBEULL,
		0xDD5F616A893F86DAULL,
		0x6EFC94AAB695D18EULL,
		0x0E5F8F5E9E127281ULL,
		0x1E351223E94BF4D6ULL,
		0x8DD42CE6A24D0CF4ULL,
		0x2C5B07C393D41EA8ULL,
		0x0F5A21014EC4B81FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0C7C9D8791BF77CULL,
		0xBABEC2D5127F0DB4ULL,
		0xDDF929556D2BA31DULL,
		0x1CBF1EBD3C24E502ULL,
		0x3C6A2447D297E9ACULL,
		0x1BA859CD449A19E8ULL,
		0x58B60F8727A83D51ULL,
		0x1EB442029D89703EULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBF0881086A244B5BULL,
		0x023555ADFA9BCACFULL,
		0x07DF1D5D4507AF45ULL,
		0xC2F09994768535BEULL,
		0xAAF14DCB05D390ADULL,
		0x2FF73A0981C62ED4ULL,
		0xFBC273A55A0BC982ULL,
		0x12D85BD36E720DDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E110210D44896B6ULL,
		0x046AAB5BF537959FULL,
		0x0FBE3ABA8A0F5E8AULL,
		0x85E13328ED0A6B7CULL,
		0x55E29B960BA7215BULL,
		0x5FEE7413038C5DA9ULL,
		0xF784E74AB4179304ULL,
		0x25B0B7A6DCE41BBBULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2590C4F29B67EA10ULL,
		0xAFDB804A7491820FULL,
		0xEBDB4B7F73DC9E8BULL,
		0xB432A84E9B28AB6CULL,
		0x9F65D32C58959262ULL,
		0xD61EED43187F2A44ULL,
		0x103E7243AA956B1FULL,
		0x14F3DAD18016F840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2189E536CFD420ULL,
		0x5FB70094E923041EULL,
		0xD7B696FEE7B93D17ULL,
		0x6865509D365156D9ULL,
		0x3ECBA658B12B24C5ULL,
		0xAC3DDA8630FE5489ULL,
		0x207CE487552AD63FULL,
		0x29E7B5A3002DF080ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x37C70D444FD56782ULL,
		0xF4A213466A3470E7ULL,
		0x62D7346F6F0EE42FULL,
		0x5AB5DD885EB6578AULL,
		0x069B8F83036A8F51ULL,
		0x6A8F3C9C41147CB0ULL,
		0xEC6EB124FD7A2A21ULL,
		0x11B0591102C2BBBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F8E1A889FAACF04ULL,
		0xE944268CD468E1CEULL,
		0xC5AE68DEDE1DC85FULL,
		0xB56BBB10BD6CAF14ULL,
		0x0D371F0606D51EA2ULL,
		0xD51E79388228F960ULL,
		0xD8DD6249FAF45442ULL,
		0x2360B22205857777ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB9D99452870AB838ULL,
		0x3B7F236CB2300415ULL,
		0xD31F291DFE057445ULL,
		0xEEC3C62152BD8C2EULL,
		0x83C070C52EA3A12EULL,
		0x97D7DDF6CD86F6CFULL,
		0xE1332DEB2E451ACDULL,
		0x2B596B729B7EDEA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73B328A50E157070ULL,
		0x76FE46D96460082BULL,
		0xA63E523BFC0AE88AULL,
		0xDD878C42A57B185DULL,
		0x0780E18A5D47425DULL,
		0x2FAFBBED9B0DED9FULL,
		0xC2665BD65C8A359BULL,
		0x56B2D6E536FDBD41ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1E4064AF86B6DA84ULL,
		0xC3553F5A01A7E838ULL,
		0x49F358F23EB7A1B9ULL,
		0x18C5E3BE0599E19EULL,
		0x832FC403FA5909C8ULL,
		0x5160AD71BD8FC840ULL,
		0xEE51AB068BE71111ULL,
		0x08F9E7AAC77B2A3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C80C95F0D6DB508ULL,
		0x86AA7EB4034FD070ULL,
		0x93E6B1E47D6F4373ULL,
		0x318BC77C0B33C33CULL,
		0x065F8807F4B21390ULL,
		0xA2C15AE37B1F9081ULL,
		0xDCA3560D17CE2222ULL,
		0x11F3CF558EF65475ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x45B24648AAA2E498ULL,
		0xD1C2A1D5D865981AULL,
		0xED06E4AF799F83AFULL,
		0x98B329A9153AB215ULL,
		0xDA1AE3FFAC8EA2B4ULL,
		0xDE4CCD4A41E2514FULL,
		0x64460CD0B436ADA6ULL,
		0x0177ED5FDF281D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B648C915545C930ULL,
		0xA38543ABB0CB3034ULL,
		0xDA0DC95EF33F075FULL,
		0x316653522A75642BULL,
		0xB435C7FF591D4569ULL,
		0xBC999A9483C4A29FULL,
		0xC88C19A1686D5B4DULL,
		0x02EFDABFBE503A6EULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x38F8B9EC7EF6A001ULL,
		0x2D4A0C157BB4E4F5ULL,
		0x055C262E8C47F447ULL,
		0x642323134D46BEC5ULL,
		0x58B66FDF5FA5494EULL,
		0x0DBB441D379E1E83ULL,
		0xD58B398E466373B3ULL,
		0x00E595A50B7E6AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F173D8FDED4002ULL,
		0x5A94182AF769C9EAULL,
		0x0AB84C5D188FE88EULL,
		0xC84646269A8D7D8AULL,
		0xB16CDFBEBF4A929CULL,
		0x1B76883A6F3C3D06ULL,
		0xAB16731C8CC6E766ULL,
		0x01CB2B4A16FCD56BULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D5F5E014D1932A0ULL,
		0x33FCA575D4977798ULL,
		0x95918BD60F4BC645ULL,
		0xE6C2174ED44A7459ULL,
		0x69FDD8EE3FA9CD1AULL,
		0xDCF20B1847A44B8EULL,
		0x1EDAB229DE47E174ULL,
		0x05E3FB79D765B553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFABEBC029A326540ULL,
		0x67F94AEBA92EEF30ULL,
		0x2B2317AC1E978C8AULL,
		0xCD842E9DA894E8B3ULL,
		0xD3FBB1DC7F539A35ULL,
		0xB9E416308F48971CULL,
		0x3DB56453BC8FC2E9ULL,
		0x0BC7F6F3AECB6AA6ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB2DD963C743C1643ULL,
		0x634A60B019162B6DULL,
		0x471BD31030F76944ULL,
		0xB3606D7B0E54EDA3ULL,
		0x6A8B9B07A5870805ULL,
		0xD9C427C5A85DD5CAULL,
		0x8EFF8E107E42EC33ULL,
		0x070D34F4F37EE8DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65BB2C78E8782C86ULL,
		0xC694C160322C56DBULL,
		0x8E37A62061EED288ULL,
		0x66C0DAF61CA9DB46ULL,
		0xD517360F4B0E100BULL,
		0xB3884F8B50BBAB94ULL,
		0x1DFF1C20FC85D867ULL,
		0x0E1A69E9E6FDD1BDULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCF7EBBCD8A8D8B0ULL,
		0xDB9EDB87D1AB484EULL,
		0x5057AA263814E13AULL,
		0xBE971EB394CC65BFULL,
		0x2E9D6517468D3449ULL,
		0x92AB14BDBF63CDAFULL,
		0xA72470FE868DB78DULL,
		0x061452954C79094EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99EFD779B151B160ULL,
		0xB73DB70FA356909DULL,
		0xA0AF544C7029C275ULL,
		0x7D2E3D672998CB7EULL,
		0x5D3ACA2E8D1A6893ULL,
		0x2556297B7EC79B5EULL,
		0x4E48E1FD0D1B6F1BULL,
		0x0C28A52A98F2129DULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x585F5801F3F3F223ULL,
		0x09FBA2A42B62BCFAULL,
		0xDFE99279F2A0A8DAULL,
		0xBE23DBA09BC31D94ULL,
		0x757A1ECC783CFDD1ULL,
		0x7C737FE87B7403F1ULL,
		0xDED200305A64A4F1ULL,
		0x318BDAEE8C1914A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0BEB003E7E7E446ULL,
		0x13F7454856C579F4ULL,
		0xBFD324F3E54151B4ULL,
		0x7C47B74137863B29ULL,
		0xEAF43D98F079FBA3ULL,
		0xF8E6FFD0F6E807E2ULL,
		0xBDA40060B4C949E2ULL,
		0x6317B5DD18322943ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x474C04B6B362BF0BULL,
		0xAC577C846A9CDE48ULL,
		0x5A12719941837A2FULL,
		0x8D6F0C8DB6792330ULL,
		0xFC3EE93678045C92ULL,
		0x53FFA6C530F6DC45ULL,
		0x531FDC66859300C8ULL,
		0x02F070DCCAF00132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E98096D66C57E16ULL,
		0x58AEF908D539BC90ULL,
		0xB424E3328306F45FULL,
		0x1ADE191B6CF24660ULL,
		0xF87DD26CF008B925ULL,
		0xA7FF4D8A61EDB88BULL,
		0xA63FB8CD0B260190ULL,
		0x05E0E1B995E00264ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x00EE8378F5F6F88DULL,
		0x1EA3FB3DA8DBC763ULL,
		0xC331E566D1EB1DBCULL,
		0x5B00629F0662EB95ULL,
		0x8BEB34AFA64DA159ULL,
		0x6BA7F574E7BBAC33ULL,
		0x672BFB7755E6D11BULL,
		0x3D5D200043132009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01DD06F1EBEDF11AULL,
		0x3D47F67B51B78EC6ULL,
		0x8663CACDA3D63B78ULL,
		0xB600C53E0CC5D72BULL,
		0x17D6695F4C9B42B2ULL,
		0xD74FEAE9CF775867ULL,
		0xCE57F6EEABCDA236ULL,
		0x7ABA400086264012ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x918D1A44DD29A9BCULL,
		0x486EC046E99B9C19ULL,
		0xBFC4E2D63C7A6A26ULL,
		0x4D511B823EB69C7FULL,
		0xA2F9543F0713D052ULL,
		0xECD0A1049EFBD953ULL,
		0xF63A0F6384D0843BULL,
		0x2BC4C61A8B2BB22BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x231A3489BA535378ULL,
		0x90DD808DD3373833ULL,
		0x7F89C5AC78F4D44CULL,
		0x9AA237047D6D38FFULL,
		0x45F2A87E0E27A0A4ULL,
		0xD9A142093DF7B2A7ULL,
		0xEC741EC709A10877ULL,
		0x57898C3516576457ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x505A8171C1BD5254ULL,
		0x46002D53C337F66FULL,
		0xE5A11085701EC382ULL,
		0x62C9B7F166FD0842ULL,
		0x603AD8F8A28D38FCULL,
		0x022FE6117622DBAFULL,
		0xCB0C256F53DABDA5ULL,
		0x2B307013E339CC8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B502E3837AA4A8ULL,
		0x8C005AA7866FECDEULL,
		0xCB42210AE03D8704ULL,
		0xC5936FE2CDFA1085ULL,
		0xC075B1F1451A71F8ULL,
		0x045FCC22EC45B75EULL,
		0x96184ADEA7B57B4AULL,
		0x5660E027C6739915ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF766AE0F9E9E5F93ULL,
		0xE471D75EE3D8BB67ULL,
		0x9A39EBF614FE742CULL,
		0x281777358A388403ULL,
		0x3BBA26F9AC56B1F2ULL,
		0xBCD672F33797826BULL,
		0x0CBFEC8B499F6919ULL,
		0x19DEE4AB062C0A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEECD5C1F3D3CBF26ULL,
		0xC8E3AEBDC7B176CFULL,
		0x3473D7EC29FCE859ULL,
		0x502EEE6B14710807ULL,
		0x77744DF358AD63E4ULL,
		0x79ACE5E66F2F04D6ULL,
		0x197FD916933ED233ULL,
		0x33BDC9560C581484ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA2228C90D52B9C61ULL,
		0xD2083E084DA5BC7AULL,
		0x6358ADDBCD949D4CULL,
		0xDF053206C1C6DE8AULL,
		0xDCBBBEBFC7DCF0A6ULL,
		0x6299AF2297D3F864ULL,
		0x6C846EC310C903C1ULL,
		0x3A2E40C530204051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44451921AA5738C2ULL,
		0xA4107C109B4B78F5ULL,
		0xC6B15BB79B293A99ULL,
		0xBE0A640D838DBD14ULL,
		0xB9777D7F8FB9E14DULL,
		0xC5335E452FA7F0C9ULL,
		0xD908DD8621920782ULL,
		0x745C818A604080A2ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA230D8CF140A89B5ULL,
		0xA13E61CA00FEF956ULL,
		0x167ABD4EA7B7675EULL,
		0x59105102F1DDEC3CULL,
		0xFBEB0F4EEF1703E7ULL,
		0x16172ABF648A8923ULL,
		0xBC86D46FD04BC9DDULL,
		0x08A1B88ABE269B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4461B19E2815136AULL,
		0x427CC39401FDF2ADULL,
		0x2CF57A9D4F6ECEBDULL,
		0xB220A205E3BBD878ULL,
		0xF7D61E9DDE2E07CEULL,
		0x2C2E557EC9151247ULL,
		0x790DA8DFA09793BAULL,
		0x114371157C4D3653ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x413609CCCBE67F89ULL,
		0x929C8EEDDE673AEAULL,
		0x6A920CA1ED40BB8CULL,
		0x1FEEE805024B25B1ULL,
		0x68AF80067F52981AULL,
		0x9F76E1ACA2C87874ULL,
		0xDBD179595C2B0A51ULL,
		0x1984D87BE0D0C50BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x826C139997CCFF12ULL,
		0x25391DDBBCCE75D4ULL,
		0xD5241943DA817719ULL,
		0x3FDDD00A04964B62ULL,
		0xD15F000CFEA53034ULL,
		0x3EEDC3594590F0E8ULL,
		0xB7A2F2B2B85614A3ULL,
		0x3309B0F7C1A18A17ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2327CC2E30D3BE15ULL,
		0x730B42EBEEB536D8ULL,
		0xC04216EC27AA49AFULL,
		0x71FAB25C2DA5EDCAULL,
		0x2684B02F44C0BFD5ULL,
		0x70CB196A24A60272ULL,
		0x633D3DCBA3485B6AULL,
		0x3BF12453386005EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464F985C61A77C2AULL,
		0xE61685D7DD6A6DB0ULL,
		0x80842DD84F54935EULL,
		0xE3F564B85B4BDB95ULL,
		0x4D09605E89817FAAULL,
		0xE19632D4494C04E4ULL,
		0xC67A7B974690B6D4ULL,
		0x77E248A670C00BD6ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8E41F140A39293A3ULL,
		0xCAC0A3C37B75B78AULL,
		0xC006DC90EE637146ULL,
		0x2AB250A7121A1E7FULL,
		0xD7E33ABC506EC2A1ULL,
		0x9FE20FF1D3B3C03BULL,
		0x7857349813C4C998ULL,
		0x35A4620DC4C44345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C83E28147252746ULL,
		0x95814786F6EB6F15ULL,
		0x800DB921DCC6E28DULL,
		0x5564A14E24343CFFULL,
		0xAFC67578A0DD8542ULL,
		0x3FC41FE3A7678077ULL,
		0xF0AE693027899331ULL,
		0x6B48C41B8988868AULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0ECD6A76CDE92FEEULL,
		0xE2E332B0F842D246ULL,
		0xC89DF88686A0D69BULL,
		0x5BFA1B07CCC925A3ULL,
		0x127E7A93AD25A89BULL,
		0xB1604E6B233DA606ULL,
		0x321E4F0037CD0E5BULL,
		0x0E6D5CCE1145D13CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D9AD4ED9BD25FDCULL,
		0xC5C66561F085A48CULL,
		0x913BF10D0D41AD37ULL,
		0xB7F4360F99924B47ULL,
		0x24FCF5275A4B5136ULL,
		0x62C09CD6467B4C0CULL,
		0x643C9E006F9A1CB7ULL,
		0x1CDAB99C228BA278ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5AA6D3690514B4AULL,
		0x5322107CFE58DA59ULL,
		0x500A124B31D54DF8ULL,
		0x534C7DDEB578EE29ULL,
		0x602670D7FE09007FULL,
		0xBAFAECE88DEC67F6ULL,
		0x99385C102C1B42DBULL,
		0x0DAB6BF9979C140CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB54DA6D20A29694ULL,
		0xA64420F9FCB1B4B3ULL,
		0xA014249663AA9BF0ULL,
		0xA698FBBD6AF1DC52ULL,
		0xC04CE1AFFC1200FEULL,
		0x75F5D9D11BD8CFECULL,
		0x3270B820583685B7ULL,
		0x1B56D7F32F382819ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA60B13FAE5AE15E5ULL,
		0x1EB7C04AA6703ACBULL,
		0x41EF2E9669729A93ULL,
		0x3A2426A54D16EA0FULL,
		0x66AF45A2DF7377A8ULL,
		0x9BE19431206D5DFCULL,
		0xAE3F2F9D7489F392ULL,
		0x3CB87B640EBFC7FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C1627F5CB5C2BCAULL,
		0x3D6F80954CE07597ULL,
		0x83DE5D2CD2E53526ULL,
		0x74484D4A9A2DD41EULL,
		0xCD5E8B45BEE6EF50ULL,
		0x37C3286240DABBF8ULL,
		0x5C7E5F3AE913E725ULL,
		0x7970F6C81D7F8FFFULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB89BDD3C3E7DB35BULL,
		0xFA5BEA640F3BC937ULL,
		0x1A7CE19607C860EEULL,
		0xD357EEA111098136ULL,
		0xB36114A620FDB62CULL,
		0xDAAAECACA1449665ULL,
		0x6D620B7F9DC3D54CULL,
		0x24AECD599292EC26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7137BA787CFB66B6ULL,
		0xF4B7D4C81E77926FULL,
		0x34F9C32C0F90C1DDULL,
		0xA6AFDD422213026CULL,
		0x66C2294C41FB6C59ULL,
		0xB555D95942892CCBULL,
		0xDAC416FF3B87AA99ULL,
		0x495D9AB32525D84CULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x52AD1B0D5BF54154ULL,
		0x7B0E0CFEF8D2FACDULL,
		0xA2BD15DEE8CA04A3ULL,
		0x5F3010773B5D05E5ULL,
		0xB027EDD0ED19891CULL,
		0xB67C7AC55CD4DE97ULL,
		0x8E03F627F8C18503ULL,
		0x0F74D3F2967543CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55A361AB7EA82A8ULL,
		0xF61C19FDF1A5F59AULL,
		0x457A2BBDD1940946ULL,
		0xBE6020EE76BA0BCBULL,
		0x604FDBA1DA331238ULL,
		0x6CF8F58AB9A9BD2FULL,
		0x1C07EC4FF1830A07ULL,
		0x1EE9A7E52CEA8799ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0070E5FD1D56A9D8ULL,
		0x5BF3B9EBA2D5108AULL,
		0xD9170E92A9742F62ULL,
		0x2C3617CEEFA5B131ULL,
		0x070CF3B1D4010EF1ULL,
		0xCE13BC8CF7F0D5B2ULL,
		0x50A72D0BEBA0A56BULL,
		0x1A64087A41381F74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00E1CBFA3AAD53B0ULL,
		0xB7E773D745AA2114ULL,
		0xB22E1D2552E85EC4ULL,
		0x586C2F9DDF4B6263ULL,
		0x0E19E763A8021DE2ULL,
		0x9C277919EFE1AB64ULL,
		0xA14E5A17D7414AD7ULL,
		0x34C810F482703EE8ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x427A8FC121996C45ULL,
		0x1C86FEB7970B8409ULL,
		0x87EAAEF01DB91C27ULL,
		0x1E89E9930CF10E76ULL,
		0x085AD2F3605AF09DULL,
		0x00F8FEE776D12414ULL,
		0x1D05EA8BA8C6D86DULL,
		0x3B4BD00C726F9FD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84F51F824332D88AULL,
		0x390DFD6F2E170812ULL,
		0x0FD55DE03B72384EULL,
		0x3D13D32619E21CEDULL,
		0x10B5A5E6C0B5E13AULL,
		0x01F1FDCEEDA24828ULL,
		0x3A0BD517518DB0DAULL,
		0x7697A018E4DF3FA8ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x859E1D9AF01188A5ULL,
		0xF3040F1C8A33FA92ULL,
		0x4833077C3256F231ULL,
		0xC0732661DBF9503FULL,
		0xDB92BF2766F3802FULL,
		0x9E6EA07C594A21B7ULL,
		0x69487FFB59D5EA3AULL,
		0x0B322FDE9286CB15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B3C3B35E023114AULL,
		0xE6081E391467F525ULL,
		0x90660EF864ADE463ULL,
		0x80E64CC3B7F2A07EULL,
		0xB7257E4ECDE7005FULL,
		0x3CDD40F8B294436FULL,
		0xD290FFF6B3ABD475ULL,
		0x16645FBD250D962AULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE3A8EDBBF327B689ULL,
		0x45329F8E6D7D95EAULL,
		0xB493A1DDC402EDB0ULL,
		0x220BD9C465F47DBEULL,
		0x5DEAF9E4643BB953ULL,
		0x1DBEC3A8A19484DBULL,
		0xC9904DD998346CD3ULL,
		0x266BDE92CD71DE2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC751DB77E64F6D12ULL,
		0x8A653F1CDAFB2BD5ULL,
		0x692743BB8805DB60ULL,
		0x4417B388CBE8FB7DULL,
		0xBBD5F3C8C87772A6ULL,
		0x3B7D8751432909B6ULL,
		0x93209BB33068D9A6ULL,
		0x4CD7BD259AE3BC57ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA06E71D75B4BBC2CULL,
		0xAEC397BFEB6A9C52ULL,
		0x84AE5ECB8B40D7AEULL,
		0x585903B7A60C67B3ULL,
		0x5968124DBAA6E510ULL,
		0x4EA515A47BA54143ULL,
		0xBE916F79D121F432ULL,
		0x2EE30A5B8D8DFED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40DCE3AEB6977858ULL,
		0x5D872F7FD6D538A5ULL,
		0x095CBD971681AF5DULL,
		0xB0B2076F4C18CF67ULL,
		0xB2D0249B754DCA20ULL,
		0x9D4A2B48F74A8286ULL,
		0x7D22DEF3A243E864ULL,
		0x5DC614B71B1BFDA3ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x89A11BADB1A96E15ULL,
		0xD2B1222EB50B1910ULL,
		0x958856E882F30478ULL,
		0x40E24A4E124AEBACULL,
		0x50E053CDE92DBDFFULL,
		0x3B107586B584DCC5ULL,
		0x248324B8FA1661AFULL,
		0x1EAE54790D6246A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1342375B6352DC2AULL,
		0xA562445D6A163221ULL,
		0x2B10ADD105E608F1ULL,
		0x81C4949C2495D759ULL,
		0xA1C0A79BD25B7BFEULL,
		0x7620EB0D6B09B98AULL,
		0x49064971F42CC35EULL,
		0x3D5CA8F21AC48D4EULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x526909F46BD5C901ULL,
		0x7BD2FC48FADDBCB7ULL,
		0x37BE52A64B587406ULL,
		0xDEC5B55BCCD2F0E6ULL,
		0xE19EA6046A4E030EULL,
		0xCFDAEB1EA19C1916ULL,
		0x80E5FD5C602637E2ULL,
		0x2417906F58858B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4D213E8D7AB9202ULL,
		0xF7A5F891F5BB796EULL,
		0x6F7CA54C96B0E80CULL,
		0xBD8B6AB799A5E1CCULL,
		0xC33D4C08D49C061DULL,
		0x9FB5D63D4338322DULL,
		0x01CBFAB8C04C6FC5ULL,
		0x482F20DEB10B1701ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2BB46A96D62E27E8ULL,
		0x5B169101B971C6B8ULL,
		0xECC13B9151289387ULL,
		0x8E52509EE53D1A00ULL,
		0x12731130FA9567FDULL,
		0xE82FF07CB8C63CFCULL,
		0x546679A5CAE406AAULL,
		0x0B31F6775B79265DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5768D52DAC5C4FD0ULL,
		0xB62D220372E38D70ULL,
		0xD9827722A251270EULL,
		0x1CA4A13DCA7A3401ULL,
		0x24E62261F52ACFFBULL,
		0xD05FE0F9718C79F8ULL,
		0xA8CCF34B95C80D55ULL,
		0x1663ECEEB6F24CBAULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0769DB93185DE2A6ULL,
		0x79D67EFFEEE173A2ULL,
		0xB2AE5F9887A8B89BULL,
		0x07462B05A6F298A0ULL,
		0xC1CE1B5351C0F425ULL,
		0x3BBA45E004270875ULL,
		0xF828ADBC849E21DBULL,
		0x34A6622A1122E6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED3B72630BBC54CULL,
		0xF3ACFDFFDDC2E744ULL,
		0x655CBF310F517136ULL,
		0x0E8C560B4DE53141ULL,
		0x839C36A6A381E84AULL,
		0x77748BC0084E10EBULL,
		0xF0515B79093C43B6ULL,
		0x694CC4542245CD5DULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x91C300E17C4AEF2CULL,
		0x437EE109C5643115ULL,
		0x04502DB49BC2DCC8ULL,
		0xA66A478CF0CCD1EDULL,
		0x25ABD95906C94BC0ULL,
		0xAF84EC1E3C1E6A7FULL,
		0xD29C33A32274201DULL,
		0x0A78E0BAFFA4881DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238601C2F895DE58ULL,
		0x86FDC2138AC8622BULL,
		0x08A05B693785B990ULL,
		0x4CD48F19E199A3DAULL,
		0x4B57B2B20D929781ULL,
		0x5F09D83C783CD4FEULL,
		0xA538674644E8403BULL,
		0x14F1C175FF49103BULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x65E7886DC97A2BE7ULL,
		0x1F305C39536D1B2BULL,
		0xC4C6E194D7FA9C66ULL,
		0x6A170EA9E79A0C3CULL,
		0xAB9B4EB407F9D281ULL,
		0xE24DF87116A7B8F2ULL,
		0xAA53E147386CBEBDULL,
		0x02C3885523F849C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCF10DB92F457CEULL,
		0x3E60B872A6DA3656ULL,
		0x898DC329AFF538CCULL,
		0xD42E1D53CF341879ULL,
		0x57369D680FF3A502ULL,
		0xC49BF0E22D4F71E5ULL,
		0x54A7C28E70D97D7BULL,
		0x058710AA47F09389ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD55E9BAA3E55A2B2ULL,
		0xB1DF4DA98B7EA4DAULL,
		0xD02FF714E97BEA35ULL,
		0x92870A2969D2D714ULL,
		0xB86040936BCD1189ULL,
		0xB146509A0FA38C38ULL,
		0xAFF47A3D341C5A01ULL,
		0x193682226D96EEF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAABD37547CAB4564ULL,
		0x63BE9B5316FD49B5ULL,
		0xA05FEE29D2F7D46BULL,
		0x250E1452D3A5AE29ULL,
		0x70C08126D79A2313ULL,
		0x628CA1341F471871ULL,
		0x5FE8F47A6838B403ULL,
		0x326D0444DB2DDDE9ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x93AD37B1D48BF44AULL,
		0x785D74065CC34046ULL,
		0xC82C6679C14534C8ULL,
		0x1E79758972FE1E69ULL,
		0xD17E1AD81F80D6F7ULL,
		0x8297639137DB948BULL,
		0x13E253D268E3B16CULL,
		0x2ECA957586F61E9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x275A6F63A917E894ULL,
		0xF0BAE80CB986808DULL,
		0x9058CCF3828A6990ULL,
		0x3CF2EB12E5FC3CD3ULL,
		0xA2FC35B03F01ADEEULL,
		0x052EC7226FB72917ULL,
		0x27C4A7A4D1C762D9ULL,
		0x5D952AEB0DEC3D3AULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC6E0EE0764B46EEFULL,
		0x0D4A5FB0A6B1DAF4ULL,
		0xCCC7460728277633ULL,
		0xBD305838E05436BCULL,
		0xB9152B651780F6EAULL,
		0xCB31FA5FEB7ED89EULL,
		0xF17DCE9D1CDE404DULL,
		0x1A3A15CB907C7DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC1DC0EC968DDDEULL,
		0x1A94BF614D63B5E9ULL,
		0x998E8C0E504EEC66ULL,
		0x7A60B071C0A86D79ULL,
		0x722A56CA2F01EDD5ULL,
		0x9663F4BFD6FDB13DULL,
		0xE2FB9D3A39BC809BULL,
		0x34742B9720F8FB8DULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x484FD317BF8CF90FULL,
		0xC00217FA3A3623A7ULL,
		0x1E1A10EAF6BAF582ULL,
		0x32D82F232D02B676ULL,
		0x4CD3EE48FF2F356FULL,
		0x9FB005098BB2634DULL,
		0xAD589E7A9B82FEB4ULL,
		0x12C1C2AE25CC81E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909FA62F7F19F21EULL,
		0x80042FF4746C474EULL,
		0x3C3421D5ED75EB05ULL,
		0x65B05E465A056CECULL,
		0x99A7DC91FE5E6ADEULL,
		0x3F600A131764C69AULL,
		0x5AB13CF53705FD69ULL,
		0x2583855C4B9903D1ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19E7F1BF347E6C6EULL,
		0x31956EB06F95FB96ULL,
		0xD10649104E78FB65ULL,
		0xFECE23FF43F765B9ULL,
		0xD6D3C68D851C401FULL,
		0xE332A7389B84A346ULL,
		0xB3DDFD5BD70D58B0ULL,
		0x24E779B1D5B50C4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CFE37E68FCD8DCULL,
		0x632ADD60DF2BF72CULL,
		0xA20C92209CF1F6CAULL,
		0xFD9C47FE87EECB73ULL,
		0xADA78D1B0A38803FULL,
		0xC6654E713709468DULL,
		0x67BBFAB7AE1AB161ULL,
		0x49CEF363AB6A189DULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4FCE55F99EC21E68ULL,
		0xE338588D5E7EB6FDULL,
		0x89F0E32B57E7D369ULL,
		0xB8D424527DFB962BULL,
		0xE16480864BDE02DDULL,
		0xF743ACA47FE5000CULL,
		0x6B85B9B21BE24C28ULL,
		0x18CB3C54B50FB864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9CABF33D843CD0ULL,
		0xC670B11ABCFD6DFAULL,
		0x13E1C656AFCFA6D3ULL,
		0x71A848A4FBF72C57ULL,
		0xC2C9010C97BC05BBULL,
		0xEE875948FFCA0019ULL,
		0xD70B736437C49851ULL,
		0x319678A96A1F70C8ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x44F33EE00F2D3A3DULL,
		0x1C4C8A10AC01594EULL,
		0x9222B3086D2D9F94ULL,
		0xF4F4FAEBCF9EDB6BULL,
		0xFC4415CA891BB992ULL,
		0x457050F5881612DEULL,
		0x930DA9C6EE9E39F0ULL,
		0x389333072B7EC479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E67DC01E5A747AULL,
		0x389914215802B29CULL,
		0x24456610DA5B3F28ULL,
		0xE9E9F5D79F3DB6D7ULL,
		0xF8882B9512377325ULL,
		0x8AE0A1EB102C25BDULL,
		0x261B538DDD3C73E0ULL,
		0x7126660E56FD88F3ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC3A6FF161BD01BDBULL,
		0x1A1E129DAF50A12DULL,
		0x7C9C438B7B2E5170ULL,
		0x135725E9EDAE94AFULL,
		0xA6302AE7AE9897F3ULL,
		0x367D8EB3A0695497ULL,
		0xF881BCFDBA74A563ULL,
		0x1FD48E0E10FAF877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x874DFE2C37A037B6ULL,
		0x343C253B5EA1425BULL,
		0xF9388716F65CA2E0ULL,
		0x26AE4BD3DB5D295EULL,
		0x4C6055CF5D312FE6ULL,
		0x6CFB1D6740D2A92FULL,
		0xF10379FB74E94AC6ULL,
		0x3FA91C1C21F5F0EFULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x93F6550A40B17F98ULL,
		0xA4E0002517F87013ULL,
		0xC3A8E23B791B487FULL,
		0xD3CD63ED687EB550ULL,
		0xE20C870F1B35353EULL,
		0x81DC3E16C66C61DDULL,
		0xF1E9E16BE696C126ULL,
		0x259D11A3A10764BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27ECAA148162FF30ULL,
		0x49C0004A2FF0E027ULL,
		0x8751C476F23690FFULL,
		0xA79AC7DAD0FD6AA1ULL,
		0xC4190E1E366A6A7DULL,
		0x03B87C2D8CD8C3BBULL,
		0xE3D3C2D7CD2D824DULL,
		0x4B3A2347420EC975ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6794F004C9663FA3ULL,
		0xA63A8838768AB3E6ULL,
		0x7B38CCAB85FFC7C8ULL,
		0x601776E4B2DB31BCULL,
		0xB343FBF1ECC35438ULL,
		0xA66B177C2D379EB5ULL,
		0x4E76C2297FA14BCDULL,
		0x03EB2B7BA439D1ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF29E00992CC7F46ULL,
		0x4C751070ED1567CCULL,
		0xF67199570BFF8F91ULL,
		0xC02EEDC965B66378ULL,
		0x6687F7E3D986A870ULL,
		0x4CD62EF85A6F3D6BULL,
		0x9CED8452FF42979BULL,
		0x07D656F74873A35AULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC11B263A54C915D2ULL,
		0xAAD9F629A6216891ULL,
		0x762C8FF43A636F41ULL,
		0x206A46650A41380CULL,
		0xC604B8606D059272ULL,
		0x43F3ADFC018D16B3ULL,
		0x04D159B978C7948AULL,
		0x0ABD9B58AE209ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82364C74A9922BA4ULL,
		0x55B3EC534C42D123ULL,
		0xEC591FE874C6DE83ULL,
		0x40D48CCA14827018ULL,
		0x8C0970C0DA0B24E4ULL,
		0x87E75BF8031A2D67ULL,
		0x09A2B372F18F2914ULL,
		0x157B36B15C413DA2ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12A05670A487A99DULL,
		0x7D30E1A20B252BDCULL,
		0x32AE45F78B23DE11ULL,
		0x2A09ACCF8F509E55ULL,
		0x7DAE628CAFC6C39AULL,
		0x94E707FB3A594CC0ULL,
		0x3D159F11E013527FULL,
		0x28EE36AFFAC8C31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2540ACE1490F533AULL,
		0xFA61C344164A57B8ULL,
		0x655C8BEF1647BC22ULL,
		0x5413599F1EA13CAAULL,
		0xFB5CC5195F8D8734ULL,
		0x29CE0FF674B29980ULL,
		0x7A2B3E23C026A4FFULL,
		0x51DC6D5FF591863AULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x62E47C8714D03409ULL,
		0x0B7EA45857B84D0EULL,
		0x7906DABF6AE87963ULL,
		0xBD0E045D85DF22B5ULL,
		0x3C7DA5579A116F6DULL,
		0x0144DE5EC8F6D151ULL,
		0x447BA6756473B3EDULL,
		0x3B65B6E1D8557033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C8F90E29A06812ULL,
		0x16FD48B0AF709A1CULL,
		0xF20DB57ED5D0F2C6ULL,
		0x7A1C08BB0BBE456AULL,
		0x78FB4AAF3422DEDBULL,
		0x0289BCBD91EDA2A2ULL,
		0x88F74CEAC8E767DAULL,
		0x76CB6DC3B0AAE066ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x42B3DCEF4E2B677CULL,
		0xBD78B200F4E38F6BULL,
		0x36BD79C1CDF421EEULL,
		0xEC84B73007EF6D2CULL,
		0xCFC2A75F50EA568AULL,
		0x8016DFE5A59B3D9EULL,
		0x58A6D3357811430FULL,
		0x0EC6E826AD229E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8567B9DE9C56CEF8ULL,
		0x7AF16401E9C71ED6ULL,
		0x6D7AF3839BE843DDULL,
		0xD9096E600FDEDA58ULL,
		0x9F854EBEA1D4AD15ULL,
		0x002DBFCB4B367B3DULL,
		0xB14DA66AF022861FULL,
		0x1D8DD04D5A453CC6ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x28AD1DB255DCEFC5ULL,
		0xCBCCAFFEB75F2002ULL,
		0xBE7328962F11F225ULL,
		0xCF98C221B78D969BULL,
		0x25825BAE8F4F5EA6ULL,
		0xF4519996725C55D8ULL,
		0xB98B28944060828DULL,
		0x01F7E902401C92EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515A3B64ABB9DF8AULL,
		0x97995FFD6EBE4004ULL,
		0x7CE6512C5E23E44BULL,
		0x9F3184436F1B2D37ULL,
		0x4B04B75D1E9EBD4DULL,
		0xE8A3332CE4B8ABB0ULL,
		0x7316512880C1051BULL,
		0x03EFD204803925D5ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2439C729A969CD49ULL,
		0x5BBD7C524E405E40ULL,
		0xC0D38F6294BBEC6EULL,
		0x98967ABE6F1D1574ULL,
		0x2F10EF24806ACA68ULL,
		0x2491EB747B3F2DC0ULL,
		0x6CCE527E7DCA31C3ULL,
		0x3A39B67E68B7898FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48738E5352D39A92ULL,
		0xB77AF8A49C80BC80ULL,
		0x81A71EC52977D8DCULL,
		0x312CF57CDE3A2AE9ULL,
		0x5E21DE4900D594D1ULL,
		0x4923D6E8F67E5B80ULL,
		0xD99CA4FCFB946386ULL,
		0x74736CFCD16F131EULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9A320734853E4516ULL,
		0x06B78DA433DBA80AULL,
		0x077DF270B884E961ULL,
		0x89AB36F6B1C302BAULL,
		0x373B9CFD4880EFA4ULL,
		0xB50C2B69CA7C476FULL,
		0x0ADB0BD5D43587B2ULL,
		0x1D646F93396E6E76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34640E690A7C8A2CULL,
		0x0D6F1B4867B75015ULL,
		0x0EFBE4E17109D2C2ULL,
		0x13566DED63860574ULL,
		0x6E7739FA9101DF49ULL,
		0x6A1856D394F88EDEULL,
		0x15B617ABA86B0F65ULL,
		0x3AC8DF2672DCDCECULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBF03A6D8231BC66FULL,
		0x5E3F9D2ADBAA9C5CULL,
		0xA02B572681FA8E8FULL,
		0xEC52A78B10080429ULL,
		0x071A1AB78E100523ULL,
		0x10A83BF828C7A38EULL,
		0xC919F30AE20F5B2DULL,
		0x177B5CDE6964548CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E074DB046378CDEULL,
		0xBC7F3A55B75538B9ULL,
		0x4056AE4D03F51D1EULL,
		0xD8A54F1620100853ULL,
		0x0E34356F1C200A47ULL,
		0x215077F0518F471CULL,
		0x9233E615C41EB65AULL,
		0x2EF6B9BCD2C8A919ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xED68008837E5EED9ULL,
		0x99863844B47910A3ULL,
		0x5AA89D64D57AF95EULL,
		0xC4B2CD3FE776882BULL,
		0x03072A04F4421580ULL,
		0xD9835D48CD044086ULL,
		0x199291AFBB6E4ADAULL,
		0x2D1637ADBB7041F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD001106FCBDDB2ULL,
		0x330C708968F22147ULL,
		0xB5513AC9AAF5F2BDULL,
		0x89659A7FCEED1056ULL,
		0x060E5409E8842B01ULL,
		0xB306BA919A08810CULL,
		0x3325235F76DC95B5ULL,
		0x5A2C6F5B76E083E8ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCF7DBA3CA327E88ULL,
		0xB3706BD41B2E7421ULL,
		0x6EF0623BF9FAC555ULL,
		0x9639A2C6B7E13F98ULL,
		0x7199283A5CB023A1ULL,
		0xD7288AC7E0863C12ULL,
		0x03F9B812324B4D23ULL,
		0x25A3C572EF8AFFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99EFB7479464FD10ULL,
		0x66E0D7A8365CE843ULL,
		0xDDE0C477F3F58AABULL,
		0x2C73458D6FC27F30ULL,
		0xE3325074B9604743ULL,
		0xAE51158FC10C7824ULL,
		0x07F3702464969A47ULL,
		0x4B478AE5DF15FFA4ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9C759D0A43232A52ULL,
		0xB690613C53976D92ULL,
		0x15F48D62CDBCE3B8ULL,
		0x7B55A86DDAE3648DULL,
		0xC69BC0C9E1C64BA7ULL,
		0xCDD852CF76EB8514ULL,
		0x2C8EFDEE2397CCA8ULL,
		0x0B91FE25DC340758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38EB3A14864654A4ULL,
		0x6D20C278A72EDB25ULL,
		0x2BE91AC59B79C771ULL,
		0xF6AB50DBB5C6C91AULL,
		0x8D378193C38C974EULL,
		0x9BB0A59EEDD70A29ULL,
		0x591DFBDC472F9951ULL,
		0x1723FC4BB8680EB0ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF43B0852894754E7ULL,
		0x681BC3024943618BULL,
		0x72D26DDC2232E90DULL,
		0x1A4D071A7F095449ULL,
		0x1023DAA1508D75C8ULL,
		0x0618E80FAC2109D1ULL,
		0xD13F11FB3CA7DFC0ULL,
		0x0313A9234898C914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87610A5128EA9CEULL,
		0xD03786049286C317ULL,
		0xE5A4DBB84465D21AULL,
		0x349A0E34FE12A892ULL,
		0x2047B542A11AEB90ULL,
		0x0C31D01F584213A2ULL,
		0xA27E23F6794FBF80ULL,
		0x0627524691319229ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE1A8B00167A5465CULL,
		0x13F02EEEA4463A85ULL,
		0xFCC48EA903F4D64BULL,
		0x45E8009EA37B0C06ULL,
		0x057241B891DA2005ULL,
		0x8362D8967A31A89FULL,
		0x998C8756D3841F6BULL,
		0x1F70A67C97828149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3516002CF4A8CB8ULL,
		0x27E05DDD488C750BULL,
		0xF9891D5207E9AC96ULL,
		0x8BD0013D46F6180DULL,
		0x0AE4837123B4400AULL,
		0x06C5B12CF463513EULL,
		0x33190EADA7083ED7ULL,
		0x3EE14CF92F050293ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1AD129E484B4199EULL,
		0x0ACDCD59B38FCAF7ULL,
		0x2C5DFF12FD57EEEDULL,
		0x16AE833C6169E350ULL,
		0x4ED81CD17F94F386ULL,
		0x5315921934EB7E02ULL,
		0x09B4046349BDA54DULL,
		0x1477A89F74791D9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A253C90968333CULL,
		0x159B9AB3671F95EEULL,
		0x58BBFE25FAAFDDDAULL,
		0x2D5D0678C2D3C6A0ULL,
		0x9DB039A2FF29E70CULL,
		0xA62B243269D6FC04ULL,
		0x136808C6937B4A9AULL,
		0x28EF513EE8F23B34ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD6DB3B7BE736D757ULL,
		0x0285348EC8176612ULL,
		0x12F859DC5811E655ULL,
		0x0FDF75D956E349A8ULL,
		0xE419F5D545D082E4ULL,
		0xE920979C0F7DEC42ULL,
		0xBC2B79EFE2584C91ULL,
		0x2578E601E043B0BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB676F7CE6DAEAEULL,
		0x050A691D902ECC25ULL,
		0x25F0B3B8B023CCAAULL,
		0x1FBEEBB2ADC69350ULL,
		0xC833EBAA8BA105C8ULL,
		0xD2412F381EFBD885ULL,
		0x7856F3DFC4B09923ULL,
		0x4AF1CC03C087617DULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8145E963ADCD278BULL,
		0x63601C8A0E74DE70ULL,
		0x24CBD94BB5FCF991ULL,
		0xD698A10C95B613DCULL,
		0x1E809C5B9473E204ULL,
		0x5A8C25901A66BCB9ULL,
		0xA0BA9C50AF7DD0B1ULL,
		0x3068580EB6307A93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028BD2C75B9A4F16ULL,
		0xC6C039141CE9BCE1ULL,
		0x4997B2976BF9F322ULL,
		0xAD3142192B6C27B8ULL,
		0x3D0138B728E7C409ULL,
		0xB5184B2034CD7972ULL,
		0x417538A15EFBA162ULL,
		0x60D0B01D6C60F527ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4D54C28FDAA41BF0ULL,
		0x84B6B0D74659353CULL,
		0x7119DB1C41FA6784ULL,
		0x5E7F5AC6A86A7CA7ULL,
		0x8B52730C36F948FFULL,
		0x25DA61C8FF3FAD1BULL,
		0x847586B01A158D1EULL,
		0x20CBAF398B36D16FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA9851FB54837E0ULL,
		0x096D61AE8CB26A78ULL,
		0xE233B63883F4CF09ULL,
		0xBCFEB58D50D4F94EULL,
		0x16A4E6186DF291FEULL,
		0x4BB4C391FE7F5A37ULL,
		0x08EB0D60342B1A3CULL,
		0x41975E73166DA2DFULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4337FD9ED95E6F6FULL,
		0x75E87284AA133B73ULL,
		0x1B037D8A73FB3245ULL,
		0xB814F13BE38CEAA0ULL,
		0xA5589C99C032F0CEULL,
		0xE96B1CFA23792EABULL,
		0xE9A5A9F9E81A0DBAULL,
		0x3FCC4D3071D59BC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x866FFB3DB2BCDEDEULL,
		0xEBD0E509542676E6ULL,
		0x3606FB14E7F6648AULL,
		0x7029E277C719D540ULL,
		0x4AB139338065E19DULL,
		0xD2D639F446F25D57ULL,
		0xD34B53F3D0341B75ULL,
		0x7F989A60E3AB3785ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1988D7DF10113EE1ULL,
		0x353398A1D38AFDBEULL,
		0x1F93FB5DEA5E71ECULL,
		0xCCA8DE3A3DAA598FULL,
		0x8806FCDE6C817993ULL,
		0x7342BBEDB2AC8FA1ULL,
		0x0A11D59F5B844577ULL,
		0x0D9EF424802D0D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3311AFBE20227DC2ULL,
		0x6A673143A715FB7CULL,
		0x3F27F6BBD4BCE3D8ULL,
		0x9951BC747B54B31EULL,
		0x100DF9BCD902F327ULL,
		0xE68577DB65591F43ULL,
		0x1423AB3EB7088AEEULL,
		0x1B3DE849005A1A8CULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C591DDE58DEFFE7ULL,
		0xCBAF281C2153B4E2ULL,
		0xB472B6E9D126FD6BULL,
		0x3A44B3544FDFA212ULL,
		0x43D03FDE60F00311ULL,
		0x2E2B589F4AF4250AULL,
		0xB8F9AD56C0D852B3ULL,
		0x3770B2F4E3C01BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8B23BBCB1BDFFCEULL,
		0x975E503842A769C4ULL,
		0x68E56DD3A24DFAD7ULL,
		0x748966A89FBF4425ULL,
		0x87A07FBCC1E00622ULL,
		0x5C56B13E95E84A14ULL,
		0x71F35AAD81B0A566ULL,
		0x6EE165E9C78037BBULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x43CEBF9705399E74ULL,
		0x7A01F9C2E149973CULL,
		0xB288FE3794A7D229ULL,
		0xAE3364C5FD130533ULL,
		0x81509965E9E908BDULL,
		0xDD9ED04D55CACE94ULL,
		0xABB845C400303EE2ULL,
		0x17E6E94C325060DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x879D7F2E0A733CE8ULL,
		0xF403F385C2932E78ULL,
		0x6511FC6F294FA452ULL,
		0x5C66C98BFA260A67ULL,
		0x02A132CBD3D2117BULL,
		0xBB3DA09AAB959D29ULL,
		0x57708B8800607DC5ULL,
		0x2FCDD29864A0C1B5ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x49D7B842BBB4EC2FULL,
		0x42949C544AD2C67CULL,
		0xC6BF6CF1035386B9ULL,
		0x4CCD8DE5F7CB0E74ULL,
		0x19957D91AC8ED389ULL,
		0x496D2413295CE56BULL,
		0x9587D2ECB772917AULL,
		0x3CFA98B8B43A6104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93AF70857769D85EULL,
		0x852938A895A58CF8ULL,
		0x8D7ED9E206A70D72ULL,
		0x999B1BCBEF961CE9ULL,
		0x332AFB23591DA712ULL,
		0x92DA482652B9CAD6ULL,
		0x2B0FA5D96EE522F4ULL,
		0x79F531716874C209ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x934119415E1A5E65ULL,
		0x6FA70ABFEEE07537ULL,
		0x0BF6C11189955E47ULL,
		0x5328241FA91523B9ULL,
		0xBBCE58502241A495ULL,
		0xC1A6E4449D66AC45ULL,
		0x6F84EA7F177A9A35ULL,
		0x2198030BCCABEF0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26823282BC34BCCAULL,
		0xDF4E157FDDC0EA6FULL,
		0x17ED8223132ABC8EULL,
		0xA650483F522A4772ULL,
		0x779CB0A04483492AULL,
		0x834DC8893ACD588BULL,
		0xDF09D4FE2EF5346BULL,
		0x433006179957DE18ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE339D94F54F69A1DULL,
		0xCFFADC9835EF8052ULL,
		0x7CF457C815C461E3ULL,
		0x04EE8183DCD64086ULL,
		0xFAB5E856C02AE27EULL,
		0x2EF68D6C82741FBDULL,
		0xA15D86125D6ED1CBULL,
		0x1E2932D82AF9975EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC673B29EA9ED343AULL,
		0x9FF5B9306BDF00A5ULL,
		0xF9E8AF902B88C3C7ULL,
		0x09DD0307B9AC810CULL,
		0xF56BD0AD8055C4FCULL,
		0x5DED1AD904E83F7BULL,
		0x42BB0C24BADDA396ULL,
		0x3C5265B055F32EBDULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB5BEEAFD48E5AF8ULL,
		0x76A3205A72E3708EULL,
		0x8F3A4FD03A20EB7BULL,
		0x1F349E9417A2B085ULL,
		0x11A6E7ED2BC9F51CULL,
		0x5CA0FE82B8A519ACULL,
		0x103CCF785055A7C1ULL,
		0x3F73C7E1BD571438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B7DD5FA91CB5F0ULL,
		0xED4640B4E5C6E11DULL,
		0x1E749FA07441D6F6ULL,
		0x3E693D282F45610BULL,
		0x234DCFDA5793EA38ULL,
		0xB941FD05714A3358ULL,
		0x20799EF0A0AB4F82ULL,
		0x7EE78FC37AAE2870ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD180328138F2B9AULL,
		0x9EDA43A6C4CA259EULL,
		0x631B5E333EE467BCULL,
		0x5CF1DB58FA7D4BD7ULL,
		0xD354B2311A52942AULL,
		0x2CA3540A74B5C45FULL,
		0xB76242C91D2017F6ULL,
		0x0542BFBE4CFA2AC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A300650271E5734ULL,
		0x3DB4874D89944B3DULL,
		0xC636BC667DC8CF79ULL,
		0xB9E3B6B1F4FA97AEULL,
		0xA6A9646234A52854ULL,
		0x5946A814E96B88BFULL,
		0x6EC485923A402FECULL,
		0x0A857F7C99F45583ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF9B645D2A43E0496ULL,
		0xC9475D1CA84D9D4BULL,
		0xB005F7523FAC0790ULL,
		0xA939B9922873D52DULL,
		0x367025B360A9F422ULL,
		0x77BFF1AB5079B4B4ULL,
		0xCEF6181433A4BD1FULL,
		0x16B0E77B661D1E8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF36C8BA5487C092CULL,
		0x928EBA39509B3A97ULL,
		0x600BEEA47F580F21ULL,
		0x5273732450E7AA5BULL,
		0x6CE04B66C153E845ULL,
		0xEF7FE356A0F36968ULL,
		0x9DEC302867497A3EULL,
		0x2D61CEF6CC3A3D1FULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD7AE552D2556EB21ULL,
		0xC3E37957AFB0A007ULL,
		0x4431213E6954DE1CULL,
		0x316564581027F968ULL,
		0x09FA97C810F3E1A9ULL,
		0x18030B6AE93182E4ULL,
		0x06BB8125C09F7DC2ULL,
		0x2269B5757EADACF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF5CAA5A4AADD642ULL,
		0x87C6F2AF5F61400FULL,
		0x8862427CD2A9BC39ULL,
		0x62CAC8B0204FF2D0ULL,
		0x13F52F9021E7C352ULL,
		0x300616D5D26305C8ULL,
		0x0D77024B813EFB84ULL,
		0x44D36AEAFD5B59EEULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC9661C6CF07D62D2ULL,
		0x5AC21DAFCFE62000ULL,
		0xF6B1D29F5FBEAD79ULL,
		0x7280788E330FBBFAULL,
		0xBC4ED96ED7E9CE31ULL,
		0xD2B7D6EEE3B99631ULL,
		0x434A461BCEEE4E41ULL,
		0x3F67885EEFC53727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92CC38D9E0FAC5A4ULL,
		0xB5843B5F9FCC4001ULL,
		0xED63A53EBF7D5AF2ULL,
		0xE500F11C661F77F5ULL,
		0x789DB2DDAFD39C62ULL,
		0xA56FADDDC7732C63ULL,
		0x86948C379DDC9C83ULL,
		0x7ECF10BDDF8A6E4EULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB64DC77F1503199BULL,
		0x1298D8ABBDE1576BULL,
		0x5127F714232890FEULL,
		0x7B541306B3999FF0ULL,
		0x69F19F25E489DEDEULL,
		0xFB2493D2D9C98C7DULL,
		0x053185E4B25AEF8DULL,
		0x1F20173E4D144529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9B8EFE2A063336ULL,
		0x2531B1577BC2AED7ULL,
		0xA24FEE28465121FCULL,
		0xF6A8260D67333FE0ULL,
		0xD3E33E4BC913BDBCULL,
		0xF64927A5B39318FAULL,
		0x0A630BC964B5DF1BULL,
		0x3E402E7C9A288A52ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x881356690720689BULL,
		0xC2BD4EB34B160694ULL,
		0xB6D33DF5B416CA66ULL,
		0xC4C09EC881C72D40ULL,
		0xF5AF0F61D745E408ULL,
		0x352FC8A0AEA98A69ULL,
		0x00CEC577DDECD0FFULL,
		0x0D6C06373C47CA68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1026ACD20E40D136ULL,
		0x857A9D66962C0D29ULL,
		0x6DA67BEB682D94CDULL,
		0x89813D91038E5A81ULL,
		0xEB5E1EC3AE8BC811ULL,
		0x6A5F91415D5314D3ULL,
		0x019D8AEFBBD9A1FEULL,
		0x1AD80C6E788F94D0ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2952545A515291E6ULL,
		0x6C0425ED20F657A9ULL,
		0x1D1B19A5741ED206ULL,
		0xC343276E5D6D1E1FULL,
		0x9193B747E48188FAULL,
		0x5A167C33A445C3EFULL,
		0x14795BC7CCAE4F05ULL,
		0x30D0A01442CFA011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52A4A8B4A2A523CCULL,
		0xD8084BDA41ECAF52ULL,
		0x3A36334AE83DA40CULL,
		0x86864EDCBADA3C3EULL,
		0x23276E8FC90311F5ULL,
		0xB42CF867488B87DFULL,
		0x28F2B78F995C9E0AULL,
		0x61A14028859F4022ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D93138F54ACF270ULL,
		0x016882E0545BA42FULL,
		0xD4733A1279049D4AULL,
		0x017AE777BEED3B95ULL,
		0x5EC329C5DB4D69D4ULL,
		0x0660CF489151C176ULL,
		0xE10CDBC45B1C0EC7ULL,
		0x298DCDB8A7D0CBBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB26271EA959E4E0ULL,
		0x02D105C0A8B7485EULL,
		0xA8E67424F2093A94ULL,
		0x02F5CEEF7DDA772BULL,
		0xBD86538BB69AD3A8ULL,
		0x0CC19E9122A382ECULL,
		0xC219B788B6381D8EULL,
		0x531B9B714FA19779ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD81402F8B52B7032ULL,
		0xE9BCBB02ED8C4244ULL,
		0xD9AEB436605C5037ULL,
		0xA7BC8461E9433F81ULL,
		0xF15486A3F0B73204ULL,
		0x7D38CE1A744A922DULL,
		0x087CC1F96837B4F1ULL,
		0x046436D1485A5D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB02805F16A56E064ULL,
		0xD3797605DB188489ULL,
		0xB35D686CC0B8A06FULL,
		0x4F7908C3D2867F03ULL,
		0xE2A90D47E16E6409ULL,
		0xFA719C34E895245BULL,
		0x10F983F2D06F69E2ULL,
		0x08C86DA290B4BA34ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4780EFB5E7514C70ULL,
		0xFD4E6721C489182BULL,
		0x1C9CCCEAE95B8059ULL,
		0x1D17259902A70E51ULL,
		0x68CEF2FE077D9AE5ULL,
		0x4129E6AC91A82BD0ULL,
		0x162BA876E979F34FULL,
		0x0CF674D8FBC13C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F01DF6BCEA298E0ULL,
		0xFA9CCE4389123056ULL,
		0x393999D5D2B700B3ULL,
		0x3A2E4B32054E1CA2ULL,
		0xD19DE5FC0EFB35CAULL,
		0x8253CD59235057A0ULL,
		0x2C5750EDD2F3E69EULL,
		0x19ECE9B1F782793CULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF709F92BD1E16CF5ULL,
		0xD16F21361D584688ULL,
		0xA29EA9294CC1478EULL,
		0x3841309747A38B72ULL,
		0x632C27E0FBF3620FULL,
		0xA88B332AA3DA0BFDULL,
		0xD6B7410BF220E0BEULL,
		0x3C178CAB1E859F27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE13F257A3C2D9EAULL,
		0xA2DE426C3AB08D11ULL,
		0x453D525299828F1DULL,
		0x7082612E8F4716E5ULL,
		0xC6584FC1F7E6C41EULL,
		0x5116665547B417FAULL,
		0xAD6E8217E441C17DULL,
		0x782F19563D0B3E4FULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6F940ED3631C003CULL,
		0x7AECE90C3C215F9DULL,
		0x2AAC62C6EA2C004CULL,
		0x1DE61031201E1186ULL,
		0xE5128FBE49297D9AULL,
		0xACBB6A1D82A04DA2ULL,
		0x6F2E0BFA1883A4ADULL,
		0x178154AC6339531CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF281DA6C6380078ULL,
		0xF5D9D2187842BF3AULL,
		0x5558C58DD4580098ULL,
		0x3BCC2062403C230CULL,
		0xCA251F7C9252FB34ULL,
		0x5976D43B05409B45ULL,
		0xDE5C17F43107495BULL,
		0x2F02A958C672A638ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8EF949676B1D5B2BULL,
		0xC368EDEFD098BD16ULL,
		0x0CBC7D284CF18F95ULL,
		0xAF328A67BADEFA97ULL,
		0x4C2E8852B4E95B09ULL,
		0x43246B75608D7AA2ULL,
		0x659E49B3DBF8BF84ULL,
		0x2BAD108270473A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF292CED63AB656ULL,
		0x86D1DBDFA1317A2DULL,
		0x1978FA5099E31F2BULL,
		0x5E6514CF75BDF52EULL,
		0x985D10A569D2B613ULL,
		0x8648D6EAC11AF544ULL,
		0xCB3C9367B7F17F08ULL,
		0x575A2104E08E7402ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC8025AB8A1A753AULL,
		0xB33368C56BF327A5ULL,
		0xDB4C94E022795DDCULL,
		0x20D31A43BE85682AULL,
		0xC13AE6967633F242ULL,
		0x7E8FB656F56DD7B8ULL,
		0x1B741080C510D71AULL,
		0x1D8045892BC26011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59004B571434EA74ULL,
		0x6666D18AD7E64F4BULL,
		0xB69929C044F2BBB9ULL,
		0x41A634877D0AD055ULL,
		0x8275CD2CEC67E484ULL,
		0xFD1F6CADEADBAF71ULL,
		0x36E821018A21AE34ULL,
		0x3B008B125784C022ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA3D4021DB93C7306ULL,
		0xC79D2F7B3EFCC4C5ULL,
		0x734A657964EC90E3ULL,
		0x2818CA5ABEBF8409ULL,
		0x9F1838AF04848E2DULL,
		0xA3F773DEC6A2634CULL,
		0xB8060CD647073A23ULL,
		0x385A443C4B350B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A8043B7278E60CULL,
		0x8F3A5EF67DF9898BULL,
		0xE694CAF2C9D921C7ULL,
		0x503194B57D7F0812ULL,
		0x3E30715E09091C5AULL,
		0x47EEE7BD8D44C699ULL,
		0x700C19AC8E0E7447ULL,
		0x70B48878966A1701ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6377D0E8CD899456ULL,
		0xDBAE24176FD9A6B9ULL,
		0x84EF88E3A7E1F6A0ULL,
		0x9132B58BE5E5611BULL,
		0xC39D8E3496BE4C86ULL,
		0x846E44EE26BA3B93ULL,
		0x974EB26EE5D7CC70ULL,
		0x31B47D670E907740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6EFA1D19B1328ACULL,
		0xB75C482EDFB34D72ULL,
		0x09DF11C74FC3ED41ULL,
		0x22656B17CBCAC237ULL,
		0x873B1C692D7C990DULL,
		0x08DC89DC4D747727ULL,
		0x2E9D64DDCBAF98E1ULL,
		0x6368FACE1D20EE81ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x82E333C0CD4EF22CULL,
		0x5B814471EE2A371CULL,
		0x06AF7B21D97FDC2FULL,
		0x30F1E1884A3CDE66ULL,
		0xEC723B820925F75FULL,
		0xA744057CC83BC181ULL,
		0x38D5C9471C3F31CCULL,
		0x077C060A53DF84A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C667819A9DE458ULL,
		0xB70288E3DC546E39ULL,
		0x0D5EF643B2FFB85EULL,
		0x61E3C3109479BCCCULL,
		0xD8E47704124BEEBEULL,
		0x4E880AF990778303ULL,
		0x71AB928E387E6399ULL,
		0x0EF80C14A7BF0948ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x94207BBDBA0878E8ULL,
		0x69749C50A975C6CCULL,
		0x9CEE976940699D98ULL,
		0xA5679E97EABE53F8ULL,
		0x82E1F4B42A06736CULL,
		0x59A323E65209775CULL,
		0x224F415066A0C85BULL,
		0x10B47A773142F9F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2840F77B7410F1D0ULL,
		0xD2E938A152EB8D99ULL,
		0x39DD2ED280D33B30ULL,
		0x4ACF3D2FD57CA7F1ULL,
		0x05C3E968540CE6D9ULL,
		0xB34647CCA412EEB9ULL,
		0x449E82A0CD4190B6ULL,
		0x2168F4EE6285F3EAULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x98C5F94DA538B00BULL,
		0x5D0E7A61D7DCD165ULL,
		0xBD9E0381A623D528ULL,
		0xFE97B1221105F16FULL,
		0x5B6B25E2F2981255ULL,
		0xBA2B5035CD2CCC59ULL,
		0x65C6FB485556FBBEULL,
		0x13A091FC60D1EFD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x318BF29B4A716016ULL,
		0xBA1CF4C3AFB9A2CBULL,
		0x7B3C07034C47AA50ULL,
		0xFD2F6244220BE2DFULL,
		0xB6D64BC5E53024ABULL,
		0x7456A06B9A5998B2ULL,
		0xCB8DF690AAADF77DULL,
		0x274123F8C1A3DFB0ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEB8DEB2E46465BEAULL,
		0x0C500BAEE0F616B0ULL,
		0x94696F9B1995F823ULL,
		0x37D5832F759F9CBFULL,
		0xEA161ABA19C48909ULL,
		0xE206F240C0BC7AFFULL,
		0x95BDF0B452D4A610ULL,
		0x1C5A0A3EF0D4F83EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71BD65C8C8CB7D4ULL,
		0x18A0175DC1EC2D61ULL,
		0x28D2DF36332BF046ULL,
		0x6FAB065EEB3F397FULL,
		0xD42C357433891212ULL,
		0xC40DE4818178F5FFULL,
		0x2B7BE168A5A94C21ULL,
		0x38B4147DE1A9F07DULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6237328A8AF44E6CULL,
		0xF4208B1AF759CE21ULL,
		0x82720DA4AA2211D8ULL,
		0x3B55DE1605F34597ULL,
		0x0D7F4CE3DCE558CAULL,
		0x54DE70721D851B4AULL,
		0xB073DFB417BBBFF5ULL,
		0x28CB9BAEB1712A77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46E651515E89CD8ULL,
		0xE8411635EEB39C42ULL,
		0x04E41B49544423B1ULL,
		0x76ABBC2C0BE68B2FULL,
		0x1AFE99C7B9CAB194ULL,
		0xA9BCE0E43B0A3694ULL,
		0x60E7BF682F777FEAULL,
		0x5197375D62E254EFULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF4CDF54A97C92EEEULL,
		0x53DFB89482418948ULL,
		0xE390744169823554ULL,
		0xA065B181B38EE5D6ULL,
		0x8741ACE1BA68506CULL,
		0xB8347C14FA50B2D4ULL,
		0xBBDCF9FFC576BE8EULL,
		0x15525862A7967575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99BEA952F925DDCULL,
		0xA7BF712904831291ULL,
		0xC720E882D3046AA8ULL,
		0x40CB6303671DCBADULL,
		0x0E8359C374D0A0D9ULL,
		0x7068F829F4A165A9ULL,
		0x77B9F3FF8AED7D1DULL,
		0x2AA4B0C54F2CEAEBULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x91C315A64A514D33ULL,
		0xDC240C716E6722A5ULL,
		0x79EA42268B1B225CULL,
		0x2F54A6F4D20BEF26ULL,
		0x28B067DEF219EFB0ULL,
		0x268815CB8F78A68DULL,
		0x07E8F151865D8044ULL,
		0x29889D4FE3930D69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23862B4C94A29A66ULL,
		0xB84818E2DCCE454BULL,
		0xF3D4844D163644B9ULL,
		0x5EA94DE9A417DE4CULL,
		0x5160CFBDE433DF60ULL,
		0x4D102B971EF14D1AULL,
		0x0FD1E2A30CBB0088ULL,
		0x53113A9FC7261AD2ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB9BAB5DECF57F4B5ULL,
		0xCFD9864E97AF4C06ULL,
		0xB9E643094F8B90B4ULL,
		0x9C2A8603997AED88ULL,
		0x8DAFD603275D4D34ULL,
		0x967B87759EB83BB4ULL,
		0x70D97D94D5B6ED9FULL,
		0x350791764CE665EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73756BBD9EAFE96AULL,
		0x9FB30C9D2F5E980DULL,
		0x73CC86129F172169ULL,
		0x38550C0732F5DB11ULL,
		0x1B5FAC064EBA9A69ULL,
		0x2CF70EEB3D707769ULL,
		0xE1B2FB29AB6DDB3FULL,
		0x6A0F22EC99CCCBD6ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x24C5CA243EF98FC0ULL,
		0x3C6A2A3C2EBFD676ULL,
		0xF2A4F92DD41B4569ULL,
		0x0DCF1BA6E2D9DA87ULL,
		0x409ABA22CCA5E699ULL,
		0x4C0E49DF9B0EB191ULL,
		0xB642F6B8F1FA6973ULL,
		0x0A5B902D5441945BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x498B94487DF31F80ULL,
		0x78D454785D7FACECULL,
		0xE549F25BA8368AD2ULL,
		0x1B9E374DC5B3B50FULL,
		0x81357445994BCD32ULL,
		0x981C93BF361D6322ULL,
		0x6C85ED71E3F4D2E6ULL,
		0x14B7205AA88328B7ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x354FADB10F27B8C1ULL,
		0x1A9D2EDC4F7F65ACULL,
		0x5F407709CDF293B7ULL,
		0xE612EB762B7DE8A5ULL,
		0x252295E5D8B86C1EULL,
		0x9BEAB91E0E6FF51EULL,
		0x2D0D9219C8AFAE42ULL,
		0x1DFE6228BC86ADD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9F5B621E4F7182ULL,
		0x353A5DB89EFECB58ULL,
		0xBE80EE139BE5276EULL,
		0xCC25D6EC56FBD14AULL,
		0x4A452BCBB170D83DULL,
		0x37D5723C1CDFEA3CULL,
		0x5A1B2433915F5C85ULL,
		0x3BFCC451790D5BAAULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x50AF333353887826ULL,
		0xF9AA395DCCB36794ULL,
		0x44913E78D8876034ULL,
		0x5EC0B5E04FADBF2CULL,
		0x7525E3E950A4735CULL,
		0x20590B602C78C712ULL,
		0xB4C415A45142679AULL,
		0x1E56D4BF3D5517A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15E6666A710F04CULL,
		0xF35472BB9966CF28ULL,
		0x89227CF1B10EC069ULL,
		0xBD816BC09F5B7E58ULL,
		0xEA4BC7D2A148E6B8ULL,
		0x40B216C058F18E24ULL,
		0x69882B48A284CF34ULL,
		0x3CADA97E7AAA2F53ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x303DDC155FF08480ULL,
		0x4235C3ED28072999ULL,
		0x37358D91F387E928ULL,
		0x4BD90945E9A138EAULL,
		0xB3F34BA2FBEC37F2ULL,
		0xB98D52BC69D32B24ULL,
		0x496859FB85A1F537ULL,
		0x0E536EF0B4170A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x607BB82ABFE10900ULL,
		0x846B87DA500E5332ULL,
		0x6E6B1B23E70FD250ULL,
		0x97B2128BD34271D4ULL,
		0x67E69745F7D86FE4ULL,
		0x731AA578D3A65649ULL,
		0x92D0B3F70B43EA6FULL,
		0x1CA6DDE1682E1478ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x649329477EB29FD7ULL,
		0x3F874B89458D7C59ULL,
		0xD41B5474C1F26CA5ULL,
		0x2218AC967434644FULL,
		0x401E092F768743EAULL,
		0xF9E9AAB52B9FE951ULL,
		0x0ACF68C94BB4BFB6ULL,
		0x081013315BA1CE75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC926528EFD653FAEULL,
		0x7F0E97128B1AF8B2ULL,
		0xA836A8E983E4D94AULL,
		0x4431592CE868C89FULL,
		0x803C125EED0E87D4ULL,
		0xF3D3556A573FD2A2ULL,
		0x159ED19297697F6DULL,
		0x10202662B7439CEAULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB11C02BC9CD2ADFAULL,
		0x8936D68E740AF64BULL,
		0x7AAEB4FCF8BE2266ULL,
		0x74F3B0A11D2DA22BULL,
		0xB074216FCF765E71ULL,
		0xA67BE480EBB70B3AULL,
		0x3270A5A7162DFCE7ULL,
		0x2AE6EF43BCAAF6F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6238057939A55BF4ULL,
		0x126DAD1CE815EC97ULL,
		0xF55D69F9F17C44CDULL,
		0xE9E761423A5B4456ULL,
		0x60E842DF9EECBCE2ULL,
		0x4CF7C901D76E1675ULL,
		0x64E14B4E2C5BF9CFULL,
		0x55CDDE877955EDEEULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20C4C600C9A0B9B8ULL,
		0xDC57B117C0C1152CULL,
		0xD535CA8C031BA493ULL,
		0xAC0B139263AF4DDFULL,
		0x14A9E0E07AA238CEULL,
		0x4DF6B22FC66C10B9ULL,
		0x1EFF30287ED650F4ULL,
		0x24439C875FE7A90BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41898C0193417370ULL,
		0xB8AF622F81822A58ULL,
		0xAA6B951806374927ULL,
		0x58162724C75E9BBFULL,
		0x2953C1C0F544719DULL,
		0x9BED645F8CD82172ULL,
		0x3DFE6050FDACA1E8ULL,
		0x4887390EBFCF5216ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFC3B7A66ABA06FF3ULL,
		0x0913CFB3EBF4BA9CULL,
		0xFB4C5EEA15EC63A2ULL,
		0x522F1CA1FC9E4E7CULL,
		0x6917DD6855947B59ULL,
		0x1929DC30D9623AC6ULL,
		0xF13104C039B0A2E1ULL,
		0x014520730220D1C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF876F4CD5740DFE6ULL,
		0x12279F67D7E97539ULL,
		0xF698BDD42BD8C744ULL,
		0xA45E3943F93C9CF9ULL,
		0xD22FBAD0AB28F6B2ULL,
		0x3253B861B2C4758CULL,
		0xE2620980736145C2ULL,
		0x028A40E60441A381ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5EA706EBCF965FB8ULL,
		0x454E0422A5C943AEULL,
		0x03B0D64CE705C1E8ULL,
		0x9817673C38FB84DDULL,
		0xA23BCCA5CEDDB0B7ULL,
		0x04A0B6D9FA8B8EFBULL,
		0xAA29327E95984C5AULL,
		0x1DC809A07F223BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4E0DD79F2CBF70ULL,
		0x8A9C08454B92875CULL,
		0x0761AC99CE0B83D0ULL,
		0x302ECE7871F709BAULL,
		0x4477994B9DBB616FULL,
		0x09416DB3F5171DF7ULL,
		0x545264FD2B3098B4ULL,
		0x3B901340FE4477F1ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4130C13254D24669ULL,
		0x22B8BB8D492503E9ULL,
		0xDE074DF79A3BE7F9ULL,
		0x27614601B7712AC4ULL,
		0x011F02CD8BCB3766ULL,
		0x590E7C702CD29C6DULL,
		0x8A4D109535DD61B5ULL,
		0x02AE7997D575898CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82618264A9A48CD2ULL,
		0x4571771A924A07D2ULL,
		0xBC0E9BEF3477CFF2ULL,
		0x4EC28C036EE25589ULL,
		0x023E059B17966ECCULL,
		0xB21CF8E059A538DAULL,
		0x149A212A6BBAC36AULL,
		0x055CF32FAAEB1319ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB0136638C4F9EA57ULL,
		0xFB1FE99678188986ULL,
		0xCA07618D7D6E5956ULL,
		0xA4204FB21BBB6718ULL,
		0xEE42BE41077BC977ULL,
		0xC8867B252962E18EULL,
		0xC4F60AB1DE66D279ULL,
		0x0F6D8C7717595931ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6026CC7189F3D4AEULL,
		0xF63FD32CF031130DULL,
		0x940EC31AFADCB2ADULL,
		0x48409F643776CE31ULL,
		0xDC857C820EF792EFULL,
		0x910CF64A52C5C31DULL,
		0x89EC1563BCCDA4F3ULL,
		0x1EDB18EE2EB2B263ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4F984FA976F0C386ULL,
		0xCDD9C21C24FDC03DULL,
		0x515D45CC16DAE3A9ULL,
		0xB40756E0C571B29DULL,
		0x8C17D0AE09758E02ULL,
		0x1695D9C9EA4CFD66ULL,
		0x0C087C8E671B2E71ULL,
		0x0F458A7B035779C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F309F52EDE1870CULL,
		0x9BB3843849FB807AULL,
		0xA2BA8B982DB5C753ULL,
		0x680EADC18AE3653AULL,
		0x182FA15C12EB1C05ULL,
		0x2D2BB393D499FACDULL,
		0x1810F91CCE365CE2ULL,
		0x1E8B14F606AEF380ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x40956A329B522B54ULL,
		0x685E2668CF579A27ULL,
		0x87DAE1346EB1328CULL,
		0xBD970DF4E79D0FB5ULL,
		0xEB17E1EF0562BBDCULL,
		0x536ED0D821B93350ULL,
		0x8049979B8DA0869CULL,
		0x26A1223888D76547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812AD46536A456A8ULL,
		0xD0BC4CD19EAF344EULL,
		0x0FB5C268DD626518ULL,
		0x7B2E1BE9CF3A1F6BULL,
		0xD62FC3DE0AC577B9ULL,
		0xA6DDA1B0437266A1ULL,
		0x00932F371B410D38ULL,
		0x4D42447111AECA8FULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x32414280D8647632ULL,
		0x1ED9D61FE4244B8DULL,
		0x38AFC5965BF7B477ULL,
		0x3723FAA40B3ADB2AULL,
		0xE042A456CEE0A975ULL,
		0x1C6604B2FE421CF8ULL,
		0x5A41693371ADDA28ULL,
		0x092419ECAAD64772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64828501B0C8EC64ULL,
		0x3DB3AC3FC848971AULL,
		0x715F8B2CB7EF68EEULL,
		0x6E47F5481675B654ULL,
		0xC08548AD9DC152EAULL,
		0x38CC0965FC8439F1ULL,
		0xB482D266E35BB450ULL,
		0x124833D955AC8EE4ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3C40C25944D8A4E8ULL,
		0x07B5AFAA5CB9858BULL,
		0xFA4815F4C5101497ULL,
		0x8D2B001BDAC62B7BULL,
		0x85A219DB2D690B55ULL,
		0x019A793C0DD507F5ULL,
		0x0EA9A547B2EB9EC5ULL,
		0x16EAEA06CFDB3159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x788184B289B149D0ULL,
		0x0F6B5F54B9730B16ULL,
		0xF4902BE98A20292EULL,
		0x1A560037B58C56F7ULL,
		0x0B4433B65AD216ABULL,
		0x0334F2781BAA0FEBULL,
		0x1D534A8F65D73D8AULL,
		0x2DD5D40D9FB662B2ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB1958E78DE1A3450ULL,
		0xE2C143B31400ACACULL,
		0xA8C663AF0A771C45ULL,
		0x4306D4D57BD6C9BCULL,
		0x95CEA279BDF335D7ULL,
		0xFBC294563B06EE6BULL,
		0x0CFDB4856B8A00CEULL,
		0x1660437339E98042ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x632B1CF1BC3468A0ULL,
		0xC582876628015959ULL,
		0x518CC75E14EE388BULL,
		0x860DA9AAF7AD9379ULL,
		0x2B9D44F37BE66BAEULL,
		0xF78528AC760DDCD7ULL,
		0x19FB690AD714019DULL,
		0x2CC086E673D30084ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE41BE117C4B60D21ULL,
		0xC70065F9084E84E2ULL,
		0x01BB024770CBA243ULL,
		0x8C7E5647A8B444BDULL,
		0x6AC94EA0FF65F81BULL,
		0x80BCB7688D3BB375ULL,
		0x397E01D779FCBD4BULL,
		0x2E30F922F79FAE3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC837C22F896C1A42ULL,
		0x8E00CBF2109D09C5ULL,
		0x0376048EE1974487ULL,
		0x18FCAC8F5168897AULL,
		0xD5929D41FECBF037ULL,
		0x01796ED11A7766EAULL,
		0x72FC03AEF3F97A97ULL,
		0x5C61F245EF3F5C7EULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6E50CB14E26DD4A4ULL,
		0xA37AE9C6EE599A2BULL,
		0x10B6A1451C694399ULL,
		0xFBFC89F5EC1AA96FULL,
		0xC123C69ED71D92C0ULL,
		0xC98711939385342EULL,
		0x30A0B1D6E36E9F00ULL,
		0x28291094AD049488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA19629C4DBA948ULL,
		0x46F5D38DDCB33456ULL,
		0x216D428A38D28733ULL,
		0xF7F913EBD83552DEULL,
		0x82478D3DAE3B2581ULL,
		0x930E2327270A685DULL,
		0x614163ADC6DD3E01ULL,
		0x505221295A092910ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x07DFA63B0BDBA644ULL,
		0x8FBADB5E5C64178CULL,
		0x0A290D2526ADA291ULL,
		0x5E54E6699D96589AULL,
		0x6F38756A4E9134A8ULL,
		0x1A89CFDDE03488B5ULL,
		0x6C959E310294F7E0ULL,
		0x29D132DB40B9AEAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FBF4C7617B74C88ULL,
		0x1F75B6BCB8C82F18ULL,
		0x14521A4A4D5B4523ULL,
		0xBCA9CCD33B2CB134ULL,
		0xDE70EAD49D226950ULL,
		0x35139FBBC069116AULL,
		0xD92B3C620529EFC0ULL,
		0x53A265B681735D5EULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF680A8BDFE7D4CDAULL,
		0x32FE1222F92F35DAULL,
		0x47AB66A811BD7B33ULL,
		0x17684224DEFA9154ULL,
		0x132D8825B56231E3ULL,
		0xF3B7540C26179655ULL,
		0xD52436A8DF6305B7ULL,
		0x39BCE02E0DC84E48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED01517BFCFA99B4ULL,
		0x65FC2445F25E6BB5ULL,
		0x8F56CD50237AF666ULL,
		0x2ED08449BDF522A8ULL,
		0x265B104B6AC463C6ULL,
		0xE76EA8184C2F2CAAULL,
		0xAA486D51BEC60B6FULL,
		0x7379C05C1B909C91ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEE220974596FE95FULL,
		0x1EDC525FAF4DD37DULL,
		0x0E2B1907213D7E1EULL,
		0x2A32C73CA4BE5198ULL,
		0xC2BBE5BB672A7F8EULL,
		0x2B553E71DE44B534ULL,
		0xB4EB92E441E8135BULL,
		0x0DA8DB2CE542DE1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC4412E8B2DFD2BEULL,
		0x3DB8A4BF5E9BA6FBULL,
		0x1C56320E427AFC3CULL,
		0x54658E79497CA330ULL,
		0x8577CB76CE54FF1CULL,
		0x56AA7CE3BC896A69ULL,
		0x69D725C883D026B6ULL,
		0x1B51B659CA85BC37ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x05A4201888853B31ULL,
		0xA30D6A18F63F4DA6ULL,
		0x3B495B1153C31360ULL,
		0xA86735E40B4F297BULL,
		0x816C4CB6EDEA2F5BULL,
		0x528F9841F7C32D01ULL,
		0xB7DDD1B8FD154344ULL,
		0x07475E7BC8DF6585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B484031110A7662ULL,
		0x461AD431EC7E9B4CULL,
		0x7692B622A78626C1ULL,
		0x50CE6BC8169E52F6ULL,
		0x02D8996DDBD45EB7ULL,
		0xA51F3083EF865A03ULL,
		0x6FBBA371FA2A8688ULL,
		0x0E8EBCF791BECB0BULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x91B941FA2F8D7893ULL,
		0x2DF3932D02F4EDE8ULL,
		0xD26908988055F750ULL,
		0x9477C63E285B04B3ULL,
		0x24B4EC96C1D191E7ULL,
		0xDDC66D383EB6C8B5ULL,
		0x92C420857DECCB53ULL,
		0x12411722C4EF85B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x237283F45F1AF126ULL,
		0x5BE7265A05E9DBD1ULL,
		0xA4D2113100ABEEA0ULL,
		0x28EF8C7C50B60967ULL,
		0x4969D92D83A323CFULL,
		0xBB8CDA707D6D916AULL,
		0x2588410AFBD996A7ULL,
		0x24822E4589DF0B69ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF3A74D8A900E3BC9ULL,
		0x24E676745158C3A3ULL,
		0xADBF392E9FCD57AAULL,
		0xA1FA465D8E35A7E9ULL,
		0xC13CC8419E65E85DULL,
		0x6A4FE579E7C04B83ULL,
		0xAE64DA46B86034E1ULL,
		0x3E9720615E6B8F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE74E9B15201C7792ULL,
		0x49CCECE8A2B18747ULL,
		0x5B7E725D3F9AAF54ULL,
		0x43F48CBB1C6B4FD3ULL,
		0x827990833CCBD0BBULL,
		0xD49FCAF3CF809707ULL,
		0x5CC9B48D70C069C2ULL,
		0x7D2E40C2BCD71EE1ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD9237E5D3CAA7746ULL,
		0x1230F66BBCC0FB78ULL,
		0xA0F504C1EBD99125ULL,
		0xCBB6F5FD19BEA019ULL,
		0xA11122EFA9F31C56ULL,
		0xA87EB73778626F18ULL,
		0xF5549B7DD3C81ADDULL,
		0x092950736675FA13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB246FCBA7954EE8CULL,
		0x2461ECD77981F6F1ULL,
		0x41EA0983D7B3224AULL,
		0x976DEBFA337D4033ULL,
		0x422245DF53E638ADULL,
		0x50FD6E6EF0C4DE31ULL,
		0xEAA936FBA79035BBULL,
		0x1252A0E6CCEBF427ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE49830AEB66AEC22ULL,
		0x43FD491AEF98F6A3ULL,
		0x13F224331699ADE7ULL,
		0xB0DD78919E9A484FULL,
		0xEF44C9554F91352AULL,
		0x1D8D3DEEBA5F4CBBULL,
		0xB75D07E11432B03DULL,
		0x1D593BC6D393169DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC930615D6CD5D844ULL,
		0x87FA9235DF31ED47ULL,
		0x27E448662D335BCEULL,
		0x61BAF1233D34909EULL,
		0xDE8992AA9F226A55ULL,
		0x3B1A7BDD74BE9977ULL,
		0x6EBA0FC22865607AULL,
		0x3AB2778DA7262D3BULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDD72E343D88F0EB4ULL,
		0x44B0C54643AAD513ULL,
		0xD16D046000C87753ULL,
		0xEB0BD00AE2BA8A3CULL,
		0x24089C1C18107472ULL,
		0x14A26FAAE3990367ULL,
		0xFD4BD505278323DBULL,
		0x1AA62CFBB7FFF26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAE5C687B11E1D68ULL,
		0x89618A8C8755AA27ULL,
		0xA2DA08C00190EEA6ULL,
		0xD617A015C5751479ULL,
		0x481138383020E8E5ULL,
		0x2944DF55C73206CEULL,
		0xFA97AA0A4F0647B6ULL,
		0x354C59F76FFFE4DBULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x392A94E9170B1367ULL,
		0x7A1E98B8A08050F0ULL,
		0x806CE5C6685C4AC4ULL,
		0xCDCF06203280C51CULL,
		0x704474F5F106CE10ULL,
		0x197284AC3D96A8D7ULL,
		0x237A69F723B75C88ULL,
		0x2BE49F8C611F463EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x725529D22E1626CEULL,
		0xF43D31714100A1E0ULL,
		0x00D9CB8CD0B89588ULL,
		0x9B9E0C4065018A39ULL,
		0xE088E9EBE20D9C21ULL,
		0x32E509587B2D51AEULL,
		0x46F4D3EE476EB910ULL,
		0x57C93F18C23E8C7CULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x952E772922F4A5D2ULL,
		0xC72BAB7C56162C1EULL,
		0x638B6942CE9A8336ULL,
		0x9EC284040D0119FCULL,
		0xB42ADD712FC6AAB2ULL,
		0x58947085BE7C503DULL,
		0x4F8E3A53140503DCULL,
		0x14DFFE110DA996E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A5CEE5245E94BA4ULL,
		0x8E5756F8AC2C583DULL,
		0xC716D2859D35066DULL,
		0x3D8508081A0233F8ULL,
		0x6855BAE25F8D5565ULL,
		0xB128E10B7CF8A07BULL,
		0x9F1C74A6280A07B8ULL,
		0x29BFFC221B532DC4ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3FD3346662E64669ULL,
		0x7FE5F98AEB522E6BULL,
		0xF38C291CB6CAFBBAULL,
		0x9389E9F52FF805D3ULL,
		0x6EB909DC8D501D3EULL,
		0xAC82DCFACCA0E724ULL,
		0x7187012D9A20A529ULL,
		0x18D8E71BC75C0765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA668CCC5CC8CD2ULL,
		0xFFCBF315D6A45CD6ULL,
		0xE71852396D95F774ULL,
		0x2713D3EA5FF00BA7ULL,
		0xDD7213B91AA03A7DULL,
		0x5905B9F59941CE48ULL,
		0xE30E025B34414A53ULL,
		0x31B1CE378EB80ECAULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x04E1F52E437EBB76ULL,
		0xFB78B97E5674EF06ULL,
		0x36EE3FFBFD6D92EFULL,
		0x461EF322B150614EULL,
		0xCCEBBCBD8CAC3FE2ULL,
		0x662745898763EE73ULL,
		0xB0CD6A33FB7CB91AULL,
		0x1C6FA8895E7BBF84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C3EA5C86FD76ECULL,
		0xF6F172FCACE9DE0CULL,
		0x6DDC7FF7FADB25DFULL,
		0x8C3DE64562A0C29CULL,
		0x99D7797B19587FC4ULL,
		0xCC4E8B130EC7DCE7ULL,
		0x619AD467F6F97234ULL,
		0x38DF5112BCF77F09ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD575854EB91C213AULL,
		0x486C171C153762FCULL,
		0x7CCA15F264ED547EULL,
		0x658EE2EB389A81ADULL,
		0xE1DE1219657A99F9ULL,
		0xC8EA1E9C2775A1C1ULL,
		0xE596D5438AA2BE0EULL,
		0x294CAF4840BF9CFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAEB0A9D72384274ULL,
		0x90D82E382A6EC5F9ULL,
		0xF9942BE4C9DAA8FCULL,
		0xCB1DC5D67135035AULL,
		0xC3BC2432CAF533F2ULL,
		0x91D43D384EEB4383ULL,
		0xCB2DAA8715457C1DULL,
		0x52995E90817F39FFULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x23A04529C7187B6BULL,
		0x762ACA30C42F3934ULL,
		0xDDFC768120DB361AULL,
		0x688201E53BD85C21ULL,
		0x6B68740332F73D5DULL,
		0xD39527D033E3D30AULL,
		0xBE9379C704ED9BBEULL,
		0x3E4EFD3A9F9B4AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47408A538E30F6D6ULL,
		0xEC559461885E7268ULL,
		0xBBF8ED0241B66C34ULL,
		0xD10403CA77B0B843ULL,
		0xD6D0E80665EE7ABAULL,
		0xA72A4FA067C7A614ULL,
		0x7D26F38E09DB377DULL,
		0x7C9DFA753F369559ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x721BF4CE4BC82558ULL,
		0x24EEAC2E4B8E5B04ULL,
		0x89DC9AF138BCB4C1ULL,
		0x850080ECE3E135AFULL,
		0xB88D6689E9054DD6ULL,
		0xC813410AF8151E2DULL,
		0x237615FBED62EAEAULL,
		0x12C67B070C225540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE437E99C97904AB0ULL,
		0x49DD585C971CB608ULL,
		0x13B935E271796982ULL,
		0x0A0101D9C7C26B5FULL,
		0x711ACD13D20A9BADULL,
		0x90268215F02A3C5BULL,
		0x46EC2BF7DAC5D5D5ULL,
		0x258CF60E1844AA80ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB418763A88F3987BULL,
		0xF949FABC1A3A421FULL,
		0xD381ADEBB32CBB37ULL,
		0xD4F158D1F0F74F71ULL,
		0xC8CE5BEC4D62E143ULL,
		0xF9D6DD6AE93C5796ULL,
		0x264EC9F3263962B6ULL,
		0x05AB0928235EFB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6830EC7511E730F6ULL,
		0xF293F5783474843FULL,
		0xA7035BD76659766FULL,
		0xA9E2B1A3E1EE9EE3ULL,
		0x919CB7D89AC5C287ULL,
		0xF3ADBAD5D278AF2DULL,
		0x4C9D93E64C72C56DULL,
		0x0B56125046BDF654ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x502C823209230955ULL,
		0x46859450C0D70EA4ULL,
		0x51A90BBFFC1B44EBULL,
		0x8DC7CFD8DF6858E9ULL,
		0x84D7AC4874C65765ULL,
		0xACC9C6DE2181547FULL,
		0x382BB52E64DDE40EULL,
		0x20BFA70C224B4EC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0590464124612AAULL,
		0x8D0B28A181AE1D48ULL,
		0xA352177FF83689D6ULL,
		0x1B8F9FB1BED0B1D2ULL,
		0x09AF5890E98CAECBULL,
		0x59938DBC4302A8FFULL,
		0x70576A5CC9BBC81DULL,
		0x417F4E1844969D80ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD576174A7802EF7AULL,
		0x0C5CFFB41A9743B4ULL,
		0xE99CDEE8DDDDA8B8ULL,
		0xF2913C53A240CD44ULL,
		0x4C514B911A684509ULL,
		0xC9AC80D122F6339BULL,
		0xEDDBF626E3F5238BULL,
		0x2A6FC6159EC1069CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAEC2E94F005DEF4ULL,
		0x18B9FF68352E8769ULL,
		0xD339BDD1BBBB5170ULL,
		0xE52278A744819A89ULL,
		0x98A2972234D08A13ULL,
		0x935901A245EC6736ULL,
		0xDBB7EC4DC7EA4717ULL,
		0x54DF8C2B3D820D39ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4C537605BAD8C7E9ULL,
		0x3AE060F6FA87E49DULL,
		0xDFDE64D041CD5A3EULL,
		0x96BCF1EDB3E1B82CULL,
		0xB1FD9E721C895F1AULL,
		0x8290BE00BCAC777CULL,
		0xEDA0929DA70F7411ULL,
		0x33BB11EEC03E3937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A6EC0B75B18FD2ULL,
		0x75C0C1EDF50FC93AULL,
		0xBFBCC9A0839AB47CULL,
		0x2D79E3DB67C37059ULL,
		0x63FB3CE43912BE35ULL,
		0x05217C017958EEF9ULL,
		0xDB41253B4E1EE823ULL,
		0x677623DD807C726FULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4A98B2B34327C0CEULL,
		0xB38AC0A5F0AC35E7ULL,
		0x372D1CA1A14E0AFEULL,
		0x5B90D2CF0D02142AULL,
		0xEE3B423CD09ABA6EULL,
		0x09E664AA3FDCD41BULL,
		0x0BF57C14A515FBBFULL,
		0x0A538B227A435B9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95316566864F819CULL,
		0x6715814BE1586BCEULL,
		0x6E5A3943429C15FDULL,
		0xB721A59E1A042854ULL,
		0xDC768479A13574DCULL,
		0x13CCC9547FB9A837ULL,
		0x17EAF8294A2BF77EULL,
		0x14A71644F486B73EULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20238463001B22E4ULL,
		0x3539984878CED88FULL,
		0x14D01529825CFF94ULL,
		0x2958F1864BB5D222ULL,
		0x7CF16FFCC28B9126ULL,
		0x92E549B199756A95ULL,
		0xA90FF80AD4DFE227ULL,
		0x21A737165081129BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x404708C6003645C8ULL,
		0x6A733090F19DB11EULL,
		0x29A02A5304B9FF28ULL,
		0x52B1E30C976BA444ULL,
		0xF9E2DFF98517224CULL,
		0x25CA936332EAD52AULL,
		0x521FF015A9BFC44FULL,
		0x434E6E2CA1022537ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x75E8B8FA6C2AD9CDULL,
		0xC1299D31BB7C7461ULL,
		0x2EFFF6B2DF7912A4ULL,
		0x831DA3F7C7EA6520ULL,
		0x068B9C7BADE0891CULL,
		0x33F588FF33F2058FULL,
		0x1ED89504E377E0A7ULL,
		0x325907C02EA42B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBD171F4D855B39AULL,
		0x82533A6376F8E8C2ULL,
		0x5DFFED65BEF22549ULL,
		0x063B47EF8FD4CA40ULL,
		0x0D1738F75BC11239ULL,
		0x67EB11FE67E40B1EULL,
		0x3DB12A09C6EFC14EULL,
		0x64B20F805D48569AULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x689596A2B99813BDULL,
		0x545A58B04E0F01DAULL,
		0xEB8A50D8C7FABCBAULL,
		0xCF9CF88779C5082FULL,
		0x668FB71972FC0E32ULL,
		0x2A4FB1A79D311B6DULL,
		0x1694C620A601586EULL,
		0x237F6DBBCFAAEA86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12B2D457330277AULL,
		0xA8B4B1609C1E03B4ULL,
		0xD714A1B18FF57974ULL,
		0x9F39F10EF38A105FULL,
		0xCD1F6E32E5F81C65ULL,
		0x549F634F3A6236DAULL,
		0x2D298C414C02B0DCULL,
		0x46FEDB779F55D50CULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x313772B1291087E0ULL,
		0xF1A72BA237B0E988ULL,
		0x88296F19C099B76AULL,
		0xFAE13FA503A95B45ULL,
		0x33FB0FA3E7387B08ULL,
		0x8AE4895C7BE4C3ABULL,
		0x367C58A8A5ACB480ULL,
		0x370DE61951E9399AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x626EE56252210FC0ULL,
		0xE34E57446F61D310ULL,
		0x1052DE3381336ED5ULL,
		0xF5C27F4A0752B68BULL,
		0x67F61F47CE70F611ULL,
		0x15C912B8F7C98756ULL,
		0x6CF8B1514B596901ULL,
		0x6E1BCC32A3D27334ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2EA6B17503805CE8ULL,
		0x1AA9625696247326ULL,
		0x598DBBB4A302FF6BULL,
		0x52435D7D66C5A9CAULL,
		0x6B6D5DE4CA96B687ULL,
		0x8FFC3FF85CA3D4D1ULL,
		0x1FF0EFB76C00A0CFULL,
		0x09814AE318401328ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4D62EA0700B9D0ULL,
		0x3552C4AD2C48E64CULL,
		0xB31B77694605FED6ULL,
		0xA486BAFACD8B5394ULL,
		0xD6DABBC9952D6D0EULL,
		0x1FF87FF0B947A9A2ULL,
		0x3FE1DF6ED801419FULL,
		0x130295C630802650ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0BFB31A804F8C286ULL,
		0x32BB99636028F61DULL,
		0xF9C24E5BBD41BBADULL,
		0x5FE230D32F861FCFULL,
		0x35668D68969A4DDFULL,
		0x0E166FB371DC5DDDULL,
		0x493E3103973A475DULL,
		0x292EA7C0CC6AFCAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F6635009F1850CULL,
		0x657732C6C051EC3AULL,
		0xF3849CB77A83775AULL,
		0xBFC461A65F0C3F9FULL,
		0x6ACD1AD12D349BBEULL,
		0x1C2CDF66E3B8BBBAULL,
		0x927C62072E748EBAULL,
		0x525D4F8198D5F95CULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBB81843D9A1EFE96ULL,
		0x06BB3CF0B4EA85B9ULL,
		0x51759476E362F222ULL,
		0x1F75402B81DF9D38ULL,
		0x187304CF2B41573CULL,
		0x0C04010F4A063869ULL,
		0x30CF929F7BDB3FDAULL,
		0x05AA4282A037CF0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7703087B343DFD2CULL,
		0x0D7679E169D50B73ULL,
		0xA2EB28EDC6C5E444ULL,
		0x3EEA805703BF3A70ULL,
		0x30E6099E5682AE78ULL,
		0x1808021E940C70D2ULL,
		0x619F253EF7B67FB4ULL,
		0x0B548505406F9E1AULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAE7DDF3FA2133E16ULL,
		0xA3459019B2FBD6A2ULL,
		0xB63BBC95900A759FULL,
		0xED91EA1FE468B77CULL,
		0x2F01AF91A1413631ULL,
		0x8CBB9081C2FF0F8EULL,
		0x89C3C52689CBF1EDULL,
		0x1D2861303B90A8DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CFBBE7F44267C2CULL,
		0x468B203365F7AD45ULL,
		0x6C77792B2014EB3FULL,
		0xDB23D43FC8D16EF9ULL,
		0x5E035F2342826C63ULL,
		0x1977210385FE1F1CULL,
		0x13878A4D1397E3DBULL,
		0x3A50C260772151B9ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA7CF119EFA00B0C2ULL,
		0xA168CBA4A20094DFULL,
		0x9E39B3D8CD5C4D06ULL,
		0x5265FABE62F6A43DULL,
		0x238F3C91FBBE89F5ULL,
		0xE341E390715CBA43ULL,
		0x0F003DF0B0AED5FBULL,
		0x3AA1ADFFAF5EC0B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F9E233DF4016184ULL,
		0x42D19749440129BFULL,
		0x3C7367B19AB89A0DULL,
		0xA4CBF57CC5ED487BULL,
		0x471E7923F77D13EAULL,
		0xC683C720E2B97486ULL,
		0x1E007BE1615DABF7ULL,
		0x75435BFF5EBD816AULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA3174B14F893163DULL,
		0xC194C2100EA2196BULL,
		0xC8196452B75B0318ULL,
		0x947C5D2994C71273ULL,
		0xDF2A7B6ABB61C35FULL,
		0x3F79AE6D62B06C98ULL,
		0x0780A6116A363E98ULL,
		0x353C07AEFA963382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462E9629F1262C7AULL,
		0x832984201D4432D7ULL,
		0x9032C8A56EB60631ULL,
		0x28F8BA53298E24E7ULL,
		0xBE54F6D576C386BFULL,
		0x7EF35CDAC560D931ULL,
		0x0F014C22D46C7D30ULL,
		0x6A780F5DF52C6704ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x11D50901D4478826ULL,
		0xF11D351C6E10702CULL,
		0x917802FD83B65E52ULL,
		0xAF3CBC36276E46BEULL,
		0x0681BBB17693C190ULL,
		0xA8756AB963884480ULL,
		0xF156D7F973803812ULL,
		0x0674E634126B2FA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AA1203A88F104CULL,
		0xE23A6A38DC20E058ULL,
		0x22F005FB076CBCA5ULL,
		0x5E79786C4EDC8D7DULL,
		0x0D037762ED278321ULL,
		0x50EAD572C7108900ULL,
		0xE2ADAFF2E7007025ULL,
		0x0CE9CC6824D65F4DULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x564FF7C0C3AC9428ULL,
		0x3A82A9157DFDD68CULL,
		0xAEB82A563533161FULL,
		0x788FA74A0C72CF46ULL,
		0xD2EC3A9C4747444BULL,
		0x510081C89E770515ULL,
		0x35453AF426760FDEULL,
		0x3C5E6528CDC79A5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC9FEF8187592850ULL,
		0x7505522AFBFBAD18ULL,
		0x5D7054AC6A662C3EULL,
		0xF11F4E9418E59E8DULL,
		0xA5D875388E8E8896ULL,
		0xA20103913CEE0A2BULL,
		0x6A8A75E84CEC1FBCULL,
		0x78BCCA519B8F34BCULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x672B45D655DE40ECULL,
		0x9815C683F6D8F93BULL,
		0xCE0D6616157E30AFULL,
		0xF278DFD8FB8FC5A5ULL,
		0xF5EDACF965383A35ULL,
		0xD4DB97BD3CEB99B9ULL,
		0x6F8C69C4E646C551ULL,
		0x225D5DD68FA8DAAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE568BACABBC81D8ULL,
		0x302B8D07EDB1F276ULL,
		0x9C1ACC2C2AFC615FULL,
		0xE4F1BFB1F71F8B4BULL,
		0xEBDB59F2CA70746BULL,
		0xA9B72F7A79D73373ULL,
		0xDF18D389CC8D8AA3ULL,
		0x44BABBAD1F51B55EULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x839AE4D5F39E361AULL,
		0x620C3941880723DCULL,
		0x5EBA0B90CFCFEE31ULL,
		0xCC3D4D849DA26999ULL,
		0xBB3CA558DCEF79F2ULL,
		0xC9B3BA8C49DC4A00ULL,
		0x1E44BB5EFA69B039ULL,
		0x280B356754C9612AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0735C9ABE73C6C34ULL,
		0xC4187283100E47B9ULL,
		0xBD7417219F9FDC62ULL,
		0x987A9B093B44D332ULL,
		0x76794AB1B9DEF3E5ULL,
		0x9367751893B89401ULL,
		0x3C8976BDF4D36073ULL,
		0x50166ACEA992C254ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8616A4980768BC9EULL,
		0x90FF40F4AEE7EB83ULL,
		0x44C07CA02C44CB49ULL,
		0x07B97F2A29AFAFCCULL,
		0xC86750963778D813ULL,
		0x0A0B47F965DC5FC3ULL,
		0xC1E6216FEEAC815DULL,
		0x2F6C165794295E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2D49300ED1793CULL,
		0x21FE81E95DCFD707ULL,
		0x8980F94058899693ULL,
		0x0F72FE54535F5F98ULL,
		0x90CEA12C6EF1B026ULL,
		0x14168FF2CBB8BF87ULL,
		0x83CC42DFDD5902BAULL,
		0x5ED82CAF2852BCE7ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA49A124B8167D317ULL,
		0x1E30AB6EE221CD7CULL,
		0x6C375A57ECFB0AB8ULL,
		0x4562B1B7B31FE6B6ULL,
		0x2A36D3CBAC670058ULL,
		0xA4395A35CBB81844ULL,
		0xFD28FD25ECA911AEULL,
		0x2C0E0F8EAF0E4B17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4934249702CFA62EULL,
		0x3C6156DDC4439AF9ULL,
		0xD86EB4AFD9F61570ULL,
		0x8AC5636F663FCD6CULL,
		0x546DA79758CE00B0ULL,
		0x4872B46B97703088ULL,
		0xFA51FA4BD952235DULL,
		0x581C1F1D5E1C962FULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9F988D73BF737526ULL,
		0x2EDC005D0377FE91ULL,
		0xD07B350F1747F54BULL,
		0x81083E678E6ED5D8ULL,
		0x003327C666250873ULL,
		0x4FB8C8B01C2C2341ULL,
		0x62FD4C3BE71525F2ULL,
		0x28B1D5F2A6B07B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F311AE77EE6EA4CULL,
		0x5DB800BA06EFFD23ULL,
		0xA0F66A1E2E8FEA96ULL,
		0x02107CCF1CDDABB1ULL,
		0x00664F8CCC4A10E7ULL,
		0x9F71916038584682ULL,
		0xC5FA9877CE2A4BE4ULL,
		0x5163ABE54D60F708ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6D148AFEF7B4B628ULL,
		0x4BC3E89C0363648FULL,
		0x309A4C7F5FC463B9ULL,
		0xBEF9CFF84AA6CB2EULL,
		0x500AD60AD2EA620BULL,
		0xCCDCA395D1410D7DULL,
		0x60FB1F8119FC265DULL,
		0x1AA55E65CBB09075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA2915FDEF696C50ULL,
		0x9787D13806C6C91EULL,
		0x613498FEBF88C772ULL,
		0x7DF39FF0954D965CULL,
		0xA015AC15A5D4C417ULL,
		0x99B9472BA2821AFAULL,
		0xC1F63F0233F84CBBULL,
		0x354ABCCB976120EAULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4269ED39170AF213ULL,
		0x452701159664DAA8ULL,
		0x8187C1B8254EA8D1ULL,
		0x2D430E7D438E71E1ULL,
		0xF6542CFBA33A9B4BULL,
		0x86627A116568C9C8ULL,
		0x5B62DF683E02CF35ULL,
		0x0C8DDFE87E94AA74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84D3DA722E15E426ULL,
		0x8A4E022B2CC9B550ULL,
		0x030F83704A9D51A2ULL,
		0x5A861CFA871CE3C3ULL,
		0xECA859F746753696ULL,
		0x0CC4F422CAD19391ULL,
		0xB6C5BED07C059E6BULL,
		0x191BBFD0FD2954E8ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2EEE0A427B120C08ULL,
		0xC5A6CD367CDD3736ULL,
		0xCE85B643D8F6EE4AULL,
		0xE116AE25C66AFA28ULL,
		0x841B8EC06D07949DULL,
		0x6CF2D3B29A1C78D5ULL,
		0x916E0FEC24DCD0B6ULL,
		0x15CFB2777C4B1BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDC1484F6241810ULL,
		0x8B4D9A6CF9BA6E6CULL,
		0x9D0B6C87B1EDDC95ULL,
		0xC22D5C4B8CD5F451ULL,
		0x08371D80DA0F293BULL,
		0xD9E5A7653438F1ABULL,
		0x22DC1FD849B9A16CULL,
		0x2B9F64EEF896375FULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7A10D1AE530DC6B8ULL,
		0xA313AAF495F4C1A4ULL,
		0x50D55864D6A8C638ULL,
		0x8666C941F6240A0FULL,
		0x536334CCFC1AE5AEULL,
		0x7BAD2AD787E6D55DULL,
		0x1D472EDC1A467B64ULL,
		0x3842012B6CC9EDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF421A35CA61B8D70ULL,
		0x462755E92BE98348ULL,
		0xA1AAB0C9AD518C71ULL,
		0x0CCD9283EC48141EULL,
		0xA6C66999F835CB5DULL,
		0xF75A55AF0FCDAABAULL,
		0x3A8E5DB8348CF6C8ULL,
		0x70840256D993DB60ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7B37BCD0ED9E1C7AULL,
		0x6946EB0B8B5398DBULL,
		0x2471DB9D353ED687ULL,
		0xF06F4FD65CD97D40ULL,
		0x2BB2C5FBE3B686C0ULL,
		0x41C990531804298BULL,
		0x9374DCB54F1BAD39ULL,
		0x0AC44F38B790FC16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66F79A1DB3C38F4ULL,
		0xD28DD61716A731B6ULL,
		0x48E3B73A6A7DAD0EULL,
		0xE0DE9FACB9B2FA80ULL,
		0x57658BF7C76D0D81ULL,
		0x839320A630085316ULL,
		0x26E9B96A9E375A72ULL,
		0x15889E716F21F82DULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x625A680D53ADF13EULL,
		0xD50321E00579B594ULL,
		0x738E2EAED7B19300ULL,
		0x7D67204844BB6B81ULL,
		0xCF19A8CA6437B346ULL,
		0xB9E72E3E0993246EULL,
		0x6575B1870577EF7CULL,
		0x2154E9F8B0661534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4B4D01AA75BE27CULL,
		0xAA0643C00AF36B28ULL,
		0xE71C5D5DAF632601ULL,
		0xFACE40908976D702ULL,
		0x9E335194C86F668CULL,
		0x73CE5C7C132648DDULL,
		0xCAEB630E0AEFDEF9ULL,
		0x42A9D3F160CC2A68ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x417818CFF9841569ULL,
		0x7579B92BE5E92F89ULL,
		0x8699E057C2CF3F4BULL,
		0xBEFD42DA663C2162ULL,
		0x616B2AE18B63DC42ULL,
		0xED7FC7E4E806100BULL,
		0xFDC06AF806D2B572ULL,
		0x271BFCDC3879B425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F0319FF3082AD2ULL,
		0xEAF37257CBD25F12ULL,
		0x0D33C0AF859E7E96ULL,
		0x7DFA85B4CC7842C5ULL,
		0xC2D655C316C7B885ULL,
		0xDAFF8FC9D00C2016ULL,
		0xFB80D5F00DA56AE5ULL,
		0x4E37F9B870F3684BULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD151961E7C9E399CULL,
		0x00E53C279DB96C58ULL,
		0xA12A0D59BE0F5CC0ULL,
		0x301834656772370FULL,
		0x4B58F07A6D0D653CULL,
		0x3DBB38C4C8A9A347ULL,
		0x68FBD61B589C226BULL,
		0x17CC4FF8304CD144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2A32C3CF93C7338ULL,
		0x01CA784F3B72D8B1ULL,
		0x42541AB37C1EB980ULL,
		0x603068CACEE46E1FULL,
		0x96B1E0F4DA1ACA78ULL,
		0x7B7671899153468EULL,
		0xD1F7AC36B13844D6ULL,
		0x2F989FF06099A288ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE840B7FF520B220ULL,
		0x4BDA5255061E6A91ULL,
		0x689D692960C82E8FULL,
		0x791D72BA358D2905ULL,
		0x275BA8D38213793EULL,
		0x997D905415FDF559ULL,
		0x4CB54990D70DA37FULL,
		0x2B9258442CD2D75DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD0816FFEA416440ULL,
		0x97B4A4AA0C3CD523ULL,
		0xD13AD252C1905D1EULL,
		0xF23AE5746B1A520AULL,
		0x4EB751A70426F27CULL,
		0x32FB20A82BFBEAB2ULL,
		0x996A9321AE1B46FFULL,
		0x5724B08859A5AEBAULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x438687729A195EECULL,
		0xF7BA2B854E51C9DEULL,
		0x63CE74FE53C1FC31ULL,
		0xCB232383AF1A0E24ULL,
		0x89F6D1F2FB646443ULL,
		0x3A27942F71C3EAF7ULL,
		0x2F4DC3507430992CULL,
		0x2FDA944207E58717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x870D0EE53432BDD8ULL,
		0xEF74570A9CA393BCULL,
		0xC79CE9FCA783F863ULL,
		0x964647075E341C48ULL,
		0x13EDA3E5F6C8C887ULL,
		0x744F285EE387D5EFULL,
		0x5E9B86A0E8613258ULL,
		0x5FB528840FCB0E2EULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDEC6C69C5A4CF46CULL,
		0x665BFA8B0C18ED97ULL,
		0xB1482451452E379FULL,
		0x987763FE733FD364ULL,
		0x0022A4E90A2CC68EULL,
		0x2A2A02780C1000F7ULL,
		0x24D5C23E8709F281ULL,
		0x29BDD74808480051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD8D8D38B499E8D8ULL,
		0xCCB7F5161831DB2FULL,
		0x629048A28A5C6F3EULL,
		0x30EEC7FCE67FA6C9ULL,
		0x004549D214598D1DULL,
		0x545404F0182001EEULL,
		0x49AB847D0E13E502ULL,
		0x537BAE90109000A2ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBCB3D670CF0BBEBCULL,
		0xC42E254E126619D7ULL,
		0x3A586EF223E4887DULL,
		0x0A5FE2AE330354D1ULL,
		0xF66C1A2435AEF14FULL,
		0x275F4A345E44A74CULL,
		0x6C8F221A95163F12ULL,
		0x3F7992EBFE62886EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7967ACE19E177D78ULL,
		0x885C4A9C24CC33AFULL,
		0x74B0DDE447C910FBULL,
		0x14BFC55C6606A9A2ULL,
		0xECD834486B5DE29EULL,
		0x4EBE9468BC894E99ULL,
		0xD91E44352A2C7E24ULL,
		0x7EF325D7FCC510DCULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x58F2BF9349662F4FULL,
		0xA525644AC3268902ULL,
		0xDF59393D6139741CULL,
		0x7A1128B7A29B070FULL,
		0x867E80E8D327E02AULL,
		0x537F360E887058D7ULL,
		0xE162252B07E1D251ULL,
		0x3925038D9555B9B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1E57F2692CC5E9EULL,
		0x4A4AC895864D1204ULL,
		0xBEB2727AC272E839ULL,
		0xF422516F45360E1FULL,
		0x0CFD01D1A64FC054ULL,
		0xA6FE6C1D10E0B1AFULL,
		0xC2C44A560FC3A4A2ULL,
		0x724A071B2AAB736BULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19621F010DBAEBC3ULL,
		0x55452138E9940380ULL,
		0xB989B2236BF06C00ULL,
		0x36A4365E844252E8ULL,
		0x3B0D579555CD9261ULL,
		0x0E0DD592DA1653E9ULL,
		0x2FF7FF3A21DA59F5ULL,
		0x242110BA7295A81EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C43E021B75D786ULL,
		0xAA8A4271D3280700ULL,
		0x73136446D7E0D800ULL,
		0x6D486CBD0884A5D1ULL,
		0x761AAF2AAB9B24C2ULL,
		0x1C1BAB25B42CA7D2ULL,
		0x5FEFFE7443B4B3EAULL,
		0x48422174E52B503CULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x859F8CD71533AD01ULL,
		0x155E8C39B1A83051ULL,
		0xD37B82C526547807ULL,
		0xD72FDD59D486D289ULL,
		0x4233180555BE5981ULL,
		0x826811F8A9E020A4ULL,
		0xA988E12746A5797BULL,
		0x30353A5253A4D7FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B3F19AE2A675A02ULL,
		0x2ABD1873635060A3ULL,
		0xA6F7058A4CA8F00EULL,
		0xAE5FBAB3A90DA513ULL,
		0x8466300AAB7CB303ULL,
		0x04D023F153C04148ULL,
		0x5311C24E8D4AF2F7ULL,
		0x606A74A4A749AFF9ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEA7831D8A2868CF7ULL,
		0xD9EC57BC0AD3B392ULL,
		0x2F6A1D09D6FA9562ULL,
		0x1D854613F452A4A3ULL,
		0x5B2E31F9A40DEBF6ULL,
		0x214F77D4990312FEULL,
		0x66E8FA448F427406ULL,
		0x0D27AFB101BB623DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F063B1450D19EEULL,
		0xB3D8AF7815A76725ULL,
		0x5ED43A13ADF52AC5ULL,
		0x3B0A8C27E8A54946ULL,
		0xB65C63F3481BD7ECULL,
		0x429EEFA9320625FCULL,
		0xCDD1F4891E84E80CULL,
		0x1A4F5F620376C47AULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D3F1EE4CE42CB4DULL,
		0xF0174A3EDDF5739AULL,
		0x0CE50D1A58C4BF42ULL,
		0xC509173E82A03068ULL,
		0xB4687EBCD3A93DDDULL,
		0xAD72A0D9BACE40D4ULL,
		0xC3955593E163D08DULL,
		0x337274D6F1BFCA05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A7E3DC99C85969AULL,
		0xE02E947DBBEAE734ULL,
		0x19CA1A34B1897E85ULL,
		0x8A122E7D054060D0ULL,
		0x68D0FD79A7527BBBULL,
		0x5AE541B3759C81A9ULL,
		0x872AAB27C2C7A11BULL,
		0x66E4E9ADE37F940BULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB1E20ECD81E2BE18ULL,
		0x081933CA72D31B52ULL,
		0x7181C556B5AA4E05ULL,
		0x39F5A022BF504252ULL,
		0xD91BB625054D2C2DULL,
		0xAB87DC9C9468D98DULL,
		0x984B2341B76BA0B7ULL,
		0x1E1220CA247498ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C41D9B03C57C30ULL,
		0x10326794E5A636A5ULL,
		0xE3038AAD6B549C0AULL,
		0x73EB40457EA084A4ULL,
		0xB2376C4A0A9A585AULL,
		0x570FB93928D1B31BULL,
		0x309646836ED7416FULL,
		0x3C24419448E93159ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x40047D8B0FF29864ULL,
		0x0BBF140DBB468C84ULL,
		0x71362852925B8968ULL,
		0x01C2EB9274371243ULL,
		0x1856E7AC6132A47AULL,
		0x8261D9202C972257ULL,
		0x3B6A43B0E293B668ULL,
		0x2139AEFE097DDDF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8008FB161FE530C8ULL,
		0x177E281B768D1908ULL,
		0xE26C50A524B712D0ULL,
		0x0385D724E86E2486ULL,
		0x30ADCF58C26548F4ULL,
		0x04C3B240592E44AEULL,
		0x76D48761C5276CD1ULL,
		0x42735DFC12FBBBF2ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF3C0FE83E212F427ULL,
		0x10087FF0B3656C6FULL,
		0xE25C8BB71CCD042FULL,
		0xD46623B5B426A412ULL,
		0xED0315FCC29DAFE8ULL,
		0x6B8A6092FB7AA15BULL,
		0x83650A0CD44A1CB6ULL,
		0x20BAC6AFDF73570FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE781FD07C425E84EULL,
		0x2010FFE166CAD8DFULL,
		0xC4B9176E399A085EULL,
		0xA8CC476B684D4825ULL,
		0xDA062BF9853B5FD1ULL,
		0xD714C125F6F542B7ULL,
		0x06CA1419A894396CULL,
		0x41758D5FBEE6AE1FULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA00D247929D07466ULL,
		0xECF6511A5C70B70EULL,
		0x7004F598CD5E7B95ULL,
		0x260A732F635FC603ULL,
		0xA625088F065E3820ULL,
		0x360A29712EAE009CULL,
		0xD500829F182BE842ULL,
		0x138FEEF0398E1D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x401A48F253A0E8CCULL,
		0xD9ECA234B8E16E1DULL,
		0xE009EB319ABCF72BULL,
		0x4C14E65EC6BF8C06ULL,
		0x4C4A111E0CBC7040ULL,
		0x6C1452E25D5C0139ULL,
		0xAA01053E3057D084ULL,
		0x271FDDE0731C3B23ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFF14F0182A2EFF00ULL,
		0x9A0FCD679641B619ULL,
		0xB2F034BF608F6A5CULL,
		0x2277F9B384DA82B4ULL,
		0xF908D12EBBD9DBBCULL,
		0x8B5C5C1C9980ECE3ULL,
		0xD44967381F90427CULL,
		0x0CBF91129727C006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE29E030545DFE00ULL,
		0x341F9ACF2C836C33ULL,
		0x65E0697EC11ED4B9ULL,
		0x44EFF36709B50569ULL,
		0xF211A25D77B3B778ULL,
		0x16B8B8393301D9C7ULL,
		0xA892CE703F2084F9ULL,
		0x197F22252E4F800DULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9EA6B4A072102E54ULL,
		0x6EF34EDC65CCBA5EULL,
		0x2B95905441F101ECULL,
		0x45834356D6E7A9BBULL,
		0x5E8270EB00C5FB5FULL,
		0x355F2E2C5D7D8D26ULL,
		0xACD1548F11E3A950ULL,
		0x3BF0777B3F3CBA3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D4D6940E4205CA8ULL,
		0xDDE69DB8CB9974BDULL,
		0x572B20A883E203D8ULL,
		0x8B0686ADADCF5376ULL,
		0xBD04E1D6018BF6BEULL,
		0x6ABE5C58BAFB1A4CULL,
		0x59A2A91E23C752A0ULL,
		0x77E0EEF67E797475ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9E942E5A9C594F6BULL,
		0x7C7E7C016CABFBD6ULL,
		0xB640E93783C5FDEDULL,
		0x2D8F7ED955188EB5ULL,
		0x75A295BA649A3ACEULL,
		0x85298B6D7D2E19C8ULL,
		0xCF3F397306C697E7ULL,
		0x09014491171428C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D285CB538B29ED6ULL,
		0xF8FCF802D957F7ADULL,
		0x6C81D26F078BFBDAULL,
		0x5B1EFDB2AA311D6BULL,
		0xEB452B74C934759CULL,
		0x0A5316DAFA5C3390ULL,
		0x9E7E72E60D8D2FCFULL,
		0x120289222E28518DULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x90E9CAF1B5D3F73DULL,
		0x4212E5D99A3BC246ULL,
		0x962880FD0B4A1F2BULL,
		0xC6EECA2007380A2AULL,
		0xF0BD45D459D9E5A8ULL,
		0x86DAF18D35F7D804ULL,
		0x6BE1F9F46E719FFFULL,
		0x3826B12DCB889459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D395E36BA7EE7AULL,
		0x8425CBB33477848DULL,
		0x2C5101FA16943E56ULL,
		0x8DDD94400E701455ULL,
		0xE17A8BA8B3B3CB51ULL,
		0x0DB5E31A6BEFB009ULL,
		0xD7C3F3E8DCE33FFFULL,
		0x704D625B971128B2ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC1A15919FFE9768FULL,
		0xC06E2FC3E0CC978BULL,
		0x8B560EC549E1296DULL,
		0xA0866D0F8E43D21BULL,
		0x66877B99DE38A304ULL,
		0x22A537F16926F6C2ULL,
		0x291581214C1F73E3ULL,
		0x1F16FF836EFEF7A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8342B233FFD2ED1EULL,
		0x80DC5F87C1992F17ULL,
		0x16AC1D8A93C252DBULL,
		0x410CDA1F1C87A437ULL,
		0xCD0EF733BC714609ULL,
		0x454A6FE2D24DED84ULL,
		0x522B0242983EE7C6ULL,
		0x3E2DFF06DDFDEF50ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x31019921AA437BC7ULL,
		0xFD37214E8D000DA0ULL,
		0x663844B8FEE4C074ULL,
		0x879A072532B7BC18ULL,
		0x65568B400CAAC39EULL,
		0xEDF336F1532BD873ULL,
		0x89CBCB6CF3730C07ULL,
		0x1CA670B4F2BB7BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x620332435486F78EULL,
		0xFA6E429D1A001B40ULL,
		0xCC708971FDC980E9ULL,
		0x0F340E4A656F7830ULL,
		0xCAAD16801955873DULL,
		0xDBE66DE2A657B0E6ULL,
		0x139796D9E6E6180FULL,
		0x394CE169E576F7E3ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF826F022A8C52E20ULL,
		0xE680D37A80408CA6ULL,
		0xBA9614D7AC43229CULL,
		0x323B720E856C6E67ULL,
		0x8CC4189C368EFDBAULL,
		0x56ACA73097EFF0DEULL,
		0xB53397B33D1B16B6ULL,
		0x0F9CC5956D7E6A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF04DE045518A5C40ULL,
		0xCD01A6F50081194DULL,
		0x752C29AF58864539ULL,
		0x6476E41D0AD8DCCFULL,
		0x198831386D1DFB74ULL,
		0xAD594E612FDFE1BDULL,
		0x6A672F667A362D6CULL,
		0x1F398B2ADAFCD4A3ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA722C9F29AA7C709ULL,
		0x82DB044F0B897A4DULL,
		0xBA23489DFB557BB0ULL,
		0x35487E7FA3897FF7ULL,
		0xA237E251AB31DC37ULL,
		0x6B4D5AE2516CFC4EULL,
		0xC043894C63502342ULL,
		0x1E73C308FC4EE120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4593E5354F8E12ULL,
		0x05B6089E1712F49BULL,
		0x7446913BF6AAF761ULL,
		0x6A90FCFF4712FFEFULL,
		0x446FC4A35663B86EULL,
		0xD69AB5C4A2D9F89DULL,
		0x80871298C6A04684ULL,
		0x3CE78611F89DC241ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x846E1A00E1BE217AULL,
		0xC936FB95ACFBCB6EULL,
		0x6584F6F42C067943ULL,
		0xA1D7EA902ED72B46ULL,
		0xD7248AEF844104E2ULL,
		0x69A2A1DB6019C963ULL,
		0x89E749DB43A544B9ULL,
		0x006FF5549DC2198BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08DC3401C37C42F4ULL,
		0x926DF72B59F796DDULL,
		0xCB09EDE8580CF287ULL,
		0x43AFD5205DAE568CULL,
		0xAE4915DF088209C5ULL,
		0xD34543B6C03392C7ULL,
		0x13CE93B6874A8972ULL,
		0x00DFEAA93B843317ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD4CC3C8F580B85C3ULL,
		0x907D02E393679B46ULL,
		0xD883D9CE8846E011ULL,
		0x8BFF9481A9D957D7ULL,
		0x1DB494EEDCE6BFA3ULL,
		0x69701B835B938D38ULL,
		0x899B61304271856BULL,
		0x15ED135D49095F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA998791EB0170B86ULL,
		0x20FA05C726CF368DULL,
		0xB107B39D108DC023ULL,
		0x17FF290353B2AFAFULL,
		0x3B6929DDB9CD7F47ULL,
		0xD2E03706B7271A70ULL,
		0x1336C26084E30AD6ULL,
		0x2BDA26BA9212BE41ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x57932B66F1A2BCB6ULL,
		0x2623E44684B95036ULL,
		0xF5EF24F5CFFBAF61ULL,
		0x5141C03C8E7823C9ULL,
		0x50154E99DFBEE089ULL,
		0xC55CFE2A729AFBA9ULL,
		0x8BF8B13AEED7B46EULL,
		0x364A374D68D4B8CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF2656CDE345796CULL,
		0x4C47C88D0972A06CULL,
		0xEBDE49EB9FF75EC2ULL,
		0xA28380791CF04793ULL,
		0xA02A9D33BF7DC112ULL,
		0x8AB9FC54E535F752ULL,
		0x17F16275DDAF68DDULL,
		0x6C946E9AD1A97195ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD56F330E8AEE4C2ULL,
		0xBF41539E69907732ULL,
		0x3EED26557A47BDC3ULL,
		0x40328BA1242D0855ULL,
		0xA03EC4B9FF40F287ULL,
		0xF2197B0082D94206ULL,
		0x9F25D625A1E1005EULL,
		0x25017A5BB184E6C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAADE661D15DC984ULL,
		0x7E82A73CD320EE65ULL,
		0x7DDA4CAAF48F7B87ULL,
		0x80651742485A10AAULL,
		0x407D8973FE81E50EULL,
		0xE432F60105B2840DULL,
		0x3E4BAC4B43C200BDULL,
		0x4A02F4B76309CD85ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0DDD64E855A99DE9ULL,
		0x5555209FA122AC10ULL,
		0xFFAA0DF1A137438BULL,
		0xCB82FFB18FFDFCF9ULL,
		0xB7AD15B4E1EE70C1ULL,
		0x0C7EAFB1B569C47BULL,
		0x58FDE1A4641F3060ULL,
		0x0CB1A794D1718793ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BBAC9D0AB533BD2ULL,
		0xAAAA413F42455820ULL,
		0xFF541BE3426E8716ULL,
		0x9705FF631FFBF9F3ULL,
		0x6F5A2B69C3DCE183ULL,
		0x18FD5F636AD388F7ULL,
		0xB1FBC348C83E60C0ULL,
		0x19634F29A2E30F26ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8999F4FA1CF053AEULL,
		0x42DB085CBD3711C0ULL,
		0x2BD3D38C6036FBFDULL,
		0x6201E8760D2C9C06ULL,
		0x837DE0C32FAA4A32ULL,
		0x5960B4C67D30612DULL,
		0x585110C17435F991ULL,
		0x11370C8215F9EACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1333E9F439E0A75CULL,
		0x85B610B97A6E2381ULL,
		0x57A7A718C06DF7FAULL,
		0xC403D0EC1A59380CULL,
		0x06FBC1865F549464ULL,
		0xB2C1698CFA60C25BULL,
		0xB0A22182E86BF322ULL,
		0x226E19042BF3D59CULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0320C694FCBE1360ULL,
		0x0B9CBC4432D611D1ULL,
		0x6BB167142A19138DULL,
		0x5142D10B8FF4A2D5ULL,
		0xD2E4538961BED52EULL,
		0xC7A70B32D93C3B11ULL,
		0xC66F905D3561AD93ULL,
		0x2B43D85E0BCA92FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06418D29F97C26C0ULL,
		0x1739788865AC23A2ULL,
		0xD762CE285432271AULL,
		0xA285A2171FE945AAULL,
		0xA5C8A712C37DAA5CULL,
		0x8F4E1665B2787623ULL,
		0x8CDF20BA6AC35B27ULL,
		0x5687B0BC179525F5ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7A37C2960F68A377ULL,
		0xD499A693D6EE0AA3ULL,
		0x8CD21B0AF97F2AD7ULL,
		0x1DCBF80DAC04F003ULL,
		0xB32CBE93ADC0D40FULL,
		0x27C4926405DD5875ULL,
		0x276F525EF52BC243ULL,
		0x324DB882F5DB2994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF46F852C1ED146EEULL,
		0xA9334D27ADDC1546ULL,
		0x19A43615F2FE55AFULL,
		0x3B97F01B5809E007ULL,
		0x66597D275B81A81EULL,
		0x4F8924C80BBAB0EBULL,
		0x4EDEA4BDEA578486ULL,
		0x649B7105EBB65328ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12BEE3E998073D4CULL,
		0xC2DDA189B38BA40CULL,
		0x2F8A3266525BE944ULL,
		0xDFF3DA49E791C604ULL,
		0xE8B69C0BE73F1502ULL,
		0xCDFDA4D5FC484ABCULL,
		0x1593D3C428C00F5CULL,
		0x3E43BB28E3BF63DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x257DC7D3300E7A98ULL,
		0x85BB431367174818ULL,
		0x5F1464CCA4B7D289ULL,
		0xBFE7B493CF238C08ULL,
		0xD16D3817CE7E2A05ULL,
		0x9BFB49ABF8909579ULL,
		0x2B27A78851801EB9ULL,
		0x7C877651C77EC7B6ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x511CD76263639727ULL,
		0xA6BC2F2B208EBB5BULL,
		0x5CE4B81008400813ULL,
		0x3CB333E1018DD36CULL,
		0xCF6E3A9A595E850CULL,
		0xE80C6A0621DA1E8BULL,
		0xB3BFD88210E2F681ULL,
		0x24CFD85170272F8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA239AEC4C6C72E4EULL,
		0x4D785E56411D76B6ULL,
		0xB9C9702010801027ULL,
		0x796667C2031BA6D8ULL,
		0x9EDC7534B2BD0A18ULL,
		0xD018D40C43B43D17ULL,
		0x677FB10421C5ED03ULL,
		0x499FB0A2E04E5F1DULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCFC126F6F27FCD8ULL,
		0x6C84AD3905C819D5ULL,
		0xDDD36086FEFF97EBULL,
		0x4AB7DBE967F432CFULL,
		0xA46FF80F74EB502EULL,
		0x7119451485B00493ULL,
		0xD3FA8D790B807B8EULL,
		0x38439DC3AEBBE9EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99F824DEDE4FF9B0ULL,
		0xD9095A720B9033ABULL,
		0xBBA6C10DFDFF2FD6ULL,
		0x956FB7D2CFE8659FULL,
		0x48DFF01EE9D6A05CULL,
		0xE2328A290B600927ULL,
		0xA7F51AF21700F71CULL,
		0x70873B875D77D3DFULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF17D16D9377B30ABULL,
		0x133C65D9164D79A7ULL,
		0x971F7B26D35E051AULL,
		0x53F8F3B11C07F2D4ULL,
		0x164FF9EFDBCCEFBBULL,
		0xD3369963F61976C1ULL,
		0x5D6DD54A83F66F79ULL,
		0x2AF73DC0F6F635AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2FA2DB26EF66156ULL,
		0x2678CBB22C9AF34FULL,
		0x2E3EF64DA6BC0A34ULL,
		0xA7F1E762380FE5A9ULL,
		0x2C9FF3DFB799DF76ULL,
		0xA66D32C7EC32ED82ULL,
		0xBADBAA9507ECDEF3ULL,
		0x55EE7B81EDEC6B5EULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x28582C404A87724AULL,
		0x70C69C9285ADB4F1ULL,
		0x6E2C6B2D1AABA7B9ULL,
		0x655FA2359FA39E02ULL,
		0x28ABABF60B409EC1ULL,
		0x14F2D9A5EA16D48BULL,
		0xD0F8BB4CAE944813ULL,
		0x0C998577AB9DD234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50B05880950EE494ULL,
		0xE18D39250B5B69E2ULL,
		0xDC58D65A35574F72ULL,
		0xCABF446B3F473C04ULL,
		0x515757EC16813D82ULL,
		0x29E5B34BD42DA916ULL,
		0xA1F176995D289026ULL,
		0x19330AEF573BA469ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4F07D1AA00DE4094ULL,
		0xA12001E86F56CF06ULL,
		0x3575DAF8BFD188EFULL,
		0x47D211C528F9BBE2ULL,
		0xBDF32B3BF3801AB6ULL,
		0xD4A5A068C09BD415ULL,
		0xBF401C04C53F2E15ULL,
		0x10E5623DB77DBF91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0FA35401BC8128ULL,
		0x424003D0DEAD9E0CULL,
		0x6AEBB5F17FA311DFULL,
		0x8FA4238A51F377C4ULL,
		0x7BE65677E700356CULL,
		0xA94B40D18137A82BULL,
		0x7E8038098A7E5C2BULL,
		0x21CAC47B6EFB7F23ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9983D1DD89F2BA27ULL,
		0x56AB115B1307EFF7ULL,
		0x41C0589B7ED918E4ULL,
		0x5066100D3F2FFBFCULL,
		0x9FA7705F07B2EC32ULL,
		0x0D9C3163910B0EF7ULL,
		0x2B021A951FACDCF9ULL,
		0x23D9B4084EE4CF90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3307A3BB13E5744EULL,
		0xAD5622B6260FDFEFULL,
		0x8380B136FDB231C8ULL,
		0xA0CC201A7E5FF7F8ULL,
		0x3F4EE0BE0F65D864ULL,
		0x1B3862C722161DEFULL,
		0x5604352A3F59B9F2ULL,
		0x47B368109DC99F20ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1A2ED2951DA1850EULL,
		0x5E55BB6B81198261ULL,
		0x0156DE14D70DC150ULL,
		0x7FAF380E28C7024CULL,
		0xA0D0C61021BBBE4FULL,
		0x2A688819CAD53528ULL,
		0x84A41A6A92C78296ULL,
		0x2B498F9C15C31FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x345DA52A3B430A1CULL,
		0xBCAB76D7023304C2ULL,
		0x02ADBC29AE1B82A0ULL,
		0xFF5E701C518E0498ULL,
		0x41A18C2043777C9EULL,
		0x54D1103395AA6A51ULL,
		0x094834D5258F052CULL,
		0x56931F382B863FF9ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D060CD3E801795EULL,
		0x85EC8F103F3DB82CULL,
		0x5A13B7E3BACBAC88ULL,
		0xAC13B91F63C1EF85ULL,
		0xC92EF2D0B22975D0ULL,
		0xDE0E8B067E28397BULL,
		0xCC4FF088DDD5272DULL,
		0x229F2CB67F04F740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A0C19A7D002F2BCULL,
		0x0BD91E207E7B7058ULL,
		0xB4276FC775975911ULL,
		0x5827723EC783DF0AULL,
		0x925DE5A16452EBA1ULL,
		0xBC1D160CFC5072F7ULL,
		0x989FE111BBAA4E5BULL,
		0x453E596CFE09EE81ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6BC0855D0CAF8403ULL,
		0x78F6DCFCC41D41F7ULL,
		0x99C7488E3F806085ULL,
		0x198E27CEE41F61B8ULL,
		0x51DF719602407128ULL,
		0xD70FF3B29B889B53ULL,
		0x0E0FAF11EF77CD70ULL,
		0x22F1300A2D5D040FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7810ABA195F0806ULL,
		0xF1EDB9F9883A83EEULL,
		0x338E911C7F00C10AULL,
		0x331C4F9DC83EC371ULL,
		0xA3BEE32C0480E250ULL,
		0xAE1FE765371136A6ULL,
		0x1C1F5E23DEEF9AE1ULL,
		0x45E260145ABA081EULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF0CB53D36510C347ULL,
		0x96776E491F873654ULL,
		0xBEAD2040C5C2AEE8ULL,
		0x86D88A2D90736FA1ULL,
		0xB0E5D7E552B69774ULL,
		0xE4E242955B4C2047ULL,
		0x11356E51E857771DULL,
		0x0175967B88682BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE196A7A6CA21868EULL,
		0x2CEEDC923F0E6CA9ULL,
		0x7D5A40818B855DD1ULL,
		0x0DB1145B20E6DF43ULL,
		0x61CBAFCAA56D2EE9ULL,
		0xC9C4852AB698408FULL,
		0x226ADCA3D0AEEE3BULL,
		0x02EB2CF710D05768ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x78235062CCF2CBAEULL,
		0xE40A89B0785C6A4BULL,
		0xA0D5A980496A06C9ULL,
		0x367D32EBB6051847ULL,
		0x5183A4E7AB661EEFULL,
		0x93922F2CEFC92FD7ULL,
		0xB093A8B24689353FULL,
		0x2C765C472BAC76D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF046A0C599E5975CULL,
		0xC8151360F0B8D496ULL,
		0x41AB530092D40D93ULL,
		0x6CFA65D76C0A308FULL,
		0xA30749CF56CC3DDEULL,
		0x27245E59DF925FAEULL,
		0x612751648D126A7FULL,
		0x58ECB88E5758EDABULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x247C40EEDF9320E7ULL,
		0xB103F32CDA548164ULL,
		0x100C633BF6410A44ULL,
		0x02B98FAE82C8B169ULL,
		0xF598E1773D283882ULL,
		0x20C589581BA1FB4AULL,
		0xC3400C6F5F7B20E2ULL,
		0x21A733C636FE5D23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F881DDBF2641CEULL,
		0x6207E659B4A902C8ULL,
		0x2018C677EC821489ULL,
		0x05731F5D059162D2ULL,
		0xEB31C2EE7A507104ULL,
		0x418B12B03743F695ULL,
		0x868018DEBEF641C4ULL,
		0x434E678C6DFCBA47ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x393AC1611216D9A4ULL,
		0x5B83D70FFC169B14ULL,
		0xDEE980EA999D0607ULL,
		0x878C9730DB12792DULL,
		0x3DBC4C0AA71E9AAFULL,
		0xAB94ED71C90BE145ULL,
		0x1C3178752CFD69BBULL,
		0x1B57EFD5765D7CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x727582C2242DB348ULL,
		0xB707AE1FF82D3628ULL,
		0xBDD301D5333A0C0EULL,
		0x0F192E61B624F25BULL,
		0x7B7898154E3D355FULL,
		0x5729DAE39217C28AULL,
		0x3862F0EA59FAD377ULL,
		0x36AFDFAAECBAF9C0ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1D1DCAC961D55EE7ULL,
		0xC35A5C7B6BE60CFEULL,
		0xA0FBAA0D717064AFULL,
		0xB61822E54F1EE069ULL,
		0xB5DBFF339F40332FULL,
		0xEB4062C04977AF89ULL,
		0x8467778E59461747ULL,
		0x360666CD12B3CC8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A3B9592C3AABDCEULL,
		0x86B4B8F6D7CC19FCULL,
		0x41F7541AE2E0C95FULL,
		0x6C3045CA9E3DC0D3ULL,
		0x6BB7FE673E80665FULL,
		0xD680C58092EF5F13ULL,
		0x08CEEF1CB28C2E8FULL,
		0x6C0CCD9A2567991DULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x99C1EDBF1B2B7DCFULL,
		0xC5BEB8EE43BC6079ULL,
		0xD503C3C4C4EA0C7FULL,
		0x295D5214311E9FB1ULL,
		0x5A1FAE3E85A2A223ULL,
		0x07D42FE6D20E124FULL,
		0x42D4D0D575DB2ADDULL,
		0x16B0005B247E7A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3383DB7E3656FB9EULL,
		0x8B7D71DC8778C0F3ULL,
		0xAA07878989D418FFULL,
		0x52BAA428623D3F63ULL,
		0xB43F5C7D0B454446ULL,
		0x0FA85FCDA41C249EULL,
		0x85A9A1AAEBB655BAULL,
		0x2D6000B648FCF47CULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xECA52A73CFEE7D4EULL,
		0x81699B02A07B70A1ULL,
		0xBF94F9DF3AB5D030ULL,
		0x5DCBA0D14BD57424ULL,
		0x07A4CFFC16F70302ULL,
		0xD5D7F88807545DE9ULL,
		0x65D8ED0A4F80D616ULL,
		0x07498E6344CB8CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD94A54E79FDCFA9CULL,
		0x02D3360540F6E143ULL,
		0x7F29F3BE756BA061ULL,
		0xBB9741A297AAE849ULL,
		0x0F499FF82DEE0604ULL,
		0xABAFF1100EA8BBD2ULL,
		0xCBB1DA149F01AC2DULL,
		0x0E931CC6899719AEULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9ACBC709D85CAC5ULL,
		0xDD9B6F7DC016CB23ULL,
		0x4BA36FC7D2BBD4C8ULL,
		0x0E4DCE6424A29407ULL,
		0x71EC8B38114C05ABULL,
		0xA488AE01FBA427A5ULL,
		0xD89F2DC0567EE59CULL,
		0x0C100AAE8076790AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD35978E13B0B958AULL,
		0xBB36DEFB802D9647ULL,
		0x9746DF8FA577A991ULL,
		0x1C9B9CC84945280EULL,
		0xE3D9167022980B56ULL,
		0x49115C03F7484F4AULL,
		0xB13E5B80ACFDCB39ULL,
		0x1820155D00ECF215ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3DE269909287F5ECULL,
		0xAC0CB6D8338C9383ULL,
		0xE45241A706EF5D75ULL,
		0x10204C40554F1BCEULL,
		0x3C906D74C6710169ULL,
		0x286E7720566DAA7BULL,
		0x80392DB5B83460EAULL,
		0x3DF3C25D3F7E0B93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BC4D321250FEBD8ULL,
		0x58196DB067192706ULL,
		0xC8A4834E0DDEBAEBULL,
		0x20409880AA9E379DULL,
		0x7920DAE98CE202D2ULL,
		0x50DCEE40ACDB54F6ULL,
		0x00725B6B7068C1D4ULL,
		0x7BE784BA7EFC1727ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB80D2CA33E3B49AFULL,
		0xD55DE8CA39C42B9AULL,
		0x77024B193E27B9B0ULL,
		0xCE305FA8543A0B08ULL,
		0x3992C4336F97E1F8ULL,
		0x6E19576FFA2B2D8CULL,
		0x4F3A262C8902D06EULL,
		0x0633F97BA2604ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x701A59467C76935EULL,
		0xAABBD19473885735ULL,
		0xEE0496327C4F7361ULL,
		0x9C60BF50A8741610ULL,
		0x73258866DF2FC3F1ULL,
		0xDC32AEDFF4565B18ULL,
		0x9E744C591205A0DCULL,
		0x0C67F2F744C0959AULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3D6BF97E72207919ULL,
		0x1897E0482325F660ULL,
		0x7A40F6C8D35A29EDULL,
		0x7F389E4E1B1FDA0EULL,
		0x7735F48A4FE0B2C6ULL,
		0x6A60012051CF55F2ULL,
		0x1D617EF76AC83331ULL,
		0x04FA190C7FA28544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD7F2FCE440F232ULL,
		0x312FC090464BECC0ULL,
		0xF481ED91A6B453DAULL,
		0xFE713C9C363FB41CULL,
		0xEE6BE9149FC1658CULL,
		0xD4C00240A39EABE4ULL,
		0x3AC2FDEED5906662ULL,
		0x09F43218FF450A88ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x463B407C9A8E6B0FULL,
		0x5D5584F4A6049B02ULL,
		0x38FC8C552EB71B6AULL,
		0x1F304D38F0D7B29DULL,
		0x30F10AC3EB685EC5ULL,
		0x98B23896E163EBCCULL,
		0x0D0F753EA34D46DDULL,
		0x12DE63DC0859E91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7680F9351CD61EULL,
		0xBAAB09E94C093604ULL,
		0x71F918AA5D6E36D4ULL,
		0x3E609A71E1AF653AULL,
		0x61E21587D6D0BD8AULL,
		0x3164712DC2C7D798ULL,
		0x1A1EEA7D469A8DBBULL,
		0x25BCC7B810B3D23EULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF00AC8CA5735DEBULL,
		0xAED3A9426B01C660ULL,
		0xAE8A9362A485C376ULL,
		0x5103C761A6C56685ULL,
		0x9241BBBE24407974ULL,
		0x52117FB361FA84DCULL,
		0x25848FA096EBEB0EULL,
		0x08068896842D8DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE0159194AE6BBD6ULL,
		0x5DA75284D6038CC1ULL,
		0x5D1526C5490B86EDULL,
		0xA2078EC34D8ACD0BULL,
		0x2483777C4880F2E8ULL,
		0xA422FF66C3F509B9ULL,
		0x4B091F412DD7D61CULL,
		0x100D112D085B1BC2ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6DBBAF22E24D1CEFULL,
		0xD2BAE23023F01448ULL,
		0x2CA84A9B1B7560F8ULL,
		0xFD832F693BA3A877ULL,
		0x1312ECB32BE79FF9ULL,
		0x903BC6334D5A1D5EULL,
		0xB0C232A6823C31B2ULL,
		0x2F37086EEA4830D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB775E45C49A39DEULL,
		0xA575C46047E02890ULL,
		0x5950953636EAC1F1ULL,
		0xFB065ED2774750EEULL,
		0x2625D96657CF3FF3ULL,
		0x20778C669AB43ABCULL,
		0x6184654D04786365ULL,
		0x5E6E10DDD49061A1ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE3820F6E9D7B7741ULL,
		0x25DC3FBCEAB2FF8EULL,
		0xA616D6B1C99849D6ULL,
		0x60DB2399A263C7D7ULL,
		0x196469D19ABBBF69ULL,
		0x20E515742EA34D4EULL,
		0xB5D71C5B18F30EFDULL,
		0x27B8CDA11C67AA7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7041EDD3AF6EE82ULL,
		0x4BB87F79D565FF1DULL,
		0x4C2DAD63933093ACULL,
		0xC1B6473344C78FAFULL,
		0x32C8D3A335777ED2ULL,
		0x41CA2AE85D469A9CULL,
		0x6BAE38B631E61DFAULL,
		0x4F719B4238CF54F7ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x032F11529987C00BULL,
		0x682F4917ADA3D2B5ULL,
		0x9101946C0BC5F241ULL,
		0x7400B52E64BEAA89ULL,
		0x9F7A119901D2F128ULL,
		0x0F77BC09B992EDC3ULL,
		0xC8115060E5A321B1ULL,
		0x0A1549A9D5043762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x065E22A5330F8016ULL,
		0xD05E922F5B47A56AULL,
		0x220328D8178BE482ULL,
		0xE8016A5CC97D5513ULL,
		0x3EF4233203A5E250ULL,
		0x1EEF78137325DB87ULL,
		0x9022A0C1CB464362ULL,
		0x142A9353AA086EC5ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5BAE7DF82ABD699CULL,
		0x7690581B1BE28135ULL,
		0xE0F3F33F7782AE23ULL,
		0x6DE8A0C1E9AADC0BULL,
		0xF29F3B80B3BB7EA2ULL,
		0x5068D9234038DBD3ULL,
		0x2521AB7713CEBD2DULL,
		0x3C47C1F2A189064AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB75CFBF0557AD338ULL,
		0xED20B03637C5026AULL,
		0xC1E7E67EEF055C46ULL,
		0xDBD14183D355B817ULL,
		0xE53E77016776FD44ULL,
		0xA0D1B2468071B7A7ULL,
		0x4A4356EE279D7A5AULL,
		0x788F83E543120C94ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1319BACF9296D0E2ULL,
		0x7566EDFB77825DF8ULL,
		0x3E78C6C3A217F5A2ULL,
		0x194699BDBD1185BCULL,
		0x5CC4FB14F1363601ULL,
		0x3E27E0DA0947AA67ULL,
		0x080C57867D8A15FCULL,
		0x344662EA82D28664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2633759F252DA1C4ULL,
		0xEACDDBF6EF04BBF0ULL,
		0x7CF18D87442FEB44ULL,
		0x328D337B7A230B78ULL,
		0xB989F629E26C6C02ULL,
		0x7C4FC1B4128F54CEULL,
		0x1018AF0CFB142BF8ULL,
		0x688CC5D505A50CC8ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE3EF76FC16161D45ULL,
		0xADBC435B51161F86ULL,
		0xED30F85125C172ACULL,
		0x8F37C32D16776A91ULL,
		0x5A82DA5B83E5CE80ULL,
		0x5D8A5A792042C0F5ULL,
		0xB778932CDDC95438ULL,
		0x368E24744F2B99A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7DEEDF82C2C3A8AULL,
		0x5B7886B6A22C3F0DULL,
		0xDA61F0A24B82E559ULL,
		0x1E6F865A2CEED523ULL,
		0xB505B4B707CB9D01ULL,
		0xBB14B4F2408581EAULL,
		0x6EF12659BB92A870ULL,
		0x6D1C48E89E573341ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA5534FE4AB9E33A5ULL,
		0x932E6F416917F69BULL,
		0x2215128D78DB0109ULL,
		0x7B96AAA511011281ULL,
		0x1D4817763E4AAD80ULL,
		0x26997A15D84733DFULL,
		0x36F7873FACD6867AULL,
		0x3B67D0553607FFB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AA69FC9573C674AULL,
		0x265CDE82D22FED37ULL,
		0x442A251AF1B60213ULL,
		0xF72D554A22022502ULL,
		0x3A902EEC7C955B00ULL,
		0x4D32F42BB08E67BEULL,
		0x6DEF0E7F59AD0CF4ULL,
		0x76CFA0AA6C0FFF6EULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD15627AA0CB9BFD3ULL,
		0x594D83142296440FULL,
		0xFD2D7C7751A64630ULL,
		0x2C79323E74C4F6BFULL,
		0x51D3F6A661001E14ULL,
		0xF4BF9692AF691021ULL,
		0xC70AFB6E13224373ULL,
		0x17722ED3886BA707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AC4F5419737FA6ULL,
		0xB29B0628452C881FULL,
		0xFA5AF8EEA34C8C60ULL,
		0x58F2647CE989ED7FULL,
		0xA3A7ED4CC2003C28ULL,
		0xE97F2D255ED22042ULL,
		0x8E15F6DC264486E7ULL,
		0x2EE45DA710D74E0FULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2C9DA7A326AE51D3ULL,
		0x5C56D310D23B1AA7ULL,
		0x280EA8D50BEE6323ULL,
		0x34E703266C766E7DULL,
		0x1418DC9232CDB2C6ULL,
		0x2D82B4B07FCD1654ULL,
		0xB7A33719716A8301ULL,
		0x21BCD20750A23414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x593B4F464D5CA3A6ULL,
		0xB8ADA621A476354EULL,
		0x501D51AA17DCC646ULL,
		0x69CE064CD8ECDCFAULL,
		0x2831B924659B658CULL,
		0x5B056960FF9A2CA8ULL,
		0x6F466E32E2D50602ULL,
		0x4379A40EA1446829ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE00AFB1AEF519CA4ULL,
		0xED8B5E667E439744ULL,
		0x985A4FE6B768C545ULL,
		0x55DDFC3D47819FCDULL,
		0x84199775D9C847C0ULL,
		0xF79B4F613562C576ULL,
		0x712C88D340888659ULL,
		0x086BF98A781D9E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC015F635DEA33948ULL,
		0xDB16BCCCFC872E89ULL,
		0x30B49FCD6ED18A8BULL,
		0xABBBF87A8F033F9BULL,
		0x08332EEBB3908F80ULL,
		0xEF369EC26AC58AEDULL,
		0xE25911A681110CB3ULL,
		0x10D7F314F03B3CF2ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x463EE94F700AAE78ULL,
		0x1B018B6E801D93E6ULL,
		0x62A508A95D9E2DC9ULL,
		0x6E099F884A53E976ULL,
		0xE809E30ADE2FE91CULL,
		0xB33A45FE7926BDDAULL,
		0xB49BA7D6147FF7AAULL,
		0x12161091F4E279AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7DD29EE0155CF0ULL,
		0x360316DD003B27CCULL,
		0xC54A1152BB3C5B92ULL,
		0xDC133F1094A7D2ECULL,
		0xD013C615BC5FD238ULL,
		0x66748BFCF24D7BB5ULL,
		0x69374FAC28FFEF55ULL,
		0x242C2123E9C4F35DULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5B60C2EF45ADAEB2ULL,
		0xC670046DC5347D35ULL,
		0xD9761DDBFDF9F164ULL,
		0xF90AE55BF6920A16ULL,
		0x845F6086A4909AA7ULL,
		0x805B1CBB1ECA9138ULL,
		0xB5C0D429E2398576ULL,
		0x2A70448E7F41DB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6C185DE8B5B5D64ULL,
		0x8CE008DB8A68FA6AULL,
		0xB2EC3BB7FBF3E2C9ULL,
		0xF215CAB7ED24142DULL,
		0x08BEC10D4921354FULL,
		0x00B639763D952271ULL,
		0x6B81A853C4730AEDULL,
		0x54E0891CFE83B63DULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x609FD4A79D657DB0ULL,
		0xEAFEB3709F32AD63ULL,
		0x45810DE08CA59A5FULL,
		0x3731C09F8332A185ULL,
		0x7DD6D844247D229AULL,
		0xB9B4A7012E4BEBF8ULL,
		0xD00DBAF95C4C7BA8ULL,
		0x0F545BE4C8495DD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC13FA94F3ACAFB60ULL,
		0xD5FD66E13E655AC6ULL,
		0x8B021BC1194B34BFULL,
		0x6E63813F0665430AULL,
		0xFBADB08848FA4534ULL,
		0x73694E025C97D7F0ULL,
		0xA01B75F2B898F751ULL,
		0x1EA8B7C99092BBB1ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x77F6BDBBB059416CULL,
		0xCE739F9ADA71CA8EULL,
		0x04A4E36FA05703E5ULL,
		0x646372EA63018A84ULL,
		0x0D574B1111968CE2ULL,
		0xEEC849D1F2E69B57ULL,
		0x2A9FD8940ED3DFF9ULL,
		0x0BD9F8A28A2A35E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFED7B7760B282D8ULL,
		0x9CE73F35B4E3951CULL,
		0x0949C6DF40AE07CBULL,
		0xC8C6E5D4C6031508ULL,
		0x1AAE9622232D19C4ULL,
		0xDD9093A3E5CD36AEULL,
		0x553FB1281DA7BFF3ULL,
		0x17B3F14514546BC4ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5CDC22BFF21CF27ULL,
		0x131BCCFFC50999C7ULL,
		0x6CBDDA467A456821ULL,
		0x11087487D1FFF48CULL,
		0xC4E511C0D651DEF4ULL,
		0xCA80B24C312940A7ULL,
		0xA788BAA7D3FC7DEBULL,
		0x0C87A479ABF5B414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB9B8457FE439E4EULL,
		0x263799FF8A13338FULL,
		0xD97BB48CF48AD042ULL,
		0x2210E90FA3FFE918ULL,
		0x89CA2381ACA3BDE8ULL,
		0x950164986252814FULL,
		0x4F11754FA7F8FBD7ULL,
		0x190F48F357EB6829ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7EB94E605C3FC354ULL,
		0xE174C206269D83B1ULL,
		0x745D207DFF2C19DAULL,
		0x4388BC6435496CAFULL,
		0x84D7227B31ACAE73ULL,
		0x98842022573626E8ULL,
		0x1EB6F3BABA60AD92ULL,
		0x1EDAFABF1F8F630DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD729CC0B87F86A8ULL,
		0xC2E9840C4D3B0762ULL,
		0xE8BA40FBFE5833B5ULL,
		0x871178C86A92D95EULL,
		0x09AE44F663595CE6ULL,
		0x31084044AE6C4DD1ULL,
		0x3D6DE77574C15B25ULL,
		0x3DB5F57E3F1EC61AULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x997176C9CF7120D1ULL,
		0xF9FB8734757F5C36ULL,
		0xBF6951F7A959460DULL,
		0xD56697863E41E716ULL,
		0x65F3F98D6EBBF111ULL,
		0xD02C4BA8B4AE2650ULL,
		0x824DD6E76BAC3AB5ULL,
		0x2F376B7442A72BC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E2ED939EE241A2ULL,
		0xF3F70E68EAFEB86DULL,
		0x7ED2A3EF52B28C1BULL,
		0xAACD2F0C7C83CE2DULL,
		0xCBE7F31ADD77E223ULL,
		0xA0589751695C4CA0ULL,
		0x049BADCED758756BULL,
		0x5E6ED6E8854E578BULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x25E70EE6EB298535ULL,
		0x8158B3ED52A5CF12ULL,
		0x51DACEB574719C92ULL,
		0xA1D9A6D840FD0FEFULL,
		0xCE7D168943417A7AULL,
		0xDAC1C4A936786A2EULL,
		0x47CA022C477600C5ULL,
		0x0859BCC145C0CBC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BCE1DCDD6530A6AULL,
		0x02B167DAA54B9E24ULL,
		0xA3B59D6AE8E33925ULL,
		0x43B34DB081FA1FDEULL,
		0x9CFA2D128682F4F5ULL,
		0xB58389526CF0D45DULL,
		0x8F9404588EEC018BULL,
		0x10B379828B819788ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x600633BAC8CC01EDULL,
		0x394E3B3E4B79765DULL,
		0xBC3E360E471C78B7ULL,
		0x39F530D0521184CDULL,
		0x8EACC66CF5658CC7ULL,
		0x3E3AB5BCE0038A8CULL,
		0xBA2D8294DCF2C61AULL,
		0x2A4DC5984FAC5F57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00C6775919803DAULL,
		0x729C767C96F2ECBAULL,
		0x787C6C1C8E38F16EULL,
		0x73EA61A0A423099BULL,
		0x1D598CD9EACB198EULL,
		0x7C756B79C0071519ULL,
		0x745B0529B9E58C34ULL,
		0x549B8B309F58BEAFULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x01E315B20056341AULL,
		0x61879C4EE1DAF292ULL,
		0xFE889BCBDC4D1B6DULL,
		0xE51D7E3F67297399ULL,
		0x1230BFE3A7A009CBULL,
		0x48226FFA9977F9EAULL,
		0x4DF7DB11751014F7ULL,
		0x3E9EBD580EFC8817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C62B6400AC6834ULL,
		0xC30F389DC3B5E524ULL,
		0xFD113797B89A36DAULL,
		0xCA3AFC7ECE52E733ULL,
		0x24617FC74F401397ULL,
		0x9044DFF532EFF3D4ULL,
		0x9BEFB622EA2029EEULL,
		0x7D3D7AB01DF9102EULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4536E0234D8E7E73ULL,
		0x74A86568DB0C0C45ULL,
		0x56145D2E67B3BBC6ULL,
		0x96D2858A576BDB61ULL,
		0x876E94D4F94A54FDULL,
		0xBAFA05BE6571C710ULL,
		0xF548057CCE5A388BULL,
		0x30F59818C1211E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A6DC0469B1CFCE6ULL,
		0xE950CAD1B618188AULL,
		0xAC28BA5CCF67778CULL,
		0x2DA50B14AED7B6C2ULL,
		0x0EDD29A9F294A9FBULL,
		0x75F40B7CCAE38E21ULL,
		0xEA900AF99CB47117ULL,
		0x61EB303182423CB3ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x66EF406DF50BBB7CULL,
		0x682D11BBC235366FULL,
		0xD5F7D439406A743EULL,
		0xEA2B6E786E30A293ULL,
		0xB4F2CD223F0DFF1CULL,
		0xD2C63C8157844368ULL,
		0x1629339F2A4684A9ULL,
		0x1D6CBDDC514B57A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDDE80DBEA1776F8ULL,
		0xD05A2377846A6CDEULL,
		0xABEFA87280D4E87CULL,
		0xD456DCF0DC614527ULL,
		0x69E59A447E1BFE39ULL,
		0xA58C7902AF0886D1ULL,
		0x2C52673E548D0953ULL,
		0x3AD97BB8A296AF4EULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8788C9AD605E6425ULL,
		0x9F117DDCEC310908ULL,
		0x2ADE260C160795B0ULL,
		0x2EF0690B1977101BULL,
		0xC5CB0941FAA78F6DULL,
		0x35F24F49BF2839D7ULL,
		0xE702A37A73932D53ULL,
		0x2C76DAE71CFDBD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F11935AC0BCC84AULL,
		0x3E22FBB9D8621211ULL,
		0x55BC4C182C0F2B61ULL,
		0x5DE0D21632EE2036ULL,
		0x8B961283F54F1EDAULL,
		0x6BE49E937E5073AFULL,
		0xCE0546F4E7265AA6ULL,
		0x58EDB5CE39FB7B25ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x66C81414A8415F6EULL,
		0x8B837B19D6196293ULL,
		0x8920C6AB54945C14ULL,
		0x5392DA62E7F5964BULL,
		0x3A51937E83013722ULL,
		0xCF52B8B53836738FULL,
		0x87AF90CAE019E314ULL,
		0x32F5542887CC1569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD9028295082BEDCULL,
		0x1706F633AC32C526ULL,
		0x12418D56A928B829ULL,
		0xA725B4C5CFEB2C97ULL,
		0x74A326FD06026E44ULL,
		0x9EA5716A706CE71EULL,
		0x0F5F2195C033C629ULL,
		0x65EAA8510F982AD3ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x50CB177D4151E785ULL,
		0x80148AAB08B456D0ULL,
		0x13D831ED7751992EULL,
		0x404B07D8326BB9B0ULL,
		0x236BFC00C2EE4436ULL,
		0x16569267E7123785ULL,
		0x34210FD284658855ULL,
		0x1CA0196015FAE0A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1962EFA82A3CF0AULL,
		0x002915561168ADA0ULL,
		0x27B063DAEEA3325DULL,
		0x80960FB064D77360ULL,
		0x46D7F80185DC886CULL,
		0x2CAD24CFCE246F0AULL,
		0x68421FA508CB10AAULL,
		0x394032C02BF5C148ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x295F1FF065789538ULL,
		0xE96ECB701324F0F3ULL,
		0x4C5B2BB8C6744F15ULL,
		0x07FD9B39F21650E2ULL,
		0x7CC7EF527EBE0BD0ULL,
		0x752D8997F7B6ECC5ULL,
		0xF56A787C5B86A5B9ULL,
		0x21F6F473A972A615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52BE3FE0CAF12A70ULL,
		0xD2DD96E02649E1E6ULL,
		0x98B657718CE89E2BULL,
		0x0FFB3673E42CA1C4ULL,
		0xF98FDEA4FD7C17A0ULL,
		0xEA5B132FEF6DD98AULL,
		0xEAD4F0F8B70D4B72ULL,
		0x43EDE8E752E54C2BULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8F2F329FF81F28EEULL,
		0x258DAD0FA2C21558ULL,
		0xA3BC4ADEF834F8F1ULL,
		0x9F7A8B0405D499B7ULL,
		0x21A1B76B526B55BDULL,
		0x75CCD0727DF3A6B9ULL,
		0x709B445214CCA745ULL,
		0x075B39982AA9AB4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5E653FF03E51DCULL,
		0x4B1B5A1F45842AB1ULL,
		0x477895BDF069F1E2ULL,
		0x3EF516080BA9336FULL,
		0x43436ED6A4D6AB7BULL,
		0xEB99A0E4FBE74D72ULL,
		0xE13688A429994E8AULL,
		0x0EB6733055535696ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x48ED87964851F612ULL,
		0x689FAC9D2917CB12ULL,
		0x8C9DE11F7806E694ULL,
		0x10B6ED0F614276ECULL,
		0x82F411AB76AC266EULL,
		0xEBFF257655180B50ULL,
		0x84F86006395C7491ULL,
		0x1F577F441C7E8349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91DB0F2C90A3EC24ULL,
		0xD13F593A522F9624ULL,
		0x193BC23EF00DCD28ULL,
		0x216DDA1EC284EDD9ULL,
		0x05E82356ED584CDCULL,
		0xD7FE4AECAA3016A1ULL,
		0x09F0C00C72B8E923ULL,
		0x3EAEFE8838FD0693ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E9BDA3F429FBA2CULL,
		0x243C170A35C287DCULL,
		0xD1BE558E57DF9133ULL,
		0x2B7EC2C2CBFAA80EULL,
		0xB1657AFBC557BA74ULL,
		0x3AF6E60A7B52D6E5ULL,
		0xFCFB7E9D2B2A39ACULL,
		0x0B955114BC4E00A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD37B47E853F7458ULL,
		0x48782E146B850FB8ULL,
		0xA37CAB1CAFBF2266ULL,
		0x56FD858597F5501DULL,
		0x62CAF5F78AAF74E8ULL,
		0x75EDCC14F6A5ADCBULL,
		0xF9F6FD3A56547358ULL,
		0x172AA229789C0151ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x60D525DD4BFE8FEDULL,
		0x11F15817F00E1856ULL,
		0x1F3927259D762C72ULL,
		0x8E030425F5F6888FULL,
		0xDBB20A1B2D1DBB96ULL,
		0xF8F30C660BD07DF1ULL,
		0x0B55FC8B38C9CE80ULL,
		0x067B80AE0F5C021CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1AA4BBA97FD1FDAULL,
		0x23E2B02FE01C30ACULL,
		0x3E724E4B3AEC58E4ULL,
		0x1C06084BEBED111EULL,
		0xB76414365A3B772DULL,
		0xF1E618CC17A0FBE3ULL,
		0x16ABF91671939D01ULL,
		0x0CF7015C1EB80438ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7DA55144337B7F8EULL,
		0xE4BF0A9B467DDAAEULL,
		0x02AE84DC1BF0BBB0ULL,
		0xD3039A6DCFA5F5D2ULL,
		0x04F29719A92D8C04ULL,
		0x8B42582D61D092A3ULL,
		0x509A268508A2991BULL,
		0x26EEB69C135EC12DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4AA28866F6FF1CULL,
		0xC97E15368CFBB55CULL,
		0x055D09B837E17761ULL,
		0xA60734DB9F4BEBA4ULL,
		0x09E52E33525B1809ULL,
		0x1684B05AC3A12546ULL,
		0xA1344D0A11453237ULL,
		0x4DDD6D3826BD825AULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD28BC74C36FE4FECULL,
		0xC65034C0D61F66A8ULL,
		0x896818D37F701748ULL,
		0x21C76DD32323D2DBULL,
		0x85D4C98ADFCCE865ULL,
		0xE8D356C246FA7990ULL,
		0x8BCF14939EB0AFC3ULL,
		0x1C8F89E3A053516BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5178E986DFC9FD8ULL,
		0x8CA06981AC3ECD51ULL,
		0x12D031A6FEE02E91ULL,
		0x438EDBA64647A5B7ULL,
		0x0BA99315BF99D0CAULL,
		0xD1A6AD848DF4F321ULL,
		0x179E29273D615F87ULL,
		0x391F13C740A6A2D7ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x010A7B695DD4D886ULL,
		0xEE1E371E53FC660CULL,
		0x8338362C29B84648ULL,
		0xF6150F23C3FC43CAULL,
		0x92A497FE29C3513BULL,
		0xC47F4AB3EA81BFB3ULL,
		0x29ED2F4547EA464AULL,
		0x2F0ED07E189D677EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0214F6D2BBA9B10CULL,
		0xDC3C6E3CA7F8CC18ULL,
		0x06706C5853708C91ULL,
		0xEC2A1E4787F88795ULL,
		0x25492FFC5386A277ULL,
		0x88FE9567D5037F67ULL,
		0x53DA5E8A8FD48C95ULL,
		0x5E1DA0FC313ACEFCULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9C39796F410239FULL,
		0xFDF2E2C0553CA1AFULL,
		0x5778F86D58F9D4A3ULL,
		0xFED76F3798F61929ULL,
		0x8B67C0653B0691C9ULL,
		0x817F58BDE9B6830DULL,
		0x071C4272FE0B8597ULL,
		0x0F1B52819F7A61F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3872F2DE820473EULL,
		0xFBE5C580AA79435FULL,
		0xAEF1F0DAB1F3A947ULL,
		0xFDAEDE6F31EC3252ULL,
		0x16CF80CA760D2393ULL,
		0x02FEB17BD36D061BULL,
		0x0E3884E5FC170B2FULL,
		0x1E36A5033EF4C3F2ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x838769B040A6D331ULL,
		0xA98D0DDDADA52FF2ULL,
		0x3404B589ACE9EACDULL,
		0xF839CC57DE35AEA2ULL,
		0xA0D894341A406B13ULL,
		0x55B4943855B43247ULL,
		0x9AD03E97CB8B98B9ULL,
		0x2ED41EF488E4B2FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x070ED360814DA662ULL,
		0x531A1BBB5B4A5FE5ULL,
		0x68096B1359D3D59BULL,
		0xF07398AFBC6B5D44ULL,
		0x41B128683480D627ULL,
		0xAB692870AB68648FULL,
		0x35A07D2F97173172ULL,
		0x5DA83DE911C965F5ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC53C802202E9448DULL,
		0xDE3B93A5DE67CC80ULL,
		0xD77CE8F794DA43CCULL,
		0xAA0696EB6AB1FB47ULL,
		0xB7EC5CE796D1941BULL,
		0x667599D52F82346FULL,
		0x40B142CF9F0870E4ULL,
		0x0E5ABDBA14E37C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A79004405D2891AULL,
		0xBC77274BBCCF9901ULL,
		0xAEF9D1EF29B48799ULL,
		0x540D2DD6D563F68FULL,
		0x6FD8B9CF2DA32837ULL,
		0xCCEB33AA5F0468DFULL,
		0x8162859F3E10E1C8ULL,
		0x1CB57B7429C6F8DCULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB3544D7D3CBA1E60ULL,
		0x07BACAC815CFF053ULL,
		0xD2B32DC57C9E9744ULL,
		0xB60575E6AC0A8493ULL,
		0x7CB73CA26527B091ULL,
		0x20A1EDED0361D6FAULL,
		0x506266533308C1E6ULL,
		0x06DDDE2FAB666809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A89AFA79743CC0ULL,
		0x0F7595902B9FE0A7ULL,
		0xA5665B8AF93D2E88ULL,
		0x6C0AEBCD58150927ULL,
		0xF96E7944CA4F6123ULL,
		0x4143DBDA06C3ADF4ULL,
		0xA0C4CCA6661183CCULL,
		0x0DBBBC5F56CCD012ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x94B7C60112649F13ULL,
		0x24FBE5E300EE130AULL,
		0x137F69D7D841B74AULL,
		0xA86D74E58D3462CEULL,
		0xE3C91B8E62AAB7BFULL,
		0x19FCA71A4D35FE16ULL,
		0xECAF062456CCDB6EULL,
		0x24B2A75CF622C4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x296F8C0224C93E26ULL,
		0x49F7CBC601DC2615ULL,
		0x26FED3AFB0836E94ULL,
		0x50DAE9CB1A68C59CULL,
		0xC792371CC5556F7FULL,
		0x33F94E349A6BFC2DULL,
		0xD95E0C48AD99B6DCULL,
		0x49654EB9EC4589EFULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF74ECF19389376EAULL,
		0xC574066714619BB7ULL,
		0xFFC1819756147AAAULL,
		0x1BF7767CA2A2D69FULL,
		0xFBD33846AA9399A8ULL,
		0x208B63BC1004CB90ULL,
		0x305EECA3ECA19CD2ULL,
		0x3776711302CCB72FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9D9E327126EDD4ULL,
		0x8AE80CCE28C3376FULL,
		0xFF83032EAC28F555ULL,
		0x37EEECF94545AD3FULL,
		0xF7A6708D55273350ULL,
		0x4116C77820099721ULL,
		0x60BDD947D94339A4ULL,
		0x6EECE22605996E5EULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7DA20CA1875DE82BULL,
		0xA7CB3FC6A68FCB04ULL,
		0x513036F9193F7F70ULL,
		0xDAB817EFAEA0A78EULL,
		0x86394AED903D555AULL,
		0xE12A9CA2EEDAA867ULL,
		0x59D0D2FD1BC60910ULL,
		0x15BF8ACA92EF4368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4419430EBBD056ULL,
		0x4F967F8D4D1F9608ULL,
		0xA2606DF2327EFEE1ULL,
		0xB5702FDF5D414F1CULL,
		0x0C7295DB207AAAB5ULL,
		0xC2553945DDB550CFULL,
		0xB3A1A5FA378C1221ULL,
		0x2B7F159525DE86D0ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6ED3BDEC41C5FA59ULL,
		0xF5F57A4CEBCA1427ULL,
		0x298764A71804F086ULL,
		0xF23DB2193F037FBBULL,
		0xA2F3FFC4E8B3DA90ULL,
		0x97B0F0EB0A8C84D6ULL,
		0x412227BCBD1C941AULL,
		0x12BFD6DF8D680B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDA77BD8838BF4B2ULL,
		0xEBEAF499D794284EULL,
		0x530EC94E3009E10DULL,
		0xE47B64327E06FF76ULL,
		0x45E7FF89D167B521ULL,
		0x2F61E1D6151909ADULL,
		0x82444F797A392835ULL,
		0x257FADBF1AD01608ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE270E59A43A88412ULL,
		0x92BF14F11FE60A4CULL,
		0xDE0E13CE8D4467EAULL,
		0xE7C53983626326FCULL,
		0x1B5A4079D3F9DC25ULL,
		0x26447F31C905A4C0ULL,
		0x8255C21B70E5851DULL,
		0x1A745A288D7C53C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E1CB3487510824ULL,
		0x257E29E23FCC1499ULL,
		0xBC1C279D1A88CFD5ULL,
		0xCF8A7306C4C64DF9ULL,
		0x36B480F3A7F3B84BULL,
		0x4C88FE63920B4980ULL,
		0x04AB8436E1CB0A3AULL,
		0x34E8B4511AF8A78FULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8291631D95E9350BULL,
		0x0B96A14FE768B480ULL,
		0xEB282E5F159F90F6ULL,
		0x979319063E8600B9ULL,
		0xF96E414C77BF4314ULL,
		0x95F0527B5BFB0176ULL,
		0x590B942ED4174A31ULL,
		0x32C5E7C28505C0B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0522C63B2BD26A16ULL,
		0x172D429FCED16901ULL,
		0xD6505CBE2B3F21ECULL,
		0x2F26320C7D0C0173ULL,
		0xF2DC8298EF7E8629ULL,
		0x2BE0A4F6B7F602EDULL,
		0xB217285DA82E9463ULL,
		0x658BCF850A0B8170ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD0133FB3FD4D81B4ULL,
		0x2E1611C4892E3D5EULL,
		0xFE90F28DAD51D21BULL,
		0x56F1DFFC4E56AC41ULL,
		0xE9B2560581E78A89ULL,
		0x472781D767F6BD31ULL,
		0xC8252A64FA8D69D6ULL,
		0x1A5C39A318A3670CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0267F67FA9B0368ULL,
		0x5C2C2389125C7ABDULL,
		0xFD21E51B5AA3A436ULL,
		0xADE3BFF89CAD5883ULL,
		0xD364AC0B03CF1512ULL,
		0x8E4F03AECFED7A63ULL,
		0x904A54C9F51AD3ACULL,
		0x34B873463146CE19ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x65AA98C9C2FE9D6BULL,
		0x6B2B743D2FB8E37EULL,
		0x24DD3480068F9E09ULL,
		0xA1BB8B175A3B3803ULL,
		0x841F9A0E59A63DEAULL,
		0x1A0694A2CD00DFA0ULL,
		0xB038AE25E08F18B6ULL,
		0x22CE0C25033B7C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB55319385FD3AD6ULL,
		0xD656E87A5F71C6FCULL,
		0x49BA69000D1F3C12ULL,
		0x4377162EB4767006ULL,
		0x083F341CB34C7BD5ULL,
		0x340D29459A01BF41ULL,
		0x60715C4BC11E316CULL,
		0x459C184A0676F839ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA0122E115E9FBA5CULL,
		0x00D37571B1CF95AAULL,
		0x00B7C822FE149426ULL,
		0x862EA9DF3C3B407AULL,
		0xE7F11088EF5AD504ULL,
		0x82C30D08DEF7A706ULL,
		0xC60CAD3660EAC04DULL,
		0x1D9F20E1F85D3631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40245C22BD3F74B8ULL,
		0x01A6EAE3639F2B55ULL,
		0x016F9045FC29284CULL,
		0x0C5D53BE787680F4ULL,
		0xCFE22111DEB5AA09ULL,
		0x05861A11BDEF4E0DULL,
		0x8C195A6CC1D5809BULL,
		0x3B3E41C3F0BA6C63ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x76FA6A14771EAAD1ULL,
		0x5314131367E9999BULL,
		0x6A4AA96F8989B5D7ULL,
		0x533D4EC38320F8C1ULL,
		0x3026BE013D15DC4EULL,
		0xC5A6053F495A6D27ULL,
		0x5B09341F75A2E269ULL,
		0x2CED278AF4B41D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDF4D428EE3D55A2ULL,
		0xA6282626CFD33336ULL,
		0xD49552DF13136BAEULL,
		0xA67A9D870641F182ULL,
		0x604D7C027A2BB89CULL,
		0x8B4C0A7E92B4DA4EULL,
		0xB612683EEB45C4D3ULL,
		0x59DA4F15E9683B3EULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD1AE14B21B0DA10ULL,
		0xC14B6A2513B1295AULL,
		0xF8083D1B168619E5ULL,
		0x6F3FEE618EC98988ULL,
		0x8373D2DBBE73CBE5ULL,
		0x87D250D899885D08ULL,
		0x886286667187BAACULL,
		0x01C43848F9F4BA8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA35C2964361B420ULL,
		0x8296D44A276252B5ULL,
		0xF0107A362D0C33CBULL,
		0xDE7FDCC31D931311ULL,
		0x06E7A5B77CE797CAULL,
		0x0FA4A1B13310BA11ULL,
		0x10C50CCCE30F7559ULL,
		0x03887091F3E9751DULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD55B575282A54690ULL,
		0x034DB244B0319A92ULL,
		0x4856F8D8829BF446ULL,
		0xBC61BAB6E019BB9DULL,
		0x8277D42508EB8802ULL,
		0x4DEFDC4C4F05591BULL,
		0xE3D7C260B4CD2A34ULL,
		0x1D98BC9F17C943C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAB6AEA5054A8D20ULL,
		0x069B648960633525ULL,
		0x90ADF1B10537E88CULL,
		0x78C3756DC033773AULL,
		0x04EFA84A11D71005ULL,
		0x9BDFB8989E0AB237ULL,
		0xC7AF84C1699A5468ULL,
		0x3B31793E2F92878FULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBFE23E8BBD4D7B10ULL,
		0x77D56D150083FA73ULL,
		0x3013A725336635B4ULL,
		0x478D48DBEA5F5C39ULL,
		0xE9E6CE9B29D5AE90ULL,
		0x7BEC8E0732921D1FULL,
		0x831E1883723794E9ULL,
		0x2D13C9340C159FA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC47D177A9AF620ULL,
		0xEFAADA2A0107F4E7ULL,
		0x60274E4A66CC6B68ULL,
		0x8F1A91B7D4BEB872ULL,
		0xD3CD9D3653AB5D20ULL,
		0xF7D91C0E65243A3FULL,
		0x063C3106E46F29D2ULL,
		0x5A279268182B3F49ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x55F8835DAF6C3EE3ULL,
		0x8638D34DC6E15AF9ULL,
		0x2EED5C8B4D8BD3C0ULL,
		0x549E8445CD91F18EULL,
		0x66B7DDF9DBB71E45ULL,
		0x2025032D7883D151ULL,
		0xE1883DA7B8EED011ULL,
		0x09201C4CD88CAA4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABF106BB5ED87DC6ULL,
		0x0C71A69B8DC2B5F2ULL,
		0x5DDAB9169B17A781ULL,
		0xA93D088B9B23E31CULL,
		0xCD6FBBF3B76E3C8AULL,
		0x404A065AF107A2A2ULL,
		0xC3107B4F71DDA022ULL,
		0x12403899B1195495ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC8A3E92622AFBCA0ULL,
		0x4CCEDCCBC5CB5A34ULL,
		0xD258C20A214D453FULL,
		0x245C5CCF000D7EB7ULL,
		0x65766522483070DCULL,
		0x97FAB076E10BAE43ULL,
		0x25ECF60C1091DCA5ULL,
		0x3B2D87F369BACFE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9147D24C455F7940ULL,
		0x999DB9978B96B469ULL,
		0xA4B18414429A8A7EULL,
		0x48B8B99E001AFD6FULL,
		0xCAECCA449060E1B8ULL,
		0x2FF560EDC2175C86ULL,
		0x4BD9EC182123B94BULL,
		0x765B0FE6D3759FC2ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD66C366DBC2286EDULL,
		0x329148DBEC185545ULL,
		0x6FC05D7D64658B70ULL,
		0xF08BC3C7F8341507ULL,
		0xBD08FB02F5F13639ULL,
		0x1DC6BE52AADB5BC6ULL,
		0xFA91A28105EF1759ULL,
		0x34981CB5EB41046EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD86CDB78450DDAULL,
		0x652291B7D830AA8BULL,
		0xDF80BAFAC8CB16E0ULL,
		0xE117878FF0682A0EULL,
		0x7A11F605EBE26C73ULL,
		0x3B8D7CA555B6B78DULL,
		0xF52345020BDE2EB2ULL,
		0x6930396BD68208DDULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x05D4B6A261865179ULL,
		0xA15B76F286FA1AD9ULL,
		0xEB3BF199CD436D24ULL,
		0xD125E0C62F7634CBULL,
		0x0098E67F8DF158BCULL,
		0x9DDC37A85A769BE3ULL,
		0xB622696D0753871CULL,
		0x35688C4BAC584C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA96D44C30CA2F2ULL,
		0x42B6EDE50DF435B2ULL,
		0xD677E3339A86DA49ULL,
		0xA24BC18C5EEC6997ULL,
		0x0131CCFF1BE2B179ULL,
		0x3BB86F50B4ED37C6ULL,
		0x6C44D2DA0EA70E39ULL,
		0x6AD1189758B0990DULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B597CC7F17AF4F9ULL,
		0xC9D83A5FD9BD945CULL,
		0xB8C43813E3B75880ULL,
		0x08FEA1B40B62322AULL,
		0x039ED507A9B241C4ULL,
		0xBA741A6D81B85870ULL,
		0xBF35F7064AD24F4EULL,
		0x3B6F5A3DE4EC3FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B2F98FE2F5E9F2ULL,
		0x93B074BFB37B28B8ULL,
		0x71887027C76EB101ULL,
		0x11FD436816C46455ULL,
		0x073DAA0F53648388ULL,
		0x74E834DB0370B0E0ULL,
		0x7E6BEE0C95A49E9DULL,
		0x76DEB47BC9D87FDFULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5F5FE77D2730467BULL,
		0x6DD5D829C2E0F55EULL,
		0xE31235FB8D58BD4FULL,
		0xCE595AFB405EB1AFULL,
		0x97E262E1C2F42D81ULL,
		0xE662D4ECDB3694E7ULL,
		0xF34ABBAC21D67DA9ULL,
		0x12E8772EF57BB30DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEBFCEFA4E608CF6ULL,
		0xDBABB05385C1EABCULL,
		0xC6246BF71AB17A9EULL,
		0x9CB2B5F680BD635FULL,
		0x2FC4C5C385E85B03ULL,
		0xCCC5A9D9B66D29CFULL,
		0xE695775843ACFB53ULL,
		0x25D0EE5DEAF7661BULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF9E73AB5CCD4C2FDULL,
		0x0A88B394B6A68F2BULL,
		0x97BF861437A633F1ULL,
		0x54C2C83DA5B6B159ULL,
		0x5B9646258BCC3424ULL,
		0xDE1FF0B933DFED59ULL,
		0x148387BB717E1F27ULL,
		0x158101B61E33ADADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3CE756B99A985FAULL,
		0x151167296D4D1E57ULL,
		0x2F7F0C286F4C67E2ULL,
		0xA985907B4B6D62B3ULL,
		0xB72C8C4B17986848ULL,
		0xBC3FE17267BFDAB2ULL,
		0x29070F76E2FC3E4FULL,
		0x2B02036C3C675B5AULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x045687246E7915A6ULL,
		0xD64A36846521D772ULL,
		0x9189165A2A966DD2ULL,
		0x7FBE5BEF3BCF82A4ULL,
		0xDF51A50F5A9FF8ADULL,
		0x79F850D4FE9D7137ULL,
		0x830F8F517DDB80D0ULL,
		0x091DD96B9A2F01C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AD0E48DCF22B4CULL,
		0xAC946D08CA43AEE4ULL,
		0x23122CB4552CDBA5ULL,
		0xFF7CB7DE779F0549ULL,
		0xBEA34A1EB53FF15AULL,
		0xF3F0A1A9FD3AE26FULL,
		0x061F1EA2FBB701A0ULL,
		0x123BB2D7345E0387ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8B5ACAC9A72CCBC3ULL,
		0xBF9F098C25DDCB3BULL,
		0x8D624A21E14106CEULL,
		0x65906B56E3B9A9A5ULL,
		0xA057A48309BE1BAFULL,
		0xE8DF8CE4A64CC893ULL,
		0x95F33101A95F6C68ULL,
		0x001061D1DDE49D65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B595934E599786ULL,
		0x7F3E13184BBB9677ULL,
		0x1AC49443C2820D9DULL,
		0xCB20D6ADC773534BULL,
		0x40AF4906137C375EULL,
		0xD1BF19C94C999127ULL,
		0x2BE6620352BED8D1ULL,
		0x0020C3A3BBC93ACBULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x72CE5CA2A2528B88ULL,
		0x22AE7CC55EA1FC1BULL,
		0x4CAC416FF2FDC376ULL,
		0x9E4AB0A66CC8E6A1ULL,
		0x44B0A07E7FF1ECB4ULL,
		0xC27F6BCAA4D1F4E0ULL,
		0x71713FAF47162D26ULL,
		0x27628C62CC4AE668ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE59CB94544A51710ULL,
		0x455CF98ABD43F836ULL,
		0x995882DFE5FB86ECULL,
		0x3C95614CD991CD42ULL,
		0x896140FCFFE3D969ULL,
		0x84FED79549A3E9C0ULL,
		0xE2E27F5E8E2C5A4DULL,
		0x4EC518C59895CCD0ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x38A068B6F503ADD7ULL,
		0x2525500470546BD5ULL,
		0x388EB70DC7273288ULL,
		0x94525F0E1472417AULL,
		0xEEDAC8BBC559226DULL,
		0xBD90B7736ED849A2ULL,
		0xA1DD7EF50BB0DBE7ULL,
		0x1356F7B3A1984CFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7140D16DEA075BAEULL,
		0x4A4AA008E0A8D7AAULL,
		0x711D6E1B8E4E6510ULL,
		0x28A4BE1C28E482F4ULL,
		0xDDB591778AB244DBULL,
		0x7B216EE6DDB09345ULL,
		0x43BAFDEA1761B7CFULL,
		0x26ADEF67433099FFULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4CADAB9B0AA66593ULL,
		0x9390C78992BDEA2FULL,
		0x7A5C7CCB6393DC74ULL,
		0x26DB695970D1AF91ULL,
		0xECDF6A0AF9A458E0ULL,
		0x79572F377143E5A4ULL,
		0x5CF5B841A624BA53ULL,
		0x2F1B6EE8A29F827FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x995B5736154CCB26ULL,
		0x27218F13257BD45EULL,
		0xF4B8F996C727B8E9ULL,
		0x4DB6D2B2E1A35F22ULL,
		0xD9BED415F348B1C0ULL,
		0xF2AE5E6EE287CB49ULL,
		0xB9EB70834C4974A6ULL,
		0x5E36DDD1453F04FEULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9A62B9E8A0E2365CULL,
		0x9CE909DB92F0E1ADULL,
		0x950BFCCE57931D51ULL,
		0x01FCF2A76F4FEF87ULL,
		0x96E8F860C3B3B91DULL,
		0xB10EDA3B1EE57AAEULL,
		0x469F65B054878400ULL,
		0x36BB92D7D1878A35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C573D141C46CB8ULL,
		0x39D213B725E1C35BULL,
		0x2A17F99CAF263AA3ULL,
		0x03F9E54EDE9FDF0FULL,
		0x2DD1F0C18767723AULL,
		0x621DB4763DCAF55DULL,
		0x8D3ECB60A90F0801ULL,
		0x6D7725AFA30F146AULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19AE7760F46B37E8ULL,
		0x8FB98950A933B97DULL,
		0x5CC1AA3F895A4D68ULL,
		0xB43FFA2D3A088507ULL,
		0x144C54DDB26A4956ULL,
		0xDEC416F2E372569DULL,
		0x09A315BE121D90C1ULL,
		0x177A302BFFA6FBC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x335CEEC1E8D66FD0ULL,
		0x1F7312A1526772FAULL,
		0xB983547F12B49AD1ULL,
		0x687FF45A74110A0EULL,
		0x2898A9BB64D492ADULL,
		0xBD882DE5C6E4AD3AULL,
		0x13462B7C243B2183ULL,
		0x2EF46057FF4DF78AULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1FF3EDC08EC70DAFULL,
		0x2DE3D44D6E100212ULL,
		0xA9214EFAC7B1C751ULL,
		0x80960231770AC6ABULL,
		0xC6F2D3C2D566A298ULL,
		0x96D800B28A8A99E7ULL,
		0x8E174FD9424C6A9DULL,
		0x369056E32A6CD5E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FE7DB811D8E1B5EULL,
		0x5BC7A89ADC200424ULL,
		0x52429DF58F638EA2ULL,
		0x012C0462EE158D57ULL,
		0x8DE5A785AACD4531ULL,
		0x2DB00165151533CFULL,
		0x1C2E9FB28498D53BULL,
		0x6D20ADC654D9ABC7ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD7C81A260992DA0BULL,
		0xAC2714357667AEBFULL,
		0x73E4DE17F8E62D26ULL,
		0xACB9AF117D3A6712ULL,
		0x1977F54B69F253A1ULL,
		0x6FA4E0CB460797D0ULL,
		0x40570EA4FA332680ULL,
		0x3197F3F7F720B41DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF90344C1325B416ULL,
		0x584E286AECCF5D7FULL,
		0xE7C9BC2FF1CC5A4DULL,
		0x59735E22FA74CE24ULL,
		0x32EFEA96D3E4A743ULL,
		0xDF49C1968C0F2FA0ULL,
		0x80AE1D49F4664D00ULL,
		0x632FE7EFEE41683AULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF843ABBD990C8FEBULL,
		0x3221092E7EBA19DAULL,
		0xFA899FF6821ECE6DULL,
		0xD5873EE37EAFB28CULL,
		0x2B60FE10A960E497ULL,
		0xC7A3E30764D62954ULL,
		0x879ED27526F76428ULL,
		0x217D4DE4E0414151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF087577B32191FD6ULL,
		0x6442125CFD7433B5ULL,
		0xF5133FED043D9CDAULL,
		0xAB0E7DC6FD5F6519ULL,
		0x56C1FC2152C1C92FULL,
		0x8F47C60EC9AC52A8ULL,
		0x0F3DA4EA4DEEC851ULL,
		0x42FA9BC9C08282A3ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x09A485C8604022B9ULL,
		0x01F8BA04C06D5814ULL,
		0x140E9A558CBBFC49ULL,
		0xA7CD0F1ECFDCF954ULL,
		0xE9EE987C62E1503EULL,
		0x3EAD34585081B934ULL,
		0x2BBFDC8C308AD723ULL,
		0x3510AE74CC422064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13490B90C0804572ULL,
		0x03F1740980DAB028ULL,
		0x281D34AB1977F892ULL,
		0x4F9A1E3D9FB9F2A8ULL,
		0xD3DD30F8C5C2A07DULL,
		0x7D5A68B0A1037269ULL,
		0x577FB9186115AE46ULL,
		0x6A215CE9988440C8ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB55BF6699ED5123ULL,
		0x328D7D1AAB876D18ULL,
		0xC092B46EA5A5D3CDULL,
		0xE23D94CAF070EEA7ULL,
		0x5F1EACBE7C65DFC9ULL,
		0xE79A9E975FD4EC9AULL,
		0xD6E9C8C883431F9FULL,
		0x33D915B007FCF2E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AB7ECD33DAA246ULL,
		0x651AFA35570EDA31ULL,
		0x812568DD4B4BA79AULL,
		0xC47B2995E0E1DD4FULL,
		0xBE3D597CF8CBBF93ULL,
		0xCF353D2EBFA9D934ULL,
		0xADD3919106863F3FULL,
		0x67B22B600FF9E5CFULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF636D9DD6E46324ULL,
		0xDCEB772B58C06438ULL,
		0x4FC1CC82AF6A71C2ULL,
		0x2128A1FDE448F111ULL,
		0xBBF1DFEF35DA621BULL,
		0x255B35331D474E02ULL,
		0x6C5DA74021475ED9ULL,
		0x0CDB5B3BE1308E76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC6DB3BADC8C648ULL,
		0xB9D6EE56B180C871ULL,
		0x9F8399055ED4E385ULL,
		0x425143FBC891E222ULL,
		0x77E3BFDE6BB4C436ULL,
		0x4AB66A663A8E9C05ULL,
		0xD8BB4E80428EBDB2ULL,
		0x19B6B677C2611CECULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9622BEC5C759E396ULL,
		0x0ECC0678681356B5ULL,
		0xB2D947FDF1712594ULL,
		0x1098E53C618B7305ULL,
		0x4E18B6250402CB44ULL,
		0x8AE749994BD3914BULL,
		0xFFA6CA7173661A60ULL,
		0x38F0802C315D4321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C457D8B8EB3C72CULL,
		0x1D980CF0D026AD6BULL,
		0x65B28FFBE2E24B28ULL,
		0x2131CA78C316E60BULL,
		0x9C316C4A08059688ULL,
		0x15CE933297A72296ULL,
		0xFF4D94E2E6CC34C1ULL,
		0x71E1005862BA8643ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x182E5CDAAEC4FC7FULL,
		0x9161D0BA0E3AC790ULL,
		0x2DDA9196E12558C0ULL,
		0x2A2265D34EAE7527ULL,
		0xD664CACE4339DBD4ULL,
		0x8DCE8AA1D8B573B2ULL,
		0x3C4850270B7D9A52ULL,
		0x1B4A968AE04AFCC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x305CB9B55D89F8FEULL,
		0x22C3A1741C758F20ULL,
		0x5BB5232DC24AB181ULL,
		0x5444CBA69D5CEA4EULL,
		0xACC9959C8673B7A8ULL,
		0x1B9D1543B16AE765ULL,
		0x7890A04E16FB34A5ULL,
		0x36952D15C095F984ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x993EB63EAAAAFF02ULL,
		0xA0DAFB791696BF80ULL,
		0xD521AD8EDFB8E5E8ULL,
		0xE1F7DC2ED71C9B6DULL,
		0x895762E71054B132ULL,
		0xF90CDFC9095A21DCULL,
		0xED30D09FC4ECD137ULL,
		0x0EEE1B572C638F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x327D6C7D5555FE04ULL,
		0x41B5F6F22D2D7F01ULL,
		0xAA435B1DBF71CBD1ULL,
		0xC3EFB85DAE3936DBULL,
		0x12AEC5CE20A96265ULL,
		0xF219BF9212B443B9ULL,
		0xDA61A13F89D9A26FULL,
		0x1DDC36AE58C71E19ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1D5A2BC7EEB6FF38ULL,
		0xF4E4F657D46D9959ULL,
		0x10C04AD437DE31A2ULL,
		0x82AFA963F3095089ULL,
		0xAC528D92C1A23CADULL,
		0x1EC21515E1324FDBULL,
		0x15745561621D584DULL,
		0x310BE08CC351D54AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AB4578FDD6DFE70ULL,
		0xE9C9ECAFA8DB32B2ULL,
		0x218095A86FBC6345ULL,
		0x055F52C7E612A112ULL,
		0x58A51B258344795BULL,
		0x3D842A2BC2649FB7ULL,
		0x2AE8AAC2C43AB09AULL,
		0x6217C11986A3AA94ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x304895ED0F49D49EULL,
		0xA882B54A85F01808ULL,
		0xA65CF66270245C03ULL,
		0x5B9951F90F53C965ULL,
		0x83C7EFD9B7F23C15ULL,
		0x38847F0985D75E02ULL,
		0x017EBB6082F26200ULL,
		0x0F0B23C986343C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60912BDA1E93A93CULL,
		0x51056A950BE03010ULL,
		0x4CB9ECC4E048B807ULL,
		0xB732A3F21EA792CBULL,
		0x078FDFB36FE4782AULL,
		0x7108FE130BAEBC05ULL,
		0x02FD76C105E4C400ULL,
		0x1E1647930C687916ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3E580CD6065F0FC1ULL,
		0xBC1334CF41EA24B8ULL,
		0x03A108A949665E1DULL,
		0xE29E5CDB94D153AAULL,
		0xCF8EB69E78E6AC62ULL,
		0xAB84B6B3129AC7EBULL,
		0x7F54F34947264911ULL,
		0x3DB6D5984EF170E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB019AC0CBE1F82ULL,
		0x7826699E83D44970ULL,
		0x0742115292CCBC3BULL,
		0xC53CB9B729A2A754ULL,
		0x9F1D6D3CF1CD58C5ULL,
		0x57096D6625358FD7ULL,
		0xFEA9E6928E4C9223ULL,
		0x7B6DAB309DE2E1CEULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5374DBDD68170DEFULL,
		0x4D394C4E7A876934ULL,
		0xF11299547C4F76E7ULL,
		0x4B7128A32B2F639CULL,
		0xFEB349956D75DB26ULL,
		0x71C2E7AFB83BF524ULL,
		0x971359AC496430C4ULL,
		0x038B47D3236E070AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E9B7BAD02E1BDEULL,
		0x9A72989CF50ED268ULL,
		0xE22532A8F89EEDCEULL,
		0x96E25146565EC739ULL,
		0xFD66932ADAEBB64CULL,
		0xE385CF5F7077EA49ULL,
		0x2E26B35892C86188ULL,
		0x07168FA646DC0E15ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9BFC5E3C29F8378CULL,
		0x24225DADF88FC191ULL,
		0xE385F90B09AA40DBULL,
		0x37BAFA562365CF2EULL,
		0x2E8B76E6E5DC2BA1ULL,
		0x8BF93D06889D254AULL,
		0x4809428D57E6196DULL,
		0x2408FF3E9D44934FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F8BC7853F06F18ULL,
		0x4844BB5BF11F8323ULL,
		0xC70BF216135481B6ULL,
		0x6F75F4AC46CB9E5DULL,
		0x5D16EDCDCBB85742ULL,
		0x17F27A0D113A4A94ULL,
		0x9012851AAFCC32DBULL,
		0x4811FE7D3A89269EULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x613824F188DA6C44ULL,
		0xFF97C0A4A017AC81ULL,
		0x44BC9263AF4EDDF5ULL,
		0x8235CE9358387C92ULL,
		0xD47426951F77AE1EULL,
		0x3627C5F81B0C9BEAULL,
		0xC89EBB02C59D6454ULL,
		0x1B65271FB340135FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC27049E311B4D888ULL,
		0xFF2F8149402F5902ULL,
		0x897924C75E9DBBEBULL,
		0x046B9D26B070F924ULL,
		0xA8E84D2A3EEF5C3DULL,
		0x6C4F8BF0361937D5ULL,
		0x913D76058B3AC8A8ULL,
		0x36CA4E3F668026BFULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5E26CADBD4454B28ULL,
		0x0EC9A15E41B7B2ABULL,
		0x80BDC2BD07E8A8CDULL,
		0x7FA504E10166DDAEULL,
		0x09DED11873BEBCF4ULL,
		0x904B4521EF9F61D2ULL,
		0xD4F4B2C371CC5CD6ULL,
		0x0F1B2D087421120BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4D95B7A88A9650ULL,
		0x1D9342BC836F6556ULL,
		0x017B857A0FD1519AULL,
		0xFF4A09C202CDBB5DULL,
		0x13BDA230E77D79E8ULL,
		0x20968A43DF3EC3A4ULL,
		0xA9E96586E398B9ADULL,
		0x1E365A10E8422417ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD87CF45096141437ULL,
		0xF54D6F2F49C56195ULL,
		0x5E0897C42F426852ULL,
		0x3BBC00A8261845D0ULL,
		0x892D446C584A4898ULL,
		0x21394313DF852F33ULL,
		0x7844323C7203388FULL,
		0x1D07F13A232656CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0F9E8A12C28286EULL,
		0xEA9ADE5E938AC32BULL,
		0xBC112F885E84D0A5ULL,
		0x777801504C308BA0ULL,
		0x125A88D8B0949130ULL,
		0x42728627BF0A5E67ULL,
		0xF0886478E406711EULL,
		0x3A0FE274464CAD9AULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAF9B408A23E216F6ULL,
		0x590BA2634479EBECULL,
		0xC637CF47EE15B32EULL,
		0x84059892DFCB2B79ULL,
		0x4799308178E90E6EULL,
		0x4CEA7C6F877C5D71ULL,
		0x761F1C2FC8CA4803ULL,
		0x0219C7EA2ABD96BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F36811447C42DECULL,
		0xB21744C688F3D7D9ULL,
		0x8C6F9E8FDC2B665CULL,
		0x080B3125BF9656F3ULL,
		0x8F326102F1D21CDDULL,
		0x99D4F8DF0EF8BAE2ULL,
		0xEC3E385F91949006ULL,
		0x04338FD4557B2D74ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2A42732EC8C6F900ULL,
		0x93B90B988DD392D5ULL,
		0x12A4BCF3A637B2EAULL,
		0x9B57E04094CFA1AAULL,
		0x83129119A2C1A28EULL,
		0x42B1D3CF4543709AULL,
		0x6D1C19BAB217228AULL,
		0x0F0D31B8FCFB07EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5484E65D918DF200ULL,
		0x277217311BA725AAULL,
		0x254979E74C6F65D5ULL,
		0x36AFC081299F4354ULL,
		0x062522334583451DULL,
		0x8563A79E8A86E135ULL,
		0xDA383375642E4514ULL,
		0x1E1A6371F9F60FDEULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9D26841914F4F05EULL,
		0x6271E95403991A0FULL,
		0xD1E1053FE56AB004ULL,
		0x85C4FB21D1150CE1ULL,
		0x45C29703E07C5AA9ULL,
		0x5C30ED6BD74C28FCULL,
		0xDB3CF575580A5B8DULL,
		0x10D6464A1504D180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A4D083229E9E0BCULL,
		0xC4E3D2A80732341FULL,
		0xA3C20A7FCAD56008ULL,
		0x0B89F643A22A19C3ULL,
		0x8B852E07C0F8B553ULL,
		0xB861DAD7AE9851F8ULL,
		0xB679EAEAB014B71AULL,
		0x21AC8C942A09A301ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1A59380000564F41ULL,
		0xFC862539D5859EB6ULL,
		0x33066F83C3926E6EULL,
		0xED8DB40B7FE39E50ULL,
		0xF2AB4619F42E9FFAULL,
		0x830F6E3543D0DE7BULL,
		0xA7B627C1078E3213ULL,
		0x09C3045CE2FF1893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B2700000AC9E82ULL,
		0xF90C4A73AB0B3D6CULL,
		0x660CDF078724DCDDULL,
		0xDB1B6816FFC73CA0ULL,
		0xE5568C33E85D3FF5ULL,
		0x061EDC6A87A1BCF7ULL,
		0x4F6C4F820F1C6427ULL,
		0x138608B9C5FE3127ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE9980A07B33B801ULL,
		0x9E0576D58BA2B98BULL,
		0xD980BE3A361186A2ULL,
		0x77502151177B8873ULL,
		0xB512DD79FB69FD3EULL,
		0x464AC548CD3453BDULL,
		0x050CAD4CEEC540C8ULL,
		0x20263325C315D135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD330140F6677002ULL,
		0x3C0AEDAB17457317ULL,
		0xB3017C746C230D45ULL,
		0xEEA042A22EF710E7ULL,
		0x6A25BAF3F6D3FA7CULL,
		0x8C958A919A68A77BULL,
		0x0A195A99DD8A8190ULL,
		0x404C664B862BA26AULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x54ED2AB0D26625EAULL,
		0x55FD0ABCBAD72A65ULL,
		0xCB94515D7AB93E5AULL,
		0x01251C3343138595ULL,
		0x171D1B115A79569BULL,
		0xFC164804F5187DCAULL,
		0x027BA8E4A61CF3C3ULL,
		0x18CB6CB4021A7D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DA5561A4CC4BD4ULL,
		0xABFA157975AE54CAULL,
		0x9728A2BAF5727CB4ULL,
		0x024A386686270B2BULL,
		0x2E3A3622B4F2AD36ULL,
		0xF82C9009EA30FB94ULL,
		0x04F751C94C39E787ULL,
		0x3196D9680434FA6EULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x93B18B7E379B837EULL,
		0xDBE4F5558FC44980ULL,
		0xD5251C0668EA528DULL,
		0xA50DDC0ACF855BD8ULL,
		0x5FEDEA5D8F77BB65ULL,
		0xEC9DD5A1FC28E9D0ULL,
		0x2CD3F2F945264FC5ULL,
		0x3D7EF9D5E8A7F3B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x276316FC6F3706FCULL,
		0xB7C9EAAB1F889301ULL,
		0xAA4A380CD1D4A51BULL,
		0x4A1BB8159F0AB7B1ULL,
		0xBFDBD4BB1EEF76CBULL,
		0xD93BAB43F851D3A0ULL,
		0x59A7E5F28A4C9F8BULL,
		0x7AFDF3ABD14FE76CULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x52FE38C874513951ULL,
		0x59FE718C6EE528F1ULL,
		0xAC3688AE87FB05D1ULL,
		0xD9586827C4CD9B8CULL,
		0x61FE96D3C767ACDDULL,
		0xBAD537272E7239FDULL,
		0xAD40477EB85C3954ULL,
		0x06F7F5E788418719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5FC7190E8A272A2ULL,
		0xB3FCE318DDCA51E2ULL,
		0x586D115D0FF60BA2ULL,
		0xB2B0D04F899B3719ULL,
		0xC3FD2DA78ECF59BBULL,
		0x75AA6E4E5CE473FAULL,
		0x5A808EFD70B872A9ULL,
		0x0DEFEBCF10830E33ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBED1221BBDF2F792ULL,
		0x1EC5147FFB60D755ULL,
		0xD6F50DC3F6A50C38ULL,
		0x7F0FEFD33DB40497ULL,
		0x9536C82B6F47E4BAULL,
		0x2B6BCF14AA185721ULL,
		0xF1EE8942856BF785ULL,
		0x18079BD41A457782ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA244377BE5EF24ULL,
		0x3D8A28FFF6C1AEABULL,
		0xADEA1B87ED4A1870ULL,
		0xFE1FDFA67B68092FULL,
		0x2A6D9056DE8FC974ULL,
		0x56D79E295430AE43ULL,
		0xE3DD12850AD7EF0AULL,
		0x300F37A8348AEF05ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4BC79589D369A108ULL,
		0x11AAEC3611ADA108ULL,
		0x76AEF864A155B91BULL,
		0xA0E491ECA13B29A2ULL,
		0xE58D6E3DFAF14D1AULL,
		0x98B8DF1CA11C38FCULL,
		0x6D37EB6076BDBCA4ULL,
		0x2698773FEABE3E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x978F2B13A6D34210ULL,
		0x2355D86C235B4210ULL,
		0xED5DF0C942AB7236ULL,
		0x41C923D942765344ULL,
		0xCB1ADC7BF5E29A35ULL,
		0x3171BE39423871F9ULL,
		0xDA6FD6C0ED7B7949ULL,
		0x4D30EE7FD57C7C92ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC22038B8D35034C7ULL,
		0x47FADD7834B75B5DULL,
		0x57406A2EC7B2BE60ULL,
		0x74D67E2F01632706ULL,
		0xA80BDC042139B384ULL,
		0x4E7C57913F3C196FULL,
		0xCDD5538ED2F8AEA8ULL,
		0x1B8B28B66BC8176CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84407171A6A0698EULL,
		0x8FF5BAF0696EB6BBULL,
		0xAE80D45D8F657CC0ULL,
		0xE9ACFC5E02C64E0CULL,
		0x5017B80842736708ULL,
		0x9CF8AF227E7832DFULL,
		0x9BAAA71DA5F15D50ULL,
		0x3716516CD7902ED9ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x937D21FB9131AFA1ULL,
		0x61ECE433A9BAA184ULL,
		0x8F63FD57AD428784ULL,
		0x240BE78D95543193ULL,
		0x0CEC72982F431AB9ULL,
		0x91467EF6FC2119F0ULL,
		0xF104F6A0C5DC19CDULL,
		0x3A3CC0A76AF034E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26FA43F722635F42ULL,
		0xC3D9C86753754309ULL,
		0x1EC7FAAF5A850F08ULL,
		0x4817CF1B2AA86327ULL,
		0x19D8E5305E863572ULL,
		0x228CFDEDF84233E0ULL,
		0xE209ED418BB8339BULL,
		0x7479814ED5E069CDULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A7D0D801B3612A0ULL,
		0xC9881064A3FD56F8ULL,
		0x42FA96816D9B10ECULL,
		0xBD9BDB855EE9711AULL,
		0x617A296FD0651132ULL,
		0x56A6328625A33418ULL,
		0x94DC49686381E263ULL,
		0x0F6F3C2680E9AC04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4FA1B00366C2540ULL,
		0x931020C947FAADF0ULL,
		0x85F52D02DB3621D9ULL,
		0x7B37B70ABDD2E234ULL,
		0xC2F452DFA0CA2265ULL,
		0xAD4C650C4B466830ULL,
		0x29B892D0C703C4C6ULL,
		0x1EDE784D01D35809ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAF183FB6E5936E4FULL,
		0xF811B1B31E24DD57ULL,
		0xC37E7FE7892A8B5AULL,
		0xFD371F5108FD48FCULL,
		0x056B1499F67DFA15ULL,
		0xB80C3F67293A2FB3ULL,
		0x02593EE431FAA12FULL,
		0x0998495CE10855FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E307F6DCB26DC9EULL,
		0xF02363663C49BAAFULL,
		0x86FCFFCF125516B5ULL,
		0xFA6E3EA211FA91F9ULL,
		0x0AD62933ECFBF42BULL,
		0x70187ECE52745F66ULL,
		0x04B27DC863F5425FULL,
		0x133092B9C210ABFEULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9F3ADD42CC06AC4AULL,
		0x0F28D3811D36CBBBULL,
		0xEA9A54079288C2F3ULL,
		0x9E0164C92F5E6579ULL,
		0x3AED8B671ECB3451ULL,
		0x404588B0D9F721F1ULL,
		0x87DFA009DE1CD36DULL,
		0x3B7E3294712BDB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E75BA85980D5894ULL,
		0x1E51A7023A6D9777ULL,
		0xD534A80F251185E6ULL,
		0x3C02C9925EBCCAF3ULL,
		0x75DB16CE3D9668A3ULL,
		0x808B1161B3EE43E2ULL,
		0x0FBF4013BC39A6DAULL,
		0x76FC6528E257B677ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x36C4AF7061807690ULL,
		0x12DF54B4291886B6ULL,
		0x36549A962B82E642ULL,
		0xAA1D932C3FF6028BULL,
		0xEFAF3C3A4ED7A30BULL,
		0x8160D97C89563E5CULL,
		0xEED499DB3A4B0C06ULL,
		0x0FEC5C39F2F3B04FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D895EE0C300ED20ULL,
		0x25BEA96852310D6CULL,
		0x6CA9352C5705CC84ULL,
		0x543B26587FEC0516ULL,
		0xDF5E78749DAF4617ULL,
		0x02C1B2F912AC7CB9ULL,
		0xDDA933B67496180DULL,
		0x1FD8B873E5E7609FULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDAB32B125AC190CBULL,
		0xD2BCAE4A1DBCB03FULL,
		0x65A26EAD818E1E86ULL,
		0x5907E3FF0AEDC6EAULL,
		0x9394F988FD8A38A7ULL,
		0x3216E0EC48F8D28EULL,
		0x2699448794A61424ULL,
		0x12046793DCAA8EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5665624B5832196ULL,
		0xA5795C943B79607FULL,
		0xCB44DD5B031C3D0DULL,
		0xB20FC7FE15DB8DD4ULL,
		0x2729F311FB14714EULL,
		0x642DC1D891F1A51DULL,
		0x4D32890F294C2848ULL,
		0x2408CF27B9551D5CULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6D95A3F4E7D7FE07ULL,
		0x4C3AF3FE44D73B7EULL,
		0x58BF87F1E1163EF1ULL,
		0xE5CD1B143991C7AFULL,
		0xEE13F48F753A7225ULL,
		0xF9D04F7D98A2A4E3ULL,
		0xF29E115C54E077FBULL,
		0x1A70B9026CEDB3F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB2B47E9CFAFFC0EULL,
		0x9875E7FC89AE76FCULL,
		0xB17F0FE3C22C7DE2ULL,
		0xCB9A362873238F5EULL,
		0xDC27E91EEA74E44BULL,
		0xF3A09EFB314549C7ULL,
		0xE53C22B8A9C0EFF7ULL,
		0x34E17204D9DB67E1ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6DF570B10A14CF2FULL,
		0x8FA7A18D8E9DE6F3ULL,
		0xF1DD49EE57AA62B2ULL,
		0x25E1670318FA6EE7ULL,
		0xDC9543CB4744814DULL,
		0x0CD3CC95ECE76E77ULL,
		0x54C443CD309477D9ULL,
		0x04D0802DEAFEB9E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBEAE16214299E5EULL,
		0x1F4F431B1D3BCDE6ULL,
		0xE3BA93DCAF54C565ULL,
		0x4BC2CE0631F4DDCFULL,
		0xB92A87968E89029AULL,
		0x19A7992BD9CEDCEFULL,
		0xA988879A6128EFB2ULL,
		0x09A1005BD5FD73C0ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC84914A27B4C4284ULL,
		0xDBB4349F04E63035ULL,
		0x94296401D341FA3CULL,
		0x8E5330642DFE6842ULL,
		0xF2AAFD48DD76913BULL,
		0x4BA0BAC932D905B4ULL,
		0xF1C19D9048408678ULL,
		0x0AFBB1A3D8F352E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90922944F6988508ULL,
		0xB768693E09CC606BULL,
		0x2852C803A683F479ULL,
		0x1CA660C85BFCD085ULL,
		0xE555FA91BAED2277ULL,
		0x9741759265B20B69ULL,
		0xE3833B2090810CF0ULL,
		0x15F76347B1E6A5D3ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x69466128B4E496FBULL,
		0x736ACE11E8731F35ULL,
		0x41414042FDBF1D3BULL,
		0xCA2237CEC916BC85ULL,
		0x922742B21E88E1C9ULL,
		0xBE13C2A5A936B838ULL,
		0xAEDBE20FDDF08058ULL,
		0x029E8C280D9E7FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD28CC25169C92DF6ULL,
		0xE6D59C23D0E63E6AULL,
		0x82828085FB7E3A76ULL,
		0x94446F9D922D790AULL,
		0x244E85643D11C393ULL,
		0x7C27854B526D7071ULL,
		0x5DB7C41FBBE100B1ULL,
		0x053D18501B3CFFB7ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE015810B665B6D57ULL,
		0x9E2379D2EC7819EAULL,
		0xBE75CD1EBC7A6967ULL,
		0xA96F4D923411C9E6ULL,
		0xCE614B0E5E71ED58ULL,
		0x43005667436A2ECAULL,
		0x431849B16745BC5FULL,
		0x293C2B3C54EBE7CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC02B0216CCB6DAAEULL,
		0x3C46F3A5D8F033D5ULL,
		0x7CEB9A3D78F4D2CFULL,
		0x52DE9B24682393CDULL,
		0x9CC2961CBCE3DAB1ULL,
		0x8600ACCE86D45D95ULL,
		0x86309362CE8B78BEULL,
		0x52785678A9D7CF94ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCE3EFFCD2E069FB1ULL,
		0x11372ABD541E93FDULL,
		0xBE47D3E8D8BA7011ULL,
		0x0901FD38510B1386ULL,
		0x994A014A8EE6A231ULL,
		0x473AD22230FD7AE4ULL,
		0x96106B9F3F3594CCULL,
		0x37506D1EAC141DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C7DFF9A5C0D3F62ULL,
		0x226E557AA83D27FBULL,
		0x7C8FA7D1B174E022ULL,
		0x1203FA70A216270DULL,
		0x329402951DCD4462ULL,
		0x8E75A44461FAF5C9ULL,
		0x2C20D73E7E6B2998ULL,
		0x6EA0DA3D58283B89ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x22083CCBC1AA32F0ULL,
		0x9BC7DF6C631D6844ULL,
		0x833879CA687CC590ULL,
		0xEF1BDB26FE14ED4FULL,
		0xF71B1E0BAD7FA7D2ULL,
		0xFBFC151691D37DF9ULL,
		0x1F1CD39F8708F584ULL,
		0x11C86305C0E2D3A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44107997835465E0ULL,
		0x378FBED8C63AD088ULL,
		0x0670F394D0F98B21ULL,
		0xDE37B64DFC29DA9FULL,
		0xEE363C175AFF4FA5ULL,
		0xF7F82A2D23A6FBF3ULL,
		0x3E39A73F0E11EB09ULL,
		0x2390C60B81C5A74CULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF6E2D074A00B472ULL,
		0x539D5B01CF9FF79BULL,
		0x271BE0E5DF49BA48ULL,
		0x8F59DAFDDDCB1EB5ULL,
		0xE6903E8A55F020E6ULL,
		0x4CF55B7DDEDEA41AULL,
		0x92812BA93A9730A3ULL,
		0x2BBCA92F04FFF7C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEDC5A0E940168E4ULL,
		0xA73AB6039F3FEF37ULL,
		0x4E37C1CBBE937490ULL,
		0x1EB3B5FBBB963D6AULL,
		0xCD207D14ABE041CDULL,
		0x99EAB6FBBDBD4835ULL,
		0x25025752752E6146ULL,
		0x5779525E09FFEF8DULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7A2A539A3A0F65E8ULL,
		0x6C8706BF3EB6F741ULL,
		0x5A06F0FA8D0AE904ULL,
		0x77CEE1AD08B4A11AULL,
		0x6CA4492CA4658755ULL,
		0x86A43D0031A4F696ULL,
		0x1A12A18F3844790AULL,
		0x356849CDB2E5203EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF454A734741ECBD0ULL,
		0xD90E0D7E7D6DEE82ULL,
		0xB40DE1F51A15D208ULL,
		0xEF9DC35A11694234ULL,
		0xD948925948CB0EAAULL,
		0x0D487A006349ED2CULL,
		0x3425431E7088F215ULL,
		0x6AD0939B65CA407CULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD387E507797587ECULL,
		0x85EFE1445D89DB5EULL,
		0x7206D25207DC444DULL,
		0x48ADCDC93EA5CACDULL,
		0xEAFF8D2108CBA5F1ULL,
		0x5D88096792752ACFULL,
		0x72F6C9082F7098D4ULL,
		0x089642545B5867B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70FCA0EF2EB0FD8ULL,
		0x0BDFC288BB13B6BDULL,
		0xE40DA4A40FB8889BULL,
		0x915B9B927D4B959AULL,
		0xD5FF1A4211974BE2ULL,
		0xBB1012CF24EA559FULL,
		0xE5ED92105EE131A8ULL,
		0x112C84A8B6B0CF68ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5D0E7730CA7117E8ULL,
		0xB4B85309934D5F6CULL,
		0x91F56F2BE3869FA8ULL,
		0xC9DB00D9ED5578B0ULL,
		0x520F5B6032E2DFC9ULL,
		0xB47E61D1829E7280ULL,
		0x92C656D19FAD0C8AULL,
		0x183E6641AEB7A793ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1CEE6194E22FD0ULL,
		0x6970A613269ABED8ULL,
		0x23EADE57C70D3F51ULL,
		0x93B601B3DAAAF161ULL,
		0xA41EB6C065C5BF93ULL,
		0x68FCC3A3053CE500ULL,
		0x258CADA33F5A1915ULL,
		0x307CCC835D6F4F27ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6E200964A3FB2A6AULL,
		0x6413AFE2F5F096FBULL,
		0x1838068BDA8BDC02ULL,
		0x73A55BD37A10FAC2ULL,
		0x15ED3283B5D659C5ULL,
		0x5943FFE6B1E092A1ULL,
		0xEB06D77613254A90ULL,
		0x0CCFFC9098A147A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC4012C947F654D4ULL,
		0xC8275FC5EBE12DF6ULL,
		0x30700D17B517B804ULL,
		0xE74AB7A6F421F584ULL,
		0x2BDA65076BACB38AULL,
		0xB287FFCD63C12542ULL,
		0xD60DAEEC264A9520ULL,
		0x199FF92131428F41ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x67C3B90EBBE14367ULL,
		0x592AC8BE35083E9EULL,
		0xBA716563112C06B3ULL,
		0x00F798DBF1082F2CULL,
		0x31D9E60F039E48C6ULL,
		0x4A6A6F22B2B36027ULL,
		0xA1F7621C6E138BC6ULL,
		0x1D8272220B2583DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF87721D77C286CEULL,
		0xB255917C6A107D3CULL,
		0x74E2CAC622580D66ULL,
		0x01EF31B7E2105E59ULL,
		0x63B3CC1E073C918CULL,
		0x94D4DE456566C04EULL,
		0x43EEC438DC27178CULL,
		0x3B04E444164B07B9ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3503F5E195602607ULL,
		0x656CF7A3423577E1ULL,
		0x2F60C35D2B70EA81ULL,
		0xB0D52183E5A36564ULL,
		0xA1B09D78F0E5C725ULL,
		0xAB52895EF5560DE7ULL,
		0x32FBDE4D7CCD363EULL,
		0x29181FC7C5BEA01FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A07EBC32AC04C0EULL,
		0xCAD9EF46846AEFC2ULL,
		0x5EC186BA56E1D502ULL,
		0x61AA4307CB46CAC8ULL,
		0x43613AF1E1CB8E4BULL,
		0x56A512BDEAAC1BCFULL,
		0x65F7BC9AF99A6C7DULL,
		0x52303F8F8B7D403EULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x24F676186592464DULL,
		0x50302DDDD9188639ULL,
		0x2B11A66AC04943B8ULL,
		0xE2FBFC6176FF49ABULL,
		0xA5FD9EBFC64FD28EULL,
		0x30C326F7D09AC31AULL,
		0x42470515D8230954ULL,
		0x11388705376BE94FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49ECEC30CB248C9AULL,
		0xA0605BBBB2310C72ULL,
		0x56234CD580928770ULL,
		0xC5F7F8C2EDFE9356ULL,
		0x4BFB3D7F8C9FA51DULL,
		0x61864DEFA1358635ULL,
		0x848E0A2BB04612A8ULL,
		0x22710E0A6ED7D29EULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x991ACF3742F52C79ULL,
		0x665EF4B8EFF607FAULL,
		0x98AA0A66C6C468C7ULL,
		0x9B6CD47EADB9BA0CULL,
		0x46416E7B578CCFEEULL,
		0xD398A82405BB1F81ULL,
		0xB329E3CE1F429628ULL,
		0x0BDD38A292ECA20CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32359E6E85EA58F2ULL,
		0xCCBDE971DFEC0FF5ULL,
		0x315414CD8D88D18EULL,
		0x36D9A8FD5B737419ULL,
		0x8C82DCF6AF199FDDULL,
		0xA73150480B763F02ULL,
		0x6653C79C3E852C51ULL,
		0x17BA714525D94419ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8EFB8A000B77D0C8ULL,
		0xD3645FAC093E0E47ULL,
		0x57E3BA3B448383F0ULL,
		0x3BC6ADF0F86E1357ULL,
		0x658DBFF163CCB34FULL,
		0xF74383DA2968964AULL,
		0xF6EDF1D4A8986DC3ULL,
		0x2F8B27777BBDA3ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF7140016EFA190ULL,
		0xA6C8BF58127C1C8FULL,
		0xAFC77476890707E1ULL,
		0x778D5BE1F0DC26AEULL,
		0xCB1B7FE2C799669EULL,
		0xEE8707B452D12C94ULL,
		0xEDDBE3A95130DB87ULL,
		0x5F164EEEF77B47D9ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8C0DB95CBC41A970ULL,
		0x42FBB7CF06FFF700ULL,
		0x4923F60A3B636329ULL,
		0x8761DF71FE1A98FBULL,
		0xDD6EC9C75F0305C7ULL,
		0x4A88358EC21C1DEEULL,
		0x142FC4D6F7AB28ACULL,
		0x25BB496B257E5B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x181B72B9788352E0ULL,
		0x85F76F9E0DFFEE01ULL,
		0x9247EC1476C6C652ULL,
		0x0EC3BEE3FC3531F6ULL,
		0xBADD938EBE060B8FULL,
		0x95106B1D84383BDDULL,
		0x285F89ADEF565158ULL,
		0x4B7692D64AFCB73AULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5D17F8A07757F8CDULL,
		0xE03261D59CDA3618ULL,
		0xBA0067068100D472ULL,
		0x41E96AE8D2EDA874ULL,
		0xE6D1D2E92234D0E5ULL,
		0x8DAA2FAD3E324EF0ULL,
		0xAF3A9F186F1CCAD6ULL,
		0x0B3FA5423A106D52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA2FF140EEAFF19AULL,
		0xC064C3AB39B46C30ULL,
		0x7400CE0D0201A8E5ULL,
		0x83D2D5D1A5DB50E9ULL,
		0xCDA3A5D24469A1CAULL,
		0x1B545F5A7C649DE1ULL,
		0x5E753E30DE3995ADULL,
		0x167F4A847420DAA5ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6BE6DE02D574AAFCULL,
		0x88CF11D96D99114AULL,
		0xF02DAABF0249DC76ULL,
		0xB3C3EEEE35C50447ULL,
		0x7FB73EFDF245A92CULL,
		0xA3F3BA640ABC25AFULL,
		0xC73E1913D9B63CA7ULL,
		0x0821B54DD394F004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7CDBC05AAE955F8ULL,
		0x119E23B2DB322294ULL,
		0xE05B557E0493B8EDULL,
		0x6787DDDC6B8A088FULL,
		0xFF6E7DFBE48B5259ULL,
		0x47E774C815784B5EULL,
		0x8E7C3227B36C794FULL,
		0x10436A9BA729E009ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x63811B8BBF628EA3ULL,
		0x47BEFF67DF3C5C91ULL,
		0x9D7964E6918510A8ULL,
		0xE3C046FBF980DF30ULL,
		0x1D5C55C7A936633EULL,
		0xBA375E5B0DFA3FC7ULL,
		0x0E99BD6AF53C20FDULL,
		0x237A558B226BC7E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC70237177EC51D46ULL,
		0x8F7DFECFBE78B922ULL,
		0x3AF2C9CD230A2150ULL,
		0xC7808DF7F301BE61ULL,
		0x3AB8AB8F526CC67DULL,
		0x746EBCB61BF47F8EULL,
		0x1D337AD5EA7841FBULL,
		0x46F4AB1644D78FCCULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x55213624F943BAEFULL,
		0x2549FEE14B0DEE6BULL,
		0xFB531C4ABA0B65FDULL,
		0x5911415284105801ULL,
		0x6A7F8BB1845B87AFULL,
		0xDFB764F923CA2137ULL,
		0x674171367B3EF3FEULL,
		0x1F6B4BFAE3F61042ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA426C49F28775DEULL,
		0x4A93FDC2961BDCD6ULL,
		0xF6A638957416CBFAULL,
		0xB22282A50820B003ULL,
		0xD4FF176308B70F5EULL,
		0xBF6EC9F24794426EULL,
		0xCE82E26CF67DE7FDULL,
		0x3ED697F5C7EC2084ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8D1AC10F8F401526ULL,
		0x60D86A813650A58FULL,
		0xD1B142059AFBA44BULL,
		0x95ECA75EE85C6AC9ULL,
		0x2AF66B14E70CE382ULL,
		0xB319469B4EA37855ULL,
		0xE6CD2806998449F9ULL,
		0x1087AEC31AF62D04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A35821F1E802A4CULL,
		0xC1B0D5026CA14B1FULL,
		0xA362840B35F74896ULL,
		0x2BD94EBDD0B8D593ULL,
		0x55ECD629CE19C705ULL,
		0x66328D369D46F0AAULL,
		0xCD9A500D330893F3ULL,
		0x210F5D8635EC5A09ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA61360DA0B4321CDULL,
		0xC69D1C65C1AD3D46ULL,
		0xEDF5E404E124744BULL,
		0x42DB9D93614EEB2FULL,
		0xE9E43F78C202F3FDULL,
		0x541B14022D0A9898ULL,
		0x2FA68D930254AB35ULL,
		0x311AA818AC9128D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C26C1B41686439AULL,
		0x8D3A38CB835A7A8DULL,
		0xDBEBC809C248E897ULL,
		0x85B73B26C29DD65FULL,
		0xD3C87EF18405E7FAULL,
		0xA83628045A153131ULL,
		0x5F4D1B2604A9566AULL,
		0x62355031592251AEULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E292E95DFC9E7EFULL,
		0x842B1551A069A13AULL,
		0x67FCD71287A7A8F9ULL,
		0x0CD5B8A7BA642996ULL,
		0xCF37C236EFE00F57ULL,
		0x4283719F36A07BF4ULL,
		0x430C38C4234A9F25ULL,
		0x1D44512345727125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC525D2BBF93CFDEULL,
		0x08562AA340D34274ULL,
		0xCFF9AE250F4F51F3ULL,
		0x19AB714F74C8532CULL,
		0x9E6F846DDFC01EAEULL,
		0x8506E33E6D40F7E9ULL,
		0x8618718846953E4AULL,
		0x3A88A2468AE4E24AULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC8ADEB77EA022762ULL,
		0x44D81C6761AB4517ULL,
		0xED91383742736351ULL,
		0x7318BB5E0568FD41ULL,
		0xCFA3B129D60C51D6ULL,
		0x7932DA4D78CDC3F2ULL,
		0xE689CB24BF22C36FULL,
		0x0FCD60ECDABBFFC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x915BD6EFD4044EC4ULL,
		0x89B038CEC3568A2FULL,
		0xDB22706E84E6C6A2ULL,
		0xE63176BC0AD1FA83ULL,
		0x9F476253AC18A3ACULL,
		0xF265B49AF19B87E5ULL,
		0xCD1396497E4586DEULL,
		0x1F9AC1D9B577FF83ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB08278D9682B6DBEULL,
		0x791D2A824120136FULL,
		0x5A36AAC7FBFA1BE4ULL,
		0x54918F2EE9A9FB9CULL,
		0x2C29C15505CACA9AULL,
		0x6D6547CDBC1EE90CULL,
		0x8CAA36107C2C82B5ULL,
		0x0F3F3AC17BEFCC93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6104F1B2D056DB7CULL,
		0xF23A5504824026DFULL,
		0xB46D558FF7F437C8ULL,
		0xA9231E5DD353F738ULL,
		0x585382AA0B959534ULL,
		0xDACA8F9B783DD218ULL,
		0x19546C20F859056AULL,
		0x1E7E7582F7DF9927ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD9F2010162EB8DDEULL,
		0x449E6A4BF495370DULL,
		0x359F01AA467A61AAULL,
		0x444D700C1027AD05ULL,
		0xA691A1A7FE994DC8ULL,
		0x454F43240BC181CFULL,
		0xA37ABFBDB26B5133ULL,
		0x3CE7BDA913FA5638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3E40202C5D71BBCULL,
		0x893CD497E92A6E1BULL,
		0x6B3E03548CF4C354ULL,
		0x889AE018204F5A0AULL,
		0x4D23434FFD329B90ULL,
		0x8A9E86481783039FULL,
		0x46F57F7B64D6A266ULL,
		0x79CF7B5227F4AC71ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBCCD6272407D71A5ULL,
		0x46106736FB9B6037ULL,
		0x27DC21D4EF3FA18DULL,
		0x3AFB48010C09657EULL,
		0x7930C0FC0033EEB8ULL,
		0x677FF4849EFE35A3ULL,
		0x3D818C1AC5072B27ULL,
		0x3D86A86E364337CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x799AC4E480FAE34AULL,
		0x8C20CE6DF736C06FULL,
		0x4FB843A9DE7F431AULL,
		0x75F690021812CAFCULL,
		0xF26181F80067DD70ULL,
		0xCEFFE9093DFC6B46ULL,
		0x7B0318358A0E564EULL,
		0x7B0D50DC6C866F96ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0C86FB598370CBEAULL,
		0x5CD19027A57E9E03ULL,
		0x46D7F52D70C9EC52ULL,
		0xD7D4E3013D6B2444ULL,
		0xAE189B949759B285ULL,
		0xF2F29DD098E7E99CULL,
		0xBCAB83015AB256D0ULL,
		0x29F9CE2FB4DF2101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190DF6B306E197D4ULL,
		0xB9A3204F4AFD3C06ULL,
		0x8DAFEA5AE193D8A4ULL,
		0xAFA9C6027AD64888ULL,
		0x5C3137292EB3650BULL,
		0xE5E53BA131CFD339ULL,
		0x79570602B564ADA1ULL,
		0x53F39C5F69BE4203ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD74786E04E2A1399ULL,
		0x8D012DDD0A6713A9ULL,
		0x6E9A6ED3F6C615B0ULL,
		0x2C55CBF9B357BBA8ULL,
		0xBC8EA035151450FCULL,
		0x443B915455B2250AULL,
		0x8D06631865CE893DULL,
		0x2ADE34D434D1DD94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE8F0DC09C542732ULL,
		0x1A025BBA14CE2753ULL,
		0xDD34DDA7ED8C2B61ULL,
		0x58AB97F366AF7750ULL,
		0x791D406A2A28A1F8ULL,
		0x887722A8AB644A15ULL,
		0x1A0CC630CB9D127AULL,
		0x55BC69A869A3BB29ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6884D81A9535A3D7ULL,
		0xEC15F10B5CD91105ULL,
		0x914CFE5395839C18ULL,
		0x7A72A33EB68E8378ULL,
		0xBEF88C5E05B81B03ULL,
		0x30B27B274CDC08CEULL,
		0x102DC7D80DC3F9F3ULL,
		0x1315C8A646CBD22DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD109B0352A6B47AEULL,
		0xD82BE216B9B2220AULL,
		0x2299FCA72B073831ULL,
		0xF4E5467D6D1D06F1ULL,
		0x7DF118BC0B703606ULL,
		0x6164F64E99B8119DULL,
		0x205B8FB01B87F3E6ULL,
		0x262B914C8D97A45AULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20B1EDD64AA60E25ULL,
		0x241DCAD91844948FULL,
		0xD13136047E4F6740ULL,
		0xE5CE6024CA1ACB1BULL,
		0x60DC72E136FCBEBAULL,
		0x582F86E81E198BDAULL,
		0x113EF3352AD0981DULL,
		0x18C6200A1882220FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4163DBAC954C1C4AULL,
		0x483B95B23089291EULL,
		0xA2626C08FC9ECE80ULL,
		0xCB9CC04994359637ULL,
		0xC1B8E5C26DF97D75ULL,
		0xB05F0DD03C3317B4ULL,
		0x227DE66A55A1303AULL,
		0x318C40143104441EULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x921F7A24E91A904BULL,
		0xFAD51737993AD65DULL,
		0x684A2BDD3E8425DDULL,
		0x6C70370CEA8E2A87ULL,
		0x24767A1E73BC2F03ULL,
		0x654A617BEF93DD69ULL,
		0x6D8A3FCFB3B8A587ULL,
		0x198AFD5FE4A7CAA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x243EF449D2352096ULL,
		0xF5AA2E6F3275ACBBULL,
		0xD09457BA7D084BBBULL,
		0xD8E06E19D51C550EULL,
		0x48ECF43CE7785E06ULL,
		0xCA94C2F7DF27BAD2ULL,
		0xDB147F9F67714B0EULL,
		0x3315FABFC94F9550ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB4B6A2464055D686ULL,
		0x7B5D5AE9CA03FF17ULL,
		0xE868CA14510179F4ULL,
		0x47EFDF671FAB0BD3ULL,
		0x7640EB3111583336ULL,
		0xED3B5AF558DDC722ULL,
		0x5FE1E0DEACE2AF0EULL,
		0x032882213E21882CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x696D448C80ABAD0CULL,
		0xF6BAB5D39407FE2FULL,
		0xD0D19428A202F3E8ULL,
		0x8FDFBECE3F5617A7ULL,
		0xEC81D66222B0666CULL,
		0xDA76B5EAB1BB8E44ULL,
		0xBFC3C1BD59C55E1DULL,
		0x065104427C431058ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x243E9E9C5119BCB2ULL,
		0xAEE76AC73A312488ULL,
		0x15014C4997006D30ULL,
		0xB375E4E7555777E8ULL,
		0x67202F732F912612ULL,
		0x538F45FBAE1E2D23ULL,
		0xC7EEB6E93E1D1D10ULL,
		0x0DB3F7F9CAEDEF1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x487D3D38A2337964ULL,
		0x5DCED58E74624910ULL,
		0x2A0298932E00DA61ULL,
		0x66EBC9CEAAAEEFD0ULL,
		0xCE405EE65F224C25ULL,
		0xA71E8BF75C3C5A46ULL,
		0x8FDD6DD27C3A3A20ULL,
		0x1B67EFF395DBDE35ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x21AA7B2EA0571CB5ULL,
		0x2CB7AFFA5DCEAA5EULL,
		0x868B4227CF723BCCULL,
		0x4DE185F56C476D0BULL,
		0x2616B39D60DAD9B1ULL,
		0x72DD594AF5C47B44ULL,
		0xB20D0DCF87CCFD25ULL,
		0x1A189FBE2EC4703AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4354F65D40AE396AULL,
		0x596F5FF4BB9D54BCULL,
		0x0D16844F9EE47798ULL,
		0x9BC30BEAD88EDA17ULL,
		0x4C2D673AC1B5B362ULL,
		0xE5BAB295EB88F688ULL,
		0x641A1B9F0F99FA4AULL,
		0x34313F7C5D88E075ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD16C659A8638A452ULL,
		0x9148599E4EB930E5ULL,
		0xA2917EB28A41408FULL,
		0x0C9ABAFB9646490FULL,
		0xC8E03A4963861030ULL,
		0x5B9A71D1AF509363ULL,
		0x99B56F0E32789461ULL,
		0x0D9216737189C223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D8CB350C7148A4ULL,
		0x2290B33C9D7261CBULL,
		0x4522FD651482811FULL,
		0x193575F72C8C921FULL,
		0x91C07492C70C2060ULL,
		0xB734E3A35EA126C7ULL,
		0x336ADE1C64F128C2ULL,
		0x1B242CE6E3138447ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x01630C0374087827ULL,
		0xF7323EAA09A81268ULL,
		0xE8336544AA49712FULL,
		0x07CBDA40FCFA4973ULL,
		0xCC1478529315FDDEULL,
		0x71BD844F867CD479ULL,
		0x616E53C5E9790575ULL,
		0x2B5948F5103E665DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C61806E810F04EULL,
		0xEE647D54135024D0ULL,
		0xD066CA895492E25FULL,
		0x0F97B481F9F492E7ULL,
		0x9828F0A5262BFBBCULL,
		0xE37B089F0CF9A8F3ULL,
		0xC2DCA78BD2F20AEAULL,
		0x56B291EA207CCCBAULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4C5C03C297570093ULL,
		0xF1ABDA9B6B17DA3FULL,
		0xAFAE17FA20B0B956ULL,
		0x0C243FB1A76F8C79ULL,
		0x94F188826E729F8AULL,
		0x169B951B20F0F760ULL,
		0x09F91B1AFB9D2352ULL,
		0x3658B52AF5AA6FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B807852EAE0126ULL,
		0xE357B536D62FB47EULL,
		0x5F5C2FF4416172ADULL,
		0x18487F634EDF18F3ULL,
		0x29E31104DCE53F14ULL,
		0x2D372A3641E1EEC1ULL,
		0x13F23635F73A46A4ULL,
		0x6CB16A55EB54DFBEULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20C876F7DFCFD4DAULL,
		0xF46A2502B34F789EULL,
		0x9DE30473CCC74C0DULL,
		0x9C456F4511346E3CULL,
		0x8F94CC7DCA8AD856ULL,
		0xFEA7B4BF21623DC2ULL,
		0x3194FE01186EDA3AULL,
		0x1C5493D280DAB2D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4190EDEFBF9FA9B4ULL,
		0xE8D44A05669EF13CULL,
		0x3BC608E7998E981BULL,
		0x388ADE8A2268DC79ULL,
		0x1F2998FB9515B0ADULL,
		0xFD4F697E42C47B85ULL,
		0x6329FC0230DDB475ULL,
		0x38A927A501B565B2ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF98A60C562BAB2CCULL,
		0x2BDF94AC986ADF98ULL,
		0xCCE765CF1A3924FFULL,
		0x05B7EEA32D0385D4ULL,
		0xFE01528D9A95E750ULL,
		0xFD06CA52AEA736E6ULL,
		0x4F9AE2BAFC611FEBULL,
		0x0C37226D5A473F5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF314C18AC5756598ULL,
		0x57BF295930D5BF31ULL,
		0x99CECB9E347249FEULL,
		0x0B6FDD465A070BA9ULL,
		0xFC02A51B352BCEA0ULL,
		0xFA0D94A55D4E6DCDULL,
		0x9F35C575F8C23FD7ULL,
		0x186E44DAB48E7EBAULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x185BAE04CAC83164ULL,
		0x7B27FB596D6C7DF6ULL,
		0xC782185122AE3C2AULL,
		0x4B84161F4FC83663ULL,
		0xEDB8FC21489C7090ULL,
		0xA87D03709A58FEF9ULL,
		0x559E14251CC3711CULL,
		0x2703508341583C5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B75C09959062C8ULL,
		0xF64FF6B2DAD8FBECULL,
		0x8F0430A2455C7854ULL,
		0x97082C3E9F906CC7ULL,
		0xDB71F8429138E120ULL,
		0x50FA06E134B1FDF3ULL,
		0xAB3C284A3986E239ULL,
		0x4E06A10682B078B4ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC64227B11C7FCC2BULL,
		0x96C1D1FA9B42D40AULL,
		0xCFA18B0C7473C1ACULL,
		0xB26DC5D0844990ECULL,
		0xC75001C2861F899DULL,
		0x0CA2273C3025F06EULL,
		0x62161258F6DBDCDFULL,
		0x33874D788D93B1EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C844F6238FF9856ULL,
		0x2D83A3F53685A815ULL,
		0x9F431618E8E78359ULL,
		0x64DB8BA1089321D9ULL,
		0x8EA003850C3F133BULL,
		0x19444E78604BE0DDULL,
		0xC42C24B1EDB7B9BEULL,
		0x670E9AF11B2763DCULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E93B926BBD92135ULL,
		0x0B25D94CFBC284CEULL,
		0x66C42F2AF5559951ULL,
		0x952D2D8EC1284822ULL,
		0x87C2CC69A524DEF9ULL,
		0xECB4C3545CDE1A64ULL,
		0xD0900F62E1C8B4A9ULL,
		0x0A9E1A95E32CE44CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD27724D77B2426AULL,
		0x164BB299F785099CULL,
		0xCD885E55EAAB32A2ULL,
		0x2A5A5B1D82509044ULL,
		0x0F8598D34A49BDF3ULL,
		0xD96986A8B9BC34C9ULL,
		0xA1201EC5C3916953ULL,
		0x153C352BC659C899ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCC275B28638DA797ULL,
		0xD4509D895B0C56C1ULL,
		0x530C9E5CA2945255ULL,
		0x44B76F536187CF56ULL,
		0xC8DC716A1D601DFEULL,
		0xDE4D565DA2A6D8BFULL,
		0x13680B6CEB42E71CULL,
		0x2082182C11FA3D13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984EB650C71B4F2EULL,
		0xA8A13B12B618AD83ULL,
		0xA6193CB94528A4ABULL,
		0x896EDEA6C30F9EACULL,
		0x91B8E2D43AC03BFCULL,
		0xBC9AACBB454DB17FULL,
		0x26D016D9D685CE39ULL,
		0x4104305823F47A26ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7FB1234D0ABA2C5AULL,
		0xFFCB547ACDF2DC80ULL,
		0x154A52EF0ED67A1EULL,
		0xBDCB29EC734C9E11ULL,
		0xF96B121805384911ULL,
		0xDBE3CE378FAECE9CULL,
		0xF66D83B20D868E73ULL,
		0x008757D6BEB4B84FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF62469A157458B4ULL,
		0xFF96A8F59BE5B900ULL,
		0x2A94A5DE1DACF43DULL,
		0x7B9653D8E6993C22ULL,
		0xF2D624300A709223ULL,
		0xB7C79C6F1F5D9D39ULL,
		0xECDB07641B0D1CE7ULL,
		0x010EAFAD7D69709FULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC65A50CF232A4871ULL,
		0x4AFB1959A0A45B88ULL,
		0xCE8A2AA3916FE04CULL,
		0x3995E23FC6C5739CULL,
		0x8F9C8635338EE027ULL,
		0x87D24D55C497CE68ULL,
		0x328A6DAC3A189B89ULL,
		0x2B4308AC38581F99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB4A19E465490E2ULL,
		0x95F632B34148B711ULL,
		0x9D14554722DFC098ULL,
		0x732BC47F8D8AE739ULL,
		0x1F390C6A671DC04EULL,
		0x0FA49AAB892F9CD1ULL,
		0x6514DB5874313713ULL,
		0x5686115870B03F32ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x22C3C56653177452ULL,
		0x35DF85B9623939A4ULL,
		0x2A607CBDBDFC06F4ULL,
		0xCD330890B149FF1DULL,
		0x0CD79CA5F7CA73B3ULL,
		0x0F5FE87A2838EAD0ULL,
		0x29B66E00863925FCULL,
		0x21D22FC5D22EA4D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45878ACCA62EE8A4ULL,
		0x6BBF0B72C4727348ULL,
		0x54C0F97B7BF80DE8ULL,
		0x9A6611216293FE3AULL,
		0x19AF394BEF94E767ULL,
		0x1EBFD0F45071D5A0ULL,
		0x536CDC010C724BF8ULL,
		0x43A45F8BA45D49A4ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4EF064075C35399BULL,
		0x7AFD40E649B50F10ULL,
		0x4D3D14B0C29B571EULL,
		0xA0D5753D7F7C1B7FULL,
		0x7946A9762A6B69EBULL,
		0x8055E013C8363899ULL,
		0x463D09FD9144E693ULL,
		0x2AD76702EE48335FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DE0C80EB86A7336ULL,
		0xF5FA81CC936A1E20ULL,
		0x9A7A29618536AE3CULL,
		0x41AAEA7AFEF836FEULL,
		0xF28D52EC54D6D3D7ULL,
		0x00ABC027906C7132ULL,
		0x8C7A13FB2289CD27ULL,
		0x55AECE05DC9066BEULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x595EDFF5135866FBULL,
		0xC098D9D62E88EE4CULL,
		0xB0BFF2A1BB9F5CA1ULL,
		0x8A353CC521314386ULL,
		0xB4B9101828418E69ULL,
		0x36465F7AA610F31BULL,
		0x6E2B583285D5753FULL,
		0x0912C9B2D84658A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2BDBFEA26B0CDF6ULL,
		0x8131B3AC5D11DC98ULL,
		0x617FE543773EB943ULL,
		0x146A798A4262870DULL,
		0x6972203050831CD3ULL,
		0x6C8CBEF54C21E637ULL,
		0xDC56B0650BAAEA7EULL,
		0x12259365B08CB146ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7DE2DD544431DDBFULL,
		0x6E0D766A8D7815C4ULL,
		0xD97C4523B02385F6ULL,
		0xDB04588E277F54A9ULL,
		0xF17A230C06CC4B90ULL,
		0x5A67C6E92B9634ADULL,
		0x7760D5ECEC067B49ULL,
		0x31E5775DAF291370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC5BAA88863BB7EULL,
		0xDC1AECD51AF02B88ULL,
		0xB2F88A4760470BECULL,
		0xB608B11C4EFEA953ULL,
		0xE2F446180D989721ULL,
		0xB4CF8DD2572C695BULL,
		0xEEC1ABD9D80CF692ULL,
		0x63CAEEBB5E5226E0ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE68A0D55B4314536ULL,
		0x629D38EC296FC033ULL,
		0x13756E9007C068A9ULL,
		0x3F0CECF035B8301AULL,
		0x09AD40FFD4CE75F1ULL,
		0xA8FFD3AB7FB2F51BULL,
		0x4907F31F7322776FULL,
		0x2BCC94CC21CC9A90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD141AAB68628A6CULL,
		0xC53A71D852DF8067ULL,
		0x26EADD200F80D152ULL,
		0x7E19D9E06B706034ULL,
		0x135A81FFA99CEBE2ULL,
		0x51FFA756FF65EA36ULL,
		0x920FE63EE644EEDFULL,
		0x5799299843993520ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0758D3326109D047ULL,
		0xCC13C7170ECC96DCULL,
		0xAD6A91E3C78FDEE1ULL,
		0xEF321E78239CCCF0ULL,
		0x329F9F9B184091E1ULL,
		0x58738DED55AEAD70ULL,
		0xD947EB4E966363E4ULL,
		0x3992D7838269FFB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB1A664C213A08EULL,
		0x98278E2E1D992DB8ULL,
		0x5AD523C78F1FBDC3ULL,
		0xDE643CF0473999E1ULL,
		0x653F3F36308123C3ULL,
		0xB0E71BDAAB5D5AE0ULL,
		0xB28FD69D2CC6C7C8ULL,
		0x7325AF0704D3FF63ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6215A0BAB6D23C28ULL,
		0xD2FAA6AC393126A0ULL,
		0x8BF3E6805489B988ULL,
		0xF22A0FF05C5AAA55ULL,
		0x3795246A8EB1E792ULL,
		0xEABFE4A7E8D30C81ULL,
		0x11C6AA399FACBBB8ULL,
		0x361E099D71ED434FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC42B41756DA47850ULL,
		0xA5F54D5872624D40ULL,
		0x17E7CD00A9137311ULL,
		0xE4541FE0B8B554ABULL,
		0x6F2A48D51D63CF25ULL,
		0xD57FC94FD1A61902ULL,
		0x238D54733F597771ULL,
		0x6C3C133AE3DA869EULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x79505FF662A986D8ULL,
		0x62F09AFF8278EE31ULL,
		0x13DEBAD377B9C468ULL,
		0xBA57E1734F84BC7AULL,
		0xEA91FE3899EA520CULL,
		0xE2E883FDA4FC1974ULL,
		0xBF0B8CCCB6834A13ULL,
		0x20BD838DE5358074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2A0BFECC5530DB0ULL,
		0xC5E135FF04F1DC62ULL,
		0x27BD75A6EF7388D0ULL,
		0x74AFC2E69F0978F4ULL,
		0xD523FC7133D4A419ULL,
		0xC5D107FB49F832E9ULL,
		0x7E1719996D069427ULL,
		0x417B071BCA6B00E9ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB7234C6C6E3380BULL,
		0x62C7F1DFE31512BCULL,
		0xCF43AECA2C3241BFULL,
		0x35614453248D1BA7ULL,
		0x0BDC4992CC2D95BDULL,
		0x1F80BE7487C17F98ULL,
		0x5107D5CFCF3A412FULL,
		0x1CD0C24E4C996A0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E4698D8DC67016ULL,
		0xC58FE3BFC62A2579ULL,
		0x9E875D945864837EULL,
		0x6AC288A6491A374FULL,
		0x17B89325985B2B7AULL,
		0x3F017CE90F82FF30ULL,
		0xA20FAB9F9E74825EULL,
		0x39A1849C9932D414ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC66389CA2319727FULL,
		0x82839D0DBE3DE765ULL,
		0x7F7F32A2FA216DEAULL,
		0x42C46D7C53CCAC39ULL,
		0x26C5C5F16071F55FULL,
		0xF82A4F91D1CC1FD2ULL,
		0xF1D75130788F9497ULL,
		0x0E18FA3874B58EABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC713944632E4FEULL,
		0x05073A1B7C7BCECBULL,
		0xFEFE6545F442DBD5ULL,
		0x8588DAF8A7995872ULL,
		0x4D8B8BE2C0E3EABEULL,
		0xF0549F23A3983FA4ULL,
		0xE3AEA260F11F292FULL,
		0x1C31F470E96B1D57ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81CBEBA771AEBD42ULL,
		0x9B692B222C82EC31ULL,
		0x116F777EED07AED0ULL,
		0xD0EDC2E86BAEF0A8ULL,
		0xAF7E00377293FEB7ULL,
		0x5405D7548540C4D9ULL,
		0x7A0469E235E2C18FULL,
		0x33E364D1B2D72A0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0397D74EE35D7A84ULL,
		0x36D256445905D863ULL,
		0x22DEEEFDDA0F5DA1ULL,
		0xA1DB85D0D75DE150ULL,
		0x5EFC006EE527FD6FULL,
		0xA80BAEA90A8189B3ULL,
		0xF408D3C46BC5831EULL,
		0x67C6C9A365AE541EULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4772783DB0973B5FULL,
		0xF9670B0986251607ULL,
		0x55F071D6F1B79990ULL,
		0x4AC9303B15656748ULL,
		0x6BD4DFDE0A8E8574ULL,
		0x93885C1D66D63F69ULL,
		0x992C6CE31B83ABDBULL,
		0x3A2E7F4D44734AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EE4F07B612E76BEULL,
		0xF2CE16130C4A2C0EULL,
		0xABE0E3ADE36F3321ULL,
		0x959260762ACACE90ULL,
		0xD7A9BFBC151D0AE8ULL,
		0x2710B83ACDAC7ED2ULL,
		0x3258D9C6370757B7ULL,
		0x745CFE9A88E69561ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7B76F1E49AF9E1BEULL,
		0xA978DCD5966F07F8ULL,
		0x74F1AF02CDEDBB15ULL,
		0xBDE05C86A316AD46ULL,
		0x8102E7202C0B08E1ULL,
		0x86097305278DE3F7ULL,
		0x77B2E904673F6D37ULL,
		0x2316E23FBC1D4FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6EDE3C935F3C37CULL,
		0x52F1B9AB2CDE0FF0ULL,
		0xE9E35E059BDB762BULL,
		0x7BC0B90D462D5A8CULL,
		0x0205CE40581611C3ULL,
		0x0C12E60A4F1BC7EFULL,
		0xEF65D208CE7EDA6FULL,
		0x462DC47F783A9F90ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC175023B9DDF0D73ULL,
		0x1A4D4F5B509BAA28ULL,
		0x0EEF6DF581151721ULL,
		0x3EC396C7D53C56FAULL,
		0xBFB450375BDEA22BULL,
		0xD4628A10741E7133ULL,
		0xA04A8EC36748ACD3ULL,
		0x300B14729D077EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EA04773BBE1AE6ULL,
		0x349A9EB6A1375451ULL,
		0x1DDEDBEB022A2E42ULL,
		0x7D872D8FAA78ADF4ULL,
		0x7F68A06EB7BD4456ULL,
		0xA8C51420E83CE267ULL,
		0x40951D86CE9159A7ULL,
		0x601628E53A0EFD4BULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D9DE13E61CB5D1AULL,
		0x0D40900FFC38D09EULL,
		0x88B4F2F005888A01ULL,
		0x9BC7C6CD9B9ED4B2ULL,
		0xE68702CAAF823F05ULL,
		0xE66D9F43C5BFCB31ULL,
		0x02143D62D7E0F5D5ULL,
		0x3ABE3CE0D4D6EA64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3BC27CC396BA34ULL,
		0x1A81201FF871A13CULL,
		0x1169E5E00B111402ULL,
		0x378F8D9B373DA965ULL,
		0xCD0E05955F047E0BULL,
		0xCCDB3E878B7F9663ULL,
		0x04287AC5AFC1EBABULL,
		0x757C79C1A9ADD4C8ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB738310783686CB1ULL,
		0x87DF5AA03C1EEA66ULL,
		0xA4D6560FE4153088ULL,
		0x829D81C1AE5619CCULL,
		0xF53117C24872B1DEULL,
		0xAD948B6686C674AFULL,
		0x6F031D28529B9642ULL,
		0x066DECB72E38E2E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E70620F06D0D962ULL,
		0x0FBEB540783DD4CDULL,
		0x49ACAC1FC82A6111ULL,
		0x053B03835CAC3399ULL,
		0xEA622F8490E563BDULL,
		0x5B2916CD0D8CE95FULL,
		0xDE063A50A5372C85ULL,
		0x0CDBD96E5C71C5C8ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6612C2B763C36C65ULL,
		0x3F4F5011CEB022D0ULL,
		0x5CCD7D59FB55D757ULL,
		0xFF039FA57A9715D0ULL,
		0xA545DC3BCBE63D57ULL,
		0xC69C1F041C938E65ULL,
		0x77AE5A0331233CF4ULL,
		0x39FC9B89E0A3913CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC25856EC786D8CAULL,
		0x7E9EA0239D6045A0ULL,
		0xB99AFAB3F6ABAEAEULL,
		0xFE073F4AF52E2BA0ULL,
		0x4A8BB87797CC7AAFULL,
		0x8D383E0839271CCBULL,
		0xEF5CB406624679E9ULL,
		0x73F93713C1472278ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA418FAAE79DE6BF3ULL,
		0x7E97505209ECA680ULL,
		0xED7645F56D8442A1ULL,
		0xF4DB5C75F8B04B09ULL,
		0x9507EEBB570FB650ULL,
		0x4D8D7A1F0306308DULL,
		0xA64633A496E37CF7ULL,
		0x16534438CA75BC30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4831F55CF3BCD7E6ULL,
		0xFD2EA0A413D94D01ULL,
		0xDAEC8BEADB088542ULL,
		0xE9B6B8EBF1609613ULL,
		0x2A0FDD76AE1F6CA1ULL,
		0x9B1AF43E060C611BULL,
		0x4C8C67492DC6F9EEULL,
		0x2CA6887194EB7861ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6CF67BDAAC0485CBULL,
		0xA10EA02A6CD6465AULL,
		0xB248A635D97140C4ULL,
		0x6FD5D21BECFECE3BULL,
		0x452D8060C14FBEDFULL,
		0x7341AA86546662D1ULL,
		0xEEAEC9BFE2E8495FULL,
		0x0A5E2F698B928E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9ECF7B558090B96ULL,
		0x421D4054D9AC8CB4ULL,
		0x64914C6BB2E28189ULL,
		0xDFABA437D9FD9C77ULL,
		0x8A5B00C1829F7DBEULL,
		0xE683550CA8CCC5A2ULL,
		0xDD5D937FC5D092BEULL,
		0x14BC5ED317251C21ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2D28F7C807FCE308ULL,
		0xA0E3E8D53CC1B55FULL,
		0x1FD53CA4367B36E2ULL,
		0x0A1937DE3C0480C4ULL,
		0x40F10D6C16F4FC5CULL,
		0xCC9FE52CC7FC436FULL,
		0xA0C6EC8E45331F4DULL,
		0x3FAB1073D90E3B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A51EF900FF9C610ULL,
		0x41C7D1AA79836ABEULL,
		0x3FAA79486CF66DC5ULL,
		0x14326FBC78090188ULL,
		0x81E21AD82DE9F8B8ULL,
		0x993FCA598FF886DEULL,
		0x418DD91C8A663E9BULL,
		0x7F5620E7B21C76C9ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9CEC23F7B22544E3ULL,
		0x321128617E5FDF40ULL,
		0x5B43EE33DFFA598DULL,
		0x25511A97221DCCEFULL,
		0xE6BA2A7F129B9C53ULL,
		0x7A75E79DC26DDF1EULL,
		0x6073A5326132CF16ULL,
		0x01BE9B1BF812EC66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D847EF644A89C6ULL,
		0x642250C2FCBFBE81ULL,
		0xB687DC67BFF4B31AULL,
		0x4AA2352E443B99DEULL,
		0xCD7454FE253738A6ULL,
		0xF4EBCF3B84DBBE3DULL,
		0xC0E74A64C2659E2CULL,
		0x037D3637F025D8CCULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB9C5609405D91AE6ULL,
		0xFBCF418876405ABCULL,
		0xE56641088407F210ULL,
		0xDF0F88D9AADB7183ULL,
		0x659CB74F17E16C9EULL,
		0x4973EAC415A61E22ULL,
		0xAA94DABEC80137B9ULL,
		0x3534980071C86FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738AC1280BB235CCULL,
		0xF79E8310EC80B579ULL,
		0xCACC8211080FE421ULL,
		0xBE1F11B355B6E307ULL,
		0xCB396E9E2FC2D93DULL,
		0x92E7D5882B4C3C44ULL,
		0x5529B57D90026F72ULL,
		0x6A693000E390DF75ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x590500A165B222F6ULL,
		0xD41B69409B183982ULL,
		0xD70B895FF7EE5AE1ULL,
		0xE0FD46FA4CB3195AULL,
		0x2BCD49CB302FB8E1ULL,
		0x11165F72AC6FEC1CULL,
		0xABE605D76A9EE4EBULL,
		0x2F749CB4A9DD9FADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB20A0142CB6445ECULL,
		0xA836D28136307304ULL,
		0xAE1712BFEFDCB5C3ULL,
		0xC1FA8DF4996632B5ULL,
		0x579A9396605F71C3ULL,
		0x222CBEE558DFD838ULL,
		0x57CC0BAED53DC9D6ULL,
		0x5EE9396953BB3F5BULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x84E634DA5E8C8D19ULL,
		0x0AC8D0A27397482AULL,
		0xCB3016E1A7FB0088ULL,
		0xD8665DB9203C3980ULL,
		0x6A70A43121E9F0A5ULL,
		0x0A867BBFB1138138ULL,
		0xE8CBFF0D5AA6FDD4ULL,
		0x10AC7B97D7F53191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09CC69B4BD191A32ULL,
		0x1591A144E72E9055ULL,
		0x96602DC34FF60110ULL,
		0xB0CCBB7240787301ULL,
		0xD4E1486243D3E14BULL,
		0x150CF77F62270270ULL,
		0xD197FE1AB54DFBA8ULL,
		0x2158F72FAFEA6323ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x185B1C1084B53EB0ULL,
		0x9574590357ECD20AULL,
		0x9A4CC0906A904D1FULL,
		0x187F263172570365ULL,
		0x15FE1D3AEC941141ULL,
		0xC77DEF389255135BULL,
		0x18835A29001A30F8ULL,
		0x1F00F84DDA10CAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B63821096A7D60ULL,
		0x2AE8B206AFD9A414ULL,
		0x34998120D5209A3FULL,
		0x30FE4C62E4AE06CBULL,
		0x2BFC3A75D9282282ULL,
		0x8EFBDE7124AA26B6ULL,
		0x3106B452003461F1ULL,
		0x3E01F09BB4219544ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4E9E635F4BA55AFFULL,
		0xB538E1EECEE9E9CAULL,
		0x4B6E8F0940A0D507ULL,
		0xF58C0E6735802F37ULL,
		0x9E26C8528857E0E6ULL,
		0x728501A493A8FA7EULL,
		0x7548441512C2A6C1ULL,
		0x29041B51E32A2C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D3CC6BE974AB5FEULL,
		0x6A71C3DD9DD3D394ULL,
		0x96DD1E128141AA0FULL,
		0xEB181CCE6B005E6EULL,
		0x3C4D90A510AFC1CDULL,
		0xE50A03492751F4FDULL,
		0xEA90882A25854D82ULL,
		0x520836A3C65458C4ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEAFF2058FCFF7A9EULL,
		0x1C5FD86FA980C50CULL,
		0x1AE64D8D01F42B80ULL,
		0x6F5A78C335B4137BULL,
		0x5F3F6D571C05A2A2ULL,
		0x20608770E2BBA7DCULL,
		0x74E951BEA98E3F43ULL,
		0x0FA93240A84C51F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5FE40B1F9FEF53CULL,
		0x38BFB0DF53018A19ULL,
		0x35CC9B1A03E85700ULL,
		0xDEB4F1866B6826F6ULL,
		0xBE7EDAAE380B4544ULL,
		0x40C10EE1C5774FB8ULL,
		0xE9D2A37D531C7E86ULL,
		0x1F5264815098A3EEULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD7DEB7A713F698B7ULL,
		0xE9E0107409CD6E31ULL,
		0x90F3F0F66889D8C6ULL,
		0x7D3EDC61C52367CFULL,
		0xEADB5759EADDD8BCULL,
		0x38E03446070FB243ULL,
		0x9806373084BB9F52ULL,
		0x19F79394B6FB98C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFBD6F4E27ED316EULL,
		0xD3C020E8139ADC63ULL,
		0x21E7E1ECD113B18DULL,
		0xFA7DB8C38A46CF9FULL,
		0xD5B6AEB3D5BBB178ULL,
		0x71C0688C0E1F6487ULL,
		0x300C6E6109773EA4ULL,
		0x33EF27296DF7318DULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA794442D4F5B18EEULL,
		0x6BAECB4C023CFBE1ULL,
		0x166B2C8CBC807FF2ULL,
		0xD07A7A1C831D6F7FULL,
		0xC37993104B4D2F3FULL,
		0xBEF16AE6325867B8ULL,
		0x64593C28D41FD21DULL,
		0x1BDE955A364CB425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F28885A9EB631DCULL,
		0xD75D96980479F7C3ULL,
		0x2CD659197900FFE4ULL,
		0xA0F4F439063ADEFEULL,
		0x86F32620969A5E7FULL,
		0x7DE2D5CC64B0CF71ULL,
		0xC8B27851A83FA43BULL,
		0x37BD2AB46C99684AULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9042F3C0E6E463FAULL,
		0xA67385693FA09EE7ULL,
		0x83EACFFD072437EDULL,
		0x18F187FC0F6B2C9DULL,
		0x5E2926A0789B3177ULL,
		0x7C039EDE02F6B082ULL,
		0x1F0577760AF6BD35ULL,
		0x3499A80584C2F1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2085E781CDC8C7F4ULL,
		0x4CE70AD27F413DCFULL,
		0x07D59FFA0E486FDBULL,
		0x31E30FF81ED6593BULL,
		0xBC524D40F13662EEULL,
		0xF8073DBC05ED6104ULL,
		0x3E0AEEEC15ED7A6AULL,
		0x6933500B0985E37AULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9E0DAA67C9FD1ACULL,
		0x10FF749727FE5274ULL,
		0x74D7B618FF53DEAFULL,
		0x201E7347A6634406ULL,
		0x0ED8226DC0753461ULL,
		0xB890375925C36C0BULL,
		0x62F3B5E75AB23674ULL,
		0x1D992D3C3AE96DE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C1B54CF93FA358ULL,
		0x21FEE92E4FFCA4E9ULL,
		0xE9AF6C31FEA7BD5EULL,
		0x403CE68F4CC6880CULL,
		0x1DB044DB80EA68C2ULL,
		0x71206EB24B86D816ULL,
		0xC5E76BCEB5646CE9ULL,
		0x3B325A7875D2DBC0ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB58D1F1132F96574ULL,
		0xB42AAA100B495D07ULL,
		0x5170B9DF13312621ULL,
		0x8B46336BBEAAD177ULL,
		0x85F52A15C5BA5C0AULL,
		0xE30D0849D3F000FDULL,
		0xB635983F58F4BDF5ULL,
		0x1730F5A1AA26FA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1A3E2265F2CAE8ULL,
		0x685554201692BA0FULL,
		0xA2E173BE26624C43ULL,
		0x168C66D77D55A2EEULL,
		0x0BEA542B8B74B815ULL,
		0xC61A1093A7E001FBULL,
		0x6C6B307EB1E97BEBULL,
		0x2E61EB43544DF465ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC51576E0E7EFD014ULL,
		0x9993F09F69C33267ULL,
		0xE9C085559168D246ULL,
		0xF92EF569021E0E89ULL,
		0xD4763F7E35435031ULL,
		0x018CD71F92252667ULL,
		0x26694EFDD55589D0ULL,
		0x3AFC4FDC72B07D33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A2AEDC1CFDFA028ULL,
		0x3327E13ED38664CFULL,
		0xD3810AAB22D1A48DULL,
		0xF25DEAD2043C1D13ULL,
		0xA8EC7EFC6A86A063ULL,
		0x0319AE3F244A4CCFULL,
		0x4CD29DFBAAAB13A0ULL,
		0x75F89FB8E560FA66ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5B82554B7F653D44ULL,
		0xCF03CB3741F0E407ULL,
		0x8D9E1AC98DD05227ULL,
		0x9D4820B5A3CB02A9ULL,
		0xC1DC3F0CECFFC740ULL,
		0x6F93855A11E3091EULL,
		0xFD5B5AC0C1FE7D0EULL,
		0x1A6CEF3D424FC096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB704AA96FECA7A88ULL,
		0x9E07966E83E1C80EULL,
		0x1B3C35931BA0A44FULL,
		0x3A90416B47960553ULL,
		0x83B87E19D9FF8E81ULL,
		0xDF270AB423C6123DULL,
		0xFAB6B58183FCFA1CULL,
		0x34D9DE7A849F812DULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x816B6090137FE330ULL,
		0x210D773848235383ULL,
		0x9D2E42E3EE27DA37ULL,
		0x6F84705672D2697DULL,
		0x2A6C0900DE3107ADULL,
		0x48560214A98D2EAAULL,
		0xA9E3F971F281EA16ULL,
		0x05EF0165D472562EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02D6C12026FFC660ULL,
		0x421AEE709046A707ULL,
		0x3A5C85C7DC4FB46EULL,
		0xDF08E0ACE5A4D2FBULL,
		0x54D81201BC620F5AULL,
		0x90AC0429531A5D54ULL,
		0x53C7F2E3E503D42CULL,
		0x0BDE02CBA8E4AC5DULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1B1C843A7D7D84F9ULL,
		0x98CD3BE8DBE422E1ULL,
		0xFA5188C578549A34ULL,
		0xC3062141D5ED0A6BULL,
		0x02F5FCA81C194DDBULL,
		0xEB4B0119BE7BD0F8ULL,
		0x1AF4A73C14003242ULL,
		0x38DFDAA58B2FDAB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36390874FAFB09F2ULL,
		0x319A77D1B7C845C2ULL,
		0xF4A3118AF0A93469ULL,
		0x860C4283ABDA14D7ULL,
		0x05EBF95038329BB7ULL,
		0xD69602337CF7A1F0ULL,
		0x35E94E7828006485ULL,
		0x71BFB54B165FB56CULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8F1E708E560579CAULL,
		0xF2D6065730FD0806ULL,
		0xE2A974FC9B5BA5F0ULL,
		0x86B2B72C9B000D70ULL,
		0x841D56FA1B60EEABULL,
		0x85925F21FDB280CEULL,
		0x2C9E7C9F7F91E3CEULL,
		0x0E1F368A38C18C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3CE11CAC0AF394ULL,
		0xE5AC0CAE61FA100DULL,
		0xC552E9F936B74BE1ULL,
		0x0D656E5936001AE1ULL,
		0x083AADF436C1DD57ULL,
		0x0B24BE43FB65019DULL,
		0x593CF93EFF23C79DULL,
		0x1C3E6D147183192EULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC1345A20738B7095ULL,
		0x241DE7A8460A4CA8ULL,
		0xC16115768169866EULL,
		0x3D2037D1D5D841A9ULL,
		0x11043EB5A44F8B9FULL,
		0xBF53004B23448ED6ULL,
		0x29864125F4E3A188ULL,
		0x0233F174E4A79AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8268B440E716E12AULL,
		0x483BCF508C149951ULL,
		0x82C22AED02D30CDCULL,
		0x7A406FA3ABB08353ULL,
		0x22087D6B489F173EULL,
		0x7EA6009646891DACULL,
		0x530C824BE9C74311ULL,
		0x0467E2E9C94F35B2ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEA9F4F5BEA6ABB49ULL,
		0x49EFCA2D8A2F004AULL,
		0x328F43045A846067ULL,
		0x75D40DACA45762AFULL,
		0xA7BFB8F9164110B3ULL,
		0xEE7EEFF5C42C2F35ULL,
		0xD5879EE1F36A5598ULL,
		0x389B2F7B55424646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53E9EB7D4D57692ULL,
		0x93DF945B145E0095ULL,
		0x651E8608B508C0CEULL,
		0xEBA81B5948AEC55EULL,
		0x4F7F71F22C822166ULL,
		0xDCFDDFEB88585E6BULL,
		0xAB0F3DC3E6D4AB31ULL,
		0x71365EF6AA848C8DULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x464435A288BA3805ULL,
		0x7E31039F97A0FB71ULL,
		0x3B244CDED7A75743ULL,
		0x0E500492A7160D8BULL,
		0x1E46B560D70CD690ULL,
		0x81077C0B4FB89C7CULL,
		0x0A947514E6EB085EULL,
		0x18ABC204F8227D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C886B451174700AULL,
		0xFC62073F2F41F6E2ULL,
		0x764899BDAF4EAE86ULL,
		0x1CA009254E2C1B16ULL,
		0x3C8D6AC1AE19AD20ULL,
		0x020EF8169F7138F8ULL,
		0x1528EA29CDD610BDULL,
		0x31578409F044FA5EULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE8E7DD6FD3DBCFE5ULL,
		0xCC897C1668F71059ULL,
		0x9706E0FDB204E859ULL,
		0x7645FB94AB2F1B37ULL,
		0x03183E9ADFB44E8AULL,
		0x4DE7E73B549E42F8ULL,
		0x9BB4ACB90EF03CD4ULL,
		0x3B4ACD8F0D5C9758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CFBADFA7B79FCAULL,
		0x9912F82CD1EE20B3ULL,
		0x2E0DC1FB6409D0B3ULL,
		0xEC8BF729565E366FULL,
		0x06307D35BF689D14ULL,
		0x9BCFCE76A93C85F0ULL,
		0x376959721DE079A8ULL,
		0x76959B1E1AB92EB1ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0DE9DED561B801AULL,
		0x9BE8121379E6D029ULL,
		0x3137B56A0A4A4E05ULL,
		0xE19D04FF196F663AULL,
		0x68EBF17B5977C4C5ULL,
		0xD8F8BBD9C07217CEULL,
		0x89555F4504FD7445ULL,
		0x3758ADBD0A6BFB48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BD3BDAAC370034ULL,
		0x37D02426F3CDA053ULL,
		0x626F6AD414949C0BULL,
		0xC33A09FE32DECC74ULL,
		0xD1D7E2F6B2EF898BULL,
		0xB1F177B380E42F9CULL,
		0x12AABE8A09FAE88BULL,
		0x6EB15B7A14D7F691ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3F3385791BD9AA98ULL,
		0x679DBBA08B754E86ULL,
		0x7D541700D1A0E857ULL,
		0xC13BB804D767E299ULL,
		0xEFC3AE2551186679ULL,
		0xE5DE34BF08626D6BULL,
		0xFDBAE49DFDFEF5ABULL,
		0x0A31A03F9735B2DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E670AF237B35530ULL,
		0xCF3B774116EA9D0CULL,
		0xFAA82E01A341D0AEULL,
		0x82777009AECFC532ULL,
		0xDF875C4AA230CCF3ULL,
		0xCBBC697E10C4DAD7ULL,
		0xFB75C93BFBFDEB57ULL,
		0x1463407F2E6B65BFULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB416E5247F9337BULL,
		0xF99DF18166F322A6ULL,
		0xFEE43845626C9E64ULL,
		0xB6A30B6DF80E5AE6ULL,
		0x4BFA804BB88E9027ULL,
		0x106682128896EF66ULL,
		0xE3C70C3608579610ULL,
		0x3B56506713F271D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5682DCA48FF266F6ULL,
		0xF33BE302CDE6454DULL,
		0xFDC8708AC4D93CC9ULL,
		0x6D4616DBF01CB5CDULL,
		0x97F50097711D204FULL,
		0x20CD0425112DDECCULL,
		0xC78E186C10AF2C20ULL,
		0x76ACA0CE27E4E3A9ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7DD5FC8F42A8306FULL,
		0x1B35AA0E12149B8BULL,
		0x59C2DF7937D3BC36ULL,
		0xA7E80A70E54CE368ULL,
		0x074A1481CD351CFEULL,
		0x3846611AE7A9D312ULL,
		0xFC0208677D0B609FULL,
		0x281B9943B258E3A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBABF91E855060DEULL,
		0x366B541C24293716ULL,
		0xB385BEF26FA7786CULL,
		0x4FD014E1CA99C6D0ULL,
		0x0E9429039A6A39FDULL,
		0x708CC235CF53A624ULL,
		0xF80410CEFA16C13EULL,
		0x5037328764B1C749ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF442F33C588E4AA7ULL,
		0x84E7B626F36A0D72ULL,
		0xAA098E7F435608D0ULL,
		0x811CED35E8F3F81BULL,
		0xFAF983308D468E9CULL,
		0xC01A278BD5341EBAULL,
		0xCB19E45D98B46A61ULL,
		0x279662ABD4693565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE885E678B11C954EULL,
		0x09CF6C4DE6D41AE5ULL,
		0x54131CFE86AC11A1ULL,
		0x0239DA6BD1E7F037ULL,
		0xF5F306611A8D1D39ULL,
		0x80344F17AA683D75ULL,
		0x9633C8BB3168D4C3ULL,
		0x4F2CC557A8D26ACBULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7F49A1FEB8F5D3DEULL,
		0xFD705BF0B5CB9D24ULL,
		0x8BD8CCA596593421ULL,
		0xA3DF2C1900E49DF8ULL,
		0x403836E5E5129466ULL,
		0x86F683C547B623E5ULL,
		0xCB8980D0201A9262ULL,
		0x34F0901B379A3816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE9343FD71EBA7BCULL,
		0xFAE0B7E16B973A48ULL,
		0x17B1994B2CB26843ULL,
		0x47BE583201C93BF1ULL,
		0x80706DCBCA2528CDULL,
		0x0DED078A8F6C47CAULL,
		0x971301A0403524C5ULL,
		0x69E120366F34702DULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8624E96A4D1E55ADULL,
		0x5615CBC83961A6E1ULL,
		0x781897768CC5EA97ULL,
		0x0A0C58420F6EEA20ULL,
		0xA831B7635EECA7AEULL,
		0xCDDAEE39AB9714C8ULL,
		0x37232071770946B7ULL,
		0x28B6C064410D8900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C49D2D49A3CAB5AULL,
		0xAC2B979072C34DC3ULL,
		0xF0312EED198BD52EULL,
		0x1418B0841EDDD440ULL,
		0x50636EC6BDD94F5CULL,
		0x9BB5DC73572E2991ULL,
		0x6E4640E2EE128D6FULL,
		0x516D80C8821B1200ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD41B39F6CF849EDEULL,
		0xD6372353EAEEDEFFULL,
		0x1A00FEA773D46288ULL,
		0x81E292EEF3542C08ULL,
		0x361E25DE867EB217ULL,
		0xB4E1F543BC6538A3ULL,
		0xDE114E4708931314ULL,
		0x371C430DBF6C05AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA83673ED9F093DBCULL,
		0xAC6E46A7D5DDBDFFULL,
		0x3401FD4EE7A8C511ULL,
		0x03C525DDE6A85810ULL,
		0x6C3C4BBD0CFD642FULL,
		0x69C3EA8778CA7146ULL,
		0xBC229C8E11262629ULL,
		0x6E38861B7ED80B5FULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0608A031D0915787ULL,
		0x7E720AB28EA10C66ULL,
		0xBCD97ECF782A4C25ULL,
		0xA566ADF8DD701067ULL,
		0x90C2FCED72CB125EULL,
		0xDB3F07A9C8BE228CULL,
		0x27EC5940B4284727ULL,
		0x18A3FE376F430C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C114063A122AF0EULL,
		0xFCE415651D4218CCULL,
		0x79B2FD9EF054984AULL,
		0x4ACD5BF1BAE020CFULL,
		0x2185F9DAE59624BDULL,
		0xB67E0F53917C4519ULL,
		0x4FD8B28168508E4FULL,
		0x3147FC6EDE861902ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8CD3F4470EF7CE8CULL,
		0x9E5BC46350D75D9EULL,
		0x31439D217A8E573FULL,
		0xA3D1BDF9A605572EULL,
		0xEAD6376BB1236A4BULL,
		0xBA5F7CB9359E6F11ULL,
		0x11B7AA50CDA949C3ULL,
		0x2B92A85C44B2C864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A7E88E1DEF9D18ULL,
		0x3CB788C6A1AEBB3DULL,
		0x62873A42F51CAE7FULL,
		0x47A37BF34C0AAE5CULL,
		0xD5AC6ED76246D497ULL,
		0x74BEF9726B3CDE23ULL,
		0x236F54A19B529387ULL,
		0x572550B8896590C8ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x222623DF021CB9AAULL,
		0xCC1682C54F07693BULL,
		0xA64176BBDEBE5C14ULL,
		0x6F8464E4C98898B2ULL,
		0x60B649B1BB583048ULL,
		0xA9E3DBC17E558F8FULL,
		0xFB3B196E15CAA8BBULL,
		0x2821C82419FCA454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444C47BE04397354ULL,
		0x982D058A9E0ED276ULL,
		0x4C82ED77BD7CB829ULL,
		0xDF08C9C993113165ULL,
		0xC16C936376B06090ULL,
		0x53C7B782FCAB1F1EULL,
		0xF67632DC2B955177ULL,
		0x5043904833F948A9ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBE9E879926EA1704ULL,
		0xCFE9709B0454C758ULL,
		0x0F8C5DB8EA3BE9D5ULL,
		0x35F614D553E6A89DULL,
		0xBA588B7F4C3B17C4ULL,
		0x5DDD38946147170CULL,
		0xE60CF24F09810117ULL,
		0x042210A7AD509F9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D3D0F324DD42E08ULL,
		0x9FD2E13608A98EB1ULL,
		0x1F18BB71D477D3ABULL,
		0x6BEC29AAA7CD513AULL,
		0x74B116FE98762F88ULL,
		0xBBBA7128C28E2E19ULL,
		0xCC19E49E1302022EULL,
		0x0844214F5AA13F3DULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8658614878677EF5ULL,
		0xE3041F9B59B1AF76ULL,
		0xF35D7B6DCA0B6B9FULL,
		0x98CF57AB01F8343AULL,
		0x28A113806DBDBC0DULL,
		0xBBDD84F27972FE36ULL,
		0xF3E27DCB15B025E7ULL,
		0x0562BFCED6444045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CB0C290F0CEFDEAULL,
		0xC6083F36B3635EEDULL,
		0xE6BAF6DB9416D73FULL,
		0x319EAF5603F06875ULL,
		0x51422700DB7B781BULL,
		0x77BB09E4F2E5FC6CULL,
		0xE7C4FB962B604BCFULL,
		0x0AC57F9DAC88808BULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x291A96D8F7BD8133ULL,
		0xEA6DD147391003DCULL,
		0x2F402CD89552B11FULL,
		0x72EDF902E8AEFC2CULL,
		0x360E863971ED6D80ULL,
		0xD4FF6163D3687757ULL,
		0x096FACF815BE550EULL,
		0x374CD8991AF82465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52352DB1EF7B0266ULL,
		0xD4DBA28E722007B8ULL,
		0x5E8059B12AA5623FULL,
		0xE5DBF205D15DF858ULL,
		0x6C1D0C72E3DADB00ULL,
		0xA9FEC2C7A6D0EEAEULL,
		0x12DF59F02B7CAA1DULL,
		0x6E99B13235F048CAULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0501C0F19F5BACDBULL,
		0x6964CECDF4F93A60ULL,
		0xA83A1CA4CFEA3B95ULL,
		0xB6DDDA3E984F2EC1ULL,
		0xBA9CFA26797AD005ULL,
		0xE0CC8ABC202EFE4BULL,
		0x21136B55050364BCULL,
		0x216CC3F5AC220C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A0381E33EB759B6ULL,
		0xD2C99D9BE9F274C0ULL,
		0x507439499FD4772AULL,
		0x6DBBB47D309E5D83ULL,
		0x7539F44CF2F5A00BULL,
		0xC1991578405DFC97ULL,
		0x4226D6AA0A06C979ULL,
		0x42D987EB58441814ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x724E7EB506C6A83CULL,
		0x0331F0423441A3CEULL,
		0x75B3F7ACAEBD6307ULL,
		0xC7E378CEBB304CEAULL,
		0x146DDB7D9E19B6AEULL,
		0x0A35789CAE759F20ULL,
		0xEA5B9BF394E045FEULL,
		0x0FABA8A6F4836A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE49CFD6A0D8D5078ULL,
		0x0663E0846883479CULL,
		0xEB67EF595D7AC60EULL,
		0x8FC6F19D766099D4ULL,
		0x28DBB6FB3C336D5DULL,
		0x146AF1395CEB3E40ULL,
		0xD4B737E729C08BFCULL,
		0x1F57514DE906D471ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF20A29AE22AF2FA2ULL,
		0xF6658050B1FBDAC4ULL,
		0x47A2C439B32E24DAULL,
		0x3BC7BB010FA38430ULL,
		0xE0951724449563C5ULL,
		0x41541AAAA1F91559ULL,
		0x98C08009E710D77BULL,
		0x399AC51BA1868917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE414535C455E5F44ULL,
		0xECCB00A163F7B589ULL,
		0x8F458873665C49B5ULL,
		0x778F76021F470860ULL,
		0xC12A2E48892AC78AULL,
		0x82A8355543F22AB3ULL,
		0x31810013CE21AEF6ULL,
		0x73358A37430D122FULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x677E5D493C196500ULL,
		0xAD1ACB3D182650BCULL,
		0x8E8A7F4778BEC174ULL,
		0xCCBBA65C793D7C20ULL,
		0x1D9EC01484B4328CULL,
		0xAE3EA37C6BD827F0ULL,
		0x2BF58F567963B1DDULL,
		0x0277011595534CACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEFCBA927832CA00ULL,
		0x5A35967A304CA178ULL,
		0x1D14FE8EF17D82E9ULL,
		0x99774CB8F27AF841ULL,
		0x3B3D802909686519ULL,
		0x5C7D46F8D7B04FE0ULL,
		0x57EB1EACF2C763BBULL,
		0x04EE022B2AA69958ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAE3DC45FF8453A10ULL,
		0x0E2A81BE2B47CCF5ULL,
		0xFE54F40988310891ULL,
		0x290B163442B88BD9ULL,
		0x77D66950E3F0C1A9ULL,
		0xC42BA3EA52146577ULL,
		0x35CD5735762B3713ULL,
		0x11FE584C32997902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7B88BFF08A7420ULL,
		0x1C55037C568F99EBULL,
		0xFCA9E81310621122ULL,
		0x52162C68857117B3ULL,
		0xEFACD2A1C7E18352ULL,
		0x885747D4A428CAEEULL,
		0x6B9AAE6AEC566E27ULL,
		0x23FCB0986532F204ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF2C78311C9C85ADBULL,
		0xF1CD9911BCEF9437ULL,
		0xFBB69B2837EB6EF7ULL,
		0xBAF2D238878E0B0BULL,
		0xA5EDC9DF8EA347A6ULL,
		0x703E7FB1E17F31B4ULL,
		0x0A7279703781A28FULL,
		0x3A8F76690E52E6B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE58F06239390B5B6ULL,
		0xE39B322379DF286FULL,
		0xF76D36506FD6DDEFULL,
		0x75E5A4710F1C1617ULL,
		0x4BDB93BF1D468F4DULL,
		0xE07CFF63C2FE6369ULL,
		0x14E4F2E06F03451EULL,
		0x751EECD21CA5CD6EULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x298AB47984ACF520ULL,
		0x20A2EC86DE8B29D4ULL,
		0xE860DF530DB1C5C8ULL,
		0x3C9DF13D36507DFBULL,
		0xBAB845167175ADF8ULL,
		0x80872B5B70480688ULL,
		0x1D259709C209F3FAULL,
		0x3244423B22C8B2EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x531568F30959EA40ULL,
		0x4145D90DBD1653A8ULL,
		0xD0C1BEA61B638B90ULL,
		0x793BE27A6CA0FBF7ULL,
		0x75708A2CE2EB5BF0ULL,
		0x010E56B6E0900D11ULL,
		0x3A4B2E138413E7F5ULL,
		0x64888476459165DCULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x32372E69A22F824AULL,
		0x6BB67EE9DF14A6A0ULL,
		0x0299BDE5C00DD2ECULL,
		0xF17FAB8DFA39A0C9ULL,
		0xF5ED7351E73B97FFULL,
		0x1A8A9DD487E13F28ULL,
		0xB7097407A1968F63ULL,
		0x215E4BEAD2F72F3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x646E5CD3445F0494ULL,
		0xD76CFDD3BE294D40ULL,
		0x05337BCB801BA5D8ULL,
		0xE2FF571BF4734192ULL,
		0xEBDAE6A3CE772FFFULL,
		0x35153BA90FC27E51ULL,
		0x6E12E80F432D1EC6ULL,
		0x42BC97D5A5EE5E7FULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5519D5C383FFD5BFULL,
		0x82AD2415D39C2463ULL,
		0xA3A32197444EE361ULL,
		0x76FC96EB90137DF4ULL,
		0x722BD1D61022BDDAULL,
		0xDDA4C9335C836532ULL,
		0x865A93EFCE016519ULL,
		0x0E4C84283AD1ED09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA33AB8707FFAB7EULL,
		0x055A482BA73848C6ULL,
		0x4746432E889DC6C3ULL,
		0xEDF92DD72026FBE9ULL,
		0xE457A3AC20457BB4ULL,
		0xBB499266B906CA64ULL,
		0x0CB527DF9C02CA33ULL,
		0x1C99085075A3DA13ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC501D729BA98AF28ULL,
		0xE3592BF9B9198069ULL,
		0x32D5B4BCB92D1618ULL,
		0x5DE67615499CA910ULL,
		0x68DE2ED267117ED1ULL,
		0xACFE0044788064EFULL,
		0x69248F2287A6A41DULL,
		0x0E3C52D38EC0B6B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A03AE5375315E50ULL,
		0xC6B257F3723300D3ULL,
		0x65AB6979725A2C31ULL,
		0xBBCCEC2A93395220ULL,
		0xD1BC5DA4CE22FDA2ULL,
		0x59FC0088F100C9DEULL,
		0xD2491E450F4D483BULL,
		0x1C78A5A71D816D6EULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDCD61582AA2B1004ULL,
		0xE7C9C861C9DB0B29ULL,
		0xEB0D9FFBCBC2713CULL,
		0x2BFCFB55173EE0C5ULL,
		0xEBA4D6498678E7F9ULL,
		0xC81F6E09C59E51D6ULL,
		0x26C70810B37E2F48ULL,
		0x30F6F0E60E266C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9AC2B0554562008ULL,
		0xCF9390C393B61653ULL,
		0xD61B3FF79784E279ULL,
		0x57F9F6AA2E7DC18BULL,
		0xD749AC930CF1CFF2ULL,
		0x903EDC138B3CA3ADULL,
		0x4D8E102166FC5E91ULL,
		0x61EDE1CC1C4CD85AULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF40335A37E7AA38ULL,
		0x24301A890C7C1FABULL,
		0xA03C44C1AD275992ULL,
		0x113506D3C5875A17ULL,
		0xD76EE5360A12B3E8ULL,
		0x70560FA8BFC936E5ULL,
		0x750941EAAB503EACULL,
		0x162AB7301DDB6AC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE8066B46FCF5470ULL,
		0x4860351218F83F57ULL,
		0x407889835A4EB324ULL,
		0x226A0DA78B0EB42FULL,
		0xAEDDCA6C142567D0ULL,
		0xE0AC1F517F926DCBULL,
		0xEA1283D556A07D58ULL,
		0x2C556E603BB6D58CULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x65A25CDCD4ECB813ULL,
		0xD0D49D798686460DULL,
		0x7B116C0234A29CFDULL,
		0xB6014622CCE333E3ULL,
		0x70875472F1B8DBB3ULL,
		0x3F4E1FBC12745661ULL,
		0xB494295D9B57352BULL,
		0x1485FF2921187DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB44B9B9A9D97026ULL,
		0xA1A93AF30D0C8C1AULL,
		0xF622D804694539FBULL,
		0x6C028C4599C667C6ULL,
		0xE10EA8E5E371B767ULL,
		0x7E9C3F7824E8ACC2ULL,
		0x692852BB36AE6A56ULL,
		0x290BFE524230FBA3ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x507A9DC4C74F6F08ULL,
		0x7D2EB185433C21ADULL,
		0xF3E90248BD9370F0ULL,
		0x88815583CE0568BDULL,
		0x3320BF10AF1CDCDAULL,
		0x65938212CDA6B6F6ULL,
		0x7C0FE0C172F9229FULL,
		0x35AD15C0BF1D105CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0F53B898E9EDE10ULL,
		0xFA5D630A8678435AULL,
		0xE7D204917B26E1E0ULL,
		0x1102AB079C0AD17BULL,
		0x66417E215E39B9B5ULL,
		0xCB2704259B4D6DECULL,
		0xF81FC182E5F2453EULL,
		0x6B5A2B817E3A20B8ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x78F551E3EED2D0F8ULL,
		0xC51E36374FECD684ULL,
		0x63B019B4BE4687BFULL,
		0x494A504A376661A4ULL,
		0xEB6AFC75B4A58AE7ULL,
		0xBD00103E408A9655ULL,
		0x2291CE80C3849344ULL,
		0x05229C7C6CD4A50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1EAA3C7DDA5A1F0ULL,
		0x8A3C6C6E9FD9AD08ULL,
		0xC76033697C8D0F7FULL,
		0x9294A0946ECCC348ULL,
		0xD6D5F8EB694B15CEULL,
		0x7A00207C81152CABULL,
		0x45239D0187092689ULL,
		0x0A4538F8D9A94A1CULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x52B1C9043A91E80CULL,
		0x1C7F26A4BA4A0727ULL,
		0x9314357CF7B449CAULL,
		0x8364D28A246E9DC8ULL,
		0x88D07A52084B3566ULL,
		0x2DEE6AFED482119AULL,
		0xBDB2FF4CCAB48FDBULL,
		0x04B33250AA1E28C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56392087523D018ULL,
		0x38FE4D4974940E4EULL,
		0x26286AF9EF689394ULL,
		0x06C9A51448DD3B91ULL,
		0x11A0F4A410966ACDULL,
		0x5BDCD5FDA9042335ULL,
		0x7B65FE9995691FB6ULL,
		0x096664A1543C5189ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x21223BD2EFE0700FULL,
		0x9BB9AAA079BB44E2ULL,
		0x49A8371E0546F7E6ULL,
		0x3E92040CC49F74B6ULL,
		0xE25FD2F14DDC2E1EULL,
		0x603CB5ED033C8381ULL,
		0xF3DC74DF1BE8F388ULL,
		0x1B062D3FD1D5DDCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424477A5DFC0E01EULL,
		0x37735540F37689C4ULL,
		0x93506E3C0A8DEFCDULL,
		0x7D240819893EE96CULL,
		0xC4BFA5E29BB85C3CULL,
		0xC0796BDA06790703ULL,
		0xE7B8E9BE37D1E710ULL,
		0x360C5A7FA3ABBB9BULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4612F60F96F9EA92ULL,
		0x5EB531C2B8A2372DULL,
		0xA3820AF15E4A2653ULL,
		0x75B9D48335406251ULL,
		0xCA078FDDEBADC83AULL,
		0x345A9106A9AD5DC6ULL,
		0xCB5EC6939BDE36CFULL,
		0x3FA6BBD785237E36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C25EC1F2DF3D524ULL,
		0xBD6A638571446E5AULL,
		0x470415E2BC944CA6ULL,
		0xEB73A9066A80C4A3ULL,
		0x940F1FBBD75B9074ULL,
		0x68B5220D535ABB8DULL,
		0x96BD8D2737BC6D9EULL,
		0x7F4D77AF0A46FC6DULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x50B29DD1B4A83864ULL,
		0x99046A56E81CFF5BULL,
		0x1F017E09769D7DEAULL,
		0xD1AE7BEFAB0005A6ULL,
		0xCC5E3A44B19977BEULL,
		0xA66AC35DDEB0039AULL,
		0x6A66C33B848FDC42ULL,
		0x051657A5FF364499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1653BA3695070C8ULL,
		0x3208D4ADD039FEB6ULL,
		0x3E02FC12ED3AFBD5ULL,
		0xA35CF7DF56000B4CULL,
		0x98BC74896332EF7DULL,
		0x4CD586BBBD600735ULL,
		0xD4CD8677091FB885ULL,
		0x0A2CAF4BFE6C8932ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB5F0839D224E0EEBULL,
		0x62D21A4DA0F982DEULL,
		0x281F6A839BDB763EULL,
		0x4F4715BB19611EB3ULL,
		0xFB40B20B887C89D9ULL,
		0x66EB3695AFBD1A4EULL,
		0x354FC5C6BB000BADULL,
		0x03724ABEB7C622A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE1073A449C1DD6ULL,
		0xC5A4349B41F305BDULL,
		0x503ED50737B6EC7CULL,
		0x9E8E2B7632C23D66ULL,
		0xF681641710F913B2ULL,
		0xCDD66D2B5F7A349DULL,
		0x6A9F8B8D7600175AULL,
		0x06E4957D6F8C4546ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC4307A738FE2D4B9ULL,
		0xC77FB88E693B09DFULL,
		0x2E356C233B16D63CULL,
		0x3BF855EA0FFC5958ULL,
		0x35534A6ACA5B3163ULL,
		0xA858B86FA9D7DA0DULL,
		0x50F6137D7ECCF69EULL,
		0x3A02DCA0275BB07EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8860F4E71FC5A972ULL,
		0x8EFF711CD27613BFULL,
		0x5C6AD846762DAC79ULL,
		0x77F0ABD41FF8B2B0ULL,
		0x6AA694D594B662C6ULL,
		0x50B170DF53AFB41AULL,
		0xA1EC26FAFD99ED3DULL,
		0x7405B9404EB760FCULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4D801A60AAB4B69BULL,
		0x4221B11A28D31B42ULL,
		0x1C1A6C85D751196EULL,
		0xD8B32485D39F9DA6ULL,
		0x3AEAF23EDC24AA30ULL,
		0x60438130C03175D1ULL,
		0xBEB949CF6322F709ULL,
		0x01BE19F66765195FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0034C155696D36ULL,
		0x8443623451A63684ULL,
		0x3834D90BAEA232DCULL,
		0xB166490BA73F3B4CULL,
		0x75D5E47DB8495461ULL,
		0xC08702618062EBA2ULL,
		0x7D72939EC645EE12ULL,
		0x037C33ECCECA32BFULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8448BBB0187C4D6DULL,
		0xD3431E3AEB79CD82ULL,
		0xCAC63E21D63ACE51ULL,
		0x7B3E0EEC4AFCDF64ULL,
		0x09D58C5313998092ULL,
		0x0E45DE6275AC31C3ULL,
		0xEC68F04AE0724080ULL,
		0x1221985B53A7D549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0891776030F89ADAULL,
		0xA6863C75D6F39B05ULL,
		0x958C7C43AC759CA3ULL,
		0xF67C1DD895F9BEC9ULL,
		0x13AB18A627330124ULL,
		0x1C8BBCC4EB586386ULL,
		0xD8D1E095C0E48100ULL,
		0x244330B6A74FAA93ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB886F1AFC2CB3ABULL,
		0x6134D55F077CB5F9ULL,
		0xEE53961C75412ABBULL,
		0xD958DE25AAA7AECCULL,
		0x5F168FFB80E50841ULL,
		0xB2DDAA50F8203488ULL,
		0xC8CFD5E646A052D5ULL,
		0x0FCEB18E37CA571DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9710DE35F8596756ULL,
		0xC269AABE0EF96BF3ULL,
		0xDCA72C38EA825576ULL,
		0xB2B1BC4B554F5D99ULL,
		0xBE2D1FF701CA1083ULL,
		0x65BB54A1F0406910ULL,
		0x919FABCC8D40A5ABULL,
		0x1F9D631C6F94AE3BULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA0302139003DE606ULL,
		0x43B2A94797355F6EULL,
		0xD26E3D73A7E824D3ULL,
		0x905322AB55C236A1ULL,
		0xD784AEC4D6194FD9ULL,
		0xF50ABC91F060F25AULL,
		0xD3413FA656C67C72ULL,
		0x155C5B13EBD26888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40604272007BCC0CULL,
		0x8765528F2E6ABEDDULL,
		0xA4DC7AE74FD049A6ULL,
		0x20A64556AB846D43ULL,
		0xAF095D89AC329FB3ULL,
		0xEA157923E0C1E4B5ULL,
		0xA6827F4CAD8CF8E5ULL,
		0x2AB8B627D7A4D111ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3C6B1396727C3B53ULL,
		0x23358C87739838F7ULL,
		0xC14BA496AB209B11ULL,
		0x1510BAD38FC08A39ULL,
		0x87422DCF8D7C1F38ULL,
		0x16AF87B3540208ADULL,
		0x73AD58DC7BDA3493ULL,
		0x1DB7F19E79762436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D6272CE4F876A6ULL,
		0x466B190EE73071EEULL,
		0x8297492D56413622ULL,
		0x2A2175A71F811473ULL,
		0x0E845B9F1AF83E70ULL,
		0x2D5F0F66A804115BULL,
		0xE75AB1B8F7B46926ULL,
		0x3B6FE33CF2EC486CULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5B8037A0180419BULL,
		0xEE53F5639282DBE1ULL,
		0xBC1A26437B80BF77ULL,
		0x7BFC4EBC803488ADULL,
		0x57838B0B9AE21E9DULL,
		0x695778AB55C3DD7FULL,
		0x788AC3D75913BA67ULL,
		0x1207512CD86187D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7006F403008336ULL,
		0xDCA7EAC72505B7C3ULL,
		0x78344C86F7017EEFULL,
		0xF7F89D790069115BULL,
		0xAF07161735C43D3AULL,
		0xD2AEF156AB87BAFEULL,
		0xF11587AEB22774CEULL,
		0x240EA259B0C30FB2ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2AAFA631F55CBBEEULL,
		0xC2A3E585429A66F6ULL,
		0xBA8234F0C735C6E9ULL,
		0x93E0F02776D63159ULL,
		0xF2AC71F6AC0684E0ULL,
		0x7C8E037C90423076ULL,
		0xD3581694FFBDD2DDULL,
		0x11630B98FDC2FCAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x555F4C63EAB977DCULL,
		0x8547CB0A8534CDECULL,
		0x750469E18E6B8DD3ULL,
		0x27C1E04EEDAC62B3ULL,
		0xE558E3ED580D09C1ULL,
		0xF91C06F9208460EDULL,
		0xA6B02D29FF7BA5BAULL,
		0x22C61731FB85F955ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAFEBCF2F76A96F15ULL,
		0x93EB67D775F36C39ULL,
		0x82B371474E298DD9ULL,
		0xDE2D91F53D927951ULL,
		0xC2BC95AEDAC14981ULL,
		0x9200BCA98234E099ULL,
		0x7ED0B2DACB2D435EULL,
		0x0ADA298F09E85E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD79E5EED52DE2AULL,
		0x27D6CFAEEBE6D873ULL,
		0x0566E28E9C531BB3ULL,
		0xBC5B23EA7B24F2A3ULL,
		0x85792B5DB5829303ULL,
		0x240179530469C133ULL,
		0xFDA165B5965A86BDULL,
		0x15B4531E13D0BC1EULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7ED1D15B9E038FB2ULL,
		0x373E136CA60CF31CULL,
		0x88D2C352D0B826B8ULL,
		0x509C67A61818C8CDULL,
		0x000409A0BCAC549CULL,
		0xE395EDFE12C8BC67ULL,
		0x25EB903FEE088C69ULL,
		0x08A504F818E4FD20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA3A2B73C071F64ULL,
		0x6E7C26D94C19E638ULL,
		0x11A586A5A1704D70ULL,
		0xA138CF4C3031919BULL,
		0x000813417958A938ULL,
		0xC72BDBFC259178CEULL,
		0x4BD7207FDC1118D3ULL,
		0x114A09F031C9FA40ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x18891C835C3D1139ULL,
		0x3E3E542A735DCA70ULL,
		0x97C361DC9B3783F7ULL,
		0xA6B21443C2AF0712ULL,
		0xADCC77E6BCDC01F6ULL,
		0xECE5872B97D2B629ULL,
		0x52DA24494FFF2C00ULL,
		0x32C602425070A6B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31123906B87A2272ULL,
		0x7C7CA854E6BB94E0ULL,
		0x2F86C3B9366F07EEULL,
		0x4D642887855E0E25ULL,
		0x5B98EFCD79B803EDULL,
		0xD9CB0E572FA56C53ULL,
		0xA5B448929FFE5801ULL,
		0x658C0484A0E14D60ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC56300FCC00BD1D2ULL,
		0xD84FA12598395790ULL,
		0x88CB130AEFA71193ULL,
		0x2A01460B291EC441ULL,
		0x2918D3119BE9B39CULL,
		0xAD2E09600520028BULL,
		0xA551E298D7A78760ULL,
		0x055ACB8FD8BC77ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AC601F98017A3A4ULL,
		0xB09F424B3072AF21ULL,
		0x11962615DF4E2327ULL,
		0x54028C16523D8883ULL,
		0x5231A62337D36738ULL,
		0x5A5C12C00A400516ULL,
		0x4AA3C531AF4F0EC1ULL,
		0x0AB5971FB178EF5BULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D7AEA4BFEE57185ULL,
		0xB4DAEF4F33E3B7A5ULL,
		0x670414FA00D9DC18ULL,
		0x15324CC5D1280496ULL,
		0x1346CCEA459048C1ULL,
		0x53548B953F2745F9ULL,
		0xD70909CEFEBB0F95ULL,
		0x20AFC9370E97C97EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF5D497FDCAE30AULL,
		0x69B5DE9E67C76F4AULL,
		0xCE0829F401B3B831ULL,
		0x2A64998BA250092CULL,
		0x268D99D48B209182ULL,
		0xA6A9172A7E4E8BF2ULL,
		0xAE12139DFD761F2AULL,
		0x415F926E1D2F92FDULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x081D9F349326E172ULL,
		0xF305EF27E036F5D0ULL,
		0x3715D8786C379419ULL,
		0x54922ED3C976AFFDULL,
		0xEED623CF3CE11692ULL,
		0x4E63A4088119E71FULL,
		0x2480C769C2554D9AULL,
		0x3890909B7BDE296EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x103B3E69264DC2E4ULL,
		0xE60BDE4FC06DEBA0ULL,
		0x6E2BB0F0D86F2833ULL,
		0xA9245DA792ED5FFAULL,
		0xDDAC479E79C22D24ULL,
		0x9CC748110233CE3FULL,
		0x49018ED384AA9B34ULL,
		0x71212136F7BC52DCULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x685FF9505DC2489CULL,
		0x570AA34D0EE653C0ULL,
		0x0DDD7338262DF60CULL,
		0x89D8AC0725A62BFEULL,
		0x46E667A58E3EE207ULL,
		0x182A65A21A99286CULL,
		0x8FAB3A7FF43F806FULL,
		0x043E7631F2BFF367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0BFF2A0BB849138ULL,
		0xAE15469A1DCCA780ULL,
		0x1BBAE6704C5BEC18ULL,
		0x13B1580E4B4C57FCULL,
		0x8DCCCF4B1C7DC40FULL,
		0x3054CB44353250D8ULL,
		0x1F5674FFE87F00DEULL,
		0x087CEC63E57FE6CFULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x033E389A5DBD854DULL,
		0x508A2440830F95E9ULL,
		0x5D09675C84753A01ULL,
		0xF215EFB98FE8DCAAULL,
		0xC64E8116F273CF98ULL,
		0xF44BA68F8941512CULL,
		0x94BF19270150D249ULL,
		0x328DCAB6A0FE19C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067C7134BB7B0A9AULL,
		0xA1144881061F2BD2ULL,
		0xBA12CEB908EA7402ULL,
		0xE42BDF731FD1B954ULL,
		0x8C9D022DE4E79F31ULL,
		0xE8974D1F1282A259ULL,
		0x297E324E02A1A493ULL,
		0x651B956D41FC338DULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x296658B9908ECE94ULL,
		0xA8122952CD0C8CD5ULL,
		0xD22984E498C8A77DULL,
		0x55408923D695AED2ULL,
		0x3F5FE5AB087DD172ULL,
		0x4193BD22F1BAE37CULL,
		0xA4546F5815D89FB6ULL,
		0x23B834940174F331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52CCB173211D9D28ULL,
		0x502452A59A1919AAULL,
		0xA45309C931914EFBULL,
		0xAA811247AD2B5DA5ULL,
		0x7EBFCB5610FBA2E4ULL,
		0x83277A45E375C6F8ULL,
		0x48A8DEB02BB13F6CULL,
		0x4770692802E9E663ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE986B685B229F235ULL,
		0x6FA65E875F4023B1ULL,
		0xE91E500A8442B3B5ULL,
		0xE6F7856793F73523ULL,
		0xAB791347CE317AD0ULL,
		0xD3550C286412D07CULL,
		0x26274CE30223D4EFULL,
		0x3A9A64A2D0390E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD30D6D0B6453E46AULL,
		0xDF4CBD0EBE804763ULL,
		0xD23CA0150885676AULL,
		0xCDEF0ACF27EE6A47ULL,
		0x56F2268F9C62F5A1ULL,
		0xA6AA1850C825A0F9ULL,
		0x4C4E99C60447A9DFULL,
		0x7534C945A0721D18ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD9740E7E4A9D9EBDULL,
		0x156C99B7C19CAC34ULL,
		0xCE14DEAC340782F9ULL,
		0x51FD2822FE47EDEFULL,
		0xB1D0BA6AFEBF1F1AULL,
		0xBDD190128E2E4F53ULL,
		0x86EF3F1D9FF9634AULL,
		0x1553C34714CC93FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E81CFC953B3D7AULL,
		0x2AD9336F83395869ULL,
		0x9C29BD58680F05F2ULL,
		0xA3FA5045FC8FDBDFULL,
		0x63A174D5FD7E3E34ULL,
		0x7BA320251C5C9EA7ULL,
		0x0DDE7E3B3FF2C695ULL,
		0x2AA7868E299927F9ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x567C4485B5D58A9BULL,
		0x37CDC28170C62A6BULL,
		0x09DE43C6CD11C954ULL,
		0x21EC3F06FED4D532ULL,
		0xCA67F0709D15D981ULL,
		0xD0CF12E357A027B1ULL,
		0x6ED3551893D0286AULL,
		0x254E86AB08C83B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF8890B6BAB1536ULL,
		0x6F9B8502E18C54D6ULL,
		0x13BC878D9A2392A8ULL,
		0x43D87E0DFDA9AA64ULL,
		0x94CFE0E13A2BB302ULL,
		0xA19E25C6AF404F63ULL,
		0xDDA6AA3127A050D5ULL,
		0x4A9D0D56119076ECULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9F9E2A2A3DCCA69EULL,
		0x97F4E8528299F7E7ULL,
		0x9143E3821EEBF8CEULL,
		0xD7A414EA2C7D2CF3ULL,
		0xE7949312FC57C0E3ULL,
		0x00FB39F8E2E0F1B3ULL,
		0x1E1620069617129CULL,
		0x0712E36FDCB66F0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F3C54547B994D3CULL,
		0x2FE9D0A50533EFCFULL,
		0x2287C7043DD7F19DULL,
		0xAF4829D458FA59E7ULL,
		0xCF292625F8AF81C7ULL,
		0x01F673F1C5C1E367ULL,
		0x3C2C400D2C2E2538ULL,
		0x0E25C6DFB96CDE16ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDD505148260E97E0ULL,
		0xE8559CE4542DCD1AULL,
		0x404804E7E5E2AB4AULL,
		0x1AC8A5AF3CD47CE0ULL,
		0xA3EE260D66DAF426ULL,
		0xA94E2A643A25C2E9ULL,
		0xA56C300663F02AFDULL,
		0x301D6F392854DD71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA0A2904C1D2FC0ULL,
		0xD0AB39C8A85B9A35ULL,
		0x809009CFCBC55695ULL,
		0x35914B5E79A8F9C0ULL,
		0x47DC4C1ACDB5E84CULL,
		0x529C54C8744B85D3ULL,
		0x4AD8600CC7E055FBULL,
		0x603ADE7250A9BAE3ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3664E859B10209C9ULL,
		0x351864947A7AB829ULL,
		0x27BB25155D8211CEULL,
		0x3D5BD095DD5AE242ULL,
		0xF53D14794907899AULL,
		0x0BF3EB4F296321D6ULL,
		0x82A4FD080B99F8BBULL,
		0x0987F69403FEB386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC9D0B362041392ULL,
		0x6A30C928F4F57052ULL,
		0x4F764A2ABB04239CULL,
		0x7AB7A12BBAB5C484ULL,
		0xEA7A28F2920F1334ULL,
		0x17E7D69E52C643ADULL,
		0x0549FA101733F176ULL,
		0x130FED2807FD670DULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE56D5A750DC82DF4ULL,
		0xFAABD3DFEAD8DA4BULL,
		0xEE2FD16F88633970ULL,
		0x3AF0C08910EB5C6BULL,
		0x2CE154C310170338ULL,
		0x25883690528E431BULL,
		0x1B3AB88096B990ACULL,
		0x24B7ABD26BCFB387ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADAB4EA1B905BE8ULL,
		0xF557A7BFD5B1B497ULL,
		0xDC5FA2DF10C672E1ULL,
		0x75E1811221D6B8D7ULL,
		0x59C2A986202E0670ULL,
		0x4B106D20A51C8636ULL,
		0x367571012D732158ULL,
		0x496F57A4D79F670EULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7B3079530E85F87DULL,
		0xEC41EDE0518D505CULL,
		0x6520E29B50D30D37ULL,
		0x81B736D0C253E13AULL,
		0x1FF2EC70583C8B71ULL,
		0x056F81ED4ADFA64EULL,
		0x7E139608E6C1F49AULL,
		0x18D7AE299B44D65EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF660F2A61D0BF0FAULL,
		0xD883DBC0A31AA0B8ULL,
		0xCA41C536A1A61A6FULL,
		0x036E6DA184A7C274ULL,
		0x3FE5D8E0B07916E3ULL,
		0x0ADF03DA95BF4C9CULL,
		0xFC272C11CD83E934ULL,
		0x31AF5C533689ACBCULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8C65D6470CE1480AULL,
		0x7E45E15AEE1F8ED7ULL,
		0xC65841FF543326CDULL,
		0xC08B5E83A7E0900AULL,
		0xE9D308F67FB17708ULL,
		0x41D138AE7D1B5FB9ULL,
		0x066B4A7728A20B5FULL,
		0x1AAB6E12D59CA218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18CBAC8E19C29014ULL,
		0xFC8BC2B5DC3F1DAFULL,
		0x8CB083FEA8664D9AULL,
		0x8116BD074FC12015ULL,
		0xD3A611ECFF62EE11ULL,
		0x83A2715CFA36BF73ULL,
		0x0CD694EE514416BEULL,
		0x3556DC25AB394430ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2098AD1F956493AEULL,
		0x5EB2B1277929062FULL,
		0x8384655F69445D25ULL,
		0xBCFA0848E3B945FEULL,
		0x657947A3DCA89584ULL,
		0xBCB2648A4F0F9F38ULL,
		0x8A3950B6DB6ED60BULL,
		0x2918D9B21A87035AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41315A3F2AC9275CULL,
		0xBD65624EF2520C5EULL,
		0x0708CABED288BA4AULL,
		0x79F41091C7728BFDULL,
		0xCAF28F47B9512B09ULL,
		0x7964C9149E1F3E70ULL,
		0x1472A16DB6DDAC17ULL,
		0x5231B364350E06B5ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x88FF14EF3B9CD3E9ULL,
		0x8E6256D3EB0B4424ULL,
		0x47990CC3F1135808ULL,
		0xD1F09301B454EE59ULL,
		0x7FEB3FD3C8208152ULL,
		0x1AD5B01355A99079ULL,
		0x5FFBB970B8475317ULL,
		0x04B7E36D7486694FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11FE29DE7739A7D2ULL,
		0x1CC4ADA7D6168849ULL,
		0x8F321987E226B011ULL,
		0xA3E1260368A9DCB2ULL,
		0xFFD67FA7904102A5ULL,
		0x35AB6026AB5320F2ULL,
		0xBFF772E1708EA62EULL,
		0x096FC6DAE90CD29EULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F21C2862FBFDB9BULL,
		0x430AE7C7E4BFA384ULL,
		0xCE5743971498CF6CULL,
		0x5537E949E1F7320DULL,
		0x650AC23B408CB617ULL,
		0x0AE72982D2E606FCULL,
		0xEB803F69249B9806ULL,
		0x1E7447F412D94CEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E43850C5F7FB736ULL,
		0x8615CF8FC97F4708ULL,
		0x9CAE872E29319ED8ULL,
		0xAA6FD293C3EE641BULL,
		0xCA15847681196C2EULL,
		0x15CE5305A5CC0DF8ULL,
		0xD7007ED24937300CULL,
		0x3CE88FE825B299DFULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5E12E46A16B2D5EBULL,
		0x81FDE2BB67D6AC4EULL,
		0x76609AB71894A0ECULL,
		0x4B285325FF341FFAULL,
		0x2693CAEC22D926F8ULL,
		0xB0B64E6BBD5686A7ULL,
		0xA4F104920812AF58ULL,
		0x016F21668880CC42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC25C8D42D65ABD6ULL,
		0x03FBC576CFAD589CULL,
		0xECC1356E312941D9ULL,
		0x9650A64BFE683FF4ULL,
		0x4D2795D845B24DF0ULL,
		0x616C9CD77AAD0D4EULL,
		0x49E2092410255EB1ULL,
		0x02DE42CD11019885ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5868D1F0BA6F3056ULL,
		0x42E957A02E065B54ULL,
		0x65879B857E1B4A81ULL,
		0x38688EE38C6A51CAULL,
		0x44B1B65999983277ULL,
		0xB84E3E0BB15121F0ULL,
		0x7A66CE1AC3F95CD6ULL,
		0x23A12DFD5B8B1358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D1A3E174DE60ACULL,
		0x85D2AF405C0CB6A8ULL,
		0xCB0F370AFC369502ULL,
		0x70D11DC718D4A394ULL,
		0x89636CB3333064EEULL,
		0x709C7C1762A243E0ULL,
		0xF4CD9C3587F2B9ADULL,
		0x47425BFAB71626B0ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x960159738CB7FFF3ULL,
		0x90FDE72A17A1F1A4ULL,
		0x484A679768F0CB72ULL,
		0xD98B8269DBCCAECCULL,
		0x84E8249A0B9BF842ULL,
		0x6967A77A638995CFULL,
		0x1AEBB0C9393F29EAULL,
		0x3F9E9415A4B4CD01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C02B2E7196FFFE6ULL,
		0x21FBCE542F43E349ULL,
		0x9094CF2ED1E196E5ULL,
		0xB31704D3B7995D98ULL,
		0x09D049341737F085ULL,
		0xD2CF4EF4C7132B9FULL,
		0x35D76192727E53D4ULL,
		0x7F3D282B49699A02ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x16EF7F08185BA658ULL,
		0xB5F36BAC032DCE3FULL,
		0x6F1EB24353694A69ULL,
		0x233B4CB1F95C51AAULL,
		0x6A51CFE5980F338FULL,
		0x22464A3DF64C44BCULL,
		0x50517688EB1523BAULL,
		0x1308DCC69CBAA05EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDEFE1030B74CB0ULL,
		0x6BE6D758065B9C7EULL,
		0xDE3D6486A6D294D3ULL,
		0x46769963F2B8A354ULL,
		0xD4A39FCB301E671EULL,
		0x448C947BEC988978ULL,
		0xA0A2ED11D62A4774ULL,
		0x2611B98D397540BCULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD957BFE53B6D175BULL,
		0x3115F63C584451E5ULL,
		0xD06DDC768CA0269EULL,
		0x1D858A5F2C6B342DULL,
		0xEEF37A89D325CAA6ULL,
		0x83DEC6A1A3BC88E4ULL,
		0x402384C509162ABEULL,
		0x1EC3C71066B1E45DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AF7FCA76DA2EB6ULL,
		0x622BEC78B088A3CBULL,
		0xA0DBB8ED19404D3CULL,
		0x3B0B14BE58D6685BULL,
		0xDDE6F513A64B954CULL,
		0x07BD8D43477911C9ULL,
		0x8047098A122C557DULL,
		0x3D878E20CD63C8BAULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFA425E4E2781C198ULL,
		0x61C07707CF76056AULL,
		0x61F544DC6438505FULL,
		0x54DCF9B0572A958CULL,
		0xE557F52D1878F47FULL,
		0xC5FD18FB007585D5ULL,
		0x42A83D0969F5D09AULL,
		0x27241A0173831F9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF484BC9C4F038330ULL,
		0xC380EE0F9EEC0AD5ULL,
		0xC3EA89B8C870A0BEULL,
		0xA9B9F360AE552B18ULL,
		0xCAAFEA5A30F1E8FEULL,
		0x8BFA31F600EB0BABULL,
		0x85507A12D3EBA135ULL,
		0x4E483402E7063F3CULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0C8EC524DE49CFEULL,
		0x45E72CC8616B901AULL,
		0x13DE3A6EDF891E44ULL,
		0x8E89022D85A6EA4CULL,
		0x572B7638F59CC521ULL,
		0xB5CD3393DA84BBCDULL,
		0x955EA4A25B1A3424ULL,
		0x322DEBAE695C319CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC191D8A49BC939FCULL,
		0x8BCE5990C2D72035ULL,
		0x27BC74DDBF123C88ULL,
		0x1D12045B0B4DD498ULL,
		0xAE56EC71EB398A43ULL,
		0x6B9A6727B509779AULL,
		0x2ABD4944B6346849ULL,
		0x645BD75CD2B86339ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x139EBE412FBD21B7ULL,
		0x0018B86697E1D6BEULL,
		0x374729EF97A62028ULL,
		0xEF40D0561948077FULL,
		0xA3BD0F6D9D80557CULL,
		0xEEFB713074D088FFULL,
		0x2BB206146BB48DB0ULL,
		0x0E232BD6396A9354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x273D7C825F7A436EULL,
		0x003170CD2FC3AD7CULL,
		0x6E8E53DF2F4C4050ULL,
		0xDE81A0AC32900EFEULL,
		0x477A1EDB3B00AAF9ULL,
		0xDDF6E260E9A111FFULL,
		0x57640C28D7691B61ULL,
		0x1C4657AC72D526A8ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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