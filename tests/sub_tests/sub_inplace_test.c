#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0xB8FDADEA7880F956ULL,
		0xB5343BF209CA4435ULL,
		0x0C26175B007C3211ULL,
		0x2B09994FD34B2E9CULL,
		0x0A279B44C3C16EE2ULL,
		0xC8C842DC3046E38BULL,
		0xCFCDFD2F9C31D1CEULL,
		0x81CE5DFA0131735BULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0x61BC61ED0B735CD8ULL,
		0xBCD649CE8698C41DULL,
		0x530D8DCE0D85B967ULL,
		0x2BF37E793EF11761ULL,
		0xDABC89C719F0D380ULL,
		0x72C217A5218FD971ULL,
		0xCE1AC02EA4CC5675ULL,
		0xCA4020BF54E7CBE8ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x57414BFD6D0D9C7EULL,
		0xF85DF22383318018ULL,
		0xB918898CF2F678A9ULL,
		0xFF161AD6945A173AULL,
		0x2F6B117DA9D09B61ULL,
		0x56062B370EB70A19ULL,
		0x01B33D00F7657B59ULL,
		0xB78E3D3AAC49A773ULL
	}};
	printf("Underflow\n");
	int sign = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF729C57EBCA24866ULL,
		0x5068B62895E02280ULL,
		0x36CE0F7129FF1ACFULL,
		0xACB7FA5EE6D16BAAULL,
		0xC36B3C607756D3AFULL,
		0x90A5516760CED650ULL,
		0xF35BDB4BAA6D6F1AULL,
		0x1B7D9BDA2626A720ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F9C7857ACC44FEULL,
		0xE393F915AE6010BCULL,
		0x4C60C7326F1F4898ULL,
		0x44B4BB6627C3F072ULL,
		0x8180D2A862E70DF2ULL,
		0xCA53515B3470721FULL,
		0xCADD588CEBEDFEE2ULL,
		0x4CCED04CFC2D0FC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE52FFDF941D60368ULL,
		0x6CD4BD12E78011C4ULL,
		0xEA6D483EBADFD236ULL,
		0x68033EF8BF0D7B37ULL,
		0x41EA69B8146FC5BDULL,
		0xC652000C2C5E6431ULL,
		0x287E82BEBE7F7037ULL,
		0xCEAECB8D29F9975DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAE17D5A4958B8D50ULL,
		0x4C99C530E1CE6244ULL,
		0x5B8C92FC4E92C6D4ULL,
		0x35A4FC349CB017B1ULL,
		0xB6D087BE35C19805ULL,
		0xF8CE03D2141D5637ULL,
		0xEBEF88F483E5BDA7ULL,
		0x253E303B6D54D000ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A9D343DBD2F984DULL,
		0x9C5731F3A1775D53ULL,
		0x39D729B2A83BFE97ULL,
		0xED8F87E7F13BF765ULL,
		0x5D173BFB49769792ULL,
		0xDCCCA2518FAEF5ADULL,
		0x2D4D70400A7540DCULL,
		0x0A0E64B14227221CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x137AA166D85BF503ULL,
		0xB042933D405704F1ULL,
		0x21B56949A656C83CULL,
		0x4815744CAB74204CULL,
		0x59B94BC2EC4B0072ULL,
		0x1C016180846E608AULL,
		0xBEA218B479707CCBULL,
		0x1B2FCB8A2B2DADE4ULL
	}};
	sign = 0;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D5E2D1AC3DD93EFULL,
		0x3C07721BEC1C1D20ULL,
		0x2875EEFA5F49F1EAULL,
		0x72DDF821964EBC2FULL,
		0xA4D314F9E32103A3ULL,
		0x80244ECDDA1AA525ULL,
		0x910C2F6D3D6F36F1ULL,
		0xFC4DEC86BD641C51ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x471170F5ACAED172ULL,
		0xAD4FF0971BCF4138ULL,
		0x284BBE9D2917C1BAULL,
		0x1D30A27A880B08EDULL,
		0x808582B4BE61B78CULL,
		0x14B9A3EA86910F7CULL,
		0x6338FD162A84BACEULL,
		0xADE81EFC8DEECA48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC64CBC25172EC27DULL,
		0x8EB78184D04CDBE7ULL,
		0x002A305D3632302FULL,
		0x55AD55A70E43B342ULL,
		0x244D924524BF4C17ULL,
		0x6B6AAAE3538995A9ULL,
		0x2DD3325712EA7C23ULL,
		0x4E65CD8A2F755209ULL
	}};
	sign = 0;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7AEC8CC5ABD92C89ULL,
		0x001F3B057189194EULL,
		0x4B7AAC55C35B2C50ULL,
		0xEB4A25400BD1055CULL,
		0xC1153DB44974D0B0ULL,
		0x1DBC26B18A688492ULL,
		0x2CDCB009FB0657E8ULL,
		0x8C830A12E96A120AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9731E092A0982595ULL,
		0xB16A6163618E5F72ULL,
		0x6B5613F6BA1F2091ULL,
		0x9F3181BE636E9F21ULL,
		0x7360B7A11B6F7099ULL,
		0xF14BC91A6BD15CADULL,
		0x1E1CAD6B66B5460DULL,
		0x13CBB5F9A192F067ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3BAAC330B4106F4ULL,
		0x4EB4D9A20FFAB9DBULL,
		0xE024985F093C0BBEULL,
		0x4C18A381A862663AULL,
		0x4DB486132E056017ULL,
		0x2C705D971E9727E5ULL,
		0x0EC0029E945111DAULL,
		0x78B7541947D721A3ULL
	}};
	sign = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA977DB316B7D1178ULL,
		0x640A0A360B265136ULL,
		0x9BF0593A23AFECD8ULL,
		0x8F4D580F816B780CULL,
		0x952B281F6DFCE034ULL,
		0x9529CE7A7581302CULL,
		0x8B1C9BACCA73F332ULL,
		0x2A16EE6ACFC32A70ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x931F787EF621A109ULL,
		0x8B69FBACE1332595ULL,
		0x963D3767DCF50283ULL,
		0xFE990DF62064BB0DULL,
		0x868B28BC0479D32CULL,
		0xACA3800BD30EC7E4ULL,
		0xC2547C98E91051F0ULL,
		0xF5B8F717F3B27E2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x165862B2755B706FULL,
		0xD8A00E8929F32BA1ULL,
		0x05B321D246BAEA54ULL,
		0x90B44A196106BCFFULL,
		0x0E9FFF6369830D07ULL,
		0xE8864E6EA2726848ULL,
		0xC8C81F13E163A141ULL,
		0x345DF752DC10AC45ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5C1606BEB2D57D58ULL,
		0x65B17B02DBB2C262ULL,
		0x7976ECCAF3926AE4ULL,
		0xC706777CE7D58D6FULL,
		0x406CE5F86481E0F0ULL,
		0x36D35E98F8BDCB3EULL,
		0x016D7BFC91624B2AULL,
		0x2159C1ED6289AAC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F9495A2A164D25ULL,
		0xA4D2DBCFB1293C32ULL,
		0x9ADBCC6AE02BC529ULL,
		0x2107812DACC5678CULL,
		0x9FEB58E222501D58ULL,
		0x8D9C1E351A90DB2EULL,
		0x88911AE600012FC5ULL,
		0x21AA0755D763B083ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA41CBD6488BF3033ULL,
		0xC0DE9F332A89862FULL,
		0xDE9B20601366A5BAULL,
		0xA5FEF64F3B1025E2ULL,
		0xA0818D164231C398ULL,
		0xA9374063DE2CF00FULL,
		0x78DC611691611B64ULL,
		0xFFAFBA978B25FA40ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4448B03C79EA55B0ULL,
		0x96CEE1C8E3222ED9ULL,
		0x9D2B1C322E86A670ULL,
		0xDE02329A9FEED22FULL,
		0x24BA7E98C84E9478ULL,
		0x56BC4A34FF168D77ULL,
		0x895F97C4A032F0AEULL,
		0xE90B8969AC637623ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x466B33F9795DF361ULL,
		0xF47D861A4869DF30ULL,
		0xD9BADBBAB482F1DAULL,
		0xBFD2FABFB53F987BULL,
		0x2A626BCD3D7A0DFBULL,
		0x8A602A961616A191ULL,
		0xD9A4D86D07A571BBULL,
		0x1CA8BE39356F14C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDDD7C43008C624FULL,
		0xA2515BAE9AB84FA8ULL,
		0xC37040777A03B495ULL,
		0x1E2F37DAEAAF39B3ULL,
		0xFA5812CB8AD4867DULL,
		0xCC5C1F9EE8FFEBE5ULL,
		0xAFBABF57988D7EF2ULL,
		0xCC62CB3076F4615BULL
	}};
	sign = 0;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB782A03CC5BC2756ULL,
		0x9309AA8CF3381957ULL,
		0x337FB0432B604EABULL,
		0x6D139DDAE98310B0ULL,
		0xDDBEAFB6540998E5ULL,
		0x58744449DEC24390ULL,
		0xF6E285EB7F21510EULL,
		0x5A12E831BE42FE37ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x345B44522F6BC252ULL,
		0x045FE671F450B309ULL,
		0x82D4CF0792F139C6ULL,
		0xAE38E1E9E185ED12ULL,
		0xCD4E54188855FEECULL,
		0xF541797550568292ULL,
		0x5D30B62941B62A93ULL,
		0x4289C4EE247B4422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83275BEA96506504ULL,
		0x8EA9C41AFEE7664EULL,
		0xB0AAE13B986F14E5ULL,
		0xBEDABBF107FD239DULL,
		0x10705B9DCBB399F8ULL,
		0x6332CAD48E6BC0FEULL,
		0x99B1CFC23D6B267AULL,
		0x1789234399C7BA15ULL
	}};
	sign = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x544767A200EE8E21ULL,
		0x09D1EAEB302604B0ULL,
		0xD96F5BE315803F61ULL,
		0x815F870963740026ULL,
		0x1BE4E8FE6FB3104CULL,
		0x3F29711C7CD8D4E5ULL,
		0x0F4F685AD9464C3EULL,
		0x3E6396CE5C98FF6DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x836FAB2F349E68DDULL,
		0x9A345FF5C19E3328ULL,
		0x935C1095AD8CDC49ULL,
		0xFF6FC8048FD4A5F4ULL,
		0xCD3CA575E382749AULL,
		0x3BB21E2C315281B5ULL,
		0xAAFC1211D865D13FULL,
		0x55D0161416A37838ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0D7BC72CC502544ULL,
		0x6F9D8AF56E87D187ULL,
		0x46134B4D67F36317ULL,
		0x81EFBF04D39F5A32ULL,
		0x4EA843888C309BB1ULL,
		0x037752F04B86532FULL,
		0x6453564900E07AFFULL,
		0xE89380BA45F58734ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0181C2A7D685EF8DULL,
		0xC4B5E2F3EED28E35ULL,
		0x6A2266E285A342B0ULL,
		0x8C1319159322C812ULL,
		0x92E71E2F77D78CFDULL,
		0x5A21CB93CF16A8CEULL,
		0x48B8085A96C1557FULL,
		0xCD3421404BD48C04ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C6CF0759B2CEFFEULL,
		0x82E2E5ADE2DF5C3AULL,
		0x5CB3CDF27AFC5A44ULL,
		0x77F8C325E33ACF78ULL,
		0xC7693211FA06DFE5ULL,
		0xF70C3424755BD28BULL,
		0x4824C32EBC57CDF7ULL,
		0x8378F4EAB2C513FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD514D2323B58FF8FULL,
		0x41D2FD460BF331FAULL,
		0x0D6E98F00AA6E86CULL,
		0x141A55EFAFE7F89AULL,
		0xCB7DEC1D7DD0AD18ULL,
		0x6315976F59BAD642ULL,
		0x0093452BDA698787ULL,
		0x49BB2C55990F7808ULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3447C6852FA29A27ULL,
		0xE20194F877B99030ULL,
		0xCDCD4C8E6E6BD74BULL,
		0xED00E1FA37AE2948ULL,
		0xB9C9C994C99E289EULL,
		0xDD84CF2E38DCA9AFULL,
		0x23441ED654FAE971ULL,
		0x501DA37E5F7C2DC0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9D064F7E147691AULL,
		0xD28E09D6206F9D6BULL,
		0xA49C2F50798C170AULL,
		0x69CC7E1F8CCC8525ULL,
		0x8FB2B0F4C534CA50ULL,
		0xC4026D9F7ACAB039ULL,
		0xD6C551965B477C8CULL,
		0xF0C6EBC1D2596595ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A77618D4E5B310DULL,
		0x0F738B225749F2C4ULL,
		0x29311D3DF4DFC041ULL,
		0x833463DAAAE1A423ULL,
		0x2A1718A004695E4EULL,
		0x1982618EBE11F976ULL,
		0x4C7ECD3FF9B36CE5ULL,
		0x5F56B7BC8D22C82AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2C32B3F289A37665ULL,
		0xF274205F5D30CBC5ULL,
		0x4C48FAC46707E4CBULL,
		0x790C5D48B64D1723ULL,
		0x9EF82998E024D1C3ULL,
		0xDD5C9BC9BBF796D5ULL,
		0x1C27DD97F7F44CCDULL,
		0xD1C0EDBE91C718F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x221F02EDB0A51364ULL,
		0x1743124E346B777AULL,
		0xBD9C9BC0BE776071ULL,
		0x897839D60DCE423DULL,
		0xAA90037BEFA7F49EULL,
		0x64C08A848A4F8D99ULL,
		0x6ADD186B900E5369ULL,
		0xDCAF139BFD0A39E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A13B104D8FE6301ULL,
		0xDB310E1128C5544BULL,
		0x8EAC5F03A890845AULL,
		0xEF942372A87ED4E5ULL,
		0xF468261CF07CDD24ULL,
		0x789C114531A8093BULL,
		0xB14AC52C67E5F964ULL,
		0xF511DA2294BCDF10ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC0FCE16FDB7F4C00ULL,
		0x841E0CA74E452ED6ULL,
		0x7A974131FDAEC682ULL,
		0x233858ECFED08167ULL,
		0x6E415CA9321ED3DFULL,
		0x9DA7E45BBE5CC5EDULL,
		0xAB44927F38C4942FULL,
		0xFDE5A3FF965C0E2CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4568F47745DCB07ULL,
		0x28F3E97C19A47E02ULL,
		0x37737034D63C0190ULL,
		0xA168D2264C56975AULL,
		0xF88C2A78189896D6ULL,
		0x222B20966152A826ULL,
		0x212B25419AE67A71ULL,
		0xBD94E9FC714E5013ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CA65228672180F9ULL,
		0x5B2A232B34A0B0D4ULL,
		0x4323D0FD2772C4F2ULL,
		0x81CF86C6B279EA0DULL,
		0x75B5323119863D08ULL,
		0x7B7CC3C55D0A1DC6ULL,
		0x8A196D3D9DDE19BEULL,
		0x4050BA03250DBE19ULL
	}};
	sign = 0;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1D2900D0607BFD53ULL,
		0x7D2084C56CA4F4A7ULL,
		0x4F94535FDAF13E71ULL,
		0x199DC3A8A079A121ULL,
		0xF3EA91E06F95C9FAULL,
		0x0D8D4A01B9F3EF30ULL,
		0x3ABB70001AE8A086ULL,
		0x3BA704A0A8594C96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E0F4136C5AB28A2ULL,
		0x23F5C8FC8DAB454CULL,
		0x8EA7779C46928971ULL,
		0x58D5935622A240D1ULL,
		0xC7604757E31A4630ULL,
		0x0E234F049D5740A5ULL,
		0xB458FF37349650DEULL,
		0x5C44016F82F0EAA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F19BF999AD0D4B1ULL,
		0x592ABBC8DEF9AF5AULL,
		0xC0ECDBC3945EB500ULL,
		0xC0C830527DD7604FULL,
		0x2C8A4A888C7B83C9ULL,
		0xFF69FAFD1C9CAE8BULL,
		0x866270C8E6524FA7ULL,
		0xDF630331256861F0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3837EDCC24369AD0ULL,
		0x52EF685768145916ULL,
		0x67C47B57D802BA63ULL,
		0x40B1447024D2D6C8ULL,
		0xEDB67C2930C55192ULL,
		0xABB48E699157D095ULL,
		0x336D064D0C6AB5A2ULL,
		0x7B364A1D496E4DABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4256DC76638E106ULL,
		0xDDA2A9D0CA8FA142ULL,
		0x73507713D1B7D6ACULL,
		0x1E47B2F7EAA565E2ULL,
		0x0D1A18DA6CBEEF14ULL,
		0x15E1F48A2DB8976FULL,
		0x86CB75F5434A8E2CULL,
		0x8868D63636ED6AC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84128004BDFDB9CAULL,
		0x754CBE869D84B7D3ULL,
		0xF4740444064AE3B6ULL,
		0x226991783A2D70E5ULL,
		0xE09C634EC406627EULL,
		0x95D299DF639F3926ULL,
		0xACA19057C9202776ULL,
		0xF2CD73E71280E2E2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8ABF59DEEE3CF3D5ULL,
		0x8EEA39DFF6A07431ULL,
		0xF706CA4C258C996DULL,
		0x7AA3E3AD04FAD3EAULL,
		0xA61DBC85C8004F64ULL,
		0xEE2B01E7E9363B6DULL,
		0x9B9683DBB8DCD07EULL,
		0xC46A3A3E2FBECF06ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x826F1381FE814A2AULL,
		0x0D5442189E4AAD57ULL,
		0x057B2AA0ACB30B8DULL,
		0xD9C5D51D210B7AB4ULL,
		0x954F7C04EDD4924AULL,
		0x1F6AEBC357133668ULL,
		0x16583EAB09A3E600ULL,
		0x71EDAC70F59E2DDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0850465CEFBBA9ABULL,
		0x8195F7C75855C6DAULL,
		0xF18B9FAB78D98DE0ULL,
		0xA0DE0E8FE3EF5936ULL,
		0x10CE4080DA2BBD19ULL,
		0xCEC0162492230505ULL,
		0x853E4530AF38EA7EULL,
		0x527C8DCD3A20A128ULL
	}};
	sign = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A6860E3FC6F4EAAULL,
		0x6028972185ED9E41ULL,
		0x9F920F9445831B2AULL,
		0x05338643ECDFE151ULL,
		0x6EF313CB7FCE2DA4ULL,
		0x453FC3739D789023ULL,
		0x65922830A94787E6ULL,
		0xB3E80C45E2CC516CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1732D97CF0F8AB1DULL,
		0x0D610374D29A5B22ULL,
		0xF1EEA2E0797355F0ULL,
		0xA7CBE5A48EAB7E27ULL,
		0x54EEBB88E7746CE9ULL,
		0x5B11AEA46DFCCAF2ULL,
		0xD05882A27CC86BF9ULL,
		0xB055E7E6E4339395ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x033587670B76A38DULL,
		0x52C793ACB353431FULL,
		0xADA36CB3CC0FC53AULL,
		0x5D67A09F5E346329ULL,
		0x1A0458429859C0BAULL,
		0xEA2E14CF2F7BC531ULL,
		0x9539A58E2C7F1BECULL,
		0x0392245EFE98BDD6ULL
	}};
	sign = 0;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x15A2B859E5343E3BULL,
		0xA41303AF15F73C7EULL,
		0xC495D819790ED448ULL,
		0x334E11AFA342BF00ULL,
		0xF37B73E7DF4C1FC6ULL,
		0x271A2F360B4757F6ULL,
		0x7613D2E41A43A255ULL,
		0x1A5E7DCDE6743A3FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4A43AABDE89496ULL,
		0x89B3DC298064BBA2ULL,
		0x8106B37D7E4F745BULL,
		0xA9C12F078B796CC9ULL,
		0x3242277D559B6975ULL,
		0xC67672F2C091AB17ULL,
		0xB819B694275E07F7ULL,
		0xC8F05750AB412569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B5874AF274BA9A5ULL,
		0x1A5F2785959280DBULL,
		0x438F249BFABF5FEDULL,
		0x898CE2A817C95237ULL,
		0xC1394C6A89B0B650ULL,
		0x60A3BC434AB5ACDFULL,
		0xBDFA1C4FF2E59A5DULL,
		0x516E267D3B3314D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE3BB5013F46EBCEEULL,
		0xCDA1E2F467B7A620ULL,
		0x8C4EB5CDC548A366ULL,
		0x3A7E0821F6CA43D2ULL,
		0xA5ABB77ABF7DDABAULL,
		0x690BB2AC20F1C77EULL,
		0x0CD2ADBB95DD1643ULL,
		0xBBC171FBFFBD4AD2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FE3299317CB9E8FULL,
		0xD645C712DD3FE81EULL,
		0x8105C68629C01EB3ULL,
		0xDEC1D3D573C683E9ULL,
		0x94BCA265B993D22CULL,
		0xD968E7853A7514E2ULL,
		0xC8059409EAE61441ULL,
		0x9624FCE15995FB55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3D82680DCA31E5FULL,
		0xF75C1BE18A77BE02ULL,
		0x0B48EF479B8884B2ULL,
		0x5BBC344C8303BFE9ULL,
		0x10EF151505EA088DULL,
		0x8FA2CB26E67CB29CULL,
		0x44CD19B1AAF70201ULL,
		0x259C751AA6274F7CULL
	}};
	sign = 0;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x911A1CF132695207ULL,
		0xAD49584768AFC46FULL,
		0x5D12B32D8C415F86ULL,
		0xCE53DD8335C94E99ULL,
		0x19EB14A08E74AEF4ULL,
		0x4023A1731759E077ULL,
		0x8CB9327CD853B5B0ULL,
		0xD344CCE8EDD6D890ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35905923DDDF5E83ULL,
		0xE5164B0D752A091CULL,
		0x950E24EEE0C9AB81ULL,
		0x206147BA3BD3AC84ULL,
		0x8E442D666AAF18D7ULL,
		0xC4019639DF6B2681ULL,
		0x135C3EF8462B6616ULL,
		0x141C90E025395BD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B89C3CD5489F384ULL,
		0xC8330D39F385BB53ULL,
		0xC8048E3EAB77B404ULL,
		0xADF295C8F9F5A214ULL,
		0x8BA6E73A23C5961DULL,
		0x7C220B3937EEB9F5ULL,
		0x795CF38492284F99ULL,
		0xBF283C08C89D7CB7ULL
	}};
	sign = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B751E0FAC1C6E78ULL,
		0x57AEF980A4C15311ULL,
		0xFE10990204F6B17BULL,
		0x555AE7FE1E00F9E8ULL,
		0xAF9C28D0B6C3F127ULL,
		0x5A4702C273DAEC57ULL,
		0x6D42A731A75DC859ULL,
		0x655CB2BB0107555CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E6AAABF11A95B8ULL,
		0x1C5628650F9EE725ULL,
		0x1ADE7D9F9923F67BULL,
		0x264F26BC779D0541ULL,
		0x5DB8BA8F49AD13DBULL,
		0x1B8FE33A4218D355ULL,
		0xFB459C822A6E84D3ULL,
		0x87E0E60086A4F9D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB48E7363BB01D8C0ULL,
		0x3B58D11B95226BEBULL,
		0xE3321B626BD2BB00ULL,
		0x2F0BC141A663F4A7ULL,
		0x51E36E416D16DD4CULL,
		0x3EB71F8831C21902ULL,
		0x71FD0AAF7CEF4386ULL,
		0xDD7BCCBA7A625B85ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC605D5D691FD8EDAULL,
		0x33BF713EDF9E936AULL,
		0xE46BF75C7BA2EA43ULL,
		0xEAEF70B6FCB3BC82ULL,
		0x3EFCAAE0D0B8ED57ULL,
		0xB8F7E2FE6F2088ECULL,
		0x2DE163B26BC151B4ULL,
		0x2B3FFCB2316F9746ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A6924358CEEF8AULL,
		0xFC3FEDD2A6745209ULL,
		0x9EA040DE4DD96D42ULL,
		0x047D06AB79895711ULL,
		0xF560630283928485ULL,
		0x2364DDFE5E7EA49BULL,
		0xF39D2C2B1A408452ULL,
		0xC2BBE73C624D90A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D5F4393392E9F50ULL,
		0x377F836C392A4161ULL,
		0x45CBB67E2DC97D00ULL,
		0xE6726A0B832A6571ULL,
		0x499C47DE4D2668D2ULL,
		0x9593050010A1E450ULL,
		0x3A4437875180CD62ULL,
		0x68841575CF2206A3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3F6D4EC4E3D06522ULL,
		0x6DFFBE5318DBBBB1ULL,
		0x18D91651E9C44FCEULL,
		0x6F9342E0E8173F7BULL,
		0x518465D968413997ULL,
		0x67ACD0319C71ED32ULL,
		0xFFB8F3DE081A44A1ULL,
		0x32654C2F90A66507ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x767312E3001A24CEULL,
		0x20480712923827E2ULL,
		0xBC924E356F187759ULL,
		0xEC87B6FF2198F72BULL,
		0x8588D5D967403DDFULL,
		0xEBD5CF1E99F17536ULL,
		0xF6201E0C7A4657D9ULL,
		0x101E7F3F4A72F3D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8FA3BE1E3B64054ULL,
		0x4DB7B74086A393CEULL,
		0x5C46C81C7AABD875ULL,
		0x830B8BE1C67E484FULL,
		0xCBFB90000100FBB7ULL,
		0x7BD70113028077FBULL,
		0x0998D5D18DD3ECC7ULL,
		0x2246CCF046337132ULL
	}};
	sign = 0;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0E4281A8A2BDA4BDULL,
		0x1F3021BFF14913CCULL,
		0x1E8687E6A38EF782ULL,
		0x777B697C6FD45B67ULL,
		0x963B6884EC8BEFE7ULL,
		0x28B6FFAAE6B1C14EULL,
		0x1A5BFD2A74E67938ULL,
		0xBC924E8075227731ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DA21E88EF0F7E68ULL,
		0x8054BCA6A1604C7DULL,
		0x9DF0F153133E4355ULL,
		0xD478A69EC77F2C54ULL,
		0x6AF755DF16E468C8ULL,
		0x358CD10068FEBAB8ULL,
		0xD738DDCAF61AB740ULL,
		0xEA4D551148C3C1E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A0631FB3AE2655ULL,
		0x9EDB65194FE8C74FULL,
		0x809596939050B42CULL,
		0xA302C2DDA8552F12ULL,
		0x2B4412A5D5A7871EULL,
		0xF32A2EAA7DB30696ULL,
		0x43231F5F7ECBC1F7ULL,
		0xD244F96F2C5EB549ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x529BB1DAE2F6F95CULL,
		0xA13BD867D8964CEDULL,
		0x0677F15D7E1BC68AULL,
		0x85D9DBAD5D5BB0D5ULL,
		0xCFB36126D980CB1AULL,
		0x46EB61758EED8396ULL,
		0x40E080B5ADC5B647ULL,
		0xC18FB05943E06F74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFB9392AEFCA0C2ULL,
		0x16B19540FFDFEC1AULL,
		0xFFDA5A8031BBDC94ULL,
		0x6D01F860EE85EBFAULL,
		0xB29C2931ACF74F79ULL,
		0x78F40917A9AE1AC3ULL,
		0xB3B4776DCC8FECDDULL,
		0x6B628A61E484D253ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7A01E4833FA589AULL,
		0x8A8A4326D8B660D2ULL,
		0x069D96DD4C5FE9F6ULL,
		0x18D7E34C6ED5C4DAULL,
		0x1D1737F52C897BA1ULL,
		0xCDF7585DE53F68D3ULL,
		0x8D2C0947E135C969ULL,
		0x562D25F75F5B9D20ULL
	}};
	sign = 0;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFAD9A5337FCC1C33ULL,
		0xFB912940F3D2E96CULL,
		0x64E20DEB80CE5DE9ULL,
		0x7B59F704081E9B64ULL,
		0x9DC857572925671BULL,
		0x34C9EBBC606981C4ULL,
		0xF0B44502B6911F55ULL,
		0xE955894DDF09F573ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF427B2352D086993ULL,
		0x48995EBA3E420E66ULL,
		0xA54DF9E84B6F2845ULL,
		0x1D1778735A80A22EULL,
		0xE90E05CB8122459DULL,
		0x6840A2892C76513CULL,
		0xB01D216C0548CD58ULL,
		0xF837ABEEBC829AE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06B1F2FE52C3B2A0ULL,
		0xB2F7CA86B590DB06ULL,
		0xBF941403355F35A4ULL,
		0x5E427E90AD9DF935ULL,
		0xB4BA518BA803217EULL,
		0xCC89493333F33087ULL,
		0x40972396B14851FCULL,
		0xF11DDD5F22875A90ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9D37551FFE83003ULL,
		0x26EE05DBEEBE8B4CULL,
		0x9B956F3B1C483C4FULL,
		0x2CC2AAFD59407F20ULL,
		0x356F19BAEAAEDB28ULL,
		0x5CFA36FEDB20DD58ULL,
		0x90CEFD15D3958574ULL,
		0x840650B065099070ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xED668E30E9E718C5ULL,
		0x842B5607EA3CC158ULL,
		0x965D90A9DD2F4D0BULL,
		0x0D11DA8DBEDD6E79ULL,
		0x22B54D84DAC8BA7AULL,
		0x9C5CB3887BD9B837ULL,
		0x8E04C6805A5CA5C0ULL,
		0x9D8B01735800166AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC6CE7211601173EULL,
		0xA2C2AFD40481C9F3ULL,
		0x0537DE913F18EF43ULL,
		0x1FB0D06F9A6310A7ULL,
		0x12B9CC360FE620AEULL,
		0xC09D83765F472521ULL,
		0x02CA36957938DFB3ULL,
		0xE67B4F3D0D097A06ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB3B1C97C22E2C735ULL,
		0xDB22A18A4955F8C8ULL,
		0x91F81D6FD8C6E0F3ULL,
		0x9BC2648A1DD1B7ECULL,
		0x4F75727FFA7FDB7CULL,
		0x81E7DC116DF36286ULL,
		0x83783BE1D9AAC9E6ULL,
		0xB6CC8FB0E63AD6FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x322584C16202C431ULL,
		0xB4C8B98CFBEB6499ULL,
		0xB54AD92DCB688E5DULL,
		0xD9480BB1568B69B4ULL,
		0x30A725A665D8E1D4ULL,
		0x9A5AF698BEBC8A6BULL,
		0x7E3E98B965AD410EULL,
		0xA85A3F6AF95142A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x818C44BAC0E00304ULL,
		0x2659E7FD4D6A942FULL,
		0xDCAD44420D5E5296ULL,
		0xC27A58D8C7464E37ULL,
		0x1ECE4CD994A6F9A7ULL,
		0xE78CE578AF36D81BULL,
		0x0539A32873FD88D7ULL,
		0x0E725045ECE99455ULL
	}};
	sign = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x762560D8AEFAE45EULL,
		0x794387E0837352D1ULL,
		0xCD4CF49E647C22A0ULL,
		0x2C2A1055C44A37A5ULL,
		0x8F90BEFA0691887FULL,
		0x6D64AD7A1311A3E0ULL,
		0x8DDF6A9BDA6E735AULL,
		0xEB2740D252885498ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52194052E570A135ULL,
		0x432CF9D71FB7B8B6ULL,
		0x6D2B223397FA6668ULL,
		0xFE0D1C7A77A0767DULL,
		0x39F86A48E1BB329AULL,
		0x651CC1C85D039AB9ULL,
		0x7592FD58E6A4A280ULL,
		0x25F9826679783676ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x240C2085C98A4329ULL,
		0x36168E0963BB9A1BULL,
		0x6021D26ACC81BC38ULL,
		0x2E1CF3DB4CA9C128ULL,
		0x559854B124D655E4ULL,
		0x0847EBB1B60E0927ULL,
		0x184C6D42F3C9D0DAULL,
		0xC52DBE6BD9101E22ULL
	}};
	sign = 0;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF70CD3BD06D8354DULL,
		0x7A45A8B3E567E901ULL,
		0xFF14415059F38F8CULL,
		0x677645D0085DDC96ULL,
		0x2E25BC596A920EAFULL,
		0xE5AAD31CD6E1E4C6ULL,
		0xCC97C2A43A68AB38ULL,
		0xE40A668218BA7DA7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5725E7882D8392D3ULL,
		0xEEB9ED4EFDD460B6ULL,
		0x500F0DFE21A2E5A9ULL,
		0x6CEEB3D114864BFCULL,
		0xD5EAFDFBD037DF6FULL,
		0x7749A373112EC472ULL,
		0x1387BA2D0373DEA4ULL,
		0xA025B9249D78A000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FE6EC34D954A27AULL,
		0x8B8BBB64E793884BULL,
		0xAF0533523850A9E2ULL,
		0xFA8791FEF3D7909AULL,
		0x583ABE5D9A5A2F3FULL,
		0x6E612FA9C5B32053ULL,
		0xB910087736F4CC94ULL,
		0x43E4AD5D7B41DDA7ULL
	}};
	sign = 0;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9D7E85E755B21969ULL,
		0xF369CC3C19CE1EB1ULL,
		0x50D5B869ADCE42F9ULL,
		0x383BC9A19550FD58ULL,
		0xD87B210938FB83F5ULL,
		0xBC30AEEE2F1281A0ULL,
		0x6BD52A563210DA5DULL,
		0x1D213D462B59E8A9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2337D9F95E958DE6ULL,
		0x99E1089F314D865FULL,
		0xC8EF320F245EC0D5ULL,
		0x066E4264340D05BCULL,
		0xC326F95647CFC94FULL,
		0x389DC28709163743ULL,
		0xD530FEC625238EE5ULL,
		0xC95B56765DB00321ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A46ABEDF71C8B83ULL,
		0x5988C39CE8809852ULL,
		0x87E6865A896F8224ULL,
		0x31CD873D6143F79BULL,
		0x155427B2F12BBAA6ULL,
		0x8392EC6725FC4A5DULL,
		0x96A42B900CED4B78ULL,
		0x53C5E6CFCDA9E587ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD56C43BC716ABCA2ULL,
		0x3CF9C560C019B1CBULL,
		0x4A37CC2B131CF228ULL,
		0x71275F3E3B22466CULL,
		0xA3961863DFC75357ULL,
		0xE357A69A11ACDA6AULL,
		0x1F075970F2E8DA1EULL,
		0x178D307ACD9F28B9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C064EA7B1355521ULL,
		0xCD2E49CBFF3AC124ULL,
		0xC1F9A83A631F5F21ULL,
		0x299D347895759520ULL,
		0x76D5A453ADFE81D5ULL,
		0x65FA35B5922E6AB2ULL,
		0x49E67BCC50FAB136ULL,
		0xCB02D77FFAC21310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA965F514C0356781ULL,
		0x6FCB7B94C0DEF0A7ULL,
		0x883E23F0AFFD9306ULL,
		0x478A2AC5A5ACB14BULL,
		0x2CC0741031C8D182ULL,
		0x7D5D70E47F7E6FB8ULL,
		0xD520DDA4A1EE28E8ULL,
		0x4C8A58FAD2DD15A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBD1CC0C0C0ECFB5BULL,
		0x6410F0422134EC1DULL,
		0x0900A43FEF55B3EDULL,
		0x6E01C76B6F1A6C5CULL,
		0x14C40DA2286FF56CULL,
		0x056BA725585CBB82ULL,
		0x1654AA6BE38FBE83ULL,
		0x2505B856AC1FAA85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8418F5F0B1C3675BULL,
		0x0853F5E39F594D01ULL,
		0x669E6447E91E6CEFULL,
		0x965F068F6E06E43AULL,
		0x915FF436205ECAA1ULL,
		0xEDECD5F9DD1C6109ULL,
		0xE67AF0FFBAB887F1ULL,
		0xDF2F0725780913FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3903CAD00F299400ULL,
		0x5BBCFA5E81DB9F1CULL,
		0xA2623FF8063746FEULL,
		0xD7A2C0DC01138821ULL,
		0x8364196C08112ACAULL,
		0x177ED12B7B405A78ULL,
		0x2FD9B96C28D73691ULL,
		0x45D6B13134169685ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x228607F17CAFAE5AULL,
		0xBBB1AD7628ED5F98ULL,
		0xE761914777920CD2ULL,
		0x682A23ACB5F49B6CULL,
		0x264FAF1B99C38060ULL,
		0x61845E962B702C57ULL,
		0xA6E9562F6D6B4EEBULL,
		0xFD03927F920AC6B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD02E062D4D73D5ULL,
		0x8E1C7FCA444D329DULL,
		0xF8450271C5E59CC3ULL,
		0x3537911CB96EE678ULL,
		0xA1F6A3D35917D1D9ULL,
		0x9569DECE7B4D6111ULL,
		0x9957062585E311D3ULL,
		0xE14AD74192FC7B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45B5D9EB4F623A85ULL,
		0x2D952DABE4A02CFAULL,
		0xEF1C8ED5B1AC700FULL,
		0x32F2928FFC85B4F3ULL,
		0x84590B4840ABAE87ULL,
		0xCC1A7FC7B022CB45ULL,
		0x0D925009E7883D17ULL,
		0x1BB8BB3DFF0E4BB3ULL
	}};
	sign = 0;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x46CF8069A6E88815ULL,
		0xCFA91D47A5CC6C3EULL,
		0x47452429FB62BF6BULL,
		0x4CE2466E1F7FC6E7ULL,
		0x8E37FD55E1CA69ADULL,
		0x299A4833A376EEDEULL,
		0x11C9B2F104D1FB75ULL,
		0x8D5D793F747D4728ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C37BC0B6A1F76FULL,
		0xF0A5A91F94B56615ULL,
		0xA3132ECD2737BB03ULL,
		0x60EC1647B23227F0ULL,
		0xC19804E0C7244FB7ULL,
		0x4203720F68C683A4ULL,
		0x25F3D68C118132F0ULL,
		0xCF1264AD8DECBFE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC10C04A8F04690A6ULL,
		0xDF03742811170628ULL,
		0xA431F55CD42B0467ULL,
		0xEBF630266D4D9EF6ULL,
		0xCC9FF8751AA619F5ULL,
		0xE796D6243AB06B39ULL,
		0xEBD5DC64F350C884ULL,
		0xBE4B1491E6908740ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7DF737ADFB52B1A6ULL,
		0x62034F7006F14526ULL,
		0x698C39DCACF06B5BULL,
		0x517EC3F60D0FE70CULL,
		0xAEED009313BBCF01ULL,
		0x51F0779311AE9831ULL,
		0xB9728D64023C3806ULL,
		0xE37A5CCE49E25C9EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE918E961C7E77769ULL,
		0xB5ECF5FE7B494B9CULL,
		0x272B4222A2C1A115ULL,
		0x7FC8708F1ED399A6ULL,
		0x08294F617D1A4A8DULL,
		0x59D7879A8C2FE4ECULL,
		0x1912EA926BBC3373ULL,
		0x2CA0B350891A321FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94DE4E4C336B3A3DULL,
		0xAC1659718BA7F989ULL,
		0x4260F7BA0A2ECA45ULL,
		0xD1B65366EE3C4D66ULL,
		0xA6C3B13196A18473ULL,
		0xF818EFF8857EB345ULL,
		0xA05FA2D196800492ULL,
		0xB6D9A97DC0C82A7FULL
	}};
	sign = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B9E600DF98D9C07ULL,
		0xF25511F10ED7D4F2ULL,
		0x7C16F592883587FEULL,
		0x73CB37D1245F4C9EULL,
		0x70253E479FA502E5ULL,
		0x3B19E52171435124ULL,
		0x84E9F4010E1CC20DULL,
		0x61BFE3F685DE7238ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12045600E9F8F927ULL,
		0x86EEFDCD927633C1ULL,
		0x00E9601136C79327ULL,
		0xA88C23E1CE91B6FAULL,
		0x30EC81B531A30B00ULL,
		0x2308F5CB1340560BULL,
		0xC16C9933AFC68989ULL,
		0x450B3E8559B8C1E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x699A0A0D0F94A2E0ULL,
		0x6B6614237C61A131ULL,
		0x7B2D9581516DF4D7ULL,
		0xCB3F13EF55CD95A4ULL,
		0x3F38BC926E01F7E4ULL,
		0x1810EF565E02FB19ULL,
		0xC37D5ACD5E563884ULL,
		0x1CB4A5712C25B055ULL
	}};
	sign = 0;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBA0CA8C00A3CCCDFULL,
		0xE3A024407757429AULL,
		0x63A257A8FB5898F0ULL,
		0xD8C5C572DFD43868ULL,
		0x926E5DCEAF5FCB3DULL,
		0xBBDEAC2CF1C9A3AAULL,
		0x5E94565DD329CB14ULL,
		0xDD3D296541C62F6CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD59E8CF72220445CULL,
		0x16830EB0606B7A93ULL,
		0x89BA8F52AFC5842AULL,
		0x98C16C00C22B30B2ULL,
		0x890F9DDD630306B5ULL,
		0x4AB3CBC36630B784ULL,
		0x705A2B870D849C79ULL,
		0x28EEE821B9A8F8C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE46E1BC8E81C8883ULL,
		0xCD1D159016EBC806ULL,
		0xD9E7C8564B9314C6ULL,
		0x400459721DA907B5ULL,
		0x095EBFF14C5CC488ULL,
		0x712AE0698B98EC26ULL,
		0xEE3A2AD6C5A52E9BULL,
		0xB44E4143881D36A5ULL
	}};
	sign = 0;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D818CC5B6849C97ULL,
		0x517D7B4F87B66905ULL,
		0x085C8856D4B7A169ULL,
		0xE7F0F47E95B02440ULL,
		0x83D00DE6EA09F701ULL,
		0xD19DAEF45851BD05ULL,
		0x7BC7AF210FBCE06DULL,
		0x79EB52D0AFE85448ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFEC074EB0FAB65DULL,
		0x50ED23D5EF2CD298ULL,
		0x6231CA1ABFA8D571ULL,
		0xE580953B1F7F7ADDULL,
		0x1C56D8B142F03515ULL,
		0xE34E3AAB10E74B12ULL,
		0x69C3A9B25EC5727EULL,
		0xF225853279E9B7A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D9585770589E63AULL,
		0x009057799889966CULL,
		0xA62ABE3C150ECBF8ULL,
		0x02705F437630A962ULL,
		0x67793535A719C1ECULL,
		0xEE4F7449476A71F3ULL,
		0x1204056EB0F76DEEULL,
		0x87C5CD9E35FE9CA4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E9A21ADF3F09BE3ULL,
		0x6E5380A42F19C75DULL,
		0x96E6D998C73297DDULL,
		0x148711277DD5EC2BULL,
		0x7F73942B864D9D57ULL,
		0xDA48C2625BA2A096ULL,
		0xCCBD3231F8AED726ULL,
		0x715B1000342CB847ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x09EAC3E12D0FC91DULL,
		0x5EC6C070DF30C82EULL,
		0x3AF4D617D9D64509ULL,
		0xE7A084CBFD7699FEULL,
		0xB7E4771BA892EED6ULL,
		0x49B9419F62A8855BULL,
		0xD38D782A4CD3706CULL,
		0xF0E2BC1880C6370CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44AF5DCCC6E0D2C6ULL,
		0x0F8CC0334FE8FF2FULL,
		0x5BF20380ED5C52D4ULL,
		0x2CE68C5B805F522DULL,
		0xC78F1D0FDDBAAE80ULL,
		0x908F80C2F8FA1B3AULL,
		0xF92FBA07ABDB66BAULL,
		0x807853E7B366813AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x02999AF3127205BDULL,
		0x584DB6F2E58A4234ULL,
		0x4158E02600737AD8ULL,
		0xDAE71E1E6FD2B370ULL,
		0x7CAC9C13862852ECULL,
		0x535EE5E3C571AE56ULL,
		0x37457AA5C8917145ULL,
		0xE99EB3C45B784FD5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34489E1E8115733ULL,
		0xD94C3C40FCFDADE1ULL,
		0xB3527244211EE7D6ULL,
		0x919F9921C67F3CDDULL,
		0xEADFF20617461EDEULL,
		0x41EC2345319E6697ULL,
		0xEAD238F119FBDC7CULL,
		0x541A15316ACCF210ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F5511112A60AE8AULL,
		0x7F017AB1E88C9452ULL,
		0x8E066DE1DF549301ULL,
		0x494784FCA9537692ULL,
		0x91CCAA0D6EE2340EULL,
		0x1172C29E93D347BEULL,
		0x4C7341B4AE9594C9ULL,
		0x95849E92F0AB5DC4ULL
	}};
	sign = 0;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4376C2E05DE477BCULL,
		0x891331F1D5C0264DULL,
		0xA246B5A5F9CAC193ULL,
		0xC2840E2BAEAAEBDDULL,
		0x377E012CB5A3233DULL,
		0x60B23812BC39790BULL,
		0xBEF9D4AC5557A7A2ULL,
		0x76C169D3509C0C72ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DBF1422E3A7842ULL,
		0x46A16939FD942BD2ULL,
		0x4C7B8F1913F6EFBEULL,
		0x01E1B7FCCA689F67ULL,
		0x3E71E8771B6A8146ULL,
		0x07D8551BFE74218CULL,
		0x524CE41153ED9F2CULL,
		0xF8ABFF974A5CFDC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x719AD19E2FA9FF7AULL,
		0x4271C8B7D82BFA7AULL,
		0x55CB268CE5D3D1D5ULL,
		0xC0A2562EE4424C76ULL,
		0xF90C18B59A38A1F7ULL,
		0x58D9E2F6BDC5577EULL,
		0x6CACF09B016A0876ULL,
		0x7E156A3C063F0EAFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xADF9EF54D882C6E6ULL,
		0xFE3E563B2C341BE4ULL,
		0x221E42FB27A5A0B8ULL,
		0x06097222EB9FDE78ULL,
		0x9430ED2FE6146CA7ULL,
		0x470AAE89EA539A41ULL,
		0x553F89F113538A77ULL,
		0xAD93042D5EFED085ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3A6510955602E35ULL,
		0x68824B4052218A28ULL,
		0xDBCF6774913D53C2ULL,
		0x181D748010B94E7AULL,
		0xACC971D1247B71BAULL,
		0x4AE95531C04A646CULL,
		0x2638C71543141839ULL,
		0xFCC3FCB9D7A0289CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA539E4B832298B1ULL,
		0x95BC0AFADA1291BBULL,
		0x464EDB8696684CF6ULL,
		0xEDEBFDA2DAE68FFDULL,
		0xE7677B5EC198FAECULL,
		0xFC2159582A0935D4ULL,
		0x2F06C2DBD03F723DULL,
		0xB0CF0773875EA7E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93AB2FE1227192BAULL,
		0xEE610BF8EACCC052ULL,
		0xCC8A2A60340F313EULL,
		0x59DE2C35F8793ABAULL,
		0xA176E91EA3B73D4BULL,
		0x7B734F33F367410BULL,
		0x976801CCBA1DAC82ULL,
		0xBA6802E98ECACA5DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3F44A4CE016905ULL,
		0xDCD98CA01415FB81ULL,
		0x28845B3506BF9B4EULL,
		0x52EE7D59D65C004CULL,
		0xD5DE497F964F0914ULL,
		0x152E8138E4974C09ULL,
		0x360CD4D769020B81ULL,
		0x7D10508B812311DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x296BEB3C547029B5ULL,
		0x11877F58D6B6C4D1ULL,
		0xA405CF2B2D4F95F0ULL,
		0x06EFAEDC221D3A6EULL,
		0xCB989F9F0D683437ULL,
		0x6644CDFB0ECFF501ULL,
		0x615B2CF5511BA101ULL,
		0x3D57B25E0DA7B881ULL
	}};
	sign = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2259BAE5C8B214D2ULL,
		0x25BAC68AEDD5308DULL,
		0x66E64F5219A33A59ULL,
		0x9625F5C4AF108EFCULL,
		0xAF24C149350EF001ULL,
		0x24DF7BA2EE685E85ULL,
		0x4D6A70F269962EF0ULL,
		0x47FF9FC1777C0E51ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDA302B902FBCDC4ULL,
		0xAB36F93DAA530325ULL,
		0x8A96745D15947715ULL,
		0xB79EB55C60FE460FULL,
		0xA2D744AB0D5FBF39ULL,
		0xEE67A0D4DDE4AF8EULL,
		0x8FA060F84816F8CCULL,
		0x1B3CBCFFF8A2AF82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54B6B82CC5B6470EULL,
		0x7A83CD4D43822D67ULL,
		0xDC4FDAF5040EC343ULL,
		0xDE8740684E1248ECULL,
		0x0C4D7C9E27AF30C7ULL,
		0x3677DACE1083AEF7ULL,
		0xBDCA0FFA217F3623ULL,
		0x2CC2E2C17ED95ECEULL
	}};
	sign = 0;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E74B84A55717D1AULL,
		0xA253F4244C857275ULL,
		0x8F38C5A8F5E48308ULL,
		0x3293FF4A1FBE4FADULL,
		0xF99EEF520561F4DDULL,
		0x6ED7B0B3DBDEA379ULL,
		0x74D8BC063284DFC6ULL,
		0x5E6EAFA5944E2DB1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F7F1CDC75A7646BULL,
		0xB65E0A53F2166E1FULL,
		0xE29AB94DB941CF8AULL,
		0xA127E2D3DD9AD467ULL,
		0xD9E15AB2CDB9A681ULL,
		0xD2368DAC2945C6EAULL,
		0xFF9A2D9D72C2E607ULL,
		0x268BD0334EF1655CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEF59B6DDFCA18AFULL,
		0xEBF5E9D05A6F0455ULL,
		0xAC9E0C5B3CA2B37DULL,
		0x916C1C7642237B45ULL,
		0x1FBD949F37A84E5BULL,
		0x9CA12307B298DC8FULL,
		0x753E8E68BFC1F9BEULL,
		0x37E2DF72455CC854ULL
	}};
	sign = 0;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD03F60B36FC08AC6ULL,
		0xB36AF3ACB72E9BFFULL,
		0x0A161F79074E718EULL,
		0x1ADB038AB856DCC8ULL,
		0xBCA6CA1E4F2BF076ULL,
		0x981EB6A8A273A65CULL,
		0x3CEAA1F1BBC6628FULL,
		0x994CE9D8668E8F52ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F9166A601FE42E0ULL,
		0x1EA49E16F62A2AFDULL,
		0x98C4259F80974C3FULL,
		0xEBAE36EFA064172CULL,
		0xC7FE8268A62E2970ULL,
		0x28C4D005E6E162AFULL,
		0x661A8E8D3890E1D0ULL,
		0x00DBD43FC9A71059ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40ADFA0D6DC247E6ULL,
		0x94C65595C1047102ULL,
		0x7151F9D986B7254FULL,
		0x2F2CCC9B17F2C59BULL,
		0xF4A847B5A8FDC705ULL,
		0x6F59E6A2BB9243ACULL,
		0xD6D01364833580BFULL,
		0x987115989CE77EF8ULL
	}};
	sign = 0;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4C66449CBD2A62EEULL,
		0xBA857003ABDBCD09ULL,
		0x6F8F0E77D9D9EBDCULL,
		0xD74ACE8E978BC332ULL,
		0x790A406D9E77D7A3ULL,
		0x2AFDECABACA4BF40ULL,
		0x9020ECB224568436ULL,
		0xDCF9BEE6446162DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD540F41D3C59B28AULL,
		0x334831FAC836CE3FULL,
		0xA6AA60A601645686ULL,
		0x6687B354E1864A1DULL,
		0x65D68EA5AA6AAA4CULL,
		0x7F56A3333A55C002ULL,
		0xCB86748C6B0CDACDULL,
		0x8DEE584429B9A09DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7725507F80D0B064ULL,
		0x873D3E08E3A4FEC9ULL,
		0xC8E4ADD1D8759556ULL,
		0x70C31B39B6057914ULL,
		0x1333B1C7F40D2D57ULL,
		0xABA74978724EFF3EULL,
		0xC49A7825B949A968ULL,
		0x4F0B66A21AA7C23DULL
	}};
	sign = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x84E962F4F76C75BDULL,
		0xE2F41C33B224C879ULL,
		0x7BB8A810D17D069EULL,
		0xD2A873310039DE07ULL,
		0x06328E0E4E70647AULL,
		0x23C32371CBC6B4B5ULL,
		0xDC8F7D32140274EDULL,
		0xE9C85B714268B128ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x540C2433EC977FC1ULL,
		0x17CA138FE81C48BCULL,
		0x29A8F1DDDCF11D4BULL,
		0x1BF812318C06819FULL,
		0x74F2D0B790EAC29CULL,
		0x6E0EA64E9A5C2CE1ULL,
		0xE00C8EDFF7AA6281ULL,
		0x0C7DDD9810771F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30DD3EC10AD4F5FCULL,
		0xCB2A08A3CA087FBDULL,
		0x520FB632F48BE953ULL,
		0xB6B060FF74335C68ULL,
		0x913FBD56BD85A1DEULL,
		0xB5B47D23316A87D3ULL,
		0xFC82EE521C58126BULL,
		0xDD4A7DD931F191F7ULL
	}};
	sign = 0;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8EC4B3C41461E9B3ULL,
		0x535617FA3F60C85CULL,
		0x1357F35B02C6C06CULL,
		0x43DBC1DFF304ECC9ULL,
		0xCF334E469F7109A0ULL,
		0x6D13BD5A76AFB91BULL,
		0x67157A76CA6014DDULL,
		0xF81997E749B6D9B9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x247C278D9114C5A7ULL,
		0x02F2BADDC26EDE21ULL,
		0xDEB2C40ADCEB9DF4ULL,
		0xE782D848D546CE26ULL,
		0x320CCFAC012FBF87ULL,
		0x74671A91C2CAAF0DULL,
		0x928BBC23EED4248EULL,
		0xA62CDC9670A5126CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A488C36834D240CULL,
		0x50635D1C7CF1EA3BULL,
		0x34A52F5025DB2278ULL,
		0x5C58E9971DBE1EA2ULL,
		0x9D267E9A9E414A18ULL,
		0xF8ACA2C8B3E50A0EULL,
		0xD489BE52DB8BF04EULL,
		0x51ECBB50D911C74CULL
	}};
	sign = 0;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C25DE7BC0165B04ULL,
		0x340B560CB35061EEULL,
		0xD93A90795AC645E9ULL,
		0x78F03616A93CB359ULL,
		0x53334B6BB059C112ULL,
		0x06A79E99C192C476ULL,
		0x6C3188F1EBACFEEDULL,
		0x0534EF34EDD105C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x51CF6C3A5430C6E0ULL,
		0x01D638472C63D7C4ULL,
		0x8A2FD15D4FEF8B03ULL,
		0x36B50C9F2718BB62ULL,
		0x4EA869311829BB94ULL,
		0x373A7B1BC62173C4ULL,
		0xB9AFA328A67423C4ULL,
		0x7A143FBB64C443CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA5672416BE59424ULL,
		0x32351DC586EC8A29ULL,
		0x4F0ABF1C0AD6BAE6ULL,
		0x423B29778223F7F7ULL,
		0x048AE23A9830057EULL,
		0xCF6D237DFB7150B2ULL,
		0xB281E5C94538DB28ULL,
		0x8B20AF79890CC1F3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3874787C79795910ULL,
		0x6E433254D32D6644ULL,
		0x3152E2D29F8E48B2ULL,
		0x7C118BA97A2B6BA1ULL,
		0x3589A306C7401701ULL,
		0xDC440D9EE23AEE66ULL,
		0xC62CFF0DF768AEC0ULL,
		0x65D210512C8346AAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D249928728A128ULL,
		0xA0772D7B7A1B60D2ULL,
		0x88A5819C72C996D5ULL,
		0x5FD332B66EF3EBB0ULL,
		0x60D7558F829276D5ULL,
		0xB1384B1022D67EF1ULL,
		0xC2A4DD56B63DBEA7ULL,
		0x08A2F0FDAB0FD98CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47A22EE9F250B7E8ULL,
		0xCDCC04D959120571ULL,
		0xA8AD61362CC4B1DCULL,
		0x1C3E58F30B377FF0ULL,
		0xD4B24D7744ADA02CULL,
		0x2B0BC28EBF646F74ULL,
		0x038821B7412AF019ULL,
		0x5D2F1F5381736D1EULL
	}};
	sign = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA279199F3B76CF7FULL,
		0x99C998295357DD97ULL,
		0x6EC79CB1DF99DAC1ULL,
		0xF606CF2B2F67D7ACULL,
		0x296178BD0C3F3519ULL,
		0x7C4ACBF864B0684AULL,
		0x676A82A319961EE9ULL,
		0x53F0B62A6D26C4F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DD71C8F318A2BB3ULL,
		0xECA307310A7DCAA5ULL,
		0x75D830A4B288C22EULL,
		0x1593E6FFF9B86CF9ULL,
		0x7BD53B387B256C66ULL,
		0x312FAA759898D207ULL,
		0xBEBD9F8F75A28B28ULL,
		0x0298B29B0440036EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14A1FD1009ECA3CCULL,
		0xAD2690F848DA12F2ULL,
		0xF8EF6C0D2D111892ULL,
		0xE072E82B35AF6AB2ULL,
		0xAD8C3D849119C8B3ULL,
		0x4B1B2182CC179642ULL,
		0xA8ACE313A3F393C1ULL,
		0x5158038F68E6C182ULL
	}};
	sign = 0;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC6AEB70CA6B47BCFULL,
		0x5AF3E89EFC8EF9D4ULL,
		0xD5E41AD57C1FCD8BULL,
		0x77D73E2FA1470D4FULL,
		0x4B0DFA3683A9C408ULL,
		0x3AADA8CB55F75DC2ULL,
		0xE4F520EB9B169A83ULL,
		0x7B6C9EFB3BCA585DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A61D38F75590FF0ULL,
		0xA61CB248DC24B3DDULL,
		0x65BE77CD8E07803FULL,
		0x7510D9382A9F397AULL,
		0x303F70FB5659CD54ULL,
		0x19FB1EAC1971CB7BULL,
		0xA60F2706FDCD822CULL,
		0x9604E39F2570665CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4CE37D315B6BDFULL,
		0xB4D73656206A45F7ULL,
		0x7025A307EE184D4BULL,
		0x02C664F776A7D3D5ULL,
		0x1ACE893B2D4FF6B4ULL,
		0x20B28A1F3C859247ULL,
		0x3EE5F9E49D491857ULL,
		0xE567BB5C1659F201ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF7E9F25649C2D16AULL,
		0xC2FF40B51FEC54E9ULL,
		0xA4DA433E22E82932ULL,
		0x93830EBC95F461E1ULL,
		0xC767DE83ADA5D077ULL,
		0xB414B73A3FB24437ULL,
		0x53DA3E98AEEA3324ULL,
		0xA419BF1C0A6B6233ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x547DE01196FA9825ULL,
		0xE0689C75BDCBA41BULL,
		0xA6C7C32D5BE38BAAULL,
		0x5AFD291ED7F8FE0BULL,
		0x5828EB920CD697ADULL,
		0x88C16BAB0399176DULL,
		0x7FD01AD93A545190ULL,
		0xDB5B71903CE8509DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA36C1244B2C83945ULL,
		0xE296A43F6220B0CEULL,
		0xFE128010C7049D87ULL,
		0x3885E59DBDFB63D5ULL,
		0x6F3EF2F1A0CF38CAULL,
		0x2B534B8F3C192CCAULL,
		0xD40A23BF7495E194ULL,
		0xC8BE4D8BCD831195ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07D38569F3F4AF8AULL,
		0xC10FF5B7470B07FFULL,
		0x68A33551BFD6B1CFULL,
		0x82086866C5888A5BULL,
		0xABFF4EC587E64972ULL,
		0x4291168C281D09E2ULL,
		0xFA4851F38D7CEF36ULL,
		0xE9E583A689229CBCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AEA216B26AA444EULL,
		0x59C9DCAF22E1A609ULL,
		0x321C49F19A47B263ULL,
		0x3B2AF73BAD62153DULL,
		0x1D385E6AD5FB4E6EULL,
		0xCB3301669DB84ADBULL,
		0xB47A7F0F93E26F2EULL,
		0xEE7A71190FD0D2FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CE963FECD4A6B3CULL,
		0x67461908242961F5ULL,
		0x3686EB60258EFF6CULL,
		0x46DD712B1826751EULL,
		0x8EC6F05AB1EAFB04ULL,
		0x775E15258A64BF07ULL,
		0x45CDD2E3F99A8007ULL,
		0xFB6B128D7951C9C0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B56B61F2A3E9553ULL,
		0xF54AEE7B07F5ACC1ULL,
		0xB34D7C78C7F0395CULL,
		0x319F170E3D627816ULL,
		0xD94F0EBFD2ED313BULL,
		0x26A1BFA16E7DD472ULL,
		0x81ED5B44DAAF4795ULL,
		0x69DF9A5302EAB5CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE341F82ACBFCF7E4ULL,
		0xCE465DA999F3A9C9ULL,
		0x0AABAE9E56A099D3ULL,
		0xDB8454DA49F0217CULL,
		0xBD2BBA988F954CE0ULL,
		0xCEFC061C0C3E6243ULL,
		0xA52119700BFD4865ULL,
		0x70EB106B632C4D9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB814BDF45E419D6FULL,
		0x270490D16E0202F7ULL,
		0xA8A1CDDA714F9F89ULL,
		0x561AC233F372569AULL,
		0x1C2354274357E45AULL,
		0x57A5B985623F722FULL,
		0xDCCC41D4CEB1FF2FULL,
		0xF8F489E79FBE682EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x25BF636742DAB0FFULL,
		0xF0B2D400707CFDC3ULL,
		0xD1C9F55448C00595ULL,
		0x64D0F8163D7DFD49ULL,
		0x6891017F626A04E2ULL,
		0xAD221889E14A850FULL,
		0x24D06A39BF25FAAFULL,
		0xDF83E6FD64BB26DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A01BAAE365F0FFULL,
		0xF1C234BE85943C94ULL,
		0xC1BAA524B54CF533ULL,
		0xE72ED27BB9F3C546ULL,
		0x8E99F583B0898DFDULL,
		0x4A286B1CB2AA3158ULL,
		0x522CD0D716DFD3C4ULL,
		0x9F6C8D3AE1BA1527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401F47BC5F74C000ULL,
		0xFEF09F41EAE8C12EULL,
		0x100F502F93731061ULL,
		0x7DA2259A838A3803ULL,
		0xD9F70BFBB1E076E4ULL,
		0x62F9AD6D2EA053B6ULL,
		0xD2A39962A84626EBULL,
		0x401759C2830111B2ULL
	}};
	sign = 0;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA734735B25E34468ULL,
		0x5264FF133013CF4DULL,
		0x7448B19CF7BE520CULL,
		0x6F49FB5E9AF56D94ULL,
		0xAB0D45F471652144ULL,
		0xE6CC290CE9AD66B3ULL,
		0xC40E93CDE3B03FE9ULL,
		0x75EDB82EA08757FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x85CE5B3D162E2781ULL,
		0x949207C7215580E8ULL,
		0x5A1B11B4899CD4D8ULL,
		0x0F63B3946DFD959AULL,
		0x00C7B6821ADB3D38ULL,
		0xC56E72EC62F37B86ULL,
		0x58E96BD8E6CCB106ULL,
		0xFC475896145AF1E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2166181E0FB51CE7ULL,
		0xBDD2F74C0EBE4E65ULL,
		0x1A2D9FE86E217D33ULL,
		0x5FE647CA2CF7D7FAULL,
		0xAA458F725689E40CULL,
		0x215DB62086B9EB2DULL,
		0x6B2527F4FCE38EE3ULL,
		0x79A65F988C2C6617ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA5D5DD4BCD1A2FFDULL,
		0xCB9F42B226CE158FULL,
		0x9CB360B690DE84AAULL,
		0x398368F78763A9D2ULL,
		0x99AA3DEE13C8434AULL,
		0x775D1B24BAE629ABULL,
		0x964E322BF5022CC8ULL,
		0x223778D12C0C42B0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2AB56706D117857ULL,
		0xD88748DB84499EBDULL,
		0x0A986A9753D89A7DULL,
		0x83CDAE4C4B33B346ULL,
		0x6D6AC6C82DAA2B24ULL,
		0x9FFA59E86B1E198FULL,
		0xEFF956D33DF51943ULL,
		0x7CE552220FB57C8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD32A86DB6008B7A6ULL,
		0xF317F9D6A28476D1ULL,
		0x921AF61F3D05EA2CULL,
		0xB5B5BAAB3C2FF68CULL,
		0x2C3F7725E61E1825ULL,
		0xD762C13C4FC8101CULL,
		0xA654DB58B70D1384ULL,
		0xA55226AF1C56C624ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF06BC28B8AAC535AULL,
		0x2032BCAFC4F77780ULL,
		0x217B1888F43E65A9ULL,
		0x7EF0743E0C40A758ULL,
		0x7F2633AFB215EB31ULL,
		0x0AAE0BC855FBB7F2ULL,
		0xFCCB0B1CE6F5E12AULL,
		0xDA4A7EBFE8E264CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63F1BFE43EB4D72ULL,
		0x7E262A9F094046EAULL,
		0xEB0336A679EDD8F6ULL,
		0x5F410604D82C9201ULL,
		0x9A154A53F0E74822ULL,
		0xC1A0F9584884CBC2ULL,
		0xFB28CA87843DE4F2ULL,
		0xF5EE1D8B26D39397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A2CA68D46C105E8ULL,
		0xA20C9210BBB73096ULL,
		0x3677E1E27A508CB2ULL,
		0x1FAF6E3934141556ULL,
		0xE510E95BC12EA30FULL,
		0x490D12700D76EC2FULL,
		0x01A2409562B7FC37ULL,
		0xE45C6134C20ED133ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CDF7BACD6C041E6ULL,
		0xDE4424A3C2FD9BE0ULL,
		0xD8DF6E9BBEB0DA8AULL,
		0x0EC804F4A816E0CDULL,
		0x444FAB8E322D18FFULL,
		0xEC145030F1C9F051ULL,
		0xBAA347D97709AA59ULL,
		0x7AFD9A8BEFD40C54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4459618B3EC11A02ULL,
		0x231E15B431A1C3A8ULL,
		0x80D95CD0207A1067ULL,
		0x59B1E92FB7DB8D00ULL,
		0x9AC3FD26FBBD98A2ULL,
		0x86B57AA4DD8A27A6ULL,
		0x7485F0FEA760379FULL,
		0x1A68E820FA9A90D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08861A2197FF27E4ULL,
		0xBB260EEF915BD838ULL,
		0x580611CB9E36CA23ULL,
		0xB5161BC4F03B53CDULL,
		0xA98BAE67366F805CULL,
		0x655ED58C143FC8AAULL,
		0x461D56DACFA972BAULL,
		0x6094B26AF5397B7BULL
	}};
	sign = 0;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x04E2B9CF28A943F7ULL,
		0xD3535D2557822216ULL,
		0x28D7796B6552A183ULL,
		0x4CD7CD1444786C69ULL,
		0xD6EF6C7461B582A5ULL,
		0xBB5B7F236E93650CULL,
		0x125D8181422AC274ULL,
		0xCD2F3BB137FF7F1AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E56C051D14FBE77ULL,
		0xF53AC3F4F44AD1B4ULL,
		0x5EE4125A5FF2A545ULL,
		0x40FAB2D6A5ECEE07ULL,
		0xDEA016EDCB4767C6ULL,
		0x7553534F05F5DCF2ULL,
		0x6E065B03745E86F1ULL,
		0x4D4E21CE7FCED3E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x968BF97D57598580ULL,
		0xDE18993063375061ULL,
		0xC9F36711055FFC3DULL,
		0x0BDD1A3D9E8B7E61ULL,
		0xF84F5586966E1ADFULL,
		0x46082BD4689D8819ULL,
		0xA457267DCDCC3B83ULL,
		0x7FE119E2B830AB30ULL
	}};
	sign = 0;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0FD10CBE52AFC16FULL,
		0x8D7CBCFA91D603F0ULL,
		0xB0201A507E01E2C0ULL,
		0xC234AFAE56405F81ULL,
		0xB7B8A93694304BA3ULL,
		0x5CCC4A13CA6B8243ULL,
		0xA8C6CD5F02E1D4B7ULL,
		0xD194BEED8ECD36D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A1B02944BD8FE9ULL,
		0x8CBB546DD681AB76ULL,
		0xA357B9FCF65D1B91ULL,
		0xC642468365EA7B6DULL,
		0x938140AF913BDD3AULL,
		0x26FB79B16CC11048ULL,
		0x57F11CF76636D58BULL,
		0xA07ED8B8FAE4C185ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x682F5C950DF23186ULL,
		0x00C1688CBB545879ULL,
		0x0CC8605387A4C72FULL,
		0xFBF2692AF055E414ULL,
		0x2437688702F46E68ULL,
		0x35D0D0625DAA71FBULL,
		0x50D5B0679CAAFF2CULL,
		0x3115E63493E8754FULL
	}};
	sign = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1FA38A24735CE047ULL,
		0x5F0C92B2F06BF0FAULL,
		0x009DC2E354CFBD0EULL,
		0xDD8CE77104247CF1ULL,
		0x99C085DD8B7D5076ULL,
		0x7D64B34C16C78D3CULL,
		0xD2547CD4D95D4884ULL,
		0x50CE64F6D2058311ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1E4F62765AD7A4DULL,
		0xF13E4258E3B3FEE0ULL,
		0x6E0EE79A324D44E2ULL,
		0x377ABB75F3D56105ULL,
		0xB4CDED4E724F594AULL,
		0x6A3D7E6A28AE7598ULL,
		0xC2E8D4D0744E02E7ULL,
		0x2C49F429F8F01635ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DBE93FD0DAF65FAULL,
		0x6DCE505A0CB7F219ULL,
		0x928EDB492282782BULL,
		0xA6122BFB104F1BEBULL,
		0xE4F2988F192DF72CULL,
		0x132734E1EE1917A3ULL,
		0x0F6BA804650F459DULL,
		0x248470CCD9156CDCULL
	}};
	sign = 0;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66C2EC7D13DEEAA3ULL,
		0x4E07DAFCE3F2F0FFULL,
		0x5AE11178EFB1794FULL,
		0xEA2BC65E85390B09ULL,
		0x1F09A676724DE3B1ULL,
		0xD3D379726AE8CEE6ULL,
		0x9AFDF917238B8761ULL,
		0x1CA2D07F6888775CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B5056CD623C551ULL,
		0xD7041AA501AF9705ULL,
		0xD3740507FB7A376EULL,
		0xFF1380EC14E53D0DULL,
		0x0FC9AF3E4732DCECULL,
		0x4EE7138811A5F5B2ULL,
		0xCC30070E1C78F608ULL,
		0x4C596A657E927B16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB40DE7103DBB2552ULL,
		0x7703C057E24359F9ULL,
		0x876D0C70F43741E0ULL,
		0xEB1845727053CDFBULL,
		0x0F3FF7382B1B06C4ULL,
		0x84EC65EA5942D934ULL,
		0xCECDF20907129159ULL,
		0xD0496619E9F5FC45ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB90579862379871DULL,
		0x281871793ECDBC62ULL,
		0xB67496324FC68F98ULL,
		0x9D2D9B6B4654B38BULL,
		0x6FCB8EFAEE1EB55FULL,
		0x2A8F47E1ABD62C78ULL,
		0x57B18FE6F5C0D8F8ULL,
		0x4E344DD77298D011ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4A30FEDF9539627ULL,
		0x092832457F1FE84AULL,
		0xB59F80E92C465348ULL,
		0x2881A47D119D5233ULL,
		0x2BCE0C44A0DE46D1ULL,
		0xB7E4F6AFE11995BAULL,
		0x81C91F52213C9D00ULL,
		0xB751556D27071272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC46269982A25F0F6ULL,
		0x1EF03F33BFADD417ULL,
		0x00D5154923803C50ULL,
		0x74ABF6EE34B76158ULL,
		0x43FD82B64D406E8EULL,
		0x72AA5131CABC96BEULL,
		0xD5E87094D4843BF7ULL,
		0x96E2F86A4B91BD9EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8FCFFB45687066D7ULL,
		0x2CFC91285F430C5FULL,
		0xA2A94A29EF3A7590ULL,
		0x6DD636387D61B688ULL,
		0x833D660C7A0431BFULL,
		0xD1EA9249FB17E7FDULL,
		0xA8FE9443BEFBCCE7ULL,
		0x9110C1609F01ABB5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E63C65B41D6F43CULL,
		0xD4EA34DB2741723AULL,
		0x9D76ACA3F421BCCFULL,
		0xEABCBE5176064F9AULL,
		0x1EF124DD59C83D55ULL,
		0xDF5F227A6302DC94ULL,
		0xC7ECD44164D4F4ABULL,
		0x8340AB16DF0CAEB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x816C34EA2699729BULL,
		0x58125C4D38019A25ULL,
		0x05329D85FB18B8C0ULL,
		0x831977E7075B66EEULL,
		0x644C412F203BF469ULL,
		0xF28B6FCF98150B69ULL,
		0xE111C0025A26D83BULL,
		0x0DD01649BFF4FD02ULL
	}};
	sign = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1EA1A816FC229FDDULL,
		0xD3703D38E39E2E69ULL,
		0x64BC13F60FCB8E3BULL,
		0x2A0CA576A44EF4CFULL,
		0xFB7FECACD67C4B36ULL,
		0xB73A6ECFB2DBF11FULL,
		0x36FEF0039CCB2688ULL,
		0xE36371D6BE71AA2AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x446D2478E6FC25B4ULL,
		0x5BA0A33DA18FC400ULL,
		0xDE1B90423333E616ULL,
		0xBBCDBCB4615B85F1ULL,
		0xAD87A08609A2A0CBULL,
		0x0E94878AA0DD01FBULL,
		0x97DE25D904352782ULL,
		0x7635DEF231240EB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA34839E15267A29ULL,
		0x77CF99FB420E6A68ULL,
		0x86A083B3DC97A825ULL,
		0x6E3EE8C242F36EDDULL,
		0x4DF84C26CCD9AA6AULL,
		0xA8A5E74511FEEF24ULL,
		0x9F20CA2A9895FF06ULL,
		0x6D2D92E48D4D9B70ULL
	}};
	sign = 0;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFAF41E56145A0E49ULL,
		0xBE9857D5B434738EULL,
		0xA151CA903DED7296ULL,
		0xD45E2326718DB80FULL,
		0x41DA6F1EBF2F818BULL,
		0xDB161A19125C3972ULL,
		0x5ED2DF7E74B75DABULL,
		0xDEA3B096A8FFB14DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E090B7ADCAED74DULL,
		0x2A2F284A596E27EFULL,
		0xFC240FED36A97DFCULL,
		0x28ED0F009300C6EFULL,
		0xDDD98E83AC191DBFULL,
		0x2DE03DEC1B98F2DFULL,
		0xC2F58AA057BDA014ULL,
		0x0DD05D2DA6EF2CDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACEB12DB37AB36FCULL,
		0x94692F8B5AC64B9FULL,
		0xA52DBAA30743F49AULL,
		0xAB711425DE8CF11FULL,
		0x6400E09B131663CCULL,
		0xAD35DC2CF6C34692ULL,
		0x9BDD54DE1CF9BD97ULL,
		0xD0D3536902108470ULL
	}};
	sign = 0;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0FEFC1C67DF406D2ULL,
		0xC251C065976307DCULL,
		0x22D48A2B579C438FULL,
		0x4C42551F33625F64ULL,
		0x6849E025E795E379ULL,
		0xE28BB228DB1487CCULL,
		0x677E99B9C19D02DEULL,
		0xEF93C8854983125FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72A942A35FCE961ULL,
		0xBFFCF2D1B9999445ULL,
		0xEACBA378D8542C5EULL,
		0x2D4EFF34E7B28DB9ULL,
		0x21E8EC5046279BDBULL,
		0xA77C08EF230B6356ULL,
		0x5E6ADAA772D43E39ULL,
		0x436D7165D91EFED3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68C52D9C47F71D71ULL,
		0x0254CD93DDC97396ULL,
		0x3808E6B27F481731ULL,
		0x1EF355EA4BAFD1AAULL,
		0x4660F3D5A16E479EULL,
		0x3B0FA939B8092476ULL,
		0x0913BF124EC8C4A5ULL,
		0xAC26571F7064138CULL
	}};
	sign = 0;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2EE98BE5D7796F86ULL,
		0xEDD4EE5FB113D299ULL,
		0xF634DD22A2F439EBULL,
		0x759577693EBA9DB7ULL,
		0xEC49B981FF8FE233ULL,
		0x724BEFAFB0459A2CULL,
		0x0D3ED6ECA752740FULL,
		0xB72E5B497DA0DF57ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x975426643B70BE5DULL,
		0xB70AD1B734CB4353ULL,
		0x0038C0318DB8AFF9ULL,
		0xBB97F81F3C6AF591ULL,
		0x71DC20B450109D66ULL,
		0x2D3763D2569FF1F9ULL,
		0x79BB62010559259EULL,
		0x1C275F5501980068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x979565819C08B129ULL,
		0x36CA1CA87C488F45ULL,
		0xF5FC1CF1153B89F2ULL,
		0xB9FD7F4A024FA826ULL,
		0x7A6D98CDAF7F44CCULL,
		0x45148BDD59A5A833ULL,
		0x938374EBA1F94E71ULL,
		0x9B06FBF47C08DEEEULL
	}};
	sign = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7AB8DE3A1D6AD504ULL,
		0xC0918836128641D6ULL,
		0x1953E2DC43C7521CULL,
		0x9E5AD5A2AF1257B4ULL,
		0xA9CA872C7DBD0E40ULL,
		0x023CA48D7C513D5FULL,
		0x0B1A1F6C8B775379ULL,
		0xAD8195522135E4DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD91A2583AC6BBE21ULL,
		0x1232E95AF8291ECCULL,
		0x115E917F49EB9024ULL,
		0x44790716CA1BF88FULL,
		0x2FE19A530E7A0E37ULL,
		0xB6C57A7BA76D5DC3ULL,
		0xA12E2E4E2F5B8B38ULL,
		0xA4AD78EE1CEE9A53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA19EB8B670FF16E3ULL,
		0xAE5E9EDB1A5D2309ULL,
		0x07F5515CF9DBC1F8ULL,
		0x59E1CE8BE4F65F25ULL,
		0x79E8ECD96F430009ULL,
		0x4B772A11D4E3DF9CULL,
		0x69EBF11E5C1BC840ULL,
		0x08D41C6404474A88ULL
	}};
	sign = 0;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB502EBD10365B390ULL,
		0x6630FF599C8B973FULL,
		0x9D275836C73079DAULL,
		0x4737840C0FA507A8ULL,
		0x9318DCC22AC43264ULL,
		0x1918F6B8E4B1E8ACULL,
		0x547C6412D4F0F37FULL,
		0xCC4226DCB7F00631ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x64A56DDE26D1C821ULL,
		0x0717D972DD0C04D5ULL,
		0x27C0F933685C1DD6ULL,
		0x39743B4278F97B56ULL,
		0x9A25D4B935D203D7ULL,
		0x8BCBB092F5FCF3FDULL,
		0x4703D161D2E03EB8ULL,
		0xC487BE6362840C7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x505D7DF2DC93EB6FULL,
		0x5F1925E6BF7F926AULL,
		0x75665F035ED45C04ULL,
		0x0DC348C996AB8C52ULL,
		0xF8F30808F4F22E8DULL,
		0x8D4D4625EEB4F4AEULL,
		0x0D7892B10210B4C6ULL,
		0x07BA6879556BF9B7ULL
	}};
	sign = 0;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3FCF7CFD3D195E28ULL,
		0xB86FC8F9D61426CBULL,
		0x0FA020DDF9B4E3DCULL,
		0xEDCD1B616FA8566DULL,
		0x09C560A460BB6061ULL,
		0x3BBABA5B5FC8DAB2ULL,
		0xD2108BAF0BC42FE4ULL,
		0xB874F93F68019B59ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x038EFF811605A9BAULL,
		0x8DD384A0E08597B6ULL,
		0x69BB50585AA43896ULL,
		0xEA208FCA9CC53BA2ULL,
		0x9B21AC61FCCADF18ULL,
		0x2CC3AB2AC8FC3DD5ULL,
		0xF4049B2FF84887CAULL,
		0x5A22A4E44EEA8F38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C407D7C2713B46EULL,
		0x2A9C4458F58E8F15ULL,
		0xA5E4D0859F10AB46ULL,
		0x03AC8B96D2E31ACAULL,
		0x6EA3B44263F08149ULL,
		0x0EF70F3096CC9CDCULL,
		0xDE0BF07F137BA81AULL,
		0x5E52545B19170C20ULL
	}};
	sign = 0;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x837262B5D137985FULL,
		0x3ADD589B77B36604ULL,
		0xDE23D23DF8FAEEBBULL,
		0xCAA046E951E4E86CULL,
		0x7F326CC367ACA3E9ULL,
		0xDAFDCD34CCFAB8D7ULL,
		0xA8940A4123C6D7CAULL,
		0xB64B16C657FC727DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A41E0171859938ULL,
		0xBCA1CA3A3A6E4641ULL,
		0xA6787A9371245CF6ULL,
		0x79751647ACFD6B1EULL,
		0xEB7619CC4F98C41DULL,
		0xD82861B6593AAA04ULL,
		0x2F9AF0D9BAA1A059ULL,
		0x01AF20A9914DBC27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82CE44B45FB1FF27ULL,
		0x7E3B8E613D451FC3ULL,
		0x37AB57AA87D691C4ULL,
		0x512B30A1A4E77D4EULL,
		0x93BC52F71813DFCCULL,
		0x02D56B7E73C00ED2ULL,
		0x78F9196769253771ULL,
		0xB49BF61CC6AEB656ULL
	}};
	sign = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C52AF7E7F32C31FULL,
		0x77746C7FD880CE43ULL,
		0x105BD65C4A913C1CULL,
		0x822C8BA4F5898D85ULL,
		0x450BD4887F8F9607ULL,
		0xD520CF8C26D798DCULL,
		0xDCD7757A5C46FC65ULL,
		0x426A307844625AE5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C497AD2D08A3C5ULL,
		0x66706E2146D63ED4ULL,
		0x723A04F87C0B7BA0ULL,
		0x9F1245AEC8A8FDB3ULL,
		0xEF8D276BE432F085ULL,
		0x4EFA96348CD46FAEULL,
		0xDC7A21DD66B8F09DULL,
		0x64744175091B6C55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x778E17D1522A1F5AULL,
		0x1103FE5E91AA8F6FULL,
		0x9E21D163CE85C07CULL,
		0xE31A45F62CE08FD1ULL,
		0x557EAD1C9B5CA581ULL,
		0x862639579A03292DULL,
		0x005D539CF58E0BC8ULL,
		0xDDF5EF033B46EE90ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA09CAAB11AC24805ULL,
		0x696077C7C3558E22ULL,
		0x276492C002DAD8AEULL,
		0xBA9DFDE09B40CFF9ULL,
		0x97C10435492687CCULL,
		0x611E152246310EC8ULL,
		0x8953F5B9996AAB43ULL,
		0xF0FAEC0F2937CDF7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52B5503F308B848FULL,
		0x10465A77C17C0332ULL,
		0xED7699E36DCA041CULL,
		0x276E3D17935128BCULL,
		0x58423829410253D1ULL,
		0x29793787A0D20C85ULL,
		0xAC217EF8EFA16A6CULL,
		0x37033EC9E8BFBCF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DE75A71EA36C376ULL,
		0x591A1D5001D98AF0ULL,
		0x39EDF8DC9510D492ULL,
		0x932FC0C907EFA73CULL,
		0x3F7ECC0C082433FBULL,
		0x37A4DD9AA55F0243ULL,
		0xDD3276C0A9C940D7ULL,
		0xB9F7AD4540781101ULL
	}};
	sign = 0;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CB312A6595EF7CDULL,
		0x9BE20A3F9FCC4FFCULL,
		0x8FE60316E128770CULL,
		0xB9F51625C75BF893ULL,
		0xDC888D6F4304F2BEULL,
		0x8EE6B773DE40E4CEULL,
		0x946A2154CDC8A2D9ULL,
		0x2BAE80E44F0EC7B4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B40DDF1EB36CDB8ULL,
		0x85051187BBF3005DULL,
		0x67989302407601A8ULL,
		0xF770FE97653E53B1ULL,
		0x2C4A63D93956A2A8ULL,
		0x67B62D0271CA8078ULL,
		0xDC706E129E4F7C8CULL,
		0xF70A190AE8B9FF9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD17234B46E282A15ULL,
		0x16DCF8B7E3D94F9EULL,
		0x284D7014A0B27564ULL,
		0xC284178E621DA4E2ULL,
		0xB03E299609AE5015ULL,
		0x27308A716C766456ULL,
		0xB7F9B3422F79264DULL,
		0x34A467D96654C814ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6DF78D64AB9D062CULL,
		0x36C4986A778AC643ULL,
		0xB4580D6DE0FAE0F2ULL,
		0x16DB46FC46306301ULL,
		0xB41500D1A6BF1227ULL,
		0x8F9D611EDA78FE21ULL,
		0x71470D608CAA84EBULL,
		0x6B1D0FDB2597BA63ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D649C9F2CB9ED8CULL,
		0xD097A4CDE150D4F7ULL,
		0x91B693C6C75A9FF8ULL,
		0x0F7BDA136EBF7671ULL,
		0xEB7F0090D2997B74ULL,
		0x2D57EF772DFC6106ULL,
		0x7665AF3174D2CA41ULL,
		0x409B8B45A1F4A7A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4092F0C57EE318A0ULL,
		0x662CF39C9639F14CULL,
		0x22A179A719A040F9ULL,
		0x075F6CE8D770EC90ULL,
		0xC8960040D42596B3ULL,
		0x624571A7AC7C9D1AULL,
		0xFAE15E2F17D7BAAAULL,
		0x2A81849583A312BAULL
	}};
	sign = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8922B1FD4D326578ULL,
		0x9315A0C3F67B3350ULL,
		0x7AF5FC2535DF811CULL,
		0xF78FEB3861A50356ULL,
		0xBD2ACA731242F804ULL,
		0x42C797DAAC464301ULL,
		0x1CBDE63781324667ULL,
		0xC5520DF5E453E592ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x196658B2ABEDEB7BULL,
		0x85F0D3FAAAB3AF30ULL,
		0x448D77D1E1FE1C97ULL,
		0xBC4FBFE800AD5FF6ULL,
		0x7FE061084E683B57ULL,
		0x351A9CE8F3715119ULL,
		0x51A95C31B2FA1676ULL,
		0xAFFCC7A6DB0FBEF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FBC594AA14479FDULL,
		0x0D24CCC94BC78420ULL,
		0x3668845353E16485ULL,
		0x3B402B5060F7A360ULL,
		0x3D4A696AC3DABCADULL,
		0x0DACFAF1B8D4F1E8ULL,
		0xCB148A05CE382FF1ULL,
		0x1555464F094426A1ULL
	}};
	sign = 0;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x975EA6EC048DA9C5ULL,
		0x4B2DA6903DD6F24EULL,
		0x4B24EC7CD65F1423ULL,
		0xB8C4C4AF27DD6074ULL,
		0xE343997C4D916D53ULL,
		0x52C78754199DEBB1ULL,
		0x647ABEA1AE4F3F20ULL,
		0x4D381ABCD25F0EB6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BAA1081D7AECB7BULL,
		0x216BEDCAE4630682ULL,
		0x1D693EFFCDA7F56DULL,
		0x716CCF00518DA1AEULL,
		0x632E930CFF3788DCULL,
		0xEE8D5A3FB5AFB8DAULL,
		0xFE254518D9F5EE96ULL,
		0x844C54D991AA3C8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BB4966A2CDEDE4AULL,
		0x29C1B8C55973EBCCULL,
		0x2DBBAD7D08B71EB6ULL,
		0x4757F5AED64FBEC6ULL,
		0x8015066F4E59E477ULL,
		0x643A2D1463EE32D7ULL,
		0x66557988D4595089ULL,
		0xC8EBC5E340B4D228ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x579303FC83334F49ULL,
		0x0BDD2EB02879EBAFULL,
		0xB5E7BD6639FFC36EULL,
		0xB89431EB9F381896ULL,
		0x24455A036BF54BE3ULL,
		0x89CF794B085020D1ULL,
		0x36E3E4DCF7469B56ULL,
		0x998FB7F3086030D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4829F243973ED28EULL,
		0xC720CF78D2FE0979ULL,
		0x68D786EEDDB02668ULL,
		0x8FD88897FDC1FD33ULL,
		0x30DB55721E2FF7A3ULL,
		0x8D893F5EB50943C8ULL,
		0xA5056678A77BF5B1ULL,
		0x80AC5039A1F01A84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F6911B8EBF47CBBULL,
		0x44BC5F37557BE236ULL,
		0x4D1036775C4F9D05ULL,
		0x28BBA953A1761B63ULL,
		0xF36A04914DC55440ULL,
		0xFC4639EC5346DD08ULL,
		0x91DE7E644FCAA5A4ULL,
		0x18E367B96670164FULL
	}};
	sign = 0;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x27526B4B79DFACA1ULL,
		0x61C2836989AD1C81ULL,
		0xE2B8D406F94916ECULL,
		0x89247802F89110CFULL,
		0xBFEF46A0724D9877ULL,
		0xE6F802905C9025CCULL,
		0xB0928FD36036ECCBULL,
		0xC17154296451470AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4A7616EF9DCE4EULL,
		0xE647BD01FC4FF440ULL,
		0xA7E24465511C8FF0ULL,
		0x591A16B95BC20DC4ULL,
		0x06400B0F2F44DE78ULL,
		0x1AE264980100C429ULL,
		0x625D3E8DB43AF0AFULL,
		0xA9373B6DCDBB4A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C07F5348A41DE53ULL,
		0x7B7AC6678D5D2840ULL,
		0x3AD68FA1A82C86FBULL,
		0x300A61499CCF030BULL,
		0xB9AF3B914308B9FFULL,
		0xCC159DF85B8F61A3ULL,
		0x4E355145ABFBFC1CULL,
		0x183A18BB9695FC7BULL
	}};
	sign = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x697396494DFF7D13ULL,
		0x73751F59C22C7228ULL,
		0x3A0EB7C54C35CBD7ULL,
		0x79D6E5884382FBA3ULL,
		0x19764924F72F7BACULL,
		0x25293B7C4ABA6ADBULL,
		0xDCC4C9780D5A9D6FULL,
		0x903ACB3D21CB4303ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B36EDE773C34CDULL,
		0x852B00766A5E5358ULL,
		0x04B396A217F5B28FULL,
		0x3A96A6DA22D49DB9ULL,
		0x938782EE6670D3B1ULL,
		0x199A17BFC1F316BAULL,
		0x1C5E9DD0D8A14A8CULL,
		0xC52C8CE3215AFEADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85C0276AD6C34846ULL,
		0xEE4A1EE357CE1ECFULL,
		0x355B212334401947ULL,
		0x3F403EAE20AE5DEAULL,
		0x85EEC63690BEA7FBULL,
		0x0B8F23BC88C75420ULL,
		0xC0662BA734B952E3ULL,
		0xCB0E3E5A00704456ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0281144DFFCE7BEAULL,
		0xB9CA72790015A8F7ULL,
		0x4BB1EBF9817D4DB8ULL,
		0xCF9C8778B25E428DULL,
		0xEBDD5F9FB0863EE1ULL,
		0x1DDA0D4BCB12A6C4ULL,
		0xD3722C1230D8ACFAULL,
		0xF7363B4773139D3EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x09FB8EE8A399D68BULL,
		0xAFF07FB48BEDE88BULL,
		0x382BA16D4939C578ULL,
		0xAEEF4962BF261C56ULL,
		0xCEE3AE091F4AD2FBULL,
		0xBABE9096A27AC8BDULL,
		0x71463E893F6F7FDCULL,
		0xCD8755CEE76DE3D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF88585655C34A55FULL,
		0x09D9F2C47427C06BULL,
		0x13864A8C38438840ULL,
		0x20AD3E15F3382637ULL,
		0x1CF9B196913B6BE6ULL,
		0x631B7CB52897DE07ULL,
		0x622BED88F1692D1DULL,
		0x29AEE5788BA5B96EULL
	}};
	sign = 0;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFFAF40DCB080FD0CULL,
		0xCEA7D247C058F850ULL,
		0x60597D9DCCE31266ULL,
		0xDEE134CE64B36E99ULL,
		0x00A3D95B58CDED9AULL,
		0x60C7CD97255E7236ULL,
		0x418ACC8D4BFBE8BAULL,
		0x6EE092DC4E03E165ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8D5553458F8139DULL,
		0xF96C3F1F558BBDFCULL,
		0x0661989AB6480BD5ULL,
		0xED881A1AAD780919ULL,
		0xDA152E8EDB5832DCULL,
		0xAC48E12C3972A848ULL,
		0xEF4BAAD16AAF62DAULL,
		0x109991371FEED84BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56D9EBA85788E96FULL,
		0xD53B93286ACD3A54ULL,
		0x59F7E503169B0690ULL,
		0xF1591AB3B73B6580ULL,
		0x268EAACC7D75BABDULL,
		0xB47EEC6AEBEBC9EDULL,
		0x523F21BBE14C85DFULL,
		0x5E4701A52E150919ULL
	}};
	sign = 0;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBCA1B0C17713C804ULL,
		0x8B6BC5CD7CD109AEULL,
		0x6723CF8214D97BB5ULL,
		0x5EFF32CEC6891F12ULL,
		0x4E997FB3C79D3A8FULL,
		0xA5F013EE0016C001ULL,
		0x2FF65315E498C242ULL,
		0xA9A6096894A34369ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BFA3DF6AFB270ABULL,
		0x068A56867D4E8B49ULL,
		0xBD84645A8C89B9ACULL,
		0xD5FA26829C660A6CULL,
		0xAF52D29D30DEBF3CULL,
		0xA3F1EC6C2FCD0F81ULL,
		0x0C14C19BE38F8084ULL,
		0x2E41CAD4A4785DB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A772CAC7615759ULL,
		0x84E16F46FF827E65ULL,
		0xA99F6B27884FC209ULL,
		0x89050C4C2A2314A5ULL,
		0x9F46AD1696BE7B52ULL,
		0x01FE2781D049B07FULL,
		0x23E1917A010941BEULL,
		0x7B643E93F02AE5B2ULL
	}};
	sign = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDB2A7008C4C79B1BULL,
		0x5FDA7EFD3221EF7BULL,
		0xAEB051843055F885ULL,
		0x0C467B340BB24E54ULL,
		0x2E1752A999BB91A1ULL,
		0x57E2F948876875DAULL,
		0xE2AC3D4CC6F24CCEULL,
		0x2222B91DEF27E11AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A8FCC361FF623CULL,
		0xFE6326BEC33239C7ULL,
		0xD88CC28F0B0BF0CBULL,
		0xAE0DFFEE5ED0D57CULL,
		0xBE88DDDD5B1E48D6ULL,
		0x7E12FC1F0B50F2E1ULL,
		0x193E02C7EA1230EFULL,
		0xA25B99CEA031C78FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA81734562C838DFULL,
		0x6177583E6EEFB5B3ULL,
		0xD6238EF5254A07B9ULL,
		0x5E387B45ACE178D7ULL,
		0x6F8E74CC3E9D48CAULL,
		0xD9CFFD297C1782F8ULL,
		0xC96E3A84DCE01BDEULL,
		0x7FC71F4F4EF6198BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD0A059154517DBA8ULL,
		0x8E32E1A282F3D456ULL,
		0xC0075C2E022FE2A8ULL,
		0xB2DF76BAEDF7F967ULL,
		0x7547A11C3A0C1F26ULL,
		0x706FCB38E6591812ULL,
		0x66F6C00BA29756B0ULL,
		0x6CDFF8A7F9B6AB70ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x61C76FF6F3B919D4ULL,
		0xA2E0ECCD902C84EAULL,
		0x7CEA66225B169243ULL,
		0xEF7DE29564C8E545ULL,
		0xC0EC1FF52F0B928BULL,
		0x62CD7D87EC4F75B7ULL,
		0x6E820DBC641ACCB8ULL,
		0x0F677D7034774598ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ED8E91E515EC1D4ULL,
		0xEB51F4D4F2C74F6CULL,
		0x431CF60BA7195064ULL,
		0xC3619425892F1422ULL,
		0xB45B81270B008C9AULL,
		0x0DA24DB0FA09A25AULL,
		0xF874B24F3E7C89F8ULL,
		0x5D787B37C53F65D7ULL
	}};
	sign = 0;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB64EEABA05026889ULL,
		0xF43867743C29580FULL,
		0x005684DC807A2BADULL,
		0x2E2B27D4F484E5CBULL,
		0x40BBEE0FC1A3731CULL,
		0x431EA4659F09F458ULL,
		0x70986F8448EAA5F6ULL,
		0xC5947C8FBD2BC93BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D071CDFE9369BCULL,
		0x39357386AD7CB876ULL,
		0x1E3174DAEE0902D1ULL,
		0x845D2048FB01DB1FULL,
		0x59D5FB1F2B1D779AULL,
		0x80138F808D92B745ULL,
		0x542249F76307304FULL,
		0xD91566AD760AB12AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x737E78EC066EFECDULL,
		0xBB02F3ED8EAC9F99ULL,
		0xE2251001927128DCULL,
		0xA9CE078BF9830AABULL,
		0xE6E5F2F09685FB81ULL,
		0xC30B14E511773D12ULL,
		0x1C76258CE5E375A6ULL,
		0xEC7F15E247211811ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x24CB3AEA7244A25AULL,
		0xA0FBD090E3156A9FULL,
		0x00CB3F14409D04A4ULL,
		0xF1C02DD25AE51789ULL,
		0x783012E086829647ULL,
		0x36BBE9AD9E2DB8B0ULL,
		0xC9374BBFF360F456ULL,
		0xB2851B7E88327C5DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD2EAB71B02688AULL,
		0x72F158C1078BE311ULL,
		0x54DEAB89F692B9D2ULL,
		0x35E58E15BC24AF66ULL,
		0x4DA42780E4B1AD8DULL,
		0x9A6A3D6530E0F6C6ULL,
		0xE5E038FF64F0D966ULL,
		0xBF68F5233EA318A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74F85033574239D0ULL,
		0x2E0A77CFDB89878DULL,
		0xABEC938A4A0A4AD2ULL,
		0xBBDA9FBC9EC06822ULL,
		0x2A8BEB5FA1D0E8BAULL,
		0x9C51AC486D4CC1EAULL,
		0xE35712C08E701AEFULL,
		0xF31C265B498F63BBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x71A09E394872D079ULL,
		0x78415BEFABF2943FULL,
		0x77BA70588611E2B4ULL,
		0x26EA2AC9B4612F5EULL,
		0x116B0105039EACAEULL,
		0x2EF2E08BEE9E545DULL,
		0xBAC7AC058244B2F2ULL,
		0x835229FCA6BDDA30ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC87C9BE28F6F5C1DULL,
		0x69C910DD4633712CULL,
		0x3BB8A3B7B4AF63C2ULL,
		0x1C74D90173E3D210ULL,
		0x55E17B6E960B22AEULL,
		0xBD52A99CD9B9C401ULL,
		0xDDA193ED48DCD640ULL,
		0xE48D39E73326C916ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9240256B903745CULL,
		0x0E784B1265BF2312ULL,
		0x3C01CCA0D1627EF2ULL,
		0x0A7551C8407D5D4EULL,
		0xBB8985966D938A00ULL,
		0x71A036EF14E4905BULL,
		0xDD2618183967DCB1ULL,
		0x9EC4F01573971119ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8C01500904698479ULL,
		0xD5116281F64C6FEEULL,
		0xA7ABDE51C080F2FFULL,
		0xD5E01BB7AE48B533ULL,
		0x7298F99BF277AC0EULL,
		0xA4B7D7843B3309C3ULL,
		0x487077D061BA290DULL,
		0xAE2E20F8D4F1A2F2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F48A9100823F3A9ULL,
		0x3CA3FD5A63175A50ULL,
		0x7BB304387987C8F3ULL,
		0x96DE8E176C595B92ULL,
		0xADA63F8E6B21F2A9ULL,
		0xDE3A9507ACD85D54ULL,
		0x9CD9E087DF671887ULL,
		0x28DB889AAF9D1781ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CB8A6F8FC4590D0ULL,
		0x986D65279335159EULL,
		0x2BF8DA1946F92A0CULL,
		0x3F018DA041EF59A1ULL,
		0xC4F2BA0D8755B965ULL,
		0xC67D427C8E5AAC6EULL,
		0xAB96974882531085ULL,
		0x8552985E25548B70ULL
	}};
	sign = 0;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF7CA32DE6E15AC3ULL,
		0xD71EDAD8F4ED0EC0ULL,
		0xF6DDA1A42534EB76ULL,
		0x1DDBD429981BCB30ULL,
		0xB112A8C84226DE9EULL,
		0x2338FE036DE53FCCULL,
		0x18267D853AF2383EULL,
		0x3C72F3B84D4869F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD0914121CF49EFULL,
		0x3DC9E87E8846764FULL,
		0xA30432D87C7E838DULL,
		0x8DAA312CCB4DBADEULL,
		0x12913465C743F7E5ULL,
		0x384C6B0C41DEBE8EULL,
		0x3F5B58E57819EE7DULL,
		0x8BE6F93B4F531FEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23AC11ECC51210D4ULL,
		0x9954F25A6CA69871ULL,
		0x53D96ECBA8B667E9ULL,
		0x9031A2FCCCCE1052ULL,
		0x9E8174627AE2E6B8ULL,
		0xEAEC92F72C06813EULL,
		0xD8CB249FC2D849C0ULL,
		0xB08BFA7CFDF54A07ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1E3EB68273DB0C35ULL,
		0x782099BD8E6554D4ULL,
		0x255762F6ED1F3543ULL,
		0x3ACDCD1E3026E58FULL,
		0xD952E100A09727C5ULL,
		0x677AA060FFE8D448ULL,
		0x53E991C0C13D793CULL,
		0xCA22E01A7E52868CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD205AAA3726745CBULL,
		0x5C81D63FE4F0D8F8ULL,
		0x6BB7D255CBEADEFFULL,
		0x8C576CEED60610F0ULL,
		0x75036F7C6B56A955ULL,
		0x558A63C9079699EAULL,
		0x55D69DFE98224490ULL,
		0xDD42BDF11BDFCD9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C390BDF0173C66AULL,
		0x1B9EC37DA9747BDBULL,
		0xB99F90A121345644ULL,
		0xAE76602F5A20D49EULL,
		0x644F718435407E6FULL,
		0x11F03C97F8523A5EULL,
		0xFE12F3C2291B34ACULL,
		0xECE022296272B8EEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCB5767EFF4DC86B8ULL,
		0xC96DB72ED0C926BDULL,
		0xF8263C269AED8F74ULL,
		0x6E3308629663CE03ULL,
		0x38EBEEADA2FBEAD5ULL,
		0xF2363571767265D4ULL,
		0xFF128D89A90558E4ULL,
		0xBE497B9D4F47F0C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E534032597A7E6AULL,
		0xF46A702C26189919ULL,
		0xCD315A3079DC9575ULL,
		0xC80CBD0738588749ULL,
		0x564CE20FADBC469CULL,
		0xAD9F45AB3361AA60ULL,
		0x62870C11834B68E3ULL,
		0xD243F971DE1416E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D0427BD9B62084EULL,
		0xD5034702AAB08DA4ULL,
		0x2AF4E1F62110F9FEULL,
		0xA6264B5B5E0B46BAULL,
		0xE29F0C9DF53FA438ULL,
		0x4496EFC64310BB73ULL,
		0x9C8B817825B9F001ULL,
		0xEC05822B7133D9DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE6D811C5BA2B6B16ULL,
		0xC92C0DB58F9F6BFDULL,
		0x2B83C3D1882099FEULL,
		0x424F7EA8A73658D1ULL,
		0x16D6160E8A764841ULL,
		0x6AC5454ED8B9D0DCULL,
		0x0D15F27B4618EC16ULL,
		0xDC8994A3CD90AB4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4319363959A650C7ULL,
		0x0BC3F7828D866928ULL,
		0x9FEDF4793D5DB2D0ULL,
		0x6571B9B934C1F8D7ULL,
		0x43C31C49F04E2323ULL,
		0xD42E9D0A4DF668C7ULL,
		0x096714CA32BE272BULL,
		0x9BAEDDD6523FDFCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3BEDB8C60851A4FULL,
		0xBD681633021902D5ULL,
		0x8B95CF584AC2E72EULL,
		0xDCDDC4EF72745FF9ULL,
		0xD312F9C49A28251DULL,
		0x9696A8448AC36814ULL,
		0x03AEDDB1135AC4EAULL,
		0x40DAB6CD7B50CB7FULL
	}};
	sign = 0;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0511BAC8BAA77C5ULL,
		0x8B4D0CCBB27100DEULL,
		0x9A656C3C0E1C4C2DULL,
		0x99B979D3362BE441ULL,
		0x36EA420FC4142A86ULL,
		0xD4F59FDCD2FA26ABULL,
		0x4C6522BAB0534DFFULL,
		0x0B5399B664190A28ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EFAB536EB70AC62ULL,
		0xC963D43D3B3CF274ULL,
		0x6BA2C01DE2A2D516ULL,
		0xD87F4FADE8D35A25ULL,
		0xC347D92138E3536CULL,
		0xD464A218FC1F0157ULL,
		0x09C2608DC293E095ULL,
		0x047BCFDC0DE1D709ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31566675A039CB63ULL,
		0xC1E9388E77340E6AULL,
		0x2EC2AC1E2B797716ULL,
		0xC13A2A254D588A1CULL,
		0x73A268EE8B30D719ULL,
		0x0090FDC3D6DB2553ULL,
		0x42A2C22CEDBF6D6AULL,
		0x06D7C9DA5637331FULL
	}};
	sign = 0;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5595CCEDC0B0CE6ULL,
		0x3734913FB12CD38FULL,
		0xF94A43FE01BB912AULL,
		0xC23320D5C367C880ULL,
		0x5B06C8B229411E48ULL,
		0xD7528F6785262DE2ULL,
		0xD4634848A249DC99ULL,
		0x7E48BBEBE5456717ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E48A488CDBA518ULL,
		0x32ED58C10FB1C947ULL,
		0x91B6A4926B026671ULL,
		0x1E9EC74D9CD2D236ULL,
		0xAB56D435E01E5ECBULL,
		0x33C5C541C7EF5492ULL,
		0x82CCC856278BD378ULL,
		0xEE2A7F3D9659B54EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B74D2864F2F67CEULL,
		0x0447387EA17B0A48ULL,
		0x67939F6B96B92AB9ULL,
		0xA39459882694F64AULL,
		0xAFAFF47C4922BF7DULL,
		0xA38CCA25BD36D94FULL,
		0x51967FF27ABE0921ULL,
		0x901E3CAE4EEBB1C9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF758C858CE0B008ULL,
		0x3426A21E7C3C4708ULL,
		0x67B26476D3B41D54ULL,
		0xA59FEE9EB9657868ULL,
		0x66CB60B135EA2CF0ULL,
		0x55277DF70223DA59ULL,
		0x5042FBC646026450ULL,
		0xB7A7F1794CF07AB0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B635602752B55DBULL,
		0xCCB13F5737533D03ULL,
		0xCE8B85365E5A1A07ULL,
		0x4408554B411167B0ULL,
		0x40D8D3D9A1838B62ULL,
		0x437DAB6EE8A3D473ULL,
		0x61F20E078EC1FC01ULL,
		0x3A367A9BC3D8EA06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD412368317B55A2DULL,
		0x677562C744E90A05ULL,
		0x9926DF40755A034CULL,
		0x61979953785410B7ULL,
		0x25F28CD79466A18EULL,
		0x11A9D288198005E6ULL,
		0xEE50EDBEB740684FULL,
		0x7D7176DD891790A9ULL
	}};
	sign = 0;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0BC5109360432B1DULL,
		0x558B941B44EA055EULL,
		0xEC2283550AEB4FDAULL,
		0x098C8AD981C4D203ULL,
		0xF748567CC7166CBCULL,
		0x738E2641B82FFDD3ULL,
		0xC04CD45CF8A9D6E7ULL,
		0xE84F2F5A957E99F7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDF72408F26BC81AULL,
		0xE3012EDD55509B5AULL,
		0x1B43CC6BC1D67E0FULL,
		0x974681055AF08FD7ULL,
		0xB1DB71106AED38E2ULL,
		0x4BBE531068D3E9EEULL,
		0x82DFA628AE5BB6E5ULL,
		0x3CB921FC398812FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DCDEC8A6DD76303ULL,
		0x728A653DEF996A03ULL,
		0xD0DEB6E94914D1CAULL,
		0x724609D426D4422CULL,
		0x456CE56C5C2933D9ULL,
		0x27CFD3314F5C13E5ULL,
		0x3D6D2E344A4E2002ULL,
		0xAB960D5E5BF686FBULL
	}};
	sign = 0;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF8408800B2F86EA0ULL,
		0xBF027681E778B144ULL,
		0xF8E59895279B6246ULL,
		0xF8B8C03E30697316ULL,
		0xA4C0577350A18229ULL,
		0x07560C8B8699B45CULL,
		0xEC24F5C77ADE023FULL,
		0xFE0F9A1B3C708A2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADFE159261227CB4ULL,
		0x3A233B4CB0EA022DULL,
		0xB0459729EB5BFAA0ULL,
		0x7BD509820351DC2EULL,
		0x17E9D4B6EB19E75AULL,
		0x621B35ACC1602BB4ULL,
		0x71E12EF859876866ULL,
		0xC5FCE1737537E49CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A42726E51D5F1ECULL,
		0x84DF3B35368EAF17ULL,
		0x48A0016B3C3F67A6ULL,
		0x7CE3B6BC2D1796E8ULL,
		0x8CD682BC65879ACFULL,
		0xA53AD6DEC53988A8ULL,
		0x7A43C6CF215699D8ULL,
		0x3812B8A7C738A58FULL
	}};
	sign = 0;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x338983A8A6DAB05FULL,
		0xD6825B7D29FD6696ULL,
		0x4AAF40BEA6110F30ULL,
		0x07C85FE0FE0DA749ULL,
		0xF35C5871BD692DFAULL,
		0x61E329CAD745CA66ULL,
		0x49825BD1AF1E8994ULL,
		0x4E69CF09032DC9A7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB21F04EA283ACEEULL,
		0x322EBC52E6C28D7DULL,
		0x323B997059209984ULL,
		0xE11DFCFFBB16434DULL,
		0xCC82BB051693E26DULL,
		0x4538CAA816D51E2AULL,
		0x3295A6AC419B7DD7ULL,
		0xAC08E27B9E64520CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4867935A04570371ULL,
		0xA4539F2A433AD918ULL,
		0x1873A74E4CF075ACULL,
		0x26AA62E142F763FCULL,
		0x26D99D6CA6D54B8CULL,
		0x1CAA5F22C070AC3CULL,
		0x16ECB5256D830BBDULL,
		0xA260EC8D64C9779BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x14C0517BC58A824BULL,
		0x782A09E6BB533EABULL,
		0xD64BA347ADCF7C0EULL,
		0x43AC320215905365ULL,
		0x4736C232942ECBB4ULL,
		0xEF05C64FF5260FDEULL,
		0x635F4CD1503A5B16ULL,
		0xFD73C480B34145FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DCC57A5957C4757ULL,
		0x696BB3C77E396783ULL,
		0x5D776E991BE6B9CCULL,
		0x003951A0F640976DULL,
		0xD3E88B1D708CF05CULL,
		0x6F33659AC7946C17ULL,
		0xF3342E435A16F292ULL,
		0xF151D1A6C5DA6FFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76F3F9D6300E3AF4ULL,
		0x0EBE561F3D19D727ULL,
		0x78D434AE91E8C242ULL,
		0x4372E0611F4FBBF8ULL,
		0x734E371523A1DB58ULL,
		0x7FD260B52D91A3C6ULL,
		0x702B1E8DF6236884ULL,
		0x0C21F2D9ED66D5FFULL
	}};
	sign = 0;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x99FF140476D23DA5ULL,
		0xDB43C5E479D10A24ULL,
		0x1107740C59BF8BA4ULL,
		0xA61964F8761943FBULL,
		0x6FF6AAE75E9ADF9BULL,
		0x566297D80D502FB5ULL,
		0x9AB12C3588FD48E6ULL,
		0x1D2247353CCF1F45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF46555C0F7DE027ULL,
		0x405B96CE345ECA4BULL,
		0xA3D022D55F319E08ULL,
		0xB1DE745D64C1F627ULL,
		0xA669D93294156F89ULL,
		0x9CA5965F5DDDED96ULL,
		0x5B8FC881D3C67FFFULL,
		0xF010736DD83FBCBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAB8BEA867545D7EULL,
		0x9AE82F1645723FD8ULL,
		0x6D375136FA8DED9CULL,
		0xF43AF09B11574DD3ULL,
		0xC98CD1B4CA857011ULL,
		0xB9BD0178AF72421EULL,
		0x3F2163B3B536C8E6ULL,
		0x2D11D3C7648F6289ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3BF32B420D3D6B3BULL,
		0x15761C5A7953547DULL,
		0x71C1C357650BFCDBULL,
		0xC1C076F826FCD9F1ULL,
		0xBBE455E31712D4ADULL,
		0x0C90974456686D5CULL,
		0xC4C8EB081C537126ULL,
		0xCDD788D783BDE1DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E51E61F88A61D84ULL,
		0x5FCD2E5C131036F6ULL,
		0x77C36C0381854BF5ULL,
		0x5B59629AAE069103ULL,
		0x8D68B75A6FF50848ULL,
		0xDBFEA1C8FF87138BULL,
		0x63A12BA81B903939ULL,
		0x8F99A51F7019713FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDA1452284974DB7ULL,
		0xB5A8EDFE66431D86ULL,
		0xF9FE5753E386B0E5ULL,
		0x6667145D78F648EDULL,
		0x2E7B9E88A71DCC65ULL,
		0x3091F57B56E159D1ULL,
		0x6127BF6000C337ECULL,
		0x3E3DE3B813A4709EULL
	}};
	sign = 0;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00850B3D3A2E62A3ULL,
		0x1EFF7848DFF611D8ULL,
		0x7807F8B5C0F9CE3BULL,
		0x372B1D36736EC732ULL,
		0x4B580F17A82E8E3CULL,
		0x82D6E4CCE26B392BULL,
		0x75B820E2581BFE83ULL,
		0xBB8B86A790A9287FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BCE8DA09A02B16ULL,
		0xB005BAD84C174E99ULL,
		0xB62C17002ABEBA28ULL,
		0xA34EAF65388EC243ULL,
		0xF82AB6B7D68CB3E8ULL,
		0x2524C8720CE0C860ULL,
		0x6D79D9E5CCEFABE7ULL,
		0x8063A701AEE98D81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EC82263308E378DULL,
		0x6EF9BD7093DEC33EULL,
		0xC1DBE1B5963B1412ULL,
		0x93DC6DD13AE004EEULL,
		0x532D585FD1A1DA53ULL,
		0x5DB21C5AD58A70CAULL,
		0x083E46FC8B2C529CULL,
		0x3B27DFA5E1BF9AFEULL
	}};
	sign = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82939E1150BE7A60ULL,
		0xC2F90FBEB4CC9C36ULL,
		0xF68A78A2D71DA1BAULL,
		0xF5E27B50223B8FC8ULL,
		0xCE4994BA589C3FCCULL,
		0xF8C55EBD1D59BAE1ULL,
		0xBBF29F6C53F8885DULL,
		0x2B26CB7BAF9848A1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x45C76F2C901B9B97ULL,
		0x540BED1A3CAF72F5ULL,
		0x5BC0A83A6637952FULL,
		0xABF12514857A6E4CULL,
		0x07ED695248C4E2A5ULL,
		0x6329A0D9889105A1ULL,
		0x0A2A0BD78EF8AACAULL,
		0xB8CB6D5C8055F422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CCC2EE4C0A2DEC9ULL,
		0x6EED22A4781D2941ULL,
		0x9AC9D06870E60C8BULL,
		0x49F1563B9CC1217CULL,
		0xC65C2B680FD75D27ULL,
		0x959BBDE394C8B540ULL,
		0xB1C89394C4FFDD93ULL,
		0x725B5E1F2F42547FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x64964D8BF7529401ULL,
		0x743DE99BE5E448D1ULL,
		0x6EE405912CABC5B6ULL,
		0x18ACD16F21CEED17ULL,
		0x6C7A3F09457F04DDULL,
		0x39FE4A689C5CF3D4ULL,
		0x8C1113FC960C55CEULL,
		0x2672A4F999579C1FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF2A18057ABD0F0ULL,
		0xC2F11D5962DA59DAULL,
		0xC7EA4B181BC2BF70ULL,
		0xF3170009D36E57F9ULL,
		0x550E91BDCBBA5E86ULL,
		0x6AFDEDC53B15BE2AULL,
		0x37CE0C2EBF5A7A82ULL,
		0xB75AFCDDABBB59B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77A3AC0B9FA6C311ULL,
		0xB14CCC428309EEF6ULL,
		0xA6F9BA7910E90645ULL,
		0x2595D1654E60951DULL,
		0x176BAD4B79C4A656ULL,
		0xCF005CA3614735AAULL,
		0x544307CDD6B1DB4BULL,
		0x6F17A81BED9C426EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x51B1CC69F585431DULL,
		0x72806D208083CB40ULL,
		0xB328E70C48C47150ULL,
		0x0090ED7E28F1918EULL,
		0x06EB2E69C537CD6DULL,
		0x1119B321BE5AC746ULL,
		0x74D29CD7A92DA81BULL,
		0xD576D8ABBFDE5B78ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEFB5F7FF85B9A4BULL,
		0x57A51B26FE48E39FULL,
		0xC42B9C16508708B4ULL,
		0x6EA896556AB6CA25ULL,
		0x9176EA881418AF8EULL,
		0xC5FF46389A37E5BDULL,
		0x0F4203274AFF5AE3ULL,
		0x265F96CAE81F2FCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2B66CE9FD29A8D2ULL,
		0x1ADB51F9823AE7A0ULL,
		0xEEFD4AF5F83D689CULL,
		0x91E85728BE3AC768ULL,
		0x757443E1B11F1DDEULL,
		0x4B1A6CE92422E188ULL,
		0x659099B05E2E4D37ULL,
		0xAF1741E0D7BF2BAAULL
	}};
	sign = 0;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9F75BFF14D9CA90FULL,
		0xF62ED1195875401AULL,
		0x91AF98AA0DE7F0A4ULL,
		0x4B978788626E4288ULL,
		0x2130CBFB60B98CCFULL,
		0x53B55BB6E27E4A49ULL,
		0xB77021C62F384C7BULL,
		0x3AA219C22CA7879BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x25722FD6EB24CEEEULL,
		0x6648D60242B1C106ULL,
		0x06D73C52C9FE19F2ULL,
		0x9993FF354CC2D7D4ULL,
		0x62E9F93AAC17A5AEULL,
		0xA8D6B7BB04389DB2ULL,
		0xFA9FDF5A0F165078ULL,
		0x97D5DAC85C1025C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A03901A6277DA21ULL,
		0x8FE5FB1715C37F14ULL,
		0x8AD85C5743E9D6B2ULL,
		0xB203885315AB6AB4ULL,
		0xBE46D2C0B4A1E720ULL,
		0xAADEA3FBDE45AC96ULL,
		0xBCD0426C2021FC02ULL,
		0xA2CC3EF9D09761D4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x56FC062B70050731ULL,
		0xDFA07D8401D66110ULL,
		0x243D1762A0153892ULL,
		0x33335B91D44EAC29ULL,
		0x7733560F34A0CFEEULL,
		0x71998BA0F5280350ULL,
		0x3A1E15495D277551ULL,
		0x36B9DD060182E60BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BEC16F3592E105FULL,
		0xE468AE4D1D9BBDB9ULL,
		0x60709850714FCDC3ULL,
		0xDD51A7506AC09ACFULL,
		0xA61EF19E9B26E67FULL,
		0xFC87C09554806F57ULL,
		0x58FC56B9B7709E92ULL,
		0x7F47E44FA16CE054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B0FEF3816D6F6D2ULL,
		0xFB37CF36E43AA357ULL,
		0xC3CC7F122EC56ACEULL,
		0x55E1B441698E1159ULL,
		0xD11464709979E96EULL,
		0x7511CB0BA0A793F8ULL,
		0xE121BE8FA5B6D6BEULL,
		0xB771F8B6601605B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2E09253B21E666B3ULL,
		0xCAA5405D78BDB4FFULL,
		0xD956FD3EDB95AB31ULL,
		0xC3B91907C81CC399ULL,
		0x485F34A1FAF3F228ULL,
		0x0F66109FF15D2BDBULL,
		0x3D722560B9032F8BULL,
		0xCE6788D65D6C6B6DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2738D888C5BF4EE5ULL,
		0x3CCFB80A9FB78E00ULL,
		0x1E755BFDC9DEFC7CULL,
		0xF27115C33ECDAA73ULL,
		0x2F46FB004444D6EDULL,
		0xBC7C076B8BDC3C9DULL,
		0xF89FD356AED8E370ULL,
		0x7BD2E4E7E2D32D98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06D04CB25C2717CEULL,
		0x8DD58852D90626FFULL,
		0xBAE1A14111B6AEB5ULL,
		0xD1480344894F1926ULL,
		0x191839A1B6AF1B3AULL,
		0x52EA09346580EF3EULL,
		0x44D2520A0A2A4C1AULL,
		0x5294A3EE7A993DD4ULL
	}};
	sign = 0;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0670864394D3DFA7ULL,
		0xFC58ECBE40DBF100ULL,
		0x13FC12D5D0111654ULL,
		0xE3F508A214E3626CULL,
		0x140F95D6A76F474FULL,
		0x7FD9AA7543405763ULL,
		0x150C8E6FF439E796ULL,
		0xD389918F07780D8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7592DBD76881CB23ULL,
		0x033B7AFBB39E8A38ULL,
		0x7CCF57EC5DED2EDFULL,
		0x004F4F6423EDE3FDULL,
		0x06A301D8C8AFE343ULL,
		0xC8546C2782BB430EULL,
		0x0767C20D1C25D4E0ULL,
		0xD90256B5BE667622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90DDAA6C2C521484ULL,
		0xF91D71C28D3D66C7ULL,
		0x972CBAE97223E775ULL,
		0xE3A5B93DF0F57E6EULL,
		0x0D6C93FDDEBF640CULL,
		0xB7853E4DC0851455ULL,
		0x0DA4CC62D81412B5ULL,
		0xFA873AD94911976DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6890BDFDFA86EEC2ULL,
		0x8077CC59A3D1FFEBULL,
		0x80CC2A87F6C64B58ULL,
		0xCD269EF4B924EA74ULL,
		0xE203D201D396C5FBULL,
		0x61B6F18390DF518AULL,
		0x7D441FD32168EBF7ULL,
		0xC4D5B19151E639E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB80A108BC212B240ULL,
		0xFA2E043D70A56261ULL,
		0x4D40DF83C59AB2A5ULL,
		0x3AAA5BFD6074C53BULL,
		0xFCD95C00E5F7A775ULL,
		0xD17F74D96F5D6DC1ULL,
		0x04DFB2F9054AD4D4ULL,
		0xEDDA8B18FD4C0C87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB086AD7238743C82ULL,
		0x8649C81C332C9D89ULL,
		0x338B4B04312B98B2ULL,
		0x927C42F758B02539ULL,
		0xE52A7600ED9F1E86ULL,
		0x90377CAA2181E3C8ULL,
		0x78646CDA1C1E1722ULL,
		0xD6FB2678549A2D5EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8414B8BD15EACE74ULL,
		0xBDD683A16529313FULL,
		0xBB20BB4648867A78ULL,
		0x26947849CC8F147CULL,
		0x716A0662FFCF3F15ULL,
		0xFDCB77E189C07352ULL,
		0x955FB822741A4A00ULL,
		0x502376C2EB45C076ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D1D2FAD2BCF9E7ULL,
		0xE0ECDD5A379BC2FCULL,
		0x8DD41F97CC952141ULL,
		0x37C96155D68756D0ULL,
		0xC3E1496A14F2EF8AULL,
		0x87B0574C7902D0B3ULL,
		0xD9AEE353A9F11B9DULL,
		0xAFF7A1377EB17956ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E42E5C2432DD48DULL,
		0xDCE9A6472D8D6E43ULL,
		0x2D4C9BAE7BF15936ULL,
		0xEECB16F3F607BDACULL,
		0xAD88BCF8EADC4F8AULL,
		0x761B209510BDA29EULL,
		0xBBB0D4CECA292E63ULL,
		0xA02BD58B6C94471FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x34FA6B05C12FBF29ULL,
		0xC360D1A7AED889CDULL,
		0x102D9911EB0F6B87ULL,
		0x046521E07CAE72D0ULL,
		0x0F731C7A166F4441ULL,
		0x62DB9054E435A017ULL,
		0xE9AF47DAF9234B5BULL,
		0x21A61C27E1619FE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A4DEC70FCE77CCULL,
		0xDE3FDC8789DE5C8DULL,
		0x7910B325B1F2F4AFULL,
		0xFA70BA41C5D1086CULL,
		0x9556D997ECE1FCBEULL,
		0x455E86A306D0417BULL,
		0x0F7A00F964BBD2A3ULL,
		0xF8121087F9BCDC19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81558C3EB161475DULL,
		0xE520F52024FA2D3FULL,
		0x971CE5EC391C76D7ULL,
		0x09F4679EB6DD6A63ULL,
		0x7A1C42E2298D4782ULL,
		0x1D7D09B1DD655E9BULL,
		0xDA3546E1946778B8ULL,
		0x29940B9FE7A4C3C8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0240B28D4C32B1F6ULL,
		0x540AB435804F753CULL,
		0xA298EAE99FAC1AB4ULL,
		0xB80126779868CF98ULL,
		0xE0783C6C7E1DFEF7ULL,
		0xEDCBBE82D2958A08ULL,
		0x2AAAAE048AF3187CULL,
		0x3686AEE6F0D571C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5032965C5B651F46ULL,
		0xC7505C513B666B4AULL,
		0xDC3BFB8159EBB26FULL,
		0xB6C55D79F45A9BA3ULL,
		0xE72426F1B1BA4270ULL,
		0xF45B6978F9FCB6B7ULL,
		0x3CC92D2D2D4E007BULL,
		0x260545E2C4C6C2C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB20E1C30F0CD92B0ULL,
		0x8CBA57E444E909F1ULL,
		0xC65CEF6845C06844ULL,
		0x013BC8FDA40E33F4ULL,
		0xF954157ACC63BC87ULL,
		0xF9705509D898D350ULL,
		0xEDE180D75DA51800ULL,
		0x108169042C0EAF02ULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x230D02DD9959A3F3ULL,
		0x70A5E0487C6083D1ULL,
		0xDBD0B8D942E25E93ULL,
		0xA82CEDB326B0CE7CULL,
		0x133157025B8B9AB6ULL,
		0x65A31263204002DCULL,
		0x3510CF32624E3E62ULL,
		0xD7EC87324471A941ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD7C15D831F61ECULL,
		0x77459610C655D376ULL,
		0xC62D0C0CD0DB6A73ULL,
		0x844A80C79C3B0FE5ULL,
		0xD8D89A28C448B856ULL,
		0xE2146392FE253652ULL,
		0x7444E7E983672FE2ULL,
		0xB6CCEBBC63DA2D0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77354180163A4207ULL,
		0xF9604A37B60AB05AULL,
		0x15A3ACCC7206F41FULL,
		0x23E26CEB8A75BE97ULL,
		0x3A58BCD99742E260ULL,
		0x838EAED0221ACC89ULL,
		0xC0CBE748DEE70E7FULL,
		0x211F9B75E0977C36ULL
	}};
	sign = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC0B7A0C04CA9CF41ULL,
		0xAB65069B95496431ULL,
		0x84879842ED463EEBULL,
		0x27B405388D369694ULL,
		0xAEA319DBFEF419A8ULL,
		0xCA855DAD0A01BAF1ULL,
		0xF320AF7527721897ULL,
		0xF2BBC5A34FA83F27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B07AC8C1F4F6917ULL,
		0x69509B6EF189EE98ULL,
		0x26BE10B2159EBD4FULL,
		0x15D399836F5FC433ULL,
		0x36C9E0D7A325FDB7ULL,
		0x049CF6B4D14428DFULL,
		0x7466A06E4901A176ULL,
		0x0F65115FB0CBFEA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65AFF4342D5A662AULL,
		0x42146B2CA3BF7599ULL,
		0x5DC98790D7A7819CULL,
		0x11E06BB51DD6D261ULL,
		0x77D939045BCE1BF1ULL,
		0xC5E866F838BD9212ULL,
		0x7EBA0F06DE707721ULL,
		0xE356B4439EDC4085ULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDC1064AFEDF922F5ULL,
		0xFDE6FE5735D08C60ULL,
		0x2F460BDB5F077983ULL,
		0x357B8A62F46689DBULL,
		0x9146CE68E0CAD92BULL,
		0xF323356C28DF4757ULL,
		0x09FB6E02EB32B9DFULL,
		0x168F2EFDB0FB3A54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A05AB540B9F038AULL,
		0x52EE1868F382C56DULL,
		0xC7B969B707F93D1BULL,
		0x491A15EB1EC6D3C5ULL,
		0xA362A0EA137296ABULL,
		0xCAE518DC3C2B1352ULL,
		0xE8F676C679F248EBULL,
		0x178E0C3DB15811E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x920AB95BE25A1F6BULL,
		0xAAF8E5EE424DC6F3ULL,
		0x678CA224570E3C68ULL,
		0xEC617477D59FB615ULL,
		0xEDE42D7ECD58427FULL,
		0x283E1C8FECB43404ULL,
		0x2104F73C714070F4ULL,
		0xFF0122BFFFA32872ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x85539F6DD633F06EULL,
		0xBF49D7434C354D53ULL,
		0x46A0C1034F9C25A2ULL,
		0x214DF57442C80A8DULL,
		0x8F38464C1896607EULL,
		0x219667B8EE769D7CULL,
		0xF44D354FD0CB67F3ULL,
		0x588FE13A7DEE4ADAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD42AB6A2F47D7FF1ULL,
		0xF3B0D53B13BC732CULL,
		0x96F1A711B04F4B99ULL,
		0x9F1E0D54FA9C2F98ULL,
		0xF589525FED8FEC63ULL,
		0x491B3CEEA4A78827ULL,
		0xE96724B08339FE29ULL,
		0x19E20059E51D9348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB128E8CAE1B6707DULL,
		0xCB9902083878DA26ULL,
		0xAFAF19F19F4CDA08ULL,
		0x822FE81F482BDAF4ULL,
		0x99AEF3EC2B06741AULL,
		0xD87B2ACA49CF1554ULL,
		0x0AE6109F4D9169C9ULL,
		0x3EADE0E098D0B792ULL
	}};
	sign = 0;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7333B17774046A0CULL,
		0x4169EDB2A641D5D2ULL,
		0x91085AF35E4BEC1CULL,
		0xE257F368F5CB8AB3ULL,
		0xE682D6F0DAD2CE68ULL,
		0x0E2B2CBDEB4B5F4DULL,
		0xC158CBB7E512D638ULL,
		0x43F8A365D1E16417ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D314414147F828FULL,
		0x6CD600836D10DE31ULL,
		0x15CC1460EEEEFF56ULL,
		0xB7CA90405512F911ULL,
		0xF1F14386009A08FBULL,
		0xF2EE60C8AF08D822ULL,
		0x7477DAF24D08141AULL,
		0x53C8C15E731937C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46026D635F84E77DULL,
		0xD493ED2F3930F7A1ULL,
		0x7B3C46926F5CECC5ULL,
		0x2A8D6328A0B891A2ULL,
		0xF491936ADA38C56DULL,
		0x1B3CCBF53C42872AULL,
		0x4CE0F0C5980AC21DULL,
		0xF02FE2075EC82C56ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5DAEECD70425D9DAULL,
		0x0CF46BCCF3CD27B7ULL,
		0x95FFCF3A967D5B0FULL,
		0xC02E2AB09E82D2C1ULL,
		0x710223C2DA9AAD8FULL,
		0x9A16E5DD98BC7934ULL,
		0x5263A384DA0FD4ABULL,
		0x98D6676E11AAD3B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF12C31C718CC42FULL,
		0xA04C17401C2D7296ULL,
		0x6ADDF6335331BACDULL,
		0x4C1082898DF3E602ULL,
		0x405B273E88904601ULL,
		0xBDA949C0737E1C6BULL,
		0xFBE53EC4F4BF95A8ULL,
		0xD5097333E8DD65F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E9C29BA929915ABULL,
		0x6CA8548CD79FB520ULL,
		0x2B21D907434BA041ULL,
		0x741DA827108EECBFULL,
		0x30A6FC84520A678EULL,
		0xDC6D9C1D253E5CC9ULL,
		0x567E64BFE5503F02ULL,
		0xC3CCF43A28CD6DC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF5B13CFD8EF7C7D5ULL,
		0x5AB901B6D1ABED85ULL,
		0x67D70BD83A2D448FULL,
		0x108DBD3A8B37A76FULL,
		0xE49435976EA409B2ULL,
		0xB62DA8FC113E8903ULL,
		0xD6DB97CBA9D20CFEULL,
		0xA0ED6E886BC1C0F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF46928F41EA65C58ULL,
		0x407CAF0CF4712651ULL,
		0xDAF6FFC0B72EFC81ULL,
		0xD55D54FF36906365ULL,
		0x7092623B6C9FAEA5ULL,
		0x0BD00E3A78A53CD1ULL,
		0x0B5E2606853E5FEAULL,
		0x2E29837D80FD1449ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0148140970516B7DULL,
		0x1A3C52A9DD3AC734ULL,
		0x8CE00C1782FE480EULL,
		0x3B30683B54A74409ULL,
		0x7401D35C02045B0CULL,
		0xAA5D9AC198994C32ULL,
		0xCB7D71C52493AD14ULL,
		0x72C3EB0AEAC4ACABULL
	}};
	sign = 0;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x070AE7A912264BDAULL,
		0x33B45982628081D4ULL,
		0x31B9ED66D0870F4FULL,
		0xA8A275D022878AAFULL,
		0x202E9427B3D33D90ULL,
		0x58FB058DB42ECCE8ULL,
		0xA642F98080E9BA54ULL,
		0x185CCBBB7963CA6FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34138F0B68C2CD81ULL,
		0x14DF4F17E8646AEBULL,
		0xC478E649A4CEC988ULL,
		0xB1AED8BC0BFAE908ULL,
		0x753D2C758AA3418FULL,
		0x5941BF5F4D8DECCAULL,
		0xBB6E946A9E37F455ULL,
		0x9967B5147C6AA16FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2F7589DA9637E59ULL,
		0x1ED50A6A7A1C16E8ULL,
		0x6D41071D2BB845C7ULL,
		0xF6F39D14168CA1A6ULL,
		0xAAF167B2292FFC00ULL,
		0xFFB9462E66A0E01DULL,
		0xEAD46515E2B1C5FEULL,
		0x7EF516A6FCF928FFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE476C72F6F878E03ULL,
		0x8437A4E536CA1491ULL,
		0x6F23F1D2BC5C7736ULL,
		0x76EFBEADDD17355CULL,
		0xE170BC29548A3016ULL,
		0x298B0050BFD5FA34ULL,
		0x0209472E35D407D2ULL,
		0x98EE3197FD08F782ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8FF3F3013719032ULL,
		0x426B5C69AEC50D3CULL,
		0x8A756244D2D2EC79ULL,
		0xF22D1DDFAAA655CEULL,
		0x4CBC5FD0862D764BULL,
		0xCD9BA089B19821D7ULL,
		0x4E5E9A3343ACC146ULL,
		0xC415CCF2CA5C1C14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B7787FF5C15FDD1ULL,
		0x41CC487B88050755ULL,
		0xE4AE8F8DE9898ABDULL,
		0x84C2A0CE3270DF8DULL,
		0x94B45C58CE5CB9CAULL,
		0x5BEF5FC70E3DD85DULL,
		0xB3AAACFAF227468BULL,
		0xD4D864A532ACDB6DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D731AA36D95F935ULL,
		0x0830F55645412E93ULL,
		0x16BBE7B30D3DEA48ULL,
		0xE6600A9078BBF5BDULL,
		0x88074441B582917EULL,
		0xD891CE87CF914C11ULL,
		0x6B98905D3CC494E6ULL,
		0x371C8F7E3C002BDAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE21693641C6AA93ULL,
		0xDD4DF470990B071FULL,
		0xF84B39646C7DA5DEULL,
		0x40BEC68B23813E91ULL,
		0x732767552D5164C6ULL,
		0xB2E262E09420256EULL,
		0xE762E8250CC1FA37ULL,
		0xA7DBD96C54F8C5E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F51B16D2BCF4EA2ULL,
		0x2AE300E5AC362773ULL,
		0x1E70AE4EA0C04469ULL,
		0xA5A14405553AB72BULL,
		0x14DFDCEC88312CB8ULL,
		0x25AF6BA73B7126A3ULL,
		0x8435A83830029AAFULL,
		0x8F40B611E70765F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD333A5846287E14DULL,
		0x4AD73EDED5D5F319ULL,
		0xB6CDDFB54FDB7D77ULL,
		0x404CDD2BD17163ABULL,
		0x4B0BC94A4C656904ULL,
		0xD339F876CAD0BDE7ULL,
		0xB2F99379C6E5D4DCULL,
		0x038124561FD3606CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x308A217A4FB6D6F3ULL,
		0xF31F37D9357077CCULL,
		0x9E052452A2F5BF76ULL,
		0x30F948EDBF113177ULL,
		0x4EA097B670625D9CULL,
		0xB03D2E270F7C5E76ULL,
		0x192E498B9BBF84AAULL,
		0x6EA9222329F8FAE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2A9840A12D10A5AULL,
		0x57B80705A0657B4DULL,
		0x18C8BB62ACE5BE00ULL,
		0x0F53943E12603234ULL,
		0xFC6B3193DC030B68ULL,
		0x22FCCA4FBB545F70ULL,
		0x99CB49EE2B265032ULL,
		0x94D80232F5DA6588ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE0850821D43D548FULL,
		0x767F34D115C440BEULL,
		0x6B057B8E0316EBB9ULL,
		0x0E5D8D5D76ED2E25ULL,
		0xC96C280243241C52ULL,
		0x3232457E216109C6ULL,
		0xE7E486C2D3511376ULL,
		0x3A617199DC2C779BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA92F4089BC11807ULL,
		0x988ED854B429CC58ULL,
		0xA07631E8CFF367CDULL,
		0x04BA17F3DB3B4BC7ULL,
		0xB3C8CC4CE1010548ULL,
		0xF1335A0BE15E5688ULL,
		0xED8D225ABC075276ULL,
		0x1F6C8619427F1FD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25F21419387C3C88ULL,
		0xDDF05C7C619A7466ULL,
		0xCA8F49A5332383EBULL,
		0x09A375699BB1E25DULL,
		0x15A35BB56223170AULL,
		0x40FEEB724002B33EULL,
		0xFA5764681749C0FFULL,
		0x1AF4EB8099AD57C1ULL
	}};
	sign = 0;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x09967C7E2F36FFE7ULL,
		0x4B719E89EF7D38F2ULL,
		0x0F2543FF7A2E2204ULL,
		0x29236E04F99BCE7FULL,
		0xC889A41D5A8B6C27ULL,
		0x3FACF05CC901D2F5ULL,
		0x5E53B427AAD0B888ULL,
		0x3E94F95CC044B4DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C092905A28CD5CULL,
		0xB4EB78FD138AACC6ULL,
		0xC7E44479A21F7229ULL,
		0x7BBF35443ACF3A47ULL,
		0xC7B63A57C621FD64ULL,
		0x7C9FCE0EB612D323ULL,
		0xDAC0A8B8E0AF7364ULL,
		0x1DA5A9E4DF62446FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6D5E9EDD50E328BULL,
		0x9686258CDBF28C2BULL,
		0x4740FF85D80EAFDAULL,
		0xAD6438C0BECC9437ULL,
		0x00D369C594696EC2ULL,
		0xC30D224E12EEFFD2ULL,
		0x83930B6ECA214523ULL,
		0x20EF4F77E0E2706EULL
	}};
	sign = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0A4840B7368CDAD3ULL,
		0x05D469D59D485F48ULL,
		0xB9BE8A7FE23FBD71ULL,
		0x4CECC1AD1CAF0C78ULL,
		0x363888D7677E43BEULL,
		0xFCEAF04FC4491AD1ULL,
		0x3C7C12DD5F831A91ULL,
		0x165CF1B1CED6FBC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x07813A8C256EE573ULL,
		0xCB7BD2C53C051881ULL,
		0x84A5F26289B7FFBFULL,
		0x634FDF9A6F15BD2BULL,
		0x6A079E8631247BEFULL,
		0x89FE47D8D3B0D82EULL,
		0x5A4C07F072A47AA8ULL,
		0x8E0B826225877C81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02C7062B111DF560ULL,
		0x3A589710614346C7ULL,
		0x3518981D5887BDB1ULL,
		0xE99CE212AD994F4DULL,
		0xCC30EA513659C7CEULL,
		0x72ECA876F09842A2ULL,
		0xE2300AECECDE9FE9ULL,
		0x88516F4FA94F7F42ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82324C0564BB04DCULL,
		0x8FB4FE320CF23C17ULL,
		0x5EFE2C2B402A4051ULL,
		0x8AA8073AC64450D8ULL,
		0x3C239AB3C9116A2DULL,
		0x416B8194649B4FE4ULL,
		0x4A59E5AA6EC70D65ULL,
		0x175666329663BAABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD6C8F3EF0A82F5CULL,
		0x06CE532A5578D926ULL,
		0xFE1F5C969132709FULL,
		0x1141A3E87578FA91ULL,
		0xA4B1788A91F22E01ULL,
		0xF6B197C7189DBDB8ULL,
		0xE9B022E4640FF1E6ULL,
		0x228886722F23DC78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4C5BCC67412D580ULL,
		0x88E6AB07B77962F0ULL,
		0x60DECF94AEF7CFB2ULL,
		0x7966635250CB5646ULL,
		0x97722229371F3C2CULL,
		0x4AB9E9CD4BFD922BULL,
		0x60A9C2C60AB71B7EULL,
		0xF4CDDFC0673FDE32ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3568F580C573E474ULL,
		0x11DDB10E0575024AULL,
		0x094FAF73C3E67F64ULL,
		0x62B3F0399440AFCAULL,
		0x4E751D1D64FE6F1DULL,
		0x36889922D493B5ABULL,
		0xD318811A1D4E17CCULL,
		0xEBE0B5E701B72765ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D8555EE81456051ULL,
		0x4635731E1C66F797ULL,
		0x18E5BAA39039CC12ULL,
		0x43E4F53B63E89ADEULL,
		0xA0E375880C79638EULL,
		0x95179F5AE135146EULL,
		0x8C438826336E60E5ULL,
		0x40AB64AC68E06085ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7E39F92442E8423ULL,
		0xCBA83DEFE90E0AB2ULL,
		0xF069F4D033ACB351ULL,
		0x1ECEFAFE305814EBULL,
		0xAD91A79558850B8FULL,
		0xA170F9C7F35EA13CULL,
		0x46D4F8F3E9DFB6E6ULL,
		0xAB35513A98D6C6E0ULL
	}};
	sign = 0;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9B8B720CB06E6FF2ULL,
		0xF598CE1765FDD453ULL,
		0x11081C92B48D4675ULL,
		0x686C3C18953F5837ULL,
		0x7ADF9EE67C15D44AULL,
		0x47E6A6A499369486ULL,
		0x520A079DAEB9E589ULL,
		0x14C2BAE007026D9DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x898BAFC25A8CBCC4ULL,
		0xF203860E11F730E7ULL,
		0xE1062A3AAE77932DULL,
		0xDE6B30A854B942B2ULL,
		0xB9AEAD4214780374ULL,
		0xA3852D70AFAD5DC6ULL,
		0xBDD9DB833BA813C5ULL,
		0xA03A32E4E58C2397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11FFC24A55E1B32EULL,
		0x039548095406A36CULL,
		0x3001F2580615B348ULL,
		0x8A010B7040861584ULL,
		0xC130F1A4679DD0D5ULL,
		0xA4617933E98936BFULL,
		0x94302C1A7311D1C3ULL,
		0x748887FB21764A05ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4154B6CF17568726ULL,
		0xCDC45AAF368DF7C9ULL,
		0x758DC3BEAF34493DULL,
		0xE6FADAAD8840B1E8ULL,
		0x5EB1EEABD0C4CB37ULL,
		0x82224F6CF12B376BULL,
		0x0A7BD7791368F9CEULL,
		0x3407A21C778FF1F7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC32D95E34098CAULL,
		0xC3A00C540354291CULL,
		0x924EE177656D6B47ULL,
		0x952E66ED0B96508EULL,
		0x56F2564B06D0317DULL,
		0xCAA8782EB2D141DFULL,
		0x2C571C69E85E99D8ULL,
		0xD09581BF2E271206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA19189393415EE5CULL,
		0x0A244E5B3339CEACULL,
		0xE33EE24749C6DDF6ULL,
		0x51CC73C07CAA6159ULL,
		0x07BF9860C9F499BAULL,
		0xB779D73E3E59F58CULL,
		0xDE24BB0F2B0A5FF5ULL,
		0x6372205D4968DFF0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC66E17B5588D2974ULL,
		0x511A0D6FC49B6862ULL,
		0x0F229E8B3B37103DULL,
		0x452778767ADDB59EULL,
		0xD263E3E889FBD899ULL,
		0xED7D460BC56F896BULL,
		0x8AC24F957A006C8AULL,
		0xDA0BA994ED4EB069ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ACA8D75FFF9FC8BULL,
		0x33405948C00EA710ULL,
		0x3DC02F2A0E285C88ULL,
		0x47C1E97909D945FAULL,
		0x95E55B2FB099FE23ULL,
		0x595553745CCBBF17ULL,
		0x25429DB645D35F54ULL,
		0xB2D290CCB116BF28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BA38A3F58932CE9ULL,
		0x1DD9B427048CC152ULL,
		0xD1626F612D0EB3B5ULL,
		0xFD658EFD71046FA3ULL,
		0x3C7E88B8D961DA75ULL,
		0x9427F29768A3CA54ULL,
		0x657FB1DF342D0D36ULL,
		0x273918C83C37F141ULL
	}};
	sign = 0;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1AA7AAAF0B384EDFULL,
		0x9F7624BD81F7D63DULL,
		0xA54AA12C1BCF4A26ULL,
		0x00B3DB65823B24BFULL,
		0x74E84C0EA526FFAAULL,
		0xFDA6087822480A20ULL,
		0x1CAEE2E74FB0311CULL,
		0x78E2D2DF32EC6DFDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7476C7F6F005CA74ULL,
		0x4704108BD6E40530ULL,
		0xD0495E97778C38DCULL,
		0x38EA52F7BC66A04BULL,
		0x5C4BC2C95B8A6E4CULL,
		0x8E3D3512A9BCE481ULL,
		0xFE8AFD2245436651ULL,
		0x2F7F5D8C2DFE463BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA630E2B81B32846BULL,
		0x58721431AB13D10CULL,
		0xD5014294A443114AULL,
		0xC7C9886DC5D48473ULL,
		0x189C8945499C915DULL,
		0x6F68D365788B259FULL,
		0x1E23E5C50A6CCACBULL,
		0x4963755304EE27C1ULL
	}};
	sign = 0;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x95876A2E4A3EC41AULL,
		0x69F586268E0518ACULL,
		0xF9281FAC6FA25387ULL,
		0x3F309F9099EB9E39ULL,
		0x264C07A48DBDD4F0ULL,
		0x2D8C6F1649A988B7ULL,
		0x9019683BA583380CULL,
		0xE7B5E26925ED84C9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3A3B0E04AECDDFULL,
		0x77399FBB13A4766EULL,
		0x4A120BA8A138B753ULL,
		0x29D8E1EEF819187EULL,
		0xA9236CDE6FB7B816ULL,
		0x194D09900589E5E4ULL,
		0x98D8189B649299BDULL,
		0xD53700674808EA63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE94D2F20458FF63BULL,
		0xF2BBE66B7A60A23DULL,
		0xAF161403CE699C33ULL,
		0x1557BDA1A1D285BBULL,
		0x7D289AC61E061CDAULL,
		0x143F6586441FA2D2ULL,
		0xF7414FA040F09E4FULL,
		0x127EE201DDE49A65ULL
	}};
	sign = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEA984FF2F474C018ULL,
		0x5B418A7F755865E2ULL,
		0xBF41534032FA09F9ULL,
		0xAFCDCC970E920DC0ULL,
		0x170A9E055E2676A6ULL,
		0x47F4DD8F63BA0277ULL,
		0xAE7AB0144E787017ULL,
		0x3C51D5C505A83867ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0397FFE05299763ULL,
		0xF1665DC7F1C3A3C9ULL,
		0x6C93BDBD3498648FULL,
		0x4CF3532311490D1CULL,
		0x0D851A1E8585CE65ULL,
		0x3C00F57DDB6B7CB0ULL,
		0xA1B7D50E66D3E32CULL,
		0x73C6D8ABE2AE87A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A5ECFF4EF4B28B5ULL,
		0x69DB2CB78394C219ULL,
		0x52AD9582FE61A569ULL,
		0x62DA7973FD4900A4ULL,
		0x098583E6D8A0A841ULL,
		0x0BF3E811884E85C7ULL,
		0x0CC2DB05E7A48CEBULL,
		0xC88AFD1922F9B0C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x42EE2FC4422A54E1ULL,
		0x41A442738711BDBDULL,
		0xBF3C8EAB8CB2439AULL,
		0x54AA2E4C80F1DFD3ULL,
		0x7A4CDB2C0910E7FDULL,
		0x36658079EF4DAA7DULL,
		0xE558EAC267F82DC3ULL,
		0x66004627C4B8D4C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC06D78F531989FAFULL,
		0x9905996A6F5A6CC1ULL,
		0xD7C230E8AF8D0DF9ULL,
		0x342137B0C2671010ULL,
		0x29C4162CCB860973ULL,
		0x223B44F74A0F40A6ULL,
		0x52ED8F4147CADD6CULL,
		0x9139D0873963FEC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8280B6CF1091B532ULL,
		0xA89EA90917B750FBULL,
		0xE77A5DC2DD2535A0ULL,
		0x2088F69BBE8ACFC2ULL,
		0x5088C4FF3D8ADE8AULL,
		0x142A3B82A53E69D7ULL,
		0x926B5B81202D5057ULL,
		0xD4C675A08B54D5FFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x044E108FE9596DFDULL,
		0x96A9B506A0B3A8C8ULL,
		0x82715DA6296543E8ULL,
		0xF7F2FD2A1C6E30AAULL,
		0xAB8DC69C15C3C77EULL,
		0x4845FAA4105B9D41ULL,
		0x20C34E3C43CE0796ULL,
		0x142D44A31D879B6CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x135086286DC2473BULL,
		0x73F5FF943CEBE357ULL,
		0xF50D5730F6AE565AULL,
		0xAD060FD67EBF1D9FULL,
		0xA6765C47DF6ED341ULL,
		0x68D1E3A9F2A9C1C3ULL,
		0x0E14E45FEE189D1FULL,
		0x540BAFE5D7A2F83DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0FD8A677B9726C2ULL,
		0x22B3B57263C7C570ULL,
		0x8D64067532B6ED8EULL,
		0x4AECED539DAF130AULL,
		0x05176A543654F43DULL,
		0xDF7416FA1DB1DB7EULL,
		0x12AE69DC55B56A76ULL,
		0xC02194BD45E4A32FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55BEC528EFC0E9E0ULL,
		0x82270C054A39BD76ULL,
		0xCFAB8AEA38E6C4EAULL,
		0x0D41A5C7C568BF94ULL,
		0xC3537795458CD98AULL,
		0x5F44BF7BE9D41ED6ULL,
		0xA3FCD79D64CC8F4AULL,
		0xA3B3F8181CC76B03ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32623C2E4D2BD673ULL,
		0x48CFFC28624B9FB7ULL,
		0x462AEFFA6D08000CULL,
		0x2E925C6C8CCECB5BULL,
		0xF0862507D1358EE8ULL,
		0x3367C504A6995FACULL,
		0x6A5FBDDCF8F9360EULL,
		0xB73C266F280F14EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235C88FAA295136DULL,
		0x39570FDCE7EE1DBFULL,
		0x89809AEFCBDEC4DEULL,
		0xDEAF495B3899F439ULL,
		0xD2CD528D74574AA1ULL,
		0x2BDCFA77433ABF29ULL,
		0x399D19C06BD3593CULL,
		0xEC77D1A8F4B85619ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0E04E580B5587846ULL,
		0x3C27C71E8C7A28A4ULL,
		0xD5080670939400C0ULL,
		0x9BE9F611841331ABULL,
		0x84D7A746AA18B118ULL,
		0x17F8FFD32C042CA2ULL,
		0x0D7B444FBB8454CFULL,
		0x415C5D20A3621FBDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x15DFEE33823E8922ULL,
		0x4A63A0A6D05B648CULL,
		0x88DACA3D9DB004FDULL,
		0x07B9A6685430F858ULL,
		0x1472807FDBFC3C7CULL,
		0xE980DBA00D3591F6ULL,
		0x6E105FA36D3D8967ULL,
		0xDEA9DD7B64C826C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF824F74D3319EF24ULL,
		0xF1C42677BC1EC417ULL,
		0x4C2D3C32F5E3FBC2ULL,
		0x94304FA92FE23953ULL,
		0x706526C6CE1C749CULL,
		0x2E7824331ECE9AACULL,
		0x9F6AE4AC4E46CB67ULL,
		0x62B27FA53E99F8F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCBA2882A740F7A92ULL,
		0x685F6E23D20D66FBULL,
		0x25120D6D24EC698AULL,
		0xEEC7186C89F0F9C8ULL,
		0x50CA683601C492C0ULL,
		0xD39D015F73BF2508ULL,
		0x8DE473394A7490C8ULL,
		0xFC654E800F6A3839ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x921C8132705C6767ULL,
		0x4712F6CF67E65320ULL,
		0x0746F1DF539A7E89ULL,
		0x2C732AD879FB4CC8ULL,
		0x03A9A789FD62C782ULL,
		0xC1959C7C0AEC4E26ULL,
		0x53E81DCFB14940C8ULL,
		0xFD29BA9A4D8FDF61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x398606F803B3132BULL,
		0x214C77546A2713DBULL,
		0x1DCB1B8DD151EB01ULL,
		0xC253ED940FF5AD00ULL,
		0x4D20C0AC0461CB3EULL,
		0x120764E368D2D6E2ULL,
		0x39FC5569992B5000ULL,
		0xFF3B93E5C1DA58D8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x02A059155BE5E1F7ULL,
		0x7C1A6047A182D323ULL,
		0x86A8C7B599D67751ULL,
		0x6EA55EDCF2FFCF4FULL,
		0xAAA8F034EBF2CF07ULL,
		0x50BDAB15557CE50DULL,
		0x18BC2BC1377552F2ULL,
		0x950F53171F86DB72ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7CD1159ECDC0493ULL,
		0xA215356825A9BD53ULL,
		0x052403CB7BCA2A36ULL,
		0x25F0C9FB0F3CC0F8ULL,
		0x2274410C62977EF3ULL,
		0xF73692A54044A759ULL,
		0x7407ADE7F39165EDULL,
		0xA4735A72B38B41F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AD347BB6F09DD64ULL,
		0xDA052ADF7BD915CFULL,
		0x8184C3EA1E0C4D1AULL,
		0x48B494E1E3C30E57ULL,
		0x8834AF28895B5014ULL,
		0x5987187015383DB4ULL,
		0xA4B47DD943E3ED04ULL,
		0xF09BF8A46BFB997AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x69D4A55B387EDBF5ULL,
		0x438690C22BF4856EULL,
		0x54C02BF78F0937F3ULL,
		0xE65B3278075258D1ULL,
		0x1BE7974C28FF9859ULL,
		0x59E156C1F6C14AE3ULL,
		0x4CFE1E276A2179D4ULL,
		0x6B8E9C42F93E844FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC06AC636822C6A3EULL,
		0xB9DC2D1DC935C7B1ULL,
		0xDEDFCC4EA85664E2ULL,
		0x5821F167C3C1DDA3ULL,
		0x2B21347539080BFBULL,
		0x33A0FBC7977E4418ULL,
		0xA88093EE5098918DULL,
		0x3875443DB18A9B03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA969DF24B65271B7ULL,
		0x89AA63A462BEBDBCULL,
		0x75E05FA8E6B2D310ULL,
		0x8E39411043907B2DULL,
		0xF0C662D6EFF78C5EULL,
		0x26405AFA5F4306CAULL,
		0xA47D8A391988E847ULL,
		0x3319580547B3E94BULL
	}};
	sign = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x752992E0C15D96A2ULL,
		0xB41EA64C7C085209ULL,
		0x6E5AF5DE7A912AA9ULL,
		0xDFE3514E58EDD33AULL,
		0x40A8F6762F00726AULL,
		0x5E84BA12C345389BULL,
		0x5A7CDADE08FF2777ULL,
		0xB7389C053A4C5FBEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AFCDC2FE36973EAULL,
		0xCDCF17BA2E2E2F90ULL,
		0xC30864A76CE57E1DULL,
		0xBA2F45965A1D8330ULL,
		0x22EECE12D6CDBD6FULL,
		0x4FDDA3975FB3E708ULL,
		0xBE4AAA7B95FBB700ULL,
		0x12E4EF28051927ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A2CB6B0DDF422B8ULL,
		0xE64F8E924DDA2279ULL,
		0xAB5291370DABAC8BULL,
		0x25B40BB7FED05009ULL,
		0x1DBA28635832B4FBULL,
		0x0EA7167B63915193ULL,
		0x9C32306273037077ULL,
		0xA453ACDD35333810ULL
	}};
	sign = 0;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x806A1C81D4B13933ULL,
		0x68FC03F8B7E6CC76ULL,
		0x52C2C284B028E8BFULL,
		0x65FD110CAC3ED843ULL,
		0x6CE24A1D224C3226ULL,
		0x613AEF6BEBEC7339ULL,
		0x5FEBD26089B099F3ULL,
		0xB8673CF539ACEF13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1830E035B89C8EEULL,
		0x6369B966D8D1B2BBULL,
		0x2DE01B5AAC04BDD3ULL,
		0x3EC5B3848516E080ULL,
		0xCD7AD421743A9B58ULL,
		0xDCB628E6D9F94A90ULL,
		0x630C34AB506587D7ULL,
		0x209F2C05A474DA09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEE70E7E79277045ULL,
		0x05924A91DF1519BAULL,
		0x24E2A72A04242AECULL,
		0x27375D882727F7C3ULL,
		0x9F6775FBAE1196CEULL,
		0x8484C68511F328A8ULL,
		0xFCDF9DB5394B121BULL,
		0x97C810EF95381509ULL
	}};
	sign = 0;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBDCA468ED3D69779ULL,
		0x0EBD57E7CCA3CB34ULL,
		0xDB2647F56F2A9A37ULL,
		0x5CFBD6201FD73557ULL,
		0x2438A56F8902C69FULL,
		0xAD4020C25F8EE6DEULL,
		0xF620CF08948B82BFULL,
		0xABA7CE05FFAAA721ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F68833EBAF1CA13ULL,
		0xD3483B25E3ABCE3DULL,
		0x3FB581CD64AD8406ULL,
		0x77616FDD8DC76E4CULL,
		0x64530C66D98CFB85ULL,
		0x6DEF30896784A97BULL,
		0x3465FDFD0DF4520BULL,
		0xBAA23EF32E39A56FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E61C35018E4CD66ULL,
		0x3B751CC1E8F7FCF7ULL,
		0x9B70C6280A7D1630ULL,
		0xE59A6642920FC70BULL,
		0xBFE59908AF75CB19ULL,
		0x3F50F038F80A3D62ULL,
		0xC1BAD10B869730B4ULL,
		0xF1058F12D17101B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x12F6920F6215F8DEULL,
		0x67BCC828EF271E03ULL,
		0xD0A898EA52D6A874ULL,
		0x7A8FE5F0C68DF1E8ULL,
		0x6C56A860872D7BA4ULL,
		0xE5847698AD91AE12ULL,
		0x47D79704FF9DF690ULL,
		0x99FE6BE9FABEC7CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA798260E48565D56ULL,
		0x776BDE41A703ADAEULL,
		0x76DABC4504A4BC65ULL,
		0x5A12F52CBB58D023ULL,
		0x11762C28006D0BB5ULL,
		0x1DA3F7132CF46308ULL,
		0xD86F299118A12863ULL,
		0x3638E1B2974862C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B5E6C0119BF9B88ULL,
		0xF050E9E748237054ULL,
		0x59CDDCA54E31EC0EULL,
		0x207CF0C40B3521C5ULL,
		0x5AE07C3886C06FEFULL,
		0xC7E07F85809D4B0AULL,
		0x6F686D73E6FCCE2DULL,
		0x63C58A3763766504ULL
	}};
	sign = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x776D1CA3F74C680BULL,
		0x1812FBFCB2F812A2ULL,
		0x89414F96490FE4ADULL,
		0xEB88DD49B358CB06ULL,
		0xE56AA40FEF77097EULL,
		0xDB016278A956A7D2ULL,
		0xFE4B11CC86B42DD8ULL,
		0x41D760591E974FA4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB5EAB28FAD08DB9ULL,
		0x751AAF92A877B5E2ULL,
		0xA4CC230EA94B2264ULL,
		0x6B10E4DFC4ED75B1ULL,
		0xF9C9226C2A9B7CB5ULL,
		0x83B4665D211F90E4ULL,
		0x4CB429A03127C8FDULL,
		0x215030F5835031B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC0E717AFC7BDA52ULL,
		0xA2F84C6A0A805CBFULL,
		0xE4752C879FC4C248ULL,
		0x8077F869EE6B5554ULL,
		0xEBA181A3C4DB8CC9ULL,
		0x574CFC1B883716EDULL,
		0xB196E82C558C64DBULL,
		0x20872F639B471DEDULL
	}};
	sign = 0;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA9059C7FDDF28C72ULL,
		0x5F80DE475665680CULL,
		0x52F81893FEBC6693ULL,
		0x332FB0D8D9A6F6F4ULL,
		0xBB69906CCE06C184ULL,
		0x23F9C57ED3879C61ULL,
		0x5AFEB47CC84AC4C8ULL,
		0xCAE31A4A5CE7DB6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA611240EAD98AFCULL,
		0xFA90638E69DDCADFULL,
		0x9F40374D8FC081CAULL,
		0xFCF2ED20A24C113DULL,
		0x74B41F9D9CBB57A5ULL,
		0x944A9B82D0334B82ULL,
		0x6C1F7FCB0672B2AAULL,
		0x48BC3E6F8E267BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEA48A3EF3190176ULL,
		0x64F07AB8EC879D2CULL,
		0xB3B7E1466EFBE4C8ULL,
		0x363CC3B8375AE5B6ULL,
		0x46B570CF314B69DEULL,
		0x8FAF29FC035450DFULL,
		0xEEDF34B1C1D8121DULL,
		0x8226DBDACEC15F83ULL
	}};
	sign = 0;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA7711D0E56BC07CEULL,
		0x12C2F51D4C15D5E2ULL,
		0xB0B63EE5126F9431ULL,
		0x9119A43F133C868DULL,
		0xB992C9B08D800A36ULL,
		0x3A9FA75EE127CB68ULL,
		0x1886416C202901A4ULL,
		0x7031D3AD4BC21CC3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEF32E2AB04D67B5ULL,
		0xD2AA4B7DDBF960EEULL,
		0x0CABC123D7D0FBB0ULL,
		0x2F3FD15F12BA3405ULL,
		0x5D92B392FE0C3012ULL,
		0xFB37F5A74B6FDB5AULL,
		0xC67053355B6E9160ULL,
		0x79A5F731A2C0213EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB87DEEE3A66EA019ULL,
		0x4018A99F701C74F3ULL,
		0xA40A7DC13A9E9880ULL,
		0x61D9D2E000825288ULL,
		0x5C00161D8F73DA24ULL,
		0x3F67B1B795B7F00EULL,
		0x5215EE36C4BA7043ULL,
		0xF68BDC7BA901FB84ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF58534CDD9D7216BULL,
		0x266F8A7F9BAF900CULL,
		0xCFEE657771E17366ULL,
		0x1772FF2DD770A4C7ULL,
		0x6BAD98F56CA209FDULL,
		0xD08F2ADEFD059F7FULL,
		0x6DB4235DF4CEE91CULL,
		0xB00781B9D463AD5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E763E8B48296ACULL,
		0xCF48A0D3D82A13E7ULL,
		0x051A10A191B2C19BULL,
		0x2EFC5098D2560515ULL,
		0x831258A3D333FDEAULL,
		0x7446AE47D89D13C8ULL,
		0x8654F732A39D8834ULL,
		0xC1A023D2BE612D36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC9DD0E525548ABFULL,
		0x5726E9ABC3857C25ULL,
		0xCAD454D5E02EB1CAULL,
		0xE876AE95051A9FB2ULL,
		0xE89B4051996E0C12ULL,
		0x5C487C9724688BB6ULL,
		0xE75F2C2B513160E8ULL,
		0xEE675DE716028027ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA1914A2B90AFC8F9ULL,
		0x968540F9ED0BE38DULL,
		0x107A212DB0C40B58ULL,
		0x8AF73B65F91DBA9AULL,
		0x6983F2103FD170B2ULL,
		0x8E35CC5647821DD1ULL,
		0xF5836CEC7ADB4C64ULL,
		0xC3A1611C0BB39ECDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CE5EEAADA8A3CE6ULL,
		0x98A44B5D36787BA6ULL,
		0xE612D5967DE01B7AULL,
		0xFF224DA93C3577EEULL,
		0x7B0F0F1E14F277EFULL,
		0xD66A8A496A644D06ULL,
		0x1CB072DF59077BA5ULL,
		0x41BC1F5B68CB5ABBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04AB5B80B6258C13ULL,
		0xFDE0F59CB69367E7ULL,
		0x2A674B9732E3EFDDULL,
		0x8BD4EDBCBCE842ABULL,
		0xEE74E2F22ADEF8C2ULL,
		0xB7CB420CDD1DD0CAULL,
		0xD8D2FA0D21D3D0BEULL,
		0x81E541C0A2E84412ULL
	}};
	sign = 0;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x19100F506A3FF38DULL,
		0x5B070F05481B78E8ULL,
		0xFF6605030EF1BBA4ULL,
		0x59D08A82F747959DULL,
		0xD29E2E1E9583FEF7ULL,
		0xEC7970D1D3593F18ULL,
		0xD52321CABE40F002ULL,
		0x841984D3668F500DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x027EA63D0D0FF309ULL,
		0xEFA16C6D21036055ULL,
		0xDEBDBA69132AD991ULL,
		0x3FE6E16569B3887FULL,
		0x5A9776415B4B2821ULL,
		0x94FF10E8DAB1EE28ULL,
		0xA7342D3D361ACE5BULL,
		0x9C4C65568A4576D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x169169135D300084ULL,
		0x6B65A29827181893ULL,
		0x20A84A99FBC6E212ULL,
		0x19E9A91D8D940D1EULL,
		0x7806B7DD3A38D6D6ULL,
		0x577A5FE8F8A750F0ULL,
		0x2DEEF48D882621A7ULL,
		0xE7CD1F7CDC49D93DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x75FC7ED3938CA1B2ULL,
		0x4D11590971605C26ULL,
		0xCFFA051DE1E91ACAULL,
		0xF5F0946AA772C73DULL,
		0xDF10A9783FC6C855ULL,
		0xCF04B26EAFB45EB0ULL,
		0x51FDE6ABAB0C0DBFULL,
		0xDD1F903A7DF7CF6DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A7299DF0DF6CA1ULL,
		0xE54C6BE78AE5408BULL,
		0xC0938DE291E297AAULL,
		0x6C2F184861D686C0ULL,
		0xBB1CDD5549344C2CULL,
		0x7B25C4D1A54E10C8ULL,
		0x62CB0F970F7DA0F4ULL,
		0xD079412F48726EA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5555535A2AD3511ULL,
		0x67C4ED21E67B1B9AULL,
		0x0F66773B5006831FULL,
		0x89C17C22459C407DULL,
		0x23F3CC22F6927C29ULL,
		0x53DEED9D0A664DE8ULL,
		0xEF32D7149B8E6CCBULL,
		0x0CA64F0B358560C7ULL
	}};
	sign = 0;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x91EB5BE34EF20436ULL,
		0xC5E74E6FF90EFB4CULL,
		0x4DF0A25C087093BBULL,
		0x0A1879558E6F1AE6ULL,
		0x014AE108A1A2162CULL,
		0x0EBA75014D4C23D9ULL,
		0xDE70FE6BA72DA288ULL,
		0x6832DCF29D52A1F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47839DF2791A5FB2ULL,
		0x9D74E733AC3C9CB4ULL,
		0x1E2A530E774FCB2DULL,
		0x820EA4AB3952C37BULL,
		0x1D099F8DE81DF950ULL,
		0x0808D0DC049C8585ULL,
		0xCFD8D69370B1F83EULL,
		0x0E1CF12EC48A8EBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A67BDF0D5D7A484ULL,
		0x2872673C4CD25E98ULL,
		0x2FC64F4D9120C88EULL,
		0x8809D4AA551C576BULL,
		0xE441417AB9841CDBULL,
		0x06B1A42548AF9E53ULL,
		0x0E9827D8367BAA4AULL,
		0x5A15EBC3D8C8133FULL
	}};
	sign = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9D37B5B2C38ED196ULL,
		0x151317976706742FULL,
		0xE4829192C0C85100ULL,
		0x3AD234437A3C52E7ULL,
		0xF8C14318FB6DC389ULL,
		0x5F7EE9DFFF08C3AFULL,
		0xCB6BA49C9B501E13ULL,
		0x8E001AE66E7975FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x51592A78F0C129C5ULL,
		0x1AF27E64BE6D2AE4ULL,
		0x59F660E2D0D6055FULL,
		0x665485330D91CF34ULL,
		0xB7B3B515AAA4C062ULL,
		0x76525A41734DA576ULL,
		0xD7366174F41D337DULL,
		0x27BEA37DFCAE32E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BDE8B39D2CDA7D1ULL,
		0xFA209932A899494BULL,
		0x8A8C30AFEFF24BA0ULL,
		0xD47DAF106CAA83B3ULL,
		0x410D8E0350C90326ULL,
		0xE92C8F9E8BBB1E39ULL,
		0xF4354327A732EA95ULL,
		0x6641776871CB4318ULL
	}};
	sign = 0;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD74E33F66BD53687ULL,
		0x093687A1A944B144ULL,
		0x9B19A56CC58B9675ULL,
		0x0F52EA3712E44448ULL,
		0x1F2DD09243D4EC1AULL,
		0x443DAEDF5E820DA5ULL,
		0x205227F8C72DB22BULL,
		0x596A29A8B31B6F1BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB9D1CEF38142486ULL,
		0x94C1860ED6EBCE04ULL,
		0x06F5D57C8195C7EEULL,
		0x665FE21D739636D9ULL,
		0x9BFF7A768A0A2B74ULL,
		0xE07A457D930A0748ULL,
		0x861F074072F5CF04ULL,
		0xDDD27B636F9ECD10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBB1170733C11201ULL,
		0x74750192D258E33FULL,
		0x9423CFF043F5CE86ULL,
		0xA8F308199F4E0D6FULL,
		0x832E561BB9CAC0A5ULL,
		0x63C36961CB78065CULL,
		0x9A3320B85437E326ULL,
		0x7B97AE45437CA20AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC6892213C6C52F66ULL,
		0x7AA9B545E6775931ULL,
		0xE77C0220DD45B704ULL,
		0xC2920977EF09AFADULL,
		0x980E31EC283112EDULL,
		0x42A25571DB0575BEULL,
		0x47DC572AB4747D27ULL,
		0xB985420F53D61BF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3690360E01D8C9DULL,
		0x3227C6ACE8AF20D5ULL,
		0x0E5A85D5B80F061BULL,
		0x44F95DB47D328F8FULL,
		0xD34BCA8A8C33E10BULL,
		0x3D61B102749BEF9DULL,
		0xDE28A8FCF4966273ULL,
		0x4C3BE8485185A704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03201EB2E6A7A2C9ULL,
		0x4881EE98FDC8385CULL,
		0xD9217C4B2536B0E9ULL,
		0x7D98ABC371D7201EULL,
		0xC4C267619BFD31E2ULL,
		0x0540A46F66698620ULL,
		0x69B3AE2DBFDE1AB4ULL,
		0x6D4959C7025074EDULL
	}};
	sign = 0;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFBF596815590F618ULL,
		0xB0FF498356B60093ULL,
		0x6ED6AF4EADA5FF57ULL,
		0xBECA0980D4FBDECBULL,
		0xF309039AB26D99F2ULL,
		0x54ABE2742CDBA340ULL,
		0xB2B062E0AA5C6182ULL,
		0x78FCF72C61999A6DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x15EF254E1136D3C8ULL,
		0xE2CEDCECCF55A3EAULL,
		0x2598FEC9DA2DAA01ULL,
		0x1ABB2AE3B09F64AFULL,
		0x915707A7FD852C8AULL,
		0xAEF4B8B04462E266ULL,
		0x4B4427BC1D36D158ULL,
		0x1F0CA2F8621C2966ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6067133445A2250ULL,
		0xCE306C9687605CA9ULL,
		0x493DB084D3785555ULL,
		0xA40EDE9D245C7A1CULL,
		0x61B1FBF2B4E86D68ULL,
		0xA5B729C3E878C0DAULL,
		0x676C3B248D259029ULL,
		0x59F05433FF7D7107ULL
	}};
	sign = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD302F88434E4DC68ULL,
		0x5AC3AA3A01FF0E9DULL,
		0xABA3B6E52D0883DAULL,
		0xA56594C0181D78C9ULL,
		0xE79954378BAF2240ULL,
		0xE13522CEF78774BEULL,
		0x04134972CD40F773ULL,
		0xADFB0364BCA45087ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9795D977A72050ABULL,
		0xBADA37ADC33CF749ULL,
		0x6C6BA69CE9F063C3ULL,
		0xAE53669EC0F0765EULL,
		0x5810946D7F43AD14ULL,
		0x214C42CA908BE92BULL,
		0xFEE6A20CA9E2A7F5ULL,
		0x2E22A9ED686E0609ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B6D1F0C8DC48BBDULL,
		0x9FE9728C3EC21754ULL,
		0x3F38104843182016ULL,
		0xF7122E21572D026BULL,
		0x8F88BFCA0C6B752BULL,
		0xBFE8E00466FB8B93ULL,
		0x052CA766235E4F7EULL,
		0x7FD8597754364A7DULL
	}};
	sign = 0;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA6084CEF553F0E25ULL,
		0x6A829306B8BAAA67ULL,
		0x5978D2FB0639CEECULL,
		0xF10183547B91B54BULL,
		0x7333D12314C14DEBULL,
		0x419B90465E044CDBULL,
		0x211E4ED27B6C3CF4ULL,
		0xD6187DB4B713CFCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD4FBC48C056502ULL,
		0x2732ED81D298DC3BULL,
		0x821EC74DF001B232ULL,
		0xE9587AF0D18C6C64ULL,
		0xF6831AF59780D0E9ULL,
		0x495A5F29138041F7ULL,
		0x90C4A26A8631BD69ULL,
		0xEDB73BDDA23F5CBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B33512AC939A923ULL,
		0x434FA584E621CE2CULL,
		0xD75A0BAD16381CBAULL,
		0x07A90863AA0548E6ULL,
		0x7CB0B62D7D407D02ULL,
		0xF841311D4A840AE3ULL,
		0x9059AC67F53A7F8AULL,
		0xE86141D714D4730CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2D0554ED88C05689ULL,
		0x33AE3003C6CF467DULL,
		0x336A10C738968534ULL,
		0x6AE62DB5FDD1F4A8ULL,
		0xE6FADE2EEEFCEA17ULL,
		0x6E60E9182CB6AA03ULL,
		0x6D06F801D007E1E1ULL,
		0xC5D2A842C7CD7222ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE6BE1D97F1FA1CULL,
		0xC01502E0B0965743ULL,
		0xF68912922A808811ULL,
		0x864EF297FC3DD65FULL,
		0x66761BDB0ACB06E5ULL,
		0xAA180D7F4155ED28ULL,
		0x0A360E664AF0C8FFULL,
		0xC9072B00AC47B2DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E1E96CFF0CE5C6DULL,
		0x73992D231638EF39ULL,
		0x3CE0FE350E15FD22ULL,
		0xE4973B1E01941E48ULL,
		0x8084C253E431E331ULL,
		0xC448DB98EB60BCDBULL,
		0x62D0E99B851718E1ULL,
		0xFCCB7D421B85BF43ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x788AF30DDACB7488ULL,
		0x0F5AD818D42D4BDEULL,
		0xDF170D0BC7C602B2ULL,
		0x2B682574F0FD71D2ULL,
		0x3CEDF73995A2CA8DULL,
		0x2269FFDD64F4E4D4ULL,
		0x3FE2052C5EDA47F9ULL,
		0x066C222F05565245ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63701AC45AD2878ULL,
		0xBC0F54F93BF502FEULL,
		0x75339AF3E4CE6039ULL,
		0x6F347EF22DE6ED7AULL,
		0xF17964AB2C971B94ULL,
		0x22C4F597CFC76007ULL,
		0x4C62EB6B6E38005EULL,
		0x22BFEF4D988E69D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD253F161951E4C10ULL,
		0x534B831F983848DFULL,
		0x69E37217E2F7A278ULL,
		0xBC33A682C3168458ULL,
		0x4B74928E690BAEF8ULL,
		0xFFA50A45952D84CCULL,
		0xF37F19C0F0A2479AULL,
		0xE3AC32E16CC7E871ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDDF2D93290D1E48CULL,
		0xCC2931A3F96EC3A4ULL,
		0x3507114F9254E48BULL,
		0x196D856BE9A66F4BULL,
		0x07235502A46114EFULL,
		0xEA5BC78F0103FCDAULL,
		0x8D6EB2EB531F0C63ULL,
		0xEF221BE7B751A38CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEA69C3A6E812EC1ULL,
		0x621D5D1EC17F528EULL,
		0xB445FE092ED69AEEULL,
		0x9C9CD0B606FECF31ULL,
		0x0295ABB114059012ULL,
		0xC80AF6B216FC39AEULL,
		0xF9E0314E41C6CAB5ULL,
		0x359DE591F0F8F12BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF4C3CF82250B5CBULL,
		0x6A0BD48537EF7115ULL,
		0x80C11346637E499DULL,
		0x7CD0B4B5E2A7A019ULL,
		0x048DA951905B84DCULL,
		0x2250D0DCEA07C32CULL,
		0x938E819D115841AEULL,
		0xB9843655C658B260ULL
	}};
	sign = 0;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBC20EF316F0C98F5ULL,
		0xF30C88B4C37BC117ULL,
		0x896573573EA6C9C0ULL,
		0x6BB5CC1345639CA4ULL,
		0x2F01CD11262C3C0BULL,
		0xAA528A122DB4B8D2ULL,
		0xDE959D191215C817ULL,
		0x310E6CBF5B2DC983ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3AF17ABD509EF28ULL,
		0x280DA327E2C3EEFAULL,
		0xAABC8180146F433FULL,
		0x7B5B516187309BAFULL,
		0x14C75565997CCE6CULL,
		0x3FFB5B77CFB8CB64ULL,
		0xA9135113D8CC4462ULL,
		0x88205380D0AC944EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE871D7859A02A9CDULL,
		0xCAFEE58CE0B7D21CULL,
		0xDEA8F1D72A378681ULL,
		0xF05A7AB1BE3300F4ULL,
		0x1A3A77AB8CAF6D9EULL,
		0x6A572E9A5DFBED6EULL,
		0x35824C05394983B5ULL,
		0xA8EE193E8A813535ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x228D556D1985E265ULL,
		0x00F54497CAF893C3ULL,
		0x0B4509785892A401ULL,
		0xA928E107854EDCADULL,
		0x85FA630F98A491A2ULL,
		0xE5552C4ED45C2F15ULL,
		0x905A96193C32F126ULL,
		0xB3A57658BEB93154ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5865A33E78173790ULL,
		0xBEDFB6126273C8ACULL,
		0x8CECB6A8EEA17DFDULL,
		0xC6F839C3A96F476DULL,
		0x8E3AF43D640ECA56ULL,
		0xF824B4997FD09D4CULL,
		0xB1502E5281AF09E8ULL,
		0xEF486FEFEC7B3E11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA27B22EA16EAAD5ULL,
		0x42158E856884CB16ULL,
		0x7E5852CF69F12603ULL,
		0xE230A743DBDF953FULL,
		0xF7BF6ED23495C74BULL,
		0xED3077B5548B91C8ULL,
		0xDF0A67C6BA83E73DULL,
		0xC45D0668D23DF342ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7E7CF5C960B252B5ULL,
		0xEF02307EEFF2EE83ULL,
		0xCD445F8970340939ULL,
		0x32D2BD32A6D559A2ULL,
		0x3CFFBDE20910627AULL,
		0x03ADA7A5C2CF9C9EULL,
		0x27E8F2E154CB42EFULL,
		0x88CAB8FDDA818274ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BDF6B573F364E4EULL,
		0xFBF95023C77C1B39ULL,
		0xEE94FBCB58C1F888ULL,
		0x2D34162AE2461A9FULL,
		0x74985C475FF644D8ULL,
		0xB406A4BF3E681185ULL,
		0x8B4A6B9B33F20C3AULL,
		0xABBB9FA5B3A9022CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x429D8A72217C0467ULL,
		0xF308E05B2876D34AULL,
		0xDEAF63BE177210B0ULL,
		0x059EA707C48F3F02ULL,
		0xC867619AA91A1DA2ULL,
		0x4FA702E684678B18ULL,
		0x9C9E874620D936B4ULL,
		0xDD0F195826D88047ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x979AABCB3286802BULL,
		0x12559664BCAD346DULL,
		0x0CA405A59DEEBF01ULL,
		0x3327892B4764C3B2ULL,
		0x4743ABA773D353DEULL,
		0x73484E1A4B6877DFULL,
		0xE3FC13D430D50895ULL,
		0x2F7E35F758118234ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x201611813BF19EF6ULL,
		0x78DBECE2201CB86FULL,
		0xB8D6A3A6DD241027ULL,
		0xF6343EB4F0532290ULL,
		0xE4DD9570A86AEA42ULL,
		0xA46193FC75310E63ULL,
		0x7705AA7F62ABAB17ULL,
		0xD8AAB723D34A041DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77849A49F694E135ULL,
		0x9979A9829C907BFEULL,
		0x53CD61FEC0CAAED9ULL,
		0x3CF34A765711A121ULL,
		0x62661636CB68699BULL,
		0xCEE6BA1DD637697BULL,
		0x6CF66954CE295D7DULL,
		0x56D37ED384C77E17ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC0D18452BB5DD5A9ULL,
		0xACDBD75B1E32B460ULL,
		0x420DC7539D17A0AEULL,
		0xFB3B0D5AF2F5B912ULL,
		0x7F230A53A293CCA8ULL,
		0xEDBF2B95D5CAAC7FULL,
		0x08E143E8ACCB9A8DULL,
		0x8ED6126C72AB3D43ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9682C77EC25219ULL,
		0xD8160930CBB54F04ULL,
		0x7660375F96924C2DULL,
		0x31981AB57D32049CULL,
		0x8F918E2DF65AC105ULL,
		0xEEACD2AB56109B75ULL,
		0x4FF51010282B8FE3ULL,
		0x5822D551CF8D6EC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD23B018B3C9B8390ULL,
		0xD4C5CE2A527D655BULL,
		0xCBAD8FF406855480ULL,
		0xC9A2F2A575C3B475ULL,
		0xEF917C25AC390BA3ULL,
		0xFF1258EA7FBA1109ULL,
		0xB8EC33D884A00AA9ULL,
		0x36B33D1AA31DCE7FULL
	}};
	sign = 0;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3D38ECC15DBAF4CEULL,
		0x78102A1C3D3AA96DULL,
		0x82984EE657E0ECDAULL,
		0x3671A81E1E4B1514ULL,
		0xE7D8D09B9F9CA79BULL,
		0xA0461DA0D7967237ULL,
		0xAB70673B3A721AC3ULL,
		0x7C6354119312A666ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F488671F213DB86ULL,
		0x1702CEDCF8CAA574ULL,
		0xE53119029569073DULL,
		0x8A3A67AEA42033CAULL,
		0xDF090C5E44885212ULL,
		0xD0116762604B3A5AULL,
		0xFA1DB0D2773A806AULL,
		0x0AEA25AC4351572EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDF0664F6BA71948ULL,
		0x610D5B3F447003F8ULL,
		0x9D6735E3C277E59DULL,
		0xAC37406F7A2AE149ULL,
		0x08CFC43D5B145588ULL,
		0xD034B63E774B37DDULL,
		0xB152B668C3379A58ULL,
		0x71792E654FC14F37ULL
	}};
	sign = 0;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x053A0508453AD8DCULL,
		0x78DDF1B4F52BF368ULL,
		0xBFF5AAC2E5968618ULL,
		0xB6A195EC03839353ULL,
		0xB589B377E54D20AEULL,
		0x24E3F066AC34715FULL,
		0x1D4A531F2FCFE8E3ULL,
		0x5B86CCAC07604CD5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7790BB52F278F880ULL,
		0xC0FB6EABD274F21EULL,
		0xE1FC8D80DC4FEED9ULL,
		0x966D5AE3F44F552FULL,
		0xE4A1DDFEAFA5C580ULL,
		0x338C041902478164ULL,
		0x9697FFE4E5628EC3ULL,
		0x19971DCA3D60CB5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DA949B552C1E05CULL,
		0xB7E2830922B70149ULL,
		0xDDF91D420946973EULL,
		0x20343B080F343E23ULL,
		0xD0E7D57935A75B2EULL,
		0xF157EC4DA9ECEFFAULL,
		0x86B2533A4A6D5A1FULL,
		0x41EFAEE1C9FF8179ULL
	}};
	sign = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C47285185C48E4EULL,
		0x3B235A36B74F7BD6ULL,
		0x638498D0AE484C6BULL,
		0x5AB42824628A78ECULL,
		0x3EB339164E479F31ULL,
		0xA80CD071E746E406ULL,
		0x34F6CBCF87258121ULL,
		0xE76F940156142AD0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BCB5D4D8F8D1D9CULL,
		0x0E5701F3E63EA491ULL,
		0x0CC3105C577DCA3BULL,
		0x81EE1B1DB12D23DDULL,
		0x7A7885D36CCA6448ULL,
		0x498D2450F31C8757ULL,
		0x1D14329892310B50ULL,
		0x4EB389580DFAD05DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE07BCB03F63770B2ULL,
		0x2CCC5842D110D744ULL,
		0x56C1887456CA8230ULL,
		0xD8C60D06B15D550FULL,
		0xC43AB342E17D3AE8ULL,
		0x5E7FAC20F42A5CAEULL,
		0x17E29936F4F475D1ULL,
		0x98BC0AA948195A73ULL
	}};
	sign = 0;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9BA217C761FC18F9ULL,
		0xEEFEC5D659C98D78ULL,
		0x844AB8EFF388D64FULL,
		0xB0D91DAAFA1EFD2AULL,
		0xAB151A791B38515CULL,
		0x2E3488A8FA25EFA6ULL,
		0x9A7EA6FD31CBA532ULL,
		0xA65F341C647A1C67ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C3DA7C1285EE78ULL,
		0x06DF957A4D2EDD9CULL,
		0xE650869407E76226ULL,
		0x82CB6C353B40867EULL,
		0xF427CA983573FA91ULL,
		0x938DB908973B24A4ULL,
		0x7A00A57975C906ABULL,
		0xEA259EC18A89D385ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9DE3D4B4F762A81ULL,
		0xE81F305C0C9AAFDBULL,
		0x9DFA325BEBA17429ULL,
		0x2E0DB175BEDE76ABULL,
		0xB6ED4FE0E5C456CBULL,
		0x9AA6CFA062EACB01ULL,
		0x207E0183BC029E86ULL,
		0xBC39955AD9F048E2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDECA5A6D4DB4FAB1ULL,
		0xC89F55D70CC35357ULL,
		0x599E8102ADEE6E4EULL,
		0x8CA4216DC85A1D80ULL,
		0x5F9C3FFD8119849EULL,
		0xB2D6F5DE60E195FBULL,
		0xFC40A1213F035FCFULL,
		0xD042088883955173ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE78594451AB14FDULL,
		0x65D08CAD42E6707DULL,
		0x8F4B3D839F98879FULL,
		0x750C2890A714FB78ULL,
		0xC89028EFF5520C5EULL,
		0xE21ADEC265903694ULL,
		0x4DDF923766F761E7ULL,
		0x9F4DAFA6B34D2EDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0520128FC09E5B4ULL,
		0x62CEC929C9DCE2D9ULL,
		0xCA53437F0E55E6AFULL,
		0x1797F8DD21452207ULL,
		0x970C170D8BC77840ULL,
		0xD0BC171BFB515F66ULL,
		0xAE610EE9D80BFDE7ULL,
		0x30F458E1D0482298ULL
	}};
	sign = 0;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5DF32EA7D5FA6BF7ULL,
		0x15E45F0CD1EF2DCEULL,
		0xFC78FE4622B1588AULL,
		0xAE12F2DCD3FAEC1BULL,
		0x6AE5774A20FC065DULL,
		0x95FF9CDC42F11CF8ULL,
		0x13B35A25848690A4ULL,
		0x1C20DB1BBA5E0D4BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4871C95BB3A2D37CULL,
		0xCF560A8FB91B8DC7ULL,
		0xFE8764B4CB8153BDULL,
		0xC2ECBDFCE655CBFAULL,
		0x5DF44E8F2CA4702EULL,
		0xE6A9F45111317875ULL,
		0x831E9DDA2316AB68ULL,
		0xCE7182D23CB525B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1581654C2257987BULL,
		0x468E547D18D3A007ULL,
		0xFDF19991573004CCULL,
		0xEB2634DFEDA52020ULL,
		0x0CF128BAF457962EULL,
		0xAF55A88B31BFA483ULL,
		0x9094BC4B616FE53BULL,
		0x4DAF58497DA8E797ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3621C23845EA3053ULL,
		0x9D61495A7BEA42D6ULL,
		0x3D5B9BDB8A407D30ULL,
		0xB3801BE7E13D76B8ULL,
		0xA1503869F9C5ECD4ULL,
		0xE94C90AB4430817BULL,
		0x9467CA71920C1704ULL,
		0x8967195FE2B6599EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA1C74232DF6735ULL,
		0x0E652D32CE43ECF6ULL,
		0xA164BCC1E8DDFF49ULL,
		0x222306B6E865291DULL,
		0x91E013EAF94D5E31ULL,
		0xD64BA5B8A590945FULL,
		0xE22042D7C39C2691ULL,
		0x92DC61961D78586EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC97FFAF6130AC91EULL,
		0x8EFC1C27ADA655DFULL,
		0x9BF6DF19A1627DE7ULL,
		0x915D1530F8D84D9AULL,
		0x0F70247F00788EA3ULL,
		0x1300EAF29E9FED1CULL,
		0xB2478799CE6FF073ULL,
		0xF68AB7C9C53E012FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2A8209CFC3BADE7ULL,
		0xB5287DEF15B08F63ULL,
		0x33E1678C9FCDEB15ULL,
		0xAD12AB1DC86A4E0EULL,
		0xD2A182221ADDC6F3ULL,
		0xAE65DB30DF11017EULL,
		0xA9841B08B3364703ULL,
		0xD177BAA9F3FFDFCCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A88155678189679ULL,
		0x438C028BCFE3218FULL,
		0xFEA882524999C3FAULL,
		0x26CC6AADF9326830ULL,
		0x0F78102A13DF768EULL,
		0xE6718B7840DF23BBULL,
		0xC3ECA1B9DA45EE6AULL,
		0x63FFAEDF651F30DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8200B468423176EULL,
		0x719C7B6345CD6DD4ULL,
		0x3538E53A5634271BULL,
		0x8646406FCF37E5DDULL,
		0xC32971F806FE5065ULL,
		0xC7F44FB89E31DDC3ULL,
		0xE597794ED8F05898ULL,
		0x6D780BCA8EE0AEECULL
	}};
	sign = 0;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2EF9FCBB36D576BDULL,
		0x6A2C965C8152CB10ULL,
		0x517282DFDCEF409CULL,
		0x0DF9A989725CA098ULL,
		0xB4124B2A14EE6B28ULL,
		0xDD4E81CC387F7DF6ULL,
		0xDB50193DCD656A3EULL,
		0xB432E2A28D92A350ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AFE08AD31979116ULL,
		0xB2DF0F36BD542AC6ULL,
		0xCF965DDC3CA83A68ULL,
		0xF74946ECFFC5ABB4ULL,
		0xB1C58DF644E1BA22ULL,
		0x601363EE0BCDD3A4ULL,
		0xCF6C86A2DB7D3166ULL,
		0x4E688E839D03EABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23FBF40E053DE5A7ULL,
		0xB74D8725C3FEA04AULL,
		0x81DC2503A0470633ULL,
		0x16B0629C7296F4E3ULL,
		0x024CBD33D00CB105ULL,
		0x7D3B1DDE2CB1AA52ULL,
		0x0BE3929AF1E838D8ULL,
		0x65CA541EF08EB896ULL
	}};
	sign = 0;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CBF32F3C3FD57E4ULL,
		0xBD886E982C155745ULL,
		0x2CA2D96925DA1421ULL,
		0xA8E29CF434E5FEA1ULL,
		0xD9D1A74C8ADB4FFEULL,
		0x6BE60D5A3FFF19B0ULL,
		0x6160853FAF087E8EULL,
		0xF07B801E73690DBCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48E6CCEFA535A0DULL,
		0x8D177D76FE43B9C6ULL,
		0xEB5B292F2CA9B7D3ULL,
		0x424247E1B5EBB590ULL,
		0x3129D2B3A4AE0DA6ULL,
		0xCC0A06A9598975CCULL,
		0x8025CDCEDF39C071ULL,
		0x34EB6697C3B69653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6830C624C9A9FDD7ULL,
		0x3070F1212DD19D7EULL,
		0x4147B039F9305C4EULL,
		0x66A055127EFA4910ULL,
		0xA8A7D498E62D4258ULL,
		0x9FDC06B0E675A3E4ULL,
		0xE13AB770CFCEBE1CULL,
		0xBB901986AFB27768ULL
	}};
	sign = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x35BA09475A98F9B2ULL,
		0xE77B58479F9F0017ULL,
		0x4D7E66ADFADB6593ULL,
		0x4EB011631D0D1F2FULL,
		0xC0F9755719E533B9ULL,
		0xAF4A7BC6F5412DC0ULL,
		0x9CD4FC93B6E91E9CULL,
		0x4E09BABE010B3E5CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D008114C2E42E64ULL,
		0x927CA43E24CD39EBULL,
		0xF03ABB8777F955A9ULL,
		0x17F1D68EADEFF075ULL,
		0x578B31280B85D79FULL,
		0x549CDA3D26A68D3EULL,
		0x554BE4BF2115D9DEULL,
		0x1C1C4A56D5485569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8B9883297B4CB4EULL,
		0x54FEB4097AD1C62BULL,
		0x5D43AB2682E20FEAULL,
		0x36BE3AD46F1D2EB9ULL,
		0x696E442F0E5F5C1AULL,
		0x5AADA189CE9AA082ULL,
		0x478917D495D344BEULL,
		0x31ED70672BC2E8F3ULL
	}};
	sign = 0;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x11455131E7DB45BEULL,
		0x0E45F49D128A36C5ULL,
		0xF44660B5C39A8B15ULL,
		0x2799835E28526437ULL,
		0xC9408FC4FADD9A71ULL,
		0xE1959EC6FC51B366ULL,
		0xA82A115089827D97ULL,
		0x5EC0A4EAEB269AB3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4138EF5CBE96A1DULL,
		0xEF561A8A1A271C65ULL,
		0x389E2B441FC59B2CULL,
		0x5EE6B714D4BD2F39ULL,
		0xDBAEFD4144BA18B7ULL,
		0x0E467522DC3C5B9CULL,
		0x05DD0E660FAB3881ULL,
		0xEE9A0145F714DA9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D31C23C1BF1DBA1ULL,
		0x1EEFDA12F8631A5FULL,
		0xBBA83571A3D4EFE8ULL,
		0xC8B2CC49539534FEULL,
		0xED919283B62381B9ULL,
		0xD34F29A4201557C9ULL,
		0xA24D02EA79D74516ULL,
		0x7026A3A4F411C019ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2542BA225935BCDFULL,
		0x50B607BC6A6E12DCULL,
		0x25506500B72E1AC1ULL,
		0x7B09F90F49E5B5C7ULL,
		0x2AE884E8E8153EB7ULL,
		0x74799BD4C83AA4EAULL,
		0x859E450D4E8BB5ADULL,
		0x10A0CD795BEE53B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE05787931D6559ULL,
		0xA399BE135DD9024BULL,
		0xF85E6220B4015AA0ULL,
		0xD85CACB1C80EA047ULL,
		0x253DDD94E88B9DB6ULL,
		0xCE00516037B90ACAULL,
		0x4891D6DC3725B118ULL,
		0x6B9E41038EAA928BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF862629AC6185786ULL,
		0xAD1C49A90C951090ULL,
		0x2CF202E0032CC020ULL,
		0xA2AD4C5D81D7157FULL,
		0x05AAA753FF89A100ULL,
		0xA6794A7490819A20ULL,
		0x3D0C6E3117660494ULL,
		0xA5028C75CD43C12DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCB826BF6DA9737E8ULL,
		0xD65F78BB35987D55ULL,
		0x24F106D1FD757EF2ULL,
		0x4BAFC953AC29CF1EULL,
		0x393B94C2D8D01383ULL,
		0x35EFA6360A9102B0ULL,
		0x26D1C23BBE18AA0BULL,
		0x8B68DD01A34CDC13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD649F93E6D8654ULL,
		0x831FFB83FE5B8D84ULL,
		0xCB488FA54B769479ULL,
		0xDD823125CB6044A2ULL,
		0xE02AF1C3D782EED4ULL,
		0x4279D5AE43375176ULL,
		0xA016461236CB1EF8ULL,
		0x6A5B3B5990945891ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BAC21FD9C29B194ULL,
		0x533F7D37373CEFD1ULL,
		0x59A8772CB1FEEA79ULL,
		0x6E2D982DE0C98A7BULL,
		0x5910A2FF014D24AEULL,
		0xF375D087C759B139ULL,
		0x86BB7C29874D8B12ULL,
		0x210DA1A812B88381ULL
	}};
	sign = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x52EC3BEA2EBF66F9ULL,
		0x93A48A6D83E68354ULL,
		0xBB9B376726296979ULL,
		0x8E24946F54727A31ULL,
		0x63958BF0E6131733ULL,
		0xDE2A7EE571040709ULL,
		0x38DDEE0EDB16CA54ULL,
		0xE3D55F2076EC24E9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1945988F1C27AF75ULL,
		0x4374169F97131982ULL,
		0xFF52431422FC2F05ULL,
		0x9D20595D4684007FULL,
		0x11A5460AA734631DULL,
		0x1893B694FB3C2C12ULL,
		0xEEE462D83925E5E3ULL,
		0x142CFD0C46CC7B60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39A6A35B1297B784ULL,
		0x503073CDECD369D2ULL,
		0xBC48F453032D3A74ULL,
		0xF1043B120DEE79B1ULL,
		0x51F045E63EDEB415ULL,
		0xC596C85075C7DAF7ULL,
		0x49F98B36A1F0E471ULL,
		0xCFA86214301FA988ULL
	}};
	sign = 0;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x25110E308DBB738CULL,
		0x07E405AA6545E7AAULL,
		0x47B09F5912D4CFE7ULL,
		0x64A0E31F60767ED1ULL,
		0x99C2C6BAE81BC4E6ULL,
		0x7F8C7C98392BDBF0ULL,
		0x6B87D533D1549A10ULL,
		0xD89E9C4208E93928ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD38A3E677DE951ULL,
		0xAFF0139466205CF3ULL,
		0xB0A3FF8DA87EED99ULL,
		0x8AB20CEB1C68307DULL,
		0xC5A9A8AE43EF63BAULL,
		0xFC9D36E131BF991CULL,
		0x4CEF7191A011F144ULL,
		0x67461AAB05680EE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x853D83F2263D8A3BULL,
		0x57F3F215FF258AB6ULL,
		0x970C9FCB6A55E24DULL,
		0xD9EED634440E4E53ULL,
		0xD4191E0CA42C612BULL,
		0x82EF45B7076C42D3ULL,
		0x1E9863A23142A8CBULL,
		0x7158819703812A47ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1419F9ADDA2F30A1ULL,
		0xD03F1037B784356AULL,
		0x967D82C41312FE58ULL,
		0xD6E7E14D3A7CA352ULL,
		0xCA11AC40CF6BC682ULL,
		0x8E714F9C86E6F63DULL,
		0xFA13CB8CAFAF6F19ULL,
		0xA77888D7DD4F27AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B751CC45E21EA44ULL,
		0xA54C0A507705C99EULL,
		0xA06C3386EB9DB82FULL,
		0xB57CAC397AAF79DBULL,
		0x37A0BF1D493E18D1ULL,
		0x8BE92D90A1FDFD29ULL,
		0x5E4B4E1F76240F74ULL,
		0xE152AFEA84A44825ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8A4DCE97C0D465DULL,
		0x2AF305E7407E6BCBULL,
		0xF6114F3D27754629ULL,
		0x216B3513BFCD2976ULL,
		0x9270ED23862DADB1ULL,
		0x0288220BE4E8F914ULL,
		0x9BC87D6D398B5FA5ULL,
		0xC625D8ED58AADF89ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5EEC48BF646A2E0DULL,
		0x1069E51BDD20FECBULL,
		0xC8E2D0061C817ABEULL,
		0x70A107DFDDB22186ULL,
		0x6EF9FC54B5A5D522ULL,
		0xC8ED3618656C32CBULL,
		0x7FEEA9885149D096ULL,
		0x3A705B7FE1F01744ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D812414D3AA811AULL,
		0x55FD5B1F76B0B4E1ULL,
		0x8B1F43EA21FC5D24ULL,
		0xECCA9C708EA0CC31ULL,
		0x665A915AFEFB8D85ULL,
		0xD0D74B1BB775E7CBULL,
		0x8C8A61AD65B895B8ULL,
		0x5512D9139CA9FF24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x116B24AA90BFACF3ULL,
		0xBA6C89FC667049EAULL,
		0x3DC38C1BFA851D99ULL,
		0x83D66B6F4F115555ULL,
		0x089F6AF9B6AA479CULL,
		0xF815EAFCADF64B00ULL,
		0xF36447DAEB913ADDULL,
		0xE55D826C4546181FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC36E10D477F381D3ULL,
		0xEF000DBF72FC9D84ULL,
		0x138F4D8F2FE85C93ULL,
		0xA08C32B52BD4456CULL,
		0x4D04487C6ECC74BDULL,
		0x36053DD90E25B80AULL,
		0xAA8A7A3EF208E200ULL,
		0xF55BC29E90E77717ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF316E0962BC350FULL,
		0xBFAAEC383499AC43ULL,
		0x3F834B52248EF873ULL,
		0x57357A1692E92C66ULL,
		0x7474FF84F2E3D7D6ULL,
		0xC18579AE4A5AD38FULL,
		0xD4C99115A1F2373EULL,
		0x82707563D716DA93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD43CA2CB15374CC4ULL,
		0x2F5521873E62F140ULL,
		0xD40C023D0B596420ULL,
		0x4956B89E98EB1905ULL,
		0xD88F48F77BE89CE7ULL,
		0x747FC42AC3CAE47AULL,
		0xD5C0E9295016AAC1ULL,
		0x72EB4D3AB9D09C83ULL
	}};
	sign = 0;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4D6BC7F8ACE3F551ULL,
		0x84512A4B28064238ULL,
		0xE9494BFD1F19B017ULL,
		0x17DD4874961629BDULL,
		0xC17C1990A80D15BAULL,
		0xC588AF6448F21438ULL,
		0x6371BDE19DA4A4C4ULL,
		0x364167065953503BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF71CD61C705B487BULL,
		0x119F71E8E1ACEF36ULL,
		0x920D997D84298FDCULL,
		0xF5EA17E4D4F11188ULL,
		0xF2BE2CCB510E90CBULL,
		0xEC67A36219441F26ULL,
		0x927F9F238BFE8917ULL,
		0xB2DC2367EA2C48E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x564EF1DC3C88ACD6ULL,
		0x72B1B86246595301ULL,
		0x573BB27F9AF0203BULL,
		0x21F3308FC1251835ULL,
		0xCEBDECC556FE84EEULL,
		0xD9210C022FADF511ULL,
		0xD0F21EBE11A61BACULL,
		0x8365439E6F270754ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCF249ECB3BEA1F5AULL,
		0x0072A9A22C3FA52CULL,
		0x3CFA42EC7C5BC7A7ULL,
		0xED2D177C67D23E48ULL,
		0xF1138C3D314AFB71ULL,
		0xD0D63650DBFE1D74ULL,
		0x5255CBFC880A4AE4ULL,
		0x794B9B96B6C005BFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x72BCD2B7AA85F28DULL,
		0xAF1180F509544A8FULL,
		0x895E155C8051CD47ULL,
		0xD0FF632521FBCB51ULL,
		0x7FB3857696B37291ULL,
		0x1346BF24AB0485ABULL,
		0x5A1BC5B26306CA6EULL,
		0x7015BD89F419A450ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C67CC1391642CCDULL,
		0x516128AD22EB5A9DULL,
		0xB39C2D8FFC09FA5FULL,
		0x1C2DB45745D672F6ULL,
		0x716006C69A9788E0ULL,
		0xBD8F772C30F997C9ULL,
		0xF83A064A25038076ULL,
		0x0935DE0CC2A6616EULL
	}};
	sign = 0;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1261CEE4FD1CFAC2ULL,
		0x47CD35899D99ACA3ULL,
		0xB2563626F8C8C315ULL,
		0x22D9A731F9847359ULL,
		0x0643264E31190765ULL,
		0x47F1F50F48949D3EULL,
		0xEBDC637E327C42EAULL,
		0x5E14040219955E54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68C2A920427C3706ULL,
		0xC2A822234F3636AEULL,
		0x71870180572C3204ULL,
		0x79D202D78F9BEFE9ULL,
		0x09F8288BC5682F0EULL,
		0x882155E563CFD216ULL,
		0x7029643D5212091EULL,
		0xFFB476B8346DCA8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA99F25C4BAA0C3BCULL,
		0x852513664E6375F4ULL,
		0x40CF34A6A19C9110ULL,
		0xA907A45A69E88370ULL,
		0xFC4AFDC26BB0D856ULL,
		0xBFD09F29E4C4CB27ULL,
		0x7BB2FF40E06A39CBULL,
		0x5E5F8D49E52793C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8A38EBDB863462FULL,
		0xA6913AFD7659A86BULL,
		0x09AC1EDBA0662A92ULL,
		0x4467B97671D85C16ULL,
		0xE7EE66FFBC284810ULL,
		0x573409C333AD944CULL,
		0x9D3EF3A4A76586BDULL,
		0x62DB9730C34AA3D3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5067A20E3518668AULL,
		0xE83D63DED6DC0DEFULL,
		0xBBB64300B579912AULL,
		0x3D1952C058A9D38CULL,
		0xAF8448980583B2D2ULL,
		0xACA8DCCB0006D3DDULL,
		0x381EE5886FE90FC6ULL,
		0xD0D2D9114E50D457ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x983BECAF834ADFA5ULL,
		0xBE53D71E9F7D9A7CULL,
		0x4DF5DBDAEAEC9967ULL,
		0x074E66B6192E8889ULL,
		0x386A1E67B6A4953EULL,
		0xAA8B2CF833A6C06FULL,
		0x65200E1C377C76F6ULL,
		0x9208BE1F74F9CF7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55BFBD36612055ADULL,
		0x95B61221D6373898ULL,
		0x52E0B4AD5813F52FULL,
		0x00AD855882A9A311ULL,
		0x5C2162F081FA38ADULL,
		0xDFA91B1E5AFC8137ULL,
		0x435C8349FF8875D3ULL,
		0x2A7A4F82BF4381F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7EFB4F5E181AE47ULL,
		0xEF5389C25E04AC39ULL,
		0x0440724D169CE405ULL,
		0x849A90CB2E1738A4ULL,
		0xE39DC9B6B87BF047ULL,
		0x7BE948EA3B6A4E80ULL,
		0x37CDD0A760211CECULL,
		0x0E1494F355E1F517ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DD008407F9EA766ULL,
		0xA662885F78328C5EULL,
		0x4EA0426041771129ULL,
		0x7C12F48D54926A6DULL,
		0x78839939C97E4865ULL,
		0x63BFD2341F9232B6ULL,
		0x0B8EB2A29F6758E7ULL,
		0x1C65BA8F69618CDDULL
	}};
	sign = 0;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x347E6571F81B6266ULL,
		0x56059BA380217C53ULL,
		0x8CB78EB078402F35ULL,
		0x2377F80F9D8B884AULL,
		0x5A446B834C5739C7ULL,
		0xC700612653156D10ULL,
		0x14557AC84929B049ULL,
		0x6B06F10167EB31EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDA0D5CAB5F15322ULL,
		0xD2AB20C9001290D4ULL,
		0x84D6FD4AA016FE94ULL,
		0xA9C8609884D582B0ULL,
		0x32D3740F8A13A990ULL,
		0xC3399B7708FF316CULL,
		0x0AE7AC411FAEE54AULL,
		0x51EE82674FA1260FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46DD8FA7422A0F44ULL,
		0x835A7ADA800EEB7EULL,
		0x07E09165D82930A0ULL,
		0x79AF977718B6059AULL,
		0x2770F773C2439036ULL,
		0x03C6C5AF4A163BA4ULL,
		0x096DCE87297ACAFFULL,
		0x19186E9A184A0BDBULL
	}};
	sign = 0;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3AAC4725FD4634F4ULL,
		0x9BA1AA60037784A7ULL,
		0x41B751A108A2EAEDULL,
		0x83F12BD68A92F6F1ULL,
		0xB94AF397F98CF23FULL,
		0xC1CE47EB03197524ULL,
		0xCF08388E6734793EULL,
		0x296DAC0DDCC35B06ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF895FDAD49CEE63ULL,
		0xAC29943376B955E7ULL,
		0xB0EFE2ACCE8A7828ULL,
		0x37E2C9F3B6AC4173ULL,
		0x8013886AF83E5FE3ULL,
		0x828C93CEDA1AE568ULL,
		0xB85A661F5DF55A50ULL,
		0x38E81170BFFDBA33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B22E74B28A94691ULL,
		0xEF78162C8CBE2EBFULL,
		0x90C76EF43A1872C4ULL,
		0x4C0E61E2D3E6B57DULL,
		0x39376B2D014E925CULL,
		0x3F41B41C28FE8FBCULL,
		0x16ADD26F093F1EEEULL,
		0xF0859A9D1CC5A0D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDDC46E14807CA7C4ULL,
		0x0C67B7068E20E9E2ULL,
		0x11A2519A99C59C9FULL,
		0x9C78ED372F105F4DULL,
		0x6EA825CF09C50C97ULL,
		0x408E392191877C3EULL,
		0xA7504C48E42B182AULL,
		0x38315C95EDEEEFADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F01754A9F55B92ULL,
		0x1961588FEAE4713DULL,
		0x4A0EFED48BF3219DULL,
		0x78E994873235D827ULL,
		0x1E9A41861A9A95D4ULL,
		0xED76FBB2C0573FD6ULL,
		0x4B5F96F978FBBBE7ULL,
		0x3D8DDD74B2D49BFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05D456BFD6874C32ULL,
		0xF3065E76A33C78A5ULL,
		0xC79352C60DD27B01ULL,
		0x238F58AFFCDA8725ULL,
		0x500DE448EF2A76C3ULL,
		0x53173D6ED1303C68ULL,
		0x5BF0B54F6B2F5C42ULL,
		0xFAA37F213B1A53B0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1308C254F604F6C7ULL,
		0x06BC48881D1A19A2ULL,
		0xCF33ABD1846EAEE5ULL,
		0x3138518381D6288DULL,
		0x6B0CC5B9137B3DF6ULL,
		0xC33E37519A0CEAC6ULL,
		0x14C7DE76971258D5ULL,
		0x787A8B7C841E253BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D23959A9086FE9ULL,
		0xC59CCE116A8D1985ULL,
		0x1796E7B1E6526944ULL,
		0x7C7F34CC2AAA6920ULL,
		0x31E3FBAA0C8E0EBFULL,
		0xE6DD6EB0CA02EE5CULL,
		0xED60D9287039C920ULL,
		0x1133649AAF9C9E45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B3688FB4CFC86DEULL,
		0x411F7A76B28D001CULL,
		0xB79CC41F9E1C45A0ULL,
		0xB4B91CB7572BBF6DULL,
		0x3928CA0F06ED2F36ULL,
		0xDC60C8A0D009FC6AULL,
		0x2767054E26D88FB4ULL,
		0x674726E1D48186F5ULL
	}};
	sign = 0;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB74027C60BAAD057ULL,
		0x43009F64FC459A54ULL,
		0x794A6EF5A824FB29ULL,
		0xE4DE551D143ED16AULL,
		0x930FF490BD6A71A3ULL,
		0xC01C21F1B63A477CULL,
		0x2AD31FD215C90450ULL,
		0x7BCE87CBAC64306FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1A299E47A178C6ULL,
		0x11D98DCDD52BAFF9ULL,
		0x2D48B3FD5EAC2892ULL,
		0xB4D3EC5F55406DBFULL,
		0x88B554C594DC6903ULL,
		0x2BFD6F0D57569F2EULL,
		0xDEA5F936BEA4E766ULL,
		0x0A107C5BA9B68380ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C25FE27C4095791ULL,
		0x312711972719EA5BULL,
		0x4C01BAF84978D297ULL,
		0x300A68BDBEFE63ABULL,
		0x0A5A9FCB288E08A0ULL,
		0x941EB2E45EE3A84EULL,
		0x4C2D269B57241CEAULL,
		0x71BE0B7002ADACEEULL
	}};
	sign = 0;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF3EFFB9ACDF20B6ULL,
		0xC4AE4E69EFF9F172ULL,
		0x18E192790E3DB7EFULL,
		0x2C901AA929344EECULL,
		0x0AEA4FC463B9222BULL,
		0x7AE1CFBD5D8AED18ULL,
		0xB03C1F3E39302322ULL,
		0xCD817BC775F2FDE4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A699D97CE434CFULL,
		0x15697F0D92458AD2ULL,
		0xEDC64356073CF1A1ULL,
		0x5AB34038920C6DF5ULL,
		0x2635606376CAAAABULL,
		0x9E29916212B6A168ULL,
		0x74DB812CEF3289AFULL,
		0xC3B43EFF5F1CACF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D9865E02FFAEBE7ULL,
		0xAF44CF5C5DB466A0ULL,
		0x2B1B4F230700C64EULL,
		0xD1DCDA709727E0F6ULL,
		0xE4B4EF60ECEE777FULL,
		0xDCB83E5B4AD44BAFULL,
		0x3B609E1149FD9972ULL,
		0x09CD3CC816D650F3ULL
	}};
	sign = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A026D2FF8BB918BULL,
		0xAD0C2204E27B48E2ULL,
		0xE53B985C1E22AC55ULL,
		0xE3A46CFD8AA57595ULL,
		0xC637F5BD144AD2ABULL,
		0xB52C9995610A6B75ULL,
		0x7F149490FF8A3EE5ULL,
		0x0CFFE72A69A16474ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA40690E5879A279ULL,
		0x4F1D519079F634AEULL,
		0xFF784EFEA3F03B69ULL,
		0xA8AB286B2E8150EAULL,
		0x8951CBCCB768B004ULL,
		0xE9D2435F6B1870BAULL,
		0x4A151E62EBD157C1ULL,
		0x5EAEA6FC5B7298A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FC20421A041EF12ULL,
		0x5DEED07468851433ULL,
		0xE5C3495D7A3270ECULL,
		0x3AF944925C2424AAULL,
		0x3CE629F05CE222A7ULL,
		0xCB5A5635F5F1FABBULL,
		0x34FF762E13B8E723ULL,
		0xAE51402E0E2ECBCCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8541754914DD8C92ULL,
		0x3AF689F38B62D0C1ULL,
		0xD2A73530B37EFB89ULL,
		0x1024A0E909680027ULL,
		0xC17478B5C0AA90E2ULL,
		0x2D58C4F10137124FULL,
		0x606DB2E852235F1BULL,
		0x7FED4C311D388750ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7290D41E0E8FAC0EULL,
		0x06AE24F0F2F99AF6ULL,
		0x48BD3CA0FC17F28DULL,
		0xBFFF82FE0C36B5C8ULL,
		0x84C6258F8CCCACE5ULL,
		0x1838AA9458A4AF26ULL,
		0xCAC0538220CC5A3DULL,
		0x88D2D093F04F8742ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12B0A12B064DE084ULL,
		0x34486502986935CBULL,
		0x89E9F88FB76708FCULL,
		0x50251DEAFD314A5FULL,
		0x3CAE532633DDE3FCULL,
		0x15201A5CA8926329ULL,
		0x95AD5F66315704DEULL,
		0xF71A7B9D2CE9000DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5458C72F0EE88EDDULL,
		0xB5F92042DC27772FULL,
		0x6AD9C6EE3CD39028ULL,
		0x7AED95FDCB430FC2ULL,
		0x754F0394DD75883CULL,
		0x4C87C01CDC4EE000ULL,
		0x906BB461AA99FC56ULL,
		0x5C7953425AA235C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DCA591A5899E6CULL,
		0xE2C0DFAA23D94136ULL,
		0x7890A167D7DA9F78ULL,
		0x3018CDDEA87014F9ULL,
		0xB5E9C4A8F8E91CEBULL,
		0x103B6664A4319CA8ULL,
		0x9EBCBE21E72035A1ULL,
		0x6D88C368B16EB41BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x337C219D695EF071ULL,
		0xD3384098B84E35F9ULL,
		0xF249258664F8F0AFULL,
		0x4AD4C81F22D2FAC8ULL,
		0xBF653EEBE48C6B51ULL,
		0x3C4C59B8381D4357ULL,
		0xF1AEF63FC379C6B5ULL,
		0xEEF08FD9A93381A6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x24AB9426D1B7892BULL,
		0xA256C51C3F437971ULL,
		0x125B3C08B78082B7ULL,
		0xBB2461F414A0561CULL,
		0x6E77A30931BAB871ULL,
		0xD5F737F765E7A881ULL,
		0x97E26EFDA06404B7ULL,
		0x3D3C180D6CD52659ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC03260900AFD316ULL,
		0x7895C373EDF01FA7ULL,
		0x94C9E52901003B21ULL,
		0x5B825A5315BDAC82ULL,
		0xDF226B8FA06EBDCFULL,
		0x01183C75EF37EC07ULL,
		0x0D6744B30CD8994AULL,
		0x8DD09ADAD53EC643ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28A86E1DD107B615ULL,
		0x29C101A8515359C9ULL,
		0x7D9156DFB6804796ULL,
		0x5FA207A0FEE2A999ULL,
		0x8F553779914BFAA2ULL,
		0xD4DEFB8176AFBC79ULL,
		0x8A7B2A4A938B6B6DULL,
		0xAF6B7D3297966016ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0009EDA0B4358685ULL,
		0xCD0E8758BFE83B05ULL,
		0xB8BA98EC019C1DD8ULL,
		0x19DA98E0552B4627ULL,
		0xE2652C4F2636DD28ULL,
		0x64ABBD571D7A7B82ULL,
		0x6914F7A94EEB4D79ULL,
		0xE5B001C511435E0DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EAFEFB6A4A1F6FULL,
		0x4A14660720DCABBCULL,
		0x8A1F23C7DF9AA418ULL,
		0x95D5B2D52CABA487ULL,
		0xED6C0BC58EB7811CULL,
		0xCA888C154F6AA03DULL,
		0xB538289BEEE65F02ULL,
		0x1FC60B18CE2908FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A1EEEA549EB6716ULL,
		0x82FA21519F0B8F48ULL,
		0x2E9B7524220179C0ULL,
		0x8404E60B287FA1A0ULL,
		0xF4F92089977F5C0BULL,
		0x9A233141CE0FDB44ULL,
		0xB3DCCF0D6004EE76ULL,
		0xC5E9F6AC431A550DULL
	}};
	sign = 0;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5F5F2941B8CCBF6FULL,
		0xAC54FBEB92C14052ULL,
		0x8020E73ECF889966ULL,
		0xE85B22D64782B8A7ULL,
		0x9B8A91B7A28DE5E6ULL,
		0x6CCF2C2360E38171ULL,
		0x56E034576D9852E0ULL,
		0xB816A4B235E494FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E5BE52C141A33BCULL,
		0x82AF11CB19550171ULL,
		0x2B1E97D214509121ULL,
		0x64325DD021275688ULL,
		0x65B26B41D3537219ULL,
		0xB2782B1AFAF149D7ULL,
		0x8BC3E87C4A0CDEEFULL,
		0x73BF5BC6C77164EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1034415A4B28BB3ULL,
		0x29A5EA20796C3EE0ULL,
		0x55024F6CBB380845ULL,
		0x8428C506265B621FULL,
		0x35D82675CF3A73CDULL,
		0xBA57010865F2379AULL,
		0xCB1C4BDB238B73F0ULL,
		0x445748EB6E733010ULL
	}};
	sign = 0;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF4C69E7ABD034693ULL,
		0xF99E11CB63EE1765ULL,
		0x65323C7858279AF1ULL,
		0x7F5D8B78DDE68441ULL,
		0xE82014CB1134D436ULL,
		0x468E3F585526DBF1ULL,
		0x5C5C4DA2D17494A5ULL,
		0xF1D86F53E995CD3FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A730F97B514367ULL,
		0x5EC3E709AB95F282ULL,
		0x5FFB5F0116BD05C9ULL,
		0x0E843F2A28C17515ULL,
		0x7613F073EBFAC9ACULL,
		0x00676462AB95D6A0ULL,
		0xDE40C9C9CC3E3D18ULL,
		0x88E463EB05FE10EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x701F6D8141B2032CULL,
		0x9ADA2AC1B85824E3ULL,
		0x0536DD77416A9528ULL,
		0x70D94C4EB5250F2CULL,
		0x720C2457253A0A8AULL,
		0x4626DAF5A9910551ULL,
		0x7E1B83D90536578DULL,
		0x68F40B68E397BC4FULL
	}};
	sign = 0;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x40778ECD701E46A7ULL,
		0x0201F1486558A874ULL,
		0x75AA8BD35D937054ULL,
		0x38AB502A531ECBE8ULL,
		0xD760826FA21229B9ULL,
		0x7BC9BAA06614BB86ULL,
		0x45B25A95C383D457ULL,
		0x2A1F391E4442F625ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6AB6BEBC47A8B8CULL,
		0x608DFFB042B5070EULL,
		0x5F2A5E95C0834341ULL,
		0x7BC57B63C92458D5ULL,
		0x694609536AF52B43ULL,
		0xCB26E0D677AD9386ULL,
		0xB92D7169E52E08D4ULL,
		0xA2BD3B4A1D6224DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59CC22E1ABA3BB1BULL,
		0xA173F19822A3A165ULL,
		0x16802D3D9D102D12ULL,
		0xBCE5D4C689FA7313ULL,
		0x6E1A791C371CFE75ULL,
		0xB0A2D9C9EE672800ULL,
		0x8C84E92BDE55CB82ULL,
		0x8761FDD426E0D146ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B90E42B97BCD2AAULL,
		0xB12E8946972854BDULL,
		0x74B68B13E0F337B5ULL,
		0x2CF4705CCC85820BULL,
		0x4DE115C94C16B2D9ULL,
		0xEB91C50D630A9C4CULL,
		0xA6D4CCD5B3619FE3ULL,
		0xF6677437298A67B3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBDBF6D14106D26ULL,
		0x77073DC43D0D79AFULL,
		0x82E359A503D2EC10ULL,
		0xEFA0F0B57F32DC96ULL,
		0x065960188B684972ULL,
		0x341F8A4726C73F7AULL,
		0xFBCC1D0B4C4BA872ULL,
		0x9760E4A0E6E0D0A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ED324BE83AC6584ULL,
		0x3A274B825A1ADB0DULL,
		0xF1D3316EDD204BA5ULL,
		0x3D537FA74D52A574ULL,
		0x4787B5B0C0AE6966ULL,
		0xB7723AC63C435CD2ULL,
		0xAB08AFCA6715F771ULL,
		0x5F068F9642A99712ULL
	}};
	sign = 0;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x402360FEEE87AEF7ULL,
		0x5DA378E468E41399ULL,
		0xFA62C1E4AC095A44ULL,
		0xBC5B07073964E6E3ULL,
		0xC329A9EAD80FFB69ULL,
		0x478F563F69B7B49FULL,
		0x41C6125D6B70618CULL,
		0x91DC9257C740444CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x044FDDA861044B72ULL,
		0x4E32449ACA009ACAULL,
		0x7985297FFDD815F0ULL,
		0xE59F80B89A097A43ULL,
		0xAE6540793D3A8138ULL,
		0xFD0F106107E2F852ULL,
		0x599D434D4B7EB9B0ULL,
		0x5DCE2B45C60FE00BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BD383568D836385ULL,
		0x0F7134499EE378CFULL,
		0x80DD9864AE314454ULL,
		0xD6BB864E9F5B6CA0ULL,
		0x14C469719AD57A30ULL,
		0x4A8045DE61D4BC4DULL,
		0xE828CF101FF1A7DBULL,
		0x340E671201306440ULL
	}};
	sign = 0;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x103559E908432DDBULL,
		0xCC66D97FD336551FULL,
		0x4E57ED6318DCE07EULL,
		0x31C3B0B05262C355ULL,
		0xDCD7BE7D395CDF04ULL,
		0x84E8F5B250005B87ULL,
		0x4E13EE1EB7CF31FDULL,
		0xB9F32150AF7B4DDBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x278D756492E59782ULL,
		0xED372A6AF2097034ULL,
		0xDEBBACA0E7C62161ULL,
		0x3CDED90786BA6AFBULL,
		0x9689AF02B01D0A73ULL,
		0xC9C0689796B952EDULL,
		0xB5FB7AEC5BFE263CULL,
		0xFF55276C1D73736CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8A7E484755D9659ULL,
		0xDF2FAF14E12CE4EAULL,
		0x6F9C40C23116BF1CULL,
		0xF4E4D7A8CBA85859ULL,
		0x464E0F7A893FD490ULL,
		0xBB288D1AB947089AULL,
		0x981873325BD10BC0ULL,
		0xBA9DF9E49207DA6EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xABEA66CE3B3581E6ULL,
		0x29C2E3DF3DA4BFC3ULL,
		0xAAC6F989FAFFD0E4ULL,
		0x382F099EB00D9E89ULL,
		0xF85F91483F61B120ULL,
		0xBBC190183CFB731EULL,
		0x7241E686433695C0ULL,
		0xA58A3B332176FDCAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F504D785C81394ULL,
		0x440EC032E5732950ULL,
		0xAAB7645FB50AE89BULL,
		0x3CDAEBC5814B6C6EULL,
		0xDDA9881D9D73489EULL,
		0x6F2637CA87936C8AULL,
		0x1A779CBAAD236963ULL,
		0x524934CF66A1D415ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79F561F6B56D6E52ULL,
		0xE5B423AC58319673ULL,
		0x000F952A45F4E848ULL,
		0xFB541DD92EC2321BULL,
		0x1AB6092AA1EE6881ULL,
		0x4C9B584DB5680694ULL,
		0x57CA49CB96132C5DULL,
		0x53410663BAD529B5ULL
	}};
	sign = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x72412FC900FEFB21ULL,
		0xF75F6FB1FB711FD4ULL,
		0x244333E89BA8A283ULL,
		0x890AE8D6D7B32A51ULL,
		0xD1935484D97169DFULL,
		0xBAE3B1AA1C1F3C77ULL,
		0xC10C4F6212C952A9ULL,
		0xC8A4D154559AE8EDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38607450B989EFE1ULL,
		0x796C64FD144CC502ULL,
		0xAF45A1E8ED168CB5ULL,
		0xDF4BBB4ED31A6E96ULL,
		0x6C496E175CB5998DULL,
		0x7F995073D8D1D992ULL,
		0xFEF396C5264957F0ULL,
		0xC422CAFE7847AB52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39E0BB7847750B40ULL,
		0x7DF30AB4E7245AD2ULL,
		0x74FD91FFAE9215CEULL,
		0xA9BF2D880498BBBAULL,
		0x6549E66D7CBBD051ULL,
		0x3B4A6136434D62E5ULL,
		0xC218B89CEC7FFAB9ULL,
		0x04820655DD533D9AULL
	}};
	sign = 0;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x176D6131EC42A5D2ULL,
		0xE5929DAF26644772ULL,
		0xE3E213FF57EBFA5FULL,
		0xB423AFD58C5A0D0CULL,
		0x73184E1A5D4F6BC6ULL,
		0xC58A8F22FA22D066ULL,
		0xF8BF39601DF99217ULL,
		0x4874D19CAAE9127AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C361C707B076EEULL,
		0xFF6013B9622F5176ULL,
		0x33659E63C3EC67ECULL,
		0x4CFF67F95EB42BFDULL,
		0x9BEB653C1E8F3555ULL,
		0x3B81D93A9FF2DFCDULL,
		0x81EE4C364D061418ULL,
		0xD699911E556E74C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5A9FF6AE4922EE4ULL,
		0xE63289F5C434F5FBULL,
		0xB07C759B93FF9272ULL,
		0x672447DC2DA5E10FULL,
		0xD72CE8DE3EC03671ULL,
		0x8A08B5E85A2FF098ULL,
		0x76D0ED29D0F37DFFULL,
		0x71DB407E557A9DBAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x23F4B04C27DAA87EULL,
		0x21813DC8D1F61217ULL,
		0x34A4F9C0736C04BDULL,
		0x05AA3399F0180572ULL,
		0xA0B51A6B76353BA9ULL,
		0xA45551385DA605BCULL,
		0xF5AD5C5BA91AA3C4ULL,
		0xDF8B9FC77B0421D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x278AE5233B87005FULL,
		0x7B2F143237DDD82AULL,
		0xA5C6B4F1504642FFULL,
		0x1FEDD2FDD33F1E49ULL,
		0x505769B1BE145978ULL,
		0xD81B2B41618E223DULL,
		0x941310F2DE5EA57AULL,
		0x8DCCFB07706ADDE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC69CB28EC53A81FULL,
		0xA65229969A1839ECULL,
		0x8EDE44CF2325C1BDULL,
		0xE5BC609C1CD8E728ULL,
		0x505DB0B9B820E230ULL,
		0xCC3A25F6FC17E37FULL,
		0x619A4B68CABBFE49ULL,
		0x51BEA4C00A9943EDULL
	}};
	sign = 0;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBC3C98EDB3F5C5C3ULL,
		0xD21B86861897A61CULL,
		0xCD50404FD3302488ULL,
		0x02DA93806F37FC05ULL,
		0xB0DE582388CBACF2ULL,
		0xBB78959DF114B29BULL,
		0x94E51A5169D1CDC8ULL,
		0xA184593E4BAFB227ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A77C7B0DEAA5271ULL,
		0x633E41532CA1BD49ULL,
		0x2DBD578740171B77ULL,
		0xB7D4AAABC78689F9ULL,
		0x2A3E503A32AC53C4ULL,
		0x15F5B645DBBA7CFBULL,
		0xCFFD5ADFEEDC0DF7ULL,
		0x525F9B8969333000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1C4D13CD54B7352ULL,
		0x6EDD4532EBF5E8D3ULL,
		0x9F92E8C893190911ULL,
		0x4B05E8D4A7B1720CULL,
		0x86A007E9561F592DULL,
		0xA582DF58155A35A0ULL,
		0xC4E7BF717AF5BFD1ULL,
		0x4F24BDB4E27C8226ULL
	}};
	sign = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5D266FDA5B040C6DULL,
		0x91E648DF86AF5A78ULL,
		0xCF212DF431C33F6DULL,
		0xC9A85615E7D09E66ULL,
		0x71AD23F061BFCC03ULL,
		0x7B6980556AA69E46ULL,
		0xBC625F074CF094C2ULL,
		0x929EBE9D74BB4370ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1276477376908C0AULL,
		0x767BA19BA2C9D3C1ULL,
		0xF9CA7B0DE7690C2FULL,
		0x8EE7DDABC402CCF9ULL,
		0x0D2C08E8CBEAE390ULL,
		0xCF3DE7710E6A0943ULL,
		0x8760D76C747A3FD4ULL,
		0xBE82EEDA4145F80BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AB02866E4738063ULL,
		0x1B6AA743E3E586B7ULL,
		0xD556B2E64A5A333EULL,
		0x3AC0786A23CDD16CULL,
		0x64811B0795D4E873ULL,
		0xAC2B98E45C3C9503ULL,
		0x3501879AD87654EDULL,
		0xD41BCFC333754B65ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x92003D1B74D74709ULL,
		0x23CE3B50F1E0F73CULL,
		0x131CE11988431BDEULL,
		0xEB24BF4E16BF2EE0ULL,
		0x7BEC9258266A7805ULL,
		0x76316FC8A7E45F7AULL,
		0xC209981D14C43408ULL,
		0x378F75F3300B8828ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE468FCFD46F4ECACULL,
		0xF3C7AF5A6F603A26ULL,
		0xDD28FDC7BB46B68CULL,
		0xE5C512DDD2821B12ULL,
		0x9E41653C724F8E3DULL,
		0x302E37271B3A70CCULL,
		0x7ECC38CB05BE8DB5ULL,
		0xFCEA27A785897B19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD97401E2DE25A5DULL,
		0x30068BF68280BD15ULL,
		0x35F3E351CCFC6551ULL,
		0x055FAC70443D13CDULL,
		0xDDAB2D1BB41AE9C8ULL,
		0x460338A18CA9EEADULL,
		0x433D5F520F05A653ULL,
		0x3AA54E4BAA820D0FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5CB777CDE3FA22C0ULL,
		0x3D75F3AAD5F7A5D9ULL,
		0x837FB5C2770D0460ULL,
		0xB28EE9E2D84347CAULL,
		0xD660DEAF902BA10FULL,
		0xD7F72BEB1EB5CE41ULL,
		0xE13C9C90EACDA22AULL,
		0xB7FB6D73C0217106ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE16CB1D5A2B9327ULL,
		0x85FED1A90990AA5DULL,
		0x36D937AAA7B5DB27ULL,
		0x6F62876AA167B0EEULL,
		0xC1EFC8B381151588ULL,
		0x5937E3F1278364D1ULL,
		0x26E6109B163C1A69ULL,
		0xC9B9CD77700248D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EA0ACB089CE8F99ULL,
		0xB7772201CC66FB7BULL,
		0x4CA67E17CF572938ULL,
		0x432C627836DB96DCULL,
		0x147115FC0F168B87ULL,
		0x7EBF47F9F7326970ULL,
		0xBA568BF5D49187C1ULL,
		0xEE419FFC501F282DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x816EDF4E82328273ULL,
		0x15199FEF212D75B4ULL,
		0x32B781D7B6FEDE7CULL,
		0x1B71BD7964341068ULL,
		0xEF6127C75032E383ULL,
		0x508FFF182B99F64FULL,
		0xE561C77AB918842BULL,
		0x6D8806A227E84028ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA58B15DC61E167ULL,
		0xBA803AC470798A00ULL,
		0xE70B1F4DA619C7C7ULL,
		0x68385F2BDDA362C4ULL,
		0x65CDC2315DE27359ULL,
		0x7B3E24652D1F3D7DULL,
		0x0E8183417DFC5A90ULL,
		0x1804BB90B443B5CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65C95438A5D0A10CULL,
		0x5A99652AB0B3EBB4ULL,
		0x4BAC628A10E516B4ULL,
		0xB3395E4D8690ADA3ULL,
		0x89936595F2507029ULL,
		0xD551DAB2FE7AB8D2ULL,
		0xD6E044393B1C299AULL,
		0x55834B1173A48A59ULL
	}};
	sign = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8652957E112B3035ULL,
		0x23080FC30076BA49ULL,
		0x35E16BFF785EDF24ULL,
		0x1C9706A6C5C0F192ULL,
		0x115ED73A23D36676ULL,
		0x3F377DCB92972764ULL,
		0xCA3C865B76E6059FULL,
		0xF394241EB7B76B8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2FC5D333F1386C7ULL,
		0x8B6DBEBB97712133ULL,
		0xB98E5BE02A34A3B6ULL,
		0x8EB6C197DAF5A5E5ULL,
		0x9DEF92AAF26A671DULL,
		0xEAFF3C096B084017ULL,
		0x100BB9BCA99BA019ULL,
		0x8D556FD3F81F30B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA356384AD217A96EULL,
		0x979A510769059915ULL,
		0x7C53101F4E2A3B6DULL,
		0x8DE0450EEACB4BACULL,
		0x736F448F3168FF58ULL,
		0x543841C2278EE74CULL,
		0xBA30CC9ECD4A6585ULL,
		0x663EB44ABF983AD7ULL
	}};
	sign = 0;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC5A5469F3CE02BA8ULL,
		0x38532958CB85257DULL,
		0x04646D51E256C3EAULL,
		0xA7C2D6B47E5B49B7ULL,
		0x373109FFF232E7BAULL,
		0x1895DDCFD5E07546ULL,
		0x2DA0651CD316AFD3ULL,
		0xE98259D84272CD6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CE87359AA502C5ULL,
		0xD549B162B3704F67ULL,
		0xAFBA243A5CD801DBULL,
		0x30592841383290D6ULL,
		0x9EFC0270538A17C1ULL,
		0x1DC373BCF594B9F4ULL,
		0x2F1F78ACC596B83CULL,
		0xA1FB209441A56F49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ED6BF69A23B28E3ULL,
		0x630977F61814D616ULL,
		0x54AA4917857EC20EULL,
		0x7769AE734628B8E0ULL,
		0x9835078F9EA8CFF9ULL,
		0xFAD26A12E04BBB51ULL,
		0xFE80EC700D7FF796ULL,
		0x4787394400CD5E21ULL
	}};
	sign = 0;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x203BC85A16B1DA40ULL,
		0xE85C72A769472061ULL,
		0x4984B46A630E8040ULL,
		0x55F75558598C65C6ULL,
		0xBFA1AEBB187D2024ULL,
		0xF1418CE49F1F1D44ULL,
		0x7509CFBC8ED37AE7ULL,
		0x1D768A8B23590A59ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3229CA1FD8845386ULL,
		0x66155E3509354596ULL,
		0xD4ECE7C0333AA565ULL,
		0x29A8AB9ECBAB21A8ULL,
		0x53E9081E6C8E6BC8ULL,
		0x977A902F1DDF21ECULL,
		0xDCD3BA977AD3D58AULL,
		0x64B97EF9A22BC093ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE11FE3A3E2D86BAULL,
		0x824714726011DACAULL,
		0x7497CCAA2FD3DADBULL,
		0x2C4EA9B98DE1441DULL,
		0x6BB8A69CABEEB45CULL,
		0x59C6FCB5813FFB58ULL,
		0x9836152513FFA55DULL,
		0xB8BD0B91812D49C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6638E0261766803DULL,
		0x7E9E60FBE8F5DB41ULL,
		0x83E503D51626B9D7ULL,
		0x8E692F6D834EB3A5ULL,
		0xC014D9BBBF7B2E01ULL,
		0xBFFCABAD047A57B8ULL,
		0x7C88A34B09FEE691ULL,
		0x6FF029C66F4D6542ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x58BD8A87112CEA05ULL,
		0xF9A63991007231A2ULL,
		0x494AEC9EE46CC45DULL,
		0xF1E36A9F43DE1370ULL,
		0xE6871A7F0585FBF5ULL,
		0x756D7390C598F543ULL,
		0xB4D36ACA5AA512FCULL,
		0x906D8C265B500337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D7B559F06399638ULL,
		0x84F8276AE883A99FULL,
		0x3A9A173631B9F579ULL,
		0x9C85C4CE3F70A035ULL,
		0xD98DBF3CB9F5320BULL,
		0x4A8F381C3EE16274ULL,
		0xC7B53880AF59D395ULL,
		0xDF829DA013FD620AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC5F41D6B75920D19ULL,
		0x1C50BC1E2A7F046DULL,
		0xA1A1A8F3BC8FE618ULL,
		0xD294D073CC34A37EULL,
		0x2D5CF562ABDFF2E6ULL,
		0x377A9795A9B02839ULL,
		0xA1E7BE005D5DCC5EULL,
		0x4C10EADAF67051ECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B0B04195DC6D06CULL,
		0x7A2B97D9BFE00217ULL,
		0xAD5A2FCBD405DEFDULL,
		0x10230BB7B0CFD6B1ULL,
		0xA2DE6EA84CC7221FULL,
		0xA3E8FF1752B135C1ULL,
		0x9D0DA84968C7C4E3ULL,
		0xECD85578827D8661ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE9195217CB3CADULL,
		0xA22524446A9F0256ULL,
		0xF4477927E88A071AULL,
		0xC271C4BC1B64CCCCULL,
		0x8A7E86BA5F18D0C7ULL,
		0x9391987E56FEF277ULL,
		0x04DA15B6F496077AULL,
		0x5F38956273F2CB8BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00B5458D2625E32CULL,
		0xBFE7529D9E3DFFA2ULL,
		0x3549F79F2B8F41C9ULL,
		0xF98240AC7A5E2047ULL,
		0x847B93B152B844ACULL,
		0x96890AD84983B5E3ULL,
		0x25CFF2CDB99DD45FULL,
		0xE92597B0E43F3984ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ABEECA76FAF9E51ULL,
		0x6FA66438328732FAULL,
		0x23506038240AB200ULL,
		0x0FDC7089868EC7ABULL,
		0x8A7AF175293CE2BBULL,
		0xADB372DD61545A13ULL,
		0xE335FAD17BF6C62FULL,
		0x5CE2EAC7C7DA8498ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95F658E5B67644DBULL,
		0x5040EE656BB6CCA7ULL,
		0x11F9976707848FC9ULL,
		0xE9A5D022F3CF589CULL,
		0xFA00A23C297B61F1ULL,
		0xE8D597FAE82F5BCFULL,
		0x4299F7FC3DA70E2FULL,
		0x8C42ACE91C64B4EBULL
	}};
	sign = 0;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7DA39E42279E3964ULL,
		0xC42D0A4747D3CFB8ULL,
		0xA2D956D270645AB3ULL,
		0x5F681C79B3AE7D8EULL,
		0xE7DDFFF096FED6B7ULL,
		0xF6FAE8FA5F8E22BBULL,
		0x8AD2B2D53EF88D84ULL,
		0x43BDBFD26B91A5B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95BBA9E47753CDD7ULL,
		0xCA3C1B6831174C28ULL,
		0x2A1D9ACE30FCC6DFULL,
		0xAC127DD20DD86D5BULL,
		0x9D4ED677D869D3C7ULL,
		0x34F69687BF2F790EULL,
		0xE3931004553562FAULL,
		0x6A88F3CD549DF201ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7E7F45DB04A6B8DULL,
		0xF9F0EEDF16BC838FULL,
		0x78BBBC043F6793D3ULL,
		0xB3559EA7A5D61033ULL,
		0x4A8F2978BE9502EFULL,
		0xC2045272A05EA9ADULL,
		0xA73FA2D0E9C32A8AULL,
		0xD934CC0516F3B3B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE07963D0DFCBFB3AULL,
		0x3B752E1BC11E3ADFULL,
		0xEBC390EA1508E0C7ULL,
		0x2B592E9A6586C829ULL,
		0x772D235F481DE8C8ULL,
		0x6FA12865537E8CDAULL,
		0xB4DF5EB5050DE076ULL,
		0x3286CB2C5148B6E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x36F9DBEEE0A5E45AULL,
		0x6FC85575FB25C0BDULL,
		0x9953B2AE5A4A3581ULL,
		0x843D789343821C39ULL,
		0x4636345BA1C507A3ULL,
		0x14A6EBF365FB89B9ULL,
		0xE4ECD40F53225EE0ULL,
		0x425E7330D8B82886ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA97F87E1FF2616E0ULL,
		0xCBACD8A5C5F87A22ULL,
		0x526FDE3BBABEAB45ULL,
		0xA71BB6072204ABF0ULL,
		0x30F6EF03A658E124ULL,
		0x5AFA3C71ED830321ULL,
		0xCFF28AA5B1EB8196ULL,
		0xF02857FB78908E5FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5E274E098AA09EFEULL,
		0xD01D8AAC81D808FBULL,
		0xCBE0104996C45EC0ULL,
		0xA1575BB771AC2BC9ULL,
		0x554F1D9E3829B305ULL,
		0x63BD4669966D497FULL,
		0x0CAE7399ECEB52F5ULL,
		0x8DB02751048E333CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAAD5EC5B1C312B6ULL,
		0x3CF8C2712BF0BF82ULL,
		0x4813FC2B1948B26AULL,
		0xB3BA517FAC6DCA2AULL,
		0x1C3F722CD79B6BEBULL,
		0x83244A4281A40799ULL,
		0x6B11C19B5609ED12ULL,
		0x78CF077A3492FFB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7379EF43D8DD8C48ULL,
		0x9324C83B55E74978ULL,
		0x83CC141E7D7BAC56ULL,
		0xED9D0A37C53E619FULL,
		0x390FAB71608E4719ULL,
		0xE098FC2714C941E6ULL,
		0xA19CB1FE96E165E2ULL,
		0x14E11FD6CFFB338AULL
	}};
	sign = 0;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1E50E95878EE8FCDULL,
		0x19B93808F6375B6CULL,
		0xD3E665A074B40376ULL,
		0x48EB054B53C30026ULL,
		0xDC2885B35203AA32ULL,
		0x32A6D3ACFD257534ULL,
		0x26076E8F653F7A09ULL,
		0xAA18B4F00369A3F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B1A74355381042ULL,
		0x52CA327179B6FF08ULL,
		0xE10A9076F952EF73ULL,
		0x44F0A4FE83F95C67ULL,
		0x7847BE1943255696ULL,
		0x66AAE6C6BED4C405ULL,
		0x40EBA4E3D826B0A0ULL,
		0x89D55C167D006427ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A9F421523B67F8BULL,
		0xC6EF05977C805C63ULL,
		0xF2DBD5297B611402ULL,
		0x03FA604CCFC9A3BEULL,
		0x63E0C79A0EDE539CULL,
		0xCBFBECE63E50B12FULL,
		0xE51BC9AB8D18C968ULL,
		0x204358D986693FCDULL
	}};
	sign = 0;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C4864D0B9F9C917ULL,
		0x9AA45E4C89647194ULL,
		0x1627B41F1711A522ULL,
		0x4925202D9BD2EBF9ULL,
		0x46CD9CED59BBD812ULL,
		0x6DFBC74973F224B8ULL,
		0xFAC80B45AC050DF6ULL,
		0x3316477E07700592ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9758FEDB2AE29DCBULL,
		0x5722ED2205CA0E5FULL,
		0xFEBB229C91F54800ULL,
		0x475DDAA4501CD575ULL,
		0x5631A01B3A0D8769ULL,
		0xFE303397568E7179ULL,
		0xD2691AFDD6D8EEE3ULL,
		0xDE38132857A39302ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84EF65F58F172B4CULL,
		0x4381712A839A6334ULL,
		0x176C9182851C5D22ULL,
		0x01C745894BB61683ULL,
		0xF09BFCD21FAE50A9ULL,
		0x6FCB93B21D63B33EULL,
		0x285EF047D52C1F12ULL,
		0x54DE3455AFCC7290ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC0F7799115CC3B11ULL,
		0x06832771B95957FAULL,
		0xE8459FFD5841A1FFULL,
		0x7D4BC441AA762A67ULL,
		0x0FB9B9E3AA0A0862ULL,
		0x9011A08929D5D862ULL,
		0x80605C9A4E0BDC2DULL,
		0x72D5FFB34F432CF5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC85F5BAA2DD370E1ULL,
		0xA3B540CD02F19C98ULL,
		0x58012C38050B7BACULL,
		0x4FC7170C7B21D7D1ULL,
		0xA0D1C647BDAC76CFULL,
		0x06E7BF5AB8BCAA99ULL,
		0xEA39F0AF385A1FD9ULL,
		0x56536B47C9083C18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8981DE6E7F8CA30ULL,
		0x62CDE6A4B667BB61ULL,
		0x904473C553362652ULL,
		0x2D84AD352F545296ULL,
		0x6EE7F39BEC5D9193ULL,
		0x8929E12E71192DC8ULL,
		0x96266BEB15B1BC54ULL,
		0x1C82946B863AF0DCULL
	}};
	sign = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCD77D1EBC32792E7ULL,
		0x9DAD3F7FB49A82F2ULL,
		0x52B120E03CB67698ULL,
		0x97CF81892A4A41F1ULL,
		0xD7EA40306B643BD6ULL,
		0x0ECEE400D9EE7F74ULL,
		0x42501D763523C252ULL,
		0x7EF14F2C93570BD4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC7704233E197ECDULL,
		0x79C125588A24CDD5ULL,
		0x6C6436CF5C034002ULL,
		0x941A250E6E32B073ULL,
		0xF95C96A8EB669B12ULL,
		0xD8F06C3CD224DD9EULL,
		0x0F85388EA66BDD5FULL,
		0x067EA24C4206BDF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE100CDC8850E141AULL,
		0x23EC1A272A75B51CULL,
		0xE64CEA10E0B33696ULL,
		0x03B55C7ABC17917DULL,
		0xDE8DA9877FFDA0C4ULL,
		0x35DE77C407C9A1D5ULL,
		0x32CAE4E78EB7E4F2ULL,
		0x7872ACE051504DDBULL
	}};
	sign = 0;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE3E5A160062B388DULL,
		0xA52D5783CED73573ULL,
		0xD21835ABA64D4D64ULL,
		0x1041330837B3BD43ULL,
		0x4966C62D55CDBB74ULL,
		0x247E58B2957B64D9ULL,
		0x335298C8DE3E23A7ULL,
		0x068DB35D7C3DE15EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF3D5A61112EC432ULL,
		0x50A6D19950D29C94ULL,
		0x5283C03E0BF1EC42ULL,
		0x84EF71C9580D3A5DULL,
		0x3AAE7CACBD0637ABULL,
		0x3F36CE5189AC34A2ULL,
		0x6AB236A398842B9DULL,
		0x5D01CA289688434AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4A846FEF4FC745BULL,
		0x548685EA7E0498DEULL,
		0x7F94756D9A5B6122ULL,
		0x8B51C13EDFA682E6ULL,
		0x0EB8498098C783C8ULL,
		0xE5478A610BCF3037ULL,
		0xC8A0622545B9F809ULL,
		0xA98BE934E5B59E13ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4FF99E3FC953A9DDULL,
		0x6F01C5FFB2268993ULL,
		0x7672A3C76E9FBBE0ULL,
		0xCC3FF0B42F6D5557ULL,
		0xEC1137AA81D488F4ULL,
		0x17247A79EE87E08EULL,
		0xAA495A60754E11F5ULL,
		0x3580554AE1787AE9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F28906BE30EBD79ULL,
		0xC734F49C53230A45ULL,
		0x96A98D73791D955AULL,
		0xAF222AF220DF97E2ULL,
		0x24577723F03E42B6ULL,
		0xA6208084D264952DULL,
		0x282AAEE2BD46CD33ULL,
		0x99830A654EB66551ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0D10DD3E644EC64ULL,
		0xA7CCD1635F037F4DULL,
		0xDFC91653F5822685ULL,
		0x1D1DC5C20E8DBD74ULL,
		0xC7B9C0869196463EULL,
		0x7103F9F51C234B61ULL,
		0x821EAB7DB80744C1ULL,
		0x9BFD4AE592C21598ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB04F0482837E463DULL,
		0xF8FA8E18D46E1F72ULL,
		0x512AB182C3D3FF00ULL,
		0x30D12132CB0D4F0EULL,
		0x8DF61495A0D7FFD7ULL,
		0xA4D04A526B1629F2ULL,
		0x5CE82AB19AA3D2F5ULL,
		0xD052798D7F7DC356ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB02893105C9965ULL,
		0xD4B7F725E53FF7E8ULL,
		0x72449EA6B5AD1E52ULL,
		0xB32E6BC5B1F63B84ULL,
		0xC3F78A7B7134FC26ULL,
		0xDCB6575F4E4DA085ULL,
		0xDBB17EFA0FCB6B1EULL,
		0xE687352F7512E31BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x149EDBEF7321ACD8ULL,
		0x244296F2EF2E278AULL,
		0xDEE612DC0E26E0AEULL,
		0x7DA2B56D19171389ULL,
		0xC9FE8A1A2FA303B0ULL,
		0xC819F2F31CC8896CULL,
		0x8136ABB78AD867D6ULL,
		0xE9CB445E0A6AE03AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7E0FB9269CCBA41AULL,
		0x15E8867FA4DE1A75ULL,
		0x0C3F921B8D7092EFULL,
		0x842EDA2CD634F062ULL,
		0x5C5012EE5B8DDFE2ULL,
		0xEBC6A5A655A7108EULL,
		0x9EF98D6E4195F486ULL,
		0x18C3C5681013E73CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A2A22565FEE335ULL,
		0x897D1F7D6E88018CULL,
		0x9132214E84E560B0ULL,
		0xEB0543A0D2111144ULL,
		0x35E49F28DCB6D188ULL,
		0x33533E576DF1069CULL,
		0xA73908EBFB939A2AULL,
		0x69ED5353DD6CA576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA76D170136CCC0E5ULL,
		0x8C6B6702365618E8ULL,
		0x7B0D70CD088B323EULL,
		0x9929968C0423DF1DULL,
		0x266B73C57ED70E59ULL,
		0xB873674EE7B609F2ULL,
		0xF7C0848246025A5CULL,
		0xAED6721432A741C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6FCD0DEBB01976A5ULL,
		0x87726A922E6921A5ULL,
		0x19D32EE04E58C11BULL,
		0xACEF6B0AF9EA6F00ULL,
		0x0A9FF42B4E262A49ULL,
		0x06BABD3FC02E83B0ULL,
		0x6978B3E7B5383AE5ULL,
		0x493F34275521C071ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C12FE18A9A442A7ULL,
		0x5D99914D3BF3A6FCULL,
		0x9807E541E05A4CD5ULL,
		0x85C63B874F5A2C95ULL,
		0x744D4197027BD0BEULL,
		0xCC6D72FD3C614EE0ULL,
		0xC7CFB42E72EAEE82ULL,
		0xCE4C635088EB5A6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03BA0FD3067533FEULL,
		0x29D8D944F2757AA9ULL,
		0x81CB499E6DFE7446ULL,
		0x27292F83AA90426AULL,
		0x9652B2944BAA598BULL,
		0x3A4D4A4283CD34CFULL,
		0xA1A8FFB9424D4C62ULL,
		0x7AF2D0D6CC366602ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B5DE861FD71923EULL,
		0x3AC92C7C8B024B8DULL,
		0xAF2D93FC859CF0C5ULL,
		0x2AE276F10C7B925FULL,
		0x4031CA2EE7AF852AULL,
		0x1F67534A05C298F4ULL,
		0x5860FA232C00F51CULL,
		0xDADFB5A70AEB1DFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x843D285CD0E78738ULL,
		0xB9E3A98590CCD768ULL,
		0x9AF0C76A867D0756ULL,
		0x82C36059870EDD71ULL,
		0xDE60DDDC057945E0ULL,
		0x61132D969C66BAB9ULL,
		0xE8B13BBA5F1B0E24ULL,
		0x1D07C071C911F247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD720C0052C8A0B06ULL,
		0x80E582F6FA357424ULL,
		0x143CCC91FF1FE96EULL,
		0xA81F1697856CB4EEULL,
		0x61D0EC52E2363F49ULL,
		0xBE5425B3695BDE3AULL,
		0x6FAFBE68CCE5E6F7ULL,
		0xBDD7F53541D92BB3ULL
	}};
	sign = 0;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1CC612AD1EF47662ULL,
		0x8709448C831A4D27ULL,
		0x85759816E1134875ULL,
		0x58C775D423278E46ULL,
		0x3401D1FE0C2D8A66ULL,
		0xD374BBACB1A2BDC7ULL,
		0xCF00A3600AA2AF52ULL,
		0x06FCBC1344553967ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x87CB46D9C4A15E3FULL,
		0xA1DA5564F7FADBE7ULL,
		0xB6849A0C14615DECULL,
		0x6A970F2F866ADAB3ULL,
		0x1ED97DE94A6A2FBAULL,
		0x00DEA46F5450AD9FULL,
		0x1227562FB1C83EAEULL,
		0xDC186782C4C3AEC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94FACBD35A531823ULL,
		0xE52EEF278B1F713FULL,
		0xCEF0FE0ACCB1EA88ULL,
		0xEE3066A49CBCB392ULL,
		0x15285414C1C35AABULL,
		0xD296173D5D521028ULL,
		0xBCD94D3058DA70A4ULL,
		0x2AE454907F918AA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7848FD94C0DA589FULL,
		0xFA473FCB59E2639BULL,
		0xA51E6764D2D2D72CULL,
		0x6A831254FE8A3CF7ULL,
		0xF39F612B41F44AB1ULL,
		0x4BFF440722CB9171ULL,
		0xC0042E50B9B44946ULL,
		0x4A7230FCC828312DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x175DC0018C72A432ULL,
		0x797D0B1051B2B17DULL,
		0xAD7720AD6C155C8FULL,
		0x3F80140C20FCE32DULL,
		0x0D37D7C5F3D893F8ULL,
		0xCEF5F615A1EFEDFCULL,
		0xD34A112087F6AC89ULL,
		0x57D7937F58CC5F3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60EB3D933467B46DULL,
		0x80CA34BB082FB21EULL,
		0xF7A746B766BD7A9DULL,
		0x2B02FE48DD8D59C9ULL,
		0xE66789654E1BB6B9ULL,
		0x7D094DF180DBA375ULL,
		0xECBA1D3031BD9CBCULL,
		0xF29A9D7D6F5BD1F2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8CDBED8A080444CDULL,
		0x528148561F16C1FCULL,
		0xF2E1E24F659BE64DULL,
		0x99153A1A27707008ULL,
		0x86A3392C61FA304BULL,
		0x0CA19B4511774C80ULL,
		0xC8D0CBC237C91560ULL,
		0x961DBFD771B40A61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F5DC078A2E1AD60ULL,
		0x78D40247ED17BE7EULL,
		0xD4D45B2A3D05226CULL,
		0xAB7F1E1FEE467792ULL,
		0xC92DE5569992EF9DULL,
		0x640E6A9A1D97F305ULL,
		0x7E3EEBF5690965C2ULL,
		0xFA75A7ECF8D3711AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D7E2D116522976DULL,
		0xD9AD460E31FF037EULL,
		0x1E0D87252896C3E0ULL,
		0xED961BFA3929F876ULL,
		0xBD7553D5C86740ADULL,
		0xA89330AAF3DF597AULL,
		0x4A91DFCCCEBFAF9DULL,
		0x9BA817EA78E09947ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE058B9C7F5237FAAULL,
		0x58BEB99175322BD8ULL,
		0x9D73D41478FA965BULL,
		0x7764F298E0AC70BEULL,
		0x379132ED097AC5ADULL,
		0x3D4170AD657FE7A8ULL,
		0x62ADFBD0C05589ECULL,
		0xFE81F00FB6F1A8F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x55A5B11785F60822ULL,
		0xA03F2B9B6215EAFBULL,
		0xE7EA362F1ED40415ULL,
		0xFD620C075CE44E8AULL,
		0x21221D62BB09B5AAULL,
		0xE50A92DE0F2BC724ULL,
		0x27DD01E93F81D312ULL,
		0xEEB9E0ACCE9D9301ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB308B06F2D7788ULL,
		0xB87F8DF6131C40DDULL,
		0xB5899DE55A269245ULL,
		0x7A02E69183C82233ULL,
		0x166F158A4E711002ULL,
		0x5836DDCF56542084ULL,
		0x3AD0F9E780D3B6D9ULL,
		0x0FC80F62E85415F0ULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1EDE8CB760FDB67DULL,
		0x8E868FAA1877A026ULL,
		0xD847901934B630A7ULL,
		0x47BD78160F7FE720ULL,
		0x5E4E4C67371EADF5ULL,
		0x0755AAF72DE257FAULL,
		0xEAF8B821BFD4F470ULL,
		0xCA5E3643825893D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x754D90DBE64C80C8ULL,
		0xCC5F41006C81C57DULL,
		0xF97185C2D536664DULL,
		0x2D3B57C699E589F9ULL,
		0xF643F973712C9E5AULL,
		0x2DADB54312D5D578ULL,
		0x13D7332D3BA36BC5ULL,
		0x33DDAEF7F51406A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA990FBDB7AB135B5ULL,
		0xC2274EA9ABF5DAA8ULL,
		0xDED60A565F7FCA59ULL,
		0x1A82204F759A5D26ULL,
		0x680A52F3C5F20F9BULL,
		0xD9A7F5B41B0C8281ULL,
		0xD72184F4843188AAULL,
		0x9680874B8D448D2DULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x60FFC52594CD42F2ULL,
		0x7F14CD987906E700ULL,
		0x105326A30652C5CBULL,
		0xEE6DED488513755CULL,
		0x493C7F8A4C713D47ULL,
		0xD81C0167FC9D98E9ULL,
		0x074D5C975DE4B3B9ULL,
		0x56A62B5936859797ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1C03283095BA05ULL,
		0x732E4C597257DD4FULL,
		0x7AF5489CA6AD2091ULL,
		0x1D5E5B15E7FBB1B3ULL,
		0x575BB9942F6CCD45ULL,
		0xF914CA3012530016ULL,
		0x9C9EE65AE1FA21ECULL,
		0x0D7E8A73B36632CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13E3C1FD643788EDULL,
		0x0BE6813F06AF09B1ULL,
		0x955DDE065FA5A53AULL,
		0xD10F92329D17C3A8ULL,
		0xF1E0C5F61D047002ULL,
		0xDF073737EA4A98D2ULL,
		0x6AAE763C7BEA91CCULL,
		0x4927A0E5831F64CCULL
	}};
	sign = 0;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x547EC6A62E20F551ULL,
		0xFC015A2AE7B6D7CFULL,
		0x16F51FF4A2490E1BULL,
		0x53058C19A7EDBA43ULL,
		0x0B17766E6F5F479CULL,
		0x3C053E60611251DCULL,
		0xAB59652C279637C9ULL,
		0x2627EF1487C9565EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x23B1E98B85594578ULL,
		0x7ABDA67BA35DB228ULL,
		0xC80D45E31642AAF1ULL,
		0x5F25DDCD3335C621ULL,
		0x4E4DA18D2A7F298AULL,
		0x33F6D0976B90B4E6ULL,
		0x325FCF5783B1BAD8ULL,
		0x225AD9B5EBFAB5F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30CCDD1AA8C7AFD9ULL,
		0x8143B3AF445925A7ULL,
		0x4EE7DA118C06632AULL,
		0xF3DFAE4C74B7F421ULL,
		0xBCC9D4E144E01E11ULL,
		0x080E6DC8F5819CF5ULL,
		0x78F995D4A3E47CF1ULL,
		0x03CD155E9BCEA06CULL
	}};
	sign = 0;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x718C905FF4B6DA7EULL,
		0xE017C1E3F2E563F3ULL,
		0x376AAB247F6F276AULL,
		0x46A5137FA37A8632ULL,
		0x750121ED1EF45A2DULL,
		0x49CA6D041BFD910EULL,
		0xE29D131B52726412ULL,
		0x455ABF81925BA690ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF56C3465F9C8A7FCULL,
		0xA03474985E370BC2ULL,
		0x3B81D05DECCC8D95ULL,
		0x4FA372F29DE00C05ULL,
		0xC5F9725C1325092EULL,
		0x4D5E66E46266D595ULL,
		0xF6E1F969B9568D4BULL,
		0x1BF4C6D8790C989DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C205BF9FAEE3282ULL,
		0x3FE34D4B94AE5830ULL,
		0xFBE8DAC692A299D5ULL,
		0xF701A08D059A7A2CULL,
		0xAF07AF910BCF50FEULL,
		0xFC6C061FB996BB78ULL,
		0xEBBB19B1991BD6C6ULL,
		0x2965F8A9194F0DF2ULL
	}};
	sign = 0;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5F19DFBBDF857B9ULL,
		0x912B39AA388F7824ULL,
		0x1C12B5823B351BB6ULL,
		0x9AD1F30C1F76CF49ULL,
		0x7A2111374B6FEEDAULL,
		0x8468838B631E53DEULL,
		0x98A598BEABDE4CA1ULL,
		0x8714D80C2DB6F0CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x46E707988DB5F1FCULL,
		0x9B81357F03A12054ULL,
		0x6C831829441E1C80ULL,
		0x5C72EFD19836F233ULL,
		0x057EB076CC73ADCAULL,
		0xB75667FC8A35B7A2ULL,
		0x17E229F97C130A1CULL,
		0xE673CF4273AF2354ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F0A9663304265BDULL,
		0xF5AA042B34EE57D0ULL,
		0xAF8F9D58F716FF35ULL,
		0x3E5F033A873FDD15ULL,
		0x74A260C07EFC4110ULL,
		0xCD121B8ED8E89C3CULL,
		0x80C36EC52FCB4284ULL,
		0xA0A108C9BA07CD7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x40C68B4E364D83D6ULL,
		0x271BCC5F995762F1ULL,
		0x660C436232311CE7ULL,
		0x5ADD67DA1A7DF5A8ULL,
		0x6801D9657DA1C687ULL,
		0xC1F0C001AF6AD749ULL,
		0x07AB353D8F44A33AULL,
		0x266B247373CBAD32ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D179E79A9644080ULL,
		0x15E5BB4C231DC16DULL,
		0xC80B08D20E2A8CC9ULL,
		0x8BDAFC02243DE285ULL,
		0x09DBD60BA3C413F2ULL,
		0x98D40FEFC08F0A21ULL,
		0x615A5461E6FF1CA5ULL,
		0x249C352106FAF5D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3AEECD48CE94356ULL,
		0x113611137639A183ULL,
		0x9E013A902406901EULL,
		0xCF026BD7F6401322ULL,
		0x5E260359D9DDB294ULL,
		0x291CB011EEDBCD28ULL,
		0xA650E0DBA8458695ULL,
		0x01CEEF526CD0B75CULL
	}};
	sign = 0;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4D3680D826AF7DC6ULL,
		0xED6B78EBEB677540ULL,
		0x2AF8862621E505FBULL,
		0x7DBAD4AD9C96A2FAULL,
		0xBD5FAB53876FD7DEULL,
		0x73E9901D88153EBBULL,
		0xEABC802BEEF71FD1ULL,
		0x39813C6D477E3C9AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2ED04195AE9B4A0ULL,
		0x22B81D4B097F3D8BULL,
		0xF5C01D8119FCCA03ULL,
		0x1621295F41A493CFULL,
		0xF29E683679E38282ULL,
		0xF8662BCAB4E708F4ULL,
		0x6B4518D146BC96F7ULL,
		0xD00CDF8823E81F32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A497CBECBC5C926ULL,
		0xCAB35BA0E1E837B4ULL,
		0x353868A507E83BF8ULL,
		0x6799AB4E5AF20F2AULL,
		0xCAC1431D0D8C555CULL,
		0x7B836452D32E35C6ULL,
		0x7F77675AA83A88D9ULL,
		0x69745CE523961D68ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x867C3AA6F2C5ED20ULL,
		0xD39FC492C1E2AF8FULL,
		0x4B0588C33EDA93E6ULL,
		0x94E2A4C7B9D1CE4FULL,
		0x5E4B20C94F1A2AC5ULL,
		0x89C24FE13AF34588ULL,
		0x27747BE318BE2661ULL,
		0x2378D4EA4AA75711ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E48944D43B78AEDULL,
		0x11B2EA491FBB8412ULL,
		0x3146EEF167763FA3ULL,
		0x2E14A4BCEF8B15F5ULL,
		0x4C6A7051F29E7B7FULL,
		0x8865DB56703A8380ULL,
		0xF678CFC897862A8AULL,
		0x14F5989AC329EBA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE833A659AF0E6233ULL,
		0xC1ECDA49A2272B7CULL,
		0x19BE99D1D7645443ULL,
		0x66CE000ACA46B85AULL,
		0x11E0B0775C7BAF46ULL,
		0x015C748ACAB8C208ULL,
		0x30FBAC1A8137FBD7ULL,
		0x0E833C4F877D6B68ULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x214FF4AD0C4FCD55ULL,
		0x90A3C71E0682CAF9ULL,
		0xB6B05421B86EB754ULL,
		0xBAAFAF26EAC5A29BULL,
		0x3487E3AB7BC222F7ULL,
		0xC32292FD2DDC1A15ULL,
		0xEEC85A98AD0A8BD7ULL,
		0xF69641F262CB847BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D579F897C3B9E91ULL,
		0xFEE62D4A64E07B8BULL,
		0xB42764EBA74DB29AULL,
		0xAB4652AC50B25F4AULL,
		0x52500CD7E4E0257CULL,
		0xB99C9EBD5B72A0CEULL,
		0x19FD2074A7962E9FULL,
		0xB12928F456486DAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83F8552390142EC4ULL,
		0x91BD99D3A1A24F6DULL,
		0x0288EF36112104B9ULL,
		0x0F695C7A9A134351ULL,
		0xE237D6D396E1FD7BULL,
		0x0985F43FD2697946ULL,
		0xD4CB3A2405745D38ULL,
		0x456D18FE0C8316CCULL
	}};
	sign = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBBDCC703156A1638ULL,
		0x32F119640D945FDDULL,
		0xDAF705E9FEA45A32ULL,
		0x4DADE08E3184694FULL,
		0xF098BED5ED1468B3ULL,
		0xD26456B97C6FAAC3ULL,
		0x1F2091A5698E8ABFULL,
		0xC950F13BA469C81BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA953EF1B3BADC99DULL,
		0xBB9D303BB193459DULL,
		0x654D523B953378B4ULL,
		0x9848AAF97506AF50ULL,
		0xF5EEC3DD9994F3F6ULL,
		0x83E001F9C1344E96ULL,
		0xC3A85580BCDE076EULL,
		0xAF1D38C69E72CA40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1288D7E7D9BC4C9BULL,
		0x7753E9285C011A40ULL,
		0x75A9B3AE6970E17DULL,
		0xB5653594BC7DB9FFULL,
		0xFAA9FAF8537F74BCULL,
		0x4E8454BFBB3B5C2CULL,
		0x5B783C24ACB08351ULL,
		0x1A33B87505F6FDDAULL
	}};
	sign = 0;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE9E19B2973FEA11ULL,
		0x979ECD22911A2EF4ULL,
		0x253300E0E397AE5FULL,
		0xBC1E23433B8C63FCULL,
		0x7F8CAA2B0D63682CULL,
		0x63892EAC452CC31AULL,
		0xEB06730D4883194AULL,
		0x9051D91E65EF05F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A49C62EA6B8786ULL,
		0xF7E190DCA4BD4527ULL,
		0x66355ECDE4348E97ULL,
		0xE42CDBAD60FFE9B7ULL,
		0x1F40A8FA5FF26696ULL,
		0x57EEE2862E173947ULL,
		0x3A383A5040B9D7F5ULL,
		0x8092782EB953AA3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CF97D4FACD4628BULL,
		0x9FBD3C45EC5CE9CDULL,
		0xBEFDA212FF631FC7ULL,
		0xD7F14795DA8C7A44ULL,
		0x604C0130AD710195ULL,
		0x0B9A4C26171589D3ULL,
		0xB0CE38BD07C94155ULL,
		0x0FBF60EFAC9B5BB5ULL
	}};
	sign = 0;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF8A1E3B9CEE82FB2ULL,
		0x6041C019B9D52DF1ULL,
		0xC267DC34F03C81EDULL,
		0xB003DF2EA7767820ULL,
		0x1B59F39884EE2126ULL,
		0x2CA34BD15F7D02A8ULL,
		0xFC7FA731813390CEULL,
		0x7B8173470132159FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8C08BC4C243D96ULL,
		0x6B4487F31B177BD6ULL,
		0x398B1431A37DC953ULL,
		0x29B5949BFAA2FA34ULL,
		0xFCF74A114EC0734DULL,
		0x2A108E7512DC4100ULL,
		0xE499420D8360CFF4ULL,
		0xC85B3537ADC903D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC15DAFD82C3F21CULL,
		0xF4FD38269EBDB21BULL,
		0x88DCC8034CBEB899ULL,
		0x864E4A92ACD37DECULL,
		0x1E62A987362DADD9ULL,
		0x0292BD5C4CA0C1A7ULL,
		0x17E66523FDD2C0DAULL,
		0xB3263E0F536911C8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B741AB8966D3365ULL,
		0xBE1081541C9810FCULL,
		0x519FD2366C91EC80ULL,
		0xA254A5420855A58BULL,
		0xBCA9955F37B37E87ULL,
		0x507895CEA5527480ULL,
		0x050CB73FE8198DA1ULL,
		0x8A16FEB3A3407F6AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF327146525F78CULL,
		0x3B0FA54ADEAE3A80ULL,
		0xE25ECA0AECA50B9FULL,
		0xD1CE3FF02919A020ULL,
		0xF10F0CFA4B575678ULL,
		0x005ED1A57C512EC2ULL,
		0x753A9AD03D26EF15ULL,
		0x15FA4DC1C196795AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5080F3A431473BD9ULL,
		0x8300DC093DE9D67CULL,
		0x6F41082B7FECE0E1ULL,
		0xD0866551DF3C056AULL,
		0xCB9A8864EC5C280EULL,
		0x5019C429290145BDULL,
		0x8FD21C6FAAF29E8CULL,
		0x741CB0F1E1AA060FULL
	}};
	sign = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC96A17EF3D8249D1ULL,
		0xEE727A3CDA60DC8FULL,
		0x08C87A026167C9CDULL,
		0xC42F469B28EB8D7BULL,
		0xB9CB8814293EFBBFULL,
		0x11E0C4D3D06CB310ULL,
		0x309270CC7845B68EULL,
		0x4B164671220D68F0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0826CF331C9ECB3ULL,
		0xD64B2AC7D2EB7290ULL,
		0x62C186100B2C4E6AULL,
		0x4C55B389B34BB56FULL,
		0xD977A0E602992F58ULL,
		0x941FFAE83065AF8FULL,
		0xD3CC42ABA82C6606ULL,
		0xD70DB77C9871B8FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18E7AAFC0BB85D1EULL,
		0x18274F75077569FFULL,
		0xA606F3F2563B7B63ULL,
		0x77D99311759FD80BULL,
		0xE053E72E26A5CC67ULL,
		0x7DC0C9EBA0070380ULL,
		0x5CC62E20D0195087ULL,
		0x74088EF4899BAFF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x63B3DB24A2F91D30ULL,
		0x688F345A8527F45EULL,
		0xAD0A0E9D73CFB66AULL,
		0xC3C899FB611C0D80ULL,
		0xDECD0B74DF97F7ECULL,
		0xC14CA9050FB55B61ULL,
		0x3911EC5AEFB64E51ULL,
		0x916C8A24CD0BB33BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFAD3FB56C0A6EAEULL,
		0xDCA67831796D6288ULL,
		0xE1360351C5A1736CULL,
		0x3EB432BA7CD62A3DULL,
		0x3466DB85BABBFCD6ULL,
		0x463EF9104EC4C748ULL,
		0x7642A8B712A3E877ULL,
		0x444DA7B86E31B202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64069B6F36EEAE82ULL,
		0x8BE8BC290BBA91D5ULL,
		0xCBD40B4BAE2E42FDULL,
		0x85146740E445E342ULL,
		0xAA662FEF24DBFB16ULL,
		0x7B0DAFF4C0F09419ULL,
		0xC2CF43A3DD1265DAULL,
		0x4D1EE26C5EDA0138ULL
	}};
	sign = 0;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE923EC479C302533ULL,
		0xB7C6B5DA1B16D095ULL,
		0x8DC3BAF05A72EF09ULL,
		0xADB73DFD70E59272ULL,
		0x7AFB750DD8BB2B81ULL,
		0x6BBDD2990045BABCULL,
		0xE7A33D024C3DCD87ULL,
		0x689202D7FC1D32AAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C63282804160FE1ULL,
		0x6CA9DBA442438FE0ULL,
		0x65B2B9581608C472ULL,
		0x4C6835A51FA328E0ULL,
		0x7DA25519E060A205ULL,
		0x156F3362445587D9ULL,
		0x291E34EC5B5FBB8DULL,
		0xBA81FB91AB6E789EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACC0C41F981A1552ULL,
		0x4B1CDA35D8D340B5ULL,
		0x28110198446A2A97ULL,
		0x614F085851426992ULL,
		0xFD591FF3F85A897CULL,
		0x564E9F36BBF032E2ULL,
		0xBE850815F0DE11FAULL,
		0xAE10074650AEBA0CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0110775F3D8C1A8ULL,
		0x7AE249E98E125D33ULL,
		0x9E9CBB82189FFD45ULL,
		0x60132B0F4FD53921ULL,
		0x55EE2CD0294364A2ULL,
		0x3ACD612BA7F1497CULL,
		0x4B06C0AAC2FDE7D6ULL,
		0xD559999EC6D68F9EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x42F746C4994DA07DULL,
		0x6948C8E87428DF01ULL,
		0xD8D4FE6FEB16F05BULL,
		0x907DB0C85763B27EULL,
		0x49A93C5A752189C6ULL,
		0xC1996BE9611303D3ULL,
		0xBBEEED3A19F2C3B2ULL,
		0xF391CBE30ACEFFCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D19C0B15A8B212BULL,
		0x1199810119E97E32ULL,
		0xC5C7BD122D890CEAULL,
		0xCF957A46F87186A2ULL,
		0x0C44F075B421DADBULL,
		0x7933F54246DE45A9ULL,
		0x8F17D370A90B2423ULL,
		0xE1C7CDBBBC078FD2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x268807FF354BFF53ULL,
		0xFBCAE720EFFAD398ULL,
		0xE91A01FDBE0C3527ULL,
		0x241889BBF46DA128ULL,
		0x663D02DA9BB7304CULL,
		0x323F7C41A96CACCBULL,
		0xF0D77FE9F4DDE686ULL,
		0xBA37E2C888B2F7A7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4057968BC1736687ULL,
		0xA64C03DA327E626EULL,
		0x78BDEE84C7835750ULL,
		0x31C957FBB23C3A44ULL,
		0x33F34C5AF2DFD6B5ULL,
		0x79F712972E4F1C43ULL,
		0x10C43CF572F067A4ULL,
		0x7ED56E822851F108ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE630717373D898CCULL,
		0x557EE346BD7C7129ULL,
		0x705C1378F688DDD7ULL,
		0xF24F31C0423166E4ULL,
		0x3249B67FA8D75996ULL,
		0xB84869AA7B1D9088ULL,
		0xE01342F481ED7EE1ULL,
		0x3B6274466061069FULL
	}};
	sign = 0;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x15BBFA15955064D4ULL,
		0xBB79CD0022BE421CULL,
		0xB4ABFD26671303D3ULL,
		0xAAFC7AA8B4465F78ULL,
		0xBC059CCC2A43BDBAULL,
		0x5D48C88F6CB0958EULL,
		0xC5C7CA11F0BAAFDDULL,
		0x8FDDDFCD55303004ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1989F8B25AC04F7FULL,
		0xD775B379EC096CFAULL,
		0x11E98D2A3B1271B6ULL,
		0x638B131E8E4B6C19ULL,
		0x5CC231170859E781ULL,
		0x09E4E23805227D00ULL,
		0xF49DCB76C55A1C4EULL,
		0x4CD3483E499CEDC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC3201633A901555ULL,
		0xE404198636B4D521ULL,
		0xA2C26FFC2C00921CULL,
		0x4771678A25FAF35FULL,
		0x5F436BB521E9D639ULL,
		0x5363E657678E188EULL,
		0xD129FE9B2B60938FULL,
		0x430A978F0B93423BULL
	}};
	sign = 0;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8ABEEEB58E2E971FULL,
		0x7E3760A31766337BULL,
		0x409467E621265E86ULL,
		0x25A8BE33B574EFE2ULL,
		0xBC96860564CE9D77ULL,
		0x233DA95DAC469608ULL,
		0x61D2693AFA080578ULL,
		0x4E05638728C1F3A8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78F958438C1BDCCULL,
		0x408C80A340A7BADAULL,
		0x715B2B8BE4E712DCULL,
		0xF8C6521E01789622ULL,
		0x9695544B8B4155FEULL,
		0x22A6608628069C93ULL,
		0x77CAF0CD3FA9AE95ULL,
		0x03E91D8228CCECEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x932F5931556CD953ULL,
		0x3DAADFFFD6BE78A0ULL,
		0xCF393C5A3C3F4BAAULL,
		0x2CE26C15B3FC59BFULL,
		0x260131B9D98D4778ULL,
		0x009748D7843FF975ULL,
		0xEA07786DBA5E56E3ULL,
		0x4A1C4604FFF506BCULL
	}};
	sign = 0;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xABF9B9AF1611F197ULL,
		0xE08117113818DA72ULL,
		0x8417A99BE7127177ULL,
		0xE25A5903BC45E0F5ULL,
		0xE10FD3ED17A65221ULL,
		0xF1F9C311E74C4C1EULL,
		0x5FDDF40A509C5DADULL,
		0x3F8C919529B9CE8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC24479A2713DF21ULL,
		0x7D0DA86D9626F81AULL,
		0x81F6C85B0AD10BB5ULL,
		0x45D52B7040B62598ULL,
		0x01CBEEE19AF30AF7ULL,
		0xA97B67C0C753D2F8ULL,
		0xD3D782B172C275A9ULL,
		0x7D4E804E6DFAE7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFD57214EEFE1276ULL,
		0x63736EA3A1F1E257ULL,
		0x0220E140DC4165C2ULL,
		0x9C852D937B8FBB5DULL,
		0xDF43E50B7CB3472AULL,
		0x487E5B511FF87926ULL,
		0x8C067158DDD9E804ULL,
		0xC23E1146BBBEE6A2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDB9E3C6D8584B387ULL,
		0xA87E02C513E95FC5ULL,
		0x96F6D0851BC9466AULL,
		0xF034D05B2AFA1A66ULL,
		0xECCD8C35154DE62DULL,
		0xF20B418B12F03F86ULL,
		0x3C4FA91F50B0E05CULL,
		0x462FDA52F658A956ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EBD0D0E1D251582ULL,
		0xCC9900C750344067ULL,
		0x8E8FFAAC955A4D25ULL,
		0xC15339FC2C32BC78ULL,
		0xAAF15F7868459398ULL,
		0x1E6416BEBF312762ULL,
		0xB6012BAFA13BF0E6ULL,
		0xA3C1AAF15BB8087FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CE12F5F685F9E05ULL,
		0xDBE501FDC3B51F5EULL,
		0x0866D5D8866EF944ULL,
		0x2EE1965EFEC75DEEULL,
		0x41DC2CBCAD085295ULL,
		0xD3A72ACC53BF1824ULL,
		0x864E7D6FAF74EF76ULL,
		0xA26E2F619AA0A0D6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x72D86587EB6CD3C6ULL,
		0xDE3CCF096F044400ULL,
		0x09870847D092F492ULL,
		0xB6D020EB36F0A4DCULL,
		0xF6D831350A1792C3ULL,
		0x64DB11CA39BE6E4AULL,
		0x471BADED5854EC46ULL,
		0xFB1D326F1C70CF3BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA35D80562DD820AULL,
		0x7307823D785A8396ULL,
		0xADFA0F31640350CFULL,
		0x93CB7A83AA198BAAULL,
		0xC1CE5D8AF986DC0AULL,
		0x52B09776895A66D2ULL,
		0x65069A4733D3BE5BULL,
		0x3D775A09F2054813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8A28D82888F51BCULL,
		0x6B354CCBF6A9C069ULL,
		0x5B8CF9166C8FA3C3ULL,
		0x2304A6678CD71931ULL,
		0x3509D3AA1090B6B9ULL,
		0x122A7A53B0640778ULL,
		0xE21513A624812DEBULL,
		0xBDA5D8652A6B8727ULL
	}};
	sign = 0;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8FA6CE4BE4EF4E8FULL,
		0xCEEFBC3610332F7EULL,
		0xCA6AF19AC1592870ULL,
		0x51F9E56622E7ABE5ULL,
		0x5F551A8762AFB8D6ULL,
		0xF59A92D285D7B12EULL,
		0x79BDDD498E15394FULL,
		0x4972E896741E3BCDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCFCED2ECBD3CC7ULL,
		0x1414A01FA27E72A7ULL,
		0x578343E8ACB8D0DDULL,
		0xFC94FEB2572C41ADULL,
		0x176AE3B0AF34FCC1ULL,
		0x9B8C418F20DA1CA0ULL,
		0xDF0A3904A72B0838ULL,
		0x5E3C3F49DB969487ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91D6FF78F83211C8ULL,
		0xBADB1C166DB4BCD6ULL,
		0x72E7ADB214A05793ULL,
		0x5564E6B3CBBB6A38ULL,
		0x47EA36D6B37ABC14ULL,
		0x5A0E514364FD948EULL,
		0x9AB3A444E6EA3117ULL,
		0xEB36A94C9887A745ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8B4AF42490572D0ULL,
		0x1F386785CF3408C5ULL,
		0x351482BC0BC63821ULL,
		0xAB7D1FD98360942CULL,
		0xEF99D1CB11150F2AULL,
		0xC43AE92382AE780BULL,
		0x17CB84340AC1FAECULL,
		0x8B5FDA4D10CBBA13ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B85A3751D4B29FULL,
		0xABAC198C082E68C2ULL,
		0x122DFE2143F4761AULL,
		0xEF9F3D29A923C1F7ULL,
		0x7E5773D70C0BBE12ULL,
		0xC1A25796D61C2B70ULL,
		0x733AA3FE62CBD7BFULL,
		0x71744669CA60F0C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4FC550AF730C031ULL,
		0x738C4DF9C705A003ULL,
		0x22E6849AC7D1C206ULL,
		0xBBDDE2AFDA3CD235ULL,
		0x71425DF405095117ULL,
		0x0298918CAC924C9BULL,
		0xA490E035A7F6232DULL,
		0x19EB93E3466AC94CULL
	}};
	sign = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9895516C47776FCEULL,
		0x39B7788CD48F6307ULL,
		0x5BEAC90CE2006E93ULL,
		0x723CAE90598C728EULL,
		0xA25C123639EB0908ULL,
		0x5F67A3B77F77FAEEULL,
		0xA825E65EB5F84021ULL,
		0x0BF3C730F9DA2B61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x973DE30B96D1D25EULL,
		0x10DF6EF0F14BF8B9ULL,
		0x5C8F57F4F2747548ULL,
		0x3504A871FCED59F7ULL,
		0x9D36CB1926789685ULL,
		0xD3348F25D73CE180ULL,
		0xAA91E447758F4706ULL,
		0xCFD51E2964A29466ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01576E60B0A59D70ULL,
		0x28D8099BE3436A4EULL,
		0xFF5B7117EF8BF94BULL,
		0x3D38061E5C9F1896ULL,
		0x0525471D13727283ULL,
		0x8C331491A83B196EULL,
		0xFD9402174068F91AULL,
		0x3C1EA907953796FAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5503D54CDF06A808ULL,
		0xC9EFFDD1A3AE2053ULL,
		0x7A7AD5264AE507D2ULL,
		0xA99E5B1C1CD72EF9ULL,
		0xB139F81EBE677652ULL,
		0x6BBC8907CEE80F83ULL,
		0xD08AF2DFE6A3C4C1ULL,
		0xCCE97101DEF67663ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3FFC35C296DCF80ULL,
		0xFC0AD6D60CF06309ULL,
		0x51236266AEF89B11ULL,
		0xAEB87C0AD9AF6E9DULL,
		0xBD9E5181A9AAF2DAULL,
		0xC1DF46FEC3912E43ULL,
		0x536E99DC71ED8C43ULL,
		0xA24791A7B62D26BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB10411F0B598D888ULL,
		0xCDE526FB96BDBD49ULL,
		0x295772BF9BEC6CC0ULL,
		0xFAE5DF114327C05CULL,
		0xF39BA69D14BC8377ULL,
		0xA9DD42090B56E13FULL,
		0x7D1C590374B6387DULL,
		0x2AA1DF5A28C94FA5ULL
	}};
	sign = 0;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x661396EBA13C1C16ULL,
		0xCFF01C19D093770EULL,
		0x020A663D28DAC037ULL,
		0xC86EF80DDEBD2342ULL,
		0x3083ED8345E2D883ULL,
		0xF7BF1552BB94175EULL,
		0x8335357822D15AF8ULL,
		0x9C48983B9FC05F8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x105ED1196422EC43ULL,
		0xBC4011DB4F2831A7ULL,
		0x7626048F27D8CDAAULL,
		0xD674D61692DB121EULL,
		0xD78F852E927F1B7CULL,
		0xD0F34D7D566E868DULL,
		0x7ABC23A761685B95ULL,
		0x7D1AF35086F767C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55B4C5D23D192FD3ULL,
		0x13B00A3E816B4567ULL,
		0x8BE461AE0101F28DULL,
		0xF1FA21F74BE21123ULL,
		0x58F46854B363BD06ULL,
		0x26CBC7D5652590D0ULL,
		0x087911D0C168FF63ULL,
		0x1F2DA4EB18C8F7C4ULL
	}};
	sign = 0;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFD612B1F227482FEULL,
		0xD58FCF28F34E633EULL,
		0xBAF4DCF82B67DC22ULL,
		0x32BA531480CDDCDEULL,
		0x65308354DA1B2A16ULL,
		0xAA4296D3443944FCULL,
		0x8B4CDDFE3E630B5BULL,
		0x1E5A779E07750642ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B49B71A93950F1ULL,
		0x480B76C4766328ADULL,
		0x32A723D4FCDC0C75ULL,
		0xF222D5C90D569006ULL,
		0x709905BEA887AE97ULL,
		0xBC880E8C99EEC38AULL,
		0x8325B8A796C7F74AULL,
		0x4398767595AD2C3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5AC8FAD793B320DULL,
		0x8D8458647CEB3A91ULL,
		0x884DB9232E8BCFADULL,
		0x40977D4B73774CD8ULL,
		0xF4977D9631937B7EULL,
		0xEDBA8846AA4A8171ULL,
		0x08272556A79B1410ULL,
		0xDAC2012871C7DA07ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1D5024304F418698ULL,
		0xCB5B093761302023ULL,
		0x62ACEF6B29648EDCULL,
		0x3904E0FE1E5AA1A5ULL,
		0x29835DE457249C75ULL,
		0x7B717BBF4B306F53ULL,
		0xFE978927E2545E23ULL,
		0x3A0C66BF28DA3E43ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x830BC13CAD5E7C7FULL,
		0x7F5DB7FE8CDE9FF4ULL,
		0xDCD3F9FB8A173DDBULL,
		0x472DB0BE1D145BD2ULL,
		0x293423401CB3DCCEULL,
		0xC99AD8716346CC07ULL,
		0xFE47F59019E63E66ULL,
		0x7C493633F4EA00E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A4462F3A1E30A19ULL,
		0x4BFD5138D451802EULL,
		0x85D8F56F9F4D5101ULL,
		0xF1D73040014645D2ULL,
		0x004F3AA43A70BFA6ULL,
		0xB1D6A34DE7E9A34CULL,
		0x004F9397C86E1FBCULL,
		0xBDC3308B33F03D5EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x81DE37A80D3B3FC4ULL,
		0x903EB9BFF9ACF4ADULL,
		0xD8C48587C5AC2F69ULL,
		0x71E7B1238B2F20DCULL,
		0x9C8BF8D6FBA0E2FDULL,
		0xABA73DB91AABF14CULL,
		0x068F6A0F2BABFD1EULL,
		0xBD6B3B94DD9E611FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DCDE57B1E64BB7EULL,
		0x22F9292785E7C2BEULL,
		0xF1E7C6B6C76F3F6CULL,
		0xFE5AE12B75E40874ULL,
		0xC5C7926C05C12916ULL,
		0x8BE2D87C63796575ULL,
		0x18A74C967EB63C50ULL,
		0x20C9EE06B3A861DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF410522CEED68446ULL,
		0x6D45909873C531EEULL,
		0xE6DCBED0FE3CEFFDULL,
		0x738CCFF8154B1867ULL,
		0xD6C4666AF5DFB9E6ULL,
		0x1FC4653CB7328BD6ULL,
		0xEDE81D78ACF5C0CEULL,
		0x9CA14D8E29F5FF42ULL
	}};
	sign = 0;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2ADB729D79295483ULL,
		0x66BAE8F91FFC2928ULL,
		0x0B7FABD03FA7236FULL,
		0xC304F26611BD96DFULL,
		0xC7E43F5F5D69BE7CULL,
		0xBE9E1A5EE67952A0ULL,
		0x1D69C2E8A797169DULL,
		0xCD827DC3948716DCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6C03DEB56097ECULL,
		0xF10ADD33C341AB22ULL,
		0x6251C412D84C6AEBULL,
		0xD372460754C9357EULL,
		0xFCBA5A32C9462881ULL,
		0x464E3E90EFB709CBULL,
		0xB0D8759C7CF43541ULL,
		0xAADDD6D16CC9CA1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB6F6EBEC3C8BC97ULL,
		0x75B00BC55CBA7E05ULL,
		0xA92DE7BD675AB883ULL,
		0xEF92AC5EBCF46160ULL,
		0xCB29E52C942395FAULL,
		0x784FDBCDF6C248D4ULL,
		0x6C914D4C2AA2E15CULL,
		0x22A4A6F227BD4CBDULL
	}};
	sign = 0;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x40E5BC32766E8936ULL,
		0x54C70BB0E9EE2082ULL,
		0xFBFF712189B8FC60ULL,
		0x6F8D33AFB3B21F0CULL,
		0x87D9A870BFC1641AULL,
		0x75C57F2DC3DF86B1ULL,
		0x6A7BB6F2938BED45ULL,
		0xEF8D79A447658C28ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x251A99D398A260ACULL,
		0xD7E74FD94E629E84ULL,
		0x9B8651EA9E47D14DULL,
		0xBDF0B718E3FB58B8ULL,
		0x66AB5C236A1445A8ULL,
		0x951D6BD3D03B2CE2ULL,
		0xAFE1A60785DDCB57ULL,
		0x85EC4E774F8D7A18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BCB225EDDCC288AULL,
		0x7CDFBBD79B8B81FEULL,
		0x60791F36EB712B12ULL,
		0xB19C7C96CFB6C654ULL,
		0x212E4C4D55AD1E71ULL,
		0xE0A81359F3A459CFULL,
		0xBA9A10EB0DAE21EDULL,
		0x69A12B2CF7D8120FULL
	}};
	sign = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7690EE363824F443ULL,
		0x60357C9D65F81B01ULL,
		0x5A849F879BEED4EEULL,
		0xB9DED16361D02290ULL,
		0xAFB8B669AE92F2C8ULL,
		0xFD7A61D3F2D52EB0ULL,
		0xCB9BD86C605C3622ULL,
		0x5EA6118712775BEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71F2E1B324C8EC3ULL,
		0x1D0C1394FF30D68BULL,
		0x051F3A510497ADA9ULL,
		0x2F04AE6399432E09ULL,
		0xDD56E2E5BA26D704ULL,
		0x0A4358B774795391ULL,
		0xD437029F7A6B94F3ULL,
		0x16D613122081C11FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F71C01B05D86580ULL,
		0x4329690866C74475ULL,
		0x5565653697572745ULL,
		0x8ADA22FFC88CF487ULL,
		0xD261D383F46C1BC4ULL,
		0xF337091C7E5BDB1EULL,
		0xF764D5CCE5F0A12FULL,
		0x47CFFE74F1F59ACAULL
	}};
	sign = 0;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x58E5B7A524FD1197ULL,
		0x13FD90A4451D1EB4ULL,
		0x6AE7D65EC19032CCULL,
		0x2C3B343338F55A93ULL,
		0x5D54A0CD8CB40BDCULL,
		0xF4F3C2219C3949DEULL,
		0xF4D7B1C97353CE24ULL,
		0x5303BF1AE5461730ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF704A9DEDA3D8DULL,
		0xB48CE1E22CCE0586ULL,
		0x50BF14EE0BBAAE69ULL,
		0x47F9C7FC01B044A6ULL,
		0x1FF2E54230ADEC34ULL,
		0x316BFCFD034ACFABULL,
		0xE7DCB03EC539EE3FULL,
		0xBDD052C9C5CB8DC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48EEB2FB4622D40AULL,
		0x5F70AEC2184F192EULL,
		0x1A28C170B5D58462ULL,
		0xE4416C37374515EDULL,
		0x3D61BB8B5C061FA7ULL,
		0xC387C52498EE7A33ULL,
		0x0CFB018AAE19DFE5ULL,
		0x95336C511F7A896DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1870D3D1A6961E7CULL,
		0x79E35DAA3290F43CULL,
		0xAE8A7682C71D789AULL,
		0x71FF77830241310DULL,
		0xA8F62CB659A3FD55ULL,
		0x02529E292099E0C0ULL,
		0x980F6B93D0C26CF4ULL,
		0xA1F807927BB9F13CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51CCD0A3E5A1B43ULL,
		0xA91320838BAF0D0BULL,
		0xED217B5EFAC1CF7EULL,
		0x070C6C316945529BULL,
		0xC28E33B0B7BA5686ULL,
		0xE3D12FB62CF5E4F9ULL,
		0x99E86117F76DA0FFULL,
		0x7097D100EAA92829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x635406C7683C0339ULL,
		0xD0D03D26A6E1E730ULL,
		0xC168FB23CC5BA91BULL,
		0x6AF30B5198FBDE71ULL,
		0xE667F905A1E9A6CFULL,
		0x1E816E72F3A3FBC6ULL,
		0xFE270A7BD954CBF4ULL,
		0x316036919110C912ULL
	}};
	sign = 0;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x024E9D4F2CDA0424ULL,
		0xFD05EAC626702AD2ULL,
		0x64589B2A7A4C4D5AULL,
		0xFE32858736B73CAEULL,
		0xE1A3831937E1B469ULL,
		0xA21CB25C472CC63AULL,
		0xEFE164DBB57B9E33ULL,
		0x7451A2E206472BF8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ADC7F7165C49D9DULL,
		0xE46B4A60C6B094B0ULL,
		0x9C09AC51B1F749D7ULL,
		0x126C98D5FE5CDAA0ULL,
		0xC8B609F2C5DA0753ULL,
		0x12CB7EC8204CF5C8ULL,
		0x00C7FEE22BFAF71DULL,
		0x9A3474768C221E7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67721DDDC7156687ULL,
		0x189AA0655FBF9621ULL,
		0xC84EEED8C8550383ULL,
		0xEBC5ECB1385A620DULL,
		0x18ED79267207AD16ULL,
		0x8F51339426DFD072ULL,
		0xEF1965F98980A716ULL,
		0xDA1D2E6B7A250D7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7B6B083D58B13AE2ULL,
		0x18C970A902E2D9B4ULL,
		0xBCDAFE55B3D8CBBCULL,
		0xF231D70FFCE04F0CULL,
		0x73B4E11217DC3F92ULL,
		0x2AC6AF28BC79E9F8ULL,
		0xA6BC66C7A8450DCEULL,
		0x1123B37CBF88EDE9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34A0A78078BCF6FEULL,
		0xAC3A3F22D592A5C5ULL,
		0x1F44E56282210F86ULL,
		0xD5397DA570CA3060ULL,
		0xD0E64EE559E46410ULL,
		0xC1580D09AAE9CEA9ULL,
		0xA8E91535439E164AULL,
		0x29A554B381722845ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46CA60BCDFF443E4ULL,
		0x6C8F31862D5033EFULL,
		0x9D9618F331B7BC35ULL,
		0x1CF8596A8C161EACULL,
		0xA2CE922CBDF7DB82ULL,
		0x696EA21F11901B4EULL,
		0xFDD3519264A6F783ULL,
		0xE77E5EC93E16C5A3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD61F7A04976DA40CULL,
		0x6DE9E7C38C622F7EULL,
		0xEA2BF3581F01EF43ULL,
		0xF9497096ADC022D9ULL,
		0xBB294717BFCFBC2FULL,
		0x074AFA78C2D6B272ULL,
		0x537B9CBE90113083ULL,
		0x058A94193A25D675ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C4059D335F7EA1ULL,
		0x2F028BD335DD608AULL,
		0xF7311FE8D8564931ULL,
		0x8F1DF954BE753449ULL,
		0x85C3EEB92C271E56ULL,
		0x403C6BA2C5272292ULL,
		0x3D4E70F01515DC37ULL,
		0x8381AE627E1D8907ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF5B7467640E256BULL,
		0x3EE75BF05684CEF4ULL,
		0xF2FAD36F46ABA612ULL,
		0x6A2B7741EF4AEE8FULL,
		0x3565585E93A89DD9ULL,
		0xC70E8ED5FDAF8FE0ULL,
		0x162D2BCE7AFB544BULL,
		0x8208E5B6BC084D6EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x26C3C46C0FE4B7A0ULL,
		0x26BE51B02114492AULL,
		0x4AE08B362572BEB0ULL,
		0xDFD6CEA559F8C261ULL,
		0x0CFA8A5E2A4B5172ULL,
		0x3DF73CA1E1150DDEULL,
		0x07B5F0C72C444C81ULL,
		0x3A70CCBB4C3FA3EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4354FA1EC1BB21EAULL,
		0x104ABF4672D3A52BULL,
		0xD0D4F29230CE7D69ULL,
		0x81A35819A4E8F3D9ULL,
		0x9AFBF81782C2CBECULL,
		0x253012245DF0DC26ULL,
		0xF6302AD8C1CF0C0DULL,
		0x9AC53EA3FC23F66EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE36ECA4D4E2995B6ULL,
		0x16739269AE40A3FEULL,
		0x7A0B98A3F4A44147ULL,
		0x5E33768BB50FCE87ULL,
		0x71FE9246A7888586ULL,
		0x18C72A7D832431B7ULL,
		0x1185C5EE6A754074ULL,
		0x9FAB8E17501BAD80ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5ED7810E8D1A4979ULL,
		0x36C1C673D503C85BULL,
		0xFA0E6B663C988127ULL,
		0xBCD2AE8D6653140FULL,
		0x535743EE47B76B42ULL,
		0x03EA5C13A71BC0D4ULL,
		0x5BFF7F716F659935ULL,
		0x01588BD9CAF593B7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x81536A35F5A6F226ULL,
		0xEE8C3DBF35F0FEF6ULL,
		0xE5F1EC578C4FDB1AULL,
		0x16DBD04C8DF68148ULL,
		0x2A7D53DBB487597DULL,
		0x404A8FA7AE8B50C4ULL,
		0x434D243CE74FEB2CULL,
		0x6E99086AFE550157ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD8416D897735753ULL,
		0x483588B49F12C964ULL,
		0x141C7F0EB048A60CULL,
		0xA5F6DE40D85C92C7ULL,
		0x28D9F012933011C5ULL,
		0xC39FCC6BF8907010ULL,
		0x18B25B348815AE08ULL,
		0x92BF836ECCA09260ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD0C3CFBAB9D451BEULL,
		0x1709C0DA42BAC7B9ULL,
		0xF1A13521EA491649ULL,
		0x90B8A2026F79B618ULL,
		0x3516F43CCDB63468ULL,
		0x1EA3EB0D12505AFAULL,
		0x5C54A7847F92D7E2ULL,
		0x9555332235231315ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06618510DA2A3FE7ULL,
		0x08C9909B7456EB0CULL,
		0xC4943320F3606256ULL,
		0xC1584572EB24502EULL,
		0xBE71A74D28B10C6CULL,
		0xA27E542085B49B58ULL,
		0x34865AC2B28538CAULL,
		0xF150233B19D75886ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA624AA9DFAA11D7ULL,
		0x0E40303ECE63DCADULL,
		0x2D0D0200F6E8B3F3ULL,
		0xCF605C8F845565EAULL,
		0x76A54CEFA50527FBULL,
		0x7C2596EC8C9BBFA1ULL,
		0x27CE4CC1CD0D9F17ULL,
		0xA4050FE71B4BBA8FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66E35E808659A452ULL,
		0x42F3070B9BC4A932ULL,
		0x4EBD72A1D95CC07DULL,
		0xD7A9E00B03170526ULL,
		0xD04506CEBDDB18EAULL,
		0x3314E226196C8D83ULL,
		0xAE6088FEFF9C396FULL,
		0x1B1088DA0BEBB6A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x28F9F99C71164F84ULL,
		0x8DBDB229A50C8029ULL,
		0xD2EE4ABC48060685ULL,
		0xF7B4F41414446613ULL,
		0xB35A98F1FCC5AD0EULL,
		0x2BC2CC7D865676BDULL,
		0xFA9527CD4F29B8CAULL,
		0x8394937CAF3DA421ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DE964E4154354CEULL,
		0xB53554E1F6B82909ULL,
		0x7BCF27E59156B9F7ULL,
		0xDFF4EBF6EED29F12ULL,
		0x1CEA6DDCC1156BDBULL,
		0x075215A8931616C6ULL,
		0xB3CB6131B07280A5ULL,
		0x977BF55D5CAE1282ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFA080D1DE2081A36ULL,
		0xE14FC33194F9FE16ULL,
		0x92B73450FA1F085FULL,
		0xDFE74EB6601AE88AULL,
		0xE02726C1108A38E2ULL,
		0xAC1FABA647EDC146ULL,
		0x29079401D1DDB9E5ULL,
		0x9ECD20D69B7199E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7048BEB6095DBB4AULL,
		0xDE0E4F4E56127FDEULL,
		0x4515D32387CFB6C0ULL,
		0x562E8C56B20351B0ULL,
		0xBDA1CE0FF3E66BFCULL,
		0xC48DEE2822DAD1AEULL,
		0x8D0CFC81298280DCULL,
		0x8548B744F6354A73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89BF4E67D8AA5EECULL,
		0x034173E33EE77E38ULL,
		0x4DA1612D724F519FULL,
		0x89B8C25FAE1796DAULL,
		0x228558B11CA3CCE6ULL,
		0xE791BD7E2512EF98ULL,
		0x9BFA9780A85B3908ULL,
		0x19846991A53C4F70ULL
	}};
	sign = 0;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF518F05EFDBA2FD8ULL,
		0x14ADD61F562CF24AULL,
		0x843B9554F93FFD7DULL,
		0x20E4A0B28B6033EDULL,
		0xB1169B83432B6708ULL,
		0xFE85564BC99A42D3ULL,
		0x2CAB6C2A1D183C68ULL,
		0xF9AF5734D46BB099ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x025E608EA261795DULL,
		0xA76F1B8A0C481716ULL,
		0xFD6D84CCDA055B1BULL,
		0x1E8722DF61CEA5D9ULL,
		0xA6959BAE8040D7B3ULL,
		0x99C8C23D14FC5B2AULL,
		0x60D9936EDE939E93ULL,
		0x39B68BB5BD2081F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2BA8FD05B58B67BULL,
		0x6D3EBA9549E4DB34ULL,
		0x86CE10881F3AA261ULL,
		0x025D7DD329918E13ULL,
		0x0A80FFD4C2EA8F55ULL,
		0x64BC940EB49DE7A9ULL,
		0xCBD1D8BB3E849DD5ULL,
		0xBFF8CB7F174B2EA7ULL
	}};
	sign = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5E983043D6E10D9CULL,
		0x9460D5657331E6B5ULL,
		0xA435A70DB5A5D741ULL,
		0x80DC36B0DE4FD5B2ULL,
		0xE4A0BE2FCC904C95ULL,
		0x9B8B214C25C96242ULL,
		0xE2FB78175FA454CCULL,
		0xFA87E0CB3D08C24FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x384CFEB3284B6374ULL,
		0x2A7D8A9CEA28F5EDULL,
		0xA0927576A7E0F541ULL,
		0xFC97BC2431961D42ULL,
		0x3B88F2237599C16AULL,
		0xEFD4A85EBE4C11BDULL,
		0x54B15398661BA871ULL,
		0x4368AACC610CEE33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x264B3190AE95AA28ULL,
		0x69E34AC88908F0C8ULL,
		0x03A331970DC4E200ULL,
		0x84447A8CACB9B870ULL,
		0xA917CC0C56F68B2AULL,
		0xABB678ED677D5085ULL,
		0x8E4A247EF988AC5AULL,
		0xB71F35FEDBFBD41CULL
	}};
	sign = 0;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB468A6C05463D7AAULL,
		0xAD4E1BD4DC0BB86AULL,
		0x0124D0DDD7834AABULL,
		0xF421CABC2954C5D1ULL,
		0x13C4833492C4BBCCULL,
		0xFC0675B419169158ULL,
		0xD81CEB46ED214022ULL,
		0x4051ACA1D23B9649ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x93A67D1C5A4F59CEULL,
		0xA8E3ABB5BAA3A23DULL,
		0xC3AC1A4249A4C63DULL,
		0xAEE962DD7082C7FFULL,
		0xF8DB6181264D7725ULL,
		0x662C9FB89F4C13F5ULL,
		0x5007FE65284C1320ULL,
		0x3AA9EDF82FB1F219ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20C229A3FA147DDCULL,
		0x046A701F2168162DULL,
		0x3D78B69B8DDE846EULL,
		0x453867DEB8D1FDD1ULL,
		0x1AE921B36C7744A7ULL,
		0x95D9D5FB79CA7D62ULL,
		0x8814ECE1C4D52D02ULL,
		0x05A7BEA9A289A430ULL
	}};
	sign = 0;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x24313D55E471D006ULL,
		0xE954F20D42870716ULL,
		0x13D64ABA39900095ULL,
		0xD34D7DE35B343942ULL,
		0x4016C4DC05489D91ULL,
		0x72E5C378C9B6AA7DULL,
		0xEDED4C13FD9CE391ULL,
		0x5EBA3DFA1A0FFCA8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E9E5867B16CCA8ULL,
		0x845ECCACBA7568F7ULL,
		0x228D1C1F9B0824C1ULL,
		0x76FC4FFE173F408EULL,
		0xB9118F416DD0521AULL,
		0x9DC114C42A9F64F5ULL,
		0xB1C344507E678542ULL,
		0x813B9767BC605DE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B4757CF695B035EULL,
		0x64F6256088119E1EULL,
		0xF1492E9A9E87DBD4ULL,
		0x5C512DE543F4F8B3ULL,
		0x8705359A97784B77ULL,
		0xD524AEB49F174587ULL,
		0x3C2A07C37F355E4EULL,
		0xDD7EA6925DAF9EC8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFBF9F7E67615926DULL,
		0x0C6DE0B836E248DEULL,
		0xF9EDD405AC0F3A77ULL,
		0xD548231B5BBAD716ULL,
		0xEA856C96BFD3CE71ULL,
		0x66963E54891A0874ULL,
		0x8A1F79088770D85BULL,
		0xDD85B08A731BC7EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5E80AD01E6A2AF0ULL,
		0x75068267D35AE711ULL,
		0xA18FA1A3ECA06109ULL,
		0xA9ED5D2BE38B059DULL,
		0xDC5CF3B6C86B2F94ULL,
		0x80FE38A49AA899FFULL,
		0x05449C1EE07D9E46ULL,
		0x3825ACBF5AF88656ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3611ED1657AB677DULL,
		0x97675E50638761CDULL,
		0x585E3261BF6ED96DULL,
		0x2B5AC5EF782FD179ULL,
		0x0E2878DFF7689EDDULL,
		0xE59805AFEE716E75ULL,
		0x84DADCE9A6F33A14ULL,
		0xA56003CB18234194ULL
	}};
	sign = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B7A068C285105C1ULL,
		0x100A8EA0ED530D26ULL,
		0x2FA67AE8D0598589ULL,
		0x7AC77DEAFCC75035ULL,
		0x2F7951D6B7343905ULL,
		0x1660DE82AA8BAF88ULL,
		0x85FEE188155B2780ULL,
		0xE1FB8033CEBDF4D5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF976DEE0BAFD06BFULL,
		0x291D834E2799A520ULL,
		0xDBD1EE1CEBC6FD08ULL,
		0xA4F176F2C2A823C1ULL,
		0xC5470569712CF0B6ULL,
		0x330ACD4E0FEB15ABULL,
		0xB40D4D1719BE6E9EULL,
		0x8450CDA7F88E4349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x620327AB6D53FF02ULL,
		0xE6ED0B52C5B96805ULL,
		0x53D48CCBE4928880ULL,
		0xD5D606F83A1F2C73ULL,
		0x6A324C6D4607484EULL,
		0xE35611349AA099DCULL,
		0xD1F19470FB9CB8E1ULL,
		0x5DAAB28BD62FB18BULL
	}};
	sign = 0;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2280F22484DC0E12ULL,
		0xC35098FB815B920AULL,
		0x9C1A97E89120FB70ULL,
		0x2BBCB184CAF5ABC1ULL,
		0x2FDC0D6E8EE1878BULL,
		0xDB7C46A1BB02DE84ULL,
		0x13F16A13131C67D9ULL,
		0x19ECEB844CD1B8C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E8B9A9C83FEDD3ULL,
		0x4E751D43A5E2F63FULL,
		0xF147661A709BDE8CULL,
		0x50181E26BCD53F6BULL,
		0xEF60BEF75A0B2F7EULL,
		0xFD3C7EBFFDCDE012ULL,
		0x5A3C0B2901596F68ULL,
		0x42BA3F015F21321BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1198387ABC9C203FULL,
		0x74DB7BB7DB789BCBULL,
		0xAAD331CE20851CE4ULL,
		0xDBA4935E0E206C55ULL,
		0x407B4E7734D6580CULL,
		0xDE3FC7E1BD34FE71ULL,
		0xB9B55EEA11C2F870ULL,
		0xD732AC82EDB086AAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC654225B33ABF86AULL,
		0xF22DEB08F1FE73D8ULL,
		0x51D6A7DBADECFCE9ULL,
		0xABBD05FCD27F1F4FULL,
		0x357A8CF807F3C228ULL,
		0xE85E45EB478E1B60ULL,
		0xA2502CFE65873FBBULL,
		0x9A318BFD2998843FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x29329EF32F3C4F43ULL,
		0x0C51E91F9566C306ULL,
		0xDFBE9752B8D1490BULL,
		0x811845E0293D6871ULL,
		0xEF5F99976345D34CULL,
		0x96C9AA4B18EF5222ULL,
		0x1D40CBFD87035CFDULL,
		0xE8FC44030FD0A211ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D218368046FA927ULL,
		0xE5DC01E95C97B0D2ULL,
		0x72181088F51BB3DEULL,
		0x2AA4C01CA941B6DDULL,
		0x461AF360A4ADEEDCULL,
		0x51949BA02E9EC93DULL,
		0x850F6100DE83E2BEULL,
		0xB13547FA19C7E22EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xECBE961864D9DF64ULL,
		0xC94FC4195AD7267DULL,
		0x7A8A9031530CBD2AULL,
		0x71A4A09757BBB0A1ULL,
		0xA8E17D6F74D071B0ULL,
		0xC64CB332CE7DA752ULL,
		0x1BE650BD1F171BFDULL,
		0xAA53D15DB2665DB1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0A1C5DACF68BB73ULL,
		0xEE110EA8BF26B2A2ULL,
		0xE16C06078DFA0B84ULL,
		0xB28D10E5DC2D8D82ULL,
		0x1FE5BE9CB89AA93EULL,
		0xE1370B525691B8A3ULL,
		0x632F21D750873D25ULL,
		0x588E27B5C24EA9AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C1CD03D957123F1ULL,
		0xDB3EB5709BB073DBULL,
		0x991E8A29C512B1A5ULL,
		0xBF178FB17B8E231EULL,
		0x88FBBED2BC35C871ULL,
		0xE515A7E077EBEEAFULL,
		0xB8B72EE5CE8FDED7ULL,
		0x51C5A9A7F017B401ULL
	}};
	sign = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6BF7E9EEC0818E7AULL,
		0x8BBB171A1283A11DULL,
		0xB0A3C66562BF9E37ULL,
		0xDF9CA0637F0BC05DULL,
		0x011B6945580BC04EULL,
		0x09DCB5378E5C85B9ULL,
		0xFD31210EFABC936AULL,
		0x06FA0BC908139F6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF44C91A45A7B7E11ULL,
		0x9728968A57D357ACULL,
		0xB6B022EEB8068847ULL,
		0xA14F2176526167CBULL,
		0xBBB8765901121521ULL,
		0x0568AA94C2A8364AULL,
		0x45E2DF67F1B04DECULL,
		0xEB68DF7D3D732802ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77AB584A66061069ULL,
		0xF492808FBAB04970ULL,
		0xF9F3A376AAB915EFULL,
		0x3E4D7EED2CAA5891ULL,
		0x4562F2EC56F9AB2DULL,
		0x04740AA2CBB44F6EULL,
		0xB74E41A7090C457EULL,
		0x1B912C4BCAA07769ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFF71CC3392EECD3CULL,
		0x44F07AEC146A4521ULL,
		0x31A0DC7393C68088ULL,
		0x43341EBA344FFB83ULL,
		0x0EA8E29081E232E8ULL,
		0xDAF239872FBE6605ULL,
		0xA6DD63BFD8FAF643ULL,
		0x1E7B94C4563AB9D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4191B764538093ULL,
		0x219F0BE498AFD916ULL,
		0x2CEF459696A941CFULL,
		0x8B76B8003191FC68ULL,
		0x8630A93E8881E050ULL,
		0xE085B964755A0D09ULL,
		0x360DE0B895B046A1ULL,
		0x957875E613998CEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30303A7C2E9B4CA9ULL,
		0x23516F077BBA6C0BULL,
		0x04B196DCFD1D3EB9ULL,
		0xB7BD66BA02BDFF1BULL,
		0x88783951F9605297ULL,
		0xFA6C8022BA6458FBULL,
		0x70CF8307434AAFA1ULL,
		0x89031EDE42A12CE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D0D9E4BC3FBCCF1ULL,
		0x3C34098276CEEB70ULL,
		0xA5B52DA75B347A5EULL,
		0x3BD7AF7C2D8DA2B9ULL,
		0x835CB28403E15A86ULL,
		0x72467A86247F113EULL,
		0x6826B9BACB703E1DULL,
		0xE4D383BAE87E923CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFD65BD5E38A2A6ULL,
		0x61E399FF80560CFDULL,
		0x5D4EE99CDA7E9462ULL,
		0x5A56D43C44EDF3D8ULL,
		0xA901208772E83482ULL,
		0xA56F9423DD32CCF8ULL,
		0x348ECA4B7079CAA7ULL,
		0x9886FB0E631E776EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D10388E65C32A4BULL,
		0xDA506F82F678DE72ULL,
		0x4866440A80B5E5FBULL,
		0xE180DB3FE89FAEE1ULL,
		0xDA5B91FC90F92603ULL,
		0xCCD6E662474C4445ULL,
		0x3397EF6F5AF67375ULL,
		0x4C4C88AC85601ACEULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD28DB3C5CEDE26D2ULL,
		0x4E42C610115B9694ULL,
		0x3918276F3800AF3BULL,
		0x2C2D88C68457F410ULL,
		0x5FBF52C6808DCC44ULL,
		0x511B26BF3374CE3BULL,
		0x4B05F4117BCCAF52ULL,
		0x69789F6FD106DAE6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2977E0A10C358400ULL,
		0x7AF6C0D1C874E094ULL,
		0x696356CD0DF3F3B0ULL,
		0x48A424EB03C0E9B1ULL,
		0x80D5E9ADFFCB116CULL,
		0xBDFCD0E4E181A46BULL,
		0x79D09CA9159C9BA2ULL,
		0x9F61FA489536725BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA915D324C2A8A2D2ULL,
		0xD34C053E48E6B600ULL,
		0xCFB4D0A22A0CBB8AULL,
		0xE38963DB80970A5EULL,
		0xDEE9691880C2BAD7ULL,
		0x931E55DA51F329CFULL,
		0xD1355768663013AFULL,
		0xCA16A5273BD0688AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06C73CCBB44F3053ULL,
		0xD71819AD55CCFAD6ULL,
		0xACF89BCB4EE941EEULL,
		0xFDD2E1381B29C719ULL,
		0x97ED6A4E5B517B1DULL,
		0xFF8791C4C3D035B9ULL,
		0xD3B231ADBD6402CEULL,
		0xCB7011A046C8FA21ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12B800B249B5581ULL,
		0xF072C208B70E3220ULL,
		0xD128A79948333FF6ULL,
		0xC1E14E3CD36D792EULL,
		0xEAE8AF0E727B7232ULL,
		0x4062A26797E8EFC6ULL,
		0xEBD034EBDB7F6FC0ULL,
		0x27B417212C9AA9E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x359BBCC08FB3DAD2ULL,
		0xE6A557A49EBEC8B5ULL,
		0xDBCFF43206B601F7ULL,
		0x3BF192FB47BC4DEAULL,
		0xAD04BB3FE8D608EBULL,
		0xBF24EF5D2BE745F2ULL,
		0xE7E1FCC1E1E4930EULL,
		0xA3BBFA7F1A2E503EULL
	}};
	sign = 0;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x72F0D2D1F9C8FF8BULL,
		0xB31BAED4ED50A57BULL,
		0x3C6C6D1FB7CDA62FULL,
		0xA9B5D7D9C962D91BULL,
		0x4808E4FF6BA51EE3ULL,
		0x8D9885C29E07A94DULL,
		0x930F1049112FF2FCULL,
		0x76415526B8CCB60EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DCC0D1475215F85ULL,
		0x981C407D1AA9A214ULL,
		0xFEF7962DD48E5992ULL,
		0x6CC17CB6070CC360ULL,
		0xA1DB94452461B515ULL,
		0x8643ADC5BF5EA69FULL,
		0x17FF64DF54F50768ULL,
		0x2DF04ACA8D90E44EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3524C5BD84A7A006ULL,
		0x1AFF6E57D2A70367ULL,
		0x3D74D6F1E33F4C9DULL,
		0x3CF45B23C25615BAULL,
		0xA62D50BA474369CEULL,
		0x0754D7FCDEA902ADULL,
		0x7B0FAB69BC3AEB94ULL,
		0x48510A5C2B3BD1C0ULL
	}};
	sign = 0;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDA7E0E75E9B89366ULL,
		0x60F5670B9376524BULL,
		0x13F941876D1209A9ULL,
		0xF0D2B5731E1071B6ULL,
		0x533580AFA16541DEULL,
		0x85F0CE47B1A91069ULL,
		0x3500F1F77BFC1702ULL,
		0x035D04301B680CF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA401C2654CDE57A7ULL,
		0x561EFA6E48615CF0ULL,
		0x2AE155DE8217A2C5ULL,
		0x99456F75AB6BC623ULL,
		0x48C9CDFB6A0BE383ULL,
		0xC1394F202DCA0100ULL,
		0x7514F50E3766B4B2ULL,
		0x93B71B8E47D026ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x367C4C109CDA3BBFULL,
		0x0AD66C9D4B14F55BULL,
		0xE917EBA8EAFA66E4ULL,
		0x578D45FD72A4AB92ULL,
		0x0A6BB2B437595E5BULL,
		0xC4B77F2783DF0F69ULL,
		0xBFEBFCE94495624FULL,
		0x6FA5E8A1D397E605ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA7F6A98412937581ULL,
		0xB19B9B31EBC50D69ULL,
		0x49C5CB96FC6F4E5DULL,
		0xA86103AE391AADCFULL,
		0x650AF7A7CD8E248CULL,
		0x0DE6F4C31A3E9391ULL,
		0x4D9BCFE01C4B38EFULL,
		0x152CC7ABF936A4A2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1347E209505730FULL,
		0x2F31E1EE3842A2EBULL,
		0x3DA33F1AA0867072ULL,
		0x81DB31BBDA55CFC3ULL,
		0xD71A70225F9D1859ULL,
		0x11BFA1C01B1A25B8ULL,
		0x14A6B9A72601D876ULL,
		0x3036007B10971910ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6C22B637D8E0272ULL,
		0x8269B943B3826A7DULL,
		0x0C228C7C5BE8DDEBULL,
		0x2685D1F25EC4DE0CULL,
		0x8DF087856DF10C33ULL,
		0xFC275302FF246DD8ULL,
		0x38F51638F6496078ULL,
		0xE4F6C730E89F8B92ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4BFC6AED47C23DABULL,
		0xC7AA03E3569BE45CULL,
		0x9D1C9E86A6B52F49ULL,
		0x0B9635BCB0DAE13DULL,
		0xB8AAA8E0E59E3954ULL,
		0x6E6F6EB74BFC2F17ULL,
		0x7DA3C13B391B9C4DULL,
		0x35CF7EEC209EA422ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x339AB798CEAF4376ULL,
		0x3C1A305DE378B8D6ULL,
		0x62CC3DBFD64E66F3ULL,
		0x27F19357245BB825ULL,
		0xEAA62E003A3719C6ULL,
		0x5FE023856A313AA9ULL,
		0x99DD2CCE19FE53B7ULL,
		0x468B0BCF95F533FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1861B3547912FA35ULL,
		0x8B8FD38573232B86ULL,
		0x3A5060C6D066C856ULL,
		0xE3A4A2658C7F2918ULL,
		0xCE047AE0AB671F8DULL,
		0x0E8F4B31E1CAF46DULL,
		0xE3C6946D1F1D4896ULL,
		0xEF44731C8AA97023ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDAE267CF18317A66ULL,
		0x8ADE20B37AC7D72AULL,
		0xAF2B7941D226620BULL,
		0xB323A4841067EF63ULL,
		0x70A9032DA2E15FA1ULL,
		0x35C017C785383788ULL,
		0xCABA94F8E98BA9CCULL,
		0x5ADEF3658B80597BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4303CBB2E4FF42FULL,
		0x0B14CDC8728E031CULL,
		0x4745B1367803C57CULL,
		0x8381AC7D57448C78ULL,
		0xC991E0D072E75D12ULL,
		0x04C75E09D9D93CCFULL,
		0xAEA443814DBF13C1ULL,
		0x7577A7635718524CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16B22B13E9E18637ULL,
		0x7FC952EB0839D40EULL,
		0x67E5C80B5A229C8FULL,
		0x2FA1F806B92362EBULL,
		0xA717225D2FFA028FULL,
		0x30F8B9BDAB5EFAB8ULL,
		0x1C1651779BCC960BULL,
		0xE5674C023468072FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA45EB25AC4BB8E14ULL,
		0x78CDAC0FCCA51669ULL,
		0x0D5BB6456B7E650AULL,
		0x267AE267644D0074ULL,
		0xB384D1686B3E6FDCULL,
		0xC4D3B50DBF09234AULL,
		0x549CC4F7F5736714ULL,
		0xAF736AEFBF4D86E8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD00FA473F281EDFULL,
		0x875E0BC3D61B142DULL,
		0xBBD199A728862E70ULL,
		0x3219E26227C68318ULL,
		0x6FB8C7B538AEBD94ULL,
		0xA59386A4908CDE94ULL,
		0x17E3CEBBAC18111EULL,
		0xC00A822CB0E412CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC75DB81385936F35ULL,
		0xF16FA04BF68A023BULL,
		0x518A1C9E42F83699ULL,
		0xF46100053C867D5BULL,
		0x43CC09B3328FB247ULL,
		0x1F402E692E7C44B6ULL,
		0x3CB8F63C495B55F6ULL,
		0xEF68E8C30E69741BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3D84863C30739A8DULL,
		0xB62BE2879F4A572AULL,
		0xF06E30A2D63690FCULL,
		0x480EA60FB89ECD73ULL,
		0xA9CF34A38F55BFACULL,
		0xDDEFE3E9F657A03EULL,
		0xBBD1A5ECDFA7E9F0ULL,
		0xCF178B4063575555ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7601B20CDF4CC4ULL,
		0x9DE45B830265669BULL,
		0x9189E2D1F98C986BULL,
		0x7BDA95DD0BE22326ULL,
		0xEE978FC839966ABCULL,
		0x9037D73A034A4188ULL,
		0xFF47F22B30B2E4C5ULL,
		0xAE899F8E5E448712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x900E848A23944DC9ULL,
		0x184787049CE4F08EULL,
		0x5EE44DD0DCA9F891ULL,
		0xCC341032ACBCAA4DULL,
		0xBB37A4DB55BF54EFULL,
		0x4DB80CAFF30D5EB5ULL,
		0xBC89B3C1AEF5052BULL,
		0x208DEBB20512CE42ULL
	}};
	sign = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0E5948EACF67572ULL,
		0xB8268DECA1FAD673ULL,
		0x2AD52080A5F84873ULL,
		0x27ADB878D67FC304ULL,
		0x090FFF979E25FEE4ULL,
		0xEC65BA28848808CAULL,
		0x7FB5F61998E28BD6ULL,
		0xAFDA1098B34BD2FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x04FCD3FF1BF2D652ULL,
		0xA822A7A09798A19AULL,
		0xC49F461206C49BD5ULL,
		0x9844AD17769E384EULL,
		0x11AD3D4FE083565BULL,
		0x983CAA7EA8E2B0EDULL,
		0x048A48C931FFAEACULL,
		0xEEC22E42AD6C7414ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BE8C08F91039F20ULL,
		0x1003E64C0A6234D9ULL,
		0x6635DA6E9F33AC9EULL,
		0x8F690B615FE18AB5ULL,
		0xF762C247BDA2A888ULL,
		0x54290FA9DBA557DCULL,
		0x7B2BAD5066E2DD2AULL,
		0xC117E25605DF5EE9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3DD1DE1D4E0CD650ULL,
		0xD45FE335A6973CDCULL,
		0x3D7794AD9C1DD7B0ULL,
		0x1CCC524CA4555E19ULL,
		0x3068BCF29A6381FAULL,
		0x3B8AD2757A272D5EULL,
		0x3BF1460CD31A99DFULL,
		0x23BAB11E2CD04126ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C6CE421C9B80B4ULL,
		0x33A786083CC17BFBULL,
		0x260FC4255ABE3E64ULL,
		0x49F1CE9DD9AE311AULL,
		0xB1815DD8427E31D5ULL,
		0x5C8ABDD89E2DD10FULL,
		0x7B2FC16C22B8E19AULL,
		0x2CD33760D17C9E52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x340B0FDB3171559CULL,
		0xA0B85D2D69D5C0E1ULL,
		0x1767D088415F994CULL,
		0xD2DA83AECAA72CFFULL,
		0x7EE75F1A57E55024ULL,
		0xDF00149CDBF95C4EULL,
		0xC0C184A0B061B844ULL,
		0xF6E779BD5B53A2D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEE25626D2465678CULL,
		0x67D89C5BEA4E3FEDULL,
		0xE1450860D81AC468ULL,
		0x20DC044643E5BECEULL,
		0x0614D4EC43E3AD94ULL,
		0xFB7BF09C08BCDF43ULL,
		0x132294AAF6796F6BULL,
		0x1C5B871F985CB730ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x760929179459591CULL,
		0xEE87B85590D58A8DULL,
		0x8084456F1EB5A97FULL,
		0xF96102C0988DF765ULL,
		0xAF811E66653B7AAEULL,
		0x63762A60073C5FBAULL,
		0x6AB3480D8D715FF6ULL,
		0x99F6B9BE85351FD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x781C3955900C0E70ULL,
		0x7950E4065978B560ULL,
		0x60C0C2F1B9651AE8ULL,
		0x277B0185AB57C769ULL,
		0x5693B685DEA832E5ULL,
		0x9805C63C01807F88ULL,
		0xA86F4C9D69080F75ULL,
		0x8264CD6113279758ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3F7CFF80A6BF353DULL,
		0x6490302F14C9DA1EULL,
		0x07891367A1A9E498ULL,
		0x9CE41BD38ADF2A5FULL,
		0x5EB1F04DDCBD31B7ULL,
		0x0194E73ACC070CD5ULL,
		0xE99077F83BE4621DULL,
		0x0614412455BF49D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA64D06CF0452BA2ULL,
		0xF751054FEC10254AULL,
		0x31887AE8A55E1FA0ULL,
		0x6D7BA71323B5F2DBULL,
		0x94FE1E19B16AA452ULL,
		0x3067BFB9CCB7808BULL,
		0x371392DC4D13AF1FULL,
		0x9A82E76881312C1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85182F13B67A099BULL,
		0x6D3F2ADF28B9B4D3ULL,
		0xD600987EFC4BC4F7ULL,
		0x2F6874C067293783ULL,
		0xC9B3D2342B528D65ULL,
		0xD12D2780FF4F8C49ULL,
		0xB27CE51BEED0B2FDULL,
		0x6B9159BBD48E1DB3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x516AE53A476CB335ULL,
		0x6FD18D6B753FA3E6ULL,
		0x4E5C7E30D197642FULL,
		0x1338EC3B1C520E3EULL,
		0xCD0667532D931ABAULL,
		0x921FAEEFF3B8602DULL,
		0x343AA8B4B7BA87E3ULL,
		0x6969226FAEBE4B81ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26176B7994F9DF2AULL,
		0x2E7E02F69F926AA8ULL,
		0x68D394356373A1D5ULL,
		0x230F2D66FDB8D516ULL,
		0xD87CC694AE185924ULL,
		0x0334356950FD6854ULL,
		0x64786F97521A6885ULL,
		0x862FBBCB3F6E7BDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B5379C0B272D40BULL,
		0x41538A74D5AD393EULL,
		0xE588E9FB6E23C25AULL,
		0xF029BED41E993927ULL,
		0xF489A0BE7F7AC195ULL,
		0x8EEB7986A2BAF7D8ULL,
		0xCFC2391D65A01F5EULL,
		0xE33966A46F4FCFA4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1495898549966044ULL,
		0x87A1824E27ADD473ULL,
		0xB41D40A1E9A8E98BULL,
		0xF2C4A29AEB5450B0ULL,
		0x0E16585BCD9AAD22ULL,
		0x05CD8E7FC957501DULL,
		0xA6FDE31E2CE191E2ULL,
		0x9AB973EF23FA0799ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7341DBF81DC7AEC6ULL,
		0xDA9A28FAB735C7FFULL,
		0x610D0D499D3ADA1EULL,
		0xD5F285C7FADEE7EAULL,
		0xA874703CC5BDAF6FULL,
		0xA606E89A09067B12ULL,
		0x487E9BC49B4F3574ULL,
		0xC730DDDBCDB53655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA153AD8D2BCEB17EULL,
		0xAD07595370780C73ULL,
		0x531033584C6E0F6CULL,
		0x1CD21CD2F07568C6ULL,
		0x65A1E81F07DCFDB3ULL,
		0x5FC6A5E5C050D50AULL,
		0x5E7F475991925C6DULL,
		0xD38896135644D144ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x78BA663590B7A8F1ULL,
		0x4156589B34D7BF97ULL,
		0x5589D9058CD6F776ULL,
		0xD08B31DD60515903ULL,
		0xB26541816EF6036DULL,
		0xB25B6331296425E9ULL,
		0x29214B18F5744C9BULL,
		0x9F20DB31E086DEADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x488CF7C72779B99DULL,
		0x2EC49DBF51D7921CULL,
		0xB4D63D19BB6A92F5ULL,
		0x20506C17B269339FULL,
		0x1E422821A9B432B5ULL,
		0x0B04314D67630EAAULL,
		0xC876D69A526A4F9CULL,
		0x9304803CF7846372ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302D6E6E693DEF54ULL,
		0x1291BADBE3002D7BULL,
		0xA0B39BEBD16C6481ULL,
		0xB03AC5C5ADE82563ULL,
		0x9423195FC541D0B8ULL,
		0xA75731E3C201173FULL,
		0x60AA747EA309FCFFULL,
		0x0C1C5AF4E9027B3AULL
	}};
	sign = 0;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE82D9CFD4FCC8F39ULL,
		0x9262876334886A98ULL,
		0x2C79FD5EC754874CULL,
		0xD8115085DFBCCEE0ULL,
		0x504455C9EF8B616CULL,
		0x2472D0BA817CB8CAULL,
		0x14002D766988EB71ULL,
		0x8253939E41403963ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC38F515267AA6D57ULL,
		0x44AEF380602D11D6ULL,
		0x745DE62D0C0615A7ULL,
		0xF3705C9E8C62513BULL,
		0x534EBEE43BD0AD80ULL,
		0x914198C0971D7028ULL,
		0x44103CA61AE07574ULL,
		0x863936DABA014F43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x249E4BAAE82221E2ULL,
		0x4DB393E2D45B58C2ULL,
		0xB81C1731BB4E71A5ULL,
		0xE4A0F3E7535A7DA4ULL,
		0xFCF596E5B3BAB3EBULL,
		0x933137F9EA5F48A1ULL,
		0xCFEFF0D04EA875FCULL,
		0xFC1A5CC3873EEA1FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x338633CB74EB0F4AULL,
		0x97EEA28B41760C0FULL,
		0x6FEBC3EAF15C6F56ULL,
		0x8E9275A84AF4FC04ULL,
		0x23AE91DE9B4B49F0ULL,
		0x320C266846BCB5FEULL,
		0x6DCC3BC26EE93CD4ULL,
		0x20B690370CF031F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1217E87CF870E6FULL,
		0xC1C4D99F8C7B0E4FULL,
		0x3D6AA4D9BEE57A0EULL,
		0x9EF3223FDE6A8780ULL,
		0x6B9B53E29E27D632ULL,
		0x21A6745D2AC16845ULL,
		0xF1C7A91A21FDDCC3ULL,
		0x335268E3D2CCD62DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5264B543A56400DBULL,
		0xD629C8EBB4FAFDBFULL,
		0x32811F113276F547ULL,
		0xEF9F53686C8A7484ULL,
		0xB8133DFBFD2373BDULL,
		0x1065B20B1BFB4DB8ULL,
		0x7C0492A84CEB6011ULL,
		0xED6427533A235BC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x608420F24AF625E9ULL,
		0x01A730C78BF4DFA8ULL,
		0x2DB7F71569E9ED88ULL,
		0xC06E3F4DABE4F77AULL,
		0x229D9B7F370B552AULL,
		0xAC0AF6C847387914ULL,
		0x870A186B667456A9ULL,
		0x65F04107E4E3F326ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC741CD24E19D829ULL,
		0x4922898212208606ULL,
		0xB3452204023453B4ULL,
		0x151A1B2B617BDE67ULL,
		0xE6BF99F01E561F32ULL,
		0x0DA976AACF8719B2ULL,
		0x516EE3B6265E2108ULL,
		0xC94D5C6DE15B2365ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9410041FFCDC4DC0ULL,
		0xB884A74579D459A1ULL,
		0x7A72D51167B599D3ULL,
		0xAB5424224A691912ULL,
		0x3BDE018F18B535F8ULL,
		0x9E61801D77B15F61ULL,
		0x359B34B5401635A1ULL,
		0x9CA2E49A0388CFC1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7C33DAAB371FE8C7ULL,
		0xF39AB9033751C65DULL,
		0x9D70C4888000BEF8ULL,
		0x06D3D55AA1BCBD39ULL,
		0xCBC92AC030F55F52ULL,
		0xCF02070DBFF591ABULL,
		0xAAADBFA27846C244ULL,
		0x631A07D0F834DE05ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95C2802F69BFCDC0ULL,
		0x7BA6E04E97BD6F8EULL,
		0x499287E88EFAA19FULL,
		0xB173D5581F4EAFEEULL,
		0x654EBB9654407C07ULL,
		0xD91B7B97D4520C65ULL,
		0xD4782D624CE73A3EULL,
		0x95AFEEBFF2EFA1C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6715A7BCD601B07ULL,
		0x77F3D8B49F9456CEULL,
		0x53DE3C9FF1061D59ULL,
		0x55600002826E0D4BULL,
		0x667A6F29DCB4E34AULL,
		0xF5E68B75EBA38546ULL,
		0xD63592402B5F8805ULL,
		0xCD6A191105453C41ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D84B37EC8B0B003ULL,
		0x56147E0DAE429C6EULL,
		0x2F6A64DAB66C7FF1ULL,
		0x1C1230C8666C71ACULL,
		0xEAE8DD55C3A708CBULL,
		0x81C9BAC7F698EE5EULL,
		0x08F630F5C47CE46AULL,
		0x951F51EA523EC166ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4B71AE849F46A0ULL,
		0x030793B602B7166DULL,
		0x7A52E7F10EF9F131ULL,
		0x7AE941179E2C50C4ULL,
		0x254190CE911A40DDULL,
		0x9ECD061A167FDE68ULL,
		0x8AC76FD3E7A26ECAULL,
		0x7D3B1197A91E8614ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x513941D044116963ULL,
		0x530CEA57AB8B8600ULL,
		0xB5177CE9A7728EC0ULL,
		0xA128EFB0C84020E7ULL,
		0xC5A74C87328CC7EDULL,
		0xE2FCB4ADE0190FF6ULL,
		0x7E2EC121DCDA759FULL,
		0x17E44052A9203B51ULL
	}};
	sign = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x649CEF58B6CA6412ULL,
		0x19719E0037A9EDA0ULL,
		0xB4240B2B024D911AULL,
		0x36A19556E0423594ULL,
		0xE6973BDE257C4323ULL,
		0xBD75AD1FC100CA94ULL,
		0x371CDAA41336A895ULL,
		0x958E564CCD248223ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFB68314EF317A52ULL,
		0xD1A1F878C7D8A13EULL,
		0xCCF909245CF1355FULL,
		0xE8A845FFA04FA595ULL,
		0xA846052A40146331ULL,
		0x04FF69A475B802CEULL,
		0x7EC0D2F4C3940548ULL,
		0x68EEB9BA36D6903CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64E66C43C798E9C0ULL,
		0x47CFA5876FD14C61ULL,
		0xE72B0206A55C5BBAULL,
		0x4DF94F573FF28FFEULL,
		0x3E5136B3E567DFF1ULL,
		0xB876437B4B48C7C6ULL,
		0xB85C07AF4FA2A34DULL,
		0x2C9F9C92964DF1E6ULL
	}};
	sign = 0;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA52306E6CFC182D8ULL,
		0x4AD9713B5D62D4F2ULL,
		0xF609E6B1D7C0286AULL,
		0x7E42E1DC0B579858ULL,
		0x405445A6E60DD274ULL,
		0x999182DE32822F7CULL,
		0xD8DC32926A955A64ULL,
		0x1515B54E54CE17CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4D8C571FD738FB0ULL,
		0x4859B26381052EA3ULL,
		0x448BA0D22E743085ULL,
		0x17AB4CC691C95256ULL,
		0x67EFB83FD02CF696ULL,
		0xFF657EBF3051A603ULL,
		0xFED525D3F50AB421ULL,
		0x25A154263D547223ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB04A4174D24DF328ULL,
		0x027FBED7DC5DA64EULL,
		0xB17E45DFA94BF7E5ULL,
		0x66979515798E4602ULL,
		0xD8648D6715E0DBDEULL,
		0x9A2C041F02308978ULL,
		0xDA070CBE758AA642ULL,
		0xEF7461281779A5ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF301286E69557220ULL,
		0x07674C33E30666C1ULL,
		0xB3ABA16C140655C4ULL,
		0x8BFB08A778D3505DULL,
		0x5297F413F00F75E7ULL,
		0x7B5DB565304159EFULL,
		0x21071A117FAC1AD6ULL,
		0x22DFFD3FCD7B0D89ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5896C0DA5B4F42D9ULL,
		0xC6D3796386F4E995ULL,
		0x872839931F36D34FULL,
		0xD42071990376CE64ULL,
		0xA39855CA79DC5E36ULL,
		0x9552449ECF4744CEULL,
		0x4CDAC727B44048E4ULL,
		0x4E3BDAE52C483BBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A6A67940E062F47ULL,
		0x4093D2D05C117D2CULL,
		0x2C8367D8F4CF8274ULL,
		0xB7DA970E755C81F9ULL,
		0xAEFF9E49763317B0ULL,
		0xE60B70C660FA1520ULL,
		0xD42C52E9CB6BD1F1ULL,
		0xD4A4225AA132D1CDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA6E602C7D014D698ULL,
		0xB8662480F04C039FULL,
		0x4C23A671EF938077ULL,
		0x6DEDA22540359B92ULL,
		0xE0B49AAB9650733FULL,
		0x189929367A84D3BAULL,
		0xAC686C91B226CA7BULL,
		0x2141D89A1C4FE30AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8EE5DC2C66429A1ULL,
		0xFD7B6DEBF46C490CULL,
		0x4863EC452132976AULL,
		0xB569817D9E0C74C8ULL,
		0x62391B2984782C31ULL,
		0xF9C5F34679CA3D2EULL,
		0xB03539BA0CAC91C6ULL,
		0x801F5995BB237BBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADF7A50509B0ACF7ULL,
		0xBAEAB694FBDFBA92ULL,
		0x03BFBA2CCE60E90CULL,
		0xB88420A7A22926CAULL,
		0x7E7B7F8211D8470DULL,
		0x1ED335F000BA968CULL,
		0xFC3332D7A57A38B4ULL,
		0xA1227F04612C674FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8EC75462B2726C81ULL,
		0xB4DEBE9A0F810CBAULL,
		0x212D4147557CAB43ULL,
		0x20B5D1F3D215C1BEULL,
		0x2E72BA04C84CCC7FULL,
		0x035402D978833608ULL,
		0x70352A1F69550091ULL,
		0x44A92DE241DC79CBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5E518444BE7DFDULL,
		0x1E7512BA0D898E52ULL,
		0xBFED0448DA11B0CEULL,
		0x3A48826726879204ULL,
		0xC10919D1AA42CA06ULL,
		0xE7DD544E8C953DD3ULL,
		0x98A6A03EC30FD637ULL,
		0xF6695292D10A47EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA06902DE6DB3EE84ULL,
		0x9669ABE001F77E67ULL,
		0x61403CFE7B6AFA75ULL,
		0xE66D4F8CAB8E2FB9ULL,
		0x6D69A0331E0A0278ULL,
		0x1B76AE8AEBEDF834ULL,
		0xD78E89E0A6452A59ULL,
		0x4E3FDB4F70D231DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x176489BCB886479EULL,
		0xCF36B33A3DE46781ULL,
		0xF9F1F161E247E1CCULL,
		0x3114AFE19AC2B512ULL,
		0x8F7E3F958522D38FULL,
		0xF84411E0672E2EB9ULL,
		0x0D862B3BB91EDF28ULL,
		0x8C6AB91BAE5ECFC5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6E2D737FA6634FULL,
		0x2AB7B7A879CE0032ULL,
		0xE157520EED9B2070ULL,
		0xFE3E36AE5E05C09AULL,
		0x56F01BC585DD5F36ULL,
		0xE46BED2986AE36F3ULL,
		0xCE1567E0DE9B5CC2ULL,
		0x8FF1B278EE6EBA13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7F65C4938DFE44FULL,
		0xA47EFB91C416674EULL,
		0x189A9F52F4ACC15CULL,
		0x32D679333CBCF478ULL,
		0x388E23CFFF457458ULL,
		0x13D824B6E07FF7C6ULL,
		0x3F70C35ADA838266ULL,
		0xFC7906A2BFF015B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE40A7C6FCF932CDBULL,
		0x61F869704E8FC87DULL,
		0xB62BC74024181670ULL,
		0xD6F673C8CA13977EULL,
		0x5CE2DADD42D02559ULL,
		0x653AED293F419FFCULL,
		0x124A2059766CBA5CULL,
		0x665ED6A3EA2DF0A9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3FC29AF90B3D64ULL,
		0xB0A7B01FBCA9DD41ULL,
		0x2F4539BB83DA7456ULL,
		0xACFAFE84AFA9E39BULL,
		0x00C5F16B9A94B1E1ULL,
		0x6B67B50E43D28190ULL,
		0x2DE9C3048E873BB3ULL,
		0xDF3B9BD5DD5A1EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97CAB9D4D687EF77ULL,
		0xB150B95091E5EB3CULL,
		0x86E68D84A03DA219ULL,
		0x29FB75441A69B3E3ULL,
		0x5C1CE971A83B7378ULL,
		0xF9D3381AFB6F1E6CULL,
		0xE4605D54E7E57EA8ULL,
		0x87233ACE0CD3D1F4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5BEBDC61DB977730ULL,
		0x042C1BAF1A30DFE1ULL,
		0x95ADA04EEE042267ULL,
		0x5832A1A9AEF94BFEULL,
		0x36A4A14939411E4DULL,
		0x0528F24BBBC8F71EULL,
		0x93F543E19E6D6AD4ULL,
		0x34116AF261104910ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE5009C6D291FB2ULL,
		0x52CC04EBFA1C451AULL,
		0x8CA499250854D3FFULL,
		0x2AC8BD27393B5E57ULL,
		0x9239C5FC6EF9AA4EULL,
		0x10218D02EFA6E8E4ULL,
		0x98693A24B3938A25ULL,
		0x1BAC7291A1D104D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7006DBC56E6E577EULL,
		0xB16016C320149AC6ULL,
		0x09090729E5AF4E67ULL,
		0x2D69E48275BDEDA7ULL,
		0xA46ADB4CCA4773FFULL,
		0xF5076548CC220E39ULL,
		0xFB8C09BCEAD9E0AEULL,
		0x1864F860BF3F4437ULL
	}};
	sign = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF23FFE3825BE9D4BULL,
		0xD080D13A0E658ECCULL,
		0x9285ADBF807E0C22ULL,
		0xF747ABB6B6984A28ULL,
		0x52A9D60DEA4BE17AULL,
		0x85A1DA7FF862BA2CULL,
		0xB7E88508147CF9D0ULL,
		0x64C76FD90004D2C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x538E35AAAB14BE94ULL,
		0x3A284BFDC255B646ULL,
		0x07A120C5BE6AB36CULL,
		0x6F327EAC6E72EC96ULL,
		0x5D37AD425BA7C76DULL,
		0x111FF416F326CB27ULL,
		0x216783C71DAEEB9EULL,
		0x710CE7209F2E4655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EB1C88D7AA9DEB7ULL,
		0x9658853C4C0FD886ULL,
		0x8AE48CF9C21358B6ULL,
		0x88152D0A48255D92ULL,
		0xF57228CB8EA41A0DULL,
		0x7481E669053BEF04ULL,
		0x96810140F6CE0E32ULL,
		0xF3BA88B860D68C6DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0AD3002E444F94E5ULL,
		0xAD7F92C6D86F632CULL,
		0x5ADAE207C4C5AACCULL,
		0xFD6EFAF2FE8D8479ULL,
		0x045340767AD092A7ULL,
		0x24F3AC0B33604F7CULL,
		0x395BFAA6B744BE3DULL,
		0x77A1AADFB8B30EB4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x780EAAA23A36C92FULL,
		0x60BB2C930EAD28FCULL,
		0xC1E6D7C333206E6FULL,
		0x4A6C41AFB63C8A69ULL,
		0xC2841CE74695CE41ULL,
		0xA44A0820626FABABULL,
		0x74184B4AA6E90427ULL,
		0x7636C6FC48CF93BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92C4558C0A18CBB6ULL,
		0x4CC46633C9C23A2FULL,
		0x98F40A4491A53C5DULL,
		0xB302B9434850FA0FULL,
		0x41CF238F343AC466ULL,
		0x80A9A3EAD0F0A3D0ULL,
		0xC543AF5C105BBA15ULL,
		0x016AE3E36FE37AF6ULL
	}};
	sign = 0;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x13A31A54ADF36067ULL,
		0xC91833323A7AAE46ULL,
		0x017386F396FD6DE6ULL,
		0x833987E4F27F5903ULL,
		0xDBA4AF0C5F0D8CB0ULL,
		0xB61D38B068646210ULL,
		0xE5684F8CD15D37C1ULL,
		0x778751DA3EA03F99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74105F8BF5B33708ULL,
		0x1DFEC5BE7F5BBB59ULL,
		0x462E0CA1EF03D03BULL,
		0x61CFF550C8E49330ULL,
		0x4CB8AA8F452B44A7ULL,
		0xB53EFA5B39597157ULL,
		0xD2FA943D70DE5C5EULL,
		0x29758AE07DFFFA58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F92BAC8B840295FULL,
		0xAB196D73BB1EF2ECULL,
		0xBB457A51A7F99DABULL,
		0x21699294299AC5D2ULL,
		0x8EEC047D19E24809ULL,
		0x00DE3E552F0AF0B9ULL,
		0x126DBB4F607EDB63ULL,
		0x4E11C6F9C0A04541ULL
	}};
	sign = 0;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39FF90E37B18694BULL,
		0x9BA7B50633D9EDE9ULL,
		0xBEB30524A5F49022ULL,
		0xDB63CCC0AC4F8291ULL,
		0x73088CE35191097BULL,
		0xEE3B2F0F951E4D49ULL,
		0x49C27DB86FC2F4ADULL,
		0x4AB2609F9D0AE0E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA5E5D7644A7D2C2ULL,
		0xB6A5F9DE4C93342AULL,
		0xF562FC7D71030940ULL,
		0x4BBABC82AA6983CEULL,
		0xACB65B608CB22616ULL,
		0x3F2C9B1B8072A494ULL,
		0x471336A55A5FD410ULL,
		0x46440F6FB0E12592ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FA1336D36709689ULL,
		0xE501BB27E746B9BEULL,
		0xC95008A734F186E1ULL,
		0x8FA9103E01E5FEC2ULL,
		0xC6523182C4DEE365ULL,
		0xAF0E93F414ABA8B4ULL,
		0x02AF47131563209DULL,
		0x046E512FEC29BB51ULL
	}};
	sign = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x18C7D777B197F345ULL,
		0x4D121376265BCF23ULL,
		0xAB91FE69CC288D66ULL,
		0x85B43CA8E71062A1ULL,
		0xCB61F2C637086F13ULL,
		0x31EDE07D372808F5ULL,
		0x315020E59AEDD4BCULL,
		0xFAC20BC6096E25C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A86483F91DEE27DULL,
		0x2562444E0B7CF5C4ULL,
		0xF0F0FB46090BFFB9ULL,
		0xB86ABE67F8303195ULL,
		0x04A1A25E0FBB31DAULL,
		0x256C5BBECBF3BD5BULL,
		0x101FB8659594C60CULL,
		0xBCB7DD526FA0C072ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E418F381FB910C8ULL,
		0x27AFCF281ADED95EULL,
		0xBAA10323C31C8DADULL,
		0xCD497E40EEE0310BULL,
		0xC6C05068274D3D38ULL,
		0x0C8184BE6B344B9AULL,
		0x2130688005590EB0ULL,
		0x3E0A2E7399CD6551ULL
	}};
	sign = 0;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9315899D6A1A303EULL,
		0x082FE2D556AC4B48ULL,
		0x22D81FCF70C49359ULL,
		0x7C7B1A217A5AEE4CULL,
		0x7E5EF20458842CF2ULL,
		0x5601353709869510ULL,
		0xBD9F71D7D513E88CULL,
		0xE1A86CC39DCD80DFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D9E2494B0D11032ULL,
		0xB08875E5E18137FAULL,
		0x2ACC3D933F900182ULL,
		0x4688A82367075AC8ULL,
		0xE9B25C8C1961C6BEULL,
		0x5347CAF6C42C0AA2ULL,
		0x058F17082A490F60ULL,
		0x4D43E3A39C7E3FBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15776508B949200CULL,
		0x57A76CEF752B134EULL,
		0xF80BE23C313491D6ULL,
		0x35F271FE13539383ULL,
		0x94AC95783F226634ULL,
		0x02B96A40455A8A6DULL,
		0xB8105ACFAACAD92CULL,
		0x94648920014F4122ULL
	}};
	sign = 0;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF09E954D639234BULL,
		0x264EEAD8A4AF1AFEULL,
		0x4888F0C4AF9E3523ULL,
		0xE3E819709C4C2F76ULL,
		0x9D1B45763722D375ULL,
		0xF1A740779D163D6FULL,
		0x3EEB289635D1075EULL,
		0x0E4EE570D8A78A16ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA7D0E94A214E26ULL,
		0xF818B0BBA67B961CULL,
		0xE8A15CF2877E25D3ULL,
		0xBB7A73F3F6FC9EE7ULL,
		0xBF8A36F19EA2C948ULL,
		0x9ACE5E43B7AD4A64ULL,
		0x4CCF6D2EA3E11578ULL,
		0x89F3B3A3D07FF159ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC062186B8C17D525ULL,
		0x2E363A1CFE3384E2ULL,
		0x5FE793D228200F4FULL,
		0x286DA57CA54F908EULL,
		0xDD910E8498800A2DULL,
		0x56D8E233E568F30AULL,
		0xF21BBB6791EFF1E6ULL,
		0x845B31CD082798BCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x96770DD6921AC420ULL,
		0x4CD3708AB52320A7ULL,
		0x8094BCA1E1674BF3ULL,
		0x5324E107D3FF240DULL,
		0x536780609F42035CULL,
		0x901AB708CC668A7FULL,
		0x051A6553CFDB8F00ULL,
		0x0812BEBA6CB83E93ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C71D776BD7605F3ULL,
		0xB6B2F03D2E03B799ULL,
		0xBA31D34367CDD0B2ULL,
		0x5A1D75606AF875CFULL,
		0xF68F7988F2C13C47ULL,
		0x270DC73919C1BBECULL,
		0xCCE819BBDA6A45C4ULL,
		0x019613D77A3D731AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A05365FD4A4BE2DULL,
		0x9620804D871F690EULL,
		0xC662E95E79997B40ULL,
		0xF9076BA76906AE3DULL,
		0x5CD806D7AC80C714ULL,
		0x690CEFCFB2A4CE92ULL,
		0x38324B97F571493CULL,
		0x067CAAE2F27ACB78ULL
	}};
	sign = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x561A43B918863F18ULL,
		0x12DFB31358323551ULL,
		0x5629C979FFAC2870ULL,
		0xE50A16A2B87980CFULL,
		0x454FD3FA261BCDFCULL,
		0x7E2B54C7CDB51097ULL,
		0x064316FB0448F205ULL,
		0x1D250F467197A689ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7F9C7C5A3E801EAULL,
		0xFE867F7A9114F7ECULL,
		0x6D051E1787FCA22BULL,
		0x620FEE50F84B5884ULL,
		0x11C6A37A9023AB17ULL,
		0xD1B8811030A34179ULL,
		0x52E947050534ACD6ULL,
		0x5B21420B2663ED1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E207BF3749E3D2EULL,
		0x14593398C71D3D64ULL,
		0xE924AB6277AF8644ULL,
		0x82FA2851C02E284AULL,
		0x3389307F95F822E5ULL,
		0xAC72D3B79D11CF1EULL,
		0xB359CFF5FF14452EULL,
		0xC203CD3B4B33B96AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEA110E8433491CB9ULL,
		0xA47AF290EC7DDD0BULL,
		0x096B6DDE8026AC9FULL,
		0x1D354A874D062443ULL,
		0x936AE0AF0C46B518ULL,
		0xC5CDBB8FDF5A8F55ULL,
		0x578059F9BB1D40DDULL,
		0x716AAD4C9DE488D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x951AB0F37DA0C2ADULL,
		0x6BA563F136C35A39ULL,
		0x40E8AB9EC8A5744CULL,
		0x5B382D42035611E3ULL,
		0x47717A7EF68CA010ULL,
		0x0F38D80011EFE27EULL,
		0x19730959C749F7FEULL,
		0xA6D8CBC81DEB4F2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54F65D90B5A85A0CULL,
		0x38D58E9FB5BA82D2ULL,
		0xC882C23FB7813853ULL,
		0xC1FD1D4549B0125FULL,
		0x4BF9663015BA1507ULL,
		0xB694E38FCD6AACD7ULL,
		0x3E0D509FF3D348DFULL,
		0xCA91E1847FF939A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAA2352DF2FEE8C17ULL,
		0x6CDD05EAE6EA1ADDULL,
		0x1D564A5D1030641FULL,
		0x9A0C1BDEA8A50444ULL,
		0xCF6F2FE83502B2A3ULL,
		0xF5A6007C60CFC5CAULL,
		0x55C7EFC3813BA151ULL,
		0x36745F5EC863B673ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF6CAA37DE2D836ULL,
		0x6B5E3DC0CC9A14D1ULL,
		0xCF7DD843627904FFULL,
		0xA6857D79B58246B8ULL,
		0x86BE484E8FD01DAFULL,
		0xC7A123288A514CE2ULL,
		0x03F5B6C12A7553B4ULL,
		0xF3E90C7EBB1A0900ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC2C883BB20BB3E1ULL,
		0x017EC82A1A50060BULL,
		0x4DD87219ADB75F20ULL,
		0xF3869E64F322BD8BULL,
		0x48B0E799A53294F3ULL,
		0x2E04DD53D67E78E8ULL,
		0x51D2390256C64D9DULL,
		0x428B52E00D49AD73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD49D52A433067CB7ULL,
		0x5125E6A716A57A65ULL,
		0x639B417D3ADA0F4BULL,
		0x8D59ABB7C655D731ULL,
		0x54F0FE62E7F19177ULL,
		0xB0092DC2986D3603ULL,
		0x63597F0024D83719ULL,
		0x4ABD7931ED499131ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C2F74DE9E4857EULL,
		0xCE6FA85C2A55E6CDULL,
		0x60715D8C4BD467FAULL,
		0x90AAE1EF246DB5F2ULL,
		0x59BF519C35F0A2B2ULL,
		0x7B19BB97012794DCULL,
		0xC909BDD0DED852F8ULL,
		0x7BF6ED92EBFDED04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12DA5B564921F739ULL,
		0x82B63E4AEC4F9398ULL,
		0x0329E3F0EF05A750ULL,
		0xFCAEC9C8A1E8213FULL,
		0xFB31ACC6B200EEC4ULL,
		0x34EF722B9745A126ULL,
		0x9A4FC12F45FFE421ULL,
		0xCEC68B9F014BA42CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x815483AB42D53BA2ULL,
		0x563296C5BDCEEA4DULL,
		0x1EC72B58EB2F0E1EULL,
		0xABDBD104E5DB664BULL,
		0xB3BCBBE5F1BA8503ULL,
		0xC16F591EA7FA9C4CULL,
		0xF16FA5AEA80DF032ULL,
		0xF544A5447361F8A6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x00B4AED415FDA598ULL,
		0x01D88374016A713CULL,
		0x67A9DA76B7F49757ULL,
		0xD0564701CD1204A5ULL,
		0x3764FF77430594B1ULL,
		0xA51B5980298B9877ULL,
		0xE4F63EEA7A62A623ULL,
		0x5561F1DCA92AD9E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x809FD4D72CD7960AULL,
		0x545A1351BC647911ULL,
		0xB71D50E2333A76C7ULL,
		0xDB858A0318C961A5ULL,
		0x7C57BC6EAEB4F051ULL,
		0x1C53FF9E7E6F03D5ULL,
		0x0C7966C42DAB4A0FULL,
		0x9FE2B367CA371EC5ULL
	}};
	sign = 0;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x428EB7F004178FC4ULL,
		0x7C055048BF52325DULL,
		0x18CD52BD834F83F4ULL,
		0x03957A2F6397C371ULL,
		0xA5840486DCEE743FULL,
		0xA45DCBDB09940F95ULL,
		0xA5E35069BA3AD80DULL,
		0x7BE348E163BB4E9EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8521673E68854B93ULL,
		0x0F9B666A0880EFFFULL,
		0x6A07EF3E40A96C29ULL,
		0x97D2FC0A13ECFE63ULL,
		0x2B368BE3F6B853E6ULL,
		0xBDFE7B08921515B8ULL,
		0x52FFF99B668D9D98ULL,
		0xB4096F4E7329FEFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD6D50B19B924431ULL,
		0x6C69E9DEB6D1425DULL,
		0xAEC5637F42A617CBULL,
		0x6BC27E254FAAC50DULL,
		0x7A4D78A2E6362058ULL,
		0xE65F50D2777EF9DDULL,
		0x52E356CE53AD3A74ULL,
		0xC7D9D992F0914FA0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1437AC5FAE512336ULL,
		0xE0D6471B35652D2DULL,
		0x25066FB21FF517DAULL,
		0x96894668A4F76C8BULL,
		0xD899F89B91D41A2EULL,
		0xF5475627EC6D8EB0ULL,
		0x6FF567C673A6C618ULL,
		0x69C4D289CBE53D82ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x873AAFFCE7AE15C1ULL,
		0x4DE67597D7878853ULL,
		0x07C1E8AF87439A0FULL,
		0xC30A0F5F332B5874ULL,
		0x20D46509E9AD622EULL,
		0x9481BF6741C87554ULL,
		0x5F4A7C02E954C832ULL,
		0x6A5669D76CED0D24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CFCFC62C6A30D75ULL,
		0x92EFD1835DDDA4D9ULL,
		0x1D44870298B17DCBULL,
		0xD37F370971CC1417ULL,
		0xB7C59391A826B7FFULL,
		0x60C596C0AAA5195CULL,
		0x10AAEBC38A51FDE6ULL,
		0xFF6E68B25EF8305EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0F4E718DF8B4AC59ULL,
		0x536BFEB9950947A3ULL,
		0x11E3AB094C135A1CULL,
		0x3754A050AB87B7DFULL,
		0x0F8E3CD5175C1137ULL,
		0xBE4CBBDF43186134ULL,
		0x6AF8CF7D2E380E3CULL,
		0xDEF4C1E490C2B734ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE68E852B4A433F9BULL,
		0x967156829B54FB05ULL,
		0x7CED8F86BAEBE04EULL,
		0xA0E9CDD8079BD852ULL,
		0xB01F03CC13A03D72ULL,
		0xD425D33D893B01D2ULL,
		0x51F5D5BBE09000A6ULL,
		0x6785B69327DE12EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28BFEC62AE716CBEULL,
		0xBCFAA836F9B44C9DULL,
		0x94F61B82912779CDULL,
		0x966AD278A3EBDF8CULL,
		0x5F6F390903BBD3C4ULL,
		0xEA26E8A1B9DD5F61ULL,
		0x1902F9C14DA80D95ULL,
		0x776F0B5168E4A447ULL
	}};
	sign = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7D1EA410D39FA3D8ULL,
		0x5329D704A14A9FC2ULL,
		0xF52A8A855F81FAF9ULL,
		0x4FCACAAF32518C20ULL,
		0x513391B5EE165141ULL,
		0xD0D3990E55EDA22DULL,
		0x5867DF0EE25B4F61ULL,
		0x3436CF4190EB5942ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA769B4789EF805ULL,
		0x5BB3878E8F3CCF62ULL,
		0x5F726104315ACE64ULL,
		0x88ED0CFD72A1882BULL,
		0xD50D634C9E9582A4ULL,
		0x227D4112873C51FBULL,
		0x79AB4B8F3CEBB17CULL,
		0xB471FCE362207B4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10773A5C5B00ABD3ULL,
		0xF7764F76120DD060ULL,
		0x95B829812E272C94ULL,
		0xC6DDBDB1BFB003F5ULL,
		0x7C262E694F80CE9CULL,
		0xAE5657FBCEB15031ULL,
		0xDEBC937FA56F9DE5ULL,
		0x7FC4D25E2ECADDF2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x870983BD4A7C24CEULL,
		0xC07BAAB099387BF2ULL,
		0x031379A7A3D90405ULL,
		0x2C43312A77506FD9ULL,
		0x4176619CD0A79714ULL,
		0x51439248ACDDD0B3ULL,
		0x3160F1658BF378F4ULL,
		0xC0255349904FB0C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x40EB0C3E20DC7C3AULL,
		0xBC3E6F335146EADCULL,
		0xE6D06577F4291931ULL,
		0x1CA78DB709A83B07ULL,
		0x059C7EE01A97D28BULL,
		0xAD30C27DBC66ED7BULL,
		0xD5A263C6F6EC83B6ULL,
		0x36399CB492391CD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x461E777F299FA894ULL,
		0x043D3B7D47F19116ULL,
		0x1C43142FAFAFEAD4ULL,
		0x0F9BA3736DA834D1ULL,
		0x3BD9E2BCB60FC489ULL,
		0xA412CFCAF076E338ULL,
		0x5BBE8D9E9506F53DULL,
		0x89EBB694FE1693EFULL
	}};
	sign = 0;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CB1205642770B2BULL,
		0xA0435A3697C203A6ULL,
		0x9E578021A9E01907ULL,
		0x98B93D713694F916ULL,
		0xE58A1B3DBD120FBBULL,
		0x1EE3F2F39A252C43ULL,
		0xADAD824BCC7321FDULL,
		0xE6AEF22E1362F7D5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD87A898B5A7290C7ULL,
		0xE295F2D19A906968ULL,
		0x01A6995850B2AD8AULL,
		0xC661E9D95AF79FE8ULL,
		0xFD154313293121ACULL,
		0x2B1AA72610890D6EULL,
		0xCDB2DA5304CF6507ULL,
		0x8DE72D02FFE3819BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x743696CAE8047A64ULL,
		0xBDAD6764FD319A3DULL,
		0x9CB0E6C9592D6B7CULL,
		0xD2575397DB9D592EULL,
		0xE874D82A93E0EE0EULL,
		0xF3C94BCD899C1ED4ULL,
		0xDFFAA7F8C7A3BCF5ULL,
		0x58C7C52B137F7639ULL
	}};
	sign = 0;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x435B6AEA527FEA36ULL,
		0x7ABF25CD720B2688ULL,
		0xCC40AF2BF6B2171DULL,
		0x3C479F3C53C45C7BULL,
		0x9A36A43FA5AFA9BBULL,
		0x78FB64737D3EB5F1ULL,
		0x43B6CF40ABCF3E66ULL,
		0x7D73867FDCED78C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x34FB8FE34FA56687ULL,
		0x34CA43C26270B684ULL,
		0x0FD8F59ED406CFBEULL,
		0x02C4FAA623827911ULL,
		0xDB119B760EA428A6ULL,
		0x1860EDCF6BE9F1A5ULL,
		0x26D1E20011514B4AULL,
		0xDC43248A83D0D346ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E5FDB0702DA83AFULL,
		0x45F4E20B0F9A7004ULL,
		0xBC67B98D22AB475FULL,
		0x3982A4963041E36AULL,
		0xBF2508C9970B8115ULL,
		0x609A76A41154C44BULL,
		0x1CE4ED409A7DF31CULL,
		0xA13061F5591CA57DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39DBFF3D113EB635ULL,
		0xA862026B48A77C9FULL,
		0x990CD58690D0AFF8ULL,
		0xB38AD34EFD041AB8ULL,
		0xC05A3CBC79A5B620ULL,
		0xEA31C7FB66217A63ULL,
		0x147188EA687742FCULL,
		0x73C05508AAB1CD11ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE41AABBA37EF403ULL,
		0xA5E0E87486D2EF21ULL,
		0x84986594CE4FD6B4ULL,
		0xD428FE89BB2BB49BULL,
		0x3875BC577869C6DDULL,
		0x85037FFE395668F0ULL,
		0xEB676AE1671F5E91ULL,
		0x22C15293D2CC03D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B9A54816DBFC232ULL,
		0x028119F6C1D48D7DULL,
		0x14746FF1C280D944ULL,
		0xDF61D4C541D8661DULL,
		0x87E48065013BEF42ULL,
		0x652E47FD2CCB1173ULL,
		0x290A1E090157E46BULL,
		0x50FF0274D7E5C93AULL
	}};
	sign = 0;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x542017577578A26AULL,
		0xF9B80E5F19F9D32CULL,
		0x61BDC7214C00A50FULL,
		0xD4B4B3F85A6AD867ULL,
		0x12F301DB3E90BBBDULL,
		0x6E87F67480FFCAA5ULL,
		0xAED33F58BF8CDB78ULL,
		0x7D06D1B4B4F257B2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97444EC67093C241ULL,
		0x9F494EDDA34DBD91ULL,
		0xD21D5EFBBADDBF5BULL,
		0x40BB1A882112F5BFULL,
		0xB68CB010A8870385ULL,
		0x6076A413C7CE3C7CULL,
		0x2E138FB3440572D6ULL,
		0x2691B2B87E8C0F39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCDBC89104E4E029ULL,
		0x5A6EBF8176AC159AULL,
		0x8FA068259122E5B4ULL,
		0x93F999703957E2A7ULL,
		0x5C6651CA9609B838ULL,
		0x0E115260B9318E28ULL,
		0x80BFAFA57B8768A2ULL,
		0x56751EFC36664879ULL
	}};
	sign = 0;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE61E2956E433725BULL,
		0x157CEB5F05A6D642ULL,
		0xC9436075350CEC41ULL,
		0xC53F8BE1B1F18D07ULL,
		0xA4BEBE98F6225320ULL,
		0xE3B33478DE7EB490ULL,
		0x900ECEA296A49F57ULL,
		0xFA8D4197946CA900ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0432E5B0B07E805ULL,
		0x1359D5FB6BEE7C95ULL,
		0x9D369B95E5653095ULL,
		0xB2740926B37EA6CDULL,
		0xAC50126E7DCE3AD7ULL,
		0xBC71C121435C7F35ULL,
		0xE72631C55ECBAAD4ULL,
		0x281B8BB1112722EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45DAFAFBD92B8A56ULL,
		0x0223156399B859ADULL,
		0x2C0CC4DF4FA7BBACULL,
		0x12CB82BAFE72E63AULL,
		0xF86EAC2A78541849ULL,
		0x274173579B22355AULL,
		0xA8E89CDD37D8F483ULL,
		0xD271B5E683458612ULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAC56E2080860AE6EULL,
		0xC99E6FD8592DBB8BULL,
		0xC159066C2506BBC4ULL,
		0x7C1CBC03C8C06A81ULL,
		0x77F0FF0C0B676939ULL,
		0xAA777593B1D75E09ULL,
		0xD578BB146AB5A1EDULL,
		0x74BD180182116A08ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FCC5DD881628525ULL,
		0xA23E5DD2967BEB4BULL,
		0x81B79832FE76A606ULL,
		0xEEEADCA099D53DFCULL,
		0x30F722A8C72077D6ULL,
		0x9E825A62DE68EEDFULL,
		0xEB373D3544835D37ULL,
		0x8C6B2B909746FE2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C8A842F86FE2949ULL,
		0x27601205C2B1D040ULL,
		0x3FA16E39269015BEULL,
		0x8D31DF632EEB2C85ULL,
		0x46F9DC634446F162ULL,
		0x0BF51B30D36E6F2AULL,
		0xEA417DDF263244B6ULL,
		0xE851EC70EACA6BD9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4DF26FF67F0758EBULL,
		0x94B06409011FB2B3ULL,
		0xE991F11DA89A622DULL,
		0x2889B2CBC5F3DEACULL,
		0x7162E046A52EDC13ULL,
		0x52D26B345B5BC997ULL,
		0x3B4BFC1BB50C4F7AULL,
		0xE4485A46E36AAF74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BFC74D0A15B828EULL,
		0xE79C525E3A687D7CULL,
		0x3FA7BD892C9360DCULL,
		0x7692E57F35D6A216ULL,
		0x9C48FCCE21216682ULL,
		0x5A9C5C6D2FC21CF5ULL,
		0x9E995F125BFDEA20ULL,
		0xB1C70DFF5EDCDC92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41F5FB25DDABD65DULL,
		0xAD1411AAC6B73537ULL,
		0xA9EA33947C070150ULL,
		0xB1F6CD4C901D3C96ULL,
		0xD519E378840D7590ULL,
		0xF8360EC72B99ACA1ULL,
		0x9CB29D09590E6559ULL,
		0x32814C47848DD2E1ULL
	}};
	sign = 0;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1487DE36E114FA9BULL,
		0x2863DA5479992736ULL,
		0x6E5E294CD84883B1ULL,
		0x7F19F54AC49A8AC9ULL,
		0xD53F412116B97C23ULL,
		0x8642FF160F660B1CULL,
		0xEC7FC04D13024023ULL,
		0x7B4696121401C1BBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3298330122F3B81EULL,
		0x5106AC789369EE3AULL,
		0xF6329A7BC2E81295ULL,
		0xB32322397819A437ULL,
		0x6B214341D5BF1146ULL,
		0x259BAF13DDF281FBULL,
		0xF325C65A25767AD4ULL,
		0xE5BCDA8C477202C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1EFAB35BE21427DULL,
		0xD75D2DDBE62F38FBULL,
		0x782B8ED11560711BULL,
		0xCBF6D3114C80E691ULL,
		0x6A1DFDDF40FA6ADCULL,
		0x60A7500231738921ULL,
		0xF959F9F2ED8BC54FULL,
		0x9589BB85CC8FBEF6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBF9BFB8D5ACC9765ULL,
		0xF9DE16915D738670ULL,
		0x43C6FA1E4EF83B26ULL,
		0x7A617B59BF168638ULL,
		0xE26B8217B053D866ULL,
		0x25FAA2279F1162D8ULL,
		0x4067DCCDCD41FEE5ULL,
		0x909CBC28EF5809FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x86086404A7C087F1ULL,
		0x87F685C662FF5DC3ULL,
		0x067B1B7F62AAF535ULL,
		0xD21EFD7E418680BFULL,
		0x715A68941A70E3A1ULL,
		0x9609383F6F20E9D8ULL,
		0x2298BC67FF865050ULL,
		0xFA8E9823C6BEA9A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39939788B30C0F74ULL,
		0x71E790CAFA7428ADULL,
		0x3D4BDE9EEC4D45F1ULL,
		0xA8427DDB7D900579ULL,
		0x7111198395E2F4C4ULL,
		0x8FF169E82FF07900ULL,
		0x1DCF2065CDBBAE94ULL,
		0x960E240528996056ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x18670FE7169B12A7ULL,
		0x366DFE48981BCA5DULL,
		0xE442C9173C078424ULL,
		0x5B42D5EEA015E845ULL,
		0x276C42A5C81C9E5EULL,
		0x4DD2025BAF4A0F83ULL,
		0x4D97564DED0422EBULL,
		0x8BAA0AD7A7916483ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA250F2942E7B6BULL,
		0xAAC4B960513EEF65ULL,
		0x1BE00B453694BB7EULL,
		0x02B61B37E6D79749ULL,
		0x171AA7A38C385BE1ULL,
		0xD020F08411BE1B0AULL,
		0x140687D2C28C719CULL,
		0x8BED35250AC2F9C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCC4BEF4826C973CULL,
		0x8BA944E846DCDAF7ULL,
		0xC862BDD20572C8A5ULL,
		0x588CBAB6B93E50FCULL,
		0x10519B023BE4427DULL,
		0x7DB111D79D8BF479ULL,
		0x3990CE7B2A77B14EULL,
		0xFFBCD5B29CCE6ABAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFA5E28666A624C34ULL,
		0x5F939C3A537E7A51ULL,
		0xBD316CD50DEFD60FULL,
		0xE6E62DF94B63CD40ULL,
		0x7DB5037811A6E862ULL,
		0x39D37D29DD0DB6A9ULL,
		0x8B071B98F0650828ULL,
		0x79785A304D6F442FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35665494D1D3BA98ULL,
		0xE65F8439A16F3FA0ULL,
		0xEE06F5C2D6CD5D2FULL,
		0xA646C3393CB9B044ULL,
		0x037DA1A5D50D0045ULL,
		0x56C85AD213DD2366ULL,
		0xD8B1D13E8B42BD2FULL,
		0xEB59B3EADCB94362ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4F7D3D1988E919CULL,
		0x79341800B20F3AB1ULL,
		0xCF2A7712372278DFULL,
		0x409F6AC00EAA1CFBULL,
		0x7A3761D23C99E81DULL,
		0xE30B2257C9309343ULL,
		0xB2554A5A65224AF8ULL,
		0x8E1EA64570B600CCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6CC23567901BA7ABULL,
		0x61F71C1150C282E9ULL,
		0x4957552C97E6D4B3ULL,
		0x849B177440DB82F0ULL,
		0x32AF7F92AB0670FCULL,
		0xAE207A7FAAE08C71ULL,
		0xDD5405F1E7039DFCULL,
		0xE9CABA7A0D3DB62DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C0E09854D0767EULL,
		0xA3CC03B783CCC5E9ULL,
		0x38A7C6318F7A4311ULL,
		0x30B1D798BD409593ULL,
		0xFE8F070DD4C8FE7AULL,
		0xE6396C2C2038567FULL,
		0x3C959A32E2E20552ULL,
		0x735446DD82AC227EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x590154CF3B4B312DULL,
		0xBE2B1859CCF5BD00ULL,
		0x10AF8EFB086C91A1ULL,
		0x53E93FDB839AED5DULL,
		0x34207884D63D7282ULL,
		0xC7E70E538AA835F1ULL,
		0xA0BE6BBF042198A9ULL,
		0x7676739C8A9193AFULL
	}};
	sign = 0;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x818748FEC3103DA7ULL,
		0x9CD1E87B2469FEE6ULL,
		0xA54AC57E4C709F86ULL,
		0xC82F7E2A6C6F0D81ULL,
		0x08B7F0275C2398CBULL,
		0x01C07A0D7B6BD1F7ULL,
		0x643CDC5912B8E509ULL,
		0xE0E3A6C39FB2C1A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A688EF0544E6858ULL,
		0xCD3D1EC522F9182EULL,
		0x2E501F13C6684AF5ULL,
		0x45C45C6FED98920BULL,
		0x39704C904DB88B1EULL,
		0x3580A8E07249DE21ULL,
		0x4321F135F136D4B3ULL,
		0xF0959B38D6BB9823ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x571EBA0E6EC1D54FULL,
		0xCF94C9B60170E6B8ULL,
		0x76FAA66A86085490ULL,
		0x826B21BA7ED67B76ULL,
		0xCF47A3970E6B0DADULL,
		0xCC3FD12D0921F3D5ULL,
		0x211AEB2321821055ULL,
		0xF04E0B8AC8F7297DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x815219876A7B13B8ULL,
		0xB4AC3146039F944EULL,
		0x942351C88BE698BBULL,
		0x2CAEB00E76746F1AULL,
		0x14E525E3EEB20FECULL,
		0xD78C76D58BAEE9A3ULL,
		0xEC66862CA4B0767BULL,
		0x14A64212CBC04D07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5EF4483DBB4E85BULL,
		0xC3691528187681E4ULL,
		0x129560D4873DD9D4ULL,
		0x76FD53B17D2020C1ULL,
		0xCAF7AB870211B9E1ULL,
		0x2101A7D28A39CAFEULL,
		0x6D98369588786878ULL,
		0x2ADDEA924E9EE56EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB62D5038EC62B5DULL,
		0xF1431C1DEB291269ULL,
		0x818DF0F404A8BEE6ULL,
		0xB5B15C5CF9544E59ULL,
		0x49ED7A5CECA0560AULL,
		0xB68ACF0301751EA4ULL,
		0x7ECE4F971C380E03ULL,
		0xE9C857807D216799ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC6274ED6B55ACB97ULL,
		0x8D2B410839D4FBB3ULL,
		0x6BB8600EFCC9B5A2ULL,
		0xB4EE46A0D7424C5FULL,
		0x2C7D89F36DAD7967ULL,
		0x6546304193EA92DCULL,
		0xB42B14DAF63ECA83ULL,
		0xF71C7B4DF0F331F8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD02A17FD65B3CE4ULL,
		0xDEAD3F5AF84E6134ULL,
		0x462D53A16E9FAFC7ULL,
		0x75918A80D3A60135ULL,
		0x80E5E0F02804378CULL,
		0x44724EB4370CC354ULL,
		0x30BB0D912AC15EB8ULL,
		0x8CCF41AAD9EE1F42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1924AD56DEFF8EB3ULL,
		0xAE7E01AD41869A7FULL,
		0x258B0C6D8E2A05DAULL,
		0x3F5CBC20039C4B2AULL,
		0xAB97A90345A941DBULL,
		0x20D3E18D5CDDCF87ULL,
		0x83700749CB7D6BCBULL,
		0x6A4D39A3170512B6ULL
	}};
	sign = 0;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDFFAD280EDE07F50ULL,
		0xA7DA36E13347E9BDULL,
		0x7514006CA4454A65ULL,
		0x9929FCBFB267C049ULL,
		0x669690CFF4B4DED5ULL,
		0x3FFEC019AD53596EULL,
		0xBCB0962AE7AF3CF4ULL,
		0xE38C8CCEE4EF2244ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA785CC656058C35ULL,
		0xF963318A4924FC51ULL,
		0xC169BA7DD1775E62ULL,
		0x4589025995459546ULL,
		0x676FCE59D6BF1019ULL,
		0xD7AA74A68C6202DAULL,
		0xC913EE60B3711F8AULL,
		0xFF0C9BAE457281D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x058275BA97DAF31BULL,
		0xAE770556EA22ED6CULL,
		0xB3AA45EED2CDEC02ULL,
		0x53A0FA661D222B02ULL,
		0xFF26C2761DF5CEBCULL,
		0x68544B7320F15693ULL,
		0xF39CA7CA343E1D69ULL,
		0xE47FF1209F7CA06FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x13A32EB91C7C2D0EULL,
		0xF5F5A2534A94BED2ULL,
		0x7EF4A17083777D05ULL,
		0x94DA3371D7D849E2ULL,
		0x16376B97DD3FBCD6ULL,
		0x79DFF2DD9A711941ULL,
		0x8B69A844C3F8EF21ULL,
		0x5A735B0CE1BE9528ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92DDE1C7272A052ULL,
		0xBE26442C196236DDULL,
		0xD9859B1D987A0EB5ULL,
		0x3602892B5D6D9308ULL,
		0x99A819A68A77A872ULL,
		0x53C7D70E3F2E9A3EULL,
		0xD5E9F7D4E4A17425ULL,
		0xE1E05A4BFF76B43DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A75509CAA098CBCULL,
		0x37CF5E27313287F4ULL,
		0xA56F0652EAFD6E50ULL,
		0x5ED7AA467A6AB6D9ULL,
		0x7C8F51F152C81464ULL,
		0x26181BCF5B427F02ULL,
		0xB57FB06FDF577AFCULL,
		0x789300C0E247E0EAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC1F904A6BEDBD321ULL,
		0xD20F6D1C171F3B5FULL,
		0xB534C219BAB2280AULL,
		0xB849832BBBAF2F44ULL,
		0xC8D4CC2A6C4B4AE7ULL,
		0x3E9CDF6D91C9CE28ULL,
		0xBD24E7AEEC0EB675ULL,
		0x07C046D7D0E81917ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x77567569977734EFULL,
		0x843D3D2FC53A300EULL,
		0xB85AD4B7BA327D66ULL,
		0x256565A791825569ULL,
		0xDFBDD3E7BF137F3BULL,
		0x2E4A0DE6F6C94D07ULL,
		0x3F36CAE0F33EC9B7ULL,
		0xEEFDDFD114623A5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AA28F3D27649E32ULL,
		0x4DD22FEC51E50B51ULL,
		0xFCD9ED62007FAAA4ULL,
		0x92E41D842A2CD9DAULL,
		0xE916F842AD37CBACULL,
		0x1052D1869B008120ULL,
		0x7DEE1CCDF8CFECBEULL,
		0x18C26706BC85DEB9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xACA3F53BA65F728BULL,
		0xB0D51748EA602395ULL,
		0x7BD242AC92D7058EULL,
		0x0F0395039D65509FULL,
		0x1E58A04AC90F2AB4ULL,
		0x64988DB8A29EFB73ULL,
		0xBB89E808E0CBB8B9ULL,
		0x9121AF1CB1D21DF5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6586EFDD273A02DCULL,
		0x4252F96731B3BDFAULL,
		0xF36DC187278329F9ULL,
		0x750314182B23B011ULL,
		0xADB2D824113B71BFULL,
		0x97AB43A6B523E4B9ULL,
		0x1D4D53C0728FE29AULL,
		0xBA85080DB33B98CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x471D055E7F256FAFULL,
		0x6E821DE1B8AC659BULL,
		0x886481256B53DB95ULL,
		0x9A0080EB7241A08DULL,
		0x70A5C826B7D3B8F4ULL,
		0xCCED4A11ED7B16B9ULL,
		0x9E3C94486E3BD61EULL,
		0xD69CA70EFE968529ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x759C61B48D63394DULL,
		0x8CC745C67FD668E3ULL,
		0xC2AEA2A1AD957D5BULL,
		0x11C26B7DC1551FD5ULL,
		0x433BAAAC31684B3CULL,
		0x04F125F0A7917D1DULL,
		0x0AA69060191023D0ULL,
		0x6FEBCF4FFBB0C08CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C012AAE25280921ULL,
		0xB3EB35CE028CFB82ULL,
		0x72E77AB04CD62985ULL,
		0xCD0C45932B36DF28ULL,
		0x79F802F6E7D7DCD4ULL,
		0x59B6CA64ED55FC2EULL,
		0x9459FF63B9132551ULL,
		0x47FB8EED5AD342FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF99B3706683B302CULL,
		0xD8DC0FF87D496D60ULL,
		0x4FC727F160BF53D5ULL,
		0x44B625EA961E40ADULL,
		0xC943A7B549906E67ULL,
		0xAB3A5B8BBA3B80EEULL,
		0x764C90FC5FFCFE7EULL,
		0x27F04062A0DD7D8CULL
	}};
	sign = 0;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x77D8E69DC493CA53ULL,
		0x7FF9238B277783B3ULL,
		0x2ECCFBB9273710C6ULL,
		0xEC4C6CA1E6212CCCULL,
		0x6AA468C140691A38ULL,
		0xD9D768668CB9B6FBULL,
		0x9B3ADF3E4ADB2B33ULL,
		0x1215ACC6323E210DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0498361D41541D7EULL,
		0x43D40212F1A46B2AULL,
		0x1E6151EDAB2EF0A7ULL,
		0xF6E1E482C9FBF6DAULL,
		0x1868414CF0C5E0D0ULL,
		0xAECCC895F49C2A06ULL,
		0xA1F6CEB8742077EDULL,
		0x1BF3AFAD54DDCBBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7340B080833FACD5ULL,
		0x3C25217835D31889ULL,
		0x106BA9CB7C08201FULL,
		0xF56A881F1C2535F2ULL,
		0x523C27744FA33967ULL,
		0x2B0A9FD0981D8CF5ULL,
		0xF9441085D6BAB346ULL,
		0xF621FD18DD60554FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6180BDA584FF0DABULL,
		0x6E11589395810B74ULL,
		0x0EA992D43864C73BULL,
		0xD2C0CA677AB1F16CULL,
		0x384622B83F66CF60ULL,
		0x075281D70B814950ULL,
		0x6C4EB86CB885E15EULL,
		0x7E45AD20EE9BFFFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C47800E092EB3FEULL,
		0x8CBFCBF288649923ULL,
		0x72E00D234495B3B8ULL,
		0x577F45DBEDEB255DULL,
		0x07CEDD1A9C659EAFULL,
		0x8485A89CB3EE3864ULL,
		0xCF4943DB191DA8BCULL,
		0x9A66FCB63B2BDCD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05393D977BD059ADULL,
		0xE1518CA10D1C7251ULL,
		0x9BC985B0F3CF1382ULL,
		0x7B41848B8CC6CC0EULL,
		0x3077459DA30130B1ULL,
		0x82CCD93A579310ECULL,
		0x9D0574919F6838A1ULL,
		0xE3DEB06AB3702323ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC9107977F2EB9D50ULL,
		0xE326E7B2C591A732ULL,
		0x2564155DA14D16BDULL,
		0x41228E9F1403EA5FULL,
		0xCFE23073C5D130B1ULL,
		0xBAE63B6A5D4F4F79ULL,
		0x37241D01AF2ED3F4ULL,
		0xE4342E8851438B2EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCF04F23A76A717AULL,
		0x85EB17402DDB5E4AULL,
		0x7E8E8B856D421A66ULL,
		0x7D9CDE5D883C7BF7ULL,
		0xF66B8909B2C95DE6ULL,
		0x872D7AF0EACA5F6AULL,
		0x7267F4D53DB76B99ULL,
		0x569BF0829B29C8F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC202A544B812BD6ULL,
		0x5D3BD07297B648E7ULL,
		0xA6D589D8340AFC57ULL,
		0xC385B0418BC76E67ULL,
		0xD976A76A1307D2CAULL,
		0x33B8C0797284F00EULL,
		0xC4BC282C7177685BULL,
		0x8D983E05B619C238ULL
	}};
	sign = 0;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD72BEA2A16695CBCULL,
		0x6B0B8125207CAC7CULL,
		0x82547B96D72D62EDULL,
		0xE98F9A69805B13EBULL,
		0x93D41FE6AB6B4347ULL,
		0x184869A03F0A4602ULL,
		0x8DDCE52EFB5C6A5FULL,
		0xCA263D3DF8279F64ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D12701FE7CAAF44ULL,
		0x5784992E9EFF1D2FULL,
		0x70EE80C3CD055744ULL,
		0x29C93D8D876ABEA8ULL,
		0xC0A3943C3A17A5E2ULL,
		0xD67ADF8E506433F8ULL,
		0x1AF924CFA3A2BF7DULL,
		0x25A180072801EE2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA197A0A2E9EAD78ULL,
		0x1386E7F6817D8F4DULL,
		0x1165FAD30A280BA9ULL,
		0xBFC65CDBF8F05543ULL,
		0xD3308BAA71539D65ULL,
		0x41CD8A11EEA61209ULL,
		0x72E3C05F57B9AAE1ULL,
		0xA484BD36D025B138ULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x30CF782DD810474FULL,
		0xDFC5EBC98B65C13CULL,
		0x5A4E6982DAF46809ULL,
		0x69EC670F1DC6D5BAULL,
		0x14F49EAAD5529A3DULL,
		0x30CDDAF514C9A71CULL,
		0xBC7CAA5EC05B1E46ULL,
		0xBD51E9991C545AC4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6C9956363F11EFULL,
		0x9E7D6EAF786FEF6AULL,
		0xF2641DC174213760ULL,
		0x37BC46BC551219E6ULL,
		0x31630C2617AEB232ULL,
		0xD2FC3CA957859718ULL,
		0xF3EAC8096B6BA977ULL,
		0x4632CB0A7055D176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE662DED7A1D13560ULL,
		0x41487D1A12F5D1D1ULL,
		0x67EA4BC166D330A9ULL,
		0x32302052C8B4BBD3ULL,
		0xE3919284BDA3E80BULL,
		0x5DD19E4BBD441003ULL,
		0xC891E25554EF74CEULL,
		0x771F1E8EABFE894DULL
	}};
	sign = 0;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x42C0DDDC0C90CDDCULL,
		0xFCAA6C3B73F86237ULL,
		0xC1A0E4E1E98F0D9FULL,
		0x661A1E32D4C3EC09ULL,
		0x65E5A614A906E413ULL,
		0x3C81941CA3A8F048ULL,
		0x56EAF65169E09711ULL,
		0x6D9070FA1EC8E2A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5F0725790D1325ULL,
		0xA1B527BA97E73236ULL,
		0x9A5BC1A12D68641AULL,
		0x47A81F5FBE8BD72CULL,
		0x55B3E51C0323861BULL,
		0xEF2E862F19578584ULL,
		0xA74FC2755B10D9E1ULL,
		0x1C2BCD16BB05F96EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2461D6B69383BAB7ULL,
		0x5AF54480DC113001ULL,
		0x27452340BC26A985ULL,
		0x1E71FED3163814DDULL,
		0x1031C0F8A5E35DF8ULL,
		0x4D530DED8A516AC4ULL,
		0xAF9B33DC0ECFBD2FULL,
		0x5164A3E363C2E931ULL
	}};
	sign = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDC6EC36AD6FA73FAULL,
		0x3F84DC08DCEABD43ULL,
		0xA958A7786BEFA718ULL,
		0x3D6FDE8009C7D962ULL,
		0xA02D6D49C81A6DABULL,
		0x8FC98F3BB3E65611ULL,
		0x164388F241583B6EULL,
		0x1940A26270E3C9B3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE5F53870020682ULL,
		0x19D3C147CAF4CA67ULL,
		0xE89D1078F35DD19DULL,
		0xD1262636C66CFCE9ULL,
		0xE426F9CE8AA9E714ULL,
		0x60A6C7B96771F486ULL,
		0x26092064AD399EEFULL,
		0xE4B2C2E828DF829FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8188CE3266F86D78ULL,
		0x25B11AC111F5F2DCULL,
		0xC0BB96FF7891D57BULL,
		0x6C49B849435ADC78ULL,
		0xBC06737B3D708696ULL,
		0x2F22C7824C74618AULL,
		0xF03A688D941E9C7FULL,
		0x348DDF7A48044713ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x70F2404ECCE96A15ULL,
		0xFCB6FC8DE0C6D77EULL,
		0x56456EA73C04FA51ULL,
		0xFBEF48ED41516250ULL,
		0xB88EB4AD07F9C839ULL,
		0x56FDB35086AB4D2BULL,
		0x641B141621F756D5ULL,
		0x0EE80F548E5154B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97B15CB1E188C62EULL,
		0x1081EC0ED49665DCULL,
		0xA537A2F9B2A07724ULL,
		0x4B6CFB47F443181EULL,
		0x716E3F71A7DFA384ULL,
		0xE77A4EA5AE3D0610ULL,
		0x1C6821EE18434765ULL,
		0x8465E9F563F9961FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD940E39CEB60A3E7ULL,
		0xEC35107F0C3071A1ULL,
		0xB10DCBAD8964832DULL,
		0xB0824DA54D0E4A31ULL,
		0x4720753B601A24B5ULL,
		0x6F8364AAD86E471BULL,
		0x47B2F22809B40F6FULL,
		0x8A82255F2A57BE97ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1A8C817BA0C5E4CULL,
		0x27EAC328C4F4E6B1ULL,
		0x1300827229173AB0ULL,
		0x9C79F1E2D2179A67ULL,
		0xD51DA78F62E48326ULL,
		0x16846BC9D77CDDDFULL,
		0xD7EBE707390268C9ULL,
		0xEDCFCA855B1230CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2783A2EB31DA38EULL,
		0x719E01002CB0C1FDULL,
		0x85566A4F6087D6FDULL,
		0xE5ADF99AFA7C2F14ULL,
		0x2AD232FB0E016A24ULL,
		0xDB9DEB0404473042ULL,
		0x1B6DCD37539D229AULL,
		0xF70771430FCFB310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF308DE906EEBABEULL,
		0xB64CC228984424B3ULL,
		0x8DAA1822C88F63B2ULL,
		0xB6CBF847D79B6B52ULL,
		0xAA4B749454E31901ULL,
		0x3AE680C5D335AD9DULL,
		0xBC7E19CFE565462EULL,
		0xF6C859424B427DBEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x12D936F7134C5B57ULL,
		0xFDE5D13E9C9F35E9ULL,
		0x49FABB1F24CF099EULL,
		0xDFBDF9FF978393D6ULL,
		0xB24FB53E54C7B40EULL,
		0x2C4592C296A42D71ULL,
		0x8017AC9A5E2541ABULL,
		0xCFBEC986516DFFE7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9886A923938DCF7ULL,
		0xF6B707FE3522AAA2ULL,
		0x067B0A27815CB5C4ULL,
		0x7C7B48EDD38FCDB0ULL,
		0x647D2DDB044B3E7EULL,
		0x11EFC37740F81DEAULL,
		0xDB7770F6927678E2ULL,
		0x255A469D0C5FB6D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3950CC64DA137E60ULL,
		0x072EC940677C8B46ULL,
		0x437FB0F7A37253DAULL,
		0x6342B111C3F3C626ULL,
		0x4DD28763507C7590ULL,
		0x1A55CF4B55AC0F87ULL,
		0xA4A03BA3CBAEC8C9ULL,
		0xAA6482E9450E4914ULL
	}};
	sign = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x59EDFA30576F8031ULL,
		0x9EBF3A8EB0F0AB06ULL,
		0x62D5EEAA38CA8633ULL,
		0xD0EAB81F9D3D34B5ULL,
		0x1A0637BD8B1120B3ULL,
		0xC00D4BA1AFF9F444ULL,
		0x004FE2F505F08D66ULL,
		0x82D8FCA81FCBE1DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x635D33DF96F51446ULL,
		0x345E66CDDACB7779ULL,
		0xF643FFE32135ACEAULL,
		0x4B097699170506A7ULL,
		0x298D037CABA2B685ULL,
		0x4033647510AC46EFULL,
		0xB19289B427389D88ULL,
		0x160526788BA05DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF690C650C07A6BEBULL,
		0x6A60D3C0D625338CULL,
		0x6C91EEC71794D949ULL,
		0x85E1418686382E0DULL,
		0xF0793440DF6E6A2EULL,
		0x7FD9E72C9F4DAD54ULL,
		0x4EBD5940DEB7EFDEULL,
		0x6CD3D62F942B8428ULL
	}};
	sign = 0;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBB0429A9AAB6B7A1ULL,
		0xB2C3A915064CCC5EULL,
		0x92878AE501BD4134ULL,
		0x9EAA4CBA609A44C4ULL,
		0x94D4E486BAF2E47AULL,
		0xBE4E33C6860F4BEFULL,
		0x08B2B428955CC4C2ULL,
		0xCE816381CE7DC85DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B6DD5F40DDFE2F0ULL,
		0x6CC6B0D561C59D92ULL,
		0x08A45C95D472C1C7ULL,
		0x9D654F59AEE8ECDAULL,
		0xB2937B996CC7C3ECULL,
		0x72AB92600FC49D95ULL,
		0x09E5E2A67A0829D7ULL,
		0x9A190E07E843E1BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F9653B59CD6D4B1ULL,
		0x45FCF83FA4872ECCULL,
		0x89E32E4F2D4A7F6DULL,
		0x0144FD60B1B157EAULL,
		0xE24168ED4E2B208EULL,
		0x4BA2A166764AAE59ULL,
		0xFECCD1821B549AEBULL,
		0x34685579E639E6A1ULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA71548EE41216B47ULL,
		0xB7787218DBD61A36ULL,
		0xA10F7B7C691E09E1ULL,
		0x38EABCB7B9171E5BULL,
		0x812CC1A20439C5E1ULL,
		0xD05AB3BB3E5DEFAAULL,
		0x48E1885525601B8BULL,
		0xAD166B3F9061DCA3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89870567B7AD8629ULL,
		0x6E145B423CDD53DFULL,
		0x0D3BF94BAC797485ULL,
		0xDCB1524C9D511C51ULL,
		0x3A7116FFD65D764DULL,
		0x2C34D7B55B3B7460ULL,
		0xCFC0D21A63A80E09ULL,
		0xF08DB1DD2F2E2C3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D8E43868973E51EULL,
		0x496416D69EF8C657ULL,
		0x93D38230BCA4955CULL,
		0x5C396A6B1BC6020AULL,
		0x46BBAAA22DDC4F93ULL,
		0xA425DC05E3227B4AULL,
		0x7920B63AC1B80D82ULL,
		0xBC88B9626133B067ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x652D04113C81FB33ULL,
		0x4E0A8D0B5FEB339FULL,
		0xE2CF38073EBFA0EFULL,
		0x4BD40AE4C3A14586ULL,
		0x617AFE3CFFCD32C0ULL,
		0x01756343D2B9563CULL,
		0x503905C29F18FDF4ULL,
		0xB7FAB0AFD78E4078ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B48D83A40975728ULL,
		0xB1E702FAC90537D2ULL,
		0x5BAE9336AC1BCDF7ULL,
		0x5B9A4BAABE5299AAULL,
		0x6FE7515136BADF87ULL,
		0x890FDD7B1D0345B7ULL,
		0x0C24CCF809852A4EULL,
		0xB9D243ECA3D721E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49E42BD6FBEAA40BULL,
		0x9C238A1096E5FBCDULL,
		0x8720A4D092A3D2F7ULL,
		0xF039BF3A054EABDCULL,
		0xF193ACEBC9125338ULL,
		0x786585C8B5B61084ULL,
		0x441438CA9593D3A5ULL,
		0xFE286CC333B71E8FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x08A4199B747F5C26ULL,
		0x3C0E941CEB558C60ULL,
		0x073F542787B4D40AULL,
		0xE9B245F344F8B525ULL,
		0x201FCDC1B4B87375ULL,
		0xAB169C4F57EBF171ULL,
		0xAB55EBC19736725CULL,
		0x6E80BA5532B9CA04ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FDC0A2A928CD3C5ULL,
		0xAC28ECB5D44D86FFULL,
		0xA1BC6FB70C211C81ULL,
		0x166986A36F95D6B8ULL,
		0x93A1613243015208ULL,
		0x0E42BBE5D2CF1615ULL,
		0x1B020E697EC2F4D0ULL,
		0x015EE0F8E612E8E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8C80F70E1F28861ULL,
		0x8FE5A76717080560ULL,
		0x6582E4707B93B788ULL,
		0xD348BF4FD562DE6CULL,
		0x8C7E6C8F71B7216DULL,
		0x9CD3E069851CDB5BULL,
		0x9053DD5818737D8CULL,
		0x6D21D95C4CA6E124ULL
	}};
	sign = 0;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x22C22014B14A2B8AULL,
		0x65E7242029BDE4A3ULL,
		0x53233E8FFEF0F25BULL,
		0xC72A2B2D9AE5DC7FULL,
		0x74DED3B4D17739AEULL,
		0xF18EBE9E0C3DA455ULL,
		0x325D8CD39AB0863FULL,
		0x91B5A6E557A4C5BEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE2F727AD9AC45FEULL,
		0xF19FBC8BE2564F74ULL,
		0x884BD3C94E095B14ULL,
		0x45018B59A72A0E4EULL,
		0x5363CFFDEB04171FULL,
		0xD1A267E37E17D4E8ULL,
		0xD26B22AA95AE28A2ULL,
		0x96E8A969FB95F487ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2492AD99D79DE58CULL,
		0x744767944767952EULL,
		0xCAD76AC6B0E79746ULL,
		0x82289FD3F3BBCE30ULL,
		0x217B03B6E673228FULL,
		0x1FEC56BA8E25CF6DULL,
		0x5FF26A2905025D9DULL,
		0xFACCFD7B5C0ED136ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF348407A8001F94EULL,
		0x939B67F7FC30DA55ULL,
		0x6B5DFEF0A5A345DEULL,
		0xAE37F797752CB999ULL,
		0xB1998DEA311DCBC0ULL,
		0x5694735CB41C8A61ULL,
		0x3D12EF250DFA5204ULL,
		0x5E9FBA0E14F18136ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC55461A567DF3B04ULL,
		0xCC071E22FBD9F8D9ULL,
		0xD81C58FA0FBAA8FDULL,
		0x3153B934AE327E4AULL,
		0xDF1D2F3995E9A145ULL,
		0x6634E89315E2DF27ULL,
		0xEE089CC94A2B8EB4ULL,
		0x5496580AB046A14EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DF3DED51822BE4AULL,
		0xC79449D50056E17CULL,
		0x9341A5F695E89CE0ULL,
		0x7CE43E62C6FA3B4EULL,
		0xD27C5EB09B342A7BULL,
		0xF05F8AC99E39AB39ULL,
		0x4F0A525BC3CEC34FULL,
		0x0A09620364AADFE7ULL
	}};
	sign = 0;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC442D47587ECABC7ULL,
		0x9D0936945BD90A64ULL,
		0xBD2E25FC9A5ABFCDULL,
		0xA8B6179367F55A6AULL,
		0x44F36295573311D7ULL,
		0x4632354767DD5EA1ULL,
		0x560384198DABCCC9ULL,
		0xB54849C68D9D663BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67F673C03F029D3ULL,
		0xE74AF474933ACD67ULL,
		0xA318A36E922A35AEULL,
		0xA3CAC8A7AD179B3EULL,
		0x5358DE131C7AE383ULL,
		0xE690B005908FFAFEULL,
		0x5872D911C3963746ULL,
		0xABF42AFB1D1336DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDC36D3983FC81F4ULL,
		0xB5BE421FC89E3CFCULL,
		0x1A15828E08308A1EULL,
		0x04EB4EEBBADDBF2CULL,
		0xF19A84823AB82E54ULL,
		0x5FA18541D74D63A2ULL,
		0xFD90AB07CA159582ULL,
		0x09541ECB708A2F5CULL
	}};
	sign = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x15331213B7430B17ULL,
		0x4C7CEF1606FA0A7EULL,
		0xBDC4FED92585A5A7ULL,
		0x2D9CAC84985BA656ULL,
		0x690A2B5173EE9B1BULL,
		0x5A130F1EC6E6F88FULL,
		0x577AA533F3998695ULL,
		0x3CED93AD83A253A2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D448354A9D5B43ULL,
		0x0D404448E7801233ULL,
		0x13CAA3985ADA841CULL,
		0x1A085D23323B24E5ULL,
		0xF61C4CDBD44C7B57ULL,
		0xA4E553679A2CEDEDULL,
		0xDDB91B73AD402549ULL,
		0x9F53FD3DAB54964CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB25EC9DE6CA5AFD4ULL,
		0x3F3CAACD1F79F84AULL,
		0xA9FA5B40CAAB218BULL,
		0x13944F6166208171ULL,
		0x72EDDE759FA21FC4ULL,
		0xB52DBBB72CBA0AA1ULL,
		0x79C189C04659614BULL,
		0x9D99966FD84DBD55ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5327DAB2F003FAC1ULL,
		0x536B8BC4366BE481ULL,
		0xA3DC378652E6E6D6ULL,
		0xF155B523AC45AEF6ULL,
		0x27D1A697E75E91E5ULL,
		0x7B273AEC0793FD2DULL,
		0xD8F44CE5B8B0CAF6ULL,
		0x74CE8F9BFEC6C61CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x583132006FF851AFULL,
		0x87E4667EF9620811ULL,
		0xE1C4BF3BAC06A1CBULL,
		0xD90FE449A95E2DC9ULL,
		0xA1088CEDA879F12FULL,
		0x5A9B88FE0E0B3862ULL,
		0xB8DE3AD852620C03ULL,
		0x4AC7BF4EA5441108ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAF6A8B2800BA912ULL,
		0xCB8725453D09DC6FULL,
		0xC217784AA6E0450AULL,
		0x1845D0DA02E7812CULL,
		0x86C919AA3EE4A0B6ULL,
		0x208BB1EDF988C4CAULL,
		0x2016120D664EBEF3ULL,
		0x2A06D04D5982B514ULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x122BAD52DE47746FULL,
		0x08325760629150A0ULL,
		0xEF97D4D2E418B226ULL,
		0xDACF6FC3D7040B55ULL,
		0xA068EBED3839ADD8ULL,
		0xF879CA568B54D79EULL,
		0x930A5CDC1A8757A8ULL,
		0xEF4787E085AD37D4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CDE29EF50F00652ULL,
		0x3EDF64AB4C209F5BULL,
		0x9557A72671795789ULL,
		0x1DA358CC0DD0475CULL,
		0x1EB4784B4C2F88C2ULL,
		0x579F5DB10CCB3EBFULL,
		0xC974728D6B357C1AULL,
		0x3497309087B6DE84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA54D83638D576E1DULL,
		0xC952F2B51670B144ULL,
		0x5A402DAC729F5A9CULL,
		0xBD2C16F7C933C3F9ULL,
		0x81B473A1EC0A2516ULL,
		0xA0DA6CA57E8998DFULL,
		0xC995EA4EAF51DB8EULL,
		0xBAB0574FFDF6594FULL
	}};
	sign = 0;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x988B3E2396FA4400ULL,
		0x8830B73B008559DEULL,
		0xF4E4F8162A2F887DULL,
		0x9D46B6A428B7ED79ULL,
		0xA17D5682DF42140CULL,
		0xD1EF74D4E4681A52ULL,
		0x274CF45F8EB37E2EULL,
		0xCF93CC0099590142ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x18141E04FA9BB6EBULL,
		0x3FCE8B2BA4FD9BB7ULL,
		0x2CA33AAB4B651406ULL,
		0x387F157DEBE972A7ULL,
		0x82E84972593AC5DAULL,
		0xC979214918610E41ULL,
		0x4489A1BBE89C92D0ULL,
		0xC4420B694F79E129ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8077201E9C5E8D15ULL,
		0x48622C0F5B87BE27ULL,
		0xC841BD6ADECA7477ULL,
		0x64C7A1263CCE7AD2ULL,
		0x1E950D1086074E32ULL,
		0x0876538BCC070C11ULL,
		0xE2C352A3A616EB5EULL,
		0x0B51C09749DF2018ULL
	}};
	sign = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEBFDD94CE83F2F69ULL,
		0x0DB99CE4A4F88B45ULL,
		0x048DBF135E6C7CACULL,
		0x3B1EFBC32D5D1A13ULL,
		0x5A24AAA31C4D2694ULL,
		0xF4966AE531FAD7C4ULL,
		0x9FC65A74885E09B2ULL,
		0xB2DF6937E67A00F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x96EA9F1CF2422B24ULL,
		0x456B80DCA16CEBA9ULL,
		0x7D497944E7D8EC0FULL,
		0xA70B90DA4BB84287ULL,
		0xD70546A587687C01ULL,
		0x8282073A0CD4173CULL,
		0x9E22905AD9A1BA21ULL,
		0xA69642B7C0060950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55133A2FF5FD0445ULL,
		0xC84E1C08038B9F9CULL,
		0x874445CE7693909CULL,
		0x94136AE8E1A4D78BULL,
		0x831F63FD94E4AA92ULL,
		0x721463AB2526C087ULL,
		0x01A3CA19AEBC4F91ULL,
		0x0C4926802673F7A1ULL
	}};
	sign = 0;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x04CBA751342C5256ULL,
		0x011D9F02DAFE3882ULL,
		0x066BF7FA3C36D490ULL,
		0x5E53D7511C855746ULL,
		0x00A93A0181A11345ULL,
		0x5049DD1FCCB49E3FULL,
		0xFF2563B92EF10748ULL,
		0xAC2DE75DAE3FF001ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CDCFC2513F9EE8ULL,
		0x6215ED65764B5227ULL,
		0x95754F9EF862E069ULL,
		0xED3E6AE198E668A0ULL,
		0x83A078F072217A7EULL,
		0xA0422F073074639EULL,
		0xE7F6990A7E1B3598ULL,
		0x2529D60DDB12E0B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BFDD78EE2ECB36EULL,
		0x9F07B19D64B2E65AULL,
		0x70F6A85B43D3F426ULL,
		0x71156C6F839EEEA5ULL,
		0x7D08C1110F7F98C6ULL,
		0xB007AE189C403AA0ULL,
		0x172ECAAEB0D5D1AFULL,
		0x8704114FD32D0F4CULL
	}};
	sign = 0;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x69DD13D0E03D8BE2ULL,
		0x0561D319BDBE8AD8ULL,
		0x22AA3AE9B5E359F8ULL,
		0x27099F353E914F1BULL,
		0x943BBBA542C552F0ULL,
		0x77905C20D5870954ULL,
		0x0F020FAE574DD58AULL,
		0x47E5A526A6E841B2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE053526C9950887BULL,
		0x791504DDC306CCD4ULL,
		0xA562956445BF25C8ULL,
		0x26C0BE745C65612CULL,
		0x3B81FA4A1A46FE86ULL,
		0x282F052BA1329DCEULL,
		0x49002FDDF76A0B63ULL,
		0x2DC406A87E3FC661ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8989C16446ED0367ULL,
		0x8C4CCE3BFAB7BE03ULL,
		0x7D47A5857024342FULL,
		0x0048E0C0E22BEDEEULL,
		0x58B9C15B287E546AULL,
		0x4F6156F534546B86ULL,
		0xC601DFD05FE3CA27ULL,
		0x1A219E7E28A87B50ULL
	}};
	sign = 0;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82961E5154A176FCULL,
		0x46E550DE3BD60991ULL,
		0x957CF35872FB95BAULL,
		0xBAD855D9021023DEULL,
		0xC5EBF1DB45A924FAULL,
		0xED4DB2612C908B35ULL,
		0x3B3D65EE3CF97737ULL,
		0x2CE25620BE2E0356ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9FEED007CE1E9ADULL,
		0x9DA8E8BFCB379FEFULL,
		0xB91A5995021B5F11ULL,
		0x62FB39CB13BC2A93ULL,
		0xC0F5C86BF88C6B68ULL,
		0x8EE634615BEE8B7EULL,
		0x2F1ABFEC02DFEFDAULL,
		0x42BB3376CEB6C223ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8973150D7BF8D4FULL,
		0xA93C681E709E69A1ULL,
		0xDC6299C370E036A8ULL,
		0x57DD1C0DEE53F94AULL,
		0x04F6296F4D1CB992ULL,
		0x5E677DFFD0A1FFB7ULL,
		0x0C22A6023A19875DULL,
		0xEA2722A9EF774133ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE5FF1842F7447505ULL,
		0xAEDF4B53B3567965ULL,
		0x3F23DCEAE23E561BULL,
		0x0E60ABE1CBBA4C46ULL,
		0xB98B09A8D81E58D5ULL,
		0x0BC23852E180BADEULL,
		0x28F9CFEA05A64379ULL,
		0x8218D4426AF5327AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D11FF7AF5B63B7ULL,
		0x84CE45CA178A4BD3ULL,
		0xA94C71511944D246ULL,
		0xD0A10BC10F592F93ULL,
		0x9B2E421CA858C19BULL,
		0x57BF9CC388AFEFDFULL,
		0x9FE43A410C14B06BULL,
		0xC80291F46F0B6F24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x102DF84B47E9114EULL,
		0x2A1105899BCC2D92ULL,
		0x95D76B99C8F983D5ULL,
		0x3DBFA020BC611CB2ULL,
		0x1E5CC78C2FC59739ULL,
		0xB4029B8F58D0CAFFULL,
		0x891595A8F991930DULL,
		0xBA16424DFBE9C355ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x01BB0C0BC309EDC3ULL,
		0xE13C3777626B9DBBULL,
		0x5FEE59B1302F0D09ULL,
		0x539EB377EA1CAB6CULL,
		0x87E2192AD57F5634ULL,
		0x5C95690908B61C20ULL,
		0xF3A21693EC69D697ULL,
		0x43F068529BDFDA80ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D6290C446CFB32ULL,
		0x57DE82A35BE32E69ULL,
		0xB3F14F5E8F9DABAFULL,
		0x614C5B8B6DE6A61BULL,
		0xAC541B3D195EA809ULL,
		0x1916AE88FB649B00ULL,
		0xAC820528524B4A03ULL,
		0x5D81C65354B5D800ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BE4E2FF7E9CF291ULL,
		0x895DB4D406886F51ULL,
		0xABFD0A52A091615AULL,
		0xF25257EC7C360550ULL,
		0xDB8DFDEDBC20AE2AULL,
		0x437EBA800D51811FULL,
		0x4720116B9A1E8C94ULL,
		0xE66EA1FF472A0280ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x60674311F67C5217ULL,
		0x2936B99DE28B7264ULL,
		0x6744DD6239F67771ULL,
		0x060C5EA7B5F24473ULL,
		0xDB483DEF8DC11EF1ULL,
		0x880E72E82445FB9CULL,
		0x5ED821062F5F3CB5ULL,
		0xCDA9F5636E86DDCFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x357847E4BA307A60ULL,
		0x12CAD0A00F9DEFA9ULL,
		0xE1D15C6733CCED4BULL,
		0x19F3BDFCBEB19D35ULL,
		0x7F8567D0960F9196ULL,
		0x677069D9061B82CDULL,
		0x314F499DAFB354E2ULL,
		0xF114F1AEF90C6820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AEEFB2D3C4BD7B7ULL,
		0x166BE8FDD2ED82BBULL,
		0x857380FB06298A26ULL,
		0xEC18A0AAF740A73DULL,
		0x5BC2D61EF7B18D5AULL,
		0x209E090F1E2A78CFULL,
		0x2D88D7687FABE7D3ULL,
		0xDC9503B4757A75AFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98AF2AE0E56B9BBBULL,
		0xB542E376FBCFAD63ULL,
		0xBBD904E48A6E08B4ULL,
		0xEECA9633B5EF9081ULL,
		0xDE898045778A08B0ULL,
		0xA426CE386FCF9938ULL,
		0x68CB9F63F15F0BA8ULL,
		0x0D399A9E9CC907D7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F1CE47CAC55C98ULL,
		0xC302967D5F1AB496ULL,
		0x6919F9802FED6F92ULL,
		0x1092B86F02322B11ULL,
		0xD69533D89ACF153BULL,
		0x57F60AABED6F5712ULL,
		0xB4171653C6E38A2FULL,
		0xCA20AFB545915D71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2BD5C991AA63F23ULL,
		0xF2404CF99CB4F8CCULL,
		0x52BF0B645A809921ULL,
		0xDE37DDC4B3BD6570ULL,
		0x07F44C6CDCBAF375ULL,
		0x4C30C38C82604226ULL,
		0xB4B489102A7B8179ULL,
		0x4318EAE95737AA65ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2804163C508E7675ULL,
		0x7FF79B33B7C8D2C4ULL,
		0xBE3DF9813706765BULL,
		0x2554A5BE8B42EE31ULL,
		0x256D9C17F7F22AD3ULL,
		0x1A5C6E19D751A624ULL,
		0x3D63E8A4D063FD92ULL,
		0xE296EE9EAF672F68ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x560AF9AA8CA724EDULL,
		0xD732BE4F695288D9ULL,
		0x09E45B3D6BBAF074ULL,
		0xC6476E4AEA496BB3ULL,
		0xF0ED0BDD50D487A6ULL,
		0x7F0599F45619AA0BULL,
		0x599721CE4D50114EULL,
		0xFDBA713AE99D6869ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1F91C91C3E75188ULL,
		0xA8C4DCE44E7649EAULL,
		0xB4599E43CB4B85E6ULL,
		0x5F0D3773A0F9827EULL,
		0x3480903AA71DA32CULL,
		0x9B56D4258137FC18ULL,
		0xE3CCC6D68313EC43ULL,
		0xE4DC7D63C5C9C6FEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFA27A78063B4E904ULL,
		0x61471058CF4E152FULL,
		0x786D55556AA81153ULL,
		0x9A17AB2B47C177B1ULL,
		0xE5502FD9F2F11D68ULL,
		0x6743E032848E4031ULL,
		0x517C8D7FB80B804FULL,
		0x8D963F7B5F211745ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BE97C53185F0765ULL,
		0x64B9021B5FA5281CULL,
		0x934845487A8665CFULL,
		0x4EFADCAED27EA348ULL,
		0x0D66A83281ECB4F3ULL,
		0xFE050F7655FB7D65ULL,
		0xB35469CA395DDBC2ULL,
		0x5AEE8563A6781A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE3E2B2D4B55E19FULL,
		0xFC8E0E3D6FA8ED13ULL,
		0xE525100CF021AB83ULL,
		0x4B1CCE7C7542D468ULL,
		0xD7E987A771046875ULL,
		0x693ED0BC2E92C2CCULL,
		0x9E2823B57EADA48CULL,
		0x32A7BA17B8A8FD41ULL
	}};
	sign = 0;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x45EC8BA8A40AC69CULL,
		0xF0EBB4E353BF2895ULL,
		0x70F232D39DA0C5DEULL,
		0xA5B97507DAAD9D7CULL,
		0x5CF379F8EB818D5FULL,
		0x6A1D3CA66FCC22C0ULL,
		0x762427295543DD84ULL,
		0x44426299EA5C08DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC542B6FF58727259ULL,
		0x7B8BBA9E65F2DE29ULL,
		0x1FBE49FA7B246CECULL,
		0xF53C5DC8D2CB0666ULL,
		0x4C1B7DFA33C8C5D9ULL,
		0x98E9C7A132830C93ULL,
		0xDEDDD43FAB47FE28ULL,
		0x688AE2C0903ADC77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80A9D4A94B985443ULL,
		0x755FFA44EDCC4A6BULL,
		0x5133E8D9227C58F2ULL,
		0xB07D173F07E29716ULL,
		0x10D7FBFEB7B8C785ULL,
		0xD13375053D49162DULL,
		0x974652E9A9FBDF5BULL,
		0xDBB77FD95A212C62ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1D5830D1C22B069DULL,
		0xE3DD9F1B52A2A0F1ULL,
		0x090DD425F4A50BBAULL,
		0x545CEF9E411EDA4CULL,
		0x8DC6E162A1E5A346ULL,
		0x5387C7E4C9CEFCDFULL,
		0x43EC53CBAD18E27DULL,
		0x9D15A989931299E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EC520251ED5A338ULL,
		0x49D87924FFE8E371ULL,
		0xE88202DC86790CA0ULL,
		0xDD56F8AFE277F322ULL,
		0x41E31BF1A81D372FULL,
		0x02778498E56DA83EULL,
		0x2A24D9E1132610DDULL,
		0xF22BADD750FA90A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE9310ACA3556365ULL,
		0x9A0525F652B9BD7FULL,
		0x208BD1496E2BFF1AULL,
		0x7705F6EE5EA6E729ULL,
		0x4BE3C570F9C86C16ULL,
		0x5110434BE46154A1ULL,
		0x19C779EA99F2D1A0ULL,
		0xAAE9FBB24218093BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA334FCDDF525715FULL,
		0x8DA4E4A5FD4BB2B9ULL,
		0xEE862D6E43DE9E37ULL,
		0x22104DAB5934B4A9ULL,
		0x4E823A9883CD6D9DULL,
		0xCDA47DB2799F0DC4ULL,
		0x83060F7E6256F91AULL,
		0x9970BC3DFE74ED6FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC0A091393EFE69BULL,
		0x804FF509FA02798BULL,
		0xBE450EAA3994B6FFULL,
		0x8FC87183113752E3ULL,
		0x8B9418AA9B4C22F0ULL,
		0xCE4AC94543060F27ULL,
		0x374420AA54C42172ULL,
		0xD5A01773BF4BB312ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD72AF3CA61358AC4ULL,
		0x0D54EF9C0349392DULL,
		0x30411EC40A49E738ULL,
		0x9247DC2847FD61C6ULL,
		0xC2EE21EDE8814AACULL,
		0xFF59B46D3698FE9CULL,
		0x4BC1EED40D92D7A7ULL,
		0xC3D0A4CA3F293A5DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6EB1607887BC2016ULL,
		0xD417DB468748DCDEULL,
		0x7530F0016D01392CULL,
		0xFF0B25A10B80587CULL,
		0x3152F9AD15C19058ULL,
		0x462BAFE68D2D156AULL,
		0x396AD42F9C667E75ULL,
		0x6BBB45E28E3421CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x192D1380C3C9C55FULL,
		0x250EC6740A77D415ULL,
		0x1AC0595E8DBFB206ULL,
		0x0C1B40BD6AB0F17AULL,
		0x85DE99DDFC933FB8ULL,
		0x87B9348F7685891DULL,
		0x279C9D600933E744ULL,
		0x25272EB70F2A3812ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55844CF7C3F25AB7ULL,
		0xAF0914D27CD108C9ULL,
		0x5A7096A2DF418726ULL,
		0xF2EFE4E3A0CF6702ULL,
		0xAB745FCF192E50A0ULL,
		0xBE727B5716A78C4CULL,
		0x11CE36CF93329730ULL,
		0x4694172B7F09E9BDULL
	}};
	sign = 0;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x05899DD60CC15286ULL,
		0x8B48B17AF9CD0DC9ULL,
		0x78A003920D09F0FEULL,
		0x93E7E10967D4802AULL,
		0x496E2207C920A9A5ULL,
		0xA8EF29BFE1A5A8E7ULL,
		0x3684694C706A5DD1ULL,
		0xE58E46827DA6B70FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x48CC4D56E84BB4B1ULL,
		0x038983EF075FB025ULL,
		0xA50ABB50471E2F2EULL,
		0x793709A06CAECEC9ULL,
		0x6216107A084FC508ULL,
		0x4F574A05A66B9774ULL,
		0x93B4BF0AC818B8F7ULL,
		0x43DF037E51771C41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCBD507F24759DD5ULL,
		0x87BF2D8BF26D5DA3ULL,
		0xD3954841C5EBC1D0ULL,
		0x1AB0D768FB25B160ULL,
		0xE758118DC0D0E49DULL,
		0x5997DFBA3B3A1172ULL,
		0xA2CFAA41A851A4DAULL,
		0xA1AF43042C2F9ACDULL
	}};
	sign = 0;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9A09834A51DA88B1ULL,
		0xFB121D0076D95A91ULL,
		0xDD20F9CACD9A028FULL,
		0x5E31CE51EEBFFA0BULL,
		0xF605DE07888A800EULL,
		0x25D1554A1F8972D0ULL,
		0x9EB39D5853685219ULL,
		0x31B4920DA0709458ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D37AB5524B0C5F6ULL,
		0xCA36D2AAB31571F3ULL,
		0x454086B438E0E2C4ULL,
		0xFBD5EF9F30BC8C9DULL,
		0x69C5624B2D22FB0CULL,
		0xAC665973DFB0807AULL,
		0x2018DEAEA6468A08ULL,
		0x043DDEE7DDB38FDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CD1D7F52D29C2BBULL,
		0x30DB4A55C3C3E89EULL,
		0x97E0731694B91FCBULL,
		0x625BDEB2BE036D6EULL,
		0x8C407BBC5B678501ULL,
		0x796AFBD63FD8F256ULL,
		0x7E9ABEA9AD21C810ULL,
		0x2D76B325C2BD047DULL
	}};
	sign = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93ACE285FBDD011CULL,
		0x4909827EE291C435ULL,
		0xD681BFA9BCB56858ULL,
		0x0A9D3F7C31EEB4ABULL,
		0x8C3BAC3535762BBDULL,
		0x8CD8F4E70D32264DULL,
		0x982A1D14C79B9425ULL,
		0x8C927E49307000CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26D7112A5096B9FULL,
		0xF5C57CF4D2CCA2A2ULL,
		0x9851579BD886FE39ULL,
		0x53CF3704E47CBB11ULL,
		0xADBA87D4494D09F1ULL,
		0xE4673E35866F8090ULL,
		0xD30B694F8AAD55E5ULL,
		0x79300FF806FA501DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC13F717356D3957DULL,
		0x5344058A0FC52192ULL,
		0x3E30680DE42E6A1EULL,
		0xB6CE08774D71F99AULL,
		0xDE812460EC2921CBULL,
		0xA871B6B186C2A5BCULL,
		0xC51EB3C53CEE3E3FULL,
		0x13626E512975B0ACULL
	}};
	sign = 0;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x89513AADD645E388ULL,
		0x2FD3918F16FA212CULL,
		0xA7E573CC73F94041ULL,
		0x522DA2AC4C9C727BULL,
		0xEA1274A33D3F7A37ULL,
		0x82569FA7FCC56D3DULL,
		0xD6EFF1AD70EAB400ULL,
		0xC685250A2EB9A6B0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74905F224BA788A5ULL,
		0xB1CB90EEFDCA3F4DULL,
		0xD64FC88C8E663E6DULL,
		0x29F2097B3E725B58ULL,
		0xB10114F10F48A4B5ULL,
		0xB29CF801F6AF6241ULL,
		0x60389EA221D68A4FULL,
		0xE0E9293DCB6BF450ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14C0DB8B8A9E5AE3ULL,
		0x7E0800A0192FE1DFULL,
		0xD195AB3FE59301D3ULL,
		0x283B99310E2A1722ULL,
		0x39115FB22DF6D582ULL,
		0xCFB9A7A606160AFCULL,
		0x76B7530B4F1429B0ULL,
		0xE59BFBCC634DB260ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3D5C85C76A0ED467ULL,
		0x03E0C6C49E7A2FF2ULL,
		0x6DCD5077CE0FF9FDULL,
		0x95A75B1748AF7315ULL,
		0xABD83F7BE634A998ULL,
		0x570238541DDB991DULL,
		0x7FBFD6B7B258FAEDULL,
		0x598882064DFCC6A9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B8A8FFCE3BDCFEULL,
		0x2A80879F41EF6CA5ULL,
		0x180E7C2232D62C76ULL,
		0x0E6D4A4B96698E3BULL,
		0x59D44927EB03A812ULL,
		0x0CA6D0405BCFA5D7ULL,
		0x6B53887251D1D572ULL,
		0xE4D8D844043D03F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76A3DCC79BD2F769ULL,
		0xD9603F255C8AC34CULL,
		0x55BED4559B39CD86ULL,
		0x873A10CBB245E4DAULL,
		0x5203F653FB310186ULL,
		0x4A5B6813C20BF346ULL,
		0x146C4E456087257BULL,
		0x74AFA9C249BFC2B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0E947E77243CF627ULL,
		0xE46536E92150EF65ULL,
		0x7E2FD6474F8D1FF2ULL,
		0xF7596A956B510829ULL,
		0xB185EBA0A747AEB3ULL,
		0x9B53F748B4F9845AULL,
		0xB0E10E6933C2F9C4ULL,
		0xFD800DDC83849A0FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB7481D2B7336A23ULL,
		0x280945706BF62FD9ULL,
		0xEF32702CFCF5037DULL,
		0x6644A541E479D786ULL,
		0x4793935E60AABACDULL,
		0xF7C0654120B4D4F5ULL,
		0x3C7FA0C7BECC6A7EULL,
		0x0F58514F64852136ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x131FFCA46D098C04ULL,
		0xBC5BF178B55ABF8BULL,
		0x8EFD661A52981C75ULL,
		0x9114C55386D730A2ULL,
		0x69F25842469CF3E6ULL,
		0xA39392079444AF65ULL,
		0x74616DA174F68F45ULL,
		0xEE27BC8D1EFF78D9ULL
	}};
	sign = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x94B1A4954D7D9FBEULL,
		0x77D3FFF8D3CCBFABULL,
		0xC70B09F3E6DF21A1ULL,
		0x54C34D7117A3A66EULL,
		0xDBF246242FA30617ULL,
		0xB1234F04BF2997ADULL,
		0x49B84CA7300803DBULL,
		0xF97F3DDD95213F64ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E43FEC56BFF2B7BULL,
		0x06DA09DC0306E12FULL,
		0x63EB8AC862373B3FULL,
		0xDEE1834E2829E156ULL,
		0x1C1B2B9010C6EE0AULL,
		0xD84B58BD7C830C14ULL,
		0xC05928ED1EC5D86AULL,
		0xCBF8CE2C774F2E50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x866DA5CFE17E7443ULL,
		0x70F9F61CD0C5DE7CULL,
		0x631F7F2B84A7E662ULL,
		0x75E1CA22EF79C518ULL,
		0xBFD71A941EDC180CULL,
		0xD8D7F64742A68B99ULL,
		0x895F23BA11422B70ULL,
		0x2D866FB11DD21113ULL
	}};
	sign = 0;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x43B8C1AC3BEC3AC4ULL,
		0x81C1F7F78BBA52A9ULL,
		0xE20028361B413FC5ULL,
		0x0AEBAAB421A90FDCULL,
		0xC39CDE3953F9F401ULL,
		0xC075EE36751BBEFDULL,
		0xAC1F39B801CFA8DDULL,
		0xB67DECE2C318AD21ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BC9152E201917EULL,
		0xEC1A2FE5A9168CC4ULL,
		0x5D620B35A7D68A38ULL,
		0xAF7C8456CC4866A4ULL,
		0x8CFA45860742811EULL,
		0xEBCD2984D041A756ULL,
		0x7F05952B91CBE673ULL,
		0x6054397A127F47A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAFC305959EAA946ULL,
		0x95A7C811E2A3C5E4ULL,
		0x849E1D00736AB58CULL,
		0x5B6F265D5560A938ULL,
		0x36A298B34CB772E2ULL,
		0xD4A8C4B1A4DA17A7ULL,
		0x2D19A48C7003C269ULL,
		0x5629B368B0996578ULL
	}};
	sign = 0;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x685B494067032B1BULL,
		0xE8E4356D2A6BB05FULL,
		0x13EED5861617F353ULL,
		0xB6C190DB0E630ABEULL,
		0x3E612134733FD5D1ULL,
		0x840C417A9033E708ULL,
		0xCB5DD292143D684EULL,
		0x25825E00D8153897ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C8D2C9CCD4FABDDULL,
		0xEA6673C17D875872ULL,
		0x15591D4D72E0F263ULL,
		0x5A97D1D84F8662F8ULL,
		0xDA5707264DB2B9D1ULL,
		0xC5C38839BF1D76B4ULL,
		0x6F9F7A16C85197FEULL,
		0x7EBC9775DA812E46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBCE1CA399B37F3EULL,
		0xFE7DC1ABACE457ECULL,
		0xFE95B838A33700EFULL,
		0x5C29BF02BEDCA7C5ULL,
		0x640A1A0E258D1C00ULL,
		0xBE48B940D1167053ULL,
		0x5BBE587B4BEBD04FULL,
		0xA6C5C68AFD940A51ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAC5DD8F81797147BULL,
		0x67B01945DD690F51ULL,
		0x96DF0651ADDD8230ULL,
		0x8624E9D0CEE94E7CULL,
		0x7C9AA87476847E03ULL,
		0xEB2D4794E55A7B61ULL,
		0x7A3FF780145ED8B9ULL,
		0x588977C262AEFFDFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE7F7D919448E3D2ULL,
		0x9CB977B90A5CD688ULL,
		0x79BB9F2BB90CCADBULL,
		0xF06FF7EA985CDAA7ULL,
		0xFB76054549FB55DDULL,
		0x980A18A8A14BEB3DULL,
		0xF37E187785CB1A22ULL,
		0x2E1535F29BF5BFFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDDE5B66834E30A9ULL,
		0xCAF6A18CD30C38C8ULL,
		0x1D236725F4D0B754ULL,
		0x95B4F1E6368C73D5ULL,
		0x8124A32F2C892825ULL,
		0x53232EEC440E9023ULL,
		0x86C1DF088E93BE97ULL,
		0x2A7441CFC6B93FE4ULL
	}};
	sign = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9EB17D57B089E42EULL,
		0xDB82AF32D774DF1CULL,
		0x7CDA498FB9AD5B93ULL,
		0x9DCE4F4A4D3E9BC9ULL,
		0xA64CD335EF87467FULL,
		0x9F5C529862C6F649ULL,
		0x733E18793C41F6A2ULL,
		0x24442FEB6C5D5D96ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB3C3D015FA96C8EULL,
		0xF4786753AB82A09EULL,
		0x36841DABD4BD408CULL,
		0x0011D4859F0F79DEULL,
		0xF9BA44EC6AD71A0AULL,
		0x03671038E4345955ULL,
		0x45305814C806234DULL,
		0xF45537323590195CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB375405650E077A0ULL,
		0xE70A47DF2BF23E7DULL,
		0x46562BE3E4F01B06ULL,
		0x9DBC7AC4AE2F21EBULL,
		0xAC928E4984B02C75ULL,
		0x9BF5425F7E929CF3ULL,
		0x2E0DC064743BD355ULL,
		0x2FEEF8B936CD443AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEF34654FEBD25B6DULL,
		0x5C7DD8964A3CC86BULL,
		0x9C6329459EC47470ULL,
		0x534F9C020B629108ULL,
		0xED8E89B89D70A905ULL,
		0x5CA72C347238F29FULL,
		0x04AA10970B84D521ULL,
		0x4CDB47C0F13140C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75A7CE3A8160ED9ULL,
		0xB95BBCA042187C43ULL,
		0xC942CE805ED93537ULL,
		0xDB14C886610226A4ULL,
		0xA4CDAFDDB922E9FEULL,
		0xF5F3B9D6C0924941ULL,
		0x327DC50C7E8C77A9ULL,
		0x3F7F08E643CDD597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7D9E86C43BC4C94ULL,
		0xA3221BF608244C27ULL,
		0xD3205AC53FEB3F38ULL,
		0x783AD37BAA606A63ULL,
		0x48C0D9DAE44DBF06ULL,
		0x66B3725DB1A6A95EULL,
		0xD22C4B8A8CF85D77ULL,
		0x0D5C3EDAAD636B30ULL
	}};
	sign = 0;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2A173A9C991E6875ULL,
		0xC3D6D301D1DE6EC5ULL,
		0xA70413FCB430C617ULL,
		0xF1A01A7AB999491FULL,
		0xF933489D9FE37E6CULL,
		0x34D2A1188AE06CB9ULL,
		0xEDA054B453C30056ULL,
		0x3F60E695B6141765ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF7305B59C377CDULL,
		0x95408B2120D2541BULL,
		0xEA4878823FD62173ULL,
		0x6DF47914B4E674CBULL,
		0x67C9F386363FC45CULL,
		0x0677B00CB3645A98ULL,
		0x106684BA0B423682ULL,
		0x2E3B045ECE42D3C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C200A413F5AF0A8ULL,
		0x2E9647E0B10C1AA9ULL,
		0xBCBB9B7A745AA4A4ULL,
		0x83ABA16604B2D453ULL,
		0x9169551769A3BA10ULL,
		0x2E5AF10BD77C1221ULL,
		0xDD39CFFA4880C9D4ULL,
		0x1125E236E7D1439CULL
	}};
	sign = 0;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6FAC26540FE3317DULL,
		0x5A8B103773541052ULL,
		0x92E52A26BCE3FBABULL,
		0xC708D0103D6083B1ULL,
		0x9C09D7A9DEC364B6ULL,
		0xE115ADB147FF1395ULL,
		0x8EE618941FA16A52ULL,
		0x0D9A2814760C5D11ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x67B231DB1AAD7B3CULL,
		0x5D9A7FAF8E55D3F0ULL,
		0x9D3DB8918524369BULL,
		0x2C1F4AE2D33A7211ULL,
		0xA99D74C3B7EBF127ULL,
		0x76A2A69F323B78F6ULL,
		0x140B4D67B7278FA1ULL,
		0x5FB0EF9C857BDD65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07F9F478F535B641ULL,
		0xFCF09087E4FE3C62ULL,
		0xF5A7719537BFC50FULL,
		0x9AE9852D6A26119FULL,
		0xF26C62E626D7738FULL,
		0x6A73071215C39A9EULL,
		0x7ADACB2C6879DAB1ULL,
		0xADE93877F0907FACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFAF89072C97181FAULL,
		0x02F7654F2F342757ULL,
		0x589EA6B0A95186B4ULL,
		0xE8F0DB695B143A6FULL,
		0x08314E75F907CC84ULL,
		0x9882161B4AC381ADULL,
		0x958C2E5F93BF1924ULL,
		0xD40DBD19D9A80F22ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2029B19B2BE92D4ULL,
		0xD7E410F2E9DB8A06ULL,
		0x8AFE075E0FD940ACULL,
		0xF89B7801D2CA8F06ULL,
		0x77D33C4BD674F6BFULL,
		0x99FC40D71388FA53ULL,
		0xEEF029FCD26656B1ULL,
		0x9CB7EC5CD65EF826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58F5F55916B2EF26ULL,
		0x2B13545C45589D51ULL,
		0xCDA09F5299784607ULL,
		0xF05563678849AB68ULL,
		0x905E122A2292D5C4ULL,
		0xFE85D544373A8759ULL,
		0xA69C0462C158C272ULL,
		0x3755D0BD034916FBULL
	}};
	sign = 0;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x711D488202C3354EULL,
		0x510C97E6B317ED70ULL,
		0xD60644269C9B203DULL,
		0x96F1B92E6E2F3757ULL,
		0x52C7581358383F4FULL,
		0xA2139B599EAE1F7BULL,
		0x16B54F6EC58E5880ULL,
		0xAEF754B3C7E76C6CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9B6AC0E3ED8117ULL,
		0xF54D2C4F9571A210ULL,
		0x9A0134F1C6170C8DULL,
		0xF86D46DF22B0D780ULL,
		0x3EA1DBA150145F35ULL,
		0xC2039E1E981E8F63ULL,
		0xDA2A479F79771ABEULL,
		0x64E1BFB0E6C52C35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA281DDC11ED5B437ULL,
		0x5BBF6B971DA64B5FULL,
		0x3C050F34D68413AFULL,
		0x9E84724F4B7E5FD7ULL,
		0x14257C720823E019ULL,
		0xE00FFD3B068F9018ULL,
		0x3C8B07CF4C173DC1ULL,
		0x4A159502E1224036ULL
	}};
	sign = 0;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06D50FB91060BAB7ULL,
		0xCD93E7E104D446D1ULL,
		0x32B998CFF70DCC66ULL,
		0xAECC5BE8965714BFULL,
		0x6DEB1F2C3275A505ULL,
		0x4324501E0D9BAA7BULL,
		0x3DE10D33ADF40DEBULL,
		0xC101866C5CAA2E84ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D44164E26D5EDEULL,
		0x37765494CD7EF849ULL,
		0xBD39BE94C18088DDULL,
		0xE21EA109EF8D1670ULL,
		0xD3A75346B8B4EAA1ULL,
		0x2D1944B8949AB35CULL,
		0x8539D5728303A389ULL,
		0xF8370312CB9BFA2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9200CE542DF35BD9ULL,
		0x961D934C37554E87ULL,
		0x757FDA3B358D4389ULL,
		0xCCADBADEA6C9FE4EULL,
		0x9A43CBE579C0BA63ULL,
		0x160B0B657900F71EULL,
		0xB8A737C12AF06A62ULL,
		0xC8CA8359910E3459ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF05BCB9474BC1C04ULL,
		0x49F2016F2BA755B7ULL,
		0x53985638FC4F4496ULL,
		0xB4364B2872704B7AULL,
		0x80B9195ABC89BC1FULL,
		0xA7915B70C94CB928ULL,
		0x8E66AAAA4F6ED8C9ULL,
		0xAA13A5F4B36B3132ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E3AD73A7390765AULL,
		0x0E4BDADFF400DC55ULL,
		0xEA9E0DE282963DCCULL,
		0x7C009594ECA6FF7AULL,
		0x10289B06C7D4AC2AULL,
		0x59BAF29F572A27AFULL,
		0x004235B13F49FA06ULL,
		0x32D63180E8728AC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB220F45A012BA5AAULL,
		0x3BA6268F37A67962ULL,
		0x68FA485679B906CAULL,
		0x3835B59385C94BFFULL,
		0x70907E53F4B50FF5ULL,
		0x4DD668D172229179ULL,
		0x8E2474F91024DEC3ULL,
		0x773D7473CAF8A66EULL
	}};
	sign = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07C683C5A8AB5A3AULL,
		0xAE4632C528117B67ULL,
		0x7CD9924C4842B0CFULL,
		0xC23A499E979DFF16ULL,
		0x1612E0279AF20406ULL,
		0x244AADAAE7B5D997ULL,
		0x1E90C29C39ED0394ULL,
		0xF276B7E187B4FA74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AAE45A956D5CCE2ULL,
		0x599FBA8D72328F9BULL,
		0x43F77476FDE979A9ULL,
		0x1B8673BD890C0544ULL,
		0x561B4D7B18E0091DULL,
		0x9E8A95A2403DFD33ULL,
		0x4EC87B760F40000DULL,
		0x1AEE086E4A22ADEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED183E1C51D58D58ULL,
		0x54A67837B5DEEBCBULL,
		0x38E21DD54A593726ULL,
		0xA6B3D5E10E91F9D2ULL,
		0xBFF792AC8211FAE9ULL,
		0x85C01808A777DC63ULL,
		0xCFC847262AAD0386ULL,
		0xD788AF733D924C86ULL
	}};
	sign = 0;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x907E2A3FC68B2214ULL,
		0x8FE60876DF173AA7ULL,
		0xC7C96B2B6583AA47ULL,
		0x635383C826270760ULL,
		0xEE516EFAD0AEAF8AULL,
		0xA2C2C3A066F31817ULL,
		0xBBC3091D3FB432BFULL,
		0xE7CEE80E6C2B8C10ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA286E71CBE7BA318ULL,
		0x08D5221F99DCEEEEULL,
		0x3A7F4B9F17D1708FULL,
		0x59D2F90D613728C4ULL,
		0xECFA5E4226ED93CCULL,
		0x0B6D6E641E3A8525ULL,
		0x35CBE3C9BAB2EFEEULL,
		0x7AA5E56AA895294DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDF74323080F7EFCULL,
		0x8710E657453A4BB8ULL,
		0x8D4A1F8C4DB239B8ULL,
		0x09808ABAC4EFDE9CULL,
		0x015710B8A9C11BBEULL,
		0x9755553C48B892F2ULL,
		0x85F72553850142D1ULL,
		0x6D2902A3C39662C3ULL
	}};
	sign = 0;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAC396F2EE4943A3DULL,
		0x4159F0AEF65147CBULL,
		0x905CEFA8BBC55EC7ULL,
		0x982075D6DAB1E28FULL,
		0x92119BD38496E34CULL,
		0x5F56C8A22692E5D7ULL,
		0x3CC38C5457072410ULL,
		0xBA871CB85ECD9E8AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD29A18B4A655E19ULL,
		0xCBC80FD13E3D9156ULL,
		0xE614957B88604DEEULL,
		0x8CC86CF6E4023D2EULL,
		0xA0A298EE31E1D6ACULL,
		0x3EB035997CA8FD50ULL,
		0x752026127553A38AULL,
		0x2F39FB4B1CCD3E7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF0FCDA39A2EDC24ULL,
		0x7591E0DDB813B674ULL,
		0xAA485A2D336510D8ULL,
		0x0B5808DFF6AFA560ULL,
		0xF16F02E552B50CA0ULL,
		0x20A69308A9E9E886ULL,
		0xC7A36641E1B38086ULL,
		0x8B4D216D4200600CULL
	}};
	sign = 0;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD039FE6744348F64ULL,
		0x7F9932771FDD731DULL,
		0x9AA1B3A2B449B12CULL,
		0xED79FE9C29F20AF2ULL,
		0x3206CB29672A19C0ULL,
		0x7E3F2D8F80843588ULL,
		0x8542B69F21AAD20EULL,
		0xC93BC8B03196ABAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6901D3002B7181ULL,
		0x6B7EAF1731A4416DULL,
		0xC92D3F1A4D784583ULL,
		0x52DA7C9C5B5B2CB9ULL,
		0x025C1CAAAE1DA53BULL,
		0x077140DFBA74825BULL,
		0xFA582685AF9E871EULL,
		0x49D7C47363362993ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70D0FC9444091DE3ULL,
		0x141A835FEE3931B0ULL,
		0xD174748866D16BA9ULL,
		0x9A9F81FFCE96DE38ULL,
		0x2FAAAE7EB90C7485ULL,
		0x76CDECAFC60FB32DULL,
		0x8AEA9019720C4AF0ULL,
		0x7F64043CCE608216ULL
	}};
	sign = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC0C99FA0F692657ULL,
		0x43A19053A9F3D5C6ULL,
		0xADDF7F0C7CD367BFULL,
		0x60D82F35219192B3ULL,
		0x57E089619E052CFBULL,
		0xE93FF929ECD4B878ULL,
		0x15B488E5E16E4E36ULL,
		0xAA808C0F922127C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x04666A451C3BDDF1ULL,
		0x0A6E18E85D774CE7ULL,
		0x4322F22A25F9050BULL,
		0xEC14E0B1ADB51DEBULL,
		0x2054AA76FCC32392ULL,
		0xB68F3E0E43A07B35ULL,
		0x99BAC94CEEBCDD64ULL,
		0x6D9816EAB5210143ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7A62FB4F32D4866ULL,
		0x3933776B4C7C88DFULL,
		0x6ABC8CE256DA62B4ULL,
		0x74C34E8373DC74C8ULL,
		0x378BDEEAA1420968ULL,
		0x32B0BB1BA9343D43ULL,
		0x7BF9BF98F2B170D2ULL,
		0x3CE87524DD002682ULL
	}};
	sign = 0;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCFF50BA6343B5C98ULL,
		0x877339C04C049B8EULL,
		0x014C5CD5FC827F2AULL,
		0x40D8CBE0E9BB8EA8ULL,
		0x06EAE7E5CB80E3D0ULL,
		0x4CE52275CE54D554ULL,
		0xFFE65521F27987D7ULL,
		0xD4704DF8C3019954ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB1C165F99C6903BULL,
		0xA40A62B1FB5333AFULL,
		0x93FC12F6E42981D9ULL,
		0x0D3803F050E53A86ULL,
		0x050D0E6CF36B33CFULL,
		0xE8F4A94CF628D7CEULL,
		0xCD29BA5B6F51199EULL,
		0xAD37D6F50FFC1F33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04D8F5469A74CC5DULL,
		0xE368D70E50B167DFULL,
		0x6D5049DF1858FD50ULL,
		0x33A0C7F098D65421ULL,
		0x01DDD978D815B001ULL,
		0x63F07928D82BFD86ULL,
		0x32BC9AC683286E38ULL,
		0x27387703B3057A21ULL
	}};
	sign = 0;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x821CB6ED095BCE82ULL,
		0xD2A8E0694D080502ULL,
		0xC991F0AA26DEEB65ULL,
		0x2F8D58C6087514AFULL,
		0x5AA10495932C1D3CULL,
		0x8E8FC4D4B45A8F8EULL,
		0x543702CD31C1D5D7ULL,
		0x5CDD3EF80D1688A1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FEF01CBED4AF808ULL,
		0x5048DCE48E888263ULL,
		0x3412AD26EEA676FBULL,
		0x944A76035DA71545ULL,
		0x07F9481F5F449334ULL,
		0x4E1F6C8BC02C3751ULL,
		0x07BB577C1A443CF5ULL,
		0x4B211D2B06D00452ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x722DB5211C10D67AULL,
		0x82600384BE7F829FULL,
		0x957F43833838746AULL,
		0x9B42E2C2AACDFF6AULL,
		0x52A7BC7633E78A07ULL,
		0x40705848F42E583DULL,
		0x4C7BAB51177D98E2ULL,
		0x11BC21CD0646844FULL
	}};
	sign = 0;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A9F30A47814C0AAULL,
		0x44DBEF06631B0B83ULL,
		0x38BC79491FFDD83BULL,
		0x68D6F05927E5AF8CULL,
		0x0EC1832DB05B99F8ULL,
		0xC132B4196EEC42B3ULL,
		0x59A04FD9932CB7CDULL,
		0xD351E70B4E454F6CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x137CCEEA61CC51D7ULL,
		0xF3756C01BEB1819FULL,
		0x7BA5E8F474B5EE77ULL,
		0x684852B702E3E57BULL,
		0x95EBE78E7BAA760DULL,
		0x425D9957728E8959ULL,
		0x7431A16F406AA28AULL,
		0x970EDFDC01C55330ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x072261BA16486ED3ULL,
		0x51668304A46989E4ULL,
		0xBD169054AB47E9C3ULL,
		0x008E9DA22501CA10ULL,
		0x78D59B9F34B123EBULL,
		0x7ED51AC1FC5DB959ULL,
		0xE56EAE6A52C21543ULL,
		0x3C43072F4C7FFC3BULL
	}};
	sign = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x53FF77A4D2D902D1ULL,
		0x34FB369845410330ULL,
		0xC1A348ED4FF00D0CULL,
		0x5A91291726CBC5C6ULL,
		0x3AEBC4C91433EC1EULL,
		0xE29218289785006AULL,
		0xCA2B3F69821BE555ULL,
		0xBE1F250A6AE76E09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A05B5826671655ULL,
		0x7453BD116FE0B54FULL,
		0x01EAF3F13F6C30F4ULL,
		0xD7E77874D343C17DULL,
		0xA4768489DEF63052ULL,
		0xD14E86BA4615EC60ULL,
		0x3E624F49AA18CB65ULL,
		0xBFED47C63E76FEDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x105F1C4CAC71EC7CULL,
		0xC0A77986D5604DE1ULL,
		0xBFB854FC1083DC17ULL,
		0x82A9B0A253880449ULL,
		0x9675403F353DBBCBULL,
		0x1143916E516F1409ULL,
		0x8BC8F01FD80319F0ULL,
		0xFE31DD442C706F2DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE19E680FA33F35C3ULL,
		0xAD69FDAD5248FDE0ULL,
		0xA0181502A08C8E3CULL,
		0x71B51DBC79E5E905ULL,
		0xB26FB5D2C98DE680ULL,
		0x0ED3009DD49B9283ULL,
		0x72E7C99832C14E12ULL,
		0x7162A024DD2D814BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A7367879CAC8D2DULL,
		0xBA3C79ADB0FA4C8DULL,
		0x8ECF70790C739C23ULL,
		0xBE9F34171E4D498CULL,
		0xDCAA9386CD80F481ULL,
		0x89F53E4926559F64ULL,
		0x86DC6004822D512FULL,
		0xACB0AD7C50E15DBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x572B00880692A896ULL,
		0xF32D83FFA14EB153ULL,
		0x1148A4899418F218ULL,
		0xB315E9A55B989F79ULL,
		0xD5C5224BFC0CF1FEULL,
		0x84DDC254AE45F31EULL,
		0xEC0B6993B093FCE2ULL,
		0xC4B1F2A88C4C238DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB55119BF70BD287ULL,
		0x6B12E700319C8C4EULL,
		0xFE05C2EE325CBB7AULL,
		0x70880D4BD0E0521EULL,
		0x8A3AF27922F99CE4ULL,
		0xA45A836987BD9D80ULL,
		0xB0B78C77667D328FULL,
		0x2403EB629C3F65E2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDE7E13A9BA2C459ULL,
		0x5E2116292DC3F99AULL,
		0x592C4165B5F7D307ULL,
		0x67C5C334B34AC976ULL,
		0x6B3B2C7A91842619ULL,
		0xED6667FBD00B9747ULL,
		0xFC9EBD5BC0A0B952ULL,
		0x7BB2E175F18A60D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D6D30615B690E2EULL,
		0x0CF1D0D703D892B4ULL,
		0xA4D981887C64E873ULL,
		0x08C24A171D9588A8ULL,
		0x1EFFC5FE917576CBULL,
		0xB6F41B6DB7B20639ULL,
		0xB418CF1BA5DC793CULL,
		0xA85109ECAAB50509ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA47D578E12BCB83BULL,
		0x217CAED7C5FE4AF2ULL,
		0xC34C487844F7D76FULL,
		0xD2497241C1080941ULL,
		0x5CD51595474DE92DULL,
		0x2F6EC909762F1D5DULL,
		0x29C2F137A2E78E74ULL,
		0x958E63413C626E85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69817C0E6A0DF3FFULL,
		0x5A56DFDFFE97A163ULL,
		0x6D3325359520BC41ULL,
		0x3BD5D9CF3590DA02ULL,
		0xB3C78442F0D85F4EULL,
		0x233A517C47FB812DULL,
		0x1C211A9CB0A974DBULL,
		0x0CECD40B24D93566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AFBDB7FA8AEC43CULL,
		0xC725CEF7C766A98FULL,
		0x56192342AFD71B2DULL,
		0x967398728B772F3FULL,
		0xA90D9152567589DFULL,
		0x0C34778D2E339C2FULL,
		0x0DA1D69AF23E1999ULL,
		0x88A18F361789391FULL
	}};
	sign = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD698945BE8C2723CULL,
		0xB5158EC26130DCEFULL,
		0x100406C056F72563ULL,
		0xB39B343A4163E244ULL,
		0xCDB5A387F0737D5BULL,
		0x8502A9D6B25CB238ULL,
		0x1398E43BA0F36B86ULL,
		0x06B31B201A034E56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC14D6E38A1E479EULL,
		0xD3032E63095CDD37ULL,
		0x9676150EE5257AF6ULL,
		0xCE302D7A852BBAD1ULL,
		0x74DF60C073FF675BULL,
		0x233EC9730EFCFBCFULL,
		0x859B546032FD460EULL,
		0x5770E5B116740117ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A83BD785EA42A9EULL,
		0xE212605F57D3FFB8ULL,
		0x798DF1B171D1AA6CULL,
		0xE56B06BFBC382772ULL,
		0x58D642C77C7415FFULL,
		0x61C3E063A35FB669ULL,
		0x8DFD8FDB6DF62578ULL,
		0xAF42356F038F4D3EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5754FB721409C1C9ULL,
		0x12888C3FB9472712ULL,
		0xAC3A1B3C4DAC1A20ULL,
		0x201D31C7E940A172ULL,
		0x19BF552FD3AE0CD2ULL,
		0xC9A7EA5216ACBC5BULL,
		0xC61AFDE5B7C19FC4ULL,
		0xD50F123423AC0040ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F884C96F7374308ULL,
		0x8934F05ACCB31619ULL,
		0x9BDF9D83137236B2ULL,
		0xAE677A48E6DCE6C8ULL,
		0xE34AE8F708370D07ULL,
		0x32542BA310880825ULL,
		0x4F1C31ED13060FCEULL,
		0xB58F3FD08F138C67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07CCAEDB1CD27EC1ULL,
		0x89539BE4EC9410F9ULL,
		0x105A7DB93A39E36DULL,
		0x71B5B77F0263BAAAULL,
		0x36746C38CB76FFCAULL,
		0x9753BEAF0624B435ULL,
		0x76FECBF8A4BB8FF6ULL,
		0x1F7FD263949873D9ULL
	}};
	sign = 0;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6CEDCC430216414DULL,
		0xD59B08432E20BA5AULL,
		0x391998335138D20CULL,
		0x92A39E0C7429EA4EULL,
		0x3957A3404C678C45ULL,
		0xDBA158E6B8FE8D92ULL,
		0x0E691EFE7BAD03AEULL,
		0xE0E3E6752B917D59ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78C669D6986C586ULL,
		0xD5F64719AEB17E79ULL,
		0x2A0BFA859D616FE2ULL,
		0x439ADEF6CA22B374ULL,
		0x834B89ED7EF11934ULL,
		0x1814B4BFD9401C46ULL,
		0x367B49E4D194570EULL,
		0x1DDC9BA519C113C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x756165A5988F7BC7ULL,
		0xFFA4C1297F6F3BE0ULL,
		0x0F0D9DADB3D76229ULL,
		0x4F08BF15AA0736DAULL,
		0xB60C1952CD767311ULL,
		0xC38CA426DFBE714BULL,
		0xD7EDD519AA18ACA0ULL,
		0xC3074AD011D06998ULL
	}};
	sign = 0;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x03C692C2CE3FB637ULL,
		0x93A0B8AF81E62B0BULL,
		0x25292D856636C0B9ULL,
		0x4E92F67A0F45C1C5ULL,
		0xAE4241D8D34ECA04ULL,
		0x09082264CA373D65ULL,
		0x63493ACD2D6D5C5AULL,
		0x0AFA773EA0EBBDC7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26034FFDCBDB8C3AULL,
		0x0F4A27270E80C754ULL,
		0x59188624302A1A31ULL,
		0x4076C710A60E8C6CULL,
		0x439F4984DDFC5E88ULL,
		0xD8542A96AAED86A2ULL,
		0xB45C491FF7200D8BULL,
		0x32B18EB244B9B603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDC342C5026429FDULL,
		0x84569188736563B6ULL,
		0xCC10A761360CA688ULL,
		0x0E1C2F6969373558ULL,
		0x6AA2F853F5526B7CULL,
		0x30B3F7CE1F49B6C3ULL,
		0xAEECF1AD364D4ECEULL,
		0xD848E88C5C3207C3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x64A8F91A56EF48E6ULL,
		0xB71810AEAC473169ULL,
		0x282506E8FBD6F164ULL,
		0x96597FD1BF7AA6B3ULL,
		0x83A871C7888B1770ULL,
		0x50B12C92E56B23DFULL,
		0x49229F75A5887C42ULL,
		0x5055B1C8FC2EA5DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x613303D643587ED5ULL,
		0x49AA8A68ACE59FD7ULL,
		0x9652E64908813628ULL,
		0x0375FB024A8D7A01ULL,
		0x03A4669E8FD92BA4ULL,
		0xF52A43D35A13819AULL,
		0x7119613DA51DED03ULL,
		0x6E5F1A8CB555CF66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0375F5441396CA11ULL,
		0x6D6D8645FF619192ULL,
		0x91D2209FF355BB3CULL,
		0x92E384CF74ED2CB1ULL,
		0x80040B28F8B1EBCCULL,
		0x5B86E8BF8B57A245ULL,
		0xD8093E38006A8F3EULL,
		0xE1F6973C46D8D673ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9E73813A0D549FCULL,
		0xC515D5CDDE8CA934ULL,
		0x2E68786C96D66ECAULL,
		0x90D72F097D90BA8BULL,
		0x46D3AF690CE2E15AULL,
		0xEF35E06F4B56F173ULL,
		0x17EE5256A33570B9ULL,
		0x620665061B3A5FF5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE57C214066D63FE9ULL,
		0x8B3571EEC4533874ULL,
		0xE4B7CE9B1014ED7FULL,
		0xF944A5AE8B0B2F8EULL,
		0xDD3863240D8316ACULL,
		0x8C0317B34D22FC26ULL,
		0x84ADF73928938D75ULL,
		0x769716BD84C7AF85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF46B16D339FF0A13ULL,
		0x39E063DF1A3970BFULL,
		0x49B0A9D186C1814BULL,
		0x9792895AF2858AFCULL,
		0x699B4C44FF5FCAADULL,
		0x6332C8BBFE33F54CULL,
		0x93405B1D7AA1E344ULL,
		0xEB6F4E489672B06FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF3CA4043B0656144ULL,
		0x56EC2D78F1144A71ULL,
		0x34C171FD7F22087DULL,
		0xE23368D1E1A0B3A7ULL,
		0xC2A95E148466A3A5ULL,
		0xD5E3A92BEEAAA706ULL,
		0x9D69F2EA477CE461ULL,
		0x427E0B4EBEA21635ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAF9644569277A4FULL,
		0x6C910EDA41A33B03ULL,
		0x3FC6C344F7BF9A27ULL,
		0x90C6CCAF21530E05ULL,
		0x90D71F6772FF3635ULL,
		0xB7996F97DEA7A990ULL,
		0x4E6BA0F43A9D5B04ULL,
		0x8106606F25021E03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48D0DBFE473DE6F5ULL,
		0xEA5B1E9EAF710F6EULL,
		0xF4FAAEB887626E55ULL,
		0x516C9C22C04DA5A1ULL,
		0x31D23EAD11676D70ULL,
		0x1E4A39941002FD76ULL,
		0x4EFE51F60CDF895DULL,
		0xC177AADF999FF832ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5263F86BC2B36C62ULL,
		0x00133EFC19F599E2ULL,
		0xB2106B873CD91160ULL,
		0xD8521DE51802C5CDULL,
		0x12F8039982ACF9A5ULL,
		0x19D2C8D999DA5092ULL,
		0x43F1E23F5FAB00D9ULL,
		0x6A32E53E5C61391DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DC7DD93F41765EULL,
		0x1365F026E9177963ULL,
		0x741BE6172C1E6CDCULL,
		0xE1A846083717BAA7ULL,
		0x228D7F8573A7166BULL,
		0x426AB40993894448ULL,
		0x56AF111E0AAB51C1ULL,
		0x8F67254AE3AAE1E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1877A928371F604ULL,
		0xECAD4ED530DE207EULL,
		0x3DF4857010BAA483ULL,
		0xF6A9D7DCE0EB0B26ULL,
		0xF06A84140F05E339ULL,
		0xD76814D006510C49ULL,
		0xED42D12154FFAF17ULL,
		0xDACBBFF378B65734ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7507E0C9BB1C3AC0ULL,
		0x4816B42E6E650501ULL,
		0x2C07A54854C89C59ULL,
		0xCC5081C42BDEEDC4ULL,
		0x0CFEF6CAB11F7802ULL,
		0x41BCA9B123F8683EULL,
		0x56068A839367A7B2ULL,
		0xDEE6B49F8C77E90CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x587A15CD9AA7E5DAULL,
		0x17981E397F1F6CB7ULL,
		0xFA9D51EFF252DACCULL,
		0x3330EE7B083A5897ULL,
		0x08DAC015FF31A2C6ULL,
		0x8934B22790B04475ULL,
		0x41719356239DC73DULL,
		0xB17F15DA07B9C62FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C8DCAFC207454E6ULL,
		0x307E95F4EF45984AULL,
		0x316A53586275C18DULL,
		0x991F934923A4952CULL,
		0x042436B4B1EDD53CULL,
		0xB887F789934823C9ULL,
		0x1494F72D6FC9E074ULL,
		0x2D679EC584BE22DDULL
	}};
	sign = 0;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x92EBEB15855FFCAAULL,
		0x2ABA8D1B15325A23ULL,
		0xC01B19D06CD5FB84ULL,
		0xA0AECBDB634BFB42ULL,
		0x2AFCB46E166E2919ULL,
		0x2DC6A40C4C621223ULL,
		0xC6BC4BB67D6C49D3ULL,
		0x6BE34231BE3639EBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE610183CC65846DULL,
		0xC5AE8E5E974337E1ULL,
		0x6D1659084CFD605EULL,
		0xBF1DEB408A1CD9C5ULL,
		0x488DD92686747BF1ULL,
		0x20D6C215F8493730ULL,
		0xFB8F69605914F281ULL,
		0x5E1B27E4F754E76AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE48AE991B8FA783DULL,
		0x650BFEBC7DEF2241ULL,
		0x5304C0C81FD89B25ULL,
		0xE190E09AD92F217DULL,
		0xE26EDB478FF9AD27ULL,
		0x0CEFE1F65418DAF2ULL,
		0xCB2CE25624575752ULL,
		0x0DC81A4CC6E15280ULL
	}};
	sign = 0;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA34E3306C172744FULL,
		0x05FF1BF5F9F501B7ULL,
		0x302E0CEEE19BC1AAULL,
		0x1D5ED34010701BF0ULL,
		0x666DB632DD3EAF2AULL,
		0xD3A7F5981ADDD333ULL,
		0x351ACF890E03F5ACULL,
		0xC24510E45285CD85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD6538515777EAB6ULL,
		0x81905D37B28F5EE2ULL,
		0x1F80E2D30C3BCF76ULL,
		0x447707A383B69679ULL,
		0x1664E2E2180C48FCULL,
		0x6805D28D76E153B5ULL,
		0x46E7BF8710609215ULL,
		0x1ECDCFF5B806F27DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5E8FAB569FA8999ULL,
		0x846EBEBE4765A2D4ULL,
		0x10AD2A1BD55FF233ULL,
		0xD8E7CB9C8CB98577ULL,
		0x5008D350C532662DULL,
		0x6BA2230AA3FC7F7EULL,
		0xEE331001FDA36397ULL,
		0xA37740EE9A7EDB07ULL
	}};
	sign = 0;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD6E7205FCEF0FCF0ULL,
		0x91F99244A796811FULL,
		0xE9A651AFE82828D2ULL,
		0x7FC73A3ED2AF3556ULL,
		0x98841DE64683EB56ULL,
		0xF25596B275A1876EULL,
		0x343D5AA59345887CULL,
		0xF7826E0F093C053BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C86C7E42D20CB49ULL,
		0xA7CBFB74E0C95172ULL,
		0x9BFD9FF33B1883A1ULL,
		0x54522D68C596D226ULL,
		0x84D67971FDA4B6B8ULL,
		0x3DEF055F0E134068ULL,
		0x7E4A58ABF86C7EA8ULL,
		0x5D48F6E07B2B3AC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A60587BA1D031A7ULL,
		0xEA2D96CFC6CD2FADULL,
		0x4DA8B1BCAD0FA530ULL,
		0x2B750CD60D186330ULL,
		0x13ADA47448DF349EULL,
		0xB4669153678E4706ULL,
		0xB5F301F99AD909D4ULL,
		0x9A39772E8E10CA76ULL
	}};
	sign = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD697C38254BD08FAULL,
		0x17A10A128929C7E1ULL,
		0x2DB8FA73402982D8ULL,
		0x53D22C131518E114ULL,
		0xC0E82032693A0049ULL,
		0x7DEC9EBC3D31C4E6ULL,
		0x9D947206896376DDULL,
		0x21524822AFC29794ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12ECCD4E5FDD3DFEULL,
		0x8D4F258AF138C8C7ULL,
		0xDAC801780B2EC05EULL,
		0x83E0ED1AAA81B4A1ULL,
		0x07A6BACCE22789D0ULL,
		0x3E1A62E7D3A8B3FAULL,
		0x17BD5B4B4BFA92B1ULL,
		0xC80F2BBECD87D7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3AAF633F4DFCAFCULL,
		0x8A51E48797F0FF1AULL,
		0x52F0F8FB34FAC279ULL,
		0xCFF13EF86A972C72ULL,
		0xB941656587127678ULL,
		0x3FD23BD4698910ECULL,
		0x85D716BB3D68E42CULL,
		0x59431C63E23ABFABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBB2F8F4B478824F5ULL,
		0x6BA04A5539FBB936ULL,
		0xD409D9A9E6247E7CULL,
		0xC99712537D9ADF33ULL,
		0x331036605314865FULL,
		0x9011E254AD754EF8ULL,
		0xDAF8403DC50BFF34ULL,
		0x64C1EAADACF625B2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x102626B49207A284ULL,
		0x2F8C2E0C677278ACULL,
		0xC6E5BD0BBDEF642EULL,
		0x30D93F8CF2C13CD5ULL,
		0xF2E24FA5EB148767ULL,
		0xDF4CB84A5EFBA412ULL,
		0xA2B78A667FEB0A01ULL,
		0x5B5BA3117A9C99F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB096896B5808271ULL,
		0x3C141C48D289408AULL,
		0x0D241C9E28351A4EULL,
		0x98BDD2C68AD9A25EULL,
		0x402DE6BA67FFFEF8ULL,
		0xB0C52A0A4E79AAE5ULL,
		0x3840B5D74520F532ULL,
		0x0966479C32598BC1ULL
	}};
	sign = 0;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x944632F2E08FD31CULL,
		0xF5A9C6C488F2EEA0ULL,
		0x31A71BE0C28A84C0ULL,
		0x26E59994E8B2491CULL,
		0x9050B0F44CDEA884ULL,
		0x9B85FBDD78511E2AULL,
		0x30CB01A52D5656F2ULL,
		0xDC6D93F6FDB7FBB8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BEA0D547DF98335ULL,
		0x72232EAD45E11DD2ULL,
		0x2FD8A6AAABDB152BULL,
		0x97E2E15424BD91E6ULL,
		0xA173F3BACEE9D8ECULL,
		0x5B501455B513F105ULL,
		0x2F94D871D3F4F60AULL,
		0x34F1C6CCE808F7F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x585C259E62964FE7ULL,
		0x838698174311D0CEULL,
		0x01CE753616AF6F95ULL,
		0x8F02B840C3F4B736ULL,
		0xEEDCBD397DF4CF97ULL,
		0x4035E787C33D2D24ULL,
		0x01362933596160E8ULL,
		0xA77BCD2A15AF03C1ULL
	}};
	sign = 0;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF18C1EB8A3A9B14CULL,
		0xF13A8564AAF0B141ULL,
		0x615B71A66E6FED14ULL,
		0x5271650DED09B07BULL,
		0x54D211333C7F7D2CULL,
		0x5FBE3EE2B9FBFD07ULL,
		0x081ABB26F7942EE1ULL,
		0x285A2B8E91D4C564ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08488C7A1F355DA2ULL,
		0x4CFE367D11FFA643ULL,
		0x63CD90B9C98F59FBULL,
		0xFD22BC50FF212247ULL,
		0x3B9086785291775CULL,
		0x56E83E9925570FEDULL,
		0x3E67F9986EBAD2F5ULL,
		0xE182DC15BF07EEE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE943923E847453AAULL,
		0xA43C4EE798F10AFEULL,
		0xFD8DE0ECA4E09319ULL,
		0x554EA8BCEDE88E33ULL,
		0x19418ABAE9EE05CFULL,
		0x08D6004994A4ED1AULL,
		0xC9B2C18E88D95BECULL,
		0x46D74F78D2CCD67FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB90EB319C587FBB3ULL,
		0x9B25582A93EFEC3CULL,
		0xFF9D0657955106B7ULL,
		0xD7D05A3B30FA6C0DULL,
		0x1EC596DA8220EFDDULL,
		0xA3322C7FF0164B88ULL,
		0x30F105E791EE7BCBULL,
		0xF7EF71BCC7A0D282ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7464234628E34015ULL,
		0x6AC90E40DB9D4DDCULL,
		0x331B6D002DF9ABAEULL,
		0xA363A90886504A09ULL,
		0x1CD866E6B3040721ULL,
		0x0D7CD0E28FE40EAAULL,
		0x1FF7D5DF945E6CC2ULL,
		0x63BE7DE18AC0ABAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44AA8FD39CA4BB9EULL,
		0x305C49E9B8529E60ULL,
		0xCC81995767575B09ULL,
		0x346CB132AAAA2204ULL,
		0x01ED2FF3CF1CE8BCULL,
		0x95B55B9D60323CDEULL,
		0x10F93007FD900F09ULL,
		0x9430F3DB3CE026D4ULL
	}};
	sign = 0;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCB4A01BD5D728692ULL,
		0xCF2B00CF74554E66ULL,
		0xCD0B5B0EDCC9F582ULL,
		0x6D43D92C2A0EF1D1ULL,
		0xF6C1202D3D75A1A7ULL,
		0x499E8E994FA344E5ULL,
		0x879611E36CE00DC1ULL,
		0x462D61454FDB85AFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0EC580275F31B94ULL,
		0x52CF3C2794470A86ULL,
		0x2A31971773048CBEULL,
		0xBCBCE8B32C5BD3F8ULL,
		0x031B51A5D648A51AULL,
		0xD33CABB8BE328484ULL,
		0x744FEB28C8DB11E0ULL,
		0x5525FE5CECFC1A02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA5DA9BAE77F6AFEULL,
		0x7C5BC4A7E00E43DFULL,
		0xA2D9C3F769C568C4ULL,
		0xB086F078FDB31DD9ULL,
		0xF3A5CE87672CFC8CULL,
		0x7661E2E09170C061ULL,
		0x134626BAA404FBE0ULL,
		0xF10762E862DF6BADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3F271240EA69960CULL,
		0xD3F5180CC3F5302BULL,
		0xC6B282848C2054F9ULL,
		0xE8E635DDF808741AULL,
		0x26847DF73E110751ULL,
		0xF4220A8AE301CE97ULL,
		0x4D8A8BB9EC665CE0ULL,
		0x4004C7E6D9857283ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x52786F6CBC3DC3ADULL,
		0xBE30CD6D292C2AE0ULL,
		0xE9172F449652CDC4ULL,
		0xF366A5082C04BB67ULL,
		0xDDEBB49BB6AF3DF7ULL,
		0x12C99A0C1A216B1DULL,
		0xD508D6690943833EULL,
		0x44C22D7422F8290BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECAEA2D42E2BD25FULL,
		0x15C44A9F9AC9054AULL,
		0xDD9B533FF5CD8735ULL,
		0xF57F90D5CC03B8B2ULL,
		0x4898C95B8761C959ULL,
		0xE158707EC8E06379ULL,
		0x7881B550E322D9A2ULL,
		0xFB429A72B68D4977ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1ABBDC431DD3EAFAULL,
		0x38173F141991D3F3ULL,
		0xAB98FD7EA6907CFFULL,
		0xE5C61356D2A84904ULL,
		0x86BECC1D789537A1ULL,
		0xC2CF4FC523A17056ULL,
		0xF85B7F94BFCFD431ULL,
		0xFD914EE760396B18ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D02D1B5C5DD69AAULL,
		0xF45BBAF08291F0D1ULL,
		0x26A3D46643CEC826ULL,
		0x1FDE14010E35BC3AULL,
		0x74ECC5AD5ADD04C1ULL,
		0x07BA7DEAD6BE9986ULL,
		0x114612AA0F77DDD6ULL,
		0x08EE01F1ABF8EBD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDB90A8D57F68150ULL,
		0x43BB842396FFE321ULL,
		0x84F5291862C1B4D8ULL,
		0xC5E7FF55C4728CCAULL,
		0x11D206701DB832E0ULL,
		0xBB14D1DA4CE2D6D0ULL,
		0xE7156CEAB057F65BULL,
		0xF4A34CF5B4407F3FULL
	}};
	sign = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x671BCAFE25FC50A8ULL,
		0xD16FED534EF35AD9ULL,
		0x3337E7C103676899ULL,
		0x9FE7619793CF46B5ULL,
		0xBAD28ED95A991936ULL,
		0xD8540D978412D9A5ULL,
		0xE2377FEDCD0CF2E4ULL,
		0x00573CC6BE80A886ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF21813212F0903D2ULL,
		0xDF83C580871D461DULL,
		0x62B87CCFCEFF059BULL,
		0xD9A64D600FB8CAE1ULL,
		0x4D8933FF77A268FAULL,
		0x5446A9E0C3ECC39CULL,
		0x20D0624408052FEDULL,
		0xF85C5087A8899E89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7503B7DCF6F34CD6ULL,
		0xF1EC27D2C7D614BBULL,
		0xD07F6AF1346862FDULL,
		0xC641143784167BD3ULL,
		0x6D495AD9E2F6B03BULL,
		0x840D63B6C0261609ULL,
		0xC1671DA9C507C2F7ULL,
		0x07FAEC3F15F709FDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0AC7AF74C2FB3586ULL,
		0x82681E5B30332049ULL,
		0xEC6430B36D068C18ULL,
		0x19C4A05F25B9DB21ULL,
		0xE7AD6D18C2AB6671ULL,
		0xE48EE6D7381D1578ULL,
		0x7A8D54C53B968390ULL,
		0xBA6AF69014A65D8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA46C14EE50167B67ULL,
		0x8B1DCD2D1D335473ULL,
		0x0BC4A4F995C405ECULL,
		0x3047A962E6E9FFCDULL,
		0xEADC6FA1375BC609ULL,
		0x5B2C027F98F6815FULL,
		0x4FE639261D4C0B07ULL,
		0xF17B1DD35B1D1F69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x665B9A8672E4BA1FULL,
		0xF74A512E12FFCBD5ULL,
		0xE09F8BB9D742862BULL,
		0xE97CF6FC3ECFDB54ULL,
		0xFCD0FD778B4FA067ULL,
		0x8962E4579F269418ULL,
		0x2AA71B9F1E4A7889ULL,
		0xC8EFD8BCB9893E23ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x136D3684D7924306ULL,
		0x47E8D5C8A50417CAULL,
		0x8CE3507282F70EECULL,
		0x542F40C0FFD6309EULL,
		0x1EEE9C09649E1CC1ULL,
		0x9C6AC915BAB8FFABULL,
		0x532F216A3AA4615AULL,
		0x98884EB321998ECBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E9A2525E0DCB7AULL,
		0x2006A6BDAEF175C7ULL,
		0xEFF7A8824DBD1EA0ULL,
		0xF6FF3C8CB6EDDADFULL,
		0x6180FA1B3476A073ULL,
		0xA12F807375EF87F0ULL,
		0x26304DC31761398BULL,
		0xB153DE20EF354A2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA98394327984778CULL,
		0x27E22F0AF612A202ULL,
		0x9CEBA7F03539F04CULL,
		0x5D30043448E855BEULL,
		0xBD6DA1EE30277C4DULL,
		0xFB3B48A244C977BAULL,
		0x2CFED3A7234327CEULL,
		0xE73470923264449DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCEDD78A18E749EABULL,
		0x62D920F05E1D2981ULL,
		0xF421FEF89FEAEA11ULL,
		0x4DD059AC59BF624AULL,
		0xC62D76BDE090D5E5ULL,
		0x817712A07D907E2AULL,
		0x01E4186B746C6B3DULL,
		0x6F894AF5B90FEE7FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0571D7589163E7ULL,
		0xA79E404234FED285ULL,
		0xC20CA30744CB6414ULL,
		0x4F787D27D63168D4ULL,
		0xB14ECBCCBB59DB8FULL,
		0x17D04C845544255EULL,
		0x95E2844A98F66C33ULL,
		0x402F9B56FDC4BE2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0D806CA35E33AC4ULL,
		0xBB3AE0AE291E56FCULL,
		0x32155BF15B1F85FCULL,
		0xFE57DC84838DF976ULL,
		0x14DEAAF12536FA55ULL,
		0x69A6C61C284C58CCULL,
		0x6C019420DB75FF0AULL,
		0x2F59AF9EBB4B3053ULL
	}};
	sign = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDCE35DD1DF980C89ULL,
		0x96322E467C16E3C3ULL,
		0x9971E9FEC169E2D2ULL,
		0x066B5383FBC6A5DBULL,
		0x22EA7DE7E7038A3EULL,
		0x74CA40EAA3FF04C6ULL,
		0x18658CCD3A03D160ULL,
		0xF2251F9D0E657B2AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4D1A88F0AF9398ULL,
		0x69C091AE1238734DULL,
		0x9DC603D1D3B514AFULL,
		0x49123EC32B2BEAC0ULL,
		0xB639ED3349D745C0ULL,
		0x6752ED2F6F645914ULL,
		0x8769CA8FC0CAD68EULL,
		0x13A2F459365338A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90964348EEE878F1ULL,
		0x2C719C9869DE7076ULL,
		0xFBABE62CEDB4CE23ULL,
		0xBD5914C0D09ABB1AULL,
		0x6CB090B49D2C447DULL,
		0x0D7753BB349AABB1ULL,
		0x90FBC23D7938FAD2ULL,
		0xDE822B43D8124280ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7157E1D86B311071ULL,
		0x298A5B801F60F8D5ULL,
		0x126406A0182E5890ULL,
		0x8FC77AAF04183DC8ULL,
		0x96F594DB777E9C42ULL,
		0xFE7B55EAB403B47DULL,
		0x9B62EF9CB7A6B636ULL,
		0x21C4692F127827D9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1A5C7EA9D180B7ULL,
		0xB509877AEB18E180ULL,
		0x5F28F60F1A23D25CULL,
		0x90F4A033A83B80C8ULL,
		0x09CAD542062C8E55ULL,
		0x295C0D543AFEB8CEULL,
		0x0348E18023530DEDULL,
		0x640929EF5D58D040ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB73D8559C15F8FBAULL,
		0x7480D40534481754ULL,
		0xB33B1090FE0A8633ULL,
		0xFED2DA7B5BDCBCFFULL,
		0x8D2ABF9971520DECULL,
		0xD51F48967904FBAFULL,
		0x981A0E1C9453A849ULL,
		0xBDBB3F3FB51F5799ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0FBE4FE9A0A7E14ULL,
		0x2E0B90A1F36822A8ULL,
		0x17A4671651CFA584ULL,
		0x6A822F77D12481DEULL,
		0x3A4D906117351B7CULL,
		0x06A3CA3DDE9955B0ULL,
		0xE16FEECDECFD83F3ULL,
		0xD4755138909572C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D84FA7804B4AA16ULL,
		0xC0F6F24BAF2EF934ULL,
		0xA309C8118ED56348ULL,
		0xC97412C63DDCC129ULL,
		0x907999DB9B8E917EULL,
		0x6F4B3BB4C1AC4D8BULL,
		0x1F02C8E27DD3FB0AULL,
		0x9023F20DD9655904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9376EA869555D3FEULL,
		0x6D149E5644392974ULL,
		0x749A9F04C2FA423BULL,
		0xA10E1CB19347C0B4ULL,
		0xA9D3F6857BA689FDULL,
		0x97588E891CED0824ULL,
		0xC26D25EB6F2988E8ULL,
		0x44515F2AB73019C0ULL
	}};
	sign = 0;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8A2131C94D4B1F0ULL,
		0x57072B3B2D9E3A5BULL,
		0xF498F772A2B0625CULL,
		0x2E4EC6128C7E08EFULL,
		0xE9F415A7D9202F57ULL,
		0x9E9B2C0A8889E78CULL,
		0x3AA20F4186200EFFULL,
		0xEF4404FCA29441E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x721BE5A5F33EE56BULL,
		0xC788D0CED433A743ULL,
		0x7D1E67C4A1A9E0A9ULL,
		0xF56E4554BDBFB067ULL,
		0x8864EB766BC58C63ULL,
		0x04E9CD5D0E2F51EDULL,
		0xF9E6D91F7EF7E568ULL,
		0x8625445532436D3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76862D76A195CC85ULL,
		0x8F7E5A6C596A9318ULL,
		0x777A8FAE010681B2ULL,
		0x38E080BDCEBE5888ULL,
		0x618F2A316D5AA2F3ULL,
		0x99B15EAD7A5A959FULL,
		0x40BB362207282997ULL,
		0x691EC0A77050D4ABULL
	}};
	sign = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE29A69B55A9EFCB7ULL,
		0xC6F986E33368EF2CULL,
		0x0C07D301FA04A1A9ULL,
		0x8E6BEF8F93A566B3ULL,
		0xC472327628E14843ULL,
		0xBE2BEA3C5536E3D6ULL,
		0x11D1ACAB08E20287ULL,
		0x84AE1FE0D49A3750ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6F4376F472BF5BBULL,
		0x85F7674E9DBAF1FEULL,
		0x541AD3F1B196F0FBULL,
		0xAA9EE9B2C65906CDULL,
		0x350CA7695CB4FA0DULL,
		0x99CDE6E8298450A5ULL,
		0x8A2C975A528C58F9ULL,
		0xF6CC62143067A489ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBA63246137306FCULL,
		0x41021F9495ADFD2DULL,
		0xB7ECFF10486DB0AEULL,
		0xE3CD05DCCD4C5FE5ULL,
		0x8F658B0CCC2C4E35ULL,
		0x245E03542BB29331ULL,
		0x87A51550B655A98EULL,
		0x8DE1BDCCA43292C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4628BD7C7817505EULL,
		0xD2EC83A93F131C93ULL,
		0xEEE7FD5AC3F0C78CULL,
		0x88D638529B37017CULL,
		0xF2B8FFD41A86F129ULL,
		0xB78ABE2FC2F60866ULL,
		0xD24D8509C6D14107ULL,
		0x1CD16E0EF5AF53D5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4486ADA0A82F4700ULL,
		0x0A43538FA5123959ULL,
		0x746DE0DF2857AB0FULL,
		0x299972DBA944CB26ULL,
		0x4A826E06B1CB2099ULL,
		0x6ECE44CB5C1F5F85ULL,
		0xD609DFD270DC8EEBULL,
		0x63AF7684D1183104ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01A20FDBCFE8095EULL,
		0xC8A930199A00E33AULL,
		0x7A7A1C7B9B991C7DULL,
		0x5F3CC576F1F23656ULL,
		0xA83691CD68BBD090ULL,
		0x48BC796466D6A8E1ULL,
		0xFC43A53755F4B21CULL,
		0xB921F78A249722D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x596D3B9134155787ULL,
		0x2848985100D5B828ULL,
		0xF8CCAB3607EE81FDULL,
		0x620C3A9EC21FAE1EULL,
		0x1C5B203CDF77FB50ULL,
		0xFB91B963FCD9B0A8ULL,
		0x04BBC617B8B1B385ULL,
		0xFF2F7F4B806AE744ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB128605036EEBBAULL,
		0x8926BFAF008653E2ULL,
		0xA7042BC51E3531B8ULL,
		0xA0459DCC06037E4BULL,
		0x951D61D586BA2B40ULL,
		0x7DF03533D6BE72CCULL,
		0x7AD77000B3A7DD6AULL,
		0x20D1D733C1E0093FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E5AB58C30A66BCDULL,
		0x9F21D8A2004F6445ULL,
		0x51C87F70E9B95044ULL,
		0xC1C69CD2BC1C2FD3ULL,
		0x873DBE6758BDD00FULL,
		0x7DA18430261B3DDBULL,
		0x89E456170509D61BULL,
		0xDE5DA817BE8ADE04ULL
	}};
	sign = 0;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAEBA4E5493AD2FB2ULL,
		0x6F671FC5830B635CULL,
		0x11A22C86A836DD62ULL,
		0x3B2A19A3AA942051ULL,
		0xA9F1BCE99581D7E0ULL,
		0x72D6569B4817CC0EULL,
		0xD5A38AD6FE430511ULL,
		0xD0E5E53A602A598BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A9EB4C9458A858ULL,
		0x30708B0FC583E909ULL,
		0x8CC0325A1F2BC6D6ULL,
		0xA2F3243D85C2AF1DULL,
		0x13F169A3562DEC66ULL,
		0x654830AC663AF163ULL,
		0x6D2E1EB4BF2C684EULL,
		0x8AA9A41B81B13C65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07106307FF54875AULL,
		0x3EF694B5BD877A53ULL,
		0x84E1FA2C890B168CULL,
		0x9836F56624D17133ULL,
		0x960053463F53EB79ULL,
		0x0D8E25EEE1DCDAABULL,
		0x68756C223F169CC3ULL,
		0x463C411EDE791D26ULL
	}};
	sign = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC3DF7FCEF008EEEDULL,
		0xAB3B4479A73E9B1BULL,
		0x4D1A030B7D4B89BAULL,
		0xB31E0BF9ADA7B1B3ULL,
		0x09E0393EF90408AAULL,
		0x8972D22665400EFEULL,
		0x24DF97471F0030F4ULL,
		0xC0A801F7514C6AF0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x81BA5DC403FAAC33ULL,
		0x33FED88613214088ULL,
		0x37EF569EE6DB6092ULL,
		0x19626A089C0F10A0ULL,
		0x7B279AD45F93C273ULL,
		0x41C1B05C46C06296ULL,
		0xAD669BAFC259096EULL,
		0xD576076F18BE68EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4225220AEC0E42BAULL,
		0x773C6BF3941D5A93ULL,
		0x152AAC6C96702928ULL,
		0x99BBA1F11198A113ULL,
		0x8EB89E6A99704637ULL,
		0x47B121CA1E7FAC67ULL,
		0x7778FB975CA72786ULL,
		0xEB31FA88388E0204ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0E242DF57F6E8B1ULL,
		0x12ED598EC7A64A33ULL,
		0x901183043948FD02ULL,
		0x581F91A11F1369BAULL,
		0x11C0013187581FE7ULL,
		0x7BB30329602A2E51ULL,
		0x4AB266913FD650A2ULL,
		0xA75D0944B550B8ABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8FCEED9783B4EE0ULL,
		0xE711D04E40EAE048ULL,
		0x21E3AF1F67F72B60ULL,
		0x047450F9C3BD13CFULL,
		0x6E2E8D0323399A6DULL,
		0x3DDEDFF9CD166509ULL,
		0x74E297F229FB74B0ULL,
		0x21C2C7A2BBE310E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37E55405DFBB99D1ULL,
		0x2BDB894086BB69EBULL,
		0x6E2DD3E4D151D1A1ULL,
		0x53AB40A75B5655EBULL,
		0xA391742E641E857AULL,
		0x3DD4232F9313C947ULL,
		0xD5CFCE9F15DADBF2ULL,
		0x859A41A1F96DA7C9ULL
	}};
	sign = 0;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC370241DA7068EB4ULL,
		0xE396668E9B3C95D1ULL,
		0x9C5D1F464F613942ULL,
		0xE4BBD3F50F7F7673ULL,
		0xCD55C6C5677592B3ULL,
		0x1318B42B7D51069CULL,
		0x2905211C25A4FF30ULL,
		0xE0A7B20D077246C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9EB4F86160001C4ULL,
		0x264FFFF9C7A4CF98ULL,
		0xC0890BB14F87F773ULL,
		0x325A518CEC13F3E9ULL,
		0x48EE18CF83AE7BABULL,
		0x3706D3D1312A0183ULL,
		0x69E15CD6D95C3EE1ULL,
		0x6826742BBD7097F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE984D49791068CF0ULL,
		0xBD466694D397C638ULL,
		0xDBD41394FFD941CFULL,
		0xB2618268236B8289ULL,
		0x8467ADF5E3C71708ULL,
		0xDC11E05A4C270519ULL,
		0xBF23C4454C48C04EULL,
		0x78813DE14A01AEC9ULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDA865E5D65E8A128ULL,
		0xD7F70E212D05F9F5ULL,
		0x000CF9BB4C1696B3ULL,
		0xC8F7B5A05BCCA422ULL,
		0xC5BADC6803D8B1B8ULL,
		0x675A4BC0E2DA5CBBULL,
		0x0383AAE050E9CC10ULL,
		0xE4EFE86DA0D877B3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47BEE63A982741B2ULL,
		0xD57CCD5677D951C5ULL,
		0x4B0BD88B210CF649ULL,
		0x0FA9CD9E5A6C368FULL,
		0x10E349E5E7084F40ULL,
		0xDA7A4D2F2BEBC776ULL,
		0xFD2C4CBA431A6AC1ULL,
		0xBAE13BFD566E97AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92C77822CDC15F76ULL,
		0x027A40CAB52CA830ULL,
		0xB50121302B09A06AULL,
		0xB94DE80201606D92ULL,
		0xB4D792821CD06278ULL,
		0x8CDFFE91B6EE9545ULL,
		0x06575E260DCF614EULL,
		0x2A0EAC704A69E008ULL
	}};
	sign = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE0E741F45FD65D82ULL,
		0x6AFFB08C8BD4CBABULL,
		0x020C635A43DBA82AULL,
		0x68408090EDC1388AULL,
		0x500C849294AFA720ULL,
		0x681E9C25C0E2DB88ULL,
		0xF5F104A8022CF729ULL,
		0x83B9693AB884CEEBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4C982F50031D1E1ULL,
		0xD44795422D4A4FE3ULL,
		0x3874E2608E0FEF6DULL,
		0x4D248CE78BC85A9AULL,
		0x4383EE18EF2A0D80ULL,
		0xB608E31CD0813F62ULL,
		0xA0469FFF86884487ULL,
		0x059528CDF3263F1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC1DBEFF5FA48BA1ULL,
		0x96B81B4A5E8A7BC7ULL,
		0xC99780F9B5CBB8BCULL,
		0x1B1BF3A961F8DDEFULL,
		0x0C889679A58599A0ULL,
		0xB215B908F0619C26ULL,
		0x55AA64A87BA4B2A1ULL,
		0x7E24406CC55E8FCCULL
	}};
	sign = 0;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x71D4CB3C647BED12ULL,
		0xB97DD46B3CE00554ULL,
		0xF6AC8508C6AC4325ULL,
		0xEDDAD334A8846BE5ULL,
		0x4B3B4C9A39169E78ULL,
		0x9FEF0F1DA3ED389DULL,
		0x30B2FE6C2A90FA53ULL,
		0xBE4594BA2B2C1D86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEED590E561DC973ULL,
		0xE74AB50B96F3EF04ULL,
		0x960B8204B1EB952FULL,
		0xA48D5B75ED710D01ULL,
		0x59797237211325EBULL,
		0x3AA2BEB31E3B1C5BULL,
		0xCF833B3B9381ED96ULL,
		0x61F3372E34AB1556ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2E7722E0E5E239FULL,
		0xD2331F5FA5EC164FULL,
		0x60A1030414C0ADF5ULL,
		0x494D77BEBB135EE4ULL,
		0xF1C1DA631803788DULL,
		0x654C506A85B21C41ULL,
		0x612FC330970F0CBDULL,
		0x5C525D8BF681082FULL
	}};
	sign = 0;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x891E03951C1AFD83ULL,
		0x9B3A4DBFFDD98941ULL,
		0x1468073707365BBEULL,
		0x3DEC653A3E521320ULL,
		0xF62411BE29486E45ULL,
		0x545EABE90C8623DEULL,
		0xC9D164AC44824BA9ULL,
		0xF6F64532873464C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08BFECA5E8FAA4FFULL,
		0x44CB17589FEDDF79ULL,
		0x06B48E932FF613DEULL,
		0x9F52130AE6D7573CULL,
		0xDE75282F21510367ULL,
		0x87978020A74BC768ULL,
		0xEC7B2FF89D3C8A51ULL,
		0x02FDFE1471F8CD81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x805E16EF33205884ULL,
		0x566F36675DEBA9C8ULL,
		0x0DB378A3D74047E0ULL,
		0x9E9A522F577ABBE4ULL,
		0x17AEE98F07F76ADDULL,
		0xCCC72BC8653A5C76ULL,
		0xDD5634B3A745C157ULL,
		0xF3F8471E153B973FULL
	}};
	sign = 0;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2443152AED3A488BULL,
		0x0B78A91B1C553BD7ULL,
		0xE0FCCDB9FA4DEECDULL,
		0xF7FFEAE54D290986ULL,
		0x4F4AF75C5BBC9A20ULL,
		0x87C20D9753C7D984ULL,
		0x14DD1BCAF538C4FCULL,
		0xB78963FD63FD99E0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63296ED262E62355ULL,
		0x46DB195B4DA58E30ULL,
		0x6380294ADF0D2BA6ULL,
		0xBAA194448C4B9895ULL,
		0xA903BCBAB9371C5EULL,
		0xD84CCA97E1A5FC31ULL,
		0xFBE947CFF1A443C4ULL,
		0xEA4C562A450C3BC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC119A6588A542536ULL,
		0xC49D8FBFCEAFADA6ULL,
		0x7D7CA46F1B40C326ULL,
		0x3D5E56A0C0DD70F1ULL,
		0xA6473AA1A2857DC2ULL,
		0xAF7542FF7221DD52ULL,
		0x18F3D3FB03948137ULL,
		0xCD3D0DD31EF15E19ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC1C34C90D39E0F4BULL,
		0x91979E72AA07F983ULL,
		0xF219421B6F29BA14ULL,
		0xBA45A3C885B4219CULL,
		0x5D84796C6BF028F2ULL,
		0xB069FDDD70BAD9B0ULL,
		0xEF2EDF0500BE2C56ULL,
		0x13B0406E2124D38DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD239A96F5AE849ULL,
		0x9C939D6FE34B1761ULL,
		0x75C0E0AC13237C32ULL,
		0xC95EBF670F056595ULL,
		0x72E4CFE65B49070CULL,
		0x164DACCADEBC74B1ULL,
		0x7969B84DB1ACD319ULL,
		0xC9BDF6D92019B40DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94F112E764432702ULL,
		0xF5040102C6BCE222ULL,
		0x7C58616F5C063DE1ULL,
		0xF0E6E46176AEBC07ULL,
		0xEA9FA98610A721E5ULL,
		0x9A1C511291FE64FEULL,
		0x75C526B74F11593DULL,
		0x49F24995010B1F80ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3820210742FBD9CEULL,
		0xDD565067050E41E4ULL,
		0x662D746E64258B85ULL,
		0xA813B0B18E49D380ULL,
		0xCE739848B0F9AE2DULL,
		0x71D48431E6872169ULL,
		0x21A4FCF66949EF6DULL,
		0x301A2CE7FE9B8B84ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x740590D072EE9B09ULL,
		0x7F7A6DBB7BB02F18ULL,
		0xB90A7A0FC2D57525ULL,
		0x3EAE450364A81565ULL,
		0x3FF91B9815BFCAECULL,
		0x401DF5374813CC90ULL,
		0x30EFCBE4DED1EFD0ULL,
		0x05DB2EB5C8E30969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC41A9036D00D3EC5ULL,
		0x5DDBE2AB895E12CBULL,
		0xAD22FA5EA1501660ULL,
		0x69656BAE29A1BE1AULL,
		0x8E7A7CB09B39E341ULL,
		0x31B68EFA9E7354D9ULL,
		0xF0B531118A77FF9DULL,
		0x2A3EFE3235B8821AULL
	}};
	sign = 0;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1ED1F9AB47378377ULL,
		0x86C29B8CA5BA3D12ULL,
		0x2FDD8EB85780C963ULL,
		0xA5CEA3F29F54F050ULL,
		0xA0F9576ADB3757C1ULL,
		0xA7A1E706E959B09EULL,
		0x70389832B57C06F7ULL,
		0xE9BCF15E83D14391ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD023B0F44BA5B25ULL,
		0x2F08524CC0C06CC5ULL,
		0x3E1005ACAF3D94ABULL,
		0x4AC11F53172539E5ULL,
		0xD5FD744CDB401282ULL,
		0x2CF09A64B728B2C9ULL,
		0x21D928E4045F4443ULL,
		0xCD2AA36C216C6BE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61CFBE9C027D2852ULL,
		0x57BA493FE4F9D04CULL,
		0xF1CD890BA84334B8ULL,
		0x5B0D849F882FB66AULL,
		0xCAFBE31DFFF7453FULL,
		0x7AB14CA23230FDD4ULL,
		0x4E5F6F4EB11CC2B4ULL,
		0x1C924DF26264D7A9ULL
	}};
	sign = 0;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC34864F7EB73E586ULL,
		0x69F57650FB02835EULL,
		0x6245DE2A4E6797DFULL,
		0x395338645B7D97D0ULL,
		0x19323C711CE187A7ULL,
		0xDD0F91CFCAB6D095ULL,
		0x7EFB356A1C8E5EE2ULL,
		0x0BBB913B21BE3EA3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0444AE380D3A97AEULL,
		0x358D15CAB45A11A7ULL,
		0x254B48F6E1A4D9B6ULL,
		0xF0CC81EB90FE0920ULL,
		0xBB3E39B20A8CA130ULL,
		0x5FA9B650B7783DD5ULL,
		0x49CDA9A83B31D517ULL,
		0x3E8624D4A01F3213ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF03B6BFDE394DD8ULL,
		0x3468608646A871B7ULL,
		0x3CFA95336CC2BE29ULL,
		0x4886B678CA7F8EB0ULL,
		0x5DF402BF1254E676ULL,
		0x7D65DB7F133E92BFULL,
		0x352D8BC1E15C89CBULL,
		0xCD356C66819F0C90ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9A424E67E30E4F20ULL,
		0xCCE9479725B5C5E3ULL,
		0x328DF64A308FE13AULL,
		0xAB656B84BA88165CULL,
		0x3990AACFEAA56F14ULL,
		0x86FEEFDCF330677AULL,
		0x8759C66ED33F3F38ULL,
		0xB5B880CEDCAA6BD4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7428C1C8F3827126ULL,
		0xA76B0BEABEFF11ACULL,
		0xC484D47E37C35219ULL,
		0x94464C83497E67A9ULL,
		0xDDCFB0D0568FE65FULL,
		0x3D90EFAD5827CC65ULL,
		0x255E72E1B9737F97ULL,
		0xC6233D5F768A1DDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26198C9EEF8BDDFAULL,
		0x257E3BAC66B6B437ULL,
		0x6E0921CBF8CC8F21ULL,
		0x171F1F017109AEB2ULL,
		0x5BC0F9FF941588B5ULL,
		0x496E002F9B089B14ULL,
		0x61FB538D19CBBFA1ULL,
		0xEF95436F66204DF5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82CBD1A42DBDD381ULL,
		0xA311D862CBCE11F4ULL,
		0xBE177D51C09B3056ULL,
		0xBD77474139BEF3D0ULL,
		0xF299476ACEA6C355ULL,
		0xC97DB8949A122F84ULL,
		0xBCC8FC8FE96BE70DULL,
		0xCE6860D8F57B0296ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C66E443CB95ADFULL,
		0x1F4FC960C601EC5EULL,
		0xCE32D4050318C2F3ULL,
		0x88D56C47056F481AULL,
		0x91C6FE73ED5B92D8ULL,
		0x2CAB38368103615DULL,
		0x66394404790FCF3AULL,
		0xF218A8C5A2A4123EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F05635FF10478A2ULL,
		0x83C20F0205CC2595ULL,
		0xEFE4A94CBD826D63ULL,
		0x34A1DAFA344FABB5ULL,
		0x60D248F6E14B307DULL,
		0x9CD2805E190ECE27ULL,
		0x568FB88B705C17D3ULL,
		0xDC4FB81352D6F058ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAABA8FEE939728CFULL,
		0x4CFA088C95EC7222ULL,
		0x4BCC5C9EB59BD5F5ULL,
		0xC90FFC939F314DCDULL,
		0x8FDD7FCBC9CB4856ULL,
		0x5E3FA1B6EA04B161ULL,
		0xA2EDF2690DA61DBFULL,
		0x4ECC646AE3E50B95ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x19BFD2EEF79CAFC9ULL,
		0xFE981D320FFCEE1DULL,
		0x53B335043ACDDDC8ULL,
		0x13CA71D8A36E06B6ULL,
		0x53D9F16F4A93952AULL,
		0x5F784FB6015F566DULL,
		0xFE224AB8CBF2FCB2ULL,
		0x6EB861D1E86A6501ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90FABCFF9BFA7906ULL,
		0x4E61EB5A85EF8405ULL,
		0xF819279A7ACDF82CULL,
		0xB5458ABAFBC34716ULL,
		0x3C038E5C7F37B32CULL,
		0xFEC75200E8A55AF4ULL,
		0xA4CBA7B041B3210CULL,
		0xE0140298FB7AA693ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE7B30B5BD0EC227ULL,
		0x368F17E7B4B17803ULL,
		0x2FE58236CD29A662ULL,
		0x1F9749F218747484ULL,
		0x5D72A71EE3D78E56ULL,
		0x8414FB210BC58512ULL,
		0xACFCC3FD3C119E73ULL,
		0x8FD0ABCCABC9E992ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD5D50A12307942ULL,
		0x89ED033987F9CB92ULL,
		0x30CD962DF961E4C5ULL,
		0x4A17F7822496A56DULL,
		0x6D42028912A67509ULL,
		0xA44AE01A0A11D5A6ULL,
		0xBE3C702ABC4B3DE2ULL,
		0xFA02DAC3FF6F4C6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3A55BABAADE48E5ULL,
		0xACA214AE2CB7AC71ULL,
		0xFF17EC08D3C7C19CULL,
		0xD57F526FF3DDCF16ULL,
		0xF030A495D131194CULL,
		0xDFCA1B0701B3AF6BULL,
		0xEEC053D27FC66090ULL,
		0x95CDD108AC5A9D23ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD2D712BFFAFA7E09ULL,
		0x9FFFA5408A8A69CDULL,
		0x157EAA9598F07788ULL,
		0x0AD27BE1C3238679ULL,
		0x14A0E9588F56C6ECULL,
		0x3A766B6A4A36B9FCULL,
		0x8EB51E64FC619A64ULL,
		0x4E847573F8C9C065ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB750B0D4D5EFAA1FULL,
		0x8FB556AE989FCC86ULL,
		0x8F8FCD8F2639AAA7ULL,
		0x9B89ADFFDD5DA488ULL,
		0x443D15ED3F2266B8ULL,
		0x5234BADE98E27436ULL,
		0xBD2B6B01FC83970BULL,
		0xF10C3262262314A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B8661EB250AD3EAULL,
		0x104A4E91F1EA9D47ULL,
		0x85EEDD0672B6CCE1ULL,
		0x6F48CDE1E5C5E1F0ULL,
		0xD063D36B50346033ULL,
		0xE841B08BB15445C5ULL,
		0xD189B362FFDE0358ULL,
		0x5D784311D2A6ABBFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6160DB0EB6B1613AULL,
		0x136FD725E537DBC1ULL,
		0x107D1D18AA7B8E2AULL,
		0x478F53D5E0A6E642ULL,
		0x73B94FAA07779341ULL,
		0x694C07313F3FF6F2ULL,
		0x2F9DD30EA05C6322ULL,
		0xA91C8C2EC7B571F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA41366664163A748ULL,
		0x6A3BC44FE1E08AA8ULL,
		0xCCDE7187F45D029AULL,
		0xD51D6D25E88482A8ULL,
		0xF38177CAF36238ACULL,
		0x898555EE8340AF30ULL,
		0xA47755785A9B0D00ULL,
		0xDBDDAB1AAE50EFC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD4D74A8754DB9F2ULL,
		0xA93412D603575118ULL,
		0x439EAB90B61E8B8FULL,
		0x7271E6AFF8226399ULL,
		0x8037D7DF14155A94ULL,
		0xDFC6B142BBFF47C1ULL,
		0x8B267D9645C15621ULL,
		0xCD3EE1141964822EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCED72927934D9528ULL,
		0xD1EB8833756ABA0FULL,
		0xE066BFEB95C37157ULL,
		0x95C19DC1A74D1F19ULL,
		0x737513EA533081F7ULL,
		0x2AE232262967CDC7ULL,
		0xA38272F278E69E1EULL,
		0xB846863C1093F9A2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F49281830DDBDD7ULL,
		0x535F5709901AE594ULL,
		0xFD273B821E668547ULL,
		0x1BF3EB2A391FB053ULL,
		0xA717CB1F8B29782DULL,
		0x3A0F30100E7492D2ULL,
		0x21D578FE6F30BEEEULL,
		0x0B7ECE2350B33DD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F8E010F626FD751ULL,
		0x7E8C3129E54FD47BULL,
		0xE33F8469775CEC10ULL,
		0x79CDB2976E2D6EC5ULL,
		0xCC5D48CAC80709CAULL,
		0xF0D302161AF33AF4ULL,
		0x81ACF9F409B5DF2FULL,
		0xACC7B818BFE0BBCBULL
	}};
	sign = 0;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A74C8FDE4C79F70ULL,
		0x5926C42490C2280CULL,
		0x0770666D5BFDFB74ULL,
		0xC61DAC615C32E5A1ULL,
		0xB791AD6523A5E426ULL,
		0x560222BFC129CD21ULL,
		0x71FAE98CB5EAD6EEULL,
		0x246A725A95AE2410ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE23FDD52FFA7C6C4ULL,
		0x82B79E1F5545D723ULL,
		0x31FACB80A1AB1887ULL,
		0xDF296B96D0294825ULL,
		0x1EAF100A333FA5B3ULL,
		0xB70288A6A994F203ULL,
		0xAAF3C741D306605AULL,
		0xBE0D396EAEE986DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3834EBAAE51FD8ACULL,
		0xD66F26053B7C50E8ULL,
		0xD5759AECBA52E2ECULL,
		0xE6F440CA8C099D7BULL,
		0x98E29D5AF0663E72ULL,
		0x9EFF9A191794DB1EULL,
		0xC707224AE2E47693ULL,
		0x665D38EBE6C49D32ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6302AA9D4B693F39ULL,
		0xF943032C53784E75ULL,
		0xFE29CF9C8D20D3E5ULL,
		0x8F878C9AAC3EF981ULL,
		0xC8106AE13FA66F3AULL,
		0xB12BE903B8214A4BULL,
		0x10EE0B59E3F726CAULL,
		0xE523CBB9C6957BBEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7464B74554AE05CULL,
		0xFCB6923DDD8E72B2ULL,
		0x23C0AAD807EEC4CEULL,
		0xE7351DE97C0EAEAAULL,
		0x8C3990EB3EC29AD9ULL,
		0x24E02F9430384897ULL,
		0x4E7190F755850D74ULL,
		0xB464B8DE48FE60E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BBC5F28F61E5EDDULL,
		0xFC8C70EE75E9DBC2ULL,
		0xDA6924C485320F16ULL,
		0xA8526EB130304AD7ULL,
		0x3BD6D9F600E3D460ULL,
		0x8C4BB96F87E901B4ULL,
		0xC27C7A628E721956ULL,
		0x30BF12DB7D971ADAULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFCB2B44BA30E2CBAULL,
		0xD65670F869DA1A70ULL,
		0x1D3289850CB20C1FULL,
		0x32473593F7E977BAULL,
		0x272359EF56D4E5D5ULL,
		0xB34A0D588721A6DFULL,
		0xD5F4D09887E1DD68ULL,
		0x850FC426CB8F42FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4161E6633EA1941ULL,
		0xE0CDCE99E2C5589DULL,
		0x76EA238EFF109664ULL,
		0x761452C9F28C2AD3ULL,
		0x4D6B149A881D9D27ULL,
		0x36FA10150D4F374FULL,
		0x216318ACA4442C66ULL,
		0x08F3DF50D31775F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x389C95E56F241379ULL,
		0xF588A25E8714C1D3ULL,
		0xA64865F60DA175BAULL,
		0xBC32E2CA055D4CE6ULL,
		0xD9B84554CEB748ADULL,
		0x7C4FFD4379D26F8FULL,
		0xB491B7EBE39DB102ULL,
		0x7C1BE4D5F877CD04ULL
	}};
	sign = 0;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9D963B0618EF67BCULL,
		0xEF96D50105F04DFFULL,
		0x76B460FD3BC6059AULL,
		0x4EF32E7D897C5216ULL,
		0x80DCD143FFBA5B12ULL,
		0xF79977D76E3DEBD9ULL,
		0x1937D53B7AEB242FULL,
		0x1983DFBE504A24EEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8D9F0454410F0B8ULL,
		0x7F799802BB039B5FULL,
		0xD78447EC27DDCE94ULL,
		0x737B1A2DB58C5FE6ULL,
		0x1A7AB990577C6D8BULL,
		0x78A88B1F41F00CB9ULL,
		0x2F46B2719FB63E7DULL,
		0xDCA4DAC44757B0BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4BC4AC0D4DE7704ULL,
		0x701D3CFE4AECB29FULL,
		0x9F30191113E83706ULL,
		0xDB78144FD3EFF22FULL,
		0x666217B3A83DED86ULL,
		0x7EF0ECB82C4DDF20ULL,
		0xE9F122C9DB34E5B2ULL,
		0x3CDF04FA08F2742EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7D523371BE7E5E90ULL,
		0x8D91C91F2701648EULL,
		0x442E9A27ADF0D812ULL,
		0x5983895CFD8392ACULL,
		0x1ECAE38CA7B8758AULL,
		0x7318E53C1E590F5BULL,
		0x32BDCA860B028B08ULL,
		0xE5D251BAD91FA852ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA54E9EDCD7DE330ULL,
		0x8C0280439B926CA6ULL,
		0x8703361C1262FC34ULL,
		0x540182A54218DDCCULL,
		0xBA3D71C1B48D8F47ULL,
		0xEBE39590EE6EFB17ULL,
		0x7E77D83F25653118ULL,
		0x118A1DFF7EC76008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2FD4983F1007B60ULL,
		0x018F48DB8B6EF7E7ULL,
		0xBD2B640B9B8DDBDEULL,
		0x058206B7BB6AB4DFULL,
		0x648D71CAF32AE643ULL,
		0x87354FAB2FEA1443ULL,
		0xB445F246E59D59EFULL,
		0xD44833BB5A584849ULL
	}};
	sign = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD8A5D0556E04D3E9ULL,
		0xB87DBD7E0CDBE9FEULL,
		0x22C1CE0882EA7DDBULL,
		0x582EB91A04A6F480ULL,
		0x5B3BC8CDF732E7B7ULL,
		0x02A51CAE9CCC27CAULL,
		0x47C649EEC74340E3ULL,
		0xA1474D2B50B4F59BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C64DDEF95FFD5AULL,
		0xD4CB4FAC7D954916ULL,
		0xE61C0FFCBF98E15CULL,
		0x50F49BA7DB248CA9ULL,
		0x1CACFB580C432EC3ULL,
		0xA07749D2E48E19FBULL,
		0xC45811593D682D50ULL,
		0xF99AF6BAD54A22C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90DF827674A4D68FULL,
		0xE3B26DD18F46A0E8ULL,
		0x3CA5BE0BC3519C7EULL,
		0x073A1D72298267D6ULL,
		0x3E8ECD75EAEFB8F4ULL,
		0x622DD2DBB83E0DCFULL,
		0x836E389589DB1392ULL,
		0xA7AC56707B6AD2D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0F38DB8A10AB191CULL,
		0x4690DCFC64F6D6FCULL,
		0x52CF1D88019C7DFFULL,
		0x85367F3454F805DCULL,
		0xAD60107109D20FF2ULL,
		0x9D18DE0F7BF30FC9ULL,
		0x852AA2A3F0C576E2ULL,
		0x85EF08172DDDF0C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x320207DDA866C12BULL,
		0x2988AA7BC65DD042ULL,
		0x76132A05E4643685ULL,
		0x028F95B6B134BFBAULL,
		0x2BB1B9474A6A2D8AULL,
		0x914586FB4E9C49C7ULL,
		0xB9F7DCB45ADB6B00ULL,
		0x12CFFEB1DA8F35B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD36D3AC684457F1ULL,
		0x1D0832809E9906B9ULL,
		0xDCBBF3821D38477AULL,
		0x82A6E97DA3C34621ULL,
		0x81AE5729BF67E268ULL,
		0x0BD357142D56C602ULL,
		0xCB32C5EF95EA0BE2ULL,
		0x731F0965534EBB08ULL
	}};
	sign = 0;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39982E152E40ACDEULL,
		0x5D714085CA4CB093ULL,
		0x7A13A5BC42DE0181ULL,
		0xC49CE0BC5772E85EULL,
		0x2FCEF7CAF0AB6D8BULL,
		0xBAC30439745F0153ULL,
		0xBA1733980B5531A7ULL,
		0xA7C6BAC70826C2A3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA361520B71156B2AULL,
		0x3663DC5342DD6F55ULL,
		0xABE254ECAF00D55EULL,
		0xADA99969A123ECBEULL,
		0x2FF23960099E965EULL,
		0x24EDB01E3584AB87ULL,
		0xA81F572E5DEE92E4ULL,
		0xF959DB723C812889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9636DC09BD2B41B4ULL,
		0x270D6432876F413DULL,
		0xCE3150CF93DD2C23ULL,
		0x16F34752B64EFB9FULL,
		0xFFDCBE6AE70CD72DULL,
		0x95D5541B3EDA55CBULL,
		0x11F7DC69AD669EC3ULL,
		0xAE6CDF54CBA59A1AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x25051ECA807B72EFULL,
		0xEEF4A12C55CB9EA9ULL,
		0x7C96D98D15251208ULL,
		0xA2F8B093F400E40AULL,
		0x06D825140BEBD058ULL,
		0xD4D8F63A0135253DULL,
		0xFA139B8C667C45E9ULL,
		0x35836781DB33C999ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA066CB03DF3A6B95ULL,
		0xE91CBF6FA517237FULL,
		0xC2706975BEEA3658ULL,
		0xD3C03C0B6435D3B8ULL,
		0x5F09746D5409A16CULL,
		0x7903A155FDCF773DULL,
		0x8EA17BD303F825B5ULL,
		0x636AE98993CFD5D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x849E53C6A141075AULL,
		0x05D7E1BCB0B47B29ULL,
		0xBA267017563ADBB0ULL,
		0xCF3874888FCB1051ULL,
		0xA7CEB0A6B7E22EEBULL,
		0x5BD554E40365ADFFULL,
		0x6B721FB962842034ULL,
		0xD2187DF84763F3C2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD6B59C68AB2A60E6ULL,
		0xE879BE9A3CDF7715ULL,
		0xBD45897D4CC246F0ULL,
		0x0A63F0C4C0577FE0ULL,
		0xECEA1575482D80ADULL,
		0x44EB172A76C85115ULL,
		0x5B5F6F0507E2A714ULL,
		0xC92A76626A4E218BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F16BB6E1BFABCDULL,
		0x297622E93CE7400CULL,
		0xD10A7DAEA9A43FF1ULL,
		0xF71871AF59DCF58EULL,
		0xDA7D9C8B0CDB48A1ULL,
		0xD5DC1D0890D5365BULL,
		0xF8E2D8B511EC7C34ULL,
		0x7EEF3595FA5F2B0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DC430B1C96AB519ULL,
		0xBF039BB0FFF83709ULL,
		0xEC3B0BCEA31E06FFULL,
		0x134B7F15667A8A51ULL,
		0x126C78EA3B52380BULL,
		0x6F0EFA21E5F31ABAULL,
		0x627C964FF5F62ADFULL,
		0x4A3B40CC6FEEF67EULL
	}};
	sign = 0;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x626DE91B1BF851EBULL,
		0x4AA1B5E7B1C7F16FULL,
		0x39FF751BE605EBCDULL,
		0xAD5C5274B16BCFEAULL,
		0x28FAB03D4D9628CFULL,
		0xDDE1A6B695C9A62BULL,
		0x4545DDA6DAE1A4AAULL,
		0xF133364D969EA8B7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1A050424AFD5DBULL,
		0x961D7FF3844DA8D3ULL,
		0xBD27651D65466845ULL,
		0xF6D70B50EF1CF91BULL,
		0x35A55FC1E0EFA09CULL,
		0xDE6FE752AAE0F2BCULL,
		0x6611CDB36543E940ULL,
		0x6B21069D3A509279ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD753E416F7487C10ULL,
		0xB48435F42D7A489BULL,
		0x7CD80FFE80BF8387ULL,
		0xB6854723C24ED6CEULL,
		0xF355507B6CA68832ULL,
		0xFF71BF63EAE8B36EULL,
		0xDF340FF3759DBB69ULL,
		0x86122FB05C4E163DULL
	}};
	sign = 0;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x78008C504481462EULL,
		0xB5540FA1EB439A7AULL,
		0x5F0F38D25ACFE2CBULL,
		0x28832AAE879315AEULL,
		0x8765A3540D9C4412ULL,
		0xB69D5320CC4065C9ULL,
		0xCF04935C02525063ULL,
		0xD2450674536CACB2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98498348D518F03DULL,
		0x0D38D5CB64BC3BFEULL,
		0xC055DB1005BDE4C3ULL,
		0x21C0E01A74B8FC3CULL,
		0x7FF7AFAB850506C3ULL,
		0xE8E731B41A80B60AULL,
		0x909F1B84FE6015F5ULL,
		0x87F7BE8510B337EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFB709076F6855F1ULL,
		0xA81B39D686875E7BULL,
		0x9EB95DC25511FE08ULL,
		0x06C24A9412DA1971ULL,
		0x076DF3A888973D4FULL,
		0xCDB6216CB1BFAFBFULL,
		0x3E6577D703F23A6DULL,
		0x4A4D47EF42B974C4ULL
	}};
	sign = 0;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}