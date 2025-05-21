#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Inplace Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xABA2E1992C002B3DULL,
		0x76FF5537924373C9ULL,
		0x578649C95784BBF2ULL,
		0xEFACC5CD563502C3ULL,
		0x4EDF79EF1741EDC2ULL,
		0xA502279179135982ULL,
		0x186E974FA4361166ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xD000000000000000ULL,
		0x9ABA2E1992C002B3ULL,
		0x276FF5537924373CULL,
		0x3578649C95784BBFULL,
		0x2EFACC5CD563502CULL,
		0x24EDF79EF1741EDCULL,
		0x6A50227917913598ULL,
		0x0186E974FA436116ULL
	}};
	int shift = 60;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA55806146B4547D4ULL,
		0x7FE869BA17FAC932ULL,
		0x1AABBF53CA95EC49ULL,
		0xCD5CF164D04958BDULL,
		0x4619C8B6F9CF0DEDULL,
		0x570D6F0095370180ULL,
		0x18544EC85E0EF1CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA00000000000000ULL,
		0x9952AC030A35A2A3ULL,
		0x24BFF434DD0BFD64ULL,
		0x5E8D55DFA9E54AF6ULL,
		0xF6E6AE78B26824ACULL,
		0xC0230CE45B7CE786ULL,
		0xE72B86B7804A9B80ULL,
		0x000C2A27642F0778ULL
	}};
	shift = 55;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x60C49BAB97A8BE7FULL,
		0xE743DE0C08A49441ULL,
		0xAD005C9B98688470ULL,
		0xBC0DE2282753D015ULL,
		0x796894B27E8CDB56ULL,
		0x2A921F24D6860437ULL,
		0x596252BE399F29C9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97A8BE7F0000000ULL,
		0xC08A4944160C49BAULL,
		0xB98688470E743DE0ULL,
		0x82753D015AD005C9ULL,
		0x27E8CDB56BC0DE22ULL,
		0x4D6860437796894BULL,
		0xE399F29C92A921F2ULL,
		0x000000000596252BULL
	}};
	shift = 28;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7A57EA137C6C5741ULL,
		0x0F68AE15236AA156ULL,
		0x648CD4CC5935866DULL,
		0xFEE4CEFC9A0B05F7ULL,
		0x42F5B4765B8CA70FULL,
		0xD7A091EF68A1FD28ULL,
		0x39A0C8735C1A2EE1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE8200000000000ULL,
		0x542ACF4AFD426F8DULL,
		0xB0CDA1ED15C2A46DULL,
		0x60BEEC919A998B26ULL,
		0x94E1FFDC99DF9341ULL,
		0x3FA5085EB68ECB71ULL,
		0x45DC3AF4123DED14ULL,
		0x00000734190E6B83ULL
	}};
	shift = 45;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6EE37220E16350C2ULL,
		0xB8D4CF59C25F0CB4ULL,
		0xD3A7518A46BE703EULL,
		0x6AD4C06CB6FD2ECAULL,
		0x5EAF6CF3299D1AD5ULL,
		0x1DABAD2C72D87149ULL,
		0x44ABABE37462C130ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16350C2000000000ULL,
		0x25F0CB46EE37220EULL,
		0x6BE703EB8D4CF59CULL,
		0x6FD2ECAD3A7518A4ULL,
		0x99D1AD56AD4C06CBULL,
		0x2D871495EAF6CF32ULL,
		0x462C1301DABAD2C7ULL,
		0x000000044ABABE37ULL
	}};
	shift = 36;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE88F840625495103ULL,
		0x58006628D78B781BULL,
		0xEDE88AF338C57339ULL,
		0x3F5D4192F1EA7FDCULL,
		0x39EC927DBC27F493ULL,
		0xC7E2F59B8F66C23DULL,
		0x2898EAC97D7B5B61ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x440C000000000000ULL,
		0xE06FA23E10189525ULL,
		0xCCE5600198A35E2DULL,
		0xFF73B7A22BCCE315ULL,
		0xD24CFD75064BC7A9ULL,
		0x08F4E7B249F6F09FULL,
		0x6D871F8BD66E3D9BULL,
		0x0000A263AB25F5EDULL
	}};
	shift = 50;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7AEB5106E33DD6FDULL,
		0xF778270BE1EA4163ULL,
		0xEE08C0253959E8E5ULL,
		0x7F516A53B4B2F878ULL,
		0x22635C0F81792357ULL,
		0xBC729AEB1901D82EULL,
		0x4CD293BB143413EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DC67BADFA00000ULL,
		0xE17C3D482C6F5D6AULL,
		0x04A72B3D1CBEEF04ULL,
		0x4A76965F0F1DC118ULL,
		0x81F02F246AEFEA2DULL,
		0x5D63203B05C44C6BULL,
		0x776286827DD78E53ULL,
		0x0000000000099A52ULL
	}};
	shift = 21;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDE19B9B7A2E20679ULL,
		0x118C35EC6C038565ULL,
		0xA47641FFA089945BULL,
		0x00FE51B6F1CC0B19ULL,
		0xA310EE56222AE6DDULL,
		0xB31C60D4BC25123FULL,
		0xAAB202769627CF96ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E20679000000000ULL,
		0xC038565DE19B9B7AULL,
		0x089945B118C35EC6ULL,
		0x1CC0B19A47641FFAULL,
		0x22AE6DD00FE51B6FULL,
		0xC25123FA310EE562ULL,
		0x627CF96B31C60D4BULL,
		0x0000000AAB202769ULL
	}};
	shift = 36;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x890CB4D73E3CCB9AULL,
		0x9E539035EC3632C4ULL,
		0x1A352011149D6234ULL,
		0xB85E50C11D694D60ULL,
		0x25CC9511CF9BDF60ULL,
		0xE74A1E259A62B55FULL,
		0x4EFFC32176E9C4DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21969AE7C7997340ULL,
		0xCA7206BD86C65891ULL,
		0x46A4022293AC4693ULL,
		0x0BCA1823AD29AC03ULL,
		0xB992A239F37BEC17ULL,
		0xE943C4B34C56ABE4ULL,
		0xDFF8642EDD389BBCULL,
		0x0000000000000009ULL
	}};
	shift = 5;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6C855DD9F7626111ULL,
		0x9EB899743A7C79F8ULL,
		0x9591BC1CDA13EC43ULL,
		0x35FC2671ACAB4615ULL,
		0x6B5257D11E47E8C6ULL,
		0xB1BDA1680C367AC4ULL,
		0xF54E255275178D54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC222000000000000ULL,
		0xF3F0D90ABBB3EEC4ULL,
		0xD8873D7132E874F8ULL,
		0x8C2B2B237839B427ULL,
		0xD18C6BF84CE35956ULL,
		0xF588D6A4AFA23C8FULL,
		0x1AA9637B42D0186CULL,
		0x0001EA9C4AA4EA2FULL
	}};
	shift = 49;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAEC0BC5E253E7D83ULL,
		0x5D6900F4BF40B83FULL,
		0x3B63DBC374211BA0ULL,
		0xF6B0060D1AE8E5E4ULL,
		0x75B8075695F2D85EULL,
		0x84578FEAA7F87DD4ULL,
		0xBCD57CCBE3E44F1BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4A7CFB06000000ULL,
		0xE97E81707F5D8178ULL,
		0x86E8423740BAD201ULL,
		0x1A35D1CBC876C7B7ULL,
		0xAD2BE5B0BDED600CULL,
		0xD54FF0FBA8EB700EULL,
		0x97C7C89E3708AF1FULL,
		0x000000000179AAF9ULL
	}};
	shift = 25;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75B9E2ADAB40BA8FULL,
		0x58DA9230CE3CE4BDULL,
		0x521315E445216737ULL,
		0x1C91631EB1C8B0ABULL,
		0xB5888E88D592D4FFULL,
		0x08612A391C1FAB09ULL,
		0x5072ECF381460654ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA3C00000000000ULL,
		0x392F5D6E78AB6AD0ULL,
		0x59CDD636A48C338FULL,
		0x2C2AD484C5791148ULL,
		0xB53FC72458C7AC72ULL,
		0xEAC26D6223A23564ULL,
		0x819502184A8E4707ULL,
		0x0000141CBB3CE051ULL
	}};
	shift = 46;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x36D4C1632551DFDBULL,
		0x6F61CE9B37803197ULL,
		0xEF77E457977C60FCULL,
		0xEC2B3BEC71FA5DE1ULL,
		0x865098E58B7F22FEULL,
		0x5EA457035F60F93AULL,
		0xE669A9BBF4693487ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58C95477F6C00000ULL,
		0xA6CDE00C65CDB530ULL,
		0x15E5DF183F1BD873ULL,
		0xFB1C7E97787BDDF9ULL,
		0x3962DFC8BFBB0ACEULL,
		0xC0D7D83E4EA19426ULL,
		0x6EFD1A4D21D7A915ULL,
		0x0000000000399A6AULL
	}};
	shift = 22;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3E8D7196F2CF7251ULL,
		0x9F4443DFC940CAABULL,
		0x14D8BBBFBB00A222ULL,
		0xC6F362D0045801FDULL,
		0xEF8077F52C3F1859ULL,
		0x4A67983D1652D848ULL,
		0x5B7F71390E369587ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0x59F46B8CB7967B92ULL,
		0x14FA221EFE4A0655ULL,
		0xE8A6C5DDFDD80511ULL,
		0xCE379B168022C00FULL,
		0x477C03BFA961F8C2ULL,
		0x3A533CC1E8B296C2ULL,
		0x02DBFB89C871B4ACULL
	}};
	shift = 59;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3CEC38611B50AD5AULL,
		0x679AD69B45FB7D99ULL,
		0x26953FFF876DFBE6ULL,
		0x9FD5275FD9C99D36ULL,
		0xF921012892AA21CCULL,
		0x17561907A26DD363ULL,
		0xC29B5CA0F07A3A23ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38611B50AD5A0000ULL,
		0xD69B45FB7D993CECULL,
		0x3FFF876DFBE6679AULL,
		0x275FD9C99D362695ULL,
		0x012892AA21CC9FD5ULL,
		0x1907A26DD363F921ULL,
		0x5CA0F07A3A231756ULL,
		0x000000000000C29BULL
	}};
	shift = 16;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC1C22142C6D4FEDDULL,
		0x54DEDEA56E8EE16DULL,
		0x759E8991DCF88AC1ULL,
		0x0D384569DB69F493ULL,
		0x41A2B9673868D930ULL,
		0x31B6DAE61001AA4BULL,
		0x6F7F5C5F5D3F7434ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C22142C6D4FEDD0ULL,
		0x4DEDEA56E8EE16DCULL,
		0x59E8991DCF88AC15ULL,
		0xD384569DB69F4937ULL,
		0x1A2B9673868D9300ULL,
		0x1B6DAE61001AA4B4ULL,
		0xF7F5C5F5D3F74343ULL,
		0x0000000000000006ULL
	}};
	shift = 4;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8EFAFB6B20D6B255ULL,
		0x1E2F3144576714E1ULL,
		0x8F9CDEDFDAB8139CULL,
		0xCACC312792E8811BULL,
		0xBFCD7242C37D5B81ULL,
		0x616ADE648518876CULL,
		0x055D458A229C3356ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0x18EFAFB6B20D6B25ULL,
		0xC1E2F3144576714EULL,
		0xB8F9CDEDFDAB8139ULL,
		0x1CACC312792E8811ULL,
		0xCBFCD7242C37D5B8ULL,
		0x6616ADE648518876ULL,
		0x0055D458A229C335ULL
	}};
	shift = 60;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9AE69A648B32D89EULL,
		0x7FB3AF7FAD8988E9ULL,
		0x99BD07E093B5E5D0ULL,
		0xD7F57E101A103FF2ULL,
		0xE95C5583C120B06DULL,
		0x2F95883037B000CAULL,
		0x587C30642A03B318ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A648B32D89E0000ULL,
		0xAF7FAD8988E99AE6ULL,
		0x07E093B5E5D07FB3ULL,
		0x7E101A103FF299BDULL,
		0x5583C120B06DD7F5ULL,
		0x883037B000CAE95CULL,
		0x30642A03B3182F95ULL,
		0x000000000000587CULL
	}};
	shift = 16;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3047346A93EB71DDULL,
		0xD58F2FFB507F098FULL,
		0x834D0BFD9FDE14F4ULL,
		0x37AC9AF664C549C9ULL,
		0x3B7C2D2CF5748827ULL,
		0x536E25898632E0B9ULL,
		0xD4609045CE6DF1FFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD527D6E3BA000000ULL,
		0xF6A0FE131E608E68ULL,
		0xFB3FBC29E9AB1E5FULL,
		0xECC98A9393069A17ULL,
		0x59EAE9104E6F5935ULL,
		0x130C65C17276F85AULL,
		0x8B9CDBE3FEA6DC4BULL,
		0x0000000001A8C120ULL
	}};
	shift = 25;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7AC368DF6BBF89B3ULL,
		0x2B1B183FB65CC659ULL,
		0xF228B5330AA53029ULL,
		0x412183CCEB1AD230ULL,
		0xC002634755C68C21ULL,
		0xCE6DE2D4AA1E6024ULL,
		0x353A5AFF2D1F65A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37DAEFE26CC00000ULL,
		0x0FED9731965EB0DAULL,
		0x4CC2A94C0A4AC6C6ULL,
		0xF33AC6B48C3C8A2DULL,
		0xD1D571A308504860ULL,
		0xB52A879809300098ULL,
		0xBFCB47D968F39B78ULL,
		0x00000000000D4E96ULL
	}};
	shift = 22;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB74C110881800357ULL,
		0x090DF86EA97A6C73ULL,
		0x4A775513BD11C5B4ULL,
		0xFA3328A0D1649FB1ULL,
		0x0C57E1C1643B139FULL,
		0x25E895A16FB5F165ULL,
		0x25DAD3C2886B6228ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x088440C001AB8000ULL,
		0xFC3754BD3639DBA6ULL,
		0xAA89DE88E2DA0486ULL,
		0x945068B24FD8A53BULL,
		0xF0E0B21D89CFFD19ULL,
		0x4AD0B7DAF8B2862BULL,
		0x69E14435B11412F4ULL,
		0x00000000000012EDULL
	}};
	shift = 15;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8DF3D4CBC89751ECULL,
		0xF8F49BC87BEC595EULL,
		0x8851CBBE32F0DB3FULL,
		0x2DC9129C5241933BULL,
		0x05E7884B47BCAF29ULL,
		0x1C3879E0E48F828FULL,
		0xE13AFFE60B188829ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D80000000000000ULL,
		0x2BD1BE7A997912EAULL,
		0x67FF1E93790F7D8BULL,
		0x67710A3977C65E1BULL,
		0xE525B922538A4832ULL,
		0x51E0BCF10968F795ULL,
		0x0523870F3C1C91F0ULL,
		0x001C275FFCC16311ULL
	}};
	shift = 53;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0F58CBB1F514C582ULL,
		0x4159A47C0DE91550ULL,
		0x908AB5EFB66213A2ULL,
		0xA4D8A91478CD7AC2ULL,
		0x4444E22757BC4F78ULL,
		0x2B6D6A5BDF229A34ULL,
		0x7DF55022D5CE28C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763EA298B0400000ULL,
		0x8F81BD22AA01EB19ULL,
		0xBDF6CC4274482B34ULL,
		0x228F19AF58521156ULL,
		0x44EAF789EF149B15ULL,
		0x4B7BE4534688889CULL,
		0x045AB9C518056DADULL,
		0x00000000000FBEAAULL
	}};
	shift = 21;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2C03C7D55E84659EULL,
		0x2626BF07A14E4E5CULL,
		0xFB5316482B464F61ULL,
		0x8664ECB803CBE067ULL,
		0x09ECBBE2C1E69544ULL,
		0x19307CFA86BCA974ULL,
		0x866A4B8572EA19CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAABD08CB3C00000ULL,
		0xE0F429C9CB858078ULL,
		0xC90568C9EC24C4D7ULL,
		0x9700797C0CFF6A62ULL,
		0x7C583CD2A890CC9DULL,
		0x9F50D7952E813D97ULL,
		0x70AE5D4339E3260FULL,
		0x000000000010CD49ULL
	}};
	shift = 21;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x16EB0B9C585D5E6FULL,
		0x6FBED9AD578936D9ULL,
		0x8DDC2300D62AA2F8ULL,
		0xD7611C09FFD1923DULL,
		0xA27B3437D83E5482ULL,
		0xA7D05AC63D7CCC6AULL,
		0x9814B47B1B98D80AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C2EAF3780000000ULL,
		0xABC49B6C8B7585CEULL,
		0x6B15517C37DF6CD6ULL,
		0xFFE8C91EC6EE1180ULL,
		0xEC1F2A416BB08E04ULL,
		0x1EBE6635513D9A1BULL,
		0x8DCC6C0553E82D63ULL,
		0x000000004C0A5A3DULL
	}};
	shift = 31;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2CD7235298C0C0BCULL,
		0x04C3FC13ADAA3BC0ULL,
		0x1B21F33A04545166ULL,
		0x5F2C72BE9FD91D75ULL,
		0x87F5E72D171B829CULL,
		0x0D5F9D5FE0A276F0ULL,
		0x7926EF7644B6FE8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C60605E00000000ULL,
		0xD6D51DE0166B91A9ULL,
		0x022A28B30261FE09ULL,
		0x4FEC8EBA8D90F99DULL,
		0x8B8DC14E2F96395FULL,
		0xF0513B7843FAF396ULL,
		0x225B7F4786AFCEAFULL,
		0x000000003C9377BBULL
	}};
	shift = 31;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD33FF84164841563ULL,
		0x82EA105B372919CAULL,
		0xEBCD979A186A45A8ULL,
		0xDB183A498B3DA581ULL,
		0xFF1AE49C6B514A6DULL,
		0xA8BB0210C654DFC5ULL,
		0x41130D759E861FBFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33FF841648415630ULL,
		0x2EA105B372919CADULL,
		0xBCD979A186A45A88ULL,
		0xB183A498B3DA581EULL,
		0xF1AE49C6B514A6DDULL,
		0x8BB0210C654DFC5FULL,
		0x1130D759E861FBFAULL,
		0x0000000000000004ULL
	}};
	shift = 4;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAF04167A18C475F2ULL,
		0xE92649E931058605ULL,
		0x6861BB246D141ED9ULL,
		0xDD83B6362E56E059ULL,
		0x007B7827EB68DA04ULL,
		0x330F24516B57F3B8ULL,
		0xEC7E9C9D29C38A5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AF900000000000ULL,
		0x2C302D7820B3D0C6ULL,
		0xA0F6CF49324F4988ULL,
		0xB702CB430DD92368ULL,
		0x46D026EC1DB1B172ULL,
		0xBF9DC003DBC13F5BULL,
		0x1C52D99879228B5AULL,
		0x00000763F4E4E94EULL
	}};
	shift = 43;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB8E7EE666C1635E0ULL,
		0xEB1063FD7FB29751ULL,
		0xFD1506BAF222C405ULL,
		0x4A2FFC0A974D9549ULL,
		0xE79AEED6AA703BA7ULL,
		0xBCD5982030791F65ULL,
		0xDF419454741473B0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E00000000000000ULL,
		0x751B8E7EE666C163ULL,
		0x405EB1063FD7FB29ULL,
		0x549FD1506BAF222CULL,
		0xBA74A2FFC0A974D9ULL,
		0xF65E79AEED6AA703ULL,
		0x3B0BCD5982030791ULL,
		0x000DF41945474147ULL
	}};
	shift = 52;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6854D47734735172ULL,
		0xADE9E8B5C1907F69ULL,
		0x648C50AAC113FF52ULL,
		0x86286EFC709DDB4EULL,
		0xAC272A4FD67DD6E8ULL,
		0x409EDC7E50AE1209ULL,
		0x26B175311F4E5F4CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45C800000000000ULL,
		0x1FDA5A15351DCD1CULL,
		0xFFD4AB7A7A2D7064ULL,
		0x76D39923142AB044ULL,
		0x75BA218A1BBF1C27ULL,
		0x84826B09CA93F59FULL,
		0x97D31027B71F942BULL,
		0x000009AC5D4C47D3ULL
	}};
	shift = 46;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0E2E1360E900414CULL,
		0xF1981CD6E02D1FA2ULL,
		0xA088261BE643A915ULL,
		0xDA5EC4FE902D2680ULL,
		0xF71D2C5CE57AE13CULL,
		0x0396AE3A7C3CFD52ULL,
		0xF340144416BA476EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0530000000000000ULL,
		0x7E8838B84D83A401ULL,
		0xA457C660735B80B4ULL,
		0x9A028220986F990EULL,
		0x84F3697B13FA40B4ULL,
		0xF54BDC74B17395EBULL,
		0x1DB80E5AB8E9F0F3ULL,
		0x0003CD0051105AE9ULL
	}};
	shift = 50;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB268BD4EC4E3EB42ULL,
		0x961CC4CCEF2CFCCEULL,
		0x0B9A319F83713C5DULL,
		0xBC7A771CE5F92920ULL,
		0x46E5098A33E25D04ULL,
		0x6A0AFC07C57CB58EULL,
		0x6462D1DCE2871C24ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9345EA76271F5A10ULL,
		0xB0E626677967E675ULL,
		0x5CD18CFC1B89E2ECULL,
		0xE3D3B8E72FC94900ULL,
		0x37284C519F12E825ULL,
		0x5057E03E2BE5AC72ULL,
		0x23168EE71438E123ULL,
		0x0000000000000003ULL
	}};
	shift = 3;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x44BD1AAB9FCD2202ULL,
		0xCF9443729EF4957BULL,
		0x51CBBA443FC9E268ULL,
		0xAC69EF50A107464FULL,
		0xAA01C35A59C974C4ULL,
		0xF29A14806E75C226ULL,
		0x15821C7658E5F3E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6910100000000000ULL,
		0xA4ABDA25E8D55CFEULL,
		0x4F13467CA21B94F7ULL,
		0x3A327A8E5DD221FEULL,
		0x4BA625634F7A8508ULL,
		0xAE1135500E1AD2CEULL,
		0x2F9F2F94D0A40373ULL,
		0x000000AC10E3B2C7ULL
	}};
	shift = 43;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x54B953E1E1D1DA9EULL,
		0x8B237636F1CB8204ULL,
		0x6CFB5210A6065156ULL,
		0x71075235F79DA2D1ULL,
		0xD424E014CE4108E6ULL,
		0xC801D2DB06EF2D66ULL,
		0x1E9AFEAAB2B1715CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1D1DA9E0000000ULL,
		0x6F1CB820454B953EULL,
		0x0A60651568B23763ULL,
		0x5F79DA2D16CFB521ULL,
		0x4CE4108E67107523ULL,
		0xB06EF2D66D424E01ULL,
		0xAB2B1715CC801D2DULL,
		0x0000000001E9AFEAULL
	}};
	shift = 28;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF327190FEB43038BULL,
		0xCFF35FB66D009269ULL,
		0xAA8AA47F229BE716ULL,
		0xD63984A72FA817F6ULL,
		0xF8B60E8B3348BEC1ULL,
		0x39CB8B5D3DF1EC8FULL,
		0xD917B44364FB10C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD6860716000000ULL,
		0x6CDA0124D3E64E32ULL,
		0xFE4537CE2D9FE6BFULL,
		0x4E5F502FED551548ULL,
		0x1666917D83AC7309ULL,
		0xBA7BE3D91FF16C1DULL,
		0x86C9F62186739716ULL,
		0x0000000001B22F68ULL
	}};
	shift = 25;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5147DF86B2A59B17ULL,
		0xA6CF905CC1CF8630ULL,
		0xF96CB9144229C6DEULL,
		0xD4B84BF9E00E8D2FULL,
		0x706982EA1C980AEAULL,
		0x486501201EFE0111ULL,
		0x4B93C8E0DA1BF2ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7E1ACA966C5C00ULL,
		0x3E4173073E18C145ULL,
		0xB2E45108A71B7A9BULL,
		0xE12FE7803A34BFE5ULL,
		0xA60BA872602BAB52ULL,
		0x9404807BF80445C1ULL,
		0x4F2383686FCAB121ULL,
		0x000000000000012EULL
	}};
	shift = 10;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF4ECA346AADB0264ULL,
		0x7FC209E746765351ULL,
		0x27477730AF9C9994ULL,
		0xEEE04A5FAD09D915ULL,
		0xBB0BF8C519D31FD0ULL,
		0x5487826578BF20D5ULL,
		0x9B51171FB9D87151ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1AAB6C099000000ULL,
		0x79D19D94D47D3B28ULL,
		0xCC2BE726651FF082ULL,
		0x97EB42764549D1DDULL,
		0x314674C7F43BB812ULL,
		0x995E2FC8356EC2FEULL,
		0xC7EE761C545521E0ULL,
		0x000000000026D445ULL
	}};
	shift = 22;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB548A9E68FC55DEFULL,
		0xC5435F9485A45DEFULL,
		0xF90629EAAB82D463ULL,
		0x66B7080E523A54BDULL,
		0xA24102F9D2EE3188ULL,
		0x6E4B923CF737913DULL,
		0x5C163FBC01E1322DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xED522A79A3F1577BULL,
		0xF150D7E52169177BULL,
		0x7E418A7AAAE0B518ULL,
		0x19ADC203948E952FULL,
		0x689040BE74BB8C62ULL,
		0x5B92E48F3DCDE44FULL,
		0x17058FEF00784C8BULL
	}};
	shift = 62;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x00A95BD6719CC65BULL,
		0x9522BD515D476D34ULL,
		0x97B4C694EB87F881ULL,
		0x4DC6041C1ED9437FULL,
		0x478AE9E8E0F3106EULL,
		0x6AFDC8415E25A7A4ULL,
		0xC6A5072DE31D88D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F59C673196C000ULL,
		0xAF545751DB4D002AULL,
		0x31A53AE1FE206548ULL,
		0x810707B650DFE5EDULL,
		0xBA7A383CC41B9371ULL,
		0x7210578969E911E2ULL,
		0x41CB78C762359ABFULL,
		0x00000000000031A9ULL
	}};
	shift = 14;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF4BFC25B5E57B431ULL,
		0x3BE04F5FCC72C497ULL,
		0x4492B20A257F87B5ULL,
		0x8CEBBA63DE721849ULL,
		0x75E23B0E9FF2B200ULL,
		0x531A9C7FED0AFAB8ULL,
		0x8DB3042D9A9E9C5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF6862000000000ULL,
		0x8E5892FE97F84B6BULL,
		0xAFF0F6A77C09EBF9ULL,
		0xCE43092892564144ULL,
		0xFE5640119D774C7BULL,
		0xA15F570EBC4761D3ULL,
		0x53D38B4A63538FFDULL,
		0x00000011B66085B3ULL
	}};
	shift = 37;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDF3F31B98E19457CULL,
		0x564C2774CB6DBCB6ULL,
		0x05A6647DDF60F5AEULL,
		0x8A07C231683DE62AULL,
		0xF7BD44B1992F5D4AULL,
		0xAA71892EF163EFC7ULL,
		0x7FA606F9456D6824ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98DCC70CA2BE0000ULL,
		0x13BA65B6DE5B6F9FULL,
		0x323EEFB07AD72B26ULL,
		0xE118B41EF31502D3ULL,
		0xA258CC97AEA54503ULL,
		0xC49778B1F7E3FBDEULL,
		0x037CA2B6B4125538ULL,
		0x0000000000003FD3ULL
	}};
	shift = 15;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAB20919DD0B614DAULL,
		0x5AD20A39D6CE230BULL,
		0xC70D1EAA452FA877ULL,
		0x57BA3C859A0DB275ULL,
		0x1915C1F58349680EULL,
		0xC15F033635F6CB0EULL,
		0x9F16B0EAD2A0B992ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7742D85368000000ULL,
		0xE75B388C2EAC8246ULL,
		0xA914BEA1DD6B4828ULL,
		0x166836C9D71C347AULL,
		0xD60D25A0395EE8F2ULL,
		0xD8D7DB2C38645707ULL,
		0xAB4A82E64B057C0CULL,
		0x00000000027C5AC3ULL
	}};
	shift = 26;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5910D13C69AFD401ULL,
		0x0E9AB0E116084D2FULL,
		0xA546194CA72DE8F5ULL,
		0xD182CD0D720558A4ULL,
		0xBEAC5E112210AA3FULL,
		0xCDF616EC9300A7C1ULL,
		0xCB89D4E243612B13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C69AFD401000000ULL,
		0xE116084D2F5910D1ULL,
		0x4CA72DE8F50E9AB0ULL,
		0x0D720558A4A54619ULL,
		0x112210AA3FD182CDULL,
		0xEC9300A7C1BEAC5EULL,
		0xE243612B13CDF616ULL,
		0x0000000000CB89D4ULL
	}};
	shift = 24;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCF7B085B689828BBULL,
		0xA5781AB2C96DEEACULL,
		0x8BB89417CCF8039BULL,
		0x196E8E13207E7B8CULL,
		0x2E2D6BBD5F8E074FULL,
		0x1E47E7FD0CD6D701ULL,
		0x0407385112A315F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC216DA260A2EC00ULL,
		0xE06ACB25B7BAB33DULL,
		0xE2505F33E00E6E95ULL,
		0xBA384C81F9EE322EULL,
		0xB5AEF57E381D3C65ULL,
		0x1F9FF4335B5C04B8ULL,
		0x1CE1444A8C57D079ULL,
		0x0000000000000010ULL
	}};
	shift = 10;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0F6CD53903106A4CULL,
		0x91901A4999AF991BULL,
		0x7F3D206B635DE4D8ULL,
		0x982F74BBED66AB68ULL,
		0x0F03E29C83E94BEAULL,
		0x5A5964F3A6806292ULL,
		0x51FEA7B2D9E982A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3903106A4C000000ULL,
		0x4999AF991B0F6CD5ULL,
		0x6B635DE4D891901AULL,
		0xBBED66AB687F3D20ULL,
		0x9C83E94BEA982F74ULL,
		0xF3A68062920F03E2ULL,
		0xB2D9E982A95A5964ULL,
		0x000000000051FEA7ULL
	}};
	shift = 24;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x36340E9B4363DF43ULL,
		0x916A2C2E6B7EA423ULL,
		0x952A95EC841553D7ULL,
		0xBE3A8515A4090E9BULL,
		0x59DC48305DAE102AULL,
		0x93CCCC238E0EC8B9ULL,
		0x2E48DF5951BE705CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1EFA18000000000ULL,
		0xBF52119B1A074DA1ULL,
		0x0AA9EBC8B5161735ULL,
		0x04874DCA954AF642ULL,
		0xD708155F1D428AD2ULL,
		0x07645CACEE24182EULL,
		0xDF382E49E66611C7ULL,
		0x00000017246FACA8ULL
	}};
	shift = 39;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x214E4CE76C87FBFDULL,
		0xEBB3350A7F3B365EULL,
		0xD536CD3F2B8D7D6DULL,
		0x19332611A231510BULL,
		0xA0BFF7C6075A7A8CULL,
		0x8C111617BF5A0539ULL,
		0x53C62F49562D2C70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643FDFE800000000ULL,
		0xF9D9B2F10A72673BULL,
		0x5C6BEB6F5D99A853ULL,
		0x118A885EA9B669F9ULL,
		0x3AD3D460C999308DULL,
		0xFAD029CD05FFBE30ULL,
		0xB16963846088B0BDULL,
		0x000000029E317A4AULL
	}};
	shift = 35;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4A2742E6BB4D3408ULL,
		0x79013B88EC44DBFBULL,
		0xBF7CA483F92929A1ULL,
		0xA07F3780CE089C96ULL,
		0x9ED0F2B2EAF268E0ULL,
		0x259611B720C9737EULL,
		0x6D0AC5BDE7BC16E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B9AED34D0200000ULL,
		0xEE23B1136FED289DULL,
		0x920FE4A4A685E404ULL,
		0xDE033822725AFDF2ULL,
		0xCACBABC9A38281FCULL,
		0x46DC8325CDFA7B43ULL,
		0x16F79EF05B809658ULL,
		0x000000000001B42BULL
	}};
	shift = 18;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x295E6A64F7062D70ULL,
		0x6A4E22DEC1926212ULL,
		0x443F0D59F5C885E0ULL,
		0xE89C2C4D349EA8D6ULL,
		0xEC14F2AA32E887A8ULL,
		0x51624F5817233C09ULL,
		0xD16971229ECA1C38ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x452BCD4C9EE0C5AEULL,
		0x0D49C45BD8324C42ULL,
		0xC887E1AB3EB910BCULL,
		0x1D138589A693D51AULL,
		0x3D829E55465D10F5ULL,
		0x0A2C49EB02E46781ULL,
		0x1A2D2E2453D94387ULL
	}};
	shift = 61;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA91A6FDCA112E1E7ULL,
		0xDE2A0EBC575952F3ULL,
		0x7D294C506122F80DULL,
		0x1754B1BD0A35407DULL,
		0xD46E7F94580258BDULL,
		0x954BDEAE336472B6ULL,
		0x2E82ABCC96CE9C76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4225C3CE00000000ULL,
		0xAEB2A5E75234DFB9ULL,
		0xC245F01BBC541D78ULL,
		0x146A80FAFA5298A0ULL,
		0xB004B17A2EA9637AULL,
		0x66C8E56DA8DCFF28ULL,
		0x2D9D38ED2A97BD5CULL,
		0x000000005D055799ULL
	}};
	shift = 33;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7FA6D222EAC084A8ULL,
		0xED20777301FF9A03ULL,
		0xE6527378788012CEULL,
		0x9593564D3C02016BULL,
		0x6231FCC9FC6E4FA6ULL,
		0x03B661F600555B58ULL,
		0xE0E38F5142BE7046ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0x06FF4DA445D58109ULL,
		0x9DDA40EEE603FF34ULL,
		0xD7CCA4E6F0F10025ULL,
		0x4D2B26AC9A780402ULL,
		0xB0C463F993F8DC9FULL,
		0x8C076CC3EC00AAB6ULL,
		0x01C1C71EA2857CE0ULL
	}};
	shift = 57;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA92995B17BF98CC7ULL,
		0xE4D2B22F1CB3B2AEULL,
		0x7C5AF4F1854BF9FDULL,
		0xBA0D64EA563B592EULL,
		0x9B579C361AF37E51ULL,
		0x0CF83FCC0A3E4FAEULL,
		0xDB2913AB46733491ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B17BF98CC70000ULL,
		0xB22F1CB3B2AEA929ULL,
		0xF4F1854BF9FDE4D2ULL,
		0x64EA563B592E7C5AULL,
		0x9C361AF37E51BA0DULL,
		0x3FCC0A3E4FAE9B57ULL,
		0x13AB467334910CF8ULL,
		0x000000000000DB29ULL
	}};
	shift = 16;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAE6614CBDFF0D063ULL,
		0xC4F7E8F7BE166806ULL,
		0xC2718313FDC42E38ULL,
		0x3EA2C8A8027B7AC0ULL,
		0xD40899E23C715E03ULL,
		0xC923CFA76D36DB56ULL,
		0xE6927DB92CCAFD44ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C60000000000000ULL,
		0x00D5CCC2997BFE1AULL,
		0xC7189EFD1EF7C2CDULL,
		0x58184E30627FB885ULL,
		0xC067D45915004F6FULL,
		0x6ADA81133C478E2BULL,
		0xA8992479F4EDA6DBULL,
		0x001CD24FB725995FULL
	}};
	shift = 53;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD6DA6F5D351E1A0AULL,
		0x40F0E72D7EF46CB6ULL,
		0x63DAC123CD7D238BULL,
		0xB207ADA8BFE10C95ULL,
		0xB2C8923748CA8EA8ULL,
		0xBFC46E0D7A67CB27ULL,
		0xB08F4F6B7FD13ABDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1400000000000000ULL,
		0x6DADB4DEBA6A3C34ULL,
		0x1681E1CE5AFDE8D9ULL,
		0x2AC7B582479AFA47ULL,
		0x51640F5B517FC219ULL,
		0x4F6591246E91951DULL,
		0x7B7F88DC1AF4CF96ULL,
		0x01611E9ED6FFA275ULL
	}};
	shift = 57;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x028891808860F305ULL,
		0xC13C5DBC026B8185ULL,
		0x9253D5B3A9A1BC31ULL,
		0x65A48792BE302312ULL,
		0x4ACEB733766DBD11ULL,
		0x161D650C01CD0258ULL,
		0xAD69D6F1EA95639DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022183CC14000000ULL,
		0xF009AE06140A2246ULL,
		0xCEA686F0C704F176ULL,
		0x4AF8C08C4A494F56ULL,
		0xCDD9B6F44596921EULL,
		0x30073409612B3ADCULL,
		0xC7AA558E74587594ULL,
		0x0000000002B5A75BULL
	}};
	shift = 26;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA6FF293C1F527CB6ULL,
		0xBEDE515D8931A005ULL,
		0x8AB4EB36A97AB261ULL,
		0xA3BBD5D542EF12E5ULL,
		0x11E188E62DB1FF50ULL,
		0xA242C7781C72506AULL,
		0x69A15C4015C0D0DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x69BFCA4F07D49F2DULL,
		0x6FB79457624C6801ULL,
		0x62AD3ACDAA5EAC98ULL,
		0x28EEF57550BBC4B9ULL,
		0x847862398B6C7FD4ULL,
		0x6890B1DE071C941AULL,
		0x1A68571005703437ULL
	}};
	shift = 62;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA816F50B41266B2AULL,
		0xCBE2676C4C963A38ULL,
		0xCC6F58C3C8D9BAE7ULL,
		0x0D2462A1E13F0FFEULL,
		0x271EB547CBCE36FDULL,
		0x315E4EDD308F80FEULL,
		0xF7F20A90B36C16CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A09335950000000ULL,
		0x6264B1D1C540B7A8ULL,
		0x1E46CDD73E5F133BULL,
		0x0F09F87FF6637AC6ULL,
		0x3E5E71B7E8692315ULL,
		0xE9847C07F138F5AAULL,
		0x859B60B6618AF276ULL,
		0x0000000007BF9054ULL
	}};
	shift = 27;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B3E813A5ED1F65DULL,
		0x059CABEB844E2577ULL,
		0x92B5B5BA58680BC4ULL,
		0xC21C2461721EF0F3ULL,
		0xFCD78E2D632E8A90ULL,
		0x3EBA83CB00F74135ULL,
		0xF24D4C38672ED542ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167D0274BDA3ECBAULL,
		0x0B3957D7089C4AEFULL,
		0x256B6B74B0D01788ULL,
		0x843848C2E43DE1E7ULL,
		0xF9AF1C5AC65D1521ULL,
		0x7D75079601EE826BULL,
		0xE49A9870CE5DAA84ULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3F9558D21D749CCAULL,
		0x80E77824FB6407FAULL,
		0x90A6112316DD64F1ULL,
		0x0F83B3C2FD06BD0BULL,
		0x69662B822CDE4759ULL,
		0x2023DAA58590E587ULL,
		0xEE86621AB9BB34B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC690EBA4E65000ULL,
		0x3BC127DB203FD1FCULL,
		0x308918B6EB278C07ULL,
		0x1D9E17E835E85C85ULL,
		0x315C1166F23AC87CULL,
		0x1ED52C2C872C3B4BULL,
		0x3310D5CDD9A58901ULL,
		0x0000000000000774ULL
	}};
	shift = 11;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1DA949E62C9F9640ULL,
		0x9C4F276045FCA252ULL,
		0x5B1D72D43EC1448FULL,
		0x2DE63AB02B84EB7DULL,
		0x9143097F427B0606ULL,
		0xBA6F21EC9EBFAD38ULL,
		0xF903B48804A25CFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9640000000000000ULL,
		0xA2521DA949E62C9FULL,
		0x448F9C4F276045FCULL,
		0xEB7D5B1D72D43EC1ULL,
		0x06062DE63AB02B84ULL,
		0xAD389143097F427BULL,
		0x5CFABA6F21EC9EBFULL,
		0x0000F903B48804A2ULL
	}};
	shift = 48;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9C6B87746D31590FULL,
		0x94EB042A4431C077ULL,
		0xA477E870EE98B0AEULL,
		0x2C71269AA96382BFULL,
		0x3EAD36D9E5E4E14CULL,
		0x03E04272FDD513C0ULL,
		0x57B4712DEB5D9CB7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F00000000000000ULL,
		0x779C6B87746D3159ULL,
		0xAE94EB042A4431C0ULL,
		0xBFA477E870EE98B0ULL,
		0x4C2C71269AA96382ULL,
		0xC03EAD36D9E5E4E1ULL,
		0xB703E04272FDD513ULL,
		0x0057B4712DEB5D9CULL
	}};
	shift = 56;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x84B9E101A0431935ULL,
		0x96230766E64D9B60ULL,
		0xE56D4B130C62B752ULL,
		0x8776182101906EE6ULL,
		0x298D70EB309C4CBCULL,
		0x281F76D2C4C604A5ULL,
		0xB28529C7845B2E5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2034086326A00000ULL,
		0xECDCC9B36C10973CULL,
		0x62618C56EA52C460ULL,
		0x0420320DDCDCADA9ULL,
		0x1D6613899790EEC3ULL,
		0xDA5898C094A531AEULL,
		0x38F08B65CB4503EEULL,
		0x00000000001650A5ULL
	}};
	shift = 21;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0101CEB58F1D8034ULL,
		0x6AB6056434F10D56ULL,
		0xE8A0129DB4FFBACFULL,
		0x230FACA94A09D465ULL,
		0xD69B0BD82E2020EAULL,
		0x2BE5D46F5EC7ED02ULL,
		0x4E80CE04CE98379CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E75AC78EC01A000ULL,
		0xB02B21A7886AB008ULL,
		0x0094EDA7FDD67B55ULL,
		0x7D654A504EA32F45ULL,
		0xD85EC17101075118ULL,
		0x2EA37AF63F6816B4ULL,
		0x06702674C1BCE15FULL,
		0x0000000000000274ULL
	}};
	shift = 11;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA9F49F01B3C7598FULL,
		0xAA39CF445889D35BULL,
		0x1C456A9894963476ULL,
		0x1C59681730EBF8C0ULL,
		0x287B8A495F239F84ULL,
		0x3BFAAD68C760BC81ULL,
		0x6B6C999D660D35AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3ACC78000000000ULL,
		0x44E9ADD4FA4F80D9ULL,
		0x4B1A3B551CE7A22CULL,
		0x75FC600E22B54C4AULL,
		0x91CFC20E2CB40B98ULL,
		0xB05E40943DC524AFULL,
		0x069AD51DFD56B463ULL,
		0x00000035B64CCEB3ULL
	}};
	shift = 39;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB9207E027F8BF2CAULL,
		0x0F49D8C467F31933ULL,
		0xD8AD6FAB207ED399ULL,
		0x99024A382F07CAAEULL,
		0xC1205675048FB188ULL,
		0x4721B33B777C93F9ULL,
		0xFF7F02B62CEAAC14ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x481F809FE2FCB280ULL,
		0xD2763119FCC64CEEULL,
		0x2B5BEAC81FB4E643ULL,
		0x40928E0BC1F2ABB6ULL,
		0x48159D4123EC6226ULL,
		0xC86CCEDDDF24FE70ULL,
		0xDFC0AD8B3AAB0511ULL,
		0x000000000000003FULL
	}};
	shift = 6;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x21F5BD2568C4B317ULL,
		0x73A410A514BDB182ULL,
		0x52C5472E23FAEB92ULL,
		0x40D7D7F83DA7D9C3ULL,
		0x7B4517EEF9582A3FULL,
		0x3B80F8E1E85D81C4ULL,
		0xB56196D08880DD99ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C0000000000000ULL,
		0x60887D6F495A312CULL,
		0xE49CE90429452F6CULL,
		0x70D4B151CB88FEBAULL,
		0x8FD035F5FE0F69F6ULL,
		0x711ED145FBBE560AULL,
		0x664EE03E387A1760ULL,
		0x002D5865B4222037ULL
	}};
	shift = 54;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x71F971A4F6D0B3C1ULL,
		0x24D5C9FB8716D50BULL,
		0xD84A4C55BB098CB2ULL,
		0x8186496292813B9CULL,
		0x9F96A72B7ED5E629ULL,
		0x649D055CEF642697ULL,
		0x85C911C52EEF8F4BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E0800000000000ULL,
		0x6A85B8FCB8D27B68ULL,
		0xC659126AE4FDC38BULL,
		0x9DCE6C25262ADD84ULL,
		0xF314C0C324B14940ULL,
		0x134BCFCB5395BF6AULL,
		0xC7A5B24E82AE77B2ULL,
		0x000042E488E29777ULL
	}};
	shift = 47;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3BF906232360B008ULL,
		0x15AB7819D77246CCULL,
		0x27A740321B9C8091ULL,
		0x206B610D05DFFEF0ULL,
		0x60E52EA7380DAE2DULL,
		0xE60BC1C1B292CF8FULL,
		0xD62503376D5DAB87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x877F20C4646C1601ULL,
		0x22B56F033AEE48D9ULL,
		0x04F4E80643739012ULL,
		0xA40D6C21A0BBFFDEULL,
		0xEC1CA5D4E701B5C5ULL,
		0xFCC17838365259F1ULL,
		0x1AC4A066EDABB570ULL
	}};
	shift = 61;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2F1F9174F7B23DD2ULL,
		0x1D6C43273F8ADC91ULL,
		0xE9604DDAC859CA08ULL,
		0x785B9058CE3C96DEULL,
		0xD6A17939FA53458AULL,
		0x804F6BC40EFA1DDEULL,
		0xC6EE8D64B4EBF587ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7B23DD20000000ULL,
		0x73F8ADC912F1F917ULL,
		0xAC859CA081D6C432ULL,
		0x8CE3C96DEE9604DDULL,
		0x9FA53458A785B905ULL,
		0x40EFA1DDED6A1793ULL,
		0x4B4EBF587804F6BCULL,
		0x000000000C6EE8D6ULL
	}};
	shift = 28;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF94519E629AF10AFULL,
		0xCB184FCF6B25ADF2ULL,
		0xC22F39C7D752AAB5ULL,
		0x8DFF607F21BE7B9BULL,
		0xC94D2EE4D35A7B62ULL,
		0x3D7D42D140759C43ULL,
		0x8E0E839C7E97A37FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5146798A6BC42BCULL,
		0x2C613F3DAC96B7CBULL,
		0x08BCE71F5D4AAAD7ULL,
		0x37FD81FC86F9EE6FULL,
		0x2534BB934D69ED8AULL,
		0xF5F50B4501D6710FULL,
		0x383A0E71FA5E8DFCULL,
		0x0000000000000002ULL
	}};
	shift = 2;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC92D53CB523520A7ULL,
		0xB107E2F3A84398E7ULL,
		0x92A08CF7D414B14AULL,
		0xF0D9EAAEFA1C980EULL,
		0x7152CF27123A64A7ULL,
		0xA57910DB4107194AULL,
		0xC38D66A5FA2BC50EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA46A414E00000000ULL,
		0x508731CF925AA796ULL,
		0xA8296295620FC5E7ULL,
		0xF439301D254119EFULL,
		0x2474C94FE1B3D55DULL,
		0x820E3294E2A59E4EULL,
		0xF4578A1D4AF221B6ULL,
		0x00000001871ACD4BULL
	}};
	shift = 33;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x057BAAE990BF39D4ULL,
		0x9AB56759C1237454ULL,
		0x9E39A404812F4B64ULL,
		0x71CFABEFD40503CFULL,
		0x1FFCFCAF6A30EE5BULL,
		0x244CE8DA50CA80CFULL,
		0x65D2EADB9B775E30ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0xA80AF755D3217E73ULL,
		0xC9356ACEB38246E8ULL,
		0x9F3C734809025E96ULL,
		0xB6E39F57DFA80A07ULL,
		0x9E3FF9F95ED461DCULL,
		0x604899D1B4A19501ULL,
		0x00CBA5D5B736EEBCULL
	}};
	shift = 57;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3E2070B245642228ULL,
		0xB205FD6D49EB97B5ULL,
		0xE93D662DF0039C2AULL,
		0xADB485F322530BB4ULL,
		0xD615E233ACA83DADULL,
		0xEED42111DE3B8132ULL,
		0x3A63698E1A90B194ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9159088A0000000ULL,
		0xB527AE5ED4F881C2ULL,
		0xB7C00E70AAC817F5ULL,
		0xCC894C2ED3A4F598ULL,
		0xCEB2A0F6B6B6D217ULL,
		0x4778EE04CB585788ULL,
		0x386A42C653BB5084ULL,
		0x0000000000E98DA6ULL
	}};
	shift = 26;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x81831650C33B8F92ULL,
		0x6C9E6889457B866CULL,
		0x635130FDC9E6E21CULL,
		0x1A9B0CDB0D61D760ULL,
		0xBD52C7E69D4293AEULL,
		0x04199807D38C2BABULL,
		0x70DD36032DDBFBE3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC900000000000000ULL,
		0x3640C18B28619DC7ULL,
		0x0E364F3444A2BDC3ULL,
		0xB031A8987EE4F371ULL,
		0xD70D4D866D86B0EBULL,
		0xD5DEA963F34EA149ULL,
		0xF1820CCC03E9C615ULL,
		0x00386E9B0196EDFDULL
	}};
	shift = 55;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x609E52DC7B1FB958ULL,
		0x5BD0323F0CDCEB07ULL,
		0x3DA16932049CFF8FULL,
		0x474D129E52F9AC3FULL,
		0xBDBCB12D8DC94BF7ULL,
		0xBA76D86DC3A305FFULL,
		0xE447425B7C9089DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94B71EC7EE560000ULL,
		0x0C8FC3373AC1D827ULL,
		0x5A4C81273FE3D6F4ULL,
		0x44A794BE6B0FCF68ULL,
		0x2C4B637252FDD1D3ULL,
		0xB61B70E8C17FEF6FULL,
		0xD096DF242277EE9DULL,
		0x0000000000003911ULL
	}};
	shift = 14;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4181435525A9A2EDULL,
		0xF79F1A6CF212831BULL,
		0xB9DC3365C6D73F70ULL,
		0xCEE3596F4929630BULL,
		0x21EE31E65010FE57ULL,
		0x2AACB66F0180EC64ULL,
		0x8F205E931AF867ABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0xD06050D5496A68BBULL,
		0x3DE7C69B3C84A0C6ULL,
		0xEE770CD971B5CFDCULL,
		0xF3B8D65BD24A58C2ULL,
		0x087B8C7994043F95ULL,
		0xCAAB2D9BC0603B19ULL,
		0x23C817A4C6BE19EAULL
	}};
	shift = 62;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA7910B43C27A89D0ULL,
		0x9EB6B07144D3E97FULL,
		0x0453D346E928F66CULL,
		0xB40CB0DDD7FAD335ULL,
		0x29278EDAF59F9107ULL,
		0x8BE8FDC7CF2047A0ULL,
		0xEDD1A709DEF4963CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2168784F513A0000ULL,
		0xD60E289A7D2FF4F2ULL,
		0x7A68DD251ECD93D6ULL,
		0x961BBAFF5A66A08AULL,
		0xF1DB5EB3F220F681ULL,
		0x1FB8F9E408F40524ULL,
		0x34E13BDE92C7917DULL,
		0x0000000000001DBAULL
	}};
	shift = 13;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5A96903EA90F905DULL,
		0x2A2BF7A8770779B8ULL,
		0xF87F8D9FB23BCC5DULL,
		0xF9FC7F5F1D60F3E3ULL,
		0x52724F46FB482596ULL,
		0x3862FE1BC81A5F0CULL,
		0x46586A565A6CDF53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5487C82E8000000ULL,
		0x43B83BCDC2D4B481ULL,
		0xFD91DE62E9515FBDULL,
		0xF8EB079F1FC3FC6CULL,
		0x37DA412CB7CFE3FAULL,
		0xDE40D2F86293927AULL,
		0xB2D366FA99C317F0ULL,
		0x000000000232C352ULL
	}};
	shift = 27;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x039737D4BF7C1230ULL,
		0x43A0025A5FE2171CULL,
		0x4950464C5D39D39BULL,
		0x9DF829EE05DC5BA6ULL,
		0x532E04567BDF227EULL,
		0xBA3A5C5A453B9882ULL,
		0xB127460A222D9C10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE0918000000000ULL,
		0xFF10B8E01CB9BEA5ULL,
		0xE9CE9CDA1D0012D2ULL,
		0x2EE2DD324A823262ULL,
		0xDEF913F4EFC14F70ULL,
		0x29DCC412997022B3ULL,
		0x116CE085D1D2E2D2ULL,
		0x00000005893A3051ULL
	}};
	shift = 35;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA0A0414593E598B0ULL,
		0x9409BF2881BA1044ULL,
		0x44C9D3AEAFA9C52CULL,
		0x76717458E51D634BULL,
		0xC522CB47252ADC8CULL,
		0xF827E95A4636EA37ULL,
		0x0650C72A1EBA9B7AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F2CC58000000000ULL,
		0x0DD0822505020A2CULL,
		0x7D4E2964A04DF944ULL,
		0x28EB1A5A264E9D75ULL,
		0x2956E463B38BA2C7ULL,
		0x31B751BE29165A39ULL,
		0xF5D4DBD7C13F4AD2ULL,
		0x0000000032863950ULL
	}};
	shift = 35;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xADDAFD0A37658FF7ULL,
		0x1C1DE1506FDAB74DULL,
		0xC59E71A2CB5B1200ULL,
		0xCD74159516B18D5FULL,
		0x0ADC45C80A7B754EULL,
		0xBF539498F32F0A4CULL,
		0xB39351097061D4F0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x963FDC0000000000ULL,
		0x6ADD36B76BF428DDULL,
		0x6C480070778541BFULL,
		0xC6357F1679C68B2DULL,
		0xEDD53B35D056545AULL,
		0xBC29302B71172029ULL,
		0x8753C2FD4E5263CCULL,
		0x000002CE4D4425C1ULL
	}};
	shift = 42;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x279304CF33F4EA36ULL,
		0x1806FA665F3E3942ULL,
		0x9467EF030CBB71D1ULL,
		0x1B9F9CF086051323ULL,
		0x491EC6A2BAF39B1AULL,
		0x281D2EC61DF3F859ULL,
		0x63A04EA015BC4604ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x099E67E9D46C0000ULL,
		0xF4CCBE7C72844F26ULL,
		0xDE061976E3A2300DULL,
		0x39E10C0A264728CFULL,
		0x8D4575E73634373FULL,
		0x5D8C3BE7F0B2923DULL,
		0x9D402B788C08503AULL,
		0x000000000000C740ULL
	}};
	shift = 17;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2E69739940C37110ULL,
		0xB172463F688D3F93ULL,
		0xAE963910DBE598C1ULL,
		0xCE572CF573F172A6ULL,
		0xC0944DA49C1C6F96ULL,
		0x43435ADDB6B1FF9FULL,
		0x5A835C759D42A913ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69739940C3711000ULL,
		0x72463F688D3F932EULL,
		0x963910DBE598C1B1ULL,
		0x572CF573F172A6AEULL,
		0x944DA49C1C6F96CEULL,
		0x435ADDB6B1FF9FC0ULL,
		0x835C759D42A91343ULL,
		0x000000000000005AULL
	}};
	shift = 8;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9399E5BF9F193553ULL,
		0x9200362CB87F310CULL,
		0x4C6EE58393578ACEULL,
		0x1A2AB930D6F5E0AAULL,
		0xF3CAC64B782AD65FULL,
		0x37F7F54269A5BF89ULL,
		0x06D14C4010FDA22DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x326AA60000000000ULL,
		0xFE62192733CB7F3EULL,
		0xAF159D24006C5970ULL,
		0xEBC15498DDCB0726ULL,
		0x55ACBE34557261ADULL,
		0x4B7F13E7958C96F0ULL,
		0xFB445A6FEFEA84D3ULL,
		0x0000000DA2988021ULL
	}};
	shift = 41;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x92707F0F2E2D5528ULL,
		0x62431F231D9048BBULL,
		0x5E49E19B69228E6CULL,
		0xBB0BED966E156E84ULL,
		0xA35AE19B860527D0ULL,
		0xC0B56965F40938F5ULL,
		0x544B20A3046395ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA94000000000000ULL,
		0x245DC9383F879716ULL,
		0x473631218F918EC8ULL,
		0xB7422F24F0CDB491ULL,
		0x93E85D85F6CB370AULL,
		0x9C7AD1AD70CDC302ULL,
		0xCAD6605AB4B2FA04ULL,
		0x00002A2590518231ULL
	}};
	shift = 47;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCAF29A361E616000ULL,
		0xC9052148F0E21F82ULL,
		0x0CE2D20D510839DDULL,
		0x2701ACB7860A2CD2ULL,
		0x12F5C0BFFB1D0EDFULL,
		0xF15CA2C6544C88F8ULL,
		0x69F9DC2CAB92616EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BCA68D879858000ULL,
		0x24148523C3887E0BULL,
		0x338B48354420E777ULL,
		0x9C06B2DE1828B348ULL,
		0x4BD702FFEC743B7CULL,
		0xC5728B19513223E0ULL,
		0xA7E770B2AE4985BBULL,
		0x0000000000000001ULL
	}};
	shift = 2;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDDE1724EBC6DEB62ULL,
		0x227102B87AE5C675ULL,
		0x564AF470EF939F3EULL,
		0xFD3820B7851A793CULL,
		0xB28BC20A97A0BFCDULL,
		0xCC7CCB4119387C78ULL,
		0xE4969DA0831734D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9275E36F5B10000ULL,
		0x815C3D72E33AEEF0ULL,
		0x7A3877C9CF9F1138ULL,
		0x105BC28D3C9E2B25ULL,
		0xE1054BD05FE6FE9CULL,
		0x65A08C9C3E3C5945ULL,
		0x4ED0418B9A6CE63EULL,
		0x000000000000724BULL
	}};
	shift = 15;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4AA04918419FB6D2ULL,
		0x15A95D31DC730822ULL,
		0x6A9DCBD63FC8CB6AULL,
		0x913EE4E0869F669BULL,
		0x23FD7466E50709EDULL,
		0x76B8CC9EDE4CC5D6ULL,
		0x66FCCCDCC8C655D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA04918419FB6D20ULL,
		0x5A95D31DC7308224ULL,
		0xA9DCBD63FC8CB6A1ULL,
		0x13EE4E0869F669B6ULL,
		0x3FD7466E50709ED9ULL,
		0x6B8CC9EDE4CC5D62ULL,
		0x6FCCCDCC8C655D97ULL,
		0x0000000000000006ULL
	}};
	shift = 4;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCF7A7487BFAADDC2ULL,
		0x404E46CFD83C9709ULL,
		0x5537907B6DDABED2ULL,
		0xA19321F40BA96A55ULL,
		0xAAA97DD7ABF27D8EULL,
		0xB7A8DF87D3703E3EULL,
		0xBFE9429BE08D4E8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE9D21EFEAB77080ULL,
		0x1391B3F60F25C273ULL,
		0x4DE41EDB76AFB490ULL,
		0x64C87D02EA5A9555ULL,
		0xAA5F75EAFC9F63A8ULL,
		0xEA37E1F4DC0F8FAAULL,
		0xFA50A6F82353A3EDULL,
		0x000000000000002FULL
	}};
	shift = 6;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x606E631AA421038BULL,
		0x0A8CED70F3D3209FULL,
		0x0403B769C12F2438ULL,
		0x1D50F70B997864DAULL,
		0x7BAB7103F8D83139ULL,
		0x50AC5CEB8B96A1E9ULL,
		0xC4D6605D0E8E8721ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6354842071600000ULL,
		0xAE1E7A6413EC0DCCULL,
		0xED3825E48701519DULL,
		0xE1732F0C9B408076ULL,
		0x207F1B062723AA1EULL,
		0x9D7172D43D2F756EULL,
		0x0BA1D1D0E42A158BULL,
		0x0000000000189ACCULL
	}};
	shift = 21;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0C26C4A062785E07ULL,
		0x33E7FB6774AA15A4ULL,
		0x1A7B0D139E0CF294ULL,
		0x3FFEE52269ADB20EULL,
		0x740FB0E16E612A8CULL,
		0x92B1C1E04AF7EC62ULL,
		0x7BC627D769DDE600ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2785E07000000000ULL,
		0x4AA15A40C26C4A06ULL,
		0xE0CF29433E7FB677ULL,
		0x9ADB20E1A7B0D139ULL,
		0xE612A8C3FFEE5226ULL,
		0xAF7EC62740FB0E16ULL,
		0x9DDE60092B1C1E04ULL,
		0x00000007BC627D76ULL
	}};
	shift = 36;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x12AC559971159E44ULL,
		0xB7EF0661A16BEC58ULL,
		0x5B08C1496043ECF5ULL,
		0xF66AB84AB4700239ULL,
		0x2CF7CA33B4F63112ULL,
		0x331C084B2CCE1356ULL,
		0x4668453AFBF1D84CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC559971159E4400ULL,
		0xEF0661A16BEC5812ULL,
		0x08C1496043ECF5B7ULL,
		0x6AB84AB47002395BULL,
		0xF7CA33B4F63112F6ULL,
		0x1C084B2CCE13562CULL,
		0x68453AFBF1D84C33ULL,
		0x0000000000000046ULL
	}};
	shift = 8;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDE7CF3DB9B489287ULL,
		0xB48A9792E77AC85EULL,
		0x551AF746605072DBULL,
		0xB2DA4484A97FD949ULL,
		0xE4C16E2FD17F2B34ULL,
		0x8F17BA033ADC0036ULL,
		0x6648BA7B6F51B439ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4943800000000000ULL,
		0x642F6F3E79EDCDA4ULL,
		0x396DDA454BC973BDULL,
		0xECA4AA8D7BA33028ULL,
		0x959A596D224254BFULL,
		0x001B7260B717E8BFULL,
		0xDA1CC78BDD019D6EULL,
		0x000033245D3DB7A8ULL
	}};
	shift = 47;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE224D43EAF429C84ULL,
		0x5D1A99CFB39FA256ULL,
		0x00CC809CB416EDBDULL,
		0x434F4800ECCA94CDULL,
		0xD5B0410D3692A8EDULL,
		0xB45CFDFFCE91A528ULL,
		0x2C45959A66B9F731ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A1F57A14E42000ULL,
		0xD4CE7D9CFD12B711ULL,
		0x6404E5A0B76DEAE8ULL,
		0x7A40076654A66806ULL,
		0x820869B495476A1AULL,
		0xE7EFFE748D2946ADULL,
		0x2CACD335CFB98DA2ULL,
		0x0000000000000162ULL
	}};
	shift = 11;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x744A0910E98D829AULL,
		0x6BF66D97FDAA415EULL,
		0x82E91E5CEEF7AC27ULL,
		0x3F6B198A51F00535ULL,
		0x0F8D51ADDBE5D54EULL,
		0xEDB3E7A8481AC211ULL,
		0x892938A3A1F3B6C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8874C6C14D000000ULL,
		0xCBFED520AF3A2504ULL,
		0x2E777BD613B5FB36ULL,
		0xC528F8029AC1748FULL,
		0xD6EDF2EAA71FB58CULL,
		0xD4240D610887C6A8ULL,
		0x51D0F9DB6176D9F3ULL,
		0x000000000044949CULL
	}};
	shift = 23;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBE4723B26D0628E7ULL,
		0x38E4015FB4899A57ULL,
		0x6EA8C1191AFAF4D0ULL,
		0x95BF0FC6C1138374ULL,
		0xAF38E7B387AE2D54ULL,
		0xA2E95F2F4C4A2075ULL,
		0x5D0C1DDE4E1C31DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xF7C8E4764DA0C51CULL,
		0x071C802BF691334AULL,
		0x8DD51823235F5E9AULL,
		0x92B7E1F8D822706EULL,
		0xB5E71CF670F5C5AAULL,
		0xD45D2BE5E989440EULL,
		0x0BA183BBC9C3863BULL
	}};
	shift = 61;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x348D8033DA0F1EF8ULL,
		0x7E24E170BA750C93ULL,
		0x3329EC56481600CEULL,
		0x75A741ECAD7A70DCULL,
		0x1AB752405B0C782EULL,
		0x261F9F7A3C870850ULL,
		0x09520C49A8BB2591ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46C019ED078F7C00ULL,
		0x1270B85D3A86499AULL,
		0x94F62B240B00673FULL,
		0xD3A0F656BD386E19ULL,
		0x5BA9202D863C173AULL,
		0x0FCFBD1E4384280DULL,
		0xA90624D45D92C893ULL,
		0x0000000000000004ULL
	}};
	shift = 7;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4D09C2F6BB92DBEFULL,
		0x7BACDBCC4F3D6D95ULL,
		0x11535D4B1C44DD29ULL,
		0xE5E02FAAE23D17D4ULL,
		0xBD8267F0870FC396ULL,
		0xF75EF25525FA9982ULL,
		0xF99F09184DB43E76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB92DBEF000000000ULL,
		0xF3D6D954D09C2F6BULL,
		0xC44DD297BACDBCC4ULL,
		0x23D17D411535D4B1ULL,
		0x70FC396E5E02FAAEULL,
		0x5FA9982BD8267F08ULL,
		0xDB43E76F75EF2552ULL,
		0x0000000F99F09184ULL
	}};
	shift = 36;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3F08713BD11926D5ULL,
		0x9722D4C58832B4C8ULL,
		0x27B8D8ED7811D11AULL,
		0x64E1DA76924F4E3EULL,
		0x557D709E74F1E9E3ULL,
		0xB4559603034C12A2ULL,
		0xCA06B2E435FEA11FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5400000000000000ULL,
		0x20FC21C4EF44649BULL,
		0x6A5C8B531620CAD3ULL,
		0xF89EE363B5E04744ULL,
		0x8D938769DA493D38ULL,
		0x8955F5C279D3C7A7ULL,
		0x7ED156580C0D304AULL,
		0x03281ACB90D7FA84ULL
	}};
	shift = 58;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4219C535564A576BULL,
		0x8CDB7BBF53EA5039ULL,
		0x28D1A6732B924E9DULL,
		0x2184075AA7923FC7ULL,
		0x5BEE641311ADB371ULL,
		0x60723A63FC3F0C9FULL,
		0x8165DAEF571418B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C535564A576B000ULL,
		0xB7BBF53EA5039421ULL,
		0x1A6732B924E9D8CDULL,
		0x4075AA7923FC728DULL,
		0xE641311ADB371218ULL,
		0x23A63FC3F0C9F5BEULL,
		0x5DAEF571418B5607ULL,
		0x0000000000000816ULL
	}};
	shift = 12;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0AA3BB41AEBAD72CULL,
		0x708AA59EB1E00490ULL,
		0x396DECA7FF023DC7ULL,
		0x336A7E3F223054C7ULL,
		0xB7AEC634F863FEFEULL,
		0xD44A8F08CFC04E9DULL,
		0xCCE630C6654F8AC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0551DDA0D75D6B96ULL,
		0xB84552CF58F00248ULL,
		0x9CB6F653FF811EE3ULL,
		0x19B53F1F91182A63ULL,
		0xDBD7631A7C31FF7FULL,
		0xEA25478467E0274EULL,
		0x6673186332A7C561ULL
	}};
	shift = 63;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE54AF7C35B593F35ULL,
		0xC95EA7433ABD1B29ULL,
		0xE5631BA3E04B15CFULL,
		0x591324AFF465BD9CULL,
		0x3583FE138DDAAF12ULL,
		0x615742A8A7C4BE77ULL,
		0x88E37E5A659FB14FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6B27E6A0000000ULL,
		0x6757A3653CA95EF8ULL,
		0x7C0962B9F92BD4E8ULL,
		0xFE8CB7B39CAC6374ULL,
		0x71BB55E24B226495ULL,
		0x14F897CEE6B07FC2ULL,
		0x4CB3F629EC2AE855ULL,
		0x00000000111C6FCBULL
	}};
	shift = 29;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA3883E8DD4005F2DULL,
		0x4A540285076A9B1EULL,
		0x1617C3ADCC365A82ULL,
		0xC5FDC1B32A4CB0F7ULL,
		0x8006B2026F1DCA98ULL,
		0x7E52A3A1C5E503BFULL,
		0x0FEA34B872AF0F9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x017CB40000000000ULL,
		0xAA6C7A8E20FA3750ULL,
		0xD96A0929500A141DULL,
		0x32C3DC585F0EB730ULL,
		0x772A6317F706CCA9ULL,
		0x940EFE001AC809BCULL,
		0xBC3E71F94A8E8717ULL,
		0x0000003FA8D2E1CAULL
	}};
	shift = 42;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1032CA75EB5CDD69ULL,
		0x0F262F9816FFB82CULL,
		0x7191921CC54090CBULL,
		0xC48577FDA2D5B308ULL,
		0x780AB83B55281852ULL,
		0xA6C699697CE3B94EULL,
		0x7565A90613FDE3C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06594EBD6B9BAD20ULL,
		0xE4C5F302DFF70582ULL,
		0x32324398A8121961ULL,
		0x90AEFFB45AB6610EULL,
		0x0157076AA5030A58ULL,
		0xD8D32D2F9C7729CFULL,
		0xACB520C27FBC78B4ULL,
		0x000000000000000EULL
	}};
	shift = 5;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCD2FA2D95E4AFA1EULL,
		0xB20BDE72531626F5ULL,
		0x6B1A8F56D82360A7ULL,
		0xAD329DBA76C1329FULL,
		0x3DD4CA6F76BC70D1ULL,
		0x58EF3747DF0FFF53ULL,
		0xA1A8D728FA975EA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1E0000000000000ULL,
		0x6F5CD2FA2D95E4AFULL,
		0x0A7B20BDE7253162ULL,
		0x29F6B1A8F56D8236ULL,
		0x0D1AD329DBA76C13ULL,
		0xF533DD4CA6F76BC7ULL,
		0xEA658EF3747DF0FFULL,
		0x000A1A8D728FA975ULL
	}};
	shift = 52;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF5D5064F96781355ULL,
		0xA7765D95B5C9D15EULL,
		0x2EB0BAA15B27FFC1ULL,
		0x124B991A952795B9ULL,
		0xCE0D037FC0F31889ULL,
		0x9175A08D8E478CDBULL,
		0xBB6F4DA7BAF65484ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754193E59E04D540ULL,
		0xDD97656D727457BDULL,
		0xAC2EA856C9FFF069ULL,
		0x92E646A549E56E4BULL,
		0x8340DFF03CC62244ULL,
		0x5D68236391E336F3ULL,
		0xDBD369EEBD952124ULL,
		0x000000000000002EULL
	}};
	shift = 6;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEE657D4757E4168EULL,
		0x41C548C2F5AE1C83ULL,
		0x84ECE059810570E3ULL,
		0x464A19CAE74F3349ULL,
		0x85307794C5950C04ULL,
		0x350D51486BA813B3ULL,
		0x0839CDE2C8EB8A96ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEA3ABF20B470000ULL,
		0xA4617AD70E41F732ULL,
		0x702CC082B871A0E2ULL,
		0x0CE573A799A4C276ULL,
		0x3BCA62CA86022325ULL,
		0xA8A435D409D9C298ULL,
		0xE6F16475C54B1A86ULL,
		0x000000000000041CULL
	}};
	shift = 15;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x56A94C5C87023B91ULL,
		0x8C137962D56D70C1ULL,
		0x17F7410891229C8EULL,
		0x62616E2640E22A28ULL,
		0x2CE9DCB28FE3DA30ULL,
		0xE62077697C146F81ULL,
		0xD945979C67FF0A83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C5C87023B910000ULL,
		0x7962D56D70C156A9ULL,
		0x410891229C8E8C13ULL,
		0x6E2640E22A2817F7ULL,
		0xDCB28FE3DA306261ULL,
		0x77697C146F812CE9ULL,
		0x979C67FF0A83E620ULL,
		0x000000000000D945ULL
	}};
	shift = 16;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3F37BF965125A6B5ULL,
		0x222C8AFF44C96D00ULL,
		0x6BBA3A25226821D0ULL,
		0x4F3FE73E5D37F6EAULL,
		0x15AB298295AA615FULL,
		0x4A0EA455FB6DC57FULL,
		0x215B8B2468D50D8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEFE5944969AD400ULL,
		0xB22BFD1325B400FCULL,
		0xE8E89489A0874088ULL,
		0xFF9CF974DFDBA9AEULL,
		0xACA60A56A9857D3CULL,
		0x3A9157EDB715FC56ULL,
		0x6E2C91A354363D28ULL,
		0x0000000000000085ULL
	}};
	shift = 10;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x50DA8F01C8E17C69ULL,
		0x334739356552124FULL,
		0xB5684096F5E2A870ULL,
		0xD784F5CB938FC092ULL,
		0xB8E5E1F3B0F8134DULL,
		0x2A20FDA340424765ULL,
		0x17AF7335573885B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2F8D2000000000ULL,
		0xAA4249EA1B51E039ULL,
		0xBC550E0668E726ACULL,
		0x71F81256AD0812DEULL,
		0x1F0269BAF09EB972ULL,
		0x0848ECB71CBC3E76ULL,
		0xE710B665441FB468ULL,
		0x00000002F5EE66AAULL
	}};
	shift = 37;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x636EA2992DCF7B92ULL,
		0xA5FCA314EE089611ULL,
		0x325EF58BE35BCCFAULL,
		0xA8566A2278914384ULL,
		0xDAE1FF8CBD535234ULL,
		0xAB0E83ABF60DE476ULL,
		0xAF189A758704EA1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45325B9EF7240000ULL,
		0x4629DC112C22C6DDULL,
		0xEB17C6B799F54BF9ULL,
		0xD444F122870864BDULL,
		0xFF197AA6A46950ACULL,
		0x0757EC1BC8EDB5C3ULL,
		0x34EB0E09D435561DULL,
		0x0000000000015E31ULL
	}};
	shift = 17;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAE5596E64E9A6A7DULL,
		0xEB7E9FFCA1D545E9ULL,
		0xD780C4BB4488C29FULL,
		0xC7954D896E02BB5FULL,
		0x6DA1708C64F8064FULL,
		0xD354B5785209DAC5ULL,
		0x6C77F92E64BC4D66ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9D34D4FA0000000ULL,
		0x943AA8BD35CAB2DCULL,
		0x68911853FD6FD3FFULL,
		0x2DC0576BFAF01897ULL,
		0x8C9F00C9F8F2A9B1ULL,
		0x0A413B58ADB42E11ULL,
		0xCC9789ACDA6A96AFULL,
		0x000000000D8EFF25ULL
	}};
	shift = 29;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4D386E7C71800808ULL,
		0x6FF4CAE3E0111A9DULL,
		0xB0DAA3FEE767F208ULL,
		0xD3CE185A9B5CA35CULL,
		0xFA789EE16A0B0958ULL,
		0x18ABE47C6934BC4EULL,
		0xED9D9FD65195C6B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E1B9F1C60020200ULL,
		0xFD32B8F80446A753ULL,
		0x36A8FFB9D9FC821BULL,
		0xF38616A6D728D72CULL,
		0x9E27B85A82C25634ULL,
		0x2AF91F1A4D2F13BEULL,
		0x6767F5946571AD86ULL,
		0x000000000000003BULL
	}};
	shift = 6;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2072B6ADEB2ED5E7ULL,
		0xD797019F42BA83FBULL,
		0x94B83398FC482002ULL,
		0x473F28885308C034ULL,
		0x5AC499D45BBA2A35ULL,
		0xA55D22BDE6D62A98ULL,
		0x3C3BF0D307E4CBDAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5976AF38000000ULL,
		0xFA15D41FD90395B5ULL,
		0xC7E2410016BCB80CULL,
		0x42984601A4A5C19CULL,
		0xA2DDD151AA39F944ULL,
		0xEF36B154C2D624CEULL,
		0x983F265ED52AE915ULL,
		0x0000000001E1DF86ULL
	}};
	shift = 27;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAAC54FB60BA41B7BULL,
		0x149412B6B618774BULL,
		0xFDBA82A689337FC7ULL,
		0x4EB1F40222F1A0C6ULL,
		0xD4CAA117B5A547D0ULL,
		0x883B63ECD3CD9C06ULL,
		0x8305A1CEC3ECE2B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC0000000000000ULL,
		0xD2EAB153ED82E906ULL,
		0xF1C52504ADAD861DULL,
		0x31BF6EA0A9A24CDFULL,
		0xF413AC7D0088BC68ULL,
		0x01B532A845ED6951ULL,
		0xAD620ED8FB34F367ULL,
		0x0020C16873B0FB38ULL
	}};
	shift = 54;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x003EC655550FC03BULL,
		0x5A5620C4BF30665EULL,
		0xCF5A1C8135701009ULL,
		0x5C808F131C284C9AULL,
		0xBF7F1488EDEA8E34ULL,
		0x826BA8AB3D3C646DULL,
		0x37394851F9909AE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32AAA87E01D80000ULL,
		0x0625F98332F001F6ULL,
		0xE409AB80804AD2B1ULL,
		0x7898E14264D67AD0ULL,
		0xA4476F5471A2E404ULL,
		0x4559E9E3236DFBF8ULL,
		0x428FCC84D704135DULL,
		0x000000000001B9CAULL
	}};
	shift = 19;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6467C4A1FE6341CEULL,
		0x71C82C2AA8ED85DFULL,
		0xEBAB273CDC3A6473ULL,
		0x03879DFC73B932ECULL,
		0x983432687A3CC7B3ULL,
		0xEB750B0AFEB25733ULL,
		0x7AF5FE2A669496BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xEC8CF8943FCC6839ULL,
		0x6E390585551DB0BBULL,
		0x9D7564E79B874C8EULL,
		0x6070F3BF8E77265DULL,
		0x7306864D0F4798F6ULL,
		0x5D6EA1615FD64AE6ULL,
		0x0F5EBFC54CD292D7ULL
	}};
	shift = 61;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x83C55FE678E9522BULL,
		0xEE2AC12E33E275C0ULL,
		0x600880EB5BEE183BULL,
		0xC0545C827CAA61C2ULL,
		0x09F8364EDFAE8A72ULL,
		0xC8A60A5B0D5F536FULL,
		0x0FFB51225DF4AAABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x157F99E3A548AC00ULL,
		0xAB04B8CF89D7020FULL,
		0x2203AD6FB860EFB8ULL,
		0x517209F2A9870980ULL,
		0xE0D93B7EBA29CB01ULL,
		0x98296C357D4DBC27ULL,
		0xED448977D2AAAF22ULL,
		0x000000000000003FULL
	}};
	shift = 10;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6ACFAE25C633D0D7ULL,
		0xBA15F824AD45800BULL,
		0xD80B14A72F7CD7BBULL,
		0x4CBC836340FAF212ULL,
		0x2BCB5C92D87B67C0ULL,
		0x3677AEC95DBEB132ULL,
		0x97D2FC3945AE88B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E319E86B8000000ULL,
		0x256A2C005B567D71ULL,
		0x397BE6BDDDD0AFC1ULL,
		0x1A07D79096C058A5ULL,
		0x96C3DB3E0265E41BULL,
		0x4AEDF589915E5AE4ULL,
		0xCA2D7445B1B3BD76ULL,
		0x0000000004BE97E1ULL
	}};
	shift = 27;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDB3237BB4B267075ULL,
		0x08FE6398F7BFA853ULL,
		0x0226D12A1035EB83ULL,
		0x0231BC713651D5BEULL,
		0xA5DA7B1673A58F7DULL,
		0xAE7381E32FD07D3EULL,
		0x0DD88E9B63453B3DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0x3DB3237BB4B26707ULL,
		0x308FE6398F7BFA85ULL,
		0xE0226D12A1035EB8ULL,
		0xD0231BC713651D5BULL,
		0xEA5DA7B1673A58F7ULL,
		0xDAE7381E32FD07D3ULL,
		0x00DD88E9B63453B3ULL
	}};
	shift = 60;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x814B6DB732D69E56ULL,
		0x12A2FE0329742EB5ULL,
		0xCF0C774783E75758ULL,
		0x3C6BCF7FADC5C910ULL,
		0x0E3DBBE665202563ULL,
		0x48596BBEB1445E60ULL,
		0x42B3AFED1B8F4D20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14B6DB732D69E560ULL,
		0x2A2FE0329742EB58ULL,
		0xF0C774783E757581ULL,
		0xC6BCF7FADC5C910CULL,
		0xE3DBBE6652025633ULL,
		0x8596BBEB1445E600ULL,
		0x2B3AFED1B8F4D204ULL,
		0x0000000000000004ULL
	}};
	shift = 4;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF197888841682227ULL,
		0xAC5607073E994767ULL,
		0x0A508A444BECAE82ULL,
		0x66C76D9E103B9082ULL,
		0xF9FE4F88F18C3071ULL,
		0x672B8623B4CE4D4DULL,
		0x1DCFD260C00C0E09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9788884168222700ULL,
		0x5607073E994767F1ULL,
		0x508A444BECAE82ACULL,
		0xC76D9E103B90820AULL,
		0xFE4F88F18C307166ULL,
		0x2B8623B4CE4D4DF9ULL,
		0xCFD260C00C0E0967ULL,
		0x000000000000001DULL
	}};
	shift = 8;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x48F3C971D84E14DAULL,
		0x384A4C61958B7B13ULL,
		0x85BD8C0F74891E47ULL,
		0x4C8C2DD507648F91ULL,
		0x90BF661D7148EDACULL,
		0x4EAA1C64C482464BULL,
		0x93204A2413097B45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71D84E14DA000000ULL,
		0x61958B7B1348F3C9ULL,
		0x0F74891E47384A4CULL,
		0xD507648F9185BD8CULL,
		0x1D7148EDAC4C8C2DULL,
		0x64C482464B90BF66ULL,
		0x2413097B454EAA1CULL,
		0x000000000093204AULL
	}};
	shift = 24;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8E2A64C3C630B591ULL,
		0x218385A1475004AEULL,
		0x41C442E859A1B51DULL,
		0xCAA14B6BC82CA1E0ULL,
		0x2BC2389E8B097E2FULL,
		0x63BFBF8CDE3A4012ULL,
		0x06653163F580260EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA64C3C630B591000ULL,
		0x385A1475004AE8E2ULL,
		0x442E859A1B51D218ULL,
		0x14B6BC82CA1E041CULL,
		0x2389E8B097E2FCAAULL,
		0xFBF8CDE3A40122BCULL,
		0x53163F580260E63BULL,
		0x0000000000000066ULL
	}};
	shift = 12;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2BB13D68F2CB09E6ULL,
		0xF67862AD17514A92ULL,
		0xD1D947468BAB3775ULL,
		0x99A5246B948F43E0ULL,
		0x97470631B69F5608ULL,
		0xE9141AB8E16A60CAULL,
		0x532FEFED545B69ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F2CB09E6000000ULL,
		0xAD17514A922BB13DULL,
		0x468BAB3775F67862ULL,
		0x6B948F43E0D1D947ULL,
		0x31B69F560899A524ULL,
		0xB8E16A60CA974706ULL,
		0xED545B69ACE9141AULL,
		0x0000000000532FEFULL
	}};
	shift = 24;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7E501C3F5985901AULL,
		0x3FB933709CB5C54EULL,
		0x1099A34FA842B583ULL,
		0x1366DFF7BD3860A9ULL,
		0xDA30AC01439A3FC1ULL,
		0x26CB9AD15F73639FULL,
		0x49ECD44D332B548AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5901A00000000000ULL,
		0x5C54E7E501C3F598ULL,
		0x2B5833FB933709CBULL,
		0x860A91099A34FA84ULL,
		0xA3FC11366DFF7BD3ULL,
		0x3639FDA30AC01439ULL,
		0xB548A26CB9AD15F7ULL,
		0x0000049ECD44D332ULL
	}};
	shift = 44;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x20AC127E269C8FC6ULL,
		0x90C959F550388FD5ULL,
		0x0BD3736F083EF033ULL,
		0x061C1529E98D7DB2ULL,
		0x592AD2194B904336ULL,
		0x7E9194934338EE78ULL,
		0x1FC9E040F090DA17ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F89A723F1800000ULL,
		0x7D540E23F5482B04ULL,
		0xDBC20FBC0CE43256ULL,
		0x4A7A635F6C82F4DCULL,
		0x8652E410CD818705ULL,
		0x24D0CE3B9E164AB4ULL,
		0x103C243685DFA465ULL,
		0x000000000007F278ULL
	}};
	shift = 22;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7938DEE019D3BD30ULL,
		0xC129970403C1C3B3ULL,
		0x5479CDBFEB12A0EDULL,
		0x451657EA8F8105EBULL,
		0x5365B13BF51F8580ULL,
		0xDCCD1AEBC9065CEAULL,
		0x3CA227D7E44EA818ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x700CE9DE98000000ULL,
		0x8201E0E1D9BC9C6FULL,
		0xDFF5895076E094CBULL,
		0xF547C082F5AA3CE6ULL,
		0x9DFA8FC2C0228B2BULL,
		0x75E4832E7529B2D8ULL,
		0xEBF227540C6E668DULL,
		0x00000000001E5113ULL
	}};
	shift = 23;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9B4C39C6B6D08B41ULL,
		0x210BF3F589C8821AULL,
		0x1CA7F71157F1E4D6ULL,
		0x94F5291736E0106AULL,
		0x4C5FEE179958B438ULL,
		0x551D915500D320C7ULL,
		0x0316F7506A228651ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA080000000000000ULL,
		0x0D4DA61CE35B6845ULL,
		0x6B1085F9FAC4E441ULL,
		0x350E53FB88ABF8F2ULL,
		0x1C4A7A948B9B7008ULL,
		0x63A62FF70BCCAC5AULL,
		0x28AA8EC8AA806990ULL,
		0x00018B7BA8351143ULL
	}};
	shift = 55;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4C298CAB52AE550BULL,
		0xAF06A36D77A52FE8ULL,
		0x3373CDC4CDC6ECD1ULL,
		0x8B54CEBA6E366A5FULL,
		0xABEFC5EB5FC22B78ULL,
		0x348E6374ABD12E37ULL,
		0xEB16558939B60811ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE550B0000000000ULL,
		0xA52FE84C298CAB52ULL,
		0xC6ECD1AF06A36D77ULL,
		0x366A5F3373CDC4CDULL,
		0xC22B788B54CEBA6EULL,
		0xD12E37ABEFC5EB5FULL,
		0xB60811348E6374ABULL,
		0x000000EB16558939ULL
	}};
	shift = 40;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4803FA1FC9D9B426ULL,
		0x79E4F597483ABE49ULL,
		0x1DCCE551F2317ACAULL,
		0x3F4B2497E8D64226ULL,
		0x2BC8911FD01163BCULL,
		0x70E8788F89C27631ULL,
		0x2996121C633D211DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B3684C000000000ULL,
		0x0757C929007F43F9ULL,
		0x462F594F3C9EB2E9ULL,
		0x1AC844C3B99CAA3EULL,
		0x022C7787E96492FDULL,
		0x384EC625791223FAULL,
		0x67A423AE1D0F11F1ULL,
		0x0000000532C2438CULL
	}};
	shift = 37;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4F9D316AA5805BC7ULL,
		0x23684D438B85B8E0ULL,
		0x0FDD156FD4FF5A1BULL,
		0xDABEA0F1FC137F4FULL,
		0xA7700AA7D5F1A9B2ULL,
		0x3CDF6ECF9D55FE29ULL,
		0xBFB5058A29F18180ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E00000000000000ULL,
		0xC09F3A62D54B00B7ULL,
		0x3646D09A87170B71ULL,
		0x9E1FBA2ADFA9FEB4ULL,
		0x65B57D41E3F826FEULL,
		0x534EE0154FABE353ULL,
		0x0079BEDD9F3AABFCULL,
		0x017F6A0B1453E303ULL
	}};
	shift = 57;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x161B52BE1ED5FDCAULL,
		0xC85F017775FE986EULL,
		0x3BF986C8634896F3ULL,
		0x6D1D01031BA03C50ULL,
		0x388D4ACF9893932FULL,
		0xA6B397D70B6C47AAULL,
		0x33E5241C9458CD05ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0F6AFEE5000000ULL,
		0xBBBAFF4C370B0DA9ULL,
		0x6431A44B79E42F80ULL,
		0x818DD01E281DFCC3ULL,
		0x67CC49C997B68E80ULL,
		0xEB85B623D51C46A5ULL,
		0x0E4A2C6682D359CBULL,
		0x000000000019F292ULL
	}};
	shift = 23;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3651FEB457708C8EULL,
		0x06BA17E6003ABE15ULL,
		0x3102025CBC5481C4ULL,
		0x56FB9051A3B746B8ULL,
		0x641823F7F4868A2AULL,
		0x07D5969F30661E04ULL,
		0x9C6196607D8884A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FEB457708C8E000ULL,
		0xA17E6003ABE15365ULL,
		0x2025CBC5481C406BULL,
		0xB9051A3B746B8310ULL,
		0x823F7F4868A2A56FULL,
		0x5969F30661E04641ULL,
		0x196607D8884A007DULL,
		0x00000000000009C6ULL
	}};
	shift = 12;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5C889A20BBDA25E0ULL,
		0x0A52E89643615184ULL,
		0xF83516FA6A6B6B28ULL,
		0xF630DCDC4A7D21C1ULL,
		0x596F874DA37A3B08ULL,
		0x0DC2E1491E3749F6ULL,
		0x036A3C6DA6EE2562ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EF689780000000ULL,
		0x590D854611722268ULL,
		0xE9A9ADACA0294BA2ULL,
		0x7129F48707E0D45BULL,
		0x368DE8EC23D8C373ULL,
		0x2478DD27D965BE1DULL,
		0xB69BB89588370B85ULL,
		0x00000000000DA8F1ULL
	}};
	shift = 26;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xECC9B9265FEB8450ULL,
		0x068EEA45496FBEB4ULL,
		0x4DC69E542C621CA4ULL,
		0x33040E59BE845812ULL,
		0x06502D81C47A607AULL,
		0x0CA7F1B2562C31FAULL,
		0x672DDED242197F75ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97FAE11400000000ULL,
		0x525BEFAD3B326E49ULL,
		0x0B18872901A3BA91ULL,
		0x6FA116049371A795ULL,
		0x711E981E8CC10396ULL,
		0x958B0C7E81940B60ULL,
		0x90865FDD4329FC6CULL,
		0x0000000019CB77B4ULL
	}};
	shift = 30;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xACEB5412F27C9B56ULL,
		0x1D97E74F4B8A7A0CULL,
		0x6C5465FE05791B41ULL,
		0x7ADB1BE1121958ABULL,
		0xEABB64DB98971948ULL,
		0x7F398D4720C1E838ULL,
		0xD5E30BC66FD1849FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09793E4DAB000000ULL,
		0xA7A5C53D065675AAULL,
		0xFF02BC8DA08ECBF3ULL,
		0xF0890CAC55B62A32ULL,
		0x6DCC4B8CA43D6D8DULL,
		0xA39060F41C755DB2ULL,
		0xE337E8C24FBF9CC6ULL,
		0x00000000006AF185ULL
	}};
	shift = 23;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4D0E1665A34DB8E9ULL,
		0xDA57F20F2C2737F1ULL,
		0x3B022542ED8AAF4EULL,
		0x14829903C2167B1AULL,
		0x6B07ABFDBCD826A2ULL,
		0x6F2C5A85274FB382ULL,
		0x5CEF98AAED41EF63ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E3A400000000000ULL,
		0xCDFC5343859968D3ULL,
		0xABD3B695FC83CB09ULL,
		0x9EC68EC08950BB62ULL,
		0x09A88520A640F085ULL,
		0xECE09AC1EAFF6F36ULL,
		0x7BD8DBCB16A149D3ULL,
		0x0000173BE62ABB50ULL
	}};
	shift = 46;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5AB370A7AF373760ULL,
		0x428852460CD306B3ULL,
		0xFBD56BAB81FA1F16ULL,
		0x5524412C56488953ULL,
		0x6AE18B257CC5C210ULL,
		0x24AFFA1C1ECBAF1CULL,
		0x6A5D5B0DB979F0F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29EBCDCDD8000000ULL,
		0x918334C1ACD6ACDCULL,
		0xEAE07E87C590A214ULL,
		0x4B15922254FEF55AULL,
		0xC95F317084154910ULL,
		0x8707B2EBC71AB862ULL,
		0xC36E5E7C3D092BFEULL,
		0x00000000001A9756ULL
	}};
	shift = 22;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEC181992502DF0A9ULL,
		0xC8F83E3C9E565784ULL,
		0x3345F265ED40C81BULL,
		0x78861EF462C85D44ULL,
		0xD0DB9ADC292088EFULL,
		0x3B9FF8C65D5FA0F2ULL,
		0x34E32F4312062A9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5200000000000000ULL,
		0x09D8303324A05BE1ULL,
		0x3791F07C793CACAFULL,
		0x88668BE4CBDA8190ULL,
		0xDEF10C3DE8C590BAULL,
		0xE5A1B735B8524111ULL,
		0x38773FF18CBABF41ULL,
		0x0069C65E86240C55ULL
	}};
	shift = 57;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2E1A4217FDAF85EAULL,
		0x4F0B2487B3515A7EULL,
		0x752A5E54AB72D7E9ULL,
		0x6ADFBF89BFE5BB88ULL,
		0x310C043CE120621BULL,
		0x2D6E49FAF616784AULL,
		0x2DA0F71A159C8AF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4217FDAF85EA000ULL,
		0xB2487B3515A7E2E1ULL,
		0xA5E54AB72D7E94F0ULL,
		0xFBF89BFE5BB88752ULL,
		0xC043CE120621B6ADULL,
		0xE49FAF616784A310ULL,
		0x0F71A159C8AF72D6ULL,
		0x00000000000002DAULL
	}};
	shift = 12;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6D08BFD2593E7BDDULL,
		0x508966C00A625A17ULL,
		0x8A9AB5C7D87A647FULL,
		0x6B785447D49A34ABULL,
		0xECAC202167C8CC7BULL,
		0x44C49640E483129AULL,
		0x5C66C51633DE62DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDD0000000000000ULL,
		0xA176D08BFD2593E7ULL,
		0x47F508966C00A625ULL,
		0x4AB8A9AB5C7D87A6ULL,
		0xC7B6B785447D49A3ULL,
		0x29AECAC202167C8CULL,
		0x2DF44C49640E4831ULL,
		0x0005C66C51633DE6ULL
	}};
	shift = 52;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDF1FD77B2E0A856AULL,
		0x1EC73C3BD70ABC17ULL,
		0xE8E4E9769D9A41BAULL,
		0x281D79846FAD94BFULL,
		0x33DD886ACF9A2D1EULL,
		0x87B98FF36C37C55CULL,
		0xC101824D136E7FF2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A80000000000000ULL,
		0x05F7C7F5DECB82A1ULL,
		0x6E87B1CF0EF5C2AFULL,
		0x2FFA393A5DA76690ULL,
		0x478A075E611BEB65ULL,
		0x570CF7621AB3E68BULL,
		0xFCA1EE63FCDB0DF1ULL,
		0x003040609344DB9FULL
	}};
	shift = 54;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x80FE37E7BFC69836ULL,
		0xD142A3048AA7DCABULL,
		0x8A4191A02A1CC59BULL,
		0x92985ACA42233C63ULL,
		0x797A26FE85D27D33ULL,
		0x90B3061C6E269130ULL,
		0xF040183142EE3A80ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8DF9EFF1A60D80ULL,
		0x50A8C122A9F72AE0ULL,
		0x9064680A873166F4ULL,
		0xA616B29088CF18E2ULL,
		0x5E89BFA1749F4CE4ULL,
		0x2CC1871B89A44C1EULL,
		0x10060C50BB8EA024ULL,
		0x000000000000003CULL
	}};
	shift = 6;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB9C27C6950E5D659ULL,
		0x80E60F615DCBD8BEULL,
		0xEE9A10790BB41ED9ULL,
		0x846B7A44268FF5B7ULL,
		0x791246F82178F19BULL,
		0x1CE55C680DA73A6BULL,
		0x188F21A812581015ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6950E5D65900000ULL,
		0xF615DCBD8BEB9C27ULL,
		0x0790BB41ED980E60ULL,
		0xA44268FF5B7EE9A1ULL,
		0x6F82178F19B846B7ULL,
		0xC680DA73A6B79124ULL,
		0x1A8125810151CE55ULL,
		0x00000000000188F2ULL
	}};
	shift = 20;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA26CC341BDC7E1D3ULL,
		0xB74EBF0E3B03DDA4ULL,
		0x68233B86CF5FCE10ULL,
		0x2616666908F032E8ULL,
		0x8B7ADB285FA757D2ULL,
		0x7DA0E6A331C73593ULL,
		0xCE8FD3717B2DB5EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x874C000000000000ULL,
		0x769289B30D06F71FULL,
		0x3842DD3AFC38EC0FULL,
		0xCBA1A08CEE1B3D7FULL,
		0x5F48985999A423C0ULL,
		0xD64E2DEB6CA17E9DULL,
		0xD7B9F6839A8CC71CULL,
		0x00033A3F4DC5ECB6ULL
	}};
	shift = 50;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6BB64D12446060AEULL,
		0xBA0FA98BE6F6F0EDULL,
		0x627742161CDA46EFULL,
		0x2D0E3CF65BF971D2ULL,
		0x8FF5E88EBAF0E444ULL,
		0x1C0C69533D0AAD34ULL,
		0x1685F08C33CD5899ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B8000000000000ULL,
		0xC3B5AED934491181ULL,
		0x1BBEE83EA62F9BDBULL,
		0xC74989DD08587369ULL,
		0x9110B438F3D96FE5ULL,
		0xB4D23FD7A23AEBC3ULL,
		0x62647031A54CF42AULL,
		0x00005A17C230CF35ULL
	}};
	shift = 50;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD4E23674B3797C15ULL,
		0xF769209B72C63F65ULL,
		0xE90F4833EC18F5B3ULL,
		0x0600289212E506D3ULL,
		0xDD9F27B6AA29D816ULL,
		0x7241DE87D75CC2A3ULL,
		0xA9808EB1A5C2AECFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B3A59BCBE0A800ULL,
		0x4904DB9631FB2EA7ULL,
		0x7A419F60C7AD9FBBULL,
		0x0144909728369F48ULL,
		0xF93DB5514EC0B030ULL,
		0x0EF43EBAE6151EECULL,
		0x04758D2E15767B92ULL,
		0x000000000000054CULL
	}};
	shift = 11;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x42D7F057128D5590ULL,
		0xFAFFE84E6A01A6E9ULL,
		0x0A7754B8F5C51D11ULL,
		0x026B47BD09704E76ULL,
		0xE06C8C554961D97BULL,
		0x527986DE34BA5328ULL,
		0xDC7596EC0BFBF5C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF82B8946AAC80000ULL,
		0xF4273500D374A16BULL,
		0xAA5C7AE28E88FD7FULL,
		0xA3DE84B8273B053BULL,
		0x462AA4B0ECBD8135ULL,
		0xC36F1A5D29947036ULL,
		0xCB7605FDFAE2293CULL,
		0x0000000000006E3AULL
	}};
	shift = 15;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x01980C310ADA2590ULL,
		0x3001C6C5C366841AULL,
		0x027DC0229F5CBB57ULL,
		0x2023EEDB93C6908BULL,
		0xF9B255C38D94ECD0ULL,
		0xECE10ADBB7956EBFULL,
		0x63E6A99ABB5E9A7CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B20000000000000ULL,
		0x08340330186215B4ULL,
		0x76AE60038D8B86CDULL,
		0x211604FB80453EB9ULL,
		0xD9A04047DDB7278DULL,
		0xDD7FF364AB871B29ULL,
		0x34F9D9C215B76F2AULL,
		0x0000C7CD533576BDULL
	}};
	shift = 49;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4A1F9708FB418904ULL,
		0x821D0BE1BFAA6F68ULL,
		0x88E5F139545A9E81ULL,
		0x440C1ABF6BB8864BULL,
		0x90413BCE17CFC7BFULL,
		0x8936020388C5C49CULL,
		0x76229881AF0D71B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x708FB41890400000ULL,
		0xBE1BFAA6F684A1F9ULL,
		0x139545A9E81821D0ULL,
		0xABF6BB8864B88E5FULL,
		0xBCE17CFC7BF440C1ULL,
		0x20388C5C49C90413ULL,
		0x881AF0D71B689360ULL,
		0x0000000000076229ULL
	}};
	shift = 20;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD729A7BFCB429DF8ULL,
		0xAE34593601652CE8ULL,
		0x3926DC1D00476B2BULL,
		0xEC7C907306F5C308ULL,
		0x193717B1BA68C0C2ULL,
		0x52DAC755F08DEAE8ULL,
		0xB1928B93DB6AE193ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BF0000000000000ULL,
		0x59D1AE534F7F9685ULL,
		0xD6575C68B26C02CAULL,
		0x8610724DB83A008EULL,
		0x8185D8F920E60DEBULL,
		0xD5D0326E2F6374D1ULL,
		0xC326A5B58EABE11BULL,
		0x000163251727B6D5ULL
	}};
	shift = 49;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5F6F6091A9A55697ULL,
		0x3E83B1DC49690AD6ULL,
		0x86062942EB165363ULL,
		0x1F0F33242E241D31ULL,
		0x2FFA13A67BCCC067ULL,
		0x40E80A1E74D3C275ULL,
		0xBE3C5135C86B83A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E00000000000000ULL,
		0xACBEDEC123534AADULL,
		0xC67D0763B892D215ULL,
		0x630C0C5285D62CA6ULL,
		0xCE3E1E66485C483AULL,
		0xEA5FF4274CF79980ULL,
		0x4E81D0143CE9A784ULL,
		0x017C78A26B90D707ULL
	}};
	shift = 57;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA65DC863AC366117ULL,
		0x8343B5A3B02CF7FBULL,
		0x268126E339E7E95EULL,
		0xED0D31D74AC1D5B6ULL,
		0x96A49F624E60C471ULL,
		0x13E84412E16AF84CULL,
		0xC99D5E11178CB89FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC22E000000000000ULL,
		0xEFF74CBB90C7586CULL,
		0xD2BD06876B476059ULL,
		0xAB6C4D024DC673CFULL,
		0x88E3DA1A63AE9583ULL,
		0xF0992D493EC49CC1ULL,
		0x713E27D08825C2D5ULL,
		0x0001933ABC222F19ULL
	}};
	shift = 49;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8E12381F86323390ULL,
		0x8F9DB8465C327FAAULL,
		0xC9CF15BB3E997025ULL,
		0x0936094881BCE10CULL,
		0xB7E15B17A380EE44ULL,
		0x02306713426CA080ULL,
		0x27500C206E67C3D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3848E07E18C8CE40ULL,
		0x3E76E11970C9FEAAULL,
		0x273C56ECFA65C096ULL,
		0x24D8252206F38433ULL,
		0xDF856C5E8E03B910ULL,
		0x08C19C4D09B28202ULL,
		0x9D403081B99F0F40ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC27FFFB105EDD993ULL,
		0x20AD51E92DE2259AULL,
		0xB6725E3AC0FFB04BULL,
		0x135F321E884AAA01ULL,
		0xBE37832A87555D9EULL,
		0x5390E33147AFD195ULL,
		0x5F54C55E6CFB6B33ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105EDD9930000000ULL,
		0x92DE2259AC27FFFBULL,
		0xAC0FFB04B20AD51EULL,
		0xE884AAA01B6725E3ULL,
		0xA87555D9E135F321ULL,
		0x147AFD195BE37832ULL,
		0xE6CFB6B335390E33ULL,
		0x0000000005F54C55ULL
	}};
	shift = 28;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7704576B5B7A15C1ULL,
		0xF8AE61076E077D35ULL,
		0x293B42ECBF4686B8ULL,
		0x4ACDB61FAFC75639ULL,
		0x98FCE417C36AF648ULL,
		0x0912097E7A951E85ULL,
		0x202BEA1EC0AA9488ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x5DC115DAD6DE8570ULL,
		0x3E2B9841DB81DF4DULL,
		0x4A4ED0BB2FD1A1AEULL,
		0x12B36D87EBF1D58EULL,
		0x663F3905F0DABD92ULL,
		0x0244825F9EA547A1ULL,
		0x080AFA87B02AA522ULL
	}};
	shift = 62;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD9C08927B35CD396ULL,
		0x1A82140BA4FF66ADULL,
		0xAC91583903E08F97ULL,
		0x29358632E390C1AAULL,
		0xAFC3280A00107143ULL,
		0x75940F9BBE042CAAULL,
		0xDC393C6C357B248DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69CB000000000000ULL,
		0xB356ECE04493D9AEULL,
		0x47CB8D410A05D27FULL,
		0x60D55648AC1C81F0ULL,
		0x38A1949AC31971C8ULL,
		0x165557E194050008ULL,
		0x9246BACA07CDDF02ULL,
		0x00006E1C9E361ABDULL
	}};
	shift = 47;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8EBEB6F7CCC7191AULL,
		0x769B293479BCD379ULL,
		0xF2B2247687D5E2EBULL,
		0x4A81A61139163EE4ULL,
		0x9B35F0A1B947EB16ULL,
		0x9DA1AA03289031B6ULL,
		0x821F85F1BA3546A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEF998E323400000ULL,
		0x268F379A6F31D7D6ULL,
		0x8ED0FABC5D6ED365ULL,
		0xC22722C7DC9E5644ULL,
		0x143728FD62C95034ULL,
		0x4065120636D366BEULL,
		0xBE3746A8D533B435ULL,
		0x00000000001043F0ULL
	}};
	shift = 21;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2DB1793B68622AA3ULL,
		0xE5E71ECB3045DA16ULL,
		0x8F2775AB13CE601DULL,
		0x7CE437D13B5CE7EFULL,
		0xD3D64A009149B1F9ULL,
		0x47E74725F7BB99F4ULL,
		0x45A26D2EF21DE4F6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB1793B68622AA30ULL,
		0x5E71ECB3045DA162ULL,
		0xF2775AB13CE601DEULL,
		0xCE437D13B5CE7EF8ULL,
		0x3D64A009149B1F97ULL,
		0x7E74725F7BB99F4DULL,
		0x5A26D2EF21DE4F64ULL,
		0x0000000000000004ULL
	}};
	shift = 4;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0C67C4A43F1F5F98ULL,
		0x719043CD149A27CBULL,
		0xC4F1230A829E3D84ULL,
		0x1BCDAB6E8339E94EULL,
		0xB80834DAAFCE3D8EULL,
		0x41AE81791D4A3C8DULL,
		0x86E3FE9FD0E900D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1F5F9800000000ULL,
		0x149A27CB0C67C4A4ULL,
		0x829E3D84719043CDULL,
		0x8339E94EC4F1230AULL,
		0xAFCE3D8E1BCDAB6EULL,
		0x1D4A3C8DB80834DAULL,
		0xD0E900D141AE8179ULL,
		0x0000000086E3FE9FULL
	}};
	shift = 32;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x760B14CA282B88CAULL,
		0xCFDA0FA80B796609ULL,
		0x9802148ADFE27242ULL,
		0xCB117800BFFA741BULL,
		0xE04D5CE5B7D1172EULL,
		0xA80CFF52B3CF8A3EULL,
		0x70192292DEA4386AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C5328A0AE23280ULL,
		0xF683EA02DE59825DULL,
		0x008522B7F89C90B3ULL,
		0xC45E002FFE9D06E6ULL,
		0x1357396DF445CBB2ULL,
		0x033FD4ACF3E28FB8ULL,
		0x0648A4B7A90E1AAAULL,
		0x000000000000001CULL
	}};
	shift = 6;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75443F956759E9E9ULL,
		0xB874AA44265223E2ULL,
		0xCB9CB13C76DCE78AULL,
		0x3211A2A42B6CE33CULL,
		0x7DA775CA2177ED13ULL,
		0xE1FE430AE2906E09ULL,
		0xC42B5D1EDE4CF191ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67A7A4000000000ULL,
		0x9488F89D510FE559ULL,
		0xB739E2AE1D2A9109ULL,
		0xDB38CF32E72C4F1DULL,
		0x5DFB44CC8468A90AULL,
		0xA41B825F69DD7288ULL,
		0x933C64787F90C2B8ULL,
		0x000000310AD747B7ULL
	}};
	shift = 38;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x926C5D18A3A93FEEULL,
		0xDF2EAFDBE5A62DBEULL,
		0x034D7EB1444E9A27ULL,
		0x1B93DF537A34E5D7ULL,
		0xB2DB65033DA0C89BULL,
		0x1442FAA84BA2577BULL,
		0xD4F0D5B84CB283BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE00000000000000ULL,
		0xBE926C5D18A3A93FULL,
		0x27DF2EAFDBE5A62DULL,
		0xD7034D7EB1444E9AULL,
		0x9B1B93DF537A34E5ULL,
		0x7BB2DB65033DA0C8ULL,
		0xBD1442FAA84BA257ULL,
		0x00D4F0D5B84CB283ULL
	}};
	shift = 56;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4DE41036631D3257ULL,
		0xA7A03E3CA4F0E8D3ULL,
		0x0FE82796042C296FULL,
		0xABD1DD5AE0DB349FULL,
		0x6399E515A74774A9ULL,
		0x1FDEA1D6CD16096BULL,
		0x64521103DB94DB07ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63A64AE00000000ULL,
		0x49E1D1A69BC8206CULL,
		0x085852DF4F407C79ULL,
		0xC1B6693E1FD04F2CULL,
		0x4E8EE95357A3BAB5ULL,
		0x9A2C12D6C733CA2BULL,
		0xB729B60E3FBD43ADULL,
		0x00000000C8A42207ULL
	}};
	shift = 33;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x01F43A7005B75F46ULL,
		0x6C046FA9B995421AULL,
		0xA6DD9CD889AB10B1ULL,
		0x2149B74F7F10E21AULL,
		0x7C4B89306979EFBCULL,
		0xCBBE02266EA05B47ULL,
		0x2287BF3FCAAA5020ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E00B6EBE8C00000ULL,
		0xF53732A843403E87ULL,
		0x9B113562162D808DULL,
		0xE9EFE21C4354DBB3ULL,
		0x260D2F3DF7842936ULL,
		0x44CDD40B68EF8971ULL,
		0xE7F9554A041977C0ULL,
		0x00000000000450F7ULL
	}};
	shift = 21;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC0984C4F054958FULL,
		0xA43C025253E569FDULL,
		0x15533A7C8C79961AULL,
		0x3C5C9FA6D366CF9DULL,
		0x4DB7341096243663ULL,
		0xEF5D902EE7246D5CULL,
		0x94E197E23C9FC22DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C4F054958F0000ULL,
		0x025253E569FDFC09ULL,
		0x3A7C8C79961AA43CULL,
		0x9FA6D366CF9D1553ULL,
		0x3410962436633C5CULL,
		0x902EE7246D5C4DB7ULL,
		0x97E23C9FC22DEF5DULL,
		0x00000000000094E1ULL
	}};
	shift = 16;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8A789821E7585F4BULL,
		0x61F8A9AD7A5276C6ULL,
		0x2BDA2D34BB88F72AULL,
		0x9B9CAFBDD659B2EDULL,
		0x449A0856652D4CBFULL,
		0x7112340A88645481ULL,
		0xCB90174DA3FFFCD4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13043CEB0BE9600ULL,
		0xF1535AF4A4ED8D14ULL,
		0xB45A697711EE54C3ULL,
		0x395F7BACB365DA57ULL,
		0x3410ACCA5A997F37ULL,
		0x24681510C8A90289ULL,
		0x202E9B47FFF9A8E2ULL,
		0x0000000000000197ULL
	}};
	shift = 9;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4002BA1FBF65331AULL,
		0x56EB02DB78C6F7D3ULL,
		0x4B8CD06B7F87E78DULL,
		0xAA0AEC095AA133D5ULL,
		0xC069BA2BBBF04742ULL,
		0xF5AD257E28CB4907ULL,
		0x5D4AD8DCD4AFEEA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF65331A0000000ULL,
		0xB78C6F7D34002BA1ULL,
		0xB7F87E78D56EB02DULL,
		0x95AA133D54B8CD06ULL,
		0xBBBF04742AA0AEC0ULL,
		0xE28CB4907C069BA2ULL,
		0xCD4AFEEA2F5AD257ULL,
		0x0000000005D4AD8DULL
	}};
	shift = 28;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0ACEB0CA42757FAFULL,
		0xC168C87F0F492D70ULL,
		0x9D0216A809EDEB48ULL,
		0x717C3B42B3B9E30DULL,
		0x0F31251D338EC6A4ULL,
		0xFA0608EDC3057AFDULL,
		0xF8578F0F30EA7760ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x02B3AC32909D5FEBULL,
		0x305A321FC3D24B5CULL,
		0x674085AA027B7AD2ULL,
		0x1C5F0ED0ACEE78C3ULL,
		0x43CC49474CE3B1A9ULL,
		0x3E81823B70C15EBFULL,
		0x3E15E3C3CC3A9DD8ULL
	}};
	shift = 62;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x57A50130D7BFD10FULL,
		0x8E394EB7D31385E7ULL,
		0x7C83856BF7CDEEBBULL,
		0x3338FDA62E729BD1ULL,
		0x8B2DD39D8A4533FBULL,
		0xB348D2FDFA3D3460ULL,
		0x2A54674FB475EEE3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261AF7FA21E00000ULL,
		0xD6FA6270BCEAF4A0ULL,
		0xAD7EF9BDD771C729ULL,
		0xB4C5CE537A2F9070ULL,
		0x73B148A67F66671FULL,
		0x5FBF47A68C1165BAULL,
		0xE9F68EBDDC76691AULL,
		0x0000000000054A8CULL
	}};
	shift = 21;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5572EB06F08F83D8ULL,
		0xB8A1A542C6188890ULL,
		0x005E92FC350504B2ULL,
		0x913454E7F6A133DFULL,
		0x097DE7FF7D3878B7ULL,
		0x6149F799D3EE9716ULL,
		0x53D165B68F4BF24BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F07B0000000000ULL,
		0xC311120AAE5D60DEULL,
		0xA0A096571434A858ULL,
		0xD4267BE00BD25F86ULL,
		0xA70F16F2268A9CFEULL,
		0x7DD2E2C12FBCFFEFULL,
		0xE97E496C293EF33AULL,
		0x0000000A7A2CB6D1ULL
	}};
	shift = 37;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1159198C0AA6B1A4ULL,
		0x46E393CB36667683ULL,
		0x60303B2CF52EC08EULL,
		0xE1BDD444B9BCA03CULL,
		0x0B18776BE9CABC95ULL,
		0x98D8C37D6E5B8243ULL,
		0xBF8E40D38D606D6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0AA6B1A40000000ULL,
		0xB366676831159198ULL,
		0xCF52EC08E46E393CULL,
		0x4B9BCA03C60303B2ULL,
		0xBE9CABC95E1BDD44ULL,
		0xD6E5B82430B18776ULL,
		0x38D606D6E98D8C37ULL,
		0x000000000BF8E40DULL
	}};
	shift = 28;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFA71D42BD039BD4AULL,
		0x130A35D761D707B4ULL,
		0x089633ED71B9CC75ULL,
		0x5CFADB8A230F954DULL,
		0xF833989DE87E4DFBULL,
		0x2B6088F4612CE221ULL,
		0x1EE980C07CC9DD5EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x039BD4A000000000ULL,
		0x1D707B4FA71D42BDULL,
		0x1B9CC75130A35D76ULL,
		0x30F954D089633ED7ULL,
		0x87E4DFB5CFADB8A2ULL,
		0x12CE221F833989DEULL,
		0xCC9DD5E2B6088F46ULL,
		0x00000001EE980C07ULL
	}};
	shift = 36;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCA7FACBDC83F1DCBULL,
		0x6D6E6AC724058A76ULL,
		0xF372C35E9F890946ULL,
		0xE589E917BC6A7311ULL,
		0x1782EC9068E1296BULL,
		0x84D5D978D3634A3CULL,
		0x5AD22C3889D1929AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F720FC772C00000ULL,
		0xB1C901629DB29FEBULL,
		0xD7A7E242519B5B9AULL,
		0x45EF1A9CC47CDCB0ULL,
		0x241A384A5AF9627AULL,
		0x5E34D8D28F05E0BBULL,
		0x0E227464A6A13576ULL,
		0x000000000016B48BULL
	}};
	shift = 22;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB1A8CB272D5B3FD8ULL,
		0x5DF4C7268E03E06DULL,
		0xE2681746E9BAE795ULL,
		0xCF9D8E6E12CEF90AULL,
		0x37B51A524486531CULL,
		0x1F0E058CD5975C8CULL,
		0x147F2E5E0D4846E2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x272D5B3FD8000000ULL,
		0x268E03E06DB1A8CBULL,
		0x46E9BAE7955DF4C7ULL,
		0x6E12CEF90AE26817ULL,
		0x524486531CCF9D8EULL,
		0x8CD5975C8C37B51AULL,
		0x5E0D4846E21F0E05ULL,
		0x0000000000147F2EULL
	}};
	shift = 24;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAB80FB7DFB7E7F6DULL,
		0xA4C003DB734F19D0ULL,
		0x37CCC2F343119B55ULL,
		0x359F0B87ED7D8530ULL,
		0x1DC1D30EA53D0C05ULL,
		0x42E3C62C27FF4515ULL,
		0x8B61E97B588C955EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0x15701F6FBF6FCFEDULL,
		0xB498007B6E69E33AULL,
		0x06F9985E6862336AULL,
		0xA6B3E170FDAFB0A6ULL,
		0xA3B83A61D4A7A180ULL,
		0xC85C78C584FFE8A2ULL,
		0x116C3D2F6B1192ABULL
	}};
	shift = 61;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBD292E2AA610CF98ULL,
		0x0F6CB030B99B03DCULL,
		0x25648021E1578DBBULL,
		0x66E49DFE0729D8B1ULL,
		0xB3340C4A5E8DC16AULL,
		0x5673154FDFC141EFULL,
		0x0B9974C3DF6F12E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xCBD292E2AA610CF9ULL,
		0xB0F6CB030B99B03DULL,
		0x125648021E1578DBULL,
		0xA66E49DFE0729D8BULL,
		0xFB3340C4A5E8DC16ULL,
		0x35673154FDFC141EULL,
		0x00B9974C3DF6F12EULL
	}};
	shift = 60;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC52CDDC837FC043FULL,
		0x4632F62BD87CEA88ULL,
		0x9C39D0D4BA16E06BULL,
		0xCB0895B4EFE7FD43ULL,
		0x6DE048139AAA235FULL,
		0xDBB24B2A00D63C5AULL,
		0x648DECEA2D4AC149ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52CDDC837FC043F0ULL,
		0x632F62BD87CEA88CULL,
		0xC39D0D4BA16E06B4ULL,
		0xB0895B4EFE7FD439ULL,
		0xDE048139AAA235FCULL,
		0xBB24B2A00D63C5A6ULL,
		0x48DECEA2D4AC149DULL,
		0x0000000000000006ULL
	}};
	shift = 4;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4DBC566AF77FE031ULL,
		0xAED05C9EB0B374A4ULL,
		0x99FCA29DB7DCB67CULL,
		0x05B7733EC088B1D5ULL,
		0x64A322737BB74539ULL,
		0x75D4589606CB51B9ULL,
		0x7F985F220EC469DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF01880000000000ULL,
		0x9BA5226DE2B357BBULL,
		0xE5B3E57682E4F585ULL,
		0x458EACCFE514EDBEULL,
		0xBA29C82DBB99F604ULL,
		0x5A8DCB2519139BDDULL,
		0x234EFBAEA2C4B036ULL,
		0x000003FCC2F91076ULL
	}};
	shift = 43;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4C2474A58882C60DULL,
		0x8A957A23AA4025F9ULL,
		0xD971659F0F2A046AULL,
		0x238DF366FD4A36D8ULL,
		0xD862641A4A4644BAULL,
		0x225DFD266B605F88ULL,
		0xF8A0FAFCB6BF0721ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB183400000000000ULL,
		0x097E53091D296220ULL,
		0x811AA2A55E88EA90ULL,
		0x8DB6365C5967C3CAULL,
		0x912E88E37CD9BF52ULL,
		0x17E2361899069291ULL,
		0xC1C848977F499AD8ULL,
		0x00003E283EBF2DAFULL
	}};
	shift = 46;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B03561B3DAF837DULL,
		0x4650E81D59F0C61DULL,
		0xA9D43391F5B6199AULL,
		0x257DC90D36336DCBULL,
		0x1ACCC12F60070F48ULL,
		0xF15B4DD02173CE52ULL,
		0x65603510E45534ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF400000000000000ULL,
		0x74EC0D586CF6BE0DULL,
		0x691943A07567C318ULL,
		0x2EA750CE47D6D866ULL,
		0x2095F72434D8CDB7ULL,
		0x486B3304BD801C3DULL,
		0xB3C56D374085CF39ULL,
		0x019580D4439154D3ULL
	}};
	shift = 58;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x488F5F93BD7E46F7ULL,
		0x5C6B1AD9042CA650ULL,
		0xDE42382B302D4D8AULL,
		0x9ACE8DEA5BCCE845ULL,
		0x96DA866F57D0C614ULL,
		0x1D35AA330569BF9BULL,
		0x84CF207356CB8ABEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F91BDC000000000ULL,
		0x0B29941223D7E4EFULL,
		0x0B5362971AC6B641ULL,
		0xF33A1177908E0ACCULL,
		0xF4318526B3A37A96ULL,
		0x5A6FE6E5B6A19BD5ULL,
		0xB2E2AF874D6A8CC1ULL,
		0x0000002133C81CD5ULL
	}};
	shift = 38;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x114763933C3A89F6ULL,
		0x682F06AD754B145CULL,
		0x25E13E1285EF9B22ULL,
		0x1974D132E03FC5AEULL,
		0x5E5945D03A968DB9ULL,
		0x1CF9CDAD49D0D533ULL,
		0xD5EC2ADF89969CC1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x451D8E4CF0EA27D8ULL,
		0xA0BC1AB5D52C5170ULL,
		0x9784F84A17BE6C89ULL,
		0x65D344CB80FF16B8ULL,
		0x79651740EA5A36E4ULL,
		0x73E736B5274354CDULL,
		0x57B0AB7E265A7304ULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x979063F72A365EE3ULL,
		0x14FBCFC7E591420BULL,
		0xA2CAB22FDF3FC63DULL,
		0xBD548CE59D0184A8ULL,
		0x3227528E3D8D4091ULL,
		0xAFCC1632C8073231ULL,
		0xB21A826DF0024349ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF718000000000000ULL,
		0x105CBC831FB951B2ULL,
		0x31E8A7DE7E3F2C8AULL,
		0x25451655917EF9FEULL,
		0x048DEAA4672CE80CULL,
		0x9189913A9471EC6AULL,
		0x1A4D7E60B1964039ULL,
		0x000590D4136F8012ULL
	}};
	shift = 51;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE2D591AEB32A73A8ULL,
		0x04EC1182A2707C16ULL,
		0xB0C896CB70433CF2ULL,
		0x93BD5FA1C4750EFCULL,
		0x2ACAE910A2FF7098ULL,
		0xE670112F99DD95BAULL,
		0x5E173CA038E41FDEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDC5AB235D6654E75ULL,
		0x409D8230544E0F82ULL,
		0x961912D96E08679EULL,
		0x1277ABF4388EA1DFULL,
		0x45595D22145FEE13ULL,
		0xDCCE0225F33BB2B7ULL,
		0x0BC2E794071C83FBULL
	}};
	shift = 61;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9AAAFA041E071A1AULL,
		0x1000B204D513AD6DULL,
		0xFB075F8F842D5ED4ULL,
		0x86E61132935AAEA8ULL,
		0x21EF53353D4E1F35ULL,
		0xE7E31065D676DD71ULL,
		0x686146D5F6AACB9DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A00000000000000ULL,
		0x6D9AAAFA041E071AULL,
		0xD41000B204D513ADULL,
		0xA8FB075F8F842D5EULL,
		0x3586E61132935AAEULL,
		0x7121EF53353D4E1FULL,
		0x9DE7E31065D676DDULL,
		0x00686146D5F6AACBULL
	}};
	shift = 56;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCC105D201CF6E49DULL,
		0x2143763E6C9FF2D6ULL,
		0xC1B8FFB64508F0D8ULL,
		0xB7E633B3BB1F1E20ULL,
		0x471FB07575EBCCC6ULL,
		0x81C2A5F107396BCDULL,
		0x998818D84748843FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93A0000000000000ULL,
		0x5AD9820BA4039EDCULL,
		0x1B04286EC7CD93FEULL,
		0xC418371FF6C8A11EULL,
		0x98D6FCC6767763E3ULL,
		0x79A8E3F60EAEBD79ULL,
		0x87F03854BE20E72DULL,
		0x001331031B08E910ULL
	}};
	shift = 53;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x609216929F8C4A33ULL,
		0xA85A127A90AC9F58ULL,
		0x68C5BAA05D803A01ULL,
		0xC4FB2665F9A4D364ULL,
		0xC096D32A6BB923E2ULL,
		0xD663A21D29002519ULL,
		0xB7E2013F3F5304CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8946600000000000ULL,
		0x93EB0C1242D253F1ULL,
		0x0740350B424F5215ULL,
		0x9A6C8D18B7540BB0ULL,
		0x247C589F64CCBF34ULL,
		0x04A33812DA654D77ULL,
		0x6099BACC7443A520ULL,
		0x000016FC4027E7EAULL
	}};
	shift = 45;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x602451FA1DB3CABCULL,
		0x18500A761BFC4059ULL,
		0x74594AB4EE4A8197ULL,
		0x7A1D26CF3D11C8BEULL,
		0x6DAFDD74F0D60816ULL,
		0x7A6ADD634A64337EULL,
		0x757E610E9C20197EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA1DB3CABC00000ULL,
		0xA761BFC405960245ULL,
		0xAB4EE4A819718500ULL,
		0x6CF3D11C8BE74594ULL,
		0xD74F0D608167A1D2ULL,
		0xD634A64337E6DAFDULL,
		0x10E9C20197E7A6ADULL,
		0x00000000000757E6ULL
	}};
	shift = 20;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x846E7E0736E67327ULL,
		0xEFC6E2A5E83EBE57ULL,
		0x8522875BBA19C0A9ULL,
		0x9B23D6BDAD06468FULL,
		0x1CAF9661080147A0ULL,
		0x3C2D4BF1613F0E91ULL,
		0x13EF46013C437045ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE64E0000000000ULL,
		0x7D7CAF08DCFC0E6DULL,
		0x338153DF8DC54BD0ULL,
		0x0C8D1F0A450EB774ULL,
		0x028F413647AD7B5AULL,
		0x7E1D22395F2CC210ULL,
		0x86E08A785A97E2C2ULL,
		0x00000027DE8C0278ULL
	}};
	shift = 41;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x18713DBC2BD339EBULL,
		0xFC3B5A8EE4524FCAULL,
		0xB42BF547A9E67936ULL,
		0xA95FFDC036CCF3DBULL,
		0x02EBCFF1359D5E2FULL,
		0xE8142F3963CBA112ULL,
		0x69BFCEF162D3DC1CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339EB00000000000ULL,
		0x24FCA18713DBC2BDULL,
		0x67936FC3B5A8EE45ULL,
		0xCF3DBB42BF547A9EULL,
		0xD5E2FA95FFDC036CULL,
		0xBA11202EBCFF1359ULL,
		0x3DC1CE8142F3963CULL,
		0x0000069BFCEF162DULL
	}};
	shift = 44;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB63997AD727B788FULL,
		0x4B9EC1823F8F0E38ULL,
		0xB5FA2D93D27E98B9ULL,
		0xB69566967AB18DD5ULL,
		0xFAD25E4DE551DFCEULL,
		0xD7D32F2F33A5018BULL,
		0x3D7A5AF80E4DAC96ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CCBD6B93DBC478ULL,
		0x5CF60C11FC7871C5ULL,
		0xAFD16C9E93F4C5CAULL,
		0xB4AB34B3D58C6EADULL,
		0xD692F26F2A8EFE75ULL,
		0xBE9979799D280C5FULL,
		0xEBD2D7C0726D64B6ULL,
		0x0000000000000001ULL
	}};
	shift = 3;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x61CD3E1937466FD3ULL,
		0x99AF2E1DD605F540ULL,
		0xC88B768A84097456ULL,
		0x6C52903B4AD9EB7FULL,
		0x6FBCE42BFD769DDCULL,
		0x44B1DBC8251C8070ULL,
		0xA931882570E4DDB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66FD300000000000ULL,
		0x5F54061CD3E19374ULL,
		0x9745699AF2E1DD60ULL,
		0x9EB7FC88B768A840ULL,
		0x69DDC6C52903B4ADULL,
		0xC80706FBCE42BFD7ULL,
		0x4DDB544B1DBC8251ULL,
		0x00000A931882570EULL
	}};
	shift = 44;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBFB5024A9CAB999FULL,
		0x48124B988941DEC9ULL,
		0x0E904811481FD501ULL,
		0xE23C9676048C9285ULL,
		0xA82AD288498E904CULL,
		0xE5EB3165457F549CULL,
		0x1F9C584B6691091FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024A9CAB999F0000ULL,
		0x4B988941DEC9BFB5ULL,
		0x4811481FD5014812ULL,
		0x9676048C92850E90ULL,
		0xD288498E904CE23CULL,
		0x3165457F549CA82AULL,
		0x584B6691091FE5EBULL,
		0x0000000000001F9CULL
	}};
	shift = 16;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2E8B6239728DA20CULL,
		0xFB6D46138CAAF4D9ULL,
		0xE73C7A41B64106D0ULL,
		0x75AB5E51C066B477ULL,
		0x83FC2C4D4BA5BBECULL,
		0x042F0643B69061CFULL,
		0x3A5BA544C40DA706ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9745B11CB946D106ULL,
		0x7DB6A309C6557A6CULL,
		0xF39E3D20DB208368ULL,
		0x3AD5AF28E0335A3BULL,
		0xC1FE1626A5D2DDF6ULL,
		0x02178321DB4830E7ULL,
		0x1D2DD2A26206D383ULL
	}};
	shift = 63;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8E1F8419A050FE0AULL,
		0xF4CBE34C51178ADFULL,
		0xD5B62702C3823B93ULL,
		0x6A65D81240E811C9ULL,
		0x7A9280E29420BC60ULL,
		0x6B7E133302A5A89BULL,
		0xDB8C5C6EFDA56E6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83340A1FC1400000ULL,
		0x698A22F15BF1C3F0ULL,
		0xE0587047727E997CULL,
		0x02481D02393AB6C4ULL,
		0x1C5284178C0D4CBBULL,
		0x666054B5136F5250ULL,
		0x8DDFB4ADCD6D6FC2ULL,
		0x00000000001B718BULL
	}};
	shift = 21;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1A664701C9915B7EULL,
		0xCC881F9F403BB687ULL,
		0xCFC986A8765F244BULL,
		0x6E135E7C2941DBF4ULL,
		0x17718714C372EF5FULL,
		0x6E74D61D24CF6312ULL,
		0x66A18661B2A8F229ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E4C8ADBF0000000ULL,
		0xFA01DDB438D33238ULL,
		0x43B2F9225E6440FCULL,
		0xE14A0EDFA67E4C35ULL,
		0xA61B977AFB709AF3ULL,
		0xE9267B1890BB8C38ULL,
		0x0D9547914B73A6B0ULL,
		0x0000000003350C33ULL
	}};
	shift = 27;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6FB56E7745B54B1DULL,
		0x833CCFB9BB64821BULL,
		0x144D623A337A97BAULL,
		0x47F386A9847BCDA1ULL,
		0x14A34F32067C1DDEULL,
		0x88F6BBDEF41A1195ULL,
		0x0F9B081AB8D3B252ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DD16D52C7400000ULL,
		0xEE6ED92086DBED5BULL,
		0x8E8CDEA5EEA0CF33ULL,
		0xAA611EF368451358ULL,
		0xCC819F077791FCE1ULL,
		0xF7BD0684654528D3ULL,
		0x06AE34EC94A23DAEULL,
		0x000000000003E6C2ULL
	}};
	shift = 22;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD6957BBACD46B4C8ULL,
		0xB92D25D41D792BBBULL,
		0xD96CA59E31D17FE8ULL,
		0x4B72B0155254CECCULL,
		0x81960685D223174EULL,
		0x5151CF4C43815305ULL,
		0xD7F3354FDDEC95F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D69900000000000ULL,
		0xF25777AD2AF7759AULL,
		0xA2FFD1725A4BA83AULL,
		0xA99D99B2D94B3C63ULL,
		0x462E9C96E5602AA4ULL,
		0x02A60B032C0D0BA4ULL,
		0xD92BE2A2A39E9887ULL,
		0x000001AFE66A9FBBULL
	}};
	shift = 41;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}