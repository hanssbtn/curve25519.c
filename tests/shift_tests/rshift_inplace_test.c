#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Inplace Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x31E649E6E9827E69ULL,
		0x8CE9FCB343B849ADULL,
		0x3E54BE129A7D890DULL,
		0xE56E71775A322D2AULL,
		0xA2F275F495A4F073ULL,
		0x7E60D1A3ED396D2DULL,
		0xCCC20E943888241DULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB849AD31E649E6E9ULL,
		0x7D890D8CE9FCB343ULL,
		0x322D2A3E54BE129AULL,
		0xA4F073E56E71775AULL,
		0x396D2DA2F275F495ULL,
		0x88241D7E60D1A3EDULL,
		0x000000CCC20E9438ULL,
		0x0000000000000000ULL
	}};
	int shift = 24;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x5E6060BA03AA5911ULL,
		0x704157C606646535ULL,
		0x64B9CD5CFCB690E4ULL,
		0x3FF89B100538E692ULL,
		0x08D3D54B5554ED0AULL,
		0x51379C40B97D54EBULL,
		0x524703212C2FCE73ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x082AF8C0CC8CA6ABULL,
		0x9739AB9F96D21C8EULL,
		0xFF136200A71CD24CULL,
		0x1A7AA96AAA9DA147ULL,
		0x26F388172FAA9D61ULL,
		0x48E0642585F9CE6AULL,
		0x000000000000000AULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x83E7983DC207DC55ULL,
		0x76994FDF741E0354ULL,
		0x305C6B32F85F431DULL,
		0xB25BBFF761A84EA2ULL,
		0xD2A1D39624D2DECAULL,
		0xEFB29CE808010D99ULL,
		0x78B8B38084C54810ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x907CF307B840FB8AULL,
		0xAED329FBEE83C06AULL,
		0x460B8D665F0BE863ULL,
		0x564B77FEEC3509D4ULL,
		0x3A543A72C49A5BD9ULL,
		0x1DF6539D010021B3ULL,
		0x0F1716701098A902ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x818078A4E45F7348ULL,
		0xCA1F35B7B47C9231ULL,
		0x69F532F6EA9C7F24ULL,
		0x944196BFEE3C0C33ULL,
		0xEBD160D7BB48ED8EULL,
		0xEAC697C7C3BE766CULL,
		0x939D25D72887AD73ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F35B7B47C923181ULL,
		0xF532F6EA9C7F24CAULL,
		0x4196BFEE3C0C3369ULL,
		0xD160D7BB48ED8E94ULL,
		0xC697C7C3BE766CEBULL,
		0x9D25D72887AD73EAULL,
		0x0000000000000093ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x40639CFDEF756075ULL,
		0x3AD1B37EC186FFBCULL,
		0x3EE1BE708F9B0477ULL,
		0x6258A2BDE4538968ULL,
		0x98BF598A31026C8FULL,
		0x7DB63A180A48BBA6ULL,
		0xD8E7EAD56F998EAFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46CDFB061BFEF10ULL,
		0xB86F9C23E6C11DCEULL,
		0x9628AF7914E25A0FULL,
		0x2FD6628C409B23D8ULL,
		0x6D8E8602922EE9A6ULL,
		0x39FAB55BE663ABDFULL,
		0x0000000000000036ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC830A5A6901F5C66ULL,
		0x85787DE1A951E8E3ULL,
		0x40C7AA90C80CA95AULL,
		0x42B7F8AC383FE477ULL,
		0xD21D8DDDB24570F5ULL,
		0xAAA669C0A423108BULL,
		0xBAD177171D96B7B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3C830A5A6901F5ULL,
		0x95A85787DE1A951EULL,
		0x47740C7AA90C80CAULL,
		0x0F542B7F8AC383FEULL,
		0x08BD21D8DDDB2457ULL,
		0x7B9AAA669C0A4231ULL,
		0x000BAD177171D96BULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB012E7864785E4ECULL,
		0xFC28610232DA2319ULL,
		0x47535F7DB08BFFD5ULL,
		0x6FA5E8DE48955E03ULL,
		0xB2798771BA06DC2DULL,
		0x60E847FABA199A5BULL,
		0x3C7B4C86107F1D8CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D118CD80973C323ULL,
		0x45FFEAFE14308119ULL,
		0x4AAF01A3A9AFBED8ULL,
		0x036E16B7D2F46F24ULL,
		0x0CCD2DD93CC3B8DDULL,
		0x3F8EC6307423FD5DULL,
		0x0000001E3DA64308ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2ABDF4694E71E378ULL,
		0x6FB6D7E21486B10BULL,
		0x7220ED210A11C8B8ULL,
		0x0ECD8D6DFD85AE8EULL,
		0xF8A7CCEA36116088ULL,
		0x03426587AC7067EEULL,
		0x31965D9A002D672AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2ABDF4694E71E37ULL,
		0x86FB6D7E21486B10ULL,
		0xE7220ED210A11C8BULL,
		0x80ECD8D6DFD85AE8ULL,
		0xEF8A7CCEA3611608ULL,
		0xA03426587AC7067EULL,
		0x031965D9A002D672ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x16BCB21AA7E2321FULL,
		0xF41870750E80221AULL,
		0xF77366AFB73082F4ULL,
		0x9F725C63DA6EDF96ULL,
		0x738D02EBA10F3BD0ULL,
		0xC3357624BDEA3ACBULL,
		0xE7FB91B0F56DB7F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8740110D0B5E590DULL,
		0xDB98417A7A0C383AULL,
		0xED376FCB7BB9B357ULL,
		0xD0879DE84FB92E31ULL,
		0x5EF51D65B9C68175ULL,
		0x7AB6DBFA619ABB12ULL,
		0x0000000073FDC8D8ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x88E7212E923E3016ULL,
		0x4B1C88C3BDE33DEAULL,
		0x86AA8FB848B4BCE4ULL,
		0x75F00734FDFB243CULL,
		0x4436BAD1478E71D8ULL,
		0x10D6D7A9C5870C83ULL,
		0x4F301E0BBD3072F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33DEA88E7212E923ULL,
		0x4BCE44B1C88C3BDEULL,
		0xB243C86AA8FB848BULL,
		0xE71D875F00734FDFULL,
		0x70C834436BAD1478ULL,
		0x072F510D6D7A9C58ULL,
		0x000004F301E0BBD3ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x644A8B41CF49DD08ULL,
		0x78109D9F83E015ABULL,
		0xC8FBDCFC21A298B9ULL,
		0x900DA8B7E753E84DULL,
		0x44B49364884E45DFULL,
		0xAB05F29DACBFD9A9ULL,
		0x0F2937B25300FF9EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9F83E015AB644A8ULL,
		0xCFC21A298B978109ULL,
		0x8B7E753E84DC8FBDULL,
		0x364884E45DF900DAULL,
		0x29DACBFD9A944B49ULL,
		0x7B25300FF9EAB05FULL,
		0x000000000000F293ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x48ACC6BC34832A67ULL,
		0xE1B84C6E60EC48FBULL,
		0x2D17BC1BA2550497ULL,
		0xD9A7773F0CD0AFB1ULL,
		0x333C27547784A45EULL,
		0x188E4E974780EA9BULL,
		0xB4332241D3EA546AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D891F691598D786ULL,
		0x4AA092FC37098DCCULL,
		0x9A15F625A2F78374ULL,
		0xF0948BDB34EEE7E1ULL,
		0xF01D53666784EA8EULL,
		0x7D4A8D4311C9D2E8ULL,
		0x000000168664483AULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x37DAF62D14F38167ULL,
		0xA172293C090BF402ULL,
		0x6FF2E9B11FB95CDFULL,
		0x810371B721A5B51AULL,
		0xB291D81721DB5C24ULL,
		0xEEBBEF124FACD979ULL,
		0x8E941340A0A92D35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2781217E8046FB5EULL,
		0x3623F72B9BF42E45ULL,
		0x36E434B6A34DFE5DULL,
		0x02E43B6B8490206EULL,
		0xE249F59B2F36523BULL,
		0x68141525A6BDD77DULL,
		0x000000000011D282ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xEA008256F8E222EDULL,
		0xDF82770DFFA52488ULL,
		0xD842751073B23A9AULL,
		0xDB0B2E0E5BB4E224ULL,
		0x6E7E4AC07939F1F3ULL,
		0xBD8E6669949E9549ULL,
		0xFC9473E3C6FFCD03ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EE1BFF4A4911D40ULL,
		0x4EA20E7647535BF0ULL,
		0x65C1CB769C449B08ULL,
		0xC9580F273E3E7B61ULL,
		0xCCCD3293D2A92DCFULL,
		0x8E7C78DFF9A077B1ULL,
		0x0000000000001F92ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x657C9349BF2C41BCULL,
		0x439501243B0585ECULL,
		0x75CF77151C592441ULL,
		0xB6C28BDB56795F7BULL,
		0x35AB1E42582DD4ACULL,
		0xAB1B9CC951AF59D7ULL,
		0xB8A4D9ADEDD507D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x501243B0585EC657ULL,
		0xF77151C592441439ULL,
		0x28BDB56795F7B75CULL,
		0xB1E42582DD4ACB6CULL,
		0xB9CC951AF59D735AULL,
		0x4D9ADEDD507D3AB1ULL,
		0x0000000000000B8AULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3CBCE880A9E2BBE5ULL,
		0x13E73A8BBF8EDAF1ULL,
		0x8048EFECF09ADA8BULL,
		0xFC0AD01F122A5319ULL,
		0x1D6858FFEF3D8D03ULL,
		0xD3A2E1F31F159400ULL,
		0x60FF28F914DBAB5FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAF13CBCE880A9EULL,
		0xADA8B13E73A8BBF8ULL,
		0xA53198048EFECF09ULL,
		0xD8D03FC0AD01F122ULL,
		0x594001D6858FFEF3ULL,
		0xBAB5FD3A2E1F31F1ULL,
		0x0000060FF28F914DULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xCB0A980EC2A1A9BEULL,
		0x402CC58401B23654ULL,
		0xDBD36D6B68B1818FULL,
		0xB285E3841BDFE23BULL,
		0x66CA3A10BA2FC056ULL,
		0xEE048A3E35A3E7FEULL,
		0xB3B93C17FD02F8BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9532C2A603B0A86AULL,
		0x63D00B3161006C8DULL,
		0x8EF6F4DB5ADA2C60ULL,
		0x15ACA178E106F7F8ULL,
		0xFF99B28E842E8BF0ULL,
		0x2FFB81228F8D68F9ULL,
		0x002CEE4F05FF40BEULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0E125539BE6725CBULL,
		0xE5AE4328B8DE80FDULL,
		0x98B7F58474E61B43ULL,
		0x22DDCE16D9B6A389ULL,
		0xEEBF0201F5D7BD51ULL,
		0xB12BC9510291D9E0ULL,
		0xF9EDD7AA3ACA8D64ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE80FD0E125539BE6ULL,
		0x61B43E5AE4328B8DULL,
		0x6A38998B7F58474EULL,
		0x7BD5122DDCE16D9BULL,
		0x1D9E0EEBF0201F5DULL,
		0xA8D64B12BC951029ULL,
		0x00000F9EDD7AA3ACULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x26E33CA9E9772D1DULL,
		0x3EE5F084D9185C00ULL,
		0xB48146D2ECAA044DULL,
		0x1A2E02C608B02782ULL,
		0x16D4BED6B5DB2B68ULL,
		0x4C2402861D103F4AULL,
		0x7AB2FD41BD7F091CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB230B8004DC67953ULL,
		0xD954089A7DCBE109ULL,
		0x11604F0569028DA5ULL,
		0x6BB656D0345C058CULL,
		0x3A207E942DA97DADULL,
		0x7AFE12389848050CULL,
		0x00000000F565FA83ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x855083BC7F63D5DEULL,
		0x3471791182587603ULL,
		0x873A7EFCE8BBFAAEULL,
		0xA4A54C9AEFE774CCULL,
		0x37CC907DBAC16BCDULL,
		0xF7982D9A11DF26E6ULL,
		0x2E761DA3E91B3A1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1791182587603855ULL,
		0xA7EFCE8BBFAAE347ULL,
		0x54C9AEFE774CC873ULL,
		0xC907DBAC16BCDA4AULL,
		0x82D9A11DF26E637CULL,
		0x61DA3E91B3A1AF79ULL,
		0x00000000000002E7ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xDB028B3C89B1B0E1ULL,
		0xEFA189D8B1956C06ULL,
		0x992069F8CC910D73ULL,
		0xB46298FD4A6F30CAULL,
		0xF23BEA429CF47B9DULL,
		0x1F4E83B379FB0D0EULL,
		0x34E5262950C3DA38ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1632AD80DB60516ULL,
		0xF199221AE7DF4313ULL,
		0xFA94DE61953240D3ULL,
		0x8539E8F73B68C531ULL,
		0x66F3F61A1DE477D4ULL,
		0x52A187B4703E9D07ULL,
		0x000000000069CA4CULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xFACADCAFE0D97FF0ULL,
		0xCD640F6163BE6D9DULL,
		0x849B0089C3DD2E3BULL,
		0xE5AFA59275C42084ULL,
		0xD4F4D7AE9686EB7EULL,
		0x10706E8087D2315CULL,
		0x14C6B73068E75D83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFACADCAFE0D97FF0ULL,
		0xCD640F6163BE6D9DULL,
		0x849B0089C3DD2E3BULL,
		0xE5AFA59275C42084ULL,
		0xD4F4D7AE9686EB7EULL,
		0x10706E8087D2315CULL,
		0x14C6B73068E75D83ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x7BFF457804B7F77FULL,
		0xA2B911C4841780FCULL,
		0x568064C9B6E35FE5ULL,
		0x487AB7D88498E08EULL,
		0x2A64A037D4E8DC32ULL,
		0x790A5AD159146FF1ULL,
		0x952C753B8C9084CBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC07E3DFFA2BC025ULL,
		0x1AFF2D15C88E2420ULL,
		0xC70472B403264DB7ULL,
		0x46E19243D5BEC424ULL,
		0xA37F89532501BEA7ULL,
		0x84265BC852D68AC8ULL,
		0x000004A963A9DC64ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x150A1C797305CA3CULL,
		0xA7C4C19D08E68C29ULL,
		0x5C54166839BECACDULL,
		0xE4D09FC9D5C87ECEULL,
		0x92D722F724642143ULL,
		0x24DFD208118D2E8CULL,
		0x72DC13D8FB50BFFFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A850E3CB982E51ULL,
		0x6D3E260CE8473461ULL,
		0x72E2A0B341CDF656ULL,
		0x1F2684FE4EAE43F6ULL,
		0x6496B917B923210AULL,
		0xF926FE90408C6974ULL,
		0x0396E09EC7DA85FFULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xEF540581450F8A50ULL,
		0x4211C954C4AC3C6DULL,
		0x652292FB0AD332B2ULL,
		0x7ECEFEF1E2CED129ULL,
		0x3258ED09C015C1A3ULL,
		0x841197CE8F833675ULL,
		0x7D45282953C763EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0847255312B0F1B7ULL,
		0x948A4BEC2B4CCAC9ULL,
		0xFB3BFBC78B3B44A5ULL,
		0xC963B4270057068DULL,
		0x10465F3A3E0CD9D4ULL,
		0xF514A0A54F1D8FBAULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3852565E1132831FULL,
		0x12535395C4B207CCULL,
		0x338FB8A58A2B2784ULL,
		0xEBD6E880C45D3610ULL,
		0x605C813146E65D5AULL,
		0x926B824909371A2BULL,
		0x43DD77868E23E742ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A72B89640F9870AULL,
		0xF714B14564F0824AULL,
		0xDD10188BA6C20671ULL,
		0x902628DCCBAB5D7AULL,
		0x70492126E3456C0BULL,
		0xAEF0D1C47CE8524DULL,
		0x000000000000087BULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xCF90E7A7EE72C435ULL,
		0x162E90648E542A38ULL,
		0x45141AC49F70E192ULL,
		0xDCAE33B4F48E32B9ULL,
		0x961EC5A06B33EAB7ULL,
		0x047B510749CF8079ULL,
		0x903A631101332A77ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x648E542A38CF90E7ULL,
		0xC49F70E192162E90ULL,
		0xB4F48E32B945141AULL,
		0xA06B33EAB7DCAE33ULL,
		0x0749CF8079961EC5ULL,
		0x1101332A77047B51ULL,
		0x0000000000903A63ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x13E6A416FB8BF961ULL,
		0xFEC70D7C498E1396ULL,
		0x953B432CEF5ECD36ULL,
		0x465F19CD6402DC36ULL,
		0x5D79C9EF5B156AB1ULL,
		0x075490E4B2A297FDULL,
		0x43B2BD0B5359EA2DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC70D7C498E139613ULL,
		0x3B432CEF5ECD36FEULL,
		0x5F19CD6402DC3695ULL,
		0x79C9EF5B156AB146ULL,
		0x5490E4B2A297FD5DULL,
		0xB2BD0B5359EA2D07ULL,
		0x0000000000000043ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD7C823A2B20C3164ULL,
		0x5D6F2DA98348A5B0ULL,
		0x099DB6A0E95F1BE8ULL,
		0x880FC6C72E6A3E3EULL,
		0x07061D88BF05B38DULL,
		0xC1F26AB44D92300BULL,
		0x463E1AF734CC88B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADE5B5306914B61AULL,
		0x33B6D41D2BE37D0BULL,
		0x01F8D8E5CD47C7C1ULL,
		0xE0C3B117E0B671B1ULL,
		0x3E4D5689B2460160ULL,
		0xC7C35EE699911678ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x014A30C7E5B54702ULL,
		0x46E77D82EB230255ULL,
		0x047DB5718AFE2599ULL,
		0x1837D2C9F87B939EULL,
		0xA5F928933060B9C1ULL,
		0x32AE17A731665D0BULL,
		0xBFB299A8B6942E3CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x255014A30C7E5B54ULL,
		0x59946E77D82EB230ULL,
		0x39E047DB5718AFE2ULL,
		0x9C11837D2C9F87B9ULL,
		0xD0BA5F928933060BULL,
		0xE3C32AE17A731665ULL,
		0x000BFB299A8B6942ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x98BBEAF624E65094ULL,
		0x63982B8145FA53B1ULL,
		0x53C45E59E01E8A33ULL,
		0x63DF8DD99F49DC62ULL,
		0x792A6CF98F3B78EBULL,
		0x759E8E2AC45596C5ULL,
		0xFCFD0830F0863134ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0517E94EC662EFABULL,
		0x67807A28CD8E60AEULL,
		0x667D2771894F1179ULL,
		0xE63CEDE3AD8F7E37ULL,
		0xAB11565B15E4A9B3ULL,
		0xC3C218C4D1D67A38ULL,
		0x0000000003F3F420ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xCEFB93A7DC675B0AULL,
		0xC3E7229A2AD02E08ULL,
		0xDE0922D5BC82B92AULL,
		0x5F51B1C5C51A3E9CULL,
		0x2FD5FC8B2D18B16FULL,
		0x5916FE1076AC4367ULL,
		0xC889E1E44A704A50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7229A2AD02E08CEULL,
		0x0922D5BC82B92AC3ULL,
		0x51B1C5C51A3E9CDEULL,
		0xD5FC8B2D18B16F5FULL,
		0x16FE1076AC43672FULL,
		0x89E1E44A704A5059ULL,
		0x00000000000000C8ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x89A544CA5D6E93C0ULL,
		0x78E1A4D7D54B04ABULL,
		0xA71B8A5DEA497B92ULL,
		0xA967A077D636730DULL,
		0x632948E672E27768ULL,
		0x64EBFBFBC1F68816ULL,
		0xB0319369A63CD7FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D26BEAA58255C4DULL,
		0xDC52EF524BDC93C7ULL,
		0x3D03BEB1B3986D38ULL,
		0x4A47339713BB454BULL,
		0x5FDFDE0FB440B319ULL,
		0x8C9B4D31E6BFE327ULL,
		0x0000000000000581ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xAED8E59CD7D043D9ULL,
		0x91A6383AA5B84BABULL,
		0x2028086A9F5A2B2BULL,
		0x27749C88CCE878C9ULL,
		0x75EE69A02970268CULL,
		0x9571B4B5B0857FA7ULL,
		0x8775D98FB8ED2811ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA96E12EAEBB6396ULL,
		0xAA7D68ACAE4698E0ULL,
		0x2333A1E32480A021ULL,
		0x80A5C09A309DD272ULL,
		0xD6C215FE9DD7B9A6ULL,
		0x3EE3B4A04655C6D2ULL,
		0x00000000021DD766ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1E5F35DE1BB5A667ULL,
		0x05F1D8F4C536E0F5ULL,
		0xE150758732221D37ULL,
		0x7E30FE34B59DE431ULL,
		0x000757737E0ABDB3ULL,
		0x609B83DBACB74DD2ULL,
		0xBAE3F66239196353ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB707A8F2F9AEF0DDULL,
		0x10E9B82F8EC7A629ULL,
		0xEF218F0A83AC3991ULL,
		0x55ED9BF187F1A5ACULL,
		0xBA6E90003ABB9BF0ULL,
		0xCB1A9B04DC1EDD65ULL,
		0x000005D71FB311C8ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA153F3C1DBA6DE55ULL,
		0x4148446F04CC7E45ULL,
		0x3A4471BD0C43FF8BULL,
		0x3C1A4EA37B1DA567ULL,
		0x23ECBA27143470B7ULL,
		0x3657E3BCFD02D908ULL,
		0xA2C215F9B495E939ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA153F3C1DBA6DE55ULL,
		0x4148446F04CC7E45ULL,
		0x3A4471BD0C43FF8BULL,
		0x3C1A4EA37B1DA567ULL,
		0x23ECBA27143470B7ULL,
		0x3657E3BCFD02D908ULL,
		0xA2C215F9B495E939ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA339326DFA817A60ULL,
		0xA1822F5E631371A3ULL,
		0x26D93EAA34893DEFULL,
		0x0B854024A1E8CEF4ULL,
		0xFF3FB3F4305809BDULL,
		0xE940086BC23D96C3ULL,
		0x8F7BCE9DCF220C35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x189B8D1D19C9936FULL,
		0xA449EF7D0C117AF3ULL,
		0x0F4677A136C9F551ULL,
		0x82C04DE85C2A0125ULL,
		0x11ECB61FF9FD9FA1ULL,
		0x791061AF4A00435EULL,
		0x000000047BDE74EEULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2D82F5129A0116EEULL,
		0xE86A667F32DC1F27ULL,
		0x89330D51E1B143D9ULL,
		0xFDA7FD36584F044BULL,
		0x0704EF2DC7F6057DULL,
		0xB288A0AE16E29234ULL,
		0x192823407D145E50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96E0F9396C17A894ULL,
		0x0D8A1ECF435333F9ULL,
		0xC278225C49986A8FULL,
		0x3FB02BEFED3FE9B2ULL,
		0xB71491A03827796EULL,
		0xE8A2F28594450570ULL,
		0x00000000C9411A03ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB9A92DBE2E93ABD8ULL,
		0x29869C0528FD347BULL,
		0x08B3E1F6A8C5F20AULL,
		0xB877051011020818ULL,
		0xB8504EE47D681D32ULL,
		0x98568D93CF664A07ULL,
		0xCE5B908BFB4151CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61A7014A3F4D1EEEULL,
		0x2CF87DAA317C828AULL,
		0x1DC1440440820602ULL,
		0x1413B91F5A074CAEULL,
		0x15A364F3D99281EEULL,
		0x96E422FED0547326ULL,
		0x0000000000000033ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x261E9C468EB952ACULL,
		0xE3198CEDA29BC8D3ULL,
		0xA7540102A597EB38ULL,
		0x4E46E93BE3A506A3ULL,
		0xF9071659C2B113FEULL,
		0x7FB6664E8929B801ULL,
		0x872FF3BCFD9DABAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3198CEDA29BC8D32ULL,
		0x7540102A597EB38EULL,
		0xE46E93BE3A506A3AULL,
		0x9071659C2B113FE4ULL,
		0xFB6664E8929B801FULL,
		0x72FF3BCFD9DABAA7ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE399F23D8D6850B6ULL,
		0x16035BD5827531CEULL,
		0x3369E8259EBEB72CULL,
		0x3F12D484B240FDF1ULL,
		0x02761574B8064D57ULL,
		0xA1DCBB4B91B15C1AULL,
		0x513DA12737229F28ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CEE399F23D8D68ULL,
		0xB72C16035BD58275ULL,
		0xFDF13369E8259EBEULL,
		0x4D573F12D484B240ULL,
		0x5C1A02761574B806ULL,
		0x9F28A1DCBB4B91B1ULL,
		0x0000513DA1273722ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0D7DEE88CEE48478ULL,
		0x69983FFCB7BEA99AULL,
		0x0B39E2148F5ADFBCULL,
		0x8FE84BE51873F9ECULL,
		0xF2A6EB3BA83D12C3ULL,
		0xD67A83DBCDA6E020ULL,
		0x4601DDB353A47E58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FFF2DEFAA66835FULL,
		0x788523D6B7EF1A66ULL,
		0x12F9461CFE7B02CEULL,
		0xBACEEA0F44B0E3FAULL,
		0xA0F6F369B8083CA9ULL,
		0x776CD4E91F96359EULL,
		0x0000000000001180ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE695251E035BAEB0ULL,
		0x69C1A0285751F45FULL,
		0x1C2B0C387773459DULL,
		0xDBECC391E61DAAF2ULL,
		0x30052C43FB697D64ULL,
		0xD5F994E45FD681C6ULL,
		0x093B4E9F750360EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF34A928F01ADD758ULL,
		0xB4E0D0142BA8FA2FULL,
		0x0E15861C3BB9A2CEULL,
		0x6DF661C8F30ED579ULL,
		0x18029621FDB4BEB2ULL,
		0xEAFCCA722FEB40E3ULL,
		0x049DA74FBA81B075ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0F40F795E8F4FDDDULL,
		0xEAF0D51B9DB2499EULL,
		0x874236C7DEE0E8C2ULL,
		0xB815328F359FDDC9ULL,
		0x4DFE67272760B42FULL,
		0xF98A1C5469188E38ULL,
		0x177FA460496D5293ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DCED924CF07A07BULL,
		0x63EF70746175786AULL,
		0x479ACFEEE4C3A11BULL,
		0x9393B05A17DC0A99ULL,
		0x2A348C471C26FF33ULL,
		0x3024B6A949FCC50EULL,
		0x00000000000BBFD2ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD539C8E5B0D5984EULL,
		0xB36C161FFE6BE247ULL,
		0x35531DAC7F9864FBULL,
		0xBB25B171AB26A111ULL,
		0x5E2656E7EA7FFD5AULL,
		0x09D52DA25E02FB97ULL,
		0xE0DA27C6D7319B54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FFE6BE247D539C8ULL,
		0xAC7F9864FBB36C16ULL,
		0x71AB26A11135531DULL,
		0xE7EA7FFD5ABB25B1ULL,
		0xA25E02FB975E2656ULL,
		0xC6D7319B5409D52DULL,
		0x0000000000E0DA27ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x46C9C71E50EFC725ULL,
		0x2B3F9D3EBB2778E1ULL,
		0xBB7DD0D125AC6039ULL,
		0xB37F8A873E49D163ULL,
		0x52877B2C0D913A7AULL,
		0x304C2F1D73325204ULL,
		0xE5DC0127506F2205ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2778E146C9C71EULL,
		0x25AC60392B3F9D3EULL,
		0x3E49D163BB7DD0D1ULL,
		0x0D913A7AB37F8A87ULL,
		0x7332520452877B2CULL,
		0x506F2205304C2F1DULL,
		0x00000000E5DC0127ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA1E1B578F7C71DADULL,
		0xBEA98DB7CD0862A3ULL,
		0xD4A43AB74D52291EULL,
		0xA67AD91521798263ULL,
		0xACE238ADA9FC5E73ULL,
		0x399E75B0C123D414ULL,
		0xB061D6FF7967A4E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F9A10C54743C36ULL,
		0x56E9AA4523D7D531ULL,
		0x22A42F304C7A9487ULL,
		0x15B53F8BCE74CF5BULL,
		0xB618247A82959C47ULL,
		0xDFEF2CF49C6733CEULL,
		0x0000000000160C3AULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9B602DB8987ABCBAULL,
		0xD35DCCD9D7FD043CULL,
		0xE5E63A6B2C0A178BULL,
		0xA757FA49051237A2ULL,
		0x6148409C60E6A792ULL,
		0x8843C0F7D2732266ULL,
		0xA051CA11A636E6A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733675FF410F26D8ULL,
		0x8E9ACB0285E2F4D7ULL,
		0xFE9241448DE8B979ULL,
		0x10271839A9E4A9D5ULL,
		0xF03DF49CC8999852ULL,
		0x7284698DB9A86210ULL,
		0x0000000000002814ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4126B2561B8ECDC0ULL,
		0x301717BBC83B62A4ULL,
		0x64200D17E5A2C7B6ULL,
		0xA99935D51F894594ULL,
		0x2B986E7992FE8D27ULL,
		0x75CD2D2FE50A41B1ULL,
		0x2B88B13C342BDCB8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1049AC9586E3B370ULL,
		0x8C05C5EEF20ED8A9ULL,
		0x19080345F968B1EDULL,
		0xEA664D7547E25165ULL,
		0x4AE61B9E64BFA349ULL,
		0x1D734B4BF942906CULL,
		0x0AE22C4F0D0AF72EULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xAF6FD3EFFA859A20ULL,
		0x9A50CCD9F7688B4FULL,
		0xBBCA44242887A57CULL,
		0x03857068DE087197ULL,
		0xA492A8568C3D6196ULL,
		0x7059A2BB0BE813BFULL,
		0x9D144057F047219CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33367DDA22D3EBDBULL,
		0x91090A21E95F2694ULL,
		0x5C1A37821C65EEF2ULL,
		0xAA15A30F586580E1ULL,
		0x68AEC2FA04EFE924ULL,
		0x1015FC11C8671C16ULL,
		0x0000000000002745ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x33E2E1BC43C32033ULL,
		0x07FDA9A04ECBB574ULL,
		0xDCA09139DF820D24ULL,
		0xE1850875AB0A06B6ULL,
		0x4B873D9D17825AA6ULL,
		0x42E5C4FD092CDEC5ULL,
		0xB05CF72EC236BB09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3409D976AE867C5CULL,
		0x273BF041A480FFB5ULL,
		0x0EB56140D6DB9412ULL,
		0xB3A2F04B54DC30A1ULL,
		0x9FA1259BD8A970E7ULL,
		0xE5D846D761285CB8ULL,
		0x0000000000160B9EULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1AD5EA8B91459FE8ULL,
		0x8A1CD467DAF7472DULL,
		0x67B96572884C7DE5ULL,
		0x1FE73D443807069EULL,
		0xB517DB09F85F8952ULL,
		0xA817703B33E9E23FULL,
		0xAD8AEAD90B0B62E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B57AA2E45167FAULL,
		0x62873519F6BDD1CBULL,
		0x99EE595CA2131F79ULL,
		0x87F9CF510E01C1A7ULL,
		0xED45F6C27E17E254ULL,
		0x2A05DC0ECCFA788FULL,
		0x2B62BAB642C2D8B9ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF15B6F541518C883ULL,
		0xBCFFBD6C92B633A1ULL,
		0x8141446C7B2575C7ULL,
		0x48AA45854C7F0BE1ULL,
		0x08B5E320FA465D05ULL,
		0x672CA15A35A7E008ULL,
		0xC85E8D19D7B574C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C92B633A1F15B6FULL,
		0x6C7B2575C7BCFFBDULL,
		0x854C7F0BE1814144ULL,
		0x20FA465D0548AA45ULL,
		0x5A35A7E00808B5E3ULL,
		0x19D7B574C4672CA1ULL,
		0x0000000000C85E8DULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x90F8CE0F529C3016ULL,
		0x0A34A787E8C3E460ULL,
		0x1D3228339344E49DULL,
		0xAFC7B4CB4093156DULL,
		0xDDA02F95044AA1ECULL,
		0x5D2DDBF77F7D0522ULL,
		0x7849588ADD99A59FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC121F19C1EA53860ULL,
		0x3A14694F0FD187C8ULL,
		0xDA3A6450672689C9ULL,
		0xD95F8F699681262AULL,
		0x45BB405F2A089543ULL,
		0x3EBA5BB7EEFEFA0AULL,
		0x00F092B115BB334BULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x307457C25040D49BULL,
		0x5F7EAC9CB0C69E4CULL,
		0x7B8B70900329B027ULL,
		0x6EE44E8276DF0F37ULL,
		0x0D9ECAF3462F9097ULL,
		0x3E8DA12924046D43ULL,
		0x0794AA92A85C4D51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x939618D3C9860E8AULL,
		0x1200653604EBEFD5ULL,
		0xD04EDBE1E6EF716EULL,
		0x5E68C5F212EDDC89ULL,
		0x2524808DA861B3D9ULL,
		0x52550B89AA27D1B4ULL,
		0x000000000000F295ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8CA9647384DC2610ULL,
		0x07A10BAAD85BC3B8ULL,
		0x5B7E298333976289ULL,
		0xB39CCE6F10EA816FULL,
		0x40A0F03BB7D59C60ULL,
		0xCF1DE4AA26CD3B35ULL,
		0xC56D26A4F0BC8CADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0B787711952C8EULL,
		0x6672EC5120F42175ULL,
		0xE21D502DEB6FC530ULL,
		0x76FAB38C167399CDULL,
		0x44D9A766A8141E07ULL,
		0x9E179195B9E3BC95ULL,
		0x0000000018ADA4D4ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x96338F9454B1F5D9ULL,
		0x1EE37816836C4655ULL,
		0xE0AD1EDBD15DC65BULL,
		0x5E8D217FCCBED16EULL,
		0x6D75871B56AC6589ULL,
		0xFA3E385CD651DF79ULL,
		0x332758373E3D560EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x816836C465596338ULL,
		0xEDBD15DC65B1EE37ULL,
		0x17FCCBED16EE0AD1ULL,
		0x71B56AC65895E8D2ULL,
		0x85CD651DF796D758ULL,
		0x8373E3D560EFA3E3ULL,
		0x0000000000033275ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x96D52A60F1EF293BULL,
		0xC89EC37C5E052304ULL,
		0x5C63D4149E4AA94DULL,
		0x6C1E7B1C76815E43ULL,
		0x9FA009784515002AULL,
		0xE0198EDB8D8073E0ULL,
		0xA2D63B5CC333E53FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF178148C125B54ULL,
		0x5052792AA537227BULL,
		0xEC71DA05790D718FULL,
		0x25E1145400A9B079ULL,
		0x3B6E3601CF827E80ULL,
		0xED730CCF94FF8066ULL,
		0x0000000000028B58ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x773195CABC05FD0FULL,
		0x5F90D8318704C979ULL,
		0x9F2AE33B6A158648ULL,
		0x0D341C3BBB9B4D26ULL,
		0x70E365B485D2BEEAULL,
		0xAE1C2F7986A85131ULL,
		0x52F2E382E63DEB43ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64BCBB98CAE55E02ULL,
		0xC3242FC86C18C382ULL,
		0xA6934F95719DB50AULL,
		0x5F75069A0E1DDDCDULL,
		0x2898B871B2DA42E9ULL,
		0xF5A1D70E17BCC354ULL,
		0x0000297971C1731EULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6F93EE97E0F0DDC2ULL,
		0x7BC15D72622EDEABULL,
		0x9AEB3EDC044E84EDULL,
		0xE46BE4EAB2758DC9ULL,
		0x0E8B70E2835CB39EULL,
		0xFF391B9B6A868954ULL,
		0x3063F9ED4799FA46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0575C988BB7AADBULL,
		0xBACFB70113A13B5EULL,
		0x1AF93AAC9D637266ULL,
		0xA2DC38A0D72CE7B9ULL,
		0xCE46E6DAA1A25503ULL,
		0x18FE7B51E67E91BFULL,
		0x000000000000000CULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3B8BDA762BD73D8AULL,
		0xCD3A494A9B5789F0ULL,
		0x9057BC18E97CBA36ULL,
		0x606C43CB4357F8FCULL,
		0x1FC6E566A57AC55AULL,
		0x974EEF51BBBE31CCULL,
		0xA85856B4DDEE909DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A74929536AF13E0ULL,
		0x20AF7831D2F9746DULL,
		0xC0D8879686AFF1F9ULL,
		0x3F8DCACD4AF58AB4ULL,
		0x2E9DDEA3777C6398ULL,
		0x50B0AD69BBDD213BULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB0F2739F55D642ABULL,
		0x022E4808DFFFF3C2ULL,
		0x3FADFCCBD610E3D0ULL,
		0xB39596BF68EAF52BULL,
		0xBE121C41EADEF857ULL,
		0x0FA0C88F459FDC14ULL,
		0xA270D3344AAFD32FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0F2739F55D642ABULL,
		0x022E4808DFFFF3C2ULL,
		0x3FADFCCBD610E3D0ULL,
		0xB39596BF68EAF52BULL,
		0xBE121C41EADEF857ULL,
		0x0FA0C88F459FDC14ULL,
		0xA270D3344AAFD32FULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB4FF98BF1DA32659ULL,
		0x4804ED1A513EFF8EULL,
		0x7BA4B87D6A8AEA1FULL,
		0xF377810B9E445C72ULL,
		0xBC09F2EC74F16415ULL,
		0xB4A219273FAE6DA6ULL,
		0xA07E5041E662C670ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D289F7FC75A7FCULL,
		0xC3EB545750FA4027ULL,
		0x085CF222E393DD25ULL,
		0x9763A78B20AF9BBCULL,
		0xC939FD736D35E04FULL,
		0x820F33163385A510ULL,
		0x00000000000503F2ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA297C66D17118D88ULL,
		0x802F2FB48EB18D20ULL,
		0x3719121A6D126599ULL,
		0xDE051AB63DF5EF1AULL,
		0xBF3F251077CCEFCDULL,
		0x3E0B881F3A45A248ULL,
		0x783C4B50429264BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F691D631A41452FULL,
		0x2434DA24CB33005EULL,
		0x356C7BEBDE346E32ULL,
		0x4A20EF99DF9BBC0AULL,
		0x103E748B44917E7EULL,
		0x96A08524C97C7C17ULL,
		0x000000000000F078ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8DCA091DEA035B77ULL,
		0x758BDBC6FBEBA28EULL,
		0xB6BE396EF678B1B6ULL,
		0x990D8ACA4B4AD465ULL,
		0x9DE244EE5AE69A94ULL,
		0xBFCACA25FAFE02B9ULL,
		0x8B86CEB4F012C41CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D7451D1B94123BDULL,
		0xCF1636CEB17B78DFULL,
		0x695A8CB6D7C72DDEULL,
		0x5CD3529321B15949ULL,
		0x5FC05733BC489DCBULL,
		0x02588397F95944BFULL,
		0x0000001170D9D69EULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x24BDAFDEE1550567ULL,
		0x7D71ED559D665D8FULL,
		0xC74CE82869AECC19ULL,
		0xAF3B6C5AEAC5680CULL,
		0x24B55816DEE3F5ACULL,
		0xD1EB7E19AA392436ULL,
		0x2168C8E5A6570DBFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB32EC7925ED7EFULL,
		0x34D7660CBEB8F6AAULL,
		0x7562B40663A67414ULL,
		0x6F71FAD6579DB62DULL,
		0xD51C921B125AAC0BULL,
		0xD32B86DFE8F5BF0CULL,
		0x0000000010B46472ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x49A033B4369685F6ULL,
		0xF453F4F341EC90F7ULL,
		0x5ADE4D9B8531E8F5ULL,
		0xB08791257F30849FULL,
		0x99E3C8A84DB69E30ULL,
		0xFC1D95E717A320A1ULL,
		0x86C32A5FAAE987E6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F341EC90F749A0ULL,
		0x4D9B8531E8F5F453ULL,
		0x91257F30849F5ADEULL,
		0xC8A84DB69E30B087ULL,
		0x95E717A320A199E3ULL,
		0x2A5FAAE987E6FC1DULL,
		0x00000000000086C3ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x85F1B429798A0D00ULL,
		0x2227AD4A8C5BBD8CULL,
		0xE45BD76A3BB1DC3CULL,
		0xC4A91F5F2F9715E9ULL,
		0xE4DF31FF29B9C43EULL,
		0xE4E4C4D063DD0F6FULL,
		0xA9E98C699157004CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190BE36852F3141AULL,
		0x78444F5A9518B77BULL,
		0xD3C8B7AED47763B8ULL,
		0x7D89523EBE5F2E2BULL,
		0xDFC9BE63FE537388ULL,
		0x99C9C989A0C7BA1EULL,
		0x0153D318D322AE00ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x47659C3A6D47958FULL,
		0x664FE41E426E706FULL,
		0xB124012DD3EBDFFCULL,
		0xDC2E46EB1BD20189ULL,
		0x074FE31A173CDBFCULL,
		0xA1F189C861A3EA0BULL,
		0x3FAA251747F6C3A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8ECB3874DA8F2B1ULL,
		0x8CC9FC83C84DCE0DULL,
		0x36248025BA7D7BFFULL,
		0x9B85C8DD637A4031ULL,
		0x60E9FC6342E79B7FULL,
		0x543E31390C347D41ULL,
		0x07F544A2E8FED874ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE84137AC36E31BC5ULL,
		0xCD321E66B8117F48ULL,
		0x96DDFB8D3723037BULL,
		0x9D36D6D39C503D52ULL,
		0x4E6686DF6A700E25ULL,
		0x434224FBBF4FF8ACULL,
		0xBEDE7A2AAA9BF288ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74209BD61B718DE2ULL,
		0xE6990F335C08BFA4ULL,
		0x4B6EFDC69B9181BDULL,
		0xCE9B6B69CE281EA9ULL,
		0x2733436FB5380712ULL,
		0x21A1127DDFA7FC56ULL,
		0x5F6F3D15554DF944ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xDF00B5E059AC153FULL,
		0x7BB2D010EC7D9098ULL,
		0xBE244DDD48A70682ULL,
		0x1E008A5F3E92ED76ULL,
		0x68CB5F0A03A93113ULL,
		0xFB7E04C30DDCD280ULL,
		0xDCB2107E304CAD9BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2637C02D78166B05ULL,
		0xA09EECB4043B1F64ULL,
		0x5DAF8913775229C1ULL,
		0x44C7802297CFA4BBULL,
		0xA01A32D7C280EA4CULL,
		0x66FEDF8130C37734ULL,
		0x00372C841F8C132BULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1B6F23DD6788C845ULL,
		0xF0A3CA5ADCD85A5FULL,
		0x65D2DED197581E03ULL,
		0x6002AA55B1C8500EULL,
		0xF907F77158AAEB7BULL,
		0x9E06B6006B258AFFULL,
		0x070C6A2FF51FCD78ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6DBC8F759E2321ULL,
		0x0FC28F296B736169ULL,
		0x39974B7B465D6078ULL,
		0xED800AA956C72140ULL,
		0xFFE41FDDC562ABADULL,
		0xE2781AD801AC962BULL,
		0x001C31A8BFD47F35ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x90137E8FBE2F5141ULL,
		0xF327ADECF373FD9EULL,
		0x850900308ABACF48ULL,
		0x687A3CB5BD8254C8ULL,
		0x580F82D23984A468ULL,
		0xFCDEBEABA882296FULL,
		0xAD00457103103C22ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90137E8FBE2F5141ULL,
		0xF327ADECF373FD9EULL,
		0x850900308ABACF48ULL,
		0x687A3CB5BD8254C8ULL,
		0x580F82D23984A468ULL,
		0xFCDEBEABA882296FULL,
		0xAD00457103103C22ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6CBE46BE96E80EFBULL,
		0x1F4BD786D3FE4661ULL,
		0x900024C12BD908CDULL,
		0x1B6D7BD02C6FB4AAULL,
		0x165A925826A74A83ULL,
		0x7528D0B85101F619ULL,
		0x5CCB0DC78BB280EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE46616CBE46BE96EULL,
		0x908CD1F4BD786D3FULL,
		0xFB4AA900024C12BDULL,
		0x74A831B6D7BD02C6ULL,
		0x1F619165A925826AULL,
		0x280EE7528D0B8510ULL,
		0x000005CCB0DC78BBULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xAD05204B4E724251ULL,
		0xBD3A383C06A25892ULL,
		0xB795F0BB1CA4D932ULL,
		0xBF0D624767A72262ULL,
		0xE4DA20F7B992B930ULL,
		0xCD01FCBA3F97D960ULL,
		0x9AE340CE4D9B0922ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E8E0F01A89624AULL,
		0xDE57C2EC729364CAULL,
		0xFC35891D9E9C898AULL,
		0x936883DEE64AE4C2ULL,
		0x3407F2E8FE5F6583ULL,
		0x6B8D0339366C248BULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x50A26C54908321ECULL,
		0x11BBA05CC52AC677ULL,
		0xE0497F901B57988EULL,
		0x81B5CB4DCD092B92ULL,
		0xA20BBF4308EEC817ULL,
		0x541F3CFD4EA5CBE1ULL,
		0xC08432522974D095ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37740B98A558CEEAULL,
		0x092FF2036AF311C2ULL,
		0x36B969B9A125725CULL,
		0x4177E8611DD902F0ULL,
		0x83E79FA9D4B97C34ULL,
		0x10864A452E9A12AAULL,
		0x0000000000000018ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x5F3C905940ED6A7EULL,
		0xD4E9C212B0781B41ULL,
		0xC7BA95621E56F797ULL,
		0x829BBC4145B6BC80ULL,
		0xC1FD750DC9F33CF8ULL,
		0x8AC4021FF8E1F153ULL,
		0xC0815B695D454ADCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0DA0AF9E482CA07ULL,
		0xB7BCBEA74E109583ULL,
		0xB5E4063DD4AB10F2ULL,
		0x99E7C414DDE20A2DULL,
		0x0F8A9E0FEBA86E4FULL,
		0x2A56E4562010FFC7ULL,
		0x000006040ADB4AEAULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x413A1CF6856D0659ULL,
		0xB3332A6BEEE705FAULL,
		0xE46C5F8C1686355EULL,
		0xE6ACD83A9125A2DDULL,
		0x712339E834CF2486ULL,
		0x30EF03CD49DFB3C8ULL,
		0x4CF07750AC5D2CC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD209D0E7B42B683ULL,
		0xAF59999535F77382ULL,
		0x6EF2362FC60B431AULL,
		0x4373566C1D4892D1ULL,
		0xE438919CF41A6792ULL,
		0x61987781E6A4EFD9ULL,
		0x0026783BA8562E96ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2D1E804A8EFCF0F7ULL,
		0x6B48BC6402C3D0D3ULL,
		0xC868A24DB0CC90B5ULL,
		0x390CB10B17C36A9FULL,
		0x0AFE7125CAE652FCULL,
		0x801EA655815DFC1DULL,
		0x4ED0FB1CF1759491ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D32D1E804A8EFCFULL,
		0x0B56B48BC6402C3DULL,
		0xA9FC868A24DB0CC9ULL,
		0x2FC390CB10B17C36ULL,
		0xC1D0AFE7125CAE65ULL,
		0x491801EA655815DFULL,
		0x0004ED0FB1CF1759ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6E90AD7F8792C5ECULL,
		0x6052CCFB68E2695EULL,
		0xA7165620D41CB4FBULL,
		0x6DE2A17DEE9EA300ULL,
		0xAE030FC51CCB9E39ULL,
		0xD9272AD2D7F6E092ULL,
		0xB5A557B993432C4BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA389A579BA42B5FULL,
		0x35072D3ED814B33EULL,
		0x7BA7A8C029C59588ULL,
		0x4732E78E5B78A85FULL,
		0xB5FDB824AB80C3F1ULL,
		0x64D0CB12F649CAB4ULL,
		0x000000002D6955EEULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1FB4A34CD814D295ULL,
		0x2B1152CD5AFA5621ULL,
		0x2372819060C796D4ULL,
		0x65519EDE07681B65ULL,
		0x12DBC93B0D12E175ULL,
		0x44603099338246B5ULL,
		0x846D2DE391772357ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66AD7D2B108FDA51ULL,
		0xC83063CB6A1588A9ULL,
		0x6F03B40DB291B940ULL,
		0x9D868970BAB2A8CFULL,
		0x4C99C1235A896DE4ULL,
		0xF1C8BB91ABA23018ULL,
		0x0000000000423696ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x831AE4B2D0414038ULL,
		0xF307783BCEA7C129ULL,
		0xE430580F09045FDDULL,
		0x98A91D5E9F89ACACULL,
		0x6D1DAD4E7A2AB9A5ULL,
		0xF317F5B87FE7E602ULL,
		0x5CDDA51658E9659AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEA7C129831AE4B2ULL,
		0x09045FDDF307783BULL,
		0x9F89ACACE430580FULL,
		0x7A2AB9A598A91D5EULL,
		0x7FE7E6026D1DAD4EULL,
		0x58E9659AF317F5B8ULL,
		0x000000005CDDA516ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6AF42C66228ECD0AULL,
		0xD398A74426D32D11ULL,
		0x6691117277C62D76ULL,
		0xD526D287624C1653ULL,
		0x71658D2154AECC4AULL,
		0x7DAAAAB178F0EEACULL,
		0x3B3AC557B2077C9DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB445ABD0B1988A3ULL,
		0x8B5DB4E629D109B4ULL,
		0x0594D9A4445C9DF1ULL,
		0xB312B549B4A1D893ULL,
		0x3BAB1C596348552BULL,
		0xDF275F6AAAAC5E3CULL,
		0x00000ECEB155EC81ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF0261B11DD84FD2FULL,
		0xF4BE7B300684BBA6ULL,
		0x2D727ADFCBFCA2A7ULL,
		0x372D1DFE8B9B6FF0ULL,
		0x61780D64D41A274AULL,
		0x0F05A8CC4765F4E8ULL,
		0x79274A255541074CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x774DE04C3623BB09ULL,
		0x454FE97CF6600D09ULL,
		0xDFE05AE4F5BF97F9ULL,
		0x4E946E5A3BFD1736ULL,
		0xE9D0C2F01AC9A834ULL,
		0x0E981E0B51988ECBULL,
		0x0000F24E944AAA82ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x452155B6304381EEULL,
		0x485C7469FEB5D593ULL,
		0x13523CB98CC3E62AULL,
		0x0BED400250FCEFDEULL,
		0x0E5E0BD9A5D2B933ULL,
		0xB49F7C75794C152FULL,
		0xD8607664BB84D501ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD148556D8C10E07BULL,
		0x92171D1A7FAD7564ULL,
		0x84D48F2E6330F98AULL,
		0xC2FB5000943F3BF7ULL,
		0xC39782F66974AE4CULL,
		0x6D27DF1D5E53054BULL,
		0x36181D992EE13540ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8EF9CCC916DA46E5ULL,
		0x7FBD13014725FE59ULL,
		0xEBA405519CB9CFDAULL,
		0xC768777C7735BE12ULL,
		0x94E843E6581D8C37ULL,
		0x2BB0E6156540AA4EULL,
		0xADD553C392B14410ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8980A392FF2CC77ULL,
		0x202A8CE5CE7ED3FDULL,
		0x43BBE3B9ADF0975DULL,
		0x421F32C0EC61BE3BULL,
		0x8730AB2A055274A7ULL,
		0xAA9E1C958A20815DULL,
		0x000000000000056EULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD92FBD8D5E7A407BULL,
		0x4513FB00832C1E50ULL,
		0x8DE804B1AF572A4BULL,
		0x6B28112A3661A1E3ULL,
		0x02CD1F13DF0D8C6DULL,
		0x79521CEDA44FAB54ULL,
		0x63D628568A56EE86ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C97DEC6AF3D203ULL,
		0x5A289FD8041960F2ULL,
		0x1C6F40258D7AB952ULL,
		0x6B59408951B30D0FULL,
		0xA01668F89EF86C63ULL,
		0x33CA90E76D227D5AULL,
		0x031EB142B452B774ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2C1D1DB5E5A8E547ULL,
		0x76F4FB774732934DULL,
		0x4EF4DAAB606FAE08ULL,
		0x4450F4BFFB7C0889ULL,
		0x1D1158B0B57B2E70ULL,
		0xC04B115CB7B48D73ULL,
		0x679C880920FF8147ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3EDDD1CCA4D34B0ULL,
		0xD36AAD81BEB821DBULL,
		0x43D2FFEDF022253BULL,
		0x4562C2D5ECB9C111ULL,
		0x2C4572DED235CC74ULL,
		0x72202483FE051F01ULL,
		0x000000000000019EULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x99A809A0273199E5ULL,
		0x8F8DF2281323439DULL,
		0x2EE4C75AB657F675ULL,
		0x024374E42C06D711ULL,
		0x24BA9563112E24ADULL,
		0xD731229E28599C7CULL,
		0xC570018C9F34231FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8D0E7666A02680ULL,
		0xD95FD9D63E37C8A0ULL,
		0xB01B5C44BB931D6AULL,
		0x44B892B4090DD390ULL,
		0xA16671F092EA558CULL,
		0x7CD08C7F5CC48A78ULL,
		0x0000000315C00632ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9BDD311E1F8BEE1AULL,
		0x550F5C64A1FEC7FAULL,
		0xF11241AB1D15838EULL,
		0x0C46569277D2CDF9ULL,
		0xEDFE73C18E376B90ULL,
		0xFA6943DC531CC59EULL,
		0x7617282BEB2A8F81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43D719287FB1FEA6ULL,
		0x44906AC74560E395ULL,
		0x1195A49DF4B37E7CULL,
		0x7F9CF0638DDAE403ULL,
		0x9A50F714C73167BBULL,
		0x85CA0AFACAA3E07EULL,
		0x000000000000001DULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB11D7D25436B7CC8ULL,
		0xCEF97BE85378D7D9ULL,
		0xA54E19BDD989B57AULL,
		0xCEDBA8910A6BE6CBULL,
		0xEA259102DDB9F4B8ULL,
		0xFB939C06E6040D58ULL,
		0xE558A192855633BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BECD88EBE92A1BULL,
		0x4DABD677CBDF429BULL,
		0x5F365D2A70CDEECCULL,
		0xCFA5C676DD448853ULL,
		0x206AC7512C8816EDULL,
		0xB19DE7DC9CE03730ULL,
		0x0000072AC50C942AULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x73AD3321471070CAULL,
		0x69B6B1B072D73390ULL,
		0x9FC32EB7496050E1ULL,
		0x4262D190C2651F5FULL,
		0x227719B892628EDBULL,
		0x51D1A9C9372B2D8EULL,
		0x1DA9EDEC20E426DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E75A66428E20E19ULL,
		0x2D36D6360E5AE672ULL,
		0xF3F865D6E92C0A1CULL,
		0x684C5A32184CA3EBULL,
		0xC44EE337124C51DBULL,
		0xCA3A353926E565B1ULL,
		0x03B53DBD841C84DBULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE36520CF2434EF72ULL,
		0xEFC36CDF1ADE5886ULL,
		0x3323058293B07A80ULL,
		0x191D0D566925F231ULL,
		0xDC7B966DDCD67055ULL,
		0xFF8A4AE85A7A1BF4ULL,
		0x36CF20F1D520F547ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5886E36520CF243ULL,
		0x07A80EFC36CDF1ADULL,
		0x5F2313323058293BULL,
		0x67055191D0D56692ULL,
		0xA1BF4DC7B966DDCDULL,
		0x0F547FF8A4AE85A7ULL,
		0x0000036CF20F1D52ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC38E232EDE9E49DBULL,
		0x0F5758C8A378296FULL,
		0x58ABF170FAFF28A2ULL,
		0xAF59B1D4942130BEULL,
		0x2CC6D2D2FA0E17D1ULL,
		0x8DCEBCB25EC4488BULL,
		0xFA1AB21069E73108ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5D63228DE0A5BFULL,
		0x62AFC5C3EBFCA288ULL,
		0xBD66C7525084C2F9ULL,
		0xB31B4B4BE8385F46ULL,
		0x373AF2C97B11222CULL,
		0xE86AC841A79CC422ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x86037DD3809B5928ULL,
		0xC56BDC4D788CFD3DULL,
		0xAF3E8CD6DB556DAAULL,
		0xAD25DCCC24260B83ULL,
		0x96CDD545DA71B553ULL,
		0x298A6D789FD6E966ULL,
		0x9A17B5A61D9D5CD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B89AF119FA7B0CULL,
		0x7D19ADB6AADB558AULL,
		0x4BB998484C17075EULL,
		0x9BAA8BB4E36AA75AULL,
		0x14DAF13FADD2CD2DULL,
		0x2F6B4C3B3AB9AE53ULL,
		0x0000000000000134ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE4ED2611B2BC519CULL,
		0x773E680539C489F9ULL,
		0xF62EF4CB8C9D102EULL,
		0x9EAA0CFB96F59C5DULL,
		0x30DDA6B3073C53B0ULL,
		0x15FA754D5B3FF641ULL,
		0x76D219999410B922ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FCF2769308D95E2ULL,
		0x8173B9F34029CE24ULL,
		0xE2EFB177A65C64E8ULL,
		0x9D84F55067DCB7ACULL,
		0xB20986ED359839E2ULL,
		0xC910AFD3AA6AD9FFULL,
		0x0003B690CCCCA085ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6DE755D2723D0B62ULL,
		0xA9DC949814C7FB98ULL,
		0xF2A02F9DA518A37BULL,
		0xF91E47B8A0EEABCFULL,
		0xB72EC04CF894DE7FULL,
		0x6FACDA1DCC4784EEULL,
		0x1C76D9FAA0823239ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92930298FF730DBCULL,
		0x05F3B4A3146F753BULL,
		0xC8F7141DD579FE54ULL,
		0xD8099F129BCFFF23ULL,
		0x9B43B988F09DD6E5ULL,
		0xDB3F541046472DF5ULL,
		0x000000000000038EULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x08F34CAC1A2D438AULL,
		0x1E969C9003D4AC20ULL,
		0xCB36C1AE0E1343BDULL,
		0xE7CCB5AED7E3BF76ULL,
		0x0A30A6FE8F05728AULL,
		0x9988191E6EFB5A92ULL,
		0xF7247F980EC60E15ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4011E69958345A87ULL,
		0x7A3D2D392007A958ULL,
		0xED966D835C1C2687ULL,
		0x15CF996B5DAFC77EULL,
		0x2414614DFD1E0AE5ULL,
		0x2B3310323CDDF6B5ULL,
		0x01EE48FF301D8C1CULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBB1E027DB1C273EAULL,
		0x15E28CBAD9941AB2ULL,
		0xF5E9DFCEC123EF61ULL,
		0x5A7AFB9DB2F0E2F8ULL,
		0x36039DFB51405F01ULL,
		0x689D06481DF9AE49ULL,
		0x1A67E0F3B3D557A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAD9941AB2BB1E02ULL,
		0xCEC123EF6115E28CULL,
		0x9DB2F0E2F8F5E9DFULL,
		0xFB51405F015A7AFBULL,
		0x481DF9AE4936039DULL,
		0xF3B3D557A9689D06ULL,
		0x00000000001A67E0ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x484E7EC690C71766ULL,
		0x6E5D26E56DCC42DBULL,
		0xFDB68DFBE17C5ADBULL,
		0x848F96CBBB322961ULL,
		0x27437C0F15AB84A3ULL,
		0xF93EAF2BCB8E63EBULL,
		0xAFCB4C19FF1CA8E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADB9885B6909CFDULL,
		0xF7C2F8B5B6DCBA4DULL,
		0x97766452C3FB6D1BULL,
		0x1E2B570947091F2DULL,
		0x57971CC7D64E86F8ULL,
		0x33FE3951CBF27D5EULL,
		0x00000000015F9698ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC637BE677C85D45CULL,
		0x97A81D6D5E1721B4ULL,
		0x573AC2904DC0E120ULL,
		0xCF88289B9F06627CULL,
		0xA86F657E51ADB077ULL,
		0x1C5A86D30D4DDEE3ULL,
		0x1DE30F3C70F34B92ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D5E1721B4C637BULL,
		0x2904DC0E12097A81ULL,
		0x89B9F06627C573ACULL,
		0x57E51ADB077CF882ULL,
		0x6D30D4DDEE3A86F6ULL,
		0xF3C70F34B921C5A8ULL,
		0x000000000001DE30ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4CA1B3241D14E7FCULL,
		0x21B2CC26FD64DA9DULL,
		0xBADB917EC2529926ULL,
		0xC14443C7CCE2ED11ULL,
		0x1CC6E135BA07769CULL,
		0x5BD6C33AE4F43042ULL,
		0x39ABCFB1C38CDD05ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB26D4EA650D9920EULL,
		0x294C9310D966137EULL,
		0x717688DD6DC8BF61ULL,
		0x03BB4E60A221E3E6ULL,
		0x7A18210E63709ADDULL,
		0xC66E82ADEB619D72ULL,
		0x0000001CD5E7D8E1ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6CD6B52A0E9B5260ULL,
		0x335A6CB423E1C962ULL,
		0x4B570DE25AC8BC36ULL,
		0x38DDAE1F582F88D0ULL,
		0x9DE4A7191AF4F3DEULL,
		0x0D4B4BEC123B8DC9ULL,
		0xC95F878B55A82EA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A11F0E4B1366B5AULL,
		0xF12D645E1B19AD36ULL,
		0x0FAC17C46825AB86ULL,
		0x8C8D7A79EF1C6ED7ULL,
		0xF6091DC6E4CEF253ULL,
		0xC5AAD4175106A5A5ULL,
		0x000000000064AFC3ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x20EE98EF8BBAD8DBULL,
		0x2C148DBC9F730E6FULL,
		0x82E02612CEE464BFULL,
		0x378ECB7795EBEE03ULL,
		0xF648B223C6398788ULL,
		0xD522B181EB560B5AULL,
		0x1D4BC605E0374486ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5236F27DCC39BC83ULL,
		0x80984B3B9192FCB0ULL,
		0x3B2DDE57AFB80E0BULL,
		0x22C88F18E61E20DEULL,
		0x8AC607AD582D6BD9ULL,
		0x2F181780DD121B54ULL,
		0x0000000000000075ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x58D35A14401D8A48ULL,
		0x3FFB32EB418DFD2FULL,
		0x0741F23BA7F8C560ULL,
		0x6FAB3CB077E5C725ULL,
		0x5FDF140AECC8A893ULL,
		0x71C4B3A2E6720A04ULL,
		0x4ED384A8346423CBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFA5EB1A6B428803ULL,
		0x18AC07FF665D6831ULL,
		0xB8E4A0E83E4774FFULL,
		0x15126DF567960EFCULL,
		0x41408BFBE2815D99ULL,
		0x84796E3896745CCEULL,
		0x000009DA7095068CULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6412EB1A7C03C434ULL,
		0x879FB3123D246748ULL,
		0x589ED8F2DE738B41ULL,
		0x3B54645AF0911468ULL,
		0xC10C0885D8B5B87EULL,
		0xC6E6A1754977CF76ULL,
		0x6241497D6E856B9BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3123D246748641ULL,
		0xED8F2DE738B41879ULL,
		0x4645AF0911468589ULL,
		0xC0885D8B5B87E3B5ULL,
		0x6A1754977CF76C10ULL,
		0x1497D6E856B9BC6EULL,
		0x0000000000000624ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x57C1415FEA270988ULL,
		0x0B77EC83E6431BAAULL,
		0xF001397E57F7E7D5ULL,
		0xA4C5513CCE80CEF5ULL,
		0x7AFF190B7469757DULL,
		0xCAE9C396DE751A38ULL,
		0x775A1FC810F35286ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6431BAA57C1415FEULL,
		0x7F7E7D50B77EC83EULL,
		0xE80CEF5F001397E5ULL,
		0x469757DA4C5513CCULL,
		0xE751A387AFF190B7ULL,
		0x0F35286CAE9C396DULL,
		0x0000000775A1FC81ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3F37BCBED2CBD31BULL,
		0x902AE5F09E02C398ULL,
		0x677E82954588B6ACULL,
		0x8DD7A0D17B233B2BULL,
		0x3B892F394753B557ULL,
		0x06EB9532B5F7A3C7ULL,
		0x2929880787D8A4FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF84F0161CC1F9BDEULL,
		0x4AA2C45B56481572ULL,
		0x68BD919D95B3BF41ULL,
		0x9CA3A9DAABC6EBD0ULL,
		0x995AFBD1E39DC497ULL,
		0x03C3EC527D0375CAULL,
		0x00000000001494C4ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x7D319B219EC824ECULL,
		0x211AADB32A134D1DULL,
		0xB1839FA7CE485BD0ULL,
		0x7A55A52F91459CB3ULL,
		0x61AE3CBBB8EFE4B7ULL,
		0xE58F5FEA383443A8ULL,
		0x14A352EC23AFF4ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D7D319B219EC82ULL,
		0xBD0211AADB32A134ULL,
		0xCB3B1839FA7CE485ULL,
		0x4B77A55A52F91459ULL,
		0x3A861AE3CBBB8EFEULL,
		0x4ADE58F5FEA38344ULL,
		0x00014A352EC23AFFULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6682838419AF6539ULL,
		0x225CB4D65130F6D7ULL,
		0xC20FCF255F0AA895ULL,
		0x9EDE309FECEA003AULL,
		0x3C6DF8AE38E6BD95ULL,
		0xD3D96D645B48E447ULL,
		0x710A7EF93C923C7BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x130F6D7668283841ULL,
		0xF0AA895225CB4D65ULL,
		0xCEA003AC20FCF255ULL,
		0x8E6BD959EDE309FEULL,
		0xB48E4473C6DF8AE3ULL,
		0xC923C7BD3D96D645ULL,
		0x0000000710A7EF93ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE256AA308A2EF321ULL,
		0x63473DEF5D03E75CULL,
		0x02C48CE19251303BULL,
		0x3C44B9124742B8C2ULL,
		0xBDEB8679D33375F8ULL,
		0xFF15B6D97C8BB534ULL,
		0x8E6B065B8BB426C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF5D03E75CE256AAULL,
		0xE19251303B63473DULL,
		0x124742B8C202C48CULL,
		0x79D33375F83C44B9ULL,
		0xD97C8BB534BDEB86ULL,
		0x5B8BB426C3FF15B6ULL,
		0x00000000008E6B06ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x48CA72E109018F40ULL,
		0x5200CC26C28B61A0ULL,
		0x2E4E3198B5F30D15ULL,
		0x3A5E599B6342BB76ULL,
		0x0C743EA2F8702BF1ULL,
		0x904F7666C21BCF4CULL,
		0x10C2858C4C02E765ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3409194E5C212031ULL,
		0xA2AA401984D8516CULL,
		0x6EC5C9C63316BE61ULL,
		0x7E274BCB336C6857ULL,
		0xE9818E87D45F0E05ULL,
		0xECB209EECCD84379ULL,
		0x00021850B189805CULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF5D5CF8D52054FB8ULL,
		0x26BB017C0C83A4ACULL,
		0x7772EF9B701E99EBULL,
		0xE32D8784EB3E0655ULL,
		0xA0A81E16CB81B02EULL,
		0x77CBC3939715FD16ULL,
		0x18791CCE8FA8D490ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0320E92B3D7573ULL,
		0xE6DC07A67AC9AEC0ULL,
		0xE13ACF81955DDCBBULL,
		0x85B2E06C0BB8CB61ULL,
		0xE4E5C57F45A82A07ULL,
		0x33A3EA35241DF2F0ULL,
		0x0000000000061E47ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA1D11DAC4D540360ULL,
		0xC57826BB1FF8EB1AULL,
		0x2BE46159D5B5FAB3ULL,
		0x26F8066E3908F220ULL,
		0x106C06A80BFB7A64ULL,
		0x93F8DE4EDB62673CULL,
		0x2271E6AA51186868ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50E88ED626AA01BULL,
		0x9E2BC135D8FFC758ULL,
		0x015F230ACEADAFD5ULL,
		0x2137C03371C84791ULL,
		0xE0836035405FDBD3ULL,
		0x449FC6F276DB1339ULL,
		0x01138F355288C343ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD0783A33807AE8BCULL,
		0xF6598A5D3422773EULL,
		0xCA6C96E73F456C84ULL,
		0x99B4932EAA8A56DDULL,
		0x73925C7C3317F43CULL,
		0xC3FBD302B8FA8D9AULL,
		0x915735BFF39A9177ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D089DCFB41E0E8ULL,
		0x9CFD15B213D96629ULL,
		0xBAAA295B7729B25BULL,
		0xF0CC5FD0F266D24CULL,
		0x0AE3EA3669CE4971ULL,
		0xFFCE6A45DF0FEF4CULL,
		0x0000000002455CD6ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4B4FEFE40DCDA67BULL,
		0x662CAA5488339E6BULL,
		0xCAB7C8CB6781FEF8ULL,
		0x368CB3F29F388985ULL,
		0x577CC6D8F905DC02ULL,
		0x4D379D3BC851FCA0ULL,
		0xE342689E8D41B335ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62CAA5488339E6B4ULL,
		0xAB7C8CB6781FEF86ULL,
		0x68CB3F29F388985CULL,
		0x77CC6D8F905DC023ULL,
		0xD379D3BC851FCA05ULL,
		0x342689E8D41B3354ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2AEDC6E3F966600CULL,
		0x14AE5A77FFCA4C25ULL,
		0xE87F18065E22FFD1ULL,
		0xD4D1507AD600E9C5ULL,
		0xDB5FD8D4581E6182ULL,
		0x52DF9101C3E718CDULL,
		0x83D14050344CE4CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFFE526129576E37ULL,
		0x32F117FE88A572D3ULL,
		0xD6B0074E2F43F8C0ULL,
		0xA2C0F30C16A68A83ULL,
		0x0E1F38C66EDAFEC6ULL,
		0x81A267267296FC88ULL,
		0x00000000041E8A02ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x5FBA4E58A8D88E90ULL,
		0xFF0AAE80B2BA1ACBULL,
		0xC5707CD7771ED5F0ULL,
		0x801CB1B18C8903FAULL,
		0xE1C0406CE4E84DC4ULL,
		0xC1DE06F2870F216CULL,
		0x205FF5ADD21E76E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE80B2BA1ACB5FBA4ULL,
		0xCD7771ED5F0FF0AAULL,
		0x1B18C8903FAC5707ULL,
		0x06CE4E84DC4801CBULL,
		0x6F2870F216CE1C04ULL,
		0x5ADD21E76E3C1DE0ULL,
		0x00000000000205FFULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x456995AF904CE40FULL,
		0x8ABBB692C24512A6ULL,
		0xB96AAC88D0E44695ULL,
		0x401DF344FB941580ULL,
		0x4697EF9EF1DC067CULL,
		0xECBF573CBC194DD7ULL,
		0xDBBEB1F45DBD6DECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5776D25848A254C8ULL,
		0x2D55911A1C88D2B1ULL,
		0x03BE689F7282B017ULL,
		0xD2FDF3DE3B80CF88ULL,
		0x97EAE7978329BAE8ULL,
		0x77D63E8BB7ADBD9DULL,
		0x000000000000001BULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x59C8E549BC1AE6B7ULL,
		0x8F24522821F8B7A2ULL,
		0x090095C399761D29ULL,
		0x58B14509B4B26D1FULL,
		0xFB6A46B15FEC4263ULL,
		0x5C97BDB473100BF8ULL,
		0x6A4A3D582F01AA20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x148A087E2DE89672ULL,
		0x2570E65D874A63C9ULL,
		0x51426D2C9B47C240ULL,
		0x91AC57FB1098D62CULL,
		0xEF6D1CC402FE3EDAULL,
		0x8F560BC06A881725ULL,
		0x0000000000001A92ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x5340201FC78DC08AULL,
		0xE343E3D24287863EULL,
		0xB9713EDF9E4AD2A0ULL,
		0x82EF1886C3DE9884ULL,
		0x5FECE369AA06378DULL,
		0x1D2338C6626FA35FULL,
		0x884AD89226A10AD0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C7A4850F0C7CA6ULL,
		0xE27DBF3C95A541C6ULL,
		0xDE310D87BD310972ULL,
		0xD9C6D3540C6F1B05ULL,
		0x46718CC4DF46BEBFULL,
		0x95B1244D4215A03AULL,
		0x0000000000000110ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xFFE88D79151A57DFULL,
		0xFF7EE66299A86F85ULL,
		0x3CC4E860C4740CFBULL,
		0x0C44A7A0B6D1CD83ULL,
		0xC33EC249063EF2D6ULL,
		0x9D33E89BBA7696CDULL,
		0xA0EA47B58C1E29C7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6299A86F85FFE88DULL,
		0x60C4740CFBFF7EE6ULL,
		0xA0B6D1CD833CC4E8ULL,
		0x49063EF2D60C44A7ULL,
		0x9BBA7696CDC33EC2ULL,
		0xB58C1E29C79D33E8ULL,
		0x0000000000A0EA47ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE1FA654276B840B6ULL,
		0xD50E1D0747A60C04ULL,
		0x307B17CDA7AC9DE4ULL,
		0xE1AFA86135F78A60ULL,
		0x44AAE27577A7075CULL,
		0x2E4AD0E62428F5B8ULL,
		0xB579E2AB8EB7EF58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA60C04E1FA654276ULL,
		0xAC9DE4D50E1D0747ULL,
		0xF78A60307B17CDA7ULL,
		0xA7075CE1AFA86135ULL,
		0x28F5B844AAE27577ULL,
		0xB7EF582E4AD0E624ULL,
		0x000000B579E2AB8EULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB9142743698D9A59ULL,
		0x7A850B6CE4D08F67ULL,
		0x4AC760C5000A0C7BULL,
		0x55914029AF8DA2E1ULL,
		0xE12BFAD0854357A5ULL,
		0xDB948F54F0AB2298ULL,
		0x6759A5F444B0460CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA142DB393423D9EEULL,
		0xB1D8314002831EDEULL,
		0x64500A6BE368B852ULL,
		0x4AFEB42150D5E955ULL,
		0xE523D53C2AC8A638ULL,
		0xD6697D112C118336ULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD21B0F699EC06FF2ULL,
		0x314DBB2399350C03ULL,
		0xAEFFD243C6DF59DFULL,
		0xD70C6E20957FF29BULL,
		0x99A54B40F25273FDULL,
		0x5EA003B8E04B682FULL,
		0x96F0C7F343DAE15EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC536EC8E64D4300FULL,
		0xBBFF490F1B7D677CULL,
		0x5C31B88255FFCA6EULL,
		0x66952D03C949CFF7ULL,
		0x7A800EE3812DA0BEULL,
		0x5BC31FCD0F6B8579ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9CEC43E9AFA73689ULL,
		0x3EEAEEDB32B0B4DBULL,
		0x3E7CD52C956096F5ULL,
		0x5DD42E229C14ED9CULL,
		0x8F5582349501770AULL,
		0x88A195C1559A1595ULL,
		0xFEC0DCABECDAC4E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CCAC2D36E73B10FULL,
		0xB255825BD4FBABBBULL,
		0x8A7053B670F9F354ULL,
		0xD25405DC297750B8ULL,
		0x05566856563D5608ULL,
		0xAFB36B1396228657ULL,
		0x0000000003FB0372ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2C8B71CB647CB0D8ULL,
		0xA75E3AA2BBFEA3A5ULL,
		0x3B0970B72730BE4CULL,
		0x0262FF5EFB0D7917ULL,
		0x643EF6A931E2B81DULL,
		0xDDA39F3C6D2C6E3DULL,
		0x98AB4CD1996DB7D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A52C8B71CB647CBULL,
		0xE4CA75E3AA2BBFEAULL,
		0x9173B0970B72730BULL,
		0x81D0262FF5EFB0D7ULL,
		0xE3D643EF6A931E2BULL,
		0x7D9DDA39F3C6D2C6ULL,
		0x00098AB4CD1996DBULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB177F287823F64AFULL,
		0x2DB3B4DACC9F3006ULL,
		0x203E4750BA48F350ULL,
		0x5CE169C8C54F6B3AULL,
		0x58FA5195B17E832BULL,
		0x1B9E6E64BC013F5EULL,
		0x6838AE87E06EF139ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC5DFCA1E08FD92BULL,
		0x0B6CED36B327CC01ULL,
		0x880F91D42E923CD4ULL,
		0xD7385A723153DACEULL,
		0x963E94656C5FA0CAULL,
		0x46E79B992F004FD7ULL,
		0x1A0E2BA1F81BBC4EULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3927840687457B37ULL,
		0x3D94C35702335795ULL,
		0xF4BB01BD4B54A3A8ULL,
		0xB601485381857FB0ULL,
		0x40EC9F580B3E7525ULL,
		0x9F6C59B5EBAD9C4BULL,
		0xE0966375A32AA4BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB8119ABCA9C93C2ULL,
		0xDEA5AA51D41ECA61ULL,
		0x29C0C2BFD87A5D80ULL,
		0xAC059F3A92DB00A4ULL,
		0xDAF5D6CE25A0764FULL,
		0xBAD195525E4FB62CULL,
		0x0000000000704B31ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x7A212E1DC0B4C68CULL,
		0x5499040B6DC7D194ULL,
		0xB84783C3E4252AC4ULL,
		0xDDD1A8D5BF7C8F9EULL,
		0x891E4922B24B5216ULL,
		0x3341B0C527CCDDE1ULL,
		0x0502BCB3FAFCC294ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB71F4651E884B87ULL,
		0xF9094AB115264102ULL,
		0x6FDF23E7AE11E0F0ULL,
		0xAC92D485B7746A35ULL,
		0x49F3377862479248ULL,
		0xFEBF30A50CD06C31ULL,
		0x000000000140AF2CULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x19D83214A7DCBAB3ULL,
		0xB4F476AC353EE860ULL,
		0xEFEF4B9F425278A4ULL,
		0x82F57D1AA77E0138ULL,
		0x8E470E1B5F3AF933ULL,
		0x5641D95262DEEA42ULL,
		0x2DE0FDA20C33E5E6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00CEC190A53EE5D5ULL,
		0x25A7A3B561A9F743ULL,
		0xC77F7A5CFA1293C5ULL,
		0x9C17ABE8D53BF009ULL,
		0x14723870DAF9D7C9ULL,
		0x32B20ECA9316F752ULL,
		0x016F07ED10619F2FULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x299616492FB61B4CULL,
		0x3264D79AFECBD00FULL,
		0xF776FCFD5FD063FCULL,
		0x2AD89AB320F86D89ULL,
		0x0D9A9887DFA6455EULL,
		0x74C68D1FD9E6E363ULL,
		0xADE0873BAC2DDE49ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E80794CB0B2497ULL,
		0xE831FE19326BCD7FULL,
		0x7C36C4FBBB7E7EAFULL,
		0xD322AF156C4D5990ULL,
		0xF371B186CD4C43EFULL,
		0x16EF24BA63468FECULL,
		0x00000056F0439DD6ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3517278E18DD3BF8ULL,
		0x8269B4BB27DD0BEEULL,
		0x0DBFB8736C7BEBBAULL,
		0xC52EADEFE41833CBULL,
		0x59DA8F049D4B7E9FULL,
		0x971216D5EDAFB712ULL,
		0x3BAC41B81216443BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEE3517278E18DD3ULL,
		0xBBA8269B4BB27DD0ULL,
		0x3CB0DBFB8736C7BEULL,
		0xE9FC52EADEFE4183ULL,
		0x71259DA8F049D4B7ULL,
		0x43B971216D5EDAFBULL,
		0x0003BAC41B812164ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB9E8776CEEA4ECDBULL,
		0x82E37ED82CFAEAA5ULL,
		0x780FD949C46D3EC3ULL,
		0xA8F5148F19B7A938ULL,
		0x680DAF3A7C29E2B4ULL,
		0x8A98B1C2DD828D8AULL,
		0x70833121E502F6B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC167D7552DCF43BBULL,
		0x4E2369F61C171BF6ULL,
		0x78CDBD49C3C07ECAULL,
		0xD3E14F15A547A8A4ULL,
		0x16EC146C53406D79ULL,
		0x0F2817B5C454C58EULL,
		0x0000000003841989ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x86D917A70292967AULL,
		0x59F8C09AD27B3BF8ULL,
		0xE9B475A28EF3FD35ULL,
		0xFA6EF30515363109ULL,
		0x4A423C8BE54099D1ULL,
		0x6677058A639FDC21ULL,
		0xDC91B88B66B0CF5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135A4F677F10DB22ULL,
		0xB451DE7FA6AB3F18ULL,
		0x60A2A6C6213D368EULL,
		0x917CA8133A3F4DDEULL,
		0xB14C73FB84294847ULL,
		0x116CD619EB4CCEE0ULL,
		0x00000000001B9237ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBBF1424939D5D7A1ULL,
		0xC3234ABA752F8831ULL,
		0x7B68192C71C102F5ULL,
		0x9F3ECA420E7BEDC7ULL,
		0xEC95999439E277B7ULL,
		0xDA7740B55A9F8DFEULL,
		0x6B69BB3C9785EF13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC418DDF8A1249CEAULL,
		0x817AE191A55D3A97ULL,
		0xF6E3BDB40C9638E0ULL,
		0x3BDBCF9F6521073DULL,
		0xC6FF764ACCCA1CF1ULL,
		0xF789ED3BA05AAD4FULL,
		0x000035B4DD9E4BC2ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x7DD4D0D6E99E2F45ULL,
		0x9048F8EF24D94FC6ULL,
		0xB66F742D16E02825ULL,
		0x1F26447F02E6A704ULL,
		0x4C057DF25211407DULL,
		0x08B20911F231761DULL,
		0x78FA16A0804B7ED5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE49B29F8CFBA9A1ULL,
		0x5A2DC0504B2091F1ULL,
		0xFE05CD4E096CDEE8ULL,
		0xE4A42280FA3E4C88ULL,
		0x23E462EC3A980AFBULL,
		0x410096FDAA116412ULL,
		0x0000000000F1F42DULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2042BE83DE9FF84CULL,
		0x34F21AA5B1E11A55ULL,
		0x0C5BC37B01D6BD93ULL,
		0x51F06212BC1E6384ULL,
		0xE4CA8491EF703408ULL,
		0xBC08644ABAD3D489ULL,
		0xFCFC102F764835C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52D8F08D2A90215FULL,
		0xBD80EB5EC99A790DULL,
		0x095E0F31C2062DE1ULL,
		0x48F7B81A0428F831ULL,
		0x255D69EA44F26542ULL,
		0x17BB241AE2DE0432ULL,
		0x00000000007E7E08ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF168B54DFFB6313BULL,
		0xD96B37C855081595ULL,
		0x71F6847849928877ULL,
		0x584C1DC64FAC28D9ULL,
		0xF5064BA7B3BEAA28ULL,
		0x6F3A977ACAB09A59ULL,
		0x05CC4A4066DB9E0BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F168B54DFFB6313ULL,
		0x7D96B37C85508159ULL,
		0x971F684784992887ULL,
		0x8584C1DC64FAC28DULL,
		0x9F5064BA7B3BEAA2ULL,
		0xB6F3A977ACAB09A5ULL,
		0x005CC4A4066DB9E0ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x55A47D08364F46D1ULL,
		0x38934585961F307AULL,
		0xF39D1B582FCBED19ULL,
		0xABFDAE4B2E0B2D02ULL,
		0x87AFAB209B19ED08ULL,
		0xB34132A12B1EFDBAULL,
		0xCEA3B665C0666AB7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C2CB0F983D2AD23ULL,
		0xDAC17E5F68C9C49AULL,
		0x7259705968179CE8ULL,
		0x5904D8CF68455FEDULL,
		0x950958F7EDD43D7DULL,
		0xB32E033355BD9A09ULL,
		0x000000000006751DULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8F091399C515B767ULL,
		0xC9D98AE4237D61F4ULL,
		0xC7ECA1B698C9AFF4ULL,
		0x6DF212A8711A8EA1ULL,
		0x64B43455225FAAEBULL,
		0x6AC6CB9361C551C0ULL,
		0xC841D7B270423EB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BEB0FA478489CCEULL,
		0xC64D7FA64ECC5721ULL,
		0x88D4750E3F650DB4ULL,
		0x12FD575B6F909543ULL,
		0x0E2A8E0325A1A2A9ULL,
		0x8211F59356365C9BULL,
		0x00000006420EBD93ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9F4CBFB5291F9744ULL,
		0x412113D7DEC3E549ULL,
		0xD4B264C6456C27EBULL,
		0x84C553DDFF7ADCB5ULL,
		0xE83E8ACA213AE501ULL,
		0x365AB1A30F496A3DULL,
		0x4FE2CA8E9474735EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA933E997F6A523F2ULL,
		0xFD6824227AFBD87CULL,
		0x96BA964C98C8AD84ULL,
		0xA03098AA7BBFEF5BULL,
		0x47BD07D15944275CULL,
		0x6BC6CB563461E92DULL,
		0x0009FC5951D28E8EULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x64E9A86FBB189495ULL,
		0x2928CD8CB27D730EULL,
		0xBF6B326996E99C6EULL,
		0x61A3F7EDEB39940FULL,
		0x18DD3CCAD3FAE227ULL,
		0x0B94C0CBFFAE5C37ULL,
		0xDE6F15202CC967FBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49466C6593EB9873ULL,
		0xFB59934CB74CE371ULL,
		0x0D1FBF6F59CCA07DULL,
		0xC6E9E6569FD7113BULL,
		0x5CA6065FFD72E1B8ULL,
		0xF378A901664B3FD8ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x81A012B3A9A5A71CULL,
		0x0BE3832B03F71F88ULL,
		0xA16152B74FCD420AULL,
		0xA8B18B054D3871FFULL,
		0xDE82782076D199F2ULL,
		0x16015926EF919BC8ULL,
		0x1B290AA1F2220D39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65607EE3F1103402ULL,
		0x56E9F9A841417C70ULL,
		0x60A9A70E3FF42C2AULL,
		0x040EDA333E551631ULL,
		0x24DDF233791BD04FULL,
		0x543E4441A722C02BULL,
		0x0000000000036521ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x7B2ED6A256E0472CULL,
		0xD31B4E182296F9A9ULL,
		0xC5F606915CF41844ULL,
		0x9B7290D1849D5A8BULL,
		0xF58B52C7C50F54A7ULL,
		0x03D52EB77EF103E1ULL,
		0xA9774E796DAE0FD4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5BE6A5ECBB5A89ULL,
		0x73D061134C6D3860ULL,
		0x12756A2F17D81A45ULL,
		0x143D529E6DCA4346ULL,
		0xFBC40F87D62D4B1FULL,
		0xB6B83F500F54BADDULL,
		0x00000002A5DD39E5ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x017D49C1ED43ADD9ULL,
		0x260FCFF1C8934FC1ULL,
		0xFCCEF43AF06D0330ULL,
		0x4DAB30DED22E914DULL,
		0xD9380210A3ADE5F2ULL,
		0x877A187B180124ECULL,
		0x5BDE1421D670C216ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7E080BEA4E0F6A1ULL,
		0x81981307E7F8E449ULL,
		0x48A6FE677A1D7836ULL,
		0xF2F926D5986F6917ULL,
		0x92766C9C010851D6ULL,
		0x610B43BD0C3D8C00ULL,
		0x00002DEF0A10EB38ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF704899962B49FB5ULL,
		0xDFFDA7F48EEB8E32ULL,
		0x3126C4DDFA10A391ULL,
		0x68F969EFF6E72621ULL,
		0x0740BBC2C73FDB31ULL,
		0xD4ECCB2D25E0F275ULL,
		0xEA8BBA36EC0BC1FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71C65EE091332C5ULL,
		0x214723BFFB4FE91DULL,
		0xCE4C42624D89BBF4ULL,
		0x7FB662D1F2D3DFEDULL,
		0xC1E4EA0E8177858EULL,
		0x1783FDA9D9965A4BULL,
		0x000001D517746DD8ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD2A367EBD716712DULL,
		0x86EC1562C8DD169CULL,
		0x9E1E5640BAB6AA3EULL,
		0xA4F628809E2773C8ULL,
		0x08F0F30EDCD24B0DULL,
		0x4CDB9D88A7B30198ULL,
		0xAF0A631BB731C4B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC591BA2D39A546CFULL,
		0x81756D547D0DD82AULL,
		0x013C4EE7913C3CACULL,
		0x1DB9A4961B49EC51ULL,
		0x114F66033011E1E6ULL,
		0x376E63897299B73BULL,
		0x00000000015E14C6ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x460D2C999857FF0AULL,
		0xE273CFEC6BE591ABULL,
		0xEB77E4FD5069CAEDULL,
		0x3AED2B618AE29D3EULL,
		0xCC1C33CA7D6A13A1ULL,
		0xD840574E5AF9CD21ULL,
		0x594BB34D50B7BECBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D5A306964CCC2BFULL,
		0x576F139E7F635F2CULL,
		0xE9F75BBF27EA834EULL,
		0x9D09D7695B0C5714ULL,
		0x690E60E19E53EB50ULL,
		0xF65EC202BA72D7CEULL,
		0x0002CA5D9A6A85BDULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x285B5883463815FEULL,
		0x61C85859A9886BF5ULL,
		0x8AABC587AC7B9467ULL,
		0xDFEC464EB0FB5CA9ULL,
		0x345A4AF9F42C1157ULL,
		0xE220EA6213FA25EDULL,
		0xE8022A8344466A13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A16D620D18E057FULL,
		0xD87216166A621AFDULL,
		0x62AAF161EB1EE519ULL,
		0xF7FB1193AC3ED72AULL,
		0x4D1692BE7D0B0455ULL,
		0xF8883A9884FE897BULL,
		0x3A008AA0D1119A84ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x16D7B486C23856AFULL,
		0x7DFAF61FF66571E5ULL,
		0xDFEEAC9F60A308C8ULL,
		0xCB42F9C4A34A65B5ULL,
		0x471DBECC72C47726ULL,
		0x5120A61E19D3F200ULL,
		0x204623314384AC19ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD7B0FFB32B8F28ULL,
		0xFF7564FB05184643ULL,
		0x5A17CE251A532DAEULL,
		0x38EDF6639623B936ULL,
		0x890530F0CE9F9002ULL,
		0x0231198A1C2560CAULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1F336158F8D8DD87ULL,
		0xE43852EBBFDB98A7ULL,
		0xA58D1095F3C2A004ULL,
		0x3CC58E93F04B9E45ULL,
		0x942EC3C92C229B30ULL,
		0x8FF4944FFE986837ULL,
		0xE585E34D8396EA4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D77FB7314E3E66CULL,
		0x12BE7854009C870AULL,
		0xD27E0973C8B4B1A2ULL,
		0x79258453660798B1ULL,
		0x89FFD30D06F285D8ULL,
		0x69B072DD49B1FE92ULL,
		0x00000000001CB0BCULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x917D92AD10D570C9ULL,
		0x8C2387FFA2EF3073ULL,
		0xEFCB1D5D1BD0041AULL,
		0x030628A4B407DB33ULL,
		0xAD90CE5DFE1321ECULL,
		0x070CF0DE93D63809ULL,
		0x7E7D1BB28F251953ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E722FB255A21AAEULL,
		0x83518470FFF45DE6ULL,
		0x667DF963ABA37A00ULL,
		0x3D8060C5149680FBULL,
		0x0135B219CBBFC264ULL,
		0x2A60E19E1BD27AC7ULL,
		0x000FCFA37651E4A3ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE9772CC28111CDD6ULL,
		0x80BC19BC878AB270ULL,
		0xB4DB8449F872AFF0ULL,
		0x3C7617B5F7842191ULL,
		0xC0952D09A40C9C89ULL,
		0x3CF660245DA927BBULL,
		0x8BE6F862CFED9AEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC878AB270E9772ULL,
		0x449F872AFF080BC1ULL,
		0x7B5F7842191B4DB8ULL,
		0xD09A40C9C893C761ULL,
		0x0245DA927BBC0952ULL,
		0x862CFED9AEA3CF66ULL,
		0x000000000008BE6FULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6B9D70525A985D68ULL,
		0xF5D5CAEF13650E05ULL,
		0x25D615B1832EB995ULL,
		0x4814358EF18D66DCULL,
		0xDA2D794D374BD8F8ULL,
		0x65EF382CE3BD7D60ULL,
		0x25F1E9A42D31F571ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D943815AE75C149ULL,
		0x0CBAE657D7572BBCULL,
		0xC6359B70975856C6ULL,
		0xDD2F63E12050D63BULL,
		0x8EF5F58368B5E534ULL,
		0xB4C7D5C597BCE0B3ULL,
		0x0000000097C7A690ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2AE625D99139AA84ULL,
		0xF1E194ECA7C40F72ULL,
		0x01D5696139FC9C8EULL,
		0x2DC981029A24189EULL,
		0x9A19B84FE9FBC07BULL,
		0xB74AE65CE33A2989ULL,
		0x9581D5C92E6D4933ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03DC8AB98976644EULL,
		0x2723BC78653B29F1ULL,
		0x062780755A584E7FULL,
		0xF01ECB726040A689ULL,
		0x8A6266866E13FA7EULL,
		0x524CEDD2B99738CEULL,
		0x0000256075724B9BULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4E103A358A548161ULL,
		0x6A53049A066422D0ULL,
		0x32E1522C5944686EULL,
		0xEF86CB1523CFEE67ULL,
		0xEF91953AB704F8D3ULL,
		0x0BB0203076A13C4AULL,
		0xDD56937E12C62EB6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6422D04E103A358AULL,
		0x44686E6A53049A06ULL,
		0xCFEE6732E1522C59ULL,
		0x04F8D3EF86CB1523ULL,
		0xA13C4AEF91953AB7ULL,
		0xC62EB60BB0203076ULL,
		0x000000DD56937E12ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBE746DA3ED3E82F1ULL,
		0x90817C41713616A4ULL,
		0x3949EFEC59242052ULL,
		0x754FC339374F7D4FULL,
		0xC682A5B0E8495C25ULL,
		0xF440F1CE0EEB39D3ULL,
		0x2909D37FBBF02672ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1713616A4BE746DAULL,
		0xC5924205290817C4ULL,
		0x9374F7D4F3949EFEULL,
		0x0E8495C25754FC33ULL,
		0xE0EEB39D3C682A5BULL,
		0xFBBF02672F440F1CULL,
		0x0000000002909D37ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA31D88667871DE41ULL,
		0x9365EDA315220640ULL,
		0xC47E13AE5FF0E554ULL,
		0x7DD0C9C94CE19733ULL,
		0x07436574FB331B92ULL,
		0x2113339D0EFBC673ULL,
		0x2C9FBEBF307C566CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D18A910320518ECULL,
		0x9D72FF872AA49B2FULL,
		0x4E4A670CB99E23F0ULL,
		0x2BA7D998DC93EE86ULL,
		0x9CE877DE33983A1BULL,
		0xF5F983E2B3610899ULL,
		0x00000000000164FDULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8117C1175E4E0913ULL,
		0xEC982EC1DF1C5D51ULL,
		0x1BF08849A3A843A3ULL,
		0x7D7F76C9BAEB00F3ULL,
		0xE10D65F19187BB3DULL,
		0x2F6457C61A6F6BDEULL,
		0x92D65DEA4837E252ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x077C717546045F04ULL,
		0x268EA10E8FB260BBULL,
		0x26EBAC03CC6FC221ULL,
		0xC6461EECF5F5FDDBULL,
		0x1869BDAF7B843597ULL,
		0xA920DF8948BD915FULL,
		0x00000000024B5977ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x77C412D8E9DB1FF7ULL,
		0x380D4A5F3329BCD3ULL,
		0xA6D97BF9E8D789D3ULL,
		0xBE06927B3FE9573EULL,
		0xE55D4C1032E52A6FULL,
		0xB842230E232F2A92ULL,
		0xA6878D3AD09FB11FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329BCD377C412D8EULL,
		0x8D789D3380D4A5F3ULL,
		0xFE9573EA6D97BF9EULL,
		0x2E52A6FBE06927B3ULL,
		0x32F2A92E55D4C103ULL,
		0x09FB11FB842230E2ULL,
		0x0000000A6878D3ADULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6176681AFFA6301EULL,
		0x0963390E44673D87ULL,
		0x7AC8C80C0A7410C4ULL,
		0xBDE2FDCF3665DC4FULL,
		0x0FFD8D45BB2B06D1ULL,
		0xA0DA9410F8E47802ULL,
		0x95A746B8002591F6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B0EC2ECD035FF4ULL,
		0x8218812C6721C88CULL,
		0xBB89EF591901814EULL,
		0x60DA37BC5FB9E6CCULL,
		0x8F0041FFB1A8B765ULL,
		0xB23ED41B52821F1CULL,
		0x000012B4E8D70004ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0A463379B75E3EBEULL,
		0x66C30BDA66FF3040ULL,
		0x6CFECB50AD216522ULL,
		0x77F12B7BFD8EC11FULL,
		0x55C29FA7947D54A1ULL,
		0x3E34D618371E6236ULL,
		0xB40936C85285A13AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8617B4CDFE60801ULL,
		0x9FD96A15A42CA44CULL,
		0xFE256F7FB1D823EDULL,
		0xB853F4F28FAA942EULL,
		0xC69AC306E3CC46CAULL,
		0x8126D90A50B42747ULL,
		0x0000000000000016ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x00958421D47852FEULL,
		0xA53B49E8B23C3725ULL,
		0x4C99C0AA7AD47DB7ULL,
		0xACAA0B71D18A558BULL,
		0x12AFEF70A7315761ULL,
		0x111E4C4F4B956741ULL,
		0xC13EAA713B2DD5B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23C372500958421DULL,
		0xAD47DB7A53B49E8BULL,
		0x18A558B4C99C0AA7ULL,
		0x7315761ACAA0B71DULL,
		0xB95674112AFEF70AULL,
		0xB2DD5B1111E4C4F4ULL,
		0x0000000C13EAA713ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2A87CDD8EBEB4BCBULL,
		0x18CEF7E7DC5D41E2ULL,
		0x783CF4978F200D13ULL,
		0x81C9DAEDFBB128E5ULL,
		0xD6643B52D89773B2ULL,
		0xF09E2769FDA43567ULL,
		0x00F00BCF79F1562AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E7DC5D41E22A87CULL,
		0x4978F200D1318CEFULL,
		0xAEDFBB128E5783CFULL,
		0xB52D89773B281C9DULL,
		0x769FDA43567D6643ULL,
		0xBCF79F1562AF09E2ULL,
		0x0000000000000F00ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8E0842D3D0670380ULL,
		0xCF374014BD6BE7C2ULL,
		0x344D63D557117978ULL,
		0x41943BBE9DAACBE3ULL,
		0xAFDA44DD1E71D131ULL,
		0xBA12CBE5E4A92B68ULL,
		0x43BCC42F72F59006ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0052F5AF9F0A3821ULL,
		0x8F555C45E5E33CDDULL,
		0xEEFA76AB2F8CD135ULL,
		0x137479C744C50650ULL,
		0x2F9792A4ADA2BF69ULL,
		0x10BDCBD6401AE84BULL,
		0x0000000000010EF3ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x67994751A2469586ULL,
		0xBF2C338BEBE7374FULL,
		0xC052EEF85E0D470CULL,
		0xDBAF12BA6E97A3F3ULL,
		0x8121E98E612D0EE7ULL,
		0xE7B58FE206137544ULL,
		0x540B01D040C76E65ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECF328EA3448D2BULL,
		0x197E586717D7CE6EULL,
		0xE780A5DDF0BC1A8EULL,
		0xCFB75E2574DD2F47ULL,
		0x890243D31CC25A1DULL,
		0xCBCF6B1FC40C26EAULL,
		0x00A81603A0818EDCULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBAA63E7C409B9175ULL,
		0xD3696AF31BE01073ULL,
		0xA91BBA08ABE73494ULL,
		0x92EA43CF0821552DULL,
		0xCC591D2ACEB610BBULL,
		0x6CA8489AE344B450ULL,
		0xDD7064FF6E1D2DCEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D2D5E637C020E7ULL,
		0x5237741157CE6929ULL,
		0x25D4879E1042AA5BULL,
		0x98B23A559D6C2177ULL,
		0xD9509135C68968A1ULL,
		0xBAE0C9FEDC3A5B9CULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x47009E66EEA77AA9ULL,
		0xFFA853D26B034EA9ULL,
		0x51ED6D1116CBC3B9ULL,
		0x36E0BA443C533053ULL,
		0xDB56E4AF1C5F593DULL,
		0x4BA0EBD671B79CD7ULL,
		0x4B9C0353EE3CA0DBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB034EA947009E66EULL,
		0x6CBC3B9FFA853D26ULL,
		0xC53305351ED6D111ULL,
		0xC5F593D36E0BA443ULL,
		0x1B79CD7DB56E4AF1ULL,
		0xE3CA0DB4BA0EBD67ULL,
		0x00000004B9C0353EULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA42548CC994E48B9ULL,
		0xEA3FCCA86F3EDDDCULL,
		0xD23E6F9A50B06FC1ULL,
		0xF4E475281EA859DDULL,
		0xC7FFC084BAB6CC26ULL,
		0x57B8EE97E9005CCAULL,
		0xD4DD7F5B296A5B56ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDCA42548CC994E4ULL,
		0xFC1EA3FCCA86F3EDULL,
		0x9DDD23E6F9A50B06ULL,
		0xC26F4E475281EA85ULL,
		0xCCAC7FFC084BAB6CULL,
		0xB5657B8EE97E9005ULL,
		0x000D4DD7F5B296A5ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF77C0F94098423DFULL,
		0xE29879A6AD2F51B6ULL,
		0x64568A5B6AC7F4A4ULL,
		0x8B289F2535A4A29EULL,
		0x25C7F29FCC2790EDULL,
		0x6F94DDE3079E9830ULL,
		0x907D8752C323A1BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34D5A5EA36DEEF81ULL,
		0x4B6D58FE949C530FULL,
		0xE4A6B49453CC8AD1ULL,
		0x53F984F21DB16513ULL,
		0xBC60F3D30604B8FEULL,
		0xEA586474374DF29BULL,
		0x0000000000120FB0ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC431EBAAE8495435ULL,
		0xF5A8BD4C9FAD91E9ULL,
		0x30792BEBA44B3E91ULL,
		0xC6B9DB77BCAE32A5ULL,
		0xFE326462F63D993BULL,
		0xA2D16F9AD2C8A7DEULL,
		0xA9287B038639B880ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64FD6C8F4E218F5DULL,
		0x5D2259F48FAD45EAULL,
		0xBDE571952983C95FULL,
		0x17B1ECC9DE35CEDBULL,
		0xD696453EF7F19323ULL,
		0x1C31CDC405168B7CULL,
		0x00000000054943D8ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0C2E271DE24C5836ULL,
		0xB5FB61F835CBC3C4ULL,
		0x9B0141152B7B63DEULL,
		0x92A2949EF7DE0240ULL,
		0xC13867B0B6BA135CULL,
		0xA5EA3AFE49EEF483ULL,
		0xF7F69217BB468F33ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835CBC3C40C2E271ULL,
		0x52B7B63DEB5FB61FULL,
		0xEF7DE02409B01411ULL,
		0x0B6BA135C92A2949ULL,
		0xE49EEF483C13867BULL,
		0x7BB468F33A5EA3AFULL,
		0x000000000F7F6921ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB2F2CD42E6DB7892ULL,
		0xA13C16ED52B5D2A2ULL,
		0x95CC9750569887C2ULL,
		0x290CEF788718B1B9ULL,
		0x914CCC62386165B3ULL,
		0xB944B91836F27070ULL,
		0x33703B88D3542177ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDAA56BA54565E5ULL,
		0x2EA0AD310F854278ULL,
		0xDEF10E3163732B99ULL,
		0x98C470C2CB665219ULL,
		0x72306DE4E0E12299ULL,
		0x7711A6A842EF7289ULL,
		0x00000000000066E0ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2731642FADF0D81FULL,
		0xBD6982A18283D097ULL,
		0x184EB3F9DBE30430ULL,
		0x9EA0F1F7FF7F2ECEULL,
		0x80EFA4947D1FD565ULL,
		0xDA91213BAD1DDC1AULL,
		0xE95FD7B190DF1793ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0972731642FADF0DULL,
		0x430BD6982A18283DULL,
		0xECE184EB3F9DBE30ULL,
		0x5659EA0F1F7FF7F2ULL,
		0xC1A80EFA4947D1FDULL,
		0x793DA91213BAD1DDULL,
		0x000E95FD7B190DF1ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xEE2E3181134B9D96ULL,
		0xF86DBF26FDE50B6BULL,
		0x81F5AF96EBE32E71ULL,
		0xEF9F36AFB6521AC2ULL,
		0xC4ACC72D740A8F64ULL,
		0xE3D6720D03D0F7E1ULL,
		0xEF4FAD36EEF1C284ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF71718C089A5CECBULL,
		0xFC36DF937EF285B5ULL,
		0x40FAD7CB75F19738ULL,
		0x77CF9B57DB290D61ULL,
		0xE2566396BA0547B2ULL,
		0x71EB390681E87BF0ULL,
		0x77A7D69B7778E142ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x09D24D631C84554FULL,
		0xE31E50DA6ABA6029ULL,
		0xDD5402A6B070094CULL,
		0xE9873E1B872163AFULL,
		0x21982E85B905DA2CULL,
		0x9E2B9D2D5E8A7467ULL,
		0x6060FC8F80AF3A46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE980A42749358C72ULL,
		0xC025338C794369AAULL,
		0x858EBF75500A9AC1ULL,
		0x1768B3A61CF86E1CULL,
		0x29D19C8660BA16E4ULL,
		0xBCE91A78AE74B57AULL,
		0x0000018183F23E02ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4F9A049B7B50213AULL,
		0xBC1A0BCB33A8E26DULL,
		0x8B2CA8883FF6A209ULL,
		0x30EEB407BCFA1767ULL,
		0xC8DDFE09004A9BE1ULL,
		0x153E774C9EC47663ULL,
		0xE57FDAEFE34F5EA1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0BCB33A8E26D4F9ULL,
		0xCA8883FF6A209BC1ULL,
		0xEB407BCFA17678B2ULL,
		0xDFE09004A9BE130EULL,
		0xE774C9EC47663C8DULL,
		0xFDAEFE34F5EA1153ULL,
		0x0000000000000E57ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x769DA1EC3FFD35C1ULL,
		0x235A162CB9114CEDULL,
		0x22BC9719374D7407ULL,
		0xB99C8AA53A49ED31ULL,
		0x98C13108FA684DC8ULL,
		0xBF9ACD74BC64073AULL,
		0x149DF84BFE4CCEABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x114CED769DA1EC3FULL,
		0x4D7407235A162CB9ULL,
		0x49ED3122BC971937ULL,
		0x684DC8B99C8AA53AULL,
		0x64073A98C13108FAULL,
		0x4CCEABBF9ACD74BCULL,
		0x000000149DF84BFEULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD8AA5D94DF195EFFULL,
		0x985371BFE025E417ULL,
		0x9C1BA4C1D76BBE67ULL,
		0x1FD2EFE93EB77DFAULL,
		0xD7A83491454A0B4BULL,
		0xAD730836C6AC8055ULL,
		0x495065E5B0C0E42FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF62A976537C657BFULL,
		0xE614DC6FF8097905ULL,
		0xA706E93075DAEF99ULL,
		0xC7F4BBFA4FADDF7EULL,
		0x75EA0D24515282D2ULL,
		0xEB5CC20DB1AB2015ULL,
		0x125419796C30390BULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x5D0B41B8F47D1EEAULL,
		0x7269141F3EC187A3ULL,
		0x0A4A991877C6362AULL,
		0xF383D444693F60F5ULL,
		0x3812C7BDADF355BEULL,
		0x2723DC7B10A62F31ULL,
		0xB8DC1617DA07E118ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A4507CFB061E8DULL,
		0x292A6461DF18D8A9ULL,
		0xCE0F5111A4FD83D4ULL,
		0xE04B1EF6B7CD56FBULL,
		0x9C8F71EC4298BCC4ULL,
		0xE370585F681F8460ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB2FE084E04BB5EA0ULL,
		0x66CFB45DBA1EFC54ULL,
		0xDDE38F3FCCC97C5DULL,
		0xC4DA1D8FD0700690ULL,
		0x9BA2F749D5A6CE34ULL,
		0x15BCD91B059523EFULL,
		0x2BF43E13311A8E61ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597F0427025DAF50ULL,
		0xB367DA2EDD0F7E2AULL,
		0x6EF1C79FE664BE2EULL,
		0x626D0EC7E8380348ULL,
		0xCDD17BA4EAD3671AULL,
		0x8ADE6C8D82CA91F7ULL,
		0x15FA1F09988D4730ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB0FFC829EDB484F6ULL,
		0xB55953CBE8F6CFA9ULL,
		0x0E96A94E2A16A20AULL,
		0x9642DF6A9906CCFCULL,
		0xAAF8596452B496A6ULL,
		0x7786FA1F2E0A26DAULL,
		0x50FB1661912EF996ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0FFC829EDB484F6ULL,
		0xB55953CBE8F6CFA9ULL,
		0x0E96A94E2A16A20AULL,
		0x9642DF6A9906CCFCULL,
		0xAAF8596452B496A6ULL,
		0x7786FA1F2E0A26DAULL,
		0x50FB1661912EF996ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4D5E4AFB51BD81D5ULL,
		0xE981F5AC85C35F9DULL,
		0x6D00AB4A0A5AADD7ULL,
		0x84101CB5A21B4A26ULL,
		0x015D7E9FC4CCCEA6ULL,
		0x147C3CFC3943DB08ULL,
		0xE6EC0BECB7C5A750ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6AF257DA8DEC0EAULL,
		0xF4C0FAD642E1AFCEULL,
		0x368055A5052D56EBULL,
		0x42080E5AD10DA513ULL,
		0x00AEBF4FE2666753ULL,
		0x0A3E1E7E1CA1ED84ULL,
		0x737605F65BE2D3A8ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB168086DCB586445ULL,
		0x9744268A598B2FC6ULL,
		0x8C1123B446CA240AULL,
		0x9B6345C465D49C31ULL,
		0xC00F556749952CFDULL,
		0xABD815D5D35BB2B2ULL,
		0x406996CBA3F684B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E884D14B3165F8DULL,
		0x182247688D944815ULL,
		0x36C68B88CBA93863ULL,
		0x801EAACE932A59FBULL,
		0x57B02BABA6B76565ULL,
		0x80D32D9747ED096DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBDE8B5CD6739BC57ULL,
		0xD57DE2C5A42F6241ULL,
		0x57C79313405A9212ULL,
		0x81B1D7241C06F66DULL,
		0x1C9C284515F2B9DFULL,
		0x26604D9FD429DA00ULL,
		0x9634FBB284FD0269ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC58B485EC4837BDULL,
		0xF262680B52425AAFULL,
		0x3AE48380DECDAAF8ULL,
		0x8508A2BE573BF036ULL,
		0x09B3FA853B400393ULL,
		0x9F76509FA04D24CCULL,
		0x00000000000012C6ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x115C005B9C9D56DCULL,
		0x0B426E5D50EBC71FULL,
		0xCE0E26501ABF6D65ULL,
		0x818520427F6C15D4ULL,
		0x7F97B885F10514BDULL,
		0x6229C72808DA7515ULL,
		0x13CBDD9CEDF130F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBAA1D78E3E22B8ULL,
		0x4CA0357EDACA1684ULL,
		0x4084FED82BA99C1CULL,
		0x710BE20A297B030AULL,
		0x8E5011B4EA2AFF2FULL,
		0xBB39DBE261E2C453ULL,
		0x0000000000002797ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9EF01A4D94138723ULL,
		0x3D667F8E540C5B63ULL,
		0xD057F80C3FAFBB15ULL,
		0x01F95957E7914C90ULL,
		0x5D57E8D3FE1A4994ULL,
		0xCA6F72A5844E5B9EULL,
		0xC7C44A4B0310CD6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73DE0349B28270E4ULL,
		0xA7ACCFF1CA818B6CULL,
		0x1A0AFF0187F5F762ULL,
		0x803F2B2AFCF22992ULL,
		0xCBAAFD1A7FC34932ULL,
		0xD94DEE54B089CB73ULL,
		0x18F88949606219ADULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x886FFD59B0576388ULL,
		0x9F3E336FC4E0DC63ULL,
		0xC8CD971D323A99B2ULL,
		0x9A2DDCFE03FF4482ULL,
		0x76F46B310760780BULL,
		0xDDAC1CBAFC992363ULL,
		0x9856B536D834B519ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63886FFD59B0576ULL,
		0x9B29F3E336FC4E0DULL,
		0x482C8CD971D323A9ULL,
		0x80B9A2DDCFE03FF4ULL,
		0x36376F46B3107607ULL,
		0x519DDAC1CBAFC992ULL,
		0x0009856B536D834BULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x779A3D544FBEF688ULL,
		0xFBFE79447B834453ULL,
		0x8CFA165A7A6EE490ULL,
		0xA03D7E5D19CEA9C4ULL,
		0x7AC3074AA4247B66ULL,
		0x46B2C720F2F324E0ULL,
		0xAF2AD67744C5962FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC1A229BBCD1EAAULL,
		0x3D3772487DFF3CA2ULL,
		0x8CE754E2467D0B2DULL,
		0x52123DB3501EBF2EULL,
		0x797992703D6183A5ULL,
		0xA262CB17A3596390ULL,
		0x0000000057956B3BULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF6253277759EB960ULL,
		0xD255A6C3DAF8C4D2ULL,
		0x1D218DF05CB53C33ULL,
		0x0BC8E6A6F4E4B131ULL,
		0xD5D525F30F3EE6CEULL,
		0x8F3F041618AA8898ULL,
		0xD9DF439229632657ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F6BE3134BD894C9ULL,
		0xC172D4F0CF49569BULL,
		0x9BD392C4C4748637ULL,
		0xCC3CFB9B382F239AULL,
		0x5862AA2263575497ULL,
		0x48A58C995E3CFC10ULL,
		0x0000000003677D0EULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x663E173E6E17C09AULL,
		0xA4E548855016C65BULL,
		0xA891587E2B2CE615ULL,
		0x7118C3E6D56B3867ULL,
		0x969E71EF92B4F5BCULL,
		0x5E570999CE4CC75AULL,
		0x605F531750C191AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15405B196D98F85CULL,
		0xF8ACB39856939522ULL,
		0x9B55ACE19EA24561ULL,
		0xBE4AD3D6F1C4630FULL,
		0x6739331D6A5A79C7ULL,
		0x5D430646A9795C26ULL,
		0x0000000001817D4CULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2EF04D0063FA6765ULL,
		0xCE26F79C83B4336DULL,
		0xF7D0049BDD5B1954ULL,
		0xF7E2C96CECDCDDCDULL,
		0xEC44A4847314B285ULL,
		0x9B7EA49072CF7F00ULL,
		0x47BA2B128C08DB36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED0CDB4BBC134018ULL,
		0x56C6553389BDE720ULL,
		0x3737737DF40126F7ULL,
		0xC52CA17DF8B25B3BULL,
		0xB3DFC03B1129211CULL,
		0x0236CDA6DFA9241CULL,
		0x00000011EE8AC4A3ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9030C12831CA949FULL,
		0xFAE59819550873B0ULL,
		0xDE2B8BF2D7AC12A1ULL,
		0x520DF26D9F7C2413ULL,
		0xFC11D21E2009EEE2ULL,
		0x278DF9D14B3536B6ULL,
		0x1ACEE448948E518EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8439D84818609418ULL,
		0xD60950FD72CC0CAAULL,
		0xBE1209EF15C5F96BULL,
		0x04F7712906F936CFULL,
		0x9A9B5B7E08E90F10ULL,
		0x4728C713C6FCE8A5ULL,
		0x0000000D6772244AULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB743BBC79AFFB209ULL,
		0xB589CAFB4DF70260ULL,
		0xEC0F44F5840FF1D3ULL,
		0x97D3C8E7D1907351ULL,
		0x8652DB5F433AAF47ULL,
		0x68BE5E261D7E1E71ULL,
		0xD76F17C831D01CF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BEE04C16E87778ULL,
		0xB081FE3A76B1395FULL,
		0xFA320E6A3D81E89EULL,
		0xE86755E8F2FA791CULL,
		0xC3AFC3CE30CA5B6BULL,
		0x063A039EAD17CBC4ULL,
		0x000000001AEDE2F9ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x9D4771E974DD5F57ULL,
		0xACFE48AA7DA3ABD0ULL,
		0x67524ABCFD5A0AC0ULL,
		0x0CD43FFEE7389BF0ULL,
		0x0DFFF7BFED62B5FAULL,
		0x1BECAAD51F6D4B9CULL,
		0xE9A3CA40CA6BE49BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE84EA3B8F4BA6EAFULL,
		0x60567F24553ED1D5ULL,
		0xF833A9255E7EAD05ULL,
		0xFD066A1FFF739C4DULL,
		0xCE06FFFBDFF6B15AULL,
		0x4D8DF6556A8FB6A5ULL,
		0x0074D1E5206535F2ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x759190F87E10800DULL,
		0xD64EEE71FCCD6924ULL,
		0x4B1A58B077B21EC0ULL,
		0x7453DAC8BBB2C946ULL,
		0x142C459890675EB8ULL,
		0xC97E76E525AEFC81ULL,
		0xFACDDB34A2243E41ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7738FE66B4923AC8ULL,
		0x2C583BD90F606B27ULL,
		0xED645DD964A3258DULL,
		0x22CC4833AF5C3A29ULL,
		0x3B7292D77E408A16ULL,
		0xED9A51121F20E4BFULL,
		0x0000000000007D66ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF9D3936E49225C5AULL,
		0x5506A28F182077E5ULL,
		0x2FDDB5E64C9EF686ULL,
		0xCFBBB7E2A599EF93ULL,
		0x00C568554370E16EULL,
		0xDD5B0C4971869D61ULL,
		0x768B73E0B31E6D35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28F182077E5F9D39ULL,
		0x5E64C9EF6865506AULL,
		0x7E2A599EF932FDDBULL,
		0x8554370E16ECFBBBULL,
		0xC4971869D6100C56ULL,
		0x3E0B31E6D35DD5B0ULL,
		0x00000000000768B7ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6724567B25BF9B4CULL,
		0xA14B0724AB29FE8FULL,
		0xDD13CDFD752E1B20ULL,
		0xBC825CF796A304C5ULL,
		0x67D9397641B87DC5ULL,
		0xDEA87AA41BA4CA97ULL,
		0x5F9ADED01B31AE85ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5653FD1ECE48ACF6ULL,
		0xEA5C364142960E49ULL,
		0x2D46098BBA279BFAULL,
		0x8370FB8B7904B9EFULL,
		0x3749952ECFB272ECULL,
		0x36635D0BBD50F548ULL,
		0x00000000BF35BDA0ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4B5369CBAECFE45BULL,
		0xB21CFBEB33818EF1ULL,
		0xE088BDEFFC657038ULL,
		0x3039D467A5A01517ULL,
		0x40480CC2C5A2710EULL,
		0x6861BD3902B9B72BULL,
		0x5AFA9303CAB554D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF599C0C778A5A9ULL,
		0x5EF7FE32B81C590EULL,
		0xEA33D2D00A8BF044ULL,
		0x066162D13887181CULL,
		0xDE9C815CDB95A024ULL,
		0x4981E55AAA6BB430ULL,
		0x0000000000002D7DULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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