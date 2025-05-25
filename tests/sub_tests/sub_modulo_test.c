#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x8CE7C4CD722032DBULL,
		0x3F7DC481CD1B4F5AULL,
		0xFD7FA92483893CBFULL,
		0xF354AC1B5346EB7BULL,
		0xF968ABBF0F1E088FULL,
		0xE9AA946CD94FF11CULL,
		0xCFE2D1C12873E61FULL,
		0xB07A02FE4A7FB446ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x79642558F41C3EF8ULL,
		0xE00D85DD91369C8EULL,
		0x74B4A54D58405EC4ULL,
		0xF311761C76AA9B73ULL,
		0x0A5A2DE966BE10C3ULL,
		0x452E913E0CA5F5D5ULL,
		0x0EE2831FC59CC6D1ULL,
		0x05975665192D502CULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x8FAA4D2B7C42BFE1ULL,
		0xC9D8B7969D1FFF79ULL,
		0x2ED6AFCBD73783A6ULL,
		0x5DE8D4BC2ED72C01ULL,
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
		0x6B20E251C750312BULL,
		0x0357A2DB8C463721ULL,
		0x2224B8625C45B740ULL,
		0x4D8F4C4CBB3E20CAULL,
		0x8EB15E3E7ED33262ULL,
		0xEEA854407F9E89AEULL,
		0x9ED592603C520FF7ULL,
		0x765BD7D688799B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DAC44CFC4024F7DULL,
		0x4DC11EA97C209A8BULL,
		0x6285B142693FFC1CULL,
		0xA15CD490EEA17164ULL,
		0x54D25821833BA81CULL,
		0x366D27971138600FULL,
		0x1CF3BF99044DAF7CULL,
		0xDF93E6A87771E27FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA48F85CF5BCC65B2ULL,
		0x0E5F2558734FCA38ULL,
		0x072450B243AC0D81ULL,
		0x0DE0449253C21D9BULL,
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
		0x3C4CB7B3D433819EULL,
		0xB7C85C2EE8F49E76ULL,
		0x8FF2595DAD70F4ECULL,
		0x9F030C94CC3974CDULL,
		0xE01CC978A9D8F6E9ULL,
		0x34D3CCA7A3DB81EEULL,
		0x3F7AE5F8265CD822ULL,
		0x50C9EE689259897DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB27E766DE9E1A9CBULL,
		0xADD347078BD4CCBBULL,
		0x8D826E4B58A7C6ADULL,
		0x25324A3341ECDA12ULL,
		0xF001036E0261B2EFULL,
		0x2BA5F3723907E849ULL,
		0x884985F0C00206FFULL,
		0xF6369E02FA7947BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DEDA6DAC605EB4CULL,
		0x66C353153888A036ULL,
		0x33C42C2B86443972ULL,
		0x6BAEB17615965D7CULL,
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
		0x8D577E586BB5AA3BULL,
		0x3CF79FEF450D0029ULL,
		0xC0E62442E3100E79ULL,
		0xFD29210CC09712B1ULL,
		0xFCCDBD26B994302AULL,
		0x9ABF557534E238BBULL,
		0x112AF4624A19B157ULL,
		0x0C3443106E8AFC0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE498CF5165E6AFB5ULL,
		0x9AEFD360241639DDULL,
		0x86B19DAB37788108ULL,
		0xD7B5FB11E9E714A2ULL,
		0xFA068200F5B40E23ULL,
		0xF33E93954FD009B6ULL,
		0x4EC732BAD4908192ULL,
		0xE071EC5E180DAF67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x125176A2191402E3ULL,
		0x7F2493CB21A9C10AULL,
		0x150345731DF4A4A1ULL,
		0x244C0473AD495EF6ULL,
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
		0x466D3CD018D52212ULL,
		0x9EE635EF2A9239A6ULL,
		0x6AF23B4ADE84E7ABULL,
		0x839F4F609E6B779FULL,
		0xBBE4903C98652F91ULL,
		0xBB1BDFEF1BBFC867ULL,
		0xB1E3122B17CD729BULL,
		0x77D61AEB9C13D86CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2A3C1E042F1F41ULL,
		0xB6A2B88BDE853C6FULL,
		0x2F617F8F91A07A2AULL,
		0x4096E5BFACCEBCD9ULL,
		0x875D03AE7902C9BFULL,
		0x67AF4573F66DCA53ULL,
		0x832094DEBE4201ECULL,
		0x1E78D42D616BC67AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9661DDCABD4121FEULL,
		0x4A626BAAD638B436ULL,
		0x2C6F551097972787ULL,
		0x06E0E9DDA68F64B9ULL,
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
		0x7C48C260FDF505F4ULL,
		0x3A7C615EF059C025ULL,
		0xA46EC6B4828E75A2ULL,
		0xA7F3CE8ADC394661ULL,
		0x99810DE6EAA72A77ULL,
		0xA78500A9EC95AF63ULL,
		0x02FD8521A6FA1D15ULL,
		0x1055B10B5C7F2D18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658C61EF842D57A6ULL,
		0xA78F627FE150CBD0ULL,
		0x42F2197F5B8E6CD8ULL,
		0x40AF5A268B476BCAULL,
		0xB27588437E9481FBULL,
		0xADB58CA10599B920ULL,
		0x8589CEBDC61E9C6DULL,
		0x5412DD3AB5A203D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x627236B3848CAF3AULL,
		0xA7B83831586F8243ULL,
		0x00A9C008879521B8ULL,
		0x592FE55D15C5FAC2ULL,
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
		0x2A872C8A344ACAA3ULL,
		0x01860276B439B435ULL,
		0x789F02313A5924D5ULL,
		0xFACEF0B4939D3BE8ULL,
		0xA433C2F18B705D78ULL,
		0x51F83B3D4A901D77ULL,
		0x06591B6AE1F602F7ULL,
		0x10E00935F268792BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE03C82299DD325AULL,
		0x30FEB848B54B5150ULL,
		0xB419F30DDE6AF88BULL,
		0x166047BE7D6E0509ULL,
		0x9C7C9E254002E975ULL,
		0xE6A1935CB3BD6EECULL,
		0x19B9C8807418E4CDULL,
		0x62EEA73BD5682576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51B2DABACCACCF06ULL,
		0xBF64358462344B87ULL,
		0xE42B5DEFAAC0A66FULL,
		0x36433416643BA3B9ULL,
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
		0x2CDB929EDC3852E7ULL,
		0xB13AA8324475C785ULL,
		0x9CEFA7ED4DC2665FULL,
		0xA1F20188CE90092CULL,
		0xBB8B0072174C08A5ULL,
		0x40B58C5FDBE9505AULL,
		0x305F1C272420EED8ULL,
		0x836AE89DEA2D09AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB294879114B95741ULL,
		0x9B18FA6F156C287EULL,
		0xCD89F01C708B7970ULL,
		0x04EC71F049640C8EULL,
		0x0313F8616A796777ULL,
		0xB59B492058F16111ULL,
		0xA5CB3DDEB948AD83ULL,
		0x8313C7F664FC01A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBF23D876EC2E88DULL,
		0xBC07A9309FD723F7ULL,
		0x6158B690B9509F7BULL,
		0x29F468764A732DE2ULL,
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
		0x30EECCD3DF35FD89ULL,
		0xC298DCC6E6A37EE1ULL,
		0xC56A7111D2AA0188ULL,
		0x5DE5804A72DCC95BULL,
		0xABDEDCE4197A450FULL,
		0x9EFA1CEAD2526A78ULL,
		0x1B2745EB55DA7959ULL,
		0xE052CE6243B630C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB538FEAFA89CD04EULL,
		0xE3088622A7743D41ULL,
		0x3F8C6C5D7924D142ULL,
		0xB52DE225FF9FBADEULL,
		0x8279E55DB7A39FC7ULL,
		0xEEF7FE8D266A6BF3ULL,
		0x3E99EFE7B8284E88ULL,
		0x56F9FA11627D4EE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0B28C16BC75B8E3ULL,
		0xFFE0D88BC39F0963ULL,
		0x42D8C93DC1F78B3FULL,
		0x0BE72225E1AE95DEULL,
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
		0x220BA9CC5D8CA727ULL,
		0xF2022AC1D009787EULL,
		0x8498934496A3CAC5ULL,
		0x6FB71DC3AB6D8D12ULL,
		0xCC9090F2DFFC208BULL,
		0x690EA29A2E5D7B41ULL,
		0x4E407BD2F6B0266AULL,
		0xFAF61074C677976CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C2219C00CBE645BULL,
		0x632A5DB7D326D1D9ULL,
		0x473C872A4FE78FD9ULL,
		0x4197037C502F0152ULL,
		0xB0ACFEF364283DFFULL,
		0xD71F4E02A1783675ULL,
		0x7EFF71C8C501C00AULL,
		0x3962287CA49E426CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09B13BF8B241E7CFULL,
		0x385E5B88E6EADCF1ULL,
		0x0103899DA69F6D1CULL,
		0x6A14891C618129B9ULL,
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
		0x0F22E609797AFC30ULL,
		0x875B59AF324E92CDULL,
		0x00365170A4A96E9BULL,
		0xAC7765B919C1ADAEULL,
		0x05CB536FD042F249ULL,
		0xAADDE2E965D274C2ULL,
		0x30CAD07EEDC3E348ULL,
		0x68C5B8349F6A838FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15FFD3FF6A16EA9ULL,
		0x8C258993EF64EEEDULL,
		0x3D8CE36B8367C4B5ULL,
		0xA2AC0FA2C85EFD80ULL,
		0x3E631AF64C226FCBULL,
		0xBFD95724EF8F56F1ULL,
		0x6CDF23D255FF5AF9ULL,
		0x01CE20D3F1159EAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x073B4AD31FACEE75ULL,
		0xDDE28F44D0E010DDULL,
		0xD7A50FA3A86DE59CULL,
		0x528BCE7031FCA98AULL,
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
		0xB32D1EEEEE506D48ULL,
		0xFAB8BC3A3A472ADCULL,
		0x1AE0C30229DF1C32ULL,
		0x1A243C7247CA8CB8ULL,
		0xA5A25E2DE164E3E3ULL,
		0x68D286486FA7937DULL,
		0x672A63826B9896D8ULL,
		0xDE723D65E5B33248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD03123C04E73707ULL,
		0x5A36BE3C4906934FULL,
		0xC3391B6D3F33B843ULL,
		0xA883EDBBEE023FAEULL,
		0x00F85B6B11E2B415ULL,
		0x3BF152A8B753B995ULL,
		0x2FB0394DE2220E83ULL,
		0x2D1539B8ECA41B69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4766759DB6BC529EULL,
		0x49EFA7B34DB2F015ULL,
		0x93C9EB615243A094ULL,
		0x456EDA635205B22BULL,
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
		0xC7F802DD5453EA8FULL,
		0x9645F568320FD050ULL,
		0x2BF409FAD573D8BFULL,
		0xC9B000A2503EBC0CULL,
		0x63DCAC18F6107DFFULL,
		0x1713796F42733816ULL,
		0xAD28BA30BB5FFA00ULL,
		0xB1EFAFC1D5BDA551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0B220E715AC63D7ULL,
		0x1BFBC9BF0457DA69ULL,
		0x617CECC4A6E49C42ULL,
		0x9AC0254B8E627AF3ULL,
		0xF076ACF810151BE3ULL,
		0xB28D89E959FD7AECULL,
		0xB1AEC1E03779DB13ULL,
		0x47EA8081A17B6D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2869C0D861F8192DULL,
		0x662BB989AF320A0EULL,
		0x1E91F929C2B7D394ULL,
		0x6BB4DEDE83B09410ULL,
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
		0xC2886795150081EFULL,
		0x6A24FE431CA9D686ULL,
		0xCCFC0B43E099F2EAULL,
		0xD14B88BB91803C96ULL,
		0x9D420E7BF074CD8FULL,
		0xD076CF131802C45EULL,
		0x9CB85892E742CB5DULL,
		0x4620D0FC9731380AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E7046767C0C18DULL,
		0x8BD81F5736201C89ULL,
		0xAC606030F01009C8ULL,
		0x43D92BB0E658C51EULL,
		0x928BE223BEB44413ULL,
		0x6D40011471F8ADA5ULL,
		0x07216674B2049D37ULL,
		0x451A9C693FFCF5ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14ABF8450FD428DDULL,
		0x986F72B88C091975ULL,
		0x55039B8ED7C4C2D4ULL,
		0x345E2AE99CE95182ULL,
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
		0x6487D8B6DBBC909DULL,
		0x3EFEA407FA1AEFB0ULL,
		0x8E894469AD48ED69ULL,
		0x11A7A2EDA4FE3A0DULL,
		0x8B5AAF110098F7C0ULL,
		0x4A687B75C4849B01ULL,
		0x8D83593B4C2006C9ULL,
		0x2FB406E280A8A56BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD2917D25B5500A9ULL,
		0xD345E8632E0FEEF3ULL,
		0x117AB207E3E5971FULL,
		0x5C49DC5AB791D455ULL,
		0x1405009CB19539FBULL,
		0xF4E0F5BA618CD972ULL,
		0x871CAD79AD661D9DULL,
		0x1997E1E22048EFB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E16A6283AF5BB91ULL,
		0x1DD695757CD1BC08ULL,
		0x704C111F58FBF2B8ULL,
		0x7D8B44A13BA15E71ULL,
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
		0x1F866778D49CBE04ULL,
		0x03C825AAD6DC6434ULL,
		0x061C7FCCF9EC6C9BULL,
		0xD4EDEDB51C70B851ULL,
		0x1743387247545004ULL,
		0x8E3AFDE372FDEF87ULL,
		0x77B618C3DFB4BDB2ULL,
		0x15567F5839BCA61EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B39AEF33B1720A4ULL,
		0x30D7C8C3003CA25BULL,
		0xB206B1D07B760422ULL,
		0xC0862D2791EC71E4ULL,
		0x154746A66D11A112ULL,
		0x883A9F4B35A2F4C2ULL,
		0x7351BE22855B010AULL,
		0x21F6F4FAF2F5146FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FB29CC7FF6B9500ULL,
		0xB6FE6780F220FB17ULL,
		0xFAFB41EFE7C86969ULL,
		0x34964A660C23E666ULL,
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
		0xAA16A9144558BA69ULL,
		0x24C05B33BBADAC10ULL,
		0x9988404DD6255035ULL,
		0xDB5D8217A9943C3EULL,
		0x896F3B2A73BB27BFULL,
		0xB0B1714872D2F4D2ULL,
		0x2A64BCAEDC3E22D4ULL,
		0x0F55F4C48C48C818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC09B8C10E061FE2ULL,
		0xBFDAC0E4705B66FFULL,
		0xD856B2F209DC5B57ULL,
		0xFEAA3AFF81EAA215ULL,
		0x50A15A3B977352C0ULL,
		0x49D3A8E60E42768BULL,
		0xC0DB16C72946B051ULL,
		0x9A41E78EC130C3CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C9C53C7E9FC3543ULL,
		0xA9D158EA38C503A3ULL,
		0x6BA02DC05D03F45EULL,
		0x3DAD3D144D3A3D0EULL,
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
		0x69DA37D7DD184726ULL,
		0x0E9487890FFEFCCEULL,
		0xE59484FE4CC98275ULL,
		0xEF94ACBF35E0534DULL,
		0xD5FB511C2891DEC4ULL,
		0xF6A17326FE6B9146ULL,
		0xA7143DB4A9509286ULL,
		0xAF0F14BA431475B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD295C6CC6CA846EULL,
		0x776992B23152FB6CULL,
		0x59596A8F1EE87EDEULL,
		0xFF5B1C232456E1EBULL,
		0x02C2152349336108ULL,
		0x2BFBE3E1918F697FULL,
		0x7D977C7BFCFEBB25ULL,
		0x7DDE240BF7767737ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC72FC25C3E546DAAULL,
		0xABBE39250759E90AULL,
		0xB4BFC8D8C206FC1AULL,
		0x3D7D4A7B4AFD388EULL,
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
		0x7AAC3E5BB8AC5958ULL,
		0xD4F20208670F9323ULL,
		0x3C3939F6AD6CF803ULL,
		0xB8140ADC87A02C7EULL,
		0x2AE3B5F0C8FC07D4ULL,
		0x385EC91CDECF45D4ULL,
		0x1E4AB286E456A5D4ULL,
		0xF76130AF359376FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E82934F20F4C7EULL,
		0x2540142AA398E04AULL,
		0x72217671B4AA3E81ULL,
		0xD330BE0D64107121ULL,
		0xCD6BAE851E4AC6DAULL,
		0x63C72D13B56DD1A1ULL,
		0x088E808FCF1EF9B1ULL,
		0x88E862DAC053F0DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31952F221CECB456ULL,
		0x3E331739E7EDF253ULL,
		0x04072E321F0646AEULL,
		0x4AD1DA588AFDA4B8ULL,
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
		0xCF20D91A452DC30FULL,
		0x22B3DBA7794BAA7DULL,
		0x125D4C12EF44DCD6ULL,
		0xE4A3725656DF1169ULL,
		0x0A363297AC6B7860ULL,
		0xD868FAB531FA7219ULL,
		0x80977C6B35C139EFULL,
		0xC111C77A2E1CC2DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9738DBB71ED61835ULL,
		0xDE7FEA4D832E135EULL,
		0x2EA912CAA6F1CE8AULL,
		0x347E38096800ACA6ULL,
		0x0C2CC807CD5E0137ULL,
		0xF75921B8DF61B7E9ULL,
		0x46D16F42DA2BFB33ULL,
		0xF312B636119D5B14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED4DCEBE425759E6ULL,
		0xAC8E26CE38C93A3EULL,
		0x771A2D45E07A5E2EULL,
		0x4401CA6929C7CC2FULL,
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
		0xC1B5ECE60D994664ULL,
		0x1C9047A844B32B38ULL,
		0xBE78A91E4667D7D7ULL,
		0x80D26207998A53C4ULL,
		0x6F4810130591862EULL,
		0x456823DA42FE0465ULL,
		0xB542A8B4E2658D68ULL,
		0x331036BFA12D38C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C09C1959FA1F511ULL,
		0x5ADE2AA265FDDDC5ULL,
		0x2D243C0A85B57486ULL,
		0x1211076A1ADCFD41ULL,
		0xABB8784B865EB0F6ULL,
		0xD4E2937E14EF7108ULL,
		0xC6EB09CBC27BACFCULL,
		0x4282A3685DDFF813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CFCB2ED4F82F757ULL,
		0x75858AB4B4DF2D38ULL,
		0xF25603AE7D69B343ULL,
		0x23C539917C24F0ECULL,
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
		0xF5A4C53B7449EF35ULL,
		0x4058A4C489DC7DF4ULL,
		0xC161750859108EABULL,
		0xB10B1A903A03CA9BULL,
		0xC4F5F526F9F0CF34ULL,
		0xE952F60C119A36E4ULL,
		0xC2662DA888A87AFFULL,
		0x80721E5DDE10E7CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20A2EF8C2720D28AULL,
		0x447CD1F2477D513EULL,
		0xE66B2FCBE3623550ULL,
		0xE156FC3C85D4E824ULL,
		0xDED25E892F866D8EULL,
		0x6D31FE014A63A890ULL,
		0x0CEA4C1EC24B499CULL,
		0x014566C59EFA0691ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE4A311B58F39E0EULL,
		0x68C0A46BD4784D2AULL,
		0xCB59BFAFE783AE1FULL,
		0x30575EED11945179ULL,
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
		0xE0D1B936785A5618ULL,
		0x41D1875CB427953EULL,
		0x4197C9DB6F85352DULL,
		0xAAA99CB1D20398EEULL,
		0x584B5A5BE0C85507ULL,
		0xF0B87B40D6F68077ULL,
		0x9E5DD434F337AA1EULL,
		0x41ACA29649E0DC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317274182C0914A3ULL,
		0x95B21D13C2F9B65AULL,
		0x8155E302059E97A7ULL,
		0x28E72E21F997B179ULL,
		0x5BEACC2D5D556E4EULL,
		0xB81111FA15AA0048ULL,
		0x2B76C9E1826A1379ULL,
		0x71395674A2B245EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25B46005CF5F7FE1ULL,
		0x14F90AC9A288E5DEULL,
		0xCE8D6F3C286AFA0CULL,
		0x72DFBB8EA95630DDULL,
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
		0xCED5E242AFEF1ABFULL,
		0x6D2C16D660CA9FD1ULL,
		0x8CB0227A663D65DDULL,
		0x0ABE2F34821DA8FAULL,
		0x153E0EB5C096DD43ULL,
		0xB939B78DBDBB4DCAULL,
		0x6468A987D6D4DC81ULL,
		0x8F0D8DCBB46E5F97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C18FFB8097A53EULL,
		0xB73C59296774272EULL,
		0xBFEFDC506985E0D9ULL,
		0x9A4B4E3F2A79C6C6ULL,
		0x4FB756C647AFDB2EULL,
		0x001241E56218584EULL,
		0xCE6E347DA7191975ULL,
		0x980CD6EFBE6A064EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29139FD321A1C453ULL,
		0x31CB34AA9386E902ULL,
		0x0FEDA5AD129678E7ULL,
		0x1A8E059BDC4922FAULL,
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
		0xD3093327964357EBULL,
		0xB405B789DB7700DBULL,
		0x7749D196FE279DC3ULL,
		0x9B95819DB8846109ULL,
		0x7AD6CB6430261CEEULL,
		0x6737C7135FE50AEFULL,
		0xCD647A95580E2DEAULL,
		0x988803F4B756930BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C170DD34462B59ULL,
		0xCC921971840379D9ULL,
		0x1298E7A052C54980ULL,
		0x0DD912B4BAF2DAA6ULL,
		0x197D3502A8EAA2A0ULL,
		0x6F39AF56B3041ED9ULL,
		0x19FC22E9E3E98A26ULL,
		0xB0D11A38A52B8A13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD9414C474D153A1ULL,
		0xB72B241A00D69254ULL,
		0x062DED69E8D2A359ULL,
		0x72E320D3AFF4DB4EULL,
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
		0x7DD74D5DC67A4FC6ULL,
		0x8CAD45858FBED85DULL,
		0xBBF5B1193237785CULL,
		0xE5D665CBA7269ABBULL,
		0xFA902BD8E356E9C2ULL,
		0x1A211D1660404B66ULL,
		0x626FA428B2E7E497ULL,
		0x36706B8CF83745D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF1D83B3F4ED45BULL,
		0xC2EE30EE0AE0FE4DULL,
		0x0B05242A2CFF76F3ULL,
		0xF2AEAC9BA05BA6E6ULL,
		0xC4A9DF6FFE382880ULL,
		0x5BDC3F33F209046BULL,
		0x04FA461578EFE6D3ULL,
		0xD1E95D5AE533BE21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E14CCB489BC27BAULL,
		0x07F80433E112635AULL,
		0x905C83C9A007AC77ULL,
		0x5F33D49ED95117DDULL,
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
		0x932C5A8425D0CDC0ULL,
		0x3121088D056A2641ULL,
		0x9D3A8AC8454E3444ULL,
		0xF8EAD8C7954D0B82ULL,
		0x26DE59E1250551D9ULL,
		0x48AAB83C82EC83BFULL,
		0x76D0B78C4AA9FC47ULL,
		0xBAED7090FB1A18E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC223119CAF71F6EULL,
		0x91F668AA5629BD8AULL,
		0x3E5C014694922EB6ULL,
		0x1310B8C915AE640AULL,
		0x5DD43A83EEDA919EULL,
		0xC3D5D03420DD3AD1ULL,
		0x7BF9BB547B18849BULL,
		0xF5A9B56D8398BC22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E8AD140653235E4ULL,
		0x56C511213D853C02ULL,
		0x9AC7F9CA8053C903ULL,
		0x2DE7E7423CD26BABULL,
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
		0x9DAFD283CD23806DULL,
		0x4500B26B061B3829ULL,
		0x28662AA61C0C67B7ULL,
		0x016920A0B4019060ULL,
		0xDCF3904CC8F594E6ULL,
		0x8FA6644208C6E3A1ULL,
		0xC969DB04FA1C9610ULL,
		0x2B5B9E4CBC15A29CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD163227B71B5C1FDULL,
		0x5C3497E5FDF9BE7CULL,
		0xA292FFE89174FA2FULL,
		0x618C1860C358AB9AULL,
		0xD1C10CB9F72F5541ULL,
		0xDAE76D46AEE360FCULL,
		0x417288F195F39EC8ULL,
		0xC11FE951D8A9239EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75CC37D37EDB2D84ULL,
		0xBD24C3D45FE6DE2CULL,
		0xB489599E68AC222CULL,
		0x64B9E57DB2C3BE8DULL,
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
		0x8E50E3BEF66F345AULL,
		0xBDB1DA0E241CDDBFULL,
		0xEA381E983E907EE0ULL,
		0x35A7B018DD22E8E4ULL,
		0x2CBEC640449A331EULL,
		0x511B2086995B6B55ULL,
		0x526645EDB706FCF3ULL,
		0x634F09247E756DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1694BB9B34829136ULL,
		0x1ADA53028D74F335ULL,
		0xCE542599608EBE36ULL,
		0xCB06BCBA316E4621ULL,
		0x859F65DD88E1C54BULL,
		0x2BA510E5B8C8773EULL,
		0x5243B4E93CA042B4ULL,
		0x33891B56D5E8D713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x466476CB9F4CF16DULL,
		0x325DD8ECEC7825E7ULL,
		0x21057FA90941660AULL,
		0x02023FE5B093031DULL,
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
		0x08DD1590B3D48DFCULL,
		0xCB0BBCDCB1C2C053ULL,
		0x4C3B809C1C4ED423ULL,
		0x4FB4321B7F19B06BULL,
		0xAE72756EE95A6BCDULL,
		0xB538E85EDB02B930ULL,
		0x737BEC719B643522ULL,
		0x34E42614C81FBA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F28870F3954DF56ULL,
		0xDC61C721BC10C8CCULL,
		0xD2D1C776B573D5AFULL,
		0x661BD82AAFB54889ULL,
		0xC806330F80356F14ULL,
		0xE90AA34534FED888ULL,
		0x0AA260E0CB3C973EULL,
		0xF5AD12015142DBECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDC668AB15FD2DCEULL,
		0x3D8837899A455072ULL,
		0x09B470A44CBC6E44ULL,
		0x4BC554D4742D6655ULL,
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
		0xC8AAADBBEFF69F3CULL,
		0x56721AA76C75A0EAULL,
		0xB03A89E6F5BE4FD5ULL,
		0xB949A9E8A8F5812DULL,
		0xF79B92DB50D7131DULL,
		0xA61DD7EB3CA37F13ULL,
		0x97718ECD25FA87B6ULL,
		0x7CD1E86E3466AC8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D4FF9F8C70F69AULL,
		0x0DE93C031CD3183FULL,
		0xFC731FCA8BFD9EA9ULL,
		0xD0E61A95D7DF95E5ULL,
		0x8B350FDFA1204448ULL,
		0x0A9356B7308537B2ULL,
		0x8DDD7A64962798CFULL,
		0xC138432B2785513CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x260D1F7878A85AB1ULL,
		0x5F180C5E1C212121ULL,
		0x1FC271A1C310278DULL,
		0x41321746BA8978DDULL,
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
		0xFA081651016AC802ULL,
		0xB213C4F8170E787EULL,
		0xEFBF067EB56022E5ULL,
		0xE767FAE587981C63ULL,
		0x799DAB2F66AD584CULL,
		0x3478F3754B720E8EULL,
		0x6CB7061BB52EE98AULL,
		0x0EF18358E3986206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE18A6B810C03CADULL,
		0x69259230B3292869ULL,
		0x66E635A1686218B6ULL,
		0x0E169700C1ACE790ULL,
		0x2DA69EFF1FA07210ULL,
		0x5007B67930357E13ULL,
		0x5DBFE0E866853EC1ULL,
		0x59856FAA95123C81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x629B3EC37C94B6AEULL,
		0x31BD40336EE2C262ULL,
		0xC188567AFA2D6401ULL,
		0x475C4FC46DD4C693ULL,
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
		0xC8B721CAE64D05A0ULL,
		0x09DBAF5AA8195EA3ULL,
		0x1ED27D3A69A2E384ULL,
		0x42469233D23EDA55ULL,
		0x17AE041030D817A9ULL,
		0xDF6CC9A39EF8F925ULL,
		0x58359F0A3302FAF0ULL,
		0xAF26A87004202EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABFD05BD0DF12CDDULL,
		0xC5013EAEFDBDCED3ULL,
		0x995FEB59BC80F5D9ULL,
		0x29816BE5E8C9FC53ULL,
		0xF7AFC7B405E98E8DULL,
		0xAC9F9166B566816EULL,
		0x46EAD630A6DA952DULL,
		0xFFB7433240F10442ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC7711BC37C43123ULL,
		0xCF50C9B6561954D8ULL,
		0x168C622B7B2108A3ULL,
		0x234E2D78E275331AULL,
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
		0xE6AC034F24D34479ULL,
		0xD0764E06FB2F017BULL,
		0xD4D39922A30E3B18ULL,
		0x73736194258EC185ULL,
		0x7462EAAD12E74A3FULL,
		0xB9C596FB1549FF8DULL,
		0xE1EB07DE36F4567CULL,
		0x201BA952CADCB7F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E20F85674616E2ULL,
		0x5F3F75C13093BE9AULL,
		0x4F052B91F81EDB33ULL,
		0x0808DEAAFE2B5456ULL,
		0xC751D8EC10321DFEULL,
		0x36E2FD300657D0AFULL,
		0x342ED8448FD387EFULL,
		0x7620C4A231548BD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x645296702471BD62ULL,
		0xDED9AC6A028E37C9ULL,
		0x4FBD7E5F79CE08E6ULL,
		0x26A8751FF199FA7BULL,
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
		0x272B3BB63B5B1330ULL,
		0xA41DE11870D283A3ULL,
		0x4C5A4F68C6AEAB2FULL,
		0x8A24783B451E07C8ULL,
		0x4F7C7F3E5041F321ULL,
		0x1DFF8BC694CC9441ULL,
		0x9E6429D2082ACEA5ULL,
		0xB028A9CC6EBCEE07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC9407F4CC16EE57ULL,
		0x1263C878A5242E36ULL,
		0x7B6564748327390FULL,
		0xB77D524C5D9E8F01ULL,
		0xAC85D0B8FA5ECAC3ULL,
		0xD3822C8578324879ULL,
		0xF4031E3CC8D341EAULL,
		0x4EE2077C61588AA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B351B8C2EFC24E1ULL,
		0xA0563C4A0A95950EULL,
		0x1B5CA31BAA8655C7ULL,
		0x43233DD0E4663920ULL,
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
		0x1D9256FAE94C8AE9ULL,
		0x003B197000B906C3ULL,
		0xE40057FE3FE5F53BULL,
		0x73E8705C81A64F41ULL,
		0x2F31C03567F11498ULL,
		0xA92D58149409B791ULL,
		0x9CC81F91154324C4ULL,
		0x95421974DF337C8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9EF918934E959C6ULL,
		0x4D2A85CB776705EFULL,
		0xEB750011BD865EC1ULL,
		0x7EC5504C366CB24FULL,
		0x8FFC0436C8E20185ULL,
		0xD8128F5A54D2B9B4ULL,
		0x9496492C0FD03195ULL,
		0xF77146B1412B958EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC59CAD3D50A003BBULL,
		0xBD0A5F49EB7BAF92ULL,
		0x2FF12AEB516FAF6CULL,
		0x62226919C065E719ULL,
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
		0x7B7F5982F4070659ULL,
		0x9520E0D1C19214D9ULL,
		0xECC6AFE515A09C35ULL,
		0xC4F5C9CA625C342AULL,
		0xD5FCC49FB72D3D90ULL,
		0x635B144D181C0B71ULL,
		0x2B4D492B722C1808ULL,
		0xE7F80A3565FAAC28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D168D06A3CB4B0ULL,
		0xA34940B2F58F5D58ULL,
		0x5B7826053A3B550FULL,
		0xD3ACCB2183CFCFE7ULL,
		0x2A805EE3066B8DA0ULL,
		0x6B54E86CD9207123ULL,
		0x5FEE58FB2A0FE8BCULL,
		0x8BC4A8EE1F1B7D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56250AB4C68A714AULL,
		0xC2C22368255B9F2EULL,
		0xC166310A8F944C6CULL,
		0x20E96F3D63AD5B1DULL,
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
		0xD8C01B59886FB840ULL,
		0x8799E095F23B8C50ULL,
		0x9506020072302931ULL,
		0xA7B6B3F571E50AB1ULL,
		0xEF32A61BAF281562ULL,
		0x80DBB4DAFEC4FC0DULL,
		0xA265901EB78576D3ULL,
		0x72770065AD7D958DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B734A3FC38C62C3ULL,
		0x4A6D2FF816B27125ULL,
		0xA87C565FC86B91C5ULL,
		0xB77C06F5C3CF09A6ULL,
		0x7F713F3D5BA8B998ULL,
		0x99891442AA210761ULL,
		0xC2A2D276402AF7DBULL,
		0x6B9D029F32E37699ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1402161A29CAF58CULL,
		0x9370873A6BDF6CC4ULL,
		0x2371D2A261337038ULL,
		0x74965875E0F6993EULL,
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
		0x3642181BDC77EB40ULL,
		0xECDFB27A2DDE2A2FULL,
		0xBE054F6EBDB97BC8ULL,
		0x2F62E188BC1E4712ULL,
		0xF6F7178C63CDBE4DULL,
		0x6142F445737C3D92ULL,
		0x7692D011D7DC3DA0ULL,
		0x0A813E432824EC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44CCB804CC616FC7ULL,
		0xCA03185E96D7F95DULL,
		0xD4BB86628505157DULL,
		0x291C289D99348342ULL,
		0xE4053D406F392B5BULL,
		0xB6B212923671F68EULL,
		0x1A1465754CA1EC50ULL,
		0x71C381994FF2079BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC15BC75D5E244918ULL,
		0x745E1AB6A68CBB6CULL,
		0xA40D9C48E35C781EULL,
		0x3270BA213A77AD87ULL,
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
		0x6F285E854605A57AULL,
		0xA3D77F9432EB3A51ULL,
		0x3ADFDD88CA7E2081ULL,
		0x2612241156BE32C1ULL,
		0x2DB209EE55609E19ULL,
		0x01C4643BE3A12DFDULL,
		0x2A70077E5D3E4106ULL,
		0xC79E25D6BF3BA84FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56957FA4122A283ULL,
		0xDCAC3F64DAD06102ULL,
		0xA1065FE7B6D161B6ULL,
		0x17284C1645A4135EULL,
		0x474AE95E41D188DAULL,
		0xAD40F75647054904ULL,
		0x8B16F27C439FD14AULL,
		0x661E50203349976EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD0DDBEDEC202C78ULL,
		0x52AD6A44973ED640ULL,
		0x41129BF0E1315499ULL,
		0x07E39113D708A0BAULL,
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
		0xE043E2B3E326C881ULL,
		0xCE718CE436D09F68ULL,
		0x3C99E5A4E9F9BEB2ULL,
		0xDB9915CD5C904001ULL,
		0x623546B2C73EBDCBULL,
		0xE830A23B377CE77DULL,
		0x9F1D73AABC1EAD83ULL,
		0xC6B1BABE11834047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A48F4D271D89E32ULL,
		0x291A858BC663FE25ULL,
		0x44E9B00002D9206AULL,
		0x5D410F89EFD92358ULL,
		0x9481A274AF1BD55BULL,
		0x25CEFCE27617B301ULL,
		0x48E04E2FAE637531ULL,
		0x9DAE6B189BD62C54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEA54F19067CABE6ULL,
		0x7FD5928525726BA3ULL,
		0xC4C3C5E8F0EAFA91ULL,
		0x14D5D8D2E46812C7ULL,
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
		0x7545F7AE706906CEULL,
		0x14CFAB58329079F1ULL,
		0xA68973948A82AFB4ULL,
		0x7D3B5A749E1EB5ECULL,
		0x7A85D52A3523DDA1ULL,
		0xDDB72D5B730210DDULL,
		0x6668D1BFE8923857ULL,
		0x36D4E49D02781A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A500AE720FB533DULL,
		0x6EE7608D9F7FF4C4ULL,
		0x345910979B989768ULL,
		0x26D39EE1B6D4CBD1ULL,
		0xD43D870CE3550155ULL,
		0x5A013D7DB678283AULL,
		0x96B80C6EE264A758ULL,
		0x936A45DD6351448FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9B18521742264D8ULL,
		0x32E9E5B48F890D51ULL,
		0x466DAD03D9AD9E39ULL,
		0x183B4C04870DA908ULL,
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
		0xC83D5A8DEB2934D4ULL,
		0x088C1CB042E42582ULL,
		0x654A4878B65DE862ULL,
		0x8696D663B053762FULL,
		0xAFB30ED5522202DDULL,
		0xBAB3B7B0199F88BEULL,
		0xCA1D137C24A03B06ULL,
		0x4DAA2E153D7801D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79099B797A604649ULL,
		0xAF3600D16C64B1FAULL,
		0x3D56EE1D11FAFEA7ULL,
		0x95A1AEB24F0C0206ULL,
		0xDE87C56E1E1C4436ULL,
		0x8BBF28C8E1843EF4ULL,
		0x1244B057CC5A9C98ULL,
		0x97F064996A29A199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BA0A46629A339A0ULL,
		0x51A352312A8C677DULL,
		0x721211C0BEB86E15ULL,
		0x6A891012BEE9BD2CULL,
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
		0x74FF9B42300699CDULL,
		0xCFCBD9F691198991ULL,
		0xDC98E1B7A4C70A30ULL,
		0x067BB9A800B678A2ULL,
		0x62EFF12B834AAB1AULL,
		0x38CD8AF16E449BD6ULL,
		0x5C09AED79B32AD5FULL,
		0x3EC18ECE53CB8C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA917D0D9FAE0A7F2ULL,
		0x51CF7BE9AAE0F437ULL,
		0xE440E3F66D4EA2D5ULL,
		0x3FC945C0CAAFD577ULL,
		0x1C7A23012518D27CULL,
		0x27591511E9F01F59ULL,
		0x7DC3E7BD4F8EC70FULL,
		0xDE3303DEEDF27BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x416464B2308C15BFULL,
		0x1545DD3A8AC30FF2ULL,
		0xF6B38BA871CC973EULL,
		0x1BDB1370543F139FULL,
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
		0x6B3B0D50562827F5ULL,
		0x3D9482AFEA1A90F3ULL,
		0x98293D10AFFD3695ULL,
		0x18048638E9050353ULL,
		0xE46332DC6BA5D146ULL,
		0xD9C9E4B471A9AD77ULL,
		0xF7728EC5AEB981B2ULL,
		0x122E74957925C5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x866C8E10E281F47AULL,
		0x1B2BFAC2C6DF62D1ULL,
		0x66C5680150052B59ULL,
		0x5825B89D11F6EF88ULL,
		0xA32DB0EC3A312572ULL,
		0xC12072ADCE13F0E1ULL,
		0x0D1A13488288D2DAULL,
		0xD0980B7A363ADDEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92BFC8E6CAF7B0A5ULL,
		0xCB8F74E96B752C6FULL,
		0xFA8629A3EF31FF4FULL,
		0x7C3267A7C5EC832FULL,
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
		0xA484303AFA01607DULL,
		0x8534E7BF937F09CDULL,
		0xC8FA3D5725A89754ULL,
		0x27EC175AD02CF95EULL,
		0xADA712018B728451ULL,
		0x76A7AA2ADE206D73ULL,
		0x50C35AC2D14A5536ULL,
		0x9539624320A418ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17459487EE4FF8C1ULL,
		0x171B2E520A30AD4DULL,
		0x5C5F48D7B582B314ULL,
		0xD6A189D89F7CB676ULL,
		0x59F476B9B296770BULL,
		0x30E107D2BA318994ULL,
		0x4735F04C03435D8DULL,
		0xCB340F9C52117926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9C1A85D3C5B5ECAULL,
		0xC995D282DEC42FA6ULL,
		0xD798C222052EA760ULL,
		0x4E14D244DA73F0CDULL,
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
		0x115B11788806B3F0ULL,
		0xFBB2EB5EA7C787B3ULL,
		0x372BA6983820586FULL,
		0xE5B176662064203EULL,
		0x85A1A6F58AD54FB8ULL,
		0x22DBFB99687702E1ULL,
		0x7F7675AA391EB690ULL,
		0xE98109B2BC6BAE93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB842A9CFBCB87571ULL,
		0x3A96747D70F9E413ULL,
		0xDB6D32947728B7BCULL,
		0xAA7874789B64826BULL,
		0xFE43296F414C3D04ULL,
		0x9A073AEDF2031E49ULL,
		0x549E1A2783817943ULL,
		0xDF4B7CB77F312D07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x711F0997B5A70570ULL,
		0x10B11054CC01921DULL,
		0xB7DC096AB64EBA10ULL,
		0x3F2BEF389BAED8A0ULL,
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
		0xC142FEA4F37F4FB7ULL,
		0x61E29B89EC8BDFB8ULL,
		0x2F5F85AD8EB3C3A9ULL,
		0xDD8C276A07784B2EULL,
		0xE2729B1B525B7230ULL,
		0x18C7EFA6491DC153ULL,
		0xD18AEC5342070BA8ULL,
		0xAD8B7D4604DFE542ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D16D877A1D2C1C5ULL,
		0x1C89ECC428192325ULL,
		0x4879DB758311DD0FULL,
		0xEB10070415772868ULL,
		0x7E21142EEF558598ULL,
		0xC36CEA5FDFEB500AULL,
		0x0F6C25B8A8B80D89ULL,
		0xCB52F2BF4313E527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68462D44048DABD7ULL,
		0xF0DB773961EF8D78ULL,
		0xB777252ACD5B9F1AULL,
		0x06E0B066B64926E4ULL,
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
		0x6FCBB42E3252D755ULL,
		0x330CB514A46622B0ULL,
		0xE5F175947EF92A0EULL,
		0x6E9619C8F8B2EBBAULL,
		0x2269F777583D17ADULL,
		0x0D5C9070D57D292AULL,
		0x58D6535C42103773ULL,
		0x494020E78AD90B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABE4BB92FFF8E081ULL,
		0x75FFB6ADE929C4A4ULL,
		0xE667A15D14067972ULL,
		0xE65E315D82D7E3B3ULL,
		0x62CBC52E0211DBB5ULL,
		0xBA1C97738C7B92C3ULL,
		0xD4C0D9CE88C6B4ECULL,
		0xD9A6A1E901FF821DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35626F7DFCC4DA60ULL,
		0x188BF3FF9178B14CULL,
		0x9AB9DF40EBDC108CULL,
		0x1900C233C6255C78ULL,
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
		0x22C682476D2569ABULL,
		0x264EE734F27689C6ULL,
		0x6227C5001715E426ULL,
		0x0541076960975A29ULL,
		0xA56681302188184FULL,
		0x40B008C193E0FE7DULL,
		0x7B2E4F85BB7A2AC3ULL,
		0x684CBF549BB8A58EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0DA5F36359E7ECULL,
		0x32C494F468DA995DULL,
		0x06383AE5AA1B5000ULL,
		0xB58EC96710CE8072ULL,
		0x70064C502C2C509DULL,
		0xFCECDEA7AF039365ULL,
		0xAAE4ED6C949EB369ULL,
		0xF8239AC5EE344BCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6200B592756B22D4ULL,
		0x028292188279D600ULL,
		0x46D419D6318E4B66ULL,
		0x75CDAB30116E2C30ULL,
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
		0xEC0DBA1C32EEA808ULL,
		0xA39F7680DB8D4133ULL,
		0x1D8DAB74083B2198ULL,
		0xD3DAF4BE969424BEULL,
		0xDA05424E49D3C3A5ULL,
		0x1425D4AB2D61E8EEULL,
		0x8A26CEA9FCD8CBA6ULL,
		0x1331FF7314C71448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB640CAA0AFC6E8AULL,
		0xC477E2C949E8AF73ULL,
		0xEA986EE29AF1D3E1ULL,
		0x33694C6F3C561958ULL,
		0x76D0E0C138A65E6BULL,
		0x741FB41D5900CECEULL,
		0x171E359272712ED1ULL,
		0xCBC9FF102A38EF3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA702862B4AF3C18ULL,
		0xA01068C5180E728EULL,
		0x463BF60FF8AA9546ULL,
		0x39E1B6FE2B578B64ULL,
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
		0xA40EE30933A2F13AULL,
		0x61E002D0E39FF4C9ULL,
		0x269894EE83C62563ULL,
		0x7D9E91B86D16DD8DULL,
		0x69429FCD81B8C176ULL,
		0x7BE71EE6B4AB602FULL,
		0xFA1C0771276DB81CULL,
		0x3F56C25968E6F193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63107075AAC0499AULL,
		0xF6D3F498AE60C410ULL,
		0x2E0E1B08AD794D5BULL,
		0xEA0E4DD479D08BADULL,
		0x0CDC834F53F63970ULL,
		0xFD0C63A576A5D001ULL,
		0x81F679602B4C37B7ULL,
		0x6F52363CA63F66F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF826AD4E53C2D754ULL,
		0x3F83D9E76A12979AULL,
		0xCE1D906B4345E6F2ULL,
		0x743D1028D824E53FULL,
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
		0x1A7E96692EA6DC86ULL,
		0x50C8EEBA8863E333ULL,
		0x2B3BFCAC4FD0ADE8ULL,
		0x0C13070139CD3903ULL,
		0xA8F749FA20C2CFB6ULL,
		0x12D1F8B4F119CF87ULL,
		0x5F8A0FEF3D123569ULL,
		0x95374686F21CF5E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18DCB3E35AE67EBULL,
		0x8124BE368A5BA91FULL,
		0x103CF63DE6C37B6DULL,
		0x568DD85D8C38E63EULL,
		0x038F79E5226CB488ULL,
		0x53DE32F97B868B1DULL,
		0xA067BDE13C254C56ULL,
		0x3AA1EDE500418E50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0659AE48B9C07F5DULL,
		0x27D38A5771E461E8ULL,
		0x7A1734828C37CB43ULL,
		0x27B056AD9425B267ULL,
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
		0xAF1A67F2ABD1A7ABULL,
		0x4BB4BC863A7A8348ULL,
		0x7C7571B14C485B5DULL,
		0x8BC704EF3DBC9C89ULL,
		0xFF2466BAB8BD3DE1ULL,
		0x12C89F72E1402F1EULL,
		0x55842FDED9C07FC3ULL,
		0xB5D7B798172607BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C592F3AD66C510ULL,
		0x4B7424C06AE8E8A7ULL,
		0xC297C20F12B8B0CEULL,
		0xB3241967B9E25579ULL,
		0x1AF9737CECE11147ULL,
		0x7B15894CA301BC3AULL,
		0x15C2E02416B4F1FEULL,
		0x63EBAE3946D5EBF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27B4F02B4119833FULL,
		0x84D5E1730CD6A89BULL,
		0x308F855B2D46B5BDULL,
		0x01AC4F9A6FBE66A3ULL,
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
		0xFB69A7276FF018D4ULL,
		0x0C178D0EF76F7D87ULL,
		0x363869EEE5C34392ULL,
		0x4ABE48C9442A69F2ULL,
		0x1B738F1FEE94D91AULL,
		0x03D7AA3C3DD62A0EULL,
		0x31ADAA07F5FE4266ULL,
		0x7AFD714B3507DFB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A2782B04394139ULL,
		0xD2FDC5A67FC64DA3ULL,
		0xADCFA88D4B79CF13ULL,
		0x4BE23081468130DCULL,
		0x0D37E3F10D60A6C6ULL,
		0xCB417957935C40B1ULL,
		0xC9B080FD7B2701FEULL,
		0xEFE98B23104EC985ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEA297F1D9764D7AULL,
		0x9F650959C5C1D3B4ULL,
		0xF7FCD8EFD63D03D0ULL,
		0x23D0423D712283F8ULL,
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
		0xEA6F4EE3AFDA73A5ULL,
		0x3FAE51B3F94FB538ULL,
		0xA7D0DDFEA7DDFF04ULL,
		0xCFBA8789F5517E3DULL,
		0x65D66FEA3AB8D4ABULL,
		0x8FC50323DCE7E932ULL,
		0xF1EE46A531A8E5C3ULL,
		0x230233D2A870A884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73B52A5609E491FEULL,
		0x5D1FF1D6E0C42C0AULL,
		0x1728E03A101AEA07ULL,
		0x7B530B03C1DA7A1FULL,
		0x5A015BF4BF99B7D2ULL,
		0x6C6FC2AB57159F82ULL,
		0xB2FC47008D412330ULL,
		0x76AFF1A9961F001FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x385B1AFDEC942802ULL,
		0x2135F1C0F5C27950ULL,
		0xE893F034FF29F6D4ULL,
		0x689D4E9EEB960325ULL,
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
		0x5F6BDC2C7594AA80ULL,
		0xAF1D61EC091039F4ULL,
		0xDF26301832815FB2ULL,
		0x86CE0ACD2ADAEB74ULL,
		0x09D8CE4693B036CDULL,
		0x14F51C861468A376ULL,
		0x620CB6F22C0BC4EBULL,
		0x9A2C0E32A8B28747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE7893F1BCBEC01ULL,
		0xA56C81FF6F7BF7A9ULL,
		0x9E101F8B3C89373BULL,
		0xA7BD643D9A262289ULL,
		0x1FA18F77B2F9D9B7ULL,
		0x3F2F600D3E7A18ECULL,
		0xC17CB65A2F77860FULL,
		0x2640BECEF4F6BB94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57B7A5A2B4DA9249ULL,
		0xC50AD9DC5AFCD2C3ULL,
		0x1676271C73F97D18ULL,
		0x13FE6F5C3E95056FULL,
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
		0x2ED541F21AAF77CFULL,
		0xC981C7B515D89283ULL,
		0xB66266EB3829A135ULL,
		0xB81ED3E1456B1228ULL,
		0x0B3918281A8AF7CCULL,
		0x495AE42F9116751DULL,
		0x8305836E860EC4EAULL,
		0xE5D3C3C35672814BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x083B8292C8784172ULL,
		0xACD6119AA07AB30EULL,
		0x0F68AF999617B241ULL,
		0x214203D2907896E2ULL,
		0x37F17A5773EA24AFULL,
		0xB588998272F8DA08ULL,
		0x2DE15172D2913702ULL,
		0x4C369AEF9AA2DC4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x833B2C580E169015ULL,
		0x0DE2CBCCEDC2E48CULL,
		0x4A5922AE46B4FF54ULL,
		0x6430DF7C95C4F979ULL,
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
		0x4246F6193590D123ULL,
		0x3B2564057C377200ULL,
		0x79EB345AEBF27850ULL,
		0xEA7FA207DF8DDDEFULL,
		0x9F5058156715E3A4ULL,
		0xAF41BC3DB69F242EULL,
		0xCF834D163BFB13D2ULL,
		0x122373F26F848D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE4AE6FCC568CCDULL,
		0xA7A59305833D3EB3ULL,
		0xA5FE8CC09A9ACA48ULL,
		0x406C96B764EA56D5ULL,
		0x128AABF852B8F0ADULL,
		0xDB7ED57F902BA4B1ULL,
		0x9FB069C48C090842ULL,
		0xD81542C4E5C09687ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAB9D3FA6F0650B2ULL,
		0x026E1139AE1F1FEFULL,
		0xED3A65BA6F456561ULL,
		0x482E5812EDBA2812ULL,
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
		0x393A076CB362EC95ULL,
		0x749C6C898E5F3B98ULL,
		0x91731CE55D8B008EULL,
		0x51F49AFF3773A6BAULL,
		0xEEEB64A12E8275CDULL,
		0xA194467559C07DF6ULL,
		0x36358BDBAFE02C23ULL,
		0x1A3154857BBA5AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0618D13FE71C200ULL,
		0x0E4B9A74C029D07DULL,
		0x6E8507B3F48B0BBEULL,
		0x3968DECCBF279DAAULL,
		0xB15361FCF2694C77ULL,
		0xD1653D41E5E2955DULL,
		0x5B11DDA22C97341CULL,
		0x207FCE2B697F6811ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D68DEB9A0AD4D33ULL,
		0x4D4C2FB80125F1D9ULL,
		0xAA39F1BAE5D4C5D3ULL,
		0x28E5AD912D0C0D3CULL,
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
		0x17E721275E79E746ULL,
		0xEB8012D12E302B2EULL,
		0xF17AC116089D0747ULL,
		0xEFCD5CFB2D323D0BULL,
		0x5E2C722F1C10FF02ULL,
		0x7B3EAA155C2BDAD5ULL,
		0xAE0131DE208C8FD2ULL,
		0x9454018506D1808DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44FC89EFFE71ED9CULL,
		0x351735CF54DDB566ULL,
		0x918872C39949D802ULL,
		0x85B9653A423DC88FULL,
		0x86FC79F0A418ABE0ULL,
		0xAEE3E97761A77815ULL,
		0x6F5B9E959279C947ULL,
		0x1D94EB3E8B4D89CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC409707D2EE45362ULL,
		0x0BE1747508F91E41ULL,
		0xAC862B17861CA7E0ULL,
		0x0A714637408B14DFULL,
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
		0x2F867CEA50B6CF80ULL,
		0xA1FAC758FE0F79DAULL,
		0xD5ABCA4D40674764ULL,
		0xC4CC625823C33811ULL,
		0xBF2F3CE1EBC9721AULL,
		0xB1ACD174E90E7DD2ULL,
		0xFEA75576A71DC4E4ULL,
		0xFAB21673A0ABD3A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A29AE221BD13459ULL,
		0x5E953D611642B4A4ULL,
		0x5FBE11293648C68DULL,
		0x906212F60CE82D09ULL,
		0xED5F1C4EED15932EULL,
		0x92799197488B6C9CULL,
		0x0F826003DE551B14ULL,
		0x9B2901D54D433BA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A41A49A0398B443ULL,
		0xE50104DDBB415333ULL,
		0xF56A282DD7E7B5BBULL,
		0x62C35EE2786199FBULL,
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
		0x243E8928ECD7F2B0ULL,
		0x75B92C11ED6A0E44ULL,
		0xE7E8EB33EEE3BA2DULL,
		0x0BEFB9904F28FCFFULL,
		0x92BE61CC0A4A1E3FULL,
		0x48D92B3D0EB61B19ULL,
		0x468576E3EBA52795ULL,
		0x29A50D6FAE3452ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F24DF33152481E9ULL,
		0xE21F5AC0CF5CFCC7ULL,
		0x15F3F989DFED6E48ULL,
		0x81B22EC087C516FBULL,
		0xEB81016AA0468860ULL,
		0x3B5942A2EC65DC2FULL,
		0x47F4ABA1799D0FF0ULL,
		0x0E5B1FD3F0FDADF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC835F86B943BB066ULL,
		0x9496583235F6682BULL,
		0x9B731D86FC29CE64ULL,
		0x1736CFEDDD8058BCULL,
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
		0x15344E52ABF0990DULL,
		0x91777BB29D39CD48ULL,
		0xF25D54804E9F59EBULL,
		0xAEE48CFF37AFEE59ULL,
		0x2433931C48C6222FULL,
		0x046195061C01B3DDULL,
		0x4BFA455621AA297CULL,
		0xB8DD1068BB20B9DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E08D293DEFBA2C9ULL,
		0x3377301B39BC10B3ULL,
		0x8D20C27F1B22A14AULL,
		0x909F656017C51440ULL,
		0xF75851513F0D1667ULL,
		0x5715E58B131891F7ULL,
		0x9C2540231DA4B23AULL,
		0x54714A23E8ED6872ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FB73FE23E6CB82EULL,
		0x173C57DAB618C499ULL,
		0x7EDB5793CC4C6C61ULL,
		0x064495D65388EF7DULL,
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
		0xC2D79366E900AB40ULL,
		0x693C75CE4DF88F6DULL,
		0x6DB4A422E693A73BULL,
		0x114E4313BB84297EULL,
		0x665C575EA58F87C3ULL,
		0x8EF2B7EE52B7D179ULL,
		0x2A3CDEEE087D117EULL,
		0xCFA6B1F7FD8E56FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE30B7E1CB419E6E4ULL,
		0x605CFCAD90925423ULL,
		0xF443B5EAAE4301B1ULL,
		0x60B808A5B90213FFULL,
		0xCF8965EA46AEAC15ULL,
		0xC549B5FCE5D1A9F7ULL,
		0xB18BE3D6B8E91721ULL,
		0x36DD6E717282BFCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x431BEC904A476374ULL,
		0xF7F5C2F6E7901886ULL,
		0x63B633AE0847CF4FULL,
		0x5E764066A63A863EULL,
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
		0x10272C02A5B93B06ULL,
		0x1E615CACFE0446A9ULL,
		0x6F16A315AA5CC6B6ULL,
		0x575A132DA9CC57CEULL,
		0xADB156ECC4381A4CULL,
		0xF0A4C8EF26E2B91CULL,
		0xF4F5EAE555D2DA35ULL,
		0x807C298BEECDC6B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8857B2BCE785B36ULL,
		0x769865C437A9A980ULL,
		0xF7CBCB14C808DB34ULL,
		0x8C64CD78DFB0BF4CULL,
		0xA1F103A4942B063BULL,
		0xA6675178FAE02843ULL,
		0x9701F0B613617630ULL,
		0x0C1A30A9255DD2D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x262E0D8DF931DCDCULL,
		0xACE8B2734EBC1D60ULL,
		0x6981FB04BF28C44AULL,
		0x1180375EB0B9CBA9ULL,
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
		0xED0094A892CBA9FCULL,
		0x750640FEC4F04C91ULL,
		0x8EB1457A8AD59870ULL,
		0xF7ED9C35045CB303ULL,
		0x1BD22CB61B287D85ULL,
		0x30AF431EEFE3F705ULL,
		0xB138CE6D5CB9DAFCULL,
		0x0A5831B0D92D51E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA4697735840404ULL,
		0x9B1EDF5038D394CCULL,
		0xA22404CF282864BCULL,
		0x814F8C1CDE0A5369ULL,
		0x689C04CE09E2DB20ULL,
		0xF6F8A8874BDC736AULL,
		0x60207B574C301EFCULL,
		0x85E826DB5539BE44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC6617A3ED9DBE4AULL,
		0x6B025430E53A40BBULL,
		0xF62995F1D71F1B96ULL,
		0x1F3FABC9BC7A48CDULL,
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
		0x50299A15326EE0E4ULL,
		0x833CAB7B8B70689BULL,
		0x628B1693E12E55A9ULL,
		0x16933BEBED327D9DULL,
		0xB46BD4A5F9192F5DULL,
		0x302DAE1E64E7E73AULL,
		0x9D7248B208CA4C67ULL,
		0x463FABDE1177E872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF340F07D03E46D00ULL,
		0xA9390E960502F9B2ULL,
		0x76D667E616B1D641ULL,
		0x7EB0DCE4325AD923ULL,
		0x8E0B9DB136A7FDBEULL,
		0x7575D180306E681CULL,
		0x49E0AF96801F22BCULL,
		0xBB7D0430BAB92DB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F30D1ED0B57CED2ULL,
		0x914E5C6150764D62ULL,
		0x535168C413E4AEBFULL,
		0x30C742C29B275CE0ULL,
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
		0xFD9A528CC6D98480ULL,
		0x4873CB487D2A8731ULL,
		0xE40A0A116CB9440EULL,
		0xB649FB3723B80664ULL,
		0xFCEC573D6CD6BA95ULL,
		0x99B8E5E1EDDD49E6ULL,
		0xCA8679C87F979279ULL,
		0x2E78B20550781788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D64CEBEDD84F00CULL,
		0xB30BB65EF1466A1DULL,
		0x76980C94063FDEEAULL,
		0x1B0239C08D29A6D2ULL,
		0x520356B12028B7F1ULL,
		0xA535A668D686C330ULL,
		0xA9774D536C11453AULL,
		0xC387AF7DD526A323ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEECB98A14B28F588ULL,
		0xE0E380E302BC1C31ULL,
		0x55B296DE4C68DC7BULL,
		0x7B0E2192E4A5A695ULL,
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
		0xC4DE20BA8B1AAA7DULL,
		0x7031494A62E7978DULL,
		0xBEBD68D1C178D50CULL,
		0x5A92DF7AB0CF6E4EULL,
		0x3BB5E183BCF034D4ULL,
		0x88E46433C99C9CC2ULL,
		0x1473C000C6469711ULL,
		0x8781B74CE149C27FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4175112E611CDCULL,
		0x9753807666A9885FULL,
		0xD8D548216D953C54ULL,
		0xBD071F137ED5D89FULL,
		0x2930A11DBA8879F0ULL,
		0x4426EF30147F5EABULL,
		0x189215EECAB7A27EULL,
		0x0873DD98A20901A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A643ACDB81F4E25ULL,
		0x0CFD2760DE95469BULL,
		0x49675F5BAB1BE694ULL,
		0x799A1128959636C8ULL,
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
		0xD2A44EE2CA8F7E4FULL,
		0x07A53DF615E585D6ULL,
		0x1D8BD702FC614F25ULL,
		0x891C50AA60613FA4ULL,
		0xDD64992CD08D8A87ULL,
		0x26EF91C38392C2E6ULL,
		0xE700B28712B6669EULL,
		0xDDBD1C10E250E7B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x618BB5AE3090EB40ULL,
		0x78E4ED073680C3E2ULL,
		0xFD28A7BBDFF93902ULL,
		0x22C29BBE2EE0B098ULL,
		0xBA1BF8F5E09B0BD6ULL,
		0xB76D68157FB9FB66ULL,
		0x663644A0BA212374ULL,
		0x1D031E4F83A20229ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADE0615C37FD65A3ULL,
		0x1C1280C371925EF9ULL,
		0x3E6F7F7842900E49ULL,
		0x01F55FA03F76A174ULL,
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
		0x7D488F96DA0CBCF8ULL,
		0xB1BD2F2D89ABD0C3ULL,
		0x66834E5685308A1AULL,
		0xE2CBF1ABD569C1F9ULL,
		0xE3DCB1BCCF6105E2ULL,
		0x422AF99861AB48D9ULL,
		0xBE2E31A3B9B7FC23ULL,
		0xD150F02BE17617B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A57E75EEEDE9A2DULL,
		0x4BDE831B415F1A44ULL,
		0x83E7420F6466BC76ULL,
		0x4EE33BDA185394A5ULL,
		0xA59EBD782F56B645ULL,
		0x10B48DC526E2E733ULL,
		0xA4F4A44C64D7627BULL,
		0x6894367E2B226F43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA022EA67ACB5F679ULL,
		0xBD72AD6D020B352CULL,
		0xA127073DBA209C9BULL,
		0x1FEC459ACD812DD1ULL,
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
		0x512532A2EFF7A5EEULL,
		0xB7F25EF339381F77ULL,
		0x0E2C543B45454CC3ULL,
		0x5F8354419E68E7D1ULL,
		0x50058B0B689D8ABDULL,
		0xDAF01CD8DEE3F68DULL,
		0xBBE8497E9316EFB9ULL,
		0x00D2A9536642B8F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B0120B0A782B15ULL,
		0x98808E26A2DC4ED6ULL,
		0x28B14B7C770307D5ULL,
		0xD2B0F0B493291F6EULL,
		0x2AC60D7F761FBB18ULL,
		0xC9B57945D68D336BULL,
		0x4230EEC7EEC3D5BEULL,
		0xFAEFDE7EB5078196ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3E1C35DE42C47B3ULL,
		0xAE26189FD33CC7B2ULL,
		0xF6B27FDB32982032ULL,
		0x6C7C7F1F5A0A0126ULL,
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
		0x5F0C900D3F2EAAB5ULL,
		0xD9B7F913B5B5208CULL,
		0x8D1CD6637E14B4F1ULL,
		0xD265F3EA2A72F13DULL,
		0xF41FACA7F7AD915CULL,
		0xBB81CE0FF8671453ULL,
		0xCEF213E24911CAE5ULL,
		0x22D659BA7B0D4F1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD09033E8E08B4BBFULL,
		0x6C1842DB0DA1D78BULL,
		0x9A60BC1CF1A85184ULL,
		0x533F06E69E053FECULL,
		0xB035269B865F99F0ULL,
		0xE6046E5CC12E5920ULL,
		0x1AC293173463D9C7ULL,
		0x22F65DDF833EAA45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA34C41FD303618FEULL,
		0x1E3BEAD2DA7F129CULL,
		0xB1C9386B9E3E2DDBULL,
		0x7A664F84551A29A1ULL,
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
		0xDD99748C7B337272ULL,
		0xEBC9692B02B29BC1ULL,
		0xCD3DB4B66C132964ULL,
		0x88CB789FB7598B1EULL,
		0x9B5A9EFDD60A33A4ULL,
		0xE25DCBD70240DADCULL,
		0x669831A7C8BF9698ULL,
		0xAA76A9683E4AB4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB59FBED24E2808ULL,
		0xF7C172F97CE94B0EULL,
		0x50AA352C15476630ULL,
		0x1ACE991C768A8FC0ULL,
		0xA15CE76E22579900ULL,
		0xBCFE36F5BE264828ULL,
		0x634A19991B846574ULL,
		0x993BF9BFB7A56D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A8D142255683F21ULL,
		0x80380FA1A1BB176AULL,
		0xFA2B11B80D950E91ULL,
		0x7CB2F2873D5795B2ULL,
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
		0x5C8F32E36E5631E6ULL,
		0xD57ED7299866FBFEULL,
		0x6BDA4AB02A9DBCFCULL,
		0xC8C57942E3A8EBDCULL,
		0x4041EA79CA8A2F42ULL,
		0xCEE9DF638A6FA1AFULL,
		0xA0F9792A9AED36A2ULL,
		0x745C9239C28AD0E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FC679BFA4632F43ULL,
		0x34902740ECB40F63ULL,
		0xD2EB6297F953BC1BULL,
		0x7168372643ABC249ULL,
		0x28AB10CDB542567AULL,
		0xE428EC0C7216E398ULL,
		0xA02DF0EF253B2007ULL,
		0x7222AB0FCD927114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD2D08AEF29D3066ULL,
		0x7992CED648DF2408ULL,
		0xB72520EBA9B95BE0ULL,
		0x2BF59256FCDB6298ULL,
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
		0x5BE39E2090C83A16ULL,
		0x9F401727A7B51E6AULL,
		0xEE74B6A985850D2BULL,
		0xF52442DF0F8184CFULL,
		0xA9A9EA6719B555D5ULL,
		0xFF0A430A23E60744ULL,
		0x0FF833064C329E20ULL,
		0x388049129036B961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79372793F5CDB9C5ULL,
		0x5802BB1B875418D3ULL,
		0x00479994D221DB39ULL,
		0x932122CE299FA8B6ULL,
		0xCAC28936823AEA69ULL,
		0xB7B8A501DC06402FULL,
		0x8D1CF21152F327FAULL,
		0xB30D09EF291004E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF904E3C317266FADULL,
		0xDD5AD146CB9892AFULL,
		0x5AB8C171B2CEBBA0ULL,
		0x311E7F5235A0A649ULL,
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
		0x419230CEF38D1F2EULL,
		0x408A336557FBDEEDULL,
		0xD8C4D2E078FDD7DCULL,
		0xE89CB63908618E0FULL,
		0x8B504BB3C59CC75BULL,
		0x71239FF6FB57FB01ULL,
		0xCB0995318DCE2083ULL,
		0x57152815FE269B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C800925EABCFA9ULL,
		0x96C0CA82C50C9E5AULL,
		0xB8E2C135C4FC01E3ULL,
		0x7859D59AB0DAE20DULL,
		0xF89A94CB81BAD73FULL,
		0xCFEDC79D66F4CD4CULL,
		0x5C3BB013DA356205ULL,
		0x0303F3994DA8B199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6C356B6A86AF588ULL,
		0x97C7862E99A80960ULL,
		0x927214135CAE1C9EULL,
		0x6AD0AB208A37645CULL,
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
		0xF1AC59DD302B5A0CULL,
		0x938AE16E1BCAFB8BULL,
		0x03258C577BE5446BULL,
		0x48933EFAD1925D70ULL,
		0x0EB03B9231BF8DFDULL,
		0x50F032EFB6F4FD74ULL,
		0x320C560B44816236ULL,
		0x29A78941AD186874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91D6526F9E6B909ULL,
		0x813DA66ABFE86F9BULL,
		0xA905AC61984857C5ULL,
		0x63A4BBF059E9351EULL,
		0x77470E6AECCB47C0ULL,
		0xAD5514A17AA0D08BULL,
		0xC6E3E99E35E14FCCULL,
		0x597F2396303BD9EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA22BA88A72870CF4ULL,
		0x5B53BAA050613676ULL,
		0x421FF8260F5FA854ULL,
		0x4AED9A7F00665091ULL,
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
		0x27C474C82BB43DD9ULL,
		0xB098D9323EF543DCULL,
		0xDDC412F098B65F06ULL,
		0xD1D71D987D0B2186ULL,
		0xCDB5593DDAB87A83ULL,
		0x51487714003F8322ULL,
		0x501AA8DDB861D868ULL,
		0x6B2E1DDBB7E53CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B5489CB6EEEDD0ULL,
		0xE73ECAF4B80CBF3CULL,
		0x8C03BACB7CB72AAEULL,
		0x18EFB4E43BE98031ULL,
		0xEB7C671D1419CACDULL,
		0xDD558E72C76C4E67ULL,
		0x24D9A322CF1E79EFULL,
		0xAD5CF91008A37F48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA831D08F05363A4ULL,
		0xFF68962BF642585DULL,
		0xBD6731E3BBFF3A38ULL,
		0x65F2DEF044E3C33FULL,
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
		0xCA5D7A28D0C7675BULL,
		0xB4BC63797B9E42E7ULL,
		0xFA0E0A2BD5F091A2ULL,
		0x0AD6047BC7764989ULL,
		0x4E3C45103DBE32E5ULL,
		0xCA873CBAE65ADB0BULL,
		0x3A6941573D4A2C93ULL,
		0xFA4E17ED6625BB8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26111A7CDD6E9909ULL,
		0x6A35BFEE9BD849EAULL,
		0xA277A90705AE90F4ULL,
		0xE2F11C6F243601A5ULL,
		0xCF3E4C2AA337735CULL,
		0xA9BB0C58748E1445ULL,
		0x7DB9EB40F20E43F3ULL,
		0xCE3DA20FB32DAFF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DFF51C0E3593D79ULL,
		0x28D5D227C42B7A4EULL,
		0x599D2873FB268873ULL,
		0x325666F5341200DCULL,
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
		0x8C2D6952A85190AEULL,
		0xFAEF8703598FE763ULL,
		0x61076DBC1720A188ULL,
		0x19EBD8EF220979ACULL,
		0x1BFB32E9C30E40F6ULL,
		0xB10ABC64F8CFDE5AULL,
		0x5EC8B0CBBE6BFE80ULL,
		0xCA4F33A6B803FE46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA5225F8FE1B763ULL,
		0xBD2563118F689019ULL,
		0xA45267FA3ECE27CDULL,
		0x16C161C73F5330E1ULL,
		0xE7668AE11AA2A896ULL,
		0x421D87E5BC6799BAULL,
		0xEFB9FD96F34610C9ULL,
		0x7C99C3AA8D65F890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C99383C18687940ULL,
		0xB4FFEED4C1A186ECULL,
		0x38E39F97FFF3C2F5ULL,
		0x0C191696362B21B9ULL,
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
		0xF03D5F1AC40BB3FDULL,
		0xF5D6F71FC56ABB01ULL,
		0x1F5BD47DC5E1F782ULL,
		0xEB0AE0E1471CDDE7ULL,
		0x4670A9F8A460841BULL,
		0x4521C1A31E76F7D4ULL,
		0x1B403C873294BEE2ULL,
		0x978EE50B2EC08D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9FAEBF359240712ULL,
		0xA6284EBEC51C485EULL,
		0x223074D2A4381FC2ULL,
		0x7F6255516814E70BULL,
		0x58AE0BA6FBCB749EULL,
		0x89520C75DCAA0690ULL,
		0x0FE2F3ECFAF6678EULL,
		0x76B3839E1186AEC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9125F3467107FA37ULL,
		0x30838D18C4BA42B8ULL,
		0xAD04268F632ACE2EULL,
		0x4C3901C2359EFE03ULL,
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
		0xCE734B82419A1B03ULL,
		0xDF1ECFEB93FDE9D2ULL,
		0xF1EC1A2D5F895728ULL,
		0xE838F3961259304BULL,
		0x9CAE53950EA3B91FULL,
		0x088CAABBCCD7A504ULL,
		0x1F90913D19E33D60ULL,
		0x1E9A820A0DE268A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF231524B3C84C6AULL,
		0x6CDC80471CBBE2D5ULL,
		0x6CFB64372C961C9CULL,
		0xDC7C27FE81AA2B98ULL,
		0xD5D6D507685BB4B7ULL,
		0xF9140552B623A06EULL,
		0xCB2E14AA3E6B3325ULL,
		0x65BDB7581686C9C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x734CFF643C827467ULL,
		0xBE2ADD3DD5FAB538ULL,
		0x0B8F33C2C6C4BF2AULL,
		0x7C82E20248489A98ULL,
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
		0xC10FF26B4FE38108ULL,
		0x45A15ABC59676DA8ULL,
		0x4F0A5E874DFA1E60ULL,
		0x6675E32161B633AFULL,
		0x8256B14AAE106451ULL,
		0x5D21CC70CB615511ULL,
		0x9F701F367412FEB9ULL,
		0x941AB7C259245594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A1247C0AC01186ULL,
		0xF9386D547F32C286ULL,
		0xE8DDE6B042D5703DULL,
		0x7F35BF798C1E06C1ULL,
		0x6B3AA5A74118218BULL,
		0x786E2BE3BDD57A53ULL,
		0x072E9FB17AE42BB8ULL,
		0x9BBCBB7AD57B75BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA898883171FD58ADULL,
		0x3F12C257DCF72359ULL,
		0xFFE5659408180044ULL,
		0x4533964560A96739ULL,
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
		0x13146C837E215090ULL,
		0x55C7AF25518216C1ULL,
		0xA300B9E99C808065ULL,
		0x61FB6A7DED0564F4ULL,
		0x1D11ACA48F749BE6ULL,
		0xAD272BAF0B128A2AULL,
		0x2EC783F1BF4DA0D6ULL,
		0x730FF8F229147C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7530970B69E58DBULL,
		0xFA8F75F14E4C26EDULL,
		0xD87CFF3DF2BF386CULL,
		0xA19F15D7D8921166ULL,
		0x728FC4F9F526BEC8ULL,
		0x2FD9E56DC97C5B9CULL,
		0xFE460AA7CD24AC6AULL,
		0x81301F0A68A7A087ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B09C665AF11C9CAULL,
		0xF4B0A6E3BF80D8DAULL,
		0xFDBBBBA59BD59012ULL,
		0x2796AD0CA49BFA8AULL,
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
		0x5C53E6C48B4B79D2ULL,
		0x30CF21DC44B0C8A7ULL,
		0x940843D6480ABDD1ULL,
		0x70F95DB9995BE1ECULL,
		0xDA47A8928C37C4F1ULL,
		0x059E37B2DB9739D4ULL,
		0xBA56EDF4B07FD769ULL,
		0x1C266FCF490BEFDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0181D0FD3C715108ULL,
		0xA69BA7BC5CA738E3ULL,
		0xC029961DA766CE70ULL,
		0xD9F03AFBAEAC7677ULL,
		0xB9EFAA38AEE1036CULL,
		0x276C013377538E08ULL,
		0xBAA35B8AEDB9FD92ULL,
		0xBBD20E60B8FC7E70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27E1D71E29BADEE5ULL,
		0x85A79108CA151011ULL,
		0xC886696B8A024545ULL,
		0x638F99274CFA41A2ULL,
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
		0xC9E40FE0CB6AF7D8ULL,
		0xF68EDE7F926385FAULL,
		0xA8B184FF4B6786C6ULL,
		0xA9D9862A36DC7245ULL,
		0x54887EB574FDDA4EULL,
		0xAF5D9BC06F73EE3CULL,
		0x6484CA3BB00088A1ULL,
		0x5CDC76A4965AA73AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x904EF6EC604E19ABULL,
		0xA6BFB524B3C8BC26ULL,
		0xDC7E7FC64457AAEDULL,
		0x98558F5A5997845DULL,
		0xB7734D355252A08DULL,
		0xEF6BC3854D7C178BULL,
		0xB8CF431ED1F7166CULL,
		0x1C7AB7D114C93B09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ABA71F99087723CULL,
		0xCDB54221E964A80BULL,
		0x49251381FC76CFADULL,
		0x20064A3518DAFD21ULL,
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
		0xFB8052B488CD3067ULL,
		0xD5ED193341276987ULL,
		0x549097A113250A89ULL,
		0x0DED714FE2730BEDULL,
		0xC0D63E13A2150569ULL,
		0x1DC600922D427B17ULL,
		0xDEBC84735D060418ULL,
		0x57BF5921E15E02BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9DF74ABE2910312ULL,
		0xF1B65B968806D817ULL,
		0xDD8218DDACAEE422ULL,
		0xF213B4477EA3429FULL,
		0xF9018A2EB0641989ULL,
		0xB411F07A6C7489A6ULL,
		0xFC7F88A3B07DEDE0ULL,
		0xA0E00BCB2A5BAAEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB339204867F2ECDULL,
		0x94F1212357B2682DULL,
		0x0C1BDF9702A972A0ULL,
		0x40FF37E78E28D2C1ULL,
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
		0xC2347EFE803EC2BEULL,
		0xE542913E99E840A7ULL,
		0x62E7ECBED040ED0FULL,
		0xE2F1816F2A994C65ULL,
		0xC713E87728FDF87CULL,
		0xDCF74697D6B7BCD2ULL,
		0x1CAFFE3A4B56069DULL,
		0x5A703BAD4C0C9863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18EC9C17A1581FE4ULL,
		0xE819BE031D037C67ULL,
		0xD811B1C3398F3FDEULL,
		0xD265F40760975F27ULL,
		0x712590C6E62AFAE7ULL,
		0x11CB868E31B396D9ULL,
		0x4CF90497425D3979ULL,
		0x908F57A200D3C66AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AA8E710CA3845C8ULL,
		0x25A754A9FB826743ULL,
		0x5FFF492EEBA020A7ULL,
		0x07ED6714F471182CULL,
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
		0xE92B3202CDBC649DULL,
		0x5ACE72E15E2368ECULL,
		0x3DAFD7D6577EE8B0ULL,
		0x21E77802C30915A0ULL,
		0x981A15D6CE921742ULL,
		0xEB8C7BAA09EF1884ULL,
		0xDDAEA07ADE3E04E7ULL,
		0xBB936C0164DE5CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A7AA63A925C5F2ULL,
		0xECA88ED0290C5ECEULL,
		0x12C8C6917C103EDAULL,
		0xEEF56ED08388EE17ULL,
		0x7183B30B18F09819ULL,
		0x6A794C987A00EB21ULL,
		0x6173DB8DB7DC1FD8ULL,
		0x65D011869CD943DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0D631DC1A8F8076ULL,
		0x96FEE0AC9271C6D5ULL,
		0x9BA04C788DF6AA22ULL,
		0x6DF1776BF041DF17ULL,
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
		0x1868BEFA484A411FULL,
		0x8F219A4FEACBA573ULL,
		0x695571F515114B97ULL,
		0x0C58E1897112DB21ULL,
		0xEA1D66C021A7FFAAULL,
		0xFFA09C1A513DD207ULL,
		0x3300190CD6854BCFULL,
		0x6980C75DEA35C358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3BC5C6218ABB3DULL,
		0x629B1490642AD389ULL,
		0xBB66A3765E0C80C6ULL,
		0xDE506E98F441879AULL,
		0x47CAB9EE9922A083ULL,
		0x4BB3CED6414EBCD5ULL,
		0xBD44528388EFCF90ULL,
		0xD5B25468F563F09AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5272A04E6A8BA326ULL,
		0xE1ACFDD9E41DF76DULL,
		0x27CE46E03B353C45ULL,
		0x1EAD834CD3F69BA6ULL,
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
		0xC11D7BD2B025D620ULL,
		0x803FC75DE000255FULL,
		0x672DEFB83D5893B8ULL,
		0xBB4A5F182FABD7B2ULL,
		0x22E431219A9AC5E8ULL,
		0xF4E6738588AC68F5ULL,
		0x7DC9817E6E63FF9DULL,
		0x823FA0B5F9560AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x737B61E305876E0FULL,
		0x532CBC4418BC8D68ULL,
		0x22E70857CAEC358DULL,
		0xADB9217FBAD1FA9FULL,
		0x7163BEBFEF7C8764ULL,
		0x6A2BA852FB06EAC6ULL,
		0xDECFA3DE3CA40795ULL,
		0x92D44718D87B91C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6B3146F111BAF4AULL,
		0xC4CD349ACDD452E5ULL,
		0xDD5DCD27D4EB2F6FULL,
		0x17808AEB5547D648ULL,
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
		0xE62F719451A886F3ULL,
		0xD7F4218AE794AA44ULL,
		0x46A17D55ECE773E2ULL,
		0x634987BBE55F60A5ULL,
		0x080E89CC5E65D186ULL,
		0xF144F14BABCE15DAULL,
		0xC9DA588249785A07ULL,
		0x850141E943AA8147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0E9F153076DCE86ULL,
		0xCAF8ED9A68695A39ULL,
		0x0413CDAA9D136865ULL,
		0xCCAADE10F045161DULL,
		0xE1B7199729E10DF3ULL,
		0x117BF311F3794CB0ULL,
		0x5DD8851201B9B06DULL,
		0x4778DDAF6145D94AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB640282715EFC182ULL,
		0x44D0F081DBC12C26ULL,
		0x4AD31255F621387AULL,
		0x38DD8A42900B3A26ULL,
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
		0x78023C1C34124BA6ULL,
		0x264105621EA735B0ULL,
		0xA7C6D922CB785E44ULL,
		0x055ECD8BD822D3C3ULL,
		0xC67735FFA1AE582DULL,
		0x560AA679A4CB2C42ULL,
		0x36945D4B1AF51D4FULL,
		0x296A524B34C9DBD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22B2BD33C7ECD548ULL,
		0x8DE31864CF09EBA3ULL,
		0xF2618857D7ED0BEEULL,
		0x9AA8EBA2140495BAULL,
		0x519ADF8D46E3495CULL,
		0x8D303B19AB3761AEULL,
		0x4047806FBF8577CBULL,
		0x9812B3F8A42EDF43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE0453E1E649A6CBULL,
		0x68C9DD3C5B8D5C16ULL,
		0x44CE195A861DE3E5ULL,
		0x7DB7622B3B1FBB8DULL,
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
		0x20DA3DAAD362A41BULL,
		0xED95D9D67FAE765FULL,
		0x622A80D5917CCA5DULL,
		0xE15643005F5E7321ULL,
		0xE6DF1008E1B1FB13ULL,
		0x561ADC8E4B804BD7ULL,
		0xD31779BA5EC3CCE4ULL,
		0x026115D31A161B65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49EDF290074C972AULL,
		0x9F8E4FB9E0E5A405ULL,
		0x9620A0807ECA4EF4ULL,
		0x3CCFD0AFE34B0562ULL,
		0x4AF70514A0E81388ULL,
		0x8A41CDDF493494EAULL,
		0x775B4D927FC98FE0ULL,
		0x89C60C555C05A566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB5DEB5C6A0E68AEULL,
		0x903FB816F605F99EULL,
		0x69F86E402BD789F9ULL,
		0x0B89DAFAB284F1A6ULL,
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
		0x17B2F892B11B7295ULL,
		0x7AA792C9E61F2839ULL,
		0x18A3A5DDE094FBD4ULL,
		0xE6114961289B20CBULL,
		0xB8431AC412CA19BFULL,
		0x49D2FD5D1FF136D1ULL,
		0x1145A2FF7EE0FB20ULL,
		0x04B1D5C22978A062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF880E140190112CDULL,
		0xA174A3DEA273B087ULL,
		0xF0DB719319052F0CULL,
		0x077C467C23A71A2AULL,
		0x66B9C946006D1FE6ULL,
		0x0B71BC4921B6B1E5ULL,
		0x788F239B22ED0B0DULL,
		0x3CEAEA154A7F7A8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3994300951E774E1ULL,
		0x1BA297E3005B32C5ULL,
		0xD2DF1D306DC56FA3ULL,
		0x061BFE8E1DEFA47AULL,
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
		0xCB6BC748ABB0D47CULL,
		0x6DFF61E3F299743EULL,
		0xBA37CF7DA366E31EULL,
		0xDF90102A2A763F40ULL,
		0x11F0826FEBFE7B3DULL,
		0x5F3F6C243FFF497EULL,
		0x3977591BA12D781CULL,
		0x16FA9C55653600A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770A8FA8308A1121ULL,
		0xBE2E9CB06F408FBAULL,
		0x80C5D07F50626D1DULL,
		0x2B8C5A3D1E161190ULL,
		0xBC754C85A5482FA7ULL,
		0x82ED4295FA76B910ULL,
		0x1AD89E0EA9A78846ULL,
		0x481CEAD9DC02E892ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04AB3866FA35FA95ULL,
		0x6402F051D59E54BFULL,
		0xC501C2EB10E60FBFULL,
		0x68EC0E4369F5BFEEULL,
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
		0x0F2D7F53446AD472ULL,
		0x4C8CF84CDAE00151ULL,
		0xCCA1B112CBCA4102ULL,
		0x8C053A62EA586394ULL,
		0x5F289F7E8E8D5857ULL,
		0xAB7A5147C25AE5BAULL,
		0xA3B95D140C9FBAF3ULL,
		0x2C5223E00D20BF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05DAB39AB17BBE07ULL,
		0x901BC30C0FF9E149ULL,
		0x8F1C4726A7665C58ULL,
		0xA35BB0C56DDBDAF6ULL,
		0x6E78DC8B3135F583ULL,
		0xFDB98BD4AE32C7EAULL,
		0x69E153A5C39E071FULL,
		0xDB708382DBA8AD58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC369BBD86DE7BDF4ULL,
		0x870E8455C8DA8CE5ULL,
		0xD396D04AFAA49615ULL,
		0x6A275772D44F3480ULL,
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
		0xB3871135873F336CULL,
		0xF5961D4D2456A805ULL,
		0xF7B6F717C7413329ULL,
		0x2391F666741AE3B2ULL,
		0x4FA5482694665842ULL,
		0x56100E97970C3413ULL,
		0x43F869D9EDAFD2F9ULL,
		0x5447D5686B290C95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE94F4610B983575ULL,
		0x6C2213897AA97972ULL,
		0xBB988C8B6A5B80B6ULL,
		0xA9C153035ABE8CC7ULL,
		0xEEF64ED1878C0F82ULL,
		0xA9EE02294B2CBB17ULL,
		0x457414DBD66461D8ULL,
		0x46F55AA8E4CBC2D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EEB1F74640DCA9DULL,
		0x1681E222ECD923E3ULL,
		0x03C30843D2187D4DULL,
		0x740EDBD10B35496BULL,
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
		0x7D88CA30CC6487C1ULL,
		0x21BA97F83A29121FULL,
		0x223DB77AD5C0D922ULL,
		0x67556DCF1E7F4008ULL,
		0x4944C3D9F912E142ULL,
		0x29637AB6B9592FA4ULL,
		0xEEB37C9129AB7232ULL,
		0xE99156A9D9DD86E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D51C98D6CACE2AULL,
		0x4CD59E486B7F1FE3ULL,
		0x0634B0B972DF3260ULL,
		0x9B86A9D31192314AULL,
		0x0C82E158533367A9ULL,
		0xAFBF552096C68918ULL,
		0xF181B5ADB9EF207DULL,
		0xBD9284A3C3C92A67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB7B4CD694C5C731ULL,
		0xE3428DF8F06EAB0CULL,
		0xB16C8C83F8D5C78BULL,
		0x53A1F0E353F2C94BULL,
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
		0x782E0378D447726EULL,
		0xF8B271313C6BA40EULL,
		0x840E34890A5FEB35ULL,
		0x3059EF5AAD64A850ULL,
		0x754EFE4010463417ULL,
		0x078B63A84B304D21ULL,
		0xD96B8E8EEA97C1FBULL,
		0x633DDF82284576ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x701D6E454D18422BULL,
		0x385835589C7302B8ULL,
		0x022A63B2A458E8D5ULL,
		0x8638FC93EB8C442EULL,
		0x5997CEBA8472D0E1ULL,
		0xA247CDDFB16011E5ULL,
		0xF003089AB7FA1BB7ULL,
		0x05D4F07B34E09850ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2541A306488FEC48ULL,
		0xC862779F74E16C42ULL,
		0x2767B315E96DB061ULL,
		0x07B46DCEE2D165C7ULL,
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
		0xBDAE81EFDDB453DCULL,
		0x6ED074583113E722ULL,
		0xCE48B0681F0ACCB8ULL,
		0x24025B348296E712ULL,
		0x3260C97A014902C2ULL,
		0x049B574904F29070ULL,
		0x9DD90311930CA53FULL,
		0x1795A2431432DAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085C45683CF1FBCCULL,
		0x1D7FD40A4CC2A624ULL,
		0xD473F3479EC114B9ULL,
		0x1CCB53A68F9C4B71ULL,
		0xD69CEF4FEE057C1FULL,
		0x5497F71B2197A7B5ULL,
		0x83BD336E5C3B5F8BULL,
		0xFF01BB9E4E0A0252ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54649EC67CC84F23ULL,
		0x71D0E71DA3CFCCA8ULL,
		0xD9F58F5AA35A10ABULL,
		0x2D2B44035D0ABEF0ULL,
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
		0x3584113B71E43102ULL,
		0xD5FC2C3087861E7DULL,
		0x1D346F8AB3DADB05ULL,
		0xD9332AADA1266150ULL,
		0x0851978A0923184DULL,
		0x45189FD472C4141FULL,
		0x709F8673A2D3E259ULL,
		0x17851401717B09ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB77D665BE17A77E4ULL,
		0x8B33754ECD463755ULL,
		0x6252E5EEA486A1A3ULL,
		0x1BAD884573D69261ULL,
		0xCDB01742E7A2BC2BULL,
		0x57F9369DA5451A27ULL,
		0xA319E5E057E434ADULL,
		0xEF5FA933A3723B62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31FFB56E8977617DULL,
		0x7D7255043B1901DAULL,
		0x3CB75F792EE800E7ULL,
		0x33137CF4C29E6DE3ULL,
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
		0x758B9E1A7B7501C6ULL,
		0x12F26A68372A85E8ULL,
		0xF9F8C0CCEF5621C4ULL,
		0x76CB9FD3B1EF7EF4ULL,
		0xEB5239532D18CD42ULL,
		0xA99C1165C31371F6ULL,
		0xF7641723651E19A0ULL,
		0x56B4733F5E71B2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF5F272BDE319020ULL,
		0xA064C2B12CB65AECULL,
		0xC56A92E3792579BEULL,
		0x3631D11D02132A7EULL,
		0xC54C5AB1FD5F62E9ULL,
		0xF64A48ECDC790B7AULL,
		0x174A5D74B7BC9A57ULL,
		0xC675F40CDA515FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B0B82DBB2C93869ULL,
		0x10B169A9455F6169ULL,
		0x785FBDD732A98CD0ULL,
		0x29E0B0364CA8A7EDULL,
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
		0xF1FE719B2DC82098ULL,
		0xA2DD7F7EB712F17AULL,
		0x9661515047614151ULL,
		0x40D9624664F5008AULL,
		0xFC9C02045087BBFFULL,
		0x4C6D4FBEC7BFDB01ULL,
		0xEFDA1A0DE15132B2ULL,
		0x6CA04F7C763EFD7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3BD79BC3914F757ULL,
		0x1E2F43B2D5D6D2B6ULL,
		0x349060CEF56C5C94ULL,
		0xBF6F01EDE089EB62ULL,
		0xA08E027BCA526CFDULL,
		0x49FD4B8A76318BB5ULL,
		0xDAF7B49D1CF3D9D9ULL,
		0x98B9BBDCF3418D89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA854E622E09CE270ULL,
		0xE14EDB8FFC5BE419ULL,
		0x7B6BFF3E77D014F3ULL,
		0x75A44A05F609B33DULL,
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
		0xC4014DD7E8349EDEULL,
		0xD483C95EB2448F0BULL,
		0x9827DCF725791708ULL,
		0x2D997DBCDC0510AAULL,
		0xA22E6AD1F4B90535ULL,
		0x532862A60382175FULL,
		0x473B19F9EE2C9255ULL,
		0x90753AC7C1441E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE6F70BC8A2C0120ULL,
		0x7EDEC7EB75120C9AULL,
		0xEB3ECB27D31DEDE3ULL,
		0xBF012A186CE9D095ULL,
		0x9D873FF9C63436A2ULL,
		0x058C7512A11AACFEULL,
		0x8198E1ECACC07351ULL,
		0x44FF29A2406B9908ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8662393245BF491FULL,
		0xDACA4553D88C4CD7ULL,
		0x02FD63C70867C3C8ULL,
		0x221EDF358F3EFE0CULL,
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
		0xF332BA41EB199EB6ULL,
		0xB746EDBC3AFF5E66ULL,
		0xD046ED988E09C6FCULL,
		0x25559B4B2674E625ULL,
		0x31F47C80D4A3F7A0ULL,
		0x4A7578D368907298ULL,
		0x91F4431B0237DB9AULL,
		0x085F332CD800DA00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEAD4A5FBAF39FE2ULL,
		0x29CDB3821465EFF0ULL,
		0x2CDAEBF22894630AULL,
		0x90E6E51879A9F244ULL,
		0x01F23CB1F4948282ULL,
		0x6BB3C12C0412004EULL,
		0x9B4C7A47AF56300AULL,
		0xF7D8C3ABCF83DAC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34DAE89772715BF0ULL,
		0x9E3A7D13115E6579ULL,
		0x4053D104B2F4DB4DULL,
		0x08634359EF58D630ULL,
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
		0x21A2BF3F485ED6FDULL,
		0xF5BA7DD5A1B5EC97ULL,
		0x34FD657054D78791ULL,
		0xFB51A9BE26EE474EULL,
		0x67850A3CB9EFF846ULL,
		0x48BA4A5EEAB1BF96ULL,
		0xC9A080FBE7EC6C36ULL,
		0x611C9E018908D878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB1BBD1CA03F8B22ULL,
		0x3BC8839947779B27ULL,
		0x8747B7D40E8FAA22ULL,
		0xF14E3471E86E897CULL,
		0x2D20CCFAB8E23850ULL,
		0x81C61EE150A31960ULL,
		0x41DBE532AD6E6B4CULL,
		0x0F2242D808FE48E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x016819EED029CC27ULL,
		0x42306EE1386AFD7CULL,
		0xD4E4CD7AF4FC0023ULL,
		0x352CFD7540110E75ULL,
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
		0x43A251D32F5E7B5BULL,
		0xF9D68F5ACD7EF45AULL,
		0x74801547E9E706DEULL,
		0x2B210C0D55A7BF4AULL,
		0x735FCE335D068675ULL,
		0xFF83054E2372A696ULL,
		0x31F9BED40DABD055ULL,
		0xE2293B46E56496B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB02FC028D951535EULL,
		0x8E32054241B1442AULL,
		0x0D067C64E9834948ULL,
		0x11E6C9CA8B407578ULL,
		0x868CD98AD4554BEFULL,
		0xE39A3ECC2992DB5DULL,
		0x559A18D061603831ULL,
		0x5B60300987EF7BF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAC2E2AEA05BDAD9ULL,
		0x90320163A305DAA2ULL,
		0x1DAC3D6E939C52F2ULL,
		0x1B11ED5EA9C94227ULL,
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
		0x5ABD2C79F93CD02BULL,
		0x42068DDC869656CFULL,
		0xB3CABC1DF8806BABULL,
		0x100E40EB0A8FC81AULL,
		0xB03E5786430FD771ULL,
		0x489C38F5D6C1569BULL,
		0xA980A8BA3CEBFA45ULL,
		0xE777BBF680194324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9CA135C12E1B26ULL,
		0xDA1B1FDC95C97CD8ULL,
		0xF1F1F7C3436A53C7ULL,
		0xD78D1640EAD5CCF1ULL,
		0xC1784DEE8B17405CULL,
		0xA324DEF42EB67D33ULL,
		0x0ADF4D229196AEE4ULL,
		0x9A4BFEE0111624F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E85F7C986F523B2ULL,
		0xF7A2CA3EE2691F64ULL,
		0x4DCC5CDE23BF483BULL,
		0x2CFF3BFE9A3075C8ULL,
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
		0xEC22987EDDBC136DULL,
		0x47DDE147634AD4E4ULL,
		0xBDCF8FDD4FFB9F91ULL,
		0xFA0777355BC115A2ULL,
		0xA504D94446BABE12ULL,
		0x14B57D3C3B73BB69ULL,
		0x7EF71DA7FF01A367ULL,
		0x242EDCB8BBDC6477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022EDECC894A3D6BULL,
		0x305909042757C86EULL,
		0x5F426974433A1282ULL,
		0x83996736CC2991C7ULL,
		0x8B2A18DF83B12ED0ULL,
		0x86CFAF4F237A0B58ULL,
		0x94ECD710EF839E04ULL,
		0xFC33B3CAB5B9948DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC06C48A747DD150EULL,
		0x27A16974CB032F00ULL,
		0x1C13A0D5597659B0ULL,
		0x65B6235378C26094ULL,
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
		0x7C7C4243F8E76008ULL,
		0x4564A1E10A3F47D0ULL,
		0xAB1234AF6E7CEF8CULL,
		0x7D911D70F517CBC4ULL,
		0xF008BB3F12866D93ULL,
		0x9BE2A078DCCF7D66ULL,
		0x0E174F85C942FC05ULL,
		0x9E896048C5A9C010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4FCDC5C0D0AA376ULL,
		0x94916C9B980F45ACULL,
		0xE508DBB1AE4D10B7ULL,
		0x583BB10EAB260C4DULL,
		0xF06B4DC7B5C381F4ULL,
		0x1C779C5124BB0515ULL,
		0xA065BFB62D5BFC3DULL,
		0x4CFD8A7D4445F0F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78DDA59FB0CBB7F4ULL,
		0x9AB5D32AC539DE29ULL,
		0x0E64B1CEE479D697ULL,
		0x401728977EC27E21ULL,
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
		0x873D18477836D590ULL,
		0xD13F5F4C5AF6ADDDULL,
		0x1765324540CBA332ULL,
		0x2A76028732BF1F85ULL,
		0x5C774448E69FFA6DULL,
		0x06821433C0C5CC8CULL,
		0x154C96A1E87CFD3EULL,
		0x485A6550852DD816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381C485B74BF0116ULL,
		0x0D61E77770B46D47ULL,
		0x3CD33CCF16CFF774ULL,
		0x961BD5011F6959A1ULL,
		0xBE9FEFF9ED5A8546ULL,
		0xDBAF15F4E5C03995ULL,
		0xA53F7F047033C02AULL,
		0x6EFDE80E2820A378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD1753A503C7374DULL,
		0x1F2F35296D161131ULL,
		0x7C8376D604DABC97ULL,
		0x5814C55FE34B9542ULL,
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
		0xBCC57253A90CF4C6ULL,
		0xE06FF3687E89FFB1ULL,
		0x62B10CE8B7DCB594ULL,
		0xCE4C96D672BF2F0FULL,
		0x0D2D3182EACE0B46ULL,
		0xA0A49B7DEADA91C2ULL,
		0x2A3F0917F1A54C62ULL,
		0x9FD1710B477E9926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D70A6866E2C0323ULL,
		0x3C3FC9D037C1C152ULL,
		0x282FEF1921470C4AULL,
		0x5BBE36F6877E058DULL,
		0x6B2EB7BEB45214CFULL,
		0x764A1A9F73C62C1DULL,
		0xF5AB4AD051B6F3DFULL,
		0x1A6B9F3051D335D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B1ADEED51478A45ULL,
		0xED9F4A9DF3CF54CFULL,
		0x086F5C7153F6CCC2ULL,
		0x3FAB866062B1E802ULL,
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
		0xACDE010115756435ULL,
		0x657571DD57561E6CULL,
		0xC731D2A70F9AB635ULL,
		0x974A1366E6CD268FULL,
		0x5535112B0FB97D7CULL,
		0xAAF8E543A485ED65ULL,
		0xFB558E556A2E653DULL,
		0x0A0039AD92D262D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF46DF7374A115661ULL,
		0xBD61B1CD6C7A9621ULL,
		0xF906EDC4B3C72F91ULL,
		0x8DE6307748F13E65ULL,
		0x9E8765105BDB2F99ULL,
		0xD8967601459AD3D9ULL,
		0xDE3862D86BDB2793ULL,
		0xF6C7F6A07440253EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD63795C07E639841ULL,
		0xE2B043EA01C15307ULL,
		0x207F59701C2EADD8ULL,
		0x63BDD6E227910CBEULL,
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
		0xB3AE5BB07A360930ULL,
		0x82C7B5DB7FDA5BE7ULL,
		0x874D7F77CA749C34ULL,
		0x80FECE26318F0314ULL,
		0xBAEEB85C364B00C8ULL,
		0x2F0D76ACE796E52AULL,
		0xCADA2DF676AE3D93ULL,
		0x15758D2A081723FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C0E28A0AA880641ULL,
		0x30315D2575E653B2ULL,
		0xCEB8FD0F762FA819ULL,
		0xE3941BACEE14AA65ULL,
		0xB9980F87D3822C0CULL,
		0xE1110E1CA714D40AULL,
		0x66BABD618B79F59DULL,
		0x18F7481586253396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA7D4296797D96B1ULL,
		0xE60DDE1F9D4292F5ULL,
		0x953F38833E07A284ULL,
		0x1828F3848D6407E1ULL,
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
		0x13B8D91E21FF547CULL,
		0x401976E9D61CF342ULL,
		0x369F81CE62391EB6ULL,
		0x1A96985DE73A6C35ULL,
		0xADAA361CD3D471D6ULL,
		0xE7B2D3C0A3B601DBULL,
		0xDD0E5F21C7D3FF68ULL,
		0x8DF939FCAFDD48CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76D6E86AA13030DAULL,
		0xD0675A8C745A934AULL,
		0x41B725C6CAA07567ULL,
		0x20038BE7F443E03BULL,
		0x16D6052EC97290B9ULL,
		0xFBCFF580BC86750EULL,
		0x645114450B5F6C53ULL,
		0x569762484E251987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x006134090B568F20ULL,
		0x735F19D9B2D1467CULL,
		0xE10178CB90E67E69ULL,
		0x3319113C744D8FFDULL,
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
		0xB62024E74BA33D0BULL,
		0x8F28A801E9BE5118ULL,
		0xA32F643DAA9CA3E1ULL,
		0xB0222D00BF19E2F6ULL,
		0xA1BC91C76EDEBDD3ULL,
		0x6956075CA71043E4ULL,
		0xE3F1AC106FCB1A59ULL,
		0xEB7E27E936F7AFCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACCCA072578BFC12ULL,
		0xDD516018D06DF9BCULL,
		0x94DDB6D634338AB6ULL,
		0xD258A9FE2ADBD065ULL,
		0x820C2BEFED746C97ULL,
		0x19A0981D0DCF2DEAULL,
		0x232C60EB7B0AA4CDULL,
		0xD023CEE560484A92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD82A27229DF5066ULL,
		0x86C5CB59D8F99A7CULL,
		0xAB9AD4E3CAFA8BFEULL,
		0x6D32B994724718FDULL,
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
		0x535EBF910FADE722ULL,
		0xDA68ADBBA11F75C8ULL,
		0xD655F0B7DE16D7E6ULL,
		0x29A0D10BCC55969DULL,
		0xA596FE0A0667A90DULL,
		0x72B46FFFFDA03DD5ULL,
		0x9D79C938B7CBC98CULL,
		0x2F6CABE264088A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1058378CAA74080ULL,
		0xA494EBB83D8362C1ULL,
		0x5C5A47FBEB728C4CULL,
		0xDBA8F68411F02607ULL,
		0x99FEFC82B3AAC6DDULL,
		0x8917F3A45D6B31ADULL,
		0xFD8E3A980C206942ULL,
		0xC62F0A65D21BDDA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AE9762E8D103645ULL,
		0xE30E379D2B7BE0F8ULL,
		0x36F2D4956E149692ULL,
		0x6D1DD30563870630ULL,
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
		0xBDE0D44E4A83AD90ULL,
		0x01B6495BE937CDB8ULL,
		0xBFF6C78AAF0207D2ULL,
		0x6744BF6AC28585F2ULL,
		0xB65660ABC0906A84ULL,
		0x28AB4F6382C55345ULL,
		0xA60E5D3462230B32ULL,
		0x6E9A02F89717E13CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BF4078458DF0E8ULL,
		0xF3CD69D2C6840429ULL,
		0x523E4421F47CC44FULL,
		0xBFBA11E348E383F8ULL,
		0x2855F791AB900C56ULL,
		0xD371F7AA820E71A1ULL,
		0xEAD5894E6F22E7B5ULL,
		0x17295D53EE875F11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B312DB52303B957ULL,
		0xB46BE4FF3DD947FCULL,
		0x3827F78ACC8A87F6ULL,
		0x224343F87F155452ULL,
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
		0xC8A0608ACC69CCF0ULL,
		0x7BEF2516C29A8F30ULL,
		0x34E31644C644116FULL,
		0x78E776AD5154D4E8ULL,
		0x40287034BD3217EEULL,
		0x60AB02BB0509D269ULL,
		0xF715514C964F7CDEULL,
		0x52435A83F6A062B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x969BD425AA7B5F44ULL,
		0xA5C0DDACA40DE443ULL,
		0x135FE66E8108A8E5ULL,
		0x21D7A9263CA3EDEDULL,
		0x4031F8B14B57EDB6ULL,
		0x795ECF3B78A5798EULL,
		0x51593F5675931BE2ULL,
		0x9DCA06B87C4E7704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x309A49E80850B05AULL,
		0x2B7DEC58F571DB6FULL,
		0xBB6DDA5F2131CDEEULL,
		0x21123DBB3CD9E2E7ULL,
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
		0x3188E7049BC80F37ULL,
		0xA10DB0EF7B791B9EULL,
		0x5CFF0D4D890BDF99ULL,
		0x6062BECDF9B5D9A7ULL,
		0x84989DF2637DAEC0ULL,
		0x988828FBE1FCF254ULL,
		0x43AB7D0FE1C3F596ULL,
		0x1D1DC7C51A151ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8AE0687D6464AF5ULL,
		0x5DBFA1FA273A9ACDULL,
		0xCB67FF2A841B1BC0ULL,
		0xF0CD931176C5C05DULL,
		0x8C7FF7D8D8734AD6ULL,
		0x9029E1537A346E4AULL,
		0x15DB31B056F05A6EULL,
		0x931787B494FB40A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C838847690C963FULL,
		0x814CB1F4BC021A4BULL,
		0x5E823E51A059CBCAULL,
		0x6C82AE3044C71508ULL,
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
		0x79FDF01A4D3A5793ULL,
		0xBCAF5C57EB21EFD1ULL,
		0xFE39CC9C20715D7AULL,
		0x456DADD35A426D2DULL,
		0x6AF704B8EEDC7E84ULL,
		0x942BB8B31F5A00BEULL,
		0x55D2ADE4A086C49CULL,
		0xC0DD2E0B933BA9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F7821C5BB39410ULL,
		0x372ADD28F53C621BULL,
		0x877F12DA4723B8FBULL,
		0x3292DB3453ECBCA2ULL,
		0xFF414229E56762B2ULL,
		0xBCEC2E64258FA262ULL,
		0x4993A076B9C3F325ULL,
		0xE1E780A57FB0EB34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E014F3958E8E3F1ULL,
		0x78F306E809EF8F47ULL,
		0x4816B8121A38BC23ULL,
		0x2B528FC5ECEDFC27ULL,
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
		0x7BCE744C81A831DBULL,
		0x7810AC3CAD50ED61ULL,
		0x87E34EC060160D20ULL,
		0x17E615D7A480708EULL,
		0xDE0DE54A9EC433E0ULL,
		0x4A81B516BAF90230ULL,
		0x5C4632318F7BEE32ULL,
		0x0BDA74560D039AADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2930C46A7C5CB28ULL,
		0xEB2F5F101E3833E1ULL,
		0xA04767562ECE7408ULL,
		0x113CE1EF4A800C44ULL,
		0x565F044BD5AB7690ULL,
		0xCC36F852500630F4ULL,
		0xC0450687B840B7FFULL,
		0x913CA78B958AD13BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED30CDD7B38E7D9BULL,
		0x4BF952546F23C87BULL,
		0x0FC862A02411A496ULL,
		0x3A1599F615EE4B27ULL,
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
		0xEF89C7849A5C28E6ULL,
		0x39F395F17193309CULL,
		0xA5C2FBA74E0A5498ULL,
		0xF9A875118A5833C6ULL,
		0x79AAE14F8C71BB8FULL,
		0xF93C6E196CE3EB8AULL,
		0x6B84DC2D25F0AC8DULL,
		0xCC957427DC549865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC181A75A3E19E588ULL,
		0x1E7074C7E9571195ULL,
		0x400706B3E3187378ULL,
		0x00393F79B6662071ULL,
		0x58F78AF199168009ULL,
		0xAF355D6868DDA569ULL,
		0x44ECC9876646BB26ULL,
		0x867CC285667BE94FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A6F21C7BCD1AE4ULL,
		0x188F9B70212A87F2ULL,
		0x204EB98DDE2BB675ULL,
		0x611993B5521C109FULL,
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
		0xDDA3CDCE0A4773ABULL,
		0xAE87BFB320F38BFFULL,
		0x2338F956BAD6504EULL,
		0xE5CA660F004BB896ULL,
		0x31D312E94D287E24ULL,
		0xA392414900FD086DULL,
		0x2C7389A83C850D42ULL,
		0x846B0B5C1F6CED87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x995CDC31F5619138ULL,
		0x3ED6D2A3BA6ED7D4ULL,
		0xE928997E6EBC9812ULL,
		0xFE349D10DCC4EC6AULL,
		0xAD9F10422C0AAB98ULL,
		0x065E63EBFFC95B3BULL,
		0x12CE810D48CA77B5ULL,
		0x1E2335A435EC28C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3FF566AFF532575ULL,
		0xC563C8DD94306984ULL,
		0x088FA6D879CBEB41ULL,
		0x163F824ACCA400AFULL,
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
		0xCB3B36D932FFCABEULL,
		0xE58ADB05B6C796E7ULL,
		0x7307C1EAFD0C8517ULL,
		0x539CFBAFEA6D7B7DULL,
		0x294CEF257DA4F838ULL,
		0x7AD41C3A7D17241EULL,
		0x612102619740B6EDULL,
		0x5EC45EFE6FFFC191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB116E308ACBDA4BAULL,
		0x6E7F1A4693B3112FULL,
		0xCF4C3C61811D193EULL,
		0x2C2E3405099A113BULL,
		0x18DF19EA19D98A76ULL,
		0x9EC0AFEDFCEEE447ULL,
		0x2463FCEE54C9B53FULL,
		0xAD13BAA6A89EBBF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A71FAA156746F1BULL,
		0x21EDD41A290DFFA4ULL,
		0xA7CA54A55999ABA8ULL,
		0x07A72CB2793A3FE4ULL,
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
		0x3A754699778E1D75ULL,
		0x0B3BBCEDCC2080ADULL,
		0xC154AFB098B29ECCULL,
		0x7922F8CBD382039CULL,
		0xEF10F8943CA8CE46ULL,
		0xAA4017F98E2DA51EULL,
		0x1C89E4A67EEB016FULL,
		0x1D41475B11A67A70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77B64035599FE3FAULL,
		0x566BF7D316597AD2ULL,
		0x042C319A6388D492ULL,
		0x8C26AE3468717CE2ULL,
		0xFDF09A1CB5711F97ULL,
		0xC2F89ECB86E5343DULL,
		0x295463C557950C8DULL,
		0x4AFC3375CDECC7B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D8D0C223032266BULL,
		0x096BC1EFCA87C73EULL,
		0xD7199F820BEC23C2ULL,
		0x233D3E9F78A10E08ULL,
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
		0x46C7C20555A4E0B8ULL,
		0x5699CDF731B5DA09ULL,
		0x4FF15568CF888E56ULL,
		0x8ED088DBD92084FDULL,
		0xE0470E4E80936E02ULL,
		0x40DD8E5CD46F985BULL,
		0x67907FC959A2C1E7ULL,
		0x37F17B614983CED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED8640063882CB2EULL,
		0x4D7E063E51A1EF04ULL,
		0x9F74888BC4158957ULL,
		0xF8C75EE7E78F404BULL,
		0xF2ED3802805D4529ULL,
		0x63EBE34F84FDAFF4ULL,
		0x4660984E3D7C7B3CULL,
		0x13FC27DBB56201D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94975147252C266BULL,
		0xD4FB2BB2AAFC6A4BULL,
		0x9D9929233921825BULL,
		0x6C738FC7EE95B34EULL,
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
		0x56EA613BB5E49D5FULL,
		0x890222536043AE05ULL,
		0xA7EDC389B15A6A2CULL,
		0x6B4EFAB96A01B0EDULL,
		0xBF6B9FE1D93442CEULL,
		0x8802F77A704D238CULL,
		0x0F7419AB1F2FFB44ULL,
		0x4118EE7A94F8483EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA161CEDE472EA560ULL,
		0xDE2A9FC87A37D4E9ULL,
		0x9C0F7837BEC16E46ULL,
		0x5EE98457AA863399ULL,
		0x9A47CC1BB043931EULL,
		0xB53B647F64CE56EBULL,
		0x14D47E3D68613725ULL,
		0x336F671BCB2F158DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38DA01C782700C6BULL,
		0xF47753CE9ADE3907ULL,
		0x3F8F5D9B154A1878ULL,
		0x138F8E73B3590399ULL,
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
		0xA658A41A546FF9EAULL,
		0x6FBC1A78B718865AULL,
		0x584D1000B7538470ULL,
		0x5F565DA7EF6F8B42ULL,
		0x53C42D1C49E94508ULL,
		0x610B72A8A189177BULL,
		0x2DF0768A9E1BA49AULL,
		0x0B19993BE9436A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4EA8584D674DD7ULL,
		0xDF9F8BF767741B21ULL,
		0x6B23D5A72BC81DE5ULL,
		0xE1CCEA9853EAF52BULL,
		0x92F77F7A01E1B4A8ULL,
		0x8032E4D5D855B0F5ULL,
		0x03A680213B596C43ULL,
		0xF068F8EF1085C142ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x766BC1D8B8281521ULL,
		0xF0419BCB2D45A313ULL,
		0x3423CDFE345FC36FULL,
		0x73C13E77C7ABA30FULL,
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
		0xB57421139F531933ULL,
		0xB779F73DC1948FF7ULL,
		0xC32EFB38DF59A609ULL,
		0x23E76DE83F4607DCULL,
		0xDED38C3954D5FF05ULL,
		0xFD3424AB8C30F4D1ULL,
		0xC346BD9AF34E94A8ULL,
		0x84EB710CE720F5BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x818D8AA3D1200E40ULL,
		0x5843B0D71AC894F1ULL,
		0x92C0CE6566067075ULL,
		0x00080F90588D65F5ULL,
		0xCD13CDB207B9CBB6ULL,
		0x4C00BE9CF39C4D99ULL,
		0x996410E97F05B674ULL,
		0x5D87178AD15EFD98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD65CDE854062A97EULL,
		0xACD76C914CDCCD58ULL,
		0x6813CF2ABC243166ULL,
		0x7CC4A7A7218377B7ULL,
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
		0x6A798A7A40F7FEAFULL,
		0x6A665649CBAD0A26ULL,
		0xDD96F212DEB9DD7CULL,
		0x97D50006295B67C7ULL,
		0x4615657AE4823D17ULL,
		0x5A5D49239A5F58ECULL,
		0x8B5CF774C51B6177ULL,
		0xD6878C8997672CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02DBEB6ADE434315ULL,
		0x8E6A2E42E0255E7FULL,
		0x0616DC53620579C5ULL,
		0x04E91274EEC1C544ULL,
		0x1A0ED562FF9615F5ULL,
		0xF007D1174B43BCE7ULL,
		0x97F8190B76A31608ULL,
		0xACE66AEA2C5C0A9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF097029B5DC28B9DULL,
		0xA4ABF9DAA9A0D46BULL,
		0xF8791961228F961AULL,
		0x40D6EB3B1E40AFB1ULL,
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
		0xC3D10ED091228F9BULL,
		0x74807DECC8E9F6B9ULL,
		0xDE2B5F3CE2D88AA8ULL,
		0x47CBE38B7A561DF7ULL,
		0x1737655D6427EFD8ULL,
		0xC6241CC81B288B44ULL,
		0x81C817F2C0E2D75AULL,
		0x0575AF9DEFA4487AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65FA8A8C698118D2ULL,
		0x19BC87D38ECB2BF4ULL,
		0x55D2E2299B71B5ADULL,
		0x8DAF81DB6D6F2CD8ULL,
		0x02E9E0C5EA97AEA4ULL,
		0x4021CE53C7453461ULL,
		0xC5C004F4AE6DCC06ULL,
		0xBFF034C3F3D3C07FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x615832C0330B2059ULL,
		0x3F1B9B5DADDDB07AULL,
		0x718B4ECA04C68387ULL,
		0x0BEC9E0B6DDB2057ULL,
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
		0xD6C35A73DB662F39ULL,
		0xAF7A27B1F6AC6643ULL,
		0x84D1E5B4656779DFULL,
		0xF91BB698819E030AULL,
		0xF69A66458BA31015ULL,
		0xC441C2C746F0DE2DULL,
		0x2C4E98117A59A2EDULL,
		0x715D441C491A7BAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAECF53E20D0D7AE3ULL,
		0x37A7A7601A5D01E0ULL,
		0xA049AD2D58AC18E8ULL,
		0xC4632F45E12D5C07ULL,
		0xAEFEE7AFE80D8D68ULL,
		0xC0AA1EFD68E35072ULL,
		0x324AD5AA211FF287ULL,
		0xE92CF8DBEEAAB96DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC908D0C8168A1758ULL,
		0x0054D048D2526E2FULL,
		0x011713DE4B4B901CULL,
		0x6BE3B2E00D077CA8ULL,
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
		0xEAE5F9DFA126CB81ULL,
		0x2FF0952D9973120BULL,
		0x413023919A1E4F6AULL,
		0x3EF2877E79DC728BULL,
		0x936E6C00671517E1ULL,
		0xED4FEE143B5C2A94ULL,
		0x69BFCEA9C0D345CCULL,
		0xB708A1C50F3C32B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA99C84FD034A7407ULL,
		0x0A9248B61284D88BULL,
		0xCBC0BFA13B7B8BCDULL,
		0xCABFC0AC9BAB40F7ULL,
		0xA40CDCF9DAF11F98ULL,
		0x4BAC60D2AF3AE247ULL,
		0xBD1E7D52B22FD1CAULL,
		0xB89B738E9EFAA483ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9C4AFDB6B33322AULL,
		0x23A5443253DEF4EBULL,
		0x156176DC8AE5FC01ULL,
		0x3867A2E687EC4C35ULL,
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
		0x13E07A5AF7494E62ULL,
		0x79C5DC70A170B972ULL,
		0x8017C50C4AD9B422ULL,
		0x69F5C17CA3CAB0D2ULL,
		0x2589A7D810F53F8BULL,
		0x38A739A1C2D09CEEULL,
		0xA88B4473C8C2A5AAULL,
		0x3383EA1783F81732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E001C33A37698CULL,
		0xC29C446642592EC6ULL,
		0xAC1A9EB3FA1943FBULL,
		0x6698C72B23B3E02AULL,
		0xDC8BC643F7C35610ULL,
		0x18D9A464E34F10B3ULL,
		0xAA4889B122A61155ULL,
		0x2022ADCDB443273AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56AFF4937A7A8D77ULL,
		0x6FADBF138C525B52ULL,
		0x91E4DF3CF8FE74C9ULL,
		0x63CBED4654F26F77ULL,
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
		0x9342AC85821FBB26ULL,
		0x8535B7A8C841763FULL,
		0xB9A37C5D7DA1D61DULL,
		0x7B89EC2338B2190FULL,
		0xE42E1A9ECADFBD5BULL,
		0xB89F059258B92E26ULL,
		0xC18D063A24D7D981ULL,
		0x9FDD46CFB3167750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2A052B3B6B45478ULL,
		0x8B13E1F22B806184ULL,
		0xA9469A697C83FBB3ULL,
		0x18FB352AF62D94EAULL,
		0xBC17C2CA7B9E16B6ULL,
		0xE36EB6FD6DC2A4B2ULL,
		0x74B667C599309338ULL,
		0xF81D188F49B8AAEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3F363558F2A213EULL,
		0x9F4D7FD17D597BF8ULL,
		0x78386740BBF24939ULL,
		0x49159487E670DB2EULL,
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
		0x9B61C862F61A0692ULL,
		0x667E58302037A8F6ULL,
		0xDC30A5637A7FF6AEULL,
		0x1963CF5C83D483A1ULL,
		0x6989499D92469F5CULL,
		0xB80034DC8EF4F61CULL,
		0x98D76DB99EF0C20CULL,
		0x8736CF6769D8E5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342667C436C1B0E0ULL,
		0xF3F8C1364A78FEFAULL,
		0xA461C07BA0061E73ULL,
		0x436C7C7F993A0A5DULL,
		0x6ACAAD9EA834ABC7ULL,
		0xBBC3D4BC914A2C6DULL,
		0x708B936093E9ED97ULL,
		0x379B14562F1D2A3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x378688757E027F85ULL,
		0xE37BDBB97D1899F6ULL,
		0x33114E1F7D7D6197ULL,
		0x2715176BA2785486ULL,
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
		0x32BB6AEC945327C6ULL,
		0x18F7C0074361D2E3ULL,
		0x054C817E7F185BBCULL,
		0x699A1A2479286CDCULL,
		0x1F8C0A6309288DB6ULL,
		0x85BC6626288746A0ULL,
		0xDE2702E32BA42E62ULL,
		0xEFFA39F3296028A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DF5104A11F30547ULL,
		0xBD14763F08D37FAAULL,
		0xA20DF6A2662D22E9ULL,
		0xA1667DCC12294D51ULL,
		0x25B2A384F95FDE1EULL,
		0xA7AD0B54598D596CULL,
		0xFADA2EC592219424ULL,
		0xD072F1D1E07F8389ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB0B9F98DA2A33A7ULL,
		0x522AC4ECF3A788EFULL,
		0x20A60740E24E1E01ULL,
		0x764851493857A246ULL,
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
		0x7EF77DDEB46DA9EFULL,
		0xBA721D95AB03247DULL,
		0x962101292E7D1DEEULL,
		0x9906C667939FE042ULL,
		0x2D75F22CCCBB77CFULL,
		0x30888D79EB422C56ULL,
		0x975F6CDB0491B434ULL,
		0xAE2D894B6F3156E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128770DB92E0EA42ULL,
		0xF14D4185C2E07B2EULL,
		0xE8C6645B934B2699ULL,
		0x34BA6090519F06B8ULL,
		0xA26C878444818D17ULL,
		0xDF2AE9F1A3524C01ULL,
		0xF8967675FC18E582ULL,
		0xA1D5A95AB770E60FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FD5E2075A259749ULL,
		0xDD0B224A95BDF5DCULL,
		0x3F2F2FCCDD20A5A6ULL,
		0x3957A392889199B1ULL,
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
		0x7E291F096A24185BULL,
		0xC89087270AA2C79DULL,
		0xCE5A2AC14BAEC711ULL,
		0xA52312626F7E88A1ULL,
		0xBBF52433E1A0D202ULL,
		0x6122AC95B2B4E7D6ULL,
		0x4BA7FFBF7886EE21ULL,
		0x9571AE0952E99FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7310FA1EE04B3B8ULL,
		0xCBFB6D245B97AA10ULL,
		0xC9C345996FA7DEB1ULL,
		0x4C8E53B966949821ULL,
		0xA99FC0D67D3EE17BULL,
		0xCB462BED04674891ULL,
		0x05C1E8F4B7164CD4ULL,
		0x2BCCD904F1CB90BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FA4CF4462A91B0DULL,
		0x3B50330C8E90C1CDULL,
		0x64BE474092BED9BEULL,
		0x070C5D4F73602F70ULL,
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
		0x54BC380B641CE126ULL,
		0xEB41614102EE4793ULL,
		0xDB24B7BB54CB2E96ULL,
		0x5157888D2CA24F78ULL,
		0xC5A9E85648AEC34AULL,
		0x68CC5AB498D1DB99ULL,
		0xFF1780A33B439B82ULL,
		0xB02B1D6A22B4E1CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB17849CBA7DEB0ULL,
		0x2C4FC95D8024F912ULL,
		0xE0AFA15642FB45B8ULL,
		0x6D0DA0386F3F8503ULL,
		0xF23B381D6CD66F40ULL,
		0x1F58644DAD35B25CULL,
		0x6FA7929F0B3078EFULL,
		0xC94EFF77D4E15451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9978E8323A917B5AULL,
		0xA6282B2A7BF76D88ULL,
		0x45126B0434A70ABBULL,
		0x28F65A4C4AC9CAF2ULL,
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
		0xA8285F8908302DA1ULL,
		0x5DD017D929F8B1FBULL,
		0x5D0BB01E119F79EFULL,
		0x317FA2FF26CC042BULL,
		0x5A6C8181018D1884ULL,
		0xA09606A47409D66CULL,
		0x21263F364CD60344ULL,
		0x256D70F031B7DE4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB87A751B6A37103ULL,
		0xE8EE3A370DF9690FULL,
		0x43E6A748624B940BULL,
		0xF96F8BAF800E0DBFULL,
		0xCB0E0EDC2F64A8BEULL,
		0xFFA08FF9C55BD270ULL,
		0x3D432C88DFDF41B9ULL,
		0xD9460E63CBCB73A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A5BCAE838D4FEDULL,
		0x59517AF809D3E043ULL,
		0xECD9CE93DBF4A077ULL,
		0x05E8B826C7D5CC15ULL,
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
		0x9ACD1C3029E42E47ULL,
		0xD1FCE781CE56DB3DULL,
		0xC65FDE051E2AFD4FULL,
		0xB183A733E47E4D81ULL,
		0x3FB392E0E0DC402DULL,
		0xCAA63497E12A7899ULL,
		0x83872188EDC88CF0ULL,
		0xB1BFDD8FED4AF0A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB13033B1A297CA2FULL,
		0x7C214560097AADEFULL,
		0xDCA97445E6A79A37ULL,
		0xD4D36BD9ABE66E78ULL,
		0xEE15024D75002776ULL,
		0xD41B51EF1D169C8EULL,
		0x6743C63CEEBB3A3BULL,
		0x34AA766EF2903621ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07265E6089F811EEULL,
		0xEE79472EDFCED6D6ULL,
		0x1BB5F707137DA9F4ULL,
		0x6DDD8A3F704F8E59ULL,
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
		0x0FFB6355BA6B30C1ULL,
		0xF7410A5A83892D61ULL,
		0xD9A45AB601D8F256ULL,
		0x4B315B7947610479ULL,
		0x1597D15CE06C5EA6ULL,
		0xB6453016224638E2ULL,
		0xBA3F84F0463B6D2EULL,
		0x402736F97A98946CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC254472F430829CCULL,
		0x30F72C0E1F8D74F3ULL,
		0x422F259CFC4FD38BULL,
		0xD36FD00853931BC1ULL,
		0x466FD4E5692D095AULL,
		0x94A1803C80F09956ULL,
		0x2946F6D91A4014E8ULL,
		0x4F2F8D6503757ABFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D9695E22AC9AFCBULL,
		0xC495F89A56B1672EULL,
		0x1C5A4C898CD83934ULL,
		0x3C84B77AA303B87CULL,
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
		0x9024CFD2D5ABACCEULL,
		0xF5CBDF5C96973DF0ULL,
		0xD6A65E358DFCFB2DULL,
		0xE4DEBB4D5DB45A19ULL,
		0x6AE85892E2846222ULL,
		0xF87540A7825A84F3ULL,
		0x474D40F8FF78B525ULL,
		0x7B09CACBD57A172FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7711FBFC706A1A9ULL,
		0x883047476195EDB9ULL,
		0x02973B85815C05D2ULL,
		0x85482386C95D18ACULL,
		0x8032AFDD6FB1F065ULL,
		0xC98548027AC3F898ULL,
		0x08D056773B60E1BBULL,
		0x54731A3EAC45896BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFAABB0219E1EE17ULL,
		0x653A8094555A25B5ULL,
		0x1A99F1F3282A571EULL,
		0x19F4CCBAB2244C8FULL,
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
		0x0E4056A468A750B6ULL,
		0x24082287F8EF3A92ULL,
		0xCE5EB3D523C5769AULL,
		0xCD3279D159D60EA2ULL,
		0x77D43292E066C341ULL,
		0xB0EC692791D27B61ULL,
		0xE67390F2F96E42ABULL,
		0x8B57B96DB78ECCDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ADAB5A007B1CC3AULL,
		0x483BEF2E5A4F6C3BULL,
		0x707D0393A352DAE4ULL,
		0xFA4647003AC18A58ULL,
		0x4902863F4838E28BULL,
		0xCB8184D07139534CULL,
		0x811586CCF4325D0CULL,
		0x51A8EDE9A7709CA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD685356CF7C4E0B0ULL,
		0xE9AA1848755BC17BULL,
		0x69D731E64756B14BULL,
		0x62DE686B838FAD67ULL,
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
		0xD1048E6DFE963386ULL,
		0xF6D72287B8FADDE1ULL,
		0x56CF0452C3FC3257ULL,
		0xDF42C87CA71E192FULL,
		0xA24A6C490B9740E7ULL,
		0x3856E68E294981E2ULL,
		0x9A210FFC0D05EDADULL,
		0x418A64B8AF4A12D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7D4AB346FD13A0ULL,
		0x43E27235E9BB40BBULL,
		0x2CA45BAA22B9D37AULL,
		0xC845CDC8403BF228ULL,
		0x31D557FE8B8AA1D6ULL,
		0xC5E5E58333737A7BULL,
		0xE5010648B46AD710ULL,
		0x4E4120144962AC33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83E846C9B978BC20ULL,
		0xAFBAD7F24D04B680ULL,
		0x0CEC1947C847BA16ULL,
		0x33DD2B1B873B62E2ULL,
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
		0xA8FCAF8D4930290BULL,
		0x0311259EF9A47C76ULL,
		0x8AB4F05010BB1ED9ULL,
		0xF601982351AB0A04ULL,
		0xD9F4F48835528CAAULL,
		0xFE16C073BC4C7B13ULL,
		0x9A87192FE0D19C8CULL,
		0x47EA6E90FD466F7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0127D9E7B0BF61C6ULL,
		0xC50AB580B69059CFULL,
		0x0388D0BCA4CBF1DEULL,
		0x34CC7A450B3AF939ULL,
		0x95E54079A86EF6D0ULL,
		0x8676D166996210D6ULL,
		0xD519313D693388EDULL,
		0x04FF2092DC4C117FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2298FCE82390730ULL,
		0xFFC3EC1171DFE7BFULL,
		0xD57C8D912D6616A5ULL,
		0x3022B1972B9A04C2ULL,
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
		0xAB6E77CC21429C03ULL,
		0xAB896B0496B0E7C9ULL,
		0x8A0E68E7A35AC322ULL,
		0x957BB6BE89F9862FULL,
		0x85F6D795AA8B71DDULL,
		0xBA8B57067EFAC732ULL,
		0x79B49A3BBDB81D59ULL,
		0x069497673C288BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE923D32226D7296DULL,
		0x0CDD17FAA58BA578ULL,
		0x7956842B1A517754ULL,
		0x401765845291C260ULL,
		0xEF0328D2820C0BB4ULL,
		0xFBA2203B3F8ECE64ULL,
		0x2BACB236EDC8E441ULL,
		0x07DABFF5039FC024ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A7695A1FD549CACULL,
		0xF54A75355B2C30D5ULL,
		0xA5E45573668BC554ULL,
		0x24FA4C2E9BB60552ULL,
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
		0x5AD72E072B97CC5DULL,
		0xBE4842568F310C14ULL,
		0xBFEADE7084BA7B87ULL,
		0x7B57C075208EB894ULL,
		0xEDE52AD8631135ADULL,
		0x1DC633B8ED9C83FAULL,
		0xB65E5863FC3D955BULL,
		0x29EABB783E8D9128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67208A56BCA2DF33ULL,
		0x0C852042E4B50FECULL,
		0x606145219881F3EFULL,
		0xEEA462A5AC306A14ULL,
		0x9D9035517DD6FBA5ULL,
		0x39966542F74574AFULL,
		0xEF2A79BF227CC60FULL,
		0x21BC67B12C652E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE05315B675998A6DULL,
		0x90DBC7963B684155ULL,
		0xF13CA5C73ED74CDCULL,
		0x4393CD5C265CFFB9ULL,
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
		0x97DF81C968369046ULL,
		0xFA70C16565BEC58EULL,
		0x9D713DEC243772CDULL,
		0x8E0215E1F6EB075EULL,
		0xC5A00B5BFB3363A3ULL,
		0xA887A14C33522323ULL,
		0x521044B2DB44E1D2ULL,
		0x03F3A83CE55585B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3623B08A42D42CD8ULL,
		0xD79E852F01D1F2ABULL,
		0xE3F1C79466A6F7C8ULL,
		0x8BC8214256BEF0E0ULL,
		0xA85C0275BC8F5B35ULL,
		0xD133D925D46FB728ULL,
		0x5E5ED3F4AEB39512ULL,
		0xC4635BF0E896AD18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9D5236C71BB9F74ULL,
		0x1941F1E87988DA29ULL,
		0xE5D632925B21DF7FULL,
		0x71A547E724803D57ULL,
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
		0x9BDBC937F76FF42AULL,
		0x262725D50B7364E5ULL,
		0x375F1BCA1B60E3EDULL,
		0xC590D63FD61FFFB8ULL,
		0x1F2AA466D4B7934EULL,
		0xF338058A58A04FBFULL,
		0x256153B866392064ULL,
		0x04E62A7B2F4DC07FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x410E67C6D9DE807DULL,
		0xAC5C2ABC8EF01D0BULL,
		0xBF5C67B46519E965ULL,
		0x1728A471AC6ABFBEULL,
		0x99332F3FECB7A075ULL,
		0xFC7CE322EDAA40DCULL,
		0xFAE494659D6A74C3ULL,
		0x53CC2F4046FE2270ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D88C5378D8F7E2EULL,
		0x199216725D097D7AULL,
		0xC6871A5F84F4746CULL,
		0x78437C8CA586B613ULL,
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
		0x1E3E5B8EA7A6208BULL,
		0x240C8174ACB52442ULL,
		0xDE6890152911F02FULL,
		0x4F2C1B9C24314DAEULL,
		0xA17D852D1D9FE52DULL,
		0x30633A20C617ACFAULL,
		0x784E11A54E4F1C68ULL,
		0xF3EA94A77FE1CAE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FE2552D42E7D4ADULL,
		0x559A604FD1A1F4F8ULL,
		0xCB11965BFB6FCD63ULL,
		0xEC44927AA40F758BULL,
		0x7437BB046434362CULL,
		0x5FFD21866500FBB2ULL,
		0xAC6DD42F0E839975ULL,
		0x59BD8C0C577EC42CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66B8086CEABA4948ULL,
		0xBD99C80F44718000ULL,
		0x56A01946A5D792D6ULL,
		0x4596D0297ED4D791ULL,
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
		0x01DF06D74C85C665ULL,
		0x17D7AF9FB9A0232BULL,
		0x1235B455754D40DEULL,
		0x9587FA5B74F70E87ULL,
		0x2C86CA045E12D551ULL,
		0xE622F56ADC0708B8ULL,
		0xD589920C11D799ADULL,
		0x8E85189546B13FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00CD15B702CF7E7ULL,
		0xEB8CCEB67C48AA88ULL,
		0xAFFC153A38493CB3ULL,
		0x7A2BE04CABAD10AFULL,
		0x333DAC44A03E8351ULL,
		0xCE3F9FF61039D55AULL,
		0x93B638AC3016D4E6ULL,
		0xEE6EC7189CF11D7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12AC9FF209DCF857ULL,
		0xB809903F7DCD1895ULL,
		0x2798E356BFA139B7ULL,
		0x5EAC328FFBCF1905ULL,
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
		0x7F482A91992D773EULL,
		0xC033C8B56A3F032BULL,
		0x6DBE9C93427C82B7ULL,
		0xA66F2BD54ED98DA3ULL,
		0x708E8E7DECCEBC77ULL,
		0x9BB6D6ED5496A066ULL,
		0x70AFC5BE70A8E78EULL,
		0x69CBEE135E8EEBF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A2FFD72F606A62CULL,
		0x3348D8C15871BB44ULL,
		0x708EDE50F1ECB4C6ULL,
		0x52A0A7FB3CDE62D5ULL,
		0x95F397C64C3A97DAULL,
		0xAD8032F1E8BB408BULL,
		0xDAC1BDFDCDA02C4DULL,
		0xE8C91470D913EF6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5818CC6079243D8EULL,
		0xE9074746145D8263ULL,
		0x3E84E4DA83DB9994ULL,
		0x7A3AD1F9E23CA7ACULL,
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
		0x04089E957E070A37ULL,
		0x55DF77ADB18BA1D4ULL,
		0x0D946DF0DBFEEABDULL,
		0x9603FE1C23EE40DEULL,
		0x665D47EE8B491AD8ULL,
		0xC03E6CCAF02FE178ULL,
		0x3DBA5FA97E0FEC1FULL,
		0x97A59A1DA6223621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8FF7670D6DDBF75ULL,
		0xABD1073D7FCD356FULL,
		0x2DD3568DB0D560E1ULL,
		0xB0F9515861DFA938ULL,
		0x9A640784A0E74678ULL,
		0xF17809B184206CE7ULL,
		0xF474C7122C5C098AULL,
		0x838E757877F35CFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5208B7DD71AED161ULL,
		0x5B8126363C09B9E2ULL,
		0xC015BDD94BDD2BF2ULL,
		0x607A1D489D02D354ULL,
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
		0xE39897178E936A16ULL,
		0x3850CF15B4B34882ULL,
		0x8E7A3E8F951244CEULL,
		0x526FAB1EB94A898DULL,
		0x84636D390BB134B9ULL,
		0xF8515BC2A40D1B85ULL,
		0xB6F1AC1544DD42FEULL,
		0x78E8018777B5C9FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5975C079D3C821ULL,
		0xDC7AF9B8DFF2BC2AULL,
		0xA8D3D577B5BFD7A7ULL,
		0xA60AC6B3F6800E62ULL,
		0x425E22C61D953C9CULL,
		0x306CFA4EACE5F498ULL,
		0x5D46865E164BD592ULL,
		0x9F51051999F26D1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16082E666CE6754CULL,
		0x07BC4C9384905390ULL,
		0x350E0248C8E8AB4CULL,
		0x78CE5CB9ADCA4452ULL,
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
		0x6E7430AF568DA38DULL,
		0x43FD8ACCBAFFE415ULL,
		0x3A4BF717D4F35652ULL,
		0xDA308D28E1E97D40ULL,
		0xED66C7FA1D3A708AULL,
		0x11AD7D1BC7B19B12ULL,
		0x932D663EA01126CEULL,
		0xCE671BE087B84C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EECE40B6AA3C36FULL,
		0x4CF69828215AD952ULL,
		0x49870BAC631B3FD4ULL,
		0x0843564180ECE960ULL,
		0x65E6D6F529FAA0A7ULL,
		0x52E3FE260067E28DULL,
		0xAA7392740060CDFCULL,
		0x011A304CABAAF3AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C8513600762C06AULL,
		0x48EFCB202E966E95ULL,
		0x7C5A5B7F260545A0ULL,
		0x4B582EDA0AF7C0A8ULL,
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
		0x001E023881C142AEULL,
		0xA1125050343579C7ULL,
		0x3959F4C0E26AE0EEULL,
		0x7E57197BD69D42A4ULL,
		0x6F9423B96589E879ULL,
		0x6FB0F1CD7EE3BB3EULL,
		0xFC4657AF03684617ULL,
		0x32C0D5FA51AB8479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA42638368815F864ULL,
		0xEA524FAA7049D858ULL,
		0xBF35D00C276BD27DULL,
		0xFD247796A8982BD1ULL,
		0x4C5E9ECE55423C9DULL,
		0x0B4CE18BB23CC21AULL,
		0xBDB5C8E874806231ULL,
		0x6F5E2012B3649547ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95E984E6644ECB89ULL,
		0x9D9A6A6A24B49CCBULL,
		0xC399562DF16AE2A3ULL,
		0x01D9A246AC8C9847ULL,
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
		0x872504753AF2D15FULL,
		0x2AC1B57E76482805ULL,
		0x1079FFFAF1F05680ULL,
		0x31AE51533C3856FDULL,
		0x6D3F4E60FEA6B477ULL,
		0xC707520ADD087E8BULL,
		0xF8706547E401D4F9ULL,
		0x26635233E24FEFD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x609973E68484A44CULL,
		0xF9AEDBE4377C4C0AULL,
		0xD96CC0E3EF146929ULL,
		0xDE0F01828A307880ULL,
		0xD074DF03A76DF993ULL,
		0x3FE66BB8F5C460D0ULL,
		0x3CF7143695C8D001ULL,
		0xBCF67784A568DF93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C981869A8D9E76EULL,
		0x3FF509C292E845AEULL,
		0x0B0F47A89F52AA3AULL,
		0x79C7C5D3BC5448FCULL,
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
		0x6202C13EDFBE1E09ULL,
		0xF7B6D6E3BFF49070ULL,
		0xD3A4C7CC1837B153ULL,
		0x80A37ADF042F0A1CULL,
		0x425BABE4FFC409A0ULL,
		0xC6C0E6B499C8590CULL,
		0x917FD31209258F1EULL,
		0xD573235B6636FAFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB461C1C6DEDC614ULL,
		0x154130789DD3C01FULL,
		0xF4873F3E7F24743FULL,
		0x1C737547413ECE03ULL,
		0xD34D67E90E39E70FULL,
		0x59C18956CC5D0F98ULL,
		0x2395CD293FEC1C46ULL,
		0x152AAE75A3F37090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22DABC884C517DB6ULL,
		0x105D8257A00DB773ULL,
		0x2FDA691B779A4935ULL,
		0x6EF15FB298F6C857ULL,
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
		0x279C6F9714EBBBA3ULL,
		0x2C869858760F354FULL,
		0x9587471B0BA8F578ULL,
		0x22B7B2F659194905ULL,
		0xFE1ACCC907EEBDC8ULL,
		0x7D6FE7F1EF14908AULL,
		0x19B767478D9354D6ULL,
		0xC28801D02DD3EBEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCB04265B1AB687EULL,
		0x82170243FD70DF42ULL,
		0xF4AB8FBDFB51A32DULL,
		0x8ADC9287807F4565ULL,
		0x80B77966B76BB566ULL,
		0xD68E8A36373EB003ULL,
		0x61885B7F403F8F08ULL,
		0x6AB40104AC406738ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7AA8DC956B3938CULL,
		0x6FE37FF1C25DAA28ULL,
		0xF7D777188AC6AED1ULL,
		0x21533EA4147FB672ULL,
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
		0xF628FF3C02E90C00ULL,
		0x4D1667F53054422AULL,
		0xCF57492A6D8289C9ULL,
		0xD0A62DB9E305EC2DULL,
		0x6C389B478DACA11AULL,
		0x08B9FFAEB9B65FC5ULL,
		0x66D3158CD3E0293EULL,
		0x03739DE45567F077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1316659D201A53ULL,
		0x269E273C8375646CULL,
		0x82C21DF52DCDB5DAULL,
		0x2049AF9111E11562ULL,
		0x27209C7ECF2B7D26ULL,
		0x0858FA0709B8B00BULL,
		0x633E20C5448CD8C1ULL,
		0x9F0CAD103A40414EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA5BAA2ACF4448EULL,
		0x34DF179CCC86F364ULL,
		0xD4B180D48612C67DULL,
		0x17A43DA4D908D6E1ULL,
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
		0x87219D46EB32979EULL,
		0x13A54A5E0221E9CAULL,
		0xBAE9A5C617C58002ULL,
		0x380F57087AA4EC48ULL,
		0xCD5890BC7D2F682CULL,
		0x2702FFE07212348BULL,
		0x65E58E4E31D5CB59ULL,
		0x599BE07DC815B104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB469406127227C05ULL,
		0x755BB3AAF1630E3BULL,
		0x33A829CF1AA50531ULL,
		0xBC102D048A6E64C9ULL,
		0xA3147075E2283B94ULL,
		0xEC6F595FFBC99757ULL,
		0x10C4F6E8C3B0C2E8ULL,
		0x3D608F6CA25FC1CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D52760C720BAAEULL,
		0x50344DC49F86314DULL,
		0x2A17F505569FBB79ULL,
		0x2CCD328F8938096AULL,
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
		0x33AA1D2CD6AE0555ULL,
		0xC39D0002949690C4ULL,
		0x9D37645ABD2204A3ULL,
		0xF1AE3FC8C96C9C02ULL,
		0xADA7400EBF4310B4ULL,
		0xD9779BA1EEB005F9ULL,
		0x7F60ADD2634EFE91ULL,
		0x6D2A60460C56B574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F822A1C887C207ULL,
		0xC494BA5EDDD79EC7ULL,
		0x015EC8F898BC4077ULL,
		0xB296221BD64F4BC1ULL,
		0x9715731D7AA1BC5FULL,
		0xFB7C43378ABFC439ULL,
		0xA55DF6DCE43C7BB4ULL,
		0xA8FF74B0CA41AC9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B56665B3E18C696ULL,
		0xF257656E8C68B480ULL,
		0xF83FC3D3012530F4ULL,
		0x5D7715D4C23CA071ULL,
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
		0x67B080B1C4F193DFULL,
		0x6043DA9FE0226BDBULL,
		0x2645872FA38C1153ULL,
		0x4A67B3EFE08738BDULL,
		0xA3C46DBA2CBA530EULL,
		0xC708F0D951B3C59AULL,
		0x20E97E4BB716C69DULL,
		0xFEF957A2D0A93743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x809C4952A778C03FULL,
		0x29D3F941FF6D2588ULL,
		0x8FE1128F5A7E0259ULL,
		0x377877F847EFA75AULL,
		0x21B5750BC9732E79ULL,
		0x50C3F38B3AD136E6ULL,
		0x585AA580DEDEA69DULL,
		0x03A3DB36D6F20D40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x354D2141DA08473CULL,
		0xC4AD7AF54656751EULL,
		0x5B98A2BC6162CF0BULL,
		0x619FB3FEA9C7CDCCULL,
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
		0x7E99DB5BD205F5DBULL,
		0x44A156212181C6CAULL,
		0x0AACCFAFD60F38BEULL,
		0x129062C2FBF52A9FULL,
		0xC7EF0FD23BE11819ULL,
		0x2C69FD418D18A883ULL,
		0x17DCFE820F2A5C28ULL,
		0x23C2896ACA1EA98EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6473B5D0B5A77D4ULL,
		0x2FA9CB7544A78CAFULL,
		0x6FFD19D46FDE0409ULL,
		0xDC60588BF8EE41A5ULL,
		0xEF999EA3D21C6B4CULL,
		0x5A19389283C3148AULL,
		0x7529B435A2C43DE8ULL,
		0x5EB2C922BEC12CC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5016CE279DD22F9ULL,
		0x4CF4BCA73F8E310AULL,
		0xC14CBD337D59B22EULL,
		0x768694E8B2E76EE7ULL,
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
		0x51F735081DAF9937ULL,
		0x29C723A83A34F19CULL,
		0xE12172B778B3BA3DULL,
		0x15D2CC8F361A55FAULL,
		0xC3670109CAD1E658ULL,
		0x1FDDF0B62FDBE0F5ULL,
		0x1D70A75D5D1CC781ULL,
		0x4578E2E01681DE7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D04C3F58987F69ULL,
		0x31500C8816491FAFULL,
		0x4D1B1245984DFDA5ULL,
		0xD6A68E20B16CA883ULL,
		0x10574256A6FC68D4ULL,
		0x622F1D98EE9D9C2EULL,
		0xB28ABB9DE4F23DADULL,
		0x2A33BD5DBB441F5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C7D376016C7BBD8ULL,
		0x206A6D77D32A0791ULL,
		0x72275EDDB6B63206ULL,
		0x4B6FCFC80FD80B89ULL,
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
		0x0F474C791F69BB6AULL,
		0xEFE34D81A5F2CC2CULL,
		0x6FD93C1140D826F9ULL,
		0x20F987F7233D6136ULL,
		0xA50F570382C28FC3ULL,
		0x6EF3719F3C1F7BBCULL,
		0xA10373AE425C7FBFULL,
		0xE643543759EF4459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5875156884B52597ULL,
		0xCFDB87BF901087DDULL,
		0xB4F298B9BA8D43AFULL,
		0xACC3583D95A915B5ULL,
		0x9329CDF75DE6B037ULL,
		0xB7CDA02C3C08605FULL,
		0xC3A597E9AA3D343EULL,
		0x391518C6840453DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EE48EDE1357C851ULL,
		0x4FA4DCD41950541FULL,
		0x96D542861AF01865ULL,
		0x291302794E73FE09ULL,
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
		0x0D32C44499D29C6FULL,
		0x61F0AFE1B1310BDDULL,
		0x55583FE59E89F281ULL,
		0x40E5C4F8F3C8F08DULL,
		0xB5F000AFB91DA5ABULL,
		0x760B09F2F2A6796AULL,
		0x6816617E7BBF5795ULL,
		0x2A0162A33D00B0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B572BAC94E34BDULL,
		0x6999EA9D0855BC91ULL,
		0x852414C399025EB0ULL,
		0x2C9762FB1B90DE46ULL,
		0x69AF414AEF4C374FULL,
		0x81E965D75FB10C99ULL,
		0x3B517B02587DA632ULL,
		0x4E6A2847B2A4E591ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B19BA7FC59AC889ULL,
		0x3555215C7949765CULL,
		0x756E618F4147E881ULL,
		0x2CC10B9461D838C1ULL,
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
		0x15627360295A7914ULL,
		0x0AC3E0925EC4204FULL,
		0xE500062CD2E32F82ULL,
		0x96571FEDB47D0E70ULL,
		0xC36F2FE3BE85A86CULL,
		0x30A18990663CCE70ULL,
		0x5A73CD042F97F2FEULL,
		0x74F462A92D0EA55EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44280D579F9A1771ULL,
		0xC2B75ABAF3989C9AULL,
		0x4D8BE9DEF95BFD63ULL,
		0xCD990E465A686A42ULL,
		0xFDD6C5657F33D776ULL,
		0x674EFEB81A109C6FULL,
		0x23F3F8C652110C0DULL,
		0x09207E805ED630D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25DA34C5EFE56874ULL,
		0x2A4D21F2B9BAEFD2ULL,
		0xAE6D9D7CBB8D79DCULL,
		0x4A31EFB5F675F14AULL,
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
		0x2E40F05399FAAE25ULL,
		0x00D53553B1B93106ULL,
		0x003AD6BD5ED1CFCAULL,
		0xD840511E37452129ULL,
		0xD65ECB957C78A470ULL,
		0xFCD5B894702889BEULL,
		0xD3B197D76955C415ULL,
		0xA4C0460A18F7FAD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31574443A0FD9475ULL,
		0xC86507CAF5533FA3ULL,
		0xB738DBE47B12EB55ULL,
		0x448B96DFAF5D9147ULL,
		0xDEBBFA83E3867A77ULL,
		0xF26045520FB44F06ULL,
		0x146A6C42B352C51EULL,
		0x7C656FE1E8A9F3E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF14B4ACACEF559DULL,
		0xC5DF49630DA6A8B1ULL,
		0xAD9272EBE830BD1FULL,
		0x11308435B37C980FULL,
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
		0x5A0A9988CD13DEE5ULL,
		0x81C2174F0725D8DBULL,
		0xB78FF074DD7D798DULL,
		0x7F8C5983DF8C0C50ULL,
		0x6CD48319EA71922FULL,
		0x48E3477B358D0B69ULL,
		0xB94F1ED5D9CDC1A2ULL,
		0xAE6D7B61A1AC1C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x652B6C4265B6C44CULL,
		0xE8E53C5EA2F88D17ULL,
		0x63E2E7F6E70D6993ULL,
		0xBFE24F14EA71BFFDULL,
		0xE8D58A41149CE8CBULL,
		0x529167248BAB063DULL,
		0x99D2B8C12E18FCD7ULL,
		0x43C38D2C8311C2ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CB81D7624EE41BEULL,
		0x290427CD9BBA1039ULL,
		0x00242F8F7345461AULL,
		0x14E366518003A1F6ULL,
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
		0x078207512BFD4E8CULL,
		0x3A968BA65FD75608ULL,
		0x8EC3B471E94CF08CULL,
		0x1968DE017C7796F7ULL,
		0x09DCABBFC97A2FDFULL,
		0x11AFB372F639B194ULL,
		0x6EEDE85704A60160ULL,
		0x002E5F5AC78CB939ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49B26CB71C28961EULL,
		0x02D3E1EB73D2B83BULL,
		0x4A63B01DC492DC5FULL,
		0x5887CE3458C89343ULL,
		0x4FCA9344595748D1ULL,
		0x014B4B4B8A033513ULL,
		0x04A48B304FC6CA77ULL,
		0x96DBE1302C5CE773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C7F3CECB5030118ULL,
		0xA6AA1F94FC1B18E8ULL,
		0x0B43D812FDDC3AC5ULL,
		0x631FCA202CC82728ULL,
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
		0x64DF98EFEB3FF745ULL,
		0xE25EEFD50572911BULL,
		0xEA2E5EA24CCBBAF7ULL,
		0x7CA4191B1E7CD666ULL,
		0xF36B05FD200CB721ULL,
		0xC912807A88AB7610ULL,
		0x8D3EB81268A34A57ULL,
		0xAB7DC80BB8F35EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9B4FE696AC5AE8ULL,
		0xF99D2989FB73488FULL,
		0x3DAACD4C3BB287E4ULL,
		0x05A3465B9AD6AEA7ULL,
		0xF1952AC489AC655DULL,
		0xC9E93A96C09D61C5ULL,
		0xF7B908BA02737F7CULL,
		0xBB590AEFDFE29011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD02D36FA6DFBF29ULL,
		0xC8E2261ABC164BADULL,
		0xDE5B98753C314F94ULL,
		0x1C74E4E1BC24D9D1ULL,
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
		0x330A584B7FA9C87BULL,
		0xE3B3C27F5BF9678BULL,
		0xA1EC644C2718B4D2ULL,
		0xAABE4E4994CCB479ULL,
		0xF1C9FFF558F64414ULL,
		0xAE5655A1C5B328DBULL,
		0x5DA8579BEEC1CC7EULL,
		0x60F3BF4DC9C8365CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C0598C1956834AULL,
		0xDD4BB6E4DA4B5BF5ULL,
		0xD7E745465641A964ULL,
		0x81DF3658CA6F1850ULL,
		0xE44964470BDEEC6BULL,
		0xBD27A4EAE68E8DC5ULL,
		0xA8615E4491C69091ULL,
		0x5A79D645AF9EE4A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D611A9ED7CA486DULL,
		0xD35646BFA11D10DCULL,
		0xB28E21FD9E21F099ULL,
		0x1EF7AF24AC7FBD21ULL,
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
		0xFAB5A9521E4389F2ULL,
		0x468F66DC38748304ULL,
		0xC69EAA1EC02EAD2BULL,
		0x59FAD7A8C9539E11ULL,
		0x15A06E8723E30F23ULL,
		0x0C1FB5A21FF69D56ULL,
		0xEB42F7AAADAA2FFEULL,
		0xDE90AC49C215719AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF2294BBA3620ABAULL,
		0x3A79350E251655F6ULL,
		0x61629D88770BE617ULL,
		0x8DA9C431399ACA4FULL,
		0x2C173B58AB4569CAULL,
		0x233EB3B6EAC0669FULL,
		0x330F41F76F0CFCD8ULL,
		0x3868D65D09DB3AEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5F0AD7C62480DFEULL,
		0x9D7C7AB7F96A4C34ULL,
		0xBCE9053194785EB4ULL,
		0x763AD49AE85CF165ULL,
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
		0x3C2F3AF8CB2B5AC4ULL,
		0xB413894FE431F752ULL,
		0x8D4BD188B49553F2ULL,
		0x42984AB0026E7CD1ULL,
		0xEFC3CCD5DCEFDBD8ULL,
		0x7B2953BC9B7E1921ULL,
		0xF4CC03252C5B2513ULL,
		0xF81243F0FDECA246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BEBE34BE23E1A81ULL,
		0x27104869C77DA208ULL,
		0x5B01B8B439541F8AULL,
		0x4E6499A8F765ED39ULL,
		0x29C8856985D907ADULL,
		0x1F29281F21636828ULL,
		0x4EA6B0C2608D2EA5ULL,
		0x0E31CE759054FF5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x538FF1C1D650C3C4ULL,
		0x3509BA463CAA9A5DULL,
		0xDBD4537EBBD3C8CAULL,
		0x2B8521594F8ABE92ULL,
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
		0x1315044CA9A26A44ULL,
		0x3D9C232FAD43F5CEULL,
		0x1B9046B7E95FBB7DULL,
		0x14DB98EE4FAFC26BULL,
		0x18D38D8F4F93D7FBULL,
		0xFB3EDE69C745A63AULL,
		0xFE524626E19D74E7ULL,
		0xC9FEDB0E2FD9C0F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73216A6FD289BD0EULL,
		0xB6B54CD0ED6C2F4FULL,
		0x7CA6B8AE34FF1492ULL,
		0xFF96FA1B1BB384EAULL,
		0x557C0E2289F1C248ULL,
		0x8F071EA203F86626ULL,
		0x28F428BA34524C1DULL,
		0x25BE0E1A91ABB8B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EF084022D27E932ULL,
		0x972D4E05BD4F496DULL,
		0x4AE1EC2B6D88B4F6ULL,
		0x76E30AFCAED17720ULL,
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
		0x34B56401470CBD7BULL,
		0x082F2A95EA6B7965ULL,
		0xAEB90BF3EEB8E3F8ULL,
		0xFC645CA6DDC26E46ULL,
		0x1554587674CAF0AAULL,
		0x44F9BFF4E1F77C7DULL,
		0x08B6BA4A7BE2BED8ULL,
		0x42E98A1885265416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x155D2F3B2E893A7BULL,
		0xCD48605CD6D28400ULL,
		0xC03875EC8F479342ULL,
		0x89F35D445DDC74E2ULL,
		0x86C2C6EE772163FFULL,
		0x3A795019C42CAE2CULL,
		0x8D0C2A2C44CB2BA0ULL,
		0x8D12962BAAF9F3FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48F3CEF5BFAE62C0ULL,
		0xC9F764BF7FB3955AULL,
		0x49D1FA838CF12B06ULL,
		0x7059348AE27C3D06ULL,
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
		0xAA104399B84F6DC9ULL,
		0x3408010A0EF499BCULL,
		0x5C64FD8BC1834757ULL,
		0xE44801CDF16B34B4ULL,
		0x173A13A3F9AE99FEULL,
		0x08368E5B04E35F70ULL,
		0x6B5323F84E80FCC7ULL,
		0x4055CB5071CD9335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B3827722E37D759ULL,
		0xCD27685D0246BF75ULL,
		0xE61C422993A5F78FULL,
		0xE10472AA12760C2FULL,
		0x4E39B2983A10712FULL,
		0x8FE57F6D4365C950ULL,
		0xF9E108AEFDC947D1ULL,
		0xC7864F6DC4433E30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54E683E5FB91A21FULL,
		0x42E8CFF7C55222FFULL,
		0x4D38C84429222C37ULL,
		0x720FF2C9A17DC72DULL,
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
		0x270E456127631C6CULL,
		0xF8916112F8BE8F03ULL,
		0xDD069C7244474C42ULL,
		0x2D7E968DC48B6731ULL,
		0x7478E30151B7AC21ULL,
		0xE0E02959D7F3FC0DULL,
		0x58996C0888358AADULL,
		0x91360BA6F7FD1F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F01A8B60EF80171ULL,
		0x31E5322E7CCD3EF6ULL,
		0xF8674E7549C7C24EULL,
		0xC8CF130A61786778ULL,
		0xD03A3981BA19498DULL,
		0xB5B8C072A8F5F3CEULL,
		0xFA40012C52728821ULL,
		0xE0B53D803AFE84CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6959C59B99EDBB18ULL,
		0x2E85C13575A68959ULL,
		0xE5E52AACF571EAC3ULL,
		0x17CE1D4370DDE70EULL,
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
		0x71F3C0C4E38546CCULL,
		0xA24D28168B67C024ULL,
		0x98D24E05BF67C1FBULL,
		0x4C2E3069E7488509ULL,
		0xECB61F5CFABE808AULL,
		0x56F25BE41F23EE2FULL,
		0x9C63B989370B0789ULL,
		0xC6211126C309CA16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33D4589C06B8F2CULL,
		0x8167EE3617C9DD51ULL,
		0x660915D57593D9E6ULL,
		0x6580B2AE748650D2ULL,
		0x3FB510E194137CCEULL,
		0xCF9AA2A50AEE6784ULL,
		0x592BD6A5A1CED37DULL,
		0xA5E6F63F70999D01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CDEA18C607C4633ULL,
		0x37EAB93D738FE04EULL,
		0x2D14E5F870C3A1CBULL,
		0x2F4D7C11AF68E55FULL,
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
		0x47FF7F4FEE8450C9ULL,
		0x5BBAA80918DCF9DBULL,
		0x4E087C7BB1EF151FULL,
		0xD477EC321C8F715CULL,
		0x99BC17B8153A9EAFULL,
		0x5C0A68DBD6CB810FULL,
		0x2F6731DEF741EE5AULL,
		0xE89FCE053C1521F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9DE6DD8F4F15C6CULL,
		0xF58E877DA87730C2ULL,
		0x6A01F0164CEBA54BULL,
		0x1D213A2FF3464E50ULL,
		0x8BD5CCB6017A49FDULL,
		0xA78DDC10FA1AA76AULL,
		0xF953010B3250B005ULL,
		0x16B61325D3A7265FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E5033C5E81F8B76ULL,
		0x30A906A832A61798ULL,
		0xEB05CBD4A0D2B066ULL,
		0x60086F2BA99C7AE5ULL,
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
		0x717149D46A018E52ULL,
		0x57695AF83754ECEFULL,
		0x49C077872D5B5332ULL,
		0xD980840CB8AFA0BFULL,
		0xB46352D0747AA5E1ULL,
		0xE885FB5FF293F50FULL,
		0x16B300DE0C3F5B2FULL,
		0xF6FC0F42FEA5DC58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6101F854AB2B2D32ULL,
		0x4FC64127237D40E5ULL,
		0x1F14E4156701D7E7ULL,
		0x060CE1050D511A8BULL,
		0x4FEE832926ABF5BBULL,
		0x537BC6E0221353B1ULL,
		0x9EB86B63FDB0370FULL,
		0x82233ABE284A94C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9C624554B848970ULL,
		0x2726E4CA06EFA00CULL,
		0xF9DDC38FEF98D821ULL,
		0x2BA32EBF7CEB2559ULL,
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
		0x8B239526F8E7D4A8ULL,
		0xC9644996707D453CULL,
		0xBFABF72D62B8FD5CULL,
		0xA6E2DA892D731387ULL,
		0xC38969CBC1864248ULL,
		0xEC832A63FFF1C870ULL,
		0xD41456D91A2BB17AULL,
		0x76E3E51552286C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD533B820E0B850EULL,
		0x9E1945F4A031D7F0ULL,
		0x33415F3C3EDB8BDAULL,
		0x9FB078386DAC50A5ULL,
		0x1CA344C53E5CCA0DULL,
		0x258EBE262ACE00A0ULL,
		0x47455ACDC42AFFC4ULL,
		0x67B0F7ADF93A2760ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53F9D89C630428A8ULL,
		0xB39314CF739B1644ULL,
		0x7324019FE7F7D2A3ULL,
		0x48C19FA7F324FCA9ULL,
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
		0x012B33D65F6E873AULL,
		0xE78B326C333FEE35ULL,
		0xD76CF922D313F43DULL,
		0x1053762E9D617CCFULL,
		0xF578379C85DB7780ULL,
		0x1DBC941BE2F81C42ULL,
		0x380D43F089BFD633ULL,
		0x0005AF466D6BFB57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA41A479111D851EBULL,
		0xE2F32A64F5A46767ULL,
		0xEBD76F3613254353ULL,
		0x73267F2C7B7775EEULL,
		0xDF4C144EC43F9805ULL,
		0x6A71E801E33DCC17ULL,
		0x9DA5D42A944AB20CULL,
		0x9ACC5946A18062B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA79E29D00AB95E14ULL,
		0xA1AD93E333436D32ULL,
		0xD6F0214F2F520EA8ULL,
		0x23AFBAFA66E2AE6BULL,
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
		0x4B5DBE83B739F60DULL,
		0xBEB939665A8796A0ULL,
		0xDA5EDAFA94D27921ULL,
		0x3EBD20EDDE4EF356ULL,
		0xFC2DA4615D8F6E10ULL,
		0x37E4792D8E14285AULL,
		0x37302AC3D51DD03CULL,
		0xB6B5E5DBADA32896ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB17526265C53AC0ULL,
		0xB5AD2E51F0286033ULL,
		0x0A71808D062A334CULL,
		0xDDA51A3F3759C166ULL,
		0x048DBF0C1A960762ULL,
		0x76241DB663281AB9ULL,
		0x56D5B8E4765368F5ULL,
		0xD570366BC33F9348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x520276C94279F850ULL,
		0xCB999EC4C9693C77ULL,
		0x1D5A4195A0B39A55ULL,
		0x5170114B71BD5B80ULL,
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
		0xBB4F245F2CC6C11DULL,
		0x3BA1399331D3989CULL,
		0x650F25C029698833ULL,
		0x60C2920D8171A7ACULL,
		0xEA802E5DAABD1842ULL,
		0xEA10D499DFDF390AULL,
		0x51C4F1AE788A73BDULL,
		0xA6BD2D8B6F0A8122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5141E13B6BB84344ULL,
		0xCD436687725CF8BBULL,
		0x31D1A3073AC3B85FULL,
		0xE85A56DF74100C3AULL,
		0xF1DB317105F9333BULL,
		0x028F4ADC3F4EB8D2ULL,
		0x78A114A517F7490FULL,
		0xBA2488C33FF27E31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x528ACE4436227C5EULL,
		0xCB98453194E9A830ULL,
		0x6E90521D447E25C9ULL,
		0x1710B0E50AF20B32ULL,
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
		0xCA5893EDB648518CULL,
		0x6CA2657DD52DD45BULL,
		0x07E5A7D573866F55ULL,
		0xB76135FD97E9E410ULL,
		0xA78765C01E8FAA42ULL,
		0x08B94D5DC77C2C62ULL,
		0x0DD01746057BEA44ULL,
		0x3DE9B9599368222CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E1E9F2C27D97532ULL,
		0xDBD448DE772711BFULL,
		0xF9AE0EBF2B21EC71ULL,
		0x92D07290DDC27823ULL,
		0xAFC5503DB630E247ULL,
		0xBA36EF0A725BCCCDULL,
		0xD1DE2306DC9D74AEULL,
		0x34EEEBBE33581216ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8309261D0C808BC2ULL,
		0x38281CFE00D4F2B9ULL,
		0xF421DA765969F70DULL,
		0x79CB487CFC89CF12ULL,
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
		0x0E78CF877520E6C9ULL,
		0xF084DB931E724811ULL,
		0x9D59079F29BDB481ULL,
		0x8AB0D31568E3A706ULL,
		0x775AEB55BC5539E4ULL,
		0x5087D68D0338D294ULL,
		0x8E39FDC1792E0E48ULL,
		0xDDDD41599AB05711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745C301CCB1D25E1ULL,
		0x95EEB5942723EB90ULL,
		0x087C67F5BD170B73ULL,
		0x80B4926B0A681FCAULL,
		0x41D09066CDDCA660ULL,
		0xBFE2997B7ADC7D09ULL,
		0x26F27762F5EEBB2CULL,
		0xF3444EE55DBB9980ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CA61EE20FE9A5FBULL,
		0xD31D369935030F2AULL,
		0xE97A91B0E80CFF25ULL,
		0x5CB03DEB6ACFAAD1ULL,
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
		0x5B7C4D9BA32FB61FULL,
		0xFF14959F2D7F06B7ULL,
		0x507BD925719D3A7AULL,
		0x65E2909E8AA9F336ULL,
		0x4A9877CE5636FFACULL,
		0xE38E5130EC4D1053ULL,
		0x92038D455EC808D6ULL,
		0xFFB30C15C09B7524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3D6A24467C3CECEULL,
		0xE76C78834DC857D0ULL,
		0x0E42CFFAE28EA6F5ULL,
		0x9F773163291863A0ULL,
		0x95D7BF2FB85588D3ULL,
		0x07C687010CB539CAULL,
		0x1E22AB011EB82EBFULL,
		0xFBC93041982960C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C4112E2AAE38B87ULL,
		0xB750203710408731ULL,
		0x759A9F4C1168F30FULL,
		0x5B2200B962809529ULL,
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
		0xAAA97BACD1BD8226ULL,
		0x147D53A6AD088B87ULL,
		0x3B75ED0ED421BCE1ULL,
		0x49F5F879413C62F6ULL,
		0x384B9162E27BF02AULL,
		0x1E39AF06DF1DC87FULL,
		0x6D4905EA08E7190AULL,
		0x4091392D5B62693CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BE95EC447797D1AULL,
		0xE7F2CFDF30C70394ULL,
		0x8F4FB513EE2571B6ULL,
		0x7BC4D41D6254F743ULL,
		0xAC497718AA2288C9ULL,
		0x4E003337034C3582ULL,
		0xD4564FEB1DDCC46CULL,
		0x6C13D8401F1FEB6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x371003ECE7895C68ULL,
		0x1512E4A21D5D5970ULL,
		0x602D3BD1C984DA97ULL,
		0x58CD8792D0C618CFULL,
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
		0x7F8D9023DDF58285ULL,
		0x0DC199ECC5345A63ULL,
		0xA16FF45912043256ULL,
		0x938CBF119F67E51DULL,
		0x2C8C9FBD365CACB5ULL,
		0xEA64B4650EE76506ULL,
		0xB0ED67F5B41C4689ULL,
		0x5FE265E1001850B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x712B85A4E2F6C1A2ULL,
		0x1436D532264D48BCULL,
		0xB81995FDB71A8C4CULL,
		0x13DE81355DED0A3AULL,
		0x6AF6D713932E5112ULL,
		0x113CEDF31842316AULL,
		0x6BEC6E53B26437EAULL,
		0xEB5EE2A86EC22D47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA9DD3AD33E0580AULL,
		0x357239A53B6CBAC5ULL,
		0x277B6C679C3BD1C4ULL,
		0x4B33B841D4441CA9ULL,
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
		0x58FDD30E95579B1FULL,
		0x30DD063966E44172ULL,
		0x450AD1CA4179D499ULL,
		0xA7511BDA363B0156ULL,
		0x6FF7DA0037B46290ULL,
		0x53837F2A28ED4D46ULL,
		0xF8FAEB1C61F44CBDULL,
		0xC8DD78C4715CD6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE05AFE12EB0D37C8ULL,
		0x67F9F48C7025F8BFULL,
		0x7CB98E7B5739B7FBULL,
		0xEAD909241B8CDB63ULL,
		0xDCF0EFDE3A5BF9CDULL,
		0xDEBFBC0F80193F4AULL,
		0xEC1AE7AB20658A0EULL,
		0x880D702D72E1B37FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BA996074569F19FULL,
		0x1DF207A206385C0AULL,
		0xB191C61EA5710283ULL,
		0x5B59591FE0F56634ULL,
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
		0x314EB5EE9BA2A8A7ULL,
		0x7A66E2869908882EULL,
		0x1306158CB4DE476DULL,
		0xCB9E3789ED9FAECBULL,
		0xF5DFF934C6B3038CULL,
		0xE7C6696C3604DFE4ULL,
		0x36BA14B3013A6ED4ULL,
		0xE849883CE4E7F6C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E9162C1D6D34654ULL,
		0x939AAE950FA014FAULL,
		0x39D9D871BD170EFBULL,
		0x7A49AA19997B66E2ULL,
		0x3E295B2167E50FF4ULL,
		0x7D0EDF0575D4A3AEULL,
		0xD29693A26C842C1BULL,
		0xAA11BA8EAF53A054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37D8CA0CD7618C4CULL,
		0xBE0ABF3210916353ULL,
		0xB67165910AD51FF7ULL,
		0x0D9D154C48291BD9ULL,
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
		0xD518B35B055BF1EBULL,
		0x94CD24CEB2B1A667ULL,
		0x22D776B89475B28EULL,
		0x846097E1658D3512ULL,
		0x9C553461ABECF4F0ULL,
		0xABFA451B8748180BULL,
		0xF3B04C5436007F72ULL,
		0x44A29AFC2379CF07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x059020742223DA83ULL,
		0xC77332FA9C87A6AEULL,
		0xB7CA0F21DF7F6699ULL,
		0x55841D695350973DULL,
		0x0F1DFBA2E6EE9BBDULL,
		0xC1199C86EE8443F7ULL,
		0xC70D170F8BE443BEULL,
		0x23435BDE61909A19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5BAFF3820F955B8ULL,
		0xAAB2F7E2C33B7AC6ULL,
		0x0B474FC7F52728A9ULL,
		0x22FFD8E2DADA792FULL,
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
		0xC53466EF72286A2AULL,
		0x3F787C39445F9E04ULL,
		0xFCC8A0CF1840D57AULL,
		0x50A2F822FD1764E6ULL,
		0x4651D5DBC75CE71AULL,
		0x2FF57286CE94D5FFULL,
		0xA469C767CC6E39A4ULL,
		0x3E66368C851E8C1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA24146AB57934BAFULL,
		0xB1CD6609BA868BE2ULL,
		0xDFE38829194FEAF8ULL,
		0x37AC3B5B4F8AECA8ULL,
		0xFF1564E9E4DBD5C1ULL,
		0x3B381D99CE750D41ULL,
		0x74CD2E85FB883BE0ULL,
		0xE8B911AF83244BFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5EBE42BB9BDADE8ULL,
		0xE1C5B15D8E90DE3AULL,
		0x2E23CA2B01149597ULL,
		0x50AA3595F8B1FD77ULL,
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
		0x829774089713E989ULL,
		0x9EF37CFE22846222ULL,
		0xA047E57A9CE66E7EULL,
		0x47CF1FBD568575CDULL,
		0xDE71E16C3D4D67DFULL,
		0xE997908086BB4E39ULL,
		0xC4C014966D14BBE7ULL,
		0x66587CAEE45BFB76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0C45045CDDDB26DULL,
		0xF1774781E25BBAA0ULL,
		0x00F625845F08F954ULL,
		0x5EF24E6F9FBCCFE1ULL,
		0xE2EC26141E3D58FDULL,
		0x659B32F981C60463ULL,
		0x407CB0DE9577DAF4ULL,
		0xFED8DA0B1F77B1B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7ACF2D76598693EULL,
		0x44F21786FC919D44ULL,
		0x41528D403F26D94FULL,
		0x45CEF59CF0AB98A6ULL,
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
		0x19D5756C858F01DCULL,
		0x6145A7D8C6A38255ULL,
		0x844C2015DC4AE92CULL,
		0x74F6060F3E1AAAA3ULL,
		0x415144BEE57E29EAULL,
		0xB5778969C5BA75E9ULL,
		0x999C90F7D39ED6E0ULL,
		0xEC24F55743DE4E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B5CAC0424E5FE5ULL,
		0x67E2762E6208E2C6ULL,
		0xFA16599EF50AE9FCULL,
		0x6F77476813B1FB60ULL,
		0x2EBF5B5D31DC7D88ULL,
		0x3A09A2B04FA75FE7ULL,
		0x41C9B300656B90C6ULL,
		0x024018E17E9676B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6C84F2CED403DA2ULL,
		0x4BB37131EB6FE3DDULL,
		0x9382B93142DC671EULL,
		0x3D7778227312AD7FULL,
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
		0xC0382F183BFD0FDFULL,
		0xAD5E2E9C8088DEA5ULL,
		0x766E8B2523E8D36DULL,
		0x9DE1B3F38CA65149ULL,
		0x4DC77D31AA16638CULL,
		0x53CA0141BACEEB42ULL,
		0x1F4CAEFC10013E75ULL,
		0x8510AD10C604A13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E6449827884CFDULL,
		0x5684E39EAE626ED3ULL,
		0xA85B31B9F3569C62ULL,
		0x22FDB15AD6C80AADULL,
		0x0B82A71976DD29CAULL,
		0x8D26AAC01BB6F3DFULL,
		0x5C4B7C90627EB4EFULL,
		0x40EECEA6D0DA47F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F89B217AEF3573DULL,
		0xD318223B6FB5288EULL,
		0xC040D566F1F2A0E6ULL,
		0x17EB06531A2786D0ULL,
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
		0x4D1A315A7F94343FULL,
		0xF75146415D64B084ULL,
		0x7D0B319ADEC086FEULL,
		0x99AAE4A1AA26DC5BULL,
		0x181FBAE661634A9EULL,
		0x5C023B637F2DCB02ULL,
		0x6F3C058A067767F7ULL,
		0xCD3DF1D911F0A420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEDF5442812C833ULL,
		0x7A44EC0B604506A9ULL,
		0x41CFBE68DB223DDDULL,
		0x64DDCD50E4269D4AULL,
		0x0D51A6AEB1E9461EULL,
		0x6B0C587D4B361273ULL,
		0xE69AEE809347373BULL,
		0xBDBF3F631C41E02EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCC33C5A639E176BULL,
		0x418C0861B3E50F16ULL,
		0x8324DE991CC58507ULL,
		0x019B94D33DF154EBULL,
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
		0xAE5760C378D529BBULL,
		0x1B349F0AB9CA77E2ULL,
		0x75221C548F152993ULL,
		0x1435B332B8FDF647ULL,
		0xC625FB7A55401FD2ULL,
		0xBFAF21CC3E3CE7C9ULL,
		0x14AEAB54D09309D0ULL,
		0x3BFDD8985BCE784DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21151403357C5A53ULL,
		0xBCA7997B2CC82AE6ULL,
		0x6FB55F49813CF3DFULL,
		0xF297DDE222D5D2D8ULL,
		0x450C53A8C66AAAB6ULL,
		0xAF05B48988652877ULL,
		0x7FA10BC809DE3F56ULL,
		0x8E7F254456B92779ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB71135DB77082F8FULL,
		0xD7B33D768B08B33BULL,
		0x25726BF08CAE43D1ULL,
		0x626C73C9575222D7ULL,
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
		0xB28F3F8C00171A5CULL,
		0x37921A2125AE14A7ULL,
		0x2A356C0FEB576C03ULL,
		0x6532E2CEFB0ED84DULL,
		0xE21B210199C04AD5ULL,
		0xFFC2BBF3B2FA3C7EULL,
		0x87F969B5AEB407FFULL,
		0xA1CB7120CC86A2C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E3035017C20A574ULL,
		0x3F1568FC4A447654ULL,
		0x544F76D6EB9AA184ULL,
		0xE18D289A2A9249B4ULL,
		0xF654C72021C6300FULL,
		0x8CFCF060DDB3825BULL,
		0x30C2D9DEE8801C7CULL,
		0xDF527C2640DD6D80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43D0620253166CD0ULL,
		0x01D8E8F083E93F82ULL,
		0xC7FF4F1A6B71C002ULL,
		0x619A17658B9A777BULL,
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
		0xF370163C6DB0C8AAULL,
		0x96CB9DC19D4568B4ULL,
		0xAE987D9A9725A2CAULL,
		0x94B32C0E89A0D505ULL,
		0x1B999D9FD0EBD72EULL,
		0xB2DEC68B4675CC41ULL,
		0xD07789EA3DA9294AULL,
		0x6E8BE01513BC2846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21FDB43E2AB693EEULL,
		0xBE14AAFEEDA76E5BULL,
		0x24D934D88ED86567ULL,
		0x1F9B2F50CC106CA6ULL,
		0xCB7B57520C2D780EULL,
		0xA3C5B6B755AA0EF2ULL,
		0xDDC4F0C0C9A5F8E2ULL,
		0x1583376DD8DAD077ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5F0D189773C557DULL,
		0x166F4C386DDC13F9ULL,
		0x904204E940C66CD5ULL,
		0x2C6105907B037117ULL,
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
		0xB13BC5828499A57BULL,
		0x6B48D8E035E18B40ULL,
		0xBB39102AA21EACDCULL,
		0xB38C63E97C041EA9ULL,
		0xADA3BF84C1A705B4ULL,
		0x959B1B0D0A26F36CULL,
		0x6272E7559EC411CFULL,
		0xB3B40936CB65DF5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0197DAB145771D7CULL,
		0xA9C05756A76EA8A4ULL,
		0x19946C58C4642751ULL,
		0xC508492F8815390DULL,
		0x6DF5DC0DCBA7F7F8ULL,
		0x885F924BF9017329ULL,
		0xB8D2DB60AE0B1A5DULL,
		0x1431406201EA8D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2373AE79C2FE9564ULL,
		0xB85ECE321A03EC98ULL,
		0xCF666A2D992F4078ULL,
		0x1BEDEA4FDC3D0B53ULL,
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
		0x48615DBE25194E45ULL,
		0x14E6378286157954ULL,
		0x6941A5BD6D514725ULL,
		0xEF20A4BAFF6FE8E0ULL,
		0xB71793C539588E97ULL,
		0xE621F27BA6441BE4ULL,
		0xDB54633EC27C385DULL,
		0x9BCFAC9C4C2ED585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B24ED368156FBFULL,
		0x77378CB850D7B446ULL,
		0xE8296625A2A6757BULL,
		0x2B0B1E05A06955A4ULL,
		0x914B5EB815F5221AULL,
		0x17A12F23A1A07BB7ULL,
		0x9E1C42BF22E9FF46ULL,
		0x8432A04187BBA12EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EFEEEDDFDC5F9ACULL,
		0x44CBA9DAE5878BC1ULL,
		0x976D12897A5F4B32ULL,
		0x45655C2E8820582EULL,
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
		0x92844FE1AE2EEA23ULL,
		0x528EE8293ADADBDAULL,
		0x32B5ED3B533CEE91ULL,
		0x9742AF641F54147CULL,
		0x89F9B8AE3F5B6FBFULL,
		0x31BF879658397A13ULL,
		0x24905CD6EE0C2262ULL,
		0x05D95715CD274AA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x977547137BC7C6D1ULL,
		0x2E0CB7E8410BAE22ULL,
		0x06C6FB02C21C3A6EULL,
		0xF4291D8B88CD691BULL,
		0xB6808881023E0C1EULL,
		0x58F8840589D2C9DFULL,
		0x37A98DA8EFAA6C75ULL,
		0xB1C0C4551B790445ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F0C2F8544C3E95CULL,
		0x520CB7BF9D0D5569ULL,
		0x5631B30C53A1B54BULL,
		0x1EBF5A72F6651D06ULL,
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
		0x9F52FA4BD58BDC95ULL,
		0x9DA31B4C202DFCF4ULL,
		0x8029C2C85A134AA8ULL,
		0x0C251A2595CE78C2ULL,
		0x4C39DE1C4CAA0FF8ULL,
		0x4CE10E4E03225AFCULL,
		0x6DFA73584AFBFF10ULL,
		0x970C782605706E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x025A1442F9640C61ULL,
		0x04E3429C2AE3C244ULL,
		0x92F9A27339A1F2C8ULL,
		0xDE7867728E78A11FULL,
		0x66B7FE70848E0168ULL,
		0x5BAACD83DBCF39EDULL,
		0x88FF1C7A67626FF2ULL,
		0xEF177204AF889A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE4019889051F780ULL,
		0x66CD76B1CBA122E6ULL,
		0xEA7F0544E93C9652ULL,
		0x1C0B9BA5C7BF518CULL,
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
		0xD18A9DAEC8C076CAULL,
		0x6059D0846780CB70ULL,
		0x427ACF2E3BA2BD9DULL,
		0x06C0E98A6CD275A8ULL,
		0x8E3C271AEB74226EULL,
		0x593EFD49ACF7BC01ULL,
		0xD0353662975698DEULL,
		0x7B86CBDCC4DE985BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x604C102BED230232ULL,
		0x76F9AC45146C196CULL,
		0xA6569B5E960E6CA8ULL,
		0xEEA5AA4856E39776ULL,
		0xFC3598CD7257F6F9ULL,
		0x85BA47CA62C2E4E8ULL,
		0xAA0055709A73BA90ULL,
		0x8B11DDF6352DF5DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E37AD02D5CBE771ULL,
		0x4F13152456EC9FAAULL,
		0x47FD97BB2F415082ULL,
		0x49768F7B6A26FCEBULL,
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
		0x1694D25E444AA63EULL,
		0xD759B01474DE9F12ULL,
		0x1B9C418346D148EEULL,
		0xBECC562EB0A9734CULL,
		0xBC0595D0A62EDEC9ULL,
		0x3ECA15FC0E9C76EDULL,
		0x00F4EE0A5F1AD1E7ULL,
		0xE5B4EF5573E279A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x091CB812865C157EULL,
		0xB66CF4E0A3B8E558ULL,
		0xD68A09E0DE7C4606ULL,
		0x9A23E0BA9CA0A82BULL,
		0x6AB69C1D441B1877ULL,
		0xF5A953A64E23B611ULL,
		0x8B2675FFF049964CULL,
		0x0203558A848937C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F312AEC4CDE05E5ULL,
		0xFBC993EE63125A6EULL,
		0xC1B8092EDB63DBCEULL,
		0x710549939B489355ULL,
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
		0xF6514AF2CBA7A41FULL,
		0xA8877605FE6FD58CULL,
		0x68AA18BC7EAB4BFFULL,
		0xCA565775DF85294DULL,
		0xE5069FD6799D91F6ULL,
		0x32A19F745AC460EBULL,
		0xC0115E79769D0593ULL,
		0x2BD812FB8C5442B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7315847B17A78AAULL,
		0x8033F0B20A1E8B65ULL,
		0x850D416D3584C140ULL,
		0x96F57F7F52D565CCULL,
		0xCA98FED84152BE02ULL,
		0x401F5F12CE95EF57ULL,
		0xF72FB5E8877E3246ULL,
		0x87A5B949EF9F5165ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B65D86775489FACULL,
		0x27A913CEC3362623ULL,
		0xB51BDCD2C7B9E82BULL,
		0x12DA2853CF8B949AULL,
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
		0x621230573BF2B99BULL,
		0xE6CC3531AA924B78ULL,
		0x0C1B521C7B040C6DULL,
		0x0920323AB33667C0ULL,
		0x4AB67DED29479A30ULL,
		0xAB251A59C8E160A9ULL,
		0xB6A5F6136EF05AE6ULL,
		0x522A8408DB23B801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC3B7FD567A651C0ULL,
		0xDD1835CC8BD43A29ULL,
		0x715C4D4A51D22021ULL,
		0xD8BDED3F18584A49ULL,
		0x69046A9FE718E97DULL,
		0x3AC29FE687B2F6B6ULL,
		0x797076AE347FCB41ULL,
		0x8808DFDBEE229698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6458DF9A73AA117ULL,
		0xB8522C80CBA1CB5BULL,
		0xB0AFEDD8D5E73EDAULL,
		0x3160A3A6C9091315ULL,
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
		0x768D5908BA9C6E84ULL,
		0xFFD39DFBF658E86EULL,
		0xEA6E49E39EB43C7FULL,
		0xC2720241B6D92D6CULL,
		0x3A154BCAD16651AAULL,
		0x60AB3CDB48B19480ULL,
		0x295FEBD098C18A64ULL,
		0x9F35E0AAE4F67678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA026D222500ECF30ULL,
		0xAC6F784B54EA1BD2ULL,
		0x937C36C08E28DD38ULL,
		0x4C730430C549EDE9ULL,
		0xDE1294C499D812AEULL,
		0xBA27138E2628D828ULL,
		0x749BDEF4315981E4ULL,
		0x343D1CB669B1891EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ECDB1D2A9AAFB1CULL,
		0x0B024723C1BAC193ULL,
		0x2C0BFBDA69FCA23AULL,
		0x56EC145B3DCA7AD4ULL,
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
		0x0C73894E961FF7F4ULL,
		0x3518E5FDD0B01F58ULL,
		0x1316DF69B87A2DFDULL,
		0xEDFD4E4CCD9E32A4ULL,
		0xCDC42B37BF184FE8ULL,
		0xF814BAA7CC8F1447ULL,
		0xC002DA3E87F00973ULL,
		0xEF2654CFA7E00296ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F17FD5251B85002ULL,
		0xE47EC092CF92EB01ULL,
		0x3FC2C70F8AF0ECDDULL,
		0xADCDB08A630AFF9EULL,
		0x7079D20D77C935A0ULL,
		0x0E451CCDA9E8F2BCULL,
		0xC637619A4B42DE3FULL,
		0xB06BBA754D2284ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6664C842DA25900BULL,
		0x056B93CC25C62F06ULL,
		0xE78800BB2F3DAAFAULL,
		0x0FE2872BE2B3E39AULL,
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
		0x3CED42A9DFEA784AULL,
		0x4D62D2B9B7FBBC22ULL,
		0x7F3D666E87D736A9ULL,
		0xFFF8C9945758263EULL,
		0x6A620C84DC457746ULL,
		0x94A46EE62D5B63D9ULL,
		0x8F86095CF614179DULL,
		0xEB5CF72EDE81E253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EF56097B8D4F514ULL,
		0xAC8D435BCDD86664ULL,
		0xDE3B550AE2256752ULL,
		0xD7AA53C67F48CE03ULL,
		0x2FF2C1D1D949B16CULL,
		0xA775D926FA3600D3ULL,
		0x49F87F856ADC3C7FULL,
		0x9B044C67026CEB18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA7CF8A49874E35AULL,
		0xD5BFC9BF81B008AAULL,
		0xF40487624FFC55C7ULL,
		0x1577CF78832C0B06ULL,
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
		0x95021528E03B52C3ULL,
		0xF431559CC4F865A5ULL,
		0x1FBF1982701C652BULL,
		0x29A33CD7B106359EULL,
		0xF150AE2A17D71F37ULL,
		0x8FCF7A23F15E320DULL,
		0xAF9D15ECC11443FFULL,
		0x1EFD7CAD15D9D33EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2890D548E958AE21ULL,
		0x72E4C1BFECD45B72ULL,
		0x7082300F322F160DULL,
		0x972EC38FF8C52C06ULL,
		0x63D5FD964C1F722BULL,
		0x5387F612E086BCF4ULL,
		0x45FBCFCA56B9AD59ULL,
		0x6B7819379889EC05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CA775D0342652A2ULL,
		0x73EA2E65581F6BFEULL,
		0x5D2D528F075FABCBULL,
		0x38413CB8521D5C1DULL,
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
		0x3309037C0DF13218ULL,
		0x113F4DF6DCA171A7ULL,
		0x5D766F1498EB7A69ULL,
		0xA3639A396B2C7D18ULL,
		0xEC331B4DAB9A5C5DULL,
		0xFDA28A2B739ACC59ULL,
		0x0DC7DA6B6F16554FULL,
		0x4C30024BCF2B294DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1045818901064D60ULL,
		0x5A73A25FC5171A5CULL,
		0x9AEB423AC84AC37BULL,
		0xA56618CFCA407D4CULL,
		0x4895BA64E7B6D2D7ULL,
		0x9756813C42FCCFF6ULL,
		0x4E299A6A22A7F54AULL,
		0x5C5CEC0D170EC0DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C1FE48020B14E3DULL,
		0xE614FF184EFDCE15ULL,
		0x3408AD0B2902F7BAULL,
		0x1752CEB8F52380D4ULL,
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
		0x99DE2946F35340D8ULL,
		0x6964DE64F18874CFULL,
		0x545D5FCE6411E5B7ULL,
		0xB77C5FFAFE081B8FULL,
		0x7A3DC3E3DAB732ACULL,
		0x4EBC2BAA3EE36F1EULL,
		0x7F407FF77CAF2CD5ULL,
		0x2EBF8E044C476A1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1888E339E4F78A8CULL,
		0x5FA02183B070AB95ULL,
		0xC73D56B698C1DFF1ULL,
		0xFC0923700C8E9284ULL,
		0xF2F96E4478C5ECEAULL,
		0x4DE338A4AB7C7A4EULL,
		0x41021B20E3DD5E88ULL,
		0xC88E5B8197E5CD0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9579FBB5982C0D9BULL,
		0x29F8CFB522602008ULL,
		0xCA6300F27A74A534ULL,
		0x66C0BBF1B7F6D973ULL,
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
		0x753FCEA6C364024CULL,
		0x7A253B78792C11C9ULL,
		0x0D49FC481F4AAD05ULL,
		0x2900A89A87C08E68ULL,
		0x3BA1372BA8373AA7ULL,
		0xC1FAD498A1D517D7ULL,
		0xF6AACBFCE6A10E98ULL,
		0x789942A5CB84E740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CAB3E294F615720ULL,
		0x05056163D0F223D2ULL,
		0x581F2FEB93D906F2ULL,
		0x31537CC5AE3F36C9ULL,
		0x443CB6A11725F3F4ULL,
		0x2C0F7BC2AB2B628AULL,
		0xC87B54D0E146A091ULL,
		0x2C615F408DFA344BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC17FA50EFC932B60ULL,
		0xB60F09D7456AD763ULL,
		0x90367CE556DDFB33ULL,
		0x47F8ECDBFC17E803ULL,
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
		0x14DBFA43518B3440ULL,
		0xF06DF4EAC3B04EA3ULL,
		0xD9F44C83004B80AEULL,
		0x71C7A0DDCCAE1496ULL,
		0x04FE37FC5A236B4CULL,
		0x36F722768FFCC0EFULL,
		0x9074EB51514D5114ULL,
		0x507DD926934B6A2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D69817065FF41EULL,
		0xF6983AFB9DA21885ULL,
		0x3AAA9AE2CE1D6AC0ULL,
		0xE0705E4D6F62392DULL,
		0xB2CF0A2C73661DBFULL,
		0xE2AC728F61A021B5ULL,
		0x0762401D219F9545ULL,
		0x8F2237E8A763055DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35062F088B44C194ULL,
		0x7CEBD64007CDD8A0ULL,
		0xF80F1B5F45F7F68EULL,
		0x44F131C161CAD25DULL,
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
		0x243AEC69B3279E6DULL,
		0x5819A4BF955B6922ULL,
		0x1DCC9BAFCFF59F2BULL,
		0x619DB7B64817294DULL,
		0x866FD8CEB4EA58EBULL,
		0x9A4BB7C96089B487ULL,
		0x554D59618C701949ULL,
		0x91E3F6B0E64A3436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6349B627DFE056AULL,
		0xE6EA38346260BFF4ULL,
		0xDAD21E6D2603AE99ULL,
		0x1BBD38065A86CCBAULL,
		0xD0F863882A19EE89ULL,
		0xA83FE1A7B2C1199AULL,
		0x217F1F0FF9D99A9AULL,
		0x8B7251FCDCDAFA99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DC1B97FD01963B5ULL,
		0x5EF1358AFEC1A850ULL,
		0xF397255E6C48BE89ULL,
		0x3ABEF2695412E9E7ULL,
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
		0xBB7BDCD122691267ULL,
		0x06EF968AABDC7331ULL,
		0x552585AA72810F29ULL,
		0x1241175A3F5F9A1CULL,
		0x8C298C5551CB5466ULL,
		0x18A7E5E77DCFA3F4ULL,
		0x5062F03C11B29060ULL,
		0x3B819D94E1E03153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35E5A76CCE872C02ULL,
		0xD49A70EC8E3CB4D4ULL,
		0x0009D29E9C100EA6ULL,
		0xB1FE4CB675DE684EULL,
		0x6E85F210A44A53DCULL,
		0x72CA4C6C7CB31BC1ULL,
		0xDA7AED7D58DB9DB7ULL,
		0x2C74B8A25C461FC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBDF1B961507FB1AULL,
		0xD139EDE047DBF5F3ULL,
		0xD58C1B5B4659058AULL,
		0x1C2CC6A39E5FCD19ULL,
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
		0x4CE80ED2185CA8A3ULL,
		0x408BBA97461571B6ULL,
		0xE32509DA320B0901ULL,
		0x3730755F9CDBDB9AULL,
		0xCFB548207A8A70D5ULL,
		0x609A04CAC5B81BBEULL,
		0xAD4FD61210F88537ULL,
		0xA71297546317CD25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254821A8AF88EDD0ULL,
		0x3925EC36FEF1711EULL,
		0x67B2AE14AEC1D2C2ULL,
		0xCC70485965E0DD26ULL,
		0x98677A89D178A98DULL,
		0x9ACBDC8E01FE9E25ULL,
		0x0EED4C33E9295C12ULL,
		0x6D189FD033828B41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D2C7186817750B3ULL,
		0x63FFC76554ACA556ULL,
		0xFE12D2BF6C0951B4ULL,
		0x05DAEAA54722C663ULL,
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
		0xD98E1A5D3FA0EA75ULL,
		0xA836F908A299C07BULL,
		0x5FCB162CB98913E2ULL,
		0x62FE982EC10DC021ULL,
		0xB34F22CC4362BB57ULL,
		0x74855B5628E2667AULL,
		0x1D5F94888D5AF9C6ULL,
		0x9AF84A13026DD8D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE682F4837D15108ULL,
		0x666AF71F457FB8C8ULL,
		0x77BA8B6ADEEA1450ULL,
		0x583428CA8A782411ULL,
		0x2EC265DEEF3C7970ULL,
		0xC00E08CFED79AD3DULL,
		0x9F554F1E8F3EA42AULL,
		0xAC11ADFEBCE0CDFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC809F64F857D6158ULL,
		0x0B8241D62EA586D4ULL,
		0x9D96D87D92D3B4AFULL,
		0x01059A668985387EULL,
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
		0xFE44C7F746654013ULL,
		0xF1FE8E1E61EF9472ULL,
		0x28175A650C13146BULL,
		0x08F9AD0C9DEBE631ULL,
		0x7C8AE5DB750C3D6BULL,
		0x3E5FC6B95B617C9AULL,
		0x2E1685943C762892ULL,
		0x66FC3C497FFDDCCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE41B1392845F9CULL,
		0xE3CECC7354B75052ULL,
		0x6F2B1B1E482371A5ULL,
		0x30FA7096F9C1CE6BULL,
		0x48B1A7F1A88B4712ULL,
		0x6D1E08349CD85734ULL,
		0xF535FA5259BCE3E9ULL,
		0xC32455A227680BB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x729FDD980F056F99ULL,
		0x1DF2095F5593D14CULL,
		0x2A40EB0E6B6FD3D5ULL,
		0x2A0B794CCA6720C6ULL,
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
		0x2E7A0F94D9B3905AULL,
		0x7AD17648E237319CULL,
		0xABE0236C136050E6ULL,
		0x62E9581E7349A280ULL,
		0x7A6DCD2C2999A5C0ULL,
		0x0C4E95470825F03FULL,
		0x42070A0A4AB355F3ULL,
		0x6FA9F14710CD047AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07CF32ADB1656AE6ULL,
		0xCB17CBDBDC1C3541ULL,
		0x85EFA248A4234C09ULL,
		0x89FC880F71ACC15AULL,
		0xDA2CB883AD6A3E97ULL,
		0x649E6EE3289D3643ULL,
		0x681296B0428F343DULL,
		0xD8174AD5E4ABDA1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF053EDE99757732AULL,
		0x93DF5D40346697B4ULL,
		0x8039A080A49A05D3ULL,
		0x58B184DB8E892B60ULL,
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
		0x504A115ED3A8D2C3ULL,
		0x1330EC933C1D3DAAULL,
		0xA6CCBA6809668CB5ULL,
		0x6B6D4D26D4596DE7ULL,
		0x3295160D521B81E1ULL,
		0x0E03104B4CC7CA40ULL,
		0xB9BB9DBA9142C232ULL,
		0xA2C011851FABA03AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7009880EB02DE83ULL,
		0xC152B78269B8950CULL,
		0xE3F36589EE1DB38DULL,
		0xF7B65E43AF163C47ULL,
		0x43FBC7585357F7DDULL,
		0xD04F7F6BB9479B3BULL,
		0xECE491CEC9E92976ULL,
		0xBDB6721AF98ED6BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF40B27BBB9AC701AULL,
		0x7A85B640B76BA358ULL,
		0x2AC519DDB29584F2ULL,
		0x732498A4CD891A4CULL,
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
		0x940A05B048F26C93ULL,
		0x62FD7C4BBFFAF30CULL,
		0xEEF0E38118D0E43CULL,
		0xB1FD75056804B9CEULL,
		0x1437FC4A4C0A2970ULL,
		0xB414BE0876E2A79DULL,
		0xEEA36333EC1CB979ULL,
		0x317C28F77FEDAF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB19BF630B1B6B12ULL,
		0x7C0DF4A50A16C5CDULL,
		0x34396D65DC185778ULL,
		0x95DF82F72DFC726CULL,
		0x40C799FD4CE93CE9ULL,
		0x60D71736B746F272ULL,
		0xA10D10DF8C2C1903ULL,
		0x9319955E1DCE1E4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B9EDDBB1CBA1B64ULL,
		0x42164AC92701119AULL,
		0x3F07AEA17A705E54ULL,
		0x1EBFDAD2CAB7CCFCULL,
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
		0x30242714065F1EDBULL,
		0x58A44081EBD518A1ULL,
		0x0D74AA7C50077AE2ULL,
		0x8C11DCBBCCBD34AEULL,
		0xCE80CC4760B8FE64ULL,
		0x4A599D8422A2D479ULL,
		0xA91E4F0BBE07C326ULL,
		0x76A14E7BD8CEB3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3E42F6357CDE46ULL,
		0x45B9F6E03A7D2F8AULL,
		0x53A4A0C8C53AE1E9ULL,
		0x3AF70C3EF0C30074ULL,
		0x06C01EACF092F2D9ULL,
		0xA1F0CCAB325070FAULL,
		0x1949B15ED80F5020ULL,
		0xE34A642ED22C0349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x487FA90A7687F4D7ULL,
		0x127949D55D92AE0EULL,
		0x135F715DADADABD0ULL,
		0x300197EBD8206327ULL,
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
		0xAADD293E1CCBB4BBULL,
		0x33C90B8324B37FA7ULL,
		0xE9377D3F5CF8D13EULL,
		0xFF90C29F996E6377ULL,
		0x40467A31BD7DA45DULL,
		0xD6C99B6A4BC7EC04ULL,
		0x599CAF06F9FB23A8ULL,
		0x946987A1D643C379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E50CBF68CA9E911ULL,
		0x30C78020DD5DFB9CULL,
		0x4400F9F4BF7FF6A7ULL,
		0x98968996EFAE9364ULL,
		0xF64903288EFCC2CCULL,
		0x14AECCAB12A2164AULL,
		0x467A231FEC60EDF6ULL,
		0x6D316A6E61A31A5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x382C08A477434814ULL,
		0xD2FC3BC4C2F33D8CULL,
		0x7C574796A25CD31FULL,
		0x394E8EABF998EA8AULL,
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
		0x4A5FA947B7904120ULL,
		0xB748861F905BB016ULL,
		0x69F7365C4359857FULL,
		0x4EC76C9AC7B9AA43ULL,
		0xA801089B1A67A9B1ULL,
		0x9CEE1471B2766EC6ULL,
		0x51CFEDF0CC2AD1C4ULL,
		0xE052C0F7E3459AF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A1E4A6CC5277776ULL,
		0xA0F581DE157B9A7BULL,
		0xE96FD70A0FB9EF31ULL,
		0x57F9C66424B6E311ULL,
		0x04A37FE658E43254ULL,
		0xC98FD1B82A0D5D45ULL,
		0xA6FDBDB1D6DEDA84ULL,
		0xEF67B068475C9493ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8023A9AFABEC8119ULL,
		0x7650EBCBBA78AED9ULL,
		0xDBBA88AA9CE649C7ULL,
		0x39B21B87C799B9D6ULL,
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
		0x0EAA0D49E4B4E74BULL,
		0xBE1151642F7A79A8ULL,
		0x9F1B6D6920E7BD91ULL,
		0xFEC34C421101CAE0ULL,
		0x27C6F797626F905DULL,
		0x5951159A53EA73AAULL,
		0x7D41B2D3AFC30CB9ULL,
		0x0AEFF8AC62DA2E7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D5DBBB112020CCULL,
		0x25A80B3EC4E4E408ULL,
		0xC2A7C13BD6D0912BULL,
		0xAFF3F321BDCD0294ULL,
		0x7017D30130FF0AC5ULL,
		0xF3CC92E9120BF612ULL,
		0xF8B7CD849D58F6C1ULL,
		0x8155D48A677A4597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D39FDA2A489876ULL,
		0xAA14AC75319C3A25ULL,
		0x88EBB5EA05D66F1FULL,
		0x3BB0B62BA3715A5DULL,
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
		0xBB30C6937CC48DFBULL,
		0xD3E9C115C0107D8EULL,
		0x10CDEFBF359125A1ULL,
		0x9CB05D7E13F67BDEULL,
		0x7C82746AA0492026ULL,
		0x28F4DA8B1521BAAFULL,
		0x129963A9527B8709ULL,
		0xA6C76E5E22745A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230D95799BD0EDD6ULL,
		0xBF2FE50CC5EC7602ULL,
		0x453B4329EFCF0C7BULL,
		0xE6F6652B50A53B6EULL,
		0xF2622B1B794E80C3ULL,
		0xE6F939F49C3132E4ULL,
		0x0D26731A5C4D34CDULL,
		0x334A137A9149F0DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18EE12D9AA274B4AULL,
		0xE013B25EEDD82F9DULL,
		0x9AA261CDD0A24DF1ULL,
		0x5A55761A4F9CE866ULL,
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
		0xF46E7E50984C5E2CULL,
		0x636D74CBD7BB74B8ULL,
		0x782D0A08D774492EULL,
		0xE3CC36B668D063D7ULL,
		0xA371F887A101AD1BULL,
		0x2969E08AD548B801ULL,
		0xD6D7FE767AD45C9FULL,
		0xB38E5410CDCFD24FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFC331CEAD348F99ULL,
		0x6EFBF41A807EF4D3ULL,
		0xE52CD7DDE833B295ULL,
		0x4B7A0F3F034931F8ULL,
		0xA7488BD779D09846ULL,
		0x59CC313EAE08E942ULL,
		0xBC5B2C4523081233ULL,
		0x0F36C858DAF74779ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2D16EA7BC60E9D4ULL,
		0xC5D985FF2AB5303EULL,
		0x8187657DF793A299ULL,
		0x7D50E4C571ABCDA6ULL,
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
		0x83A173779CC472D3ULL,
		0xEA096A490279209CULL,
		0x84DD1424CF295673ULL,
		0xFD86863F14B15BCEULL,
		0xAA4756B8C535706FULL,
		0x3B5C17C18E844B2FULL,
		0x8D8EAC47C6B5A2D7ULL,
		0x6425EA18F3F5B323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7072576A21AA50C5ULL,
		0x7691D4AF0442B5F0ULL,
		0x91ED6F55AB550906ULL,
		0x279E0131B33951F7ULL,
		0x0C95699B6D63FAC5ULL,
		0xB89081E31609AFA3ULL,
		0x8E05D24F5A5B209FULL,
		0xA0FD65CCC1FFC675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B984E6884319807ULL,
		0xDDAFD49FE069818BULL,
		0xE13FFFAF3943A1AAULL,
		0x4DEC285CCBF92BAAULL,
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
		0xAAED326733E9D799ULL,
		0x8BB391630C109D9FULL,
		0x00E286B786BE3565ULL,
		0x4A9185D1448225AAULL,
		0x637348771FFE24AFULL,
		0xE03CCAB7A4063B07ULL,
		0xBF8D3FE1C365D82DULL,
		0xB669D5C62C5208FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7EF0AE202E58FAAULL,
		0xCC58AFAF631776C3ULL,
		0x2E974D9999909E30ULL,
		0x1903E17AEA1FC970ULL,
		0x0CDB5AED5FBAD6E6ULL,
		0x06FBC8869849DBB9ULL,
		0x7EB93A0AA1D59F64ULL,
		0xAA060272D7267D34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD8B69F7BB01D411ULL,
		0xFF0134FB66EF4C7CULL,
		0x71C4170CE896052AULL,
		0x085F02B4FED91BCDULL,
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
		0x5B39D0C0F7772C1DULL,
		0x9F4694ACB6246E9DULL,
		0x0523F06479088F8BULL,
		0xAC4A01464C8F6919ULL,
		0x2FA58468894F8141ULL,
		0xF26BC4E0CC24510FULL,
		0x4A7B3FEE9E48F142ULL,
		0xCAC99062D791A231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x902B2ABCD97A31AEULL,
		0x8B60CF33E0F6D5D8ULL,
		0x97D70F315940771EULL,
		0xA92B843B2470955FULL,
		0x2A3E3BD33CB28527ULL,
		0x7EC9CFF7F7D3AF05ULL,
		0x21DC1399C7A01681ULL,
		0xCF00A5FFF7317E59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98636C2D7D4A6625ULL,
		0x3DF020085925A641ULL,
		0x74ED75CAFCD89124ULL,
		0x62F147B8766425CFULL,
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
		0x260CDD7D0DC5F2F4ULL,
		0xC8EAF25EB92EA9D5ULL,
		0xA1DDBD64E15A9933ULL,
		0xD1F09931BA9DC29AULL,
		0xFBAC5C0789E79BA5ULL,
		0xADC40AA6F0167689ULL,
		0x2DDAA19499958C07ULL,
		0x1A222D05504B7B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA1DE0E85C06947ULL,
		0x0F450545AC641D42ULL,
		0x82125924E2CCCB55ULL,
		0x35CD94301DB61E2AULL,
		0x26B1C188BD4ADB6BULL,
		0x01B0F399E3CDA09AULL,
		0x2ADF7FE169030A25ULL,
		0xE8424B5FCE2EAB98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x559DEE40E74A0DD5ULL,
		0x447B5908DF9A4E2CULL,
		0x911264D9344D1584ULL,
		0x035E8392ED2E6F36ULL,
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
		0xC2D4C78604E7B23FULL,
		0x4DCE885EB2BD1F8FULL,
		0xEA394292151EEE52ULL,
		0x4FC7A54E849B3687ULL,
		0xA19187AD7FCBBA43ULL,
		0x22C1295F297CD18DULL,
		0xA18229EA90125885ULL,
		0x0BCEBD2B38E26693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1490C7E281CF037ULL,
		0x5298DD7C6CCF191CULL,
		0x5C1E9CA838DF0E4FULL,
		0x9C624C652E472BDAULL,
		0xE990F7427BAF3191ULL,
		0x3318D95F15621AA0ULL,
		0x0151487B111EFDE5ULL,
		0xDC708946C64BC01DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41A12AEA790707C7ULL,
		0x8E318AE541E52D96ULL,
		0x555C1C76B45F53C0ULL,
		0x3B610CD258B0C049ULL,
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
		0x6397D7538F9163D5ULL,
		0x6389574BAD9B7C1EULL,
		0xC993A69D6FC5A98AULL,
		0x497CB6E061DDEAF0ULL,
		0x2996E9A1FFD097BEULL,
		0x68F34150436A93D3ULL,
		0x0F3B2B2B7915D1E4ULL,
		0x2CEEBDB7EBE5E85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE346D1234AFAAB8BULL,
		0x80E2DDB893CFB600ULL,
		0xF8F261A8D86B0587ULL,
		0x7D99930FC178AC78ULL,
		0xC37D15C35A341849ULL,
		0x50FE778C942FC5F0ULL,
		0x7038B37D5A9AABBCULL,
		0xCABAEC737588C44CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA826793CD9D1A018ULL,
		0x70FC6C9F1C8655B8ULL,
		0x6AFF08CD1DA24DF6ULL,
		0x5F9433FA3238993BULL,
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
		0xADCF2002867D137BULL,
		0xDE662D23A7C6571EULL,
		0xEB1E325C9FA1648FULL,
		0xA38E529EC3060EACULL,
		0xB6675326603C4A57ULL,
		0xD8F4581012518705ULL,
		0x4BFEB0BB36DDD70DULL,
		0x23CFDAE7BAD760BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADD6FA1468B02A6ULL,
		0x235C6587054DDE78ULL,
		0x8D8EB8C3D811FC8BULL,
		0x7ED4E76FC8A324E9ULL,
		0xF565D3F083476C28ULL,
		0xF6A0F09CD9777E92ULL,
		0x563D6E53BB5F2289ULL,
		0x0E3E0B262A29B97DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x392A92600C4B0C41ULL,
		0x536B22B712D5B9AFULL,
		0xD83F54F51C5E3398ULL,
		0x585E41EA7429BD1BULL,
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
		0x090A99A2820106D0ULL,
		0xA9BE03DCF00C70BAULL,
		0x501262DAFE377515ULL,
		0x7778A1C99AD18312ULL,
		0xB549E886A51E7185ULL,
		0x0ED2C7161B0EA272ULL,
		0x94C6A81FF8A87732ULL,
		0x3A1332ED39B4D62DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF72CFB85FB5F124EULL,
		0xCA4FA83DA170D61EULL,
		0x6E3BAD71522376FEULL,
		0xC1DF195F1EE82371ULL,
		0xC0DB6C676B9B6827ULL,
		0x562FD4D2CD680CFAULL,
		0x309DE1BF840F1014ULL,
		0x5FE34E68768FC92CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A440ABF10155792ULL,
		0x479E519CD555CA69ULL,
		0xBFE427BAFAD94C80ULL,
		0x18B5741F73694DD5ULL,
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
		0x1772A94E24480568ULL,
		0xC3F74BA7D29D60E2ULL,
		0x8F0A1FBFD437DF64ULL,
		0x414C1EB0F41F1723ULL,
		0x1F9B68C1A6E8F034ULL,
		0xBE7EABE3CB4B55B9ULL,
		0x0F4F1A45E9B0784AULL,
		0x77A8C2907C7A5F24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x879E166FE212E650ULL,
		0xE31349172B4C2F04ULL,
		0x10E18A8F35F7DF0BULL,
		0x54E2B96B42341D75ULL,
		0xFBBCEBB9987017A6ULL,
		0x700E410AC0939CACULL,
		0x9444259C922E3436ULL,
		0x9E85D68797BCD3C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2DB221068254348ULL,
		0x8593DEC83E96A9AAULL,
		0xC1C8E6539B961B5CULL,
		0x27986E97A60DAA4CULL,
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
		0xD95EEFA1A9F93B33ULL,
		0xBDFA57CB86A07F59ULL,
		0xCAE6A663CAEA4BBFULL,
		0x48E3AF6E1BA86E7DULL,
		0xE04BB1D91091DBBFULL,
		0xF351857499FE214DULL,
		0x025D22F3B1750779ULL,
		0x0F1A1D5387A0F326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4BB74A352A4589ULL,
		0xCC3513C32186CBC1ULL,
		0x05E37CF859B0A8EAULL,
		0x6BC663AB70726AEEULL,
		0xCC920AC69793BB55ULL,
		0x34F7007813F7079BULL,
		0xD5C6DFD0FB8B6CF6ULL,
		0xB1ED5BCCAACA958CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78A205156A87C1C3ULL,
		0x333501844A278407ULL,
		0x6351209271E69263ULL,
		0x31C205C77307E84CULL,
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
		0x9F386E6D1DF9DB6CULL,
		0x0265098A276FC5A4ULL,
		0xC8AA697937BBB933ULL,
		0x341683B170AA1F53ULL,
		0x46361078B080369DULL,
		0x36EF7A6DF43C3072ULL,
		0xC57DB72B49CC2399ULL,
		0x79A16A914489AFC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C69F2253B869C0ULL,
		0xF5B2878DC9FA45C4ULL,
		0x86AEDC59A1F9599BULL,
		0x8B5B6F632E188440ULL,
		0x86D9CC6A30EE04C9ULL,
		0x5949E14D16D81796ULL,
		0xF1BB1463AECFBB5BULL,
		0xDF5B5C65C0E0EA92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC323E971B9F4D4D7ULL,
		0xF3473CDD3A51307EULL,
		0xB0DFB6C09739D8C5ULL,
		0x0F212EC3CD9EE136ULL,
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
		0x2B61826865627568ULL,
		0xD0E980B58AA13FA1ULL,
		0x7E4D2E6B77D7479FULL,
		0x109561DF1F1ED5D2ULL,
		0x28494FC83A9AE4F7ULL,
		0xB8E6E90E26BE20BBULL,
		0xE5955F2F4407D592ULL,
		0x1A79F4024A6CB91CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCCDC78E88B9A54BULL,
		0x5DAB46655431EB3BULL,
		0x1BD5B4E296FCD5F7ULL,
		0x85BC472D658CF34EULL,
		0x181563FFD46E1BE0ULL,
		0xCF69A258E48B8B7AULL,
		0x14BC68767947AAD4ULL,
		0x4EE87DB0E3F049F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9648BA99074EA844ULL,
		0x1BD6B93809F17C0DULL,
		0x62AC18F6F960C9D9ULL,
		0x4270AAC6F00A6247ULL,
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
		0xA16213AF3964979FULL,
		0xC16261A552049CB0ULL,
		0xB37FC5AFC776F8D8ULL,
		0x9449F3A40C24C1BEULL,
		0xB30989399AA73003ULL,
		0x2F2F6F078ECD7EB0ULL,
		0xC4ED06D4DBAB9D95ULL,
		0xC59FC851C8EF3A2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934171C6215DC922ULL,
		0xB53530358EB51A5BULL,
		0x17849735688667C4ULL,
		0xC13FD722F14231EDULL,
		0xD9250B74840AF3F5ULL,
		0xA25F7AEC7B356F2BULL,
		0x228D1C810A4D5A4BULL,
		0xFAB0425CC07069FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x660B4D2A7337B74EULL,
		0xF30B6D74ABE1D00DULL,
		0xB637F6EB72EE8DFEULL,
		0x7297FEE05DB5772FULL,
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
		0xC833D88693B5080CULL,
		0x7B2401921CFF45B1ULL,
		0x25E1FA97180450CCULL,
		0x1CB38762FF1196BEULL,
		0x287F136358717E28ULL,
		0xD5BFAF7A19A84E1FULL,
		0xD3FE03787DDED886ULL,
		0x0879060294F32294ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26AF16C1F8F3ECB6ULL,
		0x96E54C45352A0943ULL,
		0x903338A79CCAA7BDULL,
		0x7F3DB6E5F1943663ULL,
		0xEEF3821CB102449AULL,
		0x2C086D216E966076ULL,
		0x51CD7BF3537399D3ULL,
		0x83C52163618C287EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C3C52417543A398ULL,
		0x15728E764C7E8367ULL,
		0xE8E2DFB3C724F7BAULL,
		0x5029C01EAEC67FB1ULL,
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
		0x4E0A55BF9939C427ULL,
		0xA64D6E50B93C61E8ULL,
		0x5FEED460D77F0926ULL,
		0xF076D9F20FBA7E95ULL,
		0x03AA82FBE375048DULL,
		0x6E4E0DC9CB4A3C27ULL,
		0xFDF725E43E53858FULL,
		0xE5DA3CA3DD4735C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20156BC0DD1FAEA4ULL,
		0xE984A0B11DE3C4E9ULL,
		0xB3C96C6FFE6306EFULL,
		0x3EFFE8C8C3E9A829ULL,
		0x699CDC96C082BBCFULL,
		0x02065C6214321A01ULL,
		0x894E2B8E8A2F5A2AULL,
		0x943DDDC5E9C8F3FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BFB9D01EC10E392ULL,
		0xCF6D2304C8EDAE94ULL,
		0xFD3A90A9967A7344ULL,
		0x4EAD061B708E99BAULL,
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
		0x877B03F4315A4436ULL,
		0x5641A956AFA9457BULL,
		0xC41EE58CB475C8F5ULL,
		0x3425EB1909EDB771ULL,
		0x5B21D85446C74B58ULL,
		0xCD99B81FED913147ULL,
		0xC1D92F8D8E9180CAULL,
		0x775B5892F4BE4942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6079EBF66958ADULL,
		0x5A299F830A0FD95FULL,
		0xC004440917605949ULL,
		0x876E6C39972D5604ULL,
		0x11CB1C671F8D1CD9ULL,
		0x0733A5D854CA250DULL,
		0xEE486FC92F8962B5ULL,
		0x9AEF6D9091F51DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFFA6F3C0D93D17FULL,
		0x6F3EC07453253CC2ULL,
		0x6B9718A9B849E6E7ULL,
		0x64BC613A1C9CD5F4ULL,
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
		0xD425B0BC6626F0F8ULL,
		0x94E50292ACBD5638ULL,
		0x73DBEF5037D883A1ULL,
		0xB0817E532542FCA8ULL,
		0x1D5060E94E5409A8ULL,
		0x2B871B6ACCF82B45ULL,
		0xBBEEEF229DC3B075ULL,
		0x21CB80ACA46C1923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA5719A92275E001ULL,
		0x0DC9F96551308DA9ULL,
		0xEA0C36737BA2C3EEULL,
		0x58CB881EC1B0D5DBULL,
		0x0384C4F256F30E8FULL,
		0x75E2602DEA17B3B8ULL,
		0x5DE5CAF35F70B83FULL,
		0x15B5B17205F801B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE07BDBBFC1656F9ULL,
		0x7D8ED43708DE8780ULL,
		0x7F2B17DFFC8697ACULL,
		0x22F2B8E7E8CDA096ULL,
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
		0x6F9CA201B7655C1FULL,
		0x07435F046B3C7952ULL,
		0x19EA05362D380BEDULL,
		0x2130036CC903C27DULL,
		0xC9BC3917BA8D063BULL,
		0xB2EECE44549EC81EULL,
		0xB194EA35D2FD84DEULL,
		0x79F65672988F6B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84E3D9968A8AE539ULL,
		0x62C435F41D9305E3ULL,
		0xD25CC1350E3CCDD3ULL,
		0x62D2E04B502B520BULL,
		0xAF54F769B2AA6134ULL,
		0x418941D20C6C0B75ULL,
		0xDDC23C348E43C942ULL,
		0x4455ACEC8A4CFAF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD60C8840587EF70DULL,
		0x7992020705317488ULL,
		0xB8D31831528D1752ULL,
		0x34364D0796B51550ULL,
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
		0x481A9750D163BE08ULL,
		0xBE35B879B0806679ULL,
		0x82A8DBC0E9AAF760ULL,
		0xF771D9B74DE27975ULL,
		0x56A9E0025B0BB972ULL,
		0xF0C9320C063E2199ULL,
		0x7F5BFD0505899D18ULL,
		0x7FF11FF9FD6E4AF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD96468F5716A2B75ULL,
		0xB57D888327D94962ULL,
		0x112B9E4CFB14B9F0ULL,
		0x9797B68908C9B016ULL,
		0x4CC11E3D83094E38ULL,
		0xD1C3E6573A997CC5ULL,
		0x564ECF1C0FA4D332ULL,
		0xC25736336CC77F43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE742F19370557BC6ULL,
		0xA3816CCCC317948FULL,
		0x89720E086E8C3598ULL,
		0x04B2D6A7BDDB0539ULL,
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
		0x7F4635BD9192C9A2ULL,
		0x256485DABE810A31ULL,
		0x527F99F2DFB35ED0ULL,
		0x916D778E4B7D1592ULL,
		0x6FB75D73BAE2B78AULL,
		0xAC9AF9FD8EBE97FFULL,
		0x501F80E655F045EEULL,
		0x6CA1E22674B48C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0C669CE448E2F2ULL,
		0x6DFD24967DE35EEBULL,
		0x498FBC642E7BA0C1ULL,
		0x39449BA5548ED43DULL,
		0xBB6336A271BACDA7ULL,
		0x4D3C5485EED695D3ULL,
		0x170F1303C5D6D793ULL,
		0xE6F491BB53FE0E05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96B7923189369BB6ULL,
		0xDF73F105FD0DFDC2ULL,
		0x81602D3014FE1F9EULL,
		0x2FE2CBCFD204F9ABULL,
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
		0x86C91A25776371C1ULL,
		0xDFEC0B7A719AE4D3ULL,
		0x396D9E09219E0EFAULL,
		0xEFB70DE7B01C02B7ULL,
		0x7D274B63EACC5183ULL,
		0xECC4E841CB2F61EFULL,
		0xCF385577F3A379BAULL,
		0x71D79BBC7FBF7FC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC2AB6663328576AULL,
		0x9DCB1A54B261B083ULL,
		0xB204C7045D809FC4ULL,
		0x1C2E1765E30F328CULL,
		0xA45E2B924AED7BCCULL,
		0x3A287A63BDB80651ULL,
		0xE9C9CCDF347D3C3EULL,
		0x9AE8DDB53503824DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8791CDCFF4ED2B0ULL,
		0xC559401BBEF0CDBDULL,
		0x95D11DB123CA8FB8ULL,
		0x3AF92B96E4F46FAAULL,
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
		0xB64B7E45B6AEB5E7ULL,
		0xAA49549861EF5BF5ULL,
		0x6DE6F0E549DCFA54ULL,
		0xCB122EB99338DC10ULL,
		0xFDC4F41FA375136BULL,
		0x0AA3813095BD681CULL,
		0x93F9C67C3E58A31CULL,
		0x6E58696D9134EFE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1485A4D031AF8D8ULL,
		0x989BA7611CC4261AULL,
		0x1CE5A07C1B35D49EULL,
		0xF9B7475AAA26B073ULL,
		0x3CA2A7786A8E08F7ULL,
		0x91AAF0ED03340707ULL,
		0xC3F7B15ABB2F2282ULL,
		0xCC2E3452A77E9054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x701A84CB25DF4820ULL,
		0x0693173F058F9F15ULL,
		0x31507362A6D03C7EULL,
		0x639EC95D9A245B68ULL,
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
		0x2F28EDF552A4B7AFULL,
		0x4234EC83E3DFEE08ULL,
		0xD874F324B2BC7FAEULL,
		0x6ED69B98016257E6ULL,
		0x861F94FC738C85C6ULL,
		0xB890CA7007683EA8ULL,
		0xF43CD3A65A2B7928ULL,
		0x89F5EDD8D7F30D13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE66BBEF1E00DA54EULL,
		0xB6756158E108D17DULL,
		0x886E22997DF2EE46ULL,
		0xCC9B1310FC7D44B9ULL,
		0xAE855C284364B9EEULL,
		0xEFB2382EC87EEF9FULL,
		0xAAB61C967863BEB5ULL,
		0x16B9B06B0C1E26DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49A19E82987F56E4ULL,
		0x5CC940DA5978D7DAULL,
		0x3A05FCE6B86F3E71ULL,
		0x3D2CA6D3467F3F62ULL,
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
		0x539302B1E6E9D6D2ULL,
		0x6401F0025E78FAFFULL,
		0x8CBD235BBC8EFE46ULL,
		0x20D9D03D4CEE5DB8ULL,
		0x3109D8878D2FE8B6ULL,
		0x8CDB5D3056446358ULL,
		0xAD115BF6917D7980ULL,
		0x5EC6CDFE386756F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5632F424B5E8FBFAULL,
		0x1055FC438A005BC1ULL,
		0x61D542007FCB5089ULL,
		0x145C93C09E78DE5FULL,
		0x11DF2DE0B0517209ULL,
		0xABD7DA8FD055B647ULL,
		0x289CBF8F582A6715ULL,
		0xE9D731C76D0C98B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB56351FA067568ULL,
		0xBA315792B5E64FC8ULL,
		0xD43718ADBF18699AULL,
		0x680E6C9EDDEDBD38ULL,
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
		0x674EB1C3EF42734CULL,
		0x8B191A7594BF815DULL,
		0x68CFD94B8ECF430BULL,
		0x09B61CBAD36AF7B9ULL,
		0x5393426CE0CEC125ULL,
		0x58C02AF95BA83346ULL,
		0x34FDBC48F5C86E94ULL,
		0xFBAED79B0CB8AA7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3D69679A498652DULL,
		0x2B1428A392975677ULL,
		0x0AB32DE1BBA6007BULL,
		0xA1BEA296B6A08A3BULL,
		0x4626764C1989266BULL,
		0x92AD13EC7E3013C5ULL,
		0x68D7D288C7FDB538ULL,
		0xAC1E25469F670C2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB19E6827DEFF075DULL,
		0xC6DA5DBAE1FCD80DULL,
		0xABBD5DF09F40C62FULL,
		0x3771F2AC56E7ECE4ULL,
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
		0x70F8C4AF2230DEF8ULL,
		0x6C64988EC531473CULL,
		0x83572D1F7F5B0503ULL,
		0x5C83EC4808C36BB0ULL,
		0x8521A7F8A58CD0CEULL,
		0x26376979DA6D7AA0ULL,
		0x3016DC4D89CBFCA3ULL,
		0x418E2C6B2194A93CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB767DC06DB5D50FULL,
		0xBE6C158EE9A3CEF9ULL,
		0x43C17612439A9B8EULL,
		0x911E9E5E7135B9EFULL,
		0x597AF4BB15E72DE0ULL,
		0xF7BE47814E794BEDULL,
		0x18E7265704009966ULL,
		0x88683A43F90ED527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3040E2120711379BULL,
		0x93F38DE4A1CC66DBULL,
		0xB0AAB9A517F12463ULL,
		0x47073FB99B6B2CE2ULL,
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
		0x739C2A89337F275BULL,
		0xC756EDDDB3E748F7ULL,
		0xC0708EADCF133C78ULL,
		0x03A6D3E975D70C52ULL,
		0x3A3DBC65B7D75F8CULL,
		0xFA82343DA5958463ULL,
		0xAFE71B9267869791ULL,
		0x56FCC20500B00BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7513731EAB088BD3ULL,
		0xDCFD6D9378076A5FULL,
		0xDED2CD74FE77A9E4ULL,
		0xB01E9BB977A18C83ULL,
		0xC685AEA76F262224ULL,
		0xC36F54D7ACE5F41CULL,
		0x56A912A546E306D5ULL,
		0x31D7789FD0A7D597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BDAC1A952C5B9A3ULL,
		0x1726A96D25EF490DULL,
		0x20D3146BA8E30E84ULL,
		0x57111D351F6D86AEULL,
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
		0xC4344456B6E849DDULL,
		0xCEA7F30BBA97B73DULL,
		0x83110F9DE419C42EULL,
		0x54EBBA870289E0B7ULL,
		0x8705ADE8A819F575ULL,
		0x7D815C52069B7609ULL,
		0xF0B9848D886FE4FDULL,
		0x3BC9511D0C04CDF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x756F335CB1C8ED4BULL,
		0x8A91B47071F27298ULL,
		0x3E7ADADEBF3095DEULL,
		0x802070A275073FD6ULL,
		0x6362D9E2C40A04D4ULL,
		0xAC6C6AFFA323B2D1ULL,
		0xFECEEF58BF991161ULL,
		0x0CF368778715B358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98F089D9DF7D156FULL,
		0x4D3210D60C6C3EFAULL,
		0x2D685A94F4CC9771ULL,
		0x488BD2764900936FULL,
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
		0x7F5F02B8AC29732AULL,
		0x193FBFF1CB9D25C1ULL,
		0x39CB3700BB7CB793ULL,
		0x2A9896D86959D3FCULL,
		0xABEB2460AB4DFE64ULL,
		0x7EC721198297721CULL,
		0x001A3FE2CD582C77ULL,
		0x97BD70837C902DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C5352A7D0639F1ULL,
		0x757B6DCB6D1A58A7ULL,
		0xE6F8FC5718E71ECBULL,
		0x49B4BE7A490D182FULL,
		0x2B820A4AC20A03E2ULL,
		0xCC3FFDC9D79A2D48ULL,
		0xB13AA62AD612C0AFULL,
		0xD4DFD8967B171501ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B33ACCECF3A671CULL,
		0x23D38FF9C01B04A5ULL,
		0x08030BF856E3986CULL,
		0x4DC8658C58466586ULL,
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
		0xEAA25FBA254E6E98ULL,
		0x2527D48C84DA52C1ULL,
		0x8902F346E8E4D78FULL,
		0x946C604B560981A1ULL,
		0x0DC759B50FCFA2BBULL,
		0xD8D4031A32A9AE2CULL,
		0x2EE226D53266C4F2ULL,
		0xD3A9B1C12784CEE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75342B14A0457FE0ULL,
		0xEC556976800EDAA6ULL,
		0xCC56729F7DF0C17EULL,
		0x4D02372D3CE129A7ULL,
		0xE9743A0552D8498EULL,
		0x45F2D83EA401C75DULL,
		0x86EFEEC76D896798ULL,
		0x117306AF145EA0E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9C4E8BB91C02FB4ULL,
		0x063EC7AD31B7BAB4ULL,
		0xAAA0D2B2A3CFF182ULL,
		0x1B878DCCF0D32BA0ULL,
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
		0x510766C7259B2C74ULL,
		0xFEBBE43D477D3463ULL,
		0xF227E78BF40A292EULL,
		0x949819F31213061CULL,
		0x6F15811FC1496681ULL,
		0xD0D00FBD23184E82ULL,
		0xD8E9D06F034F6150ULL,
		0xEA5A5D51D880B13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F25A1E183206D6BULL,
		0x87D942C3C564E5D8ULL,
		0xACB5CB6F8920271CULL,
		0x372003DB06ECE2D9ULL,
		0x9F375ACF889DAE3FULL,
		0xD1868CF5ADCAB3FEULL,
		0xDF28A19BF34DB6E1ULL,
		0x8AD83C12F9EE124FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCDB74CE0BF81AFCULL,
		0x5BCC0B14EB9D3E1BULL,
		0x581F0F70CB294E8CULL,
		0x0AC9056D14E9BAE2ULL,
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
		0x587B4735CFED774DULL,
		0x9E9BD2570C5C14ABULL,
		0x3F5AF7F277D1492FULL,
		0xE31653C05A9F0DB5ULL,
		0x668B17ED3E3ED7C3ULL,
		0xAD7BDC03CA5A8400ULL,
		0x3F9F8707E8C32E54ULL,
		0xF9B685A171E61735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE584F86B07ABF0A6ULL,
		0xD917AAC51A3D4F08ULL,
		0x11D01A3DCCD72101ULL,
		0x9C927F2A7575F9E0ULL,
		0x6B1BA65D6073B96CULL,
		0xD2A3BCDE0A17DE53ULL,
		0xF40745CAFCAE4F90ULL,
		0x7876072036025E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5812A25B4680A63ULL,
		0x4198C72C7C035D4FULL,
		0x66248CBFB6133940ULL,
		0x76169BC4C8F67B7AULL,
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
		0xEA4AF01F3BBDFC10ULL,
		0x0857669AE7153071ULL,
		0x1D3F3AA198B0579EULL,
		0x718B720C46C5CD99ULL,
		0xAAAF5711C0DACE22ULL,
		0x811394CC45607FCDULL,
		0x032E39C3932720E8ULL,
		0x68AC9F831849649EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D0A3EDC98CD23BEULL,
		0x6B86EEA5554A5237ULL,
		0xC8DA9BD3A2480EF1ULL,
		0xE6B50BDFB9D4C5C7ULL,
		0xA6EE95632E71BCC0ULL,
		0xEE03F9E8F9766C0EULL,
		0x67B8AA49E7FB5451ULL,
		0xEBB96B4D5C103F2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBDD712C5E8969E6ULL,
		0x712175B2D689CC94ULL,
		0x67D7EADD5EE8A706ULL,
		0x16F026267D6C9688ULL,
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
		0x5A940ACC1EED25A9ULL,
		0x804C9F590CAA07C4ULL,
		0xB1F199B891F041CEULL,
		0x51741B0CEB35AF99ULL,
		0xD8FD9B782404D629ULL,
		0x5402157773750145ULL,
		0xA5D16C75126EB4F8ULL,
		0x84ADB3661C1CE9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C2906C65F8F202ULL,
		0x01112369C435C0DFULL,
		0x8F1C15E490AFBA35ULL,
		0xDFC32BA1A8808EF2ULL,
		0x1DA38C3961245288ULL,
		0xD8663B70A7625482ULL,
		0x7B7C90B979D8087CULL,
		0x68394C1BA7B0CF03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA72FBDB0A647BE12ULL,
		0xD85DD8F19339EBF2ULL,
		0x6B6E21ACA79E21EDULL,
		0x2AF844788AC11B8DULL,
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
		0x965DB4E8A392CF49ULL,
		0xC4996173190B0BC0ULL,
		0x542D543A72721980ULL,
		0x040C3555F23D7256ULL,
		0xAE0BA55138CB5E53ULL,
		0x5D23A962678D55A6ULL,
		0x84647330EE0DE604ULL,
		0x1D50FD8272DD9360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87192AC5453E16BULL,
		0x5DFA5CB32D256E0CULL,
		0x73FB3D5657B0516EULL,
		0xC5E93E5C4BBF7333ULL,
		0x049D8E6195E53277ULL,
		0xA42B94EBC8DADB60ULL,
		0xF56A717CAFE839FDULL,
		0x6EE8FA6647CF76FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD44389CE7D696E98ULL,
		0xDB720E5B7A63C430ULL,
		0x194E57A554595111ULL,
		0x21936D280A9635EAULL,
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
		0x6995101666274F52ULL,
		0xF6AF4F83C7DDFE78ULL,
		0xE072C71D8545063AULL,
		0xEF6BB6C218FD34B9ULL,
		0x5EE1EBCDD8267378ULL,
		0xC9CE27AF63AC539FULL,
		0x5BC461DDD78B2595ULL,
		0xCEED2462ACED0D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5081FDE01F0DB7BDULL,
		0x410A9150CD30687CULL,
		0x0C3F4612E4E184B0ULL,
		0x9245C974C9E0025DULL,
		0xCDB0DCB42FF265C2ULL,
		0x7A5287366E977FB7ULL,
		0x6737C036F47EDC50ULL,
		0x62B0E9802E92E1C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA65B50053ED3A2F9ULL,
		0x81FE90275BC50A5BULL,
		0x21137FD0543661D4ULL,
		0x6E16AAEC107FB27DULL,
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
		0x5413DE3B8203A333ULL,
		0xD1F3A9FDE7C3D9D3ULL,
		0xC85F7EFB81927F0EULL,
		0x4ED4CA139BE93D29ULL,
		0xC2BD0D5225334BCAULL,
		0x4335BEB4F58DE690ULL,
		0x44A377442EE00A70ULL,
		0x1EB506A560EC0792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E2FBC032F7703C3ULL,
		0xE2B967CE3738C7C6ULL,
		0x01BDFADDF8DF8D81ULL,
		0xB988402C6150D2EEULL,
		0x63083C813D11C23BULL,
		0xAC9E966F78378396ULL,
		0x6047C99D6E826CD0ULL,
		0x891879B1C65D285BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ABB213AC7870837ULL,
		0x49AA3C804B5DC337ULL,
		0xAC3D4ADE1698573DULL,
		0x4A8976102BCD8C61ULL,
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
		0x4E7E36E262CAD750ULL,
		0x012D823E2E9DBBFFULL,
		0x837F536A4369700DULL,
		0xC9B0650F1D05BD6DULL,
		0xC9662D76CC1D7E12ULL,
		0x6B3158BF6AE737FDULL,
		0x168BC2DF7C7FD167ULL,
		0xB0589CBD55F4AC48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAC6A0C21009F57CULL,
		0x7F98A109F4C23944ULL,
		0x158910EC529452F1ULL,
		0x1F33B940FF019600ULL,
		0xC836C4E41276A342ULL,
		0xB8A8A5C6590392CCULL,
		0xA99DE0BE0ED14E56ULL,
		0x3029F46FFE6F264DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0C11BE7E1855F99ULL,
		0x01DF722CE1A60800ULL,
		0x9945D37438BC9196ULL,
		0x3169A7491BD60A99ULL,
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
		0xBE2F86F5182E4345ULL,
		0xA9C59554B4739456ULL,
		0x688608C6EB927205ULL,
		0x303BD3283DF96A39ULL,
		0x6F0C546997BEEF44ULL,
		0xB5B0898D8F168813ULL,
		0x037ACDB89C7F45D7ULL,
		0x05C91275CFA96E64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x148AD8E697B7A13BULL,
		0x6A7AC7056F4EE69EULL,
		0x819A9B070F9FA852ULL,
		0xA2483ABFD00B8161ULL,
		0xB58E87F69E716A53ULL,
		0x1AEFAB02050324E3ULL,
		0x68A33AF0589C788CULL,
		0x0F1FB3C5A417C93DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3251071F81F85D84ULL,
		0x37EBD705C40566CEULL,
		0xE2EB3779EF9D42ECULL,
		0x2B17A68EE58C6C92ULL,
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
		0x449073713169D2F7ULL,
		0x66E09E61E9A2E4E1ULL,
		0xB9AF02D0007E3C51ULL,
		0x09FD4B693BE05D8DULL,
		0x67458B4A5E48BAC1ULL,
		0x71F0A89B03E2E8BAULL,
		0x9BF6ACDCC2072312ULL,
		0x98876505EE0ADA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD784F33E2F2DEAC8ULL,
		0x18A705AA0B789976ULL,
		0xD37A48E3C44F196DULL,
		0x7D3840B5929D4B66ULL,
		0x2FDA00D6A69122D4ULL,
		0xED747A280174D2DEULL,
		0x5E38FCCB8A46A155ULL,
		0x594D3E2C40FF94BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7020D60477C76A0ULL,
		0xF8A87DCA3A818A1AULL,
		0x105CDC7A82C264DFULL,
		0x6F66CF0358EF6EEAULL,
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
		0xAFC93C5FAD91583CULL,
		0xE336778D1E9F8117ULL,
		0xB2F69CB49112D9E6ULL,
		0x2C5E7297809A8EDBULL,
		0x5FBEFBE45EE87735ULL,
		0x452A3EB20F502EB1ULL,
		0xC947890F0D97897DULL,
		0x3E0D378FCF8AFA9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0A2911FA9652C6ULL,
		0xF3EB5E1E99D30BBCULL,
		0xCBEE8AC635217813ULL,
		0x15F5BE716E070BD2ULL,
		0x581068AF5A851CB5ULL,
		0xCECDDAFE17916930ULL,
		0x8CB25323CE176915ULL,
		0x5C3DADC3C4A1CCB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5A8ED2C59BA73CBULL,
		0x8101E6254B1DC682ULL,
		0xE52E12D9C8F6312EULL,
		0x1B37286FB1305335ULL,
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
		0x978ABB580E9D9B0EULL,
		0x8DF3CC71F0120E3BULL,
		0x53CE688CA91619D8ULL,
		0x8CB03A1AC68DB0ADULL,
		0x7148F4A77745C981ULL,
		0xEECEDDB68C087CD7ULL,
		0x1DF8573E92AEF622ULL,
		0xAA3EE70BED3727C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA578857FF602E43FULL,
		0x469279525DAE4773ULL,
		0xDE7914846467BF75ULL,
		0x48457341FC201D93ULL,
		0x394D2CB66E974939ULL,
		0x5112DC1BCB9C5AEBULL,
		0x23C064110906275AULL,
		0xB6DD805696C236C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4171E39F6281C133ULL,
		0xB14990182270CFD8ULL,
		0x99A36CCAB3BD0C2AULL,
		0x64E005C39FC958F2ULL,
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
		0xCD2C4D1B7FA7E8BAULL,
		0x4DBDA4E0EDE16D86ULL,
		0xF91FF0D2EE521126ULL,
		0x661FD2FE9E2FC838ULL,
		0xB6DFC4B8990022C5ULL,
		0x51015D6E1ED52E85ULL,
		0x154F080A7BF1001DULL,
		0x84CD9EF0769383DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C64FA14840F3D0CULL,
		0x807C54DA7F086953ULL,
		0xBDBD53DED9DA428CULL,
		0x377EDDA0EB9BA278ULL,
		0x4E6DDDD358A2A817ULL,
		0x1833931D1DF3541AULL,
		0x919000496FCBB5BAULL,
		0x3E8AA5AD6045081DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31AF990E8978E311ULL,
		0x3BCD580C905F7025ULL,
		0xC9BDC39BE200D954ULL,
		0x1C91F553023A83BBULL,
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
		0xD89890A6DD31232AULL,
		0xADB7A6EAEEED233CULL,
		0x5DEDDBF854699B16ULL,
		0x272A09A76A070CE2ULL,
		0x12381FBDA85FB7F0ULL,
		0xCC7CF99FA75CC185ULL,
		0x028833E0967CFFFFULL,
		0x3179D99169B78804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2957DB456FAA2D8EULL,
		0x36BC99ED78C05AE8ULL,
		0x7665CEE05A6BCDE7ULL,
		0xE64FB32E8012B086ULL,
		0x0F2A67EF514BB0EDULL,
		0xB994B36917C2659AULL,
		0xA192609F8C0BA23AULL,
		0xAE8C5A165D6857E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2349FE025A7FFD29ULL,
		0x45757916C7166D37ULL,
		0x4C0568BF86D1B870ULL,
		0x301B42BCBDB5812AULL,
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
		0x34654C754CA06BABULL,
		0xA1EFD4509FD374B0ULL,
		0x0F81A4B12BBCC974ULL,
		0xFA223B5270E31238ULL,
		0x6E0797C985DD3060ULL,
		0xDA357D72DF285F83ULL,
		0x3B341EBBAC92DD15ULL,
		0xB75A959473A469FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA17036513DE1A00DULL,
		0xE00B5156DBB85707ULL,
		0xF79E381A8800975FULL,
		0x51DEB2FC5FFCD9EDULL,
		0x6BE6ECAD799231FBULL,
		0x0D055FB6331AEA79ULL,
		0xD56240710A8D8C6EULL,
		0x1CE660232B7A4A7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3CE7C4DE1E09219ULL,
		0x3708ECFB4E1A7D24ULL,
		0x350A6BAAB0862AFDULL,
		0x15837726C726E475ULL,
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
		0xC62AD65454A3933FULL,
		0xABD6A746CF9F2681ULL,
		0xC92EE41989A700E6ULL,
		0x2EC7D35C2AF4CCD4ULL,
		0x2D1C2BB0EA3D9513ULL,
		0xA64A63C322A82672ULL,
		0x39BD5C428B21319CULL,
		0xD1EC773815054C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20143345FCFDF0EEULL,
		0x80814E28E5D04477ULL,
		0x20741403BBBCA033ULL,
		0x12F82A775C11E31FULL,
		0x543DE226F043B3CDULL,
		0xDB8BF55CF339FBA4ULL,
		0xB4286CEAB2AD26CBULL,
		0x5FBB98C401DDAA93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7158D8972BD153BULL,
		0x4399BC48F4293C98ULL,
		0x7CD6571FEF23FBB1ULL,
		0x0F10AE1FA6C4F38FULL,
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
		0x4CC15CA7FE6369A4ULL,
		0xD0E61DE84CDDF22AULL,
		0x859D9AD282ECDAC7ULL,
		0x78D9B2873CA56BE6ULL,
		0xB7262D27C2114775ULL,
		0x44A04E8D984C094AULL,
		0xFDE39F2C55DFB0E2ULL,
		0x19321E2C39FB386CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D77972F33F2DCAULL,
		0x598494BF46834F1CULL,
		0xAC86B08AB4120837ULL,
		0x292DB14CDC5DAE0AULL,
		0xBA21B35ED7CAA79BULL,
		0x3F67DE5A33A4BE0BULL,
		0x71FF608DF253366CULL,
		0xB586A2794AEBA5F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1893F707D19FF2CCULL,
		0x3DC230C9F72FCE67ULL,
		0x9CF835CA95B50015ULL,
		0x1B205DC9DC977B28ULL,
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
		0x55324AF244CB99FDULL,
		0xC1F8CFE67A871DFDULL,
		0x3FF11DC7A6D3D1F0ULL,
		0xBF7D685F58D18CE8ULL,
		0xD5B572DC1C2C4E56ULL,
		0x62D033F1C34110A2ULL,
		0x58D7F75EC49678D2ULL,
		0xF60EC6C21D0E3897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x090D092977AC848BULL,
		0xDA0347450B458B82ULL,
		0x63A26C3CB721C362ULL,
		0x4F4D545A905FC005ULL,
		0x6DF0AE33E472F7A5ULL,
		0x75ACA5E61DB3DE7DULL,
		0x72B169FDAFA633B0ULL,
		0x17B7B56C7F0A0539ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB35A72C112A1F89EULL,
		0x1B3C9E5C02370408ULL,
		0x0607ADF40B5C5197ULL,
		0x711CA6BA3D116CD3ULL,
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
		0x5A9492889A3694AFULL,
		0x328FF1BA86A2F327ULL,
		0xA308538263796999ULL,
		0xAA935889A356B413ULL,
		0x7BB3BA35EB60BB3BULL,
		0x5B3B05826464D6CCULL,
		0x0930A97B9EE94634ULL,
		0x0C6667FCF83B669BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2530A4B1D67D13D6ULL,
		0x00A81787ACA98C45ULL,
		0xCA4555119308A1E0ULL,
		0xAFBFD86E5B27DDDEULL,
		0x01BA077F3CAE651AULL,
		0x82D9FB961C7E1518ULL,
		0x6D275146A238B0D4ULL,
		0x588711CBA3219F8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x507474F4B232480AULL,
		0x504F5345863A27ACULL,
		0x0226164E52A6F3F3ULL,
		0x2DFA4B6DEA026286ULL,
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
		0x66C9AB9A23D99E32ULL,
		0x8625B95BC9BF0E7FULL,
		0x426305A05BE728ECULL,
		0xA72061E652325D3CULL,
		0xDE001A5D293605BDULL,
		0x6BAA9C92ED14C41DULL,
		0xF62F3BC4DE176434ULL,
		0x05F8C9966BCB1B2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB105F64C8B272FFULL,
		0x3D83107962D9DB35ULL,
		0xDF2A315EED1ABE03ULL,
		0xDD9D297D2380A246ULL,
		0x2006A2BD57699086ULL,
		0xD862AD6F713491B6ULL,
		0xE8599A76663C11ADULL,
		0xB7BE38FFA5780B25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC10DEE7F808D5BULL,
		0x25502826CA2CAEAFULL,
		0x70EEC5E7395AAAE3ULL,
		0x6634AECA9F061C01ULL,
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
		0x6B78B59BF622CAB1ULL,
		0xB3A46F255763630DULL,
		0xB27CC860DBB270CDULL,
		0x6F9682ACF1799210ULL,
		0x82E68ED5563BF245ULL,
		0x479F459917767CFAULL,
		0x412CE303CD078253ULL,
		0x22E75D02B4BC14B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BACE65CC975C14AULL,
		0xB7A9706ADEA044DFULL,
		0x89DE7AEFBD498B50ULL,
		0x66586A84FFBCFF6FULL,
		0xAFE2C5B10FF36662ULL,
		0x473CF30B135F0084ULL,
		0x52BA2062487F8A4AULL,
		0x3A6F2605B2DC9D5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x725BAAA19B71CC94ULL,
		0x0A933FCF143F97ABULL,
		0x8DA7316ACA97B6D3ULL,
		0x0B1641B638E84988ULL,
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
		0xCC9243D7A3204036ULL,
		0xC7D11824D095ABD0ULL,
		0x03EB79E91C00AC41ULL,
		0x55B68F0703E2041DULL,
		0x7D2FCAA01A5DAE02ULL,
		0x37762857A40B202AULL,
		0xCA3BC3446D61EEFCULL,
		0xF5112FCA6B06E5A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x341991CF9C825350ULL,
		0xA14206359117FAC9ULL,
		0xB9E0A9851C1CFE7DULL,
		0x67DAD6A3B2823E0AULL,
		0x2673F5840B2FD56BULL,
		0x490642C7B050A592ULL,
		0xE01F4EFEBD6C50C2ULL,
		0x9E55BF9737DCAE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x785A5432476C152BULL,
		0x8B2B254D6D2BE3A4ULL,
		0x0A4412BC1E592A5DULL,
		0x4DAE5FFCE9A3F1D7ULL,
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
		0xE95620066C8DCE0CULL,
		0x15D7A8933E94039DULL,
		0x51ACCD1DC3C4DA9DULL,
		0xD1254D211FC00FFAULL,
		0x9F8BFC62E35851A1ULL,
		0xA13378C746763044ULL,
		0x46B20320608928C6ULL,
		0xE7846A7571EEB63BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7036BB7719E56220ULL,
		0x4869839260A0544EULL,
		0x396FECF25AF5861FULL,
		0xE6134585ECBAF387ULL,
		0xBE02E41EC0E65E0DULL,
		0xEA84D58DCABBF4D5ULL,
		0xB930AB4CE6D50C5CULL,
		0x22662A47EF7BD54FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF378FEAC6F929832ULL,
		0xEB5A5F893B9881C4ULL,
		0x196FE98F798B8C2EULL,
		0x2D8F8E5C90127F6AULL,
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
		0xF814CDC174D431BBULL,
		0xCF4C7A294EBDB11AULL,
		0x74564FA8FA8097AFULL,
		0x44DB0B239C0E61F3ULL,
		0x8BC22C1260FA1263ULL,
		0x912A8D77D1E73375ULL,
		0x48C557DF12F35AE1ULL,
		0x2B8F95E0D82632AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x068CD1F0CAB82785ULL,
		0x431C93055FEC47B8ULL,
		0x883C1AD6655A4900ULL,
		0x22FFBDFC18CF8B46ULL,
		0x3190021B9CD2BA7FULL,
		0xFA00D6A3F1C985A9ULL,
		0xE6851968F81BA284ULL,
		0x5F97DAE21E174BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54FA3671C7F314DEULL,
		0xFC610A97333935B8ULL,
		0x81A37A5A912BAC6DULL,
		0x68A10EF721752237ULL,
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
		0xD7EF9412B2467D72ULL,
		0x95EC7A3CE5C0C2CEULL,
		0x056A12A14177B737ULL,
		0x60F7FF379247151AULL,
		0x1D43BCA7E94B6B03ULL,
		0x5F81767E64750D64ULL,
		0x8E67D1AC6AD37296ULL,
		0x7F71E98624A92781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DB3BABF604B4080ULL,
		0x835652C0D7C97FA7ULL,
		0x8E421200E801FBE3ULL,
		0x582173135918E50FULL,
		0x650150A1756A7FBDULL,
		0xF9FD907485171922ULL,
		0x00F06777529C0637ULL,
		0xA44DF4F5C26182F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA417E248855E2885ULL,
		0x242A4CF335E984E8ULL,
		0x76E1C481F1AFD157ULL,
		0x102CD992CFD09DA5ULL,
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
		0xD0139A2E7BFBEF4FULL,
		0xBCCBF69DD3DE807FULL,
		0x7E4BFC4F5691830EULL,
		0x3C5744CD8DB671C6ULL,
		0x0BC928BD23D67059ULL,
		0xB3B6AC6948F79108ULL,
		0xDE08402E9969E7F7ULL,
		0xAF24C75E5352360EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8532A10857DE369FULL,
		0x14F18109471DFBA2ULL,
		0x4A3B6CC8222BEF48ULL,
		0x7FE7CF51E91EFDF0ULL,
		0xB72882ADA0A3595FULL,
		0xC6E62B6CCF132B39ULL,
		0x8F22765BF472903BULL,
		0x224C11462D8310C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAB99F739DB324D7ULL,
		0xCECD9B0EA4A7A17DULL,
		0xEA2C84CBB11C99ABULL,
		0x249A7D114156FCDDULL,
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
		0x9010230AF0371A8FULL,
		0x326B2E05EC561E06ULL,
		0x57CEB5776A597967ULL,
		0x3D00AA2A762D76B7ULL,
		0xA5703FA8CF28D15AULL,
		0xA8EB42726E528857ULL,
		0x199ED19098AA8231ULL,
		0xAC27B28078CE3D39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA1E35AE78D5052ULL,
		0x43E420C870C4FDEAULL,
		0x5FE7D525BD8D6F10ULL,
		0xFB13784B5F848EC0ULL,
		0x2678649AF0DD89BDULL,
		0x66E067D88AD6741FULL,
		0x1B666FB1EE79DA95ULL,
		0xDF4D9ACE359913CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE38C3BF07D66A48ULL,
		0xBC2380153FFC207EULL,
		0xB445675EF004EB88ULL,
		0x2A4CB655108D0DFEULL,
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
		0xBD0BC74A5EC6C028ULL,
		0x0075C10EA0AEAEC5ULL,
		0xD9F9E44BEA52ABDFULL,
		0x4ED386F3A6A69423ULL,
		0xB6F6B5FCD2FFB374ULL,
		0x90A6C8DACBD99749ULL,
		0x3C215A0D65A19361ULL,
		0x7BC1DCC588A0B324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5867A3A74743BEEEULL,
		0x4D990908F4A90B0AULL,
		0xE2158891220EEC87ULL,
		0x4DD30FAAE2D8166CULL,
		0x4EE0F3539B3A3103ULL,
		0xD364D023AE801282ULL,
		0x90E0EF2C87A4F093ULL,
		0xE2EE824CB58927E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7DF08C15ED45BB3ULL,
		0xCAA7A334074F5954ULL,
		0x6374391BBBC3E9E1ULL,
		0x305FE538194D2904ULL,
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
		0x5E4F7CD6B5740673ULL,
		0xE4F71C10FD843DF2ULL,
		0x64F7F1F02FED5EF8ULL,
		0xAB4B76B481E429FFULL,
		0x3F8BD116BF34D39DULL,
		0x41F65234F3473C27ULL,
		0x6EB4EE99205DACD9ULL,
		0x67CE0A413911F34FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D26DD184E901D3ULL,
		0x497E698817FAD595ULL,
		0xA6EAA3CC89B7F170ULL,
		0xB8D9206C05EBCE14ULL,
		0xF6814BABB099B31FULL,
		0x5BC80C5BA5FC70D0ULL,
		0x422A5C00C3AD74EAULL,
		0xEB0D005236DCB5A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x920CDCE95B91D45CULL,
		0xC65710CA5EA3972BULL,
		0x5A9F10C1685DBAFEULL,
		0x7719CFC2CFDF8379ULL,
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
		0x6AE5494E41881034ULL,
		0x5D6D4BCB67EE40F8ULL,
		0xAF7F150E32F3D0F8ULL,
		0xC715D7583DA204FAULL,
		0xB6B5996F33C39816ULL,
		0x0BE25B6D4E923736ULL,
		0x5F17205783BCFF8DULL,
		0x4355CD9DE45D152AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17A295B94CE81669ULL,
		0x38AE7C23D412C479ULL,
		0x08F5D12C37FDD2C1ULL,
		0xD06F40771C731F1DULL,
		0xA29E5AB5C9528638ULL,
		0xBF1455B4F6302A71ULL,
		0xD7D0EB73EB4E7962ULL,
		0x4D54284D0616A6E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EB6031AC168A073ULL,
		0x8B53A904B26961C0ULL,
		0xBAF51DAA9B5DE87EULL,
		0x7AE520E21FA343E3ULL,
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
		0x7DBFC253D14C7793ULL,
		0x619F2FCDCF3A9962ULL,
		0xCEFDF8AABECB7861ULL,
		0x6F5AE79A3E9DDADBULL,
		0x14E9C0A06AB3AACDULL,
		0x435F93C2BE01653AULL,
		0x253F60846CCDD95FULL,
		0x7C28500A2E2F4ED0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1165E16993DE02C4ULL,
		0xE29671003B4AD25EULL,
		0x5ECBC6F6943323E9ULL,
		0xE95B4161589C01B7ULL,
		0xCF63114E27875802ULL,
		0x911DD0085A39F18FULL,
		0xAA26C99C89EBC16CULL,
		0xDB5A5E028D9CCC86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE57E7203602BCB7ULL,
		0xF4CBCC78638AF24AULL,
		0xB5D8981FD827E27DULL,
		0x6491935ABBC1300CULL,
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
		0xA25448B8D39CBF37ULL,
		0xA84B648EF931FAB0ULL,
		0x84B4CF1EFB009F6DULL,
		0x0C06FD6C284D64B5ULL,
		0x560DC4472272461CULL,
		0x7D8BED371299B243ULL,
		0x11C065701F919223ULL,
		0x5A7B249C64EDF615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D3CBB1BC0703C48ULL,
		0xA0039C0265EE7526ULL,
		0xC8971620CB349C5DULL,
		0xB4A0EFC9CBF7D914ULL,
		0xAE74004CC4594088ULL,
		0x45B0E4BB3865535CULL,
		0x4A262D18A8A7446DULL,
		0xD54088071FD926DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75EAA4C70AE35415ULL,
		0x52CB0AEEF7099BC7ULL,
		0x5D0215F9D6938C1CULL,
		0x1E194BCA9D6C4E0EULL,
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
		0xB3D1A194DF769A19ULL,
		0x46F2E6F04BDD317AULL,
		0x74C44076BC64E662ULL,
		0xB43FC97A6B9196B4ULL,
		0x1501729156470168ULL,
		0xC6998E2EEA650AC0ULL,
		0x104BDB68F687F9F1ULL,
		0xBFB87DF02200FCC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x204FA74A96CBF417ULL,
		0x6FC9FE9CF7AB8337ULL,
		0x45519D893D9E69A2ULL,
		0x9CCF57C234626512ULL,
		0x3EC6A8AFE2792781ULL,
		0x25AF0D2CB54C6DF2ULL,
		0x8DE71FB9122CE2CDULL,
		0x81268F5C5D9463DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x603BF1C17938FFA2ULL,
		0xB9F80EA735D8F4D1ULL,
		0x8A667F09644BEC2FULL,
		0x6119DBA75F4DE38DULL,
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
		0xCECF3E7B80A20C7AULL,
		0xCF3250F930724F68ULL,
		0x8018B89D450683B3ULL,
		0x37AE64CCC2C3DA31ULL,
		0xC08BA6E2B64D430CULL,
		0x6E8975AEF87641B8ULL,
		0xE94550C787D8DAF6ULL,
		0x4B175F16D6982874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63211629132AFFC2ULL,
		0x5207583D0DAD997EULL,
		0x5937709625C2B623ULL,
		0x4C36BE357F9E8CF2ULL,
		0xE21AA5C35FD1D645ULL,
		0x02A7373245E97A83ULL,
		0x70D7C19F70AF6494ULL,
		0x3F2991722CA739E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x707452F943C9327BULL,
		0x80C03F3EA3AA47C3ULL,
		0x072487FA8F6B602CULL,
		0x30C42D087CE8B619ULL,
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
		0xBD7D5940E75AABB1ULL,
		0x852C0CF4604081EEULL,
		0x8F26C6AEB86199AEULL,
		0xD6EB23B7D8CD71ECULL,
		0xB0F6EF2813206D9EULL,
		0xB22DA82FFCB9CC9BULL,
		0x704B44F4F1CFF6E6ULL,
		0x7392A56F4A9E5C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4A67316C06EB638ULL,
		0x5F7128658AECEA97ULL,
		0xEBFB57AA6704D3D6ULL,
		0xAA077C4BC769DE82ULL,
		0xE7BA345863F6A552ULL,
		0xB6AFE6CCE9E7E286ULL,
		0x4829FECA3EA0BA5CULL,
		0x01CC62A190D291AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7DAA0FE271FB347ULL,
		0x7A659943A07C566CULL,
		0x981BD95AEA5FC253ULL,
		0x105191F5A5A39DD5ULL,
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
		0x96B4A4221C7754E0ULL,
		0x75B5442DC02BE8B0ULL,
		0xB477240A5B3A7604ULL,
		0xBD4BE8FFAFA109E1ULL,
		0xC50883F10A5EACC7ULL,
		0x90FF90169FDC2287ULL,
		0x8D2D1A86B7287E87ULL,
		0xA266FF00745E0502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB35A44137BA309D7ULL,
		0x84A861FDED13685EULL,
		0x0DD970BAE3843817ULL,
		0x8E831705BE148E4AULL,
		0x4644685A9917408DULL,
		0x8D6CFEA1412DADCAULL,
		0x5952053B60427E78ULL,
		0xE13C40C52444D2C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4767863716E5A3CULL,
		0x78CE799BE0FDD472ULL,
		0x5922DC7E5DDA4027ULL,
		0x5B210EC7D549F145ULL,
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
		0x533A2E84DFBA8E47ULL,
		0xCDC29836A705B2F6ULL,
		0x0460249C33FB8F55ULL,
		0x06A6AC99E588D9B1ULL,
		0x0BB7BDC74F309676ULL,
		0xFCC3C7E351E98FAFULL,
		0x2598739C203BEB7CULL,
		0xEF1231018818AD56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339BF47597615015ULL,
		0xD832DE7D23381B03ULL,
		0x8EFAFFE4DB06034DULL,
		0x84E4AFE91038B5C6ULL,
		0x1300453183131C4DULL,
		0x3D7117426A83DF67ULL,
		0x4A086F952C15F162ULL,
		0xC02DB243B0B15BBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ADA204B94B9612CULL,
		0x5BD5F19BDCE5C2A2ULL,
		0x0CC5BDBF9698AC00ULL,
		0x77ACCCDECEA6409BULL,
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
		0x435DD2940083D6DBULL,
		0x8496BD3082ECF201ULL,
		0x307E8573B65C2A88ULL,
		0xD8640AD68A9E23C0ULL,
		0xC5EA6CCE8F74C3AFULL,
		0x70FE943276186985ULL,
		0x23F586B3E32AE6F1ULL,
		0x2C3E98F2530C4FD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAA7177530D3DBE0ULL,
		0xC623DED89EC1F27CULL,
		0x9AAD508D0F6C5E02ULL,
		0xB55CE6CAD0C93888ULL,
		0x14B12016B4963A4DULL,
		0x139A8442294FA9C2ULL,
		0x9F0CBC812684136CULL,
		0xF4C57D43FE0035B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7381E694CB85B13ULL,
		0x9B4D3C0349F77690ULL,
		0x505F386EA7B33251ULL,
		0x5F013FEC59A0CC31ULL,
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
		0x002690D6362E3069ULL,
		0xFE78BE5FEC2F1149ULL,
		0x66455D26FA568D78ULL,
		0x3FD1B701960CD29FULL,
		0x77A35B8D5E624B2AULL,
		0x079FC283AA58716BULL,
		0xDBEEFE36715D4954ULL,
		0x82644F3CD5A7E900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42B9D65031B659BULL,
		0x4F8370B7813FEAA4ULL,
		0x6D593FD36116B3C4ULL,
		0xA319FDAE1B574A09ULL,
		0xB6DC38BBEF27892BULL,
		0xC8EEA63D4ED18E69ULL,
		0xA07D8035252D4534ULL,
		0x42024A6DA1D1549EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA98A1E87B5CB97FEULL,
		0xFD3F801A00F4D8E6ULL,
		0xCBC4D184E8607657ULL,
		0x2B4470152C8F8F2AULL,
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
		0x22725DFE2711BBCCULL,
		0xBDDD6418AB177C5EULL,
		0x05465E0F766E63F8ULL,
		0x946AAE8611E5ADF1ULL,
		0x50DA571239582B4FULL,
		0x1F8CCAC21D66061EULL,
		0xEB8D27478B92484CULL,
		0xCCAD35EE3EC2FEB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE79BB6C6285B26C7ULL,
		0xD3053B7D34D4DA84ULL,
		0x99745E2751BB01C1ULL,
		0xF153F9B437B8D464ULL,
		0x698DF2731781C70BULL,
		0x2D168853A7DDEEB9ULL,
		0x6EE3D65D2E688520ULL,
		0xDBF34CF178B7293EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902D96D7048976ABULL,
		0xE8660500E8761AD3ULL,
		0xECF402B1F8E65ABCULL,
		0x5EAF4A573FEE888AULL,
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
		0xBE16CA0C61645302ULL,
		0xFAF91524BBD04F21ULL,
		0x3633DBF1E711E909ULL,
		0x7D1A5AFBACDDE042ULL,
		0x16B059C4E9D430C3ULL,
		0x76525F28A9AED667ULL,
		0x43484F0242F07853ULL,
		0xD227C67604D60BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E4245B10DF84D51ULL,
		0x7C10C1EC715E6425ULL,
		0xBC6A7B74B78D2E02ULL,
		0x24EB67634BA9DEAAULL,
		0x378E872B0D78D7B0ULL,
		0x1160563BBB7DF1A2ULL,
		0x7B4787D51858C67FULL,
		0x2C7A559955C95F67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ED9C73208FB4226ULL,
		0x7AD5A663A5B3E035ULL,
		0x29E6F1318209208EULL,
		0x6FEDB45A5D15969FULL,
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
		0xA3A7D46E4846C4D6ULL,
		0x66B57EBE428C7520ULL,
		0x966E48F9721FA16FULL,
		0xA4E1C81725F9E362ULL,
		0x9F21901D54A10A43ULL,
		0xF6A82F700B16C842ULL,
		0xADA804A3804D443AULL,
		0x4F7F8F546F6553FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE45BA7322A1BCEEULL,
		0xE6B7D3B86135DBFCULL,
		0x1146C8F8AE908DE9ULL,
		0xCF7065F9BC6E215FULL,
		0x786960A7C5BCD1FBULL,
		0x7B1CD7533D66F116ULL,
		0x03BA9D31ADCDDBCAULL,
		0xF05E0F8F1ED75551ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4B9256E5B855EF5ULL,
		0xD6ACBF4C697089B1ULL,
		0xBE64DAE602789437ULL,
		0x746A59675E9F8F7EULL,
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
		0x454E4E3254DEF6CAULL,
		0xB45D9E3B04E8CB2CULL,
		0x8C7342FBEC0496D3ULL,
		0xB3DE7627993EE14FULL,
		0xAB8F025E09B10B34ULL,
		0xE783804DCDAD1F19ULL,
		0x75F7EB0579B0AE5FULL,
		0x3AAEBF684331800AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0DD70CACB9CF48ULL,
		0x6E9839DE80397AA3ULL,
		0x52278DA2655B80C4ULL,
		0x31F1E9AD4FCD2E27ULL,
		0x98F1903C3D559621ULL,
		0x267E2070A8A92751ULL,
		0x0050430F1C47A5ADULL,
		0x98D1F7403C517DAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC9F6829FDB88653ULL,
		0xEC919F300346183BULL,
		0xB12EA3EB64406097ULL,
		0x08B2426B4EB20CBBULL,
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
		0x86FAE28F7BEF8434ULL,
		0x1D5D561CC17DACFDULL,
		0xEB42CF54FA9DD988ULL,
		0xF9F756FA694D1B74ULL,
		0xFF22573614F71A46ULL,
		0x62EF73C0E4CCC8D2ULL,
		0x8860379DACD5143BULL,
		0xFA7F7895A3EB576AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA2074CE9470021BULL,
		0x3FA5245833308D23ULL,
		0xFE64211866556172ULL,
		0x412FF92F3E2681B4ULL,
		0xBC1628B1E39C6486ULL,
		0xBDA8AF727EDE9161ULL,
		0x1E228893DF96A24EULL,
		0x7549BAB5B92A0CB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80A955603AF67F91ULL,
		0x66395567AFA95AA9ULL,
		0xB206A9B10B8D6136ULL,
		0x7EC18D0803D7B16BULL,
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
		0x28CD38814B802297ULL,
		0x1EDB697C080B9C00ULL,
		0x61DF16606CC0A5BBULL,
		0x228FF246A955B544ULL,
		0xC8C696A5935B8443ULL,
		0xCF912B97857F3F1CULL,
		0x3C976F5B24DA17E7ULL,
		0x1CDCB8DDA20CE2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6731CCDFF89BB70ULL,
		0xB05CCD5F008036CAULL,
		0x1CEAF363DA886A99ULL,
		0x3DBB92A8D931DDB9ULL,
		0x81078021778D1A6BULL,
		0xB3A4475EC3814F76ULL,
		0x431A96BA6E03B925ULL,
		0x8774A7ED30C02A56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8B7734F6C9A1AD7ULL,
		0x93A87C89D33CF7E3ULL,
		0x4D7C4AD7B60A4BF1ULL,
		0x1246E34EA187357EULL,
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
		0x89A5E42FD13CFE2FULL,
		0x3F6C6411AA88858AULL,
		0x7B7D1A86CE7FD8AAULL,
		0x2655AA4AD50B74D7ULL,
		0x95BD9604D8AA5CEEULL,
		0x213FBEE7D00D94DCULL,
		0x892A9D6590C60C5DULL,
		0xAA2119037C9E85E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C588D36F6AFB761ULL,
		0x3E9C520BAC2B0569ULL,
		0x7BA1F9D4505DC53AULL,
		0x70193786B66B44F8ULL,
		0xF829BEBE35DC1F88ULL,
		0x5011056271FE6D33ULL,
		0x36E9142B17C626C6ULL,
		0x4642703ED7E0F833ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x513F4B75052A6619ULL,
		0x0DBF9BD1F49D6328ULL,
		0x35957F60741E27D3ULL,
		0x09497FF492C338EFULL,
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
		0x557898D09463174BULL,
		0xD804CDB9F8E4508CULL,
		0x60E76A729704A4CDULL,
		0xA658EDB085ADC883ULL,
		0xC06E9A46B9690686ULL,
		0xA1049D1DE200942CULL,
		0x2B57594E7AF3312CULL,
		0xEAF2AAD1738AB744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD34D8AD12508A0ULL,
		0x628A0C16ABFBA872ULL,
		0xD855DFE10B4A49A8ULL,
		0x289B59E58A95967AULL,
		0x038E933F662AC8D9ULL,
		0x616B3FF503497AC2ULL,
		0x00ACCEE3BF03D95BULL,
		0x752E09EE54D35A78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11E6565C1E7B38F2ULL,
		0xE63E95B45C166DF2ULL,
		0xDDE2166971416434ULL,
		0x78ED75818A4FF856ULL,
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
		0xCCEB9739EC0D41B9ULL,
		0x6BDA22AF89E3198BULL,
		0x305D9B66C239080DULL,
		0xD725BFA2EA707FA0ULL,
		0xEC48713F3C8464A0ULL,
		0x54722B9704EC0A7BULL,
		0xDE9E9A61B9FF529DULL,
		0xE7010D3887E223FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D78045D70735267ULL,
		0x7B4E9ABD5ACD1F9AULL,
		0x6F48D3AA19AAB96DULL,
		0x02B6BC2D666670C2ULL,
		0xFFFF4E44EA20BC9CULL,
		0x1B0731C8CC904C19ULL,
		0x1997475DBBE193AAULL,
		0xE59BA472037B37E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB24EC404B664E010ULL,
		0x766C9C8E8CB43C7AULL,
		0x002B1A5460F8A6BAULL,
		0x097C90ED2B511AFDULL,
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
		0x51D40E954C2FC1DDULL,
		0xC2AFBFEB3A3A3822ULL,
		0xA882F1942F35AFF1ULL,
		0xCE652DADE29FCC19ULL,
		0xC074BF1648F131D2ULL,
		0xDCE87F584B2FF6F0ULL,
		0x4A5781187CD6AE25ULL,
		0x28CC7BB1A39F767CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6CFE09E1D3009F7ULL,
		0x7463567C4D78D0D4ULL,
		0x8C1281FC3B54141FULL,
		0xBFA87A544F200FD3ULL,
		0xFB44D315A7D3DAF5ULL,
		0x448713CD3B363162ULL,
		0xAAC8BAEA1481519DULL,
		0x33ED8A2B758C6A53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD021360F195A9C68ULL,
		0xECC260134BD4BA58ULL,
		0xCBA1DA7B708D5818ULL,
		0x67D48D446A538A4DULL,
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
		0xF9ECBC28FE480B6CULL,
		0xAA576B77309906BAULL,
		0x27D4BAEA2010DAADULL,
		0xA3931349A464EC4AULL,
		0x5D0386FE82E87CD4ULL,
		0xB13D9DC67A5A453EULL,
		0x97C9F7B8133442F3ULL,
		0x6E3EFA5CF827DE28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC3FD39F040081AFULL,
		0xB7BFE3E9CE06A45EULL,
		0x6342F5C3F5C3ACFCULL,
		0xAE2587225D865A3FULL,
		0xD4AB8123AD1F3421ULL,
		0x7995AA6EA1EB6961ULL,
		0xFDE53126D703B2ACULL,
		0xCE7CAEFA51E78F5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ABDC705B6285228ULL,
		0x3585A69783070518ULL,
		0x9C873EB519829843ULL,
		0x2C44BCCBF46A43D1ULL,
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
		0xCBE8DA4E1B492E18ULL,
		0xEF573B28B1BE45C0ULL,
		0xE0901E07FFB99034ULL,
		0x80A63737FEA06BF1ULL,
		0xC0EE7795420651CEULL,
		0x86685FA35F8761C8ULL,
		0xBC872439AF0B82BFULL,
		0x390500A76472A644ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE17E9FD34B3801ULL,
		0xD6F90B2FC4622015ULL,
		0x81E2EA0D201C1998ULL,
		0x5C51BDFAEC0D56C4ULL,
		0xE56B755542F44297ULL,
		0x5615D2C793D0D4B3ULL,
		0x61D328B52279AAE3ULL,
		0xA0A1AEA976CAD162ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3479B12E24AC35F4ULL,
		0x449F18992A7516C4ULL,
		0xD56489A7BD43814BULL,
		0x4312A4EE597CAEC6ULL,
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
		0xF0CDC8EE64040A79ULL,
		0x34044E3E6FA0668EULL,
		0x5E62242E7F804B59ULL,
		0xB1894FA64E93045EULL,
		0x21F39DC690C36B8FULL,
		0xAD0CF8BD200ADDCCULL,
		0x894C314CEFE411ACULL,
		0x9165C8232ED1EDE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5754DA2D5E55E95BULL,
		0x724A5534E68379A5ULL,
		0xC4F100B758C5BD4AULL,
		0xC1982F288379DBA5ULL,
		0x7817599CF25E2766ULL,
		0xD77AC47E62E53ABBULL,
		0x7A76FEA3A5D43A28ULL,
		0x6D60CD26BF2D68F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD02B0CEE88B63FF2ULL,
		0x756DBA599CB32162ULL,
		0xCD16A89825148BA0ULL,
		0x48AE61F65D84E4A6ULL,
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
		0xE30501C0D81CC6DEULL,
		0x0842EA52AF76D393ULL,
		0x786385B5E5022C28ULL,
		0xB78BF9D15A200C33ULL,
		0x6002A4CCA46CEE04ULL,
		0x42C518D601C4C504ULL,
		0x74B38B6E2F63C39AULL,
		0x29C6F5FDCB13B6A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A50E94BF60B35AULL,
		0xF56F17218FA299F0ULL,
		0x90D8FF5530853BC5ULL,
		0xD60C56219D88279DULL,
		0x36EB124AFDE3F66DULL,
		0xDF0A18BD67D95139ULL,
		0x21C40354A873EF2AULL,
		0x987EEDE521FB3E78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05DFB26AD110D168ULL,
		0xE095D6D7F8C769CBULL,
		0x3718BA2ABC1678EAULL,
		0x7230D758D639BB76ULL,
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
		0x57093043E6CC6A5BULL,
		0x09EBCE092EEEE14BULL,
		0x9A09B1B47F1735E6ULL,
		0xF667C544292E3E26ULL,
		0x9167240D7C5152BDULL,
		0x7256509F1FE71CD2ULL,
		0x23F32D703758F497ULL,
		0x97AF7A88AA867CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536A5B4A3FA4C2BDULL,
		0xE740B362699C045CULL,
		0x017FA1B5823EA00BULL,
		0x8B1ADDDE1C66B9EBULL,
		0x58D41670E38BD5DCULL,
		0x4A5223CD1E036A58ULL,
		0x9E66A25B9ED7F4D3ULL,
		0x8ECCBEF9D8F7D8DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6972DA385478313DULL,
		0x1349C1D30D1F5B13ULL,
		0x6B66B50D9FFE8CF8ULL,
		0x3CF4BE9927F3D31BULL,
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
		0x5496377F8CA53477ULL,
		0x8DE8190B30B0CB15ULL,
		0x8E61BBC7D889718BULL,
		0xDA0119144AAE645EULL,
		0x855C95D4707FE035ULL,
		0x2B5E93E570910A3CULL,
		0x9FD6E7F14B569E98ULL,
		0x37E650EC45F82A1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6739DB14E58595A0ULL,
		0xA091B3F31D561A44ULL,
		0x7A927380BB0315C1ULL,
		0x8C2BDF256EEDE00AULL,
		0xEC13D9AE55888883ULL,
		0x722A173150795ACAULL,
		0x1ABF8591F6D554E1ULL,
		0x5F729998403FDDC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE284A12A7D6A25FULL,
		0x6B20E7D4D6DEBBADULL,
		0xD547E26DA8B74CE9ULL,
		0x6F027067B51BD99DULL,
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
		0xC02EEA3CD78951F8ULL,
		0x9A071CE52BB2A253ULL,
		0x157932D5E219EA80ULL,
		0x9989D47399473A03ULL,
		0xC4948E527CD2A8A5ULL,
		0x81DFFDE48B02FBC0ULL,
		0x9B940E7FD10CCB3FULL,
		0x971E550AA1147CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x966ADB5ADD977C04ULL,
		0xDB9264037FC66A50ULL,
		0x3BE8A9D9E8CE98DCULL,
		0x970FC41D21018CF5ULL,
		0x8CD3A785DEBCD70BULL,
		0x01325E74541FA810ULL,
		0x688BE36CA9EEC642ULL,
		0x56977FF71032C78BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70665141712EF439ULL,
		0xD83A6389D1AAA42BULL,
		0x6CC6EDD3C7C00F44ULL,
		0x167DB13DF9C697FFULL,
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
		0x1D3128DA0244BD09ULL,
		0x17E59F88CE52FD3CULL,
		0xF70ACAF37467E5E7ULL,
		0x05A4988DDCA4D0EAULL,
		0xB9F4580D8668EE3DULL,
		0x008998BF2D6CB979ULL,
		0xCA3E96AF8348EA27ULL,
		0x1CA1B6AB9B0B466FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291DAFBB3D070CEAULL,
		0xEF7BDD3EE8CAB0ABULL,
		0x9C071CE49DABD64CULL,
		0x89920A18DCEEF69AULL,
		0x8055A2C30A877921ULL,
		0x086C5EA07B7E027BULL,
		0xBE6226491C3265A2ULL,
		0x73E7057F130FA476ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81A2622D28B51046ULL,
		0xFCC062D84EF7764DULL,
		0x1DBC5D422413BB56ULL,
		0x07C8DB112F0FE548ULL,
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
		0xA18E28A3BB09C373ULL,
		0x23C15A96A44CC297ULL,
		0xA13B3E755DEF4D5CULL,
		0xCD7ACF3044EE3148ULL,
		0xB9143ADD4784E9DFULL,
		0xF0F8B41EE76592DCULL,
		0xDB179DBF9D95A8A3ULL,
		0x06EECEB74BC10539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E38F43EE0596EA1ULL,
		0xF076E53156A6DEA6ULL,
		0x715133D73421027DULL,
		0x265CCF98CE1ECC2CULL,
		0x85163C3C5A2593C7ULL,
		0xDF12AFAFE22F2AD7ULL,
		0xE4A11F1B530F2DEAULL,
		0xE8E68AE3ED148295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB09004816D7177CULL,
		0xDB6F1DE013B954B6ULL,
		0xC580D70139C48256ULL,
		0x1C5810F7846AC972ULL,
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
		0x4118F46AE0A83455ULL,
		0x5292C715CB3AA56DULL,
		0x83331B8D32DFBE21ULL,
		0xA35C48D65EB0E627ULL,
		0x81FCAC2B4F92BE9DULL,
		0x9D12F304FE80C2AEULL,
		0x1E1781F728AF4304ULL,
		0x7744EE80BE291D0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBAE67378A3296EBULL,
		0x59373A3BDC5FD253ULL,
		0x79FC3FF7FC208ADFULL,
		0xF97DE3E8A67F95BEULL,
		0xF41BB71E769A91F6ULL,
		0xBD3529E8BA7C3F01ULL,
		0xADA3E4A3BBE28EB3ULL,
		0xF057AD60EE055803ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94CEED1B8B4C3B75ULL,
		0x3447670C07865EB6ULL,
		0xBA6035F75D21F743ULL,
		0x31160FA69D808F83ULL,
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
		0xACC49ED85686AF46ULL,
		0x43282304F1D500D5ULL,
		0x10E0F033E8E12384ULL,
		0x259AE5BB0A63702AULL,
		0x59206B9DAE04956DULL,
		0x4F916A6FC6EDE183ULL,
		0xEAD4D5C068E01946ULL,
		0xCA007EE61F2846A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E593317C320940EULL,
		0x83F145584253CB1CULL,
		0x897CD5F44C8E2329ULL,
		0x3A87C4D7685F5FF3ULL,
		0xEE73912C7905265FULL,
		0x8AE0C61A7C8870DEULL,
		0x1AD7BEF696F6B4ECULL,
		0x145B1BBE34CCC6F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6413D88E71509B3BULL,
		0xF16F4255BA8FEE21ULL,
		0x66F57C34C4F7E5ADULL,
		0x619FD8D06B99044FULL,
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
		0x9D8A31DDA1F8F342ULL,
		0x44229B502E7C9711ULL,
		0xEA97F33C3C72CC63ULL,
		0x22E2716CA18FB235ULL,
		0x67206A129E54C5C7ULL,
		0x7D5D0A8AB69FC48BULL,
		0x0A934C8C5E679A4FULL,
		0x363D5B24F1905EEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B01D2DC66C3EDDULL,
		0xF13157EC212E5528ULL,
		0xB35FC2E2FC871E80ULL,
		0x003477FC1E511471ULL,
		0x23A107D0FAEA11FAULL,
		0x2FA57C83D5AD22D7ULL,
		0xD125018A06B59305ULL,
		0x09E61ABCEC2FC4D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDC2AA6E1D6365CAULL,
		0xDC305869715242AAULL,
		0xBD9752B24458C2E9ULL,
		0x37A188E14F957CEAULL,
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
		0x8971612764142CB6ULL,
		0xA4438961273844CEULL,
		0xB404FC1A0FAF4FA5ULL,
		0x89C5E5DB2E5133B7ULL,
		0x6D69F601AE6A01DBULL,
		0xC01AED79C7881FBCULL,
		0xE653BFFE00D17AD1ULL,
		0xE9334FF6BDC5CB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F37B552D6449E4ULL,
		0x65D197DC2D761397ULL,
		0x2279360FAD66D5F9ULL,
		0x2B4A34365D4F40A5ULL,
		0x30E2A8794A6533EAULL,
		0xD9BB0A1FFDF6838DULL,
		0xD12F56352ACBDA6DULL,
		0xF4F0BFDB1EB50437ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x029368110F66745FULL,
		0x70ADB0D8E55F603AULL,
		0xB4F379DA271E4880ULL,
		0x205D15BE6D7F8A25ULL,
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
		0x7887A2B2D447A0A1ULL,
		0xB8653703EB3AB9B6ULL,
		0x14F49321C8C74C53ULL,
		0x069C421BCA7C7B1AULL,
		0x274DEFFC7DBE26ADULL,
		0x3E6C44542F5DB4F1ULL,
		0x70C9A5E6E3F0C2C6ULL,
		0x65383A95991D9B27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF96F5964FE4D1AD1ULL,
		0xE2273CF6B5F885D6ULL,
		0xBA39B27C9942C352ULL,
		0x23F48C26FF92D880ULL,
		0xDEE046F4C49E9FFBULL,
		0xF79503467F21E222ULL,
		0x44DBA2A054550F6FULL,
		0x9F87B99B444239E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F5F607350A882E6ULL,
		0x5A31A2155E237E7EULL,
		0xE00F5D1E80A127CFULL,
		0x3ADADB1D637A1291ULL,
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
		0x72E3C608F25F2433ULL,
		0x211D106C4FF4757EULL,
		0xD0FE90C92021289EULL,
		0x5BABF864F956DCDFULL,
		0x11834401A223642AULL,
		0x196BCBE85E5CCA7FULL,
		0x58925CB2501B413BULL,
		0x5E422DD7A0F3EFDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2473737993243530ULL,
		0xC12D6C657FB1FCC3ULL,
		0xB6C9D9AA77B2CF92ULL,
		0xA614D8E0C630E617ULL,
		0x3814A50C73F95051ULL,
		0x57447579210C90C6ULL,
		0x3C1F5B78CECB1CDBULL,
		0xCD3562631FCFA974ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94DBEAF43979DEB3ULL,
		0x31C67889EA2B0A2BULL,
		0x5346E5A7DA53BF42ULL,
		0x3D7D52CF5E886A16ULL,
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
		0x38A05821B7C7C0C8ULL,
		0xC20BDFEEF766D1B2ULL,
		0xD35CA2A0EC5775B9ULL,
		0xEE86570B80C7CD34ULL,
		0x8849D82A2218D68DULL,
		0xAE0C0BAF424841AEULL,
		0x17DB7109973C6F69ULL,
		0x17AE22541CF9154FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC830EF18C6B46874ULL,
		0xD3562FF154A54A09ULL,
		0x189E28A24F9A4A3AULL,
		0x5FD71CE23F8687ABULL,
		0x325D3693E3606367ULL,
		0x41C59809D2C4D4A3ULL,
		0x85B34FD76F7830F0ULL,
		0x7782D12C716A5D34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x318F655640746DE4ULL,
		0x012ADA8C3043B757ULL,
		0x6CB3677083DE7185ULL,
		0x551D460CB870997BULL,
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
		0xBEDB3997F7A746CAULL,
		0x6AAF97025483E22CULL,
		0xB1DD57E581F57ACFULL,
		0x5ECB64D255AC331AULL,
		0xF8417374D7A536BBULL,
		0xF9ACEF49231DB9F5ULL,
		0xA92AE1617DA65BB5ULL,
		0xF242D85601DA8D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6C2E00E86F4E67ULL,
		0xA5999C873040EE9DULL,
		0xFB8357500915C27CULL,
		0xDE3CF67F74F58F91ULL,
		0x0964C12EB6E3B917ULL,
		0x1ECAAD63CDDAE16FULL,
		0x3E6222552BDBB8AAULL,
		0xF8CDCD0511F573AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x993181FFEBF09E82ULL,
		0x42ABC285CC2F1796ULL,
		0x90265C699CF3EC15ULL,
		0x07EE1C567CB8742AULL,
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
		0x38698DDEE7B2A1B1ULL,
		0x79FDDDA52B3069AAULL,
		0x64D2EA3BCA76DBC7ULL,
		0x5F87C77DFF95F50AULL,
		0xC4D1FA8E112D19E7ULL,
		0x38594F774651F217ULL,
		0x401F369992740E2CULL,
		0x53888641E6AF4332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC37AF5CD6592822ULL,
		0xC5C1DC7E57ECA4B8ULL,
		0x2CE96A65FB43BDA9ULL,
		0x8069B0D967118195ULL,
		0x102B144E85CC0FC7ULL,
		0xCD8758C75E5CC264ULL,
		0xAFA864D5F7EFB028ULL,
		0x5C9EC8C250CB83A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CF80BF0C1C0FA16ULL,
		0x8F669F4341A8D99EULL,
		0xA98CA2DEBED9129FULL,
		0x05D03794D852E252ULL,
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
		0x1627F7D405A60B22ULL,
		0x40DEF5488B8AB2B4ULL,
		0x801629AF20106687ULL,
		0xCB47B7A49FE3D3E0ULL,
		0xBDC0E7F8130BEC0FULL,
		0xF6C255CB7F664880ULL,
		0xF071D764DF7FA899ULL,
		0x892AA63E56A85EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09AB87FCD0DC9A26ULL,
		0x19D3D62C47570597ULL,
		0xA23B777B937E0004ULL,
		0x3B8EC7350004E9BBULL,
		0x1FB51F9C98883A1BULL,
		0xC3BAD66F63125384ULL,
		0xFD0B563A5E944552ULL,
		0x62DC54CB46A33E83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x823C2D6B6455DC18ULL,
		0xBA2806C878AA0A9CULL,
		0xFF11DE82AF832314ULL,
		0x3F59078400A1B168ULL,
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
		0xF9D3C0ED14E3B12DULL,
		0x0C5BDE095C44F366ULL,
		0x40FE77F2E07BC350ULL,
		0x36EED835A0651A7EULL,
		0xB4BE9652873A227EULL,
		0xE31FB5980BA0A87DULL,
		0x045A58D019B66253ULL,
		0xFE8062BA94F00F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BE49DFC7D9C275ULL,
		0x787C3DB6C3F89D35ULL,
		0xD4203BABE9645DFFULL,
		0x2241C187322C83FCULL,
		0xA857ED7E85BA6FE9ULL,
		0x97AA2A064FD4B595ULL,
		0xE4D288DD48E99A97ULL,
		0xFF8AA6AA8F783B86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B52868585FE70C3ULL,
		0xC75257F4789264A3ULL,
		0x1B071A51F57D0B43ULL,
		0x6D27010F3E0200DEULL,
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
		0x457B0CEBE7BE89D9ULL,
		0x893F1E39434BA1FFULL,
		0x84B1043258576D86ULL,
		0xCE1C4E9F4AA2006EULL,
		0x7F4592198D869A70ULL,
		0x399EAD130EB96F9EULL,
		0x334D37E6B877AF94ULL,
		0xD2B9BF381DFEAE0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A61097B0AD19ECULL,
		0xF5C7BB5E64A97286ULL,
		0x693379C1B9E8A7DDULL,
		0xFE175EA906B94BDEULL,
		0xF24E9DEA2EAFDD0EULL,
		0x31AC0B49D2597658ULL,
		0x7DB6E92B99BA43E7ULL,
		0xB416A5D6B564AD09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B7D3B5C4AF18D11ULL,
		0xC17B66B9D4E12FCCULL,
		0x0FCD3A372E8CC157ULL,
		0x5C3AB46BCAC4DAD1ULL,
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
		0x51EA5548D045A1DDULL,
		0x103451A6BFD52A87ULL,
		0xA51E7DAEC12267CBULL,
		0x3B9CDAAD77F93C6BULL,
		0xB2D787DC9E1FD1FFULL,
		0xE02A98D64DD94ED9ULL,
		0x42284A435D550A5DULL,
		0x0C1D0386993B28FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98E753A48C7E53EEULL,
		0xAFD81C130E92A0F5ULL,
		0x199BC77DE5BF3751ULL,
		0xCB240AA8855768D0ULL,
		0xC56B28EF81E4723CULL,
		0xA88393ACE24008C3ULL,
		0x744842FF8EE7E4FFULL,
		0x8C3D17C89E80ADB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF71918D6749781E9ULL,
		0xA326F9B9AA02F0D2ULL,
		0x1AC3CA417F96BC75ULL,
		0x6BB5CE382A50201EULL,
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
		0x0298FA2A902CBEC1ULL,
		0x104C951EBF64E6EDULL,
		0xEC2383578F27788CULL,
		0xFDD6206134136906ULL,
		0xD2629D55CDE34283ULL,
		0xCCEF91DEFFBB4394ULL,
		0x2BCAB452C7186328ULL,
		0xF92E18C16D56988FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB14CFA8C43AB2FULL,
		0x99B52D00967D6681ULL,
		0x154C8EA7D48A6CA0ULL,
		0x79C141E3A6E8210EULL,
		0x12419320FE0C7E60ULL,
		0xB92B8154DE715431ULL,
		0x7DA525CA02E4E11CULL,
		0x8D0DB3E5103A47F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBACF3106DDCA3337ULL,
		0x65B1DC9F19E10939ULL,
		0xB06A1CFCDA4259B6ULL,
		0x10E3D7335F5F3E30ULL,
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
		0x8082ED0B2E6B44B6ULL,
		0x244B458A9EF362CDULL,
		0xC12ADAF9234ADECBULL,
		0x263C07BE565E1426ULL,
		0x7C338CDAF9896341ULL,
		0x9DF65E7D17911CFBULL,
		0x55BEEB97A42FDDF4ULL,
		0xB4E83812F4C22026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB42E8BF886278AULL,
		0xDD36FEE043CEFB85ULL,
		0x58D10286730D9243ULL,
		0xC5071FEC0B3D5E00ULL,
		0xB44B8FA216222C5BULL,
		0xB2F261BA62CDFFC6ULL,
		0x4F01EAD9352C3DFAULL,
		0x34A15997ABDF5757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E3E54F0F73745FCULL,
		0x29ABCB91301ABD1DULL,
		0x6867F4B72AC70BA0ULL,
		0x6BB9EE1F1CCA84E1ULL,
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
		0xE4656D175CEEAC77ULL,
		0xCBAB1EBCB4A4628FULL,
		0x9942F3869C0E0CB2ULL,
		0x7FD398F838592309ULL,
		0x56321D8F91A9E607ULL,
		0x4D206B9E4F3AAFBEULL,
		0x3CF0030E263AF055ULL,
		0xB86BDA8402555FD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB14C8C5FE8981915ULL,
		0x5F2DE1EBFEF5592FULL,
		0x37069AB85DE7BB8EULL,
		0x8C8656CD57F60A39ULL,
		0x9E5D30CA5998F8F1ULL,
		0x434B9C49A120B892ULL,
		0x4BEA823824EEAD34ULL,
		0xABB0B4560C6CF63EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CB405FDC6D9C4DFULL,
		0xE21403628D89B9DDULL,
		0x290D78926F78480BULL,
		0x5714ECFD60E2C4A0ULL,
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
		0xD4691D0CEBE77562ULL,
		0x77B5EA664B068046ULL,
		0x40E231F6AE6A731CULL,
		0x4F49BEA8982014A0ULL,
		0x1467B622C34835E4ULL,
		0x4E761AFA7E2B06ABULL,
		0xB0F2EC831272400BULL,
		0xA9EF03B084D01F6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2521CE8080898B81ULL,
		0xF5A97BF8FE35EA82ULL,
		0x573A9B2510E08FE2ULL,
		0x7B0CF0D9B1ACF432ULL,
		0x88A0325BA206550FULL,
		0x7BA6F5270DBF60B0ULL,
		0x72E1746B89010AFCULL,
		0x8AD5ADB20C84CC86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EE4DE1B5B254A17ULL,
		0xCCCC0BCFFCCB38F5ULL,
		0x203F6A500457C36CULL,
		0x71FF9194C1A16EC1ULL,
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
		0x7E67976BD923C519ULL,
		0x9ED20E5FC7EC4D34ULL,
		0x1CC92C5FD85FF3DFULL,
		0x78B3697959869B58ULL,
		0x20958109F88C42BFULL,
		0x22F484189E760446ULL,
		0x6368924C4E97D0B6ULL,
		0x8B15A97E241DF0B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFC487FB71BDB7E2ULL,
		0x14B2E21995D35C5FULL,
		0x4CF29DD608088423ULL,
		0x5B0B5F77C6BD27F4ULL,
		0x816D2BF4F151C086ULL,
		0x9B09107F0E95D6F5ULL,
		0x8BE03D8E00E09D43ULL,
		0xE4827898A3B2BF01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E9FB08F7A155FACULL,
		0xB71255118D5FAACCULL,
		0xCE1322C9598912BCULL,
		0x57814C12A2B2D487ULL,
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
		0x7B9B47B27CDED469ULL,
		0xD79234C15CBF4517ULL,
		0x6233547881442C1FULL,
		0x33B6AABE77EEFDFAULL,
		0x8B31C2110BC6D304ULL,
		0x76E969351B545950ULL,
		0xD8B387060FDADE96ULL,
		0x3072E2441C099C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B446A2E06ADDFB7ULL,
		0x22066CDC3597E309ULL,
		0x91026315FD7858F4ULL,
		0x7BC233811189E5FAULL,
		0xB7AF06101B1A9E4EULL,
		0x183666CB934909EEULL,
		0x220E44A004BCFC22ULL,
		0x477C0784516835FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5BEC5A82FC0C71EULL,
		0xC41E238F58D52A93ULL,
		0xEDB8CC882A3B7071ULL,
		0x4C98EFB57A5A4ECEULL,
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
		0x6FD49FE261ACF5F5ULL,
		0xE74256E6E99E9722ULL,
		0x8997C54BC028A639ULL,
		0x0451C5B0C5732630ULL,
		0xCC6B8EA18C0B0517ULL,
		0x980224AC58E7B686ULL,
		0x0F457696F24CFD6AULL,
		0x63563E225485D910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A660F3A7F9D3E38ULL,
		0x5ECC9B8903C025E9ULL,
		0xCE9AA8F2FEECA7C6ULL,
		0x66C83D70357E2AFAULL,
		0xBAF38D77054A9363ULL,
		0xA070B70EDB157484ULL,
		0x657CB00C4784D7EDULL,
		0x75986C9A7605A9E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD3EBCF7E2A097F0ULL,
		0x480C00BE93143D87ULL,
		0xEECA94EE1AF18F00ULL,
		0x67B6A26B96FBFB8AULL,
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
		0xAD81D79E84302F0FULL,
		0x9E71B27D9AFE4C8AULL,
		0xCC76D93010568E5DULL,
		0xC753EDF01CAD353DULL,
		0x0B580B9BAC17871FULL,
		0x81EA3164B065B91FULL,
		0x9F465FA312F6CF1CULL,
		0x820FE397CF7924C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2711E90727376090ULL,
		0xE093848C57548E71ULL,
		0xC9A8E4AD0BA127FBULL,
		0x16933A50B5709056ULL,
		0xBF3D162EA27C1D88ULL,
		0x89AEEAFE4AE46466ULL,
		0x2CF51024799B5665ULL,
		0x49B24563B9E76B9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2705CC6CA0A7C3FULL,
		0x96AAA12454DC5174ULL,
		0xFADFC14DC849518AULL,
		0x0EA62F5A9ADE204FULL,
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
		0xFD06243B843654E7ULL,
		0x84EC769236D446C1ULL,
		0x177D9B5C84F30A4BULL,
		0x2C1891D95F6076B2ULL,
		0x4E3558C20112C6E6ULL,
		0x8F4E4218390C5AA3ULL,
		0xCD6AEAECDD359D33ULL,
		0x54ECC15A6FFE10E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC389096CA96CAC2ULL,
		0xCF523600A6C0B8FDULL,
		0xA371CE4816FE615CULL,
		0x01CC3E13837F75D1ULL,
		0x135E30C734BA81B8ULL,
		0xED5174A56B133E8EULL,
		0x133DD2BED907EEACULL,
		0xA8514C86AB94C476ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCBD82DF0EB9CD1EULL,
		0xC120BF9C230DB8EAULL,
		0x16BD63E90CBC90EAULL,
		0x495FAB3503825904ULL,
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
		0xC1821BB14BD60CE5ULL,
		0x990D459F631391ABULL,
		0x2D32411109FA5963ULL,
		0x52F178AD2C8D40CDULL,
		0xD82D28835203DF83ULL,
		0xFC7CC96F5C59732FULL,
		0xDAA2003689C0E052ULL,
		0xEF54941703706528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD844DA9C550CC40CULL,
		0x0E03425D3EF6175BULL,
		0x8A10258E61B56165ULL,
		0xA3D7742BE9874714ULL,
		0x0AEACA985B43D68DULL,
		0xCCCB79971464638AULL,
		0xEB8F65C6C80B2BA3ULL,
		0x5CF64A65E6A9B625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x611731F5974AA07BULL,
		0x9F5BDD5CD27DCCECULL,
		0x1FE50819693DC9FFULL,
		0x6918F4CB8883F428ULL,
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
		0x6FB20765722979FCULL,
		0x5B41DB52A5D58DD2ULL,
		0x9C4C63EF8E7B9080ULL,
		0x7A0CAA7CDF34337DULL,
		0x1ED2822D082B41A4ULL,
		0xF767100962021782ULL,
		0x7D9236412E25140DULL,
		0x1FC5E5BE00D084A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EE9045F6EE0D4C7ULL,
		0xE030341EC49BD0E0ULL,
		0xE9388AC3C1E96CF5ULL,
		0x9EC5C00A2E55D490ULL,
		0x5869585088F57601ULL,
		0x19880A715F498DEFULL,
		0x1D843747E9445681ULL,
		0x3BF8312A3C5EA1F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x446539C0E544DEBCULL,
		0x6A2C7BC4489E28BBULL,
		0xF527B22C05EE4673ULL,
		0x2BCFB861D9C605D8ULL,
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
		0xE4F55F87A09B9EAAULL,
		0x07E515E00984E7D0ULL,
		0xCA9464D87A256482ULL,
		0x2F87AC473BFBA4F1ULL,
		0x025C0BDBEE37AC0FULL,
		0x8DE0CE59E1840DECULL,
		0x477FCE3768252F6EULL,
		0x0B94B1ED184E8C42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0003777F700A347ULL,
		0x4547DA5EDCC9185CULL,
		0x75B83580746EC2EAULL,
		0x9EFB2F4E77A42C1BULL,
		0x6C0ECEE52424CADAULL,
		0x924ECAD6DAE7201CULL,
		0x5EAAAD80EEC330D4ULL,
		0xF35EF5109964E94EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x946C34B1A868640FULL,
		0x1A49C0F428071C44ULL,
		0xE47F0A6E0A426C73ULL,
		0x288685B39B05A90AULL,
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
		0x1D94DD9622C546FCULL,
		0xD8F289DD6DD02812ULL,
		0x5EF36A89D5544744ULL,
		0x68C3B9E90F26D657ULL,
		0x4DF46B3717037CF0ULL,
		0x62A6F3E182349E8AULL,
		0x1E788E98B3648EB2ULL,
		0x07009335E02AAD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EC70773AD7C4478ULL,
		0x59B2936FDB5BA371ULL,
		0x23C8A415FB9720E1ULL,
		0xF81E16689AAF5C23ULL,
		0xAB2F7B849918900FULL,
		0x14E7916224C53D56ULL,
		0xC121A80C17285CC7ULL,
		0x744F4DFB2D0C359AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28096AA126282964ULL,
		0x09A8955570FCF24BULL,
		0x1610FF530AAC8F51ULL,
		0x36F5EA370AFD48ECULL,
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
		0x71BF0F128DBE918FULL,
		0xACC69F41DE5C655EULL,
		0x45203DE147A756B5ULL,
		0x83E7D6D5C0E16A0CULL,
		0xD9FA80D2CCBA4802ULL,
		0x83F45AFF3D9D13FFULL,
		0xF31430043CDBDC59ULL,
		0xF55529FDEB406F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857D57E882B0F6BBULL,
		0xD79640AA5D146A6FULL,
		0x509DCB0F9671243FULL,
		0x7A7253C8EDAE83A8ULL,
		0x8D9490D999A1428EULL,
		0x4BA342FE6D6E1F88ULL,
		0x909090675E8CB93DULL,
		0x0DB1B717C998EE97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43635627A0C46F18ULL,
		0x3139EEB6684044A4ULL,
		0x940C241AB0F568A6ULL,
		0x6BB89135D20FF9E4ULL,
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
		0x4DA30243ED249297ULL,
		0x6E010C969554D619ULL,
		0x609D9244FDEE1B5DULL,
		0xF479A188A0FC746FULL,
		0xFDEC402161A9EE3CULL,
		0x90C8914FC9B8AF62ULL,
		0xB37C83B970CA52D9ULL,
		0xA99898A9EA6E4AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACB854026D6BD3CAULL,
		0x65FA500E86B577D4ULL,
		0x995A940C3A99F622ULL,
		0x700CDEC6B54A89FDULL,
		0xD49FEC6521118297ULL,
		0x636034D762B7FFA9ULL,
		0xCC9A29BCB9587431ULL,
		0x4D1F6DD7362A848EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC23F1C331658BB5FULL,
		0xC584766758B973C0ULL,
		0x0CDC59BBFE3B3231ULL,
		0x3E691E08ADC15944ULL,
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
		0x6369755F47CD2BCBULL,
		0xC02BF81C4721F1C0ULL,
		0xCC6A80064E37CD98ULL,
		0x76BDD9CB320F56C2ULL,
		0xF785BFFB53E11359ULL,
		0xD223600364305F80ULL,
		0x0D3B0CECEFA63AF9ULL,
		0x16349A16F50DBF73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0DE6E81AC4BEB83ULL,
		0xA97B30F1D26EEF85ULL,
		0x9E1A9D8E2FC9C03FULL,
		0x677F4D53934C9EFDULL,
		0x10400EF253046358ULL,
		0x63E60A4C84FCC2EBULL,
		0xCA8FA3AF4B508F78ULL,
		0x97C05B1C67610913ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6E34E33BC435D89ULL,
		0x73CB804F965C407AULL,
		0x13C1819E8325828FULL,
		0x547FE5A8A665C9E9ULL,
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
		0xA9608B2319AAA219ULL,
		0x7C12D2F0D39B7B11ULL,
		0x0A5793A703BF0CCDULL,
		0xC1A8492B280578B6ULL,
		0xDE09DC85A8F6D018ULL,
		0x723CE337BDBC307EULL,
		0x95DABE1AEEA118D5ULL,
		0x1B0C3BAB0205CDCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x683F3000FED5F227ULL,
		0x45CA6C1AB509DC86ULL,
		0xBF9597F0F4156667ULL,
		0xAA0BEB1B25B543F7ULL,
		0x0DC7FB47B5F00A88ULL,
		0x8B45DD13BBAFC15AULL,
		0x7FDC9CE68BBB62E6ULL,
		0xA9205FA17D4AEAB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AE8CA542DD60034ULL,
		0x7EF3502E6C6A1E02ULL,
		0x8E7AE97CBDC2A7DCULL,
		0x009F0779B60DEAE9ULL,
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
		0xE51FB0ED0863862CULL,
		0x3DFA305BB67FFC1AULL,
		0x12B49A712C57CD44ULL,
		0xF5CA7DA6D791AC64ULL,
		0x11619E91A28FF72AULL,
		0xAC54A5AD4962D851ULL,
		0xFFB828C077A44D8DULL,
		0xD41F7F181A9FE29AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDECC02F8BA88C41DULL,
		0xFA3508FB250ABDFFULL,
		0xC5AC3D07B7FCD915ULL,
		0x2F946FA242B7B37AULL,
		0x8C8893760517D265ULL,
		0x8ED12245E1AFD36AULL,
		0x63118B43874F4A0AULL,
		0x847386EF058BAD3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE8B540DADB03928ULL,
		0xA54AA8B9F607F852ULL,
		0x8DC3BDF520F979A4ULL,
		0x19BCE41DB5D9E540ULL,
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
		0xE6294BBF741A6A3FULL,
		0x1D24BCD693E2F1FBULL,
		0x6F519214F9D5A849ULL,
		0x2AE392A1C677DC12ULL,
		0x49B62885C50F4BC2ULL,
		0xCD5AD6509211C833ULL,
		0x1E85B34DEB765B32ULL,
		0x2E1E8506F3BA542FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807FA13E73C17A48ULL,
		0xF561C8DEE3F6E9E0ULL,
		0x318F23CEB837034EULL,
		0xEBD5023800F9B194ULL,
		0x2333DE29E5FE692CULL,
		0xBD84223601E4B8AEULL,
		0xC18C8D1F3FB73266ULL,
		0xC7DFCBE287604F9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D00B4241CDA8EABULL,
		0x81A1AFE9169C55DFULL,
		0x0ABE1933BFFEB344ULL,
		0x6C5E0BD1DADAD812ULL,
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
		0x42062F3754F385D1ULL,
		0x294A1BC9BC0C713FULL,
		0x5FC8C1161A228D7FULL,
		0x5EA77DDA3D7294CDULL,
		0xEE5AC2E11DE9BBD5ULL,
		0x831E3E9D42110E9BULL,
		0x8A4BFCDF0DEB0D86ULL,
		0xE628E60475D17D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA78BEB173FD08FULL,
		0x1464B6DCFF1784F6ULL,
		0x998A01446829F327ULL,
		0x90050B71D3D6FB7CULL,
		0xCB333FB0AE7A82DFULL,
		0x0F6A702D617F2D4BULL,
		0xF8BA3F24CBCFC1A5ULL,
		0xBB694B41881750D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A3C1C7CC8362AAAULL,
		0x41960988129C5E2DULL,
		0x61E0E9778205DDCFULL,
		0x27136B57B33E3FAEULL,
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
		0xB8F021A3861673AAULL,
		0x4211EE25938E88FDULL,
		0x7080B2FA2F91F52AULL,
		0x95D11A196558462FULL,
		0x6E776C766E1C90F6ULL,
		0x084E95E4890A9328ULL,
		0x5B75767E05D5F701ULL,
		0x4F7D2E26E8BC74B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CB5881FC5B733F9ULL,
		0x14B99C750D4940FFULL,
		0xAB00CE3B90A9FE4DULL,
		0x1DF7C08F829E7EB0ULL,
		0x82397102ACCE9D39ULL,
		0x0B6381819E131650ULL,
		0xA6C8666AA6CDD973ULL,
		0x6DB224AE5840D1DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD6DECB271F16D14ULL,
		0xB83D585F6701D00BULL,
		0x9730479EBA1C59F0ULL,
		0x7BFCC16F5513F41BULL,
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
		0x4E80E76A8A8BD7F2ULL,
		0x82B86E30FA2E722FULL,
		0xE72EA069E7BF8E1DULL,
		0x3F8EBEA529B65624ULL,
		0x72BFCE05F02C4B30ULL,
		0x2613EBCA8CD3D8A1ULL,
		0xDC6AA98F664AFE04ULL,
		0x6B1E588ACDED2199ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x965F1B887D88CECAULL,
		0x63555C947315F8E8ULL,
		0x1C51776B5CD47772ULL,
		0x51FBE1C5D12D2AF4ULL,
		0xADE618A7F391AA7FULL,
		0xEA4D4D24D7F3FED2ULL,
		0x8D863AC71BA9D531ULL,
		0x5DDFE500E090CBE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF072B7D58BF6E3A7ULL,
		0xFEDE9E356052CDF7ULL,
		0x80C59AB99ED725DFULL,
		0x64D80358943DE41AULL,
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
		0x123C1A42B48AB3F7ULL,
		0xE9F9CBFD7DB192ECULL,
		0xFCF6749E2CC18400ULL,
		0xD5334C9B985E78BEULL,
		0xC55CC2B27D5952A4ULL,
		0x9F6753BF93D6221CULL,
		0x49274717DAA0CC53ULL,
		0x69A3F87591AD133DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0747CB62BE40B1B9ULL,
		0x940A3D1943BE3471ULL,
		0x3DD13077A55E1E86ULL,
		0x42B74132F8B1AEBEULL,
		0x8FC37D0E2AD505E0ULL,
		0xB65FA8CC0000FCB6ULL,
		0xAC1536F4E7738BE8ULL,
		0xCCC1E6C494FBF3AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFB4A54435ED652FULL,
		0xED12EF0C2B96EBA6ULL,
		0x0FD3A956A01AF558ULL,
		0x5C0AABAE21F7792CULL,
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
		0x148D4BE68F88F443ULL,
		0xC1137013D7EF1997ULL,
		0x94633283A0A803ADULL,
		0x3D5F5C32A67D42AFULL,
		0x0E279511BEC45F33ULL,
		0x70495F6919B87B48ULL,
		0x2732ED87300F47ADULL,
		0xC80349DC79B292DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB480CFC95CA0A1F4ULL,
		0xAC72746A76876CFCULL,
		0xF874E5052CD71885ULL,
		0xC37C70F377897B29ULL,
		0xF2FDE641B66BCD50ULL,
		0x5FC860067D7291D7ULL,
		0xFE61B47F83B36D58ULL,
		0xB6F92C79851E82D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x683C6EFE700DFA4DULL,
		0x87C6E44C93C8533EULL,
		0xAAFCC4A2097353C8ULL,
		0x016347EF7CEE2953ULL,
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
		0x65FEED8234C103EDULL,
		0x36C0379DE54B8728ULL,
		0x25EAB25B772B3EDCULL,
		0x3F2ED63A4D5710A3ULL,
		0xE9EF1D53B7617F13ULL,
		0xA61611386563CF92ULL,
		0x6132C0F3ABD6E207ULL,
		0x64347946812E3766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE45C7836837D1B12ULL,
		0xA761D4C0E3D8CE72ULL,
		0x515DF0AAE27296ADULL,
		0xB31D38DE9A8DA275ULL,
		0xF926F31CC721D88AULL,
		0xAD48CEC277061748ULL,
		0xBD5B81214931320DULL,
		0xADB17FF2D05E56CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F58B9735AB69F7CULL,
		0x7DD6405E635C13AFULL,
		0x26803AEB3950C749ULL,
		0x23829FC7F1A4C548ULL,
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
		0x32649BBE37C4B7C9ULL,
		0xF3C6109D3D627A8CULL,
		0x48B586ABEABACB38ULL,
		0xE4CAC34A6BCC1EDDULL,
		0x75D42B64F9F7ABC9ULL,
		0xFA725BDBD9867AD2ULL,
		0x529481C08C731725ULL,
		0xF2EF4E1BF4B0E7C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65CE5650BA1AFDA1ULL,
		0x6D3ECF673468F980ULL,
		0xC259E6747A4D25A5ULL,
		0x8C306D4CA1481686ULL,
		0xDED08EC83B74B36DULL,
		0x98539FB24AFAD76CULL,
		0xBF805D6F87D83C70ULL,
		0x741CE5A3335DDA72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x371F84B1C51A9AA2ULL,
		0x17172F6131B3C220ULL,
		0x5B59043E1F6A1C80ULL,
		0x2BD5D7EA7CD802E4ULL,
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
		0xFD9C27EE225DFBFAULL,
		0x882516D3BBD79E7DULL,
		0xF58DEC84307BFE4BULL,
		0x883BCCA11856356FULL,
		0x376FD26399E6A4F1ULL,
		0xAA12F42DFFF95E84ULL,
		0xF832E321520D18D4ULL,
		0x8EA10A95E268B677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08B6AFD5DAC42B03ULL,
		0x86B6A1C97B878696ULL,
		0x3E04283908A03735ULL,
		0x8B5BCC3F327E5848ULL,
		0x421A81451CAA80A3ULL,
		0x9193A0B519AAB15CULL,
		0xF596E63EC6461C54ULL,
		0x6FD3294CBFD8F88BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F8F829EDE873536ULL,
		0xA454D8FC6FFDCBD6ULL,
		0x1AB14DEBE7654219ULL,
		0x0F6F713D072E0E30ULL,
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
		0x7D319C002B6AEB71ULL,
		0x530565EE97BAB621ULL,
		0x335CBECC94755021ULL,
		0x85F2A0F93EE713E2ULL,
		0x6AC8BE2D63ABA7C9ULL,
		0x851B2EF66F0690EFULL,
		0x6E50710CB384678FULL,
		0xDDB1562425C9018BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFC101D234A7E9FEULL,
		0x488E2D8505AC8A4FULL,
		0x3B36F01C07494561ULL,
		0x6C7F5FE0226D1C26ULL,
		0xAFAFB2C5B5591DCAULL,
		0xF9AC9597963F5711ULL,
		0xE6ECBDE82BD48F6BULL,
		0x1365B1EAAE35FAA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63284B91D70381C1ULL,
		0xBCE1FC7DBFA0C2BBULL,
		0x10F2661CB1462006ULL,
		0x20ADA1A0DC4CFDF4ULL,
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
		0x7011E2298B578F88ULL,
		0xEE93310C60AE5003ULL,
		0x25D77B9FC53513CDULL,
		0x6C35CF34505C5DB9ULL,
		0xD9FFE8938B9A7005ULL,
		0x6BA34DACB01866F8ULL,
		0x2DD056219892F6BFULL,
		0x9327C857A8575F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1297AB30F59A3712ULL,
		0xE16D74747D2A4CA0ULL,
		0x8C381B549A4108E1ULL,
		0x4437F40BBFB42CADULL,
		0x700D9CE0A175F766ULL,
		0x0B9E28A4506653D3ULL,
		0x62669C4D23D5D0ADULL,
		0x33D1130107228457ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1771738757274224ULL,
		0x4DE93BD617F2DAF1ULL,
		0xCB50F5D47F07B1A6ULL,
		0x4EDCC6047E80BBC5ULL,
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
		0x8D8F3019B8BF408FULL,
		0x45D5A66DB5632A81ULL,
		0xBBF5608736745055ULL,
		0x8ECD79ED1F62B8FDULL,
		0xB7879188F879192CULL,
		0x10695831E6E5EC7CULL,
		0xAC567EB2C21005B3ULL,
		0x51E101B89C8229EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3299352A12CB8AA1ULL,
		0xB80FF96CCBD683E0ULL,
		0x8787FE6E534CC11EULL,
		0x7E353542394951F6ULL,
		0xD2ED36616BA3F62EULL,
		0xCBFCD368652D7F75ULL,
		0xBDFA418FDE911488ULL,
		0x82F35DBEBDDC6ACBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49DF82CE8D96E685ULL,
		0xB5E162EA2AECD5A7ULL,
		0x961E7546A7FF5B7CULL,
		0x47DE9BC1F2B3C59EULL,
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
		0x2AE8880039DF0E7DULL,
		0xBB0756E785002374ULL,
		0x9C7150FBBD103887ULL,
		0x5C504EC40CBA292DULL,
		0x237956F9360DADBDULL,
		0xA2D78F16B4C55C9DULL,
		0x035D32408DACA460ULL,
		0x474C75723415F1DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906C9631892459DFULL,
		0xBAF805A7DFEDE26BULL,
		0x0F165316F5501C8AULL,
		0x528379187AFF2ED3ULL,
		0x796A2317C259BF28ULL,
		0x19B7D09DD039BFBBULL,
		0x17742F77D057AC56ULL,
		0xD5E7E307F02A527AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8BDA545DD701B8BULL,
		0x5AC5973191CB8A87ULL,
		0x91F167B0E25CED8DULL,
		0x5EBA9171A6B4A309ULL,
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
		0x9B394B6FC53EC8D3ULL,
		0x766820FF0F265300ULL,
		0x937A2B94CB59EBDCULL,
		0x0E6D15A4C89C653BULL,
		0xDF1A636B06B37CB7ULL,
		0x7B8B909B8E3D6955ULL,
		0xB5212C8072CFBB47ULL,
		0x8928A997256A04C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF910BC13DB314A83ULL,
		0xE0DB1EB32DC76C8AULL,
		0x7A1932041A3D413DULL,
		0x28FA81DECE1B9E7BULL,
		0x51ECEE6E34FDC567ULL,
		0x4CE3938F096BE6AEULL,
		0xCE18C28A8579E908ULL,
		0xC95B990DB4C59C9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96E7ECE30B06B2B4ULL,
		0x827C922798784B54ULL,
		0x64A0B411EBD9DFFFULL,
		0x5DE3082CB2E83CD2ULL,
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
		0x61AD2CECFBC82064ULL,
		0xB61BCCF51B07A557ULL,
		0x799FF6F7A6CBF126ULL,
		0xD99979DDCE1A321DULL,
		0x68FFBDE21B749E75ULL,
		0xC260E8EAB64D2906ULL,
		0xA2B9BA7860F02646ULL,
		0xE3A3B8E81EF5F28EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF93108CAFC418BC2ULL,
		0xE7541C5C0DB7E2BCULL,
		0x9707714167E39D86ULL,
		0x9C1CBDEEDEE3C4CFULL,
		0x28B89EB66535BDF9ULL,
		0x0EF02E7B03987327ULL,
		0x443A8EB901EF7A6EULL,
		0xA872AC1862C10342ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF30AC49F0CDBE860ULL,
		0x71835D2D9422C1BDULL,
		0xE979041E5901D5CAULL,
		0x06C4A2C4DF11F2A3ULL,
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
		0x1E1A727F5ED406E8ULL,
		0x3192E251D781536AULL,
		0xE75510B5DC775D49ULL,
		0x84558DFADA8371D0ULL,
		0xD992C6FEB3CD1C83ULL,
		0x2FFFFBB87D3F5C6BULL,
		0xECBCFD2447C071E0ULL,
		0xD3C819CA9521C855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0644F1B85A4C958ULL,
		0xC365E3B15DECF04DULL,
		0xE5E79B26748A4D2BULL,
		0x2E01D036414AAEB4ULL,
		0x8816AC1DA7A4657CULL,
		0x383DB633F20AF595ULL,
		0x569B5EFFEFCFA403ULL,
		0xDBEA0E3E501ED871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x462220CBA73A6874ULL,
		0x3503504D235BA6ECULL,
		0x4A6AEEF475AB9EEAULL,
		0x21497496D7A85F0AULL,
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
		0x5C11824C63466055ULL,
		0x7F2D2322B6B067ACULL,
		0xFE4122811CE71C91ULL,
		0x25247895E0123909ULL,
		0x320DA25A5F76CCAEULL,
		0x0ED37D2DD28E57A8ULL,
		0x6D2F40AEDA7BBBCCULL,
		0x4964C82BE93AAEB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B69DE27E4DFA42DULL,
		0x431B3E5B52C4413BULL,
		0x4021064C3CCEF0D6ULL,
		0xB20676EBEAE9FE2EULL,
		0xEFC3F84286981AFAULL,
		0xE10E4C578296CEDFULL,
		0xEB9D856198C8504DULL,
		0x53F2A023396F7BE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9796E3AEAF751C81ULL,
		0x0757249742AA742AULL,
		0xF9C1E9ACA0BA2076ULL,
		0x620FF2F40D51C61AULL,
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
		0x24F5F01B076E8353ULL,
		0xE6A02053413B21EAULL,
		0x326B10258D29552AULL,
		0xC48B6C2E8D8DA28DULL,
		0xA32F658FD81AAC54ULL,
		0xF4B69D5160FC1D55ULL,
		0xB65F2A851C19506CULL,
		0x6C2C70200AFF86C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10FA5ECB0C1C722FULL,
		0xCA18632A00A9F74EULL,
		0xA25DCFE6DAC7C874ULL,
		0x7C06B06BB4BB2DE1ULL,
		0x07746955D8579A0CULL,
		0x49A7F4E51027F2D3ULL,
		0x12882106404B8447ULL,
		0xD466BA41DB8D8F5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31BD01EBF246C587ULL,
		0x80B4BD3D400F79FFULL,
		0xE1F8A91352EDDA4DULL,
		0x4FDDBABDE3BD2E0DULL,
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
		0x0338D9FA1DA2377BULL,
		0x04784FC637AE74AAULL,
		0xE0D7BE219E72CDACULL,
		0x4CB9201C71440FC5ULL,
		0x16B4D459F3E9831BULL,
		0xAE34ACBB43BA1098ULL,
		0x104F262F395D97F6ULL,
		0xE81B1562A1C116EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88BB502F2F03F232ULL,
		0x4B4C4BA80E10B5DFULL,
		0x17041814E6DC7A55ULL,
		0x5D0EB843DE47F594ULL,
		0x23CDC75AC13D32E4ULL,
		0x4D60CEAC5796813FULL,
		0xCC505F3D4A705251ULL,
		0x731D923DF0345D55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88C977AC74322FF9ULL,
		0x189EFA5536E505FEULL,
		0xE1A52DF62ECEA9E3ULL,
		0x4D4BDF4AEDDFA6F1ULL,
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
		0x72D40E17E2C43C25ULL,
		0x34694FE53CACF492ULL,
		0x139E82F8FFA2772DULL,
		0x4A2BA4D9C3139E48ULL,
		0xC2CF8F7018183CCBULL,
		0x401C51950D835341ULL,
		0x0C3165C524B8DF0AULL,
		0x74BA18B07EBDE27CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0CD05A92D35730ULL,
		0x5D7C7F9E4E06BA66ULL,
		0x850D43D4F449EE91ULL,
		0xE5F270EB01A81676ULL,
		0x003F1EB1FE774A3AULL,
		0xBF8C1C23644892E0ULL,
		0x10C17EEC5CA61C5BULL,
		0xB0932B3B26A54D10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB937F9F51DD4E512ULL,
		0xEC54BF260D5EC8AEULL,
		0xE12D8351BE216E82ULL,
		0x02007359D511B5D8ULL,
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
		0x257C6AE1A2FBAAC4ULL,
		0xBDF73080951E687AULL,
		0x2002E89CC0C2564EULL,
		0x766AD87944A1A16BULL,
		0x0C291DBD8E72DEE4ULL,
		0x5C1561523EF06AE8ULL,
		0xB619B47764649B43ULL,
		0xEFA898616C5C986DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90ECDEF2EADD4924ULL,
		0x9178956384F633A4ULL,
		0xD2F85ACD08F5D218ULL,
		0x1A829685DB4699ADULL,
		0x6F441CE3564CED23ULL,
		0x0620A6E7182C430FULL,
		0xDE64AE91A2FDD985ULL,
		0x37567F23DBBCB81FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE8DAC530DC0485BULL,
		0xEED24704D1461EFCULL,
		0x51E96DEA6D0D4676ULL,
		0x38180116E116534BULL,
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
		0xE1B8389D91BEDEABULL,
		0x33F78FBDDAFF400FULL,
		0xC776B5CFC5A95FFEULL,
		0x38D32709A088D7A0ULL,
		0xBFB724B5CA1ED4E0ULL,
		0x23F9E9349446DBD8ULL,
		0xF7B395D2F762DA00ULL,
		0x4DA5F88D183FFD39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4425AE598AEF6F2ULL,
		0x29C270457126BE10ULL,
		0x29826D04572740A2ULL,
		0xBEDB923063380EF8ULL,
		0x3D8EFC21EA535868ULL,
		0x9A7DB1588B697B41ULL,
		0xB6E05D3524EDF07BULL,
		0x8E1628934C60FC63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F6BE3AB31445FFAULL,
		0x72A56A21BAB4D87CULL,
		0x3D4EB038ABDCC908ULL,
		0x695073ED806AE876ULL,
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
		0x6FC33DDDD891F5C3ULL,
		0xCDEBF6D4CC500D7DULL,
		0xC4095D430EC618F5ULL,
		0x2867EE8142AD61E7ULL,
		0x9FA8583939FF3B90ULL,
		0x71A3E478FA502797ULL,
		0x12D0A1FC0C47752EULL,
		0xF039F2B66ADC8591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA89DC868722B452DULL,
		0xFD30A54D12F32B4BULL,
		0x16BDFCFDB5217A1BULL,
		0x4A4FC08E7943C41BULL,
		0x7EBC19C360E7AEFAULL,
		0xA84470CFA8F9112FULL,
		0x9B8C5E0561ACDC79ULL,
		0x0C94494869A4677AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA36BAF39FE593D3ULL,
		0xB4E67CA9CC4A35A6ULL,
		0x616D76E2AC9749AFULL,
		0x28AF5446F7BE1522ULL,
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
		0x092AC023B8FC0AE0ULL,
		0xC86D4B7CE7489376ULL,
		0x31DE11A1D17C24E8ULL,
		0x3063D83D949B7A9BULL,
		0x6910B75ECC47426FULL,
		0xBDFE492113E85674ULL,
		0x3E59B0344435DA87ULL,
		0xE1263A7861D9A214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26F03B840385906BULL,
		0x43910666FF5F88EDULL,
		0x095970C817E89016ULL,
		0x479BE133B6EA3F45ULL,
		0x93352E242B01E97FULL,
		0x9709AA6A02F32C2CULL,
		0xED051B103385307CULL,
		0x2945CE3330E5792AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D0E353A5C1B217ULL,
		0x4D2BD4426C4D5132ULL,
		0x3B12C43433CCD27AULL,
		0x3418094F21EF4DF8ULL,
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
		0xFAD2A98ABCE87925ULL,
		0xC8FA2A579F29BBD8ULL,
		0x97A82DCE3BD8DDD8ULL,
		0xDCC366F32306FC35ULL,
		0x86CAF387D1F26F75ULL,
		0x8F91B8E56750F2B5ULL,
		0x3805C423B59467D0ULL,
		0x7DCD6B89A8DB1DB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3483066D48BD7656ULL,
		0x19B4F60FA8F701B4ULL,
		0xF981309CC1B070DDULL,
		0x1ECDE1B7FB36BF93ULL,
		0x3DA3ADFDCB4DEFA7ULL,
		0xA5B349222B6678CEULL,
		0x392892497B92E1C0ULL,
		0xC5991E1409012C22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA223F59A7095F9E7ULL,
		0x6649CB42DB00D279ULL,
		0x72FC639616625358ULL,
		0x15B904B0E22A17B5ULL,
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
		0xEADC9BAE0FD04F64ULL,
		0xE875EFD62980F703ULL,
		0x4B1AC8225A3CE637ULL,
		0x968F0F769F409557ULL,
		0x4B3746DC3E718C3EULL,
		0xD79741DE97705014ULL,
		0x8277C1E902CF4D74ULL,
		0x291A01C961BE9B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x878ADCC008BA9265ULL,
		0xF85313ED55FFDB04ULL,
		0x054E4B739B63B440ULL,
		0xD88B192CC2D28C3EULL,
		0xF33E252FA5E43A71ULL,
		0x768792BA2B35619AULL,
		0x4F073084AB1451BAULL,
		0x2EED87D0D5AD3D33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x724CBE8CAC0FE134ULL,
		0x5876DB50E4408202ULL,
		0xE8821193C49A8FA1ULL,
		0x609E112EA701FD20ULL,
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
		0x1DD93C6C9B7E0226ULL,
		0xF0D496B00C9B3750ULL,
		0x5628CC91B2F00469ULL,
		0x93DF1D5AD1640DA3ULL,
		0x13AD7A2AD1A2A19DULL,
		0x820F6F67A08B88B9ULL,
		0xCB8693A7F50ABD33ULL,
		0xA074AF25E9362159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4A98713A0726C86ULL,
		0xF7DC86711EDA0D1EULL,
		0x113673745698DDB5ULL,
		0x6F276F90EFAF3216ULL,
		0xD302DD0C62F34563ULL,
		0xE7D2FA0FB80224F4ULL,
		0xE8DD11393AD3F6B1ULL,
		0x09DDDC1FD95394C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE28307DD69134980ULL,
		0xDDF17B4B7225F952ULL,
		0xEA1BB58D00789DF0ULL,
		0x7F1B00B03D55B9A6ULL,
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
		0xE3D52281FC7BDFDAULL,
		0xE79A6B8790BC4124ULL,
		0x3C1ABD181A10B6CBULL,
		0x09F98391DC6ACA8EULL,
		0xDD10916E7D4DFE71ULL,
		0xD67272EEAD078EB8ULL,
		0x0ED851B95C983116ULL,
		0x53631674EC181803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B2F75F5236A4866ULL,
		0xB04D93EAC551E97BULL,
		0xC086B2CC457B5AA4ULL,
		0xC09E8146A321B22BULL,
		0xF979A856C25E0871ULL,
		0xF315779E358E2F1BULL,
		0xE51B2274E3F63819ULL,
		0x177E43F52D6F55EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x710C461298B01CA4ULL,
		0xF71A258E876E88F3ULL,
		0xADA90E75BCA051B0ULL,
		0x2D5241418655E7F8ULL,
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
		0x6C80642BAFA1981CULL,
		0x026450DABFA4042DULL,
		0x62AA84F87C11B562ULL,
		0xBC74420DE6C855C6ULL,
		0x44B8F8B7DAB3AA9FULL,
		0xCD9E92A26A9EE5B2ULL,
		0x268FE19478920C11ULL,
		0x219802E25BAC427DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2BC89B200A309AULL,
		0x421EE289A6F9C644ULL,
		0x4914DFB8639816DEULL,
		0x8908C078F52D93B5ULL,
		0x49C7DD196F34FE6FULL,
		0x765DD615CFE865A4ULL,
		0x93A3E54F6A172DC2ULL,
		0xBD6331B3C1B5470EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE1EB5148464F338ULL,
		0xB3E16B300FC13FFBULL,
		0xE89D17803EB69E4AULL,
		0x13428E7FCC44147AULL,
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
		0x100A32A27FD729A0ULL,
		0x37DEB5C054AA686FULL,
		0xA3DC44C908599A5AULL,
		0x9B5F80DDDFBE98B7ULL,
		0x3DC837B8CEA20FB7ULL,
		0x8E403130E7A6F58FULL,
		0xA3F56463B1A22552ULL,
		0x80CC20AB076D4F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x718E7A1836F37EA2ULL,
		0xF71E0069D5CA569EULL,
		0x7521AAA16E9E781DULL,
		0xFA145867A399A1F2ULL,
		0xEB20F87C1B56FCB8ULL,
		0xA972F012450F39FCULL,
		0xB9BC3B34BFC4A73EULL,
		0xEA7133FDEE10B295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE34F1B8CE6087A65ULL,
		0x37385FE2A165E988ULL,
		0xF336B71F809BD930ULL,
		0x72CA4A27FFE4444FULL,
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
		0x024EF9BC52D72B90ULL,
		0x1A5D5C79C3FE200CULL,
		0x1192FF60B3EF3376ULL,
		0x9C3F61AC538FDE87ULL,
		0xC0403CC85090D143ULL,
		0x50939D76337EFD1BULL,
		0x27B45C6C53B6CE9DULL,
		0x14C051EA0F39B72AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE5B9311D0525E8BULL,
		0x99023D67857769A9ULL,
		0x33C25851765C9412ULL,
		0x2F07947D0FA0ADC5ULL,
		0x84165D119328B020ULL,
		0x1ECB461F377AAE97ULL,
		0x54400E65CA708E2FULL,
		0x11890E7F11C17138ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x422A9BCA9FF9B84AULL,
		0xE51815FBA72A5E03ULL,
		0x41143C079E002FBEULL,
		0x676BCF10E3C992A7ULL,
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
		0xACB363F5C87AEF89ULL,
		0x97C09D00313C8F13ULL,
		0x0A398D076455F565ULL,
		0x0BCA163F5C145E82ULL,
		0x0BC5489A72A2A161ULL,
		0xD5BBB6F13AFFBF3EULL,
		0x4B93B65B8F89DAEFULL,
		0xC52C2E3225326C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A562109EA259D76ULL,
		0xAC55144D460A05A2ULL,
		0x25701714F45D0120ULL,
		0x94DBB818F02D41C8ULL,
		0x197556D5D1E9691CULL,
		0x95740E255AF1BEE0ULL,
		0xF46A8561CDFFD828ULL,
		0x936783B625BA8679ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A3B261BB9D3AD48ULL,
		0x760E96F62D469763ULL,
		0xD4E6BB052A755DD8ULL,
		0x5A1FAC8E57B339F2ULL,
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
		0x51FBB4D4D1E12CA7ULL,
		0x920D0D7CDA64BD6EULL,
		0x38E9A726A0ABB59AULL,
		0x63D0975A69921573ULL,
		0xFAC4D1E53DAB6F21ULL,
		0x3637A7872B472235ULL,
		0x42649B207568A1D7ULL,
		0x0BDF56FE890E758EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2895B15D184ECCBEULL,
		0x8D641F175FAAAEDEULL,
		0x47ACB11E70FDB638ULL,
		0x24FC41EA6B3091EAULL,
		0x08A22F4F2D72626AULL,
		0xFB1E83356FF0CF8EULL,
		0x27E0D4A96A0126CDULL,
		0x54C7E1A9708B56DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A8A25BE220A4171ULL,
		0xCA645287498A537EULL,
		0xE0CC6BB3E10A42C0ULL,
		0x6C4FC011A1D811ACULL,
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
		0x49252065076D833CULL,
		0x4B9B2C0F2EB6C08DULL,
		0xE78653607FA79232ULL,
		0xE5B0E195B7AC6FD7ULL,
		0x4754E7554A664681ULL,
		0x5E6173C60BF42382ULL,
		0xD6B125620D984421ULL,
		0xF10643B2ACC310F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1FF5269A6311349ULL,
		0xDA0F6E1A7302C2C8ULL,
		0x4C3B5DAB24E06B49ULL,
		0x24AF7025C3F1B52EULL,
		0xCF3368727F5B3B08ULL,
		0x84C57F53816124B8ULL,
		0xDC1CABAA2294C8CBULL,
		0xC4AF27C7D2AB3751ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C1EA3A584E024F3ULL,
		0xBEB206F54D85CFACULL,
		0xCD5507023D4B75A6ULL,
		0x55EF964C53450842ULL,
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
		0x7C14193D74A359ACULL,
		0x6CF8F10CA8C07395ULL,
		0x5D28F63AD5617025ULL,
		0x8F08B99E4C09C11EULL,
		0x7D9E8B5301CD0968ULL,
		0x89A28E49ABE2EC34ULL,
		0xC98EB3AAF45D4C6FULL,
		0x4FEF4825AC7DFB26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342F6882E4690DA9ULL,
		0x4BC6F267D6056D77ULL,
		0x508C33B4BE8F982DULL,
		0x3706174AF1244C07ULL,
		0xA82F587ADB143DACULL,
		0x913DFDE852806C22ULL,
		0x4531A0FAE7D83972ULL,
		0xFD0A67FEE4FF28F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6663CD04FA88622ULL,
		0x001F6D18175A08C3ULL,
		0xB26D88A7F292A985ULL,
		0x25FBE814F7B8A7FEULL,
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
		0xD67B807D08E6B543ULL,
		0xFEFB514760633ACFULL,
		0xE64DA1ED488689C5ULL,
		0x536348FD762BCD92ULL,
		0x2E2A66B5DB903CF3ULL,
		0xFB5DC455D7DA5CB1ULL,
		0x66F9485957732DA9ULL,
		0x2905D07F9F477E3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B79BE01A3A75A7AULL,
		0x31540450B7B37415ULL,
		0x4DFE480A5A82CA30ULL,
		0x985AEC1E4A3E7826ULL,
		0x1C3D2DFDBB83F578ULL,
		0xFBEF497016DF5C81ULL,
		0x5876E376AF74C54EULL,
		0x2F96B6AF1891BC1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14382DD02711F6D2ULL,
		0xB80D8B114DF1CDDDULL,
		0xBFAA5387DDC73D17ULL,
		0x418631D32AE8262EULL,
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
		0xDAB70B8B8E000319ULL,
		0x972B352D3EDE561BULL,
		0xF1DB86793A1BA204ULL,
		0x978D20488D987BADULL,
		0xF59C2CCBA0F9C959ULL,
		0xC3830A00744D8413ULL,
		0xC7BD2B55B05DAA9EULL,
		0xF085545F18E38E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DE432519FCFFF2ULL,
		0xA277F8B3F765B835ULL,
		0x95C22AA22854EFF1ULL,
		0x33EAE3A0DB5F31B6ULL,
		0x95382326A0B2BD2EULL,
		0xAE0222D8C0EA1BE6ULL,
		0x9E84F1E3FF5CEF23ULL,
		0xC3DAC8ADA626AE92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81B236E47E8ED293ULL,
		0x25D58C5DE83A14A2ULL,
		0x7A71E2B757E28658ULL,
		0x04F2F8FEBA428705ULL,
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
		0xD87D1DBCA87E0F7EULL,
		0x2927DB4E52C3894EULL,
		0xC64AB0C6344C7BC4ULL,
		0x3EE53731FD23BFDAULL,
		0xA5C7F9B13595376CULL,
		0xEA00008DCEF27210ULL,
		0x27EF4960CBAA90A9ULL,
		0x6F242839450E8BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2464F11DED889A30ULL,
		0x92D5373274458FEEULL,
		0x5CE03306F3029704ULL,
		0x28A2041D971AEBF8ULL,
		0xE0B88BB8ED02AF52ULL,
		0xAD8C3B19DD78A6F9ULL,
		0x6BFD23392C2B3E49ULL,
		0xFA3F024571DA4620ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4627F7980B5A60CULL,
		0x8F81F351B6921EC1ULL,
		0x4F5C27A0EE301F08ULL,
		0x7046D545BFCB2926ULL,
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
		0xED2AF4A6320A5BFEULL,
		0x027C847927FE86D6ULL,
		0xDBB675F3E181FE5AULL,
		0x54A370CD2D7A7167ULL,
		0x5594F7466AC53AACULL,
		0xB43474ABECEAE944ULL,
		0x70F9C9131D70862AULL,
		0x79D6C032F36344BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8EDABEEF381B98EULL,
		0xE6D87E22BEFA5931ULL,
		0x3F18EDA09DFBAF64ULL,
		0xD2E5D1E1B12329B0ULL,
		0xD8F31EE6E4DDA85EULL,
		0xD5840A152F2E07E5ULL,
		0xFD6EE867DE55C439ULL,
		0x3A373D18A443B06EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC44366E51EE85B47ULL,
		0x29D3D8B6930DA1ABULL,
		0xC33AE1BEA17F18B6ULL,
		0x736B14D33B074AEAULL,
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
		0x0EED54D6B3F0EB8BULL,
		0x25026DD7ABEBA9B5ULL,
		0x99B5A394DA0022A1ULL,
		0x1CFEBCD5D70B7D36ULL,
		0x8E7FC0B8ED013083ULL,
		0x05A1ED5373B92FE9ULL,
		0x3C2189F0D8148476ULL,
		0x816E9422733C85C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x700E0010EABFED49ULL,
		0x43652182FA83B817ULL,
		0xC51DB5DBCD8E081CULL,
		0x9572ADE7B416FE33ULL,
		0x68C223F5EE40CCB7ULL,
		0xBBB3C73EE52C2A3CULL,
		0x9D253B4F54377D9BULL,
		0x1A8412AC3782A117ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x390499B799BFD0B1ULL,
		0xDAF6F361DA56C951ULL,
		0x6E0B99B29F411EEBULL,
		0x4E5B467B008C707CULL,
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
		0x08CB908B7A84AED4ULL,
		0x823E633AA146E917ULL,
		0x32B2CD329980CAFCULL,
		0x3618054C78F494CFULL,
		0x8CA302961BF7F62CULL,
		0x49F32730FB461916ULL,
		0x783C4408DF4CCDD7ULL,
		0x01C40B54962F452EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C10BB9CBC012377ULL,
		0xC9C29AFF6FCA20E8ULL,
		0x8E04E2C8AF37C21BULL,
		0xAE99D66D40666417ULL,
		0x9A48CC64C2F97AFEULL,
		0xF7661EEB8213D9EFULL,
		0x4B1E7375C29A67CEULL,
		0xA4579557441CC397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA61EE041F449D07BULL,
		0xF96B028B2EF227F6ULL,
		0x571AE0402CC42E1CULL,
		0x6597B279674D6D28ULL,
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
		0x921B975806172CDBULL,
		0x596F55E3655ECAA8ULL,
		0x1911597A9A444A1BULL,
		0x31EDC578A0D1A80CULL,
		0xFBCB04E3B217E4D4ULL,
		0x7789B859D1E8E14CULL,
		0xD3232C30C74849A9ULL,
		0x3644C4DA96F11CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4D00B30A5FE12E0ULL,
		0x19896E7398D3F6BDULL,
		0x874A90828129C3A3ULL,
		0xBA0E8F7305793784ULL,
		0xC1C9F93486B9B859ULL,
		0x57F2884A68FE2DF5ULL,
		0xD18D4AF26EF8BE22ULL,
		0x87A911346B2F0830ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89734827D013B24FULL,
		0xF05709B95F6172DDULL,
		0xCE06383934E93C86ULL,
		0x62FBE0B01A278281ULL,
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
		0x8869F9E63989AA7AULL,
		0x50ADA971C4A804D6ULL,
		0x2CBF2154D5C4FDF2ULL,
		0xC1A2B5641979A4E9ULL,
		0xE3D6C46C111A860EULL,
		0x3A32621260B189AFULL,
		0x1B4635DF658771ADULL,
		0xB5F7C7EE261CEF73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B67F62C0553DC8EULL,
		0xB0EB8E7B11E7CE7DULL,
		0xE7DE57D967F61300ULL,
		0xA0E3C4DEADC4E026ULL,
		0x12AB66C429879650ULL,
		0xBCD371E9B8EF17D5ULL,
		0x755181D392DC6C5DULL,
		0x8271F383F477B287ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7971EAA69405653DULL,
		0x3BD9C0FF999D1CD4ULL,
		0xE733833CB331B4BEULL,
		0x469C7848CA3BCFBCULL,
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
		0x6545E13E2E9D3E99ULL,
		0x6EED08D4E2B9FB6CULL,
		0x56D98DEC0576A0B4ULL,
		0x42C6002C767BE053ULL,
		0xB9C811B8D9F4C40FULL,
		0x9A8B8982E81B9079ULL,
		0xC57376153E956F28ULL,
		0xA964A21FA2CE3DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE8EBC2577AED407ULL,
		0xD9FE3AACF0F5B57EULL,
		0x5FFC0020179EB76EULL,
		0x18B07B45C871CF5AULL,
		0xB14AF38A12024F08ULL,
		0xC0D85867D710775EULL,
		0x3876DF8221DF36C7ULL,
		0xF791B62500808F85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF949A00A64EBC7E7ULL,
		0xE588182C7969FFF0ULL,
		0xE45BE7A230E447A5ULL,
		0x0F648C1AC591EAB1ULL,
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
		0x5BF74462A85E08B3ULL,
		0xC89A3B5FDE70AF76ULL,
		0x81B5A8BCBC82BEFDULL,
		0xB9D5EB1817E7F3B5ULL,
		0x2555950C861E74D9ULL,
		0x8F78FA0C79ED8754ULL,
		0xB3AF37BF3C29B10BULL,
		0x25FB7C3C951D013AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4A4B5A6EABD4EF8ULL,
		0xB20D0CC41BD15A68ULL,
		0x8F3B3CFB8E6A8FECULL,
		0x4E62110DB3A26A0CULL,
		0xEB82BE3A52606BA7ULL,
		0x929E47962332456DULL,
		0xC502B449BEA1E4CDULL,
		0x5B198E2975759C69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C9E71EF6BD6160AULL,
		0x9F03AC2CA26B1D3AULL,
		0x6015EF31D0408044ULL,
		0x08FD30E1171E80ACULL,
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
		0xAE5C7F756955C0CBULL,
		0x3E2FB5BBA6B0DFDAULL,
		0x36D229112B1FE83BULL,
		0x7FE4450E3E6D8833ULL,
		0x0EA7B9FB9C9B10C8ULL,
		0x0C086360881EE4AFULL,
		0x31AD9B706911CDCCULL,
		0x28F4503E40A76233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E3E3A1445B1D36ULL,
		0xADDEAF3389B7A828ULL,
		0x4FA1D053319F85FFULL,
		0x4FA78C4904949327ULL,
		0x38AADF5F8C6BBB15ULL,
		0xEE7B03C6FF41047AULL,
		0xC1ADA18618D12FCDULL,
		0xDD88C203CB05D760ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00010EFE8C015825ULL,
		0xF34D37526DE87F8AULL,
		0x872F7185E317D5F3ULL,
		0x6233D572AFD39048ULL,
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
		0x150364236099EF0FULL,
		0x09DA85C8D715EF5AULL,
		0xDD0CB8FBC265E561ULL,
		0xD38EDBED7C8A2090ULL,
		0xD6BD452154B79532ULL,
		0xC15C339FEC54688BULL,
		0x9184E22E05523674ULL,
		0xF0A84F3B8E7D3890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FBD01EF57C40333ULL,
		0x1E516CDC16BC75EFULL,
		0xD1AE7C5F25EE49E7ULL,
		0x24CF5F14144F7836ULL,
		0x9211790E60F5C734ULL,
		0x0E00EBBFE80018CBULL,
		0x83A696152AE73BBBULL,
		0x9227414115B344E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6C6AD04379A81B7ULL,
		0x8B15C42D64DD4FF4ULL,
		0x1A5D884D0858D30AULL,
		0x35E790075634D34CULL,
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
		0x6BD6A69CC3FA09AEULL,
		0x1C40BB51E3A4AF58ULL,
		0x9303E57E3609C70DULL,
		0xC4CB2D14FB5E88DBULL,
		0xE0B7BFE365B1C6BFULL,
		0xA5BDE0CCB0DCF590ULL,
		0xFD4FBB8CA1771DB3ULL,
		0x00168BB23C03C490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCE3B34B436284FULL,
		0xBFFD3A728BB63129ULL,
		0x9FB937CE58343575ULL,
		0x05980A6979EEC47CULL,
		0x4B8E7C273ED92B3AULL,
		0x02BABBFDFFD7C39CULL,
		0x963F066617E036D5ULL,
		0x08216D2C70911B54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92287955D3EAF70AULL,
		0x8EBAF78D9EB3E87CULL,
		0x3FC591684A3BD6A3ULL,
		0x0D95AA87B474E356ULL,
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
		0xDBB1BA489E3806BDULL,
		0x8B42D1DB5DA1D3ADULL,
		0x0C9F3A276511446DULL,
		0x3C01AC9202973E80ULL,
		0xF2E757671648E518ULL,
		0x1A52F1EF0616988EULL,
		0xBEE5ECB710C39732ULL,
		0xE93EEC5E21D23A7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2F75CA7F01E121ULL,
		0x3DF9E9C74BCB7F2BULL,
		0xAC3D2D633E691601ULL,
		0xEEA7E38F345163C9ULL,
		0x92C6B8912743412CULL,
		0xC03134AF391E8EE7ULL,
		0xDAD54352B9CBB1B2ULL,
		0x26C3856A17A0BC12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1359D83F9A0C7ECCULL,
		0xAE4AFF8C7EA7C35BULL,
		0x3ADB31A90F743F53ULL,
		0x2BAB113C519E9E22ULL,
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
		0x346357150519A563ULL,
		0xDEBD1BA3C7D5767CULL,
		0x0EDC628843F948B6ULL,
		0xA3537168945846F4ULL,
		0x9A86C8C0E3BD8B87ULL,
		0x47BBC601DBE0CF53ULL,
		0xF0878D6AEFC36C4DULL,
		0xCEE078EF4A875786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0981B224B1DE1D7ULL,
		0x390F1D1F592DBD66ULL,
		0x1E0CE4FCD6822C9EULL,
		0x8B40E617BF0C2613ULL,
		0x45F2D3C9F35FB5DCULL,
		0xE475015DD9D39FF2ULL,
		0xD7FD3A2A6241107EULL,
		0xA00A50676BDF5AC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1C1989A67E97BF8ULL,
		0x622F2EDCBC9CC187ULL,
		0x9557D9206ED0BCBBULL,
		0x0BDC8F7BE23BA53EULL,
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
		0x50F4D794ABB76BE9ULL,
		0x77B02D50EB238D84ULL,
		0x6F5AA642528B1B94ULL,
		0xA92D2C1E4EF9A20FULL,
		0x1E7EDBB636D27BADULL,
		0xB3828C0B06852DE3ULL,
		0xFD74AACF9660BFE1ULL,
		0xAD7760DB52581BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5275152BA70B0BEEULL,
		0x85B202B89F051AB6ULL,
		0x8413180D630FDD88ULL,
		0x22D261D06B2DD877ULL,
		0x0619B1092BCB5591ULL,
		0x6DEDCD3543A8E98CULL,
		0xFD110F5EC94E3214ULL,
		0xA48899AD4B500979ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D841818A7BC085CULL,
		0x46127E5338D097BBULL,
		0xFA10A0F3603C4A84ULL,
		0x59CC5B22EEFE8871ULL,
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
		0xE505B4F45E7D6B87ULL,
		0x70B8581850B55440ULL,
		0xF88B9DA09745686AULL,
		0xFB2558273414836BULL,
		0x68B02D4EDF2F375EULL,
		0x7A911ED88269AC4BULL,
		0xCAC789D5750934AFULL,
		0xDCBE1081F0324FA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD468095C5282F721ULL,
		0xCF7EE550E5055075ULL,
		0x8CCF1DE404F70C3CULL,
		0xFDE0C6A2DF29EC93ULL,
		0xDA25085650662986ULL,
		0x24D7290CE60C3BDAULL,
		0xCF0404C66BBE97A9ULL,
		0xE7159EB617F1EC89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3945287D3DD2822AULL,
		0x5AD3EF00A18EB480ULL,
		0xCAC23FF7F361AB1EULL,
		0x744575C66E794D97ULL,
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
		0x0D9046830CF9D2C2ULL,
		0x35C7F6650EE094F0ULL,
		0x4ED43C99DE8F2E7BULL,
		0x50798FF9F466B603ULL,
		0xFD7E1B07D1507F82ULL,
		0x2F88936AB6B55523ULL,
		0xBAF4706BCEEE4648ULL,
		0xD971EC2E7EE7A197ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD9AD35D9363140ULL,
		0x7AD155F02504013FULL,
		0x84748746F0052391ULL,
		0x6EA769746F873AD0ULL,
		0x3533F231330B9439ULL,
		0x4A790DBB5D5DFA11ULL,
		0xB0052F02F614805EULL,
		0xA675590F0E918D8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28B8A928B1FE8F62ULL,
		0xBB44787C2CD4187AULL,
		0x69E36AE31EDD6BA1ULL,
		0x734FFD3031A674D6ULL,
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
		0x9AA979469B8D0F85ULL,
		0x36E5F7E80DAE8B4FULL,
		0x98B14ADA4C320934ULL,
		0xF83D4C18DCC198C0ULL,
		0xB602A8421C7248FBULL,
		0x1B8CFF4B5DBE4FD0ULL,
		0xBAE5A01A552FF79AULL,
		0x41357166C725553EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B2664546B8AD3B1ULL,
		0x5479DC22CDA239E0ULL,
		0xA38DB4AD631D2A7FULL,
		0xAAC95F2AA96DCC74ULL,
		0x583F394C6ECC149DULL,
		0x8458CFEA6FA4339EULL,
		0xFE12D913085E4F39ULL,
		0x6E20695A288FEF3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A858D69F6AE00D1ULL,
		0x542B242897EC80E9ULL,
		0xFC6D21425033DD0BULL,
		0x22931ECDBD80F0D9ULL,
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
		0x74DECD48F30978BAULL,
		0x1AF350E26C092B01ULL,
		0x4D67AD4F3EF5E5DFULL,
		0xF4918A5FAAB64E20ULL,
		0x5974BC90E807AB8EULL,
		0x5064EA88D4915958ULL,
		0x51DDC1BA82E5C765ULL,
		0x6D7FFCC59F9FEF1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF440A762CA25E12EULL,
		0xA8EE1B8BE9D51AFEULL,
		0xA71FD60FD38FE11BULL,
		0x76AB1E192D584CC0ULL,
		0x0F5F49FAB66366E7ULL,
		0x3C685FA51EEB043DULL,
		0xF708C195F81474BBULL,
		0x4BC79C557BD09071ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FCD28318745C914ULL,
		0x6981D32378E4B20FULL,
		0x21E5DCAC06784A02ULL,
		0x7F44BCEBCE260E5DULL,
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
		0xBF610D5DDC590619ULL,
		0x36F766C67E0F80ACULL,
		0x8B930E7C6B5613C2ULL,
		0x5856C2F001D5967AULL,
		0xE927E57710F794C4ULL,
		0x5BAC85E847999C38ULL,
		0x002868DCBA344726ULL,
		0x88E7A53750E4382EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7789BF7345EAD02EULL,
		0xFDDE3757384249B2ULL,
		0xBBE2AACD93AE7BE4ULL,
		0x8A7CB27746573D39ULL,
		0x3E55EDC89E559566ULL,
		0x43FA4E4FDADC4BE1ULL,
		0x68844F22206635E4ULL,
		0x4826B04F93BB5CBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA30211CF9A7A1F35ULL,
		0xBD8D700F69E723FDULL,
		0x520C3561AC3E27ACULL,
		0x6A7E6ADECF8EEC43ULL,
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
		0xC203328C2743A897ULL,
		0x2232A75B0D9EBB63ULL,
		0x13E2B881AFEBD7D7ULL,
		0x35485F1B27B606CCULL,
		0x2E0DDDC68D485959ULL,
		0xC51ED7556043C449ULL,
		0x90982F89CABCA76FULL,
		0x8A6C1FD6DA2F7CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A60FF8B4DB416CULL,
		0xBCD127C6130D139EULL,
		0x0FF799509187C386ULL,
		0xC75295AE17D87FA7ULL,
		0x2BDC4AF193671FC6ULL,
		0x6EED2618F45BC597ULL,
		0xA28BF1DBFC6E8C6AULL,
		0x74E911FD9A4CAE62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61B8EE3089D6F35CULL,
		0x30C1CE8CFF017631ULL,
		0x59BC46FDBDFC171BULL,
		0x1F69D7AC8B882916ULL,
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
		0x212F498D4BFC6028ULL,
		0x27A56C0F709E7908ULL,
		0x48CE1AA9DD5E3E28ULL,
		0x24EE4884A676337BULL,
		0x78937BCF5BCC4265ULL,
		0xBE886693F7A72F01ULL,
		0x71B70884B164C85AULL,
		0xF2F0D07B5B6F18D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A82E753276282BCULL,
		0x06B7CC1C61182833ULL,
		0xBBA1D78AC97357E5ULL,
		0x4878621B095ACA30ULL,
		0xAE3A48C44F26A658ULL,
		0x67818EF19CAB0B1DULL,
		0x3FC3522759442508ULL,
		0x1FEF9C8B257254B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFE9F5DE052F0BF4ULL,
		0x0BF1A20C90F3A4A4ULL,
		0xF75954FA28C3247CULL,
		0x2EA39C11A0A0859FULL,
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
		0xF74BC9B1FAFD4E46ULL,
		0xC46E8D8E23C9FEB7ULL,
		0x8F0F481BEAF8DFB8ULL,
		0xDB1BCB89C561068BULL,
		0x98D77285EC93ED02ULL,
		0x8C0CB3404D77E240ULL,
		0xAAA73747082DC6BEULL,
		0xC09407B39E27FB7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A3ED54D27B8607CULL,
		0xC50525D940CA0017ULL,
		0x4127E00764B6BBD7ULL,
		0xB5822009DC4411A2ULL,
		0x3433FB5F6211BE00ULL,
		0x8587AC4E235E2BD0ULL,
		0x0026DA9FE7B62D07ULL,
		0x8FB7E99134D44B70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D50A41D6297E920ULL,
		0xF7286FA722D1134FULL,
		0x9CF528E35802F50BULL,
		0x6646249B8B89173CULL,
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
		0x3E752873B5D530BBULL,
		0x0BE9B37972F357A2ULL,
		0x231EBB94C5944685ULL,
		0x05C60AFABFB09C65ULL,
		0x95320F641D1665CBULL,
		0xB5ACF7762E6E1015ULL,
		0x4224F6F50B307C5EULL,
		0x4A06D7411E4C6114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD2A650EC5827FE3ULL,
		0xDBF162BF7FDBA91EULL,
		0xEFB79F239FDA7D33ULL,
		0x56FD334EBFA75048ULL,
		0x8952940F45479F1CULL,
		0x1496E1DC03486CE0ULL,
		0x9BF372A8996ED5E5ULL,
		0xE5433F700617A73BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x047711FCF9042B55ULL,
		0x193F859C5AADE863ULL,
		0xDEC0BFCA08787F5FULL,
		0x23D160B597DCE244ULL,
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
		0x07B2D6C9401B6149ULL,
		0x6AD1B2B9CE571680ULL,
		0x1DDB619C9B1CBC86ULL,
		0xA254878DBF64AEE4ULL,
		0xE92211CD3C4DFE57ULL,
		0x86A71DFA44DDEB70ULL,
		0x862BE13406FE0D6DULL,
		0x8B7CD6681B4D31DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C09971FEA2C82DULL,
		0x855D2B889B268A3EULL,
		0x76790E43AB666312ULL,
		0x24B8EBFED07AAC2AULL,
		0x1B7B12A37B61EE97ULL,
		0x37B1D776AA49C117ULL,
		0x6F11028B2F1894F9ULL,
		0x35461870C88F1DF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1ABC1D89E482F18AULL,
		0x9DDCFEBA252ED596ULL,
		0x155F6068FBC63AB7ULL,
		0x49BBCE453720F707ULL,
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
		0x49E1CA2CCAE41165ULL,
		0x9685C86D7FE2FD62ULL,
		0xEDC9A49CBF48264CULL,
		0xBA71808C8AF78D52ULL,
		0xBE312064C2F83B8BULL,
		0x3666ABD8022041E1ULL,
		0xBDE2D6B90113C4C8ULL,
		0x570D2413FE5AB9A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x766167D2577985A4ULL,
		0xB49D9A015CD8AFC8ULL,
		0x91BB0D3721C93BFDULL,
		0x54AA91F6299E3851ULL,
		0x2F40C4474F6A961EULL,
		0xC50BFF5B25551929ULL,
		0x747F85AB46A2D6CBULL,
		0x3CEC0AA1F8459F27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B2E0EB99A711A87ULL,
		0xB55DC8F4E93258FFULL,
		0x40CC9F6F4A423DC7ULL,
		0x46B0B583487B4328ULL,
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
		0x3798676197B9E9CAULL,
		0x620531B0C5025E84ULL,
		0x78154408855D3D45ULL,
		0x3D2BE4050FDA7237ULL,
		0x84CE8702131780EAULL,
		0x3A6C57DE9A80486BULL,
		0xA4EBD2E0D0CC248EULL,
		0x4137AEF93BF111B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x356F65640D7E7B37ULL,
		0x5B460A7881C05709ULL,
		0x33E4E4FD828B5A9EULL,
		0x42B7FF52E687E9C6ULL,
		0x74A5D97AB9EB1063ULL,
		0xC92631BCD00CEE32ULL,
		0xC3A0D67B71642DE0ULL,
		0xF6321D87CB2339DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6832C414C6D41E9BULL,
		0xD728D03C50616BF3ULL,
		0xB551D6172C408065ULL,
		0x1D477B88E7E09230ULL,
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
		0x2D241234F48D972AULL,
		0x7404E5426837AAE2ULL,
		0x0ADD1590F90FB729ULL,
		0x8648987BDE68DEB9ULL,
		0x75C5C2D4CF564109ULL,
		0x6B8606FBAABDADC7ULL,
		0xA9972DE7FC74111EULL,
		0xD32A9958F94398ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D2DA03970957ABULL,
		0x9717543144BF549EULL,
		0xE4D0110657ED338BULL,
		0xAC55B3DD8A12B180ULL,
		0x26C203FF7EF4AA35ULL,
		0x4449D54DC1375917ULL,
		0x465F9321261B4463ULL,
		0xA4EAC0E9E6573B5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FDF8BDB4C00A3EEULL,
		0xAFDCF0E1CD68E86FULL,
		0xE04DFE0E7250E765ULL,
		0x376D051B236C06B4ULL,
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
		0xBD1CF9B1190545F6ULL,
		0x1B263FA590215C65ULL,
		0x9D718D48072DA2D7ULL,
		0xE0BEB6463CA6BB8CULL,
		0xAAC28B8F1C44AC2FULL,
		0x7FB7D789E8B2F302ULL,
		0x86AF6B90813DB229ULL,
		0xEE16C20073D0553BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4A4F277DF11964ULL,
		0x4AF780EE1FDEEF61ULL,
		0x1A3E9D2EE5DD02DFULL,
		0x8E507113233AF5C4ULL,
		0xB7427BAB428BF520ULL,
		0x6231F3901E2C5F3FULL,
		0x242498B3EA0F23CDULL,
		0x6AE3A7F1CF2E7C52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43D5065BEC7F5BB1ULL,
		0x320E95CB803C5BF4ULL,
		0x23CE3CD79239C1A4ULL,
		0x4C04235F8971F86DULL,
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
		0x691AB3C077ACEB90ULL,
		0x17ACD5DE6C360616ULL,
		0x62E3A77C75CF440DULL,
		0x42A9CD2253270F8CULL,
		0xE82C2DC45168BF31ULL,
		0xC4D52FAFBAA05BCBULL,
		0x03E54B740208C584ULL,
		0x39DE8C5FAE7F6C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6DF3ABAC712BCAULL,
		0x788EE14D27A41020ULL,
		0x077962A2C7A6D9F7ULL,
		0xB28FBEDF2DA6FCBFULL,
		0x1A0B6C7E9C879BE1ULL,
		0xE2A718F4FF1C434AULL,
		0xABA430E09E0F567EULL,
		0xC7241EC279481BFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB789706DA4A6FA75ULL,
		0x31F554491A2D993AULL,
		0x751436BA852EE4F5ULL,
		0x17C653990BB6024AULL,
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
		0xEA9A54C38565A186ULL,
		0xB38F3463608537F9ULL,
		0x6CC052B5BAAAF517ULL,
		0xE85B177B9A4715C1ULL,
		0x9AD8949A48746F0BULL,
		0xC9325D8A1AA154FCULL,
		0xFE8930A778E38727ULL,
		0x5943206AA688E412ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C92663B58EA437BULL,
		0x664A66DF6D836589ULL,
		0xE44A00B5AFF929ACULL,
		0xBECB1B176A5FC947ULL,
		0x55924FD699AAE58AULL,
		0xF105517BDAEE6912ULL,
		0xBECFC249C1A784D4ULL,
		0xEEBD9A309ECD1E18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x167623941E65C3DAULL,
		0x63F497A16790D737ULL,
		0xFDFCB3E93D9A23B7ULL,
		0x7961E90155C6AF9EULL,
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
		0x42E21BAD3EC56806ULL,
		0x4C052FF2A00330EFULL,
		0x48DCAEA88E6E74AEULL,
		0x0B412BD7CE46FFDBULL,
		0xBBB2BCEC3AB76E25ULL,
		0x0EAC823980F7A64CULL,
		0x909101DBD29DD696ULL,
		0x1929A38807331644ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7984DA4A38E821D6ULL,
		0x38283F5BE13DD5BDULL,
		0xD6F62F18639294ACULL,
		0x3B0A17CC1F966D3AULL,
		0xB0839851467A1765ULL,
		0x7B7FB2D8CA75D730ULL,
		0x5FFE31B4DEE7568AULL,
		0xAF1D8681EE1D7B1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x725CB06346F82359ULL,
		0xEC83B8F1D60A195BULL,
		0xA7B1655857F2E1B9ULL,
		0x0E0362F367E59A97ULL,
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
		0x19DCCB0B6436BB42ULL,
		0x77B6F63C4A312DF8ULL,
		0x33FD4C4B57F6579FULL,
		0x8ED9661FCFBAEEF8ULL,
		0xFD7F2DA97008C5FCULL,
		0x4D1072D84C093783ULL,
		0xFFAE5EFFD8B50FBFULL,
		0xB539C7D9554E94B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5317A43F5FCFB73DULL,
		0xFA9F12F949C761EEULL,
		0x2694F82A5B4A31C7ULL,
		0xB2379EB6A90C89F2ULL,
		0xFC3C392C0E5A65BFULL,
		0xB5A19B7B1CAE31C0ULL,
		0xC9403C360F64B162ULL,
		0xD8104CEF77AB56D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6B5716884494C42ULL,
		0xF78BDB1807ECA6FBULL,
		0x21C17E14DE9A2795ULL,
		0x30CA06200CE9950CULL,
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
		0x7DE00298263AC3B8ULL,
		0xA4A871584EE6CA8DULL,
		0x62B20780B46C9EAAULL,
		0x759F7079056B8E81ULL,
		0xB0773DD6B0EECF65ULL,
		0x92D3C8251913612BULL,
		0x566C0201431F645CULL,
		0x7486EC1E7DE2434FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29C19F9A04160602ULL,
		0xBD6B48609B457872ULL,
		0xF4270BA1D3C2B24CULL,
		0x54667069B852519EULL,
		0x1B18854941E66B60ULL,
		0x9672BFB00CBEA465ULL,
		0x4563955EEB4BD0C8ULL,
		0xAF68827551E90685ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x802DC7FC9D63951EULL,
		0x5DA46A5788355795ULL,
		0xF5CB1BF7EA11D455ULL,
		0x63BCAF2BD41842E0ULL,
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
		0x22FEE0D68FEF2833ULL,
		0x817DCD7A3CC99E9AULL,
		0xA13B81B685B7C4D4ULL,
		0xFDBFB43DC2F6A54CULL,
		0x365014CD5098DA86ULL,
		0xF0207F3706589791ULL,
		0xEB36F933060942AAULL,
		0x9C5CB318A4836CBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18FD6A7558D4C32ULL,
		0xA9DDB203F92BBC43ULL,
		0xAF41E59FBBD0A10BULL,
		0xE9DF990D96730BD6ULL,
		0x862860A634C06633ULL,
		0x4AC4BFC6DC1832F0ULL,
		0x919F3DAFB70AA33FULL,
		0x27C275952878615FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5753C7FD5C8322D9ULL,
		0x633E861C892CD230ULL,
		0x3E7F719483B2CDC3ULL,
		0x62C53CB496274977ULL,
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
		0xD65D1B8F7D20925DULL,
		0xD1734462691B4C5BULL,
		0x019BE1E77D9C433AULL,
		0x86F1D9AFEB0FDE8BULL,
		0x79234AC89F9BD214ULL,
		0xF9E7572D2E4939A7ULL,
		0x7CFA8AA39C862914ULL,
		0x7A44190993DE96A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51FAA65AE161A8DULL,
		0x6900E4B4DC4A761DULL,
		0x9203CD1B422326ABULL,
		0xCC8D8DA9CD883502ULL,
		0x330B6C0FCE927B60ULL,
		0x6A9F4C5549862CA2ULL,
		0x38BC800CC8C0ABE9ULL,
		0x9C9A89E701FF1ADAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88C88098D66D55B7ULL,
		0xAD23FBB981C4C506ULL,
		0x90CDA72FAAC9B106ULL,
		0x218F8B27C4B40968ULL,
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
		0xAE7CA8F0A4826D3BULL,
		0xFF9822553A90474FULL,
		0xCCF607B7BD54E13EULL,
		0xCA136E0EA44A5509ULL,
		0x5FF2AB9ACED50E8FULL,
		0xE5BB4D612E11E597ULL,
		0x41557F6B2FE9283DULL,
		0x9512F8380E8381F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5694CA04E092A55FULL,
		0xF279E81D581D880EULL,
		0x524D73EB07526B1FULL,
		0x72648AB42542BFBCULL,
		0xFC113C041E3783D9ULL,
		0x33845509504392B8ULL,
		0x5DFBC4484533B421ULL,
		0x922C451F42E23DF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B5E6F49FB525EF3ULL,
		0x81471742CF130C44ULL,
		0x39FA5AFB8CF1B261ULL,
		0x45ED7908B8F7AC65ULL,
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
		0xCF2B1320691FEF09ULL,
		0x9248C4580B2F845EULL,
		0x3C52FA1B88A046A3ULL,
		0x388F9B8999CFE03FULL,
		0xEDC221DB260DA767ULL,
		0xAD80396106E7B3E3ULL,
		0x88DD33E6AF0CEF64ULL,
		0x5E7330BF84D19652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224BA8AA8C0B79F8ULL,
		0x81EA988AA7707400ULL,
		0x306141F7E6C68225ULL,
		0xAD33A01905E90C03ULL,
		0xAA9F87004DF36EFDULL,
		0x2EDD4EB94EE75C14ULL,
		0xA4215AD6FFF20BA1ULL,
		0x81E434D7FB7EC4A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA40266F1F0F8D3E9ULL,
		0xDC8D00B2B3CC1922ULL,
		0xFFD3F0779FD79382ULL,
		0x48955FCEF631F373ULL,
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
		0x18D07A539B899AA1ULL,
		0x05112546137ED198ULL,
		0xC6CA6F16B4EFA9CAULL,
		0xC70F6BC041B4E187ULL,
		0x994DFF533467E899ULL,
		0xC3DA58A17A9FC776ULL,
		0x7C1CDF745359CD3DULL,
		0x45E80A0CD34B8E5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCFB72C799F7ED3ULL,
		0x01039BAE9D039EB6ULL,
		0xB3A62BDCE2FB4ED9ULL,
		0x5BFA9BC377058AEBULL,
		0xC005E9B1EB055732ULL,
		0x0E85AC060D33E64AULL,
		0x46CF129C71F8A9E4ULL,
		0x6A309B5C317AF717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DB3F918068BB05AULL,
		0xEE9F28A9B47E9F64ULL,
		0xFCB0AB45465F9A41ULL,
		0x084F3E34CFA5CABBULL,
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
		0x80D42BFFFC36CC4EULL,
		0x1C22EB000178A108ULL,
		0xDC3E62645490B702ULL,
		0x21075AD3BC98B483ULL,
		0x0483B71D2EFA8F64ULL,
		0x839CBAA73E9A6917ULL,
		0x9253897F84EAACC4ULL,
		0x7FE5870828EA2B05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BD30C11B26E7DBULL,
		0xB8068CD0297837ABULL,
		0xF886226E76C71A7EULL,
		0xAF3BC457AD331E76ULL,
		0x6B14B6515624EB2DULL,
		0xE88BB3A28944E7E3ULL,
		0x2E73A892FE84A0DCULL,
		0x51DF0461FF1B337AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6191198110C64581ULL,
		0x68A368E2C2B19705ULL,
		0xB6F3A311D0EF60E4ULL,
		0x46C2FB26441E54BDULL,
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
		0x6AAF7A374190BE83ULL,
		0xC920524D75990A3DULL,
		0x7C9B1A33BB90F712ULL,
		0xFE9FA110E872F99AULL,
		0xE2D44B6E8A9AC940ULL,
		0x7B65D87F6C83A02FULL,
		0xDA3309DB9D94A652ULL,
		0x8F03AEB9A7CC52C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F3D3D597853651ULL,
		0xAFF180CD7AA2F1ADULL,
		0xBE12909D76CF7DDDULL,
		0x6D419227677EC6B3ULL,
		0x25AE12DCAF96F778ULL,
		0x94340CD5BC2402A1ULL,
		0x32CA2D7F7B6B0F61ULL,
		0x4759E77E7A59E319ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76680C082C9CAD84ULL,
		0x6A930CB029277BC0ULL,
		0x98193F4356EDE0F7ULL,
		0x3491A1B23FF0C5EFULL,
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
		0x5FE7F535C2F69282ULL,
		0x287D2A02B632FBF2ULL,
		0x7597F17E30CB9523ULL,
		0x5FA0ECD96D48EF35ULL,
		0x47743FF781F6E8A0ULL,
		0x082EA14754D4E4E6ULL,
		0x53DD004B5046F663ULL,
		0x11DC362AC779E359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754E92AC167B0491ULL,
		0x7017A31E30ECC33EULL,
		0x8168B83393AE0FC3ULL,
		0x19686B36F0B32B3FULL,
		0x9C6D949FB48E6534ULL,
		0x33CB88EB1C3609DFULL,
		0x9DCCF17EEE888DF9ULL,
		0x4DB8CDDAA96C2C2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D96D19229FF0EA3ULL,
		0x3F1B2494ECDABBB1ULL,
		0xFA916BA11F610515ULL,
		0x6379FD86F29EF44CULL,
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
		0x1E8C4DB02DDFD697ULL,
		0x61382DEF2FEB0C9AULL,
		0x34C291FDA437EEB2ULL,
		0x2A1A71D0E1283680ULL,
		0x05719557F5F9C65FULL,
		0x8E2731C767C94EB6ULL,
		0x792A3E1D39F71236ULL,
		0x138820F9DD1C7364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C78514581B15F86ULL,
		0xD36B936B696F508BULL,
		0x389A56AD39FB717CULL,
		0xFEDECC1A8A019971ULL,
		0x81D39F1AE8871BE7ULL,
		0xC26463940174F699ULL,
		0x234ED1DA86242F7AULL,
		0x516C7F4A1C83967BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B86897AAB33C352ULL,
		0xCCB73624F700D04AULL,
		0xBABA4D371B8A2515ULL,
		0x7B55A5CCEDD767B1ULL,
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
		0xBD82D6B1E5255E01ULL,
		0x72DC648EFF2A0BEAULL,
		0x776E76E977E9A83BULL,
		0xBCDBC27229554D97ULL,
		0xAEB86D2C9DAB7C0DULL,
		0xBEAF06CE84C41387ULL,
		0xCB58F753A409FF07ULL,
		0xC0BA0FC77B053497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52356114CCB28B89ULL,
		0x6126F85206D6FCC6ULL,
		0x7792AE3349994632ULL,
		0x06DA17969C75E012ULL,
		0x79D0B132A5E8CFC9ULL,
		0x2B29693EF1E900BEULL,
		0x21F57511825E3B01ULL,
		0x14F39AD315F0FE46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45B35CB7DF58686CULL,
		0xF78ACF8CC4D7D902ULL,
		0x24A11E872DCF7B02ULL,
		0x357707228DDF7DA4ULL,
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
		0xE1218BFBBE842B5EULL,
		0x055E803C5DEDE640ULL,
		0x76B5DA2221A52164ULL,
		0xB67980F23E8F7F48ULL,
		0xF7F04F322872486DULL,
		0xD5F6B9C6E71965A1ULL,
		0x16165437F019DBCAULL,
		0xAC4B8B5B82B3507DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0ECDA90251AE1BDULL,
		0x0D4FEDAFF43A9DCBULL,
		0x85C0F29BC46BF21CULL,
		0x4E3A158987FC4A07ULL,
		0x0166809D114BB649ULL,
		0x726C771527B8E1DBULL,
		0x233729BB03FC81F8ULL,
		0xF7BD084608F07E93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98A95B8D0922F957ULL,
		0xBE9478EED206D7FDULL,
		0xFE15361169948482ULL,
		0x3566E098C97E5DFAULL,
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
		0xABD264355D4BC929ULL,
		0x9C939629B0CBAA8FULL,
		0x0A7CC343F093A0AFULL,
		0xBDC3986348469434ULL,
		0x338CBD7E223D7420ULL,
		0x13492F6AF52CA404ULL,
		0x054790D21D7AEA4DULL,
		0x7321FF7839D0006EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1061F87396340434ULL,
		0xE977D060D8F4D593ULL,
		0x10C9002DB4C610A8ULL,
		0x171E4D3E697505D4ULL,
		0xC0A055EEAA7552F0ULL,
		0xFDD982D294502082ULL,
		0xEAC80112DE29B21EULL,
		0xB4D5BC9BF48960DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA87CB0D8ECCB0ACULL,
		0xE1AF646738925A33ULL,
		0xE8A31979A1DBE6DDULL,
		0x65F737D7274D3D77ULL,
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
		0x929E9812ED2074F1ULL,
		0xDB73A0C88639A64AULL,
		0x114DA1BFD5154B8DULL,
		0xE864F63AA631BAF2ULL,
		0xC4B0EBD1839F762CULL,
		0x86F324B33C390126ULL,
		0xC65A43676F0FDA77ULL,
		0xF19E44DD0BC27D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C30F3846FDEC7E2ULL,
		0x34D4A55B1385D0F1ULL,
		0x15B1F181138AEF1FULL,
		0x81C12BD15D28B12FULL,
		0xD0459A9FF27F8642ULL,
		0x0ED31F98A1A11835ULL,
		0x4EBECCE9F4B0A7B0ULL,
		0x9897ED6538C0B5F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E5BB1EA07FF4BCCULL,
		0x7B5FBD606540691DULL,
		0xBCAF46DEEBABE60AULL,
		0x1D94C6329B4C9DC6ULL,
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
		0xFEF8DD9ABC4DA426ULL,
		0x83FDD4694766117CULL,
		0x96393A5705897967ULL,
		0xAEF2C88E6A8F538BULL,
		0x81A8D6880DB6E7D6ULL,
		0x0EBBC2B395DE6C2FULL,
		0xE9DFC59442268F89ULL,
		0x74637034D8CED0BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDFE1B3376FB13EULL,
		0xB836A933998C3BE5ULL,
		0xBD70934BD66C37B8ULL,
		0x818A58139614F1C0ULL,
		0xDB4311E2128686E7ULL,
		0x6461153636B6ACA1ULL,
		0xBDBF77E035379F27ULL,
		0x280049FEF33BFDDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32342C8ACE0C5817ULL,
		0x153CEBD1CDC0449EULL,
		0x65942FC51A94F02EULL,
		0x04201C7AE845AEEBULL,
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
		0x53EE6DF6E2502043ULL,
		0x25BD8BCD7BD615B4ULL,
		0xE1C205429AED14AEULL,
		0x41D9CE6FC7BBEC39ULL,
		0x6271EDA1E1F2C39AULL,
		0xE7ADF958AA10B472ULL,
		0x2C624C0E9DA5F857ULL,
		0x816B509C3172D4BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90B49CE7588337DFULL,
		0x414BE062B5B08F22ULL,
		0xF7E40E1ED933C218ULL,
		0x35FFDE6B71412D8FULL,
		0x673C99E48917E00BULL,
		0x47FB7AEA44E302D0ULL,
		0xF5EDECD4A8A47D2BULL,
		0x72C51F01411B0802ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D243F2ABA4AAFEAULL,
		0x98F06FCDCAEDE49DULL,
		0xFF2419BE1FF19B35ULL,
		0x38854D040383224DULL,
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
		0xBF0BA05AE9518588ULL,
		0x2F6C72FD789333EEULL,
		0x6662C5DA84BA52CAULL,
		0xB8EE07E4B0D2CDABULL,
		0xAD02CFC5BB603A6BULL,
		0x1E43190F634B13A3ULL,
		0x3A14329697B99CA1ULL,
		0x4B9F0E4A80E74532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E60A05759EC385EULL,
		0xC6E4BB845AFD9EE4ULL,
		0xAF5F79E68F231411ULL,
		0x3196086CED4AA65CULL,
		0x9F44200A9448F8C6ULL,
		0x1A965B653BACBB25ULL,
		0x313EF053198C5FCFULL,
		0x86D975A50B96133CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAF915CB5CD90A65ULL,
		0xF42BDEBAFF16B7C0ULL,
		0x06AB21F8B04E45E4ULL,
		0x3CACA8072D9591D4ULL,
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
		0x906FC73DAC55721AULL,
		0x900203A8B85DDEA9ULL,
		0xF18195A8A44485D3ULL,
		0x292B7332998F1801ULL,
		0xF3901CB2DE495D79ULL,
		0x23F58484C790F3F4ULL,
		0x20C0EE93F8862797ULL,
		0xF881C377F5B48107ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7849F6E72949CCULL,
		0xAA08D4FDCA495A8BULL,
		0xEC0FB0D5791C3051ULL,
		0xA6F538E4E742F9C1ULL,
		0xC1BA081968EBE0EDULL,
		0xA915C4E74E4FF4B3ULL,
		0xBB5F2C9E44F57144ULL,
		0x4486B1082B721E00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68BE8C0E310CA8F2ULL,
		0x232FA00AEDBA67CBULL,
		0x11F4AF4BD2A365C0ULL,
		0x397AF6E5B826D133ULL,
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
		0x8320518B71C8FE82ULL,
		0xF978B9CC90640257ULL,
		0x2F4E0F0E4EF9A41FULL,
		0x37E3EE0142870984ULL,
		0x5B3B08FAD2D7C00BULL,
		0x6EC585996BA2950EULL,
		0x546BEDF00AD7539EULL,
		0x38645C7BDE84E970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3B49AC71C7767DULL,
		0xBFA62BEA0B99564EULL,
		0x5A8F4824EE37547CULL,
		0x5420C7718184F140ULL,
		0x7FD8E60EB2824BB0ULL,
		0x456F5B09790098C0ULL,
		0xDA01124E872CD485ULL,
		0xAACA4A521F384982ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x597636EBCCB0CAEEULL,
		0x5C9CDF4088D61F97ULL,
		0x009B60E2EC112D5FULL,
		0x68A1D8C22661D584ULL,
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
		0xEA796F77A6FF397DULL,
		0x4873BAAD31A26F27ULL,
		0xDB41ADF596C95274ULL,
		0x7A36995271EB8DE3ULL,
		0x50F991AE4FA52CADULL,
		0x5554E92E91F8B9EDULL,
		0xB83F7E1D086FAD35ULL,
		0x630F4802C5ACEA2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1C10872812383EULL,
		0x1B91E78C86BC27EFULL,
		0xF68F4D20FF24507DULL,
		0x72DBD049D4F0F947ULL,
		0x2CA20B9F188D0F50ULL,
		0x0106C6A185E99B8BULL,
		0x93F1F7F889E228F3ULL,
		0x876C134543E86D48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x535B4532AC815C3CULL,
		0xB07AF4107524C9C9ULL,
		0x48344A3F60A6A3CFULL,
		0x21949D29E0251EEBULL,
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
		0xAD59D13A57709C09ULL,
		0x815401B23F23B432ULL,
		0x5A651B514EAAC902ULL,
		0xE2FFCAF26A4B3777ULL,
		0xC68EA1F86F80BE0BULL,
		0xFACC99F577FE95CAULL,
		0x273F46118C7FEF28ULL,
		0xBDDDCE6EB9043659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32B6D3B56C18F0CAULL,
		0x019962EF27943BC4ULL,
		0x63ED0F1AAA3362F8ULL,
		0xFEC49B1C1872EA12ULL,
		0xCE75FF3B0C105A4CULL,
		0x40634351F60BAF35ULL,
		0x145DD2C4B3844B59ULL,
		0xA4706B68108C73C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E4B25A1AE067A1EULL,
		0x2B5D7B08619DB28BULL,
		0xC3EF299ED9D1B6E0ULL,
		0x2A77E2D3539F2EEDULL,
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
		0x3D7A809A34F21618ULL,
		0x0DE2927214561F6FULL,
		0xD89DB127DBA4D763ULL,
		0x8834DA00BB61823AULL,
		0x8461C202E4344F42ULL,
		0xB6234644C5702C5CULL,
		0x5877CFEC34DD0731ULL,
		0x1B89BA28A6463AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81519DDC9FF74B12ULL,
		0x56AEB220AD90269EULL,
		0x3ABBF10C91826AA4ULL,
		0xC3FA61ED8CB7A993ULL,
		0x9D2D475439DEED69ULL,
		0xDC5A9F0A9FE6BE22ULL,
		0x566B2DF5B82CD3FEULL,
		0x4CBCD9C13B77653FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DF318AADDA7500CULL,
		0x0AFCB2F2F92C5569ULL,
		0xEBC1CAB1CC4A064BULL,
		0x76A3C76D095D8877ULL,
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
		0xBEDFAFE3C6D8E228ULL,
		0xB10E520C5B8F1767ULL,
		0x911234358EA63FE0ULL,
		0x74073A769AA15BCFULL,
		0x0B0D05FC7FF683E9ULL,
		0xAD94C82F07E59D50ULL,
		0xAC4C31F7BA5DB47BULL,
		0x26BF051544FD43E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D77FA803257FA8ULL,
		0x33D4A7B67556FAC3ULL,
		0x53CC7939F83FBC00ULL,
		0xC51F170EA2A8565FULL,
		0x792FFC5DC9FE462BULL,
		0x4615C6A124749487ULL,
		0xF3C90FBA2AC97086ULL,
		0xB61B48F9495A9FB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CD79DCAC68C8970ULL,
		0xDA13E565A8FF6A6AULL,
		0xA0BCD01EE6689A4DULL,
		0x67360F8F521D6485ULL,
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
		0xE82FCD0B002A237CULL,
		0xFE0AA5FBE53E0537ULL,
		0xEFAB74564AAEA7C6ULL,
		0xC40C95CD826F3BEBULL,
		0x9F632D13786A03D8ULL,
		0xC4DF5B3B4C0E6E28ULL,
		0x4D37AB951D9592B2ULL,
		0x53CF069B84E7BF25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0FD973EB6EE6C14ULL,
		0x94C4399191F37834ULL,
		0x623CB7BBEFA88762ULL,
		0x4C36CAA652E4E998ULL,
		0x444A94F8595441F1ULL,
		0x469FA7E09BD1DEF4ULL,
		0xB33ACE7A4A911C9EULL,
		0x9767ED88CF7F954EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CD8C9D2E6767E36ULL,
		0x26BB0BE07C47CEC8ULL,
		0x68F78E95ADAFA76FULL,
		0x6F2383EE1D00882EULL,
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
		0x5A9689DB8120D501ULL,
		0x8D3697C1BD25CE6BULL,
		0xBA28F181F62C219AULL,
		0xFD0F6D01ED2CAC09ULL,
		0xC94FE2A7229AEB34ULL,
		0xF02D798E22834796ULL,
		0x845F76B5FE7A06EEULL,
		0xF438CA596776B673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95EA8273977411C4ULL,
		0x4845696676497244ULL,
		0x3444B0340321B97BULL,
		0x5EAFAB7D994D55EDULL,
		0x0A04AF7184930672ULL,
		0xBF156127F840FBEBULL,
		0x2B6830FE1E47B656ULL,
		0x8D080B2876A6A330ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29D5A15D5ED8BA56ULL,
		0x8E84CD858CB397A5ULL,
		0xBA989A993A825EB6ULL,
		0x6F9C22C812C2321BULL,
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
		0x5624A02EAAE27097ULL,
		0x467C719C78D40A6BULL,
		0x8F8686BA01F1CAACULL,
		0xA192A0B55CA56E2CULL,
		0xBCE7851F2D428F55ULL,
		0x0177CAAE3475A5BEULL,
		0x292A5D01C885C442ULL,
		0x7DBB926D5B56695CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90C22A83C7EC693DULL,
		0x91EE16E4D450C43BULL,
		0x584993615473F502ULL,
		0x74960439D45E6994ULL,
		0x1075EA242DEC76EBULL,
		0xA0B7A10B275353C4ULL,
		0x16A0FE77D03B43C3ULL,
		0xB143ED17B49BB74CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E3F76ECC9BDA5F9ULL,
		0x111488EB979B7165ULL,
		0xF7A0FBD3888CE86CULL,
		0x06BF273247FD72FAULL,
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
		0x2EAB065C1DACCEF2ULL,
		0x4FE20454214D2D9BULL,
		0x0CFFB66D59E17C76ULL,
		0x75D83CE24DEFDD0FULL,
		0xC00DAFC374D4F55AULL,
		0x9FD02A4EB9E90D65ULL,
		0xFCCA09FF04B6C1F3ULL,
		0xC573058894E18181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAA3DBC8FB522EC1ULL,
		0x5A9D35E661018C8AULL,
		0xC64C37909C533A17ULL,
		0x1BAA652D8A86D41BULL,
		0x884A522E890EEAA4ULL,
		0x49ADE30A98282026ULL,
		0x7A51D57C2064E2C5ULL,
		0x8B8318FAAE395792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB070EAE21C03878ULL,
		0xBE5B628AC2EED872ULL,
		0xA48B4A4AA1B5633FULL,
		0x73CAF4C5005F4280ULL,
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
		0x431A7BB6D5A8273AULL,
		0x5251E1BFD7356BC2ULL,
		0x672794855AEED71BULL,
		0xE2695C75B01C61D2ULL,
		0xCF6B60EB82C2B82AULL,
		0x894696EE9BDBB457ULL,
		0xB2891B90C6DD3503ULL,
		0x75F1AD948260548AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9E050DFDC4DB8ABULL,
		0x795C881A71FE4828ULL,
		0x53516506579B1833ULL,
		0xB15F150D91675708ULL,
		0xFDD32A1A5F1D1FB3ULL,
		0x1B50E76CDC729317ULL,
		0x3B71A1A127A66211ULL,
		0x0B6884259A905983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65D24DE243EF1299ULL,
		0x2B6D66E7CED21312ULL,
		0xC1524910A5770EE4ULL,
		0x01666DDE87944DE5ULL,
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
		0xD44E9173C535FCA1ULL,
		0xAA30B975F18DC55AULL,
		0xB24C0CE9DD6B19A3ULL,
		0xD52CD50A254DF7EFULL,
		0xAF8CB4E87BBA212CULL,
		0x6A93D64F446D0F5AULL,
		0xCED310CE8AA68BF5ULL,
		0xE227713691F00DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7AC20348777F9E5ULL,
		0x2939C8BE9135CA17ULL,
		0x037E3AC055BBF7C0ULL,
		0x7ECB11EF4EEB0953ULL,
		0xA9D58F20EB732FBBULL,
		0xC060B8AA0A20CB3CULL,
		0x9EB761EE1FF29741ULL,
		0x18963CA5265D420FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5D20CDEA845DDF6ULL,
		0xC48D573E07AA17B7ULL,
		0xD2E9C7795E65748EULL,
		0x41EF90B0CE2D3125ULL,
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
		0x6DF934BD5F1B3244ULL,
		0xF7F71162711A9C79ULL,
		0x171650B0D8FF4FA7ULL,
		0x358B25018A67B909ULL,
		0x8D1A144365108F02ULL,
		0xDA1D64633734627CULL,
		0x1EC7F23CC59FEFD5ULL,
		0x78D7677D53BB7325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E06DB2E98CDD66ULL,
		0xA64E091B2840C3BFULL,
		0xD89C02D029B602E9ULL,
		0x892974368A0A2E63ULL,
		0x2BBF40C1B867955BULL,
		0x754C760C7ADBD50DULL,
		0xE126F031140D11DEULL,
		0xAF8CD18CAA7D6F46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B942C4A16A36265ULL,
		0x48AC69273DFED742ULL,
		0x64609B9D0B163F77ULL,
		0x0D73F2841F921DA2ULL,
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
		0x52484E41F2EFF17FULL,
		0x7AFB82E2A6FBCD45ULL,
		0x8B659CE62723F2E3ULL,
		0x3C99109B9570697CULL,
		0x413F7114A2286115ULL,
		0x2525A9894922AF35ULL,
		0x2C804716EE8AD6DFULL,
		0x9EB2ADC42265F4A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC67D3BDE03EB2D3BULL,
		0x4B2FA6A2ED901179ULL,
		0x8C44DFEC4BF613FBULL,
		0x331DAD377FDB8CE0ULL,
		0xBE2B45584AADB578ULL,
		0xB8CE2E3867038AF6ULL,
		0x9A3472A5923A3074ULL,
		0x645DAAD9C30266E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C99058EB3A3ED5ULL,
		0x44C82A414A0B1D13ULL,
		0xB66245CD8F2692B4ULL,
		0x3219D22E3E5BE6E5ULL,
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
		0xE3E3DF4B61835608ULL,
		0x7F739FDFF8D8E950ULL,
		0xB762504FDBB14DEEULL,
		0x617DF983166D469DULL,
		0xA5D7E76DB70283A9ULL,
		0x1015C6D401C5D33DULL,
		0x3E8877033D191289ULL,
		0x26A6366DF5DBAA67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4209A47B08046283ULL,
		0x07602E0D2B57910DULL,
		0x85DB24F2E8D188D3ULL,
		0x67DBC29B6E58DFA8ULL,
		0x0EA04D71178FA548ULL,
		0x195FE60107A291ABULL,
		0x32E6CACF11F8F4C6ULL,
		0xE971D70790162276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x141B1650048BF19DULL,
		0x1712D123EEBD1406ULL,
		0xEB86BB1B59A4300CULL,
		0x0F68601AC36694BCULL,
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
		0xA4958FEB59A53FF1ULL,
		0x992F26E84E8336DDULL,
		0xAB44F10B0F1511ADULL,
		0xAB5FB038F8DAB340ULL,
		0x74F8037035203E39ULL,
		0x08DCF4B10EF2E9F6ULL,
		0x9899A8729C262DB6ULL,
		0xE4B4719BBF4C4477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C41E13827DF187ULL,
		0x2E4CDC31FE30A9CCULL,
		0xEC255E19F8759B58ULL,
		0xDD4C6CE8D9219F4FULL,
		0xB4DF2BE94A9132A0ULL,
		0x037925DD063EFBD4ULL,
		0xAA86EB1EDD7B2916ULL,
		0x5BE4FF37119E9D9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F816FDEA8630A18ULL,
		0x37B2FE2F9B07E614ULL,
		0x15E7AD5F64022616ULL,
		0x1CDE3E41E77FD870ULL,
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
		0xEC6D4F79832F5E19ULL,
		0x08693674384A82E2ULL,
		0xB577B7AE6562F798ULL,
		0xA7598BF66C28C136ULL,
		0x62B5AEFED719A31AULL,
		0x9E9BA787223AAE0CULL,
		0xC7831F5B61366CE7ULL,
		0x1230B9C1D1B6593EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E645B7B351096D2ULL,
		0x249584725BC8FDEDULL,
		0x9B4B8BC5650EE6C6ULL,
		0xD25C57099B87EDF0ULL,
		0x69FF9C69BA4FBE28ULL,
		0xB0203E2653C527B1ULL,
		0x940984E0CE77E490ULL,
		0x395023BA990F28B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x490FB6209416C24FULL,
		0x4A25566081F37676ULL,
		0xBE391A1AC89C4DB9ULL,
		0x065379FF397207C9ULL,
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
		0xD28C27FC010D2589ULL,
		0x6BCE2172777529D8ULL,
		0xFD81EF44BE42EA62ULL,
		0x9A4CB790C312C597ULL,
		0x47E64DAA08DD852BULL,
		0x54B95C01861ACAFEULL,
		0x683DD9AE6AD83149ULL,
		0xFE9222BBCEB40E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398EDAD8C86A8DA7ULL,
		0xCE2E00798CE8AF4AULL,
		0x87631BEDF2C7000FULL,
		0xEC3EE7E025018108ULL,
		0x1F300666C94CD45FULL,
		0x982F592905DDD4B4ULL,
		0x1D51D76FF7A09BC4ULL,
		0x3E0AA9454F047B9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA40BE11EA81CDA52ULL,
		0x9A1C8D1BF3990990ULL,
		0x9527289BE5BC1C06ULL,
		0x4229D74792210516ULL,
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
		0x45292ECA6071DB84ULL,
		0x79113C821DEEA0D5ULL,
		0xD2DFD5E8704A2D08ULL,
		0xC519EF186DEDF141ULL,
		0xAA8C25EBFF3DA229ULL,
		0x98B072EF5F4E0718ULL,
		0xD3F462D79DBCCC3AULL,
		0x248EDFD8B6C50C82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994BE9A161C098C6ULL,
		0x5D145AC6DBCA0A5EULL,
		0x0C160D194B6771A7ULL,
		0xF4F00C4254A196F7ULL,
		0xFE4F09CB9D666E44ULL,
		0x80D49835310D8891ULL,
		0x66930255BC81B0BCULL,
		0xD5804EC60893D8C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CEF71F784A2F2CDULL,
		0xA69F595E1FB75E74ULL,
		0x033E1C1693A8D018ULL,
		0x0C536B9BF49A07D1ULL,
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
		0x28CA640E8A51B3B9ULL,
		0xE926D0679044A386ULL,
		0xB354A3ED7FD2B56FULL,
		0x174BB2E9113BDFDCULL,
		0x9D7742E3C84FE502ULL,
		0x8AFDF12F966A5319ULL,
		0x4E532089F4A5A46BULL,
		0xCA69F4269B35FAE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D886E2C59EA9B0ULL,
		0xC56365F5F1F9EBABULL,
		0xDCDAAC61BD3ACB60ULL,
		0x92E8818BF8D22B49ULL,
		0x7BF67714A319199AULL,
		0xB6DBF7AF7F7A6697ULL,
		0x7FF447BA1B10E232ULL,
		0x3BC8A3AC3C6BEF2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E101DEB4AD53E84ULL,
		0xA0CE737505E7D32BULL,
		0x788E26660EACBE7EULL,
		0x305523872A6770F7ULL,
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
		0xFDC83FAE012F002EULL,
		0x78B914282AEFB22BULL,
		0xD7FE954C5C98FD9EULL,
		0x408903A2D59D55D7ULL,
		0xA5700BA5AE67B45DULL,
		0xC056F5F6A251E8F8ULL,
		0x152E87584600C1BFULL,
		0x846A811F3749000FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0811BF561CFC96DULL,
		0xF0005718425ABDB7ULL,
		0x6840D5DF23E0C0DEULL,
		0x3C50D9CD9FDDEB6BULL,
		0x31D1A1111EC1AC1EULL,
		0x2B066D47515D72B3ULL,
		0xBEC012E7BC43547EULL,
		0xA342882C5333F03FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66CAF5C5F2046F5DULL,
		0xB2AD0715ECDE82C3ULL,
		0x44230821AAD6747BULL,
		0x70271DE310DFC333ULL,
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
		0x7F791EE03FF9A0C7ULL,
		0x08B972B700C14476ULL,
		0x33AD0E1470C08049ULL,
		0x386C0291B0D82C00ULL,
		0x0062F517821788A7ULL,
		0x00E585778B1C72B2ULL,
		0x2ADD3A94E7398178ULL,
		0x639EBDC955D0DFD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22540AAACE1B6CDAULL,
		0xF3099623CF11D418ULL,
		0x4EB1D1B1E005FD63ULL,
		0x97978CE940BE29D5ULL,
		0x81EAEE4D49BBB122ULL,
		0xAA5B142A308040F9ULL,
		0x27D8705EC563D308ULL,
		0xCE35D6A86560412EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22F61639CF802F38ULL,
		0xEE3CAE0EA4DED1C1ULL,
		0x57B1406B9672676BULL,
		0x4E66C48C20D18EF5ULL,
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
		0x98483341B6D29C02ULL,
		0xCA1841C41381410FULL,
		0x560ABF4BD2222AC7ULL,
		0x2D05E150BE95D4B9ULL,
		0xBF206386EDF8ED3FULL,
		0xF53B0BBA5EC30366ULL,
		0xACFF4665E5AE5AEEULL,
		0x9C993C33451FDB0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920BEE5B4C067963ULL,
		0xE7A2ADA4B9E8FAB6ULL,
		0xEEBE625DA65B1219ULL,
		0xB8FD814F9F9A3822ULL,
		0x8EF636A97F09D376ULL,
		0x30D632A3EDD4B7A4ULL,
		0xA1250F57CAAFE61AULL,
		0x0D7419F371B3ADA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C7EEDC4E249F980ULL,
		0x096DCD741CF7852CULL,
		0x29B089062D8C7043ULL,
		0x338B757A810A5A7AULL,
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
		0x71DB6194FCFC0045ULL,
		0xF13E2EEE14185DCCULL,
		0xF880C55748246092ULL,
		0xA7EF6ED64795ABD4ULL,
		0xC3E82E5DBE91AFCDULL,
		0x5C600B512CE870FEULL,
		0x880CE7B42950D667ULL,
		0x0ECC338BBE2146DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x445B6DF8C832FF1CULL,
		0x4E1D4D1D59B6766CULL,
		0xBFB5FF4A4502EA22ULL,
		0xBFC20FDBFFACEFFAULL,
		0x4E35961C4C90DE77ULL,
		0x326218A02DEEAC03ULL,
		0x0BB0A4F6FF5A0978ULL,
		0x927F5C25EDBEC7A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6028D5320E810F5ULL,
		0xDED2E816937524B3ULL,
		0xAE7CAE213DC3E1F0ULL,
		0x5B95581736879DF0ULL,
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
		0x77B96964C02CFA64ULL,
		0x846712B1A8CF14D8ULL,
		0x64F9C5E4601B9C08ULL,
		0x30CF288728F77DF5ULL,
		0xE12FD535D5CDA5D1ULL,
		0x8A4B537DECCEFB3EULL,
		0x57D4E6B540973CC8ULL,
		0x7EF9380EFFA42A31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5532971468C6D8ULL,
		0x00A381F173D60F0DULL,
		0x34F3463F450C24C9ULL,
		0xD99341D0AB6F221BULL,
		0x63F156A0DE2F36A8ULL,
		0x21EECF48CE84CE6BULL,
		0x39CF465D7DBAFFFFULL,
		0x863040505C86C2DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20AB00EA6D48B356ULL,
		0x017F30A2B3FBAD2FULL,
		0xA4DC4CAC07C07D25ULL,
		0x4510AD02B3E5B230ULL,
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
		0x8A6A5C8AC710C938ULL,
		0xE400CF16690D4CACULL,
		0x37125D19E13294E0ULL,
		0x6DB7D014A7917D0FULL,
		0x641E0C39B3BD393BULL,
		0xE746142D172A7906ULL,
		0x56211B72D8FF259AULL,
		0xBF6C88B50AE74C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B4BE894DA53DB3EULL,
		0xD8B14025573DB248ULL,
		0xA67BC48AC8393723ULL,
		0xA43FE15993DCDFDAULL,
		0x0D6CD6D10B459968ULL,
		0xAAE9FC8CDD04B239ULL,
		0xA2D9666A494ACC66ULL,
		0xE99819A44D2CEF36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED6C617EEE7EA655ULL,
		0x00FB10B9B36B1CDEULL,
		0x2D3B77D46DBE9B7EULL,
		0x07006B373D5E6E6DULL,
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
		0x0EF0677575D5B744ULL,
		0xE197D70CA14FA0ECULL,
		0x6B8B5EEC496CB3B4ULL,
		0x2659E1DF90703F6EULL,
		0x97E90268FCA18A65ULL,
		0x57D69C30CF62BB49ULL,
		0xC6CE4571F0F8D093ULL,
		0xB98A688D7177CAECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBADF4A8BB660D9F3ULL,
		0xF8968CBAECF4538EULL,
		0x6A07D675BAA693F8ULL,
		0x3E242BA76234F581ULL,
		0x26DB2399A1F06651ULL,
		0xEDA24A8CCDC775C2ULL,
		0x9D8DB5340E39A936ULL,
		0x4CBEC99544351036ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C202FB135C03AA9ULL,
		0xACC568A9F1679F78ULL,
		0x2118F1A63725F773ULL,
		0x0E6F4F0EE62300F7ULL,
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
		0x0CBFF4394EB9782DULL,
		0x456E546E4732A9A0ULL,
		0x9A244A46214EEA14ULL,
		0xFC1C13944531F0A1ULL,
		0xAE76A059A2EAA2F1ULL,
		0xB812EDAA5569992BULL,
		0xBA1360ADEFCF0D18ULL,
		0x29250BE83C0F131CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF1EC47877DB0DFULL,
		0xC0AEE5146814AAC1ULL,
		0xD20B4461DB29EE3BULL,
		0xE5F0921881D0CE0DULL,
		0x8BAD32E668D8096AULL,
		0x1574B84BA435066DULL,
		0x874C38B3A2130BCDULL,
		0x3941BD943629CC4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88B4470C65FE90F9ULL,
		0xA83B5B682CEBC717ULL,
		0x51A8F50BD00D2D12ULL,
		0x31E921F4A369A555ULL,
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
		0x907AD1BAF3470A1FULL,
		0xE0AAB7D55BC77FCBULL,
		0x7E147542ED29840DULL,
		0x26871A59EDE2D726ULL,
		0xE2E791874C261FE3ULL,
		0x4FBB516AB04378C0ULL,
		0xA12478C091F22C15ULL,
		0x766E50E874AD0906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3461094027FCBC7ULL,
		0x2AB0E17761DEDF8FULL,
		0x23591530A950730BULL,
		0xA79B743A25D0D65FULL,
		0xE517F4F0D6A54854ULL,
		0xBFB20C06069617BDULL,
		0x096B45D6C0B12174ULL,
		0x2C57C40F4C5782C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A05FF7C61E73F0EULL,
		0x175A234F29A506ADULL,
		0xE038EEC75380A4D8ULL,
		0x7E448E5BC4C3EECFULL,
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
		0x342F7AD14239C996ULL,
		0x31B686D3FEF4EE31ULL,
		0x6291DFDFEC360D9FULL,
		0x24E1BF8D213C1B2EULL,
		0xF780CCEAA52D63D5ULL,
		0x90526772C4648EB1ULL,
		0x695F60C6829D2454ULL,
		0x857E5FF206A37B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC67BFF047BD0B5ULL,
		0x14F1678E98D9AF76ULL,
		0x77466FFE72A4949FULL,
		0x1D738157F970D4EEULL,
		0x6A601105A987B64BULL,
		0x9F5A4438880C0FA5ULL,
		0x5A2F719ABBFEECF2ULL,
		0xF90094640B3EDC2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2944E2CF9855B8C4ULL,
		0xE19A59EA5B3E1A97ULL,
		0x2C68F060F50DB189ULL,
		0x621A754878BAF024ULL,
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
		0xC6819F84C6A62824ULL,
		0x14093C9B69EB7AB2ULL,
		0xF92FAB69A81F9B8CULL,
		0xD3320A245E57CD19ULL,
		0x345CC5E3853FDC46ULL,
		0xC8ECFBAE13435F21ULL,
		0x98E30BAF90F0452CULL,
		0x20C14BF568068DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC1C67E4914488BULL,
		0xA4216F24E0D81DB2ULL,
		0xAC804C3675A6B873ULL,
		0xCD2DA7488934E9FEULL,
		0xBF1795FDC901CDA2ULL,
		0x10F31D88BACE2564ULL,
		0x74F61E47A60FB466ULL,
		0xBB57F8675C193F68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F04F5206EC80887ULL,
		0xBEFEC701AA79EEF9ULL,
		0xA1DA9CA00FCE6097ULL,
		0x13A6C9F19A5C83E4ULL,
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
		0x8CC5E91E719E341BULL,
		0x19AFC19A32787C15ULL,
		0xC5109A9B57468CDDULL,
		0x2D7B7C23590A42CDULL,
		0x0CE87D2847266AF9ULL,
		0xE326383CAB3EB3EBULL,
		0xF051E89C8D2B889CULL,
		0x6F7D103A1CBA4B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E4BB2DCC24204F1ULL,
		0x7D2ED10C4EEDA784ULL,
		0xACEC444264CC9282ULL,
		0x3DE56050DBB41BC5ULL,
		0x2654AF842470ED94ULL,
		0xBC2EEDF1452B23C5ULL,
		0x40A90EC5A89C0AB4ULL,
		0x8CC2042AFE1F1410ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x486ABC9ED64CCB7DULL,
		0x6535F7BF0A723A31ULL,
		0x2B34AC3EDFC6AAD0ULL,
		0x1759E611086061E8ULL,
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
		0xFAFDC6573A5F565CULL,
		0xC770EC62DBA76771ULL,
		0x0F3D9E59F741447BULL,
		0x4BE33375B9896E4AULL,
		0xAC2AD6FC0D812A63ULL,
		0xA796A31F48C94C6DULL,
		0xC0BF6F0633A4B4A2ULL,
		0x659C4869E7EB50F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70D16935E07B0F4DULL,
		0xF12044B798B65A6DULL,
		0x9E9FAE305B19C716ULL,
		0x43C5A19A484573CFULL,
		0x51F2CCAF8CB7DF1DULL,
		0x0EA793EE5D2AEA35ULL,
		0x3DCF8D9FB0EC0763ULL,
		0xEB15225115855B2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE7DE47C77C5707BULL,
		0x89CCE8EE3C73A161ULL,
		0xE0396561039134D5ULL,
		0x382D398AAC667617ULL,
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
		0xB5F3E14FE56217ADULL,
		0x5F7829A5F02828F5ULL,
		0x96D8F44B5BC51106ULL,
		0x1D76219BB59ABBBEULL,
		0x411C8F2E3570C8BBULL,
		0x96DF734EECE6F3B5ULL,
		0xC0BC6E268AEB273CULL,
		0x24348FDD81A901C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDFD06B4F17C22CDULL,
		0xDA7DEABC96C3839EULL,
		0x7E0C427A98913913ULL,
		0x6395CAC078252978ULL,
		0x32788C7D3F52202CULL,
		0x3D804B237D3ACE48ULL,
		0x8196C91E0C3AC878ULL,
		0xB9CC41438C4A3C14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x044F40DF7C72F6C3ULL,
		0xC91A355BECF23387ULL,
		0x786331139161E917ULL,
		0x055C01B5A986EB07ULL,
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
		0x82974D3BED8D6F08ULL,
		0x04077F78E829A21AULL,
		0x49FC10C5E8EB2EEEULL,
		0x3641374226B70D27ULL,
		0xF68F71E629D580DFULL,
		0xB312F2D34FD90F87ULL,
		0xEE215D490467212FULL,
		0xFC2BF92DD053A09EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x844C07BB06977822ULL,
		0x48FF120BB45AA426ULL,
		0xAB9E8118BF8224FFULL,
		0x19326E0C5ECA163AULL,
		0x8653AA48F0345249ULL,
		0x8DBBEDE4F8D7CF92ULL,
		0x792FB8B030511B7AULL,
		0xBF8E756FA3499C1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA72AE6D774E2E280ULL,
		0x45F328CE1DFE7C62ULL,
		0xFA3BFE5CA4ADE2D2ULL,
		0x1C7057707769A1D7ULL,
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
		0x03119A239F6C3A2AULL,
		0xFE44AABD1D2FB7DEULL,
		0x9E2CFBF2197C0573ULL,
		0xC4601F5DFF72D13EULL,
		0xB91B8BF5A886F609ULL,
		0x3E119C4A5D63F6E1ULL,
		0xBFD5BE51137180FDULL,
		0x56839620AD95B9CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D819C7CEAD51DC4ULL,
		0xDBDB6F879F8C3C6EULL,
		0x79626CF7773BE432ULL,
		0xA3565AAD1BA3E16AULL,
		0x50826D83E9E01D3EULL,
		0x5049AE7316F9657BULL,
		0x5C834351E0A7BB48ULL,
		0x2B6E33C854911928ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC4A8289015B4B7FULL,
		0x6E168929F17510A2ULL,
		0xE308D0DC2C337A1CULL,
		0x06365DCE1A7EC8ACULL,
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
		0xF74B690224A49F1DULL,
		0x26B23B7F10627869ULL,
		0xC1916020BAEA3F62ULL,
		0x0B42259660F5C6CCULL,
		0x45411ED8391CDAFEULL,
		0xA0B7E875F9B0884EULL,
		0xE893CA7E334380E2ULL,
		0x8EF410625416EC5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA600E8F290D3F783ULL,
		0xE396F737D8331521ULL,
		0xF3236EA81737A051ULL,
		0xB878F5EFE8A770DAULL,
		0x365C1BD066ECA434ULL,
		0xBA84FAB487646A85ULL,
		0x6EE3BDD33B6EACD6ULL,
		0x774CCD40C0C43890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8748F338C6F8C9F5ULL,
		0x6EAA8EFE2F7BCF20ULL,
		0xDE8FD2D96D4A18D4ULL,
		0x559D26A256950671ULL,
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
		0x9664A143423C1103ULL,
		0x0AA57DB2557C0F4BULL,
		0xCDDE52D2E438F239ULL,
		0x3C1F19C3575A8EB1ULL,
		0x1F76B239BB5806E8ULL,
		0x31C6AB6E5F680B6AULL,
		0xA38773FD7D90134DULL,
		0x97C4C12D8520AA7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E208E604745C386ULL,
		0x3062DF9232A73AC6ULL,
		0x9D58FB4F724B6073ULL,
		0xF0632E71624D7159ULL,
		0x50E412666C53FEEFULL,
		0x33F8F3F64F0DBD61ULL,
		0x18F8F1B0682256ECULL,
		0x12BAF4900E606D91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB207CC40B58F7F45ULL,
		0x86CBD9F2903C69D3ULL,
		0xC1ACAEF4A037882BULL,
		0x0B304AB19596289AULL,
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
		0xC5D8FB07038DB8A0ULL,
		0x0E671293CF305636ULL,
		0xA36DCC7FB7DE309FULL,
		0x84E52CB22E055C06ULL,
		0x664F6EBCD62CC431ULL,
		0x6D79CAA0333327B1ULL,
		0x597BAE05BA985445ULL,
		0xF93A344E648D4D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x894ABDBF2AABE43CULL,
		0xB7654835FA829C9BULL,
		0xE1BE051912C7A263ULL,
		0x234F0CAA8B775BC7ULL,
		0xF6EEFE5B5AB2A68AULL,
		0xCEDF9E578B9FC006ULL,
		0x9D92D2BDF8E064E7ULL,
		0x6E03B7F14E1F1F23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4DEEBC02D023E4CULL,
		0xE1E45D26B48F1CE7ULL,
		0xA640540D66641620ULL,
		0x0BAC95D8F6E8E2C0ULL,
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
		0x466951EE8DFFB4D3ULL,
		0xFD331C10C5556010ULL,
		0x5C53317211F011B6ULL,
		0xC1C88477B038CF68ULL,
		0x5829CF8F057CF07DULL,
		0x7AD3AD05ECBF06A7ULL,
		0xE2DE4EBB67042C9DULL,
		0x8035F47D4E159A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x029D44AD7366769EULL,
		0x80394E01601C18C3ULL,
		0x43C325A1EA75C64CULL,
		0xDC268D721BCB4284ULL,
		0xA8CB6793379C5C05ULL,
		0x424D7C35E6A167BBULL,
		0xEEA9157B64067152ULL,
		0x58614506562BF48FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BCF7CA1A9EF48D6ULL,
		0xE0E50CF04D9EDE49ULL,
		0x58768B5099241894ULL,
		0x4F3402AE611C2788ULL,
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
		0x738DA93110379302ULL,
		0xF3E17F9E5394A8B4ULL,
		0xD05636EDB980D474ULL,
		0x84694FF322DB9CA8ULL,
		0x8C153FAF479CBAA1ULL,
		0x4B823330DF8B962EULL,
		0x05AB275F55BC3424ULL,
		0x11B66F7E46EB2A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73075B8936D24BEBULL,
		0xEDB582CA6F5C210BULL,
		0xE67D47639A4E8BE7ULL,
		0x2DEF1D94BBAE0144ULL,
		0x9A31D1CE91DC62C9ULL,
		0x5191CA47A119BC0DULL,
		0x04C8BD24FC460F23ULL,
		0xEF37DF5C24AE567FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8489D02D3F24C41ULL,
		0x1FDB8F73291EE88CULL,
		0x0B74B43366BBC6B2ULL,
		0x7543976F7C350998ULL,
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
		0xB2506035C0E1F59CULL,
		0x22FFE6E5EFDD4CBEULL,
		0x3D88F70F0C757F84ULL,
		0xEF9FAF9558F0288AULL,
		0x0E5EE07870798136ULL,
		0x774FA718954C7896ULL,
		0xB6360047E5DEF4AFULL,
		0xF1D3291991BEB4E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E2720518511EBCULL,
		0x25554E352D77A45BULL,
		0x2CB8EFD94354A610ULL,
		0x415E4028005BD16AULL,
		0x795EA03492CA6DA3ULL,
		0xED5225924D8D0810ULL,
		0x45F235BFB1F2458DULL,
		0x7E1FF01160E03E78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59777843908DC14BULL,
		0x794BD29F68D05C37ULL,
		0xBAE0176D7E42D86EULL,
		0x5ADBE6A49999EB12ULL,
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
		0xA2B4C706C62BB314ULL,
		0x60A2D9DEC3F63157ULL,
		0x2F59C5A15CA0DDB6ULL,
		0xA1FFE00954140B91ULL,
		0x0796BD2F1645432BULL,
		0x08453821AE6BEA5DULL,
		0x527B7C0083C4534DULL,
		0xDC49F00E47477381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBF3B4B30A4D800FULL,
		0xC2B32A50F9BCBCFFULL,
		0x3278E64B56AEAECCULL,
		0x59D4C2B4E8A5A98EULL,
		0x426B6EB3DFF543C1ULL,
		0x80B190FAE9E3A32DULL,
		0x042054AD37D95B4EULL,
		0x099F76C735B47659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB2EB89DCBBE216EULL,
		0xBDDA7F4EF674056EULL,
		0x9E68B5B34AD2FEB1ULL,
		0x0D791DE1073FF5FEULL,
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
		0x5B5DDFD252DA1279ULL,
		0x4940741C4F06A11FULL,
		0x4207F5F1E9C88F31ULL,
		0x63CC1B42228302A6ULL,
		0xFE393B8A9187F2ADULL,
		0x4948F43C3B60FACBULL,
		0x342A00C40FFD5BFAULL,
		0xCE36E3484AF19770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x079B7F0B20B8B7F8ULL,
		0x673709FD607FDA14ULL,
		0xFEE0D771F0ADF2FDULL,
		0x3A814BED744C6D9BULL,
		0x9C612CAD8ADC0EA1ULL,
		0x6B93FD14F03BD381ULL,
		0x7E15FF7C0411EBAAULL,
		0x0F12B0A8EBC4113CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9D495962FA53884ULL,
		0xCAE619F4160A9C15ULL,
		0x4A1F4F31BE0D480EULL,
		0x08AA52FCCEF880B7ULL,
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
		0xD39349B9ED83590AULL,
		0x225DA617C891761BULL,
		0xB0E65704D348A000ULL,
		0x5460E3373656711DULL,
		0x575A80D47239CF05ULL,
		0x49114E724B0C0B5EULL,
		0xDFFE1C70464209E3ULL,
		0x5C1F5A50EF640C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBDF17766D2C7B5FULL,
		0xAD4F8652B9B1B43BULL,
		0x2C1F8FDD181496C3ULL,
		0x6E374DCFBF1765B3ULL,
		0x6D7B7DF20B9299E2ULL,
		0xDD12C7645CE0BBE6ULL,
		0x16C9112A638AA540ULL,
		0x415E17AF66B039DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCECE9FDEBD28C162ULL,
		0x7CD62BD6694D8DACULL,
		0x62A67387626CF958ULL,
		0x5ED97961C1F04B92ULL,
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
		0x9ABFDAA5DB33FEA8ULL,
		0xFC17B9D91F75B9EEULL,
		0x1762A1BDFB52472FULL,
		0x517288A8BA181B6EULL,
		0xE8AB7311559BFB87ULL,
		0x773E8E6FAB731485ULL,
		0x008A68215193246CULL,
		0x62DB4E4491524182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E590C0F5A4725FULL,
		0x10CB36DAFE5BBA62ULL,
		0xCDFCC07DEF5E07BDULL,
		0xF139E4339CFC53FEULL,
		0xAB4813C0C63EFBB0ULL,
		0x3ADDC187E02729D2ULL,
		0x1A27D6394461D819ULL,
		0xA6B831845BE381AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F9A6FDA2D5D8491ULL,
		0xE1AAED664E5ED627ULL,
		0x7C0789B2014593CDULL,
		0x4D6EE8FD0B8C40BDULL,
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
		0x60132C3974FF82B1ULL,
		0x3012B1400E8DF35DULL,
		0xF3E38F723BE595F7ULL,
		0xBD94E1B02C6833D1ULL,
		0x39B097DA6D7254A4ULL,
		0xDC7E3F61692F3AF5ULL,
		0x146601856705E9E6ULL,
		0x55B500799D42D53CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B81D441F7CCFD8ULL,
		0x242023AC45078AEBULL,
		0xA19581177063AAFCULL,
		0x5F654BA498CE8FFCULL,
		0x10DE6F7046F4C547ULL,
		0x3C0C081D1979613BULL,
		0x3F79FA022748CB27ULL,
		0x6C072E9B65F7BD4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B8D0EB70C25FA35ULL,
		0xDCE6C1B79E84BA14ULL,
		0xED572BD641947B6CULL,
		0x0DFCBD07C8BF3194ULL,
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
		0x0BA75FC7593DB7C3ULL,
		0x4E22A1F672449D99ULL,
		0x69C538155C70027FULL,
		0xC87E41EC323A435AULL,
		0x2C5485F26B066436ULL,
		0xC99AAD8DF2B4494FULL,
		0xAECE3B5C31B14476ULL,
		0x2EE68015B53BA47CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46D6D22FB7171822ULL,
		0x6535F17125BBAD0BULL,
		0xDB526FA7F6E98B18ULL,
		0xE3AFAB6A7ADD87A5ULL,
		0xFF238E0F6EE9FC59ULL,
		0xB92081CB76045E65ULL,
		0x23C9EAA6CC9BEC60ULL,
		0xD4CFB4AD3EFF5EACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A1559490E5E06B9ULL,
		0x5B0F2F63CEA5CF2AULL,
		0x3116C35A66B18AADULL,
		0x4430C803444F18A9ULL,
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
		0x2ECD4B1B1F6F4BE6ULL,
		0xC2997924E6A6295CULL,
		0xE3C89DA7F218521DULL,
		0x7E8F55CD5F9D2253ULL,
		0x9F371677550393FEULL,
		0x39254FCD39292604ULL,
		0x9AB2C602FD421E79ULL,
		0x8863920542920962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CDAF79705A2BF8ULL,
		0xCD29C162FCDF4285ULL,
		0xEC6E30A48051059DULL,
		0xD0A5022383B764DEULL,
		0x71E42F98E808E6F0ULL,
		0xCCE0E4909931DB49ULL,
		0xEBDD45D5974F22B8ULL,
		0xFE80230D305624C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x104DE0A5DC4ACD56ULL,
		0x0797A2C1A87BFE9FULL,
		0xEB0B73C093D8AB10ULL,
		0x25ACCC7C90C9ACB6ULL,
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
		0x17AEB70BEBF01DF8ULL,
		0x01811E2C280B784DULL,
		0x189F8B1D51D6EB09ULL,
		0xF316E5877BE33CCBULL,
		0x6C697ADD384E80EAULL,
		0xC91B34BA1FB387EDULL,
		0x65368F7B6D9AA52DULL,
		0xE9ABD1190171B337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA412CB30048F62E6ULL,
		0xA68A333B12F4CE64ULL,
		0xFB83A57FF48C317DULL,
		0x2D9B2EC57F90226CULL,
		0xDABA54B14CCE75D5ULL,
		0x070ED43ECDB5C626ULL,
		0x6F2D8481E1FD955DULL,
		0xD8307C53D677A0A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x139B9660DC6260A2ULL,
		0x28CD3D3F40C16D62ULL,
		0xA27386A8169B1288ULL,
		0x5DCA4C065D71DCC6ULL,
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
		0x2FE1030EFB14236EULL,
		0x42E5007B4C9ECD91ULL,
		0xD15D7AD97348A3DCULL,
		0x6C0A293010315DC8ULL,
		0xD30B6EEFE8BDDB0AULL,
		0x469C8590F69D0A85ULL,
		0x2FB0A7018611ADF4ULL,
		0x8E2AA7F8872F007CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342265084FB407BDULL,
		0xBCB09D7CAD754420ULL,
		0xC903DBCC2DC3A0FBULL,
		0x53377ECAD407E3CFULL,
		0x7DEFBF2833CADFB2ULL,
		0xFD96B31896B77DDAULL,
		0x840234517749DC23ULL,
		0xB1A8E4B4300E3741ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DDAB5AB877169F0ULL,
		0x5D11A0DCDB3C6ADFULL,
		0x843EA52F772E27CBULL,
		0x5415A68A2B0758AEULL,
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
		0x54C7C92337D36A2AULL,
		0xFDEB5488AB66CF56ULL,
		0x34D6C2D7D874D5F5ULL,
		0x1C70C18A293AAE53ULL,
		0x0D2AE745BCF8234BULL,
		0x3F1BC8C47A246012ULL,
		0x327B104197FAF302ULL,
		0x4697B573CA2BECF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C84391CCB1D0875ULL,
		0xEAF6AEBC337F979EULL,
		0xB0651E5A0E16914FULL,
		0x778E7964DB889F2CULL,
		0x6FA31E389BCDA152ULL,
		0x9532D2AF242226B7ULL,
		0xFB4893007EAEBED3ULL,
		0x216B5A915F8D8EC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A6B67F95905AD69ULL,
		0x4B892CF73C3BBB2BULL,
		0xB5F03C278BAE0393ULL,
		0x2977C5C121340AC0ULL,
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
		0xC2EEEBA4C0A1FE70ULL,
		0xA624A84C052EF245ULL,
		0xC93A49129BA08EA0ULL,
		0x592848E0298D2CCAULL,
		0x246A3F8DE245E45DULL,
		0x38EBA1772347B88FULL,
		0x3AF3AF00BED59EF8ULL,
		0xE2850293568B2F48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4235F61E50A4ED1ULL,
		0xCBB476A9A7AE89ADULL,
		0x01952FB4FF0B420CULL,
		0x3520DF589F8937E9ULL,
		0x4193F4AA4240D466ULL,
		0xA1BA01129C7D9D17ULL,
		0x661425461A1430D3ULL,
		0x403E278E0D446E40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA9AAA0C9C5811D9ULL,
		0x4BCE008E5F807C63ULL,
		0x60D38B12114BA602ULL,
		0x3A8BEC506A849C0BULL,
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
		0xB1FCB4F6EA26F755ULL,
		0x1FE07A2D777B166CULL,
		0x2B14C88A8CB4B0E5ULL,
		0x7A6D3B20AA6E82C4ULL,
		0x260C184BDC000972ULL,
		0xEA0F98098583281DULL,
		0x9AC1480DCC95A2EEULL,
		0x3114BBDE6A8E6945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E7EA143ACAD961ULL,
		0xA5B45E0004309764ULL,
		0x783BF2283132383BULL,
		0xD944B82900E9563EULL,
		0x1CA3C9D684591F06ULL,
		0xA79DB5CF53030276ULL,
		0x3280810027F6C19AULL,
		0x706FF6A4686F029FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0290704DB222E880ULL,
		0x5713B0D0F25015D4ULL,
		0x2C766268CB17EB2BULL,
		0x399DC993FA2E6939ULL,
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
		0xC87C9EB1F56FF3D3ULL,
		0xA42BE8C9E5625491ULL,
		0x3E91EE6817308594ULL,
		0x8EEEC5B369BE5978ULL,
		0xC91719CB3EEC4878ULL,
		0xB0F855B78869962CULL,
		0xDC8E5CAE020741DBULL,
		0x56290F2853F68750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0216C300C921231ULL,
		0xF53795755B724BAFULL,
		0x3757330814E694DFULL,
		0x4D87169EAC813037ULL,
		0x536FE41CB913E92EULL,
		0x756910E93961F0F7ULL,
		0xCA0945FA85D83163ULL,
		0xCCED0385186EDD11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F2D2A69C6FC0405ULL,
		0x863889F445128ED1ULL,
		0xC6FC1A047146628DULL,
		0x2051694F93606E9DULL,
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
		0xBA85E67D7BB1B17FULL,
		0xC07DFDDC6A339EA3ULL,
		0xFD2869B7F1129932ULL,
		0x0836FBFC2B39B339ULL,
		0xBC476ECE9CEC2336ULL,
		0x7477F71AFF064596ULL,
		0xADF5517C116576D2ULL,
		0xE8355D3EE8DBD6B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7B2E31B7BB3602AULL,
		0x469B5AA4CFDE8E43ULL,
		0x12B38A26221428EDULL,
		0x1CC344A506D664F7ULL,
		0x73070B63906B1D28ULL,
		0x644F0F785A4AD4B4ULL,
		0xBC132FE4D451EA58ULL,
		0x576463E055605B96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE261C545DB253A87ULL,
		0xDFF5055C0E27D1F6ULL,
		0xD205DC04DFE54A63ULL,
		0x6A78BB6108B79468ULL,
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
		0xCD41361F04A94231ULL,
		0x64615C9B218507A5ULL,
		0x6A31043376A71E79ULL,
		0xCFE3D38320AB27DEULL,
		0x5346464CDEE88063ULL,
		0xBF40D16F81E66338ULL,
		0x79F3926D88E8A808ULL,
		0xC0223ACCDF7E88E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9C885132450E9CFULL,
		0x85FC4AE1D1BF0451ULL,
		0x783D35EC05DB4F99ULL,
		0xF36729189FA3525AULL,
		0xEB85F07891A19C05ULL,
		0xF01C74B5CB8D210FULL,
		0x94D50D2C80717FC4ULL,
		0xCF3242059AE9B429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A056E8F58DE3DF7ULL,
		0x9DCAD54A6105D553ULL,
		0xF47B95EEB27BC8F0ULL,
		0x201B97FEAF1F691BULL,
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